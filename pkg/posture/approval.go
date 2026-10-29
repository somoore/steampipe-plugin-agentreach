package posture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Approval: what stands between the agent and an action when nothing in the
// session has approved it yet. One implementation, used by the reach rows,
// the agent row and the path legs.
//
// Sources (code.claude.com/docs/en):
//   - permissions, "Permission system": Bash commands need approval "except a
//     built-in set of read-only commands"; WebFetch needs approval except
//     preapproved documentation domains; file reads need none inside the
//     working directories.
//   - permission-modes: default, acceptEdits and plan prompt; auto routes to
//     the classifier; dontAsk denies what is not pre-approved;
//     bypassPermissions allows.
//   - sandboxing, "Auto-allow mode": with autoAllowBashIfSandboxed (default
//     true) a command that runs inside the sandbox needs no prompt.
//   - sandboxing, "Hosts outside your allowed domains": a sandboxed command
//     connecting to a host outside allowedDomains is allowed in
//     bypassPermissions, prompts in default, acceptEdits and plan, goes to
//     the classifier in auto mode (per-command host lists), and is refused in
//     dontAsk; strictAllowlist or allowManagedDomainsOnly refuses it in every
//     mode.
const (
	ApprovalNone       = "none"       // runs with no prompt
	ApprovalClassifier = "classifier" // auto mode's classifier decides, not a human
	ApprovalPrompt     = "prompt"     // a human approves each time (or saves a rule)
	ApprovalDenied     = "denied"     // refused in this configuration
	ApprovalUnknown    = "unknown"    // the permission mode is unknown
)

// approvalRank orders gates from weakest to strongest. unknown sits below
// prompt: a gate agentreach cannot establish is not counted as a human.
var approvalRank = map[string]int{ApprovalNone: 0, ApprovalClassifier: 1, ApprovalUnknown: 2, ApprovalPrompt: 3, ApprovalDenied: 4}

// strongestApproval returns the gate that lets the least through: a path
// runs unattended only when every step does.
func strongestApproval(as ...string) string {
	best := ""
	for _, a := range as {
		if a == "" {
			continue
		}
		if best == "" || approvalRank[a] > approvalRank[best] {
			best = a
		}
	}
	if best == "" {
		return ApprovalUnknown
	}
	return best
}

// weakestApproval returns the gate that lets the most through.
func weakestApproval(as ...string) string {
	best := ""
	for _, a := range as {
		if a == "" {
			continue
		}
		if best == "" || approvalRank[a] < approvalRank[best] {
			best = a
		}
	}
	if best == "" {
		return ApprovalDenied
	}
	return best
}

// modeApproval is what a tool call that needs approval gets in a mode.
func modeApproval(mode string) string {
	switch mode {
	case "bypassPermissions":
		return ApprovalNone
	case "dontAsk":
		return ApprovalDenied
	case "auto":
		return ApprovalClassifier
	case "default", "acceptEdits", "plan":
		return ApprovalPrompt
	}
	return ApprovalUnknown
}

// networkCommands can send data off the machine, or run arbitrary code that
// can. An allow rule for one of them is an exit that needs no prompt.
var networkCommands = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true, "ftp": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true, "gh": true, "http": true, "https": true, "xh": true,
	"npm": true, "npx": true, "pnpm": true, "yarn": true, "bun": true, "bunx": true, "deno": true, "node": true,
	"pip": true, "pip3": true, "uv": true, "uvx": true, "python": true, "python3": true, "ruby": true, "perl": true, "php": true,
	"go": true, "cargo": true, "docker": true, "podman": true, "kubectl": true, "helm": true,
	"aws": true, "gcloud": true, "az": true, "terraform": true, "tofu": true, "sh": true, "bash": true, "zsh": true, "env": true,
}

// gitNetwork are git subcommands that talk to a remote.
var gitNetwork = map[string]bool{"push": true, "fetch": true, "pull": true, "clone": true, "remote": true, "ls-remote": true, "submodule": true}

var envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=("[^"]*"|'[^']*'|\S*)\s+`)

// bashRule splits a Bash rule pattern into its command words, with leading
// variable assignments removed. blanket is true for Bash, Bash(*) and
// Bash(:*); wildcard is true when the pattern ends in a wildcard.
func bashRule(pattern string) (words []string, blanket, wildcard, ok bool) {
	p := strings.TrimSpace(pattern)
	if p == "Bash" {
		return nil, true, true, true
	}
	if !strings.HasPrefix(p, "Bash(") || !strings.HasSuffix(p, ")") {
		return nil, false, false, false
	}
	inner := strings.TrimSpace(p[5 : len(p)-1])
	for {
		m := envAssign.FindString(inner)
		if m == "" {
			break
		}
		inner = inner[len(m):]
	}
	if inner == "*" || inner == ":*" || inner == "" {
		return nil, true, true, true
	}
	wildcard = strings.HasSuffix(inner, "*")
	inner = strings.TrimSuffix(strings.TrimSuffix(inner, ":*"), "*")
	words = strings.Fields(inner)
	if len(words) == 0 {
		return nil, true, true, true
	}
	if i := strings.LastIndex(words[0], "/"); i >= 0 {
		words[0] = words[0][i+1:]
	}
	return words, false, wildcard, true
}

// bashRuleCarriesNetwork reports whether a Bash allow rule pattern approves a
// command that can reach the network.
func bashRuleCarriesNetwork(pattern string) bool {
	f, blanket, _, ok := bashRule(pattern)
	switch {
	case !ok:
		return false
	case blanket:
		return true
	case f[0] == "git":
		return len(f) == 1 || gitNetwork[f[1]]
	}
	return networkCommands[f[0]]
}

var (
	allStars      = regexp.MustCompile(`^[\s*]+$`)
	pythonCmd     = regexp.MustCompile(`^python[\d.]*$`)
	pythonDottedM = regexp.MustCompile(`^-m\s+\w+\.[\w.]+(\s*:|\s+)$`)
)

// droppedInAutoMode on the collector uses the list in effect for this
// collection: read from the installed Claude Code, pinned, or the fallback.
// For a listed command C a rule is dropped when its pattern is C, C:*, C *,
// C*, or C followed by a flag and ending in * (python -m with a dotted
// module is kept). So Bash(npm run *) and Bash(npm run) are dropped,
// Bash(npm run build:*) and Bash(python3 x.py) are kept.
func (c *ccCollector) droppedInAutoMode(pattern string) bool {
	return droppedInAutoModeWith(c.autoDrop.Commands, pattern)
}

func droppedInAutoModeWith(list []string, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "Bash" {
		return true
	}
	if !strings.HasPrefix(pattern, "Bash(") || !strings.HasSuffix(pattern, ")") {
		return false
	}
	content := pattern[len("Bash(") : len(pattern)-1]
	if content == "" || allStars.MatchString(content) {
		return true
	}
	o := strings.ToLower(strings.TrimSpace(content))
	for _, c := range list {
		if o == c || o == c+":*" || o == c+" *" || o == c+"*" {
			return true
		}
		if strings.HasPrefix(o, c+" ") && strings.HasSuffix(o, "*") {
			rest := o[len(c)+1:]
			if strings.HasPrefix(rest, "-") {
				m := rest[:len(rest)-1]
				if !(pythonCmd.MatchString(c) && pythonDottedM.MatchString(m)) {
					return true
				}
			}
		}
	}
	return false
}

// computeApprovals derives the network and approval switches. Run after
// computeEffective, computeSandboxPosture and effectiveMode.
func (c *ccCollector) computeApprovals() {
	c.planGate = c.planModeGate("")
	c.bashNetAllow, c.mcpAllow, c.webFetchAllowAll = nil, nil, false
	for _, m := range []map[string]any{c.managed, c.user} {
		if b := getBool(m, "sandbox", "network", "strictAllowlist"); b != nil && *b {
			c.strictNet = true // "When any of the honored sources sets it to true, it stays on."
		}
	}
	if b := getBool(c.managed, "sandbox", "network", "allowManagedDomainsOnly"); b != nil && *b {
		c.strictNet = true
		c.managedDomainsOnly = true
	}
	c.autoAllow = true
	if b := getBool(c.managed, "sandbox", "autoAllowBashIfSandboxed"); b != nil {
		c.autoAllow = *b
	} else if b := getBool(c.user, "sandbox", "autoAllowBashIfSandboxed"); b != nil {
		c.autoAllow = *b
	}
	c.bashNetAllowProject = map[string][]string{}
	for _, r := range c.snap.SandboxRules {
		if r.Category != "permission" || r.RuleType != "allow" {
			continue
		}
		machine := machineScope(r.Scope)
		project := (r.Scope == "project" || r.Scope == "local") && r.ProjectDir != ""
		ruleMode := c.effMode
		if project {
			ruleMode = c.projectMode(r.ProjectDir)
		}
		if ruleMode == "auto" && r.Tool == "Bash" && c.droppedInAutoMode(r.Pattern) {
			continue
		}
		switch {
		case r.Tool == "Bash" && bashRuleCarriesNetwork(r.Pattern):
			if machine {
				c.bashNetAllow = append(c.bashNetAllow, r.Pattern+" ("+r.Scope+")")
			} else if project {
				c.bashNetAllowProject[r.ProjectDir] = append(c.bashNetAllowProject[r.ProjectDir], r.Pattern)
			}
		case r.Tool == "WebFetch" && machine && (r.Pattern == "WebFetch" || r.Pattern == "WebFetch(domain:*)"):
			c.webFetchAllowAll = true
		case strings.HasPrefix(r.Tool, "mcp__") && machine:
			c.mcpAllow = append(c.mcpAllow, r.Tool)
		}
	}
	sort.Strings(c.bashNetAllow)
	for i := range c.snap.SandboxRules {
		r := &c.snap.SandboxRules[i]
		r.CarriesNetwork = r.Category == "permission" && r.RuleType == "allow" && r.Tool == "Bash" && bashRuleCarriesNetwork(r.Pattern)
		r.DroppedInAutoMode = r.Category == "permission" && r.RuleType == "allow" && r.Tool == "Bash" && c.droppedInAutoMode(r.Pattern)
		ruleMode := c.effMode
		if (r.Scope == "project" || r.Scope == "local") && r.ProjectDir != "" {
			ruleMode = c.projectMode(r.ProjectDir)
		}
		r.ApprovesNetwork = r.CarriesNetwork && !(ruleMode == "auto" && r.DroppedInAutoMode)
	}
	// The sandbox allowlist is allowedDomains plus the domains of
	// WebFetch(domain:...) allow rules; with allowManagedDomainsOnly only the
	// managed entries count (settings-reference, strictAllowlist and
	// allowManagedDomainsOnly).
	sources := []map[string]any{c.managed, c.user}
	if c.managedDomainsOnly {
		sources = []map[string]any{c.managed}
		c.allowedDomains = toStringSlice(getMap(c.managed, "sandbox", "network")["allowedDomains"])
	}
	for _, m := range sources {
		for _, rule := range toStringSlice(getMap(m, "permissions")["allow"]) {
			if strings.HasPrefix(rule, "WebFetch(domain:") && strings.HasSuffix(rule, ")") {
				c.allowedDomains = append(c.allowedDomains, strings.TrimSuffix(strings.TrimPrefix(rule, "WebFetch(domain:"), ")"))
			}
		}
	}
	for i := range c.snap.MCPServers {
		m := &c.snap.MCPServers[i]
		if m.Agent == AgentClaudeCode {
			m.ToolApproval = c.mcpToolApproval(m.Name)
		}
	}
	for i := range c.snap.Projects {
		p := &c.snap.Projects[i]
		if p.Agent != AgentClaudeCode {
			continue
		}
		g := c.gatesFor(p.ProjectDir)
		p.EffectivePermissionMode, p.PermissionModeSource = g.mode, g.source
		p.ShellApproval, p.NetworkApproval, p.NetworkApprovalReason = g.shell, g.network, g.networkReason
		p.WebFetchApproval, p.ReadApproval = g.webFetch, g.read
		p.WebSourceApproval = c.webSourceApproval(p.ProjectDir)
		p.SandboxAllowedDomains = c.projectAllowedDomains(p.ProjectDir)
	}
}

// modeGate is modeApproval with plan mode resolved.
func (c *ccCollector) modeGate(mode string) string {
	if mode == "plan" {
		return c.planGate
	}
	return modeApproval(mode)
}

// bypassAvailable reports whether bypassPermissions is in the session's mode
// cycle, as far as files show. Docs (permission-modes, "Switch permission
// modes"): bypassPermissions "appears after you start with --permission-mode
// bypassPermissions, --dangerously-skip-permissions,
// --allow-dangerously-skip-permissions, or permissions.defaultMode:
// bypassPermissions in user, --settings, or managed settings";
// permissions.disableBypassPermissionsMode "disable" blocks it (a lock: the
// strictest value any source sets applies). Launch flags are not visible;
// skipDangerousModePermissionPrompt in user settings shows they were
// accepted on this machine before, which the reason says.
func (c *ccCollector) bypassAvailable(dir string) (bool, string) {
	sources := []map[string]any{c.managed, c.user}
	if dir != "" {
		sources = append(sources, c.projectSettings(dir)...)
	}
	for _, m := range sources {
		if getString(getMap(m, "permissions"), "disableBypassPermissionsMode") == "disable" {
			return false, "permissions.disableBypassPermissionsMode is disable"
		}
	}
	for _, s := range []struct {
		name string
		m    map[string]any
	}{{"managed", c.managed}, {"user", c.user}} {
		if getString(getMap(s.m, "permissions"), "defaultMode") == "bypassPermissions" {
			return true, "permissions.defaultMode is bypassPermissions in " + s.name + " settings"
		}
	}
	if c.flagBypass != "" {
		return true, c.flagBypass
	}
	if b := getBool(c.user, "skipDangerousModePermissionPrompt"); b != nil && *b {
		return false, "no settings file or startup-file alias makes bypassPermissions available, but skipDangerousModePermissionPrompt shows a bypass launch flag was accepted on this machine before; see agentreach_launch_flag for running sessions"
	}
	return false, "no settings file or startup-file alias makes bypassPermissions available"
}

// planModeGate follows permission-modes, "Analyze before you edit with plan
// mode": in an interactive session with bypass permissions available,
// "neither the classifier nor a prompt applies to planning commands";
// otherwise, with auto mode available and useAutoModeDuringPlan on (the
// default), the classifier reviews shell commands; otherwise commands
// outside the read-only set prompt. agentreach models the interactive terminal,
// the worst case: -p runs, the SDK and the VS Code panel keep plan mode's
// blocks.
func (c *ccCollector) planModeGate(dir string) string {
	if ok, _ := c.bypassAvailable(dir); ok {
		return ApprovalNone
	}
	for _, m := range []map[string]any{c.managed, c.user} {
		if getString(m, "disableAutoMode") == "disable" || getString(getMap(m, "permissions"), "disableAutoMode") == "disable" {
			return ApprovalPrompt
		}
	}
	use := true
	if b := getBool(c.managed, "useAutoModeDuringPlan"); b != nil {
		use = *b
	} else if b := getBool(c.user, "useAutoModeDuringPlan"); b != nil {
		use = *b
	}
	if use {
		return ApprovalClassifier
	}
	return ApprovalPrompt
}

// modeGates are the gates of a session started in one directory.
type modeGates struct {
	mode, source, shell, network, networkReason, webFetch, read string
}

// gatesFor computes the gates for a session started in dir ("" for the
// machine-wide view): that directory's permission mode, whether the sandbox
// is on there, and the Bash allow rules saved there.
func (c *ccCollector) gatesFor(dir string) modeGates {
	saveMode, saveNet, saveSB, savePlan := c.effMode, c.bashNetAllow, c.sandboxEnabled, c.planGate
	defer func() { c.effMode, c.bashNetAllow, c.sandboxEnabled, c.planGate = saveMode, saveNet, saveSB, savePlan }()
	g := modeGates{mode: c.effMode, source: c.effModeSource}
	if dir != "" {
		c.planGate = c.planModeGate(dir)
		g.mode, g.source = c.projectModeSource(dir)
		c.effMode = g.mode
		c.sandboxEnabled = c.sandboxActive(dir)
		// Machine rules auto mode drops come back in a project that starts
		// in another mode; the project's own rules join them.
		var net []string
		for _, r := range c.snap.SandboxRules {
			if r.Category != "permission" || r.RuleType != "allow" || r.Tool != "Bash" || !bashRuleCarriesNetwork(r.Pattern) {
				continue
			}
			machine := machineScope(r.Scope)
			here := (r.Scope == "project" || r.Scope == "local") && r.ProjectDir == dir
			if (machine || here) && !(g.mode == "auto" && c.droppedInAutoMode(r.Pattern)) {
				net = append(net, r.Pattern+" ("+r.Scope+")")
			}
		}
		sort.Strings(net)
		c.bashNetAllow = net
	}
	if c.sandboxEnabled {
		g.shell = c.sandboxedApproval()
	} else {
		g.shell = c.unsandboxedApproval()
	}
	g.network, g.networkReason = c.networkApproval()
	g.webFetch = c.webFetchApproval()
	g.read = c.modeGate(g.mode)
	return g
}

// projectAllowedDomains are the hosts a project's own settings add to the
// sandbox allowlist: arrays merge across scopes, and WebFetch(domain:...)
// allow rules join the allowlist (sandboxing, "Approval choices"). With
// allowManagedDomainsOnly none of them count.
func (c *ccCollector) projectAllowedDomains(dir string) []string {
	if c.managedDomainsOnly || dir == "" || !c.sandboxActive(dir) {
		return nil // with the sandbox off there is no allowlist to widen
	}
	var out []string
	for _, f := range []string{".claude/settings.json", ".claude/settings.local.json"} {
		m := c.doc(filepath.Join(dir, f))
		out = append(out, toStringSlice(getMap(m, "sandbox", "network")["allowedDomains"])...)
		for _, rule := range toStringSlice(getMap(m, "permissions")["allow"]) {
			if strings.HasPrefix(rule, "WebFetch(domain:") && strings.HasSuffix(rule, ")") {
				out = append(out, strings.TrimSuffix(strings.TrimPrefix(rule, "WebFetch(domain:"), ")"))
			}
		}
	}
	return uniqSorted(out)
}

// escapeApproval is what a command that leaves the sandbox gets, and false
// when no route out of the sandbox exists (sandboxing, "The unsandboxed
// retry escape hatch", excludedCommands, failIfUnavailable).
func (c *ccCollector) escapeApproval() (string, bool) {
	if c.sb.allowUnsandboxed || c.sb.excluded > 0 || (c.sb.runtimeAvailable != nil && !*c.sb.runtimeAvailable && !c.sb.failIfUnavailable) {
		return c.unsandboxedApproval(), true
	}
	return ApprovalDenied, false
}

// hostApproval is what a shell command connecting to a local listener or
// socket needs. Sandbox off: the regular permission flow. Allowed by the
// sandbox: what a sandboxed command gets. A TCP port no rule allows is an
// unlisted host, decided like the internet (sandboxing, "Hostnames that
// resolve to local addresses"); a Unix socket no rule allows is refused
// unless the command can leave the sandbox.
func (c *ccCollector) hostApproval(h ReachHost) string {
	if h.Reachable == nil || !*h.Reachable {
		return ApprovalDenied
	}
	if !c.sandboxEnabled {
		return c.unsandboxedApproval()
	}
	if h.AllowedBySandbox != nil && *h.AllowedBySandbox {
		return c.sandboxedApproval()
	}
	if h.Kind == "tcp" {
		g, _ := c.networkApproval()
		return g
	}
	g, _ := c.escapeApproval()
	return g
}

// sandboxedApproval is what a command that stays inside the sandbox gets.
func (c *ccCollector) sandboxedApproval() string {
	if c.autoAllow && c.effMode != "plan" {
		return ApprovalNone
	}
	return c.modeGate(c.effMode)
}

// unsandboxedApproval is what a non-read-only command that runs outside the
// sandbox gets: the sandbox is off, or the command is retried outside it.
func (c *ccCollector) unsandboxedApproval() string {
	if len(c.bashNetAllow) > 0 {
		return ApprovalNone
	}
	return c.modeGate(c.effMode)
}

// shellGateText says what a mode does with a shell command that needs
// approval.
func shellGateText(mode, gate string) string {
	switch gate {
	case ApprovalNone:
		return mode + " mode runs it with no prompt"
	case ApprovalClassifier:
		return "auto mode's classifier reviews it, not a person"
	case ApprovalPrompt:
		return mode + " mode prompts you first"
	case ApprovalDenied:
		return mode + " mode refuses it unless an allow rule matches"
	}
	return "the permission mode is unknown"
}

// networkApproval is what decides a shell command's connection to a host
// that no rule allows, and why.
func (c *ccCollector) networkApproval() (string, string) {
	if !c.sandboxEnabled {
		if len(c.bashNetAllow) > 0 {
			return ApprovalNone, "the sandbox is off and the allow rule " + c.bashNetAllow[0] + " runs a network-capable command with no prompt"
		}
		g := c.modeGate(c.effMode)
		return g, "the sandbox is off; for a command that is not read-only, " + shellGateText(c.effMode, g)
	}
	if c.sandboxAllowsAll() {
		g := c.sandboxedApproval()
		return g, "sandbox.network.allowedDomains contains *, so a sandboxed command reaches any host; " + map[bool]string{true: "auto-allow runs it with no prompt", false: shellGateText(c.effMode, g)}[g == ApprovalNone && c.autoAllow]
	}
	var gate, why string
	if c.strictNet {
		lock := "sandbox.network.strictAllowlist"
		if c.managedDomainsOnly {
			lock = "sandbox.network.allowManagedDomainsOnly in managed settings"
		}
		gate, why = ApprovalDenied, lock+" makes the sandbox refuse hosts outside the allowlist in every mode"
	} else {
		gate = c.modeGate(c.effMode)
		switch gate {
		case ApprovalNone:
			why = "bypassPermissions mode lets the sandbox connect to hosts outside allowedDomains with no prompt"
		case ApprovalClassifier:
			why = "auto mode refuses hosts outside allowedDomains unless the command lists them and the classifier approves"
		case ApprovalPrompt:
			why = "the sandbox asks you before connecting to a host outside allowedDomains (" + c.effMode + " mode)"
		case ApprovalDenied:
			why = "dontAsk mode refuses hosts outside allowedDomains"
		default:
			why = "the permission mode is unknown"
		}
	}
	if c.sb.allowUnsandboxed || c.sb.excluded > 0 || (c.sb.runtimeAvailable != nil && !*c.sb.runtimeAvailable && !c.sb.failIfUnavailable) {
		// A command can leave the sandbox: retried, excluded, or no runtime.
		esc := c.unsandboxedApproval()
		if approvalRank[esc] < approvalRank[gate] {
			how := shellGateText(c.effMode, esc)
			if len(c.bashNetAllow) > 0 {
				how = "the allow rule " + c.bashNetAllow[0] + " also approves the retry"
			}
			gate, why = esc, "a command can run outside the sandbox ("+c.sandboxBypasses()+"), and there "+how
		}
	}
	return gate, why
}

func (c *ccCollector) sandboxAllowsAll() bool {
	for _, d := range c.allowedDomains {
		if d == "*" {
			return true
		}
	}
	return false
}

// webSourceApproval is what it takes for a fetched page to reach the agent
// in a session started in dir ("" for the machine-wide view). It is the
// weakest way a page can arrive, not what a fetch to an arbitrary host
// gets: preapproved documentation domains and domains with a saved
// WebFetch(domain:...) allow rule fetch with no prompt, so only a rule that
// covers every domain gates the source: a deny of WebFetch, or an ask of
// WebFetch(domain:*), since an explicit WebFetch(domain:...) rule takes
// precedence over the preapproved set, and auto and bypassPermissions skip
// the prompt except where an ask rule matches (tools-reference, "WebFetch
// tool behavior"). CLAUDE_CODE_DISABLE_WEB_FETCH=1 turns the tool off
// ("WebFetch availability"). The classifier is never a source gate here:
// it does not see tool results (permission-modes), so it cannot catch
// injected content in a page.
func (c *ccCollector) webSourceApproval(dir string) string {
	if c.webFetchDisabledByEnv() {
		return ApprovalDenied
	}
	deny, ask := false, false
	for _, r := range c.snap.SandboxRules {
		if r.Agent != AgentClaudeCode || r.Category != "permission" || r.Tool != "WebFetch" ||
			(r.Pattern != "WebFetch" && r.Pattern != "WebFetch(domain:*)") {
			continue
		}
		here := machineScope(r.Scope) || (r.Scope == "project" || r.Scope == "local") && r.ProjectDir != "" && r.ProjectDir == dir
		if !here {
			continue
		}
		switch {
		case r.RuleType == "deny":
			deny = true // a bare deny removes the tool; domain:* matches every host
		case r.RuleType == "ask" && r.Pattern == "WebFetch(domain:*)":
			// Only an explicit WebFetch(domain:...) rule is documented to
			// take precedence over the preapproved set; a bare WebFetch ask
			// is not, and a gate agentreach cannot establish never counts.
			ask = true
		}
	}
	switch {
	case deny:
		return ApprovalDenied
	case ask:
		return ApprovalPrompt
	}
	return ApprovalNone
}

// webFetchDisabledByEnv reports CLAUDE_CODE_DISABLE_WEB_FETCH set to a true
// value in managed or user settings env, or, on a live run, in agentreach's own
// environment (which a session started from the same shell inherits).
func (c *ccCollector) webFetchDisabledByEnv() bool {
	truthy := func(v string) bool { return v == "1" || strings.EqualFold(v, "true") }
	for _, m := range []map[string]any{c.managed, c.user} {
		if v, ok := getMap(m, "env")["CLAUDE_CODE_DISABLE_WEB_FETCH"].(string); ok && truthy(v) {
			return true
		}
	}
	return c.opts.Home == "" && truthy(os.Getenv("CLAUDE_CODE_DISABLE_WEB_FETCH"))
}

// webFetchApproval is what a WebFetch to an arbitrary host gets.
func (c *ccCollector) webFetchApproval() string {
	switch {
	case c.webFetchDenied:
		return ApprovalDenied
	case c.webFetchAllowAll:
		return ApprovalNone
	}
	return c.modeGate(c.effMode)
}

// mcpNameNorm is the server segment of an MCP tool name: characters outside
// [A-Za-z0-9_-] become "_" (docs: mcp, tool names).
var mcpNameNorm = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// mcpToolApproval is what a call to one of the server's tools gets.
func (c *ccCollector) mcpToolApproval(name string) string {
	prefix := "mcp__" + mcpNameNorm.ReplaceAllString(name, "_")
	for _, t := range c.mcpAllow {
		if t == prefix || t == prefix+"__*" || strings.HasPrefix(t, prefix+"__") {
			return ApprovalNone
		}
	}
	return c.modeGate(c.effMode)
}

// editApprovalGate maps an edit_tool_approval value onto the approval scale.
func editApprovalGate(v string) string {
	switch v {
	case "auto", "allowed":
		return ApprovalNone
	case "classifier":
		return ApprovalClassifier
	case "prompt":
		return ApprovalPrompt
	case "denied":
		return ApprovalDenied
	}
	return ApprovalUnknown
}

// readApproval is the weakest gate on any route to a file. A shell read is a
// read-only command (cat, head), which runs "without a permission prompt in
// every mode" (permissions, "Read-only commands"). A read the sandbox blocks
// leaves through the escape route and is approved like any unsandboxed
// retry. The Read tool needs no approval inside the working directories and
// goes through the mode outside them (permissions, tool table), except in
// auto mode (below). In a session with server-side classifier review, a
// read-only shell command waits for that review (permission-modes, decision
// order step 2); agentreach cannot see whether a session has it, so the shell
// route stays none.
func (c *ccCollector) readApproval(bash, retry, tool bool, projectDir string) string {
	gates := []string{}
	if bash {
		gates = append(gates, ApprovalNone)
	}
	if retry {
		// The retried read is prompted as "Bash command (unsandboxed)" in
		// Manual and acceptEdits, reviewed by the classifier in auto,
		// allowed in bypassPermissions and denied in dontAsk.
		gates = append(gates, c.modeGate(c.effMode))
	}
	if tool {
		switch {
		case projectDir != "":
			gates = append(gates, ApprovalNone)
		case c.effMode == "auto":
			// Auto mode auto-approves read-only actions (decision order step
			// 2); the one exception is a prompt before the first Read, Grep
			// or Glob outside the working directories, which "Yes, and keep
			// allowing" turns off for good and which -p and background
			// sessions never show (permission-modes, "The first read outside
			// the working directories"). A one-time prompt is not a gate.
			gates = append(gates, ApprovalNone)
		default:
			gates = append(gates, c.modeGate(c.effMode))
		}
	}
	return weakestApproval(gates...)
}

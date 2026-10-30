package posture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Codex CLI gate model. What a session started in a directory needs before
// a shell command runs, reaches an unlisted host, or reads a file. Facts
// are from the Codex docs (developers.openai.com/codex, now served from
// learn.chatgpt.com/docs) and were checked against the codex-cli 0.155.1
// source; the citations are next to each rule.
//
// Layers, lowest to highest (config-basic, "Configuration precedence";
// managed-configuration): /etc/codex/config.toml, ~/.codex/config.toml, the
// project's .codex/config.toml (trusted projects only), then the legacy
// /etc/codex/managed_config.toml, which overrides user config and CLI
// overrides. CLI flags (--sandbox, -a, --yolo) and a thread's persisted
// permission profile are not visible in files; like Claude Code's
// --permission-mode, agentreach reports what the files say.

// codexGate is the effective configuration and gates for one session.
type codexGate struct {
	Sandbox, SandboxSource string // read-only | workspace-write | danger-full-access
	Approval               string // on-request | never | granular | untrusted
	SandboxApproval        bool   // granular: escalation prompts may surface
	NetworkAccess          bool
	Proxy                  bool // features.network_proxy (experimental) is on
	// WritableRoots are sandbox_workspace_write.writable_roots; the cwd is
	// always writable, and $TMPDIR and /tmp unless excluded.
	WritableRoots                  []string
	ExcludeTmpdir, ExcludeSlashTmp bool
	WebSearch                      string
	AllowRules                     []string // exec-policy allow rules for network-capable commands
	// Unknown is set when the files cannot decide the gates; every gate is
	// then "unknown" with this reason.
	Unknown     string
	ReadUnknown string // reads are restricted by something agentreach does not model

	Shell, Network, Read, Web string
	NetworkReason             string
}

// Mode is the agentreach effective_permission_mode for Codex: sandbox/approval.
func (g codexGate) Mode() string {
	if g.Unknown != "" {
		return "unknown"
	}
	return g.Sandbox + "/" + g.Approval
}

type codexModel struct {
	home, system string // CODEX_HOME and /etc/codex ("" = not read)
	sysCfg       map[string]any
	user         map[string]any
	managed      map[string]any
	requirements map[string]any
	flags        map[string]any // flags on the default codex alias or function
	userRules    []string
	// broken names a machine-wide config file that does not parse; Codex
	// does not start with it, so every gate is unknown.
	broken string
}

// layered returns the value of key from the highest layer that sets it, and
// that layer's name.
func (m *codexModel) layered(project map[string]any, keys ...string) (any, string) {
	for _, l := range []struct {
		name string
		cfg  map[string]any
	}{{"managed", m.managed}, {"launch_flag", m.flags}, {"project", project}, {"user", m.user}, {"system", m.sysCfg}} {
		if v, ok := lookup(l.cfg, keys...); ok {
			return v, l.name
		}
	}
	return nil, ""
}

func lookup(m map[string]any, keys ...string) (any, bool) {
	cur := any(m)
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[k]; !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

// gate resolves the session gate for a directory with the given trust
// ("trusted", "untrusted" or "" for no decision) and project config (only
// passed when trusted).
func (m *codexModel) gate(trust string, project map[string]any, projectRules []string, projectBroken string) codexGate {
	g := codexGate{}
	// Permission profiles (beta) replace sandbox_mode; agentreach does not model
	// their filesystem and network tables. permissions docs: "Configure
	// either default_permissions and [permissions], or sandbox_mode /
	// sandbox_workspace_write, but not both."
	switch {
	case m.broken != "":
		g.Unknown = m.broken + " does not parse, and Codex does not start with it"
	case projectBroken != "":
		g.Unknown = projectBroken + " does not parse, and Codex does not start with it in this project"
	default:
		if v, _ := m.layered(project, "default_permissions"); v != nil {
			g.Unknown = "default_permissions selects a permission profile (beta), which agentreach does not model"
		} else if v, _ := m.layered(project, "permissions"); v != nil {
			g.Unknown = "[permissions] profiles (beta) are configured, which agentreach does not model"
		}
	}

	// sandbox_mode; unset is read-only, or workspace-write once the project
	// has a trust decision (agent-approvals-security: "Codex may also start
	// in read-only until you explicitly trust the working directory";
	// 0.155.1 source: trusted or untrusted gives workspace-write).
	if v, src := m.layered(project, "sandbox_mode"); v != nil {
		g.Sandbox, _ = v.(string)
		g.SandboxSource = src
	} else {
		g.Sandbox, g.SandboxSource = "read-only", "built_in"
		if trust != "" {
			g.Sandbox = "workspace-write"
		}
	}
	switch g.Sandbox {
	case "read-only", "workspace-write", "danger-full-access":
	default:
		if g.Unknown == "" {
			g.Unknown = "sandbox_mode " + quoteOr(g.Sandbox) + " is not one agentreach models"
		}
	}

	// approval_policy (config-reference): on-request (default) | never |
	// granular table; on-failure is a deprecated alias of on-request;
	// "untrusted" is unsupported in config and is only the policy of a
	// project marked untrusted: "Commands then require approval unless an
	// execution-policy rule allows them" (agent-approvals-security).
	v, _ := m.layered(project, "approval_policy")
	switch x := v.(type) {
	case nil:
		g.Approval = "on-request"
		if trust == "untrusted" {
			g.Approval = "untrusted"
		}
	case string:
		switch x {
		case "on-request", "on-failure":
			g.Approval = "on-request"
		case "never":
			g.Approval = "never"
		case "untrusted":
			if g.Unknown == "" {
				g.Unknown = `approval_policy = "untrusted" is no longer supported and stops Codex from starting`
			}
			g.Approval = "untrusted"
		default:
			if g.Unknown == "" {
				g.Unknown = "approval_policy " + quoteOr(x) + " is not one agentreach models"
			}
		}
	case map[string]any:
		gr := getMap(x, "granular")
		if gr == nil {
			if g.Unknown == "" {
				g.Unknown = "approval_policy table without granular is not one agentreach models"
			}
			break
		}
		g.Approval = "granular"
		if b := getBool(gr, "sandbox_approval"); b != nil {
			g.SandboxApproval = *b
		}
	}

	if b, _ := m.layered(project, "sandbox_workspace_write", "network_access"); b != nil {
		g.NetworkAccess, _ = b.(bool)
	}
	if v, _ := m.layered(project, "sandbox_workspace_write", "writable_roots"); v != nil {
		g.WritableRoots = toStringSlice(v)
	}
	if b, _ := m.layered(project, "sandbox_workspace_write", "exclude_tmpdir_env_var"); b != nil {
		g.ExcludeTmpdir, _ = b.(bool)
	}
	if b, _ := m.layered(project, "sandbox_workspace_write", "exclude_slash_tmp"); b != nil {
		g.ExcludeSlashTmp, _ = b.(bool)
	}
	// The network proxy (experimental) constrains enabled network to a
	// domain list; agentreach does not model its rules.
	proxy := false
	if v, _ := m.layered(project, "features", "network_proxy"); v != nil {
		switch x := v.(type) {
		case bool:
			proxy = x
		case map[string]any:
			proxy = getBool(x, "enabled") != nil && *getBool(x, "enabled")
		}
	}

	// web_search (config-basic): disabled | cached (default) | indexed |
	// live; full access upgrades cached to live (0.155.1 source).
	g.WebSearch = "cached"
	if v, _ := m.layered(project, "web_search"); v != nil {
		g.WebSearch, _ = v.(string)
	}
	if g.Sandbox == "danger-full-access" && g.WebSearch == "cached" {
		g.WebSearch = "live"
	}

	// Managed requirements: a value outside allowed_* falls back to "a
	// compatible value" (managed-configuration) that agentreach does not choose.
	if g.Unknown == "" && m.requirements != nil {
		if al := toStringSlice(m.requirements["allowed_sandbox_modes"]); len(al) > 0 && !has(al, g.Sandbox) {
			g.Unknown = "requirements.toml does not allow sandbox_mode " + g.Sandbox + "; Codex falls back to an allowed mode agentreach cannot pick"
		}
		if al := toStringSlice(m.requirements["allowed_approval_policies"]); len(al) > 0 && !has(al, g.Approval) {
			g.Unknown = "requirements.toml does not allow approval_policy " + g.Approval + "; Codex falls back to an allowed policy agentreach cannot pick"
		}
	}
	if m.requirements != nil {
		if dr := toStringSlice(getMap(m.requirements, "permissions", "filesystem")["deny_read"]); len(dr) > 0 {
			g.ReadUnknown = "requirements.toml [permissions.filesystem] deny_read hides some paths; agentreach does not match them"
		}
	}
	if g.Unknown != "" {
		g.ReadUnknown = g.Unknown
	}

	rules := append(append([]string{}, m.userRules...), projectRules...)
	for _, r := range rules {
		if codexRuleCarriesNetwork(r) {
			g.AllowRules = append(g.AllowRules, r)
		}
	}
	sort.Strings(g.AllowRules)

	g.Proxy = proxy
	g.decide(proxy)
	return g
}

func (g *codexGate) decide(proxy bool) {
	if g.Unknown != "" {
		g.Shell, g.Network, g.Read, g.Web = ApprovalUnknown, ApprovalUnknown, ApprovalUnknown, ApprovalUnknown
		g.NetworkReason = "not assessed: " + g.Unknown
		return
	}
	untrusted := g.Approval == "untrusted"
	// Shell: "With on-request, commands allowed by the sandbox can run
	// without approval, read accessible files, and use network access if
	// enabled" (agent-approvals-security). never and granular do not add
	// prompts for sandboxed commands; danger-full-access has no sandbox.
	g.Shell, g.Read = ApprovalNone, ApprovalNone
	if untrusted {
		g.Shell, g.Read = ApprovalPrompt, ApprovalPrompt
	}
	if g.ReadUnknown != "" {
		g.Read = ApprovalUnknown
	}
	g.Web = ApprovalNone
	if g.WebSearch == "disabled" {
		g.Web = ApprovalDenied
	}

	open := ""
	switch {
	case g.Sandbox == "danger-full-access":
		open = "sandbox_mode is danger-full-access: commands run with no sandbox"
	case g.Sandbox == "workspace-write" && g.NetworkAccess:
		open = "sandbox_workspace_write.network_access is true: sandboxed commands have unrestricted outbound access"
		if proxy {
			g.Network, g.NetworkReason = ApprovalUnknown, "not assessed: network access is on and the experimental network_proxy limits it by rules agentreach does not model"
			return
		}
	}
	if open != "" {
		if untrusted {
			g.Network, g.NetworkReason = ApprovalPrompt, open+", and in this untrusted project each command needs your approval"
			return
		}
		g.Network, g.NetworkReason = ApprovalNone, open+"; "+g.Approval+" runs such a command without asking"
		return
	}
	if len(g.AllowRules) > 0 {
		show := g.AllowRules
		if len(show) > 2 {
			show = show[:2]
		}
		g.Network, g.NetworkReason = ApprovalNone, "the sandbox blocks network, but an exec-policy allow rule ("+strings.Join(show, ", ")+") runs a network-capable command outside the sandbox without prompting"
		return
	}
	blocked := "the " + g.Sandbox + " sandbox blocks network"
	g.Network = g.escape()
	switch {
	case untrusted:
		g.NetworkReason = blocked + "; in this untrusted project a denied command can be retried outside the sandbox after you approve it"
	case g.Approval == "on-request":
		g.NetworkReason = blocked + "; on-request lets the model ask to run a command outside the sandbox, and you approve it"
	case g.Approval == "granular" && g.SandboxApproval:
		g.NetworkReason = blocked + "; granular sandbox_approval lets an escalation request reach you"
	default:
		g.NetworkReason = blocked + " and " + g.Approval + " never escalates a sandbox denial to you"
	}
}

// escape is what a command the sandbox refuses needs to run outside it: an
// escalation you approve, or nothing under never and granular without
// sandbox_approval, which return the denial to the model. Exec-policy allow
// rules are not counted here; callers that know the command add them.
func (g codexGate) escape() string {
	switch {
	case g.Unknown != "":
		return ApprovalUnknown
	case g.Approval == "untrusted", g.Approval == "on-request", g.Approval == "granular" && g.SandboxApproval:
		return ApprovalPrompt
	}
	return ApprovalDenied
}

// codexShellEnforced: no route out of the sandbox, not even with a prompt.
func (g codexGate) enforced() bool {
	return g.Unknown == "" && g.Sandbox != "danger-full-access" && len(g.AllowRules) == 0 &&
		(g.Approval == "never" || (g.Approval == "granular" && !g.SandboxApproval))
}

func (g codexGate) bypasses() string {
	var b []string
	if g.Sandbox != "danger-full-access" && !g.enforced() && g.Unknown == "" {
		if len(g.AllowRules) > 0 {
			b = append(b, "exec_policy_allow")
		}
		if g.Approval == "on-request" || g.Approval == "untrusted" || (g.Approval == "granular" && g.SandboxApproval) {
			b = append(b, "escalation_request")
		}
	}
	return strings.Join(b, ",")
}

func quoteOr(s string) string {
	if s == "" {
		return "(empty)"
	}
	return `"` + s + `"`
}

// Exec-policy rules (rules docs): prefix_rule(pattern=[...],
// decision="allow"|"prompt"|"forbidden"), decision defaulting to allow;
// "allow: Run the command outside the sandbox without prompting."
var (
	prefixRuleCall = regexp.MustCompile(`(?s)prefix_rule\s*\((.*?)\)\s*(?:\n|$)`)
	rulePatternKey = regexp.MustCompile(`pattern\s*=\s*\[`)
	ruleDecision   = regexp.MustCompile(`decision\s*=\s*"([a-z]+)"`)
	ruleString     = regexp.MustCompile(`"([^"]*)"`)
)

// codexAllowRules returns the allow rules in dir/*.rules as space-joined
// command prefixes. The first pattern element may be a list of
// alternatives; each becomes its own prefix.
func codexAllowRules(dir string) []string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.rules"))
	sort.Strings(files)
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, call := range prefixRuleCall.FindAllStringSubmatch(string(b), -1) {
			body := call[1]
			if d := ruleDecision.FindStringSubmatch(body); d != nil && d[1] != "allow" {
				continue
			}
			list, ok := patternList(body)
			if !ok {
				continue
			}
			first, rest := splitFirstElement(list)
			var tail []string
			for _, s := range ruleString.FindAllStringSubmatch(rest, -1) {
				tail = append(tail, s[1])
			}
			for _, s := range ruleString.FindAllStringSubmatch(first, -1) {
				out = append(out, strings.TrimSpace(strings.Join(append([]string{s[1]}, tail...), " ")))
			}
		}
	}
	return out
}

// patternList returns the body of the pattern = [...] list, brackets
// balanced (elements may be nested lists).
func patternList(body string) (string, bool) {
	loc := rulePatternKey.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	depth, inStr := 1, false
	for i := loc[1]; i < len(body); i++ {
		switch c := body[i]; {
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '[':
			depth++
		case c == ']':
			depth--
			if depth == 0 {
				return body[loc[1]:i], true
			}
		}
	}
	return "", false
}

// splitFirstElement splits a Starlark list body after its first element,
// which is a string or a nested list.
func splitFirstElement(body string) (string, string) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "[") {
		if i := strings.Index(body, "]"); i >= 0 {
			return body[:i+1], body[i+1:]
		}
	}
	if i := strings.Index(body, ","); i >= 0 {
		return body[:i], body[i+1:]
	}
	return body, ""
}

// codexRuleCarriesNetwork reports whether an allow-rule prefix lets a
// network-capable command run outside the sandbox.
func codexRuleCarriesNetwork(prefix string) bool {
	f := strings.Fields(prefix)
	if len(f) == 0 {
		return false
	}
	if i := strings.LastIndex(f[0], "/"); i >= 0 {
		f[0] = f[0][i+1:]
	}
	if f[0] == "git" {
		return len(f) == 1 || gitNetwork[f[1]]
	}
	return networkCommands[f[0]]
}

// codexToolApproval is the gate on a Codex MCP tool call:
// default_tools_approval_mode / tools.<tool>.approval_mode = auto (default)
// | prompt | writes | approve (mcp docs). Only approve and prompt are
// definite; auto and writes depend on tool annotations agentreach cannot see.
// codexToolApproval decides what a call to one of the server's tools gets.
// Source: developers.openai.com/codex/mcp, "default_tools_approval_mode
// (optional): Default approval behavior for tools from this server.
// Supported values are auto, prompt, writes, and approve." Unset is
// optional-with-auto, so the session's approval policy decides; a
// per-server "approve" wins over the policy; "prompt" asks for every tool
// (under approval_policy never, casf cannot establish which wins, so
// unknown); "writes" auto-runs read-only tools and prompts for the rest,
// and casf cannot see which tools are read-only, so the gate is a prompt.
func codexToolApproval(sm map[string]any, approval string) string {
	mode := getString(sm, "default_tools_approval_mode")
	weakest := mode
	for _, t := range getMap(sm, "tools") {
		if tm, ok := t.(map[string]any); ok && getString(tm, "approval_mode") == "approve" {
			weakest = "approve"
		}
	}
	switch {
	case weakest == "approve":
		return ApprovalNone
	case weakest == "prompt":
		if approval == "never" {
			return ApprovalUnknown
		}
		return ApprovalPrompt
	case weakest == "writes":
		return ApprovalPrompt
	}
	// Unset or "auto": the session's approval policy decides. An empty
	// policy (no session context) stays unknown.
	switch approval {
	case "never":
		return ApprovalNone
	case "on-request", "untrusted", "granular":
		return ApprovalPrompt
	}
	return ApprovalUnknown
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

package posture

import (
	"context"
	"crypto/sha1" // #nosec G505 -- git's object id format for SHA-1 repositories; recomputed to compare against ls-tree ids, never a security decision
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AgentClaudeCode is the agent identifier used in every Claude Code row.
const AgentClaudeCode = "claude_code"

type ccCollector struct {
	opts       Options
	home       string
	configDir  string
	globalPath string
	global     map[string]any

	managedDir        string // system directory: managed-settings.json, managed-settings.d, managed-mcp.json, CLAUDE.md
	managedPath       string // managedDir/managed-settings.json
	plistPath         string // macOS managed-preferences plist, "" when not applicable
	remotePath        string // <configDir>/remote-settings.json: server-managed settings cached from the admin console
	managedSources    []managedSource
	managedSourceName string         // see Agent.ManagedSource
	managedSelected   []string       // names of the sources that contribute to c.managed
	managedBehavior   string         // first-wins | merge
	managed           map[string]any // the effective managed document after source selection and locks
	userPath          string
	user              map[string]any
	projectSandboxOn  map[string]bool // project dirs whose project or local settings set sandbox.enabled true

	snap *Snapshot

	// effective agent-level rules used by reach_* tables
	sandboxEnabled  bool
	sandboxDenyRead []scopedRule
	permDenyRead    []scopedRule
	allowedDomains  []string
	allowUnixSocks  []string
	allowAllUnix    bool
	allowLocalBind  bool // sandbox.network.allowLocalBinding (macOS: direct loopback dials)

	sb                sandboxPosture
	sandboxAllowRead  []scopedRule
	sandboxDenyWrite  []scopedRule
	sandboxAllowWrite []scopedRule
	editDeny          []scopedRule
	editAllow         []scopedRule
	webFetchDenied    bool
	// approval model (approval.go)
	strictNet             bool
	planGate              string // what plan mode gives a command that is not read-only
	managedDomainsOnly    bool
	autoAllow             bool
	bashNetAllow          []string            // machine-wide Bash allow rules for network-capable commands
	bashNetAllowProject   map[string][]string // project dir -> the same, from project and local settings
	webFetchAllowAll      bool
	mcpAllow              []string
	binaryPath            string
	flagMode, flagModeWhy string // mode set by a flag on the default claude command
	flagBypass            string // why bypassPermissions is available from a flag
	runningBypass         int
	autoDrop              autoDropList // auto mode rule-drop list in effect (autodrop.go)
	version               string
	effMode               string
	effModeSource         string
	docCache              map[string]map[string]any // settings file path -> parsed document
	reviews               *ReviewLedger
	modelOpen             map[string]bool // path -> the model says a sandboxed shell read succeeds

	gitFiles map[string]map[string]bool   // repo root -> tracked files
	gitIDs   map[string]map[string]bool   // repo root -> emails that count as the user
	gitHead  map[string]map[string]string // repo root -> path -> blob id at HEAD
}

type scopedRule struct {
	Pattern    string
	Resolved   string
	Scope      string
	ProjectDir string // set for project and local rules; they apply only in sessions started there
}

// collectClaudeCode populates snap with everything Claude Code related.
func collectClaudeCode(ctx context.Context, opts Options, snap *Snapshot) {
	c := &ccCollector{opts: opts, snap: snap, gitFiles: map[string]map[string]bool{}, gitIDs: map[string]map[string]bool{}, projectSandboxOn: map[string]bool{}, docCache: map[string]map[string]any{}, modelOpen: map[string]bool{}}
	c.home = opts.Home
	if c.home == "" {
		c.home, _ = os.UserHomeDir()
	}
	c.configDir = os.Getenv("CLAUDE_CONFIG_DIR")
	if c.configDir == "" {
		c.configDir = filepath.Join(c.home, ".claude")
	}
	c.globalPath = filepath.Join(c.home, ".claude.json")
	if alt := filepath.Join(c.configDir, ".claude.json"); c.configDir != filepath.Join(c.home, ".claude") && fileExists(alt) {
		c.globalPath = alt
	}
	c.managedDir = opts.ManagedDir
	if c.managedDir == "" {
		c.managedDir = managedSystemDir()
	}
	c.managedPath = filepath.Join(c.managedDir, "managed-settings.json")
	c.plistPath = opts.PlistPath
	if c.plistPath == "" {
		c.plistPath = managedPlistPath()
	} else if c.plistPath == "-" {
		c.plistPath = ""
	}
	c.remotePath = filepath.Join(c.configDir, "remote-settings.json")
	c.userPath = filepath.Join(c.configDir, "settings.json")

	var err error
	if c.global, err = readJSON(c.globalPath); err != nil {
		snap.Errors = append(snap.Errors, "global config: "+c.globalPath+": "+err.Error())
	}
	c.loadManaged(ctx)
	if c.user, err = readJSON(c.userPath); err != nil {
		snap.Errors = append(snap.Errors, "user settings: "+c.userPath+": "+err.Error()+"; Claude Code skips a settings file it cannot parse")
	}

	// Every managed document is listed in agentreach_setting so an auditor can see
	// what was deployed; only the selected source(s) contribute hooks and
	// rules, and only their rows carry applies = true.
	for _, s := range c.managedSources {
		if s.Doc == nil {
			continue
		}
		if c.managedApplies(s.Name) {
			c.ingestSettings("managed", s.Path, "", s.Doc, c.configDir)
		} else {
			c.emitSettingRows("managed", s.Path, "", s.Doc, false)
		}
	}
	c.ingestSettings("user", c.userPath, "", c.user, c.configDir)
	c.ingestLaunchFlags()
	c.ingestManagedMCP()
	c.ingestUserMCP()
	c.addInstruction("managed", "", filepath.Join(c.managedDir, "CLAUDE.md"), "CLAUDE.md")
	c.ingestUserInstructionFiles()
	c.ingestPlugins()
	c.ingestMarketplaces()
	c.ingestProjects()
	c.computeEffective() // after projects: their deny rules and sandbox.enabled apply in their own directory
	c.computeSandboxPosture()
	c.detectBinary(ctx)
	c.effMode, c.effModeSource = c.effectiveMode(c.version)
	if c.flagMode != "" && !(c.flagMode == "bypassPermissions" && c.bypassDisabled()) {
		if m, ok := claudePermModes[c.flagMode]; ok {
			c.effMode, c.effModeSource = m, "launch_flag"
		}
	}
	c.computeApprovals()
	c.markHooks()
	c.reviews = loadReviewLedger(opts.ReviewLedgerPath, c.home, snap)
	c.markInstructionTrust()
	errsBefore := len(c.snap.Errors)
	if opts.Probe {
		c.ingestReachFiles()
		c.ingestReachHosts()
		c.ingestInternetHosts()
	} else {
		c.ingestReachFilesNoProbe()
		c.ingestInternetHosts()
	}
	c.ingestWriteTargets(opts.Probe)
	if opts.Observe {
		c.observe(ctx)
	}
	_ = errsBefore
	c.ingestAgent(ctx)
	if n := len(c.snap.Agents); n > 0 {
		a := &c.snap.Agents[n-1]
		for _, e := range c.snap.Errors {
			if !strings.HasPrefix(e, "codex") {
				a.CollectErrors = append(a.CollectErrors, e)
			}
		}
		a.AssessmentComplete = len(a.CollectErrors) == 0 && opts.Probe
		a.Probed = opts.Probe
		a.ProbeSkippedReason = opts.probeSkipped
		c.computeSurfaces(a)
	}
}

// detectBinary finds the claude binary and asks it for its version.
func (c *ccCollector) detectBinary(ctx context.Context) {
	defer c.resolveAutoDrop()
	if c.opts.ClaudeVersion != "" {
		c.version = c.opts.ClaudeVersion
		return
	}
	if c.opts.Home != "" {
		return // fixture runs never consult the real binary
	}
	p, err := exec.LookPath("claude")
	if err != nil {
		return
	}
	c.binaryPath = p
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// #nosec G204 -- a version probe of the installed Claude Code binary found on this machine, with
	// a fixed argument and a five-second timeout.
	if out, err := exec.CommandContext(cctx, p, "--version").Output(); err == nil {
		if f := strings.Fields(string(out)); len(f) > 0 {
			c.version = f[0]
		}
	}
}

// resolveAutoDrop picks the auto mode rule-drop list: pinned by the caller,
// read from the installed binary, or the built-in fallback.
func (c *ccCollector) resolveAutoDrop() {
	switch {
	case len(c.opts.AutoModeDropCommands) > 0:
		c.autoDrop = autoDropList{Commands: c.opts.AutoModeDropCommands, Source: "pinned", Reason: "set by the caller"}
	case c.opts.Home != "":
		c.autoDrop = autoDropList{Commands: builtinAutoDrop, Source: "built_in",
			Reason: "fixture run; using the list read from Claude Code " + builtinAutoDropVersion}
	default:
		c.autoDrop = loadAutoDrop(c.binaryPath, c.version)
	}
}

// doc reads and caches a settings document.
func (c *ccCollector) doc(path string) map[string]any {
	if m, ok := c.docCache[path]; ok {
		return m
	}
	m, _ := readJSON(path)
	c.docCache[path] = m
	return m
}

//// AGENT

func (c *ccCollector) ingestAgent(ctx context.Context) {
	// Discovery is automatic for every agent: no binary, no config directory
	// and no settings file means Claude Code is not installed, so it gets no
	// row at all. Fixture runs skip binary detection, so their config files
	// are what make the agent present.
	if c.binaryPath == "" && !dirExists(c.configDir) && !fileExists(c.globalPath) && c.user == nil &&
		len(c.managedSources) == 0 {
		return
	}
	a := Agent{
		Agent:                  AgentClaudeCode,
		ConfigDir:              c.configDir,
		GlobalConfigPath:       c.globalPath,
		UserSettingsPath:       c.userPath,
		UserSettingsPresent:    c.user != nil,
		ManagedSettingsPath:    c.managedPath,
		ManagedSettingsPresent: len(c.managedSources) > 0,
		RemoteSettingsPath:     c.remotePath,
		SandboxEnabled:         c.sandboxEnabled,
		ManagedSource:          c.managedSourceName,
		ManagedSourcesBehavior: c.managedBehavior,
	}
	for _, s := range c.managedSources {
		if s.Name == "remote" {
			a.RemoteSettingsPresent = true
		}
	}
	a.BinaryPath, a.Version = c.binaryPath, c.version
	a.InstallMethod = getString(c.global, "installMethod")
	a.AutoUpdates = getBool(c.global, "autoUpdates")
	a.LoggedIn = getMap(c.global, "oauthAccount") != nil
	a.EffectivePermissionMode, a.PermissionModeSource = c.effMode, c.effModeSource
	a.SandboxEnforced = c.sandboxEnforced()
	a.SandboxRuntimeAvailable = c.sb.runtimeAvailable
	a.SandboxAllowUnsandboxed = c.sb.allowUnsandboxed
	a.SandboxFailIfUnavailable = c.sb.failIfUnavailable
	a.SandboxFilesystemDisabled = c.sb.fsDisabled
	a.SandboxExcludedCommands = c.sb.excluded
	a.SandboxBypasses = c.sandboxBypasses()
	a.BlockReadsOutsideWorkDirs = c.sb.blockReads
	a.WebFetchDenied = c.webFetchDenied
	a.NetworkStrictAllowlist = c.strictNet
	a.SandboxAutoAllow = c.autoAllow
	a.BypassAvailable, a.BypassAvailableReason = c.bypassAvailable("")
	a.RunningBypassSessions = c.runningBypass
	a.AutoModeDropCommands, a.AutoModeDropSource, a.AutoModeDropReason = c.autoDrop.Commands, c.autoDrop.Source, c.autoDrop.Reason
	if c.sandboxEnabled {
		a.ShellApproval = c.sandboxedApproval()
	} else {
		a.ShellApproval = c.unsandboxedApproval()
	}
	a.NetworkApproval, a.NetworkApprovalReason = c.networkApproval()
	a.WebFetchApproval = c.webFetchApproval()
	a.WebSourceApproval = c.webSourceApproval("")
	// Managed wins outright; otherwise the user value. Project and local
	// files can also set it, but only for sessions started there.
	if b := getBool(c.managed, "disableAllHooks"); b != nil {
		a.HooksDisabled = *b
	} else if b := getBool(c.user, "disableAllHooks"); b != nil {
		a.HooksDisabled = *b
	}
	for _, v := range mergeEnabled(getMap(c.user, "enabledPlugins"), getMap(c.managed, "enabledPlugins")) {
		if on, ok := v.(bool); ok && on {
			a.PluginsEnabled++
		}
	}
	for _, p := range c.snap.Projects {
		if p.Agent != AgentClaudeCode {
			continue
		}
		a.ProjectsKnown++
		if p.Trusted && p.Exists {
			a.ProjectsTrusted++
		}
	}
	c.snap.Agents = append(c.snap.Agents, a)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

//// SETTINGS, HOOKS, RULES (shared by every scope)

// permRulePattern splits "Tool(spec)"; (?s) lets a multi-line Bash spec
// match, which Claude Code writes for heredoc approvals.
var permRulePattern = regexp.MustCompile(`(?s)^([A-Za-z_*][A-Za-z0-9_*]*)(?:\((.*)\))?$`)

// benignEnvValue reports whether a settings value is a switch, not a secret,
// and may be kept as-is.
func benignEnvValue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "1", "true", "false", "yes", "no", "on", "off":
		return true
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// emitSettingRows flattens one settings document into agentreach_setting rows.
// Values under env.*, *Helper keys and header maps are redacted unless they
// are plain switches; the row then says whether the value looked like a
// credential. No secret value is ever stored.
func (c *ccCollector) emitSettingRows(scope, path, projectDir string, m map[string]any, applies bool) {
	flat := map[string]any{}
	flatten("", m, flat)
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "hooks.") || k == "hooks" {
			continue // exposed by agentreach_hook
		}
		row := Setting{Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir, Key: k, Value: flat[k], Applies: applies}
		last := k[strings.LastIndex(k, ".")+1:]
		sensitive := strings.HasPrefix(k, "env.") || strings.HasSuffix(last, "Helper") || strings.Contains(k, ".headers.") || strings.HasSuffix(k, ".headers")
		if s, ok := flat[k].(string); ok && sensitive && !benignEnvValue(s) {
			looks := looksLikeSecret(last, s)
			row.Value, row.Redacted, row.LooksLikeSecret = nil, true, &looks
		} else if _, isMap := flat[k].(map[string]any); isMap && sensitive {
			f := false
			row.Value, row.Redacted, row.LooksLikeSecret = nil, true, &f
		} else if v, ch := scrubValue(flat[k]); ch {
			// Any other string (a statusLine command, a Bash allow rule, a
			// URL) keeps its shape with credential spans replaced.
			tr := true
			row.Value, row.Redacted, row.LooksLikeSecret = v, true, &tr
		}
		c.snap.Settings = append(c.snap.Settings, row)
	}
}

// ingestSettings flattens one settings file and extracts its hooks, sandbox
// rules and permission rules. anchor is the directory relative paths resolve
// against (project root, or ~/.claude for user settings).
func (c *ccCollector) ingestSettings(scope, path, projectDir string, m map[string]any, anchor string) {
	if m == nil {
		return
	}
	c.emitSettingRows(scope, path, projectDir, m, true)
	if projectDir != "" {
		if b := getBool(m, "sandbox", "enabled"); b != nil && *b {
			c.projectSandboxOn[projectDir] = true
		}
	}

	// hooks
	c.ingestHookMap(scope, path, projectDir, getMap(m, "hooks"))

	// permission rules
	perms := getMap(m, "permissions")
	for _, rt := range []string{"allow", "deny", "ask"} {
		for _, rule := range toStringSlice(perms[rt]) {
			tool, spec := "", ""
			if mm := permRulePattern.FindStringSubmatch(rule); mm != nil {
				tool, spec = mm[1], mm[2]
			} else {
				tool = rule
			}
			resolved := ""
			if (tool == "Read" || tool == "Edit" || tool == "Write" || tool == "Glob") && spec != "" {
				resolved = resolvePermissionRule(spec, rt, c.home, anchor)
			}
			pat, red := scrubText(rule)
			c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
				Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
				Category: "permission", RuleType: rt, Tool: tool, Pattern: pat, ResolvedPath: resolved, Redacted: red,
			})
		}
	}
	for _, d := range toStringSlice(perms["additionalDirectories"]) {
		c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
			Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
			Category: "filesystem", RuleType: "additionalDirectories", Pattern: d,
			ResolvedPath: resolveSandboxPath(d, c.home, anchor),
		})
	}

	// sandbox rules
	sb := getMap(m, "sandbox")
	fs := getMap(sb, "filesystem")
	for _, rt := range []string{"denyRead", "allowRead", "denyWrite", "allowWrite"} {
		for _, p := range toStringSlice(fs[rt]) {
			c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
				Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
				Category: "filesystem", RuleType: rt, Pattern: p, ResolvedPath: resolveSandboxPath(p, c.home, anchor),
			})
		}
	}
	nw := getMap(sb, "network")
	for _, rt := range []string{"allowedDomains", "deniedDomains"} {
		for _, p := range toStringSlice(nw[rt]) {
			c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
				Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
				Category: "network", RuleType: rt, Pattern: p,
			})
		}
	}
	for _, p := range toStringSlice(nw["allowUnixSockets"]) {
		c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
			Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
			Category: "network", RuleType: "allowUnixSockets", Pattern: p, ResolvedPath: resolveSandboxPath(p, c.home, anchor),
		})
	}
	for _, p := range toStringSlice(sb["excludedCommands"]) {
		pat, red := scrubText(p)
		c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
			Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
			Category: "execution", RuleType: "excludedCommands", Tool: "Bash", Pattern: pat, Redacted: red,
		})
	}
	cred := getMap(sb, "credentials")
	if files, ok := cred["files"].([]any); ok {
		for _, f := range files {
			fm, _ := f.(map[string]any)
			p, _ := fm["path"].(string)
			mode, _ := fm["mode"].(string)
			c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
				Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
				Category: "credential", RuleType: "credentialFile", Tool: mode, Pattern: p, ResolvedPath: resolveSandboxPath(p, c.home, anchor),
			})
		}
	}
	if vars, ok := cred["envVars"].([]any); ok {
		for _, f := range vars {
			fm, _ := f.(map[string]any)
			n, _ := fm["name"].(string)
			mode, _ := fm["mode"].(string)
			c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
				Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
				Category: "credential", RuleType: "credentialEnvVar", Tool: mode, Pattern: n,
			})
		}
	}
}

// ingestHookMap parses the {Event: [{matcher, hooks:[{type,command,timeout}]}]} shape.
func (c *ccCollector) ingestHookMap(scope, path, projectDir string, hooks map[string]any) {
	c.ingestHookMapFrom(scope, path, projectDir, hooks, "", nil, "settings")
}

// ingestHookMapPlugin is ingestHookMap with plugin provenance attached.
func (c *ccCollector) ingestHookMapPlugin(scope, path, projectDir string, hooks map[string]any, pluginName string, pluginEnabled *bool) {
	c.ingestHookMapFrom(scope, path, projectDir, hooks, pluginName, pluginEnabled, "plugin")
}

// ingestHookMapFrom parses one hooks object. origin is settings, plugin,
// skill or subagent (frontmatter hooks).
func (c *ccCollector) ingestHookMapFrom(scope, path, projectDir string, hooks map[string]any, pluginName string, pluginEnabled *bool, origin string) {
	if hooks == nil {
		return
	}
	wb := writableBy(path)
	tracked := c.tracked(path)
	events := make([]string, 0, len(hooks))
	for e := range hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		groups, _ := hooks[event].([]any)
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			matcher, _ := gm["matcher"].(string)
			entries, _ := gm["hooks"].([]any)
			for _, e := range entries {
				em, _ := e.(map[string]any)
				h := Hook{
					Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir,
					Event: event, Matcher: matcher, SourceWritableBy: wb, SourceTrackedGit: tracked,
					PluginName: pluginName, PluginEnabled: pluginEnabled, ThirdParty: pluginName != "",
					Origin: origin,
				}
				h.HookType, _ = em["type"].(string)
				if h.HookType == "" {
					h.HookType = "command"
				}
				h.Command, _ = em["command"].(string)
				switch h.HookType {
				case "prompt", "agent":
					if h.Command == "" {
						h.Command, _ = em["prompt"].(string)
					}
				case "mcp_tool":
					if h.Command == "" {
						h.Command = getString(em, "server") + ":" + getString(em, "tool")
					}
				}
				h.URL, _ = em["url"].(string)
				h.Args = toStringSlice(em["args"])
				h.If, _ = em["if"].(string)
				var r1, r2, r3 bool
				h.Command, r1 = scrubText(h.Command)
				h.URL, r2 = scrubURL(h.URL)
				h.Args, r3 = scrubArgs(h.Args)
				if len(getMap(em, "headers")) > 0 {
					for k, v := range getMap(em, "headers") {
						if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
							r1 = true
						}
					}
				}
				h.Redacted = r1 || r2 || r3
				if t, ok := em["timeout"].(float64); ok {
					ti := int(t)
					h.Timeout = &ti
					h.EffectiveTimeout = ti
				} else {
					h.EffectiveTimeout = defaultHookTimeout(h.HookType, event)
				}
				c.snap.Hooks = append(c.snap.Hooks, h)
			}
		}
	}
}

//// MCP

func (c *ccCollector) ingestMCPMap(scope, path, projectDir string, servers map[string]any, enabled func(name string) *bool) {
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		sm, _ := servers[name].(map[string]any)
		s := MCPServer{Agent: AgentClaudeCode, Scope: scope, SourcePath: path, ProjectDir: projectDir, Name: name}
		s.Command, _ = sm["command"].(string)
		s.Args = toStringSlice(sm["args"])
		s.URL, _ = sm["url"].(string)
		s.Transport, _ = sm["type"].(string)
		if s.Transport == "" {
			if s.URL != "" {
				// A url with no type is a configuration error in Claude Code,
				// not an implicit http server; report it and assume http.
				s.Transport = "http"
				c.snap.Errors = append(c.snap.Errors, "MCP server "+name+" in "+path+": url without type; Claude Code reports this as a configuration error")
			} else {
				s.Transport = "stdio"
			}
		}
		// Classify on the raw values, then redact before storing.
		lt := launcherType(s.Command, s.Args, s.URL)
		pin := pinned(lt, s.Args)
		var r1, r2, r3 bool
		s.Args, r1 = scrubArgs(s.Args)
		s.URL, r2 = scrubURL(s.URL)
		s.Command, r3 = scrubText(s.Command)
		s.Redacted = r1 || r2 || r3
		if s.Redacted {
			s.HasInlineSecret = true
		}
		env := getMap(sm, "env")
		for k, v := range env {
			s.EnvKeys = append(s.EnvKeys, k)
			if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
				s.HasInlineSecret = true
			}
		}
		sort.Strings(s.EnvKeys)
		for k, v := range getMap(sm, "headers") {
			if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
				s.HasInlineSecret = true
			}
		}
		s.LauncherType = lt
		s.Pinned = pin
		s.CommandExists = launcherExists(getString(sm, "command"))
		if enabled != nil {
			s.Enabled = enabled(name)
		}
		c.snap.MCPServers = append(c.snap.MCPServers, s)
	}
}

func (c *ccCollector) ingestUserMCP() {
	c.ingestMCPMap("user", c.globalPath, "", getMap(c.global, "mcpServers"), nil)
}

// ingestManagedMCP reads managed-mcp.json from the system directory and the
// managedMcpServers key of the effective managed document.
func (c *ccCollector) ingestManagedMCP() {
	p := filepath.Join(c.managedDir, "managed-mcp.json")
	m, err := readJSON(p)
	if err != nil {
		c.snap.Errors = append(c.snap.Errors, "managed MCP: "+p+": "+err.Error())
	} else if m != nil {
		c.ingestMCPMap("managed", p, "", getMap(m, "mcpServers"), nil)
	}
	if servers := getMap(c.managed, "managedMcpServers"); len(servers) > 0 {
		c.ingestMCPMap("managed", "managedMcpServers", "", servers, nil)
	}
}

//// INSTRUCTION FILES

func (c *ccCollector) ingestUserInstructionFiles() {
	c.addInstruction("user", "", filepath.Join(c.configDir, "CLAUDE.md"), "CLAUDE.md")
	c.addTree("user", "", filepath.Join(c.configDir, "rules"), ".md", "rules", "")
	c.addTree("user", "", filepath.Join(c.configDir, "skills"), "SKILL.md", "skill", "")
	c.addTree("user", "", filepath.Join(c.configDir, "agents"), ".md", "subagent", "")
	c.addTree("user", "", filepath.Join(c.configDir, "commands"), ".md", "command", "")
}

func (c *ccCollector) addInstruction(scope, projectDir, path, kind string) {
	c.addInstructionPlugin(scope, projectDir, path, kind, "")
}

func (c *ccCollector) addInstructionPlugin(scope, projectDir, path, kind, pluginName string) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return
	}
	b, err := readFileLimited(path)
	if err != nil {
		return
	}
	f := InstructionFile{
		Agent: AgentClaudeCode, Scope: scope, ProjectDir: projectDir, Path: path, Kind: kind,
		SizeBytes: fi.Size(), SHA256: sha256File(path), WritableBy: writableBy(path),
		TrackedInGit: c.tracked(path), HiddenUnicode: hiddenUnicodeCount(b),
		HTMLComments:     len(htmlCommentPattern.FindAll(b, -1)),
		ExternalIncludes: len(includePattern.FindAll(b, -1)),
		ExternalURLs:     len(urlPattern.FindAll(b, -1)),
	}
	f.PluginName = pluginName
	if kind == "skill" || kind == "subagent" {
		if hooks := frontmatterHooks(b); len(hooks) > 0 {
			var en *bool
			if pluginName != "" {
				en = c.pluginEnabledIn(pluginName, "")
			}
			c.ingestHookMapFrom(scope, path, projectDir, hooks, pluginName, en, kind)
		}
	}
	if f.TrackedInGit {
		f.GitLastAuthor = c.lastAuthor(path)
		f.GitUncommitted = c.uncommitted(path)
	}
	// Third party: provided by a plugin, or last committed by someone other
	// than the git identity configured for that repository. Being in git by
	// itself is normal and is not a finding.
	f.ThirdParty = pluginName != "" || (f.GitLastAuthor != "" && !c.repoIdentities(path)[strings.ToLower(f.GitLastAuthor)])
	c.snap.InstructionFiles = append(c.snap.InstructionFiles, f)
}

//// PLUGINS

// ingestPlugins reads installed_plugins.json once and, for every install
// record, emits a Plugin row; for every distinct install path it also ingests
// the plugin's hooks, skills, subagents and commands. Only installed plugins
// load into sessions; marketplace clones under plugins/marketplaces are
// catalogs, not active code, and are ignored here (see ingestMarketplaces).
func (c *ccCollector) ingestPlugins() {
	inst, err := readJSON(filepath.Join(c.configDir, "plugins", "installed_plugins.json"))
	if err != nil || inst == nil {
		return
	}
	plugins := getMap(inst, "plugins")
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, name := range names {
		entries, _ := plugins[name].([]any)
		// A plugin installed at user scope loads in every session; one
		// installed only at project or local scope loads only in that
		// project, so its components belong to that project.
		machineWide := map[string]bool{}
		for _, e := range entries {
			em, _ := e.(map[string]any)
			if s := getString(em, "scope"); s != "project" && s != "local" || getString(em, "projectPath") == "" {
				machineWide[getString(em, "installPath")] = true
			}
		}
		for _, e := range entries {
			em, _ := e.(map[string]any)
			root, _ := em["installPath"].(string)
			if root == "" {
				continue
			}
			p := Plugin{
				Agent:             AgentClaudeCode,
				FullName:          name,
				Scope:             getString(em, "scope"),
				ProjectDir:        getString(em, "projectPath"),
				InstallPath:       root,
				InstallPathExists: fileExists(root),
				Version:           getString(em, "version"),
				GitCommitSHA:      getString(em, "gitCommitSha"),
				InstalledAt:       parseTime(getString(em, "installedAt")),
				LastUpdated:       parseTime(getString(em, "lastUpdated")),
			}
			p.Name, p.Marketplace = splitPluginName(name)
			p.Pinned = pluginPinned(p.Version, p.GitCommitSHA)
			p.Enabled = c.pluginEnabledIn(name, p.ProjectDir)
			if p.InstallPathExists {
				p.WritableBy = writableBy(root)
				p.HasHooks = fileExists(filepath.Join(root, "hooks", "hooks.json"))
				p.HasInstructionFile = fileExists(filepath.Join(root, "CLAUDE.md"))
				p.HasMCP = fileExists(filepath.Join(root, ".mcp.json"))
				for _, mf := range []string{filepath.Join(root, ".claude-plugin", "plugin.json"), filepath.Join(root, "plugin.json")} {
					if m, err := readJSON(mf); err == nil && m != nil && m["mcpServers"] != nil {
						p.HasMCP = true
					}
				}
				p.SkillCount = globCount(filepath.Join(root, "skills", "*", "SKILL.md"))
				p.AgentCount = globCount(filepath.Join(root, "agents", "*.md"))
				p.CommandCount = globCount(filepath.Join(root, "commands", "*.md"))
			}
			c.snap.Plugins = append(c.snap.Plugins, p)

			dir := p.ProjectDir
			if machineWide[root] {
				dir = ""
			}
			if seen[root+"|"+dir] || !p.InstallPathExists {
				continue
			}
			seen[root+"|"+dir] = true
			// The plugin's own components follow the machine-wide decision
			// (managed, then user); a project that enables or disables it is
			// visible on the Plugin row for that project.
			en := c.pluginEnabledIn(name, dir)
			if en == nil {
				t := true // installed and undecided: Claude Code loads it
				en = &t
			}
			if m, err := readJSON(filepath.Join(root, "hooks", "hooks.json")); err == nil && m != nil {
				hooks := getMap(m, "hooks")
				if hooks == nil {
					hooks = m
				}
				c.ingestHookMapPlugin("plugin", filepath.Join(root, "hooks", "hooks.json"), dir, hooks, name, en)
			}
			c.ingestPluginMCP(root, name, dir, en)
			before := len(c.snap.InstructionFiles)
			c.addTree("plugin", dir, filepath.Join(root, "skills"), "SKILL.md", "skill", name)
			c.addTree("plugin", dir, filepath.Join(root, "agents"), ".md", "subagent", name)
			c.addTree("plugin", dir, filepath.Join(root, "commands"), ".md", "command", name)
			c.addInstructionPlugin("plugin", dir, filepath.Join(root, "CLAUDE.md"), "CLAUDE.md", name)
			for i := before; i < len(c.snap.InstructionFiles); i++ {
				v := *en
				c.snap.InstructionFiles[i].PluginEnabled = &v
			}
		}
	}
}

// ingestMarketplaces reads known_marketplaces.json: the plugin sources this
// machine can install from, and whether a managed strictKnownMarketplaces
// policy would admit each one.
func (c *ccCollector) ingestMarketplaces() {
	known, err := readJSON(filepath.Join(c.configDir, "plugins", "known_marketplaces.json"))
	if err != nil || known == nil {
		return
	}
	var strict []any
	hasStrict := false
	// strictKnownMarketplaces is a managed-only key ("Scope: Managed" in
	// the settings reference); a copy in user settings has no effect.
	for _, k := range []string{"strictKnownMarketplaces", "allowedMarketplaces"} {
		if v, ok := c.managed[k].([]any); ok {
			strict, hasStrict = v, true
			break
		}
	}
	extraUser := getMap(c.user, "extraKnownMarketplaces")
	extraManaged := getMap(c.managed, "extraKnownMarketplaces")
	names := make([]string, 0, len(known))
	for n := range known {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		rec, _ := known[name].(map[string]any)
		if rec == nil {
			continue
		}
		src := getMap(rec, "source")
		mk := Marketplace{
			Agent:           AgentClaudeCode,
			Name:            name,
			SourceType:      getString(src, "source"),
			SourceRepo:      firstNonEmpty(getString(src, "repo"), getString(src, "url"), getString(src, "path")),
			InstallLocation: getString(rec, "installLocation"),
			AutoUpdate:      getBool(rec, "autoUpdate"),
			LastUpdated:     parseTime(getString(rec, "lastUpdated")),
		}
		mk.InstallLocationExists = mk.InstallLocation != "" && fileExists(mk.InstallLocation)
		mk.Official = marketplaceOfficial(name, mk.SourceRepo)
		_, mk.InExtraKnown = extraUser[name]
		if !mk.InExtraKnown {
			_, mk.InExtraKnown = extraManaged[name]
		}
		if hasStrict {
			ok := marketplaceAllowed(name, mk.SourceType, mk.SourceRepo, strict)
			mk.InStrictAllowlist = &ok
		}
		c.snap.Marketplaces = append(c.snap.Marketplaces, mk)
	}
}

const officialMarketplace = "claude-plugins-official"
const officialMarketplaceRepo = "anthropics/claude-plugins-official"

func marketplaceOfficial(name, repo string) bool {
	return name == officialMarketplace || strings.EqualFold(repo, officialMarketplaceRepo)
}

// splitPluginName turns "name@marketplace" into its parts.
func splitPluginName(full string) (name, marketplace string) {
	if i := strings.LastIndex(full, "@"); i > 0 {
		return full[:i], full[i+1:]
	}
	return full, ""
}

// pluginPinned reports whether an install record names a release (a version
// string that is not just the commit it happens to resolve to). Nil when the
// record carries no version at all.
func pluginPinned(version, sha string) *bool {
	v := strings.TrimSpace(version)
	if v == "" || strings.EqualFold(v, "unknown") {
		return nil // no version recorded (audit M16)
	}
	pinned := true
	lv := strings.ToLower(v)
	if sha != "" && strings.HasPrefix(strings.ToLower(sha), lv) {
		pinned = false // version is a prefix of the commit sha: floating head
	} else if len(lv) >= 7 && len(lv) <= 40 && isHex(lv) && strings.Trim(lv, "0123456789") != "" {
		// all digits is a date version (CalVer), not a commit (audit M16)
		pinned = false // looks like a bare commit sha
	}
	return &pinned
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return s != ""
}

// mergeEnabled overlays a project's enabledPlugins on the user's.
func mergeEnabled(user, project map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range user {
		out[k] = v
	}
	for k, v := range project {
		out[k] = v
	}
	return out
}

// marketplaceAllowed evaluates a strictKnownMarketplaces allowlist against a
// registered marketplace. Entries are source objects; github repos accept an
// "owner/*" wildcard; hostPattern and pathPattern are regexes. The official
// marketplace is admitted by name alone.
func marketplaceAllowed(name, sourceType, repo string, list []any) bool {
	for _, e := range list {
		switch v := e.(type) {
		case string:
			if v == name || strings.EqualFold(v, repo) {
				return true
			}
			if name == officialMarketplace && v == officialMarketplace {
				return true
			}
		case map[string]any:
			src := getString(v, "source")
			switch src {
			case "github":
				r := getString(v, "repo")
				if strings.EqualFold(r, repo) || (strings.HasSuffix(r, "/*") && strings.HasPrefix(strings.ToLower(repo), strings.ToLower(strings.TrimSuffix(r, "*")))) {
					return true
				}
				if name == officialMarketplace && strings.EqualFold(r, officialMarketplaceRepo) {
					return true
				}
			case "git", "url":
				if strings.EqualFold(getString(v, "url"), repo) {
					return true
				}
			case "file", "directory":
				if getString(v, "path") == repo {
					return true
				}
			case "hostPattern":
				if re, err := regexp.Compile(getString(v, "hostPattern")); err == nil && re.MatchString(marketplaceHost(sourceType, repo)) {
					return true
				}
			case "pathPattern":
				if (sourceType == "file" || sourceType == "directory") && repo != "" {
					if re, err := regexp.Compile(getString(v, "pathPattern")); err == nil && re.MatchString(repo) {
						return true
					}
				}
			}
		}
	}
	return false
}

// marketplaceHost is the host a hostPattern entry is matched against.
func marketplaceHost(sourceType, repo string) string {
	switch sourceType {
	case "github":
		return "github.com"
	case "git", "url":
		if i := strings.Index(repo, "://"); i >= 0 {
			rest := repo[i+3:]
			if j := strings.IndexAny(rest, "/:"); j >= 0 {
				rest = rest[:j]
			}
			if at := strings.LastIndex(rest, "@"); at >= 0 {
				rest = rest[at+1:]
			}
			return rest
		}
		if at := strings.Index(repo, "@"); at >= 0 {
			if colon := strings.Index(repo[at:], ":"); colon >= 0 {
				return repo[at+1 : at+colon]
			}
		}
	}
	return ""
}

func globCount(pattern string) int {
	m, _ := filepath.Glob(pattern)
	return len(m)
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t = t.UTC()
		return &t
	}
	return nil
}

//// PROJECTS

func (c *ccCollector) ingestProjects() {
	dirs := map[string]bool{}
	for d := range getMap(c.global, "projects") {
		dirs[d] = true
	}
	for _, d := range c.opts.ProjectDirs {
		dirs[filepath.Clean(expandHome(d, c.home))] = true
	}
	list := make([]string, 0, len(dirs))
	for d := range dirs {
		list = append(list, d)
	}
	sort.Strings(list)
	recorded := getMap(c.global, "projects")
	for _, dir := range list {
		rec := getMap(recorded, dir)
		p := Project{Agent: AgentClaudeCode, ProjectDir: dir, Exists: fileExists(dir)}
		if t := getBool(rec, "hasTrustDialogAccepted"); t != nil {
			p.Trusted = *t
		}
		p.AllowedTools = toStringSlice(rec["allowedTools"])
		p.EnabledMCPJSON = toStringSlice(rec["enabledMcpjsonServers"])
		p.DisabledMCPJSON = toStringSlice(rec["disabledMcpjsonServers"])
		if ms, ok := rec["lastStartTime"].(float64); ok && ms > 0 {
			t := time.UnixMilli(int64(ms)).UTC()
			p.LastStartTime = &t
		}
		if !p.Exists {
			c.snap.Projects = append(c.snap.Projects, p)
			continue
		}
		if fileExists(filepath.Join(dir, ".git")) {
			p.IsGitRepo = true
			p.GitRemote = gitRemoteFromConfig(filepath.Join(dir, ".git", "config"))
		}
		proj := filepath.Join(dir, ".claude", "settings.json")
		local := filepath.Join(dir, ".claude", "settings.local.json")
		mcp := filepath.Join(dir, ".mcp.json")
		p.HasProjectSettings = fileExists(proj)
		p.HasLocalSettings = fileExists(local)
		p.HasMCPJSON = fileExists(mcp)

		// A session started in the home directory registers $HOME as a
		// project. Its ".claude/settings.json" is the user settings file,
		// already ingested at user scope, so do not re-ingest it as project
		// scope; the same goes for ~/.claude/{rules,skills,agents,commands}.
		isHome := filepath.Clean(dir) == filepath.Clean(c.home) || filepath.Join(dir, ".claude") == c.configDir
		if !isHome {
			if m := c.configOrErr(proj); m != nil {
				c.ingestSettings("project", proj, dir, m, dir)
			}
		}
		// In the home directory .claude/settings.json is the user file, but
		// .claude/settings.local.json is still the local file of sessions
		// started there (settings, "Where settings live").
		if m := c.configOrErr(local); m != nil {
			c.ingestSettings("local", local, dir, m, dir)
		}
		// local-scope MCP servers recorded in the global config for this project
		c.ingestMCPMap("local", c.globalPath, dir, getMap(rec, "mcpServers"), nil)
		if m := c.configOrErr(mcp); m != nil {
			projSettings, _ := readJSON(proj)
			localSettings, _ := readJSON(local)
			if isHome {
				projSettings, localSettings = nil, nil
			}
			enabled := c.mcpApproval(p, projSettings, localSettings)
			c.ingestMCPMap("project", mcp, dir, getMap(m, "mcpServers"), enabled)
		}
		before := len(c.snap.InstructionFiles)
		if !isHome {
			c.addInstruction("project", dir, filepath.Join(dir, "CLAUDE.md"), "CLAUDE.md")
			c.addInstruction("project", dir, filepath.Join(dir, ".claude", "CLAUDE.md"), "CLAUDE.md")
			c.addInstruction("project", dir, filepath.Join(dir, "CLAUDE.local.md"), "CLAUDE.md")
			c.addInstruction("project", dir, filepath.Join(dir, "AGENTS.md"), "AGENTS.md")
			c.addTree("project", dir, filepath.Join(dir, ".claude", "rules"), ".md", "rules", "")
			c.addTree("project", dir, filepath.Join(dir, ".claude", "skills"), "SKILL.md", "skill", "")
			c.addTree("project", dir, filepath.Join(dir, ".claude", "agents"), ".md", "subagent", "")
			c.addTree("project", dir, filepath.Join(dir, ".claude", "commands"), ".md", "command", "")
		}
		p.HasInstructionFile = len(c.snap.InstructionFiles) > before
		c.snap.Projects = append(c.snap.Projects, p)
	}
}

var remoteURLPattern = regexp.MustCompile(`(?m)^\s*url\s*=\s*(.+)$`)

// gitRemoteFromConfig reads the first remote url from .git/config without exec.
func gitRemoteFromConfig(p string) string {
	b, err := readFileLimited(p)
	if err != nil {
		return ""
	}
	if m := remoteURLPattern.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// gitRootOf walks up from path to the nearest directory containing .git.
func gitRootOf(path string) string {
	for d := filepath.Dir(path); d != "/" && d != "."; d = filepath.Dir(d) {
		if fileExists(filepath.Join(d, ".git")) {
			return d
		}
	}
	return ""
}

// lastAuthor returns the email of the last commit touching path.
func (c *ccCollector) lastAuthor(path string) string {
	root := gitRootOf(path)
	if root == "" {
		return ""
	}
	out, err := gitCmd("-C", root, "log", "-1", "--format=%ae", "--", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// uncommitted reports whether a tracked file's content differs from HEAD.
// It hashes the file as a git blob and compares that with the blob ids from
// one `git ls-tree -r HEAD` per repository. git status would refresh the
// index (a write) and can run fsmonitor and clean filters from repository
// config; this runs neither. A file stored through a filter (LFS, eol
// conversion) can read as changed.
func (c *ccCollector) uncommitted(path string) bool {
	root := gitRootOf(path)
	if root == "" {
		return false
	}
	if c.gitHead == nil {
		c.gitHead = map[string]map[string]string{}
	}
	head, ok := c.gitHead[root]
	if !ok {
		head = map[string]string{}
		if out, err := gitCmd("-C", root, "ls-tree", "-r", "-z", "--full-tree", "HEAD").Output(); err == nil {
			for _, e := range strings.Split(string(out), "\x00") {
				// "<mode> blob <id>\t<path>"
				meta, rel, ok := strings.Cut(e, "\t")
				if f := strings.Fields(meta); ok && len(f) == 3 && f[1] == "blob" {
					head[filepath.Join(root, rel)] = f[2]
				}
			}
		}
		c.gitHead[root] = head
	}
	want, ok := head[path]
	if !ok {
		return false // not in HEAD: new and staged, or not tracked
	}
	b, err := readFileLimited(path)
	if err != nil {
		return false
	}
	return gitBlobID(b, len(want)) != want
}

// gitBlobID is git's object id for content as a blob: SHA-1, or SHA-256 in
// a repository whose ids are 64 hex characters.
func gitBlobID(b []byte, idLen int) string {
	hdr := fmt.Sprintf("blob %d\x00", len(b))
	if idLen == 64 {
		h := sha256.New()
		h.Write([]byte(hdr))
		h.Write(b)
		return hex.EncodeToString(h.Sum(nil))
	}
	// #nosec G401 -- SHA-1 is git's own object id format for these
	// repositories; we recompute it to compare against ls-tree ids. It is
	// not used for any security decision.
	h := sha1.New()
	h.Write([]byte(hdr))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// repoIdentities returns the email addresses that count as "the user" for the
// repository containing path: the user.email in effect there, the global
// user.email, and the most frequent author in the last 500 commits. The last
// one covers developers who commit under several addresses; in a team repo
// it means the majority author is never flagged, which errs toward silence.
func (c *ccCollector) repoIdentities(path string) map[string]bool {
	root := gitRootOf(path)
	if root == "" {
		return nil
	}
	if ids, ok := c.gitIDs[root]; ok {
		return ids
	}
	ids := map[string]bool{}
	add := func(out []byte, err error) {
		if e := strings.ToLower(strings.TrimSpace(string(out))); err == nil && e != "" {
			ids[e] = true
		}
	}
	add(gitCmd("-C", root, "config", "--get", "user.email").Output())
	add(gitCmd("config", "--global", "--get", "user.email").Output())
	if out, err := gitCmd("-C", root, "log", "-n", "500", "--format=%ae").Output(); err == nil {
		counts := map[string]int{}
		top, topN := "", 0
		for _, e := range strings.Split(string(out), "\n") {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" {
				continue
			}
			counts[e]++
			if counts[e] > topN {
				top, topN = e, counts[e]
			}
		}
		if top != "" {
			ids[top] = true
		}
	}
	c.gitIDs[root] = ids
	return ids
}

// tracked reports whether path is tracked by git, using one ls-files per repo.
func (c *ccCollector) tracked(path string) bool {
	root := gitRootOf(path)
	if root == "" {
		return false
	}
	files, ok := c.gitFiles[root]
	if !ok {
		files = map[string]bool{}
		if out, err := gitCmd("-C", root, "ls-files", "-z").Output(); err == nil {
			for _, f := range strings.Split(string(out), "\x00") {
				if f != "" {
					files[filepath.Join(root, f)] = true
				}
			}
		}
		c.gitFiles[root] = files
	}
	return files[path]
}

//// EFFECTIVE RULES

// computeEffective derives the machine-wide switches and the deny rules.
//
// Boolean keys: "When managed settings set a Boolean key such as enabled or
// failIfUnavailable, Claude Code uses the managed value and ignores anything
// a developer sets locally" (sandboxing docs). sandbox.enabled: "A false in
// your user settings, --settings, or managed settings holds even when a
// project's settings set true"; a project true applies only in that project
// (see sandboxEnabledIn).
//
// Deny rules: "if user settings allow a permission and project settings deny
// it, the deny rule blocks it ... deny rules from any scope are evaluated
// before allow rules" (permissions docs). Project and local rules are kept
// with their project directory and consulted only for files in that project.
func (c *ccCollector) computeEffective() {
	if b := getBool(c.managed, "sandbox", "enabled"); b != nil {
		c.sandboxEnabled = *b
	} else if b := getBool(c.user, "sandbox", "enabled"); b != nil {
		c.sandboxEnabled = *b
	}
	if b := getBool(c.managed, "sandbox", "network", "allowLocalBinding"); b != nil {
		c.allowLocalBind = *b
	} else if b := getBool(c.user, "sandbox", "network", "allowLocalBinding"); b != nil {
		c.allowLocalBind = *b
	}
	if b := getBool(c.managed, "sandbox", "network", "allowAllUnixSockets"); b != nil {
		c.allowAllUnix = *b
	} else if b := getBool(c.user, "sandbox", "network", "allowAllUnixSockets"); b != nil {
		c.allowAllUnix = *b
	}
	for _, m := range []map[string]any{c.managed, c.user} {
		c.allowedDomains = append(c.allowedDomains, toStringSlice(getMap(m, "sandbox", "network")["allowedDomains"])...)
		for _, p := range toStringSlice(getMap(m, "sandbox", "network")["allowUnixSockets"]) {
			c.allowUnixSocks = append(c.allowUnixSocks, resolveSandboxPath(p, c.home, c.configDir))
		}
	}
	for _, r := range c.snap.SandboxRules {
		pd := ""
		if r.Scope == "project" || r.Scope == "local" {
			pd = r.ProjectDir
		} else if !machineScope(r.Scope) {
			continue
		}
		switch {
		case r.Category == "filesystem" && r.RuleType == "denyRead":
			c.sandboxDenyRead = append(c.sandboxDenyRead, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "filesystem" && r.RuleType == "allowRead":
			c.sandboxAllowRead = append(c.sandboxAllowRead, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "filesystem" && r.RuleType == "denyWrite":
			c.sandboxDenyWrite = append(c.sandboxDenyWrite, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "filesystem" && (r.RuleType == "allowWrite" || r.RuleType == "additionalDirectories"):
			c.sandboxAllowWrite = append(c.sandboxAllowWrite, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "permission" && r.RuleType == "deny" && (r.Tool == "Edit" || r.Tool == "Write"):
			res := r.ResolvedPath
			if res == "" {
				res = "/"
			}
			c.editDeny = append(c.editDeny, scopedRule{r.Pattern, res, r.Scope, pd})
		case r.Category == "permission" && r.RuleType == "allow" && (r.Tool == "Edit" || r.Tool == "Write") && r.ResolvedPath != "":
			c.editAllow = append(c.editAllow, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "permission" && r.RuleType == "deny" && (r.Tool == "WebFetch") && r.Pattern == "WebFetch" && pd == "":
			c.webFetchDenied = true
		case r.Category == "credential" && r.RuleType == "credentialFile" && r.Tool == "deny":
			c.sandboxDenyRead = append(c.sandboxDenyRead, scopedRule{r.Pattern, r.ResolvedPath, r.Scope, pd})
		case r.Category == "permission" && r.RuleType == "deny" && r.Tool == "Read":
			resolved := r.ResolvedPath
			if resolved == "" { // bare Read: denies all reads
				resolved = "/"
			}
			c.permDenyRead = append(c.permDenyRead, scopedRule{r.Pattern, resolved, r.Scope, pd})
		}
	}
}

// sandboxEnabledIn reports whether the sandbox is on for a session started
// in projectDir ("" means machine-wide, i.e. any directory).
func (c *ccCollector) sandboxEnabledIn(projectDir string) bool {
	if b := getBool(c.managed, "sandbox", "enabled"); b != nil {
		return *b
	}
	if b := getBool(c.user, "sandbox", "enabled"); b != nil {
		return *b
	}
	return projectDir != "" && c.projectSandboxOn[projectDir]
}

// ruleCovers finds the first rule that applies to path for a file that
// belongs to projectDir ("" for home-directory files, which are reachable
// from every project, so only machine-wide rules count).
func ruleCovers(rules []scopedRule, path, projectDir string) string {
	for _, d := range rules {
		if d.ProjectDir != "" && d.ProjectDir != projectDir {
			continue
		}
		if covers(withCwd(d.Resolved, projectDir), path) {
			return d.Pattern
		}
	}
	return ""
}

// mcpApproval resolves the approval decision for servers in a project's
// .mcp.json.
//
// Source: https://code.claude.com/docs/en/mcp, "Project server approvals and
// workspace trust": "enableAllProjectMcpServers or enabledMcpjsonServers
// committed to the project's .claude/settings.json is ignored in an untrusted
// folder"; "Approvals from these sources still apply in an untrusted folder:
// your user ~/.claude/settings.json, managed settings"; "Claude Code also
// applies approvals from an untracked .claude/settings.local.json ... In a
// folder you've never trusted, Claude Code waits for the trust dialog";
// "A disabledMcpjsonServers entry in any settings file still rejects the
// server." Interactive choices are also recorded per project in ~/.claude.json.
func (c *ccCollector) mcpApproval(p Project, projSettings, localSettings map[string]any) func(string) *bool {
	has := func(list []string, name string) bool {
		for _, n := range list {
			if n == name {
				return true
			}
		}
		return false
	}
	type src struct {
		m       map[string]any
		trusted bool // only applies once the folder is trusted
	}
	sources := []src{{c.managed, false}, {localSettings, true}, {projSettings, true}, {c.user, false}}
	return func(name string) *bool {
		f, t := false, true
		if has(p.DisabledMCPJSON, name) {
			return &f
		}
		for _, s := range sources {
			if has(toStringSlice(s.m["disabledMcpjsonServers"]), name) {
				return &f
			}
		}
		if has(p.EnabledMCPJSON, name) {
			return &t
		}
		for _, s := range sources {
			if s.trusted && !p.Trusted {
				continue
			}
			if has(toStringSlice(s.m["enabledMcpjsonServers"]), name) {
				return &t
			}
			if b := getBool(s.m, "enableAllProjectMcpServers"); b != nil && *b {
				return &t
			}
		}
		return nil
	}
}

//// REACH: FILES

func (c *ccCollector) reachFileRow(path, category, desc, projectDir string, probe bool) ReachFile {
	r := ReachFile{Agent: AgentClaudeCode, Path: path, Category: category, Tier: tierFor(category, path), Description: desc + cacheNote(path, c.snap.CollectedAt), ProjectDir: projectDir}
	fi, err := os.Stat(path)
	r.Exists = err == nil
	if !r.Exists {
		return r
	}
	r.IsDir = fi.IsDir()
	deny, allow := c.sandboxReadDecision(path, projectDir)
	if deny != "permissions.blockReadsOutsideWorkingDirectories" {
		r.SandboxDenyReadRule = deny
	}
	r.SandboxAllowReadRule = allow
	r.PermissionDenyReadRule = ruleCovers(c.permDenyRead, path, projectDir)
	// blockReadsOutsideWorkingDirectories fences home-directory files (not
	// files inside a project) for the file tools in every mode, and for
	// sandboxed commands while the sandbox enforces it.
	if c.sb.blockReads && projectDir == "" {
		r.ReadBlockRule = "permissions.blockReadsOutsideWorkingDirectories"
	}
	r.ReadableEvidence, r.ReachEvidence = EvidenceUnknown, EvidenceUnknown
	if probe {
		r.Readable = probeReadable(path)
		r.ProbeMethod = "user_process"
		r.ReadableEvidence, r.ReachEvidence = EvidenceObserved, EvidenceInferred
		blocked := c.sandboxActive(projectDir) && deny != ""
		bash := *r.Readable && !blocked
		c.modelOpen[path] = *r.Readable && deny == ""
		if blocked {
			r.BashBypass = c.sandboxBypasses()
			// In bypassPermissions an unsandboxed retry needs no approval.
			if c.sb.allowUnsandboxed && c.effMode == "bypassPermissions" {
				bash = *r.Readable
			}
		}
		tool := *r.Readable && r.PermissionDenyReadRule == "" && r.ReadBlockRule == ""
		retry := false
		if blocked && !bash && *r.Readable {
			_, retry = c.escapeApproval()
		}
		r.ReachableViaBash, r.ReachableViaReadTool, r.ReachableViaRetry = &bash, &tool, &retry
		r.ReadApproval = c.readApproval(bash, retry, tool, projectDir)
	}
	return r
}

func (c *ccCollector) ingestReachFilesNoProbe() { c.ingestReachFilesWith(false) }
func (c *ccCollector) ingestReachFiles()        { c.ingestReachFilesWith(true) }

func (c *ccCollector) ingestReachFilesWith(probe bool) {
	seen := map[string]bool{}
	add := func(r ReachFile) {
		if r.Exists && !seen[r.Path] {
			seen[r.Path] = true
			c.snap.ReachFiles = append(c.snap.ReachFiles, r)
		}
	}
	for _, s := range sensitiveCatalog {
		if (c.opts.goos() == "darwin" && !s.Darwin) || (c.opts.goos() == "linux" && !s.Linux) {
			continue
		}
		p := expandHome(s.Path, c.home)
		add(c.reachFileRow(p, s.Category, s.Description, "", probe))
	}
	for _, pr := range c.snap.Projects {
		if !pr.Exists {
			continue
		}
		for _, n := range projectSensitiveNames {
			p := filepath.Join(pr.ProjectDir, n.Name)
			add(c.reachFileRow(p, n.Category, n.Description, pr.ProjectDir, probe))
		}
	}
}

//// REACH: HOSTS

func (c *ccCollector) allowedTCP(host string, port int) (bool, string) {
	hp := host + ":" + itoaStd(port)
	local := host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]" || host == "*"
	// macOS: allowLocalBinding lets sandboxed commands "connect to any port
	// on localhost" (settings-reference, sandbox.network.allowLocalBinding);
	// it has no effect on Linux. Observed in srt 0.0.81 (observed_srt_test.go).
	if local && c.allowLocalBind && c.opts.goos() == "darwin" {
		return true, "allowLocalBinding"
	}
	// An allowedDomains entry below governs connections through the sandbox
	// proxy (curl and other proxy-aware clients); a direct dial to the port
	// stays refused. allowed_by_sandbox reports the proxied reach.
	for _, d := range c.allowedDomains {
		switch {
		case d == "*":
			return true, d
		case d == hp || d == host:
			return true, d
		case local && (d == "localhost" || d == "127.0.0.1" || d == "localhost:"+itoaStd(port) || d == "127.0.0.1:"+itoaStd(port)):
			return true, d
		}
	}
	return false, ""
}

func (c *ccCollector) ingestReachHosts() {
	for _, s := range localServices(c.opts, c.home, c.snap) {
		r := s
		reach := *s.Reachable
		r.Agent, r.Reachable, r.SandboxEnabled = AgentClaudeCode, &reach, c.sandboxEnabled
		if c.sandboxEnabled && r.Kind == "tcp" {
			ok, rule := c.allowedTCP(r.Target[:strings.LastIndex(r.Target, ":")], tcpPort(r.Target))
			r.AllowedBySandbox, r.SandboxRule = &ok, rule
		}
		if c.sandboxEnabled && r.Kind == "unix_socket" {
			ok := c.allowAllUnix
			rule := ""
			if ok {
				rule = "allowAllUnixSockets"
			}
			for _, a := range c.allowUnixSocks {
				if covers(a, r.Target) {
					ok, rule = true, a
				}
			}
			r.AllowedBySandbox, r.SandboxRule = &ok, rule
		}
		r.Approval = c.hostApproval(r)
		c.snap.ReachHosts = append(c.snap.ReachHosts, r)
	}
}

// tcpPort is the port of a host:port target, 0 when it has none.
func tcpPort(target string) int {
	p, _ := strconv.Atoi(target[strings.LastIndex(target, ":")+1:])
	return p
}

// ingestInternetHosts emits the internet row and one row per allowed domain.
// They come from configuration, not probes, so they exist with probing off.
func (c *ccCollector) ingestInternetHosts() {
	// internet
	// The internet row is assumed, never probed: agentreach sends nothing. With the
	// sandbox on, the row is closed unless "*" is allowed, but every
	// allowedDomains entry stays a way out ("An allowed internet destination
	// can still carry data"), so each one gets its own row.
	inet := ReachHost{Agent: AgentClaudeCode, Target: "*", Kind: "internet", Service: "internet", ProbeMethod: "assumed", SandboxEnabled: c.sandboxEnabled, ReachableEvidence: EvidenceInferred}
	t := true
	inet.Reachable = &t
	if c.sandboxEnabled {
		ok, rule := c.allowedTCP("*", 0)
		inet.AllowedBySandbox, inet.SandboxRule = &ok, rule
	}
	c.snap.ReachHosts = append(c.snap.ReachHosts, inet)
	if c.sandboxEnabled {
		seen := map[string]bool{}
		for _, d := range c.allowedDomains {
			if d == "*" || seen[d] || d == "localhost" || d == "127.0.0.1" {
				continue
			}
			seen[d] = true
			ok := true
			c.snap.ReachHosts = append(c.snap.ReachHosts, ReachHost{
				Agent: AgentClaudeCode, Target: d, Kind: "allowed_domain", Service: "internet", ProbeMethod: "assumed",
				SandboxEnabled: true, Reachable: &t, AllowedBySandbox: &ok, SandboxRule: d, ReachableEvidence: EvidenceInferred,
			})
		}
	}
}

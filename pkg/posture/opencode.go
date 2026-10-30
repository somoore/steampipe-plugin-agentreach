package posture

// OpenCode collector (opencode.ai). Discovery is automatic: the collector
// reports nothing unless OpenCode is installed (binary, config directory or
// a project config). Sources and behaviour:
//   - docs/permissions: the permission config, per tool, "allow" | "ask" |
//     "deny" or a pattern object (last matching rule wins; "*" and "?"
//     wildcards). Defaults are permissive: most tools allow; read allows
//     everything but *.env, which asks; external_directory asks. --auto
//     (a session flag, not visible in files) approves what would ask.
//   - docs/config: JSON/JSONC configs merge across layers, later wins per
//     key: remote (.well-known, not readable here) -> global
//     ~/.config/opencode/opencode.json -> OPENCODE_CONFIG (env, live only)
//     -> project opencode.json -> managed (/Library/Application
//     Support/opencode on macOS, /etc/opencode on Linux) and the macOS
//     ai.opencode.managed MDM domain. Project .opencode/ directories carry
//     agents, commands, skills and plugins.
//   - docs/mcp-servers: the mcp config key holds local (command) and remote
//     (type remote, url) servers with an enabled decision.
// There is no OS sandbox; the docs call the permission system "a workflow
// safeguard, not a security sandbox". Not collected yet: plugins (npm and
// .opencode/plugins, which run JS), skills, commands, remote config, and
// per-agent permission overrides (agent.<name>.permission); the gates model
// the default agent.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const AgentOpenCode = "opencode"

// opencodeSettingKeys are copied into agentreach_setting. Only non-secret
// values; provider options and credentials never leave the parser.
var opencodeSettingKeys = []string{
	"autoupdate", "default_agent", "model", "small_model", "shell",
	"snapshot", "subagent_depth", "instructions", "plugin",
	"disabled_providers", "enabled_providers",
	"permission", "permissions", "policies", "tools",
}

func collectOpenCode(ctx context.Context, opts Options, snap *Snapshot) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	cfgDir := filepath.Join(home, ".config", "opencode")
	if opts.Home == "" {
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
			cfgDir = filepath.Join(x, "opencode")
		}
	}
	a := Agent{Agent: AgentOpenCode, ConfigDir: cfgDir}
	if opts.Home == "" {
		if p, err := lookPath("opencode"); err == nil {
			a.BinaryPath = p
			if out, err := runVersion(ctx, p); err == nil {
				a.Version = versionFrom(out)
			}
		}
	}

	managed := opts.OpenCodeManagedDir
	if managed == "" && opts.Home == "" {
		managed = openCodeManagedDir(opts)
	}

	// Layers in precedence order (later wins per key).
	type layer struct {
		scope, path string
		cfg         map[string]any
	}
	var layers []layer
	addLayer := func(scope, path string) {
		cfg, err := readOpenCodeConfig(path)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			e := "opencode: " + path + ": " + err.Error()
			snap.Errors = append(snap.Errors, e)
			a.CollectErrors = append(a.CollectErrors, e)
			return
		}
		layers = append(layers, layer{scope, path, cfg})
		if scope == "managed" && !a.ManagedSettingsPresent {
			a.ManagedSettingsPath, a.ManagedSettingsPresent = path, true
		}
		if scope == "user" {
			a.UserSettingsPath, a.UserSettingsPresent = path, true
		}
	}
	for _, n := range []string{"opencode.json", "opencode.jsonc"} {
		if managed != "" {
			addLayer("managed", filepath.Join(managed, n))
		}
		addLayer("user", filepath.Join(cfgDir, n))
	}
	projects := projectRoots(opts, snap)
	for _, p := range projects {
		for _, n := range []string{"opencode.json", "opencode.jsonc"} {
			addLayer("project", filepath.Join(p, n))
		}
	}
	if !dirExists(cfgDir) && a.BinaryPath == "" && len(layers) == 0 {
		return // not installed: no rows at all
	}
	a.Probed = opts.Probe
	a.ProbeSkippedReason = opts.probeSkipped

	// Merge for the effective config: later layers win per key, and nested
	// objects (permission) merge per sub-key so a project overriding bash
	// does not wipe the global webfetch rule.
	merged := map[string]any{}
	for _, l := range layers {
		mergeMaps(merged, l.cfg)
	}

	// Settings rows: allowlisted keys per source; the winning source is the
	// one that sets the key last.
	flat := map[string]any{}
	for _, k := range opencodeSettingKeys {
		if v, ok := merged[k]; ok {
			flat[k] = v
		}
	}
	for _, l := range layers {
		fl := map[string]any{}
		flatten("", l.cfg, fl)
		for _, k := range opencodeSettingKeys {
			v, ok := fl[k]
			if !ok {
				continue
			}
			if s, isStr := v.(string); isStr && looksLikeSecret(k, s) {
				continue
			}
			snap.Settings = append(snap.Settings, Setting{
				Agent: AgentOpenCode, Scope: l.scope, SourcePath: l.path, ProjectDir: projectDirFor(l.scope, l.path),
				Key: k, Value: v, Applies: sameJSON(v, flat[k]),
			})
		}
	}

	// Gates from the merged permission config (default agent; per-agent
	// overrides are documented but not modelled yet). The read gate is
	// per-project in agentreach's model and not yet derived for OpenCode;
	// the read permission appears in the settings and rule rows.
	//
	// Two formats (opencode.ai/docs/permissions for v1,
	// opencode.ai/v2/docs/permissions for v2): v1 is a per-tool
	// "permission" object with permissive defaults; v2 is a "permissions"
	// rule array where the last matching rule wins and the built-in base
	// policy allows everything.
	if rules := slicesOfMaps(merged["permissions"]); len(rules) > 0 {
		a.ShellApproval = ocV2Approval(rules, "shell")
		a.WebFetchApproval = ocV2Approval(rules, "webfetch")
	} else {
		perm := getMap(merged, "permission")
		a.ShellApproval = ocToolApproval(perm, "bash", "allow")
		a.WebFetchApproval = ocToolApproval(perm, "webfetch", "allow")
	}
	a.EffectivePermissionMode = "default"
	a.PermissionModeSource = "built_in"
	a.NetworkApproval = a.ShellApproval
	a.NetworkApprovalReason = "opencode gates a network command through the bash permission; there is no separate network rule"
	a.SandboxEnabled = false
	a.SandboxEnforced = false
	a.SandboxBypasses = "opencode has no OS sandbox; its permission system is a workflow safeguard, not a security sandbox (opencode.ai/docs/permissions)"

	// Every permission rule becomes a row, with its source; a whole-tool
	// string value is the "*" pattern. Both formats emit rows, tools and
	// patterns sorted for byte-stable snapshots.
	for _, l := range layers {
		for _, r := range slicesOfMaps(l.cfg["permissions"]) {
			action, resource, effect := getString(r, "action"), getString(r, "resource"), getString(r, "effect")
			if action == "" || effect == "" {
				continue
			}
			rule := SandboxRule{
				Agent: AgentOpenCode, Scope: l.scope, SourcePath: l.path, ProjectDir: projectDirFor(l.scope, l.path),
				Category: "permission", RuleType: effect, Tool: openCodeToolName(action), Pattern: resource,
			}
			rule.CarriesNetwork = (action == "shell" || action == "bash") && ruleCarriesNetwork(resource)
			snap.SandboxRules = append(snap.SandboxRules, rule)
		}
		perm := getMap(l.cfg, "permission")
		for _, tool := range sortedKeys(perm) {
			switch val := perm[tool].(type) {
			case string:
				snap.SandboxRules = append(snap.SandboxRules, ocRule(l.scope, l.path, tool, "*", val))
			case map[string]any:
				for _, pat := range sortedKeys(val) {
					if s, ok := val[pat].(string); ok {
						snap.SandboxRules = append(snap.SandboxRules, ocRule(l.scope, l.path, tool, pat, s))
					}
				}
			}
		}
	}

	// MCP servers from the merged config; a project's mcp key replaces the
	// global list for its own sessions, so rows carry the source. Names are
	// sorted: snapshot rows must be byte-stable across runs.
	for _, l := range layers {
		for _, name := range sortedKeys(getMap(l.cfg, "mcp")) {
			sm, ok := getMap(l.cfg, "mcp")[name].(map[string]any)
			if !ok {
				continue
			}
			snap.MCPServers = append(snap.MCPServers, mcpFromMap(AgentOpenCode, l.scope, l.path, projectDirFor(l.scope, l.path), name, sm, ApprovalUnknown))
		}
	}

	reviews, _ := LoadReviewLedger(reviewPath(opts, home))
	git := &ccCollector{gitIDs: map[string]map[string]bool{}}
	// Instruction files: AGENTS.md per project, the config's instructions
	// list, and markdown agents (they can carry permission frontmatter).
	for _, p := range projects {
		if n := codexInstructionName(p); n != "" {
			addAgentInstruction(snap, AgentOpenCode, "project", p, filepath.Join(p, n), "AGENTS.md", git, reviews)
		}
		addAgentMarkdownDir(snap, AgentOpenCode, "project", p, filepath.Join(p, ".opencode", "agents"), "subagent", git, reviews)
	}
	for _, inc := range toStringSlice(merged["instructions"]) {
		if p := resolveProjectPath(inc, home); p != "" {
			addAgentInstruction(snap, AgentOpenCode, "project", filepath.Dir(p), p, "instructions", git, reviews)
		}
	}
	addAgentMarkdownDir(snap, AgentOpenCode, "user", "", filepath.Join(cfgDir, "agents"), "subagent", git, reviews)

	snap.Agents = append(snap.Agents, a)
}

// ocToolApproval resolves one tool's gate: a string action, or the "*" rule
// of a pattern object; def is the documented default.
func ocToolApproval(perm map[string]any, tool, def string) string {
	action := def
	switch v := perm[tool].(type) {
	case string:
		action = v
	case map[string]any:
		if s, ok := v["*"].(string); ok {
			action = s
		}
	}
	return ocActionApproval(action)
}

// ocV2Approval resolves a v2 gate: the last rule whose action is the tool
// (or "*") and whose resource is the catch-all "*"; with no such rule the
// built-in base policy allows everything (opencode.ai/v2/docs/permissions,
// "Defaults").
func ocV2Approval(rules []map[string]any, action string) string {
	approval := ApprovalNone // base policy: {action:"*", resource:"*", effect:"allow"}
	for _, r := range rules {
		a, res, eff := getString(r, "action"), getString(r, "resource"), getString(r, "effect")
		if (a == action || a == "*") && res == "*" {
			approval = ocActionApproval(eff)
		}
	}
	return approval
}

func ocActionApproval(action string) string {
	switch action {
	case "allow":
		return ApprovalNone
	case "ask":
		return ApprovalPrompt
	case "deny":
		return ApprovalDenied
	}
	return ApprovalUnknown
}

func ocRule(scope, path, tool, pattern, action string) SandboxRule {
	r := SandboxRule{
		Agent: AgentOpenCode, Scope: scope, SourcePath: path, ProjectDir: projectDirFor(scope, path),
		Category: "permission", RuleType: action, Tool: openCodeToolName(tool), Pattern: pattern,
	}
	r.CarriesNetwork = tool == "bash" && ruleCarriesNetwork(pattern)
	return r
}

func openCodeToolName(tool string) string {
	switch tool {
	case "bash", "shell":
		return "Bash"
	case "read":
		return "Read"
	case "edit", "write", "patch":
		return "Edit"
	case "webfetch":
		return "WebFetch"
	case "websearch":
		return "WebSearch"
	case "task", "subagent":
		return "Task"
	case "skill":
		return "Skill"
	}
	return strings.Title(tool) // best effort for glob, grep, lsp, ...
}

// readOpenCodeConfig parses opencode.json or .jsonc (the shared JSONC
// stripper also tolerates trailing commas).
func readOpenCodeConfig(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(stripJSONC(b), &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func openCodeManagedDir(opts Options) string {
	if opts.goos() == "darwin" {
		return "/Library/Application Support/opencode"
	}
	return "/etc/opencode"
}

// mergeMaps deep-merges src into dst: maps merge per key (src wins), every
// other value replaces. Nested maps are copied into dst, never referenced,
// so merging cannot mutate a layer's own parsed config.
func mergeMaps(dst, src map[string]any) {
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			d, ok := dst[k].(map[string]any)
			if !ok {
				d = map[string]any{}
				dst[k] = d
			}
			mergeMaps(d, m)
			continue
		}
		dst[k] = v
	}
}

// projectDirFor maps a layer to the project it belongs to (project layers
// only); the file sits at the project root.
func projectDirFor(scope, path string) string {
	if scope != "project" {
		return ""
	}
	return filepath.Dir(path)
}

// resolveProjectPath resolves an instructions entry; only absolute and ~
// paths can be resolved without knowing which project's config listed them.
func resolveProjectPath(p, home string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "~") {
		return expandHome(p, home)
	}
	return ""
}

func addAgentMarkdownDir(snap *Snapshot, agent, scope, projectDir, dir, kind string, git *ccCollector, reviews *ReviewLedger) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		addAgentInstruction(snap, agent, scope, projectDir, filepath.Join(dir, n), kind, git, reviews)
	}
}

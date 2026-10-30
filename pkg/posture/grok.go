package posture

// Grok Build collector (x.ai docs, docs.x.ai/build). Discovery is
// automatic: nothing is reported unless Grok Build is installed (binary,
// ~/.grok or a project .grok). Sources and behaviour:
//   - build/settings: config scopes are user ~/.grok/config.toml (or
//     $GROK_HOME), project .grok/config.toml (MCP servers, plugins and
//     permission rules only), managed ~/.grok/managed_config.toml and
//     /etc/grok/managed_config.toml, and requirements ~/.grok/
//     requirements.toml and /etc/grok/requirements.toml (policy pins).
//   - build/features/permissions: modes ask (default), auto (a classifier
//     approves safe tools) and always-approve; [ui] permission_mode in
//     user, managed or requirements config only, and it wins over the
//     legacy approval_mode and yolo = true. [permission] rules are
//     allow/deny per tool with patterns; deny wins over allow.
//   - build/features/sandbox: profiles off (default), workspace, devbox,
//     read-only and strict in [sandbox] profile or ~/.grok/sandbox.toml
//     custom profiles. Child-process network is enforced on Linux only.
//     Permissions decide whether a call runs; the sandbox limits what an
//     approved call can do.
// Not modelled yet: plugins/skills/hooks (Claude Code-compatible formats;
// their locations are not documented), auth.json (existence only), headless
// enterprise modes, and per-pattern rule evaluation for gates; rules appear
// as rows and the mode gates everything else.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

const AgentGrok = "grok"

func collectGrok(ctx context.Context, opts Options, snap *Snapshot) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	dir := filepath.Join(home, ".grok")
	if opts.Home == "" {
		if g := os.Getenv("GROK_HOME"); g != "" {
			dir = g
		}
	}
	a := Agent{Agent: AgentGrok, ConfigDir: dir}
	if opts.Home == "" {
		if p, err := lookPath("grok"); err == nil {
			a.BinaryPath = p
			if out, err := runVersion(ctx, p); err == nil {
				a.Version = versionFrom(out)
			}
		}
	}

	system := opts.GrokSystemDir
	if system == "" && opts.Home == "" {
		system = "/etc/grok"
	}

	present := dirExists(dir) || a.BinaryPath != ""
	if !present {
		return // not installed: no rows at all
	}
	a.Probed = opts.Probe
	a.ProbeSkippedReason = opts.probeSkipped
	a.LoggedIn = fileExists(filepath.Join(dir, "auth.json")) // existence only; never read
	a.UserSettingsPath = filepath.Join(dir, "config.toml")

	// Config layers in precedence order: requirements pin, then managed,
	// then user; project config holds MCP, plugins and permission rules.
	type glayer struct {
		scope, path string
		cfg         map[string]any
	}
	var layers []glayer
	add := func(scope, path string) {
		cfg, bad := readAgentTOML(path, &a, snap, AgentGrok)
		if cfg == nil && bad == "" {
			return
		}
		layers = append(layers, glayer{scope, path, cfg})
		switch scope {
		case "requirements", "managed":
			if !a.ManagedSettingsPresent {
				a.ManagedSettingsPath, a.ManagedSettingsPresent = path, true
			}
		case "user":
			a.UserSettingsPresent = true
		}
	}
	if system != "" {
		add("requirements", filepath.Join(system, "requirements.toml"))
		add("managed", filepath.Join(system, "managed_config.toml"))
	}
	add("requirements", filepath.Join(dir, "requirements.toml"))
	add("managed", filepath.Join(dir, "managed_config.toml"))
	add("user", filepath.Join(dir, "config.toml"))
	userCfg := filepath.Join(dir, "config.toml")
	projects := projectRoots(opts, snap)
	for _, p := range projects {
		path := filepath.Join(p, ".grok", "config.toml")
		// The home directory is often a registered project; its .grok is
		// the user layer, already read above, not a project layer.
		if path == userCfg {
			continue
		}
		cfg, _ := readAgentTOML(path, &a, snap, AgentGrok)
		if cfg != nil {
			layers = append(layers, glayer{"project", path, cfg})
		}
	}

	// permission_mode: requirements and managed pin it, then user config;
	// a project config cannot set it. permission_mode wins over the legacy
	// approval_mode and yolo.
	mode, modeSource := "", ""
	for _, l := range layers {
		if l.scope == "project" {
			continue
		}
		ui := getMap(l.cfg, "ui")
		if pm := getString(ui, "permission_mode"); pm != "" {
			mode, modeSource = pm, l.scope
			break
		}
		if am := getString(ui, "approval_mode"); am != "" && mode == "" {
			mode, modeSource = legacyGrokMode(am), l.scope
		}
		if getBool(ui, "yolo") != nil && *getBool(ui, "yolo") && mode == "" {
			mode, modeSource = "always-approve", l.scope
		}
	}
	if mode == "" {
		mode, modeSource = "ask", "built_in"
	}
	a.EffectivePermissionMode, a.PermissionModeSource = grokModeName(mode), modeSource
	a.ShellApproval = grokModeApproval(mode)
	a.NetworkApproval = a.ShellApproval
	a.NetworkApprovalReason = "grok gates every tool call, including network ones, with its permission mode; deny rules and hooks still apply"
	a.WebFetchApproval = a.ShellApproval

	// Permission rules from every layer: allow/deny per tool with patterns;
	// deny wins. They gate matching calls beyond the mode.
	for _, l := range layers {
		for _, r := range permissionRules(l.cfg) {
			r.Agent, r.Scope, r.SourcePath = AgentGrok, l.scope, l.path
			if l.scope == "project" {
				r.ProjectDir = filepath.Dir(filepath.Dir(l.path))
			}
			snap.SandboxRules = append(snap.SandboxRules, r)
		}
	}

	// Sandbox profile: [sandbox] profile in user/managed/requirements, or a
	// custom profile in ~/.grok/sandbox.toml. Off by default.
	profile := ""
	for _, l := range layers {
		if l.scope == "project" {
			continue
		}
		if p := getString(getMap(l.cfg, "sandbox"), "profile"); p != "" {
			profile = p
			break
		}
	}
	a.SandboxEnabled = profile != "" && profile != "off"
	a.SandboxEnforced = a.SandboxEnabled
	if a.SandboxEnabled && (profile == "read-only" || profile == "strict") && opts.goos() != "linux" {
		a.SandboxBypasses = "child-process network is enforced on Linux only; on this OS the network part of " + profile + " is a no-op (docs.x.ai/build/features/sandbox)"
	} else if a.SandboxEnabled {
		a.SandboxBypasses = "built-in profiles do not permanently protect paths such as ~/.ssh; use a custom deny list (docs.x.ai/build/features/sandbox)"
	}

	// MCP servers from every layer, names sorted for byte-stable snapshots.
	for _, l := range layers {
		servers := getMap(l.cfg, "mcp_servers")
		for _, name := range sortedKeys(servers) {
			sm, ok := servers[name].(map[string]any)
			if !ok {
				continue
			}
			pd := ""
			if l.scope == "project" {
				pd = filepath.Dir(filepath.Dir(l.path))
			}
			snap.MCPServers = append(snap.MCPServers, mcpFromMap(AgentGrok, l.scope, l.path, pd, name, sm, ApprovalUnknown))
		}
	}

	// Settings rows: allowlisted scalars per source.
	for _, l := range layers {
		flat := map[string]any{}
		flatten("", l.cfg, flat)
		for _, k := range []string{"ui.permission_mode", "ui.approval_mode", "ui.yolo", "sandbox.profile", "models.default"} {
			if v, ok := flat[k]; ok {
				snap.Settings = append(snap.Settings, Setting{
					Agent: AgentGrok, Scope: l.scope, SourcePath: l.path, ProjectDir: grokProjectDir(l.scope, l.path),
					Key: k, Value: v, Applies: true,
				})
			}
		}
	}

	reviews, _ := LoadReviewLedger(reviewPath(opts, home))
	git := &ccCollector{gitIDs: map[string]map[string]bool{}}
	for _, p := range projects {
		if n := codexInstructionName(p); n != "" { // Grok Build reads AGENTS.md
			addAgentInstruction(snap, AgentGrok, "project", p, filepath.Join(p, n), "AGENTS.md", git, reviews)
		}
	}

	snap.Agents = append(snap.Agents, a)
}

func grokProjectDir(scope, path string) string {
	if scope == "project" {
		return filepath.Dir(filepath.Dir(path))
	}
	return ""
}

func legacyGrokMode(am string) string {
	if strings.EqualFold(am, "always-approve") || strings.EqualFold(am, "yolo") {
		return "always-approve"
	}
	return "ask"
}

func grokModeName(mode string) string {
	switch mode {
	case "always-approve":
		return "bypassPermissions"
	case "auto":
		return "auto"
	}
	return "default"
}

func grokModeApproval(mode string) string {
	switch mode {
	case "always-approve":
		return ApprovalNone
	case "auto":
		return ApprovalClassifier
	}
	return ApprovalPrompt
}

// permissionRules turns [permission] rules into rows. deny wins over allow.
func permissionRules(cfg map[string]any) []SandboxRule {
	var out []SandboxRule
	for _, r := range slicesOfMaps(getMap(cfg, "permission")["rules"]) {
		action := getString(r, "action")
		tool := getString(r, "tool")
		pattern := getString(r, "pattern")
		if action == "" || tool == "" {
			continue
		}
		rule := SandboxRule{
			Category: "permission", RuleType: action, Tool: tool, Pattern: pattern,
		}
		if strings.EqualFold(tool, "bash") {
			rule.CarriesNetwork = ruleCarriesNetwork(pattern)
		}
		out = append(out, rule)
	}
	return out
}

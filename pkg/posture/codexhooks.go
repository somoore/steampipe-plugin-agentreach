package posture

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Codex hooks and notify. Facts (codex-cli 0.155.1):
//
//   - Hooks live in hooks.json or inline [hooks] tables in config.toml next
//     to every active config layer: ~/.codex, <repo>/.codex (only when the
//     project is trusted), /etc/codex, and a plugin's hooks/hooks.json.
//     https://learn.chatgpt.com/docs/hooks: "Project-local hooks load only
//     when the project .codex/ layer is trusted."
//   - "Non-managed hooks must be reviewed and trusted before they run" and
//     "new or changed hooks are marked for review and skipped until
//     trusted" (hooks docs). Trust is [hooks.state."<key>"] trusted_hash in
//     the user config.toml, key "<source path>:<event_label>:<group>:<handler>"
//     (hooks/src/lib.rs hook_key; plugin key source "<plugin id>:<relative
//     path>", declarations.rs). Managed (system, requirements) hooks are
//     trusted by policy; state.enabled = false turns one off
//     (engine/discovery.rs hook_trust_status, hook_enabled).
//   - "Hooks are enabled by default"; [features] hooks = false turns them off.
//   - Hook commands are spawned directly, with no sandbox wrapper
//     (hooks/src/engine/command_runner.rs); the docs do not say. agentreach treats
//     them as running with the user's full access.
//   - notify = [argv] runs on agent-turn-complete with no trust step
//     (config-advanced; hooks/src/legacy_notify.rs).
//
// agentreach does not recompute trusted_hash (a sha256 over a normalized
// definition): a recorded hash counts as running, so a definition changed
// since (which Codex skips) is still counted.

// codexHookEvents are the 0.155.1 HookEventName values, in a fixed order.
var codexHookEvents = []string{
	"PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact", "SessionStart",
	"SessionEnd", "UserPromptSubmit", "SubagentStart", "SubagentStop", "Stop", "Interrupt",
}

// codexEventLabel is the snake_case label used in hook keys.
func codexEventLabel(ev string) string {
	var b strings.Builder
	for i, r := range ev {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// codexHookSource is one file that declares hooks.
type codexHookSource struct {
	scope, path, keySource, projectDir string
	events                             map[string]any // event name -> groups
	managed                            bool
	plugin                             string
	pluginEnabled                      *bool
	blocked                            string // set when the whole source does not load
}

// codexHooksJSON reads <dir>/hooks.json; nil when absent or unreadable.
func codexHooksJSON(path string) map[string]any {
	d, err := readJSON(path)
	if err != nil {
		return nil
	}
	if h := getMap(d, "hooks"); h != nil {
		return h
	}
	return nil
}

func (x *codexScan) hooks() {
	m, cfg := x.m, x.cfg
	off := ""
	if v, _ := m.layered(nil, "features", "hooks"); v != nil {
		if b, ok := v.(bool); ok && !b {
			off = "hooks are turned off ([features] hooks = false)"
		}
	}
	if v, _ := m.layered(nil, "features", "codex_hooks"); v != nil && off == "" {
		if b, ok := v.(bool); ok && !b {
			off = "hooks are turned off ([features] codex_hooks = false)"
		}
	}
	managedOnly := false
	if b := getBool(m.requirements, "allow_managed_hooks_only"); b != nil && *b {
		managedOnly = true
	}
	if b := getBool(m.requirements, "hooks", "allow_managed_hooks_only"); b != nil && *b {
		managedOnly = true
	}
	states := getMap(cfg, "hooks", "state")

	var sources []codexHookSource
	layer := func(scope, dir string, layerCfg map[string]any, cfgPath, projectDir string, managed bool, blocked string) {
		hj := filepath.Join(dir, "hooks.json")
		if ev := codexHooksJSON(hj); ev != nil {
			sources = append(sources, codexHookSource{scope: scope, path: hj, keySource: hj, projectDir: projectDir, events: ev, managed: managed, blocked: blocked})
		}
		if ev := getMap(layerCfg, "hooks"); ev != nil {
			sources = append(sources, codexHookSource{scope: scope, path: cfgPath, keySource: cfgPath, projectDir: projectDir, events: ev, managed: managed, blocked: blocked})
		}
	}
	if m.system != "" {
		layer("managed", m.system, m.sysCfg, filepath.Join(m.system, "config.toml"), "", true, "")
		if ev := getMap(m.requirements, "hooks"); ev != nil {
			p := filepath.Join(m.system, "requirements.toml")
			sources = append(sources, codexHookSource{scope: "managed", path: p, keySource: p, events: ev, managed: true})
		}
	}
	layer("user", x.dir, cfg, x.cfgPath, "", false, "")
	for _, p := range x.sorted {
		if _, known := x.projects[p]; !known || !dirExists(p) || isCodexHome(p, x.dir) {
			continue
		}
		blocked := ""
		if getString(getMap(x.projects, p), "trust_level") != "trusted" {
			blocked = "project-local hooks load only when the project .codex/ layer is trusted"
		}
		pcPath := filepath.Join(p, ".codex", "config.toml")
		var pcfg map[string]any
		if b, err := os.ReadFile(pcPath); err == nil {
			_ = toml.Unmarshal(b, &pcfg) // a parse error is recorded by collectCodex
		}
		layer("project", filepath.Join(p, ".codex"), pcfg, pcPath, p, false, blocked)
	}
	for _, pl := range x.pluginHooks {
		sources = append(sources, pl)
	}

	for _, src := range sources {
		for _, ev := range codexHookEvents {
			groups, _ := src.events[ev].([]any)
			for gi, gv := range groups {
				grp, _ := gv.(map[string]any)
				handlers, _ := grp["hooks"].([]any)
				for hi, hv := range handlers {
					h, _ := hv.(map[string]any)
					key := src.keySource + ":" + codexEventLabel(ev) + ":" + strconv.Itoa(gi) + ":" + strconv.Itoa(hi)
					x.addHook(src, ev, getString(grp, "matcher"), h, getMap(states, key), off, managedOnly)
				}
			}
		}
	}

	// notify: an argv run on agent-turn-complete, user config only (project
	// config cannot set it).
	if argv := toStringSlice(cfg["notify"]); len(argv) > 0 {
		cmd, r1 := scrubText(argv[0])
		args, r2 := scrubArgs(argv[1:])
		t := true
		x.snap.Hooks = append(x.snap.Hooks, Hook{
			Agent: AgentCodex, Scope: "user", SourcePath: x.cfgPath, Event: "agent-turn-complete", HookType: "command",
			Command: cmd, Args: args, Redacted: r1 || r2, Origin: "notify", Runs: &t,
			RunsReason:       "notify runs on every agent-turn-complete event with no trust step",
			SourceWritableBy: writableBy(x.cfgPath), SourceTrackedGit: gitTracked(x.cfgPath),
		})
	}
}

func (x *codexScan) addHook(src codexHookSource, event, matcher string, h, state map[string]any, off string, managedOnly bool) {
	typ := getString(h, "type")
	cmd, red := scrubText(getString(h, "command"))
	row := Hook{
		Agent: AgentCodex, Scope: src.scope, SourcePath: src.path, ProjectDir: src.projectDir, Event: event, Matcher: matcher,
		HookType: typ, Command: cmd, Redacted: red, Origin: "settings",
		SourceWritableBy: writableBy(src.path), SourceTrackedGit: gitTracked(src.path),
	}
	if src.plugin != "" {
		row.Origin, row.PluginName, row.PluginEnabled, row.ThirdParty = "plugin", src.plugin, src.pluginEnabled, true
	}
	if t, ok := toInt(h["timeout"]); ok {
		row.Timeout = &t
	}
	// engine/discovery.rs normalize_command_hook.
	row.EffectiveTimeout = 600
	if row.Timeout != nil {
		row.EffectiveTimeout = max(*row.Timeout, 1)
	}
	if event == "SessionEnd" || event == "Interrupt" {
		row.EffectiveTimeout = 1
		if row.Timeout != nil {
			row.EffectiveTimeout = min(max(*row.Timeout, 1), 3)
		}
	}
	runs, why := false, ""
	trusted := getString(state, "trusted_hash") != ""
	switch {
	case off != "":
		why = off
	case typ != "command" && typ != "mcp_tool":
		why = "Codex 0.155.1 runs command and mcp_tool handlers only; " + quoteOr(typ) + " is skipped"
	case src.blocked != "":
		why = src.blocked
	case src.pluginEnabled != nil && !*src.pluginEnabled:
		why = "plugin " + src.plugin + " is disabled"
	case !src.managed && managedOnly:
		why = "requirements.toml allow_managed_hooks_only skips user, project and plugin hooks"
	case src.managed:
		runs, why = true, "managed hooks are trusted by policy"
	case getBool(state, "enabled") != nil && !*getBool(state, "enabled"):
		why = "turned off in [hooks.state]"
	case !trusted:
		why = "not trusted: Codex skips new or changed hooks until you review them"
	default:
		row.RunsReason = "trusted (hash recorded in [hooks.state]); agentreach does not recompute the hash, so a definition changed since, which Codex skips, still counts as running"
		x.snap.Hooks = append(x.snap.Hooks, row)
		return
	}
	row.Runs, row.RunsReason = &runs, why
	x.snap.Hooks = append(x.snap.Hooks, row)
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

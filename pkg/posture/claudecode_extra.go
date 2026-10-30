package posture

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginEnabledIn resolves the enabledPlugins decision for a plugin in a
// session started in projectDir ("" means machine-wide). Settings precedence
// is managed, local, project, user; nil when no file decides.
func (c *ccCollector) pluginEnabledIn(full, projectDir string) *bool {
	docs := []map[string]any{c.managed}
	switch {
	case projectDir == "":
	case filepath.Clean(projectDir) == filepath.Clean(c.home):
		// The home project's .claude is ~/.claude: its settings.json is the
		// user file (read below), but settings.local.json is that project's
		// local file, where a local-scope install in ~ records its decision.
		docs = append(docs, c.doc(filepath.Join(projectDir, ".claude", "settings.local.json")))
	default:
		docs = append(docs,
			c.doc(filepath.Join(projectDir, ".claude", "settings.local.json")),
			c.doc(filepath.Join(projectDir, ".claude", "settings.json")))
	}
	docs = append(docs, c.user)
	for _, d := range docs {
		if v, ok := getMap(d, "enabledPlugins")[full].(bool); ok {
			return &v
		}
	}
	return nil
}

// ingestPluginMCP emits the MCP servers a plugin bundles: .mcp.json at the
// plugin root (either {"mcpServers": {...}} or servers keyed at the top
// level) and mcpServers in plugin.json (an object, or a path to a JSON file).
func (c *ccCollector) ingestPluginMCP(root, plugin, projectDir string, enabled *bool) {
	emit := func(path string, servers map[string]any) {
		before := len(c.snap.MCPServers)
		c.ingestMCPMap("plugin", path, projectDir, servers, func(string) *bool { return enabled })
		for i := before; i < len(c.snap.MCPServers); i++ {
			c.snap.MCPServers[i].PluginName = plugin
		}
	}
	if m, err := readJSON(filepath.Join(root, ".mcp.json")); err == nil && m != nil {
		if s := getMap(m, "mcpServers"); s != nil {
			emit(filepath.Join(root, ".mcp.json"), s)
		} else {
			emit(filepath.Join(root, ".mcp.json"), m)
		}
	}
	for _, mf := range []string{filepath.Join(root, ".claude-plugin", "plugin.json"), filepath.Join(root, "plugin.json")} {
		m, err := readJSON(mf)
		if err != nil || m == nil {
			continue
		}
		switch v := m["mcpServers"].(type) {
		case map[string]any:
			emit(mf, v)
		case string:
			p := filepath.Join(root, strings.ReplaceAll(v, "${CLAUDE_PLUGIN_ROOT}", ""))
			if inner, err := readJSON(p); err == nil && inner != nil {
				if s := getMap(inner, "mcpServers"); s != nil {
					emit(p, s)
				} else {
					emit(p, inner)
				}
			}
		}
	}
}

// addTree adds every file under dir whose name ends with suffix (or equals
// it, for SKILL.md), at any depth. Claude Code discovers rules, commands and
// agents recursively.
func (c *ccCollector) addTree(scope, projectDir, dir, suffix, kind, plugin string) {
	var found []string
	// The callback swallows per-entry errors by design: an unreadable
	// directory yields no files, which is the correct scanner result.
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == suffix || (strings.HasPrefix(suffix, ".") && strings.HasSuffix(d.Name(), suffix)) {
			found = append(found, p)
		}
		return nil
	})
	sort.Strings(found)
	for _, p := range found {
		c.addInstructionPlugin(scope, projectDir, p, kind, plugin)
	}
}

// frontmatterHooks extracts the hooks object from a skill or subagent's
// YAML frontmatter, in the same shape as settings hooks.
func frontmatterHooks(b []byte) map[string]any {
	s := string(b)
	if !strings.HasPrefix(s, "---") {
		return nil
	}
	end := strings.Index(s[3:], "\n---")
	if end < 0 {
		return nil
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(s[3:3+end]), &fm); err != nil {
		return nil
	}
	h, _ := fm["hooks"].(map[string]any)
	return h
}

// defaultHookTimeout is the documented default in seconds.
//
// Source: https://code.claude.com/docs/en/hooks, "Common fields": "Defaults:
// 600 for command, http, and mcp_tool; 30 for prompt; 60 for agent. Claude
// Code lowers the command, http, and mcp_tool default to 30 on
// UserPromptSubmit, PreModelSwitch, and PostModelSwitch, and to 10 on
// MessageDisplay."
func defaultHookTimeout(hookType, event string) int {
	switch hookType {
	case "prompt":
		return 30
	case "agent":
		return 60
	}
	switch event {
	case "UserPromptSubmit", "PreModelSwitch", "PostModelSwitch":
		return 30
	case "MessageDisplay":
		return 10
	}
	return 600
}

// markHooks records whether each hook runs, given disableAllHooks,
// allowManagedHooksOnly and the plugin's enabled state.
//
// Source: https://code.claude.com/docs/en/hooks: "allowManagedHooksOnly ...
// Your user, project, local, and plugin hooks are blocked. Hooks from
// plugins force-enabled in managed settings enabledPlugins are exempt" and
// "the disableAllHooks setting can't disable managed hooks from outside
// managed settings".
func (c *ccCollector) markHooks() {
	managedOnly := false
	if b := getBool(c.managed, "allowManagedHooksOnly"); b != nil && *b {
		managedOnly = true
	}
	managedDisable := getBool(c.managed, "disableAllHooks")
	userDisable := getBool(c.user, "disableAllHooks")
	forced := getMap(c.managed, "enabledPlugins")
	for i := range c.snap.Hooks {
		h := &c.snap.Hooks[i]
		if h.Agent != AgentClaudeCode {
			continue
		}
		runs, why := true, ""
		switch {
		case managedDisable != nil && *managedDisable:
			runs, why = false, "disableAllHooks (managed)"
		case h.Scope != "managed" && userDisable != nil && *userDisable:
			runs, why = false, "disableAllHooks (user)"
		case h.Scope != "managed" && managedOnly && !(h.PluginName != "" && forced[h.PluginName] == true):
			runs, why = false, "allowManagedHooksOnly"
		case h.PluginEnabled != nil && !*h.PluginEnabled:
			runs, why = false, "plugin disabled"
		}
		h.Runs, h.RunsReason = &runs, why
	}
}

// scrubValue redacts strings, and strings inside arrays, in a settings value.
func scrubValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if strings.Contains(x, "://") && !strings.ContainsAny(x, " \t") {
			return scrubURL(x)
		}
		return scrubText(x)
	case []any:
		out := make([]any, len(x))
		changed := false
		for i, e := range x {
			r, ch := scrubValue(e)
			out[i] = r
			changed = changed || ch
		}
		if !changed {
			return v, false
		}
		return out, true
	}
	return v, false
}

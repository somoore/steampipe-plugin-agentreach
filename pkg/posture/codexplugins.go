package posture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// codexScan carries what collectCodex has resolved to the hook, plugin,
// skill, service and write-target passes.
type codexScan struct {
	opts               Options
	snap               *Snapshot
	a                  *Agent
	m                  *codexModel
	cfg                map[string]any
	cfgPath, dir, home string
	g                  codexGate
	projects           map[string]any
	sorted             []string
	gates              []codexGate // aligned with sorted
	git                *ccCollector
	reviews            *ReviewLedger
	pluginHooks        []codexHookSource
	pluginSkillRoots   []codexSkillRoot
}

type codexSkillRoot struct {
	dir, scope, projectDir, plugin string
	pluginEnabled                  *bool
}

// Plugins (codex-cli 0.155.1, core-plugins): a plugin loads only when
// [plugins."<name>@<marketplace>"] is in the user config.toml (enabled
// defaults to true, config/src/types.rs default_enabled). Its files are in
// $CODEX_HOME/plugins/cache/<marketplace>/<name>/<version>; the active
// version is "local" when present, else the highest (semver, else lexical)
// (core-plugins/src/store.rs active_plugin_version). A plugin bundles
// skills (skills/), MCP servers (.mcp.json) and hooks (hooks/hooks.json),
// or the paths its manifest (.codex-plugin/plugin.json) names
// (core-plugins/src/loader.rs). https://learn.chatgpt.com/docs/plugins:
// "Installing or enabling a plugin doesn't automatically trust its hooks"
// (hooks docs). agentreach never walks plugins/cache: entries there that the
// config does not name (remote-synced or stale) are not loaded, and
// remote plugins synced from ChatGPT are not visible in config.
func (x *codexScan) plugins() {
	plugins := getMap(x.cfg, "plugins")
	for _, full := range sortedKeys(plugins) {
		pc := getMap(plugins, full)
		i := strings.LastIndex(full, "@")
		if i <= 0 {
			continue
		}
		name, market := full[:i], full[i+1:]
		en := true
		if b := getBool(pc, "enabled"); b != nil {
			en = *b
		}
		enabled := en
		base := filepath.Join(x.dir, "plugins", "cache", market, name)
		ver := codexActivePluginVersion(base)
		p := Plugin{Agent: AgentCodex, FullName: full, Name: name, Marketplace: market, Scope: "user", InstallPath: base, Enabled: &enabled}
		if ver == "" {
			x.snap.Plugins = append(x.snap.Plugins, p)
			continue
		}
		root := filepath.Join(base, ver)
		p.InstallPath, p.InstallPathExists, p.Version, p.WritableBy = root, true, ver, writableBy(root)
		if ver != "local" {
			p.Pinned = pluginPinned(ver, "")
		}
		var manifest map[string]any
		for _, mf := range []string{".codex-plugin/plugin.json", ".claude-plugin/plugin.json"} {
			if d, err := readJSON(filepath.Join(root, mf)); err == nil {
				manifest = d
				break
			}
		}
		rel := func(v any) []string {
			var out []string
			if s, ok := v.(string); ok {
				out = []string{s}
			} else {
				out = toStringSlice(v)
			}
			for i := range out {
				out[i] = filepath.Join(root, out[i])
			}
			return out
		}
		// Skills.
		skillRoots := rel(manifest["skills"])
		if len(skillRoots) == 0 && dirExists(filepath.Join(root, "skills")) {
			skillRoots = []string{filepath.Join(root, "skills")}
		}
		for _, d := range skillRoots {
			n := len(codexSkillFiles(d))
			p.SkillCount += n
			x.pluginSkillRoots = append(x.pluginSkillRoots, codexSkillRoot{dir: d, scope: "plugin", plugin: full, pluginEnabled: &enabled})
		}
		// Hooks.
		hookFiles := rel(manifest["hooks"])
		if len(hookFiles) == 0 {
			hookFiles = []string{filepath.Join(root, "hooks", "hooks.json")}
		}
		for _, hf := range hookFiles {
			if ev := codexHooksJSON(hf); ev != nil {
				r, _ := filepath.Rel(root, hf)
				p.HasHooks = true
				x.pluginHooks = append(x.pluginHooks, codexHookSource{scope: "plugin", path: hf, keySource: full + ":" + filepath.ToSlash(r),
					events: ev, plugin: full, pluginEnabled: &enabled})
			}
		}
		// MCP servers.
		mcpFiles := []string{filepath.Join(root, ".mcp.json")}
		if s, ok := manifest["mcpServers"].(string); ok {
			mcpFiles = []string{filepath.Join(root, s)}
		}
		for _, mf := range mcpFiles {
			d, err := readJSON(mf)
			if err != nil {
				continue
			}
			servers := getMap(d, "mcpServers")
			if servers == nil {
				servers = d
			}
			for _, n := range sortedKeys(servers) {
				sm := getMap(servers, n)
				if sm == nil {
					continue
				}
				// [plugins."<id>".mcp_servers.<name>] overlays policy.
				merged := map[string]any{}
				for k, v := range sm {
					merged[k] = v
				}
				ov := getMap(pc, "mcp_servers", n)
				for k, v := range ov {
					merged[k] = v
				}
				s := codexMCPServer(mf, n, merged, x.g.Approval)
				s.Scope, s.PluginName = "plugin", full
				on := en
				if b := getBool(ov, "enabled"); b != nil && !*b {
					on = false
				}
				s.Enabled = &on
				p.HasMCP = true
				x.snap.MCPServers = append(x.snap.MCPServers, s)
			}
		}
		x.snap.Plugins = append(x.snap.Plugins, p)
	}
}

var strictSemver = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// codexActivePluginVersion mirrors PluginStore::active_plugin_version.
func codexActivePluginVersion(base string) string {
	ents, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	var vs []string
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			if e.Name() == "local" {
				return "local"
			}
			vs = append(vs, e.Name())
		}
	}
	if len(vs) == 0 {
		return ""
	}
	sort.Slice(vs, func(i, j int) bool { return compareCodexVersions(vs[i], vs[j]) < 0 })
	return vs[len(vs)-1]
}

func compareCodexVersions(a, b string) int {
	ma, mb := strictSemver.FindStringSubmatch(a), strictSemver.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ma[4] == mb[4]:
		return 0
	case ma[4] == "":
		return 1 // a release ranks above its pre-releases
	case mb[4] == "":
		return -1
	}
	return strings.Compare(ma[4], mb[4])
}

// Skills (codex-cli 0.155.1, ext/skills/src/host_roots.rs; docs
// https://learn.chatgpt.com/docs/build-skills): user $HOME/.agents/skills
// and the deprecated $CODEX_HOME/skills ("kept for backward
// compatibility"; its .system folder holds skills bundled with Codex, not
// reported); admin /etc/codex/skills; per repository .agents/skills ("from
// your current working directory up to the repository root"; agentreach checks
// the project root) and <project>/.codex/skills; and enabled plugins'
// skill roots. The repo roots are not trust-gated in the source. A skill is
// a folder with SKILL.md; [[skills.config]] path = ".../SKILL.md",
// enabled = false turns one off.
func (x *codexScan) skills() {
	disabled := map[string]bool{}
	if arr, ok := getMap(x.cfg, "skills")["config"].([]any); ok {
		for _, e := range arr {
			if em, ok := e.(map[string]any); ok {
				if b := getBool(em, "enabled"); b != nil && !*b {
					disabled[filepath.Clean(expandHome(getString(em, "path"), x.home))] = true
				}
			}
		}
	}
	roots := []codexSkillRoot{
		{dir: filepath.Join(x.home, ".agents", "skills"), scope: "user"},
		{dir: filepath.Join(x.dir, "skills"), scope: "user"},
	}
	if x.m.system != "" {
		roots = append(roots, codexSkillRoot{dir: filepath.Join(x.m.system, "skills"), scope: "managed"})
	}
	for _, p := range x.sorted {
		if _, known := x.projects[p]; !known || !dirExists(p) || filepath.Clean(p) == filepath.Clean(x.home) {
			continue
		}
		roots = append(roots, codexSkillRoot{dir: filepath.Join(p, ".agents", "skills"), scope: "project", projectDir: p},
			codexSkillRoot{dir: filepath.Join(p, ".codex", "skills"), scope: "project", projectDir: p})
	}
	roots = append(roots, x.pluginSkillRoots...)
	seen := map[string]bool{}
	for _, r := range roots {
		for _, f := range codexSkillFiles(r.dir) {
			if disabled[filepath.Clean(f)] || seen[f] {
				continue
			}
			seen[f] = true
			addCodexInstructionKind(x.snap, r.scope, r.projectDir, f, "skill", r.plugin, r.pluginEnabled, x.git, x.reviews)
		}
	}
}

// codexSkillFiles finds SKILL.md files under root, following symlinked
// folders (Codex does), three levels deep, skipping hidden folders (the
// bundled .system) and node_modules. A folder with SKILL.md is a skill and
// is not searched further.
func codexSkillFiles(root string) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 3 {
			return
		}
		if depth > 0 {
			if fi, err := os.Stat(filepath.Join(dir, "SKILL.md")); err == nil && !fi.IsDir() {
				out = append(out, filepath.Join(dir, "SKILL.md"))
				return
			}
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			n := e.Name()
			if strings.HasPrefix(n, ".") || n == "node_modules" {
				continue
			}
			if fi, err := os.Stat(filepath.Join(dir, n)); err == nil && fi.IsDir() {
				walk(filepath.Join(dir, n), depth+1)
			}
		}
	}
	walk(root, 0)
	return out
}

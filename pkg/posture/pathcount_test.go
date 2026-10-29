package posture

import (
	"path/filepath"
	"strings"
	"testing"
)

// A plugin's files are one source: one publisher, one switch.
func TestPluginFilesAreOneSource(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.cfg, "plugins", "cache", "m", "p", "1.0.0")
	for _, s := range []string{"a", "b", "c"} {
		f.write(filepath.Join(root, "skills", s, "SKILL.md"), "---\nname: "+s+"\ndescription: x\n---\nDo "+s+".\n")
	}
	f.write(filepath.Join(root, "commands", "go.md"), "Run it.\n")
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"p@m":[{"scope":"user","installPath":"`+root+`","version":"1.0.0"}]}}`)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"enabledPlugins":{"p@m":true}}`)
	s := f.collectWith(Options{Probe: true})
	var legs []Leg
	for _, l := range UntrustedLegs(s, AgentClaudeCode) {
		if l.Kind == "plugin_file" {
			legs = append(legs, l)
		}
	}
	if len(legs) != 1 || legs[0].ID != "src:plugin:p@m" || !strings.HasPrefix(legs[0].Detail, "4 file(s)") {
		t.Fatalf("plugin legs: %+v", legs)
	}
}

// Every path id is unique, in every fixture-like snapshot agentreach builds.
func TestPathIDsUnique(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	f.write(filepath.Join(proj, "CLAUDE.md"), "<!-- hidden -->\n")
	f.write(filepath.Join(proj, ".env"), "x\n")
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "not a key")
	f.write(filepath.Join(f.home, ".env"), "x\n") // machine-wide, and Codex's project .env for the home project
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n[projects.\""+f.home+"\"]\ntrust_level = \"trusted\"\n[projects.\""+proj+"\"]\ntrust_level = \"trusted\"\n")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	seen := map[string]bool{}
	for _, p := range s.Paths {
		k := p.Agent + " " + p.PathID
		if seen[k] {
			t.Errorf("duplicate path id %s", k)
		}
		seen[k] = true
	}
	legs := map[string]bool{}
	for _, l := range s.Legs {
		k := l.Agent + " " + l.Role + " " + l.LegID + " " + l.ProjectDir
		if legs[k] {
			t.Errorf("duplicate leg %s", k)
		}
		legs[k] = true
	}
	for _, ag := range []string{AgentClaudeCode, AgentCodex} {
		n := 0
		for _, l := range PrivateLegs(s, ag) {
			if l.Path == filepath.Join(f.home, ".env") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: ~/.env is %d private legs, want 1", ag, n)
		}
	}
	if len(s.Paths) == 0 {
		t.Fatal("no paths")
	}
}

// Codex skips a project's .codex folder when it is CODEX_HOME
// (config/src/loader/mod.rs, discover_project_layers, 0.155.1): the home
// folder as a trusted project does not load the user config twice.
func TestCodexHomeIsNotAProjectLayer(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "[projects.\""+f.home+"\"]\ntrust_level = \"trusted\"\n[mcp_servers.local]\ncommand = \"./server\"\n")
	s := f.collect()
	n := 0
	for _, m := range s.MCPServers {
		if m.Agent == AgentCodex {
			n++
			if m.Scope == "project" {
				t.Errorf("user server read again as a project server: %+v", m)
			}
		}
	}
	if n != 1 {
		t.Errorf("codex servers %d, want 1", n)
	}
}

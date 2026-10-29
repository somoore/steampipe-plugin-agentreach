package posture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codexHooks(s *Snapshot) map[string]Hook {
	out := map[string]Hook{}
	for _, h := range s.Hooks {
		if h.Agent == AgentCodex {
			out[h.Scope+":"+h.Event] = h
		}
	}
	return out
}

func TestCodexHooksTrust(t *testing.T) {
	f := newFixture(t)
	proj, other := filepath.Join(f.home, "repo"), filepath.Join(f.home, "other")
	hj := filepath.Join(f.home, ".codex", "hooks.json")
	f.write(hj, `{"hooks":{"PreToolUse":[{"matcher":"shell","hooks":[{"type":"command","command":"a.sh","timeout":5}]}],
	  "PostToolUse":[{"hooks":[{"type":"command","command":"b.sh"}]}],
	  "Stop":[{"hooks":[{"type":"prompt","command":"c"}]}],
	  "SessionEnd":[{"hooks":[{"type":"command","command":"d.sh","timeout":30}]}],
	  "Bogus":[{"hooks":[{"type":"command","command":"e.sh"}]}]}}`)
	f.write(filepath.Join(proj, ".codex", "hooks.json"), `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"p.sh"}]}]}}`)
	f.write(filepath.Join(other, ".codex", "hooks.json"), `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"q.sh"}]}]}}`)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `[projects."`+proj+`"]
trust_level = "trusted"
[projects."`+other+`"]
trust_level = "untrusted"
[hooks.state."`+hj+`:pre_tool_use:0:0"]
trusted_hash = "sha256:`+strings.Repeat("0", 64)+`"
[hooks.state."`+hj+`:session_end:0:0"]
trusted_hash = "sha256:`+strings.Repeat("0", 64)+`"
enabled = false
`)
	s := f.collectWith(Options{Probe: true})
	hooks := codexHooks(s)
	n := 0
	for _, h := range s.Hooks {
		if h.Agent == AgentCodex {
			n++
		}
	}
	if n != 6 {
		t.Fatalf("want 6 Codex hooks (Bogus is not an event), got %d", n)
	}
	if h := hooks["user:PreToolUse"]; h.Runs != nil || h.EffectiveTimeout != 5 || h.Matcher != "shell" {
		t.Errorf("trusted hook: runs=%s timeout=%d matcher=%q", b2s(h.Runs), h.EffectiveTimeout, h.Matcher)
	}
	for k, want := range map[string]string{"user:PostToolUse": "not trusted", "user:Stop": "runs command and mcp_tool", "user:SessionEnd": "turned off", "project:UserPromptSubmit": ""} {
		h := hooks[k]
		if want == "" {
			continue
		}
		if h.Runs == nil || *h.Runs || !strings.Contains(h.RunsReason, want) {
			t.Errorf("%s: runs=%s reason=%q", k, b2s(h.Runs), h.RunsReason)
		}
	}
	if h := hooks["user:SessionEnd"]; h.EffectiveTimeout != 3 {
		t.Errorf("SessionEnd timeout clamps to 3, got %d", h.EffectiveTimeout)
	}
	// Only the untrusted project's hook is reported as blocked by trust; the
	// trusted project's is reported but not trusted yet.
	var blocked, pending int
	for _, h := range s.Hooks {
		if h.Agent == AgentCodex && h.Scope == "project" {
			if strings.Contains(h.RunsReason, "project .codex/ layer is trusted") {
				blocked++
			} else if strings.Contains(h.RunsReason, "not trusted") {
				pending++
			}
		}
	}
	if blocked != 1 || pending != 1 {
		t.Errorf("project hooks: blocked=%d pending=%d", blocked, pending)
	}

	// [features] hooks = false stops every hook.
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "[features]\nhooks = false\n")
	for _, h := range f.collectWith(Options{Probe: true}).Hooks {
		if h.Agent == AgentCodex && (h.Runs == nil || *h.Runs) {
			t.Errorf("hooks off: %s still runs", h.Event)
		}
	}
}

func TestCodexPluginsAndSkills(t *testing.T) {
	f := newFixture(t)
	cache := filepath.Join(f.home, ".codex", "plugins", "cache")
	// Version choice: 1.10.0 beats 1.9.0; an unconfigured plugin is ignored.
	f.write(filepath.Join(cache, "m", "a", "1.9.0", "skills", "old", "SKILL.md"), "old\n")
	f.write(filepath.Join(cache, "m", "a", "1.10.0", "skills", "x", "SKILL.md"), "---\nname: x\n---\nbody\n")
	f.write(filepath.Join(cache, "m", "a", "1.10.0", "hooks", "hooks.json"), `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"s.sh"}]}]}}`)
	f.write(filepath.Join(cache, "m", "a", "1.10.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"node","args":["s.js"]}}}`)
	f.write(filepath.Join(cache, "m", "off", "local", "skills", "y", "SKILL.md"), "y\n")
	f.write(filepath.Join(cache, "m", "stray", "1.0.0", "skills", "z", "SKILL.md"), "z\n")
	// Skills: user, deprecated CODEX_HOME, bundled .system (skipped), one turned off.
	f.write(filepath.Join(f.home, ".agents", "skills", "u", "SKILL.md"), "u\n")
	f.write(filepath.Join(f.home, ".codex", "skills", "legacy", "SKILL.md"), "l\n")
	f.write(filepath.Join(f.home, ".codex", "skills", ".system", "sys", "SKILL.md"), "s\n")
	f.write(filepath.Join(f.home, ".agents", "skills", "gone", "SKILL.md"), "g\n")
	gone := filepath.Join(f.home, ".agents", "skills", "gone", "SKILL.md")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `[plugins."a@m"]
[plugins."off@m"]
enabled = false
[plugins."a@m".mcp_servers.srv]
default_tools_approval_mode = "approve"
[[skills.config]]
path = "`+gone+`"
enabled = false
`)
	s := f.collectWith(Options{Probe: true})
	pl := map[string]Plugin{}
	for _, p := range s.Plugins {
		if p.Agent == AgentCodex {
			pl[p.FullName] = p
		}
	}
	if len(pl) != 2 {
		t.Fatalf("plugins: %v", pl)
	}
	if a := pl["a@m"]; a.Version != "1.10.0" || !a.HasHooks || !a.HasMCP || a.SkillCount != 1 || a.Enabled == nil || !*a.Enabled {
		t.Errorf("a@m: %+v", a)
	}
	if o := pl["off@m"]; o.Version != "local" || o.Enabled == nil || *o.Enabled || o.Pinned != nil {
		t.Errorf("off@m: %+v", o)
	}
	skills := map[string]InstructionFile{}
	for _, f := range s.InstructionFiles {
		if f.Agent == AgentCodex && f.Kind == "skill" {
			skills[filepath.Base(filepath.Dir(f.Path))] = f
		}
	}
	for _, n := range []string{"u", "legacy", "x", "y"} {
		if _, ok := skills[n]; !ok {
			t.Errorf("skill %s missing: %v", n, skills)
		}
	}
	for _, n := range []string{"sys", "gone", "z", "old"} {
		if _, ok := skills[n]; ok {
			t.Errorf("skill %s should not load", n)
		}
	}
	if x := skills["x"]; !x.Untrusted || !x.ThirdParty || x.PluginName != "a@m" {
		t.Errorf("plugin skill: %+v", x)
	}
	if y := skills["y"]; y.Untrusted {
		t.Errorf("a disabled plugin's skill is not untrusted input: %+v", y)
	}
	for _, m := range s.MCPServers {
		if m.Agent == AgentCodex && m.Name == "srv" && (m.Scope != "plugin" || m.ToolApproval != ApprovalNone || m.PluginName != "a@m") {
			t.Errorf("plugin mcp: %+v", m)
		}
	}
	// The plugin's untrusted hook is not a leg; its skill and server are.
	ComputePaths(s)
	var hookLeg, skillLeg bool
	for _, l := range s.Legs {
		if l.Agent == AgentCodex {
			hookLeg = hookLeg || l.Kind == "plugin_hook"
			skillLeg = skillLeg || l.Kind == "plugin_file"
		}
	}
	if hookLeg || !skillLeg {
		t.Errorf("legs: plugin hook %v, plugin skill %v", hookLeg, skillLeg)
	}
}

func TestCodexServiceGate(t *testing.T) {
	base := codexGate{Sandbox: "read-only", Approval: "on-request"}
	base.decide(false)
	netOn := codexGate{Sandbox: "workspace-write", Approval: "on-request", NetworkAccess: true}
	netOn.decide(false)
	never := codexGate{Sandbox: "workspace-write", Approval: "never"}
	never.decide(false)
	full := codexGate{Sandbox: "danger-full-access", Approval: "never"}
	full.decide(false)
	for _, c := range []struct {
		name       string
		g          codexGate
		kind, goos string
		want       string
		allowed    string
	}{
		{"tcp blocked, escalation", base, "tcp", "darwin", ApprovalPrompt, "false"},
		{"tcp network on", netOn, "tcp", "darwin", ApprovalNone, "true"},
		{"socket stays refused on macOS with network on", netOn, "unix_socket", "darwin", ApprovalPrompt, "false"},
		{"socket on Linux with network on", netOn, "unix_socket", "linux", ApprovalNone, "true"},
		{"socket on Linux, network off", base, "unix_socket", "linux", ApprovalUnknown, "nil"},
		{"never refuses", never, "tcp", "darwin", ApprovalDenied, "false"},
		{"full access", full, "unix_socket", "darwin", ApprovalNone, "nil"},
	} {
		got, allowed, _ := codexServiceGate(c.g, c.kind, c.goos)
		if got != c.want || b2s(allowed) != c.allowed {
			t.Errorf("%s: %s allowed=%s", c.name, got, b2s(allowed))
		}
	}
}

// In a trusted project that turns network on, a TCP service needs nothing,
// but the Docker socket still needs the escalation (macOS).
func TestCodexServicesInProjectSession(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "repo")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `[projects."`+proj+`"]
trust_level = "trusted"
`)
	f.write(filepath.Join(proj, ".codex", "config.toml"), "[sandbox_workspace_write]\nnetwork_access = true\n")
	f.write(filepath.Join(proj, ".agents", "skills", "s", "SKILL.md"), "s\n")
	if err := os.Chmod(filepath.Join(proj, ".agents", "skills", "s", "SKILL.md"), 0o666); err != nil {
		t.Fatal(err)
	}
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "fixture\n")
	sock := "~/.docker/run/docker.sock"
	s := f.collectWith(Options{Probe: true, GOOS: "darwin", Agents: []string{AgentCodex}, Services: []FixtureService{
		{Kind: "tcp", Target: "127.0.0.1:2375", Process: "dockerd", Reachable: true},
		{Kind: "unix_socket", Target: sock, Reachable: true},
	}})
	got := map[string]string{}
	for _, p := range s.Paths {
		if p.Agent == AgentCodex && p.ProjectDir == proj && p.ExitKind == "local_service" {
			got[p.ExitID] = p.Approval
		}
	}
	tcp, unix := got["exit:127.0.0.1:2375"], got["exit:"+expandHome(sock, f.home)]
	if tcp != ApprovalNone || unix != ApprovalPrompt {
		t.Errorf("project session: tcp %q socket %q (%v)", tcp, unix, got)
	}

	// never machine-wide refuses both; the network-on project still reaches
	// TCP with nothing, and a full-access project reaches the socket too.
	full := filepath.Join(f.home, "full")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `approval_policy = "never"
[projects."`+proj+`"]
trust_level = "trusted"
[projects."`+full+`"]
trust_level = "trusted"
`)
	f.write(filepath.Join(full, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	f.write(filepath.Join(full, "AGENTS.md"), "x\n")
	if err := os.Chmod(filepath.Join(full, "AGENTS.md"), 0o666); err != nil {
		t.Fatal(err)
	}
	s = f.collectWith(Options{Probe: true, GOOS: "darwin", Agents: []string{AgentCodex}, Services: []FixtureService{
		{Kind: "tcp", Target: "127.0.0.1:2375", Process: "dockerd", Reachable: true},
		{Kind: "unix_socket", Target: sock, Reachable: true},
	}})
	got = map[string]string{}
	for _, p := range s.Paths {
		if p.Agent == AgentCodex && p.ExitKind == "local_service" {
			got[strings.TrimPrefix(p.ProjectDir, f.home)+" "+strings.TrimPrefix(p.ExitID, "exit:")] = p.Approval
		}
	}
	want := map[string]string{
		"/repo 127.0.0.1:2375@" + proj:                   ApprovalNone,
		"/full 127.0.0.1:2375@" + full:                   ApprovalNone,
		"/full " + expandHome(sock, f.home) + "@" + full: ApprovalNone,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q (all: %v)", k, got[k], got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra service paths: %v", got)
	}
}

func TestCodexWriteTargets(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "repo")
	f.write(filepath.Join(proj, "AGENTS.md"), "a\n")
	f.write(filepath.Join(proj, "package.json"), "{}\n")
	f.write(filepath.Join(proj, ".git", "config"), "[core]\n")
	f.write(filepath.Join(proj, ".github", "workflows", "ci.yml"), "on: push\n")
	f.write(filepath.Join(f.home, ".zshrc"), "x\n")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `[projects."`+proj+`"]
trust_level = "trusted"
`)
	rows := func(s *Snapshot) map[string]WriteTarget {
		out := map[string]WriteTarget{}
		for _, w := range s.WriteTargets {
			if w.Agent == AgentCodex {
				out[strings.TrimPrefix(w.Path, f.home+"/")+"@"+strings.TrimPrefix(w.SessionDir, f.home+"/")] = w
			}
		}
		return out
	}
	r := rows(f.collectWith(Options{Probe: true}))
	if w := r["repo/AGENTS.md@repo"]; !boolOf(w.WritableViaBash) || w.EditToolApproval != "allowed" || w.SandboxWriteRule != "cwd" {
		t.Errorf("AGENTS.md: %+v", w)
	}
	if w := r["repo/.git/config@repo"]; boolOf(w.WritableViaBash) || !w.SandboxProtected || w.EditToolApproval != "prompt" {
		t.Errorf(".git/config: %+v", w)
	}
	if w := r["repo/.codex/config.toml@repo"]; w.Path != "" {
		t.Errorf("a missing .codex/config.toml is not a row: %+v", w)
	}
	if w := r[".zshrc@"]; boolOf(w.WritableViaBash) || w.EditToolApproval != "prompt" {
		t.Errorf("machine .zshrc: %+v", w)
	}

	// writable_roots = [home] makes ~/.zshrc writable in that project; never
	// refuses everything outside the roots.
	f.write(filepath.Join(proj, ".codex", "config.toml"), "approval_policy = \"never\"\n[sandbox_workspace_write]\nwritable_roots = [\""+f.home+"\"]\n")
	s := f.collectWith(Options{Probe: true})
	r = rows(s)
	if w := r[".zshrc@repo"]; !boolOf(w.WritableViaBash) || w.EditToolApproval != "allowed" || !strings.HasPrefix(w.SandboxWriteRule, "writable_roots") {
		t.Errorf("writable_roots .zshrc: %+v", w)
	}
	if w := r["repo/.codex/config.toml@repo"]; !w.SandboxProtected || w.EditToolApproval != "denied" {
		t.Errorf(".codex under never: %+v", w)
	}
	for _, l := range WriteLegs(s, AgentCodex) {
		if strings.HasSuffix(l.ID, "/repo/.codex/config.toml") {
			t.Errorf("a target never can write is not a leg: %+v", l)
		}
	}

	// danger-full-access: the user's own permissions decide.
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n")
	r = rows(f.collectWith(Options{Probe: true}))
	if w := r[".zshrc@"]; !boolOf(w.WritableViaBash) || w.EditToolApproval != "allowed" {
		t.Errorf("full access .zshrc: %+v", w)
	}
}

func TestCodexVersionOrder(t *testing.T) {
	for _, c := range [][2]string{{"1.9.0", "1.10.0"}, {"1.0.0-rc1", "1.0.0"}, {"abc", "abd"}} {
		if compareCodexVersions(c[0], c[1]) >= 0 {
			t.Errorf("%s should sort before %s", c[0], c[1])
		}
	}
}

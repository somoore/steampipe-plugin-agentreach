package posture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// One allow-listed MCP server does not open the others: exits are grouped
// per gate, so the classifier-gated servers keep their own exit.
func TestMCPExitsSplitByGate(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"auto","allow":["mcp__open"]}}`)
	f.write(filepath.Join(f.home, ".claude.json"), `{"mcpServers":{"open":{"command":"a"},"b":{"command":"b"},"c":{"command":"c"}}}`)
	s := f.collectWith(Options{Probe: true})
	got := map[string]string{}
	for _, l := range ExitLegs(s, AgentClaudeCode) {
		if l.Kind == "mcp_process" {
			got[l.Approval] = l.Title
		}
	}
	if len(got) != 2 || !strings.Contains(got[ApprovalNone], "open") || strings.Contains(got[ApprovalNone], "b") ||
		!strings.Contains(got[ApprovalClassifier], "b, c") {
		t.Fatalf("mcp exits by gate: %v", got)
	}
}

// A plugin installed at local scope for the home folder records its
// decision in ~/.claude/settings.local.json; its components load only in
// sessions there.
func TestHomeLocalPluginDecision(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.cfg, "plugins", "cache", "m", "p", "1")
	f.write(filepath.Join(root, "hooks", "hooks.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}`)
	f.write(filepath.Join(root, ".mcp.json"), `{"mcpServers":{"srv":{"type":"http","url":"https://mcp.invalid"}}}`)
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"p@m":[{"scope":"local","projectPath":"`+f.home+`","installPath":"`+root+`","version":"1"}]}}`)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"enabledPlugins":{"p@m":true}}`)

	s := f.collectWith(Options{Probe: true})
	for _, m := range s.MCPServers {
		if m.PluginName == "p@m" && m.ProjectDir != f.home {
			t.Errorf("local-scope plugin server is machine-wide: %q", m.ProjectDir)
		}
	}
	for _, l := range ExitLegs(s, AgentClaudeCode) {
		if l.Kind == "plugin_hooks" && l.ProjectDir != f.home {
			t.Errorf("hooks exit %s not scoped to the home project", l.ID)
		}
	}

	f.write(filepath.Join(f.cfg, "settings.local.json"), `{"enabledPlugins":{"p@m":false}}`)
	s = f.collectWith(Options{Probe: true})
	for _, p := range s.Plugins {
		if p.FullName == "p@m" && (p.Enabled == nil || *p.Enabled) {
			t.Errorf("home settings.local.json false ignored: %v", p.Enabled)
		}
	}
	for _, l := range ExitLegs(s, AgentClaudeCode) {
		if l.Kind == "plugin_hooks" || l.Kind == "mcp_remote" {
			t.Errorf("disabled plugin still an exit: %s", l.ID)
		}
	}
}

// Catalog files that point at a credential, or hold it encrypted, rank
// below the credentials themselves.
func TestPathTierOverrides(t *testing.T) {
	for path, want := range map[string]int{
		"/h/.aws/credentials": 1, "/h/.aws/config": 2, "/h/.aws/sso/cache": 1,
		"/h/.gitconfig": 3, "/h/.config/gh/hosts.yml": 2, "/h/Library/Keychains/login.keychain-db": 2,
	} {
		cat := "cloud_credential"
		switch {
		case strings.Contains(path, "git") || strings.Contains(path, "gh/"):
			cat = "vcs_credential"
		case strings.Contains(path, "Keychains"):
			cat = "secrets_manager"
		}
		if got := tierFor(cat, path); got != want {
			t.Errorf("%s: tier %d, want %d", path, got, want)
		}
	}
}

// A coding agent's commit is named as such, not as another person's.
func TestCodingAgentAuthorReason(t *testing.T) {
	if !codingAgentIdentity("NoReply@Anthropic.com") || codingAgentIdentity("someone@example.com") {
		t.Fatal("codingAgentIdentity")
	}
}

// In auto mode the Read tool is auto-approved outside the working
// directories apart from a one-time prompt, so a home file read by the
// Read tool alone is not gated by the classifier.
func TestAutoModeReadToolGate(t *testing.T) {
	c := &ccCollector{effMode: "auto"}
	if g := c.readApproval(false, false, true, ""); g != ApprovalNone {
		t.Errorf("auto Read tool outside: %s", g)
	}
	c.effMode = "default"
	if g := c.readApproval(false, false, true, ""); g != ApprovalPrompt {
		t.Errorf("manual Read tool outside: %s", g)
	}
}

// A server whose absolute launcher is gone cannot start, so it is no exit;
// a bare command name is assumed to resolve.
func TestMissingLauncherIsNoExit(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.home, "bin", "srv")
	f.write(bin, "#!/bin/sh\n")
	f.write(filepath.Join(f.home, ".claude.json"), `{"mcpServers":{"gone":{"command":"`+filepath.Join(f.home, "nope", "srv")+`"},"here":{"command":"`+bin+`"},"bare":{"command":"srv"}}}`)
	s := f.collectWith(Options{Probe: true})
	var titles []string
	for _, l := range ExitLegs(s, AgentClaudeCode) {
		if l.Kind == "mcp_process" {
			titles = append(titles, l.Title)
		}
	}
	if len(titles) != 1 || strings.Contains(titles[0], "gone") || !strings.Contains(titles[0], "bare, here") {
		t.Fatalf("mcp exits: %v", titles)
	}
	for _, m := range s.MCPServers {
		want := map[string]string{"gone": "false", "here": "true", "bare": "nil"}[m.Name]
		got := "nil"
		if m.CommandExists != nil {
			got = map[bool]string{true: "true", false: "false"}[*m.CommandExists]
		}
		if got != want {
			t.Errorf("%s command_exists %s, want %s", m.Name, got, want)
		}
	}
}

// A coding agent's commit is flagged as third party, and its reason names
// the agent rather than reading as another person's commit.
func TestCodingAgentCommitIsFlagged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	git := func(email string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", proj, "-c", "user.name=x", "-c", "user.email=" + email, "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	f.write(filepath.Join(proj, "a.txt"), "a\n")
	git("me@example.com", "init", "-q")
	git("me@example.com", "config", "user.email", "me@example.com")
	git("me@example.com", "add", "a.txt")
	git("me@example.com", "commit", "-qm", "a")
	f.write(filepath.Join(proj, "b.txt"), "b\n")
	git("me@example.com", "add", "b.txt")
	git("me@example.com", "commit", "-qm", "b") // me is the most frequent author
	f.write(filepath.Join(proj, "CLAUDE.md"), "Be brief.\n")
	git("noreply@anthropic.com", "add", "CLAUDE.md")
	git("noreply@anthropic.com", "commit", "-qm", "agent")
	f.write(filepath.Join(proj, ".claude", "agents", "r.md"), "---\nname: r\ndescription: x\n---\nReview.\n")
	git("other@example.com", "add", ".")
	git("other@example.com", "commit", "-qm", "other")

	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	found := false
	for _, i := range s.InstructionFiles {
		if i.Path != filepath.Join(proj, "CLAUDE.md") {
			continue
		}
		found = true
		if !i.ThirdParty || !strings.Contains(i.UntrustedReason, "a coding agent (noreply@anthropic.com)") {
			t.Errorf("agent-committed CLAUDE.md: third_party=%v reason=%q", i.ThirdParty, i.UntrustedReason)
		}
		if i.GitUncommitted || strings.Contains(i.UntrustedReason, "uncommitted") {
			t.Errorf("clean file marked uncommitted: %q", i.UntrustedReason)
		}
	}
	if !found {
		t.Fatal("CLAUDE.md not collected")
	}

	// A local edit since that commit is named in the reason.
	f.write(filepath.Join(proj, "CLAUDE.md"), "Be brief. Edited here.\n")
	s = f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	for _, i := range s.InstructionFiles {
		if i.Path == filepath.Join(proj, "CLAUDE.md") && (!i.GitUncommitted || !strings.Contains(i.UntrustedReason, "uncommitted changes on this machine")) {
			t.Errorf("edited CLAUDE.md: uncommitted=%v reason=%q", i.GitUncommitted, i.UntrustedReason)
		}
	}
}

// A role-credential cache whose newest entry is older than a role session
// can last says so; a fresh one says nothing.
func TestStaleCredentialCacheNote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".aws", "cli", "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if n := cacheNote(dir, time.Now()); !strings.Contains(n, "Empty") {
		t.Errorf("empty cache: %q", n)
	}
	p := filepath.Join(dir, "a.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if n := cacheNote(dir, now); n != "" {
		t.Errorf("fresh cache: %q", n)
	}
	old := now.Add(-72 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if n := cacheNote(dir, now); !strings.Contains(n, "3 day(s) ago") || !strings.Contains(n, "likely expired") {
		t.Errorf("stale cache: %q", n)
	}
	if n := cacheNote(filepath.Join(t.TempDir(), ".ssh"), now); n != "" {
		t.Errorf("not a cache: %q", n)
	}
}

// Repository config cannot make a scan run a program: agentreach's git calls
// ignore core.fsmonitor and never refresh the index.
func TestRepoConfigRunsNothing(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	marker := filepath.Join(f.home, "ran")
	hook := filepath.Join(f.home, "fsmon.sh")
	f.write(hook, "#!/bin/sh\ntouch "+marker+"\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(filepath.Join(proj, "CLAUDE.md"), "Be brief.\n")
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "me@example.com"}, {"config", "user.name", "x"},
		{"add", "CLAUDE.md"}, {"-c", "commit.gpgsign=false", "commit", "-qm", "a"},
		{"config", "core.fsmonitor", hook},
	} {
		if out, err := exec.Command("git", append([]string{"-C", proj}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	os.Remove(marker)
	index, _ := os.Stat(filepath.Join(proj, ".git", "index"))
	f.write(filepath.Join(proj, "CLAUDE.md"), "Be brief. Edited.\n")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	if _, err := os.Stat(marker); err == nil {
		t.Error("core.fsmonitor ran during a scan")
	}
	if after, _ := os.Stat(filepath.Join(proj, ".git", "index")); index != nil && after != nil && !after.ModTime().Equal(index.ModTime()) {
		t.Error("scan rewrote the git index")
	}
	for _, i := range s.InstructionFiles {
		if i.Path == filepath.Join(proj, "CLAUDE.md") && !i.GitUncommitted {
			t.Error("edit not detected without git status")
		}
	}
}

// A project MCP server with no decision loads only once approved, so its
// paths wait for that prompt.
func TestPendingMCPSourceIsGated(t *testing.T) {
	f := newFixture(t)
	a := filepath.Join(f.home, "a")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	f.write(filepath.Join(a, ".mcp.json"), `{"mcpServers":{"x":{"command":"node","args":["x.js"]}}}`)
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "not a key")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{a}})
	n := 0
	for _, p := range s.Paths {
		if p.SourceKind != "mcp" {
			continue
		}
		n++
		if p.SourceApproval != ApprovalPrompt || p.Approval != ApprovalPrompt {
			t.Errorf("%s: source %s, path %s; want prompt", p.PathID, p.SourceApproval, p.Approval)
		}
	}
	if n == 0 {
		t.Fatal("no paths from the pending server")
	}
}

// agentreach inside a sandbox would measure that sandbox, so it says so.
func TestSandboxedProcessDetected(t *testing.T) {
	env := func(k, v string) func(string) string {
		return func(n string) string {
			if n == k {
				return v
			}
			return ""
		}
	}
	if sandboxedProcess(env("SANDBOX_RUNTIME", "1")) == "" || sandboxedProcess(env("CODEX_SANDBOX", "seatbelt")) == "" {
		t.Error("sandbox not detected")
	}
	if sandboxedProcess(env("HOME", "/h")) != "" {
		t.Error("false positive")
	}
}

// Surfaces: the terminal is assumed; claude -p and the SDK start in
// default; VS Code takes claudeCode.initialPermissionMode from JSONC.
func TestStartSurfaces(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{}`)
	vs := vscodeSettingsPath(f.home, "darwin")
	f.write(vs, "{\n  // comment\n  \"claudeCode.initialPermissionMode\": \"manual\", /* x */\n  \"editor.fontSize\": 12,\n}\n")
	a := f.agent(f.collectWith(Options{Probe: true, GOOS: "darwin"}))
	if a.StartSurface != SurfaceTerminal || a.StartSurfaceSource != "assumed" {
		t.Errorf("surface %s from %s", a.StartSurface, a.StartSurfaceSource)
	}
	if a.VscodeInitialPermissionMode != "manual" || a.SurfaceModes[SurfaceVSCode] != "default" {
		t.Errorf("vscode: %q modes %v", a.VscodeInitialPermissionMode, a.SurfaceModes)
	}
	if !strings.HasPrefix(a.SurfaceModes[SurfacePrintSDK], "default") || a.SurfaceModes[SurfaceTerminal] != a.EffectivePermissionMode {
		t.Errorf("modes %v (terminal %s)", a.SurfaceModes, a.EffectivePermissionMode)
	}
	a = f.agent(f.collectWith(Options{Probe: true, GOOS: "darwin", Entrypoint: "sdk-ts"}))
	if a.StartSurface != SurfacePrintSDK || a.StartSurfaceSource != "CLAUDE_CODE_ENTRYPOINT=sdk-ts" {
		t.Errorf("sdk: %s from %s", a.StartSurface, a.StartSurfaceSource)
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{"a": "x // not a comment", /* c */ "b": [1, 2,], // end
}`
	m, err := parseJSONBytes(stripJSONC([]byte(in)))
	if err != nil || m["a"] != "x // not a comment" {
		t.Fatalf("%v %v", m, err)
	}
}

// A fetched page arrives the weakest way it can: preapproved documentation
// domains and saved allow rules fetch with no prompt, so the web source is
// ungated unless a rule covers every domain (tools-reference, "WebFetch tool
// behavior").
func TestWebSourceGate(t *testing.T) {
	webLeg := func(snap *Snapshot) *Leg {
		for _, l := range UntrustedLegs(snap, AgentClaudeCode) {
			if l.ID == "src:web" {
				l := l
				return &l
			}
		}
		return nil
	}
	for name, c := range map[string]struct {
		settings string
		want     string // "" = no web leg
	}{
		"default mode":   {`{"permissions":{"defaultMode":"default"}}`, ApprovalNone},
		"auto mode":      {`{"permissions":{"defaultMode":"auto"}}`, ApprovalNone},
		"bare ask":       {`{"permissions":{"defaultMode":"auto","ask":["WebFetch"]}}`, ApprovalNone}, // not documented to cover preapproved domains
		"ask wildcard":   {`{"permissions":{"defaultMode":"auto","ask":["WebFetch(domain:*)"]}}`, ApprovalPrompt},
		"ask one domain": {`{"permissions":{"ask":["WebFetch(domain:example.com)"]}}`, ApprovalNone},
		"deny":           {`{"permissions":{"deny":["WebFetch"]}}`, ""},
		"env off":        {`{"env":{"CLAUDE_CODE_DISABLE_WEB_FETCH":"1"}}`, ""},
	} {
		f := newFixture(t)
		f.write(filepath.Join(f.cfg, "settings.json"), c.settings)
		snap := f.collectWith(Options{Probe: true})
		l := webLeg(snap)
		switch {
		case c.want == "" && l != nil:
			t.Errorf("%s: web leg present (%s)", name, l.Approval)
		case c.want != "" && l == nil:
			t.Errorf("%s: no web leg", name)
		case l != nil && l.Approval != c.want:
			t.Errorf("%s: web source %s, want %s", name, l.Approval, c.want)
		}
		if c.want != "" && f.agent(snap).WebSourceApproval != c.want {
			t.Errorf("%s: agent web_source_approval %s", name, f.agent(snap).WebSourceApproval)
		}
	}
}

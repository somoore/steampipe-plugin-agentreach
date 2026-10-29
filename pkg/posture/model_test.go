package posture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (f fixture) collectWith(o Options) *Snapshot {
	o.Home, o.ManagedDir, o.PlistPath = f.home, f.managed, "-"
	if o.ClaudeVersion == "" {
		o.ClaudeVersion = "2.1.312"
	}
	return Collect(context.Background(), o)
}

func reachFile(s *Snapshot, path string) (ReachFile, bool) {
	for _, r := range s.ReachFiles {
		if r.Path == path {
			return r, true
		}
	}
	return ReachFile{}, false
}

func b2s(b *bool) string { return fmtBool(b) }

// The sandbox is enabled but not enforced while the unsandboxed retry is
// allowed; a denyRead still blocks the sandboxed read and names the bypass.
func TestSandboxEnforcement(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true,"filesystem":{"denyRead":["~/.ssh"]}}}`)
	s := f.collectWith(Options{Probe: true})
	a := f.agent(s)
	if !a.SandboxEnabled || a.SandboxEnforced || !strings.Contains(a.SandboxBypasses, "unsandboxed_retry") {
		t.Errorf("enabled=%v enforced=%v bypasses=%q", a.SandboxEnabled, a.SandboxEnforced, a.SandboxBypasses)
	}
	r, _ := reachFile(s, filepath.Join(f.home, ".ssh"))
	if b2s(r.ReachableViaBash) != "false" || !strings.Contains(r.BashBypass, "unsandboxed_retry") || r.ReachEvidence != EvidenceInferred || r.ReadableEvidence != EvidenceObserved {
		t.Errorf("ssh: bash=%s bypass=%q ev=%s/%s", b2s(r.ReachableViaBash), r.BashBypass, r.ReachEvidence, r.ReadableEvidence)
	}
	if b2s(r.ReachableViaReadTool) != "true" {
		t.Errorf("denyRead must not stop the Read tool: %s", b2s(r.ReachableViaReadTool))
	}

	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false,"excludedCommands":["docker *"],"filesystem":{"denyRead":["~/.ssh"]}}}`)
	a = f.agent(f.collectWith(Options{Probe: true}))
	// An excluded command runs outside the sandbox, so it is a bypass.
	if a.SandboxEnforced || a.SandboxExcludedCommands != 1 || a.SandboxBypasses != "excluded_commands" {
		t.Errorf("excluded: enforced=%v excluded=%d bypasses=%q", a.SandboxEnforced, a.SandboxExcludedCommands, a.SandboxBypasses)
	}
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false,"filesystem":{"denyRead":["~/.ssh"]}}}`)
	a = f.agent(f.collectWith(Options{Probe: true}))
	if !a.SandboxEnforced || a.SandboxBypasses != "" {
		t.Errorf("strict: enforced=%v bypasses=%q", a.SandboxEnforced, a.SandboxBypasses)
	}

	// bypassPermissions auto-approves the unsandboxed retry.
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"},"sandbox":{"enabled":true,"failIfUnavailable":true,"filesystem":{"denyRead":["~/.ssh"]}}}`)
	r, _ = reachFile(f.collectWith(Options{Probe: true}), filepath.Join(f.home, ".ssh"))
	if b2s(r.ReachableViaBash) != "true" {
		t.Errorf("bypassPermissions + retry should reach: %s", b2s(r.ReachableViaBash))
	}
}

// "When read rules overlap, the rule with the narrower path applies", and a
// repository's allowRead cannot re-open a path user settings deny.
func TestAllowReadReopens(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(f.home, ".aws", "config"), "x")
	f.write(filepath.Join(f.home, ".ssh", "id"), "x")
	f.write(filepath.Join(proj, ".env"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true,"filesystem":{"denyRead":["~/"],"allowRead":["~/.aws"]}}}`)
	f.write(filepath.Join(proj, ".claude", "settings.json"), `{"sandbox":{"filesystem":{"allowRead":["~/.ssh"]}}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	aws, _ := reachFile(s, filepath.Join(f.home, ".aws", "config"))
	ssh, _ := reachFile(s, filepath.Join(f.home, ".ssh"))
	if b2s(aws.ReachableViaBash) != "true" || aws.SandboxAllowReadRule != "~/.aws" {
		t.Errorf("aws: bash=%s allow=%q", b2s(aws.ReachableViaBash), aws.SandboxAllowReadRule)
	}
	if b2s(ssh.ReachableViaBash) != "false" || ssh.SandboxDenyReadRule != "~/" {
		t.Errorf("ssh: bash=%s deny=%q (project allowRead must not re-open a user deny)", b2s(ssh.ReachableViaBash), ssh.SandboxDenyReadRule)
	}
}

func TestBlockReadsOutsideWorkingDirs(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(f.home, ".aws", "config"), "x")
	f.write(filepath.Join(proj, ".env"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"blockReadsOutsideWorkingDirectories":true}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	aws, _ := reachFile(s, filepath.Join(f.home, ".aws", "config"))
	env, _ := reachFile(s, filepath.Join(proj, ".env"))
	if b2s(aws.ReachableViaReadTool) != "false" || aws.ReadBlockRule == "" {
		t.Errorf("home file: tool=%s block=%q", b2s(aws.ReachableViaReadTool), aws.ReadBlockRule)
	}
	if b2s(aws.ReachableViaBash) != "true" {
		t.Errorf("sandbox off: shell read is not fenced: %s", b2s(aws.ReachableViaBash))
	}
	if b2s(env.ReachableViaReadTool) != "true" || env.ReadBlockRule != "" {
		t.Errorf("project file stays readable: tool=%s block=%q", b2s(env.ReachableViaReadTool), env.ReadBlockRule)
	}
	if !f.agent(s).BlockReadsOutsideWorkDirs {
		t.Error("agent flag")
	}
}

func TestEffectiveModeByVersion(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		settings, version, mode, source string
	}{
		{`{}`, "2.1.312", "auto", "built_in"},
		{`{}`, "2.1.200", "default", "built_in"},
		{`{"disableAutoMode":"disable"}`, "2.1.312", "default", "built_in"},
		{`{"permissions":{"defaultMode":"acceptEdits"}}`, "2.1.312", "acceptEdits", "user"},
	} {
		f.write(filepath.Join(f.cfg, "settings.json"), c.settings)
		a := f.agent(f.collectWith(Options{ClaudeVersion: c.version}))
		if a.EffectivePermissionMode != c.mode || a.PermissionModeSource != c.source {
			t.Errorf("%s @%s: got %s/%s want %s/%s", c.settings, c.version, a.EffectivePermissionMode, a.PermissionModeSource, c.mode, c.source)
		}
	}
}

// Fake credentials placed in every free-text field never reach the
// marshalled snapshot, which is what JSON exports and every table read.
func TestRedactionEverySurface(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	sk := fake("s"+"k-", 6)
	gh := fake("gh"+"p_", 9)
	tok := fake("t", 8)
	pw := fake("pw", 5)
	f.write(filepath.Join(f.home, ".claude.json"), `{"mcpServers":{
	  "a":{"command":"npx","args":["-y","@acme/mcp@1.0.0","--api-key","`+sk+`"]},
	  "b":{"type":"http","url":"https://mcp.example.com/sse?token=`+tok+`"},
	  "c":{"type":"http","url":"https://bob:`+pw+`@mcp.example.com/x"}}}`)
	f.write(filepath.Join(f.cfg, "settings.json"), `{
	  "statusLine":{"type":"command","command":"GITHUB_TOKEN=`+gh+` ~/bin/status"},
	  "permissions":{"allow":["Bash(curl -H \"Authorization: Bearer `+tok+`\" https://api.example.com)"]},
	  "hooks":{"Stop":[{"hooks":[
	    {"type":"command","command":"notify --token `+tok+`"},
	    {"type":"http","url":"https://hooks.example.com/x?key=`+tok+`"},
	    {"type":"command","command":"node","args":["hook.js","--secret","`+sk+`"]}]}]}}`)
	f.write(filepath.Join(proj, ".mcp.json"), `{"mcpServers":{"d":{"command":"uvx","args":["srv==1.0","TOKEN=`+gh+`"]}}}`)
	// Codex surfaces: config.toml MCP args, url, env and headers.
	// Codex hooks.json commands, notify argv and plugin MCP servers too.
	f.write(filepath.Join(f.home, ".codex", "hooks.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"notify --token `+tok+`"}]}]}}`)
	f.write(filepath.Join(f.home, ".codex", "plugins", "cache", "m", "p", "1.0.0", ".mcp.json"), `{"mcpServers":{"g":{"command":"npx","args":["-y","@acme/mcp@1.0.0","--api-key","`+sk+`"]}}}`)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `sandbox_mode = "workspace-write"
notify = ["notify-send", "--token", "`+tok+`"]
[plugins."p@m"]
[mcp_servers.e]
command = "npx"
args = ["-y", "@acme/mcp@1.0.0", "--api-key", "`+sk+`"]
[mcp_servers.e.env]
API_TOKEN = "`+gh+`"
[mcp_servers.f]
url = "https://mcp.example.com/sse?token=`+tok+`"
[mcp_servers.f.http_headers]
Authorization = "Bearer `+tok+`"
`)
	// A CI workflow: claude_args rules, a prompt, a run script and env values.
	f.write(filepath.Join(proj, ".github", "workflows", "claude.yml"), `on: issue_comment
jobs:
  c:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "use `+pw+`"
          claude_args: |
            --allowedTools "Bash(curl -H 'Authorization: Bearer `+tok+`' https://api.example.com)"
          github_token: `+gh+`
      - run: claude -p "key `+sk+`" --permission-mode `+pw+`
        env:
          API_TOKEN: `+gh+`
`)
	// Launch flags: rules from an alias, and running-session argv.
	f.write(filepath.Join(f.home, ".zshrc"), `alias claude="claude --allowedTools 'Bash(curl -H Authorization: Bearer `+tok+` https://api.example.com)' -p `+sk+`"`+"\n")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}, Processes: []string{"7 claude --api-key " + gh + " --permission-mode " + pw}})
	b, _ := json.Marshal(s)
	for _, secret := range []string{sk, gh, tok, pw} {
		if strings.Contains(string(b), secret) {
			t.Errorf("secret %q... reached the snapshot", secret[:6])
		}
	}
	if !strings.Contains(string(b), "@acme/mcp@1.0.0") || !strings.Contains(string(b), "mcp.example.com") {
		t.Error("redaction removed non-secret context")
	}
	if len(s.CIWorkflows) != 2 || !s.CIWorkflows[0].HasInlineSecret || s.CIWorkflows[0].GitHubToken != "inline" {
		t.Errorf("ci rows: %+v", s.CIWorkflows)
	}
	for _, m := range s.MCPServers {
		if m.Name == "a" && (!m.Redacted || !m.HasInlineSecret || m.Pinned == nil || !*m.Pinned) {
			t.Errorf("mcp a: redacted=%v secret=%v pinned=%s", m.Redacted, m.HasInlineSecret, b2s(m.Pinned))
		}
	}
}

func TestHookFields(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"hooks":{
	  "PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"node","args":["x.js"],"if":"Bash(rm *)"}]}],
	  "UserPromptSubmit":[{"hooks":[{"type":"http","url":"https://h.example.com/a"}]}]}}`)
	f.write(filepath.Join(f.cfg, "skills", "s", "SKILL.md"), "---\nname: s\ndescription: d\nhooks:\n  PostToolUse:\n    - matcher: Edit\n      hooks:\n        - type: command\n          command: ./fmt.sh\n---\nbody\n")
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"allowManagedHooksOnly":true}`)
	s := f.collectWith(Options{})
	var pre, http, skill *Hook
	for i := range s.Hooks {
		h := &s.Hooks[i]
		switch {
		case h.Event == "PreToolUse":
			pre = h
		case h.HookType == "http":
			http = h
		case h.Origin == "skill":
			skill = h
		}
	}
	if pre == nil || pre.If != "Bash(rm *)" || len(pre.Args) != 1 || pre.EffectiveTimeout != 600 || pre.Runs == nil || *pre.Runs || pre.RunsReason != "allowManagedHooksOnly" {
		t.Errorf("pre: %+v", pre)
	}
	if http == nil || http.URL != "https://h.example.com/a" || http.EffectiveTimeout != 30 {
		t.Errorf("http: %+v", http)
	}
	if skill == nil || skill.Command != "./fmt.sh" || skill.Event != "PostToolUse" {
		t.Errorf("skill frontmatter hook: %+v", skill)
	}
}

func TestPluginScopesAndMCP(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	root := filepath.Join(f.cfg, "plugins", "cache", "m", "p", "1.0.0")
	f.write(filepath.Join(root, ".mcp.json"), `{"db":{"command":"node","args":["db.js"]}}`)
	f.write(filepath.Join(root, "CLAUDE.md"), "plugin rules\n")
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"p@m":[
	  {"scope":"user","installPath":"`+root+`","version":"1.0.0"},
	  {"scope":"local","projectPath":"`+proj+`","installPath":"`+root+`","version":"1.0.0"}]}}`)
	f.write(filepath.Join(proj, ".claude", "settings.local.json"), `{"enabledPlugins":{"p@m":false}}`)
	f.write(filepath.Join(proj, "README"), "x")
	s := f.collectWith(Options{ProjectDirs: []string{proj}})
	var user, local *Plugin
	for i := range s.Plugins {
		if s.Plugins[i].Scope == "user" {
			user = &s.Plugins[i]
		} else {
			local = &s.Plugins[i]
		}
	}
	if user == nil || user.Enabled != nil || local == nil || local.Enabled == nil || *local.Enabled {
		t.Errorf("enabled: user=%v local=%v", user, local)
	}
	found := false
	for _, m := range s.MCPServers {
		if m.Scope == "plugin" && m.Name == "db" && m.PluginName == "p@m" {
			found = true
		}
	}
	if !found {
		t.Error("plugin MCP server not emitted")
	}
	untrusted := false
	for _, i := range s.InstructionFiles {
		if i.PluginName == "p@m" && i.Untrusted && strings.Contains(i.UntrustedReason, "plugin p@m") {
			untrusted = true
		}
	}
	if !untrusted {
		t.Error("enabled-by-default plugin file should be an untrusted source")
	}
}

func TestReviewLedger(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.cfg, "plugins", "cache", "m", "p", "1.0.0")
	md := filepath.Join(root, "CLAUDE.md")
	f.write(md, "plugin rules <!-- note -->\n")
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"p@m":[{"scope":"user","installPath":"`+root+`","version":"1.0.0"}]}}`)
	ledger := filepath.Join(f.home, "reviews.json")
	l, _ := LoadReviewLedger(ledger)
	if err := l.Add(md, sha256File(md), "read it", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	get := func() InstructionFile {
		for _, i := range f.collectWith(Options{ReviewLedgerPath: ledger}).InstructionFiles {
			if i.Path == md {
				return i
			}
		}
		t.Fatal("missing")
		return InstructionFile{}
	}
	i := get()
	if !i.Reviewed || i.Untrusted || i.ReviewSignals != "html_comments" {
		t.Errorf("reviewed: %+v", i)
	}
	f.write(md, "plugin rules, edited\n")
	i = get()
	if i.Reviewed || !i.ChangedSinceReview || !i.Untrusted || !strings.Contains(i.UntrustedReason, "changed since review") {
		t.Errorf("changed: %+v", i)
	}
}

func TestWriteTargets(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(proj, ".github", "workflows", "ci.yml"), "x")
	f.write(filepath.Join(proj, ".claude", "settings.json"), `{}`)
	f.write(filepath.Join(proj, "CLAUDE.md"), "x")
	f.write(filepath.Join(proj, "go.mod"), "module x")
	f.write(filepath.Join(f.home, ".zshrc"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"failIfUnavailable":true},"permissions":{"deny":["Edit(go.mod)"]}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	got := map[string]WriteTarget{}
	for _, w := range s.WriteTargets {
		got[Tilde(strings.Replace(w.Path, f.home, "~", 1))] = w
	}
	ci := got["~/proj/.github/workflows"]
	if b2s(ci.WritableViaBash) != "true" || ci.EditToolApproval != "auto" || ci.SandboxProtected {
		t.Errorf("ci: bash=%s edit=%s protected=%v", b2s(ci.WritableViaBash), ci.EditToolApproval, ci.SandboxProtected)
	}
	set := got["~/proj/.claude/settings.json"]
	if b2s(set.WritableViaBash) != "false" || !set.SandboxProtected || set.EditToolApproval != "classifier" {
		t.Errorf("settings: bash=%s protected=%v edit=%s", b2s(set.WritableViaBash), set.SandboxProtected, set.EditToolApproval)
	}
	if got["~/proj/CLAUDE.md"].SandboxProtected || b2s(got["~/proj/CLAUDE.md"].WritableViaBash) != "true" {
		t.Error("project CLAUDE.md is not on the protected list")
	}
	if got["~/proj/go.mod"].EditToolApproval != "denied" {
		t.Errorf("go.mod: %s", got["~/proj/go.mod"].EditToolApproval)
	}
	if z := got["~/.zshrc"]; b2s(z.WritableViaBash) != "false" || z.EditToolApproval != "classifier" {
		t.Errorf("zshrc outside the working dir: bash=%s edit=%s", b2s(z.WritableViaBash), z.EditToolApproval)
	}
}

// Legs that load in one project pair only with that project's legs.
func TestPathsSessionScope(t *testing.T) {
	f := newFixture(t)
	a := filepath.Join(f.home, "a")
	b := filepath.Join(f.home, "b")
	f.write(filepath.Join(a, ".mcp.json"), `{"mcpServers":{"x":{"command":"node","args":["x.js"]}}}`)
	f.write(filepath.Join(a, ".env"), "x")
	f.write(filepath.Join(b, ".env"), "x")
	f.write(filepath.Join(f.home, ".ssh", "id"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"deny":["WebFetch"]}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{a, b}, DeclaredControls: []string{"egress_allowlist"}})
	var toA, toB, toSSH bool
	for _, p := range s.Paths {
		if p.Kind != "confidentiality" || p.SourceKind != "mcp" {
			continue
		}
		switch p.TargetPath {
		case filepath.Join(a, ".env"):
			toA = true
		case filepath.Join(b, ".env"):
			toB = true
		case filepath.Join(f.home, ".ssh"):
			toSSH = true
			if p.ProjectDir != a {
				t.Errorf("ssh path project: %q", p.ProjectDir)
			}
		}
		if p.ExitKind == "internet" && (p.Status != "attested" || !strings.Contains(p.MitigatedBy, "egress_allowlist")) {
			t.Errorf("declared allowlist should mark internet paths attested (unverified): %+v", p)
		}
		if p.SourceKind == "web_tool" || p.ExitKind == "web_tool" {
			t.Error("WebFetch is denied")
		}
	}
	if !toA || toB || !toSSH {
		t.Errorf("session scope: a=%v b=%v ssh=%v", toA, toB, toSSH)
	}
	var env bool
	for _, e := range s.Environment {
		if e.Name == "egress_allowlist" && e.Declared && e.Evidence == EvidenceConfigured {
			env = true
		}
	}
	if !env || s.SchemaVersion == "" || s.SnapshotID == "" || !s.Probed {
		t.Errorf("envelope/env: %v %q %q", env, s.SchemaVersion, s.SnapshotID)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v    string
		want bool
	}{{"2.1.283", true}, {"2.1.312", true}, {"2.1.282", false}, {"2.2.0", true}, {"v3", true}, {"", false}} {
		if got := versionAtLeast(c.v, 2, 1, 283); got != c.want {
			t.Errorf("%s: %v", c.v, got)
		}
	}
	_ = os.Getenv
}

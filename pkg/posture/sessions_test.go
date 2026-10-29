package posture

import (
	"path/filepath"
	"strings"
	"testing"
)

func project(s *Snapshot, dir string) *Project {
	for i := range s.Projects {
		if s.Projects[i].ProjectDir == dir {
			return &s.Projects[i]
		}
	}
	return nil
}

// N6: a project's defaultMode decides its sessions' gates, including which
// allow rules auto mode drops; auto and bypassPermissions do not take
// effect from project files (permission-modes, "Which mode a session starts
// in").
func TestProjectModeGates(t *testing.T) {
	f := newFixture(t)
	a, b, c := filepath.Join(f.home, "a"), filepath.Join(f.home, "b"), filepath.Join(f.home, "c")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"allow":["Bash(python3 *)"]}}`)
	f.write(filepath.Join(a, ".claude", "settings.local.json"), `{"permissions":{"defaultMode":"default"}}`)
	f.write(filepath.Join(b, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	f.write(filepath.Join(c, ".claude", "settings.json"), `{"permissions":{"defaultMode":"dontAsk"}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{a, b, c}})
	if s.Agents[0].EffectivePermissionMode != "auto" || s.Agents[0].NetworkApproval != ApprovalClassifier {
		t.Fatalf("machine: mode %s network %s", s.Agents[0].EffectivePermissionMode, s.Agents[0].NetworkApproval)
	}
	cases := []struct{ dir, mode, source, network string }{
		{a, "default", "local", ApprovalNone},   // the python3 rule auto mode drops applies again
		{b, "default", "project", ApprovalNone}, // bypassPermissions there starts in Manual mode
		{c, "dontAsk", "project", ApprovalNone}, // allow rules still run in dontAsk
	}
	for _, k := range cases {
		p := project(s, k.dir)
		if p == nil || p.EffectivePermissionMode != k.mode || p.PermissionModeSource != k.source || p.NetworkApproval != k.network {
			t.Errorf("%s: %+v", filepath.Base(k.dir), p)
		}
	}
	if p := project(s, c); p.WebFetchApproval != ApprovalDenied || p.ReadApproval != ApprovalDenied {
		t.Errorf("dontAsk denies what would prompt: webfetch %s read %s", p.WebFetchApproval, p.ReadApproval)
	}
}

// N6 in paths: a path whose session starts in a project takes that
// project's gates.
func TestPathsUseProjectGates(t *testing.T) {
	f := newFixture(t)
	a := filepath.Join(f.home, "a")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"allow":["Bash(python3 *)"],"deny":["WebFetch"]}}`)
	f.write(filepath.Join(a, ".claude", "settings.local.json"), `{"permissions":{"defaultMode":"default"}}`)
	// A plugin is a source with no gate of its own, so the path's gate is the
	// project's read and exit gates.
	root := filepath.Join(f.cfg, "plugins", "cache", "m", "p", "1")
	f.write(filepath.Join(root, "skills", "s", "SKILL.md"), "---\nname: s\ndescription: x\n---\nDo it.\n")
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"p@m":[{"scope":"user","installPath":"`+root+`","version":"1"}]}}`)
	f.write(filepath.Join(a, ".env"), "x")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{a}})
	var inA bool
	for _, p := range s.Paths {
		if p.Kind == "confidentiality" && p.ExitID == "exit:internet" && p.ProjectDir == a && p.SourceKind == "plugin_file" {
			inA = true
			if p.Approval != ApprovalNone {
				t.Errorf("internet path in project a: %s, want none (allow rule applies in default mode)", p.Approval)
			}
		}
	}
	if !inA {
		t.Fatal("no internet path in project a")
	}
}

// N4: project allowedDomains and WebFetch(domain:) rules widen that
// project's allowlist, only where the sandbox is on.
func TestProjectAllowedDomains(t *testing.T) {
	f := newFixture(t)
	on, off := filepath.Join(f.home, "on"), filepath.Join(f.home, "off")
	f.write(filepath.Join(on, ".claude", "settings.json"), `{"sandbox":{"enabled":true,"network":{"allowedDomains":["a.example"]}},"permissions":{"allow":["WebFetch(domain:b.example)"]}}`)
	f.write(filepath.Join(off, ".claude", "settings.json"), `{"permissions":{"allow":["WebFetch(domain:c.example)"]}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{on, off}})
	if got := project(s, on).SandboxAllowedDomains; len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Errorf("on: %v", got)
	}
	if got := project(s, off).SandboxAllowedDomains; len(got) != 0 {
		t.Errorf("off: %v (no sandbox, no allowlist)", got)
	}
	var leg bool
	for _, l := range s.Legs {
		if l.LegID == "exit:allowed_domains@"+on && l.ProjectDir == on {
			leg = true
		}
	}
	if !leg {
		t.Error("no allowed_domains exit for the project")
	}
}

// N7: plan mode is reviewed by the classifier unless auto mode is disabled
// or useAutoModeDuringPlan is off.
func TestPlanModeGate(t *testing.T) {
	for _, k := range []struct{ settings, want string }{
		{`{"permissions":{"defaultMode":"plan"}}`, ApprovalClassifier},
		{`{"permissions":{"defaultMode":"plan"},"useAutoModeDuringPlan":false}`, ApprovalPrompt},
		{`{"permissions":{"defaultMode":"plan"},"disableAutoMode":"disable"}`, ApprovalPrompt},
	} {
		f := newFixture(t)
		f.write(filepath.Join(f.cfg, "settings.json"), k.settings)
		s := f.collectWith(Options{Probe: true})
		if got := s.Agents[0].ShellApproval; got != k.want {
			t.Errorf("%s: shell %s, want %s", k.settings, got, k.want)
		}
	}
}

// N8: a local listener is decided like an unlisted host; strictAllowlist
// refuses it in every mode; a socket no rule allows is refused unless a
// command can leave the sandbox.
func TestHostApproval(t *testing.T) {
	svc := []FixtureService{{Kind: "tcp", Target: "127.0.0.1:5432", Process: "postgres", Reachable: true},
		{Kind: "tcp", Target: "127.0.0.1:6379", Process: "redis", Reachable: false}}
	for _, k := range []struct{ settings, want string }{
		{`{"permissions":{"defaultMode":"default"}}`, ApprovalPrompt},
		{`{"permissions":{"defaultMode":"bypassPermissions"}}`, ApprovalNone},
		{`{"sandbox":{"enabled":true},"permissions":{"defaultMode":"default"}}`, ApprovalPrompt},
		{`{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"failIfUnavailable":true,"network":{"strictAllowlist":true}},"permissions":{"defaultMode":"bypassPermissions"}}`, ApprovalDenied},
	} {
		f := newFixture(t)
		f.write(filepath.Join(f.cfg, "settings.json"), k.settings)
		yes := true
		s := f.collectWith(Options{Probe: true, Services: svc, SandboxRuntime: &yes})
		for _, h := range s.ReachHosts {
			switch h.Target {
			case "127.0.0.1:5432":
				if h.Approval != k.want {
					t.Errorf("%s: postgres %s, want %s", k.settings, h.Approval, k.want)
				}
			case "127.0.0.1:6379":
				if h.Approval != ApprovalDenied {
					t.Errorf("unreachable listener: %s", h.Approval)
				}
			}
		}
	}
}

// N9: a file the sandbox blocks but the unsandboxed retry can read stays a
// private leg, gated like the retry.
func TestReadApprovalThroughRetry(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".ssh", "id"), "x")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"sandbox":{"enabled":true,"filesystem":{"denyRead":["~/.ssh"]}},"permissions":{"defaultMode":"default","deny":["Read(~/.ssh/**)"]}}`)
	yes := true
	s := f.collectWith(Options{Probe: true, SandboxRuntime: &yes})
	r, ok := reachFile(s, filepath.Join(f.home, ".ssh"))
	if !ok {
		t.Fatal("no ~/.ssh row")
	}
	if *r.ReachableViaBash || !*r.ReachableViaRetry || r.ReadApproval != ApprovalPrompt {
		t.Errorf("bash %v retry %v approval %s", b2s(r.ReachableViaBash), b2s(r.ReachableViaRetry), r.ReadApproval)
	}
	var leg bool
	for _, l := range s.Legs {
		if l.Role == "private" && l.Path == r.Path {
			leg = l.Approval == ApprovalPrompt && l.Via == "shell_retry"
		}
	}
	if !leg {
		t.Error("retry-only file should be a private leg gated by a prompt")
	}
}

// P15: home settings.local.json is the local file of sessions started in
// the home directory; trusted counts only directories that exist; a url
// with no type is reported.
func TestP15Residue(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.local.json"), `{"permissions":{"deny":["Read(~/.aws/**)"]}}`)
	gone := filepath.Join(f.home, "gone")
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+gone+`":{"hasTrustDialogAccepted":true},"`+f.home+`":{"hasTrustDialogAccepted":true}},"mcpServers":{"u":{"url":"https://mcp.example/x"}}}`)
	s := f.collectWith(Options{Probe: true})
	var local bool
	for _, st := range s.Settings {
		if st.Scope == "local" && st.SourcePath == filepath.Join(f.cfg, "settings.local.json") {
			local = true
		}
	}
	if !local {
		t.Error("~/.claude/settings.local.json not ingested as local scope")
	}
	if n := s.Agents[0].ProjectsTrusted; n != 1 {
		t.Errorf("projects_trusted = %d, want 1 (the missing directory does not count)", n)
	}
	var urlErr bool
	for _, e := range s.Agents[0].CollectErrors {
		if strings.Contains(e, "url without type") {
			urlErr = true
		}
	}
	if !urlErr {
		t.Error("an MCP url without type should be a collect error")
	}
}

// N7: with bypassPermissions in the mode cycle (user defaultMode), a project
// session that starts in plan mode runs planning commands with no
// classifier and no prompt; a disableBypassPermissionsMode lock restores the
// classifier.
func TestPlanModeWithBypassAvailable(t *testing.T) {
	for _, k := range []struct {
		managed, want string
		avail         bool
	}{
		{"", ApprovalNone, true},
		{`{"permissions":{"disableBypassPermissionsMode":"disable"}}`, ApprovalClassifier, false},
	} {
		f := newFixture(t)
		p := filepath.Join(f.home, "p")
		f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
		f.write(filepath.Join(p, ".claude", "settings.json"), `{"permissions":{"defaultMode":"plan"}}`)
		opts := Options{Probe: true, ProjectDirs: []string{p}}
		if k.managed != "" {
			f.write(filepath.Join(f.managed, "managed-settings.json"), k.managed)
		}
		s := f.collectWith(opts)
		if a := s.Agents[0]; a.BypassAvailable != k.avail {
			t.Errorf("managed %q: bypass_available %v (%s)", k.managed, a.BypassAvailable, a.BypassAvailableReason)
		}
		pr := project(s, p)
		if pr == nil || pr.EffectivePermissionMode != "plan" || pr.ShellApproval != k.want {
			t.Errorf("managed %q: project %+v, want plan with shell %s", k.managed, pr, k.want)
		}
	}
}

// N7 hint: skipDangerousModePermissionPrompt says a bypass flag was
// accepted before; agentreach reports it and still does not model the flag.
func TestBypassFlagHint(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"skipDangerousModePermissionPrompt":true,"permissions":{"defaultMode":"default"}}`)
	a := f.collectWith(Options{Probe: true}).Agents[0]
	if a.BypassAvailable || !strings.Contains(a.BypassAvailableReason, "skipDangerousModePermissionPrompt") {
		t.Errorf("got %v %q", a.BypassAvailable, a.BypassAvailableReason)
	}
}

// N6 residue: a session in a project with its own mode writes home files
// under that project's gates, and its integrity paths use them instead of
// the machine-wide row.
func TestHomeWritesUseProjectGates(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.home, "p")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"acceptEdits"}}`)
	f.write(filepath.Join(f.home, ".zshrc"), "x")
	f.write(filepath.Join(p, ".claude", "settings.local.json"), `{"permissions":{"defaultMode":"dontAsk"}}`)
	f.write(filepath.Join(p, "CLAUDE.md"), "<!-- hidden -->")
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{p}})
	zsh := filepath.Join(f.home, ".zshrc")
	var machine, inP *WriteTarget
	for i := range s.WriteTargets {
		w := &s.WriteTargets[i]
		if w.Path == zsh && w.SessionDir == "" {
			machine = w
		}
		if w.Path == zsh && w.SessionDir == p {
			inP = w
		}
	}
	if machine == nil || inP == nil {
		t.Fatalf("rows: machine %v project %v", machine, inP)
	}
	if machine.EditToolApproval != "prompt" || inP.EditToolApproval != "denied" {
		t.Errorf("edit approval: machine %s (want prompt), project %s (want denied in dontAsk)", machine.EditToolApproval, inP.EditToolApproval)
	}
	for _, path := range s.Paths {
		if path.Kind == "integrity" && path.TargetPath == zsh && path.ProjectDir == p && strings.HasSuffix(path.PathID, "write:"+zsh) {
			t.Errorf("project session uses the machine-wide row: %s", path.PathID)
		}
	}
}

// M16: "unknown" is no version, an all-digit date version is a release, a
// bare hex commit floats.
func TestPluginPinnedM16(t *testing.T) {
	for v, want := range map[string]string{"unknown": "nil", "": "nil", "20261028": "true", "1.2.0": "true", "a1b2c3d4e5": "false"} {
		got := "nil"
		if p := pluginPinned(v, ""); p != nil {
			got = map[bool]string{true: "true", false: "false"}[*p]
		}
		if got != want {
			t.Errorf("%q: got %s want %s", v, got, want)
		}
	}
}

// A project's local MCP server loads only in that project's sessions, so its
// exit belongs to that project.
func TestLocalMCPExitPerProject(t *testing.T) {
	f := newFixture(t)
	a := filepath.Join(f.home, "a")
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"default"}}`)
	f.write(filepath.Join(a, ".mcp.json"), `{"mcpServers":{"x":{"command":"node","args":["x.js"]}}}`)
	f.write(filepath.Join(a, ".claude", "settings.local.json"), `{"enabledMcpjsonServers":["x"]}`)
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+a+`":{"hasTrustDialogAccepted":true}}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{a}})
	var found bool
	for _, l := range s.Legs {
		if l.Kind == "mcp_process" {
			found = true
			if l.ProjectDir != a || l.LegID != "exit:mcp_process@"+a {
				t.Errorf("leg %s in %q, want project a", l.LegID, l.ProjectDir)
			}
		}
	}
	if !found {
		t.Fatal("no local MCP exit")
	}
	for _, p := range s.Paths {
		if strings.HasPrefix(p.ExitID, "exit:mcp_process") && p.ProjectDir != a {
			t.Errorf("path %s outside project a", p.PathID)
		}
	}
}

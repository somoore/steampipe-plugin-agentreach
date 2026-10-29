package posture

import (
	"path/filepath"
	"testing"
)

func TestBashRuleCarriesNetwork(t *testing.T) {
	for pat, want := range map[string]bool{
		"Bash":                     true,
		"Bash(*)":                  true,
		"Bash(curl:*)":             true,
		"Bash(curl *)":             true,
		"Bash(/usr/bin/curl *)":    true,
		"Bash(python3:*)":          true,
		"Bash(npm run build:*)":    true,
		"Bash(git push:*)":         true,
		"Bash(git add:*)":          false,
		"Bash(git status)":         false,
		"Bash(ls:*)":               false,
		"Bash(make test)":          false,
		"Bash(FOO=bar curl *)":     true,
		`Bash(P="a b" aws logs:*)`: true,
		"Read(~/.ssh)":             false,
	} {
		if got := bashRuleCarriesNetwork(pat); got != want {
			t.Errorf("%s: got %v want %v", pat, got, want)
		}
	}
}

func exitLeg(s *Snapshot, id string) (Leg, bool) {
	for _, l := range ExitLegs(s, AgentClaudeCode) {
		if l.ID == id {
			return l, true
		}
	}
	return Leg{}, false
}

// TestApprovalGates follows the permission and sandboxing docs: Bash prompts
// unless read-only or allowed; the sandbox auto-allows what runs inside it;
// a host outside allowedDomains is decided by the mode unless strictAllowlist
// refuses it.
func TestApprovalGates(t *testing.T) {
	enforced := `"enabled":true,"failIfUnavailable":true,"allowUnsandboxedCommands":false`
	for _, tc := range []struct {
		name, settings           string
		shell, network, webFetch string
		internet                 string // gate on exit:internet, "" when there is no such leg
	}{
		{"sandbox off, default", `{"permissions":{"defaultMode":"default"}}`, "prompt", "prompt", "prompt", "prompt"},
		{"sandbox off, curl allowed", `{"permissions":{"defaultMode":"default","allow":["Bash(curl:*)"]}}`, "none", "none", "prompt", "none"},
		{"sandbox off, dontAsk", `{"permissions":{"defaultMode":"dontAsk"}}`, "denied", "denied", "denied", ""},
		{"sandbox off, auto", `{"permissions":{"defaultMode":"auto"}}`, "classifier", "classifier", "classifier", "classifier"},
		{"sandbox off, bypass", `{"permissions":{"defaultMode":"bypassPermissions"}}`, "none", "none", "none", "none"},
		{"enforced, default", `{"permissions":{"defaultMode":"default"},"sandbox":{` + enforced + `}}`, "none", "prompt", "prompt", "prompt"},
		{"enforced, no auto-allow", `{"permissions":{"defaultMode":"default"},"sandbox":{` + enforced + `,"autoAllowBashIfSandboxed":false}}`, "prompt", "prompt", "prompt", "prompt"},
		{"enforced, strict", `{"permissions":{"defaultMode":"default"},"sandbox":{` + enforced + `,"network":{"strictAllowlist":true}}}`, "none", "denied", "prompt", ""},
		{"enforced, dontAsk", `{"permissions":{"defaultMode":"dontAsk"},"sandbox":{` + enforced + `}}`, "none", "denied", "denied", ""},
		{"strict but retry allowed by rule", `{"permissions":{"defaultMode":"default","allow":["Bash(curl:*)"]},"sandbox":{"enabled":true,"failIfUnavailable":true,"network":{"strictAllowlist":true}}}`, "none", "none", "prompt", "none"},
		{"WebFetch allowed", `{"permissions":{"defaultMode":"default","allow":["WebFetch"]}}`, "prompt", "prompt", "none", "prompt"},
		{"WebFetch denied", `{"permissions":{"defaultMode":"default","deny":["WebFetch"]}}`, "prompt", "prompt", "denied", "prompt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.write(filepath.Join(f.cfg, "settings.json"), tc.settings)
			s := f.collectWith(Options{Probe: true})
			a := f.agent(s)
			if a.ShellApproval != tc.shell || a.NetworkApproval != tc.network || a.WebFetchApproval != tc.webFetch {
				t.Errorf("shell=%s network=%s webfetch=%s (%s), want %s %s %s", a.ShellApproval, a.NetworkApproval, a.WebFetchApproval, a.NetworkApprovalReason, tc.shell, tc.network, tc.webFetch)
			}
			l, ok := exitLeg(s, "exit:internet")
			switch {
			case tc.internet == "" && ok:
				t.Errorf("internet leg present with gate %s", l.Approval)
			case tc.internet != "" && (!ok || l.Approval != tc.internet):
				t.Errorf("internet leg ok=%v gate=%s, want %s", ok, l.Approval, tc.internet)
			}
			_, web := exitLeg(s, "exit:web_tool")
			if web != (tc.webFetch != "denied") {
				t.Errorf("web_tool leg present=%v with webfetch=%s", web, tc.webFetch)
			}
		})
	}
}

func TestApprovalProjectRulesAndMCP(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "src", "app")
	f.write(filepath.Join(proj, ".claude", "settings.local.json"), `{"permissions":{"allow":["Bash(python3:*)","Bash(git add:*)"]}}`)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"default","allow":["mcp__db"]}}`)
	f.write(filepath.Join(f.home, ".claude.json"), `{"mcpServers":{"db":{"command":"db-mcp"},"web":{"type":"http","url":"https://mcp.invalid/x"}}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	l, ok := exitLeg(s, "exit:internet@"+proj)
	if !ok || l.Approval != ApprovalNone || l.ProjectDir != proj {
		t.Fatalf("project exit: ok=%v %+v", ok, l)
	}
	var carries int
	for _, r := range s.SandboxRules {
		if r.CarriesNetwork {
			carries++
		}
	}
	if carries != 1 {
		t.Errorf("carries_network rules: %d, want 1 (python3)", carries)
	}
	for _, m := range s.MCPServers {
		want := map[string]string{"db": ApprovalNone, "web": ApprovalPrompt}[m.Name]
		if m.ToolApproval != want {
			t.Errorf("%s tool_approval=%s want %s", m.Name, m.ToolApproval, want)
		}
	}
	if l, ok := exitLeg(s, "exit:mcp_remote@"); !ok || l.Approval != ApprovalPrompt {
		t.Errorf("mcp_remote leg ok=%v gate=%s", ok, l.Approval)
	}
	if l, ok := exitLeg(s, "exit:mcp_process"); !ok || l.Approval != ApprovalNone {
		t.Errorf("mcp_process leg ok=%v gate=%s", ok, l.Approval)
	}
}

func TestWriteLegGate(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "src", "app")
	f.write(filepath.Join(proj, "CLAUDE.md"), "x")
	for mode, want := range map[string]string{"default": ApprovalPrompt, "acceptEdits": ApprovalNone, "dontAsk": ""} {
		f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"`+mode+`"}}`)
		s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
		var got string
		found := false
		for _, w := range WriteLegs(s, AgentClaudeCode) {
			if w.Path == filepath.Join(proj, "CLAUDE.md") {
				got, found = w.Approval, true
			}
		}
		if (want == "") == found || got != want {
			t.Errorf("%s: found=%v gate=%s want %q", mode, found, got, want)
		}
	}
}

func TestDroppedInAutoMode(t *testing.T) {
	for pat, want := range map[string]bool{
		"Bash":                          true,
		"Bash(*)":                       true,
		"Bash(python3:*)":               true,
		"Bash(python*)":                 true,
		"Bash(node *)":                  true,
		"Bash(npm run *)":               true,
		"Bash(npm run:*)":               true,
		"Bash(npm run build:*)":         false,
		"Bash(npm test)":                false,
		"Bash(curl:*)":                  false,
		"Bash(python3 x.py)":            false,
		"Bash(npm run)":                 true,
		"Bash(npx:*)":                   true,
		"Bash(sudo *)":                  true,
		"Bash(env *)":                   true,
		"Bash(python -c *)":             true,
		"Bash(python -m pytest *)":      true,
		"Bash(python -m http.server *)": false,
		"Bash(bun:*)":                   false,
		"Bash(bun run *)":               true,
		"Bash(python3.11 *)":            false,
		"Bash(git push *)":              false,
		"Bash(  *  )":                   true,
	} {
		if got := droppedInAutoModeWith(builtinAutoDrop, pat); got != want {
			t.Errorf("%s: got %v want %v", pat, got, want)
		}
	}
	// In auto mode a dropped interpreter rule no longer opens the exit.
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"auto","allow":["Bash(python3:*)"]}}`)
	if a := f.agent(f.collectWith(Options{Probe: true})); a.NetworkApproval != ApprovalClassifier {
		t.Errorf("auto with python3:* network=%s, want classifier", a.NetworkApproval)
	}
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"default","allow":["Bash(python3:*)"]}}`)
	if a := f.agent(f.collectWith(Options{Probe: true})); a.NetworkApproval != ApprovalNone {
		t.Errorf("default with python3:* network=%s, want none", a.NetworkApproval)
	}
}

func TestProtectedFilesByName(t *testing.T) {
	for p, want := range map[string]bool{
		"/w/app/.mcp.json":                true,
		"/w/app/sub/.npmrc":               true,
		"/h/.zshrc":                       true,
		"/w/app/.claude/settings.json":    true,
		"/w/app/.github/workflows/ci.yml": false,
		"/w/app/CLAUDE.md":                false,
		"/w/app/package.json":             false,
	} {
		if got := permissionProtected(p, "/h", "/w/app"); got != want {
			t.Errorf("%s: got %v want %v", p, got, want)
		}
	}
}

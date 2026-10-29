package posture

// Collectors for OpenCode, Cline and Grok Build: discovery is automatic
// (nothing installed means no rows at all), gates follow each agent's
// documented permission model, and a gate the config cannot establish is
// unknown, never guessed.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func agentRow(s *Snapshot, id string) (Agent, bool) {
	for _, a := range s.Agents {
		if a.Agent == id {
			return a, true
		}
	}
	return Agent{}, false
}

func newAgentOpts(f fixture, agents ...string) Options {
	return Options{Home: f.home, Probe: true, PlistPath: "-", Agents: agents}
}

// An empty machine reports no rows at all for the new agents.
func TestNewAgentsAbsentWhenNotInstalled(t *testing.T) {
	f := newFixture(t)
	s := Collect(context.Background(), newAgentOpts(f, AgentOpenCode, AgentCline, AgentGrok))
	if len(s.Agents) != 0 {
		t.Fatalf("agents on an empty machine: %d", len(s.Agents))
	}
	absent := map[string]bool{AgentOpenCode: true, AgentCline: true, AgentGrok: true}
	for _, st := range s.Settings {
		if absent[st.Agent] {
			t.Errorf("settings row for absent agent %s", st.Agent)
		}
	}
	for _, m := range s.MCPServers {
		if absent[m.Agent] {
			t.Errorf("MCP row for absent agent %s", m.Agent)
		}
	}
	for _, i := range s.InstructionFiles {
		if absent[i.Agent] {
			t.Errorf("instruction file for absent agent %s", i.Agent)
		}
	}
	for _, r := range s.SandboxRules {
		if absent[r.Agent] {
			t.Errorf("rule for absent agent %s", r.Agent)
		}
	}
}

func TestOpenCodeGatesAndRows(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".config", "opencode", "opencode.json"), `{
		"permission": {
			"bash": {"*": "ask", "git *": "allow", "npm *": "deny"},
			"webfetch": "ask",
			"edit": "deny"
		},
		"mcp": {
			"fs":   {"command": "node", "args": ["fs.js"]},
			"docs": {"type": "remote", "url": "https://mcp.example.net/mcp", "enabled": false}
		}
	}`)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(proj, "opencode.json"), `{"permission": {"bash": "allow"}}`)
	f.write(filepath.Join(proj, "AGENTS.md"), "# Project\n")
	f.write(filepath.Join(proj, ".opencode", "agents", "review.md"), "---\ndescription: review\n---\nNo edits.\n")
	s := Collect(context.Background(), Options{Home: f.home, Probe: true, PlistPath: "-",
		Agents: []string{AgentOpenCode}, ProjectDirs: []string{proj}})
	a, ok := agentRow(s, AgentOpenCode)
	if !ok {
		t.Fatal("no opencode agent row")
	}
	// The project config overrides the global bash object ("later wins"),
	// so a shell command needs no prompt; webfetch still asks.
	if a.ShellApproval != ApprovalNone {
		t.Errorf("shell approval %q, want none (project bash allow wins)", a.ShellApproval)
	}
	if a.WebFetchApproval != ApprovalPrompt {
		t.Errorf("webfetch approval %q, want prompt", a.WebFetchApproval)
	}
	if a.NetworkApproval != ApprovalNone {
		t.Errorf("network approval %q, want none (follows bash)", a.NetworkApproval)
	}
	if a.SandboxEnabled || a.SandboxEnforced {
		t.Error("opencode has no OS sandbox")
	}
	if a.ModelBasis != ModelBasisOpenCode {
		t.Errorf("model basis %q", a.ModelBasis)
	}
	var gitAllow, npmDeny, editDeny bool
	for _, r := range s.SandboxRules {
		if r.Agent != AgentOpenCode {
			continue
		}
		switch {
		case r.Tool == "Bash" && r.Pattern == "git *" && r.RuleType == "allow":
			gitAllow = true
			if r.CarriesNetwork {
				t.Error("git * must not carry network")
			}
		case r.Tool == "Bash" && r.Pattern == "npm *" && r.RuleType == "deny":
			npmDeny = true
			if !r.CarriesNetwork {
				t.Error("npm * carries network")
			}
		case r.Tool == "Edit" && r.Pattern == "*" && r.RuleType == "deny":
			editDeny = true
		}
	}
	if !gitAllow || !npmDeny || !editDeny {
		t.Errorf("permission rules: git allow %v, npm deny %v, edit deny %v", gitAllow, npmDeny, editDeny)
	}
	var fsRow, docsRow MCPServer
	for _, m := range s.MCPServers {
		if m.Agent != AgentOpenCode {
			continue
		}
		switch m.Name {
		case "fs":
			fsRow = m
		case "docs":
			docsRow = m
		}
	}
	if fsRow.Name == "" || fsRow.Transport != "stdio" || fsRow.LauncherType != "node" {
		t.Errorf("fs MCP row: %+v", fsRow)
	}
	if docsRow.Name == "" || docsRow.Transport != "http" || docsRow.Enabled == nil || *docsRow.Enabled {
		t.Errorf("docs MCP row: %+v", docsRow)
	}
	var agentsMD, review bool
	for _, i := range s.InstructionFiles {
		if i.Agent != AgentOpenCode {
			continue
		}
		if i.Kind == "AGENTS.md" {
			agentsMD = true
		}
		if i.Kind == "subagent" && strings.HasSuffix(i.Path, "review.md") {
			review = true
		}
	}
	if !agentsMD || !review {
		t.Errorf("instruction files: AGENTS.md %v, markdown agent %v", agentsMD, review)
	}
}

func TestGrokGatesAndRows(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".grok", "config.toml"), `
[ui]
permission_mode = "auto"

[sandbox]
profile = "strict"

[permission]
rules = [
  { action = "allow", tool = "bash", pattern = "git *" },
  { action = "deny",  tool = "bash", pattern = "rm -rf *" },
]

[mcp_servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
`)
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(proj, ".grok", "config.toml"), `
[mcp_servers.proj]
command = "node"
args = ["p.js"]
`)
	f.write(filepath.Join(proj, "AGENTS.md"), "# Project\n")
	s := Collect(context.Background(), Options{Home: f.home, Probe: true, PlistPath: "-", GOOS: "darwin",
		Agents: []string{AgentGrok}, ProjectDirs: []string{proj}})
	a, ok := agentRow(s, AgentGrok)
	if !ok {
		t.Fatal("no grok agent row")
	}
	if a.EffectivePermissionMode != "auto" || a.PermissionModeSource != "user" {
		t.Errorf("mode %q from %q, want auto from user", a.EffectivePermissionMode, a.PermissionModeSource)
	}
	if a.ShellApproval != ApprovalClassifier || a.NetworkApproval != ApprovalClassifier {
		t.Errorf("approvals shell=%q network=%q, want classifier", a.ShellApproval, a.NetworkApproval)
	}
	if !a.SandboxEnabled || !a.SandboxEnforced {
		t.Error("strict profile must be an enforced sandbox")
	}
	if !strings.Contains(a.SandboxBypasses, "Linux only") {
		t.Errorf("sandbox bypasses %q must name the Linux-only network note", a.SandboxBypasses)
	}
	if a.ModelBasis != ModelBasisGrok || a.ModelBasisStale != nil {
		t.Errorf("grok model basis %q stale %v, want empty and unknown", a.ModelBasis, a.ModelBasisStale)
	}
	var allow, deny, fsRow, projRow bool
	for _, r := range s.SandboxRules {
		if r.Agent != AgentGrok {
			continue
		}
		if r.Tool == "bash" && r.Pattern == "git *" && r.RuleType == "allow" && r.Scope == "user" {
			allow = true
		}
		if r.Tool == "bash" && r.Pattern == "rm -rf *" && r.RuleType == "deny" {
			deny = true
		}
	}
	for _, m := range s.MCPServers {
		if m.Agent != AgentGrok {
			continue
		}
		if m.Name == "filesystem" && m.LauncherType == "npx" {
			fsRow = true
		}
		if m.Name == "proj" && m.Scope == "project" {
			projRow = true
		}
	}
	if !allow || !deny || !fsRow || !projRow {
		t.Errorf("rules/mcp: allow %v deny %v fs %v proj %v", allow, deny, fsRow, projRow)
	}
	var agentsMD bool
	for _, i := range s.InstructionFiles {
		if i.Agent == AgentGrok && i.Kind == "AGENTS.md" {
			agentsMD = true
		}
	}
	if !agentsMD {
		t.Error("grok reads AGENTS.md; no instruction row")
	}
}

// OpenCode 2's permissions array: last matching rule wins, and the base
// policy allows everything when no rule matches.
func TestOpenCodeV2Permissions(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".config", "opencode", "opencode.json"), `{
		"permissions": [
			{"action": "shell", "resource": "*", "effect": "ask"},
			{"action": "shell", "resource": "git status *", "effect": "allow"},
			{"action": "webfetch", "resource": "*", "effect": "deny"}
		]
	}`)
	s := Collect(context.Background(), newAgentOpts(f, AgentOpenCode))
	a, ok := agentRow(s, AgentOpenCode)
	if !ok {
		t.Fatal("no opencode agent row")
	}
	if a.ShellApproval != ApprovalPrompt {
		t.Errorf("shell approval %q, want prompt (catch-all ask is last)", a.ShellApproval)
	}
	if a.WebFetchApproval != ApprovalDenied {
		t.Errorf("webfetch approval %q, want denied", a.WebFetchApproval)
	}
	var catchAllAsk, gitAllow bool
	for _, r := range s.SandboxRules {
		if r.Agent != AgentOpenCode {
			continue
		}
		if r.Tool == "Bash" && r.Pattern == "*" && r.RuleType == "ask" {
			catchAllAsk = true
		}
		if r.Tool == "Bash" && r.Pattern == "git status *" && r.RuleType == "allow" {
			gitAllow = true
		}
	}
	if !catchAllAsk || !gitAllow {
		t.Errorf("v2 rules: catch-all ask %v, git allow %v", catchAllAsk, gitAllow)
	}
}

// With no rules at all, the v2 base policy allows everything.
func TestOpenCodeV2BasePolicyAllows(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".config", "opencode", "opencode.json"), `{"permissions": []}`)
	s := Collect(context.Background(), newAgentOpts(f, AgentOpenCode))
	a, _ := agentRow(s, AgentOpenCode)
	if a.ShellApproval != ApprovalNone || a.WebFetchApproval != ApprovalNone {
		t.Errorf("empty v2 rules: shell %q webfetch %q, want none/none (base policy allows)", a.ShellApproval, a.WebFetchApproval)
	}
}

// Grok's always-approve mode maps to no approval at all.
func TestGrokAlwaysApprove(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".grok", "config.toml"), `
[ui]
permission_mode = "always-approve"
`)
	s := Collect(context.Background(), newAgentOpts(f, AgentGrok))
	a, _ := agentRow(s, AgentGrok)
	if a.EffectivePermissionMode != "bypassPermissions" || a.ShellApproval != ApprovalNone {
		t.Errorf("mode %q shell %q, want bypassPermissions/none", a.EffectivePermissionMode, a.ShellApproval)
	}
}

func TestClineInventoryAndUnknownGates(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".cline", "data", "settings", "cline_mcp_settings.json"),
		`{"mcpServers": {"db": {"command": "node", "args": ["db.js"]}}}`)
	token := "s" + "k-" + strings.Repeat("x", 24) // built at runtime; never a literal
	f.write(filepath.Join(f.home, ".cline", "data", "settings", "global-settings.json"),
		`{"telemetry": true, "apiToken": "`+token+`"}`)
	f.write(filepath.Join(f.home, ".cline", "rules", "global.md"), "Be careful.\n")
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(proj, ".clinerules", "notes.md"), "Use tabs.\n")
	proj2 := filepath.Join(f.home, "proj2")
	f.write(filepath.Join(proj2, ".clinerules"), "Legacy rules file.\n")
	f.write(filepath.Join(proj, "AGENTS.md"), "# Project\n")
	s := Collect(context.Background(), Options{Home: f.home, Probe: true, PlistPath: "-",
		Agents: []string{AgentCline}, ProjectDirs: []string{proj, proj2}})
	a, ok := agentRow(s, AgentCline)
	if !ok {
		t.Fatal("no cline agent row")
	}
	if a.ShellApproval != ApprovalUnknown || a.EffectivePermissionMode != "unknown" {
		t.Errorf("cline gates must be unknown, got shell=%q mode=%q", a.ShellApproval, a.EffectivePermissionMode)
	}
	if a.SandboxEnabled {
		t.Error("cline has no sandbox")
	}
	var telemetry, secretRow, dbRow, globalRule, projRule, legacyRule, agentsMD bool
	for _, st := range s.Settings {
		if st.Agent != AgentCline {
			continue
		}
		if st.Key == "telemetry" {
			telemetry = true
		}
		if strings.Contains(st.Key, "apiToken") || strings.Contains(st.Key, "Token") {
			secretRow = true
		}
	}
	for _, m := range s.MCPServers {
		if m.Agent == AgentCline && m.Name == "db" {
			dbRow = true
		}
	}
	for _, i := range s.InstructionFiles {
		if i.Agent != AgentCline {
			continue
		}
		switch {
		case i.Kind == "rules" && strings.HasSuffix(i.Path, "global.md"):
			globalRule = true
		case i.Kind == "rules" && strings.HasSuffix(i.Path, "notes.md"):
			projRule = true
		case i.Kind == "rules" && strings.HasSuffix(i.Path, ".clinerules"):
			legacyRule = true
		case i.Kind == "AGENTS.md":
			agentsMD = true
		}
	}
	if !telemetry || secretRow || !dbRow || !globalRule || !projRule || !legacyRule || !agentsMD {
		t.Errorf("cline rows: telemetry %v secretRow %v db %v global %v proj %v legacy %v agents %v",
			telemetry, secretRow, dbRow, globalRule, projRule, legacyRule, agentsMD)
	}
}

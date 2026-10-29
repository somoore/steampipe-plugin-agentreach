package posture

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexAbsentYieldsNothing(t *testing.T) {
	f := newFixture(t)
	snap := f.collect()
	for _, a := range snap.Agents {
		if a.Agent == AgentCodex {
			t.Fatal("codex row emitted for a home without ~/.codex")
		}
	}
}

func TestCodexCollector(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "repo")
	other := filepath.Join(f.home, "untrusted")
	key := fake("s"+"k-", 10)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `sandbox_mode = "danger-full-access"
approval_policy = "never"
[sandbox_workspace_write]
network_access = true
[features]
hooks = false
[projects."`+proj+`"]
trust_level = "trusted"
[projects."`+other+`"]
trust_level = "untrusted"
[mcp_servers.docs]
command = "npx"
args = ["-y", "@acme/docs-mcp"]
[mcp_servers.docs.env]
OPENAI_API_KEY = "`+key+`"
[mcp_servers.ref]
command = "npx"
args = ["-y", "@acme/ref@1.2.3"]
[mcp_servers.ref.env]
REF_API_KEY = "${REF_API_KEY}"
`)
	f.write(filepath.Join(f.home, ".codex", "AGENTS.md"), "# global codex rules\n")
	f.write(filepath.Join(proj, "AGENTS.md"), "# project rules\n")
	f.write(filepath.Join(other, "AGENTS.md"), "# skipped: untrusted\n")
	snap := f.collect()

	var a *Agent
	for i := range snap.Agents {
		if snap.Agents[i].Agent == AgentCodex {
			a = &snap.Agents[i]
		}
	}
	if a == nil {
		t.Fatal("no codex agent row")
	}
	if a.SandboxEnabled || !a.HooksDisabled || a.ProjectsKnown != 2 || a.ProjectsTrusted != 1 {
		t.Errorf("agent: sandbox=%v hooksDisabled=%v known=%d trusted=%d", a.SandboxEnabled, a.HooksDisabled, a.ProjectsKnown, a.ProjectsTrusted)
	}
	// Explicit danger-full-access + never: no sandbox, no prompt.
	if a.EffectivePermissionMode != "danger-full-access/never" || a.ShellApproval != ApprovalNone || a.NetworkApproval != ApprovalNone || !a.AssessmentComplete {
		t.Errorf("codex gates: mode=%s shell=%s net=%s complete=%v", a.EffectivePermissionMode, a.ShellApproval, a.NetworkApproval, a.AssessmentComplete)
	}

	settings := map[string]any{}
	for _, s := range snap.Settings {
		if s.Agent == AgentCodex {
			settings[s.Key] = s.Value
		}
	}
	if settings["sandbox_mode"] != "danger-full-access" || settings["approval_policy"] != "never" || settings["sandbox_workspace_write.network_access"] != true {
		t.Errorf("codex settings: %v", settings)
	}

	mcp := map[string]MCPServer{}
	for _, m := range snap.MCPServers {
		if m.Agent == AgentCodex {
			mcp[m.Name] = m
		}
	}
	if !mcp["docs"].HasInlineSecret || mcp["ref"].HasInlineSecret {
		t.Errorf("inline secret: docs=%v ref=%v", mcp["docs"].HasInlineSecret, mcp["ref"].HasInlineSecret)
	}
	if mcp["docs"].ToolApproval != ApprovalUnknown || mcp["ref"].Pinned == nil || !*mcp["ref"].Pinned {
		t.Errorf("docs approval=%s ref pinned=%s", mcp["docs"].ToolApproval, b2s(mcp["ref"].Pinned))
	}

	got := map[string]bool{}
	for _, i := range snap.InstructionFiles {
		if i.Agent == AgentCodex {
			got[i.Scope+":"+i.Path] = true
		}
	}
	if !got["user:"+filepath.Join(f.home, ".codex", "AGENTS.md")] || !got["project:"+filepath.Join(proj, "AGENTS.md")] || got["project:"+filepath.Join(other, "AGENTS.md")] {
		t.Errorf("codex instruction files: %v", got)
	}

}

func TestCodexMalformedConfigIsAnError(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = [unclosed\n")
	snap := f.collect()
	for _, a := range snap.Agents {
		if a.Agent == AgentClaudeCode && len(a.CollectErrors) != 0 {
			t.Errorf("codex error leaked into the claude_code row: %v", a.CollectErrors)
		}
		if a.Agent == AgentCodex && len(a.CollectErrors) == 0 {
			t.Error("codex parse failure not recorded")
		}
	}
}

func codexAgent(t *testing.T, snap *Snapshot) Agent {
	t.Helper()
	for _, a := range snap.Agents {
		if a.Agent == AgentCodex {
			return a
		}
	}
	t.Fatal("no codex agent row")
	return Agent{}
}

func codexProjects(snap *Snapshot) map[string]Project {
	out := map[string]Project{}
	for _, p := range snap.Projects {
		if p.Agent == AgentCodex {
			out[p.ProjectDir] = p
		}
	}
	return out
}

// Defaults: a folder with no trust decision is read-only/on-request, so a
// shell command runs and reads in the sandbox with no prompt, and reaching
// the internet needs an escalation you approve. A trusted project's own
// config (network_access) opens the network there; an untrusted project
// prompts for every command.
func TestCodexDefaultGates(t *testing.T) {
	f := newFixture(t)
	trusted := filepath.Join(f.home, "trusted")
	untrusted := filepath.Join(f.home, "untrusted")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), `[projects."`+trusted+`"]
trust_level = "trusted"
[projects."`+untrusted+`"]
trust_level = "untrusted"
`)
	f.write(filepath.Join(trusted, ".codex", "config.toml"), "[sandbox_workspace_write]\nnetwork_access = true\n[mcp_servers.local]\ncommand = \"./server\"\n")
	f.write(filepath.Join(untrusted, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n") // ignored: not trusted
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "not a key")
	snap := f.collect()

	a := codexAgent(t, snap)
	if a.EffectivePermissionMode != "read-only/on-request" || a.PermissionModeSource != "built_in" || a.ShellApproval != ApprovalNone ||
		a.NetworkApproval != ApprovalPrompt || a.WebFetchApproval != ApprovalNone || a.SandboxEnforced || a.SandboxBypasses != "escalation_request" || !a.AssessmentComplete {
		t.Errorf("machine gate: %+v", a)
	}
	ps := codexProjects(snap)
	if p := ps[trusted]; p.EffectivePermissionMode != "workspace-write/on-request" || p.NetworkApproval != ApprovalNone || p.ShellApproval != ApprovalNone || p.ReadApproval != ApprovalNone {
		t.Errorf("trusted project: %+v", p)
	}
	if p := ps[untrusted]; p.EffectivePermissionMode != "workspace-write/untrusted" || p.NetworkApproval != ApprovalPrompt || p.ShellApproval != ApprovalPrompt || p.ReadApproval != ApprovalPrompt {
		t.Errorf("untrusted project: %+v", p)
	}

	var ssh *ReachFile
	for i := range snap.ReachFiles {
		if r := &snap.ReachFiles[i]; r.Agent == AgentCodex && r.Category == "ssh" {
			ssh = r
		}
	}
	if ssh == nil || ssh.ReachableViaBash == nil || !*ssh.ReachableViaBash || ssh.ReadApproval != ApprovalNone {
		t.Fatalf("codex ssh reach: %+v", ssh)
	}
	var inet *ReachHost
	for i := range snap.ReachHosts {
		if h := &snap.ReachHosts[i]; h.Agent == AgentCodex && h.Kind == "internet" {
			inet = h
		}
	}
	if inet == nil || inet.Approval != ApprovalPrompt {
		t.Fatalf("codex internet row: %+v", inet)
	}

	var srv *MCPServer
	for i := range snap.MCPServers {
		if m := &snap.MCPServers[i]; m.Agent == AgentCodex && m.Name == "local" {
			srv = m
		}
	}
	if srv == nil || srv.Scope != "project" || srv.ProjectDir != trusted || srv.Enabled == nil || !*srv.Enabled {
		t.Fatalf("trusted project MCP server: %+v", srv)
	}

	// Paths: web search results -> ~/.ssh -> the internet. Machine-wide the
	// exit waits for your approval; in the trusted project it does not.
	got := map[string]string{}
	for _, p := range snap.Paths {
		if p.Agent == AgentCodex && p.Kind == "confidentiality" && p.SourceID == "src:web" && p.TargetCategory == "ssh" {
			got[p.ExitID] = p.Approval
		}
	}
	if got["exit:internet"] != ApprovalPrompt || got["exit:internet@"+trusted] != ApprovalNone {
		t.Errorf("codex paths by exit: %v", got)
	}
}

func TestCodexNeverAndRules(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = \"workspace-write\"\napproval_policy = \"never\"\nweb_search = \"disabled\"\n")
	a := codexAgent(t, f.collect())
	if a.NetworkApproval != ApprovalDenied || !a.SandboxEnforced || a.WebFetchApproval != ApprovalDenied {
		t.Errorf("never: %+v", a)
	}
	f.write(filepath.Join(f.home, ".codex", "rules", "default.rules"), `prefix_rule(
    pattern = ["git", "status"],
)
prefix_rule(pattern = [["curl", "wget"], "https://example.org"], decision = "allow")
prefix_rule(pattern = ["python3"], decision = "prompt")
`)
	a = codexAgent(t, f.collect())
	if a.NetworkApproval != ApprovalNone || a.SandboxEnforced || a.SandboxBypasses != "exec_policy_allow" {
		t.Errorf("allow rule: net=%s enforced=%v bypasses=%s reason=%s", a.NetworkApproval, a.SandboxEnforced, a.SandboxBypasses, a.NetworkApprovalReason)
	}
}

func TestCodexAllowRuleParsing(t *testing.T) {
	dir := t.TempDir()
	f := fixture{t: t, home: dir}
	f.write(filepath.Join(dir, "a.rules"), `# comment
prefix_rule(pattern = ["git", "push"], justification = "ok")
prefix_rule(pattern = [["npm", "pnpm"], "install"], decision = "allow")
prefix_rule(pattern = ["rm"], decision = "forbidden")
`)
	got := codexAllowRules(dir)
	want := []string{"git push", "npm install", "pnpm install"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("rules: %q", got)
	}
	for r, net := range map[string]bool{"git push": true, "git status": false, "curl x": true, "/usr/bin/wget": true, "ls": false} {
		if codexRuleCarriesNetwork(r) != net {
			t.Errorf("%q network=%v", r, !net)
		}
	}
}

// What agentreach cannot decide stays unknown, with the reason.
func TestCodexUnknownGates(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "default_permissions = \":workspace\"\n")
	a := codexAgent(t, f.collect())
	if a.EffectivePermissionMode != "unknown" || a.NetworkApproval != ApprovalUnknown || a.AssessmentComplete || !strings.Contains(a.NetworkApprovalReason, "permission profile") {
		t.Errorf("profiles: %+v", a)
	}

	sys := filepath.Join(f.home, "etc-codex")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	f.write(filepath.Join(sys, "requirements.toml"), "allowed_sandbox_modes = [\"read-only\", \"workspace-write\"]\n")
	snap := Collect(context.Background(), Options{Home: f.home, Probe: true, ManagedDir: f.managed, PlistPath: "-", CodexSystemDir: sys})
	a = codexAgent(t, snap)
	if a.NetworkApproval != ApprovalUnknown || !strings.Contains(a.NetworkApprovalReason, "requirements.toml") || a.ManagedSettingsPath == "" {
		t.Errorf("requirements: %+v", a)
	}

	f.write(filepath.Join(sys, "requirements.toml"), "[permissions.filesystem]\ndeny_read = [\"~/.ssh\"]\n")
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "not a key")
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "")
	snap = Collect(context.Background(), Options{Home: f.home, Probe: true, ManagedDir: f.managed, PlistPath: "-", CodexSystemDir: sys})
	a = codexAgent(t, snap)
	if a.AssessmentComplete || a.NetworkApproval != ApprovalPrompt {
		t.Errorf("deny_read: complete=%v net=%s", a.AssessmentComplete, a.NetworkApproval)
	}
	for _, r := range snap.ReachFiles {
		if r.Agent == AgentCodex && (r.ReachableViaBash != nil || r.ReadApproval != ApprovalUnknown) {
			t.Errorf("deny_read must leave reads unknown: %+v", r)
		}
	}
	for _, p := range snap.Paths {
		if p.Agent == AgentCodex && p.Kind == "confidentiality" {
			t.Errorf("no private leg when reads are unknown: %+v", p)
		}
	}
}

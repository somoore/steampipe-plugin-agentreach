package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ciRows writes one workflow (and an optional .claude/settings.json) into a
// fresh repository root and parses it.
func ciRows(t *testing.T, workflow, projectSettings string) []CIWorkflow {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, ".github", "workflows", "w.yml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	if projectSettings != "" {
		if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(projectSettings), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return parseWorkflow(root, p)
}

// The pull_request_target pattern the action's security guide warns about:
// the head is checked out at the workspace root before the agent runs, and
// bots and bypassPermissions are allowed.
func TestCIRiskyClaudeAction(t *testing.T) {
	rows := ciRows(t, `name: claude
on:
  pull_request_target:
  issue_comment:
    types: [created]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          allowed_bots: "*"
          claude_args: --dangerously-skip-permissions --max-turns 5
`, "")
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	r := rows[0]
	want := CIWorkflow{Agent: AgentClaudeCode, Launcher: ciClaudeAction, ActionRef: "v1", Mode: "interactive", Job: "review",
		UntrustedTrigger: true, OutsiderTrigger: true, BaseSecretsTrigger: true, ChecksOutHead: true,
		ActorCheck: "write_access", AllowedBots: "all", PermissionMode: "bypassPermissions", PermissionModeSource: "flag",
		SkipPermissions: true, UnrestrictedShell: true, Sandbox: "off", GitHubToken: "app"}
	r.ProjectDir, r.Path, r.Line, r.Triggers, r.Secrets, r.WriteScopes = "", "", 0, nil, nil, nil
	if !equalJSON(r, want) {
		t.Errorf("got  %+v\nwant %+v", r, want)
	}
	if !slices.Equal(rows[0].Triggers, []string{"issue_comment", "pull_request_target"}) || !slices.Equal(rows[0].Secrets, []string{"ANTHROPIC_API_KEY"}) {
		t.Errorf("triggers %v secrets %v", rows[0].Triggers, rows[0].Secrets)
	}
	if rows[0].Line != 13 || rows[0].PermissionsDeclared || rows[0].Pinned {
		t.Errorf("line %d declared %v pinned %v", rows[0].Line, rows[0].PermissionsDeclared, rows[0].Pinned)
	}
}

// The documented @claude workflow, pinned and scoped: nothing to flag.
func TestCIScopedClaudeAction(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	rows := ciRows(t, `on:
  issue_comment:
    types: [created]
permissions:
  contents: read
  issues: write
  id-token: write
jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    permissions: {contents: write, pull-requests: write, issues: read}
    steps:
      - uses: actions/checkout@v6
        with:
          path: pr-head
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@`+sha+`
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          include_comments_by_actor: "somoore"
          claude_args: '--allowedTools "Bash(npm test)" --add-dir pr-head'
`, `{"permissions":{"allow":["Read"]}}`)
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	r := rows[0]
	if !r.Pinned || r.ChecksOutHead || r.UnrestrictedShell || r.SkipPermissions || r.AllowRules != 2 ||
		r.PermissionMode != "default" || r.PermissionModeSource != "built_in" || r.GitHubToken != "workflow" || !r.CommentFilter || r.AllowedBots != "none" {
		t.Errorf("%+v", r)
	}
	// Job permissions replace the workflow's.
	if !r.PermissionsDeclared || !slices.Equal(r.WriteScopes, []string{"contents", "pull-requests"}) {
		t.Errorf("declared %v scopes %v", r.PermissionsDeclared, r.WriteScopes)
	}
}

// Run steps check no actor; the mode comes from the repository's settings
// unless a flag sets it, and a blanket Bash rule opens the shell.
func TestCIRunSteps(t *testing.T) {
	rows := ciRows(t, `on: [issues, push]
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout 1
      - run: |
          claude --version
          npx -y @anthropic-ai/claude-code@2.1.312 -p "Label ${{ github.event.issue.title }}" \
            --allowedTools Bash
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - run: claude --print --permission-mode ${{ inputs.mode }} "x" && codex exec --sandbox danger-full-access "fix it"
      - run: codex exec "summarise"
      - run: claude mcp list
`, `{"permissions":{"defaultMode":"acceptEdits"}}`)
	if len(rows) != 4 {
		t.Fatalf("want 4 rows, got %d: %+v", len(rows), rows)
	}
	npx, expr, codexDanger, codexDefault := rows[0], rows[1], rows[2], rows[3]
	if npx.Agent != AgentClaudeCode || npx.Launcher != ciRun || npx.ActorCheck != "none" || !npx.UnrestrictedShell ||
		npx.PermissionMode != "acceptEdits" || npx.PermissionModeSource != "project_settings" || !npx.ChecksOutHead || !npx.OutsiderTrigger {
		t.Errorf("npx: %+v", npx)
	}
	if !slices.Equal(npx.WriteScopes, []string{"write-all"}) || !slices.Equal(npx.Secrets, []string{"ANTHROPIC_API_KEY"}) {
		t.Errorf("npx scopes %v secrets %v", npx.WriteScopes, npx.Secrets)
	}
	// An expression is not a mode agentreach can read: the settings decide.
	if expr.PermissionModeSource != "project_settings" || expr.UnrestrictedShell {
		t.Errorf("expr: %+v", expr)
	}
	if codexDanger.Agent != AgentCodex || codexDanger.Sandbox != "danger-full-access" || !codexDanger.UnrestrictedShell {
		t.Errorf("codex danger: %+v", codexDanger)
	}
	if codexDefault.Sandbox != "read-only" || codexDefault.UnrestrictedShell {
		t.Errorf("codex default: %+v", codexDefault)
	}
}

func TestCICodexAction(t *testing.T) {
	rows := ciRows(t, `on:
  issues:
    types: [opened]
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          allow-users: "*"
          safety-strategy: unsafe
          codex-args: '["--sandbox", "danger-full-access"]'
      - uses: openai/codex-action@v1
        with:
          permission-profile: ":workspace"
      - uses: OpenAI/codex-action@v1
`, "")
	if len(rows) != 3 {
		t.Fatalf("rows: %+v", rows)
	}
	if r := rows[0]; r.ActorCheck != "relaxed" || r.SafetyStrategy != "unsafe" || r.Sandbox != "danger-full-access" || !r.UnrestrictedShell || r.PermissionModeSource != "flag" {
		t.Errorf("unsafe: %+v", r)
	}
	if r := rows[1]; r.Sandbox != "profile" || r.PermissionMode != ":workspace" || r.SafetyStrategy != "drop-sudo" {
		t.Errorf("profile: %+v", r)
	}
	if r := rows[2]; r.Sandbox != "workspace-write" || r.PermissionModeSource != "built_in" || r.ActorCheck != "write_access" {
		t.Errorf("default: %+v", r)
	}
}

// The base action does no actor check; a settings input file in the
// repository is read, one outside it is not.
func TestCIBaseActionSettings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ci-settings.json"), []byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	wf := `on: workflow_dispatch
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action/base-action@v1
        with:
          prompt: "x"
          settings: ci-settings.json
      - uses: anthropics/claude-code-base-action@v1
        with:
          prompt: "x"
          settings: ../outside.json
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "x"
          settings: '{"sandbox":{"enabled":true},"permissions":{"allow":["Bash(*)"]}}'
`
	p := filepath.Join(root, ".github", "workflows", "w.yml")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(wf), 0o644)
	rows := parseWorkflow(root, p)
	if len(rows) != 3 {
		t.Fatalf("rows: %+v", rows)
	}
	if r := rows[0]; r.Launcher != ciClaudeBase || r.ActorCheck != "none" || r.PermissionMode != "bypassPermissions" || r.PermissionModeSource != "settings_input" || r.Mode != "automation" {
		t.Errorf("base: %+v", r)
	}
	if r := rows[1]; r.PermissionModeSource != "built_in" || r.UntrustedTrigger {
		t.Errorf("outside: %+v", r)
	}
	if r := rows[2]; r.Sandbox != "enabled" || !r.UnrestrictedShell || r.Mode != "automation" || r.ActorCheck != "write_access" {
		t.Errorf("inline settings: %+v", r)
	}
}

// Prompts, scripts and rule text never reach a row, and a file that does
// not parse, a reusable workflow call or an unknown job id yields nothing
// to quote.
func TestCIKeepsNoText(t *testing.T) {
	marker := "NEVER-STORE-" + strings.Repeat("q", 4)
	rows := ciRows(t, `on: {issue_comment: {types: [created]}, "bad event!": {}}
jobs:
  "job with spaces":
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@`+marker+`!
        with:
          prompt: "`+marker+`"
          claude_args: --allowedTools "Bash(`+marker+` *)"
      - run: claude -p "`+marker+`"
  reuse:
    uses: ./.github/workflows/other.yml
`, "")
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", rows)
	}
	b, _ := json.Marshal(rows)
	if strings.Contains(string(b), marker) || strings.Contains(string(b), "bad event") || strings.Contains(string(b), "spaces") {
		t.Errorf("text leaked: %s", b)
	}
	if rows[0].ActionRef != "" || rows[0].Job != "" || rows[0].AllowRules != 1 {
		t.Errorf("%+v", rows[0])
	}
	if got := ciRows(t, "on: [push\njobs: {", ""); got != nil {
		t.Errorf("unparsable file gave %+v", got)
	}
}

// Collect finds workflows in known projects' repositories only.
func TestCIWorkflowsCollected(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	other := filepath.Join(f.home, "unknown")
	wf := "on: issue_comment\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"
	f.write(filepath.Join(proj, ".github", "workflows", "a.yml"), wf)
	f.write(filepath.Join(other, ".github", "workflows", "a.yml"), wf)
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+proj+`":{"hasTrustDialogAccepted":true}}}`)
	s := f.collectWith(Options{Probe: true})
	if len(s.CIWorkflows) != 1 || s.CIWorkflows[0].ProjectDir != proj {
		t.Fatalf("rows: %+v", s.CIWorkflows)
	}
	if s := f.collectWith(Options{Probe: true, Agents: []string{AgentCodex}}); len(s.CIWorkflows) != 0 {
		t.Errorf("agent filter: %+v", s.CIWorkflows)
	}
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

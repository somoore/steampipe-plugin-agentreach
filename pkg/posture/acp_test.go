package posture

// ACP harness discovery: editor agent_servers that can start an agent are
// recorded on its row; an unidentifiable wrapper attaches to nothing.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestACPHarnessDiscovered(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "")
	f.write(filepath.Join(f.home, ".config", "zed", "settings.json"), `{
		"agent_servers": {
			"Claude Agent": {"command": "claude-code-acp"},
			"codex": {"command": "npx", "args": ["@zed-industries/codex-acp"]},
			"custom": {"command": "node", "args": ["~/agent/index.js", "--acp"]}
		}
	}`)
	s := Collect(context.Background(), newAgentOpts(f, AgentClaudeCode, AgentCodex, AgentOpenCode))
	claude, ok := agentRow(s, AgentClaudeCode)
	if !ok {
		t.Fatal("no claude_code row")
	}
	if !strings.Contains(claude.ACPHarness, `"Claude Agent"`) || !strings.Contains(claude.ACPHarness, "claude-code-acp") {
		t.Errorf("claude acp_harness %q", claude.ACPHarness)
	}
	codex, ok := agentRow(s, AgentCodex)
	if !ok {
		t.Fatal("no codex row")
	}
	if !strings.Contains(codex.ACPHarness, "codex-acp") {
		t.Errorf("codex acp_harness %q", codex.ACPHarness)
	}
	opencode, _ := agentRow(s, AgentOpenCode)
	if opencode.ACPHarness != "" {
		t.Errorf("opencode must not match a claude/codex server: %q", opencode.ACPHarness)
	}
}

// No Zed settings, no harness fact.
func TestACPHarnessAbsent(t *testing.T) {
	f := newFixture(t)
	s := Collect(context.Background(), newAgentOpts(f, AgentClaudeCode))
	a, _ := agentRow(s, AgentClaudeCode)
	if a.ACPHarness != "" {
		t.Errorf("acp_harness %q, want empty", a.ACPHarness)
	}
}

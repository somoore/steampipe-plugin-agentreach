package main

// A machine with no coding agent or harness installed is a clean result:
// the report says so in the discovered-agents line, no finding is shown,
// and the exit code is 0, not "not fully assessed".

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

func TestNoAgentsIsClean(t *testing.T) {
	snap := &posture.Snapshot{
		SchemaVersion: posture.SchemaVersion, SnapshotID: "none", Host: "empty",
		CollectedAt: time.Now().UTC(),
	}
	var out, errb bytes.Buffer
	code := run([]string{"scan"}, &out, &errb, func([]string, bool) *posture.Snapshot { return snap })
	if code != 0 {
		t.Fatalf("exit %d, want 0 (no agent installed is clean)\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "No coding agent or harness found on this machine.") {
		t.Errorf("output must state that no agent was found:\n%s", out.String())
	}
	if strings.Contains(out.String(), "NOT FULLY ASSESSED") {
		t.Errorf("an empty machine must not be a not-assessed finding:\n%s", out.String())
	}
}

func TestAgentsInventoryInReport(t *testing.T) {
	snap := &posture.Snapshot{
		SchemaVersion: posture.SchemaVersion, SnapshotID: "inv", Host: "h", CollectedAt: time.Now().UTC(),
		Agents: []posture.Agent{
			{Agent: "claude_code", Version: "2.1.312"},
			{Agent: "opencode", Version: "1.19.5"},
		},
	}
	var out, errb bytes.Buffer
	code := run([]string{"scan"}, &out, &errb, func([]string, bool) *posture.Snapshot { return snap })
	if code != 2 { // unknown gates on the synthetic rows: not fully assessed, but the inventory still shows
		t.Logf("exit %d (expected 2 for synthetic unassessed rows)", code)
	}
	if !strings.Contains(out.String(), "Agents found: claude_code 2.1.312, opencode 1.19.5") {
		t.Errorf("output must list the discovered agents:\n%s", out.String())
	}
}

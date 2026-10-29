package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

// fixture builds a small hand-made snapshot; nothing reads the real home.
func fixture(approval string, probed bool, inlineSecret bool) *posture.Snapshot {
	return &posture.Snapshot{
		SchemaVersion: posture.SchemaVersion, CollectorVersion: "test", SnapshotID: "abc123", Host: "fx-cli",
		CollectedAt: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC),
		Probed:      probed,
		Agents:      []posture.Agent{{Agent: "claude_code", Probed: probed, EffectivePermissionMode: "default"}},
		Paths: []posture.Path{
			{PathID: "p1", Agent: "claude_code", Kind: "confidentiality", Status: "candidate", Approval: approval,
				SourceTitle: "/Users/alice/proj/CLAUDE.md", SourceKind: "instruction_file",
				TargetPath: "/Users/alice/.ssh/id_ed25519", TargetTitle: "~/.ssh/id_ed25519", TargetTier: 1,
				Via: "shell", ExitTitle: "the internet", ProjectDir: "/Users/alice/proj"},
			{PathID: "p2", Agent: "claude_code", Kind: "integrity", Status: "candidate", Approval: "prompt",
				SourceTitle: "web pages", SourceKind: "web_tool", TargetPath: "/Users/alice/proj/.github/workflows/ci.yml",
				TargetTitle: "CI workflow", Via: "edit_tool"},
			{PathID: "p3", Agent: "claude_code", Kind: "confidentiality", Status: "rejected", Approval: "none"},
		},
		MCPServers: []posture.MCPServer{{Agent: "claude_code", Scope: "user", Name: "meshy", SourcePath: "/Users/alice/.claude.json",
			EnvKeys: []string{"MESHY_API_KEY"}, HasInlineSecret: inlineSecret}},
	}
}

func scan(t *testing.T, snap *posture.Snapshot, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"scan"}, args...), &out, &errb, func([]string, bool) *posture.Snapshot { return snap })
	return code, out.String() + errb.String()
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		snap *posture.Snapshot
		args []string
		want int
	}{
		{"open path fails", fixture("none", true, false), nil, 1},
		{"classifier passes at fail-on none", fixture("classifier", true, false), []string{"--fail-on", "none"}, 0},
		{"classifier fails by default without an enforced sandbox", fixture("classifier", true, false), nil, 1},
		{"classifier passes by default with an enforced sandbox", enforced(fixture("classifier", true, false)), nil, 0},
		{"no agents is a clean result", noAgents(), nil, 0},
		{"sandboxed scan is not assessed", skipped(fixture("prompt", false, false)), nil, 2},
		{"sdk session is not assessed", surface(fixture("prompt", true, false), posture.SurfacePrintSDK, "CLAUDE_CODE_ENTRYPOINT=sdk-ts"), nil, 2},
		{"assumed terminal is assessed", surface(fixture("prompt", true, false), posture.SurfaceTerminal, "assumed"), nil, 0},
		{"attested path still fails", attested(fixture("none", true, false)), nil, 1},
		{"attested path accepted", attested(fixture("none", true, false)), []string{"--accept-attested"}, 0},
		{"classifier fails at fail-on classifier", fixture("classifier", true, false), []string{"--fail-on", "classifier"}, 1},
		{"prompt fails at fail-on prompt", fixture("prompt", true, false), []string{"--fail-on", "prompt"}, 1},
		{"never", fixture("none", true, true), []string{"--fail-on", "never"}, 0},
		{"inline secret fails", fixture("prompt", true, true), nil, 1},
		{"not probed is not assessed", fixture("prompt", false, false), nil, 2},
		{"unknown approval is not assessed", fixture("unknown", true, false), nil, 2},
		{"bad flag", fixture("none", true, false), []string{"--fail-on", "maybe"}, 3},
		{"bad format", fixture("none", true, false), []string{"--format", "xml"}, 3},
	}
	for _, c := range cases {
		if got, out := scan(t, c.snap, c.args...); got != c.want {
			t.Errorf("%s: exit %d, want %d\n%s", c.name, got, c.want, out)
		}
	}
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb, nil); code != 3 {
		t.Errorf("no args: exit %d, want 3", code)
	}
}

func TestJSONShape(t *testing.T) {
	_, out := scan(t, fixture("none", true, true), "--format", "json")
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	for _, k := range []string{"schema_version", "collector_version", "snapshot_id", "host", "findings", "summary"} {
		if _, ok := r[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	fs := r["findings"].([]any)
	if len(fs) != 3 { // p1, p2, inline secret; p3 is mitigated
		t.Errorf("findings = %d, want 3", len(fs))
	}
	if strings.Contains(out, "/Users/alice/proj/CLAUDE.md (") {
		t.Error("home path not tilde-collapsed in message")
	}
}

func TestSARIFShape(t *testing.T) {
	_, out := scan(t, fixture("classifier", true, true), "--format", "sarif")
	var d struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string            `json:"id"`
						ShortDescription map[string]string `json:"shortDescription"`
						HelpURI          string            `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if d.Version != "2.1.0" || len(d.Runs) != 1 || d.Runs[0].Tool.Driver.Name != "agentreach" {
		t.Fatalf("bad envelope: %+v", d)
	}
	rules := d.Runs[0].Tool.Driver.Rules
	for _, r := range rules {
		if r.ShortDescription["text"] == "" || !strings.HasPrefix(r.HelpURI, "https://") {
			t.Errorf("rule %s incomplete", r.ID)
		}
	}
	levels := map[string]string{}
	for _, res := range d.Runs[0].Results {
		if rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex mismatch for %s", res.RuleID)
		}
		levels[res.RuleID] = res.Level
		for _, l := range res.Locations {
			// Home files are relative to HOME: no username in the report.
			if l.PhysicalLocation.ArtifactLocation.URIBaseID != "HOME" || strings.Contains(l.PhysicalLocation.ArtifactLocation.URI, "alice") || strings.HasPrefix(l.PhysicalLocation.ArtifactLocation.URI, "/") {
				t.Errorf("home location not relative to HOME: %+v", l.PhysicalLocation.ArtifactLocation)
			}
		}
	}
	if levels[rulePathConf] != "warning" || levels[rulePathIntegrity] != "note" || levels[ruleInlineSecret] != "error" {
		t.Errorf("levels = %v", levels)
	}
}

// The fake value is built at runtime so no secret-shaped literal lives in
// the repository.
func TestNoSecretInOutput(t *testing.T) {
	fake := "s" + "k-" + strings.Repeat("Q7x", 10)
	snap := fixture("none", true, true)
	snap.Paths[0].SourceTitle = "file mentioning " + fake
	shape := regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)
	for _, f := range []string{"text", "json", "sarif"} {
		if _, out := scan(t, snap, "--format", f); shape.MatchString(out) {
			t.Errorf("%s output carries a secret-shaped string", f)
		}
	}
}

func TestFromSnapshotAndOutFiles(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snap.json")
	outPath := filepath.Join(dir, "report.json")
	if code, out := scan(t, fixture("none", true, false), "--snapshot-out", snapPath, "--format", "json", "--out", filepath.Join(dir, "first.json")); code != 1 {
		t.Fatalf("first scan exit %d\n%s", code, out)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--from", snapPath, "--format", "json", "--out", outPath}, &stdout, &stderr,
		func([]string, bool) *posture.Snapshot { t.Fatal("collector ran with --from"); return nil })
	if code != 1 {
		t.Fatalf("--from exit %d: %s", code, stderr.String())
	}
	b, err := os.ReadFile(outPath)
	if err != nil || !bytes.Contains(b, []byte(`"snapshot_id": "abc123"`)) {
		t.Fatalf("report not written from snapshot: %v", err)
	}
	if st, _ := os.Stat(outPath); st.Mode().Perm() != 0o600 {
		t.Errorf("report mode %v, want 0600", st.Mode().Perm())
	}
}

func enforced(s *posture.Snapshot) *posture.Snapshot {
	s.Agents[0].SandboxEnforced = true
	return s
}

func noAgents() *posture.Snapshot {
	s := fixture("none", true, false)
	s.Agents, s.Paths, s.MCPServers = nil, nil, nil
	return s
}

func skipped(s *posture.Snapshot) *posture.Snapshot {
	s.Agents[0].ProbeSkippedReason = "agentreach ran inside a sandbox"
	return s
}

func surface(s *posture.Snapshot, surf, src string) *posture.Snapshot {
	s.Agents[0].StartSurface, s.Agents[0].StartSurfaceSource = surf, src
	s.Agents[0].SurfaceModes = map[string]string{posture.SurfacePrintSDK: "default", posture.SurfaceVSCode: "auto"}
	return s
}

func attested(s *posture.Snapshot) *posture.Snapshot {
	s.Paths = s.Paths[:1]
	s.Paths[0].Status, s.Paths[0].MitigatedBy = "attested", "declared egress_allowlist (not verified)"
	return s
}

// --from accepts only a agentreach snapshot: an empty object, a missing envelope
// or an incompatible schema is an error, never a clean result.
func TestFromRejectsNonSnapshots(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty object": `{}`,
		"no metadata":  `{"agents":[{"agent":"claude_code"}]}`,
		"newer schema": `{"schema_version":"9.0","snapshot_id":"x","host":"h","collected_at":"2026-10-28T00:00:00Z"}`,
		"not json":     `nope`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"scan", "--from", p}, &out, &errb, nil); code != 3 {
			t.Errorf("%s: exit %d, want 3 (%s)", name, code, errb.String())
		}
	}
	// A valid envelope with no agents is readable and clean: nothing is
	// installed, so there is nothing to assess and no finding to show.
	p := filepath.Join(dir, "no_agents.json")
	os.WriteFile(p, []byte(`{"schema_version":"`+posture.SchemaVersion+`","snapshot_id":"x","host":"h","collected_at":"2026-10-28T00:00:00Z"}`), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--from", p}, &out, &errb, nil); code != 0 || !strings.Contains(out.String(), "No coding agent or harness found") {
		t.Errorf("no agents: exit %d\n%s", code, out.String())
	}
}

// The text report groups paths by file and ranks fixes.
func TestTextGroupsByFile(t *testing.T) {
	s := fixture("none", true, false)
	p := s.Paths[0]
	for _, exit := range []string{"a", "b", "c"} {
		q := p
		q.PathID, q.ExitID, q.ExitTitle = "p-"+exit, "exit:"+exit, "exit "+exit
		s.Paths = append(s.Paths, q)
	}
	_, out := scan(t, s)
	if n := strings.Count(out, "~/.ssh/id_ed25519 can be read and sent out"); n != 1 {
		t.Errorf("file listed %d times, want once\n%s", n, out)
	}
	if !strings.Contains(out, "4 path(s) from 1 source(s), through 3 exit(s)") || !strings.Contains(out, "What to change first") {
		t.Errorf("grouping or fixes missing\n%s", out)
	}
}

// A path gated only when its source first loads says so, instead of
// claiming a prompt guards the harmful step or that nothing asks at all.
func TestSourceOnlyGateWording(t *testing.T) {
	p := fixture("prompt", true, false).Paths[0]
	p.SourceTitle, p.SourceKind, p.SourceApproval, p.AfterSourceApproval = "srv", "mcp", "prompt", "none"
	m := pathMessage(p)
	if !strings.Contains(m, "once it loads (a prompt asks you to approve it first), no later step asks you") {
		t.Errorf("message: %s", m)
	}
	p.SourceApproval, p.AfterSourceApproval = "none", "prompt"
	if m := pathMessage(p); !strings.Contains(m, "but a prompt asks you first") {
		t.Errorf("exit-gated message: %s", m)
	}
}

// ci adds two CI agent steps to a passing snapshot: one where outsiders'
// input meets the base repository's secrets and an open shell, one scoped.
func ci(s *posture.Snapshot) *posture.Snapshot {
	s.CIWorkflows = []posture.CIWorkflow{
		{Agent: "claude_code", ProjectDir: "/Users/alice/proj", Path: "/Users/alice/proj/.github/workflows/claude.yml", Line: 13,
			Launcher: "claude_code_action", ActorCheck: "write_access", AllowedBots: "all", UntrustedTrigger: true, OutsiderTrigger: true,
			BaseSecretsTrigger: true, ChecksOutHead: true, SkipPermissions: true, UnrestrictedShell: true},
		{Agent: "claude_code", ProjectDir: "/Users/alice/proj", Path: "/Users/alice/proj/.github/workflows/scoped.yml", Line: 9,
			Launcher: "claude_code_action", ActorCheck: "write_access", AllowedBots: "none", UntrustedTrigger: true, OutsiderTrigger: true},
	}
	return s
}

func TestCIFindings(t *testing.T) {
	snap := ci(fixture("prompt", true, false))
	if code, out := scan(t, snap); code != 1 || !strings.Contains(out, "AgentReach-CI-AGENT") ||
		!strings.Contains(out, "~/proj/.github/workflows/claude.yml:13: it runs a pull request's tree with the base repository's secrets") ||
		!strings.Contains(out, "allowed_bots: '*'") || !strings.Contains(out, "(bypassPermissions)") || strings.Contains(out, "scoped.yml:9") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if code, _ := scan(t, ci(fixture("prompt", true, false)), "--fail-on", "never"); code != 0 {
		t.Errorf("--fail-on never: exit %d", code)
	}
	_, out := scan(t, ci(fixture("prompt", true, false)), "--format", "sarif")
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI, URIBaseID string } `json:"artifactLocation"`
						Region           *struct{ StartLine int }        `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "AgentReach-CI-AGENT" {
			found = true
			l := r.Locations[0].PhysicalLocation
			if l.ArtifactLocation.URI != "proj/.github/workflows/claude.yml" || l.Region == nil || l.Region.StartLine != 13 {
				t.Errorf("sarif location %+v", l)
			}
		}
	}
	if !found {
		t.Error("no CI result in SARIF")
	}
}

// An SDK launcher in bypassPermissions is reported, never failing: agentreach
// read it from source text.
func TestSDKFinding(t *testing.T) {
	snap := fixture("prompt", true, false)
	snap.SDKLaunchers = []posture.SDKLauncher{{Agent: "claude_code", ProjectDir: "/Users/alice/proj", Path: "/Users/alice/proj/agent/run.ts",
		ImportLine: 1, PermissionModes: []string{"bypassPermissions"}}}
	code, out := scan(t, snap)
	if code != 0 || !strings.Contains(out, "AgentReach-SDK-BYPASS") || !strings.Contains(out, "~/proj/agent/run.ts starts Agent SDK sessions in bypassPermissions and no sandbox option") ||
		!strings.Contains(out, "SDK: 1 file(s)") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

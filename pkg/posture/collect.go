package posture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Collect gathers a posture snapshot for every supported agent found on
// this machine. It never fails hard: per-source problems are appended to
// Snapshot.Errors so partial inventories still return, and each agent row
// says whether its assessment is complete.
func Collect(ctx context.Context, opts Options) *Snapshot {
	snap := &Snapshot{
		SchemaVersion:    SchemaVersion,
		CollectorVersion: CollectorVersion,
		CollectedAt:      time.Now().UTC(),
		OS:               opts.goos(),
		Arch:             opts.arch(),
		Probed:           opts.Probe,
	}
	if !opts.Now.IsZero() {
		snap.CollectedAt = opts.Now.UTC()
	}
	snap.Host, _ = os.Hostname()
	if opts.Home != "" {
		// Every rule is resolved against Home, so it must be absolute or
		// prefix matching silently fails.
		if abs, err := filepath.Abs(opts.Home); err == nil {
			opts.Home = abs
		}
		snap.Host = "fixture"
	}
	if opts.Host != "" {
		snap.Host = opts.Host
	}
	sum := sha256.Sum256([]byte(snap.Host + "|" + snap.CollectedAt.Format(time.RFC3339Nano)))
	snap.SnapshotID = hex.EncodeToString(sum[:8])

	// Probes run as this process. Inside a sandbox (srt, which Claude Code's
	// sandbox is built on, or Codex's) they would measure that sandbox, not
	// what the agent's own tools can reach: the Read tool, MCP servers and
	// hooks run outside it. A live run there turns probes off and says why.
	if opts.Home == "" && opts.Probe {
		if why := sandboxedProcess(os.Getenv); why != "" {
			opts.Probe, opts.probeSkipped = false, why
			snap.Probed = false
		}
	}
	collectEnvironment(ctx, opts, snap)
	collectLaunchFlags(ctx, opts, snap)
	if wantAgent(opts, AgentClaudeCode) {
		collectClaudeCode(ctx, opts, snap)
	}
	if wantAgent(opts, AgentCodex) {
		collectCodex(ctx, opts, snap)
	}
	if wantAgent(opts, AgentOpenCode) {
		collectOpenCode(ctx, opts, snap)
	}
	if wantAgent(opts, AgentCline) {
		collectCline(ctx, opts, snap)
	}
	if wantAgent(opts, AgentGrok) {
		collectGrok(ctx, opts, snap)
	}
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	applyACP(opts, home, snap)
	collectCIWorkflows(opts, snap)
	collectSDKLaunchers(opts, snap)
	ComputePaths(snap)
	return snap
}

func wantAgent(opts Options, id string) bool {
	if len(opts.Agents) == 0 {
		return true
	}
	for _, a := range opts.Agents {
		if a == id {
			return true
		}
	}
	return false
}

// ReadSnapshot loads a snapshot written by the agentreach CLI. Snapshots from a
// newer major schema are rejected rather than half-read.
func ReadSnapshot(path string) (*Snapshot, error) {
	b, err := readFileLimited(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if err := ValidateSnapshot(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ValidateSnapshot rejects JSON that parsed but is not a agentreach snapshot from
// a compatible collector: an empty object, missing envelope fields or a
// different major schema. A snapshot with no agents is valid; reports say
// that nothing was assessed.
func ValidateSnapshot(s *Snapshot) error {
	var missing []string
	if s.SchemaVersion == "" {
		missing = append(missing, "schema_version")
	}
	if s.SnapshotID == "" {
		missing = append(missing, "snapshot_id")
	}
	if s.Host == "" {
		missing = append(missing, "host")
	}
	if s.CollectedAt.IsZero() {
		missing = append(missing, "collected_at")
	}
	if len(missing) > 0 {
		return fmt.Errorf("not a agentreach snapshot: missing %s", strings.Join(missing, ", "))
	}
	if major(s.SchemaVersion) != major(SchemaVersion) {
		return fmt.Errorf("schema %s is not compatible with this reader (%s)", s.SchemaVersion, SchemaVersion)
	}
	return nil
}

func major(v string) string {
	if i := strings.Index(v, "."); i >= 0 {
		return v[:i]
	}
	return v
}

// goos is the operating system the model assumes.
func (o Options) goos() string {
	if o.GOOS != "" {
		return o.GOOS
	}
	return runtime.GOOS
}

func (o Options) arch() string {
	if o.Arch != "" {
		return o.Arch
	}
	return runtime.GOARCH
}

// sandboxedProcess reports why this process looks sandboxed, or "".
func sandboxedProcess(getenv func(string) string) string {
	switch {
	case getenv("SANDBOX_RUNTIME") != "":
		return "agentreach ran inside a sandbox (SANDBOX_RUNTIME is set), so probes would measure that sandbox, not the agent; reach comes from the model only. Run agentreach outside the sandbox for a full assessment"
	case getenv("CODEX_SANDBOX") != "":
		return "agentreach ran inside Codex's sandbox (CODEX_SANDBOX is set), so probes would measure that sandbox, not the agent; reach comes from the model only. Run agentreach outside the sandbox for a full assessment"
	}
	return ""
}

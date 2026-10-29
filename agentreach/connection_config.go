package agentreach

import (
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
)

type agentreachConfig struct {
	// Extra project directories to inspect. Discovered projects (from the
	// agent's own records) are always included.
	ProjectDirs []string `hcl:"project_dirs,optional"`

	// Run inert reachability probes. Defaults to true.
	Probe *bool `hcl:"probe,optional"`

	// Per-dial timeout for TCP/unix probes, in milliseconds. Defaults to 300.
	ProbeTimeoutMs *int `hcl:"probe_timeout_ms,optional"`

	// Run the file and loopback probes a second time inside Anthropic's
	// sandbox runtime (srt) configured from the effective settings.
	// Defaults to false.
	Observe *bool `hcl:"observe,optional"`

	// Path to the srt binary; empty means look on PATH.
	SRTPath string `hcl:"srt_path,optional"`

	// Controls outside the agent that the operator asserts exist:
	// egress_allowlist, devcontainer, vm, edr, secrets_broker. Reported as
	// declared, never as verified.
	DeclaredControls []string `hcl:"declared_controls,optional"`

	// Review ledger written by "agentreach review"; defaults to
	// ~/.config/agentreach/reviews.json.
	ReviewLedger string `hcl:"review_ledger,optional"`

	// Agents to collect (claude_code, codex); empty means all.
	Agents []string `hcl:"agents,optional"`

	// Read snapshot JSON files (written by "agentreach collect") instead of
	// collecting this machine. Globs; ~ expands to the home directory.
	SnapshotPaths []string `hcl:"snapshot_paths,optional"`
}

// ConfigInstance returns an empty config for the SDK to populate.
func ConfigInstance() interface{} {
	return &agentreachConfig{}
}

// GetConfig extracts the config from a connection, or a zero value.
func GetConfig(connection *plugin.Connection) agentreachConfig {
	if connection == nil || connection.GetConfig() == nil {
		return agentreachConfig{}
	}
	config, _ := connection.GetConfig().(agentreachConfig)
	return config
}

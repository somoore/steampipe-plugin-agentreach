package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachReachFile(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_reach_file",
		Description: "Sensitive files and directories on this machine and whether the agent can read them, by tool path. The probe opens the file for reading and discards at most one byte; contents are never retained.",
		List:        &plugin.ListConfig{Hydrate: listReachFiles},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "category", Type: proto.ColumnType_STRING, Description: "Why the path is sensitive: ssh, cloud_credential, kube, vcs_credential, package_registry, agent_credential, secrets_manager, browser, shell_history or env_file."},
			{Name: "description", Type: proto.ColumnType_STRING, Description: "What the path holds."},
			{Name: "exists", Type: proto.ColumnType_BOOL, Description: "Whether the path exists."},
			{Name: "is_dir", Type: proto.ColumnType_BOOL, Description: "Whether the path is a directory."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Absolute path."},
			{Name: "permission_deny_read_rule", Type: proto.ColumnType_STRING, Description: "Read deny rule that covers the path, if any: managed and user rules for every file, plus the project's own project and local rules for files inside that project. Applies to the Read tool and to file commands Claude Code recognizes in Bash (cat, head, sed, tee, redirections), not to arbitrary subprocesses."},
			{Name: "probe_method", Type: proto.ColumnType_STRING, Description: "How readability was measured: user_process (open as the current user) or empty when probing is off."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project-local files such as .env; empty for home-directory paths."},
			{Name: "reachable_via_bash", Type: proto.ColumnType_BOOL, Description: "Readable and not blocked by a sandbox denyRead rule while the sandbox is on for that directory, i.e. a shell command can read it. Treats an enabled sandbox as enforced; unsandboxed retries and excludedCommands are not yet modelled."},
			{Name: "reachable_via_read_tool", Type: proto.ColumnType_BOOL, Description: "Readable and not blocked by a permission Read deny rule, i.e. the Read tool can read it."},
			{Name: "readable", Type: proto.ColumnType_BOOL, Description: "Whether the current user can open the path for reading."},
			{Name: "sandbox_deny_read_rule", Type: proto.ColumnType_STRING, Description: "Sandbox denyRead or credential deny rule that covers the path, if any: managed and user rules for every file, plus the project's own rules for files inside that project. Only enforced when the sandbox is enabled."},
			{Name: "tier", Type: proto.ColumnType_INT, Description: "Blast radius: 1 grants access to other systems outright, 2 is tokens and agent state, 3 is files that often leak secrets."},
			{Name: "bash_bypass", Type: proto.ColumnType_STRING, Description: "When the sandbox blocks the read, the escape routes still open: unsandboxed_retry (needs approval unless an allow rule or bypassPermissions approves it), excluded_commands, runtime_missing."},
			{Name: "model_agrees", Type: proto.ColumnType_BOOL, Description: "Whether the srt observation matches the model; null when not observed. False means the model or the settings translation is wrong."},
			{Name: "observed_method", Type: proto.ColumnType_STRING, Description: "How the path was observed in srt, or why it was not."},
			{Name: "observed_via_sandbox", Type: proto.ColumnType_BOOL, Description: "Whether a one-byte read succeeded inside srt configured from the effective managed and user settings; null when observed mode did not run."},
			{Name: "read_block_rule", Type: proto.ColumnType_STRING, Description: "Set to permissions.blockReadsOutsideWorkingDirectories when that setting fences this home-directory path from the file tools."},
			{Name: "reach_evidence", Type: proto.ColumnType_STRING, Description: "How the reachable_via_* columns were established: inferred (a model of Claude Code on top of the probe) or unknown."},
			{Name: "readable_evidence", Type: proto.ColumnType_STRING, Description: "How readable was established: observed (probe as the current user) or unknown."},
			{Name: "sandbox_allow_read_rule", Type: proto.ColumnType_STRING, Description: "A narrower allowRead rule that re-opens the path inside a denyRead region."},
			{Name: "read_approval", Type: proto.ColumnType_STRING, Description: "Weakest gate on any route that reads the file: a read-only shell command, the unsandboxed retry or other bypass, or the Read tool (none, classifier, prompt, denied, unknown)."},
			{Name: "reachable_via_retry", Type: proto.ColumnType_BOOL, Description: "Whether the sandbox blocks the read but an unsandboxed retry, an excluded command or a missing runtime can still read it."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Path"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listReachFiles(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.ReachFile { return s.ReachFiles })
	return nil, nil
}

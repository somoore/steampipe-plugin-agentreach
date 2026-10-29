package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachPath(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_path",
		Description: "Candidate exposure paths: an untrusted source the agent loads, a private file or write target it can touch, and for confidentiality paths an exit. Each leg is established separately, so a row is a candidate, not a demonstrated attack; each leg carries its own evidence.",
		List:        &plugin.ListConfig{Hydrate: listPaths},
		Columns: withCommon([]*plugin.Column{
			{Name: "after_source_approval", Type: proto.ColumnType_STRING, Description: "The strongest gate on the steps after the source has loaded: the read and the exit, or the write. When source_approval is stronger, the path waits only for the source to load (for example your approval of a project MCP server) and nothing later asks you."},
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "approval", Type: proto.ColumnType_STRING, Description: "Strongest gate on any step of the path (source, read, exit or write): none, classifier, prompt or unknown. The path runs unattended only when every step does."},
			{Name: "exit_detail", Type: proto.ColumnType_STRING, Description: "Why the exit can carry data out."},
			{Name: "exit_evidence", Type: proto.ColumnType_STRING, Description: "How the exit was established: configured, observed, inferred or unknown."},
			{Name: "exit_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.ExitID"), Description: "Stable exit identifier; empty for integrity paths."},
			{Name: "exit_kind", Type: proto.ColumnType_STRING, Description: "Exit kind: internet, allowed_domains, web_tool, mcp_remote, mcp_process, plugin_hooks or local_service."},
			{Name: "exit_rank", Type: proto.ColumnType_INT, Description: "Sort rank of the exit, 0 first."},
			{Name: "exit_title", Type: proto.ColumnType_STRING, Description: "Exit, in words."},
			{Name: "kind", Type: proto.ColumnType_STRING, Description: "Path kind: confidentiality (source, private file, exit) or integrity (source, write target)."},
			{Name: "mitigated_by", Type: proto.ColumnType_STRING, Description: "Declared control that the operator says closes the exit; not verified by agentreach."},
			{Name: "path_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.PathID"), Description: "Stable identifier: source id, target path and exit id joined by |, with #<project_dir> for a path that needs a project session. Unique per agent."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project a session must start in for every leg to load; empty when the legs load in any session."},
			{Name: "source_approval", Type: proto.ColumnType_STRING, Description: "Gate before the source reaches the agent: prompt for a project MCP server with no approval decision (it loads only once approved), web_source_approval for fetched pages, none for files and plugins that load on their own."},
			{Name: "source_detail", Type: proto.ColumnType_STRING, Description: "Why the source counts as untrusted."},
			{Name: "source_evidence", Type: proto.ColumnType_STRING, Description: "How the source was established: configured, observed, inferred or unknown."},
			{Name: "source_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.SourceID"), Description: "Stable source identifier."},
			{Name: "source_kind", Type: proto.ColumnType_STRING, Description: "Source kind: instruction_file, plugin_file (one per plugin: its skills, commands and subagents), mcp, plugin_hook or web_tool."},
			{Name: "source_rank", Type: proto.ColumnType_INT, Description: "Sort rank of the source, 0 first."},
			{Name: "source_title", Type: proto.ColumnType_STRING, Description: "Source, in words."},
			{Name: "status", Type: proto.ColumnType_STRING, Description: "Candidate, or attested when the operator declared a control that covers the exit; agentreach has not verified it, so an attested path is still a finding."},
			{Name: "target_blocked_by", Type: proto.ColumnType_STRING, Description: "Control that blocks one tool path to the target while another stays open, if any."},
			{Name: "target_category", Type: proto.ColumnType_STRING, Description: "Category of the private file or write target."},
			{Name: "target_evidence", Type: proto.ColumnType_STRING, Description: "How access to the target was established: inferred from configuration and a probe, or observed when srt confirmed the shell read."},
			{Name: "target_path", Type: proto.ColumnType_STRING, Description: "Absolute path of the private file or write target."},
			{Name: "target_tier", Type: proto.ColumnType_INT, Description: "Blast radius of a private file, 1 to 3; 0 for write targets."},
			{Name: "target_title", Type: proto.ColumnType_STRING, Description: "Target path with the home directory shown as ~."},
			{Name: "via", Type: proto.ColumnType_STRING, Description: "Tool path the agent uses on the target: shell, read_tool or edit_tool."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.PathID"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listPaths(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Path { return s.Paths })
	return nil, nil
}

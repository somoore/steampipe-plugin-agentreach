package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachLeg(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_leg",
		Description: "The legs agentreach_path is built from, one row each, whether or not they meet in a path: untrusted sources, private files, exits and write targets, with the evidence and, for exits and writes, the approval each step needs.",
		List:        &plugin.ListConfig{Hydrate: listLegs},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "approval", Type: proto.ColumnType_STRING, Description: "For exits and write targets, the gate on this step: none, classifier, prompt or unknown; empty for sources and private files."},
			{Name: "blocked_by", Type: proto.ColumnType_STRING, Description: "Declared control that covers an exit, or the control that blocks one tool path to a private file."},
			{Name: "category", Type: proto.ColumnType_STRING, Description: "Category of a private file or write target."},
			{Name: "detail", Type: proto.ColumnType_STRING, Description: "Why the leg exists."},
			{Name: "evidence", Type: proto.ColumnType_STRING, Description: "How the leg was established: configured, observed, inferred or unknown."},
			{Name: "kind", Type: proto.ColumnType_STRING, Description: "Leg kind: for sources instruction_file, plugin_file, mcp, plugin_hook or web_tool; for exits internet, allowed_domains, web_tool, mcp_remote, mcp_process, plugin_hooks or local_service; private_file; write_target."},
			{Name: "leg_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.LegID"), Description: "Stable identifier, the same value agentreach_path uses for source_id and exit_id."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Absolute path of a private file or write target."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project a session must start in for the leg to load; empty when it loads in any session."},
			{Name: "rank", Type: proto.ColumnType_INT, Description: "Sort rank within the role, 0 first."},
			{Name: "role", Type: proto.ColumnType_STRING, Description: "Role in a path: untrusted, private, exit or write."},
			{Name: "tier", Type: proto.ColumnType_INT, Description: "Blast radius of a private file, 1 to 3; 0 otherwise."},
			{Name: "via", Type: proto.ColumnType_STRING, Description: "Tool path to a private file or write target: shell, read_tool or edit_tool."},
			{Name: "title", Type: proto.ColumnType_STRING, Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listLegs(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.LegRow { return s.Legs })
	return nil, nil
}

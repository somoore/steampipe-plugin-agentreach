package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachLaunchFlag(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_launch_flag",
		Description: "Launch flags that change what an agent may do, found in shell aliases and functions (configured) and on running sessions (observed). Only flag names are kept, plus values from fixed sets such as permission modes.",
		List:        &plugin.ListConfig{Hydrate: listLaunchFlag},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier, such as claude_code or codex."},
			{Name: "default", Type: proto.ColumnType_BOOL, Description: "Whether the alias or function is named after the agent, so every session typed as that command gets the flag; agentreach models only these."},
			{Name: "effect", Type: proto.ColumnType_STRING, Description: "What the flag does to the session."},
			{Name: "evidence", Type: proto.ColumnType_STRING, Description: "Configured for a startup file, observed for a running session."},
			{Name: "file", Type: proto.ColumnType_STRING, Description: "Startup file the alias or function is in; empty for a running session."},
			{Name: "flag", Type: proto.ColumnType_STRING, Description: "Flag name, such as --dangerously-skip-permissions or --sandbox."},
			{Name: "line", Type: proto.ColumnType_INT, Description: "Line in the startup file."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Alias or function name, or pid and number for a running session."},
			{Name: "source", Type: proto.ColumnType_STRING, Description: "Where the flag was found: alias, function or running_session."},
			{Name: "value", Type: proto.ColumnType_STRING, Description: "Flag value when it comes from a fixed set (a permission mode, sandbox mode, approval policy or config key); prompts, paths and rules are never kept."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Flag"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listLaunchFlag(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.LaunchFlag { return s.LaunchFlags })
	return nil, nil
}

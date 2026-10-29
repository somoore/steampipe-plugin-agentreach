package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachSDKLauncher(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_sdk_launcher",
		Description: "Source files in known projects that start Claude Code through the Agent SDK, with the literal options they pass: permission mode, settingSources, canUseTool and the sandbox option. A heuristic read of the file's text; values built at run time show as dynamic.",
		List:        &plugin.ListConfig{Hydrate: listAgentreachSDKLauncher},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent the SDK starts, claude_code."},
			{Name: "can_use_tool", Type: proto.ColumnType_BOOL, Description: "Whether the file passes a canUseTool callback, so approvals go to the application's code instead of a person."},
			{Name: "dynamic_permission_mode", Type: proto.ColumnType_BOOL, Description: "Whether a permission mode is set from a value agentreach cannot read in the file."},
			{Name: "import_line", Type: proto.ColumnType_INT, Description: "Line of the first SDK import."},
			{Name: "language", Type: proto.ColumnType_STRING, Description: "Language of the file: typescript (TypeScript or JavaScript) or python."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Source file."},
			{Name: "permission_modes", Type: proto.ColumnType_JSON, Description: "Permission modes the file passes as literals, such as bypassPermissions or dontAsk."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Repository root the file belongs to."},
			{Name: "sandbox_enabled", Type: proto.ColumnType_BOOL, Description: "Whether the file passes the sandbox option with enabled set to true."},
			{Name: "setting_sources", Type: proto.ColumnType_JSON, Description: "Setting sources the file passes; null when it never sets settingSources, so the SDK reads user, project and local settings like the CLI."},
			{Name: "skip_permissions_allowed", Type: proto.ColumnType_BOOL, Description: "Whether the file sets allowDangerouslySkipPermissions to true."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Path"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listAgentreachSDKLauncher(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.SDKLauncher { return s.SDKLaunchers })
	return nil, nil
}

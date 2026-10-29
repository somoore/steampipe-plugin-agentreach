package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachMCPServer(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_mcp_server",
		Description: "Configured MCP servers from user, project and local scope, with launcher type, version pinning and whether a credential is embedded inline. Secret values are never read into the table, only their presence.",
		List:        &plugin.ListConfig{Hydrate: listMCPServers},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "args", Type: proto.ColumnType_JSON, Description: "Launcher arguments."},
			{Name: "command", Type: proto.ColumnType_STRING, Description: "Launcher command for stdio servers."},
			{Name: "command_exists", Type: proto.ColumnType_BOOL, Description: "For a launcher given as an absolute path, whether that file exists; a server whose launcher is missing cannot start. Null for a bare command name resolved on PATH and for remote servers."},
			{Name: "enabled", Type: proto.ColumnType_BOOL, Description: "Approval decision for .mcp.json servers, resolved from disabledMcpjsonServers in any settings file, then enabledMcpjsonServers and enableAllProjectMcpServers in managed and user settings, in project and local settings once the folder is trusted, and the choices recorded in ~/.claude.json; null when no source decides."},
			{Name: "env_keys", Type: proto.ColumnType_JSON, Description: "Names of environment variables passed to the server."},
			{Name: "has_inline_secret", Type: proto.ColumnType_BOOL, Description: "Whether an env or header value looks like a real credential."},
			{Name: "launcher_type", Type: proto.ColumnType_STRING, Description: "How the server starts: npx, uvx, docker, node, python, shell, binary or remote."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Server name as configured."},
			{Name: "pinned", Type: proto.ColumnType_BOOL, Description: "For npx/uvx launchers, whether an exact package version is named; null otherwise."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project and local scope; empty otherwise."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Where the server is declared: managed, user, project or local."},
			{Name: "source_path", Type: proto.ColumnType_STRING, Description: "File that declares the server."},
			{Name: "tool_approval", Type: proto.ColumnType_STRING, Description: "What a call to one of the server tools gets: none, classifier, prompt, denied or unknown."},
			{Name: "transport", Type: proto.ColumnType_STRING, Description: "Transport: stdio, http or sse."},
			{Name: "url", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.URL"), Description: "Endpoint URL for remote servers."},
			{Name: "plugin_name", Type: proto.ColumnType_STRING, Description: "Plugin that bundles the server, as name@marketplace; empty outside plugin scope."},
			{Name: "redacted", Type: proto.ColumnType_BOOL, Description: "Whether credential-shaped text was removed from command, args or url."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Name"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listMCPServers(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.MCPServer { return s.MCPServers })
	return nil, nil
}

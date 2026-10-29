package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachPlugin(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_plugin",
		Description: "Installed plugins, one row per install record in installed_plugins.json: where each came from, whether its version is pinned, whether it is enabled, and what it ships (hooks, MCP servers, skills, subagents, commands).",
		List:        &plugin.ListConfig{Hydrate: listPlugins},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "agent_count", Type: proto.ColumnType_INT, Description: "Number of subagent definitions (agents/*.md) the plugin ships."},
			{Name: "command_count", Type: proto.ColumnType_INT, Description: "Number of slash commands (commands/*.md) the plugin ships."},
			{Name: "enabled", Type: proto.ColumnType_BOOL, Description: "The enabledPlugins decision in user settings (or the project's settings for a project-scoped install); null when no decision is recorded."},
			{Name: "full_name", Type: proto.ColumnType_STRING, Description: "Plugin identifier as name@marketplace."},
			{Name: "git_commit_sha", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.GitCommitSHA"), Description: "Commit of the marketplace the install was resolved from, when recorded."},
			{Name: "has_hooks", Type: proto.ColumnType_BOOL, Description: "Whether the plugin ships hooks/hooks.json, i.e. commands that run on lifecycle events outside the sandbox."},
			{Name: "has_instruction_file", Type: proto.ColumnType_BOOL, Description: "Whether the plugin ships a CLAUDE.md that is added to every session's context."},
			{Name: "has_mcp", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Item.HasMCP"), Description: "Whether the plugin ships MCP servers (.mcp.json or mcpServers in plugin.json)."},
			{Name: "install_path", Type: proto.ColumnType_STRING, Description: "Directory the installed version lives in."},
			{Name: "install_path_exists", Type: proto.ColumnType_BOOL, Description: "Whether the install directory exists on disk."},
			{Name: "installed_at", Type: proto.ColumnType_TIMESTAMP, Description: "When the record says the plugin was installed."},
			{Name: "last_updated", Type: proto.ColumnType_TIMESTAMP, Description: "When the record says the plugin was last updated."},
			{Name: "marketplace", Type: proto.ColumnType_STRING, Description: "Marketplace the plugin was installed from."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Plugin name without the marketplace suffix."},
			{Name: "pinned", Type: proto.ColumnType_BOOL, Description: "Whether the recorded version is a release tag rather than a floating commit sha; null when the record has no version."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project the install applies to for project and local scope; empty for user scope."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Install scope: user, project or local (Codex plugins are user)."},
			{Name: "skill_count", Type: proto.ColumnType_INT, Description: "Number of skills (skills/*/SKILL.md) the plugin ships."},
			{Name: "version", Type: proto.ColumnType_STRING, Description: "Version string in the install record: a release tag, or a commit sha when the marketplace does not version the plugin."},
			{Name: "writable_by", Type: proto.ColumnType_STRING, Description: "Broadest class that can write the install directory: owner, group or others."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.FullName"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listPlugins(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Plugin { return s.Plugins })
	return nil, nil
}

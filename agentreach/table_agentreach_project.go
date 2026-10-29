package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachProject(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_project",
		Description: "Project directories the agent has worked in, with the trust decision it recorded and which project-scoped config files each one supplies.",
		List:        &plugin.ListConfig{Hydrate: listProjects},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "allowed_tools", Type: proto.ColumnType_JSON, Description: "Tools pre-approved for this project in the agent's global config."},
			{Name: "effective_permission_mode", Type: proto.ColumnType_STRING, Description: "Permission mode a terminal session started in this project begins in: project and local defaultMode apply, except auto and bypassPermissions, which do not take effect from those files. For Codex: sandbox_mode/approval_policy for a session here, from the project trust level and, when trusted, its .codex/config.toml."},
			{Name: "permission_mode_source", Type: proto.ColumnType_STRING, Description: "Where effective_permission_mode came from: managed, local, project, user, built_in or unknown."},
			{Name: "disabled_mcpjson_servers", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.DisabledMCPJSON"), Description: "Project .mcp.json servers the user rejected."},
			{Name: "enabled_mcpjson_servers", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.EnabledMCPJSON"), Description: "Project .mcp.json servers the user approved."},
			{Name: "exists", Type: proto.ColumnType_BOOL, Description: "Whether the directory still exists on disk."},
			{Name: "git_remote", Type: proto.ColumnType_STRING, Description: "First remote URL from .git/config, when a repository."},
			{Name: "has_instruction_file", Type: proto.ColumnType_BOOL, Description: "Whether the project supplies CLAUDE.md, AGENTS.md, rules, skills or subagents."},
			{Name: "has_local_settings", Type: proto.ColumnType_BOOL, Description: "Whether .claude/settings.local.json exists."},
			{Name: "has_mcp_json", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Item.HasMCPJSON"), Description: "Whether .mcp.json exists."},
			{Name: "has_project_settings", Type: proto.ColumnType_BOOL, Description: "Whether .claude/settings.json exists."},
			{Name: "network_approval", Type: proto.ColumnType_STRING, Description: "What decides a shell connection to a host no rule allows, in a session started here: none, classifier, prompt, denied or unknown."},
			{Name: "network_approval_reason", Type: proto.ColumnType_STRING, Description: "Why network_approval has its value."},
			{Name: "read_approval", Type: proto.ColumnType_STRING, Description: "What a read outside the working directory or around the sandbox needs in a session started here."},
			{Name: "sandbox_allowed_domains", Type: proto.ColumnType_JSON, Description: "Hosts this project's settings add to the sandbox allowlist: sandbox.network.allowedDomains and WebFetch(domain:...) allow rules."},
			{Name: "shell_approval", Type: proto.ColumnType_STRING, Description: "What a shell command that is not read-only needs in a session started here."},
			{Name: "web_fetch_approval", Type: proto.ColumnType_STRING, Description: "What a WebFetch to an arbitrary host needs in a session started here."},
			{Name: "is_git_repo", Type: proto.ColumnType_BOOL, Description: "Whether the directory contains a .git entry."},
			{Name: "last_start_time", Type: proto.ColumnType_TIMESTAMP, Description: "When the agent last started a session here, if recorded."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Absolute project directory."},
			{Name: "trusted", Type: proto.ColumnType_BOOL, Description: "Whether the workspace trust dialog was accepted for this directory."},
			{Name: "web_source_approval", Type: proto.ColumnType_STRING, Description: "What it takes for a fetched web page to reach the agent in a session started in this project: none unless a deny or ask rule covers every domain, because preapproved documentation domains and domains with a saved allow rule fetch with no prompt; prompt when an ask rule on WebFetch(domain:*) covers every domain; denied when WebFetch is denied or turned off. The classifier never counts here: it does not see tool results."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.ProjectDir"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listProjects(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Project { return s.Projects })
	return nil, nil
}

package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachHook(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_hook",
		Description: "Commands the agent runs on lifecycle events, from managed, user, project, local and plugin hook definitions. Hooks run outside the sandbox and before workspace trust.",
		List:        &plugin.ListConfig{Hydrate: listHooks},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "command", Type: proto.ColumnType_STRING, Description: "Shell command (or prompt text for prompt hooks) the hook runs."},
			{Name: "event", Type: proto.ColumnType_STRING, Description: "Lifecycle event, e.g. PreToolUse, PostToolUse, SessionStart, Stop; agent-turn-complete for a Codex notify program."},
			{Name: "hook_type", Type: proto.ColumnType_STRING, Description: "Hook type: command or prompt."},
			{Name: "matcher", Type: proto.ColumnType_STRING, Description: "Tool matcher pattern; empty matches every tool."},
			{Name: "plugin_enabled", Type: proto.ColumnType_BOOL, Description: "For plugin hooks, whether the plugin is enabled in user settings; null otherwise."},
			{Name: "plugin_name", Type: proto.ColumnType_STRING, Description: "For plugin hooks, the plugin identifier as name@marketplace."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project and local scope; empty otherwise."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Where the hook is defined: managed, user, project, local or plugin."},
			{Name: "source_path", Type: proto.ColumnType_STRING, Description: "File that defines the hook."},
			{Name: "source_tracked_in_git", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Item.SourceTrackedGit"), Description: "Whether the defining file is tracked by git, i.e. anyone with push access can change it."},
			{Name: "source_writable_by", Type: proto.ColumnType_STRING, Description: "Broadest class that can write the defining file: owner, group or others."},
			{Name: "third_party", Type: proto.ColumnType_BOOL, Description: "Whether the hook ships with a plugin rather than being written by the user."},
			{Name: "timeout", Type: proto.ColumnType_INT, Description: "Hook timeout in seconds, when set."},
			{Name: "args", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.Args").Transform(marshalJSON), Description: "Exec-form argument list, with credential-shaped arguments replaced by <redacted>."},
			{Name: "effective_timeout", Type: proto.ColumnType_INT, Description: "Timeout in seconds after defaults: 600 for command, http and mcp_tool hooks, 30 for prompt, 60 for agent, lower on some events."},
			{Name: "if", Type: proto.ColumnType_STRING, Description: "Permission-rule filter that narrows when the hook runs."},
			{Name: "origin", Type: proto.ColumnType_STRING, Description: "Where the hook is defined: settings, plugin, skill or subagent frontmatter, or notify (the Codex notify program)."},
			{Name: "redacted", Type: proto.ColumnType_BOOL, Description: "Whether credential-shaped text was removed from command, url or args."},
			{Name: "runs", Type: proto.ColumnType_BOOL, Description: "Whether the hook runs: false when disableAllHooks, allowManagedHooksOnly or a disabled plugin stops it, or for Codex when the hook has no recorded trust, hooks are off or the project is not trusted; null for a trusted Codex hook, whose hash agentreach does not recompute (counted as running)."},
			{Name: "runs_reason", Type: proto.ColumnType_STRING, Description: "Why the hook does not run, when runs is false, or why agentreach cannot confirm it, when runs is null."},
			{Name: "url", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.URL"), Description: "Endpoint of an http hook, with userinfo and secret query values redacted."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Event"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listHooks(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Hook { return s.Hooks })
	return nil, nil
}

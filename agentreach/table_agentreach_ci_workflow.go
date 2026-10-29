package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachCIWorkflow(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_ci_workflow",
		Description: "GitHub Actions workflow steps that run a coding agent: the Claude Code GitHub Action and its base action, the Codex action, and run steps that call claude -p or codex exec. Read from .github/workflows in the repositories of known projects; prompts, scripts and input values are never kept.",
		List:        &plugin.ListConfig{Hydrate: listAgentreachCIWorkflow},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent the step runs, such as claude_code or codex."},
			{Name: "action_ref", Type: proto.ColumnType_STRING, Description: "Ref after @ in the action's uses line; empty for a run step."},
			{Name: "actor_check", Type: proto.ColumnType_STRING, Description: "Who may trigger the agent: write_access (the action refuses users without write access), relaxed (allowed_non_write_users or allow-users widens it) or none (the base action and run steps check nobody)."},
			{Name: "allow_rules", Type: proto.ColumnType_INT, Description: "Allow rules the session gets from flags, the settings input and the repository's .claude/settings.json."},
			{Name: "allowed_bots", Type: proto.ColumnType_STRING, Description: "Bots that may trigger the action: none, listed or all; empty when the launcher has no bot check."},
			{Name: "base_secrets_trigger", Type: proto.ColumnType_BOOL, Description: "Whether the workflow runs on pull_request_target or workflow_run, which run with the base repository's secrets on pull request content."},
			{Name: "checks_out_head", Type: proto.ColumnType_BOOL, Description: "Whether an earlier step in the job checks out the pull request head into the workspace root, so the agent runs in that tree and reads its settings, hooks and instructions."},
			{Name: "comment_filter", Type: proto.ColumnType_BOOL, Description: "Whether include_comments_by_actor limits whose comments reach Claude."},
			{Name: "github_token", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.GitHubToken"), Description: "Token the Claude Code action works with: app (the Claude GitHub App), workflow (GITHUB_TOKEN), secret (another secret, often a personal access token) or inline; empty for other launchers."},
			{Name: "has_inline_secret", Type: proto.ColumnType_BOOL, Description: "Whether an input or environment value in the step, job or workflow is a literal credential; the value is not kept."},
			{Name: "job", Type: proto.ColumnType_STRING, Description: "Job id; empty when it is not one GitHub accepts."},
			{Name: "launcher", Type: proto.ColumnType_STRING, Description: "How the step starts the agent: claude_code_action, claude_code_base_action, codex_action or run."},
			{Name: "line", Type: proto.ColumnType_INT, Description: "Line of the step in the workflow file."},
			{Name: "mode", Type: proto.ColumnType_STRING, Description: "How the session starts: interactive (the action answers @claude mentions) or automation (it runs a fixed prompt)."},
			{Name: "outsider_trigger", Type: proto.ColumnType_BOOL, Description: "Whether someone without write access can cause a run that has the repository's secrets: issues, issue_comment, discussion, discussion_comment, pull_request_target or workflow_run."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Workflow file."},
			{Name: "permission_mode", Type: proto.ColumnType_STRING, Description: "Claude Code permission mode the session starts in, or the Codex permission profile."},
			{Name: "permission_mode_source", Type: proto.ColumnType_STRING, Description: "Where the mode comes from: flag, settings_input, project_settings, action_input or built_in."},
			{Name: "permissions_declared", Type: proto.ColumnType_BOOL, Description: "Whether the job or workflow sets permissions; without it the token gets the repository default, which agentreach cannot see."},
			{Name: "pinned", Type: proto.ColumnType_BOOL, Description: "Whether the action is pinned to a full commit SHA."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Repository root the workflow belongs to."},
			{Name: "safety_strategy", Type: proto.ColumnType_STRING, Description: "Codex action safety-strategy: drop-sudo (the default), unprivileged-user, read-only or unsafe."},
			{Name: "sandbox", Type: proto.ColumnType_STRING, Description: "Claude Code: enabled or off. Codex: read-only, workspace-write, danger-full-access or profile."},
			{Name: "secrets", Type: proto.ColumnType_JSON, Description: "Names of the secrets the step, its job or the workflow passes; values are never read."},
			{Name: "skip_permissions", Type: proto.ColumnType_BOOL, Description: "Whether the session runs in bypassPermissions, or Codex runs with no sandbox and no approvals."},
			{Name: "triggers", Type: proto.ColumnType_JSON, Description: "Events under on: that start the workflow."},
			{Name: "unrestricted_shell", Type: proto.ColumnType_BOOL, Description: "Whether any shell command runs with no approval and no sandbox: bypassPermissions, a blanket Bash allow rule, or Codex danger-full-access."},
			{Name: "untrusted_trigger", Type: proto.ColumnType_BOOL, Description: "Whether an event where someone else's text can reach the agent starts the workflow: issues, comments, reviews, discussions, pull requests or workflow_run."},
			{Name: "write_scopes", Type: proto.ColumnType_JSON, Description: "Token scopes the job or workflow grants write, or write-all."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Launcher"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listAgentreachCIWorkflow(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.CIWorkflow { return s.CIWorkflows })
	return nil, nil
}

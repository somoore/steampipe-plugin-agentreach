package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachWriteTarget(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_write_target",
		Description: "Files whose modification changes what the agent obeys or what runs on the developer's behalf: the agent's own guardrails, instruction files, CI workflows, dependency manifests, git hooks and shell startup files, and whether the agent can change each one without a human approving that write. Writability is checked with access(2); nothing is written.",
		List:        &plugin.ListConfig{Hydrate: listWriteTargets},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "bash_bypass", Type: proto.ColumnType_STRING, Description: "Escape routes still open when the sandbox blocks the write: unsandboxed_retry, excluded_commands, runtime_missing; for Codex escalation_request or exec_policy_allow."},
			{Name: "category", Type: proto.ColumnType_STRING, Description: "Target kind: guardrail, instruction, ci_workflow, dependency_manifest, git_hooks, shell_startup or devcontainer."},
			{Name: "edit_allow_rule", Type: proto.ColumnType_STRING, Description: "Edit or Write allow rule that pre-approves edits to the path, if any."},
			{Name: "edit_deny_rule", Type: proto.ColumnType_STRING, Description: "Edit or Write deny rule that covers the path, if any."},
			{Name: "edit_tool_approval", Type: proto.ColumnType_STRING, Description: "What happens when the agent's file tool edits the path in the session's permission mode: denied, prompt, classifier (auto mode reviews it), auto (no prompt) or allowed (bypassPermissions); for Codex what apply_patch gets: allowed, prompt, denied or unknown."},
			{Name: "is_dir", Type: proto.ColumnType_BOOL, Description: "Whether the target is a directory."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Absolute path."},
			{Name: "permission_protected", Type: proto.ColumnType_BOOL, Description: "Whether the path is on the permission system's protected list, whose writes are never auto-approved outside bypassPermissions."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project the target belongs to; empty for home-directory targets."},
			{Name: "session_dir", Type: proto.ColumnType_STRING, Description: "Project a session must start in for this row's gates: the target's project, or for a home-directory target a project whose own permission mode or sandbox setting differs from the machine-wide one (that project's gates apply there). Empty for the machine-wide gates."},
			{Name: "sandbox_protected", Type: proto.ColumnType_BOOL, Description: "Whether the sandbox denies shell writes to the path even inside a writable directory (for Codex, .git, .agents and .codex in a writable root)."},
			{Name: "sandbox_write_rule", Type: proto.ColumnType_STRING, Description: "The allowWrite, additionalDirectories or denyWrite rule that decided the shell write, if any; for Codex the writable root (cwd, writable_roots, TMPDIR, /tmp) or the protected path."},
			{Name: "writable_by_user", Type: proto.ColumnType_BOOL, Description: "Whether the current user can write the path, from access(2); null when probing is off."},
			{Name: "writable_evidence", Type: proto.ColumnType_STRING, Description: "How writable_by_user was established: observed or unknown."},
			{Name: "writable_via_bash", Type: proto.ColumnType_BOOL, Description: "Whether a shell command the agent runs can write the path, from agentreach's model of the sandbox."},
			{Name: "write_evidence", Type: proto.ColumnType_STRING, Description: "How writable_via_bash was established: inferred or unknown."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Path"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listWriteTargets(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.WriteTarget { return s.WriteTargets })
	return nil, nil
}

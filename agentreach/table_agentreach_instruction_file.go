package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachInstructionFile(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_instruction_file",
		Description: "Files the agent obeys as instructions (CLAUDE.md, AGENTS.md, rules, skills, subagents, commands) with integrity signals: hidden Unicode, HTML comments, external includes and URLs, git tracking and write permissions.",
		List:        &plugin.ListConfig{Hydrate: listInstructionFiles},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "external_include_count", Type: proto.ColumnType_INT, Transform: transform.FromField("Item.ExternalIncludes"), Description: "Count of @path include directives that pull other files into context."},
			{Name: "external_url_count", Type: proto.ColumnType_INT, Transform: transform.FromField("Item.ExternalURLs"), Description: "Count of http(s) URLs in the file."},
			{Name: "git_last_author", Type: proto.ColumnType_STRING, Description: "Email of the last commit that touched the file, when tracked in git."},
			{Name: "git_uncommitted", Type: proto.ColumnType_BOOL, Description: "Whether the working copy differs from the last commit, so the text loaded now is not only what that commit's author wrote."},
			{Name: "hidden_unicode_count", Type: proto.ColumnType_INT, Transform: transform.FromField("Item.HiddenUnicode"), Description: "Count of zero-width, bidi-override and tag characters that can hide text from reviewers."},
			{Name: "html_comment_count", Type: proto.ColumnType_INT, Transform: transform.FromField("Item.HTMLComments"), Description: "Count of HTML comments, which render invisibly but reach the model."},
			{Name: "kind", Type: proto.ColumnType_STRING, Description: "File kind: CLAUDE.md, AGENTS.md, rules, cursorrules, copilot-instructions, skill, subagent or command."},
			{Name: "path", Type: proto.ColumnType_STRING, Description: "Absolute file path."},
			{Name: "plugin_name", Type: proto.ColumnType_STRING, Description: "For plugin-provided files, the plugin identifier as name@marketplace."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project scope; empty otherwise."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Where the file applies: managed, user, project or plugin."},
			{Name: "sha256", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.SHA256"), Description: "SHA-256 of the file contents, for pinning and drift detection."},
			{Name: "size_bytes", Type: proto.ColumnType_INT, Description: "File size in bytes."},
			{Name: "third_party", Type: proto.ColumnType_BOOL, Description: "Whether the file comes from a plugin, or was last committed by an author who is neither the configured git identity nor the repository's most frequent author."},
			{Name: "tracked_in_git", Type: proto.ColumnType_BOOL, Description: "Whether the file is tracked by git, i.e. anyone with push access can change what the agent obeys."},
			{Name: "writable_by", Type: proto.ColumnType_STRING, Description: "Broadest class that can write the file: owner, group or others."},
			{Name: "changed_since_review", Type: proto.ColumnType_BOOL, Description: "Whether this path was reviewed, but its content has changed since."},
			{Name: "plugin_enabled", Type: proto.ColumnType_BOOL, Description: "For plugin files, whether the plugin is enabled; null when no decision is recorded (it loads)."},
			{Name: "review_signals", Type: proto.ColumnType_STRING, Description: "Reasons a human should read the file: hidden_unicode, html_comments, external_urls, external_includes. Signals, not verdicts."},
			{Name: "reviewed", Type: proto.ColumnType_BOOL, Description: "Whether this exact content (by SHA-256) is in the review ledger."},
			{Name: "untrusted", Type: proto.ColumnType_BOOL, Description: "Whether the file counts as an untrusted source: plugin-provided or committed by someone else and not reviewed, writable by group or others, or changed since review."},
			{Name: "untrusted_reason", Type: proto.ColumnType_STRING, Description: "Why the file counts as untrusted."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Path"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listInstructionFiles(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.InstructionFile { return s.InstructionFiles })
	return nil, nil
}

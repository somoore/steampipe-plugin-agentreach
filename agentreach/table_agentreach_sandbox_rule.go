package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachSandboxRule(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_sandbox_rule",
		Description: "Every grant and restriction from sandbox and permission configuration, normalised to one row per rule with the path it resolves to.",
		List:        &plugin.ListConfig{Hydrate: listSandboxRules},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "approves_network", Type: proto.ColumnType_BOOL, Description: "Whether the rule runs a network-capable command with no prompt in the effective permission mode."},
			{Name: "carries_network", Type: proto.ColumnType_BOOL, Description: "Whether a Bash allow rule approves a command that can reach the network or run arbitrary code."},
			{Name: "category", Type: proto.ColumnType_STRING, Description: "Rule category: filesystem, network, permission, credential or execution."},
			{Name: "dropped_in_auto_mode", Type: proto.ColumnType_BOOL, Description: "Whether auto mode ignores this broad Bash allow rule (blanket, wildcarded interpreter, package-manager run)."},
			{Name: "pattern", Type: proto.ColumnType_STRING, Description: "Rule text exactly as configured."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project and local scope; empty otherwise."},
			{Name: "resolved_path", Type: proto.ColumnType_STRING, Description: "Absolute path the pattern resolves to, when it is a path; <cwd>-prefixed when it depends on the session directory."},
			{Name: "rule_type", Type: proto.ColumnType_STRING, Description: "Rule type: denyRead, allowRead, denyWrite, allowWrite, allowedDomains, deniedDomains, allowUnixSockets, allow, deny, ask, excludedCommands, additionalDirectories, credentialFile or credentialEnvVar."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Settings scope: managed, user, project or local."},
			{Name: "source_path", Type: proto.ColumnType_STRING, Description: "File that defines the rule."},
			{Name: "tool", Type: proto.ColumnType_STRING, Description: "Tool a permission rule targets (Bash, Read, Edit, WebFetch, mcp__server__tool); mode for credential rules."},
			{Name: "redacted", Type: proto.ColumnType_BOOL, Description: "Whether credential-shaped text was removed from the rule."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Pattern"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listSandboxRules(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.SandboxRule { return s.SandboxRules })
	return nil, nil
}

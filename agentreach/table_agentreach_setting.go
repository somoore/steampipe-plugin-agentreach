package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachSetting(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_setting",
		Description: "Every leaf setting from every settings file the agent reads, with its scope so precedence can be reasoned about in SQL. Hooks are excluded; see agentreach_hook.",
		List:        &plugin.ListConfig{Hydrate: listSettings},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "applies", Type: proto.ColumnType_BOOL, Description: "Whether this row is part of the configuration the agent uses. False only for managed documents that lost the first-wins selection; see agentreach_agent.managed_source."},
			{Name: "key", Type: proto.ColumnType_STRING, Description: "Dotted setting key, e.g. permissions.defaultMode or sandbox.enabled."},
			{Name: "looks_like_secret", Type: proto.ColumnType_BOOL, Description: "For redacted values, whether the value classified as a credential; null otherwise. The value itself is never stored."},
			{Name: "project_dir", Type: proto.ColumnType_STRING, Description: "Project directory for project and local scope; empty otherwise."},
			{Name: "redacted", Type: proto.ColumnType_BOOL, Description: "Whether the value was withheld: env.* values other than plain switches (0, 1, true, false, digits), *Helper commands and header maps are never exposed."},
			{Name: "scope", Type: proto.ColumnType_STRING, Description: "Settings scope: managed, user, project or local."},
			{Name: "source_path", Type: proto.ColumnType_STRING, Description: "File the setting was read from."},
			{Name: "value", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.Value").Transform(marshalJSON), Description: "Setting value as JSON; lists are kept whole; null when redacted."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Key"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listSettings(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Setting { return s.Settings })
	return nil, nil
}

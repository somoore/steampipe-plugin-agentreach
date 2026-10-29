package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachMarketplace(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_marketplace",
		Description: "Plugin marketplaces registered on this machine (known_marketplaces.json): where plugins can be installed from, whether they auto-update, and whether a strictKnownMarketplaces policy would admit them.",
		List:        &plugin.ListConfig{Hydrate: listMarketplaces},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "auto_update", Type: proto.ColumnType_BOOL, Description: "Whether the marketplace refreshes itself automatically; null when the record does not say."},
			{Name: "in_extra_known", Type: proto.ColumnType_BOOL, Description: "Whether user or managed settings pre-register this marketplace under extraKnownMarketplaces."},
			{Name: "in_strict_allowlist", Type: proto.ColumnType_BOOL, Description: "Whether a strictKnownMarketplaces (or allowedMarketplaces) policy admits this marketplace; null when no such policy exists."},
			{Name: "install_location", Type: proto.ColumnType_STRING, Description: "Local clone or cache directory of the marketplace."},
			{Name: "install_location_exists", Type: proto.ColumnType_BOOL, Description: "Whether the install location exists on disk."},
			{Name: "last_updated", Type: proto.ColumnType_TIMESTAMP, Description: "When the marketplace was last refreshed."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Marketplace name as plugins reference it (name@marketplace)."},
			{Name: "official", Type: proto.ColumnType_BOOL, Description: "Whether this is Anthropic's official marketplace."},
			{Name: "source_repo", Type: proto.ColumnType_STRING, Description: "The repo, URL or path the marketplace is fetched from, by source type."},
			{Name: "source_type", Type: proto.ColumnType_STRING, Description: "Source type: github, git, url, file or directory."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Name"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listMarketplaces(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Marketplace { return s.Marketplaces })
	return nil, nil
}

package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachEnvironment(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_environment",
		Description: "Controls outside the agent's configuration: egress proxies, container boundaries and endpoint agents agentreach detected, and controls the operator declared. Detection is an observed fact, not proof the control blocks anything; declarations are not verified.",
		List:        &plugin.ListConfig{Hydrate: listEnvironment},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier; * for controls that cover the whole machine."},
			{Name: "declared", Type: proto.ColumnType_BOOL, Description: "Whether the operator declared the control in the connection config."},
			{Name: "detail", Type: proto.ColumnType_STRING, Description: "What was found, such as the proxy host; credentials are never included."},
			{Name: "detected", Type: proto.ColumnType_BOOL, Description: "Whether agentreach found the control on this machine."},
			{Name: "evidence", Type: proto.ColumnType_STRING, Description: "Observed for a detected control, configured for a declared one."},
			{Name: "kind", Type: proto.ColumnType_STRING, Description: "Control kind: network, isolation, endpoint or declared."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Control name: egress_proxy, system_proxy, container, devcontainer, edr, or a declared name such as egress_allowlist."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Name"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listEnvironment(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.EnvControl { return s.Environment })
	return nil, nil
}

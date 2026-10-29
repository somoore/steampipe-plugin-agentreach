package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachReachHost(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_reach_host",
		Description: "Network destinations the agent can reach from this machine: listening local services, privileged unix sockets and the internet, with the sandbox verdict for each. Probes dial and immediately disconnect; nothing is sent.",
		List:        &plugin.ListConfig{Hydrate: listReachHosts},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier."},
			{Name: "allowed_by_sandbox", Type: proto.ColumnType_BOOL, Description: "Whether sandbox network rules allow the destination; null when the sandbox is disabled and nothing restricts it, or for a Codex row agentreach cannot decide (a Unix socket under the Linux sandbox with network off, or the network proxy)."},
			{Name: "kind", Type: proto.ColumnType_STRING, Description: "Destination kind: tcp, unix_socket or internet."},
			{Name: "loopback", Type: proto.ColumnType_BOOL, Description: "Whether the destination is reached over this machine's loopback interface."},
			{Name: "probe_method", Type: proto.ColumnType_STRING, Description: "How reachability was measured: listener_table, catalog_dial, dial or assumed."},
			{Name: "process_name", Type: proto.ColumnType_STRING, Description: "Process listening on the port, when discoverable."},
			{Name: "reachable", Type: proto.ColumnType_BOOL, Description: "Whether a connection from the current user succeeded."},
			{Name: "sandbox_enabled", Type: proto.ColumnType_BOOL, Description: "Whether the sandbox is enabled at agent level."},
			{Name: "sandbox_rule", Type: proto.ColumnType_STRING, Description: "The allowedDomains or unix socket rule that permits the destination, if any."},
			{Name: "service", Type: proto.ColumnType_STRING, Description: "Service guessed from the port or socket (postgres, docker, ollama, ...)."},
			{Name: "target", Type: proto.ColumnType_STRING, Description: "Host:port, unix socket path, or * for the internet."},
			{Name: "observed_method", Type: proto.ColumnType_STRING, Description: "How the destination was observed in srt."},
			{Name: "observed_via_sandbox", Type: proto.ColumnType_BOOL, Description: "Whether a loopback dial succeeded inside srt; null when not observed."},
			{Name: "reachable_evidence", Type: proto.ColumnType_STRING, Description: "How reachable was established: observed (dialled), inferred (assumed, for the internet and allowed domains) or unknown."},
			{Name: "approval", Type: proto.ColumnType_STRING, Description: "What a shell command connecting to the destination needs: none, classifier, prompt, denied or unknown; denied when the sandbox refuses it in every mode or it is not reachable."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Target"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listReachHosts(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.ReachHost { return s.ReachHosts })
	return nil, nil
}

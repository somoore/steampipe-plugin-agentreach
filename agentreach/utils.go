package agentreach

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

//// ROWS

// row wraps every streamed item with the snapshot it came from, so a
// connection reading a folder of snapshots from many machines can tell the
// rows apart. Column transforms reach the item through Item.
type row struct {
	Item       any
	Host       string
	SnapshotID string
}

// fromItemCamel is the plugin's default transform: FromCamel applied to the
// wrapped item. Zero values (0, false) stay queryable.
func fromItemCamel(ctx context.Context, d *transform.TransformData) (any, error) {
	if r, ok := d.HydrateItem.(row); ok {
		d2 := *d
		d2.HydrateItem = r.Item
		return transform.FieldValueCamelCase(ctx, &d2)
	}
	return transform.FieldValueCamelCase(ctx, d)
}

// withCommon adds the host and snapshot_id columns and orders columns the
// way the standards ask: alphabetical, title last.
func withCommon(cols []*plugin.Column) []*plugin.Column {
	cols = append(cols,
		&plugin.Column{Name: "host", Type: proto.ColumnType_STRING, Transform: transform.FromField("Host"), Description: "Host name of the machine the snapshot was collected on."},
		&plugin.Column{Name: "snapshot_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("SnapshotID"), Description: "Identifier of the snapshot the row came from."},
	)
	sort.SliceStable(cols, func(i, j int) bool {
		if cols[i].Name == "title" {
			return false
		}
		if cols[j].Name == "title" {
			return true
		}
		return cols[i].Name < cols[j].Name
	})
	return cols
}

//// TRANSFORMS

// marshalJSON encodes any Go value as JSON text. The SDK treats a plain
// string in a JSON column as already-encoded JSON, so a bare "gold" would
// fail to parse; encoding first makes scalars and lists alike valid.
func marshalJSON(_ context.Context, d *transform.TransformData) (any, error) {
	b, err := json.Marshal(d.Value)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

//// SNAPSHOT CACHE

// snapshotTTL bounds how long one collection pass serves every table, so a
// benchmark run probes once.
const snapshotTTL = 60 * time.Second

// collectTimeout bounds one live collection. Collection runs on its own
// context, not the query's: a cancelled query must not leave a truncated
// snapshot in the cache.
const collectTimeout = 3 * time.Minute

type cacheEntry struct {
	mu    sync.Mutex
	snaps []*posture.Snapshot
	at    time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*cacheEntry{}
)

func entryFor(name string) *cacheEntry {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	e, ok := cache[name]
	if !ok {
		e = &cacheEntry{}
		cache[name] = e
	}
	return e
}

// getSnapshots returns the snapshots this connection serves: one live
// collection of this machine, or every snapshot file matched by
// snapshot_paths. Only the connection's own entry is locked, so one slow
// connection does not block another.
func getSnapshots(_ context.Context, d *plugin.QueryData) []*posture.Snapshot {
	name := ""
	if d.Connection != nil {
		name = d.Connection.Name
	}
	e := entryFor(name)
	return e.get(func() []*posture.Snapshot {
		cfg := GetConfig(d.Connection)
		if len(cfg.SnapshotPaths) > 0 {
			return loadSnapshotFiles(cfg.SnapshotPaths)
		}
		opts := posture.Options{ProjectDirs: cfg.ProjectDirs, Probe: true, ProbeTimeout: 300 * time.Millisecond}
		if cfg.Probe != nil {
			opts.Probe = *cfg.Probe
		}
		if cfg.ProbeTimeoutMs != nil && *cfg.ProbeTimeoutMs > 0 {
			opts.ProbeTimeout = time.Duration(*cfg.ProbeTimeoutMs) * time.Millisecond
		}
		if cfg.Observe != nil {
			opts.Observe = *cfg.Observe
		}
		opts.SRTPath = cfg.SRTPath
		opts.DeclaredControls = cfg.DeclaredControls
		opts.ReviewLedgerPath = cfg.ReviewLedger
		opts.Agents = cfg.Agents
		return []*posture.Snapshot{liveCollect(opts)}
	})
}

// get returns the cached snapshots, or loads them under this entry's lock.
func (e *cacheEntry) get(load func() []*posture.Snapshot) []*posture.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.snaps != nil && time.Since(e.at) < snapshotTTL {
		return e.snaps
	}
	e.snaps = load()
	e.at = time.Now()
	return e.snaps
}

// collect is posture.Collect; tests replace it.
var collect = posture.Collect

// liveCollect runs one collection on its own bounded context, never the
// query's.
func liveCollect(opts posture.Options) *posture.Snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()
	return collect(ctx, opts)
}

// loadSnapshotFiles reads every JSON snapshot the globs match. A file that
// does not parse becomes a snapshot with only an error, so the failure is
// visible in agentreach_agent.collect_errors rather than silently dropped.
func loadSnapshotFiles(globs []string) []*posture.Snapshot {
	home, _ := os.UserHomeDir()
	var files []string
	seen := map[string]bool{}
	for _, g := range globs {
		if strings.HasPrefix(g, "~/") {
			g = filepath.Join(home, g[2:])
		}
		m, _ := filepath.Glob(g)
		for _, f := range m {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)
	var out []*posture.Snapshot
	for _, f := range files {
		s, err := posture.ReadSnapshot(f)
		if err != nil {
			out = append(out, &posture.Snapshot{Host: filepath.Base(f), SnapshotID: "unreadable",
				Agents: []posture.Agent{{Agent: "unknown", CollectErrors: []string{fmt.Sprintf("snapshot %s: %v", f, err)}}}})
			continue
		}
		out = append(out, s)
	}
	return out
}

// streamRows sends each item of every snapshot, wrapped with its origin,
// and honours the row limit.
func streamRows[T any](ctx context.Context, d *plugin.QueryData, pick func(*posture.Snapshot) []T) {
	for _, s := range getSnapshots(ctx, d) {
		for _, it := range pick(s) {
			d.StreamListItem(ctx, row{Item: it, Host: s.Host, SnapshotID: s.SnapshotID})
			if d.RowsRemaining(ctx) == 0 {
				return
			}
		}
	}
}

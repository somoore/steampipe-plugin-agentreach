// Command agentreach-snapshot prints the raw posture snapshot as JSON. It is a
// library smoke test that needs no Steampipe.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

func main() {
	probe := flag.Bool("probe", true, "run inert reachability probes")
	flag.Parse()
	snap := posture.Collect(context.Background(), posture.Options{
		ProjectDirs: flag.Args(), Probe: *probe, ProbeTimeout: 300 * time.Millisecond,
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

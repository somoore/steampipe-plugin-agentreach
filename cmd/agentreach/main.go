// Command agentreach reports what a coding agent on this machine can reach and
// where it can send data, from the same read-only collector the Steampipe
// plugin uses. It never changes configuration and never sends anything.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

const usage = `agentreach: read-only posture check for coding agents

Usage:
  agentreach scan [flags] [PROJECT_DIR...]
  agentreach version

Scan flags:
  --format text|json|sarif   output format (default text)
  --out FILE                 write the report to FILE instead of stdout
  --snapshot-out FILE        also write the raw snapshot JSON to FILE
  --from SNAPSHOT.json       report a saved snapshot instead of collecting
  --no-probe                 skip the inert reachability probes (result is not fully assessed)
  --fail-on auto|none|classifier|prompt|never
                             fail on paths whose approval is at or below this gate. auto
                             (default) fails ungated paths, and classifier-only paths when
                             the agent's sandbox is not enforced
  --accept-attested          report paths through an exit you declared closed (for example
                             egress_allowlist) as accepted instead of failing; agentreach does not
                             verify the declaration either way

Exit codes:
  0  no failing finding, fully assessed
  1  at least one failing finding
  2  no failing finding, but part of the posture was not assessed
  3  usage or runtime error
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, collectLive))
}

type collector func(dirs []string, probe bool) *posture.Snapshot

func collectLive(dirs []string, probe bool) *posture.Snapshot {
	return posture.Collect(context.Background(), posture.Options{
		ProjectDirs: dirs, Probe: probe, ProbeTimeout: 300 * time.Millisecond,
	})
}

func run(args []string, stdout, stderr io.Writer, collect collector) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 3
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "agentreach "+posture.CollectorVersion)
		fmt.Fprintf(stdout, "behaviour model basis: claude_code %s, codex %s, opencode %s (cline and grok follow the current docs; no release pin)\n",
			posture.ModelBasisClaudeCode, posture.ModelBasisCodex, posture.ModelBasisOpenCode)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan":
	default:
		fmt.Fprintf(stderr, "agentreach: unknown command %q\n\n%s", args[0], usage)
		return 3
	}

	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	format := fl.String("format", "text", "")
	outPath := fl.String("out", "", "")
	snapOut := fl.String("snapshot-out", "", "")
	from := fl.String("from", "", "")
	noProbe := fl.Bool("no-probe", false, "")
	failOn := fl.String("fail-on", "auto", "")
	acceptAttested := fl.Bool("accept-attested", false, "")
	if err := fl.Parse(args[1:]); err != nil {
		fmt.Fprintf(stderr, "agentreach scan: %v\n\n%s", err, usage)
		return 3
	}
	if _, ok := approvalRank[*failOn]; (!ok || *failOn == "unknown" || *failOn == "denied") && *failOn != "never" && *failOn != "auto" {
		fmt.Fprintf(stderr, "agentreach scan: --fail-on must be auto, none, classifier, prompt or never\n")
		return 3
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "agentreach scan: --format must be text, json or sarif\n")
		return 3
	}

	var snap *posture.Snapshot
	if *from != "" {
		s, err := posture.ReadSnapshot(*from)
		if err != nil {
			fmt.Fprintf(stderr, "agentreach scan: %s: %v\n", *from, err)
			return 3
		}
		snap = s
	} else {
		snap = collect(fl.Args(), !*noProbe)
	}
	if snap == nil {
		fmt.Fprintln(stderr, "agentreach scan: no snapshot")
		return 3
	}

	if *snapOut != "" {
		if err := writeFile(*snapOut, func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(snap)
		}); err != nil {
			fmt.Fprintf(stderr, "agentreach scan: %v\n", err)
			return 3
		}
	}

	fs, sum := buildFindings(snap, *failOn, *acceptAttested)
	emit := func(w io.Writer) error {
		switch *format {
		case "json":
			return writeJSON(w, snap, fs, sum)
		case "sarif":
			return writeSARIF(w, snap, fs)
		}
		writeText(w, snap, fs, sum)
		return nil
	}
	var err error
	if *outPath != "" {
		err = writeFile(*outPath, emit)
	} else {
		err = emit(stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "agentreach scan: %v\n", err)
		return 3
	}
	return exitCode(sum)
}

func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		return err
	}
	return errors.Join(f.Close())
}

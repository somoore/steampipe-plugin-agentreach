package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

type jsonReport struct {
	SchemaVersion    string    `json:"schema_version"`
	CollectorVersion string    `json:"collector_version"`
	SnapshotID       string    `json:"snapshot_id"`
	Host             string    `json:"host"`
	Findings         []Finding `json:"findings"`
	Summary          Summary   `json:"summary"`
}

func writeJSON(w io.Writer, s *posture.Snapshot, fs []Finding, sum Summary) error {
	if fs == nil {
		fs = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{posture.SchemaVersion, s.CollectorVersion, s.SnapshotID, s.Host, fs, sum})
}

func writeText(w io.Writer, s *posture.Snapshot, fs []Finding, sum Summary) {
	fmt.Fprintf(w, "agentreach %s  host %s  snapshot %s\n", s.CollectorVersion, s.Host, s.SnapshotID)
	if len(sum.Agents) == 0 {
		fmt.Fprintln(w, "No coding agent or harness found on this machine.")
	} else {
		parts := make([]string, 0, len(sum.Agents))
		for _, ag := range sum.Agents {
			if ag.Version != "" {
				parts = append(parts, ag.Agent+" "+ag.Version)
			} else {
				parts = append(parts, ag.Agent)
			}
		}
		fmt.Fprintf(w, "Agents found: %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	if !sum.Assessed {
		fmt.Fprintln(w, "NOT FULLY ASSESSED:")
		for _, r := range sum.NotAssessedBy {
			fmt.Fprintln(w, "  - "+textSafe(r))
		}
		fmt.Fprintln(w)
	}
	for _, a := range sum.Assumptions {
		fmt.Fprintln(w, "Assumed: "+textSafe(a)+".")
	}
	if len(sum.Assumptions) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Candidate paths by approval: none %d, classifier %d, prompt %d, unknown %d\n",
		sum.PathsByGate["none"], sum.PathsByGate["classifier"], sum.PathsByGate["prompt"], sum.PathsByGate["unknown"])
	if sum.Attested > 0 {
		fmt.Fprintf(w, "Paths through an exit you declared closed (not verified): %d, accepted: %d\n", sum.Attested, sum.Accepted)
	}
	fmt.Fprintf(w, "Failing findings (fail-on %s): %d of %d\n\n", sum.FailOn, sum.Failing, sum.Findings)

	var other []Finding
	type group struct {
		title, gate    string
		tier           int
		n              int
		sources, exits map[string]bool
		example        string
	}
	groups := map[string]*group{}
	var order []string
	multi := len(s.Agents) > 1
	label := func(agent string) string {
		if multi {
			return agentName(agent) + ": "
		}
		return ""
	}
	for _, f := range fs {
		if !f.Failing && f.RuleID != ruleInlineSecret && f.RuleID != ruleSDKBypass || f.RuleID == ruleNotAssessed {
			continue
		}
		if f.RuleID != rulePathConf && f.RuleID != rulePathIntegrity {
			other = append(other, f)
			continue
		}
		k := f.kind + "|" + f.Agent + "|" + f.target
		g := groups[k]
		if g == nil {
			verb := "read and sent out"
			if f.kind == "integrity" {
				verb = "changed"
			}
			g = &group{title: label(f.Agent) + f.targetTitle + " can be " + verb, gate: f.Approval, tier: f.tier,
				sources: map[string]bool{}, exits: map[string]bool{}, example: f.Message}
			groups[k] = g
			order = append(order, k) // findings arrive worst first
		}
		g.n++
		g.sources[f.source] = true
		if f.exit != "" {
			g.exits[f.exit] = true
		}
	}
	for _, f := range other {
		fmt.Fprintf(w, "[%s] %s\n  %s\n", strings.ToUpper(f.Level), f.RuleID, textSafe(f.Message))
	}
	if len(other) > 0 {
		fmt.Fprintln(w)
	}
	if len(order) > 0 {
		fmt.Fprintln(w, "Failing paths, one line per file (worst first):")
	}
	for i, k := range order {
		if i == 10 {
			fmt.Fprintf(w, "  ... and %d more file(s); use --format json for every path.\n", len(order)-i)
			break
		}
		g := groups[k]
		via := ""
		if len(g.exits) > 0 {
			via = fmt.Sprintf(", through %d exit(s)", len(g.exits))
		}
		fmt.Fprintf(w, "  %s: %d path(s) from %d source(s)%s, %s\n    e.g. %s\n",
			textSafe(g.title), g.n, len(g.sources), via, gateWord(g.gate), textSafe(g.example))
	}
	if fixes := rankFixes(fs, label); len(fixes) > 0 {
		fmt.Fprintln(w, "\nWhat to change first (failing paths each change would close):")
		for i, x := range fixes {
			if i == 5 {
				break
			}
			fmt.Fprintf(w, "  %4d  %s\n", x.n, textSafe(x.what))
		}
	}
	if len(order) == 0 && len(other) == 0 {
		fmt.Fprintln(w, "No failing findings.")
	}
}

func gateWord(g string) string {
	switch g {
	case "none":
		return "nothing asks you"
	case "classifier":
		return "only auto mode's classifier"
	case "prompt":
		return "a prompt asks you"
	}
	return "approval unknown"
}

type fix struct {
	what string
	n    int
}

// rankFixes counts, for each leg of the failing paths, how many paths
// cutting that leg alone would close: every path needs all of its legs.
func rankFixes(fs []Finding, label func(string) string) []fix {
	count := map[string]int{}
	for _, f := range fs {
		if !f.Failing || f.RuleID != rulePathConf && f.RuleID != rulePathIntegrity {
			continue
		}
		l := label(f.Agent)
		switch {
		case f.kind == "integrity":
			count[l+"Deny writes to "+f.targetTitle]++
		case f.Agent == "claude_code":
			count[l+"Deny reads of "+f.targetTitle+" (sandbox.filesystem.denyRead and a Read deny rule)"]++
		default:
			count[l+"Deny reads of "+f.targetTitle]++
		}
		if f.exitTitle != "" {
			count[l+"Close the exit: "+f.exitTitle]++
		}
		count[l+"Remove or review the source: "+f.sourceTitle]++
	}
	var out []fix
	for k, n := range count {
		out = append(out, fix{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].what < out[j].what
	})
	return out
}

// SARIF 2.1.0, the subset GitHub code scanning reads.
func writeSARIF(w io.Writer, s *posture.Snapshot, fs []Finding) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription msg               `json:"shortDescription"`
		Help             msg               `json:"help"`
		HelpURI          string            `json:"helpUri"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type artifactLoc struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId,omitempty"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physLoc struct {
		ArtifactLocation artifactLoc `json:"artifactLocation"`
		Region           *region     `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physLoc `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		RuleIndex           int               `json:"ruleIndex"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations,omitempty"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
		Properties          map[string]any    `json:"properties,omitempty"`
	}
	var rs []rule
	index := map[string]int{}
	for i, r := range rules {
		index[r.ID] = i
		rs = append(rs, rule{r.ID, r.Name, msg{r.Short}, msg{r.Help}, r.HelpURI, nil})
	}
	results := []result{}
	for _, f := range fs {
		r := result{RuleID: f.RuleID, RuleIndex: index[f.RuleID], Level: f.Level, Message: msg{f.Message},
			Properties: map[string]any{"agent": f.Agent, "failing": f.Failing}}
		if f.Approval != "" {
			r.Properties["approval"] = f.Approval
		}
		if f.PathID != "" {
			r.PartialFingerprints = map[string]string{"agentreachPathId/v1": f.PathID}
		}
		if f.Location != "" && strings.HasPrefix(f.Location, "/") {
			// Files under a home directory are given relative to HOME, so
			// an uploaded report names neither the user nor the full path
			// and the same finding matches across machines.
			if loc := homeRE.FindStringIndex(f.Location); loc != nil && loc[0] == 0 {
				rel := strings.TrimPrefix(f.Location[loc[1]:], "/")
				r.Locations = []location{{physLoc{ArtifactLocation: artifactLoc{URI: (&url.URL{Path: rel}).String(), URIBaseID: "HOME"}}}}
			} else {
				u := url.URL{Scheme: "file", Path: f.Location}
				r.Locations = []location{{physLoc{ArtifactLocation: artifactLoc{URI: u.String()}}}}
			}
			if f.Line > 0 {
				r.Locations[0].PhysicalLocation.Region = &region{StartLine: f.Line}
			}
		}
		results = append(results, r)
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "agentreach", "version": s.CollectorVersion,
				"informationUri": "https://github.com/somoore/steampipe-plugin-agentreach",
				"rules":          rs,
			}},
			"results": results,
			"originalUriBaseIds": map[string]any{
				"HOME": map[string]any{"description": map[string]string{"text": "The scanned user's home directory."}},
			},
			"properties": map[string]any{"host": s.Host, "snapshot_id": s.SnapshotID},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

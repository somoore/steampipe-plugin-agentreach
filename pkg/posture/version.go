package posture

// Version handling. agentreach reports the version an agent reports about
// itself and never stores a baseline to compare against: coding agents
// release continuously, so a pinned "verified against" version is stale
// within days and turns every scan into a false alarm. What the model needs
// at scan time is read from the installed release (for example auto mode's
// rule-drop list, autodrop.go) or from the documents watched by
// ci/docs_drift.sh, never from a constant here.

import "strings"

// versionFrom picks the version token out of a --version output split into
// fields. Agents word it differently:
//
//	opencode v2.2.4
//	grok 1.0.46 (2765805b9442) [stable]
//	codex-cli 0.155.1
//	2.1.314 (Claude Code)
//
// so the first field that parses as a dotted numeric version wins, with any
// leading v dropped. The last field is never used: it can be a channel name
// such as "[stable]".
func versionFrom(fields []string) string {
	for _, f := range fields {
		f = strings.Trim(f, "()[],")
		if _, ok := parseVersion(f); ok {
			return strings.TrimPrefix(strings.TrimPrefix(f, "v"), "V")
		}
	}
	return ""
}

// parseVersion splits a dotted numeric version; every component must parse.
// A leading v (v2.2.4) is tolerated. It recognises a version token; it does
// not compare releases.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, false
		}
		out[i] = 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, false
			}
			out[i] = out[i]*10 + int(r-'0')
		}
	}
	return out, true
}

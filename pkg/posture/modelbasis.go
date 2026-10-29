package posture

import (
	"strconv"
	"strings"
)

// The behaviour model: every gate in approval.go and codexmodel.go, the
// settings scope and merge rules in managed.go, the protected-file list and
// the defaults that change per release. It was built from the Claude Code
// and Codex CLI documents and releases named below, and everything
// version-dependent in it is verified against them. ModelBasis* is the
// newest release whose behaviour the model has been checked against; when
// the installed agent is newer, findings may lag, and the agent row and the
// CLI say so instead of passing silently.
//
// Three drift signals keep the model honest:
//
//   - scan time: auto mode's rule-drop list is read from the installed
//     Claude Code binary (autodrop.go); the fallback is the list read from
//     ModelBasisClaudeCode.
//   - scan time: agentreach_agent.model_basis and model_basis_stale compare
//     the basis with the installed version.
//   - weekly CI: ci/docs_drift.sh fails when any document the model cites
//     changed content (re-verify the model, then refresh the baseline), and
//     the claude-code-drift workflow fails when the installed-release drop
//     list cannot be read, changes shape or changes content.
const (
	// ModelBasisClaudeCode is the Claude Code release the gates, defaults
	// and protected-file list were verified against. Keep in step with the
	// fixtures' pinned versions (cmd/agentreach-fixtures) and the mod's
	// spec/controls.yaml applicability note.
	ModelBasisClaudeCode = "2.1.312"
	// ModelBasisCodex is the Codex CLI release the Codex gate model was
	// verified against (docs plus the 0.155.1 source).
	ModelBasisCodex = "0.155.1"
)

// versionAfter reports whether version a is newer than b. Claude Code and
// Codex CLI versions are numeric major.minor[.patch[...]] (2.1.312,
// 0.155.1); missing components count as zero. A non-numeric or empty
// version makes the answer unknown (nil), never a silent false.
func versionAfter(a, b string) *bool {
	pa, ok := parseVersion(a)
	if !ok {
		return nil
	}
	pb, ok := parseVersion(b)
	if !ok {
		return nil
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			t := x > y
			return &t
		}
	}
	t := false
	return &t
}

// parseVersion splits a dotted numeric version; every component must parse.
// A leading v (v2.2.1) is tolerated.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

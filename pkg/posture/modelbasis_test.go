package posture

import "testing"

func TestVersionAfter(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want *bool // nil = unknown
	}{
		{"2.1.340", "2.1.312", boolPtr(true)},     // newer patch
		{"2.2.0", "2.1.312", boolPtr(true)},       // newer minor
		{"3.0.0", "2.1.312", boolPtr(true)},       // newer major
		{"2.1.312", "2.1.312", boolPtr(false)},    // equal
		{"2.1.300", "2.1.312", boolPtr(false)},    // older
		{"0.155.1", "0.155.1", boolPtr(false)},    // codex equal
		{"0.156.0", "0.155.1", boolPtr(true)},     // codex newer
		{"2.1", "2.1.0", boolPtr(false)},          // missing component counts as zero
		{"2.1.1", "2.1", boolPtr(true)},           // present beats missing zero
		{"", "2.1.312", nil},                      // unknown installed version
		{"unknown", "2.1.312", nil},               // non-numeric
		{"2.1.312", "", nil},                      // unknown basis
		{"2.1.312 (Claude Code)", "2.1.312", nil}, // decorated version string
	} {
		got := versionAfter(tc.a, tc.b)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("versionAfter(%q, %q) = %v, want unknown", tc.a, tc.b, *got)
		case tc.want != nil && got == nil:
			t.Errorf("versionAfter(%q, %q) = unknown, want %v", tc.a, tc.b, *tc.want)
		case tc.want != nil && got != nil && *got != *tc.want:
			t.Errorf("versionAfter(%q, %q) = %v, want %v", tc.a, tc.b, *got, *tc.want)
		}
	}
}

// The basis constants must stay parseable: an unparseable basis would make
// every staleness answer unknown.
func TestModelBasesParse(t *testing.T) {
	for _, v := range []string{ModelBasisClaudeCode, ModelBasisCodex} {
		if _, ok := parseVersion(v); !ok {
			t.Errorf("model basis %q is not a numeric version", v)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

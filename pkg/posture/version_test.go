package posture

import "testing"

func TestVersionFrom(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"claude", []string{"2.1.314", "(Claude", "Code)"}, "2.1.314"},
		{"codex", []string{"codex-cli", "0.155.1"}, "0.155.1"},
		{"opencode", []string{"opencode", "v2.2.4"}, "2.2.4"},
		{"grok", []string{"grok", "1.0.46", "(2765805b9442)", "[stable]"}, "1.0.46"},
		{"cline", []string{"3.0.73"}, "3.0.73"},
		{"comma suffix", []string{"tool", "4.2.0,"}, "4.2.0"},
		{"nothing numeric", []string{"tool", "beta"}, ""},
		{"empty", nil, ""},
	} {
		if got := versionFrom(tc.args); got != tc.want {
			t.Errorf("%s: versionFrom(%q) = %q, want %q", tc.name, tc.args, got, tc.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		ok   bool
		want []int
	}{
		{"2.1.312", true, []int{2, 1, 312}},
		{"v2.2.4", true, []int{2, 2, 4}},
		{"0.155.1", true, []int{0, 155, 1}},
		{"2.1", true, []int{2, 1}},
		{"", false, nil},
		{"unknown", false, nil},
		{"2.1.x", false, nil},
		{"2..4", false, nil},
		{"2.1.312 (Claude Code)", false, nil},
	} {
		got, ok := parseVersion(tc.in)
		if ok != tc.ok {
			t.Errorf("parseVersion(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseVersion(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

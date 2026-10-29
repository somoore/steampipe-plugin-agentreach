package posture

// ScrubText replaces credential-shaped substrings in s with <redacted>. It is
// the same scrubber the collector runs on every string that leaves a config
// file, exported so the CLI can apply it a second time to everything it
// prints.
func ScrubText(s string) string {
	out, _ := scrubText(s)
	return out
}

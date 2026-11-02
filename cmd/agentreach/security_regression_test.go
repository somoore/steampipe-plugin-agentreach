package main

// Regression tests for the CLI hardening fixes: --out/--snapshot-out must not
// follow a symlink (a repository can plant one and --out truncates it), and
// text output must not carry control bytes from a snapshot it did not author.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutRefusesSymlink(t *testing.T) {
	for _, flag := range []string{"--out", "--snapshot-out"} {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		link := filepath.Join(dir, "link")
		if err := os.WriteFile(target, []byte("ORIGINAL"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink: %v", err)
		}
		code, out := scan(t, fixture("none", true, false), flag, link)
		if code != 3 {
			t.Errorf("%s: exit %d, want 3 (%s)", flag, code, out)
		}
		if got, err := os.ReadFile(target); err != nil || string(got) != "ORIGINAL" {
			t.Errorf("%s: symlink target modified: %q (%v)", flag, got, err)
		}
	}
}

func TestTextOutputHasNoControlBytes(t *testing.T) {
	s := fixture("none", true, false)
	s.Host = "h\x1b]0;pwned\x07"
	s.SnapshotID = "sid\x1b[2J"
	s.CollectorVersion = "0.2.0\x1b[31m"
	s.Agents[0].Version = "1.0\x1b]52;c;cGF5bG9hZA==\x07"
	_, out := scan(t, s, "--format", "text")
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("raw control bytes in text output: %q", out)
	}
}

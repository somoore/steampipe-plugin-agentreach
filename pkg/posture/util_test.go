package posture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config that exists but cannot be read must make the posture not fully
// assessed, not silently disappear.
func TestUnreadableProjectConfigIsReported(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".mcp.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(filepath.Join(proj, "CLAUDE.md"), "# Project\n")
	s := f.collect(proj)
	for _, e := range s.Errors {
		if strings.Contains(e, ".mcp.json") {
			return
		}
	}
	t.Errorf("no collect error for an unreadable .mcp.json; errors: %v", s.Errors)
}

func TestReadFileLimited(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "config.json")
	if err := os.WriteFile(ok, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readFileLimited(ok); err != nil || string(b) != `{"a":1}` {
		t.Errorf("readFileLimited(ok) = %q, %v", b, err)
	}

	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := readFileLimited(big); err == nil {
		t.Error("readFileLimited accepted a file larger than the cap")
	}
	if _, err := readFileLimited(dir); err == nil {
		t.Error("readFileLimited accepted a directory")
	}
}

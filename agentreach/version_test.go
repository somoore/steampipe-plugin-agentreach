package agentreach

// Release consistency: the CHANGELOG's newest version heading, the collector
// version recorded in every snapshot, and the Claude Code plugin manifest must
// agree. A release is only real when all three move together; the interim
// v0.1.0/v0.1.1 tags (tagged from main with no CHANGELOG entry) are why this
// test exists. `make test` and CI run it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

func TestReleaseVersionsAgree(t *testing.T) {
	changelog, err := os.ReadFile(filepath.Join("..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	m := regexp.MustCompile(`(?m)^## (\S+)`).FindSubmatch(changelog)
	if m == nil {
		t.Fatal("CHANGELOG.md has no '## ' heading")
	}
	top := string(m[1])

	manifest, err := os.ReadFile(filepath.Join("..", "claude-plugin", ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatalf("read claude-plugin/.claude-plugin/plugin.json: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &doc); err != nil {
		t.Fatalf("parse plugin.json: %v", err)
	}

	// Work in progress after a release: the code versions must still agree
	// with each other; only a versioned CHANGELOG heading pins them to a tag.
	if top == "Unreleased" {
		if doc.Version != posture.CollectorVersion {
			t.Errorf("claude-plugin plugin.json version %q != CollectorVersion %q", doc.Version, posture.CollectorVersion)
		}
		return
	}

	if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(top) {
		t.Fatalf("CHANGELOG.md top heading %q is not 'Unreleased' or vX.Y.Z", top)
	}
	want := strings.TrimPrefix(top, "v")
	if posture.CollectorVersion != want {
		t.Errorf("CollectorVersion %q != CHANGELOG release %q (pkg/posture/types.go)", posture.CollectorVersion, want)
	}
	if doc.Version != want {
		t.Errorf("claude-plugin plugin.json version %q != CHANGELOG release %q", doc.Version, want)
	}
}

package main

// Static guards for the composite action. It cannot be executed without a
// runner and a release, so the properties that matter are checked as text:
// the args input is word-split into an array (never expanded unquoted, which
// could inject flags) and the action keeps ownership of the output paths.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompositeActionArgsHandling(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatalf("action.yml: %v", err)
	}
	s := string(b)

	// -d '' reads the whole value: plain read -a stops at the first line and
	// would drop the rest of a multiline args block.
	if !strings.Contains(s, `read -r -d '' -a extra <<<"$AGENTREACH_ARGS"`) {
		t.Error("args is not split with read -d '' -a")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, " $AGENTREACH_ARGS") {
			t.Errorf("args is expanded unquoted: %q", strings.TrimSpace(line))
		}
	}
	for _, guard := range []string{"--out|--out=*", "--snapshot-out|--snapshot-out=*"} {
		if !strings.Contains(s, guard) {
			t.Errorf("missing rejection of %s in args", guard)
		}
	}
	if !strings.Contains(s, `"${extra[@]}"`) {
		t.Error("split args are not passed as a quoted array")
	}
}

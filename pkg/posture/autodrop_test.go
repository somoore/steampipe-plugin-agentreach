package posture

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A minified bundle in the shape Claude Code 2.1.312 ships: the base list,
// a list that spreads it, the final list, and the matcher.
const fakeBundle = `var re=[],Ger=[...re,"python","python3","node","npm run","yarn run","pnpm run","bun run","bash","sh"],` +
	`PKo=[...Ger,"zsh","sudo"],j6r=["curl","wget"],B=new Set([...j6r]),j=[...PKo,...[]];` +
	"function zer(e,r){let o=e.trim();for(let n of r){let s=n;if(o===s)return!0;if(o===`${s}:*`||o===`${s} *`)return!0}return!1}"

func writeBundle(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "claude")
	// Padding on both sides puts the list away from chunk edges.
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 1<<16)+body+strings.Repeat("y", 1<<16)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAutoDropFromBundle(t *testing.T) {
	l := loadAutoDrop(writeBundle(t, fakeBundle), "9.9.9")
	want := []string{"bash", "bun run", "node", "npm run", "pnpm run", "python", "python3", "sh", "sudo", "yarn run", "zsh"}
	if l.Source != "binary" || !slices.Equal(l.Commands, want) {
		t.Fatalf("got %s %v (%s)", l.Source, l.Commands, l.Reason)
	}
	if !strings.Contains(l.Reason, "9.9.9") {
		t.Errorf("reason %q lacks the version", l.Reason)
	}
	// A new release adds a command: the list follows the binary.
	l = loadAutoDrop(writeBundle(t, strings.Replace(fakeBundle, `"sudo"]`, `"sudo","doas"]`, 1)), "10.0.0")
	if !slices.Contains(l.Commands, "doas") || slices.Contains(l.Commands, "curl") {
		t.Errorf("new release: %v", l.Commands)
	}
}

// Anything agentreach cannot verify falls back to the built-in list and says why.
func TestAutoDropFallback(t *testing.T) {
	for name, body := range map[string]string{
		"no list":     `var x=["a","b"];`,
		"no matcher":  strings.Split(fakeBundle, "function")[0],
		"odd element": strings.Replace(fakeBundle, `"zsh"`, `"zsh;rm"`, 1),
	} {
		l := loadAutoDrop(writeBundle(t, body), "9.9.9")
		if l.Source != "built_in" || !slices.Equal(l.Commands, builtinAutoDrop) || l.Reason == "" {
			t.Errorf("%s: %s %q", name, l.Source, l.Reason)
		}
	}
	if l := loadAutoDrop("", ""); l.Source != "built_in" {
		t.Errorf("no binary: %s", l.Source)
	}
}

// A fixture run and a pinned list never read a binary.
func TestAutoDropSourceInSnapshot(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"defaultMode":"auto","allow":["Bash(doas *)"]}}`)
	a := f.agent(f.collectWith(Options{Probe: true}))
	if a.AutoModeDropSource != "built_in" {
		t.Errorf("fixture source %s", a.AutoModeDropSource)
	}
	s := f.collectWith(Options{Probe: true, AutoModeDropCommands: []string{"doas"}})
	if a := f.agent(s); a.AutoModeDropSource != "pinned" {
		t.Errorf("pinned source %s", a.AutoModeDropSource)
	}
	for _, r := range s.SandboxRules {
		if r.Pattern == "Bash(doas *)" && !r.DroppedInAutoMode {
			t.Error("pinned list not applied")
		}
	}
}

// TestAutoDropDrift reads the list from a real Claude Code (a binary,
// cli.js or an installed npm package directory) named by AGENTREACH_CLAUDE_BIN,
// and fails when it cannot be read or differs from the built-in fallback.
// make check-claude-code runs it; so does the weekly claude-code-drift
// workflow against the latest npm release.
func TestAutoDropDrift(t *testing.T) {
	root := os.Getenv("AGENTREACH_CLAUDE_BIN")
	if root == "" {
		t.Skip("set AGENTREACH_CLAUDE_BIN to a Claude Code binary or package directory")
	}
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil && fi.Size() > 1<<20 {
				files = append(files, p)
			}
		}
		return nil
	})
	if fi, err := os.Stat(root); err == nil && !fi.IsDir() {
		files = []string{root}
	}
	for _, p := range files {
		cmds, matcher, err := extractAutoDropFile(p)
		if err != nil {
			continue
		}
		if !matcher {
			t.Fatalf("%s: list found but not the matcher agentreach models; check the matching in droppedInAutoModeWith", p)
		}
		want := slices.Sorted(slices.Values(builtinAutoDrop))
		if !slices.Equal(cmds, want) {
			t.Fatalf("%s: auto mode drop list changed\n got  %v\n want %v\nupdate builtinAutoDrop and builtinAutoDropVersion", p, cmds, want)
		}
		t.Logf("%s: list matches the built-in list (%d commands)", p, len(cmds))
		return
	}
	t.Fatalf("no auto mode drop list found under %s", root)
}

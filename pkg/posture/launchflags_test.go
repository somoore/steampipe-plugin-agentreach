package posture

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchFlagsFromStartupFiles(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".zshrc"), strings.Join([]string{
		`# alias claude="claude --dangerously-skip-permissions"`,
		`alias claude='claude --permission-mode acceptEdits --allowedTools "Bash(git *)" Read'`,
		`alias yolo="claude --dangerously-skip-permissions -p 'fix it'"`,
		`cx() {`,
		`  codex --sandbox danger-full-access -a never -c model="x" "$@"`,
		`}`,
		`function codex { command codex --yolo "$@"; }`,
	}, "\n"))
	s := f.collectWith(Options{Probe: true, Processes: []string{
		"4242 /usr/local/bin/claude --dangerously-skip-permissions",
		"4243 node /x/node_modules/@anthropic-ai/claude-code/cli.js --permission-mode plan",
		"4244 /bin/zsh",
	}})
	got := map[string]LaunchFlag{}
	for _, l := range s.LaunchFlags {
		got[l.Name+" "+l.Flag] = l
		if strings.Contains(l.Value, "fix it") || strings.Contains(l.Value, "git") || l.Value == "x" {
			t.Errorf("value leaked: %+v", l)
		}
	}
	for _, k := range []string{"claude --permission-mode", "claude --allowedTools", "yolo --dangerously-skip-permissions",
		"cx --sandbox", "cx -a", "cx -c", "codex --yolo", "pid 4242 --dangerously-skip-permissions", "pid 4243 --permission-mode"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if l := got["claude --permission-mode"]; !l.Default || l.Value != "acceptEdits" || l.Line != 2 {
		t.Errorf("default alias: %+v", l)
	}
	if got["yolo --dangerously-skip-permissions"].Default || !got["codex --yolo"].Default {
		t.Error("default marks wrong")
	}
	if got["cx -c"].Value != "model" {
		t.Errorf("config key: %q", got["cx -c"].Value)
	}
	a := f.agent(s)
	if a.EffectivePermissionMode != "acceptEdits" || a.PermissionModeSource != "launch_flag" {
		t.Errorf("mode %s from %s", a.EffectivePermissionMode, a.PermissionModeSource)
	}
	if a.RunningBypassSessions != 1 {
		t.Errorf("running bypass %d", a.RunningBypassSessions)
	}
	rules := 0
	for _, r := range s.SandboxRules {
		if r.Scope == "launch_flag" && r.RuleType == "allow" && (r.Pattern == "Bash(git *)" || r.Pattern == "Read") {
			rules++
		}
	}
	if rules != 2 {
		t.Errorf("flag rules %d", rules)
	}
}

func TestLaunchFlagBypass(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".bashrc"), "alias claude='claude --dangerously-skip-permissions'\n")
	a := f.agent(f.collectWith(Options{Probe: true}))
	if a.EffectivePermissionMode != "bypassPermissions" || !a.BypassAvailable || !strings.Contains(a.BypassAvailableReason, ".bashrc:1") {
		t.Errorf("bypass: %s %v %q", a.EffectivePermissionMode, a.BypassAvailable, a.BypassAvailableReason)
	}
	// Project settings do not outrank the flag.
	proj := filepath.Join(f.home, "proj")
	f.write(filepath.Join(proj, ".claude", "settings.local.json"), `{"permissions":{"defaultMode":"default"}}`)
	s := f.collectWith(Options{Probe: true, ProjectDirs: []string{proj}})
	found := false
	for _, p := range s.Projects {
		if p.Agent == AgentClaudeCode && p.ProjectDir == proj {
			found = true
			if p.EffectivePermissionMode != "bypassPermissions" {
				t.Errorf("project mode %s, want bypassPermissions from the flag", p.EffectivePermissionMode)
			}
		}
	}
	if !found {
		t.Error("project row missing")
	}
	// Settings that disable bypass stop the flag too.
	f.write(filepath.Join(f.cfg, "settings.json"), `{"permissions":{"disableBypassPermissionsMode":"disable"}}`)
	a = f.agent(f.collectWith(Options{Probe: true}))
	if a.EffectivePermissionMode == "bypassPermissions" || a.BypassAvailable {
		t.Errorf("disabled bypass still applied: %s %v", a.EffectivePermissionMode, a.BypassAvailable)
	}
}

func TestShellWords(t *testing.T) {
	w := shellWords(`claude --a "b c" && codex -s x; echo 'y z'`)
	want := []string{"claude", "--a", "b c", "&&", "codex", "-s", "x", ";", "echo", "y z"}
	if strings.Join(w, "|") != strings.Join(want, "|") {
		t.Errorf("%q", w)
	}
}

// A default codex alias outranks config files; managed config still wins.
func TestCodexLaunchFlagLayer(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.home, ".codex", "config.toml"), "sandbox_mode = \"read-only\"\n")
	f.write(filepath.Join(f.home, ".zshrc"), "alias codex='codex --yolo'\nalias cx='codex -s workspace-write'\n")
	a := codexAgent(t, f.collect())
	if a.EffectivePermissionMode != "danger-full-access/never" || a.PermissionModeSource != "launch_flag" {
		t.Errorf("codex flags: %s from %s", a.EffectivePermissionMode, a.PermissionModeSource)
	}
	f.write(filepath.Join(f.home, ".zshrc"), "alias codex='codex -c sandbox_mode=workspace-write -c model=x'\n")
	if a := codexAgent(t, f.collect()); a.EffectivePermissionMode != "workspace-write/on-request" {
		t.Errorf("-c override: %s", a.EffectivePermissionMode)
	}
}

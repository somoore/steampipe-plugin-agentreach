package posture

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// The sandbox model. Everything here encodes documented Claude Code
// behaviour; each rule cites the sentence it relies on. The model is
// agentreach's inference, so every column it feeds carries evidence "inferred".
//
// Source: https://code.claude.com/docs/en/sandboxing
//
//   "The sandbox covers shell commands only. Claude's file tools, MCP
//    servers, and hooks run outside it."
//   "By default, if the sandbox can't start because a dependency is missing
//    or the platform is unsupported, Claude Code runs commands without
//    sandboxing. To make Claude Code exit at startup instead, set
//    sandbox.failIfUnavailable to true."
//   "You can disable the unsandboxed retry by setting
//    "allowUnsandboxedCommands": false ... While the sandbox is running,
//    commands Claude runs are then sandboxed unless they match an
//    excludedCommands entry."
//   "When read rules overlap, the rule with the narrower path applies."
//   "If you or your administrator disable the retry in managed settings ...
//    Claude Code then ignores the settings in a repository's files that
//    loosen the sandbox, excludedCommands entries included."

type sandboxPosture struct {
	allowUnsandboxed  bool
	failIfUnavailable bool
	fsDisabled        bool
	runtimeAvailable  *bool
	excluded          int
	adminRequired     bool
	blockReads        bool // permissions.blockReadsOutsideWorkingDirectories true in managed or user settings
	managedReadOnly   bool // sandbox.filesystem.allowManagedReadPathsOnly
}

// sandboxRuntimeAvailable checks for the OS sandbox the docs name: Seatbelt
// (sandbox-exec) on macOS, bubblewrap and socat on Linux. It runs nothing.
func sandboxRuntimeAvailable(goos string) *bool {
	var ok bool
	switch goos {
	case "darwin":
		_, err := os.Stat("/usr/bin/sandbox-exec")
		ok = err == nil
	case "linux":
		_, e1 := exec.LookPath("bwrap")
		_, e2 := exec.LookPath("socat")
		ok = e1 == nil && e2 == nil
	default:
		ok = false // "The sandbox doesn't run on native Windows"
	}
	return &ok
}

// managedThenUser returns the managed value of a Boolean key, else the user
// value, else def. "When managed settings set a Boolean key such as enabled
// or failIfUnavailable, Claude Code uses the managed value."
func (c *ccCollector) managedThenUser(def bool, keys ...string) bool {
	if b := getBool(c.managed, keys...); b != nil {
		return *b
	}
	if b := getBool(c.user, keys...); b != nil {
		return *b
	}
	return def
}

func (c *ccCollector) computeSandboxPosture() {
	s := sandboxPosture{}
	s.allowUnsandboxed = c.managedThenUser(true, "sandbox", "allowUnsandboxedCommands")
	s.failIfUnavailable = c.managedThenUser(false, "sandbox", "failIfUnavailable")
	s.fsDisabled = c.managedThenUser(false, "sandbox", "filesystem", "disabled")
	if b := getBool(c.managed, "sandbox", "allowUnsandboxedCommands"); b != nil && !*b {
		s.adminRequired = true
	}
	// permissions.blockReadsOutsideWorkingDirectories: "A true in any file
	// applies, so a repository can turn the block on for itself but can't
	// lift yours." Machine-wide, only managed and user count.
	for _, m := range []map[string]any{c.managed, c.user} {
		if b := getBool(m, "permissions", "blockReadsOutsideWorkingDirectories"); b != nil && *b {
			s.blockReads = true
		}
	}
	if b := getBool(c.managed, "sandbox", "filesystem", "allowManagedReadPathsOnly"); b != nil && *b {
		s.managedReadOnly = true
	}
	for _, r := range c.snap.SandboxRules {
		if r.RuleType != "excludedCommands" {
			continue
		}
		if s.adminRequired && r.Scope != "managed" && r.Scope != "user" {
			continue // ignored under an admin-required sandbox
		}
		s.excluded++
	}
	if c.sandboxEnabled {
		if c.opts.SandboxRuntime != nil {
			v := *c.opts.SandboxRuntime
			s.runtimeAvailable = &v
		} else {
			s.runtimeAvailable = sandboxRuntimeAvailable(c.opts.goos())
		}
	}
	c.sb = s
}

// sandboxActive reports whether shell commands started in projectDir run
// sandboxed with filesystem isolation. A missing runtime with
// failIfUnavailable means Claude Code does not start, so nothing runs.
func (c *ccCollector) sandboxActive(projectDir string) bool {
	if !c.sandboxEnabledIn(projectDir) || c.sb.fsDisabled {
		return false
	}
	if c.sb.runtimeAvailable != nil && !*c.sb.runtimeAvailable && !c.sb.failIfUnavailable {
		return false
	}
	return true
}

// sandboxEnforced is the agent-level verdict: on, no retry escape hatch,
// and no silent fallback to unsandboxed execution.
func (c *ccCollector) sandboxEnforced() bool {
	// Enforced means enabled with no route around it: every bypass that
	// sandboxBypasses names lets some command run unsandboxed or unfenced.
	return c.sandboxEnabled && c.sandboxBypasses() == ""
}

// sandboxBypasses lists the routes by which a shell command can still run
// outside the sandbox while it is enabled.
func (c *ccCollector) sandboxBypasses() string {
	if !c.sandboxEnabled {
		return ""
	}
	var b []string
	if c.sb.allowUnsandboxed {
		b = append(b, "unsandboxed_retry")
	}
	if c.sb.excluded > 0 {
		b = append(b, "excluded_commands")
	}
	if c.sb.runtimeAvailable != nil && !*c.sb.runtimeAvailable && !c.sb.failIfUnavailable {
		b = append(b, "runtime_missing")
	}
	if c.sb.fsDisabled {
		b = append(b, "filesystem_disabled")
	}
	return strings.Join(b, ",")
}

// narrowestCover returns the rule covering path with the longest resolved
// pattern, and that length.
func narrowestCover(rules []scopedRule, path, projectDir string, ok func(scopedRule) bool) (scopedRule, int) {
	best, bestLen := scopedRule{}, -1
	for _, d := range rules {
		if d.ProjectDir != "" && d.ProjectDir != projectDir {
			continue
		}
		if ok != nil && !ok(d) {
			continue
		}
		res := withCwd(d.Resolved, projectDir)
		if covers(res, path) && len(res) > bestLen {
			best, bestLen = d, len(res)
		}
	}
	return best, bestLen
}

// sandboxReadDecision decides whether the sandbox blocks a shell read of
// path. It returns the deny rule that blocks it ("" when open) and the
// allowRead rule that re-opened it, if any.
//
// Locks: "filesystem.denyRead, a Read(...) deny rule, or a credentials.files
// entry" in managed or user settings cannot be re-opened by "an allowRead
// ... entry" from a repository. With allowManagedReadPathsOnly only managed
// allowRead entries count.
func (c *ccCollector) sandboxReadDecision(path, projectDir string) (deny, allow string) {
	d, dl := narrowestCover(c.sandboxDenyRead, path, projectDir, nil)
	if dl < 0 {
		if c.sb.blockReads && projectDir == "" {
			return "permissions.blockReadsOutsideWorkingDirectories", ""
		}
		return "", ""
	}
	a, al := narrowestCover(c.sandboxAllowRead, path, projectDir, func(r scopedRule) bool {
		if c.sb.managedReadOnly && r.Scope != "managed" {
			return false
		}
		if machineScope(d.Scope) && !machineScope(r.Scope) {
			return false
		}
		return true
	})
	if al > dl {
		if c.sb.blockReads && projectDir == "" {
			return "permissions.blockReadsOutsideWorkingDirectories", a.Pattern
		}
		return "", a.Pattern
	}
	return d.Pattern, ""
}

// effectiveMode resolves the permission mode a terminal session starts in.
//
// Source: https://code.claude.com/docs/en/permission-modes, "permissions.
// defaultMode in a settings file", then "The built-in default": "Any
// settings file sets disableAutoMode to "disable"" gives default; "In a
// terminal ... auto with Claude Code v2.1.283 or later; on earlier versions,
// auto on Pro, Max, or Team plans ... and default otherwise".
func (c *ccCollector) effectiveMode(version string) (mode, source string) {
	if m := getString(c.managed, "permissions", "defaultMode"); m != "" {
		return m, "managed"
	}
	if m := getString(c.user, "permissions", "defaultMode"); m != "" {
		return m, "user"
	}
	return c.builtInModeFor(version)
}

// builtInMode is the built-in default for the detected version.
func (c *ccCollector) builtInMode() (string, string) { return c.builtInModeFor(c.version) }

func (c *ccCollector) builtInModeFor(version string) (string, string) {
	for _, m := range []map[string]any{c.managed, c.user} {
		if getString(m, "disableAutoMode") == "disable" {
			return "default", "built_in"
		}
	}
	// The built-in default changed in v2.1.283; without a version it is
	// unknown, not default.
	if strings.TrimSpace(version) == "" {
		return "unknown", "unknown"
	}
	if versionAtLeast(version, 2, 1, 283) {
		return "auto", "built_in"
	}
	return "default", "built_in"
}

// versionAtLeast compares a dotted version such as 2.1.312.
func versionAtLeast(v string, want ...int) bool {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	for i, w := range want {
		if i >= len(parts) {
			return false
		}
		n, err := strconv.Atoi(strings.TrimFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
		if err != nil {
			return false
		}
		if n != w {
			return n > w
		}
	}
	return true
}

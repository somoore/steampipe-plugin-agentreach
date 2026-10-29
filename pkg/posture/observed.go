package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Observed mode. Verified against @anthropic-ai/sandbox-runtime 0.0.81
// (npm; github.com/anthropics/sandbox-runtime): `srt --settings <path> --
// <command...>` and the settings keys in srtSettings match its README.
//
// The modelled columns (reachable_via_bash) are agentreach's
// re-implementation of Claude Code's sandbox rules, which can drift with
// every release. Observed mode runs the same inert probes inside Anthropic's
// sandbox runtime, srt (https://github.com/anthropic-experimental/
// sandbox-runtime), configured with agentreach's translation of the effective
// machine-wide settings, and reports the result next to the model. When the
// two disagree, either the model or the translation is wrong.
//
// What it is not: a probe inside the agent's own session. srt is the
// runtime Claude Code's sandbox is built on, but agentreach writes the srt
// settings itself, so the result is "observed under agentreach's translation".
//
// Safety: srt always gets --settings <temp file>, so ~/.srt-settings.json is
// never read or created. The probe script reads at most one byte of each
// file into /dev/null, lists directories into /dev/null, and opens and
// closes loopback TCP connections; it prints only 0 or 1 per probe, plus a
// listed directory's device and inode. On Linux srt hides a denied
// directory by mounting an empty one over it, so listing succeeds; a
// different device or inode inside the sandbox means the real directory
// is hidden.

const probeScript = `for p in "$@"; do
  case "$p" in
    tcp:*) hp=${p#tcp:}; h=${hp%:*}; port=${hp##*:}
      (exec 3<>"/dev/tcp/$h/$port") >/dev/null 2>&1 && echo 1 || echo 0 ;;
    *) if [ -d "$p" ]; then
         if ls "$p" >/dev/null 2>&1; then
           id=$(stat -c %d:%i "$p" 2>/dev/null || stat -f %d:%i "$p" 2>/dev/null)
           echo "1:${id:-?}"
         else echo 0; fi
       else head -c 1 "$p" >/dev/null 2>&1 && echo 1 || echo 0; fi ;;
  esac
done`

type srtSettings struct {
	Network struct {
		AllowedDomains      []string `json:"allowedDomains"`
		DeniedDomains       []string `json:"deniedDomains"`
		AllowUnixSockets    []string `json:"allowUnixSockets"`
		AllowAllUnixSockets bool     `json:"allowAllUnixSockets,omitempty"`
		AllowLocalBinding   bool     `json:"allowLocalBinding"`
	} `json:"network"`
	Filesystem struct {
		DenyRead   []string `json:"denyRead"`
		AllowRead  []string `json:"allowRead"`
		AllowWrite []string `json:"allowWrite"`
		DenyWrite  []string `json:"denyWrite"`
	} `json:"filesystem"`
}

// srtTranslation builds srt settings from the machine-wide (managed and
// user) rules. Project-scoped rules are not included; project files are
// therefore not observed.
func (c *ccCollector) srtTranslation() srtSettings {
	var s srtSettings
	s.Network.AllowedDomains = append([]string{}, c.allowedDomains...)
	for _, m := range []map[string]any{c.managed, c.user} {
		s.Network.DeniedDomains = append(s.Network.DeniedDomains, toStringSlice(getMap(m, "sandbox", "network")["deniedDomains"])...)
	}
	s.Network.AllowUnixSockets = append([]string{}, c.allowUnixSocks...)
	s.Network.AllowAllUnixSockets = c.allowAllUnix
	// Same key and meaning in Claude Code (settings-reference,
	// sandbox.network.allowLocalBinding) and srt 0.0.81 (README,
	// network.allowLocalBinding): on macOS it allows direct loopback dials;
	// on Linux srt ignores it.
	s.Network.AllowLocalBinding = c.allowLocalBind
	for _, r := range c.sandboxDenyRead {
		if r.ProjectDir == "" && !strings.HasPrefix(r.Resolved, "<cwd>") {
			s.Filesystem.DenyRead = append(s.Filesystem.DenyRead, r.Resolved)
		}
	}
	for _, r := range c.sandboxAllowRead {
		if r.ProjectDir == "" && !strings.HasPrefix(r.Resolved, "<cwd>") && (!c.sb.managedReadOnly || r.Scope == "managed") {
			s.Filesystem.AllowRead = append(s.Filesystem.AllowRead, r.Resolved)
		}
	}
	if c.sb.blockReads {
		// Approximation of the read block for home-directory files.
		s.Filesystem.DenyRead = append(s.Filesystem.DenyRead, c.home)
	}
	s.Filesystem.AllowWrite = []string{}
	s.Filesystem.DenyWrite = []string{}
	if s.Network.AllowedDomains == nil {
		s.Network.AllowedDomains = []string{}
	}
	if s.Network.DeniedDomains == nil {
		s.Network.DeniedDomains = []string{}
	}
	if s.Network.AllowUnixSockets == nil {
		s.Network.AllowUnixSockets = []string{}
	}
	if s.Filesystem.DenyRead == nil {
		s.Filesystem.DenyRead = []string{}
	}
	if s.Filesystem.AllowRead == nil {
		s.Filesystem.AllowRead = []string{}
	}
	return s
}

func (c *ccCollector) observe(ctx context.Context) {
	srt := c.opts.SRTPath
	if srt == "" && c.opts.Home != "" {
		// A fixture run never uses whatever srt happens to be on PATH; the
		// test names the binary it means.
		c.snap.Observed, c.snap.ObservedTool = false, "srt (skipped: fixture home without SRTPath)"
		return
	}
	if srt == "" {
		if p, err := exec.LookPath("srt"); err == nil {
			srt = p
		}
	}
	if srt == "" {
		c.snap.Errors = append(c.snap.Errors, "observed mode: srt not found; install @anthropic-ai/sandbox-runtime or pass its path")
		return
	}
	if !c.sandboxEnabled {
		for i := range c.snap.ReachFiles {
			if c.snap.ReachFiles[i].Agent == AgentClaudeCode {
				c.snap.ReachFiles[i].ObservedMethod = "not observed: the sandbox is off, so shell reads are not sandboxed"
			}
		}
		c.snap.Observed, c.snap.ObservedTool = true, "srt (skipped: sandbox off)"
		return
	}
	version := "srt"
	vctx, vcancel := context.WithTimeout(ctx, 10*time.Second)
	if out, err := exec.CommandContext(vctx, srt, "--version").Output(); err == nil {
		version = "srt " + strings.TrimSpace(string(out))
	}
	vcancel()

	dir, err := os.MkdirTemp("", "agentreach-srt-")
	if err != nil {
		c.snap.Errors = append(c.snap.Errors, "observed mode: "+err.Error())
		return
	}
	defer os.RemoveAll(dir)
	settings := filepath.Join(dir, "srt-settings.json")
	b, _ := json.MarshalIndent(c.srtTranslation(), "", "  ")
	if err := os.WriteFile(settings, b, 0o600); err != nil {
		c.snap.Errors = append(c.snap.Errors, "observed mode: "+err.Error())
		return
	}

	type target struct {
		file int // index into ReachFiles, or -1
		host int // index into ReachHosts, or -1
		arg  string
	}
	var targets []target
	for i, f := range c.snap.ReachFiles {
		if f.Agent != AgentClaudeCode {
			continue
		}
		if f.ProjectDir != "" {
			c.snap.ReachFiles[i].ObservedMethod = "not observed: project-scoped rules are not translated"
			continue
		}
		targets = append(targets, target{file: i, host: -1, arg: f.Path})
	}
	for i, h := range c.snap.ReachHosts {
		if h.Agent == AgentClaudeCode && h.Kind == "tcp" && h.Loopback && h.Reachable != nil && *h.Reachable {
			port := h.Target[strings.LastIndex(h.Target, ":")+1:]
			targets = append(targets, target{file: -1, host: i, arg: "tcp:127.0.0.1:" + port})
		}
	}
	if len(targets) == 0 {
		return
	}
	args := []string{"--settings", settings, "--", "/bin/bash", "-c", probeScript, "agentreach-probe"}
	for _, t := range targets {
		args = append(args, t.arg)
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, srt, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		c.snap.Errors = append(c.snap.Errors, "observed mode: srt run failed: "+err.Error())
		return
	}
	lines := strings.Fields(out.String())
	if len(lines) != len(targets) {
		c.snap.Errors = append(c.snap.Errors, "observed mode: expected "+strconv.Itoa(len(targets))+" results from srt, got "+strconv.Itoa(len(lines)))
		return
	}
	c.snap.Observed, c.snap.ObservedTool = true, version
	for i, t := range targets {
		ok := lines[i] == "1"
		if id, isDir := strings.CutPrefix(lines[i], "1:"); isDir && t.file >= 0 {
			// A directory: readable only if it is the same directory.
			outside := devIno(c.snap.ReachFiles[t.file].Path)
			ok = id != "?" && outside != "" && id == outside
		}
		v := ok
		if t.file >= 0 {
			f := &c.snap.ReachFiles[t.file]
			f.ObservedViaSandbox, f.ObservedMethod = &v, version+" with agentreach's translation of managed and user settings"
			if open, known := c.modelOpen[f.Path]; known {
				agree := open == ok
				f.ModelAgrees = &agree
			}
		} else {
			h := &c.snap.ReachHosts[t.host]
			h.ObservedViaSandbox, h.ObservedMethod = &v, version
		}
	}
}

package posture

import (
	"os"
	"path/filepath"
	"strings"
)

// Codex write targets. Facts:
//
//   - workspace-write: "The workspace includes the current directory and
//     temporary directories like /tmp"
//     (https://learn.chatgpt.com/docs/agent-approvals-security), plus
//     sandbox_workspace_write.writable_roots; $TMPDIR and /tmp unless
//     exclude_tmpdir_env_var / exclude_slash_tmp (config reference).
//     read-only writes nothing; danger-full-access has no sandbox.
//   - Protected inside writable roots (0.155.1 protocol/src/permissions.rs
//     PROTECTED_METADATA_PATH_NAMES): .git as a directory or file (and the
//     gitdir a .git file points to), .agents when it exists as a directory,
//     .codex always in the primary root and in other roots when it exists.
//     Protection is recursive. The docs also list .aws, which 0.155.1 does
//     not have.
//   - File edits (apply_patch, core/src/safety.rs assess_patch_safety): an
//     untrusted project asks every time; a patch inside writable paths is
//     auto-approved; otherwise never and granular without sandbox_approval
//     reject it and the rest ask.
//
// Exec-policy allow rules are not counted for writes (an allowed command
// may or may not write the target).

type codexWriteSpec struct{ rel, category string }

var codexHomeWriteTargets = []codexWriteSpec{
	{"config.toml", "guardrail"}, {"hooks.json", "guardrail"}, {"rules", "guardrail"},
	{"AGENTS.md", "instruction"}, {"AGENTS.override.md", "instruction"}, {"skills", "instruction"},
}

var codexProjectWriteTargets = []codexWriteSpec{
	{".codex/config.toml", "guardrail"}, {".codex/hooks.json", "guardrail"}, {".codex/rules", "guardrail"},
	{"AGENTS.md", "instruction"}, {"AGENTS.override.md", "instruction"},
	{".codex/skills", "instruction"}, {".agents/skills", "instruction"},
}

// codexOtherTargets are the agent-neutral entries of the Claude Code lists:
// shell startup, git, CI, manifests, devcontainer.
func codexOtherTargets(list []writeSpec) []codexWriteSpec {
	var out []codexWriteSpec
	for _, s := range list {
		r := strings.TrimPrefix(s.rel, "~/")
		if strings.HasPrefix(r, ".claude") || strings.HasPrefix(r, "CLAUDE") || r == ".mcp.json" || r == "AGENTS.md" {
			continue
		}
		out = append(out, codexWriteSpec{r, s.category})
	}
	return out
}

type codexRoot struct {
	dir, rule string
	primary   bool
}

// codexWriteRule returns where a shell write to path is decided: the
// writable root that allows it, or the protected path that refuses it
// ("" when no root covers it).
func (x *codexScan) codexWriteRule(path, cwd string, g codexGate) (rule string, allowed bool) {
	var roots []codexRoot
	if cwd != "" {
		roots = append(roots, codexRoot{cwd, "cwd", true})
	}
	for _, r := range g.WritableRoots {
		r = filepath.Clean(expandHome(r, x.home))
		roots = append(roots, codexRoot{r, "writable_roots: " + r, false})
	}
	// A fixture home lives under the temp directory; tmp roots would make
	// every fixture file writable and differ between machines.
	if x.opts.Home == "" {
		if t := os.Getenv("TMPDIR"); t != "" && !g.ExcludeTmpdir {
			roots = append(roots, codexRoot{filepath.Clean(t), "TMPDIR", false})
		}
		if !g.ExcludeSlashTmp {
			roots = append(roots, codexRoot{"/tmp", "/tmp", false})
		}
	}
	var in *codexRoot
	for i := range roots {
		r := roots[i]
		if !covers(r.dir, path) {
			continue
		}
		if in == nil {
			in = &roots[i]
		}
		for _, n := range []string{".git", ".agents", ".codex"} {
			pp := filepath.Join(r.dir, n)
			fi, err := os.Stat(pp)
			protected := false
			switch n {
			case ".git":
				protected = err == nil
				if err == nil && !fi.IsDir() {
					if b, e := readFileLimited(pp); e == nil {
						if s, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:"); ok {
							gd := strings.TrimSpace(s)
							if !filepath.IsAbs(gd) {
								gd = filepath.Join(r.dir, gd)
							}
							if covers(filepath.Clean(gd), path) {
								return "protected: " + filepath.Clean(gd), false
							}
						}
					}
				}
			case ".agents":
				protected = err == nil && fi.IsDir()
			case ".codex":
				protected = r.primary || (err == nil && fi.IsDir())
			}
			if protected && covers(pp, path) {
				return "protected: " + pp, false
			}
		}
	}
	if in == nil {
		return "", false
	}
	return in.rule, true
}

// codexPatchGate mirrors assess_patch_safety, in edit_tool_approval words.
func codexPatchGate(g codexGate, writable bool) string {
	switch {
	case g.Unknown != "":
		return "unknown"
	case g.Approval == "untrusted":
		return "prompt"
	case writable:
		return "allowed"
	case g.Approval == "never", g.Approval == "granular" && !g.SandboxApproval:
		return "denied"
	}
	return "prompt"
}

func (x *codexScan) codexWriteRow(path, category, projectDir, cwd string, g codexGate) (WriteTarget, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return WriteTarget{}, false
	}
	w := WriteTarget{Agent: AgentCodex, Path: path, Category: category, ProjectDir: projectDir, IsDir: fi.IsDir(),
		WritableEvidence: EvidenceUnknown, WriteEvidence: EvidenceUnknown}
	inSandbox := false
	switch g.Sandbox {
	case "danger-full-access":
		inSandbox = true
	case "workspace-write":
		rule, ok := x.codexWriteRule(path, cwd, g)
		w.SandboxWriteRule, inSandbox = rule, ok
		w.SandboxProtected = strings.HasPrefix(rule, "protected: ")
	}
	if g.Unknown != "" {
		inSandbox = false
	}
	w.EditToolApproval = codexPatchGate(g, inSandbox)
	if !x.opts.Probe {
		return w, true
	}
	w.WritableByUser = accessWritable(path)
	w.WritableEvidence, w.WriteEvidence = EvidenceObserved, EvidenceInferred
	bash := inSandbox && *w.WritableByUser
	if !inSandbox {
		w.BashBypass = g.bypasses()
	}
	w.WritableViaBash = &bash
	return w, true
}

func (x *codexScan) writeTargets() {
	home := func() []codexWriteSpec {
		var out []codexWriteSpec
		for _, s := range codexHomeWriteTargets {
			out = append(out, codexWriteSpec{filepath.Join(x.dir, s.rel), s.category})
		}
		out = append(out, codexWriteSpec{filepath.Join(x.home, ".agents", "skills"), "instruction"})
		for _, s := range codexOtherTargets(homeWriteTargets) {
			out = append(out, codexWriteSpec{filepath.Join(x.home, s.rel), s.category})
		}
		return out
	}()
	// The machine-wide session: a directory with no trust decision.
	machine := map[string]WriteTarget{}
	for _, s := range home {
		if w, ok := x.codexWriteRow(s.rel, s.category, "", "", x.g); ok {
			machine[w.Path] = w
			x.snap.WriteTargets = append(x.snap.WriteTargets, w)
		}
	}
	project := append(append([]codexWriteSpec{}, codexProjectWriteTargets...), codexOtherTargets(projectWriteTargets)...)
	for i, p := range x.sorted {
		if _, known := x.projects[p]; !known || !dirExists(p) || filepath.Clean(p) == filepath.Clean(x.home) {
			continue
		}
		g := x.gates[i]
		// Home files under this project's gates, when they differ.
		for _, s := range home {
			w, ok := x.codexWriteRow(s.rel, s.category, "", p, g)
			if !ok {
				continue
			}
			mw := machine[w.Path]
			if w.EditToolApproval == mw.EditToolApproval && boolOf(w.WritableViaBash) == boolOf(mw.WritableViaBash) &&
				w.BashBypass == mw.BashBypass && g.Shell == x.g.Shell {
				continue
			}
			w.SessionDir = p
			x.snap.WriteTargets = append(x.snap.WriteTargets, w)
		}
		for _, s := range project {
			if w, ok := x.codexWriteRow(filepath.Join(p, s.rel), s.category, p, p, g); ok {
				w.SessionDir = p
				x.snap.WriteTargets = append(x.snap.WriteTargets, w)
			}
		}
	}
}

func boolOf(b *bool) bool { return b != nil && *b }

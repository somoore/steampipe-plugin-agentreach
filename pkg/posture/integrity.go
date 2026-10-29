package posture

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Integrity: can the agent change its own guardrails, the instructions it
// obeys, what CI runs, what the project depends on, or what runs in the
// developer's shell? WriteTarget rows answer that per file with agentreach's
// model of Claude Code's two write layers.
//
// Sandbox layer, https://code.claude.com/docs/en/sandboxing, "Protected
// paths": "Inside the directories that sandboxed commands can write to, the
// sandbox still denies writes to the files Claude Code loads configuration
// and code from." Groups: in the working directory and above it, "the
// .claude settings files, the .claude/skills, .claude/agents,
// .claude/commands, and .claude/hooks directories, .mcp.json"; in the
// working directory only, "shell startup files such as .bashrc and .zshrc,
// .gitconfig, the .vscode and .idea directories, and hooks and config inside
// .git"; and "In ~/.claude ... most of its contents, plus ~/.claude.json".
// Default writable set: "the working directory, a per-user temp directory,
// and directories you've added".
//
// Permission layer, https://code.claude.com/docs/en/permission-modes,
// "Protected paths": writes are "Prompted" in default and acceptEdits,
// "Routed to the classifier" in auto, "Denied" in dontAsk, "Allowed" in
// bypassPermissions, for .git, .config/git, .vscode, .idea, .husky, .cargo,
// .devcontainer, .yarn, .mvn and .claude. "permissions.allow rules in
// settings files do not pre-approve protected-path writes." Outside the
// protected set, acceptEdits and auto approve "file edits in your working
// directory".

type writeSpec struct {
	rel      string
	category string
}

var homeWriteTargets = []writeSpec{
	{"~/.claude/settings.json", "guardrail"},
	{"~/.claude.json", "guardrail"},
	{"~/.claude/CLAUDE.md", "instruction"},
	{"~/.claude/rules", "instruction"},
	{"~/.claude/skills", "instruction"},
	{"~/.claude/agents", "instruction"},
	{"~/.claude/commands", "instruction"},
	{"~/.zshrc", "shell_startup"},
	{"~/.zshenv", "shell_startup"},
	{"~/.zprofile", "shell_startup"},
	{"~/.bashrc", "shell_startup"},
	{"~/.bash_profile", "shell_startup"},
	{"~/.profile", "shell_startup"},
	{"~/.gitconfig", "git_hooks"},
}

var projectWriteTargets = []writeSpec{
	{".claude/settings.json", "guardrail"},
	{".claude/settings.local.json", "guardrail"},
	{".mcp.json", "guardrail"},
	{".claude/hooks", "guardrail"},
	{"CLAUDE.md", "instruction"},
	{"CLAUDE.local.md", "instruction"},
	{"AGENTS.md", "instruction"},
	{".claude/CLAUDE.md", "instruction"},
	{".claude/rules", "instruction"},
	{".claude/skills", "instruction"},
	{".claude/agents", "instruction"},
	{".claude/commands", "instruction"},
	{".github/workflows", "ci_workflow"},
	{".gitlab-ci.yml", "ci_workflow"},
	{".circleci", "ci_workflow"},
	{".buildkite", "ci_workflow"},
	{"Jenkinsfile", "ci_workflow"},
	{"azure-pipelines.yml", "ci_workflow"},
	{"bitbucket-pipelines.yml", "ci_workflow"},
	{"package.json", "dependency_manifest"},
	{"package-lock.json", "dependency_manifest"},
	{"pnpm-lock.yaml", "dependency_manifest"},
	{"yarn.lock", "dependency_manifest"},
	{"go.mod", "dependency_manifest"},
	{"go.sum", "dependency_manifest"},
	{"requirements.txt", "dependency_manifest"},
	{"pyproject.toml", "dependency_manifest"},
	{"uv.lock", "dependency_manifest"},
	{"poetry.lock", "dependency_manifest"},
	{"Cargo.toml", "dependency_manifest"},
	{"Cargo.lock", "dependency_manifest"},
	{"Gemfile.lock", "dependency_manifest"},
	{".npmrc", "dependency_manifest"},
	{".git/hooks", "git_hooks"},
	{".git/config", "git_hooks"},
	{".husky", "git_hooks"},
	{".devcontainer", "devcontainer"},
	{".envrc", "shell_startup"},
}

// sandboxProtectedRel is the working-directory-and-above group plus the
// working-directory-only group, relative to a project root.
var sandboxProtectedRel = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/skills", ".claude/agents",
	".claude/commands", ".claude/hooks", ".mcp.json", ".claude/workflows", ".claude/scheduled_tasks.json",
	".bashrc", ".zshrc", ".bash_profile", ".profile", ".zprofile", ".zshenv", ".gitconfig",
	".vscode", ".idea", ".git/hooks", ".git/config",
}

var permissionProtectedDirs = []string{".git", ".config/git", ".vscode", ".idea", ".husky", ".cargo", ".devcontainer", ".yarn", ".mvn", ".claude"}

// permissionProtectedFiles are protected by name wherever they sit
// (permission-modes, "Protected files").
var permissionProtectedFiles = map[string]bool{
	".gitconfig": true, ".gitmodules": true,
	".bashrc": true, ".bash_profile": true, ".bash_login": true, ".bash_aliases": true, ".bash_logout": true,
	".zshrc": true, ".zprofile": true, ".zshenv": true, ".zlogin": true, ".zlogout": true, ".profile": true, ".envrc": true,
	".npmrc": true, ".yarnrc": true, ".yarnrc.yml": true, ".pnp.cjs": true, ".pnp.loader.mjs": true, ".pnpmfile.cjs": true, "bunfig.toml": true, ".bunfig.toml": true,
	".bazelrc": true, ".bazelversion": true, ".bazeliskrc": true,
	".pre-commit-config.yaml": true, "lefthook.yml": true, "lefthook.yaml": true, ".lefthook.yml": true, ".lefthook.yaml": true,
	"gradle-wrapper.properties": true, "maven-wrapper.properties": true,
	".devcontainer.json": true, ".ripgreprc": true, "pyrightconfig.json": true,
	".mcp.json": true, ".claude.json": true,
}

func accessWritable(p string) *bool {
	ok := syscall.Access(p, 2) == nil // W_OK; nothing is opened or written
	return &ok
}

func (c *ccCollector) sandboxProtected(path, projectDir string) bool {
	if path == c.globalPath || covers(c.configDir, path) {
		return true
	}
	if projectDir == "" {
		return false
	}
	for _, rel := range sandboxProtectedRel {
		if covers(filepath.Join(projectDir, rel), path) {
			return true
		}
	}
	return false
}

func permissionProtected(path, home, projectDir string) bool {
	if permissionProtectedFiles[filepath.Base(path)] {
		return true
	}
	for _, base := range []string{projectDir, home} {
		if base == "" {
			continue
		}
		for _, d := range permissionProtectedDirs {
			if covers(filepath.Join(base, d), path) {
				return true
			}
		}
	}
	return false
}

// projectSettings are the project's local and shared settings documents.
func (c *ccCollector) projectSettings(dir string) []map[string]any {
	return []map[string]any{
		c.doc(filepath.Join(dir, ".claude/settings.local.json")),
		c.doc(filepath.Join(dir, ".claude/settings.json")),
	}
}

// projectMode is the permission mode a session in projectDir starts in.
func (c *ccCollector) projectMode(projectDir string) string {
	m, _ := c.projectModeSource(projectDir)
	return m
}

// projectModeSource follows permission-modes, "Which mode a session starts
// in": managed defaultMode wins; then local, then project; "auto" in those
// two files does not take effect and the built-in default applies (not the
// user value); "bypassPermissions" there starts the session in Manual mode;
// then the user value; then the built-in default.
func (c *ccCollector) projectModeSource(projectDir string) (string, string) {
	if projectDir == "" || c.effModeSource == "managed" {
		return c.effMode, c.effModeSource
	}
	// A flag on the default claude command outranks every settings file;
	// only a disableBypassPermissionsMode lock in the project stops bypass.
	if c.effModeSource == "launch_flag" {
		if c.effMode == "bypassPermissions" {
			if ok, why := c.bypassAvailable(projectDir); !ok && strings.Contains(why, "disableBypassPermissionsMode") {
				return "default", "launch_flag"
			}
		}
		return c.effMode, c.effModeSource
	}
	for _, s := range []struct{ f, scope string }{{".claude/settings.local.json", "local"}, {".claude/settings.json", "project"}} {
		switch m := getString(c.doc(filepath.Join(projectDir, s.f)), "permissions", "defaultMode"); m {
		case "":
			continue
		case "auto":
			return c.builtInMode()
		case "bypassPermissions":
			return "default", s.scope
		default:
			return m, s.scope
		}
	}
	return c.effMode, c.effModeSource
}

// hasProjectEditRules reports whether the project's own settings carry
// Edit rules or sandbox write rules, which change home-file write gates in
// its sessions.
func (c *ccCollector) hasProjectEditRules(dir string) bool {
	for _, rs := range [][]scopedRule{c.editDeny, c.editAllow, c.sandboxAllowWrite, c.sandboxDenyWrite} {
		for _, r := range rs {
			if r.ProjectDir == dir {
				return true
			}
		}
	}
	return false
}

func editApproval(mode string, protected, inWorkDir, allowRule bool) string {
	switch mode {
	case "", "unknown":
		return "unknown"
	case "bypassPermissions":
		return "allowed"
	case "dontAsk":
		if allowRule && !protected {
			return "auto"
		}
		return "denied"
	}
	if protected {
		if mode == "auto" {
			return "classifier"
		}
		return "prompt"
	}
	if allowRule {
		return "auto"
	}
	switch mode {
	case "acceptEdits":
		if inWorkDir {
			return "auto"
		}
		return "prompt"
	case "auto":
		if inWorkDir {
			return "auto"
		}
		return "classifier"
	}
	return "prompt"
}

func (c *ccCollector) writeTargetRow(path, category, projectDir string, probe bool) (WriteTarget, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return WriteTarget{}, false
	}
	w := WriteTarget{Agent: AgentClaudeCode, Path: path, Category: category, ProjectDir: projectDir, IsDir: fi.IsDir(),
		WritableEvidence: EvidenceUnknown, WriteEvidence: EvidenceUnknown}
	w.SandboxProtected = c.sandboxProtected(path, projectDir)
	w.PermissionProtected = permissionProtected(path, c.home, projectDir)
	w.EditDenyRule = ruleCovers(c.editDeny, path, projectDir)
	w.EditAllowRule = ruleCovers(c.editAllow, path, projectDir)
	inWork := projectDir != "" && covers(projectDir, path)
	mode := c.projectMode(projectDir)
	if ok, _ := c.bypassAvailable(projectDir); ok && mode == "plan" {
		// Plan mode with bypass available does not enforce its blocks; protected
		// paths are not auto-approved "except in bypassPermissions mode and in
		// plan-mode sessions where bypass permissions are available".
		mode = "bypassPermissions"
	}
	if w.EditDenyRule != "" {
		w.EditToolApproval = "denied"
	} else {
		w.EditToolApproval = editApproval(mode, w.PermissionProtected, inWork, w.EditAllowRule != "")
	}
	if !probe {
		return w, true
	}
	w.WritableByUser = accessWritable(path)
	w.WritableEvidence, w.WriteEvidence = EvidenceObserved, EvidenceInferred
	bash := *w.WritableByUser
	if c.sandboxActive(projectDir) {
		allowed := inWork || ruleCovers(c.sandboxAllowWrite, path, projectDir) != ""
		if r := ruleCovers(c.sandboxAllowWrite, path, projectDir); r != "" {
			w.SandboxWriteRule = r
		}
		if d := ruleCovers(c.sandboxDenyWrite, path, projectDir); d != "" {
			allowed, w.SandboxWriteRule = false, d
		}
		if w.SandboxProtected {
			allowed = false
		}
		if !allowed {
			bash = false
			w.BashBypass = c.sandboxBypasses()
			if c.sb.allowUnsandboxed && mode == "bypassPermissions" {
				bash = *w.WritableByUser
			}
		}
	}
	w.WritableViaBash = &bash
	return w, true
}

// ingestWriteTargets emits one row per existing integrity target.
func (c *ccCollector) ingestWriteTargets(probe bool) {
	seen := map[string]bool{}
	add := func(w WriteTarget, ok bool) {
		if ok && !seen[w.Path+"|"+w.ProjectDir] {
			seen[w.Path+"|"+w.ProjectDir] = true
			c.snap.WriteTargets = append(c.snap.WriteTargets, w)
		}
	}
	homePath := func(rel string) string {
		p := expandHome(rel, c.home)
		if strings.HasPrefix(rel, "~/.claude/") {
			p = filepath.Join(c.configDir, strings.TrimPrefix(rel, "~/.claude/"))
		}
		if rel == "~/.claude.json" {
			p = c.globalPath
		}
		return p
	}
	for _, s := range homeWriteTargets {
		add(c.writeTargetRow(homePath(s.rel), s.category, "", probe))
	}
	// A session started in a project with its own mode or sandbox setting
	// writes home files under that project's gates (audit N6 residue).
	for _, pr := range c.snap.Projects {
		if pr.Agent != AgentClaudeCode || !pr.Exists || filepath.Clean(pr.ProjectDir) == filepath.Clean(c.home) {
			continue
		}
		if c.projectMode(pr.ProjectDir) == c.effMode && c.sandboxActive(pr.ProjectDir) == c.sandboxEnabled && !c.hasProjectEditRules(pr.ProjectDir) {
			continue
		}
		for _, s := range homeWriteTargets {
			w, ok := c.writeTargetRow(homePath(s.rel), s.category, pr.ProjectDir, probe)
			if ok {
				w.ProjectDir, w.SessionDir = "", pr.ProjectDir
				if !seen[w.Path+"|@"+pr.ProjectDir] {
					seen[w.Path+"|@"+pr.ProjectDir] = true
					c.snap.WriteTargets = append(c.snap.WriteTargets, w)
				}
			}
		}
	}
	for _, pr := range c.snap.Projects {
		if pr.Agent != AgentClaudeCode || !pr.Exists {
			continue
		}
		if filepath.Clean(pr.ProjectDir) == filepath.Clean(c.home) {
			continue
		}
		for _, s := range projectWriteTargets {
			w, ok := c.writeTargetRow(filepath.Join(pr.ProjectDir, s.rel), s.category, pr.ProjectDir, probe)
			w.SessionDir = pr.ProjectDir
			add(w, ok)
		}
	}
}

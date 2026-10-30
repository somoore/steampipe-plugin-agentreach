package posture

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// SDKLauncher is a source file in a known project that starts Claude Code
// through the Agent SDK. The options it passes decide the session's gates,
// and agentreach cannot see them from settings: the SDK hands them to the CLI as
// flags (--permission-mode, --setting-sources, --permission-prompt-tool),
// which agentreach_launch_flag shows while such a session runs. This row is the
// static side: literal option values found in the file's text. It is a
// heuristic: a value built at run time shows as dynamic, and code that is
// commented out still counts.
//
// Docs: Agent SDK permissions (permission modes, canUseTool) and "Use Claude
// Code features in the SDK" (settingSources: omitting it loads user,
// project and local settings).
type SDKLauncher struct {
	Agent      string `json:"agent"`
	ProjectDir string `json:"project_dir"`
	Path       string `json:"path"`
	Language   string `json:"language"` // typescript or python
	ImportLine int    `json:"import_line"`
	// PermissionModes are the literal modes the file passes.
	PermissionModes []string `json:"permission_modes"`
	// DynamicPermissionMode: a permission mode is set from a value agentreach
	// cannot read.
	DynamicPermissionMode bool `json:"dynamic_permission_mode"`
	// SkipPermissionsAllowed: allowDangerouslySkipPermissions is true.
	SkipPermissionsAllowed bool `json:"skip_permissions_allowed"`
	// SettingSources is null when the file never sets settingSources, so
	// the SDK reads user, project and local settings like the CLI.
	SettingSources []string `json:"setting_sources"`
	CanUseTool     bool     `json:"can_use_tool"`    // approvals go to the application's callback
	SandboxEnabled bool     `json:"sandbox_enabled"` // the sandbox option sets enabled to true
}

var (
	sdkPackages = [][]byte{[]byte("@anthropic-ai/claude-agent-sdk"), []byte("@anthropic-ai/claude-code"), []byte("claude-agent-sdk"), []byte("claude_agent_sdk"), []byte("claude-code-sdk"), []byte("claude_code_sdk")}
	// Manifests that name a dependency; a directory with one that names
	// the SDK is walked.
	sdkManifests = []string{"package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py", "setup.cfg", "Pipfile"}
	sdkSkipDirs  = map[string]bool{"node_modules": true, "vendor": true, "dist": true, "build": true, "out": true, "target": true, "venv": true, "__pycache__": true, "site-packages": true, "coverage": true}
	sdkExts      = map[string]string{".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript", ".js": "typescript", ".mjs": "typescript", ".cjs": "typescript", ".py": "python"}

	reSDKImportTS = regexp.MustCompile(`(?m)(?:from\s+|require\(\s*|import\(\s*)['"]@anthropic-ai/(?:claude-agent-sdk|claude-code)(?:/[^'"]*)?['"]`)
	reSDKImportPy = regexp.MustCompile(`(?m)^\s*(?:from|import)\s+(?:claude_agent_sdk|claude_code_sdk)\b`)

	reSDKModeTS    = regexp.MustCompile(`\bpermissionMode\s*:\s*(?:(['"` + "`" + `])([A-Za-z]+)['"` + "`" + `]|([^,}\s]))`)
	reSDKModePy    = regexp.MustCompile(`(?:\bpermission_mode\s*=\s*|['"]permission_mode['"]\s*:\s*)(?:(['"])([A-Za-z]+)['"]|([^,)\s]))`)
	reSDKSkipTS    = regexp.MustCompile(`\ballowDangerouslySkipPermissions\s*:\s*true\b`)
	reSDKSkipPy    = regexp.MustCompile(`\ballow_dangerously_skip_permissions\s*=\s*True\b`)
	reSDKSourcesTS = regexp.MustCompile(`\bsettingSources\s*:\s*\[([^\]]*)\]`)
	reSDKSourcesPy = regexp.MustCompile(`\bsetting_sources\s*=\s*\[([^\]]*)\]`)
	reSDKCanUseTS  = regexp.MustCompile(`\bcanUseTool\b`)
	reSDKCanUsePy  = regexp.MustCompile(`\bcan_use_tool\b`)
	reSDKSandboxTS = regexp.MustCompile(`\bsandbox\s*:\s*\{[^}]*\benabled\s*:\s*true\b`)
	reSDKSandboxPy = regexp.MustCompile(`\bsandbox\s*=\s*(?:\{[^}]*['"]enabled['"]\s*:\s*True\b|SandboxSettings\([^)]*\benabled\s*=\s*True\b)`)
	reSDKSource    = regexp.MustCompile(`['"](user|project|local)['"]`)

	sdkMaxFiles     = 3000
	sdkMaxFileBytes = int64(512 << 10)
)

// collectSDKLaunchers looks for the Agent SDK in the repositories of known
// projects: a manifest at the root or up to two levels down that names the
// SDK marks a directory, and that directory's source files are read. It
// never walks the home directory or node_modules.
func collectSDKLaunchers(opts Options, snap *Snapshot) {
	if !wantAgent(opts, AgentClaudeCode) {
		return
	}
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, root := range projectRoots(opts, snap) {
		for _, base := range sdkBases(root, home) {
			snap.SDKLaunchers = append(snap.SDKLaunchers, scanSDKBase(root, base)...)
		}
	}
}

// projectRoots returns the repository root of every known project (the
// project directory itself when it is not in a repository), sorted.
func projectRoots(opts Options, snap *Snapshot) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		root := dir
		if r := gitRoot(dir); r != "" {
			root = r
		}
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	for _, p := range snap.Projects {
		if p.Exists {
			add(p.ProjectDir)
		}
	}
	for _, d := range opts.ProjectDirs {
		if abs, err := filepath.Abs(d); err == nil {
			add(abs)
		}
	}
	sort.Strings(roots)
	return roots
}

// sdkBases returns root and the directories up to two levels below it
// whose manifest names the SDK. The home directory is never a base: a
// project at ~ would otherwise walk everything under it.
func sdkBases(root, home string) []string {
	if root == home || root == "/" {
		return nil
	}
	var bases []string
	check := func(dir string) {
		for _, m := range sdkManifests {
			b, err := readFileLimited(filepath.Join(dir, m))
			if err != nil || len(b) > 1<<20 {
				continue
			}
			for _, pkg := range sdkPackages {
				if bytes.Contains(b, pkg) {
					bases = append(bases, dir)
					return
				}
			}
		}
	}
	check(root)
	if len(bases) > 0 {
		return bases // the root walk covers everything below it
	}
	for _, d1 := range subdirs(root) {
		check(d1)
		for _, d2 := range subdirs(d1) {
			check(d2)
		}
	}
	return bases
}

func subdirs(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !sdkSkipDirs[e.Name()] {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func scanSDKBase(root, base string) []SDKLauncher {
	var out []SDKLauncher
	n := 0
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != base && (strings.HasPrefix(d.Name(), ".") || sdkSkipDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		lang := sdkExts[filepath.Ext(p)]
		if lang == "" || !d.Type().IsRegular() {
			return nil
		}
		if n++; n > sdkMaxFiles {
			return filepath.SkipAll
		}
		if fi, err := d.Info(); err != nil || fi.Size() > sdkMaxFileBytes {
			return nil
		}
		// #nosec G122 -- a read-only scan of source files; the only
		// effect of a swapped path would be reading a different local
		// file's bytes, which never leave this process unredacted.
		b, err := readFileLimited(p)
		if err != nil {
			return nil
		}
		if l, ok := parseSDKLauncher(b, lang); ok {
			l.ProjectDir, l.Path = root, p
			out = append(out, l)
		}
		return nil
	})
	return out
}

// parseSDKLauncher reads the options a file passes to the SDK. Only mode
// names from the fixed set and setting source names are kept.
func parseSDKLauncher(b []byte, lang string) (SDKLauncher, bool) {
	imp, mode, skip, sources, canUse, sandbox := reSDKImportTS, reSDKModeTS, reSDKSkipTS, reSDKSourcesTS, reSDKCanUseTS, reSDKSandboxTS
	if lang == "python" {
		imp, mode, skip, sources, canUse, sandbox = reSDKImportPy, reSDKModePy, reSDKSkipPy, reSDKSourcesPy, reSDKCanUsePy, reSDKSandboxPy
	}
	loc := imp.FindIndex(b)
	if loc == nil {
		return SDKLauncher{}, false
	}
	l := SDKLauncher{Agent: AgentClaudeCode, Language: lang, ImportLine: bytes.Count(b[:loc[0]], []byte("\n")) + 1, PermissionModes: []string{}}
	for _, m := range mode.FindAllSubmatch(b, -1) {
		if len(m[2]) > 0 {
			if v := claudePermModes[string(m[2])]; v != "" && !slices.Contains(l.PermissionModes, v) {
				l.PermissionModes = append(l.PermissionModes, v)
				continue
			}
		}
		l.DynamicPermissionMode = true
	}
	sort.Strings(l.PermissionModes)
	l.SkipPermissionsAllowed = skip.Match(b)
	for _, m := range sources.FindAllSubmatch(b, -1) {
		if l.SettingSources == nil {
			l.SettingSources = []string{}
		}
		for _, s := range reSDKSource.FindAllSubmatch(m[1], -1) {
			if v := string(s[1]); !slices.Contains(l.SettingSources, v) {
				l.SettingSources = append(l.SettingSources, v)
			}
		}
	}
	sort.Strings(l.SettingSources)
	l.CanUseTool = canUse.Match(b)
	l.SandboxEnabled = sandbox.Match(b)
	return l, true
}

package posture

// Cline collector (docs.cline.bot). Discovery is automatic: nothing is
// reported unless Cline is installed (the ~/.cline directory, the cline
// CLI, or the VS Code extension). Cline runs in several harnesses - VS Code
// and JetBrains extensions, a CLI, a desktop app, the SDK - and they share
// configuration under ~/.cline (docs.cline.bot/getting-started/config):
//   - data/settings/global-settings.json  global settings
//   - data/settings/cline_mcp_settings.json  MCP servers (CLI; the VS Code
//     extension keeps its copy in its globalStorage directory)
//   - rules/, workflows/, hooks/, skills/, agents/, plugins/ under ~/.cline
//     and ~/Documents/Cline
//   - project .cline/ and the older .clinerules/, AGENTS.md and
//     .agents/skills/
// Approval gates are NOT modelled (docs.cline.bot/features/auto-approve):
// auto-approve and YOLO mode are per-tool toggles whose persisted state
// lives in app-specific storage agentreach cannot read, so every gate is
// reported unknown rather than guessed. There is no OS sandbox. Facts
// agentreach does establish: the config, the rules and instruction files
// with provenance, the MCP servers, and the installed surfaces.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const AgentCline = "cline"

func collectCline(ctx context.Context, opts Options, snap *Snapshot) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	dir := filepath.Join(home, ".cline")
	if opts.Home == "" {
		if c := os.Getenv("CLINE_DIR"); c != "" {
			dir = c
		}
	}
	a := Agent{Agent: AgentCline, ConfigDir: dir}
	if opts.Home == "" {
		if p, err := lookPath("cline"); err == nil {
			a.BinaryPath = p
			if out, err := runVersion(ctx, p); err == nil {
				a.Version = versionFrom(out)
			}
		}
	}
	// The VS Code extension is a second install surface and a better
	// version source: ~/.vscode/extensions/saoudrizwan.claude-dev-x.y.z.
	extDir, extVersion := vscodeExtensionVersion(home, "saoudrizwan.claude-dev")
	if extDir != "" {
		a.InstallMethod = "vscode_extension"
		if a.Version == "" {
			a.Version = extVersion
		}
	}

	mcpPaths := []string{filepath.Join(dir, "data", "settings", "cline_mcp_settings.json")}
	if g := vscodeGlobalStorage(opts, home); g != "" {
		mcpPaths = append(mcpPaths, filepath.Join(g, "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"))
	}
	present := dirExists(dir) || a.BinaryPath != "" || extDir != ""
	for _, p := range mcpPaths {
		if fileExists(p) {
			present = true
		}
	}
	if !present {
		return // not installed: no rows at all
	}
	a.Probed = opts.Probe
	a.ProbeSkippedReason = opts.probeSkipped
	a.UserSettingsPath = filepath.Join(dir, "data", "settings", "global-settings.json")

	// Gates: unknown, with the reason. A gate agentreach cannot establish
	// never counts as a person.
	a.EffectivePermissionMode = "unknown"
	a.PermissionModeSource = "unknown"
	a.ShellApproval = ApprovalUnknown
	a.NetworkApproval = ApprovalUnknown
	a.NetworkApprovalReason = "cline stores its auto-approve and YOLO-mode decisions in app state agentreach cannot read; treat every action as needing a person (docs.cline.bot/features/auto-approve)"
	a.WebFetchApproval = ApprovalUnknown
	a.SandboxEnabled = false
	a.SandboxEnforced = false
	a.SandboxBypasses = "cline has no OS sandbox; it runs in the editor or terminal as you"

	// Global settings: every scalar key that is not secret-shaped.
	if cfg, err := readJSONFile(a.UserSettingsPath); err == nil {
		a.UserSettingsPresent = true
		flat := map[string]any{}
		flatten("", cfg, flat)
		for _, k := range sortedKeys(flat) {
			switch flat[k].(type) {
			case string, bool, float64, int:
			default:
				continue
			}
			if v, ok := flat[k].(string); ok {
				if looksLikeSecret(k, v) {
					continue
				}
				scrubbed, _ := scrubText(v)
				snap.Settings = append(snap.Settings, Setting{
					Agent: AgentCline, Scope: "user", SourcePath: a.UserSettingsPath, Key: k,
					Value: scrubbed, Applies: true, Redacted: scrubbed != v,
				})
				continue
			}
			snap.Settings = append(snap.Settings, Setting{
				Agent: AgentCline, Scope: "user", SourcePath: a.UserSettingsPath, Key: k, Value: flat[k], Applies: true,
			})
		}
	} else if !os.IsNotExist(err) {
		e := "cline: " + a.UserSettingsPath + ": " + err.Error()
		snap.Errors = append(snap.Errors, e)
		a.CollectErrors = append(a.CollectErrors, e)
	}

	// MCP servers from every copy (CLI and VS Code extension), names
	// sorted for byte-stable snapshots.
	for _, p := range mcpPaths {
		cfg, err := readJSONFile(p)
		if err != nil {
			continue
		}
		servers := getMap(cfg, "mcpServers")
		for _, name := range sortedKeys(servers) {
			sm, ok := servers[name].(map[string]any)
			if !ok {
				continue
			}
			snap.MCPServers = append(snap.MCPServers, mcpFromMap(AgentCline, "user", p, "", name, sm, ApprovalUnknown))
		}
	}

	// Rules and instruction files, with git provenance.
	reviews, _ := LoadReviewLedger(reviewPath(opts, home))
	git := &ccCollector{gitIDs: map[string]map[string]bool{}}
	addRulesDir := func(scope, projectDir, d string) {
		addAgentMarkdownDir(snap, AgentCline, scope, projectDir, d, "rules", git, reviews)
	}
	addRulesDir("user", "", filepath.Join(dir, "rules"))
	addRulesDir("user", "", filepath.Join(home, "Documents", "Cline", "Rules"))
	projects := projectRoots(opts, snap)
	for _, p := range projects {
		addRulesDir("project", p, filepath.Join(p, ".cline", "rules"))
		addRulesDir("project", p, filepath.Join(p, ".clinerules"))
		if f := filepath.Join(p, ".clinerules"); fileExists(f) {
			addAgentInstruction(snap, AgentCline, "project", p, f, "rules", git, reviews)
		}
		if n := codexInstructionName(p); n != "" { // Cline auto-imports AGENTS.md
			addAgentInstruction(snap, AgentCline, "project", p, filepath.Join(p, n), "AGENTS.md", git, reviews)
		}
	}

	snap.Agents = append(snap.Agents, a)
}

// vscodeExtensionVersion finds ~/.vscode/extensions/<publisher.name>-* and
// returns its directory and version from package.json.
func vscodeExtensionVersion(home, id string) (string, string) {
	exts := filepath.Join(home, ".vscode", "extensions")
	ents, err := os.ReadDir(exts)
	if err != nil {
		return "", ""
	}
	best, version := "", ""
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, id+"-") {
			continue
		}
		var pkg struct {
			Version string `json:"version"`
		}
		if b, err := os.ReadFile(filepath.Join(exts, name, "package.json")); err == nil && json.Unmarshal(b, &pkg) == nil {
			if pkg.Version > version { // several versions can be installed
				best, version = filepath.Join(exts, name), pkg.Version
			}
		}
	}
	return best, version
}

// vscodeGlobalStorage is the VS Code user-globalStorage directory.
func vscodeGlobalStorage(opts Options, home string) string {
	sub := filepath.Join("Code", "User", "globalStorage")
	if opts.GOOS != "" {
		switch opts.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", sub)
		case "linux":
			return filepath.Join(home, ".config", sub)
		}
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", sub)
	case "linux":
		return filepath.Join(home, ".config", sub)
	}
	return ""
}

func readJSONFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

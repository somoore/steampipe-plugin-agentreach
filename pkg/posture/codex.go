package posture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// AgentCodex is the agent identifier used in every Codex CLI row.
const AgentCodex = "codex"

// Codex CLI inventory, minimal. Facts and sources (OpenAI docs moved from
// developers.openai.com/codex to learn.chatgpt.com/docs; both cited):
//
//   - Config file: $CODEX_HOME/config.toml, default ~/.codex/config.toml.
//     https://developers.openai.com/codex/config-basic
//   - sandbox_mode: read-only | workspace-write | danger-full-access. When
//     unset it is read-only, or workspace-write once the cwd's project has
//     a trust decision. https://developers.openai.com/codex/sandboxing
//   - approval_policy: on-request (default) | never | granular table;
//     on-failure is an alias of on-request.
//     https://developers.openai.com/codex/config-reference
//   - sandbox_workspace_write.network_access (default false).
//   - [mcp_servers.<name>]: command, args, env, url, http_headers,
//     bearer_token_env_var, enabled. https://developers.openai.com/codex/mcp
//   - [projects."<path>"] trust_level = "trusted" | "untrusted".
//   - AGENTS.md: $CODEX_HOME/AGENTS.override.md else AGENTS.md; per project
//     the same names from the repo root down.
//     https://developers.openai.com/codex/guides/agents-md
//
// The gates (sandbox_mode, approval_policy, network_access, exec-policy
// allow rules, project trust) are modelled in codexmodel.go; hooks and
// notify in codexhooks.go, plugins and skills in codexplugins.go, local
// services in codexservices.go and write targets in codexwrite.go. Not
// modelled, and reported as unknown or left out: permission profiles
// (beta), the experimental network_proxy, CLI flags and persisted thread
// profiles, remote-synced plugins, and managed hooks under
// requirements managed_dir.

// codexSettingKeys are the config keys copied into agentreach_setting. Only
// non-secret scalars; MCP env and headers never leave the parser.
var codexSettingKeys = []string{
	"sandbox_mode", "approval_policy", "approvals_reviewer", "web_search",
	"sandbox_workspace_write.network_access",
	"shell_environment_policy.inherit", "shell_environment_policy.ignore_default_excludes",
	"features.hooks", "features.network_proxy",
}

func collectCodex(ctx context.Context, opts Options, snap *Snapshot) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	dir := filepath.Join(home, ".codex")
	if opts.Home == "" {
		if ch := os.Getenv("CODEX_HOME"); ch != "" {
			dir = ch
		}
	}
	a := Agent{Agent: AgentCodex, ConfigDir: dir}
	if opts.Home == "" {
		if p, err := exec.LookPath("codex"); err == nil {
			a.BinaryPath = p
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			// #nosec G204 -- a version probe of the installed Codex binary found on this machine, with
			// a fixed argument and a five-second timeout.
			if out, err := exec.CommandContext(cctx, p, "--version").Output(); err == nil {
				if f := strings.Fields(string(out)); len(f) > 0 {
					a.Version = f[len(f)-1]
				}
			}
			cancel()
		}
	}
	if !dirExists(dir) && a.BinaryPath == "" {
		return
	}

	cfgPath := filepath.Join(dir, "config.toml")
	a.GlobalConfigPath = cfgPath
	a.UserSettingsPath = cfgPath
	var cfg map[string]any
	if b, err := readFileLimited(cfgPath); err == nil {
		a.UserSettingsPresent = true
		if err := toml.Unmarshal(b, &cfg); err != nil {
			e := "codex: " + cfgPath + ": " + err.Error()
			snap.Errors = append(snap.Errors, e)
			a.CollectErrors = append(a.CollectErrors, e)
			cfg = nil
		}
	}
	m := &codexModel{home: dir, user: cfg}
	m.flags, _ = codexFlagLayer(snap.LaunchFlags)
	if len(a.CollectErrors) > 0 {
		m.broken = cfgPath
	}
	m.system = opts.CodexSystemDir
	if m.system == "" && opts.Home == "" {
		m.system = "/etc/codex"
	}
	if m.system != "" {
		var bad string
		m.sysCfg, bad = readCodexTOML(filepath.Join(m.system, "config.toml"), &a, snap)
		m.broken = firstNonEmpty(m.broken, bad)
		m.managed, bad = readCodexTOML(filepath.Join(m.system, "managed_config.toml"), &a, snap)
		m.broken = firstNonEmpty(m.broken, bad)
		m.requirements, bad = readCodexTOML(filepath.Join(m.system, "requirements.toml"), &a, snap)
		m.broken = firstNonEmpty(m.broken, bad)
		for _, n := range []string{"managed_config.toml", "requirements.toml"} {
			if p := filepath.Join(m.system, n); fileExists(p) && a.ManagedSettingsPath == "" {
				a.ManagedSettingsPath, a.ManagedSettingsPresent = p, true
			}
		}
		m.userRules = codexAllowRules(filepath.Join(m.system, "rules"))
	}
	m.userRules = append(m.userRules, codexAllowRules(filepath.Join(dir, "rules"))...)
	a.LoggedIn = fileExists(filepath.Join(dir, "auth.json")) // existence only; never read

	if f := getBool(cfg, "features", "hooks"); f != nil && !*f {
		a.HooksDisabled = true
	}

	// The machine-wide row is a session in a directory with no trust
	// decision (the default for any folder Codex has not been told about).
	g := m.gate("", nil, nil, "")
	applyCodexGate(&a, g)
	a.Probed = opts.Probe
	a.ProbeSkippedReason = opts.probeSkipped

	// Settings: allowlisted scalars only.
	flat := map[string]any{}
	flatten("", cfg, flat)
	for _, k := range codexSettingKeys {
		if v, ok := flat[k]; ok {
			if s, isStr := v.(string); isStr && looksLikeSecret(k, s) {
				continue
			}
			snap.Settings = append(snap.Settings, Setting{Agent: AgentCodex, Scope: "user", SourcePath: cfgPath, Key: k, Value: v, Applies: true})
		}
	}

	reviews, _ := LoadReviewLedger(reviewPath(opts, home)) // the Claude Code collector reports a broken ledger
	git := &ccCollector{gitIDs: map[string]map[string]bool{}}

	// Projects, trust and per-project gates. A trusted project's
	// .codex/config.toml and .codex/rules apply; an untrusted one's do not,
	// and its AGENTS.md is skipped (config-basic, "Project trust").
	projects := getMap(cfg, "projects")
	dirs := map[string]bool{}
	for p := range projects {
		dirs[p] = true
	}
	for _, p := range opts.ProjectDirs {
		dirs[p] = true
	}
	sorted := make([]string, 0, len(dirs))
	for p := range dirs {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	var gates []codexGate
	for _, p := range sorted {
		trust := getString(getMap(projects, p), "trust_level")
		if trust != "trusted" && trust != "untrusted" {
			trust = ""
		}
		if _, known := projects[p]; known {
			a.ProjectsKnown++
		}
		pr := Project{Agent: AgentCodex, ProjectDir: p, Exists: dirExists(p), Trusted: trust == "trusted"}
		if pr.Trusted && pr.Exists {
			a.ProjectsTrusted++
		}
		var pcfg map[string]any
		var prules []string
		pbad := ""
		if pr.Exists && !isCodexHome(p, dir) {
			pcPath := filepath.Join(p, ".codex", "config.toml")
			pr.HasProjectSettings = fileExists(pcPath)
			if pr.Trusted {
				pcfg, pbad = readCodexTOML(pcPath, &a, snap)
				prules = codexAllowRules(filepath.Join(p, ".codex", "rules"))
			}
			if name := codexInstructionName(p); name != "" {
				pr.HasInstructionFile = true
				if trust != "untrusted" { // project AGENTS.md loads unless explicitly untrusted
					addCodexInstruction(snap, "project", p, filepath.Join(p, name), git, reviews)
				}
			}
		}
		pg := m.gate(trust, pcfg, prules, pbad)
		// Project-scoped MCP servers inherit the project session's gate,
		// like the user-scope servers below inherit the machine-wide one.
		if pr.Trusted && pcfg != nil {
			pcPath := filepath.Join(p, ".codex", "config.toml")
			servers := getMap(pcfg, "mcp_servers")
			for _, n := range sortedKeys(servers) {
				s := codexMCPServer(pcPath, n, getMap(servers, n), pg.Approval)
				s.Scope, s.ProjectDir = "project", p
				if s.Enabled == nil {
					t := true // trusting the project is the approval; no per-server prompt
					s.Enabled = &t
				}
				snap.MCPServers = append(snap.MCPServers, s)
			}
		}
		gates = append(gates, pg)
		pr.EffectivePermissionMode = pg.Mode()
		pr.PermissionModeSource = pg.SandboxSource
		pr.ShellApproval, pr.NetworkApproval, pr.NetworkApprovalReason = pg.Shell, pg.Network, pg.NetworkReason
		pr.WebFetchApproval, pr.ReadApproval = pg.Web, pg.Read
		if _, known := projects[p]; known {
			snap.Projects = append(snap.Projects, pr)
		}
	}

	// Global instructions: the first non-empty of AGENTS.override.md, AGENTS.md.
	for _, n := range []string{"AGENTS.override.md", "AGENTS.md"} {
		p := filepath.Join(dir, n)
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			addCodexInstruction(snap, "user", "", p, git, reviews)
			break
		}
	}

	// MCP servers from the user config.
	servers := getMap(cfg, "mcp_servers")
	for _, n := range sortedKeys(servers) {
		snap.MCPServers = append(snap.MCPServers, codexMCPServer(cfgPath, n, getMap(servers, n), g.Approval))
	}

	// Reach. read-only and workspace-write do not restrict reads (both
	// start from ":root = read"; managed-configuration: "a read-only
	// default by itself doesn't hide files"), and Codex reads files by
	// shell command, so a readable file is reachable by shell with the
	// session's read gate.
	// One row per file: the home catalog is read first, then project files, so
	// a path that is both (the home dotenv in a session started in ~) keeps
	// the catalog row. Claude Code dedupes the same way.
	seen := map[string]bool{}
	addFile := func(path, category, desc, projectDir, readGate, unknown string) {
		if seen[path] {
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		seen[path] = true
		r := ReachFile{Agent: AgentCodex, Path: path, Category: category, Tier: tierFor(category, path), Description: desc + cacheNote(path, snap.CollectedAt), ProjectDir: projectDir, Exists: true, IsDir: fi.IsDir()}
		r.ReadableEvidence, r.ReachEvidence = EvidenceUnknown, EvidenceUnknown
		f := false
		r.ReachableViaReadTool, r.ReachableViaRetry = &f, &f
		r.ReadApproval = ApprovalUnknown
		if opts.Probe {
			r.Readable = probeReadable(path)
			r.ProbeMethod = "user_process"
			r.ReadableEvidence = EvidenceObserved
			if unknown == "" {
				bash := *r.Readable
				r.ReachableViaBash = &bash
				r.ReachEvidence = EvidenceInferred
				r.ReadApproval = readGate
			}
		}
		snap.ReachFiles = append(snap.ReachFiles, r)
	}
	for _, s := range sensitiveCatalog {
		if (opts.goos() == "darwin" && !s.Darwin) || (opts.goos() == "linux" && !s.Linux) {
			continue
		}
		addFile(expandHome(s.Path, home), s.Category, s.Description, "", g.Read, g.ReadUnknown)
	}
	for i, p := range sorted {
		if _, known := projects[p]; !known || !dirExists(p) {
			continue
		}
		for _, n := range projectSensitiveNames {
			addFile(filepath.Join(p, n.Name), n.Category, n.Description, p, gates[i].Read, gates[i].ReadUnknown)
		}
	}
	inet := ReachHost{Agent: AgentCodex, Target: "*", Kind: "internet", Service: "internet",
		ProbeMethod: "assumed", SandboxEnabled: a.SandboxEnabled,
		ReachableEvidence: EvidenceInferred, Approval: g.Network}
	// The internet row is assumed, never probed: agentreach sends nothing.
	// With the sandbox on, outbound access depends on
	// sandbox_workspace_write.network_access (default false) or an exec-policy
	// allow rule that runs a network-capable command outside the sandbox.
	// The experimental network_proxy limits traffic by rules the model does
	// not read, so it stays unknown rather than claimed either way.
	reach := g.Sandbox == "danger-full-access" || g.NetworkAccess || len(g.AllowRules) > 0
	if g.Proxy && a.SandboxEnabled {
		inet.Reachable = nil
	} else {
		inet.Reachable = &reach
	}
	snap.ReachHosts = append(snap.ReachHosts, inet)

	// Plugins, hooks, skills, local services and write targets.
	x := &codexScan{opts: opts, snap: snap, a: &a, m: m, cfg: cfg, cfgPath: cfgPath, dir: dir, home: home,
		g: g, projects: projects, sorted: sorted, gates: gates, git: git, reviews: reviews}
	x.plugins()
	x.hooks()
	x.skills()
	x.services()
	x.writeTargets()

	a.AssessmentComplete = opts.Probe && len(a.CollectErrors) == 0 && g.Unknown == "" && g.ReadUnknown == ""
	snap.Agents = append(snap.Agents, a)
}

func applyCodexGate(a *Agent, g codexGate) {
	a.EffectivePermissionMode = g.Mode()
	a.PermissionModeSource = g.SandboxSource
	a.SandboxEnabled = g.Sandbox != "danger-full-access"
	a.SandboxEnforced = a.SandboxEnabled && g.enforced()
	a.SandboxAllowUnsandboxed = a.SandboxEnabled && !g.enforced()
	a.SandboxBypasses = g.bypasses()
	a.ShellApproval, a.NetworkApproval, a.NetworkApprovalReason, a.WebFetchApproval = g.Shell, g.Network, g.NetworkReason, g.Web
	a.SandboxAutoAllow = g.Shell == ApprovalNone && a.SandboxEnabled
}

// readCodexTOML returns the parsed file, and the path when it exists but
// does not parse (recorded as a collect error).
func readCodexTOML(path string, a *Agent, snap *Snapshot) (map[string]any, string) {
	b, err := readFileLimited(path)
	if err != nil {
		return nil, ""
	}
	var cfg map[string]any
	if err := toml.Unmarshal(b, &cfg); err != nil {
		e := "codex: " + path + ": " + err.Error()
		snap.Errors = append(snap.Errors, e)
		a.CollectErrors = append(a.CollectErrors, e)
		return nil, path
	}
	return cfg, ""
}

func reviewPath(opts Options, home string) string {
	if opts.ReviewLedgerPath != "" {
		return opts.ReviewLedgerPath
	}
	return DefaultReviewLedgerPath(home)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func codexInstructionName(dir string) string {
	for _, n := range []string{"AGENTS.override.md", "AGENTS.md"} {
		if fi, err := os.Stat(filepath.Join(dir, n)); err == nil && fi.Size() > 0 {
			return n
		}
	}
	return ""
}

func addCodexInstruction(snap *Snapshot, scope, projectDir, path string, git *ccCollector, reviews *ReviewLedger) {
	addCodexInstructionKind(snap, scope, projectDir, path, "AGENTS.md", "", nil, git, reviews)
}

// addCodexInstructionKind adds an AGENTS.md or skill file; plugin files are
// third party.
func addCodexInstructionKind(snap *Snapshot, scope, projectDir, path, kind, plugin string, pluginEnabled *bool, git *ccCollector, reviews *ReviewLedger) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return
	}
	b, err := readFileLimited(path)
	if err != nil {
		return
	}
	f := InstructionFile{
		Agent: AgentCodex, Scope: scope, ProjectDir: projectDir, Path: path, Kind: kind, PluginName: plugin, PluginEnabled: pluginEnabled,
		SizeBytes: fi.Size(), SHA256: sha256File(path), WritableBy: writableBy(path),
		TrackedInGit: gitTracked(path), HiddenUnicode: hiddenUnicodeCount(b),
		HTMLComments:     len(htmlCommentPattern.FindAll(b, -1)),
		ExternalIncludes: len(includePattern.FindAll(b, -1)),
		ExternalURLs:     len(urlPattern.FindAll(b, -1)),
	}
	// Same provenance rule as Claude Code: last committed by someone outside
	// the repository's identity set, unless reviewed (markTrust).
	if f.TrackedInGit {
		f.GitLastAuthor = git.lastAuthor(path)
		f.GitUncommitted = git.uncommitted(path)
	}
	f.ThirdParty = plugin != "" || (f.GitLastAuthor != "" && !git.repoIdentities(path)[strings.ToLower(f.GitLastAuthor)])
	markTrust(&f, reviews)
	snap.InstructionFiles = append(snap.InstructionFiles, f)
}

func codexMCPServer(src, name string, sm map[string]any, approval string) MCPServer {
	s := MCPServer{Agent: AgentCodex, Scope: "user", SourcePath: src, Name: name, ToolApproval: codexToolApproval(sm, approval)}
	s.Command, _ = sm["command"].(string)
	s.Args = toStringSlice(sm["args"])
	s.URL, _ = sm["url"].(string)
	s.Transport = "stdio"
	if s.URL != "" {
		s.Transport = "http"
	}
	lt := launcherType(s.Command, s.Args, s.URL)
	pin := pinned(lt, s.Args)
	var r1, r2, r3 bool
	s.Args, r1 = scrubArgs(s.Args)
	s.URL, r2 = scrubURL(s.URL)
	s.Command, r3 = scrubText(s.Command)
	s.Redacted = r1 || r2 || r3
	s.HasInlineSecret = s.Redacted
	for k, v := range getMap(sm, "env") {
		s.EnvKeys = append(s.EnvKeys, k)
		if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
			s.HasInlineSecret = true
		}
	}
	sort.Strings(s.EnvKeys)
	for k, v := range getMap(sm, "http_headers") {
		if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
			s.HasInlineSecret = true
		}
	}
	if e := getBool(sm, "enabled"); e != nil {
		s.Enabled = e
	}
	s.LauncherType = lt
	s.Pinned = pin
	s.CommandExists = launcherExists(getString(sm, "command"))
	return s
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// isCodexHome reports whether project p's .codex folder is CODEX_HOME. Codex
// skips that folder as a project layer (config/src/loader/mod.rs,
// discover_project_layers, 0.155.1): it is the user layer, already read.
func isCodexHome(p, codexHome string) bool {
	norm := func(s string) string {
		if r, err := filepath.EvalSymlinks(s); err == nil {
			s = r
		}
		return filepath.Clean(s)
	}
	return norm(filepath.Join(p, ".codex")) == norm(codexHome)
}

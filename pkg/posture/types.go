// Package posture collects the local security posture of AI coding agents:
// what the agent is configured to do, what it is told to obey, and what it
// can actually reach on this machine. It is a plain Go library with no
// Steampipe dependency so the same collector can back a Steampipe plugin, a
// CLI, or a CI check.
//
// Nothing in this package attacks anything. Collectors parse configuration
// and run inert probes (open-for-read, TCP dial) that never read secret
// contents, send data anywhere, or modify state.
package posture

import "time"

// Evidence says how a column's value was established. Every verdict-bearing
// column has a matching *_evidence column so a reader can tell a probe
// result from agentreach's model of the agent.
const (
	EvidenceConfigured = "configured" // read from a configuration file
	EvidenceObserved   = "observed"   // a probe saw it on this machine
	EvidenceInferred   = "inferred"   // derived by agentreach from configured and observed facts
	EvidenceUnknown    = "unknown"    // could not be assessed
)

// SchemaVersion identifies the Snapshot JSON shape. Bump the minor number
// for additive changes and the major number for anything that breaks a
// reader.
const SchemaVersion = "1.0"

// CollectorVersion is the version of this collector; the CLI and plugin
// override it at build time.
var CollectorVersion = "0.2.0"

// Agent describes one installed coding agent and its effective top-level posture.
type Agent struct {
	Agent                   string   `json:"agent"`
	BinaryPath              string   `json:"binary_path"`
	Version                 string   `json:"version"`
	ACPHarness              string   `json:"acp_harness"` // editor ACP agent servers that can start this agent; their options are not visible
	InstallMethod           string   `json:"install_method"`
	AutoUpdates             *bool    `json:"auto_updates"`
	ConfigDir               string   `json:"config_dir"`
	GlobalConfigPath        string   `json:"global_config_path"`
	UserSettingsPath        string   `json:"user_settings_path"`
	UserSettingsPresent     bool     `json:"user_settings_present"`
	ManagedSettingsPath     string   `json:"managed_settings_path"`
	ManagedSettingsPresent  bool     `json:"managed_settings_present"` // file-based or server-managed
	RemoteSettingsPath      string   `json:"remote_settings_path"`
	RemoteSettingsPresent   bool     `json:"remote_settings_present"`
	ManagedSource           string   `json:"managed_source"`           // which admin source supplies the managed tier: remote, plist, file, drop-ins, file + drop-ins, or "a + b, merged"; empty when none delivers a policy key
	ManagedSourcesBehavior  string   `json:"managed_sources_behavior"` // first-wins (default) or merge
	CollectErrors           []string `json:"collect_errors"`           // per-source read or parse failures; a row here means part of the posture is unknown
	EffectivePermissionMode string   `json:"effective_permission_mode"`
	PermissionModeSource    string   `json:"permission_mode_source"` // managed | user | built_in
	SandboxEnabled          bool     `json:"sandbox_enabled"`
	// SandboxEnforced is true only when the sandbox is on, cannot be
	// skipped by an unsandboxed retry, and either the runtime is available
	// or Claude Code refuses to start without it.
	SandboxEnforced             bool              `json:"sandbox_enforced"`
	SandboxRuntimeAvailable     *bool             `json:"sandbox_runtime_available"` // nil when not checked
	SandboxAllowUnsandboxed     bool              `json:"sandbox_allow_unsandboxed_commands"`
	SandboxFailIfUnavailable    bool              `json:"sandbox_fail_if_unavailable"`
	SandboxFilesystemDisabled   bool              `json:"sandbox_filesystem_disabled"`
	SandboxExcludedCommands     int               `json:"sandbox_excluded_commands"`
	SandboxBypasses             string            `json:"sandbox_bypasses"` // comma list: unsandboxed_retry, excluded_commands, runtime_missing
	BlockReadsOutsideWorkDirs   bool              `json:"block_reads_outside_working_dirs"`
	WebFetchDenied              bool              `json:"web_fetch_denied"`
	NetworkStrictAllowlist      bool              `json:"network_strict_allowlist"` // strictAllowlist or allowManagedDomainsOnly: hosts outside the allowlist are refused in every mode
	SandboxAutoAllow            bool              `json:"sandbox_auto_allow"`       // autoAllowBashIfSandboxed: sandboxed commands run without a prompt
	BypassAvailable             bool              `json:"bypass_available"`         // bypassPermissions is in the mode cycle as far as files show
	BypassAvailableReason       string            `json:"bypass_available_reason"`
	RunningBypassSessions       int               `json:"running_bypass_sessions"` // running claude sessions started with a bypass flag
	AutoModeDropCommands        []string          `json:"auto_mode_drop_commands"` // commands whose broad allow rules auto mode drops
	AutoModeDropSource          string            `json:"auto_mode_drop_source"`   // binary | built_in | pinned
	AutoModeDropReason          string            `json:"auto_mode_drop_reason"`
	ShellApproval               string            `json:"shell_approval"`   // what a command that is not read-only gets: none | classifier | prompt | denied | unknown
	NetworkApproval             string            `json:"network_approval"` // what decides a shell connection to a host no rule allows
	NetworkApprovalReason       string            `json:"network_approval_reason"`
	WebFetchApproval            string            `json:"web_fetch_approval"`             // what a WebFetch to an arbitrary host gets
	WebSourceApproval           string            `json:"web_source_approval"`            // what it takes for a fetched page to reach the agent: the weakest way one can arrive
	AssessmentComplete          bool              `json:"assessment_complete"`            // false when any collect error or unassessed area exists
	Probed                      bool              `json:"probed"`                         // whether the reachability probes ran
	ProbeSkippedReason          string            `json:"probe_skipped_reason"`           // why probes did not run although asked for, e.g. agentreach itself ran inside a sandbox
	StartSurface                string            `json:"start_surface"`                  // how sessions are started for the gates agentreach models: terminal (assumed unless detected), print_or_sdk, vscode, desktop
	StartSurfaceSource          string            `json:"start_surface_source"`           // assumed, or CLAUDE_CODE_ENTRYPOINT=<value> when agentreach ran inside a session
	SurfaceModes                map[string]string `json:"surface_modes"`                  // starting permission mode per surface
	VscodeInitialPermissionMode string            `json:"vscode_initial_permission_mode"` // claudeCode.initialPermissionMode from VS Code user settings
	VscodeProcessWrapper        bool              `json:"vscode_process_wrapper"`         // claudeCode.claudeProcessWrapper is set
	HooksDisabled               bool              `json:"hooks_disabled"`
	LoggedIn                    bool              `json:"logged_in"`
	ProjectsKnown               int               `json:"projects_known"`
	ProjectsTrusted             int               `json:"projects_trusted"`
	PluginsEnabled              int               `json:"plugins_enabled"`
}

// Project is a directory the agent has worked in, with the trust state the
// agent recorded for it and which project-scoped files it supplies.
type Project struct {
	Agent              string     `json:"agent"`
	ProjectDir         string     `json:"project_dir"`
	Exists             bool       `json:"exists"`
	Trusted            bool       `json:"trusted"`
	IsGitRepo          bool       `json:"is_git_repo"`
	GitRemote          string     `json:"git_remote"`
	HasProjectSettings bool       `json:"has_project_settings"`
	HasLocalSettings   bool       `json:"has_local_settings"`
	HasMCPJSON         bool       `json:"has_mcp_json"`
	HasInstructionFile bool       `json:"has_instruction_file"`
	AllowedTools       []string   `json:"allowed_tools"`
	EnabledMCPJSON     []string   `json:"enabled_mcpjson_servers"`
	DisabledMCPJSON    []string   `json:"disabled_mcpjson_servers"`
	LastStartTime      *time.Time `json:"last_start_time"`
	// Gates for a session started in this project: project and local
	// defaultMode, project sandbox settings and project allow rules apply.
	EffectivePermissionMode string   `json:"effective_permission_mode"`
	PermissionModeSource    string   `json:"permission_mode_source"` // managed | local | project | user | built_in | unknown
	ShellApproval           string   `json:"shell_approval"`
	NetworkApproval         string   `json:"network_approval"`
	NetworkApprovalReason   string   `json:"network_approval_reason"`
	WebFetchApproval        string   `json:"web_fetch_approval"`
	WebSourceApproval       string   `json:"web_source_approval"` // what it takes for a fetched page to reach the agent here
	ReadApproval            string   `json:"read_approval"`       // a read the sandbox or the working directory does not cover
	SandboxAllowedDomains   []string `json:"sandbox_allowed_domains"`
}

// Setting is one leaf key/value from a settings file, with its scope.
type Setting struct {
	Agent           string `json:"agent"`
	Scope           string `json:"scope"` // managed | user | project | local
	SourcePath      string `json:"source_path"`
	ProjectDir      string `json:"project_dir"`
	Key             string `json:"key"`   // dotted path, e.g. permissions.defaultMode
	Value           any    `json:"value"` // JSON value (arrays kept whole); nil when redacted
	Applies         bool   `json:"applies"`
	Redacted        bool   `json:"redacted"`
	LooksLikeSecret *bool  `json:"looks_like_secret"` // only for redacted values: whether the value classified as a credential
}

// Hook is one command the agent will run on a lifecycle event.
type Hook struct {
	Agent            string   `json:"agent"`
	Scope            string   `json:"scope"` // managed | user | project | local | plugin
	SourcePath       string   `json:"source_path"`
	ProjectDir       string   `json:"project_dir"`
	Event            string   `json:"event"`
	Matcher          string   `json:"matcher"`
	HookType         string   `json:"hook_type"`
	Command          string   `json:"command"` // credential-shaped spans replaced with <redacted>
	URL              string   `json:"url"`     // http hooks; userinfo and secret query values redacted
	Args             []string `json:"args"`    // exec-form hooks; redacted like MCP args
	If               string   `json:"if"`
	Timeout          *int     `json:"timeout"`
	EffectiveTimeout int      `json:"effective_timeout"` // seconds; the documented default when unset
	Redacted         bool     `json:"redacted"`
	Origin           string   `json:"origin"` // settings | plugin | skill | subagent
	Runs             *bool    `json:"runs"`   // false when disableAllHooks, allowManagedHooksOnly or a disabled plugin stops it
	RunsReason       string   `json:"runs_reason"`
	SourceWritableBy string   `json:"source_writable_by"` // owner | group | others
	SourceTrackedGit bool     `json:"source_tracked_in_git"`
	PluginName       string   `json:"plugin_name"`    // name@marketplace for plugin scope
	PluginEnabled    *bool    `json:"plugin_enabled"` // nil outside plugin scope
	ThirdParty       bool     `json:"third_party"`    // code the user did not write: plugin-provided
}

// MCPServer is one configured MCP server and where it was declared.
type MCPServer struct {
	Agent           string   `json:"agent"`
	Scope           string   `json:"scope"` // user | project | local | managed
	SourcePath      string   `json:"source_path"`
	ProjectDir      string   `json:"project_dir"`
	Name            string   `json:"name"`
	Transport       string   `json:"transport"`      // stdio | http | sse
	Command         string   `json:"command"`        // redacted like args
	CommandExists   *bool    `json:"command_exists"` // for an absolute launcher path, whether it exists; nil for a bare name or a remote server
	Args            []string `json:"args"`           // credential-shaped args replaced with <redacted>
	URL             string   `json:"url"`            // userinfo and secret query values replaced with <redacted>
	EnvKeys         []string `json:"env_keys"`
	HasInlineSecret bool     `json:"has_inline_secret"` // env, headers, args or url carried a credential
	Redacted        bool     `json:"redacted"`
	PluginName      string   `json:"plugin_name"`   // set for plugin scope
	ToolApproval    string   `json:"tool_approval"` // what a call to one of its tools gets: none (allow rule or mode) | classifier | prompt | denied | unknown
	Enabled         *bool    `json:"enabled"`       // nil = no per-project decision recorded
	LauncherType    string   `json:"launcher_type"` // npx | uvx | docker | node | python | binary | shell | remote
	Pinned          *bool    `json:"pinned"`        // nil when not applicable
}

// InstructionFile is content the agent obeys as instructions.
type InstructionFile struct {
	Agent            string `json:"agent"`
	Scope            string `json:"scope"` // user | project | plugin
	ProjectDir       string `json:"project_dir"`
	Path             string `json:"path"`
	Kind             string `json:"kind"` // CLAUDE.md | AGENTS.md | rules | skill | subagent | command
	PluginName       string `json:"plugin_name"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	TrackedInGit     bool   `json:"tracked_in_git"`
	GitLastAuthor    string `json:"git_last_author"` // email of the last committer, when tracked
	GitUncommitted   bool   `json:"git_uncommitted"` // the working copy differs from the last commit
	ThirdParty       bool   `json:"third_party"`     // plugin-provided, or last committed by someone else
	WritableBy       string `json:"writable_by"`
	HiddenUnicode    int    `json:"hidden_unicode_count"`
	HTMLComments     int    `json:"html_comment_count"`
	ExternalIncludes int    `json:"external_include_count"`
	ExternalURLs     int    `json:"external_url_count"`
	// Review state from the user's review ledger (see ReviewLedger).
	Reviewed           bool   `json:"reviewed"`             // this exact content (sha256) was reviewed
	ChangedSinceReview bool   `json:"changed_since_review"` // this path was reviewed, but its content has changed since
	ReviewSignals      string `json:"review_signals"`       // comma list of reasons a human should look: hidden_unicode, html_comments, external_urls, external_includes
	Untrusted          bool   `json:"untrusted"`            // counts as an untrusted source in agentreach_path
	UntrustedReason    string `json:"untrusted_reason"`
	PluginEnabled      *bool  `json:"plugin_enabled"` // plugin files only
}

// SandboxRule is one restriction or grant from sandbox or permission config.
type SandboxRule struct {
	Agent        string `json:"agent"`
	Scope        string `json:"scope"`
	SourcePath   string `json:"source_path"`
	ProjectDir   string `json:"project_dir"`
	Category     string `json:"category"`  // filesystem | network | permission | credential | execution
	RuleType     string `json:"rule_type"` // denyRead | allowRead | denyWrite | allowWrite | allowedDomains | deniedDomains | allow | deny | ask | excludedCommands | additionalDirectories | allowUnixSockets | credentialFile | credentialEnvVar
	Tool         string `json:"tool"`      // for permission rules: Bash, Read, Edit, WebFetch, mcp__x__y ...
	Pattern      string `json:"pattern"`   // rule text; credential-shaped spans redacted
	ResolvedPath string `json:"resolved_path"`
	Redacted     bool   `json:"redacted"`
	// CarriesNetwork marks a Bash allow rule that approves a command able to
	// reach the network (curl, ssh, interpreters, package managers ...).
	CarriesNetwork bool `json:"carries_network"`
	// DroppedInAutoMode marks a broad Bash allow rule that auto mode ignores.
	DroppedInAutoMode bool `json:"dropped_in_auto_mode"`
	// ApprovesNetwork is CarriesNetwork in the effective permission mode: the
	// rule runs a network-capable command with no prompt.
	ApprovesNetwork bool `json:"approves_network"`
}

// ReachFile is a sensitive path and whether the agent can read it.
type ReachFile struct {
	Agent                  string `json:"agent"`
	Path                   string `json:"path"`
	Category               string `json:"category"`
	Tier                   int    `json:"tier"` // 1 = keys that grant access elsewhere, 2 = tokens and configs, 3 = often-leaky files
	Description            string `json:"description"`
	ProjectDir             string `json:"project_dir"`
	Exists                 bool   `json:"exists"`
	IsDir                  bool   `json:"is_dir"`
	Readable               *bool  `json:"readable"` // nil when not probed
	ProbeMethod            string `json:"probe_method"`
	ReadableEvidence       string `json:"readable_evidence"` // observed | unknown
	SandboxDenyReadRule    string `json:"sandbox_deny_read_rule"`
	SandboxAllowReadRule   string `json:"sandbox_allow_read_rule"` // a narrower allowRead that re-opens the path
	PermissionDenyReadRule string `json:"permission_deny_read_rule"`
	ReadBlockRule          string `json:"read_block_rule"` // permissions.blockReadsOutsideWorkingDirectories when it fences this path
	ReachableViaBash       *bool  `json:"reachable_via_bash"`
	ReachableViaReadTool   *bool  `json:"reachable_via_read_tool"`
	ReachEvidence          string `json:"reach_evidence"`      // inferred (agentreach's model of Claude Code) | unknown
	BashBypass             string `json:"bash_bypass"`         // escape routes still open when the sandbox blocks the path
	ReachableViaRetry      *bool  `json:"reachable_via_retry"` // the sandbox blocks it, but an unsandboxed retry or other bypass can read it
	ReadApproval           string `json:"read_approval"`       // weakest gate on any route that reads it
	// Observed mode: the same one-byte read run inside Anthropic's sandbox
	// runtime (srt) with agentreach's translation of the effective settings.
	ObservedViaSandbox *bool  `json:"observed_via_sandbox"` // nil when observed mode did not run
	ObservedMethod     string `json:"observed_method"`
	ModelAgrees        *bool  `json:"model_agrees"` // observed_via_sandbox == reachable_via_bash; nil when not observed
}

// ReachHost is a network destination and whether the agent can reach it.
type ReachHost struct {
	Agent              string `json:"agent"`
	Target             string `json:"target"`   // host:port, unix socket path, or "*"
	Kind               string `json:"kind"`     // tcp | unix_socket | internet
	Loopback           bool   `json:"loopback"` // reachable on this machine's loopback interface
	Service            string `json:"service"`
	ProcessName        string `json:"process_name"`
	Reachable          *bool  `json:"reachable"`
	ProbeMethod        string `json:"probe_method"`
	SandboxEnabled     bool   `json:"sandbox_enabled"`
	AllowedBySandbox   *bool  `json:"allowed_by_sandbox"` // nil = sandbox off, unrestricted
	SandboxRule        string `json:"sandbox_rule"`
	Approval           string `json:"approval"`           // what a shell command connecting to it needs
	ReachableEvidence  string `json:"reachable_evidence"` // observed (dialled) | inferred (assumed) | unknown
	ObservedViaSandbox *bool  `json:"observed_via_sandbox"`
	ObservedMethod     string `json:"observed_method"`
}

// Snapshot is everything collected in one pass. The envelope fields
// identify the snapshot so a folder of them from many machines can be
// queried together.
type Snapshot struct {
	SchemaVersion    string            `json:"schema_version"`
	CollectorVersion string            `json:"collector_version"`
	SnapshotID       string            `json:"snapshot_id"` // sha256 of host + collected_at, first 16 hex
	Host             string            `json:"host"`
	OS               string            `json:"os"`
	Arch             string            `json:"arch"`
	Probed           bool              `json:"probed"`   // inert probes ran
	Observed         bool              `json:"observed"` // observed mode (srt) ran
	ObservedTool     string            `json:"observed_tool"`
	CollectedAt      time.Time         `json:"collected_at"`
	Agents           []Agent           `json:"agents"`
	Projects         []Project         `json:"projects"`
	Settings         []Setting         `json:"settings"`
	Hooks            []Hook            `json:"hooks"`
	MCPServers       []MCPServer       `json:"mcp_servers"`
	InstructionFiles []InstructionFile `json:"instruction_files"`
	Plugins          []Plugin          `json:"plugins"`
	Marketplaces     []Marketplace     `json:"marketplaces"`
	SandboxRules     []SandboxRule     `json:"sandbox_rules"`
	LaunchFlags      []LaunchFlag      `json:"launch_flags"`
	CIWorkflows      []CIWorkflow      `json:"ci_workflows"`
	SDKLaunchers     []SDKLauncher     `json:"sdk_launchers"`
	ReachFiles       []ReachFile       `json:"reach_files"`
	ReachHosts       []ReachHost       `json:"reach_hosts"`
	WriteTargets     []WriteTarget     `json:"write_targets"`
	Environment      []EnvControl      `json:"environment"`
	Legs             []LegRow          `json:"legs"`
	Paths            []Path            `json:"paths"`
	Errors           []string          `json:"errors"`

	// services holds the local listeners and sockets probed once per
	// collection; every agent's reach rows are built from it.
	services     []ReachHost
	servicesDone bool
}

// Options controls a collection pass.
type Options struct {
	probeSkipped string // set by Collect when it turns probes off
	// Entrypoint is the CLAUDE_CODE_ENTRYPOINT to assume; live runs read
	// the environment, fixture runs only this.
	Entrypoint string
	// Home overrides the user's home directory (tests).
	Home string
	// ProjectDirs are extra project directories to inspect. Discovered
	// projects (from the agent's own records) are always included.
	ProjectDirs []string
	// Probe enables inert reachability probes.
	Probe bool
	// ProbeTimeout bounds each TCP dial.
	ProbeTimeout time.Duration
	// ManagedDir overrides the system directory that holds
	// managed-settings.json, managed-settings.d and managed-mcp.json (tests).
	ManagedDir string
	// CodexSystemDir is where Codex's system and managed files live
	// (config.toml, managed_config.toml, requirements.toml, rules/). Empty
	// means /etc/codex for a live run and nothing for a fixture run (Home
	// set), so fixtures never read this machine's /etc.
	CodexSystemDir string
	// OpenCodeManagedDir overrides the OpenCode managed-config directory
	// (/Library/Application Support/opencode on macOS, /etc/opencode on
	// Linux). Empty means the platform default for a live run and nothing
	// for a fixture run (Home set).
	OpenCodeManagedDir string
	// GrokSystemDir overrides Grok Build's system directory (/etc/grok:
	// managed_config.toml, requirements.toml). Empty means /etc/grok for a
	// live run and nothing for a fixture run (Home set).
	GrokSystemDir string
	// PlistPath overrides the macOS managed-preferences plist path (tests).
	// Set to "-" to disable plist reading.
	PlistPath string
	// Observe runs the file and loopback probes a second time inside
	// Anthropic's sandbox runtime (srt) configured from the effective
	// settings. SRTPath overrides the srt binary; empty means look on PATH.
	Observe bool
	SRTPath string
	// Listeners are host:port addresses treated as listening TCP ports
	// (tests). A fixture run (Home set) never reads this machine's listener
	// table, so tests that need tcp rows list them here.
	Listeners []string
	// GOOS and Arch pin the operating system the model assumes (catalog
	// entries, sandbox runtime, allowLocalBinding) and the envelope, so
	// fixtures are byte-identical on every build machine. Empty means the
	// running system.
	GOOS, Arch string
	// SandboxRuntime pins whether the OS sandbox runtime is installed
	// (fixtures); nil means check this machine.
	SandboxRuntime *bool
	// Services stand in for discovered TCP listeners and Unix sockets in
	// fixture runs, with a fixed probe result instead of a dial.
	Services []FixtureService
	// DeclaredControls are controls outside the agent's configuration that
	// the operator asserts exist (egress_allowlist, devcontainer, edr,
	// secrets_broker). agentreach cannot verify them; they are reported as declared.
	DeclaredControls []string
	// ReviewLedgerPath overrides the review ledger location
	// (default ~/.config/agentreach/reviews.json).
	ReviewLedgerPath string
	// Agents limits collection to these agent ids; empty means all.
	Agents []string
	// Version overrides the agent binary version probe (tests).
	ClaudeVersion string
	// Processes pins the `ps -o pid=,args=` lines read for running
	// sessions (tests). Unset: ps runs only on a live collection.
	Processes []string
	// AutoModeDropCommands pins the command list auto mode's rule drop uses
	// (tests). Unset: read from the installed Claude Code, or the built-in
	// list for fixture runs and when it cannot be read.
	AutoModeDropCommands []string
	// Now and Host pin the snapshot envelope so generated fixtures are
	// byte-stable (tests and cmd/agentreach-fixtures).
	Now  time.Time
	Host string
}

// Plugin is one install record of a plugin from installed_plugins.json: the
// same plugin installed at user scope and again for a project is two rows.
// Counts and existence only; no plugin file contents are read.
type Plugin struct {
	Agent              string     `json:"agent"`
	FullName           string     `json:"full_name"` // name@marketplace
	Name               string     `json:"name"`
	Marketplace        string     `json:"marketplace"`
	Scope              string     `json:"scope"` // user | project | local
	ProjectDir         string     `json:"project_dir"`
	InstallPath        string     `json:"install_path"`
	InstallPathExists  bool       `json:"install_path_exists"`
	Version            string     `json:"version"`
	GitCommitSHA       string     `json:"git_commit_sha"`
	Pinned             *bool      `json:"pinned"` // version is a release tag, not a floating commit; nil when no version
	InstalledAt        *time.Time `json:"installed_at"`
	LastUpdated        *time.Time `json:"last_updated"`
	Enabled            *bool      `json:"enabled"` // enabledPlugins decision; nil when none recorded
	HasHooks           bool       `json:"has_hooks"`
	HasMCP             bool       `json:"has_mcp"`
	HasInstructionFile bool       `json:"has_instruction_file"`
	SkillCount         int        `json:"skill_count"`
	AgentCount         int        `json:"agent_count"`
	CommandCount       int        `json:"command_count"`
	WritableBy         string     `json:"writable_by"`
}

// Marketplace is one registered plugin source from known_marketplaces.json.
type Marketplace struct {
	Agent                 string     `json:"agent"`
	Name                  string     `json:"name"`
	SourceType            string     `json:"source_type"` // github | git | url | file | directory
	SourceRepo            string     `json:"source_repo"` // repo, url or path, whichever the source carries
	InstallLocation       string     `json:"install_location"`
	InstallLocationExists bool       `json:"install_location_exists"`
	AutoUpdate            *bool      `json:"auto_update"`
	LastUpdated           *time.Time `json:"last_updated"`
	Official              bool       `json:"official"`
	InStrictAllowlist     *bool      `json:"in_strict_allowlist"` // nil when no strictKnownMarketplaces policy exists
	InExtraKnown          bool       `json:"in_extra_known"`
}

// WriteTarget is a file or directory whose modification changes what the
// agent obeys, what runs on the developer's behalf, or what ships: the
// agent's own guardrails, instruction files, CI workflows, dependency
// manifests, git hooks and shell startup files. It is the integrity
// counterpart of ReachFile.
type WriteTarget struct {
	Agent      string `json:"agent"`
	Path       string `json:"path"`
	Category   string `json:"category"` // guardrail | instruction | ci_workflow | dependency_manifest | git_hooks | shell_startup | devcontainer
	ProjectDir string `json:"project_dir"`
	// SessionDir is the project a session must start in for this row's
	// gates: the target's project, or for a home-directory target a project
	// whose own mode or sandbox setting differs from the machine-wide one.
	// Empty means the machine-wide gates.
	SessionDir string `json:"session_dir"`
	IsDir      bool   `json:"is_dir"`
	// WritableByUser comes from access(2) with W_OK; nothing is written.
	WritableByUser      *bool  `json:"writable_by_user"`
	WritableEvidence    string `json:"writable_evidence"`
	SandboxProtected    bool   `json:"sandbox_protected"`    // on the sandbox's protected-path list
	PermissionProtected bool   `json:"permission_protected"` // on the permission system's protected-path list
	SandboxWriteRule    string `json:"sandbox_write_rule"`   // the allowWrite or denyWrite rule that decides
	EditDenyRule        string `json:"edit_deny_rule"`
	EditAllowRule       string `json:"edit_allow_rule"`
	WritableViaBash     *bool  `json:"writable_via_bash"`
	BashBypass          string `json:"bash_bypass"`
	EditToolApproval    string `json:"edit_tool_approval"` // denied | prompt | classifier | auto | allowed | unknown
	WriteEvidence       string `json:"write_evidence"`     // inferred | unknown
}

// EnvControl is a control outside the agent's configuration: an egress
// proxy, a container boundary, an endpoint agent, or something the operator
// declared. Detected controls are observed facts, not verified protection.
type EnvControl struct {
	Agent    string `json:"agent"`
	Name     string `json:"name"` // egress_proxy | system_proxy | container | devcontainer | edr | <declared name>
	Kind     string `json:"kind"` // network | isolation | endpoint | declared
	Detected bool   `json:"detected"`
	Declared bool   `json:"declared"`
	Evidence string `json:"evidence"` // observed | configured (declared) | unknown
	Detail   string `json:"detail"`   // host only, no credentials
}

// Path is one candidate exposure path: an untrusted source the agent loads,
// a private file or write target the agent can touch, and (for
// confidentiality paths) an exit. It is a candidate because the legs are
// established separately; agentreach has not demonstrated them in one session.
// Each edge carries its own evidence.
// LegRow is one leg that paths are built from, whether or not it ends up in
// a path: an untrusted source, a private file, an exit or a write target.
type LegRow struct {
	Agent      string `json:"agent"`
	Role       string `json:"role"` // untrusted | private | exit | write
	LegID      string `json:"leg_id"`
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	ProjectDir string `json:"project_dir"`
	Evidence   string `json:"evidence"`
	Rank       int    `json:"rank"`
	Path       string `json:"path"`
	Category   string `json:"category"`
	Tier       int    `json:"tier"`
	Via        string `json:"via"`
	BlockedBy  string `json:"blocked_by"`
	Approval   string `json:"approval"` // exits and write targets: the gate on this step
}

type Path struct {
	PathID      string `json:"path_id"`
	Agent       string `json:"agent"`
	Kind        string `json:"kind"`        // confidentiality | integrity
	ProjectDir  string `json:"project_dir"` // the project a session must start in for every leg to load; "" for any
	Status      string `json:"status"`      // candidate | attested (a declared control the operator says closes it; not verified)
	MitigatedBy string `json:"mitigated_by"`

	SourceID       string `json:"source_id"`
	SourceKind     string `json:"source_kind"` // instruction_file | plugin_file | mcp | plugin_hook | web_tool
	SourceTitle    string `json:"source_title"`
	SourceDetail   string `json:"source_detail"`
	SourceEvidence string `json:"source_evidence"`

	TargetPath          string `json:"target_path"`
	TargetTitle         string `json:"target_title"`
	TargetCategory      string `json:"target_category"`
	TargetTier          int    `json:"target_tier"`
	Via                 string `json:"via"`                   // shell | read_tool | edit_tool
	Approval            string `json:"approval"`              // strongest gate on any step (source, read, exit or write): none | classifier | prompt | unknown
	SourceApproval      string `json:"source_approval"`       // gate before the source reaches the agent: prompt for a project MCP server with no decision, the web source gate for fetched pages, none otherwise
	AfterSourceApproval string `json:"after_source_approval"` // strongest gate on the steps after the source has loaded (read and exit, or the write)
	TargetEvidence      string `json:"target_evidence"`       // inferred, or observed when srt confirmed the shell read
	TargetBlockedBy     string `json:"target_blocked_by"`

	ExitID       string `json:"exit_id"`
	ExitKind     string `json:"exit_kind"` // internet | allowed_domains | web_tool | mcp_remote | mcp_process | plugin_hooks | local_service
	ExitTitle    string `json:"exit_title"`
	ExitDetail   string `json:"exit_detail"`
	ExitEvidence string `json:"exit_evidence"`

	SourceRank int `json:"source_rank"`
	ExitRank   int `json:"exit_rank"`
}

// FixtureService is a listener or socket a fixture declares, with the probe
// result agentreach would have observed.
type FixtureService struct {
	Kind      string // tcp or unix_socket
	Target    string // host:port, or a socket path ("~/" is the fixture home)
	Process   string
	Reachable bool
}

package agentreach

import (
	"context"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"

	"github.com/turbot/steampipe-plugin-sdk/v6/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func tableAgentreachAgent(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "agentreach_agent",
		Description: "Installed AI coding agents and their effective top-level posture: version, permission mode, sandbox state, managed policy presence.",
		List:        &plugin.ListConfig{Hydrate: listAgents},
		Columns: withCommon([]*plugin.Column{
			{Name: "agent", Type: proto.ColumnType_STRING, Description: "Agent identifier, e.g. claude_code."},
			{Name: "acp_harness", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.ACPHarness"), Description: "Editor Agent Client Protocol (ACP) agent servers that can start this agent, e.g. Zed's agent_servers. A session started through an adapter uses the adapter's own options, which agentreach cannot see; empty when none are configured."},
			{Name: "auto_updates", Type: proto.ColumnType_BOOL, Description: "Whether the agent auto-updates itself."},
			{Name: "binary_path", Type: proto.ColumnType_STRING, Description: "Resolved path of the agent binary on PATH."},
			{Name: "collect_errors", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.CollectErrors").Transform(marshalJSON), Description: "Files the collector could not read or parse. A non-empty list means part of the posture is unknown, not absent; a malformed managed document also stops Claude Code from starting."},
			{Name: "config_dir", Type: proto.ColumnType_STRING, Description: "Agent configuration directory (CLAUDE_CONFIG_DIR or ~/.claude)."},
			{Name: "effective_permission_mode", Type: proto.ColumnType_STRING, Description: "Permission mode sessions start in, from managed then user settings (default, acceptEdits, plan, auto, dontAsk, bypassPermissions). Project and local files can change it for sessions started there; see agentreach_setting. For Codex: sandbox_mode/approval_policy, such as read-only/on-request."},
			{Name: "global_config_path", Type: proto.ColumnType_STRING, Description: "Path of the agent-written global config (~/.claude.json)."},
			{Name: "hooks_disabled", Type: proto.ColumnType_BOOL, Description: "Whether disableAllHooks is true: the managed value when managed settings set it, else the user value."},
			{Name: "install_method", Type: proto.ColumnType_STRING, Description: "How the agent was installed (native, npm, brew, ...)."},
			{Name: "logged_in", Type: proto.ColumnType_BOOL, Description: "Whether an OAuth account is recorded in the global config."},
			{Name: "managed_settings_path", Type: proto.ColumnType_STRING, Description: "Where the OS-level managed settings file would live; managed-settings.d, managed-mcp.json and a managed CLAUDE.md sit beside it."},
			{Name: "managed_settings_present", Type: proto.ColumnType_BOOL, Description: "Whether any managed document exists: cached server-managed settings, a macOS managed-preferences plist, managed-settings.json or a managed-settings.d drop-in, including one that could not be read."},
			{Name: "managed_source", Type: proto.ColumnType_STRING, Description: "Which admin source supplies the managed tier after first-wins selection: remote, plist, file, drop-ins, file + drop-ins, or a list ending in ', merged'. Empty when no source delivers a policy key."},
			{Name: "managed_sources_behavior", Type: proto.ColumnType_STRING, Description: "How several managed sources combine: first-wins (default) or merge."},
			{Name: "model_basis", Type: proto.ColumnType_STRING, Description: "Claude Code or Codex release the behaviour model (gates, defaults, protected files) was verified against."},
			{Name: "model_basis_stale", Type: proto.ColumnType_BOOL, Description: "True when the installed version is newer than model_basis, so modelled gates and defaults may lag the installed release; null when the installed version is unknown."},
			{Name: "network_approval", Type: proto.ColumnType_STRING, Description: "What decides a shell command connection to a host no rule allows: none, classifier, prompt, denied or unknown."},
			{Name: "network_approval_reason", Type: proto.ColumnType_STRING, Description: "Why network_approval has its value."},
			{Name: "network_strict_allowlist", Type: proto.ColumnType_BOOL, Description: "Whether strictAllowlist or allowManagedDomainsOnly refuses hosts outside the sandbox allowlist in every mode."},
			{Name: "plugins_enabled", Type: proto.ColumnType_INT, Description: "Count of plugins enabled in user settings."},
			{Name: "projects_known", Type: proto.ColumnType_INT, Description: "Count of project directories the agent has recorded."},
			{Name: "projects_trusted", Type: proto.ColumnType_INT, Description: "Count of recorded projects whose trust dialog was accepted."},
			{Name: "remote_settings_path", Type: proto.ColumnType_STRING, Description: "Where server-managed settings from the claude.ai admin console are cached (remote-settings.json in the config directory)."},
			{Name: "remote_settings_present", Type: proto.ColumnType_BOOL, Description: "Whether cached server-managed settings exist. They rank first among managed sources; see managed_source for whether they were selected."},
			{Name: "running_bypass_sessions", Type: proto.ColumnType_INT, Description: "Running Claude Code sessions whose command line carries a bypass flag or --permission-mode bypassPermissions (observed; see agentreach_launch_flag)."},
			{Name: "sandbox_auto_allow", Type: proto.ColumnType_BOOL, Description: "Whether autoAllowBashIfSandboxed lets sandboxed commands run without a prompt (default true)."},
			{Name: "bypass_available", Type: proto.ColumnType_BOOL, Description: "Whether bypassPermissions is in the mode cycle as far as settings show (defaultMode bypassPermissions in user or managed settings, not disabled). In an interactive terminal, plan mode then does not enforce its blocks. Launch flags are not visible."},
			{Name: "bypass_available_reason", Type: proto.ColumnType_STRING, Description: "Why bypass_available has its value, including when skipDangerousModePermissionPrompt shows a bypass launch flag was accepted before."},
			{Name: "auto_mode_drop_commands", Type: proto.ColumnType_JSON, Description: "Commands whose broad Bash allow rules auto mode drops (for a command C: C, C:*, C *, C* or C followed by a flag and *).", Transform: transform.FromField("Item.AutoModeDropCommands").Transform(marshalJSON)},
			{Name: "auto_mode_drop_reason", Type: proto.ColumnType_STRING, Description: "Where the auto mode drop list came from, with the Claude Code version and path, or why the fallback list is in use."},
			{Name: "auto_mode_drop_source", Type: proto.ColumnType_STRING, Description: "Source of the auto mode drop list: binary (read from the installed Claude Code), built_in (the list read from 2.1.312) or pinned."},
			{Name: "sandbox_enabled", Type: proto.ColumnType_BOOL, Description: "Whether the sandbox is on for every session: the managed value when managed settings set it, else the user value. A project file can turn it on for its own directory only, which agentreach_reach_file honours per project."},
			{Name: "shell_approval", Type: proto.ColumnType_STRING, Description: "What a shell command that is not read-only gets before it runs: none, classifier, prompt, denied or unknown."},
			{Name: "start_surface", Type: proto.ColumnType_STRING, Description: "How sessions are started for the gates agentreach models: terminal (assumed unless agentreach ran inside a session and could tell), print_or_sdk, vscode or desktop. The starting permission mode differs by surface; see surface_modes."},
			{Name: "start_surface_source", Type: proto.ColumnType_STRING, Description: "Where start_surface came from: assumed, or CLAUDE_CODE_ENTRYPOINT=<value> when agentreach ran inside a Claude Code session."},
			{Name: "surface_modes", Type: proto.ColumnType_JSON, Transform: transform.FromField("Item.SurfaceModes").Transform(marshalJSON), Description: "Starting permission mode per surface: terminal, print_or_sdk (claude -p and the Agent SDK, which deny calls that need approval in default mode) and vscode (claudeCode.initialPermissionMode, then the mode last picked)."},
			{Name: "user_settings_path", Type: proto.ColumnType_STRING, Description: "Path of the user settings file."},
			{Name: "user_settings_present", Type: proto.ColumnType_BOOL, Description: "Whether the user settings file exists."},
			{Name: "version", Type: proto.ColumnType_STRING, Description: "Agent version as reported by the binary."},
			{Name: "assessment_complete", Type: proto.ColumnType_BOOL, Description: "Whether every source was read and probes ran. False means some of the posture is unknown; do not read an empty finding list as safe."},
			{Name: "block_reads_outside_working_dirs", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Item.BlockReadsOutsideWorkDirs"), Description: "Whether permissions.blockReadsOutsideWorkingDirectories is true in managed or user settings, which fences home-directory files from the file tools and from sandboxed commands."},
			{Name: "permission_mode_source", Type: proto.ColumnType_STRING, Description: "Where the effective permission mode came from: launch_flag (a flag on the default claude alias or function, which outranks settings), managed, user, or built_in (the version-dependent default: auto from v2.1.283 in a terminal)."},
			{Name: "probe_skipped_reason", Type: proto.ColumnType_STRING, Description: "Why the probes did not run although they were asked for, for example because agentreach itself ran inside a sandbox and would have measured that sandbox instead of the agent; empty otherwise."},
			{Name: "probed", Type: proto.ColumnType_BOOL, Description: "Whether the reachability probes ran. When false, readable, reachable and writable columns are unknown and controls that need them report not assessed."},
			{Name: "sandbox_allow_unsandboxed_commands", Type: proto.ColumnType_BOOL, Transform: transform.FromField("Item.SandboxAllowUnsandboxed"), Description: "Whether a command that fails in the sandbox can be retried outside it (allowUnsandboxedCommands, default true)."},
			{Name: "sandbox_bypasses", Type: proto.ColumnType_STRING, Description: "Routes by which shell commands still run outside an enabled sandbox: unsandboxed_retry, excluded_commands, runtime_missing, filesystem_disabled; for Codex escalation_request and exec_policy_allow."},
			{Name: "sandbox_enforced", Type: proto.ColumnType_BOOL, Description: "Whether the sandbox is on with no bypass route: no unsandboxed retry, no excludedCommands, filesystem isolation on, and either the runtime is present or failIfUnavailable stops Claude Code from starting without it."},
			{Name: "sandbox_excluded_commands", Type: proto.ColumnType_INT, Description: "Number of excludedCommands entries that apply; each runs outside the sandbox with full access."},
			{Name: "sandbox_fail_if_unavailable", Type: proto.ColumnType_BOOL, Description: "Whether Claude Code exits at startup when the sandbox cannot start (failIfUnavailable, default false)."},
			{Name: "sandbox_filesystem_disabled", Type: proto.ColumnType_BOOL, Description: "Whether sandbox.filesystem.disabled turns off filesystem isolation."},
			{Name: "sandbox_runtime_available", Type: proto.ColumnType_BOOL, Description: "Whether the OS sandbox is present: sandbox-exec on macOS, bubblewrap and socat on Linux; null when the sandbox is off."},
			{Name: "vscode_initial_permission_mode", Type: proto.ColumnType_STRING, Description: "The claudeCode.initialPermissionMode value from VS Code user settings; empty when unset."},
			{Name: "vscode_process_wrapper", Type: proto.ColumnType_BOOL, Description: "Whether claudeCode.claudeProcessWrapper is set in VS Code user settings, which makes VS Code conversations start in Manual unless a mode is picked."},
			{Name: "web_fetch_approval", Type: proto.ColumnType_STRING, Description: "What a WebFetch to an arbitrary host gets: none, classifier, prompt, denied or unknown."},
			{Name: "web_fetch_denied", Type: proto.ColumnType_BOOL, Description: "Whether a bare WebFetch deny rule in managed or user settings removes the WebFetch tool."},
			{Name: "web_source_approval", Type: proto.ColumnType_STRING, Description: "What it takes for a fetched web page to reach the agent: none unless a deny or ask rule covers every domain, because preapproved documentation domains and domains with a saved allow rule fetch with no prompt; prompt when an ask rule on WebFetch(domain:*) covers every domain; denied when WebFetch is denied or turned off. The classifier never counts here: it does not see tool results."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromField("Item.Agent"), Description: "Title of the resource."},
		}),
	}
}

//// LIST HYDRATE FUNCTIONS

func listAgents(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	streamRows(ctx, d, func(s *posture.Snapshot) []posture.Agent { return s.Agents })
	return nil, nil
}

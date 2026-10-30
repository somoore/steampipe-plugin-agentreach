# Changelog

All notable changes to this plugin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Version reporting is shared and picks the numeric token, so Grok reports
  `1.0.46` instead of `[stable]` and OpenCode reports `2.2.4` instead of
  `v2.2.4`.
- A machine with no coding agent installed now produces no rows at all for
  Claude Code too, so the scan exits 0 with "No coding agent or harness
  found" instead of reporting a phantom agent as not assessed.
- Codex's internet reach-host row now carries `reachable` (from
  `sandbox_mode`, `network_access` and exec-policy allow rules), `service`
  and `probe_method`, matching the same row for Claude Code; with the
  experimental `network_proxy` on it stays unknown instead of claiming
  either way.
- Codex reach files are deduplicated by path, so the home dotenv reached
  from a session started in `~` no longer appears twice.
- Two gate bugs found by the first end-to-end run against a real machine
  with all five agents installed:
  - Codex MCP tool approval now follows the session policy when
    `default_tools_approval_mode` is unset (the docs make it optional with
    an `auto` value, so unset means the policy decides), and project-scoped
    servers inherit their project session's gate instead of always
    reporting unknown. On the test machine this turned 6,182 paths from
    unknown to their real gate under `approval_policy = never`.
  - Grok no longer reads `~/.grok/config.toml` twice when the home
    directory is a registered project (once as the user layer and once as
    a project layer), which duplicated every setting row.

### Changed

- No release is pinned. `model_basis` and `model_basis_stale` are gone:
  versions change weekly, so a stored baseline only ever went stale.
  agentreach reports the version each binary reports about itself, reads
  version-dependent behaviour from the installed release where it can
  (auto mode's rule-drop list), and keeps the weekly docs drift alarm for
  the rest. A construct the model cannot interpret comes back unknown or
  not assessed, never guessed.
- Faster feedback. The pre-commit hook runs the fast checks only (about a
  second; the fixture suite runs in CI before merge), the 19 dashboard
  renders run in parallel, and CI skips each job's heavy steps when the
  diff is markdown outside docs/tables while still reporting every
  required status check.
- License changed from Apache-2.0 to MIT.
- Supply chain: every GitHub Action is pinned to a commit SHA; the mod's
  CI installs Steampipe and Powerpipe from pinned releases verified
  against their published checksums instead of piped install scripts, and
  pins PyYAML; `make test` runs `go mod verify` (go.sum already pins every
  dependency's hash). SECURITY.md and CODEOWNERS added, and main is
  protected: pull requests must pass CI.
- Commit history: the repository was re-created on 2026-10-29 with a
  fresh single-commit history (author email addresses are GitHub's
  noreply form). This CHANGELOG is the record of what changed and when.
- Dead code removed (ruleByID, the builtin-list droppedInAutoMode wrapper,
  ccCollector.addGlob, pluginEnabled, mergeSettings, hostOf, SHA256File,
  gitRemote) - the collector keeps one implementation per fact.

### Added

- ACP harness discovery. agentreach does not integrate with the Agent
  Client Protocol (no dry-run permission check exists; a live session would
  put an LLM in the verdict path and would not be inert), but it records
  the harness: `agentreach_agent.acp_harness` names the editor agent
  servers that can start each agent (Zed's `agent_servers` in
  ~/.config/zed/settings.json), a start surface whose options are not
  visible - the same blind spot as the Agent SDK and VS Code surfaces. An
  ACP audit proxy is parked as a separate idea (issue #1).
- OpenCode, Cline and Grok Build collectors. Discovery is automatic for
  all five agents: nothing is reported for an agent that is not installed,
  and a machine with no coding agent or harness at all is a clean result
  (the CLI prints "No coding agent or harness found on this machine" and
  exits 0; every report carries the discovered inventory, and the mod's
  dashboard opens with a discovered-agents table).
  - OpenCode (opencode.ai/docs and opencode.ai/v2/docs): config layers
    merged per key (managed, global, OPENCODE_CONFIG, project), both
    permission formats modelled to gates - v1's per-tool permission object
    (allow/ask/deny, pattern objects, permissive defaults) and v2's
    permissions rule array (last match wins, allow-all base policy, shell
    and subagent action names) - permission rules as sandbox_rule rows,
    MCP servers, AGENTS.md, markdown agents and the instructions list.
    Verified against 2.2.1, with a v-prefixed version string tolerated.
  - Grok Build (docs.x.ai/build): user/project/managed/requirements TOML
    layers, permission_mode (ask/auto/always-approve, legacy approval_mode
    and yolo) modelled to gates, [permission] allow/deny rules as rows,
    sandbox profiles (off/workspace/devbox/read-only/strict with the
    Linux-only network note), MCP servers, AGENTS.md. Early beta: no
    release pin, the docs drift alarm watches the pages.
  - Cline (docs.cline.bot): the ~/.cline tree and VS Code extension
    surface, global settings (secrets skipped), MCP servers from every
    copy, rules (.cline/rules, .clinerules, ~/Documents/Cline/Rules,
    AGENTS.md) with git provenance. Approval gates are honestly unknown:
    auto-approve and YOLO mode live in app state agentreach cannot read.
- Drift is now measured, not assumed. `agentreach_agent.model_basis` and
  `model_basis_stale` name the Claude Code (2.1.312) and Codex CLI (0.155.1)
  releases the behaviour model was verified against and flag an installed
  agent that is newer, so a scan says when findings may lag instead of
  passing silently; the CLI repeats it as an assumption line and
  `agentreach version` prints the bases. `ci/docs_drift.sh`
  (`make docs-drift`) fails when any cited Claude Code document's content
  hash changed since `ci/docs-baseline.sha256` (`make docs-baseline`
  refreshes it after re-verification), and the weekly claude-code-drift
  workflow runs it beside the auto-mode drop-list check.

## v0.2.0 - 2026-10-29

### Renamed

- The project is now **agentreach** (formerly casf, the "Coding Agent
  Security Framework" placeholder): tables are `agentreach_*`, the CLI is
  `agentreach`, the package is `agentreach`, the connection config is
  `agentreach.spc` and the Claude Code skills are `agentreach-posture` and
  `agentreach-verify`. Install paths change from
  `~/.steampipe/plugins/local/casf` to `~/.steampipe/plugins/local/agentreach`
  and the connection key from `local/casf` to `local/agentreach`: re-run
  `make install` and update `~/.steampipe/config/casf.spc` (rename the
  connection and its `plugin` key). Snapshot JSON is unchanged apart from
  prose that named the tool.

### Added

- Fixture fx-managed: the first fixture home with managed settings, so the
  mod's `managed_only_sql` hardening template gets its ok branch
  (`allowManagedHooksOnly` set in managed settings) and its alarm branch
  (`forceRemoteSettingsRefresh` pasted into user settings, where Claude Code
  ignores it) on a real host. Before this every managed-only control
  returned skip on every fixture.
- Codex integrity and the remaining legs: hooks from `hooks.json`, inline
  `[hooks]` and plugins, with Codex hook trust (`runs` false until a hash is
  recorded in `[hooks.state]`, null once it is), plus `notify`; plugins from
  `[plugins."<name>@<marketplace>"]` with their skills, hooks and MCP
  servers; skills from `~/.agents/skills`, `$CODEX_HOME/skills`,
  `/etc/codex/skills` and each project's `.agents/skills` and
  `.codex/skills`; local services gated by the Codex sandbox; and
  `agentreach_write_target` rows from writable roots, the protected `.git`,
  `.agents` and `.codex`, and `apply_patch` approval, so Codex gets
  integrity paths. Facts follow the docs and the codex-cli 0.155.1 source.
- Local services are probed once per collection and shared by every agent.
- Tables `agentreach_path` (candidate confidentiality and integrity paths, with
  evidence per leg), `agentreach_leg` (each leg those paths are built from, listed
  even when it meets no path), `agentreach_write_target` (guardrails, instruction files, CI
  workflows, dependency manifests, git hooks and shell startup files the agent
  can change, and whether a human approves the write) and `agentreach_environment`
  (detected proxies, containers and endpoint agents, and declared controls).
  The legs are computed once, in Go; the mod reads them.
- `host` and `snapshot_id` on every table, and a `snapshot_paths` connection
  option that reads snapshot JSON files instead of collecting (fleet mode).
- Evidence columns: `readable_evidence`, `reach_evidence`,
  `reachable_evidence`, `write_evidence`, `writable_evidence`, and
  `agentreach_agent.assessment_complete`.
- Sandbox enforcement on `agentreach_agent`: `sandbox_enforced`,
  `sandbox_bypasses`, `sandbox_allow_unsandboxed_commands`,
  `sandbox_fail_if_unavailable`, `sandbox_runtime_available`,
  `sandbox_filesystem_disabled`, `sandbox_excluded_commands`, plus
  `block_reads_outside_working_dirs`, `web_fetch_denied` and
  `permission_mode_source`.
- Observed mode (`observe = true`): the file and loopback probes run again
  inside srt configured from the effective settings; `observed_via_sandbox`
  and `model_agrees` record the result.
- Review ledger (`review_ledger`): instruction files reviewed at their current
  SHA-256 stop counting as untrusted. Hidden Unicode, HTML comments, URLs and
  includes are `review_signals`, not verdicts.
- Hooks report `url`, `args`, `if`, `effective_timeout`, `origin`, `runs` and
  `runs_reason`; plugin MCP servers appear with `plugin_name`; hooks in skill
  and subagent frontmatter are found.
- Approval model (`pkg/posture/approval.go`): what stands between the agent
  and an action, as `none`, `classifier`, `prompt`, `denied` or `unknown`.
  `agentreach_agent` gains `shell_approval`, `network_approval` (with
  `network_approval_reason`), `web_fetch_approval`, `sandbox_auto_allow` and
  `network_strict_allowlist`; `agentreach_mcp_server` gains `tool_approval`;
  `agentreach_sandbox_rule` gains `carries_network`, `dropped_in_auto_mode` and
  `approves_network`; `agentreach_path` gains `approval`, the gate on the exit or
  the write. Follows the permissions, permission-modes and sandboxing docs:
  sandbox auto-allow (`autoAllowBashIfSandboxed`), hosts outside
  `allowedDomains` decided by mode unless `strictAllowlist` or
  `allowManagedDomainsOnly` refuses them, the unsandboxed retry, and auto
  mode dropping broad allow rules.
- `cmd/agentreach-fixtures` builds fixture homes and writes byte-stable snapshot
  JSON for the mod's behavioural tests.
- `agentreach` CLI (`cmd/agentreach`, `make cli`): `agentreach scan` prints text, JSON or
  SARIF, reads snapshots (`--from`), writes one (`--snapshot-out`), and exits
  0 clean, 1 failing, 2 not assessed, 3 error (`docs/cli.md`).
- A skill-only Claude Code plugin (`claude-plugin/`, listed in
  `.claude-plugin/marketplace.json`) with the `agentreach-posture` skill. It ships
  no hooks; the opt-in SessionStart snippet is in its README.
- Codex CLI collector: `config.toml` (an allowlist of keys), MCP servers,
  `AGENTS.md` files and project trust, as rows with `agent = 'codex'`.
- Codex gate model (`pkg/posture/codexmodel.go`): `sandbox_mode`,
  `approval_policy` (on-failure as on-request; untrusted projects prompt for
  every command), `network_access`, exec-policy `allow` rules for
  network-capable commands, web search, MCP `approval_mode`, and the
  system, user, trusted-project and legacy managed layers plus
  `requirements.toml` allow-lists. Codex rows fill `shell_approval`,
  `network_approval`, `read_approval`, `effective_permission_mode`
  (`sandbox/approval`), reach rows for sensitive files and the internet, and
  per-project gates; Codex now gets legs and paths. AGENTS.md files use the
  same git-provenance rule as CLAUDE.md. Permission profiles, an unparsable
  config and a disallowed managed value leave the gates `unknown`.
  `Options.CodexSystemDir` points tests at a fake `/etc/codex`.
- `make test-srt SRT=<path>` runs observed mode against a real srt.
- Per-project gates (`agentreach_project`): `effective_permission_mode`,
  `permission_mode_source`, `shell_approval`, `network_approval`,
  `network_approval_reason`, `web_fetch_approval`, `read_approval` and
  `sandbox_allowed_domains`. A session started in a project uses that
  project's mode, sandbox and saved rules; paths of project sessions are
  gated by them, and project `WebFetch(domain:...)` rules join that project's
  allowlist.
- `agentreach_reach_host.approval`: what a shell connection to that service needs.
  A local port no rule allows is decided by the mode, like any unlisted host.
- `agentreach_reach_file.reachable_via_retry` and `read_approval`: a file only the
  unsandboxed retry reaches stays a private leg, gated by the retry.
- Plan mode is modelled as auto's classifier unless auto is disabled or
  `useAutoModeDuringPlan` is false.
- `~/.claude/settings.local.json` is read as local scope.
- Path counting fixes (live Codex went from 62,103 paths to about 9,800,
  Claude Code from 9,915 to about 4,100):
  - A plugin's files are one untrusted source (`src:plugin:<name>`), as its
    hooks already were; each skill was a separate source.
  - Codex no longer reads `~/.codex` as a project layer when the home
    folder is a trusted project (`discover_project_layers` skips the
    CODEX_HOME `.codex`, 0.155.1); its MCP servers were counted twice.
  - A project copy of a private file already counted machine-wide with
    the same gate is dropped (Codex's project `.env` for the home project).
  - `path_id` carries `#<project_dir>` for project-session paths, so ids
    are unique.
- Launch flags: new table `agentreach_launch_flag` reads shell aliases and
  functions in startup files (configured) and the command lines of running
  `claude` and `codex` sessions (observed, live only), keeping flag names and
  fixed-set values only. Flags on the default `claude` alias or function are
  modelled: `--dangerously-skip-permissions` / `--permission-mode` set the
  effective mode (`permission_mode_source = launch_flag`),
  `--allow-dangerously-skip-permissions` makes bypass available,
  `--allowedTools` / `--disallowedTools` add machine-wide rules (scope
  `launch_flag`), `--settings` loads that file. `disableBypassPermissionsMode`
  still wins. New `agentreach_agent.running_bypass_sessions`.
- Codex launch flags on the default `codex` alias or function (`--yolo`,
  `--approve-for-me`, `-s`, `-a`, `-c sandbox_mode|approval_policy|
  sandbox_workspace_write.network_access`) form a config layer below managed
  config and above project, user and system config
  (`permission_mode_source = launch_flag`). `--profile` and other `-c` keys
  are listed, not modelled. New fixture fx-flags.
- Auto mode's rule drop is read from the installed Claude Code at scan time
  (`pkg/posture/autodrop.go`): the command list is parsed from the program's
  bytes (nothing runs), the matcher's shape is checked, and the result is
  cached per binary. When it cannot be read, agentreach uses the list read from
  2.1.312 and says so. New `agentreach_agent` columns `auto_mode_drop_commands`,
  `auto_mode_drop_source` (binary, built_in, pinned) and
  `auto_mode_drop_reason`; `Options.AutoModeDropCommands` pins it. `make
  check-claude-code` and the weekly `claude-code-drift` workflow fail when
  the latest release's list cannot be read or differs from the fallback.
  The matching (C, C:*, C *, C*, or C plus a flag and *) keeps
  `Bash(npm run build:*)`.
- `agentreach_agent.bypass_available` and `bypass_available_reason`: with
  bypassPermissions in the mode cycle (user or managed `defaultMode`, not
  disabled), plan mode runs planning commands and protected-path writes with
  no prompt in an interactive terminal. `skipDangerousModePermissionPrompt`
  is reported as a sign that bypass launch flags were accepted before.
- `agentreach_plugin.pinned` reads `unknown` as no version and an all-digit date
  version as a release.
- Local MCP server exits are one per project: a server that loads only in
  one project no longer pairs with sources in other sessions.
- Fixture fx-codex (Codex gates, trusted and untrusted projects).
- `agentreach_write_target.session_dir`: home-directory targets get one more row
  per project whose own mode, sandbox setting or write rules differ, with
  that project's gates; integrity paths in that project's sessions use it.
- Secret scan: `ci/secrets.sh` (`make secrets`, pre-commit and CI) checks
  for credential files, credential-shaped text (printing file names only)
  and runs gitleaks over the history and the tree.
- Fixture options: `Options.GOOS`, `Arch`, `SandboxRuntime` and `Services`
  pin the platform and the probe results, so `cmd/agentreach-fixtures` writes the
  same snapshots on any build machine; CI generates them twice and diffs.
  New fixtures fx-services, fx-strict-services, fx-project and fx-unknown.

### Changed

- Steampipe Plugin SDK v6.1.0 (requires Go 1.26).
- Credential-shaped text is redacted on every surface (hook commands, URLs and
  args, MCP args and URLs, permission and sandbox patterns, setting strings);
  rows that lost text carry `redacted`.
- `reachable_via_bash` follows the sandbox model: an `allowRead` rule narrower
  than a `denyRead` region re-opens the path; a repository `allowRead` cannot
  re-open a managed or user deny; `allowManagedReadPathsOnly` and
  `blockReadsOutsideWorkingDirectories` are applied. `bash_bypass` names the
  routes that stay open.
- Exit legs follow the approval model. With the sandbox on, the internet is
  still an exit unless the sandbox refuses unlisted hosts (previously the
  sandbox was assumed to deny them); a leg that is refused is dropped; saved
  Bash allow rules for network-capable commands open a per-project exit;
  integrity paths include writes that need a prompt, marked by `approval`.
- `WebFetch(domain:...)` allow rules in managed and user settings join the
  sandbox allowlist, as the sandboxing docs describe.
- Permission-protected files (`.mcp.json`, `.claude.json`, shell startup
  files, `.npmrc` and the rest of the documented list) are matched by name;
  only the protected directories were matched before, so `.mcp.json` edits
  were reported as auto-approved.
- The effective permission mode falls back to the version-dependent built-in
  default (auto from v2.1.283) instead of `default`.
- `strictKnownMarketplaces` is read from managed settings only; plugin
  enablement is resolved per scope (managed, local, project, user).
- Snapshot cache: collection runs on its own context with a timeout, a
  cancelled query no longer caches a truncated snapshot, and each connection
  locks only its own entry (tested in `agentreach/cache_test.go`).
- Instruction-file discovery is recursive; a leading BOM is not counted as
  hidden Unicode; supplementary variation selectors and Hangul fillers are.

- Managed tier now follows the documented source ranking (remote settings,
  macOS managed-preferences plist, `managed-settings.json` merged with
  `managed-settings.d/*.json`) with `managedSourcesBehavior` first-wins or
  merge, and the cross-source locks (`allowManagedReadPathsOnly`,
  `allowManagedDomainsOnly`, `allowAllClaudeAiMcps`,
  `allowManagedMcpServersOnly`) read from every admin source. Previously the
  file was merged over the remote cache with the file winning, which is
  backwards. `agentreach_agent` gains `managed_source` and
  `managed_sources_behavior`; every managed document is still listed in
  `agentreach_setting`, with `applies = false` on a source that lost selection. An
  empty `{}` remote cache no longer counts as a policy.
- `managed-mcp.json` servers appear in `agentreach_mcp_server` at `managed` scope
  and a managed `CLAUDE.md` in `agentreach_instruction_file`.
- Project and local settings now contribute deny rules and `sandbox.enabled`
  for files inside their own project: `agentreach_reach_file` evaluates a project's
  `.env` against that project's `.claude/settings*.json`. Relative deny and
  ask patterns match at any depth (`Read(.env)` means `**/.env`), allow
  patterns stay anchored, as the permissions docs specify. Home-directory
  files are still judged by managed and user rules only, because a project
  rule cannot protect them from sessions started elsewhere.
- `.mcp.json` approvals are resolved from `disabledMcpjsonServers` in any
  settings file, `enabledMcpjsonServers` and `enableAllProjectMcpServers` in
  managed and user settings, in project and local settings once the folder is
  trusted, and the choices recorded in `~/.claude.json`. Previously only the
  `~/.claude.json` record and user `enableAllProjectMcpServers` were read.
- `agentreach_setting` no longer exposes values under `env.*`, `*Helper` keys or
  header maps unless they are plain switches; such rows carry `redacted` and
  `looks_like_secret`.
- `sandbox_enabled`, `hooks_disabled` and `allowAllUnixSockets` take the
  managed value when managed settings set it, else the user value, instead of
  OR-ing both.
- `agentreach_agent.collect_errors` lists files that could not be read or parsed. A
  malformed managed document now counts as present and is reported, since
  Claude Code refuses to start on it.
- `looksLikeSecret` accepts tokens containing `/` (AWS secret keys) and URLs
  with a userinfo password, and still rejects paths. `@latest` and other
  dist-tags no longer count as pinned. `uv run <script.py>` classifies as a
  local Python launcher, not a registry launcher. Multi-line Bash permission
  rules parse.

## v0.1.1 - 2026-10-29

Tagged from main after v0.1.0 with no changelog entry of its own; everything
between v0.0.3 and the rename is recorded under v0.2.0.

## v0.1.0 - 2026-10-29

Tagged from main before the rename; everything it shipped is recorded under
v0.2.0.

## v0.0.3 - 2026-10-27

### Added

- `agentreach_plugin`: one row per install record in `installed_plugins.json`, with
  `pinned` (release tag vs floating commit sha), `enabled` (the
  `enabledPlugins` decision, null when none), `has_hooks`, `has_mcp`,
  `has_instruction_file`, `skill_count`, `agent_count`, `command_count`,
  `writable_by`, timestamps and the install path. Existence and counts only.
- `agentreach_marketplace`: one row per entry in `known_marketplaces.json`, with
  `source_type`, `source_repo`, `official`, `auto_update`, `in_extra_known`
  and `in_strict_allowlist` (evaluated against a `strictKnownMarketplaces` or
  `allowedMarketplaces` policy; null when no policy exists).

- Server-managed settings (Team and Enterprise, cached at
  `~/.claude/remote-settings.json`) are ingested at `managed` scope with their
  own `source_path`, after the file-based `managed-settings.json`, and count
  toward effective sandbox, permission, hook and MCP rules. `agentreach_agent` gains
  `remote_settings_present` and `remote_settings_path`;
  `managed_settings_present` is now true when either source exists.

### Fixed

- A session started in the home directory registers `$HOME` as a project.
  Its `.claude/settings.json` and `.claude/{rules,skills,agents,commands}`
  are the user-scope files and were ingested a second time at project scope.
  They now appear once, at user scope.

## v0.0.2 - 2026-10-27

### Added

- `agentreach_instruction_file.plugin_name`, `git_last_author`, `third_party`:
  provenance for every instruction file. `third_party` is true for
  plugin-provided files and for files last committed by someone who is
  neither the configured git identity nor the repository's most frequent
  author. Being tracked in git is no longer treated as a finding.
- `agentreach_hook.plugin_name`, `plugin_enabled`, `third_party`.
- `agentreach_reach_file.tier`: blast-radius rank (1 keys, 2 tokens, 3 leaky files).
- `agentreach_reach_host.loopback`.

### Changed

- Plugin hooks, skills, subagents and commands are read from
  `installed_plugins.json` only. Marketplace clones are catalogs and are
  ignored, which removes phantom hooks from plugins that were never installed.
- `.cursorrules` and Copilot instruction files are no longer collected for
  Claude Code, which does not read them.

## v0.0.1 - 2026-10-27

### Added

- Initial release. Claude Code collector with nine tables: `agentreach_agent`,
  `agentreach_project`, `agentreach_setting`, `agentreach_hook`, `agentreach_mcp_server`,
  `agentreach_instruction_file`, `agentreach_sandbox_rule`, `agentreach_reach_file`,
  `agentreach_reach_host`.
- Inert reachability probes: one-byte open-for-read on a catalogue of
  sensitive paths, TCP dial on discovered listeners, Unix socket dial on
  well-known sockets. Contents are never read or stored.
- Effective-rule resolution across managed, user, project and local scopes
  for permission mode, sandbox filesystem/network/credential rules, and
  `Read` deny rules, so `reachable_via_bash` and `reachable_via_read_tool`
  reflect what the agent would actually be allowed to do.
- `pkg/posture` collector library with no Steampipe dependency, and a
  `agentreach-snapshot` command that dumps it as JSON.

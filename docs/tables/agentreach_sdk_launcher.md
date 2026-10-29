# Table: agentreach_sdk_launcher

An application built on the Agent SDK starts Claude Code with options its code passes, not from a settings file agentreach can read. Those options decide the session's gates: `permissionMode`, `allowDangerouslySkipPermissions`, `canUseTool` (approvals go to the application's callback, not a person), `settingSources` (omitted, the SDK reads user, project and local settings like the CLI; `[]` reads none) and the `sandbox` option.

agentreach sees them two ways:

- **While a session runs**: the SDK passes them to the CLI as flags (`--permission-mode`, `--setting-sources`, `--permission-prompt-tool stdio`, `--input-format stream-json`). With probes on, `agentreach_launch_flag` lists them for each running session, as observed.
- **In the source**: this table. agentreach looks in the repository of every known project for a manifest (`package.json`, `pyproject.toml`, `requirements.txt` and the like, at the root or up to two levels down) that names `@anthropic-ai/claude-agent-sdk` or `claude-agent-sdk`, then reads the TypeScript, JavaScript and Python files under it that import the SDK. It never walks the home directory, `node_modules` or a virtual environment.

The source read is a heuristic over the file's text. A literal mode from the fixed set is kept; a mode built at run time sets `dynamic_permission_mode`; code that is commented out still counts. Only mode and setting-source names leave the file.

## Examples

### Basic info

```sql
select
  path,
  language,
  permission_modes,
  setting_sources,
  can_use_tool
from
  agentreach_sdk_launcher;
```

### List launchers that start in bypassPermissions

```sql
select
  path,
  permission_modes,
  skip_permissions_allowed,
  sandbox_enabled
from
  agentreach_sdk_launcher
where
  permission_modes ? 'bypassPermissions'
  or skip_permissions_allowed;
```

### List launchers that read the machine's settings

```sql
select
  path,
  project_dir
from
  agentreach_sdk_launcher
where
  setting_sources is null
  or setting_sources ? 'user';
```

### List the options running SDK sessions were started with

```sql
select
  name,
  flag,
  value,
  effect
from
  agentreach_launch_flag
where
  source = 'running_session'
  and flag in ('--permission-mode', '--setting-sources', '--permission-prompt-tool', '--input-format');
```

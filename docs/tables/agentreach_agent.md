# Table: agentreach_agent

One row per installed coding agent: version, install method, where its config lives, and the effective top-level posture (permission mode, sandbox, managed settings, hooks) after resolving the managed tier (remote, plist, file and drop-ins under first-wins or merge) and the user settings.

## Examples

### Basic info

```sql
select
  agent,
  version,
  install_method,
  effective_permission_mode,
  sandbox_enabled
from
  agentreach_agent;
```

### Compare the gates of each agent

For Codex, `effective_permission_mode` is `sandbox_mode/approval_policy`
for a folder with no trust decision; `agentreach_project` has the gate of each
trusted or untrusted project.

```sql
select
  agent,
  effective_permission_mode,
  shell_approval,
  network_approval,
  network_approval_reason,
  sandbox_bypasses
from
  agentreach_agent;
```

### Find agents running without a sandbox or managed policy

An agent with no managed settings and no sandbox is governed only by files the
user (and therefore the agent itself) can edit.

```sql
select
  agent,
  version,
  effective_permission_mode
from
  agentreach_agent
where
  not sandbox_enabled
  and not managed_settings_present;
```

### Compare trusted projects to known projects

```sql
select
  agent,
  projects_known,
  projects_trusted,
  round(100.0 * projects_trusted / nullif(projects_known, 0)) as pct_trusted
from
  agentreach_agent;
```

### List config file locations for audit

```sql
select
  agent,
  global_config_path,
  user_settings_path,
  user_settings_present,
  managed_settings_path,
  remote_settings_present,
  managed_settings_present
from
  agentreach_agent;
```

### Show which managed source is in force and whether anything failed to load

```sql
select
  agent,
  managed_source,
  managed_sources_behavior,
  remote_settings_present,
  collect_errors
from
  agentreach_agent;
```

### Show what an injected shell command or web request would need

```sql
select
  effective_permission_mode,
  sandbox_enabled,
  sandbox_auto_allow,
  shell_approval,
  network_approval,
  network_approval_reason,
  web_fetch_approval
from
  agentreach_agent;
```

### Check where the auto mode rule-drop list came from

```sql
select
  auto_mode_drop_source,
  auto_mode_drop_reason,
  jsonb_array_length(auto_mode_drop_commands) as commands
from
  agentreach_agent
where
  agent = 'claude_code';
```

### Check whether the behaviour model matches the installed release

```sql
select
  agent,
  version,
  model_basis,
  model_basis_stale
from
  agentreach_agent;
```

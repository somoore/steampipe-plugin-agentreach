# Table: agentreach_setting

Every leaf key from every settings file the agent loads (managed, user, project, local), flattened to a dotted path with its JSON value. Hooks are excluded here and surfaced in `agentreach_hook`. Lists such as `permissions.allow` are kept whole.

Values under `env.*`, `*Helper` keys and header maps are redacted unless they are plain switches (`0`, `1`, `true`, `false`, digits); the row then carries `redacted = true` and `looks_like_secret`. Every managed document found on the machine is listed, but only the source Claude Code selects carries `applies = true` (see `agentreach_agent.managed_source`).

## Examples

### Basic info

```sql
select
  scope,
  key,
  value,
  source_path
from
  agentreach_setting;
```

### Show the permission mode at every scope

Later scopes override earlier ones (managed > local > project > user), so
seeing all four explains the effective mode on `agentreach_agent`.

```sql
select
  scope,
  project_dir,
  value as default_mode
from
  agentreach_setting
where
  key = 'permissions.defaultMode'
order by
  scope;
```

### Find project settings that auto-enable all project MCP servers

```sql
select
  scope,
  project_dir,
  source_path
from
  agentreach_setting
where
  key = 'enableAllProjectMcpServers'
  and value = 'true'::jsonb;
```

### List every allow rule across all scopes

```sql
select
  scope,
  project_dir,
  jsonb_array_elements_text(value) as allow_rule
from
  agentreach_setting
where
  key = 'permissions.allow'
order by
  scope,
  allow_rule;
```

### Find credentials pasted into settings files

The value is never stored; the row only says that one was there.

```sql
select
  scope,
  source_path,
  key
from
  agentreach_setting
where
  redacted
  and looks_like_secret;
```

### List managed settings that are deployed but not in effect

A lower-ranked managed source loses to the selected one under first-wins.

```sql
select
  source_path,
  key,
  value
from
  agentreach_setting
where
  scope = 'managed'
  and not applies;
```

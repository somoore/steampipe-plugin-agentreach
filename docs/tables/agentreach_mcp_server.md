# Table: agentreach_mcp_server

One row per MCP server definition the agent can load, from user, project (`.mcp.json`) and local scope. Columns classify how it is launched, whether the package is pinned, and whether its `env` block carries a literal credential. Secret values are never stored, only the boolean.

## Examples

### Basic info

```sql
select
  name,
  scope,
  transport,
  launcher_type,
  command,
  url
from
  agentreach_mcp_server;
```

### Find servers with an inline secret in their env block

`has_inline_secret` is true when an env value looks like a real credential
(known token prefixes, or a long opaque value under a key named like a secret).
Env references such as `${OPENAI_API_KEY}` do not count.

```sql
select
  name,
  scope,
  source_path,
  env_keys
from
  agentreach_mcp_server
where
  has_inline_secret;
```

### Find npx and uvx servers that are not version-pinned

An unpinned `npx -y some-server` fetches whatever the registry serves today.

```sql
select
  name,
  scope,
  launcher_type,
  args
from
  agentreach_mcp_server
where
  launcher_type in ('npx', 'uvx')
  and not pinned;
```

### List project-scoped servers and their approval state

`enabled` is null when the user has not yet made a per-project decision for a
`.mcp.json` server. `agentreach_setting` key `enableAllProjectMcpServers` can
approve them wholesale.

```sql
select
  project_dir,
  name,
  launcher_type,
  enabled
from
  agentreach_mcp_server
where
  scope = 'project'
order by
  project_dir,
  name;
```

### Find remote servers over plain HTTP

```sql
select
  name,
  scope,
  url
from
  agentreach_mcp_server
where
  transport in ('http', 'sse')
  and url like 'http://%';
```

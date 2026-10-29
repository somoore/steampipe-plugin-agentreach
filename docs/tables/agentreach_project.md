# Table: agentreach_project

One row per project directory the agent has opened (plus any `project_dirs` from the connection config): trust state, whether it is a git repo and where it pushes, and which project-level config files exist.

## Examples

### Basic info

```sql
select
  project_dir,
  trusted,
  is_git_repo,
  git_remote,
  last_start_time
from
  agentreach_project
where
  exists;
```

### Show what a session started in each project needs to act

A project's own `defaultMode`, sandbox setting and saved rules can make it
looser or stricter than the machine-wide answer on `agentreach_agent`.

```sql
select
  project_dir,
  effective_permission_mode,
  permission_mode_source,
  shell_approval,
  network_approval,
  network_approval_reason,
  read_approval
from
  agentreach_project
where
  exists
order by
  network_approval = 'none' desc,
  project_dir;
```

### List trusted projects that carry their own MCP servers or hooks

A trusted project's `.mcp.json` and `.claude/settings.json` are loaded
automatically, so anyone who can push to the repo can add tools and hooks.

```sql
select
  project_dir,
  git_remote,
  has_mcp_json,
  has_project_settings
from
  agentreach_project
where
  trusted
  and (has_mcp_json or has_project_settings);
```

### Find projects with a local settings override

`.claude/settings.local.json` is git-ignored by convention and is where
per-machine `allow` rules accumulate.

```sql
select
  project_dir,
  allowed_tools
from
  agentreach_project
where
  has_local_settings;
```

### Count projects by trust and remote host

```sql
select
  trusted,
  split_part(split_part(git_remote, '://', 2), '/', 1) as remote_host,
  count(*)
from
  agentreach_project
where
  exists
group by
  trusted,
  remote_host
order by
  count desc;
```

# Table: agentreach_plugin

One row per plugin install record in `installed_plugins.json`. A plugin installed at user scope and again for a project is two rows. The table says where each plugin came from, whether its version is a release tag or a floating commit, whether an `enabledPlugins` decision exists, and what the plugin ships: hooks (which run outside the sandbox), MCP servers, skills, subagents and commands. Only existence and counts are read; no plugin file contents.

For Codex, rows come from `[plugins."<name>@<marketplace>"]` in `config.toml` (enabled unless `enabled = false`), resolved to the active version under `$CODEX_HOME/plugins/cache`. agentreach never walks that cache: entries the config does not name do not load.

## Examples

### Basic info

```sql
select
  full_name,
  scope,
  version,
  pinned,
  enabled
from
  agentreach_plugin;
```

### List plugins that ship hooks or MCP servers

Hooks run with your privileges on every matching event and MCP servers add tools to every session, so these plugins deserve a closer look than a skills-only plugin.

```sql
select
  full_name,
  marketplace,
  has_hooks,
  has_mcp,
  enabled
from
  agentreach_plugin
where
  has_hooks
  or has_mcp;
```

### Find plugins whose version floats with the marketplace head

A version that is just a commit sha means the next marketplace refresh can change the plugin's code without a visible version bump.

```sql
select
  full_name,
  version,
  git_commit_sha,
  last_updated
from
  agentreach_plugin
where
  pinned is distinct from true;
```

### Count what each plugin adds to the agent

```sql
select
  full_name,
  skill_count,
  agent_count,
  command_count,
  has_instruction_file
from
  agentreach_plugin
order by
  skill_count + agent_count + command_count desc;
```

### List plugins with no enabled decision

A plugin whose install record exists but whose `enabledPlugins` entry is missing loads by default.

```sql
select
  full_name,
  scope,
  project_dir
from
  agentreach_plugin
where
  enabled is null;
```

### Find install directories writable by group or others

```sql
select
  full_name,
  install_path,
  writable_by
from
  agentreach_plugin
where
  writable_by <> 'owner';
```

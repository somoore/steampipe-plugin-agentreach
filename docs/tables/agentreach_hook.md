# Table: agentreach_hook

One row per hook command the agent will run on a lifecycle event, from every scope including installed plugins. Hooks execute with the user's full privileges outside any permission check, so who can edit the file that defines them matters as much as what they run.

For Codex (`agent = 'codex'`), rows come from `hooks.json` and inline `[hooks]` in each config layer, plugin `hooks/hooks.json` and the `notify` program. Codex runs a non-managed hook only after you trust its current definition: `runs` is false when no trust is recorded, the hook is turned off in `[hooks.state]`, hooks are off, or the project is not trusted, and null when trust is recorded, because agentreach does not recompute the hash (a definition changed since is skipped by Codex but still counted here). Hook commands run with no sandbox.

## Examples

### Basic info

```sql
select
  scope,
  event,
  matcher,
  hook_type,
  command
from
  agentreach_hook;
```

### Count hooks by scope and event

```sql
select
  scope,
  event,
  count(*)
from
  agentreach_hook
group by
  scope,
  event
order by
  count desc;
```

### Find hooks defined in files that are tracked in git

A hook in a committed `.claude/settings.json` runs on every machine that
clones the repo. That is a feature for teams and a supply-chain risk for
anyone cloning untrusted code.

```sql
select
  project_dir,
  event,
  command,
  source_path
from
  agentreach_hook
where
  source_tracked_in_git;
```

### Find hooks whose source file is writable by group or world

```sql
select
  scope,
  event,
  source_path,
  source_writable_by
from
  agentreach_hook
where
  source_writable_by in ('group', 'world');
```

### Find hooks with no timeout or a very long one

```sql
select
  scope,
  event,
  command,
  timeout
from
  agentreach_hook
where
  timeout is null
  or timeout > 300;
```

### List hooks installed by plugins, with the plugin's enabled state

```sql
select
  plugin_name,
  plugin_enabled,
  event,
  matcher,
  command
from
  agentreach_hook
where
  third_party
order by
  plugin_name,
  event;
```

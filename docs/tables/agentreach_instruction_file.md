# Table: agentreach_instruction_file

One row per file the agent treats as instructions: `CLAUDE.md` at every level, `AGENTS.md`, rules, skills, subagents and commands, including those shipped by installed plugins. Each row carries provenance (`plugin_name`, `git_last_author`, `third_party`) and integrity signals (hash, git tracking, writability) and content signals that matter for prompt injection (hidden Unicode, HTML comments, external URLs, `@` includes).

For Codex, skills (`kind = 'skill'`) come from `~/.agents/skills`, the deprecated `$CODEX_HOME/skills` (not its bundled `.system`), `/etc/codex/skills` (scope `managed`), each project's `.agents/skills` and `.codex/skills` (loaded whatever the project's trust) and enabled plugins, minus those turned off with `[[skills.config]] enabled = false`.

## Examples

### Basic info

```sql
select
  kind,
  scope,
  path,
  size_bytes,
  tracked_in_git
from
  agentreach_instruction_file;
```

### Find instruction files containing hidden Unicode

Zero-width, bidi-override and tag characters can carry instructions a human
reviewer cannot see. Any non-zero count deserves a look.

```sql
select
  path,
  kind,
  hidden_unicode_count
from
  agentreach_instruction_file
where
  hidden_unicode_count > 0;
```

### Find project instruction files that are not tracked in git

An untracked `CLAUDE.md` in a repo is invisible to code review but obeyed by
the agent.

```sql
select
  project_dir,
  kind,
  path,
  writable_by
from
  agentreach_instruction_file
where
  scope = 'project'
  and not tracked_in_git;
```

### Rank instruction files by external reach

Files that pull in content from URLs or `@` includes extend the trusted
instruction surface to places outside the repo.

```sql
select
  path,
  external_url_count,
  external_include_count,
  html_comment_count
from
  agentreach_instruction_file
where
  external_url_count + external_include_count + html_comment_count > 0
order by
  external_url_count desc;
```

### Count instruction files by kind

```sql
select
  kind,
  count(*),
  count(*) filter (where tracked_in_git) as tracked
from
  agentreach_instruction_file
group by
  kind
order by
  count desc;
```

### List third-party instruction files and where they came from

```sql
select
  kind,
  coalesce(nullif(plugin_name, ''), git_last_author) as provided_by,
  path
from
  agentreach_instruction_file
where
  third_party
order by
  kind,
  path;
```

### Count plugin-provided skills, subagents and commands per plugin

```sql
select
  plugin_name,
  count(*) filter (where kind = 'skill') as skills,
  count(*) filter (where kind = 'subagent') as subagents,
  count(*) filter (where kind = 'command') as commands
from
  agentreach_instruction_file
where
  scope = 'plugin'
group by
  plugin_name
order by
  plugin_name;
```

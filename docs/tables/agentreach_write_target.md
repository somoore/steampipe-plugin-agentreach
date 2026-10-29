# Table: agentreach_write_target

One row per existing file or directory whose modification changes what the agent obeys, what CI runs, what the project depends on, or what runs in the developer's shell: the agent's own settings, `.mcp.json`, instruction files, `.github/workflows`, lockfiles and manifests, git hooks and config, shell startup files and `.devcontainer`.

Two write layers are modelled separately, following Claude Code's documentation. `writable_via_bash` is the sandbox layer: with the sandbox on, shell commands write only to the working directory, the temp directory and added directories, and never to the sandbox's protected paths. `edit_tool_approval` is the permission layer: what happens when the file tool edits the path in the session's permission mode. `CLAUDE.md`, `.claude/rules`, CI workflows and dependency manifests are not on either protected list.

`writable_by_user` comes from `access(2)` with `W_OK`. Nothing is opened for writing.

A home-directory file can appear more than once: one row with an empty
`session_dir` for the machine-wide gates, and one per project whose own
permission mode, sandbox setting or write rules change the gate there.

For Codex (`agent = 'codex'`), `writable_via_bash` is true when the Codex sandbox lets a command write the path: under `workspace-write`, inside the working directory, `writable_roots`, `$TMPDIR` or `/tmp`, and not under a protected `.git`, `.agents` or `.codex`; under `danger-full-access`, whenever you can write it; never under `read-only`. `edit_tool_approval` is what `apply_patch` gets: `allowed` inside writable paths, `prompt` outside them (and always in an untrusted project), `denied` under `never`. The machine-wide rows are a session in a folder with no trust decision. Exec-policy allow rules are not counted for writes.

## Examples

### Basic info

```sql
select
  category,
  path,
  writable_via_bash,
  edit_tool_approval
from
  agentreach_write_target;
```

### List targets the file tool edits with no prompt

```sql
select
  category,
  path,
  project_dir
from
  agentreach_write_target
where
  edit_tool_approval in ('auto', 'allowed')
order by
  category,
  path;
```

### Find CI workflows a shell command can rewrite

```sql
select
  path,
  bash_bypass
from
  agentreach_write_target
where
  category = 'ci_workflow'
  and writable_via_bash;
```

### Show home files a project makes easier to change

```sql
select
  m.path,
  m.edit_tool_approval as machine_wide,
  p.session_dir,
  p.edit_tool_approval as in_project
from
  agentreach_write_target m
  join agentreach_write_target p on p.path = m.path and p.session_dir <> ''
where
  m.project_dir = ''
  and m.session_dir = ''
  and p.project_dir = ''
  and p.edit_tool_approval is distinct from m.edit_tool_approval;
```

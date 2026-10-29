# Table: agentreach_ci_workflow

A CI workflow is another way an agent session starts, and the terminal model does not cover it. There is no person at the prompt. Who triggers the run, the token it gets and the permission mode come from the workflow file. agentreach reads `.github/workflows/*.yml` in the repository of every project it already knows; it never walks the home directory. It lists one row per step that runs an agent:

- `claude_code_action`: `anthropics/claude-code-action`. It refuses users without write access, rejects bots unless `allowed_bots` lists them, and restores `.claude/`, `.mcp.json` and `CLAUDE.md` from the base branch on pull requests.
- `claude_code_base_action`: the base action. It does none of those checks.
- `codex_action`: `openai/codex-action`. It refuses users without write access unless `allow-users` adds them.
- `run`: a shell step that calls `claude -p` or `codex exec`, directly or through `npx`/`bunx`. A run step checks nobody.

Only enums, booleans, counts and names GitHub restricts (job ids, event names, secret names) are kept. Prompts, run scripts, `claude_args` rule text and input values never reach the table. agentreach reads configuration, not runs; a composite action or reusable workflow that starts an agent is not followed.

The permission mode is resolved like a session's: a `claude_args` flag, then the action's `settings` input (inline JSON or a file in the repository), then the repository's `.claude/settings.json`, then the built-in default. `claude -p` and the Agent SDK start in `default` mode, where a call that needs approval is denied because nobody is there to approve it. `unrestricted_shell` is true when nothing stands between an injected instruction and a shell command: `bypassPermissions`, a blanket `Bash` allow rule, or Codex `danger-full-access`. With neither `sandbox` nor `permission-profile`, the Codex action runs the `workspace-write` sandbox; `codex exec` on its own runs `read-only`.

Trigger columns separate three risks. `untrusted_trigger`: someone else's text (an issue, comment, review, discussion or pull request) can reach the agent. `outsider_trigger`: someone without write access can start a run that has the repository's secrets; fork pull request and review events run with no secrets, so they do not count. `base_secrets_trigger`: `pull_request_target` or `workflow_run`, where checking out the pull request head (`checks_out_head`) hands the agent a tree the pull request author wrote, its settings and hooks included.

## Examples

### Basic info

```sql
select
  agent,
  path,
  job,
  launcher,
  triggers,
  permission_mode,
  actor_check
from
  agentreach_ci_workflow;
```

### List agent steps that run a pull request's code with the base repository's secrets

```sql
select
  path,
  line,
  launcher,
  triggers
from
  agentreach_ci_workflow
where
  base_secrets_trigger
  and checks_out_head;
```

### List agent steps that outsiders can start with no actor check

```sql
select
  path,
  line,
  launcher,
  actor_check,
  allowed_bots,
  triggers
from
  agentreach_ci_workflow
where
  outsider_trigger
  and (actor_check in ('none', 'relaxed') or allowed_bots = 'all');
```

### List agent steps that run any shell command on untrusted input

```sql
select
  path,
  line,
  launcher,
  permission_mode,
  sandbox,
  write_scopes
from
  agentreach_ci_workflow
where
  untrusted_trigger
  and unrestricted_shell;
```

### List actions not pinned to a commit

```sql
select
  path,
  line,
  launcher,
  action_ref
from
  agentreach_ci_workflow
where
  launcher <> 'run'
  and not pinned;
```

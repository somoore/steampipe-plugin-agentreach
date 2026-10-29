# Table: agentreach_launch_flag

Launch flags change what a session may do, and no settings file shows them. agentreach reads them from two places without running the agent:

- Shell aliases and functions in startup files (`.zshrc`, `.bashrc`, `.profile`, fish config and others). These are configured: every session typed as that command gets them.
- Command lines of running `claude` and `codex` sessions (live collections only). These are observed.

Only recognised flag names are kept, plus a value when it comes from a fixed set: a permission mode, Codex sandbox mode or approval policy, a `-c` config key. Prompts, paths and rule text never reach the table.

The Agent SDK starts the CLI with its options as flags, so a running SDK session shows them here: `--permission-mode`, `--setting-sources` (which settings files apply; `none` for `settingSources: []`), `--permission-prompt-tool stdio` (approvals go to the application's `canUseTool` callback) and `--input-format stream-json` (a program, not a person, sends the prompts). `agentreach_sdk_launcher` reads the same options from the application's source.

Flags on an alias or function named after the agent (`default` is true) are modelled. For Claude Code, `--dangerously-skip-permissions` and `--permission-mode` set the effective permission mode (the flag outranks `defaultMode`), `--allow-dangerously-skip-permissions` makes bypass available, `--allowedTools` and `--disallowedTools` add machine-wide rules (scope `launch_flag` in `agentreach_sandbox_rule`), and `--settings` loads that file as a settings source. `permissions.disableBypassPermissionsMode` still wins. Flags on other names (an alias such as `yolo`) and on running sessions are listed but change nothing; `agentreach_agent.running_bypass_sessions` counts running bypass sessions.

## Examples

### Basic info

```sql
select
  agent,
  source,
  name,
  flag,
  value,
  effect
from
  agentreach_launch_flag;
```

### List flags that skip permission checks

```sql
select
  agent,
  source,
  name,
  file,
  line,
  flag
from
  agentreach_launch_flag
where
  flag in ('--dangerously-skip-permissions', '--allow-dangerously-skip-permissions', '--dangerously-bypass-approvals-and-sandbox', '--yolo')
  or value in ('bypassPermissions', 'danger-full-access', 'never');
```

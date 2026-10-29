# Table: agentreach_sandbox_rule

One row per permission or sandbox rule from every settings scope: `permissions.allow/ask/deny` entries parsed into tool and specifier, and `sandbox.filesystem`, `sandbox.network`, `sandbox.credential` and `excludedCommands` entries. Path specifiers are resolved to absolute form so they can be joined against `agentreach_reach_file`.

## Examples

### Basic info

```sql
select
  scope,
  category,
  rule_type,
  tool,
  pattern,
  resolved_path
from
  agentreach_sandbox_rule;
```

### Count rules by category and type

A machine with hundreds of `allow` rules and zero `deny` rules has a
permission model that only ever widens.

```sql
select
  category,
  rule_type,
  count(*)
from
  agentreach_sandbox_rule
group by
  category,
  rule_type
order by
  count desc;
```

### Find broad Bash allow rules

```sql
select
  scope,
  project_dir,
  pattern
from
  agentreach_sandbox_rule
where
  tool = 'Bash'
  and rule_type = 'allow'
  and (pattern = 'Bash' or pattern like 'Bash(*%' or pattern like '%:*)')
order by
  scope;
```

### Find deny rules that protect a path

```sql
select
  scope,
  tool,
  pattern,
  resolved_path
from
  agentreach_sandbox_rule
where
  rule_type = 'deny'
  and resolved_path <> '';
```

### Show which sandbox filesystem rules exist, if any

When this returns no rows the sandbox is not configured and `agentreach_reach_file`
will report everything readable as reachable via Bash.

```sql
select
  scope,
  rule_type,
  pattern,
  resolved_path
from
  agentreach_sandbox_rule
where
  category = 'filesystem';
```

# Table: agentreach_reach_file

One row per catalogued sensitive path (SSH keys, cloud credentials, agent tokens, shell history, browser profiles, `.env` files in known projects): whether it exists, whether the agent's process can read it, and whether the agent's effective sandbox and permission rules would stop a `Bash` command or the `Read` tool from reaching it.

`readable` comes from a one-byte open-for-read probe. Contents are never read beyond that byte and never stored.

## Examples

### Basic info

```sql
select
  category,
  path,
  exists,
  readable,
  reachable_via_bash,
  reachable_via_read_tool
from
  agentreach_reach_file;
```

### List every credential the agent can reach through Bash

`reachable_via_bash` is false only when the sandbox is on and a filesystem or
credential deny rule covers the path. Permission rules on the `Read` tool do
not apply to `cat`.

```sql
select
  category,
  path,
  description
from
  agentreach_reach_file
where
  reachable_via_bash
order by
  category,
  path;
```

### Find files only the unsandboxed retry reaches

```sql
select
  path,
  category,
  reachable_via_retry,
  read_approval
from
  agentreach_reach_file
where
  exists
  and reachable_via_retry
  and not reachable_via_bash;
```

### Find paths protected from the Read tool but not from Bash

This is the gap that a `Read(~/.ssh/**)` deny rule leaves open.

```sql
select
  path,
  permission_deny_read_rule
from
  agentreach_reach_file
where
  reachable_via_bash
  and not reachable_via_read_tool;
```

### Summarize reach by category

```sql
select
  category,
  count(*) as cataloged,
  count(*) filter (where exists) as present,
  count(*) filter (where reachable_via_bash) as reachable
from
  agentreach_reach_file
group by
  category
order by
  reachable desc;
```

### Show the rule that blocks each protected path

```sql
select
  path,
  sandbox_deny_read_rule,
  permission_deny_read_rule
from
  agentreach_reach_file
where
  exists
  and (sandbox_deny_read_rule <> '' or permission_deny_read_rule <> '');
```

### Rank reachable files by blast radius tier

```sql
select
  tier,
  category,
  path
from
  agentreach_reach_file
where
  reachable_via_bash
order by
  tier,
  category,
  path;
```

# Table: agentreach_leg

One row per leg that `agentreach_path` is built from: each **untrusted** source the agent loads, each **private** file it can open, each **exit** that can carry data off the machine, and each **write** target it can change. A leg appears here even when it never meets the others in a path, so counts of sources or exits do not depend on whether a full path exists.

`leg_id` is the value `agentreach_path` uses in `source_id` and `exit_id`. For exits and write targets, `approval` is the gate on that step: `none`, `classifier`, `prompt` or `unknown`. A leg the configuration refuses outright is not listed.

## Examples

### Basic info

```sql
select
  role,
  kind,
  title,
  evidence,
  approval
from
  agentreach_leg
order by
  role,
  rank,
  title;
```

### Count legs by role

```sql
select
  role,
  count(*) as legs
from
  agentreach_leg
group by
  role
order by
  role;
```

### List exits that need no approval

```sql
select
  kind,
  title,
  detail,
  project_dir
from
  agentreach_leg
where
  role = 'exit'
  and approval = 'none'
order by
  rank,
  title;
```

### List untrusted sources that load in every session

```sql
select
  kind,
  title,
  detail
from
  agentreach_leg
where
  role = 'untrusted'
  and project_dir = ''
order by
  rank,
  title;
```

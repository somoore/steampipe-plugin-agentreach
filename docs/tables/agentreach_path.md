# Table: agentreach_path

One row per candidate exposure path. A **confidentiality** path joins an untrusted source the agent loads (a plugin's instruction file, an unapproved project MCP server, a plugin hook, web pages from WebFetch), a private file the agent can open, and an exit that can carry data off the machine. An **integrity** path joins an untrusted source and a file the agent can change without a human approving that write: its own settings, an instruction file, a CI workflow, a dependency manifest, a git hook or a shell startup file.

The legs are established one at a time from configuration and probes. A row says the pieces exist and can load in the same session (`project_dir` names the project when one leg only loads there); it does not say agentreach chained them. Each leg has its own `*_evidence` value: `configured`, `observed`, `inferred` or `unknown`.

`approval` is the gate on the last step, the exit or the write: `none` when the permission mode, a saved allow rule or the sandbox's auto-allow lets it run with no prompt, `classifier` when auto mode's classifier decides, `prompt` when a person approves it, and `unknown` when the permission mode is unknown. Reading the private file is not a gate: read-only shell commands and the Read tool run without a prompt in every mode. A leg that the configuration refuses outright (dontAsk mode, `strictAllowlist`, a WebFetch deny rule) is not a leg.

This table is the single implementation of the legs. The Powerpipe mod reads it and never re-derives them.

Rows are combinations, not separate findings: each pairs one untrusted source, one private file and one exit (or one source and one write target) that can load in the same session. The count grows as the product of the legs, so count distinct `source_id`, `target_path` and `exit_id` to see how many ways in and out there are. A plugin's files are one source, and a file agentreach already counts machine-wide is not counted again for a project.

## Examples

### Basic info

```sql
select
  kind,
  source_title,
  target_title,
  exit_title,
  status
from
  agentreach_path
limit 20;
```

### Count candidate paths by kind and status

```sql
select
  kind,
  status,
  count(*)
from
  agentreach_path
group by
  kind,
  status;
```

### List the worst source and exit for each private file

```sql
select distinct on (target_path)
  target_tier,
  target_title,
  via,
  source_title,
  exit_title
from
  agentreach_path
where
  kind = 'confidentiality'
  and status in ('candidate', 'attested')
order by
  target_path,
  source_rank,
  exit_rank;
```

### Show which legs rest on inference rather than observation

```sql
select
  source_evidence,
  target_evidence,
  exit_evidence,
  count(*)
from
  agentreach_path
group by
  1, 2, 3
order by
  4 desc;
```

### List untrusted sources that can change CI workflows or the agent's own settings

```sql
select
  source_title,
  target_title,
  target_category,
  via
from
  agentreach_path
where
  kind = 'integrity'
  and target_category in ('ci_workflow', 'guardrail');
```

### Count candidate paths by the approval they need

```sql
select
  kind,
  approval,
  count(*) as paths
from
  agentreach_path
where
  status in ('candidate', 'attested')
group by
  kind,
  approval
order by
  kind,
  approval;
```

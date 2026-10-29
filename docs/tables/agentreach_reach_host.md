# Table: agentreach_reach_host

One row per network destination the agent could use: every TCP port listening on this machine (discovered, then dialed), well-known Unix sockets such as Docker, and a single `*` row for the internet. `reachable` is a real dial result for TCP and sockets; the internet row is assumed, never tested.

Codex rows reuse the same probe results. With the network off the Codex sandbox refuses loopback TCP, so `approval` is the escalation (`prompt`, or `denied` under `never`); with `network_access = true` TCP needs nothing. On macOS the sandbox refuses Unix sockets even with the network on; on Linux with the network off agentreach cannot tell (`unknown`). A socket row uses the machine-wide session's gate in every project.

## Examples

### Basic info

```sql
select
  kind,
  target,
  service,
  process_name,
  reachable
from
  agentreach_reach_host;
```

### Show what a shell connection to each local service needs

`approval` is `none`, `classifier`, `prompt`, `denied` or `unknown`. A local
port that no sandbox rule allows is an unlisted host: the permission mode
decides it unless `strictAllowlist` refuses it.

```sql
select
  kind,
  target,
  service,
  allowed_by_sandbox,
  approval
from
  agentreach_reach_host
where
  reachable
  and kind in ('tcp', 'unix_socket')
order by
  approval;
```

### List reachable local services

Local services are exit channels and lateral-movement targets at once: an
agent that can reach Ollama can exfiltrate through it, and one that can reach
Postgres can read it.

```sql
select
  target,
  service,
  process_name
from
  agentreach_reach_host
where
  kind = 'tcp'
  and reachable
order by
  target;
```

### Check whether the Docker socket is dialable

A dialable Docker socket is root on the host.

```sql
select
  target,
  service,
  reachable
from
  agentreach_reach_host
where
  kind = 'unix_socket';
```

### Show what the sandbox network policy allows

`allowed_by_sandbox` is null when the sandbox is off, meaning nothing
restricts the destination.

```sql
select
  target,
  service,
  sandbox_enabled,
  allowed_by_sandbox,
  sandbox_rule
from
  agentreach_reach_host
where
  reachable
order by
  kind,
  target;
```

### Count reachable destinations by kind

```sql
select
  kind,
  count(*) filter (where reachable) as reachable,
  count(*) as total
from
  agentreach_reach_host
group by
  kind;
```

### List loopback services a shell command could reach

```sql
select
  target,
  service,
  process_name
from
  agentreach_reach_host
where
  loopback
  and reachable
order by
  target;
```

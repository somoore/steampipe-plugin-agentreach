# Table: agentreach_environment

Controls outside the agent's own configuration. agentreach detects some of them without sending anything: proxy environment variables (host only, credentials dropped), macOS system proxy settings, container markers such as `/.dockerenv`, devcontainer variables, and running endpoint agents by process name. Operators can declare others in the connection config with `declared_controls`, for example an egress allowlist the laptop cannot see.

A detected control is an observed fact, not proof that it blocks anything. A declared control is the operator's word. `agentreach_path` marks paths through an internet exit `attested` when `egress_allowlist` is declared (they stay findings; agentreach has not verified the declaration), and labels exit evidence `unknown` when a proxy is detected.

## Examples

### Basic info

```sql
select
  name,
  kind,
  detected,
  declared,
  evidence,
  detail
from
  agentreach_environment;
```

### List controls that were declared but not detected

```sql
select
  name,
  detail
from
  agentreach_environment
where
  declared
  and not detected;
```

---
organization: somoore
category: ["security"]
icon_url: "/images/plugins/somoore/agentreach.svg"
brand_color: "#B4660A"
display_name: "agentreach"
short_name: "agentreach"
description: "Steampipe plugin to query what your AI coding agent can actually reach on your machine: settings, hooks, MCP servers, instruction files, and probed access to credentials and local services."
og_description: "Query your coding agent's security posture with SQL! Open source CLI. No DB required."
og_image: "/images/plugins/somoore/agentreach-social-graphic.png"
engines: ["steampipe", "sqlite", "postgres", "export"]
---

# agentreach + Steampipe

**agentreach** answers one question: *what can my AI coding agent actually reach on this machine?* It reads the agent's real configuration, resolves the effective permission and sandbox rules, and runs inert probes to find out which credentials and local services are within reach. [Steampipe](https://steampipe.io) exposes the result as SQL tables.

Nothing is enforced and nothing is modified. Probes open files for a one-byte read and dial TCP ports; they never read secret contents, never send data, and never write.

```sql
select category, path, reachable_via_bash, reachable_via_read_tool
from agentreach_reach_file
where exists
order by category;
```

```
+------------------+-----------------------+--------------------+-------------------------+
| category         | path                  | reachable_via_bash | reachable_via_read_tool |
+------------------+-----------------------+--------------------+-------------------------+
| agent_credential | ~/.claude.json        | true               | true                    |
| agent_credential | ~/.codex/auth.json    | true               | true                    |
| cloud_credential | ~/.aws/credentials    | true               | true                    |
| kube             | ~/.kube/config        | true               | true                    |
| ssh              | ~/.ssh                | true               | true                    |
| vcs_credential   | ~/.config/gh/hosts.yml| true               | true                    |
+------------------+-----------------------+--------------------+-------------------------+
```

Supported agents: **Claude Code** (full model) and **Codex CLI** (`agent = 'codex'`). For Codex, agentreach models `sandbox_mode`, `approval_policy`, `sandbox_workspace_write.network_access`, exec-policy allow rules and project trust into the same approval columns and paths: reads are unrestricted in every sandbox mode, so private files are reachable by shell; the internet needs an escalation you approve unless the network is on or a rule lets a network command out. Hooks and `notify` (with Codex's hook trust), plugins configured in `config.toml`, skills, local services (gated by the Codex sandbox, which refuses loopback with the network off and Unix sockets on macOS) and write targets (writable roots, the protected `.git`, `.agents` and `.codex`, and `apply_patch` approval) are modelled too, so Codex gets integrity paths. Permission profiles (beta), the experimental network proxy, CLI flags and remote-synced plugins are not modelled and report `unknown` or no rows. Filter on `agent` when a query encodes one agent's rules.

## Documentation

- **[Table definitions & examples →](tables)**

## Quick start

Install the plugin (once published; for now, build locally with `make install`):

```bash
steampipe plugin install somoore/agentreach
```

Configure your connection in `~/.steampipe/config/agentreach.spc`:

```hcl
connection "agentreach" {
  plugin = "somoore/agentreach"

  # Extra project directories to inspect, beyond the ones the agent already
  # knows about. Optional.
  # project_dirs = ["~/github/myapp"]

  # Run inert reachability probes (open-for-read, TCP dial). Default true.
  # probe = true
}
```

Run a query:

```bash
steampipe query "select agent, version, effective_permission_mode, sandbox_enabled from agentreach_agent"
```

## Credentials

| Item        | Description |
|-------------|-------------|
| Credentials | None. The plugin reads local files as the user running Steampipe. |
| Permissions | Read access to the agent's config directories (`~/.claude`, `~/.claude.json`, `~/.claude/plugins/*.json`, project `.claude/` and `.mcp.json`). Probes check readability of catalogued sensitive paths with a one-byte read and dial localhost ports; they store booleans only, never contents. |
| Radius      | One machine, one user: every project the agent has opened plus any `project_dirs` you list. |
| Resolution  | `CLAUDE_CONFIG_DIR` is honored for the Claude Code user config directory. |

## Multiple Connections

Each `agentreach` connection inspects the machine Steampipe runs on, so multiple connections mostly make sense for different `project_dirs` sets or for toggling probes. Group them with an [aggregator](https://steampipe.io/docs/managing/connections#using-aggregators) if you want one query over several:

```hcl
connection "agentreach_probe" {
  plugin = "somoore/agentreach"
  probe  = true
}

connection "agentreach_static" {
  plugin = "somoore/agentreach"
  probe  = false
}

connection "agentreach_all" {
  plugin      = "somoore/agentreach"
  type        = "aggregator"
  connections = ["agentreach_probe", "agentreach_static"]
}
```

## Fleet mode

A connection with `snapshot_paths` reads snapshot files instead of collecting
the machine Steampipe runs on. Every table has `host` and `snapshot_id`
columns, so one query can compare many machines:

```hcl
connection "agentreach_fleet" {
  plugin         = "somoore/agentreach"
  snapshot_paths = ["~/agentreach-snapshots/*.json"]
}
```

A file that cannot be read appears as an `unknown` agent row whose
`collect_errors` names the file, rather than disappearing.

## Evidence

Columns that state a fact about access carry a sibling `*_evidence` column:
`configured` (read from a settings file), `observed` (probed as the current
user, or inside srt), `inferred` (agentreach's model of the agent's rules on top of
configuration and probes) or `unknown`. `agentreach_agent.assessment_complete` is
false when any source could not be read; treat that as "not assessed", not as
a pass.

## Approvals

Each exit and write target carries the gate an action meets before it runs:
`none` (the permission mode, a saved allow rule or the sandbox's auto-allow
runs it), `classifier` (auto mode's classifier decides), `prompt` (a person
approves it), `denied`, or `unknown` when the permission mode is unknown. The
model follows Claude Code's permissions, permission-modes and sandboxing
docs. See `agentreach_agent.shell_approval`, `network_approval` and
`web_fetch_approval`, `agentreach_mcp_server.tool_approval`, and `approval` on
`agentreach_leg` and `agentreach_path`.

## What the plugin does not do

- It does not read the contents of credentials. `has_inline_secret` and similar columns are classifications of shape, computed in memory and never stored.
- It does not send anything anywhere. The internet row in `agentreach_reach_host` is assumed reachable, not tested.
- It does not block, rewrite, or enforce. Pair it with the [agentreach compliance mod](https://github.com/somoore/steampipe-mod-agentreach-compliance) for benchmarks and an attack-path graph.

## Get involved

- Open source: [github.com/somoore/steampipe-plugin-agentreach](https://github.com/somoore/steampipe-plugin-agentreach)
- Community: [Steampipe Slack](https://turbot.com/community/join)

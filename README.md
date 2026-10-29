# steampipe-plugin-agentreach

Query what your AI coding agent can actually reach on your machine, with SQL.

## What it is

A [Steampipe](https://steampipe.io) plugin that turns a coding agent's local security posture into 18 tables: its settings, hooks, MCP servers, plugins, instruction files, sandbox and permission rules, launch flags, the CI workflows and Agent SDK applications that start it, which credentials, local services and network destinations it can reach, and the attack paths those facts combine into. It discovers every coding agent and harness on the machine automatically — Claude Code, OpenAI Codex, OpenCode, Cline and Grok Build — and a machine with none of them installed is a clean result, not a finding. Every table has an `agent` column; the Powerpipe mod's controls read the Claude Code rows. The other four agents are collection and modelled gates (OpenCode and Grok Build from their documented permission configs, Cline honest-unknown where its approval state lives in app storage), not verdicts: no mod control assesses them.

The name says what it answers: what can the agent reach. This is an unofficial community project.

## Why it exists

Coding agents run shell commands as you. If a malicious instruction reaches the agent through a repo file, a skill, or an MCP server, the damage is bounded by what the agent can read and where it can send it. That boundary is spread across half a dozen config files and is hard to see. This plugin makes it one query.

## What it helps with

- See every credential file the agent can read, via shell and via the Read tool, before someone else does.
- Find MCP servers with secrets pasted inline or unpinned launchers.
- Find instruction files with hidden Unicode or HTML comments the model reads but you do not.
- Count attack paths using the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): private data the agent can read, untrusted content it obeys, and an open channel out.
- Feed the [agentreach compliance mod](https://github.com/somoore/steampipe-mod-agentreach-compliance), which turns these facts into a reviewed control profile built on OWASP AISVS and draws the attack graph.

It reads config and runs inert probes only. A file probe opens for read and discards at most one byte. A network probe dials and disconnects. Secret values are classified as a boolean and never stored. Nothing is changed, enforced, or sent anywhere.

## Get it running

Requires Go 1.26 and Steampipe.

```bash
brew install turbot/tap/steampipe
git clone https://github.com/somoore/steampipe-plugin-agentreach
cd steampipe-plugin-agentreach
make install
cp config/agentreach.spc ~/.steampipe/config/agentreach.spc
steampipe query "select category, path, reachable_via_bash from agentreach_reach_file"
```

Example output:

```
+------------------+------------------------+--------------------+
| category         | path                   | reachable_via_bash |
+------------------+------------------------+--------------------+
| ssh              | ~/.ssh                 | true               |
| cloud_credential | ~/.aws/credentials     | true               |
| vcs_credential   | ~/.config/gh/hosts.yml | true               |
| agent_credential | ~/.codex/auth.json     | true               |
+------------------+------------------------+--------------------+
```

## Tables

| Table | One row per |
|-------|-------------|
| `agentreach_agent` | installed agent: version, permission mode, sandbox state |
| `agentreach_project` | project the agent has worked in, with its trust decision |
| `agentreach_setting` | settings key at every scope |
| `agentreach_hook` | command that runs on a lifecycle event |
| `agentreach_mcp_server` | MCP server, with launcher type, pinning, inline-secret flag |
| `agentreach_instruction_file` | file the agent obeys, with integrity signals |
| `agentreach_plugin` | installed plugin: version pinning, enabled decision, what it ships |
| `agentreach_marketplace` | plugin source the machine can install from, and whether a strict allowlist admits it |
| `agentreach_sandbox_rule` | permission or sandbox rule, path resolved |
| `agentreach_reach_file` | sensitive file and whether the agent can read it |
| `agentreach_reach_host` | local port, socket or the internet and whether the agent can dial it |
| `agentreach_write_target` | file whose change alters what the agent obeys or what runs later, and whether the agent can write it |
| `agentreach_launch_flag` | permission flag on a shell alias, function or running session (including the flags the Agent SDK passes) |
| `agentreach_ci_workflow` | GitHub Actions step that runs an agent: trigger, actor check, token, permission mode |
| `agentreach_sdk_launcher` | source file that starts Claude Code through the Agent SDK, with the literal options it passes |
| `agentreach_environment` | environment variable that changes the agent's posture (names and fixed values only) |
| `agentreach_leg` | one leg of an attack path: an untrusted source, a private file, an exit or a write target, with its gate |
| `agentreach_path` | candidate attack path joining a source, a private file and an exit (or a write target), with the strongest gate on any step |

The same collector backs the `agentreach` CLI (`make cli`): `agentreach scan` prints a text, JSON or SARIF report and exits 0 (clean), 1 (failing findings), 2 (not fully assessed) or 3 (error).

Table docs and examples are in [docs/tables](docs/tables).

## What a result means

Every fact the tables carry has an evidence type: `configured` (read from a settings file), `observed` (an inert probe saw it: a one-byte open, a dial, a stat), `inferred` (derived by agentreach from configured plus observed — most reachability is inference from your effective rules), or `unknown` (could not be assessed). Columns named `*_evidence` say which. With `observe = true` in the connection config, the file and loopback probes run again inside the sandbox runtime configured from your effective settings, and `observed_via_sandbox` and `model_agrees` record whether the observation matched the model.

A `false` is a fact; a `null` is not. Null means unknown or unrestricted (no decision recorded, the sandbox off, a gate agentreach cannot establish), never "protected". Downstream queries must write `is distinct from false` when a null should count as open.

The behaviour model is verified against named releases, not "whatever is installed": `agentreach_agent.model_basis` carries the release each agent's gates were checked against, and `model_basis_stale` is true when your installed agent is newer, so a scan tells you its findings may lag instead of passing silently. `agentreach version` prints the bases, and a weekly CI job fails when any document the model cites changes. Discovery is automatic and every report carries the inventory: the CLI prints an "Agents found" line (or "No coding agent or harness found on this machine", which is a clean result), JSON reports carry `summary.agents`, and the mod's dashboard opens with the discovered-agents table.

## What agentreach cannot see

agentreach reads configuration and probes what this machine can reach. It does not see:

- **Runs.** A CI workflow, an Agent SDK application or a session started by an IDE is read from its files; what a given run was passed at run time is visible only while it runs (`agentreach_launch_flag`, observed) or not at all.
- **Auto mode's decisions.** Auto mode's classifier decides each action on Anthropic's side. agentreach reports where it is the only gate (`approval = 'classifier'`), not what it would allow.
- **Server-delivered policy.** Server-managed settings and a cloud session's environment come from the account, not from a file on this machine.
- **Composite actions and reusable workflows** that start an agent; agentreach follows the steps in each workflow file only.

## Development

```bash
make test      # gofmt, vet, standards tests, unit tests
make snapshot  # JSON dump of the collector without Steampipe
```

The collector in `pkg/posture` has no Steampipe dependency so it can back a CLI later.

## Publishing

Releases are tagged `vX.Y.Z` on this repository; the CHANGELOG's version heading is the release note. Publishing to the Steampipe Hub (so `steampipe plugin install somoore/agentreach` works and the mod's `agentreach@X.Y.Z` requirement resolves without a local build) needs a Turbot account and a pull request to the [steampipe hub repository](https://github.com/turbot/steampipe-plugin-sdk/blob/main/README.md) — until then, install from source with `make install` as above.

## License

MIT

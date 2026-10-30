# agentreach

Query what your AI coding agent can actually reach on your machine, with SQL.

## Supported agents

Discovery is automatic: an agent that is not installed produces no rows at all.

| Agent | Coverage |
|-------|----------|
| Claude Code | Full: settings, hooks, MCP, plugins, skills, sandbox, permission rules, CI workflows, launch flags, attack paths |
| Codex | Full: config, sandbox, approval policy, MCP, hooks, skills, plugins, write targets, attack paths |
| OpenCode | Config, permission gates (v1 and v2 formats), MCP, instruction files, agents |
| Cline | Config, MCP, rules and instruction files; approval gates honestly unknown (stored in app state we cannot read) |
| Grok Build | Config, permission modes and rules, sandbox profiles, MCP, instruction files |

Every table has an `agent` column. The [compliance mod](https://github.com/somoore/steampipe-mod-agentreach-compliance) judges the Claude Code rows; the other agents are inventory.

## What it does

agentreach is a read-only security scanner for AI coding agents. It reads each agent's configuration and answers one question: if a malicious instruction reached your agent, what could it actually do?

It never starts a session, never sends a prompt, never writes your configuration, and never stores a secret value. It does run each agent's `--version` to report the installed release, and some agents create their own state directory the first time that happens. A machine with no coding agent installed is a clean result.

One collector backs three things:

- 18 SQL tables through a [Steampipe](https://steampipe.io) plugin
- A CLI: `agentreach scan` prints text, JSON or SARIF, and exits 0 (clean), 1 (failing findings) or 2 (not fully assessed)
- A skill-only Claude Code plugin so the agent can help you fix what the scan finds

## Install

Requires Go 1.26 and Steampipe.

```bash
brew install turbot/tap/steampipe
git clone https://github.com/somoore/steampipe-plugin-agentreach
cd steampipe-plugin-agentreach && make install
cp config/agentreach.spc ~/.steampipe/config/agentreach.spc
steampipe service start
```

Ask it a question:

```sql
select category, path, reachable_via_bash
from agentreach_reach_file
where agent = 'claude_code';
```

## Tables

| Table | One row per |
|-------|-------------|
| `agentreach_agent` | installed agent: version, permission mode, sandbox state, ACP harness |
| `agentreach_project` | project the agent has worked in, with its trust decision |
| `agentreach_setting` | settings key at every scope |
| `agentreach_hook` | command that runs on a lifecycle event |
| `agentreach_mcp_server` | MCP server, with launcher type, pinning, inline-secret flag |
| `agentreach_instruction_file` | file the agent obeys, with integrity signals |
| `agentreach_plugin` | installed plugin: version pinning, enabled decision, what it ships |
| `agentreach_marketplace` | plugin source the machine can install from |
| `agentreach_sandbox_rule` | permission or sandbox rule, path resolved |
| `agentreach_reach_file` | sensitive file and whether the agent can read it |
| `agentreach_reach_host` | local port, socket or the internet and whether the agent can dial it |
| `agentreach_write_target` | file whose change alters what the agent obeys, and whether the agent can write it |
| `agentreach_launch_flag` | permission flag on an alias, function or running session |
| `agentreach_ci_workflow` | GitHub Actions step that runs an agent |
| `agentreach_sdk_launcher` | source file that starts Claude Code through the Agent SDK |
| `agentreach_environment` | environment variable that changes the agent's posture |
| `agentreach_leg` | one leg of an attack path, with its gate |
| `agentreach_path` | candidate attack path, with the strongest gate on any step |

Table docs and examples are in [docs/tables](docs/tables).

## How to read a result

- Every fact carries an evidence type: `configured` (read from a settings file), `observed` (an inert probe saw it), `inferred` (derived from both), or `unknown`.
- A false is a fact. A null means unknown or unrestricted, never safe.
- `agentreach_agent.version` is whatever the installed binary reports. Nothing is pinned to a release: agents ship continuously, so a construct the model cannot interpret comes back `unknown` or not assessed instead of being guessed.
- `agentreach_agent.acp_harness` names the editor Agent Client Protocol servers that can start each agent, whose options are not visible to the scan.
- Not collected: content that only loads at run time, remote config, and the newer agents' plugin and skill directories.

## Security promises

- Read-only. A file probe reads one byte and stops. A network probe dials and disconnects. The only subprocess is each agent's `--version`.
- No secret value is ever stored. Values become booleans and free text is scrubbed.
- Deterministic. No LLM anywhere in the verdict path.

## Development

```bash
make test      # gofmt, vet, go mod verify, standards + unit tests
make security  # gosec + govulncheck at pinned versions
make snapshot  # JSON dump of the collector, no Steampipe needed
```

Publishing to the Steampipe Hub needs a Turbot account and a pull request to the hub repository; until then install from source as above. Security issues go through **Security > Report a vulnerability**, never a public issue. See CONTRIBUTING.md and SECURITY.md.

## License

MIT

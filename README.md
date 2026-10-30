# agentreach

Query what your AI coding agent can actually reach on your machine, with SQL.

agentreach is a read-only security scanner for AI coding agents. It reads each agent's configuration and answers one question: if a malicious instruction reached your agent, what could it actually do?

One collector backs three things:

- a CLI that prints text, JSON or SARIF
- 18 SQL tables through a [Steampipe](https://steampipe.io) plugin
- a [Powerpipe](https://powerpipe.io) compliance mod with 112 controls

## Quick start

```bash
go install github.com/somoore/steampipe-plugin-agentreach/cmd/agentreach@latest
agentreach scan
```

Prebuilt binaries for macOS and Linux on arm64 and amd64 are on [Releases](https://github.com/somoore/steampipe-plugin-agentreach/releases). Verify them against `checksums.txt`.

A condensed run on a developer laptop:

```text
Agents found: claude_code 2.1.314, codex 0.155.1

Candidate paths by approval: none 4, classifier 2, prompt 0, unknown 0
Failing findings (fail-on auto): 4 of 6

Failing paths, one line per file (worst first):
  Claude Code: ~/.ssh can be read and sent out: 4 path(s) from 2 source(s), through 3 exit(s), nothing asks you
    e.g. ~/work/app/CLAUDE.md (instruction_file) can make the agent read ~/.ssh by shell and send it out through plugin hooks, and no step asks you first.
```

`agentreach scan` exits 0 (clean), 1 (failing findings) or 2 (not fully assessed). `--format json` gives the whole snapshot, `--format sarif` is for GitHub code scanning, and `--no-probe` skips the network and file probes.

## What it does

It reads configuration, permission rules, hooks, MCP servers, plugins, CI workflows and project history. It does not start a session or send a prompt.

- **Gates.** For each step it models what actually stops the command: no gate, a classifier, a human prompt, or an enforced sandbox.
- **Attack paths.** It joins an untrusted source (an instruction file, a web page, an MCP server) to a private file and to an exit (the internet, a socket, a hook), and reports the strongest gate on the way.
- **Evidence.** Every fact says whether it is `configured`, `observed`, `inferred` or `unknown`. A `null` means unknown or unrestricted, never safe.

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

## Use it as a Steampipe plugin

```bash
brew install turbot/tap/steampipe
git clone https://github.com/somoore/steampipe-plugin-agentreach
cd steampipe-plugin-agentreach && make install
cp config/agentreach.spc ~/.steampipe/config/agentreach.spc
steampipe service start
```

The plugin is not on the Steampipe Hub yet, so install from source for now. Then query it:

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

## In CI

The repository ships a composite action that downloads a verified binary, scans the runner and uploads SARIF to code scanning.

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: somoore/steampipe-plugin-agentreach@v0.2.0
```

A GitHub-hosted runner has no agent installed, so the scan is clean there. Use a self-hosted runner, or install the agent first. [docs/ci.md](docs/ci.md) has the inputs and a plain shell recipe.

## Security promises

- Read-only. A file probe reads one byte and stops. A network probe dials and disconnects. The only subprocess is each agent's `--version`.
- No secret value is ever stored. Values become booleans and free text is scrubbed.
- Deterministic. No LLM anywhere in the verdict path.

## Development

```bash
make test      # gofmt, vet, go mod verify, standards and unit tests
make security  # gosec and govulncheck at pinned versions
make snapshot  # JSON dump of the collector, no Steampipe needed
```

The collector's model of each agent is tested against 19 fixture machines, and CI watches the vendor documentation for drift. Security issues go through **Security > Report a vulnerability**, never a public issue. See CONTRIBUTING.md and SECURITY.md.

## License

MIT

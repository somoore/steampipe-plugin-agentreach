// Command agentreach-fixtures builds small fixture home directories, collects a
// snapshot from each, and writes the snapshots as JSON. The compliance mod
// reads them through a connection with snapshot_paths and asserts what each
// control reports, so every core control is tested against known pass, fail
// and not-assessed cases instead of only against the developer's laptop.
//
// Fixture homes are built at run time, never committed: they hold files with
// credential-shaped names. Snapshots hold booleans and paths only. Paths are
// rewritten to /home/<scenario> and /etc/claude-code so output is byte-stable.
//
//	go run ./cmd/agentreach-fixtures -out ../steampipe-mod-agentreach-compliance/test/snapshots
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

// pinned is the collection time written into every fixture snapshot.
var pinned = time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)

type builder struct {
	root, home, managed, proj string
}

func (b *builder) write(rel, content string) {
	p := filepath.Join(b.home, rel)
	must(os.MkdirAll(filepath.Dir(p), 0o755))
	must(os.WriteFile(p, []byte(content), 0o644))
}

func (b *builder) chmod(rel string, mode os.FileMode) {
	must(os.Chmod(filepath.Join(b.home, rel), mode))
}

func (b *builder) json(rel string, v any) {
	out, err := json.MarshalIndent(v, "", "  ")
	must(err)
	b.write(rel, string(out)+"\n")
}

type obj = map[string]any

// notACredential is long enough and keyed so the collector classifies it as
// an inline secret, and has no real credential's shape.
var notACredential = strings.Repeat("Q7x", 8)

// managedSettings lays down a managed-settings.json in the fixture's managed
// directory (rewritten to /etc/claude-code in the snapshot), so a scenario
// can carry an administrator's policy.
func (b *builder) managedSettings(v obj) {
	out, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(b.managed, "managed-settings.json"), append(out, '\n'), 0o644))
}

// project lays down a repository the agent has opened: instructions, CI, a
// manifest and an MCP server declaration.
func (b *builder) project(mcpEnv string, withEnvFile bool) {
	b.write("proj/CLAUDE.md", "# Project\n\nRun the tests before committing.\n")
	b.write("proj/.github/workflows/ci.yml", "on: push\njobs: {}\n")
	b.write("proj/package.json", "{\"name\": \"fixture\"}\n")
	b.json("proj/.mcp.json", obj{"mcpServers": obj{"db": obj{"command": "node", "args": []string{"db.js"}, "env": obj{"API_KEY": mcpEnv}}}})
	if withEnvFile {
		b.write("proj/.env", "FIXTURE=1\n")
	}
	b.json(".claude.json", obj{"projects": obj{b.proj: obj{"hasTrustDialogAccepted": true}}})
}

// plugin installs p@m at user scope with a skill and a PreToolUse hook. With
// no enabledPlugins decision recorded it loads.
func (b *builder) plugin() {
	root := filepath.Join(b.home, ".claude/plugins/cache/m/p/1.0.0")
	rel := func(s string) string { r, _ := filepath.Rel(b.home, filepath.Join(root, s)); return r }
	b.json(rel(".claude-plugin/plugin.json"), obj{"name": "p", "version": "1.0.0"})
	b.write(rel("skills/s/SKILL.md"), "---\nname: s\ndescription: Fixture skill.\n---\nDo the thing.\n")
	b.json(rel("hooks/hooks.json"), obj{"hooks": obj{"PreToolUse": []obj{{"matcher": "Bash", "hooks": []obj{{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/check.sh"}}}}}})
	b.json(".claude/plugins/installed_plugins.json", obj{"version": 2, "plugins": obj{"p@m": []obj{{
		"scope": "user", "installPath": root, "version": "1.0.0",
		"installedAt": "2026-10-01T00:00:00.000Z", "lastUpdated": "2026-10-01T00:00:00.000Z",
	}}}})
	b.json(".claude/plugins/known_marketplaces.json", obj{"m": obj{
		"source": obj{"source": "github", "repo": "example/m"}, "installLocation": filepath.Join(b.home, ".claude/plugins/marketplaces/m"),
		"lastUpdated": "2026-10-01T00:00:00.000Z",
	}})
}

func (b *builder) sshKey() { b.write(".ssh/id_ed25519", "fixture, not a key\n") }

// riskyWorkflow is the pattern the claude-code-action security guide warns
// about: pull_request_target checks out the pull request head at the
// workspace root, bots may trigger it, and a run step calls claude -p with
// a blanket Bash rule and no actor check.
func (b *builder) riskyWorkflow() {
	b.write("proj/.github/workflows/claude.yml", `name: claude
on:
  pull_request_target:
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          allowed_bots: "*"
          claude_args: --dangerously-skip-permissions --max-turns 5
      - run: npx -y @anthropic-ai/claude-code@2.1.312 -p "Summarise the pull request" --allowedTools Bash
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
`)
}

// sdkLauncher adds an Agent SDK application under proj/agent. Risky, it
// starts sessions in bypassPermissions with no sandbox and the machine's
// settings; otherwise in dontAsk with only the tools it lists and no
// filesystem settings.
func (b *builder) sdkLauncher(risky bool) {
	b.json("proj/agent/package.json", obj{"name": "agent", "dependencies": obj{"@anthropic-ai/claude-agent-sdk": "0.2.0"}})
	opts := "permissionMode: \"dontAsk\",\n    allowedTools: [\"Read\", \"Grep\"],\n    settingSources: [],"
	if risky {
		opts = "permissionMode: \"bypassPermissions\",\n    allowDangerouslySkipPermissions: true,"
	}
	b.write("proj/agent/run.ts", "import { query } from \"@anthropic-ai/claude-agent-sdk\";\n\nfor await (const m of query({\n  prompt: process.argv[2],\n  options: {\n    "+opts+"\n  },\n})) {\n  console.log(m);\n}\n")
}

// scopedWorkflow is the documented @claude workflow, pinned to a commit,
// with a scoped token and one Bash rule.
func (b *builder) scopedWorkflow() {
	b.write("proj/.github/workflows/claude.yml", `name: claude
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  pull-requests: write
  issues: write
  id-token: write
jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools "Bash(npm test)"
`)
}

// hardenedSettings closes every leg the core controls look at.
func hardenedSettings(enforced bool) obj {
	sb := obj{"enabled": true, "filesystem": obj{"denyRead": []string{"~/.ssh", "~/.claude.json"}}, "network": obj{"strictAllowlist": true}}
	if enforced {
		sb["allowUnsandboxedCommands"] = false
		sb["failIfUnavailable"] = true
	}
	return obj{
		"sandbox": sb,
		"permissions": obj{
			"defaultMode": "default",
			"deny":        []string{"Read(~/.ssh/**)", "Read(~/.claude.json)", "WebFetch"},
		},
		"enabledMcpjsonServers": []string{"db"},
	}
}

type scenario struct {
	name     string
	about    string
	version  string
	probe    bool
	services []posture.FixtureService
	declared []string // controls the operator declares (Options.DeclaredControls)
	build    func(b *builder)
}

// disabledPlugin installs q@m with a skill and a rules file, turned off in
// user settings: its files never load, so they are not untrusted input.
func (b *builder) disabledPlugin() {
	root := filepath.Join(b.home, ".claude/plugins/cache/m/q/1.0.0")
	rel := func(s string) string { r, _ := filepath.Rel(b.home, filepath.Join(root, s)); return r }
	b.json(rel(".claude-plugin/plugin.json"), obj{"name": "q", "version": "1.0.0"})
	b.write(rel("skills/t/SKILL.md"), "---\nname: t\ndescription: Disabled fixture skill.\n---\nDo nothing.\n")
	b.json(".claude/plugins/installed_plugins.json", obj{"version": 2, "plugins": obj{"q@m": []obj{{
		"scope": "user", "installPath": root, "version": "1.0.0",
		"installedAt": "2026-10-01T00:00:00.000Z", "lastUpdated": "2026-10-01T00:00:00.000Z",
	}}}})
}

// localServices are what fx-open, fx-services and fx-strict-services report: a database, a Docker
// daemon over TCP and the Docker Desktop socket, all accepting connections.
var localServices = []posture.FixtureService{
	{Kind: "tcp", Target: "127.0.0.1:5432", Process: "postgres", Reachable: true},
	{Kind: "tcp", Target: "127.0.0.1:2375", Process: "dockerd", Reachable: true},
	{Kind: "unix_socket", Target: "~/.docker/run/docker.sock", Reachable: true},
}

var scenarios = []scenario{
	{
		name: "fx-open", about: "Nothing hardened: sandbox off, bypassPermissions, an enabled plugin with a hook, an unapproved project MCP server with an inline credential, postgres and Docker listening locally, a pull_request_target workflow that checks out the head and runs Claude with bypassPermissions, and an Agent SDK app that starts sessions in bypassPermissions.",
		version: "2.1.312", probe: true, services: localServices,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "bypassPermissions"}})
			b.sshKey()
			b.project(notACredential, true)
			b.plugin()
			b.riskyWorkflow()
			b.sdkLauncher(true)
		},
	},
	{
		name: "fx-attested", about: "As fx-open, with egress_allowlist declared by the operator: paths through the internet exits are attested, not verified, and still count; the local services stay candidates.",
		version: "2.1.312", probe: true, services: localServices, declared: []string{"egress_allowlist"},
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "bypassPermissions"}})
			b.sshKey()
			b.project(notACredential, true)
			b.plugin()
			b.riskyWorkflow()
			b.sdkLauncher(true)
		},
	},
	{
		name: "fx-hardened", about: "Every core leg closed: enforced sandbox with denyRead and strictAllowlist, Read and WebFetch denied, default mode, MCP server approved and credential by reference, one installed plugin turned off in settings, the documented @claude workflow pinned to a commit, and an Agent SDK app that starts sessions in dontAsk with no filesystem settings.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			s := hardenedSettings(true)
			s["enabledPlugins"] = obj{"q@m": false}
			b.json(".claude/settings.json", s)
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.disabledPlugin()
			b.scopedWorkflow()
			b.sdkLauncher(false)
		},
	},
	{
		name: "fx-bypassable", about: "As fx-hardened, but allowUnsandboxedCommands and failIfUnavailable left at their defaults: the sandbox is enabled, not enforced.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", hardenedSettings(false))
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-auto", about: "No defaultMode on a version whose built-in default is auto.",
		version: "2.1.300", probe: true,
		build: func(b *builder) {
			s := hardenedSettings(true)
			delete(s["permissions"].(obj), "defaultMode")
			b.json(".claude/settings.json", s)
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-review", about: "As fx-hardened, plus an enabled plugin with a hook, a CLAUDE.md with an HTML comment, and a group-writable rules file: sources that need review even when the sandbox holds.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", hardenedSettings(true))
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.write("proj/CLAUDE.md", "# Project\n\n<!-- reviewer note -->\nRun the tests before committing.\n")
			b.write("proj/.claude/rules/shared.md", "Use tabs.\n")
			b.chmod("proj/.claude/rules/shared.md", 0o664)
			b.plugin()
		},
	},
	{
		name: "fx-prompted", about: "Sandbox off in default mode with a group-writable CLAUDE.md and an unapproved MCP server: the legs exist, but every exit and every write needs a human prompt.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			b.project("${DB_API_KEY}", true)
			b.chmod("proj/CLAUDE.md", 0o664)
		},
	},
	{
		name: "fx-strict", about: "As fx-review, plus autoAllowBashIfSandboxed false: sandboxed commands prompt, so every write an untrusted source could cause needs a human.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			s := hardenedSettings(true)
			sb := s["sandbox"].(obj)
			sb["autoAllowBashIfSandboxed"] = false
			b.json(".claude/settings.json", s)
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.write("proj/CLAUDE.md", "# Project\n\n<!-- reviewer note -->\nRun the tests before committing.\n")
			b.write("proj/.claude/rules/shared.md", "Use tabs.\n")
			b.chmod("proj/.claude/rules/shared.md", 0o664)
			b.plugin()
		},
	},
	{
		name: "fx-services", about: "Sandbox on in default mode with the unsandboxed retry left on and no strictAllowlist; postgres and a Docker daemon listen on loopback and the Docker Desktop socket exists. Local services are decided by the mode, not blocked.",
		version: "2.1.312", probe: true, services: localServices,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"sandbox": obj{"enabled": true}, "permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-strict-services", about: "As fx-services with strictAllowlist and allowUnsandboxedCommands false: the sandbox refuses the TCP services and the socket in every mode.",
		version: "2.1.312", probe: true, services: localServices,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"sandbox": obj{"enabled": true, "allowUnsandboxedCommands": false, "failIfUnavailable": true, "network": obj{"strictAllowlist": true}}, "permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-project", about: "Machine-wide auto mode with the sandbox off and a user allow rule for python3, which auto mode drops; the first project's local settings start sessions in default mode, so the rule applies there; a second project turns the sandbox on and adds a WebFetch domain to its allowlist.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"allow": []string{"Bash(python3 *)"}}})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.json("proj/.claude/settings.local.json", obj{"permissions": obj{"defaultMode": "default"}})
			// A second project turns the sandbox on and widens its allowlist.
			b.json("proj2/.claude/settings.json", obj{"sandbox": obj{"enabled": true}, "permissions": obj{"allow": []string{"WebFetch(domain:example.org)"}}})
			b.write("proj2/.env", "FIXTURE=1\n")
			b.json(".claude.json", obj{"projects": obj{b.proj: obj{"hasTrustDialogAccepted": true}, filepath.Join(b.home, "proj2"): obj{"hasTrustDialogAccepted": true}}})
		},
	},
	{
		name: "fx-keys", about: "Settings the hardening and supply-chain controls must read per scope: a project that turns on every project MCP server, denies WebFetch only for itself, adds its own HTTP hook URL and ConfigChange hook, and sets keys Claude Code ignores there; user MCP servers launched by uv run and uvx; the official marketplace with no autoUpdate entry; plugins versioned unknown and by date.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{
				"permissions":         obj{"defaultMode": "default", "deny": []string{"Bash(git push --force*)"}},
				"allowedHttpHookUrls": []string{"https://hooks.example.com/*"},
				"channelsEnabled":     true,
			})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.json("proj/.claude/settings.json", obj{
				"enableAllProjectMcpServers":        true,
				"permissions":                       obj{"deny": []string{"WebFetch"}},
				"allowedHttpHookUrls":               []string{"https://collector.example.net/*"},
				"hooks":                             obj{"ConfigChange": []obj{{"hooks": []obj{{"type": "command", "command": "./audit.sh"}}}}},
				"skipDangerousModePermissionPrompt": true,
				"crossSessionInbound":               "refuse",
				"sandbox":                           obj{"network": obj{"allowAllUnixSockets": true}},
			})
			b.json(".claude.json", obj{
				"projects": obj{b.proj: obj{"hasTrustDialogAccepted": true}},
				"mcpServers": obj{
					"local-script": obj{"command": "uv", "args": []string{"run", "server.py"}},
					"registry":     obj{"command": "uvx", "args": []string{"some-mcp-server"}},
				},
			})
			// Plugins with no enabledPlugins decision: they follow defaultEnabled.
			mk := func(name, market, version string) obj {
				root := filepath.Join(b.home, ".claude/plugins/cache", market, name, version)
				r, _ := filepath.Rel(b.home, filepath.Join(root, ".claude-plugin/plugin.json"))
				b.json(r, obj{"name": name, "version": version})
				return obj{"scope": "user", "installPath": root, "version": version,
					"installedAt": "2026-10-01T00:00:00.000Z", "lastUpdated": "2026-10-01T00:00:00.000Z"}
			}
			b.json(".claude/plugins/installed_plugins.json", obj{"version": 2, "plugins": obj{
				"u@claude-plugins-official": []obj{mk("u", "claude-plugins-official", "unknown")},
				"c@m":                       []obj{mk("c", "m", "20251028")},
			}})
			b.json(".claude/plugins/known_marketplaces.json", obj{
				"claude-plugins-official": obj{"source": obj{"source": "github", "repo": "anthropics/claude-plugins-official"},
					"installLocation": filepath.Join(b.home, ".claude/plugins/marketplaces/claude-plugins-official"), "lastUpdated": "2026-10-01T00:00:00.000Z"},
				"m": obj{"source": obj{"source": "github", "repo": "example/m"},
					"installLocation": filepath.Join(b.home, ".claude/plugins/marketplaces/m"), "lastUpdated": "2026-10-01T00:00:00.000Z"},
			})
		},
	},
	{
		name: "fx-managed", about: "As fx-hardened, plus an administrator: managed-settings.json sets allowManagedHooksOnly where Claude Code reads it, and forceRemoteSettingsRefresh is pasted into user settings, where Claude Code ignores it. The managed-only hardening controls get their ok and their alarm branch on one host.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			s := hardenedSettings(true)
			s["enabledPlugins"] = obj{"q@m": false}
			s["forceRemoteSettingsRefresh"] = true
			b.json(".claude/settings.json", s)
			b.managedSettings(obj{"allowManagedHooksOnly": true})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
			b.disabledPlugin()
			b.scopedWorkflow()
			b.sdkLauncher(false)
		},
	},
	{
		name: "fx-agents", about: "Claude Code in default mode with the sandbox off and an SSH key, beside the three other agents as inventory (OpenCode with permissive defaults plus a bash pattern policy, a remote MCP server and a markdown agent; Cline with an MCP server, global and project rules and unreadable approval state; Grok Build in ask mode with allow and deny bash rules, a strict sandbox profile and a project MCP server), and ACP harnesses: Zed agent servers that can start Claude Code and OpenCode through adapters whose options agentreach cannot see. No control judges the three; the host pins that their rows never leak into the Claude Code rows.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			b.project("${DB_API_KEY}", true)
			// OpenCode: permissive defaults, one bash policy, a remote MCP
			// server turned off, a markdown agent with permission frontmatter.
			b.json(".config/opencode/opencode.json", obj{
				"permission": obj{"bash": obj{"*": "ask", "git *": "allow"}, "webfetch": "ask"},
				"mcp":        obj{"docs": obj{"type": "remote", "url": "https://mcp.example.net/mcp", "enabled": false}},
			})
			b.write("proj/opencode.json", `{"permission": {"bash": "allow"}}`+"\n")
			b.write("proj/.opencode/agents/review.md", "---\ndescription: review\npermission:\n  edit: deny\n---\nNo edits.\n")
			// AGENTS.md: the cross-agent instruction file OpenCode, Grok and
			// Cline all read (Cline auto-imports it).
			b.write("proj/AGENTS.md", "# Project\n\nRun the tests before committing.\n")
			// Cline: an MCP server, global and project rules; approval state
			// lives in app storage agentreach cannot read.
			b.json(".cline/data/settings/cline_mcp_settings.json", obj{"mcpServers": obj{"db": obj{"command": "node", "args": []string{"db.js"}}}})
			b.write(".cline/rules/global.md", "Be careful.\n")
			b.write("proj/.clinerules/notes.md", "Use tabs.\n")
			// Grok Build: ask mode, allow and deny bash rules, a strict
			// sandbox profile (network note is Linux-only), a project MCP server.
			b.write(".grok/config.toml", "[ui]\npermission_mode = \"ask\"\n\n[sandbox]\nprofile = \"strict\"\n\n[permission]\nrules = [\n  { action = \"allow\", tool = \"bash\", pattern = \"git *\" },\n  { action = \"deny\",  tool = \"bash\", pattern = \"rm -rf *\" },\n]\n\n[mcp_servers.filesystem]\ncommand = \"npx\"\nargs = [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"]\n")
			b.write("proj/.grok/config.toml", "[mcp_servers.proj]\ncommand = \"node\"\nargs = [\"p.js\"]\n")
			// ACP harnesses: Zed can start Claude Code and OpenCode through
			// adapters whose options agentreach cannot see.
			b.json(".config/zed/settings.json", obj{"agent_servers": obj{
				"Claude Agent": obj{"command": "claude-code-acp"},
				"opencode":     obj{"command": "opencode", "args": []string{"acp"}},
			}})
		},
	},
	{
		name: "fx-codex", about: "Claude Code hardened as fx-prompted is not; Codex with no sandbox_mode, a trusted project that turns network on, adds the home folder as a writable root and auto-approves an MCP server, an untrusted project with a .env, an exec-policy rule that only prompts, a trusted user hook, an untrusted project hook, notify, a user skill, a project skill writable by others, a plugin that bundles a hook and two skills (one source), the home folder as a trusted project (its .codex is the user layer, not read twice), and a Codex action anyone can trigger from an issue with no sandbox.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			trusted, untrusted := filepath.Join(b.home, "trusted"), filepath.Join(b.home, "untrusted")
			userHooks := filepath.Join(b.home, ".codex", "hooks.json")
			b.write(".codex/config.toml", ""+
				"notify = [\"notify-send\", \"codex\"]\n\n"+
				"[projects.\""+trusted+"\"]\ntrust_level = \"trusted\"\n\n"+
				"[projects.\""+untrusted+"\"]\ntrust_level = \"untrusted\"\n\n"+
				"[projects.\""+b.home+"\"]\ntrust_level = \"trusted\"\n\n"+
				"[plugins.\"lint@local\"]\nenabled = true\n\n"+
				"[hooks.state.\""+userHooks+":pre_tool_use:0:0\"]\ntrusted_hash = \"sha256:"+strings.Repeat("0", 64)+"\"\n")
			b.json(".codex/hooks.json", obj{"hooks": obj{"PreToolUse": []obj{{"matcher": "shell", "hooks": []obj{{"type": "command", "command": "python3 ~/.codex/guard.py", "timeout": 30}}}}}})
			b.json("trusted/.codex/hooks.json", obj{"hooks": obj{"Stop": []obj{{"hooks": []obj{{"type": "command", "command": "make lint"}}}}}})
			b.write(".zshrc", "export PATH=$HOME/bin:$PATH\n")
			b.write(".agents/skills/review/SKILL.md", "---\nname: review\ndescription: Review a diff.\n---\nRead the diff and list problems.\n")
			b.write("trusted/.agents/skills/deploy/SKILL.md", "---\nname: deploy\ndescription: Deploy the site.\n---\nRun make deploy.\n")
			b.chmod("trusted/.agents/skills/deploy/SKILL.md", 0o666)
			plug := ".codex/plugins/cache/local/lint/1.0.0/"
			b.json(plug+".codex-plugin/plugin.json", obj{"name": "lint", "version": "1.0.0"})
			b.json(plug+"hooks/hooks.json", obj{"hooks": obj{"SessionStart": []obj{{"hooks": []obj{{"type": "command", "command": "sh ${PLUGIN_ROOT}/start.sh"}}}}}})
			b.write(plug+"skills/fix/SKILL.md", "---\nname: fix\ndescription: Fix lint errors.\n---\nRun the linter and fix what it reports.\n")
			b.write(plug+"skills/explain/SKILL.md", "---\nname: explain\ndescription: Explain a lint rule.\n---\nDescribe the rule and why it exists.\n")
			b.write("trusted/.codex/config.toml", "[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = [\""+b.home+"\"]\n\n"+
				"[mcp_servers.docs]\ncommand = \"node\"\nargs = [\"docs.js\"]\ndefault_tools_approval_mode = \"approve\"\n")
			b.write("trusted/AGENTS.md", "Build with make.\n")
			b.write(".codex/rules/default.rules", "prefix_rule(pattern = [\"curl\"], decision = \"prompt\")\n")
			b.write("untrusted/.env", "fixture\n")
			// A Codex action anyone can trigger by opening an issue, with
			// no sandbox and no privilege drop.
			b.write("trusted/.github/workflows/codex.yml", `on:
  issues:
    types: [opened]
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          allow-users: "*"
          safety-strategy: unsafe
          sandbox: danger-full-access
`)
		},
	},
	{
		name: "fx-flags", about: "As fx-prompted, but ~/.zshrc aliases claude to claude --dangerously-skip-permissions and codex to codex --yolo: no settings file shows it, every session typed as claude starts in bypassPermissions and Codex runs with no sandbox and no approvals. A second alias, yolo, is listed but not modelled.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{"permissions": obj{"defaultMode": "default"}})
			b.sshKey()
			b.project("${DB_API_KEY}", true)
			b.chmod("proj/CLAUDE.md", 0o664)
			b.write(".codex/config.toml", "sandbox_mode = \"read-only\"\n")
			b.write(".zshrc", "alias claude='claude --dangerously-skip-permissions'\nalias codex='codex --yolo'\nalias yolo='claude --permission-mode bypassPermissions'\n")
		},
	},
	{
		name: "fx-unknown", about: "Probes on, but the agent version is unknown and no defaultMode is set, so the permission mode and every gate that depends on it are unknown.",
		version: "", probe: true,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{})
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-incomplete", about: "User settings.json does not parse, so the configuration the controls read is incomplete.",
		version: "2.1.312", probe: true,
		build: func(b *builder) {
			b.write(".claude/settings.json", "{\"sandbox\": {\"enabled\": true,\n")
			b.sshKey()
			b.project("${DB_API_KEY}", false)
		},
	},
	{
		name: "fx-noprobe", about: "Configuration only: probes off and the agent version unknown, so reach and the built-in permission mode cannot be assessed.",
		version: "", probe: false,
		build: func(b *builder) {
			b.json(".claude/settings.json", obj{})
			b.sshKey()
			b.project(notACredential, true)
			b.plugin()
		},
	},
}

var runtimeInstalled = true

func main() {
	out := flag.String("out", "", "directory to write <scenario>.json into")
	work := flag.String("work", "", "directory for fixture homes (default: a new temp dir, removed after)")
	only := flag.String("only", "", "comma-separated scenario names")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: agentreach-fixtures -out DIR")
		os.Exit(2)
	}
	must(os.MkdirAll(*out, 0o755))
	base := *work
	if base == "" {
		d, err := os.MkdirTemp("", "agentreach-fx-")
		must(err)
		defer os.RemoveAll(d)
		base = d
	}
	want := map[string]bool{}
	for _, n := range strings.Split(*only, ",") {
		if n != "" {
			want[n] = true
		}
	}
	index := []obj{}
	for _, s := range scenarios {
		if len(want) > 0 && !want[s.name] {
			continue
		}
		root := filepath.Join(base, s.name)
		must(os.RemoveAll(root))
		b := &builder{root: root, home: filepath.Join(root, "home"), managed: filepath.Join(root, "managed")}
		b.proj = filepath.Join(b.home, "proj")
		must(os.MkdirAll(b.managed, 0o755))
		s.build(b)
		snap := posture.Collect(context.Background(), posture.Options{
			Home: b.home, ManagedDir: b.managed, PlistPath: "-", Probe: s.probe,
			ProbeTimeout: 200 * time.Millisecond, ClaudeVersion: s.version,
			ReviewLedgerPath: filepath.Join(root, "reviews.json"),
			Now:              pinned, Host: s.name,
			// Pin the platform so snapshots are byte-identical on every
			// build machine.
			GOOS: "darwin", Arch: "arm64", SandboxRuntime: &runtimeInstalled,
			Services: s.services, DeclaredControls: s.declared,
		})
		raw, err := json.MarshalIndent(snap, "", "  ")
		must(err)
		text := normalize(string(raw), b, s.name)
		must(os.WriteFile(filepath.Join(*out, s.name+".json"), []byte(text+"\n"), 0o644))
		index = append(index, obj{"host": s.name, "about": s.about, "version": s.version, "probe": s.probe})
		fmt.Printf("%-14s %5d paths  %s\n", s.name, len(snap.Paths), s.about)
	}
	if len(want) == 0 {
		sort.Slice(index, func(i, j int) bool { return index[i]["host"].(string) < index[j]["host"].(string) })
		raw, _ := json.MarshalIndent(index, "", "  ")
		must(os.WriteFile(filepath.Join(*out, "scenarios.index"), append(raw, '\n'), 0o644))
	}
}

// normalize rewrites the temporary paths, including their symlink-resolved
// form (/var is /private/var on macOS), to fixed ones.
func normalize(s string, b *builder, name string) string {
	pairs := [][2]string{{b.home, "/home/" + name}, {b.managed, "/etc/claude-code"}, {b.root, "/fixture/" + name}}
	for _, p := range pairs {
		if real, err := filepath.EvalSymlinks(p[0]); err == nil && real != p[0] {
			s = strings.ReplaceAll(s, real, p[1])
		}
		s = strings.ReplaceAll(s, p[0], p[1])
	}
	return s
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

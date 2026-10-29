# agentreach for Claude Code

A skill-only Claude Code plugin with one skill, `agentreach-posture`. It loads when you ask about your agent's security posture, ask whether a agentreach finding is true, share a dashboard result, or ask for help fixing findings.

- It runs the read-only `agentreach scan` CLI and explains the results: which untrusted content can make the agent read which private file, where it could send it, and what approval stands in the way.
- On request it checks findings, from a scan or the Powerpipe dashboard, against the real configuration: what agentreach saw, the settings files themselves, and inert behaviour checks. Each finding comes back confirmed, confirmed but scoped, refuted (a agentreach bug) or not verifiable. It then offers fixes for the confirmed ones, one at a time with your yes. Fixes only tighten settings, back up the file first, and never touch managed settings. Inline credentials are moved by a script you run with the agents quit, never by Claude.

The plugin has no hooks and no MCP servers. agentreach itself counts plugin hooks as an exit channel, because they run outside the sandbox, so it does not ship one.

## Install

```text
/plugin marketplace add somoore/steampipe-plugin-agentreach
/plugin install agentreach@agentreach
```

The skill needs the CLI: `make cli` in this repository (Go 1.26), or `GOPRIVATE=github.com/somoore/* go install github.com/somoore/steampipe-plugin-agentreach/cmd/agentreach@v0.1.1`. Pin a release; agentreach's own supply-chain checks flag an unpinned install.

## Optional: a scan at session start

If you want a one-line posture summary when a session starts, add this to your own `~/.claude/settings.json`. It is opt-in, lives in your settings rather than the plugin, and is a hook that runs outside the sandbox, so agentreach will list it. It prints only counts.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "command -v agentreach >/dev/null && agentreach scan --format json --no-probe | jq -r '\"agentreach: \\(.summary.failing) failing finding(s); run the agentreach-posture skill for details\"' || true",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

`--no-probe` keeps the hook fast; the summary is therefore marked not fully assessed. Run the skill for a full scan.

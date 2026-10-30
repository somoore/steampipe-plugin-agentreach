---
name: agentreach-posture
description: Check what this machine's coding agent can reach and where it can send data with the read-only agentreach scanner, check agentreach findings against the real configuration, and help fix the confirmed ones. Use when the user asks whether Claude Code (or another coding agent) can read their secrets, what an attacker-controlled file could make it do, or how locked down their agent setup is; asks whether a agentreach finding is true or accurate; shares a agentreach or Powerpipe dashboard result or screenshot (such as "Shell commands run inside an enforced sandbox"); or asks for help fixing agentreach findings.
---

# agentreach posture check

agentreach is a read-only scanner. It reads the agent's settings and runs inert probes (a one-byte read, a TCP connect and close). It never changes configuration, never sends data anywhere, and never stores secret values.

## Rules

- The scan and the explanation are read-only. Change nothing while scanning or explaining. Checking findings and fixing them follow verify-and-fix.md, where every change needs the user's explicit yes.
- Never print, quote or echo a secret value, even if you come across one. agentreach reports `has_inline_secret` and server names only; keep it that way. Do not open the files a finding names to "check" a credential.
- Do not run agentreach with extra flags that send data, there are none; do not pipe its output to any network tool.

## 1. Find or build the CLI

Run `command -v agentreach`. If it is missing:

- With Go 1.26 or later and a checkout of github.com/somoore/steampipe-plugin-agentreach: `make cli` there, then use `./bin/agentreach`.
- Otherwise install the pinned release: `go install github.com/somoore/steampipe-plugin-agentreach/cmd/agentreach@v0.2.0`. Never `@latest`: an unpinned install is what agentreach's own supply-chain checks flag.

Tell the user which one you used. Do not download prebuilt binaries from anywhere else.

## 2. Scan

```bash
AGENTREACH_DIR=$(mktemp -d) && agentreach scan --format json --out "$AGENTREACH_DIR/agentreach-report.json"; echo "exit=$? dir=$AGENTREACH_DIR"
```

`$TMPDIR` is unset on most Linux machines, so always use `mktemp -d`.

Exit codes: 0 nothing failing and fully assessed; 1 failing findings; 2 nothing failing but part of the posture was not assessed; 3 usage or runtime error. Exit 2 is not a pass: say what was not assessed (`summary.not_assessed_reasons`).

If a reason says agentreach ran inside a sandbox, the probes were skipped: inside the sandbox they would measure the sandbox, not what the agent's Read tool, MCP servers and hooks can reach. Do not retry with the sandbox turned off yourself. Ask the user to run the scan in their own terminal, for example by typing `! agentreach scan` in Claude Code, and read that output instead.

Read the report with `jq`, not by printing it whole; it can hold thousands of paths:

```bash
jq '.summary' "$AGENTREACH_DIR/agentreach-report.json"
jq '[.findings[] | select(.failing)] | group_by(.rule_id) | map({rule: .[0].rule_id, n: length})' "$AGENTREACH_DIR/agentreach-report.json"
jq '[.findings[] | select(.failing)][0:5]' "$AGENTREACH_DIR/agentreach-report.json"
```

`summary.assumptions` says which surface the gates model (a terminal session unless agentreach could tell); mention it when the user starts Claude Code another way, such as `claude -p`, the Agent SDK or VS Code.

## 3. Explain

Lead with one sentence: the worst thing that can happen, in plain words. Findings are already sorted worst first.

- `AgentReach-PATH-CONF`: content the user did not write (a plugin file, a third-party instruction file, an unapproved MCP server, a web page) can make the agent read a private file and send it out. `approval` is the strongest gate on any step, the source included (a fetched page counts as ungated, because some domains fetch with no prompt; when `after_source_approval` is `none`, the only gate is approving the source, such as a project MCP server, and nothing asks after that): `none` means nothing asks the user; `classifier` means only auto mode's classifier; `prompt` means the user is asked. By default classifier-only paths fail when the sandbox is not enforced. A finding with `status: attested` goes through an exit the user declared closed; agentreach did not verify that, so say so.
- `AgentReach-PATH-INTEGRITY`: the same kind of content can make the agent change settings, CI, dependency manifests, git hooks or shell startup files.
- `AgentReach-MCP-INLINE-SECRET`: an MCP server's configuration holds a credential in the file. Name the server and file only.
- `AgentReach-NOT-ASSESSED`: say what evidence is missing. Never call the machine safe while this is present.

Every path needs all of its legs; cutting one removes it. Count paths per fix and suggest the fix that removes the most, in the vendor's own setting, for example:

- Enforce the sandbox: `sandbox.enabled: true`, `sandbox.allowUnsandboxedCommands: false`, and refuse unlisted hosts with `sandbox.network.strictAllowlist: true`.
- Deny reads of credential directories: `sandbox.filesystem.denyRead` and `permissions.deny` entries such as `Read(~/.ssh/**)`.
- Deny `WebFetch`, or disable an MCP server with `disabledMcpjsonServers`.
- Move an inline credential to the environment and reference it as `${VAR}`, then rotate it.

Show the settings snippet and which file it belongs in (`~/.claude/settings.json` for the user, `.claude/settings.json` for a project, managed settings for an organization). Then offer to check the findings against the real configuration and to help fix the confirmed ones.

## 4. Check and fix

When the user asks whether a finding is true, shares a dashboard result, or wants help fixing findings, read [verify-and-fix.md](verify-and-fix.md) in this skill's directory and follow it. Its rules apply to every change: tighten only, one fix at a time, ask first.

For more depth, the Powerpipe mod github.com/somoore/steampipe-mod-agentreach-compliance has the controls and a dashboard.

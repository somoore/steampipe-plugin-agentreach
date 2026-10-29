connection "agentreach" {
  plugin = "local/agentreach"

  # Project directories to inspect for project-scoped settings, hooks, MCP
  # servers and instruction files. When omitted, agentreach discovers projects from
  # the agent's own records (for Claude Code: the `projects` map in
  # ~/.claude.json) and keeps only directories that still exist on disk.
  # project_dirs = ["~/github/myapp"]

  # Run inert reachability probes (open-for-read on sensitive paths, TCP dial
  # to localhost services). Probes never read secrets, send data, or modify
  # anything. Set to false for a config-only inventory.
  probe = true

  # Run the file and loopback probes a second time inside Anthropic's sandbox
  # runtime (srt, npm @anthropic-ai/sandbox-runtime) configured from the
  # effective managed and user sandbox settings. Rows gain
  # observed_via_sandbox and model_agrees. Needs srt on PATH or srt_path.
  # observe  = false
  # srt_path = ""

  # Controls outside the agent that you know exist but agentreach cannot see from
  # this machine. Reported as declared, never as verified. Known names:
  # egress_allowlist, devcontainer, vm, edr, secrets_broker.
  # declared_controls = ["egress_allowlist"]

  # Review ledger written by "agentreach review"; files reviewed at their current
  # SHA-256 stop counting as untrusted sources.
  # review_ledger = "~/.config/agentreach/reviews.json"

  # Agents to collect; empty means all supported.
  # agents = ["claude_code"]

  # Fleet mode: read snapshot JSON files instead of collecting this machine.
  # Every row carries host and snapshot_id.
  # snapshot_paths = ["~/agentreach-snapshots/*.json"]
}

# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability**
on this repository. You can also open a security advisory draft
(GitHub → Security → Advisories).

Include what you found, how to reproduce it, and whether you plan to publish
it. Reports are answered within 7 days. Coordinated disclosure is preferred;
credit is given on request.

## Scope

- The collectors (`pkg/posture`) and everything they read: a crash, a
  secret leak into a table or a snapshot, or any write to the machine are
  in scope and serious.
- The CI pipelines and the fixture generator.
- The Powerpipe mod's SQL: a control that reports `ok` for an unsafe state,
  or mixes one machine's rows into another's, is in scope.
- Out of scope: the vendors' own products (Claude Code, Codex, OpenCode,
  Cline, Grok Build) and the documents they publish.

## Design guarantees to test against

- agentreach never writes, never sends anything, and never runs an agent.
  File probes read at most one byte; network probes dial and disconnect.
- Secret values are never stored: values are classified to booleans, and
  free text is scrubbed (`redact.go`) on every surface.
- A file discovered inside a repository or a plugin is read only if it
  resolves inside that tree. A symlinked instruction file that points
  elsewhere is recorded as a collect error and is not fingerprinted; a
  symlinked `--out`/`--snapshot-out` path is refused.
- Operator-owned inputs are trusted config, not untrusted data: `srt_path`
  in the connection config names a program the plugin runs, and the action's
  `args` input is workflow configuration.
- A machine with no coding agent installed is a clean result, not a finding.
- Model gates carry their evidence type; a gate agentreach cannot establish
  is `unknown`, never "safe".

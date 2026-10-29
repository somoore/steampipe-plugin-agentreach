# agentreach CLI

A standalone, read-only scanner built on the same collector (`pkg/posture`) as the Steampipe plugin. Build it with `make cli` (writes `./bin/agentreach`).

```text

Usage:
  agentreach scan [flags] [PROJECT_DIR...]
  agentreach version

Scan flags:
  --format text|json|sarif   output format (default text)
  --out FILE                 write the report to FILE instead of stdout
  --snapshot-out FILE        also write the raw snapshot JSON to FILE
  --from SNAPSHOT.json       report a saved snapshot instead of collecting
  --no-probe                 skip the inert reachability probes (result is not fully assessed)
  --fail-on none|classifier|prompt|never
                             fail on paths whose approval is at or below this gate (default none)

Exit codes:
  0  no failing finding, fully assessed
  1  at least one failing finding
  2  no failing finding, but part of the posture was not assessed
  3  usage or runtime error
```

## Findings

Every finding comes from a value the collector already computed; the CLI adds no rules.

| Rule | From | Level |
|------|------|-------|
| `AgentReach-PATH-CONF` | a candidate confidentiality path in `agentreach_path` | error when `approval` is none, warning for classifier, note for prompt |
| `AgentReach-PATH-INTEGRITY` | a candidate integrity path | same |
| `AgentReach-MCP-INLINE-SECRET` | an MCP server with `has_inline_secret` | error |
| `AgentReach-NOT-ASSESSED` | collect errors, probes off, an unknown permission mode, or paths whose approval is unknown | warning; sets exit code 2 |

A finding is failing when its approval is at or below `--fail-on` (unknown never fails; it makes the scan not assessed). Inline secrets fail unless `--fail-on never`.

## Output

- `text`: a summary and the ten worst failing findings.
- `json`: `{schema_version, collector_version, snapshot_id, host, findings, summary}`.
- `sarif`: SARIF 2.1.0 for code scanning; `partialFingerprints.agentreachPathId/v1` is the stable `path_id`.

Home directories are written as `~` in messages, and every string is passed through the collector's credential scrubber again before it is printed. `--snapshot-out` and `--out` files are created with mode 0600.

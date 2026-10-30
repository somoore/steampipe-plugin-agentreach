# Monthly live check

Fixtures prove the model. A live scan is what catches a new agent release that
changed behaviour in a way the fixtures do not describe.

```bash
make live-check            # scan now, compare with the previous run
make live-check-install    # schedule it monthly with launchd
make live-check-uninstall  # remove the schedule
```

## What it does

`tools/live-check.sh` runs the installed release once with probes on, saves
three files, and compares the result with the previous snapshot:

| File | Contents |
|------|----------|
| `report-YYYY-MM-DD.json.gz` | the findings report |
| `snapshot-YYYY-MM-DD.json.gz` | the raw collector snapshot |
| `scan-YYYY-MM-DD.txt` | the text report |

It prints the agents and their versions, the path counts by gate, the failing
findings, and any change since last time: a new or removed agent, a version
change, a failing rule that appeared or disappeared, or a rule whose count
moved by 10% or more (small moves are usually a local service starting or
stopping).

## Where the reports live

- macOS: `~/Library/Logs/agentreach`
- Linux: `~/.local/state/agentreach`
- Override with `AGENTREACH_STATE_DIR`

The directory is mode 0700 and the reports are 0600. The JSON is compressed
(one snapshot is about 20 MB of paths). Nothing is sent anywhere. The last 12
monthly runs are kept.

## The schedule

`make live-check-install` writes `~/Library/LaunchAgents/com.agentreach.livecheck.plist`
and loads it. It runs on the first of every month at 09:17 local time, and
after wake if the Mac was asleep. Output goes to `launchd.log` in the same
directory.

It uses `~/.local/bin/agentreach` by default. Point it elsewhere with
`AGENTREACH_BIN=/path/to/agentreach make live-check-install`.

On macOS a notification appears when the comparison found changes. Set
`AGENTREACH_NOTIFY=0` in the plist's environment to turn that off.

## Exit codes

The script exits with the scan's own code: 0 clean, 1 failing findings, 2 not
fully assessed. The launchd job ignores it; the report carries the detail.

## Why a live check

Everything in the collector's model is checked against documents and fixtures,
but a real machine has combinations the fixtures were not built from. The two
gate bugs found by the first live run (Codex MCP approval and Grok double
reading its home config) were invisible to 19 fixture hosts. A monthly run
costs one scan and closes that gap.

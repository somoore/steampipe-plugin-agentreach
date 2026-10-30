#!/usr/bin/env bash
# Monthly live check: scan this machine with the installed agentreach release,
# keep a dated report, and say what changed since the previous run.
#
#   ./tools/live-check.sh              scan now
#   AGENTREACH_BIN=/path/to/agentreach ./tools/live-check.sh
#   AGENTREACH_STATE_DIR=/tmp/state ./tools/live-check.sh
#
# Reports go to ~/Library/Logs/agentreach on macOS and
# ~/.local/state/agentreach elsewhere, mode 0600. Nothing leaves the machine.
# The exit code is the scan's: 0 clean, 1 failing findings, 2 not fully
# assessed.
set -uo pipefail
umask 077

bin="${AGENTREACH_BIN:-$(command -v agentreach 2>/dev/null || true)}"
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
  echo "live-check: agentreach not found. Put it on PATH or set AGENTREACH_BIN." >&2
  exit 3
fi

if [ -n "${AGENTREACH_STATE_DIR:-}" ]; then
  state="$AGENTREACH_STATE_DIR"
elif [ "$(uname -s)" = "Darwin" ]; then
  state="$HOME/Library/Logs/agentreach"
else
  state="${XDG_STATE_HOME:-$HOME/.local/state}/agentreach"
fi
mkdir -p "$state"
chmod 700 "$state"
# launchd creates its log with the default umask; keep the whole directory
# private, not only the reports.
[ -f "$state/launchd.log" ] && chmod 600 "$state/launchd.log"

day="$(date +%Y-%m-%d)"
report="$state/report-$day.json.gz"
snapshot="$state/snapshot-$day.json.gz"
text="$state/scan-$day.txt"
prev_snapshot=""
for f in "$state"/snapshot-*.json.gz; do
  [ -e "$f" ] || continue
  [ "${f##*/}" = "snapshot-$day.json.gz" ] && continue
  prev_snapshot="$f" # names are dates, so the last match is the newest
done
prev_report=""
if [ -n "$prev_snapshot" ]; then
  prev_report="${prev_snapshot/snapshot-/report-}"
fi

# One probe pass, then a text report from the saved snapshot so the scan is
# not repeated. The JSON is compressed: a snapshot is about 20 MB of paths.
"$bin" scan --format json --out "$state/report-$day.json" --snapshot-out "$state/snapshot-$day.json" || code=$?
code="${code:-0}"
"$bin" scan --from "$state/snapshot-$day.json" --format text --out "$text" >/dev/null 2>&1 || true
gzip -f "$state/report-$day.json" "$state/snapshot-$day.json"

summary="$(python3 - "$snapshot" "${prev_snapshot:-}" "$report" "${prev_report:-}" <<'PY'
import gzip, json, sys

cur_s, prev_s, cur_r, prev_r = sys.argv[1:5]

def load(path):
    if not path:
        return None
    try:
        with (gzip.open if path.endswith(".gz") else open)(path, "rt") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

cs, ps = load(cur_s), load(prev_s)
cr, pr = load(cur_r), load(prev_r)

def agents(s):
    return {a.get("agent", "?"): (a.get("version") or "") for a in (s or {}).get("agents") or []}

def paths(s):
    out = {}
    for p in (s or {}).get("paths") or []:
        g = p.get("approval") or "unknown"
        out[g] = out.get(g, 0) + 1
    return out

def failing(report):
    out = {}
    for f in (report or {}).get("findings") or []:
        if f.get("failing"):
            out[f.get("rule_id", "?")] = out.get(f.get("rule_id", "?"), 0) + 1
    return out

ca, pa = agents(cs), agents(ps)
cp, pp = paths(cs), paths(ps)
cf, pf = failing(cr), failing(pr)
errors = len((cs or {}).get("errors") or [])

lines = []
lines.append("host %s  snapshot %s  collector %s" % (
    (cs or {}).get("host", "?"), (cs or {}).get("snapshot_id", "?")[:12], (cs or {}).get("collector_version", "?")))
lines.append("agents: " + (", ".join("%s %s" % (k, v or "(no version)") for k, v in sorted(ca.items())) or "none"))
lines.append("paths: %d (none %d, classifier %d, prompt %d, unknown %d)" % (
    sum(cp.values()), cp.get("none", 0), cp.get("classifier", 0), cp.get("prompt", 0), cp.get("unknown", 0)))
lines.append("failing findings: %d" % sum(cf.values()))
lines.append("collect errors: %d" % errors)

changes = []
if ps is not None:
    for name in sorted(set(ca) - set(pa)):
        changes.append("new agent %s %s" % (name, ca[name] or "(no version)"))
    for name in sorted(set(pa) - set(ca)):
        changes.append("agent gone %s" % name)
    for name in sorted(set(ca) & set(pa)):
        if ca[name] != pa[name] and ca[name] and pa[name]:
            changes.append("%s %s -> %s" % (name, pa[name], ca[name]))
    for rule in sorted(set(cf) - set(pf)):
        changes.append("new failing rule %s (%d)" % (rule, cf[rule]))
    for rule in sorted(set(pf) - set(cf)):
        changes.append("rule no longer failing %s" % rule)
    for rule in sorted(set(cf) & set(pf)):
        # A count that moves a few percent is usually a service starting or
        # stopping (the path count is a product of sources, files and exits).
        # Report a change of 10% or more, or any rule that appears or goes.
        if cf[rule] != pf[rule] and abs(cf[rule] - pf[rule]) / max(pf[rule], 1) >= 0.10:
            changes.append("%s %d -> %d" % (rule, pf[rule], cf[rule]))
    if errors != len((ps or {}).get("errors") or []):
        changes.append("collect errors %d -> %d" % (len((ps or {}).get("errors") or []), errors))

if ps is None:
    lines.append("first run: no previous snapshot to compare")
elif changes:
    lines.append("changes since %s:" % (ps or {}).get("collected_at", "the previous run")[:10])
    lines.extend("  " + c for c in changes)
else:
    lines.append("no change since %s" % (ps or {}).get("collected_at", "the previous run")[:10])

print("\n".join(lines))
PY
)"

printf '%s\n' "$summary"
printf '%s\n' "$summary" >"$state/latest.txt"

# Keep a year of monthly reports.
files=()
for f in "$state"/report-*.json.gz; do
  [ -e "$f" ] && files+=("$f")
done
while [ "${#files[@]}" -gt 12 ]; do
  old="${files[0]}"
  d="${old##*/report-}"
  d="${d%.json.gz}"
  rm -f "$old" "$state/snapshot-$d.json.gz" "$state/scan-$d.txt"
  files=("${files[@]:1}")
done

if [ "$(uname -s)" = "Darwin" ] && [ "${AGENTREACH_NOTIFY:-1}" = "1" ]; then
  if printf '%s' "$summary" | grep -q "^changes since"; then
    n="$(printf '%s\n' "$summary" | grep -c '^  ')"
    osascript -e "display notification \"$n change(s) since the last run\" with title \"agentreach live check\"" >/dev/null 2>&1 || true
  fi
fi

exit "$code"

#!/usr/bin/env bash
# Drift alarm for the behaviour model. The gates, defaults, protected files
# and settings rules in pkg/posture were built from the Claude Code
# documents listed in ci/docs-baseline.sha256. When a page's content hash
# changes, the model may need re-verification; this script fails with the
# pages that moved.
#
#   ./ci/docs_drift.sh            check (CI, weekly)
#   ./ci/docs_drift.sh --update   re-hash every page after re-verifying
#
# To watch a new page, append a line with a zero hash and its URL, then run
# --update. Pages that serve markdown (.md) are hashed raw; HTML pages are
# hashed as tag-stripped, whitespace-normalized text, because their raw
# markup carries volatile nonces.
#
# When this fails: re-read the changed pages against pkg/posture
# (approval.go, codexmodel.go, managed.go, sandboxmodel.go,
# launchflags.go), update what moved, bump ModelBasis* in modelbasis.go,
# refresh the fixtures' pinned versions if behaviour changed, then run
# --update.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

base=ci/docs-baseline.sha256
update=0
[ "${1:-}" = "--update" ] && update=1
[ -f "$base" ] || { echo "  FAIL $base is missing"; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  H="sha256sum"
else
  H="shasum -a 256"
fi
NORM='import sys, re, html
b = sys.stdin.buffer.read().decode("utf-8", "replace")
b = re.sub(r"<(script|style).*?</\1>", "", b, flags=re.S | re.I)
b = re.sub(r"<[^>]+>", " ", b)
b = html.unescape(b)
b = re.sub(r"\s+", " ", b)
sys.stdout.write(b.strip())'

# fetch_hash prints the content hash of a page: raw for markdown, stripped
# text for HTML.
fetch_hash() {
  case "$1" in
    *.md) curl -fsSL --max-time 60 "$1" | $H ;;
    *)    curl -fsSL --max-time 60 "$1" | python3 -c "$NORM" | $H ;;
  esac
}

fail=0
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
while read -r want url; do
  case "$want" in '' | \#*) continue ;; esac
  got=$(fetch_hash "$url" | cut -d' ' -f1) || { echo "  FAIL could not fetch $url"; fail=1; continue; }
  if [ "$got" != "$want" ]; then
    if [ "$update" = 1 ]; then
      echo "  updated $url"
    else
      echo "  FAIL $url changed since the baseline (was ${want:0:12}, now ${got:0:12})"
      echo "        re-verify pkg/posture against it, bump ModelBasis*, then: ./ci/docs_drift.sh --update"
      fail=1
    fi
  fi
  printf '%s  %s\n' "$got" "$url" >> "$tmp"
done < "$base"

if [ "$update" = 1 ]; then
  cp "$tmp" "$base"
  echo "  ok: $base refreshed"
elif [ "$fail" = 0 ]; then
  echo "  ok: every cited document matches the baseline"
fi
exit $fail

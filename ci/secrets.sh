#!/usr/bin/env bash
# Secret scan for this repo. Prints file:line only, never the match.
#   1. no credential-shaped files tracked
#   2. no secret-shaped strings in the working tree (tests build fake
#      credentials at runtime, e.g. strings.Repeat, so none should appear)
#   3. gitleaks over the whole git history (and the working tree)
# AGENTREACH_GITLEAKS_REQUIRED=1 fails when gitleaks is missing (CI sets it).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0
files=$(git ls-files -co --exclude-standard \
  | grep -E '(^|/)\.env($|\.)|(^|/)credentials(\.|$)|\.pem$|\.p12$|id_rsa|id_ed25519' || true)
if [ -n "$files" ]; then echo "FAIL credential-shaped file(s):"; echo "$files" | sed 's/^/    /'; fail=1; else echo "ok   no credential-shaped files"; fi
hits=$(git grep -nIlE '(sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}|tskey-[A-Za-z0-9-]{20,}|xox[abposc]-[A-Za-z0-9-]{20,}|glpat-[A-Za-z0-9_-]{15,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|dop_v1_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{20,})' -- . || true)
if [ -n "$hits" ]; then echo "FAIL secret-shaped string(s) in:"; echo "$hits" | sed 's/^/    /'; fail=1; else echo "ok   no secret-shaped strings"; fi
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --source . --redact --no-banner >/dev/null 2>&1 \
     && gitleaks detect --source . --no-git --redact --no-banner >/dev/null 2>&1; then
    echo "ok   gitleaks: history and tree clean"
  else
    echo "FAIL gitleaks found secret(s); run: gitleaks detect --source . --redact"; fail=1
  fi
elif [ "${AGENTREACH_GITLEAKS_REQUIRED:-0}" = 1 ]; then
  echo "FAIL gitleaks not installed"; fail=1
else
  echo "skip gitleaks not installed"
fi
exit $fail

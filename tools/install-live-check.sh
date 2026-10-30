#!/usr/bin/env bash
# Install (or remove) a launchd job that runs tools/live-check.sh on the first
# of every month at 09:17 local time. The job runs when the Mac is awake; a
# run missed while asleep happens after wake.
#
#   ./tools/install-live-check.sh              install or replace
#   ./tools/install-live-check.sh --uninstall   remove
#
# Needs the agentreach release binary at AGENTREACH_BIN, default
# ~/.local/bin/agentreach.
set -euo pipefail

label="com.agentreach.livecheck"
plist="$HOME/Library/LaunchAgents/$label.plist"
domain="gui/$(id -u)"

if [ "${1:-}" = "--uninstall" ]; then
  launchctl bootout "$domain/$label" 2>/dev/null || true
  rm -f "$plist"
  echo "removed $label"
  exit 0
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
bin="${AGENTREACH_BIN:-$HOME/.local/bin/agentreach}"
if [ ! -x "$bin" ]; then
  echo "install: $bin is not executable." >&2
  echo "         curl the release binary there, or set AGENTREACH_BIN." >&2
  exit 1
fi

if [ -n "${AGENTREACH_STATE_DIR:-}" ]; then
  state="$AGENTREACH_STATE_DIR"
else
  state="$HOME/Library/Logs/agentreach"
fi
mkdir -p "$state" "$HOME/Library/LaunchAgents"
chmod 700 "$state"

cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$repo/tools/live-check.sh</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENTREACH_BIN</key>
    <string>$bin</string>
    <key>AGENTREACH_STATE_DIR</key>
    <string>$state</string>
    <key>PATH</key>
    <string>$HOME/.local/bin:$HOME/.opencode/bin:$HOME/.grok/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Day</key>
    <integer>1</integer>
    <key>Hour</key>
    <integer>9</integer>
    <key>Minute</key>
    <integer>17</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>$state/launchd.log</string>
  <key>StandardErrorPath</key>
  <string>$state/launchd.log</string>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
EOF
chmod 644 "$plist"

launchctl bootout "$domain/$label" 2>/dev/null || true
launchctl bootstrap "$domain" "$plist"
launchctl enable "$domain/$label"

echo "installed $label"
echo "  runs:     first of every month, 09:17"
echo "  script:   $repo/tools/live-check.sh"
echo "  binary:   $bin"
echo "  reports:  $state (mode 0700, reports 0600)"
echo "  run now:  make live-check"
echo "  logs:     $state/launchd.log"

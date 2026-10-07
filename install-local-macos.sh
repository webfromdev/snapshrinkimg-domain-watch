#!/bin/bash
# Installs a launchd agent that runs the watcher every 20 minutes while this
# Mac is awake. This is the BACKUP to the GitHub Actions workflow -- it only
# runs when the machine is on, so don't rely on it alone.
#
#   ./install-local-macos.sh            install + start
#   ./install-local-macos.sh uninstall  remove
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="com.local.domainwatch"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
INTERVAL=1200   # seconds (20 minutes)

if [ "${1:-}" = "uninstall" ]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Removed $LABEL"
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents" "$DIR/logs"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>$DIR/watch_domain.py</string>
    <string>--state</string>
    <string>$DIR/state.local.json</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>WATCH_DOMAIN</key><string>${WATCH_DOMAIN:-snapshrinkimg.com}</string>
    <key>NTFY_TOPIC</key><string>${NTFY_TOPIC:-}</string>
  </dict>
  <key>StartInterval</key><integer>$INTERVAL</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$DIR/logs/watch.log</string>
  <key>StandardErrorPath</key><string>$DIR/logs/watch.err</string>
</dict>
</plist>
PLISTEOF

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/$LABEL"

echo "Installed $LABEL (every $((INTERVAL/60)) min while this Mac is awake)."
echo "Logs:      $DIR/logs/watch.log"
echo "Uninstall: $0 uninstall"

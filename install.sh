#!/bin/zsh
# Installs devhub as a launchd agent: starts at login, restarts if it crashes.
#   ./install.sh            install / reinstall (also after editing ~/.devhub/config.json)
#   ./install.sh uninstall  stop and remove the agent (keeps ~/.devhub history)
set -euo pipefail

DIR="${0:A:h}"
LABEL="local.devhub"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="$(command -v python3)"
DOMAIN="gui/$(id -u)"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true

if [[ "${1:-}" == "uninstall" ]]; then
  rm -f "$PLIST"
  echo "devhub removed. History is still in ~/.devhub"
  exit 0
fi

mkdir -p "$HOME/.devhub/logs" "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string>
    <string>$DIR/devhub.py</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>StandardOutPath</key><string>$HOME/.devhub/hub.log</string>
  <key>StandardErrorPath</key><string>$HOME/.devhub/hub.log</string>
</dict>
</plist>
EOF

launchctl bootstrap "$DOMAIN" "$PLIST"
sleep 2
PORT=$("$PY" -c "import json,os;print(json.load(open(os.path.expanduser('~/.devhub/config.json'))).get('port',80))" 2>/dev/null || echo 80)
if curl -fsS -o /dev/null "http://localhost:$PORT/_hub/api/state"; then
  echo "devhub is running → http://localhost:$PORT"
else
  echo "devhub did not answer yet; check ~/.devhub/hub.log"
fi

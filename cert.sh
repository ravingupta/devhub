#!/bin/zsh
# Let's Encrypt wildcard certificate for devhub (<domain> and *.<domain>) via a DNS-01 challenge.
#   ./cert.sh            issue the first time, afterwards renew when < 30 days are left
#   ./cert.sh schedule   check daily at 04:00 via launchd
# Credentials for your DNS provider live in ~/.devhub/dns.env (see the message below).
set -euo pipefail

DIR="${0:A:h}"
HUB="$HOME/.devhub"
ENV_FILE="$HUB/dns.env"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if [[ "${1:-}" == "schedule" ]]; then
  PLIST="$HOME/Library/LaunchAgents/local.devhub.cert.plist"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.devhub.cert</string>
  <key>ProgramArguments</key><array><string>$DIR/cert.sh</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>4</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>$HUB/cert.log</string>
  <key>StandardErrorPath</key><string>$HUB/cert.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)/local.devhub.cert" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "renewal check scheduled daily at 04:00 (log: $HUB/cert.log)"
  exit 0
fi

DOMAIN=$(python3 -c "import json;print(json.load(open('$HUB/config.json')).get('domain',''))")
[[ -n "$DOMAIN" ]] || { echo "set \"domain\" in $HUB/config.json first"; exit 1; }

if [[ ! -f "$ENV_FILE" ]]; then
  cat <<EOF
Create $ENV_FILE (chmod 600) with your DNS provider's API credentials, for example:

  # Cloudflare: a token with Zone:DNS:Edit on your zone
  DNS_PROVIDER=cloudflare
  CF_DNS_API_TOKEN=...

  # GoDaddy: https://developer.godaddy.com/keys (production key)
  DNS_PROVIDER=godaddy
  GODADDY_API_KEY=...
  GODADDY_API_SECRET=...

Optional: ACME_EMAIL=you@example.com
Any provider lego supports works: https://go-acme.github.io/lego/dns/
EOF
  exit 1
fi
set -a; source "$ENV_FILE"; set +a
command -v lego >/dev/null || brew install lego

# lego v5: `run` both issues and renews (only when due), options go after the command.
args=(--accept-tos --dns "$DNS_PROVIDER" --dns.resolvers 1.1.1.1:53 --path "$HUB/lego"
      -d "$DOMAIN" -d "*.$DOMAIN")
[[ -n "${ACME_EMAIL:-}" ]] && args+=(--email "$ACME_EMAIL")

first_time=0
[[ -f "$HUB/certs/fullchain.pem" ]] || first_time=1
lego run "${args[@]}"

CRT=$(ls -t "$HUB"/lego/certificates/*"$DOMAIN"*.crt 2>/dev/null | grep -v issuer | head -1)
KEY="${CRT%.crt}.key"
[[ -f "$CRT" && -f "$KEY" ]] || { echo "lego finished but no certificate found in $HUB/lego/certificates"; exit 1; }

mkdir -p "$HUB/certs"
install -m 600 "$CRT" "$HUB/certs/fullchain.pem"
install -m 600 "$KEY" "$HUB/certs/privkey.pem"
echo "$(date '+%F %T') certificate in place for $DOMAIN, *.$DOMAIN"

# devhub enables HTTPS at startup and reloads renewed certs on its own.
(( first_time )) && "$DIR/install.sh"
exit 0

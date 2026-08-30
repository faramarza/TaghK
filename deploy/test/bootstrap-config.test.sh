#!/usr/bin/env bash
# bootstrap-config.test.sh — the configs bootstrap.sh generates, parsed and served.
#
# bootstrap.sh has never been run (04-STATUS.md §1). It needs a real VPS, root,
# systemd, and package installs, none of which exist in CI. What CAN be checked
# without a VPS is the part that actually encodes the security properties: the
# Xray and nginx configuration it writes.
#
# So this extracts the two configuration heredocs from the real script, expands
# them with the same variables bootstrap.sh would have set, and then:
#   * parses the Xray config and asserts the privacy properties 03-SECURITY §3.4
#     claims for it;
#   * runs the nginx site config through nginx -t;
#   * SERVES it and checks the camouflage and WebSocket-path behaviour over real
#     HTTP — a path that 404s to a scanner but proxies a genuine upgrade.
#
# What it does NOT check: xray itself (no binary available here), systemd
# hardening, sysctl, ufw, fail2ban, or SSH. Those need a real host — see P1.
set -uo pipefail
cd "$(dirname "$0")/.."
DIR=/tmp/tk-bootcfg
PORT=9450

fail=0
count=0
check() {
  count=$((count + 1))
  if [[ "$1" == "0" ]]; then printf '  \033[32m✓\033[0m %s\n' "$2"
  else printf '  \033[31m✗\033[0m %s\n' "$2"; fail=$((fail + 1)); fi
}
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

[[ -f "$DIR/nginx.pid" ]] && nginx -s quit -c "$DIR/nginx.conf" -p "$DIR" 2>/dev/null
rm -rf "$DIR"; mkdir -p "$DIR/www" "$DIR/logs" "$DIR/tmp"

# The variables bootstrap.sh computes before writing its configs.
export REALITY_DEST="www.apple.com"
export PRIVATE_KEY="0000000000000000000000000000000000000000000"
export SHORTID_JSON='"ab","cdef"'
export WS_PATH="/$(openssl rand -hex 12)"
export CLIENTS_VISION='[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision"},{"id":"22222222-2222-2222-2222-222222222222","flow":"xtls-rprx-vision"}]'
export CLIENTS_WS='[{"id":"11111111-1111-1111-1111-111111111111"},{"id":"22222222-2222-2222-2222-222222222222"}]'

# Pull each heredoc body straight out of the real script, so this test tracks
# bootstrap.sh rather than a copy of it that can drift.
# awk with an exact line match: the heredoc openers contain slashes and dollars
# that a sed address would have to escape, and getting that wrong fails quietly.
extract() { awk -v start="$1" '$0 == start && !seen { seen = 1; next } seen && $0 == "EOF" { exit } seen' bootstrap.sh; }

extract 'cat > "$XRAY_CONF" <<EOF'                        > "$DIR/xray.tpl"
extract 'cat > /etc/nginx/sites-available/default <<EOF'  > "$DIR/site.tpl"
extract "cat > /var/www/html/index.html <<'EOF'"          > "$DIR/www/index.html"

for f in xray.tpl site.tpl www/index.html; do
  [[ -s "$DIR/$f" ]] || { echo "extraction produced an empty $f — bootstrap.sh changed shape" >&2; exit 1; }
done

eval "cat <<XEOF
$(cat "$DIR/xray.tpl")
XEOF" > "$DIR/xray.json"
eval "cat <<NEOF
$(cat "$DIR/site.tpl")
NEOF" > "$DIR/site.conf"

section "Xray configuration"

jq -e . "$DIR/xray.json" >/dev/null 2>&1
check $? "the generated Xray config is valid JSON"

q() { jq -er "$1" "$DIR/xray.json" 2>/dev/null; }

[[ "$(q '.log.loglevel')" == "none" && "$(q '.log.access')" == "none" && "$(q '.log.error')" == "none" ]]
check $? "all Xray logging is off — connection records never exist (I1)"

[[ "$(q '.policy.system.statsInboundUplink')" == "false" && "$(q '.policy.system.statsInboundDownlink')" == "false" ]]
check $? "per-inbound traffic statistics are disabled"

[[ "$(q '[.routing.rules[] | select(.ip == ["geoip:private"]) | .outboundTag] | first')" == "block" ]]
check $? "private ranges are blocked — no SSRF into the host's own network"

[[ "$(q '[.routing.rules[] | select(.protocol == ["bittorrent"]) | .outboundTag] | first')" == "block" ]]
check $? "BitTorrent is blocked — abuse complaints get nodes terminated"

[[ "$(q '.inbounds[0].streamSettings.realitySettings.dest')" == "${REALITY_DEST}:443" \
   && "$(q '.inbounds[0].streamSettings.realitySettings.serverNames[0]')" == "$REALITY_DEST" ]]
check $? "REALITY dest and serverNames agree — a mismatch breaks every handshake"

[[ "$(q '.inbounds[1].listen')" == "127.0.0.1" ]]
check $? "the Tier A WebSocket inbound binds loopback only, never the public interface"

[[ "$(q '.inbounds[1].streamSettings.wsSettings.path')" == "$WS_PATH" ]]
check $? "the WebSocket path matches the one nginx proxies"

[[ "$(q '[.inbounds[].settings.clients[].id] | length')" == "4" \
   && "$(q '[.inbounds[].settings.clients[].id] | unique | length')" == "2" ]]
check $? "both inbounds serve the same credential set"

[[ -z "$(q '.inbounds[1].settings.clients[] | select(.flow)' 2>/dev/null)" ]]
check $? "the WebSocket inbound has no flow field — xtls flow is invalid over ws"

section "nginx site configuration"

cat > "$DIR/nginx.conf" <<NGINX
daemon on;
pid $DIR/nginx.pid;
error_log $DIR/logs/error.log crit;
events { worker_connections 32; }
http {
  client_body_temp_path $DIR/tmp; proxy_temp_path $DIR/tmp;
  fastcgi_temp_path $DIR/tmp; uwsgi_temp_path $DIR/tmp; scgi_temp_path $DIR/tmp;
  include $DIR/site.served.conf;
}
NGINX

# Only two edits, so the file can be served here at all: the listen port, and
# the document root. Everything the test asserts is untouched.
sed -e "s/listen 80 default_server;/listen 127.0.0.1:$PORT default_server;/" \
    -e "/listen \[::\]:80 default_server;/d" \
    -e "s|root /var/www/html;|root $DIR/www;|" "$DIR/site.conf" > "$DIR/site.served.conf"

nginx -t -c "$DIR/nginx.conf" -p "$DIR" >"$DIR/logs/nginxt.log" 2>&1
check $? "nginx accepts the generated site config"
[[ $fail -eq 0 ]] || sed 's/^/    /' "$DIR/logs/nginxt.log"

grep -q "access_log off;" "$DIR/site.conf"
check $? "nginx access logging is off"

grep -q "server_tokens off;" "$DIR/site.conf"
check $? "nginx version banner is suppressed"

! grep -qiE "proxy_set_header (X-Real-IP|X-Forwarded-For)" "$DIR/site.conf"
check $? "no client address is forwarded into Xray (I1)"

section "camouflage and path discovery, served over real HTTP"

nginx -c "$DIR/nginx.conf" -p "$DIR"
sleep 0.5
trap 'nginx -s quit -c "$DIR/nginx.conf" -p "$DIR" 2>/dev/null' EXIT

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@"; }
body() { curl -s --max-time 5 "$@"; }

[[ "$(code "http://127.0.0.1:$PORT/")" == "200" ]]
check $? "the root path serves a real page, not a blank or default one"

[[ "$(body "http://127.0.0.1:$PORT/" | grep -ci '<html')" -ge 1 ]]
check $? "the camouflage page is real HTML"

[[ "$(code "http://127.0.0.1:$PORT/wp-admin")" == "404" ]]
check $? "an unknown path returns an ordinary 404"

[[ "$(code "http://127.0.0.1:$PORT$WS_PATH")" == "404" ]]
check $? "the WebSocket path 404s to a plain GET — scanning cannot discover it"

# With a genuine upgrade header nginx proxies to Xray, which is not running
# here, so the tell is a 502 rather than a 404: the request was ACCEPTED and
# forwarded. That distinction is the whole control.
[[ "$(code -H 'Upgrade: websocket' -H 'Connection: upgrade' "http://127.0.0.1:$PORT$WS_PATH")" == "502" ]]
check $? "the same path proxies a real WebSocket upgrade (502 = forwarded, no Xray here)"

if [[ $fail -gt 0 ]]; then
  printf '\n\033[31m%d of %d checks FAILED\033[0m\n' "$fail" "$count"; exit 1
fi
printf '\n\033[32mall %d checks passed\033[0m\n' "$count"

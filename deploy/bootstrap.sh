#!/usr/bin/env bash
#
# bootstrap.sh — provision one transport node (Tier A + Tier D)
#
# Deploys on a fresh Debian 12 / Ubuntu 22.04+ VPS:
#   :443  VLESS + REALITY + XTLS-Vision   (Tier D — direct, high throughput)
#   :8443 VLESS + WebSocket + TLS         (Tier A — behind CDN, whitelist-proof)
#   :80   real camouflage website          (defeats casual probing)
#
# Design notes:
#   * Nodes are CATTLE, NOT PETS. Expect a lifetime of days to weeks.
#     Never repair a burned node — destroy it and run this on a new one.
#   * Zero logging, by construction. Logs do not exist to be seized.
#   * Idempotent: safe to re-run.
#
# Usage:
#   ./bootstrap.sh --dest www.apple.com --domain cdn.example.com --users 500
#
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# REALITY borrows this site's genuine TLS certificate chain. Requirements:
#   (a) NOT blocked in Iran        — else you self-inflict a block
#   (b) TLS 1.3 + HTTP/2           — mandatory for REALITY
#   (c) plausible destination      — high-volume, boring
#   (d) geographically sensible relative to this VPS
REALITY_DEST="${REALITY_DEST:-www.apple.com}"

# Cloudflare-proxied domain for the Tier A WebSocket path (orange cloud ON).
CDN_DOMAIN="${CDN_DOMAIN:-}"

# How many per-user credentials to mint. Per-user UUIDs are free and are what
# make surgical revocation and leak attribution possible. Never share one UUID.
USER_COUNT="${USER_COUNT:-500}"

OUT_DIR="/root/node-credentials"
XRAY_CONF="/usr/local/etc/xray/config.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)   REALITY_DEST="$2"; shift 2 ;;
    --domain) CDN_DOMAIN="$2";   shift 2 ;;
    --users)  USER_COUNT="$2";   shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

log() { printf '\033[1;36m[+]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[!]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Base system
# ─────────────────────────────────────────────────────────────────────────────
log "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl unzip nginx jq openssl ufw uuid-runtime >/dev/null

log "kernel tuning + hardening"
cat >/etc/sysctl.d/99-node.conf <<'EOF'
# Performance — BBR and generous buffers matter on deliberately lossy links
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv6.conf.all.disable_ipv6=0

# Hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1

# No core dumps — a crash dump of the Xray process contains live user UUIDs
fs.suid_dumpable=0
kernel.core_pattern=|/bin/false
EOF
sysctl --system >/dev/null 2>&1 || true

# Swap holds process memory on disk, and that memory contains credentials.
log "disabling swap (keeps credentials out of persistent storage)"
swapoff -a 2>/dev/null || true
sed -i '/\sswap\s/s/^/#/' /etc/fstab 2>/dev/null || true

# Shell history on a node that may be seized is a record of operator activity.
log "disabling shell history"
cat >/etc/profile.d/00-nohist.sh <<'EOF'
unset HISTFILE
export HISTFILESIZE=0
export HISTSIZE=0
EOF
chmod 644 /etc/profile.d/00-nohist.sh

# ─────────────────────────────────────────────────────────────────────────────
# 2. Xray-core
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v xray >/dev/null 2>&1; then
  log "installing Xray-core"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
       @ install >/dev/null
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Keys and per-user credentials
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"

if [[ ! -f "$OUT_DIR/reality.keys" ]]; then
  log "generating REALITY x25519 keypair"
  xray x25519 > "$OUT_DIR/reality.keys"
fi
PRIVATE_KEY=$(awk '/[Pp]rivate/ {print $NF}' "$OUT_DIR/reality.keys")
PUBLIC_KEY=$(awk  '/[Pp]ublic/  {print $NF}' "$OUT_DIR/reality.keys")
[[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" ]] || die "key generation failed"

# Multiple short IDs let you revoke a distribution channel without touching others.
if [[ ! -f "$OUT_DIR/shortids" ]]; then
  for _ in $(seq 1 8); do openssl rand -hex 8; done > "$OUT_DIR/shortids"
fi
mapfile -t SHORT_IDS < "$OUT_DIR/shortids"
SHORTID_JSON=$(printf '"%s",' "${SHORT_IDS[@]}" | sed 's/,$//')

# PER-USER UUIDs. This is the single most important design choice in the file:
# it is what turns "a server got blocked" into "these N users knew about it".
if [[ ! -f "$OUT_DIR/users.json" ]]; then
  log "minting $USER_COUNT per-user credentials"
  : > "$OUT_DIR/users.tmp"
  for i in $(seq 1 "$USER_COUNT"); do
    printf '{"id":"%s","email":"u%05d@node","flow":"xtls-rprx-vision"}\n' "$(uuidgen)" "$i" \
      >> "$OUT_DIR/users.tmp"
  done
  jq -s '.' "$OUT_DIR/users.tmp" > "$OUT_DIR/users.json"
  rm -f "$OUT_DIR/users.tmp"
  chmod 600 "$OUT_DIR/users.json"
fi
CLIENTS_VISION=$(jq -c '.' "$OUT_DIR/users.json")
# WebSocket transport does not support XTLS flow control — strip it.
CLIENTS_WS=$(jq -c '[.[] | del(.flow)]' "$OUT_DIR/users.json")

WS_PATH="${WS_PATH:-/$(openssl rand -hex 12)}"
echo "$WS_PATH" > "$OUT_DIR/ws_path"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Xray configuration
# ─────────────────────────────────────────────────────────────────────────────
log "writing Xray config"
mkdir -p "$(dirname "$XRAY_CONF")"
cat > "$XRAY_CONF" <<EOF
{
  "log": { "loglevel": "none", "access": "none", "error": "none" },

  "inbounds": [
    {
      "tag": "tier-d-reality",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": $CLIENTS_VISION, "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DEST}:443",
          "xver": 0,
          "serverNames": ["${REALITY_DEST}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [${SHORTID_JSON}]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
    },
    {
      "tag": "tier-a-ws",
      "listen": "127.0.0.1",
      "port": 8443,
      "protocol": "vless",
      "settings": { "clients": $CLIENTS_WS, "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "${WS_PATH}" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] }
    }
  ],

  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4v6" } },
    { "tag": "block",  "protocol": "blackhole" }
  ],

  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
    ]
  },

  "policy": {
    "levels": { "0": { "handshake": 3, "connIdle": 180, "uplinkOnly": 2, "downlinkOnly": 3 } },
    "system": { "statsInboundUplink": false, "statsInboundDownlink": false }
  }
}
EOF

xray run -test -config "$XRAY_CONF" >/dev/null || die "Xray config invalid"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Camouflage site + WebSocket reverse proxy
# ─────────────────────────────────────────────────────────────────────────────
# Anything that is not a valid tunnel connection must see a real, boring website.
# A blank page, an error, or the nginx default page is itself a signature.
log "deploying camouflage site"
mkdir -p /var/www/html
cat > /var/www/html/index.html <<'EOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Status</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
      display:grid;place-items:center;min-height:100vh;background:#fafafa;color:#333}
 main{text-align:center;max-width:34rem;padding:2rem}
 h1{font-weight:500;font-size:1.4rem;margin:0 0 .5rem}
 p{color:#777;line-height:1.6;font-size:.95rem}
 .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#2ea043;margin-right:.5rem}
</style></head>
<body><main>
 <h1><span class="dot"></span>All systems operational</h1>
 <p>This endpoint serves automated infrastructure monitoring.
    There is no interactive content at this address.</p>
</main></body></html>
EOF

cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
    access_log off;
    error_log /dev/null crit;
    server_tokens off;

    # Tier A: CDN terminates TLS upstream and forwards here over plain HTTP.
    location ${WS_PATH} {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        # Deliberately NOT forwarding X-Real-IP or X-Forwarded-For. Xray has no
        # use for them, and on a direct (non-CDN) connection \$remote_addr is a
        # user's address. Logging is off today, so nothing records it — but a
        # header that carries a user address into another process is one config
        # change away from being a record, and there is no reason to carry it.
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    location / { try_files \$uri \$uri/ =404; }
}
EOF

nginx -t >/dev/null 2>&1 || die "nginx config invalid"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Firewall + services
# ─────────────────────────────────────────────────────────────────────────────
log "hardening SSH"
# Key-only auth. A node reachable by password is a node that will be brute-forced,
# and a compromised node hands the attacker every credential it serves.
if [[ -s /root/.ssh/authorized_keys ]]; then
  cat >/etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
  sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
  log "WARNING: no authorized_keys found — leaving password auth enabled."
  log "         Add your key and re-run, or this node is brute-forceable."
fi

log "installing fail2ban and unattended security upgrades"
apt-get install -y -qq fail2ban unattended-upgrades >/dev/null 2>&1 || true
cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 3
findtime = 600
bantime = 86400
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 || true
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

log "configuring firewall"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming  >/dev/null
ufw default allow outgoing >/dev/null
ufw limit 22/tcp  >/dev/null      # rate-limited, not merely allowed
ufw allow 80/tcp  >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

log "restricting Xray service"
mkdir -p /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service.d/hardening.conf <<'EOF'
[Service]
# Least privilege: a compromise of Xray should not yield the host.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=false
ReadWritePaths=/usr/local/etc/xray
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitCORE=0
EOF
systemctl daemon-reload

systemctl enable --now nginx >/dev/null 2>&1
systemctl restart nginx
systemctl enable --now xray  >/dev/null 2>&1
systemctl restart xray
sleep 2
systemctl is-active --quiet xray  || die "xray failed to start"
systemctl is-active --quiet nginx || die "nginx failed to start"

# ─────────────────────────────────────────────────────────────────────────────
# 7. Emit node manifest for the control plane
# ─────────────────────────────────────────────────────────────────────────────
SERVER_IP=$(curl -fsS --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')

jq -n \
  --arg ip "$SERVER_IP" \
  --arg pbk "$PUBLIC_KEY" \
  --arg dest "$REALITY_DEST" \
  --arg wspath "$WS_PATH" \
  --arg cdn "$CDN_DOMAIN" \
  --argjson sids "$(jq -R -s -c 'split("\n")|map(select(length>0))' < "$OUT_DIR/shortids")" \
  --argjson users "$(jq -c '[.[]|{id,email}]' "$OUT_DIR/users.json")" \
  '{
     node: { ip:$ip, provisioned_by:"bootstrap.sh", status:"active" },
     tier_d_reality: { port:443, public_key:$pbk, dest:$dest, short_ids:$sids, flow:"xtls-rprx-vision" },
     tier_a_cdn:     { cdn_domain:$cdn, ws_path:$wspath, note:"point Cloudflare-proxied domain here, orange cloud ON" },
     users: $users
   }' > "$OUT_DIR/manifest.json"
chmod 600 "$OUT_DIR/manifest.json"

log "node ready — ${SERVER_IP}"
cat <<EOF

  ┌─────────────────────────────────────────────────────────────────┐
  │  NODE PROVISIONED                                               │
  ├─────────────────────────────────────────────────────────────────┤
  │  IP            ${SERVER_IP}
  │  REALITY dest  ${REALITY_DEST}
  │  Public key    ${PUBLIC_KEY}
  │  WS path       ${WS_PATH}
  │  Users minted  ${USER_COUNT}
  ├─────────────────────────────────────────────────────────────────┤
  │  Manifest:  ${OUT_DIR}/manifest.json                            │
  │  Feed it to the control plane; never hand-distribute configs.   │
  ├─────────────────────────────────────────────────────────────────┤
  │  NEXT: point a Cloudflare-proxied domain (orange cloud ON) at   │
  │  this IP to activate Tier A. Without it you have throughput but │
  │  no whitelist resistance.                                       │
  └─────────────────────────────────────────────────────────────────┘

  Reminder: this node is a CONSUMABLE. When it burns, destroy it and
  provision a new one on a different ASN. Never rehabilitate an IP.

EOF

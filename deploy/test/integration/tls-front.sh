#!/usr/bin/env bash
# tls-front.sh — real HTTPS in front of the local workerd instances.
#
# control-plane.py refuses non-HTTPS endpoints and validates certificates in
# full. Both are correct and neither is weakened for testing: we stand up a real
# CA, a real nginx TLS terminator, and point the trust store at it. The test
# therefore EXERCISES those checks instead of routing around them.
#
# Ports:
#   9443  HTTPS -> distributor     (dist.test)
#   9444  HTTPS -> collector       (collect.test)
#   9445  HTTPS  camouflage page   — stands in for a transport node as seen from
#                                    OUTSIDE the censored network: TCP open, TLS
#                                    completes
#   9446  nothing listening        — the same node as seen from INSIDE: blocked
set -euo pipefail
trap 'echo "[tls-front] FAILED at line $LINENO (see $DIR/logs/ for openssl and nginx output)" >&2' ERR
DIR="${1:-/tmp/tk-tls}"
DIST_PORT="${DIST_PORT:-8787}"
COLL_PORT="${COLL_PORT:-8788}"

# A leftover nginx from an interrupted run still owns the ports.
[[ -f "$DIR/nginx.pid" ]] && nginx -s quit -c "$DIR/nginx.conf" -p "$DIR" 2>/dev/null
# -x matches the process NAME only: `pkill -f nginx` also matches any
# shell whose command line mentions nginx, including this script.
pkill -x nginx 2>/dev/null || true   # returns 1 when nothing matched; set -e would abort
sleep 0.3

rm -rf "$DIR"; mkdir -p "$DIR/certs" "$DIR/logs" "$DIR/www" "$DIR/tmp"

openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout "$DIR/certs/ca.key" -out "$DIR/certs/ca.pem" \
  -subj "/CN=taghk-integration-ca" \
  -addext "basicConstraints=critical,CA:TRUE" 2>>"$DIR/logs/openssl.log"

openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/certs/srv.key" -out "$DIR/tmp/srv.csr" \
  -subj "/CN=dist.test" 2>>"$DIR/logs/openssl.log"

openssl x509 -req -in "$DIR/tmp/srv.csr" -CA "$DIR/certs/ca.pem" -CAkey "$DIR/certs/ca.key" \
  -CAcreateserial -days 2 -sha256 -out "$DIR/certs/srv.pem" \
  -extfile <(printf 'subjectAltName=DNS:dist.test,DNS:collect.test,DNS:node.test,IP:127.0.0.1\n') 2>>"$DIR/logs/openssl.log"

cat > "$DIR/www/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Bookmarks</title></head>
<body><h1>Bookmarks</h1><p>Nothing to see here.</p></body></html>
HTML

cat > "$DIR/nginx.conf" <<NGINX
daemon on;
pid $DIR/nginx.pid;
error_log $DIR/logs/error.log crit;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path $DIR/tmp;
  proxy_temp_path $DIR/tmp;
  fastcgi_temp_path $DIR/tmp;
  uwsgi_temp_path $DIR/tmp;
  scgi_temp_path $DIR/tmp;

  ssl_certificate     $DIR/certs/srv.pem;
  ssl_certificate_key $DIR/certs/srv.key;
  ssl_protocols TLSv1.2 TLSv1.3;

  server {
    listen 127.0.0.1:9443 ssl;
    server_name dist.test;
    location / { proxy_pass http://127.0.0.1:$DIST_PORT; proxy_set_header Host \$host; }
  }
  server {
    listen 127.0.0.1:9444 ssl;
    server_name collect.test;
    location / { proxy_pass http://127.0.0.1:$COLL_PORT; proxy_set_header Host \$host; }
  }
  server {
    listen 0.0.0.0:9445 ssl;
    server_name node.test;
    root $DIR/www;
  }
}
NGINX

nginx -t -c "$DIR/nginx.conf" -p "$DIR" 2>&1 | sed 's/^/[nginx] /'
nginx -c "$DIR/nginx.conf" -p "$DIR"
echo "$DIR/certs/ca.pem"

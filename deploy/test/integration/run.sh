#!/usr/bin/env bash
# run.sh — Plane 3 end-to-end: burn -> attribution -> replacement -> self-heal.
#
# Brings up both Workers in workerd, a real nginx TLS terminator in front of
# them, and drives the real control plane, the real probe agent, and the
# reference client against them. Tears everything down afterwards.
#
#   ./test/integration/run.sh
#
# NO_PROXY is set for loopback because this sandbox routes egress through an
# agent proxy that would otherwise intercept the local sockets. It is an
# artefact of the environment, not of the system under test.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"

TLS_DIR=/tmp/tk-tls
SERVER_LOG=/tmp/tk-servers.log

cleanup() {
  [[ -n "${SERVERS_PID:-}" ]] && kill "$SERVERS_PID" 2>/dev/null
  [[ -f "$TLS_DIR/nginx.pid" ]] && nginx -s quit -c "$TLS_DIR/nginx.conf" -p "$TLS_DIR" 2>/dev/null
  wait "${SERVERS_PID:-}" 2>/dev/null
  return 0
}
trap cleanup EXIT

echo "── starting workerd (distributor + collector)"
: > "$SERVER_LOG"
node test/integration/servers.mjs >> "$SERVER_LOG" 2>&1 &
SERVERS_PID=$!
for _ in $(seq 60); do grep -q '"ready":true' "$SERVER_LOG" && break; sleep 1; done
if ! grep -q '"ready":true' "$SERVER_LOG"; then
  echo "workers failed to start:"; tail -20 "$SERVER_LOG"; exit 1
fi

echo "── starting nginx TLS terminator"
./test/integration/tls-front.sh "$TLS_DIR" >/dev/null || { echo "tls-front failed"; exit 1; }

READY=$(grep -o '{"ready".*}' "$SERVER_LOG" | head -1)
export DISTRIBUTOR_URL=https://127.0.0.1:9443
export COLLECTOR_URL=https://127.0.0.1:9444
export ADMIN_KEY=$(jq -r .admin_key <<<"$READY")
export COLLECTOR_ADMIN=$(jq -r .collector_admin <<<"$READY")
export OPERATOR_PUBKEY=$(jq -r .operator_pubkey <<<"$READY")
# Pinned in a real client build; passed to the harness client here.
export COMMITMENT_PK=$(jq -r .commitment_pk <<<"$READY")
export SSL_CERT_FILE="$TLS_DIR/certs/ca.pem"
export NODE_EXTRA_CA_CERTS="$TLS_DIR/certs/ca.pem"
export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1

echo "── running the scenario"
python3 test/integration/plane3.py
exit $?

#!/usr/bin/env bash
# run-all.sh — everything, in dependency order. Nothing here is a mock: the
# worker tests run the real code in the real Workers runtime (workerd).
#
#   ./test/run-all.sh
#
# PYTHON is the interpreter used for the cross-implementation Ed25519 check. It
# needs the `cryptography` package as an independent reference; override it if
# your system python does not have one:
#   PYTHON=/path/to/venv/bin/python ./test/run-all.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

echo "═══ 1/5  cryptographic self-test (voprf.js)"
node selftest.mjs

echo; echo "═══ 2/5  KV eventual-consistency regression (04-STATUS 2.1, 2.2)"
node test/kv-race.test.mjs

echo; echo "═══ 3/5  canary pool invariants (04-STATUS 2.5)"
node test/canary.test.mjs

echo; echo "═══ 4/5  distributor in workerd — exactly-once, rate limits, adversarial"
node test/distributor.test.mjs 2>&1 | grep -vE "wrangler:(info|warn)|Request was cancelled|^\s+at |undici|node:internal|^\(node:|DeprecationWarning|^Your Worker|^Binding|^env\.|^⎔|^\s*$"

echo; echo "═══ 5/5  collector in workerd + independent Ed25519 verification (04-STATUS 2.3)"
node test/collector.test.mjs 2>&1 | grep -vE "wrangler:(info|warn)|Request was cancelled|^\s+at |undici|node:internal|^\(node:|DeprecationWarning|^Your Worker|^Binding|^env\.|^⎔|^\s*$"
"$PYTHON" test/verify-manifest.py

echo; echo "═══ all suites passed"

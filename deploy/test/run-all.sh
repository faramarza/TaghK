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

echo "═══ 1/8  cryptographic self-test (voprf.js)"
node selftest.mjs

echo; echo "═══ 2/8  KV eventual-consistency regression (04-STATUS 2.1, 2.2)"
node test/kv-race.test.mjs

echo; echo "═══ 3/8  key-commitment anchoring — the tagging attack, mounted (04-STATUS 2.17)"
node test/anchor.test.mjs

echo; echo "═══ 4/8  canary pool invariants (04-STATUS 2.5)"
node test/canary.test.mjs

echo; echo "═══ 5/8  distributor in workerd — exactly-once, rate limits, adversarial"
node test/distributor.test.mjs 2>&1 | tr -d "\000" | grep -vE "wrangler:(info|warn)|Request was cancelled|^\s+at |undici|node:internal|^\(node:|DeprecationWarning|^Your Worker|^Binding|^env\.|^⎔|^\s*$"

echo; echo "═══ 6/8  collector in workerd + independent Ed25519 verification (04-STATUS 2.3)"
node test/collector.test.mjs 2>&1 | tr -d "\000" | grep -vE "wrangler:(info|warn)|Request was cancelled|^\s+at |undici|node:internal|^\(node:|DeprecationWarning|^Your Worker|^Binding|^env\.|^⎔|^\s*$"
"$PYTHON" test/verify-manifest.py

# The last two need nginx (a real TLS terminator and a real HTTP server). Skip
# with a loud notice rather than a silent pass if it is not installed — a
# skipped security test that looks like a passing one is how things ship broken.
if ! command -v nginx >/dev/null; then
  echo; echo "═══ 7/8, 8/8  SKIPPED — nginx not installed"
  echo "    The node-config and Plane 3 integration suites need it:"
  echo "      apt-get install -y nginx-light   (or your platform's equivalent)"
  echo; echo "═══ suites 1-6 passed; 7 and 8 did not run"
  exit 0
fi

export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1}" no_proxy="${no_proxy:-localhost,127.0.0.1}"

echo; echo "═══ 7/8  node configuration from bootstrap.sh, parsed and served"
./test/bootstrap-config.test.sh

echo; echo "═══ 8/8  Plane 3 end to end — burn, attribution, replacement, self-heal"
./test/integration/run.sh

echo; echo "═══ all suites passed"

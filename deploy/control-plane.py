#!/usr/bin/env python3
"""
control-plane.py — PLANE 3: burn detection and automated response

The rule this file exists to enforce:

    A NODE THAT ANSWERS YOU IN BERLIN AND IS BLOCKED IN TEHRAN LOOKS PERFECTLY
    HEALTHY ON EVERY CONVENTIONAL MONITOR.

Reachability from inside the censored country is the only signal that matters.
Everything else is a comfortable lie.

───────────────────────────────────────────────────────────────────────────────
 ARCHITECTURE — PULL, NEVER PUSH
───────────────────────────────────────────────────────────────────────────────
 This process does NOT contact probes. It reads quorum-checked verdicts from the
 collector, which probes push to on their own schedule.

 That direction is a security property, not a style choice. If the control plane
 queried probes with "test host:port", then anyone who observed, spoofed, or
 compromised that channel would learn the fleet, and the probes would become a
 free scanning service. Probes instead receive SIGNED work manifests and report
 back — they never take targets from an unauthenticated caller, and this process
 never needs to know where any probe is.

 Consequence: this tool holds NO probe identities, NO probe addresses, and no
 way to reach one. There is no probe roster here to seize.

───────────────────────────────────────────────────────────────────────────────
 PRIVACY CONSTRAINTS — non-negotiable
───────────────────────────────────────────────────────────────────────────────
 * Aggregate verdicts only. Never per-user or per-probe records.
 * No IP addresses. No individual timestamps. No geography beyond coarse counts.
 * DO NOT COLLECT WHAT YOU WOULD NOT WANT SEIZED. In hostile hands, this
   database becomes an arrest list.

Usage:
    ./control-plane.py check
    ./control-plane.py watch --interval 300
    ./control-plane.py sync-targets           # push node list to the collector
    ./control-plane.py replace <node_id>
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

# ── configuration ────────────────────────────────────────────────────────────

DISTRIBUTOR = os.environ.get("DISTRIBUTOR_URL", "")
COLLECTOR = os.environ.get("COLLECTOR_URL", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
COLLECTOR_ADMIN = os.environ.get("COLLECTOR_ADMIN", "")

# Consecutive rounds of a 'blocked' verdict before acting. Absorbs transient
# nationwide events; without it, a brief disruption destroys the whole fleet.
STRIKES_BEFORE_BURN = 3

# If more than this fraction of the fleet reads as blocked at once, this is a
# nationwide event, not a set of individual burns. Reprovisioning into a dead
# network wastes exactly the capacity needed when it lifts.
FLEET_WIDE_THRESHOLD = 0.6

PROVISION_CMD = os.environ.get("PROVISION_CMD", "")
STATE_PATH = os.environ.get("STATE_PATH", "./control-state.json")
CONNECT_TIMEOUT = 6.0


# ── transport ────────────────────────────────────────────────────────────────

def api(base: str, key: str, path: str, method: str = "GET",
        body: dict | list | None = None) -> Any:
    if not base:
        raise RuntimeError("endpoint URL not configured")
    if not base.startswith("https://"):
        # Admin keys travel on this channel. Plaintext is not acceptable.
        raise RuntimeError(f"refusing non-HTTPS endpoint: {base}")

    req = urllib.request.Request(
        f"{base}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "x-admin-key": key,
            "content-type": "application/json",
            "user-agent": "Mozilla/5.0",
        },
    )
    ctx = ssl.create_default_context()          # full cert validation, always
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


dist = lambda p, m="GET", b=None: api(DISTRIBUTOR, ADMIN_KEY, p, m, b)          # noqa: E731
coll = lambda p, m="GET", b=None: api(COLLECTOR, COLLECTOR_ADMIN, p, m, b)      # noqa: E731


# ── outside-vantage sanity checks ────────────────────────────────────────────

def alive_from_outside(host: str, port: int) -> bool:
    """
    NARROW PURPOSE: distinguish 'the node is broken' from 'the node is blocked'.
    A node unreachable from outside too is an infrastructure fault. Counting it
    as a burn would feed false data into leak attribution and wrongly raise
    suspicion on innocent lineages.
    """
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def tls_ok(host: str, port: int, sni: str) -> bool:
    """
    TCP up but TLS failing usually means the borrowed REALITY `dest` site has
    itself become blocked. That is a cheap fix (change dest) rather than an
    expensive one (destroy and reprovision) — worth distinguishing.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as t:
                return t.version() is not None
    except (OSError, ssl.SSLError):
        return False


# ── response ─────────────────────────────────────────────────────────────────

def handle_burn(node: dict[str, Any]) -> None:
    """Closed loop. At public scale, a human in this path is the bottleneck."""
    nid = node["id"]
    print(f"  [BURN] {nid} ({node['ip']}) — quorum of in-country probes confirms blocked")

    result = dist("/admin/report-blocked", "POST", {"node_id": nid})
    print(f"         attribution: {result.get('implicated', 0)} lineages implicated "
          f"(weight {result.get('weight')}) — demoted, never banned")

    # Retire the measurement target too.
    #
    # Without this the collector keeps handing the burned node to probes, so
    # volunteers inside the country go on connecting to an address the censor
    # has just demonstrated it is watching — indefinitely, since this process
    # stops evaluating the node the moment the distributor marks it blocked and
    # nothing else ever revisits it. Burning a node must stop pointing people at
    # it, in both planes.
    try:
        targets = coll("/admin/targets")
        retired = False
        for t in targets:
            if t.get("node_id") == nid and t.get("status") == "active":
                t["status"] = "retired"
                retired = True
        if retired:
            coll("/admin/targets", "POST", targets)
            print("         measurement target retired — probes stop connecting to it")
    except Exception as exc:
        print(f"         [!] could not retire the measurement target: {exc}\n"
              f"             DO THIS BY HAND — probes are still being sent to {nid}",
              file=sys.stderr)

    if PROVISION_CMD:
        print("         provisioning replacement on a different ASN…")
        subprocess.run(PROVISION_CMD, shell=True, check=False)
    else:
        print("         PROVISION_CMD unset — provision manually, DIFFERENT ASN")

    print("         destroy the burned instance; never reuse a blocklisted IP")
    print("         clients self-heal on next subscription poll")


# ── state ────────────────────────────────────────────────────────────────────

def load_state() -> dict[str, int]:
    try:
        with open(STATE_PATH) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict[str, int]) -> None:
    fd = os.open(STATE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh)


# ── commands ─────────────────────────────────────────────────────────────────

def sync_targets() -> None:
    """
    Push the node list to the collector as opaque refs.
    Probes only ever see refs and host:port — never node IDs, pool membership,
    or anything that would let a hostile probe map the fleet's structure.
    """
    nodes = dist("/admin/nodes")
    targets = [
        {
            "node_id": n["id"],
            "host": n["ip"],
            "port": n.get("tier_d_reality", {}).get("port", 443),
            "sni": n.get("tier_d_reality", {}).get("dest"),
            "status": n.get("status", "active"),
        }
        for n in nodes
    ]
    result = coll("/admin/targets", "POST", targets)
    print(f"[+] synced {result.get('count', 0)} targets to collector")


def run_check() -> None:
    strikes = load_state()

    try:
        nodes = {n["id"]: n for n in dist("/admin/nodes")}
        report = coll("/admin/verdicts")
    except Exception as exc:
        print(f"[!] cannot reach control endpoints: {exc}", file=sys.stderr)
        return

    verdicts = report.get("verdicts", [])
    active = [v for v in verdicts if nodes.get(v.get("node_id"), {}).get("status") == "active"]

    print(f"[{time.strftime('%H:%M:%S')}] {len(active)} active nodes, "
          f"quorum={report.get('quorum')}")

    blocked_now = [v for v in active if v["verdict"] == "blocked"]

    # Nationwide-event guard. Do not burn the fleet into a dead network.
    if active and len(blocked_now) / len(active) >= FLEET_WIDE_THRESHOLD:
        print(f"  [!] {len(blocked_now)}/{len(active)} nodes reading blocked.")
        print("      This is a NATIONWIDE EVENT, not individual burns.")
        print("      HOLDING: not reprovisioning. Preserve spares and budget for")
        print("      the restoration — that is when demand spikes hardest.")
        print("      Verify Tier A (CDN) and Tier B (Snowflake) paths instead.")
        save_state({})
        return

    for v in active:
        node = nodes[v["node_id"]]
        nid = node["id"]
        short = nid[:8]

        if v["verdict"] == "insufficient-data":
            print(f"  [?] {short} {node['ip']}: insufficient probe coverage")
            continue

        if v["verdict"] == "reachable":
            if strikes.pop(nid, None):
                print(f"  [~] {short} recovered — strikes cleared")
            print(f"  [+] {short} {node['ip']}: reachable "
                  f"({v['reachable_slots']} slots)")
            continue

        # verdict == blocked. Confirm it is censorship, not a dead box.
        port = node.get("tier_d_reality", {}).get("port", 443)
        sni = node.get("tier_d_reality", {}).get("dest", "")

        if not alive_from_outside(node["ip"], port):
            print(f"  [x] {short} {node['ip']}: down from outside too — "
                  f"infrastructure fault, NOT a block. No attribution.")
            continue

        if sni and not tls_ok(node["ip"], port, sni):
            print(f"  [!] {short} {node['ip']}: TLS fails — dest '{sni}' may itself "
                  f"be blocked. CHANGE DEST FIRST; do not reprovision.")
            continue

        strikes[nid] = strikes.get(nid, 0) + 1
        print(f"  [-] {short} {node['ip']}: blocked from {v['blocked_slots']} "
              f"slots — strike {strikes[nid]}/{STRIKES_BEFORE_BURN}")

        if strikes[nid] >= STRIKES_BEFORE_BURN:
            handle_burn(node)
            strikes.pop(nid, None)

    save_state(strikes)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="one measurement pass")
    w = sub.add_parser("watch", help="run continuously")
    w.add_argument("--interval", type=int, default=300)
    sub.add_parser("sync-targets", help="push node list to the collector")
    r = sub.add_parser("replace", help="manually declare a node burned")
    r.add_argument("node_id")

    args = ap.parse_args()

    missing = [n for n, v in (("DISTRIBUTOR_URL", DISTRIBUTOR), ("ADMIN_KEY", ADMIN_KEY),
                              ("COLLECTOR_URL", COLLECTOR),
                              ("COLLECTOR_ADMIN", COLLECTOR_ADMIN)) if not v]
    if missing:
        print(f"[!] missing environment: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    if args.cmd == "check":
        run_check()
    elif args.cmd == "sync-targets":
        sync_targets()
    elif args.cmd == "watch":
        while True:
            try:
                run_check()
            except KeyboardInterrupt:
                break
            except Exception as exc:
                print(f"[!] {exc}", file=sys.stderr)
            time.sleep(args.interval)
    elif args.cmd == "replace":
        nodes = dist("/admin/nodes")
        node = next((n for n in nodes if n["id"] == args.node_id), None)
        if not node:
            print("unknown node", file=sys.stderr)
            sys.exit(1)
        handle_burn(node)


if __name__ == "__main__":
    main()

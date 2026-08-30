#!/usr/bin/env python3
"""
probe-agent.py — in-country measurement vantage point

Runs on a volunteer device INSIDE the censored country. This is the highest-risk
component in the entire system: the person running it is physically within reach
of the state, and the thing they are running is measurement infrastructure for a
circumvention service.

Every design decision below is dominated by that fact.

───────────────────────────────────────────────────────────────────────────────
 WHY THIS EXISTS
───────────────────────────────────────────────────────────────────────────────
 A node that answers you in Berlin and is blocked in Tehran looks perfectly
 healthy on every conventional monitor. Reachability from inside is the only
 signal that matters, and it cannot be measured from outside. Full stop.

───────────────────────────────────────────────────────────────────────────────
 THE THREE ATTACKS THIS DEFENDS AGAINST
───────────────────────────────────────────────────────────────────────────────

 1. PROBE-AS-ORACLE.
    A naive agent that accepts "test host:port" from the network is a free
    scanner AND leaks which hosts the operator cares about. Anyone able to
    observe or spoof requests enumerates the fleet.
    → Fixed: work manifests are Ed25519-SIGNED by the operator. The agent tests
      only what is in a valid signed manifest and never accepts ad-hoc targets.

 2. HOSTILE PROBE ENUMERATION.
    A censor volunteers as a probe and is handed the full node list. This is the
    fundamental tension of in-country measurement and cannot be eliminated, only
    priced.
    → Fixed three ways:
      (a) PARTITIONING — each probe receives a small random SUBSET, so a hostile
          probe learns few nodes.
      (b) CANARY TARGETS — every manifest contains decoys that are not real
          nodes. A canary can only be blocked by someone who learned it HERE. If
          a canary dies, the probes that held it are hostile, and the canary is
          unique per probe, so attribution is exact rather than statistical.
      (c) REPUTATION — probes earn larger subsets by surviving; the ones whose
          targets keep dying get demoted to canary-heavy manifests.

 3. DE-ANONYMISATION OF THE VOLUNTEER.
    A list of probes is a list of people inside to arrest.
    → Fixed: reports carry an anonymous VOPRF token, never an identity. The
      collector cannot link a report to an enrolment, cannot link two reports to
      each other, and holds no probe roster. Nothing durable is written to disk.

───────────────────────────────────────────────────────────────────────────────
 OPERATIONAL SECURITY FOR THE PERSON RUNNING THIS
───────────────────────────────────────────────────────────────────────────────
 * Nothing is written to disk. State lives in memory and dies with the process.
 * Reports go out over HTTPS to a CDN-fronted collector — indistinguishable from
   ordinary web traffic on the wire.
 * Timing is jittered. A fixed interval is itself a fingerprint.
 * The agent makes plain TCP/TLS connections to ordinary-looking hosts. It is
   not, and must never become, a tunnel.
 * Run it under an innocuous process name. Do not run it on a device you would
   not want examined.

 Usage:
     ./probe-agent.py --collector https://collect.example.workers.dev \\
                      --enrol <one-time-code>
     ./probe-agent.py --collector https://collect.example.workers.dev   # resume
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

# ── constants ────────────────────────────────────────────────────────────────

# Operator's Ed25519 public key (base64, 32 bytes). Manifests not signed by this
# key are discarded. PIN THIS AT BUILD TIME — it is the agent's root of trust and
# the only thing standing between a volunteer and an attacker-supplied target list.
OPERATOR_PUBKEY_B64 = os.environ.get("OPERATOR_PUBKEY", "")

BASE_INTERVAL_S = 900          # 15 min
JITTER_FRAC = 0.4              # ±40% — a fixed heartbeat is a fingerprint
CONNECT_TIMEOUT = 6.0
MAX_TARGETS = 24
USER_AGENT = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"


# ── minimal Ed25519 verification (pure Python, no dependencies) ──────────────
# Vendored deliberately: the agent must install cleanly on a phone or an old
# laptop with no package manager access and no network fetch of dependencies.

_P = 2**255 - 19
_Lo = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


def _edwards_add(P: tuple, Q: tuple) -> tuple:
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(P: tuple, e: int) -> tuple:
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _point_decompress(s: bytes) -> tuple | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _point_equal(P: tuple, Q: tuple) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


def ed25519_verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """Standard Ed25519 verification. Returns False on any malformed input."""
    try:
        if len(signature) != 64 or len(pubkey) != 32:
            return False
        A = _point_decompress(pubkey)
        if A is None:
            return False
        Rs, s = signature[:32], int.from_bytes(signature[32:], "little")
        if s >= _Lo:
            return False
        R = _point_decompress(Rs)
        if R is None:
            return False
        k = int.from_bytes(
            hashlib.sha512(Rs + pubkey + message).digest(), "little"
        ) % _Lo
        return _point_equal(_scalar_mult(_B, s), _edwards_add(R, _scalar_mult(A, k)))
    except Exception:
        return False


# ── measurement ──────────────────────────────────────────────────────────────

@dataclass
class Target:
    ref: str          # opaque handle — the agent never learns a node's real identity
    host: str
    port: int
    sni: str | None = None
    kind: str = "node"   # "node" | "canary" — the agent cannot tell them apart


def probe_tcp(host: str, port: int) -> tuple[bool, float | None]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True, round((time.monotonic() - start) * 1000)
    except OSError:
        return False, None


def probe_tls(host: str, port: int, sni: str) -> bool:
    """
    Distinguishes TCP-level blocking from TLS-level interference (RST injection
    on SNI). Different causes, different fixes: a failed handshake with a working
    TCP connect usually means the borrowed `dest` site is itself blocked — a
    cheap fix, versus destroying and reprovisioning the node.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                return tls.version() is not None
    except (OSError, ssl.SSLError):
        return False


def measure(t: Target) -> dict[str, Any]:
    tcp_ok, rtt = probe_tcp(t.host, t.port)
    result: dict[str, Any] = {"ref": t.ref, "tcp": tcp_ok}

    if tcp_ok:
        result["rtt_bucket"] = bucket_rtt(rtt)          # bucketed, never raw
        if t.sni:
            result["tls"] = probe_tls(t.host, t.port, t.sni)
    return result


def bucket_rtt(rtt_ms: float | None) -> str | None:
    """
    Coarse buckets, not raw timings. Precise RTTs from a known vantage point
    fingerprint the probe's network position and can help locate the volunteer.
    """
    if rtt_ms is None:
        return None
    for edge, label in ((50, "<50"), (150, "50-150"), (400, "150-400"), (1000, "400-1000")):
        if rtt_ms < edge:
            return label
    return ">1000"


# ── collector transport ──────────────────────────────────────────────────────

def http_json(url: str, payload: dict | None = None, timeout: int = 25) -> dict | None:
    """
    All collector traffic is ordinary HTTPS to a CDN-fronted endpoint. Browser
    user-agent, no custom headers that would stand out in flow metadata.
    """
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method="POST" if data else "GET",
        headers={
            "user-agent": USER_AGENT,
            "accept": "application/json,text/plain,*/*",
            **({"content-type": "application/json"} if data else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def fetch_manifest(
    collector: str, token: dict[str, str] | None
) -> tuple[list[Target], list[dict]] | None:
    """
    Fetch and VERIFY a signed work manifest. Returns (targets, fresh_tokens).

    The signature check is the security boundary of this whole component. Without
    it, anyone who can answer the agent's request chooses what the volunteer's
    device connects to.

    The fresh tokens ride along so the agent never has to re-enrol. They MUST be
    kept: every collector call spends exactly one token, so the report that
    follows this manifest needs one of its own.
    """
    body = {"token": token} if token else {}
    resp = http_json(f"{collector}/probe/manifest", body)
    if not resp or "manifest" not in resp or "signature" not in resp:
        return None

    manifest_json = resp["manifest"]
    try:
        sig = base64.b64decode(resp["signature"])
        pub = base64.b64decode(OPERATOR_PUBKEY_B64)
    except Exception:
        return None

    if not OPERATOR_PUBKEY_B64:
        print("[!] OPERATOR_PUBKEY not pinned — refusing to act on an unverified manifest",
              file=sys.stderr)
        return None

    if not ed25519_verify(pub, manifest_json.encode(), sig):
        print("[!] MANIFEST SIGNATURE INVALID — discarding. "
              "Someone is trying to choose what this device connects to.", file=sys.stderr)
        return None

    try:
        parsed = json.loads(manifest_json)
    except json.JSONDecodeError:
        return None

    # Freshness: reject replayed old manifests pointing at long-dead targets.
    if abs(time.time() - parsed.get("issued_at", 0)) > 3600:
        print("[!] manifest stale — discarding", file=sys.stderr)
        return None

    targets = [
        Target(ref=t["ref"], host=t["host"], port=int(t["port"]),
               sni=t.get("sni"), kind=t.get("kind", "node"))
        for t in parsed.get("targets", [])[:MAX_TARGETS]
    ]
    return targets, resp.get("tokens") or []


def submit(collector: str, results: list[dict], token: dict[str, str] | None) -> dict | None:
    """
    Submit measurements with an anonymous VOPRF token.

    The token proves entitlement to submit without identifying the submitter. The
    collector cannot link this report to an enrolment, or to any previous report
    from the same agent.

    Deliberately absent from the payload: probe identity, IP address, ISP,
    location, device information, precise timestamps, raw RTTs.
    """
    return http_json(
        f"{collector}/probe/report",
        {
            "token": token,
            "results": results,
            # Coarse bucket only. Exact submission times across many probes would
            # allow correlation and de-anonymisation.
            "window": int(time.time() // 900) * 900,
        },
    )


def enrol(collector: str, code: str) -> dict | None:
    """
    One-time enrolment. Exchanges a single-use code for a batch of anonymous
    tokens. After this the collector retains nothing linking the tokens to this
    device — there is no probe roster to seize.
    """
    resp = http_json(f"{collector}/probe/enrol", {"code": code})
    if not resp or "tokens" not in resp:
        print("[!] enrolment failed", file=sys.stderr)
        return None
    print(f"[+] enrolled — {len(resp['tokens'])} anonymous tokens issued")
    print("    Nothing linking these tokens to this device is stored anywhere.")
    return resp


# ── main loop ────────────────────────────────────────────────────────────────

def run(collector: str, tokens: list[dict]) -> None:
    print("[+] probe agent running. In-memory only; nothing is written to disk.")
    print("    Ctrl-C to stop. Kill the process and no trace remains.\n")

    while True:
        if not tokens:
            print("[!] out of tokens — re-enrol to continue", file=sys.stderr)
            return

        # ONE TOKEN PER COLLECTOR CALL. The manifest fetch and the report are
        # two calls and need two tokens.
        #
        # This used to reuse a single token for both. The collector's spend
        # check was a read-then-write against eventually consistent storage, so
        # the second use usually landed before the first had propagated and was
        # waved through. Once that check became exactly-once the reuse was
        # correctly refused and EVERY report silently failed — the probe network
        # would have measured faithfully and reported nothing, and the only
        # symptom would have been verdicts that never reached quorum. See
        # 04-STATUS.md 2.13.
        manifest = fetch_manifest(collector, tokens.pop())
        if not manifest:
            print("[~] no valid manifest; will retry")
        else:
            targets, fresh = manifest
            tokens.extend(fresh)         # rolling re-issue rides on the manifest
            results = [measure(t) for t in targets]
            up = sum(1 for r in results if r.get("tcp"))

            if not tokens:
                print("[!] out of tokens — re-enrol to continue", file=sys.stderr)
                return
            resp = submit(collector, results, tokens.pop())
            status = "accepted" if resp and resp.get("ok") else "not accepted"
            print(f"[{time.strftime('%H:%M:%S')}] probed {len(results)} targets, "
                  f"{up} reachable — report {status}")

            if resp and resp.get("tokens"):
                # Rolling re-issue keeps the agent supplied without a second
                # enrolment, and each new token is unlinkable to the one spent.
                tokens.extend(resp["tokens"])

        # Jittered sleep — a regular heartbeat is itself a signature.
        delay = BASE_INTERVAL_S * (1 + random.uniform(-JITTER_FRAC, JITTER_FRAC))
        time.sleep(delay)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--collector", required=True, help="CDN-fronted collector base URL")
    ap.add_argument("--enrol", help="one-time enrolment code")
    args = ap.parse_args()

    if not OPERATOR_PUBKEY_B64:
        print("[!] OPERATOR_PUBKEY is not set.", file=sys.stderr)
        print("    Without a pinned operator key this agent cannot verify work", file=sys.stderr)
        print("    manifests, and an attacker could choose what this device", file=sys.stderr)
        print("    connects to. Refusing to run.", file=sys.stderr)
        sys.exit(1)

    tokens: list[dict] = []
    if args.enrol:
        result = enrol(args.collector, args.enrol)
        if not result:
            sys.exit(1)
        tokens = result["tokens"]
    else:
        print("[!] no --enrol code given and tokens are memory-only.", file=sys.stderr)
        print("    Re-run with --enrol <code>.", file=sys.stderr)
        sys.exit(1)

    try:
        run(args.collector, tokens)
    except KeyboardInterrupt:
        print("\n[+] stopped. Nothing was written to disk.")


if __name__ == "__main__":
    main()

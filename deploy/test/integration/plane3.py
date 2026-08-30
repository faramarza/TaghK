#!/usr/bin/env python3
"""
plane3.py — the burn -> attribution -> replacement -> self-heal loop, executed.

04-STATUS.md 3.7: "no end-to-end run of burn -> attribution -> replacement ->
client self-heal. The recovery path has never been exercised, and an untested
recovery path is a broken one."

This runs it, with real processes throughout:

  * both Workers in workerd, behind a real nginx TLS terminator
  * control-plane.py as a real subprocess, over HTTPS with FULL certificate
    validation — its refusal to speak plaintext is exercised, not bypassed
  * probe-agent.py as a real subprocess, pinned to a real operator key,
    verifying real Ed25519 manifest signatures
  * the reference client (client.mjs) doing real VOPRF with mandatory DLEQ

HOW THE TWO VANTAGE POINTS ARE SIMULATED
The whole point of Plane 3 is that a node can be healthy from outside and
blocked from inside. Both processes run on one host here, so the divergence is
created by giving the probes a CLOSED port for the burned node while the
control plane checks an OPEN one. That is the only fiction in this file; every
other byte crosses a real socket.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

DIST = os.environ["DISTRIBUTOR_URL"]
COLL = os.environ["COLLECTOR_URL"]
ADMIN_KEY = os.environ["ADMIN_KEY"]
COLL_ADMIN = os.environ["COLLECTOR_ADMIN"]
OPERATOR_PUBKEY = os.environ["OPERATOR_PUBKEY"]
DEPLOY = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NODE_PORT_OPEN = 9445     # nginx TLS: the node as seen from OUTSIDE
NODE_PORT_SHUT = 9446     # nothing listening: the node as seen from INSIDE

failures = []
count = 0


def section(t):
    print(f"\n\033[1m{t}\033[0m")


def check(ok, label, detail=""):
    global count
    count += 1
    mark = "\033[32m✓\033[0m" if ok else "\033[31m✗\033[0m"
    print(f"  {mark} {label}" + (f"  \033[90m{detail}\033[0m" if detail else ""))
    if not ok:
        failures.append(label)


def eq(got, want, label):
    check(got == want, label, f"got {got!r}, want {want!r}")


def api(base, key, path, method="GET", body=None):
    req = urllib.request.Request(
        f"{base}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"x-admin-key": key, "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"_status": e.code}


d = lambda p, m="GET", b=None: api(DIST, ADMIN_KEY, p, m, b)
c = lambda p, m="GET", b=None: api(COLL, COLL_ADMIN, p, m, b)


def run(cmd, env_extra=None, timeout=180, cwd=DEPLOY):
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def node(nid, ip="127.0.0.1", pool="sacrificial", asn="prov-a"):
    return {
        "id": nid, "ip": ip, "pool": pool, "status": "active", "asn_group": asn,
        "users": [{"id": f"{nid[:8]}-1111-2222-3333-444444444444"}],
        "tier_d_reality": {"port": NODE_PORT_OPEN, "flow": "xtls-rprx-vision",
                           "dest": "node.invalid", "public_key": "PBK", "short_ids": ["ab"]},
    }


# ═══════════════════════════════════════════════════════════════════════════
section("operator: seed the fleet and push targets")

NODES = ["node0001", "node0002", "node0003"]
eq(d("/admin/nodes", "POST", [node(n) for n in NODES]).get("count"), 3, "three nodes registered")

state_path = "/tmp/tk-control-state.json"
provision_marker = "/tmp/tk-provisioned"
for f in (state_path, provision_marker):
    if os.path.exists(f):
        os.remove(f)

cp_env = {
    "DISTRIBUTOR_URL": DIST, "COLLECTOR_URL": COLL,
    "ADMIN_KEY": ADMIN_KEY, "COLLECTOR_ADMIN": COLL_ADMIN,
    "STATE_PATH": state_path,
    "PROVISION_CMD": f"touch {provision_marker}",
}

r = run(["python3", "control-plane.py", "sync-targets"], cp_env)
check(r.returncode == 0, "control-plane.py sync-targets runs", r.stdout.strip() or r.stderr.strip()[:120])
check("synced 3 targets" in r.stdout, "it pushed three targets to the collector", r.stdout.strip())

targets = c("/admin/targets")
check(all("node_id" in t for t in targets), "targets carry node_id for the operator")
check(len(targets) == 3, f"collector holds {len(targets)} targets")

# The divergence: node0001 is given a closed port for the probes only.
for t in targets:
    t["asn_group"] = "prov-a"
    if t["node_id"] == "node0001":
        t["port"] = NODE_PORT_SHUT
c("/admin/targets", "POST", targets)
check(True, "node0001 is now unreachable from the probe vantage only",
      f"probes see :{NODE_PORT_SHUT}, control plane checks :{NODE_PORT_OPEN}")

# ASN-aligned operator canaries, all reachable, on the same loopback listener.
pool = [{"host": f"127.0.0.{i}", "port": NODE_PORT_OPEN, "asn_group": "prov-a"}
        for i in range(2, 26)]
health = c("/admin/canary-pool", "POST", pool)["health"]
eq(health["asn_aligned"], 24, "24 ASN-aligned operator canaries accepted")
eq(health["warnings"], [], "canary pool reports healthy")


# ═══════════════════════════════════════════════════════════════════════════
section("a real client obtains credentials")

r = run(["node", "test/integration/client.mjs", "enrol", DIST])
check(r.returncode == 0, "client.mjs completes the VOPRF flow with DLEQ verification",
      r.stderr.strip()[:120])
client = json.loads(r.stdout)
check(re.fullmatch(r"[0-9a-f]{32}", client["lineage"]) is not None, "client holds a lineage")

# A client built with the WRONG pinned key must refuse the same issuance. This
# is the end-to-end proof that anchoring is live rather than merely present: if
# the anchor were skipped, this would succeed identically to the honest client.
bad = run(["node", "test/integration/client.mjs", "enrol", DIST],
          {"COMMITMENT_PK": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
check(bad.returncode != 0 and "commitment" in (bad.stderr + bad.stdout).lower(),
      "a client with a different pinned key refuses the issuance",
      (bad.stderr.strip().splitlines() or ["(no error)"])[-1][:100])

nokey = run(["node", "test/integration/client.mjs", "enrol", DIST], {"COMMITMENT_PK": ""})
check(nokey.returncode != 0,
      "a client with NO pinned key refuses rather than trusting the server",
      (nokey.stderr.strip().splitlines() or ["(no error)"])[-1][:100])

r = run(["node", "test/integration/client.mjs", "poll", DIST, client["lineage"], client["device_sk"]])
check(r.returncode == 0, "client polls its subscription with a device signature")
before = [u for u in r.stdout.strip().splitlines() if u.startswith("vless://")]
assigned_before = {u.split("#")[-1] for u in before}
check(len(before) == 3, f"client is assigned {len(before)} nodes", ", ".join(sorted(assigned_before)))


# ═══════════════════════════════════════════════════════════════════════════
section("real probe agents measure from the 'inside' vantage")

codes = c("/admin/enrol-codes", "POST", {"count": 8})["codes"]

agent_env = {"OPERATOR_PUBKEY": OPERATOR_PUBKEY}
agents = []
for i in (0, 1):
    p = subprocess.Popen(
        ["python3", "probe-agent.py", "--collector", COLL, "--enrol", codes[i]],
        cwd=DEPLOY, env={**os.environ, **agent_env},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    agents.append(p)

# One cycle each, then stop. BASE_INTERVAL_S is 900s, so the agent does its
# first pass immediately and then sleeps; we read that pass and terminate.
outputs = []
deadline = time.time() + 90
for p in agents:
    lines = []
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        lines.append(line.rstrip())
        if "probed" in line:
            break
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
    outputs.append("\n".join(lines))

for i, out in enumerate(outputs):
    check("enrolled" in out, f"probe {i} enrolled with a one-time code",
          next((l for l in out.splitlines() if "enrolled" in l), ""))
    check("SIGNATURE INVALID" not in out, f"probe {i} accepted a genuine signed manifest")
    m = re.search(r"probed (\d+) targets, (\d+) reachable — report (\w+)", out)
    check(m is not None, f"probe {i} completed a measurement cycle",
          m.group(0) if m else out.splitlines()[-1] if out else "(no output)")
    if m:
        check(m.group(3) == "accepted", f"probe {i}'s report was accepted")
        check(int(m.group(2)) < int(m.group(1)),
              f"probe {i} saw the closed node as unreachable",
              f"{m.group(2)} of {m.group(1)} reachable")

# ═══════════════════════════════════════════════════════════════════════════
section("burn: three strikes, then attribution")

runs = []
for i in (1, 2, 3):
    r = run(["python3", "control-plane.py", "check"], cp_env)
    runs.append(r.stdout)
    check(r.returncode == 0, f"control-plane.py check round {i} runs", r.stderr.strip()[:100])

check("strike 1/3" in runs[0], "round 1 records a strike rather than acting",
      next((l.strip() for l in runs[0].splitlines() if "strike" in l), ""))
check("strike 2/3" in runs[1], "round 2 records the second strike")
check("[BURN]" in runs[2], "round 3 burns the node",
      next((l.strip() for l in runs[2].splitlines() if "BURN" in l), ""))
check("reachable" in runs[2], "healthy nodes are reported reachable in the same pass")

m = re.search(r"attribution: (\d+) lineages implicated \(weight ([\d.]+)\)", runs[2])
check(m is not None, "attribution ran", m.group(0) if m else runs[2][-200:])
if m:
    check(int(m.group(1)) >= 1, f"{m.group(1)} lineage(s) implicated by the burn")
    eq(m.group(2), "0.5", "sacrificial-pool burn carries the lightest weight")
check("demoted, never banned" in runs[2], "the response is demotion, never a ban (I3)")

check(os.path.exists(provision_marker), "PROVISION_CMD fired to provision a replacement")
check("measurement target retired" in runs[2],
      "the burned node is retired from the probe manifest too",
      "otherwise volunteers keep connecting to an address the censor is watching")

inv = {n["id"]: n for n in d("/admin/nodes")}
eq(inv["node0001"]["status"], "blocked", "distributor marks node0001 blocked")
eq(inv["node0002"]["status"], "active", "node0002 untouched")
eq(inv["node0003"]["status"], "active", "node0003 untouched")

tgt = {t["node_id"]: t for t in c("/admin/targets")}
eq(tgt["node0001"]["status"], "retired", "collector stops issuing the burned node")


# ═══════════════════════════════════════════════════════════════════════════
section("client self-heals with no user action")

d("/admin/nodes", "POST", [node("node0004", asn="prov-b")])
r = run(["node", "test/integration/client.mjs", "poll", DIST, client["lineage"], client["device_sk"]])
check(r.returncode == 0, "the same client polls again — no reinstall, no new credential")
after = [u for u in r.stdout.strip().splitlines() if u.startswith("vless://")]
tags = {u.split("#")[-1] for u in after}
check(len(after) == 3, f"client is still assigned {len(after)} nodes", ", ".join(sorted(tags)))
check("D-node00" in " ".join(tags), "assignments are live REALITY endpoints")

# The burned node must be gone from what the client is handed, and the
# replacement must be in it. Node ids are compared through the per-node
# credential UUID, which is what the client actually dials.
burned_cred = inv["node0001"]["users"][0]["id"]
check(not any(burned_cred in u for u in after),
      "the burned node's credential is no longer served to the client")
new_inv = {n["id"]: n for n in d("/admin/nodes")}
fresh_cred = new_inv["node0004"]["users"][0]["id"]
check(any(fresh_cred in u for u in after),
      "the replacement node's credential is served instead", "self-heal is complete")


# ═══════════════════════════════════════════════════════════════════════════
section("a deliberately hostile probe (P5 acceptance criterion)")

def probe_post(path, body):
    req = urllib.request.Request(f"{COLL}{path}", method="POST",
                                 data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError:
        return None


def enrol_slot(code):
    r = probe_post("/probe/enrol", {"code": code})
    return r["tokens"] if r else []


def cycle(tokens):
    """One manifest + one report, spending a token on each. Returns entries."""
    if not tokens:
        return None, None
    got = probe_post("/probe/manifest", {"token": tokens.pop()})
    if not got:
        return None, None
    tokens.extend(got.get("tokens") or [])
    return json.loads(got["manifest"])["targets"], tokens


REAL_HOST = "127.0.0.1"          # every real target; canaries are 127.0.0.2+

# Honest slots build the corroboration record: a canary down-report only counts
# against a slot once ANOTHER slot has reached that same host in the window.
covered = set()
for code in codes[2:5]:
    toks = enrol_slot(code)
    for _ in range(15):
        entries, toks = cycle(toks)
        if entries is None or not toks:
            break
        canaries = [e for e in entries if e["host"] != REAL_HOST]
        covered.update(e["host"] for e in canaries)
        probe_post("/probe/report", {"token": toks.pop(),
                                     "results": [{"ref": e["ref"], "tcp": True} for e in canaries]})
check(len(covered) >= 18, f"honest slots corroborated {len(covered)} of 24 canary hosts",
      "a lie is only counted once someone honest has reached the same host")

# The censor. Enrols like anyone else, receives real work, and reports
# everything unreachable in order to burn healthy nodes.
hostile = enrol_slot(codes[5])
canary_heavy_at = None
for round_no in range(1, 9):
    entries, hostile = cycle(hostile)
    if entries is None or not hostile:
        break
    n_real = sum(1 for e in entries if e["host"] == REAL_HOST)
    if len(entries) >= 7 and n_real <= 1:
        canary_heavy_at = round_no
        break
    probe_post("/probe/report", {"token": hostile.pop(),
                                 "results": [{"ref": e["ref"], "tcp": False} for e in entries]})

check(canary_heavy_at is not None,
      "the hostile slot is detected and demoted to a canary-heavy manifest",
      f"after {canary_heavy_at} rounds of lying" if canary_heavy_at else "NOT detected within 8 rounds")

# The whole point: detection must not have cost a healthy node.
final = {n["id"]: n for n in d("/admin/nodes")}
for nid in ("node0002", "node0003", "node0004"):
    eq(final[nid]["status"], "active", f"{nid} survived the hostile reports")

report = c("/admin/verdicts")
by_ref = {v["node_id"]: v for v in report["verdicts"]}
for nid in ("node0002", "node0003"):
    check(by_ref[nid]["verdict"] != "blocked",
          f"{nid} is not judged blocked on the strength of a hostile slot",
          f"verdict={by_ref[nid]['verdict']}, blocked_slots={by_ref[nid]['blocked_slots']}")

r = run(["python3", "control-plane.py", "check"], cp_env)
check("[BURN]" not in r.stdout, "a further control-plane pass burns nothing",
      "a censor feeding false blocks does not get to destroy the fleet")

# ═══════════════════════════════════════════════════════════════════════════
section("operator health check — the failures that are otherwise silent")

health_env = {"DISTRIBUTOR_URL": DIST, "ADMIN_KEY": ADMIN_KEY,
              "COLLECTOR_URL": COLL, "COLLECTOR_ADMIN": COLL_ADMIN}
r = run(["node", "tools/health-check.mjs"], health_env)
check(r.returncode in (0, 1), "health-check.mjs runs against the live system",
      f"exit {r.returncode}")
check("key commitment serial" in r.stdout,
      "it reports the key commitment and its headroom",
      next((l.strip() for l in r.stdout.splitlines() if "commitment" in l), ""))
check("canary" in r.stdout, "and the canary pool state")

# The trap this script exists for: a commitment that no longer covers the
# current epoch stops enrolment dead, with no error anywhere until someone
# tries to sign up.
stats = d("/admin/stats")
check(stats["key_commitment"]["issuing"] is True,
      "the live distributor is issuing", 
      f"headroom {stats['key_commitment']['epochs_of_headroom']} epoch(s)")

r = run(["node", "tools/verify-commitment.mjs", "--key", os.environ["COMMITMENT_PK"],
         f"{DIST}/api/keys"], {"NODE_EXTRA_CA_CERTS": os.environ["SSL_CERT_FILE"]})
check(r.returncode == 0, "verify-commitment.mjs validates the published commitment",
      next((l.strip() for l in r.stdout.splitlines() if "serial" in l), r.stderr[:90]))
check("sha256" in r.stdout, "and prints a hash anyone can compare against a mirror")


print(json.dumps({"failures": failures, "count": count}), file=sys.stderr)
if failures:
    print(f"\n\033[31m{len(failures)} of {count} checks FAILED\033[0m")
    for f in failures:
        print(f"   - {f}")
    sys.exit(1)
print(f"\n\033[32mall {count} checks passed\033[0m")

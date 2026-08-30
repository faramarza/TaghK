# Public-Scale Circumvention System

A design and reference implementation for population-scale internet access under a
hostile, well-resourced, whitelist-capable state.

**Not bulletproof.** No such system exists, and one sold as bulletproof is the dangerous
kind. This is a system where every layer's death is anticipated, survivable, and already
has a successor staged.

---

## The founding assumption

> **The censor is your user.**

At public scale you cannot vet anyone. The state registers like everyone else and holds
every config within hours. Any design that depends on the adversary not knowing something
is already dead.

Only three things survive full adversary knowledge:

1. **Collateral damage** — your endpoint is infrastructure they cannot afford to block
2. **Churn economics** — you create endpoints faster than they can enumerate them
3. **No endpoint exists** — volunteer swarms and refraction networking

Everything here serves those three.

---

## Files

| File | What it is |
|---|---|
| **`01-ARCHITECTURE.md`** | The design. Four planes, five transport tiers, threat model, economics, and what the system deliberately does not do. **Read this first.** |
| **`02-RUNBOOK.md`** | Operating manual. Setup, provider selection, incident response, maintenance, operator security, metrics. |
| **`03-SECURITY.md`** | Security model, anonymity architecture, full hardening register with reasoning, secret handling, residual risk, pre-launch checklist. |
| `deploy/voprf.js` | Privacy Pass core. ristretto255 VOPRF with batched Chaum–Pedersen DLEQ proofs. Entitlement without identity. |
| `deploy/distributor-worker.js` | Plane 1. Anonymous, accountable credential issuance. VOPRF tokens, proof-of-work, lineage reputation, tiered pools, leak attribution, device binding. |
| `deploy/collector-worker.js` | Plane 3 front end. Signed work manifests, canary-based hostile-probe detection, quorum verdicts. **Deploys separately from the distributor.** |
| `deploy/probe-agent.py` | In-country measurement vantage point. Signature-pinned, memory-only, zero-dependency. |
| `deploy/control-plane.py` | Plane 3. Pull-only burn detection, nationwide-event guard, automated replacement. |
| `deploy/bootstrap.sh` | Provisions one transport node — REALITY (Tier D) + CDN-fronted WebSocket (Tier A) + camouflage site + full host hardening. Idempotent. |
| `deploy/client-singbox.json` | Plane 4. Client template with automatic tier failover. Zero user decisions. |
| `deploy/commitment.js` | The key commitment clients anchor against. Its signing key lives **offline**, never on the Worker — see `docs/adr/0006`. |
| `deploy/durable.js` | Strongly consistent primitives. Token spend records, single-use proof-of-work, probe nonces, rate limiters. These cannot live in KV — see `docs/adr/0001`. |
| `deploy/canary.js`, `deploy/canary-pool.js` | Canary selection and the generated 246-host bootstrap pool. |
| `deploy/selftest.mjs` | Cryptographic self-test. **Run before every deployment.** |
| `deploy/test/` | 260 checks across eight suites. Both Workers driven through their real APIs in the real Workers runtime; the node's generated configs parsed and served; and the burn → attribution → replacement → self-heal loop run end to end with real processes. |
| `docs/adr/` | Architecture decision records, including the escalated Cloudflare terms-of-service question. |
| `deploy/wrangler*.toml`, `package.json` | Deployment config and key generation scripts. |

---

## Start here

Do these in order. Each stage is independently useful — a partial build still delivers access.

**1. Tier B, today, ten minutes, free:**

```bash
docker run -d --restart=always --name snowflake \
  --network host thetorproject/snowflake-proxy:latest
```

This is the highest leverage per unit of effort in the entire project. It needs no
infrastructure, cannot be burned by your mistakes, and scales with diaspora participation
rather than with your budget. Getting ten thousand people abroad to run it is worth more
than everything else here combined.

**2. Verify it actually works before trusting it:**

```bash
cd deploy && npm install
node selftest.mjs        # cryptography only, two seconds
./test/run-all.sh        # everything, about three minutes
```

`run-all.sh` runs both Workers in the real Workers runtime and drives them
through the real API — issuance, redemption, concurrency, and the failure paths
— then stands up the whole measurement plane and burns a node to confirm a
client heals without touching anything. If your system Python lacks the
`cryptography` package, pass an interpreter that has one:
`PYTHON=/path/to/venv/bin/python ./test/run-all.sh`. The last two suites need
`nginx` and are skipped with a notice if it is missing.

Crypto that does not work is worse than no crypto, because it looks like
protection. In particular, an unverified DLEQ proof silently forfeits all
anonymity against the server.

**Read `04-STATUS.md` before assuming any of this is ready.** The backend now
runs correctly under test; it has never been deployed, there is no client, and
one open question about Cloudflare's terms of service blocks Tier A
(`docs/adr/0002`).

**3. Then read `01-ARCHITECTURE.md`, `03-SECURITY.md`, and `02-RUNBOOK.md` §1.**

---

## The anonymity architecture, in one paragraph

Reputation requires memory; memory endangers users. Most systems resolve that
tension by quietly choosing surveillance. This one splits the functions apart.
**Entitlement** — may you ask? — is carried by VOPRF tokens: cryptographically
unlinkable, so the server cannot connect a redemption to its issuance even if
compromised and logging everything. **Reputation** — what do you deserve? — is
carried by a *lineage*: an opaque ID proven by holding the previous credential
secret, which accrues suspicion when its nodes get blocked. Stated honestly, this
is **pseudonymous, not fully anonymous** — a lineage is linkable to itself over
time, but to no person, device, phone number, or address. That is the strongest
position achievable while retaining any ability to respond to leaks.

---

## Four things to take away

1. **Assume the censor is a subscriber.** Design so full adversary knowledge is survivable.
2. **Rented servers are throughput, not resistance.** The load-bearing tiers are collateral damage and volunteer swarm.
3. **Distribution, measurement, client UX, and trust *are* the system.** Servers are the easy part, and building only servers is the standard way to fail.
4. **The two highest-leverage actions are not engineering.** A diaspora-scale volunteer proxy campaign, and policy pressure for satellite direct-to-cell and refraction partnerships. Both change the structure of the problem instead of playing another round of the arms race.

---

## Rules that are not negotiable

- **Do not collect what you would not want seized.** No device fingerprints, no phone
  numbers, no user IPs, no per-user connection logs. That database is an arrest list.
- **Demote, never ban.** A false positive under a hostile government means doing the
  censor's work for them.
- **Open source, reproducible builds, signed releases.** A closed-source circumvention
  tool for Iranians should be assumed hostile, and users are right to assume it.
- **Nodes are cattle, not pets.** Never rehabilitate a blocked IP. Destroy and replace.
- **Measure from inside.** A node that answers you in Berlin and is blocked in Tehran
  looks healthy on every conventional monitor.

---

## What this does not solve

Stated plainly, because an undocumented limit is one that surprises you at the worst moment.

- **Total national blackout.** Off-network channels buy contact, not bandwidth. Nothing restores the internet.
- **Device seizure and physical coercion.** No network layer helps.
- **Metadata correlation.** Encryption hides content, not the fact of the connection.
- **A state that accepts total economic collateral damage.** If they will block Cloudflare and break WebRTC nationally, the load-bearing tiers fall.
- **Prosecution risk.** 2026 legislation attaches severe penalties. This reduces detection; it cannot make use safe.
- **The last mile of adoption.** Tools not installed before the crisis do not exist during it.

---

## Legal

In the US, EU, and Canada, operating this is lawful. **OFAC General License D-2**
explicitly authorises exporting personal communications services and
anti-surveillance/circumvention software to Iran. Practical constraints are hosting
provider terms of service, not sanctions law. Do not accept payment from inside Iran.

The real risk is targeting, not prosecution. Hardware security keys on every account.

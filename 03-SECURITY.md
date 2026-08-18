# Security Model and Hardening Register

**Companion to `01-ARCHITECTURE.md`. This document states what the system
protects, what it does not, and every hardening decision with its reasoning.**

---

## 0. The one rule

> **Do not collect what you would not want seized.**

Under 2026 Iranian law, a database linking people to proven use of a
circumvention tool is an arrest list with evidence attached. Every design choice
below is downstream of that sentence. Where security and data collection
conflict, collection loses.

---

## 1. Who we are defending against

| Adversary | Capability | Our position |
|---|---|---|
| **The censor as subscriber** | Registers like anyone, receives credentials, blocks them | **Assumed from the outset.** Priced via partitioning, attribution, and churn. |
| **The censor as network observer** | DPI, active probing, ASN blocklisting, whitelisting | Defended by REALITY, uTLS, CDN-riding, protocol diversity |
| **The censor as probe volunteer** | Enrols as a measurement node, learns the fleet | Partitioned manifests + unique canaries + slot reputation |
| **Server seizure / subpoena** | Full read of any component's storage | **Nothing durable worth stealing.** No identities, no IPs, no logs. |
| **Operator compromise** | Phishing, credential theft, coerced access | Plane separation, hardware keys, distinct secrets per plane |
| **Malicious server (us, compromised)** | Could tag users at issuance | **DLEQ proofs** — mathematically prevented, not merely promised |
| **Device seizure** | Full read of a user's phone | Client deniability only. **Unsolved, and honestly so.** |

---

## 2. The anonymity architecture

### 2.1 The tension

Reputation requires memory. Memory endangers users. Most systems resolve this by
quietly choosing surveillance. This one splits the two functions apart:

| Function | Mechanism | Property |
|---|---|---|
| **Entitlement** — may you ask? | VOPRF tokens (`voprf.js`) | **Cryptographically unlinkable.** The server cannot connect a redemption to its issuance, cannot tell two redemptions apart, and this holds even if the server is compromised and logs everything. |
| **Reputation** — what do you deserve? | Lineage — an opaque ID proven by holding the prior credential secret | **Pseudonymous.** Linkable to itself over time; linkable to no person, device, number, or address. |

### 2.2 Stated honestly

**This is pseudonymous, not fully anonymous.** A lineage can be followed across
its own renewals. What it can never be followed to is a human being. That is the
strongest achievable position while retaining any ability to respond to leaks,
and claiming more would be dishonest.

### 2.3 Why the DLEQ proof is mandatory

Without a proof of correct evaluation, a compromised server can use a **different
secret key per user**. At redemption it tries each key, sees which matches, and
has de-anonymised that user completely.

The Chaum–Pedersen batch proof forces the server to demonstrate it used the one
advertised public key, so every token in existence shares a single anonymity set.

> **A VOPRF deployment where the client skips DLEQ verification provides no
> anonymity against the server at all.** `unblind()` throws rather than
> proceeding — this is deliberate and must not be softened.

### 2.4 Probe tokens — a documented weaker choice

Probes authenticate with stateless HMAC bearer tokens rather than VOPRF:

```
token = slot || nonce || HMAC(K, slot||nonce)
```

The collector verifies without storing, so **no probe roster exists to seize** —
and a list of probes is a list of people inside the country to arrest.

**The limit, stated plainly:** this is unlinkability *by amnesia*, not by
mathematics. It holds because the collector does not log at issuance. VOPRF holds
even if it does.

**Why we accept it:** the agent must install on an old phone with no package
manager and no dependency fetch. Pure-Python ristretto255 is not a reasonable ask
there. This is a deliberate trade with a documented upgrade path, not an oversight.

---

## 3. Hardening register

Every control, why it exists, and what it stops.

### 3.1 Distributor (`distributor-worker.js`)

| Control | Prevents |
|---|---|
| `KEY_SALT` separate from `ADMIN_KEY` | Rotating the admin key would otherwise invalidate every stored hash, forcing operators to choose between key hygiene and system continuity |
| Constant-time comparison on admin keys and MACs | Timing oracle recovering the operator key byte by byte |
| `crypto.getRandomValues` for all node selection | `Math.random()` is predictable; a censor could anticipate assignments and pre-position blocks |
| Fisher–Yates with CSPRNG | Biased shuffles leak pool structure |
| **Reverse index** `node → lineages` | The naive scan was O(all users) per burn — slow, and a denial-of-service vector an attacker could trigger by burning cheap nodes |
| Bounded body reads (64 KB) | Memory exhaustion |
| Strict regex validation on every ID, hex field, and header | Injection and KV key poisoning |
| Rate limits on challenge and issuance, keyed on a **hashed, minute-expiring** hint | Mass harvesting, while storing no durable record of any address |
| Single-use PoW challenges | Replay of one solved proof across many issuances |
| Single-use VOPRF tokens, spend record stored as a **peppered hash** | Double-spend; and a seized spend log reveals nothing about tokens not yet presented |
| Rotating lineage continuity secret | A captured secret expires at the next issuance |
| Uniform `404` decoy for every error, unauthorised, and malformed request | Distinct error responses fingerprint the service as circumvention infrastructure |
| `no-store`, `nosniff`, `no-referrer` on every response | Caching and referrer leakage |
| UTF-8-safe base64 | `btoa()` throws on multi-byte input — a functional bug with availability consequences |
| No analytics, no observability, no request logging | The logs cannot be seized if they were never written |

### 3.2 Collector (`collector-worker.js`)

| Control | Prevents |
|---|---|
| **Deployed as a separate Worker, KV, and admin key** | Compromising measurement must not yield credential issuance. Co-locating for convenience merges both blast radii. |
| **Ed25519-signed work manifests** | Probe-as-oracle. Without signatures, anyone answering the agent chooses what a volunteer's device connects to. |
| Manifest freshness window (1 hour) | Replay of stale manifests pointing at dead or re-assigned targets |
| **Partitioned manifests** | A hostile probe learns a small subset, never the fleet |
| **Unique per-issuance canaries** | Hostile-probe detection. A canary is known to exactly one slot, so attribution is exact rather than statistical. |
| Canary results excluded from node verdicts | A hostile probe cannot burn real nodes through false reports |
| Slot suspicion demotes to canary-heavy manifests | The censor ends up measuring decoys |
| Quorum across independent slots | One hostile or flaky probe cannot destroy a healthy node |
| One vote per slot per window | Ballot stuffing |
| Enrolment codes stored **hashed**, single-use | A KV read yields no usable code |
| Slot ID **not derived** from the enrolment code | Otherwise the enrolment record links a slot back to whoever received the code |
| RTTs reported in **coarse buckets** | Precise timings from a known vantage fingerprint the probe's network position and help locate the volunteer |
| Report windows bucketed to 15 minutes | Cross-probe timing correlation |

### 3.3 Probe agent (`probe-agent.py`)

| Control | Prevents |
|---|---|
| **Pinned operator public key; refuses to run without it** | Attacker-supplied target lists on a volunteer's device inside a hostile state |
| Vendored pure-Python Ed25519 | Requires no package manager, no dependency fetch — installs on a phone or an old laptop |
| Signature verified **before** any target is contacted | Unsigned manifests never influence behaviour |
| **Memory-only state, nothing written to disk** | Device seizure yields no evidence of participation |
| Jittered intervals (±40%) | A fixed heartbeat is itself a fingerprint |
| Browser user-agent, ordinary HTTPS to a CDN-fronted collector | Flow-metadata distinguishability |
| No tunnelling capability, ever | The agent must never become a proxy; that would change the volunteer's legal exposure entirely |
| Reports carry no identity, IP, ISP, location, or device data | De-anonymisation of the volunteer |

### 3.4 Node (`bootstrap.sh`)

| Control | Prevents |
|---|---|
| SSH key-only, root password login disabled, `MaxAuthTries 3` | Brute force. A compromised node hands over every credential it serves. |
| Modern KEX / cipher / MAC allowlist | Downgrade attacks |
| `ufw limit` on SSH, deny-by-default inbound | Scanning and brute force |
| fail2ban | Sustained credential attacks |
| Unattended security upgrades | Known-CVE exploitation on unattended cattle nodes |
| **Swap disabled** | Process memory holds live user UUIDs; swap writes them to persistent storage |
| **Core dumps disabled** (`LimitCORE=0`, `suid_dumpable=0`, `core_pattern`) | A crash dump of Xray contains live credentials |
| Shell history disabled | A seized node otherwise records operator activity |
| systemd sandboxing: `ProtectSystem=strict`, `NoNewPrivileges`, capability bounding to `CAP_NET_BIND_SERVICE` | Xray compromise escalating to host compromise |
| `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, BPF hardening | Local privilege escalation and kernel-address leakage |
| Xray logging fully disabled (`access: none`, `error: none`) | Connection records existing at all |
| Credentials `chmod 600` in a `700` directory | Casual local read |
| Camouflage site on all unmatched paths | A blank page or nginx default is itself a signature |
| WebSocket path returns 404 without an `Upgrade` header | Path discovery by scanning |
| Private-range and BitTorrent egress blocked | SSRF into the host's own network; abuse complaints that get the node terminated |

### 3.5 Control plane (`control-plane.py`)

| Control | Prevents |
|---|---|
| **Pull-only; never contacts probes** | Holds no probe identities or addresses. There is no roster here to seize. |
| HTTPS enforced, non-HTTPS endpoints refused outright | Admin keys traversing plaintext |
| Full certificate validation on admin channels | Interception of operator credentials |
| Outside-vantage sanity check before attribution | A dead box being counted as a block, feeding false suspicion onto innocent lineages |
| TLS-vs-TCP distinction | Destroying a healthy node over a blocked `dest` site — a cheap fix mistaken for an expensive one |
| Strike threshold (3 rounds) | Transient outages triggering fleet destruction |
| **Nationwide-event guard (60% threshold)** | Reprovisioning into a dead network during a total blackout, burning exactly the capacity needed at restoration |
| State file `0600` | Local read of operational state |

### 3.6 Client (`client-singbox.json`)

| Control | Prevents |
|---|---|
| `utls: chrome` on every outbound | ClientHello fingerprinting identifying a Go program |
| DNS exclusively over the tunnel | Plaintext `:53` leaking every destination and being hijacked to block pages |
| Domestic and private traffic routed direct | Local banking through a foreign tunnel is slow, breaks sites, and makes the tunnel conspicuous |
| Tier ordering A → D → Tor | Under default-deny, the surviving path is tried first |
| `interrupt_exist_connections: false` | A failover dropping a live call |
| Neutral app name and icon | Every circumvention app on a phone is evidence at a checkpoint |

---

## 4. Secrets

Each plane holds different secrets. Compromise of one must not yield another.

| Secret | Held by | Rotate | On compromise |
|---|---|---|---|
| `ADMIN_KEY` | Distributor | Quarterly | Rotate immediately — **safe**, because `KEY_SALT` is separate and hashes survive |
| `KEY_SALT` | Distributor | **Never** | Rotating invalidates all stored digests. Treat as permanent. |
| `VOPRF_SK` | Distributor | On compromise only | All outstanding tokens become invalid; users must re-enrol |
| `PROBE_HMAC_KEY` | Collector | Quarterly | All probe tokens invalid; probes must re-enrol |
| `MANIFEST_SK` | Collector | On compromise only | **Critical** — an attacker can direct volunteers' devices. Rotate and push a client update immediately. |
| `COLLECTOR_ADMIN` | Collector | Quarterly | Rotate |
| `ENROL_SALT` | Collector | **Never** | Rotating invalidates outstanding enrolment codes |
| Node SSH keys | Operator | Per node | Destroy the node. Never rehabilitate. |

**Rules:** never in source control. Never reused across planes. Hardware keys on
every account that can reach them. Separate operator identity from personal
accounts.

---

## 5. Residual risk — what is not solved

Stated plainly. An undocumented limit is one that surprises you at the worst moment.

| Risk | Status |
|---|---|
| **Device seizure** | **Unsolved.** No network layer helps. Client deniability and user education only. |
| **Physical coercion** | **Unsolved.** No technical answer exists. |
| **Metadata correlation** | **Unsolved.** The ISP knows an ID-registered SIM held a long encrypted connection abroad. Encryption hides content, not the fact of connection. |
| **Total blackout** | **Unsolved.** Off-network channels buy contact, not bandwidth. |
| **A state accepting total collateral damage** | If they will block Cloudflare and break WebRTC nationally, the load-bearing tiers fall. |
| **Lineage linkability** | Accepted by design. Pseudonymous, not anonymous — see §2.2. |
| **Probe volunteer risk** | Reduced, not eliminated. Anyone measuring from inside is exposed. Recruit with informed consent and say so plainly. |
| **Honeypot cloning of the client** | Mitigated by reproducible builds and signed releases. Requires continuous vigilance and fast public response. |
| **Provider ejection** | Recurring and expected. Answered by multi-provider diversity, not prevention. |

---

## 6. Pre-launch checklist

Do not serve real users until every line is true.

```
[ ] KEY_SALT generated and DISTINCT from ADMIN_KEY
[ ] VOPRF_SK generated via voprf.js generateKey()
[ ] MANIFEST_SK generated; public key PINNED into every probe agent build
[ ] Distributor and collector on SEPARATE Workers, KV namespaces, admin keys
[ ] Client verifies DLEQ proofs — confirm unblind() throws on a tampered proof
[ ] Reproducible build pipeline working; hashes published
[ ] Release signing key verifiable through at least two independent channels
[ ] Verification instructions published IN PERSIAN, prominently
[ ] Third-party audit commissioned
[ ] Zero logging confirmed on every plane — grep the configs, do not assume
[ ] Nationwide-event guard tested (simulate a fleet-wide block)
[ ] Recovery tested end to end: kill a node, confirm a client self-heals untouched
[ ] Hardware security keys on every operator account
[ ] Canary detection tested with a deliberately hostile probe
[ ] Rate limits verified under load
[ ] Transparency and funding statement published
```

---

## 7. Disclosure

Publish a security contact and a PGP key. Respond within 72 hours. Publish
findings in full — including the ones you would rather not.

**Trust is a load-bearing component of this system, exactly as much as the
transport tiers.** A tool nobody trusts is a tool nobody uses, and a tool nobody
uses provides zero access no matter how good the cryptography is.

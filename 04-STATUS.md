# Build Status and Gap Register

**Honest assessment as of this build. Read before assuming anything works.**

Nothing here has served a real user. One component has been tested. Most has
never been executed at all.

---

## 1. Component maturity

| Component | State | Evidence |
|---|---|---|
| `voprf.js` | **Tested** | 12/12 self-test checks pass, including anti-tagging. Found and fixed a real endianness bug. |
| `probe-agent.py` Ed25519 verify | **Tested** | Validated against the reference `cryptography` implementation, including tamper and wrong-key cases. |
| `01/02/03` docs | **Complete** | Design work, not code. |
| `bootstrap.sh` | **Never executed** | Syntax-checked only. Never run on a real VPS. |
| `distributor-worker.js` | **Never executed** | Syntax-valid. Never deployed, never handled a request. |
| `collector-worker.js` | **Never executed** | Same. Ed25519 signing support in Workers is *assumed*, not verified. |
| `control-plane.py` | **Never executed** | Compiles. Never talked to a live endpoint. |
| `probe-agent.py` (main loop) | **Never executed** | Only the crypto path is tested. |
| `client-singbox.json` | **Never loaded** | A template. sing-box has never parsed it. |

**Rough completion: architecture ~85%, backend code ~40%, client ~5%,
operations ~0%.**

---

## 2. Known defects — these are bugs, not gaps

### 2.1 KV eventual consistency breaks double-spend prevention — **critical**

Cloudflare Workers KV is eventually consistent, with propagation lag up to ~60
seconds globally. Both of these are read-then-write:

```js
if (await env.ACCOUNTS.get(spentKey)) return false;   // may read stale
await env.ACCOUNTS.put(spentKey, '1');
```

The same VOPRF token redeemed concurrently in two colos will pass in **both**.
Same flaw in the collector's token spend check.

**Impact:** token replay. An adversary can multiply their credential draw by
firing parallel redemptions from different regions.

**Fix:** move spend records to **Durable Objects** (strongly consistent,
single-threaded per key), or a strongly-consistent external store. KV is
appropriate for the node inventory; it is not appropriate for anything requiring
exactly-once semantics.

### 2.2 Rate limiter undercounts under concurrency — **moderate**

`rateLimited()` is also read-modify-write on KV. Concurrent requests read the
same counter and each writes `n+1`, so the effective limit is far higher than
configured. Same fix.

### 2.3 Ed25519 in Workers WebCrypto — **unverified**

`crypto.subtle.sign('Ed25519', ...)` is assumed available. If the runtime
requires `NODE-ED25519` or a compatibility flag, manifest signing fails closed
and the probe network never starts. Untested.

### 2.4 Cloudflare Terms of Service — **possible blocker**

Running a proxy/tunnel service through Workers and the CDN very likely violates
Cloudflare's terms. Tier A is the load-bearing whitelist-resistant tier, so this
is not a footnote. **Unresearched.** Needs a real answer before scaling: a
commercial agreement, a different provider, or a different Tier A mechanism.

### 2.5 Canary pool is three hardcoded hosts — **moderate**

`makeCanary()` returns one of three well-known domains. A censor who enrols two
probes sees the same canaries and identifies the mechanism immediately. Needs a
large rotating pool, ideally on the same ASNs as real nodes so the two are not
separable.

---

## 3. Not built at all

### 3.1 The client application — **the largest gap by far**

`client-singbox.json` is a config template. The actual application does not
exist, and without it there is no product. Missing:

- Blind/unblind VOPRF flow on the client, **including mandatory DLEQ verification**
- Proof-of-work solver
- Secure-enclave keypair generation and challenge-response signing
  (iOS Secure Enclave / Android StrongBox)
- Subscription polling and config rewriting
- Lineage secret storage and rotation
- Persian-first UI
- Neutral app identity for checkpoint deniability
- Pre-seeded emergency endpoints
- Packaging, store presence, and side-load distribution

This is the majority of the remaining work and the part that determines whether
anyone can actually use the system.

### 3.2 Provisioning automation

`PROVISION_CMD` is an empty placeholder. Tier D's entire premise is
minutes-to-replacement with no human in the loop. Needs Terraform or
provider-API automation across multiple providers, plus IPv6 rotation.

### 3.3 Second-shape transport

AmneziaWG and Hysteria2 are specified in the architecture as the diversity layer
— the thing that survives when the TLS-mimicry family gets targeted. Neither is
implemented. Today a single protocol-family detection push takes down everything
except Tier B.

### 3.4 Bootstrap channels

Email autoresponder, Telegram bot, SMS gateway, QR distribution, peer-to-peer
sharing. None built. Currently the only path to credentials is an HTTP API that
a non-technical user cannot reach.

### 3.5 Probe recruitment and enrolment distribution

`mintCodes` generates codes. There is no mechanism, and no process, for getting
them to volunteers inside the country — or for the informed-consent conversation
that must precede it. Recruiting people to run measurement infrastructure inside
a hostile state is a human problem before it is a technical one.

### 3.6 Trust infrastructure

Reproducible build pipeline, release signing, key verification through multiple
channels, third-party audit, published transparency and funding statement. All
absent. Per `03-SECURITY.md` §7, a public tool nobody trusts provides zero
access regardless of its cryptography — and it *will* be accused of being a
honeypot.

### 3.7 Testing beyond the crypto

No integration tests, no load tests, no chaos testing, no end-to-end run of
burn → attribution → replacement → client self-heal. The recovery path has never
been exercised, and an untested recovery path is a broken one.

### 3.8 Operations

Funding model, bandwidth cost projection, abuse-complaint handling, provider
relationships, legal entity, user support in Persian, incident communications.
None of this is engineering, and all of it determines survival.

---

## 4. What it would take

Rough, assuming competent people and no surprises.

| Phase | Work | Order of magnitude |
|---|---|---|
| **Fix known defects** | Durable Objects migration, verify Ed25519, canary pool, resolve ToS | 1–2 weeks |
| **First real deployment** | Actually run bootstrap, deploy both Workers, one end-to-end path | 1–2 weeks |
| **Client v1** | Android first, full VOPRF + PoW + enclave + polling, Persian UI | 2–3 months |
| **Provisioning automation** | Multi-provider Terraform, IPv6 rotation, burn→replace loop | 3–4 weeks |
| **Second-shape transport** | AmneziaWG or Hysteria2 fleet | 2–3 weeks |
| **Bootstrap channels** | Email autoresponder + one messenger bot minimum | 2–3 weeks |
| **Probe network** | Recruitment, consent process, enrolment logistics | Ongoing, human |
| **Trust infrastructure** | Reproducible builds, signing, audit | 1–2 months, partly external |
| **iOS client** | Enclave integration, App Store or sideload strategy | 2–3 months |

**Realistically: 6–9 months to something that could responsibly serve strangers,
with a small team.** Much of that is not code.

---

## 5. What you could responsibly do now

The architecture is genuinely usable as a design. Two things are ready today:

1. **Run Snowflake and Psiphon Conduit.** Zero dependency on anything here.
   Real access for real people this afternoon.
2. **Use `01-ARCHITECTURE.md` and `03-SECURITY.md` as a design document** —
   to brief a team, apply for OTF funding, or evaluate an existing project.
   The reasoning is sound even where the code is not finished.

**What you should not do:** deploy this for people inside Iran. The double-spend
defect is exploitable, the recovery path is untested, there is no client, and
nobody has audited any of it. Shipping untested circumvention infrastructure to
users under a hostile government is worse than shipping nothing, because they
will rely on it.

---

## 6. The honest summary

This is a **well-reasoned architecture with a tested cryptographic core and a
set of reference implementations that have mostly never run.**

That is a real artifact and a useful one. It is not a system. The distance
between the two is mostly the client application, operational maturity, and
trust infrastructure — and that distance is measured in months, not days.

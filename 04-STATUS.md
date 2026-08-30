# Build Status and Gap Register

**Honest assessment. Read before assuming anything works.**

Nothing here has served a real user. As of the P0 defect-closure pass, the two
Workers and the cryptographic core have been executed under test in the real
Workers runtime; nothing has been deployed to Cloudflare, no node has been
bootstrapped, and there is still no client.

**Last updated:** P0 defect closure (see `docs/adr/`).

---

## 1. Component maturity

| Component | State | Evidence |
|---|---|---|
| `voprf.js` | **Tested** | 12/12 self-test checks pass, including anti-tagging. Found and fixed a real endianness bug. |
| `probe-agent.py` Ed25519 verify | **Tested** | Validated against the reference `cryptography` implementation, including tamper and wrong-key cases. Now also verifies a real workerd-produced signature. |
| `durable.js` | **Tested** | Exercised through both Workers in workerd; exactly-once proven under 32-way concurrency. |
| `canary.js` / `canary-pool.js` | **Tested** | 29 unit checks plus integration through the collector. |
| `distributor-worker.js` | **Tested in workerd, never deployed** | 37 checks: full issuance flow, concurrency, rate limits, 14 adversarial cases. Has never run on Cloudflare's edge or handled a real user. |
| `collector-worker.js` | **Tested in workerd, never deployed** | 37 checks incl. Ed25519 signing, cross-verified by two independent implementations. Never deployed. |
| `01/02/03` docs | **Complete** | Design work, not code. |
| `bootstrap.sh` | **Configs executed; script never run** | shellcheck clean. The Xray and nginx configs it generates are parsed, asserted against 03-SECURITY §3.4, and **served** — camouflage page, 404-on-scan, and WebSocket upgrade all verified over real HTTP. The script itself still needs a real VPS: package installs, systemd, sysctl, ufw, fail2ban and SSH hardening are all unverified. |
| `control-plane.py` | **Executed** | Drives a real distributor and collector over real HTTPS with full certificate validation. The whole burn -> attribution -> replacement -> self-heal loop runs. Found defect 2.14. |
| `probe-agent.py` (main loop) | **Executed** | Runs as a real subprocess against a real collector: enrols, verifies a real Ed25519 manifest, measures, reports. Found defect 2.13. |
| `client-singbox.json` | **Never loaded** | A template. sing-box has never parsed it — no sing-box binary is reachable from the build environment. |

**Rough completion: architecture ~85%, backend code ~65%, client ~5%,
operations ~5%.**

The backend figure moved again because Plane 3 — the measurement and
burn-response loop — now runs end to end with real processes instead of being
a set of components that had each been reasoned about separately. Two defects
that only appear when the parts are wired together were found that way, and one
of them would have silently disabled the entire probe network.

It did not move further because "runs correctly against a local runtime" and
"serves people in Tehran" are still separated by a deployment, a fleet, a
client, and volunteers.

---

## 2. Defect register

Closed defects are kept, not deleted. A register that only lists open items
loses the record of what was wrong and how it was found.

### CLOSED

#### 2.1 KV eventual consistency broke double-spend prevention — *was critical*

`redeem()` and the collector's token check were read-then-write against
eventually consistent KV. The same token redeemed concurrently in two colos
passed in both, multiplying an adversary's credential draw by their number of
vantage points.

**Closed by** ADR-0001: spend records, PoW single-use, and probe nonces moved to
Durable Objects. **Evidence:** one token fired from 32 parallel requests is
accepted exactly once (`test/distributor.test.mjs`); one probe token fired 20
ways is accepted exactly once (`test/collector.test.mjs`);
`test/kv-race.test.mjs` asserts the legacy pattern still fails under a model of
KV's documented behaviour, so the fix cannot silently regress.

**Residual:** every test request reaches one runtime instance. The single-
instance-per-ID guarantee is the platform's and is unverified by us until a
real multi-region deployment in P1.

#### 2.2 Rate limiter undercounted under concurrency — *was moderate*

Same root cause. **Closed by** the same migration. **Evidence:** a 90-request
burst against a limit of 30 now yields exactly 30 successes; the legacy pattern
allowed 24 against a limit of 5.

#### 2.3 Ed25519 in Workers WebCrypto — *was unverified*

`crypto.subtle.sign('Ed25519', …)` was assumed available.

**Closed for the runtime.** The collector signs a manifest in workerd; the
signature is verified by the vendored pure-Python code in `probe-agent.py`
(the code that actually runs on a volunteer's phone) and independently by
`python-cryptography`. Eight adversarial cases — modified body, substituted
target host, wrong key, flipped bit, truncated signature, malformed key — are
all rejected by both.

**Not yet closed for deployment.** workerd is the same runtime binary
Cloudflare deploys, but this ran locally. The acceptance criterion in the build
prompt is a *deployed* Worker; that is a P1 item and remains outstanding.

#### 2.5 Canary pool was three hardcoded hosts — *was moderate*

**Closed by** ADR-0003: a generated 246-host pool plus an operator-managed pool
for ASN-aligned decoys, sampled without replacement. Two behaviours that the
original design did not have, both found by tests rather than by reasoning, are
described in that ADR: ASN preference yields below a subpool threshold, and a
canary down-report only scores when another slot independently reached the same
host.

#### 2.7 `RATE_LIMIT_PER_MIN` was declared and never enforced — *new, closed*

The collector's config declared a per-minute limit that no code read. A control
that exists only in a config file is worse than an absent one, because the
register in 03-SECURITY.md implies it is there.

**Closed:** enforced on `/probe/manifest` and `/probe/report`, keyed on the
**slot**, never on an address — the people on that endpoint are volunteers
inside Iran, and the slot is already an opaque pseudonym that identifies nobody
(I1). Authentication was split from nonce spending so a rate-limited request
does not destroy a token the volunteer still needs.

#### 2.9 Operator API failed OPEN when `ADMIN_KEY` was unset — *new, closed*

`ctEqual(header, env.ADMIN_KEY || <sentinel>)`. On a Worker deployed before its
secrets were set, whoever sent exactly the sentinel authenticated as the
operator.

The sentinel in the shipped source was a NUL byte, which HTTP header values
cannot carry, so **that exact variant was not reachable over the wire** — the
severity of the shipped code was lower than the shape suggests. It was one
careless edit away from being a space, which is reachable, and the code should
not have been comparing against a sentinel at all. A misconfiguration must
never be an authentication bypass (I5).

**Closed:** the check now requires a configured key of plausible length and
refuses otherwise. Tested against empty string, space, tab, and the literal
`"undefined"`.

*(The NUL byte also made the file register as binary to `grep` and `diff`. For
a project whose trust model depends on people being able to read the source,
that is not cosmetic.)*

#### 2.10 Device binding was bypassable by omitting a field — *new, closed*

`/api/issue` required `device_pubkey`. `/api/credentials` treated it as
optional, and `/sub/` skipped the device check entirely when the lineage had no
bound key. A client that simply left the field out received a lineage whose
subscription URL was bearer-only — usable by anyone who leaked or stole it,
which is precisely what device binding exists to prevent.

A security property that switches off when a field is absent is a silent
downgrade (§9). **Closed:** `device_pubkey` is required whenever
`REQUIRE_DEVICE_BINDING` is set, checked *before* the token is spent so a
malformed request does not cost the user a credential; and `/sub/` now fails
closed on a lineage with no bound key rather than serving it unauthenticated.

#### 2.12 Rate-limit retention silently extended by the DO migration — *new, closed*

Found by re-reading the P0 diff against I1 rather than by a test, which is the
only way this class of thing gets found.

A rate-limit key contains a peppered hash of a client address. Under KV it
carried a 120-second `expirationTtl` and the platform deleted it. Durable Object
storage has **no TTL**, so the migration quietly made the prune cadence the
retention period — six hours. IPv4 is small enough to enumerate, so a seizure of
that storage together with `KEY_SALT` would have recovered which addresses made
requests during the retained window.

Two minutes of that is abuse control. Six hours of it is a log.

**Closed:** `RateLimiter` prunes on a 120-second cadence, matching the previous
KV behaviour. The ledger keeps the six-hour cadence, where rows are opaque
hashes of tokens with no link to any person and the cadence is a cost decision.

*This is the exact shape of the failure mode §9 warns about — a privacy property
lost as a side effect of a change made for a different reason. It was introduced
and closed inside one phase; the lesson is that the diff needs reading against
I1 every time, not that the process worked.*

#### 2.13 The probe agent spent one token on two calls — *new, closed, was silent*

Found by running `probe-agent.py` against a real collector for the first time.

`run()` popped one token and used it for BOTH `/probe/manifest` and
`/probe/report`. Probe tokens are single-use. Every report the agent ever
submitted was refused.

**It did not fail before because defect 2.1 was hiding it.** The collector's
spend check was a read-then-write against eventually consistent storage, so the
second use landed a second later, usually before the first had propagated, and
was waved through. Closing 2.1 made the collector correct and the agent's bug
visible — which is the good outcome, but note what the failure would have looked
like in production: **volunteers inside Iran measuring faithfully, reporting
nothing, and no verdict ever reaching quorum.** No error, no alert; the fleet
would simply never learn that anything was blocked.

**Closed:** `fetch_manifest()` now returns the fresh tokens the collector
already sends for exactly this purpose (they were being discarded), and the
agent spends one token per call. Each cycle spends 2 and receives 4, so the
supply is self-sustaining.

*The lesson is about testing, not about tokens. Both components were "correct"
in isolation. The defect lived only in the seam, and nothing but running them
together was ever going to find it.*

#### 2.14 A burned node stayed in the probe manifest forever — *new, closed*

`handle_burn()` told the distributor a node was blocked and ran
`PROVISION_CMD`, but never told the collector. The collector kept issuing the
dead node in work manifests, so **probes inside the country went on connecting
to an address the censor had just demonstrated it was watching** — indefinitely,
because the control plane stops evaluating a node the moment it is marked
blocked, and nothing else ever revisits it.

Wasted probe capacity is the least of it. The exposure is a volunteer's device
repeatedly contacting a burned endpoint.

**Closed:** `handle_burn()` retires the collector target as well, and says so in
its output. If that call fails it prints an explicit instruction to do it by
hand rather than continuing quietly.

#### 2.16 The node forwarded a client address into Xray — *new, closed*

`bootstrap.sh` set `proxy_set_header X-Real-IP $remote_addr` on the WebSocket
location. Xray has no use for it. Behind the CDN it carries the edge's address,
but on a direct connection it is a user's.

Nothing recorded it — Xray logging is off — so this was a latent risk rather
than a live leak, and it is described at that severity. It was also one config
change away from being a record, for no benefit. **Closed:** removed, with a
test asserting no client-address header is forwarded.

### ESCALATED — needs a human decision

#### 2.4 Cloudflare Terms of Service — *researched; decision outstanding*

**Researched and answered as a question; not decided.** Cloudflare's terms were
updated on 3 December 2024 to state explicitly that proxy services, such as a
VPN service, may not run on its network without express approval. Tier A as
designed is that activity. The distributor and collector are not — they are
ordinary JSON APIs and no user traffic passes through them.

The sharpest finding is not the prohibition itself: it is that running Tier A on
the same account as the distribution plane **re-couples the failure domains the
architecture separated on purpose**, because a terms enforcement action takes
down both at once, without notice, at peak usage.

Sanctions are not the obstacle — OFAC General License D-2 (31 CFR § 560.540)
authorises anti-censorship tools for Iran. The blocker is contractual.

**Recommendation and options: `docs/adr/0002-cloudflare-terms-of-service.md`.**
Requires the project lead, and counsel. Do not proceed with Tier A until
answered.

### OPEN

#### 2.6 A token can be replayed once its spend record expires — *moderate*

Spend records carry a 30-day TTL (`CFG.SPEND_TTL_S`), inherited from the KV
implementation. A token held for longer than that and then presented is
accepted again, because the record proving it was spent has gone.

Not exploitable for the parallel-redemption attack — that is closed — but it is
a slow replay path with no bound other than patience. Options: bind tokens to a
key epoch so old tokens become invalid rather than merely unrecorded; retain
spend records permanently and accept the storage growth; or expire tokens
themselves at issuance. This wants a decision, not a default. **Do not shorten
the TTL as a cost saving — that makes the window come sooner.**

#### 2.8 Lost updates remain on lineage state, the reverse index, and inventory

Three read-then-writes on KV were deliberately left alone in the P0 pass because
moving them is an architecture decision, not a bug fix:

- `lin:<id>` — concurrent updates can lose a suspicion increment
- `idx:<node>` — a lost update lets a lineage escape attribution entirely
- `inventory` — concurrent operator writes can clobber each other

None permits a double-spend. All three weaken **attribution**, which is the
burn-response loop that the rest of the system's safety rests on. Moving
lineage state to Durable Objects would take the subscription hot path off
edge-cached storage; that needs its own ADR and the human's sign-off. See
ADR-0001 "What this does NOT fix".

#### 2.11 Builtin canary reachability from inside Iran is unverified — *blocks P5*

The 246 builtin canary hosts were chosen by judgement, not measurement. If one
is in fact blocked in country, every honest probe reports it down.

The corroboration rule added in ADR-0003 makes this **harmless rather than
harmful** — an unreachable canary simply never scores, instead of accusing
honest volunteers. But the pool still needs empirical validation from the first
honest probes before their reports are allowed to influence anything, and the
operator pool needs populating before decoys stop being separable from real
nodes by address shape. Both are P5 prerequisites and are listed in ADR-0003.

#### 2.15 The subscription URL is built from the request's own origin — *low, open*

`getCredentials()` returns `subscription: ${new URL(request.url).origin}/sub/…`.
Behind anything that terminates TLS and forwards over HTTP — which is what Tier
A is — the origin the Worker sees is not the origin the client used. In the
integration harness the client is handed `http://127.0.0.1/sub/…`: wrong scheme,
missing port.

On Cloudflare `request.url` does reflect the public URL, so this is probably
inert in the intended deployment. It is recorded because it is invisible until
a fronting layer changes, the value is derived from an attacker-settable `Host`
header, and the client that will consume it does not exist yet (P2).

**Recommended fix:** serve a configured public origin, or have the client
construct `<base>/sub/<lineage>` itself and ignore the field. Decide before the
client is written, not after.


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

Largely addressed. `deploy/test/` runs **206 checks across seven suites**:

| Suite | What it runs |
|---|---|
| `selftest.mjs` | the VOPRF core |
| `kv-race` | a model of KV's eventual consistency; asserts the legacy pattern still fails |
| `canary` | pool invariants |
| `distributor` | the Worker in workerd, driven through its real API |
| `collector` | the Worker in workerd + Ed25519 cross-verified by two independent implementations |
| `bootstrap-config` | the Xray and nginx configs `bootstrap.sh` generates, parsed and **served** over real HTTP |
| `integration` | **burn → attribution → replacement → client self-heal**, with real processes |

The recovery path is no longer untested. The integration suite stands up both
Workers in workerd behind a real nginx TLS terminator, runs `control-plane.py`
and `probe-agent.py` as real subprocesses over HTTPS with full certificate
validation, drives a real client through VOPRF with mandatory DLEQ, and then:
strikes → burn → attribution → `PROVISION_CMD` → target retirement → the same
client self-heals onto a replacement with no user action. It also enrols a
deliberately hostile probe and confirms it is detected, demoted to a
canary-heavy manifest, and destroys no healthy node.

Still absent: load tests, chaos testing, and anything involving real network
conditions. The two vantage points are simulated with an open and a closed
local port — every other byte crosses a real socket, but nothing here has met a
censor, a mobile carrier, or a node in another country.

### 3.8 Operations

Funding model, bandwidth cost projection, abuse-complaint handling, provider
relationships, legal entity, user support in Persian, incident communications.
None of this is engineering, and all of it determines survival.

---

## 4. What it would take

Rough, assuming competent people and no surprises.

| Phase | Work | Order of magnitude |
|---|---|---|
| ~~**Fix known defects**~~ | ~~Durable Objects migration, verify Ed25519, canary pool~~ **done**; ToS researched and escalated, decision outstanding | — |
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
defect is now closed, but the recovery path is still untested, there is still no
client, nothing has run on Cloudflare, and nobody has audited any of it.
Shipping untested circumvention infrastructure to users under a hostile
government is worse than shipping nothing, because they will rely on it.

Closing the defects changed one sentence in that paragraph. It did not change
the paragraph.

---

## 6. The honest summary

This is a **well-reasoned architecture with a tested cryptographic core and a
backend that now runs correctly under test but has never been deployed.**

That is a real artifact and a useful one. It is not a system. The distance
between the two is mostly the client application, operational maturity, and
trust infrastructure — and that distance is measured in months, not days.

What changed in the P0 pass is that the backend is no longer *assumed* to work.
Four defects are closed with executed evidence, one is escalated with research
behind it, and five more were found — three of them fixed, two recorded open
rather than quietly patched outside the phase's scope. What has not changed is
that no user can reach any of it.

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

#### 2.6 A token could be replayed once its spend record expired — *closed*

Spend records carried a flat 30-day TTL. A token held longer and then presented
was accepted again, because the record proving it had been spent was gone. Not
the parallel-redemption attack — that is closed — but a replay path bounded only
by patience.

**Closed by** ADR-0004: key epochs. Issuance happens under a key derived for the
current epoch; the server accepts the current epoch and its predecessor and
refuses anything older, so a token is refused on its own terms rather than
relying on a spend record still existing to catch it. Records are namespaced by
epoch and only have to outlive two of them.

**The cost, recorded rather than buried:** the epoch is visible at redemption,
so the anonymity set is partitioned by issuance period instead of being global.
With a 30-day epoch the server learns "issued this month or last month". Do not
shorten `EPOCH_LENGTH_S` — a smaller epoch is a smaller crowd to hide in.

#### 2.8a Lost updates on the reverse index and suspicion — *closed*

`idx:<node>` and `lin:<id>.suspicion` were read-then-writes on KV. A lost append
to the reverse index meant a lineage **escaped attribution entirely, in
silence** — and since the censor is by construction the lineage holding the most
burned nodes, the mechanism failed hardest against the adversary it exists for.

**Closed by** ADR-0005: an `Attribution` Durable Object holds both. The lineage
blob stays in KV because it is read on every subscription poll; only the values
written concurrently moved. These helpers deliberately fail OPEN — denying
credentials because a bookkeeping object blinked would cost a real person their
connection to protect a reputation score (I3).

#### 2.15 The subscription URL was built from the request's own origin — *closed*

`getCredentials()` returned `${new URL(request.url).origin}/sub/…`. Behind
anything that terminates TLS and forwards over HTTP — which is what a
CDN-fronted deployment is — that origin is not the one the client used: the
integration harness was handed `http://127.0.0.1/sub/…`, scheme and port wrong.
The value also derived from a caller-controlled `Host` header.

**Closed:** the endpoint returns `subscription_path` and the client joins it to
the base URL it already contacted. It never trusts the server to tell it its own
address.

#### 2.17 DLEQ verification did not prevent tagging — *was critical, closed*

**A security property the documents asserted did not hold as implemented.**
Found while implementing key epochs, by asking what the client actually
verifies the proof *against*.

The client verified the batched proof against the public key that arrived in
the same response. That proves the server used *some* key consistently, not that
it used *everyone's*. A malicious or compromised distributor picks a distinct
`k_user` per client, evaluates under it, produces a perfectly valid proof
against `Y_user`, and at redemption tries each stored key until one matches —
identifying that user exactly. Precisely the attack the proof exists to stop.
I2 was **verified but not anchored**.

**Closed by** ADR-0006. The operator publishes an epoch key commitment signed
with a long-term key that clients pin at build time; `unblind()` refuses any
issuer key not named there, and refuses to run at all without an anchor.

**The load-bearing part is where the signing key lives: `COMMITMENT_SK` never
touches the Worker.** The Worker serves a pre-signed blob it cannot produce, so
a compromised distributor cannot tag — it can refuse service or serve garbage a
client rejects, but it cannot make a client accept a key the offline holder
never committed to. That is what finally answers the "malicious server (us,
compromised)" adversary named in 03-SECURITY.md §1.

**Demonstrated, not asserted.** `test/anchor.test.mjs` builds a working attacker
whose proof verifies under its own key, and shows the anchored client refusing
it. `test/integration/plane3.py` runs the same client with a wrong pinned key
and with no pinned key, and both refuse an issuance the honest client accepts —
because a skipped anchor would otherwise look identical to a working one.

**Residual, and it is weaker — see 2.18.**

#### 2.16 The node forwarded a client address into Xray — *new, closed*

`bootstrap.sh` set `proxy_set_header X-Real-IP $remote_addr` on the WebSocket
location. Xray has no use for it. Behind the CDN it carries the edge's address,
but on a direct connection it is a user's.

Nothing recorded it — Xray logging is off — so this was a latent risk rather
than a live leak, and it is described at that severity. It was also one config
change away from being a record, for no benefit. **Closed:** removed, with a
test asserting no client-address header is forwarded.

### DECIDED

#### 2.4 Cloudflare Terms of Service — *researched, decided*

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

**Decided by the project lead: Tier A does not stay on Cloudflare.**
Separate the accounts and narrow Tier A to the control channel now; relocate
CDN-fronted transport to a provider whose terms permit it. Cloudflare's approval
was deliberately not sought — a discretionary permission can be withdrawn, by a
company whose terms already changed once in a direction that broke this design.

**Consequence: P4 (second-shape transport) moves up the order.** It is no longer
the diversity layer, it is the bulk path until a permitting CDN provider is
found. That provider shortlist is now open work — see
`docs/adr/0002-cloudflare-terms-of-service.md`.

### OPEN

#### 2.18 A malicious operator can still equivocate on the key commitment — *open, needs P7*

The residual of 2.17, recorded separately because it is a materially weaker
property than the one that was closed.

An operator holding `COMMITMENT_SK` can sign a commitment naming a per-user
issuer key and serve it to one client. Signing prevents a compromised **server**
from equivocating. It cannot prevent the **key holder** from equivocating, and
nothing cryptographic can — the key holder is by definition authorised.

What exists today makes it leave evidence: monotonic serials plus a hash chain
over predecessors, client-side rollback refusal, and a byte-identical document
served from a stable public location.

What is missing to make that evidence usable:

1. **Reproducible, signed client builds (P7)** so the pinned key is verifiably
   the one in the published source. A pinned key nobody can check is a promise.
2. **An independent mirror** of the commitment document, outside the operator's
   control, so a client or a researcher can compare what they were served.
3. **A published comparison procedure**, in Persian, that a non-technical user
   or a local technologist can actually follow.

Until all three exist the honest claim is: *a compromised server cannot tag; a
malicious operator can, but not invisibly, and not to a client that has already
seen a later commitment.* Do not state it more strongly than that in any
user-facing material.

**This makes P7 a dependency of the anonymity claim, not a trust nicety.**

#### 2.8 Node inventory can still lose concurrent operator writes — *low*

The reverse index and the suspicion counters moved to Durable Objects
(ADR-0005); `inventory` did not. Two operators writing the node list at the same
moment can still clobber each other.

Out of the decided scope, operator-side rather than user-facing, and the failure
mode is two admins racing rather than an adversary. Left open deliberately
rather than quietly closed.

#### 2.11 Builtin canary reachability from inside Iran is unverified — *blocks P5*

The 246 builtin canary hosts were chosen by judgement, not measurement. If one
is in fact blocked in country, every honest probe reports it down.

The corroboration rule added in ADR-0003 makes this **harmless rather than
harmful** — an unreachable canary simply never scores, instead of accusing
honest volunteers. But the pool still needs empirical validation from the first
honest probes before their reports are allowed to influence anything, and the
operator pool needs populating before decoys stop being separable from real
nodes by address shape. Both are P5 prerequisites and are listed in ADR-0003.


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

Largely addressed. `deploy/test/` runs **265 checks across eight suites**:

| Suite | What it runs |
|---|---|
| `selftest.mjs` | the VOPRF core |
| `kv-race` | a model of KV's eventual consistency; asserts the legacy pattern still fails |
| `anchor` | key-commitment anchoring, with the per-user-key tagging attack mounted and caught |
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

# PUBLIC-SCALE CIRCUMVENTION SYSTEM — Architecture

**Version 2.0 — August 2026**
**Target: population-scale access under a hostile, well-resourced, whitelist-capable state**

---

## 0. The founding assumption

> **The censor is your user.**

At public scale you cannot vet anyone. The state signs up like everyone else. Within hours
of publication it holds every config, every server IP, every domain, every protocol
parameter you distribute. Any design whose security depends on the adversary not knowing
something is already dead.

This single fact invalidates most of what works for small private networks. Stealth,
obfuscation, and "don't share the config" are not strategies here. They buy hours.

**What survives full adversary knowledge?** Only three things:

| # | Principle | Mechanism |
|---|---|---|
| **1** | **Collateral damage** | Your endpoint is indistinguishable from — or literally *is* — infrastructure the state cannot afford to block. Blocking you costs them Cloudflare, Google, the app stores, their own economy. |
| **2** | **Churn economics** | You create endpoints faster and more cheaply than they can enumerate and block them. You win on cost per blocked address, not on stealth. |
| **3** | **No endpoint exists** | Volunteer swarms with constantly-rotating addresses, and refraction networking where the proxy is a stretch of network rather than a host. There is nothing to put on a blocklist. |

Everything else in this document is in service of those three. Obfuscation still matters —
but only because it *forces* the censor up the cost curve from cheap protocol-matching to
expensive IP enumeration. It is a tax on the adversary, not a shield.

---

## 1. System overview — four planes

A public system is not a pile of servers. It is four separate subsystems, each of which can
fail independently, and three of which most projects neglect entirely.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  PLANE 1 — DISTRIBUTION                                                   │
│  Getting credentials to millions of people without handing the censor     │
│  a complete list. Reputation-gated issuance. THE hardest problem.         │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ issues per-user credentials
┌──────────────────────────────▼────────────────────────────────────────────┐
│  PLANE 2 — TRANSPORT                                                      │
│  Five tiers of carriage, ordered by resistance:                           │
│    A  Collateral-damage (CDN / serverless / fronting)   ← load-bearing    │
│    B  Volunteer swarm (Snowflake model)                 ← load-bearing    │
│    C  Refraction networking (no proxy IP exists)        ← strategic       │
│    D  Churned VPS fleet (disposable, automated)         ← throughput      │
│    E  Off-network (mesh / satellite / cross-border)     ← blackout        │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ health + reachability telemetry
┌──────────────────────────────▼────────────────────────────────────────────┐
│  PLANE 3 — CONTROL                                                        │
│  In-country measurement, automated burn detection, auto-provisioning,     │
│  credential revocation, subscription republication. Fully closed-loop.    │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │ pushes config updates
┌──────────────────────────────▼────────────────────────────────────────────┐
│  PLANE 4 — CLIENT                                                         │
│  One app. Automatic tier failover. Zero user decisions. Self-healing.     │
└───────────────────────────────────────────────────────────────────────────┘
```

**The failure mode of nearly every real-world project is building Plane 2 only.** A fleet of
excellent servers with no distribution system, no measurement, and a client that asks the
user to paste a config is a system that works for two weeks and then dies quietly.

---

## 2. PLANE 1 — Distribution (the hard problem)

### 2.1 Why this is the crux

You must give working credentials to millions of strangers, at least one of whom is the
Ministry of Intelligence. Naive approaches and how they die:

| Approach | Time to death |
|---|---|
| Public list of servers on a website | Hours |
| One shared config for everyone | Hours — one revocation kills all users |
| Telegram channel posting configs | Days |
| Unlimited automated issuance | Days — censor harvests the whole pool |
| Invite-only | Survives, but does not reach the public. Not a public system. |

### 2.2 The actual answer: reputation-gated, per-user issuance

Three mechanisms combined. None works alone.

#### (a) Per-user unique credentials — always

Every user gets their **own UUID / key / bridge line**, never a shared one. This costs
essentially nothing (a UUID is free; one server hosts thousands) and buys the single most
important capability in the system: **surgical revocation and leak attribution.**

Without this, you cannot tell a leak from a coincidence, and every response is a blunt
instrument that punishes real users.

#### (b) Leak attribution — which users knew the burned resource?

This is the core insight from the bridge-distribution research literature (Salmon, rBridge,
Proteus, and BridgeDB's later designs):

```
   Server X gets blocked at time T
        │
        ▼
   Who held credentials for X?  →  users {A, B, C, D}
        │
        ▼
   Increment suspicion on A, B, C, D
        │
        ▼
   Over many blocks, the informant appears in the intersection repeatedly.
   Honest users appear once, by bad luck. The censor appears every time.
        │
        ▼
   High-suspicion accounts are quietly routed to a sacrificial pool.
```

**Key design details:**

- **Partition users across resources.** If everyone knows every server, a block implicates
  everyone and you learn nothing. Assign each user a small random subset. Blocks then carry
  information.
- **Never accuse, just deprioritise.** A user flagged as suspicious is not banned — they are
  moved to a pool of cheap, disposable endpoints. False positives cost that user speed and
  stability, not access. This matters enormously: your false positives are real people under
  a hostile government, and cutting them off is doing the censor's work.
- **Reputation accrues from survival.** A user whose resources have never been blocked earns
  access to the protected pool over time.

#### (c) Tiered resource pools

```
   NEW / UNVETTED  ──►  SACRIFICIAL POOL
                        Cheap, high-churn, disposable endpoints.
                        Expected lifetime: days. Cost per burn: cents.
                        Everyone starts here. Censors stay here.

   ESTABLISHED     ──►  STANDARD POOL
                        Normal servers, moderate churn.

   LONG-TRUSTED    ──►  PROTECTED POOL
                        Best endpoints, scarce resources (residential IPs,
                        premium routes). Never issued to new accounts.
```

The censor can burn the sacrificial pool all day. That is what it is for — it is cheap by
construction, and every burn produces attribution data.

#### (d) Sybil resistance on the front door

The censor's cheapest attack is to create 100,000 accounts and harvest everything. Raise
the unit cost of an identity:

- **Phone number verification** — effective, but excludes exactly the people at highest risk. Use with care.
- **Proof-of-work** — a client-side computation per request. Free for one user, expensive at scale. **Preferred: no identity required, no exclusion, purely economic.**
- **Rate limiting per network / per identity**, with global caps.
- **Time-delayed issuance** — new accounts wait. Costs a real user one day, costs a harvesting operation everything.
- **Social vouching as an accelerator, not a gate** — an existing trusted user can fast-track someone, and inherits reputation consequences if that person leaks. Optional path, never mandatory.

### 2.3 What we deliberately do not build — device fingerprinting and identity bans

The obvious next step from per-user credentials is: fingerprint the device, and
permanently ban devices implicated in blocks. **This is rejected.** It is worth
documenting why, because it is a natural idea that arrives in every design review.

**It fails on its own terms.** The state has unlimited devices — emulators, VMs,
burner hardware, and phones seized from detainees. Fingerprints are cheap to spoof and
cheap to rotate. The cost imposed on the adversary is near zero.

**It punishes the right people.** Honest users wipe phones before checkpoints, reinstall
after crackdowns, borrow relatives' devices, and run old or unusual hardware. Fingerprint
bans lock out precisely the highest-risk users. The asymmetry runs backwards.

**It builds the arrest list.** Device identifiers + accounts + proven use of a circumvention
tool is exactly the database the state wants, with evidence attached. It can be seized,
subpoenaed, leaked, or extracted by compromising the operator. Under 2026 Iranian law,
people die for what would be in that table.

**It destroys trust.** A public tool for Iranians known to collect device identifiers is
correctly assumed to be a honeypot, and adoption collapses. Per §7, trust is load-bearing.

> **Rule: do not collect what you would not want seized.**

**What achieves the same goal safely:**

| Instead of | Use | Why it works |
|---|---|---|
| Device *identifying* | Device ***binding*** | Client generates a non-extractable ECDSA keypair in the secure enclave (iOS Secure Enclave / Android StrongBox). Credentials are bound by challenge-response. A harvested credential or leaked subscription URL is useless without the enclave. We see only an opaque public key — no model, IMEI, OS, or advertising ID — and store only a salted hash of it. |
| Identity-based rate limits | **Proof-of-work** | Economic Sybil resistance. Free for one user, ruinous at harvesting scale. Excludes nobody. |
| Identity tracking | **Behavioural attribution** | The informant must *use* credentials to block nodes, and using them is what implicates them. Works against an adversary with infinite devices, because it keys on behaviour rather than hardware. |
| Banning | **Demotion** | A false positive under a hostile government means doing the censor's work. Suspicious accounts keep access; they simply stop receiving good nodes. |
| Known identities | **Blinded tokens** (Privacy Pass / VOPRF) | *v2 direction.* Rate-limit and revoke without the server learning which account presents a token. State of the art for this exact problem. |

Device binding is implemented in `deploy/distributor-worker.js`. Note the precise
distinction it embodies: **binding a credential to hardware is safe; identifying the
hardware is not.**

### 2.4 Bootstrap channels — reaching people who are already cut off

The recursive problem: distribution requires connectivity. Solve by using channels that are
independently reachable.

| Channel | Works under | Notes |
|---|---|---|
| **Subscription URL on Cloudflare Workers** | Whitelist | Primary. Riding permitted CDN infra. |
| **Email autoresponder** (GetTor model) | Whitelist | Gmail/Outlook were on the 2026 whitelist. Extremely robust. Attach the client, return configs in body. |
| **Telegram / permitted messenger bot** | Filtering | High reach, dies under whitelist. |
| **SMS gateway** | Total blackout of data | Text-only configs. Survives when data does not. |
| **Peer-to-peer app sharing** | Total blackout | APK + config over Bluetooth. How tools actually spread inside. |
| **QR codes in physical space** | Anything | Stickers, flyers, word of mouth. Unblockable. |
| **Pre-seeded fallbacks in the client** | Anything | Ship the app with hardcoded emergency endpoints, held in reserve, never used until needed. |
| **Satellite text** | Total blackout | Config delivery of last resort. |

**Design rule: the distribution channel must live in a different failure domain than the
transport it describes.** If your subscription URL is hosted on the same VPS as your proxy,
one block kills both, and you are back to hand-delivering configs to millions of people.

---

## 3. PLANE 2 — Transport tiers

### Tier A — Collateral damage (load-bearing)

**This is the backbone of any public system, because it is the only tier whose resistance
does not degrade with scale.** A million users behind Cloudflare are no easier to block than
ten.

**Mechanisms:**

1. **CDN-fronted tunnels** — VLESS + WebSocket + TLS on a Cloudflare-proxied domain. Traffic
   terminates at Cloudflare IPs. Blocking those means blocking a large fraction of the
   functioning web, including whitelisted sites.
2. **Serverless workers** — Cloudflare Workers, Deno Deploy, and equivalents on
   `*.workers.dev` and similar. No origin server exists to block. Deployment is free and
   instant, so churn is effectively unlimited.
3. **Domain fronting** — SNI says one permitted domain, the encrypted Host header says
   another. Curtailed by major providers but variants persist on smaller CDNs.
4. **Encrypted Client Hello (ECH)** — encrypts SNI itself, killing the single most-used
   filtering technique wherever the CDN supports it.
5. **Riding whitelisted platforms specifically** — if GitHub, ChatGPT, the app stores and
   Google are permitted, they are transport. Config channels on Gists. Proxies on permitted
   platform infrastructure. **This is the direct answer to default-deny.**

**Why it holds:** the censor's counter is not technical, it is political — accept the
collateral damage of blocking a CDN the economy depends on. Sometimes they do. Usually the
cost is too high, and that gap is your service.

**Limits:** ToS pressure from providers, bandwidth cost at scale, and the standing risk that
a provider decides to cooperate or simply eject you.

### Tier B — Volunteer swarm (load-bearing)

**The Snowflake model, and the only tier that scales without a budget.**

Volunteers worldwide run ephemeral WebRTC proxies — a browser extension, a Docker container,
a phone app. A user inside is matched to a random volunteer through a broker, connects over
WebRTC (the same protocol as video calls), and the volunteer's address is used briefly and
then never again.

**Why it is structurally strong:**

- Addresses rotate faster than any blocklist can be updated. Enumeration is futile.
- The only general counter is blocking WebRTC nationally, which breaks video calling for the
  entire country — a large, visible, economically expensive act.
- The resource pool grows with diaspora participation rather than with your budget. This is
  the correct scaling model for a public system.
- No infrastructure you own; nothing your compromise can burn.

**Strategic implication:** the highest-leverage public campaign available to a diaspora
community is not fundraising — it is getting hundreds of thousands of people abroad to
install a proxy extension and a bandwidth-sharing app. Roughly 400,000 Iranians abroad were
already running Psiphon Conduit during the January 2026 shutdown. That is the model.

**Limits:** low and variable throughput, poor for media, and DTLS handshake fingerprinting is
an emerging counter that needs continuing engineering.

### Tier C — Refraction networking (strategic)

**Conjure, TapDance, and related designs. Structurally the most censorship-resistant
approach that exists.**

The proxy is not a host — it is a **stretch of network**. A cooperating ISP places a station
in its backbone. The user connects to an ordinary, innocuous, *real* address that happens to
route through that ISB. The station recognises a covert signal in the flow and diverts it.

There is no proxy IP. The censor cannot blocklist the destination, because the destination is
a legitimate unrelated host. Blocking would require blocking every address routed through a
major transit provider.

**Why it is listed as strategic rather than deployable:** it requires partnerships with
transit ISPs. You cannot stand this up alone. But it is the correct long-term answer, and
**advocacy and funding directed at ISP participation is among the highest-value work
available** — it is a structural fix rather than another round of the arms race.

### Tier D — Churned VPS fleet (throughput)

Conventional servers, but treated as **cattle, not pets**. This tier provides the speed and
bandwidth that Tiers A and B cannot, and it survives by being cheap to replace.

**Design:**

- **Fully automated provisioning** via provider APIs / Terraform. Time from burn to
  replacement measured in minutes, with no human in the loop.
- **Provider diversity above all.** Avoid DigitalOcean, Vultr, Hetzner, OVH, Linode, and the
  hyperscalers — those ranges are blocklisted wholesale precisely because hobbyist proxies
  live there. Spread across many small regional providers.
- **Exploit IPv6.** A single /64 contains more addresses than the entire IPv4 internet.
  Rotating within it is nearly free. Where IPv6 reaches the user, address-based blocking
  collapses as a strategy.
- **Residential and mobile IPs** where obtainable — extremely expensive for a censor to block,
  since collateral damage lands on ordinary subscribers.
- **Short-lived instances.** Deliberately destroy and recreate on a schedule, not only on burn.
- **Protocol:** VLESS + REALITY + XTLS-Vision, with `fp=chrome` (uTLS) mandatory. REALITY
  borrows a real third-party certificate chain, so active probing returns the genuine site.
  This does not make servers unblockable — it forces the censor to spend IP-blocking effort
  instead of cheap protocol-matching, which is the entire point of this tier.
- **Diverse second shape:** AmneziaWG (randomised WireGuard, still functioning on strict
  Iranian carriers in 2026) or Hysteria2 (QUIC, aggressive congestion control — the right
  answer to *throttling* specifically, since it holds up on deliberately lossy links).

**Economics is the design constraint here.** Cost per user-month and cost per burned server
determine whether the tier is sustainable. Track both.

### Tier E — Off-network (total blackout)

When international connectivity is zero, no transport tier functions. The goal changes from
*reaching the world* to *reaching each other*.

| Channel | Public-scale role |
|---|---|
| **Bluetooth / LoRa mesh** (Briar, Bitchat, Meshtastic) | Neighbourhood messaging. Must be pre-installed at population scale — the deployment window is *before* the blackout. Noghteha saw 72,000 downloads in three days in January 2026; the ones that mattered were installed earlier. |
| **Satellite direct-to-cell** | **The single most important technical development for shutdown resistance.** No dish, nothing to seize, nothing to direction-find — an ordinary phone. Low bandwidth, but text is what matters. Getting this enabled for Iranian users is a policy fight worth more than any engineering effort here. |
| **Starlink** | Real bandwidth, but jammed (30–80% loss), seizable, criminal to possess, and the uplink is RF-locatable. High risk, not population-scale. |
| **Cross-border roaming** | Foreign SIMs near Turkey / Iraq / Armenia. Regional, not national. |
| **Voice and SMS** | Frequently survive data blocks. Consistently forgotten. Build them into the client's fallback ladder. |
| **Sneakernet** | USB and Bluetooth file transfer. How censored populations actually move bulk media. |

**Honest limit: no public system restores bandwidth during a total national blackout.**
Tier E buys contact, coordination, and proof of life. It does not buy the internet. Anyone
claiming otherwise is selling something.

---

## 4. PLANE 3 — Control loop

Automation is not a convenience here. At public scale, manual response is the bottleneck
that kills the system.

```
   ┌──────────────────────────────────────────────────────────────┐
   │                                                              │
   │   IN-COUNTRY MEASUREMENT                                     │
   │   • OONI Probe data                                          │
   │   • Privacy-preserving client telemetry (aggregate only)     │
   │   • Volunteer vantage points inside                          │
   │                    │                                         │
   │                    ▼                                         │
   │   BURN DETECTION                                             │
   │   endpoint unreachable from N independent in-country probes  │
   │                    │                                         │
   │        ┌───────────┴───────────┐                             │
   │        ▼                       ▼                             │
   │   AUTO-PROVISION          LEAK ATTRIBUTION                   │
   │   new endpoint from       which users held it?               │
   │   a different ASN         update suspicion scores            │
   │        │                       │                             │
   │        └───────────┬───────────┘                             │
   │                    ▼                                         │
   │   REPUBLISH SUBSCRIPTIONS                                    │
   │   clients self-heal on next poll. No user action.            │
   │                                                              │
   └──────────────────────────────────────────────────────────────┘
```

**Critical requirements:**

- **You cannot manage what you cannot measure.** Reachability *from inside Iran* is the only
  signal that matters. A server that responds perfectly to you in Berlin and is blocked in
  Tehran looks healthy on every conventional monitor. Multiple independent in-country vantage
  points are mandatory infrastructure, not a nice-to-have.
- **Telemetry must be privacy-preserving.** Aggregate reachability counts by region and
  endpoint. Never per-user connection logs. Your telemetry database is a target, and in the
  wrong hands it is a list of people to arrest. **Do not collect what you would not want
  seized.**
- **Require N independent probes to agree** before declaring a burn. Otherwise you destroy
  healthy servers on regional noise and burn budget for nothing.
- **Closed loop, no human in the path.** Burn to replacement to republication should complete
  without anyone waking up.

---

## 5. PLANE 4 — Client

The client is where a technically excellent system succeeds or fails in practice. **The most
common cause of total failure is not blocking — it is that people did not install it, could
not configure it, or gave up when it broke.**

**Requirements:**

1. **Zero decisions.** No protocol picker, no server list, no "advanced settings" to reach a
   working state. Open, connect, done.
2. **Automatic tier failover.** Sing-box and Xray both support this natively via a `urltest`
   selector — try Tier A, then B, then D, then Tor, transparently. The user never learns the
   word "REALITY."
3. **Auto-updating subscription** on a few-hour interval. Burns repair themselves silently.
4. **Persian-first UI.** Not a translation bolted on afterward. This is the largest
   unglamorous gap in the entire ecosystem — excellent tools go unused because setup is in
   English and written by engineers.
5. **Works on a bad connection.** Aggressive timeouts, resumable, low-bandwidth mode.
6. **Deniability options.** Neutral app name and icon. Every circumvention app on a phone is
   evidence at a checkpoint.
7. **Pre-seeded emergency endpoints** shipped in the binary, unused until everything else fails.
8. **Open source, reproducible builds, signed releases.** Non-negotiable — see §7.

---

## 6. Threat model at public scale

| Threat | Answer | Residual |
|---|---|---|
| Censor enumerates all configs | Assumed from the start. Per-user creds + attribution + churn. | Sacrificial pool burns constantly. By design. |
| Protocol fingerprinting | REALITY, uTLS, AmneziaWG randomisation | Taxes the adversary; does not stop them |
| Active probing | REALITY returns the genuine borrowed site | — |
| IP / ASN blocklisting | Churn, provider diversity, IPv6, CDN tiers | **Primary cost driver. Accepted.** |
| Whitelist / default-deny | Tier A (rides permitted infra) | CDN-wide block remains possible |
| WebRTC blocking | — | Kills Tier B. Costs them video calling nationally. |
| Total blackout | Tier E | **No bandwidth restoration. Contact only.** |
| Sybil harvesting of configs | Proof-of-work, rate limits, tiered pools, delayed issuance | Well-funded adversary still harvests the cheap tier |
| **Honeypot cloning of your app** | Signed reproducible builds, verified channels | **Serious. See §7.** |
| Telemetry database seizure | Collect almost nothing; aggregate only | — |
| Device seizure | Client deniability; nothing else helps | **High. Not a network problem.** |
| Metadata correlation | Nothing, realistically | Accepted |
| Provider ejection (Cloudflare etc.) | Multi-provider Tier A | Real and recurring |

---

## 7. The honeypot problem — unique to public systems

A public circumvention tool serving a targeted population **will** be accused of being a
state honeypot, and **will** be cloned into one. This is not paranoia; it is the standard
playbook. A modified build distributed through unofficial channels that logs users is
cheaper and more effective for the state than any amount of DPI.

**Mandatory countermeasures:**

- **Open source.** No exceptions. A closed-source circumvention tool for Iranians should be
  assumed hostile by users, and correctly so.
- **Reproducible builds** — anyone can verify the published binary matches the published source.
- **Signed releases**, with the signing key verifiable through multiple independent channels.
- **Publish verification instructions in Persian**, prominently, and teach the check as part
  of onboarding.
- **Third-party security audits**, published in full including findings you did not like.
- **No logging, architecturally** — not as a policy, but so that logs do not exist to be
  seized or subpoenaed. Publish the design that makes this true.
- **Transparent governance and funding.** Who pays for this is the first question a
  security-conscious Iranian user will ask, and they deserve a straight answer.

**Trust is a load-bearing component of this system, exactly as much as the transport tiers.**
A tool nobody trusts is a tool nobody uses, and a tool nobody uses provides zero access
regardless of how good the cryptography is.

---

## 8. Economics

A public system lives or dies on cost per user, and this is where most efforts quietly fail.

| Tier | Cost model | Scaling |
|---|---|---|
| A — CDN / serverless | Bandwidth-metered. Real money at scale. | Expensive but reliable |
| B — Volunteer swarm | **Free.** Donated bandwidth. | **The only tier that scales to millions without a budget** |
| C — Refraction | Partnership-funded | Strategic investment |
| D — VPS fleet | Per-server per-month plus burn rate | Linear cost — the budget sink |
| E — Off-network | User-side hardware | Not operator-funded |

**Strategic conclusion:** push as much traffic as possible onto **Tier B**, and use Tiers A
and D for what the swarm cannot carry. A design that puts everyone on rented VPSes has a
funding ceiling it will hit long before it reaches population scale.

**Funding paths:** Open Technology Fund (its *Surge and Sustain Fund* exists specifically to
spike capacity during active shutdowns), diaspora donation, and — most scalably — **donated
bandwidth rather than donated money.**

---

## 9. What this system does not solve

Stated plainly, because an undocumented limit is a limit that surprises you at the worst moment.

- **Total national blackout.** Tier E buys contact, not access. Nothing restores bandwidth.
- **Device seizure and physical coercion.** No network layer helps. Client deniability and
  user education only.
- **Metadata correlation.** The ISP knows an ID-registered SIM held a long encrypted
  connection abroad. Encryption hides content, not the fact of connection. Unsolved.
- **A state that accepts total economic collateral damage.** If they are willing to block
  Cloudflare and break WebRTC nationwide, Tiers A and B fall. Iran has approached this line.
- **Prosecution risk for users.** 2026 legislation attaches severe penalties, reportedly up
  to ten years for operating and distributing tools. The system reduces detection; it cannot
  make use safe.
- **The last mile of adoption.** Tools not installed before the crisis are tools that do not
  exist during it.

---

## 10. Build order

Sequenced so each stage is independently useful — a partial build still delivers access.

| Stage | Build | Why here |
|---|---|---|
| **1** | **Tier B participation drive** — Snowflake + Psiphon Conduit at diaspora scale | Free, instant, needs no infrastructure, helps immediately. Highest leverage per unit effort in the entire document. |
| **2** | **Tier A** — CDN-fronted tunnels + Worker endpoints | The whitelist-proof backbone. Cheap to start, scales. |
| **3** | **Plane 1 v1** — per-user credentials + subscription delivery on unblockable infra | Without this, nothing else is maintainable. |
| **4** | **Plane 4** — one client, auto-failover, Persian-first | Determines whether any of it is actually used. |
| **5** | **Plane 3** — in-country measurement + automated burn response | Turns a manual firefight into a system. |
| **6** | **Tier D** — automated churned VPS fleet | Throughput, once the control loop can manage it. |
| **7** | **Plane 1 v2** — reputation, tiered pools, leak attribution | Needed once the censor starts harvesting seriously. |
| **8** | **Trust infrastructure** — reproducible builds, audits, published governance | Before mass adoption, not after the first honeypot accusation. |
| **9** | **Tier C + policy** — refraction partnerships, satellite direct-to-cell advocacy | The structural fixes. Longest lead time, largest payoff. |

---

## 11. The strategic summary

If you take four things from this document:

1. **Assume the censor is a subscriber.** Design so that full adversary knowledge is survivable. Everything follows from this.
2. **The load-bearing tiers are collateral damage and volunteer swarm.** Rented servers are throughput, not resistance.
3. **Distribution, measurement, client UX, and trust are not supporting functions — they are the system.** Servers are the easy part, and building only servers is the standard way to fail.
4. **The two highest-leverage actions are not engineering.** They are (a) a diaspora-scale volunteer proxy campaign, and (b) policy pressure for satellite direct-to-cell and refraction partnerships. Both change the structure of the problem instead of playing another round of the arms race.

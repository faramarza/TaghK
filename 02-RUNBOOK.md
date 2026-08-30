# Operator Runbook

**Companion to `01-ARCHITECTURE.md`. This is the day-to-day operating manual.**

---

## Quick reference

| Situation | Go to |
|---|---|
| Standing the system up for the first time | §1 |
| A node just got blocked | §4.1 |
| Everything died at once | §4.3 |
| Whitelist mode came down | §4.4 |
| Total blackout | §4.5 |
| Suspected honeypot clone of your app | §4.6 |
| Weekly / monthly maintenance | §5 |
| Setting up canaries before enrolling probes | §6 |
| Something feels wrong and you can't tell what | §7 |

---

## 1. Standing it up

Sequenced so each stage is independently useful. A partial build still delivers access.

### Stage 1 — Tier B (free, instant, do this today)

Requires no infrastructure and helps immediately, including people who will never
touch your system.

```bash
# Snowflake proxy — one container, forget it exists
docker run -d --restart=always --name snowflake \
  --network host thetorproject/snowflake-proxy:latest
```

Also install the Snowflake browser extension and Psiphon Conduit on any always-on
device. Then **run the campaign**: this tier scales with diaspora participation, not
with your budget. Getting ten thousand people abroad to do the above is worth more
than anything else in this document.

### Stage 2 — Distribution plane (before any servers)

Build this first. Without it you are hand-delivering configs forever, and the system
cannot exceed the number of people you can personally message.

> **Account separation — read `docs/adr/0002-cloudflare-terms-of-service.md` first.**
> Cloudflare's terms prohibit running proxy services on its network without
> express approval. The distributor and collector are ordinary JSON APIs and are
> not that; **Tier A is.** Use a Cloudflare account for the distribution and
> measurement planes that never carries tunnelled traffic. If Tier A runs on
> Cloudflare at all, it goes on a different account. Sharing one account means a
> single terms enforcement action takes down both the transport and the
> subscription URL that was supposed to survive it.

**Run the test suite before you deploy anything.** It takes about two minutes
and it is the difference between "syntax-valid" and "works".

```bash
cd deploy && npm install
./test/run-all.sh          # 260 checks; PYTHON=<venv>/bin/python if your
                           # system python lacks `cryptography`.
                           # Suites 6 and 7 need nginx and are SKIPPED loudly
                           # without it: apt-get install -y nginx-light
```

```bash
npm install -g wrangler    # wrangler 4 or later — v3 ships known advisories
wrangler login

wrangler kv namespace create ACCOUNTS
wrangler kv namespace create NODES
# paste the returned IDs into wrangler.toml

# Durable Objects need no pre-creation: the [[migrations]] block in
# wrangler.toml creates the Ledger and RateLimiter classes on first deploy.
# They hold token spend records and rate limiters, which CANNOT live in KV —
# see docs/adr/0001-durable-objects-for-exactly-once.md.

wrangler secret put ADMIN_KEY        # generate: openssl rand -hex 32
wrangler secret put KEY_SALT         # openssl rand -hex 32 — NEVER ROTATE,
                                     # and it MUST DIFFER from ADMIN_KEY
wrangler secret put VOPRF_MASTER     # npm run keygen:voprf
                                     # per-epoch keys derive from this;
                                     # there is NO rotation ceremony
wrangler deploy
```

#### The key commitment — do this before the first user, and quarterly after

Clients refuse any issuer key that is not named in a commitment signed by a key
they pin at build time. Without it a compromised distributor could hand each
user a different key and de-anonymise them at redemption (03-SECURITY.md §2.3).

**`COMMITMENT_SK` NEVER GOES ON THE WORKER.** That is the entire security
property: the Worker serves a blob it cannot forge. Generate and use it on a
machine that is not the server.

```bash
# ONCE, offline. Pin the printed COMMITMENT_PK into every client build and
# publish it through at least two independent channels.
node tools/mint-commitment.mjs --keygen

# QUARTERLY, offline. Covers the current epoch and the next two (~90 days).
VOPRF_MASTER=... COMMITMENT_SK=... \
  node tools/mint-commitment.mjs --epochs 3 --prev-doc last-commitment.json \
  > commitment.json

# Upload the signed blob. Keep commitment.json — the next mint chains to it.
curl -X POST https://dist.<you>.workers.dev/admin/commitment \
  -H "x-admin-key: $ADMIN_KEY" -H 'content-type: application/json' \
  -d @commitment.json
```

**Issuance FAILS CLOSED without a current commitment** — `/api/issue` returns
503 and nobody can enrol. That is deliberate: tokens issued outside a commitment
are tokens a correct client must throw away. Check your headroom:

```bash
curl -s -H "x-admin-key: $ADMIN_KEY" .../admin/stats | jq .key_commitment
# { "serial": 3, "issuing": true, "epochs_of_headroom": 2, ... }
```

**If `issuing` is false, no new user can enrol.** Re-mint and upload before
anything else. Set a calendar reminder for `epochs_of_headroom <= 1`.

Uploading a commitment whose serial is not greater than the stored one is
refused with 409 — the server will not roll back, and neither will a client.

**All three secrets are required.** The Worker refuses the operator API
outright when `ADMIN_KEY` is absent rather than falling back to anything, so a
half-configured deployment fails closed and looks like a 404. That is intended;
if `/admin/stats` returns the decoy with a key you believe is right, check the
secret is actually set before debugging anything else.

Verify it is alive and that unknown paths look boring:

```bash
curl -s https://dist.<you>.workers.dev/api/challenge | jq
curl -s -o /dev/null -w '%{http_code}\n' https://dist.<you>.workers.dev/     # expect 404 decoy
curl -s -H "x-admin-key: $ADMIN_KEY" https://dist.<you>.workers.dev/admin/stats | jq
```

The challenge is a self-contained MAC-bound string of the form
`p1.<random>.<bits>.<expiry>.<mac>` — nothing is written at issuance, so a
challenge that never gets solved costs storage nothing.

### Stage 3 — First transport node

```bash
scp deploy/bootstrap.sh root@<vps>:/root/
ssh root@<vps> 'chmod +x bootstrap.sh && ./bootstrap.sh \
    --dest www.apple.com \
    --domain cdn.example.com \
    --users 500'
```

Then point a **Cloudflare-proxied domain (orange cloud ON)** at the node's IP. Without
this you have throughput but no whitelist resistance — Tier A is the layer that survives
default-deny, and it is not optional.

Register the node with the distributor:

```bash
ssh root@<vps> 'cat /root/node-credentials/manifest.json' \
  | curl -sX POST https://dist.<you>.workers.dev/admin/nodes \
      -H "x-admin-key: $ADMIN_KEY" -H 'content-type: application/json' -d @-
```

### Stage 4 — Control plane

```bash
export DISTRIBUTOR_URL=https://dist.<you>.workers.dev
export ADMIN_KEY=<key>
./deploy/control-plane.py check
```

It will warn that no in-country vantage points are configured. **Fix this before
anything else.** Burn detection without in-country measurement is blind — a node that
answers you in Berlin and is blocked in Tehran looks perfectly healthy on every
conventional monitor.

Then run it continuously:

```bash
./deploy/control-plane.py watch --interval 300
```

### Stage 5 — Cold spares

Provision **two** nodes on different providers in different countries. Register them,
then **leave them alone**. Unused endpoints are not probed and do not get burned. When
a live node dies you promote a spare in minutes instead of provisioning from scratch
over hours.

---

## 2. Provider selection

This matters more than any config tuning, and is the most common thing done wrong.

**Avoid entirely:** DigitalOcean, Vultr, Hetzner, OVH, Linode, AWS, GCP, Azure. These
ranges are blocklisted wholesale precisely because hobbyist proxies live there. A
perfect REALITY config on a DigitalOcean droplet is a perfect config on a blocked IP.

**Prefer:**

- Small regional providers, especially those with mixed residential/business allocations
- Turkey, UAE, Armenia, Georgia, Cyprus, Bulgaria, Romania, Germany — low latency to Iran
- **IPv6-heavy providers.** A single /64 holds more addresses than the entire IPv4
  internet. Rotating inside it is nearly free, and where IPv6 reaches users, address
  blocking collapses as a strategy.
- Residential and mobile IPs where obtainable — extremely expensive for a censor to
  block, because collateral damage lands on ordinary subscribers.

**Above all: spread across many providers.** Diversity beats any single provider's
quality. One provider ejecting you should cost you a fraction of capacity, never all of it.

---

## 3. Choosing the REALITY `dest`

The borrowed certificate site. Requirements, in order:

1. **Not blocked in Iran.** Using a blocked site is a self-inflicted outage — and a
   surprisingly common mistake.
2. **TLS 1.3 + HTTP/2.** Mandatory for REALITY.
3. **Plausible and high-volume.** Boring is good.
4. **Geographically sensible** relative to the node.

Reasonable choices: `www.apple.com`, `swcdn.apple.com`, `dl.google.com`,
`www.microsoft.com`, `www.bing.com`.

**Vary it across your fleet.** If every node borrows the same site, that site becomes a
fleet-wide fingerprint and one `dest` block takes down everything at once.

Verify before deploying:

```bash
openssl s_client -connect www.apple.com:443 -tls1_3 -alpn h2 </dev/null 2>&1 \
  | grep -E 'Protocol|ALPN'
```

---

## 4. Incident response

### 4.1 A single node is blocked

**Symptom:** control plane reports quorum of in-country probes failing; the node still
answers you directly.

**This is normal and expected.** Nodes are consumables.

1. Control plane handles it automatically: marks blocked → runs leak attribution →
   **retires the measurement target** → provisions a replacement → clients
   self-heal on next poll. This whole chain is exercised by
   `npm run test:integration`; if you change any part of it, run that first.

   The target retirement matters as much as the rest: without it the collector
   keeps handing the burned node to probes, and volunteers inside the country go
   on connecting to an address the censor has just shown it is watching. If the
   control plane prints `[!] could not retire the measurement target`, do it by
   hand immediately — `POST /admin/targets` with that node's entry set to
   `"status": "retired"`.
2. **Destroy the burned instance.** Do not repair, do not reuse the IP. Once
   blocklisted, an address is gone permanently.
3. Provision the replacement **on a different ASN** — same provider means likely the
   same blocked range.
4. Review attribution output. If the same accounts appear across several burns, the
   pool logic will demote them automatically. Do not intervene manually; do not ban.

**Response target:** replacement live within 2 hours. Users take no action.

**What to expect in the log.** Three consecutive `check` rounds before anything
happens — the strike counter absorbs transient outages, and without it a brief
disruption destroys the fleet:

```
[-] node0001 203.0.113.10: blocked from 2 slots — strike 1/3
[-] node0001 203.0.113.10: blocked from 2 slots — strike 2/3
[BURN] node0001 (203.0.113.10) — quorum of in-country probes confirms blocked
       attribution: 1 lineages implicated (weight 0.5) — demoted, never banned
       measurement target retired — probes stop connecting to it
       provisioning replacement on a different ASN…
```

### 4.2 TCP connects but TLS fails

**Diagnosis:** the `dest` site has probably become blocked in Iran, or the protocol is
being targeted.

**Try the cheap fix first.** Change `dest` to a different real site and restart Xray.
This costs seconds. Only reprovision if it does not help — do not destroy a healthy
node over a `dest` problem.

```bash
ssh root@<vps> "sed -i 's/www\.apple\.com/dl.google.com/g' \
  /usr/local/etc/xray/config.json && xray run -test -config /usr/local/etc/xray/config.json \
  && systemctl restart xray"
```

### 4.3 The whole fleet dies at once

**Diagnosis:** either a protocol-family detection push, or an ASN sweep.

1. **Check whether Tier A is still up.** If CDN paths work and direct nodes do not,
   it is IP-level. If both are down, it is protocol-level or worse.
2. **Do not burn all your spares probing a dead network.** Confirm with in-country
   probes first. Panic-rotating during a nationwide event wastes the exact capacity
   you will need when it lifts.
3. If protocol-level: shift weight to the diverse-shape tier (AmneziaWG / Hysteria2),
   which fails differently by design.
4. Verify Tier B fallbacks are present in every subscription. They require nothing from
   you and cannot be burned by your mistakes — they are the floor.

### 4.4 Whitelist / default-deny mode

**Symptom:** whitelisted sites load; everything else, including all direct nodes, is dead.

**Obfuscation is now irrelevant.** It does not matter how normal your traffic looks —
unrecognised destinations are dropped regardless.

1. **Tier A is the only path.** Confirm CDN endpoints are in every subscription and that
   the client's failover ordering reaches them first.
2. Deploy Worker-based endpoints — no origin server to block, free, instant, unlimited churn.
3. Move config distribution onto permitted infrastructure: email autoresponder through
   Gmail/Outlook, Gists on GitHub, anything on the permitted list.
4. Escalate Tier B (Snowflake/WebTunnel) in client priority.

### 4.5 Total blackout

**No transport tier functions. Do not fight the network — it is not there.**

1. **Stop rotating.** You are burning budget and spare capacity against a dead link.
   Preserve both for the restoration.
2. Activate off-network channels: mesh, satellite text, SMS, voice, cross-border.
3. Publish status through diaspora channels so people outside know what is happening
   and stop assuming individual devices are at fault.
4. **Prepare for restoration.** The moment connectivity returns is when demand spikes
   hardest and configs are most stale. Have fresh nodes provisioned and subscriptions
   ready to publish the instant it lifts.

### 4.6 Suspected honeypot clone

**This will happen.** A modified build that logs users is cheaper and more effective for
the state than any amount of DPI.

1. Publish signed hashes of legitimate releases immediately, through every channel.
2. Push verification instructions **in Persian**, prominently.
3. Name the malicious distribution channel publicly and specifically.
4. Coordinate with Filterwatch, Certfa, Access Now, and OONI — they have reach and
   credibility you do not.
5. **Do not go quiet.** Silence during a trust incident is read as confirmation.

---

## 5. Maintenance

### Continuous (automated)

- Control plane on `watch` — measurement, burn detection, provisioning, republication
- Subscription auto-refresh — clients self-heal without user action

### Weekly

- Review burn rate. Rising sharply means either a detection improvement or a leak — check
  whether burns cluster in one pool, which points at the pool's population.
- Confirm at least 2 cold spares are provisioned and untouched.
- Check pool balance: `curl -H "x-admin-key: $KEY" .../admin/stats | jq`
- Verify Tier B fallbacks in subscriptions still resolve.

### Monthly

- Rotate short IDs across the fleet (cheap; invalidates harvested config strings).
- Audit provider mix. If any single provider exceeds ~25% of capacity, diversify.
- Re-verify every `dest` site is still unblocked in Iran.
- Test the full recovery path end to end: kill a node deliberately, confirm a client
  self-heals without human intervention. **An untested recovery path is a broken one.**
- Review suspicion-score distribution. A bimodal split is the system working. Everyone
  drifting upward means the scoring is miscalibrated and is punishing honest users.

### Quarterly

- Reproducible-build verification by an outside party.
- Refresh the published transparency report.
- Rotate `ADMIN_KEY` and all operator credentials.
- Tabletop the blackout playbook with whoever else operates this.

---

## 6. Canary pool — do this before enrolling any probe

Manifests carry decoy targets so a probe that lies about them identifies
itself. Out of the box the collector uses a 246-host builtin pool, which works
but is **separable from real nodes by shape**: real Tier-D targets are IPs on
VPS ASNs, builtin canaries are third-party domains on academic and CDN ASNs. A
careful adversary can tell them apart. `/admin/verdicts` warns while this is
true — check `canary_pool.warnings` in its output.

The fix is decoy hosts you run yourself, on the same providers as the real
fleet, serving an ordinary website and no proxy:

```bash
# Stand up ordinary web servers on the SAME providers as your real nodes.
# They must be real, reachable, and boring. They are not proxies and must
# never become proxies.

curl -X POST https://collect.<you>.workers.dev/admin/canary-pool \
  -H "x-admin-key: $COLLECTOR_ADMIN" -H 'content-type: application/json' \
  -d '[{"host":"a.decoy.example","port":443,"asn_group":"prov-a"},
       {"host":"b.decoy.example","port":443,"asn_group":"prov-a"}]'

# Tag the real targets with the matching asn_group so canaries are drawn from
# the same ASNs:
curl -X POST https://collect.<you>.workers.dev/admin/targets \
  -H "x-admin-key: $COLLECTOR_ADMIN" -H 'content-type: application/json' \
  -d '[{"ref":"n-aaa","node_id":"...","host":"203.0.113.10","asn_group":"prov-a"}]'

# Check it took:
curl -s -H "x-admin-key: $COLLECTOR_ADMIN" \
  https://collect.<you>.workers.dev/admin/canary-pool | jq .health
```

**At least 24 aligned entries are needed before alignment turns on.** Below
that the collector deliberately ignores `asn_group` and draws from the whole
pool, because drawing repeatedly from a handful of hosts identifies them — which
is the original defect wearing a better hat. `health.warnings` says so
explicitly when you are under the threshold.

**A canary down-report only counts against a slot once another slot has
independently reached the same host.** This means detection is slower and it
means an honest volunteer whose network cannot reach some canary is never
accused for it. That trade is deliberate: under this government a false
positive is a real person losing access.

Regenerating the builtin pool as hosts die:

```bash
cd deploy && npm run build:canary-pool && npm run test:canary
```

---

## 7. Debugging checklist

When something is wrong and you cannot tell what, work down this list in order.

```
1. Is the node alive?              ssh + systemctl status xray nginx
2. Is Xray's config valid?         xray run -test -config /usr/local/etc/xray/config.json
3. Does TCP connect from outside?  nc -zv <ip> 443
4. Does TLS complete?              openssl s_client -connect <ip>:443 -servername <dest>
5. Does the camouflage page serve? curl -sI http://<ip>/       → expect 200, real page
6. Is the WS path proxying?        curl -sI http://<ip><ws_path>  → expect 404 (no Upgrade)
7. Can Iran reach it?              ./control-plane.py check      ← THE ONLY QUESTION THAT MATTERS
8. Is the node in the inventory?   curl -H "x-admin-key: $KEY" .../admin/nodes | jq
9. Does the subscription serve?    curl -s .../sub/<account> | base64 -d
10. Is the client's clock right?   TLS fails silently on clock skew. Checked last, breaks first.
```

Two failure modes that now look like a 404 rather than an error, because
everything does:

- **`/admin/*` returns the decoy with a key you believe is correct.** The secret
  is probably not set on the Worker. Auth refuses outright when `ADMIN_KEY` is
  missing instead of falling back to anything.
- **`/sub/<lineage>` returns the decoy for a client that used to work.** The
  device signature is missing, stale (outside the ±5 minute skew), or the
  lineage was created without a bound device key. The last case cannot happen
  any more but pre-existing lineages are refused rather than served
  unauthenticated — those clients must re-establish.

**Step 7 is the one that matters.** Steps 1–6 can all pass on a node that is completely
blocked inside Iran.

---

## 8. Operator security

**Legal position:** in the US, EU, and Canada this is lawful. OFAC **General License D-2**
explicitly authorises exporting personal communications services and
anti-surveillance/circumvention software to Iran. Your practical constraints are hosting
provider terms of service, not sanctions law. Do not accept payment from inside Iran.

**The real risk is targeting, not prosecution.** Iranian state-linked phishing against
diaspora technologists is persistent, well-resourced, and convincing. It typically arrives
as a plausible approach from a "journalist," a "researcher," or a genuinely compromised
acquaintance's real account.

| Control | Priority |
|---|---|
| **Hardware security keys on every account.** Not SMS, not TOTP. | **Critical — defeats nearly the entire phishing threat on its own** |
| Separate identity, email, and payment method for infrastructure work | High |
| Never publicly link your operator role to specific users inside | High |
| Treat unsolicited contact referencing this work as hostile until proven otherwise | High |
| Never sell access — it is what gets users prosecuted and makes you a target | High |
| Never run a Tor **exit** from home. Bridges and Snowflake, always | High |
| Keep no logs, architecturally — not as policy | Critical |

---

## 9. Metrics that matter

Track these. Ignore vanity numbers.

| Metric | Why | Warning sign |
|---|---|---|
| **Reachability from inside Iran** | The only real measure of success | Any sustained decline |
| Burn rate (nodes/week) | Adversary effort and your cost floor | Sudden rise = detection improvement or leak |
| Cost per burned node | Determines sustainability | Rising faster than budget |
| Mean time to recovery | How long users sit broken | > 2 hours |
| Tier B traffic share | The only tier that scales without money | Falling — means unsustainable VPS dependence |
| Pool distribution | Health of the reputation system | Everyone in sacrificial = scoring is broken |
| Client self-heal rate | Whether burns are invisible to users | Users manually reconfiguring = Plane 4 failure |

**Do not track:** per-user connection logs, user IP addresses, browsing destinations,
device identifiers. That database is an arrest list. Its existence is a greater risk to
your users than any censorship it would help you defeat.

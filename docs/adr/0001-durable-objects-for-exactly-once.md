# ADR-0001 — Durable Objects for exactly-once operations

**Status:** accepted, implemented
**Closes:** 04-STATUS.md 2.1 (critical), 2.2
**Supersedes nothing. Deviates from nothing in 01-ARCHITECTURE.md** — this is an
implementation-layer decision about storage, not a change to any plane.

---

## Context

Three security controls were built on read-then-write against Cloudflare
Workers KV:

```js
if (await env.ACCOUNTS.get(spentKey)) return false;      // double-spend
await env.ACCOUNTS.put(spentKey, '1');

const raw = await env.ACCOUNTS.get(`pow:${challenge}`);  // PoW single use
await env.ACCOUNTS.delete(`pow:${challenge}`);

const n = Number(await env.ACCOUNTS.get(key) || 0) + 1;  // rate limit
await env.ACCOUNTS.put(key, String(n));
```

KV is eventually consistent. A write is not visible to reads in other colos
until it propagates, which Cloudflare documents as taking up to about sixty
seconds worldwide. Every one of these is therefore a race.

The consequence is not theoretical and not small. An adversary who fires the
same VOPRF token at N colos simultaneously has their credential draw multiplied
by N. For a state adversary N is bounded only by how many networks they can
reach from, which is to say not bounded. The rate limiter fails the same way:
concurrent requests all read the same counter and all write `n+1`, so the
effective limit is roughly the configured limit times the concurrency — the
control does nothing under exactly the load it exists to handle.

## Decision

Move every operation that must happen **at most once** to Durable Objects, and
leave everything else on KV.

| Operation | Store | Why |
|---|---|---|
| VOPRF token spend records | DO `Ledger` | must be exactly-once |
| Proof-of-work single use | DO `Ledger` | must be exactly-once |
| Probe nonce spend records | DO `Ledger` | must be exactly-once |
| Rate limit counters | DO `RateLimiter` | must count correctly under concurrency |
| Node inventory, fallbacks | KV `NODES` | read-mostly, on the subscription hot path, staleness of seconds is harmless, edge caching is wanted |
| Measurement aggregates, targets, canary pool | KV `MEASUREMENTS` | aggregates; staleness delays a verdict, it does not corrupt one |
| Lineage state | KV `ACCOUNTS` | see "What this does not fix" |

For a given Durable Object ID there is exactly one instance world-wide,
requests to it are delivered single-threaded, and the runtime's input gate
holds back new events while a storage operation is in flight. A plain
get-then-put inside a Durable Object is therefore atomic with no explicit
locking. The race cannot be expressed rather than being unlikely.

### Sharding

Keys are sharded across 4096 objects by an FNV-1a hash of the key. Unrelated
keys proceed in parallel; the same key always lands on the same object, which
is the only property exactly-once actually needs. A single unsharded object
would have been a global serialisation point capping the whole system's
issuance rate.

### Fail closed

`claimOnce()` returns false and `overLimit()` returns true when the object is
unreachable. An availability blip must never become a free double-spend or an
unmetered harvesting window (I5). Both are one-line behaviours and both are
tested.

### Proof-of-work challenges became stateless

The old flow wrote `pow:<challenge>` to KV at issuance. Two problems: the
delete at redemption was the same race, and the write itself was an
unauthenticated storage primitive anyone could hammer for free. Challenges now
carry their difficulty and expiry inside themselves, bound by an HMAC under
`KEY_SALT`:

```
challenge = p1.<random>.<bits>.<expiry>.<mac>
```

Nothing is written at issuance. One `claimOnce` happens at redemption. A client
cannot lower its own difficulty or extend its own deadline — both are tested
adversarially.

This changes the wire format of `/api/challenge`. There is no client yet
(04-STATUS.md 3.1), so the cost is zero now and would not have been later.

## Consequences

**Cost.** Durable Object requests are billed per request and per duration, and
are more expensive per operation than KV. This affects only issuance and
redemption, not the subscription poll that every client performs hourly, so it
scales with new credentials rather than with users.

**Latency.** A DO request may cross regions to reach the object's home. Added
to issuance and redemption, not to the hot path.

**Migration.** `[[migrations]] new_sqlite_classes` in both wrangler configs.
Deploying this to an environment that already has KV spend records will not
carry them across; since nothing has ever been deployed (04-STATUS.md §1),
there is nothing to migrate.

## What this does NOT fix

Stated explicitly so nobody reads this ADR and assumes the whole class of
problem is gone. Three read-then-writes on KV remain, and they are recorded as
new defects in 04-STATUS.md §2 rather than silently fixed outside this phase's
scope:

- lineage state (`lin:<id>`) — concurrent updates can lose a suspicion increment
- the reverse index (`idx:<node>`) — a lost update lets a lineage escape attribution
- node inventory (`inventory`) — concurrent operator writes can clobber

None is exploitable for double-spend. All three weaken attribution, which is
the burn-response loop, and all three want a design decision about whether
lineage state belongs in a Durable Object at all — that would move the
subscription hot path off edge-cached storage, which is an architecture change
and needs its own ADR.

## Verification

`test/kv-race.test.mjs` models KV's documented behaviour and asserts the
**legacy pattern fails** — 24 of 24 concurrent redemptions accepted, 24
requests allowed against a limit of 5. If those tests ever start passing, the
model has been weakened rather than the bug fixed.

`test/distributor.test.mjs` runs the real worker in the real runtime and fires
one token from 32 parallel requests: exactly one success, 31 rejections. A
90-request burst against a limit of 30 yields exactly 30.

**Limit of the evidence:** every request in these tests reaches one runtime
instance. Durable Objects guarantee a single instance per ID world-wide, so the
property is expected to hold across colos, but that guarantee is the platform's
and is unverified by us until a real multi-region deployment in P1.

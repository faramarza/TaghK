# ADR-0005 — Attribution state in Durable Objects

**Status:** accepted (decided by the project lead), implemented
**Closes:** 04-STATUS.md 2.8, except node inventory — see "What is left"

---

## Context

ADR-0001 moved exactly-once operations off KV and deliberately left three
read-then-writes alone, because moving them was an architecture decision rather
than a bug fix:

- `idx:<node>` — the reverse index from a node to the lineages holding it
- `lin:<id>.suspicion` — the suspicion counter
- `inventory` — the node list

None permits a double-spend. All three lose updates under concurrency, and the
first two are the burn-response loop.

The lost append to the reverse index is the one that matters. Two clients
assigned the same node at the same moment each read the set without the other's
entry; one append is lost; **that lineage escapes attribution entirely**, in
silence. The censor is by construction the lineage holding the most burned
nodes, which makes them the most likely to be dropped. The mechanism fails
hardest against exactly the adversary it exists for.

A lost suspicion increment is milder: it under-counts, which at least fails in
the direction that does not punish an innocent person (I3).

## Decision

A third Durable Object class, `Attribution`, holds the reverse index and the
suspicion counters. **The lineage blob itself stays in KV.**

That split is the whole decision. The lineage blob is read on every subscription
poll — hourly, by every client, on connections that are already bad in a
censored country. Moving it would take that path off edge-cached storage to fix
a problem the poll does not have. Only the two values that are *written
concurrently* move.

| Operation | Where | Why |
|---|---|---|
| `implicate(node, lineage)` | DO, atomic set-add | a lost append loses a suspect |
| `drain(node)` | DO, read-and-clear in one step | two burns of one node must not double-count |
| `bump(lineage, weight)` | DO, atomic add | concurrent burns each kept their own increment and lost the rest |
| suspicion read on the credential path | DO | infrequent, and already talking to a DO to claim its token |
| suspicion read on the subscription path | **KV, cached** | the hot path never waits on a DO |

The credential path refreshes the cached value from the authoritative counter;
the burn path mirrors the new total into the blob so a demotion takes effect at
the next poll without the poll having to ask.

### These helpers fail OPEN, and the asymmetry is deliberate

Every other Durable Object helper in `durable.js` denies on error. These return
"nothing implicated" and carry on.

Refusing to issue credentials because a bookkeeping object was briefly
unreachable would deny access to a real person under a hostile government in
order to protect a reputation score. Losing an attribution record costs the
operator some certainty about who is leaking. Losing access costs a user their
connection. The second is worse, and I3 already says which way to lean.

### Bounded

A node held by more than `MAX_IMPLICATED_PER_NODE` (10 000) lineages stops
recording new ones. Attribution is statistically saturated long before that, and
an unbounded array is a storage bug an adversary can drive by enrolling
repeatedly.

## What is left

**Node inventory (`inventory`) stays on KV and can still lose concurrent
operator writes.** It was out of the decided scope, it is operator-side rather
than user-facing, and the failure mode is two admins racing — not an adversary.
It stays open in 04-STATUS.md 2.8 rather than being quietly closed.

## Verification

`test/distributor.test.mjs`:

```
2.8 — attribution survives concurrency
  ✓ six distinct lineages hold node0005
  ✓ every lineage that held the burned node is implicated, none lost   got 6, want 6
  ✓ a sacrificial-pool burn carries the lightest weight
  ✓ a second burn of the same node implicates nobody twice — the index is drained atomically
```

`test/integration/run.sh` exercises the same path end to end through
`control-plane.py`: strikes, burn, attribution, target retirement, and a client
self-healing onto a replacement.

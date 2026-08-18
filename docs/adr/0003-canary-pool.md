# ADR-0003 — Canary pool and hostile-probe scoring

**Status:** accepted, implemented
**Closes:** 04-STATUS.md 2.5
**Opens:** a prerequisite for P5 (probe network) — see "What must happen before
enrolling anyone"

---

## Context

Every work manifest carries decoy targets. A canary is issued to exactly one
slot, so a canary reported blocked while other slots reach the same host
identifies that slot as hostile — attribution becomes exact rather than
statistical.

`makeCanary()` returned one of three hardcoded well-known domains. A censor who
enrolled twice saw the same three hosts and identified the mechanism
immediately. After that the detector is worse than absent: the attacker answers
truthfully about decoys, falsely about real nodes, and the system certifies them
as trustworthy while they burn the fleet.

## Decision

### Two pools

**Operator pool** (KV `canary_pool`, set via `POST /admin/canary-pool`) — the
real answer. Decoy hosts the operator runs on the same providers and ASNs as
the real fleet, serving an ordinary website and no proxy. Not separable from
real nodes by address, ASN, or TLS shape, because in every respect except
purpose they are the same kind of machine.

**Builtin pool** (`canary-pool.js`, 246 hosts, generated) — a bootstrap so the
mechanism functions on day one. Selection rules are enforced by
`tools/build-canary-pool.mjs` and re-checked in tests: real and long-lived, not
circumvention-adjacent, not political or inflammatory, plausibly TCP-reachable
from Iran.

The pools are unioned rather than one replacing the other, so an operator with
a handful of decoys still gets a pool large enough that canaries do not repeat.

### Honest statement of the builtin pool's limit

Real Tier-D targets are registered by IP on VPS ASNs. Builtin canaries are
third-party domains on academic, CDN, and hosting ASNs. **An attentive
adversary can separate them by shape.** This is a documented limit, not a claim
of equivalence. `poolHealth()` reports it, `/admin/verdicts` surfaces it, and
the warning text says so in words rather than as a status code.

### ASN alignment yields when the aligned subpool is small

Canaries are preferentially drawn from entries whose `asn_group` matches the
real targets in the same manifest — but only when at least 24 such entries
exist. Below that, the whole pool is one bucket.

This threshold exists because the first implementation did not have it, and the
test caught what the reasoning missed: with a three-host operator pool,
preferring aligned entries meant every manifest drew from the same three hosts.
That is defect 2.5 again in a better disguise. Repetition across issuances is
the primary failure; ASN alignment is the refinement. When they conflict,
alignment loses.

### A canary down-report scores only when corroborated

The original detector added suspicion whenever a slot reported a canary
unreachable. **That runs backwards under the conditions this system operates
in.** Whether any given host is reachable from inside Iran is a judgement, not
a measurement. If a pool host turns out to be blocked in country, every honest
probe reports it down and is accused, while the censor — who knows which hosts
are blocked — reports it up and looks clean.

Suspicion is now credited only when another slot independently reached the same
host in the same window. The corroboration read comes from KV and may be stale,
which can only ever **under**-credit suspicion. That is the correct direction to
fail: a false positive here is a real person, under a government that imprisons
them, quietly losing access to the good nodes. Demote, never ban (I3) governs
the outcome; this governs how likely a wrong demotion is in the first place.

## Consequences

- Detection is slower. A hostile slot must lie about a host that someone else
  has already reached. Over a probe network of any size this is a delay, not a
  gap.
- The builtin pool needs periodic regeneration as hosts die.
  `node tools/build-canary-pool.mjs`; the generator enforces the selection
  rules and fails rather than emitting a bad list.
- One extra KV read and write per canary result.

## What must happen before enrolling anyone (P5 prerequisite)

1. **Populate the operator pool.** Until then, decoys are separable from real
   nodes by shape and the detector can be gamed by a sufficiently careful
   adversary. `/admin/verdicts` warns while this is true.
2. **Validate builtin reachability from inside Iran** using the first honest
   probes, before any of their reports are allowed to score. A host that no slot
   ever reaches should be dropped from the pool, not left to accuse people.

## Verification

`test/canary.test.mjs` — 29 checks: pool size and uniqueness, sampling without
replacement, 100 manifests drawing 138 distinct hosts where the old
implementation could produce 3, the alignment-yields regression, operator input
validation, and a check that no host in the pool would incriminate the
volunteer whose phone the target list sits on.

`test/collector.test.mjs` — the same behaviour through the real worker in
workerd, including that decoys are shaped identically to real targets and that
no `node_id` reaches a probe.

# ADR-0004 — VOPRF key epochs

**Status:** accepted (decided by the project lead), implemented
**Closes:** 04-STATUS.md 2.6
**Raises:** 04-STATUS.md 2.17, which is critical and open — read it before
believing anything in here about anonymity.

---

## Context

Spend records carried a flat 30-day TTL. A token held longer than that and then
presented was accepted again, because the record proving it had been spent was
gone. Not the parallel-redemption attack — that is closed by ADR-0001 — but a
replay path bounded only by patience.

The three ways out were: keep spend records forever and accept unbounded
storage growth; put an expiry inside the token; or bound token validity by a key
epoch. Storage that only grows is a cost problem that becomes an availability
problem, and a per-token expiry partitions the anonymity set more finely than an
epoch does, which is the wrong direction.

## Decision

Issuance happens under a key derived for the current epoch. The server accepts
the current epoch and its immediate predecessor, and refuses anything older.

```
epoch      = floor(now / EPOCH_LENGTH_S)          EPOCH_LENGTH_S = 30 days
key(e)     = reduce( SHA512( CTX ‖ 0x05 ‖ master ‖ "epoch:e" ) )  mod L
spend key  = spent:<epoch>:<peppered hash of token>
spend TTL  = 2 epochs + 7 days
```

A token is refused on its own terms once its epoch retires, so the spend record
only has to outlive two epochs and can then be dropped safely. Records are
namespaced by epoch so a retired epoch's rows can be discarded wholesale.

### The anonymity cost, stated plainly

The epoch travels with the token and is visible at redemption. The anonymity set
is therefore partitioned by issuance period rather than being global: with a
30-day epoch the server learns "issued this month or last month" and nothing
finer. This is the standard Privacy Pass trade, and it is a real cost — a
shorter epoch means a smaller crowd to hide in. **Do not shorten
`EPOCH_LENGTH_S` for operational convenience.** If storage pressure ever argues
for it, the answer is more shards, not a smaller crowd.

### Derivation instead of rotation

Epoch keys derive from one master secret rather than being generated and
swapped by hand. A rotation ceremony that has to happen on a schedule is a
ceremony that stops happening, and a missed rotation here fails silently — the
operator would see nothing wrong until tokens started being refused.

The cost: compromise of `VOPRF_MASTER` yields every epoch, past and future,
where independently generated keys plus secure deletion of retired ones would
have protected the past. Secure deletion is the part operators do not actually
do, so this trades a property that holds on paper for one that holds in
practice. It is a trade, not a free win, and 03-SECURITY.md §4 records it.

`VOPRF_SK` is renamed `VOPRF_MASTER`, because a name that says "the secret key"
for something that is never used as a key directly is how the next person
misuses it.

## Consequences

- `/api/issue` returns `epoch` and `epoch_length_s`. `/api/credentials` requires
  `token.e`. There is no client yet, so the wire change is free now and would
  not have been after P2.
- Rotation is automatic and needs no operator action. 02-RUNBOOK.md says so.
- A client must keep the epoch alongside each token. Losing it makes the token
  unusable, so it belongs in the same record, not alongside it.

## Verification

`test/distributor.test.mjs`, against the real Worker in workerd. Tokens for
non-current epochs are minted locally under the derived key, which is the only
way to test the boundary without waiting a month:

```
key epochs — validity is bounded by the epoch, not by the spend log
  ✓ a token from the PREVIOUS epoch is still accepted — rotation is not a cliff
  ✓ a token two epochs old is refused on its own terms, spend record or not
  ✓ a token claiming a future epoch is refused
  ✓ lying about which epoch a token came from fails verification
  ✓ a token with no epoch is refused
  ✓ a non-integer epoch is refused
  ✓ and the same token under its real epoch is accepted
```

**Not verified:** an actual epoch rollover in wall-clock time. The boundary is
tested by constructing tokens either side of it, not by living through one.

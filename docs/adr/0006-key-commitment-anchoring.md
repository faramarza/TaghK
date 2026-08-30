# ADR-0006 — Anchoring the issuer public key

**Status:** accepted, implemented
**Closes:** 04-STATUS.md 2.17 (critical)
**Corrects:** 03-SECURITY.md §2.3, which asserted a guarantee the code did not
provide
**Depends on:** P7 for the last part of the guarantee — see "What is still not
solved"

---

## Context

The client verified the batched Chaum–Pedersen proof against the public key
**that arrived in the same response as the proof**.

That check proves the server used *some* key consistently. It does not prove it
used *everyone's* key. A malicious or compromised distributor picks a distinct
`k_user` per client, evaluates under it, and produces a perfectly valid proof
with respect to `Y_user = G·k_user`. `verifyBatch()` returns true. At redemption
the server tries each stored key until one verifies, and has identified that
user exactly.

This is precisely the attack the proof exists to prevent. It was described
correctly at the top of `voprf.js` and asserted in 03-SECURITY.md §2.3 — "the
server must demonstrate it used the one *advertised* public key" — and the word
doing the work is *advertised*. A value handed over in the same breath is not
advertised, it is asserted.

Invariant I2 was therefore **verified but not anchored**: `unblind()` correctly
threw on a tampered proof, which is worth having, but the deployment provided no
anti-tagging guarantee at all.

The only reason nothing was exploited is that there is no client yet. The single
existing consumer was a test that *did* pin — it compared against
`epochPublicKey(master, epoch)` because it had generated the master. A real
client cannot do that.

## Decision

The operator publishes a **key commitment**: a document naming the VOPRF public
key for each epoch, signed with a long-term Ed25519 key that clients pin at
build time.

```
{ "v":1, "serial":N, "prev":"<sha256 of the previous document>",
  "issued_at":…, "not_after":…, "keys": { "<epoch>": "<public key>", … } }
```

`unblind()` now performs two checks, both mandatory, both fatal, in this order:

1. **Anchor** — the commitment verifies under the pinned key, is current, is not
   a rollback, and names a key for this epoch; and the issuer key the server
   sent equals that key.
2. **DLEQ** — the server actually evaluated under it.

### The load-bearing decision: where the signing key lives

**`COMMITMENT_SK` never touches the Worker.** It is generated offline, kept
offline, and used offline by `tools/mint-commitment.mjs` to produce a document
that is uploaded as an opaque blob. The Worker serves bytes it cannot produce.

This is the whole ADR. Two very different security claims turn on it:

| | |
|---|---|
| If the Worker signed on demand | A compromised Worker mints a per-user commitment. Tagging still works. The signature is decoration. |
| Because the Worker cannot sign | A compromised Worker **cannot tag**. It can refuse service, serve stale keys, or serve garbage a client rejects — but it cannot make a client accept a key the offline holder never committed to. |

"Malicious server (us, compromised)" is a named adversary in 03-SECURITY.md §1.
Until now nothing actually answered it.

### There is no unanchored mode

`unblind()` requires the anchor and throws without one. A client built with no
pinned key throws rather than falling back to trusting the server, because that
fallback *is* the vulnerability.

This is deliberate API design, not defensiveness. An optional anchor is an
anchor that gets skipped under deadline, and the resulting client looks
identical to a correct one while protecting nobody. The unsafe path must not be
reachable by omission.

### Issuance fails closed outside a commitment

`/api/issue` returns 503 when no published commitment covers the current epoch.
Tokens issued outside one are tokens a correct client must discard, so issuing
them helps nobody and disguises an operator error as client-side tampering.

The cost is real and falls on the operator: forget to re-mint and enrolment
stops. Mitigated by minting several epochs ahead (90 days at the default), and
by `/admin/stats` reporting `key_commitment.issuing` and `epochs_of_headroom`.

## What is still not solved

Stated separately because it is a **weaker** property than the one above.

An operator holding `COMMITMENT_SK` can sign a commitment naming a per-user key
and serve it to one client. Signing prevents a compromised *server* from
equivocating; it cannot prevent the *key holder* from equivocating, and nothing
cryptographic can, because the key holder is by definition authorised.

The design makes equivocation leave evidence instead:

- monotonic `serial` plus the predecessor's hash, so the published history is a
  chain;
- clients refuse a serial below the highest accepted, so a targeted document
  cannot be a silent rollback;
- the document is byte-identical for everyone and served from a stable public
  location, intended to be mirrored outside the operator's control, so two
  clients comparing what they received detect a split.

That is the certificate-transparency posture: **detection, not prevention.** It
closes only with reproducible signed client builds (P7) and an independent
mirror, which makes **P7 a dependency of the anonymity claim rather than a trust
nicety**. Until both exist, the honest claim is:

> A compromised server cannot tag. A malicious operator can — but not invisibly,
> and not to a client that has already seen a later commitment.

## Consequences

- `unblind()` is now async (Ed25519 verification is async in WebCrypto) and its
  signature gained a required `anchor`. No client exists, so the cost is zero
  now and would not have been after P2.
- Tokens carry their `epoch` and the `commitment_serial` they were anchored
  against. The client must persist the highest serial it has seen and pass it as
  `minSerial`, or rollback protection does nothing.
- P2 must ship `COMMITMENT_PK` **in the build**, not in configuration and not
  fetched at runtime. A pinned key that arrives over the network is not pinned.
- 03-SECURITY.md §2.3 is corrected in place, with the previous wording quoted so
  the error is on the record rather than edited away.

## Verification

`test/anchor.test.mjs` — 24 checks. The centrepiece builds a working attacker:

```
the tagging attack, mounted
  ✓ the attacker issues under a key that is not the operator's
  ✓ the DLEQ proof is VALID under the attacker's own key
        this is why verifying the proof alone proves nothing about anonymity
  ✓ the anchored client refuses it — the key is not in the operator commitment
  ✓ a commitment signed by anyone but the pinned operator key is refused
```

Plus rollback, expiry, wrong epoch, unsigned, unanchored, and a check that the
published document contains no secret material.

`test/distributor.test.mjs` runs it against the real Worker: issuance 503s
before a commitment is uploaded, `/api/keys` serves the blob byte-for-byte, a
stale serial is refused with 409, and a rogue issuer key with a valid proof is
rejected by the anchored client.

`test/integration/plane3.py` proves anchoring is **live rather than merely
present** — the same client, built with a wrong pinned key and then with no
pinned key, refuses an issuance the honest client accepts. Without that pair a
skipped anchor would look identical to a working one.

#!/usr/bin/env node
/**
 * anchor.test.mjs — 04-STATUS.md 2.17: the issuer key must be anchored.
 *
 * The centrepiece is `the tagging attack, mounted`. It builds a malicious
 * issuer that uses a DIFFERENT SECRET KEY FOR ONE USER and produces a
 * completely valid DLEQ proof under that key — then shows that the old check
 * accepts it and the anchored check does not.
 *
 * A test that only confirms the good path would not have caught this. The bug
 * was that a correct-looking verification verified the wrong thing.
 *
 *   node test/anchor.test.mjs
 */
import { section, check, eq, throws, summary } from './harness.mjs';
import {
  blind, unblind, issue, verifyBatch, generateMaster, generateKey,
  currentEpoch, epochPublicKey, deriveEpochKey, EPOCH_LENGTH_S,
} from '../voprf.js';
import { buildCommitment, commitmentHash, anchorEpochKey, NULL_PREV,
         EPOCH_SECONDS_FOR_BOUNDS, crossCheckCommitment, requireAgreement } from '../commitment.js';
import { commitmentKeypair, sign, mint, anchorFor } from './anchor-helper.mjs';

const master = generateMaster();
const EPOCH = currentEpoch();
const operator = commitmentKeypair();
const commitment = await mint({ master, pkcs8: operator.pkcs8, span: 2, serial: 4 });

const honestIssue = (items) =>
  issue(deriveEpochKey(master, EPOCH), items.map((i) => i.blinded));

section('the honest path');

{
  const items = blind(4);
  const res = honestIssue(items);
  const tokens = await unblind(items, res.evaluated, res.proof, res.public_key,
    anchorFor(EPOCH, commitment, operator.pinnedKey));
  eq(tokens.length, 4, 'an anchored issuance unblinds');
  eq(tokens[0].epoch, EPOCH, 'tokens carry their epoch');
  eq(tokens[0].commitment_serial, 4, 'tokens carry the commitment serial for rollback protection');
}

section('the tagging attack, mounted');

{
  // A malicious distributor. It has its own secret key, uses it for THIS user
  // only, and proves DLEQ honestly with respect to it. Everything it produces
  // is internally consistent; that is the point.
  const attacker = generateKey();
  const items = blind(4);
  const evil = issue(attacker.secret, items.map((i) => i.blinded));

  check(evil.public_key !== epochPublicKey(master, EPOCH),
    'the attacker issues under a key that is not the operator’s');

  check(verifyBatch(evil.public_key, items.map((i) => i.blinded), evil.evaluated, evil.proof),
    'the DLEQ proof is VALID under the attacker’s own key',
    'this is why verifying the proof alone proves nothing about anonymity');

  await throws(() => unblind(items, evil.evaluated, evil.proof, evil.public_key,
    anchorFor(EPOCH, commitment, operator.pinnedKey)),
    'the anchored client refuses it — the key is not in the operator commitment');

  // The subtler version: the attacker also forges a commitment naming its key.
  // Without the pinned signing key it cannot sign one that verifies.
  const forgedKeys = { [String(EPOCH)]: evil.public_key };
  const forgedDoc = buildCommitment({
    serial: 99, prev: NULL_PREV, keys: forgedKeys,
    issuedAt: Math.floor(Date.now() / 1000), notAfter: (EPOCH + 2) * EPOCH_LENGTH_S,
  });
  const attackerKeys = commitmentKeypair();
  const forged = { doc: forgedDoc, signature: await sign(forgedDoc, attackerKeys.pkcs8) };

  await throws(() => unblind(items, evil.evaluated, evil.proof, evil.public_key,
    anchorFor(EPOCH, forged, operator.pinnedKey)),
    'a commitment signed by anyone but the pinned operator key is refused');

  check(true, 'a compromised Worker cannot mount this at all',
    'COMMITMENT_SK is offline — it can serve a forged blob, and no client will take it');
}

section('the unanchored path does not exist');

await throws(() => unblind(blind(2), [], { e: '', s: '' }, 'x'),
  'unblind() with no anchor throws rather than falling back');
await throws(async () => {
  const items = blind(2);
  const res = honestIssue(items);
  return unblind(items, res.evaluated, res.proof, res.public_key,
    { epoch: EPOCH, doc: commitment.doc, signature: commitment.signature, pinnedKey: '' });
}, 'a client built with no pinned key refuses rather than trusting the server');

section('commitment validation');

// Server-supplied bytes and client-held trust are separate arguments; these
// helpers keep the test honest about which side each tampering happens on.
const served = (over = {}) => ({ doc: commitment.doc, signature: commitment.signature, ...over });
const trust = (over = {}) => ({ pinnedKey: operator.pinnedKey, minSerial: 0, ...over });

await throws(() => anchorEpochKey(EPOCH, served({ doc: commitment.doc + ' ' }), trust()),
  'a modified document fails the signature');
await throws(() => anchorEpochKey(EPOCH, served({ signature: 'AAAA' }), trust()),
  'a malformed signature is refused');
await throws(() => anchorEpochKey(EPOCH, served({ doc: '' }), trust()),
  'an empty document is refused');
await throws(() => anchorEpochKey(EPOCH + 5, served(), trust()),
  'an epoch outside the client’s own clock is refused');
await throws(() => anchorEpochKey(EPOCH, served(), trust({ minSerial: 5 })),
  'a serial older than one already seen is refused — no silent rollback');
await throws(() => anchorEpochKey(EPOCH, served(), trust({ now: (EPOCH + 9) * EPOCH_LENGTH_S * 1000 })),
  'an expired commitment is refused');
await throws(() => anchorEpochKey(EPOCH, served(), trust({ pinnedKey: undefined })),
  'a missing pinned key is refused rather than defaulted');

{
  const r = await anchorEpochKey(EPOCH, served(), trust({ minSerial: 4 }));
  eq(r.publicKey, epochPublicKey(master, EPOCH), 'the committed key is the derived epoch key');
  eq(r.serial, 4, 'the serial is returned so the client can raise its floor');
}

section('the trust boundary cannot be collapsed');

{
  // The failure this shape exists to prevent: a client that merges the server
  // response into its own options. If both halves shared one object, a response
  // carrying `minSerial` or `now` would silently disable rollback protection
  // and expiry. Here the server's fields land in `served` and are ignored.
  const hostileResponse = {
    doc: commitment.doc, signature: commitment.signature,
    minSerial: 0, now: (EPOCH + 9) * EPOCH_LENGTH_S * 1000, pinnedKey: 'AAAA',
  };
  await throws(() => anchorEpochKey(EPOCH, hostileResponse, trust({ minSerial: 5 })),
    'server-supplied minSerial cannot lower the client’s rollback floor');
  const r = await anchorEpochKey(EPOCH, hostileResponse, trust());
  eq(r.serial, 4, 'and server-supplied now/pinnedKey are simply not read');
}

eq(EPOCH_SECONDS_FOR_BOUNDS, EPOCH_LENGTH_S,
  'commitment.js and voprf.js agree on the epoch length');

section('the published history is a chain');

{
  const next = await mint({ master, pkcs8: operator.pkcs8, span: 2, serial: 5, prevDoc: commitment.doc });
  const parsed = JSON.parse(next.doc);
  eq(parsed.prev, await commitmentHash(commitment.doc),
    'each document names the hash of its predecessor');
  check(parsed.serial > JSON.parse(commitment.doc).serial, 'serials increase');

  const r = await anchorEpochKey(EPOCH, { doc: next.doc, signature: next.signature },
    trust({ minSerial: 4 }));
  eq(r.serial, 5, 'a newer commitment is accepted over the floor');
  await throws(() => anchorEpochKey(EPOCH, served(), trust({ minSerial: 5 })),
    'and the older one is then refused — equivocation cannot be a quiet downgrade');
}

section('no secret material in what is published');

{
  const doc = JSON.parse(commitment.doc);
  const flat = JSON.stringify(doc);
  check(!flat.includes(master), 'the commitment does not contain the VOPRF master');
  check(!flat.includes(deriveEpochKey(master, EPOCH)), 'nor any epoch secret key');
  check(Object.values(doc.keys).every((k) => /^[0-9a-f]{64}$/.test(k)), 'only public points are published');
}

section('cross-checking against independent copies (2.18)');

{
  const mirror = { doc: commitment.doc, signature: commitment.signature, source: 'mirror-a' };
  const agreed = await crossCheckCommitment(commitment, [mirror]);
  eq(agreed.equivocation, null, 'identical copies agree');
  eq(agreed.compared, 1, 'the comparison actually happened');

  // The operator signs a second document at the SAME serial for one client.
  // Signing cannot prevent this; comparison makes it visible.
  const targeted = await mint({
    master, pkcs8: operator.pkcs8, span: 2, serial: 4,
    keys: { [String(EPOCH)]: generateKey().public },
  });
  const split = await crossCheckCommitment(commitment,
    [{ ...targeted, source: 'mirror-a' }]);
  check(split.equivocation !== null,
    'two different documents at one serial are detected as equivocation',
    `serial ${split.equivocation?.serial}`);
  check(split.equivocation.primary_hash !== split.equivocation.mirror_hash,
    'and the two hashes are reported so it can be published');

  await throws(() => requireAgreement(commitment, [{ ...targeted, source: 'mirror-a' }]),
    'requireAgreement() fails closed on equivocation');

  // A mirror that is merely ahead is lag, not an attack — but it raises the
  // floor, so a rolled-back primary then fails the rollback check.
  const newer = await mint({ master, pkcs8: operator.pkcs8, span: 2, serial: 9,
                             prevDoc: commitment.doc });
  const floor = await requireAgreement(commitment, [{ ...newer, source: 'mirror-a' }]);
  eq(floor, 9, 'a mirror ahead of the server raises the client’s serial floor');
  await throws(() => anchorEpochKey(EPOCH, served(), trust({ minSerial: floor })),
    'so the older document the server offered is then refused');

  const offline = await requireAgreement(commitment, []);
  eq(offline, 4, 'an unreachable mirror is not treated as an attack');
}

summary();

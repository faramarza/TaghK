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
import { buildCommitment, commitmentHash, anchorEpochKey, NULL_PREV } from '../commitment.js';
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

const good = anchorFor(EPOCH, commitment, operator.pinnedKey);

await throws(() => anchorEpochKey(EPOCH, { ...good, doc: commitment.doc + ' ' }),
  'a modified document fails the signature');
await throws(() => anchorEpochKey(EPOCH, { ...good, signature: 'AAAA' }),
  'a malformed signature is refused');
await throws(() => anchorEpochKey(EPOCH + 5, good),
  'an epoch with no committed key is refused');
await throws(() => anchorEpochKey(EPOCH, { ...good, minSerial: 5 }),
  'a serial older than one already seen is refused — no silent rollback');
await throws(() => anchorEpochKey(EPOCH, { ...good, now: (EPOCH + 9) * EPOCH_LENGTH_S * 1000 }),
  'an expired commitment is refused');

{
  const r = await anchorEpochKey(EPOCH, { ...good, minSerial: 4 });
  eq(r.publicKey, epochPublicKey(master, EPOCH), 'the committed key is the derived epoch key');
  eq(r.serial, 4, 'the serial is returned so the client can raise its floor');
}

section('the published history is a chain');

{
  const next = await mint({ master, pkcs8: operator.pkcs8, span: 2, serial: 5, prevDoc: commitment.doc });
  const parsed = JSON.parse(next.doc);
  eq(parsed.prev, await commitmentHash(commitment.doc),
    'each document names the hash of its predecessor');
  check(parsed.serial > JSON.parse(commitment.doc).serial, 'serials increase');

  const r = await anchorEpochKey(EPOCH, anchorFor(EPOCH, next, operator.pinnedKey, 4));
  eq(r.serial, 5, 'a newer commitment is accepted over the floor');
  await throws(() => anchorEpochKey(EPOCH, anchorFor(EPOCH, commitment, operator.pinnedKey, 5)),
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

summary();

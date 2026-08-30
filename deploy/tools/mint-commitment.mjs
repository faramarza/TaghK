#!/usr/bin/env node
/**
 * mint-commitment.mjs — OFFLINE. Run this on a machine that is not the server.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Mints and signs the key commitment that clients anchor against.
 *
 *   COMMITMENT_SK AND VOPRF_MASTER MUST NEVER BE PRESENT ON THE WORKER
 *   AT THE SAME TIME AS THIS SCRIPT RUNS ANYWHERE NEAR IT.
 *
 * VOPRF_MASTER is on the Worker because it has to be — issuance needs it. The
 * point of this script is that COMMITMENT_SK is NOT, so a compromised Worker
 * can misbehave in every way except the one that de-anonymises people: it
 * cannot mint a commitment for a key the offline holder did not commit to, so
 * a client will not accept one. See commitment.js.
 *
 * Usage:
 *   node tools/mint-commitment.mjs --keygen
 *       Generate the long-term commitment keypair. Do this ONCE, offline, and
 *       pin the printed public key into every client build.
 *
 *   VOPRF_MASTER=... COMMITMENT_SK=... \
 *   node tools/mint-commitment.mjs --epochs 3 [--prev-doc previous.json]
 *       Emit {doc, signature} covering the current epoch and the next N-1.
 *       Upload with:  POST /admin/commitment
 *
 * Cover several epochs ahead. The distributor REFUSES TO ISSUE when no valid
 * commitment covers the current epoch — correctly, because tokens issued
 * outside a commitment are tokens the client must reject anyway — so an
 * operator who forgets to re-mint takes the service down. Minting three epochs
 * ahead buys ninety days of slack; the runbook says do it quarterly.
 */
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { currentEpoch, epochPublicKey, EPOCH_LENGTH_S, generateMaster } from '../voprf.js';
import { buildCommitment, commitmentHash, NULL_PREV } from '../commitment.js';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};

if (args.includes('--keygen')) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  console.log('COMMITMENT_SK  (SECRET — keep offline, never put on the Worker):');
  console.log(privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'));
  console.log('\nCOMMITMENT_PK  (pin into every client build, publish widely):');
  console.log(publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64'));
  console.log('\nAlso generate the VOPRF master if you have not:');
  console.log(`VOPRF_MASTER   ${generateMaster()}`);
  console.log('\nThese two secrets live in different places. That separation is the');
  console.log('whole security property — do not store them together.');
  process.exit(0);
}

const master = process.env.VOPRF_MASTER;
const skB64 = process.env.COMMITMENT_SK;
if (!master || !skB64) {
  console.error('VOPRF_MASTER and COMMITMENT_SK must both be set. Run with --keygen first.');
  process.exit(1);
}

const span = Number(flag('--epochs', '3'));
if (!Number.isInteger(span) || span < 1 || span > 24) {
  console.error('--epochs must be between 1 and 24');
  process.exit(1);
}

// Chain to the previous document so the published history is verifiable and a
// silent rollback is detectable.
let serial = 0;
let prev = NULL_PREV;
const prevPath = flag('--prev-doc');
if (prevPath) {
  const previous = JSON.parse(readFileSync(prevPath, 'utf8'));
  serial = JSON.parse(previous.doc).serial + 1;
  prev = await commitmentHash(previous.doc);
}

const start = currentEpoch();
const keys = {};
for (let i = 0; i < span; i++) keys[String(start + i)] = epochPublicKey(master, start + i);

const issuedAt = Math.floor(Date.now() / 1000);
// Expires when the last covered epoch does, so an expired commitment and an
// uncovered epoch are the same event rather than two ways to fail.
const notAfter = (start + span) * EPOCH_LENGTH_S;

const doc = buildCommitment({ serial, prev, keys, issuedAt, notAfter });
const key = await webcrypto.subtle.importKey(
  'pkcs8', Buffer.from(skB64, 'base64'), { name: 'Ed25519' }, false, ['sign']);
const signature = Buffer.from(
  await webcrypto.subtle.sign('Ed25519', key, new TextEncoder().encode(doc))).toString('base64');

console.log(JSON.stringify({ doc, signature }, null, 2));
console.error(`\n[mint] serial ${serial}, epochs ${start}..${start + span - 1}, ` +
              `expires ${new Date(notAfter * 1000).toISOString()}`);
console.error('[mint] upload:  curl -X POST .../admin/commitment -H "x-admin-key: $ADMIN_KEY" -d @-');

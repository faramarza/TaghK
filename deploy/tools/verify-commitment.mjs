#!/usr/bin/env node
/**
 * verify-commitment.mjs — anyone can run this. That is the point.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The anti-tagging guarantee rests on every client receiving the SAME key
 * commitment. A compromised server cannot forge one — the signing key is
 * offline — but the operator holding that key could sign a second, targeted
 * document and hand it to one person. Nothing cryptographic prevents that.
 *
 * What prevents it going unnoticed is people checking. This tool is the
 * checking: fetch the commitment from wherever you can reach it, verify it
 * against the published operator key, print its hash and serial, and compare
 * copies from independent sources.
 *
 * If two sources publish DIFFERENT BYTES AT THE SAME SERIAL, the operator has
 * equivocated. Say so publicly.
 *
 *   node tools/verify-commitment.mjs --key <COMMITMENT_PK> \
 *        https://dist.example/api/keys https://mirror.example/keys.json
 *
 *   node tools/verify-commitment.mjs --key <COMMITMENT_PK> ./commitment.json
 *
 * Exit codes:  0 agreement   1 verification failed   2 EQUIVOCATION DETECTED
 */
import { readFileSync } from 'node:fs';
import { anchorEpochKey, commitmentHash, crossCheckCommitment } from '../commitment.js';
import { currentEpoch } from '../voprf.js';

const args = process.argv.slice(2);
const keyIndex = args.indexOf('--key');
const pinnedKey = keyIndex >= 0 ? args[keyIndex + 1] : process.env.COMMITMENT_PK;
const sources = args.filter((a, i) => a !== '--key' && i !== keyIndex + 1 && !a.startsWith('--'));

if (!pinnedKey || !sources.length) {
  console.error('usage: verify-commitment.mjs --key <COMMITMENT_PK> <url-or-file> [more sources…]');
  console.error('\nThe key should come from the published release, not from the server you');
  console.error('are checking. Verifying a document against a key the same party gave you');
  console.error('proves nothing.');
  process.exit(1);
}

async function load(source) {
  if (/^https?:\/\//.test(source)) {
    const r = await fetch(source);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return { ...(await r.json()), source };
  }
  return { ...JSON.parse(readFileSync(source, 'utf8')), source };
}

const fetched = [];
for (const source of sources) {
  try {
    fetched.push(await load(source));
  } catch (e) {
    // An unreachable source is not an attack. A censor can block a mirror, and
    // treating that as a failure would hand them an off switch.
    console.log(`  ?  ${source}\n     unreachable: ${e.message}`);
  }
}

if (!fetched.length) {
  console.error('no source could be read');
  process.exit(1);
}

let failed = false;
const epoch = currentEpoch();

for (const record of fetched) {
  const hash = await commitmentHash(record.doc);
  let parsed;
  try { parsed = JSON.parse(record.doc); } catch { parsed = {}; }
  try {
    const { publicKey } = await anchorEpochKey(epoch, record, { pinnedKey });
    console.log(`  ok ${record.source}`);
    console.log(`     serial ${parsed.serial}  sha256 ${hash}`);
    console.log(`     epochs ${Object.keys(parsed.keys ?? {}).join(', ')}`);
    console.log(`     key for epoch ${epoch}: ${publicKey}`);
    console.log(`     expires ${new Date((parsed.not_after ?? 0) * 1000).toISOString()}`);
  } catch (e) {
    failed = true;
    console.log(`  XX ${record.source}`);
    console.log(`     serial ${parsed.serial}  sha256 ${hash}`);
    console.log(`     ${e.message}`);
  }
}

if (fetched.length > 1) {
  const [primary, ...mirrors] = fetched;
  const result = await crossCheckCommitment(primary, mirrors);
  console.log(`\ncompared ${result.compared} independent copies`);
  if (result.equivocation) {
    console.log('\n  *** EQUIVOCATION DETECTED ***');
    console.log(`  serial ${result.equivocation.serial} was published as two different documents:`);
    console.log(`    ${primary.source}: ${result.equivocation.primary_hash}`);
    console.log(`    ${result.equivocation.source}: ${result.equivocation.mirror_hash}`);
    console.log('\n  The operator is handing different keys to different people.');
    console.log('  This is the attack the commitment exists to make visible. Report it publicly.');
    process.exit(2);
  }
  console.log('  all copies at the same serial are byte-identical');
}

process.exit(failed ? 1 : 0);

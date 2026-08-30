#!/usr/bin/env node
/**
 * client.mjs — the reference client, driven from the command line.
 *
 * Stands in for the Android app that does not exist yet (04-STATUS.md 3.1).
 * It performs the real user flow against a real distributor: challenge,
 * proof of work, enclave-style keypair, blinded issuance, MANDATORY DLEQ
 * verification, unblind, redemption, and subscription polling.
 *
 * Usage:
 *   node client.mjs enrol <base>                 -> {lineage, lineage_proof, ...}
 *   node client.mjs poll  <base> <lineage> <sk>  -> decoded subscription URIs
 *
 * The device keypair is exported and passed back in so a later poll can sign
 * as the same device. A real client keeps it non-extractable in StrongBox and
 * can never do this; here it is the only way to survive process boundaries, and
 * it is a property of the test harness, not of the design.
 */
import { createHash, webcrypto } from 'node:crypto';
import { blind, unblind } from '../../voprf.js';

const [cmd, base, ...rest] = process.argv.slice(2);
const b64 = (b) => Buffer.from(b).toString('base64');

function solvePow(challenge, bits) {
  for (let i = 0; ; i++) {
    const d = createHash('sha256').update(challenge + i).digest();
    let zeros = 0;
    for (const byte of d) {
      if (byte === 0) { zeros += 8; continue; }
      zeros += Math.clz32(byte) - 24;
      break;
    }
    if (zeros >= bits) return String(i);
  }
}

const post = (path, body, headers = {}) =>
  fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });

if (cmd === 'enrol') {
  const kp = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = b64(await webcrypto.subtle.exportKey('spki', kp.publicKey));
  const pkcs8 = b64(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey));
  const sign = async (m) => b64(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(m)));

  const ch = await (await fetch(`${base}/api/challenge`)).json();
  const items = blind(4);
  const res = await post('/api/issue', {
    challenge: ch.challenge, nonce: solvePow(ch.challenge, ch.bits),
    blinded: items.map((i) => i.blinded), device_pubkey: spki, device_sig: await sign(ch.challenge),
  });
  if (res.status !== 200) { console.error(`issue failed: ${res.status}`); process.exit(1); }
  const out = await res.json();

  // Throws rather than degrading if the server used a per-user key (I2).
  const tokens = unblind(items, out.evaluated, out.proof, out.public_key);

  const cred = await post('/api/credentials', {
    token: { t: tokens[0].token, w: tokens[0].witness }, device_pubkey: spki,
  });
  if (cred.status !== 200) { console.error(`credentials failed: ${cred.status}`); process.exit(1); }
  const c = await cred.json();
  console.log(JSON.stringify({ ...c, device_sk: pkcs8, device_pk: spki }));
} else if (cmd === 'poll') {
  const [lineage, sk] = rest;
  const key = await webcrypto.subtle.importKey('pkcs8', Buffer.from(sk, 'base64'),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const ts = Date.now();
  const sig = b64(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key,
    new TextEncoder().encode(`${lineage}:${ts}`)));
  const r = await fetch(`${base}/sub/${lineage}`, {
    headers: { 'x-device-ts': String(ts), 'x-device-sig': sig },
  });
  if (r.status !== 200) { console.error(`poll failed: ${r.status}`); process.exit(1); }
  console.log(Buffer.from(await r.text(), 'base64').toString('utf8'));
} else {
  console.error('usage: client.mjs enrol <base> | poll <base> <lineage> <device_sk>');
  process.exit(1);
}

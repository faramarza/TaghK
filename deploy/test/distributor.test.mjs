#!/usr/bin/env node
/**
 * distributor.test.mjs — the distributor, executed.
 *
 * Runs the REAL worker in the REAL Workers runtime (workerd, via wrangler's
 * local dev server) with real Durable Object bindings, and drives it through
 * the real API: challenge -> proof of work -> device signature -> blinded
 * issuance -> DLEQ verification -> unblind -> redemption -> subscription.
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT
 *
 * It proves the code runs, that exactly-once holds under concurrency against a
 * real Durable Object, and that the failure paths fail closed. It does NOT
 * prove multi-colo behaviour: every request here reaches one runtime instance.
 * Durable Objects guarantee a single instance per ID world-wide, so the
 * property is expected to hold across colos, but that claim is the platform's
 * and remains unverified by us until P1 deploys for real.
 *
 *   node test/distributor.test.mjs
 */
import { unstable_dev } from 'wrangler';
import { createHash, webcrypto } from 'node:crypto';
import { rmSync, readFileSync } from 'node:fs';
import { section, check, eq, throws, summary } from './harness.mjs';
import { blind, unblind, verifyBatch, generateKey } from '../voprf.js';

const ADMIN_KEY = 'a1'.repeat(32);
const PERSIST = `/tmp/tk-dist-${process.pid}`;

const b64 = (buf) => Buffer.from(buf).toString('base64');

// ── helpers ───────────────────────────────────────────────────────────────

/** Solve the proof of work. Sync SHA-256; crypto.subtle would be 20x slower. */
function solvePow(challenge, bits) {
  for (let i = 0; ; i++) {
    const nonce = String(i);
    const d = createHash('sha256').update(challenge + nonce).digest();
    let zeros = 0;
    for (const byte of d) {
      if (byte === 0) { zeros += 8; continue; }
      zeros += Math.clz32(byte) - 24;
      break;
    }
    if (zeros >= bits) return nonce;
  }
}

async function makeDevice() {
  const kp = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const spki = b64(await webcrypto.subtle.exportKey('spki', kp.publicKey));
  const sign = async (msg) => b64(await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, new TextEncoder().encode(msg)
  ));
  return { spki, sign };
}

// Generated per run, so no key material ever lands in the tree (03-SECURITY §4).
const voprfKey = generateKey();

rmSync(PERSIST, { recursive: true, force: true });
const w = await unstable_dev('distributor-worker.js', {
  config: 'wrangler.toml',
  local: true,
  persistTo: PERSIST,
  vars: { ADMIN_KEY, KEY_SALT: 'b2'.repeat(32), VOPRF_SK: voprfKey.secret },
  experimental: { disableExperimentalWarning: true },
});

const IP = { 'cf-connecting-ip': '10.0.0.1' };
const post = (path, body, headers = {}) =>
  w.fetch(`http://d${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...IP, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

/** Run the whole issuance flow and return unblinded tokens. */
async function getTokens(device, count = 4) {
  const ch = await (await w.fetch('http://d/api/challenge', { headers: IP })).json();
  const nonce = solvePow(ch.challenge, ch.bits);
  const items = blind(count);
  const res = await post('/api/issue', {
    challenge: ch.challenge, nonce,
    blinded: items.map((i) => i.blinded),
    device_pubkey: device.spki,
    device_sig: await device.sign(ch.challenge),
  });
  if (res.status !== 200) throw new Error(`issue failed: ${res.status}`);
  const out = await res.json();
  return { tokens: unblind(items, out.evaluated, out.proof, out.public_key), raw: out, items };
}

try {
  const device = await makeDevice();

  // ── happy path ─────────────────────────────────────────────────────────
  section('issuance — the full real flow through workerd');

  const ch = await w.fetch('http://d/api/challenge', { headers: IP });
  eq(ch.status, 200, 'GET /api/challenge returns 200');
  const chal = await ch.json();
  check(/^p1\.[0-9a-f]{48}\.\d+\.\d+\.[0-9a-f]{32}$/.test(chal.challenge),
    'challenge is stateless and MAC-bound', chal.challenge.slice(0, 40) + '...');
  eq(chal.bits, 18, 'new-account difficulty is 18 bits');

  const t0 = Date.now();
  const first = await getTokens(device, 8);
  check(first.tokens.length === 8, `issued 8 tokens with a verified DLEQ proof`, `${Date.now() - t0}ms incl. PoW`);
  check(first.raw.public_key === voprfKey.public, 'server advertises the expected public key');
  check(verifyBatch(first.raw.public_key, first.items.map((i) => i.blinded), first.raw.evaluated, first.raw.proof),
    'DLEQ proof from the live server verifies independently');

  const seed = await post('/admin/nodes', [
    { id: 'node0001', pool: 'sacrificial', status: 'active', ip: '203.0.113.10',
      users: [{ id: '11111111-1111-1111-1111-111111111111' }],
      tier_d_reality: { port: 443, flow: 'xtls-rprx-vision', dest: 'www.iana.org',
                        public_key: 'PBK', short_ids: ['ab'] } },
  ], { 'x-admin-key': ADMIN_KEY });
  eq(seed.status, 200, 'operator seeds node inventory');

  const cred = await post('/api/credentials', { token: { t: first.tokens[0].token, w: first.tokens[0].witness }, device_pubkey: device.spki });
  eq(cred.status, 200, 'POST /api/credentials redeems a token');
  const credJson = await cred.json();
  check(/^[0-9a-f]{32}$/.test(credJson.lineage), 'a lineage id is returned');

  const ts = Date.now();
  const sub = await w.fetch(`http://d/sub/${credJson.lineage}`, {
    headers: { ...IP, 'x-device-ts': String(ts), 'x-device-sig': await device.sign(`${credJson.lineage}:${ts}`) },
  });
  eq(sub.status, 200, 'subscription serves with a fresh device signature');
  const uris = Buffer.from(await sub.text(), 'base64').toString('utf8');
  check(uris.includes('vless://') && uris.includes('fp=chrome'),
    'subscription contains a REALITY URI with uTLS fingerprinting');

  // ── I-defect-1: exactly-once redemption under concurrency ───────────────
  section('I-defect-1 — exactly-once redemption under concurrency');

  const { tokens } = await getTokens(device, 4);
  const victim = tokens[0];
  const PARALLEL = 32;
  const responses = await Promise.all(Array.from({ length: PARALLEL }, () =>
    post('/api/credentials', { token: { t: victim.token, w: victim.witness }, device_pubkey: device.spki })
  ));
  const codes = responses.map((r) => r.status);
  const ok = codes.filter((c) => c === 200).length;
  eq(ok, 1, `one token fired from ${PARALLEL} parallel requests is accepted exactly once`);
  eq(codes.filter((c) => c === 403).length, PARALLEL - 1, 'every other parallel request is rejected');

  const again = await post('/api/credentials', { token: { t: victim.token, w: victim.witness }, device_pubkey: device.spki });
  eq(again.status, 403, 'sequential replay of a spent token is rejected');

  // ── I-defect-2: the rate limiter actually limits ────────────────────────
  section('I-defect-2 — rate limiter enforces the configured limit');

  const RATE_IP = { 'cf-connecting-ip': '10.0.0.99' };
  const windowBefore = Math.floor(Date.now() / 1000 / 60);
  const burst = await Promise.all(Array.from({ length: 90 }, () =>
    w.fetch('http://d/api/challenge', { headers: RATE_IP })
  ));
  const windowAfter = Math.floor(Date.now() / 1000 / 60);
  const allowed = burst.filter((r) => r.status === 200).length;
  if (windowBefore === windowAfter) {
    eq(allowed, 30, 'a 90-request burst yields exactly RATE_MAX_CHALLENGE=30 successes');
  } else {
    check(allowed <= 60, 'burst stayed within limit (rate window rolled mid-test)', `allowed=${allowed}`);
  }
  check(burst.filter((r) => r.status === 404).length === 90 - allowed,
    'over-limit requests get the standard decoy, not a distinct error');

  // ── adversarial ────────────────────────────────────────────────────────
  section('adversarial — every one of these MUST fail');

  {
    const ch2 = await (await w.fetch('http://d/api/challenge', { headers: IP })).json();
    const n2 = solvePow(ch2.challenge, ch2.bits);
    const items = blind(2);
    const body = {
      challenge: ch2.challenge, nonce: n2, blinded: items.map((i) => i.blinded),
      device_pubkey: device.spki, device_sig: await device.sign(ch2.challenge),
    };
    eq((await post('/api/issue', body)).status, 200, 'a solved challenge is accepted once');
    eq((await post('/api/issue', body)).status, 403, 'the same solved challenge cannot be replayed');

    const parts = ch2.challenge.split('.');
    const forged = [parts[0], parts[1], '1', parts[3], parts[4]].join('.');
    eq((await post('/api/issue', { ...body, challenge: forged, nonce: solvePow(forged, 1) })).status, 403,
      'lowering the difficulty inside the challenge fails the MAC');

    const expired = [parts[0], parts[1], parts[2], '1', parts[4]].join('.');
    eq((await post('/api/issue', { ...body, challenge: expired })).status, 403,
      'rewriting the expiry inside the challenge fails the MAC');
  }

  {
    const { tokens: tt } = await getTokens(device, 2);
    const bad = { t: tt[0].token, w: tt[1].witness };
    eq((await post('/api/credentials', { token: bad, device_pubkey: device.spki })).status, 403,
      'a token presented with a mismatched witness is rejected');
    const tampered = { t: tt[0].token, w: 'f'.repeat(64) };
    eq((await post('/api/credentials', { token: tampered, device_pubkey: device.spki })).status, 403,
      'a forged witness is rejected');
    check((await post('/api/credentials', { token: { t: 'zz', w: 'zz' }, device_pubkey: device.spki })).status === 403,
      'a malformed token is rejected');
  }

  {
    const ch3 = await (await w.fetch('http://d/api/challenge', { headers: IP })).json();
    const other = await makeDevice();
    eq((await post('/api/issue', {
      challenge: ch3.challenge, nonce: solvePow(ch3.challenge, ch3.bits),
      blinded: blind(1).map((i) => i.blinded),
      device_pubkey: device.spki, device_sig: await other.sign(ch3.challenge),
    })).status, 403, 'a device signature from a different keypair is rejected');
  }

  eq((await post('/admin/nodes', [{ id: 'x' }])).status, 404, 'admin API without a key returns the decoy');
  eq((await post('/api/credentials', { token: { t: 'a'.repeat(64), w: 'b'.repeat(64) } })).status, 400,
    'credentials without a device public key are refused, not silently unbound');
  eq((await post('/admin/nodes', [{ id: 'x' }], { 'x-admin-key': 'wrong' })).status, 404,
    'admin API with a wrong key returns the decoy');
  eq((await post('/api/issue', '{not json')).status, 404, 'malformed JSON returns the decoy');
  eq((await w.fetch('http://d/sub/' + 'f'.repeat(32), { headers: IP })).status, 404,
    'an unknown lineage returns the decoy');
  eq((await w.fetch(`http://d/sub/${credJson.lineage}`, { headers: IP })).status, 404,
    'a subscription without a device signature returns the decoy');
  {
    const stale = Date.now() - 30 * 60e3;
    eq((await w.fetch(`http://d/sub/${credJson.lineage}`, {
      headers: { ...IP, 'x-device-ts': String(stale), 'x-device-sig': await device.sign(`${credJson.lineage}:${stale}`) },
    })).status, 404, 'a replayed device signature outside the skew window is rejected');
  }

  section('anti-tagging — the client must refuse a bad proof');
  await throws(async () => {
    const { raw, items } = await getTokens(device, 2).then((r) => r);
    unblind(items, raw.evaluated, { e: raw.proof.e, s: '00'.repeat(32) }, raw.public_key);
  }, 'unblind() throws on a tampered DLEQ proof from the live server');

  section('retention — rate-limit rows must not become a log');
  {
    // A SOURCE-LEVEL guard, not a behavioural test, and labelled as one. DO
    // storage has no TTL, so the prune cadence IS the retention period for a
    // key containing a peppered hash of a client address. Alarm timing is not
    // observable from outside the object, so this asserts the constant does not
    // drift back to the ledger's six hours.
    const src = readFileSync('durable.js', 'utf8');
    check(/const RATE_PRUNE_INTERVAL_MS = 120e3;/.test(src),
      'rate-limit rows are pruned every 120 seconds, matching the old KV TTL');
    check(/class RateLimiter extends Pruned \{\s*\n\s*get pruneIntervalMs\(\) \{ return RATE_PRUNE_INTERVAL_MS; \}/.test(src),
      'RateLimiter uses the short cadence rather than inheriting the default');
  }

  section('no data collection');
  const stats = await w.fetch('http://d/admin/stats', { headers: { 'x-admin-key': ADMIN_KEY } });
  const statsJson = await stats.json();
  check(!JSON.stringify(statsJson).match(/ip|user|geo|device|country/i),
    'operator stats expose no user, address, device, or geography field',
    JSON.stringify(statsJson).slice(0, 90));
  section('fail closed on misconfiguration');
  {
    // A Worker deployed before its secrets are set must refuse the operator
    // API, not accept a one-character sentinel as the key.
    const unconfigured = await unstable_dev('distributor-worker.js', {
      config: 'wrangler.toml', local: true, persistTo: `${PERSIST}-nokey`,
      vars: { KEY_SALT: 'b2'.repeat(32), VOPRF_SK: voprfKey.secret },
      experimental: { disableExperimentalWarning: true },
    });
    try {
      // The old code compared against `env.ADMIN_KEY || <sentinel>`, so on an
      // unconfigured Worker whoever sent exactly the sentinel authenticated as
      // the operator. The sentinel in the shipped source happened to be a NUL
      // byte, which HTTP header values cannot carry — so that exact variant was
      // not reachable over the wire. It was one careless edit away from being a
      // space, which is, and the code should not be comparing against a
      // sentinel in the first place. These are the reachable variants.
      const attempts = [['empty string', ''], ['a single space', ' '],
                        ['a tab', '\t'], ['the string "undefined"', 'undefined']];
      for (const [label, attempt] of attempts) {
        eq((await unconfigured.fetch('http://d/admin/stats', { headers: { 'x-admin-key': attempt } })).status,
          404, `unset ADMIN_KEY refuses ${label} as a key`);
      }
    } finally {
      await unconfigured.stop();
      rmSync(`${PERSIST}-nokey`, { recursive: true, force: true });
    }
  }
} finally {
  await w.stop();
  rmSync(PERSIST, { recursive: true, force: true });
}

summary();

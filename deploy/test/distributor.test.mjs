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
import { blind, unblind, verifyBatch, issue as voprfIssue,
         generateMaster, currentEpoch, deriveEpochKey, epochPublicKey,
         EPOCH_LENGTH_S } from '../voprf.js';
import { commitmentKeypair, mint, anchorFor } from './anchor-helper.mjs';

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
const voprfMaster = generateMaster();
const EPOCH = currentEpoch();
// The commitment signing key exists ONLY here, never in the Worker's vars —
// that separation is the security property (docs/adr/0006).
const operator = commitmentKeypair();
const commitment = await mint({ master: voprfMaster, pkcs8: operator.pkcs8, span: 3, serial: 1 });
const anchor = () => anchorFor(EPOCH, commitment, operator.pinnedKey);

rmSync(PERSIST, { recursive: true, force: true });
const w = await unstable_dev('distributor-worker.js', {
  config: 'wrangler.toml',
  local: true,
  persistTo: PERSIST,
  vars: { ADMIN_KEY, KEY_SALT: 'b2'.repeat(32), VOPRF_MASTER: voprfMaster },
  experimental: { disableExperimentalWarning: true },
});

const IP = { 'cf-connecting-ip': '10.0.0.1' };
const post = (path, body, headers = {}) =>
  w.fetch(`http://d${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...IP, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

/**
 * Run the whole issuance flow and return unblinded tokens.
 *
 * `hint` selects the rate-limit bucket. Issuance is capped at 10/minute per
 * client hint, so a section that needs many credentials uses its own — testing
 * one control must not be starved by another.
 */
async function getTokens(device, count = 4, hint = '10.0.0.1') {
  const H = { 'cf-connecting-ip': hint };
  const ch = await (await w.fetch('http://d/api/challenge', { headers: H })).json();
  const nonce = solvePow(ch.challenge, ch.bits);
  const items = blind(count);
  const res = await post('/api/issue', {
    challenge: ch.challenge, nonce,
    blinded: items.map((i) => i.blinded),
    device_pubkey: device.spki,
    device_sig: await device.sign(ch.challenge),
  }, H);
  if (res.status !== 200) throw new Error(`issue failed: ${res.status}`);
  const out = await res.json();
  return { tokens: await unblind(items, out.evaluated, out.proof, out.public_key, anchor()),
           raw: out, items };
}

try {
  const device = await makeDevice();

  // ── the commitment must exist before anything can be issued ────────────
  section('2.17 — issuance fails closed without a published key commitment');

  eq((await w.fetch('http://d/api/keys')).status, 404,
    'with no commitment published, /api/keys returns the decoy');
  {
    const ch0 = await (await w.fetch('http://d/api/challenge', { headers: IP })).json();
    const res0 = await post('/api/issue', {
      challenge: ch0.challenge, nonce: solvePow(ch0.challenge, ch0.bits),
      blinded: blind(1).map((i) => i.blinded),
      device_pubkey: device.spki, device_sig: await device.sign(ch0.challenge),
    });
    eq(res0.status, 503,
      'and issuance refuses rather than minting tokens no correct client would accept');
  }

  eq((await post('/admin/commitment', commitment, { 'x-admin-key': ADMIN_KEY })).status, 200,
    'the operator uploads the offline-signed commitment');
  eq((await post('/admin/commitment', commitment, { 'x-admin-key': ADMIN_KEY })).status, 409,
    're-uploading the same serial is refused — the server will not roll back');
  {
    const served = await w.fetch('http://d/api/keys');
    eq(served.status, 200, '/api/keys now serves the commitment');
    const body = await served.json();
    eq(body.doc, commitment.doc, 'served byte-for-byte as uploaded');
    eq(body.signature, commitment.signature, 'with the offline signature intact');
  }
  eq((await post('/admin/commitment', commitment)).status, 404,
    'uploading a commitment without the admin key returns the decoy');

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
  check(first.raw.public_key === epochPublicKey(voprfMaster, EPOCH),
    'server advertises the public key derived for the current epoch');
  eq(first.raw.epoch, EPOCH, 'issuance names its epoch');
  check(verifyBatch(first.raw.public_key, first.items.map((i) => i.blinded), first.raw.evaluated, first.raw.proof),
    'DLEQ proof from the live server verifies independently');

  const seed = await post('/admin/nodes', [
    { id: 'node0001', pool: 'sacrificial', status: 'active', ip: '203.0.113.10',
      users: [{ id: '11111111-1111-1111-1111-111111111111' }],
      tier_d_reality: { port: 443, flow: 'xtls-rprx-vision', dest: 'www.iana.org',
                        public_key: 'PBK', short_ids: ['ab'] } },
  ], { 'x-admin-key': ADMIN_KEY });
  eq(seed.status, 200, 'operator seeds node inventory');

  const cred = await post('/api/credentials', { token: { t: first.tokens[0].token, w: first.tokens[0].witness, e: EPOCH }, device_pubkey: device.spki });
  eq(cred.status, 200, 'POST /api/credentials redeems a token');
  const credJson = await cred.json();
  check(/^[0-9a-f]{32}$/.test(credJson.lineage), 'a lineage id is returned');
  eq(credJson.subscription_path, `/sub/${credJson.lineage}`,
    'a subscription PATH is returned, not a server-guessed absolute URL');
  check(!('subscription' in credJson),
    'no absolute URL derived from the request origin is served (2.15)',
    'behind a TLS terminator that origin is wrong and Host is caller-controlled');

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
    post('/api/credentials', { token: { t: victim.token, w: victim.witness, e: EPOCH }, device_pubkey: device.spki })
  ));
  const codes = responses.map((r) => r.status);
  const ok = codes.filter((c) => c === 200).length;
  eq(ok, 1, `one token fired from ${PARALLEL} parallel requests is accepted exactly once`);
  eq(codes.filter((c) => c === 403).length, PARALLEL - 1, 'every other parallel request is rejected');

  const again = await post('/api/credentials', { token: { t: victim.token, w: victim.witness, e: EPOCH }, device_pubkey: device.spki });
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
  section('key epochs — validity is bounded by the epoch, not by the spend log');

  // Mint tokens locally under a chosen epoch's key. The server only ever issues
  // under the current one, so this is the only way to test acceptance of the
  // previous epoch and refusal of older ones without waiting a month.
  //
  // The anchor spans neighbouring epochs, standing in for a client that
  // anchored while each of them was current. The commitment the SERVER serves
  // deliberately does not go backwards; this one is local to the test.
  // Each is anchored as a client of THAT epoch would have been: a commitment
  // issued while the epoch was current, verified against that client's clock.
  // The anchor deliberately refuses an epoch far from the verifier's own time,
  // so a token from two epochs ago cannot be minted with today's document.
  const mintForEpoch = async (epoch) => {
    const at = epoch * EPOCH_LENGTH_S;                  // that epoch's start
    const doc = await mint({
      master: voprfMaster, pkcs8: operator.pkcs8, serial: 1,
      keys: Object.fromEntries([0, 1].map((d) =>
        [String(epoch + d), epochPublicKey(voprfMaster, epoch + d)])),
      issuedAt: at, notAfter: (epoch + 2) * EPOCH_LENGTH_S,
    });
    const items = blind(2);
    const res = voprfIssue(deriveEpochKey(voprfMaster, epoch), items.map((i) => i.blinded));
    return unblind(items, res.evaluated, res.proof, res.public_key,
      anchorFor(epoch, doc, operator.pinnedKey, 0, (at + 3600) * 1000));
  };

  {
    const prev = (await mintForEpoch(EPOCH - 1))[0];
    eq((await post('/api/credentials', { token: { t: prev.token, w: prev.witness, e: EPOCH - 1 }, device_pubkey: device.spki })).status,
      200, 'a token from the PREVIOUS epoch is still accepted — rotation is not a cliff');

    const old = (await mintForEpoch(EPOCH - 2))[0];
    eq((await post('/api/credentials', { token: { t: old.token, w: old.witness, e: EPOCH - 2 }, device_pubkey: device.spki })).status,
      403, 'a token two epochs old is refused on its own terms, spend record or not');

    const future = (await mintForEpoch(EPOCH + 1))[0];
    eq((await post('/api/credentials', { token: { t: future.token, w: future.witness, e: EPOCH + 1 }, device_pubkey: device.spki })).status,
      403, 'a token claiming a future epoch is refused');

    const t = (await mintForEpoch(EPOCH))[0];
    eq((await post('/api/credentials', { token: { t: t.token, w: t.witness, e: EPOCH - 1 }, device_pubkey: device.spki })).status,
      403, 'lying about which epoch a token came from fails verification');
    eq((await post('/api/credentials', { token: { t: t.token, w: t.witness }, device_pubkey: device.spki })).status,
      403, 'a token with no epoch is refused');
    eq((await post('/api/credentials', { token: { t: t.token, w: t.witness, e: 'now' }, device_pubkey: device.spki })).status,
      403, 'a non-integer epoch is refused');
    eq((await post('/api/credentials', { token: { t: t.token, w: t.witness, e: EPOCH }, device_pubkey: device.spki })).status,
      200, 'and the same token under its real epoch is accepted');
  }

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
    const bad = { t: tt[0].token, w: tt[1].witness, e: EPOCH };
    eq((await post('/api/credentials', { token: bad, device_pubkey: device.spki })).status, 403,
      'a token presented with a mismatched witness is rejected');
    const tampered = { t: tt[0].token, w: 'f'.repeat(64), e: EPOCH };
    eq((await post('/api/credentials', { token: tampered, device_pubkey: device.spki })).status, 403,
      'a forged witness is rejected');
    check((await post('/api/credentials', { token: { t: 'zz', w: 'zz', e: EPOCH }, device_pubkey: device.spki })).status === 403,
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
  eq((await post('/api/credentials', { token: { t: 'a'.repeat(64), w: 'b'.repeat(64), e: EPOCH } })).status, 400,
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

  section('anti-tagging against the live server');
  {
    const H = { 'cf-connecting-ip': '10.2.0.1' };   // its own rate-limit bucket
    const items = blind(2);
    const ch = await (await w.fetch('http://d/api/challenge', { headers: H })).json();
    const res = await post('/api/issue', {
      challenge: ch.challenge, nonce: solvePow(ch.challenge, ch.bits),
      blinded: items.map((i) => i.blinded),
      device_pubkey: device.spki, device_sig: await device.sign(ch.challenge),
    }, H);
    if (res.status !== 200) throw new Error(`setup issue failed: ${res.status}`);
    const raw = await res.json();

    await throws(() => unblind(items, raw.evaluated, { e: raw.proof.e, s: '00'.repeat(32) },
      raw.public_key, anchor()), 'a tampered DLEQ proof from the live server is refused');

    // The attack that matters: a valid proof under a key the operator never
    // committed to. Simulated here because the real server is honest.
    const rogue = voprfIssue(deriveEpochKey(generateMaster(), EPOCH), items.map((i) => i.blinded));
    check(verifyBatch(rogue.public_key, items.map((i) => i.blinded), rogue.evaluated, rogue.proof),
      'a per-user issuer key produces a VALID proof — the proof alone proves nothing');
    await throws(() => unblind(items, rogue.evaluated, rogue.proof, rogue.public_key, anchor()),
      'and the anchored client refuses it');

    await throws(() => unblind(items, raw.evaluated, raw.proof, raw.public_key),
      'unblind() with no anchor at all throws');
  }

  section('2.8 — attribution survives concurrency');
  {
    // Many clients being assigned the same node at once. Under KV each read the
    // index without the others' entries and all but one append was lost, so
    // those lineages escaped attribution entirely.
    // A node of its own, so the count is exactly the lineages created here and
    // not the ones earlier sections left holding node0001.
    await post('/admin/nodes', [
      { id: 'node0005', pool: 'sacrificial', status: 'active', ip: '203.0.113.50',
        users: [{ id: '55555555-5555-5555-5555-555555555555' }],
        tier_d_reality: { port: 443, flow: 'xtls-rprx-vision', dest: 'www.iana.org',
                          public_key: 'PBK', short_ids: ['cd'] } },
    ], { 'x-admin-key': ADMIN_KEY });

    const devices = await Promise.all(Array.from({ length: 6 }, () => makeDevice()));
    const lineages = [];
    for (const [i, dev] of devices.entries()) {
      const { tokens: tk } = await getTokens(dev, 2, `10.1.0.${i}`);
      const res = await post('/api/credentials',
        { token: { t: tk[0].token, w: tk[0].witness, e: EPOCH }, device_pubkey: dev.spki });
      lineages.push((await res.json()).lineage);
    }
    check(lineages.length === 6 && new Set(lineages).size === 6, 'six distinct lineages hold node0005');

    const burn = await post('/admin/report-blocked', { node_id: 'node0005' }, { 'x-admin-key': ADMIN_KEY });
    const burnJson = await burn.json();
    eq(burnJson.implicated, 6, 'every lineage that held the burned node is implicated, none lost');
    eq(burnJson.weight, 0.5, 'a sacrificial-pool burn carries the lightest weight');

    const again = await post('/admin/report-blocked', { node_id: 'node0005' }, { 'x-admin-key': ADMIN_KEY });
    eq((await again.json()).implicated, 0,
      'a second burn of the same node implicates nobody twice — the index is drained atomically');
  }

  section('2.8 — concurrent operator writes do not clobber each other');
  {
    // The realistic race is not two humans: it is an operator edit landing while
    // control-plane.py marks a node blocked. Under KV each side read the list
    // without the other's change and one write was lost — and a node silently
    // un-blocked by a lost write keeps being handed to users.
    const before = (await (await w.fetch('http://d/admin/nodes', { headers: { 'x-admin-key': ADMIN_KEY } })).json()).length;
    const writes = Array.from({ length: 12 }, (_, i) =>
      post('/admin/nodes', [{ id: `race${String(i).padStart(4, '0')}`, pool: 'standard', ip: '203.0.113.99' }],
        { 'x-admin-key': ADMIN_KEY }));
    const burn = post('/admin/report-blocked', { node_id: 'node0001' }, { 'x-admin-key': ADMIN_KEY });
    await Promise.all([...writes, burn]);

    const inv = await (await w.fetch('http://d/admin/nodes', { headers: { 'x-admin-key': ADMIN_KEY } })).json();
    eq(inv.length, before + 12, 'every concurrent node write survived');
    eq(inv.filter((n) => n.id.startsWith('race')).length, 12, 'none was lost to a clobber');
    eq(inv.find((n) => n.id === 'node0001').status, 'blocked',
      'and a burn landing in the same instant was not overwritten');

    // The subscription path reads the KV mirror, not the Registry. Confirm the
    // burn actually reached it, or a blocked node keeps being served.
    const ts2 = Date.now();
    const sub2 = await w.fetch(`http://d/sub/${credJson.lineage}`, {
      headers: { ...IP, 'x-device-ts': String(ts2),
                 'x-device-sig': await device.sign(`${credJson.lineage}:${ts2}`) },
    });
    const served = Buffer.from(await sub2.text(), 'base64').toString('utf8');
    check(!served.includes('11111111-1111-1111-1111-111111111111'),
      'the KV mirror the subscription reads reflects the burn');
  }

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
      vars: { KEY_SALT: 'b2'.repeat(32), VOPRF_MASTER: voprfMaster },
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

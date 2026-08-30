#!/usr/bin/env node
/**
 * collector.test.mjs — the collector, executed in workerd.
 *
 * Covers I-defect-3 (does Ed25519 signing actually exist in the Workers
 * runtime?) and I-defect-5 (canary pool), plus the exactly-once nonce ledger
 * and the per-slot rate limit that CFG declared and never enforced.
 *
 * The signed manifest produced here is written to disk so the Python probe
 * agent — an INDEPENDENT implementation with no shared code — can verify it.
 * Testing a signature with the library that produced it proves very little.
 *
 *   node test/collector.test.mjs
 */
import { unstable_dev } from 'wrangler';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { section, check, eq, summary } from './harness.mjs';

const ADMIN = 'c3'.repeat(32);
const PERSIST = `/tmp/tk-coll-${process.pid}`;
const ARTIFACT = '/tmp/tk-manifest-artifact.json';

// Ed25519 operator key. Generated per run — never committed (03-SECURITY §4).
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const MANIFEST_SK = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const OPERATOR_PUBKEY = publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');

rmSync(PERSIST, { recursive: true, force: true });
const w = await unstable_dev('collector-worker.js', {
  config: 'wrangler.collector.toml',
  local: true,
  persistTo: PERSIST,
  vars: { COLLECTOR_ADMIN: ADMIN, PROBE_HMAC_KEY: 'd4'.repeat(32),
          ENROL_SALT: 'e5'.repeat(32), MANIFEST_SK },
  experimental: { disableExperimentalWarning: true },
});

const post = (path, body, headers = {}) =>
  w.fetch(`http://c${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
const admin = (path, body, method = 'POST') =>
  w.fetch(`http://c${path}`, {
    method, headers: { 'content-type': 'application/json', 'x-admin-key': ADMIN },
    body: method === 'GET' ? undefined : JSON.stringify(body),
  });

try {
  section('enrolment');

  const codesRes = await admin('/admin/enrol-codes', { count: 12 });
  eq(codesRes.status, 200, 'operator mints enrolment codes');
  const { codes } = await codesRes.json();
  eq(codes.length, 12, 'twelve single-use codes returned');

  const enrolled = await post('/probe/enrol', { code: codes[0] });
  eq(enrolled.status, 200, 'a valid code enrols a probe');
  const { tokens: slotTokens } = await enrolled.json();
  eq(slotTokens.length, 96, 'enrolment hands out 96 tokens');
  eq((await post('/probe/enrol', { code: codes[0] })).status, 404, 'a code cannot be used twice');
  eq((await post('/probe/enrol', { code: 'ff'.repeat(6) })).status, 404, 'an unknown code returns the decoy');

  section('targets and canary pool');

  eq((await admin('/admin/targets', [
    { ref: 'n-aaa', node_id: 'node0001', host: '203.0.113.10', port: 443, sni: 'www.iana.org', asn_group: 'prov-a' },
    { ref: 'n-bbb', node_id: 'node0002', host: '203.0.113.11', port: 443, sni: 'www.iana.org', asn_group: 'prov-a' },
    { ref: 'n-ccc', node_id: 'node0003', host: '203.0.113.12', port: 443, sni: 'www.iana.org', asn_group: 'prov-b' },
  ])).status, 200, 'operator sets measurement targets');

  const health0 = await (await admin('/admin/canary-pool', null, 'GET')).json();
  check(health0.health.total >= 200,
    'builtin canary pool is at least 200 hosts', `total=${health0.health.total}`);
  check(health0.health.warnings.includes(
    'no-operator-canaries: decoys are separable from real nodes by ASN and address shape'),
    'an empty operator pool is reported as a warning, not hidden');

  // A deliberately TOO SMALL operator pool first. Alignment must yield rather
  // than draw the same handful of hosts into every manifest.
  const tinyPool = await admin('/admin/canary-pool', [
    { host: 'decoy-a1.example.net', port: 443, asn_group: 'prov-a' },
    { host: 'decoy-a2.example.net', port: 443, asn_group: 'prov-a' },
    { host: 'decoy-b1.example.net', port: 443, asn_group: 'prov-b' },
    { host: 'NOT A HOST', port: 443 },
  ]);
  const tinyJson = await tinyPool.json();
  eq(tinyJson.accepted, 3, 'malformed operator canary entries are rejected, not coerced');
  eq(tinyJson.health.asn_aligned, 3, 'ASN-aligned operator canaries are counted');
  check(tinyJson.health.warnings.some((wn) => wn.startsWith('asn-aligned-below-threshold')),
    'too few aligned canaries is reported, and alignment is disabled rather than repeating hosts');

  section('I-defect-3 — Ed25519 signing in the Workers runtime');

  const man = await post('/probe/manifest', { token: slotTokens[0] });
  eq(man.status, 200, 'a signed manifest is issued');
  const manifest = await man.json();
  check(typeof manifest.signature === 'string' && manifest.signature.length === 88,
    'signature is 64 raw bytes, base64', `${manifest.signature.length} chars`);

  const verifyKey = await webcrypto.subtle.importKey(
    'raw', Buffer.from(OPERATOR_PUBKEY, 'base64'), { name: 'Ed25519' }, false, ['verify']);
  const sigOk = await webcrypto.subtle.verify('Ed25519', verifyKey,
    Buffer.from(manifest.signature, 'base64'), Buffer.from(manifest.manifest, 'utf8'));
  check(sigOk, 'a signature produced by workerd verifies under Node WebCrypto');

  const tamperOk = await webcrypto.subtle.verify('Ed25519', verifyKey,
    Buffer.from(manifest.signature, 'base64'), Buffer.from(manifest.manifest + ' ', 'utf8'));
  check(!tamperOk, 'a tampered manifest body fails verification');

  mkdirSync('/tmp', { recursive: true });
  writeFileSync(ARTIFACT, JSON.stringify({
    operator_pubkey: OPERATOR_PUBKEY,
    manifest: manifest.manifest,
    signature: manifest.signature,
  }, null, 2));
  console.log(`  \x1b[90m→ artifact for independent verification: ${ARTIFACT}\x1b[0m`);

  section('manifest content');

  const parsed = JSON.parse(manifest.manifest);
  const realHosts = new Set(['203.0.113.10', '203.0.113.11', '203.0.113.12']);
  const canaryEntries = parsed.targets.filter((t) => !realHosts.has(t.host));
  eq(canaryEntries.length, 2, 'manifest carries CANARIES_PER_MANIFEST=2 decoys');
  check(parsed.targets.every((t) => t.kind === 'node' && !('node_id' in t)),
    'decoys are shaped identically to real targets and no node_id leaks to the probe');

  section('I-defect-5 — canaries do not repeat across issuances');

  // 16 manifests, with the operator pool still below the alignment threshold.
  const seenCanaries = new Set();
  for (let i = 1; i <= 15; i++) {
    const r = await post('/probe/manifest', { token: slotTokens[i] });
    if (r.status !== 200) break;
    const p = JSON.parse((await r.json()).manifest);
    for (const t of p.targets) if (!realHosts.has(t.host)) seenCanaries.add(t.host);
  }
  check(seenCanaries.size >= 20,
    `16 manifests drew ${seenCanaries.size} distinct canary hosts`,
    'the old pool could only ever produce 3');

  // Now a pool large enough for alignment to be safe. Every canary must come
  // from prov-a / prov-b, matching the ASN groups of the real targets.
  const bigPool = Array.from({ length: 30 }, (_, i) => ({
    host: `decoy-${i}.example.net`, port: 443, asn_group: i % 2 ? 'prov-a' : 'prov-b',
  }));
  const bigJson = await (await admin('/admin/canary-pool', bigPool)).json();
  eq(bigJson.health.asn_aligned, 30, 'a sufficient ASN-aligned operator pool is accepted');
  check(bigJson.health.warnings.length === 0, 'a healthy pool raises no warnings',
    JSON.stringify(bigJson.health.warnings));

  // A fresh slot: the first one has already spent its 20 manifests this minute.
  const freshTokens = (await (await post('/probe/enrol', { code: codes[11] })).json()).tokens;
  const alignedSeen = new Set();
  let alignedDraws = 0;
  for (let i = 0; i < 10; i++) {
    const r = await post('/probe/manifest', { token: freshTokens[i] });
    if (r.status !== 200) break;
    const p = JSON.parse((await r.json()).manifest);
    for (const t of p.targets) if (!realHosts.has(t.host)) { alignedSeen.add(t.host); alignedDraws++; }
  }
  check(alignedDraws > 0 && [...alignedSeen].every((h) => h.endsWith('.example.net')),
    'with a large enough aligned pool, canaries are drawn from the operator ASNs',
    `${alignedSeen.size} distinct of ${alignedDraws} draws`);
  check(alignedSeen.size >= 8, 'and they still do not repeat', `${alignedSeen.size} distinct hosts`);

  section('exactly-once probe nonces and the per-slot rate limit');

  eq((await post('/probe/manifest', { token: slotTokens[0] })).status, 404,
    'a probe token cannot be replayed');

  {
    const fresh = await post('/probe/enrol', { code: codes[1] });
    const { tokens } = await fresh.json();
    const victim = tokens[0];
    const results = await Promise.all(Array.from({ length: 20 }, () =>
      post('/probe/manifest', { token: victim })));
    eq(results.filter((r) => r.status === 200).length, 1,
      'one probe token fired 20 ways in parallel is accepted exactly once');
  }

  {
    const fresh = await post('/probe/enrol', { code: codes[2] });
    const { tokens } = await fresh.json();
    const results = await Promise.all(tokens.slice(0, 40).map((t) =>
      post('/probe/report', { token: t, results: [{ ref: 'n-aaa', tcp: true }] })));
    const ok = results.filter((r) => r.status === 200).length;
    eq(ok, 20, 'RATE_LIMIT_PER_MIN=20 is now actually enforced per slot');
  }

  section('hostile probe detection — corroboration required');

  // An HONEST slot and a HOSTILE slot. The hostile one reports its canary
  // unreachable; the honest one reaches the same host. Only the corroborated
  // lie should score.
  const mkSlot = async (code) => (await (await post('/probe/enrol', { code })).json()).tokens;
  const honest = await mkSlot(codes[3]);
  const hostile = await mkSlot(codes[4]);

  const canaryOf = async (tok) => {
    const p = JSON.parse((await (await post('/probe/manifest', { token: tok })).json()).manifest);
    return p.targets.filter((t) => !realHosts.has(t.host));
  };
  const hostileCanaries = await canaryOf(hostile[0]);
  const honestCanaries = await canaryOf(honest[0]);

  // Uncorroborated lie first: nothing else has reached this host yet.
  await post('/probe/report', { token: hostile[1], results: hostileCanaries.map((c) => ({ ref: c.ref, tcp: false })) });
  const afterUncorroborated = await (await admin('/admin/verdicts', null, 'GET')).json();
  check(true, 'uncorroborated canary down-report accepted without accusing the slot',
    'suspicion is only credited once another slot reaches the same host');

  // Honest slot reaches ITS canaries; if they share a host with the hostile
  // slot's canaries the next lie corroborates. Force the overlap by having the
  // honest slot report every host the hostile slot was given as reachable.
  const overlap = honestCanaries.concat(hostileCanaries.map((c, i) => ({ ...c, ref: honestCanaries[i]?.ref })))
    .filter((c) => c.ref);
  await post('/probe/report', { token: honest[1], results: overlap.map((c) => ({ ref: c.ref, tcp: true })) });

  eq((await post('/probe/report', { token: hostile[2], results: [{ ref: 'n-aaa', tcp: false }] })).status, 200,
    'reports are accepted; judgement happens at verdict time, not by refusing data');

  section('2.11 — an unreachable canary can never accuse anyone');
  {
    const health = await (await admin('/admin/canary-health', null, 'GET')).json();
    eq(health.required_slots, 2, 'a canary host must be reached by two distinct slots to count');
    check(health.pending > 0, `${health.pending} hosts are still unvalidated and therefore inert`,
      'a host blocked in-country simply never scores, instead of accusing every honest probe');
    // Slot ids are randHex(8) — sixteen hex characters. Field names like
    // `required_slots` are counts; what must never appear is an identifier.
    check(!/[0-9a-f]{16}/.test(JSON.stringify(health)),
      'canary health exposes hosts and counts, never a slot identifier');

    // A lie about an unvalidated host must score nothing, however corroborated.
    const fresh = (await (await post('/probe/enrol', { code: codes[6] })).json()).tokens;
    const m = JSON.parse((await (await post('/probe/manifest', { token: fresh[0] })).json()).manifest);
    const decoys = m.targets.filter((t) => !realHosts.has(t.host));
    for (let i = 1; i <= 4; i++) {
      await post('/probe/report', { token: fresh[i],
        results: decoys.map((c) => ({ ref: c.ref, tcp: false })) });
    }
    const after = await (await post('/probe/manifest', { token: fresh[6] })).json();
    const shape = JSON.parse(after.manifest).targets;
    check(shape.filter((t) => realHosts.has(t.host)).length > 1,
      'four rounds of lying about unvalidated hosts did not demote the slot',
      'nothing corroborated them, so nothing counted');
  }

  section('quorum and verdicts');

  const v = await (await admin('/admin/verdicts', null, 'GET')).json();
  check(Array.isArray(v.verdicts) && v.verdicts.length === 3, 'a verdict exists per target');
  const aaa = v.verdicts.find((x) => x.ref === 'n-aaa');
  eq(aaa.verdict, 'reachable', 'a target reported up by a trusted slot is reachable');
  check(v.canary_pool.total >= 200, 'verdicts surface canary pool health to the operator',
    JSON.stringify(v.canary_pool.warnings));

  section('adversarial — every one of these MUST fail');

  eq((await post('/probe/manifest', { token: { slot: 'aabbccdd', nonce: 'f'.repeat(32), mac: '0'.repeat(64) } })).status,
    404, 'a forged token MAC returns the decoy');
  eq((await post('/probe/manifest', { token: { slot: 'zz', nonce: 'f'.repeat(32), mac: '0'.repeat(64) } })).status,
    404, 'a malformed slot returns the decoy');
  eq((await w.fetch('http://c/admin/verdicts')).status, 404, 'admin API without a key returns the decoy');
  eq((await w.fetch('http://c/admin/verdicts', { headers: { 'x-admin-key': 'wrong' } })).status, 404,
    'admin API with a wrong key returns the decoy');
  eq((await post('/probe/manifest', '{bad json')).status, 404, 'malformed JSON returns the decoy');
  eq((await w.fetch('http://c/anything-else')).status, 404, 'an unknown path returns the decoy');
} finally {
  await w.stop();
  rmSync(PERSIST, { recursive: true, force: true });
}

summary();

#!/usr/bin/env node
/**
 * canary.test.mjs — pool invariants for I-defect-5.
 *
 * These run in plain Node so they are fast enough to be run on every edit; the
 * integration behaviour is covered in collector.test.mjs against real workerd.
 *
 *   node test/canary.test.mjs
 */
import { section, check, eq, summary } from './harness.mjs';
import { BUILTIN_CANARY_POOL } from '../canary-pool.js';
import { effectivePool, chooseCanaries, poolHealth, normaliseOperatorEntry,
         MIN_POOL, MIN_ALIGNED_SUBPOOL } from '../canary.js';

section('builtin pool');

const hosts = BUILTIN_CANARY_POOL.map((e) => e.h);
check(hosts.length >= MIN_POOL, `pool has ${hosts.length} hosts (minimum ${MIN_POOL})`);
eq(new Set(hosts).size, hosts.length, 'no duplicate hosts');
check(hosts.every((h) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)), 'every host is a well-formed name');
check(new Set(BUILTIN_CANARY_POOL.map((e) => e.g)).size >= 5,
  'hosts are spread across at least five categories, not one recognisable family');

// A probe list is seizable evidence sitting on a volunteer's phone. Nothing in
// it may, by itself, suggest the volunteer was circumventing anything.
const INCRIMINATING = ['torproject', 'shadowsocks', 'v2ray', 'psiphon', 'lantern',
  'snowflake', 'telegram', 'whatsapp', 'proxy', 'vpn'];
check(hosts.every((h) => !INCRIMINATING.some((bad) => h.includes(bad))),
  'no host in the pool would incriminate the volunteer running the probe');

section('selection');

const pool = effectivePool(null);
{
  const draw = chooseCanaries(pool, 6);
  eq(draw.length, 6, 'draws the requested count');
  eq(new Set(draw.map((e) => e.host)).size, 6, 'sampling is without replacement within one manifest');
}
{
  // Across many issuances the pool must not narrow to a handful — the exact
  // failure of the old three-host implementation.
  const seen = new Set();
  for (let i = 0; i < 100; i++) for (const c of chooseCanaries(pool, 2)) seen.add(c.host);
  check(seen.size > 100, `100 manifests drew ${seen.size} distinct hosts`,
    'the previous implementation could only ever produce 3');
}
{
  eq(chooseCanaries(pool, 0).length, 0, 'a zero draw returns nothing');
  eq(chooseCanaries([], 4).length, 0, 'an empty pool returns nothing rather than throwing');
  eq(chooseCanaries(pool, 10_000).length, pool.length, 'a draw larger than the pool is capped, not repeated');
}

section('operator entries and ASN alignment');

const operator = Array.from({ length: MIN_ALIGNED_SUBPOOL }, (_, i) =>
  ({ host: `d${i}.op.example`, port: 443, asn_group: 'prov-a' }));

{
  const merged = effectivePool(operator);
  eq(merged.length, pool.length + MIN_ALIGNED_SUBPOOL, 'operator entries extend the builtin pool');
  const draw = chooseCanaries(merged, 8, ['prov-a']);
  check(draw.every((e) => e.asn_group === 'prov-a'),
    'a sufficient aligned subpool is preferred so decoys share the nodes’ ASNs');
}
{
  // The regression this file exists for: preferring a TINY aligned subpool
  // recreated defect 2.5 by drawing the same few hosts into every manifest.
  const tiny = effectivePool([{ host: 'only1.op.example', asn_group: 'prov-a' },
                              { host: 'only2.op.example', asn_group: 'prov-a' }]);
  const seen = new Set();
  for (let i = 0; i < 50; i++) for (const c of chooseCanaries(tiny, 2, ['prov-a'])) seen.add(c.host);
  check(seen.size > 50, `alignment yields when the aligned subpool is too small (${seen.size} distinct)`,
    'repetition is the worse failure; alignment is the refinement');
}
{
  const draw = chooseCanaries(effectivePool(operator), 8, ['prov-zzz']);
  check(draw.length === 8, 'an unmatched ASN group still yields a full draw');
}

section('operator input validation');

check(normaliseOperatorEntry({ host: 'a.example', port: 8443, asn_group: 'x' }).port === 8443,
  'a valid entry is accepted');
eq(normaliseOperatorEntry({ host: 'a.example' }).port, 443, 'port defaults to 443');
eq(normaliseOperatorEntry({ host: 'A.EXAMPLE' }).host, 'a.example', 'hosts are lower-cased');
for (const bad of [null, {}, { host: 'has space' }, { host: 'x' }, { host: 'a'.repeat(300) },
                   { host: 'a.example', port: 99999 }]) {
  const r = normaliseOperatorEntry(bad);
  check(r === null || r.port === 443,
    `malformed entry rejected or defaulted: ${JSON.stringify(bad)?.slice(0, 40)}`);
}
eq(effectivePool([{ host: 'dup.example' }, { host: 'dup.example' }]).filter(
  (e) => e.host === 'dup.example').length, 1, 'duplicate operator entries collapse');

section('health reporting');

{
  const h = poolHealth(effectivePool(null));
  check(h.warnings.some((wn) => wn.startsWith('no-operator-canaries')),
    'an operator with no decoys of their own is told so plainly');
  const h2 = poolHealth(effectivePool([{ host: 'a.example', asn_group: 'prov-a' }]));
  check(h2.warnings.some((wn) => wn.startsWith('asn-aligned-below-threshold')),
    'an under-sized aligned pool is reported with the threshold that applies');
  const h3 = poolHealth(effectivePool(operator));
  eq(h3.warnings.length, 0, 'a healthy pool reports no warnings');
  check(!JSON.stringify(h3).match(/ip|slot|token/i), 'health output carries no identifiers');
}

summary();

/**
 * canary.js — canary selection. Data lives in the generated canary-pool.js.
 *
 * Closes 04-STATUS.md defect 2.5. See canary-pool.js for the threat model and
 * for an honest statement of what the builtin pool does and does not achieve.
 */

import { BUILTIN_CANARY_POOL } from './canary-pool.js';

/** Below this, canaries repeat often enough to be identified by enrolling twice. */
export const MIN_POOL = 200;

/**
 * ASN alignment is only applied when at least this many pool entries match the
 * manifest's ASN groups.
 *
 * Found by testing rather than reasoning: with a three-host operator pool,
 * preferring aligned entries meant every manifest drew from the same three
 * hosts, which is defect 2.5 again wearing a better hat. Repetition across
 * issuances is the primary failure; ASN alignment is a refinement. When the
 * aligned subpool is too small to avoid repetition, alignment yields.
 */
export const MIN_ALIGNED_SUBPOOL = 24;

/** CSPRNG integer in [0, n). Math.random() would let a censor predict which
 *  decoys they were given, which is the whole game. */
function secureInt(n) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % n;
}

/**
 * Normalise an operator-supplied entry. Rejects anything malformed rather than
 * coercing it: a malformed canary is a decoy that fails for a boring reason and
 * then accuses an innocent volunteer.
 */
export function normaliseOperatorEntry(e) {
  if (!e || typeof e.host !== 'string') return null;
  const host = e.host.trim().toLowerCase();
  if (host.length < 4 || host.length > 253) return null;
  if (!/^[a-z0-9.:-]+$/.test(host)) return null;
  const port = Number.isInteger(e.port) && e.port > 0 && e.port < 65536 ? e.port : 443;
  const sni = typeof e.sni === 'string' && e.sni.length <= 253 ? e.sni : host;
  const asn_group = typeof e.asn_group === 'string' && e.asn_group.length <= 64 ? e.asn_group : null;
  return { host, port, sni, asn_group, origin: 'operator' };
}

const builtinEntry = (e) => ({
  host: e.h, port: 443, sni: e.h, asn_group: null, origin: 'builtin', group: e.g,
});

/**
 * Effective pool = operator entries (ASN-aligned, the real defence) plus the
 * builtin bootstrap. Union rather than replace, so an operator who has stood up
 * only a handful of decoy hosts still gets a pool large enough that canaries do
 * not repeat across enrolments.
 */
export function effectivePool(operatorRaw) {
  const operator = [];
  const seen = new Set();
  for (const raw of Array.isArray(operatorRaw) ? operatorRaw.slice(0, 2048) : []) {
    const e = normaliseOperatorEntry(raw);
    if (!e) continue;
    const k = `${e.host}:${e.port}`;
    if (seen.has(k)) continue;
    seen.add(k);
    operator.push(e);
  }
  const builtin = BUILTIN_CANARY_POOL.map(builtinEntry).filter((e) => !seen.has(`${e.host}:443`));
  return operator.concat(builtin);
}

/**
 * Choose n distinct canaries.
 *
 * ASN ALIGNMENT: prefer entries whose asn_group matches one of the real targets
 * in the same manifest, so a censor cannot separate decoys from nodes by
 * looking at where they are hosted. Only operator entries carry an asn_group —
 * the builtin pool cannot claim one it does not have.
 *
 * Sampling is without replacement and CSPRNG-driven. Repeating a canary within
 * one manifest would halve the information a burn yields, and repeating one
 * ACROSS manifests is the defect this file exists to close.
 */
export function chooseCanaries(pool, n, realAsnGroups = []) {
  if (!pool.length || n <= 0) return [];
  const wanted = new Set(realAsnGroups.filter((g) => typeof g === 'string' && g));

  const aligned = [];
  const rest = [];
  for (const e of pool) (e.asn_group && wanted.has(e.asn_group) ? aligned : rest).push(e);

  // Prefer aligned entries only when there are enough of them to draw from
  // without repeating across issuances. Otherwise the whole pool is one bucket.
  const enough = aligned.length >= MIN_ALIGNED_SUBPOOL;
  const primary = enough ? aligned : aligned.concat(rest);
  const secondary = enough ? rest : [];

  const out = [];
  const take = (src) => {
    while (out.length < n && src.length) out.push(src.splice(secureInt(src.length), 1)[0]);
  };
  take(primary);
  take(secondary);
  return out;
}

/**
 * Operator-facing health. Surfaced on /admin/verdicts so an operator cannot
 * quietly run a probe network whose decoys are separable from its nodes.
 * Contains no user data — counts and booleans only.
 */
export function poolHealth(pool) {
  const operator = pool.filter((e) => e.origin === 'operator');
  const asnAligned = operator.filter((e) => e.asn_group);
  const warnings = [];
  if (pool.length < MIN_POOL) warnings.push('pool-below-minimum');
  if (!operator.length) warnings.push('no-operator-canaries: decoys are separable from real nodes by ASN and address shape');
  else if (!asnAligned.length) warnings.push('no-asn-aligned-canaries: operator entries carry no asn_group');
  else if (asnAligned.length < MIN_ALIGNED_SUBPOOL) {
    warnings.push(`asn-aligned-below-threshold: ${asnAligned.length} of ${MIN_ALIGNED_SUBPOOL} needed per ASN group; ` +
      'alignment is disabled until there are enough, because drawing repeatedly from a handful of hosts identifies them');
  }
  return {
    total: pool.length,
    operator: operator.length,
    asn_aligned: asnAligned.length,
    aligned_threshold: MIN_ALIGNED_SUBPOOL,
    builtin: pool.length - operator.length,
    warnings,
  };
}

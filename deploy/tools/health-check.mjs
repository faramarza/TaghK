#!/usr/bin/env node
/**
 * health-check.mjs — the things that fail silently. Run it from cron.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Every check here is for a condition that produces NO error anywhere until it
 * has already caused harm:
 *
 *   • key commitment expiring — issuance fails closed when no commitment covers
 *     the current epoch, so enrolment stops dead and existing users notice
 *     nothing until they need to re-enrol. This is the one operational trap the
 *     anchoring design introduces and it is the reason this script exists.
 *   • no operator canaries — decoys stay separable from real nodes by address
 *     shape, and a careful adversary can tell them apart.
 *   • unvalidated canary pool — decoys nobody has ever reached are inert, which
 *     is safe but useless, and it means the detector has less to work with than
 *     the numbers suggest.
 *   • no active nodes in a pool — users assigned to it get nothing.
 *
 * Exit 0 healthy, 1 warnings, 2 something is broken now.
 *
 *   DISTRIBUTOR_URL=… ADMIN_KEY=… COLLECTOR_URL=… COLLECTOR_ADMIN=… \
 *     node tools/health-check.mjs
 */
const DIST = process.env.DISTRIBUTOR_URL;
const COLL = process.env.COLLECTOR_URL;
const ADMIN = process.env.ADMIN_KEY;
const CADMIN = process.env.COLLECTOR_ADMIN;

if (!DIST || !ADMIN) {
  console.error('DISTRIBUTOR_URL and ADMIN_KEY are required');
  process.exit(2);
}

let worst = 0;
const say = (level, line) => {
  worst = Math.max(worst, level);
  console.log(`${['  ok', 'WARN', 'FAIL'][level]}  ${line}`);
};

async function get(base, key, path) {
  const r = await fetch(`${base}${path}`, { headers: { 'x-admin-key': key } });
  if (!r.ok) throw new Error(`HTTP ${r.status} — check the admin key and the URL`);
  return r.json();
}

try {
  const stats = await get(DIST, ADMIN, '/admin/stats');
  const kc = stats.key_commitment ?? {};

  if (!kc.issuing) {
    say(2, 'KEY COMMITMENT DOES NOT COVER THE CURRENT EPOCH — nobody can enrol.');
    say(2, '      Mint and upload one now: see 02-RUNBOOK.md §1 Stage 2.');
  } else if ((kc.epochs_of_headroom ?? 0) < 1) {
    say(1, `key commitment expires at the end of this epoch (serial ${kc.serial}).`);
    say(1, '      Mint the next one before it does, or enrolment stops.');
  } else {
    say(0, `key commitment serial ${kc.serial}, ${kc.epochs_of_headroom} epoch(s) of headroom`);
  }

  for (const [pool, counts] of Object.entries(stats.by_pool ?? {})) {
    if (counts.active === 0 && counts.blocked > 0) {
      say(2, `pool '${pool}' has no active nodes and ${counts.blocked} blocked — users here get nothing`);
    } else if (counts.active === 0) {
      say(1, `pool '${pool}' is empty`);
    } else {
      say(0, `pool '${pool}': ${counts.active} active, ${counts.blocked} blocked`);
    }
  }
} catch (e) {
  say(2, `distributor unreachable: ${e.message}`);
}

if (COLL && CADMIN) {
  try {
    const verdicts = await get(COLL, CADMIN, '/admin/verdicts');
    for (const w of verdicts.canary_pool?.warnings ?? []) say(1, `canary pool: ${w}`);
    if (!(verdicts.canary_pool?.warnings ?? []).length) {
      say(0, `canary pool healthy (${verdicts.canary_pool?.total} hosts)`);
    }

    const canary = await get(COLL, CADMIN, '/admin/canary-health');
    if (canary.validated < canary.required_slots * 4) {
      say(1, `only ${canary.validated} canary hosts have been reached from inside the country`);
      say(1, `      ${canary.pending} are unvalidated and therefore inert — prune or wait for probes`);
    } else {
      say(0, `${canary.validated} canary hosts validated, ${canary.pending} pending`);
    }

    const stale = (verdicts.verdicts ?? []).filter((v) => v.verdict === 'insufficient-data');
    if (stale.length) say(1, `${stale.length} node(s) have insufficient probe coverage`);
  } catch (e) {
    say(1, `collector unreachable: ${e.message}`);
  }
} else {
  say(1, 'COLLECTOR_URL / COLLECTOR_ADMIN not set — measurement plane not checked');
}

process.exit(worst);

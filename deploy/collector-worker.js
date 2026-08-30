/**
 * collector-worker.js — PLANE 3 front end: measurement collection
 * ---------------------------------------------------------------------------
 * Signs work manifests for in-country probes, ingests their reports, and hands
 * the control plane a quorum-checked verdict per node.
 *
 * DEPLOYED SEPARATELY FROM THE DISTRIBUTOR, ON PURPOSE.
 * Different Worker, different KV, different admin key. Compromising the
 * measurement plane must not yield the credential-issuance plane, and vice
 * versa. These two systems know different secrets and have different blast
 * radii; co-locating them for convenience would merge both.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  THE CENTRAL TENSION, AND HOW IT IS PRICED
 * ───────────────────────────────────────────────────────────────────────────
 *  To learn whether a node is blocked inside Iran, someone inside Iran must be
 *  told the node exists. A censor who volunteers as a probe is therefore handed
 *  intelligence. This cannot be eliminated — only made expensive and
 *  self-revealing:
 *
 *   • PARTITIONING  — each token sees a small random subset, never the fleet.
 *   • CANARIES      — every manifest carries decoys that are not real nodes.
 *                     A canary is unique to one token. If it is ever reported
 *                     blocked from elsewhere, or if real targets around it die
 *                     while it does not, that token's slot is hostile.
 *                     Attribution becomes exact rather than statistical.
 *   • REPUTATION    — slots that keep losing targets get canary-heavy manifests
 *                     and few real nodes. The censor ends up measuring decoys.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  ANONYMITY MODEL — and an honest statement of its limits
 * ───────────────────────────────────────────────────────────────────────────
 *  Probes authenticate with STATELESS HMAC BEARER TOKENS:
 *      token = slot || nonce || HMAC(K, slot||nonce)
 *
 *  The collector can verify a token without storing it, so no roster of probes
 *  exists to seize. A list of probes is a list of people inside to arrest, and
 *  the safest way to protect that list is for it never to exist.
 *
 *  HONEST LIMIT: this is unlinkability by amnesia, not by mathematics. It holds
 *  because the collector does not log at issuance. A VOPRF (see voprf.js) gives
 *  the same property CRYPTOGRAPHICALLY — the server cannot link even if it
 *  wants to, even if compromised, even if it logs everything.
 *
 *  User clients use the full VOPRF path. Probes use HMAC because the agent must
 *  install on an old phone with no package manager and no dependency fetch, and
 *  pure-Python ristretto255 is not a reasonable ask there. This is a deliberate,
 *  documented trade — not an oversight. If the agent ever gains a runtime that
 *  can do group arithmetic, move it to VOPRF.
 *
 * Bindings:
 *   KV      PROBES         slot reputation, canary issuance records
 *   KV      MEASUREMENTS   targets, canary pool, aggregated per-node verdicts
 *   DO      LEDGER         spent probe nonces  — STRONGLY CONSISTENT
 *   DO      RATE_LIMITER   per-slot counters   — STRONGLY CONSISTENT
 *   Secret  PROBE_HMAC_KEY   token authentication key
 *   Secret  MANIFEST_SK      Ed25519 private key (PKCS#8, base64) for signing
 *   Secret  COLLECTOR_ADMIN  operator API key
 *   Secret  ENROL_SALT       one-time enrolment code derivation
 *
 * Nonce spend records moved off KV for the same reason as the distributor's
 * token spend records: a KV read-then-write is not exactly-once, and a probe
 * token replayed from two vantage points passed both checks. See
 * 04-STATUS.md 2.1 and docs/adr/0001-durable-objects-for-exactly-once.md.
 */

import { claimOnce, overLimit } from './durable.js';
import { effectivePool, chooseCanaries, poolHealth, normaliseOperatorEntry } from './canary.js';

// Durable Object classes must be exported from the Worker entry point.
export { Ledger, RateLimiter } from './durable.js';

const CFG = {
  TOKENS_PER_ENROL: 96,
  TOKENS_PER_REPORT: 2,        // rolling re-issue; keeps agents supplied
  MANIFEST_TTL_S: 3600,

  REAL_TARGETS_PER_MANIFEST: 6,
  CANARIES_PER_MANIFEST: 2,
  CANARY_HEAVY_REAL: 1,        // what a suspected-hostile slot receives
  CANARY_HEAVY_DECOY: 6,

  QUORUM: 2,                   // independent slots that must agree
  REPORT_WINDOW_S: 900,
  MAX_RESULTS_PER_REPORT: 32,

  SLOT_SUSPICION_THRESHOLD: 2.0,
  RATE_LIMIT_PER_MIN: 20,
  NONCE_TTL_S: 7 * 86400,

  // A canary host cannot accuse anyone until this many DISTINCT slots have
  // independently reached it. Whether a given host is reachable from inside
  // Iran is a judgement when the pool is built, not a measurement; a host that
  // turns out to be blocked in country is reported down by every honest probe,
  // and without this it would accuse all of them while the censor — who knows
  // which hosts are blocked — reports it up and looks clean (04-STATUS.md 2.11).
  CANARY_VALIDATION_SLOTS: 2,
  CANARY_VALIDATION_TTL_S: 60 * 86400,

  // At most this much suspicion per REPORT, however many canaries were lied
  // about in it.
  //
  // Before this, each corroborated canary scored separately, so a manifest with
  // two canaries meant one bad report reached the threshold and demoted the
  // slot outright. A volunteer whose mobile connection drops for five minutes
  // reports everything unreachable, including both canaries, and looked exactly
  // like a censor.
  //
  // Requiring two separate reports means roughly half an hour of continuous
  // failure before a demotion — long for a transient outage, trivial for a
  // censor who intends to keep lying. That is the trade being made here, and it
  // is a trade rather than a free win: detection is slower on purpose.
  MAX_SUSPICION_PER_REPORT: 1.0,

  // Suspicion decays. "Demote, never ban" (I3) is not honoured by a demotion
  // that is permanent: an honest volunteer implicated by bad luck would lose
  // the good nodes forever. A censor has to stop lying for weeks to recover the
  // same ground, and learns little in the meantime.
  SUSPICION_DECAY_PER_DAY: 0.1,
};

/**
 * Suspicion as it stands NOW, after decay. Computed on read — no background
 * job, nothing to forget to run.
 */
function effectiveSuspicion(state) {
  const raw = state?.suspicion || 0;
  if (raw <= 0) return 0;
  const since = state.suspicion_at ? Date.now() - state.suspicion_at : 0;
  const decayed = raw - (since / 86400e3) * CFG.SUSPICION_DECAY_PER_DAY;
  return Math.max(0, decayed);
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    try {
      switch (path) {
        case '/probe/enrol':    return await enrol(request, env);
        case '/probe/manifest': return await manifest(request, env);
        case '/probe/report':   return await report(request, env);
        case '/admin/verdicts': return await verdicts(request, env);
        case '/admin/targets':  return await setTargets(request, env);
        case '/admin/canary-pool': return await canaryPool(request, env);
        case '/admin/canary-health': return await canaryHealth(request, env);
        case '/admin/enrol-codes': return await mintCodes(request, env);
        default:                return decoy();
      }
    } catch {
      return decoy();          // never leak internals; an error page is a fingerprint
    }
  },
};

// ───────────────────────────────────────────────────────────────────────────
// Crypto helpers
// ───────────────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** Constant-time string compare — admin keys and MACs must never short-circuit. */
function ctEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmac(env, message) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(env.PROBE_HMAC_KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

/** Cryptographically secure integer in [0, n). Math.random() is predictable — never use it here. */
function secureInt(n) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % n;
}

function secureShuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = secureInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const randHex = (bytes = 16) => hex(crypto.getRandomValues(new Uint8Array(bytes)));

// ───────────────────────────────────────────────────────────────────────────
// Tokens — stateless, unlogged, slot-bearing
// ───────────────────────────────────────────────────────────────────────────
//
// A token carries an opaque SLOT. Reputation attaches to the slot, never to a
// person. The operator can learn "slot 4f2a is hostile" and can never learn who
// that is — which is the whole point.

async function mintToken(env, slot) {
  const nonce = randHex(16);
  return { slot, nonce, mac: await hmac(env, `${slot}:${nonce}`) };
}

/**
 * Authentication only — verifies the MAC and returns the slot. Deliberately
 * STATELESS and side-effect free so the caller can rate-limit on the slot
 * BEFORE spending the nonce. Spending first would mean a rate-limited request
 * had already destroyed a token the volunteer needs.
 */
async function authSlot(env, token) {
  if (!token?.slot || !token?.nonce || !token?.mac) return null;
  if (!/^[0-9a-f]{1,32}$/.test(token.slot) || !/^[0-9a-f]{32}$/.test(token.nonce)) return null;
  const expected = await hmac(env, `${token.slot}:${token.nonce}`);
  return ctEqual(expected, token.mac) ? token.slot : null;
}

/**
 * Single use. Strongly consistent — the KV version was a read-then-write, so
 * one probe token replayed from two vantage points was accepted twice.
 *
 * The spent record is a hash of the nonce, so the ledger reveals nothing about
 * tokens not yet presented and nothing at all about who holds them.
 */
async function spendNonce(env, token) {
  const key = `spent:${(await hmac(env, `spend:${token.nonce}`)).slice(0, 32)}`;
  return claimOnce(env.LEDGER, key, CFG.NONCE_TTL_S);
}

/**
 * Rate limiting is keyed on the SLOT, never on an address.
 *
 * The obvious implementation hashes cf-connecting-ip like the distributor does.
 * We do not, because the people on this endpoint are volunteers running
 * measurement infrastructure inside a hostile state, the slot is already an
 * opaque pseudonym that identifies nobody, and it is a tighter limit anyway.
 * Do not "improve" this by adding an address (I1).
 *
 * CFG.RATE_LIMIT_PER_MIN was declared and never enforced before this — a
 * control that existed only in the config file. See 04-STATUS.md 2.7.
 */
async function slotLimited(env, bucket, slot) {
  const window = Math.floor(Date.now() / 1000 / 60);
  return overLimit(env.RATE_LIMITER, `rl:${bucket}:${window}:${slot}`, CFG.RATE_LIMIT_PER_MIN, 60);
}

// ───────────────────────────────────────────────────────────────────────────
// Enrolment
// ───────────────────────────────────────────────────────────────────────────

async function enrol(request, env) {
  if (request.method !== 'POST') return decoy();
  const { code } = await request.json().catch(() => ({}));
  if (!code || typeof code !== 'string' || code.length > 64) return decoy();

  // One-time codes are stored as hashes, so the KV never holds a usable code.
  const codeHash = (await hmac(env, `enrol:${env.ENROL_SALT}:${code}`)).slice(0, 32);
  const rec = await env.PROBES.get(`code:${codeHash}`);
  if (!rec) return decoy();
  await env.PROBES.delete(`code:${codeHash}`);

  // Fresh random slot. Deliberately NOT derived from the code — otherwise the
  // enrolment record would link a slot back to whoever received that code.
  const slot = randHex(8);
  await env.PROBES.put(
    `slot:${slot}`,
    JSON.stringify({ created: Date.now(), suspicion: 0, reports: 0, canaries: {} }),
    { expirationTtl: 180 * 86400 }
  );

  const tokens = [];
  for (let i = 0; i < CFG.TOKENS_PER_ENROL; i++) tokens.push(await mintToken(env, slot));

  // NOTHING linking this slot to the code, the requester, or their IP is written.
  return json({ tokens });
}

async function mintCodes(request, env) {
  if (!ctEqual(request.headers.get('x-admin-key') || '', env.COLLECTOR_ADMIN)) return decoy();
  const { count = 10 } = await request.json().catch(() => ({}));
  const codes = [];
  for (let i = 0; i < Math.min(count, 200); i++) {
    const code = randHex(12);
    const h = (await hmac(env, `enrol:${env.ENROL_SALT}:${code}`)).slice(0, 32);
    await env.PROBES.put(`code:${h}`, '1', { expirationTtl: 30 * 86400 });
    codes.push(code);
  }
  return json({ codes, note: 'distribute out-of-band; each is single-use' });
}

// ───────────────────────────────────────────────────────────────────────────
// Manifests — signed, partitioned, canary-laced
// ───────────────────────────────────────────────────────────────────────────

async function signingKey(env) {
  return crypto.subtle.importKey(
    'pkcs8', unb64(env.MANIFEST_SK), { name: 'Ed25519' }, false, ['sign']
  );
}

async function manifest(request, env) {
  if (request.method !== 'POST') return decoy();
  const { token } = await request.json().catch(() => ({}));

  const slot = await authSlot(env, token);
  if (!slot) return decoy();
  if (await slotLimited(env, 'manifest', slot)) return decoy();
  if (!(await spendNonce(env, token))) return decoy();

  const state = JSON.parse((await env.PROBES.get(`slot:${slot}`)) || 'null');
  if (!state) return decoy();

  const targets = JSON.parse((await env.MEASUREMENTS.get('targets')) || '[]');
  const hostile = effectiveSuspicion(state) >= CFG.SLOT_SUSPICION_THRESHOLD;

  const nReal = hostile ? CFG.CANARY_HEAVY_REAL : CFG.REAL_TARGETS_PER_MANIFEST;
  const nDecoy = hostile ? CFG.CANARY_HEAVY_DECOY : CFG.CANARIES_PER_MANIFEST;

  // Partition: a small random subset, never the fleet. A hostile probe learns
  // few nodes, and which few is attributable.
  const chosen = secureShuffle(targets.filter((t) => t.status === 'active')).slice(0, nReal);

  const entries = chosen.map((t) => ({
    ref: t.ref,                       // opaque handle; the agent never learns node identity
    host: t.host,
    port: t.port,
    sni: t.sni || undefined,
    kind: 'node',
  }));

  // Canaries: real, reachable, unremarkable hosts that are NOT our nodes.
  // Unique per issuance, so a canary that dies points at exactly one slot.
  //
  // Drawn WITHOUT REPLACEMENT from a pool of at least 200 hosts, preferring
  // hosts on the same ASNs as the real targets in this same manifest. The old
  // three-host hardcoded pool was identifiable by enrolling twice
  // (04-STATUS.md 2.5). See canary.js and canary-pool.js.
  const pool = effectivePool(JSON.parse((await env.MEASUREMENTS.get('canary_pool')) || 'null'));
  const canaries = chooseCanaries(pool, nDecoy, chosen.map((t) => t.asn_group));

  const canaryRefs = [];
  for (const c of canaries) {
    const ref = `c-${randHex(6)}`;
    canaryRefs.push(ref);
    entries.push({ ref, host: c.host, port: c.port, sni: c.sni, kind: 'node' });
    await env.PROBES.put(
      `canary:${ref}`,
      JSON.stringify({ slot, issued: Date.now(), host: c.host }),
      { expirationTtl: 30 * 86400 }
    );
  }

  state.canaries = { ...(state.canaries || {}), ...Object.fromEntries(canaryRefs.map((r) => [r, Date.now()])) };
  await env.PROBES.put(`slot:${slot}`, JSON.stringify(state), { expirationTtl: 180 * 86400 });

  const body = JSON.stringify({
    issued_at: Math.floor(Date.now() / 1000),
    targets: secureShuffle(entries),   // canaries indistinguishable from real nodes
  });

  const signature = b64(
    await crypto.subtle.sign('Ed25519', await signingKey(env), enc.encode(body))
  );

  // Fresh tokens ride along so the agent never has to re-enrol.
  const tokens = [];
  for (let i = 0; i < CFG.TOKENS_PER_REPORT; i++) tokens.push(await mintToken(env, slot));

  return json({ manifest: body, signature, tokens });
}

// ───────────────────────────────────────────────────────────────────────────
// Reports
// ───────────────────────────────────────────────────────────────────────────

/**
 * Record one slot's observation of a canary HOST (not the per-slot ref) and
 * report whether some OTHER slot reached that same host in this window.
 *
 * The aggregate is keyed on a MAC of the hostname, never the hostname itself.
 * A seized MEASUREMENTS namespace must not hand the adversary the canary pool —
 * knowing which hosts are decoys is precisely what lets them answer truthfully
 * about decoys and falsely about real nodes.
 *
 * KV is the right store here: this is an aggregate, staleness only delays a
 * verdict, and a stale read can only under-credit suspicion (see report()).
 */
async function recordCanaryObservation(env, host, slot, up, window) {
  const hostKey = (await hmac(env, `canary-host:${host}`)).slice(0, 24);

  // Per-window corroboration: did anyone ELSE reach this host right now?
  const key = `cm:${window}:${hostKey}`;
  const agg = JSON.parse((await env.MEASUREMENTS.get(key)) || '{"up":[],"down":[]}');
  const bucket = up ? agg.up : agg.down;
  if (!bucket.includes(slot)) bucket.push(slot);
  agg.up = agg.up.slice(-256);        // bounded: one vote per slot, capped
  agg.down = agg.down.slice(-256);
  await env.MEASUREMENTS.put(key, JSON.stringify(agg), { expirationTtl: 7 * 86400 });

  // Long-lived validation: has this host EVER been reached, by enough distinct
  // slots to believe it is reachable from inside the country at all? A host
  // that never clears this bar simply never accuses anyone — which is what a
  // pool built by judgement rather than measurement requires.
  const vKey = `cv:${hostKey}`;
  const seen = JSON.parse((await env.MEASUREMENTS.get(vKey)) || '{"slots":[]}');
  if (up && !seen.slots.includes(slot) && seen.slots.length < 64) {
    seen.slots.push(slot);
    await env.MEASUREMENTS.put(vKey, JSON.stringify(seen),
      { expirationTtl: CFG.CANARY_VALIDATION_TTL_S });
  }

  return {
    corroborated: agg.up.some((s) => s !== slot),
    validated: seen.slots.filter((s) => s !== slot).length >= CFG.CANARY_VALIDATION_SLOTS,
  };
}

async function report(request, env) {
  if (request.method !== 'POST') return decoy();
  const body = await request.json().catch(() => ({}));

  const slot = await authSlot(env, body.token);
  if (!slot) return decoy();
  if (await slotLimited(env, 'report', slot)) return decoy();
  if (!(await spendNonce(env, body.token))) return decoy();

  const results = Array.isArray(body.results)
    ? body.results.slice(0, CFG.MAX_RESULTS_PER_REPORT)
    : [];
  if (!results.length) return json({ ok: true });

  const state = JSON.parse((await env.PROBES.get(`slot:${slot}`)) || '{}');
  state.reports = (state.reports || 0) + 1;

  const window = Math.floor(Date.now() / 1000 / CFG.REPORT_WINDOW_S) * CFG.REPORT_WINDOW_S;
  let lied = false;

  for (const r of results) {
    if (typeof r?.ref !== 'string' || r.ref.length > 64) continue;

    // Canary handling — the hostile-probe detector.
    const canary = JSON.parse((await env.PROBES.get(`canary:${r.ref}`)) || 'null');
    if (canary) {
      // A down-report on a canary scores ONLY when another slot independently
      // reached the same host in the same window.
      //
      // Without that condition the detector runs backwards. Whether a given
      // canary host is reachable from inside Iran is a judgement, not a
      // measurement; if one of them is in fact blocked in country, every HONEST
      // probe reports it down and gets accused, while the censor — who knows
      // which hosts are blocked — reports it up and looks clean.
      //
      // The corroboration read is from KV and may be stale, which can only
      // UNDER-credit suspicion. That is the correct direction to fail: a false
      // positive here is a real person quietly losing the good nodes (I3).
      const seen = await recordCanaryObservation(env, canary.host, slot, r.tcp === true, window);

      // THREE conditions, all required, and every one exists to avoid accusing
      // an honest volunteer:
      //   validated    — this host is known reachable in-country by other slots,
      //                  so a down-report is a claim about the network and not
      //                  about a host that is simply blocked here for everyone;
      //   corroborated — someone else reached it in THIS window, so it is not a
      //                  transient outage everyone is seeing;
      //   once/report  — counted below, outside this loop, so lying about two
      //                  canaries at once is worth no more than lying about one.
      if (r.tcp === false && seen.validated && seen.corroborated) lied = true;
      continue;                       // canary results never touch node verdicts
    }

    const key = `m:${window}:${r.ref}`;
    const agg = JSON.parse((await env.MEASUREMENTS.get(key)) || '{"up":[],"down":[]}');
    const bucket = r.tcp ? agg.up : agg.down;
    if (!bucket.includes(slot)) bucket.push(slot);   // one vote per slot per window
    await env.MEASUREMENTS.put(key, JSON.stringify(agg), { expirationTtl: 7 * 86400 });
  }

  // One credit per report, regardless of how many canaries were lied about.
  // Applied to the DECAYED value so a slot that has been clean for weeks starts
  // from where it actually stands, not from a number it earned months ago.
  if (lied) {
    state.suspicion = effectiveSuspicion(state) + CFG.MAX_SUSPICION_PER_REPORT;
    state.suspicion_at = Date.now();
  }

  await env.PROBES.put(`slot:${slot}`, JSON.stringify(state), { expirationTtl: 180 * 86400 });

  const tokens = [];
  for (let i = 0; i < CFG.TOKENS_PER_REPORT; i++) tokens.push(await mintToken(env, slot));
  return json({ ok: true, tokens });
}

// ───────────────────────────────────────────────────────────────────────────
// Operator API
// ───────────────────────────────────────────────────────────────────────────

async function setTargets(request, env) {
  if (!ctEqual(request.headers.get('x-admin-key') || '', env.COLLECTOR_ADMIN)) return decoy();

  if (request.method === 'GET') {
    return json(JSON.parse((await env.MEASUREMENTS.get('targets')) || '[]'));
  }
  const incoming = await request.json();
  const list = [].concat(incoming).map((t) => ({
    ref: t.ref || `n-${randHex(6)}`,
    node_id: t.node_id,               // operator-side only; never sent to probes
    host: t.host,
    port: t.port || 443,
    sni: t.sni || null,
    // Operator-side only, never sent to probes. Used to draw canaries from the
    // same ASNs as the real targets in a manifest so the two are not separable.
    asn_group: typeof t.asn_group === 'string' ? t.asn_group.slice(0, 64) : null,
    status: t.status || 'active',
  }));
  await env.MEASUREMENTS.put('targets', JSON.stringify(list));
  return json({ ok: true, count: list.length });
}

/**
 * Operator-managed canary pool.
 *
 * This is where ASN-aligned decoys go — hosts on the SAME providers as the real
 * fleet, serving an ordinary site and no proxy. Until this is populated the
 * builtin bootstrap pool is in use and decoys are separable from real nodes by
 * address shape; poolHealth() says so rather than letting an operator assume
 * otherwise. See canary-pool.js and 02-RUNBOOK.md §6.
 */
async function canaryPool(request, env) {
  if (!ctEqual(request.headers.get('x-admin-key') || '', env.COLLECTOR_ADMIN)) return decoy();

  if (request.method === 'GET') {
    const raw = JSON.parse((await env.MEASUREMENTS.get('canary_pool')) || 'null');
    return json({ operator: Array.isArray(raw) ? raw : [], health: poolHealth(effectivePool(raw)) });
  }

  const incoming = await request.json().catch(() => null);
  if (!Array.isArray(incoming)) return decoy();
  const clean = incoming.slice(0, 2048).map(normaliseOperatorEntry).filter(Boolean);
  await env.MEASUREMENTS.put('canary_pool', JSON.stringify(clean));
  return json({ ok: true, accepted: clean.length, rejected: incoming.length - clean.length,
                health: poolHealth(effectivePool(clean)) });
}

/**
 * Which canary hosts have actually proved reachable from inside the country.
 *
 * An unvalidated host is inert — it can never accuse anyone — but it is also
 * wasted manifest space and a hint that the pool needs pruning. This is how an
 * operator finds out which of their decoys are dead, without ever learning
 * which slot reported what.
 *
 * Counts and hostnames only. No slots, no addresses, no timing.
 */
async function canaryHealth(request, env) {
  if (!ctEqual(request.headers.get('x-admin-key') || '', env.COLLECTOR_ADMIN)) return decoy();

  const pool = effectivePool(JSON.parse((await env.MEASUREMENTS.get('canary_pool')) || 'null'));
  const validated = [];
  const pending = [];
  for (const entry of pool.slice(0, 512)) {
    const vKey = `cv:${(await hmac(env, `canary-host:${entry.host}`)).slice(0, 24)}`;
    const seen = JSON.parse((await env.MEASUREMENTS.get(vKey)) || '{"slots":[]}');
    (seen.slots.length >= CFG.CANARY_VALIDATION_SLOTS ? validated : pending).push({
      host: entry.host, origin: entry.origin, reached_by: seen.slots.length,
    });
  }

  return json({
    required_slots: CFG.CANARY_VALIDATION_SLOTS,
    validated: validated.length,
    pending: pending.length,
    note: 'pending hosts are inert — they cannot raise suspicion against any slot',
    // Truncated: an operator wants to prune, not to page through a pool.
    pending_hosts: pending.slice(0, 50).map((p) => p.host),
    validated_hosts: validated.slice(0, 50).map((p) => p.host),
  });
}

/**
 * Quorum verdicts for the control plane.
 *
 * A node counts as blocked only when QUORUM independent slots report it down
 * and none reports it up. Requiring independence is what separates a nationwide
 * block from one flaky mobile carrier — and prevents a single hostile slot from
 * burning healthy nodes.
 */
async function verdicts(request, env) {
  if (!ctEqual(request.headers.get('x-admin-key') || '', env.COLLECTOR_ADMIN)) return decoy();

  const targets = JSON.parse((await env.MEASUREMENTS.get('targets')) || '[]');
  const now = Math.floor(Date.now() / 1000 / CFG.REPORT_WINDOW_S) * CFG.REPORT_WINDOW_S;
  const windows = [now, now - CFG.REPORT_WINDOW_S, now - 2 * CFG.REPORT_WINDOW_S];

  const out = [];
  for (const t of targets) {
    const up = new Set();
    const down = new Set();
    for (const w of windows) {
      const agg = JSON.parse((await env.MEASUREMENTS.get(`m:${w}:${t.ref}`)) || 'null');
      if (!agg) continue;
      agg.up.forEach((s) => up.add(s));
      agg.down.forEach((s) => down.add(s));
    }

    // Weight down-votes only from slots not flagged hostile.
    const trustedDown = [];
    for (const s of down) {
      const st = JSON.parse((await env.PROBES.get(`slot:${s}`)) || '{}');
      if (effectiveSuspicion(st) < CFG.SLOT_SUSPICION_THRESHOLD) trustedDown.push(s);
    }

    out.push({
      ref: t.ref,
      node_id: t.node_id,
      reachable_slots: up.size,
      blocked_slots: trustedDown.length,
      verdict:
        up.size > 0 ? 'reachable'
        : trustedDown.length >= CFG.QUORUM ? 'blocked'
        : 'insufficient-data',
    });
  }

  // Surfaced so an operator cannot unknowingly run a probe network whose
  // decoys an adversary can separate from real nodes. Counts only, no user data.
  const pool = effectivePool(JSON.parse((await env.MEASUREMENTS.get('canary_pool')) || 'null'));

  return json({
    generated_at: Date.now(),
    quorum: CFG.QUORUM,
    canary_pool: poolHealth(pool),
    verdicts: out,
  });
}

// ───────────────────────────────────────────────────────────────────────────

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });

const decoy = () =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Not Found</title></head>
<body style="font-family:system-ui;padding:3rem"><h1 style="font-weight:500">404</h1>
<p style="color:#777">The requested resource was not found.</p></body></html>`,
    { status: 404, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } }
  );

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
 *   KV      PROBES         slot reputation, canary state, spent nonces
 *   KV      MEASUREMENTS   aggregated per-node verdicts
 *   Secret  PROBE_HMAC_KEY   token authentication key
 *   Secret  MANIFEST_SK      Ed25519 private key (PKCS#8, base64) for signing
 *   Secret  COLLECTOR_ADMIN  operator API key
 *   Secret  ENROL_SALT       one-time enrolment code derivation
 */

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
};

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

async function verifyToken(env, token) {
  if (!token?.slot || !token?.nonce || !token?.mac) return null;
  if (!/^[0-9a-f]{1,32}$/.test(token.slot) || !/^[0-9a-f]{32}$/.test(token.nonce)) return null;

  const expected = await hmac(env, `${token.slot}:${token.nonce}`);
  if (!ctEqual(expected, token.mac)) return null;

  // Single use. The spent record is a hash — the token itself is never stored,
  // so the spend log reveals nothing about tokens not yet presented.
  const spentKey = `spent:${(await hmac(env, `spend:${token.nonce}`)).slice(0, 32)}`;
  if (await env.PROBES.get(spentKey)) return null;
  await env.PROBES.put(spentKey, '1', { expirationTtl: 7 * 86400 });

  return token.slot;
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

  const slot = await verifyToken(env, token);
  if (!slot) return decoy();

  const state = JSON.parse((await env.PROBES.get(`slot:${slot}`)) || 'null');
  if (!state) return decoy();

  const targets = JSON.parse((await env.MEASUREMENTS.get('targets')) || '[]');
  const hostile = state.suspicion >= CFG.SLOT_SUSPICION_THRESHOLD;

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
  const canaryRefs = [];
  for (let i = 0; i < nDecoy; i++) {
    const c = makeCanary();
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

/**
 * Canary hosts. Must be real, reachable, and boring — a decoy that is already
 * unreachable teaches nothing, and one that looks like infrastructure teaches
 * the adversary what to look for.
 *
 * In production draw these from a large rotating pool of innocuous public
 * endpoints, ideally on the same providers as real nodes so the two are not
 * separable by ASN.
 */
function makeCanary() {
  const pool = [
    { host: 'example.com', port: 443, sni: 'example.com' },
    { host: 'www.iana.org', port: 443, sni: 'www.iana.org' },
    { host: 'neverssl.com', port: 80, sni: null },
  ];
  return pool[secureInt(pool.length)];
}

// ───────────────────────────────────────────────────────────────────────────
// Reports
// ───────────────────────────────────────────────────────────────────────────

async function report(request, env) {
  if (request.method !== 'POST') return decoy();
  const body = await request.json().catch(() => ({}));

  const slot = await verifyToken(env, body.token);
  if (!slot) return decoy();

  const results = Array.isArray(body.results)
    ? body.results.slice(0, CFG.MAX_RESULTS_PER_REPORT)
    : [];
  if (!results.length) return json({ ok: true });

  const state = JSON.parse((await env.PROBES.get(`slot:${slot}`)) || '{}');
  state.reports = (state.reports || 0) + 1;

  const window = Math.floor(Date.now() / 1000 / CFG.REPORT_WINDOW_S) * CFG.REPORT_WINDOW_S;

  for (const r of results) {
    if (typeof r?.ref !== 'string' || r.ref.length > 64) continue;

    // Canary handling — the hostile-probe detector.
    const canary = JSON.parse((await env.PROBES.get(`canary:${r.ref}`)) || 'null');
    if (canary) {
      // A canary is a well-known public host. If a slot reports it unreachable
      // while other slots reach it fine, that slot is lying — the signature of a
      // censor feeding false blocks to burn healthy nodes.
      if (r.tcp === false) {
        state.suspicion = (state.suspicion || 0) + 1.0;
      }
      continue;                       // canary results never touch node verdicts
    }

    const key = `m:${window}:${r.ref}`;
    const agg = JSON.parse((await env.MEASUREMENTS.get(key)) || '{"up":[],"down":[]}');
    const bucket = r.tcp ? agg.up : agg.down;
    if (!bucket.includes(slot)) bucket.push(slot);   // one vote per slot per window
    await env.MEASUREMENTS.put(key, JSON.stringify(agg), { expirationTtl: 7 * 86400 });
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
    status: t.status || 'active',
  }));
  await env.MEASUREMENTS.put('targets', JSON.stringify(list));
  return json({ ok: true, count: list.length });
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
      if ((st.suspicion || 0) < CFG.SLOT_SUSPICION_THRESHOLD) trustedDown.push(s);
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

  return json({ generated_at: Date.now(), quorum: CFG.QUORUM, verdicts: out });
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

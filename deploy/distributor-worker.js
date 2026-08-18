/**
 * distributor-worker.js — PLANE 1: anonymous, accountable credential distribution
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Cloudflare Worker. Runs on *.workers.dev and custom domains, both of which
 * ride CDN infrastructure a censor generally cannot afford to block.
 * THE DISTRIBUTION CHANNEL MUST LIVE IN A DIFFERENT FAILURE DOMAIN THAN THE
 * TRANSPORT IT DESCRIBES — if your subscription URL dies with your proxies you
 * are hand-delivering configs to millions of people.
 *
 * FOUNDING ASSUMPTION: THE CENSOR IS A USER. They register, solve the
 * proof-of-work, receive credentials, and block them. Nothing here tries to
 * prevent that. It makes it expensive, slow, and self-incriminating.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  THE CENTRAL PROBLEM: reputation requires memory, memory endangers users
 * ───────────────────────────────────────────────────────────────────────────
 *  To demote whoever is leaking nodes, the system must remember something
 *  across requests. To keep users safe, it must remember nothing that could
 *  identify them. These pull in opposite directions, and most systems resolve
 *  the tension by quietly choosing surveillance.
 *
 *  Resolution here — SEPARATE ENTITLEMENT FROM REPUTATION:
 *
 *    ENTITLEMENT is carried by VOPRF tokens (voprf.js). Cryptographically
 *    unlinkable: the server cannot connect a redemption to the issuance it came
 *    from, cannot tell two redemptions apart, and this holds even if the server
 *    is compromised and logs everything. It is mathematics, not policy.
 *
 *    REPUTATION is carried by a LINEAGE: an opaque random ID proven by holding
 *    the previous credential set. It accrues suspicion when its nodes get
 *    blocked. It is a pseudonym with NO link to a person, device, phone number,
 *    or IP address.
 *
 *  Stated honestly: this is PSEUDONYMOUS, NOT FULLY ANONYMOUS. A lineage is
 *  linkable to itself over time. What it is not linkable to is a human being.
 *  That is the strongest position achievable while retaining any ability to
 *  respond to leaks, and pretending otherwise would be dishonest.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  WHAT THIS SYSTEM DELIBERATELY DOES NOT DO
 * ───────────────────────────────────────────────────────────────────────────
 *  NO device fingerprinting. NO phone numbers. NO IP logging. NO per-user
 *  connection records. NO identity bans. NO analytics.
 *
 *  Fingerprinting devices and banning the implicated ones is the obvious next
 *  step, and it is wrong on four counts:
 *
 *   1. IT DOES NOT WORK — the state has unlimited devices: emulators, VMs,
 *      burners, phones seized from detainees. Fingerprints are cheap to spoof.
 *   2. IT PUNISHES THE RIGHT PEOPLE — honest users wipe phones before
 *      checkpoints, reinstall after crackdowns, borrow devices, run old
 *      hardware. The asymmetry runs backwards.
 *   3. IT BUILDS THE ARREST LIST — device IDs plus proven use of a
 *      circumvention tool, seizable and subpoenable. People die for that table.
 *   4. IT DESTROYS TRUST — a public tool known to collect device identifiers is
 *      correctly assumed to be a honeypot, and adoption collapses.
 *
 *  RULE: DO NOT COLLECT WHAT YOU WOULD NOT WANT SEIZED.
 *
 *  Device BINDING (enclave keypair, challenge-response) is retained and is a
 *  different thing entirely: it stops a harvested credential being resold to a
 *  crowd, while revealing nothing about the hardware. Binding a credential to
 *  hardware is safe. Identifying the hardware is not.
 *
 * STORAGE SPLIT — read this before moving anything between the two.
 *
 *   KV is EVENTUALLY CONSISTENT. A read may be up to ~60s stale and colos read
 *   independently. That is fine for read-mostly inventory on the hot path and
 *   fatal for anything that must happen at most once. Token spend records, PoW
 *   single-use, and rate limiters therefore live in Durable Objects
 *   (durable.js), where the same key is served by exactly one instance
 *   world-wide and read-modify-write is atomic. See 04-STATUS.md defects 2.1
 *   and 2.2 and docs/adr/0001-durable-objects-for-exactly-once.md.
 *
 * Bindings:
 *   KV      ACCOUNTS      lineage state
 *   KV      NODES         inventory, reverse index, fallbacks
 *   DO      LEDGER        spent tokens, single-use PoW  — STRONGLY CONSISTENT
 *   DO      RATE_LIMITER  request counters              — STRONGLY CONSISTENT
 *   Secret  ADMIN_KEY  operator API auth
 *   Secret  KEY_SALT   hashing pepper — SEPARATE from ADMIN_KEY so that
 *                      rotating the admin key does not invalidate every hash
 *   Secret  VOPRF_SK   VOPRF secret key (see voprf.js generateKey())
 */

import { issue, verifyToken as voprfVerify, spendKey, timingSafeEqual } from './voprf.js';
import { claimOnce, overLimit } from './durable.js';

// Durable Object classes must be exported from the Worker entry point.
export { Ledger, RateLimiter } from './durable.js';

// ───────────────────────────────────────────────────────────────────────────
// Tunables
// ───────────────────────────────────────────────────────────────────────────

const CFG = {
  // Proof-of-work, in leading zero bits of SHA-256. ~18 bits is a second or two
  // on a phone: negligible once, ruinous across a hundred thousand accounts.
  POW_BITS_NEW: 18,
  POW_BITS_RENEW: 12,
  POW_TTL_S: 600,

  TOKENS_PER_ISSUE: 16,
  MAX_BLIND_BATCH: 32,

  NODES_PER_LINEAGE: 3,
  TRUST_AGE_MS: { standard: 24 * 3600e3, protected: 14 * 86400e3 },
  SUSPICION_THRESHOLD: 3.0,
  SUBSCRIPTION_TTL_S: 3600,

  REQUIRE_DEVICE_BINDING: true,
  DEVICE_SIG_SKEW_MS: 5 * 60e3,

  RATE_WINDOW_S: 60,
  RATE_MAX_CHALLENGE: 30,
  RATE_MAX_ISSUE: 10,

  // How long a spend record is retained. A token presented after this window
  // would be accepted again — see 04-STATUS.md defect 2.6. Do not shorten it
  // without reading that entry first.
  SPEND_TTL_S: 30 * 86400,

  MAX_BODY_BYTES: 64 * 1024,
};

const POOLS = ['sacrificial', 'standard', 'protected'];

// ───────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    try {
      switch (true) {
        case path === '/api/challenge':        return await getChallenge(request, env);
        case path === '/api/issue':            return await issueTokens(request, env);
        case path === '/api/credentials':      return await getCredentials(request, env);
        case path.startsWith('/sub/'):         return await subscription(request, env, path);

        case path === '/admin/nodes':          return await adminNodes(request, env);
        case path === '/admin/report-blocked': return await adminReportBlocked(request, env, ctx);
        case path === '/admin/stats':          return await adminStats(request, env);
        case path === '/admin/fallbacks':      return await adminFallbacks(request, env);

        default:                               return decoy();
      }
    } catch {
      return decoy();   // never leak internals — an error page is a fingerprint
    }
  },
};

// ───────────────────────────────────────────────────────────────────────────
// Primitives
// ───────────────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

/** Constant-time string comparison. Admin keys must never short-circuit. */
function ctEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** CSPRNG integer. Math.random() is predictable and must never gate node selection. */
function secureInt(n) {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  return b[0] % n;
}

function secureShuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = secureInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const randHex = (n = 16) => toHex(crypto.getRandomValues(new Uint8Array(n)));

/** Peppered hash. Uses KEY_SALT, never ADMIN_KEY — admin rotation must not break stored digests. */
async function peppered(env, label, value) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(`${env.KEY_SALT}:${label}:${value}`));
  return toHex(d).slice(0, 32);
}

/** Bounded JSON parse. An unbounded body is a cheap denial-of-service. */
async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > CFG.MAX_BODY_BYTES) return null;
  const text = await request.text();
  if (text.length > CFG.MAX_BODY_BYTES) return null;
  try { return JSON.parse(text); } catch { return null; }
}

/** Base64 that survives non-ASCII. btoa() alone throws on multi-byte characters. */
function b64utf8(str) {
  const bytes = enc.encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * Coarse rate limiting keyed on a HASHED client hint.
 *
 * The hint is never stored in the clear and expires within the minute, so no
 * durable record of any address exists. This is abuse control, not logging.
 *
 * Counted in a Durable Object, not KV. The KV version was read-modify-write:
 * concurrent requests all read the same counter and all wrote n+1, so the
 * effective limit was roughly (configured limit x concurrency) and the control
 * did nothing under exactly the load it exists to handle (04-STATUS.md 2.2).
 *
 * Fails CLOSED — if the counter is unreachable the request is limited. An
 * outage must not open an unmetered harvesting window.
 */
async function rateLimited(request, env, bucket, max) {
  const hint = request.headers.get('cf-connecting-ip') || 'unknown';
  const window = Math.floor(Date.now() / 1000 / CFG.RATE_WINDOW_S);
  const key = `rl:${bucket}:${window}:${await peppered(env, 'rl', hint)}`;
  return overLimit(env.RATE_LIMITER, key, max, CFG.RATE_WINDOW_S);
}

// ───────────────────────────────────────────────────────────────────────────
// Proof of work — economic Sybil resistance, no identity required
// ───────────────────────────────────────────────────────────────────────────

/**
 * Challenges are STATELESS: the difficulty and expiry travel inside the
 * challenge and are bound by an HMAC under KEY_SALT, so a client cannot lower
 * its own difficulty or extend its own deadline.
 *
 * The previous design wrote `pow:<challenge>` to KV at issuance and deleted it
 * at redemption. That was wrong twice over. The delete was a read-then-write on
 * eventually consistent storage, so one solved challenge could be spent
 * concurrently in several colos; and the write itself was an unauthenticated
 * storage primitive an attacker could hammer for free. Nothing is written at
 * issuance now, and the single-use record is claimed in a Durable Object.
 *
 *   challenge = p1.<random>.<bits>.<expiry>.<mac>
 */
const POW_VERSION = 'p1';
const POW_RE = /^p1\.[0-9a-f]{48}\.\d{1,3}\.\d{1,12}\.[0-9a-f]{32}$/;

async function powMac(env, payload) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(`${env.KEY_SALT}:pow`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(payload))).slice(0, 32);
}

async function getChallenge(request, env) {
  if (await rateLimited(request, env, 'chal', CFG.RATE_MAX_CHALLENGE)) return decoy();

  const renew = new URL(request.url).searchParams.get('renew') === '1';
  const bits = renew ? CFG.POW_BITS_RENEW : CFG.POW_BITS_NEW;
  const expiry = Math.floor(Date.now() / 1000) + CFG.POW_TTL_S;
  const payload = `${POW_VERSION}.${randHex(24)}.${bits}.${expiry}`;

  return json({
    challenge: `${payload}.${await powMac(env, payload)}`,
    bits,
    algorithm: 'sha256-leading-zero-bits',
    expires_in: CFG.POW_TTL_S,
  });
}

async function consumePow(env, challenge, nonce) {
  if (typeof challenge !== 'string' || !POW_RE.test(challenge)) return false;
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(nonce)) return false;

  const parts = challenge.split('.');
  const mac = parts.pop();
  if (!ctEqual(await powMac(env, parts.join('.')), mac)) return false;

  const bits = Number(parts[2]);
  const expiry = Number(parts[3]);
  // The MAC already binds both, so these are defence in depth against a future
  // edit that lets an operator configure a nonsensical difficulty.
  if (!(bits >= CFG.POW_BITS_RENEW && bits <= 32)) return false;
  if (Math.floor(Date.now() / 1000) > expiry) return false;

  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', enc.encode(challenge + nonce))
  );
  let zeros = 0;
  for (const byte of digest) {
    if (byte === 0) { zeros += 8; continue; }
    zeros += Math.clz32(byte) - 24;
    break;
  }
  if (zeros < bits) return false;

  // Single use. Strongly consistent, so parallel submissions of one solved
  // challenge yield exactly one success. Claimed only after the work checks
  // out, so a wrong nonce cannot burn someone else's challenge.
  return claimOnce(env.LEDGER, `pow:${parts[1]}`, CFG.POW_TTL_S + 60);
}

// ───────────────────────────────────────────────────────────────────────────
// Device binding — cryptographic, never identifying
// ───────────────────────────────────────────────────────────────────────────
//
// The client generates a NON-EXTRACTABLE ECDSA P-256 keypair inside the phone's
// secure enclave (Secure Enclave / StrongBox) and sends only the public key. We
// learn no model, OS, IMEI, or advertising ID — a public key is an opaque point.
// We store only a peppered hash of it.
//
// Buys: a harvested credential or leaked subscription URL is useless without the
// enclave holding the private key, so one credential cannot be resold to a crowd.
// Is not: an identity, a ban primitive, or a tracking key. It cannot link two
// lineages and does not survive a reinstall. A censor can mint unlimited
// keypairs — that is fine; Sybil resistance is proof-of-work's job.

async function verifyDeviceSig(spkiB64, message, sigB64) {
  try {
    if (typeof spkiB64 !== 'string' || spkiB64.length > 512) return false;
    const key = await crypto.subtle.importKey(
      'spki', Uint8Array.from(atob(spkiB64), (c) => c.charCodeAt(0)),
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key,
      Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0)),
      enc.encode(message)
    );
  } catch {
    return false;
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Token issuance (VOPRF) — entitlement without identity
// ───────────────────────────────────────────────────────────────────────────

async function issueTokens(request, env) {
  if (request.method !== 'POST') return decoy();
  if (await rateLimited(request, env, 'issue', CFG.RATE_MAX_ISSUE)) return decoy();

  const body = await readJson(request);
  if (!body) return decoy();

  const { challenge, nonce, blinded, device_pubkey, device_sig } = body;
  if (!(await consumePow(env, challenge, nonce))) return json({ error: 'invalid' }, 403);

  if (CFG.REQUIRE_DEVICE_BINDING) {
    if (!device_pubkey || !device_sig) return json({ error: 'invalid' }, 400);
    if (!(await verifyDeviceSig(device_pubkey, challenge, device_sig)))
      return json({ error: 'invalid' }, 403);
  }

  if (!Array.isArray(blinded) || !blinded.length || blinded.length > CFG.MAX_BLIND_BATCH)
    return json({ error: 'invalid' }, 400);
  if (!blinded.every((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)))
    return json({ error: 'invalid' }, 400);

  // The server sees only uniformly random group elements here. It cannot link
  // any of these to a later redemption — that is the whole point of the blind.
  let result;
  try {
    result = issue(env.VOPRF_SK, blinded, CFG.MAX_BLIND_BATCH);
  } catch {
    return json({ error: 'invalid' }, 400);
  }

  return json({
    evaluated: result.evaluated,
    proof: result.proof,           // DLEQ — client MUST verify; see voprf.js
    public_key: result.public_key,
  });
}

async function redeem(env, token) {
  if (!token?.t || !token?.w) return false;
  if (!/^[0-9a-f]{64}$/.test(token.t) || !/^[0-9a-f]{64}$/.test(token.w)) return false;
  if (!voprfVerify(env.VOPRF_SK, token.t, token.w)) return false;

  // Double-spend check. The stored key is a peppered hash, so the spend log
  // reveals nothing about tokens that have not yet been presented.
  //
  // claimOnce() is a Durable Object insert-if-absent, NOT a KV read-then-write.
  // The KV version returned true in every colo that read the record before it
  // propagated, which let an adversary multiply their credential draw by their
  // number of vantage points — unbounded for a state actor. See 04-STATUS 2.1.
  return claimOnce(env.LEDGER, `spent:${spendKey(token.t, env.KEY_SALT)}`, CFG.SPEND_TTL_S);
}

// ───────────────────────────────────────────────────────────────────────────
// Credentials — reputation via lineage, never via identity
// ───────────────────────────────────────────────────────────────────────────

async function getCredentials(request, env) {
  if (request.method !== 'POST') return decoy();

  const body = await readJson(request);
  if (!body) return decoy();

  const { token, lineage, lineage_proof, device_pubkey } = body;

  // Anonymous entitlement.
  if (!(await redeem(env, token))) return json({ error: 'invalid' }, 403);

  // Continue an existing lineage, or start a fresh one.
  let state = null;
  let lineageId = null;

  if (lineage && typeof lineage === 'string' && /^[0-9a-f]{32}$/.test(lineage)) {
    state = JSON.parse((await env.ACCOUNTS.get(`lin:${lineage}`)) || 'null');
    // Continuity proof: holding the previous credential secret. Stops a censor
    // adopting a stranger's good reputation by guessing a lineage ID.
    if (state && ctEqual(await peppered(env, 'lin', lineage_proof || ''), state.proof_hash)) {
      lineageId = lineage;
    } else {
      state = null;
    }
  }

  if (!state) {
    lineageId = randHex(16);
    state = {
      created: Date.now(),
      suspicion: 0,
      survived: 0,
      assignments: [],
      proof_hash: null,
      device_hash: CFG.REQUIRE_DEVICE_BINDING && device_pubkey
        ? await peppered(env, 'dev', device_pubkey) : null,
      device_pubkey: device_pubkey || null,
    };
  }

  // Rotate the continuity secret on every issuance — a captured old secret
  // becomes useless immediately.
  const nextProof = randHex(24);
  state.proof_hash = await peppered(env, 'lin', nextProof);

  state.assignments = await assignNodes(env, state);
  state.updated = Date.now();

  await env.ACCOUNTS.put(`lin:${lineageId}`, JSON.stringify(state), {
    expirationTtl: 180 * 86400,
  });

  // Reverse index: node -> lineages. Without this, attribution requires scanning
  // every lineage in KV, which is both slow and a denial-of-service vector.
  for (const nid of state.assignments) {
    const k = `idx:${nid}`;
    const set = JSON.parse((await env.NODES.get(k)) || '[]');
    if (!set.includes(lineageId)) {
      set.push(lineageId);
      await env.NODES.put(k, JSON.stringify(set), { expirationTtl: 180 * 86400 });
    }
  }

  return json({
    lineage: lineageId,
    lineage_proof: nextProof,          // client stores this; required next time
    subscription: `${new URL(request.url).origin}/sub/${lineageId}`,
    poll_interval_s: CFG.SUBSCRIPTION_TTL_S,
  });
}

async function assignNodes(env, state) {
  const pool = poolFor(state);
  const inventory = JSON.parse((await env.NODES.get('inventory')) || '[]');
  const eligible = inventory.filter((n) => n.status === 'active' && n.pool === pool);
  if (!eligible.length) return state.assignments;

  // Random SUBSET, cryptographically shuffled. Partitioning is what makes a
  // block informative — if everyone holds every node, attribution learns nothing.
  return secureShuffle(eligible).slice(0, CFG.NODES_PER_LINEAGE).map((n) => n.id);
}

function poolFor(state) {
  if (state.suspicion >= CFG.SUSPICION_THRESHOLD) return 'sacrificial';
  const age = Date.now() - state.created;
  if (age >= CFG.TRUST_AGE_MS.protected && state.survived >= 5) return 'protected';
  if (age >= CFG.TRUST_AGE_MS.standard) return 'standard';
  return 'sacrificial';
}

// ───────────────────────────────────────────────────────────────────────────
// Subscription
// ───────────────────────────────────────────────────────────────────────────

async function subscription(request, env, path) {
  const id = path.slice('/sub/'.length);
  if (!/^[0-9a-f]{32}$/.test(id)) return decoy();

  const state = JSON.parse((await env.ACCOUNTS.get(`lin:${id}`)) || 'null');
  if (!state) return decoy();

  // Device binding: a leaked subscription URL is useless without a fresh
  // signature from the enclave that registered it. The timestamp is signed too,
  // so a captured signature cannot be replayed later.
  if (CFG.REQUIRE_DEVICE_BINDING && state.device_pubkey) {
    const ts = request.headers.get('x-device-ts');
    const sig = request.headers.get('x-device-sig');
    if (!ts || !sig) return decoy();
    if (!Number.isFinite(Number(ts))) return decoy();
    if (Math.abs(Date.now() - Number(ts)) > CFG.DEVICE_SIG_SKEW_MS) return decoy();
    if (!(await verifyDeviceSig(state.device_pubkey, `${id}:${ts}`, sig))) return decoy();
  }

  const inventory = JSON.parse((await env.NODES.get('inventory')) || '[]');
  const byId = Object.fromEntries(inventory.map((n) => [n.id, n]));

  // Silent self-heal: drop blocked nodes, top back up. The user does nothing.
  const live = state.assignments.filter((nid) => byId[nid]?.status === 'active');
  if (live.length < CFG.NODES_PER_LINEAGE) {
    state.assignments = await assignNodes(env, { ...state, assignments: live });
    await env.ACCOUNTS.put(`lin:${id}`, JSON.stringify(state), { expirationTtl: 180 * 86400 });
  }

  const uris = [];
  for (const nid of state.assignments) {
    const node = byId[nid];
    if (!node || node.status !== 'active') continue;

    const users = node.users || [];
    if (!users.length) continue;
    const cred = users[hashIndex(id, users.length)];
    if (!cred?.id) continue;

    // Tier A — CDN-fronted. Listed FIRST: under default-deny it is the only
    // thing that survives, and client failover tries entries in order.
    if (node.tier_a_cdn?.cdn_domain) {
      const t = node.tier_a_cdn;
      uris.push(
        `vless://${cred.id}@${t.cdn_domain}:443` +
        `?encryption=none&security=tls&type=ws&host=${t.cdn_domain}` +
        `&sni=${t.cdn_domain}&fp=chrome&path=${encodeURIComponent(t.ws_path)}` +
        `#A-${nid.slice(0, 6)}`
      );
    }

    // Tier D — direct REALITY. Throughput. fp=chrome (uTLS) is mandatory:
    // without it the ClientHello identifies a Go program regardless of the rest.
    if (node.tier_d_reality) {
      const t = node.tier_d_reality;
      const sid = t.short_ids?.[secureInt(t.short_ids.length)] ?? '';
      uris.push(
        `vless://${cred.id}@${node.ip}:${t.port}` +
        `?encryption=none&flow=${t.flow}&security=reality&type=tcp` +
        `&sni=${t.dest}&fp=chrome&pbk=${t.public_key}&sid=${sid}` +
        `#D-${nid.slice(0, 6)}`
      );
    }
  }

  // Infrastructure-riding fallbacks. These need nothing from us and cannot be
  // burned by our mistakes — the floor of the system.
  uris.push(...JSON.parse((await env.NODES.get('fallbacks')) || '[]'));

  return new Response(b64utf8(uris.join('\n')), {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'profile-update-interval': String(Math.floor(CFG.SUBSCRIPTION_TTL_S / 3600)),
    },
  });
}

// ───────────────────────────────────────────────────────────────────────────
// Operator API
// ───────────────────────────────────────────────────────────────────────────

const authed = (request, env) =>
  ctEqual(request.headers.get('x-admin-key') || '', env.ADMIN_KEY || ' ');

async function adminNodes(request, env) {
  if (!authed(request, env)) return decoy();

  if (request.method === 'GET') {
    return json(JSON.parse((await env.NODES.get('inventory')) || '[]'));
  }

  const incoming = await readJson(request);
  if (!incoming) return decoy();

  const inventory = JSON.parse((await env.NODES.get('inventory')) || '[]');
  for (const node of [].concat(incoming)) {
    node.id ||= randHex(8);
    node.status ||= 'active';
    node.pool = POOLS.includes(node.pool) ? node.pool : 'sacrificial';
    node.added ||= Date.now();
    const i = inventory.findIndex((n) => n.id === node.id);
    i >= 0 ? (inventory[i] = node) : inventory.push(node);
  }
  await env.NODES.put('inventory', JSON.stringify(inventory));
  return json({ ok: true, count: inventory.length });
}

/**
 * LEAK ATTRIBUTION.
 * Called when in-country probes reach quorum that a node is blocked. Uses the
 * reverse index rather than scanning all lineages — the naive scan is O(users)
 * per burn and is itself a denial-of-service vector.
 *
 * Honest users appear in one implicated set by bad luck. A censor appears in
 * every one. Over time the intersection converges.
 */
async function adminReportBlocked(request, env, ctx) {
  if (!authed(request, env)) return decoy();

  const body = await readJson(request);
  const nodeId = body?.node_id;
  if (typeof nodeId !== 'string') return decoy();

  const inventory = JSON.parse((await env.NODES.get('inventory')) || '[]');
  const node = inventory.find((n) => n.id === nodeId);
  if (!node) return json({ error: 'unknown' }, 404);

  node.status = 'blocked';
  node.blocked_at = Date.now();
  await env.NODES.put('inventory', JSON.stringify(inventory));

  // A burned PROTECTED node is far more incriminating — few lineages reach it.
  const weight = { sacrificial: 0.5, standard: 1.0, protected: 2.5 }[node.pool] ?? 1.0;
  const implicated = JSON.parse((await env.NODES.get(`idx:${nodeId}`)) || '[]');

  const work = (async () => {
    for (const lid of implicated) {
      const st = JSON.parse((await env.ACCOUNTS.get(`lin:${lid}`)) || 'null');
      if (!st) continue;
      st.suspicion = (st.suspicion || 0) + weight;
      await env.ACCOUNTS.put(`lin:${lid}`, JSON.stringify(st), { expirationTtl: 180 * 86400 });
    }
    await env.NODES.delete(`idx:${nodeId}`);
  })();

  ctx?.waitUntil ? ctx.waitUntil(work) : await work;

  // DEMOTION, NEVER A BAN. A false positive under a hostile government means
  // doing the censor's work. Suspicious lineages keep access — they simply stop
  // receiving good nodes.
  return json({ ok: true, node_id: nodeId, implicated: implicated.length, weight });
}

async function adminFallbacks(request, env) {
  if (!authed(request, env)) return decoy();
  if (request.method === 'GET') {
    return json(JSON.parse((await env.NODES.get('fallbacks')) || '[]'));
  }
  const list = await readJson(request);
  if (!Array.isArray(list)) return decoy();
  await env.NODES.put('fallbacks', JSON.stringify(list.slice(0, 32)));
  return json({ ok: true, count: list.length });
}

async function adminStats(request, env) {
  if (!authed(request, env)) return decoy();
  const inventory = JSON.parse((await env.NODES.get('inventory')) || '[]');
  return json({
    nodes: inventory.length,
    by_pool: Object.fromEntries(
      POOLS.map((p) => [p, {
        active: inventory.filter((n) => n.pool === p && n.status === 'active').length,
        blocked: inventory.filter((n) => n.pool === p && n.status === 'blocked').length,
      }])
    ),
    // Deliberately absent: user counts, connection stats, geography, anything
    // that would make this endpoint worth compromising.
  });
}

// ───────────────────────────────────────────────────────────────────────────

function hashIndex(str, mod) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
  return Math.abs(h) % mod;
}

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

/** Everything unrecognised, unauthorised, or malformed returns the same page.
 *  Distinct errors are a fingerprint that says "circumvention infrastructure". */
const decoy = () =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Not Found</title></head>
<body style="font-family:system-ui;padding:3rem"><h1 style="font-weight:500">404</h1>
<p style="color:#777">The requested resource was not found.</p></body></html>`,
    { status: 404, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } }
  );

export { timingSafeEqual };

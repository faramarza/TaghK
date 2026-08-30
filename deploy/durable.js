/**
 * durable.js — strongly consistent primitives (Durable Objects)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * WHY THIS FILE EXISTS
 *
 * Workers KV is eventually consistent: a read may serve a value up to ~60
 * seconds stale, and reads in different colos are independent. Every
 * read-then-write on KV is therefore a race, and three of this system's
 * security properties were built on exactly that pattern:
 *
 *   • double-spend prevention   `if (await KV.get(spent)) return false; KV.put(...)`
 *   • proof-of-work single use  `if (!await KV.get(pow)) return false; KV.delete(...)`
 *   • rate limiting             `n = await KV.get(k) + 1; KV.put(k, n)`
 *
 * Fire the same token at two colos simultaneously and both read "not spent".
 * Fire N requests at a rate limiter and all N read the same counter. This is
 * 04-STATUS.md defects 2.1 and 2.2, and it is exploitable rather than
 * theoretical: it multiplies an adversary's credential draw by their number of
 * vantage points, which for a state adversary is unbounded.
 *
 * Durable Objects fix it structurally rather than probabilistically. For a
 * given object ID there is exactly ONE instance in the world, requests to it
 * are delivered single-threaded, and the runtime's INPUT GATE holds back new
 * events while a storage operation is in flight. A plain get-then-put inside a
 * Durable Object is therefore atomic without any explicit locking — the race
 * cannot be expressed. See https://blog.cloudflare.com/durable-objects-easy-fast-correct-choose-three/
 *
 * WHAT STAYS ON KV
 *
 * Node inventory, fallbacks, targets, and measurement aggregates. Those are
 * read-mostly, tolerate staleness of seconds, and are read on the hot path by
 * every subscription poll — KV's edge caching is exactly right for them. Only
 * operations that must happen AT MOST ONCE move here.
 *
 * SHARDING
 *
 * A single Durable Object is a global serialisation point and would cap the
 * whole system's issuance rate. Keys are therefore sharded across SHARDS
 * objects by a deterministic hash of the key, so unrelated keys proceed in
 * parallel while the SAME key always lands on the SAME object — which is the
 * only property exactly-once actually requires.
 *
 * PRIVACY
 *
 * Nothing here stores a token, a challenge, an address, or anything derived
 * from a person. Ledger keys are peppered hashes supplied by the caller (see
 * voprf.js spendKey()) and rate-limit keys are peppered hashes of a client
 * hint that expires within the minute. A seizure of this storage yields a set
 * of opaque 40-character strings and their expiry times. That is deliberate
 * and must stay true — see 03-SECURITY.md §0.
 */

import { DurableObject } from 'cloudflare:workers';

/** Number of shards. Same key -> same shard, always. */
export const SHARDS = 4096;

/** Default prune cadence. Storage is not free and an unbounded ledger is a cost
 *  bug that eventually becomes an outage. Ledger rows are opaque hashes of
 *  tokens with no link to any person, so six hours here is a cost decision. */
const PRUNE_INTERVAL_MS = 6 * 3600e3;

/**
 * Rate-limit rows prune far more aggressively, and that is a PRIVACY decision,
 * not a cost one.
 *
 * A rate-limit key contains a peppered hash of a client address. Under KV it
 * carried a 120-second expirationTtl and the platform deleted it. Durable
 * Object storage has NO TTL, so moving it here would have quietly extended
 * retention to whatever the prune cadence happened to be. IPv4 is small enough
 * to enumerate, so a seizure of this storage together with KEY_SALT would
 * recover which addresses made requests during the retained window. Two minutes
 * of that is abuse control. Six hours of it is a log (I1).
 */
const RATE_PRUNE_INTERVAL_MS = 120e3;

/**
 * FNV-1a over the key. Not cryptographic and does not need to be: it chooses a
 * shard, it does not protect anything. It must only be deterministic and
 * dependency-free.
 */
export function shardOf(key) {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `s${(h % SHARDS).toString(16)}`;
}

/** Rows are { v: value, e: expiryMillis }. */
class Pruned extends DurableObject {
  /** Subclasses override to prune faster. Milliseconds. */
  get pruneIntervalMs() { return PRUNE_INTERVAL_MS; }

  async ensurePrune() {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + this.pruneIntervalMs);
    }
  }

  async alarm() {
    const now = Date.now();
    const rows = await this.ctx.storage.list();
    const dead = [];
    for (const [k, row] of rows) if (!row || typeof row.e !== 'number' || row.e <= now) dead.push(k);
    // delete() accepts at most 128 keys per call.
    for (let i = 0; i < dead.length; i += 128) await this.ctx.storage.delete(dead.slice(i, i + 128));
    const left = await this.ctx.storage.list({ limit: 1 });
    if (left.size > 0) await this.ctx.storage.setAlarm(Date.now() + this.pruneIntervalMs);
  }
}

/**
 * Ledger — at-most-once primitives.
 *
 * claim()   insert-if-absent. Returns true to EXACTLY ONE caller per key.
 *           Used for VOPRF token spend records and probe nonce spend records.
 * consume() read-and-delete in one indivisible step. Returns the value to
 *           exactly one caller. Used where the record carries data.
 * put()     write with expiry.
 * peek()    read without consuming. Test and operator introspection only.
 */
export class Ledger extends Pruned {
  async claim(key, ttlS) {
    const now = Date.now();
    const row = await this.ctx.storage.get(key);
    if (row && row.e > now) return false;          // already claimed and live
    await this.ctx.storage.put(key, { v: 1, e: now + ttlS * 1000 });
    await this.ensurePrune();
    return true;
  }

  async put(key, value, ttlS) {
    await this.ctx.storage.put(key, { v: value, e: Date.now() + ttlS * 1000 });
    await this.ensurePrune();
    return true;
  }

  async consume(key) {
    const row = await this.ctx.storage.get(key);
    await this.ctx.storage.delete(key);
    if (!row || row.e <= Date.now()) return null;
    return row.v;
  }

  async peek(key) {
    const row = await this.ctx.storage.get(key);
    return row && row.e > Date.now() ? row.v : null;
  }
}

/**
 * RateLimiter — a counter that actually counts.
 *
 * The caller supplies a key that already contains the time window, so a new
 * window starts from zero without any reset logic. Returns the post-increment
 * count and whether it has passed the limit.
 */
export class RateLimiter extends Pruned {
  get pruneIntervalMs() { return RATE_PRUNE_INTERVAL_MS; }

  async incr(key, limit, windowS) {
    const now = Date.now();
    const row = await this.ctx.storage.get(key);
    const count = (row && row.e > now ? row.v : 0) + 1;
    await this.ctx.storage.put(key, { v: count, e: now + windowS * 2000 });
    await this.ensurePrune();
    return { count, limited: count > limit };
  }
}

/**
 * Attribution — the reverse index and suspicion counters.
 *
 * Both were read-modify-write on KV (04-STATUS.md 2.8). A lost append to the
 * reverse index means a lineage that held a burned node is never implicated at
 * all: it escapes attribution entirely, silently, and the censor is exactly the
 * lineage that holds the most burned nodes and therefore the one most likely to
 * be dropped. A lost suspicion increment is milder — it under-counts, which at
 * least fails in the direction that does not punish an innocent person (I3).
 *
 * Deliberately NOT holding the lineage blob itself. That is read on every
 * subscription poll, hourly, by every client on a bad connection in a censored
 * country; it stays on edge-cached KV. Only the two values that are written
 * concurrently live here, and the credential path (infrequent, and already
 * talking to a Durable Object to claim its token) refreshes the KV copy.
 */
export class Attribution extends Pruned {
  /** Record that a lineage was given a node. Idempotent. */
  async implicate(key, lineage, ttlS, cap) {
    const now = Date.now();
    const row = await this.ctx.storage.get(key);
    const set = row && row.e > now ? row.v : [];
    if (set.includes(lineage)) return true;
    // Bounded: a popular node is held by many lineages, and an unbounded array
    // is a storage bug that an adversary can drive by enrolling repeatedly.
    // Past this point attribution is statistically saturated anyway.
    if (set.length >= cap) return false;
    set.push(lineage);
    await this.ctx.storage.put(key, { v: set, e: now + ttlS * 1000 });
    await this.ensurePrune();
    return true;
  }

  /** Read and clear in one indivisible step, so a burn cannot double-count. */
  async drain(key) {
    const row = await this.ctx.storage.get(key);
    await this.ctx.storage.delete(key);
    return row && row.e > Date.now() ? row.v : [];
  }

  /** Atomic add. Returns the new total. */
  async bump(key, weight, ttlS) {
    const now = Date.now();
    const row = await this.ctx.storage.get(key);
    const total = (row && row.e > now ? row.v : 0) + weight;
    await this.ctx.storage.put(key, { v: total, e: now + ttlS * 1000 });
    await this.ensurePrune();
    return total;
  }

  async total(key) {
    const row = await this.ctx.storage.get(key);
    return row && row.e > Date.now() ? row.v : 0;
  }
}

/**
 * Registry — operator-mutable state that must not be clobbered.
 *
 * Node inventory, fallbacks, and the stored key commitment were each a
 * read-then-write on KV (04-STATUS.md 2.8). Two operators acting at once — or
 * one operator racing the automated burn handler, which is the realistic case
 * since control-plane.py marks nodes blocked without a human — could each read
 * the list without the other's change and one write would be lost. A node
 * silently un-blocked by a concurrent edit is a node still being handed to
 * users after it was burned.
 *
 * A SINGLE, UNSHARDED instance. Operator writes are rare and must be totally
 * ordered with respect to each other; sharding would only reintroduce the
 * problem it exists to solve. Reads stay on KV — the subscription path polls
 * hourly from every client and must not wait on this.
 *
 * The DO holds the authority; KV holds a mirror for the read path. If a mirror
 * write fails the two diverge until the next mutation, so every mutating helper
 * rewrites the mirror from the value the DO returned rather than from its own
 * idea of what it just wrote.
 */
export class Registry extends DurableObject {
  async #inventory() { return (await this.ctx.storage.get('inventory')) || []; }

  /** Merge nodes in, preserving fields the caller did not send. */
  async upsertNodes(incoming) {
    const inv = await this.#inventory();
    for (const node of incoming) {
      const i = inv.findIndex((n) => n.id === node.id);
      if (i >= 0) inv[i] = { ...inv[i], ...node };
      else inv.push(node);
    }
    await this.ctx.storage.put('inventory', inv);
    return inv;
  }

  async markBlocked(nodeId) {
    const inv = await this.#inventory();
    const node = inv.find((n) => n.id === nodeId);
    if (!node) return { ok: false, inventory: inv };
    node.status = 'blocked';
    node.blocked_at = Date.now();
    await this.ctx.storage.put('inventory', inv);
    return { ok: true, pool: node.pool, inventory: inv };
  }

  async inventory() { return this.#inventory(); }

  async setFallbacks(list) {
    await this.ctx.storage.put('fallbacks', list);
    return list;
  }

  /**
   * Compare-and-set on the serial. The published history must only move
   * forwards: a client that has seen serial N refuses anything lower, so
   * serving an older document after a race would lock those clients out while
   * looking like an equivocation attempt to anyone comparing.
   */
  async setCommitment(record, serial) {
    const current = await this.ctx.storage.get('commitment_serial');
    if (current !== undefined && serial <= current) return { ok: false, have: current };
    await this.ctx.storage.put('commitment_serial', serial);
    await this.ctx.storage.put('commitment', record);
    return { ok: true, serial };
  }

  async commitment() {
    return {
      record: (await this.ctx.storage.get('commitment')) ?? null,
      serial: (await this.ctx.storage.get('commitment_serial')) ?? null,
    };
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Worker-side helpers. Every one FAILS CLOSED: if the Durable Object is
// unreachable we deny rather than allow. An availability blip must never
// become a free double-spend or an unmetered issuance window (I5).
// ───────────────────────────────────────────────────────────────────────────

const stub = (ns, key) => ns.get(ns.idFromName(shardOf(key)));

/** true only for the first caller with this key. Denies on any error. */
export async function claimOnce(ns, key, ttlS) {
  try { return await stub(ns, key).claim(key, ttlS); } catch { return false; }
}

export async function ledgerPut(ns, key, value, ttlS) {
  try { return await stub(ns, key).put(key, value, ttlS); } catch { return false; }
}

/** Returns the stored value to exactly one caller, else null. */
export async function ledgerConsume(ns, key) {
  try { return await stub(ns, key).consume(key); } catch { return null; }
}

export async function ledgerPeek(ns, key) {
  try { return await stub(ns, key).peek(key); } catch { return null; }
}

/** true when the caller is OVER the limit. Denies (limits) on any error. */
export async function overLimit(ns, key, limit, windowS) {
  try { return (await stub(ns, key).incr(key, limit, windowS)).limited; } catch { return true; }
}

// Attribution helpers. These fail OPEN rather than closed, and the asymmetry is
// deliberate: refusing to issue credentials because a bookkeeping object is
// briefly unreachable would deny access to real people under a hostile
// government in order to protect a reputation score. Losing an attribution
// record costs the operator some certainty about who is leaking. Losing access
// costs a user their connection. The second is worse (I3).

export async function implicateLineage(ns, node, lineage, ttlS, cap) {
  const key = `idx:${node}`;
  try { return await stub(ns, key).implicate(key, lineage, ttlS, cap); } catch { return false; }
}

export async function drainImplicated(ns, node) {
  const key = `idx:${node}`;
  try { return await stub(ns, key).drain(key); } catch { return []; }
}

export async function bumpSuspicion(ns, lineage, weight, ttlS) {
  const key = `sus:${lineage}`;
  try { return await stub(ns, key).bump(key, weight, ttlS); } catch { return null; }
}

export async function readSuspicion(ns, lineage) {
  const key = `sus:${lineage}`;
  try { return await stub(ns, key).total(key); } catch { return null; }
}

/**
 * The registry is a single named object, not a shard. Operator mutations must
 * be totally ordered with respect to one another.
 *
 * These throw rather than returning a sentinel: they are operator-facing, and a
 * silent no-op on an inventory write is how a burned node stays in service. The
 * caller turns a throw into the standard decoy, so nothing leaks either way.
 */
export const registry = (ns) => ns.get(ns.idFromName('registry'));

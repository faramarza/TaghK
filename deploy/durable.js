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

/** How often an object prunes expired rows. Storage is not free and an
 *  unbounded ledger is a cost bug that eventually becomes an outage. */
const PRUNE_INTERVAL_MS = 6 * 3600e3;

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
  async ensurePrune() {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + PRUNE_INTERVAL_MS);
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
    if (left.size > 0) await this.ctx.storage.setAlarm(Date.now() + PRUNE_INTERVAL_MS);
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
  async incr(key, limit, windowS) {
    const now = Date.now();
    const row = await this.ctx.storage.get(key);
    const count = (row && row.e > now ? row.v : 0) + 1;
    await this.ctx.storage.put(key, { v: count, e: now + windowS * 2000 });
    await this.ensurePrune();
    return { count, limited: count > limit };
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

#!/usr/bin/env node
/**
 * kv-race.test.mjs — proves 04-STATUS.md defects 2.1 and 2.2 are real.
 *
 * A fix nobody can see failing is a fix nobody can review. Miniflare's local KV
 * is strongly consistent, so running the OLD code under a local emulator would
 * have shown it passing — which is exactly how this defect survived being
 * "syntax-checked" in the first place.
 *
 * So this file models what Cloudflare KV actually documents: writes take time
 * to propagate, and until they do, a read in another colo returns the previous
 * value. Cloudflare states up to ~60s worldwide. Everything below uses 0ms of
 * simulated propagation for concurrent in-flight requests, which is the
 * MILDEST possible version of the problem — a single event-loop turn.
 *
 * These tests assert that the legacy pattern FAILS. If a future edit ever makes
 * them pass, the model has been weakened, not the bug fixed.
 *
 *   node test/kv-race.test.mjs
 */
import { section, check, eq, summary } from './harness.mjs';

/**
 * A KV that behaves like KV: put() returns immediately but the value is not
 * visible to get() until the propagation delay has elapsed.
 */
class EventuallyConsistentKV {
  constructor(propagationMs = 0) {
    this.committed = new Map();
    this.propagationMs = propagationMs;
  }
  async get(key) {
    await null;                                   // an await, as a real get has
    return this.committed.has(key) ? this.committed.get(key) : null;
  }
  async put(key, value) {
    const commit = () => this.committed.set(key, value);
    if (this.propagationMs === 0) setTimeout(commit, 0);   // next macrotask
    else setTimeout(commit, this.propagationMs);
  }
}

/** Strongly consistent, single-threaded per key — what a Durable Object gives. */
class DurableLedger {
  constructor() { this.rows = new Map(); this.chain = Promise.resolve(); }
  claim(key) {
    // Serialised per object, exactly as the DO runtime's input gate does.
    const run = async () => {
      if (this.rows.has(key)) return false;
      this.rows.set(key, 1);
      return true;
    };
    this.chain = this.chain.then(run, run);
    return this.chain;
  }
  incr(key, limit) {
    const run = async () => {
      const n = (this.rows.get(key) || 0) + 1;
      this.rows.set(key, n);
      return n > limit;
    };
    this.chain = this.chain.then(run, run);
    return this.chain;
  }
}

// ── the legacy patterns, copied verbatim in shape from the pre-fix code ────

async function legacyRedeem(kv, spentKey) {
  if (await kv.get(spentKey)) return false;
  await kv.put(spentKey, '1');
  return true;
}

async function legacyRateLimited(kv, key, max) {
  const n = Number((await kv.get(key)) || 0) + 1;
  await kv.put(key, String(n));
  return n > max;
}

const N = 24;

section('the defect: KV read-then-write is not exactly-once');

{
  const kv = new EventuallyConsistentKV();
  const results = await Promise.all(
    Array.from({ length: N }, () => legacyRedeem(kv, 'spent:deadbeef'))
  );
  const accepted = results.filter(Boolean).length;
  check(accepted > 1,
    `legacy redeem() accepts one token ${accepted} times under ${N}-way concurrency`,
    'this is the exploit: credential draw x number of vantage points');
}

{
  const kv = new EventuallyConsistentKV();
  const results = await Promise.all(
    Array.from({ length: N }, () => legacyRateLimited(kv, 'rl:chal:0:abc', 5))
  );
  const allowed = results.filter((limited) => !limited).length;
  check(allowed > 5,
    `legacy rateLimited() allows ${allowed} requests against a limit of 5`,
    'the control does nothing under exactly the load it exists for');
}

section('the fix: strongly consistent claim is exactly-once');

{
  const ledger = new DurableLedger();
  const results = await Promise.all(
    Array.from({ length: N }, () => ledger.claim('spent:deadbeef'))
  );
  eq(results.filter(Boolean).length, 1, `claim() succeeds exactly once across ${N} concurrent callers`);
}

{
  const ledger = new DurableLedger();
  const results = await Promise.all(
    Array.from({ length: N }, () => ledger.incr('rl:chal:0:abc', 5))
  );
  eq(results.filter((limited) => !limited).length, 5, 'incr() allows exactly the configured limit');
}

{
  const ledger = new DurableLedger();
  const a = await Promise.all(Array.from({ length: 8 }, () => ledger.claim('k1')));
  const b = await Promise.all(Array.from({ length: 8 }, () => ledger.claim('k2')));
  check(a.filter(Boolean).length === 1 && b.filter(Boolean).length === 1,
    'independent keys do not interfere');
}

summary();

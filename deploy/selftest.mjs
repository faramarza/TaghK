#!/usr/bin/env node
/**
 * selftest.mjs — cryptographic self-test.
 *
 * Run before every deployment. Crypto that does not work is worse than no
 * crypto, because it looks like protection. In particular, an unverified DLEQ
 * proof silently forfeits all anonymity against the server.
 *
 *   npm install && node selftest.mjs
 */
import * as v from './voprf.js';

let fail = 0;
const check = (ok, label) => { console.log(`${ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${label}`); if (!ok) fail++; };

const kp = v.generateKey();
check(kp.secret.length === 64 && kp.public.length === 64, 'keygen produces well-formed key material');

const items = v.blind(8);
const res = v.issue(kp.secret, items.map((i) => i.blinded));
check(res.evaluated.length === 8, 'batch issuance evaluates every element');

let tokens;
try { tokens = v.unblind(items, res.evaluated, res.proof, res.public_key); check(true, 'DLEQ proof verifies; tokens unblind'); }
catch { check(false, 'DLEQ proof verifies; tokens unblind'); tokens = []; }

check(tokens.every((t) => v.verifyToken(kp.secret, t.token, t.witness)), 'every token verifies under the issuing key');

// A tampered proof MUST be rejected — this is the anti-tagging guarantee.
let rejected = false;
try { v.unblind(items, res.evaluated, { e: res.proof.e, s: '00'.repeat(32) }, res.public_key); }
catch { rejected = true; }
check(rejected, 'tampered DLEQ proof is rejected (anti-tagging holds)');

const kp2 = v.generateKey();
check(!v.verifyToken(kp2.secret, tokens[0].token, tokens[0].witness), 'token from another key is rejected');
check(!v.verifyToken(kp.secret, tokens[0].token, tokens[1].witness), 'mismatched witness is rejected');

check(v.spendKey(tokens[0].token, 'p') === v.spendKey(tokens[0].token, 'p'), 'spend key is deterministic');
check(v.spendKey(tokens[0].token, 'p') !== v.spendKey(tokens[0].token, 'q'), 'spend key depends on the pepper');
check(!v.spendKey(tokens[0].token, 'p').includes(tokens[0].token), 'spend record does not contain the token');

// Blinding must hide the token from the server at issuance.
check(items.every((i) => i.blinded !== v.hashToGroup(v.fromHex(i.token)).toHex()), 'blinding hides the token from the issuer');

// Timing-safe comparison correctness.
const a = new Uint8Array([1, 2, 3]), b = new Uint8Array([1, 2, 3]), c = new Uint8Array([1, 2, 4]);
check(v.timingSafeEqual(a, b) && !v.timingSafeEqual(a, c), 'constant-time comparison is correct');

console.log(fail ? `\n\x1b[31m${fail} check(s) FAILED — do not deploy\x1b[0m` : '\n\x1b[32mall checks passed\x1b[0m');
process.exit(fail ? 1 : 0);

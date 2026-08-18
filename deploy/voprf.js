/**
 * voprf.js — Verifiable Oblivious Pseudorandom Function (Privacy Pass core)
 * ---------------------------------------------------------------------------
 * ristretto255 VOPRF, following the structure of RFC 9497.
 *
 * THE PROBLEM THIS SOLVES
 *
 * The distributor needs to rate-limit, revoke, and score reputation. Doing that
 * the obvious way means knowing WHO is asking — which means a database linking
 * people to proven use of a circumvention tool. Under 2026 Iranian law that
 * database is an arrest list, and its existence is a greater danger to users
 * than most of the censorship it would help defeat.
 *
 * A VOPRF breaks the link. The client blinds a random token, the server
 * evaluates it under a secret key without ever seeing the token, and the client
 * unblinds the result. Later the client presents the unblinded token. The server
 * can verify it issued that token — but CANNOT tell which issuance it came from.
 *
 *   issuance:   client                          server
 *               T  ← random 32 bytes
 *               r  ← random scalar
 *               B  = H(T) · r          ──────►  Z = B · k
 *                                               π = DLEQ(k; G, Y, B, Z)
 *               W  = Z · r⁻¹ = H(T)·k  ◄──────  (Z, π)
 *               verify π, store (T, W)
 *
 *   redemption: client                          server
 *               (T, W)                 ──────►  check W == H(T) · k
 *                                               check T not already spent
 *
 * The server sees B at issuance (uniformly random — r blinds it perfectly) and T
 * at redemption. Nothing connects them. Unlinkability is information-theoretic
 * in the blind, not merely computational.
 *
 * WHY THE "V" (VERIFIABLE) MATTERS — this is not optional decoration.
 *
 * Without the DLEQ proof, a malicious or compromised server can use a DIFFERENT
 * secret key for each user. At redemption it tries each key, learns which one
 * matched, and has just de-anonymised the user completely. The proof forces the
 * server to demonstrate it used the one advertised public key, so every token in
 * existence shares one anonymity set. A VOPRF deployment without DLEQ
 * verification on the client provides no anonymity against the server at all.
 *
 * Requires: @noble/curves@^1.4.0  (audited, works in Workers, no WASM)
 *   npm i @noble/curves@1.4.0
 */

import { RistrettoPoint } from '@noble/curves/ed25519';
import { invert, mod } from '@noble/curves/abstract/modular';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';

/** Order of the ristretto255 group. */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const CTX = new TextEncoder().encode('circumvention-voprf-v1');

// ───────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ───────────────────────────────────────────────────────────────────────────

export const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

export const fromHex = (h) => {
  if (typeof h !== 'string' || h.length % 2 || !/^[0-9a-fA-F]*$/.test(h)) {
    throw new Error('bad hex');
  }
  return Uint8Array.from(h.match(/../g)?.map((x) => parseInt(x, 16)) ?? []);
};

const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
};

/** Reduce 64 uniform bytes into a scalar — avoids the modulo bias of 32 bytes. */
const scalarFromWide = (bytes64) => {
  let n = 0n;
  for (const b of bytes64) n = (n << 8n) | BigInt(b);
  return mod(n, L);
};

/** Uniform random scalar in [1, L). */
export const randomScalar = () => {
  const buf = new Uint8Array(64);
  crypto.getRandomValues(buf);
  const s = scalarFromWide(buf);
  return s === 0n ? 1n : s;
};

/** Serialise a scalar as 32 little-endian bytes (ristretto convention). */
const scalarToBytes = (s) => {
  const out = new Uint8Array(32);
  let n = mod(s, L);
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
};

/** Inverse of scalarToBytes. MUST match its endianness — mismatching the two
 *  is a silent failure that only shows up as "every proof is invalid". */
const scalarFromBytes = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return mod(n, L);
};

/**
 * Hash an arbitrary token to a group element.
 * Domain-separated so tokens can never collide with any other hash use.
 */
export const hashToGroup = (tokenBytes) =>
  RistrettoPoint.hashToCurve(sha512(concat(CTX, new Uint8Array([0x01]), tokenBytes)));

// ───────────────────────────────────────────────────────────────────────────
// Server key material
// ───────────────────────────────────────────────────────────────────────────

export function generateKey() {
  const k = randomScalar();
  return {
    secret: toHex(scalarToBytes(k)),
    public: RistrettoPoint.BASE.multiply(k).toHex(),
  };
}

const loadSecret = (hex) => {
  const bytes = fromHex(hex);
  let n = 0n;
  for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  const k = mod(n, L);
  if (k === 0n) throw new Error('invalid key');
  return k;
};

// ───────────────────────────────────────────────────────────────────────────
// DLEQ — Chaum–Pedersen proof of discrete-log equality (batched)
// ───────────────────────────────────────────────────────────────────────────
//
// Proves log_G(Y) == log_{B_i}(Z_i) for every i, without revealing k.
// Batched via random linear combination so one proof covers a whole issuance,
// keeping issuance cheap regardless of batch size.

const challengeScalar = (Y, B, Z, A1, A2) =>
  scalarFromWide(
    sha512(
      concat(
        CTX,
        new Uint8Array([0x02]),
        RistrettoPoint.BASE.toRawBytes(),
        Y.toRawBytes(),
        B.toRawBytes(),
        Z.toRawBytes(),
        A1.toRawBytes(),
        A2.toRawBytes()
      )
    )
  );

/** Deterministic batching coefficients — both sides derive the same values. */
function batchCoefficients(Y, blinded, evaluated) {
  const seed = sha512(
    concat(
      CTX,
      new Uint8Array([0x03]),
      Y.toRawBytes(),
      ...blinded.map((p) => p.toRawBytes()),
      ...evaluated.map((p) => p.toRawBytes())
    )
  );
  return blinded.map((_, i) =>
    scalarFromWide(sha512(concat(seed, new Uint8Array([i & 0xff, (i >> 8) & 0xff]))))
  );
}

const combine = (points, coeffs) =>
  points.reduce(
    (acc, P, i) => acc.add(P.multiply(coeffs[i])),
    RistrettoPoint.ZERO
  );

export function proveBatch(k, Y, blinded, evaluated) {
  const c = batchCoefficients(Y, blinded, evaluated);
  const B = combine(blinded, c);
  const Z = combine(evaluated, c);

  const t = randomScalar();
  const A1 = RistrettoPoint.BASE.multiply(t);
  const A2 = B.multiply(t);

  const e = challengeScalar(Y, B, Z, A1, A2);
  const s = mod(t - e * k, L);

  return { e: toHex(scalarToBytes(e)), s: toHex(scalarToBytes(s)) };
}

/**
 * Client-side verification. SHIPPED IN THE CLIENT, NOT USED BY THE SERVER —
 * included here so both sides share one reference implementation and cannot
 * drift apart. A client that skips this check gets no anonymity guarantee.
 */
export function verifyBatch(Ypub, blindedHex, evaluatedHex, proof) {
  try {
    const Y = RistrettoPoint.fromHex(Ypub);
    const blinded = blindedHex.map((h) => RistrettoPoint.fromHex(h));
    const evaluated = evaluatedHex.map((h) => RistrettoPoint.fromHex(h));
    if (blinded.length !== evaluated.length || !blinded.length) return false;

    const c = batchCoefficients(Y, blinded, evaluated);
    const B = combine(blinded, c);
    const Z = combine(evaluated, c);

    const eBytes = fromHex(proof.e);
    const sBytes = fromHex(proof.s);
    if (eBytes.length !== 32 || sBytes.length !== 32) return false;
    const e = scalarFromBytes(eBytes);
    const s = scalarFromBytes(sBytes);

    // A1 = sG + eY ; A2 = sB + eZ  — reconstruct and re-derive the challenge.
    const A1 = RistrettoPoint.BASE.multiply(s).add(Y.multiply(e));
    const A2 = B.multiply(s).add(Z.multiply(e));

    return challengeScalar(Y, B, Z, A1, A2) === e;
  } catch {
    return false;
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Server operations
// ───────────────────────────────────────────────────────────────────────────

/**
 * Evaluate blinded elements under the secret key and prove correctness.
 * The server learns nothing: each B_i is a uniformly random group element.
 */
export function issue(secretHex, blindedHex, maxBatch = 32) {
  if (!Array.isArray(blindedHex) || !blindedHex.length) throw new Error('empty batch');
  if (blindedHex.length > maxBatch) throw new Error('batch too large');

  const k = loadSecret(secretHex);
  const Y = RistrettoPoint.BASE.multiply(k);

  const blinded = blindedHex.map((h) => RistrettoPoint.fromHex(h));
  // Reject the identity: it would produce a degenerate token the server could tag.
  for (const P of blinded) if (P.equals(RistrettoPoint.ZERO)) throw new Error('bad element');

  const evaluated = blinded.map((P) => P.multiply(k));

  return {
    evaluated: evaluated.map((P) => P.toHex()),
    proof: proveBatch(k, Y, blinded, evaluated),
    public_key: Y.toHex(),
  };
}

/**
 * Verify a presented token. Constant-time in the comparison.
 *
 * Double-spend prevention is the CALLER's responsibility — see spendKey() and
 * the KV-backed check in the distributor. Verification alone does not prevent
 * replay.
 */
export function verifyToken(secretHex, tokenHex, witnessHex) {
  try {
    const k = loadSecret(secretHex);
    const expected = hashToGroup(fromHex(tokenHex)).multiply(k).toRawBytes();
    const got = RistrettoPoint.fromHex(witnessHex).toRawBytes();
    return timingSafeEqual(expected, got);
  } catch {
    return false;
  }
}

/**
 * Opaque, stable key for double-spend records.
 * Stored INSTEAD of the token itself: the spend log then reveals nothing about
 * any token that has not already been presented, so a database seizure yields
 * no usable token material.
 */
export function spendKey(tokenHex, pepper) {
  return toHex(sha256(concat(CTX, new Uint8Array([0x04]),
    new TextEncoder().encode(pepper), fromHex(tokenHex)))).slice(0, 40);
}

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ───────────────────────────────────────────────────────────────────────────
// Client reference implementation
// ───────────────────────────────────────────────────────────────────────────
//
// Ships in the app. Mirrored here so server and client cannot drift.

export function blind(count = 8) {
  const items = [];
  for (let i = 0; i < count; i++) {
    const token = new Uint8Array(32);
    crypto.getRandomValues(token);
    const r = randomScalar();
    items.push({
      token: toHex(token),
      blindScalar: r,
      blinded: hashToGroup(token).multiply(r).toHex(),
    });
  }
  return items;
}

export function unblind(items, evaluatedHex, proof, publicKey) {
  // MANDATORY. Skipping this check forfeits anonymity entirely — see the
  // per-user-key tagging attack described at the top of this file.
  if (!verifyBatch(publicKey, items.map((i) => i.blinded), evaluatedHex, proof)) {
    throw new Error('DLEQ verification failed — server may be tagging users. Discard these tokens.');
  }

  return items.map((item, i) => {
    const rInv = invert(item.blindScalar, L);
    return {
      token: item.token,
      witness: RistrettoPoint.fromHex(evaluatedHex[i]).multiply(rInv).toHex(),
    };
  });
}

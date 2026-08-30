/**
 * commitment.js — anchoring the issuer public key
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * THE ATTACK THIS EXISTS TO STOP (04-STATUS.md 2.17)
 *
 * A client that verifies the DLEQ proof against the public key that arrived in
 * the same response has verified nothing about anonymity. The proof shows the
 * server used SOME key consistently. It does not show the server used
 * EVERYONE'S key.
 *
 * A malicious or compromised distributor picks a distinct k_user per client,
 * evaluates under it, and produces a perfectly valid Chaum–Pedersen proof with
 * respect to Y_user = G·k_user. verifyBatch() returns true. At redemption the
 * server tries each stored k_user until one verifies and has identified that
 * user exactly — which is precisely the attack the proof was supposed to
 * prevent. The word doing the work in "proves it used the one ADVERTISED key"
 * is *advertised*, and a value the server hands you in the same breath is not
 * advertised, it is asserted.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  THE CONSTRUCTION, AND WHY THE SIGNING KEY IS NOT ON THE SERVER
 * ───────────────────────────────────────────────────────────────────────────
 *
 * The operator publishes a KEY COMMITMENT: a document naming the VOPRF public
 * key for each epoch, signed with a long-term Ed25519 key that the client pins
 * at build time. The client refuses to unblind unless the public key it was
 * given appears in a valid, current, signed commitment.
 *
 * The load-bearing decision is where that signing key lives:
 *
 *   COMMITMENT_SK NEVER TOUCHES THE WORKER.
 *
 * It is generated offline, kept offline, and used offline to mint a signed
 * document that is then uploaded as an opaque blob. The Worker serves bytes it
 * cannot produce. This is the difference between two very different security
 * claims:
 *
 *   if the Worker signed on demand   →  a compromised Worker mints a per-user
 *                                       commitment and tagging still works.
 *                                       The signature proves nothing.
 *   because the Worker cannot sign   →  a compromised Worker CANNOT tag. It can
 *                                       refuse service, serve stale keys, or
 *                                       hand out garbage the client rejects —
 *                                       but it cannot make a client accept a
 *                                       key that the offline holder did not
 *                                       commit to.
 *
 * "Malicious server (us, compromised)" is a named adversary in 03-SECURITY.md
 * §1 and this is what actually answers it.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  WHAT IS STILL NOT SOLVED — read this before believing the paragraph above
 * ───────────────────────────────────────────────────────────────────────────
 *
 * An operator who holds COMMITMENT_SK can sign a per-user commitment and serve
 * it to one client. Signing prevents a compromised SERVER from equivocating; it
 * does not prevent the KEY HOLDER from equivocating. Nothing cryptographic can,
 * because the key holder is by definition authorised.
 *
 * What the design does instead is make equivocation LEAVE EVIDENCE:
 *
 *   • every document carries a monotonically increasing `serial` and the hash
 *     of its predecessor, so the published history is a chain;
 *   • the client refuses a serial lower than the highest it has seen, so a
 *     targeted document cannot be a silent rollback;
 *   • the document is byte-identical for every client, published at a stable
 *     public location, and intended to be mirrored outside the operator's
 *     control, so two clients comparing what they received detect a split.
 *
 * That is the certificate-transparency posture: not prevention, detection. It
 * is weaker than the guarantee above and it is stated separately on purpose.
 * The remaining gap closes only with reproducible signed client builds (P7) and
 * an independent mirror, and until both exist the honest claim is:
 *
 *   a compromised server cannot tag; a malicious OPERATOR can, but not
 *   invisibly, and not to a client that has ever seen a later document.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  WHY THE DOCUMENT IS A STRING AND NOT AN OBJECT
 * ───────────────────────────────────────────────────────────────────────────
 *
 * The signature covers the exact bytes that were served. There is no canonical
 * JSON step, because a canonicalisation mismatch between signer and verifier is
 * a silent verification bypass, and every such scheme has produced one. The
 * client verifies the signature over the received string, and only then parses
 * it. Same pattern as the collector's work manifests, which already works.
 */

const enc = new TextEncoder();

export const COMMITMENT_VERSION = 1;

/**
 * Epoch length, duplicated from voprf.js rather than imported.
 *
 * commitment.js must stay importable by a client that does not pull in the
 * group arithmetic, and a circular import between the two is worse than one
 * constant in two places. The anchor test asserts they agree, so a change to
 * one that is not mirrored fails the build rather than silently loosening this
 * bound.
 */
export const EPOCH_SECONDS_FOR_BOUNDS = 30 * 86400;
export const NULL_PREV = '0'.repeat(64);

const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** SHA-256 of the exact document bytes. Links one document to the next. */
export async function commitmentHash(docString) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(docString)));
}

/**
 * Verify a commitment and return the public key committed for `epoch`.
 * Throws on every failure — there is no partial success worth having here.
 *
 * THE TWO ARGUMENTS ARE SPLIT ALONG THE TRUST BOUNDARY, ON PURPOSE.
 *
 *   `served` is what came off the network. The server chose every byte of it.
 *   `trust`  is what the client knows independently: the key pinned in its
 *            build, the highest serial it has already accepted, and its clock.
 *
 * They are separate objects so that no future client can merge them. A single
 * bag of options invites `{ ...serverResponse, pinnedKey }`, and the moment a
 * server response gains a `minSerial` or `now` field — by accident or by
 * design — that spread silently disables rollback protection and expiry
 * checking while the code continues to look correct. Keeping the boundary in
 * the signature makes the mistake unspellable rather than merely discouraged.
 *
 * @param served.doc        the document string EXACTLY as received
 * @param served.signature  base64 Ed25519 signature over those bytes
 * @param trust.pinnedKey   base64 raw Ed25519 public key, pinned in the build
 * @param trust.minSerial   highest serial this client has ever accepted
 * @param trust.now         milliseconds; the CLIENT's clock, never the server's
 */
export async function anchorEpochKey(epoch, served, trust) {
  const { doc, signature } = served ?? {};
  const { pinnedKey, minSerial = 0, now = Date.now() } = trust ?? {};

  if (typeof doc !== 'string' || !doc.length) throw new Error('commitment: missing document');
  if (typeof signature !== 'string') throw new Error('commitment: missing signature');
  if (typeof pinnedKey !== 'string' || !pinnedKey) {
    // A client built without a pinned key has no anchor and therefore no
    // anti-tagging guarantee. It must refuse rather than fall back to trusting
    // whatever the server said — that fallback IS the vulnerability.
    throw new Error('commitment: no pinned operator key — refusing to trust a server-supplied key');
  }

  let key;
  let sig;
  try {
    key = await crypto.subtle.importKey('raw', fromB64(pinnedKey), { name: 'Ed25519' }, false, ['verify']);
    sig = fromB64(signature);
  } catch {
    throw new Error('commitment: malformed key or signature');
  }

  if (!(await crypto.subtle.verify('Ed25519', key, sig, enc.encode(doc)))) {
    throw new Error('commitment: SIGNATURE INVALID — the issuer key is not the operator’s. Discard these tokens.');
  }

  let parsed;
  try { parsed = JSON.parse(doc); } catch { throw new Error('commitment: unparseable after verification'); }

  if (parsed.v !== COMMITMENT_VERSION) throw new Error('commitment: unknown version');
  if (!Number.isSafeInteger(parsed.serial) || parsed.serial < 0) throw new Error('commitment: bad serial');

  // Rollback protection. A commitment older than one already accepted is either
  // a stale cache or a targeted document, and the two are indistinguishable
  // from here, so both are refused.
  if (parsed.serial < minSerial) {
    throw new Error(`commitment: serial ${parsed.serial} is older than ${minSerial} already seen — refusing a rollback`);
  }

  if (!Number.isSafeInteger(parsed.not_after)) throw new Error('commitment: bad expiry');
  if (now / 1000 > parsed.not_after) throw new Error('commitment: expired — refusing to issue against stale keys');
  if (Number.isSafeInteger(parsed.issued_at) && now / 1000 + 86400 < parsed.issued_at) {
    throw new Error('commitment: issued in the future');
  }

  if (typeof parsed.prev !== 'string' || !/^[0-9a-f]{64}$/.test(parsed.prev)) {
    throw new Error('commitment: bad predecessor hash');
  }

  // The server names the epoch, so bound it against the client's own clock.
  // Otherwise a server holding the master could issue every user a different
  // epoch from within the commitment window, widening a two-way partition into
  // an N-way one. N is small, but it costs nothing to refuse.
  if (!Number.isSafeInteger(epoch)) throw new Error('commitment: bad epoch');
  const localEpoch = Math.floor(now / 1000 / EPOCH_SECONDS_FOR_BOUNDS);
  if (Math.abs(epoch - localEpoch) > 1) {
    throw new Error(`commitment: epoch ${epoch} is not close to this client's own epoch ${localEpoch}`);
  }

  const committed = parsed.keys?.[String(epoch)];
  if (typeof committed !== 'string' || !/^[0-9a-f]{64}$/.test(committed)) {
    throw new Error(`commitment: no key committed for epoch ${epoch}`);
  }

  return { publicKey: committed, serial: parsed.serial, notAfter: parsed.not_after };
}

/**
 * Build a document body. Used by the OFFLINE minting tool only — nothing in
 * either Worker imports this, because nothing in either Worker may sign.
 */
export function buildCommitment({ serial, prev, keys, issuedAt, notAfter }) {
  if (!Number.isSafeInteger(serial) || serial < 0) throw new Error('bad serial');
  if (!/^[0-9a-f]{64}$/.test(prev)) throw new Error('bad prev');
  for (const [e, k] of Object.entries(keys)) {
    if (!/^\d+$/.test(e) || !/^[0-9a-f]{64}$/.test(k)) throw new Error(`bad key entry ${e}`);
  }
  // Key order is fixed by construction so successive mints of the same input
  // produce identical bytes. This is a reproducibility property, not a security
  // one — the signature covers the bytes either way.
  const ordered = {};
  for (const e of Object.keys(keys).sort((a, b) => Number(a) - Number(b))) ordered[e] = keys[e];
  return JSON.stringify({
    v: COMMITMENT_VERSION, serial, prev,
    issued_at: issuedAt, not_after: notAfter, keys: ordered,
  });
}

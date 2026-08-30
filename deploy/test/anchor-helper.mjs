/**
 * anchor-helper.mjs — build signed key commitments for tests.
 *
 * Mirrors what tools/mint-commitment.mjs does offline. Kept separate from the
 * tool so no test can accidentally become a path by which a signing key reaches
 * a Worker.
 */
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { epochPublicKey, currentEpoch, EPOCH_LENGTH_S } from '../voprf.js';
import { buildCommitment, commitmentHash, NULL_PREV } from '../commitment.js';

export function commitmentKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pinnedKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64'),
    pkcs8: privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}

export async function sign(doc, pkcs8) {
  const key = await webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  return Buffer.from(
    await webcrypto.subtle.sign('Ed25519', key, new TextEncoder().encode(doc))).toString('base64');
}

/** A commitment covering `span` epochs from the current one. */
export async function mint({ master, pkcs8, span = 3, serial = 0, prevDoc = null, keys = null,
                             issuedAt = null, notAfter = null }) {
  const start = currentEpoch();
  const committed = keys ?? Object.fromEntries(
    Array.from({ length: span }, (_, i) => [String(start + i), epochPublicKey(master, start + i)]));
  const doc = buildCommitment({
    serial,
    prev: prevDoc ? await commitmentHash(prevDoc) : NULL_PREV,
    keys: committed,
    // Overridable so a test can model a client that anchored while an older
    // epoch was current, rather than one time-travelling with today's document.
    issuedAt: issuedAt ?? Math.floor(Date.now() / 1000),
    notAfter: notAfter ?? (start + span) * EPOCH_LENGTH_S,
  });
  return { doc, signature: await sign(doc, pkcs8) };
}

/**
 * The anchor a client passes to unblind(). Note the shape: what the server sent
 * and what the client knows are kept apart so they cannot be merged.
 */
export const anchorFor = (epoch, commitment, pinnedKey, minSerial = 0, now = undefined) => ({
  epoch,
  served: { doc: commitment.doc, signature: commitment.signature },
  trust: { pinnedKey, minSerial, ...(now === undefined ? {} : { now }) },
});

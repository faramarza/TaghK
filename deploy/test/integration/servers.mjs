#!/usr/bin/env node
/**
 * servers.mjs — boots both Workers in workerd on fixed ports and stays up.
 *
 * Part of the Plane 3 integration harness. Prints one JSON line of secrets and
 * ports on stdout when ready, then blocks until SIGTERM. Secrets are generated
 * per run and exist only in this process tree — nothing is written to the repo.
 */
import { unstable_dev } from 'wrangler';
import { generateKeyPairSync } from 'node:crypto';
import { rmSync } from 'node:fs';
import { generateMaster, currentEpoch, epochPublicKey } from '../../voprf.js';
import { commitmentKeypair, mint } from '../anchor-helper.mjs';

const PERSIST = process.env.PERSIST_DIR || '/tmp/tk-integration';
const DIST_PORT = Number(process.env.DIST_PORT || 8787);
const COLL_PORT = Number(process.env.COLL_PORT || 8788);

rmSync(PERSIST, { recursive: true, force: true });

const voprfMaster = generateMaster();
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// The key-commitment keypair. Its secret NEVER enters the Worker's vars — it is
// used here only to mint the document that is then uploaded as an opaque blob,
// which is exactly how an operator does it offline (docs/adr/0006).
const operator = commitmentKeypair();
const commitment = await mint({ master: voprfMaster, pkcs8: operator.pkcs8, span: 3, serial: 1 });

const env = {
  ADMIN_KEY: 'ad'.repeat(32),
  COLLECTOR_ADMIN: 'ca'.repeat(32),
  KEY_SALT: 'sa'.repeat(32),
  PROBE_HMAC_KEY: 'ph'.repeat(32),
  ENROL_SALT: 'en'.repeat(32),
  VOPRF_MASTER: voprfMaster,
  MANIFEST_SK: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
};

const common = { local: true, experimental: { disableExperimentalWarning: true } };

const dist = await unstable_dev('distributor-worker.js', {
  ...common, config: 'wrangler.toml', port: DIST_PORT, persistTo: `${PERSIST}/dist`,
  vars: { ADMIN_KEY: env.ADMIN_KEY, KEY_SALT: env.KEY_SALT, VOPRF_MASTER: env.VOPRF_MASTER },
});

const coll = await unstable_dev('collector-worker.js', {
  ...common, config: 'wrangler.collector.toml', port: COLL_PORT, persistTo: `${PERSIST}/coll`,
  vars: {
    COLLECTOR_ADMIN: env.COLLECTOR_ADMIN, PROBE_HMAC_KEY: env.PROBE_HMAC_KEY,
    ENROL_SALT: env.ENROL_SALT, MANIFEST_SK: env.MANIFEST_SK,
  },
});

// Upload the pre-signed commitment. Without it the distributor refuses to
// issue — deliberately, since tokens outside a commitment are tokens a correct
// client must discard.
const uploaded = await dist.fetch('http://d/admin/commitment', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-admin-key': env.ADMIN_KEY },
  body: JSON.stringify(commitment),
});
if (uploaded.status !== 200) {
  console.error(`commitment upload failed: ${uploaded.status}`);
  process.exit(1);
}

console.log(JSON.stringify({
  ready: true,
  dist_port: DIST_PORT,
  coll_port: COLL_PORT,
  admin_key: env.ADMIN_KEY,
  collector_admin: env.COLLECTOR_ADMIN,
  operator_pubkey: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64'),
  voprf_public: epochPublicKey(voprfMaster, currentEpoch()),
  commitment_pk: operator.pinnedKey,
}));

const shutdown = async () => {
  await dist.stop().catch(() => {});
  await coll.stop().catch(() => {});
  rmSync(PERSIST, { recursive: true, force: true });
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
setInterval(() => {}, 1 << 30);

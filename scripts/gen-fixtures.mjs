#!/usr/bin/env node
/**
 * Generate conformance fixtures under conformance/fixtures/.
 *
 * Produces:
 *   - valid-simple/     a PASS bundle with a verified attachment
 *   - valid-signed/     a PASS bundle with an Ed25519 signature (+ pubkey PEM)
 *   - tamper-modified-event/     -> EVENT_HASH_MISMATCH
 *   - tamper-broken-chain/       -> CHAIN_BROKEN
 *   - tamper-count-mismatch/     -> MANIFEST_MISMATCH (event_count)
 *   - tamper-last-hash-mismatch/ -> MANIFEST_MISMATCH (last_event_hash)
 *   - tamper-bad-signature/      -> SIGNATURE_INVALID
 *   - tamper-truncated-tail/     -> INVALID_EVENT_JSON (torn write)
 *
 * All values are neutral example data. No internal hostnames or IPs.
 * Run: node scripts/gen-fixtures.mjs (requires a prior `npm run build`).
 */
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  buildBundle,
  eventsToNdjson,
  eventHash,
  signBundle,
  attachSignature,
} from '../dist/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIX = join(__dirname, '..', 'conformance', 'fixtures');

const RUN_ID = 'RUN-EXAMPLE-1';
const BUNDLE_ID = 'BUNDLE-EXAMPLE-1';
const CREATED_TS = '2026-02-28T19:00:01.000Z';
const CORR = 'corr-001';

// Attachment: neutral tool stdout. Its SHA-256 is embedded as an attachment_ref
// hash so the verifier can content-address it on disk.
const STDOUT_BYTES = Buffer.from('service is active (running)\n', 'utf8');
const STDOUT_HASH = createHash('sha256').update(STDOUT_BYTES).digest('hex');

/** Eight-event read-only run, adapted from WORKED_EXAMPLES.md Example 1. */
function makeEvents() {
  return [
    {
      volt_version: '0.1', event_id: 'E1', run_id: RUN_ID, ts: '2026-02-28T19:00:00.000Z', seq: 1,
      event_type: 'run.started',
      actor: { actor_type: 'system', actor_id: 'quox.core' },
      context: { correlation_id: CORR, aee_envelope_id: 'env-001' },
      payload: { entrypoint: 'api.chat' },
    },
    {
      volt_version: '0.1', event_id: 'E2', run_id: RUN_ID, ts: '2026-02-28T19:00:00.010Z', seq: 2,
      event_type: 'aee.envelope.received',
      actor: { actor_type: 'system', actor_id: 'quox.aee.gateway' },
      context: { correlation_id: CORR, aee_envelope_id: 'env-001' },
      payload: { channel: 'web', size_bytes: 612, redacted: true },
    },
    {
      volt_version: '0.1', event_id: 'E3', run_id: RUN_ID, ts: '2026-02-28T19:00:00.020Z', seq: 3,
      event_type: 'aocl.policy.evaluated',
      actor: { actor_type: 'system', actor_id: 'quox.aocl' },
      context: { correlation_id: CORR, aocl_policy_id: 'policy.ops.readonly', aocl_decision_id: 'dec-001' },
      payload: { result: 'allow', reason: 'read_only_check' },
    },
    {
      volt_version: '0.1', event_id: 'E4', run_id: RUN_ID, ts: '2026-02-28T19:00:00.021Z', seq: 4,
      event_type: 'aocl.decision.approved',
      actor: { actor_type: 'system', actor_id: 'quox.aocl' },
      context: { correlation_id: CORR, aocl_decision_id: 'dec-001' },
      payload: { result: 'allow' },
    },
    {
      volt_version: '0.1', event_id: 'E5', run_id: RUN_ID, ts: '2026-02-28T19:00:00.030Z', seq: 5,
      event_type: 'tool.call.requested',
      actor: { actor_type: 'agent', actor_id: 'quox.agent.ops' },
      context: { correlation_id: CORR },
      payload: { tool_name: 'shell', operation: 'service_status', target: 'example-service', inputs_redacted: true },
    },
    {
      volt_version: '0.1', event_id: 'E6', run_id: RUN_ID, ts: '2026-02-28T19:00:00.180Z', seq: 6,
      event_type: 'tool.call.executed',
      actor: { actor_type: 'runner', actor_id: 'runner:node-01' },
      context: { correlation_id: CORR },
      payload: {
        tool_name: 'shell', status: 'success', duration_ms: 150,
        attachment_refs: [{ hash_alg: 'sha256', hash: STDOUT_HASH, content_type: 'text/plain', label: 'stdout' }],
      },
    },
    {
      volt_version: '0.1', event_id: 'E7', run_id: RUN_ID, ts: '2026-02-28T19:00:00.200Z', seq: 7,
      event_type: 'aee.envelope.sent',
      actor: { actor_type: 'system', actor_id: 'quox.aee.gateway' },
      context: { correlation_id: CORR, aee_envelope_id: 'env-001' },
      payload: { channel: 'web', size_bytes: 980 },
    },
    {
      volt_version: '0.1', event_id: 'E8', run_id: RUN_ID, ts: '2026-02-28T19:00:00.210Z', seq: 8,
      event_type: 'run.completed',
      actor: { actor_type: 'system', actor_id: 'quox.core' },
      context: { correlation_id: CORR },
      payload: { status: 'success', summary: 'example-service is active' },
    },
  ];
}

const BUILD_OPTS = {
  bundleId: BUNDLE_ID,
  createdTs: CREATED_TS,
  bundleMode: 'final',
  correlationId: CORR,
  producer: { name: 'volt-sdk-fixtures', version: '0.1.0' },
  attachmentsPresent: true,
  redactionsPresent: true,
};

function writeDir(name, files) {
  const dir = join(FIX, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  return dir;
}

function main() {
  const built = buildBundle(makeEvents(), BUILD_OPTS);
  const manifestJson = JSON.stringify(built.manifest, null, 2) + '\n';
  const eventsNdjson = built.eventsNdjson;
  const attachRel = `attachments/${STDOUT_HASH.slice(0, 2)}/${STDOUT_HASH}`;

  // --- valid-simple ---
  writeDir('valid-simple', {
    'manifest.json': manifestJson,
    'events.ndjson': eventsNdjson,
    [attachRel]: STDOUT_BYTES,
  });

  // --- valid-signed ---
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const sig = signBundle(built.manifest, privateKey, { keyId: 'did:key:example-fixture-key', signedTs: '2026-02-28T19:00:02.000Z' });
  const signedManifest = attachSignature(built.manifest, sig);
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  writeDir('valid-signed', {
    'manifest.json': JSON.stringify(signedManifest, null, 2) + '\n',
    'events.ndjson': eventsNdjson,
    [attachRel]: STDOUT_BYTES,
    'pubkey.pem': pubPem,
  });

  // --- tamper-modified-event: change a payload value, keep the stale hash ---
  {
    const lines = eventsNdjson.trimEnd().split('\n').map((l) => JSON.parse(l));
    lines[3].payload.result = 'deny'; // was "allow"; hash now stale
    const tampered = lines.map((e) => JSON.stringify(e)).join('\n') + '\n';
    writeDir('tamper-modified-event', { 'manifest.json': manifestJson, 'events.ndjson': tampered });
  }

  // --- tamper-broken-chain: re-hash a middle event but leave the next link ---
  {
    const evs = eventsNdjson.trimEnd().split('\n').map((l) => JSON.parse(l));
    evs[2].payload.reason = 'mutated_but_self_consistent';
    evs[2].hash = eventHash(evs[2]); // event 3 now self-valid...
    // ...but event 4's prev_hash still points at the ORIGINAL event-3 hash.
    const tampered = evs.map((e) => JSON.stringify(e)).join('\n') + '\n';
    writeDir('tamper-broken-chain', { 'manifest.json': manifestJson, 'events.ndjson': tampered });
  }

  // --- tamper-count-mismatch ---
  {
    const m = { ...built.manifest, event_count: 99 };
    writeDir('tamper-count-mismatch', { 'manifest.json': JSON.stringify(m, null, 2) + '\n', 'events.ndjson': eventsNdjson });
  }

  // --- tamper-last-hash-mismatch ---
  {
    const m = { ...built.manifest, last_event_hash: 'f'.repeat(64) };
    writeDir('tamper-last-hash-mismatch', { 'manifest.json': JSON.stringify(m, null, 2) + '\n', 'events.ndjson': eventsNdjson });
  }

  // --- tamper-bad-signature: flip signature bytes ---
  {
    const badSig = { ...sig };
    const raw = Buffer.from(badSig.signature, 'base64');
    raw[0] ^= 0xff;
    badSig.signature = raw.toString('base64');
    const m = attachSignature(built.manifest, badSig);
    writeDir('tamper-bad-signature', {
      'manifest.json': JSON.stringify(m, null, 2) + '\n',
      'events.ndjson': eventsNdjson,
      [attachRel]: STDOUT_BYTES,
      'pubkey.pem': pubPem,
    });
  }

  // --- tamper-truncated-tail: cut the final event line, no trailing newline ---
  {
    const lines = eventsNdjson.trimEnd().split('\n');
    const last = lines[lines.length - 1];
    lines[lines.length - 1] = last.slice(0, Math.floor(last.length / 2)); // torn mid-JSON
    const torn = lines.join('\n'); // deliberately no trailing newline
    writeDir('tamper-truncated-tail', { 'manifest.json': manifestJson, 'events.ndjson': torn });
  }

  console.log('fixtures written to', FIX);
  console.log('example first_event_hash:', built.manifest.first_event_hash);
  console.log('example last_event_hash: ', built.manifest.last_event_hash);
  console.log('attachment stdout hash:  ', STDOUT_HASH);
}

main();

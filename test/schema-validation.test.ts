/**
 * Validate SDK outputs against the four VENDORED spec schemas
 * (conformance/schemas/, copied verbatim from the VOLT spec repo). This is the
 * independent check that build/sign/verify emit spec-shaped artifacts, not
 * merely internally-consistent ones.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import { buildBundle } from '../src/build.js';
import { signBundle, attachSignature } from '../src/sign.js';
import { verifyBundle } from '../src/verify.js';
import type { UnchainedEvent } from '../src/types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMAS = join(ROOT, 'conformance', 'schemas');
const FIX = join(ROOT, 'conformance', 'fixtures');

function loadSchema(name: string) {
  return JSON.parse(readFileSync(join(SCHEMAS, name), 'utf8'));
}

let validateEvent: ValidateFunction;
let validateManifest: ValidateFunction;
let validateSignature: ValidateFunction;
let validateReport: ValidateFunction;

beforeAll(() => {
  const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false, allErrors: true });
  const event = loadSchema('event.schema.json');
  const manifest = loadSchema('manifest.schema.json');
  const signature = loadSchema('signature.schema.json');
  const report = loadSchema('verification-report.schema.json');
  ajv.addSchema(signature);
  ajv.addSchema(event);
  ajv.addSchema(manifest);
  ajv.addSchema(report);
  validateEvent = ajv.getSchema(event.$id)!;
  validateManifest = ajv.getSchema(manifest.$id)!;
  validateSignature = ajv.getSchema(signature.$id)!;
  validateReport = ajv.getSchema(report.$id)!;
});

function events(): UnchainedEvent[] {
  return [
    { volt_version: '0.1', event_id: 'E1', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'quox.core' }, context: { correlation_id: 'c' }, payload: { entrypoint: 'api.chat' } },
    { volt_version: '0.1', event_id: 'E2', run_id: 'R', ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'quox.core' }, context: { correlation_id: 'c' }, payload: { status: 'success' } },
  ];
}

describe('outputs validate against vendored spec schemas', () => {
  it('built events validate against event.schema.json', () => {
    const { events: chained } = buildBundle(events(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    for (const ev of chained) {
      expect(validateEvent(ev), JSON.stringify(validateEvent.errors)).toBe(true);
    }
  });

  it('built manifest validates against manifest.schema.json', () => {
    const { manifest } = buildBundle(events(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z', bundleMode: 'final', producer: { name: 'p', version: '0.1.0' } });
    expect(validateManifest(manifest), JSON.stringify(validateManifest.errors)).toBe(true);
  });

  it('signature record validates against signature.schema.json', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = buildBundle(events(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test', signedTs: '2026-02-28T19:00:02.000Z' });
    expect(validateSignature(sig), JSON.stringify(validateSignature.errors)).toBe(true);
  });

  it('a signed manifest (with signatures[]) validates against manifest.schema.json', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = buildBundle(events(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test', signedTs: '2026-02-28T19:00:02.000Z' });
    const signed = attachSignature(manifest, sig);
    expect(validateManifest(signed), JSON.stringify(validateManifest.errors)).toBe(true);
  });

  it('a PASS report validates against verification-report.schema.json', () => {
    const dir = join(FIX, 'valid-simple');
    const report = verifyBundle({
      manifestJson: readFileSync(join(dir, 'manifest.json'), 'utf8'),
      eventsNdjson: readFileSync(join(dir, 'events.ndjson'), 'utf8'),
    });
    expect(validateReport(report), JSON.stringify(validateReport.errors)).toBe(true);
  });

  it('every FAIL report from the tamper fixtures validates against the report schema', () => {
    const fixtures = ['tamper-modified-event', 'tamper-broken-chain', 'tamper-count-mismatch', 'tamper-last-hash-mismatch', 'tamper-truncated-tail'];
    for (const f of fixtures) {
      const dir = join(FIX, f);
      const report = verifyBundle({
        manifestJson: readFileSync(join(dir, 'manifest.json'), 'utf8'),
        eventsNdjson: readFileSync(join(dir, 'events.ndjson'), 'utf8'),
      });
      expect(report.result).toBe('FAIL');
      expect(validateReport(report), `${f}: ${JSON.stringify(validateReport.errors)}`).toBe(true);
    }
  });

  it('an ERROR report validates against the report schema', () => {
    const report = verifyBundle({ manifestJson: '{bad', eventsNdjson: '' });
    expect(validateReport(report), JSON.stringify(validateReport.errors)).toBe(true);
  });
});

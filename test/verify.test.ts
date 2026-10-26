import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey } from 'node:crypto';
import { generateKeyPairSync } from 'node:crypto';
import { verifyBundle, verifyParsedBundle, type AttachmentReader } from '../src/verify.js';
import { buildBundle } from '../src/build.js';
import { signBundle, attachSignature } from '../src/sign.js';
import type { UnchainedEvent, VoltManifest } from '../src/types.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'conformance', 'fixtures');

function raw(name: string) {
  const dir = join(FIX, name);
  return {
    dir,
    manifestJson: readFileSync(join(dir, 'manifest.json'), 'utf8'),
    eventsNdjson: readFileSync(join(dir, 'events.ndjson'), 'utf8'),
  };
}

function fsAttachmentReader(root: string): AttachmentReader {
  return (ref) => {
    const p = join(root, ref.path);
    return existsSync(p) ? new Uint8Array(readFileSync(p)) : null;
  };
}

function simpleEvents(): UnchainedEvent[] {
  return [
    { volt_version: '0.1', event_id: 'E1', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
    { volt_version: '0.1', event_id: 'E2', run_id: 'R', ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
  ];
}

describe('verifyBundle: valid fixtures', () => {
  it('PASSes the valid-simple bundle and verifies its attachment', () => {
    const r = raw('valid-simple');
    const report = verifyBundle(r, { attachmentReader: fsAttachmentReader(r.dir) });
    expect(report.result).toBe('PASS');
    if (report.result === 'PASS') {
      expect(report.event_count).toBe(8);
      expect(report.attachments_verified).toBe(true);
      expect(report.signatures_verified).toBe(false);
      expect(report.warnings).toEqual([]);
    }
  });

  it('PASSes the valid-signed bundle with the embedded key and verifies the signature', () => {
    const r = raw('valid-signed');
    const report = verifyBundle(r, { attachmentReader: fsAttachmentReader(r.dir) });
    expect(report.result).toBe('PASS');
    if (report.result === 'PASS') expect(report.signatures_verified).toBe(true);
  });

  it('PASSes the valid-signed bundle with an external PEM key', () => {
    const r = raw('valid-signed');
    const pem = readFileSync(join(r.dir, 'pubkey.pem'), 'utf8');
    const report = verifyBundle(r, { keyProvider: { publicKey: createPublicKey(pem) } });
    expect(report.result).toBe('PASS');
    if (report.result === 'PASS') expect(report.signatures_verified).toBe(true);
  });
});

describe('verifyBundle: one tamper fixture per failure reason', () => {
  const cases: Array<[string, string]> = [
    ['tamper-modified-event', 'EVENT_HASH_MISMATCH'],
    ['tamper-broken-chain', 'CHAIN_BROKEN'],
    ['tamper-count-mismatch', 'MANIFEST_MISMATCH'],
    ['tamper-last-hash-mismatch', 'MANIFEST_MISMATCH'],
    ['tamper-truncated-tail', 'INVALID_EVENT_JSON'],
  ];
  for (const [fixture, reason] of cases) {
    it(`${fixture} -> FAIL ${reason}`, () => {
      const report = verifyBundle(raw(fixture));
      expect(report.result).toBe('FAIL');
      if (report.result === 'FAIL') expect(report.reason).toBe(reason);
    });
  }

  it('tamper-bad-signature -> FAIL SIGNATURE_INVALID (with key)', () => {
    const r = raw('tamper-bad-signature');
    const pem = readFileSync(join(r.dir, 'pubkey.pem'), 'utf8');
    const report = verifyBundle(r, { keyProvider: { publicKey: createPublicKey(pem) } });
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') expect(report.reason).toBe('SIGNATURE_INVALID');
  });

  it('truncated tail is flagged distinctly as a torn write, not a throw', () => {
    const report = verifyBundle(raw('tamper-truncated-tail'));
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') {
      expect(report.reason).toBe('INVALID_EVENT_JSON');
      expect(report.details?.torn_write).toBe(true);
      expect(report.details?.detail).toBe('TRUNCATED_TAIL');
    }
  });
});

describe('verifyBundle: external anchor (truncation detection)', () => {
  function chainOfThree() {
    const events: UnchainedEvent[] = [
      { volt_version: '0.1', event_id: 'E1', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
      { volt_version: '0.1', event_id: 'E2', run_id: 'R', ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'tool.call.executed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
      { volt_version: '0.1', event_id: 'E3', run_id: 'R', ts: '2026-02-28T19:00:00.020Z', seq: 3, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
    ];
    return buildBundle(events, { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
  }

  it('PASSes when the anchor matches the last event hash', () => {
    const full = chainOfThree();
    const report = verifyParsedBundle(
      { manifest: full.manifest, events: full.events },
      { anchor: { lastEventHash: full.manifest.last_event_hash } },
    );
    expect(report.result).toBe('PASS');
  });

  it('FAILs when a truncated bundle does not reach the anchored last hash', () => {
    const full = chainOfThree();
    const anchoredLast = full.manifest.last_event_hash;
    // Rebuild a bundle from only the first two events (a truncated prefix).
    const truncated = buildBundle(full.events.slice(0, 2), { bundleId: 'B2', createdTs: '2026-02-28T19:00:01.000Z' });
    const report = verifyParsedBundle(
      { manifest: truncated.manifest, events: truncated.events },
      { anchor: { lastEventHash: anchoredLast } },
    );
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') {
      expect(report.reason).toBe('MANIFEST_MISMATCH');
      expect(report.details?.anchor_mismatch).toBe(true);
    }
  });

  it('FAILs when the anchor event count exceeds the bundle count', () => {
    const truncated = chainOfThree();
    const report = verifyParsedBundle(
      { manifest: truncated.manifest, events: truncated.events },
      { anchor: { eventCount: 5 } },
    );
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') expect(report.details?.anchor_mismatch).toBe(true);
  });
});

describe('verifyBundle: no silent signature downgrade', () => {
  function signed(): { manifest: VoltManifest; events: ReturnType<typeof buildBundle>['events'] } {
    const built = buildBundle(simpleEvents(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const { privateKey } = generateKeyPairSync('ed25519');
    // embedPublicKey:false so the bundle is NOT self-verifiable.
    const sig = signBundle(built.manifest, privateKey, { keyId: 'did:key:x', embedPublicKey: false });
    return { manifest: attachSignature(built.manifest, sig), events: built.events };
  }

  it('warns (does not fail) when a signed bundle is verified without a key', () => {
    const { manifest, events } = signed();
    const report = verifyParsedBundle({ manifest, events });
    expect(report.result).toBe('PASS');
    if (report.result === 'PASS') {
      expect(report.signatures_verified).toBe(false);
      expect(report.warnings.join(' ')).toMatch(/not verified/i);
    }
  });

  it('fails when requireSignatures is set and no key is available', () => {
    const { manifest, events } = signed();
    const report = verifyParsedBundle({ manifest, events }, { requireSignatures: true });
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') expect(report.reason).toBe('SIGNATURE_INVALID');
  });

  it('fails when requireSignatures is set and the bundle has no signatures', () => {
    const built = buildBundle(simpleEvents(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const report = verifyParsedBundle({ manifest: built.manifest, events: built.events }, { requireSignatures: true });
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') expect(report.reason).toBe('SIGNATURE_INVALID');
  });
});

describe('verifyBundle: seq handling', () => {
  it('FAILs on a seq gap in strict mode', () => {
    const built = buildBundle(simpleEvents(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    built.events[1].seq = 5; // gap 1 -> 5 (breaks the recomputed hash too, but seq is checked first)
    const report = verifyParsedBundle({ manifest: built.manifest, events: built.events }, { strict: true });
    expect(report.result).toBe('FAIL');
    if (report.result === 'FAIL') expect(report.reason).toBe('SEQ_GAP');
  });

  it('reports MANIFEST_MISSING-style ERROR when manifest is not JSON', () => {
    const report = verifyBundle({ manifestJson: '{ not json', eventsNdjson: '' });
    expect(report.result).toBe('ERROR');
    if (report.result === 'ERROR') expect(report.reason).toBe('MANIFEST_UNREADABLE');
  });
});

describe('verifyBundle: CRLF leniency (M-5)', () => {
  it('PASSes a CRLF-terminated events file (parity with LF)', () => {
    const built = buildBundle(simpleEvents(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const crlf = built.eventsNdjson.trimEnd().split('\n').join('\r\n') + '\r\n';
    const report = verifyBundle({ manifestJson: JSON.stringify(built.manifest), eventsNdjson: crlf });
    expect(report.result).toBe('PASS');
  });

  it('skips a blank CRLF line the same way it skips a blank LF line', () => {
    const built = buildBundle(simpleEvents(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    const lines = built.eventsNdjson.trimEnd().split('\n');
    const withBlank = [lines[0], '', lines[1], ...lines.slice(2)].join('\r\n') + '\r\n';
    const report = verifyBundle({ manifestJson: JSON.stringify(built.manifest), eventsNdjson: withBlank });
    expect(report.result).toBe('PASS');
  });
});

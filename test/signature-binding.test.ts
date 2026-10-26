import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { buildBundle } from '../src/build.js';
import { signBundle, attachSignature } from '../src/sign.js';
import { verifyBundle } from '../src/verify.js';
import type { UnchainedEvent } from '../src/types.js';

export function mk(run: string, n: number): UnchainedEvent[] {
  return Array.from({ length: n }, (_, k) => ({
    volt_version: '0.1',
    event_id: `${run}-E${k + 1}`,
    run_id: run,
    ts: `2026-02-28T19:00:0${k}.000Z`,
    seq: k + 1,
    event_type: 't',
    actor: { actor_type: 'system' as const, actor_id: 'a' },
    context: { correlation_id: 'c' },
    payload: { n: k },
  }));
}

describe('signature message binding (BLOCKER-1: transplant defence)', () => {
  it('rejects a valid signature made for bundle X when transplanted onto bundle Y (pinned key + requireSignatures)', () => {
    const Y = buildBundle(mk('RUN-Y', 3), { bundleId: 'BUNDLE-Y', createdTs: '2026-02-28T19:00:09.000Z' });
    const X = buildBundle(mk('RUN-X', 5), { bundleId: 'BUNDLE-X', createdTs: '2026-02-28T19:00:09.000Z' });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    // A genuine signature over X's endpoints.
    const sigForX = signBundle(X.manifest, privateKey, { keyId: 'signer', signedTs: '2026-02-28T19:00:10.000Z', embedPublicKey: false });
    // Transplant it onto Y, present Y's events, pin the signer's real public key.
    const forged = attachSignature(Y.manifest, sigForX);
    const rep = verifyBundle(
      { manifestJson: JSON.stringify(forged), eventsNdjson: Y.eventsNdjson },
      { requireSignatures: true, keyProvider: { publicKey } },
    );
    expect(rep.result).toBe('FAIL');
    if (rep.result === 'FAIL') {
      expect(rep.reason).toBe('SIGNATURE_INVALID');
      expect(rep.details?.reason).toBe('signature_message_mismatch');
    }
  });

  it('rejects a manifest field tamper that keeps a valid signature over the original message', () => {
    const B = buildBundle(mk('R', 3), { bundleId: 'B', createdTs: '2026-02-28T19:00:09.000Z' });
    const { privateKey } = generateKeyPairSync('ed25519');
    const sig = signBundle(B.manifest, privateKey, { keyId: 'k1', signedTs: '2026-02-28T19:00:10.000Z' });
    const signed = attachSignature(B.manifest, sig);
    // Change bundle_id after signing; the signature still verifies over its own message.
    const tampered = { ...signed, bundle_id: 'MASQUERADE' };
    const rep = verifyBundle(
      { manifestJson: JSON.stringify(tampered), eventsNdjson: B.eventsNdjson },
      { requireSignatures: true },
    );
    expect(rep.result).toBe('FAIL');
    if (rep.result === 'FAIL') {
      expect(rep.reason).toBe('SIGNATURE_INVALID');
      expect(rep.details?.reason).toBe('signature_message_mismatch');
    }
  });

  it('still PASSES a correctly signed bundle (pinned key + requireSignatures)', () => {
    const B = buildBundle(mk('R', 4), { bundleId: 'B', createdTs: '2026-02-28T19:00:09.000Z' });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const sig = signBundle(B.manifest, privateKey, { keyId: 'k1', embedPublicKey: false });
    const signed = attachSignature(B.manifest, sig);
    const rep = verifyBundle(
      { manifestJson: JSON.stringify(signed), eventsNdjson: B.eventsNdjson },
      { requireSignatures: true, keyProvider: { publicKey } },
    );
    expect(rep.result).toBe('PASS');
    if (rep.result === 'PASS') {
      expect(rep.signatures_verified).toBe(true);
    }
  });
});

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { buildBundle } from '../src/build.js';
import { signBundle, attachSignature } from '../src/sign.js';
import { verifyBundle } from '../src/verify.js';
import { mk } from './signature-binding.test.js';

describe('signature trust provenance (M-4)', () => {
  it('reports signature_trust "pinned" when verified against a caller-supplied key', () => {
    const B = buildBundle(mk('R', 2), { bundleId: 'B', createdTs: '2026-02-28T19:00:09.000Z' });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const sig = signBundle(B.manifest, privateKey, { keyId: 'k1', embedPublicKey: false });
    const signed = attachSignature(B.manifest, sig);
    const rep = verifyBundle(
      { manifestJson: JSON.stringify(signed), eventsNdjson: B.eventsNdjson },
      { keyProvider: { publicKey } },
    );
    expect(rep.result).toBe('PASS');
    if (rep.result === 'PASS') {
      expect(rep.signature_trust).toBe('pinned');
      expect(rep.signatures_verified).toBe(true);
    }
  });

  it('reports signature_trust "embedded" and warns identity is unverified when only the bundle-embedded key is used', () => {
    const B = buildBundle(mk('R', 2), { bundleId: 'B', createdTs: '2026-02-28T19:00:09.000Z' });
    const { privateKey } = generateKeyPairSync('ed25519');
    const sig = signBundle(B.manifest, privateKey, { keyId: 'k1' }); // embeds public key
    const signed = attachSignature(B.manifest, sig);
    const rep = verifyBundle(
      { manifestJson: JSON.stringify(signed), eventsNdjson: B.eventsNdjson },
      { requireSignatures: true },
    );
    expect(rep.result).toBe('PASS');
    if (rep.result === 'PASS') {
      expect(rep.signature_trust).toBe('embedded');
      expect(rep.signatures_verified).toBe(true);
      expect(rep.warnings.some((w) => /identity/i.test(w))).toBe(true);
    }
  });

  it('reports signature_trust "none" for an unsigned bundle', () => {
    const B = buildBundle(mk('R', 2), { bundleId: 'B', createdTs: '2026-02-28T19:00:09.000Z' });
    const rep = verifyBundle({ manifestJson: JSON.stringify(B.manifest), eventsNdjson: B.eventsNdjson });
    expect(rep.result).toBe('PASS');
    if (rep.result === 'PASS') {
      expect(rep.signature_trust).toBe('none');
    }
  });
});

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { buildBundle } from '../src/build.js';
import {
  signBundle,
  attachSignature,
  verifySignatureRecord,
  signatureMessageFromManifest,
  reconstructEd25519PublicKey,
  rawPublicKeyBase64,
} from '../src/sign.js';
import type { UnchainedEvent } from '../src/types.js';

function bundle() {
  const events: UnchainedEvent[] = [
    { volt_version: '0.1', event_id: 'E1', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
    { volt_version: '0.1', event_id: 'E2', run_id: 'R', ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
  ];
  return buildBundle(events, { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
}

describe('Ed25519 bundle signing (SPEC section 15)', () => {
  it('signs the bundle-scope message and produces a spec-shaped record', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = bundle();
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test', signedTs: '2026-02-28T19:00:02.000Z' });
    expect(sig.sig_version).toBe('0.1');
    expect(sig.sig_type).toBe('ed25519');
    expect(sig.scope).toBe('bundle');
    expect(sig.message).toEqual(signatureMessageFromManifest(manifest));
    expect(sig.signature).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it('verifies with the matching public key', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = bundle();
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test', embedPublicKey: false });
    const res = verifySignatureRecord(sig, { publicKey });
    expect(res).toEqual({ verified: true, valid: true, keySource: 'pinned' });
  });

  it('self-verifies via the embedded public key', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = bundle();
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test' });
    expect(sig.public_key).toBeTruthy();
    expect(verifySignatureRecord(sig)).toEqual({ verified: true, valid: true, keySource: 'embedded' });
  });

  it('reports verified-but-invalid when signature bytes are tampered', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = bundle();
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test' });
    const raw = Buffer.from(sig.signature, 'base64');
    raw[0] ^= 0xff;
    sig.signature = raw.toString('base64');
    const res = verifySignatureRecord(sig, { publicKey });
    expect(res.verified).toBe(true);
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('signature_mismatch');
  });

  it('reports no_key_available when no key can be resolved', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { manifest } = bundle();
    const sig = signBundle(manifest, privateKey, { keyId: 'did:key:test', embedPublicKey: false });
    const res = verifySignatureRecord(sig);
    expect(res).toEqual({ verified: false, valid: false, reason: 'no_key_available' });
  });

  it('round-trips a raw public key through SPKI reconstruction', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const b64 = rawPublicKeyBase64(publicKey);
    const reconstructed = reconstructEd25519PublicKey(b64);
    expect(reconstructed).not.toBeNull();
    expect(rawPublicKeyBase64(reconstructed!)).toBe(b64);
  });

  it('rejects a non-ed25519 signing key', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { manifest } = bundle();
    expect(() => signBundle(manifest, privateKey, { keyId: 'x' })).toThrow(/ed25519/);
  });
});

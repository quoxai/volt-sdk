/**
 * Ed25519 bundle signing and signature verification (SPEC section 15).
 *
 * The signed message is the bundle-scope object of SPEC section 15.1, and the
 * signature is computed over its Canonical JSON bytes (SPEC section 3.2) so the
 * verifier can reconstruct the exact preimage. Uses node:crypto only.
 *
 * The raw-32-byte-pubkey <-> SPKI DER reconstruction mirrors the live signing
 * path in quox-dashboard/services/collector/lib/volt-certifier.js, so bundles
 * signed there verify here.
 */
import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize } from './canonical.js';
import type { SignatureMessage, SignatureRecord, VoltManifest } from './types.js';

/**
 * SPKI wrapper for a raw 32-byte Ed25519 public key:
 * 30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte key>
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build the SPEC section 15.1 signed message from a manifest. */
export function signatureMessageFromManifest(manifest: VoltManifest): SignatureMessage {
  return {
    run_id: manifest.run_id,
    bundle_id: manifest.bundle_id,
    hash_alg: 'sha256',
    first_event_hash: manifest.first_event_hash,
    last_event_hash: manifest.last_event_hash,
    event_count: manifest.event_count,
  };
}

/** Extract the raw 32-byte public key (base64) from an Ed25519 KeyObject. */
export function rawPublicKeyBase64(key: KeyObject): string {
  const spki = key.export({ type: 'spki', format: 'der' });
  // The raw key is the final 32 bytes of the SPKI DER encoding.
  return Buffer.from(spki.subarray(spki.length - 32)).toString('base64');
}

/**
 * Reconstruct an Ed25519 public KeyObject from a raw 32-byte base64 key.
 * Returns null if the input is not a valid raw Ed25519 key.
 */
export function reconstructEd25519PublicKey(publicKeyB64: string): KeyObject | null {
  try {
    const rawPub = Buffer.from(publicKeyB64, 'base64');
    if (rawPub.length !== 32) return null;
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, rawPub]);
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

export interface SignOptions {
  /** Stable identifier for the signing key (DID or fingerprint). */
  keyId: string;
  /** ISO 8601 UTC signing timestamp. Defaults to now. */
  signedTs?: string;
  /**
   * Embed the raw public key in the signature record so the bundle is
   * self-verifiable without an out-of-band key. Defaults to true.
   */
  embedPublicKey?: boolean;
}

/**
 * Produce an Ed25519 signature record over a manifest's bundle-scope message.
 * `privateKey` may be a node:crypto KeyObject or any input `createPrivateKey`
 * accepts (PEM string/Buffer, JWK, etc.).
 */
export function signBundle(
  manifest: VoltManifest,
  privateKey: KeyObject | string | Buffer,
  options: SignOptions,
): SignatureRecord {
  const keyObj = privateKey instanceof Object && 'asymmetricKeyType' in privateKey
    ? (privateKey as KeyObject)
    : createPrivateKey(privateKey as string | Buffer);

  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`signBundle: expected an ed25519 private key, got ${keyObj.asymmetricKeyType}`);
  }

  const message = signatureMessageFromManifest(manifest);
  const data = Buffer.from(canonicalize(message), 'utf8');
  const signature = edSign(null, data, keyObj).toString('base64');

  const record: SignatureRecord = {
    sig_version: '0.1',
    sig_type: 'ed25519',
    key_id: options.keyId,
    signed_ts: options.signedTs ?? new Date().toISOString(),
    scope: 'bundle',
    message,
    signature,
  };

  if (options.embedPublicKey !== false) {
    record.public_key = rawPublicKeyBase64(createPublicKey(keyObj));
  }

  return record;
}

/** Append a signature record to a manifest's `signatures` array (immutably). */
export function attachSignature(manifest: VoltManifest, sig: SignatureRecord): VoltManifest {
  return { ...manifest, signatures: [...(manifest.signatures ?? []), sig] };
}

/**
 * Where the public key used to verify a signature came from. `pinned` = a key
 * the caller supplied out-of-band (identity-verified). `embedded` = the key
 * carried inside the signature record itself (self-consistent only; proves the
 * record is internally intact, NOT who signed it).
 */
export type KeySource = 'pinned' | 'embedded';

export interface VerifySignatureResult {
  /** True only when the signature bytes were checked and matched. */
  verified: boolean;
  /** True when the signature is cryptographically valid. */
  valid: boolean;
  reason?: string;
  /** Provenance of the verifying key. Present only when a key was resolved. */
  keySource?: KeySource;
}

/**
 * Resolve a public key for a signature record, preferring an explicitly
 * supplied key, then a keyResolver by key_id, then the record's embedded
 * `public_key`. Returns null when no key is available.
 */
export interface KeyProvider {
  /** A single Ed25519 public key applied to every signature. */
  publicKey?: KeyObject | string | Buffer;
  /** Resolve a public key by the signature's `key_id`. */
  keyResolver?: (keyId: string) => KeyObject | string | Buffer | null | undefined;
}

function coercePublicKey(input: KeyObject | string | Buffer): KeyObject | null {
  try {
    if (input instanceof Object && 'asymmetricKeyType' in input) return input as KeyObject;
    return createPublicKey(input as string | Buffer);
  } catch {
    return null;
  }
}

function resolvePublicKey(
  sig: SignatureRecord,
  provider?: KeyProvider,
): { key: KeyObject; source: KeySource } | null {
  if (provider?.publicKey) {
    const k = coercePublicKey(provider.publicKey);
    if (k) return { key: k, source: 'pinned' };
  }
  if (provider?.keyResolver) {
    const resolved = provider.keyResolver(sig.key_id);
    if (resolved) {
      const k = coercePublicKey(resolved);
      if (k) return { key: k, source: 'pinned' };
    }
  }
  if (sig.public_key) {
    const k = reconstructEd25519PublicKey(sig.public_key);
    if (k) return { key: k, source: 'embedded' };
  }
  return null;
}

/**
 * Verify a single signature record.
 *
 * A record with no resolvable key returns `{ verified: false, valid: false,
 * reason: 'no_key_available' }` so callers can distinguish "could not verify"
 * from "verified and invalid" and avoid a silent downgrade.
 */
export function verifySignatureRecord(
  sig: SignatureRecord,
  provider?: KeyProvider,
): VerifySignatureResult {
  if (!sig || typeof sig !== 'object') {
    return { verified: false, valid: false, reason: 'missing_signature' };
  }
  if (sig.sig_type !== 'ed25519') {
    return { verified: false, valid: false, reason: `unsupported_sig_type:${String(sig.sig_type)}` };
  }
  if (!sig.signature || !sig.key_id || !sig.message) {
    return { verified: false, valid: false, reason: 'missing_required_fields' };
  }

  const resolved = resolvePublicKey(sig, provider);
  if (!resolved) {
    return { verified: false, valid: false, reason: 'no_key_available' };
  }

  try {
    const data = Buffer.from(canonicalize(sig.message), 'utf8');
    const sigBuf = Buffer.from(sig.signature, 'base64');
    const ok = edVerify(null, data, resolved.key, sigBuf);
    return ok
      ? { verified: true, valid: true, keySource: resolved.source }
      : { verified: true, valid: false, reason: 'signature_mismatch', keySource: resolved.source };
  } catch (err) {
    return { verified: false, valid: false, reason: `verify_error:${(err as Error).message}` };
  }
}

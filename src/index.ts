/**
 * @quox/volt: VOLT v0.1 evidence bundle SDK.
 *
 * Build, verify, and Ed25519-sign tamper-evident execution traces per the VOLT
 * specification (https://github.com/quoxai/volt). Zero runtime dependencies;
 * cryptography is node:crypto only.
 */
export { VOLT_VERSION } from './version.js';
export { canonicalize } from './canonical.js';
export { GENESIS_PREV_HASH, sha256Hex, sha256Bytes, eventHash, chainEvents } from './hash.js';
export { buildBundle, eventsToNdjson } from './build.js';
export type { BuildOptions, BuildResult } from './build.js';
export {
  signBundle,
  attachSignature,
  verifySignatureRecord,
  signatureMessageFromManifest,
  reconstructEd25519PublicKey,
  rawPublicKeyBase64,
} from './sign.js';
export type { SignOptions, VerifySignatureResult, KeyProvider, KeySource } from './sign.js';
export {
  verifyBundle,
  verifyParsedBundle,
} from './verify.js';
export type {
  VerifyOptions,
  VerifyAnchor,
  RawBundle,
  AttachmentRef,
  AttachmentReader,
} from './verify.js';
export type {
  ActorType,
  VoltActor,
  VoltContext,
  VoltEvent,
  UnchainedEvent,
  VoltManifest,
  VoltProducer,
  VoltBundle,
  SignatureRecord,
  SignatureMessage,
  SignatureTrust,
  FailureReason,
  VerificationReport,
  PassReport,
  FailReport,
  ErrorReport,
} from './types.js';

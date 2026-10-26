/**
 * VOLT v0.1 type definitions.
 *
 * These mirror the vendored JSON schemas in `conformance/schemas/` and the
 * normative field lists in the VOLT SPEC (sections 6, 15, 16, 18). Types are
 * intentionally permissive on optional fields (the schemas allow additional
 * properties for forward compatibility per SPEC section 2.2).
 */

export type ActorType = 'agent' | 'human' | 'system' | 'tool' | 'runner';

/** Who caused or observed an event (SPEC section 6.1). */
export interface VoltActor {
  actor_type: ActorType;
  actor_id: string;
  display_name?: string;
  org_id?: string;
  team_id?: string;
  runner_id?: string;
  [key: string]: unknown;
}

/** Correlation and linkage to AEE/AOCL (SPEC section 6.2). */
export interface VoltContext {
  correlation_id: string;
  parent_event_id?: string;
  aee_envelope_id?: string;
  aee_message_id?: string;
  aocl_policy_id?: string;
  aocl_decision_id?: string;
  workspace_id?: string;
  project_id?: string;
  tags?: string[];
  [key: string]: unknown;
}

/** A single VOLT trace event (SPEC section 6). */
export interface VoltEvent {
  volt_version: string;
  event_id: string;
  run_id: string;
  ts: string;
  seq: number;
  event_type: string;
  actor: VoltActor;
  context: VoltContext;
  payload: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  [key: string]: unknown;
}

/**
 * An event without the two chain-derived fields. Callers hand these to
 * `buildBundle` / `chainEvents`, which fill in `prev_hash` and `hash`.
 */
export type UnchainedEvent = Omit<VoltEvent, 'prev_hash' | 'hash'> & {
  prev_hash?: string;
  hash?: string;
};

/** The signed message for a bundle-scope signature (SPEC section 15.1). */
export interface SignatureMessage {
  run_id: string;
  bundle_id: string;
  hash_alg: 'sha256';
  first_event_hash: string;
  last_event_hash: string;
  event_count: number;
}

/** A signature/attestation record (SPEC section 15.1). */
export interface SignatureRecord {
  sig_version: string;
  sig_type: 'ed25519';
  key_id: string;
  signed_ts: string;
  scope: 'bundle';
  message: SignatureMessage;
  signature: string;
  /**
   * Optional raw 32-byte Ed25519 public key, base64-encoded. Non-normative
   * additive field (the schema allows it via additionalProperties). When
   * present, a verifier can check the signature without an out-of-band key.
   */
  public_key?: string;
  [key: string]: unknown;
}

/** Producer metadata (SPEC section 16.2). */
export interface VoltProducer {
  name?: string;
  version?: string;
  build?: string;
  [key: string]: unknown;
}

/** Evidence Bundle manifest (SPEC sections 10 and 16). */
export interface VoltManifest {
  volt_version: string;
  bundle_id: string;
  run_id: string;
  created_ts: string;
  hash_alg: 'sha256';
  events_file: string;
  event_count: number;
  first_event_hash: string;
  last_event_hash: string;
  bundle_mode?: 'rolling' | 'final';
  cutoff_ts?: string;
  correlation_id?: string;
  producer?: VoltProducer;
  integrations?: Record<string, unknown>;
  redactions_present?: boolean;
  attachments_present?: boolean;
  signatures?: SignatureRecord[];
  notes?: string;
  [key: string]: unknown;
}

/** An in-memory bundle: a manifest plus its ordered events. */
export interface VoltBundle {
  manifest: VoltManifest;
  events: VoltEvent[];
}

/** Standard verifier failure reason codes (VERIFICATION.md section 7). */
export type FailureReason =
  | 'MANIFEST_MISSING'
  | 'MANIFEST_UNREADABLE'
  | 'MANIFEST_SCHEMA_INVALID'
  | 'EVENTS_FILE_MISSING'
  | 'INVALID_EVENT_JSON'
  | 'EVENT_SCHEMA_INVALID'
  | 'VERSION_MISMATCH'
  | 'RUN_ID_MISMATCH'
  | 'SEQ_NOT_MONOTONIC'
  | 'SEQ_DUPLICATE'
  | 'SEQ_GAP'
  | 'EVENT_HASH_MISMATCH'
  | 'INVALID_GENESIS_PREV_HASH'
  | 'CHAIN_BROKEN'
  | 'MANIFEST_MISMATCH'
  | 'ATTACHMENT_MISSING'
  | 'ATTACHMENT_HASH_MISMATCH'
  | 'SIGNATURE_SCHEMA_INVALID'
  | 'SIGNATURE_INVALID'
  | 'UNSUPPORTED_SIGNATURE_TYPE';

/**
 * Provenance of the key that verified a bundle's signature(s).
 * - `pinned`: verified against a caller-supplied (out-of-band) key. Identity
 *   is verified.
 * - `embedded`: verified only against the key embedded in the signature
 *   record. Self-consistent, but the signer's identity is NOT verified.
 * - `none`: no signature was verified (unsigned, or no key available).
 */
export type SignatureTrust = 'pinned' | 'embedded' | 'none';

/** PASS verification report (VERIFICATION.md section 6.1). */
export interface PassReport {
  result: 'PASS';
  run_id: string;
  bundle_id: string;
  volt_version: string;
  hash_alg: string;
  event_count: number;
  first_event_hash: string;
  last_event_hash: string;
  attachments_verified: boolean;
  signatures_verified: boolean;
  /**
   * Trust provenance of the verified signature(s). `signatures_verified: true`
   * with `signature_trust: "embedded"` means the record is self-consistent but
   * the signer's identity was NOT verified against a pinned key.
   */
  signature_trust: SignatureTrust;
  warnings: string[];
}

/** FAIL verification report (VERIFICATION.md section 6.2). */
export interface FailReport {
  result: 'FAIL';
  reason: FailureReason;
  details?: Record<string, unknown>;
}

/** ERROR verification report (VERIFICATION.md section 6.3). */
export interface ErrorReport {
  result: 'ERROR';
  reason: string;
  details?: Record<string, unknown>;
}

export type VerificationReport = PassReport | FailReport | ErrorReport;

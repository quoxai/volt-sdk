/**
 * Evidence Bundle verification (VERIFICATION.md sections 5, 6, 7; SPEC
 * section 11). VOLT-V conformant.
 *
 * The verifier operates on the RAW manifest text and RAW events NDJSON text so
 * that byte-level defects (a torn final line from an interrupted write) are
 * detected rather than silently swallowed by a lenient parse. It is fs-free:
 * attachment bytes are supplied through an optional reader callback, so the
 * core runs unchanged in a browser or a worker.
 */
import { eventHash, sha256Bytes, GENESIS_PREV_HASH } from './hash.js';
import { canonicalize } from './canonical.js';
import { verifySignatureRecord, signatureMessageFromManifest, type KeyProvider } from './sign.js';
import type {
  FailReport,
  FailureReason,
  PassReport,
  SignatureRecord,
  SignatureTrust,
  VerificationReport,
  VoltBundle,
  VoltEvent,
  VoltManifest,
} from './types.js';

/** An attachment the verifier was asked to check. */
export interface AttachmentRef {
  hash: string;
  path: string;
  content_type?: string;
  label?: string;
}

/** Supplies raw attachment bytes by content-addressed path. Returns null if absent. */
export type AttachmentReader = (ref: AttachmentRef) => Uint8Array | null;

/** External trust anchor to detect truncation against a known-good endpoint. */
export interface VerifyAnchor {
  /** Expected hash of the last event in the complete run. */
  lastEventHash?: string;
  /** Expected hash of the first event. */
  firstEventHash?: string;
  /** Expected total event count of the complete run. */
  eventCount?: number;
  /** A trusted signed manifest whose message endpoints are the anchor. */
  signedManifest?: VoltManifest;
}

export interface VerifyOptions {
  /** Strict mode fails on seq gaps; permissive warns. Default true. */
  strict?: boolean;
  /** Attachment reader; when absent, referenced attachments are not verified. */
  attachmentReader?: AttachmentReader;
  /** Public key material for signature verification. */
  keyProvider?: KeyProvider;
  /**
   * Treat a bundle whose signatures cannot be verified (or that has none) as a
   * failure. Prevents a silent signature downgrade. Default false.
   */
  requireSignatures?: boolean;
  /** External endpoint to check for truncation / tampering. */
  anchor?: VerifyAnchor;
}

/** Raw text form of a bundle: exactly what is on disk. */
export interface RawBundle {
  manifestJson: string;
  eventsNdjson: string;
}

const REQUIRED_MANIFEST_FIELDS = [
  'volt_version',
  'bundle_id',
  'run_id',
  'created_ts',
  'hash_alg',
  'events_file',
  'event_count',
  'first_event_hash',
  'last_event_hash',
] as const;

const REQUIRED_EVENT_FIELDS: Array<[string, 'string' | 'number' | 'object']> = [
  ['volt_version', 'string'],
  ['event_id', 'string'],
  ['run_id', 'string'],
  ['ts', 'string'],
  ['seq', 'number'],
  ['event_type', 'string'],
  ['actor', 'object'],
  ['context', 'object'],
  ['payload', 'object'],
  ['prev_hash', 'string'],
  ['hash', 'string'],
];

function fail(reason: FailureReason, details?: Record<string, unknown>): FailReport {
  return details ? { result: 'FAIL', reason, details } : { result: 'FAIL', reason };
}

function error(reason: string, details?: Record<string, unknown>): VerificationReport {
  return { result: 'ERROR', reason, details };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Verify a bundle from its raw text. This is the primary entry point; the
 * torn-write check depends on seeing the un-parsed NDJSON bytes.
 */
export function verifyBundle(raw: RawBundle, options: VerifyOptions = {}): VerificationReport {
  const strict = options.strict !== false;

  // --- Step 0: manifest ---
  let manifest: VoltManifest;
  try {
    manifest = JSON.parse(raw.manifestJson) as VoltManifest;
  } catch (err) {
    return error('MANIFEST_UNREADABLE', { message: `manifest.json is not valid JSON: ${(err as Error).message}` });
  }
  if (!isPlainObject(manifest)) {
    return error('MANIFEST_UNREADABLE', { message: 'manifest.json is not a JSON object' });
  }
  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!(field in manifest)) {
      return fail('MANIFEST_SCHEMA_INVALID', { missing_field: field });
    }
  }

  // --- Step 1: load events (with torn-write detection) ---
  const endsWithNewline = raw.eventsNdjson.endsWith('\n');
  const allLines = raw.eventsNdjson.split('\n');
  const contentLines: Array<{ lineNo: number; text: string }> = [];
  for (let i = 0; i < allLines.length; i++) {
    // M-5: tolerate CRLF line endings by stripping a single trailing '\r' so a
    // bare '\r' (a blank line in a CRLF file, after splitting on '\n') is
    // skipped exactly like a blank LF line, and stored/verified forms match.
    let text = allLines[i];
    if (text.endsWith('\r')) text = text.slice(0, -1);
    if (text.length === 0) continue; // skip blank lines (incl. trailing newline artifact)
    contentLines.push({ lineNo: i + 1, text });
  }

  if (contentLines.length === 0) {
    return fail('EVENTS_FILE_MISSING', { message: 'events file contains no event lines' });
  }

  const events: VoltEvent[] = [];
  for (let idx = 0; idx < contentLines.length; idx++) {
    const { lineNo, text } = contentLines[idx];
    try {
      events.push(JSON.parse(text) as VoltEvent);
    } catch (err) {
      const isFinal = idx === contentLines.length - 1;
      // A parse failure on the final content line of a file that does not end
      // in a newline is the signature of a torn write (an event append that
      // was interrupted mid-line). Reported distinctly via details so it is
      // not confused with mid-file corruption, while keeping the spec reason
      // code (INVALID_EVENT_JSON) so the report validates against the schema.
      const tornTail = isFinal && !endsWithNewline;
      return fail('INVALID_EVENT_JSON', {
        line: lineNo,
        torn_write: tornTail,
        detail: tornTail ? 'TRUNCATED_TAIL' : 'MALFORMED_LINE',
        message: `event line ${lineNo} is not valid JSON: ${(err as Error).message}`,
      });
    }
  }

  return verifyParsedEvents(manifest, events, options, strict);
}

/**
 * Verify an already-parsed in-memory bundle. Skips torn-write detection (there
 * are no raw bytes to inspect) but performs every other check.
 */
export function verifyParsedBundle(bundle: VoltBundle, options: VerifyOptions = {}): VerificationReport {
  const strict = options.strict !== false;
  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!(field in bundle.manifest)) {
      return fail('MANIFEST_SCHEMA_INVALID', { missing_field: field });
    }
  }
  if (!Array.isArray(bundle.events) || bundle.events.length === 0) {
    return fail('EVENTS_FILE_MISSING', { message: 'bundle has no events' });
  }
  return verifyParsedEvents(bundle.manifest, bundle.events, options, strict);
}

function verifyParsedEvents(
  manifest: VoltManifest,
  events: VoltEvent[],
  options: VerifyOptions,
  strict: boolean,
): VerificationReport {
  const warnings: string[] = [];

  // --- Step 2: ordering ---
  let prevSeq = 0;
  for (const ev of events) {
    if (typeof ev.seq !== 'number' || !Number.isInteger(ev.seq)) {
      return fail('EVENT_SCHEMA_INVALID', { event_id: ev.event_id, field: 'seq' });
    }
    if (ev.seq === prevSeq) {
      return fail('SEQ_DUPLICATE', { seq: ev.seq, event_id: ev.event_id });
    }
    if (ev.seq < prevSeq) {
      return fail('SEQ_NOT_MONOTONIC', { seq: ev.seq, previous_seq: prevSeq, event_id: ev.event_id });
    }
    if (ev.seq > prevSeq + 1) {
      if (strict) {
        return fail('SEQ_GAP', { seq: ev.seq, previous_seq: prevSeq, event_id: ev.event_id });
      }
      warnings.push(`seq gap between ${prevSeq} and ${ev.seq}`);
    }
    prevSeq = ev.seq;
  }
  if (events[0].seq !== 1) {
    return fail('EVENT_SCHEMA_INVALID', { message: 'first event seq must be 1', found: events[0].seq });
  }

  // --- Step 3: required event fields ---
  for (const ev of events) {
    for (const [field, kind] of REQUIRED_EVENT_FIELDS) {
      const val = (ev as Record<string, unknown>)[field];
      const ok =
        kind === 'object'
          ? isPlainObject(val)
          : kind === 'number'
            ? typeof val === 'number'
            : typeof val === 'string';
      if (!ok) {
        return fail('EVENT_SCHEMA_INVALID', { event_id: ev.event_id, seq: ev.seq, field });
      }
    }
  }

  // --- Step 4: version compatibility ---
  for (const ev of events) {
    if (ev.volt_version !== manifest.volt_version) {
      return fail('VERSION_MISMATCH', {
        seq: ev.seq,
        event_volt_version: ev.volt_version,
        manifest_volt_version: manifest.volt_version,
      });
    }
  }

  // --- Step 5: recompute + validate event hashes ---
  for (const ev of events) {
    const computed = eventHash(ev);
    if (computed !== ev.hash) {
      return fail('EVENT_HASH_MISMATCH', {
        seq: ev.seq,
        event_id: ev.event_id,
        expected_hash: computed,
        found_hash: ev.hash,
      });
    }
  }

  // --- Step 6: validate the chain ---
  if (events[0].prev_hash !== GENESIS_PREV_HASH) {
    return fail('INVALID_GENESIS_PREV_HASH', {
      seq: 1,
      event_id: events[0].event_id,
      prev_hash_found: events[0].prev_hash,
    });
  }
  for (let i = 1; i < events.length; i++) {
    if (events[i].prev_hash !== events[i - 1].hash) {
      return fail('CHAIN_BROKEN', {
        seq: events[i].seq,
        event_id: events[i].event_id,
        prev_hash_found: events[i].prev_hash,
        prev_hash_expected: events[i - 1].hash,
      });
    }
  }

  // --- Step 7: run_id consistency ---
  for (const ev of events) {
    if (ev.run_id !== manifest.run_id) {
      return fail('RUN_ID_MISMATCH', {
        seq: ev.seq,
        event_run_id: ev.run_id,
        manifest_run_id: manifest.run_id,
      });
    }
  }

  // --- Step 8: manifest counts + endpoints ---
  const firstHash = events[0].hash;
  const lastHash = events[events.length - 1].hash;
  if (manifest.event_count !== events.length) {
    return fail('MANIFEST_MISMATCH', {
      field: 'event_count',
      manifest_value: manifest.event_count,
      actual_value: events.length,
    });
  }
  if (manifest.first_event_hash !== firstHash) {
    return fail('MANIFEST_MISMATCH', {
      field: 'first_event_hash',
      manifest_value: manifest.first_event_hash,
      actual_value: firstHash,
    });
  }
  if (manifest.last_event_hash !== lastHash) {
    return fail('MANIFEST_MISMATCH', {
      field: 'last_event_hash',
      manifest_value: manifest.last_event_hash,
      actual_value: lastHash,
    });
  }

  // --- External anchor (truncation detection against a trusted endpoint) ---
  const anchorReport = checkAnchor(options.anchor, { firstHash, lastHash, count: events.length });
  if (anchorReport) return anchorReport;

  // --- Step 9: attachments ---
  let attachmentsVerified = false;
  const refs = collectAttachmentRefs(events);
  if (refs.length > 0) {
    if (options.attachmentReader) {
      for (const ref of refs) {
        const bytes = options.attachmentReader(ref);
        if (bytes == null) {
          return fail('ATTACHMENT_MISSING', { hash: ref.hash, path: ref.path });
        }
        const computed = sha256Bytes(bytes);
        if (computed !== ref.hash) {
          return fail('ATTACHMENT_HASH_MISMATCH', {
            path: ref.path,
            expected_hash: ref.hash,
            actual_hash: computed,
          });
        }
      }
      attachmentsVerified = true;
    } else {
      warnings.push(`${refs.length} attachment reference(s) present but not verified (no attachment reader supplied)`);
    }
  }

  // --- Step 10: signatures ---
  const sigOutcome = verifySignatures(manifest, options);
  if (sigOutcome.failure) return sigOutcome.failure;
  warnings.push(...sigOutcome.warnings);

  const pass: PassReport = {
    result: 'PASS',
    run_id: manifest.run_id,
    bundle_id: manifest.bundle_id,
    volt_version: manifest.volt_version,
    hash_alg: manifest.hash_alg,
    event_count: events.length,
    first_event_hash: firstHash,
    last_event_hash: lastHash,
    attachments_verified: attachmentsVerified,
    signatures_verified: sigOutcome.signaturesVerified,
    signature_trust: sigOutcome.signatureTrust,
    warnings,
  };
  return pass;
}

function checkAnchor(
  anchor: VerifyAnchor | undefined,
  actual: { firstHash: string; lastHash: string; count: number },
): FailReport | null {
  if (!anchor) return null;
  const expectedLast = anchor.lastEventHash ?? anchor.signedManifest?.last_event_hash;
  const expectedFirst = anchor.firstEventHash ?? anchor.signedManifest?.first_event_hash;
  const expectedCount = anchor.eventCount ?? anchor.signedManifest?.event_count;

  if (expectedLast != null && expectedLast !== actual.lastHash) {
    return fail('MANIFEST_MISMATCH', {
      anchor_mismatch: true,
      field: 'last_event_hash',
      expected_last_event_hash: expectedLast,
      found_last_event_hash: actual.lastHash,
      note: 'bundle endpoint does not match external anchor (possible truncation or tampering)',
    });
  }
  if (expectedFirst != null && expectedFirst !== actual.firstHash) {
    return fail('MANIFEST_MISMATCH', {
      anchor_mismatch: true,
      field: 'first_event_hash',
      expected_first_event_hash: expectedFirst,
      found_first_event_hash: actual.firstHash,
      note: 'bundle first-event endpoint does not match external anchor',
    });
  }
  if (expectedCount != null && expectedCount !== actual.count) {
    return fail('MANIFEST_MISMATCH', {
      anchor_mismatch: true,
      field: 'event_count',
      expected_event_count: expectedCount,
      found_event_count: actual.count,
      note: 'bundle event count does not match external anchor (possible truncation)',
    });
  }
  return null;
}

function collectAttachmentRefs(events: VoltEvent[]): AttachmentRef[] {
  const out: AttachmentRef[] = [];
  for (const ev of events) {
    const refs = (ev.payload as Record<string, unknown>)?.attachment_refs;
    if (!Array.isArray(refs)) continue;
    for (const r of refs) {
      if (!isPlainObject(r) || typeof r.hash !== 'string') continue;
      const hash = r.hash;
      out.push({
        hash,
        path: `attachments/${hash.slice(0, 2)}/${hash}`,
        content_type: typeof r.content_type === 'string' ? r.content_type : undefined,
        label: typeof r.label === 'string' ? r.label : undefined,
      });
    }
  }
  return out;
}

const REQUIRED_SIG_FIELDS = ['sig_version', 'sig_type', 'key_id', 'signed_ts', 'scope', 'message', 'signature'];

function verifySignatures(
  manifest: VoltManifest,
  options: VerifyOptions,
): { failure: FailReport | null; signaturesVerified: boolean; signatureTrust: SignatureTrust; warnings: string[] } {
  const warnings: string[] = [];
  const signatures: SignatureRecord[] = Array.isArray(manifest.signatures) ? manifest.signatures : [];

  if (signatures.length === 0) {
    if (options.requireSignatures) {
      return {
        failure: fail('SIGNATURE_INVALID', {
          reason: 'signatures_required_but_absent',
          note: 'requireSignatures is set but the bundle carries no signatures',
        }),
        signaturesVerified: false,
        signatureTrust: 'none',
        warnings,
      };
    }
    return { failure: null, signaturesVerified: false, signatureTrust: 'none', warnings };
  }

  let anyValid = false;
  let anyUnverifiable = false;
  let anyPinned = false;
  let anyEmbeddedOnly = false;

  for (const sig of signatures) {
    for (const f of REQUIRED_SIG_FIELDS) {
      if (!(f in sig)) {
        return {
          failure: fail('SIGNATURE_SCHEMA_INVALID', { missing_field: f, key_id: sig.key_id }),
          signaturesVerified: false,
          signatureTrust: 'none',
          warnings,
        };
      }
    }
    if (sig.scope !== 'bundle') {
      return {
        failure: fail('SIGNATURE_SCHEMA_INVALID', { field: 'scope', value: sig.scope }),
        signaturesVerified: false,
        signatureTrust: 'none',
        warnings,
      };
    }

    const res = verifySignatureRecord(sig, options.keyProvider);
    if (res.verified && !res.valid) {
      // Present and cryptographically wrong: tampering. Always a failure.
      return {
        failure: fail('SIGNATURE_INVALID', { key_id: sig.key_id, reason: res.reason }),
        signaturesVerified: false,
        signatureTrust: 'none',
        warnings,
      };
    }
    if (res.verified && res.valid) {
      // Signature binding (BLOCKER-1): a cryptographically valid signature only
      // proves the signer signed *some* message. Assert that message is THIS
      // bundle's message, derived from the already-verified manifest (the same
      // helper signBundle uses), so a signature made for bundle X cannot be
      // transplanted onto bundle Y. On mismatch this is tampering, not a
      // downgrade: always a hard failure.
      const expected = signatureMessageFromManifest(manifest);
      if (canonicalize(sig.message) !== canonicalize(expected)) {
        return {
          failure: fail('SIGNATURE_INVALID', {
            key_id: sig.key_id,
            reason: 'signature_message_mismatch',
            note: 'signature is cryptographically valid but attests a different bundle than the one presented',
          }),
          signaturesVerified: false,
          signatureTrust: 'none',
          warnings,
        };
      }
      anyValid = true;
      // M-4: distinguish identity-verified (pinned key) from self-consistent
      // (bundle-embedded key). An embedded key proves the record is internally
      // intact, NOT who signed it.
      if (res.keySource === 'pinned') anyPinned = true;
      else anyEmbeddedOnly = true;
    } else {
      // No key available for this signature: cannot verify.
      anyUnverifiable = true;
    }
  }

  if (anyUnverifiable && !anyValid) {
    // No signature could be checked. Do not silently downgrade.
    if (options.requireSignatures) {
      return {
        failure: fail('SIGNATURE_INVALID', {
          reason: 'signatures_present_but_unverifiable',
          note: 'requireSignatures is set but no signing key was available to verify the signature(s)',
        }),
        signaturesVerified: false,
        signatureTrust: 'none',
        warnings,
      };
    }
    warnings.push('signatures present but not verified (no signing key provided)');
    return { failure: null, signaturesVerified: false, signatureTrust: 'none', warnings };
  }

  if (anyUnverifiable && anyValid) {
    warnings.push('some signatures could not be verified (no key), but at least one verified');
  }

  // Trust provenance: pinned (identity-verified) outranks embedded
  // (self-consistent only). Emit a warning whenever the only verified
  // signatures came from a bundle-embedded key, so requireSignatures does not
  // silently imply the signer's identity was checked.
  const signatureTrust: SignatureTrust = anyPinned ? 'pinned' : anyEmbeddedOnly ? 'embedded' : 'none';
  if (signatureTrust === 'embedded') {
    warnings.push(
      'signature verified against the bundle-embedded key only; signer identity is NOT verified against a pinned key',
    );
  }

  return { failure: null, signaturesVerified: anyValid, signatureTrust, warnings };
}

/**
 * Evidence Bundle construction (SPEC sections 10, 16 and EVIDENCE_BUNDLES.md).
 *
 * `buildBundle` takes a list of events, chains them (SPEC section 7), and
 * emits a spec-conformant manifest plus the `events.ndjson` text. It is
 * VOLT-B conformant: required manifest fields per SPEC section 16.1, events
 * serialized one-per-line as NDJSON per SPEC section 3.1.
 */
import { randomUUID } from 'node:crypto';
import { chainEvents } from './hash.js';
import type {
  UnchainedEvent,
  VoltEvent,
  VoltManifest,
  VoltProducer,
} from './types.js';

export interface BuildOptions {
  /** Bundle identifier. Defaults to a random UUIDv4. */
  bundleId?: string;
  /** Manifest `created_ts` (ISO 8601 UTC). Defaults to now. */
  createdTs?: string;
  /** Events filename recorded in the manifest. Defaults to `events.ndjson`. */
  eventsFile?: string;
  bundleMode?: 'rolling' | 'final';
  cutoffTs?: string;
  correlationId?: string;
  producer?: VoltProducer;
  integrations?: Record<string, unknown>;
  redactionsPresent?: boolean;
  attachmentsPresent?: boolean;
  notes?: string;
}

export interface BuildResult {
  manifest: VoltManifest;
  events: VoltEvent[];
  /** The exact bytes to write to the events file, one JSON object per line. */
  eventsNdjson: string;
}

/**
 * Serialize events to NDJSON text (SPEC section 3.1): one compact JSON object
 * per line, UTF-8, trailing newline. The stored line form is standard
 * `JSON.stringify` (NOT canonical JSON) so that the event's own `hash` field
 * is included verbatim; canonical form is only used for hashing.
 */
export function eventsToNdjson(events: VoltEvent[]): string {
  return events.map((e) => JSON.stringify(e)).join('\n') + '\n';
}

/**
 * Build an Evidence Bundle from an ordered list of events.
 *
 * @throws if `events` is empty. SPEC section 16.1 requires `event_count >= 1`,
 *   so an empty bundle can never be schema-valid.
 */
export function buildBundle(events: UnchainedEvent[], options: BuildOptions = {}): BuildResult {
  if (!Array.isArray(events) || events.length === 0) {
    throw new Error('buildBundle: at least one event is required (SPEC section 16.1: event_count >= 1)');
  }

  const chained = chainEvents(events);

  const runIds = new Set(chained.map((e) => e.run_id));
  if (runIds.size !== 1) {
    throw new Error(
      `buildBundle: all events must share one run_id (found ${runIds.size}: ${[...runIds].join(', ')})`,
    );
  }
  const runId = chained[0].run_id;
  const voltVersion = chained[0].volt_version;

  const firstEventHash = chained[0].hash;
  const lastEventHash = chained[chained.length - 1].hash;

  const manifest: VoltManifest = {
    volt_version: voltVersion,
    bundle_id: options.bundleId ?? randomUUID(),
    run_id: runId,
    created_ts: options.createdTs ?? new Date().toISOString(),
    hash_alg: 'sha256',
    events_file: options.eventsFile ?? 'events.ndjson',
    event_count: chained.length,
    first_event_hash: firstEventHash,
    last_event_hash: lastEventHash,
  };

  if (options.bundleMode) manifest.bundle_mode = options.bundleMode;
  if (options.cutoffTs) manifest.cutoff_ts = options.cutoffTs;
  if (options.correlationId) manifest.correlation_id = options.correlationId;
  if (options.producer) manifest.producer = options.producer;
  if (options.integrations) manifest.integrations = options.integrations;
  if (typeof options.redactionsPresent === 'boolean') manifest.redactions_present = options.redactionsPresent;
  if (typeof options.attachmentsPresent === 'boolean') manifest.attachments_present = options.attachmentsPresent;
  if (options.notes) manifest.notes = options.notes;

  return {
    manifest,
    events: chained,
    eventsNdjson: eventsToNdjson(chained),
  };
}

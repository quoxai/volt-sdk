import { describe, it, expect } from 'vitest';
import { buildBundle, eventsToNdjson } from '../src/build.js';
import { GENESIS_PREV_HASH } from '../src/hash.js';
import type { UnchainedEvent } from '../src/types.js';

function events(runId = 'R'): UnchainedEvent[] {
  return [
    { volt_version: '0.1', event_id: 'E1', run_id: runId, ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: { entrypoint: 'api.chat' } },
    { volt_version: '0.1', event_id: 'E2', run_id: runId, ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: { status: 'success' } },
  ];
}

describe('buildBundle (SPEC section 16)', () => {
  it('emits all required manifest fields', () => {
    const { manifest } = buildBundle(events(), { bundleId: 'B', createdTs: '2026-02-28T19:00:01.000Z' });
    for (const f of ['volt_version', 'bundle_id', 'run_id', 'created_ts', 'hash_alg', 'events_file', 'event_count', 'first_event_hash', 'last_event_hash']) {
      expect(manifest).toHaveProperty(f);
    }
    expect(manifest.hash_alg).toBe('sha256');
    expect(manifest.events_file).toBe('events.ndjson');
    expect(manifest.event_count).toBe(2);
  });

  it('computes first/last event hash from the chain', () => {
    const { manifest, events: chained } = buildBundle(events(), {});
    expect(manifest.first_event_hash).toBe(chained[0].hash);
    expect(manifest.last_event_hash).toBe(chained[chained.length - 1].hash);
    expect(chained[0].prev_hash).toBe(GENESIS_PREV_HASH);
  });

  it('serializes events as newline-terminated NDJSON', () => {
    const { eventsNdjson, events: chained } = buildBundle(events(), {});
    expect(eventsNdjson.endsWith('\n')).toBe(true);
    const lines = eventsNdjson.trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).event_id).toBe('E1');
    expect(eventsToNdjson(chained)).toBe(eventsNdjson);
  });

  it('throws on an empty event list (event_count must be >= 1)', () => {
    expect(() => buildBundle([], {})).toThrow(/at least one event/);
  });

  it('throws when events span more than one run_id', () => {
    const mixed = [...events('R1'), ...events('R2')];
    expect(() => buildBundle(mixed, {})).toThrow(/one run_id/);
  });

  // MAJOR-1: canonical.ts mapped undefined -> 'null' for HASHING while
  // eventsToNdjson used JSON.stringify, which DROPS undefined keys from the
  // STORED line. verify re-parsed a different object and recomputed a
  // different hash, so buildBundle silently emitted a bundle that failed its
  // own verify. Policy: reject undefined at build time.
  it('rejects an event payload carrying an undefined value rather than emitting an un-verifiable bundle', () => {
    const evs: UnchainedEvent[] = [
      { volt_version: '0.1', event_id: 'U1', run_id: 'RU', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'x' }, context: { correlation_id: 'c' }, payload: { a: undefined, b: 2 } },
    ];
    expect(() => buildBundle(evs, { bundleId: 'BU', createdTs: '2026-02-28T19:00:01.000Z' })).toThrow(/undefined/i);
  });

  it('passes through optional manifest fields when supplied', () => {
    const { manifest } = buildBundle(events(), { bundleMode: 'final', correlationId: 'c', producer: { name: 'p' }, attachmentsPresent: false });
    expect(manifest.bundle_mode).toBe('final');
    expect(manifest.correlation_id).toBe('c');
    expect(manifest.producer).toEqual({ name: 'p' });
    expect(manifest.attachments_present).toBe(false);
  });
});

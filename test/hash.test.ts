import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { sha256Hex, sha256Bytes, eventHash, chainEvents, GENESIS_PREV_HASH } from '../src/hash.js';
import type { UnchainedEvent } from '../src/types.js';

describe('hashing primitives (SPEC section 4, 7)', () => {
  it('GENESIS_PREV_HASH is 64 hex zeros', () => {
    expect(GENESIS_PREV_HASH).toBe('0'.repeat(64));
    expect(GENESIS_PREV_HASH).toMatch(/^[0-9a-f]{64}$/);
  });

  it('sha256Hex matches node:crypto', () => {
    expect(sha256Hex('abc')).toBe(createHash('sha256').update('abc', 'utf8').digest('hex'));
  });

  it('sha256Bytes hashes raw bytes', () => {
    const bytes = Buffer.from('service is active\n', 'utf8');
    expect(sha256Bytes(bytes)).toBe(createHash('sha256').update(bytes).digest('hex'));
  });

  it('eventHash removes the hash field before hashing', () => {
    const base = {
      volt_version: '0.1', event_id: 'X', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1,
      event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' },
      context: { correlation_id: 'c' }, payload: {}, prev_hash: GENESIS_PREV_HASH,
    };
    const withStale = { ...base, hash: 'stale' };
    const withCorrect = { ...base, hash: eventHash(base) };
    expect(eventHash(withStale)).toBe(eventHash(withCorrect));
  });
});

describe('chainEvents (SPEC section 7.2, 7.3)', () => {
  const raw: UnchainedEvent[] = [
    { volt_version: '0.1', event_id: 'E1', run_id: 'R', ts: '2026-02-28T19:00:00.000Z', seq: 1, event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
    { volt_version: '0.1', event_id: 'E2', run_id: 'R', ts: '2026-02-28T19:00:00.010Z', seq: 2, event_type: 'run.completed', actor: { actor_type: 'system', actor_id: 'a' }, context: { correlation_id: 'c' }, payload: {} },
  ];

  it('assigns genesis prev_hash to the first event', () => {
    const chained = chainEvents(raw);
    expect(chained[0].prev_hash).toBe(GENESIS_PREV_HASH);
  });

  it('links each event prev_hash to the prior hash', () => {
    const chained = chainEvents(raw);
    expect(chained[1].prev_hash).toBe(chained[0].hash);
  });

  it('produces hashes that match eventHash of the chained event', () => {
    const chained = chainEvents(raw);
    for (const ev of chained) expect(ev.hash).toBe(eventHash(ev));
  });

  it('ignores and recomputes any pre-existing hash/prev_hash', () => {
    const dirty = raw.map((e) => ({ ...e, prev_hash: 'garbage', hash: 'garbage' }));
    const chained = chainEvents(dirty);
    expect(chained[0].prev_hash).toBe(GENESIS_PREV_HASH);
    expect(chained[0].hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

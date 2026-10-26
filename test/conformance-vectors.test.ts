/**
 * EXTERNAL CONFORMANCE VECTORS.
 *
 * The expected hashes below are FROZEN LITERALS. They are not produced by any
 * code in src/. Two independent oracles cross-check them:
 *
 *   1. An inline canonicalize + SHA-256 written with raw node:crypto in THIS
 *      file (no import from src/). If src/ and this file ever drift, the inline
 *      oracle catches it.
 *   2. The frozen literal strings themselves, computed once out-of-band and
 *      pinned here. If src/ AND the inline oracle both drift the same way, the
 *      literals still catch it. This is what stops the conformance suite from
 *      being self-licking.
 *
 * Only after both oracles agree do we assert that src/eventHash matches.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { eventHash } from '../src/hash.js';

const GENESIS = '0'.repeat(64);

// --- Oracle 1: inline, raw node:crypto, zero src/ imports ---
function inlineCanonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return String(obj);
  if (typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') return JSON.stringify(obj.normalize('NFC'));
  if (Array.isArray(obj)) return `[${obj.map(inlineCanonicalize).join(',')}]`;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${inlineCanonicalize((obj as Record<string, unknown>)[k])}`).join(',')}}`;
}
function inlineEventHash(event: Record<string, unknown>): string {
  const { hash: _omit, ...rest } = event;
  void _omit;
  return createHash('sha256').update(inlineCanonicalize(rest), 'utf8').digest('hex');
}

// --- Frozen literals (Oracle 2) ---
const V1_HASH = 'c6f2e87d21faaad34ceb3e27c3abd5ded6814c97464231ea7ffb1de6b6557135';
const V2_HASH = 'a0973121feb91235659a5eb59aea8859809a5bcd21bb34030f5a46c3f057fcb3';
const V3_HASH = 'a82c4b6667dd607d6ab50507c3f7a125a6fe1c0ecb5ae971edce5637a06a89cd';

const v1 = {
  volt_version: '0.1', event_id: 'CV1', run_id: 'CV-RUN', ts: '2026-02-28T19:00:00.000Z', seq: 1,
  event_type: 'run.started', actor: { actor_type: 'system', actor_id: 'quox.core' },
  context: { correlation_id: 'cv-corr' }, payload: { entrypoint: 'api.chat' }, prev_hash: GENESIS,
};
const v2 = {
  volt_version: '0.1', event_id: 'CV2', run_id: 'CV-RUN', ts: '2026-02-28T19:00:00.010Z', seq: 2,
  event_type: 'tool.call.executed', actor: { actor_type: 'runner', actor_id: 'runner:node-01' },
  context: { correlation_id: 'cv-corr', tags: ['a', 'b'] },
  payload: { tool_name: 'shell', status: 'success', duration_ms: 42 }, prev_hash: V1_HASH,
};
// Intentionally unsorted keys + a non-ASCII string to exercise key-sort + NFC.
const v3 = {
  payload: { z: 1, a: 2, nested: { y: 'å', x: 2 } },
  volt_version: '0.1', event_id: 'CV3', run_id: 'CV-RUN', ts: '2026-02-28T19:00:00.020Z', seq: 3,
  event_type: 'model.responded', actor: { actor_id: 'quox.agent.ops', actor_type: 'agent' },
  context: { correlation_id: 'cv-corr' }, prev_hash: V2_HASH,
};

describe('external conformance vectors', () => {
  it('vector 1 (genesis): inline oracle == frozen literal == src', () => {
    expect(inlineEventHash(v1)).toBe(V1_HASH);
    expect(eventHash(v1)).toBe(V1_HASH);
  });

  it('vector 2 (chained): inline oracle == frozen literal == src', () => {
    expect(inlineEventHash(v2)).toBe(V2_HASH);
    expect(eventHash(v2)).toBe(V2_HASH);
  });

  it('vector 3 (unsorted keys + NFC): inline oracle == frozen literal == src', () => {
    expect(inlineEventHash(v3)).toBe(V3_HASH);
    expect(eventHash(v3)).toBe(V3_HASH);
  });
});

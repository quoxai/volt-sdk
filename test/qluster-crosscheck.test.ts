/**
 * Cross-check against the reference bundler in
 * quox-qluster/server/lib/volt.js. Its canonicalize() + event-hash preimage
 * construction are ported verbatim below (a scratch helper, no src/ import for
 * the reference side) and the resulting hashes are asserted bit-exact against
 * this SDK's chainEvents/eventHash. If either implementation drifts, this test
 * breaks. This is what makes "conformant" mean interoperable rather than
 * internally consistent.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { chainEvents, eventHash } from '../src/hash.js';
import type { UnchainedEvent } from '../src/types.js';

// --- verbatim port of quox-qluster/server/lib/volt.js ---
const GENESIS_PREV_HASH = '0'.repeat(64);
function qlusterSha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
function qlusterCanonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return String(obj);
  if (typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') return JSON.stringify((obj as string).normalize('NFC'));
  if (Array.isArray(obj)) return `[${obj.map(qlusterCanonicalize).join(',')}]`;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${qlusterCanonicalize((obj as Record<string, unknown>)[k])}`).join(',')}}`;
}
function qlusterEventHash(eventWithoutHash: Record<string, unknown>): string {
  return qlusterSha256(qlusterCanonicalize(eventWithoutHash));
}
// qluster's envelopeToEvent output shape (its exact field set + order concerns
// do not matter for hashing since canonicalize sorts keys).
function qlusterEnvelopeToEvent(
  envelope: { id: string; ts: string; intent: string; from: string; type: string; to: string; priority?: string; payload?: Record<string, unknown>; reply_to?: string },
  { runId, seq, prevHash }: { runId: string; seq: number; prevHash: string },
) {
  const payloadKeys = envelope.payload && typeof envelope.payload === 'object' ? Object.keys(envelope.payload) : [];
  const context: Record<string, unknown> = { correlation_id: runId, aee_envelope_id: envelope.id };
  if (envelope.reply_to) context.parent_event_id = envelope.reply_to;
  const event: Record<string, unknown> = {
    volt_version: '0.1', event_id: envelope.id, run_id: runId, ts: envelope.ts, seq,
    event_type: envelope.intent,
    actor: { actor_type: 'system', actor_id: envelope.from },
    context,
    payload: { envelope_type: envelope.type, to: envelope.to, priority: envelope.priority ?? 'normal', payload_keys: payloadKeys },
    prev_hash: prevHash,
  };
  event.hash = qlusterEventHash(event);
  return event;
}

const envelopes = [
  { id: 'env-a', ts: '2026-02-28T19:00:00.000Z', intent: 'qluster.delegate.started', from: 'human.adam', type: 'task', to: 'agent.ops', payload: { text: 'do', mode: 'x' } },
  { id: 'env-b', ts: '2026-02-28T19:00:00.500Z', intent: 'qluster.delegate.completed', from: 'agent.ops', type: 'result', to: 'human.adam', reply_to: 'env-a', payload: { status: 'ok' } },
];

describe('bit-exact cross-check vs quox-qluster volt.js', () => {
  it('produces identical event hashes for the same envelope inputs', () => {
    // Reference side: chain with the ported qluster code.
    let prev = GENESIS_PREV_HASH;
    const refEvents = envelopes.map((env, i) => {
      const e = qlusterEnvelopeToEvent(env, { runId: 'CORR-X', seq: i + 1, prevHash: prev });
      prev = e.hash as string;
      return e;
    });

    // SDK side: build the same event objects (minus hash/prev_hash) and chain.
    const sdkInput: UnchainedEvent[] = envelopes.map((env, i) => ({
      volt_version: '0.1', event_id: env.id, run_id: 'CORR-X', ts: env.ts, seq: i + 1,
      event_type: env.intent,
      actor: { actor_type: 'system', actor_id: env.from },
      context: env.reply_to
        ? { correlation_id: 'CORR-X', aee_envelope_id: env.id, parent_event_id: env.reply_to }
        : { correlation_id: 'CORR-X', aee_envelope_id: env.id },
      payload: { envelope_type: env.type, to: env.to, priority: env.priority ?? 'normal', payload_keys: env.payload ? Object.keys(env.payload) : [] },
    }));
    const sdkEvents = chainEvents(sdkInput);

    expect(sdkEvents.map((e) => e.hash)).toEqual(refEvents.map((e) => e.hash));
    expect(sdkEvents[0].prev_hash).toBe(GENESIS_PREV_HASH);
    expect(sdkEvents[1].prev_hash).toBe(sdkEvents[0].hash);
    // And the SDK's own eventHash (which strips the hash field) reproduces the
    // stored reference hash for each event.
    for (let i = 0; i < sdkEvents.length; i++) {
      expect(eventHash(sdkEvents[i])).toBe(refEvents[i].hash);
    }
  });
});

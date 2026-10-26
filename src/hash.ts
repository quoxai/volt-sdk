/**
 * VOLT event hashing and chaining (SPEC section 7).
 *
 * Uses node:crypto only. No third-party dependencies.
 */
import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';
import type { VoltEvent, UnchainedEvent } from './types.js';

/** SPEC section 7.2: the genesis (seq=1) event's prev_hash is 64 hex zeros. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

/** SHA-256 of a UTF-8 string, lowercase hex (SPEC section 4.2). */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** SHA-256 of raw bytes, lowercase hex (used for attachment hashing, SPEC section 9.1). */
export function sha256Bytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Event hash per SPEC section 7.1:
 *   SHA-256( CanonicalJSON( EventWithoutHashField ) )
 *
 * The `hash` field is removed before hashing regardless of whether the input
 * carries one, so this is safe to call on a fully-formed event.
 */
export function eventHash(event: Record<string, unknown>): string {
  const { hash: _omit, ...withoutHash } = event as { hash?: unknown };
  void _omit;
  return sha256Hex(canonicalize(withoutHash));
}

/**
 * Chain a list of events (SPEC section 7): assign `prev_hash` (genesis for the
 * first, the prior event's `hash` for the rest) and compute each `hash`.
 *
 * Any pre-existing `prev_hash`/`hash` on the input events is ignored and
 * recomputed, so this is deterministic no matter what the caller passed.
 * Input order is preserved and is treated as authoritative; callers are
 * responsible for ordering events by `seq` ascending before chaining.
 */
export function chainEvents(events: UnchainedEvent[]): VoltEvent[] {
  let prevHash = GENESIS_PREV_HASH;
  return events.map((raw) => {
    const { hash: _h, prev_hash: _p, ...core } = raw as Record<string, unknown>;
    void _h;
    void _p;
    const withPrev = { ...core, prev_hash: prevHash };
    const hash = eventHash(withPrev);
    prevHash = hash;
    return { ...withPrev, hash } as VoltEvent;
  });
}

/**
 * Canonical JSON serialization (VOLT SPEC section 3.2).
 *
 * Produces a deterministic byte representation so the same event hashes
 * identically across implementations:
 *   - object keys sorted lexicographically (byte-wise) at every nesting level
 *   - no insignificant whitespace
 *   - strings Unicode NFC-normalized
 *   - numbers via the platform's shortest round-trip form
 *
 * This is a direct, bit-exact port of the canonicalize() in
 * quox-qluster/server/lib/volt.js (the reference recorder/bundler). Keeping it
 * byte-identical is what lets a bundle produced there verify here and vice
 * versa; the cross-check is asserted in test/qluster-crosscheck.test.ts.
 *
 * Note on numbers (SPEC section 3.2, point 3): JavaScript's String(number)
 * yields the shortest round-trippable decimal and drops any trailing ".0" for
 * integral values, which satisfies the spec for the integer and small-decimal
 * values VOLT events carry (seq, counts, durations). A value whose shortest
 * form requires exponent notation (magnitude >= 1e21 or denormalized), or a
 * non-finite number, would hash to an unstable/invalid form, so canonicalize
 * throws NonConformantNumber rather than silently hashing it.
 *
 * Note on undefined: undefined is not a JSON value; canonicalize throws rather
 * than coercing it to null (which would diverge from the stored NDJSON line).
 */
export function canonicalize(obj: unknown): string {
  // `undefined` has no JSON representation. Mapping it to 'null' for hashing
  // (while JSON.stringify silently drops undefined-valued keys from the stored
  // NDJSON line) makes the stored bytes and the hash preimage diverge, and
  // collides {a:undefined} with {a:null}. Reject it here, the single
  // canonicalization chokepoint, so build/verify can never disagree (SPEC 3.2:
  // canonical JSON is defined over JSON values; undefined is not one).
  if (obj === undefined) {
    throw new Error(
      'canonicalize: undefined is not representable in VOLT Canonical JSON (SPEC 3.2); omit the key or use null before hashing',
    );
  }
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return String(obj);
  if (typeof obj === 'number') {
    // SPEC 3.2(3): numbers MUST be without exponent notation and finite. A
    // value whose shortest round-trip string carries an exponent (>= 1e21 or a
    // denormalized magnitude) hashes to an unstable form across implementations;
    // NaN/Infinity are not valid JSON at all. Refuse rather than silently hash.
    if (!Number.isFinite(obj)) {
      throw new Error(`NonConformantNumber: ${String(obj)} is not a finite JSON number (SPEC 3.2)`);
    }
    const s = String(obj);
    if (s.includes('e') || s.includes('E')) {
      throw new Error(
        `NonConformantNumber: ${s} requires exponent notation, forbidden by VOLT Canonical JSON (SPEC 3.2 point 3)`,
      );
    }
    return s;
  }
  if (typeof obj === 'string') return JSON.stringify(obj.normalize('NFC'));
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalize((obj as Record<string, unknown>)[k])}`)
    .join(',')}}`;
}

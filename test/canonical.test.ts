import { describe, it, expect } from 'vitest';
import { canonicalize } from '../src/canonical.js';

describe('canonicalize (SPEC section 3.2)', () => {
  it('sorts object keys lexicographically at the top level', () => {
    expect(canonicalize({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  it('sorts keys at every nesting level', () => {
    expect(canonicalize({ z: { y: 1, x: 2 }, a: [{ q: 1, p: 2 }] })).toBe(
      '{"a":[{"p":2,"q":1}],"z":{"x":2,"y":1}}',
    );
  });

  it('emits no insignificant whitespace', () => {
    expect(canonicalize({ a: 1, b: [1, 2, 3] })).toBe('{"a":1,"b":[1,2,3]}');
  });

  it('renders integral numbers without a trailing .0', () => {
    expect(canonicalize({ seq: 8, count: 128 })).toBe('{"count":128,"seq":8}');
  });

  it('NFC-normalizes strings so composed and decomposed forms hash equal', () => {
    const composed = 'å'; // U+00E5
    const decomposed = 'å'; // 'a' + combining ring above
    expect(canonicalize({ v: composed })).toBe(canonicalize({ v: decomposed }));
  });

  it('encodes null and booleans deterministically', () => {
    expect(canonicalize({ a: null, b: true, c: false })).toBe('{"a":null,"b":true,"c":false}');
  });

  it('preserves array order', () => {
    expect(canonicalize(['c', 'a', 'b'])).toBe('["c","a","b"]');
  });

  // MAJOR-1 / M-2: undefined has no JSON representation. Mapping it to 'null'
  // for hashing while JSON.stringify drops it from the stored line makes the
  // stored bytes and the hash preimage diverge, and collides {a:undefined}
  // with {a:null}. Policy: reject undefined at canonicalization time.
  it('rejects an undefined value inside an object (distinct from null)', () => {
    expect(() => canonicalize({ a: undefined })).toThrow(/undefined/i);
  });

  it('keeps null distinct: null serializes, absent is absent, undefined throws', () => {
    expect(canonicalize({ a: null })).toBe('{"a":null}');
    expect(canonicalize({})).toBe('{}');
    expect(() => canonicalize({ a: undefined })).toThrow();
  });

  it('rejects undefined nested in an array', () => {
    expect(() => canonicalize([1, undefined, 3])).toThrow(/undefined/i);
  });

  // M-3: String(1e21) === '1e+21', which violates SPEC 3.2(3) (no exponent
  // notation). Silently hashing an unstable form is worse than refusing it.
  it('rejects a large number that forces exponent notation (SPEC 3.2 point 3)', () => {
    expect(() => canonicalize(1e21)).toThrow(/NonConformantNumber/);
  });

  it('rejects a tiny number that forces exponent notation', () => {
    expect(() => canonicalize(1e-7)).toThrow(/NonConformantNumber/);
  });

  it('rejects non-finite numbers (NaN, Infinity)', () => {
    expect(() => canonicalize(NaN)).toThrow(/NonConformantNumber/);
    expect(() => canonicalize(Infinity)).toThrow(/NonConformantNumber/);
  });

  it('still accepts ordinary integers and small decimals', () => {
    expect(canonicalize({ seq: 8, ms: 812, ratio: 0.25 })).toBe('{"ms":812,"ratio":0.25,"seq":8}');
    expect(canonicalize(-0)).toBe('0');
  });
});

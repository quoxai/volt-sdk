# @quox/volt

A standalone library for **VOLT v0.1 evidence bundles**: build, verify, and
Ed25519-sign tamper-evident execution traces, and check them independently.

VOLT (Verifiable Operations Ledger & Trace) is an open protocol for producing
portable, hash-chained evidence of what an agentic workflow actually did. This
package is a clean-room implementation of the **Record → Bundle → Verify** loop
defined in the [VOLT spec](https://github.com/quoxai/volt).

- **Zero runtime dependencies.** Cryptography is Node's built-in `node:crypto`
  only. `ajv` is a dev dependency used solely to validate outputs against the
  vendored spec schemas in tests.
- **Spec-conformant.** Event hashing and chaining per SPEC section 7, manifest
  per SPEC section 16, signatures per SPEC section 15, verification per
  VERIFICATION.md, report format per SPEC section 18.
- **Interoperable, not self-licking.** Conformance is anchored to frozen
  external hash vectors and a bit-exact cross-check against the reference
  bundler in `quox-qluster` (see `test/conformance-vectors.test.ts` and
  `test/qluster-crosscheck.test.ts`).

## Status

Version `0.1.0`. Tracks VOLT protocol v0.1. This is an early release: the core
build/verify/sign paths and the CLI are covered by the test suite, but the API
surface may still change before a `1.0` line.

**[STATUS_AND_LIMITS.md](./STATUS_AND_LIMITS.md) is the honest source of truth
for what works and what doesn't.** Where this README and that file disagree,
that file wins. Snapshot as of the last verification pass: 83 tests across 11
files, all green, run live against this checkout. Not built: a Python port
(this package is TypeScript/Node only).

## Install (from source)

**Publishing to npm at launch.** This package is not yet on the public npm
registry. Until it is published there are no `npm install @quox/volt`
instructions to give, and this README will not pretend otherwise. The repo
(github.com/quoxai/volt-sdk) opens at launch as well. To use the package today,
build it from a checkout:

```bash
cd volt-sdk
npm install
npm run build
```

Then reference the built package by path (`npm install /path/to/volt-sdk`),
via `npm link`, or import from source in a monorepo. The `import ... from
'@quox/volt'` lines below work once the package is linked or path-installed.

## What it does

| Capability | Function | Conformance target |
|-----------|----------|--------------------|
| Canonical JSON | `canonicalize` | SPEC section 3.2 |
| Event hashing + chaining | `eventHash`, `chainEvents` | SPEC section 7 |
| Build a bundle | `buildBundle` | VOLT-B (SPEC section 16) |
| Verify a bundle | `verifyBundle`, `verifyParsedBundle` | VOLT-V (VERIFICATION.md) |
| Ed25519 sign | `signBundle`, `attachSignature` | SPEC section 15 |
| Verify a signature | `verifySignatureRecord` | SPEC section 15 |
| CLI | `bin/volt-verify.mjs` | SPEC section 18.2 |

## Library usage

```ts
import { buildBundle, verifyBundle, signBundle, attachSignature } from '@quox/volt';
import { generateKeyPairSync } from 'node:crypto';

// 1. Build a bundle from ordered events (each without prev_hash/hash; the
//    builder chains them and computes every hash).
const { manifest, events, eventsNdjson } = buildBundle(myEvents, {
  bundleMode: 'final',
  producer: { name: 'my-recorder', version: '1.0.0' },
});

// 2. Optionally sign it (Ed25519).
const { privateKey } = generateKeyPairSync('ed25519');
const sig = signBundle(manifest, privateKey, { keyId: 'did:key:...' });
const signedManifest = attachSignature(manifest, sig);

// 3. Verify from the raw text (this is what catches a torn final line).
const report = verifyBundle({
  manifestJson: JSON.stringify(signedManifest),
  eventsNdjson,
});
// report.result is 'PASS' | 'FAIL' | 'ERROR'
```

### Notable verification options

- **External anchor.** Pass `anchor: { lastEventHash }` (or a trusted
  `signedManifest`, or an `eventCount`) to detect a truncated bundle that does
  not reach a known-good endpoint. Reported as `MANIFEST_MISMATCH` with
  `details.anchor_mismatch = true`.
- **Signature message binding.** A signature is only accepted when its
  `message` matches the message derived from the verified manifest (via the
  same `signatureMessageFromManifest` helper `signBundle` uses). A signature
  legitimately made for one bundle cannot be transplanted onto another: the
  mismatch fails as `SIGNATURE_INVALID` with
  `details.reason: "signature_message_mismatch"`, even with a pinned key.
- **No silent signature downgrade.** Verifying a signed bundle without a key
  yields a PASS with a warning and `signatures_verified: false`, never a silent
  "looks fine". Set `requireSignatures: true` to make an unverifiable (or
  absent) signature a hard failure.
- **Signature trust provenance.** A PASS report carries
  `signature_trust: "pinned" | "embedded" | "none"`. `pinned` means the
  signature was checked against a caller-supplied (out-of-band) key, so the
  signer's identity is verified. `embedded` means it was checked only against
  the key carried inside the signature record: self-consistent, but the
  signer's identity is NOT verified (a warning is emitted, and this holds even
  under `requireSignatures`). `none` means no signature was verified.
- **Torn-write tolerance.** A truncated final NDJSON line is reported as
  `INVALID_EVENT_JSON` with `details.torn_write: true` and
  `details.detail: "TRUNCATED_TAIL"`, distinguishing an interrupted append from
  mid-file corruption. It is never an unhandled throw.
- **CRLF tolerance.** CRLF (`\r\n`) line endings verify identically to LF; a
  single trailing `\r` is stripped per line before parsing, so a blank CRLF
  line is skipped like a blank LF line.

### Canonicalization strictness

`canonicalize` (and therefore `eventHash`, `chainEvents`, and `buildBundle`)
rejects values that have no stable Canonical JSON form, rather than silently
hashing an unstable one:

- **`undefined` is rejected.** It has no JSON representation; mapping it to
  `null` for hashing while `JSON.stringify` drops it from the stored line would
  make the stored bytes and the hash preimage diverge. Use `null` or omit the
  key. (`null` and an absent key remain distinct and valid.)
- **Exponent / non-finite numbers are rejected** with a `NonConformantNumber`
  error. A number whose shortest form needs exponent notation (magnitude
  `>= 1e21` or denormalized), or `NaN`/`Infinity`, violates SPEC 3.2(3).

As a result `buildBundle` never emits a bundle that fails its own verify: an
undefined-bearing or non-conformant-number payload throws a clear error at
build time instead.

## CLI

```
node bin/volt-verify.mjs <bundle-dir>
node bin/volt-verify.mjs --manifest manifest.json --events events.ndjson
node bin/volt-verify.mjs <bundle-dir> --pubkey key.pem --require-signatures
node bin/volt-verify.mjs <bundle-dir> --no-strict
```

Prints the verification report as JSON. Exit codes: `0` = PASS, `1` = FAIL,
`2` = ERROR (unreadable bundle / IO).

## Bundle format (recap)

A bundle is a folder (or zip of the same layout) containing at least:

```
manifest.json        # index + endpoints (SPEC section 16)
events.ndjson        # one hash-chained event per line (SPEC section 3.1)
attachments/<ab>/<hash>   # optional, content-addressed (SPEC section 9)
```

Events are linked by `prev_hash` (64 hex zeros for the genesis event), and each
event's `hash` is `SHA-256(CanonicalJSON(event without its hash field))`.

## Development

```
npm install
npm run build          # tsc -> dist/
npm test               # vitest
npm run gen-fixtures   # regenerate conformance/fixtures/ (requires a prior build)
```

## Conformance fixtures

`conformance/fixtures/` contains valid bundles plus one tamper fixture per
failure reason (modified event, broken chain, manifest count mismatch,
first/last hash mismatch, bad signature, truncated tail). `conformance/schemas/`
holds the four spec schemas, vendored verbatim, that outputs are validated
against.

## License

Apache-2.0. See [LICENSE](./LICENSE).

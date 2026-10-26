# STATUS_AND_LIMITS — VOLT SDK

> Treat the README and CHANGELOG as marketing-adjacent. Treat this file as the source of truth for what works and what doesn't in this package.

**Repo:** `volt-sdk` (`@quox/volt` TypeScript). MIT licensed, unpublished. Version `0.1.0`, tracks VOLT protocol v0.1.
**Created:** 2026-07-25. **Last verified:** 2026-07-25 (tests run live against this checkout).
**Authoritative paths:** `src/canonical.ts`, `src/hash.ts`, `src/build.ts`, `src/verify.ts`, `src/sign.ts`, `bin/volt-verify.mjs`, `conformance/` (fixtures + vendored spec schemas).

## How to read the tags

| Tag | Meaning |
|---|---|
| **Stable-candidate** | Fully implemented, spec-conformant, backed by an automated test suite with a live green run. Not "Stable" in the strict production-use sense yet (pre-launch, zero deployed consumers), but no known gap between spec and implementation. |
| **Not built** | Does not exist. |

## Maturity table

| Capability | Status | Notes |
|---|---|---|
| Canonical JSON (`canonicalize`) | Stable-candidate | SPEC §3.2. `test/canonical.test.ts` (14 tests). |
| Event hashing + chaining (`eventHash`, `chainEvents`) | Stable-candidate | SPEC §7. `test/hash.test.ts` (8 tests). |
| Bundle build (`buildBundle`) | Stable-candidate | Manifest per SPEC §16, events.ndjson output. `test/build.test.ts` (7 tests). |
| Bundle verify (`verifyBundle`, `verifyParsedBundle`) | Stable-candidate | Per VERIFICATION.md. `test/verify.test.ts` (20 tests). |
| Ed25519 signing (`signBundle`, `attachSignature`) | Stable-candidate | SPEC §15. `test/sign.test.ts` (7 tests, includes rejection of a non-Ed25519 signing key). |
| Signature message binding | Stable-candidate | A signature's `message` must match the message derived from the verified manifest; a signature made for bundle X cannot be transplanted onto bundle Y even with a pinned trusted key and `requireSignatures`. Fails as `SIGNATURE_INVALID` with `details.reason: "signature_message_mismatch"`. `test/signature-binding.test.ts` (3 tests). |
| Signature trust labelling | Stable-candidate | PASS reports carry `signature_trust: "pinned" \| "embedded" \| "none"`. `embedded` (checked only against the key inside the signature record) is explicitly flagged as identity-unverified, even under `requireSignatures`. `test/signature-trust.test.ts` (6 tests). |
| External anchor | Stable-candidate | `anchor: { lastEventHash }` (or a trusted `signedManifest`, or `eventCount`) detects a truncated bundle; reported as `MANIFEST_MISMATCH` with `details.anchor_mismatch = true`. |
| Torn-write tolerance | Stable-candidate | A truncated final NDJSON line reports as `INVALID_EVENT_JSON` with `details.torn_write: true` / `details.detail: "TRUNCATED_TAIL"`, never an unhandled throw. CRLF line endings verified to behave identically to LF. |
| `volt-verify` CLI | Stable-candidate | Exit codes: 0 PASS, 1 FAIL, 2 ERROR. `test/cli.test.ts` (7 tests). |
| External + cross-implementation conformance | Stable-candidate | `test/conformance-vectors.test.ts` (3 tests) anchors to frozen external hash vectors. `test/qluster-crosscheck.test.ts` (1 test) is a bit-exact cross-check against the independent reference bundler in `quox-qluster`, so conformance is not self-verifying against this SDK's own writer. |
| Whole suite | Stable-candidate | 83 tests across 11 files, all green as of this verification pass (`npx vitest run`). |

## Strict behaviours (intentional, not bugs)

- **`undefined` is rejected at canonicalization.** `undefined` has no stable Canonical JSON form: mapping it to `null` would diverge from the stored NDJSON line (since `JSON.stringify` silently drops undefined-valued keys), which would make the stored bytes and the hash preimage disagree. `canonicalize` throws instead of silently hashing an unstable value. `null` and an absent key remain distinct and valid.
- **Exponent-form and non-finite numbers are rejected** with a `NonConformantNumber` error, per SPEC §3.2(3): a number whose shortest form needs exponent notation (magnitude >= 1e21, or denormalized) or that is `NaN`/`Infinity` cannot be hashed in a stable way, so it throws at build time rather than producing a bundle that later fails its own verify.

## Known product divergence (flag for the reader, not an SDK bug)

The QuoxCORE collector's own VOLT emitter (`quox-dashboard/services/collector/lib/voltEmitter.js`) implements a separate, older canonical-JSON routine that behaves differently from this SDK on two points verified directly in that file:

- It **filters out `undefined`-valued keys** (`.filter(k => obj[k] !== undefined)`) rather than rejecting them, so a payload containing `undefined` hashes successfully in the collector but would throw in this SDK.
- It does **not NFC-normalize strings** before hashing (no Unicode normalization step present in `canonicalJSON`).

The practical effect: for a payload containing non-NFC-normalized strings or `undefined`-bearing keys, the collector's emitted hash and this SDK's computed hash for the "same" logical event will diverge. This is a product alignment gap, not a defect in this SDK; tracked as a separate product ticket, not tracked in this repo.

## Not built

- **Python port.** This package is JavaScript/TypeScript only.

## Known gaps

- Version `0.1.0` is an early release per the README's own "Status" section: the core build/verify/sign paths and the CLI are covered, but the API surface may still change before a `1.0` line. Treat as pre-1.0 API stability, not just pre-launch packaging.

## What this SDK is NOT

- Not a database or storage layer; it builds and verifies bundle folders (manifest + events.ndjson + optional attachments), it does not persist or query them.
- Not the same canonicalization implementation the QuoxCORE collector currently uses in production; see the divergence note above before assuming hash parity across the two.

## Cross-cutting (applies to all four SDK repos: aee-sdk, ward-sdk, volt-sdk, aocl-sdk)

- None of the four packages are published to npm or PyPI yet. Publishing is owner-gated, planned for launch.
- None of the four repos have a public GitHub remote configured yet (`git remote -v` returns empty in all four checkouts as of this verification). Publishing the remote is owner-gated.
- Install-from-source only today. Any `npm install @quox/volt` instruction elsewhere is aspirational until launch.
- Zero runtime dependencies (`node:crypto` only; `ajv` is a dev/test dependency used solely to validate outputs against vendored spec schemas in tests).

# Changelog

All notable changes to `@quox/volt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
semantic versioning. The leading `0.` version tracks the VOLT protocol v0.1.

## [Unreleased]

### Security

- **Signature message binding (BLOCKER).** `verifyBundle` now asserts that a
  cryptographically valid signature's `message` matches the message derived
  from the verified manifest (single source of truth: `signatureMessageFromManifest`,
  shared by `signBundle` and the verifier). A signature legitimately made for
  bundle X can no longer be transplanted onto bundle Y, even with a pinned
  trusted key and `requireSignatures`. Mismatch fails as `SIGNATURE_INVALID`
  with `details.reason: "signature_message_mismatch"`.

### Changed

- **Undefined is rejected in canonical JSON (MAJOR).** `canonicalize` no longer
  maps `undefined` to `'null'`. It previously diverged from the stored NDJSON
  line (`JSON.stringify` drops undefined-valued keys), so `buildBundle` could
  emit a bundle that failed its own verify, and `{a:undefined}` collided with
  `{a:null}`. `undefined` now throws; `null` and an absent key remain distinct.
- **Exponent and non-finite numbers are rejected.** `canonicalize` throws
  `NonConformantNumber` for a number whose shortest form requires exponent
  notation (magnitude `>= 1e21` or denormalized) or that is `NaN`/`Infinity`,
  per SPEC 3.2(3), instead of hashing an unstable form.
- **CRLF line endings tolerated consistently.** A single trailing `\r` is
  stripped per event line before the blank-line check and parse, so CRLF files
  (including blank CRLF lines) verify identically to LF.

### Added

- **`signature_trust` report field** (`"pinned" | "embedded" | "none"`).
  Distinguishes a signature verified against a caller-pinned key
  (identity-verified) from one verified only against the bundle-embedded key
  (self-consistent). Verifying via an embedded key alone now emits a warning
  that the signer's identity is unverified, even under `requireSignatures`.
  `verifySignatureRecord` reports the verifying key's provenance via `keySource`.

## [0.1.0] - 2026-07-25

Initial release. Implements the VOLT v0.1 Record → Bundle → Verify loop as a
standalone, zero-runtime-dependency library.

### Added

- **Core hashing and chaining** (`canonicalize`, `eventHash`, `chainEvents`,
  `sha256Hex`, `sha256Bytes`) per SPEC sections 3.2, 4, and 7.
- **Bundle build** (`buildBundle`, `eventsToNdjson`): events to a
  spec-conformant `manifest.json` plus `events.ndjson`, computing first/last
  event hash and event count. VOLT-B conformant.
- **Bundle verify** (`verifyBundle`, `verifyParsedBundle`): full VERIFICATION.md
  algorithm producing a spec-conformant verification report. VOLT-V conformant.
  Includes:
  - external anchor support (`anchor`) to detect truncation against a trusted
    endpoint or signed manifest,
  - no silent signature downgrade (unverifiable signatures warn by default;
    `requireSignatures` makes them fail),
  - torn-write tolerance (a truncated final NDJSON line is reported as
    `INVALID_EVENT_JSON` with `details.torn_write`, never an unhandled throw).
- **Ed25519 signing and verification** (`signBundle`, `attachSignature`,
  `verifySignatureRecord`) per SPEC section 15, using `node:crypto` only.
- **`volt-verify` CLI** (`bin/volt-verify.mjs`): verify a bundle directory or a
  manifest/events file pair; exit `0` valid / `1` invalid / `2` unreadable.
- **Conformance fixtures** (`conformance/fixtures/`): valid and signed bundles
  plus one tamper fixture per failure reason.
- **Vendored spec schemas** (`conformance/schemas/`) with tests validating all
  outputs against them.
- **External conformance vectors**: frozen expected hashes cross-checked with
  raw `node:crypto` and a bit-exact comparison against the reference bundler in
  `quox-qluster`.

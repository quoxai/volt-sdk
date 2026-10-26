# Security policy

## What this library guarantees

`@quox/volt` implements the VOLT v0.1 tamper-evidence and chain-of-custody
model. A successful verification (`result: "PASS"`) means:

- every event's `hash` matches its canonical content,
- every event links to the previous one via `prev_hash`,
- the manifest's count and first/last endpoints match the events,
- any referenced attachments (when a reader is supplied) match their hashes,
- any signatures checked with an available key are cryptographically valid.

## What it does NOT guarantee

- It does not prove the host or runner was uncompromised during execution.
- It does not prove recorded tool results are "true" beyond what was recorded.
- Without signatures, a chain that an attacker fully rewrote (re-hashing every
  event) cannot be distinguished from the original. Ed25519 signatures over the
  bundle endpoints (SPEC section 15) are what defeat a full rewrite. Use
  `requireSignatures: true` where non-repudiation matters.

## Cryptography

- Hashing: SHA-256 over Canonical JSON (SPEC sections 3.2, 4, 7).
- Signatures: Ed25519 via `node:crypto` only. No third-party crypto.
- The signed message is the SPEC section 15.1 bundle-scope object, signed over
  its Canonical JSON bytes.

## Handling of signing keys

- This library never generates, stores, or transmits private keys on your
  behalf. Callers pass a private key (or `KeyObject`) into `signBundle` and are
  responsible for its storage and lifecycle.
- An optional `public_key` (raw 32-byte Ed25519 key, base64) may be embedded in
  a signature record so a bundle is self-verifiable. This is a convenience for
  distribution; for strong assurance, verify against a key obtained
  out-of-band (`keyProvider.publicKey` or `keyProvider.keyResolver`) rather than
  trusting the embedded key.

## No secrets in evidence

Per SPEC section 2.1, VOLT events MUST NOT contain secrets (API keys, tokens,
passwords, private keys). This library does not redact for you: producers are
responsible for keeping payloads metadata-only before calling `buildBundle`.

## Reporting a vulnerability

Report suspected vulnerabilities privately to security@quox.ai rather than
opening a public issue. Please include a reproduction and the affected
version. Triage is best-effort and carries no service-level agreement.

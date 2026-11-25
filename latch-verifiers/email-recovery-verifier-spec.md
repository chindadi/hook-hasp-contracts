# Email / DKIM Recovery Verifier Spec

A stateless Soroban verifier specification for validating cryptographic proofs of email recovery (`DKIM-Signature` header + RFC 5322 canonicalized headers) on behalf of Latch smart accounts.

## Overview

Email recovery enables a Latch smart account owner (or designated guardian domain) to authorize account key rotation by proving receipt and control of an email signed by an authoritative mail transfer agent (MTA) via DomainKeys Identified Mail (DKIM, RFC 6376).

Like `ed25519-verifier`, `p256-verifier`, `secp256k1-verifier`, and `webauthn-verifier`, the email recovery verifier implements the OpenZeppelin `Verifier` trait (`verify`, `canonicalize_key`, `batch_canonicalize_key`) as a stateless singleton contract.

---

## Proof of Email Recovery Structure

### 1. Challenge Binding

To prevent replay across accounts, networks, or recovery sessions, the email subject or body hash must bind the 32-byte Soroban authorization payload digest (`hash`):

```text
challenge = base64url(auth_payload_hash)
```

During verification:
1. Recompute `expected_challenge = base64url(hash)`.
2. Confirm `expected_challenge` appears at the signed challenge offset within the canonicalized `Subject` or `To`/`From` header block covered by the DKIM `h=` tag.
3. Verify that the SHA-256 digest of the canonicalized headers matches the digest signed by the domain's DKIM selector public key.

### 2. Key Data (`KeyData = Bytes`)

```text
[domain_hash: 32 bytes (SHA-256 of lowercase domain)][selector_pubkey: DER/RSA or Ed25519 public key bytes]
```

- **`canonicalize_key`**: Validates the minimum key length and returns the canonical `(domain_hash || selector_pubkey)` representation so duplicate recovery guardians for the same domain and selector deduplicate deterministically.

### 3. Signature Data (`SigData = Bytes`)

XDR-encoded `EmailRecoveryProof`:

- `canonical_headers`: Canonicalized RFC 6376 `relaxed` header bytes ending with the `dkim-signature` header line (with empty `b=`).
- `challenge_offset`: Byte offset of the 43-byte `base64url(auth_payload_hash)` challenge inside `canonical_headers`.
- `signature`: Raw cryptographic signature bytes (`b=` value from the `DKIM-Signature` header).

---

## Verification Procedure (`verify`)

1. **Validate `hash` length**: Must be exactly 32 bytes.
2. **Decode `EmailRecoveryProof`** from `sig_data`.
3. **Verify challenge binding**:
   - Encode `hash` as 43-byte unpadded `base64url`.
   - Slice `canonical_headers[challenge_offset .. challenge_offset + 43]` and assert exact byte equality with `base64url(hash)`.
4. **Verify domain binding**:
   - Confirm the `d=` domain tag in `canonical_headers` hashes to `key_data[0..32]`.
5. **Verify cryptographic signature**:
   - Compute `header_digest = SHA-256(canonical_headers)`.
   - Verify `signature` over `header_digest` against `selector_pubkey` (`rsa-sha256` or `ed25519-sha256`).
6. Return `true` on valid proof; panic with a typed contract error on any validation or signature mismatch.

---

## Security & Adversarial Test Matrix

| Scenario | Expected Outcome |
|---|---|
| Valid DKIM header proof bound to 32-byte `hash` | `verify` returns `true` |
| Challenge mismatch (proof generated for different `hash`) | Panics (`ChallengeMismatch`) |
| Tampered canonical header byte (e.g. modified `From:` or `d=`) | Panics (`InvalidSignature`) |
| Wrong DKIM selector public key | Panics (`InvalidSignature`) |
| Malformed `key_data` or truncated proof | Panics (`InvalidKeyEncoding` / `MalformedProof`) |
| `canonicalize_key` / `batch_canonicalize_key` | Preserves deterministic key identity and input ordering |

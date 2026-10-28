# Public-key consent admission

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); hash-based message authentication code (HMAC); Coordinated
Universal Time (UTC). Ed25519 is the signature algorithm. This experimental
mechanism is a prerequisite for current consent certificates; it does not itself
register the six proposed object-specific objectives or establish polished issuance.

The input is one exact action, an ordered grant chain, a revocation snapshot,
independently selected public authority policy and evaluation time. No secret key
is required to evaluate or replay. Existing HMAC envelopes and receipts keep their
separate meanings; neither format is accepted as the other.

## Binding and native rules

The public policy binds a policy identifier, required holder, unique key identifiers
and public-key bytes, separate grant-root and revocation-key roles, exact object
names and artifact digests, freshness interval, rollback floor and chain bound.
Policy terms and the context are captured before signature verification. The
candidate cannot choose its own policy, clock, key source, callback or module.
Public-key admission rejects noncanonical point encodings and small-order points
before signature work. A small-order point repeats after very few group additions;
such a configured key cannot establish exclusive signing control. The screen checks
the lower 255 encoded bits, the dimensionless y coordinate, against the field prime
`2**255 - 19` and the five small-order y values (both sign-bit choices). It follows
the encoded-coordinate cases in [libsodium 1.0.18](https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c).
The optional backend still performs signature verification. This admission screen
does not prove private-key generation, custody, full subgroup membership or human identity.
The descriptor binds the installed public adapter, shared native admission source,
shared `core/signature_keys.py` admission screen and this specification. It does not attest authenticity of the loaded runtime.

The envelope has exactly `schema_version`, `algorithm`, `key_id`, `payload`,
`payload_digest` and `signature`. Version is `verifier-consent-public-envelope-1`;
algorithm is exactly `Ed25519`. Digest is lowercase SHA-256 hexadecimal of the
canonical payload. Signature is lowercase hexadecimal of 64 signature bytes;
public keys contain 32 bytes. Signing input is the literal byte prefix
`vstd-consent-ed25519-1` followed by one zero byte and the canonical envelope
without `signature`. Canonical JSON sorts keys, uses compact separators, preserves
Unicode text, forbids nonfinite numbers and uses Unicode Transformation Format,
8-bit (UTF-8) bytes. Signatures bind both the envelope discriminator
and complete payload. A digest alone cannot authenticate a grant.

Grant and status payloads respectively use `verifier-consent-public-grant-1` and
`verifier-consent-public-revocations-1`. Their fields retain the exact scope, issuer,
delegation, interval and revocation rules in [consent admission](../../../docs/CONSENT_LEVEL7.md).
The actual shared native evaluator checks configured artifact authority; root and
delegate attribution; exact actor, action, observer and purpose; parent digests;
non-widening scope and validity; authenticated denial; ancestor revocation; current
time equality; half-open intervals; status freshness and rollback floor.

All times and durations use nonnegative integer UTC Unix seconds no greater than
`2**53 - 1`. Intervals include the start and exclude the end. There is no ambient
clock fallback. At most 16 grants are accepted, subject to a lower selected bound.
Policy inventories contain at most 256 keys, role names and artifact bindings.
Plain input capture is bounded to depth 64, 50,000 visited values, one mebibyte
(1,048,576 bytes) of encoded text, 10,000 entries per candidate container,
512 characters per string and 4,096 bits per integer. Counts are dimensionless.

## Results and reproduction

Known-key signature failure, malformed evidence, mismatched scope, unauthorized
roles, expired grants and authenticated revocation reject. Missing policy, keys,
grant chain, status, clock, backend or adequate freshness remain UNKNOWN.
The optional signature backend is imported only when signature work is required;
base import requires only the standard library. No private key loading, signing,
network access, registry synchronization or protected operation occurs.

The receipt separately records admission and the unchanged input computational
verdict. Recheck returns `REPRODUCED` only for exact recomputation, including an
UNKNOWN or rejected receipt. A retained positive result whose required checking
inputs are unavailable yields `UNAVAILABLE` with UNKNOWN admission, not reproduced
success. Receipt shape and independently selected evidence bindings are checked
before unavailable signature verification can yield `UNAVAILABLE`. Detectable
substitution yields `REJECTED`. Historical replay under an
explicit historical clock establishes only that historical evaluation.

Public verification of configured-key statements is not human identity, holder
authority, comprehension, voluntariness, legal capacity, registry completeness,
clock authenticity, computational correctness, global consent of all affected
people or durable one-use enforcement. Those remain external obligations.
No complete consent tier, public witness-disclosure permission, current publishing
permission or positive polished-artifact issuer is established by this helper.

Algorithm and backend interface references: [Request for Comments (RFC) 8032](https://www.rfc-editor.org/rfc/rfc8032)
and [cryptography Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
The cited algorithm document is informational.

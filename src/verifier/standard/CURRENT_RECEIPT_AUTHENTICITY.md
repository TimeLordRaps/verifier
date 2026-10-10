# Current RECEIPT-9.2: selected issuer-key signature

Verifier Standard (VSTD) semantic family `verifier-current-object-obligations-1`
registers one bounded RECEIPT security proposition. The selected issuer key
must verify a signature over exact externally selected intent, and the retained
`RECEIPT-9.1` certificate must independently replay `PASS` under its separately
selected request and policy. No historical coordinate or wire reader is changed.

The threat model admits an adversary who can replace retained evidence, receipt
bytes, certificate results, signed messages and carried key labels, but cannot
replace the verifier's external selection or forge the admitted key's signature.
The selector supplies the issuer public key and label, chain request and policy,
exact chain certificate digest, 32-byte challenge, evaluation time, finite
validity ceiling and resource bounds. These selections must be retained outside
the candidate certificate. The certificate does not authenticate that selector,
the label's real-world identity, private-key custody, governance authority or
authorization to publish retained bytes. Compromised or wrongly selected keys
invalidate the trust assumption. Live revocation is not queried or established.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
The checker uses the optional `cryptography` verifier and the existing public-key
admission screen, which rejects known small-order and noncanonical encodings.
It implements no signature arithmetic. Algorithm references are
[Request for Comments 8032](https://www.rfc-editor.org/rfc/rfc8032.html) and the
[library verification contract](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
Cryptographic unforgeability and Secure Hash Algorithm 256-bit (SHA-256)
collision resistance are assumptions, not properties proved by this checker.

The signing bytes are the literal domain prefix
`verifier-current-receipt-issuer-attestation-1` followed by a zero octet and canonical
JavaScript Object Notation (JSON). The message binds its version, semantic
family, coordinate, proposition digest, issuer-key label, receipt identifier
and record digest, chain certificate digest, chain request digest, policy
digest, challenge, evaluation time, issuance time and expiry time. The request's
evidence digest is excluded from the message to avoid circularly hashing the
signature; the external request separately selects all retained evidence bytes.
No embedded public key can override the selected policy.

Times are integer Coordinated Universal Time (UTC) Unix seconds in the inclusive
range zero through 2^53-1. The selected evaluation time must satisfy
`issued_at <= evaluation_time < expires_at`; interval length must not exceed the
selected ceiling, which is between 1 and 31,536,000 seconds. That representational
ceiling is not a recommended freshness window. No trusted clock is established.
The 32-byte challenge binds this selection; fresh generation, uniqueness,
one-time consumption and replay prevention across reused challenges are external
requirements and remain unestablished.

Evidence has exactly `schema_version`, `chain_certificate` and `attestation`.
The chain is retained as exact text or `null` when unavailable. Attestation is
`null` or contains exactly `schema_version`, `key_id`, `payload` and `signature`;
the signature is 64 bytes encoded as 128 lowercase hexadecimal characters.
The chain's own native checker validates its complete retained evidence rather
than trusting a carried `PASS`. Maximum outer evidence is 4 mebibytes (MiB,
1,048,576 bytes each), certificate 8 MiB and signable JSON 8,192 bytes. The child
chain's separately selected byte and entry ceilings remain enforced.

Changed selections, signatures, intervals, chain contents and malformed evidence
fail or refuse replay. Missing evidence, an unavailable prerequisite, an exhausted
selected bound or unavailable signature backend stays `UNKNOWN`. An available
refutation is not repaired by a signature. When a previously issued certificate
cannot have its signature checked, replay reports `UNAVAILABLE` and `UNKNOWN`
after checking all decidable selection, chain and carried-result invariants;
it does not report that the previous positive result was reproduced.

`PASS` establishes only the selected key signature and native chain prerequisite.
It does not establish the opaque receipt payload's truth, typed-composition
closure, full history, availability, confidentiality, legal identity, governance,
privacy, consent, a complete security tier or polished-artifact issuance.
Public replay uses `vstd current-object check` with objective `RECEIPT-9.2`,
represented kind `RECEIPT`, and independently selected request and policy.

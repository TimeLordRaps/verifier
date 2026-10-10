# Current simulation selected shard signatures (`SIM-4.3`)

Verifier Standard (VSTD) selects this simulation (SIM) obligation under
`verifier-current-object-obligations-1`. JavaScript Object Notation (JSON)
uses the installed canonical encoder; Secure Hash Algorithm 256-bit (SHA-256)
binds exact selected bytes. Ed25519 is the Edwards-curve digital signature
algorithm with a 255-bit field. Public keys contain 32 bytes and signatures
contain 64 bytes. Time and state retain the selected model's declared units;
the checker does not establish physical or dimensional truth. Byte limits
count bytes; step, item, signature and operation counts are dimensionless.

**Exact proposition:** The exact externally selected `SIM-4.2` certificate
replays `PASS` on the same simulation subject, object and collection. For
every row retained in each nonempty policy-required shard, its supplied
Ed25519 signature verifies under that shard's externally selected admitted
public key on the exact message below. Required shards are a sorted unique
nonempty subset of the child's declared shards. A policy requiring fewer
shards can establish only that selected subset, never all shard signatures.

The signed message consists of American Standard Code for Information
Interchange (ASCII) bytes
`verifier-current-sim-shard-signature-1`, one zero byte, then canonical JSON with
exactly these fields:

```text
schema_version = verifier-current-sim-shard-signature-message-1
semantic_version = verifier-current-object-obligations-1
coordinate = SIM-4.3
proposition_digest
subject_id, object_digest, collection_digest
relations_request_digest, relations_policy_digest, relations_certificate_digest
policy_digest
shard_id, step_index, time, state
```

The last three values are the zero-based row index and exact canonical time/state
representations extracted from the replayed child. The policy and child
commitments are externally selected. The parent evidence reference and full
parent request digest are excluded from the signed message to avoid a
signature/hash cycle. Parent replay separately binds the evidence reference
and all request fields. The message helper encodes bytes but does not prove
that a caller-supplied row belongs to the selected child; only full replay
establishes that membership.

Evidence retains the child request, policy and canonical base64 certificate,
and an exact map from required shards to ordered signature lists. Each list
has one lowercase hexadecimal 64-byte signature (or explicit absent value)
per retained row. The policy public-key map has exactly the required shard
keys and lowercase hexadecimal 32-byte values, or explicit absent values.
Standard-library admission rejects noncanonical and known small-order key
encodings; it does not prove full subgroup membership or key custody.
The optional, lazily imported `cryptography` version `50.0.0` backend then
performs signature verification, following its
[pinned Ed25519 interface](https://cryptography.io/en/50.0.0/hazmat/primitives/asymmetric/ed25519/)
and [Request for Comments (RFC) 8032](https://www.rfc-editor.org/info/rfc8032/).

A malformed signature, invalid present signature, incomplete or extra shard
inventory, mismatched row count, out-of-scope required shard, forged child
verdict or selected-byte substitution yields `FAIL` or selection refusal.
An absent child, public key or signature, an unavailable or differently
versioned backend, or exhausted admitted checking capacity remains `UNKNOWN`.
Known malformed signature encodings are checked before child absence;
available signatures are still checked when another selected key/signature
is absent. A retained certificate made with an unavailable dependency must
be regenerated when that dependency becomes available; replay never trusts
its earlier carried verdict.

The parent budget charges retained structure, exact child certificate bytes
and verified message bytes. Each child independently enforces its bounds;
the separate signature count bounds backend calls. These are conservative
checker accounting limits, not claims about native processor instructions or
wall-clock time. The public route is:

```text
vstd current-object check <certificate> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.3 --represented-kind SIM --request <request> --policy <policy>
```

`PASS` establishes only selected key/message validity over the retained rows.
It does not establish independent origin, authority, key custody, live key
revocation, freshness, anti-equivocation, actual execution, correctness of
the cryptographic backend, no unattributed transition, whole simulated
surface, complete closure-tier conformance or object-profile conformance.
Privacy, consent, governance, security, spending and publication authority
remain separate. The canonical
`verifier-current-sim-shard-signatures-certificate-1` envelope is rebuilt
byte for byte. Changing any selected child, required shard, key, signature,
message, policy, implementation or specification invalidates prior evidence.

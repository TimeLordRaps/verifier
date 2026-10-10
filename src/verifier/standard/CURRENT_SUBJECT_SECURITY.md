# Current typed-subject receipt binding

Verifier Standard (VSTD) semantic family `verifier-current-object-obligations-1`
adds one finite association proposition per admitted namespace kind. Coordinates
are `<kind>-9.1`, except `RECEIPT-9.3`; the existing `RECEIPT-9.1` chain and
`RECEIPT-9.2` issuer-key signature meanings remain unchanged. This is a bounded
security mechanism and does not complete any object's tier 9.

The selected exact namespace record must reconstruct with the selected identifier,
kind and digest. A separately selected RECEIPT record must name that identifier
as its sole direct `subject` operand. Its retained `RECEIPT-9.1` certificate must
replay `PASS` under the independently selected chain request and policy. At the
externally selected integer chain sequence, the exact opaque receipt bytes must
equal the canonical typed-subject message defined below. Other entries remain
opaque. Payload truth and typed-composition closure are separate obligations.

The selector retains subject identifier, kind and record digest, context digest,
chain request, exact chain-certificate digest, chain sequence, outer evidence
digest, policy and byte ceilings outside the candidate certificate. The chain
request binds the exact RECEIPT identifier and digest, domain, genesis, first
sequence, tip and complete retained chain bytes. It must use the installed native
chain mechanism. Neither a certificate's carried request nor self-selected
anchors confer authority on those selections.

The message has exactly `schema_version`, `semantic_version`, `coordinate`,
`proposition_digest`, `object_kind`, `subject_id`, `object_digest`,
`receipt_object_id`, `chain_domain`, `chain_genesis_digest`,
`chain_first_sequence`, `chain_sequence`, `context_digest` and `policy_digest`.
Its schema is `verifier-current-subject-security-message-1`; its other version,
coordinate and proposition fields identify this exact kind-specific objective.
The policy digest commits the complete outer policy, including the separately
selected child-chain policy. JavaScript Object Notation (JSON) is canonicalized
using the existing certificate byte contract. Secure Hash Algorithm 256-bit
(SHA-256) collision resistance is assumed, not proved.

The message omits the final chain tip, RECEIPT record digest, chain-certificate
digest and outer evidence digest because they depend on the message and would
make its construction circular. Those values are independently selected and
bound by the outer request and native child replay. The message's receipt
identifier, genesis, domain and position make the construction acyclic while
preserving association to the selected final anchored chain. A changed context,
kind, record, objective, policy, receipt identifier or anchored position must not
reuse a message for this proposition.

The context is a dimensionless externally selected SHA-256 commitment: this
checker does not infer its meaning, fresh generation, uniqueness or consumption.
Replaying exactly the same valid selection remains possible. This mechanism
rejects scope changes, not all replay; applications must independently enforce
one-time use when their contract requires it.

Evidence has exactly `schema_version`, `subject` and `chain_certificate`. Its
schema is `verifier-current-subject-security-evidence-1`; `subject` is the full
canonical namespace record; `chain_certificate` is the exact retained native
certificate text or `null` when unavailable. The native checker is invoked on
that text; carried `PASS` never substitutes for native replay. Malformed,
noncanonical, transplanted, wrong-kind or wrong-version evidence is `FAIL`.
Missing evidence, an unavailable chain prerequisite and exhausted selected
budgets are `UNKNOWN`. A refuted prerequisite remains `FAIL`. Malformed external
selection or substituted outer certificate refuses replay.

The outer policy binds installed source, native child mechanism and this exact
specification; its `object_kind` and mechanism digest select the exact kind.
Policies for different kinds cannot be transplanted. Maximum evidence is
4 mebibytes (MiB; 1,048,576 bytes each) and
certificate 8 MiB. The native child has its own smaller evidence, certificate
and entry ceilings. Sequence numbers are plain integers from zero through
2^63-1, are dimensionless, and cannot fall outside the selected bounded chain
interval. These bounds cover the local interface, not arbitrary host workloads.

`PASS` establishes exact retained typed-subject association to one entry in the
selected finite chain. It does not establish digital-signature validity, issuer
authenticity, actual execution, secure hardware, physical safety, confinement,
complete history, freshness, enforcement, privacy, consent, governance, public
disclosure authority, complete security-tier coverage or polished status.
`RECEIPT-9.2` can separately authenticate the same selected child chain under its
admitted issuer key. Combining both propositions requires matching their exact
child request, policy and certificate digest; proximity alone does not combine
their evidence. No historical wire identifier is reinterpreted.

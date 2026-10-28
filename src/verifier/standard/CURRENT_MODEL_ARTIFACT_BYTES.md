# Current MODEL-3.1: retained architecture and weight bytes

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers a bounded `MODEL-3.1`
certificate. This coordinate is selected together with its semantic version;
legacy numbered MODEL obligations and serialized certificate bytes are not
reinterpreted.

The exact claim is that an independently selected MODEL namespace record occurs
once in the selected finite typed collection, its one typed ARCH operand agrees
on the architecture byte commitment, and two nonempty retained raw artifacts
match the MODEL record's Secure Hash Algorithm 256-bit (SHA-256) commitments
and byte lengths. The MODEL record supplies
`architecture_bytes_sha256`, `architecture_byte_length`,
`weights_bytes_sha256`, and `weights_byte_length`; the ARCH operand supplies
`artifact_bytes_sha256`. Other payload fields stay bound by the namespace
records. Evidence carries canonical JavaScript Object
Notation (JSON) containing that collection and canonical base64 encodings of
the architecture and weight bytes. Byte lengths are bytes. The exact evidence
bundle has its own selected byte reference. The source-bound policy fixes trust
root labels and finite byte, item, object and operation limits.

The checker reconstructs the subject and its ARCH operand, validates the
selected collection, decodes each base64 value canonically, and compares raw byte lengths and
SHA-256 values. A mismatch, malformed encoding, empty artifact, substituted
selection or forged carried result fails or is rejected. Missing retained
inputs or exhausted selected limits remain `UNKNOWN`. `PASS` establishes this
finite retained-byte agreement only. It does not establish file-format
validity, training or checkpoint truth, model execution, hardware authenticity,
artifact origin, ownership, hash-function preimage or collision resistance, or
the whole MODEL statics tier.

The canonical certificate retains both raw artifacts inside its evidence
payload. Anyone given it can recover the bytes. Use this route only when those
bytes are independently authorized for the intended disclosure. Omitting the
payload or redacting it cannot leave a checkable canonical certificate; private
weights require a separately qualified confidential-witness mechanism. A
digest alone is not a zero-knowledge proof or authority to publish.

Public replay selects the exact request and policy, then uses
`vstd current-object check <certificate> --semantic-version
verifier-current-object-obligations-1 --objective MODEL-3.1
--represented-kind MODEL --request <request> --policy <policy> --json`.
The checker reports computational `PASS`, `FAIL`, or `UNKNOWN` separately from
format validity, training truth, execution truth, provenance, disclosure
authority and object-profile conformance, which remain `NOT_ESTABLISHED`.

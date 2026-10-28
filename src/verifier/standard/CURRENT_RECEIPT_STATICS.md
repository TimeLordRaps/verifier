# Current RECEIPT-3.1: canonical VSTD-1 claim-receipt byte statics

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, Secure Hash
Algorithm 256-bit (SHA-256) names commitments, and Unicode Transformation
Format, 8-bit (UTF-8) is the only admitted text encoding. Byte limits measure
exact retained bytes. Counts and checking budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `RECEIPT-3.1` selects one
bounded **static byte-invariant** proposition about one externally selected
`RECEIPT` namespace record and the exact receipt bytes it commits to:

1. The retained record reconstructs as the exact canonical namespace record
   whose identifier and digest the request selects.
2. Its payload has exactly four fields: `receipt_kind` equal to
   `claim_mechanics`, `receipt_schema_version` equal to `VSTD-1`,
   `receipt_sha256` (a canonical `sha256:` commitment) and `prerequisites`
   (a sorted, unique list of bounded nonempty identifiers, possibly empty).
3. The retained receipt bytes hash to that commitment.
4. The bytes are strict UTF-8 JSON without duplicate keys or non-finite
   numbers, and equal the VSTD-1 canonical re-serialization of their own value
   (`VSTD-1.md` section 7: sorted keys, minimal separators, American Standard Code for Information Interchange (ASCII) escapes).
5. The value decodes under the installed `verifier.core.receipt` VSTD-1
   claim-mechanics model with exact field sets taken from the installed
   dataclasses, exact JSON value types, admitted enumeration values, and no
   serialized `EVIDENCED` independence status (`VSTD-1.md` section 5: the
   reference runtime rejects receipts that serialize `EVIDENCED`).
6. Re-serializing the decoded model reproduces the same bytes, so no field is
   carried that the model would drop or derive differently (for example the
   derived `independently_verified` flag).
7. `canonical_digest` is 64 lowercase hexadecimal digits and equals the
   SHA-256 of the canonical stable payload that the installed model defines.

This is a strict subset of the STATICS question "which external constraints
and invariants must hold?" restricted to the rationale's canonical
serialization byte invariants, immutable SHA-256 digest bindings and schema
validity. A violation of any step is `FAIL`. An exhausted byte, item or
operation budget, or the checker's recursion ceiling, is `UNKNOWN`. A
malformed request, policy or limit override, or a substituted certificate, is
`REJECTED`: `ReceiptStaticsError` is raised before replay.

Difference from `RECEIPT-9.1` (receipt chain): 9.1 treats receipts as opaque
bytes and checks a domain-separated link hash chain to a selected tip; it
never parses the VSTD-1 dialect. This objective parses one receipt's dialect
and checks its canonical form, schema and internal digest; it checks no
chain. Difference from `RECEIPT-9.2` (receipt authenticity): 9.2 checks an
issuer signature over receipt bytes. This objective checks no signature and
says nothing about who produced the bytes.

`PASS` means only that the selected retained bytes are a canonical,
schema-valid, self-digest-consistent VSTD-1 claim receipt committed by the
selected record. It does **not** establish that the claim is true, that the
retained independent audit would replay to the same report (that is
`RECEIPT-2.1`), that bytes named by `source_file_hashes` or
`source_artifacts` exist or match, that declared prerequisites resolve or
form an acyclic cone (that is `RECEIPT-4.1`), hash-chain continuity, issuer
authenticity, typed namespace composition of the record's subject or
hardware operands, the whole RECEIPT statics tier or object-profile
conformance. Privacy, consent, governance, security, authority and
publication are not claimed; their result fields remain `NOT_ESTABLISHED`.

The certificate retains the exact namespace record, receipt bytes, request,
policy digest and replay result. Retained receipts may carry provenance text
such as local paths; public release of retained contents requires separate
disclosure authority. Changed mechanism source, the installed receipt,
checker, provenance or namespace model, `NAMESPACE_OBJECTS.md`, `VSTD-1.md`,
this specification, retained bytes or policy invalidates the pinned
mechanism digest and therefore the certificate.

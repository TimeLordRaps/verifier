# Object Context Closure

This optional composition checks whether one finite object/context/security
selection is closed over the exact evidence supplied to the current native
checkers. It does not change the selected-context, certificate directed acyclic
graph (DAG), subject-security, lineage, or facet propositions.

`assess_object_context_closure` requires all of the following before returning
`PASS`:

1. Independently selected current-application compiler-manifest bytes and their
   internal Secure Hash Algorithm 256-bit (SHA-256) `manifest_digest`. The
   composition requires the canonical bytes to reproduce that digest and the
   selected native-context policy to name it. This binds the exact manifest but
   does not establish compiler closure because the compiler inputs are not
   replayed here.
2. A retained selected-context assessment and its independently selected
   assessment digest. The installed selected-context mechanism must reproduce
   that assessment from the exact bundle, dependency policy, context policy,
   and retained artifact snapshot.
3. Every selected DAG node certificate resolved by path and digest from that
   same retained artifact snapshot. The existing certificate-DAG assessment
   must run every selected native rechecker and return `PASS` for every direct
   and prerequisite-qualified node.
4. A retained subject-security certificate, exact request, and exact policy.
   Its native rechecker must return `PASS`. The request `context_digest` must
   equal the reproduced selected-context assessment digest, and the selected
   context must contain a passing row for the same subject identifier, kind,
   and object digest.
5. Independently selected canonical ancestry-evidence bytes and digest using
   `verifier-object-context-ancestry-evidence-1`. The record binds the same
   subject and exact object digest and explicitly keeps
   `actual_revision_history` at `NOT_ESTABLISHED`.
6. An independently selected canonical applicability denominator and digest
   using `verifier-object-context-applicability-denominator-1`. It names the
   complete selected node identifier set for this finite composition and keeps
   complete application applicability at `NOT_ESTABLISHED`.

Missing bytes, absent certificates, exhausted bounds, or unavailable native
mechanisms produce `UNKNOWN`. A present digest mismatch, malformed selected
record, changed subject, changed context, or native refutation produces `FAIL`.
Any `FAIL` dominates concurrent `UNKNOWN` results. Consequently, arbitrary
all-ones compiler-manifest commitments, all-zero certificate commitments,
missing certificate paths, and self-selected unrelated context digests cannot
produce a composed `PASS`.

The ancestry record has exactly these fields:

```json
{
  "actual_revision_history": "NOT_ESTABLISHED",
  "admission": "EXTERNALLY_ADMITTED",
  "evidence_kind": "DECLARED_REVISION_OR_ANCESTRY_EVIDENCE",
  "object_digest": "sha256:<64 lowercase hexadecimal characters>",
  "schema_version": "verifier-object-context-ancestry-evidence-1",
  "subject_id": "<selected subject identifier>"
}
```

The applicability record has exactly these fields:

```json
{
  "admission": "EXTERNALLY_ADMITTED",
  "complete_application_applicability": "NOT_ESTABLISHED",
  "context_assessment_digest": "sha256:<64 lowercase hexadecimal characters>",
  "node_ids": ["<sorted selected DAG node identifiers>"],
  "object_digest": "sha256:<64 lowercase hexadecimal characters>",
  "schema_version": "verifier-object-context-applicability-denominator-1",
  "subject_id": "<selected subject identifier>"
}
```

A composed `PASS` establishes only that the stated finite bindings and native
replays succeeded at the installed source bytes. It grants no authority,
permission, release, publication, source authenticity, actual revision or
ancestry history, complete applicability, whole security conformance,
object-profile conformance, or whole-object acceptance.

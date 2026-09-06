# Artifact awareness and confidentiality of awareness

Verifier Standard (VSTD) v1.3.0 introduces these explicit interoperability terms and
prohibited inferences. This is a semantic and diagnostic contract, not a new receipt
format, awareness-tracking implementation, or confidentiality guarantee.

> Permission does not establish knowledge, and withholding direct access does not establish that something cannot be inferred.

## Meaning-bearing terms

- **Artifact awareness:** information an artifact has about another artifact, including
  its existence, contents, properties, dependencies, and awareness of other artifacts.
  A claim of awareness requires an exact artifact state and evidence of the named fact;
  a descriptive declaration alone does not establish that claim.
  Awareness of a claim is not verification of that claim.
- **Awareness relation:** a directed, context-specific relation from an aware artifact
  to the artifact and facts it is aware of. Knowing that an artifact exists is distinct
  from knowing its contents or its awareness relations. The relation itself can be
  confidential.
- **Awareness boundary:** an explicit separation between named facts that may be
  disclosed and facts whose disclosure or derivation is restricted. A declared boundary
  is policy, not evidence that the boundary is enforced.
- **Confidentiality of awareness:** constraints on exposing, acquiring, or propagating
  artifact awareness, including through intermediate artifacts and inference. Establishing
  that these constraints hold requires evidence for the named boundary and threat model.

These terms describe artifact-to-artifact relationships, not a new class of verifiers.
They do not depend on a particular application domain or on publisher identity.

## Three questions, recorded separately

| Question | Meaning | What does not establish it |
|---|---|---|
| Actual awareness | What information the exact artifact state has about another artifact; observations support only the facts their mechanism examines. | Permission, availability, a catalog entry, or an unexamined declaration. |
| Permitted awareness | What awareness a named policy and authority allow in a stated context. | Possession of information, successful proof checking, or a caller-supplied authorization label alone. |
| Potentially inferable awareness | What additional information can be derived from available observations under a named inference model and its assumptions. | Direct-access restrictions, omitted fields, an unsuccessful inference attempt, or absence of recorded awareness. |

These are separate dimensions, not interchangeable statuses or a progression toward
stronger assurance. An artifact may possess information it was not permitted to obtain.
Conversely, permission need not have been exercised. Failure to observe awareness leaves
it unknown; it does not demonstrate its absence.

## Composition and disclosure

**No automatic awareness inheritance:** if artifact A is aware of B, and B is aware of C,
neither A's awareness of C nor permission for A to acquire it follows automatically.
An actual disclosure or derivation needs its own relation, context and evidence.

Indirect inference nevertheless matters. In a non-critical inventory example, one
private artifact records a quantity, a public artifact records 3 items, and a combined
report discloses a total of 10 items. Given the explicit relation that the total is the
sum of those two quantities, subtraction reveals the private quantity: 7 items. Direct
access to the private artifact was unnecessary. This is an explanatory counterexample,
not an implemented confidentiality analysis.

Review metadata as well as payloads: artifact names, existence, dependency edges, receipts,
logs, output combinations and timing can reveal facts. A hash, signature, seal, omitted
payload or successful verification does not by itself establish confidentiality of
awareness. Any disclosure mechanism must name which facts may be revealed, to which
recipient, under which authority, and what inference and execution channels it covers.
Do not put confidential facts or confidential awareness relations into a public manifest
merely to describe a boundary that is supposed to protect them.

## v1.3.0 release boundary

The release defines this vocabulary and includes its limits in existing package-inspection,
surface-analysis, planning and execution-readiness diagnostics. It does not implement an awareness tracker
and does not enforce confidentiality of awareness. It neither computes general inference
closure nor proves that hidden information cannot be derived. Existing `READY` and integrity
`PASS` results keep their original narrow meanings; no awareness or confidentiality verdict
is inferred from them. Unsupported or missing evidence remains unestablished.

Serialized structures, receipt identifiers and stored-package formats are unchanged.
Expanded diagnostic text changes earlier release-candidate report bytes and their digests.
Regenerate affected analyses, plans and readiness reports, and rebind declarations that
name their digests; do not reuse an earlier authorization binding for a changed plan.

Awareness tracking, inference-sensitive composition and runtime enforcement require
separately specified mechanisms, evidence and native-platform qualification. That work is
planned for v1.4.0 alongside the hub; it is not supplied by these v1.3.0 definitions.

Descriptive names remain primary. Bell-LaPadula's
[information-flow model](https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/bell76.pdf)
and Giampaolo Bella's
[formal protocol work](https://link.springer.com/book/10.1007/978-3-540-68136-6)
are relevant influences, not names for VSTD's artifact-awareness semantics or claims that
their mechanisms have already been integrated.

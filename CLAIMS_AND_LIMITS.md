# Claims and limits in plain language

**Status:** normative interpretation guide for VSTD-0.1 and VSTD-DATA-0.1

This guide translates VSTD claim language into ordinary language. When a short claim
conflicts with the bounded wording here, the bounded wording controls.

## Reading every VSTD claim

A VSTD result always has this form:

> For this identified subject snapshot, this declared verification surface passed this
> identified mechanism using this bound evidence, subject to these limitations, trust
> roots, and horizons.

Omitting any bolded idea changes the claim. `VERIFIED` never means universally true,
safe, complete, permanent, legally authorized, or endorsed.

## Claim translation table

| Claim | May it be made? | Why | Required evidence | What it does not mean |
|---|---|---|---|---|
| “This receipt's stable content has not changed.” | **Yes, after validation passes.** | The validator recomputes the canonical digest over the specified stable fields and compares it with the recorded digest. | Receipt bytes, canonicalization version, recorded digest, passing validator result. | The statements inside the receipt are true or authentic. |
| “These observed bytes match this SHA-256 digest.” | **Yes, conditionally.** | A named mechanism can hash accessible bytes at an observation time and compare them with the recorded digest. | The bytes, hashing mechanism, observation time, expected digest, comparison result. | The bytes came from the claimed source, existed before observation, are uncontaminated, or are legally usable. |
| “VSTD-DATA records this lineage graph.” | **Yes.** | The receipt binds the stored artifact nodes, transformation edges, roles, statuses, and declarations. | Valid receipt and structurally valid hypergraph. | The graph contains every real-world input or transformation. |
| “This is the complete provenance of the model or dataset.” | **No, unless completeness is independently evidenced for the declared boundary.** | A graph cannot infer hidden inputs, pre-observation history, out-of-band processing, or missing instrumentation. | Independent coverage evidence for every declared boundary plus explicit horizons outside it. | That a high coverage summary proves complete real-world lineage. |
| “This transformation actually ran and produced this output.” | **Only with execution evidence.** | Software, parameters, and environment fields are declarations until a run trace, rerun, attestation, or equivalent evidence binds execution to the output. | Identified inputs and outputs, execution trace or rerun, software identity, parameters, environment, and evidence classification. | Recording a script name or commit proves execution. |
| “The recorded Boolean provenance policy passed.” | **Yes, when the policy result validates.** | The reference solver evaluates the recorded CNF formula. | Formula, variable map, graph snapshot, solver identity, passing result. | The prose-to-formula translation was complete, the external facts were true, or broader policy compliance was established. |
| “No recorded ancestor is marked `REVOKED`.” | **Yes, if that narrow query passes.** | The query checks exactly the recorded `REVOKED` status over the ancestor closure. | Target artifact, recorded graph, status values, passing policy result. | Every ancestor is `VALID`; `UNKNOWN`, `CHALLENGED`, or `STALE` may still exist unless explicitly rejected. |
| “All recorded target ancestors are explicitly `VALID`.” | **Yes, if the fail-closed valid-ancestor policy passes.** | That policy rejects every recorded target ancestor not explicitly marked `VALID`. | Target artifact, ancestor closure, status evidence, passing `POL-ALL-ANCESTORS-VALID`. | The status declarations are authentic or that unrecorded ancestors do not exist. |
| “The recorded SPDX metadata matches the allowlist.” | **Yes, if the exact metadata policy passes.** | The policy compares recorded license identifiers with the declared allowlist. | Rights records, roots, allowlist, passing policy result. | Copyright ownership, license authenticity, compatibility, fair use, or a legal ruling. |
| “This result reproduced bitwise.” | **Yes, for the declared outputs after a passing rerun.** | The rerun produced byte-identical declared output artifacts. | Original receipt, runnable command, captured inputs, environment boundary, rerun outputs, byte comparison. | All environments will reproduce it or the computation is empirically correct. |
| “This was independently verified.” | **Only when the relevant independence seam is demonstrated.** | Independence requires separation from the producer's relevant state and logic plus a declared trusted computing base. | Producer/auditor boundary, TCB, source identities, isolation evidence, independent result. | Running the bundled verifier on its own output is automatically independent. |
| “This verification surface is self-closed.” | **Only if every VSTD-0.2 self-closure condition passes.** | Self-closure requires ordinary closure, resolved material residuals, discharged valences, post-verified mechanisms, no unresolved trust-root horizon, and contiguous verification orders. | Complete geometry document and passing closure assessment with no blockers. | Universal truth, infinite regress closure, permanent validity, or verification outside the surface. |
| “This competition submission and score are bound together.” | **Yes, conditionally.** | A receipt can bind identified submission bytes, evaluator version, raw metrics, and deterministic score derivation. | Submission digest, evaluator/scorer identity, environment, raw metrics, score rule, receipt. | Hidden-test integrity, no leakage, leaderboard ranking, prize eligibility, or organizer acceptance. |
| “A challenge to this recorded ancestor affects these recorded descendants.” | **Yes.** | Blast radius is forward reachability over the stored graph. | Challenged artifact ID and bound hypergraph. | Historical receipts were automatically mutated or that unrecorded downstream systems were found. |

## Implemented mechanism versus specification requirement

VSTD documents contain both requirements and implemented reference mechanisms.

- **Implemented claim:** the public Python path and its tests perform the named bounded
  operation.
- **Conformance requirement:** another implementation must satisfy the stated rule, but
  the existence of the rule is not evidence that an integration satisfied it.
- **Future or experimental surface:** vocabulary or geometry exists, but broader
  interoperability or independent implementation evidence is incomplete.

Always cite the exact VSTD version, implementation commit, receipt type, mechanism,
and demonstrated test or receipt. Do not turn specification text into an implementation
claim.

## Safe claim template

> Using VSTD-DATA-0.1 at commit `<commit>`, receipt `<receipt-id>` validated the stored
> provenance graph and replayed its declared graph mechanisms for target `<artifact>`.
> This establishes receipt integrity and the stated recorded-graph results. It does not
> establish complete real-world lineage, legal rights, physical-file identity without a
> rehashing adapter, or truth outside the declared surface.

## Prohibited shortcuts

Do not publish any of these without the missing qualification:

- “VSTD proves provenance.”
- “VSTD proves the dataset is clean.”
- “VSTD proves the license is valid.”
- “VSTD independently verifies itself.”
- “VSTD proves the model is safe.”
- “VSTD verifies the competition result.”
- “Completely verified” when any material residual, valence, mechanism, order, or trust
  root remains unresolved.

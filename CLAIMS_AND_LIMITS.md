# Claims and limits in plain language

**Status:** normative interpretation guide for VSTD-0.1, VSTD-DATA-0.1, and VSTD-3.0

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

## VSTD 3 accelerator claim translations

Every `PASS` below is conditional on full receipt validation with the required trust
keys and appraisal inputs. A recorded `verification_state: VERIFIED` is not enough by
itself.

| Claim | May it be made? | Plain-language translation | Evidence and verification | `FAIL` / `UNKNOWN` behavior | Prohibited stronger inference |
|---|---|---|---|---|---|
| **Positive execution evidence** — “Execution E was observed by S.” | **Yes, when S actually emitted execution-specific evidence.** | The named source recorded the identified execution inside its declared observation boundary. | Execution identity; source-specific positive observation; authenticated start/observation/end when claiming device evidence; topology binding. | `FAIL` for a contradictory binding; `UNKNOWN` when there is inventory telemetry but no execution-specific evidence. | The device originated the evidence, the workload was correct, or all execution was logged. |
| **Device identity** — “Device D presented an authenticated identity.” | **Yes, conditionally.** | A verifier authenticated an identity and bound it to this receipt's physical/logical subject. | Nonce-bound signed evidence, certificate/endorsement chain, trust root, subject/certificate match, freshness. | `FAIL` for invalid signature, wrong subject/certificate, or nonce mismatch; `UNKNOWN` without keys, roots, or an implemented verifier. | Firmware was approved, workload ran, counters are exact, or the device mediated every path. |
| **Firmware integrity** — “Device D presented approved firmware measurements.” | **Yes, conditionally.** | Signed measurements matched the verifier's named reference values and policy. | Authenticated device evidence, component measurements, authentic reference values, appraisal result, nonce and freshness checks. | `FAIL` for a proven mismatch/invalid signature/staleness; `UNKNOWN` when reference values, policy, roots, or parser are absent. | Every job was logged, firmware has no vulnerabilities, or a reported version alone proves approval. |
| **Execution attestation** — “Execution E has authenticated device/firmware evidence.” | **Yes, only with execution-bound attestation.** | Authenticated evidence binds the execution/workload commitment, device/logical identity, topology, and event record. | Valid device/firmware signature and challenge; workload commitments; bound start/observation/end events. | `FAIL` for altered or inconsistent bindings; `UNKNOWN` for host telemetry or opaque vendor evidence not verified by the core. | The accounting quantity is exact or complete mediation holds. |
| **Execution accounting** — “Execution E has quantity Q under method M and scope B.” | **Yes, with the qualifiers intact.** | The receipt binds a typed quantity to an execution, source, method, unit, exactness label, and device scope. | Bound accounting observation and event; source; method semantics; partition/topology scope; uncertainty for estimates. | `FAIL` when an estimate is labeled exact, scope escapes the execution, or payload binding changes; `UNKNOWN` when counter semantics/evidence are unavailable. | `Q` is exact physical FLOPs outside B, or different counter methods are interchangeable. |
| **Accounting continuity** — “The authenticated sequence is continuous over interval I.” | **Yes, conditionally.** | Every expected sequence position between the evidenced endpoints connects by authenticated rolling roots and valid reset/anchor semantics. | Event IDs, epoch/sequence, predecessor/rolling roots, signatures, reset records, and external anchors when claimed. | `FAIL` for forks, rollback, wrong roots, invalid signatures, or tampering; `UNKNOWN` for gaps, unavailable keys, or honestly unanchored history. | Events before/after I exist, timestamps are accurate UTC, or all compute paths entered the sequence. |
| **Complete mediation** — “All governed execution paths on D in epoch E were mediated.” | **Only for a mechanism that can substantiate path control.** The reference emulator can make this claim only inside its API boundary. Commodity adapters currently cannot. | Within the exact named boundary, the measured mechanism gates every governed submission path and emits continuous authenticated accounting. | Explicit `COMPLETE_MEDIATION_ATTESTED` capability from verified device/firmware (or test emulator) evidence, passing continuity, complete execution start/end records, and a documented no-bypass boundary. | `FAIL` for an evidenced bypass or incomplete recorded execution; `UNKNOWN` when path control, keys, continuity, or firmware behavior cannot be established; `UNSUPPORTED` when the mechanism declares no such capability. | No ungoverned path exists outside the boundary, no other device computed, or no undeclared compute occurred anywhere. |
| **Fleet completeness** — “All enrolled devices in F reported during T.” | **Yes, relative to the exact enrolled boundary.** | The expected enrolled-member set and observed set matched for the interval, with no missing or unexpected enrolled member. | Fleet manifest/boundary, enrollment state, observation, identities, topology, evidence sources, and separately evidenced enrollment completeness. | `FAIL` for missing/unexpected members or inconsistent set accounting; `UNKNOWN` when enrollment completeness or required evidence is absent. | The manifest lists every physically present accelerator or every accelerator controlled by an organization. |
| **Physical-world/global completeness** — “No undeclared compute occurred anywhere.” | **No. It is mechanically `UNSUPPORTED`.** | Ordinary receipts have no observation boundary capable of enumerating all physical execution worldwide. | No implemented ordinary VSTD evidence set is sufficient. | This is not converted to `FAIL`; it remains `UNSUPPORTED` because the quantification cannot be observed. | Any wording that turns fleet, host, provider, or device receipts into global absence. |

### What the current adapters can say

- Generic, NVIDIA `nvidia-smi`/NVML-style, AMD SMI, and Intel generic fixtures can say
  that the collector observed the recorded host-visible metadata and preserved the raw
  bytes/digest. That is not device attestation.
- Opaque NVIDIA SPDM/NVTrust/NVSwitch or AMD DICE-labeled bytes can be retained without
  being promoted. Until certificate, nonce, signature, and measurement appraisal run,
  the result includes `UNVERIFIED_VENDOR_ATTESTATION`.
- A verified Google/AWS/Microsoft provider fixture can say the provider control-plane
  statement's test signature matched. It cannot say the tenant accessed or verified
  physical firmware unless separately verified hardware evidence is referenced.
- `VirtualVSTDAccelerator` can demonstrate nonce binding, measured reference firmware,
  execution/accounting events, continuity, reset, anchoring, partition lineage, and
  complete mediation inside the emulator API. It cannot make a physical hardware,
  tamper-resistance, or commodity-product claim.

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

VSTD 3 safe template:

> Using VSTD-3.0 at commit `<commit>`, verifier `<mechanism/version>` validated receipt
> `<receipt-id>` for device/logical boundary `<boundary>` and interval `<interval>`.
> Claim `<claim>` returned `<PASS|FAIL|UNKNOWN|UNSUPPORTED>` using evidence
> `<evidence-ids>`. This says `<bounded translation>`. It does not say
> `<prohibited inference>`.

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
- “Hardware attested” for host inventory, a provider allocation response, or opaque
  bytes that no implemented verifier authenticated.
- “All compute was accounted for” without complete-mediation evidence for every path in
  the named governed boundary.
- “No undeclared compute occurred” from a device, host, provider, or fleet receipt.

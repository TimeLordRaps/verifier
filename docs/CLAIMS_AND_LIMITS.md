# Claims and limits in plain language

> **Acronyms:** artificial intelligence (AI); Advanced Micro Devices (AMD); application programming interface (API);
> Amazon Web Services (AWS); Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE);
> conjunctive normal form (CNF); Device Identifier Composition Engine (DICE);
> grounded decision certificate (GDC); identifier (ID); machine learning (ML); NVIDIA Management Library (NVML);
> Secure Hash Algorithm 256-bit (SHA-256); system management interface (SMI); Security Protocol and Data Model (SPDM);
> Software Package Data Exchange (SPDX); Supply Chain Integrity, Transparency, and Trust (SCITT);
> trusted computing base (TCB); Coordinated Universal Time (UTC);
> Verifier Standard (VSTD).

> Reader aid: [concept glossary and primary precedents](CONCEPTS_AND_PRECEDENTS.md).

**Status:** normative interpretation guide for the VSTD object and Graph ladders

This guide translates VSTD claim language into ordinary language. When a short claim
conflicts with the bounded wording here, the bounded wording controls.

## Reading every VSTD claim

A VSTD result always has this form:

> For this **identified subject snapshot**, this **identified mechanism** returned this
> **bounded result** over this **declared verification surface**, using this
> **bound evidence**, subject to these **limitations**, **trust roots**, and **horizons**.

Omitting any bolded idea changes the claim. `VERIFIED` never means universally true,
safe, complete, permanent, legally authorized, or endorsed.

## Skeptical review summary

VSTD has no single scalar “strongest claim”; mechanisms establish different predicates.
The strongest generally reusable implemented statement is therefore an exact, bounded
checker result—not a claim of universal truth or whole-project conformance.

| Reviewer question | Current answer | Mechanism and trust roots | Boundary or missing mechanism |
|---|---|---|---|
| What can the generic validator establish? | Stable receipt content and strict profile shape. | Canonicalization, recorded digest, profile discriminator, and bundled validator bytes. | It does not verify the recorded native claim, external evidence, actor identity, or independence. |
| What can the grounded-certificate kernel establish? | The exact `VSTD4-GDC-1` decision was accepted, rejected, or left `UNKNOWN` under its claim binding and resource bound. | Certificate bytes, formula, grounding, policy/evidence roots, verifier descriptor, and kernel. | VSTD-4 depth conformance is `NOT_ESTABLISHED`; rung evidence and lower-layer preconditions are not bound by the depth runtime. |
| What can VSTD-Graph establish? | Stored objects, transformations, conflicts, recorded reachability, and policy results over that graph. | Content digests, Graph receipt, hyperedges, statuses, and named query or policy. | Graph levels 2–5 are candidates from caller-supplied ratings; completeness, causality, and rating-to-evidence binding are absent. |
| What can VSTD-3 establish? | Conditional device, firmware, execution, accounting, continuity, or fleet predicates when each required evidence path validates. | Named roots, keys, nonces, measurements, topology, events, appraisal inputs, and profile-specific validators. | Host inventory is not attestation; production vendor integration and complete mediation outside the emulator remain separate requirements. |
| What does SCITT add? | Signature and registration/inclusion evidence for exact payload bytes under a declared relying-party policy. | Native SCITT verifier, issuer/log keys, payload digest, registration policy, and Transparency Service evidence. | Registration cannot establish payload correctness, VSTD conformance, or issuer authority outside the policy. The current example uses a local test log. |
| What remains outside current support? | General AI safety, hidden state, complete physical-world history, automatic actor independence, automatic challenge-to-Graph propagation, VSTD-5, and unqualified provenance truth. | No current ordinary VSTD mechanism observes or validates those propositions. | Preserve `UNKNOWN`, `UNSUPPORTED`, `CONFLICTED`, or `NOT_ESTABLISHED`; do not infer a clean result. |

Every claim below expands one of these boundaries into publishable wording and its
required falsification surface.

## Claim translation table

| Claim | May it be made? | Why | Required evidence | What it does not mean |
|---|---|---|---|---|
| “This receipt's stable content has not changed.” | **Yes, after validation passes.** | The validator recomputes the canonical digest over the specified stable fields and compares it with the recorded digest. | Receipt bytes, canonicalization version, recorded digest, passing validator result. | The statements inside the receipt are true or authentic. |
| “These observed bytes match this SHA-256 digest.” | **Yes, conditionally.** | A named mechanism can hash accessible bytes at an observation time and compare them with the recorded digest. | The bytes, hashing mechanism, observation time, expected digest, comparison result. | The bytes came from the claimed source, existed before observation, are uncontaminated, or are legally usable. |
| “VSTD-Graph records this lineage graph.” | **Yes.** | The receipt binds the stored artifact nodes, transformation edges, roles, statuses, and declarations. Historical Graph-1 receipts retain the `VSTD-DATA-0.1` wire identifier. | Valid receipt and structurally valid hypergraph. | The graph contains every real-world input or transformation. |
| “This is the complete provenance of the model or dataset.” | **No, unless completeness is independently evidenced for the declared boundary.** | A graph cannot infer hidden inputs, pre-observation history, out-of-band processing, or missing instrumentation. | Independent coverage evidence for every declared boundary plus explicit horizons outside it. | That a high coverage summary proves complete real-world lineage. |
| “This transformation actually ran and produced this output.” | **Only with execution evidence.** | Software, parameters, and environment fields are declarations until a run trace, rerun, attestation, or equivalent evidence binds execution to the output. | Identified inputs and outputs, execution trace or rerun, software identity, parameters, environment, and evidence classification. | Recording a script name or commit proves execution. |
| “The recorded Boolean provenance policy passed.” | **Yes, when the policy result validates.** | The reference solver evaluates the recorded CNF formula. | Formula, variable map, graph snapshot, solver identity, passing result. | The prose-to-formula translation was complete, the external facts were true, or broader policy compliance was established. |
| “No recorded ancestor is marked `REVOKED`.” | **Yes, if that narrow query passes.** | The query checks exactly the recorded `REVOKED` status over the ancestor closure. | Target artifact, recorded graph, status values, passing policy result. | Every ancestor is `VALID`; `UNKNOWN`, `CHALLENGED`, or `STALE` may still exist unless explicitly rejected. |
| “All recorded target ancestors are explicitly `VALID`.” | **Yes, if the fail-closed valid-ancestor policy passes.** | That policy rejects every recorded target ancestor not explicitly marked `VALID`. | Target artifact, ancestor closure, status evidence, passing `POL-ALL-ANCESTORS-VALID`. | The status declarations are authentic or that unrecorded ancestors do not exist. |
| “The recorded SPDX metadata matches the allowlist.” | **Yes, if the exact metadata policy passes.** | The policy compares recorded license identifiers with the declared allowlist. | Rights records, roots, allowlist, passing policy result. | Copyright ownership, license authenticity, compatibility, fair use, or a legal ruling. |
| “This result reproduced bitwise.” | **Yes, for the declared outputs after a passing rerun.** | The rerun produced byte-identical declared output artifacts. | Original receipt, runnable command, captured inputs, environment boundary, rerun outputs, byte comparison. | All environments will reproduce it or the computation is empirically correct. |
| “This was independently verified.” | **Only when distinct producer and checker actors plus the relevant execution seams are evidenced.** | Matching results establish artifact agreement, not who performed either run. Actor independence, implementation separation, runtime separation, and the trusted computing base must be recorded separately. | Evidence binding distinct actors to the producer and checker runs, implementation/runtime isolation, trusted computing base, and the checker result. | Two runs, two processes, two machines, or matching outputs automatically prove independent actors. |
| “This verification surface is self-closed.” | **Only if every VSTD-2 self-closure condition passes.** | Self-closure requires ordinary closure, resolved material residuals, discharged valences, post-verified mechanisms, no unresolved trust-root horizon, and contiguous verification orders. | Complete geometry document and passing closure assessment with no blockers. | Universal truth, infinite regress closure, permanent validity, or verification outside the surface. |
| “This competition submission and score are bound together.” | **Yes, conditionally.** | A receipt can bind identified submission bytes, evaluator version, raw metrics, and deterministic score derivation. | Submission digest, evaluator/scorer identity, environment, raw metrics, score rule, receipt. | Hidden-test integrity, no leakage, leaderboard ranking, prize eligibility, or organizer acceptance. |
| “This native verifier result was mapped into VSTD.” | **Yes, when the mapping preserves the native object, result, trust roots, bounds, and unsupported fields.** | VSTD can standardize the claim boundary and portable result semantics around a domain verifier without performing that verifier's native work. | Native object and version, native verifier implementation/version, native result, field-level mapping, information-loss declaration, VSTD coordinate, adapter tests. | VSTD replaced or reimplemented the native verifier, strengthened its result, inherited its authority, or established conformance to the source standard. |
| “A challenge to this recorded ancestor affects these recorded descendants.” | **Yes.** | Blast radius is forward reachability over the stored graph. | Challenged artifact ID and bound hypergraph. | Historical receipts were automatically mutated or that unrecorded downstream systems were found. |
| “The reference implementation computed VSTD-Graph depth `N`.” | **Not yet as a conformance claim.** | The current implementation computes a candidate level from caller-supplied artifact and edge ratings. It labels the result `CALLER_SUPPLIED` and `NOT_ESTABLISHED`. | A structurally valid graph and explicit supplied ratings. Conformance additionally requires implemented rating-to-evidence bindings for each reached layer. | The supplied ratings were independently derived, each layer's evidence passed, or Graph conformance was established. |

## Competition and scored-evaluation claims

For predictive-AI, scientific-ML, agent, and other scored evaluations, bind the exact
rules, data, model, submission, evaluator, metrics, score, transformations, environment,
and evidence classes. Mark hidden tests as a horizon—not evidence of integrity. This adds
no verdict, affiliation, certification, endorsement, ranking, prize eligibility, or
organizer acceptance.

For later-resolved predictions, also bind emission and resolution times, the frozen
prediction digest, update or abstention policy, resolution source and digest, scoring
rule, and channel independence. Corrections are additive; never overwrite a frozen
prediction. See the complete non-normative
[`competition profile`](profiles/competition-evaluation.md).

Use the coordinate-bounded wording:

> The submission and score receipt binds the declared artifact, evaluator, and
> provenance surface. Hidden-test integrity and organizer acceptance remain outside the
> participant-observable surface.

Do not shorten this to “the model,” “the competition result,” or “the prediction is
verified.”

## VSTD-4 grounded-decision claim translations

`VSTD4-GDC-1` makes a decision certificate checkable outside its producer against an
explicit claim coordinate, formula, grounding map, verifier identity, resource
bounds, and prior commitment. It does not make the certificate independent of
the evidence source or make the grounded claim true outside that coordinate.

| Claim | Bounded translation | Required qualification | Prohibited stronger inference |
|---|---|---|---|
| “This VSTD4-GDC-1 certificate was accepted.” | The identified reference kernel accepted the exact canonical certificate under the declared claim binding, fragment, verifier, and resource bounds. | Name the certificate digest, implementation commit, claim coordinate, cost tier, bounds, and kernel result. | The underlying evidence is authentic, the policy captured every intended condition, or the claim is globally true. |
| “This decision is grounded.” | Every variable and clause in the accepted certificate maps to declared subjects, predicates, values, and encoding rules whose roots are bound by the certificate. | Preserve the evidence root, policy root, grounding map, and exclusions. | Unrecorded evidence does not exist, the grounding source is independent, or the physical world is completely represented. |
| “The reference implementation computed VSTD-4 candidate depth `k`.” | Caller-supplied nonempty references were structurally consistent through rungs `1..k` and, when `k < 14`, the candidate ceiling certificate blocks rung `k+1`. | State `CANDIDATE`, `conformance_status = NOT_ESTABLISHED`, the supplied references, certificates, budgets, and horizons. | The references establish their rung propositions, VSTD-1/2/3 passed, normative VSTD-4 conformance was established, or VSTD-5 entry is permitted. |
| “The result is refutable.” | The published result exposes a machine-checkable falsification surface and admissible counterevidence within the declared boundary. | Name that surface, the admissible counterevidence, exclusions, and decision rule. | A separate party actually attempted refutation or independently witnessed the evidence. |
| “The verifier returned `UNKNOWN`.” | The declared check could not establish `PASS` or `FAIL` within the implemented fragment, available evidence, or resource bound. | Preserve the indeterminacy reason and transcript. | The proposition is false, no proof exists, or a larger bound could not decide it. |
| “The artifact is ready for VSTD-5 evaluation.” | **Not established by the current reference implementation.** | VSTD-5 requires evidence-bound VSTD-1/2/3 preconditions and normative VSTD-4 conformance at depth 14. `require_vstd5_entry` rejects the current unbound candidate. | Candidate depth 14, a `PASS` over the candidate formula, or nonempty references satisfy the gate. |

The public reference implementation and its tests are one implementation. This source
coordinate does not claim an external implementation, interoperability result,
security audit, independent witness, or third-party certification.

## VSTD-3 accelerator claim translations

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

The bundled checker records a checker verdict. Its historical `independent_audit` field
name is not evidence of independence. Claim independent verification only when the
receipt's `independence_basis` demonstrates distinct actors plus the relevant
implementation and runtime separation. Matching run results cannot supply that evidence.

## Safe claim template

> Using VSTD-Graph-1 at commit `<commit>`, receipt `<receipt-id>` validated the stored
> provenance graph and replayed its declared graph mechanisms for target `<artifact>`.
> This establishes receipt integrity and the stated recorded-graph results. It does not
> establish complete real-world lineage, legal rights, physical-file identity without a
> rehashing adapter, or truth outside the declared surface.

VSTD-3 safe template:

> Using VSTD-3 at commit `<commit>`, verifier `<mechanism/version>` validated receipt
> `<receipt-id>` for device/logical boundary `<boundary>` and interval `<interval>`.
> Claim `<claim>` returned `<PASS|FAIL|UNKNOWN|UNSUPPORTED>` using evidence
> `<evidence-ids>`. This says `<bounded translation>`. It does not say
> `<prohibited inference>`.

VSTD-4 safe template:

> Using VSTD4-GDC-1 at commit `<commit>`, kernel `<descriptor>` accepted
> certificate `<digest>` for claim coordinate `<coordinate>` at tier `<tier>`
> within bounds `<bounds>`. The result was `<PASS|FAIL|UNKNOWN>` and its
> machine-checkable refutation surface was `<surface>`. This establishes only
> the grounded decision within the bound roots and exclusions; it does not
> establish evidence authenticity, complete policy coverage, independent
> witnessing, or truth outside the coordinate.

VSTD-5 draft boundary template for the current implementation:

> The artifact reached VSTD-4 structural candidate depth 14 with an accepted
> certificate over caller-supplied references. Conformance remains
> `NOT_ESTABLISHED`; the VSTD-5 entry gate rejected the candidate. VSTD-5 remains
> a draft specification, and no VSTD-5 readiness, conformance, or
> independent-witness claim is made.

## Prohibited shortcuts

Do not publish any of these without the missing qualification:

- “VSTD proves provenance.”
- “VSTD proves the dataset is clean.”
- “VSTD proves the license is valid.”
- “VSTD independently verifies itself.”
- “A VSTD-4 result is independently verified” when no separate witnessing seam was
  demonstrated.
- “`UNKNOWN` proves no proof exists” or “the next rung is impossible.”
- “VSTD-5 verified” based only on passing the VSTD-5 entry gate.
- “VSTD proves the model is safe.”
- “VSTD verifies the competition result.”
- “Completely verified” when any material residual, valence, mechanism, order, or trust
  root remains unresolved.
- “Hardware attested” for host inventory, a provider allocation response, or opaque
  bytes that no implemented verifier authenticated.
- “All compute was accounted for” without complete-mediation evidence for every path in
  the named governed boundary.
- “No undeclared compute occurred” from a device, host, provider, or fleet receipt.

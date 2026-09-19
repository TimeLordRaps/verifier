# Verifier Standard (VSTD) grounded certification

**Status:** project specification for the additive version 1 certification contract.
**Certificate identifier:** `VSTD-GROUNDED-CERTIFICATION-1`.

## 1. Coordinates and meaning

`X.M` identifies obligation M within object numbered profile X. These are
dimensionless identifiers, not decimal numbers, software versions or confidence
scores. Each profile has its own finite sequence. VSTD-4 retains the exact
fourteen rungs and dependency graph from `VSTD-4.md`; other entries are called
obligations. The Graph axis has no new dotted coordinates in this contract.

Grounded certification requires the exact claim, artifact coordinate, obligation,
evidence bytes, mechanism implementation, trust roots and bounds to be bound and
checked. Certificates carry replay inputs and computed results. They MUST NOT
accept a declarant-supplied success, profile depth or certification grade as input.

The normative tables below decompose the existing object-profile requirements.
They do not replace the full requirements in `VSTD-1.md` through `VSTD-5.md`.
A domain mechanism MUST evaluate the stated obligation inside the exact declared
scope. Merely checking a record's shape, repeating its fields or matching a digest
does not discharge a substantive obligation about the record's meaning.

## 2. Admission and grounding

The checker MUST supply an external `VSTD-GROUNDED-POLICY-1` admission policy.
For each admitted obligation it selects an exact mechanism identifier, implementation
digest and trust-root set. The policy pins the obligation catalogue and normative
specification bytes. Registration and policy admission declare a trust boundary;
they do not establish that a mechanism is correct or independent. Domain-specific
mechanism qualification remains necessary before relying on its conclusions.

Each `VSTD-GROUNDED-REQUEST-1` binds a claim identifier, complete claim commitment,
target numbered profile and an individually bound proposition for each supplied
obligation. The claim's policy root MUST equal the external policy digest. Its
evidence root MUST commit to the sorted unique set of all referenced evidence
addresses. Every obligation binds the same claim identifier and commitment, its
exact catalogue predicate, Boolean true, admitted mechanism, trust roots and input
bounds. Claims about two different identifiers require separate checking; no alias
is inferred. Unknown or out-of-target obligation identifiers MUST be rejected.

Rechecking MUST be anchored to an externally expected request digest. A certificate
cannot establish that its claim is the one a consumer intended to check merely by
carrying its own claim identifier. A checker digest binds the reference orchestration
implementation; each domain mechanism remains separately pinned.

## 3. Evaluation and dependency semantics

Every supplied admissible obligation MUST have its evidence rehashed and its
mechanism rerun. The direct outcome is `PASS`, `FAIL` or `UNKNOWN`. Missing evidence,
unavailable mechanisms, digest mismatch, unapproved trust roots, unsupported checking
and exhausted input bounds MUST NOT become success. Invalid embedded byte bindings
MUST be rejected. A mechanism refutation remains `FAIL`, even if another obligation
is `UNKNOWN`.

An obligation is established only if its direct outcome is `PASS` and all its
listed dependencies are established. A blocked obligation retains its direct
observation separately. A profile coordinate is established only when all its
obligations are established. A cumulative profile additionally requires every
earlier profile coordinate. The `certified_profile_depth` is the largest uninterrupted
established prefix, or zero; it never suppresses later direct evidence. Per-profile
`established_prefix` counts contiguous established obligations within that profile.
Neither count is a strength score.

Overall `PASS` means all required obligations through the requested profile are
established under the admitted mechanisms, evidence and limits. Any directly failed
obligation produces overall `FAIL`; otherwise incomplete support produces `UNKNOWN`.
`certification_status` is `ESTABLISHED` only for the complete requested prefix.
A failed certification obligation does not imply a universal claim about the artifact.

An inapplicable domain requirement is not silently omitted. A mechanism must check
the precise applicability boundary and show that the scoped obligation is satisfied.
For VSTD-3 this preserves declared capability limits: discovery is never promoted
to attestation, complete mediation or physical-world completeness. VSTD-5 requires
actual corroboration and all seven evidenced separation dimensions. Names, hashes,
duplicate observations and witness counts never manufacture independence.

## 4. Portability, bounds and compatibility

A certificate embeds all available referenced evidence bytes and preserves absent
references in the request so an `UNKNOWN` result can replay. It carries the exact
request, catalogue/specification/policy/checker digests and complete derived result.
Its canonical digest establishes byte integrity only. Rechecking MUST validate the
exact shape, externally expected request, external policy and implementation coordinate,
rehash evidence, rerun the mechanisms, and compare the complete derived result.
Neither deleting a blocker nor replacing the carried result may survive replay.

Input counts are dimensionless; evidence and certificate limits are bytes. Global
evidence limits apply before domain execution; each proposition retains its tighter
input limits. The reference parser also imposes a 32 mebibyte (MiB, 1,048,576 bytes per unit) document ceiling. The
reference engine does not sandbox or interrupt arbitrary Python mechanism code;
deployments must admit bounded checkers or isolate them. Input byte ceilings are not
a claim of bounded arbitrary computation or physical resource enforcement.

The new request, policy and certificate identifiers are additive. Existing receipt
identifiers, VSTD-4 rung predicates, candidate-depth behavior, native VSTD-5 entry
checks and historical receipts remain unchanged. A legacy receipt is evidence for
a suitable mechanism, never automatically a complete new certificate. The new
engine does not convert a certificate into a legacy VSTD-4 or VSTD-5 receipt.

Evidence degrades when the claim, artifact, policy, mechanism, trust roots, bounds,
specification or dependency evidence changes. Old receipts remain historical bytes;
a changed coordinate requires a new assessment. Portable replay establishes only
the registered mechanisms' scoped propositions, not external independence,
accreditation, physical containment or correctness of unimplemented domain checks.

## 5. Object-profile obligation catalogue

The reference catalogue is `verifier.core.profile_obligations.OBLIGATIONS`.
Every row below is individually evidence-bound. Dependencies listed here are
within the same numbered profile; cumulative profile prerequisites also apply.

### VSTD-1: Claim Mechanics

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| 1.1 | Claim coordinate | The exact subject, proposition, scope, limitations and falsifier are bound. | none | VSTD-1.md sections 2 and 4 |
| 1.2 | Evidence binding | Every verdict-material evidence item is identified, available and bound to this claim. | 1.1 | VSTD-1.md section 7 |
| 1.3 | Checker and trust boundary | The actual checker implementation, dependencies and achieved role separation are evidenced without inferring independence. | 1.1, 1.2 | VSTD-1.md section 5 |
| 1.4 | Decision replay | The declared decision follows from rerunning the bound computational checker on the bound evidence within its limits. | 1.2, 1.3 | VSTD-1.md sections 2, 3 and 5 |
| 1.5 | Provenance | Source and execution provenance match the observed evidence and their stated observation boundary. | 1.2 | VSTD-1.md section 7 |
| 1.6 | Reproduction fidelity | The declared reproduction result and fidelity are supported by a checked comparison of the named executions. | 1.4, 1.5 | VSTD-1.md section 6 |
| 1.7 | Challenge and correction | The falsification procedure is executable and any observed challenge or correction is retained without rewriting historical evidence. | 1.1, 1.4 | VSTD-1.md section 8 |

### VSTD-2: Verification Surface

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| 2.1 | Subject and surface | The primary subject, selected surface, exclusions and coordinate meanings are explicit and bound. | none | VSTD-2.md section 3 |
| 2.2 | Geometry consistency | All selected coordinate references, containment relations and seams are internally consistent. | 2.1 | VSTD-2.md sections 3 and 10 |
| 2.3 | Translation and reconstruction | The named translation or reconstruction is checked against its source and exposes information loss and unresolved mappings. | 2.1, 2.2 | VSTD-2.md sections 4 and 8 |
| 2.4 | Evidence-earned judgments | Every relied-on judgment is earned by its exact evidence and executed mechanism rather than a status label. | 2.1, 2.2 | VSTD-2.md sections 2 and 10 |
| 2.5 | Residuals and horizons | Residuals, exclusions and horizons are typed, localized and retained in the assessed scope. | 2.2, 2.3 | VSTD-2.md sections 5 and 6 |
| 2.6 | Adjacent verification orders | Each represented meta-verification order checks its immediate predecessor and retains its evidence and termination horizon. | 2.2, 2.4 | VSTD-2.md section 6.4 |
| 2.7 | Bounded surface closure | The declared closure result is recomputed for the exact selected surface with every blocker preserved. | 2.3, 2.4, 2.5, 2.6 | VSTD-2.md sections 6 and 10 |

### VSTD-3: Substrate Accountability

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| 3.1 | Subject and capability boundary | Observed devices, execution scope, capability class and unsupported capabilities match the declared substrate boundary. | none | VSTD-3.md sections 3, 5, 6 and 7 |
| 3.2 | Attestation binding | Every relied-on attestation binds its challenge, subject, evidence and declared trust root; absent authentication cannot support an attested claim. | 3.1 | VSTD-3.md section 8 |
| 3.3 | Firmware accountability | Firmware identity, measurement and accountability claims are checked under the declared firmware contract and capability boundary. | 3.1, 3.2 | VSTD-3.md section 9 |
| 3.4 | Execution binding | Every claimed execution is linked to the exact workload, inputs, outputs and evidenced execution boundary. | 3.1, 3.2 | VSTD-3.md section 12 |
| 3.5 | Accounting and topology | Reported accounting and partition/topology claims are recomputed from bound evidence with uncertainty and virtualization limits preserved. | 3.1, 3.4 | VSTD-3.md sections 13 and 14 |
| 3.6 | Continuity and anchors | Claimed continuity and external anchors are checked for the declared interval without inferring unobserved continuity. | 3.2, 3.3, 3.4 | VSTD-3.md sections 10 and 11 |
| 3.7 | Provider and fleet scope | Provider and fleet statements are checked only inside their enumerated evidence boundary; unobserved physical work remains unsupported. | 3.1, 3.4, 3.5 | VSTD-3.md sections 15 and 16 |
| 3.8 | Derived substrate outcome | The substrate outcome is recomputed from the preceding obligations and capability-specific evidence without promoting an unsupported claim. | 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7 | VSTD-3.md sections 17, 20 and 24 |

### VSTD-4: Refutability

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| 4.1 | Decision certification | PASS, FAIL and UNKNOWN each carry a checkable artifact | none | VSTD-4.md section 2 |
| 4.2 | Semantic binding | the certificate proves the exact declared claim coordinate | 4.1 | VSTD-4.md section 2 |
| 4.3 | Anti-equivocation | claim, coordinate, policy, evidence, verifier, bounds and prior commitment bind into one digest C | 4.2 | VSTD-4.md section 2 |
| 4.4 | Portable verification | checking needs no post-verdict cooperation from the declarant | 4.3 | VSTD-4.md section 2 |
| 4.5 | Bounded verification | declared cost, memory and size bounds, enforced by the checker on itself | 4.4 | VSTD-4.md section 2 |
| 4.6 | Re-derivability | no undeclared hidden state, unpinned dependency, local path, wall-clock read or ambient entropy is verdict-material | 4.4 | VSTD-4.md section 2 |
| 4.7 | Minimal trusted checker | certificate semantics implementable with zero shared verdict-producing code | 4.5 | VSTD-4.md section 2 |
| 4.8 | Availability | verdict-critical artifacts are AVAILABLE, PORTABLE or SELF_CONTAINED, not merely IDENTIFIED | 4.6 | VSTD-4.md section 2 |
| 4.9 | Disclosure-safe checkability | confidential evidence still satisfies a declared verification interface | 4.8 | VSTD-4.md section 2 |
| 4.10 | Explicit refutation surface | machine-readable admissible_refutations and excluded_claims | 4.2 | VSTD-4.md section 2 |
| 4.11 | Prior commitment | a PrecommitmentEnvelope over every verdict-material degree of freedom | 4.10 | VSTD-4.md section 2 |
| 4.12 | Challenge handling | valid counterevidence deterministically changes claim status | 4.10, 4.1 | VSTD-4.md section 2 |
| 4.13 | Monotonic degradation | weakening evidence can never preserve an unsupported verdict | 4.12, 4.8 | VSTD-4.md section 2 |
| 4.14 | Compositionality | a RefutabilityClosure states how refutability propagates through transformations | 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.11, 4.12, 4.13 | VSTD-4.md section 2 |

### VSTD-5: Witness Corroboration

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| 5.1 | Exact refutability entry | The exact claim has evidence-bound prerequisite profiles and all fourteen VSTD-4 rungs; a candidate depth cannot admit a witness. | none | VSTD-5.md section 1 |
| 5.2 | Witness identity binding | Each witness identity is bound to available identity evidence; duplicate evidence and dangling identities do not create witnesses. | 5.1 | VSTD-5.md sections 2 and 3 |
| 5.3 | Operational separation | Ownership or operational control separation is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.4 | Implementation separation | Separation of verdict-producing code is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.5 | Trust-root separation | Verifier trust-root separation is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.6 | Evidence-source separation | Evidence-source or telemetry-provider separation is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.7 | Infrastructure separation | Separation of infrastructure capable of changing the result is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.8 | Financial separation | Material financial dependence is checked for the exact declarant/witness pair, corroboration and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.9 | Compulsion separation | Material jurisdictional or contractual dependence is checked for the exact declarant/witness pair and claim commitment. | 5.2 | VSTD-5.md section 3 |
| 5.10 | Executed corroboration | Actual witness checking binds the admitted certificate, checker, class, observation time, evidence and result; declarations alone do not satisfy it. | 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9 | VSTD-5.md section 4 |
| 5.11 | Disagreement preservation | All checked disagreements and duplicate-evidence findings are retained; voting or repeated evidence cannot produce independent corroboration. | 5.10 | VSTD-5.md sections 4 and 5 |

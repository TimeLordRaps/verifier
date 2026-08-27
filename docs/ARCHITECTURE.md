# Verifier Standard (VSTD) conformance architecture

> **Acronyms:** Boolean satisfiability problem (SAT); command-line interface (CLI);
> JavaScript Object Notation (JSON); reduced instruction set computer (RISC);
> Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD);
> zero-identity/zero-knowledge (ZIZK).

**Status:** implementation and ownership map; normative meaning remains in `standard/`

Use this order when two surfaces appear to disagree:

1. normative layer document;
2. frozen wire identifier and profile discriminator;
3. published JSON Schema;
4. typed model and validator;
5. conformance tests;
6. generated reference and examples.

A lower item cannot silently redefine a higher item. A passing schema check establishes
shape only; a passing validator establishes only its named implemented checks.

## Layer ownership

| Coordinate | Normative source | Runtime owner | Published shape | Primary tests |
|---|---|---|---|---|
| VSTD-1 claim receipt | `standard/VSTD-1.md` | `verifier.core.receipt`, `verifier.core.checker` | `vstd1_receipt.json` | `test_independent_checker.py`, `test_vstd_schemas.py` |
| VSTD-1 generic run | `standard/VSTD-1.md` | `verifier.core.run` | `vstd1_generic_run_receipt.json` | `test_generic_run.py` |
| VSTD-2 | `standard/VSTD-2.md` | `verifier.core.geometry` | `vstd2_receipt.json` | `test_verification_geometry.py` |
| VSTD-3 | `standard/VSTD-3.md` | `verifier.hardware` | `vstd3_receipt.json`, `vstd3_accelerator_profile.json` | `test_vstd3_schema.py`, hardware tests |
| VSTD-4 | `standard/VSTD-4.md` | certificate/kernel checks plus unbound candidate depth in `verifier.core.depth` | `vstd4_certificate.json`, `vstd4_receipt.json` | `test_gdc_certificate.py`, `test_vstd4_depth.py` |
| VSTD-5 | `standard/VSTD-5.md` | fail-closed candidate rejection only | `vstd5_receipt.json` | `test_vstd4_depth.py`, `test_vstd_schemas.py` |
| VSTD-Graph-1 | `standard/VSTD-Graph-1.md` | `verifier.data.models`, `verifier.data.receipt` | `vstd_graph_receipt.json` | `test_public_data.py` |
| VSTD-Graph-2..5 | matching Graph documents | `verifier.data.graph_level` | `computed_graph_level` within `vstd_graph_receipt.json` | `test_graph_level.py` |
| ZIZK artifact-first trust | `standard/LADDER.md` section 1.1 | Governs every mechanism; bounded RISC Zero example under `examples/zizk_artifact_first/` | No separate wire identifier or profile | presentation, experiment-manifest, and ZIZK mechanism tests |

VSTD-5 is draft. The VSTD-4 depth runtime and Graph-2 through Graph-5 compute candidates
from caller-supplied references or ratings and return
`conformance_status = NOT_ESTABLISHED`; evidence binding is not implemented. Neither
candidate is layer conformance.

## Governing ZIZK architecture and mechanism ownership

Zero-identity/zero-knowledge (ZIZK) artifact-first trust is a governing VSTD
architecture, not a side experiment, layer, profile, or scalar trust system. Its
normative source is `standard/LADDER.md` section 1.1:

- identity or reputation alone, popularity, and repetition supply no assurance;
- actor and artifact are contextual roles rather than permanent entity classes;
- established artifact support may move forward only across admissible bound
  transformations, while every child discharges its new obligations;
- diagnostic Rust may move backward only as recorded ancestral reachability; and
- forward support and backward Rust never cancel, reverse direction, or manufacture a
  clean signal from `UNKNOWN` or `CONFLICTED` inputs.

Zero identity is the no-identity-derived-trust rule above, not anonymity or absence of
identifiers. Checked identity evidence may establish only its exact attribution,
authorization, or separation proposition. Zero knowledge is mechanism-specific: it
applies only where a named proof system establishes the formal property for the exact
predicate and parameters under explicit assumptions.

Maturity attaches to mechanisms beneath that architecture:

| Mechanism surface | Current status | Ownership boundary |
|---|---|---|
| RISC Zero hidden-witness predicate | Bounded reference mechanism with tracked public proof artifacts | `examples/zizk_artifact_first/risc0/`; native verification only, no VSTD receipt mapping |
| Bounded identity-disclosure evaluator | Bounded non-normative reference mechanism | `examples/zizk_artifact_first/zero_identity/`; no identity-derived trust |
| Event serialization and support-transfer algebra | Experimental and unimplemented | May implement the governing direction but cannot redefine it |
| Rust concentration and localization | Experimental and unimplemented | Diagnostic reachability only until a separately specified mechanism earns more |
| Complete `PASS`/`FAIL`/`UNKNOWN`/`CONFLICTED` hidden-witness derivation | Experimental and unimplemented | A caller-supplied state tag is not an earned verdict |
| Specific optional proof backends | Backend-specific maturity; the RISC Zero example has one recorded native proof | Optional proof machinery cannot make the governing architecture optional or establish broader VSTD conformance |

## Wire dispatch

Dispatch first by `schema_version`, then by a required profile discriminator when the
frozen identifier carries multiple profiles. `VSTD-0.1` generic-run receipts require
`receipt_kind = "generic_computational_run"`. Legacy SAT/derivation receipts have no
discriminator and must match the claim-receipt required fields. Unknown combinations fail
closed.

## Installed specification ownership

Every `standard/*.md` file has a byte-identical installed resource under
`src/verifier/specifications/`. Verifier descriptors use those resources when no source
checkout is present. The installed-wheel gate runs outside the checkout and rejects an
unavailable specification digest.

## Generic-run validation contract

`vstd validate` is an integrity/profile validator for the
`generic_computational_run` profile. It enforces the strict receipt shape and recomputes
the stable-payload digest. The dynamic path keys inside
`source_state.source_file_hashes`, unconstrained recorded evaluator values, and
additional declarations inside `layer4_binding.refutation_surface` are explicit data or
extension surfaces. The refutation surface remains open because versions 1.1.2 and 1.1.3
preserved caller-defined domain refutations under the frozen `VSTD-0.1` wire identifier.
Unknown object properties outside those named surfaces fail closed.

Validation does not rehash referenced artifacts, rerun the command, resolve evidence
references, or establish that recorded declarations are true. Those are separate
mechanisms. `validate`, `inspect`, and `reproduce` honor `--json` for generic-run and
VSTD-Graph receipts; the envelope reports command completion without upgrading the
receipt's claim semantics.

### Historical generic-run binding container

`layer4_binding` is a legacy `VSTD-0.1` generic-run wire container, not a VSTD-4 object.
Versions 0.1.0 and 0.2.0 omitted it; released writers from 1.0.0 through 1.1.3 emitted it.
It is optional for historical reads and participates in the canonical digest when present.
The version 1.2.0 writer keeps emitting it because the current profile has no other lossless
location for its manifest-declared context. Dropping it would discard evidence; moving it
would define a new wire shape.

| Member | Five-As role | Maximum current meaning |
|---|---|---|
| verifier identity | Assessment | Names the generic mechanism; identity alone earns no result. |
| specification identity | Attribution and Assessment | Binds the mechanism to VSTD-1 bytes, not VSTD-4. |
| implementation identity | Assignment | Identifies implementation bytes; it does not prove an independent implementation. |
| parser identity | Assignment | Identifies parser bytes; equality with the implementation hash records shared bytes, not separation. |
| format identity | Attribution | Names the generic capture/validate/reproduce fragment. |
| resource bounds | Assurance input and Assessment bound | Records manifest declarations; the generic runtime does not establish their enforcement. |
| prior commitment | Assurance input | Records a commitment string; receipt inclusion does not prove temporal priority. |
| refutation surface | Attribution | Declares admissible refutations and exclusions; it is not the checked VSTD-4 `RefutationSurface`. |
| `vstd4_conformance` | VSTD-4-specific Assessment coordinate | Only `NOT_EVALUATED` is permitted; it earns no VSTD-4 state. |

Layers are assessment coordinates, not containers for generic verification context. The
legacy name must not generate `layer1_binding`, `layer2_binding`, or similar structures.
Replacing this writer requires an explicit later generic-run profile discriminator and
matching schema coordinate; a package version alone cannot redefine the frozen profile.
No future identifier is reserved here.

## Five-As human traversal

**Status:** non-wire architecture guide. The five As are roles in a human traversal of
existing VSTD records, not five new object types, levels, statuses, or a scalar assurance
score. No receipt or schema format is defined here.

`ASSURANCE_0 -> ATTRIBUTION -> ASSIGNMENT -> ASSESSMENT -> ASSURANCE_1` reads as follows:

| Stage | Operational meaning | Existing VSTD machinery | Current gap |
|---|---|---|---|
| `ASSURANCE_0` | Identified evidence or a previously assessed claim, with its evidence basis, provenance, bounds, trust roots, limitations, current state, and unresolved conflicts or unknowns. | Generic-run receipts and external-evaluation evidence; `EvidenceClassification`; Graph artifacts, statuses, and `ConflictRecord`; VSTD-3 evidence sources, gaps, and claim evaluations; VSTD-4 certificates and kernel results. | There is no universal Assurance record or cross-profile scalar ordering. |
| `ATTRIBUTION` | The explicit relation from evidence to the exact subject/predicate it supports, including the mapping, extraction, or transformation, scope, bounds, provenance, and information loss. | Generic-run bound-output extraction and recorded external references; Graph transformation hyperedges; VSTD-4 `ClaimCoordinate`, `ClaimBinding`, and `Grounding`; loss-sensitive SCITT coordinates. | Mapping and loss declarations remain profile-specific; a reference alone is not a checked mapping. |
| `ASSIGNMENT` | The most precise evidenced execution coordinate available: computation, execution instance, software/runtime, machine/substrate, then optional actor/operator bindings. Missing coordinates remain partial or `UNKNOWN`. | Generic-run execution and source-state records; VSTD-3 `WorkloadIdentity`, `ExecutionIdentity`, topology, device, runtime, and evidence-source records; VSTD-1 `independence_basis` for the separate independence question. | Generic actor/execution evidence binding is not implemented. Assignment alone establishes no trust, authorization, independence, or responsibility. |
| `ASSESSMENT` | An identified verifier or mechanism evaluates one bounded proposition under the applicable input Assurance, Attribution, Assignment, specification/profile, trust roots, and bounds. It earns only the predicates it checks. | Generic validation, artifact rehash, and rerun mechanisms; VSTD-3 recomputed `ClaimEvaluation`; Graph validation and candidate-level certificates; the VSTD-4 grounded certificate kernel; native VSTD plus native SCITT composition. | No one verifier covers every profile; mechanism results remain adjacent rather than silently merged. |
| `ASSURANCE_1` | The assessment output recorded as new evidence with complete lineage to its inputs, mechanism, proposition, and limits. It may be `PASS`, `FAIL`, `UNKNOWN`, `CONFLICTED`, or a profile-specific equivalent. | Receipts, claim evaluations, kernel results, certificates, artifact digests, Graph artifacts/hyperedges, and prior commitments can preserve and reference the output. | There is no universal recursive-loop envelope; any future wire representation requires a separate proposal. |

First-hand and second-hand describe **provenance**, not strength. A first-hand
self-observation may be weak; a second-hand certificate may be strongly bound to a narrow
proposition. `EvidenceClassification` records how evidence entered a profile, but its name,
source, or placement never substitutes for the profile's verification mechanism.

The smallest operational loop is:

1. select one proposition and retain every applicable input state, limitation, conflict,
   unknown, trust root, and freshness bound;
2. bind each input to that proposition through an inspectable attribution, preserving
   transformations and declared information loss;
3. record Assignment only to the depth evidenced, leaving absent coordinates `UNKNOWN`;
4. run the named assessment mechanism under its specification and bounds; and
5. record the output as a new evidence artifact and transformation, without changing any
   input record. A later loop may consume that output only as lineage-preserving input to
   another explicitly identified assessment.

> No semantic strength is gained by storage location, field name, repetition, graph
> multiplicity, actor reputation, or propagation. Every increase in assurance must
> identify the verification mechanism that earned it.

This is the human forward traversal of the same topology VSTD-Graph stores for machines.
Artifact trust is bounded forward support across an admissible recorded transformation;
the child still discharges its new obligations. Rust is reverse diagnostic reachability
from a downstream deviation toward recorded ancestors. Rust can prioritize examination;
it is not guilt, responsibility, direct causal identification, or automatic ancestor
falsification. Neither direction creates a second causality graph, and neither is currently
an emitted or validated transfer result.

### Recursive-amplification falsification outcomes

| Probe | Required outcome |
|---|---|
| Duplicate evidence or a duplicate identifier | No extra support; public receipts reject duplicates and in-memory graph construction rejects replacement. |
| Duplicate graph paths | Reachability is set-valued; path count never raises assurance or candidate level. |
| Repeated identical reruns | At most the same bounded equivalence result; repetition does not prove independence or a stronger tier. |
| Assessment consumes its own output | Invalid within that assessment; an output can enter only a later, distinct assessment with preserved lineage. |
| `A -> B -> A` or a self-loop | Invalid Graph topology; acyclicity checking rejects the loop. |
| Second-hand evidence relabeled first-hand | Provenance conflict or unsupported declaration; no strength change. |
| Attribution without a checked mapping | Declaration or `UNKNOWN`, never mapped support. |
| Machine Assignment treated as responsibility | Prohibited inference; Assignment records execution coordinates only. |
| Actor identity treated as trust | Prohibited inference; identity and reputation do not strengthen an artifact result. |
| Conflicted upstream evidence collapsed | Conflict remains explicit and blocks a clean candidate level. |
| Stale, revoked, challenged, or unknown evidence reused as clean current support | Inadmissible to a clean current Graph candidate; the historical record remains. |
| Recursive propagation with no new mechanism | No transition from `ASSURANCE_0` to stronger `ASSURANCE_1`; lineage growth is not assurance growth. |

## Separation and Graph boundaries

The historical `independent_audit` field name does not prove independence. Its
`independence_basis` records actor, implementation, and runtime separation. Repeated or
matching results are artifact agreement, not evidence that separate actors performed the
runs; absent separation evidence is `NOT_DEMONSTRATED`. Serialized status words and
evidence-reference strings cannot self-promote that result. Because version 1.2.0 has no
actor/execution evidence-binding adapter, the bundled runtime treats supplied assertions
as no stronger than `DECLARED`, rejects receipts that label them `EVIDENCED`, and never
derives `EVIDENCED`.

Graph conflict records retain incompatible values and their evidence references without
adding a scalar score or changing the frozen artifact-status vocabulary. A conflict makes
the subject inadmissible to a clean candidate Graph level.

### Recursive current-state audit

Historical receipt bytes and their recorded `PASS` remain unchanged. A later current-state
question is a new assessment over the retained graph and applicable lifecycle records:

| Scenario | Implemented outcome |
|---|---|
| An ancestor is `CHALLENGED`, `REVOKED`, or `STALE` | Candidate Graph recomputation follows the full ancestor closure and returns level 0. It does not rewrite the historical receipt. |
| An ancestor is `SUPERSEDED` | The historical Graph candidate remains admissible by design; the stricter all-ancestors-`VALID` policy rejects it for current-use admission. Supersession does not retroactively falsify its prior lineage role. |
| Upstream evidence conflicts | A retained `ConflictRecord` blocks a clean candidate. Conflict resolution is not implemented; any future resolution must be additive and retain the competing evidence. |
| Evidence arrives by multiple paths or one run receipt repeats a reference | Reachability and impact sets deduplicate identifiers. Multiplicity supplies no independence or strength. |
| A descendant deviation points toward shared ancestors | Existing ancestor queries establish recorded reverse reachability only. No runtime emits Rust, measures independent concentration, or attributes causal responsibility. |
| A challenge ledger changes a claim's current status | The append-only ledger derives `CHALLENGED` or `REVOKED`, but no adapter binds that claim status into a Graph artifact. Cross-surface propagation is `NOT_ESTABLISHED`, not silently clean. |
| Later evidence is intended to clear a conflict | No conflict-resolution transition exists in version 1.2.0. Removing the old record would violate additive correction; a future mechanism must preserve it and identify what resolved it. |
| Candidate calculation encounters cyclic ancestry | Rejected before candidate calculation; recursive topology cannot manufacture assurance. |

The implemented forward blast-radius query discovers recorded downstream artifacts and
generic-run receipts that require reconsideration when given an invalidated artifact. It is
a discovery mechanism, not automatic status mutation, current-admissibility adjudication,
or proof of causal influence. Automatic propagation for challenge, staleness, supersession,
conflict resolution, Artifact support, and Rust remains `NOT_ESTABLISHED` until a distinct
mechanism binds the lifecycle event to the exact Graph artifact and proposition.

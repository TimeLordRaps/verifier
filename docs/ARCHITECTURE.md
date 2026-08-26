# Verifier Standard (VSTD) conformance architecture

> **Acronyms:** Boolean satisfiability problem (SAT); command-line interface (CLI);
> JavaScript Object Notation (JSON); Supply Chain Integrity, Transparency, and Trust (SCITT);
> Verifier Standard (VSTD).

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
| VSTD-4 | `standard/VSTD-4.md` | `verifier.core.certificate`, `verifier.core.kernel`, `verifier.core.depth` | `vstd4_certificate.json`, `vstd4_receipt.json` | `test_gdc_certificate.py` |
| VSTD-5 | `standard/VSTD-5.md` | entry gate only | `vstd5_receipt.json` | `test_vstd_schemas.py` |
| VSTD-Graph-1 | `standard/VSTD-Graph-1.md` | `verifier.data.models`, `verifier.data.receipt` | `vstd_graph_receipt.json` | `test_public_data.py` |
| VSTD-Graph-2..5 | matching Graph documents | `verifier.data.graph_level` | `computed_graph_level` within `vstd_graph_receipt.json` | `test_graph_level.py` |

VSTD-5 is draft. Graph-2 through Graph-5 currently compute candidate levels from
caller-supplied ratings and return `conformance_status = NOT_ESTABLISHED`; rating-evidence
binding is not implemented.

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

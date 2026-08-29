# Verifier Standard (VSTD) conformance architecture

> **Acronyms:** application programming interface (API); Boolean satisfiability problem (SAT); command-line interface (CLI);
> JavaScript Object Notation (JSON); reduced instruction set computer (RISC);
> Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD);
> zero-identity/zero-knowledge (ZIZK).

**Status:** implementation and ownership map; normative meaning remains in `standard/`

TRUST is mechanism-earned forward artifact support; ROT is typed, time-indexed
degradation of current admissibility; and RUST is inverse-TRUST diagnostic traversal
toward recorded ancestors. They are formal semantic names, not acronyms or actor ratings.

Use this order when two surfaces appear to disagree:

1. normative numbered-profile document;
2. serialized receipt identifier (`schema_version`) and profile discriminator;
3. published JSON Schema;
4. typed model and validator;
5. conformance tests;
6. generated reference and examples.

A lower item cannot silently redefine a higher item. A passing schema check establishes
shape only; a passing validator establishes only its named implemented checks.

## Numbered-profile ownership

| Coordinate | Normative source | Runtime owner | Published shape | Primary tests |
|---|---|---|---|---|
| VSTD-1 claim receipt | `standard/VSTD-1.md` | `verifier.core.receipt`, `verifier.core.checker` | `vstd1_receipt.json` | `test_independent_checker.py`, `test_vstd_schemas.py` |
| VSTD-1 generic run | `standard/VSTD-1.md` | `verifier.core.run` capture/facade plus `run_planning`, `run_validation`, `run_inspection`, `run_reproduction`, and `run_impact` | `vstd1_generic_run_receipt.json` | `test_generic_run.py` |
| VSTD-2 | `standard/VSTD-2.md` | `verifier.core.geometry` | `vstd2_receipt.json` | `test_verification_geometry.py` |
| VSTD-3 | `standard/VSTD-3.md` | `verifier.hardware` | `vstd3_receipt.json`, `vstd3_accelerator_profile.json` | `test_vstd3_schema.py`, hardware tests |
| VSTD-4 | `standard/VSTD-4.md` | certificate/kernel checks plus candidate and evidence-bound paths in `verifier.core.depth` / `verifier.core.evidence` | `vstd4_certificate.json`, `vstd4_receipt.json` | `test_gdc_certificate.py`, `test_vstd4_depth.py`, `test_evidence_bound_assurance.py` |
| VSTD-5 | `standard/VSTD-5.md` | `verifier.core.witness` evidence-bound entry, independence, corroboration, disagreement, build, and replay | `vstd5_receipt.json` | `test_evidence_bound_assurance.py`, `test_vstd_schemas.py` |
| VSTD-Graph-1 | `standard/VSTD-Graph-1.md` | `verifier.data.models`, `verifier.data.receipt` | `vstd_graph_receipt.json` | `test_public_data.py` |
| VSTD-Graph-2..5 | matching Graph documents | `verifier.data.graph_level` candidate/evidence-bound paths | `computed_graph_level` within `vstd_graph_receipt.json` | `test_graph_level.py`, `test_evidence_bound_assurance.py` |
| ZIZK artifact-first TRUST/ROT/RUST | `standard/LADDER.md` section 1.1 | `verifier.data.assurance`; bounded RISC Zero example under `examples/zizk_artifact_first/` | `vstd-graph-assurance-1.schema.json`; not a numbered-profile receipt | assurance, presentation, experiment-manifest, and ZIZK mechanism tests |
| Artifact freeze, seal, and thaw | `standard/ARTIFACT_CONTROL.md` | `verifier.artifact_control` and `vstd artifact` | `standard/schemas/artifact-control-1.schema.json`; these are mechanism objects, not receipts | `test_artifact_control.py`, public API/CLI tests |

Compatibility VSTD-4 and Graph paths still compute candidates from caller-supplied
references or ratings and return `conformance_status = NOT_ESTABLISHED`. Separate
evidence-bound paths resolve exact bytes, pin and rerun registered mechanisms, enforce
bounds, and recheck certificates before they can report `ESTABLISHED`. A mechanism result
is limited to its proposition, evidence, trust roots, implementation digest, and bounds;
the repository claims no external witness or independent implementation.

Artifact control is an orthogonal mechanism beneath the axes. It can preserve and close
an artifact used in any numbered profile, but its successful verification establishes only exact-byte
integrity, structural closure, and any separately supplied external anchor. It cannot
supply a numbered-profile result, semantic correctness, encryption, trusted time, actor trust, or
continuous temporal mediation.

## Verification complex and profile satisfaction

VSTD is organized by named **closure coordinates**, not interchangeable layers or scalar
assurance levels. A **numbered profile** is a cumulative requirement formula over those
coordinates. The two axes use different coordinate sets even when their profile numbers
match:

| Profile number | Object closure coordinate | Graph closure coordinate |
|---:|---|---|
| 1 | Claim Mechanics | Recorded Lineage |
| 2 | Verification Surface | Bounded Collection Surface |
| 3 | Substrate Accountability | Accountable Provenance Closure |
| 4 | Refutability | Refutable Transformation Closure |
| 5 | Witness Corroboration | Corroborated Verification Network |

Evidence enters through a named mechanism, establishes or fails to establish exact
coordinate facts, and is then evaluated against the selected profile formula. A complete
assessment preserves `ESTABLISHED`, `REFUTED`, `UNKNOWN`, `CONFLICTED`, and
`NOT_ESTABLISHED` rather than collapsing absent evidence into false or a satisfiable
encoding into conformance. A satisfying assignment over unvalidated caller assertions is
only a candidate. Satisfaction suffices only when every satisfying fact is itself bound to
evidence by the mechanism that earned it.

“Closure” is always qualified. VSTD-2 surface closure, Graph provenance closure,
refutability closure, and artifact-seal structural closure are distinct propositions.
“Profile” is likewise qualified as a numbered, receipt, application, or geometry profile
when context does not make the category unique. The exact compatibility names and
exceptions are normative in [`standard/LADDER.md`](../standard/LADDER.md#terminology-contract).

## Operational traversal and recursive Graph materialization

This non-serialized implementation view does not redefine the numbered profiles:

```text
native computation
  -> VSTD-1 execution and claim capture
  -> profiler or domain adapter
  -> VSTD-2 verification-surface normalization
  -> VSTD-3 substrate accountability
  -> VSTD-4 portable refutation
  -> VSTD-5 independently evidenced witness corroboration
  -> VSTD-Graph collection assessment
  -> content-addressed result artifact
  -> later bounded verification loop
```

VSTD-2 is the semantic target for adjacent adapters, not the adapter implementation
itself. Geometry profiles constrain reusable selections of VSTD-2 geometry; they are connected only
by explicit shared coordinates, seams, mappings, and evidence-bearing transformations.
The current `VSTD-2` receipt has no geometry-profile or profile-composition field, so this
relationship is conceptual rather than a new serialized contract. See
[`VSTD-2` section 8.1](../standard/VSTD-2.md#81-profiles-and-profiler-adapters).

The complete apparatus that constructs or assesses a Graph is a verifying process. In a
later order it may become the subject of a new VSTD-2 surface, while an adjacent adapter
maps its selected observable outputs into that geometry. Treating the whole apparatus as
the adapter would erase the builder, mapping, verifier, and output seams that the next
assessment must examine.

A materialized Graph result must retain or bind the source Graph receipt, target collection
or induced subgraph, selection query, object and edge ratings with their evidence, selected
surface, lifecycle and conflict state, Graph profile certificate, materialization mechanism,
and declared information loss. It earns no strength from size, path count, repetition,
storage, or agreement. Its result is capped by every applicable member, transformation,
mapping, substrate, refutation, witness, and materialization obligation. The compatibility
path establishes only its candidate computation. The evidence-bound path can establish a
Graph profile only after rerunning every required rating mechanism across the complete
closure.

## Governing ZIZK architecture and mechanism ownership

ZIZK artifact-first TRUST is a governing VSTD architecture, not a side experiment,
numbered profile, scalar trust system, or actor
reputation system. VSTD evaluates bounded validity propositions about computational
processes represented by software and evidence-bearing artifacts; it does not determine
whether an actor is good or bad. Its normative source is `standard/LADDER.md` section 1.1.

Zero identity means zero identity-derived verdict weight, not anonymity or absence of
identifiers. Checked identity evidence may establish only its exact attribution,
authorization, or separation proposition, adjacent to the process claim. Zero knowledge
means zero unevidenced knowledge is presumed: absent a mechanism-earned result, the exact
proposition remains `UNKNOWN`. When a witness must remain confidential, cryptographic zero
knowledge may enclose this architectural rule by binding the exact program, predicate,
public commitments, output, proof parameters, and verifier. The proof remains bearer- and
artifact-bound; prover identity or reputation supplies no TRUST. This property applies
only where a named proof system establishes it under explicit assumptions.

TRUST, ROT, and RUST are formal semantic names, not acronyms, serialized receipt values, actor ratings,
scalar scores, or references to the Rust programming language:

- TRUST is mechanism-earned artifact support moving forward only across admissible bound
  transformations while every child discharges its new obligations;
- ROT is typed, time-indexed degradation of current admissibility without rewriting
  historical evidence; and
- RUST is the inverse-TRUST diagnostic mechanic moving backward from an observed descendant
  deviation through recorded contributing ancestry.

The three never cancel, reverse direction, or manufacture a clean signal from `UNKNOWN` or
`CONFLICTED` inputs. Identity, popularity, repetition, age alone, topology, and propagation
supply no assurance.

Maturity attaches to mechanisms beneath that architecture:

| Mechanism surface | Current status | Ownership boundary |
|---|---|---|
| RISC Zero hidden-witness predicate | Bounded reference mechanism with tracked public proof artifacts | `examples/zizk_artifact_first/risc0/`; native verification only, no VSTD receipt mapping |
| Bounded identity-disclosure evaluator | Bounded non-normative reference mechanism | `examples/zizk_artifact_first/zero_identity/`; no identity-derived trust |
| Assurance event serialization and replay | Implemented bounded reference mechanism | `VSTD-GRAPH-ASSURANCE-1` embeds the historical Graph, exact bindings, evidence bytes, a hash chain, and a current-view digest; `recheck_assurance_log` reruns every event mechanism |
| TRUST transfer | Implemented edge-local proposition-dispatch reference mechanism | `record_trust` binds one exact transformation, its complete inputs and output, the historical Graph digest, and the prerequisite TRUST event for every derived input. Recursive current-admissibility checking excludes the route if any required event, artifact, or transformation degrades or conflicts, without deleting history. No universal scalar support algebra exists. |
| ROT derivation and cross-surface propagation | Implemented bounded reference mechanisms | Strictly degrading status propositions and complete challenge-ledger projections produce additive current-state overlays; the deduplicated descendant impact set is discovery, and a descendant status change still needs its own mechanism |
| RUST concentration and localization | Implemented bounded reference mechanisms | A passing descendant-deviation proposition produces deduplicated reverse reachability; concentration counts unique descendants; localization and artifact-relative diagnostic attribution require separate passing propositions |
| Complete `PASS`/`FAIL`/`UNKNOWN`/`CONFLICTED` hidden-witness derivation | Experimental and unimplemented | A caller-supplied state tag is not an earned verdict |
| Specific optional proof backends | Backend-specific maturity; the RISC Zero example has one recorded native proof | Optional proof machinery cannot make the governing architecture optional or establish broader VSTD conformance |

## Serialized receipt dispatch

Dispatch first by `schema_version`, then by the required profile discriminator. VSTD-1
claim receipts require `receipt_kind = "claim_mechanics"`; generic-run receipts require
`receipt_kind = "generic_computational_run"`. Unknown identifiers, absent discriminators,
and mismatched shapes fail closed. The current reader does not infer a profile from
retired pre-current-profile field arrangements.

## Installed specification ownership

Every `standard/*.md` file has a byte-identical installed resource under
`src/verifier/specifications/`. Verifier descriptors use those resources when no source
checkout is present. The installed-wheel gate runs outside the checkout and rejects an
unavailable specification digest.

The artifact-control schema has a byte-identical installed copy under
`src/verifier/artifact_control/`. GitHub Pages publishes it at its declared `/schemas/`
route alongside receipt schemas without reclassifying it as a receipt.

## Generic-run validation contract

`vstd validate` is an integrity/profile validator for the
`generic_computational_run` profile. It enforces the strict receipt shape and recomputes
the stable-payload digest. The dynamic path keys inside
`source_state.source_file_hashes`, unconstrained recorded evaluator values, and
additional declarations inside `assessment_context.refutation_surface` are explicit data or
extension surfaces. The refutation surface remains open for caller-defined domain
refutations, but every additional value remains a declaration until an applicable mechanism
checks it. Unknown object properties outside those named surfaces fail closed.

Validation does not rehash referenced artifacts, rerun the command, resolve evidence
references, or establish that recorded declarations are true. Those are separate
mechanisms. `validate`, `inspect`, and `reproduce` honor `--json` for generic-run and
VSTD-Graph receipts; the envelope reports command completion without upgrading the
receipt's claim semantics.

### Generic-run assessment context

`assessment_context` is a required VSTD-1 generic-run container, not a VSTD-4 object. It
participates in the canonical digest and retains the manifest-declared mechanism,
resource-bound, commitment, and refutation coordinates without using a numbered-profile
identifier as a generic container name.

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

Closure coordinates identify assessment questions; they are not containers for generic
verification context. The neutral container must not generate profile-numbered binding
structures. Nothing in
`assessment_context` supplies a VSTD-4 result.

## Five-As human traversal

**Status:** non-serialized architecture guide. The five As are roles in a human traversal
of existing VSTD records, not five new object types, numbered profiles, statuses, or a scalar assurance
score. No receipt or schema format is defined here.

`ASSURANCE_0 -> ATTRIBUTION -> ASSIGNMENT -> ASSESSMENT -> ASSURANCE_1` reads as follows:

| Stage | Operational meaning | Existing VSTD machinery | Current gap |
|---|---|---|---|
| `ASSURANCE_0` | Identified evidence or a previously assessed claim, with its evidence basis, provenance, bounds, trust roots, limitations, current state, and unresolved conflicts or unknowns. | Generic-run receipts and external-evaluation evidence; `EvidenceClassification`; Graph artifacts, statuses, and `ConflictRecord`; VSTD-3 evidence sources, gaps, and claim evaluations; VSTD-4 certificates and kernel results. | There is no universal Assurance record or cross-profile scalar ordering. |
| `ATTRIBUTION` | The explicit relation from evidence to the exact subject/predicate it supports, including the mapping, extraction, or transformation, scope, bounds, provenance, and information loss. | Generic-run bound-output extraction and recorded external references; Graph transformation hyperedges; VSTD-4 `ClaimCoordinate`, `ClaimBinding`, and `Grounding`; loss-sensitive SCITT coordinates. | Mapping and loss declarations remain profile-specific; a reference alone is not a checked mapping. |
| `ASSIGNMENT` | The most precise evidenced execution coordinate available: computation, execution instance, software/runtime, machine/substrate, then optional actor/operator bindings. Missing coordinates remain partial or `UNKNOWN`. | Generic-run execution and source-state records; VSTD-3 `WorkloadIdentity`, `ExecutionIdentity`, topology, device, runtime, and evidence-source records; VSTD-1 `independence_basis` for the separate independence question; generic `BoundProposition` mechanism dispatch for an exact assignment proposition. | The legacy generic-run declaration does not self-promote into an evidenced Assignment. A deployment supplies the mechanism and observations; Assignment alone establishes no trust, authorization, independence, or responsibility. |
| `ASSESSMENT` | An identified verifier or mechanism evaluates one bounded proposition under the applicable input Assurance, Attribution, Assignment, specification/profile, trust roots, and bounds. It earns only the predicates it checks. | Generic validation, artifact rehash, and rerun mechanisms; VSTD-3 recomputed `ClaimEvaluation`; Graph validation and candidate-profile certificates; the VSTD-4 grounded certificate kernel; native VSTD plus native SCITT composition. | No one verifier covers every profile; mechanism results remain adjacent rather than silently merged. |
| `ASSURANCE_1` | The assessment output recorded as new evidence with complete lineage to its inputs, mechanism, proposition, and limits. It may be `PASS`, `FAIL`, `UNKNOWN`, `CONFLICTED`, or a profile-specific equivalent. | Receipts, claim evaluations, kernel results, certificates, artifact digests, Graph artifacts/hyperedges, prior commitments, and the replayable `VSTD-GRAPH-ASSURANCE-1` event envelope preserve and reference the output. | The Graph envelope is not a universal scalar or an automatic cross-profile cast; each later loop still names and reruns its mechanism. |

First-hand and second-hand describe **provenance**, not strength. A first-hand
self-observation may be weak; a second-hand certificate may be strongly bound to a narrow
proposition. `EvidenceClassification` records how evidence entered a profile, but its name,
source, or placement never substitutes for the profile's verification mechanism.

The smallest operational loop is:

1. select one proposition and retain every applicable input state, limitation, conflict,
   unknown, trust root, and freshness bound;
2. bind each input to that proposition through an inspectable attribution, preserving
   transformations and declared information loss;
3. record Assignment only to the specificity evidenced, leaving absent coordinates `UNKNOWN`;
4. run the named assessment mechanism under its specification and bounds; and
5. record the output as a new evidence artifact and transformation, without changing any
   input record. A later loop may consume that output only as lineage-preserving input to
   another explicitly identified assessment.

> No semantic strength is gained by storage location, field name, repetition, graph
> multiplicity, actor reputation, or propagation. Every increase in assurance must
> identify the verification mechanism that earned it.

This is the human forward traversal of the same topology VSTD-Graph stores for machines.
TRUST is bounded, mechanism-earned support across an admissible recorded transformation;
the child still discharges its new obligations. ROT is typed, time-indexed degradation of
current admissibility while historical evidence remains immutable. RUST is inverse-TRUST
diagnostic reachability from a downstream deviation toward recorded ancestors. Together
they describe memetic causal-provenance and lifecycle behavior over one development graph.
They do not establish actor standing, moral character, responsibility, or automatic
ancestor falsification. The reference runtime emits bounded TRUST, ROT, and RUST events
only after their exact mechanisms run. Causal localization and artifact-relative `BLAME`
or `GUILT` require additional exact propositions. BLAME establishes bounded responsibility
or material contribution; GUILT is not directionally opposite, but additionally binds and
checks an exact violated obligation. Neither becomes actor reputation.

### Recursive-amplification falsification outcomes

| Probe | Required outcome |
|---|---|
| Duplicate evidence or a duplicate identifier | No extra support; public receipts reject duplicates and in-memory graph construction rejects replacement. |
| Duplicate graph paths | Reachability is set-valued; path count never raises assurance or the candidate Graph profile. |
| Repeated identical reruns | At most the same bounded equivalence result; repetition does not prove independence or a stronger reproduction state. |
| Assessment consumes its own output | Invalid within that assessment; an output can enter only a later, distinct assessment with preserved lineage. |
| `A -> B -> A` or a self-loop | Invalid Graph topology; acyclicity checking rejects the loop. |
| Second-hand evidence relabeled first-hand | Provenance conflict or unsupported declaration; no strength change. |
| Attribution without a checked mapping | Declaration or `UNKNOWN`, never mapped support. |
| Machine Assignment treated as responsibility | Prohibited inference; Assignment records execution coordinates only. |
| Actor identity treated as trust | Prohibited inference; identity and reputation do not strengthen an artifact result. |
| Conflicted upstream evidence collapsed | Conflict remains explicit and blocks a clean candidate Graph profile. |
| Stale, revoked, challenged, or unknown evidence reused as clean current support | Inadmissible to a clean current Graph candidate; this is ROT in current admissibility, not revision of the historical record. |
| Recursive propagation with no new mechanism | No transition from `ASSURANCE_0` to stronger `ASSURANCE_1`; lineage growth is not assurance growth. |

## Separation and Graph boundaries

The historical `independent_audit` field name does not prove independence. Its
`independence_basis` records actor, implementation, and runtime separation. Repeated or
matching results are artifact agreement, not evidence that separate actors performed the
runs; absent separation evidence is `NOT_DEMONSTRATED`. Serialized status words and
evidence-reference strings cannot self-promote that result. The generic-run compatibility
path treats supplied assertions as no stronger than `DECLARED`, rejects receipts that label
them `EVIDENCED`, and never derives `EVIDENCED`. The distinct VSTD-5 reference path can
establish only its exact declarant/witness separation propositions after all seven seams are
rerun by registered mechanisms. Typed binding, identity, separation, and corroboration
errors keep `computed_independence` fail-closed; no error-message text is interpreted as a
semantic category. This path does not upgrade the legacy generic-run fields.

Graph conflict records retain incompatible values and their evidence references without
adding a scalar score or changing the frozen artifact-status vocabulary. A conflict makes
the subject inadmissible to a clean candidate Graph profile.

### Recursive current-state audit

Historical receipt bytes and their recorded `PASS` remain unchanged. A later current-state
question is a new assessment over the retained graph and applicable lifecycle records:

| Scenario | Implemented outcome |
|---|---|
| An ancestor is `CHALLENGED`, `REVOKED`, or `STALE` | Candidate/evidence-bound Graph recomputation follows the full ancestor closure and returns compatibility field `level = 0`. `AssuranceLedger` also records typed ROT or projects append-only challenge-ledger state into a derived current view; historical Graph bytes remain unchanged. |
| An ancestor is `SUPERSEDED` | The historical Graph candidate remains admissible by design; the stricter all-ancestors-`VALID` policy rejects it for current-use admission. Supersession does not retroactively falsify its prior lineage role. |
| Upstream evidence conflicts | A retained `ConflictRecord` or a mechanism-established `CONFLICT_DECLARATION` event blocks every dependent edge-local TRUST route. `resolve_conflict` accepts only a mechanism-passing proposition bound to the exact conflict and one retained competing value; the original conflict remains in history while the derived current view records the additive resolution. |
| Evidence arrives by multiple paths or one run receipt repeats a reference | Reachability and impact sets deduplicate identifiers. Multiplicity supplies no independence or strength. |
| A descendant deviation points toward shared ancestors | A mechanism-passing deviation emits RUST over the deduplicated recorded ancestor set. Structural concentration counts unique deviating descendants, not paths or causal strength. Localization, BLAME, and GUILT require separate exact mechanisms. |
| A challenge ledger changes a claim's current status | `project_challenges` binds its complete append-only records into a current Graph overlay and embeds those records for replay. Existing TRUST remains historical, while recursively dependent events disappear from `current_trust_events`; `impacted_descendants` reports the deduplicated reassessment surface. It never mutates the historical graph. |
| Later evidence clears a conflict | The additive resolution retains the original competing evidence and its mechanism evaluation. Removing or rewriting the conflict remains invalid. |
| Candidate calculation encounters cyclic ancestry | Rejected before candidate calculation; recursive topology cannot manufacture assurance. |

The forward blast-radius query remains discovery only. `AssuranceLedger` is the distinct
binding mechanism for explicit edge-local TRUST, ROT, RUST, challenge projection, and
conflict declaration/resolution. `recheck_assurance_log` reconstructs the historical Graph, rehashes every
embedded evidence item, reruns the exact registered mechanisms, reproduces the event chain,
and compares the derived current view. The ledger never infers an unrecorded edge, converts
topology into assurance, or treats RUST as causality. Domain-specific transfer and
localization propositions still require their registered mechanisms and may return
`UNKNOWN`.

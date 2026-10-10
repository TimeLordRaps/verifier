# Python application programming interface (API) stability

> **Term:** Verifier Standard (VSTD).

This policy applies beginning with the first release that contains it. It does not
retroactively change frozen receipts or earlier release bytes.

Signature consumers reject noncanonical and small-order Ed25519 public keys through
the internal `verifier.core.signature_keys` admission screen. Ed25519 is the
Edwards-curve digital signature algorithm with a 255-bit field. Signature checking
still uses the existing optional backend. This correction preserves wire shapes;
affected mechanism digests change, requiring policy selection and evidence replay.
Key admission does not establish full subgroup membership, custody or authority.

The experimental [retained hardware inventory](../src/verifier/standard/CURRENT_HARDWARE_INVENTORY.md)
adds current `HARDWARE-1.3` through `vstd current-object`. It checks retained device
records and per-device integer capacities. Physical authenticity, live availability,
cross-device equivalence and credit authority remain unestablished. Current typed
facets `HARDWARE-1.1` and legacy inventory/topology meanings remain separate.

The unreleased 2.0.0 domain path adds `NativeDomainAdapter`, `domain_catalog`,
`domain_policy`, `domain_request`, `build_domain_certificate`, and
`recheck_domain_certificate` to the supported exports. These functions consume
the additive [domain contracts](../src/verifier/standard/DOMAIN_GROUNDING.md); they do not
reinterpret historical domain records or establish object numbered-profile conformance.

The current hierarchy foundation uses experimental direct submodules
`verifier.core.namespace` and `verifier.domains.contracts`. Immutable objects,
typed composition, finite simulation isolation, and hardware-ownership eligibility
have the boundaries in [the object contract](../src/verifier/standard/NAMESPACE_OBJECTS.md).
They are not top-level supported exports or complete nine-tier certifications.
Consumers must bind the exact source or package revision and replay their evidence
when it changes; historical numbered-profile receipts retain their own semantics.
The versioned [declared identity binding](../src/verifier/standard/IDENTITY_OCCUPANCY.md)
is also a direct experimental submodule. It accepts current HUMAN, AGENT and BOT
representations within its declared-relation scope. The legacy native IDENTITY
adapter and command-line route retain their historical meanings; this contract
does not migrate their numbered-profile meanings. The separate experimental
[current identity scope certificate](../src/verifier/standard/CURRENT_IDENTITY_SCOPE.md)
adds public current `IDENTITY-3.1` selection through
`verifier.domains.contracts.identity_scope`, preserving declared-relation limits.
The native helper also admits explicit composition and relation-traversal bounds.

The experimental [current-object grounding route](../src/verifier/standard/CURRENT_OBJECT_GROUNDING.md)
adds an independently versioned certificate and replay for one finite simulation
confinement objective. Its request and policy must be selected outside the carried
certificate. It has no top-level export and does not establish
an entire meta-tier, physical isolation or external authority.

The experimental direct submodule `verifier.corrigibility.controlled_operation`
adds a cooperative, in-process stop gate around the existing controlled-emission
admission. It is not a top-level supported export or a numbered-profile
certificate. Its local quiescence result does not establish process, child,
network or physical shutdown; the host must independently control authority
inputs and route effects through the gate.
Its adjacent direct submodule `verifier.corrigibility.operator_stop` supplies an
opt-in configured-public-key signed STOP request. A protected session refuses
unsigned, malformed, stale or substituted requests; an unprotected session
retains the earlier cooperative stop. This is not human identity proof, durable
request consumption, process preemption or descendant quiescence.
The session also exposes a read-only local stop latch and bounded wait for
cooperating callbacks admitted before STOP. Neither forces a callback to return.
The adjacent [HYPER closure route](../src/verifier/standard/CURRENT_HYPER_CLOSURE.md)
binds one exact finite declared operand-cone proposition under the same current
semantic version. It is also a direct experimental import with externally selected
request and policy, full retained evidence and complete certificate replay. Neither
route establishes privacy, publication permission or full object-profile conformance.

The experimental [generic OBJECT facets route](../src/verifier/standard/CURRENT_OBJECT_FACETS.md)
adds current `OBJECT-1.1`: exact canonical representation and a deterministic
record address. Any admitted kind can be its subject; the result does not
establish that kind's own structural facets, an issued receipt or execution.
It retains one complete record and requires external request/policy selection
and exact certificate replay. It is a direct submodule import with the same
revision-binding requirement as the other current-object routes.

The experimental [native simulation-checker dynamics route](../src/verifier/standard/CURRENT_SIM_CHECKER.md)
adds current `VERIFIER-2.1` through the direct `verifier.domains.contracts.sim_checker`
submodule. It binds an exact checker object, installed mechanism and independently
selected finite expected outcomes; it does not establish class-wide soundness.

The experimental [selected receipt-chain route](../src/verifier/standard/CURRENT_RECEIPT_CHAIN.md)
adds current `RECEIPT-9.1` through `verifier.domains.contracts.receipt_chain`.
It binds the exact retained receipt object and a finite byte sequence to externally
selected chain anchors; it does not establish issuer authenticity or signature validity.

The experimental [declared structural-facet routes](../src/verifier/standard/CURRENT_TYPED_FACETS.md)
add one native operand-contract proposition per kind through
`verifier.domains.contracts.typed_facets`. Current `OBJECT-1.2` supplements generic
`OBJECT-1.1`; the other kinds use their current `1.1` coordinate. These structural
claims do not establish payload truth, actual personhood, execution or authority.

The experimental [retained dataset certificates](../src/verifier/standard/CURRENT_DATA_CHECKS.md)
add five separately selected DATA predicates through
`verifier.domains.contracts.data_checks`. They execute retained native checks
without transferring historical results or establishing complete dataset coverage.

The experimental [retained environment certificates](../src/verifier/standard/CURRENT_ENV_CHECKS.md)
add four separately selected ENV predicates through
`verifier.domains.contracts.env_checks`. They check retained observations without
claiming live attestation, actual reruns or physical isolation.

The experimental [retained benchmark certificates](../src/verifier/standard/CURRENT_BENCH_CHECKS.md)
add four separately selected BENCH predicates through
`verifier.domains.contracts.bench_checks`. Native score reports retain `score` and
add `score_exact` numerator/denominator evidence; exact arithmetic now governs
linear residuals and minimum-score admission. Changed implementation commitments
require new selected policies; historical certificates are not silently promoted.

The experimental [retained training certificates](../src/verifier/standard/CURRENT_TRAIN_CHECKS.md)
add five separately selected TRAIN predicates through
`verifier.domains.contracts.train_checks`. Configuration, checkpoint inventory,
loss/gradient replay, retained-gradient updates and lineage remain distinct.
Current TRAIN-1.1 keeps its typed structural meaning; legacy optimizer admission
is not silently substituted. Changed native dependencies require newly selected
policies and fresh evidence.

The experimental [retained model certificates](../src/verifier/standard/CURRENT_MODEL_CHECKS.md)
add five separately selected MODEL predicates through
`verifier.domains.contracts.model_checks`. Artifact binding, dense tensor shape,
inference, metric evaluation and finite probes remain distinct. Current MODEL-1.1
keeps its typed structural meaning; historical tensor inventory is not substituted.
The selected training-checkpoint relationship does not establish training arithmetic
or execution. Changed dependencies require newly selected policies and evidence.

The experimental [retained harness certificates](../src/verifier/standard/CURRENT_HARNESS_CHECKS.md)
add five separately selected HARNESS predicates through
`verifier.domains.contracts.harness_checks`. Declared channels, messages, complete
tool-record pairing, effects and transcript commitments remain distinct. Current
HARNESS-1.1 retains typed structural facets; HARNESS-1.6 selects channel partition
without reinterpreting historical facet coordinates. Retained association does not
establish actual tool execution or recorder authenticity. Changed dependencies
require newly selected policies and evidence.

The experimental [retained agent certificates](../src/verifier/standard/CURRENT_AGENT_CHECKS.md)
add five selected AGENT predicates through `verifier.domains.contracts.agent_checks`.
Harness replay, trajectory positions, distinct actions, exact outcome comparison and
claim support remain separate. AGENT-1.1 retains typed facets; AGENT-1.8 selects
harness binding without reinterpreting historical facet coordinates. Current external
policy governs child replay. Historical child-policy reproduction, actual execution,
internal deliberation and statement truth remain unestablished. Changed native-domain
dependencies invalidate both agent and aggregate replay policies.

The experimental [retained BOT certificates](../src/verifier/standard/CURRENT_BOT_CHECKS.md)
add five selected coupling predicates through `verifier.domains.contracts.bot_checks`.
BOT-1.1 remains typed facets; BOT-1.6 selects child binding. Alignment, observations,
actions and declared environment separation remain distinct. Current external policy
selects the numerical tolerance ceiling and recursive checking limits; historical
child policy cannot grant current acceptance. Actual invocation, physical containment
and whole-tier conformance remain unestablished.

The experimental [full-record disclosure certificates](../src/verifier/standard/CURRENT_PRIVACY_CHECKS.md)
register `<kind>-6.7` through `verifier.domains.contracts.privacy_checks` for each
admitted kind. They check whole-record preservation under declared field bounds,
observer facts and typed co-disclosure refusal rules. Legacy 6.1 through 6.6 remain
distinct. Observer authentication, underlying payload validity and actual emission
remain unestablished. Portable certificates retain disclosure-sensitive witnesses.

The experimental `verifier.consent.public` module admits and rechecks one exact
action using independently configured public keys, authority terms and trusted time.
Its separately versioned signatures preserve shared-secret consent wire meanings.
Reproduction and current admission remain distinct; missing verification cannot
erase a detectable receipt-binding mismatch. See [public consent](../src/verifier/standard/CONSENT_PUBLIC_ADMISSION.md).
This helper does not register the six proposed consent objectives or issue polished artifacts.

`vstd current-object catalog` and `vstd current-object check` expose the registered
experimental nine-tier routes with explicit semantic version, objective and represented-kind
selection. `vstd polish catalog`, `assess` and `check` expose the versioned
[polished-artifact assessment contract](../src/verifier/standard/POLISHED_ARTIFACTS.md).
The direct `verifier.runtime.polish` module remains experimental and requires an
exact installed-revision binding. Assessment and replay are not polished-artifact
issuance; missing closure and public proof mechanisms remain unestablished.

The experimental [current-certificate emission bridge](CURRENT_CERTIFICATE_EMISSION.md)
replays full current SIM and HYPER certificates before and after local disclosure
assessment. Reproducing a native FAIL or UNKNOWN does not promote its computational
result. Generic disclosure refuses partial projections of those canonical formats
and current OBJECT-facets, native simulation-checker, selected receipt-chain and declared structural-facet
certificates. The bridge supports only SIM and HYPER and does not establish consent,
governance, transmission or publication authority.

## Supported boundary

The supported Python runtime API is the set of names exported by `verifier.__all__` and
rendered under **Top-level Python exports** in the generated
[reference](https://timelordraps.github.io/verifier/reference.html). The implementation
tests that the two surfaces agree and that every exported name resolves.

`verifier.__version__`, `verifier.__standard__`, and `verifier.__standard_status__` are
stable read-only metadata names. The standard coordinate and status describe this project;
they do not claim standards-body recognition, conformance, adoption, or endorsement.

The supported artifact-control exports are `freeze_artifact`, `seal_artifact`,
`verify_frozen_artifact`, `thaw_artifact`, `thawed_artifact_status`,
`ArtifactVerification`, and `ArtifactControlError`. Seal creation and seal verification
require the optional `seal` dependency extra; importing the base package and freeze-only
operations retain the zero-third-party-dependency boundary.

`freeze_artifact` classifies the supplied final source entry before dereferencing it and
refuses symbolic links. New freeze bundles, thaw descendants, and generated thaw sidecars
require absent lexical destination entries, including refusal of dangling symbolic links.
This fail-closed creation contract does not promise universal race-free filesystem security
against concurrent privileged replacement.

Verification also requires authoritative internal bundle members to have their ordinary
lexical file or directory type. The freeze manifest, payload, seals container, and seal
envelopes cannot inherit authoritative bytes through symbolic links or supported
reparse-point aliases. This does not change the accepted read-only alias behavior of an
outer parent-bundle or explicit thaw-record argument. Ordinary hard links remain regular
file byte-and-path semantics rather than an exclusive-inode claim.

`thawed_artifact_status` treats a `verifier-artifact-thaw-1` sidecar as unkeyed lineage
metadata. Without `parent_bundle`, it returns `NOT_ESTABLISHED` even when descendant bytes
agree with the sidecar's recorded identifier. `THAWED_CLEAN` or `THAWED_DIRTY` requires an
actual supplied parent that verifies as cleanly sealed and matches every recorded parent
coordinate. Optional expected artifact and key identifiers add external-anchor checks.
The result still does not authenticate the historical copy operation.

The supported evidence-bound construction exports are `BoundProposition`,
`EvidenceBindingError`, `EvidenceBounds`, `EvidenceStore`, `MechanismDecision`,
`MechanismOutcome`, `VerificationSession`, `WitnessBundle`, `ProvenanceHypergraph`,
`claim_binding_from_dict`, `establish_vstd4`, `assess_witness_corroboration`,
`establish_graph_level`, `graph_collection_binding_digest`, and `AssuranceLedger`.
The matching supported portable-record exports are
`build_evidence_bound_vstd4_receipt`, `recheck_evidence_bound_vstd4_receipt`,
`build_vstd5_receipt`, `recheck_vstd5_receipt`,
`build_evidence_bound_graph_level_record`,
`recheck_evidence_bound_graph_level_record`, and `recheck_assurance_log`.
Session evaluation snapshots ordinary canonical binding values before evidence
resolution and invokes mechanisms with a second copy. Single and compound results
bind only the private snapshot; a mechanism mutating its invocation copy yields
UNKNOWN. Capture is not atomic against concurrent caller writes, and arbitrary
Python copy hooks are not sandboxed. Failure to obtain a digestible snapshot raises
`EvidenceBindingError` before execution rather than inventing a bound result.

Compatibility `vstd4_depth` and `graph_level`-style candidate results do not become
conformance results merely because the evidence-bound APIs also exist.

In version 1.3.0, `compare_platform_run_receipts`, `PlatformComparisonResult`, and
`PlatformComparisonStatus` are supported additions for the bounded operating-system
comparison API.
They operate on existing VSTD-1 generic-run receipts and return a diagnostic object, not
a new receipt or conformance result. `PASS` requires complete declared platform coverage,
canonical integrity, equal non-platform bindings, and equal declared result projections;
`CONFLICTED`, `NOT_ESTABLISHED`, and `INVALID` remain distinct failure states.

Version 1.3.0 also adds supported `GeometryLoadError`,
`load_verification_geometry`, `ControlSurfaceContext`, `InteractionMode`, `SurfaceAnalysis`,
`SurfaceAnalysisError`, `SurfaceHole`, `SurfaceHoleKind`, and
`analyze_verification_surface` exports. The loader accepts a strict VSTD-2 JavaScript
Object Notation (JSON) file or an already parsed mapping, rejects unknown structure and
invalid geometry references, and returns only a valid typed `VerificationGeometry`.
Analysis is deterministic and limited to the supplied modeled surface. It neither infers
omitted obligations nor establishes real-world completeness, safety, authority,
conformance, or a native checker result.

`assess_witness_corroboration` accepts incomplete inputs so it can return a typed diagnostic
result. The supported `build_vstd5_receipt` boundary is stricter: it either raises or returns
an object satisfying the published receipt shape with all verdict-material evidence bytes.
`recheck_vstd5_receipt` applies the same zero-dependency structural gate before replay and
does not accept a schema-invalid assessment object as a portable receipt. It also compares
the complete carried VSTD-4 entry, requires the bundle `claim_id` to equal the admitted
VSTD-4 claim identifier, and mechanism-checks `corroboration_class`; schema-valid field
relabeling cannot retain an established replay result.

`ProvenanceHypergraph.from_dict` retains the frozen `verifier-data-1` two-namespace reader:
one identifier may occur once as an artifact and once as a transformation. Direct `add_*`
construction and default structural validation are stricter and globally disjoint. Such a
historical overlap remains readable but cannot enter evidence-bound Graph establishment or
assurance mechanisms. The compatibility candidate computation retains its historical scope
and remains `NOT_ESTABLISHED`.

### Interoperability facade: supported analysis and experimental planning

Supported/stable compatibility applies to the explicitly exported geometry loader,
surface-analysis subset, and platform comparator described above. It does not extend
to every name under `verifier.interoperability`:

| Surface | Compatibility boundary |
|---|---|
| Geometry loading, modeled-surface analysis, platform comparison | Supported top-level exports; the version and deprecation rules below apply, without broader correctness claims. |
| Component descriptors, kinds, catalog matching, stored packages, planning, execution-readiness preflight | Experimental; declarations and byte bindings do not supply execution, qualification, or authority. |
| Graph topology | Experimental direct submodule only; separate from supported analysis and from a general geometry satisfiability checker. |
| Selected digest execution and validation loops | Experimental direct `selected_execution` and `validation_loop` submodules only; one host-approved builtin byte-digest check, or a bounded ordered loop of them, with complete reassessment and replay. Not a receipt, portable authorization, general executor or runtime qualification. See [selected validation](../examples/selected_validation/README.md). |
| Explicit geometry constraints | Experimental direct `geometry_constraints` submodule only; caller-declared Boolean clauses over exact geometry coordinates, checked by the existing bounded solver and proof checker. No automatic premise or hole closure. See [explicit geometry constraints](../examples/geometry_constraints/README.md). |
| Composed untraversability | Experimental direct submodule only; observer-relative bounded knowledge closure, not universal confidentiality or runtime enforcement. |
| Computational environments | Experimental `verifier.environments` namespace; exact definitions, instances, run bindings, nonexecuting projections, and explicitly selected checks. See [environment foundations](ENVIRONMENTS.md) and the [migration boundary](ENVIRONMENT_CONTRACT.md). No supported top-level exports or receipt formats change. |
| Typed formation | Experimental direct `formation_*` submodules only; finite proof-step production, independent checking, evidence-bound session integration and retained-silo inspection. Catalog discovery is inert; census-byte retention is not silo completeness. No source self-status, completeness or agency upgrade. See [typed formation](../src/verifier/standard/TYPED_FORMATION.md). |
| Finite authority composition | Experimental direct `authority_composition` submodule and strict `network compose --require-finite-authority-composition` mode; exact selected finite asynchronous-interleaving correspondence, with separate coordinate, transition and authority results. Strict qualification additionally requires the legacy composition assessment and exact input binding; no runtime correspondence, source proof or six-axis status upgrade. See [finite authority composition](../src/verifier/standard/FINITE_AUTHORITY_COMPOSITION.md). |

`verifier.interoperability` contains both the supported analyzer names exported by
`verifier.__all__` and an experimental planning surface. Its complete characterized names
in version 1.3.0 are:

```text
AcyclicPropositionDependency
AuthorizationDecision
CandidateStatus
CandidateExecutionDeclaration
CatalogError
COMPONENT_PACKAGE_SCHEMA_VERSION
ComponentAvailability
ComponentKind
ComponentLifecycle
ComponentPackageError
ConflictWitnessKind
ControlSurfaceContext
ExecutionReadinessError
ExecutionReadinessReport
ExecutionReadinessStatus
GeometryConflictReport
GeometryConflictStatus
GeometryConflictWitness
ImplementationBinding
InteractionMode
InteroperabilityComponentDescriptor
InteroperabilityComponentRegistry
JudgmentObservation
NativeInputBinding
PackageArtifact
PackageDependency
PlannedEvidenceMapping
PostExecutionReassessmentContract
PrerequisiteResolution
SharedPropositionIdentity
StoredComponentPackage
SurfaceAnalysis
SurfaceAnalysisError
SurfaceHole
SurfaceHoleKind
SuppliedAuthorizationDecision
ValidationCandidate
ValidationPlan
analyze_geometry_conflicts
analyze_verification_surface
assess_execution_readiness
load_component_package
plan_validation
reference_component_registry
save_component_package
```

The redundant internal aliases `InteroperabilityCatalog` and
`generate_validation_plan` are intentionally not facade exports. Every name above except
the supported analysis subset also exported by top-level `verifier` remains experimental
and may change in a minor release. The planning names match exact declared capabilities
and produce registry-bound, nonexecuting plans. The conflict names compare only explicitly
identified propositions across exact geometries and emit structural witnesses; they do not
perform Boolean satisfiability analysis. The readiness names check caller-supplied native
input, planned evidence, prerequisite, authorization, and reassessment declarations but
never import or invoke a component. Catalog schema 1.1 serializes
`planning_surface_schema_ids` separately from native `accepted_schema_ids`; a planning
match is not a claim that the entry point accepts the planning document as native input. The
`vstd surface analyze --plan` command exposes that experimental plan without selecting or
executing a component. The facade provides no component executor, evidence collector,
post-execution reanalysis implementation, Boolean satisfiability geometry analyzer, or new
closure result.

The experimental stored-component format `verifier-component-package-1` adds
`PackageArtifact`, `ImplementationBinding`, `PackageDependency`, `StoredComponentPackage`,
`load_component_package` and `save_component_package` through
`verifier.interoperability.storage` and the interoperability facade. It retains exact
artifact bytes and an embedded catalog for inspection and nonexecuting planning. Loading
does not install, fetch or execute a component, authenticate publisher declarations,
resolve dependencies or grant conformance. Unknown formats are rejected; an incompatible
stored layout requires a distinct identifier and explicit migration. This experimental
format is not a receipt wire identifier. See [stored components](COMPONENT_PACKAGES.md).

**Certifier** names a certificate-issuance capability, orthogonal to the component's
algorithm role: a prover may certify, but a certifier need not prove. The current closed
`ComponentKind` vocabulary has no `CERTIFIER` member or kind filter. Preserve the word
in descriptor labels/native-object descriptions and specify its exact issuance relation,
mechanism, native inputs/outputs, and emitted certificate contract; see the
[serialization mapping](COMPONENT_PACKAGES.md#certifier-is-a-capability-not-a-kind-alias).
Matching does not inspect `kind` or infer capability from names or tags. This clarification
changes neither catalog 1.1 nor package-1 identifiers, adds no native certifier, and does
not authorize widening strict readers under their existing identifiers.

Direct imports from `verifier.core`, `verifier.data`, `verifier.hardware`, other
subpackages, or underscore-prefixed names are internal unless another published policy
explicitly names them. They may change in a minor release. That freedom does not override
frozen receipt identifiers, schemas, packaged specification bytes, command compatibility,
or historical refutation obligations.

The separately documented experimental `verifier.interoperability.graph_topology`
module provides `GraphTopologyContract`, `GraphTopologyReport`, `GraphTopologyStatus`,
`GraphTopologyError`, `graph_topology_binding_digest` and `analyze_graph_topology`.
These are not top-level or interoperability-facade exports. It checks explicitly encoded
finite Boolean equations and temporal offsets over an exact graph-bound interpretation;
it is not the general VSTD-2 geometry satisfiability analyzer excluded above. No new
numbered-profile result or receipt identifier is introduced. See [graph topology](GRAPH_TOPOLOGY.md).

The follow-on experimental `verifier.interoperability.selected_execution` module
provides `prepare_digest_validation`, `DigestHostPolicy`, `execute_selected_validation`,
`replay_selected_validation`, `SelectedExecutionError`, and `DIGEST_FACET_DESCRIPTION`.
These are direct-module imports, not top-level or interoperability-facade exports, and
are unreleased 2.0.0 source, not part of any tagged release. One explicitly host-approved builtin
byte-digest candidate can update its exact coordinate and reassess the complete supplied
geometry. Other holes remain unresolved. Registry-only records use experimental
`verifier-selected-digest-execution-1`; the distinct `verifier-selected-digest-execution-2` retains
a full component package and its package-bound plan, with selected primary-source bytes
matched to the host builtin. Unresolved selected package dependencies are rejected;
no package-supplied code is loaded. Neither record is a receipt, conformance result,
portable authorization, general executor, or runtime/dependency qualification.
No existing wire identifier or supported interface changes. See the runnable
[selected-validation example](../examples/selected_validation/README.md) for evidence,
replay, and host-boundary limits.

The separate follow-on experimental `verifier.interoperability.validation_loop` module
adds `DigestValidationTarget`, `DigestLoopBounds`, `DigestLoopPolicy`,
`prepare_digest_validation_loop`, `execute_digest_validation_loop`,
`replay_digest_validation_loop`, and `DigestLoopError` as direct imports only.
The distinct experimental formats are `verifier-digest-loop-request-1` and
`verifier-digest-loop-execution-1`. An exact host-approved ordered
target list drives bounded selected checks, with complete geometry analysis and planning
after each attempt. Declared per-step byte ceilings are reserved before admission; they
are not measured runtime usage. Explicit target, budget, negative, and uncertain stops
preserve unattempted targets and unresolved holes. Neither finishing the target list nor
replaying the chain grants whole-geometry closure, independent correctness, authorization
freshness, or a numbered-profile result. Single-step formats and both facades remain
unchanged. See the [bounded-loop example](../examples/selected_validation/README.md#bounded-multi-step-loop).

The separate follow-on `verifier.interoperability.geometry_constraints` module
provides experimental direct imports for `SignedProposition`, `GeometryClause`,
`GeometryConstraintBounds`, `prepare_geometry_constraints`,
`solve_geometry_constraints`, and `recheck_geometry_constraints`. It binds explicit
Boolean clauses to exact geometry snapshots and declared coordinate identities,
then checks an assignment or the existing refutation certificate. It is unreleased
2.0.0 source and not part of either facade. No judgment, seam, or missing
evidence is automatically translated into a Boolean premise; the caller's
interpretation and its checked consistency remain separate from geometry closure.
Rechecking takes a separately selected expected problem digest and does not invoke
the producer. An uncertain result remains uncertain, not a checked historical
search transcript. No new receipt identifier or normative schema is introduced.
See the [explicit-constraints example](../examples/geometry_constraints/README.md).

The experimental `verifier.interoperability.untraversable` module provides strict
contracts and reports for composed, observer-relative finite knowledge closure. It remains
outside the top-level and interoperability-facade exports. Native `MATCH`, `FAIL`,
`UNKNOWN` and `CONFLICTED` results stay bounded to the exact graph, observer, awareness
mode, observation interval, transcript, capabilities, declared inference rules, evidence
and resource coordinate. No result grants authorization, conformance, actor attribution,
runtime mediation or universal confidentiality. Its version 1.3.0 experimental contract
requires exact interface source-artifact coverage and exact graph-transformation incidence
for graph-backed knowledge rules; incompatible future layouts require a new experimental
schema identifier.

The experimental current-object modules `time_order` and `space_layout` add
separately versioned `TIME-2.1` retained microsecond ordering and `SPACE-3.1`
retained logical byte-layout checks. They preserve existing typed-facet and
legacy coordinate meanings through explicit semantic selection. Neither
authenticates physical clocks, establishes causality, allocates host resources
nor proves physical isolation. The added routes and specification bytes change
the installed mechanism descriptors; old selected policies require explicit
requalification against their intended source, not automatic digest rewriting.

The experimental `event_prerequisites` module registers current `EVENT-3.1`
for exact retained payload commitments and strictly ordered declared
prerequisites. It preserves explicit semantic selection and does not establish
historical occurrence, physical causality, operand truth or the whole tier.

TIME, SPACE and EVENT retained routes share internal plain-value selection
capture in `retained_selection`. Their native evaluators, exception classes,
wire versions, selected limits and verdict meanings remain distinct and
unchanged. This source refactor changes each installed mechanism digest;
selected policies bind the helper and must be requalified explicitly.

The experimental `verifier.consent.stages` module separates scope, configured
authority, validity/revocation, delegation and computational-verdict independence.
Its separate rechecker establishes exact stage reproduction, including reproduced
negative or unknown admission. Existing consent helpers and their wire meanings
remain unchanged. These [stage primitives](../src/verifier/standard/CONSENT_STAGES.md)
do not register namespace routes or establish complete required-holder coverage.

The experimental `verifier.domains.contracts.consent_checks` module registers
six distinct current consent predicates per admitted kind. It binds the exact
namespace record and collection, independently selected required holders and
public policies, action, time and retained evidence. Its
[versioned contract](../src/verifier/standard/CURRENT_CONSENT_CHECKS.md) preserves
admission separately from reproduction and the unchanged computational verdict.
These routes use `verifier-current-object-route-replay-2`; existing route records
retain version 1. An unavailable historical replay remains UNKNOWN. No holder-set
completeness, human consent, real-world authority or enforcement is established.

The experimental `object_governance` and `hardware_capacity` contracts add
current `OBJECT-8.1` signed namespace-admission decisions and `HARDWARE-2.1`
retained per-device capacity accounting. The former uses public replay version 2
to distinguish unavailable authentication from reproduced evidence; the latter
retains version 1. Existing route records and their wire meanings remain unchanged.
Neither establishes external authority, enforcement or whole-tier conformance.
Canonical certificate disclosure refuses removal of retained evidence for every
registered schema. Selected mechanism digests change with these source and
specification edits; policies must be requalified against their intended artifact.

The experimental polish assessment adds explicit `contract_version="2"` and
`--contract-version 2` selection for externally bounded larger inventories and
exact-byte shared evidence. [Its paired versioned inputs and outputs](../src/verifier/standard/POLISHED_ARTIFACTS.md)
do not replace version 1 defaults, limits or wire meanings. No positive polished
issuance is added. The aggregate installed mechanism digest binds the new helper;
historical assessments must be requalified against the intended implementation.

The experimental `verifier.domains.contracts.object_governance` module now
selects configured signed namespace admission at `<kind>-8.1` for all 26 admitted
kinds. `registration()` keeps its default OBJECT descriptor and historical wire
identifiers; explicit kind selection binds the actual record kind and proposition.
Exact canonical-value comparison preserves numeric types in replayed selection
and result fields. Signed admission and fresh revocation evidence do not establish
distinct humans, legal authority, actual enforcement or complete governance tiers.

The experimental `verifier.domains.contracts.subject_security` module adds
`<kind>-9.1`, except `RECEIPT-9.3`, for exact retained subject association to one
externally selected finite receipt-chain entry. Existing `RECEIPT-9.1` chain and
`RECEIPT-9.2` issuer-key signature meanings are unchanged. Its
[typed-subject contract](../src/verifier/standard/CURRENT_SUBJECT_SECURITY.md)
does not authenticate an issuer, prove execution or establish complete security.

The experimental `verifier.runtime.polish_requirements` module exposes
`assess_polish_inventory` and `vstd polish coverage` for a separately pinned finite
numbered inventory. The [coverage contract](../src/verifier/standard/POLISH_REQUIREMENTS.md)
requires an independently supplied expected inventory digest and binds the selected
subjects, objectives, installed mechanisms and native evidence. Selected coverage
may be PASS while aggregate status remains UNKNOWN; empty required slots remain
explicit gaps. Inventory authority and exhaustive applicability remain
NOT_ESTABLISHED, and polished issuance is not supported. These direct modules add
no top-level supported exports. Installed source/specification changes require
explicit policy and evidence requalification; historical meanings are preserved.

## Version and deprecation rules

- Patch releases preserve supported signatures and behavior while correcting defects.
- Minor releases may add supported names and compatible parameters.
- Removing or incompatibly changing a supported name requires the next major release.
- Before removal, the name remains usable through the current major series, emits
  `DeprecationWarning`, names a supported replacement, and appears in release notes.
- `_API_DEPRECATIONS` in `verifier.__init__` is the testable warning registry. A warning
  cannot change the returned object, verdict, or failure semantics.

Semantic Versioning governs only this declared software compatibility surface. It does not
increase assurance or establish an external standard.

## Separate compatibility surfaces

- `vstd` is the canonical command-line interface (CLI). `verifier` remains a compatibility
  alias where unambiguous; `verifiable` is permanent because published refutation steps
  bind it.
- Serialized receipt identifiers and released receipt bytes follow
  [`WIRE_IDENTIFIERS.md`](../src/verifier/standard/WIRE_IDENTIFIERS.md), not this Python policy.
- Published JavaScript Object Notation (JSON) Schemas change only under their declared
  profile and compatibility rules.
- Artifact-control formats follow `standard/ARTIFACT_CONTROL.md`. They are not receipts;
  an incompatible format change requires a new artifact-control mechanism identifier.
- `verifier.experimental_workflow` is experimental and outside the supported Python API;
  its outputs still cannot strengthen a VSTD verdict by naming or placement.

# Python application programming interface (API) stability

> **Term:** Verifier Standard (VSTD).

This policy applies beginning with the first release that contains it. It does not
retroactively change frozen receipts or earlier release bytes.

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

`thawed_artifact_status` treats a `VSTD-ARTIFACT-THAW-1` sidecar as unkeyed lineage
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
Compatibility `vstd4_depth` and `graph_level`-style candidate results do not become
conformance results merely because the evidence-bound APIs also exist.

At the current unreleased source coordinate, `compare_platform_run_receipts`,
`PlatformComparisonResult`, and `PlatformComparisonStatus` are supported additions for
the next minor release's bounded operating-system comparison API.
They operate on existing VSTD-1 generic-run receipts and return a diagnostic object, not
a new receipt or conformance result. `PASS` requires complete declared platform coverage,
canonical integrity, equal non-platform bindings, and equal declared result projections;
`CONFLICTED`, `NOT_ESTABLISHED`, and `INVALID` remain distinct failure states.

The next minor release also adds supported `GeometryLoadError`,
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

`ProvenanceHypergraph.from_dict` retains the frozen `VSTD-DATA-0.1` two-namespace reader:
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

`verifier.interoperability` contains both the supported analyzer names exported by
`verifier.__all__` and an experimental planning surface. Its complete characterized names
at the current unreleased source coordinate are:

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

The experimental stored-component format `VSTD-COMPONENT-PACKAGE-1` adds
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
  [`WIRE_IDENTIFIERS.md`](../standard/WIRE_IDENTIFIERS.md), not this Python policy.
- Published JavaScript Object Notation (JSON) Schemas change only under their declared
  profile and compatibility rules.
- Artifact-control formats follow `standard/ARTIFACT_CONTROL.md`. They are not receipts;
  an incompatible format change requires a new artifact-control mechanism identifier.
- `verifier.experimental_workflow` is experimental and outside the supported Python API;
  its outputs still cannot strengthen a VSTD verdict by naming or placement.

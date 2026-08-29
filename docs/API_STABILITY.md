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

Direct imports from `verifier.core`, `verifier.data`, `verifier.hardware`, other
subpackages, or underscore-prefixed names are internal unless another published policy
explicitly names them. They may change in a minor release. That freedom does not override
frozen receipt identifiers, schemas, packaged specification bytes, command compatibility,
or historical refutation obligations.

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

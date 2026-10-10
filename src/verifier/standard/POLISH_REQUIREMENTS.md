# Pinned requirements coverage

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8). Counts are
dimensionless. Transport sizes count encoded bytes. This document defines the
`verifier-polish-requirements-inventory-1` transport and
`verifier-polish-requirements-assessment-1` assessment.

## Proposition and boundary

The gate compares a finite, separately selected numbered requirements inventory
with a submitted polish request, then calls the actual installed native polish
assessment. It rejects omissions and substitutions relative to that selected
inventory. It does not determine whether its author selected every obligation,
whether the author has authority, or whether declarations of inapplicability are
true. There is no authenticated exhaustive-completeness mechanism in this version.

`declared_coverage: PASS` means every numbered objective in this selected inventory
has matching subject, semantic version, tier, mechanism, proposition, request,
policy and exact certificate-byte bindings, and every selected native replay
returned PASS. It does not mean every objective for a tier has been enumerated.
Empty REQUIRED slots remain explicit `open_required_slots`; their presence does
not enlarge or discharge the finite selected proposition set. A zero-objective
inventory has UNKNOWN coverage. Unregistered objectives have UNKNOWN coverage.

Every report MUST retain `polished: false`,
`objective_inventory_closure: NOT_ESTABLISHED`, and
`inventory_authentication: NOT_ESTABLISHED`. Its aggregate status MUST be FAIL
when the inventory gate or native assessment refutes a binding or proposition,
and UNKNOWN otherwise. Aggregate PASS is unsupported. Native retained private
replay does not establish public checkability. A digest pins bytes; it does not
authenticate their author, policy authority, completeness or applicability.

## External selection and public function

The Python function is:

```python
assess_polish_inventory(bundle_bytes: bytes, *, request_bytes: bytes,
    inventory_bytes: bytes, expected_inventory_digest: str,
    contract_version: str = "1") -> dict
```

The caller MUST supply the expected SHA-256 inventory digest independently of
the submitted inventory. An interface MUST NOT silently calculate the expected
digest from the file under assessment. The gate checks equality to that supplied
digest but cannot prove how its caller selected it. Callers needing trusted
selection must bind the expected digest in their own independently authenticated
policy. This version provides no callback that can assert such authentication.

The proposed command-line interface is:

```text
vstd polish coverage BUNDLE --request REQUEST --requirements INVENTORY
  --requirements-digest sha256:... --contract-version 1|2 --json
```

This command assesses existing artifacts. It neither issues certificates nor
changes inventories or their evidence. Missing input files produce UNKNOWN with
the same assessment schema and unestablished closure, never a positive result.

## Exact inventory structure

All records have exactly the fields specified here. Duplicate JSON keys, unknown
fields, duplicate subjects, duplicate subject-tier rows and duplicate numbered
objectives within a subject-tier row are invalid. JSON parsing follows the same
strict rules as native polish.

The inventory root fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `verifier-polish-requirements-inventory-1` |
| `semantic_version` | Exact installed current-object semantic version, shared by every selected objective |
| `catalog_digest` | SHA-256 of canonical installed route-catalog rows sorted by semantic version and objective |
| `root_id` | Exact selected polish root identifier |
| `collection_digest` | Exact selected collection digest |
| `subjects` | Exact represented object set |
| `requirements` | Exactly nine rows per represented subject, one per tier 1 through 9 |

A subject has `object_id`, `object_kind`, and `object_digest`. Kind and digest
MUST match the actual namespace object reconstructed from the submitted bundle.
The inventory cannot substitute one kind's registered proposition for another.
Generic OBJECT routes are permitted only where the installed registry permits
that represented kind; a lexical OBJECT coordinate alone is insufficient.

A requirement row has `object_id`, integer `tier`, `applicability`,
`rationale_digest`, and `objectives`. Applicability is exactly REQUIRED,
NOT_APPLICABLE or UNKNOWN. The latter two values require an empty objective list.
The submitted request MUST contain the same rows and applicability, and its
rationale MUST have the selected canonical-value digest. Boolean tiers are
invalid. Required rows with no numbered objectives are retained as explicit gaps.

Each selected objective has these exact fields:

```text
coordinate mechanism_id mechanism_digest proposition_digest
request_digest policy_digest certificate_digest
```

Its coordinate MUST belong to its row's tier and represented kind, according to
the actual installed route. The request's objective set MUST equal the selected
set for every subject-tier row; omissions and extra objectives are both refused.
The request semantic version MUST equal the inventory version. Mechanism identity,
mechanism digest and proposition digest MUST match the installed registered
native checker. Metadata comes from that registered replay function's installed
module; submitted import paths and callbacks are never used.
The installed `subject_security` mechanism receives the exact represented kind
when computing its digest. Other supported installed mechanisms have no-argument
digest functions. Unsupported installed binding signatures produce explicit
`mechanism_binding_gaps` and UNKNOWN coverage, not fabricated metadata.

`rationale_digest`, `request_digest`, and `policy_digest` hash the corresponding
canonical JSON value using Verifier's `canonical_bytes`. `certificate_digest`
hashes the exact retained certificate bytes, including any encoding differences.
The inventory itself is pinned by its exact transport bytes. Its digest cannot
be replaced by an equivalent reserialization without fresh external selection.
The gate does not duplicate certificate semantics: existing polish checks actual
subject and dependency bindings, certificate bytes and native replay.

## Bounds and assessment

`MAX_INVENTORY_BYTES` is 4,194,304 bytes (4 mebibytes) for this inventory transport,
independent of the selected polish contract version. Existing version 1 and
version 2 bundle, request, object, objective and native replay bounds remain
unchanged. Native version 2 selected-capacity exhaustion retains UNKNOWN and its
named exhausted resource. After the external inventory pin is checked, version 2
request and bundle byte capacities MUST be charged before hashing or decoding the
bundle. This wrapper admission order is stronger than the native checker's byte
comparison order; it is not a claim that native assessment already avoids hashing
an over-capacity bundle. Object,
requirement and objective capacities MUST be charged before namespace reconstruction.
The requirement and objective charges use the larger count across the externally
selected inventory and submitted request; mismatched sets still fail comparison
when admitted. Preflight exhaustion returns UNKNOWN with `RESOURCE_LIMIT_EXCEEDED`,
the `exhausted_resource`, and `resource_stage: REQUIREMENTS_PREFLIGHT`. Native replay
has not run, so this report MUST NOT contain a fabricated `native_assessment`.
Inventory comparison still precedes every native certificate replay.
This wrapper is additionally bounded by its fixed
inventory byte cap and installed object/objective ceilings; it is not a new
native capacity contract. Its report contains the native report plus bounded
comparison metadata, so the native output reservation is not a reservation for
the complete wrapper output.

The wrapper first validates strict transport and pin bindings, then compares the
selected inventories, then invokes `assess_polish` with the original bundle and
request bytes and the explicitly selected contract version. It MUST NOT mint a
PASS from carried status fields, hashes alone, a signature alone or successful
schema validation. Unknown catalog entries remain explicit unregistered gaps.
Missing retained certificate evidence remains UNKNOWN through native replay.

Report fields include the assessment schema, aggregate `status`,
`declared_coverage`, the three permanent closure boundaries, a claim boundary,
the gate `mechanism_digest`, and `assessment_digest`. Successful comparison also
retains exact input digests, `selected_objective_count`, `open_required_slots`,
`unregistered_objectives`, and the complete bounded `native_assessment`.
Installed mechanism binding gaps are separately retained as
`mechanism_binding_gaps`.
`assessment_digest` hashes the canonical report before that field is added.
Diagnostics are fixed reasons; private witness content and exception text MUST
NOT be copied into diagnostics.

The gate mechanism digest binds its implementation, this packaged normative
document, and the delegated native polish mechanism digest. The inventory catalog
digest pins registered propositions; it is neither a closure certificate nor a
substitute for selected per-objective mechanism bindings. Changes in those
dependencies invalidate previous binding evidence and require reassessment.

## Exact core self-polish replay

The installed `CORE-SELF-POLISH-1` selector is a separate, narrower production
path. It is admitted only for a represented `VERIFIER` and binds the fixed
`verifier-core-application-full-gates-1` proposition published by the core
application release composer. It does not add that proposition to the current-
object numbered-inventory denominator.

The path has four exact transports:

- `verifier-core-self-polish-source-manifest-2` embeds the shared candidate-source
  census. It enumerates every Git-tracked working byte and every bounded,
  nonignored untracked ordinary file by repository-relative path, provenance,
  Git mode or `UNTRACKED_REGULAR`, byte count, and SHA-256 digest. It also binds
  HEAD, the HEAD tree, the exact Git index digest, raw porcelain-v2 status digest,
  and the ignored-path exclusion taxonomy. Ignored discoverable source/control
  files, symlinks, reparse points, special files, path escapes, capacity overflow,
  or pre/post drift are refused. Ignored cache/build paths are path-bound but their
  bytes remain explicitly unverified.
- `verifier-core-self-polish-selection-1` binds the fixed coordinate, application
  identity, source manifest, selected instruction rows, exact compiler and native
  inputs, installed mechanism digests, and the structural denominator.
- `verifier-core-self-polish-receipt-1` is issued only after current source bytes
  reproduce the manifest, the installed application compiler reproduces a closed
  `retained-namespace-structure-1` manifest, and both actual selected tier-1
  native certificates replay PASS.
- `verifier-core-self-polish-replay-1` re-runs those checks and requires byte-
  identical assessment and receipt digests.

The Python entry points are:

```python
prepare_core_self_polish_inputs(root, *, application_id=None,
    instruction_paths=("AGENTS.md", "TIME.md"), contract_version="2")

assess_core_self_polish(selection_bytes, *, expected_selection_digest,
    source_manifest_bytes, source_root, source_scope_bytes, collection_bytes,
    application_selection_bytes, compiler_policy_bytes, compiler_manifest_bytes,
    polish_bundle_bytes, polish_request_bytes, polish_inventory_bytes,
    expected_polish_inventory_digest, contract_version="2", cancelled=False)

recheck_core_self_polish_receipt(assessment_bytes, *,
    expected_assessment_digest, expected_receipt_digest, **assessment_inputs)
```

Preparation grants no credit. The caller must retain and independently pass the
exact selection digest into assessment. A receipt binds 27 installed structural
definitions and 52 per-kind memberships; for its single concrete VERIFIER root,
exactly two obligations are instantiated: `OBJECT-1.1` and `VERIFIER-1.1`.
The application identity is derived from the exact selected `[project]` name and
version in `pyproject.toml`, Git HEAD, and the complete working-source manifest
digest. An optional caller-supplied `application_id` is an expected value only;
it is refused if it differs from that derived identity.
The source manifest must contain byte-identical copies of the installed
application-compiler source bindings plus this selector/orchestrator, its
specification, the native polish dispatcher and capacity implementation, the
candidate-source selector, current-object router, and the fixed core application
coordinate source. The
selection and root object bind that source-set digest. Consequently, a caller
cannot assess an unrelated Git tree while executing the checker from another
installation.
The compiler's full-application status and the native inventory assessment's
aggregate status remain UNKNOWN by design; the self-polish gate PASS is only the
conjunction of exact source replay, selected structural compiler closure, and the
two selected native PASS outcomes.

Every receipt therefore retains `polished: false`,
`full_application_status: UNKNOWN`, `selection_authority: NOT_ESTABLISHED`,
`public_checkability: NOT_ESTABLISHED`, `human_acceptance: NOT_ESTABLISHED`, and
`release_authorized: false`. Those boundaries do not weaken the fixed selected
self-replay proposition, but they prohibit recasting this one gate as full
application completion or release qualification. Source, instruction, selection,
input, rule, compiler, native route, or mechanism changes invalidate the receipt
and require a fresh independently selected assessment.

## Governance and security are bounded mechanisms

OBJECT-8.1 can establish its registered finite namespace-admission quorum
proposition under a selected policy. It excludes registry completeness. RECEIPT-9.1
can establish its finite chain proposition; RECEIPT-9.2 additionally checks its
registered issuer-signature binding. Neither establishes complete history or
exhaustive object requirements. Such certificates MUST NOT bypass this gate's
missing-objective, wrong-kind, wrong-version, duplicate or evidence-binding checks.
Their PASS results may cover exactly their selected numbered propositions; they
cannot turn this assessment's unestablished closure into authenticated completeness.

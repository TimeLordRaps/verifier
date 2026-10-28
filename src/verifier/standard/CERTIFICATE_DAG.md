# Exact certificate dependency closure

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI).

This additive application-profile contract checks exact claims and their
prerequisites. Nodes are certificates/claims. Edges may connect claims within one
meta-tier, across meta-tiers, or across typed operand objects. Tier numbers are
a projection; they do not generate dependency edges or impose universal execution
order. No complete approved profile for any of the 26 object kinds is supplied.
A finite selected claim closure does not establish polished-artifact issuance.

## Exact externally selected inputs

All records are canonical JSON bytes with no duplicate or additional fields.
Consumer selection is passed separately to the validator; carried policy,
approval, signatures and outcomes do not select the consumer's requirements.

`verifier-certificate-dag-profile-1` contains exactly `schema_version`,
`profile_id`, `profile_version`, `object_kind`, and `obligations`.
Each obligation contains `claim_id`, `semantic_version`, `objective`,
`proposition_digest`, `scope`, `assumptions`, and `dependencies`.
Assumptions are exact SHA-256 commitments to the selected assumptions; their
presence does not prove their truth. Objective, proposition and scope must match
an installed native registration. Unsupported physical or statistical scopes
remain UNKNOWN. No generic PASS, profile label or graph shape supplies a residual
metric, units, tolerance, sample contract or statistical checking mechanism.

Each dependency contains `claim_id`, `operand_role`, `object_kind`, and
`profile_digest`. A local edge has null role and profile digest, and the same
object kind. A cross-object edge selects a named role in the exact namespace
record, the expected target kind and an exact target profile digest. Every target
of that role requires the named target claim; matching tier labels cannot replace
it. Profiles are pinned by SHA-256 over their complete canonical bytes.

`verifier-certificate-dag-bundle-1` contains exactly `schema_version`,
`profiles`, `objects`, `nodes`, and `edges`. Objects are exact namespace
records. Each node contains `node_id`, `object_id`, `claim_id`,
`certificate_path`, `certificate_digest`, `request`, `checker_policy`,
`contract_version`, `artifact_bindings`, and `facet_bindings`.
Node identifiers are globally unique; each (object identifier, claim identifier) pair
is unique and resolves one profile obligation. Exact externally selected request,
checker-policy, certificate, proposition, facet and profile bindings define its claim
identity; a same-label replacement cannot supply a prerequisite.
Native requests and policies are retained in full under external selection,
including installed mechanism identity/digest and exact evidence commitments.
Artifact bindings contain snapshot-relative `path` and exact byte `digest`.
Facet bindings contain `payload_digest` and `operands_digest`, both
recomputed from the exact selected record. Each edge contains `node_id`,
`prerequisite_id`, and `operand_role`.

`verifier-certificate-dag-policy-1` contains exactly `schema_version`,
`approved_profiles`, `required_objects`, `required_roots`, `nodes`,
and `artifact_files_digest`. Only independently selected profile digests are
approved. Required objects contain `object_id`, `object_kind`,
`record_digest`, and `profile_digest`; all supplied objects must be selected.
The complete exact node list must match the consumer's node list. Roots define
the selected closure; extra unconnected nodes are refused. The artifact file
digest commits the complete sorted file inventory, names, sizes and exact bytes,
so omitted or additional files change the binding. For publication, the host's configured policy is authoritative. A producer's client
selection cannot replace it. Consumer/host policy selection,
approval provenance and obligation completeness remain external responsibilities.

## Exact selected GRAPH child correlation

For a selected local GRAPH-4.1 or GRAPH-9.2 prerequisite edge to GRAPH-3.1,
the edge target must be the parent's exact selected native child. GRAPH-4.1
matches canonical request and checker-policy digests and raw certificate digest.
GRAPH-9.2 matches the complete nested child request and policy and raw certificate
digest. A different child that independently replays PASS for the same object
cannot discharge that edge. Such a contradictory selection gives qualified FAIL
while the direct native replay is reported separately. Both parents may share the
same exact child. This check creates no new prerequisite for profiles that do not
select such an edge; missing required child evidence still prevents completion.

## Replay and outcome semantics

`assess_certificate_dependencies(bundle_bytes, expected_policy_bytes=...,
artifact_files=...)` executes only installed native callbacks. No carried code,
command, locator, credential or approval is executed. The native subject kind,
identifier, record and collection commitments must match the selected objects.
A native request carrying an explicit object kind must match it exactly. Requests
whose native schema omits that field, including HYPER-4.1, bind kind through the
installed fixed-kind route instead. No field is inserted into existing native
requests; generic representation routes still require their explicit kind field.

The `verifier-certificate-dag-assessment-1` reports direct native observations
separately from dependency-qualified results. A claim is qualified PASS only
when its direct replay is reproduced PASS, its profile is independently approved,
and every exact prerequisite is qualified PASS. Missing or UNKNOWN prerequisites
leave it UNKNOWN; a higher-tier PASS cannot replace them. Refuted claims or
prerequisites produce FAIL. Duplicate nodes, dangling/cyclic edges, altered
bindings and edges differing from the selected profile are refused as FAIL.
Missing profiles, approval, supported mechanisms or retained native evidence
block closure as UNKNOWN. Typed inapplicability waivers are not supported and
cannot discharge any obligation.

Bounds are 8 mebibytes per dependency record, 512 objects/profiles/claims,
4,096 edges, nesting depth 48, 100,000 parsed values, 4,096-bit integers,
1,024 artifact files and 64 mebibytes of artifact bytes and cumulative native replay bytes. Profile dependency
work and expanded edges are also limited to 4,096. One mebibyte is
1,048,576 bytes. Resource exhaustion returns UNKNOWN; malformed bounded inputs
return FAIL. Native mechanisms retain their own independently selected limits.

All source, specification and optional dependency versions are additionally
bound by the gates implementation digest. Changing upstream artifact/facet,
profile version, selected assumption, request, policy, evidence or installed
checker bytes invalidates replay of old clearance.

## Clearance and local preparation

Existing `verifier-gates-clearance-1` remains a local technical report. It cannot
prepare publication. `vstd gates --dependency-bundle ... --dependency-policy ...`
produces `verifier-gates-clearance-2`, retaining the exact bundle text, independent
policy digest and reproduced dependency assessment alongside the original gates.
Consumers must pass their own dependency policy to recheck it.

Current `verifier-gates-publication-preparation-3` requires version 2 clearance,
independently selected dependency policy, and independent facet inventory,
specification and derivation policy. The preparer reruns native gates and exact
claim dependencies, then assesses the facet-derived obligation denominator.
Missing or incomplete facet/applicability coverage refuses local preparation as
UNKNOWN; a demonstrated binding/native violation remains FAIL. The exact local
assessment is retained in the rejection, and no payload is written. See
[FACET_OBLIGATION_DERIVATION.md](FACET_OBLIGATION_DERIVATION.md).

The earlier version 2 preparation contract checked only selected claim dependency
closure. Its frozen historical fixtures do not establish the newly required facet
denominator or current preparation acceptance. Changing installed bytes invalidates
old clearance; consumers must select the current implementation independently.

There are zero complete approved production profiles. Object profile and whole-tier
conformance remain NOT_ESTABLISHED. Authentication, moderation, rights, authority,
human acceptance and production promotion remain separate requirements. No shipped
profile is silently approved; the preparer performs no transport.

Native callback input/checker unavailability (including import and operating-system
I/O failures) yields direct UNKNOWN with CHECKER_UNAVAILABLE, retaining node and
blocked-descendant diagnostics. A native semantic refusal yields direct FAIL with
NATIVE_REPLAY_REJECTED. An unavailable checker is not a refutation.

Cumulative native replay exhaustion preserves all previously observed native
outcomes and exact node provenance. Further native callbacks are fenced as UNKNOWN
with DEPENDENCY_RESOURCE_BOUND_EXHAUSTED; known FAIL and failed prerequisites
remain FAIL. Exhaustion before any observation still establishes no verdict.

The opt-in `assess_certificate_dependencies_preserving_faults` entry point emits
`verifier-certificate-dag-assessment-2`. Input selection and native propositions
remain unchanged. It retains completed node observations across later cancellation,
capacity exhaustion, unavailable imports or operating-system failures; an observed
FAIL remains FAIL. An interrupted closure cannot become PASS. Version 1 entry points
and existing receipt dispatch remain unchanged. The separate
[ten-tier progression](CURRENT_TEN_TIER_PROGRESSION.md) uses this version 2 report;
its rank constraints do not change the version 1 dependency contract.

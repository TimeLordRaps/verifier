# Facet-first native obligation derivation

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256).

This additive sidecar separates retained facets, selected abstract properties,
derived native obligations, and certificate evidence. Certificate nodes cannot
define the requirement denominator. One native certificate can support multiple
facets, one facet can require multiple predicates, and selected interactions can
add requirements. Tier numbers group results; they do not create dependencies.

This first implementation supplies a finite namespace-field census and 41 authored,
source-pinned mappings to existing native predicates. It does not supply an
authoritative application facet inventory, complete interaction inventory, or
complete higher-tier applicability profile for any object kind. Their denominators
remain unknown, and local preparation remains blocked. A finite derivation PASS or
native replay PASS does not establish whole-tier conformance, scientific validity,
model correctness, authenticated identity, or overall safety.

## Separate scopes and exact inputs

`namespace_facet_inventory(objects)` accepts exact `NamespaceObject` records and
returns `verifier-namespace-facet-inventory-1`. The exact fields are
`schema_version`, `inventory_version` ("1"), `scope`
("exact_finite_canonical_namespace_fields"), `facets`,
`domain_facet_completeness`, and `interaction_inventory_completeness`.
Both completeness fields must be UNKNOWN. Each facet contains `facet_id`,
`object_id`, `object_kind`, `record_digest`, `path`, and `value_digest`.
The census includes containers, nested payload fields, list positions, object
identity, kind, and every declared operand role and target. Facet identity commits
the object identifier and exact path; record and value digests separately commit
the selected revision. Paths distinguish string keys from integer list positions.

A source-declaration inventory, application property inventory, and this namespace
field inventory have different meanings. Neither schema renaming nor truncation
converts one into another. A source-to-native adapter must retain exact source
revision, source facet identity and scope, target field/record commitment, versioned
mapping rule, units, information loss, and unsupported meaning. That semantic mapping
and its independently selected authority are not supplied by this sidecar.

`verifier-facet-obligation-specification-1` contains exactly `schema_version`,
`specification_id`, `specification_version`, `facets`, and `interactions`.
Each facet entry contains `facet_id` and `properties`; each interaction contains
`interaction_id`, `facet_ids` (at least two distinct retained facets), and
`properties`. Property identifiers select installed authored rules. An empty
property list, omitted facet, unsupported scientific property, unsupported cross-object
interaction, or ambiguous rule produces a localized UNKNOWN diagnostic. There is no
author N/A waiver or interpretation by a language model.

`verifier-facet-derivation-policy-1` contains exactly `schema_version`,
`inventory_digest`, `specification_digest`, `rule_set_digest`, and
`approved_rule_digests`. These are independently selected complete-byte commitments.
The installed rule-set digest must match the selected version and source bytes.
Admitting a finite authored rule does not approve an application object profile.

`native_structural_facet_mapping(objects)` returns the additive typed mapping
`verifier-native-structural-facet-mapping-1`. It retains the four semantic facets
specified by CURRENT_OBJECT_FACETS.md: identifier, admitted kind, canonical payload,
and named ordered operand map. It separately retains declared typed composition
from CURRENT_TYPED_FACETS.md. These five known specification facets per object map
many-to-many to exact namespace fields and the existing generic/typed predicates;
a nested field does not become an invented domain facet. Each mapping row carries
stable semantic facet identity, exact record revision, native outputs, source
specification/checker digests, and rule identity. Its field projection can seed a
candidate finite native specification, requiring separate external rule admission.
Source-declaration mapping, interaction applicability, and full application
completeness remain UNKNOWN. HYPER composition does not automatically require an
invented HYPER-4.1 child-certificate edge.

## Existing native rules and prerequisite bindings

`installed_facet_derivation_rules()` returns
`verifier-native-facet-derivation-rules-1`, rule-set version "1". Every rule records
its identifier, version, digest, abstract property, applicable native kind, exact
native outputs, source specification and checker digests, prerequisites, admissible
certificate schema, completion criteria, and units. Counts are dimensionless,
encoded lengths use bytes, and application values keep their opaque native meaning.
No physical units, tolerance, statistical sample contract, or scientific semantics
are inferred from an opaque value.

The 33 base structural and SIM rules cover:

- `canonical_namespace_record`: generic OBJECT-1.1 representation;
- `declared_operand_structure`: the existing typed 1.1 predicate for each of
  the 26 kinds, with OBJECT-1.2 for OBJECT;
- HYPER `finite_declared_operand_cone`: existing HYPER-4.1, whose composition
  evidence is consumed inline;
- SIM `selected_transition_replay`: SIM-2.1;
- SIM `selected_action_response`: SIM-2.1 and SIM-2.2;
- SIM `selected_internal_state`: SIM-2.1 and SIM-2.3;
- SIM `selected_perspective`: SIM-2.1, SIM-2.3, and SIM-2.5;
- SIM `selected_shard_coverage`: SIM-2.1 and SIM-4.1.

Three additional TOKEN mappings are specified by CURRENT_TOKEN_FACET_MAPPING.md:

- `selected_capability_token_tenure`: TOKEN-2.1;
- `selected_capability_token_windows`: TOKEN-3.1;
- `selected_capability_token_parent_grants`: TOKEN-4.1.

The installed inventory therefore contains 41 authored mappings: 33 base rules,
three TOKEN rules, and five selected DATA and GRAPH rules. The TOKEN rules require the exact retained scope,
declared microsecond unit, field anchors, and inline namespace-composition and
token-inventory replay specified by that mapping. This finite rule census does
not establish application facet completeness or exhaustive objective applicability.

The existing child-certificate rules are SIM-2.2 requiring SIM-2.1, SIM-2.3
requiring SIM-2.1, SIM-2.5 requiring SIM-2.3, and SIM-4.1 requiring SIM-2.1,
with the same exact object and selected child evidence. No new HYPER-1.1 to
HYPER-4.1 certificate dependency is invented. Native request schemas, coordinate
meanings, evidence stores, and bound propositions remain authoritative.

## Selected DATA and GRAPH rules

Five additional authored property identifiers select existing finite predicates:

- `selected_retained_data_inventory`: DATA-1.2; exact `payload.shards` origin.
- `selected_retained_data_lineage`: DATA-2.1; exact `payload.transforms` origin.
- `selected_retained_graph_statics`: GRAPH-3.1.
- `selected_retained_graph_closure`: GRAPH-3.1 and GRAPH-4.1.
- `selected_direct_operand_content_lineage`: GRAPH-3.1 and GRAPH-9.2.

GRAPH rules require `retained_directed_graph` scope, direct members and selected
node/edge commitments, originating at `payload.edges_digest`. DATA lineage
replays inventory inline; it creates no external DATA-2.1 to DATA-1.2 edge.
Payload transformation lineage does not create DATA namespace operands.
GRAPH-4.1 checks reachability of selected edges, separately from DATA integrity.
GRAPH-9.2 checks only the direct member operand relation and exact endpoint-record
contents. Primitive DATA members with no operands can have an empty relation
while their payload transformation sequence remains nonempty.

The two GRAPH parents require the exact selected GRAPH-3.1 child. Byte-identical
GRAPH-3.1 output metadata deduplicates one obligation while retaining all three
rule origins. This does not equate distinct request, policy or certificate
instances: each selected dependency edge must correlate with its parent's actual
child selections. Authored parent prerequisite correlation also applies when
a separately selected partial dependency profile omits the edge; that profile
cannot erase the independently derived requirement. Standalone partial dependency
replay remains separate. All rule and native dependency source pins require fresh
independent policy selection when their bytes change. Missing anchors, rules,
approval or evidence stay UNKNOWN; no complete applicability profile is added.

## Derivation, retrofit, and deterministic diagnostics

`derive_facet_obligations(inventory_bytes, specification_bytes,
expected_policy_bytes=...)` returns
`verifier-derived-facet-obligations-1` independently of submitted certificates.
Identical exact native obligations are deduplicated while retaining all
facet/interaction origins, selected rules, and source versions. The manifest
contains obligation edges, a nine-cell classification ledger per retained facet,
diagnostics, explicit denominator fields, and a manifest digest.

A cell with a selected native obligation is REQUIRED_FOR_SELECTED_NATIVE_PROPERTY.
Other cells are UNKNOWN applicability. Those nine cells are bookkeeping, not a
claim that every tier universally applies to every facet. The finite field and
derived-obligation counts are known; `complete_domain_facets` and
`complete_applicable_obligations` are null. No coverage percentage is reported.
A successful finite rule derivation is `derivation_status=PASS`; aggregate
qualification still remains UNKNOWN.

`assess_facet_completeness(inventory_bytes, specification_bytes,
expected_policy_bytes=..., bundle_bytes=...,
expected_dependency_policy_bytes=..., artifact_files=...)` recomputes the actual
namespace census before matching evidence. Omitted fields and unselected declared
operand targets remain explicit gaps even when a separately selected partial
certificate graph passes. Invented or substituted field bindings produce FAIL.
Every derived predicate requires exact selected native evidence and its real
prerequisites. Existing certificates can be assessed for retrofits without changing
their request bytes or adding unsupported fields.

Diagnostics include component identity, PASS/FAIL/UNKNOWN meaning, blocked
descendants, and required resolution inputs. Missing evidence and unavailable
checker inputs remain UNKNOWN; native semantic refusal or demonstrated binding
violation remains FAIL, including when later census/coverage work exhausts its
resource bound. Malformed supplied request types return a bounded FAIL diagnostic
instead of escaping as an exception. Native node outcomes and obligation outcomes are retained
separately. Diagnostics do not manufacture a scientific contradiction: unsupported
scientific interpretation stays UNKNOWN.

The existing finite-completeness, source-grounding, formation-wire, and native
grounded-certification mechanisms retain their meanings. Their authority receipts
are not yet integrated into a complete production facet/applicability profile here.
Compiled rules cite their actual existing specification/checker sources; those
citations alone do not establish completeness of an application's source inventory.

## Bounds and local preparation

The sidecar uses the bounded canonical codec and artifact limits in
[CERTIFICATE_DAG.md](CERTIFICATE_DAG.md), with at most 256 retained namespace facets.
Oversized inputs are refused as UNKNOWN rather than truncated or counted as complete.
Native evidence retains its own limits. Duplicate or malformed exact bindings
produce FAIL; source/checker unavailability and resource exhaustion produce UNKNOWN.

Current `verifier-gates-publication-preparation-3` requires independent facet
inventory, specification, and derivation policy in addition to exact clearance
and dependency policy. Missing or incomplete facet coverage raises
`FacetCoverageIncomplete` with the assessment. The local command returns
REJECTED / UNKNOWN with exit code 2 for unresolved coverage and writes no prepared
payload. A demonstrated coverage violation returns FAIL. There are zero complete
approved production profiles; this implementation currently emits no positive
preparation under a complete profile. It performs no transport.

The v2 namespace retains its existing nine tiers. Future design hypotheses are
separate roadmap work and provide no current predicate or safety guarantee.

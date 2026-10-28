# Selected objective inventory application-profile plan closure

> **Acronyms:** JavaScript Object Notation (JSON);
> Secure Hash Algorithm 256-bit (SHA-256);
> Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

**Status:** experimental finite prerequisite. This mechanism does not issue polished
artifacts or change the retained polish assessment versions 1 and 2. PASS establishes
only exact plan coverage relative to independently selected retained inputs and
replay of their declared applicability rules. A selected application profile is not
proof that the normative objective inventory is exhaustive or independently admitted.
Native objective truth, authenticated authority and inapplicability, public proof and
positive polished admission remain NOT_ESTABLISHED.

## Exact selected inputs

All inputs are immutable UTF-8 JSON bytes. Duplicate keys and nonfinite numbers
refuse parsing. An author cannot replace the consumer's external request with a
selection carried in its plan. Digest strings are lowercase `sha256:` plus 64
hexadecimal digits. Digests bind exact encoded bytes except the namespace collection
digest, whose canonical record-order-independent mechanism is explicitly retained.

`verifier-polish-objective-profile-1` has exactly `schema_version`, `profile_id`,
`revision` and `kinds`. This serialized objective profile is an **application profile**,
not a numbered assurance profile. `kinds` is a nonempty list of distinct admitted
namespace kinds. Each entry has exactly `kind` and `tiers`. Every kind must retain all
nine general meta-tiers, as nine distinct positive plain integer `tier` values 1–9;
boolean values are not integers. Every tier row has exactly `tier` and `objectives`.
Its nonempty objective list includes an unconditional `always` rule. No general tier
can therefore be wholly waived by changing an object's payload.

Each objective has exactly `semantic_version`, `coordinate`, `proposition` and
`applicability_rule`. Its canonical numbered coordinate matches the selected tier
and the represented kind, or the generic OBJECT kind. Semantic version and coordinate
together identify an objective within a kind; duplicate identities refuse admission.
The proposition is nonblank text of at most 1,024 characters. Other identifiers are
nonblank plain text of at most 256 characters. The mechanism retains selected semantic
identifiers without translating legacy meanings or claiming their native mechanisms
exist. Synthetic application profiles used by tests are not normative objective lists.

`verifier-polish-object-collection-1` has exactly `schema_version` and `objects`.
Each object has the canonical namespace fields `object_id`, `kind`, `payload` and
`operands`. Object identities are unique. Finite typed composition is independently
replayed against the selected collection commitment. Every supplied object, including
non-root and disconnected supplied records, receives its own complete declared plan.
A kind lacking a selected application profile remains UNKNOWN; the generic OBJECT
profile is not silently applied to it. Known omissions in other covered kinds still
refute the plan.

`verifier-polish-inventory-request-1` has exactly `schema_version`, `root_id`,
`profile_digest`, `collection_bytes_digest`, `collection_digest`, `mechanism_digest`
and `limits`. The root belongs to the complete supplied collection. The consumer pins
the exact application profile bytes, collection bytes, canonical collection commitment
and installed replay mechanism. This pinning alone does not authenticate the consumer,
profile issuer, normative completeness or historical execution.

`verifier-polish-objective-plan-1` has exactly `schema_version`, `profile_digest`,
`collection_digest`, `request_digest` and `requirements`. Requirements have exactly
`object_id`, `semantic_version`, `coordinate` and `applicability`. They match the entire
independently derived list, sorted by object identity, tier, objective index and semantic
version. A second numbered objective in a tier cannot be omitted behind one tier row.
Duplicate, extra, reordered, omitted, substituted or falsely waived entries yield FAIL.

## Bounded declarative applicability

Rules inspect only an exact retained namespace record. They do not execute commands,
invoke callbacks, access external data or grant spending, disclosure or execution
authority. A rule node has exactly the fields listed below; unknown fields/operators
refuse admission even inside a decisive or otherwise inactive branch.

| Operator | Other fields | Result |
|---|---|---|
| `always` | None | True |
| `present` | `path` | Whether the exact retained path resolves, including explicit null |
| `equals` | `path`, `value` | Typed structural equality; missing observation is unknown |
| `integer_range` | `path`, `minimum`, `maximum` | Inclusive plain integer interval; missing or differently typed observation is unknown |
| `not` | `rule` | Inversion preserving unknown |
| `all` | `rules` | False if any false, otherwise unknown if any unknown, otherwise true |
| `any` | `rules` | True if any true, otherwise unknown if any unknown, otherwise false |

True maps to REQUIRED, false to NOT_APPLICABLE, and unknown to UNKNOWN. A resolved
false is only a declared-rule computation. Authenticated admission of inapplicability
remains a separate gate. Presence does not establish consent or any real-world fact.

A path has 1–16 plain string keys or plain nonnegative integer array indices below
10,000; boolean indices refuse admission. Unresolved paths are absent for `present`
and unknown for value predicates. Empty string keys are not admitted. Equality
literals have at most 4,096 canonical bytes. Equality checks types recursively: true
differs from integer 1, integer 3 from float 3.0, and float negative zero from positive
zero under their canonical encoded scalars. The interval endpoints are ordered plain
integers of at most 128 bits. Compound rules have 1–64 children. Every rule has at most
512 nodes and depth at most 16. All nodes are validated; all admitted children are
evaluated. There is no validity inferred for uninspected input after capacity exhaustion.

## Capacity and reproducible outputs

Fixed transport ceilings are 4 mebibytes for an application profile, 32 mebibytes for
a collection, 1 mebibyte for a request, and 8 mebibytes for a plan or assessment.
One mebibyte is 1,048,576 bytes. Exceeding a fixed transport or rule structural ceiling
is invalid input and yields FAIL. Every supplied input passes its immutable type and fixed byte bound
before that input is hashed or decoded, in both the builder and assessor. Type checks
precede length inspection, so user-defined byte subclasses cannot enter that inspection.
Every `limits` map contains exactly the following
independently selected positive plain integers, at or below the implementation ceiling:

| Field | Ceiling | Charge |
|---|---:|---|
| `objects` | 256 | All supplied records |
| `profile_objectives` | 8,192 | Every declared objective, including unused kinds |
| `expanded_objectives` | 32,768 | Instantiated objectives for every supplied record |
| `rule_operations` | 1,000,000 | Reserved node/path/value-comparison work units |
| `composition_operations` | 1,000,000 | Selected allowance passed to native finite composition |
| `output_bytes` | 8,388,608 | Canonical derived plan plus 4,096 reserved assessment bytes |

Counts and reserved operation units are dimensionless, not processor benchmark units.
Rule validation charges each node and path segment. Evaluation charges each node,
path segment plus its key length (or one for an index), and each compared value pair.
String characters, dictionary key characters and integer representation bytes add
comparison charges; integer interval comparison adds one plus its representation
bytes. This bounds repeat inspection of large retained values without claiming measured
machine runtime. Composition operations report the reserved selected allowance, not
an actual processor operation count. `output_bytes` is at least 4,096. Diagnostics
after refused work are fixed bounded metadata and reveal no witness or exception text.

Valid selected capacity that cannot discharge work yields UNKNOWN with
`reason=RESOURCE_LIMIT_EXCEEDED` and the named `exhausted_resource`. Matching unresolved
rule entries retain `profile_plan_coverage=PASS` but aggregate UNKNOWN. Missing kind
profiles retain UNKNOWN. Invalid or substituted input yields FAIL with a fixed reason.
Mechanism source unavailability yields UNKNOWN. No carried status supplies computation.

Direct experimental imports expose `build_objective_inventory_plan`,
`assess_objective_inventory` and `recheck_objective_inventory` from
`verifier.runtime.polish_inventory`. The builder preserves unresolved observations
but raises `InventoryUnavailable` rather than emitting a partial plan on capacity
exhaustion or an uncovered kind. It does not create native certificates. The assessor
returns `verifier-polish-inventory-assessment-1`, scoped status, exact input bindings,
usage, unresolved applicability count, missing kind profiles and claim boundaries.
Its `assessment_digest` hashes canonical output before adding that digest field.
Every replayable assessment binds the exact plan, application profile, collection
and request bytes under `input_digests`, including FAIL and capacity UNKNOWN results.
Two inputs producing the same diagnostic still produce distinct bound assessments.
Inputs outside immutable transport bounds and unavailable mechanism source produce
`replayable=false` diagnostics; the rechecker refuses to admit those diagnostics,
even when their output bytes agree. No source-bound proposition is synthesized.
It always retains `polished=false`, `objective_inventory_closure=NOT_ESTABLISHED`,
`authority_status=NOT_ESTABLISHED` and `public_checkability=NOT_ESTABLISHED`.

The rechecker returns `verifier-polish-inventory-replay-1`, independently reruns the
same installed mechanism against externally selected retained inputs and compares
canonical assessment bytes. Rehashing a forged PASS or polished flag cannot pass.
This is reproduced computation, not an independent implementation or historical seal.
The mechanism digest binds its code, executed namespace/canonical/parser helpers and
the packaged namespace, meta-tier, polish and inventory specifications. Changing those
dependencies invalidates the selected pin and requires reassessment.

Before positive polished issuance, a separately qualified versioned admission mechanism
must authenticate the application profile's authority and normative completeness,
admit every applicability decision, replay each required native certificate and prove
its configured public checkability. This prerequisite supplies none of those gates
through status words, selection hashes or nine complete tier rows.

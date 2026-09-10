# Experimental proposition transfer

Verifier Standard (VSTD) distinguishes a proposition about exact retained bytes
from self-derivation, completeness, grounding, and authority axiom agency.
This experimental contract adds a rule-specific proposition-transfer surface.
It does not upgrade any six-axis silo assessment or graph-reachability result.

Terminology: JavaScript Object Notation (JSON); Unicode Transformation Format,
8-bit (UTF-8); Secure Hash Algorithm 256-bit (SHA-256); identifier (ID).
Set members are dimensionless strings. They do not denote physical quantities,
permissions, complete real-world inventories, or facts outside the retained data.

## 1. Records and interpretation

The network canonical JSON codec applies: UTF-8, Unicode Normalization Form C,
no surrogate code points, sorted lowercase snake_case object keys, no extra
whitespace, no duplicate object keys, and no noncanonical numerical spellings.
All decoders accept exact bytes and reject a reserialization mismatch.
All objects below have exactly their defined fields.

A transfer declaration has:

- `schema_version`: `VSTD-PROPOSITION-TRANSFER-0.1`.
- `rule_id`: a nonempty string.
- `rule_profile_digest`: a lowercase `sha256:` digest.
- `premises`: one to sixteen proposition objects, sorted by their canonical
  proposition digest, without duplicates. Repeated (commit_digest, artifact_path)
  pairs are invalid, even if their predicates differ.
- `conclusion`: one proposition object.
- `residual_obligations`: a sorted, duplicate-free string array, at most 256.

Each proposition has exactly:

- `commit_digest`, `artifact_digest`: lowercase `sha256:` digests.
- `artifact_path`: the exact network-census path, using the existing portable
  path grammar. It is never a host filesystem path.
- `size_bytes`: a nonnegative integer, at most 4,194,304.
- `predicate_id`, `facet`: nonempty strings.
- `parameters`: a canonical JSON object, interpreted only by a supported predicate.
- `context`: the exact context object below.

The context has exactly `semantic_scope`, `actor_scope`,
`agency_digest`, `authority_model_digest`, `assumptions`, and `exclusions`.
Scope fields are nonempty strings; `agency_digest` is a digest;
`authority_model_digest` is a digest or null; assumptions and exclusions are
sorted duplicate-free string arrays, at most 256 each. Scope and actor names
are bound declarations, not mechanisms establishing those declarations.
All context objects, predicate facets, and supported predicate identities must
match exactly across premises and conclusion before this rule supports transfer.
No scope coercion, unit conversion, actor substitution, or authority inheritance
is implicit.

Unless a stricter field rule applies, strings are nonempty, at most 256 UTF-8
bytes. Sorted string arrays use lexicographic UTF-8 byte order, not a runtime's
default string comparison. This matters for supplementary Unicode characters.

## 2. First compiled rule

Only `canonical_finite_set_union_v1` is currently registered. Its exact rule
profile is the canonical encoding of this object:

```json
{"artifact_schema":"VSTD-CANONICAL-FINITE-SET-0.1","context_policy":"EXACT","facet":"items","max_evidence_bytes":4194304,"max_items":256,"max_json_depth":32,"max_json_nodes":20000,"max_objects":34,"max_premises":16,"max_record_bytes":262144,"max_string_bytes":256,"predicate_id":"canonical_finite_set_subset_v1","rule_id":"canonical_finite_set_union_v1","schema_version":"VSTD-PROPOSITION-TRANSFER-RULE-0.1"}
```

The profile is a mathematical rule/version identity, NOT an implementation
digest. Implementations register this exact rule ID and profile digest together.
An unknown ID or changed profile is unsupported, never loaded as code.

The supported predicate is `canonical_finite_set_subset_v1`, facet `items`,
with parameters exactly `{"allowed_items":[...]}`. The declaration decoder treats
parameters as an opaque canonical object under record byte/depth/node bounds;
only the selected predicate checks its parameter grammar. The default text-field
limit does not interpret unknown parameter contents. Allowed items are sorted
unique strings, at most 256. Its artifact is exactly
`{"schema_version":"VSTD-CANONICAL-FINITE-SET-0.1","items":[...]}`, with the
same item grammar and limit. Empty sets are allowed.

For source item sets S_i, declared source bounds A_i, actual target set T,
and declared target bound B, the independent checks are:

1. Each source predicate checks S_i is a subset of A_i.
2. The actual-artifact relation checks T equals the union of all S_i.
3. Upper-bound preservation checks the union of all A_i is a subset of B.
4. The target predicate independently checks T is a subset of B.

The third condition is sufficient but not complete for the fourth: it can fail
while the actual target predicate passes. Failed transfer is NOT proof that the
target predicate is false. False premises do not support a conclusion through
classical explosion. Each source predicate reads its own exact artifact bytes;
an incoming graph arrow, receipt status, or entry-node flag never supplies it.

Direct byte checking can remain meaningful even when the surrounding graph
contains cycles. That does not prove acyclicity, ground-origin derivation,
fixed-point soundness, self-derivation, or graph-wide deduction. Future rules
that consume prior proof conclusions must explicitly check proof ancestry and
handle circular support under their own registered semantics.

## 3. Exact evidence and bounds

The pure checker receives a declaration's exact bytes and a mapping from digests
to retained byte arrays. It has no network, filesystem, dynamic imports, or plugin
execution. Resolve only the distinct commit and artifact digests named by the
declaration, at most 34. Ignore unrelated mapping entries; they are not evidence.
An absent required mapping key is UNKNOWN. A present value that is not a supported
byte buffer is INVALID, including a present null/undefined value; do not recast
malformed evidence as missing. Read actual buffer size before making a copy.
Retain a defensive copy once per required digest before checking, so caller
mutation cannot replace a later observation. Count each retained object once.
Visit required digests in ascending digest-string order. Charge actual byte length
only when retaining an object. Skip an object exceeding the per-object bound or
remaining aggregate budget as UNKNOWN, then continue to later objects; do not
clear earlier observations. A digest mentioned with conflicting size declarations
is evaluated against each proposition's declared size independently.

Input declaration and receipt records are at most 262,144 bytes, depth 32 (root
depth zero), and 20,000 JSON values including containers (object keys do not
count as value nodes). A child value has its parent's depth plus one, including
scalar values. Violation of these
wire-record bounds is invalid input. Retained evidence is bounded to the same
per-object size and 4,194,304 aggregate bytes. Unavailable evidence and exhausted
evidence bounds yield UNKNOWN, not success or a fabricated negative proposition.
A parser must enforce nesting bounds before recursive canonicalization.

For each proposition, independently:

- Recheck the commit bytes' digest, canonical encoding, and existing silo-commit
  decoder. The exact artifact path must occur in that commit's census.
- The census entry's artifact digest and size must equal the proposition.
- The context agency digest must equal the commit's authority axiom agency digest.
- The context authority-model digest must equal the object digest at the commit's
  authority-model path, or null when that path is null. This binds a model; it
  does not assess or adopt it.
- Separately recheck artifact digest and actual size. Only a supported predicate
  and facet interpret its artifact's canonical bytes and set grammar. An
  unsupported predicate may name opaque non-JSON bytes without that alone making
  evidence binding INVALID; its predicate remains UNKNOWN.

Evidence binding combines commit/census/context binding with artifact digest and
actual-size checking. It does not include the artifact's interpreted set grammar:
malformed canonical set content makes predicate_result INVALID independently.
Malformed supported parameters likewise affect the predicate, not byte identity.
Within a combined check, INVALID takes precedence over FAIL, then UNKNOWN, then
PASS. This precedence does not erase the separate proposition or transfer checks.

A missing commit makes its binding UNKNOWN but does not erase a directly
observed artifact-predicate failure. A valid commit with missing/mismatching
census membership or context binding produces binding FAIL. Digest substitution,
wrong actual byte size, malformed retained bytes, or malformed supported
predicate parameters produce INVALID on the affected check. Unsupported predicate
IDs or facets produce predicate UNKNOWN. Never interpret unsupported parameters.

## 4. Assessment and receipt

An assessment has exactly:

- `schema_version`: `VSTD-PROPOSITION-TRANSFER-ASSESSMENT-0.1`.
- `premises`: one result per declared premise in the same order.
- `conclusion`: a proposition result.
- `context_preservation`, `artifact_relation`, `upper_bound_preservation`,
  `residual_closure`: each PASS, FAIL, UNKNOWN, or INVALID.
- `conclusion_support`: SUPPORTED or NOT_ESTABLISHED.
- `authority_admissibility`: always NOT_ESTABLISHED.
- `reason_codes`: sorted unique codes as defined below.

A proposition result has exactly `proposition_digest`, `evidence_binding`,
and `predicate_result`. The latter two use PASS, FAIL, UNKNOWN, INVALID.

Known predicates are checked independently even when the rule is unsupported.
For the supported rule, context preservation is PASS only for exact equal
contexts and supported matching predicate IDs/facets; a known context mismatch
is FAIL, including when another predicate/facet is unsupported. Otherwise,
unsupported predicate/facet inputs make context preservation UNKNOWN.
Upper-bound preservation needs all supported, structurally valid parameter sets:
otherwise INVALID for a malformed supported set, or UNKNOWN if unsupported.
Artifact relation needs all supported, valid actual item sets; otherwise INVALID
for malformed required actual evidence, or UNKNOWN for missing/bounded/unsupported
inputs. For each of these aggregate checks, INVALID takes precedence over UNKNOWN.
Malformed supported parameters do not prevent independently parsing valid actual
artifact sets for the artifact relation. A known negative in any separate check
is retained.
Residual closure is PASS for no residual obligations and UNKNOWN otherwise.
An unsupported rule makes context preservation, artifact relation, and upper-bound
preservation UNKNOWN, without changing independently checked predicate results.

Conclusion support is SUPPORTED only if every proposition evidence binding and
predicate result, context preservation, artifact relation, upper-bound
preservation, and residual closure is PASS. Otherwise it is NOT_ESTABLISHED.
This says only that the named finite-set conclusion has this checked support.
Authority admissibility remains NOT_ESTABLISHED even with identical contexts.

Reason codes are computed from the final checks, using only these codes:
`EVIDENCE_BINDING_FAIL`, `EVIDENCE_BINDING_INVALID`,
`EVIDENCE_BINDING_UNKNOWN`, `PREDICATE_FAIL`, `PREDICATE_INVALID`,
`PREDICATE_UNKNOWN`, `CONTEXT_PRESERVATION_FAIL`,
`CONTEXT_PRESERVATION_UNKNOWN`, `ARTIFACT_RELATION_FAIL`,
`ARTIFACT_RELATION_INVALID`, `ARTIFACT_RELATION_UNKNOWN`,
`UPPER_BOUND_PRESERVATION_FAIL`, `UPPER_BOUND_PRESERVATION_INVALID`,
`UPPER_BOUND_PRESERVATION_UNKNOWN`, `RESIDUAL_OBLIGATIONS`,
and `UNSUPPORTED_RULE`. Include the appropriate code for each non-PASS result,
deduplicate, and sort. Residual UNKNOWN uses RESIDUAL_OBLIGATIONS.
No positive result needs a reason code.

A receipt has exactly `schema_version` =
`VSTD-PROPOSITION-TRANSFER-RECEIPT-0.1`, `declaration_digest`,
`rule_profile_digest` (copied from the declaration), and `assessment`.
It is an unsigned, deterministic portable semantic record, not an assertion of
producer execution, authorship, independent implementation, or trusted identity.
Decode alone establishes no recomputation. Recheck binds the exact declaration,
reruns all available checks, rebuilds the complete receipt, and requires exact
byte equality. Availability may legitimately change a fresh assessment; correctly
bound bytes cannot change at the same digest coordinate. A missing object becoming
available, or retained evidence becoming unavailable, can make an old receipt
non-reproducible under the current observation without rewriting history.
A well-formed receipt that differs from fresh computation raises
`TRANSFER_NOT_REPRODUCED`; that is neither a negation nor an accusation of forgery.
Malformed receipt bytes are invalid, and a receipt bound to another declaration
or rule profile raises `TRANSFER_RECEIPT_BINDING_INVALID`. Neither case erases a
separately retained historical negative assessment.

A separate local replay observation must bind the original receipt digest, rule
profile, and local checker implementation/dependency/build coordinate when
reporting an execution. A configured build coordinate is not proof that hosted
bytes matched that build. A TypeScript implementation must never claim it ran
the Python checker merely because both produce equal semantic records.

## 5. Integration boundary

This experimental direct-module interface does not change numbered profiles,
the stable top-level Python interface, existing graph request versions, or
composition semantics. Until a coordinate-bound service/graph adapter explicitly
consumes it, existing generic DEPENDS_ON edges remain unsupported.
General composed trust and deductive trust remain NOT_ESTABLISHED.

A finite-set union is the first registered transfer mechanism, not the full
interoperability or mathematical-completeness target. Formal proof adapters,
solver/prover/verifier translations, predicate conflict combination, hosted
execution observations, and preservation over the full composed authority graph
remain separate obligations. No uploaded artifact or checker is executed.

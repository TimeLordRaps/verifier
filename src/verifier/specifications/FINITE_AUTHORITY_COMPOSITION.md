# Finite authority composition

Experimental Verifier Standard (VSTD) contract. JavaScript Object Notation (JSON)
records use the artifact-network canonical codec; Secure Hash Algorithm 256-bit
(SHA-256) digests bind exact bytes, not implementation correctness. Counts are
dimensionless and size limits are bytes.

## Scope and interface

`verifier.interoperability.authority_composition` exports:

```python
authority_composition_profile_bytes() -> bytes
authority_composition_profile_digest() -> str
assess_authority_composition(declaration_bytes: bytes, evidence: dict[str, bytes]) -> dict
```

The fixed rule is asynchronous interleaving of selected declared finite authority
models. A transition selects exactly one member edge; all other coordinates
remain unchanged. Self-loops are valid and retain their member identity and
multiplicity. A transition label does not establish permission, enabledness,
capability or actual execution. Synchronization, scheduler restrictions, hidden
guards and executable adapter policies are outside this interpretation.

This separate result does not revise existing silo, composition or Graph schemas,
six-axis assessments, or their residual obligations. It is not a portable replay
receipt, an execution attestation, a general agency theorem, or a new supported
top-level export. Existing individually passing action floors do not establish
this stronger, explicitly finite transition-correspondence proposition.

## Declaration and rule profile

The declaration has exactly these fields:

```text
schema_version: "VSTD-FINITE-AUTHORITY-COMPOSITION-0.1"
profile_digest: canonical SHA-256 digest
members: [selection, ...]
composite: selection
state_bindings: [{composite_state_id, member_state_ids}, ...]
transition_bindings:
  [{composite_transition_id, member_index, member_transition_id}, ...]
selection: {commit_digest, authority_model_path, authority_model_digest}
```

Members are sorted by distinct commit digest; the composite commit is distinct
from each member. Member indices are zero-based integers, never booleans.
State tuples contain one member-state identifier for each member in that exact
order. Binding arrays are sorted by distinct composite identifier; duplicate
state tuples are invalid. Identifiers follow the native model text rule with a
128-character limit; selected paths follow the native portable census-path rule.
There are no additional or optional fields.

The compiled inert rule record is
`VSTD-FINITE-AUTHORITY-COMPOSITION-PROFILE-0.1`. Its bytes are returned by the
profile function, not loaded dynamically. Its digest identifies the rule
declaration, not the checker source or complete dependency set. A different
well-formed rule digest is unsupported; it cannot authorize new inference rules.

## Admission and retained observations

The evidence argument must be an exact built-in dictionary. Keys must be ordinary
canonical digest strings; custom mappings or custom key objects are unsupported
without invoking their methods. Selected values must be exact immutable bytes:
a missing key is UNKNOWN, while a present non-byte value is INVALID for that
selection. Unselected values are not semantic evidence. Input collection and total
byte limits are checked before model observations. Capture is not promised atomic
against concurrent mutation; retained immutable bytes are exactly the bytes hashed.

Before JSON parsing or recursive canonicalization, scan each record for its byte,
container-depth and container-count limits. Duplicate fields, extra fields,
noncanonical serialization, noncanonical identifiers and malformed numeric fields
are INVALID. A missing discriminator is INVALID; an unsupported discriminator is
UNKNOWN. A syntax-budget stop-loss is UNKNOWN even if unexamined deeper syntax
would also be malformed. No artifact is imported, evaluated or executed.

For each selected member and composite, independently rehash commit and authority
model bytes and strictly decode the existing native record types. Require the
selected path to equal the commit's authority-model path and a census entry with
the selected digest, exact byte size, artifact kind `authority-model`, declared
schema `VSTD-AUTHORITY-MODEL-0.1` and media type `application/json`.
An observed digest, path, size or role mismatch is INVALID even when other bytes
are missing or the model schema is unsupported. The commit must declare the exact
canonical authority action tuple and version; a self-consistent replacement tuple
is unsupported, and a declaration/digest disagreement is INVALID.

This selection binding does not rehash the complete silo census, prove ground
reachability, authenticate its publisher or establish any existing silo axis.

## Finite model and correspondence rules

1. Model state and transition universes must exactly equal their records; initial
   states must be a nonempty subset. Every transition endpoint must exist.
   Such malformed finite topology is INVALID. Ground/actor-scope versions and
   digests must match the compiled interpretation; unsupported actor scopes or
   model interpretations are UNKNOWN.
2. Compute reachable states from every initial state using declared edges. A bound
   reachable state that removes a canonical ground action establishes VIOLATED.
   An unreachable hostile state is not a reachable counterexample. A positive
   per-model preservation result additionally requires every declared state
   reachable, `CLOSED`, no model residuals and the exact canonical ground tuple
   at every state. Ground extensions do not establish a positive floor result.
3. Require a bijection from composite states to the Cartesian product of member
   reachable states. Composite initial states must map to the product of member
   initial states. A well-formed missing tuple or wrong initial set is MISMATCH.
   References into available models that name nonexistent states or transitions
   are INVALID, including when another model is unavailable.
4. Independently generate the complete single-member interleaving relation. Match
   each edge by member index, member transition identifier, source tuple, target
   tuple, actor scope and action, preserving multiplicity. Every declared composite
   edge needs exactly one binding. Omitted, extra, remapped or mutated transitions
   are MISMATCH, not merely UNKNOWN. Equal labels do not merge distinct member edges.
5. A correspondence MATCHED requires all model observations available and their
   reachable denominators closed as above. Open closure can retain a definite
   observed mismatch but cannot establish MATCHED.
6. The union of `COMPOSITION_PRESERVED` local additions over reachable member
   states must be present at every reachable composite state. An addition's exact
   actor scope, action and propagation participate in its identity. `LOCAL_ONLY`
   does not impose that cross-composition obligation. This checks declared
   allowances, never permission or knowledge of a runtime actor.

No all-future or runtime statement follows from a closed finite declared model.

## Bounds and failure precedence

Ceilings: 2–4 members; existing native models each have 1–256 states and at most
256 transitions; 256 product states; 256 generated transitions; 262,144 bytes per
record; JSON container depth 16 and 8,192 containers; 16 evidence entries and
8,388,608 total supplied ordinary bytes. Binding arrays have the respective product
state and generated-transition ceilings.

Compute capped Cartesian cardinality and generated-edge counts before multiplication
that would exceed the bound and before allocating a product or appending edges.
Budget exhaustion is UNKNOWN, never a positive result. A collection/admission
stop-loss occurs before observations and makes no claim about unexamined evidence.
An oversized selected artifact is unavailable, not hashed past its allowed bound.

Within coordinate binding, INVALID dominates UNKNOWN and BOUND. Structural invalid
references dominate unavailable peer observations. A definite mapped edge label
or endpoint-tuple contradiction is checked before missing-peer and expansion-limit
exits; it remains MISMATCH without a completed positive product proof. A known bound reachable action
or required-addition removal survives missing peers, open positive closure and
expansion limits. Per-model floor negatives also survive an unsupported composition
profile because their canonical model interpretation is separately fixed;
profile-specific addition/correspondence claims remain UNKNOWN. Relation MISMATCH
is not itself proof that an action floor was violated.

## Result

The result has exactly these fields:

```text
schema_version: "VSTD-FINITE-AUTHORITY-COMPOSITION-RESULT-0.1"
declaration_digest: digest or null before successful declaration admission
profile_digest: compiled rule digest
coordinates: {members, composite} or null before successful declaration admission
coordinate_binding: BOUND | INVALID | UNKNOWN
transition_correspondence: MATCHED | MISMATCH | INVALID | UNKNOWN
agency_preservation: PRESERVED | VIOLATED | UNKNOWN
local_addition_preservation: PRESERVED | VIOLATED | UNKNOWN
model_results: [model_result, ...]
counts: {product_states: integer or null, generated_transitions: integer or null}
reason_codes: sorted distinct strings
residual_obligations: fixed ordered strings
model_result: {selection_index, commit_digest, authority_model_path,
  authority_model_digest, coordinate_binding, model_admission,
  reachable_state_ids, agency_preservation, reason_codes}
```

Model results are in member order followed by composite; model admission is
`VALID | INVALID | UNKNOWN`, reachable state identifiers are sorted. It concerns
the bound interpreted model, not a claim that every byte-only parsing substep
was completed. Counts remain null until their respective preflight succeeds.
The top-level action/addition PRESERVED states require correspondence MATCHED;
per-model passing floors remain narrower independent observations.

Every result retains: runtime/model correspondence not established; general
composed agency not established; source grounding not established; self-derivation
not established; source relation and boundary not established; global cycle not
established; stronger completeness not established; full silo assessment not
performed. These remain required proof obligations, not claims discharged by the
finite state census. Changing any selected bytes, mapping or compiled rule
coordinate requires fresh assessment.

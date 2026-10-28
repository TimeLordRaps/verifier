# Experimental relation and boundary preservation

Verifier Standard (VSTD) relation-boundary replay is a direct-module version
0.1 experiment. It checks one explicit facet mapping between exact canonical
source and target objects and retains every declared lost facet. It does not
infer semantic equivalence or a general translation theorem.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8); identifier (ID).
Facet counts, byte sizes, digests, and IDs are dimensionless.

## 1. Records and topology

`verifier-relation-boundary-1` declares source and target proposition endpoints,
their exact artifact references and semantic frames, the registered translation
coordinate, exact execution-evidence reference, consumed facets, one-to-one
preservation map, loss map, and assumptions. Arrays are unique and in UTF-8 byte
order. All objects have exactly their defined fields and use canonical JSON.

The declared topology is valid only when:

1. consumed facets equal every source-frame facet;
2. preserved source facets and lost facets are a disjoint complete partition of
   the consumed facets; and
3. preserved target facets equal every target-frame facet.

The registered mechanism is `canonical-json-facet-map-v1`, bound to the inert
profile retained as `verifier/profiles/relation-boundary-mechanism-1.json`.
Both endpoints must use frame `CANONICAL-JSON-OBJECT-0.1`, language
`CANONICAL_JSON_OBJECT`, and the same vocabulary digest.

`verifier-relation-boundary-evidence-1` retains the source and target identities,
frame and translation identities, exact facet maps, producer and checker
coordinates, per-preserved-facet value digests and equality result, explicit
information-loss state, and overall `ESTABLISHED` or `REFUTED` result. Its
`MECHANISM_EXECUTION` label is replayed rather than accepted as proof of a
historical execution.

`verifier-relation-boundary-receipt-1` retains exact evidence coordinates,
mapping, losses, checks, result, reason codes, assumptions, and residual
obligations. Public JSON Schema validation is structural only. Canonical byte
identity, digest and size binding, frame equality, topology, per-facet replay,
and receipt reproduction remain mechanism checks.

## 2. Qualification and results

Qualification independently binds the source, target, and execution evidence;
checks mapping topology and registered coordinates; decodes exact canonical
endpoint objects; then rebuilds every equality observation from the mapped
values. The rebuilt evidence must match byte for byte.

- `ESTABLISHED` means every preserved source value canonically equals its mapped
  target value under this exact map. Explicitly lost facets remain lost.
- `REFUTED` means at least one mapped value differs.
- `UNKNOWN` means required bytes or supported semantics are unavailable.
- `INVALID` means supplied bytes, bindings, topology, canonical encoding, role
  separation, or replay are malformed or substituted.

A declaration, source, target, and execution-evidence role must not form a
circular or aliased binding. Recheck recomputes the complete receipt from the
declaration and exact evidence and requires byte equality.

## 3. Bounds and claim boundary

Endpoint and relation artifacts are each at most 1,048,576 bytes, record bounds
are inherited from source grounding, and a mapping contains at most 64 facets.
An `ESTABLISHED` result establishes only equality of the named preserved facets
for the two retained objects. It does not establish general translation
correctness, equivalence outside those facets, completeness, authority,
historical execution, producer independence, runtime correspondence, or a
numbered VSTD profile.


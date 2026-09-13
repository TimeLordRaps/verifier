# Experimental source grounding

Verifier Standard (VSTD) source grounding is a direct-module version 0.1
experiment. It replays one registered interpretation over exact retained source
bytes. It does not infer a ground from a declaration, a digest, certificate
authorship, or a stored result.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8); identifier (ID).
Digests, byte sizes, item counts, and IDs are dimensionless unless a field says
otherwise.

## 1. Records

All records use strict canonical JSON bytes: UTF-8, sorted object keys, no
duplicate keys, no extra whitespace, and no unsupported values. A decoder
rejects a reserialization mismatch. Source and certificate evidence are selected
by lowercase `sha256:` digest and exact byte size.

`VSTD-SOURCE-GROUNDING-0.1` declares exactly:

- a source byte reference;
- a semantic frame with frame ID, proposition language, vocabulary digest, and
  sorted top-level facets;
- an interpretation profile, mechanism, inert mechanism-profile digest, and
  checker coordinate;
- one ground proposition containing proposition ID, `JSON_POINTER_EQUALS`
  predicate, nonempty object path, and expected bounded JSON value;
- a `DERIVATION` or `TRANSLATION` certificate reference;
- sorted assumptions and a declarer coordinate.

The only registered interpretation is
`VSTD-CANONICAL-JSON-INTERPRETATION-0.1` with mechanism
`canonical-json-pointer-equality-v1`, frame
`CANONICAL-JSON-OBJECT-0.1`, language `CANONICAL_JSON_OBJECT`, and the inert
profile retained as
`verifier/profiles/source-grounding-mechanism-0.1.json`.

`VSTD-SOURCE-GROUNDING-CERTIFICATE-0.1` retains the exact source, semantic
frame, interpretation, proposition, producer, and checker coordinates plus the
observed path/value and `ESTABLISHED` or `REFUTED` result. Its
`evidence_origin` is `MECHANISM_EXECUTION`. That label is replayed, not trusted
as historical proof of execution.

`VSTD-SOURCE-GROUNDING-RECEIPT-0.1` retains all checked digests, checker
coordinate, assumptions, exact check map, sorted reason codes, result, and
residual obligations. The public JSON Schema is structural only; canonical-byte
identity, profile support, facet equality, evidence binding, certificate replay,
and receipt reproduction require the Python mechanism.

## 2. Qualification

Qualification separately checks source and certificate binding, registered
mechanism support, semantic-frame compatibility, certificate reproduction, and
proposition evaluation. Source top-level keys must equal the declared facets.
The certificate is rebuilt from the retained source and its carried producer
coordinate and must match byte for byte.

Results are:

- `ESTABLISHED`: the selected path exists and its canonical value equals the
  declared expected value under the exact supported coordinate;
- `REFUTED`: the path is absent or its canonical value differs;
- `UNKNOWN`: required evidence is absent or the profile/frame is unsupported;
- `INVALID`: evidence, canonical encoding, binding, circularity, or replay is
  malformed or substituted.

Missing evidence remains `UNKNOWN`; malformed supplied evidence is `INVALID`.
The mechanism rejects a declaration whose source, certificate, or declaration
identity aliases another role. Recheck rebuilds the complete receipt from the
exact declaration and current evidence and requires byte equality.

## 3. Bounds and claim boundary

Records are at most 65,536 bytes, source objects at most 1,048,576 bytes,
decoded JSON depth at most 16, decoded values at most 4,096, and sorted arrays
at most 64 items. These are operational limits, not semantic completeness.

An `ESTABLISHED` result closes only one exact pointer-equality proposition over
one exact source object. It does not establish producer independence, historical
execution, denominator or real-world completeness, authority, source truth,
runtime correspondence, or a numbered VSTD profile. These residual obligations
remain explicit in every receipt.


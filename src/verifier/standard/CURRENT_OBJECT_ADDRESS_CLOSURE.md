# Current OBJECT-4.2: reachable operand-address closure

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained records, and Secure
Hash Algorithm 256-bit (SHA-256) names record, collection and closure
commitments. Record and reference counts and checking budgets are
dimensionless.

The pair `verifier-current-object-obligations-1` / `OBJECT-4.2` selects a
bounded **address closure** proposition for one selected root record under the
admitted namespace of `NAMESPACE_OBJECTS.md`. The coordinate is `OBJECT-4.2`
because `CURRENT_OBJECT_FACETS.md` reserves `OBJECT-4.1` for a future
receipt-to-subject closure objective; this objective does not claim that
reservation. The request selects the root identifier (`subject_id`), its
admitted kind (`object_kind`) and its record digest (`object_digest`), the
collection commitment and a closure commitment. The evidence is one canonical
JSON object retaining the complete selected collection.

## Subject kind

The root may be a record of any admitted kind. `NAMESPACE_OBJECTS.md` uses
OBJECT for something a RECEIPT can describe, and OBJECT slots accept any
admitted kind. The precedent is `OBJECT-1.1` in `object_facets.py`, whose
registration names subject kind OBJECT while its request selects any admitted
kind. The same holds here: the registration's `subject_kind` stays `OBJECT`,
the request selects the root's kind, and a retained root whose identifier or
record digest differs from the selection, or whose kind differs from the
selected kind, is `FAIL`. The public route selects the represented kind
externally and refuses a request or result whose kind differs from it.

## Closure commitment

The closure commitment is the SHA-256 digest of the canonical JSON object
`{"schema_version": "verifier-object-address-closure-1", "root_id": <root>,
"addresses": [...]}` whose addresses list one `{"object_id", "record_digest"}`
pair for the root and for every record reachable from it through operand
references, sorted by identifier. A namespace record digest commits to operand
identifiers, not to the records they name; the closure commitment binds the
exact digest of every reached record, so a changed reachable record changes
the closure even when the root digest is unchanged.

## Exact proposition

In the selected finite collection of retained canonical namespace records,
every operand reference reachable from the selected root record of the
selected admitted kind names exactly one retained record, the reachable
reference graph has no cycle, and the canonical manifest of the root
identifier and every reached identifier with its record digest recomputes the
selected closure commitment.

Only the reachable part is decided. A record outside the closure may carry a
dangling reference without changing the verdict; the collection commitment
still binds it.

## Verdicts

`PASS` sets `reachable_address_closure=PASS`. A reachable dangling reference,
a reachable reference cycle, an overclaimed or underclaimed manifest, a
changed reachable record, an inadmissible kind, a duplicate operand target, a
repeated identifier, a differing collection commitment, a root whose identity
differs from the selected record or a root whose kind differs from the
selected kind is `FAIL`. Missing retained evidence or an exhausted operation
or item budget is `UNKNOWN`. A malformed request, unsupported policy,
substituted request or policy, or any altered certificate byte raises
`ObjectAddressClosureError` and is `REJECTED` before replay.

## How this differs from neighbouring objectives

- `OBJECT-1.1` reconstructs one record and its versioned address and leaves
  its named operands unresolved; this objective resolves every reachable
  operand and binds the reached records' digests.
- `OBJECT-1.2` decides typed composition of a complete collection: role
  names, kinds and acyclicity of **every** record. This objective checks only
  resolution and acyclicity of the reachable part and assigns no kind
  contract. A namespace-valid collection can PASS both; a collection whose
  unreached records break typed composition can still PASS this objective,
  which neither checks nor overrides the composition verdict.
- `OBJECT-8.1` decides signed namespace-admission governance; this objective
  checks no signature, authority, clock or revocation.
- `HYPER-4.1` closes the typed operand cone of a HYPER root and admits no
  unrelated record in the collection; this objective admits a root of any
  selected admitted kind, assigns no kind contract to reached records and
  permits records outside the closure.

## Exclusions

`PASS` does not establish receipt-to-subject closure, typed composition,
anything about records outside the reachable closure, payload meaning, truth
or authorship, the whole OBJECT closure tier or object-profile conformance.
`typed_composition`, `receipt_to_subject_closure`, `payload_truth`,
`whole_object_closure` and `object_profile_conformance` are always
`NOT_ESTABLISHED`. Privacy, consent, governance and security are not claimed.

The certificate retains the complete collection and its result. Retention may
disclose payload contents; local checking grants no permission to publish it.
A changed mechanism source, namespace source, `NAMESPACE_OBJECTS.md` or this
specification changes the mechanism digest and requires policy readmission.

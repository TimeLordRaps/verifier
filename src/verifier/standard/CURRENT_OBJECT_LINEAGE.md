# Current OBJECT-2.1: declared linear version lineage

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained records, and Secure
Hash Algorithm 256-bit (SHA-256) names record digests. Version numbers, counts
and checking budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `OBJECT-2.1` selects a
bounded **declared dynamics** proposition: how one representation progresses
through versions and which exact operand records each version binds. The
request selects the head identifier (`subject_id`), its admitted kind
(`object_kind`) and its record digest (`object_digest`), the collection
commitment of `NAMESPACE_OBJECTS.md` and a lineage identifier. The evidence is
one canonical JSON object retaining the complete selected collection.

## Subject kind

The head and every version may be records of any admitted kind, provided all
of them are of the one selected kind. `NAMESPACE_OBJECTS.md` uses OBJECT for
something a RECEIPT can describe, and OBJECT slots accept any admitted kind.
The precedent is `OBJECT-1.1` in `object_facets.py`, whose registration names
subject kind OBJECT while its request selects any admitted kind. The same
holds here: the registration's `subject_kind` stays `OBJECT`, the request
selects the head's kind, and a retained head whose identifier or record digest
differs from the selection, a head whose kind differs from the selected kind,
or a version of another kind is `FAIL`. The public route selects the
represented kind externally and refuses a request or result whose kind differs
from it.

## Lineage declaration convention

This objective defines, and only it interprets, a payload member named
`lineage` on a record of the selected kind. `lineage` is a payload convention
defined by this objective, not namespace text: `NAMESPACE_OBJECTS.md` neither
names nor reserves it, certifies no payload semantics and does not interpret
relationships inside a payload as composition dependencies. The member is a
JSON object with exactly four members:

- `lineage_id`: bounded nonblank text naming the lineage;
- `version`: an integer from 1 to 2^53 - 1;
- `predecessor`: `null` for version 1, otherwise the canonical record digest
  (`sha256:` and 64 lowercase hexadecimal digits) of the previous version;
- `operand_digests`: a map from each operand identifier the record references
  to the canonical record digest that version pins.

A record is a member of the selected lineage exactly when its payload has a
`lineage` object whose `lineage_id` is the selected identifier. Every member
must satisfy the convention. This convention is new with this objective; no
earlier objective assigns meaning to a `lineage` member.

## Exact proposition

In the selected finite collection the selected head record of the selected
admitted kind declares the selected lineage identifier; following each
declared predecessor record digest from the head reaches only retained records
of that kind and lineage whose versions decrease by exactly one until version
1, which declares no predecessor; for every version the operand reference
identifiers equal its pinned operand keys and each pinned operand is retained
with exactly the pinned record digest; and no other retained record declares
the selected lineage identifier.

A namespace record digest commits to operand identifiers, not to the records
those identifiers name. The pins close that gap for each version: a changed
operand record keeps the referring record digest but no longer matches its
pin.

## Verdicts

`PASS` sets `version_lineage_progression=PASS`. A skipped version, an
unretained predecessor, a stale operand pin, a fork, a retained version later
than the head, a dangling pinned operand, an operand without a pin or a pin
without an operand, a version 1 with a predecessor, a lineage identifier that
changes along the chain, a head of another lineage, a head whose identity
differs from the selected record, a head or version whose kind differs from
the selected kind, a repeated identifier or a differing collection commitment
is `FAIL`. Missing retained evidence or an exhausted operation or item budget
is `UNKNOWN`. A malformed request, unsupported policy, substituted request or
policy, or any altered certificate byte raises `ObjectLineageError` and is
`REJECTED` before replay.

## How this differs from neighbouring objectives

- `OBJECT-1.1` reconstructs one record and its versioned **address**; the
  address schema version is a format version, not a lineage. It leaves named
  operands unresolved.
- `OBJECT-1.2` decides typed composition. Versions whose pinned operands are
  the typed roles of their kind, or that carry no operands, can PASS both
  objectives over one namespace-valid collection; this objective neither
  checks nor overrides the composition verdict and keeps
  `typed_composition=NOT_ESTABLISHED`.
- `OBJECT-8.1` decides signed namespace-admission governance; this objective
  checks no signature, authority, clock or revocation.

## Exclusions

`PASS` does not establish actual revision history, authorship, wall-clock or
causal order, semantic compatibility between versions, payload truth, typed
composition, the whole OBJECT dynamics tier or object-profile conformance.
`typed_composition`, `actual_revision_history`, `payload_truth`,
`whole_object_dynamics` and `object_profile_conformance` are always
`NOT_ESTABLISHED`. Privacy, consent, governance and security are not claimed.

The certificate retains the complete collection and its result. Retention may
disclose payload contents; local checking grants no permission to publish it.
A changed mechanism source, namespace source, `NAMESPACE_OBJECTS.md` or this
specification changes the mechanism digest and requires policy readmission.

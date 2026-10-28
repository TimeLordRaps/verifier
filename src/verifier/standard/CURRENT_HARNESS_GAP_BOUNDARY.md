# Current HARNESS-3.1: named gaps bounded by instrument placements

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Window, placement and gap
endpoints are integer instants on one declared session clock, in that clock's
unit; intervals are half-open. Counts and checking budgets are dimensionless.

## Row

The pair `verifier-current-object-obligations-1` / `HARNESS-3.1` selects a
bounded strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

| HARNESS-3.1 | Gap boundary | The named uninstrumented gap is stated as a property of where the instrument was placed. | none | statics:gap |

## Proposition

The externally selected exact HARNESS record occurs once in the selected
finite typed collection. Its retained named instrument placements rehash to
its commitment and lie inside its declared session window. Under
statics:gap, its declared named gaps equal, in ascending order, the
complement of those placements over the window. Each gap therefore begins at
the window start or where a named placement ends, and ends at the window end
or where a named placement begins.

## Retained bytes

Evidence is the canonical JSON object `{"schema_version":
"verifier-current-harness-gap-boundary-evidence-1", "objects": [...],
"inputs": {"placements": [...]}}`. Each object row is one namespace record and
must reconstruct exactly. The request commits the subject digest, the
composition digest of every row and the SHA-256 of the evidence bytes.

- The HARNESS payload is exactly `{"scope": "retained-harness-gap-boundary",
  "window": {"start", "end"}, "gaps": [{"name", "start", "end"}, ...],
  "placements_digest": "sha256:<hex>"}`.
- `placements_digest` is the SHA-256 of the canonical JSON of the retained
  placements array.
- Each placement is exactly `{"instrument", "start", "end"}`.
- Gap names and instrument names are nonempty strings of at most 256
  characters. Gap names are unique.

## Decision

1. The following are `FAIL`:
   - non-canonical or wrong-version evidence;
   - a subject that is absent, repeated, of another kind or of another digest;
   - a failed typed composition;
   - a wrong scope;
   - a placements commitment mismatch;
   - an unnamed or duplicate-named gap, or an unnamed placement.
2. The following are `UNKNOWN`:
   - an exhausted bound;
   - missing evidence;
   - `null` inputs or placements;
   - an empty placements array.
3. Otherwise `statics.evaluate("HARNESS", "gap", {"window": <window>, "gap":
   [<gap start/end>...]}, {"instrumented": [<placement start/end>...]},
   budget, subject=<subject_id>)` decides. The following are each `FAIL`:
   - an empty window, or a placement outside it;
   - a declared gap whose boundary is not a window edge or a placement edge;
   - a declared gap over an instrumented instant;
   - an uninstrumented instant that no declared gap covers.
4. `PASS` reports, per gap, its name, interval, and anchors. The `after`
   anchor names the placements ending at the gap start, or is `null` at the
   window start. The `before` anchor names the placements starting at the gap
   end, or is `null` at the window end. A gap without such an anchor is
   `FAIL`. `PASS` also reports the placement count and the total
   uninstrumented length.

## Relation to other HARNESS coordinates

`harness_checks.py` registers HARNESS-1.6 (surface), HARNESS-2.1 (messages),
HARNESS-2.2 (tools), HARNESS-2.3 (effects) and HARNESS-4.1 (transcript).
HARNESS-1.6 partitions channels into instrumented and named declared-gap
channels. This objective names time intervals of one session window instead,
and derives them from retained placements.

The other rows of this tier remain `NOT_ESTABLISHED` here: HARNESS-3.2
(timestamp resolution), HARNESS-3.3 (channel capacity) and HARNESS-3.4
(instrument fixity). The inventory rationale for this slot names isolation,
interceptor determinism and immutable test logic. None of these is
established by this objective.

## Exclusions

`PASS` establishes none of the following, each of which is `NOT_ESTABLISHED`:

- that an instrument was actually placed or recorded as retained;
- what happened inside a gap;
- clock accuracy;
- isolation, authority, safety, security, privacy or consent;
- closure of the HARNESS statics tier;
- object-profile conformance.

The pinned mechanism is invalidated by a change to any of these:

- the HARNESS record or the collection;
- the retained placements;
- the limits or the policy;
- `statics.py`, this mechanism or this specification.

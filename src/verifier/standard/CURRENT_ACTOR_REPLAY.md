# Current ACTOR accountability replay

Status: experimental, versioned, bounded objective. Verifier Standard (VSTD)
names the claim; the Python mechanism is a reference implementation. JavaScript
Object Notation (JSON) bytes are canonicalized and committed with Secure Hash
Algorithm 256-bit (SHA-256). Positions, event counts and operation counts are
dimensionless; byte ceilings count encoded bytes.

`verifier-current-object-obligations-1` / `ACTOR-2.7` grounds one bounded,
strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

> Replaying the declared events from the first reproduces the current delegation, key and membership state.

The row depends on `ACTOR-2.2` through `ACTOR-2.6`. Their declared transition
rules are used here as prerequisites; none of those rows, and not `ACTOR-2.1`,
is emitted by this certificate.

## Selection

The external request independently selects an exact ACTOR identifier and
namespace-record digest, the complete typed-collection digest, the digests of a
retained base declaration, a retained declared event array and a retained
current state, an evidence byte reference, a policy digest and finite checking
limits. The evidence bundle has exact fields `schema_version`, `objects` and
`inputs`; `inputs` is absent or `null` (UNKNOWN), or an object with exact keys
`base`, `events` and `state`. A missing key is UNKNOWN. Each retained input is
rehashed and must equal its selected digest.

An object's kind is read from its typed namespace record, never from its
identifier. An identifier spelled like another kind's label is only a name.

## Replay

`base` declares `keys` and `decision_classes` for one nonempty set of actors,
each a typed ACTOR record; key material is declared by SHA-256 commitment and
classes are sorted unique names. The selected ACTOR must be in the base.

Events are replayed from the first, in strictly increasing stated position. The
only shared position is a succession: a `succession_end` immediately followed
by the `succession_begin` with the same succession identifier and position.

- `delegation` names a fresh identifier, a delegator whose capacity to decide
  has not ended, another typed ACTOR as delegate, an ordered interval and a
  nonempty subset of the delegator's declared decision classes. A subset that
  exceeds them refutes; a subset covered only by authority conveyed to the
  delegator is re-delegation and is UNKNOWN.
- `revocation` names a live delegation and removes it.
- `rotation` replaces a held key commitment of an actor already in the replayed
  key state with a new one. A rotation never mints a new actor.
- `membership` enters or leaves a typed COLLECTIVE record; entering a held
  membership or leaving an unheld one refutes.
- `dissolution` ends an active actor's capacity to decide from that position.
- `succession_end` ends the replaced actor's capacity; the paired
  `succession_begin` adds a different, fresh typed ACTOR with declared keys and
  classes. An unpaired half refutes.

State changes only through declared events: no implicit revocation and no
interval expiry. The replayed state is `delegations` sorted by identifier,
`keys` by actor and `memberships` sorted by actor then collective; it must equal
the retained current state byte for byte in canonical form.

## Verdicts

`PASS` establishes only that this finite retained event array, replayed from the
retained base under the rules above, reproduces the retained current
delegation, key and membership state. A superset delegation, a revocation of a
non-live delegation, a rotation naming an actor outside the key state or a key
not held, an unpaired or split succession, an out-of-order position, a
non-ACTOR or non-COLLECTIVE reference, a delegation after the delegator's
capacity ended, or a retained state differing from the replay yields `FAIL`.
Absent inputs, re-delegation, or an exhausted operation, item, event, actor or
byte limit yields `UNKNOWN`. A malformed or substituted policy, request or
certificate is rejected before any computational verdict.

The result carries `accountability_replay`, `PASS` only on a pass. Personhood,
real-world completeness, record authenticity, authority, consent, the whole
ACTOR dynamics tier and `object_profile_conformance` are always
`NOT_ESTABLISHED`. Role-branch admission of members, key uniqueness across
actors and decisions taken under a delegation are outside this certificate.

The external policy binds the installed implementation and this specification
by a mechanism digest, selected trust-root labels and a certificate byte
ceiling. Offline recheck needs the independently selected request and policy,
re-executes the installed mechanism and compares complete certificate bytes.
Trust-root labels are selections, not authentication of an event author.

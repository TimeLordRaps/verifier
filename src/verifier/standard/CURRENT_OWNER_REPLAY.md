# Current OWNER-2.6: ordered replay of a retained holding

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Positions and term bounds
are dimensionless integers in the declared order. Counts and checking budgets
are dimensionless.

The pair `verifier-current-object-obligations-1` / `OWNER-2.6` selects this
row of the OWNER dynamics table, quoted verbatim:

> Replaying the declared events from the origin in the declared order reproduces the current holding.

The represented proposition is a bounded strict subset of that row. The
request selects one exact `OWNER` namespace record, its complete finite typed
collection and the SHA-256 commitment of retained replay inputs; the `OWNER`
payload carries the same commitment. The inputs are sorted unique retained
instrument bytes, an origin (position, bound instrument digest and granted
limbs), an ordered list of declared events, an evaluation position and the
retained current holding.

A holder is admitted only when it is an `ACTOR` record bound by the `OWNER`
`actor` operand, directly or through a typed `GRAPH` of `ACTOR` records. A held
object is admitted only when it is bound by the `object` operand. A holder's
kind is read from those typed records and never from an identifier or a label
prefix: a `HUMAN` record, or a text label shaped like a person, is not a holder.

Each limb row names its held object, holder, limb, one of the three limb kinds
(right, discharge-duty, answering-duty) and a term: a start and an exclusive
end, or a start and a declared non-expiry. The origin and every event must
carry an instrument digest that matches retained instrument bytes. Event
positions strictly increase from the origin. Replay applies the prerequisite
rows as follows:

- a transfer conveys only limbs the transferor holds at its position and
  removes them from the transferor;
- a delegation conveys only limbs the delegator holds at its position and
  leaves the delegator's holding intact;
- a revocation withdraws exactly the limbs it names, each held at its
  position;
- a term ends by the declared order alone, and a lapse declared as an event
  is `FAIL`, because lapse is distinguished from revocation.

The checker then compares the limbs alive at the evaluation position with the
retained current holding, row for row, by held object, holder, limb, kind and
term. An evaluation position before the last event is `FAIL`. A mismatch is
`FAIL` and the certificate observations list the replayed rows missing from
the retained holding and the retained rows the replay does not produce.

A conveyance into a limb the recipient already holds would need a merge rule
the row does not state, so it is `UNKNOWN` and never `PASS`. An exhausted
event, grant, instrument, object or operation budget is `UNKNOWN`. Missing
evidence is `UNKNOWN`. A malformed or substituted certificate is refused with
the module error before any verdict is returned.

`PASS` establishes only that the represented replay reproduces the represented
holding. It does not establish legal title, liens or any law of property; the
authority of an instrument's issuer or its admissibility at issue time;
consent; personhood, or that a `HUMAN` record names a natural person; the
holder's own `ACTOR` certificate or the held object's own certificate;
translation from an instrument's own clock; declared-shared limbs or any
OWNER statics row; OWNER closure; the whole OWNER dynamics tier; or
object-profile conformance. Privacy, governance, security, spending and
publication remain `NOT_ESTABLISHED`.

The certificate retains the exact evidence bytes, request, policy digest,
mechanism digest and replay result. Public release of retained contents
requires separate disclosure authority. A changed module, shared selection
helper, namespace specification, this specification, retained bytes or policy
invalidates the pinned mechanism.

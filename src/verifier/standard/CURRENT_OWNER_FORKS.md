# Current OWNER-4.3: fork detection over retained holdings

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Positions are
dimensionless integers in the declared order, and a holding's first and last
positions are inclusive. Counts and checking budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `OWNER-4.3` selects this
row of the OWNER closure table, quoted verbatim:

> No two holdings claim the same limb over the same object at the same position, and a fork is reported rather than resolved.

The represented proposition is a bounded strict subset of that row together
with the row's own stated dependency, `OWNER-4.2`, and through it `OWNER-4.1`,
checked as conjuncts over the selected chains. The request selects one exact
`OWNER` namespace record, its complete finite typed collection and the
SHA-256 commitment of retained inputs; the `OWNER` payload carries the same
commitment. The inputs are sorted unique retained instrument bytes, retained
holdings and one declared chain per held object.

A holder is admitted only when it is an `ACTOR` record bound by the `OWNER`
`actor` operand, directly or through a typed `GRAPH` of `ACTOR` records. A held
object is admitted only when it is bound by the `object` operand. A holder's
kind is read from those typed records and never from an identifier or a label
prefix: a `HUMAN` record, or a text label shaped like a person, is not a holder.

Each holding has a unique identifier, a held object, a holder, a nonempty
sorted list of limbs with their kinds (right, discharge-duty,
answering-duty), and a first and last position. Each chain names its held
object, an origin position, an origin instrument digest, a head position and
the holdings that make up the chain. The chain prerequisites are:

- the origin instrument digest matches retained instrument bytes;
- every position from the origin to the head is covered by exactly one of the
  chain's holdings, so a gap, a double cover, a holding before the origin
  and a holding past the head are each reported.

Fork detection runs over every retained holding, chained or not. For each
held object and limb it reports every pair of holdings whose positions meet,
with the first position they share. Pairs are listed in a fixed order by
object, limb and the sorted pair of identifiers, independent of input order.

A fork is reported rather than resolved: the checker never names a winning
holding and never drops either side. Any fork or chain finding is `FAIL`, and
the certificate observations carry exactly the list of forks and the list of
chain findings. With neither, a held object without a selected chain is
`UNKNOWN`, because its prerequisite chain is unestablished. An exhausted
holding, chain, instrument, object or operation budget is `UNKNOWN`. Missing
evidence is `UNKNOWN`. A malformed or substituted certificate is refused with
the module error before any verdict is returned.

Declared-shared limbs are not represented. The exception for a limb declared
shared belongs to the OWNER statics asymmetry row, which this objective does
not claim; every same-limb meeting is therefore reported here.

`PASS` establishes only fork freedom over the represented holdings and gapless
represented chains from bound origins. It is not the `OWNER-4.6` closure
result: a chain is never reported closed here, and `OWNER-4.4` admissibility
at issue time and the `OWNER-4.5` accountability floor are not computed. It
does not establish legal title, liens or any law of property; the authority
of an instrument's issuer; consent; personhood, or that a `HUMAN` record names
a natural person; which side of a fork is legitimate; the holder's own `ACTOR`
certificate or the held object's own certificate; the whole OWNER closure
tier; or object-profile conformance. Privacy, governance, security, spending
and publication remain `NOT_ESTABLISHED`.

The certificate retains the exact evidence bytes, request, policy digest,
mechanism digest and result. Public release of retained contents requires
separate disclosure authority. A changed module, shared selection helper,
namespace specification, this specification, retained bytes or policy
invalidates the pinned mechanism.

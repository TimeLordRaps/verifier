# Current simulation dynamics: selected finite transition replay

Verifier Standard (VSTD) registers `SIM-2.1` under
`verifier-current-object-obligations-1`. Simulation (SIM) means a generative
simulation specification. This coordinate is one current dynamics objective;
it does not inherit the same-spelled legacy domain-catalogue result.

## Exact bounded proposition

For the externally selected exact SIM object, finite typed collection,
transition program and retained state, entropy and causal-time sequence, the
installed native interpreter replays every selected transition and returns
the selected state and transition counts.

The external request selects the SIM record digest, complete collection
digest, canonical artifact and input digests, expected positive counts, exact
retained evidence reference, proposition, installed mechanism, policy and
resource limits. The SIM payload must bind the same artifact and input digests.
The checker reconstructs every retained namespace record, checks finite typed
composition, compares both available program and trace commitments, and runs
`verifier.domains.sim.evaluate("replay", ...)` on retained program and inputs.
Its transition-expression interpreter has no arbitrary code loading. A
transition mismatch, contradictory selected byte commitment, mismatched
record or wrong count is `FAIL`. Missing selected evidence, unsupported native
semantics or exhausted bounds is `UNKNOWN`. Malformed external selection and
substituted certificates are refused; certificate replay reconstructs the
exact result from retained bytes and compares complete certificate bytes.

The retained `states`, `entropy` and `times` arrays use the model's declared
state and time units. State, transition, object and operation counts are
dimensionless. Transport and certificate limits count bytes. Secure Hash
Algorithm 256-bit (SHA-256) commitments depend on collision resistance and
canonical JavaScript Object Notation (JSON) serialization. The installed
interpreter, checker and host are trusted assumptions; their source digest
does not attest a historical execution.

This selected trajectory says nothing about unselected runs, action
responsiveness, observation projection, hidden-state enumeration, computational
resource consumption, perspective shifts, physical time, collector
authenticity or actual prior execution. Those are separate SIM dynamics
objectives. The full tier, object profile, privacy, consent, governance,
security and publication authority remain `NOT_ESTABLISHED`. No simulation
result is promoted from legacy `SIM-2.1` by matching spelling.

## Scope declaration

The retained SIM payload field `scope` takes one of two forms. The legacy
scalar form is the exact string `selected-retained-trajectory-replay`. The
composable form is one nonempty array of distinct admitted member strings in
strictly ascending code-point order; the admitted members are exactly
`selected-external-law-statement` (current `SIM-3.4`) and
`selected-retained-trajectory-replay` (this route), so the complete composable
declaration is
`["selected-external-law-statement", "selected-retained-trajectory-replay"]`.
This route passes only when its own member is declared. A repeated member, a
member out of that order, an empty array, a non-string member or an unknown
member is a present contradiction and is `FAIL`; the checker never reorders,
deduplicates or otherwise canonicalizes the declaration. A scalar naming any
other string, an absent or null `scope`, or any other value type remains
`FAIL`, as before. One exact SIM record and complete collection can therefore
be selected by `SIM-2.1` and `SIM-3.4` separately. Each route issues its own
certificate under its own request, policy, mechanism and certificate versions,
and a `PASS` from one route establishes nothing about the other.

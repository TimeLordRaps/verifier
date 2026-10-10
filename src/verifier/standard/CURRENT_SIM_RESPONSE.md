# Current simulation dynamics: selected action response

Verifier Standard (VSTD) registers `SIM-2.2` under
`verifier-current-object-obligations-1`. Simulation (SIM) here means a
generative simulation specification. The coordinate depends on a separately
selected, replayed `SIM-2.1` certificate; matching legacy spellings do not
import legacy results.

## Exact bounded proposition

For an exact selected `SIM-2.1` passing trajectory, the installed finite
expression interpreter executes each retained action against the selected
state and entropy. The resulting next state must equal the retained next
state and differ numerically from the state computed with the declared
baseline action. An action numerically equal to its baseline has no selected
intervention. Exact selected bytes remain bound and exact trajectory replay
still distinguishes serialized values such as an integer and a float; signed
zero alone cannot establish an action or next-state effect.
Each model-time difference from action step to next state must be positive and
at most the externally selected response delay. The policy and request bind
the object, child certificate, action program, actions, baseline, bounds,
model time-unit label, response delay and finite resource limits.

An action with no model-relative effect, a wrong next state, an out-of-bounds
action, a delayed response or contradictory selected bytes returns `FAIL`.
Missing child or action evidence, an unknown child result or exhausted bounds
returns `UNKNOWN`. A failed `SIM-2.1` child cannot be repaired here. Exact
replay rejects request, policy or certificate substitution. The child and
action check both execute from retained bytes; a carried success word alone
cannot establish this proposition.

The state, action and time values use the selected model's declared units;
the time-unit label is a contract label, not a measured physical conversion.
Counts and expression operations are dimensionless. Size limits count bytes.
Secure Hash Algorithm 256-bit (SHA-256) commitments rely on collision
resistance and canonical JavaScript Object Notation (JSON) serialization.

This is a counterfactual result *inside the selected model*. It does not show
historical intervention, causal identification in nature, physical time,
collector authenticity, effects of unselected actions, hidden-state
enumeration, resource use, perspective agreement or whole dynamics-tier
closure. Object profile, privacy, consent, governance, security and
publication authority remain `NOT_ESTABLISHED`.

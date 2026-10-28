# Current EVENT declared dispatch and acknowledgment check

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python module is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes and Secure Hash
Algorithm 256-bit (SHA-256) names commitments. Log positions, event, handler and
acknowledgment counts and operation budgets are dimensionless. Evidence and
certificate bounds are measured in bytes.

The pair `verifier-current-object-obligations-1` / `EVENT-2.1` selects one
bounded dynamics proposition for the governing question "Which transitions and
interactions can its facets undergo?". The EVENT dynamics slot names event
emission, bus routing, handler dispatch, state mutation and acknowledgment. This
objective decides a strict finite subset of that rationale on retained bytes
only. `DOMAIN_OBLIGATIONS.md` has no EVENT row, so no numbered legacy wording is
quoted or transferred. Current `EVENT-3.1` (declared prerequisite cone) is a
different statics proposition; neither objective supplies the other.

Proposition: the externally selected exact EVENT namespace record occurs in the
selected finite typed collection and commits to the retained finite handler
declaration and ordered dispatch log; in that log each log-local event is
emitted once, is dispatched exactly once to each declared handler whose
subscribed topics contain its topic and to no other handler, every dispatch
follows its emission and is acknowledged exactly once after the dispatch, and
the retained final state equals the retained initial state updated by each
acknowledged handler's declared writes in log order.

The selected EVENT record payload has exactly `scope` and `dispatch_digest`;
the scope is `retained-event-dispatch` and the digest commits to the retained
inputs. Inputs have exactly `handlers`, `initial_state`, `log` and
`final_state`. A handler has exactly `id`, a nonempty list of unique bounded
`topics`, and `writes`, a JSON object of declared state assignments. A log
entry is `{"op":"emit","event","topic"}`, `{"op":"dispatch","event","handler"}`
or `{"op":"ack","event","handler"}`; its position is its list index. Event
identifiers are local to the log, not namespace records. The state fold applies
`writes` of the acknowledged handler, entry by entry, as a shallow key update.

`PASS` means the retained declaration and log reproduce the proposition.
`FAIL` means the selected bytes contradict it: a changed commitment, a repeated
emission, a dispatch before emission, to an undeclared or non-subscribed
handler, or repeated; an acknowledgment before its dispatch or repeated; a
subscribed handler never dispatched; a dispatch never acknowledged; or a final
state that differs from the fold. `UNKNOWN` means the retained inputs or a
nonempty log are absent, or a selected checking limit is exhausted. Malformed or
substituted requests, policies and certificates are rejected before a
computational verdict. Source or specification changes invalidate the mechanism
digest. Trust-root labels do not authenticate an observer.

The certificate carries the retained declaration, log and states. Do not put
confidential inputs in a public certificate without separate disclosure
authority. Actual emission, transport, delivery guarantees, handler execution,
occurrence authenticity, physical causality, wall-clock timing, TIME, SPACE and
meaning operand truth, events or handlers outside the retained log, privacy,
consent, governance, security and whole EVENT dynamics tier conformance remain
`NOT_ESTABLISHED`. This check authorizes no scheduling, spending or publication.

The installed descriptor also binds `retained_selection.py`, the shared
plain-value request and policy capture helper. Native evaluation remains
specific to this objective; shared selection infrastructure does not establish
its proposition.

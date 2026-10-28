# Finite TRAIN control application profile, version 1

`verifier-train-control-1` selects a bounded optimization-control contract. TRAIN
is an optimization procedure/run and MODEL an optimized artifact, which may
itself implement an optimizer. This contract adds no object kind or numbered
meta-tier and does not reinterpret existing numerical TRAIN certificates.
Architecture, optimization strategy and ordinary finite parameter updates remain
independent of this control contract. MODEL strategy suggestions are data, not
execution authority.

## Selected finite control boundary

`TrainControlPlan` captures exact native namespace records, revision families,
declared aliases, typed MODEL use/derivation relations, capability routes,
checkpoint targets and TIME/TOKEN/environment (ENV)/HARDWARE/SPACE context.
Every selected TRAIN must bind procedure, objective, evaluator,
data split, policy, authority and downstream artifact bindings. Collections are
immutable tuples of at most 256 entries; canonical plan bytes are bounded to
1,048,576. Families cannot change native kind. Declared aliases cannot shadow
object identifiers; unresolved external aliases remain UNKNOWN.

Ordinary acyclic data/derivation reuse is allowed. Literal lineage/delegation
cycles are refuted. Reachability also refutes a MODEL reaching an effect
capability through lineage, delegation, aliases or revision families. Thus an
acyclic MODEL → TRAIN → MODEL → TRAIN chain does not acquire modification rights
merely because it is acyclic. Known contradictions are checked even when another
relation is unresolved. These relations are additional selected control evidence;
they are not new TRAIN operand roles or numerical optimizer-update EVENTs.

Mandatory mediation covers binding mutation, agent activation, TRAIN launch,
explicit TRAIN fork, delegation minting, MODEL/evaluator modification and
checkpoint writing. An incomplete inventory, unresolved external effect paths,
missing context, missing protected facets or unsupported capability semantics
blocks admission as UNKNOWN. Known contradictions remain FAIL. Preflight PASS
means only that the selected finite relation/policy checks passed, under the
host's completeness assumptions; it establishes no executed control.

## Authority and actual local mediation

`TrainControlSession` is a trusted host component. The host supplies authentic
proposal attribution, selected root/executor keys, current authority snapshots,
an integer clock in Coordinated Universal Time (UTC) Unix seconds and trusted
effect callbacks. MODEL code must not receive this controller, its internals,
root signing keys or direct effect interfaces. Every effect in scope must use
this instance. This is cooperative host mediation, not operating-system isolation.
The public plan/policy selections are read-only; new revisions require a new
explicitly selected session. This is not protection against a compromised host.

An operation has exactly the fields admitted by `operation_signing_bytes`:
schema, session, plan, request, actor, origin, TRAIN, target and target digest,
action and new-content/plan digest. Ed25519, the Edwards-curve digital signature
algorithm with a 255-bit field, binds the complete operation. `operation_scope`
binds every operation field except the invocation identifier to a native TOKEN
scope. Native TOKEN tenure, lease attenuation, signatures and freshness/closure
are rerun at each admitted effect boundary. After host/native work, the clock,
selected grant intervals and status freshness are checked again before admission.
The final atomic commit rechecks stop, invocation spending, every ancestor's
remaining ceiling, retained revocation and the exact current authority view.
The selected root, parent issuer and
delegate, principal key, proof of possession, audience, exact operation, finite
window and invocation ceiling must also match. The host's status-age bound is
1..3,600 seconds; candidate evidence cannot extend it. Native unsigned status rows are
current authority only because the host supplies an authenticated current view;
TOKEN replay alone does not authenticate that view or authorize an action.

MODEL-origin actions are denied before invoking a callback, including at lineage
topological depth zero. An executor cannot replace a MODEL origin with its own
identity. Only a selected executor may write a declared checkpoint; immutable
checkpoint bytes must match the signed new-content digest before the callback.
Only separately selected root authority permits other effects. A TRAIN fork
must supply and pass an exact new finite plan and a direct root grant. It does
not create a successor session or copy privileges. New session/branch selection,
fresh authority and complete mediation remain host responsibilities.

Invocations are consumed before callback entry; all lifetime ancestors share
spending across sibling grants within this session. Observed revocation cannot
be reversed by a later ACTIVE view. Authority generation rollback/equivocation,
stale status, revoked ancestors, bad signatures, changed artifacts and reused
invocations block execution. Local state is not durable across process restart;
a new session nonce invalidates old operation bindings, but restored/reused
nonces and durable revocation/spending require separate evidence.

Configured-key STOP reuses `operator_stop`; valid STOP permanently blocks new
admissions. Quiescence means this session is stopped and its callbacks finished.
An already admitted callback may continue, and external queued/delegated effects
are outside this control. Cancellation, callback failure or interruption retains
UNKNOWN rather than a successful operation; invocation spending remains consumed.

## Retained evidence and native replay

Up to 4,096 native EVENT records retain the exact plan, policy, session/process,
operation, selected authority-view digest, context digests, observed host clock,
decision and callback-entry observation in an ordered hash chain. Clock values
are the last admission/STOP observations, not independent completion timestamps.
Missing context
cannot produce a falsely bound EVENT. A full trace refuses new effect admission;
STOP still latches if its observation cannot fit. The trace is then insufficient
to establish complete stop evidence. The callback is responsible for its actual
target/output effects; digest binding does not prove a physical write.

`recheck_denial_trace` is pure historical replay. An operation FAIL denotes denied
admission, while denial-replay PASS denotes the finite recorded MODEL-origin
denial predicate. `TrainDenialTraceMechanism` exposes the separate predicate
`retained-model-origin-effects-denied-1` through BoundProposition, EvidenceStore
and VerificationSession. The host separately selects exact trace, plan, policy,
implementation digest and trust root; carried PASS fields grant nothing. Native
replay is bounded to one plain retained trace of at most 256 records, 16,384
visited values, nesting depth 32 and 1,048,576 bytes, plus selected evidence bounds.
Support exhaustion is UNKNOWN. A native TRAIN-bound result requires an actually
recorded denial for that exact selected TRAIN; a different subject gains no result
from another TRAIN's denial. Replay never invokes callbacks or consumes current grants.
It checks retained bindings/denials; an independently selected commitment does
not prove complete instrumentation, faithful explanations or absence of bypass.

## Wider corrigibility remains required and unresolved

This is one bounded obligation, not a whole-corrigibility certificate. Mandatory
UNKNOWN cannot be repaired by optional coverage, an aggregate score, or a later
numbered-profile result. A consumer selecting the wider specification must block
its overall claim until every required obligation has separate admissible evidence.

| Obligation | Version 1 control and remaining boundary |
|---|---|
| Authorized intervention | Configured-key STOP and operation possession are checked; human/key custody and current authority provenance are assumptions. |
| Effective interruption | New local admissions stop; forced interruption, child work and physical shutdown remain UNKNOWN. |
| Revocation closure | Fresh host views and local ancestor spending/revocation are checked; distributed caches and restored snapshots remain UNKNOWN. |
| Substantive correction | Root-selected new bindings/plans are admitted; durable correction and no silent reversion remain UNKNOWN. |
| Oversight noninterference | MODEL-origin enumerated effects are denied; complete substrate protection and anti-deception behavior remain UNKNOWN. |
| Intervention incentives | Neither incentives to resist nor incentives to manufacture intervention are evaluated; UNKNOWN. |
| Evaluator/evidence integrity | Exact selected bindings and retained chain replay are checked; complete independent observation remains UNKNOWN. |
| Delegation/successor closure | Finite cycles, acyclic capability reachability and local model activation are checked; uncontrolled descendants remain UNKNOWN. |
| Replacement/rollback/recovery | Old nonce bindings are refused by a new session; durable epoch/spending and recovery correctness remain UNKNOWN. |
| Reserved intervention resources | Local retention is bounded; resource reservation and starvation resistance remain UNKNOWN. |
| Trajectory completeness | Retained callback-entry observations are tested; unobserved paths and explanation fidelity remain UNKNOWN. |
| Scoped regression assurance | Named adversarial controls test this implementation only; class-wide model correctness and overall safety remain UNKNOWN. |

TRUST is mechanism-earned artifact support, ROT current-admissibility degradation,
and RUST inverse diagnostic ancestry; none is an execution grant. Freeze preserves
exact bytes, seal closes selected artifact state, and thaw creates a child.
Existing assurance/artifact-control evidence must be selected separately; this
profile does not manufacture freshness, owner acceptance or stronger authority.

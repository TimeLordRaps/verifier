# Declared TIME/SPACE capabilities and contextual namespace extension

**Version:** `verifier-spacetime-context-extension-1`, an opt-in extension.
Verifier Standard (VSTD); JavaScript Object Notation (JSON); directed acyclic
graph (DAG); simulation (SIM); Secure Hash Algorithm 256-bit (SHA-256).

TIME abstracts ordering and progression. SPACE abstracts selected spatial
relationships and operations. Neither has a universal physical representation.
Existing TIME-2.1 and TIME-3.1 microsecond-clock certificates and SPACE-3.1 byte
layout certificates retain their identifiers, units, prerequisites, implementation
digests and meanings. This extension neither reinterprets their evidence nor
registers a replacement numbered objective, tier, certificate census or release gate.

## Exact domains and capabilities

`verifier-declared-time-capabilities-1` has closed fields: profile, domain, unit,
epoch, resolution, uncertainty, run identifier, branch identifier, points and
order, plus its schema version. Rational coordinates serialize as coprime bounded
integer numerator and positive denominator. The factory normalizes; readers
reject noncanonical values, floating point, booleans and exceeded integer bounds.
Resolution and uncertainty are separate declarations; neither authenticates
physical accuracy, clock calibration or synchronization.

| Explicit profile | Implemented proposition | Remaining boundary |
|---|---|---|
| `logical-strict/1` | Exact retained point values strictly increase on the named trajectory. | No physical epoch or fabricated physical uncertainty. Units remain declared logical/model units. |
| `logical-partial/1` | The exact declared finite relation is acyclic; reachability supplies order and unconnected points remain incomparable. | No implicit scalar instants. Incomparability concerns the selected relation, not observed physical concurrency. |
| `physical-clock/1` | Exact rational coordinates, unit/epoch and separate positive resolution/nonnegative uncertainty are represented. | No clock authenticity; overlapping declared uncertainty intervals cannot establish order. |

Comparisons require identical profile, domain, unit, epoch, resolution,
uncertainty, run and branch bindings. There are no implicit unit conversions.
Comparing different domains requires a separately selected mapping. Partial-order
comparisons also require the same retained graph. Missing points, unsupported
capabilities and exhausted bounds yield UNKNOWN.

`verifier-declared-space-capabilities-1` closes profile, domain, unit, frame,
nodes and relations. Directed adjacency has no implicit metric unit. A selected
finite metric table must be complete and satisfy exact identity, positivity,
symmetry and triangle inequalities under finite bounds. It need not be Euclidean.
Direction, frame transforms and other unimplemented capabilities return UNKNOWN
with an UNSUPPORTED reason. A frame label is a binding, not a transform proof.
The existing logical byte-layout route remains separate and unchanged.

## Contextual namespace wire

`verifier-contextual-namespace-object-1` wraps one unchanged namespace record and
an explicit context list. A context reference closes role, TIME/SPACE kind,
target identifier, exact contextual target digest, domain and profile. Roles may
distinguish authority validity, observation, execution, host or SIM contexts.
Multiple domains are separate records, not ambiguous shared fields. Role/kind/
domain keys are unique and sorted. Any of the 26 kinds may carry contexts without
an additional HYPER. Profiles select required contexts explicitly through the
independently supplied context policy; missing required observations stay UNKNOWN.

The wrapper and `verifier-contextual-namespace-composition-1` have new digest
domains. Base namespace record and collection digests remain unchanged. Operand
slots still obey namespace version one; EVENT still requires time, space and
meaning. Contexts cannot replace those roles. Payload fields do not create typed
contexts. Both operand and context edges participate in a finite acyclic closure
check; missing targets are UNKNOWN and cycles or substituted digests/kinds/
domains/profiles are FAIL. Structural context identity does not establish a
capability. `assess_context_capabilities` additionally replays selected supported
profile predicates. Schema conformance establishes shape only.

## SIM/host retained mapping

A `verifier-sim-host-time-relation-1` HYPER uses exactly `simulation`, `sim_times`
and `host_time` roles. The first selects one SIM, the second distinct branch-bound
logical TIME trajectories, and the third one host TIME record. Exact subject,
collection, evidence and run commitments are independently selected. The mapping
wire `verifier-retained-sim-host-time-mapping-1` retains finite point pairs and
piece kinds `advance`, `pause`, `step` or `rollback`.

Advance admits arbitrary exact retained rates, including accelerated progression;
it proves no rate outside the retained pairs or relative to an unselected nominal
baseline. Pause may map one SIM coordinate to several advancing host coordinates.
Step may advance SIM coordinates at the same host point and is noninvertible.
Rollback must select a fresh retained branch and the exact preceding endpoint;
it cannot reuse a previously advanced trajectory under its old branch identity.
it cannot reverse the old branch's strict-order profile silently. SIM units are
never relabeled microseconds. Mappings are partial and piecewise; interpolation,
clock authenticity, synchronization and actual SIM execution remain unestablished.

## Computational cost and execution observations

Cost selection binds exact implementation, operation, input-size definition,
computational model, assumptions, run, domain and unit. `observed` checks retained
cost records only. `budget_replay` reruns an independently selected finite
deny-before-charge rational machine against retained allow/refuse decisions.
It establishes that finite policy replay, not live mediation or actual consumed
physical resources. Live enforced-budget and complexity proof families are
currently unsupported and remain UNKNOWN. Finite timings, successful tests or
timeouts never imply an asymptotic bound.

`verifier-declared-prerequisite-order-1` represents a finite DAG.
`verifier-retained-execution-time-trace-1` separately binds observed intervals to
independently selected typed TIME contexts, the exact DAG, contextual collection,
implementation/model/input definition/assumptions and run. Missing observations,
incomparable or cross-clock intervals remain UNKNOWN; reversed intervals,
substitution or contrary prerequisite order are FAIL. Dependency edges alone
do not prove that operations executed, and retained observations do not
authenticate their historical execution.

## Bounds and qualification

The extension uses 4 MiB immutable evidence/collection ceilings, at most 256
contextual objects, 4,096 references/items, 100,000 checking operations, bounded
depth and 128-bit rational components. Accumulated exact results must remain
representable; exhaustion yields UNKNOWN. Cancellation likewise supplies no PASS.
No optional package, service, arbitrary callback verifier, model execution or
physical-clock attestation is introduced. These bounded assessments are not native
certificates or whole-object/profile conformance. Application admission, all five
application gates, complete M1 qualification and human acceptance remain separate.

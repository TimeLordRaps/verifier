# Selected local permission-slot controls

Verifier Standard (VSTD); application programming interface (API); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

This runtime slice implements a finite local callback boundary.
It supplies retained observations to the separately selected
[native replacement replay](CURRENT_VERIFIER_REPLACEMENT.md),
`verifier-current-ten-tier-object-obligations-1` / `VERIFIER-10.1`.
The host itself issues no native certificate, authenticates no production
authority and admits no observer. Neither slice completes any object, tier,
family census or application profile. No legacy coordinate is converted. This
retained finite `VERIFIER-10.1` predicate supplies no current-core or cross-kind
corrigibility-extension credit. Release approval is absent.

The API is `verifier.runtime.permission_slot`. Runtime dependencies are only the
Python standard library, compatible with Python 3.10 or later. This source calls
no provider, model, network, subprocess, environment/account reader or installed
application. The local process identifier is read from the operating system.

Each frozen `Selection` binds exact artifact, instruction, policy and context
commitments, session identifier, actual local process identifier and generation.
These commitments do not preserve the corresponding bytes or establish payload
truth. The future native consumer must retain and check those bytes and the full
typed context. A `Grant` additionally freezes permission, revocation-view and
grant-evidence commitments, purpose, authority and nonce. Tickets freeze the
selection, permission and permission epoch. A successor has independently selected
operands and exactly the next generation in the same local process. Replacing an
operating-system process or recovering durable state is outside this implementation.

Construction selects an inactive slot. Callers must separately admit the configured
authority identifiers, external `GrantVerifier` implementation and `EntryObserver`
implementation plus observer identifier. Identifier equality is not admission.
Missing dependencies return UNKNOWN and create no active slot. The verifier must
check actual grant authenticity, purpose, external authority and a sufficiently
fresh revocation view under consumer-selected policy. These upstream checks are
explicit dependencies, not implementations hidden inside this runtime. Production
admission is not established by the test fixtures.

The grant verifier and observer are caller-supplied, separately admitted host
dependencies. They are never deserialized from carried evidence as callbacks.
Authority identifiers require exact plain strings of at most 256 characters;
length is checked before stripping. Every bounded authority-tuple element is
validated before the distinct-identifier set is hashed, so foreign hash callbacks
are not invoked during configuration capture.

An exact selected-tuple/purpose contradiction, revoked initial reactivation or
authority rejection under a present nonempty configured authority tuple is FAIL
before optional verifier/observer availability is considered. Missing optional
dependencies cannot conceal those independently decidable contradictions. The
default empty authority tuple means missing admission and remains UNKNOWN for an
otherwise neutral grant; it is not treated as a selected empty authorization list.

The grant verifier returns an immutable `GrantDecision` binding the exact grant
and epoch. After verifier and optional preparation callbacks, the host takes its
lock and rechecks epoch, selected generation/tuple, frozen intent, inactive state,
drain, queue/inflight census, local authority revocation and absence of a previous
successor commit. A changed cutoff prevents activation. Authority that issued the
revoked parent grant is permanently excluded from granting its successor. One
host object commits at most one successor. A distinct independently admitted
authority and successful external verification are required.

`queue` registers a finite exact ticket. `revoke` increments the permission epoch,
disables admission and clears queued admissions while retaining their historical
tickets. Already admitted preparation/entry remains in the inflight census until
the enclosing observer call actually finishes. A repeated cutoff increments the
epoch and invalidates pending grant preparation. A callback already entered before
cutoff may finish; it is not reported as preempted. `drain` requires an empty actual
registered census read by the selected observer and unchanged after that observer
callback. Empty producer counters alone do not complete observed drain.

`invoke` reserves admitted, uncancelled work under the lock and runs its preparation
outside the lock. The selected observer must synchronously attempt the boundary on the caller
thread and wrap actual supplied effect entry and exit. The host rechecks epoch,
generation, complete tuple, permission, cancellation and actual process under its
lock at the final entry after preparation and observer setup. The host then holds
that lock through the effect callback. Cross-thread revocation is ordered before
entry or after callback completion; reentrant local revocation does not undo work
already entered. The observer's entry/exit counts must match actual guarded calls.
A skipped attempt, missing record or producer `effect_called=false` is UNKNOWN.
Contradictory instrumentation or a bypass/duplicate attempt is FAIL. A refused,
actually observed stale attempt has PASS for the local refusal control and zero
callback entry; it has no permission grant or effect success.

The boundary covers callbacks registered through this slot only. The host cannot
contain arbitrary effects inside preparation/verifier/observer code, callbacks
invoked outside the API, privileged writes, unregistered threads or other host
processes. Those dependencies must be selected separately. No callback completion,
deadline, service availability, interruption, data destruction or BURN-erasure
claim follows from this lock or from cancellation. Caller callbacks can block;
duration and process containment remain outside this slice.

`select_successor` records a frozen `RestartIntent`; it does not activate it.
`reconcile` reads actual in-memory selection and active state. Intent alone, or
the same intent presented to a fresh host with no observed committed state, remains
UNKNOWN. Exact binding contradictions are FAIL. No persisted intent is silently
promoted to availability or restored permission.

The declared finite limits are queue length, inflight count and total registered
invocations, each at most 4,096; total event and observation records are each at
most 16,384. Defaults are 32 queued, 8 inflight, 128 invocations and 512 events.
Attempt count is bounded by the invocation limit. Event/observation exhaustion
halts new effects and activation; it does not erase existing records. Unavailability,
cancellation and exhaustion preserve any previously known FAIL. The final local
`assessment` requires initial admission, old revocation, observed drain, one external
successor grant, an actual observed stale refusal and actual successor entry/exit.
Incomplete coverage is UNKNOWN. These outcomes apply only to the named local
controls under the configured dependencies.

The full admitted preparation and observer lifetime has unconditional inflight
cleanup, including BaseException paths. Actual `asyncio.CancelledError` during
preparation, observation, callback entry, grant verification/preparation or drain
is cooperative cancellation: return UNKNOWN while retaining any sticky known FAIL.
Other BaseException aborts propagate after inflight cleanup. Neither outcome proves
preemption, erasure or absence of a partially entered callback. The terminal Result
census is captured after cleanup rather than retaining an abandoned inflight entry.

`Result` is frozen and always reports `scope=finite-local-permission-slot-controls`,
`native_corrigibility_conformance=NOT_ESTABLISHED`, and external authority/observer
admission dependencies. Its PASS cannot be used as whole Corrigibility PASS.
`census`, `trace` and `observations` return frozen records/tuples. `capture` returns
at most sixteen mebibytes of immutable canonical JSON bytes with local identifier
`verifier-local-permission-slot-observation-1`, exact events, terminal sequence,
trace commitment and retained grant/drain/entry observations. Capture repeats no
callback and establishes no independent authentication. The future native consumer
must strictly parse these bytes and verify separately admitted signed evidence.
There is currently no portable native certificate decoder or rechecker here.

`trace_commitment` hashes exact local event bytes. `check_trace` checks exact event
sequence and commitment against an independently selected terminal anchor without
repeating effects. Missing anchor is UNKNOWN; omission/substitution is FAIL.
Producer-selected anchors qualify only digest mechanics, never independent closure.

Public call surfaces:

| Surface | Result |
| --- | --- |
| `PermissionSlot(initial, *, authorities=(), verifier=None, observer=None, observer_id=None, max_queue=32, max_inflight=8, max_invocations=128, max_events=512)` | Inactive bounded host boundary |
| `grant(grant, *, prepare=None)` | Exact externally verified initial/successor activation or refusal |
| `queue(selection, invocation_id)` | Immutable Result with ticket on registration |
| `invoke(ticket, effect, *, prepare=None)` | Actual observed guarded callback/refusal |
| `revoke(expected)` / `drain()` / `cancel(ticket)` | Cutoff, actual observed drain, or cancellation request |
| `select_successor(successor)` / `reconcile(intent)` | Intent declaration / actual-state reconciliation |
| `census()` / `trace()` / `observations()` / `capture()` / `assessment()` | Immutable current observations and bounded claim limits |
| `trace_commitment(events)` / `check_trace(events, *, expected_digest, expected_sequence)` | Read-only exact trace mechanics |

The bounded test file supplies explicitly admitted fixture dependencies and real
callback wrappers. The controls cover lifecycle order, queued/inflight drain,
preparation/observer/grant races, old authority rejection, wrong artifact/instruction/
policy/context/session/process/generation/permission/epoch, duplicate activation
and entry, missing/stale observations, forged counters, moved/bypassed boundaries,
cancel/outage/exhaustion after FAIL, trace omission/substitution, fresh-host intent,
read-only capture and unrelated canary invariance. The fixture selection does not require optional providers.

The bounded test command is
`python -B -u -m pytest -vv -s --durations=10 --timeout=60 tests/test_permission_slot.py`
in an environment resolving the selected source or installed artifact bytes.
The fixtures exercise finite local controls; passing them supplies no external
authority or observer admission. One worker, ten minutes, one gibibyte
process-tree memory and offline fixtures are qualification bounds, not limits
enforced by this runtime. Strict native contract capture/recheck, mechanism
pins, dispatcher registration, objective mapping, complete family/applicability
census and production adoption remain separate unestablished obligations.

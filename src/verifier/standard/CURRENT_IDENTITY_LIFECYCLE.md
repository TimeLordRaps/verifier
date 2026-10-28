# Current selected declared identity lifecycle consistency

Verifier Standard (VSTD); simulation (SIM); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); central processing unit (CPU);
identifier (ID); Unicode Transformation Format, 8-bit (UTF-8).

This mechanism belongs to semantic version
`verifier-current-object-obligations-1`, objective `IDENTITY-2.1`, and scope
`finite_selected_declared_identity_lifecycle_consistency`.
It does not reinterpret historical numbered identity contracts.

The exact independently selected current IDENTITY-3.1 request, policy and full
certificate bytes must reproduce through the installed child checker. Subject,
object and collection commitments agree with the lifecycle selection. Its
reproduced actor, representation, HUMAN root, ROLE, COLLECTIVE and declared scope
agree with the immutable lifecycle binding. HUMAN, AGENT and BOT are explicit;
there is no legacy AGENT exclusion and no authentication from a HUMAN reference.

`identity-lifecycle-protocol-1` checks one selected binding and finite retained
history. The binding records one selected clock, inclusive `valid_from` and
exclusive `valid_until`, in nonnegative plain integer microseconds through
2^63-1. Boolean values are not integers. The externally selected renewal ceiling
is immutable within this selection. The external initial event anchor, final head
and count fix the selected finite history; a local chain digest proves no real
world completeness, independent issuer or clock truth.

Events have contiguous positions starting at zero, nondecreasing declared time,
unique IDs, the selected binding commitment and previous full event commitment.
The first event is enrollment at `valid_from`, or declared handover-in for a
distinct prior identity. Reverification, accepted presentation and renewal occur
while active and before the current exclusive end. Renewal strictly extends that
end within the selected ceiling and never reactivates an expired/revoked binding.
This extension is the new declared protocol's meaning, not legacy renewal replay.

One explicit terminal event is supported: revocation, expiry, handover-out,
HUMAN exit, BOT SIM-end or BOT SIM-supersession. It occurs no later than the
current end; explicit expiry equals that end. No explicit expiry record is needed
for half-open end validity. A further terminal/audit notification requires a
separately selected protocol; it cannot restore active status. Handover names a
distinct new identity without mutating the old binding. BOT terminal events name
the exact declared SIM/record and supersession names a distinct successor SIM.
HUMAN exit is limited to a represented HUMAN. Declared events do not authenticate
these events or prove paired new enrollment, actual SIM occurrence or exit effect.

Every selected presentation row must be matched exactly once to its event,
enrollment, binding, scope, clock, SIM, context and disclosure commitment.
Eligibility uses validity and any terminal event at or before presentation time.
A terminal at equal time wins even if serialized after the presentation. Later
termination preserves earlier valid history. An optional selected evaluation time
produces only declared current eligibility: it authenticates no clock or status.

A coherent terminated history may PASS lifecycle consistency while declared
relying eligibility is FAIL. The native outcome is PASS only when both the actual
selected IDENTITY-3.1 replay and all selected history checks complete PASS. Missing
child evidence, external anchor/head/count/clock selections, unsupported retained
binding/event/presentation protocol versions or event kinds, or exhausted checking
bounds are UNKNOWN. A wrong outer five-field evidence bundle version or canonical
encoding is FAIL; it is not an unsupported inner protocol interpretation.
Evaluated contradictions dominate
evaluated UNKNOWN; known failures and unrun descendants remain explicit. A malformed
external request/policy or forged/nonreproducing certificate refuses transport.
Neither incomplete nor rehashed carried results supply native acceptance.

Each present component's independently necessary grammar and exact commitment are
inspected before native child replay. Missing companions and unsupported component
semantics do not hide a contradiction in another supported present component.
Subject/record, selected clock, final head and event count refutations also precede
child callbacks. Available event-chain and event/presentation relationships are
checked with their available companions. Binding and events can still refute a
declared transition when the initial anchor or presentation inventory is missing;
that partial history supplies no consistency or eligibility completion.
Supported presentation rows also match the external binding commitment, and match
the supported present binding's clock, scope and SIM independently of absent events
or unrelated unsupported records. Missing event chronology, enrollment and
eligibility remain unavailable; no partial completion is granted. Resource
fences may stop further inspection; already evaluated FAIL remains FAIL. Absent
native replay supplies no native relation facts or aggregate PASS.

Request fields are exactly `schema_version`, `semantic_version`, `coordinate`,
`proposition_digest`, `object_kind`, `subject_id`, `object_digest`,
`collection_digest`, `protocol_id`, `identity_scope_request`,
`identity_scope_certificate_ref`, `binding_digest`, `events_digest`,
`presentation_inventory_digest`, `initial_event_anchor`, `selected_head_digest`,
`selected_event_count`, `clock_id`, `evaluation_at`, `renewal_ceiling`,
`evidence_ref`, `policy_digest`, and `limits`. The selected
policy fixes the installed lifecycle source, replay helper, core implementation,
this specification, `schemas/identity_lifecycle_evidence.json`, the shared domain
unavailability definitions and the child mechanism's recursive source/specification
closure, plus the independently selected complete IDENTITY-3.1 policy. Requests
embed the full externally selected child request and exact child certificate byte
reference. Candidate evidence never selects a child policy or import.
Policy fields are exactly `schema_version`, `mechanism_id`, `mechanism_digest`,
`trust_roots`, `identity_scope_policy`, and `max_certificate_bytes`. Trust-root
labels remain selection assumptions and do not authenticate the selector.
All public constructors, build and recheck own the complete plain nested request,
policy, roots, child selections and limits before installed source readers or child
callbacks. Foreign containers and unbounded external selections refuse transport.
`registration()` returns an owned copy of the selected proposition; its descriptor
grants no route installation, profile closure or qualification credit.

`verifier-current-identity-declared-lifecycle-evidence-1` has exactly
`schema_version`, `binding`, `events`, `presentations`, and
`identity_scope_certificate`. The last is the complete canonical child certificate
map or null when unavailable. `binding`, `events` and `presentations` retain the
exact protocol schemas in the installed replay helper; their canonical commitments
are externally selected. The event initial anchor and final head are SHA-256
commitments with `sha256:` prefix in the request; protocol record digest fields use
lowercase 64-hex, and support locator fields use `sha256:` prefix. Encoding uses
sorted-key compact ASCII-escaped JSON encoded as UTF-8 with nonfinite values and
duplicate keys refused. A separately versioned future closure evidence format is
required for authority/support inventories; it cannot reinterpret this schema.
The installed JSON schema closes these five outer fields and retained record field
layouts with event/presentation array ceilings of 1,024. It is explicitly structural:
it does not define unknown version/kind semantics or validate native plain types,
commitments, transitions, child reproduction or authority. The native evaluator is
authoritative; a work-ceiling rejection means unavailable checking, not a semantic
refutation. Record payload and value grammar remain the exact replay helper's
supported protocol rules.
Its identifier is the canonical published schema route
`https://timelordraps.github.io/verifier/schemas/identity_lifecycle_evidence.json`.

The certificate retains the full evidence, selected request and mechanism policy
commitments. Public recheck uses the independent request/policy, replays the actual
child and lifecycle mechanisms and compares all rebuilt certificate bytes.
Redaction, rehashed PASS fields and replacement dependency bytes refuse admission.
Independent envelope, carried result shape, fixed scope/NOT_ESTABLISHED claim
boundaries, evaluation selections and digest are checked before replay availability.
Recursion/overflow or unavailable installed checking does not become malformed
evidence FAIL. A direct public recheck whose capacity is unavailable raises
`IdentityLifecycleUnavailable`, an `OSError` subtype; it returns no carried PASS.
A genuine semantic `ValueError`, substituted certificate or independently false
claim remains a transport refusal. A resource-generated UNKNOWN rebuild mismatch
is unavailable only after those independent transport checks. This also applies
when a carried FAIL and freshly evaluated local FAIL agree, but unavailable child
or replay capacity prevents exact certificate reproduction. The evaluated FAIL is
preserved; public recheck returns no carried result. A carried PASS contradicted
by fresh local FAIL, or a genuine fresh semantic refusal, remains a transport
refusal even when another checked phase was unavailable. Natural missing
support or selected-work UNKNOWN certificates still require exact reproduction.

Selected ceilings are 1,024 events, 1,024 presentations and 100,000 declared replay
steps. A step counts initial or binding-grammar entry, each checked binding identifier
or attribute ID, each presentation-row or event visit (including independent
grammar, chain/duplicate sweeps and subsequent replay), each payload field, each
available event/presentation or binding/presentation relationship, and each presentation or current
eligibility calculation. Repeated phases count repeated visits; these are not
machine instructions. Child replay
has its own exact selected bounds, enforced by the installed child. Full lifecycle
evidence is at most 4 MiB and certificate at most 8 MiB; one MiB is 1,048,576 bytes.
Before recursive retained JSON decoding or hashing, fixed structural guards bound
depth to 64, each container to 4,096 entries and the scan to 100,000 structural
nodes; unquoted JSON atoms are at most 256 bytes. Plain helper inputs have the same
depth/container/node bounds, at most 8 MiB aggregate UTF-8 text and integers at most
256 bits before protocol-specific plain integer checks. External owned captures use
those structural bounds, at most 4 MiB per string and 8 MiB aggregate UTF-8 text.
These guards are capacity fences, without JSON validity or protocol acceptance.
These are dimensionless counters/encoded bytes, without wall-time or CPU guarantee.
Declared microseconds and the 2^63-1 bound assert no equivalence to a TIME clock
coordinate, physical clock observation or alternative 2^53 numeric convention.

Real personhood/issuer authority, live occupancy, observed clock, real complete
history/nonrevocation, paired-recipient enrollment, actual SIM occurrence or
containment, unilateral exit enforcement, assurance, attribute sources, privacy,
public checkability, complete IDENTITY closure and object polish remain
NOT_ESTABLISHED. IDENTITY-4 needs independently admitted purpose-specific support
for those stronger applicable predicates. Generic NAMESPACE_ADMIT and secret-key
inventory admission do not supply it. HUMAN-7.3 temporal PASS does not establish
terminal ALLOW or exit enforcement; historical 7.5 does not grant current admission.

A selected certificate byte checking ceiling raises IdentityLifecycleUnavailable. A foreign byte type or semantic substitution remains IdentityLifecycleError. The helper retains verifier-private-declared-lifecycle-replay-1 as its internal diagnostic version; that diagnostic establishes no independent public route or closure.

# Exact public authority for the new polish issuance operation

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

**Status:** experimental configured-public-key authority prerequisite; full issuance and production acceptance are separate. JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Edwards-curve digital
signature algorithm with a 255-bit field (Ed25519); hash-based message authentication
code (HMAC); Unicode Transformation Format, 8-bit (UTF-8); identifier (ID).
Time uses integer Unix seconds;
all byte caps count encoded bytes. This is not a numbered native objective.

`assess_polish_authority(subject_bytes, *, context_bytes, evidence_bytes,
trusted_policy_bytes, expected_trusted_policy_digest, evaluation_time)` authenticates
one exact `ISSUE_POLISHED_ARTIFACT` subject. Policy bytes and expected digest come
from the host's authenticated operator configuration, separately from candidate
evidence. A caller passing its own candidate policy has not authenticated that
selection. Every root/scope change requires fresh configured policy selection and
recheck; producer-carried roots never bootstrap authority.

The signature attests the configured key's exact scoped statement. It does not
establish source completeness, computation, living humans, legal authority,
person-separated voting, consent, public predicate proof, or ledger consumption.
The new issuance mechanism must independently check each of those required gates.
This prerequisite always returns `polished=false` and
`invocation_consumption=NOT_PERFORMED`. Retained HMAC finite inventory authority,
namespace admission, consent, and operator-stop operations retain separate meanings.

All transports are plain immutable canonical UTF-8 JSON objects with no duplicate,
additional, or nonfinite fields, at most 1,048,576 bytes each. The inherited bounded
canonical decoder enforces depth 48, 100,000 values and 4,096-bit integer limits.
Malformed or fixed transport-bound input refuses as FAIL. Finite decoder/checker
capacity exhaustion is UNKNOWN with AUTHORITY_RESOURCE_BOUND_EXHAUSTED and preserves
previously established failures. IDs are nonblank strings of at most
256 characters. Timestamps are plain integers in [0, 2^63); booleans refuse.
There are at most 256 keys, scopes, decisions and identifiers per status list.
The assessment is at most 1,048,576 bytes; output capacity exhaustion is UNKNOWN.

`verifier-polish-public-authority-policy-1` has exactly:
`schema_version mechanism_digest policy_id revision keys voting_key_ids status_key_id
quorum veto_actor_ids scopes effective_from effective_until max_status_age_seconds`.
Each key has exactly `key_id actor_id public_key`; public_key is canonical 32-byte
lowercase hex, screened by the installed public-key admission primitive. Keys and
key IDs are distinct; voting actor IDs are distinct; the status key is separate
from voting keys. Quorum is an achievable positive plain integer. Veto actors belong
to the electorate. Policy interval is half-open and nonempty; revision is positive.

Each exact scope has `operation application_id profile_digest source_scope_digest
collection_digest jurisdiction ledger_id policy_domain policy_epoch`. No wildcard operation/profile/source or
application fallback is supported. These scopes are operator-authorized policy
terms, not candidate-selected evidence or claims that laws were enforced.

`verifier-polish-public-authority-context-1` has exactly:
`schema_version mechanism_digest subject_digest policy_digest operation application_id
profile_digest source_scope_digest collection_digest actor_id observer_id purpose
jurisdiction timestamp invocation_id ledger_id policy_domain policy_epoch`.
Digests are `sha256:` plus lowercase 64-hex. The subject is the exact canonical
new-issuance signing subject independently reconstructed by the issuer; its
operation/application/profile/source/collection/ledger/domain/epoch fields match the context.
This authority checker does not interpret a generic subject as completeness.

Evidence is exactly `{decisions, status}`, with bounded decisions and nullable
status. The envelope `verifier-polish-public-authority-envelope-1` has exactly
`schema_version algorithm key_id payload payload_digest signature`; algorithm is
Ed25519, signature canonical 64-byte lowercase hex. The signature message is
`b"vstd-polish-public-authority-ed25519-1" + bytes([0])` followed by canonical JSON of the
envelope excluding signature. It cannot authenticate consent, namespace admission,
or an earlier retained polish contract by matching a label.

Decision payload `verifier-polish-public-authority-decision-1` has exactly
`schema_version decision_id actor_id context_digest policy_digest issued_at
expires_at decision`. Signed context digest binds the entire operation, subject,
caller, observer, purpose, exact action time, jurisdiction, invocation and ledger.
Duplicate IDs/actors, unconfigured or nonvoting keys, key/actor mismatch, submitter
self-approval, wrong bindings, ineffective intervals, invalid signatures and
unsupported decision kinds FAIL. Authenticated DENY or configured VETO FAIL.
APPROVE contributes at most one vote per configured actor.

Status payload `verifier-polish-public-authority-status-1` has exactly
`schema_version policy_digest ledger_id policy_domain policy_epoch observed_at expires_at revoked_decisions
revoked_actors consumed_invocations`. A distinct configured status key signs it.
Known revoked decision/actor or consumed invocation FAIL. The status interval is
half-open. Absent clock/policy/quorum/status, stale status, unavailable exact backend,
or missing installed source is UNKNOWN. A known failure dominates such UNKNOWN.
Checking a current consumed list is read-only; it cannot close races or perform
atomic consumption. Final issuance separately compares/consumes in the exact trusted
ledger transaction and records the immutable result.

The optional signature backend is `cryptography==50.0.0`, matching this checkout's
existing optional dependency pin. Missing/mismatched/unsupported backend is UNKNOWN;
invalid supported signatures are FAIL. No signing key is loaded or generated here.

`verifier-polish-public-authority-assessment-1` carries exact input and mechanism
digests, evaluation time, actor set, fixed reason codes and canonical assessment
digest. It is replayable only when all captured source/input bindings are retained.
`recheck_polish_authority` recomputes with externally selected current roots/clock
and compares canonical bytes; `verifier-polish-public-authority-replay-1` reports
REPRODUCED or REJECTED with scoped PASS/FAIL/UNKNOWN. Reproducing an UNKNOWN does not
admit issuance. The assessment is a local computational report, not a signature
over historical execution, and contains neither HMAC secrets nor protected witness
bytes. Human acceptance and hosted promotion remain separately required.


## Exact ledger policy generation and local contradictions

The context, subject scope, each admitted policy scope and signed status bind
`ledger_id`, `policy_domain` and positive plain integer `policy_epoch` together.
The issuer independently compares all three with its authenticated host ledger
selection. Policy/root/status rotations advance that same ledger's epoch before
new admission; changing ledger path or identifier is not permitted as a replay
reset. This helper authenticates the submitted generation, not host provisioning.

Plain bounded external time is validated before retaining it or hashing a report.
Invalid clock objects yield a bounded FAIL record without storing their value.
Even without trusted policy, duplicate submitted decision identifiers/actor
identifiers, exact context/policy commitment mismatches and status generation
scope mismatches are demonstrated local contract contradictions and FAIL. An
unauthenticated APPROVE, DENY or consumed-list assertion has no authority force.
Later finite capacity exhaustion preserves an earlier demonstrated contradiction.

Before optional signature verification, a present decision interval that excludes
the validated external action time is a demonstrated input contradiction and FAIL,
including when trusted policy is absent. After separately selected exact policy
bytes are validated and pinned, nonvoting/unconfigured decision-key claims,
key-to-actor mismatch, submitter self-decision, VETO outside the configured veto
electorate and use of another key for the status role are also demonstrated
policy/input contradictions and FAIL before unavailable backend classification.
Cheap screens authenticate no actor, vote, denial, revocation or consumed-list
claim. A well-shaped APPROVE, DENY, configured VETO or revocation/consumption list
without actual signature verification remains unauthenticated and cannot establish
authority. Real optional Ed25519 verification and every existing scope, quorum,
freshness and revocation gate remain mandatory for PASS.

## Separate finite operation and exact replay availability correction

The additive explicitly named `ISSUE_FINITE_OBJECT_RECORD` operation signs the
separate finite OBJECT-1.1 record issuance subject. The existing
`ISSUE_POLISHED_ARTIFACT` operation and all original signing envelope/prefix,
fields, policy roots, scope/purpose/quorum/veto/status checks remain unchanged.
One exact policy scope still names one exact operation. A full vote cannot be
reused for the finite operation, nor a finite vote promoted to full polish.
The finite issuer always retains polished=false/full_application_status UNKNOWN.

Recheck first validates the closed bounded canonical retained replayable report,
its complete body commitment, explicit claim boundary and exact input pins. It
admits all current transport types/bounds before hashing any selected sibling.
Available changed subject/context/evidence/policy bytes, historical time or
independent policy pin refuse before missing source/backend/input can dominate.
Missing originally committed input or current source/backend/capacity prevents
exact reconstruction and yields UNKNOWN/UNAVAILABLE, never carried PASS or
REPRODUCED. A newly observed current FAIL remains FAIL even if later source I/O
unavailability makes that assessment nonreplayable. Narrow OSError/ImportError
availability is not a blanket reinterpretation of semantic ValueError refusal.
Exact reproduced UNKNOWN/FAIL retain their own status and do not admit issuance.
Changed installed source/spec hashes require fresh independently selected
policy/context/signature admission; prior reports supply no current admission.

## Cancellation and source order

Available bounded contradictions precede source or backend availability.
These guards authenticate no statement and grant no positive credit.

After every explicit transport bound, assess checks plain context schema/types,
operation/subject/scope commitments, evidence payload/binding/time contradictions,
the present policy's pure schema/key/role/scope/interval admission, independent
policy selection and known selected role/scope/time contradictions before installed
source reconstruction. `_policy(..., check_mechanism=False)` is an internal pure
screen used by authority/finite admission; it grants no statement, vote, source,
revocation, consumption or PASS. Fresh mechanism equality remains mandatory before
actual signature verification and any replayable positive assessment. Missing
policy/source with no independently available contradiction remains UNKNOWN.

Decision, status, outer decoder/source work and final report formatting treat
`asyncio.CancelledError` as unavailable capacity. The report preserves every already
observed FAIL, otherwise returns UNKNOWN; capacity/cancellation reports are
nonreplayable. Cancellation never authenticates an APPROVE, DENY, VETO, revocation
or consumed ID. Semantic/structural `ValueError` remains refusal. A cancelled source
cannot supply a fresh mechanism pin; captured input digests remain metadata only.

Rechecker first retains its closed bounded report/body/claim/input/time/policy
guards. Fresh cancellation without a demonstrated contradiction is typed
UNKNOWN/UNAVAILABLE, never a carried old PASS. A freshly observed FAIL persists if
later replay/output work is cancelled. A present false interval remains a fresh
FAIL during source loss; a stored FAIL alone with missing original evidence does
not establish a new result. Finding-specific controls use real prior positive
fixtures and negative-only cancellation/refusal callbacks, never positive mocks.

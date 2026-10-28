"""Finite source-bound worker PROTOCOL checks for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) payloads carry the bounded worker observations.

The subject is the installed dispatcher, not an arbitrary distributed protocol.
Fault injection replaces only its transport edge in a private worker. Real peer
exchanges are separate controls. Neither establishes host authentication,
message authority, confinement, liveness under all faults, or complete kind
conformance. Those two are declared NOT_ESTABLISHED and are never simulated to PASS.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-worker-protocol-1"
SEMANTIC_VERSION = "verifier-worker-protocol-obligations-2"
IMPLEMENTATION = "src/verifier/runtime/package_execution.py"
WORKER = "worker_protocol_worker.py"
REQUEST_SCHEMA = "verifier-worker-protocol-request-1"
OBSERVATION_SCHEMA = "verifier-worker-protocol-observations-1"
# The fixed specimen makes two sequential peer launches, each with the
# dispatcher's 30-second deadline, before completing its bounded fault matrix
# and final source recapture.  Its outer owner therefore needs a strictly wider
# finite window; the dispatcher independently caps declarations at 90 seconds.
WORKER_TIMEOUT_SECONDS = 90
# Declared version pairs. The peer pair is what the parent accepts from the fixed ledger worker.
# Negotiation is exact-match only: no range is offered, so a superseded version is refused.
COMPATIBILITY = {
    "protocol_request": REQUEST_SCHEMA,
    "protocol_observation": OBSERVATION_SCHEMA,
    "peer_request": "verifier-local-ledger-execution-request-1",
    "peer_observation": "verifier-local-ledger-execution-observations-1",
    "negotiation": "exact-declared-version-or-refusal",
}
# Participants and the single legal attempt: CREATED_REQUEST -> LAUNCHED_FIXED_WORKER -> one terminal state.
# An attempt with no launch has an empty transcript and is NOT_LAUNCHED.
PARTICIPANTS = {"CREATED_REQUEST": "parent_dispatcher", "LAUNCHED_FIXED_WORKER": "fixed_worker",
                "DECODED_BOUND_REPLY": "parent_dispatcher", "REJECTED_REPLY": "parent_dispatcher",
                "FAILED_TRANSPORT": "parent_dispatcher"}
TERMINAL_STATES = frozenset({"DECODED_BOUND_REPLY", "REJECTED_REPLY", "FAILED_TRANSPORT"})
RECOVERY = {"DECODED_BOUND_REPLY": "NOT_REQUIRED", "FAILED_TRANSPORT": "NO_RETRY_UNAVAILABLE",
            "REJECTED_REPLY": "NO_RETRY_REFUSED", "NOT_LAUNCHED": "NOT_ATTEMPTED"}
PARENT_OUTCOMES = {"DECODED_BOUND_REPLY": {"ACCEPTED"}, "REJECTED_REPLY": {"REJECTED"},
                   "FAILED_TRANSPORT": {"TIMEOUT", "NONZERO_EXIT"}, "NOT_LAUNCHED": {None}}
NOT_ESTABLISHED = {
    "message_authority": "No sender authentication: a reply is bound to the request identity and pinned source bytes, not to an authenticated host or worker principal.",
    "liveness": "No progress guarantee under arbitrary faults: a timeout or nonzero exit yields unavailability after one attempt, not eventual completion.",
}
BOUNDARY = ("Finite installed dispatcher executions with two actual private ledger-worker exchanges and injected transport faults, "
            "each attempt recorded as an ordered transcript. Message authority and liveness are NOT_ESTABLISHED. "
            "Not distributed agreement, host authentication, sandboxing, bounded subprocess capture memory, full kind conformance or package polish.")
_CONTRACTS = (
    ("PROTOCOL-1.1", "fixed-worker-selection", 1,
     "Participant identities, roles, states and transitions must be executable properties of the source-bound exchange; selection must not turn into caller-selected commands or inherit an arbitrary subject import environment.",
     "The installed parent dispatcher and fixed ledger worker perform, per exchange, CREATED_REQUEST to LAUNCHED_FIXED_WORKER to DECODED_BOUND_REPLY as a monotonic transcript observed at the transport edge, with fixed interpreter flags, pinned worker bytes, closed request fields, bounded transport configuration, sequential non-interleaved exchanges and a parent_record verified against the decoded reply."),
    ("PROTOCOL-1.2", "response-envelope", 1,
     "Malformed, truncated or differently versioned replies cannot be evidence for the selected exchange.",
     "Wrong or superseded schema version, missing or extra envelope fields, duplicate keys, non-object output, truncated JSON and invalid encoding are each refused as REJECTED_REPLY with one launch, no retry and a parent_record outcome of REJECTED; only the exact declared peer schema is accepted."),
    ("PROTOCOL-2.1", "fresh-exchange", 2,
     "A valid reply for a different request, subject or collection must not be replayed as current evidence.",
     "Two actual exchanges bind distinct fresh nonces; stale nonce, object identifier, object digest and collection digest substitutions are refused as REJECTED_REPLY."),
    ("PROTOCOL-2.2", "failure-without-retry", 2,
     "Uncertain transport completion neither supplies a reply nor authorizes an automatic repeat execution.",
     "Injected timeout and nonzero exit terminate in FAILED_TRANSPORT after exactly one launch with recovery NO_RETRY_UNAVAILABLE and a parent_record outcome of TIMEOUT or NONZERO_EXIT; a forged retry, forged recovery or any extra transition is refused."),
    ("PROTOCOL-3.1", "executable-source-binding", 3,
     "Request identity alone cannot bind observations to the selected executable implementation.",
     "Unavailable selected source yields NOT_LAUNCHED with no transport call; substituted peer source pins and source change at final recapture refuse the reply as REJECTED_REPLY."),
    ("PROTOCOL-3.2", "response-capacity", 3,
     "The accepted response size must obey its explicit byte boundary rather than depend on the apparent status inside it.",
     "A correctly bound response at 1048576 bytes is accepted with a parent_record outcome of ACCEPTED; one byte above is refused as REJECTED_REPLY. This is an acceptance bound, not a streaming memory bound."),
)


def catalog() -> list[dict[str, Any]]:
    return [{"coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
             "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": "PROTOCOL",
             "tier": tier, "reason": reason, "exact_claim": claim, "semantic_version": SEMANTIC_VERSION,
             "proposition_digest": value_digest({"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
             "checking_mechanism": "verifier.runtime.worker_protocol_execution.evaluate",
             "scope": "fresh_worker_protocol_" + slug.replace("-", "_"), "adapter": ADAPTER,
             "not_established": dict(NOT_ESTABLISHED)}
            for coordinate, slug, tier, reason, claim in _CONTRACTS]


def _refused(row: dict[str, Any], exception: str, reason: str | None = None, *, calls: int = 1) -> bool:
    return (type(row["calls"]) is int and row["calls"] == calls and row["exception"] == exception
            and row["returned"] is False and (reason is None or row["reason"] == reason))


def _attempt_state(events: Any) -> str | None:
    """Terminal state of one legal attempt; None for missing, skipped, reordered, duplicate or unknown states."""
    if type(events) is not list:
        return None
    if not events:
        return "NOT_LAUNCHED"
    if len(events) != 3 or any(type(event) is not dict for event in events):
        return None
    created, launched, final = events
    if (set(created) != {"seq", "state", "participant"} or set(launched) != {"seq", "state", "participant", "worker_sha256"}
            or set(final) != {"seq", "state", "participant"}):
        return None
    if (created["state"], created["participant"]) != ("CREATED_REQUEST", PARTICIPANTS["CREATED_REQUEST"]):
        return None
    if (launched["state"], launched["participant"]) != ("LAUNCHED_FIXED_WORKER", PARTICIPANTS["LAUNCHED_FIXED_WORKER"]):
        return None
    if final["state"] not in TERMINAL_STATES or final["participant"] != PARTICIPANTS["DECODED_BOUND_REPLY"]:
        return None
    seqs = [event["seq"] for event in events]
    if any(type(seq) is not int for seq in seqs) or not seqs[0] < seqs[1] < seqs[2]:
        return None
    if type(launched["worker_sha256"]) is not str:
        return None
    return final["state"]


def _participant_state_machine(real: Any) -> bool:
    """Recheck the finite parent/worker roles and their request-to-reply identities."""
    if type(real) is not list or len(real) != 2:
        return False
    requests = [row.get("request") for row in real if type(row) is dict]
    if len(requests) != 2 or any(type(request) is not dict for request in requests):
        return False
    nonces = [request.get("nonce") for request in requests]
    stable_fields = ("object_id", "object_digest", "collection_digest")
    return (
        len(set(nonces)) == 2
        and all(
            type(nonce) is str
            and len(nonce) == 64
            and set(nonce) <= set("0123456789abcdef")
            for nonce in nonces
        )
        and all(requests[0].get(field) == requests[1].get(field) for field in stable_fields)
        and all(
            row["worker"] == "local_ledger_worker.py"
            and row["flags"] == ["-I", "-S", "-B"]
            and row["interpreter_matches"] is True
            and {"TEMP", "TMP", "TMPDIR"} <= set(row["environment_keys"])
            and set(row["environment_keys"])
            <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATH"}
            and canonical_bytes(row["parameters"])
            == canonical_bytes({"capture_output": True, "timeout": 30, "check": False})
            and set(row["request"])
            == {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}
            and row["request"]["schema_version"] == COMPATIBILITY["peer_request"]
            and row["reply_request"] == row["request"]
            for row in real
        )
    )


def _exchanges_transcribed(observed: dict[str, Any]) -> bool:
    """Each real exchange is one legal attempt; exchanges never interleave and bind the pinned worker bytes."""
    real, identities = observed.get("real"), observed.get("identities")
    fixed = identities.get("fixed_worker") if isinstance(identities, dict) else None
    if type(real) is not list or not isinstance(fixed, dict):
        return False
    previous_last = -1
    for row in real:
        events = row.get("transcript")
        if _attempt_state(events) != "DECODED_BOUND_REPLY":
            return False
        if events[1]["worker_sha256"] != fixed["sha256"] or events[0]["seq"] <= previous_last:
            return False
        previous_last = events[-1]["seq"]
    return True


def _parent_records_verified(observed: dict[str, Any]) -> bool:
    """Parent-side execution records must verify against the decoded reply of the same exchange."""
    from verifier.runtime import local_ledger_execution as peer
    from verifier.runtime.package_execution_observation import verify_accepted
    item = SimpleNamespace(object_id=observed["item"]["object_id"], digest=observed["item"]["object_digest"])
    for row in observed["real"]:
        try:
            verify_accepted(row.get("parent_record"), row.get("reply"), selection=observed["selection"], item=item,
                            collection_digest=observed["collection_digest"], module=peer)
        except (OSError, ValueError, TypeError, KeyError):
            return False
    return True


def _fault_terminal(row: dict[str, Any], state: str, *, calls: int) -> bool:
    """A fault row must reach exactly the expected terminal state with its derived recovery and parent outcome."""
    if type(row) is not dict or _attempt_state(row.get("transcript")) != state:
        return False
    parent = row.get("parent_record")
    parent_outcome = None if parent is None else parent.get("outcome")
    return (row["calls"] == calls and row["recovery"] == RECOVERY[state]
            and parent_outcome in PARENT_OUTCOMES[state])


def _malformed_refused(row: dict[str, Any], exception: str, reason: str | None = None) -> bool:
    return _refused(row, exception, reason) and _fault_terminal(row, "REJECTED_REPLY", calls=1)


def _capacity_refused(row: dict[str, Any]) -> bool:
    """Output-capacity refusal: typed OSError, one launch, REJECTED_REPLY, and the parent's capacity outcome.

    The parent records OUTPUT_CAP_EXCEEDED rather than the generic REJECTED of reply validation, so an
    oversize reply is never confused with a malformed or mismatched one. No retry follows either.
    """
    parent = row.get("parent_record")
    return (_refused(row, "OSError", "PACKAGE_EXECUTION_OUTPUT_CAPACITY")
            and _attempt_state(row.get("transcript")) == "REJECTED_REPLY"
            and row["recovery"] == RECOVERY["REJECTED_REPLY"]
            and type(parent) is dict and parent.get("outcome") == "OUTPUT_CAP_EXCEEDED")


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Check captured inputs, transcripts and outcomes without calling the subject or worker."""
    real, faults = observed["real"], observed["faults"]
    if coordinate == "PROTOCOL-1.1":
        return (_participant_state_machine(real) and _exchanges_transcribed(observed)
                and _parent_records_verified(observed))
    if coordinate == "PROTOCOL-1.2":
        return (_participant_state_machine(real)
                and all(_malformed_refused(faults[name], "ValueError", "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")
                        for name in ("schema", "downgrade", "missing", "extra", "nonobject"))
                and _malformed_refused(faults["duplicate"], "StrictJsonError")
                and _malformed_refused(faults["truncated"], "JSONDecodeError")
                and _malformed_refused(faults["encoding"], "UnicodeDecodeError"))
    if coordinate == "PROTOCOL-2.1":
        nonces = [row["request"]["nonce"] for row in real]
        return (len(real) == 2 and len(set(nonces)) == 2
            and all(type(nonce) is str and len(nonce) == 64 and set(nonce) <= set("0123456789abcdef") for nonce in nonces)
            and all(row["reply_request"] == row["request"] for row in real)
            and all(_malformed_refused(faults[name], "ValueError", "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")
                    for name in ("nonce", "object_id", "object_digest", "collection_digest")))
    if coordinate == "PROTOCOL-2.2":
        return (_refused(faults["timeout"], "TimeoutExpired")
                and _fault_terminal(faults["timeout"], "FAILED_TRANSPORT", calls=1)
                and _refused(faults["exit"], "OSError", "PACKAGE_EXECUTION_WORKER_UNAVAILABLE")
                and _fault_terminal(faults["exit"], "FAILED_TRANSPORT", calls=1))
    if coordinate == "PROTOCOL-3.1":
        return (_refused(faults["selected_source"], "OSError", "PACKAGE_EXECUTION_SOURCE_UNAVAILABLE", calls=0)
                and _fault_terminal(faults["selected_source"], "NOT_LAUNCHED", calls=0)
                and all(_malformed_refused(faults[name], "ValueError", "PACKAGE_EXECUTION_SOURCE_CHANGED")
                        for name in ("peer_source", "recapture")))
    if coordinate == "PROTOCOL-3.2":
        row = faults["at_capacity"]
        return (row["returned"] is True and row["exception"] is None
                and type(row["calls"]) is int and row["calls"] == 1
                and row["response_bytes"] == 1048576 and type(row["response_bytes"]) is int
                and _fault_terminal(row, "DECODED_BOUND_REPLY", calls=1)
                and faults["over_capacity"]["response_bytes"] == 1048577
                and _capacity_refused(faults["over_capacity"]))
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound
    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected
    return evaluate_selected(snapshot, item, route)

"""Finite declared single-binding identity lifecycle replay.

The native wrapper independently selects and replays IDENTITY-3.1. This helper
checks retained grammar, commitments and declared time; it authenticates no human,
issuer, clock, event, status head or authority. JavaScript Object Notation (JSON);
American Standard Code for Information Interchange (ASCII); identifier (ID).
No filesystem, subprocess, network or candidate callback is executed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

TIME_MAX = (1 << 63) - 1
BINDING_VERSION = "verifier-current-identity-lifecycle-binding-1"
EVENT_VERSION = "verifier-current-identity-lifecycle-event-1"
PRESENTATION_VERSION = "verifier-current-identity-presentation-1"
BINDING_FIELDS = {
    "schema_version", "identity_id", "identity_record_digest", "actor_id",
    "representation_id", "represented_kind", "root_human_id", "role_id",
    "collective_id", "scope", "clock_id", "valid_from", "valid_until",
    "simulation_id", "simulation_record_digest", "assurance_requirement_id",
    "relied_attribute_ids", "revocation_policy_id", "human_exit_policy_id",
}
EVENT_FIELDS = {
    "schema_version", "event_id", "position", "binding_digest",
    "previous_event_digest", "kind", "at", "payload", "authority_evidence_ref",
}
PRESENTATION_FIELDS = {
    "schema_version", "presentation_id", "event_id", "binding_digest",
    "enrollment_id", "at", "clock_id", "scope", "simulation_id",
    "context_digest", "disclosed_field_inventory_digest", "linkability_claim",
    "linkability_support_requirement_id",
}
PAYLOAD_FIELDS = {
    "enrollment": {"enrollment_id", "support_inventory_digest"},
    "reverification": {"verification_id", "support_inventory_digest"},
    "renewal": {"new_valid_until", "support_inventory_digest"},
    "presentation": {"presentation_id", "presentation_digest"},
    "revocation": {"revocation_id", "reason_ref"},
    "expiry": set(),
    "handover_out": {"handover_id", "replacement_identity_id",
                     "replacement_binding_digest", "handover_pair_digest"},
    "handover_in": {"handover_id", "prior_identity_id", "prior_binding_digest",
                    "handover_pair_digest", "support_inventory_digest"},
    "simulation_end": {"simulation_id", "simulation_record_digest",
                       "simulation_event_ref"},
    "simulation_superseded": {"simulation_id", "simulation_record_digest",
                              "successor_simulation_id", "simulation_event_ref"},
    "human_exit": {"exit_request_ref", "exit_control_rule_digest"},
}
TERMINAL = {"revocation", "expiry", "handover_out", "simulation_end",
            "simulation_superseded", "human_exit"}


def _digest(value: Any) -> str:
    # Same ASCII canonical codec as verifier.core.certificate:106-113.
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _time(value: Any) -> bool:
    return type(value) is int and 0 <= value <= TIME_MAX


def _text(value: Any, maximum: int = 256) -> bool:
    return type(value) is str and 0 < len(value) <= maximum and bool(value.strip())


def _hex(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value
    )


def _ref(value: Any) -> bool:
    return type(value) is str and value.startswith("sha256:") and _hex(value[7:])


class _Stop(Exception):
    def __init__(self, status: str, message: str, *, exhausted: bool = False):
        self.status = status
        self.message = message
        self.exhausted = exhausted


def _plain_fence(value: Any) -> None:
    """Bound plain retained containers before any recursive canonical hash."""
    pending = [(value, 0)]
    nodes = text_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 100000 or depth > 64:
            raise _Stop("UNKNOWN", "retained plain depth/node bound exhausted", exhausted=True)
        if type(item) is dict:
            if len(item) > 4096:
                raise _Stop("UNKNOWN", "retained map bound exhausted", exhausted=True)
            for key, child in item.items():
                if type(key) is not str:
                    raise _Stop("FAIL", "retained plain text key required")
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > 4096:
                raise _Stop("UNKNOWN", "retained array bound exhausted", exhausted=True)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > 8 * 1024 * 1024:
                raise _Stop("UNKNOWN", "retained text bound exhausted", exhausted=True)
        elif type(item) is int:
            if item.bit_length() > 256:
                raise _Stop("UNKNOWN", "retained integer bound exhausted", exhausted=True)
        elif item is not None and type(item) is not bool:
            raise _Stop("FAIL", "plain bounded retained JSON required")


def replay_declared_identity_lifecycle(
    binding: Any, events: Any, presentations: Any, *,
    expected_binding_digest: str, expected_events_digest: str,
    expected_presentations_digest: str, initial_event_anchor: str | None,
    evaluation_at: int | None, renewal_ceiling: int,
    max_events: int = 1024, max_presentations: int = 1024,
    max_steps: int = 100000,
) -> dict[str, Any]:
    """Return bounded declared results, never authority or closure PASS.

    Selections are caller-external assumptions. Malformed selections raise
    ValueError; retained contradictions yield FAIL, unavailable/unsupported
    inputs or exhausted bounds UNKNOWN. An evaluated refutation survives later
    exhaustion. Public wrappers must enforce canonical byte and object limits
    before decoding and bind these selections to the exact native request.
    """
    selected = (expected_binding_digest, expected_events_digest, expected_presentations_digest)
    if not all(_hex(v) for v in selected) or (initial_event_anchor is not None and not _hex(initial_event_anchor)):
        raise ValueError("malformed externally selected digest")
    if not _time(renewal_ceiling) or (evaluation_at is not None and not _time(evaluation_at)):
        raise ValueError("malformed selected microsecond time")
    if not (type(max_events) is int and 0 < max_events <= 1024
            and type(max_presentations) is int and 0 < max_presentations <= 1024
            and type(max_steps) is int and 0 < max_steps <= 100000):
        raise ValueError("malformed or unsupported selected bounds")
    result: dict[str, Any] = {
        "schema_version": "verifier-private-declared-lifecycle-replay-1",
        "consistency_scope": "declared_single_binding_grammar_only",
        "consistency_status": "UNKNOWN", "presentation_results": [],
        "declared_reliance_eligibility": "UNKNOWN",
        "final_declared_state": "UNKNOWN", "current_valid_until": None,
        "violations": [], "missing_support": [], "steps": 0,
        "selected_protocol_status": "UNKNOWN", "authority_status": "UNKNOWN",
        "closure_status": "UNKNOWN", "public_checkability": "NOT_ESTABLISHED",
        "not_established": ["native_identity3.1", "independent_authority",
                            "human_authenticity", "live_clock", "log_completeness",
                            "fresh_authenticated_status", "handover_pair_support",
                            "SIM_terminal_support", "unilateral_exit_enforcement",
                            "retained_assurance", "attribute_source_admission",
                            "full_profile", "positive_polish"],
    }

    def take(count: int = 1) -> None:
        if result["steps"] + count > max_steps:
            raise _Stop("UNKNOWN", "selected replay budget exhausted; remaining phases unrun", exhausted=True)
        result["steps"] += count

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise _Stop("FAIL", message)

    def violation(message: str) -> None:
        result["violations"].append(message)

    def inspect(check) -> bool:
        try:
            check()
            return True
        except _Stop as exc:
            if exc.exhausted:
                raise
            if exc.status == "FAIL":
                violation(exc.message)
            else:
                result["missing_support"].append(exc.message)
            return False

    def binding_grammar() -> None:
        take()
        require(type(binding) is dict and set(binding) == BINDING_FIELDS, "binding shape")
        if binding["schema_version"] != BINDING_VERSION:
            raise _Stop("UNKNOWN", "unsupported selected binding version")
        require(binding["represented_kind"] in ("HUMAN", "AGENT", "BOT"), "required representation kind")
        for field in ("identity_id", "actor_id", "representation_id", "root_human_id", "role_id",
                      "collective_id", "clock_id", "assurance_requirement_id", "revocation_policy_id"):
            take()
            require(_text(binding[field]), "binding identifier " + field)
        require(_text(binding["scope"], 4096) and _hex(binding["identity_record_digest"]), "binding scope/record")
        require(_time(binding["valid_from"]) and _time(binding["valid_until"])
                and binding["valid_from"] < binding["valid_until"] <= renewal_ceiling, "nonempty bounded selected validity")
        attrs = binding["relied_attribute_ids"]
        require(type(attrs) is list, "attribute inventory shape")
        if len(attrs) > 256:
            raise _Stop("UNKNOWN", "attribute inventory bound exhausted", exhausted=True)
        seen = set()
        for attribute in attrs:
            take()
            require(_text(attribute) and attribute not in seen, "attribute ID or duplication")
            seen.add(attribute)
        if binding["represented_kind"] == "BOT":
            require(_text(binding["simulation_id"]) and _hex(binding["simulation_record_digest"])
                    and binding["scope"] == "simulation:" + binding["simulation_id"], "BOT requires exact SIM declaration/scope")
        else:
            require(binding["simulation_id"] is None and binding["simulation_record_digest"] is None, "non-BOT SIM fields must be null")
        require(_text(binding["human_exit_policy_id"]) if binding["represented_kind"] == "HUMAN"
                else binding["human_exit_policy_id"] is None, "selected HUMAN exit policy")

    def event_grammar(event: Any, position: int) -> None:
        take()
        require(type(event) is dict and set(event) == EVENT_FIELDS, "event shape")
        if event["schema_version"] != EVENT_VERSION:
            raise _Stop("UNKNOWN", "unsupported selected event version")
        require(_text(event["event_id"]) and type(event["position"]) is int
                and event["position"] == position, "event identifier/contiguous plain position")
        require(event["binding_digest"] == expected_binding_digest and _hex(event["previous_event_digest"]), "event binding/previous commitment")
        require(_time(event["at"]), "event plain time")
        require(event["authority_evidence_ref"] is None or _ref(event["authority_evidence_ref"]), "authority support locator shape")
        kind = event["kind"]
        require(type(kind) is str, "event kind shape")
        if kind not in PAYLOAD_FIELDS:
            raise _Stop("UNKNOWN", "unsupported selected event kind")
        payload = event["payload"]
        require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS[kind], "kind-specific payload shape")
        for field, value in payload.items():
            take()
            valid = (_time(value) if field == "new_valid_until" else _hex(value) if field.endswith("_digest")
                     else _ref(value) if field.endswith("_ref") else _text(value))
            require(valid, "payload plain shape: " + field)
        require(kind in ("enrollment", "handover_in") if position == 0 else kind not in ("enrollment", "handover_in"), "initial/duplicate enrollment grammar")

    def row_grammar(row: Any) -> None:
        take()
        require(type(row) is dict and set(row) == PRESENTATION_FIELDS, "presentation shape")
        if row["schema_version"] != PRESENTATION_VERSION:
            raise _Stop("UNKNOWN", "unsupported selected presentation version")
        require(all(_text(row[k]) for k in ("presentation_id", "event_id", "enrollment_id", "clock_id")), "presentation identifier")
        require(_hex(row["binding_digest"]) and _hex(row["context_digest"])
                and _hex(row["disclosed_field_inventory_digest"]) and _time(row["at"]), "presentation digest/plain time")
        require(row["binding_digest"] == expected_binding_digest, "presentation selected binding substitution")
        require(_text(row["scope"], 4096), "presentation scope shape")
        require(row["linkability_claim"] in ("none", "linkable", "unlinkable", "not_selected"), "presentation linkability vocabulary")
        require(row["linkability_support_requirement_id"] is None
                or _text(row["linkability_support_requirement_id"]), "linkability requirement shape")

    try:
        take()
        complete = True
        # Absence/unsupported semantics do not prevent cheap present predicates.
        for item, commitment in ((binding, expected_binding_digest), (events, expected_events_digest),
                                 (presentations, expected_presentations_digest)):
            if item is not None:
                _plain_fence(item)
                complete = inspect(lambda item=item, commitment=commitment:
                    require(_digest(item) == commitment, "retained component commitment substitution")) and complete
        binding_ok = False
        if binding is not None:
            binding_ok = inspect(binding_grammar)
            complete = binding_ok and complete
        event_ok = row_ok = False
        supported_rows = []
        if events is not None:
            event_ok = inspect(lambda: require(type(events) is list, "event inventory shape"))
            if event_ok:
                if len(events) > max_events:
                    raise _Stop("UNKNOWN", "selected event count exhausted", exhausted=True)
                event_ok = inspect(lambda: require(bool(events), "selected protocol requires one initial enrollment"))
                for position, event in enumerate(events):
                    event_ok = inspect(lambda event=event, position=position: event_grammar(event, position)) and event_ok
                if event_ok:
                    ids = set()
                    previous = initial_event_anchor
                    previous_at = None
                    for event in events:
                        take()
                        require(event["event_id"] not in ids, "event ID duplication")
                        ids.add(event["event_id"])
                        require(previous is None or event["previous_event_digest"] == previous, "event chain substitution")
                        require(previous_at is None or event["at"] >= previous_at, "event time/order")
                        previous, previous_at = _digest(event), event["at"]
            complete = event_ok and complete
        if presentations is not None:
            row_ok = inspect(lambda: require(type(presentations) is list, "presentation inventory shape"))
            if row_ok:
                if len(presentations) > max_presentations:
                    raise _Stop("UNKNOWN", "selected presentation count exhausted", exhausted=True)
                for row in presentations:
                    supported = inspect(lambda row=row: row_grammar(row))
                    if supported:
                        supported_rows.append(row)
                    row_ok = supported and row_ok
                if row_ok:
                    ids, event_ids = set(), set()
                    for row in presentations:
                        take()
                        require(row["presentation_id"] not in ids and row["event_id"] not in event_ids, "duplicate presentation ID/event")
                        ids.add(row["presentation_id"])
                        event_ids.add(row["event_id"])
            complete = row_ok and complete
        if binding_ok:
            for row in supported_rows:
                take()
                require(row["clock_id"] == binding["clock_id"] and row["scope"] == binding["scope"]
                        and row["simulation_id"] == binding["simulation_id"], "presentation supported binding clock/scope/SIM substitution")
        if event_ok and row_ok:
            by_id = {row["presentation_id"]: row for row in presentations}
            matched = set()
            enrollment = events[0]["payload"]["enrollment_id"] if events[0]["kind"] == "enrollment" else events[0]["event_id"]
            for event in events:
                if event["kind"] == "presentation":
                    take()
                    pid = event["payload"]["presentation_id"]
                    require(pid in by_id and pid not in matched, "presentation inventory mismatch")
                    row = by_id[pid]
                    require(event["payload"]["presentation_digest"] == _digest(row)
                            and row["event_id"] == event["event_id"] and row["at"] == event["at"]
                            and row["binding_digest"] == expected_binding_digest and row["enrollment_id"] == enrollment,
                            "presentation event/content/enrollment substitution")
                    matched.add(pid)
            require(matched == set(by_id), "unmatched selected presentation rows")
        if not complete:
            raise _Stop("UNKNOWN", "present independent component invalid/unsupported; dependent replay unrun")
        if binding is None or events is None:
            raise _Stop("UNKNOWN", "retained binding/event inventory absent; dependent replay unrun")
        missing_completion = initial_event_anchor is None or presentations is None
        if initial_event_anchor is None:
            result["missing_support"].append("external initial anchor absent; anchored completion unavailable")
        if presentations is None:
            result["missing_support"].append("presentation inventory absent; presentation completion unavailable")
        require(type(binding) is dict and set(binding) == BINDING_FIELDS, "binding shape")
        if binding["schema_version"] != BINDING_VERSION:
            raise _Stop("UNKNOWN", "unsupported selected binding version")
        require(binding["represented_kind"] in ("HUMAN", "AGENT", "BOT"), "required representation kind")
        for field in ("identity_id", "actor_id", "representation_id", "root_human_id",
                      "role_id", "collective_id", "clock_id", "assurance_requirement_id",
                      "revocation_policy_id"):
            take()
            require(_text(binding[field]), "binding identifier " + field)
        require(_text(binding["scope"], 4096), "binding scope")
        require(_hex(binding["identity_record_digest"]), "identity record commitment")
        require(_time(binding["valid_from"]) and _time(binding["valid_until"])
                and binding["valid_from"] < binding["valid_until"] <= renewal_ceiling,
                "nonempty bounded selected validity")
        attributes = binding["relied_attribute_ids"]
        require(type(attributes) is list, "attribute inventory shape")
        if len(attributes) > 256:
            raise _Stop("UNKNOWN", "attribute inventory bound exhausted")
        seen_attributes: set[str] = set()
        for attribute in attributes:
            take()
            require(_text(attribute) and attribute not in seen_attributes, "attribute ID or duplication")
            seen_attributes.add(attribute)
        if binding["represented_kind"] == "BOT":
            require(_text(binding["simulation_id"]) and _hex(binding["simulation_record_digest"]),
                    "BOT requires exact SIM declaration")
            require(binding["scope"] == "simulation:" + binding["simulation_id"], "BOT SIM scope")
        else:
            require(binding["simulation_id"] is None and binding["simulation_record_digest"] is None,
                    "non-BOT SIM fields must be null")
        require(_text(binding["human_exit_policy_id"]) if binding["represented_kind"] == "HUMAN"
                else binding["human_exit_policy_id"] is None, "selected HUMAN exit policy")
        require(type(events) is list and (presentations is None or type(presentations) is list), "retained inventory shape")
        if len(events) > max_events or (presentations is not None and len(presentations) > max_presentations):
            raise _Stop("UNKNOWN", "selected retained inventory count exhausted")
        require(_digest(binding) == expected_binding_digest, "binding commitment substitution")
        # The native wrapper fences whole bytes before these bounded-map hashes.
        require(_digest(events) == expected_events_digest, "event inventory commitment substitution")
        if presentations is not None:
            require(_digest(presentations) == expected_presentations_digest, "presentation inventory commitment substitution")
        require(bool(events), "selected protocol requires one initial enrollment")
        row_by_id: dict[str, dict[str, Any]] = {}
        seen_row_events: set[str] = set()
        for row in presentations or []:
            take()
            require(type(row) is dict and set(row) == PRESENTATION_FIELDS, "presentation shape")
            if row["schema_version"] != PRESENTATION_VERSION:
                raise _Stop("UNKNOWN", "unsupported selected presentation version")
            require(all(_text(row[k]) for k in ("presentation_id", "event_id", "enrollment_id", "clock_id")),
                    "presentation identifier")
            require(row["presentation_id"] not in row_by_id and row["event_id"] not in seen_row_events,
                    "duplicate presentation ID/event")
            require(_hex(row["binding_digest"]) and _hex(row["context_digest"])
                    and _hex(row["disclosed_field_inventory_digest"]) and _time(row["at"]),
                    "presentation digest/time")
            require(_text(row["scope"], 4096), "presentation scope shape")
            require(row["linkability_claim"] in ("none", "linkable", "unlinkable", "not_selected"),
                    "presentation linkability vocabulary")
            require(row["linkability_support_requirement_id"] is None
                    or _text(row["linkability_support_requirement_id"]), "linkability requirement shape")
            row_by_id[row["presentation_id"]] = row
            seen_row_events.add(row["event_id"])
        previous_digest = initial_event_anchor
        previous_at = binding["valid_from"]
        current_end = binding["valid_until"]
        terminal_at: int | None = None
        enrollment_id: str | None = None
        seen_event_ids: set[str] = set()
        selected_presentations: list[tuple[dict[str, Any], dict[str, Any], int]] = []
        seen_presentations: set[str] = set()
        for position, event in enumerate(events):
            take()
            require(type(event) is dict and set(event) == EVENT_FIELDS, "event shape")
            if event["schema_version"] != EVENT_VERSION:
                raise _Stop("UNKNOWN", "unsupported selected event version")
            require(_text(event["event_id"]) and event["event_id"] not in seen_event_ids, "event ID duplication/shape")
            seen_event_ids.add(event["event_id"])
            require(type(event["position"]) is int and event["position"] == position, "noncontiguous event position")
            require(event["binding_digest"] == expected_binding_digest
                    and (previous_digest is None or event["previous_event_digest"] == previous_digest), "event binding/chain substitution")
            require(_time(event["at"]) and event["at"] >= previous_at, "event time/order")
            require(event["authority_evidence_ref"] is None or _ref(event["authority_evidence_ref"]),
                    "authority support locator shape")
            kind = event["kind"]
            require(type(kind) is str, "event kind shape")
            if kind not in PAYLOAD_FIELDS:
                raise _Stop("UNKNOWN", "unsupported selected event kind")
            payload = event["payload"]
            require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS[kind], "kind-specific payload shape")
            for field, value in payload.items():
                take()
                if field == "new_valid_until":
                    require(_time(value), "renewal time shape")
                elif field.endswith("_digest"):
                    require(_hex(value), "payload digest shape: " + field)
                elif field.endswith("_ref"):
                    require(_ref(value), "payload locator shape: " + field)
                else:
                    require(_text(value), "payload identifier shape: " + field)
            if position == 0:
                require(kind in ("enrollment", "handover_in") and event["at"] == binding["valid_from"],
                        "initial enrollment at validity start")
                enrollment_id = payload["enrollment_id"] if kind == "enrollment" else event["event_id"]
                if kind == "handover_in":
                    require(payload["prior_identity_id"] != binding["identity_id"], "handover must use distinct identity")
                    result["missing_support"].append("paired prior binding and exact3.1 support unrun")
            else:
                require(kind not in ("enrollment", "handover_in"), "duplicate enrollment/rebinding")
                if kind in ("renewal", "reverification", "presentation"):
                    if terminal_at is not None or event["at"] >= current_end:
                        violation("active event at/after termination or expiry: " + event["event_id"])
                if kind == "renewal":
                    require(current_end < payload["new_valid_until"] <= renewal_ceiling, "renewal extension/ceiling")
                    if terminal_at is None and event["at"] < current_end:
                        current_end = payload["new_valid_until"]
                elif kind == "presentation":
                    pid = payload["presentation_id"]
                    if presentations is not None:
                        require(pid in row_by_id and pid not in seen_presentations, "presentation inventory mismatch")
                        row = row_by_id[pid]
                        require(payload["presentation_digest"] == _digest(row), "presentation content substitution")
                        selected_presentations.append((event, row, current_end))
                        seen_presentations.add(pid)
                elif kind in TERMINAL:
                    require(terminal_at is None and event["at"] <= current_end, "terminal grammar or expired binding")
                    if kind == "expiry":
                        require(event["at"] == current_end, "explicit expiry must equal end")
                    elif kind in ("simulation_end", "simulation_superseded"):
                        require(binding["represented_kind"] == "BOT"
                                and payload["simulation_id"] == binding["simulation_id"]
                                and payload["simulation_record_digest"] == binding["simulation_record_digest"],
                                "SIM terminal relation")
                        if kind == "simulation_superseded":
                            require(payload["successor_simulation_id"] != binding["simulation_id"], "distinct successor SIM")
                        result["missing_support"].append("selected actual SIM terminal support unrun")
                    elif kind == "human_exit":
                        require(binding["represented_kind"] == "HUMAN", "HUMAN-only exit event")
                        result["missing_support"].append("authenticated unilateral exit and enforcement support unrun")
                    elif kind == "handover_out":
                        require(payload["replacement_identity_id"] != binding["identity_id"], "distinct handover identity")
                        result["missing_support"].append("paired replacement binding and exact3.1 support unrun")
                    terminal_at = event["at"]
            previous_at = event["at"]
            previous_digest = _digest(event)
        require(seen_presentations == set(row_by_id), "unmatched selected presentation rows")
        # This second phase sees every terminal, including equal-time events that
        # occur after a presentation in serialized order. Budget abort => no PASS.
        completed_rows = []
        for event, row, end_at_presentation in selected_presentations:
            take()
            bound = (row["event_id"] == event["event_id"]
                     and row["binding_digest"] == expected_binding_digest
                     and row["enrollment_id"] == enrollment_id
                     and row["at"] == event["at"] and row["clock_id"] == binding["clock_id"]
                     and row["scope"] == binding["scope"]
                     and row["simulation_id"] == binding["simulation_id"])
            eligible = (binding["valid_from"] <= row["at"] < end_at_presentation
                        and (terminal_at is None or row["at"] < terminal_at))
            verdict = "PASS" if bound and eligible else "FAIL"
            if verdict == "FAIL":
                violation("ineligible/substituted retained presentation: " + row["presentation_id"])
            completed_rows.append({"presentation_id": row["presentation_id"],
                                   "declared_binding_eligibility": verdict})
        result["presentation_results"] = completed_rows
        result["current_valid_until"] = current_end
        if evaluation_at is not None:
            take()
            active = (binding["valid_from"] <= evaluation_at < current_end
                      and (terminal_at is None or evaluation_at < terminal_at))
            result["declared_reliance_eligibility"] = "PASS" if active else "FAIL"
            result["final_declared_state"] = "ACTIVE" if active else "INACTIVE"
        else:
            result["missing_support"].append("externally selected evaluation time absent")
        result["consistency_status"] = "FAIL" if result["violations"] else "UNKNOWN" if missing_completion else "PASS"
        if missing_completion:
            result["declared_reliance_eligibility"] = "UNKNOWN"
            result["final_declared_state"] = "UNKNOWN"
            result["presentation_results"] = []
    except _Stop as exc:
        if exc.status == "FAIL":
            violation(exc.message)
        else:
            result["missing_support"].append(exc.message)
        result["consistency_status"] = "FAIL" if result["violations"] else "UNKNOWN"
        result["declared_reliance_eligibility"] = "UNKNOWN"
        result["final_declared_state"] = "UNKNOWN"
        result["presentation_results"] = []  # no completion credit for aborted second phase
    except (OverflowError, RecursionError):
        result["missing_support"].append("retained replay checking capacity unavailable")
        result["checking_unavailable"] = True
        result["consistency_status"] = "FAIL" if result["violations"] else "UNKNOWN"
        result["declared_reliance_eligibility"] = "UNKNOWN"
        result["final_declared_state"] = "UNKNOWN"
        result["presentation_results"] = []
    except (TypeError, ValueError):
        violation("malformed retained canonical value; native wrapper must enforce byte/depth bounds")
        result["consistency_status"] = "FAIL"
        result["declared_reliance_eligibility"] = "UNKNOWN"
        result["final_declared_state"] = "UNKNOWN"
        result["presentation_results"] = []
    return result

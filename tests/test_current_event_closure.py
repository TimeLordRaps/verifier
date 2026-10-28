"""Selected finite EVENT declared-log closure over one head, not occurrence.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); mebibyte (MiB). Sequence numbers, counts and
checker budgets are dimensionless; evidence and certificate bounds are bytes.
The EVENT-3.1 child and the EVENT-4.1 parent log closure are separately
replayed. Negatives that target the parent keep a child that alone PASSes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import event_closure, event_prerequisites
from verifier.domains.contracts import space_layout, time_order
from verifier.domains.inventory import get_slot


LOG_VERSION = "verifier-current-event-closure-log-1"
OPERANDS = {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]}
CHAIN = [
    ("first", 0, [], {"value": "first"}),
    ("second", 1, ["first"], {"value": "second"}),
    ("head", 2, ["second"], {"value": "third"}),
]
Event = tuple[str, Any, list[str], Any]


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def operand_records() -> list[NamespaceObject]:
    return [NamespaceObject.create("clock", "TIME", {}),
            NamespaceObject.create("place", "SPACE", {}),
            NamespaceObject.create("meaning", "OBJECT", {})]


def event_records(events: list[Event]) -> list[NamespaceObject]:
    return [NamespaceObject.create(name, "EVENT", {
        "scope": "retained-declared-prerequisites", "sequence": sequence,
        "prerequisites": parents, "payload_digest": digest(payload)}, OPERANDS)
        for name, sequence, parents, payload in events]


def log_rows(records: list[NamespaceObject]) -> list[dict[str, Any]]:
    """Independent ascending-sequence log rows; not read from the mechanism."""
    rows = [{"object_id": record.object_id, "object_digest": record.digest,
             "sequence": record.payload["sequence"]} for record in records]
    return sorted(rows, key=lambda row: (row["sequence"], row["object_id"]))


def log_digest(head: str, first: int, rows: list[dict[str, Any]]) -> str:
    return digest({"schema_version": LOG_VERSION, "head_id": head,
                   "first_sequence": first, "events": rows})


def child(events: list[Event], *, head: str = "head",
          retained: list[str] | None = None, payloads: dict[str, Any] | None = None,
          include_inputs: bool = True,
          extra: list[NamespaceObject] | None = None) -> dict[str, Any]:
    records = event_records(events)
    objects = [*operand_records(), *records, *(extra or [])]
    names = retained if retained is not None else [name for name, *_ in events]
    content = payloads if payloads is not None else {
        name: payload for name, _, _, payload in events if name in names}
    evidence = canonical_bytes({
        "schema_version": event_prerequisites.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"payloads": content} if include_inputs else None})
    policy = event_prerequisites.event_prerequisites_policy(
        trust_roots=["selected-event-cone"])
    subject = next(item for item in records if item.object_id == head)
    request = event_prerequisites.event_prerequisites_request(
        subject_id=head, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    certificate = event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)
    return {"request": request, "policy": policy, "certificate": certificate,
            "evidence": evidence, "records": records, "objects": objects,
            "subject": subject}


def child_status(parts: dict[str, Any]) -> str:
    return event_prerequisites.recheck_event_prerequisites_certificate(
        parts["certificate"], expected_request=parts["request"],
        policy=parts["policy"])["status"]


def parent_evidence(child_request: dict[str, Any], child_policy: dict[str, Any],
                    certificate: bytes) -> bytes:
    return canonical_bytes({
        "schema_version": event_closure.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(certificate).decode("ascii")})


def selected(events: list[Event] | None = None, *, head: str = "head",
             first_sequence: int = 0, log: str | None = None,
             include_child: bool = True, limits: dict[str, int] | None = None,
             parts: dict[str, Any] | None = None,
             **child_options: Any) -> dict[str, Any]:
    events = events if events is not None else CHAIN
    parts = parts if parts is not None else child(events, head=head, **child_options)
    evidence = parent_evidence(parts["request"], parts["policy"],
                               parts["certificate"]) if include_child else None
    policy = event_closure.event_closure_policy(trust_roots=["closure-root"])
    rows = log_rows(parts["records"])
    fields = {
        "subject_id": head, "object_digest": parts["subject"].digest,
        "collection_digest": composition_digest(parts["objects"]),
        "child_request_digest": digest(parts["request"]),
        "child_policy_digest": digest(parts["policy"]),
        "child_certificate_digest": raw_digest(parts["certificate"]),
        "first_sequence": first_sequence,
        "log_digest": log if log is not None else log_digest(head, first_sequence, rows),
        "evidence_ref": digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        "policy": policy, "limits": limits}
    request = event_closure.event_closure_request(**fields)
    return {"request": request, "policy": policy, "evidence": evidence,
            "child": parts, "rows": rows, "fields": fields}


def with_fields(case: dict[str, Any], **changes: Any) -> dict[str, Any]:
    fields = {**case["fields"], **changes}
    return {**case, "fields": fields,
            "request": event_closure.event_closure_request(**fields)}


def replay(case: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    certificate = event_closure.build_event_closure_certificate(
        case["request"], case["evidence"], policy=case["policy"])
    result = event_closure.recheck_event_closure_certificate(
        certificate, expected_request=case["request"], policy=case["policy"])
    return certificate, result


def status(case: dict[str, Any]) -> str:
    return replay(case)[1]["status"]


def details(case: dict[str, Any]) -> str:
    return replay(case)[1]["evaluation"]["details"]


# Positive controls and boundary promotion.

def test_selected_log_closure_passes_without_occurrence_promotion() -> None:
    case = selected()
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    assert result["declared_log_closure"] == "PASS"
    for field in ("occurrence_authenticity", "physical_causality",
                  "completeness_outside_collection", "append_only",
                  "operand_truth", "whole_event_closure",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["events"] == 3
    assert certificate == event_closure.build_event_closure_certificate(
        case["request"], case["evidence"], policy=case["policy"])


def test_non_event_operand_records_are_not_orphans() -> None:
    """Required negative 11, a positive control: TIME, SPACE and OBJECT stay out of E."""
    case = selected()
    kinds = sorted(item.kind.value for item in case["child"]["objects"])
    assert kinds == ["EVENT", "EVENT", "EVENT", "OBJECT", "SPACE", "TIME"]
    assert status(case) == "PASS"


@pytest.mark.parametrize("first", [0, 5, 2**53 - 1])
def test_single_event_log_passes_only_at_its_own_first_sequence(first: int) -> None:
    """Required negative 12, a positive control: one event, no prerequisites."""
    events = [("head", first, [], {"value": "only"})]
    assert status(selected(events, first_sequence=first)) == "PASS"
    wrong = first - 1 if first else first + 1
    assert status(selected(events, first_sequence=wrong)) == "FAIL"


def test_declared_sequence_translation_preserves_closure() -> None:
    largest = 2**53 - 1
    for base in (0, 17, 1000000, largest - 2):
        events = [("first", base, [], {"value": 1}),
                  ("second", base + 1, ["first"], {"value": 2}),
                  ("head", base + 2, ["second", "first"], {"value": 3})]
        assert status(selected(events, first_sequence=base)) == "PASS"


# Negatives 1 to 5: the child alone PASSes; the parent is stricter.

def test_orphan_event_outside_the_head_cone_fails() -> None:
    """Required negative 1."""
    events = [("first", 0, [], {"value": 1}), ("orphan", 1, [], {"value": 2}),
              ("second", 2, ["first"], {"value": 3}),
              ("head", 3, ["second"], {"value": 4})]
    case = selected(events, retained=["first", "second", "head"])
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "FAIL"
    assert "outside the head" in details(case)


@pytest.mark.parametrize("head", ["left", "right"])
def test_second_maximal_event_fails(head: str) -> None:
    """Required negative 2: two heads over one collection."""
    events = [("first", 0, [], {"value": 1}), ("left", 1, ["first"], {"value": 2}),
              ("right", 2, ["first"], {"value": 3})]
    case = selected(events, head=head, retained=["first", head])
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "FAIL"
    assert "outside the head" in details(case)


def test_interior_gap_fails() -> None:
    """Required negative 3: sequences 0, 1, 3."""
    events = [("first", 0, [], {"value": 1}), ("second", 1, ["first"], {"value": 2}),
              ("head", 3, ["second"], {"value": 3})]
    case = selected(events)
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "FAIL"
    assert "gap or repeat" in details(case)


@pytest.mark.parametrize("first", [0, 2])
def test_leading_gap_and_off_by_one_first_sequence_fail(first: int) -> None:
    """Required negative 4: sequences 1..3 against first_sequence 0 or 2."""
    events = [("first", 1, [], {"value": 1}), ("second", 2, ["first"], {"value": 2}),
              ("head", 3, ["second"], {"value": 3})]
    case = selected(events, first_sequence=first)
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "FAIL"
    assert "gap or repeat" in details(case)
    assert status(selected(events, first_sequence=1)) == "PASS"


@pytest.mark.parametrize("sequences,first", [((0, 0, 1), 0), ((1, 1, 2), 1)])
def test_duplicate_sibling_sequence_fails(sequences: tuple[int, int, int],
                                          first: int) -> None:
    """Required negative 5, including a repeat whose value set is contiguous."""
    left, right, top = sequences
    events = [("left", left, [], {"value": 1}), ("right", right, [], {"value": 2}),
              ("head", top, ["left", "right"], {"value": 3})]
    case = selected(events, first_sequence=first)
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "FAIL"
    assert "gap or repeat" in details(case)


# Negative 6: substituted log commitments.

def _changed_digest(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    changed = deepcopy(rows)
    changed[0]["object_digest"] = "sha256:" + "1" * 64
    return changed


@pytest.mark.parametrize("form", ["event_digest", "reordered", "first_sequence",
                                  "dropped", "head_id", "version"])
def test_substituted_log_digest_fails(form: str) -> None:
    """Required negative 6."""
    case = selected()
    rows = case["rows"]
    substitutes = {
        "event_digest": lambda: log_digest("head", 0, _changed_digest(rows)),
        "reordered": lambda: log_digest("head", 0, list(reversed(rows))),
        "first_sequence": lambda: log_digest("head", 1, rows),
        "dropped": lambda: log_digest("head", 0, rows[:-1]),
        "head_id": lambda: log_digest("second", 0, rows),
        "version": lambda: digest({"schema_version": "other", "head_id": "head",
                                   "first_sequence": 0, "events": rows}),
    }
    changed = with_fields(case, log_digest=substitutes[form]())
    assert status(changed) == "FAIL"
    assert "log commitment" in details(changed)
    assert status(case) == "PASS"


# Negative 7: substituted child.

def test_child_certificate_digest_mismatch_fails() -> None:
    case = selected()
    changed = with_fields(case, child_certificate_digest=raw_digest(b"other"))
    assert status(changed) == "FAIL"


def test_child_for_another_subject_or_collection_fails() -> None:
    # The child for "second" retains only its own cone, so it passes alone.
    other_subject = child(CHAIN, head="second", retained=["first", "second"])
    case = selected()
    swapped = selected(parts=other_subject, head="second")
    # Parent selects "head" but binds the retained child for "second".
    forged = with_fields(
        {**case, "evidence": swapped["evidence"]},
        child_request_digest=swapped["fields"]["child_request_digest"],
        child_policy_digest=swapped["fields"]["child_policy_digest"],
        child_certificate_digest=swapped["fields"]["child_certificate_digest"],
        evidence_ref=swapped["fields"]["evidence_ref"])
    assert child_status(other_subject) == "PASS"
    assert status(forged) == "FAIL"
    wider = child(CHAIN, extra=[NamespaceObject.create("note", "OBJECT", {})])
    assert child_status(wider) == "PASS"
    evidence = parent_evidence(wider["request"], wider["policy"], wider["certificate"])
    forged = with_fields(
        {**case, "evidence": evidence},
        child_request_digest=digest(wider["request"]),
        child_policy_digest=digest(wider["policy"]),
        child_certificate_digest=raw_digest(wider["certificate"]),
        evidence_ref=digest(json.loads(evidence)))
    assert status(forged) == "FAIL"
    assert "not the selected EVENT-3.1" in details(forged)


def _time_child() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    samples = [{"id": "a", "at_us": 2}]
    subject = NamespaceObject.create("head", "TIME", {
        "scope": "retained-declared-clock-order", "clock": "test:clock",
        "unit": "microsecond", "span_start_us": 0, "span_end_us": 10,
        "samples_digest": digest(samples)})
    evidence = canonical_bytes({"schema_version": time_order.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"samples": samples}})
    policy = time_order.time_order_policy(trust_roots=["time-root"])
    request = time_order.time_order_request(
        subject_id="head", object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    return request, policy, time_order.build_time_order_certificate(
        request, evidence, policy=policy)


def _space_child() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    partitions = [{"id": "all", "start_byte": 0, "end_byte": 8, "alignment_bytes": 8}]
    subject = NamespaceObject.create("head", "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 8, "partitions_digest": digest(partitions)})
    evidence = canonical_bytes({"schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"partitions": partitions}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id="head", object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    return request, policy, space_layout.build_space_layout_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("foreign", [_time_child, _space_child],
                         ids=["TIME-2.1", "SPACE-3.1"])
def test_foreign_objective_child_cannot_stand_in(foreign: Any) -> None:
    """Required negative 7: a PASSing TIME-2.1 or SPACE-3.1 certificate as child."""
    request, policy, certificate = foreign()
    case = selected()
    evidence = parent_evidence(request, policy, certificate)
    forged = with_fields(
        {**case, "evidence": evidence},
        child_request_digest=digest(request), child_policy_digest=digest(policy),
        child_certificate_digest=raw_digest(certificate),
        evidence_ref=digest(json.loads(evidence)))
    assert json.loads(certificate)["result"]["status"] == "PASS"
    assert status(forged) == "FAIL"
    assert "not the selected EVENT-3.1" in details(forged)


# Negatives 8 and 9: child verdicts propagate; absent evidence is UNKNOWN.

def test_child_fail_is_fail_and_child_unknown_is_unknown() -> None:
    """Required negative 8."""
    changed = {name: payload for name, _, _, payload in CHAIN}
    changed["first"] = {"value": "substituted"}
    case = selected(payloads=changed)
    assert child_status(case["child"]) == "FAIL"
    assert status(case) == "FAIL"
    case = selected(include_inputs=False)
    assert child_status(case["child"]) == "UNKNOWN"
    assert status(case) == "UNKNOWN"


def test_absent_parent_evidence_is_unknown() -> None:
    """Required negative 9."""
    case = selected(include_child=False)
    assert status(case) == "UNKNOWN"


def test_rehashed_child_verdict_cannot_be_selected_as_closure() -> None:
    changed = {name: payload for name, _, _, payload in CHAIN}
    changed["first"] = {"value": "substituted"}
    case = selected(payloads=changed)
    assert child_status(case["child"]) == "FAIL"
    altered = json.loads(case["child"]["certificate"])
    altered["result"]["status"] = "PASS"
    altered["result"]["evaluation"]["outcome"] = "PASS"
    altered.pop("digest")
    altered["digest"] = digest(altered)
    altered_bytes = canonical_bytes(altered)
    evidence = parent_evidence(case["child"]["request"], case["child"]["policy"],
                               altered_bytes)
    forged = with_fields({**case, "evidence": evidence},
                         child_certificate_digest=raw_digest(altered_bytes),
                         evidence_ref=digest(json.loads(evidence)))
    assert status(forged) == "FAIL"


# Negative 10: budgets and limits.

def _long_chain(count: int) -> list[Event]:
    return [(f"e{index:02d}" if index < count - 1 else "head", index,
             [f"e{index - 1:02d}"] if index else [], {"value": index})
            for index in range(count)]


def test_event_count_above_selected_item_bound_is_unknown() -> None:
    """Required negative 10: |E| = 12 exceeds max_items = 11 after structure fits."""
    events = _long_chain(12)
    assert status(selected(events)) == "PASS"
    case = selected(events, limits={"max_items": 11})
    assert child_status(case["child"]) == "PASS"
    assert status(case) == "UNKNOWN"
    assert "event log item bound" in details(case)


@pytest.mark.parametrize("bound", ["max_items", "max_operations", "max_evidence_bytes"])
def test_exhausted_parent_limits_are_unknown(bound: str) -> None:
    assert status(selected(limits={bound: 1})) == "UNKNOWN"


@pytest.mark.parametrize("limits", [
    {"max_items": 4097}, {"max_operations": 100001},
    {"max_evidence_bytes": 8 * 1024 * 1024 + 1}, {"max_items": 0},
    {"max_items": True}, {"max_objects": 1}, {"unknown": 1},
])
def test_unsupported_limits_are_rejected(limits: dict[str, Any]) -> None:
    with pytest.raises(event_closure.EventClosureError):
        selected(limits=limits)


@pytest.mark.parametrize("first", [-1, 2**53, True, 1.0, "0", None])
def test_first_sequence_must_be_a_plain_safe_integer(first: Any) -> None:
    with pytest.raises(event_closure.EventClosureError):
        selected(first_sequence=first, log="sha256:" + "0" * 64)


@pytest.mark.parametrize("log", ["sha256:" + "A" * 64, "sha256:" + "0" * 63, "", None])
def test_log_digest_must_be_a_commitment(log: Any) -> None:
    case = selected()
    with pytest.raises(event_closure.EventClosureError):
        with_fields(case, log_digest=log)


# Size bounds, measured rather than assumed.

def test_largest_admitted_child_fits_parent_evidence_bound() -> None:
    """A child with 4 MiB evidence yields parent evidence under 8 MiB.

    The EVENT-3.1 builder refuses evidence above 4 MiB, so a real child
    certificate stays near 5.34 MiB, below its own 8 MiB bound. The parent
    "child certificate bound exhausted" branch is therefore unreachable
    under shipped ceilings; the next test reaches it only by lowering the
    child bound.
    """
    ceiling = event_prerequisites._CEILINGS["max_evidence_bytes"]
    empty = child([("head", 0, [], {"value": ""})])["evidence"]
    padded = "x" * (ceiling - len(empty))
    parts = child([("head", 0, [], {"value": padded})])
    assert len(parts["evidence"]) == ceiling
    case = selected([("head", 0, [], {"value": padded})], parts=parts)
    child_bytes = len(parts["certificate"])
    parent_bytes = len(case["evidence"])
    assert 5 * 1024 * 1024 < child_bytes < 6 * 1024 * 1024, child_bytes
    assert child_bytes < event_prerequisites._MAX_CERTIFICATE_BYTES
    assert 7 * 1024 * 1024 < parent_bytes < 8 * 1024 * 1024, parent_bytes
    assert status(case) == "PASS"


def test_child_certificate_over_child_bound_is_unknown(monkeypatch: Any) -> None:
    case = selected()
    monkeypatch.setattr(event_prerequisites, "_MAX_CERTIFICATE_BYTES", 64)
    assert status(case) == "UNKNOWN"
    assert "child certificate bound" in details(case)


def test_parent_evidence_over_ceiling_is_rejected_at_build() -> None:
    case = selected()
    oversized = b" " * (8 * 1024 * 1024 + 1)
    with pytest.raises(event_closure.EventClosureError, match="bounded evidence"):
        event_closure.build_event_closure_certificate(
            case["request"], oversized, policy=case["policy"])
    with pytest.raises(event_closure.EventClosureError, match="byte reference"):
        event_closure.build_event_closure_certificate(
            case["request"], case["evidence"] + b" ", policy=case["policy"])


def test_certificate_over_policy_bound_is_rejected() -> None:
    case = selected()
    certificate, _ = replay(case)
    small = event_closure.event_closure_policy(trust_roots=["closure-root"],
                                               max_certificate_bytes=1024)
    request = event_closure.event_closure_request(**{**case["fields"], "policy": small})
    with pytest.raises(event_closure.EventClosureError, match="certificate byte bound"):
        event_closure.build_event_closure_certificate(
            request, case["evidence"], policy=small)
    with pytest.raises(event_closure.EventClosureError):
        event_closure.recheck_event_closure_certificate(
            certificate, expected_request=request, policy=small)


# Negative 13: forged verdicts, substitutions and changed mechanisms refuse.

def test_forged_verdict_and_substituted_selection_are_rejected() -> None:
    case = selected()
    certificate, _ = replay(case)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(event_closure.EventClosureError):
        event_closure.recheck_event_closure_certificate(
            canonical_bytes(forged), expected_request=case["request"],
            policy=case["policy"])
    for field, value in (("first_sequence", 1), ("subject_id", "second"),
                         ("log_digest", "sha256:" + "2" * 64)):
        changed = event_closure.event_closure_request(
            **{**case["fields"], field: value})
        with pytest.raises(event_closure.EventClosureError):
            event_closure.recheck_event_closure_certificate(
                certificate, expected_request=changed, policy=case["policy"])
    other = deepcopy(case["policy"])
    other["trust_roots"] = ["other-root"]
    with pytest.raises(event_closure.EventClosureError):
        event_closure.recheck_event_closure_certificate(
            certificate, expected_request=case["request"], policy=other)


@pytest.mark.parametrize("relative", [
    "domains/contracts/event_closure.py",
    "domains/contracts/event_prerequisites.py",
    "domains/contracts/retained_selection.py",
    "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py",
    "core/receipt.py",
    "standard/CURRENT_EVENT_CLOSURE.md",
    "standard/CURRENT_EVENT_PREREQUISITES.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(
        relative: str, monkeypatch: Any) -> None:
    case = selected()
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    target = Path(event_closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        event_closure.recheck_event_closure_certificate(
            certificate, expected_request=case["request"], policy=case["policy"])


# Public route, inventory, redaction, command line and polish.

def test_public_route_and_inventory_select_only_this_closure_objective() -> None:
    case = selected()
    certificate, _ = replay(case)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=event_closure.SEMANTIC_VERSION,
        objective=event_closure.COORDINATE, represented_kind="EVENT",
        expected_request=case["request"], policy=case["policy"])
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["occurrence_authenticity"] == "NOT_ESTABLISHED"
    assert report["native_result"]["completeness_outside_collection"] == "NOT_ESTABLISHED"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=event_closure.SEMANTIC_VERSION,
            objective=event_closure.COORDINATE, represented_kind="SPACE",
            expected_request=case["request"], policy=case["policy"])
    slot = get_slot("EVENT", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "EVENT-4.1"
    assert get_slot("EVENT", 3).mechanized_route["artifact_coordinate"] == "EVENT-3.1"


def test_retained_closure_certificate_refuses_evidence_redaction() -> None:
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    case = selected()
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("EVENT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def test_public_command_and_polish_keep_tier_boundary(tmp_path: Path,
                                                      capsys: Any) -> None:
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    case = selected()
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(case["request"])),
                           ("policy", canonical_bytes(case["policy"])),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", event_closure.SEMANTIC_VERSION,
        "--objective", event_closure.COORDINATE, "--represented-kind", "EVENT",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(case["child"]["evidence"])["objects"],
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "head", "collection_digest": case["request"]["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "head", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected declared log only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][3]["objectives"] = [{
        "semantic_version": event_closure.SEMANTIC_VERSION,
        "coordinate": event_closure.COORDINATE,
        "request": case["request"], "policy": case["policy"],
        "certificate_digest": digest(json.loads(certificate))}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("relative", ["domains/contracts/event_closure.py",
                                      "standard/CURRENT_EVENT_CLOSURE.md"])
def test_changed_closure_source_invalidates_polish_aggregate(
        relative: str, monkeypatch: Any) -> None:
    from verifier.runtime import polish

    before = polish.mechanism_digest()
    target = Path(event_closure.__file__).parents[2] / relative
    assert target.is_file()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged closure route\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before

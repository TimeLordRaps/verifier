"""Current HARNESS-3.1 named gaps bounded by retained instrument placements.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Window, placement and gap endpoints are integer
instants of one declared session clock; intervals are half-open; counts are
dimensionless. The oracle classifies every instant of the window one at a time
instead of merging intervals.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import harness_gap_boundary as contract
from verifier.domains.inventory import get_slot

SRC = Path(contract.__file__).parents[2]
SPEC = SRC / "standard" / "CURRENT_HARNESS_GAP_BOUNDARY.md"
ROW_PREFIX = "| HARNESS-3.1 |"
WINDOW = {"start": 0, "end": 100}
PLACEMENTS = [
    {"instrument": "message_tap", "start": 0, "end": 30},
    {"instrument": "tool_tap", "start": 45, "end": 80},
    {"instrument": "effect_tap", "start": 70, "end": 90},
]
GAPS = [
    {"name": "between-message-and-tool", "start": 30, "end": 45},
    {"name": "after-effects", "start": 90, "end": 100},
]


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, gaps: list | None = None, placements: list | None = None,
             committed: list | None = None, window: dict | None = None,
             inputs: object = "default", subject: str = "harness",
             include_evidence: bool = True, **limits: int):
    gaps = deepcopy(GAPS if gaps is None else gaps)
    placements = deepcopy(PLACEMENTS if placements is None else placements)
    committed = placements if committed is None else committed
    harness = NamespaceObject.create("harness", "HARNESS", {
        "scope": "retained-harness-gap-boundary", "window": window or dict(WINDOW),
        "gaps": gaps, "placements_digest": digest(committed)})
    decoy = NamespaceObject.create("decoy-harness", "HARNESS", {"fixture": "unbound"})
    objects = [harness, decoy]
    chosen = next(item for item in objects if item.object_id == subject)
    evidence = canonical_bytes({
        "schema_version": contract.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
        "inputs": {"placements": placements} if inputs == "default" else inputs,
    })
    policy = contract.harness_gap_boundary_policy(trust_roots=["harness-statics-root"])
    request = contract.harness_gap_boundary_request(
        subject_id=chosen.object_id, object_digest=chosen.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None)
    return request, policy, (evidence if include_evidence else None)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = contract.build_harness_gap_boundary_certificate(request, evidence, policy=policy)
    result = contract.recheck_harness_gap_boundary_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(window: dict, placements: list, gaps: list) -> tuple[str, list]:
    """Pointwise: an instant is uninstrumented when no placement covers it."""
    start, end = window["start"], window["end"]
    if any(not start <= row["start"] < row["end"] <= end for row in placements):
        return "FAIL", []
    runs, run_start = [], None
    for instant in range(start, end + 1):
        free = instant < end and not any(row["start"] <= instant < row["end"] for row in placements)
        if free and run_start is None:
            run_start = instant
        elif not free and run_start is not None:
            runs.append((run_start, instant))
            run_start = None
    declared = [(row["start"], row["end"]) for row in gaps]
    if declared != runs:
        return "FAIL", []
    anchored = []
    for row in gaps:
        after = None if row["start"] == start else sorted(
            {p["instrument"] for p in placements if p["end"] == row["start"]})
        before = None if row["end"] == end else sorted(
            {p["instrument"] for p in placements if p["start"] == row["end"]})
        anchored.append({"name": row["name"], "start": row["start"], "end": row["end"],
                         "after": after, "before": before})
    return "PASS", anchored


def test_inventory_selects_harness_gap_boundary_and_spec_quotes_row() -> None:
    slot = get_slot("HARNESS", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "HARNESS-3.1" == contract.COORDINATE
    route = slot.mechanized_route
    assert route["checking_mechanism"] == (
        "verifier.domains.contracts.harness_gap_boundary.recheck_harness_gap_boundary_certificate")
    assert route["artifact_coordinate"] == "HARNESS-3.1"
    assert route["exact_claim"] == contract.registration()["proposition"]
    rows = (SRC / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8").splitlines()
    row = next(line for line in rows if line.startswith(ROW_PREFIX))
    spec = SPEC.read_text(encoding="utf-8")
    assert row in spec.splitlines()
    proposition = spec.split("## Proposition", 1)[1].split("\n## ", 1)[0]
    assert " ".join(proposition.split()) == contract.registration()["proposition"]


def test_named_gaps_anchor_to_named_placements_and_recheck() -> None:
    expected, anchored = oracle(WINDOW, PLACEMENTS, GAPS)
    assert expected == "PASS"
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]["details"]
    assert result["gap_boundary"] == "PASS"
    observations = result["evaluation"]["observations"]
    assert observations["gaps"] == anchored
    assert observations["gaps"][0]["after"] == ["message_tap"]
    assert observations["gaps"][0]["before"] == ["tool_tap"]
    assert observations["gaps"][1]["before"] is None
    assert observations["placements"] == len(PLACEMENTS)
    assert observations["uninstrumented"] == sum(row["end"] - row["start"] for row in anchored)
    for field in ("whole_harness_statics_tier", "object_profile_conformance",
                  "timestamp_resolution", "channel_capacity", "instrument_fixity",
                  "actual_instrument_placement", "isolation", "security"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert contract.recheck_harness_gap_boundary_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy) == result
    assert certificate == contract.build_harness_gap_boundary_certificate(
        request, evidence, policy=policy)


def test_placement_order_does_not_move_the_gaps() -> None:
    reordered = list(reversed(PLACEMENTS))
    assert oracle(WINDOW, reordered, GAPS)[0] == "PASS"
    request, policy, evidence = selected(placements=reordered)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    covering = [{"instrument": "whole_tap", "start": 0, "end": 100}]
    assert oracle(WINDOW, covering, [])[0] == "PASS"
    request, policy, evidence = selected(placements=covering, gaps=[])
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "PASS" and result["evaluation"]["observations"]["gaps"] == []


_MOVED = [dict(GAPS[0], end=40), GAPS[1]]
_PHANTOM = [GAPS[0], {"name": "phantom", "start": 50, "end": 60}, GAPS[1]]
_WITHOUT_TOOL = [PLACEMENTS[0], PLACEMENTS[2]]
_OUTSIDE = [PLACEMENTS[0], PLACEMENTS[1], dict(PLACEMENTS[2], end=120)]


@pytest.mark.parametrize("name, gaps, placements", [
    ("gap-end-not-at-a-placement-start", _MOVED, PLACEMENTS),
    ("placement-removed-leaves-an-undeclared-uninstrumented-span", GAPS, _WITHOUT_TOOL),
    ("phantom-gap-over-an-instrumented-span", _PHANTOM, PLACEMENTS),
    ("placement-outside-the-session-window", GAPS, _OUTSIDE),
    ("gaps-not-in-ascending-order", list(reversed(GAPS)), PLACEMENTS),
])
def test_gap_not_bounded_by_named_placements_is_refuted(name, gaps, placements) -> None:
    assert oracle(WINDOW, placements, gaps)[0] == "FAIL", name
    request, policy, evidence = selected(gaps=gaps, placements=placements)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])
    assert result["gap_boundary"] == "NOT_ESTABLISHED"
    assert "gaps" not in result["evaluation"]["observations"]


@pytest.mark.parametrize("name, kwargs", [
    ("uncommitted-placements", {"committed": _WITHOUT_TOOL}),
    ("duplicate-gap-name", {"gaps": [GAPS[0], dict(GAPS[1], name=GAPS[0]["name"])]}),
    ("unnamed-placement", {"placements": [dict(PLACEMENTS[0], instrument=" "),
                                          PLACEMENTS[1], PLACEMENTS[2]]}),
    ("empty-window", {"window": {"start": 50, "end": 50}, "gaps": [],
                      "placements": [{"instrument": "x", "start": 50, "end": 51}]}),
])
def test_unbound_or_unnamed_retained_bytes_fail(name, kwargs) -> None:
    request, policy, evidence = selected(**kwargs)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])


@pytest.mark.parametrize("case", ["budget", "missing-evidence", "null-inputs", "empty-placements"])
def test_exhausted_or_absent_inputs_remain_unknown(case: str) -> None:
    if case == "budget":
        request, policy, evidence = selected(max_operations=8)
    elif case == "missing-evidence":
        request, policy, evidence = selected(include_evidence=False)
    elif case == "null-inputs":
        request, policy, evidence = selected(inputs=None)
    else:
        request, policy, evidence = selected(placements=[], gaps=[dict(WINDOW, name="all")])
    _, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN", result["evaluation"]["details"]
    assert result["gap_boundary"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("position", [0, 0.5, -2])
def test_one_flipped_certificate_bit_is_refused(position: float) -> None:
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    index = int(len(certificate) * position) if type(position) is float else position % len(certificate)
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(contract.HarnessGapBoundaryError):
        contract.recheck_harness_gap_boundary_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_or_verdict_is_refused() -> None:
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    decoy_request = selected(subject="decoy-harness")[0]
    with pytest.raises(contract.HarnessGapBoundaryError):
        contract.recheck_harness_gap_boundary_certificate(
            certificate, expected_request=decoy_request, policy=policy)
    other_policy = contract.harness_gap_boundary_policy(trust_roots=["another-root"])
    with pytest.raises(contract.HarnessGapBoundaryError):
        contract.recheck_harness_gap_boundary_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(contract.HarnessGapBoundaryError):
        contract.recheck_harness_gap_boundary_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    assert replay(*selected(subject="decoy-harness"))[1]["status"] == "FAIL"
    malformed = deepcopy(request)
    malformed["semantic_version"] = "verifier-current-object-obligations-0"
    with pytest.raises(contract.HarnessGapBoundaryError):
        contract.build_harness_gap_boundary_certificate(malformed, evidence, policy=policy)


def test_public_route_and_command_replay_the_selected_objective(tmp_path: Path, capsys) -> None:
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=contract.SEMANTIC_VERSION,
        objective=contract.COORDINATE, represented_kind="HARNESS",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["gap_boundary"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", contract.SEMANTIC_VERSION,
                 "--objective", contract.COORDINATE, "--represented-kind", "HARNESS",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1", "root_id": "harness",
                      "collection_digest": request["collection_digest"],
                      "bundle_digest": digest(bundle),
                      "requirements": [{"object_id": "harness", "tier": tier,
                                        "applicability": "REQUIRED",
                                        "rationale": "Selected gap boundary only",
                                        "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][2]["objectives"] = [{
        "semantic_version": contract.SEMANTIC_VERSION, "coordinate": contract.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": certificate_digest}]
    polished = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert polished["objectives"][0]["status"] == "PASS", polished["objectives"][0]
    assert polished["status"] == "UNKNOWN" and polished["polished"] is False


def test_retained_certificate_refuses_evidence_redaction() -> None:
    from verifier.privacy import (DisclosureBound, DisclosureSurface, EmissionContext,
                                  EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("HARNESS", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/harness_gap_boundary.py",
                                      "standard/CURRENT_HARNESS_GAP_BOUNDARY.md"])
def test_mechanism_sources_invalidate_polish(relative: str, monkeypatch) -> None:
    from verifier.runtime import polish

    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged statics dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("relative", [
    "domains/contracts/harness_gap_boundary.py", "domains/statics.py", "domains/common.py",
    "domains/contracts/retained_selection.py", "core/namespace.py",
    "standard/CURRENT_HARNESS_GAP_BOUNDARY.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative: str, monkeypatch) -> None:
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = SRC / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_harness_gap_boundary_certificate(
            certificate, expected_request=request, policy=policy)

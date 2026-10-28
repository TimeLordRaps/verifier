"""Current TIME-3.1: strictly increasing retained instants on one declared clock.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI). Instants are integer
microseconds on one declared clock. Counts and checking budgets are
dimensionless. The exact TIME-2.1 child and the TIME-3.1 parent are two
certificates, built and replayed separately; a child PASS never implies a
parent PASS. The mechanism is imported at use, so that on a source without it
every parent test fails as an absent capability while child controls still run.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import event_prerequisites, time_order


MODULE = "verifier.domains.contracts.time_strict"
SEMANTIC_VERSION = "verifier-current-object-obligations-1"
OBJECTIVE = "TIME-3.1"
CHILD_OBJECTIVE = "TIME-2.1"
EXCLUDED = ("causal_arrow", "clock_skew", "clock_identity", "clock_calibration",
            "wall_clock_truth", "cross_clock_relation", "minimum_spacing",
            "whole_time_statics", "privacy", "consent", "governance", "security",
            "object_profile_conformance")
EQUAL_PAIRS = {"first": (3, 3, 5, 8), "interior": (1, 4, 4, 8), "last": (1, 4, 8, 8)}


def strict() -> ModuleType:
    """Import the TIME-3.1 mechanism at use; its absence fails only parent tests."""
    from verifier.domains.contracts import time_strict
    return time_strict


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def samples_at(*instants: int) -> list[dict[str, Any]]:
    return [{"id": "s" + str(index), "at_us": at} for index, at in enumerate(instants)]


def child(instants: tuple[int, ...] = (2, 5, 7), *, start: int = 0, end: int = 10,
          clock: str = "test:clock", subject_id: str = "time-root",
          samples: list[dict[str, Any]] | None = None, include_inputs: bool = True,
          **limits: int) -> dict[str, Any]:
    """Build one exact TIME-2.1 selection and its certificate."""
    samples = samples if samples is not None else samples_at(*instants)
    subject = NamespaceObject.create(subject_id, "TIME", {
        "scope": "retained-declared-clock-order", "clock": clock,
        "unit": "microsecond", "span_start_us": start, "span_end_us": end,
        "samples_digest": digest(samples)})
    evidence = canonical_bytes({
        "schema_version": time_order.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"samples": samples} if include_inputs else None})
    policy = time_order.time_order_policy(trust_roots=["selected-retained-clock"])
    request = time_order.time_order_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    certificate = time_order.build_time_order_certificate(request, evidence, policy=policy)
    return {"request": request, "policy": policy, "evidence": evidence,
            "certificate": certificate}


def event_child() -> dict[str, Any]:
    """Build one valid EVENT-3.1 certificate: a real certificate of the wrong dependency."""
    fixed = [NamespaceObject.create("clock", "TIME", {}),
             NamespaceObject.create("place", "SPACE", {}),
             NamespaceObject.create("meaning", "OBJECT", {})]
    payloads = {"parent": {"value": "first"}, "root": {"value": "second"}}
    events = [NamespaceObject.create(name, "EVENT", {
        "scope": "retained-declared-prerequisites", "sequence": sequence,
        "prerequisites": parents, "payload_digest": digest(payloads[name])},
        {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]})
        for name, sequence, parents in (("parent", 1, []), ("root", 2, ["parent"]))]
    objects = [*fixed, *events]
    subject = events[1]
    evidence = canonical_bytes({
        "schema_version": event_prerequisites.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"payloads": payloads}})
    policy = event_prerequisites.event_prerequisites_policy(
        trust_roots=["selected-event-cone"])
    request = event_prerequisites.event_prerequisites_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits={})
    certificate = event_prerequisites.build_event_prerequisites_certificate(
        request, evidence, policy=policy)
    return {"request": request, "policy": policy, "evidence": evidence,
            "certificate": certificate}


def bind(selected: dict[str, Any], *, target: dict[str, Any] | None = None,
         certificate: bytes | None = None, encoded: str | None = None,
         schema_version: str | None = None, include_evidence: bool = True,
         **limits: int) -> dict[str, Any]:
    """Bind one TIME-3.1 selection to exactly one child; `target` names the subject."""
    module = strict()
    target = target if target is not None else selected["request"]
    certificate = certificate if certificate is not None else selected["certificate"]
    evidence = canonical_bytes({
        "schema_version": schema_version or module.EVIDENCE_VERSION,
        "child_request": selected["request"], "child_policy": selected["policy"],
        "child_certificate": (encoded if encoded is not None
                              else base64.b64encode(certificate).decode("ascii"))})
    policy = module.time_strict_policy(trust_roots=["selected-strict-clock"])
    request = module.time_strict_request(
        subject_id=target["subject_id"], object_digest=target["object_digest"],
        collection_digest=target["collection_digest"],
        child_request_digest=digest(selected["request"]),
        child_policy_digest=digest(selected["policy"]),
        child_certificate_digest=raw_digest(selected["certificate"]),
        evidence_ref=raw_digest(evidence), policy=policy, limits=limits)
    return {"request": request, "policy": policy,
            "evidence": evidence if include_evidence else None}


def build(case: dict[str, Any]) -> bytes:
    return strict().build_time_strict_certificate(
        case["request"], case["evidence"], policy=case["policy"])


def replay(case: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    certificate = build(case)
    result = strict().recheck_time_strict_certificate(
        certificate, expected_request=case["request"], policy=case["policy"])
    return certificate, result


def routed(case: dict[str, Any], certificate: bytes) -> dict[str, Any]:
    return routes.replay_current_object_certificate(
        certificate, semantic_version=SEMANTIC_VERSION, objective=OBJECTIVE,
        represented_kind="TIME", expected_request=case["request"], policy=case["policy"])


def child_status(selected: dict[str, Any]) -> str:
    """Replay the child alone through its own installed public route."""
    report = routes.replay_current_object_certificate(
        selected["certificate"], semantic_version=SEMANTIC_VERSION,
        objective=CHILD_OBJECTIVE, represented_kind="TIME",
        expected_request=selected["request"], policy=selected["policy"])
    return report["computational_status"]


def json_values(value: Any) -> int:
    """Count every JSON value: each object, array, member value and element is one."""
    if isinstance(value, dict):
        return 1 + sum(json_values(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(json_values(item) for item in value)
    return 1


def widest_container(value: Any) -> int:
    if isinstance(value, dict):
        return max([len(value), *(widest_container(item) for item in value.values())])
    if isinstance(value, list):
        return max([len(value), *(widest_container(item) for item in value)])
    return 0


# Child controls: these use only the installed TIME-2.1 route.

@pytest.mark.parametrize("position", sorted(EQUAL_PAIRS))
def test_child_alone_passes_equal_adjacent_instants(position: str) -> None:
    assert child_status(child(EQUAL_PAIRS[position])) == "PASS"


def test_child_alone_passes_strict_and_single_sample_controls() -> None:
    assert child_status(child((2, 5, 7))) == "PASS"
    assert child_status(child((5,))) == "PASS"


# Parent stricter than child.

@pytest.mark.parametrize("position", sorted(EQUAL_PAIRS))
def test_parent_fails_equal_adjacent_pair_that_child_passes(position: str) -> None:
    selected = child(EQUAL_PAIRS[position])
    assert child_status(selected) == "PASS"
    case = bind(selected)
    certificate, result = replay(case)
    assert result["status"] == "FAIL"
    assert result["strict_declared_order"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["details"] == (
        "declared clock instants are not strictly increasing")
    assert routed(case, certificate)["computational_status"] == "FAIL"


def test_strictly_increasing_samples_pass_without_physical_promotion() -> None:
    selected = child((2, 5, 7))
    case = bind(selected)
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    assert result["semantic_version"] == SEMANTIC_VERSION
    assert result["coordinate"] == OBJECTIVE and result["object_kind"] == "TIME"
    assert result["strict_declared_order"] == "PASS"
    assert all(result[key] == "NOT_ESTABLISHED" for key in EXCLUDED)
    assert result["evaluation"]["observations"]["samples"] == 3
    assert result["evaluation"]["observations"]["pairs"] == 2
    assert certificate == build(case)
    report = routed(case, certificate)
    assert report["computational_status"] == "PASS"
    assert report["native_result"] == result


def test_single_sample_passes_vacuously() -> None:
    _, result = replay(bind(child((5,))))
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["pairs"] == 0


def test_uniform_offset_and_largest_safe_instants_keep_strict_order() -> None:
    for shift in (0, 13, 1000000):
        _, result = replay(bind(child((2 + shift, 7 + shift), start=shift, end=10 + shift)))
        assert result["status"] == "PASS"
        assert result["clock_skew"] == "NOT_ESTABLISHED"
    largest = 2**53 - 1
    _, result = replay(bind(child((largest - 3, largest - 2), start=largest - 3, end=largest)))
    assert result["status"] == "PASS"


@pytest.mark.parametrize("instants,end", [((7, 2), 10), ((3, 10), 10), ((10,), 10)],
                         ids=["decreasing", "span_end_after_strict", "span_end_single"])
def test_child_failure_is_parent_failure(instants: tuple[int, ...], end: int) -> None:
    selected = child(instants, end=end)
    assert child_status(selected) == "FAIL"
    _, result = replay(bind(selected))
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "selected TIME-2.1 child did not pass"


# Substitution: wrong subject and wrong dependency.

@pytest.mark.parametrize("form", ["other_record", "other_clock", "other_span"])
def test_wrong_subject_child_fails(form: str) -> None:
    selected = child((2, 5, 7))
    other = {"other_record": lambda: child((2, 5, 7), subject_id="time-other"),
             "other_clock": lambda: child((2, 5, 7), clock="other:clock"),
             "other_span": lambda: child((2, 5, 7), end=11)}[form]()
    assert child_status(other) == "PASS"
    _, result = replay(bind(other, target=selected["request"]))
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "child is not selected TIME-2.1 subject"


@pytest.mark.parametrize("target", ["event_subject", "time_subject"])
def test_wrong_dependency_event_certificate_as_child_fails(target: str) -> None:
    wrong = event_child()
    report = routes.replay_current_object_certificate(
        wrong["certificate"], semantic_version=SEMANTIC_VERSION,
        objective=event_prerequisites.COORDINATE, represented_kind="EVENT",
        expected_request=wrong["request"], policy=wrong["policy"])
    assert report["computational_status"] == "PASS"
    selected = wrong["request"] if target == "event_subject" else child()["request"]
    _, result = replay(bind(wrong, target=selected))
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "child is not selected TIME-2.1 subject"


# Tamper and rehashed forgery.

def test_tampered_child_selection_or_certificate_fails() -> None:
    selected = child((2, 5, 7))
    altered = json.loads(selected["certificate"])
    altered["result"]["status"] = "FAIL"
    changed = canonical_bytes(altered)
    _, result = replay(bind(selected, certificate=changed))
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "selected child certificate differs"
    padded = base64.b64encode(selected["certificate"]).decode("ascii") + "\n"
    _, result = replay(bind(selected, encoded=padded))
    assert result["status"] == "FAIL"
    case = bind(selected)
    other = child((2, 5, 7), clock="other:clock")
    case["request"] = strict().time_strict_request(
        **{key: case["request"][key] for key in (
            "subject_id", "object_digest", "collection_digest",
            "child_policy_digest", "child_certificate_digest", "evidence_ref")},
        child_request_digest=digest(other["request"]), policy=case["policy"])
    _, result = replay(case)
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "selected child request or policy differs"


def test_parent_evidence_version_or_noncanonical_bytes_fail() -> None:
    selected = child((2, 5, 7))
    _, result = replay(bind(selected, schema_version="verifier-other-evidence-1"))
    assert result["status"] == "FAIL"
    case = bind(selected)
    spaced = json.dumps(json.loads(case["evidence"]), indent=1).encode("utf-8")
    case["request"] = strict().time_strict_request(
        **{key: case["request"][key] for key in (
            "subject_id", "object_digest", "collection_digest", "child_request_digest",
            "child_policy_digest", "child_certificate_digest")},
        evidence_ref=raw_digest(spaced), policy=case["policy"])
    case["evidence"] = spaced
    _, result = replay(case)
    assert result["status"] == "FAIL"


def test_tampered_parent_evidence_or_certificate_is_refused() -> None:
    module = strict()
    case = bind(child((2, 5, 7)))
    with pytest.raises(module.TimeStrictError):
        module.build_time_strict_certificate(
            case["request"], case["evidence"] + b" ", policy=case["policy"])
    certificate, _ = replay(case)
    flipped = certificate.replace(b'"status":"PASS"', b'"status":"FAIL"', 1)
    assert flipped != certificate
    with pytest.raises(module.TimeStrictError):
        module.recheck_time_strict_certificate(
            flipped, expected_request=case["request"], policy=case["policy"])
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routed(case, flipped)


def test_rehashed_parent_forgery_and_other_policy_are_refused() -> None:
    module = strict()
    case = bind(child(EQUAL_PAIRS["interior"]))
    certificate, result = replay(case)
    assert result["status"] == "FAIL"
    forged = json.loads(certificate)
    forged["result"]["status"] = "PASS"
    forged["result"]["strict_declared_order"] = "PASS"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(module.TimeStrictError):
        module.recheck_time_strict_certificate(
            canonical_bytes(forged), expected_request=case["request"], policy=case["policy"])
    other = deepcopy(case["policy"])
    other["trust_roots"] = ["other-root"]
    with pytest.raises(module.TimeStrictError):
        module.recheck_time_strict_certificate(
            certificate, expected_request=case["request"], policy=other)
    moved = deepcopy(case["request"])
    moved["subject_id"] = "other-time"
    with pytest.raises(module.TimeStrictError):
        module.recheck_time_strict_certificate(
            certificate, expected_request=moved, policy=case["policy"])


def test_rehashed_child_verdict_cannot_stand_in_for_child_replay() -> None:
    selected = child((3, 10), end=10)
    assert child_status(selected) == "FAIL"
    forged = json.loads(selected["certificate"])
    forged["result"]["status"] = "PASS"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    rehashed = dict(selected, certificate=canonical_bytes(forged))
    _, result = replay(bind(rehashed))
    assert result["status"] == "FAIL"
    assert result["evaluation"]["details"] == "selected TIME-2.1 child does not replay"


@pytest.mark.parametrize("relative", [
    "domains/contracts/time_strict.py", "domains/contracts/time_order.py",
    "domains/contracts/retained_selection.py", "domains/common.py",
    "core/namespace.py", "core/certificate.py", "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_TIME_STRICT.md", "standard/CURRENT_TIME_ORDER.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(
        relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module = strict()
    case = bind(child((2, 5, 7)))
    certificate, result = replay(case)
    assert result["status"] == "PASS"
    target = Path(module.__file__).parents[2] / relative
    assert target.is_file()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged strict-order dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        module.recheck_time_strict_certificate(
            certificate, expected_request=case["request"], policy=case["policy"])


# Missing evidence and limits.

def test_missing_evidence_and_unavailable_child_are_unknown() -> None:
    case = bind(child((2, 5, 7)), include_evidence=False)
    assert replay(case)[1]["status"] == "UNKNOWN"
    for selected in (child((2, 5, 7), include_inputs=False), child(samples=[]),
                     child((2, 5, 7), max_operations=1)):
        assert child_status(selected) == "UNKNOWN"
        _, result = replay(bind(selected))
        assert result["status"] == "UNKNOWN"
        assert result["evaluation"]["details"] == "selected TIME-2.1 child remains UNKNOWN"


@pytest.mark.parametrize("bound", ["max_operations", "max_items", "max_evidence_bytes"])
def test_exhausted_parent_limit_is_unknown(bound: str) -> None:
    _, result = replay(bind(child((2, 5, 7)), **{bound: 1}))
    assert result["status"] == "UNKNOWN"
    assert result["strict_declared_order"] == "NOT_ESTABLISHED"


def test_operation_and_sample_bounds_are_exact() -> None:
    instants = tuple(range(0, 26, 2))
    selected = child(instants, end=30)
    case = bind(selected)
    evidence = json.loads(case["evidence"])
    expected = json_values(evidence) + len(instants) - 1
    _, result = replay(case)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["operations"] == expected
    assert replay(bind(selected, max_operations=expected))[1]["status"] == "PASS"
    short = replay(bind(selected, max_operations=expected - 1))[1]
    assert short["status"] == "UNKNOWN"
    assert widest_container(evidence) < len(instants) - 1
    assert replay(bind(selected, max_items=len(instants)))[1]["status"] == "PASS"
    narrow = replay(bind(selected, max_items=len(instants) - 1))[1]
    assert narrow["status"] == "UNKNOWN"
    assert narrow["evaluation"]["details"] == "retained sample bound exhausted"


@pytest.mark.parametrize("limits", [
    {"max_operations": 100001}, {"max_items": 4097},
    {"max_evidence_bytes": 8 * 1024 * 1024 + 1}, {"max_operations": 0},
    {"max_objects": 1}, {"max_items": True},
], ids=["operations_above", "items_above", "bytes_above", "zero", "unknown_key", "boolean"])
def test_malformed_limits_are_refused_before_a_verdict(limits: dict[str, Any]) -> None:
    module = strict()
    with pytest.raises(module.TimeStrictError):
        bind(child((2, 5, 7)), **limits)


@pytest.mark.parametrize("field,value", [
    ("coordinate", CHILD_OBJECTIVE), ("object_kind", "EVENT"),
    ("semantic_version", "verifier-current-object-obligations-2"),
    ("subject_id", " "), ("child_certificate_digest", "sha256:" + "A" * 64),
])
def test_malformed_selection_is_refused_before_a_verdict(field: str, value: str) -> None:
    module = strict()
    case = bind(child((2, 5, 7)))
    case["request"][field] = value
    with pytest.raises(module.TimeStrictError):
        build(case)


def test_route_refuses_other_represented_kind() -> None:
    case = bind(child((2, 5, 7)))
    certificate, _ = replay(case)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=SEMANTIC_VERSION, objective=OBJECTIVE,
            represented_kind="EVENT", expected_request=case["request"],
            policy=case["policy"])


def test_direct_builder_rejects_foreign_comparison_before_callback() -> None:
    class HostileText(str):
        def __eq__(self, other: object) -> bool:
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other: object) -> bool:
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    module = strict()
    case = bind(child((2, 5, 7)))
    case["policy"]["schema_version"] = HostileText(module.POLICY_VERSION)
    with pytest.raises(module.TimeStrictError):
        build(case)
    case = bind(child((2, 5, 7)))
    case["request"]["coordinate"] = HostileText(OBJECTIVE)
    with pytest.raises(module.TimeStrictError):
        build(case)


def test_policy_factory_owns_mutable_trust_root_list() -> None:
    roots = ["selected-strict-clock"]
    policy = strict().time_strict_policy(trust_roots=roots)
    roots[0] = "changed"
    assert policy["trust_roots"] == ["selected-strict-clock"]


# Public surfaces and privacy registration.

def test_public_command_route_inventory_and_polish_keep_tier_boundary(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from verifier.domains.inventory import get_slot
    from verifier.runtime.polish import assess_polish
    from verifier.runtime.public_cli import main

    cases = {"pass": bind(child((2, 5, 7))), "fail": bind(child(EQUAL_PAIRS["last"])),
             "unknown": bind(child((2, 5, 7)), include_evidence=False)}
    for label, expected in (("pass", 0), ("fail", 1), ("unknown", 2)):
        case = cases[label]
        certificate = build(case)
        folder = tmp_path / label
        folder.mkdir()
        for name, contents in (("request", canonical_bytes(case["request"])),
                               ("policy", canonical_bytes(case["policy"])),
                               ("certificate", certificate)):
            (folder / (name + ".json")).write_bytes(contents)
        code = main(["current-object", "check", str(folder / "certificate.json"),
            "--semantic-version", SEMANTIC_VERSION, "--objective", OBJECTIVE,
            "--represented-kind", "TIME", "--request", str(folder / "request.json"),
            "--policy", str(folder / "policy.json"), "--json"])
        assert code == expected
        report = json.loads(capsys.readouterr().out)
        assert report["computational_status"] == label.upper()
    slot = get_slot("TIME", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == OBJECTIVE
    assert get_slot("TIME", 2).mechanized_route["artifact_coordinate"] == CHILD_OBJECTIVE
    selected = child((2, 5, 7))
    case = bind(selected)
    certificate = build(case)
    child_evidence = json.loads(selected["evidence"])
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": child_evidence["objects"],
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "time-root", "collection_digest": case["request"]["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "time-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected strict declared order only",
            "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][2]["objectives"] = [{
        "semantic_version": SEMANTIC_VERSION, "coordinate": OBJECTIVE,
        "request": case["request"], "policy": case["policy"],
        "certificate_digest": digest(json.loads(certificate))}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert report["objectives"][0]["status"] == "PASS", report["objectives"][0]
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


def test_retained_certificate_refuses_evidence_redaction() -> None:
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)
    from verifier.privacy import engine

    module = strict()
    assert module.CERTIFICATE_VERSION in engine._CANONICAL_CERTIFICATE_SCHEMAS
    certificate, result = replay(bind(child((2, 5, 7))))
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("TIME", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def test_specification_states_vacuity_exclusions_and_two_certificates() -> None:
    module = strict()
    text = (Path(module.__file__).parents[2] / "standard" / "CURRENT_TIME_STRICT.md"
            ).read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "A single retained sample passes vacuously" in flat
    assert ("One selected instance is two certificates: the TIME-3.1 parent and the "
            "exact TIME-2.1 child it embeds, which is owned by its TIME-2 obligation. "
            "It is not a checker call and not a duplicate certificate. How many "
            "instances the whole slot requires is UNKNOWN.") in flat
    exclusions = text.split("## Exclusions", 1)[1].split("\n## ", 1)[0]
    for phrase in ("causal arrow", "clock skew", "clock identity", "calibration",
                   "wall-clock truth", "relations between clocks", "minimum spacing",
                   "whole TIME statics tier", "privacy", "consent", "governance",
                   "security"):
        assert phrase in " ".join(exclusions.split()), phrase
    assert exclusions.count("NOT_ESTABLISHED") >= 1
    registration = module.registration()
    assert registration["coordinate"] == OBJECTIVE and registration["subject_kind"] == "TIME"

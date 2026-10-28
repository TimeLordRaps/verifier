"""Adversarial selected TIME inventory closure with exact retained child context.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). These declarations are neither physical time nor release proof.
"""
from __future__ import annotations

from asyncio import CancelledError
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.domains.contracts import time_closure, time_order
from test_current_time_order import selected as child_selected


DEFAULT_SAMPLES = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 7}]


def digest(value):
    return "sha256:" + canonical_digest(value)


def byte_digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selected(*, samples=None, required_samples=None, include_child_inputs=True,
             mutation=None, limits=None):
    samples = deepcopy(DEFAULT_SAMPLES if samples is None else samples)
    required_samples = deepcopy(samples if required_samples is None else required_samples)
    child_request, child_policy, child_evidence = child_selected(
        samples=samples, include_inputs=include_child_inputs)
    child_certificate = time_order.build_time_order_certificate(
        child_request, child_evidence, policy=child_policy)
    child_payload = json.loads(child_evidence)["objects"][0]["payload"]
    inventory = {"schema_version": time_closure.INVENTORY_VERSION,
        "subject_id": child_request["subject_id"], "object_digest": child_request["object_digest"],
        "collection_digest": child_request["collection_digest"], "clock": child_payload["clock"],
        "unit": "microsecond", "span_start_us": child_payload["span_start_us"],
        "span_end_us": child_payload["span_end_us"], "cutoff_us": child_payload["span_end_us"],
        "root_sample_id": required_samples[0]["id"],
        "terminal_sample_id": required_samples[-1]["id"], "samples": required_samples}
    expected_inventory = deepcopy(inventory)
    value = {"schema_version": time_closure.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "inventory": inventory}
    if mutation == "inventory-substitution":
        inventory["samples"][0]["at_us"] += 1
    elif mutation == "child-policy-substitution":
        value["child_policy"] = {**child_policy, "trust_roots": ["other-context"]}
    elif mutation == "child-certificate-substitution":
        changed = json.loads(child_certificate)
        changed["result"]["status"] = "PASS"
        changed["result"]["clock_authenticity"] = "PASS"
        changed.pop("digest")
        changed["digest"] = digest(changed)
        value["child_certificate"] = base64.b64encode(canonical_bytes(changed)).decode("ascii")
    raw = canonical_bytes(value)
    policy = time_closure.time_closure_policy(trust_roots=["test:external-time-inventory"])
    request = time_closure.time_closure_request(subject_id=child_request["subject_id"],
        object_digest=child_request["object_digest"], collection_digest=child_request["collection_digest"],
        child_request_digest=digest(child_request), child_policy_digest=digest(child_policy),
        child_certificate_digest=byte_digest(child_certificate), inventory_digest=digest(expected_inventory),
        inventory_count=len(expected_inventory["samples"]), root_sample_id=expected_inventory["root_sample_id"],
        terminal_sample_id=expected_inventory["terminal_sample_id"], clock=expected_inventory["clock"],
        span_start_us=expected_inventory["span_start_us"], span_end_us=expected_inventory["span_end_us"],
        cutoff_us=expected_inventory["cutoff_us"], evidence_ref=byte_digest(raw), policy=policy,
        limits=limits)
    return request, policy, raw


def replay(request, policy, raw):
    certificate = time_closure.build_time_closure_certificate(request, raw, policy=policy)
    result = time_closure.recheck_time_closure_certificate(certificate,
        expected_request=request, policy=policy)
    return certificate, result


def repack(request, raw, mutate, *, update_inventory_digest=False):
    value = json.loads(raw)
    mutate(value)
    raw = canonical_bytes(value)
    request = deepcopy(request)
    request["evidence_ref"] = byte_digest(raw)
    if update_inventory_digest:
        request["inventory_digest"] = digest(value["inventory"])
    return request, raw


def test_complete_selected_inventory_replays_without_physical_promotion():
    request, policy, raw = selected()
    certificate, result = replay(request, policy, raw)
    assert result["status"] == "PASS"
    assert result["selected_inventory_closure"] == "PASS"
    for field in ("external_inventory_completeness", "physical_clock_truth", "cross_clock_synchronization",
            "causal_order", "event_to_sample_binding", "continuous_temporal_coverage", "minimum_spacing",
            "actual_termination", "append_only_history", "whole_time_closure", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert certificate == time_closure.build_time_closure_certificate(request, raw, policy=policy)


def test_half_open_boundary_is_cutoff_and_neither_endpoint_requires_sample():
    request, policy, raw = selected()
    assert request["span_start_us"] == 0 and request["cutoff_us"] == 10
    samples = json.loads(raw)["inventory"]["samples"]
    assert samples[0]["at_us"] == 2 and samples[-1]["at_us"] == 7
    assert replay(request, policy, raw)[1]["status"] == "PASS"


def test_equal_instants_are_not_reinterpreted_as_strictness_or_causality():
    request, policy, raw = selected(samples=[{"id": "a", "at_us": 2}, {"id": "b", "at_us": 2}])
    assert replay(request, policy, raw)[1]["status"] == "PASS"


@pytest.mark.parametrize("samples", [DEFAULT_SAMPLES[:1], DEFAULT_SAMPLES + [{"id": "c", "at_us": 8}]])
def test_passing_child_cannot_hide_omission_or_extra_against_external_inventory(samples):
    request, policy, raw = selected(samples=samples, required_samples=DEFAULT_SAMPLES)
    value = json.loads(raw)
    child = base64.b64decode(value["child_certificate"])
    assert time_order.recheck_time_order_certificate(child,
        expected_request=value["child_request"], policy=value["child_policy"])["status"] == "PASS"
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_equal_instant_child_reordering_still_contradicts_selected_inventory():
    original = [{"id": "a", "at_us": 2}, {"id": "b", "at_us": 2}]
    assert replay(*selected(samples=list(reversed(original)), required_samples=original))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["inventory-substitution", "child-policy-substitution", "child-certificate-substitution"])
def test_rehashed_parent_bytes_do_not_select_child_or_inventory_authority(mutation):
    assert replay(*selected(mutation=mutation))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,replacement", [("clock", "other-clock"), ("span_end_us", 11),
    ("cutoff_us", 11), ("root_sample_id", "b"), ("terminal_sample_id", "a")])
def test_present_inventory_endpoint_metadata_disagreement_fails(field, replacement):
    request, policy, raw = selected()
    request, raw = repack(request, raw, lambda value: value["inventory"].update({field: replacement}),
        update_inventory_digest=True)
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


@pytest.mark.parametrize("samples", [[{"id": "a", "at_us": 10}], list(reversed(DEFAULT_SAMPLES)),
    [{"id": "a", "at_us": 2}, {"id": "a", "at_us": 7}]])
def test_genuine_child_refutations_remain_fail(samples):
    assert replay(*selected(samples=samples))[1]["status"] == "FAIL"


def test_missing_parent_or_child_support_remains_unknown():
    request, policy, _ = selected()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    assert replay(*selected(include_child_inputs=False))[1]["status"] == "UNKNOWN"
    assert replay(*selected(samples=[], required_samples=DEFAULT_SAMPLES))[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("limit", ["max_operations", "max_items", "max_evidence_bytes", "max_nesting_depth"])
def test_selected_capacity_exhaustion_remains_unknown(limit):
    assert replay(*selected(limits={limit: 1}))[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("exception", [OSError, ImportError, CancelledError])
def test_unavailable_or_cancelled_native_child_does_not_become_refutation(exception, monkeypatch):
    request, policy, raw = selected()
    def unavailable(*args, **kwargs):
        raise exception("test:child-unavailable")
    monkeypatch.setattr(time_order, "recheck_time_order_certificate", unavailable)
    assert replay(request, policy, raw)[1]["status"] == "UNKNOWN"


def test_rehashed_invented_parent_pass_is_refused():
    request, policy, raw = selected(samples=DEFAULT_SAMPLES[:1], required_samples=DEFAULT_SAMPLES)
    certificate, result = replay(request, policy, raw)
    assert result["status"] == "FAIL"
    value = json.loads(certificate)
    value["result"]["status"] = "PASS"
    value.pop("digest")
    value["digest"] = digest(value)
    with pytest.raises(time_closure.TimeClosureError):
        time_closure.recheck_time_closure_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", ["domains/contracts/time_closure.py", "domains/contracts/time_order.py",
    "domains/contracts/retained_selection.py", "domains/common.py", "core/namespace.py", "core/certificate.py",
    "core/evidence.py", "core/receipt.py", "standard/CURRENT_TIME_CLOSURE.md",
    "standard/CURRENT_TIME_ORDER.md", "standard/NAMESPACE_OBJECTS.md"])
def test_executed_dependency_bytes_invalidate_selected_policy(relative, monkeypatch):
    request, policy, raw = selected()
    certificate, _ = replay(request, policy, raw)
    original = Path.read_bytes
    target = Path(time_closure.__file__).parents[2] / relative
    def changed(path):
        contents = original(path)
        return contents + b"\nchanged time closure dependency\n" if path == target else contents
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(time_closure.TimeClosureError, match="installed mechanism"):
        time_closure.recheck_time_closure_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["inventory", "child_request", "child_policy", "child_certificate"])
def test_explicit_null_retained_support_stays_unknown(field):
    request, policy, raw = selected()
    request, raw = repack(request, raw, lambda value: value.update({field: None}))
    assert replay(request, policy, raw)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["digest", "count", "duplicate", "boundary", "endpoint", "order"])
@pytest.mark.parametrize("missing_child", [False, True])
def test_independently_inspectable_inventory_fail_dominates_unknown_child(case, missing_child):
    request, policy, raw = selected(include_child_inputs=False)
    def contradiction(value):
        if missing_child:
            value["child_certificate"] = None
        inventory = value["inventory"]
        if case == "digest": inventory["samples"][0]["at_us"] = 3
        elif case == "duplicate": inventory["samples"][1]["id"] = "a"
        elif case == "boundary": inventory["samples"][1]["at_us"] = 10
        elif case == "endpoint": inventory["root_sample_id"] = "other"
        elif case == "order": inventory["samples"] = list(reversed(inventory["samples"]))
    request, raw = repack(request, raw, contradiction, update_inventory_digest=case != "digest")
    if case == "count": request["inventory_count"] += 1
    if case == "endpoint": request["root_sample_id"] = "other"
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_replayed_child_fail_dominates_null_inventory():
    request, policy, raw = selected(samples=[{"id": "a", "at_us": 10}])
    request, raw = repack(request, raw, lambda value: value.update({"inventory": None}))
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_certificate_decoder_depth_is_unavailability_before_recursive_parse():
    request, policy, _ = selected()
    hostile = b'[' * 80 + b'0' + b']' * 80
    with pytest.raises(time_closure.TimeClosureUnavailable):
        time_closure.recheck_time_closure_certificate(hostile, expected_request=request, policy=policy)


@pytest.mark.parametrize("exception", [RecursionError, OverflowError])
def test_decoder_capacity_exceptions_do_not_refute_evidence(exception, monkeypatch):
    request, policy, raw = selected()
    def exhausted(*args, **kwargs):
        raise exception("test:decoder-capacity")
    monkeypatch.setattr(time_closure, "strict_json_loads", exhausted)
    certificate = time_closure.build_time_closure_certificate(request, raw, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "UNKNOWN"
    with pytest.raises(time_closure.TimeClosureUnavailable):
        time_closure.recheck_time_closure_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("missing,present_fault", [
    ("child_policy", "request-digest"), ("child_policy", "request-subject"),
    ("child_certificate", "policy-digest"), ("child_request", "policy-shape"),
    ("child_request", "certificate-digest"), ("child_policy", "certificate-base64"),
    ("child_policy", "certificate-shape")])
def test_partial_child_support_cannot_mask_present_selection_contradiction(missing, present_fault):
    request, policy, raw = selected()
    value = json.loads(raw)
    value[missing] = None
    if present_fault in ("request-digest", "request-subject"):
        value["child_request"]["subject_id"] = "different-time"
        if present_fault == "request-subject": request["child_request_digest"] = digest(value["child_request"])
    elif present_fault == "policy-digest":
        value["child_policy"]["trust_roots"] = ["different-context"]
    elif present_fault == "policy-shape":
        value["child_policy"] = {"schema_version": time_order.POLICY_VERSION}
        request["child_policy_digest"] = digest(value["child_policy"])
    elif present_fault == "certificate-digest":
        value["child_certificate"] = base64.b64encode(b"different certificate").decode("ascii")
    elif present_fault == "certificate-base64": value["child_certificate"] = "?"
    elif present_fault == "certificate-shape":
        malformed = canonical_bytes({"schema_version": time_order.CERTIFICATE_VERSION})
        value["child_certificate"] = base64.b64encode(malformed).decode("ascii")
        request["child_certificate_digest"] = byte_digest(malformed)
    raw = canonical_bytes(value)
    request["evidence_ref"] = byte_digest(raw)
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_limit_and_policy_inputs_are_owned_before_source_callbacks(monkeypatch):
    request, policy, raw = selected()
    supplied_limits = {"max_operations": 100000}
    supplied_roots = policy["trust_roots"]
    original = time_closure.mechanism_digest
    def mutate_inputs():
        supplied_limits["max_operations"] = 1
        supplied_roots[:] = ["mutated-after-selection"]
        return original()
    monkeypatch.setattr(time_closure, "mechanism_digest", mutate_inputs)
    admitted = time_closure._policy(policy)
    assert admitted["trust_roots"] == ["test:external-time-inventory"]
    policy["trust_roots"] = ["test:external-time-inventory"]
    supplied_roots = policy["trust_roots"]
    supplied_limits["max_operations"] = 100000
    kwargs = {key: request[key] for key in ("subject_id", "object_digest", "collection_digest",
        "child_request_digest", "child_policy_digest", "child_certificate_digest", "inventory_digest",
        "inventory_count", "root_sample_id", "terminal_sample_id", "clock", "span_start_us", "span_end_us",
        "cutoff_us", "evidence_ref")}
    captured = time_closure.time_closure_request(**kwargs, policy=policy, limits=supplied_limits)
    assert captured["limits"]["max_operations"] == 100000
    assert captured["policy_digest"] == digest(admitted)


def test_public_route_inventory_and_polish_preserve_exact_boundary(tmp_path, capsys):
    from verifier.domains.inventory import build_234_inventory
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, raw = selected()
    certificate, _ = replay(request, policy, raw)
    direct = replay_current_object_certificate(certificate, semantic_version=time_closure.SEMANTIC_VERSION,
        objective=time_closure.COORDINATE, represented_kind="TIME", expected_request=request, policy=policy)
    assert direct["computational_status"] == "PASS"
    assert direct["native_result"]["whole_time_closure"] == "NOT_ESTABLISHED"
    slot = next(s for s in build_234_inventory() if s.coordinate == time_closure.COORDINATE)
    assert slot.mechanized is True and slot.status == "REPLAYABLE"
    for name, contents in (("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)),
            ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    assert main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", time_closure.SEMANTIC_VERSION, "--objective", time_closure.COORDINATE,
        "--represented-kind", "TIME", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    child = json.loads(base64.b64decode(json.loads(raw)["child_certificate"]))
    child_data = json.loads(base64.b64decode(child["evidence_payloads"][child["request"]["evidence_ref"]]))
    cert_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": child_data["objects"],
        "certificates": {cert_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1", "root_id": request["subject_id"],
        "collection_digest": request["collection_digest"], "bundle_digest": digest(bundle),
        "requirements": [{"object_id": request["subject_id"], "tier": tier, "applicability": "REQUIRED",
            "rationale": "Selected finite declared clock inventory", "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][3]["objectives"] = [{"semantic_version": time_closure.SEMANTIC_VERSION,
        "coordinate": time_closure.COORDINATE, "request": request, "policy": policy,
        "certificate_digest": cert_digest}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False

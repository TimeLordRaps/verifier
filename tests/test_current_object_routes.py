"""Refutable tests for explicit current-object replay selection.

Acronyms: command-line interface (CLI); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Simulation (SIM); Verifier Standard (VSTD).
Counts are dimensionless.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import hyper_closure, object_facets, object_grounding
from verifier.domains.contracts.current_object_routes import (
    CurrentObjectRouteRefusal, current_object_route_catalog,
    replay_current_object_certificate,
)
from verifier.runtime.current_object_cli import (
    add_current_object_parsers, handle_current_object_command,
)
from verifier.runtime.public_cli import build_parser, main


SEMANTIC = "verifier-current-object-obligations-1"


def specimen(objective: str):
    if objective == "OBJECT-1.1":
        item = NamespaceObject.create("represented", "SIM", {"x": 1})
        policy = object_facets.object_facets_policy(trust_roots=("independent",))
        request = object_facets.object_facets_request(item, policy=policy)
        certificate = object_facets.build_object_facets_certificate(
            request, canonical_bytes(item.to_dict()), policy=policy)
        return "SIM", request, policy, certificate
    if objective == "SIM-5.1":
        model = canonical_bytes({
            "schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
            "initial_state": "idle",
            "virtual_hardware": [{"id": "cpu", "kind": "compute"}],
            "states": [{"id": "idle", "partition": "inside", "capabilities": ["cpu"]}],
            "actions": ["step"],
            "transitions": [{"source": "idle", "action": "step", "outcomes": [
                {"target": "idle", "effects": [{"kind": "internal_write", "target": "cpu"}]},
            ]}],
        })
        make = NamespaceObject.create
        objects = [make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
                   make("room", "OBJECT", {}), make("env", "ENV", {})]
        objects.append(make("sim", "SIM", {
            "isolation_evidence_digest": "sha256:" + hashlib.sha256(model).hexdigest(),
        }, {"data": ["data"], "verifier": ["verifier"],
            "objects": ["room"], "env": ["env"]}))
        policy = object_grounding.current_object_policy(trust_roots=("independent",))
        request = object_grounding.current_object_request(
            objects, sim_id="sim", isolation_evidence_bytes=model, policy=policy)
        certificate = object_grounding.build_current_object_certificate(
            request, objects, model, policy=policy)
        return "SIM", request, policy, certificate
    if objective == "HYPER-4.1":
        make = NamespaceObject.create
        objects = [make("t", "TIME", {}), make("s", "SPACE", {}),
                   make("meaning", "OBJECT", {}), make("d", "DATA", {}),
                   make("e", "EVENT", {}, {"time": ["t"], "space": ["s"],
                                           "meaning": ["meaning"]}),
                   make("h", "HYPER", {}, {"event": ["e"], "input": ["d"]})]
        policy = hyper_closure.hyper_closure_policy(trust_roots=("independent",))
        request = hyper_closure.hyper_closure_request(
            objects, hyper_id="h", policy=policy)
        certificate = hyper_closure.build_hyper_closure_certificate(
            request, objects, policy=policy)
        return "HYPER", request, policy, certificate
    raise AssertionError(objective)


@pytest.mark.parametrize("objective", ["OBJECT-1.1", "SIM-5.1", "HYPER-4.1"])
def test_three_exact_routes_replay_without_profile_promotion(objective):
    represented_kind, request, policy, certificate = specimen(objective)
    result = replay_current_object_certificate(
        certificate, semantic_version=SEMANTIC, objective=objective,
        represented_kind=represented_kind, expected_request=request, policy=policy)
    assert result["selection"] == {
        "semantic_version": SEMANTIC, "objective": objective,
        "represented_kind": represented_kind}
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["certificate_sha256"] == "sha256:" + hashlib.sha256(certificate).hexdigest()
    assert replay_current_object_certificate(
        certificate, semantic_version=SEMANTIC, objective=objective,
        represented_kind=represented_kind, expected_request=request, policy=policy) == result


def test_catalog_has_registered_objectives_without_profile_stamps():
    rows = current_object_route_catalog()
    expected_keys = {
        (SEMANTIC, "OBJECT-1.1"), (SEMANTIC, "OBJECT-8.1"), (SEMANTIC, "HARDWARE-2.1"), (SEMANTIC, "HARDWARE-2.2"), (SEMANTIC, "SIM-2.1"), (SEMANTIC, "SIM-2.2"), (SEMANTIC, "SIM-2.3"), (SEMANTIC, "SIM-2.4"), (SEMANTIC, "SIM-2.5"), (SEMANTIC, "SIM-3.4"), (SEMANTIC, "SIM-4.1"), (SEMANTIC, "SIM-4.2"), (SEMANTIC, "SIM-4.3"), (SEMANTIC, "SIM-4.4"), (SEMANTIC, "SIM-5.1"),
        *((SEMANTIC, kind + "-7." + str(stage)) for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split() for stage in range(1,7)),
        (SEMANTIC, "HYPER-4.1"), (SEMANTIC, "VERIFIER-2.1"), (SEMANTIC, "RECEIPT-9.1"), (SEMANTIC, "RECEIPT-9.2"),
        (SEMANTIC, "OBJECT-1.2"), (SEMANTIC, "HARDWARE-1.2"), (SEMANTIC, "HARDWARE-1.3"), (SEMANTIC, "IDENTITY-3.1"),
        (SEMANTIC, "TIME-2.1"), (SEMANTIC, "SPACE-3.1"), (SEMANTIC, "SPACE-4.1"), (SEMANTIC, "EVENT-3.1"), (SEMANTIC, "ARCH-3.1"),
        (SEMANTIC, "GRAPH-3.1"), (SEMANTIC, "GRAPH-4.1"), (SEMANTIC, "GRAPH-9.2"),
        (SEMANTIC, "EVENT-4.1"), (SEMANTIC, "TIME-3.1"), (SEMANTIC, "GRAPH-2.1"),
        (SEMANTIC, "DATA-1.2"), (SEMANTIC, "DATA-1.4"), (SEMANTIC, "DATA-2.1"),
        (SEMANTIC, "DATA-3.4"), (SEMANTIC, "DATA-4.1"), (SEMANTIC, "DATA-4.4"),
        (SEMANTIC, "ENV-1.2"), (SEMANTIC, "ENV-1.3"), (SEMANTIC, "ENV-1.4"), (SEMANTIC, "ENV-1.5"), (SEMANTIC, "ENV-2.3"), (SEMANTIC, "ENV-3.3"), (SEMANTIC, "ENV-4.1"),
        (SEMANTIC, "BENCH-1.2"), (SEMANTIC, "BENCH-1.4"), (SEMANTIC, "BENCH-3.6"), (SEMANTIC, "BENCH-4.4"),
        (SEMANTIC, "TRAIN-1.2"), (SEMANTIC, "TRAIN-1.3"), (SEMANTIC, "TRAIN-1.5"), (SEMANTIC, "TRAIN-2.1"), (SEMANTIC, "TRAIN-2.3"), (SEMANTIC, "TRAIN-4.1"),
        (SEMANTIC, "MODEL-1.5"), (SEMANTIC, "MODEL-1.2"), (SEMANTIC, "MODEL-2.1"), (SEMANTIC, "MODEL-3.1"), (SEMANTIC, "MODEL-3.2"), (SEMANTIC, "MODEL-3.3"), (SEMANTIC, "MODEL-3.4"), (SEMANTIC, "MODEL-3.5"), (SEMANTIC, "MODEL-3.7"), (SEMANTIC, "MODEL-4.2"), (SEMANTIC, "MODEL-4.4"),
        (SEMANTIC, "HARNESS-1.6"), (SEMANTIC, "HARNESS-2.1"), (SEMANTIC, "HARNESS-2.2"), (SEMANTIC, "HARNESS-2.3"), (SEMANTIC, "HARNESS-4.1"),
        (SEMANTIC, "AGENT-1.8"), (SEMANTIC, "AGENT-2.1"), (SEMANTIC, "AGENT-2.3"), (SEMANTIC, "AGENT-4.1"), (SEMANTIC, "AGENT-4.3"),
        (SEMANTIC, "BOT-1.6"), (SEMANTIC, "BOT-2.1"), (SEMANTIC, "BOT-2.2"), (SEMANTIC, "BOT-2.3"), (SEMANTIC, "BOT-4.1"),
        *((SEMANTIC, kind + "-6.7") for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()),
        *((SEMANTIC, kind + "-1.1") for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()),
        *((SEMANTIC, kind + "-8.1") for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()),
        *((SEMANTIC, "RECEIPT-9.3" if kind == "RECEIPT" else kind + "-9.1") for kind in "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split())}
    expected_keys |= {
        (SEMANTIC, kind + "-5.1") for kind in
        "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT BOT TOKEN".split()
    } | {(SEMANTIC, "TOKEN-2.1"), (SEMANTIC, "TOKEN-3.1"), (SEMANTIC, "TOKEN-4.1")}
    # Keys below are written from the packet RESULT files, never read back from the registry.
    expected_keys |= {(SEMANTIC, "RECEIPT-2.1"), (SEMANTIC, "RECEIPT-3.1"), (SEMANTIC, "RECEIPT-4.1")}  # w1
    expected_keys |= {(SEMANTIC, "OBJECT-3.1"), (SEMANTIC, "OBJECT-4.2")}  # w2
    expected_keys |= {(SEMANTIC, "OBJECT-2.1")}  # w2L
    expected_keys |= {(SEMANTIC, "ARCH-2.1"), (SEMANTIC, "TRAIN-3.2")}  # w3
    expected_keys |= {(SEMANTIC, "HYPER-2.3"), (SEMANTIC, "HYPER-3.1")}  # w4
    expected_keys |= {(SEMANTIC, "HARDWARE-3.1"), (SEMANTIC, "HARDWARE-4.1")}  # w5
    expected_keys |= {(SEMANTIC, "AGENT-3.1"), (SEMANTIC, "BOT-3.1"), (SEMANTIC, "HARNESS-3.1")}  # w7
    expected_keys |= {(SEMANTIC, "EVENT-2.1"), (SEMANTIC, "SPACE-2.1"), (SEMANTIC, "BENCH-2.1")}  # w8
    expected_keys |= {(SEMANTIC, "ACTOR-2.7"), (SEMANTIC, "ACTOR-3.3"), (SEMANTIC, "ACTOR-4.6")}  # w9
    expected_keys |= {(SEMANTIC, "HUMAN-2.5"), (SEMANTIC, "HUMAN-3.6"), (SEMANTIC, "HUMAN-4.3")}  # w10
    expected_keys |= {(SEMANTIC, "OWNER-2.6"), (SEMANTIC, "OWNER-4.3")}  # w11
    expected_keys |= {(SEMANTIC, "VERIFIER-3.1"), (SEMANTIC, "VERIFIER-4.1")}  # w6
    expected_keys |= {(SEMANTIC, "ROLE-3.1"), (SEMANTIC, "COLLECTIVE-3.1"), (SEMANTIC, "ROLE-2.1"), (SEMANTIC, "COLLECTIVE-2.1"), (SEMANTIC, "ARCH-4.1")}  # t4
    expected_keys |= {(SEMANTIC, "OWNER-3.1"), (SEMANTIC, "TIME-4.1"), (SEMANTIC, "ROLE-4.1"), (SEMANTIC, "COLLECTIVE-4.1"), (SEMANTIC, "IDENTITY-2.1"), (SEMANTIC, "IDENTITY-4.1")}
    assert {(row["semantic_version"], row["objective"]) for row in rows} == expected_keys
    assert len(rows) == len(expected_keys)
    assert len(rows) == 408
    assert len({(row["semantic_version"], row["objective"]) for row in rows}) == len(rows)
    assert all(row["object_profile_conformance"] == "NOT_ESTABLISHED" for row in rows)


@pytest.mark.parametrize("change", [
    {"semantic_version": "verifier-domain-obligations-1"},
    {"objective": "SIM-1.1"},
    {"objective": "HYPER-4.1"},
    {"represented_kind": "OBJECT"},
])
def test_wrong_external_selector_refused_before_cert_self_description(change):
    kind, request, policy, certificate = specimen("SIM-5.1")
    selection = {"semantic_version": SEMANTIC, "objective": "SIM-5.1",
                 "represented_kind": kind}
    selection.update(change)
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate, expected_request=request,
                                          policy=policy, **selection)


def test_generic_object_route_keeps_represented_kind_separate():
    kind, request, policy, certificate = specimen("OBJECT-1.1")
    assert kind == "SIM" and request["coordinate"] == "OBJECT-1.1"
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
            objective="OBJECT-1.1", represented_kind="OBJECT",
            expected_request=request, policy=policy)


def test_changed_request_policy_and_rehashed_certificate_refuse():
    kind, request, policy, certificate = specimen("OBJECT-1.1")
    args = {"semantic_version": SEMANTIC, "objective": "OBJECT-1.1",
            "represented_kind": kind}
    wrong_request = deepcopy(request)
    wrong_request["object_id"] = "another"
    wrong_policy = deepcopy(policy)
    wrong_policy["trust_roots"] = ["different"]
    for selected_request, selected_policy, encoded in (
        (wrong_request, policy, certificate), (request, wrong_policy, certificate)):
        with pytest.raises(CurrentObjectRouteRefusal):
            replay_current_object_certificate(encoded, expected_request=selected_request,
                                              policy=selected_policy, **args)
    forged = json.loads(certificate)
    forged["result"]["status"] = "UNKNOWN"
    forged["digest"] = "sha256:" + canonical_digest(
        {key: value for key, value in forged.items() if key != "digest"})
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(canonical_bytes(forged),
            expected_request=request, policy=policy, **args)


def test_missing_retained_evidence_remains_reproduced_unknown():
    item = NamespaceObject.create("record", "OBJECT", {"x": 1})
    policy = object_facets.object_facets_policy(trust_roots=("independent",))
    request = object_facets.object_facets_request(item, policy=policy)
    certificate = object_facets.build_object_facets_certificate(request, None, policy=policy)
    result = replay_current_object_certificate(certificate,
        semantic_version=SEMANTIC, objective="OBJECT-1.1", represented_kind="OBJECT",
        expected_request=request, policy=policy)
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("limited", ["max_operations", "max_reference_bytes"])
def test_generic_checker_exhaustion_stays_reproduced_unknown(limited):
    item = NamespaceObject.create("relation", "HYPER", {}, {"edge": ["unresolved"]})
    policy = object_facets.object_facets_policy(trust_roots=("independent",))
    request = object_facets.object_facets_request(item, policy=policy)
    record = canonical_bytes(item.to_dict())
    ordinary = object_facets.build_object_facets_certificate(request, record, policy=policy)
    selected = {"semantic_version": SEMANTIC, "objective": "OBJECT-1.1",
                "represented_kind": "HYPER"}
    assert replay_current_object_certificate(ordinary, expected_request=request,
        policy=policy, **selected)["computational_status"] == "PASS"
    bounded_request = deepcopy(request)
    bounded_request["limits"][limited] = 1
    exhausted = object_facets.build_object_facets_certificate(
        bounded_request, record, policy=policy)
    result = replay_current_object_certificate(exhausted,
        expected_request=bounded_request, policy=policy, **selected)
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == "UNKNOWN"


def test_explicit_sim_escape_stays_reproduced_fail():
    model = canonical_bytes({
        "schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
        "initial_state": "idle",
        "virtual_hardware": [{"id": "cpu", "kind": "compute"}],
        "states": [{"id": "idle", "partition": "inside", "capabilities": ["cpu"]}],
        "actions": ["step"],
        "transitions": [{"source": "idle", "action": "step", "outcomes": [
            {"target": "idle", "effects": [
                {"kind": "external_export", "target": "host:network"}]},
        ]}],
    })
    make = NamespaceObject.create
    objects = [make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
               make("room", "OBJECT", {}), make("env", "ENV", {})]
    objects.append(make("sim", "SIM", {
        "isolation_evidence_digest": "sha256:" + hashlib.sha256(model).hexdigest(),
    }, {"data": ["data"], "verifier": ["verifier"],
        "objects": ["room"], "env": ["env"]}))
    policy = object_grounding.current_object_policy(trust_roots=("independent",))
    request = object_grounding.current_object_request(
        objects, sim_id="sim", isolation_evidence_bytes=model, policy=policy)
    certificate = object_grounding.build_current_object_certificate(
        request, objects, model, policy=policy)
    result = replay_current_object_certificate(certificate,
        semantic_version=SEMANTIC, objective="SIM-5.1", represented_kind="SIM",
        expected_request=request, policy=policy)
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == "FAIL"
    assert result["native_result"]["authority"] == "NOT_ESTABLISHED"


def test_plain_selector_types_and_nominal_profile_routes_refuse():
    class EqStr(str):
        def __eq__(self, _other):
            return True

    kind, request, policy, certificate = specimen("OBJECT-1.1")
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate,
            semantic_version=EqStr(SEMANTIC), objective="OBJECT-1.1",
            represented_kind=kind, expected_request=request, policy=policy)
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate,
            semantic_version=SEMANTIC, objective="SIM-1.1",
            represented_kind="SIM", expected_request=request, policy=policy)
    wrong_request = deepcopy(request)
    wrong_request["limits"]["max_operations"] = 1.0
    with pytest.raises(CurrentObjectRouteRefusal):
        replay_current_object_certificate(certificate,
            semantic_version=SEMANTIC, objective="OBJECT-1.1",
            represented_kind=kind, expected_request=wrong_request, policy=policy)


def test_public_cli_reads_local_files_and_leaves_them_unchanged(tmp_path, capsys):
    kind, request, policy, certificate = specimen("OBJECT-1.1")
    certificate_path = tmp_path / "certificate.json"
    request_path = tmp_path / "request.json"
    policy_path = tmp_path / "policy.json"
    certificate_path.write_bytes(certificate)
    request_path.write_bytes(canonical_bytes(request))
    policy_path.write_bytes(canonical_bytes(policy))
    parser = argparse.ArgumentParser()
    add_current_object_parsers(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["current-object", "check", str(certificate_path),
        "--semantic-version", SEMANTIC, "--objective", "OBJECT-1.1",
        "--represented-kind", kind, "--request", str(request_path),
        "--policy", str(policy_path), "--json"])
    before = tuple(path.read_bytes() for path in
                   (certificate_path, request_path, policy_path))
    assert handle_current_object_command(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["selection"]["objective"] == "OBJECT-1.1"
    assert report["selection"]["represented_kind"] == "SIM"
    assert tuple(path.read_bytes() for path in
                 (certificate_path, request_path, policy_path)) == before
    assert "current-object" in next(a for a in build_parser()._actions
        if isinstance(a, argparse._SubParsersAction)).choices


def test_cli_rejects_unknown_route_before_opening_certificate(capsys):
    parser = argparse.ArgumentParser()
    add_current_object_parsers(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["current-object", "check", "missing-certificate.json",
        "--semantic-version", SEMANTIC, "--objective", "ACTOR-2.1",
        "--represented-kind", "ACTOR", "--request", "missing-request.json",
        "--policy", "missing-policy.json", "--json"])
    assert handle_current_object_command(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REJECTED"
    assert report["computational_status"] == "NOT_CHECKED"
    assert "unsupported" in report["error"]


def test_public_cli_main_catalog_and_json(capsys):
    exit_code = main(["current-object", "catalog"])
    assert exit_code == 0
    text_out = capsys.readouterr().out
    assert "OBJECT-1.1" in text_out
    assert "SIM-5.1" in text_out
    assert "HYPER-4.1" in text_out

    exit_code_json = main(["current-object", "catalog", "--json"])
    assert exit_code_json == 0
    json_out = json.loads(capsys.readouterr().out)
    assert json_out["schema_version"] == "verifier-current-object-route-catalog-1"
    # Transport bookkeeping follows the native census; the separate exact-key
    # contract above still requires deliberate additions for every new route.
    native_rows = current_object_route_catalog()
    assert json_out["routes"] == native_rows
    assert len(json_out["routes"]) == len(native_rows)
    assert len({(row["semantic_version"], row["objective"]) for row in json_out["routes"]}) == len(native_rows)
    assert all(row["object_profile_conformance"] == "NOT_ESTABLISHED" for row in json_out["routes"])


@pytest.mark.parametrize("objective", ["OBJECT-1.1", "SIM-5.1", "HYPER-4.1"])
def test_public_cli_main_check_pass(tmp_path, capsys, objective):
    kind, request, policy, certificate = specimen(objective)
    cert_path = tmp_path / f"{objective}_cert.json"
    req_path = tmp_path / f"{objective}_req.json"
    pol_path = tmp_path / f"{objective}_pol.json"
    cert_path.write_bytes(certificate)
    req_path.write_bytes(canonical_bytes(request))
    pol_path.write_bytes(canonical_bytes(policy))

    exit_code = main([
        "current-object", "check", str(cert_path),
        "--semantic-version", SEMANTIC, "--objective", objective,
        "--represented-kind", kind, "--request", str(req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert report["selection"]["objective"] == objective
    assert report["selection"]["represented_kind"] == kind


def test_public_cli_main_check_fail_sim_escape(tmp_path, capsys):
    model = canonical_bytes({
        "schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
        "initial_state": "idle",
        "virtual_hardware": [{"id": "cpu", "kind": "compute"}],
        "states": [
            {"id": "idle", "partition": "inside", "capabilities": ["cpu"]},
            {"id": "escaped", "partition": "outside", "capabilities": []},
        ],
        "actions": ["step"],
        "transitions": [{"source": "idle", "action": "step", "outcomes": [
            {"target": "escaped", "effects": [{"kind": "external_effect", "target": "host"}]},
        ]}],
    })
    make = NamespaceObject.create
    objects = [make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
               make("room", "OBJECT", {}), make("env", "ENV", {})]
    objects.append(make("sim", "SIM", {
        "isolation_evidence_digest": "sha256:" + hashlib.sha256(model).hexdigest(),
    }, {"data": ["data"], "verifier": ["verifier"],
        "objects": ["room"], "env": ["env"]}))
    policy = object_grounding.current_object_policy(trust_roots=("independent",))
    request = object_grounding.current_object_request(
        objects, sim_id="sim", isolation_evidence_bytes=model, policy=policy)
    certificate = object_grounding.build_current_object_certificate(
        request, objects, model, policy=policy)

    cert_path = tmp_path / "sim_escape_cert.json"
    req_path = tmp_path / "sim_escape_req.json"
    pol_path = tmp_path / "sim_escape_pol.json"
    cert_path.write_bytes(certificate)
    req_path.write_bytes(canonical_bytes(request))
    pol_path.write_bytes(canonical_bytes(policy))

    exit_code = main([
        "current-object", "check", str(cert_path),
        "--semantic-version", SEMANTIC, "--objective", "SIM-5.1",
        "--represented-kind", "SIM", "--request", str(req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "FAIL"


def test_public_cli_main_check_unknown_missing_evidence(tmp_path, capsys):
    item = NamespaceObject.create("rep", "SIM", {"x": 1})
    policy = object_facets.object_facets_policy(trust_roots=("independent",))
    request = object_facets.object_facets_request(item, policy=policy)
    certificate = object_facets.build_object_facets_certificate(request, None, policy=policy)

    cert_path = tmp_path / "unknown_cert.json"
    req_path = tmp_path / "unknown_req.json"
    pol_path = tmp_path / "unknown_pol.json"
    cert_path.write_bytes(certificate)
    req_path.write_bytes(canonical_bytes(request))
    pol_path.write_bytes(canonical_bytes(policy))

    exit_code = main([
        "current-object", "check", str(cert_path),
        "--semantic-version", SEMANTIC, "--objective", "OBJECT-1.1",
        "--represented-kind", "SIM", "--request", str(req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "UNKNOWN"


def test_public_cli_main_check_rejected_cases(tmp_path, capsys):
    kind, request, policy, certificate = specimen("OBJECT-1.1")
    cert_path = tmp_path / "cert.json"
    req_path = tmp_path / "req.json"
    pol_path = tmp_path / "pol.json"
    cert_path.write_bytes(certificate)
    req_path.write_bytes(canonical_bytes(request))
    pol_path.write_bytes(canonical_bytes(policy))

    # 1. Unavailable file
    exit_code = main([
        "current-object", "check", str(tmp_path / "missing.json"),
        "--semantic-version", SEMANTIC, "--objective", "OBJECT-1.1",
        "--represented-kind", kind, "--request", str(req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REJECTED"

    # 2. Malformed certificate bytes
    bad_cert = tmp_path / "bad_cert.json"
    bad_cert.write_bytes(b"{not valid json")
    exit_code = main([
        "current-object", "check", str(bad_cert),
        "--semantic-version", SEMANTIC, "--objective", "OBJECT-1.1",
        "--represented-kind", kind, "--request", str(req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REJECTED"

    # 3. Substituted request (wrong coordinate)
    sub_req = deepcopy(request)
    sub_req["coordinate"] = "OBJECT-2.1"
    sub_req_path = tmp_path / "sub_req.json"
    sub_req_path.write_bytes(canonical_bytes(sub_req))
    exit_code = main([
        "current-object", "check", str(cert_path),
        "--semantic-version", SEMANTIC, "--objective", "OBJECT-1.1",
        "--represented-kind", kind, "--request", str(sub_req_path),
        "--policy", str(pol_path), "--json",
    ])
    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["replay_status"] == "REJECTED"


def test_installed_wheel_current_object_qualification(tmp_path, wheel_source):
    repo_root = wheel_source
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    subprocess.check_call(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-cache-dir", "-w", str(wheel_dir), str(repo_root)],
        timeout=60,
    )
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    target_dir = tmp_path / "site-packages"
    target_dir.mkdir()
    with zipfile.ZipFile(wheels[0]) as archive:
        archive.extractall(target_dir)

    work_dir = tmp_path / "isolated_workspace"
    work_dir.mkdir()

    kind, request, policy, certificate = specimen("OBJECT-1.1")
    cert_path = work_dir / "certificate.json"
    req_path = work_dir / "request.json"
    pol_path = work_dir / "policy.json"
    cert_path.write_bytes(certificate)
    req_path.write_bytes(canonical_bytes(request))
    pol_path.write_bytes(canonical_bytes(policy))

    env = {
        "PYTHONPATH": str(target_dir),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PATH": os.environ.get("PATH", ""),
    }

    # 1. Test catalog in isolated process
    proc_catalog = subprocess.run(
        [sys.executable, "-S", "-c",
         "import sys; from verifier.runtime.public_cli import main; sys.exit(main(['current-object', 'catalog', '--json']))"],
        cwd=str(work_dir), env=env, capture_output=True, text=True, timeout=30, check=True,
    )
    catalog_report = json.loads(proc_catalog.stdout)
    assert catalog_report["schema_version"] == "verifier-current-object-route-catalog-1"
    # Installed transport must preserve the exact source catalogue, not an old total.
    native_rows = current_object_route_catalog()
    assert catalog_report["routes"] == native_rows
    assert len(catalog_report["routes"]) == len(native_rows)

    # 2. Test check in isolated process
    proc_check = subprocess.run(
        [sys.executable, "-S", "-c",
         "import sys; from verifier.runtime.public_cli import main; "
         f"sys.exit(main(['current-object', 'check', '{cert_path.name}', "
         f"'--semantic-version', '{SEMANTIC}', '--objective', 'OBJECT-1.1', "
         f"'--represented-kind', '{kind}', '--request', '{req_path.name}', "
         f"'--policy', '{pol_path.name}', '--json']))"],
        cwd=str(work_dir), env=env, capture_output=True, text=True, timeout=30, check=True,
    )
    check_report = json.loads(proc_check.stdout)
    assert check_report["replay_status"] == "REPRODUCED"
    assert check_report["computational_status"] == "PASS"
    assert check_report["selection"]["objective"] == "OBJECT-1.1"

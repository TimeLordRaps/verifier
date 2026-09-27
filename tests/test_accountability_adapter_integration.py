"""Native accountability adapter registration stays aligned with portable envelopes.

Verifier Standard (VSTD) certificate depth is a dimensionless count of retained
checks. Registration alone does not establish numbered-profile conformance.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from importlib import import_module, util
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from verifier.domains.catalog import ALL_CHECKS, ALL_SCOPES, COORDINATES, domain_specification_digest
from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate,
)
from verifier.domains.common import digest
from test_human_identity_domains import human_specimen, identity_specimen
from test_role_collective_domains import _role, _collective_decisions


FAMILY = ("HUMAN", "IDENTITY", "ROLE", "COLLECTIVE")


@pytest.mark.parametrize("domain", FAMILY)
def test_accountability_adapter_has_a_bound_native_request(domain: str) -> None:
    assert domain in ALL_CHECKS, domain
    assert domain in ALL_SCOPES, domain
    assert len(ALL_CHECKS[domain]) == len(COORDINATES[domain]) > 0
    assert all(coordinate.startswith(domain + "-") for coordinate in COORDINATES[domain])
    assert hasattr(import_module("verifier.domains." + domain.lower()), "evaluate")

    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": domain,
                "subject_id": "subject:test", "artifact": {}, "inputs": {}}
    request = domain_request(evidence)
    assert request["domain"] == domain
    assert request["target_depth"] == len(ALL_CHECKS[domain])


@pytest.mark.parametrize("domain", FAMILY)
def test_all_three_portable_envelopes_name_accountability_domain(domain: str) -> None:
    schemas = files("verifier.schemas")
    evidence = json.loads(schemas.joinpath("verifier-domain-evidence-1.schema.json").read_text(encoding="utf-8"))
    request = json.loads(schemas.joinpath("verifier-domain-request-1.schema.json").read_text(encoding="utf-8"))
    certificate = json.loads(schemas.joinpath("verifier-domain-certification-1.schema.json").read_text(encoding="utf-8"))
    assert domain in evidence["properties"]["domain"]["enum"], domain
    assert domain in request["properties"]["domain"]["enum"], domain
    for schema in (evidence, request, certificate["properties"]["evidence"],
                   certificate["properties"]["request"]):
        assert any(branch.get("if", {}).get("properties", {}).get("domain", {}).get("const") == domain
                   for branch in schema["allOf"]), domain
    for part in ("evidence", "request"):
        assert domain in certificate["properties"][part]["properties"]["domain"]["enum"], domain
    pattern = next(iter(certificate["properties"]["result"]["properties"]["checks"]["patternProperties"]))
    assert domain in pattern, domain


@pytest.mark.parametrize(("domain", "specimen", "subject"), (
    ("HUMAN", human_specimen, "pseudonym-1"),
    ("IDENTITY", identity_specimen, "identity:bot-1:seat-1"),
    ("ROLE", _role, "seat-1"),
    ("COLLECTIVE", _collective_decisions, "collective:1"),
))
def test_accountability_certificate_build_schema_and_replay(domain, specimen, subject) -> None:
    artifact, inputs = specimen()
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": domain,
                "subject_id": subject, "artifact": artifact, "inputs": inputs}
    request = domain_request(evidence, target_depth=2)
    policy = domain_policy(trust_roots=["test:accountability-root"])
    certificate = build_domain_certificate(request, evidence, policy=policy)

    schemas = files("verifier.schemas")
    for filename, document in (
        ("verifier-domain-evidence-1.schema.json", evidence),
        ("verifier-domain-request-1.schema.json", request),
        ("verifier-domain-certification-1.schema.json", certificate),
    ):
        schema = json.loads(schemas.joinpath(filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS", (domain, result)
    assert result["domain_depth"] == 2
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert list(result["checks"]) == list(COORDINATES[domain][:2])
    certificate["result"]["status"] = "FAIL"
    assert recheck_domain_certificate(certificate, expected_request=request, policy=policy)["status"] == "REJECTED"


def test_human_full_depth_preserves_unknown_closure() -> None:
    artifact, inputs = human_specimen()
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "HUMAN",
                "subject_id": "pseudonym-1", "artifact": artifact, "inputs": inputs}
    request = domain_request(evidence)
    policy = domain_policy(trust_roots=["test:accountability-root"])
    certificate = build_domain_certificate(request, evidence, policy=policy)
    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert result["domain_depth"] == 2
    assert result["checks"]["HUMAN-4.4"]["evaluation"]["outcome"] == "UNKNOWN"


def test_specification_digest_binds_accountability_checks(monkeypatch) -> None:
    original = ALL_CHECKS["ROLE"]
    baseline = domain_specification_digest()
    monkeypatch.setitem(ALL_CHECKS, "ROLE", ((original[0][0], original[0][1] + " revised", ()),) + original[1:])
    assert domain_specification_digest() != baseline


def _nested_bot_identity() -> tuple[dict, dict]:
    example = Path(__file__).resolve().parents[1] / "examples" / "domain_grounding.py"
    spec = util.spec_from_file_location("accountability_nested_example", example)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bot_evidence = module.specimens()["BOT"]
    policy = domain_policy(trust_roots=["test:accountability-root"])
    bot_certificate = build_domain_certificate(domain_request(bot_evidence, target_depth=1),
                                                bot_evidence, policy=policy)
    assert bot_certificate["result"]["status"] == "PASS"

    role_artifact, role_inputs = _role()
    role_inputs["occupancy_events"] = [{"position": 0, "event": "take",
                                         "bearer_id": "example:bot", "bearer_class": "bot"}]
    role_artifact["admissible_bearer_classes"] = ["bot"]
    role_artifact["occupancy_events_digest"] = digest(role_inputs["occupancy_events"])
    role_artifact["current_occupants"] = ["example:bot"]
    role_evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "ROLE",
                     "subject_id": "seat-1", "artifact": role_artifact, "inputs": role_inputs}
    role_certificate = build_domain_certificate(domain_request(role_evidence, target_depth=2),
                                                 role_evidence, policy=policy)
    assert role_certificate["result"]["status"] == "PASS"

    artifact, inputs = identity_specimen()
    artifact["bearer_subject_id"] = "example:bot"
    artifact["simulation_id"] = "example:sim"
    artifact["inherited_scope"] = "simulation:example:sim"
    inputs["bearer_certificate"] = bot_certificate
    inputs["role_certificate"] = role_certificate
    inputs["occupancy_evidence"]["bearer_subject_id"] = "example:bot"
    for event in inputs["events"]:
        event["bearer_subject_id"] = "example:bot"
    artifact["bearer_certificate_digest"] = digest(bot_certificate)
    artifact["role_certificate_digest"] = digest(role_certificate)
    artifact["occupancy_digest"] = digest(inputs["occupancy_evidence"])
    artifact["events_digest"] = digest(inputs["events"])
    return {"schema_version": "verifier-domain-evidence-1", "domain": "IDENTITY",
            "subject_id": "identity:example:bot:seat-1", "artifact": artifact, "inputs": inputs}, policy


def test_nested_bot_identity_supports_only_declared_occupied_role_and_world() -> None:
    evidence, policy = _nested_bot_identity()
    result = build_domain_certificate(domain_request(evidence), evidence, policy=policy)["result"]
    assert result["status"] == "PASS", result
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation", ("inadmissible_role", "different_occupant", "different_world", "unsupported_assurance"))
def test_nested_bot_identity_refuses_cross_certificate_substitution(mutation: str) -> None:
    evidence, policy = _nested_bot_identity()
    evidence = deepcopy(evidence)
    artifact, inputs = evidence["artifact"], evidence["inputs"]
    if mutation in {"inadmissible_role", "different_occupant"}:
        role_evidence = deepcopy(inputs["role_certificate"]["evidence"])
        role_artifact, role_inputs = role_evidence["artifact"], role_evidence["inputs"]
        if mutation == "inadmissible_role":
            role_artifact["admissible_bearer_classes"] = ["human"]
            role_inputs["occupancy_events"][0]["bearer_class"] = "human"
        else:
            role_inputs["occupancy_events"][0]["bearer_id"] = "another:bot"
            role_artifact["current_occupants"] = ["another:bot"]
        role_artifact["occupancy_events_digest"] = digest(role_inputs["occupancy_events"])
        child = build_domain_certificate(domain_request(role_evidence), role_evidence, policy=policy)
        assert child["result"]["status"] == "PASS"
        inputs["role_certificate"] = child
        artifact["role_certificate_digest"] = digest(child)
    elif mutation == "different_world":
        artifact["simulation_id"] = "another:sim"
        artifact["inherited_scope"] = "simulation:another:sim"
    else:
        artifact["assurance_level"] = "independent-personhood"
    result = build_domain_certificate(domain_request(evidence), evidence, policy=policy)["result"]
    assert result["status"] != "PASS", (mutation, result)


@pytest.mark.parametrize(("domain", "specimen", "subject"), (
    ("HUMAN", human_specimen, "pseudonym-1"),
    ("IDENTITY", identity_specimen, "identity:bot-1:seat-1"),
    ("ROLE", _role, "seat-1"),
    ("COLLECTIVE", _collective_decisions, "collective:1"),
))
def test_accountability_public_cli_assess_and_check(tmp_path, domain, specimen, subject) -> None:
    artifact, inputs = specimen()
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": domain,
                "subject_id": subject, "artifact": artifact, "inputs": inputs}
    request = domain_request(evidence, target_depth=2)
    policy = domain_policy(trust_roots=["test:accountability-root"])
    for name, document in (("evidence", evidence), ("request", request), ("policy", policy)):
        (tmp_path / f"{name}.json").write_text(json.dumps(document), encoding="utf-8")
    certificate = tmp_path / "certificate.json"
    root = Path(__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": str(root / "src")}
    base = [sys.executable, "-B", "-m", "verifier", "certification"]
    assessed = subprocess.run(base + ["domain-assess", str(tmp_path / "evidence.json"),
        "--request", str(tmp_path / "request.json"), "--policy", str(tmp_path / "policy.json"),
        "--output", str(certificate), "--json"], capture_output=True, text=True,
        timeout=30, env=environment)
    assert assessed.returncode == 0, assessed.stdout + assessed.stderr
    assert certificate.exists()
    checked = subprocess.run(base + ["domain-check", str(certificate),
        "--request", str(tmp_path / "request.json"), "--policy", str(tmp_path / "policy.json"),
        "--json"], capture_output=True, text=True, timeout=30, env=environment)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert json.loads(checked.stdout)["domain_depth"] == 2

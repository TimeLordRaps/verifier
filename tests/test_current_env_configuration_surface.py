"""Selected ENV configuration domains; labels are not live host observations.

Verifier Standard (VSTD); verifiable execution environment (ENV); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless; byte ceilings measure bytes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import env_configuration_surface, typed_facets


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selected(*, config: dict | None = None, surface: dict | None = None,
             missing_child: bool = False, limits: dict | None = None) -> Any:
    module = env_configuration_surface
    declared = surface if surface is not None else {
        "byteorder": {"kind": "enum", "values": ["little", "big"]},
        "threads": {"kind": "integer", "minimum": 1, "maximum": 16},
        "features": {"kind": "array", "items": {"kind": "string",
                     "minimum_length": 1, "maximum_length": 20},
                     "minimum_length": 0, "maximum_length": 4},
    }
    values = config if config is not None else {
        "byteorder": "little", "threads": 4, "features": ["fft", "cpu"],
    }
    subject = NamespaceObject.create("environment", "ENV", {
        "scope": "retained-process-observations",
        "configuration_surface": declared,
        "configuration": values,
    })
    collection = composition_digest([subject])
    child_evidence = canonical_bytes({
        "schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [subject.to_dict()],
    })
    child_policy = typed_facets.typed_facets_policy(
        trust_roots=["selected-env-facets"],
    )
    child_request = typed_facets.typed_facets_request(
        object_kind="ENV", subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=collection,
        evidence_ref=digest(child_evidence), policy=child_policy,
    )
    child_certificate = typed_facets.build_typed_facets_certificate(
        child_request, child_evidence, policy=child_policy,
    )
    assert typed_facets.recheck_typed_facets_certificate(
        child_certificate, expected_request=child_request, policy=child_policy,
    )["status"] == "PASS"
    evidence = canonical_bytes({
        "schema_version": module.EVIDENCE_VERSION,
        "facets_certificate_b64": ("" if missing_child else
                                    base64.b64encode(child_certificate).decode("ascii")),
    })
    policy = module.env_configuration_surface_policy(
        trust_roots=["selected-env-configuration"],
    )
    request = module.env_configuration_surface_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=collection, evidence_ref=digest(evidence),
        required_surface=declared,
        facets_certificate_digest=digest(child_certificate),
        facets_request=child_request, facets_policy=child_policy,
        policy=policy, limits=limits,
    )
    return module, request, policy, evidence


def replay(module: Any, request: Any, policy: Any, evidence: Any) -> Any:
    certificate = module.build_env_configuration_surface_certificate(
        request, evidence, policy=policy,
    )
    return module.recheck_env_configuration_surface_certificate(
        certificate, expected_request=request, policy=policy,
    )["status"]


def test_selected_required_configuration_domains_replay() -> None:
    assert replay(*selected()) == "PASS"


@pytest.mark.parametrize("config", [
    {"byteorder": "little", "threads": 0, "features": ["fft"]},
    {"byteorder": "little", "threads": True, "features": ["fft"]},
    {"byteorder": "little", "threads": 4, "features": ["fft", 3]},
    {"byteorder": "middle", "threads": 4, "features": []},
    {"byteorder": "little", "threads": 4},
    {"byteorder": "little", "threads": 4, "features": [], "hidden": "x"},
])
def test_out_of_domain_and_incomplete_configuration_fail(config: Any) -> None:
    assert replay(*selected(config=config)) == "FAIL"


def test_missing_selected_facet_certificate_is_unknown() -> None:
    assert replay(*selected(missing_child=True)) == "UNKNOWN"


def test_external_surface_substitution_is_rejected() -> None:
    module, request, policy, evidence = selected()
    certificate = module.build_env_configuration_surface_certificate(
        request, evidence, policy=policy,
    )
    changed = deepcopy(request)
    changed["required_surface"]["threads"]["maximum"] = 64
    with pytest.raises(module.EnvConfigurationSurfaceError):
        module.recheck_env_configuration_surface_certificate(
            certificate, expected_request=changed, policy=policy,
        )


def test_malformed_empty_value_domain_is_rejected() -> None:
    surface = {"mode": {"kind": "enum", "values": []}}
    with pytest.raises(ValueError):
        selected(surface=surface, config={"mode": "fast"})


def test_selected_surface_cannot_equate_boolean_and_integer_literals() -> None:
    artifact_surface = {"mode": {"kind": "literal", "value": True}}
    module, request, policy, evidence = selected(
        surface=artifact_surface, config={"mode": 1},
    )
    changed = deepcopy(request)
    changed["required_surface"]["mode"]["value"] = 1
    assert replay(module, changed, policy, evidence) == "FAIL"


def test_nested_domains_admit_selected_values_and_refute_wrong_nested_value() -> None:
    surface = {
        "limits": {"kind": "record", "fields": {
            "ratio": {"kind": "number", "minimum": 0, "maximum": 1},
            "enabled": {"kind": "boolean"},
        }},
        "mode": {"kind": "union", "options": [
            {"kind": "literal", "value": "automatic"},
            {"kind": "integer", "minimum": 1, "maximum": 4},
        ]},
    }
    config = {"limits": {"ratio": 0.5, "enabled": True}, "mode": 2}
    assert replay(*selected(surface=surface, config=config)) == "PASS"
    wrong = deepcopy(config)
    wrong["limits"]["enabled"] = 1
    assert replay(*selected(surface=surface, config=wrong)) == "FAIL"


def test_selected_child_collection_substitution_rejected() -> None:
    module, request, policy, evidence = selected()
    changed = deepcopy(request)
    changed["facets_request"]["collection_digest"] = digest(b"other collection")
    with pytest.raises(module.EnvConfigurationSurfaceError):
        module.build_env_configuration_surface_certificate(
            changed, evidence, policy=policy,
        )


def test_child_certificate_byte_limit_stays_unknown() -> None:
    module, request, policy, evidence = selected()
    child = base64.b64decode(json.loads(evidence)["facets_certificate_b64"])
    changed = deepcopy(request)
    changed["limits"]["max_child_certificate_bytes"] = len(child) - 1
    assert replay(module, changed, policy, evidence) == "UNKNOWN"


def test_large_literal_comparison_exhausts_parent_operation_budget() -> None:
    large = "x" * 12000
    surface = {"blob": {"kind": "literal", "value": large}}
    module, request, policy, evidence = selected(
        surface=surface, config={"blob": large},
        limits={"max_operations": 10000},
    )
    assert replay(module, request, policy, evidence) == "UNKNOWN"


def test_recomputed_parent_result_forgery_is_rejected() -> None:
    module, request, policy, evidence = selected()
    certificate = module.build_env_configuration_surface_certificate(
        request, evidence, policy=policy,
    )
    changed = json.loads(certificate)
    changed["result"]["status"] = "UNKNOWN"
    changed.pop("digest")
    changed["digest"] = digest(canonical_bytes(changed))
    with pytest.raises(module.EnvConfigurationSurfaceError):
        module.recheck_env_configuration_surface_certificate(
            canonical_bytes(changed), expected_request=request, policy=policy,
        )


def test_rehashed_forged_child_result_cannot_supply_prerequisite() -> None:
    module, request, policy, evidence = selected()
    retained = json.loads(evidence)
    child = json.loads(base64.b64decode(retained["facets_certificate_b64"]))
    child["result"]["status"] = "FAIL"
    child.pop("digest")
    child["digest"] = digest(canonical_bytes(child))
    forged_child = canonical_bytes(child)
    retained["facets_certificate_b64"] = base64.b64encode(forged_child).decode("ascii")
    changed_evidence = canonical_bytes(retained)
    changed_request = deepcopy(request)
    changed_request["facets_certificate_digest"] = digest(forged_child)
    changed_request["evidence_ref"] = digest(changed_evidence)
    assert replay(module, changed_request, policy, changed_evidence) == "FAIL"


def test_public_route_replays_selected_configuration_surface(tmp_path: Any, capsys: Any) -> None:
    from verifier.domains.contracts import current_object_routes as routes
    from verifier.runtime.public_cli import main

    module, request, policy, evidence = selected()
    certificate = module.build_env_configuration_surface_certificate(
        request, evidence, policy=policy,
    )
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=module.SEMANTIC_VERSION,
        objective=module.COORDINATE, represented_kind="ENV",
        expected_request=request, policy=policy,
    )
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["live_host_configuration"] == "NOT_ESTABLISHED"
    assert report["native_result"]["external_surface_completeness"] == "NOT_ESTABLISHED"
    for stem, raw in (("certificate", certificate), ("request", canonical_bytes(request)),
                      ("policy", canonical_bytes(policy))):
        (tmp_path / (stem + ".json")).write_bytes(raw)
    assert main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", module.SEMANTIC_VERSION,
        "--objective", module.COORDINATE, "--represented-kind", "ENV",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_configuration_certificate_cannot_redact_child_evidence() -> None:
    from verifier.privacy import (
        DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty,
    )

    module, request, policy, evidence = selected()
    envelope = json.loads(module.build_env_configuration_surface_certificate(
        request, evidence, policy=policy,
    ))
    fields = tuple(key for key in envelope if key != "evidence_payloads")
    surface = DisclosureSurface("ENV", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(envelope, surface, bounds, context)

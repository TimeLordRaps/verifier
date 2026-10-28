"""Independent finite simulation (SIM) refutation and uncertainty guards.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). State/action/effect
counts are dimensionless. Retained edge reachability is independent of unknown
effect meaning; these fixtures establish no physical containment or authority.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import current_object_routes, object_grounding, sim_isolation


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def evidence() -> dict:
    return {"schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "selected-simulation",
            "initial_state": "ready", "virtual_hardware": [{"id": "store", "kind": "storage"}],
            "states": [{"id": "ready", "partition": "inside", "capabilities": ["store"]}],
            "actions": ["tick"], "transitions": [{"source": "ready", "action": "tick",
            "outcomes": [{"target": "ready", "effects": []}]}]}


def replay(value: dict) -> dict:
    raw = encoded(value)
    selected_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    binding = {"sim_id": value["sim_id"], "evidence_digest": selected_digest,
               "max_operations": 1000, "max_items": 64}
    result = sim_isolation.assess_sim_isolation(value, expected_binding=binding)
    assert sim_isolation.recheck_sim_isolation(result, value, expected_binding=binding) == result
    make = NamespaceObject.create
    objects = [make("data", "DATA", {}), make("checker", "VERIFIER", {}),
               make("room", "OBJECT", {}), make("environment", "ENV", {}),
               make(value["sim_id"], "SIM", {"isolation_evidence_digest": selected_digest},
                    {"data": ["data"], "verifier": ["checker"], "objects": ["room"], "env": ["environment"]})]
    policy = object_grounding.current_object_policy(trust_roots=("selected-regression-fixture",))
    request = object_grounding.current_object_request(objects, sim_id=value["sim_id"],
                isolation_evidence_bytes=raw, policy=policy)
    certificate = object_grounding.build_current_object_certificate(request, objects, raw, policy=policy)
    native = object_grounding.recheck_current_object_certificate(certificate, expected_request=request, policy=policy)
    public = current_object_routes.replay_current_object_certificate(certificate,
                semantic_version="verifier-current-object-obligations-1", objective="SIM-5.1",
                represented_kind="SIM", expected_request=request, policy=policy)
    assert result["status"] == native["status"] == public["computational_status"]
    assert public["replay_status"] == "REPRODUCED"
    assert native["physical_host_containment"] == native["authority"] == "NOT_ESTABLISHED"
    assert native["sim_tier_5_conformance"] == native["object_profile_conformance"] == "NOT_ESTABLISHED"
    return result


@pytest.mark.parametrize("kind", ["outside_write", "external_actuation", "external_export", "capability_acquire"])
@pytest.mark.parametrize("placement", ["same-outcome", "other-outcome", "downstream"])
def test_unknown_effect_does_not_hide_an_independently_reachable_refutation(kind: str, placement: str) -> None:
    value = evidence()
    uncertain = {"kind": "unregistered-effect", "target": "uninterpreted-target"}
    violation = {"kind": kind, "target": "outside-resource"}
    first = value["transitions"][0]
    if placement == "same-outcome":
        first["outcomes"][0]["effects"] = [uncertain, violation]
    elif placement == "other-outcome":
        first["outcomes"] = [{"target": "ready", "effects": [uncertain]},
                             {"target": "ready", "effects": [violation]}]
    else:
        value["states"].append({"id": "next", "partition": "inside", "capabilities": ["store"]})
        first["outcomes"] = [{"target": "next", "effects": [uncertain]}]
        value["transitions"].append({"source": "next", "action": "tick",
                                    "outcomes": [{"target": "next", "effects": [violation]}]})
        # The selected edge declares this reachability; its effect is never
        # presumed safe or assigned semantics by this independent oracle.
        assert first["outcomes"][0]["target"] == "next"
    result = replay(value)
    assert result["status"] == "FAIL", result
    assert "crosses isolation boundary" in result["reason"]


@pytest.mark.parametrize("kind,status", [("unregistered-effect", "UNKNOWN"), ("internal_write", "FAIL")])
def test_unsupported_unheld_target_remains_distinct_from_supported_unheld_write(kind: str, status: str) -> None:
    value = evidence()
    value["transitions"][0]["outcomes"][0]["effects"] = [{"kind": kind, "target": "not-held"}]
    assert replay(value)["status"] == status


def test_unknown_hardware_remains_unadmitted_before_reachable_refutation() -> None:
    value = evidence()
    value["virtual_hardware"][0]["kind"] = "unregistered-hardware"
    value["transitions"][0]["outcomes"][0]["effects"] = [{"kind": "external_export", "target": "outside-resource"}]
    assert replay(value)["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["unregistered-effect", "external_export"])
def test_unreachable_unsupported_or_boundary_effect_does_not_refute_selected_reachable_model(kind: str) -> None:
    value = evidence()
    value["states"].append({"id": "disconnected", "partition": "inside", "capabilities": ["store"]})
    value["transitions"].append({"source": "disconnected", "action": "tick",
                                "outcomes": [{"target": "disconnected", "effects": [{"kind": kind, "target": "outside-resource"}]}]})
    result = replay(value)
    assert result["status"] == "PASS"
    assert result["reachable_states"] == 1 and result["unreachable_states"] == 1

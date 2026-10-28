"""Central public replay for finite documentary Independence contracts.

command-line interface (CLI); JavaScript Object Notation (JSON).
Registered predicates do not establish whole-tier or real-world independence.
"""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import independence_checks as contract
from verifier.domains.inventory import get_slot
from test_current_independence_checks import inputs, reselect

KINDS = tuple(contract.KIND_SCOPES)


def certificate_case(kind: str, case: str) -> tuple[dict, dict, bytes]:
    c, request, policy, evidence = inputs(kind)
    if case == "shared":
        evidence["sources"]["checker"]["parents"] = ["producer-support"]
        reselect(c, request, policy, evidence)
    elif case == "missing":
        evidence["artifacts"].pop(evidence["sources"]["checker-support"]["artifact_ref"])
        reselect(c, request, policy, evidence)
    encoded = c.build_independence_checks_certificate(request, canonical_bytes(evidence), policy=policy)
    return request, policy, encoded


def public_replay(request: dict, policy: dict, encoded: bytes) -> dict:
    return routes.replay_current_object_certificate(encoded, semantic_version=contract.SEMANTIC_VERSION,
        objective=request["coordinate"], represented_kind=request["object_kind"],
        expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("case,expected", [("pass", "PASS"), ("shared", "FAIL"), ("missing", "UNKNOWN")])
def test_each_independence_route_preserves_documentary_verdicts(kind: str, case: str, expected: str) -> None:
    request, policy, encoded = certificate_case(kind, case)
    report = public_replay(request, policy, encoded)
    assert report["schema_version"] == "verifier-current-object-route-replay-1"
    assert report["computational_status"] == expected
    assert report["replay_status"] == "REPRODUCED"
    assert report["native_result"]["independence_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["native_result"]["source_authenticity"] == "UNKNOWN"
    assert all(report["native_result"]["dimensions"][name] == "UNKNOWN"
        for name in contract.DIMENSIONS if name != "retained_provenance")
    assert "documentary source-footprint" in report["claim_boundary"]
    assert "causal/statistical independence remain UNKNOWN" in report["claim_boundary"]
    assert get_slot(kind, 5).coordinate == kind + "-5.1"


def test_independence_catalog_preserves_sim_and_exact_kind_metadata() -> None:
    catalog = {row["objective"]: row for row in routes.current_object_route_catalog()}
    for kind in KINDS:
        row = catalog[kind + "-5.1"]
        assert row["represented_kind_rule"] == kind
        assert row["proposition_digest"] == contract.IndependenceChecksDescriptor(kind).PROPOSITION_DIGEST
        assert row["certificate_schema_version"] == contract.CERTIFICATE_VERSION
    assert catalog["SIM-5.1"]["certificate_schema_version"] != contract.CERTIFICATE_VERSION
    assert get_slot("SIM", 5).coordinate == "SIM-5.1"


@pytest.mark.parametrize("field", ["dimensions", "source_authenticity", "independence_tier_conformance"])
def test_public_wrapper_refuses_native_real_world_promotion(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, encoded = certificate_case("MODEL", "pass")
    identity = contract.SEMANTIC_VERSION, "MODEL-5.1"
    original = routes._ROUTES[identity]
    def overclaim(*args: object, **kwargs: object) -> dict:
        result = original.replay(*args, **kwargs)
        if field == "dimensions":
            result["dimensions"]["causal"] = "PASS"
        else:
            result[field] = "PASS"
        return result
    monkeypatch.setitem(routes._ROUTES, identity, replace(original, replay=overclaim))
    with pytest.raises(routes.CurrentObjectRouteRefusal, match="documentary boundary"):
        public_replay(request, policy, encoded)


def test_independence_certificate_cannot_disclose_a_redacted_witness() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    _, _, encoded = certificate_case("MODEL", "pass")
    value = json.loads(encoded)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("MODEL", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "local-check"), "2026-10-01T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)

"""Fixed one-way projections for four reviewed BENCH registrations."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import bench_checks, current_object_routes


SCHEMA_VERSION = "verifier-current-bench-checks-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = "3f8b72dab3d6d6b379db5b2362bc3413f840bf35095d9816bf45bae52a7a5bdb"
NATIVE_SOURCE_PATH = "src/verifier/domains/contracts/bench_checks.py"
NATIVE_SOURCE_SHA256 = "3826e27fba32889349b989be5e6362bcc5a04ddce8aa897e1243b31bc13a4e5a"
ROUTE_SOURCE_PATH = "src/verifier/domains/contracts/current_object_routes.py"
ROUTE_SOURCE_SHA256 = "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
REJECTED_ROUTE_SELECTOR_SHA256 = "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
ACCEPTANCE_MECHANISM_ID = "verifier.domains.contracts.bench_checks.recheck_bench_checks_certificate"
UNION_SOURCE = {
    "uri": "producer-source://src/verifier/standard/CURRENT_BENCH_CHECKS.md",
    "sha256": "sha256:f920f7f0a968e3a8c7f51297d018cad1c58606fd2078e8d9059ce9c347b69623",
}
SOURCE_MAP_DIGEST = "sha256:ad55a1f640e1811a4f87ebdf68786752e2e9887735ee2513802a654d6cd3d25f"
PRODUCER_SOURCE_COORDINATE_DIGEST = "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462"
CANDIDATE_INPUT_DIGEST = "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc"

_ACCEPTED = {
    "problems": (
        "BENCH-1.2", 1, "finite_retained_bench_problems",
        "route-instance:bf1b19d698462619ea217aa39145953869c7b85a56aa8fcac1b2adcab8ef29f3",
        "union-candidate:fbccbe17018c4cd1b2c3dc3376f54768da8f9d254d467d34d610086ad547a2ad",
        "sha256:3a4972cdaa2f0a2263f671274603ae8ae1b1f4ea509f374dc6723954cc5ce740",
        "sha256:0b99d361c2c56c4684097bc14f089d8e4cc41b34df8aee23d1c05ddbc77021fe", 8, 1,
    ),
    "oracles": (
        "BENCH-1.4", 1, "finite_retained_bench_oracles",
        "route-instance:2bec6f2af7ec2be4330bb7689d904211c8704fc657085933639386a8b9cbe087",
        "union-candidate:96e8c02421ec62ba47c1b13db4fdca505a9d510e8579c4b51ed48d90b4d5e77a",
        "sha256:d1764836c5993e1f201ce834e0c30e296cc80c129a8c4c26c99bda56244f63a2",
        "sha256:94f54c950957facb333fe5f4995e9a7c31dfafab2baa6c9940ea64dffe719631", 8, 2,
    ),
    "budgets": (
        "BENCH-3.6", 3, "finite_retained_bench_budgets",
        "route-instance:f8ddd64d979def30e5b8475dbc434acbd6e33ff85171cc9aa7b30270267cc639",
        "union-candidate:ecc7be9520dbefc98d75f633aa9a32103d99adca3a9dfd2a2d8a3a8e4fabea1f",
        "sha256:8ad9a1fb6e15609b8b1c9247cd2c477dceebcf713f7da8c472a1a91db230e749",
        "sha256:caaaf4fe8662bb2c0258ba21b49a95f76567ee7c4bf23e185823f0b69d0d2c9e", 8, 4,
    ),
    "coverage": (
        "BENCH-4.4", 4, "finite_retained_bench_coverage",
        "route-instance:7c60da08992652f85706c88dcf8a61739bb063138939ea0fbde16710e5770e7e",
        "union-candidate:5c110e33b232564a513df2387eeac04eb77de46a9bab3756e4dd262981dcd3e6",
        "sha256:636aabd2a103c0007f5f14d0c3f89a772831c9adc4361c4deb558b5948dc4a77",
        "sha256:a4e2f3fe465bf360531bd514b385e53d4933b34d0bc98134e9479c76c6ae837f", 8, 5,
    ),
}
MAPPED_CHECKS = tuple(_ACCEPTED)
EXCLUDED_DISJOINT_MEMBER = "BENCH-2.1"


class BenchChecksProjectionRefusal(ValueError):
    """The input is outside the exact four-row reviewed mapping."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_source_bindings() -> dict[str, dict[str, str]]:
    sources = {
        "bench_checks": (Path(bench_checks.__file__).resolve(), NATIVE_SOURCE_PATH, NATIVE_SOURCE_SHA256),
        "route_catalog": (Path(current_object_routes.__file__).resolve(), ROUTE_SOURCE_PATH,
                          ROUTE_SOURCE_SHA256),
    }
    result = {}
    for name, (path, logical, expected) in sources.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise BenchChecksProjectionRefusal(name + " source differs from reviewed bytes")
        result[name] = {"path": logical, "sha256": actual}
    return result


def accepted_projection(check: str) -> dict[str, Any]:
    if type(check) is not str or check not in _ACCEPTED:
        raise BenchChecksProjectionRefusal("check is outside the fixed reviewed BENCH set")
    member, tier, scope, route_id, union_id, route_digest, claim_digest, ci, ri = _ACCEPTED[check]
    return {
        "check": check, "object_kind": "BENCH", "tier": tier, "member_id": member,
        "scope": scope, "route_instance_id": route_id, "union_ref_id": union_id,
        "route_registration_digest": route_digest, "union_claim_digest": claim_digest,
        "source": dict(UNION_SOURCE), "source_map_digest": SOURCE_MAP_DIGEST,
        "producer_source_coordinate_digest": PRODUCER_SOURCE_COORDINATE_DIGEST,
        "candidate_input_digest": CANDIDATE_INPUT_DIGEST,
        "contribution_index": ci, "row_index": ri,
    }


def project_registration(check: str, native_registration: Mapping[str, Any],
                         union_candidate: Mapping[str, Any], *,
                         direction: str = "ROUTE_TO_UNION") -> dict[str, Any]:
    pin = accepted_projection(check)
    if direction != "ROUTE_TO_UNION":
        raise BenchChecksProjectionRefusal("only ROUTE_TO_UNION narrowing is admitted")
    expected = bench_checks.registration(check)
    if dict(native_registration) != expected:
        raise BenchChecksProjectionRefusal("native registration differs from reviewed registration")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise BenchChecksProjectionRefusal("native registration digest differs")
    required = {key: pin[key] for key in (
        "check", "object_kind", "tier", "member_id", "scope", "route_instance_id",
        "union_ref_id", "source", "source_map_digest", "producer_source_coordinate_digest",
        "candidate_input_digest", "contribution_index", "row_index",
    )}
    required["claim_sha256"] = pin["union_claim_digest"]
    for field, value in required.items():
        if union_candidate.get(field) != value:
            raise BenchChecksProjectionRefusal("union candidate has substituted " + field)
    text = union_candidate.get("claim_text")
    if type(text) is not str or text != expected["proposition"] or _text_digest(text) != pin["union_claim_digest"]:
        raise BenchChecksProjectionRefusal("union claim does not preserve exact proposition text")
    return {
        "schema_version": SCHEMA_VERSION, "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "check": check, "object_kind": "BENCH", "tier": pin["tier"], "member_id": pin["member_id"],
        "relation": {"direction": "ROUTE_TO_UNION",
                     "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
                     "information_relation": "NARROWING_NON_REVERSIBLE",
                     "semantic_equivalence_claimed": False, "digest_alias_claimed": False},
        "route_registration_digest": route_digest, "union_claim_digest": pin["union_claim_digest"],
        "acceptance_mechanism": {"kind": "REGISTERED", "identifier": ACCEPTANCE_MECHANISM_ID},
        "installed_sources": installed_source_bindings(),
        "excluded_disjoint_members": [EXCLUDED_DISJOINT_MEMBER],
        "host_selections": {"package_digest": None, "installed_mechanism_digest": None,
                            "authority_digest": None, "cli_module_origins": None},
        "dependency_binding_status": "UNKNOWN", "current_evidence_status": "UNKNOWN",
        "evidence_credit": "NONE", "authority_credit": "NONE", "package_credit": "NONE",
        "installed_mechanism_credit": "NONE", "test_credit": "NONE",
        "semantic_completeness": "UNKNOWN", "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    return {"remaining_before": 93, "selected": 4, "mapped": len(MAPPED_CHECKS),
            "refused_inside_selected_cluster": 0, "excluded_disjoint_members": [EXCLUDED_DISJOINT_MEMBER],
            "remaining_after": 89, "semantic_completeness": "UNKNOWN", "release_admissible": False}

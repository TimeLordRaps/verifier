"""Fixed one-way projections for three reviewed TOKEN registrations."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import current_object_routes, token_checks


SCHEMA_VERSION = "verifier-current-token-checks-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = "3f8b72dab3d6d6b379db5b2362bc3413f840bf35095d9816bf45bae52a7a5bdb"
NATIVE_SOURCE_PATH = "src/verifier/domains/contracts/token_checks.py"
NATIVE_SOURCE_SHA256 = "bc3b900da75a2ead7bce66f04287bc9c240138195a04b8c3fd67417fdd1efd77"
ROUTE_SOURCE_PATH = "src/verifier/domains/contracts/current_object_routes.py"
ROUTE_SOURCE_SHA256 = "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
REJECTED_ROUTE_SELECTOR_SHA256 = "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
ACCEPTANCE_MECHANISM_ID = "verifier.domains.contracts.token_checks.recheck_token_checks_certificate"
UNION_SOURCE = {
    "uri": "producer-source://src/verifier/standard/CURRENT_TOKEN_CHECKS.md",
    "sha256": "sha256:0ed6583a2f8f3174d9576d47141036f7963ce7d71b0b391da6ae94b619f2f398",
}
SOURCE_MAP_DIGEST = "sha256:7bc722d0daf5802665e54c3947f167abd7d7f736c6b2a68e80671e6ad6cfb64f"
PRODUCER_SOURCE_COORDINATE_DIGEST = "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462"
CANDIDATE_INPUT_DIGEST = "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc"

_ACCEPTED = {
    "tenure": (
        "TOKEN-2.1", 2, "finite_retained_token_tenure",
        ("legacy TOKEN-1.4", "legacy TOKEN-2.1..3", "legacy TOKEN-2.11", "legacy TOKEN-4.2"),
        "route-instance:2186a82a792962e2735b7c162e331a766b4dc2706d9ab52f3a9b4ed3d044c275",
        "union-candidate:80a248de1eea0437950bb6514f2bc10dbc18b4cc5a1edc686ff44e70a59e89ae",
        "sha256:9caa49c2b4e1929c1cb8e8b915f48ba3d946c60572e4e7f3c5d3ab7a485ca28c",
        "sha256:4cbdad4ae4115fe5350a4fba8e70759c2184452b64a3f6cfa26dc7cb2b24dec8", 13, 1,
    ),
    "windows": (
        "TOKEN-3.1", 3, "finite_retained_token_windows",
        ("legacy TOKEN-1.10", "legacy TOKEN-3.8"),
        "route-instance:e64715b82fdaf85e13eb82da2ff30890bc9512267b0d5341fb16d5cc90d505e0",
        "union-candidate:07104107f5ae6c2685503d9b54273d95208872d466723931b1955d71d5141f15",
        "sha256:00588019fe514ecfd02ef2e67c54072cdff1321efcc3f5cb7e8ba4de620cdb24",
        "sha256:a936e39e2402bc593dbe5e7ba97d5283ba9d27a97b9495516e79adfe5e500e97", 13, 2,
    ),
    "delegation": (
        "TOKEN-4.1", 4, "finite_retained_token_delegation",
        ("legacy TOKEN-2.4", "legacy TOKEN-3.4..5", "legacy TOKEN-3.10", "legacy TOKEN-4.3..4"),
        "route-instance:eadfd3e26dae80a821fba8297098a453613ea43ac604b92eb68a9e502d0e5279",
        "union-candidate:fa8b60ea8f701923f0c890cfa23b56351de6247050c7decd4202bc8859d1c3be",
        "sha256:82d1b4f7d6cabe512b8349a8c1a31b3be2ca969407f767c8eff208fc7947ee4f",
        "sha256:a593ce3f9335d861dcf85417d9c23d1dc3f29c47ad2756ed576a9d7ee4e0456f", 13, 3,
    ),
}
MAPPED_CHECKS = tuple(_ACCEPTED)
EXCLUDED_DISJOINT_MEMBERS = ("TOKEN-1.1", "TOKEN-5.1")


class TokenChecksProjectionRefusal(ValueError):
    """The input is outside the exact three-row reviewed mapping."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_source_bindings() -> dict[str, dict[str, str]]:
    sources = {
        "token_checks": (Path(token_checks.__file__).resolve(), NATIVE_SOURCE_PATH, NATIVE_SOURCE_SHA256),
        "route_catalog": (Path(current_object_routes.__file__).resolve(), ROUTE_SOURCE_PATH,
                          ROUTE_SOURCE_SHA256),
    }
    result = {}
    for name, (path, logical, expected) in sources.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise TokenChecksProjectionRefusal(name + " source differs from reviewed bytes")
        result[name] = {"path": logical, "sha256": actual}
    return result


def accepted_projection(check: str) -> dict[str, Any]:
    if type(check) is not str or check not in _ACCEPTED:
        raise TokenChecksProjectionRefusal("check is outside the fixed reviewed TOKEN set")
    member, tier, scope, source_rows, route_id, union_id, route_digest, claim_digest, ci, ri = _ACCEPTED[check]
    return {
        "check": check, "object_kind": "TOKEN", "tier": tier, "member_id": member,
        "scope": scope, "source_rows": list(source_rows), "route_instance_id": route_id,
        "union_ref_id": union_id, "route_registration_digest": route_digest,
        "union_claim_digest": claim_digest, "source": dict(UNION_SOURCE),
        "source_map_digest": SOURCE_MAP_DIGEST,
        "producer_source_coordinate_digest": PRODUCER_SOURCE_COORDINATE_DIGEST,
        "candidate_input_digest": CANDIDATE_INPUT_DIGEST,
        "contribution_index": ci, "row_index": ri,
    }


def project_registration(check: str, native_registration: Mapping[str, Any],
                         union_candidate: Mapping[str, Any], *,
                         direction: str = "ROUTE_TO_UNION") -> dict[str, Any]:
    pin = accepted_projection(check)
    if direction != "ROUTE_TO_UNION":
        raise TokenChecksProjectionRefusal("only ROUTE_TO_UNION narrowing is admitted")
    expected = token_checks.registration(check)
    if dict(native_registration) != expected:
        raise TokenChecksProjectionRefusal("native registration differs from reviewed registration")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise TokenChecksProjectionRefusal("native registration digest differs")
    required = {key: pin[key] for key in (
        "check", "object_kind", "tier", "member_id", "scope", "source_rows", "route_instance_id",
        "union_ref_id", "source", "source_map_digest", "producer_source_coordinate_digest",
        "candidate_input_digest", "contribution_index", "row_index",
    )}
    required["claim_sha256"] = pin["union_claim_digest"]
    for field, value in required.items():
        if union_candidate.get(field) != value:
            raise TokenChecksProjectionRefusal("union candidate has substituted " + field)
    text = union_candidate.get("claim_text")
    if type(text) is not str or text != expected["proposition"] or _text_digest(text) != pin["union_claim_digest"]:
        raise TokenChecksProjectionRefusal("union claim does not preserve exact proposition text")
    return {
        "schema_version": SCHEMA_VERSION, "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "check": check, "object_kind": "TOKEN", "tier": pin["tier"], "member_id": pin["member_id"],
        "relation": {"direction": "ROUTE_TO_UNION",
                     "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
                     "information_relation": "NARROWING_NON_REVERSIBLE",
                     "semantic_equivalence_claimed": False, "digest_alias_claimed": False},
        "route_registration_digest": route_digest, "union_claim_digest": pin["union_claim_digest"],
        "acceptance_mechanism": {"kind": "REGISTERED", "identifier": ACCEPTANCE_MECHANISM_ID},
        "installed_sources": installed_source_bindings(),
        "excluded_disjoint_members": list(EXCLUDED_DISJOINT_MEMBERS),
        "host_selections": {"package_digest": None, "installed_mechanism_digest": None,
                            "authority_digest": None, "cli_module_origins": None},
        "dependency_binding_status": "UNKNOWN", "current_evidence_status": "UNKNOWN",
        "evidence_credit": "NONE", "authority_credit": "NONE", "package_credit": "NONE",
        "installed_mechanism_credit": "NONE", "test_credit": "NONE",
        "semantic_completeness": "UNKNOWN", "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    return {"remaining_before": 89, "selected": 3, "mapped": len(MAPPED_CHECKS),
            "refused_inside_selected_cluster": 0,
            "excluded_disjoint_members": list(EXCLUDED_DISJOINT_MEMBERS),
            "remaining_after": 86, "semantic_completeness": "UNKNOWN", "release_admissible": False}

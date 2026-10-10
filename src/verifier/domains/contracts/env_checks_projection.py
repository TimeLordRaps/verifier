"""Fixed one-way projections for four reviewed ENV registrations."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import current_object_routes, env_checks


SCHEMA_VERSION = "verifier-current-env-checks-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = "3f8b72dab3d6d6b379db5b2362bc3413f840bf35095d9816bf45bae52a7a5bdb"
NATIVE_SOURCE_PATH = "src/verifier/domains/contracts/env_checks.py"
NATIVE_SOURCE_SHA256 = "3f653ffcf352eeb22a803a416369243e0e14ad271d97679c9613fc57fe74b79b"
ROUTE_SOURCE_PATH = "src/verifier/domains/contracts/current_object_routes.py"
ROUTE_SOURCE_SHA256 = "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
REJECTED_ROUTE_SELECTOR_SHA256 = "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
ACCEPTANCE_MECHANISM_ID = "verifier.domains.contracts.env_checks.recheck_env_checks_certificate"
UNION_SOURCE = {
    "uri": "producer-source://src/verifier/standard/CURRENT_ENV_CHECKS.md",
    "sha256": "sha256:92e7819b2d4b8157c41662f240397703d11b09d2958a3fe813a3531d8dfeff03",
}
SOURCE_MAP_DIGEST = "sha256:ffdaa0a809714d8ecc8cf7e7bdd9b2d842bc8406ff91abc264ec81f039baf708"
PRODUCER_SOURCE_COORDINATE_DIGEST = "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462"
CANDIDATE_INPUT_DIGEST = "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc"

_ACCEPTED = {
    "closure": (
        "ENV-1.2", 1, "finite_retained_env_closure",
        "route-instance:2c7e24fa2444023f7e3c0fc33acb9d15b49f55bcb58a7598e68c05b9291c1958",
        "union-candidate:f0fdafb01e71edbd4ddb146b654e386462d7d3001978bb06d074c6f33bcc6fa2",
        "sha256:dcbfb38534445dc7837b71e797b17f2cf86847cabc500fd0753b8d625e56d88e",
        "sha256:f34e8910e094df83972aaf2d6f454132f418a8870abc2e25d527e2f3c46b117a", 9, 1,
    ),
    "configuration": (
        "ENV-1.5", 1, "finite_retained_env_configuration",
        "route-instance:666b50f5439e0d53c3f2df0a78cb8d77d6923ae5908c0dc7a8535ce055bbe440",
        "union-candidate:1511cefcb70df0a161a153e76821def85974822b94c0147147a2a0c1934346f0",
        "sha256:82924da3a4df9cfcf166c390bf93cdc5f0824c477f0a235478409934c4ea09c2",
        "sha256:b592f3d4585276800c1ef13cafdc376fc949e553df2fc4a4214fc855bd42a7e3", 9, 4,
    ),
    "reproduction": (
        "ENV-2.3", 2, "finite_retained_env_reproduction",
        "route-instance:30aed4e19bd9fc92f7a523f5a5a4deca3522fda1be7f3330d6661d5fdaf49483",
        "union-candidate:b945f8c9e7bb017ec421d1e45740019c12b595b1bbf7e25f3e315ccc6b735d09",
        "sha256:1dde94563a02fd6bf666d9e9bacb95e19b885128170aca745c0af27792dc36ac",
        "sha256:075d80282404c095c7a69728ad39004c04ed9d79e8ac3e352bcafd61a1b987a5", 9, 5,
    ),
    "resources": (
        "ENV-3.3", 3, "finite_retained_env_resources",
        "route-instance:b4a723c7408f1503479b4f3eac564fea46f3ab09ff6951b468776d636da51bc8",
        "union-candidate:ca5d1df1e017a54794a38761c82f926f11daac567a417a591a1860ecbba45d6b",
        "sha256:7ded57b746e170caa340b812a014d1311b9bfbb72cdeca5939b37569e6147605",
        "sha256:983637e678a1e20d8dec203bb505f0fe8ca5515140c1cc9b626257b411c1bdcc", 9, 6,
    ),
}
MAPPED_CHECKS = tuple(_ACCEPTED)


class EnvChecksProjectionRefusal(ValueError):
    """The input is outside the exact four-row reviewed mapping."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_source_bindings() -> dict[str, dict[str, str]]:
    sources = {
        "env_checks": (Path(env_checks.__file__).resolve(), NATIVE_SOURCE_PATH, NATIVE_SOURCE_SHA256),
        "route_catalog": (Path(current_object_routes.__file__).resolve(), ROUTE_SOURCE_PATH,
                          ROUTE_SOURCE_SHA256),
    }
    result = {}
    for name, (path, logical, expected) in sources.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise EnvChecksProjectionRefusal(name + " source differs from reviewed bytes")
        result[name] = {"path": logical, "sha256": actual}
    return result


def accepted_projection(check: str) -> dict[str, Any]:
    if type(check) is not str or check not in _ACCEPTED:
        raise EnvChecksProjectionRefusal("check is outside the fixed reviewed ENV set")
    member, tier, scope, route_id, union_id, route_digest, claim_digest, ci, ri = _ACCEPTED[check]
    return {
        "check": check, "object_kind": "ENV", "tier": tier, "member_id": member,
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
        raise EnvChecksProjectionRefusal("only ROUTE_TO_UNION narrowing is admitted")
    expected = env_checks.registration(check)
    if dict(native_registration) != expected:
        raise EnvChecksProjectionRefusal("native registration differs from reviewed registration")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise EnvChecksProjectionRefusal("native registration digest differs")
    required = {key: pin[key] for key in (
        "check", "object_kind", "tier", "member_id", "scope", "route_instance_id",
        "union_ref_id", "source", "source_map_digest", "producer_source_coordinate_digest",
        "candidate_input_digest", "contribution_index", "row_index",
    )}
    required["claim_sha256"] = pin["union_claim_digest"]
    for field, value in required.items():
        if union_candidate.get(field) != value:
            raise EnvChecksProjectionRefusal("union candidate has substituted " + field)
    text = union_candidate.get("claim_text")
    if type(text) is not str or text != expected["proposition"] or _text_digest(text) != pin["union_claim_digest"]:
        raise EnvChecksProjectionRefusal("union claim does not preserve exact proposition text")
    return {
        "schema_version": SCHEMA_VERSION, "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "check": check, "object_kind": "ENV", "tier": pin["tier"], "member_id": pin["member_id"],
        "relation": {"direction": "ROUTE_TO_UNION",
                     "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
                     "information_relation": "NARROWING_NON_REVERSIBLE",
                     "semantic_equivalence_claimed": False, "digest_alias_claimed": False},
        "route_registration_digest": route_digest, "union_claim_digest": pin["union_claim_digest"],
        "acceptance_mechanism": {"kind": "REGISTERED", "identifier": ACCEPTANCE_MECHANISM_ID},
        "installed_sources": installed_source_bindings(),
        "host_selections": {"package_digest": None, "installed_mechanism_digest": None,
                            "authority_digest": None, "cli_module_origins": None},
        "dependency_binding_status": "UNKNOWN", "current_evidence_status": "UNKNOWN",
        "evidence_credit": "NONE", "authority_credit": "NONE", "package_credit": "NONE",
        "installed_mechanism_credit": "NONE", "test_credit": "NONE",
        "semantic_completeness": "UNKNOWN", "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    return {"remaining_before": 97, "selected": 4, "mapped": len(MAPPED_CHECKS),
            "refused_inside_selected_cluster": 0, "remaining_after": 93,
            "semantic_completeness": "UNKNOWN", "release_admissible": False}

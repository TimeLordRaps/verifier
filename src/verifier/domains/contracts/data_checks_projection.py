"""Bounded one-way reconciliation of five native DATA check registrations.

The fixed table narrows an exact structured registration to its proposition
text. It grants no reverse equivalence, digest alias, evidence, authority,
package, installed-mechanism, profile, completeness, or release credit.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import current_object_routes, data_checks


SCHEMA_VERSION = "verifier-current-data-checks-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = (
    "b0ca52730786625846bbb2d3dada2295dfb96d641341d77ec8accbdc45c1558b"
)
DATA_CHECKS_SOURCE_PATH = "src/verifier/domains/contracts/data_checks.py"
DATA_CHECKS_SOURCE_SHA256 = (
    "0e799306164671ced01e7a81007d712d52e8ecde8f1ecf024fb4181d58023e3e"
)
ROUTE_CATALOG_SOURCE_PATH = "src/verifier/domains/contracts/current_object_routes.py"
ROUTE_CATALOG_SOURCE_SHA256 = (
    "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
)
REJECTED_ROUTE_CATALOG_SELECTOR_SHA256 = (
    "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
)
ACCEPTANCE_MECHANISM_ID = (
    "verifier.domains.contracts.data_checks.recheck_data_checks_certificate"
)
UNION_SOURCE = {
    "uri": "producer-source://src/verifier/standard/CURRENT_DATA_CHECKS.md",
    "sha256": "sha256:8fd77330056227e969aae1277714cde55aa8a9dfaa498d76bc2a909654e9816f",
}
PRODUCER_SOURCE_COORDINATE_DIGEST = (
    "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1"
)
CANDIDATE_INPUT_DIGEST = (
    "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1"
)

# Values are member, tier, scope, route instance, union reference, full
# registration digest, claim-text digest, contribution index, and row index.
# This exact table is not a rule for admitting another check.
_ACCEPTED: dict[str, tuple[str, int, str, str, str, str, str, int, int]] = {
    "inventory": (
        "DATA-1.2", 1, "finite_retained_data_inventory",
        "route-instance:5d5001a5ccedd42ccaef3d163ef5a6c122d8289002de9a3a8bdf1473ff722b9d",
        "union-candidate:6c4b31ff110ee9056fbf42bc4159f7b8fd8fcca9a2f687764c68e14cf47713bf",
        "sha256:76bb8b7603a04c834abfde9d5d638779f2ec64013bbca94eacbc5a805e64b932",
        "sha256:f87263a6fe304d0a08da53cada4b098b85d7671130fec3d161d0ba5ce6b809de", 21, 1,
    ),
    "schema": (
        "DATA-1.4", 1, "finite_retained_data_schema",
        "route-instance:558cdfd435dae3b8b89ea0e42b8f180391a3cf158fccb702ec805bd5973f2c1b",
        "union-candidate:0d5af68cd22ef41b4fc6244b6c2960dd22e4195aa54fef32902deaa04b59048b",
        "sha256:0b7407049f7b80e18c165124635e2d98a22f4b4919d82ad57025b8b434babde8",
        "sha256:5460017dfea8c974c06dddae9486344d8301ad73ec29b3fddb861c8bfefe12fa", 21, 2,
    ),
    "lineage": (
        "DATA-2.1", 2, "finite_retained_data_lineage",
        "route-instance:b506304900a33f9c485af4eaf4678d4a4797bdb239febda58cbc6fc4630a1145",
        "union-candidate:ea1c34b21f014f018971fc29e5a99b1aae46da0b51c7f9cda8fcd7b4b9ba299b",
        "sha256:2960bdfe7004920c153ea2013594dc0c310be9ec25754be6e8bc3c713129de9a",
        "sha256:e7b49703292f7880707a14826c147f8a6a11a4790968247ca84fc43b8ca12c30", 21, 3,
    ),
    "splits": (
        "DATA-4.1", 4, "finite_retained_data_splits",
        "route-instance:00a684bca5bc61f65256b357f398c6b96b8bdc6060ec3cd35ed46359eda5c688",
        "union-candidate:f9655a643acdea9defa308ffac2c7af302edc3961a5abc5b6cb50bb91eadd639",
        "sha256:55bc6462c16097fa9c4afb8cadbef24eb143c81bdcbf8b79611c8d5de2071528",
        "sha256:eb4f5751a444ffb8f70d5a5fa872e579d0374ae33358100b9884a859eecc9fe0", 21, 5,
    ),
    "overlap": (
        "DATA-4.4", 4, "finite_retained_data_overlap",
        "route-instance:e18204ba60af283015a1ab3474975358f7f6775717694aa37281900c3da2af8b",
        "union-candidate:b5521eccc968c9ba706e1587b51b84510aa7843ab0a69d5816ba64edd4a70bf5",
        "sha256:7447f7be5e05f0e810588f4d191f927e1ea9772c3b83e7e6a4bebed47093cb1e",
        "sha256:b5e96362e6327f8f616d94a894a9d16577c05d08a84089b15192b8f920dcfe9f", 21, 6,
    ),
}

MAPPED_CHECKS = tuple(_ACCEPTED)


class DataChecksProjectionRefusal(ValueError):
    """The supplied data is not one of the exact reviewed projections."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_source_bindings() -> dict[str, dict[str, str]]:
    """Verify and return the installed DATA and route-catalog bindings."""
    paths = {
        "data_checks": (Path(data_checks.__file__).resolve(), DATA_CHECKS_SOURCE_PATH,
                        DATA_CHECKS_SOURCE_SHA256),
        "route_catalog": (Path(current_object_routes.__file__).resolve(), ROUTE_CATALOG_SOURCE_PATH,
                          ROUTE_CATALOG_SOURCE_SHA256),
    }
    result = {}
    for name, (path, logical_path, expected) in paths.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise DataChecksProjectionRefusal(name + " source differs from reviewed bytes")
        result[name] = {"path": logical_path, "sha256": actual}
    return result


def accepted_projection(check: str) -> dict[str, Any]:
    """Return the exact reviewed pins for one admitted DATA check."""
    if type(check) is not str or check not in _ACCEPTED:
        raise DataChecksProjectionRefusal("check is outside the fixed reviewed five-row set")
    (member_id, tier, scope, route_instance_id, union_ref_id, route_digest,
     claim_digest, contribution_index, row_index) = _ACCEPTED[check]
    return {
        "check": check,
        "object_kind": "DATA",
        "tier": tier,
        "member_id": member_id,
        "scope": scope,
        "route_instance_id": route_instance_id,
        "union_ref_id": union_ref_id,
        "route_registration_digest": route_digest,
        "union_claim_digest": claim_digest,
        "source": dict(UNION_SOURCE),
        "producer_source_coordinate_digest": PRODUCER_SOURCE_COORDINATE_DIGEST,
        "candidate_input_digest": CANDIDATE_INPUT_DIGEST,
        "contribution_index": contribution_index,
        "row_index": row_index,
    }


def project_registration(
    check: str,
    native_registration: Mapping[str, Any],
    union_candidate: Mapping[str, Any],
    *,
    direction: str = "ROUTE_TO_UNION",
) -> dict[str, Any]:
    """Verify one fixed non-reversible DATA proposition-text projection."""
    pin = accepted_projection(check)
    if direction != "ROUTE_TO_UNION":
        raise DataChecksProjectionRefusal("only ROUTE_TO_UNION narrowing is admitted")
    expected_registration = data_checks.registration(check)
    if dict(native_registration) != expected_registration:
        raise DataChecksProjectionRefusal("native registration differs from reviewed registration")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise DataChecksProjectionRefusal("native registration digest differs from reviewed route digest")
    required = {
        "check": check,
        "object_kind": "DATA",
        "tier": pin["tier"],
        "member_id": pin["member_id"],
        "scope": pin["scope"],
        "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"],
        "claim_sha256": pin["union_claim_digest"],
        "source": pin["source"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
    }
    for field, value in required.items():
        if union_candidate.get(field) != value:
            raise DataChecksProjectionRefusal("union candidate has a substituted " + field)
    claim_text = union_candidate.get("claim_text")
    if type(claim_text) is not str or claim_text != expected_registration["proposition"]:
        raise DataChecksProjectionRefusal("projection does not preserve exact proposition text")
    if _text_digest(claim_text) != pin["union_claim_digest"]:
        raise DataChecksProjectionRefusal("union digest does not bind exact proposition text")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "check": check,
        "object_kind": "DATA",
        "tier": pin["tier"],
        "member_id": pin["member_id"],
        "relation": {
            "direction": "ROUTE_TO_UNION",
            "operation": "EXTRACT_EXACT_REGISTRATION_PROPOSITION_FIELD_AS_UTF8",
            "information_relation": "NARROWING_NON_REVERSIBLE",
            "semantic_equivalence_claimed": False,
            "digest_alias_claimed": False,
        },
        "route_registration_digest": route_digest,
        "union_claim_digest": pin["union_claim_digest"],
        "acceptance_mechanism": {"kind": "REGISTERED", "identifier": ACCEPTANCE_MECHANISM_ID},
        "installed_sources": installed_source_bindings(),
        "union_source": pin["source"],
        "host_selections": {"package_digest": None, "installed_mechanism_digest": None,
                            "authority_digest": None, "cli_module_origins": None},
        "dependency_binding_status": "UNKNOWN",
        "current_evidence_status": "UNKNOWN",
        "evidence_credit": "NONE",
        "authority_credit": "NONE",
        "package_credit": "NONE",
        "installed_mechanism_credit": "NONE",
        "test_credit": "NONE",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    """Return the immutable reviewed denominator accounting."""
    return {
        "remaining_before": 102,
        "selected": 5,
        "mapped": len(MAPPED_CHECKS),
        "refused_inside_selected_cluster": 0,
        "remaining_after": 97,
        "remaining_breakdown": {"env_checks": 4, "bench_checks": 4,
                                "token_checks": 3, "other_single_row_mechanisms": 86},
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }

"""Bounded one-way reconciliation of sixteen native typed-facet registrations.

The fixed table narrows an exact structured registration to its proposition
text. It grants no reverse equivalence, digest alias, evidence, authority,
package, installed-mechanism, profile, completeness, or release credit.

Terminology: uniform resource identifier (URI).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.core.certificate import canonical_digest
from verifier.domains.contracts import current_object_routes, typed_facets


SCHEMA_VERSION = "verifier-current-typed-facets-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = (
    "dd25d91d91dea3f982ec08737be7fcf239aa6dcfe26d31aaae5b15159858ef12"
)
TYPED_FACETS_SOURCE_PATH = "src/verifier/domains/contracts/typed_facets.py"
TYPED_FACETS_SOURCE_SHA256 = (
    "ccf9ed4d4dfa25975cd3eb4694eb8b23dd7906c1fa65adb2645e45220a0267df"
)
ROUTE_CATALOG_SOURCE_PATH = "src/verifier/domains/contracts/current_object_routes.py"
ROUTE_CATALOG_SOURCE_SHA256 = (
    "1daa659a53bbd22fddb441056363834b40e346607b3143c005fe5214001d4477"
)
REJECTED_ROUTE_CATALOG_SELECTOR_SHA256 = (
    "1daa659a375fb21de867f1e8b7930d3fbba37dceac93821255358b1fc079ca53"
)
ACCEPTANCE_MECHANISM_ID = (
    "verifier.domains.contracts.typed_facets.recheck_typed_facets_certificate"
)

# Values are member, route instance, union reference, route registration
# digest, claim-text digest, union source URI/digest, producer coordinate,
# candidate input, contribution index, and row index. This is the complete
# reviewed 16-row set, not a rule for admitting another kind.
_ACCEPTED: dict[str, tuple[str, str, str, str, str, str, str, str, str, int, int]] = {
    "ACTOR": (
        "ACTOR-1.1", "route-instance:bdc3353108756be492bd6e2f9940d1bef0d0b39921e239ce52b18e3e090050b2",
        "union-candidate:334b8f77ae04b861d4030417db1017b179437609bbfd8ad0e690de2eb226eaad",
        "sha256:7f1b502efea3c89a53095567a770333a22e5e7dd0c893ede78dbd57ac2e2b059",
        "sha256:f9e2652865a38212756974bb93d234cb49a4c1eefa059cc7df6b8e7437d39227",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 7, 0,
    ),
    "ARCH": (
        "ARCH-1.1", "route-instance:4b50a3d500e788cde99f745de78440801fb64762c62d05407f42b6881f68c7e7",
        "union-candidate:989ad74fab5aeee98510d040dd7c1e4448b11c80a1798c62ab65a038743ec740",
        "sha256:e924078c1e304d8dc34630856dbfd80d4db8e344ee9fea0f35e2a71b391c4e4b",
        "sha256:01fb772ad1ec4e480ffc72ec8d914a3b5cdf9d82c614b12bb2ac4ef1d69597e7",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 1, 0,
    ),
    "BENCH": (
        "BENCH-1.1", "route-instance:a7545089c62cb0ed00b64be5285e50531e4c0855aedfc41c86f7cecd5418a85c",
        "union-candidate:9813d8a0e51238c3485c537d3953f1f206828dd8e20259ea9f3611d3e5a0722b",
        "sha256:a4994f78755c279a87e9f0427aad6a10a89b3941da00aee88a3c3cf305ffa281",
        "sha256:ba5928a86ea7a05f5756a48a340b080b0d52c8d571fdce2f0dcdcb3d5e1561da",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 8, 0,
    ),
    "COLLECTIVE": (
        "COLLECTIVE-1.1", "route-instance:23d73b27ba1baf4ab9efaa64c11d202c80c8f39e577c7e8bef6282183fcbf695",
        "union-candidate:430bfe40b3bbbed74f925baf9702587b5e6612601d2e1879f084e73378c7bc15",
        "sha256:51150142a986f42596f22863916f0d333400098578c4d87910749ead6d4414e3",
        "sha256:bdde6231380f5323f870c8e699a3730c4af47fddf33a42cb868f6950b885cf0d",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 2, 0,
    ),
    "DATA": (
        "DATA-1.1", "route-instance:3c7f58d14d3eaffc479d4ca5618695384fb4dcf21f7f5476c126e7bdd6aff29d",
        "union-candidate:b8d55a56acdea7935b1edc94863de36e506d595134962213f38d9fbc97d987c6",
        "sha256:8badfedada638907c37c4497ad0a354d9722dcb67c019679a7274c739c87c3f6",
        "sha256:2bd8a3df467b596ffbeda2adbbaf28089a0b0493d02b4ab1cd7919f95036cde2",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1",
        "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", 21, 0,
    ),
    "ENV": (
        "ENV-1.1", "route-instance:e017f8a06e0d1f68755518cd4de61162b08283a66c72c22cd59152ae3672358a",
        "union-candidate:8ee9aa3328ba19da343df2e407df61a1c0b91ebb9eaf3894d675a2dcc93bfba8",
        "sha256:815d50ab2cd1d1bb624ae0002a816804f2bff008b77f00a49859f5105c1db45f",
        "sha256:ee281d7f498d08ffe31e7c7d4f10f0a86008cbcbffc384e1555954e1ee8ce062",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 9, 0,
    ),
    "GRAPH": (
        "GRAPH-1.1", "route-instance:345cb28df9db66b5f55bcbb19c38f766a7a8b8b437c53660f75992e0a521522e",
        "union-candidate:246f96a01041670c8804c54073f908ff3f29013abb33113431155910a8bade40",
        "sha256:1cfbbb215e6b1a5c7e0db98dc0b96f06b9fb817e198c412dcf248c6410bbfdab",
        "sha256:4f386842b0c25cf480a6c7482b9acf1ea6494209c68835f21a63f1148ddc4d48",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1",
        "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", 23, 0,
    ),
    "HARDWARE": (
        "HARDWARE-1.1", "route-instance:bd0311b6e82217fe3713fc2eed612d40cb13f1ed0f28e9a6b51582696df8ceb1",
        "union-candidate:6ac00d495276558f0e9fc82ab47d2c626c9e0c757e2474d33700a1a72a32ba3d",
        "sha256:d6f6cda0bc2cd01da876e8a53ef1dcd5333c5ed610f9b25521b14f43e3056ff2",
        "sha256:bab66ebfdd4c1d3f5ce549a94e72eec1dc44f4dd4739d770538ac71294ec10a1",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 3, 0,
    ),
    "HUMAN": (
        "HUMAN-1.1", "route-instance:f51bd825a612bd17b17471eb7bfc74a3f7cd6de922cfe27ad309112a3859d367",
        "union-candidate:126cc08e949bc776fb4ce8211b89327598aad3eb676a789c0f0d9a72cd4b4d68",
        "sha256:2558c77ba0ee5b40c488520a35ce3181a65ead0c5d94b671b4513bd6ce6d2ea9",
        "sha256:a2b6eace8af38dd84fa6597bc379302ce9062da1018cc6aa3313d4dd69836e43",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 10, 0,
    ),
    "IDENTITY": (
        "IDENTITY-1.1", "route-instance:b69a59c97e4b0318b9ccf541e78ae1c160826bd6cb1df784a6184cb17a7c8b51",
        "union-candidate:32145327c38b495817eb76a3c8fdb77807c6e32880ea6475f55dd845cda4e938",
        "sha256:8da7e982e371253de039af7d9abaf678005030c1a03d324a54261a50203c25c9",
        "sha256:2bb80451b715830875594c1433df2408a8cc9a4f3d46f9f8f98cde43ffbf1467",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 4, 0,
    ),
    "OBJECT": (
        "OBJECT-1.2", "route-instance:9ab7a79644958aeb5540cc007af4089e5c5987f40fe99a7406220bf7f7eb06f5",
        "union-candidate:272dd30cd98d65c8dd28580650e71a9ef868ef6f0f1577ac2a57ae142833236b",
        "sha256:b3afd51f8dea343be68cd63a207df8cd720a3f020f9fdc2c3a2111bd482d8cce",
        "sha256:b052a2aa240c24279b15c0cde435f1fc577581a93406e7415015771c7d885830",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 11, 1,
    ),
    "RECEIPT": (
        "RECEIPT-1.1", "route-instance:7452c777bd777c0e2ad7bbb970532337e36162819b8683562eee0242dab1af0d",
        "union-candidate:7a69be2c83f23f798f78d965e78f334238eee7a1be70646b17aff2b9209977d9",
        "sha256:0b3c8c42da0f3a8b4731dadd575e804347f9906e46d0f4e18beb4252738663f8",
        "sha256:a033c5448edb179585a9f20f1eed9fb680f9e0fece7888458b548a7dc7c1c949",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:0fde25d7391f67887f570da73d6b96084eb49daa183650cba90202e223b58dc1",
        "sha256:672b4e8aaace91a49c291a3a96e9ea746016a094eccddd34d0387560e35cd1e1", 22, 0,
    ),
    "ROLE": (
        "ROLE-1.1", "route-instance:f3687b2827a64b5385f8f045ba8fa7ac07a89c4702c5a4e0cf3d962f3eb06241",
        "union-candidate:20556b13ffd0f41589ec4ada4bc6bcf8d858435334a7da78b2b460779e80b024",
        "sha256:e88e6b186c49138bac1ae296642fce6b30703a1381285212b3cd90a0d5865674",
        "sha256:4b778ddcdeaac67248b059e7aa7c736d9814ca61e2aac34c5a2bfdfe945facbe",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 5, 0,
    ),
    "SIM": (
        "SIM-1.1", "route-instance:192d6cc13086354cca52f95d96d03729d734cc9b15914bed3121b22178802c80",
        "union-candidate:a57ac39a4809fa67aae0cd779b60d640f3bcae45b0c43ec06ffd28dc9fce5fdd",
        "sha256:c5b51c5d74d161366cfc43e3ab6a77e1029334ead745c1d187cdef8074e7f4e0",
        "sha256:5be99715cd08c55d2dbb21ac2d1686f73328642eae23e25e56fe44d2f1c5e2a1",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 12, 0,
    ),
    "TIME": (
        "TIME-1.1", "route-instance:988fedf1c31a21b29ae88eb2b1bc437b430b89b5cd0d2587ecb67d7011840c16",
        "union-candidate:662efe7d1fa0a8a0f8fe382e29c8bb6a82f571818578202ee9800ed656e3e24e",
        "sha256:1d871e52d584ded4019786415b3e6e7a09dab98f564d5a4c5b9fb9824231af6f",
        "sha256:566ce1ab5bc48b46a88fe694cc01c91ea804e607a09ad34c684e69e5de161277",
        "producer-source://src/verifier/standard/META_TIERS.md",
        "sha256:f6d338f3ee17b3358a1f4b76b4e0caa7a1b59e63d44f3b8997872a5baf9d529c",
        "sha256:a89e977fd629f39dc989eed26cd79dcbf716ff44c26674b01d3da5f5520c4fa1",
        "sha256:2b3dbbcc8f58bcfff00f69f411addb2603c10543295360f331cd50b8830a206b", 6, 0,
    ),
    "TOKEN": (
        "TOKEN-1.1", "route-instance:5469cf8eae42572bbdb7d3ab7c24c5514cc320196bde18402f033a0cb8c0bf57",
        "union-candidate:69347b8216b5e0d3f207406e655c7698aae28a820e6ed2a24fc1c1d6814080d5",
        "sha256:df8251b6111902f0ccb7ec3e0beebd75079ee7881c2781ccf5be9e96a1349bef",
        "sha256:87aed21e0821f93222e7357e8af0accee926ede7f266054e446b070616483c4a",
        "producer-source://src/verifier/standard/CURRENT_TYPED_FACETS.md",
        "sha256:d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
        "sha256:80dcff0ba1cf2f26c05288b0e42783f40e994b10f495f9100a3c6eb3213fe462",
        "sha256:8a3e4e14f52a737832512b1441e2c9f9d69a9b813d30c7c3cc29c15e63d587cc", 13, 0,
    ),
}

MAPPED_KINDS = tuple(_ACCEPTED)
UNMAPPED_KINDS = (
    "AGENT", "BOT", "EVENT", "HARNESS", "HYPER", "MODEL", "OWNER", "SPACE", "TRAIN", "VERIFIER"
)


class TypedFacetsProjectionRefusal(ValueError):
    """The supplied data is not one of the exact reviewed projections."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_source_bindings() -> dict[str, dict[str, str]]:
    """Verify and return the two installed native source bindings."""
    paths = {
        "typed_facets": (Path(typed_facets.__file__).resolve(), TYPED_FACETS_SOURCE_PATH,
                         TYPED_FACETS_SOURCE_SHA256),
        "route_catalog": (Path(current_object_routes.__file__).resolve(), ROUTE_CATALOG_SOURCE_PATH,
                          ROUTE_CATALOG_SOURCE_SHA256),
    }
    result = {}
    for name, (path, logical_path, expected) in paths.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise TypedFacetsProjectionRefusal(name + " source differs from reviewed bytes")
        result[name] = {"path": logical_path, "sha256": actual}
    return result


def accepted_projection(kind: str) -> dict[str, Any]:
    """Return the exact reviewed pins for one admitted kind."""
    if type(kind) is not str or kind not in _ACCEPTED:
        raise TypedFacetsProjectionRefusal("kind is outside the fixed reviewed 16-row set")
    (member_id, route_instance_id, union_ref_id, route_digest, claim_digest,
     source_uri, source_sha256, producer_coordinate, candidate_input,
     contribution_index, row_index) = _ACCEPTED[kind]
    return {
        "object_kind": kind,
        "member_id": member_id,
        "route_instance_id": route_instance_id,
        "union_ref_id": union_ref_id,
        "route_registration_digest": route_digest,
        "union_claim_digest": claim_digest,
        "source": {"uri": source_uri, "sha256": source_sha256},
        "producer_source_coordinate_digest": producer_coordinate,
        "candidate_input_digest": candidate_input,
        "contribution_index": contribution_index,
        "row_index": row_index,
    }


def project_registration(
    kind: str,
    native_registration: Mapping[str, Any],
    union_candidate: Mapping[str, Any],
    *,
    direction: str = "ROUTE_TO_UNION",
) -> dict[str, Any]:
    """Verify one fixed non-reversible proposition-text projection."""
    pin = accepted_projection(kind)
    if direction != "ROUTE_TO_UNION":
        raise TypedFacetsProjectionRefusal("only ROUTE_TO_UNION narrowing is admitted")
    expected_registration = typed_facets.registration(kind)
    if dict(native_registration) != expected_registration:
        raise TypedFacetsProjectionRefusal("native registration differs from reviewed registration")
    route_digest = "sha256:" + canonical_digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise TypedFacetsProjectionRefusal("native registration digest differs from reviewed route digest")
    required = {
        "object_kind": kind,
        "member_id": pin["member_id"],
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
            raise TypedFacetsProjectionRefusal("union candidate has a substituted " + field)
    claim_text = union_candidate.get("claim_text")
    if type(claim_text) is not str or claim_text != expected_registration["proposition"]:
        raise TypedFacetsProjectionRefusal("projection does not preserve exact proposition text")
    if _text_digest(claim_text) != pin["union_claim_digest"]:
        raise TypedFacetsProjectionRefusal("union digest does not bind exact proposition text")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "object_kind": kind,
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
                            "authority_digest": None},
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
        "remaining_before": 118,
        "selected": 16,
        "mapped": len(MAPPED_KINDS),
        "refused_inside_selected_cluster": 0,
        "remaining_after": 102,
        "remaining_breakdown": {"data_checks": 5, "env_checks": 4,
                                "bench_checks": 4, "token_checks": 3,
                                "other_single_row_mechanisms": 86},
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }

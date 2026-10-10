"""Bounded one-way reconciliation of fifteen tier-5 independence registrations.

This module recognizes only the exact projections admitted by the independently
reviewed R12 adapter packet.  A projection narrows one current structured
registration to its exact proposition text; it is not a semantic equivalence,
an evidence decision, or an authority/completeness/package selection.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from verifier.domains.common import digest
from verifier.domains.contracts import independence_checks


SCHEMA_VERSION = "verifier-current-independence-projection-1"
BASE_SOURCE_COORDINATE_SHA256 = (
    "9e10b026c6eca5d26d4ab517a9c8f1b9245e9812415e9d35be84fc7edc09bd55"
)
ROUTE_SOURCE_PATH = "src/verifier/domains/contracts/independence_checks.py"
ROUTE_SOURCE_SHA256 = (
    "6786272c6d05cfb4e6c974d47a815b0909f96f8073037290ff38992e6fea1edc"
)
UNION_SOURCE_URI = "producer-source://src/verifier/standard/CURRENT_INDEPENDENCE_CHECKS.md"
UNION_SOURCE_SHA256 = (
    "c5f51a17826be5cd0d8a47716d04537605529ff1b7c63242f9025a10390f4abc"
)

# Values are (route registration digest, proposition-text digest, union ref,
# contribution index, row index).  These are the complete accepted R12 set,
# not a template for admitting another kind.
_ACCEPTED: dict[str, tuple[str, str, str, int, int]] = {
    "ACTOR": (
        "sha256:8dd0663239c69ecedad711bd21647eb4ba98b229003c4387997ac5c65d79c7cd",
        "sha256:f402d4a1c02c175dda0a2efb24c14d6629040ca43e583cd743a5f7100d2c533d",
        "union-candidate:b685ddf0f55680964ab7698ce75376d63be5a27d014b0985919ab0aaca253ed0",
        7, 4,
    ),
    "ARCH": (
        "sha256:7fcc33baac55e6827bf45f3941414dbe05cff2c0e6c27e0e6fa3603b61351ab0",
        "sha256:cd27b7f9f8b668d210297e3ec0c831d6a056becde7701e6d2d56fb85109d3d02",
        "union-candidate:9a56eae69a1ca4e6b82ae2dd425cd6a99bee7f09025fbf50481a6d0086ab117e",
        1, 4,
    ),
    "BENCH": (
        "sha256:8e06c7bd2a15fdf649ee85e1cd5cf6e637acafbb03d5cc7c3614f0559bb6a3d0",
        "sha256:1bc0fdd39647cf34198781d57b25f0a1295460cbef5a0352ee4f0d02da145329",
        "union-candidate:e67690b168c102239d8514d5fed5321f3cb745bb94c985ee1be6ec212ecf9aa9",
        8, 6,
    ),
    "COLLECTIVE": (
        "sha256:3a09d1f98c87070fdbf1d10b03b3238f6bb9ac82a70e0f7870263fc42b6dbc79",
        "sha256:7a5bfd305d757f61e808c10a912cf9402b0fbfb75c22c7d5e341d8a330974ba5",
        "union-candidate:183bb1e6aee1151f503d0384aaa6230275e22bddee32c320b52eb81a48fd7344",
        2, 4,
    ),
    "DATA": (
        "sha256:cfcef82d6e5e64b2ec1860c61694fe042ce25494d29da8c516e72dfd6875c48e",
        "sha256:8f99185dd9dc25c1027faa3361f9b5d4035866730b008e173f70b5f098070011",
        "union-candidate:7798421a71c27c94730de76f4978edcced27a6973c8d0fb4b16ce1f1bacecea9",
        21, 7,
    ),
    "ENV": (
        "sha256:44a6aa3347856a4cbc919c2724c6e59671ccadab26fec3bab5be99b89b005404",
        "sha256:3430053ccfb8b8998afacd74ba3254cc4cd2a266b5102ab747122399376e9a87",
        "union-candidate:988f579b7991f007914e8d67f6c48221aa187f4baf05ba700689b650a5d9162a",
        9, 8,
    ),
    "GRAPH": (
        "sha256:5527978693fcd724703d255c608c120a5dd6069cac2e2ba9680b46078e4299ff",
        "sha256:15872a1da1dbc7d9432282dd1f41ec5d9fe4f3e46614a8b8cbe4d6c3bb877ce5",
        "union-candidate:bd8f62c15435543e93568791ffd0132eb30ca11b869fa3d7f4878251d3c85245",
        23, 4,
    ),
    "HARDWARE": (
        "sha256:6e169adb0b14262aa3d717031a328495f1d3f6d373894d26d0a9ea2f7bb54fb4",
        "sha256:231c75a1311e037c3dea28c440b2ccb7187d9b65bf8104df0dcc5f0abfc26764",
        "union-candidate:20b7b6696cdfdeb3530ac8bf25367e06d7106393e2ccfce6d8408e7173b08fe7",
        3, 7,
    ),
    "HUMAN": (
        "sha256:248c6bd4485c9a9c5b89610385a4b78d5e94bb376ed51981716ccdc7ecdee18a",
        "sha256:8d3c9267bb977d05413d0329ddf0ab94468a9bb4abebddd684fe6cc97b3ef478",
        "union-candidate:f91fbf58129808e4cf468b638176edeb097335680bc51e25383d8160535212c6",
        10, 4,
    ),
    "IDENTITY": (
        "sha256:c771d2dde7c33258248d105a8bb7d320e1c3f31ddf12ff615f9b06d7e4984e5b",
        "sha256:d3e6d682e224be59cdb550f130d6c402618a4d8bace4d66da63911b7a3b34569",
        "union-candidate:a682a71e0689ce556108e590450ba318206890ad725a00e0432ac561b013c3c8",
        4, 4,
    ),
    "OBJECT": (
        "sha256:2c3851e2f705ce0bafbfdf9796d6a2a7b56742cb0ac43e5ede0660550caaf475",
        "sha256:7d31672ce3d8ddc84af277c46c68c67f3eb08402ddf275db1f555ab5418371ec",
        "union-candidate:019aec01a342bd71a9717c6fe69e7386aa2113278fed308fdadb45e1544a8040",
        11, 5,
    ),
    "RECEIPT": (
        "sha256:177e35792e42117e6fd20de3b0e637f69f1e7d15c887884f0ac6bbbabf808119",
        "sha256:5c7e22b7c243bb9fca7e6fc9ed75c02e90c2e3374b5b08e546490dbd3f80caab",
        "union-candidate:ec4e43c1385d16bcfe9e2e47f0a41cf57087cbe10038fed1167a1b6b1b284171",
        22, 4,
    ),
    "ROLE": (
        "sha256:534148fa8aa5bc7c0e7d6da33f99d9e7fe8b5da872befec57923a583fcdc87dd",
        "sha256:12be2ea6bcd7d19e9a6ba702e788c23ef116971b4d7329111de6281a1e35e9fa",
        "union-candidate:23bea32cb5847437387fc0579df3c305fe24cd46a674c8cd931f5a6249ba093c",
        5, 4,
    ),
    "TIME": (
        "sha256:4a371554c1f2681cc2c2f46ddc3729109850910e392e8fa7cdfb03c463a11d82",
        "sha256:feb6b9a824279f36c3dcbdb3ee8092b30b06b88ba72dfb73fa930ce0975f216b",
        "union-candidate:cc0470b99ebdefb898af47a167262a67eebbb36558d5e3cbb881829c0305b028",
        6, 4,
    ),
    "TOKEN": (
        "sha256:de59dca3605e559f8b4e4c56e69690662108d0954de88cbb1f56b87e272c7581",
        "sha256:7005371352a059f78fcef6eabb266f3e7618e6d708d64f38d7e480b89d478254",
        "union-candidate:f7a570f30de73838f2a2970a74583691708451dfe6ba5ba4a5eaa9b2cfe86235",
        13, 4,
    ),
}

MAPPED_KINDS = tuple(_ACCEPTED)
REJECTED_KINDS = (
    "AGENT", "BOT", "EVENT", "HYPER", "MODEL", "OWNER", "SPACE", "TRAIN", "VERIFIER"
)
MISSING_KIND = "HARNESS"


class ProjectionRefusal(ValueError):
    """The supplied row is not one of the exact reviewed one-way projections."""


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def installed_route_source_binding() -> dict[str, Any]:
    """Return and verify the installed native registration source binding."""
    path = Path(independence_checks.__file__).resolve()
    source_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if source_sha256 != ROUTE_SOURCE_SHA256:
        raise ProjectionRefusal("installed native registration source is not the reviewed source")
    return {"path": ROUTE_SOURCE_PATH, "sha256": source_sha256}


def accepted_projection(kind: str) -> dict[str, Any]:
    """Describe one fixed accepted projection without granting any semantic credit."""
    if type(kind) is not str or kind not in _ACCEPTED:
        if kind in REJECTED_KINDS:
            raise ProjectionRefusal("kind was rejected by the reviewed bounded adapter")
        if kind == MISSING_KIND:
            raise ProjectionRefusal("HARNESS tier-5 registration remains UNKNOWN and absent")
        raise ProjectionRefusal("kind is outside the fixed reviewed projection set")
    route_digest, claim_digest, ref_id, contribution_index, row_index = _ACCEPTED[kind]
    return {
        "object_kind": kind,
        "member_id": kind + "-5.1",
        "route_registration_digest": route_digest,
        "union_claim_digest": claim_digest,
        "union_ref_id": ref_id,
        "contribution_index": contribution_index,
        "row_index": row_index,
        "source": {"uri": UNION_SOURCE_URI, "sha256": UNION_SOURCE_SHA256},
    }


def project_registration(
    kind: str,
    native_registration: Mapping[str, Any],
    union_candidate: Mapping[str, Any],
    *,
    direction: str = "ROUTE_TO_UNION",
) -> dict[str, Any]:
    """Verify one exact, non-reversible proposition-text projection.

    ``union_candidate`` is data, not authority.  Successful return only proves
    that its text and bindings match the fixed reviewed structural mapping.
    """
    pin = accepted_projection(kind)
    if direction != "ROUTE_TO_UNION":
        raise ProjectionRefusal("only the narrowing ROUTE_TO_UNION direction is admitted")
    expected_registration = independence_checks.registration(kind)
    if dict(native_registration) != expected_registration:
        raise ProjectionRefusal("native registration differs from the installed exact registration")
    route_digest = digest(dict(native_registration))
    if route_digest != pin["route_registration_digest"]:
        raise ProjectionRefusal("native registration digest differs from the reviewed route digest")

    required = {
        "object_kind": kind,
        "member_id": kind + "-5.1",
        "union_ref_id": pin["union_ref_id"],
        "claim_sha256": pin["union_claim_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
        "source": pin["source"],
    }
    for field, value in required.items():
        if union_candidate.get(field) != value:
            raise ProjectionRefusal("union candidate has a substituted " + field)
    claim_text = union_candidate.get("claim_text")
    if type(claim_text) is not str:
        raise ProjectionRefusal("union candidate claim_text must be exact text")
    if claim_text != expected_registration["proposition"]:
        raise ProjectionRefusal("projection does not preserve exact proposition text")
    if _text_digest(claim_text) != pin["union_claim_digest"]:
        raise ProjectionRefusal("union claim digest does not bind the exact proposition text")
    route_source = installed_route_source_binding()
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "STRUCTURAL_PROJECTION_ONLY",
        "base_source_coordinate_sha256": BASE_SOURCE_COORDINATE_SHA256,
        "object_kind": kind,
        "member_id": kind + "-5.1",
        "relation": {
            "direction": "ROUTE_TO_UNION",
            "operation": "EXTRACT_EXACT_PROPOSITION_FIELD_AS_UTF8",
            "information_relation": "NARROWING_NON_REVERSIBLE",
            "semantic_equivalence_claimed": False,
            "digest_alias_claimed": False,
        },
        "route_registration_digest": route_digest,
        "union_claim_digest": pin["union_claim_digest"],
        "route_source": route_source,
        "union_source": pin["source"],
        "current_evidence_status": "UNKNOWN",
        "evidence_credit": "NONE",
        "completeness_credit": "NONE",
        "authority_credit": "NONE",
        "package_credit": "NONE",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def bounded_accounting() -> dict[str, Any]:
    """Return the immutable denominator accounting retained from review."""
    return {
        "non_sim_current_tier5_positions": 25,
        "mapped": len(MAPPED_KINDS),
        "rejected": len(REJECTED_KINDS),
        "missing_unknown": 1,
        "missing_kind": MISSING_KIND,
        "reconciled_in_140": 15,
        "unresolved_in_140": 125,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import re

import pytest

from verifier.runtime.package_semantic_ownership import (
    SEMANTIC_OWNERSHIP_SPECS,
    validate_catalog,
)
from verifier.runtime.package_semantic_ownership_normative_assets import (
    AGENCY_CROSSWALK_ROOT_APPLIES,
    NORMATIVE_ASSET_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]
ASSET_ROOTS = (
    "src/verifier/standard",
    "src/verifier/schemas",
    "src/verifier/profiles",
    "docs/profiles",
)
AGENCY_PATH = "src/verifier/standard/AGENCY_SURFACE.md"
AGENCY_OWNER = "vstd-agency-surface-crosswalk-assets"
ROUTE_COORDINATES = (
    "BOT-1.7-agency-surface-binding",
    "BOT-2.6-agency-surface-trace",
    "BOT-3.5-agency-surface-operational-boundary",
    "ROBOT-1.2-agency-surface-binding",
    "ROBOT-2.2-agency-surface-trace",
    "ROBOT-3.2-agency-surface-operational-boundary",
    "FINBOT-1.2-agency-surface-binding",
    "FINBOT-2.2-agency-surface-trace",
    "FINBOT-3.2-agency-surface-operational-boundary",
)


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _ordinary_assets() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for relative in ASSET_ROOTS
        for path in (ROOT / relative).rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


def _other_specs() -> tuple:
    partition_ids = {item.object_id for item in NORMATIVE_ASSET_OWNERSHIP_SPECS}
    return tuple(
        item
        for item in SEMANTIC_OWNERSHIP_SPECS
        if item.object_id not in partition_ids
    )


def _partition_with_extra_path(object_id: str, path: str) -> tuple:
    return tuple(
        replace(item, owned_paths=tuple(sorted((*item.owned_paths, path))))
        if item.object_id == object_id
        else item
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
    )


def test_partition_is_the_exact_current_residual_without_catalog_overlap() -> None:
    partition_ids = {item.object_id for item in NORMATIVE_ASSET_OWNERSHIP_SPECS}
    other_specs = tuple(
        item
        for item in SEMANTIC_OWNERSHIP_SPECS
        if item.object_id not in partition_ids
    )
    other_paths = {
        path
        for item in other_specs
        for path in item.owned_paths
    }
    paths = [
        path
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]

    assert len(NORMATIVE_ASSET_OWNERSHIP_SPECS) == 67
    assert len(paths) == 291
    assert len(paths) == len(set(paths))
    assert not set(paths) & other_paths
    assert set(paths) == _ordinary_assets() - other_paths
    assert Counter(
        next(root for root in ASSET_ROOTS if path.startswith(root + "/"))
        for path in paths
    ) == {
        "src/verifier/standard": 191,
        "src/verifier/schemas": 80,
        "src/verifier/profiles": 12,
        "docs/profiles": 8,
    }
    assert sum("/profiles/" in path for path in paths) == 20
    assert all((ROOT / path).is_file() for path in paths)


def test_partition_distinguishes_static_semantics_without_effect_overclaim() -> None:
    assert Counter(
        item.primary_kind for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
    ) == {
        "DATA": 3,
        "POLICY": 37,
        "PROTOCOL": 18,
        "VERIFIER": 9,
    }
    allowed = {"DATA", "POLICY", "PROTOCOL", "VERIFIER"}
    for item in NORMATIVE_ASSET_OWNERSHIP_SPECS:
        assert set((item.primary_kind, *item.specializations)) <= allowed
        assert item.representation_role.strip()
        assert item.necessity_reason.strip()
        assert item.consequence_boundary.strip()
        assert item.object_id.endswith("-assets")

    rows = {item.object_id: item for item in NORMATIVE_ASSET_OWNERSHIP_SPECS}
    assert rows["vstd-profile-architecture-assets"].primary_kind == "POLICY"
    assert "not a computational-model ARCH" in rows[
        "vstd-profile-architecture-assets"
    ].consequence_boundary
    assert rows["vstd-repository-admission-assets"].primary_kind == "POLICY"
    assert rows["vstd-prdel-language-assets"].primary_kind == "PROTOCOL"
    assert rows["vstd-component-index-data-assets"].primary_kind == "DATA"
    assert rows["vstd-package-self-polish-assets"].primary_kind == "VERIFIER"
    simulation_receipts = rows["vstd-simulation-risk-receipt-assets"]
    assert simulation_receipts.primary_kind == "PROTOCOL"
    assert tuple(
        (decision.kind, decision.status)
        for decision in simulation_receipts.root_role_decisions
    ) == (("RECEIPT", "DOES_NOT_APPLY"),)
    assert rows["vstd-experimental-workflow-profile-assets"].primary_kind == (
        "PROTOCOL"
    )
    assert "run nothing" in rows[
        "vstd-package-self-polish-assets"
    ].consequence_boundary
    assert "no ROBOT" in rows["vstd-current-bot-policy-assets"].consequence_boundary


def test_partition_rejects_an_asset_reassigned_to_an_existing_owner() -> None:
    other_specs = _other_specs()
    existing_path = next(path for item in other_specs for path in item.owned_paths)
    conflicting = replace(
        NORMATIVE_ASSET_OWNERSHIP_SPECS[0],
        object_id="audit-normative-overlap",
        owned_paths=(existing_path,),
    )
    with pytest.raises(ValueError, match="PATH_DUPLICATED"):
        validate_catalog(ROOT, other_specs + (conflicting,))


def test_agency_surface_document_has_exactly_one_normative_owner() -> None:
    assert (ROOT / AGENCY_PATH).is_file()
    assert AGENCY_PATH in _ordinary_assets()
    assert AGENCY_PATH not in {
        path for item in _other_specs() for path in item.owned_paths
    }
    owners = [
        item.object_id
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
        if AGENCY_PATH in item.owned_paths
    ]
    assert owners == [AGENCY_OWNER]


@pytest.mark.parametrize(
    "duplicate_owner",
    [
        "vstd-certificate-dependency-assets",
        "vstd-current-bot-policy-assets",
        "vstd-current-agent-policy-assets",
    ],
)
def test_agency_surface_second_owner_is_rejected_as_duplicate(
    duplicate_owner: str,
) -> None:
    partition = _partition_with_extra_path(duplicate_owner, AGENCY_PATH)
    with pytest.raises(ValueError, match="PATH_DUPLICATED"):
        validate_catalog(ROOT, _other_specs() + partition)


def test_agency_surface_owner_keeps_cumulative_roles_without_object_exemption() -> None:
    rows = {item.object_id: item for item in NORMATIVE_ASSET_OWNERSHIP_SPECS}
    owner = rows[AGENCY_OWNER]
    assert owner.primary_kind == "POLICY"
    assert owner.specializations == ("PROTOCOL",)
    assert "OBJECT" not in (owner.primary_kind, *owner.specializations)
    assert tuple(decision.kind for decision in owner.root_role_decisions) == (
        AGENCY_CROSSWALK_ROOT_APPLIES
    )
    assert all(decision.status == "APPLIES" for decision in owner.root_role_decisions)
    assert owner.owned_paths == (AGENCY_PATH,)
    assert "accumulate" in owner.necessity_reason
    assert "OBJECT" in owner.necessity_reason
    assert "obligation" in owner.consequence_boundary
    assert "NOT_ESTABLISHED" in owner.consequence_boundary
    for kind in ("BOT", "ROBOT", "FINBOT"):
        assert kind in owner.representation_role
    assert "do not promote" in owner.consequence_boundary
    assert "subject instantiation" in owner.consequence_boundary


def test_agency_surface_is_not_owned_by_a_single_role_bot_or_agent_policy() -> None:
    rows = {item.object_id: item for item in NORMATIVE_ASSET_OWNERSHIP_SPECS}
    for single_role in ("vstd-current-bot-policy-assets", "vstd-current-agent-policy-assets"):
        assert AGENCY_PATH not in rows[single_role].owned_paths
    assert "has no ROBOT" in rows["vstd-current-bot-policy-assets"].consequence_boundary


def test_agency_surface_document_retains_route_table_and_role_accumulation() -> None:
    text = " ".join((ROOT / AGENCY_PATH).read_text(encoding="utf-8").split())
    routes = re.findall(
        r"^\| `([A-Z]+-\d\.\d-agency-surface-[a-z-]+)` \|",
        (ROOT / AGENCY_PATH).read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert tuple(routes) == ROUTE_COORDINATES
    for phrase in (
        "These roles accumulate:",
        "A simulation label never discharges either consequence.",
        "an `OBJECT` label, omission, or unknown applicability cannot",
        "changing the string in a retained record is rejected.",
    ):
        assert phrase in text


def test_partition_pins_mapping_semantics_and_source_bytes() -> None:
    paths = [
        path
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(paths) == (
        "0ba002b5512657e95fdb52887318c561cb5e2c39c23a4b3cecffcce31a8f798d"
    )

    mapping = [
        f"{item.object_id}\t{item.primary_kind}\t{','.join(item.specializations)}\t{path}"
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(mapping) == (
        "3a99102df32ff1600975ccee20eea68fcf68a757c66bfbbc1006a7990f651d49"
    )

    semantics = [
        json.dumps(
            asdict(item),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        for item in NORMATIVE_ASSET_OWNERSHIP_SPECS
    ]
    assert _sha256(semantics) == (
        "5a5e3fae1ca6438093d18f8b1d3ec6d6015a43a8fa61e48528602688eafa4712"
    )

    inventory = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        # Two consecutive reads prove each owned byte string is stable before pinning.
        assert (ROOT / path).read_bytes() == content, path
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    assert _sha256(inventory) == (
        "9c662d567efbb2c04ce4f4b648639fe9b152634033474c47ff32b8e8b9e93a05"
    )

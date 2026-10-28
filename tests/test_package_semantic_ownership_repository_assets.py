from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from verifier.runtime import package_original_kind_catalog_repository_assets as catalog
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_ownership_model import root_role_decision
from verifier.runtime.package_semantic_ownership_repository_assets import (
    CATCHALL_BOUNDARY_EXCLUSIONS,
    REPOSITORY_ASSET_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]
# Concurrent test runs leave transient scratch files at the repository root.
# They are neither manifest catchall members nor repository assets, so only this
# exact prefix is excluded from the root bucket; every other top-level file counts.
TRANSIENT_ROOT_SCRATCH_PREFIX = ".pytest-tmp-"
# Reconciled with the catalog audit's per-row content digests over the same bytes.
OWNED_INVENTORY_SHA256 = (
    "046a649b83e0aa6198998aa77eb8f291e44d310bc4f566e1608ddb753e653d1b"
)

# These are the six byte-changing paths behind the aggregate rebind.  Pinning
# them independently prevents an incompatible change from hiding behind a new
# aggregate digest while preserving the larger exact 234-path census below.
CHANGED_SOURCE_BYTES = {
    "docs/ACCOUNTABILITY_RELEASE_SCOPE.md": (
        5920,
        "d9a8f6ee00f123815359333f1223972c27e4d4336eeaeff960cfc6e0e50b3734",
    ),
    "docs/API_STABILITY.md": (
        38164,
        "598b7c8a5cb5f31ea9cc9813b9b9961a9138bd31ccfaf437212151f7b6a02207",
    ),
    ".github/workflows/ci.yml": (
        40422,
        "57dc0dc41e1d6cb45ba17fb16193017f597031e7ded574a0fdbc74f89436ff56",
    ),
    "src/verifier_standard.egg-info/PKG-INFO": (
        80721,
        "93081843eea0bfd25da856f90977bc4256b84369dffcb19e50c7dceafa9105d6",
    ),
    "src/verifier_standard.egg-info/SOURCES.txt": (
        64706,
        "8e5041342a118fa5d7ee0aee06cdb78f0e7e48316580972103e93637aa58fca7",
    ),
    "src/verifier_standard.egg-info/requires.txt": (
        665,
        "3201b970487a679e72f77bd19290c88a3d65e45c4da3cbe031e9b5741258a2f0",
    ),
}

# The manifest catchall contained 249 paths in the six broad locations.  Eight
# generated/build surfaces and eight normative documentation profiles belong
# to separate audits. The separately owned root uv lock makes the exact current
# static-asset denominator 234 paths without widening the package object.
EXPECTED_BUCKET_COUNTS = {
    "vstd": 131,
    "docs": 51,
    "github": 13,
    "receipts": 9,
    "egg_info": 6,
    "root": 24,
}
EXPECTED_SEMANTICS = {
    "vstd-retained-facet-policy-inputs": ("POLICY", (), 4),
    "vstd-retained-graph-statics-policy-input": ("POLICY", (), 1),
    "vstd-retained-object-facet-requests": ("PROTOCOL", (), 6),
    "vstd-retained-typed-facet-requests": ("PROTOCOL", (), 56),
    "vstd-retained-graph-statics-request": ("PROTOCOL", (), 1),
    "vstd-retained-object-facet-certificates": ("DATA", (), 6),
    "vstd-retained-typed-facet-certificates": ("DATA", (), 56),
    "vstd-retained-graph-statics-certificate": ("DATA", (), 1),
    "vstd-root-uv-dependency-resolution": ("DATA", ("POLICY", "PROTOCOL"), 1),
    "vstd-documentation-claim-boundary-policy": ("POLICY", (), 8),
    "vstd-documentation-reader-reference": ("DATA", ("POLICY",), 4),
    "vstd-documentation-core-architecture": ("ARCH", ("POLICY",), 5),
    "vstd-documentation-artifact-interoperability-architecture": (
        "ARCH",
        ("POLICY",),
        6,
    ),
    "vstd-documentation-control-domain-candidates": ("POLICY", (), 5),
    "vstd-documentation-environment-graph-architecture": (
        "ARCH",
        ("POLICY",),
        3,
    ),
    "vstd-documentation-local-tool-protocols": (
        "PROTOCOL",
        ("POLICY",),
        4,
    ),
    "vstd-documentation-remote-submission-protocols": (
        "PROTOCOL",
        ("POLICY",),
        4,
    ),
    "vstd-documentation-user-navigation": ("DATA", (), 5),
    "vstd-documentation-hosting-protocol": (
        "PROTOCOL",
        ("POLICY",),
        1,
    ),
    "vstd-documentation-adjacent-standards-crosswalks": (
        "ARCH",
        ("POLICY",),
        3,
    ),
    "vstd-documentation-derived-metadata": ("DATA", (), 3),
    "vstd-repository-file-and-package-policy": ("POLICY", (), 3),
    "vstd-repository-citation-metadata": ("DATA", (), 2),
    "vstd-repository-legal-notices": ("POLICY", (), 2),
    "vstd-repository-agent-operating-policy": ("POLICY", (), 3),
    "vstd-repository-community-governance-policy": ("POLICY", (), 4),
    "vstd-repository-source-admission-designs": (
        "ARCH",
        ("POLICY",),
        4,
    ),
    "vstd-repository-overview": ("DATA", (), 1),
    "vstd-repository-release-procedure-policy": ("POLICY", (), 2),
    "vstd-repository-history-and-roadmap": ("DATA", (), 2),
    "vstd-github-contribution-form-policy": ("POLICY", (), 5),
    "vstd-github-external-link-policy": ("POLICY", (), 1),
    "vstd-github-verification-workflow-protocols": (
        "PROTOCOL",
        ("POLICY",),
        2,
    ),
    "vstd-github-source-description-workflow-protocol": (
        "PROTOCOL",
        ("POLICY",),
        1,
    ),
    "vstd-github-promotion-policy-protocols": (
        "PROTOCOL",
        ("POLICY",),
        2,
    ),
    "vstd-github-documentation-deployment-protocol": (
        "PROTOCOL",
        ("POLICY",),
        1,
    ),
    "vstd-github-release-workflow-protocol": (
        "PROTOCOL",
        ("POLICY",),
        1,
    ),
    "vstd-receipt-wire-schema-catalog": ("PROTOCOL", ("POLICY",), 8),
    "vstd-accelerator-profile-wire-schema": ("PROTOCOL", ("POLICY",), 1),
    "vstd-generated-distribution-metadata": ("DATA", (), 6),
}


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _relative_files(root: Path, folder: str) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in (root / folder).rglob("*")
        if path.is_file()
    }


def _audited_inventory(root: Path = ROOT) -> tuple[set[str], Counter[str]]:
    excluded = set(CATCHALL_BOUNDARY_EXCLUSIONS)
    buckets = {
        "vstd": _relative_files(root, ".vstd"),
        "docs": _relative_files(root, "docs") - excluded,
        "github": _relative_files(root, ".github"),
        "receipts": _relative_files(root, "receipts"),
        "egg_info": _relative_files(root, "src/verifier_standard.egg-info"),
        # objects.vstd did not own itself in the source catchall.  pyproject.toml
        # is the separately audited executable build and packaging configuration.
        "root": {
            path.name
            for path in root.iterdir()
            if path.is_file()
            and path.name not in {"objects.vstd", "pyproject.toml"}
            and not path.name.startswith(TRANSIENT_ROOT_SCRATCH_PREFIX)
        },
    }
    return set().union(*buckets.values()), Counter(
        {name: len(paths) for name, paths in buckets.items()}
    )


def _inventory_digest(paths: list[str] | tuple[str, ...], root: Path = ROOT) -> str:
    """Digest the path, byte length and content hash of every owned path."""
    return _sha256(_inventory_rows(paths, root))


def _inventory_rows(
    paths: list[str] | tuple[str, ...], root: Path = ROOT
) -> list[str]:
    """Capture one exact source inventory for stability comparison."""
    inventory = []
    for path in paths:
        content = (root / path).read_bytes()
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    return inventory


def _synthetic_root(tmp_path: Path) -> Path:
    """Copy only the owned and boundary-excluded bytes into a scratch tree."""
    root = tmp_path / "repo"
    names = {
        path
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    } | set(CATCHALL_BOUNDARY_EXCLUSIONS)
    for name in sorted(names):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return root


def test_partition_is_the_exact_source_bound_asset_denominator() -> None:
    expected_paths, counts = _audited_inventory()
    actual_paths = [
        path
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]

    assert counts == Counter(EXPECTED_BUCKET_COUNTS)
    assert len(actual_paths) == 234
    assert len(actual_paths) == len(set(actual_paths))
    assert set(actual_paths) == expected_paths
    assert all((ROOT / path).is_file() for path in actual_paths)

    assert set(CATCHALL_BOUNDARY_EXCLUSIONS) == {
        "docs/assets/orientation-previews.js",
        "docs/assets/site.css",
        "docs/assets/vstd-overview.png",
        "docs/assets/vstd-overview.svg",
        "docs/guides.html",
        "docs/index.html",
        "docs/profiles/competition-evaluation.md",
        "docs/profiles/experimental-workflow.md",
        "docs/profiles/experimental-workflow.schema.json",
        "docs/profiles/vstd-3/artifact-tracing.md",
        "docs/profiles/vstd-3/compatibility.md",
        "docs/profiles/vstd-3/references.md",
        "docs/profiles/vstd-3/threat-model.md",
        "docs/profiles/vstd-3/vendor-integration.md",
        "docs/reference.html",
        "pyproject.toml",
    }
    assert all((ROOT / path).is_file() for path in CATCHALL_BOUNDARY_EXCLUSIONS)
    assert set(actual_paths).isdisjoint(CATCHALL_BOUNDARY_EXCLUSIONS)


def test_partition_pins_semantic_grouping_and_required_reasons() -> None:
    actual = {
        item.object_id: (
            item.primary_kind,
            item.specializations,
            len(item.owned_paths),
        )
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED_SEMANTICS
    assert len(actual) == 40
    assert all(item.representation_role.strip() for item in REPOSITORY_ASSET_OWNERSHIP_SPECS)
    assert all(item.necessity_reason.strip() for item in REPOSITORY_ASSET_OWNERSHIP_SPECS)
    assert all(item.consequence_boundary.strip() for item in REPOSITORY_ASSET_OWNERSHIP_SPECS)


def test_partition_does_not_overlap_any_other_current_semantic_owner() -> None:
    selected_ids = {item.object_id for item in REPOSITORY_ASSET_OWNERSHIP_SPECS}
    selected_paths = {
        path
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    }
    other_paths = {
        path
        for item in SEMANTIC_OWNERSHIP_SPECS
        if item.object_id not in selected_ids
        for path in item.owned_paths
    }
    assert selected_paths.isdisjoint(other_paths)


def test_static_assets_cannot_inherit_operational_or_real_world_roles() -> None:
    forbidden = {
        "ACTUATOR",
        "AGENT",
        "ASSET",
        "BOT",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "MODEL",
        "OBJECT",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    }
    for item in REPOSITORY_ASSET_OWNERSHIP_SPECS:
        assert forbidden.isdisjoint((item.primary_kind, *item.specializations))
        assert item.operands == ()

    by_id = {
        item.object_id: item for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
    }
    for object_id in (
        "vstd-retained-object-facet-certificates",
        "vstd-retained-typed-facet-certificates",
        "vstd-retained-graph-statics-certificate",
    ):
        boundary = by_id[object_id].consequence_boundary.lower()
        assert "current" in boundary
        assert "conformance" in boundary
        assert tuple(
            (decision.kind, decision.status)
            for decision in by_id[object_id].root_role_decisions
        ) == (("RECEIPT", "APPLIES"),)

    for object_id in (
        "vstd-github-verification-workflow-protocols",
        "vstd-github-source-description-workflow-protocol",
        "vstd-github-promotion-policy-protocols",
        "vstd-github-documentation-deployment-protocol",
        "vstd-github-release-workflow-protocol",
    ):
        boundary = by_id[object_id].consequence_boundary.lower()
        assert "static" in boundary or "declaration" in boundary
        assert "not" in boundary

    generated = by_id["vstd-generated-distribution-metadata"].consequence_boundary
    for term in ("installation", "release", "publication"):
        assert term in generated

    lock_boundary = by_id["vstd-root-uv-dependency-resolution"].consequence_boundary
    for term in (
        "installed dependencies",
        "artifact availability",
        "artifact integrity",
        "runtime execution",
        "reproducibility",
        "zero-required-runtime-dependency",
    ):
        assert term in lock_boundary


def test_changed_assets_retain_exact_roles_audits_and_no_effect_boundaries() -> None:
    """Bind each changed file to its reviewed owner and static-effect boundary."""
    specs = {item.object_id: item for item in REPOSITORY_ASSET_OWNERSHIP_SPECS}
    rows = {
        row.object_id: row for row in catalog.REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    }
    expected = {
        "vstd-documentation-claim-boundary-policy": (
            "POLICY",
            (),
            set(),
            "does not itself run a gate",
        ),
        "vstd-github-verification-workflow-protocols": (
            "PROTOCOL",
            ("POLICY",),
            set(),
            "not a current run",
        ),
        "vstd-generated-distribution-metadata": (
            "DATA",
            (),
            {"DATA"},
            "does not prove freshness",
        ),
    }
    changed_paths = set(CHANGED_SOURCE_BYTES)
    for object_id, (primary, specializations, original_applies, boundary) in expected.items():
        spec = specs[object_id]
        assert spec.primary_kind == primary
        assert spec.specializations == specializations
        assert spec.operands == ()
        assert spec.root_role_decisions == ()
        assert changed_paths & set(spec.owned_paths)
        assert boundary in spec.consequence_boundary.lower()

        questions = rows[object_id].questions
        assert {
            question.kind for question in questions if question.status == catalog.APPLIES
        } == original_applies
        assert all(question.status != "DOES_NOT_APPLY" for question in questions)

    owners = {
        path: item.object_id
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
        if path in changed_paths
    }
    assert owners == {
        "docs/ACCOUNTABILITY_RELEASE_SCOPE.md": "vstd-documentation-claim-boundary-policy",
        "docs/API_STABILITY.md": "vstd-documentation-claim-boundary-policy",
        ".github/workflows/ci.yml": "vstd-github-verification-workflow-protocols",
        "src/verifier_standard.egg-info/PKG-INFO": "vstd-generated-distribution-metadata",
        "src/verifier_standard.egg-info/SOURCES.txt": "vstd-generated-distribution-metadata",
        "src/verifier_standard.egg-info/requires.txt": "vstd-generated-distribution-metadata",
    }
    for path, (expected_length, expected_digest) in CHANGED_SOURCE_BYTES.items():
        content = (ROOT / path).read_bytes()
        assert len(content) == expected_length
        assert hashlib.sha256(content).hexdigest() == expected_digest

    accountability = (ROOT / "docs/ACCOUNTABILITY_RELEASE_SCOPE.md").read_text(
        encoding="utf-8"
    )
    api_stability = (ROOT / "docs/API_STABILITY.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    package_info = (ROOT / "src/verifier_standard.egg-info/PKG-INFO").read_text(
        encoding="utf-8"
    )
    source_list = (ROOT / "src/verifier_standard.egg-info/SOURCES.txt").read_text(
        encoding="utf-8"
    )
    requirements = (ROOT / "src/verifier_standard.egg-info/requires.txt").read_text(
        encoding="utf-8"
    )
    assert "38-kind extensible namespace" in accountability
    assert "not all 38 kinds in the extensible namespace" in api_stability
    assert "  optional-discovery:" in workflow
    assert "tests/test_namespace_javascript.py" in workflow
    assert package_info.startswith("Metadata-Version: 2.4\nName: verifier-standard\n")
    assert "src/verifier/runtime/package_semantic_ownership_repository_assets.py" in source_list
    for extra in (
        "[discovery-javascript]",
        "[discovery-rust]",
        "[discovery-shell]",
        "[discovery-workflows]",
    ):
        assert extra in requirements


def test_partition_pins_mapping_declarations_and_source_bytes() -> None:
    ids = [item.object_id for item in REPOSITORY_ASSET_OWNERSHIP_SPECS]
    paths = [
        path
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    mapping = [
        f"{item.object_id}\t{item.primary_kind}\t{','.join(item.specializations)}\t{path}"
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    declarations = [
        json.dumps(asdict(item), sort_keys=True, separators=(",", ":"))
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
    ]
    assert _sha256(ids) == (
        "65fae2445aee6d65f7664d9efba8c8cbd692687c8016654b4498653827965a95"
    )
    assert _sha256(paths) == (
        "4a4c317daadb0748192d66c2c6f3c8b11fbe860f9f9536bcf18170ccacc2dec1"
    )
    assert _sha256(mapping) == (
        "8f526cc00c45e96b56f8bb4c55a4edd8197834038ae45de46f507316ba28921e"
    )
    assert _sha256(declarations) == (
        "ff4888b7b53fba29cc0ee1477a067e4272e4833c82c6900e0167a85c3eb7f52a"
    )
    opening_inventory = _inventory_rows(paths)
    closing_inventory = _inventory_rows(paths)
    assert opening_inventory == closing_inventory
    assert _sha256(opening_inventory) == OWNED_INVENTORY_SHA256


def test_root_bucket_excludes_only_transient_scratch(tmp_path: Path) -> None:
    root = _synthetic_root(tmp_path)
    _, counts = _audited_inventory(root)
    assert counts == Counter(EXPECTED_BUCKET_COUNTS)

    (root / f"{TRANSIENT_ROOT_SCRATCH_PREFIX}run.log").write_text("scratch\n", encoding="utf-8")
    _, counts = _audited_inventory(root)
    assert counts == Counter(EXPECTED_BUCKET_COUNTS)

    (root / "STRAY_NOTE.md").write_text("not a repository asset\n", encoding="utf-8")
    _, counts = _audited_inventory(root)
    assert counts["root"] == EXPECTED_BUCKET_COUNTS["root"] + 1
    assert counts == Counter({**EXPECTED_BUCKET_COUNTS, "root": 25})


def test_inventory_pin_rejects_single_bit_drift_and_missing_bytes(tmp_path: Path) -> None:
    root = _synthetic_root(tmp_path)
    paths = [
        path
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _inventory_digest(paths, root) == OWNED_INVENTORY_SHA256

    target = root / "uv.lock"
    data = target.read_bytes()
    target.write_bytes(bytes([data[0] ^ 0x01]) + data[1:])
    assert _inventory_digest(paths, root) != OWNED_INVENTORY_SHA256

    target.unlink()
    with pytest.raises(FileNotFoundError):
        _inventory_digest(paths, root)


def test_stale_ownership_pins_cannot_reverse_the_catalog_downgrade() -> None:
    specs = {item.object_id: item for item in REPOSITORY_ASSET_OWNERSHIP_SPECS}
    rows = {row.object_id: row for row in catalog.REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS}
    assert set(rows) == set(specs)
    assert len(catalog.validate_source_partition()) == len(specs)

    # The catalog records no refutation.  The sole former denial stays UNRESOLVED
    # behind its exact effect-boundary blocker, so no ownership pin may restore it.
    statuses = [question.status for row in rows.values() for question in row.questions]
    assert "DOES_NOT_APPLY" not in statuses
    verifier = next(
        question
        for question in rows["vstd-retained-object-facet-requests"].questions
        if question.kind == "VERIFIER"
    )
    assert verifier.status == catalog.UNRESOLVED
    assert (
        "vstd-retained-object-facet-requests",
        "VERIFIER",
        catalog.UNCLOSED_EFFECT_BOUNDARY,
    ) in catalog.DEMOTED_EXCLUSIONS

    for object_id, row in rows.items():
        item = specs[object_id]
        assert all(decision.status == "APPLIES" for decision in item.root_role_decisions)
        established = {
            item.primary_kind,
            *item.specializations,
            *(decision.kind for decision in item.root_role_decisions),
        }
        applies = {question.kind for question in row.questions if question.status == "APPLIES"}
        assert applies == established & set(catalog.ORIGINAL_NON_OBJECT_KINDS)
        assert row.expected_owned_content_digest == catalog.owned_content_digest(
            item.owned_paths
        )

    # A stale declaration that re-admits the refutation changes the coordinate
    # digest, so the catalog rejects the whole partition rather than the denial.
    refuted = replace(
        specs["vstd-retained-object-facet-requests"],
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "Retained request messages are not checking mechanisms.",
            ),
        ),
    )
    stale_partition = [
        refuted if item.object_id == refuted.object_id else item
        for item in REPOSITORY_ASSET_OWNERSHIP_SPECS
    ]
    with pytest.raises(
        ValueError,
        match="REPOSITORY_ASSET_ORIGINAL_KIND_COORDINATE_DRIFT:vstd-retained-object-facet-requests",
    ):
        catalog.validate_source_partition(stale_partition)

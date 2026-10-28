from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
from typing import Callable

import pytest

from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]
SELF_PATH = "tests/test_package_semantic_ownership_tests_fixtures.py"
EXPECTED_PREPARTITION_MANIFEST_PATHS = 566
EXPECTED_PREMIGRATION_CURRENT_PATHS = 598
EXPECTED_PREMIGRATION_CURRENT_DIGEST = (
    "53cee2c6cafbee10833bcb942d43028a7d0ca345f56af60233d8f04cefdfb033"
)
EXPECTED_PREPARTITION_MANIFEST_DIGEST = (
    "c76eff3e0353cf6a154b16fe42b819cfd8c00e11f42c931bf62df829223acb27"
)
EXPECTED_PREAUTOREFRESH_CURRENT_PATHS = 600
EXPECTED_PREAUTOREFRESH_CURRENT_DIGEST = (
    "78ac831cd7b52c3cdb866c0edfd7a5ddfd11503127199827154888330d747b15"
)
EXPECTED_PRECUMULATIVE_CURRENT_PATHS = 601
EXPECTED_PRECUMULATIVE_CURRENT_DIGEST = (
    "97c6ee4294abd45d8ede291bdf524506e3e71bbf8a498a282fb6dc13c49a0d9f"
)
EXPECTED_PREGRAPH_ADAPTER_CURRENT_PATHS = 604
EXPECTED_PREGRAPH_ADAPTER_CURRENT_DIGEST = (
    "d55cfc45bf997f7dd17b1f42cc0ca1dfe8678efcb0d95cc2da44f8bb968dc3d2"
)
EXPECTED_PRE_ADDED_KIND_CURRENT_PATHS = 605
EXPECTED_PRE_ADDED_KIND_CURRENT_DIGEST = (
    "cec8c4bdb1e4159da91a49bb7d4465bd91c1c5318fdfe5bee069c680b155a0c5"
)
EXPECTED_MANIFEST_TEST_PATHS = 618
# The root manifest still represents this earlier admitted state (the paths of
# the pre-admission 618-object census). Its digest equals the prior path digest.
EXPECTED_MANIFEST_TEST_DIGEST = (
    "fbf501adf3a51e553a73bf88606288cd17a19e28d73c051bbc05cd3445ffc9ba"
)
EXPECTED_CURRENT_PATHS = 659
EXECUTION_ROLES = (
    "ACTUATOR",
    "CONTROLLER",
    "MEASUREMENT",
    "POLICY",
    "PROTOCOL",
    "SENSOR",
    "TRANSACTION",
)
EXPECTED_SEMANTICS = {
    "vstd-test-fixture-harness": ("HARNESS", EXECUTION_ROLES, 4),
    "vstd-test-formation-fixture-corpus": ("DATA", ("POLICY", "PROTOCOL"), 2),
    "vstd-test-spacetime-extension-schema": ("PROTOCOL", ("POLICY",), 1),
    "vstd-test-namespace-admission-regressions": ("VERIFIER", EXECUTION_ROLES, 91),
    "vstd-test-polish-regressions": ("VERIFIER", EXECUTION_ROLES, 70),
    "vstd-test-current-object-regressions": ("VERIFIER", EXECUTION_ROLES, 124),
    "vstd-test-simulation-model-regressions": ("VERIFIER", EXECUTION_ROLES, 33),
    "vstd-test-hardware-environment-regressions": ("VERIFIER", EXECUTION_ROLES, 23),
    "vstd-test-artifact-evidence-regressions": ("VERIFIER", EXECUTION_ROLES, 65),
    "vstd-test-governance-authority-regressions": ("VERIFIER", EXECUTION_ROLES, 40),
    "vstd-test-release-publication-regressions": ("VERIFIER", EXECUTION_ROLES, 38),
    "vstd-test-prdel-regressions": ("VERIFIER", EXECUTION_ROLES, 21),
    "vstd-test-security-privacy-regressions": ("VERIFIER", EXECUTION_ROLES, 8),
    "vstd-test-graph-composition-regressions": ("VERIFIER", EXECUTION_ROLES, 56),
    "vstd-test-runtime-execution-regressions": ("VERIFIER", EXECUTION_ROLES, 61),
    "vstd-test-packaging-compatibility-regressions": ("VERIFIER", EXECUTION_ROLES, 22),
}
EXPECTED_NEW_PATH_ASSIGNMENTS = {
    "tests/test_agency_surface.py": "vstd-test-current-object-regressions",
    "tests/test_language_runner_extension_outcomes.py": "vstd-test-hardware-environment-regressions",
    "tests/test_mandatory_test_dependencies.py": "vstd-test-packaging-compatibility-regressions",
    "tests/test_namespace_refutation.py": "vstd-test-namespace-admission-regressions",
    "tests/test_namespace_refutation_admission.py": "vstd-test-namespace-admission-regressions",
    "tests/test_native_language_extensions_batch_three.py": "vstd-test-hardware-environment-regressions",
    "tests/test_native_language_extensions_batch_two.py": "vstd-test-hardware-environment-regressions",
    "tests/test_native_language_package_dispatch_batch_three.py": "vstd-test-hardware-environment-regressions",
    "tests/test_native_language_package_dispatch_batch_two.py": "vstd-test-hardware-environment-regressions",
    "tests/test_native_language_top24_adapters.py": "vstd-test-hardware-environment-regressions",
    "tests/test_package_admission_semantic_review_replay.py": "vstd-test-namespace-admission-regressions",
    "tests/test_package_checker_source_binding.py": "vstd-test-runtime-execution-regressions",
    "tests/test_package_execution_owned_process_tree.py": "vstd-test-runtime-execution-regressions",
    "tests/test_package_execution_source_integrity.py": "vstd-test-runtime-execution-regressions",
    "tests/test_package_manifest_migration_harness_ownership.py": "vstd-test-namespace-admission-regressions",
    "tests/test_package_manifest_refresh_recovery.py": "vstd-test-namespace-admission-regressions",
    "tests/test_package_policy_enforcement_execution.py": "vstd-test-governance-authority-regressions",
    "tests/test_package_policy_enforcement_routes.py": "vstd-test-governance-authority-regressions",
    "tests/test_package_policy_route_integration.py": "vstd-test-governance-authority-regressions",
    "tests/test_package_protocol_dependency_relation.py": "vstd-test-graph-composition-regressions",
    "tests/test_package_transaction_execution.py": "vstd-test-runtime-execution-regressions",
    "tests/test_policy_decision_evidence.py": "vstd-test-governance-authority-regressions",
    "tests/test_run_owned_process_tree.py": "vstd-test-runtime-execution-regressions",
    "tests/test_runner_adversarial.py": "vstd-test-hardware-environment-regressions",
    "tests/test_self_polish_estate_git_isolation.py": "vstd-test-polish-regressions",
}
EXPECTED_ID_DIGEST = "c3593f995672d4176e0838042f0645e8ff4340139c56a94c886e3d2fc620b304"
EXPECTED_PATH_DIGEST = "680abcac5ccbdb05f4f3127b6aeee2b63ef0cd28cc7ec29ce80da16fe407140b"
EXPECTED_MAPPING_DIGEST = "2e6b4555b71c390df4e5d091be1b8eabff21ea0e37ed772f4121286157fd8ab0"
EXPECTED_DECLARATION_DIGEST = "14ad858ba14588aceeea1e5259412c061d8ae17be8beb3a188fca7332db26683"
EXPECTED_SOURCE_INVENTORY_DIGEST = "464fbafac4a36bf192b0457e476bb34dce6ca0de7f8875c1f116234a97d6702c"
# Foreign owned test whose bytes were strengthened after the partition pin was
# first taken. Recording its digest here names the drifted file explicitly.
FOREIGN_PINNED_TEST_SHA256 = {
    "tests/test_package_semantic_ownership_repository_assets.py": (
        "a7f4e8fa3ad1bd62fec679728c6cac8c7ecdf28bf890e2ed58e945529283671b"
    ),
}
OWNED_PATHS = tuple(
    path for item in TEST_FIXTURE_OWNERSHIP_SPECS for path in item.owned_paths
)


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _current_bytes(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _source_test_paths(root: Path = ROOT) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in (root / "tests").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def _census_mismatch(
    source: set[str], owned: tuple[str, ...] | list[str]
) -> tuple[list[str], list[str]]:
    """Return (unowned source files, owned paths absent from source)."""
    return sorted(source - set(owned)), sorted(set(owned) - source)


def _manifest_test_paths() -> set[str]:
    document = json.loads((ROOT / "objects.vstd").read_text(encoding="utf-8"))
    return {
        surface.removeprefix("file:")
        for item in document["namespace"]["objects"]
        for surface in item["surfaces"]
        if surface.startswith("file:tests/")
    }


def _normalized_source(
    path: str, read: Callable[[str], bytes] = _current_bytes
) -> bytes:
    content = read(path)
    if path == SELF_PATH:
        content, substitutions = re.subn(
            rb'EXPECTED_SOURCE_INVENTORY_DIGEST = "[0-9a-f]{64}"',
            b'EXPECTED_SOURCE_INVENTORY_DIGEST = "<self-normalized>"',
            content,
            count=1,
        )
        assert substitutions == 1
    return content


def _inventory_digest(
    paths: list[str] | tuple[str, ...],
    read: Callable[[str], bytes] = _current_bytes,
) -> str:
    """Digest path, byte length and content hash of every path, atomically."""
    inventory = []
    for path in paths:
        content = _normalized_source(path, read)
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    return _sha256(inventory)


def _foreign_pin_mismatches(
    pins: dict[str, str], read: Callable[[str], bytes] = _current_bytes
) -> list[str]:
    return [
        path
        for path, digest in sorted(pins.items())
        if hashlib.sha256(read(path)).hexdigest() != digest
    ]


def _with_bytes(
    target: str, content: bytes | None
) -> Callable[[str], bytes]:
    """Reader that substitutes one path's bytes; ``None`` removes the path."""

    def read(path: str) -> bytes:
        if path != target:
            return _current_bytes(path)
        if content is None:
            raise FileNotFoundError(path)
        return content

    return read


def _single_bit_flip(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def test_partition_is_the_exact_current_test_and_fixture_denominator() -> None:
    represented = _manifest_test_paths()
    actual = list(OWNED_PATHS)

    # The root manifest may still represent an exact earlier admitted state
    # while new source paths await the final package remigration. Every such
    # state is pinned explicitly instead of accepting an arbitrary subset.
    assert len(represented) in {
        EXPECTED_PREPARTITION_MANIFEST_PATHS,
        EXPECTED_PREMIGRATION_CURRENT_PATHS,
        EXPECTED_PREAUTOREFRESH_CURRENT_PATHS,
        EXPECTED_PRECUMULATIVE_CURRENT_PATHS,
        EXPECTED_PREGRAPH_ADAPTER_CURRENT_PATHS,
        EXPECTED_PRE_ADDED_KIND_CURRENT_PATHS,
        EXPECTED_MANIFEST_TEST_PATHS,
        EXPECTED_CURRENT_PATHS,
    }
    assert represented.issubset(actual)
    if len(represented) == EXPECTED_PREPARTITION_MANIFEST_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PREPARTITION_MANIFEST_DIGEST
    elif len(represented) == EXPECTED_PREMIGRATION_CURRENT_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PREMIGRATION_CURRENT_DIGEST
    elif len(represented) == EXPECTED_PREAUTOREFRESH_CURRENT_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PREAUTOREFRESH_CURRENT_DIGEST
    elif len(represented) == EXPECTED_PRECUMULATIVE_CURRENT_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PRECUMULATIVE_CURRENT_DIGEST
    elif len(represented) == EXPECTED_PREGRAPH_ADAPTER_CURRENT_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PREGRAPH_ADAPTER_CURRENT_DIGEST
    elif len(represented) == EXPECTED_PRE_ADDED_KIND_CURRENT_PATHS:
        assert _sha256(list(represented)) == EXPECTED_PRE_ADDED_KIND_CURRENT_DIGEST
    elif len(represented) == EXPECTED_MANIFEST_TEST_PATHS:
        assert _sha256(list(represented)) == EXPECTED_MANIFEST_TEST_DIGEST
    else:
        assert represented == set(actual)
    assert len(actual) == EXPECTED_CURRENT_PATHS
    assert len(actual) == len(set(actual))
    # Any test file on disk outside this partition is an unowned surface, and
    # any owned path absent from disk is a missing surface. Both fail closed.
    unowned, missing = _census_mismatch(_source_test_paths(), actual)
    assert unowned == []
    assert missing == []
    assert all((ROOT / path).is_file() for path in actual)


def test_census_rejects_extra_and_missing_owned_paths_atomically(
    tmp_path: Path,
) -> None:
    owned = list(OWNED_PATHS)
    extra = "tests/test_added_unowned_regression.py"
    unowned, missing = _census_mismatch({*owned, extra}, owned)
    assert unowned == [extra]
    assert missing == []

    unowned, missing = _census_mismatch(set(owned) - {owned[0]}, owned)
    assert unowned == []
    assert missing == [owned[0]]

    # The on-disk scanner is the census source; a real extra file under tests/
    # must surface in it rather than being silently skipped.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_extra.py").write_text("", encoding="utf-8")
    (tmp_path / "tests" / "__pycache__").mkdir()
    (tmp_path / "tests" / "__pycache__" / "x.pyc").write_bytes(b"")
    assert _source_test_paths(tmp_path) == {"tests/test_extra.py"}


def test_partition_pins_object_specific_semantics_and_reasons() -> None:
    actual = {
        item.object_id: (
            item.primary_kind,
            item.specializations,
            len(item.owned_paths),
        )
        for item in TEST_FIXTURE_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED_SEMANTICS
    assert len(actual) == 16
    assert all(
        item.representation_role.strip()
        and item.necessity_reason.strip()
        and item.consequence_boundary.strip()
        for item in TEST_FIXTURE_OWNERSHIP_SPECS
    )


def test_new_paths_have_exactly_one_content_specific_semantic_owner() -> None:
    actual: dict[str, list[str]] = {
        path: [] for path in EXPECTED_NEW_PATH_ASSIGNMENTS
    }
    for item in TEST_FIXTURE_OWNERSHIP_SPECS:
        for path in item.owned_paths:
            if path in actual:
                actual[path].append(item.object_id)

    assert set(actual) == set(EXPECTED_NEW_PATH_ASSIGNMENTS)
    assert actual == {
        path: [owner] for path, owner in EXPECTED_NEW_PATH_ASSIGNMENTS.items()
    }


def test_partition_does_not_overlap_any_other_current_semantic_owner() -> None:
    selected_ids = {item.object_id for item in TEST_FIXTURE_OWNERSHIP_SPECS}
    selected_paths = set(OWNED_PATHS)
    other_paths = {
        path
        for item in SEMANTIC_OWNERSHIP_SPECS
        if item.object_id not in selected_ids
        for path in item.owned_paths
    }
    assert selected_paths.isdisjoint(other_paths)


def test_test_subject_names_do_not_invent_external_consequence_roles() -> None:
    forbidden = {
        "AGENT",
        "ASSET",
        "BOT",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MODEL",
        "OBJECT",
        "ROBOT",
        "SIM",
    }
    by_id = {item.object_id: item for item in TEST_FIXTURE_OWNERSHIP_SPECS}
    for item in TEST_FIXTURE_OWNERSHIP_SPECS:
        assert forbidden.isdisjoint((item.primary_kind, *item.specializations))
        boundary = item.consequence_boundary
        assert "whole-package conformance" in boundary
        assert "physical actuation" in boundary
        assert "real-money authority" in boundary
        assert "MARKET" in boundary
        assert "BOT, ROBOT, or FINBOT" in boundary

    executable = [
        item
        for item in TEST_FIXTURE_OWNERSHIP_SPECS
        if item.primary_kind in {"HARNESS", "VERIFIER"}
    ]
    assert executable
    assert all(item.specializations == EXECUTION_ROLES for item in executable)

    simulation = by_id["vstd-test-simulation-model-regressions"].consequence_boundary
    assert "software-local" in simulation
    assert "not SIMs, BOTs, ROBOTs, FINBOTs" in simulation
    hardware = by_id["vstd-test-hardware-environment-regressions"].consequence_boundary
    assert "command no physical device" in hardware
    evidence = by_id["vstd-test-artifact-evidence-regressions"].consequence_boundary
    for term in ("custody", "backing", "finality", "financial value"):
        assert term in evidence


def test_partition_pins_mapping_declarations_and_normalized_source_bytes() -> None:
    ids = [item.object_id for item in TEST_FIXTURE_OWNERSHIP_SPECS]
    paths = list(OWNED_PATHS)
    mapping = [
        f"{item.object_id}\t{item.primary_kind}\t{','.join(item.specializations)}\t{path}"
        for item in TEST_FIXTURE_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    declarations = [
        json.dumps(asdict(item), sort_keys=True, separators=(",", ":"))
        for item in TEST_FIXTURE_OWNERSHIP_SPECS
    ]

    assert _sha256(ids) == EXPECTED_ID_DIGEST
    assert _sha256(paths) == EXPECTED_PATH_DIGEST
    assert _sha256(mapping) == EXPECTED_MAPPING_DIGEST
    assert _sha256(declarations) == EXPECTED_DECLARATION_DIGEST
    assert _inventory_digest(paths) == EXPECTED_SOURCE_INVENTORY_DIGEST
    assert _foreign_pin_mismatches(FOREIGN_PINNED_TEST_SHA256) == []


def test_inventory_pin_rejects_single_bit_drift_missing_and_extra_bytes() -> None:
    paths = list(OWNED_PATHS)
    assert _inventory_digest(paths) == EXPECTED_SOURCE_INVENTORY_DIGEST

    # Single-bit drift in any owned path, including the foreign sibling test,
    # changes the whole-partition digest.
    for target in (
        "tests/test_package_semantic_ownership_repository_assets.py",
        "tests/test_package_execution_source_integrity.py",
        "tests/conftest.py",
        "tests/fixtures/formation-receipt-corpus.json",
    ):
        flipped = _single_bit_flip(_current_bytes(target))
        assert _inventory_digest(paths, _with_bytes(target, flipped)) != (
            EXPECTED_SOURCE_INVENTORY_DIGEST
        ), target

    # A missing owned path fails closed rather than being skipped.
    with pytest.raises(FileNotFoundError):
        _inventory_digest(paths, _with_bytes(paths[0], None))

    # An extra owned path that was not pinned changes the digest.
    extra = "tests/test_added_unowned_regression.py"
    assert _inventory_digest([*paths, extra], _with_bytes(extra, b"")) != (
        EXPECTED_SOURCE_INVENTORY_DIGEST
    )

    # The self pin literal is the only normalized span; a bit flip elsewhere in
    # this module still changes the digest.
    self_bytes = _current_bytes(SELF_PATH)
    assert _normalized_source(SELF_PATH, _with_bytes(SELF_PATH, self_bytes)) == (
        _normalized_source(SELF_PATH)
    )
    assert _inventory_digest(paths, _with_bytes(SELF_PATH, _single_bit_flip(self_bytes))) != (
        EXPECTED_SOURCE_INVENTORY_DIGEST
    )


def test_stale_foreign_pin_is_rejected_by_bytes_it_no_longer_matches() -> None:
    foreign = "tests/test_package_semantic_ownership_repository_assets.py"
    assert _foreign_pin_mismatches(FOREIGN_PINNED_TEST_SHA256) == []

    # A digest recorded before the sibling was strengthened is a stale pin: it
    # must surface as a mismatch on that exact path, not as a silent pass.
    stale = hashlib.sha256(_single_bit_flip(_current_bytes(foreign))).hexdigest()
    assert _foreign_pin_mismatches({foreign: stale}) == [foreign]

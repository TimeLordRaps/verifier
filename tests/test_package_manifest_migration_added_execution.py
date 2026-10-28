"""Adversarial migration checks for the added ASSET and emulated-control selectors.

Verifier Standard (VSTD) migration must preserve unrelated manifest state and
must not turn a partial source review into an execution selection.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import pytest

from verifier.runtime import (
    emulator_control_execution,
    package_manifest_migration as migration,
    package_original_review_computation,
    package_semantic_review_records,
    token_asset_execution,
)


Selector = Callable[..., None]


def _binding(reason: str = "Unrelated reviewed binding.") -> dict[str, Any]:
    return {
        "reason": reason,
        "evidence": [],
        "declaration": {"scope": "Preserve this unrelated declaration exactly."},
    }


def _fixture(
    kind: str,
) -> tuple[Path, Selector, ModuleType, dict[str, Any], dict[str, str], dict[str, Any]]:
    root = Path(migration.__file__).resolve().parents[3]
    if kind == "asset":
        selector = migration._select_token_asset
        execution = token_asset_execution
        review = package_original_review_computation.review_document()["vstd-token"]
        row = {
            "object_id": "vstd-token",
            "kind": "TOKEN",
            "surfaces": ["file:" + path for path in review["owned_paths"]],
            "specializations": ["PROTOCOL", "POLICY"],
            "classification": {
                "ASSET": {"status": "UNRESOLVED", "reason": "", "evidence": []},
                "FINBOT": {
                    "status": "DOES_NOT_APPLY",
                    "reason": "Separately reviewed nonfinancial boundary.",
                    "evidence": [],
                },
            },
            "obligations": {"FINBOT-0.test-unrelated": _binding()},
            "reason": "Preserve the TOKEN object's existing reason.",
            "payload": {"sentinel": ["asset", 1]},
        }
    elif kind == "emulator":
        selector = migration._select_emulator_control
        execution = emulator_control_execution
        review = package_semantic_review_records.review_document()[
            "vstd-firmware-emulator-accounting"
        ]
        row = {
            "object_id": "vstd-firmware-emulator-accounting",
            "kind": "LEDGER",
            "surfaces": ["file:" + path for path in review["owned_paths"]],
            "specializations": ["TRANSACTION"],
            "classification": {
                role: {"status": "UNRESOLVED", "reason": "", "evidence": []}
                for role in ("CONTROLLER", "ACTUATOR")
            }
            | {
                "ROBOT": {
                    "status": "DOES_NOT_APPLY",
                    "reason": "The software emulator has no physical actuator.",
                    "evidence": [],
                }
            },
            "obligations": {"ROBOT-0.test-unrelated": _binding()},
            "reason": "Preserve the emulator ledger's existing reason.",
            "payload": {"sentinel": ["emulator", 1]},
        }
    else:  # pragma: no cover - helper misuse, not a migration branch
        raise AssertionError(kind)
    files = {
        path: migration.bytes_digest((root / path).read_bytes())
        for path in review["owned_paths"]
    }
    unrelated = {
        "object_id": "unrelated-object",
        "mechanism": "unrelated-adapter-1",
        "reason": "Preserve this unrelated selection byte-for-byte.",
        "evidence": [{"path": "unrelated.py", "sha256": "sha256:" + "a" * 64}],
    }
    namespace = {
        "objects": [row],
        "execution_checks": [deepcopy(unrelated)],
        "instance_checks": [{"sentinel": "preserve-instance-checks"}],
        "custom_unrelated_field": {"nested": [1, 2, 3]},
    }
    return root, selector, execution, namespace, files, review


@pytest.mark.parametrize("kind", ["asset", "emulator"])
def test_added_selector_is_deterministic_idempotent_and_preserves_unrelated_state(
    kind: str,
) -> None:
    root, selector, execution, namespace, files, review = _fixture(kind)
    unrelated_namespace = {
        key: deepcopy(namespace[key])
        for key in ("instance_checks", "custom_unrelated_field")
    }
    row = namespace["objects"][0]
    unrelated_row = {
        key: deepcopy(row[key])
        for key in ("kind", "reason", "payload")
    }
    unrelated_classification = deepcopy(
        row["classification"]["FINBOT" if kind == "asset" else "ROBOT"]
    )
    unrelated_obligation = deepcopy(
        row["obligations"][
            "FINBOT-0.test-unrelated" if kind == "asset" else "ROBOT-0.test-unrelated"
        ]
    )

    selector(root, namespace, row, files)
    first = deepcopy(namespace)
    selector(root, namespace, row, files)
    assert namespace == first

    _, second_selector, _, second, second_files, _ = _fixture(kind)
    second_selector(root, second, second["objects"][0], second_files)
    assert second == first
    assert namespace["execution_checks"][0]["mechanism"] == "unrelated-adapter-1"
    assert namespace["execution_checks"][1]["mechanism"] == execution.ADAPTER
    assert namespace["execution_checks"][1]["object_id"] == row["object_id"]
    assert unrelated_namespace == {
        key: namespace[key] for key in unrelated_namespace
    }
    assert unrelated_row == {key: row[key] for key in unrelated_row}
    assert row["classification"]["FINBOT" if kind == "asset" else "ROBOT"] == unrelated_classification
    assert row["obligations"][
        "FINBOT-0.test-unrelated" if kind == "asset" else "ROBOT-0.test-unrelated"
    ] == unrelated_obligation

    if kind == "asset":
        assert row["kind"] == "TOKEN"
        assert row["specializations"] == ["PROTOCOL", "POLICY", "ASSET"]
        roles = ("ASSET",)
        expected_evidence_paths = review["owned_paths"]
    else:
        assert row["kind"] == "LEDGER"
        assert row["specializations"] == ["TRANSACTION", "CONTROLLER", "ACTUATOR"]
        roles = ("CONTROLLER", "ACTUATOR")
        expected_evidence_paths = [execution.IMPLEMENTATION]
    assert namespace["execution_checks"][1]["evidence"] == [
        {"path": path, "sha256": files[path]} for path in expected_evidence_paths
    ]
    for role in roles:
        expected = review["classification"][role]
        assert row["classification"][role] == {
            "status": "APPLIES",
            "reason": expected["reason"],
            "evidence": [
                {"path": path, "sha256": files[path]}
                for path in expected["evidence_paths"]
            ],
        }
        names = {name for name in row["obligations"] if name.startswith(role + "-")}
        expected_names = {
            name for name in review["declarations"] if name.startswith(role + "-")
        }
        assert names == expected_names
        assert all(row["obligations"][name]["reason"].strip() for name in names)


@pytest.mark.parametrize("kind", ["asset", "emulator"])
@pytest.mark.parametrize(
    "conflict",
    ["owner", "source", "ownership", "decision", "declaration", "selection"],
)
def test_added_selector_failure_is_atomic(kind: str, conflict: str) -> None:
    root, selector, execution, namespace, files, _ = _fixture(kind)
    row = namespace["objects"][0]
    roles = ("ASSET",) if kind == "asset" else ("CONTROLLER", "ACTUATOR")
    if conflict == "owner":
        row["object_id"] = "different-owner"
    elif conflict == "source":
        files[execution.IMPLEMENTATION] = "sha256:" + "0" * 64
    elif conflict == "ownership":
        row["surfaces"].remove("file:" + execution.IMPLEMENTATION)
    elif conflict == "decision":
        row["classification"][roles[-1]]["status"] = "DOES_NOT_APPLY"
    elif conflict == "declaration":
        role = roles[-1]
        row["obligations"][role + "-0.conflicting-declaration"] = {
            "reason": "A separately selected conflicting declaration.",
            "evidence": [],
            "declaration": {"scope": "different"},
        }
        # The conflict must use a real catalog key to reach the exact binding guard.
        real_name = next(
            name
            for name in (
                package_original_review_computation.review_document()["vstd-token"]["declarations"]
                if kind == "asset"
                else package_semantic_review_records.review_document()[
                    "vstd-firmware-emulator-accounting"
                ]["declarations"]
            )
            if name.startswith(role + "-")
        )
        row["obligations"][real_name] = row["obligations"].pop(
            role + "-0.conflicting-declaration"
        )
    else:
        namespace["execution_checks"].append(
            {
                "object_id": row["object_id"],
                "mechanism": execution.ADAPTER,
                "reason": "Conflicting prior selection.",
                "evidence": [],
            }
        )
    before = deepcopy(namespace)
    with pytest.raises(ValueError, match="PACKAGE_MIGRATION_"):
        selector(root, namespace, row, files)
    assert namespace == before


@pytest.mark.parametrize(
    "mechanism,implementation,owner",
    [
        (
            token_asset_execution.ADAPTER,
            token_asset_execution.IMPLEMENTATION,
            "vstd-token",
        ),
        (
            emulator_control_execution.ADAPTER,
            emulator_control_execution.IMPLEMENTATION,
            "vstd-firmware-emulator-accounting",
        ),
    ],
)
def test_selected_execution_rehomes_only_to_unique_source_owner(
    mechanism: str, implementation: str, owner: str
) -> None:
    root = Path(migration.__file__).resolve().parents[3]
    reference = {
        "path": implementation,
        "sha256": migration.bytes_digest((root / implementation).read_bytes()),
    }
    original = {
        "object_id": "legacy-catchall",
        "mechanism": mechanism,
        "reason": "Retained selection must follow exact source ownership.",
        "evidence": [reference, {"path": "other.py", "sha256": "sha256:" + "b" * 64}],
    }
    namespace = {"execution_checks": [deepcopy(original)]}
    rows = {
        "legacy-catchall": {"surfaces": []},
        owner: {"surfaces": ["file:" + implementation]},
    }
    migration._rehome_execution_checks(
        namespace, rows, {implementation: owner}
    )
    assert namespace["execution_checks"] == [{**original, "object_id": owner}]

    missing_binding = {"execution_checks": [{**original, "evidence": []}]}
    with pytest.raises(
        ValueError,
        match="PACKAGE_MIGRATION_EXECUTION_EVIDENCE_DOES_NOT_BIND_IMPLEMENTATION",
    ):
        migration._rehome_execution_checks(
            missing_binding, rows, {implementation: owner}
        )
    ambiguous_rows = {
        **rows,
        "second-owner": {"surfaces": ["file:" + implementation]},
    }
    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_AMBIGUOUS"
    ):
        migration._rehome_execution_checks(
            {"execution_checks": [deepcopy(original)]},
            ambiguous_rows,
            {implementation: owner},
        )
    duplicate = {
        "execution_checks": [
            deepcopy(original),
            {**deepcopy(original), "object_id": owner},
        ]
    }
    with pytest.raises(
        ValueError, match="PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_CONFLICT"
    ):
        migration._rehome_execution_checks(
            duplicate, rows, {implementation: owner}
        )


def test_refresh_recovers_only_selected_added_execution_flags() -> None:
    document = {
        "namespace": {
            "objects": [],
            "execution_checks": [
                {
                    "object_id": "vstd-token",
                    "mechanism": token_asset_execution.ADAPTER,
                }
            ],
        }
    }
    options = migration.selected_refresh_options(document)
    assert options["select_token_asset"] is True
    assert options["select_emulator_control"] is False

    document["namespace"]["execution_checks"].append(
        {
            "object_id": "vstd-firmware-emulator-accounting",
            "mechanism": emulator_control_execution.ADAPTER,
        }
    )
    options = migration.selected_refresh_options(document)
    assert options["select_token_asset"] is True
    assert options["select_emulator_control"] is True

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import re

import pytest

from verifier.runtime import package_semantic_review_admission as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


def test_builtin_callable_registry_is_static_and_excludes_capability_roots() -> None:
    assert {"ValueError", "PermissionError", "len", "type"} <= review._KNOWN_BUILTINS
    assert review._DYN_BUILTINS.isdisjoint(review._KNOWN_BUILTINS)
    assert review._STDIO_BUILTINS.isdisjoint(review._KNOWN_BUILTINS)
    assert "open" not in review._KNOWN_BUILTINS


EXPECTED_PATHS = {
    "vstd-runtime-package-marker": ("src/verifier/runtime/__init__.py",),
    "vstd-namespace-rule-engine": (
        "src/verifier/runtime/namespace_classification.py",
        "src/verifier/runtime/namespace_consequences.mjs",
        "src/verifier/runtime/namespace_consequences.py",
        "src/verifier/runtime/namespace_contracts.py",
        "src/verifier/runtime/namespace_dominance.py",
        "src/verifier/runtime/namespace_refutation.py",
    ),
    "vstd-namespace-source-census": (
        "src/verifier/runtime/namespace_discovery.py",
        "src/verifier/runtime/namespace_exports.py",
        "src/verifier/runtime/namespace_html.py",
        "src/verifier/runtime/namespace_metadata.py",
        "src/verifier/runtime/namespace_source_imports.py",
        "src/verifier/runtime/namespace_svg.py",
        "src/verifier/runtime/source_declaration_inputs.py",
    ),
    "vstd-manifest-admission": (
        "src/verifier/runtime/namespace_manifest.py",
        "src/verifier/runtime/package_manifest.py",
        "src/verifier/runtime/tier_zero_manifest.py",
    ),
    "vstd-package-semantic-review-policy": (
        "src/verifier/runtime/package_api_surface_admission.py",
        "src/verifier/runtime/package_namespace_review.py",
        "src/verifier/runtime/package_original_kind_catalog.py",
        "src/verifier/runtime/package_original_kind_catalog_domains.py",
        "src/verifier/runtime/package_original_kind_catalog_experiments_hardware.py",
        "src/verifier/runtime/package_original_kind_catalog_python_apps_public_cli.py",
        "src/verifier/runtime/package_original_kind_catalog_repository_assets.py",
        "src/verifier/runtime/package_original_kind_catalog_retained.py",
        "src/verifier/runtime/package_original_kind_catalog_runtime.py",
        "src/verifier/runtime/package_original_kind_catalog_scripts_examples.py",
        "src/verifier/runtime/package_original_kind_catalog_tests_normative.py",
        "src/verifier/runtime/package_original_kind_profiles.py",
        "src/verifier/runtime/package_original_kind_review.py",
        "src/verifier/runtime/package_original_review_computation.py",
        "src/verifier/runtime/package_original_review_people.py",
        "src/verifier/runtime/package_original_review_systems.py",
        "src/verifier/runtime/package_semantic_review_admission.py",
        "src/verifier/runtime/package_semantic_review_commands.py",
        "src/verifier/runtime/package_semantic_review_core.py",
        "src/verifier/runtime/package_semantic_review_hardware_cli.py",
        "src/verifier/runtime/package_semantic_review_operations.py",
        "src/verifier/runtime/package_semantic_review_package_object.py",
        "src/verifier/runtime/package_semantic_review_partitions.py",
        "src/verifier/runtime/package_semantic_review_polish.py",
        "src/verifier/runtime/package_semantic_review_records.py",
        "src/verifier/runtime/package_semantic_review_scripts.py",
        "src/verifier/runtime/package_semantic_review_self_polish.py",
        "src/verifier/runtime/package_semantic_review_subjects.py",
        "src/verifier/runtime/package_semantic_review_verifier.py",
    ),
    "vstd-package-semantic-ownership-policy": (
        "src/verifier/runtime/package_semantic_ownership.py",
        "src/verifier/runtime/package_semantic_ownership_current_untracked.py",
        "src/verifier/runtime/package_semantic_ownership_domains.py",
        "src/verifier/runtime/package_semantic_ownership_domains_agency_collective.py",
        "src/verifier/runtime/package_semantic_ownership_domains_context.py",
        "src/verifier/runtime/package_semantic_ownership_domains_sim_model.py",
        "src/verifier/runtime/package_semantic_ownership_domains_systems.py",
        "src/verifier/runtime/package_semantic_ownership_experiments.py",
        "src/verifier/runtime/package_semantic_ownership_hardware_interop.py",
        "src/verifier/runtime/package_semantic_ownership_model.py",
        "src/verifier/runtime/package_semantic_ownership_normative_assets.py",
        "src/verifier/runtime/package_semantic_ownership_python_apps.py",
        "src/verifier/runtime/package_semantic_ownership_public_cli.py",
        "src/verifier/runtime/package_semantic_ownership_repository_assets.py",
        "src/verifier/runtime/package_semantic_ownership_scripts_examples.py",
        "src/verifier/runtime/package_semantic_ownership_tests_fixtures.py",
    ),
    "vstd-package-graph-contract": (
        "src/verifier/runtime/package_contract_coverage.py",
        "src/verifier/runtime/package_contract_profiles.py",
        "src/verifier/runtime/package_graph_representation.py",
    ),
    "vstd-package-instance-evidence": (
        "src/verifier/runtime/package_instance_evidence.py",
    ),
    "vstd-package-kind-requirements": (
        "src/verifier/runtime/package_kind_requirements.py",
    ),
    "vstd-package-obligation-candidate": (
        "src/verifier/runtime/package_obligation_candidate.py",
    ),
    "vstd-package-owner-decision": ("src/verifier/runtime/package_owner_decision.py",),
    "vstd-native-operation-metadata": (
        "src/verifier/runtime/native_operation_contracts.py",
        "src/verifier/runtime/native_operation_cli.py",
    ),
    "vstd-object-context-closure": ("src/verifier/runtime/object_context_closure.py",),
}

# (APPLIES kinds, DOES_NOT_APPLY kinds) per object.  Every other kind is
# UNRESOLVED.  The complement is only ever checked against module output.
EXPECTED_BASES = {
    "vstd-runtime-package-marker": (
        set(),
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "POLICY",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-namespace-rule-engine": (
        {"POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-namespace-source-census": (
        {"MEASUREMENT", "SENSOR", "POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ROBOT", "FINBOT"},
    ),
    "vstd-manifest-admission": (
        {"POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"},
    ),
    "vstd-package-semantic-review-policy": (
        {"POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT"},
    ),
    "vstd-package-semantic-ownership-policy": (
        {"POLICY"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-package-graph-contract": (
        {"POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-package-instance-evidence": (
        {"MEASUREMENT", "POLICY", "SENSOR"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-package-kind-requirements": (
        {"POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ROBOT", "FINBOT"},
    ),
    "vstd-package-obligation-candidate": (
        {"POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-package-owner-decision": (
        {"PROTOCOL", "POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"},
    ),
    "vstd-native-operation-metadata": (
        {"POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-object-context-closure": (
        {"POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        },
    ),
}

EXPECTED_APPLICABILITY = {object_id: applies for object_id, (applies, _) in EXPECTED_BASES.items()}

# Synthetic workspaces hold a JavaScript owned file that the Python gate cannot
# close, so the rule engine's refutations are UNRESOLVED there by design.  The census
# fixture carries one read in its acquisition file (the positive SENSOR channel), and
# the strict closure gate then withdraws its declaration-only refutations.
_SYNTHETIC_WITHDRAWN_REFUTATIONS = {
    "vstd-namespace-source-census": {"ASSET", "CONTROLLER", "MARKET"},
    "vstd-package-instance-evidence": {"ASSET", "CONTROLLER", "MARKET"},
}
SYNTHETIC_BASES = {
    object_id: (
        applies,
        set()
        if object_id == "vstd-namespace-rule-engine"
        else refuted - _SYNTHETIC_WITHDRAWN_REFUTATIONS.get(object_id, set()),
    )
    for object_id, (applies, refuted) in EXPECTED_BASES.items()
}

# Live-repository outcome of the mechanical DOES_NOT_APPLY gate.  Only the inert
# runtime marker's closure is fully visible and free of every refuted role's
# channels; every other object imports code outside the admission-owned set
# (verifier.core, subprocess, os, time, ...), so its refutations are UNRESOLVED.
# APPLIES cells are unchanged.  Synthetic workspaces use EXPECTED_BASES instead.
REAL_BASES = {
    object_id: (
        applies,
        EXPECTED_BASES[object_id][1]
        if object_id == "vstd-runtime-package-marker"
        else set(),
    )
    for object_id, (applies, _) in EXPECTED_BASES.items()
}

ACQUISITION = (
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/namespace_source_imports.py",
)
NATIVE_OPERATION_CONTRACTS = ("src/verifier/runtime/native_operation_contracts.py",)

# Role evidence defaults to every owned path; these overrides are the narrow
# establishing files named in the audit.
EXPECTED_ROLE_PATHS = {
    object_id: {kind: paths for kind in EXPECTED_APPLICABILITY[object_id]}
    for object_id, paths in EXPECTED_PATHS.items()
}
for kind in ("MEASUREMENT", "SENSOR"):
    EXPECTED_ROLE_PATHS["vstd-namespace-source-census"][kind] = ACQUISITION
# The declaration-input fingerprint measures one supplied Python file and decides no
# admission, so the census POLICY role stays on the files that select, bind and
# classify census members.
EXPECTED_ROLE_PATHS["vstd-namespace-source-census"]["POLICY"] = tuple(
    path
    for path in EXPECTED_PATHS["vstd-namespace-source-census"]
    if path != "src/verifier/runtime/source_declaration_inputs.py"
)
EXPECTED_ROLE_PATHS["vstd-native-operation-metadata"]["POLICY"] = NATIVE_OPERATION_CONTRACTS

# Declarations for the applicable kinds only: 17 APPLIES cells, 51 Tier-0 rows.
EXPECTED_DECLARATION_TOTAL = 51


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _all_obligations() -> dict[str, dict]:
    result = {}
    registry = namespace_registry()
    for kind in review.REVIEW_KINDS:
        for obligation in requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            result[obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
    return result


_READ_FIXTURE = {
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/package_instance_evidence.py",
}


def _clean_source(path: str) -> bytes:
    """A declaration-only Python module: its closure refutes every channel role."""
    if path.endswith(".mjs"):
        return ("// Synthetic fixture for " + path + "\n").encode()
    text = '"""Synthetic declaration-only fixture for ' + path + '."""\n'
    if path in _READ_FIXTURE:
        # The census and package-instance SENSOR claims need one read in their own
        # body; a bare reference is enough for the positive channel and executes
        # nothing at import.
        text += "import hashlib\n\n_READ_CHANNEL = hashlib.file_digest\n"
    return text.encode()


def _write_source(root: Path, files: dict[str, str], path: str, text: str) -> None:
    """Write exact bytes (no newline translation) and bind the digest to them."""
    raw = text.encode("utf-8")
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = _clean_source(path)
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for semantic-review tests.",
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Current source has not yet been reviewed.",
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_obligations(),
        }
    ambient = tmp_path / "src/verifier/__init__.py"
    ambient.parent.mkdir(parents=True, exist_ok=True)
    ambient.write_bytes(_clean_source("src/verifier/__init__.py"))
    return tmp_path, rows, files


def _assert_statuses(object_id: str, classification: dict, bases=SYNTHETIC_BASES) -> None:
    """Each kind has exactly its explicit basis; absence stays UNRESOLVED."""
    applies, refuted = bases[object_id]
    owned = EXPECTED_PATHS[object_id]
    for kind in review.REVIEW_KINDS:
        decision = classification[kind]
        if kind in applies:
            assert decision["status"] == "APPLIES", (object_id, kind)
            assert tuple(decision["evidence_paths"]) == (
                EXPECTED_ROLE_PATHS[object_id][kind]
            ), (object_id, kind)
        elif kind in refuted:
            assert decision["status"] == "DOES_NOT_APPLY", (object_id, kind)
            assert tuple(decision["evidence_paths"]) == owned, (object_id, kind)
        else:
            assert decision["status"] == "UNRESOLVED", (object_id, kind)
            assert tuple(decision["evidence_paths"]) == (), (object_id, kind)


def _assert_bases(object_id: str, classification: dict) -> None:
    """Status-only check for applied rows, whose evidence is a reference list."""
    applies, refuted = SYNTHETIC_BASES[object_id]
    for kind in review.REVIEW_KINDS:
        expected = (
            "APPLIES"
            if kind in applies
            else "DOES_NOT_APPLY"
            if kind in refuted
            else "UNRESOLVED"
        )
        assert classification[kind]["status"] == expected, (object_id, kind)


def test_review_document_has_exact_complete_thirteen_object_denominator():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.ADMISSION_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_PATHS) == set(EXPECTED_BASES)
    assert len(catalog) == 13
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 72
    assert (
        len({path for item in catalog.values() for path in item["owned_paths"]}) == 72
    )
    assert sum(len(item["classification"]) for item in catalog.values()) == 156
    assert (
        sum(len(item["declarations"]) for item in catalog.values())
        == EXPECTED_DECLARATION_TOTAL
    )

    for object_id, item in catalog.items():
        assert tuple(item["owned_paths"]) == EXPECTED_PATHS[object_id]
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        refuted = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert refuted == REAL_BASES[object_id][1]
        _assert_statuses(object_id, item["classification"], REAL_BASES)
        for decision in item["classification"].values():
            assert decision["reason"].strip()
        expected = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applies
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "Tier-0" in item["claim_boundary"]
        assert "behavior truth" in item["claim_boundary"]

    catalog["vstd-namespace-source-census"]["owned_paths"].clear()
    assert review.review_document()["vstd-namespace-source-census"]["owned_paths"]


def test_package_instance_evidence_review_matches_owned_effect_roles() -> None:
    instance_review = review._REVIEWS["vstd-package-instance-evidence"]
    assert set(instance_review.applicable) == {
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
    }
    assert "ACTUATOR" in instance_review.refuted
    assert "TRANSACTION" in instance_review.refuted


def test_review_paths_are_current_ordinary_repository_files():
    root = Path(__file__).resolve().parents[1]
    catalog = review.review_document()

    for object_id, expected_paths in EXPECTED_PATHS.items():
        assert tuple(catalog[object_id]["owned_paths"]) == expected_paths
        for path in expected_paths:
            candidate = root / path
            assert candidate.is_file(), path
            assert not candidate.is_symlink(), path
            assert candidate.resolve(strict=True).is_relative_to(root.resolve())


def test_role_evidence_is_narrow_and_does_not_promote_parser_or_metadata():
    catalog = review.review_document()
    census = catalog["vstd-namespace-source-census"]
    manifest = catalog["vstd-manifest-admission"]
    metadata = catalog["vstd-native-operation-metadata"]
    marker = catalog["vstd-runtime-package-marker"]

    # Census ACTUATOR and PROTOCOL have no positive channel in the cited discovery
    # body: the parser exchange is delegated to an unowned module, so no role is minted.
    for kind in ("ACTUATOR", "PROTOCOL"):
        assert census["classification"][kind]["status"] == "UNRESOLVED", kind
        assert census["classification"][kind]["evidence_paths"] == [], kind
    assert census["classification"]["TRANSACTION"]["status"] == "UNRESOLVED"
    for kind in ("MEASUREMENT", "SENSOR"):
        assert tuple(census["classification"][kind]["evidence_paths"]) == ACQUISITION
    # Manifest and native-metadata reads are checks of the artifacts they validate,
    # not observations of a phenomenon, so their MEASUREMENT and SENSOR are UNRESOLVED.
    for item in (manifest, metadata):
        for kind in ("MEASUREMENT", "SENSOR"):
            assert item["classification"][kind]["status"] == "UNRESOLVED", kind
            assert item["classification"][kind]["evidence_paths"] == []
    assert tuple(metadata["classification"]["POLICY"]["evidence_paths"]) == (
        NATIVE_OPERATION_CONTRACTS
    )
    # The marker has no applicable role; every kind is an explicit refutation over
    # its one owned file, including ROBOT and FINBOT: __init__.py holds no agent path.
    assert all(
        decision["status"] == "DOES_NOT_APPLY"
        and tuple(decision["evidence_paths"]) == EXPECTED_PATHS[
            "vstd-runtime-package-marker"
        ]
        for decision in marker["classification"].values()
    )
    assert marker["declarations"] == {}
    assert "not a sandbox" in census["claim_boundary"]
    assert "not a sandbox" in review.CLAIM_BOUNDARY
    for object_id, item in catalog.items():
        # Physical and financial roles are never APPLIES from a software-only
        # review; a DNE needs a stated local mechanism, else UNRESOLVED.
        assert item["classification"]["ROBOT"]["status"] != "APPLIES"
        assert item["classification"]["FINBOT"]["status"] != "APPLIES"
        _assert_statuses(object_id, item["classification"], REAL_BASES)


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_admission(root, rows, files)
    second = review.apply_package_semantic_review_admission(root, first, files)

    assert rows == before
    assert first == second
    assert sum(len(row["classification"]) for row in first.values()) == 156
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applies for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )
        _assert_bases(object_id, row["classification"])
        for kind, decision in row["classification"].items():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence"] == []
            elif decision["status"] == "APPLIES":
                assert tuple(ref["path"] for ref in decision["evidence"]) == (
                    EXPECTED_ROLE_PATHS[object_id][kind]
                )
            else:
                assert tuple(ref["path"] for ref in decision["evidence"]) == (
                    EXPECTED_PATHS[object_id]
                )
        for obligation_id, binding in row["obligations"].items():
            kind = obligation_id.split("-", 1)[0]
            assert (
                tuple(ref["path"] for ref in binding["evidence"])
                == (EXPECTED_ROLE_PATHS[object_id][kind])
            )


def test_apply_preserves_compatible_current_review_byte_for_byte(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    object_id = "vstd-package-owner-decision"
    expected = deepcopy(selected[object_id])

    result = review.apply_package_semantic_review_admission(root, selected, files)

    assert result[object_id] == expected


def test_unreviewed_extra_object_is_not_classified_by_catalog_complement(tmp_path):
    root, rows, files = _workspace(tmp_path)
    future = deepcopy(rows["vstd-runtime-package-marker"])
    future["object_id"] = "future-admission-object"
    future["surfaces"] = []
    rows[future["object_id"]] = future

    result = review.apply_package_semantic_review_admission(root, rows, files)

    assert result[future["object_id"]] == future
    assert {
        decision["status"] for decision in future["classification"].values()
    } == {"UNRESOLVED"}


def test_absent_refutation_is_not_inferred_from_catalog_complement(
    tmp_path, monkeypatch
):
    """A kind dropped from the explicit refuted tuple must become UNRESOLVED."""
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-namespace-rule-engine"
    catalog = dict(review._REVIEWS)
    catalog[object_id] = replace(
        catalog[object_id],
        refuted=tuple(kind for kind in catalog[object_id].refuted if kind != "MARKET"),
    )
    monkeypatch.setattr(review, "_REVIEWS", catalog)

    result = review.apply_package_semantic_review_admission(root, rows, files)

    assert result[object_id]["classification"]["MARKET"]["status"] == "UNRESOLVED"
    assert result[object_id]["classification"]["MARKET"]["evidence"] == []


def test_stale_refutation_cannot_survive_after_catalog_drops_it(
    tmp_path, monkeypatch
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    object_id = "vstd-package-semantic-ownership-policy"
    catalog = dict(review._REVIEWS)
    catalog[object_id] = replace(
        catalog[object_id],
        refuted=tuple(kind for kind in catalog[object_id].refuted if kind != "MARKET"),
    )
    monkeypatch.setattr(review, "_REVIEWS", catalog)
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-namespace-source-census"
    path = EXPECTED_PATHS[object_id][0]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        (root / path).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].remove("file:" + path)
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/extra.py")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_admission(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "stale_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "unlisted_dne",
        "forged_applies_on_unresolved",
        "forged_applies_on_refuted",
        "reason_substitution",
        "refuted_reason_substitution",
        "refuted_partial_evidence",
        "obligation_reason_substitution",
        "label_conflict",
        "object_classification_key",
        "object_specialization",
        "object_obligation",
        "unknown_obligation",
    ],
)
def test_apply_rejects_conflicting_or_partial_reviews_atomically(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    instance = selected["vstd-package-instance-evidence"]
    marker = selected["vstd-runtime-package-marker"]
    if failure == "status":
            instance["classification"]["PROTOCOL"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        instance["classification"]["POLICY"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        instance["obligations"]["POLICY-0.1-rules-and-precedence"]["declaration"][
            "scope"
        ] = ""
    elif failure == "refuted_declaration":
        marker["obligations"]["POLICY-0.1-rules-and-precedence"] = {
            "reason": "Contradictory policy declaration.",
            "evidence": deepcopy(marker["classification"]["POLICY"]["evidence"]),
            "declaration": {
                "scope": "Contradictory scope.",
                "decision_inputs": "Contradictory inputs.",
                "precedence": "Contradictory precedence.",
                "defaults": "Contradictory defaults.",
            },
        }
    elif failure == "malformed_unresolved":
        # PROTOCOL has no explicit basis for the instance-evidence object.
        instance["classification"]["PROTOCOL"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "unlisted_dne":
        # PROTOCOL is unlisted for the instance-evidence object; a forged refutation
        # is not a complement answer and must be rejected.
        instance["classification"]["PROTOCOL"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Invented from absence.",
            "evidence": deepcopy(instance["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "forged_applies_on_unresolved":
        instance["classification"]["PROTOCOL"] = {
            "status": "APPLIES",
            "reason": "Forged applicability.",
            "evidence": deepcopy(instance["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "forged_applies_on_refuted":
        # ASSET is an explicit refutation for this object; APPLIES must not replace it.
        instance["classification"]["ASSET"]["status"] = "APPLIES"
    elif failure == "reason_substitution":
        instance["classification"]["POLICY"]["reason"] = (
            "Different same-status reason."
        )
    elif failure == "refuted_reason_substitution":
        instance["classification"]["ASSET"]["reason"] = (
            "Different same-status refutation."
        )
    elif failure == "refuted_partial_evidence":
        instance["classification"]["ASSET"]["evidence"] = []
    elif failure == "obligation_reason_substitution":
        instance["obligations"]["POLICY-0.1-rules-and-precedence"][
            "reason"
        ] = "Different same-shape reason."
    elif failure == "label_conflict":
        instance["specializations"].append("ASSET")
    elif failure == "object_classification_key":
        instance["classification"]["OBJECT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Object-level label.",
            "evidence": [],
        }
    elif failure == "object_specialization":
        instance["specializations"].append("OBJECT")
    elif failure == "object_obligation":
        instance["obligations"]["OBJECT-0.1-invented"] = {
            "reason": "Object-level obligation.",
            "evidence": [],
            "declaration": {},
        }
    else:
        instance["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_apply_is_atomic_when_the_last_object_conflicts(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    last = selected["vstd-object-context-closure"]
    last["classification"]["PROTOCOL"]["status"] = "APPLIES"
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_apply_rechecks_complete_source_denominator_before_mutation(
    tmp_path, monkeypatch
):
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED_PATHS["vstd-object-context-closure"][0]
    original = review._shared._read_digest
    calls = 0

    def drifting_digest(selected_root: Path, path: str) -> str:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return "sha256:" + "a" * 64
        return value

    monkeypatch.setattr(review._shared, "_read_digest", drifting_digest)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_admission(root, rows, files)
    assert rows == before


def test_dne_reasons_cite_each_owned_source_and_avoid_absence_wording() -> None:
    """A DOES_NOT_APPLY reason names its reviewed file, never a kind template."""
    catalog = review.review_document()
    for object_id, item in catalog.items():
        basenames = {Path(path).name for path in item["owned_paths"]}
        for kind, decision in item["classification"].items():
            if decision["status"] != "DOES_NOT_APPLY":
                continue
            assert any(name in decision["reason"] for name in basenames), (object_id, kind)
            assert "separately owned" not in decision["reason"], (object_id, kind)


def test_residual_unresolved_cells_are_exactly_the_live_verified_set() -> None:
    """Verified refutations stay DOES_NOT_APPLY; every other open cell is UNRESOLVED."""
    catalog = review.review_document()
    for object_id, (_, refuted) in REAL_BASES.items():
        for kind in refuted:
            decision = catalog[object_id]["classification"][kind]
            assert decision["status"] == "DOES_NOT_APPLY", (object_id, kind)
            assert decision["evidence_paths"] == catalog[object_id]["owned_paths"]
    unresolved = {
        (object_id, kind)
        for object_id, item in catalog.items()
        for kind, decision in item["classification"].items()
        if decision["status"] == "UNRESOLVED"
    }
    expected = {
        (object_id, kind)
        for object_id, (applies, refuted) in REAL_BASES.items()
        for kind in review.REVIEW_KINDS
        if kind not in applies and kind not in refuted
    }
    assert unresolved == expected
    applies_total = sum(len(applies) for applies, _ in REAL_BASES.values())
    assert len(unresolved) == 156 - applies_total - 12
    assert all(
        catalog[object_id]["classification"][kind]["evidence_paths"] == []
        for object_id, kind in unresolved
    )


def test_legacy_generic_refutation_text_is_a_stale_verdict_that_fails_closed(
    tmp_path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    object_id = "vstd-runtime-package-marker"
    stale = deepcopy(selected)
    stale[object_id]["classification"]["LEDGER"]["reason"] = (
        "Runtime package marker does not apply as LEDGER. It has no separately "
        "owned ledger state."
    )
    before = deepcopy(stale)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, stale, files)
    assert stale == before


def test_original_kind_questions_ride_along_but_a_review_kind_cannot_go_missing(
    tmp_path,
) -> None:
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-runtime-package-marker"
    original = {
        "status": "UNRESOLVED",
        "reason": "An original-kind question this review does not own.",
        "evidence": [],
    }
    for kind in ORIGINAL_NON_OBJECT_KINDS:
        rows[object_id]["classification"][kind] = dict(original)

    result = review.apply_package_semantic_review_admission(root, rows, files)

    for kind in ORIGINAL_NON_OBJECT_KINDS:
        assert result[object_id]["classification"][kind] == original

    del rows[object_id]["classification"]["LEDGER"]
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID"):
        review.apply_package_semantic_review_admission(root, rows, files)


def test_object_label_cannot_escape_as_specialization_or_classification(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-runtime-package-marker"
    rows[object_id]["specializations"] = ["OBJECT"]
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID"):
        review.apply_package_semantic_review_admission(root, rows, files)

    rows[object_id]["specializations"] = []
    rows[object_id]["classification"]["OBJECT"] = {
        "status": "APPLIES",
        "reason": "unreviewed label",
        "evidence": [],
    }
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID"):
        review.apply_package_semantic_review_admission(root, rows, files)


def test_applicable_roles_accumulate_without_dropping_existing_specializations(
    tmp_path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-namespace-source-census"
    rows[object_id]["specializations"] = ["POLICY"]

    result = review.apply_package_semantic_review_admission(root, rows, files)

    specializations = result[object_id]["specializations"]
    assert specializations[0] == "POLICY"
    assert len(specializations) == len(set(specializations))
    assert set(specializations) == EXPECTED_APPLICABILITY[object_id] - {
        result[object_id]["kind"]
    }


def test_refutation_citing_unowned_source_fails_closed_atomically(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    object_id = "vstd-runtime-package-marker"
    selected[object_id]["classification"]["LEDGER"]["evidence"].append(
        {
            "path": "src/verifier/runtime/namespace_manifest.py",
            "sha256": "sha256:" + "0" * 64,
        }
    )
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


_PROCESS_NETWORK_ROOTS = {
    "subprocess", "socket", "urllib", "http", "requests", "httpx", "aiohttp",
    "multiprocessing", "ctypes",
}
_PROCESS_NETWORK_LAST = {
    "Popen", "urlopen", "create_connection", "create_subprocess_exec",
    "create_subprocess_shell",
}
_PATH_WRITE_METHODS = {"write_bytes", "write_text", "mkdir", "unlink", "rmdir", "touch"}
_OS_WRITE_CALLS = {
    "os.replace", "os.rename", "os.remove", "os.unlink", "os.makedirs", "os.mkdir",
}
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")
_JS_PROCESS_OR_WRITE = re.compile(
    r"child_process|\bspawn\(|\bexec\(|\bfetch\(|require\(['\"](?:http|https|net|child_process)['\"]\)"
    r"|fs\.(?:write|append|mkdir|unlink|rm)|writeFile"
)


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    func = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _mode_argument(node: ast.Call, *, position: int) -> str:
    for keyword in node.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    if len(node.args) > position and isinstance(node.args[position], ast.Constant):
        return str(node.args[position].value)
    return ""


def _is_builtin_open(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == "open"


def _is_method_open(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and _call_name(node) != "os.open"
    )


def _writes(mode: str) -> bool:
    return any(char in mode for char in "wax+")


def _flags_text(tree: ast.Module, source: str, node: ast.Call) -> str:
    """Return the source text of an os.open flags argument, following local names."""
    if len(node.args) < 2:
        return ""
    flags = node.args[1]
    if not isinstance(flags, ast.Name):
        return ast.get_source_segment(source, flags) or ""
    texts = []
    for item in ast.walk(tree):
        if isinstance(item, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == flags.id
            for target in item.targets
        ):
            texts.append(ast.get_source_segment(source, item.value) or "")
    return " ".join(texts)


def _scan_python_effects(path: Path) -> dict[str, list[str]]:
    """Find process, network, and write call sites in one owned file's own body."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    found: dict[str, list[str]] = {"process_network": [], "write": []}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        parts = name.split(".")
        if (
            parts[0] in _PROCESS_NETWORK_ROOTS
            or parts[-1] in _PROCESS_NETWORK_LAST
            or name in {"os.system", "os.popen"}
            or name.startswith(("os.spawn", "os.exec"))
        ):
            found["process_network"].append(f"{name}:{node.lineno}")
        if parts[-1] in _PATH_WRITE_METHODS or name in _OS_WRITE_CALLS or parts[0] == "shutil":
            found["write"].append(f"{name}:{node.lineno}")
        elif _is_builtin_open(node) and _writes(_mode_argument(node, position=1)):
            found["write"].append(f"{name}:{node.lineno}")
        elif _is_method_open(node) and _writes(_mode_argument(node, position=0)):
            found["write"].append(f"{name}:{node.lineno}")
        elif name == "os.open" and any(token in _flags_text(tree, source, node) for token in _WRITE_FLAGS):
            found["write"].append(f"{name}:{node.lineno}")
    return found


def _scan_owned(root: Path, paths: tuple[str, ...] | list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"process_network": [], "write": []}
    for path in paths:
        target = root / path
        if target.suffix == ".mjs":
            if _JS_PROCESS_OR_WRITE.search(target.read_text(encoding="utf-8")):
                found["process_network"].append(path)
            continue
        for key, values in _scan_python_effects(target).items():
            found[key].extend(f"{path}:{value}" for value in values)
    return found


def test_refuted_actuator_and_protocol_denials_have_no_owned_body_counterexample() -> None:
    """A DOES_NOT_APPLY ACTUATOR/PROTOCOL claim must survive a body-level call scan."""
    root = Path(__file__).resolve().parents[1]
    for object_id, item in review.review_document().items():
        classification = item["classification"]
        if classification["ACTUATOR"]["status"] == "DOES_NOT_APPLY":
            found = _scan_owned(root, item["owned_paths"])
            assert found == {"process_network": [], "write": []}, (object_id, found)
        if classification["PROTOCOL"]["status"] == "DOES_NOT_APPLY":
            found = _scan_owned(root, item["owned_paths"])
            assert found["process_network"] == [], (object_id, found)


def test_transaction_on_pure_evaluator_cannot_be_forged_as_applies(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    rule = selected["vstd-namespace-rule-engine"]
    assert rule["classification"]["TRANSACTION"]["status"] == "UNRESOLVED"
    rule["classification"]["TRANSACTION"] = {
        "status": "APPLIES",
        "reason": "Forged commit boundary on a pure rule evaluator.",
        "evidence": deepcopy(rule["classification"]["POLICY"]["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_unresolved_transaction_is_rewritten_to_the_canonical_reason(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    manifest = selected["vstd-manifest-admission"]
    manifest["classification"]["TRANSACTION"]["reason"] = "Forged commit reason."

    result = review.apply_package_semantic_review_admission(root, selected, files)

    assert result["vstd-manifest-admission"]["classification"]["TRANSACTION"] == {
        "status": "UNRESOLVED",
        "reason": review._shared._unresolved_reason("TRANSACTION"),
        "evidence": [],
    }


def test_unresolved_protocol_cannot_be_forged_as_refuted(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    context = selected["vstd-object-context-closure"]
    context["classification"]["PROTOCOL"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Invented from absence.",
        "evidence": deepcopy(context["classification"]["POLICY"]["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_invoked_rechecker_is_a_dispatcher_not_an_actuator(tmp_path) -> None:
    """Selected in-process rechecker calls dispatch another artifact's checks.

    The closure has no write or process channel in its own body, so the former
    ACTUATOR claim is withdrawn to UNRESOLVED, and a forged APPLIES is rejected.
    """
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    context = selected["vstd-object-context-closure"]
    decision = context["classification"]["ACTUATOR"]
    assert decision["status"] == "UNRESOLVED"
    assert decision["evidence"] == []
    context["classification"]["ACTUATOR"] = {
        "status": "APPLIES",
        "reason": "Forged command boundary over selected rechecker calls.",
        "evidence": [
            {
                "path": "src/verifier/runtime/object_context_closure.py",
                "sha256": files["src/verifier/runtime/object_context_closure.py"],
            }
        ],
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_effect_scanner_flags_real_calls_and_ignores_data_and_read_flags(tmp_path: Path) -> None:
    """Good and bad fixtures: the scanner must catch real calls, never strings or reads."""
    bad = tmp_path / "bad.py"
    bad.write_text(
        "import subprocess, os\n"
        "subprocess.run(['x'])\n"
        "Path('a').write_text('b')\n"
        "open('f', 'w')\n"
        "flags = os.O_WRONLY | os.O_CREAT\n"
        "os.open('f', flags)\n"
        "Path('p').open('xb')\n",
        encoding="utf-8",
    )
    good = tmp_path / "good.py"
    good.write_text(
        "import os\n"
        "DATA = 'subprocess.run(...) and path.write_bytes(...) are text'\n"
        "flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)\n"
        "os.open('f', flags)\n"
        "with Path('f').open('rb') as stream:\n"
        "    stream.read()\n",
        encoding="utf-8",
    )

    found_bad = _scan_python_effects(bad)
    assert found_bad["process_network"] == ["subprocess.run:2"]
    assert sorted(entry.rsplit(":", 1)[0] for entry in found_bad["write"]) == [
        "open",
        "open",
        "os.open",
        "write_text",
    ]
    assert _scan_python_effects(good) == {"process_network": [], "write": []}


MARKER = "vstd-runtime-package-marker"
MARKER_PATH = "src/verifier/runtime/__init__.py"
MARKER_REFUTED = set(EXPECTED_BASES[MARKER][1])
KIND_REQUIREMENTS = "vstd-package-kind-requirements"
KIND_REQUIREMENTS_PATH = "src/verifier/runtime/package_kind_requirements.py"
NAMESPACE_DISCOVERY_PATH = "src/verifier/runtime/namespace_discovery.py"
OWNERSHIP_POLICY = "vstd-package-semantic-ownership-policy"
OWNERSHIP_CLI_PATH = "src/verifier/runtime/package_semantic_ownership_public_cli.py"
OWNERSHIP_REFUTED = set(EXPECTED_BASES[OWNERSHIP_POLICY][1])
# A closed effect-free pure module keeps every catalog refutation; each channel
# below removes exactly the refutations whose role it touches.
WRITE_CHANNEL_SURVIVORS = {"MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"}


def _classification(root, rows, files, object_id: str) -> dict:
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    return selected[object_id]["classification"]


def _dne_kinds(classification: dict) -> set[str]:
    return {
        kind
        for kind, decision in classification.items()
        if decision["status"] == "DOES_NOT_APPLY"
    }


@pytest.mark.parametrize(
    "text",
    [
        "import importlib\n_LOADER = importlib.import_module('subprocess')\n",
        "_VALUE = __import__('subprocess')\n",
        "_VALUE = getattr(object, '__class__')\n",
        "def run(callback):\n    return callback()\n",
        "_HANDLERS = {}\n\n\ndef run(name):\n    return _HANDLERS[name]()\n",
        "from importlib import import_module as load\n\n\ndef run(name):\n    return load(name)\n",
    ],
    ids=["import_module", "dunder_import", "getattr", "callback_parameter", "table_dispatch", "aliased_dynamic_import"],
)
def test_dynamic_dispatch_downgrades_every_refutation_of_the_object(tmp_path, text):
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, MARKER_PATH, text)

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == set()
    assert {classification[kind]["status"] for kind in MARKER_REFUTED} == {"UNRESOLVED"}


def test_strings_and_docstrings_name_effects_without_counting_as_effects(tmp_path):
    """Referent text such as subprocess.run in prose is data, not an executed channel."""
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        MARKER_PATH,
        '"""Mentions subprocess.run([]) and path.write_text(x) as prose."""\n'
        '__all__ = ("subprocess.run",)\n',
    )

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == MARKER_REFUTED


@pytest.mark.parametrize(
    "text",
    [
        "import json as codec\n\n\ndef save(payload, handle):\n    codec.dump(payload, handle)\n",
        "from pathlib import Path as Pth\n\n\ndef save(text):\n    Pth('out.txt').write_text(text)\n",
    ],
    ids=["module_alias_full_name", "symbol_alias_method"],
)
def test_aliased_writer_is_a_write_channel_for_every_writing_role(tmp_path, text):
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, MARKER_PATH, text)

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == WRITE_CHANNEL_SURVIVORS


def test_reference_alias_of_a_method_is_an_opaque_callee(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        MARKER_PATH,
        "from pathlib import Path\n\n\ndef save(text):\n"
        "    writer = Path('out.txt').write_text\n    writer(text)\n",
    )

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == set()


def test_imported_effect_from_a_sibling_owned_module_is_transitive(tmp_path):
    """An object inherits the write channel of an owned module it imports."""
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        KIND_REQUIREMENTS_PATH,
        "from verifier.runtime import namespace_discovery\n\n__all__ = ()\n",
    )
    clean = _classification(root, deepcopy(rows), files, KIND_REQUIREMENTS)
    assert clean["LEDGER"]["status"] == "DOES_NOT_APPLY"
    assert clean["ROBOT"]["status"] == "DOES_NOT_APPLY"

    # The census SENSOR primary keeps its own read, so only the transitive write varies.
    _write_source(
        root,
        files,
        NAMESPACE_DISCOVERY_PATH,
        "from pathlib import Path\nimport hashlib\n\n_READ_CHANNEL = hashlib.file_digest\n\n\n"
        "def publish(text):\n    Path('report.txt').write_text(text)\n",
    )
    dirty = _classification(root, deepcopy(rows), files, KIND_REQUIREMENTS)

    assert dirty["LEDGER"]["status"] == "UNRESOLVED"
    assert dirty["ROBOT"]["status"] == "UNRESOLVED"
    assert dirty["ASSET"]["status"] == "UNRESOLVED"
    # APPLIES cells are never altered by the gate, even with a dirty closure.
    assert dirty["POLICY"]["status"] == "APPLIES"


@pytest.mark.parametrize(
    "text",
    [
        "from verifier.core import namespace\n\n__all__ = ()\n",
        "import subprocess\n\n__all__ = ()\n",
    ],
    ids=["verifier_core_import", "stdlib_process_import"],
)
def test_import_outside_the_admission_denominator_is_an_open_boundary(tmp_path, text):
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, KIND_REQUIREMENTS_PATH, text)

    classification = _classification(root, rows, files, KIND_REQUIREMENTS)

    assert _dne_kinds(classification) == set()


def test_role_accumulation_downgrades_only_the_roles_a_sibling_touches(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        OWNERSHIP_CLI_PATH,
        'def announce():\n    print("ready")\n',
    )

    classification = _classification(root, rows, files, OWNERSHIP_POLICY)

    assert _dne_kinds(classification) == {
        "LEDGER",
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
    }
    assert classification["PROTOCOL"]["status"] == "UNRESOLVED"
    assert classification["ASSET"]["status"] == "UNRESOLVED"
    assert OWNERSHIP_REFUTED - _dne_kinds(classification) == {
        "PROTOCOL",
        "ROBOT",
        "FINBOT",
        "ASSET",
        "MARKET",
        "CONTROLLER",
    }


def test_inert_label_is_not_an_escape_for_semantic_only_roles(tmp_path):
    """Executed top-level code breaks the observed declaration-only shape."""
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, MARKER_PATH, "print('side effect')\n")

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == {
        "ACTUATOR",
        "LEDGER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    }
    for kind in ("ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"):
        assert classification[kind]["status"] == "UNRESOLVED", kind


def test_javascript_owned_source_is_an_open_boundary_for_its_object(tmp_path):
    root, rows, files = _workspace(tmp_path)

    classification = _classification(root, rows, files, "vstd-namespace-rule-engine")

    assert _dne_kinds(classification) == set()


def test_stored_refutation_that_fails_the_gate_aborts_atomically(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    _write_source(
        root,
        files,
        MARKER_PATH,
        "import importlib\n_LOADER = importlib.import_module('x')\n",
    )
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_refutation_reason_copied_from_another_object_is_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    foreign = selected[OWNERSHIP_POLICY]["classification"]["ACTUATOR"]["reason"]
    selected[MARKER]["classification"]["ACTUATOR"]["reason"] = foreign
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_refutation_citing_a_neighbours_source_fails_the_catalog_check(monkeypatch):
    monkeypatch.setitem(
        review._DNE_BASES[MARKER],
        "ROBOT",
        "namespace_discovery.py reads source members and connects no agent.",
    )

    with pytest.raises(AssertionError, match="cites no or a foreign source"):
        review._catalog_check()


def test_gate_never_removes_or_creates_applies(tmp_path):
    root, rows, files = _workspace(tmp_path)
    context = "vstd-object-context-closure"
    _write_source(
        root,
        files,
        "src/verifier/runtime/object_context_closure.py",
        "import importlib\n_LOADER = importlib.import_module('x')\n",
    )

    classification = _classification(root, rows, files, context)

    applies = {kind for kind, d in classification.items() if d["status"] == "APPLIES"}
    assert applies == EXPECTED_APPLICABILITY[context]


def test_source_change_after_gate_analysis_is_rejected(tmp_path, monkeypatch):
    root, rows, files = _workspace(tmp_path)
    original = review._read_source
    reads = {"count": 0}

    def drifting(selected_root, path):
        value = original(selected_root, path)
        if path == MARKER_PATH:
            reads["count"] += 1
            if reads["count"] == 2:
                return (value or b"") + b"# concurrent edit\n"
        return value

    monkeypatch.setattr(review, "_read_source", drifting)
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_admission(root, rows, files)
    assert rows == before


def test_unreadable_sources_downgrade_refutations_instead_of_asserting(tmp_path):
    document = review.review_document(tmp_path)

    for object_id, item in document.items():
        statuses = {decision["status"] for decision in item["classification"].values()}
        assert "DOES_NOT_APPLY" not in statuses, object_id


def test_module_level_alias_of_a_builtin_writer_is_a_channel_when_referenced(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, MARKER_PATH, "_OPENER = open\n")

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == {"POLICY", "PROTOCOL"}


def test_module_level_bound_method_is_a_channel(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        MARKER_PATH,
        "from pathlib import Path\n\n_WRITER = Path('out.txt').write_text\n",
    )

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == WRITE_CHANNEL_SURVIVORS


def test_read_mode_open_is_a_read_channel_not_a_write_channel(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        MARKER_PATH,
        "def load(path):\n    with open(path, 'rb') as stream:\n        return stream.read()\n",
    )

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == MARKER_REFUTED - {
        "SENSOR",
        "MEASUREMENT",
        "ASSET",
        "MARKET",
        "CONTROLLER",
    }


def test_method_passed_as_a_value_is_a_channel(tmp_path):
    root, rows, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        MARKER_PATH,
        "from pathlib import Path\n\n\ndef clear(paths):\n"
        "    return list(map(Path.unlink, paths))\n",
    )

    classification = _classification(root, rows, files, MARKER)

    assert _dne_kinds(classification) == WRITE_CHANNEL_SURVIVORS


CENSUS = "vstd-namespace-source-census"
DISCOVERY_PATH = "src/verifier/runtime/namespace_discovery.py"
SIBLING_HTML_PATH = "src/verifier/runtime/namespace_html.py"
OWNER = "vstd-package-owner-decision"
OWNER_PATH = "src/verifier/runtime/package_owner_decision.py"


@pytest.mark.parametrize(
    "text, applies",
    [
        ('"""Reads members with read_bytes() and hashlib.file_digest in prose."""\n', False),
        ("# hashlib.file_digest(handle) would read here\n_DOC = 'path.read_bytes()'\n", False),
        ("import hashlib\n\n_READ_CHANNEL = hashlib.file_digest\n", True),
    ],
    ids=["docstring_only", "comment_and_string_only", "executed_read_reference"],
)
def test_sensor_claim_needs_a_read_channel_in_its_own_body(tmp_path, text, applies) -> None:
    """Strings, comments, and docstrings are data; only a real read supports SENSOR."""
    root, rows, files = _workspace(tmp_path)
    _write_source(root, files, DISCOVERY_PATH, text)

    classification = review.review_document(root)[CENSUS]["classification"]

    expected = "APPLIES" if applies else "UNRESOLVED"
    assert classification["SENSOR"]["status"] == expected
    assert classification["MEASUREMENT"]["status"] == expected
    assert classification["POLICY"]["status"] == "APPLIES"
    if applies:
        assert tuple(classification["SENSOR"]["evidence_paths"]) == ACQUISITION
    else:
        assert classification["SENSOR"]["evidence_paths"] == []
        assert classification["MEASUREMENT"]["evidence_paths"] == []
        # SENSOR is the census primary kind, so an unsupported primary is a mislabel.
        with pytest.raises(
            ValueError, match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + CENSUS + ":SENSOR"
        ):
            review.apply_package_semantic_review_admission(root, rows, files)


def test_inserted_process_call_in_a_sibling_never_creates_a_cited_role(tmp_path) -> None:
    """Positive-effect insertion into an uncited file mints no PROTOCOL or ACTUATOR."""
    root, _, files = _workspace(tmp_path)
    _write_source(
        root,
        files,
        SIBLING_HTML_PATH,
        'import subprocess\n\n\ndef run():\n    subprocess.run(["x"])\n',
    )

    classification = review.review_document(root)[CENSUS]["classification"]

    for kind in ("PROTOCOL", "ACTUATOR"):
        assert classification[kind]["status"] == "UNRESOLVED", kind
        assert classification[kind]["evidence_paths"] == [], kind
    assert classification["SENSOR"]["status"] == "APPLIES"
    assert tuple(classification["SENSOR"]["evidence_paths"]) == ACQUISITION


def test_analysis_scope_reanalyses_only_changed_bytes_within_one_command(
    tmp_path, monkeypatch
) -> None:
    """One polish command reruns this review once per stale label the stage must hide.

    Inside ``analysis_scope`` each file is analysed once per exact bytes, so a rerun parses
    nothing; a changed byte is analysed again and moves the verdict.  Outside a scope every
    call analyses afresh, and nothing outlives the scope.
    """
    root, _, files = _workspace(tmp_path)
    analysed: list[tuple[str, str]] = []
    scan, positives = review._scan_source, review._positive_channels

    def counted_scan(path, raw, denominator):
        analysed.append(("scan", path))
        return scan(path, raw, denominator)

    def counted_positives(path, raw):
        analysed.append(("positives", path))
        return positives(path, raw)

    monkeypatch.setattr(review, "_scan_source", counted_scan)
    monkeypatch.setattr(review, "_positive_channels", counted_positives)
    expected = review.review_document(root)
    every_file = sorted(analysed)
    analysed.clear()
    assert review.review_document(root) == expected
    assert sorted(analysed) == every_file

    with review.analysis_scope():
        analysed.clear()
        assert review.review_document(root) == expected
        assert sorted(analysed) == every_file
        analysed.clear()
        assert review.review_document(root) == expected
        assert analysed == []
        _write_source(
            root,
            files,
            DISCOVERY_PATH,
            '"""Reads members with read_bytes() and hashlib.file_digest in prose."""\n',
        )
        changed = review.review_document(root)
        assert sorted(analysed) == [("positives", DISCOVERY_PATH), ("scan", DISCOVERY_PATH)]

    assert expected[CENSUS]["classification"]["SENSOR"]["status"] == "APPLIES"
    assert changed[CENSUS]["classification"]["SENSOR"]["status"] == "UNRESOLVED"
    analysed.clear()
    assert review.review_document(root) == changed
    assert sorted(analysed) == every_file


def test_stale_applies_on_a_withdrawn_cell_aborts_atomically(tmp_path) -> None:
    """A stored APPLIES that the audit withdrew is a conflict, never a kept verdict."""
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_admission(root, rows, files)
    manifest = selected["vstd-manifest-admission"]
    manifest["classification"]["MEASUREMENT"] = {
        "status": "APPLIES",
        "reason": "Stale manifest observation.",
        "evidence": deepcopy(manifest["classification"]["POLICY"]["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-manifest-admission:MEASUREMENT",
    ):
        review.apply_package_semantic_review_admission(root, selected, files)
    assert selected == before


def test_withdrawn_label_in_specializations_is_a_label_conflict(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows[CENSUS]["specializations"] = ["PROTOCOL"]

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + CENSUS + ":PROTOCOL"
    ):
        review.apply_package_semantic_review_admission(root, rows, files)


def test_branch_only_policy_check_supports_policy_but_never_execution() -> None:
    """A rule check is policy checking; it is not a write, process, or read channel."""
    text = "def admit(value):\n    if value < 0:\n        raise ValueError('refused')\n    return value\n"
    positives = {"p.py": review._positive_channels("p.py", text.encode())}

    assert positives["p.py"] == frozenset()
    assert review._positively_supported("POLICY", ("p.py",), positives)
    assert not review._positively_supported("ACTUATOR", ("p.py",), positives)
    assert not review._positively_supported("SENSOR", ("p.py",), positives)
    assert not review._positively_supported("PROTOCOL", ("p.py",), positives)


def test_simulated_label_does_not_exempt_a_real_process_channel() -> None:
    """A simulation label is text; a real subprocess call in code still counts."""
    simulated = (
        '"""SIMULATED endpoint: no real device, labelled as a simulation."""\n'
        "import subprocess\n\n\ndef send(command):\n    return subprocess.run(command)\n"
    )
    positives = {"p.py": review._positive_channels("p.py", simulated.encode())}
    assert "PROC" in positives["p.py"]
    assert review._positively_supported("ACTUATOR", ("p.py",), positives)
    assert review._positively_supported("PROTOCOL", ("p.py",), positives)

    named_only = '"""run subprocess.run(...) and socket.connect here, in prose only."""\n'
    prose = {"p.py": review._positive_channels("p.py", named_only.encode())}
    assert prose["p.py"] == frozenset()
    assert not review._positively_supported("ACTUATOR", ("p.py",), prose)


def test_dynamic_dispatch_establishes_no_subject_actuator() -> None:
    """A callable chosen at runtime names no write or process endpoint."""
    text = (
        "_HANDLERS = {}\n\n\ndef run(name, value):\n"
        "    return _HANDLERS[name](value)\n\n\ndef invoke(obj, attr):\n"
        "    return getattr(obj, attr)()\n"
    )
    positives = {"p.py": review._positive_channels("p.py", text.encode())}

    assert "PROC" not in positives["p.py"]
    assert "WRITE" not in positives["p.py"]
    assert not review._positively_supported("ACTUATOR", ("p.py",), positives)


def test_read_only_observation_is_not_a_write_or_transaction() -> None:
    read_only = "def load(p):\n    with open(p, 'rb') as stream:\n        return stream.read()\n"
    writer = "def store(p, raw):\n    with open(p, 'wb') as stream:\n        stream.write(raw)\n"
    reads = {"r.py": review._positive_channels("r.py", read_only.encode())}
    writes = {"w.py": review._positive_channels("w.py", writer.encode())}

    assert reads["r.py"] == frozenset({"READ"})
    assert review._positively_supported("SENSOR", ("r.py",), reads)
    assert not review._positively_supported("ACTUATOR", ("r.py",), reads)
    assert writes["w.py"] == frozenset({"WRITE"})
    assert review._positively_supported("ACTUATOR", ("w.py",), writes)
    assert not review._positively_supported("SENSOR", ("w.py",), writes)


def test_live_catalog_has_a_positive_channel_for_every_applies_cell_but_one() -> None:
    """Every APPLIES cell in the catalog is backed by its cited body, except the residual."""
    root = Path(__file__).resolve().parents[1]
    sources = review._read_sources(root)
    positives = {
        path: review._positive_channels(path, raw)
        for path, raw in sources.items()
        if raw is not None
    }
    unsupported = {
        (object_id, kind)
        for object_id, catalog_review in review._REVIEWS.items()
        for kind in catalog_review.applicable
        if not review._positively_supported(kind, catalog_review.role_paths[kind], positives)
    }

    assert unsupported == set(review._PRIMARY_LABEL_RESIDUALS)


def test_owner_protocol_primary_label_is_a_reported_residual() -> None:
    """Owner PROTOCOL is the primary kind; its cited body has no process exchange.

    It stays APPLIES here because withdrawing a primary kind makes every apply raise a
    label conflict.  The residual is reported, not treated as established.
    """
    catalog = review.review_document()
    assert catalog[OWNER]["primary_kind"] == "PROTOCOL"
    assert catalog[OWNER]["classification"]["PROTOCOL"]["status"] == "APPLIES"
    raw = (Path(__file__).resolve().parents[1] / OWNER_PATH).read_bytes()
    assert "PROC" not in review._positive_channels(OWNER_PATH, raw)

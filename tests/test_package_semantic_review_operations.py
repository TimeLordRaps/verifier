# Terminology: abstract syntax tree (AST); identifier (ID).
from __future__ import annotations

import ast
import dataclasses
import re
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_operations as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS


EXPECTED_APPLICABILITY = {
    "vstd-claim-garden-lifecycle": {"PROTOCOL", "TRANSACTION"},
    "vstd-controlled-emission-controller": {
        "CONTROLLER",
        "POLICY",
        "TRANSACTION",
    },
    "vstd-core-mechanism-executor": {"TRANSACTION", "POLICY"},
    "vstd-core-provenance-sensor": {
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
    },
    "vstd-core-receipt-transaction": {"TRANSACTION"},
    "vstd-digest-validation-policy": {"POLICY", "CONTROLLER", "PROTOCOL"},
    "vstd-finite-record-issuance": {
        "LEDGER",
        "TRANSACTION",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-gate-pipeline-controller": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "CONTROLLER",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-gated-publication": {"PROTOCOL", "TRANSACTION"},
    "vstd-javascript-parser-protocol": {"PROTOCOL"},
    "vstd-package-worker-exchange": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
    },
    "vstd-permission-slot-controller": {
        "CONTROLLER",
        "LEDGER",
        "POLICY",
        "PROTOCOL",
        "TRANSACTION",
    },
    "vstd-policy-enforcement-engine": {"POLICY", "PROTOCOL"},
    "vstd-polish-workflow-transaction": {
        "TRANSACTION",
        "CONTROLLER",
        "LEDGER",
        "POLICY",
        "PROTOCOL",
    },
    "vstd-sim-artifact-publication": {"PROTOCOL", "TRANSACTION"},
    "vstd-systems-parser-protocol": {"PROTOCOL"},
    "vstd-train-control-session": {
        "CONTROLLER",
        "LEDGER",
        "POLICY",
        "TRANSACTION",
    },
    "vstd-transaction-execution-coordinator": {"POLICY", "PROTOCOL", "TRANSACTION"},
    "vstd-workflow-parser-protocol": {"PROTOCOL"},
}

# Independent literal oracle for the explicit refutation catalog.  Counts are
# typed here rather than derived from the module's complement of applicability.
# Repaired by the source audit: a refutation whose owned source contradicts it or
# whose verdict is UNKNOWN is migrated to UNRESOLVED, never kept as an exemption.
EXPECTED_REFUTED_COUNT = {
    "vstd-claim-garden-lifecycle": 8,
    "vstd-controlled-emission-controller": 7,
    "vstd-core-mechanism-executor": 8,
    "vstd-core-provenance-sensor": 8,
    "vstd-core-receipt-transaction": 9,
    "vstd-digest-validation-policy": 9,
    "vstd-finite-record-issuance": 8,
    "vstd-gate-pipeline-controller": 5,
    "vstd-gated-publication": 8,
    "vstd-javascript-parser-protocol": 10,
    "vstd-package-worker-exchange": 3,
    "vstd-permission-slot-controller": 4,
    # The standalone current-source audit lists roles only; every other added kind is
    # unlisted (UNRESOLVED), so these two rows carry no explicit refutation.
    "vstd-policy-enforcement-engine": 0,
    "vstd-polish-workflow-transaction": 5,
    "vstd-sim-artifact-publication": 9,
    "vstd-systems-parser-protocol": 9,
    "vstd-train-control-session": 5,
    "vstd-transaction-execution-coordinator": 0,
    "vstd-workflow-parser-protocol": 10,
}

# Kinds with no explicit basis at all.  Each is the canonical UNRESOLVED.
EXPECTED_UNLISTED = {
    "vstd-claim-garden-lifecycle": ("ACTUATOR", "POLICY"),
    "vstd-controlled-emission-controller": ("ACTUATOR", "PROTOCOL"),
    "vstd-core-mechanism-executor": ("ACTUATOR", "PROTOCOL"),
    "vstd-core-provenance-sensor": ("ACTUATOR",),
    "vstd-core-receipt-transaction": ("ACTUATOR", "PROTOCOL"),
    "vstd-gated-publication": ("ACTUATOR", "POLICY"),
    "vstd-gate-pipeline-controller": ("ACTUATOR",),
    "vstd-javascript-parser-protocol": ("ACTUATOR",),
    "vstd-package-worker-exchange": ("ASSET", "CONTROLLER", "LEDGER", "POLICY"),
    "vstd-permission-slot-controller": ("ACTUATOR", "ASSET", "MEASUREMENT"),
    "vstd-policy-enforcement-engine": (
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "ROBOT",
        "SENSOR",
        "TRANSACTION",
    ),
    "vstd-polish-workflow-transaction": ("ACTUATOR", "MEASUREMENT"),
    "vstd-sim-artifact-publication": ("ACTUATOR",),
    "vstd-systems-parser-protocol": ("ACTUATOR", "SENSOR"),
    "vstd-train-control-session": ("ACTUATOR", "PROTOCOL", "ROBOT"),
    "vstd-transaction-execution-coordinator": (
        "ACTUATOR",
        "ASSET",
        "CONTROLLER",
        "FINBOT",
        "LEDGER",
        "MARKET",
        "MEASUREMENT",
        "ROBOT",
        "SENSOR",
    ),
    "vstd-workflow-parser-protocol": ("ACTUATOR",),
}

# Objects reviewed from the standalone current-source audit: roles only, nothing refuted.
# Every non-role kind (including ROBOT and FINBOT) stays the canonical UNRESOLVED.
UNLISTED_ONLY_OBJECTS = frozenset(
    {"vstd-policy-enforcement-engine", "vstd-transaction-execution-coordinator"}
)

CANONICAL_UNRESOLVED_REASON = (
    "Migration retains this applicability question. Static ownership alone cannot "
    "refute a {kind} role."
)

# Simulated ACTUATOR/MEASUREMENT mechanism launched as a child by package_execution.
EMULATOR_EXECUTION_PATHS = (
    "src/verifier/runtime/emulator_control_execution.py",
    "src/verifier/runtime/emulator_control_worker.py",
)


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


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows = {}
    files = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (object_id + "\0" + path + "\n").encode()
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
    return tmp_path, rows, files


def test_review_document_is_complete_exact_and_defensive():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.OPERATIONS_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_APPLICABILITY)
    assert len(catalog) == 19
    assert sum(len(row["classification"]) for row in catalog.values()) == 228
    assert sum(len(row["declarations"]) for row in catalog.values()) == 165

    totals = {"APPLIES": 0, "DOES_NOT_APPLY": 0, "UNRESOLVED": 0}
    for object_id, item in catalog.items():
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
        unresolved = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "UNRESOLVED"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert len(refuted) == EXPECTED_REFUTED_COUNT[object_id]
        assert unresolved == set(EXPECTED_UNLISTED.get(object_id, ()))
        for kind, decision in item["classification"].items():
            totals[decision["status"]] += 1
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert decision["reason"] == CANONICAL_UNRESOLVED_REASON.format(
                    kind=kind
                )
            else:
                assert decision["reason"].strip()
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(item["owned_paths"])
        assert len(item["owned_paths"]) == len(set(item["owned_paths"]))
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
        assert "Tier-1-plus" in item["claim_boundary"]
    assert totals == {"APPLIES": 55, "DOES_NOT_APPLY": 125, "UNRESOLVED": 48}

    catalog["vstd-claim-garden-lifecycle"]["owned_paths"].clear()
    assert review.review_document()["vstd-claim-garden-lifecycle"]["owned_paths"]


def test_review_matches_exact_semantic_ownership_partition():
    catalog = review.review_document()
    ownership = {
        spec.object_id: spec
        for spec in SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id in catalog
    }

    assert set(ownership) == set(catalog)
    for object_id, item in catalog.items():
        spec = ownership[object_id]
        assert item["primary_kind"] == spec.primary_kind
        assert item["owned_paths"] == list(spec.owned_paths)
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        } == {
            kind
            for kind in (spec.primary_kind, *spec.specializations)
            if kind in review.REVIEW_KINDS
        }


def test_core_splits_keep_callbacks_observation_and_publication_distinct() -> None:
    catalog = review.review_document()
    executor = catalog["vstd-core-mechanism-executor"]
    assert executor["primary_kind"] == "VERIFIER"
    assert len(executor["owned_paths"]) == 7
    assert executor["classification"]["ACTUATOR"]["status"] == "UNRESOLVED"
    assert executor["classification"]["ACTUATOR"]["evidence_paths"] == []
    assert "not confinement" in executor["classification"]["ROBOT"]["reason"]

    provenance = catalog["vstd-core-provenance-sensor"]
    assert provenance["classification"]["SENSOR"]["status"] == "APPLIES"
    assert provenance["classification"]["MEASUREMENT"]["status"] == "APPLIES"
    assert provenance["classification"]["PROTOCOL"]["status"] == "APPLIES"
    assert (
        "host-visible software acquisition"
        in provenance["declarations"]["MEASUREMENT-0.1-phenomenon-and-method"][
            "observation_vs_estimate"
        ]
    )

    receipt = catalog["vstd-core-receipt-transaction"]
    assert receipt["classification"]["TRANSACTION"]["status"] == "APPLIES"
    assert (
        "no atomic group commit"
        in receipt["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )


def test_finite_record_review_never_expands_to_full_package_polish() -> None:
    item = review.review_document()["vstd-finite-record-issuance"]
    assert item["primary_kind"] == "TRANSACTION"
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "APPLIES"
    } == {"LEDGER", "TRANSACTION", "PROTOCOL", "POLICY"}
    assert (
        "no full-application claim"
        in item["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert (
        "polished or full-application PASS"
        in item["declarations"]["POLICY-0.3-enforcement-and-decisions"][
            "unavailable_behavior"
        ]
    )


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_operations(root, rows, files)
    second = review.apply_package_semantic_review_operations(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        unresolved = {
            kind: decision
            for kind, decision in row["classification"].items()
            if decision["status"] == "UNRESOLVED"
        }
        assert set(unresolved) == set(EXPECTED_UNLISTED.get(object_id, ()))
        assert all(
            decision
            == {
                "status": "UNRESOLVED",
                "reason": CANONICAL_UNRESOLVED_REASON.format(kind=kind),
                "evidence": [],
            }
            for kind, decision in unresolved.items()
        )
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applies for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )


def test_apply_resolves_current_rehomed_candidates_from_any_owned_path(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-package-worker-exchange"
    path = "src/verifier/runtime/package_execution.py"
    evidence = [{"path": path, "sha256": files[path]}]
    for kind in ("LEDGER", "MEASUREMENT"):
        rows[object_id]["classification"][kind] = {
            "status": "UNRESOLVED",
            "reason": (
                "Migration retains this applicability question. Static ownership "
                "alone cannot refute a " + kind + " role."
            ),
            "evidence": deepcopy(evidence),
        }
    for obligation_id in (
        "LEDGER-0.1-authoritative-history",
        "MEASUREMENT-0.1-phenomenon-and-method",
    ):
        rows[object_id]["obligations"][obligation_id]["evidence"] = deepcopy(evidence)

    result = review.apply_package_semantic_review_operations(root, rows, files)

    # LEDGER has no explicit basis for this object (audited UNKNOWN), so the
    # validated owned candidate survives as UNRESOLVED evidence, not an exemption.
    assert result[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED_REASON.format(kind="LEDGER"),
        "evidence": deepcopy(evidence),
    }
    assert result[object_id]["classification"]["MEASUREMENT"]["status"] == "APPLIES"
    assert not any(
        name.startswith("LEDGER-") for name in result[object_id]["obligations"]
    )
    measurement = result[object_id]["obligations"][
        "MEASUREMENT-0.1-phenomenon-and-method"
    ]
    assert measurement["evidence"] == [
        {"path": observed, "sha256": files[observed]}
        for observed in (
            "src/verifier/runtime/package_execution_observation.py",
            *EMULATOR_EXECUTION_PATHS,
        )
    ]


def test_apply_rejects_stale_rehomed_migration_candidate(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-package-worker-exchange"
    kind = "MEASUREMENT"
    path = "src/verifier/runtime/package_execution.py"
    rows[object_id]["classification"][kind] = {
        "status": "UNRESOLVED",
        "reason": (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a " + kind + " role."
        ),
        "evidence": [{"path": path, "sha256": "sha256:" + "0" * 64}],
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_apply_preserves_exact_complete_reviews_with_reviewed_declaration_text(
    tmp_path,
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    worker = selected["vstd-package-worker-exchange"]
    obligation_id = "MEASUREMENT-0.1-phenomenon-and-method"
    binding = worker["obligations"][obligation_id]
    worker["obligations"][obligation_id] = {
        "reason": binding["reason"],
        "evidence": deepcopy(binding["evidence"]),
        "declaration": {
            field: "Prior exact nonblank " + field + "."
            for field in binding["declaration"]
        },
    }
    before = deepcopy(selected)

    result = review.apply_package_semantic_review_operations(root, selected, files)

    assert result == before
    assert selected == before


@pytest.mark.parametrize(
    "failure",
    [
        "same_status_reason",
        "same_status_refuted_reason",
        "partial_refuted_evidence",
        "duplicate_refuted_evidence",
        "stale_refuted_evidence",
        "unowned_refuted_evidence",
        "partial_role_evidence",
        "duplicate_role_evidence",
        "unowned_role_evidence",
        "obligation_reason",
        "obligation_partial_evidence",
    ],
)
def test_complete_reviews_must_equal_their_explicit_basis_exactly(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    worker = selected["vstd-package-worker-exchange"]
    claim = selected["vstd-claim-garden-lifecycle"]
    executor = selected["vstd-core-mechanism-executor"]
    gated = review.review_document()["vstd-gated-publication"]["owned_paths"][0]
    if failure == "same_status_reason":
        worker["classification"]["MEASUREMENT"]["reason"] = "Prior reviewer reason."
    elif failure == "same_status_refuted_reason":
        claim["classification"]["FINBOT"]["reason"] = "Prior reviewer reason."
    elif failure == "partial_refuted_evidence":
        executor["classification"]["ROBOT"]["evidence"].pop()
    elif failure == "duplicate_refuted_evidence":
        evidence = executor["classification"]["ROBOT"]["evidence"]
        evidence.append(deepcopy(evidence[0]))
    elif failure == "stale_refuted_evidence":
        claim["classification"]["FINBOT"]["evidence"][0]["sha256"] = (
            "sha256:" + "e" * 64
        )
    elif failure == "unowned_refuted_evidence":
        claim["classification"]["FINBOT"]["evidence"] = [
            {"path": gated, "sha256": files[gated]}
        ]
    elif failure == "partial_role_evidence":
        executor["classification"]["TRANSACTION"]["evidence"].pop()
    elif failure == "duplicate_role_evidence":
        evidence = executor["classification"]["TRANSACTION"]["evidence"]
        evidence.append(deepcopy(evidence[0]))
    elif failure == "unowned_role_evidence":
        worker["classification"]["MEASUREMENT"]["evidence"] = [
            {"path": gated, "sha256": files[gated]}
        ]
    elif failure == "obligation_reason":
        worker["obligations"]["MEASUREMENT-0.1-phenomenon-and-method"]["reason"] = (
            "Prior reviewer reason."
        )
    else:
        executor["obligations"]["TRANSACTION-0.1-effects-and-authority"][
            "evidence"
        ].pop()
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_without_mutation(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-javascript-parser-protocol"
    path = review.review_document()[object_id]["owned_paths"][0]
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
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status",
        "stale_decision",
        "unowned_decision",
        "partial_declaration",
        "refuted_declaration",
        "malformed_unresolved",
        "label_conflict",
        "unknown_obligation",
    ],
)
def test_apply_rejects_conflicting_partial_or_unowned_reviews_atomically(
    tmp_path, failure
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    claim = selected["vstd-claim-garden-lifecycle"]
    worker = selected["vstd-package-worker-exchange"]
    if failure == "status":
        claim["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        claim["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "unowned_decision":
        foreign = review.review_document()["vstd-gated-publication"]["owned_paths"][0]
        worker["classification"]["MEASUREMENT"]["evidence"] = [
            {"path": foreign, "sha256": files[foreign]}
        ]
    elif failure == "partial_declaration":
        claim["obligations"]["TRANSACTION-0.1-effects-and-authority"]["declaration"][
            "effects"
        ] = ""
    elif failure == "refuted_declaration":
        fields = ("identity", "rights", "units", "precision")
        claim["obligations"]["ASSET-0.1-identity-and-quantity"] = {
            "reason": "Contradictory ASSET declaration.",
            "evidence": deepcopy(claim["classification"]["ASSET"]["evidence"]),
            "declaration": {field: "Contradictory " + field for field in fields},
        }
    elif failure == "malformed_unresolved":
        claim["classification"]["ASSET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        claim["specializations"].append("ASSET")
    else:
        claim["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


def test_apply_rechecks_all_sources_after_semantic_preflight(tmp_path, monkeypatch):
    root, rows, files = _workspace(tmp_path)
    target = review.review_document()["vstd-workflow-parser-protocol"]["owned_paths"][
        -1
    ]
    original = review._read_digest
    calls = 0

    def drifting_digest(selected_root: Path, path: str) -> str:
        nonlocal calls
        value = original(selected_root, path)
        if path == target:
            calls += 1
            if calls == 2:
                return "sha256:" + "a" * 64
        return value

    monkeypatch.setattr(review, "_read_digest", drifting_digest)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_exact_role_and_consequence_boundaries_are_not_collapsed():
    catalog = review.review_document()

    worker = catalog["vstd-package-worker-exchange"]
    observation = "src/verifier/runtime/package_execution_observation.py"
    # emulator_control_execution is a simulated ACTUATOR check whose worker submits and
    # observes commands in a child that package_execution launches: it is evidence.
    assert worker["classification"]["MEASUREMENT"]["evidence_paths"] == [
        observation,
        *EMULATOR_EXECUTION_PATHS,
    ]
    assert worker["classification"]["ACTUATOR"]["evidence_paths"] == [
        "src/verifier/runtime/package_execution.py",
        *EMULATOR_EXECUTION_PATHS,
    ]
    assert worker["classification"]["SENSOR"]["evidence_paths"] == [observation]
    assert set(worker["classification"]["PROTOCOL"]["evidence_paths"]) == set(
        worker["owned_paths"]
    )
    measurement = worker["declarations"]["MEASUREMENT-0.1-phenomenon-and-method"][
        "observation_vs_estimate"
    ]
    assert "child internals" in measurement.lower()
    assert "confinement" in measurement.lower()

    controlled = catalog["vstd-controlled-emission-controller"]
    assert controlled["classification"]["ACTUATOR"]["status"] == "UNRESOLVED"
    assert not any(name.startswith("ACTUATOR-") for name in controlled["declarations"])
    gate = catalog["vstd-gate-pipeline-controller"]
    assert gate["classification"]["ACTUATOR"]["status"] == "UNRESOLVED"
    assert not any(name.startswith("ACTUATOR-") for name in gate["declarations"])
    assert (
        "not transactional commit"
        in gate["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    train = catalog["vstd-train-control-session"]
    assert train["classification"]["ACTUATOR"]["status"] == "UNRESOLVED"
    assert not any(name.startswith("ACTUATOR-") for name in train["declarations"])
    polish = catalog["vstd-polish-workflow-transaction"]
    workflow_paths = {
        "src/verifier/runtime/polish_prepare.py",
        "src/verifier/runtime/polish_workflow.py",
        "src/verifier/runtime/polish_workflow_cli.py",
        "src/verifier/runtime/polish_workflow_replay.py",
    }
    assert set(polish["owned_paths"]) == workflow_paths
    for kind in EXPECTED_APPLICABILITY["vstd-polish-workflow-transaction"]:
        assert set(polish["classification"][kind]["evidence_paths"]) == workflow_paths
    assert (
        "explicitly selected preparation command"
        in polish["declarations"]["POLICY-0.1-rules-and-precedence"]["scope"]
    )
    assert (
        "preparation, recovery or association command"
        in polish["declarations"]["CONTROLLER-0.1-feedback-and-authority"][
            "commands"
        ]
    )
    assert (
        "not atomic across files"
        in polish["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert "establishes no polish tier" in polish["classification"]["ROBOT"]["reason"]

    for parser_id in (
        "vstd-javascript-parser-protocol",
        "vstd-systems-parser-protocol",
        "vstd-workflow-parser-protocol",
    ):
        parser = catalog[parser_id]
        assert {
            kind
            for kind, decision in parser["classification"].items()
            if decision["status"] == "APPLIES"
        } == {"PROTOCOL"}
        assert "separately represented" in parser["classification"]["ROBOT"]["reason"]
    assert set(catalog["vstd-systems-parser-protocol"]["owned_paths"]) == {
        "src/verifier/runtime/namespace_rust_expansions.py",
        "src/verifier/runtime/namespace_systems.py",
        "src/verifier/runtime/namespace_systems_worker.py",
    }

    for object_id in UNLISTED_ONLY_OBJECTS:
        for kind in ("ROBOT", "FINBOT"):
            decision = catalog[object_id]["classification"][kind]
            assert decision["status"] == "UNRESOLVED"
            assert decision["reason"] == CANONICAL_UNRESOLVED_REASON.format(kind=kind)
    for object_id, item in catalog.items():
        if object_id in UNLISTED_ONLY_OBJECTS:
            continue
        assert item["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
        assert "does not infer absence" in item["classification"]["FINBOT"]["reason"]
        if object_id == "vstd-train-control-session":
            # ROBOT is UNRESOLVED here: its HARDWARE context is declared, not refuted.
            continue
        assert item["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
        assert "does not infer confinement" in item["classification"]["ROBOT"]["reason"]


def test_remote_states_do_not_become_publication_or_payment_claims():
    catalog = review.review_document()
    claim = catalog["vstd-claim-garden-lifecycle"]
    gated = catalog["vstd-gated-publication"]
    sim = catalog["vstd-sim-artifact-publication"]

    assert (
        "PENDING_REVIEW"
        in claim["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert "public release" in gated["classification"]["ROBOT"]["reason"]
    assert (
        "QUARANTINED"
        in sim["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    for item in (claim, gated, sim):
        finbot = item["classification"]["FINBOT"]
        assert finbot["status"] == "DOES_NOT_APPLY"
        assert "financial endpoint" in finbot["reason"]


def test_refutation_catalog_is_literal_disjoint_registered_and_nineteen_objects():
    assert len(review.OPERATIONS_OBJECT_IDS) == 19
    assert len(review._REVIEWS) == 19
    total = 0
    for object_id, catalog_row in review._REVIEWS.items():
        assert set(catalog_row.refuted) <= set(review.REVIEW_KINDS)
        assert len(catalog_row.refuted) == len(set(catalog_row.refuted))
        assert not set(catalog_row.refuted) & set(catalog_row.applicable)
        assert len(catalog_row.refuted) == EXPECTED_REFUTED_COUNT[object_id]
        for kind in EXPECTED_UNLISTED.get(object_id, ()):
            assert kind not in catalog_row.refuted
            assert kind not in catalog_row.applicable
        total += len(catalog_row.refuted)
    assert total == 125


def test_applicable_train_ledger_rejects_an_invented_refutation(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    object_id = "vstd-train-control-session"
    policy = selected[object_id]["classification"]["POLICY"]
    selected[object_id]["classification"]["LEDGER"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Complement-era refutation without an explicit basis.",
        "evidence": deepcopy(policy["evidence"]),
    }

    before = deepcopy(selected)
    with pytest.raises(
        ValueError,
        match=(
            "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:"
            "vstd-train-control-session:LEDGER"
        ),
    ):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


def test_unlisted_protocol_candidate_evidence_is_not_erased(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-train-control-session"
    path = review.review_document()[object_id]["owned_paths"][0]
    evidence = [{"path": path, "sha256": files[path]}]
    reason = CANONICAL_UNRESOLVED_REASON.format(kind="PROTOCOL")
    rows[object_id]["classification"]["PROTOCOL"] = {
        "status": "UNRESOLVED",
        "reason": reason,
        "evidence": deepcopy(evidence),
    }

    result = review.apply_package_semantic_review_operations(root, rows, files)

    assert result[object_id]["classification"]["PROTOCOL"] == {
        "status": "UNRESOLVED",
        "reason": reason,
        "evidence": evidence,
    }


@pytest.mark.parametrize("failure", ["stale", "reason"])
def test_unlisted_candidate_must_be_current_and_canonical(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-train-control-session"
    path = review.review_document()[object_id]["owned_paths"][0]
    digest = files[path]
    reason = CANONICAL_UNRESOLVED_REASON.format(kind="PROTOCOL")
    if failure == "stale":
        digest = "sha256:" + "0" * 64
    else:
        reason = "Prior reviewer reason."
    rows[object_id]["classification"]["PROTOCOL"] = {
        "status": "UNRESOLVED",
        "reason": reason,
        "evidence": [{"path": path, "sha256": digest}],
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("label", ["ROBOT", "FINBOT"])
def test_robot_and_finbot_labels_fail_on_refuted_specialization(tmp_path, label):
    root, rows, files = _workspace(tmp_path)
    rows["vstd-claim-garden-lifecycle"]["specializations"].append(label)
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_refuted_reasons_are_object_specific_and_robot_finbot_stay_distinct():
    catalog = review.review_document()
    reasons = [
        decision["reason"]
        for item in catalog.values()
        for decision in item["classification"].values()
        if decision["status"] == "DOES_NOT_APPLY"
    ]
    assert len(reasons) == 125
    assert len(set(reasons)) == 125
    for object_id, item in catalog.items():
        if object_id in UNLISTED_ONLY_OBJECTS:
            continue
        assert "real-money decision/effect" in item["classification"]["FINBOT"][
            "reason"
        ]
        if object_id == "vstd-train-control-session":
            continue
        assert "agent-to-physical-actuator" in item["classification"]["ROBOT"]["reason"]


def test_apply_requires_all_nineteen_objects_and_leaves_rows_unchanged(tmp_path):
    root, rows, files = _workspace(tmp_path)
    del rows["vstd-workflow-parser-protocol"]
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("basis", [("TRANSACTION",), ("NOT_A_KIND",), ("LEDGER", "LEDGER")])
def test_catalog_check_rejects_overlapping_unregistered_or_duplicate_refutations(
    monkeypatch, basis
):
    review._catalog_check()
    original = review._REVIEWS["vstd-claim-garden-lifecycle"]
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-claim-garden-lifecycle",
        dataclasses.replace(original, refuted=basis),
    )

    with pytest.raises(AssertionError):
        review._catalog_check()


def _strings(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }


def _mentions(node: ast.AST, names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
        if isinstance(child, ast.Attribute) and child.attr in names:
            return True
        # Reflective access such as getattr(review, "applicable") is still a mention.
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "getattr"
            and len(child.args) == 2
            and isinstance(child.args[1], ast.Constant)
            and child.args[1].value in names
        ):
            return True
    return False


def _has_membership(node: ast.AST, ops: tuple[type, ...]) -> bool:
    return any(
        isinstance(child, ast.Compare)
        and any(isinstance(op, ops) for op in child.ops)
        for child in ast.walk(node)
    )


_STATUS_STATEMENTS = (ast.Assign, ast.AnnAssign, ast.Return, ast.Expr)


def _positive_refuted_elif(node: ast.If) -> bool:
    """Return True for ``elif kind in review.refuted`` as the only else-branch."""
    if len(node.orelse) != 1 or not isinstance(node.orelse[0], ast.If):
        return False
    branch = node.orelse[0]
    return _has_membership(branch.test, (ast.In,)) and _mentions(
        branch.test, {"refuted"}
    )


def _complement_findings(source: str) -> list[str]:
    """Flag applicability statuses chosen by a complement or by absence.

    Aliases (``ap = review.applicable``), reflection (``getattr``), comprehensions,
    ``.difference`` calls, and dictionaries keyed by membership are checked in
    addition to the literal-name forms, because each one can express absence as a
    refutation without spelling the complement operator.
    """
    findings = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.IfExp) and (
            _strings(node.body) | _strings(node.orelse)
        ) & {"APPLIES", "DOES_NOT_APPLY"}:
            findings.append(str(node.lineno) + ": status chosen by conditional")
        if (
            isinstance(node, ast.If)
            and _mentions(node.test, {"applicable"})
            and any("DOES_NOT_APPLY" in _strings(item) for item in node.orelse)
            and not _positive_refuted_elif(node)
        ):
            findings.append(str(node.lineno) + ": refutation is an else-branch")
        if (
            isinstance(node, ast.If)
            and _has_membership(node.test, (ast.In,))
            and any(
                isinstance(item, _STATUS_STATEMENTS)
                and "DOES_NOT_APPLY" in _strings(item)
                for item in node.orelse
            )
        ):
            findings.append(str(node.lineno) + ": membership else-branch refutation")
        if (
            isinstance(node, ast.If)
            and _has_membership(node.test, (ast.NotIn,))
            and any(
                "DOES_NOT_APPLY" in _strings(item)
                for item in [*node.body, *node.orelse]
            )
        ):
            findings.append(str(node.lineno) + ": refutation chosen by absence")
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            if any(
                _has_membership(condition, (ast.NotIn,))
                for generator in node.generators
                for condition in generator.ifs
            ) and "DOES_NOT_APPLY" in _strings(node):
                findings.append(str(node.lineno) + ": refutation comprehension by absence")
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Sub)
            and _mentions(node, {"REVIEW_KINDS", "applicable", "refuted"})
        ):
            findings.append(str(node.lineno) + ": complement by set difference")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"difference", "symmetric_difference"}
            and _mentions(node, {"REVIEW_KINDS", "applicable", "refuted"})
        ):
            findings.append(str(node.lineno) + ": complement by set method")
        if (
            isinstance(node, ast.Subscript)
            and {"APPLIES", "DOES_NOT_APPLY"} <= _strings(node.value)
            and _has_membership(node.slice, (ast.In, ast.NotIn))
        ):
            findings.append(str(node.lineno) + ": status chosen by membership table")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_review"
            and "refuted" not in {keyword.arg for keyword in node.keywords}
        ):
            findings.append(str(node.lineno) + ": _review without explicit refuted")
    return findings


_DYNAMIC_CALLS = {"__import__", "eval", "exec", "compile"}
_EFFECT_MODULES = {"importlib", "subprocess", "socket", "shutil", "importlib.util"}


def _dynamic_findings(source: str) -> list[str]:
    """Flag routes that could compute applicability outside this audited source.

    The operations module is a pure catalog and comparison.  Any dynamic import,
    evaluated string, reflective attribute with a non-literal name, or process or
    network effect would let applicability come from code this review never read.
    """
    findings = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _DYNAMIC_CALLS:
                findings.append(str(node.lineno) + ": dynamic call " + node.func.id)
            if node.func.id == "getattr" and not (
                len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
            ):
                findings.append(str(node.lineno) + ": reflective getattr")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _EFFECT_MODULES:
                    findings.append(str(node.lineno) + ": effect import " + alias.name)
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in _EFFECT_MODULES:
                findings.append(str(node.lineno) + ": effect import " + node.module)
    return findings


def test_module_source_has_no_complement_generated_applicability():
    source = Path(review.__file__).read_text(encoding="utf-8")
    assert _complement_findings(source) == []


@pytest.mark.parametrize(
    "fixture",
    [
        'status = "APPLIES" if kind in review.applicable else "DOES_NOT_APPLY"\n',
        'if kind in review.applicable:\n    status = "APPLIES"\n'
        'else:\n    status = "DOES_NOT_APPLY"\n',
        "missing = set(REVIEW_KINDS) - set(review.applicable)\n",
        '_review("X", paths, ("LEDGER",), profile)\n',
        # Absence-conditioned refutation spelled without the complement operator.
        'if kind not in review.applicable:\n    status = "DOES_NOT_APPLY"\n',
        'for kind in K:\n    if kind not in review.applicable:\n'
        '        status = "DOES_NOT_APPLY"\n',
        '{k: "DOES_NOT_APPLY" for k in REVIEW_KINDS if k not in review.applicable}\n',
        '[("DOES_NOT_APPLY", k) for k in REVIEW_KINDS if k not in review.applicable]\n',
        'if kind not in getattr(review, "applicable"):\n'
        '    status = "DOES_NOT_APPLY"\n',
        'missing = set(REVIEW_KINDS).difference(review.applicable)\n',
        # Alias of the applicable tuple used as the membership test.
        'ap = review.applicable\nif kind in ap:\n    status = "APPLIES"\n'
        'else:\n    status = "DOES_NOT_APPLY"\n',
        # Callback body that chooses the status by absence.
        'status = resolve(kind, lambda k: "DOES_NOT_APPLY" '
        'if k not in review.applicable else "APPLIES")\n',
        # Membership table whose key is the absence test.
        '{True: "APPLIES", False: "DOES_NOT_APPLY"}[kind in review.applicable]\n',
    ],
)
def test_complement_guard_flags_known_bad_fixtures(fixture):
    assert _complement_findings(fixture)


@pytest.mark.parametrize(
    "fixture",
    [
        "def basis(review, kind):\n"
        "    if kind in review.applicable:\n"
        '        return "APPLIES"\n'
        "    if kind in review.refuted:\n"
        '        return "DOES_NOT_APPLY"\n'
        '    return "UNRESOLVED"\n',
        # The same literal basis written as an elif chain is still positive.
        "def basis(review, kind):\n"
        "    if kind in review.applicable:\n"
        '        return "APPLIES"\n'
        "    elif kind in review.refuted:\n"
        '        return "DOES_NOT_APPLY"\n'
        '    return "UNRESOLVED"\n',
    ],
)
def test_complement_guard_accepts_literal_basis_fixture(fixture):
    assert _complement_findings(fixture) == []


def test_module_source_has_no_dynamic_reflective_or_effect_applicability():
    source = Path(review.__file__).read_text(encoding="utf-8")
    assert _dynamic_findings(source) == []


@pytest.mark.parametrize(
    "fixture",
    [
        'x = __import__("importlib").import_module("ledger")\n',
        'value = eval("APPLIES")\n',
        'kind_status = getattr(review, name)\n',
        "import importlib\n",
        "from subprocess import run\n",
    ],
)
def test_dynamic_guard_flags_known_bad_fixtures(fixture):
    assert _dynamic_findings(fixture)


TRAIN = "vstd-train-control-session"
FINITE = "vstd-finite-record-issuance"
TRAIN_SOURCE = Path(review.__file__).parents[1] / "corrigibility" / "train_control.py"
FINITE_SOURCE = Path(review.__file__).with_name("finite_record_issuance.py")


def _function_strings(path: Path, name: str) -> set[str]:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return _strings(node)
    raise AssertionError("function not found: " + name)


def _attribute_calls(path: Path) -> set[str]:
    calls = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        ):
            calls.add(node.func.value.id + "." + node.func.attr)
    return calls


def _owned_evidence(files: dict[str, str], object_id: str) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": files[path]}
        for path in review.review_document()[object_id]["owned_paths"]
    ]


def test_finite_record_source_binds_the_ledger_commit_and_replay() -> None:
    # Grounds the accumulated LEDGER role in the authoritative local commit and
    # stored-receipt reconciliation, independently of the declaration text.
    calls = _attribute_calls(FINITE_SOURCE)
    assert {"ledger.commit_issuance", "ledger.recheck_issuance_commit"} <= calls


def test_finite_record_ledger_applies_with_source_owned_commit_and_replay() -> None:
    item = review.review_document()[FINITE]
    assert item["classification"]["LEDGER"]["status"] == "APPLIES"
    assert item["classification"]["LEDGER"]["evidence_paths"] == [
        "src/verifier/runtime/finite_record_issuance.py"
    ]
    accounting = item["declarations"]["LEDGER-0.2-accounting-invariants"]
    assert "not a fungible balance sheet" in accounting["balance_rules"]
    assert "atomic exact-proposal consumption" in accounting["balance_rules"]
    assert accounting["balance_rules"] != review._FINITE_RECORD.limits


def test_train_control_robot_is_unresolved_because_retained_events_declare_hardware() -> None:
    item = review.review_document()[TRAIN]
    assert item["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED_REASON.format(kind="ROBOT"),
        "evidence_paths": [],
    }
    # Every retained EVENT context requires a declared HARDWARE object.
    assert "HARDWARE" in _function_strings(TRAIN_SOURCE, "_record")


def test_train_control_ledger_applies_with_explicit_non_durable_boundaries() -> None:
    # The locally authoritative EVENT chain gates capacity and denial replay. Its
    # lack of a durable store or reconciliation path is a declared LEDGER limit,
    # not an exemption from the role.
    source = TRAIN_SOURCE.read_text(encoding="utf-8")
    assert "sqlite3" not in source
    assert "polish_invocation_ledger" not in source
    train = review.review_document()[TRAIN]
    assert train["classification"]["LEDGER"]["status"] == "APPLIES"
    assert "locally authoritative ordered history" in train["classification"]["LEDGER"]["reason"]
    ledger = train["declarations"]["LEDGER-0.3-correction-and-recovery"]
    assert "not automatically retried" in ledger["replay"]
    assert "retained denial replay" in ledger["recovery"]


def test_train_control_commit_declaration_names_raise_and_nonretention_paths() -> None:
    commit = review.review_document()[TRAIN]["declarations"][
        "TRANSACTION-0.2-commit-and-failure"
    ]["commit"]
    assert "returned or raised" in commit
    assert "not guaranteed" in commit


@pytest.mark.parametrize(
    "object_id,kind,status",
    [
        (TRAIN, "PROTOCOL", "APPLIES"),
        (TRAIN, "ROBOT", "DOES_NOT_APPLY"),
    ],
)
def test_forged_complete_decision_on_unlisted_kind_fails_closed(
    tmp_path, object_id, kind, status
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    profile = review._REVIEWS[object_id].profile
    # Exact-looking reason and current owned evidence, but no explicit basis.
    selected[object_id]["classification"][kind] = {
        "status": status,
        "reason": review._reason(profile, kind, status == "APPLIES"),
        "evidence": _owned_evidence(files, object_id),
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":" + kind,
    ):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


def test_unlisted_robot_declaration_is_refused_not_erased(tmp_path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    contract = review._contract_rows("ROBOT")[0]
    obligation_id = contract["id"]
    selected[TRAIN]["obligations"][obligation_id] = {
        "reason": "Prior reviewer reason.",
        "evidence": _owned_evidence(files, TRAIN),
        "declaration": {field: "Prior " + field for field in contract["declaration_fields"]},
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_UNLISTED_DECLARATION_CONFLICT:"
        + TRAIN
        + ":"
        + obligation_id,
    ):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    "object_id,label", [(TRAIN, "ROBOT"), (TRAIN, "PROTOCOL")]
)
def test_unlisted_protocol_or_robot_specialization_label_fails_closed(
    tmp_path, object_id, label
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows[object_id]["specializations"].append(label)
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


CANONICAL_ROBOT_REASON = CANONICAL_UNRESOLVED_REASON.format(kind="ROBOT")


@pytest.mark.parametrize("kind", ["ROBOT", "CONTROLLER"])
@pytest.mark.parametrize("variant", ["lower", "underscore", "leading_space", "padded"])
def test_obligation_name_aliases_fail_closed_without_mutation(tmp_path, kind, variant):
    # A lowercase, separator, or padded spelling of a review obligation must not
    # survive as an unchecked row entry that another reader could count.
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    canonical = review._contract_rows(kind)[0]["id"]
    alias = {
        "lower": canonical.lower(),
        "underscore": canonical.replace("-", "_", 1),
        "leading_space": " " + canonical,
        "padded": canonical + " ",
    }[variant]
    selected[TRAIN]["obligations"][alias] = {
        "reason": "Forged declaration under an alias.",
        "evidence": _owned_evidence(files, TRAIN),
        "declaration": {"forged": "alias"},
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:" + TRAIN
    ):
        review.apply_package_semantic_review_operations(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("alias", ["robot", " ROBOT", "Finbot", "finbot ", "ledger"])
def test_classification_label_aliases_fail_closed(tmp_path, alias):
    root, rows, files = _workspace(tmp_path)
    rows[TRAIN]["classification"][alias] = {
        "status": "DOES_NOT_APPLY",
        "reason": "This object is not a robot and no robot role applies.",
        "evidence": [],
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("alias", ["robot", " ROBOT", "Finbot", "controller", "ledger"])
def test_specialization_label_aliases_fail_closed(tmp_path, alias):
    root, rows, files = _workspace(tmp_path)
    rows[TRAIN]["specializations"].append(alias)
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:"
    ):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_disclaimer_text_cannot_establish_does_not_apply_for_unlisted_kind(tmp_path):
    # Negative prose on an unlisted kind is not a basis: DOES_NOT_APPLY is refused,
    # and an UNRESOLVED candidate with negative prose is replaced by the canonical
    # migration reason rather than promoted into an exemption.
    root, rows, files = _workspace(tmp_path)
    disclaimer = (
        "Not a ROBOT: no physical endpoint, absence of actuator, does not apply."
    )
    rows[TRAIN]["classification"]["ROBOT"] = {
        "status": "UNRESOLVED",
        "reason": disclaimer,
        "evidence": [],
    }
    selected = review.apply_package_semantic_review_operations(root, rows, files)
    assert selected[TRAIN]["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_ROBOT_REASON,
        "evidence": [],
    }

    forged = deepcopy(rows)
    forged[TRAIN]["classification"]["ROBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": disclaimer,
        "evidence": [],
    }
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + TRAIN + ":ROBOT"
    ):
        review.apply_package_semantic_review_operations(root, forged, files)


def test_row_identity_operand_and_payload_text_cannot_refute_or_exempt(tmp_path):
    root, rows, files = _workspace(tmp_path)
    rows[TRAIN]["operands"] = {"ROBOT": "not applicable", "FINBOT": "absent endpoint"}
    rows[TRAIN]["payload"] = {
        "applicable": [],
        "refuted": ["ROBOT", "CONTROLLER"],
        "kind": "OBJECT",
    }
    rows[TRAIN]["reason"] = "OBJECT: a ROBOT-free controller; no robot applies."
    before = deepcopy(rows)

    selected = review.apply_package_semantic_review_operations(root, rows, files)

    assert selected[TRAIN]["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_ROBOT_REASON,
        "evidence": [],
    }
    assert selected[TRAIN]["classification"]["CONTROLLER"]["status"] == "APPLIES"
    for field in ("operands", "payload", "reason"):
        assert selected[TRAIN][field] == before[TRAIN][field]
    assert rows == before


@pytest.mark.parametrize("placement", ["specializations", "classification"])
def test_generic_object_label_never_exempts_an_unlisted_or_refuted_kind(
    tmp_path, placement
):
    root, rows, files = _workspace(tmp_path)
    if placement == "specializations":
        rows[TRAIN]["specializations"].append("OBJECT")
    else:
        rows[TRAIN]["classification"]["OBJECT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "A generic object label does not apply.",
            "evidence": [],
        }

    selected = review.apply_package_semantic_review_operations(root, rows, files)

    assert selected[TRAIN]["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert selected[TRAIN]["classification"]["LEDGER"]["status"] == "APPLIES"
    assert selected[TRAIN]["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
    assert (
        review._contract_rows("ROBOT")[0]["id"] not in selected[TRAIN]["obligations"]
    )


_DECLARED_KIND_ID = re.compile(
    r"\b(" + "|".join(review.REVIEW_KINDS) + r")-\d+\.\d+"
)
REPO_ROOT = Path(review.__file__).parents[3]


def _declared_refutation_conflicts(catalog):
    """Return (object, path, kind) where an owned source declares a refuted kind's ID.

    A contract ID such as ``ASSET-1.1`` inside an owned file is the file's own
    claim that the kind is in scope, so a refutation of that kind for the same
    object is contradicted by the source it was supposed to rest on.
    """
    conflicts = []
    for object_id, row in catalog.items():
        for path in row.owned_paths:
            text = (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")
            for kind in sorted(set(_DECLARED_KIND_ID.findall(text))):
                if kind in row.refuted:
                    conflicts.append((object_id, path, kind))
    return conflicts


def test_owned_source_declared_kind_ids_are_never_refuted(monkeypatch):
    assert _declared_refutation_conflicts(review._REVIEWS) == []

    # Bad fixture: refuting ASSET for the object whose owned token worker declares
    # ASSET-* obligations must be caught by the same check.
    object_id = "vstd-package-worker-exchange"
    mutated = dict(review._REVIEWS)
    row = mutated[object_id]
    mutated[object_id] = dataclasses.replace(row, refuted=row.refuted + ("ASSET",))
    assert _declared_refutation_conflicts(mutated) == [
        (object_id, "src/verifier/runtime/token_asset_execution.py", "ASSET")
    ]


RUNTIME_DIR = Path(review.__file__).parent
CORE_DIR = RUNTIME_DIR.parent / "core"
PROVENANCE = "vstd-core-provenance-sensor"
RECEIPT = "vstd-core-receipt-transaction"
GATE = "vstd-gate-pipeline-controller"
# (object_id, parent launcher that submits the command, fixed child worker)
PARSER_LAUNCHERS = (
    (
        "vstd-javascript-parser-protocol",
        "namespace_javascript.py",
        "namespace_javascript_worker.py",
    ),
    (
        "vstd-systems-parser-protocol",
        "namespace_systems.py",
        "namespace_systems_worker.py",
    ),
    (
        "vstd-workflow-parser-protocol",
        "namespace_workflows.py",
        "namespace_workflow_worker.py",
    ),
)
_WRITE_METHODS = {
    "write_text",
    "write_bytes",
    "mkdir",
    "makedirs",
    "replace",
    "rename",
    "unlink",
    "remove",
    "touch",
}


def _subprocess_launches(path: Path) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr in {"run", "Popen"}
    ]


def _writes_durable_state(path: Path) -> bool:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in _WRITE_METHODS:
            return True
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            for arg in node.args[1:2]:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and set(arg.value) & set("wax+")
                ):
                    return True
    return False


@pytest.mark.parametrize(
    "placement,label",
    [
        ("classification", "REAL_ROBOT"),
        ("classification", "REAL_FINBOT"),
        ("specializations", "REAL_ROBOT"),
        ("specializations", "REAL_FINBOT"),
        ("obligations", "REAL_ROBOT-0.1-physical-endpoint"),
    ],
)
def test_real_prefixed_kind_labels_fail_closed_without_mutation(
    tmp_path, placement, label
):
    # The REAL_ prefix leaves the leading token non-kind; only token-level naming
    # refuses it, so a label cannot carry a physical or financial role claim.
    root, rows, files = _workspace(tmp_path)
    if placement == "classification":
        rows[TRAIN]["classification"][label] = {
            "status": "APPLIES",
            "reason": "Real physical consequence.",
            "evidence": [],
        }
        code = "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:"
    elif placement == "specializations":
        rows[TRAIN]["specializations"].append(label)
        code = "PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID:"
    else:
        rows[TRAIN]["obligations"][label] = {
            "reason": "Real physical consequence.",
            "evidence": [],
            "declaration": {"endpoint": "physical"},
        }
        code = "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:"
    before = deepcopy(rows)

    with pytest.raises(ValueError, match=code):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_real_prefixed_owned_path_insertion_fails_ownership(tmp_path):
    root, rows, files = _workspace(tmp_path)
    rows[TRAIN]["surfaces"].append("file:src/verifier/corrigibility/REAL_ROBOT.py")
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + TRAIN
    ):
        review.apply_package_semantic_review_operations(root, rows, files)
    assert rows == before


def test_accumulated_roles_keep_each_applicable_kind_once(tmp_path):
    # Roles accumulate on the primary kind: each applicable kind appears once, and
    # re-applying the complete row reproduces the same set.
    root, rows, files = _workspace(tmp_path)
    controlled = "vstd-controlled-emission-controller"
    result = review.apply_package_semantic_review_operations(root, rows, files)
    assert result[controlled]["kind"] == "CONTROLLER"
    assert sorted(result[controlled]["specializations"]) == [
        "POLICY",
        "TRANSACTION",
    ]
    again = review.apply_package_semantic_review_operations(root, result, files)
    assert again[controlled]["specializations"] == result[controlled]["specializations"]


def test_gate_launch_is_not_actuator_and_robot_finbot_stay_identity_refuted():
    # Arbitrary caller-selected argv is submission authority, not an owned effect
    # endpoint. ROBOT/FINBOT remain refuted on the gate's identity.
    gate = review.review_document()[GATE]
    assert gate["classification"]["ACTUATOR"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("ACTUATOR"),
        "evidence_paths": [],
    }
    assert gate["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
    assert gate["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
    assert not any(name.startswith("ACTUATOR-") for name in gate["declarations"])
    source = (RUNTIME_DIR / "gate_pipeline.py").read_text(encoding="utf-8")
    assert "shell=False" in source and "argv," in source


def test_gate_launches_manifest_argv_while_parser_children_use_fixed_worker_argv():
    gate_launches = _subprocess_launches(RUNTIME_DIR / "gate_pipeline.py")
    assert any(
        isinstance(call.args[0], ast.Name) and call.args[0].id == "argv"
        for call in gate_launches
    )
    fixed_prefix = "[sys.executable, \"-I\", \"-B\", str(worker)]"
    for _, launcher, _ in PARSER_LAUNCHERS:
        text = (RUNTIME_DIR / launcher).read_text(encoding="utf-8")
        assert fixed_prefix in text


@pytest.mark.parametrize("object_id,launcher,worker", PARSER_LAUNCHERS)
def test_parser_parent_is_the_executor_and_child_spawns_nothing(
    object_id, launcher, worker
):
    # The parent submits the command, so it is the executor; the child is a PROTOCOL
    # participant and must not launch further processes itself.
    assert _subprocess_launches(RUNTIME_DIR / launcher)
    assert not _subprocess_launches(RUNTIME_DIR / worker)
    assert "import subprocess" not in (RUNTIME_DIR / worker).read_text(encoding="utf-8")
    owned = review.review_document()[object_id]["owned_paths"]
    assert "src/verifier/runtime/" + launcher in owned
    assert "src/verifier/runtime/" + worker in owned


def test_receipt_transaction_declares_nonatomic_publication_without_exclusive_create():
    # Sequential writes without a boundary keep TRANSACTION only with the boundary
    # stated as absent: no atomic group commit, no rollback, no exclusive create.
    receipt = review.review_document()[RECEIPT]
    commit = receipt["declarations"]["TRANSACTION-0.2-commit-and-failure"]
    assert "no atomic group commit" in commit["commit"]
    assert "no automatic rollback" in commit["abort"]
    source = (CORE_DIR / "receipt.py").read_text(encoding="utf-8")
    assert "write_text" in source
    assert "O_EXCL" not in source
    assert not re.search(r"open\([^)]*[\"']x", source)


def test_provenance_source_writes_no_durable_state():
    # Fixed read-only git queries and an in-memory return: this owned source is the
    # evidence behind the TRANSACTION blocker below.
    assert not _writes_durable_state(CORE_DIR / "provenance.py")
    assert _subprocess_launches(CORE_DIR / "provenance.py")


def test_provenance_transaction_becomes_does_not_apply_after_ownership_correction():
    provenance = review.review_document()[PROVENANCE]
    assert provenance["classification"]["TRANSACTION"]["status"] == "DOES_NOT_APPLY"


def test_train_control_ledger_applies_like_permission_slot():
    train = review.review_document()[TRAIN]
    assert train["classification"]["LEDGER"]["status"] == "APPLIES"


@pytest.mark.parametrize(
    "object_id,launcher", [(object_id, launcher) for object_id, launcher, _ in PARSER_LAUNCHERS]
)
def test_parser_launch_does_not_establish_actuator(object_id, launcher):
    actuator = review.review_document()[object_id]["classification"]["ACTUATOR"]
    assert actuator == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("ACTUATOR"),
        "evidence_paths": [],
    }
    source = (RUNTIME_DIR / launcher).read_text(encoding="utf-8")
    assert "subprocess" in source


def test_owned_emulator_endpoint_retains_complete_actuator_basis() -> None:
    item = review._REVIEWS["vstd-package-worker-exchange"]
    basis = item.actuator_basis

    assert basis is not None
    assert basis.endpoint_path in item.owned_paths
    assert basis.endpoint_path in item.role_paths["ACTUATOR"]
    assert basis.command_to_effect.strip()
    assert basis.feedback.strip()
    assert basis.failure_surface.strip()


def test_command_acceptance_only_actuator_mutant_is_rejected(monkeypatch) -> None:
    object_id = "vstd-package-worker-exchange"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        dataclasses.replace(
            original,
            actuator_basis=review._ActuatorBasis(
                endpoint_path=original.owned_paths[0],
                command_to_effect="Accept and submit one command.",
                feedback="",
                failure_surface="",
            ),
        ),
    )

    with pytest.raises(AssertionError, match="ACTUATOR basis"):
        review._catalog_check()


@pytest.mark.parametrize(
    "object_id",
    [
        "vstd-controlled-emission-controller",
        "vstd-core-mechanism-executor",
        "vstd-core-provenance-sensor",
        "vstd-gate-pipeline-controller",
        "vstd-javascript-parser-protocol",
        "vstd-permission-slot-controller",
        "vstd-systems-parser-protocol",
        "vstd-train-control-session",
        "vstd-workflow-parser-protocol",
    ],
)
def test_command_only_actuator_apply_forces_empty_unresolved_without_declaration(
    tmp_path, object_id
):
    root, rows, files = _workspace(tmp_path)
    owned_path = review._REVIEWS[object_id].owned_paths[0]
    rows[object_id]["classification"]["ACTUATOR"] = {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("ACTUATOR"),
        "evidence": [{"path": owned_path, "sha256": files[owned_path]}],
    }

    selected = review.apply_package_semantic_review_operations(root, rows, files)
    assert selected[object_id]["classification"]["ACTUATOR"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("ACTUATOR"),
        "evidence": [],
    }
    assert not any(
        name.startswith("ACTUATOR-")
        for name in selected[object_id]["obligations"]
    )

# Terminology: abstract syntax tree (AST).
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_commands as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


# (primary kind, sole owned path, APPLIES kinds, DOES_NOT_APPLY kinds).  Every
# other kind is UNRESOLVED; the test derives that complement only for checking
# the module's output, never as a refutation.
EXPECTED = {
    "vstd-artifact-snapshot-transaction": (
        "TRANSACTION",
        "src/verifier/runtime/artifact_snapshot.py",
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT", "POLICY"},
    ),
    "vstd-accessibility-artifact-reader": (
        "VERIFIER",
        "src/verifier/runtime/accessibility_cli.py",
        set(review.REVIEW_KINDS),
        set(),
    ),
    "vstd-graph-topology-reader": (
        "VERIFIER",
        "src/verifier/runtime/graph_topology_cli.py",
        {"MEASUREMENT", "SENSOR", "POLICY"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-current-object-reader": (
        "VERIFIER",
        "src/verifier/runtime/current_object_cli.py",
        {"MEASUREMENT", "SENSOR", "POLICY", "ACTUATOR"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-experimental-workflow-reader": (
        "VERIFIER",
        "src/verifier/runtime/experimental_workflow_cli.py",
        {"MEASUREMENT", "SENSOR", "POLICY"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "ACTUATOR",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-security-artifact-reader": (
        "VERIFIER",
        "src/verifier/runtime/security_cli.py",
        {"MEASUREMENT", "SENSOR", "POLICY", "ACTUATOR"},
        {
            "LEDGER",
            "TRANSACTION",
            "ASSET",
            "MARKET",
            "CONTROLLER",
            "PROTOCOL",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-certification-command": (
        "VERIFIER",
        "src/verifier/runtime/certification_cli.py",
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"},
    ),
    "vstd-clearance-publication-preparation": (
        "TRANSACTION",
        "src/verifier/runtime/clearance_publish.py",
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"},
    ),
    "vstd-demo-specimen-materializer": (
        "VERIFIER",
        "src/verifier/runtime/demo.py",
        {"TRANSACTION", "MEASUREMENT", "SENSOR", "ACTUATOR", "POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "PROTOCOL", "ROBOT", "FINBOT"},
    ),
    "vstd-core-obligation-union-policy": (
        "VERIFIER",
        "src/verifier/runtime/core_obligation_union.py",
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
    "vstd-security9-accounting-policy": (
        "VERIFIER",
        "src/verifier/runtime/core_security9_accounting.py",
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
    "vstd-application-authority-protocol": (
        "PROTOCOL",
        "src/verifier/runtime/core_application_authority.py",
        {"PROTOCOL", "POLICY"},
        {
            "LEDGER",
            "ASSET",
            "MARKET",
            "MEASUREMENT",
            "SENSOR",
            "CONTROLLER",
            "ACTUATOR",
            "ROBOT",
            "FINBOT",
        },
    ),
    "vstd-release-source-binding": (
        "VERIFIER",
        "src/verifier/runtime/release_source_binding.py",
        {"POLICY"},
        {"LEDGER", "ASSET", "MARKET", "CONTROLLER", "ACTUATOR", "PROTOCOL", "ROBOT", "FINBOT", "MEASUREMENT", "SENSOR"},
    ),
}

# Third-pass audit: these four pure evaluators have no commit, rollback, or external
# write in their owned bodies, so TRANSACTION is UNRESOLVED rather than APPLIES.
# The current-object reader's PROTOCOL is UNRESOLVED because its invoked route
# (model_hardware_observation -> _run_windows) reaches a worker-process exchange.
EXPECTED_UNRESOLVED = {
    ("vstd-core-obligation-union-policy", "TRANSACTION"),
    ("vstd-security9-accounting-policy", "TRANSACTION"),
    ("vstd-application-authority-protocol", "TRANSACTION"),
    ("vstd-release-source-binding", "TRANSACTION"),
    ("vstd-current-object-reader", "PROTOCOL"),
}

EXPECTED_DECLARATION_TOTAL = 150


def _unresolved(object_id: str) -> set[str]:
    _, _, applicable, refuted = EXPECTED[object_id]
    return set(review.REVIEW_KINDS) - applicable - refuted


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
        path = item["owned_paths"][0]
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
            "surfaces": ["file:" + path],
            "reason": "Synthetic exact owner for command-review tests.",
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


def _assert_statuses(object_id: str, classification: dict) -> None:
    """Every kind has exactly its explicit basis; the rest stays UNRESOLVED."""
    _, path, applicable, refuted = EXPECTED[object_id]
    for kind in review.REVIEW_KINDS:
        decision = classification[kind]
        if kind in applicable:
            assert decision["status"] == "APPLIES", (object_id, kind)
            assert decision["evidence_paths"] == [path], (object_id, kind)
        elif kind in refuted:
            assert decision["status"] == "DOES_NOT_APPLY", (object_id, kind)
            assert decision["evidence_paths"] == [path], (object_id, kind)
        else:
            assert decision["status"] == "UNRESOLVED", (object_id, kind)
            assert decision["evidence_paths"] == [], (object_id, kind)


def _assert_bases(object_id: str, classification: dict) -> None:
    """Status-only check for applied rows, whose evidence is a reference list."""
    _, _, applicable, refuted = EXPECTED[object_id]
    for kind in review.REVIEW_KINDS:
        expected = (
            "APPLIES"
            if kind in applicable
            else "DOES_NOT_APPLY"
            if kind in refuted
            else "UNRESOLVED"
        )
        assert classification[kind]["status"] == expected, (object_id, kind)


def test_document_closes_exact_13_by_13_by_12_denominator() -> None:
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.COMMAND_OBJECT_IDS
    assert set(catalog) == set(EXPECTED)
    assert len(catalog) == 13
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 13
    assert sum(len(item["classification"]) for item in catalog.values()) == 156
    assert (
        sum(len(item["declarations"]) for item in catalog.values())
        == EXPECTED_DECLARATION_TOTAL
    )

    owned_paths = []
    for object_id, item in catalog.items():
        primary, path, applicable, refuted = EXPECTED[object_id]
        assert item["primary_kind"] == primary
        assert item["owned_paths"] == [path]
        owned_paths.extend(item["owned_paths"])
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        } == applicable
        assert {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        } == refuted
        _assert_statuses(object_id, item["classification"])
        for decision in item["classification"].values():
            assert decision["reason"].strip()
        expected_declarations = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applicable
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected_declarations)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected_declarations[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "Tier-1-plus" in item["claim_boundary"]
        assert "authority" in item["claim_boundary"]
    assert len(owned_paths) == len(set(owned_paths))

    catalog["vstd-current-object-reader"]["owned_paths"].clear()
    assert review.review_document()["vstd-current-object-reader"]["owned_paths"]


def test_command_boundaries_preserve_missing_authority_and_effects() -> None:
    catalog = review.review_document()

    snapshot = catalog["vstd-artifact-snapshot-transaction"]
    assert (
        "not atomic across files"
        in snapshot["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert (
        "no provenance"
        in snapshot["declarations"]["TRANSACTION-0.1-effects-and-authority"][
            "authorization"
        ]
    )

    accessibility = catalog["vstd-accessibility-artifact-reader"]
    assert (
        "without reevaluating evidence"
        in accessibility["declarations"]["MEASUREMENT-0.1-phenomenon-and-method"][
            "method"
        ]
    )
    # The reader executes one selected installed native checker, so ACTUATOR applies;
    # its PROTOCOL stays UNRESOLVED because the invoked route can reach a worker exchange.
    current = catalog["vstd-current-object-reader"]
    assert current["classification"]["ACTUATOR"]["status"] == "APPLIES"
    assert current["classification"]["ACTUATOR"]["evidence_paths"] == [
        "src/verifier/runtime/current_object_cli.py"
    ]
    assert current["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"
    # The docstring's "network-backed" note concerns where a selected file lives, not an
    # agent, actuator, or financial endpoint, so ROBOT and FINBOT are refuted by source.
    assert current["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
    assert current["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"

    clearance = catalog["vstd-clearance-publication-preparation"]
    assert (
        "send nothing"
        in clearance["declarations"]["TRANSACTION-0.1-effects-and-authority"]["effects"]
    )
    assert clearance["classification"]["ASSET"]["status"] == "DOES_NOT_APPLY"
    authority = catalog["vstd-application-authority-protocol"]
    assert authority["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
    release = catalog["vstd-release-source-binding"]
    assert release["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
    demo = catalog["vstd-demo-specimen-materializer"]
    assert demo["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"

    for object_id, item in catalog.items():
        for kind in _unresolved(object_id):
            assert item["classification"][kind]["status"] == "UNRESOLVED"
            assert item["classification"][kind]["evidence_paths"] == []


def test_apply_is_pure_complete_deterministic_and_idempotent(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_commands(root, rows, files)
    second = review.apply_package_semantic_review_commands(root, first, files)

    assert rows == before
    assert first == second
    for object_id, row in first.items():
        _, path, applicable, _ = EXPECTED[object_id]
        _assert_bases(object_id, row["classification"])
        for decision in row["classification"].values():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence"] == []
            else:
                assert [ref["path"] for ref in decision["evidence"]] == [path]
        assert applicable - {row["kind"]} <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applicable for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )


def test_apply_preserves_complete_current_same_status_bindings(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    object_id = "vstd-application-authority-protocol"
    row = selected[object_id]
    obligation_id = "PROTOCOL-0.1-participants-and-states"
    expected_decision = deepcopy(row["classification"]["PROTOCOL"])
    expected_binding = deepcopy(row["obligations"][obligation_id])

    result = review.apply_package_semantic_review_commands(root, selected, files)

    assert result[object_id]["classification"]["PROTOCOL"] == expected_decision
    assert result[object_id]["obligations"][obligation_id] == expected_binding


def test_unreviewed_extra_object_is_not_classified_by_catalog_complement(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    future = deepcopy(rows["vstd-current-object-reader"])
    future["object_id"] = "future-command-object"
    future["surfaces"] = []
    rows[future["object_id"]] = future

    result = review.apply_package_semantic_review_commands(root, rows, files)

    assert result[future["object_id"]] == future
    assert {
        decision["status"] for decision in future["classification"].values()
    } == {"UNRESOLVED"}


def test_absent_refutation_is_not_inferred_from_catalog_complement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kind dropped from the explicit refuted tuple must become UNRESOLVED."""
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-artifact-snapshot-transaction"
    catalog = dict(review._REVIEWS)
    catalog[object_id] = replace(
        catalog[object_id],
        refuted=tuple(
            kind for kind in catalog[object_id].refuted if kind != "MARKET"
        ),
    )
    monkeypatch.setattr(review, "_REVIEWS", catalog)

    result = review.apply_package_semantic_review_commands(root, rows, files)

    assert result[object_id]["classification"]["MARKET"]["status"] == "UNRESOLVED"
    assert result[object_id]["classification"]["MARKET"]["evidence"] == []


def test_stale_refutation_cannot_survive_after_catalog_drops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    object_id = "vstd-artifact-snapshot-transaction"
    catalog = dict(review._REVIEWS)
    catalog[object_id] = replace(
        catalog[object_id],
        refuted=tuple(
            kind for kind in catalog[object_id].refuted if kind != "MARKET"
        ),
    )
    monkeypatch.setattr(review, "_REVIEWS", catalog)
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-certification-command"
    path = EXPECTED[object_id][1]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        (root / path).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].clear()
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/extra.py")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_commands(root, rows, files)
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
def test_apply_rejects_conflicting_or_partial_reviews_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    row = selected["vstd-artifact-snapshot-transaction"]
    if failure == "status":
        row["classification"]["TRANSACTION"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        row["classification"]["TRANSACTION"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "partial_declaration":
        row["obligations"]["TRANSACTION-0.1-effects-and-authority"]["declaration"][
            "effects"
        ] = ""
    elif failure == "refuted_declaration":
        row["obligations"]["MARKET-0.1-orders-and-access"] = {
            "reason": "Contradictory MARKET declaration.",
            "evidence": deepcopy(row["classification"]["MARKET"]["evidence"]),
            "declaration": {
                "participant_access": "Contradictory access.",
                "order_states": "Contradictory states.",
                "validation": "Contradictory validation.",
                "cancellation": "Contradictory cancellation.",
            },
        }
    elif failure == "malformed_unresolved":
        # POLICY has no explicit basis for this object, so its UNRESOLVED
        # candidate must be a well-formed, reasoned record.
        row["classification"]["POLICY"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "unlisted_dne":
        # POLICY is unlisted for this object; a forged DOES_NOT_APPLY is not a
        # complement answer and must be rejected.
        row["classification"]["POLICY"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Invented by complement.",
            "evidence": deepcopy(row["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "forged_applies_on_unresolved":
        row["classification"]["POLICY"] = {
            "status": "APPLIES",
            "reason": "Forged applicability.",
            "evidence": deepcopy(row["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "reason_substitution":
        row["classification"]["TRANSACTION"]["reason"] = (
            "Different same-status reason."
        )
    elif failure == "refuted_reason_substitution":
        row["classification"]["MARKET"]["reason"] = "Different same-status refutation."
    elif failure == "refuted_partial_evidence":
        row["classification"]["MARKET"]["evidence"] = []
    elif failure == "obligation_reason_substitution":
        row["obligations"]["TRANSACTION-0.1-effects-and-authority"][
            "reason"
        ] = "Different same-shape reason."
    elif failure == "label_conflict":
        row["specializations"].append("MARKET")
    elif failure == "object_classification_key":
        row["classification"]["OBJECT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Object-level label.",
            "evidence": [],
        }
    elif failure == "object_specialization":
        row["specializations"].append("OBJECT")
    elif failure == "object_obligation":
        row["obligations"]["OBJECT-0.1-invented"] = {
            "reason": "Object-level obligation.",
            "evidence": [],
            "declaration": {},
        }
    else:
        row["obligations"]["TRANSACTION-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


def test_apply_is_atomic_when_the_last_object_conflicts(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    release = selected["vstd-release-source-binding"]
    release["classification"]["POLICY"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Forged on the final object.",
        "evidence": [],
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


def test_apply_rechecks_all_sources_after_semantic_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = EXPECTED["vstd-release-source-binding"][1]
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
        review.apply_package_semantic_review_commands(root, rows, files)
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


def test_residual_unresolved_cells_are_exactly_the_audited_set() -> None:
    """Closed refutations stay DOES_NOT_APPLY; every other open cell is audited residue."""
    catalog = review.review_document()
    closed = {
        "vstd-artifact-snapshot-transaction": ("POLICY",),
        "vstd-current-object-reader": ("ROBOT", "FINBOT"),
        "vstd-certification-command": ("PROTOCOL", "ROBOT", "FINBOT"),
        "vstd-clearance-publication-preparation": ("ASSET",),
        "vstd-application-authority-protocol": ("LEDGER", "ASSET", "MEASUREMENT"),
        "vstd-release-source-binding": ("MEASUREMENT", "SENSOR"),
    }
    for object_id, kinds in closed.items():
        for kind in kinds:
            decision = catalog[object_id]["classification"][kind]
            assert decision["status"] == "DOES_NOT_APPLY", (object_id, kind)
            assert decision["evidence_paths"] == catalog[object_id]["owned_paths"]
    unresolved = {
        (object_id, kind)
        for object_id, item in catalog.items()
        for kind, decision in item["classification"].items()
        if decision["status"] == "UNRESOLVED"
    }
    assert unresolved == EXPECTED_UNRESOLVED
    assert all(
        catalog[object_id]["classification"][kind]["evidence_paths"] == []
        for object_id, kind in unresolved
    )


def test_legacy_generic_refutation_text_is_a_stale_verdict_that_fails_closed(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    object_id = "vstd-artifact-snapshot-transaction"
    stale = deepcopy(selected)
    stale[object_id]["classification"]["LEDGER"]["reason"] = (
        "The bounded artifact snapshot mechanism does not apply as LEDGER. It has "
        "no separately owned ledger state."
    )
    before = deepcopy(stale)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, stale, files)
    assert stale == before


def test_original_kind_questions_ride_along_but_a_review_kind_cannot_go_missing(
    tmp_path: Path,
) -> None:
    from verifier.runtime.package_original_kind_profiles import (
        ORIGINAL_NON_OBJECT_KINDS,
    )

    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-artifact-snapshot-transaction"
    original = {
        "status": "UNRESOLVED",
        "reason": "An original-kind question this review does not own.",
        "evidence": [],
    }
    for kind in ORIGINAL_NON_OBJECT_KINDS:
        rows[object_id]["classification"][kind] = dict(original)

    result = review.apply_package_semantic_review_commands(root, rows, files)

    for kind in ORIGINAL_NON_OBJECT_KINDS:
        assert result[object_id]["classification"][kind] == original

    del rows[object_id]["classification"]["LEDGER"]
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID"):
        review.apply_package_semantic_review_commands(root, rows, files)


def test_object_label_cannot_escape_as_specialization_or_classification(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-artifact-snapshot-transaction"
    rows[object_id]["specializations"] = ["OBJECT"]
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_SPECIALIZATIONS_INVALID"):
        review.apply_package_semantic_review_commands(root, rows, files)

    rows[object_id]["specializations"] = []
    rows[object_id]["classification"]["OBJECT"] = {
        "status": "APPLIES",
        "reason": "unreviewed label",
        "evidence": [],
    }
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID"):
        review.apply_package_semantic_review_commands(root, rows, files)


def test_applicable_roles_accumulate_without_dropping_existing_specializations(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-core-obligation-union-policy"
    rows[object_id]["specializations"] = ["POLICY"]

    result = review.apply_package_semantic_review_commands(root, rows, files)

    specializations = result[object_id]["specializations"]
    assert specializations[0] == "POLICY"
    assert len(specializations) == len(set(specializations))
    _, _, applicable, _ = EXPECTED[object_id]
    assert set(specializations) == applicable - {result[object_id]["kind"]}


def test_refutation_citing_unowned_source_fails_closed_atomically(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    object_id = "vstd-artifact-snapshot-transaction"
    selected[object_id]["classification"]["LEDGER"]["evidence"].append(
        {
            "path": "src/verifier/runtime/namespace_manifest.py",
            "sha256": "sha256:" + "0" * 64,
        }
    )
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


_PROCESS_NETWORK_ROOTS = {
    "subprocess", "socket", "urllib", "http", "requests", "httpx", "aiohttp",
    "multiprocessing", "ctypes", "ssl", "ftplib", "smtplib", "imaplib", "poplib",
    "telnetlib", "xmlrpc", "webbrowser", "pty",
}
_PROCESS_NETWORK_LAST = {
    "Popen", "urlopen", "create_connection", "create_subprocess_exec",
    "create_subprocess_shell", "open_connection", "start_server", "create_datagram_endpoint",
}
_PROCESS_NETWORK_PREFIXES = ("os.system", "os.popen", "os.spawn", "os.exec", "os.fork")
# Dynamic code loading or evaluation can reach any effect, so it counts as an escape.
# importlib.metadata reads distribution metadata and loads no code, so it is allowed.
_DYNAMIC_ROOTS = {"importlib", "runpy", "builtins", "pkgutil"}
_DYNAMIC_BUILTINS = {"__import__", "eval", "exec", "compile"}
_DYNAMIC_ALLOWED_PREFIXES = ("importlib.metadata",)
_PATH_WRITE_METHODS = {
    "write_bytes", "write_text", "mkdir", "unlink", "rmdir", "touch", "rename",
    "symlink_to", "hardlink_to", "chmod",
}
_WRITE_ROOTS = {"shutil", "tempfile"}
_OS_WRITE_CALLS = {
    "os.replace", "os.rename", "os.remove", "os.unlink", "os.makedirs", "os.mkdir",
    "os.rmdir", "os.removedirs", "os.link", "os.symlink", "os.chmod", "os.truncate",
    "os.ftruncate", "os.write", "os.utime",
}
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    func = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _dotted(node: ast.AST) -> str:
    """Attribute chain rooted at a plain name; empty when the root is computed."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Map each locally bound import name to its dotted origin."""
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    names[item.asname] = item.name
                else:
                    head = item.name.split(".", 1)[0]
                    names.setdefault(head, head)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for item in node.names:
                names[item.asname or item.name] = node.module + "." + item.name
    return names


def _resolve(name: str, aliases: dict[str, str]) -> str:
    head, dot, rest = name.partition(".")
    return aliases.get(head, head) + dot + rest


def _is_process_network(origin: str) -> bool:
    parts = origin.split(".")
    return (
        parts[0] in _PROCESS_NETWORK_ROOTS
        or parts[-1] in _PROCESS_NETWORK_LAST
        or origin.startswith(_PROCESS_NETWORK_PREFIXES)
    )


def _is_dynamic(origin: str) -> bool:
    if origin in _DYNAMIC_BUILTINS:
        return True
    if origin.startswith(_DYNAMIC_ALLOWED_PREFIXES):
        return False
    return origin.split(".")[0] in _DYNAMIC_ROOTS


def _writes(mode: str) -> bool:
    return any(char in mode for char in "wax+")


def _mode_writes(node: ast.Call, *, position: int) -> bool:
    """A missing mode is read-only; a computed mode cannot be proven read-only."""
    mode: ast.expr | None = None
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None and len(node.args) > position:
        mode = node.args[position]
    if mode is None:
        return False
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return _writes(mode.value)
    return True


def _assigned_values(tree: ast.Module, name: str) -> list[ast.expr]:
    values: list[ast.expr] = []
    for item in ast.walk(tree):
        if isinstance(item, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in item.targets
        ):
            values.append(item.value)
        elif (
            isinstance(item, ast.AugAssign)
            and isinstance(item.target, ast.Name)
            and item.target.id == name
        ):
            values.append(item.value)
    return values


def _flag_tokens(
    node: ast.expr | None, tree: ast.Module, depth: int = 0
) -> tuple[set[str], bool]:
    """Names an os.open flags expression can carry; unresolved names are unknown."""
    if node is None:
        return set(), True
    names: set[str] = set()
    unresolved = False
    for part in ast.walk(node):
        if isinstance(part, ast.Attribute):
            names.add(part.attr)
        elif isinstance(part, ast.Constant) and isinstance(part.value, str):
            names.add(part.value)
        elif isinstance(part, ast.Name) and part.id not in {"os", "getattr"}:
            values = _assigned_values(tree, part.id)
            if depth >= 4 or not values:
                unresolved = True
            for value in values:
                inner, inner_unresolved = _flag_tokens(value, tree, depth + 1)
                names |= inner
                unresolved = unresolved or inner_unresolved
    return names, unresolved


def _record_call(
    node: ast.Call,
    tree: ast.Module,
    aliases: dict[str, str],
    found: dict[str, list[str]],
) -> None:
    name = _call_name(node)
    origin = _resolve(name, aliases)
    last = origin.split(".")[-1]
    site = origin + ":" + str(node.lineno)
    if _is_process_network(origin):
        found["process_network"].append(site)
    if _is_dynamic(origin):
        found["dynamic"].append(site)
    if origin == "getattr" and "getattr" not in aliases:
        attribute = node.args[1] if len(node.args) > 1 else None
        if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
            target = _resolve(_dotted(node.args[0]), aliases) if node.args else ""
            full = (target + "." if target else "") + attribute.value
            if _is_process_network(full) or _is_dynamic(full):
                found["dynamic"].append(site + " getattr " + full)
        else:
            found["dynamic"].append(site + " getattr(non-constant)")
    if origin == "os.open":
        flags = node.args[1] if len(node.args) > 1 else None
        names, unresolved = _flag_tokens(flags, tree)
        if unresolved or names & set(_WRITE_FLAGS):
            found["write"].append(site)
    elif last in _PATH_WRITE_METHODS or origin in _OS_WRITE_CALLS or (
        origin.split(".")[0] in _WRITE_ROOTS
    ):
        found["write"].append(site)
    elif isinstance(node.func, ast.Name) and node.func.id == "open" and "open" not in aliases:
        if _mode_writes(node, position=1):
            found["write"].append(site)
    elif last == "open" and isinstance(node.func, ast.Attribute):
        if _mode_writes(node, position=0):
            found["write"].append(site)
    elif origin == "os.fdopen" and _mode_writes(node, position=1):
        found["write"].append(site)


def _scan_python_effects(path: Path) -> dict[str, list[str]]:
    """Find effect calls, dynamic escapes, and effect references in one owned body.

    Names resolve through the file's own import aliases, so ``import subprocess as sp``,
    ``from subprocess import run``, and ``getattr(os, "system")`` reach the same origin.
    A reference is a non-call use of an effect symbol, such as a callback argument.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    aliases = _aliases(tree)
    found: dict[str, list[str]] = {
        "process_network": [], "write": [], "dynamic": [], "reference": [],
    }
    callees: set[int] = set()
    attribute_values: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callees.add(id(node.func))
        elif isinstance(node, ast.Attribute):
            attribute_values.add(id(node.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _record_call(node, tree, aliases, found)
        elif (
            isinstance(node, (ast.Name, ast.Attribute))
            and id(node) not in callees
            and id(node) not in attribute_values
        ):
            dotted = _dotted(node)
            if dotted:
                origin = _resolve(dotted, aliases)
            elif isinstance(node, ast.Attribute):
                # A computed base such as Path(name).write_bytes still names its method.
                origin = node.attr
            else:
                continue
            if (
                _is_process_network(origin)
                or _is_dynamic(origin)
                or origin.split(".")[-1] in _PATH_WRITE_METHODS
            ):
                found["reference"].append(origin + ":" + str(node.lineno))
    return found


def test_refuted_actuator_and_protocol_denials_have_no_owned_body_counterexample() -> None:
    """A DOES_NOT_APPLY ACTUATOR/PROTOCOL claim must survive a body-level call scan."""
    root = Path(__file__).resolve().parents[1]
    for object_id, item in review.review_document().items():
        classification = item["classification"]
        path = root / item["owned_paths"][0]
        found = _scan_python_effects(path)
        if classification["ACTUATOR"]["status"] == "DOES_NOT_APPLY":
            assert not any(found.values()), (object_id, found)
        if classification["PROTOCOL"]["status"] == "DOES_NOT_APPLY":
            # A dynamic loader or a callback to an effect symbol can carry an exchange too.
            assert not (
                found["process_network"] or found["dynamic"] or found["reference"]
            ), (object_id, found)


def test_pure_evaluator_transaction_cannot_be_forged_as_applies(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    row = selected["vstd-core-obligation-union-policy"]
    assert row["classification"]["TRANSACTION"]["status"] == "UNRESOLVED"
    row["classification"]["TRANSACTION"] = {
        "status": "APPLIES",
        "reason": "Forged commit boundary on a pure policy evaluator.",
        "evidence": deepcopy(row["classification"]["POLICY"]["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


def test_invoked_native_checker_actuator_cannot_be_forged_as_refuted(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    row = selected["vstd-current-object-reader"]
    decision = row["classification"]["ACTUATOR"]
    assert decision["status"] == "APPLIES"
    row["classification"]["ACTUATOR"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Invented: invokes only an installed in-process checker.",
        "evidence": deepcopy(decision["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


def test_reachable_worker_protocol_cannot_be_forged_as_refuted(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    row = selected["vstd-current-object-reader"]
    row["classification"]["PROTOCOL"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Invented from absence of a participant exchange.",
        "evidence": deepcopy(row["classification"]["POLICY"]["evidence"]),
    }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
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
    assert _scan_python_effects(good) == {
        "process_network": [], "write": [], "dynamic": [], "reference": [],
    }


_ESCAPE_FIXTURES = {
    "module_alias_call": "import subprocess as sp\nsp.run(['x'])\n",
    "from_import_alias_call": "from subprocess import run as go\ngo(['x'])\n",
    "from_os_system_call": "from os import system\nsystem('x')\n",
    "callback_reference": "import os\nlist(map(os.system, ['x']))\n",
    "imported_name_reference": "from subprocess import run\nhandler = run\n",
    "importlib_import": "import importlib\nimportlib.import_module('subprocess')\n",
    "dunder_import": "__import__('subprocess').run(['x'])\n",
    "eval_call": "eval('1')\n",
    "computed_attribute_name": "import os\nname = 'sys' + 'tem'\ngetattr(os, name)('x')\n",
    "constant_getattr_effect": "import os\ngetattr(os, 'system')('x')\n",
    "variable_open_mode": "def f(path, mode):\n    return open(path, mode)\n",
    "parameter_os_open_flags": "import os\ndef f(path, flags):\n    return os.open(path, flags)\n",
    "augmented_os_open_flags": "import os\nflags = os.O_RDONLY\nflags |= os.O_CREAT\nos.open('f', flags)\n",
    "fdopen_variable_mode": "import os\ndef f(fd, mode):\n    return os.fdopen(fd, mode)\n",
    "path_write_method_reference": "from pathlib import Path\nwriter = Path('a').write_bytes\nwriter(b'x')\n",
}

_ESCAPE_CONTROLS = {
    "read_only_flags": "import os\nflags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)\nos.open('f', flags)\n",
    "constant_non_effect_getattr": "callable_digest = getattr(object(), 'mechanism_digest', None)\n",
    "exception_name_import": "from asyncio import CancelledError\ntry:\n    pass\nexcept CancelledError:\n    pass\n",
    "read_mode_open": "from pathlib import Path\nwith Path('f').open('rb') as stream:\n    stream.read()\n",
}


@pytest.mark.parametrize("name", sorted(_ESCAPE_FIXTURES))
def test_effect_scanner_flags_alias_dynamic_and_callback_escapes(
    tmp_path: Path, name: str
) -> None:
    fixture = tmp_path / (name + ".py")
    fixture.write_text(_ESCAPE_FIXTURES[name], encoding="utf-8")
    found = _scan_python_effects(fixture)
    assert any(found.values()), (name, found)


@pytest.mark.parametrize("name", sorted(_ESCAPE_CONTROLS))
def test_effect_scanner_keeps_read_only_and_constant_controls_clean(
    tmp_path: Path, name: str
) -> None:
    fixture = tmp_path / (name + ".py")
    fixture.write_text(_ESCAPE_CONTROLS[name], encoding="utf-8")
    found = _scan_python_effects(fixture)
    assert not any(found.values()), (name, found)


@pytest.mark.parametrize(
    "variant",
    ["foreign_suffix", "subject_moved", "no_own_name_control"],
)
def test_dne_text_must_be_subject_bound_to_its_own_source(
    monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    object_id = "vstd-security9-accounting-policy"
    texts = deepcopy(review._DNE_BASES)
    original = texts[object_id]["ASSET"]
    if variant == "foreign_suffix":
        texts[object_id]["ASSET"] = original + " It also reads release_source_binding.py."
    elif variant == "subject_moved":
        texts[object_id]["ASSET"] = "Reviewed with core_security9_accounting.py as context: " + original
    else:
        texts[object_id]["ASSET"] = "This accounting represents no quantity."
    monkeypatch.setattr(review, "_DNE_BASES", texts)
    with pytest.raises(AssertionError, match=object_id):
        review._catalog_check()


def test_apply_rejects_primary_kind_identity_forged_as_object(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-artifact-snapshot-transaction"]["kind"] = "OBJECT"
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_PRIMARY_KIND_DIFFERS"):
        review.apply_package_semantic_review_commands(root, rows, files)


def test_apply_rejects_path_alias_spelling_in_existing_evidence(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    selected["vstd-artifact-snapshot-transaction"]["classification"]["TRANSACTION"][
        "evidence"
    ][0]["path"] = "src/verifier/runtime/./artifact_snapshot.py"
    before = deepcopy(selected)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


def test_apply_rejects_cross_object_evidence_forged_with_a_real_digest(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    foreign = EXPECTED["vstd-clearance-publication-preparation"][1]
    selected["vstd-artifact-snapshot-transaction"]["classification"]["LEDGER"]["evidence"] = [
        {"path": foreign, "sha256": files[foreign]}
    ]
    before = deepcopy(selected)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("candidate", ["foreign_path", "stale_digest"])
def test_unresolved_candidate_evidence_must_be_owned_and_current(
    tmp_path: Path, candidate: str
) -> None:
    from verifier.runtime import package_semantic_review_operations as shared

    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    object_id = "vstd-core-obligation-union-policy"
    path = EXPECTED[object_id][1]
    if candidate == "foreign_path":
        reference = {"path": "src/verifier/runtime/namespace_manifest.py", "sha256": files[path]}
    else:
        reference = {"path": path, "sha256": "sha256:" + "e" * 64}
    selected[object_id]["classification"]["TRANSACTION"] = {
        "status": "UNRESOLVED",
        "reason": shared._unresolved_reason("TRANSACTION"),
        "evidence": [reference],
    }
    before = deepcopy(selected)
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_commands(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    ("object_id", "kind", "expected_status"),
    [
        ("vstd-artifact-snapshot-transaction", "MARKET", "DOES_NOT_APPLY"),
        ("vstd-artifact-snapshot-transaction", "TRANSACTION", "APPLIES"),
    ],
)
def test_unresolved_downgrade_cannot_exempt_an_explicit_decision(
    tmp_path: Path, object_id: str, kind: str, expected_status: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_commands(root, rows, files)
    selected[object_id]["classification"][kind] = {
        "status": "UNRESOLVED",
        "reason": "Caller claims no basis.",
        "evidence": [],
    }

    result = review.apply_package_semantic_review_commands(root, selected, files)

    assert result[object_id]["classification"][kind]["status"] == expected_status
    assert result[object_id]["classification"][kind]["evidence"]

from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_review_scripts as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.package_semantic_ownership import SEMANTIC_OWNERSHIP_SPECS


EXPECTED_PATHS = {
    "vstd-selected-source-admission": (
        "scripts/admitted_root_binding.py",
        "scripts/exact_materialized_member.py",
        "scripts/exact_source_scope.py",
        "scripts/windows_anchored_member.py",
    ),
    "vstd-network-fixture-corpus": (
        "scripts/build_artifact_network_fixture.py",
        "scripts/build_artifact_network_negative_corpus.py",
        "scripts/build_formation_corpus.py",
        "scripts/build_formation_receipt_corpus.py",
        "scripts/build_proposition_transfer_fixture.py",
        "scripts/build_silo_composition_fixture.py",
    ),
    "vstd-self-polish-native-case-corpus": (
        "scripts/build_self_polish_native_tier3_cases.py",
        "scripts/build_self_polish_native_tier4_cases.py",
        "scripts/build_self_polish_native_tier5_cases.py",
        "scripts/build_self_polish_native_tier6_cases.py",
        "scripts/build_self_polish_native_tier7_cases.py",
        "scripts/build_self_polish_native_tier8_cases.py",
        "scripts/build_self_polish_native_tier9_cases.py",
        "scripts/fixtures/self_polish_native_tier4_seed.json",
    ),
    "vstd-self-polish-case-materializer": (
        "scripts/build_self_polish_native_cases.py",
        "scripts/build_self_polish_sim_case_patch.py",
        "scripts/render_self_polish_native_case_module.py",
    ),
    "vstd-self-polish-full-candidate-capture": (
        "scripts/build_self_polish_native_full_candidate.py",
    ),
    "vstd-tier1-evidence-ledger": ("scripts/build_self_polish_tier1_ledger.py",),
}

EXPECTED_APPLICABILITY = {
    "vstd-selected-source-admission": {
        "POLICY",
        "CONTROLLER",
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
        "TRANSACTION",
    },
    "vstd-network-fixture-corpus": {"LEDGER", "PROTOCOL", "TRANSACTION"},
    "vstd-self-polish-native-case-corpus": {
        "POLICY",
        "MEASUREMENT",
        "SENSOR",
    },
    "vstd-self-polish-case-materializer": {
        "TRANSACTION",
        "ACTUATOR",
        "POLICY",
    },
    "vstd-self-polish-full-candidate-capture": {
        "CONTROLLER",
        "ACTUATOR",
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
        "POLICY",
        "TRANSACTION",
    },
    "vstd-tier1-evidence-ledger": {
        "LEDGER",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "SENSOR",
        "PROTOCOL",
        "POLICY",
        "TRANSACTION",
    },
}


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
            target = tmp_path.joinpath(*path.split("/"))
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
                    "reason": review._shared._unresolved_reason(kind),
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_obligations(),
        }
    return tmp_path, rows, files


def test_review_document_closes_exact_six_object_twenty_three_path_denominator():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.SCRIPT_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_PATHS) == set(EXPECTED_APPLICABILITY)
    assert len(catalog) == 6
    assert sum(len(item["owned_paths"]) for item in catalog.values()) == 23
    assert sum(len(item["classification"]) for item in catalog.values()) == 72
    assert sum(len(item["declarations"]) for item in catalog.values()) == 90

    for object_id, item in catalog.items():
        assert tuple(item["owned_paths"]) == EXPECTED_PATHS[object_id]
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert all(
            decision["status"] == ("APPLIES" if kind in applies else "UNRESOLVED")
            and decision["reason"].strip()
            and bool(decision["evidence_paths"]) == (kind in applies)
            and set(decision["evidence_paths"]) <= set(item["owned_paths"])
            for kind, decision in item["classification"].items()
        )
        assert not any(
            decision["status"] == "DOES_NOT_APPLY"
            for decision in item["classification"].values()
        )
        expected = {
            obligation["id"]: set(obligation["declaration_fields"])
            for kind in applies
            for obligation in requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        assert set(item["declarations"]) == set(expected)
        assert all(
            set(declaration) == expected[obligation_id]
            and all(value.strip() for value in declaration.values())
            for obligation_id, declaration in item["declarations"].items()
        )
        assert "Tier-0" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]

    catalog["vstd-selected-source-admission"]["owned_paths"].clear()
    assert review.review_document()["vstd-selected-source-admission"]["owned_paths"]


def test_review_matches_semantic_ownership_and_current_repository_paths():
    root = Path(__file__).resolve().parents[1]
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
        assert all(
            root.joinpath(*path.split("/")).is_file() for path in item["owned_paths"]
        )


def test_role_evidence_preserves_live_observation_and_legacy_boundaries():
    catalog = review.review_document()
    cases = catalog["vstd-self-polish-native-case-corpus"]
    tier3 = ["scripts/build_self_polish_native_tier3_cases.py"]

    assert cases["classification"]["POLICY"]["evidence_paths"] == list(
        EXPECTED_PATHS["vstd-self-polish-native-case-corpus"]
    )
    assert cases["classification"]["MEASUREMENT"]["evidence_paths"] == tier3
    assert cases["classification"]["SENSOR"]["evidence_paths"] == tier3
    tier3_source = (
        Path(__file__).resolve().parents[1] / tier3[0]
    ).read_text(encoding="utf-8")
    assert "platform." not in tier3_source and "subprocess" not in tier3_source
    assert "AMD64" in tier3_source
    assert "residual" in cases["classification"]["MEASUREMENT"]["reason"]
    assert "residual" in cases["classification"]["SENSOR"]["reason"]

    for object_id, item in catalog.items():
        for kind in EXPECTED_APPLICABILITY[object_id]:
            if object_id == "vstd-self-polish-native-case-corpus" and kind in {
                "MEASUREMENT",
                "SENSOR",
            }:
                continue
            assert item["classification"][kind]["evidence_paths"] == item["owned_paths"]
        for kind in review.REVIEW_KINDS:
            if kind not in EXPECTED_APPLICABILITY[object_id]:
                assert item["classification"][kind]["status"] == "UNRESOLVED"
                assert item["classification"][kind]["evidence_paths"] == []

    ledger = catalog["vstd-tier1-evidence-ledger"]
    assert ledger["classification"]["ROBOT"]["reason"] == (
        review._shared._unresolved_reason("ROBOT")
    )
    assert (
        "cannot claim current 38-kind completeness"
        in ledger["declarations"]["TRANSACTION-0.2-commit-and-failure"]["commit"]
    )
    assert (
        "UNKNOWN"
        in ledger["declarations"]["POLICY-0.3-enforcement-and-decisions"][
            "unavailable_behavior"
        ]
    )


def test_apply_is_atomic_pure_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_semantic_review_scripts(root, rows, files)
    second = review.apply_package_semantic_review_scripts(root, first, files)

    assert rows == before
    assert first == second
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
    case = first["vstd-self-polish-native-case-corpus"]
    assert case["classification"]["MEASUREMENT"]["evidence"] == [
        {
            "path": "scripts/build_self_polish_native_tier3_cases.py",
            "sha256": files["scripts/build_self_polish_native_tier3_cases.py"],
        }
    ]
    assert (
        case["obligations"]["SENSOR-0.1-acquisition-and-observations"]["evidence"]
        == case["classification"]["SENSOR"]["evidence"]
    )


def test_apply_preserves_exact_current_answers_and_reviewed_declaration_text(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    admission = selected["vstd-selected-source-admission"]
    obligation_id = "POLICY-0.1-rules-and-precedence"
    declaration = admission["obligations"][obligation_id]["declaration"]
    admission["obligations"][obligation_id]["declaration"] = {
        field: "Reviewed exact nonblank " + field + "." for field in declaration
    }
    expected = deepcopy(selected)

    result = review.apply_package_semantic_review_scripts(root, selected, files)

    assert result == expected


@pytest.mark.parametrize("failure", ["stale", "missing", "unowned", "extra_owned"])
def test_apply_rejects_source_or_ownership_drift_without_mutation(tmp_path, failure):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-self-polish-case-materializer"
    path = EXPECTED_PATHS[object_id][0]
    if failure == "stale":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing":
        root.joinpath(*path.split("/")).unlink()
    elif failure == "unowned":
        rows[object_id]["surfaces"].remove("file:" + path)
    else:
        rows[object_id]["surfaces"].append("file:unreviewed/extra.py")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_scripts(root, rows, files)
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
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    admission = selected["vstd-selected-source-admission"]
    materializer = selected["vstd-self-polish-case-materializer"]
    if failure == "status":
        admission["classification"]["POLICY"]["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        admission["classification"]["POLICY"]["evidence"][0]["sha256"] = (
            "sha256:" + "f" * 64
        )
    elif failure == "unowned_decision":
        foreign = EXPECTED_PATHS["vstd-network-fixture-corpus"][0]
        admission["classification"]["POLICY"]["evidence"] = [
            {"path": foreign, "sha256": files[foreign]}
        ]
    elif failure == "partial_declaration":
        admission["obligations"]["POLICY-0.1-rules-and-precedence"]["declaration"][
            "scope"
        ] = ""
    elif failure == "refuted_declaration":
        materializer["obligations"]["ASSET-0.1-identity-and-quantity"] = {
            "reason": "Contradictory ASSET declaration.",
            "evidence": deepcopy(materializer["classification"]["ASSET"]["evidence"]),
            "declaration": {
                field: "Contradictory " + field
                for field in ("identity", "rights", "units", "precision")
            },
        }
    elif failure == "malformed_unresolved":
        admission["classification"]["ASSET"] = {
            "status": "UNRESOLVED",
            "reason": "",
            "evidence": [],
        }
    elif failure == "label_conflict":
        admission["specializations"].append("ASSET")
    else:
        admission["obligations"]["POLICY-0.99-invented"] = {
            "reason": "Invented.",
            "evidence": [],
            "declaration": {},
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_"):
        review.apply_package_semantic_review_scripts(root, selected, files)
    assert selected == before


def test_apply_rechecks_all_sources_after_semantic_preflight(tmp_path, monkeypatch):
    root, rows, files = _workspace(tmp_path)
    target = "scripts/build_self_polish_tier1_ledger.py"
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
        review.apply_package_semantic_review_scripts(root, rows, files)
    assert rows == before


def test_no_complement_based_does_not_apply_is_emitted_for_any_object():
    catalog = review.review_document()

    for object_id, item in catalog.items():
        for kind, decision in item["classification"].items():
            if kind in EXPECTED_APPLICABILITY[object_id]:
                assert decision["status"] == "APPLIES"
            else:
                assert decision["status"] == "UNRESOLVED"
                assert decision["evidence_paths"] == []
                assert decision["reason"].endswith("refute a " + kind + " role.")
    assert not any(
        decision["status"] == "DOES_NOT_APPLY"
        for item in catalog.values()
        for decision in item["classification"].values()
    )
    assert (
        sum(
            decision["status"] == "APPLIES"
            for item in catalog.values()
            for decision in item["classification"].values()
        )
        == 30
    )


def test_absent_kinds_are_unresolved_not_refuted_for_every_catalog_object():
    for object_id, item in review._REVIEWS.items():
        for kind in review.REVIEW_KINDS:
            expected = "APPLIES" if kind in item.applicable else "UNRESOLVED"
            assert review._basis(item, kind) == expected, (object_id, kind)


def test_unlisted_object_cannot_inherit_or_receive_a_does_not_apply_decision(tmp_path):
    root, rows, files = _workspace(tmp_path)
    foreign_id = "vstd-unlisted-object"
    foreign_path = EXPECTED_PATHS["vstd-network-fixture-corpus"][0]
    rows[foreign_id] = deepcopy(rows["vstd-network-fixture-corpus"])
    rows[foreign_id]["object_id"] = foreign_id
    rows[foreign_id]["classification"] = {
        kind: {
            "status": "DOES_NOT_APPLY",
            "reason": "Foreign unlisted refutation.",
            "evidence": [{"path": foreign_path, "sha256": files[foreign_path]}],
        }
        for kind in review.REVIEW_KINDS
    }
    before = deepcopy(rows)

    result = review.apply_package_semantic_review_scripts(root, rows, files)

    assert rows == before
    assert result[foreign_id] == before[foreign_id]
    for object_id in review.SCRIPT_OBJECT_IDS:
        assert not any(
            decision["status"] == "DOES_NOT_APPLY"
            for decision in result[object_id]["classification"].values()
        )


@pytest.mark.parametrize(
    ("object_id", "kind"),
    [
        ("vstd-self-polish-case-materializer", "ROBOT"),
        ("vstd-selected-source-admission", "FINBOT"),
        ("vstd-network-fixture-corpus", "ASSET"),
    ],
)
def test_forged_does_not_apply_without_a_basis_is_rejected_not_erased(
    tmp_path, object_id, kind
):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    selected[object_id]["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Forged refutation.",
        "evidence": [
            {"path": path, "sha256": files[path]}
            for path in EXPECTED_PATHS[object_id]
        ],
    }
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_UNBACKED_DECISION:" + object_id + ":" + kind,
    ):
        review.apply_package_semantic_review_scripts(root, selected, files)
    assert selected == before


def test_same_status_reason_and_role_evidence_substitution_is_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    admission = selected["vstd-selected-source-admission"]
    admission["classification"]["POLICY"]["reason"] = "Prior policy review."
    before = deepcopy(selected)
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-selected-source-admission:POLICY",
    ):
        review.apply_package_semantic_review_scripts(root, selected, files)
    assert selected == before

    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    corpus = selected["vstd-self-polish-native-case-corpus"]
    corpus["classification"]["MEASUREMENT"]["evidence"] = [
        {"path": path, "sha256": files[path]}
        for path in EXPECTED_PATHS["vstd-self-polish-native-case-corpus"]
    ]
    before = deepcopy(selected)
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-self-polish-native-case-corpus:MEASUREMENT",
    ):
        review.apply_package_semantic_review_scripts(root, selected, files)
    assert selected == before


def test_unresolved_candidate_is_kept_only_with_canonical_reason_and_owned_evidence(
    tmp_path,
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-network-fixture-corpus"
    path = EXPECTED_PATHS[object_id][0]
    candidate = {
        "status": "UNRESOLVED",
        "reason": review._shared._unresolved_reason("ASSET"),
        "evidence": [{"path": path, "sha256": files[path]}],
    }
    rows[object_id]["classification"]["ASSET"] = deepcopy(candidate)

    result = review.apply_package_semantic_review_scripts(root, rows, files)
    assert result[object_id]["classification"]["ASSET"] == candidate

    rows[object_id]["classification"]["ASSET"]["reason"] = "Substituted candidate reason."
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":ASSET",
    ):
        review.apply_package_semantic_review_scripts(root, rows, files)
    assert rows == before


def _apply_expecting(root, rows, files, code):
    before = deepcopy(rows)
    with pytest.raises(ValueError, match=code):
        review.apply_package_semantic_review_scripts(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("variant", ["robot", " ROBOT", "ROBOT_0.1", "Robot-2"])
def test_label_variant_classification_key_cannot_launder_a_refutation(tmp_path, variant):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-selected-source-admission"
    rows[object_id]["classification"][variant] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Variant label refutation.",
        "evidence": [],
    }
    _apply_expecting(
        root, rows, files, "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id
    )


@pytest.mark.parametrize("variant", ["robot", "ROBOT_0.1", "finbot 2"])
def test_label_variant_specialization_cannot_mislabel_an_object(tmp_path, variant):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-network-fixture-corpus"
    rows[object_id]["specializations"].append(variant)
    _apply_expecting(
        root, rows, files, "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:" + object_id
    )


@pytest.mark.parametrize(
    "name",
    [
        "robot-0.1-identity-and-quantity",
        "policy-0.1-rules-and-precedence",
        "POLICY_0.99-invented",
    ],
)
def test_label_variant_obligation_name_cannot_inject_an_invented_declaration(
    tmp_path, name
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-self-polish-case-materializer"
    rows[object_id]["obligations"][name] = {
        "reason": "Invented variant declaration.",
        "evidence": [],
        "declaration": {"identity": "Invented."},
    }
    _apply_expecting(
        root, rows, files, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_UNKNOWN:" + object_id
    )


def test_dict_subclass_decision_with_forged_equality_is_rejected(tmp_path):
    class ForgedDecision(dict):
        def __ne__(self, other):
            return False

        def __eq__(self, other):
            return True

    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    object_id = "vstd-selected-source-admission"
    selected[object_id]["classification"]["POLICY"] = ForgedDecision(
        selected[object_id]["classification"]["POLICY"]
    )
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id,
    )


def test_str_and_list_subclasses_with_forged_equality_cannot_fake_an_obligation(
    tmp_path,
):
    class ForgedText(str):
        def __ne__(self, other):
            return False

    class ForgedList(list):
        def __ne__(self, other):
            return False

    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    object_id = "vstd-selected-source-admission"
    binding = selected[object_id]["obligations"]["POLICY-0.1-rules-and-precedence"]
    binding["reason"] = ForgedText("Forged reason.")
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id,
    )

    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    binding = selected[object_id]["obligations"]["POLICY-0.1-rules-and-precedence"]
    binding["evidence"] = ForgedList(binding["evidence"])
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:" + object_id,
    )


def test_shared_containers_across_rows_are_rejected_without_mutation(tmp_path):
    root, rows, files = _workspace(tmp_path)
    shared = rows["vstd-network-fixture-corpus"]["specializations"]
    rows["vstd-selected-source-admission"]["specializations"] = shared
    _apply_expecting(root, rows, files, "PACKAGE_SEMANTIC_REVIEW_ALIASED_ROWS")

    rows = _workspace(tmp_path / "second")[1]
    rows["vstd-tier1-evidence-ledger"]["classification"] = rows[
        "vstd-network-fixture-corpus"
    ]["classification"]
    _apply_expecting(root, rows, files, "PACKAGE_SEMANTIC_REVIEW_ALIASED_ROWS")


def test_shared_container_with_an_unowned_row_cannot_leak_review_edits(tmp_path):
    root, rows, files = _workspace(tmp_path)
    rows["vstd-unrelated-row"] = {
        "object_id": "vstd-unrelated-row",
        "classification": rows["vstd-selected-source-admission"]["classification"],
    }
    _apply_expecting(root, rows, files, "PACKAGE_SEMANTIC_REVIEW_ALIASED_ROWS")


@pytest.mark.parametrize(
    "reason",
    [
        "ASSET does not apply here and is exempt for this object.",
        "Out of scope; not applicable.",
        "",
    ],
)
def test_unresolved_negative_text_without_evidence_is_not_retained(tmp_path, reason):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-network-fixture-corpus"
    rows[object_id]["classification"]["ASSET"] = {
        "status": "UNRESOLVED",
        "reason": reason,
        "evidence": [],
    }
    _apply_expecting(
        root, rows, files, "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id
    )


_EFFECT_ROLES = {
    "LAUNCH": {"ACTUATOR"},
    "DYNAMIC_LOAD": {"ACTUATOR"},
    "FS_WRITE": {"TRANSACTION", "ACTUATOR"},
    "NETWORK": {"PROTOCOL", "ACTUATOR"},
    "HOST_OBSERVATION": {"MEASUREMENT", "SENSOR"},
}
_WRITE_MODES = set("wax+")


def _dotted(node) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return base + "." + node.attr if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _effect_families(path: Path) -> set[str]:
    """Return effect families named by the exact source bytes of one file.

    The scan reads imports, calls and attributes; it never infers a kind from a
    filename and never treats a string literal or comment as an effect.
    """
    families: set[str] = set()
    tree = ast.parse(path.read_bytes(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for module in modules:
                root = module.split(".")[0]
                if root == "subprocess":
                    families.add("LAUNCH")
                elif root in {"socket", "urllib", "http", "requests", "ssl"}:
                    families.add("NETWORK")
                elif root == "importlib":
                    families.add("DYNAMIC_LOAD")
        elif isinstance(node, ast.Attribute):
            name = _dotted(node)
            if name in {"os.environ", "sys.executable"} or name.startswith("platform."):
                families.add("HOST_OBSERVATION")
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in {"__import__", "exec", "eval"} or name.startswith("importlib."):
                families.add("DYNAMIC_LOAD")
            if name.startswith(
                ("subprocess.", "os.system", "os.popen", "os.spawn", "os.exec")
            ):
                families.add("LAUNCH")
            if name.split(".")[-1] in {"write_text", "write_bytes"} or name.startswith(
                (
                    "os.remove",
                    "os.unlink",
                    "os.rename",
                    "os.replace",
                    "os.mkdir",
                    "os.makedirs",
                    "os.rmdir",
                    "shutil.",
                )
            ):
                families.add("FS_WRITE")
            if name in {"open", "os.open"} or name.endswith(".open"):
                modes = [
                    arg.value
                    for arg in [*node.args[:2], *(kw.value for kw in node.keywords)]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                ]
                if any(set(mode) & _WRITE_MODES for mode in modes if len(mode) <= 3):
                    families.add("FS_WRITE")
    return families


def test_effect_scanner_detects_each_family_in_synthetic_source(tmp_path):
    cases = {
        "LAUNCH": "import subprocess\nsubprocess.run(['git'])\n",
        "DYNAMIC_LOAD": "import importlib\nimportlib.import_module('x')\n",
        "FS_WRITE": "from pathlib import Path\nPath('o').write_text('x')\n",
        "NETWORK": "import urllib.request\n",
        "HOST_OBSERVATION": "import os\nos.environ.get('X')\n",
    }
    for family, source in cases.items():
        path = tmp_path / (family + ".py")
        path.write_text(source, encoding="utf-8")
        assert family in _effect_families(path), family
    quiet = tmp_path / "quiet.py"
    quiet.write_text(
        "from pathlib import Path\nPath('o').read_text()\n# subprocess os.environ\n",
        encoding="utf-8",
    )
    assert _effect_families(quiet) == set()


def test_direct_effect_constructs_are_covered_by_applicable_roles():
    root = Path(__file__).resolve().parents[1]
    observed: dict[str, set[str]] = {}
    for object_id, item in review._REVIEWS.items():
        families: set[str] = set()
        for rel in item.owned_paths:
            families |= _effect_families(root.joinpath(*rel.split("/")))
        observed[object_id] = families
        for family in families:
            assert _EFFECT_ROLES[family] & set(item.applicable), (object_id, family)
    # Non-vacuity: the scanner must see the known exact effects in these sources.
    assert "LAUNCH" in observed["vstd-tier1-evidence-ledger"]
    assert "HOST_OBSERVATION" in observed["vstd-tier1-evidence-ledger"]
    assert "FS_WRITE" in observed["vstd-self-polish-case-materializer"]
    assert "FS_WRITE" in observed["vstd-network-fixture-corpus"]


@pytest.mark.parametrize(
    "variant",
    [
        "scripts/./admitted_root_binding.py",
        "scripts//admitted_root_binding.py",
        "scripts\\admitted_root_binding.py",
        "../scripts/admitted_root_binding.py",
        "/scripts/admitted_root_binding.py",
    ],
)
def test_constructed_surface_path_variants_are_not_owned_sources(tmp_path, variant):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-selected-source-admission"
    rows[object_id]["surfaces"] = [
        "file:" + variant if item == "file:scripts/admitted_root_binding.py" else item
        for item in rows[object_id]["surfaces"]
    ]
    _apply_expecting(
        root, rows, files, "PACKAGE_SEMANTIC_REVIEW_OWNERSHIP_DIFFERS:" + object_id
    )


def test_constructed_evidence_path_variant_is_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    object_id = "vstd-selected-source-admission"
    selected[object_id]["classification"]["POLICY"]["evidence"][0]["path"] = (
        "scripts/./admitted_root_binding.py"
    )
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:" + object_id + ":POLICY",
    )


def test_stale_obligation_digest_and_swapped_role_evidence_are_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    object_id = "vstd-self-polish-native-case-corpus"
    obligation = "SENSOR-0.1-acquisition-and-observations"
    selected[object_id]["obligations"][obligation]["evidence"][0]["sha256"] = (
        "sha256:" + "e" * 64
    )
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:" + object_id + ":" + obligation,
    )

    selected = review.apply_package_semantic_review_scripts(root, rows, files)
    selected[object_id]["obligations"][obligation]["evidence"] = deepcopy(
        selected[object_id]["classification"]["POLICY"]["evidence"]
    )
    _apply_expecting(
        root,
        selected,
        files,
        "PACKAGE_SEMANTIC_REVIEW_DECLARATION_CONFLICT:" + object_id + ":" + obligation,
    )


def test_in_root_symlink_source_substitution_is_rejected(tmp_path):
    root, rows, files = _workspace(tmp_path)
    target_path = "scripts/admitted_root_binding.py"
    donor_path = "scripts/exact_source_scope.py"
    target = root.joinpath(*target_path.split("/"))
    donor = root.joinpath(*donor_path.split("/"))
    donor.write_bytes(target.read_bytes())
    files[donor_path] = files[target_path]
    target.unlink()
    try:
        target.symlink_to(donor)
    except OSError as exc:
        pytest.skip("symlink creation unavailable: " + str(exc))
    _apply_expecting(
        root,
        rows,
        files,
        "PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:" + target_path,
    )


def test_callback_object_in_owned_binding_is_rejected_before_any_hook_runs(tmp_path):
    class Hook:
        calls = 0

        def __deepcopy__(self, memo):
            Hook.calls += 1
            return self

    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-selected-source-admission"
    rows[object_id]["obligations"]["POLICY-0.1-rules-and-precedence"]["declaration"][
        "scope"
    ] = Hook()
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_REVIEW_BINDINGS_INVALID:"):
        review.apply_package_semantic_review_scripts(root, rows, files)
    assert Hook.calls == 0


def test_failure_at_any_point_leaves_caller_rows_unchanged(tmp_path, monkeypatch):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)
    original = review._explicit_decision
    counted = {"calls": 0}

    def counting(*args, **kwargs):
        counted["calls"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(review, "_explicit_decision", counting)
    review.apply_package_semantic_review_scripts(root, rows, files)
    total = counted["calls"]
    assert total > 2

    for failing_call in (1, total // 2, total):
        seen = {"calls": 0}

        def failing(*args, _at=failing_call, _seen=seen, **kwargs):
            _seen["calls"] += 1
            if _seen["calls"] == _at:
                raise RuntimeError("injected at " + str(_at))
            return original(*args, **kwargs)

        monkeypatch.setattr(review, "_explicit_decision", failing)
        with pytest.raises(RuntimeError, match="injected"):
            review.apply_package_semantic_review_scripts(root, rows, files)
        assert rows == before

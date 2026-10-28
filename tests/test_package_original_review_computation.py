from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from verifier.runtime import package_original_review_computation as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


EXPECTED_APPLICABILITY = {
    "vstd-architecture": set(review.REVIEW_KINDS),
    "vstd-training": {"POLICY"},
    "vstd-hypergraph": {"POLICY"},
    "vstd-model": {
        "TRANSACTION",
        "MEASUREMENT",
        "SENSOR",
        "ACTUATOR",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-agent": set(review.REVIEW_KINDS),
    "vstd-bot": set(review.REVIEW_KINDS),
    "vstd-token": {"ASSET", "PROTOCOL", "POLICY"},
}

PREFIXES = {
    "vstd-architecture": ("ARCH", "arch", False),
    "vstd-training": ("TRAIN", "train", True),
    "vstd-hypergraph": ("HYPER", "hyper", False),
    "vstd-model": ("MODEL", "model", True),
    "vstd-agent": ("AGENT", "agent", True),
    "vstd-bot": ("BOT", "bot", True),
    "vstd-token": ("TOKEN", "token", True),
}


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _migration_question(kind: str) -> dict:
    return {
        "status": "UNRESOLVED",
        "reason": (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a " + kind + " role."
        ),
        "evidence": [],
    }


def _full_classification() -> dict[str, dict]:
    return {
        kind: _migration_question(kind)
        for kind in namespace_registry()
        if kind != "OBJECT"
    }


def _all_candidates() -> dict[str, dict]:
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


def _rows() -> dict[str, dict]:
    return {
        object_id: {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic canonical current migration candidate.",
            "classification": _full_classification(),
            "obligations": _all_candidates(),
        }
        for object_id, item in review.review_document().items()
    }


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    files: dict[str, str] = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = f"# {object_id} {path}\n".encode()
            target.write_bytes(raw)
            files[path] = _digest(raw)
    return tmp_path, _rows(), files


def test_review_document_is_complete_deterministic_and_registry_exact() -> None:
    first = review.review_document()
    second = review.review_document()
    registry = namespace_registry()

    assert first == second
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    )
    assert tuple(first) == review.ORIGINAL_OBJECT_IDS
    assert set(first) == set(EXPECTED_APPLICABILITY)
    assert sum(len(item["declarations"]) for item in first.values()) == 141

    for object_id, item in first.items():
        decisions = item["classification"]
        applies = {
            kind
            for kind, decision in decisions.items()
            if decision["status"] == "APPLIES"
        }
        assert set(decisions) == set(review.REVIEW_KINDS)
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert all(decision["reason"].strip() for decision in decisions.values())
        for kind, decision in decisions.items():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert decision["reason"] == review._MIGRATION_REASON.format(kind=kind)
            else:
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(item["owned_paths"])

        expected = {}
        for kind in applies:
            for obligation in requirements_for(registry, (kind,)):
                if obligation["kind"] == kind:
                    expected[obligation["id"]] = set(obligation["declaration_fields"])
        assert set(item["declarations"]) == set(expected)
        assert all(
            set(item["declarations"][name]) == fields
            for name, fields in expected.items()
        )
        assert all(
            value.strip()
            for declaration in item["declarations"].values()
            for value in declaration.values()
        )
        assert "Tier-0" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]


def test_review_ownership_matches_current_migration_domain_and_prefix_rule() -> None:
    root = Path(__file__).resolve().parents[1]
    catalog = review.review_document()
    all_paths = []
    for object_id, (kind, prefix, has_domain) in PREFIXES.items():
        expected = {
            path.relative_to(root).as_posix()
            for path in (root / "src/verifier/domains/contracts").rglob("*.py")
            if path.stem.split("_", 1)[0].upper() == kind
        }
        if has_domain:
            expected.add("src/verifier/domains/" + prefix + ".py")
        item = catalog[object_id]
        assert item["primary_kind"] == kind
        assert set(item["owned_paths"]) == expected
        assert all((root / path).is_file() for path in item["owned_paths"])
        all_paths.extend(item["owned_paths"])
    assert len(all_paths) == 30
    assert len(all_paths) == len(set(all_paths))


def test_apply_is_atomic_pure_idempotent_complete_and_deep_copied(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    original = deepcopy(rows)
    first = review.apply_package_original_review_computation(root, rows, files)
    second = review.apply_package_original_review_computation(root, first, files)

    assert rows == original
    assert first == second
    assert first is not rows
    document = review.review_document()
    foreign = (set(namespace_registry()) - {"OBJECT"}) - set(review.REVIEW_KINDS)
    for object_id, row in first.items():
        assert set(row["classification"]) == set(namespace_registry()) - {"OBJECT"}
        assert {
            kind: row["classification"][kind] for kind in foreign
        } == {
            kind: original[object_id]["classification"][kind] for kind in foreign
        }
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        for kind in review.REVIEW_KINDS:
            decision = row["classification"][kind]
            expected_decision = document[object_id]["classification"][kind]
            assert decision["status"] == expected_decision["status"]
            assert decision["reason"] == expected_decision["reason"]
            assert [item["path"] for item in decision["evidence"]] == (
                expected_decision["evidence_paths"]
            )
            assert all(
                item["sha256"] == files[item["path"]] for item in decision["evidence"]
            )
        assert applies <= set(row["specializations"])
        expected_declarations = document[object_id]["declarations"]
        assert set(row["obligations"]) == set(expected_declarations)
        for obligation_id, binding in row["obligations"].items():
            kind = obligation_id.split("-", 1)[0]
            assert kind in applies
            assert binding["declaration"] == expected_declarations[obligation_id]
            assert [item["path"] for item in binding["evidence"]] == document[
                object_id
            ]["classification"][kind]["evidence_paths"]
            assert all(
                item["sha256"] == files[item["path"]] for item in binding["evidence"]
            )
        assert all(binding["reason"].strip() for binding in row["obligations"].values())
        assert all(binding["evidence"] for binding in row["obligations"].values())

    first["vstd-token"]["classification"]["ASSET"]["reason"] = "changed"
    assert rows == original
    assert second != first


def test_apply_accumulates_roles_without_erasing_registered_prior_roles(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-bot"]["specializations"] = ["ENV"]

    selected = review.apply_package_original_review_computation(root, rows, files)

    assert selected["vstd-bot"]["specializations"] == [
        "ENV", "ASSET", "FINBOT", "LEDGER", "MARKET", "MEASUREMENT",
        "ROBOT", "SENSOR", "TRANSACTION", "CONTROLLER", "ACTUATOR", "PROTOCOL",
        "POLICY",
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-foreign",
        "missing-owned",
        "unknown",
        "extra-field",
    ],
)
def test_apply_rejects_malformed_or_missing_foreign_questions_atomically(
    tmp_path: Path, mutation: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-model"
    classification = rows[object_id]["classification"]
    foreign_kind = sorted(set(classification) - set(review.REVIEW_KINDS))[0]
    if mutation == "missing-foreign":
        classification.pop(foreign_kind)
    elif mutation == "missing-owned":
        classification.pop(review.REVIEW_KINDS[0])
    elif mutation == "unknown":
        classification["UNREGISTERED"] = _migration_question("UNREGISTERED")
    elif mutation == "applies":
        classification[foreign_kind]["status"] = "APPLIES"
    elif mutation == "does-not-apply":
        classification[foreign_kind]["status"] = "DOES_NOT_APPLY"
    elif mutation == "wrong-reason":
        classification[foreign_kind]["reason"] = "Unreviewed but noncanonical."
    elif mutation == "evidence":
        classification[foreign_kind]["evidence"] = [
            {"path": "foreign.py", "sha256": "sha256:" + "0" * 64}
        ]
    else:
        classification[foreign_kind]["extra"] = True
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_BINDINGS_INVALID"
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "mutation", ["applies", "does-not-apply", "wrong-reason", "evidence"]
)
def test_apply_passes_through_a_foreign_question_decided_by_its_own_catalog(
    tmp_path: Path, mutation: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-model"
    classification = rows[object_id]["classification"]
    foreign_kind = sorted(set(classification) - set(review.REVIEW_KINDS))[0]
    if mutation == "applies":
        classification[foreign_kind]["status"] = "APPLIES"
    elif mutation == "does-not-apply":
        classification[foreign_kind]["status"] = "DOES_NOT_APPLY"
    elif mutation == "wrong-reason":
        classification[foreign_kind]["reason"] = "Decided by its own catalog."
    else:
        classification[foreign_kind]["evidence"] = [
            {"path": "foreign.py", "sha256": "sha256:" + "0" * 64}
        ]
    decided = deepcopy(classification[foreign_kind])
    before = deepcopy(rows)

    result = review.apply_package_original_review_computation(root, rows, files)

    assert result[object_id]["classification"][foreign_kind] == decided
    assert rows == before
    again = review.apply_package_original_review_computation(root, result, files)
    assert again == result


def test_apply_accepts_only_canonical_evidenced_migration_candidates(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-model"
    path = review.review_document()[object_id]["owned_paths"][0]
    evidence = [{"path": path, "sha256": files[path]}]
    rows[object_id]["classification"]["SENSOR"]["evidence"] = deepcopy(evidence)
    rows[object_id]["obligations"]["SENSOR-0.1-acquisition-and-observations"][
        "evidence"
    ] = deepcopy(evidence)

    result = review.apply_package_original_review_computation(root, rows, files)
    assert result[object_id]["classification"]["SENSOR"]["status"] == "APPLIES"

    bad = deepcopy(rows)
    bad[object_id]["classification"]["SENSOR"]["reason"] = "Plausible but noncanonical."
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECISION"
    ):
        review.apply_package_original_review_computation(root, bad, files)


def test_apply_preserves_only_exact_complete_current_reviews(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    assert (
        review.apply_package_original_review_computation(root, selected, files)
        == selected
    )
    object_id = "vstd-token"
    selected[object_id]["classification"]["FINBOT"]["reason"] = (
        "Substituted noncanonical refutation."
    )
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECISION"
    ):
        review.apply_package_original_review_computation(root, selected, files)


def test_unlisted_basis_and_unknown_object_never_gain_complement_refutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    object_id = "vstd-training"
    kind = "ACTUATOR"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        replace(original, refuted=tuple(k for k in original.refuted if k != kind)),
    )
    assert review.review_document()[object_id]["classification"][kind] == {
        "status": "UNRESOLVED",
        "reason": review._MIGRATION_REASON.format(kind=kind),
        "evidence_paths": [],
    }
    root, rows, files = _workspace(tmp_path)
    rows["unknown-future-owner"] = {"sentinel": "unchanged"}
    result = review.apply_package_original_review_computation(root, rows, files)
    assert result[object_id]["classification"][kind] == review._canonical_migration_question(kind)
    assert result["unknown-future-owner"] == {"sentinel": "unchanged"}


def test_apply_preserves_registered_out_of_scope_questions(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-model"
    foreign = (set(namespace_registry()) - {"OBJECT"}) - set(review.REVIEW_KINDS)
    questions = {
        kind: deepcopy(rows[object_id]["classification"][kind]) for kind in foreign
    }

    result = review.apply_package_original_review_computation(root, rows, files)

    assert {
        kind: result[object_id]["classification"][kind] for kind in foreign
    } == questions


@pytest.mark.parametrize(
    "failure",
    [
        "stale_census",
        "missing_source",
        "missing_owned_path",
        "extra_owned_path",
        "missing_object",
        "wrong_primary",
        "new_same_prefix_contract",
        "new_bare_prefix_contract",
        "new_nested_case_contract",
        "new_pyi_contract",
        "new_artifact_contract",
        "refuted_label",
    ],
)
def test_apply_rejects_source_ownership_and_label_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-bot"
    path = review.review_document()[object_id]["owned_paths"][0]
    if failure == "stale_census":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing_source":
        (root / path).unlink()
    elif failure == "missing_owned_path":
        rows[object_id]["surfaces"].remove("file:" + path)
    elif failure == "extra_owned_path":
        rows[object_id]["surfaces"].append("file:unreviewed/new.py")
    elif failure == "missing_object":
        rows.pop(object_id)
    elif failure == "wrong_primary":
        rows[object_id]["kind"] = "OBJECT"
    elif failure == "new_same_prefix_contract":
        added = root / "src/verifier/domains/contracts/bot_new_surface.py"
        added.write_text("# newly owned BOT contract\n", encoding="utf-8")
    elif failure == "new_bare_prefix_contract":
        added = root / "src/verifier/domains/contracts/bot.py"
        added.write_text("# newly owned BOT contract\n", encoding="utf-8")
    elif failure == "new_nested_case_contract":
        added = root / "src/verifier/domains/contracts/nested/BOT_new_surface.py"
        added.parent.mkdir(parents=True)
        added.write_text("# newly owned nested BOT contract\n", encoding="utf-8")
    elif failure == "new_pyi_contract":
        added = root / "src/verifier/domains/contracts/bot_types.pyi"
        added.write_text("VALUE: int\n", encoding="utf-8")
    elif failure == "new_artifact_contract":
        added = root / "src/verifier/domains/contracts/bot_schema.json"
        added.write_text("{}\n", encoding="utf-8")
    else:
        object_id = "vstd-token"
        rows[object_id]["specializations"].append("FINBOT")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_"):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "status_conflict",
        "stale_decision",
        "unowned_decision",
        "partial_decision",
        "evidenced_unresolved",
        "partial_declaration",
        "stale_declaration",
        "unexpected_field",
        "refuted_declaration",
    ],
)
def test_apply_rejects_conflicting_stale_unowned_and_partial_bindings(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    object_id = "vstd-model"
    item = selected[object_id]
    path = review.review_document()[object_id]["owned_paths"][0]
    decision = item["classification"]["SENSOR"]
    obligation = item["obligations"]["SENSOR-0.1-acquisition-and-observations"]
    if failure == "status_conflict":
        decision["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        decision["evidence"][0]["sha256"] = "sha256:" + "a" * 64
    elif failure == "unowned_decision":
        decision["evidence"] = [{"path": "src/unowned.py", "sha256": files[path]}]
    elif failure == "partial_decision":
        decision["reason"] = ""
    elif failure == "evidenced_unresolved":
        decision["status"] = "UNRESOLVED"
    elif failure == "partial_declaration":
        obligation["declaration"]["acquisition"] = ""
    elif failure == "stale_declaration":
        obligation["evidence"][0]["sha256"] = "sha256:" + "b" * 64
    elif failure == "unexpected_field":
        obligation["declaration"]["not_registered"] = "No."
    else:
        finbot = next(
            obligation
            for obligation in requirements_for(namespace_registry(), ("FINBOT",))
            if obligation["kind"] == "FINBOT"
        )
        item["obligations"][finbot["id"]] = {
            "reason": "Contradictory refuted declaration.",
            "evidence": [{"path": path, "sha256": files[path]}],
            "declaration": {
                field: "Contradictory " + field + "."
                for field in finbot["declaration_fields"]
            },
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_"):
        review.apply_package_original_review_computation(root, selected, files)
    assert selected == before


def test_apply_rejects_source_change_during_review(tmp_path: Path, monkeypatch) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-agent"
    path = review.review_document()[object_id]["owned_paths"][0]
    target = root / path
    original_snapshot = review._source_snapshot
    changed = False

    def changing_snapshot(selected_root, paths, *, object_id):
        nonlocal changed
        result = original_snapshot(selected_root, paths, object_id=object_id)
        if object_id == "vstd-agent" and not changed:
            target.write_bytes(b"# changed after opening snapshot\n")
            changed = True
        return result

    monkeypatch.setattr(review, "_source_snapshot", changing_snapshot)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SOURCE_CHANGED"
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


def test_apply_rejects_newly_owned_contract_during_review(
    tmp_path: Path, monkeypatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    added = root / "src/verifier/domains/contracts/arch_late.py"
    original_snapshot = review._source_snapshot
    changed = False

    def changing_snapshot(selected_root, paths, *, object_id):
        nonlocal changed
        result = original_snapshot(selected_root, paths, object_id=object_id)
        if object_id == "vstd-architecture" and not changed:
            added.write_text("# newly owned during review\n", encoding="utf-8")
            changed = True
        return result

    monkeypatch.setattr(review, "_source_snapshot", changing_snapshot)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_MIGRATION_DENOMINATOR_CHANGED",
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


def test_consequence_boundaries_distinguish_the_seven_objects() -> None:
    catalog = review.review_document()
    model = catalog["vstd-model"]
    agent = catalog["vstd-agent"]
    bot = catalog["vstd-bot"]
    token = catalog["vstd-token"]
    train = catalog["vstd-training"]

    assert model["classification"]["SENSOR"]["status"] == "APPLIES"
    assert "fresh" in model["classification"]["SENSOR"]["reason"].lower()
    assert model["classification"]["CONTROLLER"]["status"] == "DOES_NOT_APPLY"
    assert {
        kind
        for kind, decision in agent["classification"].items()
        if decision["status"] == "APPLIES"
    } == set(review.REVIEW_KINDS)
    assert bot["classification"]["CONTROLLER"]["status"] == "APPLIES"
    assert bot["classification"]["ACTUATOR"]["status"] == "APPLIES"
    assert bot["declarations"]["ACTUATOR-0.1-command-to-effect"][
        "effect_domains"
    ].startswith("SIMULATED_ONLY")
    for kind in ("ROBOT", "FINBOT", "SENSOR"):
        assert bot["classification"][kind]["status"] == "APPLIES"
        assert "sole authored reasons.vstd" in bot["classification"][kind]["reason"]
        assert all(
            "NOT_ESTABLISHED" in value
            for obligation_id, declaration in bot["declarations"].items()
            if obligation_id.startswith(kind + "-")
            for value in declaration.values()
        )
    assert catalog["vstd-architecture"]["classification"]["MEASUREMENT"]["status"] == "APPLIES"
    assert train["classification"]["MEASUREMENT"]["status"] == "UNRESOLVED"
    assert token["classification"]["LEDGER"]["status"] == "UNRESOLVED"
    assert token["classification"]["ASSET"]["status"] == "APPLIES"
    assert (
        "not an authority grant"
        in token["declarations"]["ASSET-0.1-identity-and-quantity"]["rights"]
    )
    assert token["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
    assert train["classification"]["CONTROLLER"]["status"] == "DOES_NOT_APPLY"
    assert train["classification"]["ACTUATOR"]["status"] == "DOES_NOT_APPLY"
    assert "retained" in train["classification"]["ACTUATOR"]["reason"].lower()
    for object_id, item in catalog.items():
        if object_id in {"vstd-architecture", "vstd-agent", "vstd-bot"}:
            continue
        assert item["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
        assert item["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"


def _complement_catalog(object_id: str) -> review._Review:
    """A complement-shaped refutation: every unapplied kind is refuted by default."""
    original = review._REVIEWS[object_id]
    applicable = set(original.applicable)
    return replace(
        original,
        refuted=tuple(kind for kind in review.REVIEW_KINDS if kind not in applicable),
    )


def test_complement_shaped_catalog_cannot_refute_a_kind_the_source_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    # token.py names a ledger mechanism; the complement catalog refutes LEDGER.
    path = "src/verifier/domains/token.py"
    raw = b"ledger = {}\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    monkeypatch.setitem(review._REVIEWS, "vstd-token", _complement_catalog("vstd-token"))
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_MECHANISM_CONTRADICTS_REFUTATION:vstd-token:LEDGER",
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    ("object_id", "kind", "word"),
    [
        ("vstd-training", "ACTUATOR", "actuator"),
        ("vstd-hypergraph", "MEASUREMENT", "measurement"),
    ],
)
def test_source_naming_a_refuted_role_cannot_be_substituted_as_not_applicable(
    tmp_path: Path,
    object_id: str,
    kind: str,
    word: str,
) -> None:
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS[object_id].owned_paths[0]
    raw = ("# rewritten\n" + word + " = 1\n").encode()
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="MECHANISM_CONTRADICTS_REFUTATION:" + object_id + ":" + kind,
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


def test_stale_pre_audit_bot_robot_application_fails_closed(tmp_path: Path) -> None:
    """A prior simulated-BOT-as-ROBOT decision cannot survive current source."""
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    stale = deepcopy(selected)
    decision = stale["vstd-bot"]["classification"]["ROBOT"]
    decision["status"] = "APPLIES"
    decision["reason"] = (
        "The retained simulated action was previously treated as a ROBOT carrier."
    )
    before = deepcopy(stale)
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECISION"):
        review.apply_package_original_review_computation(root, stale, files)
    assert stale == before


def _generated_refutation(object_id: str, kind: str, files: dict[str, str]) -> dict:
    """The exact DOES_NOT_APPLY cell this catalog writes for a refuted kind."""
    item = review._REVIEWS[object_id]
    return {
        "status": "DOES_NOT_APPLY",
        "reason": item.reasons[kind],
        "evidence": [
            {"path": path, "sha256": files[path]} for path in item.owned_paths
        ],
    }


def test_record_gaps_reopens_a_refutation_the_source_contradicts_instead_of_aborting(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id, kind = "vstd-hypergraph", "ROBOT"
    path = review._REVIEWS[object_id].owned_paths[0]
    raw = b"# rewritten\nrobot = 1\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    rows[object_id]["classification"][kind] = _generated_refutation(
        object_id, kind, files
    )
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="MECHANISM_CONTRADICTS_REFUTATION:" + object_id + ":" + kind
    ):
        review.apply_package_original_review_computation(root, rows, files)

    gaps: list[dict[str, object]] = []
    result = review.apply_package_original_review_computation(
        root, rows, files, record_gaps=True, gaps=gaps
    )

    assert result[object_id]["classification"][kind] == (
        review._canonical_migration_question(kind)
    )
    assert gaps == [
        {
            "stage": "computation",
            "object_id": object_id,
            "kind": kind,
            "gap": "REFUTATION_REOPENED_MECHANISM_WORD",
            "words": ["robot"],
        }
    ]
    assert rows == before
    again_gaps: list[dict[str, object]] = []
    again = review.apply_package_original_review_computation(
        root, result, files, record_gaps=True, gaps=again_gaps
    )
    assert again == result
    assert len(again_gaps) == 1


def test_record_gaps_still_rejects_a_substituted_refutation_it_did_not_generate(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id, kind = "vstd-hypergraph", "ROBOT"
    path = review._REVIEWS[object_id].owned_paths[0]
    raw = b"# rewritten\nrobot = 1\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    cell = _generated_refutation(object_id, kind, files)
    cell["reason"] = "A hand-written refutation."
    rows[object_id]["classification"][kind] = cell
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECISION"):
        review.apply_package_original_review_computation(
            root, rows, files, record_gaps=True, gaps=[]
        )
    assert rows == before


def test_real_physical_source_path_keeps_bot_robot_obligation_without_claiming_effect(
    tmp_path: Path,
) -> None:
    """A physical-looking alias cannot turn conservative applicability into an effect claim."""
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = b"REAL_PHYSICAL = 'REAL_PHYSICAL'\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    selected = review.apply_package_original_review_computation(root, rows, files)
    decision = selected["vstd-bot"]["classification"]["ROBOT"]
    assert decision["status"] == "APPLIES"
    assert "sole authored reasons.vstd" in decision["reason"]
    assert all(
        "NOT_ESTABLISHED" in value
        for obligation_id, declaration in review.review_document()["vstd-bot"]["declarations"].items()
        if obligation_id.startswith("ROBOT-")
        for value in declaration.values()
    )


@pytest.mark.parametrize(
    "source",
    [
        "external_endpoint = 'gpio_channel_7'\n",
        "physicalOutput = 'MODBUS-link'\n",
        "plc_command = 'write'\n",
        "servo-control = 1\n".replace("servo-control", "servo_control"),
        "relayOutput = True\n",
        "CAN_endpoint = 'bus0'\n",
        "rosCommand = 'publish'\n",
        "from board import GPIO_COMMAND\n",
        "endpoint = 'g' + 'pio'\n",
        "getattr(board, 'gpio_' + 'write')\n",
    ],
)
def test_physical_control_endpoint_alias_keeps_conservative_robot_obligation(
    tmp_path: Path,
    source: str,
) -> None:
    """Common physical-control aliases cannot promote retention into mechanism truth."""
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = source.encode()
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    selected = review.apply_package_original_review_computation(root, rows, files)
    decision = selected["vstd-bot"]["classification"]["ROBOT"]
    assert decision["status"] == "APPLIES"
    assert "neither a concrete mechanism" in decision["reason"]


@pytest.mark.parametrize(
    "source",
    [
        '"""The GPIO command example is documentation only."""\nvalue = 1\n',
        "# GPIO command example only\nvalue = 1\n",
        "gpio_samples = data\n",
        "output = 'report'\nprotocol = 'ROS'\n",
        "references = {'endpoint': 'GPIO', 'command': 'write'}\n",
        "checker_references = ('MODBUS', 'output')\n",
        "SIMULATED_ONLY_GPIO_COMMAND = 'transition'\n",
        "simulated_gpio_output = 'sim-state'\n",
        "can_write_report = True\n",
        "ros_output_schema = {'type': 'string'}\n",
    ],
)
def test_physical_alias_guard_ignores_non_effect_references_and_simulation(
    tmp_path: Path,
    source: str,
) -> None:
    """Documentation, data vocabulary and explicit simulation are not reach."""
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = source.encode()
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)

    selected = review.apply_package_original_review_computation(root, rows, files)

    assert selected["vstd-bot"]["classification"]["ROBOT"]["status"] == "APPLIES"
    assert "neither a concrete mechanism" in selected["vstd-bot"]["classification"]["ROBOT"]["reason"]


def test_simulated_label_and_physical_alias_still_cannot_claim_a_robot_effect(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = (
        b"SIMULATED_ONLY_GPIO_COMMAND = 'transition'\n"
        b"external_endpoint = 'gpio_channel_7'\n"
    )
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)

    selected = review.apply_package_original_review_computation(root, rows, files)
    decision = selected["vstd-bot"]["classification"]["ROBOT"]
    assert decision["status"] == "APPLIES"
    assert "external effect" in decision["reason"]


@pytest.mark.parametrize(
    "source",
    [
        "broker_endpoint = 'account_7'\n",
        "bankTransfer = 'execute'\n",
        "SWIFT_endpoint = 'send'\n",
        "wire_transfer = True\n",
    ],
)
def test_real_financial_endpoint_alias_keeps_conservative_finbot_obligation(
    tmp_path: Path,
    source: str,
) -> None:
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = source.encode()
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)

    selected = review.apply_package_original_review_computation(root, rows, files)
    decision = selected["vstd-bot"]["classification"]["FINBOT"]
    assert decision["status"] == "APPLIES"
    assert "neither a concrete mechanism" in decision["reason"]


@pytest.mark.parametrize(
    "source",
    [
        "SIMULATED_ONLY_BROKER_ORDER = 'fill'\n",
        "simulated_bank_transfer = 'sim-state'\n",
        "references = {'endpoint': 'broker', 'transfer': 'wire'}\n",
        "bank_samples = data\n",
    ],
)
def test_financial_alias_guard_ignores_references_and_simulation(
    tmp_path: Path,
    source: str,
) -> None:
    root, rows, files = _workspace(tmp_path)
    path = review._REVIEWS["vstd-bot"].owned_paths[0]
    raw = source.encode()
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)

    selected = review.apply_package_original_review_computation(root, rows, files)

    assert selected["vstd-bot"]["classification"]["FINBOT"]["status"] == "APPLIES"
    assert "neither a concrete mechanism" in selected["vstd-bot"]["classification"]["FINBOT"]["reason"]


@pytest.mark.parametrize("specialization", ["OBJECT", "GHOST"])
def test_object_or_unregistered_specialization_cannot_escape_review(
    tmp_path: Path, specialization: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-bot"]["specializations"].append(specialization)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SPECIALIZATION_UNREGISTERED:vstd-bot",
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


def test_failure_in_last_object_leaves_every_input_row_unchanged(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-token"]["specializations"].append("GHOST")
    before = deepcopy(rows)
    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_SPECIALIZATION_UNREGISTERED:vstd-token",
    ):
        review.apply_package_original_review_computation(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_declaration_must_equal_reviewed_text(
    tmp_path: Path, object_id: str
) -> None:
    # A non-blank declaration that is not the reviewed Tier-0 text is a
    # conflicting binding, not a compatible current review.
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    selected[object_id]["obligations"][obligation_id]["declaration"]["scope"] = (
        "Non-blank text that names a different object's policy scope."
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_computation(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_obligation_reason_substitution_is_rejected(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    selected[object_id]["obligations"][obligation_id]["reason"] = (
        review._obligation_reason(review._REVIEWS[object_id], "PROTOCOL")
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_computation(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_obligation_evidence_from_another_object_is_rejected(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_computation(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    foreign_owner = next(
        other for other in review.review_document() if other != object_id
    )
    foreign_path = review.review_document()[foreign_owner]["owned_paths"][0]
    selected[object_id]["obligations"][obligation_id]["evidence"] = [
        {"path": foreign_path, "sha256": files[foreign_path]}
    ]
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_COMPUTATION_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_computation(root, selected, files)
    assert selected == before

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

from verifier.runtime import package_original_review_people as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


EXPECTED_APPLICABILITY = {
    "vstd-actor": set(review.REVIEW_KINDS),
    "vstd-collective": set(review.REVIEW_KINDS),
    "vstd-human": set(review.REVIEW_KINDS),
    "vstd-identity": {"PROTOCOL", "POLICY"},
    "vstd-owner": {"ASSET", "PROTOCOL", "POLICY"},
    "vstd-receipt": {"PROTOCOL", "POLICY"},
    "vstd-role": {"PROTOCOL", "POLICY"},
}

PREFIXES = {
    "vstd-actor": ("ACTOR", "actor", True),
    "vstd-collective": ("COLLECTIVE", "collective", True),
    "vstd-human": ("HUMAN", "human", True),
    "vstd-identity": ("IDENTITY", "identity", True),
    "vstd-owner": ("OWNER", "owner", True),
    "vstd-receipt": ("RECEIPT", "receipt", False),
    "vstd-role": ("ROLE", "role", True),
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
    assert tuple(first) == review.PEOPLE_OBJECT_IDS
    assert set(first) == set(EXPECTED_APPLICABILITY)
    assert sum(len(item["owned_paths"]) for item in first.values()) == 31
    assert sum(len(item["classification"]) for item in first.values()) == 84
    assert sum(
        decision["status"] == "APPLIES"
        for item in first.values()
        for decision in item["classification"].values()
    ) == 45
    assert sum(len(item["declarations"]) for item in first.values()) == 135

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
        # UNRESOLVED carries the migration question and no evidence by design.
        for kind, decision in decisions.items():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert decision["reason"] == review._MIGRATION_REASON.format(kind=kind)
            else:
                assert set(decision["evidence_paths"]) == set(item["owned_paths"])

        expected = {}
        for kind in applies:
            for obligation in requirements_for(registry, (kind,)):
                if obligation["kind"] == kind:
                    expected[obligation["id"]] = set(
                        obligation["declaration_fields"]
                    )
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
        assert "unestablished" in item["claim_boundary"]


def test_review_ownership_matches_current_migration_domain_and_prefix_rule() -> None:
    root = Path(__file__).resolve().parents[1]
    catalog = review.review_document()
    all_paths = []
    for object_id, (kind, prefix, has_domain) in PREFIXES.items():
        expected = {
            path.relative_to(root).as_posix()
            for path in (root / "src/verifier/domains/contracts").glob(
                prefix + "_*.py"
            )
        }
        if has_domain:
            expected.add("src/verifier/domains/" + prefix + ".py")
        item = catalog[object_id]
        assert item["primary_kind"] == kind
        assert set(item["owned_paths"]) == expected
        assert all((root / path).is_file() for path in item["owned_paths"])
        all_paths.extend(item["owned_paths"])
    assert len(all_paths) == 31
    assert len(all_paths) == len(set(all_paths))


def test_apply_is_atomic_pure_idempotent_complete_and_deep_copied(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    original = deepcopy(rows)
    first = review.apply_package_original_review_people(root, rows, files)
    second = review.apply_package_original_review_people(root, first, files)

    assert rows == original
    assert first == second
    assert first is not rows
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
        assert applies <= set(row["specializations"])
        assert all(
            obligation_id.split("-", 1)[0] in applies
            for obligation_id in row["obligations"]
        )
        assert all(
            binding["reason"].strip() for binding in row["obligations"].values()
        )
        assert all(binding["evidence"] for binding in row["obligations"].values())

    first["vstd-human"]["classification"]["POLICY"]["reason"] = "changed"
    assert rows == original
    assert second != first


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
    object_id = "vstd-actor"
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
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_CLASSIFICATION_INVALID"
    ):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "mutation", ["applies", "does-not-apply", "wrong-reason", "evidence"]
)
def test_apply_passes_through_a_foreign_question_decided_by_its_own_catalog(
    tmp_path: Path, mutation: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-actor"
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

    result = review.apply_package_original_review_people(root, rows, files)

    assert result[object_id]["classification"][foreign_kind] == decided
    assert rows == before
    again = review.apply_package_original_review_people(root, result, files)
    assert again == result


def test_apply_allows_absent_untriggered_templates_and_keeps_unrelated_obligations(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    for row in rows.values():
        row["obligations"] = {
            "BASE-0.1-unrelated": {
                "reason": "Existing primary-kind declaration.",
                "evidence": [],
                "declaration": {"field": "Primary-kind value."},
            }
        }

    result = review.apply_package_original_review_people(root, rows, files)

    for object_id, row in result.items():
        assert "BASE-0.1-unrelated" in row["obligations"]
        assert {
            name for name in row["obligations"] if not name.startswith("BASE-")
        } == set(review.review_document()[object_id]["declarations"])


def test_apply_accepts_only_canonical_current_migration_candidates(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-identity"
    path = review.review_document()[object_id]["owned_paths"][0]
    evidence = [{"path": path, "sha256": files[path]}]
    rows[object_id]["classification"]["PROTOCOL"]["evidence"] = deepcopy(
        evidence
    )
    rows[object_id]["obligations"][
        "PROTOCOL-0.1-participants-and-states"
    ]["evidence"] = deepcopy(evidence)

    result = review.apply_package_original_review_people(root, rows, files)
    assert result[object_id]["classification"]["PROTOCOL"]["status"] == "APPLIES"

    bad = deepcopy(rows)
    bad[object_id]["classification"]["PROTOCOL"][
        "reason"
    ] = "Plausible but noncanonical."
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECISION"):
        review.apply_package_original_review_people(root, bad, files)


def test_apply_preserves_only_exact_complete_current_reviews(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    assert review.apply_package_original_review_people(root, selected, files) == selected
    object_id = "vstd-owner"
    selected[object_id]["classification"]["FINBOT"]["reason"] = (
        "Substituted noncanonical refutation."
    )
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECISION"):
        review.apply_package_original_review_people(root, selected, files)


def test_unlisted_basis_and_unknown_object_never_gain_complement_refutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    object_id = "vstd-actor"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        replace(
            original,
            applicable=tuple(k for k in original.applicable if k != "LEDGER"),
            declarations={
                key: value
                for key, value in original.declarations.items()
                if not key.startswith("LEDGER-")
            },
        ),
    )
    assert review.review_document()[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": review._MIGRATION_REASON.format(kind="LEDGER"),
        "evidence_paths": [],
    }
    root, rows, files = _workspace(tmp_path)
    rows["unknown-future-owner"] = {"sentinel": "unchanged"}
    result = review.apply_package_original_review_people(root, rows, files)
    assert result[object_id]["classification"]["LEDGER"] == review._canonical_migration_question("LEDGER")
    assert result["unknown-future-owner"] == {"sentinel": "unchanged"}


def test_apply_preserves_registered_out_of_scope_questions(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-actor"
    foreign = (set(namespace_registry()) - {"OBJECT"}) - set(review.REVIEW_KINDS)
    questions = {
        kind: deepcopy(rows[object_id]["classification"][kind]) for kind in foreign
    }

    result = review.apply_package_original_review_people(root, rows, files)

    assert {
        kind: result[object_id]["classification"][kind] for kind in foreign
    } == questions


@pytest.mark.parametrize(
    "failure",
    [
        "stale_census",
        "missing_source",
        "missing_owned_path",
        "duplicate_owned_path",
        "extra_owned_path",
        "prefix_source_added",
        "missing_object",
        "wrong_primary",
        "refuted_label",
    ],
)
def test_apply_rejects_source_ownership_and_label_drift_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-human"
    path = review.review_document()[object_id]["owned_paths"][0]
    if failure == "stale_census":
        files[path] = "sha256:" + "0" * 64
    elif failure == "missing_source":
        (root / path).unlink()
    elif failure == "missing_owned_path":
        rows[object_id]["surfaces"].remove("file:" + path)
    elif failure == "duplicate_owned_path":
        rows[object_id]["surfaces"].append("file:" + path)
    elif failure == "extra_owned_path":
        rows[object_id]["surfaces"].append("file:unreviewed/new.py")
    elif failure == "prefix_source_added":
        added = root / "src/verifier/domains/contracts/human_new_surface.py"
        added.write_text("# newly discovered current source\n", encoding="utf-8")
    elif failure == "missing_object":
        rows.pop(object_id)
    elif failure == "wrong_primary":
        rows[object_id]["kind"] = "OBJECT"
    else:
        object_id = "vstd-identity"
        rows[object_id]["specializations"].append("ROBOT")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_"):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "failure",
    [
        "missing_decision",
        "extra_decision",
        "altered_unresolved_reason",
        "status_conflict",
        "stale_decision",
        "unowned_decision",
        "duplicate_decision_evidence",
        "partial_decision",
        "evidenced_noncanonical_unresolved",
        "partial_declaration",
        "stale_declaration",
        "unowned_declaration",
        "unexpected_field",
        "stale_obligation",
        "refuted_declaration",
    ],
)
def test_apply_rejects_noncanonical_conflicting_stale_and_partial_bindings(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    object_id = "vstd-identity"
    item = selected[object_id]
    path = review.review_document()[object_id]["owned_paths"][0]
    decision = item["classification"]["PROTOCOL"]
    obligation = item["obligations"]["PROTOCOL-0.1-participants-and-states"]
    if failure == "missing_decision":
        item["classification"].pop("MARKET")
    elif failure == "extra_decision":
        item["classification"]["UNREGISTERED"] = deepcopy(decision)
    elif failure == "altered_unresolved_reason":
        decision.update(
            status="UNRESOLVED", reason="Unresolved but not migration-canonical."
        )
        decision["evidence"] = []
    elif failure == "status_conflict":
        decision["status"] = "DOES_NOT_APPLY"
    elif failure == "stale_decision":
        decision["evidence"][0]["sha256"] = "sha256:" + "a" * 64
    elif failure == "unowned_decision":
        decision["evidence"] = [
            {"path": "src/unowned.py", "sha256": files[path]}
        ]
    elif failure == "duplicate_decision_evidence":
        decision["evidence"].append(deepcopy(decision["evidence"][0]))
    elif failure == "partial_decision":
        decision["reason"] = ""
    elif failure == "evidenced_noncanonical_unresolved":
        decision["status"] = "UNRESOLVED"
    elif failure == "partial_declaration":
        obligation["declaration"]["participants"] = ""
    elif failure == "stale_declaration":
        obligation["evidence"][0]["sha256"] = "sha256:" + "b" * 64
    elif failure == "unowned_declaration":
        obligation["evidence"] = [
            {"path": "src/unowned.py", "sha256": files[path]}
        ]
    elif failure == "unexpected_field":
        obligation["declaration"]["not_registered"] = "No."
    elif failure == "stale_obligation":
        item["obligations"]["PROTOCOL-0.0-retired"] = deepcopy(obligation)
    else:
        item["obligations"]["ROBOT-0.1-agent-to-actuator-binding"] = {
            "reason": "Contradictory physical declaration.",
            "evidence": [{"path": path, "sha256": files[path]}],
            "declaration": {
                field: "Contradictory " + field + "."
                for field in ("agent", "harness", "controllers", "actuators")
            },
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_"):
        review.apply_package_original_review_people(root, selected, files)
    assert selected == before


def test_apply_rejects_source_change_during_review(tmp_path: Path, monkeypatch) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-actor"
    path = review.review_document()[object_id]["owned_paths"][0]
    target = root / path
    original_snapshot = review._source_snapshot
    changed = False

    def changing_snapshot(selected_root, paths, *, object_id):
        nonlocal changed
        result = original_snapshot(selected_root, paths, object_id=object_id)
        if object_id == "vstd-actor" and not changed:
            target.write_bytes(b"# changed after opening snapshot\n")
            changed = True
        return result

    monkeypatch.setattr(review, "_source_snapshot", changing_snapshot)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError, match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_SOURCE_CHANGED"
    ):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


def test_human_counts_are_not_mislabeled_as_measurement_or_sensor() -> None:
    human = review.review_document()["vstd-human"]
    for kind in ("MEASUREMENT", "SENSOR"):
        assert human["classification"][kind]["status"] == "APPLIES"
        assert "sole authored reasons.vstd" in human["classification"][kind]["reason"]
        declarations = {
            field
            for obligation_id, declaration in human["declarations"].items()
            if obligation_id.startswith(kind + "-")
            for field in declaration.values()
        }
        assert declarations
        assert all("NOT_ESTABLISHED" in value for value in declarations)


def test_identity_replay_is_not_mislabeled_as_controller_or_actuator() -> None:
    identity = review.review_document()["vstd-identity"]
    controller = identity["classification"]["CONTROLLER"]
    actuator = identity["classification"]["ACTUATOR"]
    # identity_presentation.py names controller_id and terminal_controller, so a
    # CONTROLLER refutation is not positively established: UNRESOLVED, not DNE.
    assert controller["status"] == "UNRESOLVED"
    assert controller["reason"] == review._MIGRATION_REASON.format(kind="CONTROLLER")
    assert actuator["status"] == "DOES_NOT_APPLY"
    assert "ephemeral local list" in actuator["reason"]
    assert "no command-to-effect" in actuator["reason"]


def test_owner_asset_boundary_does_not_infer_money_title_or_market() -> None:
    owner = review.review_document()["vstd-owner"]
    assert owner["classification"]["ASSET"]["status"] == "APPLIES"
    assert owner["classification"]["MARKET"]["status"] == "DOES_NOT_APPLY"
    assert owner["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
    declarations = owner["declarations"]
    assert "not proof of legal title" in declarations[
        "ASSET-0.1-identity-and-quantity"
    ]["identity"]
    assert "liens" in declarations["ASSET-0.3-custody-and-encumbrance"][
        "encumbrances"
    ]
    assert "economic backing" in declarations[
        "ASSET-0.2-issuance-and-redemption"
    ]["backing_claims"]


def test_replay_authenticity_physical_and_financial_boundaries_remain_explicit() -> None:
    catalog = review.review_document()
    receipt = catalog["vstd-receipt"]
    # receipt_validation_replay.py names ledger_registration, so LEDGER is not refuted.
    assert receipt["classification"]["LEDGER"]["status"] == "UNRESOLVED"
    assert "key custody" in receipt["declarations"][
        "PROTOCOL-0.2-ordering-and-replay"
    ]["message_authority"]
    retained_agency = {"vstd-actor", "vstd-collective", "vstd-human"}
    for object_id, item in catalog.items():
        if object_id in retained_agency:
            assert item["classification"]["LEDGER"]["status"] == "APPLIES"
        elif object_id == "vstd-receipt":
            assert item["classification"]["LEDGER"]["status"] == "UNRESOLVED"
        else:
            assert item["classification"]["LEDGER"]["status"] == "DOES_NOT_APPLY"
        if object_id in retained_agency:
            for kind in ("TRANSACTION", "ROBOT", "FINBOT"):
                assert item["classification"][kind]["status"] == "APPLIES"
        else:
            assert item["classification"]["TRANSACTION"]["status"] == "DOES_NOT_APPLY"
            assert item["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
            assert item["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
            assert "physical" in item["classification"]["ROBOT"]["reason"]
            assert "live-money" in item["classification"]["FINBOT"]["reason"]


def _catalog_forcing_refutation(object_id: str, kind: str) -> review._Review:
    """Replace one applicable role with a source-contradicting refutation."""
    original = review._REVIEWS[object_id]
    return replace(
        original,
        applicable=tuple(item for item in original.applicable if item != kind),
        refuted=(*original.refuted, kind),
        declarations={
            obligation_id: declaration
            for obligation_id, declaration in original.declarations.items()
            if not obligation_id.startswith(kind + "-")
        },
    )


def test_complement_shaped_catalog_cannot_refute_a_kind_the_source_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, rows, files = _workspace(tmp_path)
    # collective_closure.py names a ledger mechanism; a complement-shaped
    # catalog that refutes LEDGER for COLLECTIVE must fail closed.
    path = "src/verifier/domains/contracts/collective_closure.py"
    raw = b"ledger = {}\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    monkeypatch.setitem(
        review._REVIEWS,
        "vstd-collective",
        _catalog_forcing_refutation("vstd-collective", "LEDGER"),
    )
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="MECHANISM_CONTRADICTS_REFUTATION:vstd-collective:LEDGER"):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


def test_unparseable_owned_source_fails_closed_with_coded_error(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    path = "src/verifier/domains/human.py"
    raw = b"def broken(:\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    with pytest.raises(ValueError, match="SOURCE_UNPARSEABLE:vstd-human:"):
        review.apply_package_original_review_people(root, rows, files)


def test_mechanism_words_ignore_docstrings_and_prose_literals() -> None:
    code = (
        '"""A ledger, a market, and a robot appear only in prose here."""\n'
        "def check() -> str:\n"
        '    """Mentions an actuator and money in a docstring."""\n'
        '    note = "this sentence about a payment is prose, not a token"\n'
        "    return note\n"
    )
    # Names only: the return annotation is the Name ``str``; prose literals and
    # docstrings contribute nothing.
    assert review._code_words(code) == {"check", "note", "str"}
    assert review._code_words("ledger = 1\n") & review._MECHANISM_WORDS["LEDGER"]
    assert not review._code_words(code) & review._MECHANISM_WORDS["LEDGER"]
    assert not review._code_words(code) & review._MECHANISM_WORDS["ROBOT"]
    assert review._code_words("state.actuation_check = True\n") & review._MECHANISM_WORDS["ACTUATOR"]


@pytest.mark.parametrize("specialization", ["OBJECT", "GHOST"])
def test_object_or_unregistered_specialization_cannot_escape_review(
    tmp_path: Path, specialization: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-human"]["specializations"].append(specialization)
    with pytest.raises(ValueError, match="SPECIALIZATION_UNREGISTERED:vstd-human"):
        review.apply_package_original_review_people(root, rows, files)


def test_forged_decision_substituted_from_another_object_is_rejected(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    forged = deepcopy(rows)
    # A complete HUMAN PROTOCOL decision placed under ACTOR names HUMAN sources.
    forged["vstd-actor"]["classification"]["PROTOCOL"] = deepcopy(
        selected["vstd-human"]["classification"]["PROTOCOL"]
    )
    with pytest.raises(ValueError, match="DECISION_CONFLICT:vstd-actor:PROTOCOL"):
        review.apply_package_original_review_people(root, forged, files)


def test_failure_in_last_object_leaves_every_input_row_unchanged(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-receipt"]["specializations"].append("OBJECT")
    before = deepcopy(rows)
    with pytest.raises(ValueError):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("object_id", sorted(EXPECTED_APPLICABILITY))
def test_preserved_declaration_must_equal_reviewed_text(
    tmp_path: Path, object_id: str
) -> None:
    # A non-blank declaration that is not the reviewed Tier-0 text is a
    # conflicting binding, not a compatible current review.
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    selected[object_id]["obligations"][obligation_id]["declaration"]["scope"] = (
        "Non-blank text that names a different object's policy scope."
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_people(root, selected, files)
    assert selected == before


def test_preserved_obligation_evidence_from_another_object_is_rejected(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    foreign_path = review.review_document()["vstd-human"]["owned_paths"][0]
    selected["vstd-actor"]["obligations"]["PROTOCOL-0.1-participants-and-states"][
        "evidence"
    ] = [{"path": foreign_path, "sha256": files[foreign_path]}]
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECLARATION_CONFLICT:vstd-actor:",
    ):
        review.apply_package_original_review_people(root, selected, files)
    assert selected == before


@pytest.mark.parametrize(
    "case",
    ["bare_prefix", "pyi_stub", "json_artifact", "nested_uppercase"],
)
def test_omitted_original_interface_of_any_suffix_or_depth_fails_closed(
    tmp_path: Path, case: str
) -> None:
    # The migration owner rule is any file under domains/contracts whose stem
    # prefix names the kind, regardless of suffix, nesting, or case.
    root, rows, files = _workspace(tmp_path)
    contracts = root / "src/verifier/domains/contracts"
    added = {
        "bare_prefix": contracts / "human.py",
        "pyi_stub": contracts / "human_types.pyi",
        "json_artifact": contracts / "human_schema.json",
        "nested_uppercase": contracts / "nested" / "HUMAN_new_surface.py",
    }[case]
    added.parent.mkdir(parents=True, exist_ok=True)
    added.write_text("# newly discovered HUMAN contract surface\n", encoding="utf-8")
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_MIGRATION_DENOMINATOR_CHANGED:vstd-human",
    ):
        review.apply_package_original_review_people(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("object_id", sorted(EXPECTED_APPLICABILITY))
def test_preserved_obligation_reason_substitution_is_rejected(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_people(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    substituted = review._obligation_reason(
        review._REVIEWS[object_id], "PROTOCOL"
    )
    selected[object_id]["obligations"][obligation_id]["reason"] = substituted
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_PEOPLE_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_people(root, selected, files)
    assert selected == before

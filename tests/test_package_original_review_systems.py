from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from verifier.runtime import package_original_review_systems as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


EXPECTED_APPLICABILITY = {
    "vstd-package-graph": {"POLICY"},
    "vstd-space": {"POLICY"},
    "vstd-time": {"POLICY"},
    "vstd-event": {"POLICY"},
    "vstd-environment": {"MEASUREMENT", "SENSOR", "POLICY"},
    "vstd-data": {"MEASUREMENT", "POLICY"},
    "vstd-benchmark": set(review.REVIEW_KINDS),
}

EXPECTED_PATHS = {
    "vstd-package-graph": [
        "src/verifier/domains/contracts/graph_closure.py",
        "src/verifier/domains/contracts/graph_lineage.py",
        "src/verifier/domains/contracts/graph_order.py",
        "src/verifier/domains/contracts/graph_statics.py",
    ],
    "vstd-space": [
        "src/verifier/domains/contracts/space_closure.py",
        "src/verifier/domains/contracts/space_layout.py",
        "src/verifier/domains/contracts/space_migration.py",
    ],
    "vstd-time": [
        "src/verifier/domains/contracts/time_closure.py",
        "src/verifier/domains/contracts/time_order.py",
        "src/verifier/domains/contracts/time_strict.py",
    ],
    "vstd-event": [
        "src/verifier/domains/contracts/event_closure.py",
        "src/verifier/domains/contracts/event_dispatch.py",
        "src/verifier/domains/contracts/event_prerequisites.py",
    ],
    "vstd-environment": [
        "src/verifier/domains/env.py",
        "src/verifier/domains/contracts/env_checks_projection.py",
        "src/verifier/domains/contracts/env_checks.py",
        "src/verifier/domains/contracts/env_configuration_surface.py",
        "src/verifier/domains/contracts/env_executable.py",
        "src/verifier/domains/contracts/env_pin_closure.py",
    ],
    "vstd-data": [
        "src/verifier/domains/data.py",
        "src/verifier/domains/contracts/data_checks_projection.py",
        "src/verifier/domains/contracts/data_checks.py",
        "src/verifier/domains/contracts/data_distribution.py",
    ],
    "vstd-benchmark": [
        "src/verifier/domains/bench.py",
        "src/verifier/domains/contracts/bench_attempts.py",
        "src/verifier/domains/contracts/bench_checks_projection.py",
        "src/verifier/domains/contracts/bench_checks.py",
    ],
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


def _all_obligations() -> dict[str, dict]:
    obligations = {}
    registry = namespace_registry()
    for kind in review.REVIEW_KINDS:
        for obligation in requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            obligations[obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
    return obligations


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    rows: dict[str, dict] = {}
    files: dict[str, str] = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path.joinpath(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = f"# {object_id} {path}\n".encode()
            target.write_bytes(raw)
            files[path] = _digest(raw)
        rows[object_id] = {
            "object_id": object_id,
            "kind": item["primary_kind"],
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["file:" + path for path in item["owned_paths"]],
            "reason": "Synthetic exact owner for original-system review tests.",
            "classification": _full_classification(),
            "obligations": _all_obligations(),
        }
    return tmp_path, rows, files


def _evidence(path: str, files: dict[str, str]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": files[path]}]


def test_review_document_is_complete_exact_and_defensive():
    catalog = review.review_document()
    registry = namespace_registry()

    assert tuple(catalog) == review.ORIGINAL_SYSTEM_OBJECT_IDS
    assert set(catalog) == set(EXPECTED_APPLICABILITY)
    assert len(catalog) == 7
    assert sum(len(item["classification"]) for item in catalog.values()) == 84
    assert sum(len(item["declarations"]) for item in catalog.values()) == 63

    for object_id, item in catalog.items():
        assert item["owned_paths"] == EXPECTED_PATHS[object_id]
        assert set(item["classification"]) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in item["classification"].items()
            if decision["status"] == "APPLIES"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        for kind, decision in item["classification"].items():
            assert decision["status"] in {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED"}
            assert decision["reason"].strip()
            if decision["status"] == "UNRESOLVED":
                # Unproven refutations carry the migration question and no evidence.
                assert decision["evidence_paths"] == []
                assert decision["reason"] == review._MIGRATION_REASON.format(kind=kind)
            else:
                assert decision["evidence_paths"]
                assert set(decision["evidence_paths"]) <= set(item["owned_paths"])
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

    catalog["vstd-time"]["owned_paths"].clear()
    catalog["vstd-data"]["declarations"].clear()
    fresh = review.review_document()
    assert fresh["vstd-time"]["owned_paths"]
    assert fresh["vstd-data"]["declarations"]


def test_role_evidence_names_exact_source_functions_and_boundaries():
    catalog = review.review_document()

    env = catalog["vstd-environment"]["classification"]
    assert env["SENSOR"]["evidence_paths"] == ["src/verifier/domains/env.py"]
    assert "collect_configuration()" in env["SENSOR"]["reason"]
    assert set(env["MEASUREMENT"]["evidence_paths"]) == {
        "src/verifier/domains/env.py",
        "src/verifier/domains/contracts/env_checks.py",
    }
    assert 'evaluate(check="resources")' in env["MEASUREMENT"]["reason"]

    data = catalog["vstd-data"]["classification"]
    assert set(data["MEASUREMENT"]["evidence_paths"]) == {
        "src/verifier/domains/data.py",
        "src/verifier/domains/contracts/data_distribution.py",
    }
    assert "data.distribution()" in data["MEASUREMENT"]["reason"]
    assert data["SENSOR"]["status"] == "DOES_NOT_APPLY"
    assert "already retained bytes" in data["SENSOR"]["reason"]

    bench = catalog["vstd-benchmark"]["classification"]
    assert set(bench["MEASUREMENT"]["evidence_paths"]) == {
        "src/verifier/domains/bench.py",
        "src/verifier/domains/contracts/bench_checks.py",
    }
    assert 'evaluate(check="budgets")' in bench["MEASUREMENT"]["reason"]
    assert bench["SENSOR"]["status"] == "APPLIES"
    assert "sole authored reasons.vstd" in bench["SENSOR"]["reason"]
    assert all(
        "NOT_ESTABLISHED" in value
        for obligation_id, declaration in catalog["vstd-benchmark"]["declarations"].items()
        if obligation_id.startswith("SENSOR-")
        for value in declaration.values()
    )


def test_near_name_false_positives_are_explicitly_refuted():
    catalog = review.review_document()

    graph_market = catalog["vstd-package-graph"]["classification"]["MARKET"]
    assert graph_market["status"] == "DOES_NOT_APPLY"
    assert "not market participants" in graph_market["reason"]

    # time_strict.py names clock_calibration (reported NOT_ESTABLISHED): the
    # MEASUREMENT refutation is not positively established, so it is UNRESOLVED.
    time_measurement = catalog["vstd-time"]["classification"]["MEASUREMENT"]
    assert time_measurement["status"] == "UNRESOLVED"
    assert time_measurement["reason"] == review._MIGRATION_REASON.format(kind="MEASUREMENT")

    event_protocol = catalog["vstd-event"]["classification"]["PROTOCOL"]
    assert event_protocol["status"] == "DOES_NOT_APPLY"
    assert "event_dispatch.py" in event_protocol["reason"]
    assert (
        "no actual emission, transport, delivery, handler execution"
        in event_protocol["reason"]
    )

    space_transaction = catalog["vstd-space"]["classification"]["TRANSACTION"]
    assert space_transaction["status"] == "DOES_NOT_APPLY"
    assert "no allocation, copy, commit, rollback" in space_transaction["reason"]


def test_external_physical_money_authenticity_and_freshness_boundaries_are_explicit():
    catalog = review.review_document()
    for object_id, item in catalog.items():
        if object_id == "vstd-benchmark":
            for kind in ("ROBOT", "FINBOT"):
                assert item["classification"][kind]["status"] == "APPLIES"
                assert "sole authored reasons.vstd" in item["classification"][kind]["reason"]
        else:
            assert item["classification"]["ROBOT"]["status"] == "DOES_NOT_APPLY"
            assert "physical" in item["classification"]["ROBOT"]["reason"]
            assert item["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"
            assert "live-money" in item["classification"]["FINBOT"]["reason"]

    env = catalog["vstd-environment"]["declarations"]
    assert (
        "no independent acquisition"
        in env["MEASUREMENT-0.2-units-time-and-uncertainty"]["arrival_time"]
    )
    assert (
        "No freshness window"
        in env["MEASUREMENT-0.3-validity-and-missingness"]["freshness"]
    )
    assert (
        "no independent host attestation"
        in env["SENSOR-0.2-calibration-and-envelope"]["calibration_evidence"]
    )

    data = catalog["vstd-data"]["declarations"]
    assert (
        "not an estimate"
        in data["MEASUREMENT-0.1-phenomenon-and-method"]["observation_vs_estimate"]
    )
    assert (
        "external origin"
        in data["MEASUREMENT-0.3-validity-and-missingness"]["provenance"]
    )

    bench = catalog["vstd-benchmark"]["declarations"]
    assert (
        "does not execute or observe the candidate"
        in bench["MEASUREMENT-0.1-phenomenon-and-method"]["source"]
    )
    assert (
        "No freshness window"
        in bench["MEASUREMENT-0.3-validity-and-missingness"]["freshness"]
    )


def test_apply_is_pure_deterministic_complete_and_idempotent(tmp_path):
    root, rows, files = _workspace(tmp_path)
    before = deepcopy(rows)

    first = review.apply_package_original_review_systems(root, rows, files)
    second = review.apply_package_original_review_systems(root, first, files)

    assert rows == before
    assert first == second
    assert first is not rows
    foreign = (set(namespace_registry()) - {"OBJECT"}) - set(review.REVIEW_KINDS)
    for object_id, row in first.items():
        assert set(row["classification"]) == set(namespace_registry()) - {"OBJECT"}
        assert {
            kind: row["classification"][kind] for kind in foreign
        } == {
            kind: before[object_id]["classification"][kind] for kind in foreign
        }
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert applies <= set(row["specializations"])
        assert all(name.split("-", 1)[0] in applies for name in row["obligations"])
        assert all(
            binding["reason"].strip()
            and binding["evidence"]
            and all(value.strip() for value in binding["declaration"].values())
            for binding in row["obligations"].values()
        )


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
    tmp_path, mutation: str
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-environment"
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

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_BINDINGS_INVALID"):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


@pytest.mark.parametrize(
    "mutation", ["applies", "does-not-apply", "wrong-reason", "evidence"]
)
def test_apply_passes_through_a_foreign_question_decided_by_its_own_catalog(
    tmp_path, mutation: str
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-environment"
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

    result = review.apply_package_original_review_systems(root, rows, files)

    assert result[object_id]["classification"][foreign_kind] == decided
    assert rows == before
    again = review.apply_package_original_review_systems(root, result, files)
    assert again == result


def test_apply_preserves_only_exact_complete_current_reviews(tmp_path):
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_systems(root, rows, files)
    assert review.apply_package_original_review_systems(root, selected, files) == selected
    graph_id = "vstd-package-graph"
    selected[graph_id]["classification"]["MARKET"]["reason"] = (
        "Substituted noncanonical refutation."
    )
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"):
        review.apply_package_original_review_systems(root, selected, files)


def test_unlisted_basis_and_unknown_object_never_gain_complement_refutation(
    tmp_path, monkeypatch
):
    object_id = "vstd-package-graph"
    original = review._REVIEWS[object_id]
    monkeypatch.setitem(
        review._REVIEWS,
        object_id,
        replace(original, refuted=tuple(k for k in original.refuted if k != "LEDGER")),
    )
    assert review.review_document()[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": review._MIGRATION_REASON.format(kind="LEDGER"),
        "evidence_paths": [],
    }
    root, rows, files = _workspace(tmp_path)
    rows["unknown-future-owner"] = {"sentinel": "unchanged"}
    result = review.apply_package_original_review_systems(root, rows, files)
    assert result[object_id]["classification"]["LEDGER"] == review._canonical_migration_question("LEDGER")
    assert result["unknown-future-owner"] == {"sentinel": "unchanged"}


def test_apply_accepts_only_canonical_unresolved_migration_candidate(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-time"
    rows[object_id]["classification"]["MEASUREMENT"]["reason"] = (
        "Looks unresolved but is not the canonical migration candidate."
    )

    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


def test_apply_accepts_current_rehomed_candidate_evidence(tmp_path):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-data"
    path = "src/verifier/domains/contracts/data_checks.py"
    rows[object_id]["classification"]["SENSOR"]["evidence"] = _evidence(path, files)
    obligation_id = "SENSOR-0.1-acquisition-and-observations"
    rows[object_id]["obligations"][obligation_id]["evidence"] = _evidence(path, files)

    result = review.apply_package_original_review_systems(root, rows, files)

    assert result[object_id]["classification"]["SENSOR"]["status"] == ("DOES_NOT_APPLY")
    assert obligation_id not in result[object_id]["obligations"]


def test_apply_rejects_stale_files_map_and_stale_review_evidence(tmp_path):
    root, rows, files = _workspace(tmp_path)
    path = EXPECTED_PATHS["vstd-space"][0]
    stale_files = dict(files)
    stale_files[path] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_SOURCE_DIFFERS"):
        review.apply_package_original_review_systems(root, rows, stale_files)

    object_id = "vstd-environment"
    rows[object_id]["classification"]["SENSOR"] = {
        "status": "APPLIES",
        "reason": "Complete but stale source review.",
        "evidence": [
            {"path": "src/verifier/domains/env.py", "sha256": "sha256:" + "0" * 64}
        ],
    }
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"):
        review.apply_package_original_review_systems(root, rows, files)


def test_apply_rejects_missing_and_unowned_source_evidence(tmp_path):
    root, rows, files = _workspace(tmp_path)
    missing = root.joinpath(*EXPECTED_PATHS["vstd-event"][0].split("/"))
    missing.unlink()
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_SOURCE_UNAVAILABLE"):
        review.apply_package_original_review_systems(root, rows, files)

    root, rows, files = _workspace(tmp_path / "other")
    object_id = "vstd-data"
    rows[object_id]["classification"]["MEASUREMENT"] = {
        "status": "APPLIES",
        "reason": "Complete but owned by a different object.",
        "evidence": _evidence("src/verifier/domains/bench.py", files),
    }
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"):
        review.apply_package_original_review_systems(root, rows, files)


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("status", "PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"),
        ("extra-decision-field", "PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"),
        ("partial-declaration", "PACKAGE_ORIGINAL_REVIEW_DECLARATION_CONFLICT"),
        (
            "refuted-declaration",
            "PACKAGE_ORIGINAL_REVIEW_REFUTED_DECLARATION_CONFLICT",
        ),
        ("label", "PACKAGE_ORIGINAL_REVIEW_LABEL_CONFLICT"),
        ("unknown-obligation", "PACKAGE_ORIGINAL_REVIEW_OBLIGATION_UNKNOWN"),
    ],
)
def test_apply_rejects_conflicting_partial_or_extra_state(
    tmp_path, mutation: str, error: str
):
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-benchmark"
    if mutation == "status":
        path = "src/verifier/domains/bench.py"
        rows[object_id]["classification"]["MEASUREMENT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Contradicts current source.",
            "evidence": _evidence(path, files),
        }
    elif mutation == "extra-decision-field":
        rows[object_id]["classification"]["MEASUREMENT"]["extra"] = True
    elif mutation == "partial-declaration":
        obligation = rows[object_id]["obligations"][
            "MEASUREMENT-0.1-phenomenon-and-method"
        ]
        obligation["reason"] = "Partially answered."
        obligation["declaration"]["phenomenon"] = "Only one field."
    elif mutation == "refuted-declaration":
        object_id = "vstd-data"
        obligation = rows[object_id]["obligations"][
            "SENSOR-0.1-acquisition-and-observations"
        ]
        obligation["reason"] = "A reviewed declaration cannot accompany refutation."
        obligation["evidence"] = _evidence("src/verifier/domains/bench.py", files)
        obligation["declaration"] = {
            field: "Nonblank conflict." for field in obligation["declaration"]
        }
    elif mutation == "label":
        object_id = "vstd-data"
        rows[object_id]["specializations"].append("SENSOR")
    else:
        rows[object_id]["obligations"]["SENSOR-0.99-invented"] = {
            "reason": "",
            "evidence": [],
            "declaration": {},
        }

    before = deepcopy(rows)
    with pytest.raises(ValueError, match=error):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


def test_apply_validates_whole_review_before_mutating(tmp_path):
    root, rows, files = _workspace(tmp_path)
    # The conflict is on the final catalog object; every earlier plan must still
    # remain unpublished when it is discovered.
    rows["vstd-benchmark"]["classification"]["POLICY"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Late contradictory review.",
        "evidence": _evidence("src/verifier/domains/bench.py", files),
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT"):
        review.apply_package_original_review_systems(root, rows, files)

    assert rows == before
    assert all(
        decision["status"] == "UNRESOLVED"
        for decision in rows["vstd-package-graph"]["classification"].values()
    )


def test_apply_detects_source_drift_between_opening_and_publication(
    tmp_path, monkeypatch
):
    root, rows, files = _workspace(tmp_path)
    original = review._source_evidence
    calls = 0

    def drifting(selected_root: Path, paths: tuple[str, ...]):
        nonlocal calls
        calls += 1
        evidence = original(selected_root, paths)
        if calls == len(review.ORIGINAL_SYSTEM_OBJECT_IDS) + 1:
            evidence[0] = {**evidence[0], "sha256": "sha256:" + "f" * 64}
        return evidence

    monkeypatch.setattr(review, "_source_evidence", drifting)

    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_SOURCE_CHANGED"):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


def test_apply_rejects_missing_object_and_ownership_drift(tmp_path):
    root, rows, files = _workspace(tmp_path)
    rows.pop("vstd-package-graph")
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_OBJECT_MISSING"):
        review.apply_package_original_review_systems(root, rows, files)

    root, rows, files = _workspace(tmp_path / "ownership")
    rows["vstd-space"]["surfaces"].pop()
    with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_OWNERSHIP_DIFFERS"):
        review.apply_package_original_review_systems(root, rows, files)


@pytest.mark.parametrize(
    ("bad_files", "bad_rows"),
    [({"x": "not-a-digest"}, None), (None, []), ({}, None)],
)
def test_apply_rejects_invalid_top_level_inputs(tmp_path, bad_files, bad_rows):
    root, rows, files = _workspace(tmp_path)
    if bad_rows is not None:
        with pytest.raises(ValueError, match="PACKAGE_ORIGINAL_REVIEW_ROWS_INVALID"):
            review.apply_package_original_review_systems(root, bad_rows, files)
    else:
        with pytest.raises(ValueError):
            review.apply_package_original_review_systems(root, rows, bad_files)


def _complement_catalog(object_id: str):
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
    # time_strict.py names clock_calibration. A complement-shaped catalog that
    # refutes MEASUREMENT for TIME must fail closed instead of writing DOES_NOT_APPLY.
    path = "src/verifier/domains/contracts/time_strict.py"
    raw = b"clock_calibration = {}\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    monkeypatch.setitem(review._REVIEWS, "vstd-time", _complement_catalog("vstd-time"))
    before = deepcopy(rows)
    with pytest.raises(
        ValueError, match="MECHANISM_CONTRADICTS_REFUTATION:vstd-time:MEASUREMENT"
    ):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("specialization", ["OBJECT", "GHOST"])
def test_object_or_unregistered_specialization_cannot_escape_review(
    tmp_path: Path, specialization: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-data"]["specializations"].append(specialization)
    with pytest.raises(ValueError, match="SPECIALIZATION_UNREGISTERED:vstd-data"):
        review.apply_package_original_review_systems(root, rows, files)


def test_forged_decision_substituted_from_another_object_is_rejected(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_systems(root, rows, files)
    forged = deepcopy(rows)
    forged["vstd-benchmark"]["classification"]["MEASUREMENT"] = deepcopy(
        selected["vstd-data"]["classification"]["MEASUREMENT"]
    )
    with pytest.raises(ValueError, match="DECISION_CONFLICT:vstd-benchmark:MEASUREMENT"):
        review.apply_package_original_review_systems(root, forged, files)


def test_failure_in_last_object_leaves_every_input_row_unchanged(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    rows["vstd-benchmark"]["specializations"].append("OBJECT")
    before = deepcopy(rows)
    with pytest.raises(ValueError):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


def test_unparseable_owned_source_fails_closed_with_coded_error(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    path = "src/verifier/domains/contracts/time_strict.py"
    raw = b"def broken(:\n"
    (root / path).write_bytes(raw)
    files[path] = _digest(raw)
    with pytest.raises(ValueError, match="SOURCE_UNPARSEABLE:vstd-time:"):
        review.apply_package_original_review_systems(root, rows, files)


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_declaration_must_equal_reviewed_text(
    tmp_path: Path, object_id: str
) -> None:
    # A non-blank declaration that is not the reviewed Tier-0 text is a
    # conflicting binding, not a compatible current review.
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_systems(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    selected[object_id]["obligations"][obligation_id]["declaration"]["scope"] = (
        "Non-blank text that names a different object's policy scope."
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_systems(root, selected, files)
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
        "bare_prefix": contracts / "env.py",
        "pyi_stub": contracts / "env_types.pyi",
        "json_artifact": contracts / "env_schema.json",
        "nested_uppercase": contracts / "nested" / "ENV_new_surface.py",
    }[case]
    added.parent.mkdir(parents=True, exist_ok=True)
    added.write_text("# newly discovered ENV contract surface\n", encoding="utf-8")
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_MIGRATION_DENOMINATOR_CHANGED:vstd-environment",
    ):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("object_id", ["vstd-environment", "vstd-package-graph"])
def test_partial_none_decision_is_not_treated_as_canonical_absence(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    rows[object_id]["classification"]["LEDGER"] = None
    before = deepcopy(rows)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_DECISION_CONFLICT:" + object_id + ":LEDGER",
    ):
        review.apply_package_original_review_systems(root, rows, files)
    assert rows == before


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_obligation_reason_substitution_is_rejected(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_systems(root, rows, files)
    obligation_id = "POLICY-0.1-rules-and-precedence"
    selected[object_id]["obligations"][obligation_id]["reason"] = (
        review._obligation_reason(review._REVIEWS[object_id], "PROTOCOL")
    )
    before = deepcopy(selected)

    with pytest.raises(
        ValueError,
        match="PACKAGE_ORIGINAL_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_systems(root, selected, files)
    assert selected == before


@pytest.mark.parametrize("object_id", sorted(review.review_document()))
def test_preserved_obligation_evidence_from_another_object_is_rejected(
    tmp_path: Path, object_id: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_original_review_systems(root, rows, files)
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
        match="PACKAGE_ORIGINAL_REVIEW_DECLARATION_CONFLICT:"
        + object_id
        + ":"
        + obligation_id,
    ):
        review.apply_package_original_review_systems(root, selected, files)
    assert selected == before

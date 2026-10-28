# Terminology: Advanced Micro Devices (AMD); JavaScript Object Notation (JSON).
from __future__ import annotations

import ast
from copy import deepcopy
import dataclasses
from hashlib import sha256
import json
import os
from pathlib import Path
import re

import pytest

from verifier.runtime import package_semantic_review_records as review
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


EXPECTED_APPLICABILITY = {
    "vstd-amd-live-sensor": {"MEASUREMENT", "SENSOR"},
    "vstd-anchor-history-ledger": {"LEDGER", "TRANSACTION"},
    "vstd-artifact-network-history": {
        "LEDGER",
        "TRANSACTION",
        "PROTOCOL",
        "POLICY",
    },
    "vstd-assurance-event-ledger": {"LEDGER", "TRANSACTION"},
    "vstd-challenge-record-ledger": {"LEDGER", "TRANSACTION", "POLICY"},
    "vstd-consent-policy": {"POLICY"},
    "vstd-dataset-provenance-policy": {"POLICY"},
    "vstd-firmware-emulator-accounting": {
        "LEDGER",
        "TRANSACTION",
        "CONTROLLER",
        "ACTUATOR",
        "PROTOCOL",
    },
    "vstd-governance-policy": {"POLICY"},
    "vstd-nvidia-live-sensor": {"MEASUREMENT", "SENSOR"},
    "vstd-precommitment-ledger": {"LEDGER", "TRANSACTION"},
    "vstd-retention-policy": {"MEASUREMENT", "POLICY"},
    "vstd-sim-resource-measurement": {"MEASUREMENT", "SENSOR"},
}

# Literal per-object DOES_NOT_APPLY catalog.  Every other non-applicable kind is
# UNRESOLVED; no test may infer a refutation from the complement of APPLIES.
EXPECTED_REFUTED = {
    "vstd-amd-live-sensor": {"TRANSACTION", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT", "MARKET"},
    "vstd-anchor-history-ledger": {"ASSET", "ROBOT", "FINBOT", "MARKET"},
    "vstd-artifact-network-history": {"ASSET", "MARKET"},
    "vstd-assurance-event-ledger": {"ASSET", "ROBOT", "FINBOT", "MARKET"},
    "vstd-challenge-record-ledger": {"ASSET", "ROBOT", "FINBOT", "MARKET"},
    "vstd-consent-policy": {"ROBOT", "FINBOT", "MARKET"},
    "vstd-dataset-provenance-policy": {"MARKET"},
    "vstd-firmware-emulator-accounting": {"SENSOR", "ASSET", "ROBOT", "FINBOT", "MARKET"},
    "vstd-governance-policy": {"ROBOT", "FINBOT", "MARKET"},
    "vstd-nvidia-live-sensor": {"TRANSACTION", "CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT", "MARKET"},
    "vstd-precommitment-ledger": {"ASSET", "ROBOT", "FINBOT", "MARKET"},
    "vstd-retention-policy": {"ASSET", "SENSOR", "ROBOT", "FINBOT", "MARKET"},
    "vstd-sim-resource-measurement": {"MARKET"},
}
# Output-level DOES_NOT_APPLY cells after the static demotions and the live closed-surface
# screen.  The screen is OPEN for every owned object: the reflection in governance, the
# fixed-argument subprocess in the NVIDIA/AMD adapters, the import-reached package
# __init__ launches, and the filesystem writes in the closures withhold every refutation.
# No cell is decided DOES_NOT_APPLY until a closed, positively identified boundary exists.
EXPECTED_DOES_NOT_APPLY = {object_id: set() for object_id in EXPECTED_REFUTED}
CANONICAL_UNRESOLVED = (
    "Migration retains this applicability question. Static ownership alone cannot "
    "refute a {kind} role."
)


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


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
            "reason": "Synthetic exact owner for record-review tests.",
            "classification": {
                kind: {
                    "status": "UNRESOLVED",
                    "reason": "Not yet reviewed.",
                    "evidence": [],
                }
                for kind in review.REVIEW_KINDS
            },
            "obligations": _all_candidates(),
        }
        for object_id, item in review.review_document().items()
    }


def _synthetic_bytes(object_id: str, path: str) -> bytes:
    """Valid, import-free owned bytes: a Python comment for .py and JSON for schemas.

    NUL bytes would be PYTHON_SYNTAX_ERROR blockers in the closed-surface screen, so
    synthetic sources must parse; their closure is then exactly the owned file.
    """
    if path.endswith(".json"):
        return (json.dumps({"object_id": object_id, "path": path}, sort_keys=True) + "\n").encode()
    return ("# Synthetic owned source for " + object_id + " at " + path + ".\n").encode()


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, dict], dict[str, str]]:
    files: dict[str, str] = {}
    for object_id, item in review.review_document().items():
        for path in item["owned_paths"]:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = _synthetic_bytes(object_id, path)
            target.write_bytes(raw)
            files[path] = _digest(raw)
    return tmp_path, _rows(), files


def test_review_document_is_complete_deterministic_and_live_registry_exact() -> None:
    first = review.review_document()
    second = review.review_document()
    registry = namespace_registry()

    assert first == second
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    )
    assert tuple(first) == review.RECORD_OBJECT_IDS
    assert set(first) == set(EXPECTED_APPLICABILITY)
    assert sum(len(item["declarations"]) for item in first.values()) == 87

    for object_id, item in first.items():
        decisions = item["classification"]
        assert set(decisions) == set(review.REVIEW_KINDS)
        applies = {
            kind
            for kind, decision in decisions.items()
            if decision["status"] == "APPLIES"
        }
        refuted = {
            kind
            for kind, decision in decisions.items()
            if decision["status"] == "DOES_NOT_APPLY"
        }
        assert applies == EXPECTED_APPLICABILITY[object_id]
        assert refuted == EXPECTED_DOES_NOT_APPLY[object_id]
        assert set(decisions) - applies - refuted == {
            kind
            for kind, decision in decisions.items()
            if decision["status"] == "UNRESOLVED"
        }
        assert all(decision["reason"].strip() for decision in decisions.values())
        for kind, decision in decisions.items():
            if decision["status"] == "UNRESOLVED":
                assert decision["evidence_paths"] == []
                assert decision["reason"] == CANONICAL_UNRESOLVED.format(kind=kind)
            else:
                assert set(decision["evidence_paths"]) == set(item["owned_paths"])

        expected = {}
        for kind in applies:
            for obligation in requirements_for(registry, (kind,)):
                if obligation["kind"] == kind:
                    expected[obligation["id"]] = set(obligation["declaration_fields"])
        assert set(item["declarations"]) == set(expected)
        for obligation_id, declaration in item["declarations"].items():
            assert set(declaration) == expected[obligation_id]
            assert all(value.strip() for value in declaration.values())
        assert "Tier-0" in item["claim_boundary"]
        assert "Tier-1-plus" in item["claim_boundary"]


def test_review_uses_exact_existing_owned_sources() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        path
        for item in review.review_document().values()
        for path in item["owned_paths"]
    ]
    assert len(paths) == 19
    assert len(paths) == len(set(paths))
    assert all((root / path).is_file() for path in paths)


def test_apply_is_atomic_pure_complete_idempotent_and_deep_copied(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    original = deepcopy(rows)
    first = review.apply_package_semantic_review_records(root, rows, files)
    second = review.apply_package_semantic_review_records(root, first, files)

    assert rows == original
    assert first == second
    assert first is not rows
    for object_id, row in first.items():
        applies = EXPECTED_APPLICABILITY[object_id]
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES"
        } == applies
        assert applies - {row["kind"]} <= set(row["specializations"])
        assert {
            kind
            for kind, decision in row["classification"].items()
            if decision["status"] == "DOES_NOT_APPLY"
        } == EXPECTED_DOES_NOT_APPLY[object_id]
        assert all(
            obligation_id.split("-", 1)[0] in applies
            for obligation_id in row["obligations"]
        )
        assert all(binding["reason"].strip() for binding in row["obligations"].values())
        assert all(binding["evidence"] for binding in row["obligations"].values())
        assert all(
            value.strip()
            for binding in row["obligations"].values()
            for value in binding["declaration"].values()
        )

    first["vstd-consent-policy"]["classification"]["POLICY"]["reason"] = "changed"
    assert rows == original
    assert second != first


def test_apply_resolves_current_rehomed_migration_candidates(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-amd-live-sensor"
    path = review.review_document()[object_id]["owned_paths"][0]
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

    result = review.apply_package_semantic_review_records(root, rows, files)

    assert result[object_id]["classification"]["LEDGER"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="LEDGER"),
        "evidence": evidence,
    }
    assert result[object_id]["classification"]["MEASUREMENT"]["status"] == "APPLIES"
    assert not any(
        name.startswith("LEDGER-") for name in result[object_id]["obligations"]
    )
    assert all(
        result[object_id]["obligations"]["MEASUREMENT-0.1-phenomenon-and-method"][
            "declaration"
        ].values()
    )


def test_apply_rejects_stale_rehomed_migration_candidate(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-amd-live-sensor"
    kind = "LEDGER"
    path = review.review_document()[object_id]["owned_paths"][0]
    rows[object_id]["classification"][kind] = {
        "status": "UNRESOLVED",
        "reason": (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a " + kind + " role."
        ),
        "evidence": [{"path": path, "sha256": "sha256:" + "0" * 64}],
    }
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION"):
        review.apply_package_semantic_review_records(root, rows, files)
    assert rows == before


def test_apply_preserves_complete_current_compatible_answers(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_records(root, rows, files)
    item = selected["vstd-retention-policy"]
    decisions = deepcopy(item["classification"])
    obligation_id = "MEASUREMENT-0.1-phenomenon-and-method"
    custom_binding = deepcopy(item["obligations"][obligation_id])
    custom_binding["declaration"] = {
        field: "Prior exact answer for " + field + "."
        for field in custom_binding["declaration"]
    }
    item["obligations"][obligation_id] = deepcopy(custom_binding)

    result = review.apply_package_semantic_review_records(root, selected, files)
    assert result["vstd-retention-policy"]["classification"] == decisions
    assert (
        result["vstd-retention-policy"]["obligations"][obligation_id] == custom_binding
    )


@pytest.mark.parametrize(
    "failure",
    [
        "same_status_reason",
        "same_status_evidence",
        "same_status_stale_digest",
        "other_object_reason",
        "forged_applies_on_unlisted",
        "forged_refutation_on_unlisted",
    ],
)
def test_apply_rejects_forged_or_substituted_decisions_without_erasure(
    tmp_path: Path, failure: str
) -> None:
    # retention ROBOT is statically withheld, so the output row is UNRESOLVED.  Each
    # forgery restates it as DOES_NOT_APPLY, which only an exact historic refutation with
    # current bytes may do; every other restatement must abort the whole operation.
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_records(root, rows, files)
    item = selected["vstd-retention-policy"]
    robot = item["classification"]["ROBOT"]
    owned = review._REVIEWS["vstd-retention-policy"].owned_paths
    exact = [{"path": path, "sha256": files[path]} for path in owned]
    refuted_reason = review._REVIEWS["vstd-retention-policy"].refuted["ROBOT"]
    if failure == "same_status_reason":
        robot.update(
            status="DOES_NOT_APPLY",
            reason="Prior current-byte review found no physical actuation path.",
            evidence=deepcopy(exact),
        )
    elif failure == "same_status_evidence":
        robot.update(
            status="DOES_NOT_APPLY",
            reason=refuted_reason,
            evidence=[{"path": "src/unowned.py", "sha256": "sha256:" + "0" * 64}],
        )
    elif failure == "same_status_stale_digest":
        stale = [{"path": path, "sha256": "sha256:" + "0" * 64} for path in owned]
        robot.update(status="DOES_NOT_APPLY", reason=refuted_reason, evidence=stale)
    elif failure == "other_object_reason":
        robot.update(
            status="DOES_NOT_APPLY",
            reason=review._REVIEWS["vstd-amd-live-sensor"].refuted["ROBOT"],
            evidence=deepcopy(exact),
        )
    elif failure == "forged_applies_on_unlisted":
        item["classification"]["MARKET"] = {
            "status": "APPLIES",
            "reason": "Forged market applicability.",
            "evidence": deepcopy(robot["evidence"]),
        }
    else:
        item["classification"]["MARKET"] = {
            "status": "DOES_NOT_APPLY",
            "reason": robot["reason"],
            "evidence": deepcopy(robot["evidence"]),
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_"):
        review.apply_package_semantic_review_records(root, selected, files)
    assert selected == before


def test_unlisted_objects_and_kinds_never_inherit_refutations(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    neighbor = deepcopy(rows["vstd-consent-policy"])
    neighbor["object_id"] = "vstd-unlisted-neighbor"
    rows["vstd-unlisted-neighbor"] = neighbor
    before = deepcopy(neighbor)

    result = review.apply_package_semantic_review_records(root, rows, files)

    assert result["vstd-unlisted-neighbor"] == before
    assert all(
        decision["status"] == "UNRESOLVED"
        for decision in before["classification"].values()
    )
    assert "vstd-unlisted-neighbor" not in review.review_document()
    # Consent's catalogued refutations are withheld by its open closure, and the
    # unlisted neighbor never inherits them; governance keeps its closed-surface refutation.
    consent = result["vstd-consent-policy"]["classification"]
    assert consent["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence": [],
    }
    assert consent["MARKET"]["status"] == "UNRESOLVED"
    governance = result["vstd-governance-policy"]["classification"]
    assert governance["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence": [],
    }


@pytest.mark.parametrize(
    "failure",
    [
        "stale_census",
        "missing_source",
        "missing_owned_path",
        "extra_owned_path",
        "missing_object",
        "wrong_primary",
        "refuted_label",
    ],
)
def test_apply_rejects_source_ownership_and_label_drift_without_mutation(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-retention-policy"
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
    else:
        rows[object_id]["specializations"].append("SENSOR")
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_"):
        review.apply_package_semantic_review_records(root, rows, files)
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
def test_apply_rejects_conflicting_stale_unowned_and_partial_bindings_atomically(
    tmp_path: Path, failure: str
) -> None:
    root, rows, files = _workspace(tmp_path)
    selected = review.apply_package_semantic_review_records(root, rows, files)
    object_id = "vstd-anchor-history-ledger"
    item = selected[object_id]
    path = review.review_document()[object_id]["owned_paths"][0]
    decision = item["classification"]["TRANSACTION"]
    obligation = item["obligations"]["TRANSACTION-0.1-effects-and-authority"]
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
        obligation["declaration"]["effects"] = ""
    elif failure == "stale_declaration":
        obligation["evidence"][0]["sha256"] = "sha256:" + "b" * 64
    elif failure == "unexpected_field":
        obligation["declaration"]["not_registered"] = "No."
    else:
        item["obligations"]["SENSOR-0.1-acquisition-and-observations"] = {
            "reason": "Contradictory declaration.",
            "evidence": [{"path": path, "sha256": files[path]}],
            "declaration": {
                field: "Contradictory " + field + "."
                for field in (
                    "acquisition",
                    "phenomena",
                    "measurements",
                    "deployment",
                )
            },
        }
    before = deepcopy(selected)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_"):
        review.apply_package_semantic_review_records(root, selected, files)
    assert selected == before


def test_apply_rejects_source_change_during_review(tmp_path: Path, monkeypatch) -> None:
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-amd-live-sensor"
    path = review.review_document()[object_id]["owned_paths"][0]
    target = root / path
    original_snapshot = review._source_snapshot
    changed = False

    def changing_snapshot(selected_root, paths, *, object_id):
        nonlocal changed
        result = original_snapshot(selected_root, paths, object_id=object_id)
        if object_id == "vstd-amd-live-sensor" and not changed:
            target.write_bytes(b"changed after opening digest\n")
            changed = True
        return result

    monkeypatch.setattr(review, "_source_snapshot", changing_snapshot)
    before = deepcopy(rows)
    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED"
    ):
        review.apply_package_semantic_review_records(root, rows, files)
    assert rows == before


def test_boundaries_preserve_simulated_physical_financial_and_acquisition_types() -> (
    None
):
    catalog = review.review_document()
    emulator = catalog["vstd-firmware-emulator-accounting"]
    retention = catalog["vstd-retention-policy"]
    challenge = catalog["vstd-challenge-record-ledger"]
    network = catalog["vstd-artifact-network-history"]

    assert emulator["declarations"]["ACTUATOR-0.1-command-to-effect"][
        "effect_domains"
    ].startswith("SIMULATED_ACCELERATOR_ONLY")
    # Qualified subtype denial: "EMULATED" and "acquires no observations" describe the
    # owned mechanism's representation.  They do not license a DOES_NOT_APPLY for the base
    # ROBOT or SENSOR kind while the closure is open, so both cells are withheld.
    assert "EMULATED" in review._REVIEWS["vstd-firmware-emulator-accounting"].refuted["ROBOT"]
    assert emulator["classification"]["ROBOT"]["status"] == "UNRESOLVED"
    assert emulator["classification"]["SENSOR"]["status"] == "UNRESOLVED"
    assert emulator["classification"]["MEASUREMENT"]["status"] == "UNRESOLVED"
    assert retention["classification"]["MEASUREMENT"]["status"] == "APPLIES"
    assert retention["classification"]["SENSOR"]["status"] == "UNRESOLVED"
    assert "acquires no observations" in review._REVIEWS["vstd-retention-policy"].refuted["SENSOR"]
    assert challenge["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"
    assert challenge["classification"]["POLICY"]["status"] == "APPLIES"
    assert network["classification"]["POLICY"]["status"] == "APPLIES"
    # ROBOT and FINBOT are emitted DOES_NOT_APPLY only where the catalog refutes them and
    # the live screen has not withheld them.  A refuted FINBOT must cite the exact owned
    # line that supports it; an unrefuted or withheld FINBOT carries the canonical reason.
    for object_id, item in catalog.items():
        for kind in ("ROBOT", "FINBOT"):
            expected = (
                "DOES_NOT_APPLY" if kind in EXPECTED_DOES_NOT_APPLY[object_id] else "UNRESOLVED"
            )
            assert item["classification"][kind]["status"] == expected
        finbot = item["classification"]["FINBOT"]
        if finbot["status"] == "DOES_NOT_APPLY":
            assert re.search(r"[\w/.-]+\.py:\d+", finbot["reason"])
        else:
            assert finbot["reason"] == CANONICAL_UNRESOLVED.format(kind="FINBOT")


def test_every_mutating_ledger_accumulates_transaction_without_financial_overclaim() -> (
    None
):
    catalog = review.review_document()
    ledgers = {
        object_id
        for object_id, item in catalog.items()
        if item["classification"]["LEDGER"]["status"] == "APPLIES"
    }
    assert ledgers == {
        "vstd-anchor-history-ledger",
        "vstd-artifact-network-history",
        "vstd-assurance-event-ledger",
        "vstd-challenge-record-ledger",
        "vstd-firmware-emulator-accounting",
        "vstd-precommitment-ledger",
    }
    for object_id in ledgers:
        item = catalog[object_id]
        assert item["classification"]["TRANSACTION"]["status"] == "APPLIES"
        # Ledger ASSET, MARKET, and FINBOT refutations are catalogued but withheld: each
        # closure contains an open site (see screen_blocks), so no ledger keeps a
        # financial or transfer DOES_NOT_APPLY.  The ledger's TRANSACTION
        # applicability is unaffected because it is a catalogued role, not a refutation.
        for kind in ("ASSET", "MARKET", "FINBOT"):
            assert item["classification"][kind]["status"] == "UNRESOLVED"
            assert item["classification"][kind]["evidence_paths"] == []


# Refuted reasons must be positive, object-specific source facts; see the subjects
# review tests for the same contract.  Citations resolve inside owned bytes, and
# evidence tokens occur in those bytes.  Generic absence rationales must not return.
REPO_ROOT = Path(__file__).resolve().parents[1]
CITATION = re.compile(r"((?:[\w.-]+/)*[\w.-]+\.(?:py|json|md)):(\d+)(?:-(\d+))?")
EVIDENCE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
GENERIC_ABSENCE = (
    "later ",
    "would separately",
    "could be composed",
    "not established",
    "neither identif",
    "no endpoint",
    "not promoted",
    "observing hardware",
    "sim-to-real",
    "does not authenticate",
    "separately accumulate",
    "enforces no exposure",
    "future",
)


def test_refuted_reasons_cite_exact_owned_source_without_generic_absence() -> None:
    for object_id, review_item in review._REVIEWS.items():
        owned_text = "\n".join(
            (REPO_ROOT / path).read_text(encoding="utf-8")
            for path in review_item.owned_paths
        )
        for kind, reason in review_item.refuted.items():
            where = object_id + ":" + kind
            lowered = reason.lower()
            assert not [term for term in GENERIC_ABSENCE if term in lowered], where
            citations = CITATION.findall(reason)
            assert citations, where
            for cited, first, last in citations:
                matches = [
                    path
                    for path in review_item.owned_paths
                    if path == cited or path.endswith("/" + cited)
                ]
                assert len(matches) == 1, where + " cites unowned " + cited
                count = len((REPO_ROOT / matches[0]).read_text(encoding="utf-8").splitlines())
                assert 1 <= int(first) <= int(last or first) <= count, where
            for token in set(EVIDENCE_TOKEN.findall(reason)):
                assert token in owned_text, where + " cites absent token " + token


def test_removing_a_refuted_cell_yields_unresolved_never_the_complement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-retention-policy"
    original = review._REVIEWS[object_id]
    weakened = dataclasses.replace(
        original,
        refuted={kind: reason for kind, reason in original.refuted.items() if kind != "FINBOT"},
    )
    monkeypatch.setitem(review._REVIEWS, object_id, weakened)

    decision = review.review_document()[object_id]["classification"]["FINBOT"]

    assert decision["status"] == "UNRESOLVED"
    assert decision["reason"] == CANONICAL_UNRESOLVED.format(kind="FINBOT")
    assert decision["evidence_paths"] == []


def test_catalogued_primary_or_specialized_role_cannot_be_demoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-firmware-emulator-accounting"
    original = review._REVIEWS[object_id]
    demoted = dataclasses.replace(
        original,
        applicable=tuple(kind for kind in original.applicable if kind != "CONTROLLER"),
        reasons={kind: text for kind, text in original.reasons.items() if kind != "CONTROLLER"},
    )
    monkeypatch.setitem(review._REVIEWS, object_id, demoted)

    with pytest.raises(AssertionError, match="dropped an owned primary"):
        review._catalog_check()


# Closed-surface regressions.  A DOES_NOT_APPLY effect refutation needs a closed
# effect surface; these cells lost theirs when a subprocess, network, or
# remote-endpoint site became reachable through owned imports or calls.
CLOSURE_DEMOTED_CELLS = (
    ("vstd-artifact-network-history", "ROBOT"),
    ("vstd-artifact-network-history", "FINBOT"),
    ("vstd-dataset-provenance-policy", "ROBOT"),
    ("vstd-dataset-provenance-policy", "FINBOT"),
    ("vstd-sim-resource-measurement", "ROBOT"),
    ("vstd-sim-resource-measurement", "FINBOT"),
)


@pytest.mark.parametrize(("object_id", "kind"), CLOSURE_DEMOTED_CELLS)
@pytest.mark.parametrize(
    "stale_reason",
    (
        "Forged closed-surface refutation retained against the demoted cell.",
        "Earlier lexical refutation retained after its closure was reached.",
    ),
)
def test_closure_demoted_cells_reject_forged_or_stale_refutations(
    tmp_path: Path, object_id: str, kind: str, stale_reason: str
) -> None:
    decision = review.review_document()[object_id]["classification"][kind]
    assert decision["status"] == "UNRESOLVED"
    assert decision["reason"] == CANONICAL_UNRESOLVED.format(kind=kind)

    root, rows, files = _workspace(tmp_path)
    owned = review._REVIEWS[object_id].owned_paths
    rows[object_id]["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": stale_reason,
        "evidence": [{"path": path, "sha256": files[path]} for path in owned],
    }
    before = deepcopy(rows)

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_DECISION_CONFLICT"
    ):
        review.apply_package_semantic_review_records(root, rows, files)
    assert rows == before


def test_injected_sink_in_owned_source_makes_the_prior_review_stale(
    tmp_path: Path,
) -> None:
    root, rows, files = _workspace(tmp_path)
    target = root / "src/verifier/runtime/resource_measurement_execution.py"
    target.write_bytes(target.read_bytes() + b"\nimport subprocess\nsubprocess.run(['true'])\n")

    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_DIFFERS:vstd-sim-resource-measurement",
    ):
        review.apply_package_semantic_review_records(root, rows, files)


def test_symlinked_owned_source_is_unavailable_not_followed(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    owned = root / "src/verifier/hardware/adapters/nvidia.py"
    outside = root / "outside_nvidia.py"
    outside.write_bytes(owned.read_bytes())
    owned.unlink()
    try:
        os.symlink(outside, owned)
    except OSError as exc:
        # OS_CAPABILITY_GUARD: unprivileged Windows symlink creation is unavailable.
        pytest.skip("OS_CAPABILITY_GUARD: symlink creation unavailable: " + str(exc))

    with pytest.raises(
        ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_UNAVAILABLE"
    ):
        review.apply_package_semantic_review_records(root, rows, files)


def test_duplicate_owned_surface_is_rejected_before_any_copy(tmp_path: Path) -> None:
    root, rows, files = _workspace(tmp_path)
    surfaces = rows["vstd-amd-live-sensor"]["surfaces"]
    surfaces.append(surfaces[0])

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_SURFACES_INVALID"):
        review.apply_package_semantic_review_records(root, rows, files)


def test_transitive_helper_surfaces_are_outside_the_amd_review_evidence() -> None:
    """Known limitation, not an accepted closure.

    The AMD fixture path imports the NVIDIA in-memory helper (hardware/adapters/amd.py:19,
    63), whose temporary-directory write and subprocess-capable module sit outside
    AMD's owned path.  AMD's evidence therefore covers only amd.py, and an edit to
    nvidia.py cannot stale AMD's cells.  Closing that gap needs a central ownership
    change; this test pins the current evidence so the change is noticed.
    """
    item = review.review_document()["vstd-amd-live-sensor"]
    evidence = {
        path
        for decision in item["classification"].values()
        for path in decision["evidence_paths"]
    }

    assert evidence == {"src/verifier/hardware/adapters/amd.py"}


# Live process-call anchors.  The vendor reviews cite the adapter's one subprocess call by
# line span; a citation is valid only when it covers the call as it exists in the current
# source, with explicit timeout and file-backed capture, not merely a line inside the file.
PROCESS_ADAPTERS = (
    ("amd", "AmdAdapter", "vstd-amd-live-sensor"),
    ("nvidia", "NvidiaAdapter", "vstd-nvidia-live-sensor"),
)


def _live_process_call(adapter: str, class_name: str) -> ast.Call:
    path = REPO_ROOT / f"src/verifier/hardware/adapters/{adapter}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and [target.id for target in node.targets if isinstance(target, ast.Name)]
        == ["_DISCOVERY_TIMEOUT_SECONDS"]
    ]
    assert len(bound) == 1 and ast.literal_eval(bound[0]) > 0, adapter + " has no timeout bound"
    (cls,) = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    (discover,) = [
        node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "discover"
    ]
    calls = [
        node
        for node in ast.walk(discover)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.run"
    ]
    assert len(calls) == 1, adapter + " discover must make exactly one subprocess.run call"
    call = calls[0]
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    assert "capture_output" not in keywords and "timeout" in keywords, adapter
    assert ast.unparse(keywords["timeout"]) == "_DISCOVERY_TIMEOUT_SECONDS", adapter
    assert ast.unparse(keywords["stderr"]) == "subprocess.DEVNULL", adapter
    captured = keywords["stdout"]
    assert isinstance(captured, ast.Name), adapter + " stdout must be a file-backed name"
    bindings = [
        node
        for node in ast.walk(discover)
        if isinstance(node, ast.With)
        and any(
            ast.unparse(item.context_expr) == "tempfile.TemporaryFile()"
            and isinstance(item.optional_vars, ast.Name)
            and item.optional_vars.id == captured.id
            for item in node.items
        )
        and any(child is call for child in ast.walk(node))
    ]
    assert bindings, adapter + " subprocess.run must write into a TemporaryFile"
    guarded = [
        node
        for node in ast.walk(discover)
        if isinstance(node, ast.Try)
        and any(child is call for stmt in node.body for child in ast.walk(stmt))
        and any(
            handler.type is not None and ast.unparse(handler.type) == "subprocess.TimeoutExpired"
            for handler in node.handlers
        )
    ]
    assert guarded, adapter + " subprocess.run must catch TimeoutExpired"
    return call


def _declared_field(item, field: str) -> str:
    """Return the one declaration field named ``field``; ids are registry-bound, not kind-bound."""
    values = [row[field] for row in item.declarations.values() if field in row]
    assert len(values) == 1, field
    return values[0]


def _cites_live_call(text: str, adapter: str, call: ast.Call) -> bool:
    spans = [
        (int(first), int(last or first))
        for cited, first, last in CITATION.findall(text)
        if cited.endswith(f"adapters/{adapter}.py")
    ]
    last_line = call.end_lineno or call.lineno
    return any(first <= call.lineno and last_line <= last for first, last in spans)


@pytest.mark.parametrize(("adapter", "class_name"), [(a, c) for a, c, _ in PROCESS_ADAPTERS])
def test_discovery_process_call_is_bounded_and_file_captured(adapter: str, class_name: str) -> None:
    _live_process_call(adapter, class_name)


@pytest.mark.parametrize(("adapter", "class_name", "object_id"), PROCESS_ADAPTERS)
def test_sensor_process_citations_cover_the_live_bounded_call(
    adapter: str, class_name: str, object_id: str
) -> None:
    call = _live_process_call(adapter, class_name)
    item = review._REVIEWS[object_id]

    method = _declared_field(item, "method")
    assert _cites_live_call(method, adapter, call), method
    latency = _declared_field(item, "latency")
    assert "no timeout" not in latency.lower(), latency
    assert "timeout" in latency.lower(), latency
    assert _cites_live_call(latency, adapter, call), latency
    for kind in ("ACTUATOR", "ROBOT"):
        assert _cites_live_call(item.refuted[kind], adapter, call), object_id + ":" + kind


# External-effect guard.  The catalog may state a DOES_NOT_APPLY for an external kind only
# where the live closed-surface screen is CLOSED and no vocabulary hit names that kind.
# The screen follows module-level and function-level project imports, package __init__
# files, and relative imports; runtime dispatch and third-party imports are open sites.


def _tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return root


def test_external_refutations_in_the_catalog_require_a_closed_live_screen() -> None:
    catalog = review.review_document()
    for object_id, item in catalog.items():
        screen = review.closed_surface_screen(REPO_ROOT, item["owned_paths"])
        for kind in review.EXTERNAL_EFFECT_KINDS:
            if item["classification"][kind]["status"] == "DOES_NOT_APPLY":
                assert not review.screen_blocks(screen, kind), (
                    object_id
                    + ":"
                    + kind
                    + " refuted while the live screen withholds it: "
                    + screen.status
                    + " "
                    + repr(screen.open_sites[:2])
                )


def test_effect_guard_fires_on_a_reinstated_closure_refutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-artifact-network-history"
    original = review._REVIEWS[object_id]
    reinstated = dataclasses.replace(
        original,
        refuted={**original.refuted, "ROBOT": "Reinstated lexical refutation of a remote endpoint."},
        demoted=original.demoted - {"ROBOT"},
    )
    monkeypatch.setitem(review._REVIEWS, object_id, reinstated)

    with pytest.raises(AssertionError, match="refuted while the live screen withholds it"):
        test_external_refutations_in_the_catalog_require_a_closed_live_screen()


def test_demotion_must_withhold_a_refuted_kind_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "vstd-governance-policy"
    original = review._REVIEWS[object_id]
    widened = dataclasses.replace(original, demoted=frozenset({"ASSET"}))
    monkeypatch.setitem(review._REVIEWS, object_id, widened)

    with pytest.raises(AssertionError, match="withholds a kind it does not refute"):
        review._catalog_check()


def test_screen_follows_transitive_local_imports_to_a_process_site(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "src/verifier/alpha.py": "from verifier.beta import relay\n\n\ndef go(argv):\n    return relay(argv)\n",
            "src/verifier/beta.py": "from verifier.gamma import launch as relay\n",
            "src/verifier/gamma.py": "import subprocess\n\n\ndef launch(argv):\n    return subprocess.run(argv)\n",
        },
    )

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert screen.status == "OPEN"
    assert {rel for rel, _digest in screen.closure} == {
        "src/verifier/alpha.py",
        "src/verifier/beta.py",
        "src/verifier/gamma.py",
    }
    assert ("src/verifier/gamma.py", 5, "unfixed_process", "subprocess.run") in screen.open_sites
    assert review.screen_blocks(screen, "ROBOT")
    assert review.screen_blocks(screen, "MARKET")


def test_closed_transitive_chain_leaves_external_refutations_available(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "src/verifier/alpha.py": "from verifier.beta import relay\n\n\ndef go(value):\n    return relay(value)\n",
            "src/verifier/beta.py": "from verifier.gamma import launch as relay\n",
            "src/verifier/gamma.py": "def launch(value):\n    return value\n",
        },
    )

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert screen.status == "CLOSED"
    assert screen.open_sites == ()
    assert len(screen.closure) == 3
    assert not review.screen_blocks(screen, "ROBOT")


@pytest.mark.parametrize(
    ("source", "site"),
    (
        ("def run(emit):\n    return emit(1)\n", "injected_callable"),
        (
            "import importlib\n\n\ndef load(name):\n    return importlib.import_module(name)\n",
            "dynamic_code",
        ),
        ("import cryptography.fernet\n", "external_dependency"),
    ),
)
def test_callback_dynamic_and_third_party_imports_open_the_closure(
    tmp_path: Path, source: str, site: str
) -> None:
    root = _tree(tmp_path, {"src/verifier/alpha.py": source})

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert screen.status == "OPEN"
    assert site in {klass for _rel, _line, klass, _target in screen.open_sites}
    assert review.screen_blocks(screen, "ROBOT")


def test_lazy_export_reached_from_owned_code_opens_the_closure(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "src/verifier/__init__.py": '_LAZY_EXPORTS = {"hidden": "verifier.gamma"}\n',
            "src/verifier/alpha.py": "from verifier import hidden\n",
            "src/verifier/gamma.py": "VALUE = 1\n",
        },
    )

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert screen.status == "OPEN"
    assert ("src/verifier/alpha.py", 1, "lazy_export_escape", "hidden") in screen.open_sites


def test_namespace_members_resolve_but_a_compiled_member_is_a_blocker(tmp_path: Path) -> None:
    closed = _tree(
        tmp_path / "closed",
        {
            "src/verifier/ns/mod.py": "VALUE = 1\n",
            "src/verifier/alpha.py": "from verifier.ns import mod\n",
        },
    )
    assert review.closed_surface_screen(closed, ("src/verifier/alpha.py",)).status == "CLOSED"

    compiled = _tree(
        tmp_path / "compiled",
        {
            "src/verifier/ns/native.pyd": b"MZ\x90\x00",
            "src/verifier/alpha.py": "from verifier.ns import native\n",
        },
    )
    screen = review.closed_surface_screen(compiled, ("src/verifier/alpha.py",))

    assert screen.status == "OPEN"
    assert screen.blockers == ("UNRESOLVED_PROJECT_IMPORT:src/verifier/alpha.py:1",)


def test_closure_drift_after_planning_aborts_the_whole_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Owned bytes are unchanged; only a transitive closure digest moves between the
    # planning screen and the closing screen.  The whole apply must abort atomically.
    root, rows, files = _workspace(tmp_path)
    real_screen = review.closed_surface_screen
    calls: list[tuple[str, ...]] = []

    def drifting(root_arg: str | Path, owned: tuple[str, ...]) -> review.SurfaceScreen:
        screen = real_screen(root_arg, owned)
        calls.append(tuple(owned))
        if len(calls) > len(review._REVIEWS):
            moved = screen.closure + (("src/verifier/late_helper.py", "sha256:" + "1" * 64),)
            return dataclasses.replace(screen, closure=moved)
        return screen

    monkeypatch.setattr(review, "closed_surface_screen", drifting)
    before = deepcopy(rows)

    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_RECORD_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_records(root, rows, files)
    assert rows == before


def test_exact_qualified_refutation_is_demoted_not_restored(tmp_path: Path) -> None:
    # The emulator reason says EMULATED.  An exact historic refutation with current bytes
    # is accepted as the prior record, but the qualified subtype does not restore it.
    root, rows, files = _workspace(tmp_path)
    object_id = "vstd-firmware-emulator-accounting"
    spec = review._REVIEWS[object_id]
    rows[object_id]["classification"]["ROBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": spec.refuted["ROBOT"],
        "evidence": [{"path": path, "sha256": files[path]} for path in spec.owned_paths],
    }

    result = review.apply_package_semantic_review_records(root, rows, files)

    assert "EMULATED" in spec.refuted["ROBOT"]
    assert result[object_id]["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": CANONICAL_UNRESOLVED.format(kind="ROBOT"),
        "evidence": [],
    }


def test_clean_owned_text_over_an_effectful_package_init_is_open(tmp_path: Path) -> None:
    # Representation versus behavior: the owned file names no effect and imports only a
    # package, but that package's __init__ eagerly imports a subprocess-capable module.
    root = _tree(
        tmp_path,
        {
            "src/verifier/diode/effect.py": "from verifier.hw import helper\n",
            "src/verifier/hw/__init__.py": "from verifier.hw import proc\n",
            "src/verifier/hw/helper.py": "VALUE = 1\n",
            "src/verifier/hw/proc.py": "import subprocess\n\n\ndef run(argv):\n    return subprocess.run(argv)\n",
        },
    )
    owned = "src/verifier/diode/effect.py"
    assert "subprocess" not in (root / owned).read_text(encoding="utf-8")

    screen = review.closed_surface_screen(root, (owned,))

    assert screen.status == "OPEN"
    assert all(rel != owned for rel, *_ in screen.open_sites)
    assert review.screen_blocks(screen, "ROBOT")


# Adversarial screen regressions for the state-kind and synonym gaps.  A DOES_NOT_APPLY
# for any kind needs a CLOSED screen; state kinds are also blocked by a filesystem write,
# and an effect-kind refutation is not blocked by a write alone.  Each case is a source
# shape that the previous screen treated as closed.


def _screen_for(tmp_path: Path, source: str, rel: str = "src/verifier/alpha.py"):
    root = _tree(tmp_path, {rel: source})
    return review.closed_surface_screen(root, (rel,))


def test_screen_reuses_identifier_tokens_but_rereads_current_source(tmp_path: Path) -> None:
    rel = "src/verifier/alpha.py"
    root = _tree(tmp_path, {rel: "def exactAlphaSensor():\n    return 1\n"})
    target = root / rel

    review._tokens.cache_clear()
    review._vocabulary_kinds.cache_clear()
    first = review.closed_surface_screen(root, (rel,))
    first_cache = review._vocabulary_kinds.cache_info()
    repeated = review.closed_surface_screen(root, (rel,))
    repeated_cache = review._vocabulary_kinds.cache_info()

    assert repeated == first
    assert repeated_cache.hits > first_cache.hits

    target.write_text("def exactBetaController():\n    return 2\n", encoding="utf-8")
    changed = review.closed_surface_screen(root, (rel,))
    changed_cache = review._vocabulary_kinds.cache_info()

    assert changed != first
    assert changed.closure != first.closure
    assert changed_cache.misses > repeated_cache.misses


@pytest.mark.parametrize(
    "source",
    (
        "import importlib.util\n\n\ndef load(path):\n"
        "    spec = importlib.util.spec_from_file_location('m', path)\n    return spec\n",
        "import runpy\n\n\ndef go(path):\n    return runpy.run_path(path)\n",
        "def probe(obj, name):\n    return getattr(obj, name)\n",
        "def mutate(obj):\n    setattr(obj, 'x', 1)\n",
        "def table():\n    return vars()\n",
        "def module_table():\n    return globals()\n",
    ),
)
def test_reflection_and_dynamic_loading_open_the_closure_for_every_kind(
    tmp_path: Path, source: str
) -> None:
    screen = _screen_for(tmp_path, source)

    assert screen.status == "OPEN"
    assert screen.open_sites
    for kind in ("ROBOT", "FINBOT", "MARKET", "LEDGER", "TRANSACTION"):
        assert review.screen_blocks(screen, kind), kind


@pytest.mark.parametrize(
    ("source", "site"),
    (
        ("import os\n\n\ndef go(argv):\n    return os.posix_spawn(argv[0], argv, {})\n", "unfixed_process"),
        ("import os\n\n\ndef go():\n    return os.fork()\n", "unfixed_process"),
        ("import webbrowser\n\n\ndef go(url):\n    return webbrowser.open(url)\n", "unfixed_process"),
        ("import multiprocessing\n\n\ndef go():\n    return multiprocessing.Pool(2)\n", "unfixed_process"),
        (
            "import subprocess\n\n\ndef go():\n    return subprocess.run(['git', 'status'])\n",
            "fixed_process_argv",
        ),
        (
            "import asyncio\n\n\nasync def go(host):\n    return await asyncio.open_connection(host, 80)\n",
            "network",
        ),
        ("import telnetlib\n\n\ndef go(host):\n    return telnetlib.Telnet(host)\n", "network"),
    ),
)
def test_launcher_and_network_synonyms_are_open_for_every_kind(
    tmp_path: Path, source: str, site: str
) -> None:
    screen = _screen_for(tmp_path, source)

    assert screen.status == "OPEN"
    assert site in {klass for _rel, _line, klass, _target in screen.open_sites}
    assert review.screen_blocks(screen, "ROBOT")
    assert review.screen_blocks(screen, "TRANSACTION")


@pytest.mark.parametrize(
    "source",
    (
        "def save(path, data):\n    with open(path, 'w') as handle:\n        handle.write(data)\n",
        "def save(path, data):\n    with open(path, mode='ab') as handle:\n        handle.write(data)\n",
        "def save(path, data, mode):\n    with open(path, mode) as handle:\n        return handle\n",
        "from pathlib import Path\n\n\ndef save(path, data):\n    Path(path).write_text(data)\n",
        "import os\n\n\ndef publish(src, dst):\n    os.replace(src, dst)\n",
        "import tempfile\n\n\ndef scratch():\n    return tempfile.TemporaryFile()\n",
        "import shutil\n\n\ndef copy(src, dst):\n    shutil.copyfile(src, dst)\n",
        "import sys\n\n\ndef note(text):\n    print(text, file=sys.stderr)\n",
    ),
)
def test_filesystem_writes_block_state_kinds_as_write_sites(tmp_path: Path, source: str) -> None:
    screen = _screen_for(tmp_path, source)

    assert screen.write_sites, source
    assert screen.status == "CLOSED"
    assert review.screen_blocks(screen, "LEDGER")
    assert review.screen_blocks(screen, "TRANSACTION")
    # A write alone is not an effect-kind role: ROBOT and FINBOT stay refutable only
    # when no open site exists, so the write is a state-kind blocker, not a role.
    assert not review.screen_blocks(screen, "ROBOT")
    assert not review.screen_blocks(screen, "FINBOT")


@pytest.mark.parametrize(
    "source",
    (
        "def load(path):\n    with open(path) as handle:\n        return handle.read()\n",
        "def load(path):\n    with open(path, 'rb') as handle:\n        return handle.read()\n",
        "import os\n\n\ndef name(path):\n    return os.path.basename(path)\n",
        "def canonical(text):\n    return text.replace(' ', '')\n",
    ),
)
def test_read_only_and_common_text_methods_leave_state_kinds_closed(
    tmp_path: Path, source: str
) -> None:
    screen = _screen_for(tmp_path, source)

    assert screen.status == "CLOSED"
    assert screen.write_sites == ()
    assert not review.screen_blocks(screen, "TRANSACTION")
    assert not review.screen_blocks(screen, "LEDGER")


def test_imported_writer_reaches_the_owned_state_refutation(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "src/verifier/alpha.py": "from verifier.beta import persist\n\n\ndef go(value):\n    return persist(value)\n",
            "src/verifier/beta.py": "from verifier.gamma import sink as persist\n",
            "src/verifier/gamma.py": "def sink(value):\n    with open('receipt.json', 'w') as handle:\n        return handle.write(value)\n",
        },
    )

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert ("src/verifier/gamma.py", 2, "filesystem_write", "open") in screen.write_sites
    assert review.screen_blocks(screen, "TRANSACTION")
    assert review.screen_blocks(screen, "LEDGER")
    assert not review.screen_blocks(screen, "ROBOT")


def test_bounded_lazy_loader_reflection_does_not_open_the_package(tmp_path: Path) -> None:
    root = _tree(
        tmp_path,
        {
            "src/verifier/__init__.py": (
                "from importlib import import_module\n\n"
                "_LAZY_EXPORTS = {'hidden': 'verifier.gamma'}\n\n\n"
                "def __getattr__(name):\n"
                "    module_name = _LAZY_EXPORTS[name]\n"
                "    value = getattr(import_module(module_name), name)\n"
                "    globals()[name] = value\n"
                "    return value\n\n\n"
                "def __dir__():\n    return sorted(globals())\n"
            ),
            "src/verifier/gamma.py": "def hidden():\n    return 1\n",
            "src/verifier/alpha.py": "def go():\n    return 1\n",
        },
    )

    screen = review.closed_surface_screen(root, ("src/verifier/alpha.py",))

    assert screen.status == "CLOSED"
    assert screen.open_sites == ()
    assert not review.screen_blocks(screen, "TRANSACTION")


def test_every_refutation_of_every_kind_requires_a_closed_live_screen() -> None:
    catalog = review.review_document()
    for object_id, item in catalog.items():
        screen = review.closed_surface_screen(REPO_ROOT, item["owned_paths"])
        for kind, decision in item["classification"].items():
            if decision["status"] == "DOES_NOT_APPLY":
                assert not review.screen_blocks(screen, kind), (
                    object_id + ":" + kind + " refuted while the live screen is " + screen.status
                )


@pytest.mark.parametrize(
    "source",
    (
        "import shutil\n\n\ndef locate(name):\n    return shutil.which(name)\n",
        "import os\n\n\ndef read(fd):\n    with os.fdopen(fd, 'rb') as handle:\n        return handle.read()\n",
    ),
)
def test_shutil_lookups_and_read_mode_fdopen_are_not_write_sites(
    tmp_path: Path, source: str
) -> None:
    screen = _screen_for(tmp_path, source)

    assert screen.write_sites == ()
    assert not review.screen_blocks(screen, "TRANSACTION")


def test_os_open_with_non_literal_flags_is_a_write_site(tmp_path: Path) -> None:
    source = (
        "import os\n\n\ndef read(path, flags):\n"
        "    with os.fdopen(os.open(path, flags), 'rb') as handle:\n        return handle.read()\n"
    )
    screen = _screen_for(tmp_path, source)

    assert screen.write_sites and screen.write_sites[0][2] == "filesystem_write"
    assert review.screen_blocks(screen, "LEDGER")


def test_callable_stored_on_self_and_invoked_opens_the_closure(tmp_path: Path) -> None:
    source = (
        "class Gate:\n"
        "    def __init__(self, authenticate):\n"
        "        self._authenticate = authenticate\n\n"
        "    def check(self, token):\n"
        "        return self._authenticate(token)\n"
    )
    screen = _screen_for(tmp_path, source)

    assert screen.status == "OPEN"
    assert ("src/verifier/alpha.py", 6, "injected_callable", "self._authenticate") in screen.open_sites
    assert review.screen_blocks(screen, "TRANSACTION")


def test_self_method_call_without_callable_store_stays_closed(tmp_path: Path) -> None:
    source = (
        "class Gate:\n"
        "    def __init__(self, token):\n"
        "        self._token = token\n\n"
        "    def check(self):\n"
        "        return self._render(self._token)\n\n"
        "    def _render(self, value):\n"
        "        return value\n"
    )
    screen = _screen_for(tmp_path, source)

    assert screen.status == "CLOSED"
    assert screen.open_sites == ()

"""Package admission replays the installed 318-object semantic review.

The generic Tier-0 obligation shapes accept any same-status reason or non-empty
declaration.  These tests stub only the retained Tier-0 and namespace contracts
to PASS, then run the real ``package_admission.assess`` replay against a fixture
root whose manifest rows are produced by the installed audit itself.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from verifier.runtime import namespace_contracts
from verifier.runtime import package_manifest_migration
from verifier.runtime import package_semantic_review_partitions as partitions


REMOTE = "https://github.com/TimeLordRaps/verifier.git"
REVISION = "8" * 40
CENSUS_DIGEST = "sha256:" + "c" * 64
GRAPH_ID = "vstd-semantic-replay-fixture-graph"
REVIEW_KINDS = set(partitions.REVIEW_KINDS)
COORDINATES = ("VSTD-T0.2", "VSTD-T0.6")


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def fixture_root(tmp_path: Path) -> dict[str, Any]:
    """Write every owned denominator path and build canonical audited rows."""
    owned = sorted({path for spec in partitions.PARTITION_SPECS for path in spec.owned_paths})
    files: dict[str, str] = {}
    for path in owned:
        raw = f"fixture source for {path}\n".encode()
        target = tmp_path.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        files[path] = _sha(raw)
    base = {
        spec.object_id: {
            "object_id": spec.object_id,
            "kind": spec.primary_kind,
            "operands": {name: list(targets) for name, targets in spec.operands},
            "surfaces": ["file:" + path for path in spec.owned_paths],
            "specializations": [],
            "classification": {},
            "obligations": {},
        }
        for spec in partitions.PARTITION_SPECS
    }
    canonical = partitions.apply_package_semantic_review_partitions(tmp_path, base, files)
    return {"root": tmp_path, "files": files, "objects": list(canonical.values())}


def _assess(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    objects: list[dict[str, Any]],
    *,
    during_admission: Callable[[], None] | None = None,
    namespace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from verifier.runtime import (
        namespace_admission,
        namespace_manifest,
        package_admission,
        package_manifest,
        package_polish,
        self_polish_estate,
        tier_zero,
    )

    root = fixture["root"]
    raw = b'{"fixture": "package-admission-semantic-review-replay"}\n'
    (root / "objects.vstd").write_bytes(raw)
    document = {"namespace": {"objects": objects} if namespace is None else namespace}
    coordinate = {"repository": REMOTE, "revision": REVISION}
    census_files = [{"path": path, "sha256": digest}
                    for path, digest in sorted(fixture["files"].items())]
    census = {"census_digest": CENSUS_DIGEST, "files": census_files}
    obligations = [
        {
            "coordinate": "VSTD-T0." + str(index),
            "name": "Bounded admission check",
            "status": "PASS",
            "assessment_reason": "The retained bounded component passed.",
            "blockers": [],
        }
        for index in range(1, 10)
    ]
    common = {
        "status": "PASS",
        "profile_id": "bounded-admission",
        "profile_digest": "sha256:" + "1" * 64,
        "manifest_digest": _sha(raw),
        "mechanism_digest": "sha256:" + "2" * 64,
        "obligation_count": 9,
        "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
        "obligations": obligations,
        "blockers": [],
        "report_digest": "sha256:" + "3" * 64,
    }
    core = {
        **common,
        "schema_version": tier_zero.REPORT_SCHEMA,
        "source_coordinate": coordinate,
        "claim_boundary": "Bounded retained admission.",
        "finalization": {
            "source_census_digest": CENSUS_DIGEST,
            "source_coordinate": coordinate,
        },
    }
    extension = {
        **common,
        "schema_version": namespace_admission.REPORT_SCHEMA,
        "source_census_digest": CENSUS_DIGEST,
        "findings": [],
        "object_assessments": [],
        "required_obligations": [],
        "assessment_executed": True,
        "next_obligation": None,
    }

    def namespace_extension(*args: Any, **kwargs: Any) -> dict[str, Any]:
        # The census was captured before this point, so a mutation here is the
        # window between admission captures that the replay must still observe.
        if during_admission is not None:
            during_admission()
        return deepcopy(extension)

    monkeypatch.setattr(namespace_manifest, "read_manifest", lambda path: (raw, document))
    monkeypatch.setattr(package_manifest, "select", lambda *args, **kwargs: (
        {"objects": [{"object_id": GRAPH_ID, "object_kind": "GRAPH"}]}, None, (),
    ))
    monkeypatch.setattr(package_polish, "_verifier_selection",
                        lambda manifest, objects: SimpleNamespace(object_id="vstd-fixture-verifier"))
    monkeypatch.setattr(self_polish_estate, "_git_coordinate", lambda root: coordinate)
    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census",
                        lambda root: deepcopy(census))
    monkeypatch.setattr(tier_zero, "assess_legacy_tier_zero",
                        lambda *args, **kwargs: deepcopy(core))
    monkeypatch.setattr(namespace_admission, "assess", namespace_extension)
    return package_admission.assess(root)


def _row(report: dict[str, Any], coordinate: str) -> dict[str, Any]:
    return next(row for row in report["obligations"] if row["coordinate"] == coordinate)


def _first_cell(objects: list[dict[str, Any]], status: str) -> tuple[dict[str, Any], str]:
    for row in objects:
        for kind, cell in row["classification"].items():
            if kind in REVIEW_KINDS and cell["status"] == status:
                return row, kind
    raise AssertionError("fixture has no " + status + " cell")


def _first_obligation(objects: list[dict[str, Any]]) -> tuple[dict[str, Any], str]:
    for row in objects:
        for name in row["obligations"]:
            if name.split("-", 1)[0] in REVIEW_KINDS:
                return row, name
    raise AssertionError("fixture has no reviewed obligation")


def _first_projected_cell(
    objects: list[dict[str, Any]],
) -> tuple[dict[str, Any], str, str]:
    for row in objects:
        for kind, cell in row["classification"].items():
            if kind not in REVIEW_KINDS:
                continue
            projected = package_manifest_migration._compiled_classification_reason(
                cell["status"], cell["reason"]
            )
            if projected != cell["reason"]:
                return row, kind, projected
    raise AssertionError("fixture has no classification reason requiring projection")


def _install_documented_demand_binding(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    objects: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    """Install the compiler's exact reason-ledger-only obligation representation."""
    from verifier.runtime.tier_zero_reasoning import integration

    registry = namespace_contracts.namespace_registry()
    selected: tuple[dict[str, Any], str, dict[str, Any], str] | None = None
    for row in objects:
        owned_paths = sorted(
            (
                surface.removeprefix("file:")
                for surface in row["surfaces"]
                if surface.startswith("file:")
                and surface.removeprefix("file:") in fixture["files"]
            ),
            key=lambda path: (len(path.encode("utf-8")), path),
        )
        if not owned_paths:
            continue
        for kind in REVIEW_KINDS:
            for contract in namespace_contracts.requirements_for(registry, (kind,)):
                if contract["kind"] == kind and contract["id"] not in row["obligations"]:
                    selected = row, kind, contract, owned_paths[0]
                    break
            if selected is not None:
                break
        if selected is not None:
            break
    if selected is None:
        raise AssertionError("fixture has no absent reviewed obligation contract")

    row, kind, contract, evidence_path = selected
    reason_id = "tier0-fixture-documented-demand"
    row["obligations"][contract["id"]] = {
        "reason": f"reasons.vstd:{reason_id}; fulfillment NOT_ESTABLISHED.",
        "evidence": [{
            "path": evidence_path,
            "sha256": fixture["files"][evidence_path],
        }],
        "declaration": {
            field: "NOT_ESTABLISHED"
            for field in contract["declaration_fields"]
        },
    }
    answer = {
        "object_id": row["object_id"],
        "object_kind": kind,
        "reason_id": reason_id,
        "decision": "APPLIES",
    }
    monkeypatch.setattr(integration, "select_root_reasons", lambda root: object())
    monkeypatch.setattr(
        integration,
        "documented_applicability_answers",
        lambda selection, selected_objects: [answer],
    )
    return row, contract["id"]


def _assert_fail_closed(report: dict[str, Any], prefix: str) -> None:
    assert report["status"] == "FAIL"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "FAIL"
        assert any(code.startswith(prefix) for code in row["blockers"]), row["blockers"]


@pytest.mark.parametrize("status", ["DOES_NOT_APPLY", "APPLIES"])
def test_same_status_reason_substitution_fails_closed(fixture_root, monkeypatch, status):
    objects = deepcopy(fixture_root["objects"])
    row, kind = _first_cell(objects, status)
    row["classification"][kind]["reason"] += " A different same-status explanation."

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_CONFLICT:" + row["object_id"])


def test_exact_compiled_classification_projection_replays(fixture_root, monkeypatch):
    monkeypatch.setattr(partitions, "unresolved_inventory", lambda: {})
    objects = deepcopy(fixture_root["objects"])
    row, kind, projected = _first_projected_cell(objects)
    row["classification"][kind]["reason"] = projected

    report = _assess(fixture_root, monkeypatch, objects)

    assert report["status"] == "PASS", [
        item["blockers"][:3] for item in report["obligations"]
    ]


def test_near_miss_compiled_classification_projection_fails_closed(
    fixture_root, monkeypatch,
):
    objects = deepcopy(fixture_root["objects"])
    row, kind, projected = _first_projected_cell(objects)
    row["classification"][kind]["reason"] = projected + " altered"

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(
        report,
        "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_CONFLICT:"
        + row["object_id"]
        + ":"
        + kind,
    )


def test_classification_evidence_substitution_fails_closed(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row, kind = _first_cell(objects, "DOES_NOT_APPLY")
    row["classification"][kind]["evidence"][0]["sha256"] = "sha256:" + "0" * 64

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_CONFLICT:" + row["object_id"])


def test_obligation_reason_substitution_fails_closed(fixture_root, monkeypatch):
    # The audit's preserve path accepts any non-empty reason, so only the exact
    # replay comparison can reject this substitution.
    objects = deepcopy(fixture_root["objects"])
    row, name = _first_obligation(objects)
    row["obligations"][name]["reason"] += " Substituted reason text."

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])


def test_obligation_declaration_value_substitution_fails_closed(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row, name = _first_obligation(objects)
    field = sorted(row["obligations"][name]["declaration"])[0]
    row["obligations"][name]["declaration"][field] += " substituted"

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])


def test_obligation_declaration_field_set_change_fails_closed(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row, name = _first_obligation(objects)
    row["obligations"][name]["declaration"]["unreviewed_field"] = "added text"

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])


def test_obligation_evidence_substitution_fails_closed(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row, name = _first_obligation(objects)
    row["obligations"][name]["evidence"] = [{"path": "src/verifier/hardware/__init__.py",
                                             "sha256": "sha256:" + "5" * 64}]

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])


def test_forged_reviewed_obligation_name_fails_closed(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row = objects[0]
    row["obligations"]["LEDGER-9.9-forged-declaration"] = {
        "reason": "A forged declaration outside the installed contract.",
        "evidence": [],
        "declaration": {"forged": "value"},
    }

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])


def test_exact_documented_demand_binding_replays(fixture_root, monkeypatch):
    monkeypatch.setattr(partitions, "unresolved_inventory", lambda: {})
    objects = deepcopy(fixture_root["objects"])
    _install_documented_demand_binding(fixture_root, monkeypatch, objects)

    report = _assess(fixture_root, monkeypatch, objects)

    assert report["status"] == "PASS", [
        item["blockers"][:3] for item in report["obligations"]
    ]


@pytest.mark.parametrize("mutation", ["reason", "declaration", "evidence"])
def test_near_miss_documented_demand_binding_fails_closed(
    fixture_root, monkeypatch, mutation,
):
    objects = deepcopy(fixture_root["objects"])
    row, name = _install_documented_demand_binding(
        fixture_root, monkeypatch, objects
    )
    binding = row["obligations"][name]
    if mutation == "reason":
        binding["reason"] += " altered"
    elif mutation == "declaration":
        field = sorted(binding["declaration"])[0]
        binding["declaration"][field] = "ESTABLISHED"
    else:
        binding["evidence"][0]["sha256"] = "sha256:" + "0" * 64

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(
        report,
        "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:"
        + row["object_id"]
        + ":"
        + name,
    )


def test_source_drift_during_admission_is_unknown_not_fail(fixture_root, monkeypatch):
    target = sorted(fixture_root["files"])[0]

    def mutate() -> None:
        (fixture_root["root"].joinpath(*target.split("/"))).write_bytes(b"mutated after capture\n")

    report = _assess(fixture_root, monkeypatch, deepcopy(fixture_root["objects"]),
                     during_admission=mutate)

    assert report["status"] == "UNKNOWN"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "UNKNOWN"
        assert any(code.startswith("PACKAGE_SEMANTIC_REVIEW_SOURCE_DIFFERS:") for code in row["blockers"])


def test_unavailable_owned_source_is_unknown_not_fail(fixture_root, monkeypatch):
    target = sorted(fixture_root["files"])[0]

    def remove() -> None:
        fixture_root["root"].joinpath(*target.split("/")).unlink()

    report = _assess(fixture_root, monkeypatch, deepcopy(fixture_root["objects"]),
                     during_admission=remove)

    assert report["status"] == "UNKNOWN"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "UNKNOWN"
        assert any(code.startswith("PACKAGE_SEMANTIC_REVIEW_SOURCE_UNAVAILABLE:") for code in row["blockers"])


def test_exact_replay_is_unknown_while_installed_audit_has_unresolved_cells(
    fixture_root, monkeypatch,
):
    objects = deepcopy(fixture_root["objects"])
    before = deepcopy(objects)
    unresolved = sorted(
        "PACKAGE_SEMANTIC_REVIEW_UNRESOLVED:" + object_id + ":" + kind
        for object_id, kinds in partitions.unresolved_inventory().items()
        for kind in kinds
    )

    report = _assess(fixture_root, monkeypatch, objects)

    assert objects == before, "replay must not mutate the caller's rows"
    if not unresolved:
        assert report["status"] == "PASS"
        return
    assert report["status"] == "UNKNOWN"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "UNKNOWN"
        assert row["blockers"] == unresolved
        assert row["semantic_review_replay"]["status"] == "UNKNOWN"


def test_replay_reads_a_compact_namespace_through_its_expanded_rows(
    fixture_root, monkeypatch,
):
    """Compact v6 rows hold evidence-set pointers, so the replay must see the expansion."""
    from verifier.runtime import namespace_manifest

    monkeypatch.setattr(partitions, "unresolved_inventory", lambda: {})
    objects = deepcopy(fixture_root["objects"])
    compact = {"schema_version": namespace_manifest.COMPACT_SCHEMA, "objects": []}
    expanded: list[dict[str, Any]] = []

    def normalize(value: dict[str, Any]) -> dict[str, Any]:
        expanded.append(value)
        return {"objects": deepcopy(objects)}

    monkeypatch.setattr(namespace_manifest, "normalize_manifest", normalize)

    report = _assess(fixture_root, monkeypatch, objects, namespace=compact)

    assert expanded == [compact]
    assert report["status"] == "PASS", [row["blockers"][:3] for row in report["obligations"]]
    for coordinate in COORDINATES:
        assert _row(report, coordinate)["semantic_review_replay"]["status"] == "PASS"


def test_exact_resolved_replay_passes_and_leaves_unreviewed_objects_to_generic_admission(
    fixture_root, monkeypatch,
):
    monkeypatch.setattr(partitions, "unresolved_inventory", lambda: {})
    objects = deepcopy(fixture_root["objects"])
    objects.append({
        "object_id": "vstd-unreviewed-generic-fixture",
        "kind": "POLICY",
        "operands": {},
        "surfaces": [],
        "specializations": [],
        "classification": {"LEDGER": {"status": "APPLIES", "reason": "Unreviewed.", "evidence": []}},
        "obligations": {"LEDGER-9.9-unreviewed": {
            "reason": "Unreviewed generic obligation.", "evidence": [], "declaration": {},
        }},
    })
    before_root = {path: _sha(fixture_root["root"].joinpath(*path.split("/")).read_bytes())
                   for path in fixture_root["files"]}

    report = _assess(fixture_root, monkeypatch, objects)

    assert report["status"] == "PASS"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "PASS"
        assert row["blockers"] == []
        assert row["semantic_review_replay"]["status"] == "PASS"
    after_root = {path: _sha(fixture_root["root"].joinpath(*path.split("/")).read_bytes())
                  for path in fixture_root["files"]}
    assert after_root == before_root, "replay must not write to the source root"


def _reopen_cell(row: dict[str, Any], kind: str) -> None:
    """Leave the cell exactly as source-drift regeneration does: open, with no evidence."""
    row["classification"][kind] = {
        "status": "UNRESOLVED",
        "reason": "Reopened: the semantics of an owned source changed after this answer was "
                  "reviewed, so it is not inherited and must be reviewed again.",
        "evidence": [],
    }


def _blank_obligation(row: dict[str, Any], name: str) -> None:
    binding = row["obligations"][name]
    row["obligations"][name] = {
        "reason": "", "evidence": [],
        "declaration": {field: "" for field in binding["declaration"]},
    }


def _assert_unknown_unadopted(report: dict[str, Any], prefix: str) -> None:
    assert report["status"] == "UNKNOWN"
    for coordinate in COORDINATES:
        row = _row(report, coordinate)
        assert row["status"] == "UNKNOWN"
        assert any(code.startswith(prefix) for code in row["blockers"]), row["blockers"]
        assert not any("_CONFLICT:" in code for code in row["blockers"]), row["blockers"]


@pytest.mark.parametrize("status", ["DOES_NOT_APPLY", "APPLIES"])
def test_reopened_classification_cell_is_unknown_not_a_conflict(fixture_root, monkeypatch, status):
    """A cell that source drift reopened makes no claim, so it cannot contradict the audit."""
    objects = deepcopy(fixture_root["objects"])
    row, kind = _first_cell(objects, status)
    _reopen_cell(row, kind)

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_unknown_unadopted(
        report, "PACKAGE_SEMANTIC_REVIEW_UNADOPTED:" + row["object_id"] + ":" + kind)


def test_blank_reopened_obligation_is_unknown_not_a_conflict(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row, name = _first_obligation(objects)
    _blank_obligation(row, name)

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_unknown_unadopted(
        report, "PACKAGE_SEMANTIC_REVIEW_UNADOPTED:" + row["object_id"] + ":" + name)


def test_a_real_contradiction_still_fails_beside_unadopted_cells(fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    reopened, kind = _first_cell(objects, "DOES_NOT_APPLY")
    _reopen_cell(reopened, kind)
    other, other_kind = next(
        (row, name) for row in objects if row is not reopened
        for name, cell in row["classification"].items()
        if name in REVIEW_KINDS and cell["status"] == "DOES_NOT_APPLY"
    )
    other["classification"][other_kind]["reason"] += " A different same-status explanation."

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(
        report, "PACKAGE_SEMANTIC_REVIEW_CLASSIFICATION_CONFLICT:" + other["object_id"])
    for coordinate in COORDINATES:
        assert any(
            code.startswith("PACKAGE_SEMANTIC_REVIEW_UNADOPTED:" + reopened["object_id"])
            for code in _row(report, coordinate)["blockers"]
        )


def test_a_blank_obligation_outside_the_installed_contract_is_still_a_conflict(
        fixture_root, monkeypatch):
    objects = deepcopy(fixture_root["objects"])
    row = objects[0]
    row["obligations"]["LEDGER-9.9-forged-declaration"] = {
        "reason": "", "evidence": [], "declaration": {},
    }

    report = _assess(fixture_root, monkeypatch, objects)

    _assert_fail_closed(report, "PACKAGE_SEMANTIC_REVIEW_OBLIGATION_CONFLICT:" + row["object_id"])

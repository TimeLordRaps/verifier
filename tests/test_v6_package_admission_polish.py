"""Version-6 compact namespace admission and Polish integration regressions.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from verifier.runtime import namespace_manifest, package_manifest, tier_zero_manifest
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


REMOTE = "https://github.com/TimeLordRaps/verifier.git"
REVISION = "7" * 40
PIN = "sha256:" + "a" * 64


def _v5_manifest() -> dict[str, Any]:
    retained = tier_zero_manifest.manifest_template(
        repository=REMOTE,
        revision=REVISION,
    )
    rows = [
        {
            **item.to_dict(),
            "specializations": [],
            "surfaces": [],
            "reason": "The package declaration retains this exact bounded role.",
            "classification": {},
            "obligations": {},
        }
        for item in tier_zero_manifest._namespace_objects(retained["objects"])
    ]
    subject = next(row for row in rows if row["kind"] == "OBJECT")
    evidence = [{"path": "src/subject.py", "sha256": PIN}]
    subject["classification"] = {
        "OBJECT": {
            "status": "APPLIES",
            "reason": "The retained subject carries the OBJECT role.",
            "evidence": deepcopy(evidence),
        }
    }
    subject["obligations"] = {
        "OBJECT-0.1-subject-boundary": {
            "reason": "The retained subject boundary remains explicit.",
            "declaration": {"contract": "vstd-package-object"},
            "evidence": deepcopy(evidence),
        }
    }
    return {
        **retained,
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {
            "schema_version": namespace_manifest.SCHEMA,
            "extensions": [],
            "registry_digest": registry_document(namespace_registry())["digest"],
            "objects": rows,
        },
        "representation_updates": [],
    }


def _v6_manifest() -> dict[str, Any]:
    document = deepcopy(_v5_manifest())
    document["schema_version"] = (
        package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    )
    declaration = document["namespace"]
    declaration["schema_version"] = namespace_manifest.COMPACT_SCHEMA
    for row in declaration["objects"]:
        evidence_sets: dict[str, list[dict[str, str]]] = {}
        for decision in row["classification"].values():
            evidence = decision.pop("evidence")
            digest = value_digest(evidence)
            evidence_sets.setdefault(digest, deepcopy(evidence))
            decision["evidence_set_digest"] = digest
        for binding in row["obligations"].values():
            evidence = binding.pop("evidence")
            digest = value_digest(evidence)
            evidence_sets.setdefault(digest, deepcopy(evidence))
            binding["evidence_set_digest"] = digest
        row["evidence_sets"] = evidence_sets
    return document


def _subject(document: dict[str, Any]) -> dict[str, Any]:
    return next(
        row for row in document["namespace"]["objects"]
        if row["kind"] == "OBJECT"
    )


def test_v6_polish_projection_matches_v5_semantics_not_digest_selectors() -> None:
    from verifier.runtime import package_polish

    v5 = _v5_manifest()
    v6 = _v6_manifest()
    normalized = package_polish._semantic_namespace(v6)

    assert normalized == v5["namespace"]
    assert package_polish._graph_declaration_profile(
        v6, package_manifest.retained_contract(v6),
        semantic_namespace=normalized,
    ) == package_polish._graph_declaration_profile(
        v5, package_manifest.retained_contract(v5),
        semantic_namespace=v5["namespace"],
    )
    selected = _subject({"namespace": normalized})
    assert selected["classification"]["OBJECT"]["evidence"] == [
        {"path": "src/subject.py", "sha256": PIN}
    ]
    assert "evidence_set_digest" not in json.dumps(normalized)


@pytest.mark.parametrize("damage", ["missing", "unused", "substituted"])
def test_v6_polish_semantic_selection_rejects_bad_compact_references(
    damage: str,
) -> None:
    from verifier.runtime import package_polish

    document = _v6_manifest()
    subject = _subject(document)
    digest = next(iter(subject["evidence_sets"]))
    if damage == "missing":
        subject["evidence_sets"].clear()
        code = "NAMESPACE_COMPACT_EVIDENCE_SET_REFERENCE_MISSING"
    elif damage == "unused":
        extra = [{"path": "src/unused.py", "sha256": "sha256:" + "b" * 64}]
        subject["evidence_sets"][value_digest(extra)] = extra
        code = "NAMESPACE_COMPACT_EVIDENCE_SET_UNUSED"
    else:
        subject["evidence_sets"][digest][0]["path"] = "src/substituted.py"
        code = "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_DIFFERS"

    with pytest.raises(ValueError, match="^" + code + "$"):
        package_polish._semantic_namespace(document)


def test_v6_namespace_admission_reconciles_normalized_inline_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_admission

    document = _v6_manifest()
    raw = canonical_bytes(document) + b"\n"
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "objects.vstd").write_bytes(raw)
    reconciled: list[tuple[dict[str, Any], bool]] = []

    def reconcile(
        selected: bytes, registry: dict[str, Any], observed: dict[str, Any],
        classified: dict[str, Any], *,
        representations: dict[str, Any] | None = None,
        package_transport: bool = False,
        established_non_applicability: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        del registry, observed, classified, representations, established_non_applicability
        reconciled.append((json.loads(selected), package_transport))
        return {"status": "PASS", "reason": "The bounded interpreters agree."}

    monkeypatch.setattr(namespace_admission, "_reconcile", reconcile)
    report = namespace_admission.assess(tmp_path)

    assert report["assessment_executed"] is True
    assert reconciled == [(_v5_manifest()["namespace"], True)]
    assert report["namespace_manifest_digest"] == namespace_admission.bytes_digest(
        canonical_bytes(_v5_manifest()["namespace"]) + b"\n"
    )
    assert "evidence_set_digest" not in json.dumps(reconciled[0][0])


def test_v6_full_package_admission_selects_the_compact_outer_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import (
        namespace_admission,
        package_admission,
        self_polish_estate,
        tier_zero,
    )

    document = _v6_manifest()
    raw = canonical_bytes(document) + b"\n"
    (tmp_path / "objects.vstd").write_bytes(raw)
    census_digest = "sha256:" + "c" * 64
    coordinate = {"repository": REMOTE, "revision": REVISION}
    obligations = [
        {
            "coordinate": "VSTD-T0." + str(index),
            "name": "Bounded admission check",
            "status": "PASS",
            "assessment_reason": "The bounded component passed.",
            "blockers": [],
        }
        for index in range(1, 10)
    ]
    counts = {"PASS": 9, "FAIL": 0, "UNKNOWN": 0}
    common = {
        "status": "PASS",
        "profile_id": "bounded-admission",
        "profile_digest": "sha256:" + "1" * 64,
        "manifest_digest": self_polish_estate.bytes_digest(raw),
        "mechanism_digest": "sha256:" + "2" * 64,
        "obligation_count": 9,
        "obligation_status_counts": counts,
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
            "source_census_digest": census_digest,
            "source_coordinate": coordinate,
        },
    }
    graph_id = next(
        row["object_id"] for row in document["namespace"]["objects"]
        if row["kind"] == "GRAPH"
    )
    extension = {
        **common,
        "schema_version": namespace_admission.REPORT_SCHEMA,
        "source_census_digest": census_digest,
        "findings": [],
        "object_assessments": [{
            "object_id": graph_id,
            "declared_kind": "GRAPH",
            "effective_kinds": ["GRAPH"],
        }],
        "required_obligations": [],
        "assessment_executed": True,
        "next_obligation": None,
    }
    monkeypatch.setattr(
        self_polish_estate, "_git_coordinate", lambda root: coordinate,
    )
    monkeypatch.setattr(
        self_polish_estate,
        "capture_candidate_source_census",
        lambda root: {"census_digest": census_digest},
    )
    monkeypatch.setattr(
        tier_zero, "assess_legacy_tier_zero", lambda *args, **kwargs: core,
    )
    monkeypatch.setattr(
        namespace_admission, "assess", lambda *args, **kwargs: extension,
    )
    # This compact fixture has no installed 318-object audit or file census; the
    # semantic replay has its own integration tests in its dedicated module.
    monkeypatch.setattr(
        package_admission,
        "_semantic_review_replay",
        lambda *args, **kwargs: {"status": "PASS", "blockers": []},
    )

    report = package_admission.assess(tmp_path)

    assert report["status"] == "PASS"
    assert report["manifest_digest"] == self_polish_estate.bytes_digest(raw)
    assert report["package_graph"]["declaration_count"] == len(
        document["namespace"]["objects"]
    )
    assert report["verifier_execution"]["object_id"]
    assert report["package_graph"]["root_id"] == graph_id


def test_v6_package_polish_passes_only_expanded_evidence_to_consumers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_polish

    document = _v6_manifest()
    raw = canonical_bytes(document) + b"\n"
    (tmp_path / "objects.vstd").write_bytes(raw)
    coordinate = {"repository": REMOTE, "revision": REVISION}
    source = {"source_census_digest": "sha256:" + "d" * 64}
    received: list[dict[str, Any]] = []

    class Evidence:
        def __init__(
            self, root: Path, objects: tuple[Any, ...],
            declaration: dict[str, Any], **kwargs: Any,
        ) -> None:
            del root, objects, kwargs
            received.append(declaration)
            self.execution_transports: dict[tuple[str, str], dict[str, Any]] = {}

        def recapture(self) -> None:
            return None

    class Kinds:
        def __init__(self, root: Path, declaration: dict[str, Any]) -> None:
            del root
            received.append(declaration)
            self.report = {
                "status": "PASS",
                "harness_applicability": {
                    "selection_status": "NOT_SELECTED",
                    "status": "PASS",
                    "blockers": [],
                },
            }

        def recapture(self) -> None:
            return None

    def stop_after_selection(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        del args, kwargs
        raise package_polish.PackagePolishUnknown("TEST_STOP_AFTER_V6_SELECTION")

    monkeypatch.setattr(
        package_polish.self_polish_estate,
        "_git_coordinate",
        lambda root: coordinate,
    )
    monkeypatch.setattr(
        package_polish.self_polish_statics,
        "_capture_coordinate",
        lambda root: source,
    )
    monkeypatch.setattr(package_polish, "mechanism_digest", lambda: PIN)
    monkeypatch.setattr(
        package_polish.tier_zero, "_selected_file", lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        package_polish.package_self_polish,
        "_native_facets_replay",
        lambda *args, **kwargs: {"status": "PASS", "replay_digest": PIN},
    )
    monkeypatch.setattr(package_polish, "InstanceEvidence", Evidence)
    monkeypatch.setattr(package_polish, "KindRequirements", Kinds)
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "SourceContractAssessment",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(package_polish, "_instance_obligations", stop_after_selection)
    monkeypatch.setattr(
        package_polish.self_polish_tiers,
        "_post_replay_source_recapture",
        lambda root, selected: {"status": "PASS"},
    )

    report = package_polish.assess_package_polish(1, tmp_path)

    assert "TEST_STOP_AFTER_V6_SELECTION" in report["blockers"]
    assert "PACKAGE_NATIVE_DIAGNOSTICS_NOT_RUN" in report["blockers"]
    assert len(received) == 2
    assert received[0] == received[1] == _v5_manifest()["namespace"]
    assert "evidence_set_digest" not in json.dumps(received)
    assert report["package_graph"]["declaration_digest"] == value_digest(
        _v5_manifest()["namespace"]["objects"]
    )
    assert "declarations" not in report["package_graph"]


def test_v6_capacity_replay_uses_the_same_expanded_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_polish

    document = _v6_manifest()
    raw = canonical_bytes(document) + b"\n"
    (tmp_path / "objects.vstd").write_bytes(raw)
    coordinate = {"repository": REMOTE, "revision": REVISION}
    source = {"source_census_digest": "sha256:" + "e" * 64}
    received: list[dict[str, Any]] = []

    class Kinds:
        def __init__(self, root: Path, declaration: dict[str, Any]) -> None:
            del root
            received.append(declaration)

        def recapture(self) -> None:
            return None

    monkeypatch.setattr(
        package_polish.self_polish_estate,
        "_git_coordinate",
        lambda root: coordinate,
    )
    monkeypatch.setattr(
        package_polish.self_polish_statics,
        "_capture_coordinate",
        lambda root: source,
    )
    monkeypatch.setattr(package_polish, "KindRequirements", Kinds)
    monkeypatch.setattr(
        package_polish,
        "_obligation_selection_preflight",
        lambda *args, **kwargs: (None, []),
    )

    selected = package_polish._source_capacity_binding(tmp_path, 1)

    assert received == [_v5_manifest()["namespace"]]
    assert "evidence_set_digest" not in json.dumps(received)
    assert selected["package_graph"]["declaration_digest"] == value_digest(
        _v5_manifest()["namespace"]["objects"]
    )
    assert selected["package_graph"]["object_payloads_transport"] == (
        "MANIFEST_DIGEST_BOUND_REFERENCES"
    )


"""Version-5 package regressions for Verifier Standard (VSTD).

The distribution check inspects a wheel and source distribution (sdist) without
installing either artifact.  The admission check keeps the version-5 manifest
parser, package bridge, report composer, and targeted gate dispatch real while
replacing only the two expensive component assessments with bounded receipts.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from verifier.runtime import package_manifest, tier_zero_manifest
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_NAME = "verifier-objects-manifest-5.schema.json"
REMOTE = "https://github.com/TimeLordRaps/verifier.git"
REVISION = "1" * 40


def _copy_build_source(destination: Path) -> None:
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            ".pytest_cache",
            ".venv",
            "*.egg-info",
            "__pycache__",
            "artifacts_tmp",
            "build",
            "dist",
        ),
    )


def test_v5_schema_is_in_built_wheel_and_sdist(tmp_path: Path) -> None:
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    _copy_build_source(source)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--outdir",
            str(artifacts),
            ".",
        ],
        cwd=source,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]
    wheels = list(artifacts.glob("*.whl"))
    sdists = list(artifacts.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1

    expected = (source / "src" / "verifier" / "schemas" / SCHEMA_NAME).read_bytes()
    wheel_member = "verifier/schemas/" + SCHEMA_NAME
    with zipfile.ZipFile(wheels[0]) as archive:
        assert archive.namelist().count(wheel_member) == 1
        assert archive.read(wheel_member) == expected

    with tarfile.open(sdists[0], "r:gz") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.replace("\\", "/").endswith(
                "/src/verifier/schemas/" + SCHEMA_NAME
            )
        ]
        assert len(matches) == 1 and matches[0].isfile()
        stream = archive.extractfile(matches[0])
        assert stream is not None and stream.read() == expected


def _v5_manifest() -> dict[str, Any]:
    retained = tier_zero_manifest.manifest_template(
        repository=REMOTE,
        revision=REVISION,
    )
    objects = [
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
    return {
        **retained,
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {
            "schema_version": "verifier-objects-manifest-2",
            "extensions": [],
            "registry_digest": registry_document(namespace_registry())["digest"],
            "objects": objects,
        },
        "representation_updates": [],
    }


def _obligations() -> list[dict[str, Any]]:
    return [
        {
            "coordinate": f"VSTD-T0.{index}",
            "name": "Bounded admission check",
            "status": "PASS",
            "assessment_reason": "The selected bounded test component passed.",
            "blockers": [],
        }
        for index in range(1, 10)
    ]


def _count_key(value: Any, selected: str) -> int:
    if isinstance(value, dict):
        return int(selected in value) + sum(
            _count_key(item, selected) for item in value.values()
        )
    if isinstance(value, list):
        return sum(_count_key(item, selected) for item in value)
    return 0


def _install_bounded_components(tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
    """Write the compact v5 manifest and stub only the two expensive assessments."""
    from verifier.runtime import namespace_admission, self_polish_estate, tier_zero

    document = _v5_manifest()
    raw = canonical_bytes(document) + b"\n"
    (tmp_path / "objects.vstd").write_bytes(raw)
    coordinate = {"repository": REMOTE, "revision": REVISION}
    census_digest = "sha256:" + "c" * 64
    manifest_digest = self_polish_estate.bytes_digest(raw)
    graph_id = next(
        row["object_id"]
        for row in document["namespace"]["objects"]
        if row["kind"] == "GRAPH"
    )
    assessments = [
        {
            "object_id": graph_id,
            "declared_kind": "GRAPH",
            "effective_kinds": ["GRAPH"],
        }
    ]
    required = [
        {
            "object_id": graph_id,
            "kind": "GRAPH",
            "id": "GRAPH-0.1-bounded-membership",
            "status": "PASS",
        }
    ]
    component_obligations = _obligations()
    counts = {"PASS": 9, "FAIL": 0, "UNKNOWN": 0}
    core_report = {
        "schema_version": tier_zero.REPORT_SCHEMA,
        "status": "PASS",
        "profile_id": "bounded-retained-admission",
        "profile_digest": "sha256:" + "1" * 64,
        "manifest_digest": manifest_digest,
        "mechanism_digest": "sha256:" + "2" * 64,
        "source_coordinate": coordinate,
        "obligation_count": 9,
        "obligation_status_counts": counts,
        "obligations": component_obligations,
        "blockers": [],
        "claim_boundary": "The retained component receipt is bounded test input.",
        "finalization": {
            "source_census_digest": census_digest,
            "source_coordinate": coordinate,
        },
        "report_digest": "sha256:" + "3" * 64,
    }
    namespace_report = {
        "schema_version": namespace_admission.REPORT_SCHEMA,
        "status": "PASS",
        "profile_id": namespace_admission.PROFILE_ID,
        "profile_digest": "sha256:" + "4" * 64,
        "manifest_digest": manifest_digest,
        "mechanism_digest": "sha256:" + "5" * 64,
        "source_census_digest": census_digest,
        "obligation_count": 9,
        "obligation_status_counts": counts,
        "obligations": component_obligations,
        "blockers": [],
        "findings": [],
        "object_assessments": assessments,
        "required_obligations": required,
        "assessment_executed": True,
        "next_obligation": None,
        "report_digest": "sha256:" + "6" * 64,
    }
    monkeypatch.setattr(self_polish_estate, "_git_coordinate", lambda root: coordinate)
    monkeypatch.setattr(
        self_polish_estate,
        "capture_candidate_source_census",
        lambda root: {"census_digest": census_digest},
    )
    monkeypatch.setattr(
        tier_zero,
        "assess_legacy_tier_zero",
        lambda *args, **kwargs: core_report,
    )
    monkeypatch.setattr(
        namespace_admission,
        "assess",
        lambda *args, **kwargs: namespace_report,
    )
    return {
        "document": document,
        "coordinate": coordinate,
        "manifest_digest": manifest_digest,
        "graph_id": graph_id,
        "assessments": assessments,
        "required": required,
        "core_report": core_report,
        "namespace_report": namespace_report,
    }


def test_v5_package_admission_and_target_gate_keep_compact_v4_report(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from verifier.runtime import manifest_gate, package_admission, self_polish_estate

    fixture = _install_bounded_components(tmp_path, monkeypatch)
    # This 26-object synthetic package has no installed 318-object audit or file
    # census, so the replay is stubbed for this distribution subject only. The
    # fail-closed test below runs the same fixture unstubbed to pin the bypass.
    monkeypatch.setattr(
        package_admission,
        "_semantic_review_replay",
        lambda *args, **kwargs: {"status": "PASS", "blockers": []},
    )
    document = fixture["document"]
    coordinate = fixture["coordinate"]
    manifest_digest = fixture["manifest_digest"]
    graph_id = fixture["graph_id"]
    assessments = fixture["assessments"]
    required = fixture["required"]
    core_report = fixture["core_report"]
    namespace_report = fixture["namespace_report"]

    report = package_admission.assess(tmp_path)
    assert report["schema_version"] == package_admission.REPORT_SCHEMA
    assert report["status"] == "PASS"
    assert report["source_coordinate"] == coordinate
    assert report["manifest_digest"] == manifest_digest
    assert report["object_assessments"] == assessments
    assert report["required_obligations"] == required
    assert report["package_graph"]["declaration_count"] == len(
        document["namespace"]["objects"]
    )
    assert report["package_graph"]["declaration_digest"] == value_digest(
        document["namespace"]["objects"]
    )
    assert "objects" not in report["package_graph"]
    assert "object_assessments" not in report["retained_admission"]
    assert "object_assessments" not in report["namespace_admission"]
    assert "required_obligations" not in report["namespace_admission"]
    assert "assessment_executed" not in report["namespace_admission"]
    assert _count_key(report, "object_assessments") == 1
    assert _count_key(report, "required_obligations") == 1
    assert _count_key(report, "namespace") == 0
    assert report["retained_admission"]["profile_digest"] == core_report["profile_digest"]
    assert report["retained_admission"]["report_digest"] == core_report["report_digest"]
    assert report["namespace_admission"]["profile_digest"] == namespace_report["profile_digest"]
    assert report["namespace_admission"]["report_digest"] == namespace_report["report_digest"]
    assert report["verifier_execution"]["manifest_digest"] == manifest_digest
    assert report["verifier_execution"]["mechanism_digest"] == report["mechanism_digest"]

    gate = manifest_gate.assess_object_gate(
        graph_id,
        "VSTD-T0.1-namespace-admission",
        tmp_path,
    )
    assert gate["schema_version"] == package_admission.REPORT_SCHEMA
    assert gate["status"] == gate["package_admission_status"] == "PASS"
    assert gate["selection_status"] == "PASS"
    assert gate["selected_obligation"]["coordinate"] == "VSTD-T0.1"
    assert gate["manifest_digest"] == manifest_digest
    assert gate["source_coordinate"] == coordinate
    assert _count_key(gate, "object_assessments") == 1
    assert _count_key(gate, "required_obligations") == 1
    assert "object_assessments" not in gate["namespace_admission"]
    assert "objects" not in gate["package_graph"]


def test_v5_incomplete_fixture_without_semantic_replay_fails_closed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from verifier.runtime import package_admission

    _install_bounded_components(tmp_path, monkeypatch)
    report = package_admission.assess(tmp_path)

    replay_rows = [
        row
        for row in report["obligations"]
        if row["coordinate"] in package_admission.SEMANTIC_REVIEW_COORDINATES
    ]
    assert report["status"] == "FAIL"
    assert len(replay_rows) == 2
    for row in replay_rows:
        assert row["status"] == "FAIL"
        assert row["semantic_review_replay"]["status"] == "FAIL"
        assert any(
            code.startswith("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:")
            for code in row["semantic_review_replay"]["blockers"]
        )
    assert any(
        code.startswith("PACKAGE_SEMANTIC_REVIEW_OBJECT_MISSING:")
        for code in report["blockers"]
    )

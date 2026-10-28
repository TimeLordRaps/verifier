# Terminology: line feed (LF).
from __future__ import annotations

from pathlib import Path
import json
import re
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace

import pytest

from verifier.runtime import tier_zero
from verifier.runtime import package_self_polish
from verifier.runtime import self_polish_estate_native_evidence
from verifier.runtime.package_original_kind_catalog import (
    ORIGINAL_KIND_QUESTION_DENOMINATOR,
)


def test_reason_closure_accepts_optional_conservative_denial_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest, package_manifest

    selection = SimpleNamespace(
        authority={"path": "reasons.vstd", "only_authored_reason_input": True},
        ir_digest="sha256:" + "1" * 64,
        ir={"reasons": [{"id": "retain-actuator"}]},
        classification_decisions=({
            "reason_id": "retain-actuator",
            "object_id": "selected-object",
            "object_kind": "ACTUATOR",
            "decision": "APPLIES",
        },),
    )
    document = {
        "schema_version": next(iter(package_manifest.SCHEMAS)),
        "namespace": {
            "schema_version": "test-expanded-namespace",
            "objects": [{
                "object_id": "selected-object",
                "classification": {
                    "ACTOR": {"status": "UNRESOLVED"},
                    "ACTUATOR": {"status": "DOES_NOT_APPLY"},
                },
            }],
        },
    }
    selection.classification_decisions += ({
        "reason_id": "retain-actor",
        "object_id": "selected-object",
        "object_kind": "ACTOR",
        "decision": "APPLIES",
    },)

    monkeypatch.setattr(tier_zero, "_selected_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        tier_zero.reason_integration,
        "select_root_reasons",
        lambda _root: selection,
    )
    monkeypatch.setattr(
        namespace_manifest,
        "read_manifest",
        lambda _path: (b"", document),
    )

    result = tier_zero._reason_closure(
        tmp_path,
        {},
        {"obligation_reason_provider": {"path": "reasons.vstd"}},
    )

    assert result["status"] == "PASS"
    assert result["open_classification_count"] == 1
    assert result["reconciled_classification_count"] == 1
    assert result["denial_override_eligible_count"] == 1
    assert result["conservative_override_count"] == 1
    assert result["reconciled_total_classification_count"] == 2
    assert result["orphaned_classification_count"] == 0


def _passing_package_admission_report() -> dict:
    obligations = [
        {
            "coordinate": f"VSTD-T0.{index}",
            "status": "PASS",
            "blockers": [],
            "assessment_reason": "Synthetic prerequisite passed.",
            "evidence": {},
        }
        for index in range(1, 10)
    ]
    return {
        "schema_version": "verifier-tier-zero-package-admission-report-4",
        "status": "PASS",
        "obligation_count": 9,
        "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
        "obligations": obligations,
        "blockers": [],
        "findings": [],
        "finalization": {
            "status": "PASS",
            "complete": True,
            "finalized": True,
            "closed_coordinates": [row["coordinate"] for row in obligations],
            "unclosed_coordinates": [],
            "reason": "Synthetic package admission passed.",
        },
        "report_digest": "sha256:" + "0" * 64,
    }


def test_retained_version_one_closes_with_native_boundary_applicability() -> None:
    root = Path(__file__).parents[1]
    report = tier_zero.assess_legacy_tier_zero(root)
    assert report["status"] == "PASS"
    assert report["obligation_count"] == 9
    assert report["obligation_status_counts"] == {
        "PASS": 9, "FAIL": 0, "UNKNOWN": 0,
    }
    assert report["blockers"] == []
    outcomes = {row["coordinate"]: row for row in report["obligations"]}
    assert outcomes["VSTD-T0.4"]["evidence"]["candidate_count"] > 10_000
    assert outcomes["VSTD-T0.4"]["status"] == "PASS"
    assert outcomes["VSTD-T0.4"]["evidence"][
        "native_not_applicable_surface_ids"
    ] == [
        "unresolved-surface:external-plugin-estate",
        "unresolved-surface:generated-build-backend-estate",
        "unresolved-surface:runtime-environment-estate",
    ]
    assert outcomes["VSTD-T0.4"]["evidence"][
        "unresolved_excluded_surface_ids"
    ] == []
    assert outcomes["VSTD-T0.9"]["status"] == "PASS"
    assert outcomes["VSTD-T0.9"]["evidence"]["unknown_preserved"] is True
    assert outcomes["VSTD-T0.5"]["evidence"]["slot_count"] == 234
    assert outcomes["VSTD-T0.5"]["evidence"]["route_count"] == 408
    reason_evidence = outcomes["VSTD-T0.6"]["evidence"]
    assert reason_evidence["open_classification_count"] == 11_158
    assert reason_evidence["denial_override_eligible_count"] == 3_514
    assert reason_evidence["classification_reason_count"] == 13_321
    assert reason_evidence["reconciled_classification_count"] == 11_158
    assert reason_evidence["conservative_override_count"] == 2_163
    assert reason_evidence["reconciled_total_classification_count"] == 13_321
    assert reason_evidence["missing_classification_count"] == 0
    assert reason_evidence["orphaned_classification_count"] == 0
    assert reason_evidence["reason_authority"]["path"] == "reasons.vstd"
    assert reason_evidence["reason_authority"]["only_authored_reason_input"] is True
    assert outcomes["VSTD-T0.8"]["evidence"]["structural_agreement_status"] == "PASS"
    assert all(row["assessment_reason"].strip() for row in outcomes.values())
    assert report["finalization"]["status"] == "PASS"
    assert report["finalization"]["complete"] is True
    assert report["finalization"]["finalized"] is True
    assert report["finalization"]["scope"] == "TIER_ZERO_REPOSITORY_ADMISSION_ONLY"
    assert report["finalization"]["closed_coordinates"] == [
        f"VSTD-T0.{index}" for index in range(1, 10)
    ]
    assert report["finalization"]["unclosed_coordinates"] == []
    assert report["finalization"]["profile_digest"] == report["profile_digest"]
    assert report["finalization"]["mechanism_digest"] == report["mechanism_digest"]
    assert report["mechanism_digest"] == tier_zero.mechanism_digest()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", report["mechanism_digest"])
    assert report["finalization"]["source_coordinate"] == report["source_coordinate"]
    assert "All nine fixed Tier-0" in report["finalization"]["reason"]
    assert "new profile version and digest" in report["finalization"]["profile_change_rule"]
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["release_authorized"] is False


def test_orchestrator_reads_packaged_bytes_and_profile_only_digests_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import tier_zero_profile

    captured: list[tuple[bytes, bytes]] = []
    real_digest = tier_zero_profile.mechanism_digest

    def spy(module_bytes: bytes, specification_bytes: bytes) -> str:
        captured.append((module_bytes, specification_bytes))
        return real_digest(module_bytes, specification_bytes)

    monkeypatch.setattr(tier_zero_profile, "mechanism_digest", spy)
    module = Path(tier_zero_profile.__file__).resolve()
    specification = module.parents[1] / "standard" / "TIER_ZERO.md"
    digest = tier_zero.mechanism_digest()
    assert captured == [(module.read_bytes(), specification.read_bytes())]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


@pytest.mark.parametrize("status,blocker", [
    ("UNKNOWN", "TIER_ZERO_NODE_RECONCILER_UNAVAILABLE"),
    ("FAIL", "TIER_ZERO_NODE_STRUCTURAL_DISAGREEMENT"),
])
def test_unclosed_tier_zero_never_finalizes_and_package_preserves_verdict(
        monkeypatch: pytest.MonkeyPatch, status: str, blocker: str) -> None:
    root = Path(__file__).parents[1]
    monkeypatch.setattr(
        tier_zero, "_node_structural_reconciliation",
        lambda *_args: {"status": status, "blockers": [blocker]},
    )
    report = tier_zero.assess_legacy_tier_zero(root)
    assert report["status"] == status
    assert report["finalization"]["complete"] is False
    assert report["finalization"]["finalized"] is False
    assert report["finalization"]["unclosed_coordinates"] == ["VSTD-T0.8"]
    row = next(row for row in report["obligations"]
               if row["coordinate"] == "VSTD-T0.8")
    assert blocker in row["assessment_reason"]
    monkeypatch.setattr(tier_zero, "assess_tier_zero", lambda *_args: report)
    bound = package_self_polish._tier_zero_repository_admission(
        root, {"source_head": report["source_coordinate"]["revision"]},
        {"candidate_source_census_digest":
         report["finalization"]["source_census_digest"]},
    )
    assert bound["status"] == status
    assert bound["source_binding_status"] == "PASS"
    assert bound["unclosed_coordinates"] == ["VSTD-T0.8"]


def test_exclusion_without_reason_cannot_pass_surface_closure() -> None:
    estate = {
        "candidates": [{
            "candidate_id": "unresolved-surface:external-plugin-estate",
            "category": "external", "metadata": {},
        }],
        "candidate_count": 1, "candidate_universe_digest": "unused",
        "estate_digest": "unused", "required_categories": ["external"],
    }
    manifest = {"surface_rules": [{"category": "external", "disposition": "EXCLUDED"}]}
    result = tier_zero._surface_closure(estate, manifest)
    assert result["status"] == "FAIL"
    assert "TIER_ZERO_EXCLUDED_SURFACE_REASON_MISSING" in result["blockers"]


def test_reasoned_unknown_exclusion_stays_unknown_not_pass() -> None:
    estate = {
        "candidates": [{
            "candidate_id": "unresolved-surface:external-plugin-estate",
            "category": "unresolved_surface",
            "applicability_status": "UNKNOWN",
            "authority_status": "NOT_ESTABLISHED",
            "evidence_status": "NOT_ESTABLISHED",
            "semantic_status": "NOT_ESTABLISHED",
            "metadata": {
                "enumeration_status": "UNKNOWN",
                "reason": "External plugin entry points are not imported or executed.",
            },
        }],
        "candidate_count": 1,
        "candidate_universe_digest": "unused",
        "estate_digest": "unused",
        "required_categories": ["unresolved_surface"],
    }
    manifest = {"surface_rules": [{
        "category": "unresolved_surface",
        "disposition": "EXCLUDED",
    }]}

    result = tier_zero._surface_closure(estate, manifest)

    assert result["status"] == "UNKNOWN"
    assert result["blockers"] == [
        "TIER_ZERO_EXCLUDED_SURFACE_APPLICABILITY_UNRESOLVED"
    ]
    assert result["excluded_surface_reason_preservation"] == "PASS"


def test_exact_native_not_applicable_boundary_closes_exclusion() -> None:
    body = {
        "candidate_id": "unresolved-surface:external-plugin-estate",
        "category": "unresolved_surface",
        "candidate_type": "EXPLICIT_UNKNOWN_SURFACE",
        "source_refs": [],
        "mechanical_status": "PASS",
        "applicability_status": "UNKNOWN",
        "authority_status": "NOT_ESTABLISHED",
        "evidence_status": "NOT_ESTABLISHED",
        "semantic_status": "NOT_ESTABLISHED",
        "metadata": {
            "surface_id": "external-plugin-estate",
            "enumeration_status": "UNKNOWN",
            "reason": "External plugin entry points are not imported or executed.",
        },
    }
    candidate = {
        **body,
        "candidate_digest": self_polish_estate_native_evidence.value_digest(body),
    }
    estate = {
        "candidates": [candidate],
        "candidate_count": 1,
        "candidate_universe_digest": "unused",
        "estate_digest": "unused",
        "required_categories": ["unresolved_surface"],
    }
    manifest = {"surface_rules": [{
        "category": "unresolved_surface",
        "disposition": "EXCLUDED",
    }]}

    result = tier_zero._surface_closure(estate, manifest)

    assert result["status"] == "PASS"
    assert result["blockers"] == []
    assert result["native_not_applicable_surface_ids"] == [
        "unresolved-surface:external-plugin-estate"
    ]
    assert result["unresolved_excluded_surface_ids"] == []


def test_reasoned_false_exclusion_remains_fail() -> None:
    estate = {
        "candidates": [{
            "candidate_id": "python-function:verifier.subject:run",
            "category": "python_function",
            "metadata": {"reason": "Caller declared this out of scope."},
        }],
        "candidate_count": 1,
        "candidate_universe_digest": "unused",
        "estate_digest": "unused",
        "required_categories": ["python_function"],
    }
    manifest = {"surface_rules": [{
        "category": "python_function",
        "disposition": "EXCLUDED",
    }]}

    result = tier_zero._surface_closure(estate, manifest)

    assert result["status"] == "FAIL"
    assert "TIER_ZERO_FALSE_SOURCE_SURFACE_EXCLUSION" in result["blockers"]
    assert "TIER_ZERO_EXCLUDED_SURFACE_APPLICABILITY_UNRESOLVED" not in result["blockers"]


def test_owned_surface_still_passes_surface_closure() -> None:
    estate = {
        "candidates": [{
            "candidate_id": "python-function:verifier.subject:run",
            "category": "python_function",
            "metadata": {},
        }],
        "candidate_count": 1,
        "candidate_universe_digest": "unused",
        "estate_digest": "unused",
        "required_categories": ["python_function"],
    }
    manifest = {"surface_rules": [{
        "category": "python_function",
        "disposition": "OWNED",
    }]}

    result = tier_zero._surface_closure(estate, manifest)

    assert result["status"] == "PASS"
    assert result["blockers"] == []


def test_reasoned_unknown_exclusion_keeps_boundary_pass_and_aggregate_unknown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    digest = "sha256:" + "1" * 64
    coordinate = {"repository": "example/repository", "revision": "a" * 40}
    census = {"census_digest": digest}
    estate = {
        "candidates": [{
            "candidate_id": "unresolved-surface:external-plugin-estate",
            "category": "unresolved_surface",
            "applicability_status": "UNKNOWN",
            "authority_status": "NOT_ESTABLISHED",
            "evidence_status": "NOT_ESTABLISHED",
            "semantic_status": "NOT_ESTABLISHED",
            "metadata": {
                "enumeration_status": "UNKNOWN",
                "reason": "External plugin entry points are not imported or executed.",
            },
        }],
        "candidate_count": 1,
        "candidate_universe_digest": digest,
        "estate_digest": digest,
        "required_categories": ["unresolved_surface"],
        "post_source_census": census,
    }
    manifest = {"surface_rules": [{
        "category": "unresolved_surface",
        "disposition": "EXCLUDED",
    }]}
    validation = {
        "manifest_digest": digest,
        "manifest_value_digest": digest,
        "profile_digest": digest,
        "status": "PASS",
        "object_count": 26,
        "object_kind_digest": digest,
        "graph_digest": digest,
    }
    monkeypatch.setattr(
        tier_zero.self_polish_estate,
        "_git_coordinate",
        lambda _root: coordinate,
    )
    monkeypatch.setattr(
        tier_zero.tier_zero_manifest,
        "load_manifest",
        lambda *_args, **_kwargs: (manifest, validation),
    )
    monkeypatch.setattr(
        tier_zero.self_polish_estate,
        "build_candidate_estate",
        lambda *_args, **_kwargs: estate,
    )
    monkeypatch.setattr(
        tier_zero.self_polish_estate,
        "capture_candidate_source_census",
        lambda _root: census,
    )
    monkeypatch.setattr(tier_zero, "_denominator_closure", lambda _estate: {
        "status": "PASS",
        "blockers": [],
        "slot_count": 234,
        "route_count": 408,
    })
    monkeypatch.setattr(tier_zero, "_reason_closure", lambda *_args: {
        "status": "PASS",
        "blockers": [],
        "objective_reason_count": 408,
        "slot_reason_count": 234,
    })
    monkeypatch.setattr(tier_zero, "_node_structural_reconciliation", lambda *_args: {
        "status": "PASS",
        "blockers": [],
        "compared_fields": [],
    })
    monkeypatch.setattr(tier_zero, "mechanism_digest", lambda: digest)

    report = tier_zero.assess_legacy_tier_zero(tmp_path)
    outcomes = {row["coordinate"]: row for row in report["obligations"]}

    assert report["status"] == "UNKNOWN"
    assert report["finalization"]["complete"] is False
    assert report["finalization"]["unclosed_coordinates"] == ["VSTD-T0.4"]
    assert outcomes["VSTD-T0.4"]["status"] == "UNKNOWN"
    assert outcomes["VSTD-T0.9"]["status"] == "PASS"
    assert outcomes["VSTD-T0.9"]["evidence"]["unknown_preserved"] is True


def test_package_tier_zero_downgrades_pass_for_exact_unresolved_original_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stable_census(monkeypatch)
    from verifier.runtime import (
        namespace_manifest,
        package_admission,
        package_manifest,
        package_original_kind_catalog,
    )

    document = {
        "schema_version": package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {"schema_version": namespace_manifest.COMPACT_SCHEMA},
    }
    normalized = {
        "schema_version": namespace_manifest.SCHEMA,
        "objects": [
            {
                "object_id": "vstd-simulation",
                "kind": "SIM",
                "classification": {},
            }
        ],
    }
    monkeypatch.setattr(
        namespace_manifest, "read_manifest", lambda _path: (b"{}\n", document)
    )
    monkeypatch.setattr(
        namespace_manifest, "normalize_manifest", lambda _namespace: normalized
    )
    monkeypatch.setattr(
        package_admission,
        "assess",
        lambda *args, **kwargs: deepcopy(_passing_package_admission_report()),
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "admission_closure_report",
        lambda rows, **_kwargs: {
            "status": "UNKNOWN",
            "question_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
            "decided_count": ORIGINAL_KIND_QUESTION_DENOMINATOR - 1,
            "unresolved_count": 1,
            "unresolved": [
                {"object_id": "vstd-simulation", "kind": "MODEL"}
            ],
            "next_unresolved": {
                "object_id": "vstd-simulation",
                "kind": "MODEL",
            },
            "diagnostic": (
                "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
                "vstd-simulation:MODEL"
            ),
            "next_conflict": None,
        },
    )

    report = tier_zero.assess_tier_zero(".")

    assert report["status"] == "UNKNOWN"
    assert report["obligation_count"] == 9
    assert report["obligation_status_counts"] == {
        "PASS": 8,
        "FAIL": 0,
        "UNKNOWN": 1,
    }
    selected = next(
        row for row in report["obligations"] if row["coordinate"] == "VSTD-T0.2"
    )
    assert selected["status"] == "UNKNOWN"
    assert (
        selected["evidence"]["original_kind_closure"]["question_count"]
        == ORIGINAL_KIND_QUESTION_DENOMINATOR
    )
    finding = report["findings"][-1]
    assert finding["object_id"] == "vstd-simulation"
    assert finding["classification_kind"] == "MODEL"
    assert finding["coordinate"] == "VSTD-T0.2"
    assert finding["gate_id"] == "object-inventory"
    assert finding["status"] == "UNKNOWN"
    assert finding["rerun_argv"] == [
        "vstd",
        "gate",
        "--object",
        "vstd-simulation",
        "--obligation",
        "VSTD-T0.2-object-denominator-closure",
    ]
    assert report["finalization"]["complete"] is False
    assert report["finalization"]["unclosed_coordinates"] == ["VSTD-T0.2"]


def test_package_tier_zero_preserves_catalog_status_contradiction_as_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stable_census(monkeypatch)
    from verifier.runtime import (
        namespace_manifest,
        package_admission,
        package_manifest,
        package_original_kind_catalog,
    )

    document = {
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {
            "schema_version": namespace_manifest.SCHEMA,
            "objects": [
                {
                    "object_id": "vstd-simulation",
                    "kind": "SIM",
                    "classification": {
                        "SIM": {
                            "status": "DOES_NOT_APPLY",
                            "reason": "Contradictory refutation.",
                            "evidence": [{
                                "path": "sim.py",
                                "sha256": "sha256:" + "1" * 64,
                            }],
                        }
                    },
                }
            ],
        },
    }
    monkeypatch.setattr(
        namespace_manifest, "read_manifest", lambda _path: (b"{}\n", document)
    )
    monkeypatch.setattr(
        namespace_manifest,
        "normalize_manifest",
        lambda namespace: deepcopy(namespace),
    )
    monkeypatch.setattr(
        package_admission,
        "assess",
        lambda *args, **kwargs: deepcopy(_passing_package_admission_report()),
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "admission_closure_report",
        lambda rows, **_kwargs: {
            "status": "FAIL",
            "question_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
            "decided_count": ORIGINAL_KIND_QUESTION_DENOMINATOR,
            "unresolved_count": 0,
            "unresolved": [],
            "next_unresolved": None,
            "next_conflict": {
                "object_id": "vstd-simulation",
                "kind": "SIM",
                "expected_status": "APPLIES",
                "actual_status": "DOES_NOT_APPLY",
            },
            "diagnostic": (
                "PACKAGE_ORIGINAL_KIND_CATALOG_CONFLICT:"
                "vstd-simulation:SIM"
            ),
        },
    )

    report = tier_zero.assess_tier_zero(".")

    assert report["status"] == "FAIL"
    finding = report["findings"][-1]
    assert finding["status"] == "FAIL"
    assert finding["object_id"] == "vstd-simulation"
    assert finding["classification_kind"] == "SIM"
    assert finding["code"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:vstd-simulation:SIM"
    )


SYNTHETIC_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _census(digest: str, path: str = "owned.py") -> dict:
    """Return one census capture whose file bytes carry the supplied digest."""
    return {
        "census_digest": "sha256:" + sha256(digest.encode("ascii")).hexdigest(),
        "files": [{"path": path, "sha256": digest}],
    }


def _stable_census(monkeypatch: pytest.MonkeyPatch, digest: str = SYNTHETIC_DIGEST) -> None:
    from verifier.runtime import self_polish_estate

    monkeypatch.setattr(
        self_polish_estate,
        "capture_candidate_source_census",
        lambda _root, **_kwargs: _census(digest),
    )


def _synthetic_package(object_count: int, *, owned: bool = True) -> tuple[dict, dict]:
    """Return a namespace document and a matching review document of N objects."""
    from verifier.runtime import (
        namespace_manifest,
        package_manifest,
        package_original_kind_catalog,
    )

    kinds = package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS
    objects = [
        {"object_id": "vstd-" + str(index).zfill(3), "kind": "SIM",
         "surfaces": ["file:owned.py"] if owned else [], "classification": {}}
        for index in range(object_count)
    ]
    document = {
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {"schema_version": namespace_manifest.SCHEMA, "objects": objects},
    }
    review = {
        row["object_id"]: {"questions": {
            kind: {"status": "UNRESOLVED", "reason": "Open."} for kind in kinds
        }}
        for row in objects
    }
    return document, review


def _bound_package(monkeypatch: pytest.MonkeyPatch, object_count: int = 1,
                   *, census_digests: tuple[str, ...] = (SYNTHETIC_DIGEST,),
                   contradiction: bool = False) -> tuple[dict, dict]:
    """Install a synthetic package whose every cell is decided and byte-bound."""
    from verifier.runtime import (
        namespace_manifest,
        package_original_kind_catalog,
        self_polish_estate,
    )

    document, review = _synthetic_package(object_count)
    kinds = package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS
    for row in document["namespace"]["objects"]:
        row["classification"] = {
            kind: {
                "status": "DOES_NOT_APPLY",
                "reason": "Explicit bounded refutation.",
                "evidence": [{"path": "owned.py", "sha256": SYNTHETIC_DIGEST}],
            }
            for kind in kinds
        }
        if contradiction:
            row["classification"][kinds[0]]["status"] = "APPLIES"
    for object_id, reviewed in review.items():
        reviewed["questions"] = {
            kind: {"status": "DOES_NOT_APPLY", "reason": "Explicit bounded refutation."}
            for kind in kinds
        }
    monkeypatch.setattr(
        namespace_manifest, "normalize_manifest", lambda namespace: deepcopy(namespace)
    )
    monkeypatch.setattr(
        package_original_kind_catalog, "review_document", lambda: review
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "validated_review_document",
        lambda _root, _files: review,
    )
    digests = iter(census_digests)
    last = [census_digests[-1]]

    def capture(_root, **_kwargs):
        try:
            last[0] = next(digests)
        except StopIteration:
            pass
        return _census(last[0])

    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census", capture)
    return document, review


CLOSED_PYTHON = "def owned():\n    return 1\n"
OPEN_PYTHON = "def owned(text):\n    return eval(text)\n"


def _write_owned(root: Path, files: dict[str, str]) -> dict[str, str]:
    """Write owned bytes under ``root`` (LF, per .gitattributes) and digest them."""
    from verifier.runtime import core_obligation_union

    digests: dict[str, str] = {}
    for path, body in files.items():
        target = root / path
        target.write_bytes(body.encode("utf-8"))
        digests[path] = core_obligation_union.bytes_digest(target.read_bytes())
    return digests


def _snapshot(digests: dict[str, str]) -> dict:
    """Shape a census like the candidate capture, binding each file's real digest."""
    from verifier.runtime import core_obligation_union

    files = [{"path": path, "sha256": digest} for path, digest in sorted(digests.items())]
    return {"census_digest": core_obligation_union.value_digest(files), "files": files}


def _closed_package(monkeypatch: pytest.MonkeyPatch, root: Path, digests: dict[str, str], *,
                    cited: list[dict[str, str]] | None = None,
                    expected: list[str] | None = None) -> dict:
    """Return one object refuting every original kind over the real owned bytes.

    Replaced: the component review (its 464-object denominator is validated by the
    full suite, not reproducible here) and the git-backed census capture (which
    cannot run on a plain temp root).  Real: the file bytes, their digests, the
    owned-source effect audit, and the decision/digest/closure binding.
    """
    from verifier.runtime import (
        namespace_manifest,
        package_manifest,
        package_original_kind_catalog,
        self_polish_estate,
    )

    kinds = package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS
    evidence = cited if cited is not None else [
        {"path": path, "sha256": digest} for path, digest in sorted(digests.items())
    ]
    owned = list(expected) if expected is not None else sorted(digests)
    row = {
        "object_id": "vstd-000",
        "kind": "SIM",
        "surfaces": ["file:" + path for path in sorted(digests)],
        "classification": {
            kind: {
                "status": "DOES_NOT_APPLY",
                "reason": "Explicit bounded refutation.",
                "evidence": evidence,
            }
            for kind in kinds
        },
    }
    review = {"vstd-000": {
        "expected_owned_paths": owned,
        "questions": {
            kind: {"status": "DOES_NOT_APPLY", "reason": "Explicit bounded refutation."}
            for kind in kinds
        },
    }}
    monkeypatch.setattr(
        namespace_manifest, "normalize_manifest", lambda namespace: deepcopy(namespace)
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "validated_review_document",
        lambda _root, _files: deepcopy(review),
    )
    monkeypatch.setattr(
        self_polish_estate,
        "capture_candidate_source_census",
        lambda _root, **_kwargs: _snapshot(digests),
    )
    return {
        "schema_version": package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {"schema_version": namespace_manifest.SCHEMA, "objects": [row]},
    }


def test_original_kind_retention_uses_answers_only_after_base_admission_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from verifier.runtime import namespace_manifest

    (tmp_path / "reasons.vstd").write_text("synthetic\n", encoding="utf-8")
    objects = [{"object_id": "vstd-one", "classification": {}}]
    document = {"namespace": {"objects": objects}}
    selection = object()
    monkeypatch.setattr(
        namespace_manifest,
        "normalize_manifest",
        lambda namespace: deepcopy(namespace),
    )
    monkeypatch.setattr(
        tier_zero.reason_integration,
        "select_root_reasons",
        lambda root: selection,
    )
    monkeypatch.setattr(
        tier_zero.reason_integration,
        "documented_applicability_answers",
        lambda selected, rows: ({
            "object_id": "vstd-one",
            "object_kind": "MODEL",
            "reason_id": "retain-model",
            "decision": "APPLIES",
        },),
    )

    assert tier_zero._documented_original_kind_retention_keys(
        {"status": "PASS"}, document, tmp_path
    ) == frozenset({("vstd-one", "MODEL")})

    monkeypatch.setattr(
        tier_zero.reason_integration,
        "select_root_reasons",
        lambda _root: pytest.fail("non-PASS admission must not select reasons"),
    )
    assert tier_zero._documented_original_kind_retention_keys(
        {"status": "UNKNOWN"}, document, tmp_path
    ) == frozenset()


def test_bound_package_passes_only_with_a_stable_byte_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    digests = _write_owned(tmp_path, {"owned.py": CLOSED_PYTHON})
    document = _closed_package(monkeypatch, tmp_path, digests)

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, tmp_path
    )

    assert report["status"] == "PASS"
    closure = report["original_kind_closure"]
    assert closure["status"] == "PASS"
    assert closure["unresolved_count"] == 0
    assert closure["source_binding"]["status"] == "BOUND"
    assert (
        closure["source_binding"]["opening_census_digest"]
        == closure["source_binding"]["closing_census_digest"]
    )
    assert report["finalization"]["complete"] is True


def test_source_mutation_between_snapshots_yields_unknown_retry_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document, _review = _bound_package(
        monkeypatch, census_digests=(SYNTHETIC_DIGEST, OTHER_DIGEST)
    )

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    assert report["status"] == "UNKNOWN"
    assert report["finalization"]["complete"] is False
    selected = next(row for row in report["obligations"] if row["coordinate"] == "VSTD-T0.2")
    assert selected["status"] == "UNKNOWN"
    assert "PACKAGE_ORIGINAL_KIND_SOURCE_MUTATED" in selected["blockers"]
    finding = report["findings"][-1]
    assert finding["status"] == "UNKNOWN"
    assert finding["code"] == "PACKAGE_ORIGINAL_KIND_SOURCE_MUTATED"
    summary = selected["evidence"]["original_kind_closure"]
    assert summary["source_binding"]["status"] == "MUTATED"
    assert summary["source_binding"]["opening_census_digest"] != (
        summary["source_binding"]["closing_census_digest"]
    )


def test_stale_cell_digest_reaches_the_exact_tier_zero_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document, _review = _bound_package(monkeypatch)
    first_kind = next(iter(document["namespace"]["objects"][0]["classification"]))
    document["namespace"]["objects"][0]["classification"][first_kind][
        "evidence"
    ][0]["sha256"] = OTHER_DIGEST

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    assert report["status"] == "UNKNOWN"
    finding = report["findings"][-1]
    assert finding["classification_kind"] == first_kind
    assert finding["status"] == "UNKNOWN"
    assert "recorded sha256 differs from the current file bytes" in finding["reason"]
    assert "do not reuse the stale digest" in finding["next_action"]


def test_catalog_contradiction_stays_fail_under_source_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_original_kind_catalog

    document, _review = _bound_package(
        monkeypatch, census_digests=(SYNTHETIC_DIGEST, OTHER_DIGEST),
        contradiction=True,
    )

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    assert report["status"] == "FAIL"
    assert report["findings"][-1]["status"] == "FAIL"
    assert report["findings"][-1]["code"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_CONTRADICTION:vstd-000:"
        + package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS[0]
    )


def test_unavailable_source_census_is_unknown_and_names_the_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import self_polish_estate

    document, _review = _bound_package(monkeypatch)

    def refuse(_root, **_kwargs):
        raise self_polish_estate.EstateError("CANDIDATE_SOURCE_MUTATED")

    monkeypatch.setattr(self_polish_estate, "capture_candidate_source_census", refuse)

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    assert report["status"] == "UNKNOWN"
    assert report["findings"][-1]["code"] == (
        "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_UNAVAILABLE:CANDIDATE_SOURCE_MUTATED"
    )


def test_large_unresolved_set_reports_bounded_summary_and_exact_first_focus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_original_kind_catalog

    document, _review = _synthetic_package(40)
    _stable_census(monkeypatch)
    monkeypatch.setattr(
        package_original_kind_catalog, "review_document",
        lambda: _review,
    )
    monkeypatch.setattr(
        package_original_kind_catalog,
        "validated_review_document",
        lambda _root, _files: _review,
    )
    from verifier.runtime import namespace_manifest

    monkeypatch.setattr(
        namespace_manifest, "normalize_manifest", lambda namespace: deepcopy(namespace)
    )

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    selected = next(row for row in report["obligations"] if row["coordinate"] == "VSTD-T0.2")
    summary = selected["evidence"]["original_kind_closure"]
    first_kind = package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS[0]
    assert report["status"] == "UNKNOWN"
    assert summary["unresolved_count"] == 1000
    assert summary["unresolved_truncated"] is True
    assert summary["unresolved_sample_limit"] == 16
    assert len(summary["unresolved_sample"]) == 16
    assert summary["unresolved_sample"][0]["object_id"] == "vstd-000"
    assert summary["unresolved_digest"].startswith("sha256:")
    assert summary["next_unresolved"] == {"object_id": "vstd-000", "kind": first_kind}
    assert "unresolved" not in summary
    finding = report["findings"][-1]
    assert finding["object_id"] == "vstd-000"
    assert finding["classification_kind"] == first_kind
    assert len(json.dumps(report)) < 30_000


def test_catalog_validation_refusal_is_bounded_unknown_not_an_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest, package_original_kind_catalog

    document, _review = _synthetic_package(1)
    _stable_census(monkeypatch)
    monkeypatch.setattr(
        namespace_manifest, "normalize_manifest", lambda namespace: deepcopy(namespace)
    )

    def refuse(_root, _files):
        raise ValueError("SYNTHETIC_COMPONENT_EVIDENCE_DRIFT")

    monkeypatch.setattr(
        package_original_kind_catalog, "validated_review_document", refuse
    )

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, Path(".")
    )

    assert report["status"] == "UNKNOWN"
    finding = report["findings"][-1]
    assert finding["status"] == "UNKNOWN"
    assert finding["code"] == (
        "PACKAGE_ORIGINAL_KIND_CATALOG_REFUSED:"
        "SYNTHETIC_COMPONENT_EVIDENCE_DRIFT"
    )


# Exact cell reason substring and next-action prefix for each non-PASS refusal.
_UNBOUND_CASES = {
    "partial": (
        "does not cite every file",
        "Cite every owned file",
    ),
    "fake_digest": (
        "recorded sha256 differs from the current file bytes",
        "do not reuse the stale digest",
    ),
    "stale_digest": (
        "recorded sha256 differs from the current file bytes",
        "do not reuse the stale digest",
    ),
    "non_python": (
        "unsupported language",
        "Close the named effect boundary",
    ),
    "unclosed_effects": (
        "dynamic execution",
        "Close the named effect boundary",
    ),
}


@pytest.mark.parametrize("case", ["closed", *_UNBOUND_CASES])
def test_only_closed_current_python_source_passes_every_other_case_is_exact_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case: str,
) -> None:
    from verifier.runtime import package_original_kind_catalog as catalog

    kinds = catalog.ORIGINAL_NON_OBJECT_KINDS
    first = kinds[0]
    detail = None
    if case == "closed":
        digests = _write_owned(tmp_path, {"owned.py": CLOSED_PYTHON})
        document = _closed_package(monkeypatch, tmp_path, digests)
    elif case == "partial":
        digests = _write_owned(tmp_path, {
            "owned.py": CLOSED_PYTHON, "other.py": CLOSED_PYTHON,
        })
        document = _closed_package(
            monkeypatch, tmp_path, digests,
            cited=[{"path": "owned.py", "sha256": digests["owned.py"]}],
        )
        detail = "DOES_NOT_APPLY_DENOMINATOR_INCOMPLETE"
    elif case == "fake_digest":
        digests = _write_owned(tmp_path, {"owned.py": CLOSED_PYTHON})
        document = _closed_package(
            monkeypatch, tmp_path, digests,
            cited=[{"path": "owned.py", "sha256": "sha256:" + "a" * 64}],
        )
    elif case == "stale_digest":
        stale = _write_owned(tmp_path, {"owned.py": CLOSED_PYTHON})
        digests = _write_owned(tmp_path, {"owned.py": CLOSED_PYTHON + "# revised\n"})
        document = _closed_package(
            monkeypatch, tmp_path, digests,
            cited=[{"path": "owned.py", "sha256": stale["owned.py"]}],
        )
    elif case == "non_python":
        digests = _write_owned(tmp_path, {"owned.txt": "plain notes\n"})
        document = _closed_package(monkeypatch, tmp_path, digests)
        detail = "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED"
    else:
        digests = _write_owned(tmp_path, {"owned.py": OPEN_PYTHON})
        document = _closed_package(monkeypatch, tmp_path, digests)
        detail = "DOES_NOT_APPLY_EFFECT_BOUNDARY_UNCLOSED"

    report = tier_zero._bind_package_original_kind_closure(
        _passing_package_admission_report(), document, tmp_path
    )

    closure = report["original_kind_closure"]
    if case == "closed":
        assert report["status"] == "PASS"
        assert closure["blocker_counts"] == {}
        assert report["findings"] == []
        return
    reason_text, action_text = _UNBOUND_CASES[case]
    assert report["status"] == "UNKNOWN"
    assert report["finalization"]["complete"] is False
    assert report["finalization"]["unclosed_coordinates"] == ["VSTD-T0.2"]
    assert closure["status"] == "UNKNOWN"
    assert closure["blocker_counts"] == (
        {detail: len(kinds)} if detail is not None else {}
    )
    head = closure["unresolved_sample"][0]
    assert (head["object_id"], head["kind"]) == ("vstd-000", first)
    assert ("denominator_blocker" in head) == (detail is not None)
    finding = report["findings"][-1]
    assert finding["status"] == "UNKNOWN"
    assert finding["code"] == "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:vstd-000:" + first
    assert reason_text in finding["reason"]
    assert action_text in finding["next_action"]
    if detail is not None:
        assert head["denominator_blocker"] == detail
        assert head["next_action"] == catalog._DOES_NOT_APPLY_BLOCKER_ACTIONS[detail]

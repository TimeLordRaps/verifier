"""Package graph composition verdicts keep their exact tri-state meaning.

The typed composition assessment is evidence about the selected package graph.
PASS continues to the next package stage. FAIL remains a refutation and UNKNOWN
remains an unestablished result; neither may be cast into the other, and each
non-PASS keeps its own assessment reason in the package findings. A PASS whose
digest or object count does not bind the selected collection is not the graph
verdict. Capacity replay of the same source obeys the same rule.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from verifier.core import namespace
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import package_polish as package
from verifier.runtime import package_polish_schema_validation
from test_package_polish_capacity_invariants import _valid_report_through_tier


ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "PACKAGE_TEST_CONTINUED_PAST_COMPOSITION"
COMPOSITION_CODES = {
    "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
    "PACKAGE_GRAPH_COMPOSITION_FAILED",
}
DIGEST_F = "sha256:" + "f" * 64
EMPTY_REASON_MARKER = "retained no reason text"


@pytest.fixture
def composition_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Select the real root manifest on a hermetic, git-free source coordinate.

    Only source identity and the post-replay recapture are isolated. The real
    manifest selector and the real composition assessment run unless a test
    installs a typed verdict of its own.
    """

    manifest = package.package_manifest.retained_contract(
        json.loads((ROOT / "objects.vstd").read_bytes())
    )
    (tmp_path / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
    provider = tmp_path / "src/verifier/runtime/tier_zero_reasons.py"
    provider.parent.mkdir(parents=True)
    provider.write_bytes(
        (ROOT / "src/verifier/runtime/tier_zero_reasons.py").read_bytes()
    )
    reasons = package.tier_zero_reasons.installed_reason_ledger(ROOT)
    coordinate = {
        "source_head": manifest["repository"]["revision"],
        "source_tree": "2" * 40,
        "source_manifest_digest": "sha256:" + "a" * 64,
        "source_worktree_status_digest": "sha256:" + "b" * 64,
    }
    monkeypatch.setattr(package.self_polish_estate, "_git_coordinate", lambda root: {
        "repository": manifest["repository"]["remote"],
        "revision": manifest["repository"]["revision"],
    })
    monkeypatch.setattr(package.self_polish_statics, "_capture_coordinate", lambda root: coordinate)
    monkeypatch.setattr(package.self_polish_tiers, "_post_replay_source_recapture", lambda *args: {"status": "PASS"})
    monkeypatch.setattr(package.tier_zero_reasons, "installed_reason_ledger", lambda root: deepcopy(reasons))

    def stop_after_composition(*_args, **_kwargs):
        raise package.PackagePolishUnknown(SENTINEL)

    monkeypatch.setattr(package, "_verifier_selection", stop_after_composition)
    return tmp_path


def _install_composition(
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
    reason: str,
    *,
    collection_digest: str | None = None,
    objects_checked: int | None = None,
) -> None:
    """Replace only the typed verdict; the digest and count default to a true binding."""

    def assess(objects, *, expected_digest, **_bounds):
        return namespace.CompositionAssessment(
            namespace.Verdict(verdict),
            expected_digest if collection_digest is None else collection_digest,
            reason,
            len(objects) if objects_checked is None else objects_checked,
        )

    monkeypatch.setattr(namespace, "assess_composition", assess)


def _composition_findings(rows: list[dict]) -> list[dict]:
    return [row for row in rows if row.get("code") in COMPOSITION_CODES]


@pytest.mark.parametrize(
    ("verdict", "status", "code"),
    [
        ("FAIL", "FAIL", "PACKAGE_GRAPH_COMPOSITION_FAILED"),
        ("UNKNOWN", "UNKNOWN", "PACKAGE_GRAPH_COMPOSITION_NOT_PASS"),
    ],
)
def test_non_pass_composition_keeps_its_verdict_reason_and_coordinate(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
    status: str,
    code: str,
) -> None:
    reason = f"R-{verdict}: exact typed composition reason"
    _install_composition(monkeypatch, verdict, reason)

    report = package.assess_package_polish(1, composition_root)

    assert report["status"] == status
    assert SENTINEL not in report["blockers"]
    assert "PACKAGE_GRAPH_COMPOSITION_NOT_PASS" in report["blockers"]
    assert ("PACKAGE_GRAPH_COMPOSITION_FAILED" in report["blockers"]) == (verdict == "FAIL")
    findings = _composition_findings(report["findings"])
    assert [row["code"] for row in findings] == [code]
    assert findings[0]["status"] == verdict
    assert findings[0]["reason"] == reason
    assert findings[0]["explanation"] == reason
    assert findings[0]["rerun_argv"] == ["vstd", "polish", "1", "--json"]


@pytest.mark.parametrize("verdict", ["FAIL", "UNKNOWN"])
def test_empty_non_pass_reason_is_replaced_by_explicit_unretained_text(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
) -> None:
    _install_composition(monkeypatch, verdict, "")

    report = package.assess_package_polish(1, composition_root)

    findings = _composition_findings(report["findings"])
    assert len(findings) == 1
    assert findings[0]["status"] == verdict
    # The explicit marker proves the bounded fallback was used, not generic text.
    assert EMPTY_REASON_MARKER in findings[0]["explanation"]
    assert findings[0]["reason"] == findings[0]["explanation"]


@pytest.mark.parametrize("verdict", ["FAIL", "UNKNOWN"])
def test_non_pass_composition_report_is_schema_valid(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
) -> None:
    """The publication gate must accept the bounded non-PASS result it carries."""

    _install_composition(monkeypatch, verdict, f"R-{verdict}: schema-bound reason")

    report = package.assess_package_polish(1, composition_root)

    validation = package_polish_schema_validation.validate_package_polish_report(report)
    assert validation.valid, validation.errors


def test_real_pass_composition_continues_to_the_next_stage(
    composition_root: Path,
) -> None:
    report = package.assess_package_polish(1, composition_root)

    assert SENTINEL in report["blockers"]
    assert not set(report["blockers"]) & COMPOSITION_CODES
    assert _composition_findings(report.get("findings", [])) == []


def test_count_preserving_unbound_pass_does_not_continue(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PASS for another digest with the same object count is not this graph's PASS."""

    _install_composition(
        monkeypatch, "PASS", "replacement reason", collection_digest=DIGEST_F,
    )

    report = package.assess_package_polish(1, composition_root)

    assert SENTINEL not in report["blockers"]
    assert report["status"] == "UNKNOWN"
    assert "PACKAGE_GRAPH_COMPOSITION_NOT_PASS" in report["blockers"]
    assert "PACKAGE_GRAPH_COMPOSITION_FAILED" not in report["blockers"]
    findings = _composition_findings(report["findings"])
    assert [row["status"] for row in findings] == ["UNKNOWN"]
    assert findings[0]["explanation"] != "replacement reason"


@pytest.mark.parametrize(
    ("movement", "status"),
    [("UNKNOWN", "UNKNOWN"), ("FAIL", "FAIL")],
)
def test_post_composition_source_movement_keeps_the_unknown_reason(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    movement: str,
    status: str,
) -> None:
    reason = "R-UNKNOWN: composition bound exhausted before source movement"
    _install_composition(monkeypatch, "UNKNOWN", reason)
    monkeypatch.setattr(
        package.self_polish_tiers,
        "_post_replay_source_recapture",
        lambda *args: {"status": movement},
    )

    report = package.assess_package_polish(1, composition_root)

    assert report["status"] == status
    assert "PACKAGE_SOURCE_RECAPTURE_NOT_PASS" in report["blockers"]
    findings = _composition_findings(report["findings"])
    assert [row["status"] for row in findings] == ["UNKNOWN"]
    assert findings[0]["explanation"] == reason


@pytest.mark.parametrize(("verdict", "receipt_status"), [("UNKNOWN", "UNKNOWN"), ("FAIL", "FAIL")])
def test_capacity_source_replay_refusal_keeps_reason_and_never_completes(
    composition_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
    receipt_status: str,
) -> None:
    """The source-capacity replay (package_polish ~L487) must not discard its verdict."""

    reason = f"R-{verdict}: replayed source composition"
    _install_composition(monkeypatch, verdict, reason)

    receipt = package._capacity_receipt(
        _valid_report_through_tier(1), source_root=composition_root,
    )

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["status"] == receipt_status
    findings = _composition_findings(receipt["findings"])
    assert [row["status"] for row in findings] == [verdict]
    assert findings[0]["explanation"] == reason
    schema = json.loads((
        ROOT / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(receipt)

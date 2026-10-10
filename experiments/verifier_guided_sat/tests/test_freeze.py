from __future__ import annotations

from pathlib import Path

from verifier_guided_sat.canonical import read_json
from verifier_guided_sat.freeze import validate_freeze
from verifier_guided_sat.result_validator import validate_result


ROOT = Path(__file__).resolve().parents[1]


def test_pre_held_out_freeze_is_intact() -> None:
    assert validate_freeze(ROOT) == []


def test_committed_blocked_result_validates_against_current_freeze() -> None:
    """The committed envelope must pass the validator that gates it, not only a synthetic fixture."""

    assert validate_result(ROOT, read_json(ROOT / "results" / "live-blocked.json")) == []


def test_public_result_cites_current_freeze_digest() -> None:
    digest = read_json(ROOT / "freeze-manifest.json")["freeze_digest"]
    text = (ROOT / "PUBLIC_RESULT.md").read_text(encoding="utf-8")
    assert digest in text
    assert digest.removeprefix("sha256:") in text


def test_freeze_lineage_accounts_for_every_frozen_file_and_digest() -> None:
    lineage = read_json(ROOT / "freeze-lineage.json")
    freeze = read_json(ROOT / "freeze-manifest.json")
    current = lineage["current"]
    assert current["freeze_digest"] == freeze["freeze_digest"]
    assert current["freeze_date_utc"] == freeze["freeze_date_utc"]
    assert current["held_out_live_evaluation_started"] is freeze["held_out_live_evaluation_started"]
    assert current["freeze_digest"] not in {entry["freeze_digest"] for entry in lineage["previous"]}
    changed = lineage["changed_frozen_files"]
    unchanged = lineage["unchanged_frozen_files"]
    assert not set(changed) & set(unchanged)
    assert set(changed) | set(unchanged) == set(freeze["files"])
    for relative, change in changed.items():
        assert change["previous"] != change["current"]
        assert freeze["files"][relative] == change["current"]
    for relative, digest in unchanged.items():
        assert freeze["files"][relative] == digest

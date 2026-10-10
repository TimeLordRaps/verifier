"""Public command discoverability for numeric self-polish tiers."""

from __future__ import annotations

import pytest

from verifier.runtime.public_cli import main


def test_polish_help_advertises_numeric_self_polish_tiers(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "--help"])

    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    normalized_help = " ".join(help_text.split())
    assert "1" in help_text
    assert "2" in help_text
    assert (
        "complete Tier 1 mechanics across the repository/package estate"
        in normalized_help
    )
    assert (
        "Tier 2 dynamics after a mechanically replayed Tier 1 PASS"
        in normalized_help
    )


def test_numeric_tier1_help_explains_estate_authority_and_evidence_inputs(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "1", "--help"])

    assert stopped.value.code == 0
    normalized_help = " ".join(capsys.readouterr().out.split()).lower()
    assert "--candidate-estate-authority-policy" in normalized_help
    assert "independently selected estate-authority policy" in normalized_help
    assert "--candidate-estate-evidence-manifest" in normalized_help
    assert "exact per-candidate semantic-evidence manifest" in normalized_help
    assert "--candidate-estate-evidence-selection" in normalized_help
    assert "repeatable configured-key replay selection" in normalized_help


def test_numeric_tier2_help_states_full_tier1_report_transport_bound(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "2", "--help"])

    assert stopped.value.code == 0
    normalized_help = " ".join(capsys.readouterr().out.split()).lower()
    assert "--tier1-report" in normalized_help
    assert "at most 16 mib including any final newline" in normalized_help

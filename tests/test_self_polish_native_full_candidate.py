"""All-route candidate replay without extension installation or promotion."""
from __future__ import annotations

from pathlib import Path

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_full_candidate as candidate


def test_full_candidate_preserves_the_single_installed_unknown() -> None:
    root = Path(__file__).parents[1]
    source_coordinate_digest = "sha256:" + "8" * 64

    report = candidate.replay_full_native_candidate(
        root,
        source_coordinate_digest=source_coordinate_digest,
    )

    assert report["status"] == "UNKNOWN"
    assert report["source_coordinate_digest"] == source_coordinate_digest
    assert report["tiers"] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert report["tier_membership_counts"] == {
        "1": 45, "2": 37, "3": 31, "4": 32, "5": 26,
        "6": 26, "7": 156, "8": 26, "9": 29,
    }
    assert report["membership_count"] == 408
    assert report["case_count"] == 1224
    assert report["route_status_counts"] == {"PASS": 407, "UNKNOWN": 1}
    assert report["case_status_counts"] == {"PASS": 1223, "UNKNOWN": 1}
    assert report["native_status_counts"] == {
        "FAIL": 408, "PASS": 407, "UNKNOWN": 409,
    }
    unresolved = [
        row for row in report["routes"] if row["status"] == "UNKNOWN"
    ]
    assert [row["obligation_id"] for row in unresolved] \
        == ["SIM:SIM-2.4"]
    assert report["installed_membership_count"] == 82
    assert report["prepared_membership_count"] == 326
    assert report["extension_installation_status"] \
        == "PREPARED_NOT_INSTALLED"
    assert report["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["release_authority"] == "NONE"
    body = {
        key: value for key, value in report.items()
        if key != "candidate_digest"
    }
    assert report["candidate_digest"] \
        == core_obligation_union.value_digest(body)


@pytest.mark.parametrize("prior_status", ["PASS", "FAIL"])
def test_later_outage_preserves_prior_installed_failure(
        monkeypatch: pytest.MonkeyPatch, prior_status: str) -> None:
    def installed(_root, tier, _source_digest):
        if tier == 2:
            raise OSError("synthetic unavailable source")
        return {"status": prior_status}, []

    monkeypatch.setattr(candidate, "_installed_tier", installed)
    with pytest.raises(candidate.self_polish_native_replay.NativeReplayResourceError) as error:
        candidate.replay_full_native_candidate(
            Path(__file__).parents[1], source_coordinate_digest="sha256:" + "8" * 64
        )
    assert error.value.failure_observed is (prior_status == "FAIL")

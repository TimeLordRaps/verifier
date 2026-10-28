"""Behavioral replay for prepared, explicitly uninstalled native cases."""
from __future__ import annotations

from pathlib import Path

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_extension_replay as replay


def test_all_prepared_extension_triads_replay_against_current_source() -> None:
    root = Path(__file__).parents[1]
    source_coordinate_digest = "sha256:" + "7" * 64

    receipt = replay.replay_prepared_extensions(
        root,
        source_coordinate_digest=source_coordinate_digest,
    )

    assert receipt["status"] == "PASS"
    assert receipt["preparation_status"] == "PREPARED_NOT_INSTALLED"
    assert receipt["source_coordinate_digest"] == source_coordinate_digest
    assert receipt["tiers"] == [3, 4, 5, 6, 7, 8, 9]
    assert receipt["tier_membership_counts"] == {
        "3": 31, "4": 32, "5": 26, "6": 26, "7": 156,
        "8": 26, "9": 29,
    }
    assert receipt["membership_count"] == 326
    assert receipt["case_count"] == 978
    assert receipt["completed_membership_count"] == 326
    assert receipt["completed_case_count"] == 978
    assert receipt["case_status_counts"] == {"PASS": 978}
    assert len(receipt["memberships"]) == 326
    assert all(row["status"] == "PASS" for row in receipt["memberships"])
    assert all(
        [case["native_status"] for case in row["cases"]]
            == ["PASS", "FAIL", "UNKNOWN"]
        for row in receipt["memberships"]
    )
    assert receipt["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert receipt["release_authority"] == "NONE"
    body = {
        key: value for key, value in receipt.items()
        if key != "replay_digest"
    }
    assert receipt["replay_digest"] \
        == core_obligation_union.value_digest(body)


def test_prepared_checker_binds_byte_identical_selected_source(
        tmp_path: Path) -> None:
    registry = replay.self_polish_native_extensions.prepared_extension_registry()
    row = next(
        item for rows in registry["memberships_by_tier"].values()
        for item in rows
    )
    mechanism = row["checking_mechanism"]
    module_name = mechanism.rsplit(".", 1)[0]
    relative = Path(*module_name.split(".")).with_suffix(".py")
    loaded = Path(replay.__file__).resolve().parents[2] / relative
    selected = tmp_path / "src" / relative
    selected.parent.mkdir(parents=True)
    selected.write_bytes(loaded.read_bytes())

    function, source_path, source_digest = replay._resolve_mechanism(
        tmp_path, mechanism
    )

    assert callable(function)
    assert source_path == (Path("src") / relative).as_posix()
    assert source_digest == core_obligation_union.bytes_digest(
        selected.read_bytes()
    )


@pytest.mark.parametrize(
    "mutation", ("changed-source", "missing-source", "out-of-package")
)
def test_prepared_checker_refuses_source_substitution(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    registry = replay.self_polish_native_extensions.prepared_extension_registry()
    row = next(
        item for rows in registry["memberships_by_tier"].values()
        for item in rows
    )
    mechanism = row["checking_mechanism"]
    module_name = mechanism.rsplit(".", 1)[0]
    relative = Path(*module_name.split(".")).with_suffix(".py")
    loaded = Path(replay.__file__).resolve().parents[2] / relative
    selected = tmp_path / "src" / relative
    selected.parent.mkdir(parents=True)
    selected.write_bytes(loaded.read_bytes())
    if mutation == "changed-source":
        selected.write_bytes(selected.read_bytes() + b"\n# changed selection\n")
    elif mutation == "missing-source":
        selected.unlink()
    else:
        outside = tmp_path / "outside.py"
        outside.write_bytes(loaded.read_bytes())
        monkeypatch.setattr(
            replay.inspect, "getsourcefile", lambda _function: str(outside)
        )

    with pytest.raises(
        replay.PreparedNativeReplayError,
        match="PREPARED_NATIVE_MECHANISM_SOURCE_DIFFERS",
    ):
        replay._resolve_mechanism(tmp_path, mechanism)

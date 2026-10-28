"""Installed native mechanism source-byte binding regression."""
from __future__ import annotations

from pathlib import Path

import pytest

from verifier.domains.contracts import sim_dynamics
from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_replay as replay


MECHANISM = "verifier.domains.contracts.sim_dynamics.recheck_sim_dynamics_certificate"
RELATIVE = "src/verifier/domains/contracts/sim_dynamics.py"


def test_byte_identical_installed_checker_binds_to_selected_source(tmp_path: Path) -> None:
    selected = tmp_path / RELATIVE
    selected.parent.mkdir(parents=True)
    raw = Path(sim_dynamics.__file__).read_bytes()
    selected.write_bytes(raw)
    function, source_path, source_digest = replay._resolve_mechanism(tmp_path, MECHANISM)
    assert function is sim_dynamics.recheck_sim_dynamics_certificate
    assert source_path == RELATIVE
    assert source_digest == core_obligation_union.bytes_digest(raw)


def test_loaded_distribution_checker_retains_repository_coordinate() -> None:
    loaded_root = Path(replay.__file__).resolve().parents[2]
    raw = Path(sim_dynamics.__file__).read_bytes()

    function, source_path, source_digest = replay._resolve_mechanism(
        loaded_root, MECHANISM, source_layout="loaded-distribution"
    )

    assert function is sim_dynamics.recheck_sim_dynamics_certificate
    assert source_path == RELATIVE
    assert source_digest == core_obligation_union.bytes_digest(raw)


def test_loaded_distribution_mode_refuses_another_root(tmp_path: Path) -> None:
    with pytest.raises(
        replay.NativeReplayError,
        match="NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS",
    ):
        replay._resolve_mechanism(
            tmp_path, MECHANISM, source_layout="loaded-distribution"
        )


@pytest.mark.parametrize("mutation", ["changed-source", "missing-source", "out-of-package"])
def test_installed_checker_cannot_substitute_source(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    selected = tmp_path / RELATIVE
    selected.parent.mkdir(parents=True)
    raw = Path(sim_dynamics.__file__).read_bytes()
    if mutation != "missing-source":
        selected.write_bytes(raw + b"\n# different bytes\n" if mutation == "changed-source" else raw)
    if mutation == "out-of-package":
        other = tmp_path / "unselected.py"
        other.write_bytes(raw)
        monkeypatch.setattr(replay.inspect, "getsourcefile", lambda _function: str(other))
    with pytest.raises(replay.NativeReplayError, match="NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS"):
        replay._resolve_mechanism(tmp_path, MECHANISM)

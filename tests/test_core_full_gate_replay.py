"""Focused controls for exact six-gate selection and native replay composition."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import core_application_release as app


def gate_fixture() -> tuple[dict, dict[str, dict]]:
    instances = {}
    gates = []
    for index, gate in enumerate(app.FULL_GATES):
        instance_id = f"gate:{index}"
        coordinate = app.full_gate_coordinate(gate)
        row = {
            "instance_id": instance_id,
            **coordinate,
        }
        instances[instance_id] = row
        gates.append({
            "gate": gate,
            "semantic_version": row["semantic_version"],
            "objective": row["objective"],
            "proposition_digest": coordinate["proposition_digest"],
            "required_instances": [instance_id],
        })
    selection = {
        "schema_version": app.FULL_GATE_SELECTION,
        "profile_id": app.PROFILE,
        "application_selection_digest": "sha256:" + "a" * 64,
        "requirements_digest": "sha256:" + "b" * 64,
        "application_mechanism_digest": app.mechanism_digest(),
        "gates": gates,
    }
    return selection, instances


def select(selection: dict, instances: dict[str, dict]):
    raw = canonical_bytes(selection)
    return app._select_full_gates(
        raw,
        expected_digest=app.digest(raw),
        application_selection_digest="sha256:" + "a" * 64,
        requirements_digest="sha256:" + "b" * 64,
        instances=instances,
    )


def test_exact_six_gate_selection_has_a_replayed_positive_path():
    selection, instances = gate_fixture()
    plan = select(selection, instances)
    outcomes = {name: "PASS" for row in plan.values() for name in row}

    replay = app._full_gate_outcomes(
        plan,
        outcomes,
        census_established=True,
        cancelled=False,
        externally_pinned=True,
    )

    assert replay == {gate: "PASS" for gate in app.FULL_GATES}


@pytest.mark.parametrize("change", ["carried-status", "duplicate-instance", "changed-coordinate",
                                     "foreign-passing-coordinate", "changed-requirements"])
def test_gate_selection_refutes_carried_or_misbound_evidence(change: str):
    selection, instances = gate_fixture()
    if change == "carried-status":
        selection["gates"][0]["status"] = "PASS"
    elif change == "duplicate-instance":
        selection["gates"][1]["required_instances"] = selection["gates"][0]["required_instances"]
    elif change == "changed-coordinate":
        selection["gates"][0]["objective"] = "SUBSTITUTED"
    elif change == "foreign-passing-coordinate":
        selection["gates"][0]["objective"] = "UNRELATED-PASS"
        instances["gate:0"]["objective"] = "UNRELATED-PASS"
    else:
        selection["requirements_digest"] = "sha256:" + "c" * 64

    with pytest.raises(app._Refuted):
        select(selection, instances)


def test_missing_or_cancelled_replay_stays_unknown_but_observed_fail_survives():
    selection, instances = gate_fixture()
    plan = select(selection, instances)
    acceptance_id = plan["ACCEPTANCE"][0]

    missing = app._full_gate_outcomes(
        plan,
        {},
        census_established=False,
        cancelled=False,
        externally_pinned=True,
    )
    assert all(value == "UNKNOWN" for value in missing.values())

    cancelled = app._full_gate_outcomes(
        plan,
        {acceptance_id: "FAIL"},
        census_established=True,
        cancelled=True,
        externally_pinned=True,
    )
    assert cancelled["ACCEPTANCE"] == "FAIL"
    assert all(cancelled[gate] == "UNKNOWN" for gate in app.FULL_GATES if gate != "ACCEPTANCE")


def test_unpinned_producer_selection_never_receives_gate_credit():
    selection, instances = gate_fixture()
    plan = select(selection, instances)
    outcomes = {name: "PASS" for row in plan.values() for name in row}
    replay = app._full_gate_outcomes(
        plan,
        outcomes,
        census_established=True,
        cancelled=False,
        externally_pinned=False,
    )
    assert all(value == "UNKNOWN" for value in replay.values())


def test_each_gate_requires_every_distinct_selected_instance():
    selection, instances = gate_fixture()
    extra = deepcopy(instances["gate:2"])
    extra["instance_id"] = "gate:2:extra"
    instances[extra["instance_id"]] = extra
    selection["gates"][2]["required_instances"].append(extra["instance_id"])
    plan = select(selection, instances)

    outcomes = {name: "PASS" for row in plan.values() for name in row}
    outcomes[extra["instance_id"]] = "UNKNOWN"
    replay = app._full_gate_outcomes(
        plan,
        outcomes,
        census_established=True,
        cancelled=False,
        externally_pinned=True,
    )

    assert replay["NATIVE_PRDEL"] == "UNKNOWN"
    assert all(replay[gate] == "PASS" for gate in app.FULL_GATES if gate != "NATIVE_PRDEL")


def test_gate_selection_refutes_omitted_required_exact_coordinate_instance():
    selection, instances = gate_fixture()
    omitted = deepcopy(instances["gate:5"])
    omitted["instance_id"] = "gate:5:omitted-required"
    instances[omitted["instance_id"]] = omitted

    with pytest.raises(app._Refuted, match="APPLICATION_FULL_GATE_INSTANCE_SET_DIFFERS"):
        select(selection, instances)


def test_full_gate_specification_bytes_bind_the_installed_mechanism(monkeypatch: pytest.MonkeyPatch):
    before = app.mechanism_digest()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\nsubstitution" if path.name == "CORE_FULL_GATE_REPLAY.md" else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert app.mechanism_digest() != before

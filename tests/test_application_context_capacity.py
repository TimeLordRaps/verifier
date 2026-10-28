"""Capacity and cancellation cannot establish a semantic contradiction.

An independently observed failed context remains failed when a later row is
unavailable. No carried positive result survives fresh source unavailability.
"""
from asyncio import CancelledError
from copy import deepcopy
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import application_requirements as app
from verifier.domains.contracts import selected_native_contexts as context
from test_application_requirements import fixture as app_fixture, run_case, recheck_case
from test_selected_native_contexts import fixture as context_fixture, assess, recheck


CAPACITY = (RecursionError, OverflowError, CancelledError)


def unavailable(error):
    def refuse(*args, **kwargs):
        raise error("private capacity detail")
    return refuse


@pytest.mark.parametrize("error", CAPACITY)
def test_compiler_source_capacity_and_cancellation_are_unknown(error, monkeypatch):
    args = app_fixture()
    monkeypatch.setattr(app, "source_bindings", unavailable(error))
    result = run_case(*args)
    assert result["status"] == "UNKNOWN" and result["replayable"] is False
    assert result["full_application_status"] == "UNKNOWN" and result["polished"] is False
    assert "private capacity detail" not in canonical_bytes(result).decode()


@pytest.mark.parametrize("error", CAPACITY)
def test_compiler_replay_decoder_capacity_is_unavailable(error, monkeypatch):
    args = app_fixture()
    retained = run_case(*args)
    assert retained["status"] == "PASS"
    monkeypatch.setattr(app.dag, "_parse", unavailable(error))
    replay = recheck_case(retained, args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("error", CAPACITY)
def test_context_source_capacity_and_cancellation_are_unknown(error, monkeypatch):
    args = context_fixture()
    monkeypatch.setattr(context, "source_bindings", unavailable(error))
    result = assess(*args)
    assert result["status"] == "UNKNOWN" and result["replayable"] is False
    assert "private capacity detail" not in canonical_bytes(result).decode()


@pytest.mark.parametrize("error", CAPACITY)
def test_context_row_capacity_and_cancellation_are_unknown(error, monkeypatch):
    args = context_fixture()
    monkeypatch.setattr(context, "_context", unavailable(error))
    result = assess(*args)
    assert result["status"] == "UNKNOWN" and result["rows"][0]["status"] == "UNKNOWN"


@pytest.mark.parametrize("error", CAPACITY)
def test_known_context_failure_survives_later_row_capacity(error, monkeypatch):
    bundle, dependency, policy = context_fixture()
    bundle["nodes"].append(deepcopy(bundle["nodes"][0]))
    bundle["nodes"][1]["node_id"] = "second"
    bundle["nodes"][1]["claim_id"] = "second-claim"
    dependency["nodes"] = deepcopy(bundle["nodes"])
    policy["contexts"][0]["member_ids"] = ["root"]
    policy["contexts"].append(deepcopy(policy["contexts"][0]))
    policy["contexts"][1]["node_id"] = "second"
    policy["contexts"][1]["member_ids"] = ["h", "root"]
    original = context._context
    def selected(row, *args):
        if row["node_id"] == "second":
            raise error("private capacity detail")
        return original(row, *args)
    monkeypatch.setattr(context, "_context", selected)
    result = assess(bundle, dependency, policy)
    assert result["status"] == "FAIL"
    assert [row["status"] for row in result["rows"]] == ["FAIL", "UNKNOWN"]


@pytest.mark.parametrize("error", CAPACITY)
def test_context_replay_decoder_capacity_is_unavailable(error, monkeypatch):
    args = context_fixture()
    retained = assess(*args)
    assert retained["status"] == "PASS"
    monkeypatch.setattr(context.dag, "_parse", unavailable(error))
    replay = recheck(retained, *args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"


ROW_UNAVAILABLE = CAPACITY + (OSError, ImportError)


@pytest.mark.parametrize("error", ROW_UNAVAILABLE)
def test_old_pass_context_replay_becomes_unavailable_with_fresh_row_outage(error, monkeypatch):
    args = context_fixture()
    retained = assess(*args)
    assert retained["status"] == "PASS"
    monkeypatch.setattr(context, "_context", unavailable(error))
    replay = recheck(retained, *args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["input_digests"] == retained["input_digests"]


@pytest.mark.parametrize("error", ROW_UNAVAILABLE)
def test_current_row_outage_diagnostic_replay_is_unavailable(error, monkeypatch):
    args = context_fixture()
    monkeypatch.setattr(context, "_context", unavailable(error))
    diagnostic = assess(*args)
    assert diagnostic["status"] == "UNKNOWN" and diagnostic["replayable"] is False
    replay = recheck(diagnostic, *args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["input_digests"] == diagnostic["input_digests"]

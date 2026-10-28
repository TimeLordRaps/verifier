"""Prevent package execution evidence from moving between graph subjects.

These tests construct internally consistent parent observations.  Each forged
observation is re-sealed and retains matching request/response bytes, so the
expected rejection cannot be credited to malformed transport evidence.  The
only contradiction is the named subject or collection coordinate.
"""
from __future__ import annotations

from copy import deepcopy
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.runtime import (
    local_ledger_execution as ledger,
    package_execution,
    package_execution_observation as observation,
)
from verifier.runtime.tier_zero_profile import canonical_bytes


def _selection(item: NamespaceObject) -> dict[str, Any]:
    return {
        "object_id": item.object_id,
        "mechanism": ledger.ADAPTER,
        "reason": "Bound test selection for one exact package subject.",
        "evidence": [
            {"path": ledger.IMPLEMENTATION, "sha256": "sha256:" + "a" * 64}
        ],
    }


def _request(item: NamespaceObject, collection_digest: str) -> dict[str, Any]:
    return {
        "schema_version": ledger.REQUEST_SCHEMA,
        "nonce": "1" * 64,
        "object_id": item.object_id,
        "object_digest": item.digest,
        "collection_digest": collection_digest,
    }


def _accepted_exchange(
    request: dict[str, Any], selection: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Make a coherent accepted exchange without claiming a subprocess ran."""
    report = {
        "schema_version": ledger.OBSERVATION_SCHEMA,
        "request": deepcopy(request),
        "source_pins": {},
        "observations": {"sentinel": "subject-binding-only"},
    }
    parameters = {
        "env": {"TEMP": "", "TMP": "", "TMPDIR": ""},
        "input": canonical_bytes(request),
        "capture_output": True,
        "timeout": 30,
        "check": False,
    }
    record = observation.begin(
        request,
        selection,
        {},
        [sys.executable, "-I", "-S", "-B", ledger.WORKER],
        parameters,
    )
    record.update(
        outcome="ACCEPTED",
        returncode=0,
        streams_complete=True,
        stdout=observation.stream(
            canonical_bytes(report) + b"\n", observation.OUTPUT_LIMIT
        ),
        stderr=observation.stream(b"", observation.STDERR_LIMIT),
    )
    return observation.seal(record), report


@pytest.fixture
def subjects() -> tuple[NamespaceObject, NamespaceObject, str]:
    first = NamespaceObject.create("subject-a", "OBJECT", {"variant": "a"}, {})
    second = NamespaceObject.create("subject-b", "OBJECT", {"variant": "b"}, {})
    collection = composition_digest((first, second))
    assert first.kind is second.kind
    assert first.object_id != second.object_id
    assert first.digest != second.digest
    return first, second, collection


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("object_id", lambda first, second, collection: second.object_id),
        ("object_digest", lambda first, second, collection: second.digest),
        (
            "collection_digest",
            lambda first, second, collection: composition_digest((first,)),
        ),
    ),
)
def test_resealed_exchange_refuses_each_independent_subject_binding_mismatch(
    subjects: tuple[NamespaceObject, NamespaceObject, str],
    field: str,
    replacement: Any,
) -> None:
    first, second, collection = subjects
    selection = _selection(first)
    expected_request = _request(first, collection)
    baseline_trace, baseline_report = _accepted_exchange(expected_request, selection)

    # The control proves the fixture is acceptable before any one coordinate
    # changes.  A green rejection therefore cannot be a wrong-reason pass.
    observation.verify_accepted(
        baseline_trace,
        baseline_report,
        selection=selection,
        item=first,
        collection_digest=collection,
        module=ledger,
    )

    forged_request = deepcopy(expected_request)
    forged_request[field] = replacement(first, second, collection)
    differences = {
        key
        for key in expected_request
        if forged_request[key] != expected_request[key]
    }
    assert differences == {field}
    assert forged_request[field] != expected_request[field]
    forged_trace, forged_report = _accepted_exchange(forged_request, selection)

    # The forged record remains digest-valid and its retained input and output
    # agree with one another.  It must fail specifically because it is not the
    # expected object/graph subject, not because its transport was corrupted.
    assert forged_trace["request"] == forged_report["request"] == forged_request
    with pytest.raises(
        ValueError, match=r"^PACKAGE_EXECUTION_PARENT_BINDING_DIFFERS$"
    ):
        observation.verify_accepted(
            forged_trace,
            forged_report,
            selection=selection,
            item=first,
            collection_digest=collection,
            module=ledger,
        )


def test_valid_object_a_exchange_cannot_be_cached_as_object_b_execution(
    subjects: tuple[NamespaceObject, NamespaceObject, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second, collection = subjects
    selection = _selection(first)
    trace, report = _accepted_exchange(_request(first, collection), selection)

    # Model the hostile transplant after selection: a valid A exchange is put
    # under B's cache key.  Keeping the original selection digest valid forces
    # evaluation to reach the request-to-current-subject binding check.
    key = (second.object_id, ledger.ADAPTER)
    snapshot = SimpleNamespace(
        collection_digest=collection,
        execution_checks={key: selection},
        execution_transports={key: trace},
        executions={key: report},
        execution_failures={},
    )
    monkeypatch.setattr(
        ledger,
        "check_observations",
        lambda *args: pytest.fail(
            "transplanted evidence must be rejected before its observations are read"
        ),
    )

    result = package_execution.evaluate_selected(
        snapshot, second, ledger.catalog()[0]
    )

    assert result is not None
    assert result["status"] == "FAIL"
    assert result["reason"] == "PACKAGE_EXECUTION_PARENT_BINDING_DIFFERS"
    assert result["applicability_established"] is False
    assert result["replay"] is None
    assert result["parent_observation_digest"] == trace["observation_digest"]
    assert snapshot.executions[key] is report
    assert snapshot.execution_failures == {}, (
        "A rejected cached transplant must not be recast as a launch failure."
    )

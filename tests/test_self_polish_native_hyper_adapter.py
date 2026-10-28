"""Public-input adapter coverage for the non-generic HYPER-4.1 route."""
from __future__ import annotations

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import hyper_closure
from verifier.runtime import core_obligation_union
from verifier.runtime import self_polish_native_adapters as adapters


def _selection() -> tuple[dict, bytes, dict]:
    make = NamespaceObject.create
    objects = [
        make("t", "TIME", {}),
        make("s", "SPACE", {}),
        make("meaning", "OBJECT", {}),
        make("d", "DATA", {}),
        make(
            "e", "EVENT", {},
            {"time": ["t"], "space": ["s"], "meaning": ["meaning"]},
        ),
        make("h", "HYPER", {}, {"event": ["e"], "input": ["d"]}),
    ]
    policy = hyper_closure.hyper_closure_policy(
        trust_roots=["native-extension-fixture"]
    )
    request = hyper_closure.hyper_closure_request(
        objects, hyper_id="h", policy=policy
    )
    evidence = core_obligation_union.canonical_bytes({
        "schema_version": hyper_closure.COLLECTION_VERSION,
        "objects": [item.to_dict() for item in sorted(
            objects, key=lambda item: item.object_id
        )],
    })
    return request, evidence, policy


def test_hyper_adapter_reproduces_public_pass_fail_unknown_triad() -> None:
    request, evidence, policy = _selection()
    negative_request, negative_evidence = adapters.negative_case(
        "HYPER_UNRELATED_OBJECT_COLLECTION",
        request,
        evidence,
        policy=policy,
    )
    unknown_request, unknown_evidence = adapters.unknown_case(
        "HYPER_CLOSURE_OPERATION_BUDGET",
        request,
        evidence,
        policy=policy,
    )
    selected = {
        "POSITIVE": (request, evidence, "POSITIVE"),
        "NEGATIVE": (negative_request, negative_evidence, "NEGATIVE"),
        "UNKNOWN": (
            unknown_request,
            unknown_evidence,
            "HYPER_CLOSURE_OPERATION_BUDGET",
        ),
    }

    statuses = {}
    for label, (selected_request, replay_input, case_kind) in selected.items():
        certificate = adapters.build_certificate(
            "HYPER_OBJECT_COLLECTION",
            case_kind,
            hyper_closure.build_hyper_closure_certificate,
            selected_request,
            replay_input,
            policy,
        )
        statuses[label] = hyper_closure.recheck_hyper_closure_certificate(
            certificate,
            expected_request=selected_request,
            policy=policy,
        )["status"]

    assert statuses == {
        "POSITIVE": "PASS",
        "NEGATIVE": "FAIL",
        "UNKNOWN": "UNKNOWN",
    }
    assert negative_request != request
    assert negative_evidence != evidence
    assert unknown_request["limits"]["max_closure_operations"] == 1
    assert request["limits"]["max_closure_operations"] > 1


def test_hyper_adapter_rejects_noncanonical_collection_input() -> None:
    request, evidence, policy = _selection()

    with pytest.raises(
        adapters.NativeReplayAdapterError,
        match="NATIVE_HYPER_REPLAY_INPUT_INVALID",
    ):
        adapters.build_certificate(
            "HYPER_OBJECT_COLLECTION",
            "POSITIVE",
            hyper_closure.build_hyper_closure_certificate,
            request,
            evidence + b" ",
            policy,
        )


def test_hyper_negative_adapter_requires_explicit_policy() -> None:
    request, evidence, _policy = _selection()

    with pytest.raises(
        adapters.NativeReplayAdapterError,
        match="NATIVE_HYPER_POLICY_UNAVAILABLE",
    ):
        adapters.negative_case(
            "HYPER_UNRELATED_OBJECT_COLLECTION", request, evidence
        )

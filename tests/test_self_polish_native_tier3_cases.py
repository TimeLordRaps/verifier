"""Source-bound Tier-3 native specimen extension tests."""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import zlib
from collections.abc import Callable
from copy import deepcopy

import pytest

from verifier.core import namespace as namespace_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.domains.contracts import (
    actor_decision_record,
    agent_ceiling_fixity,
    arch_shapes,
    bench_checks,
    bot_inherited_ceiling,
    collective_constraints,
    data_checks,
    data_distribution,
    env_checks,
    event_prerequisites,
    graph_statics,
    hardware_substrate_observations,
    harness_gap_boundary,
    human_no_composition,
    hyper_composed_ceiling,
    identity_scope,
    model_artifact_bytes,
    model_data_citation,
    model_data_lineage,
    model_hardware_observation,
    model_quantization,
    model_train_citation,
    object_statics,
    owner_eligibility,
    receipt_statics,
    role_constraints,
    sim_external_law,
    space_layout,
    time_strict,
    token_checks,
    train_accumulation,
    train_checks,
    train_data_bridge,
    verifier_run_constraints,
)
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_tier3_cases as tier3_cases


_MECHANISM_MODULES = {
    module.__name__: module
    for module in (
        actor_decision_record,
        agent_ceiling_fixity,
        arch_shapes,
        bench_checks,
        bot_inherited_ceiling,
        collective_constraints,
        data_checks,
        data_distribution,
        env_checks,
        event_prerequisites,
        graph_statics,
        hardware_substrate_observations,
        harness_gap_boundary,
        human_no_composition,
        hyper_composed_ceiling,
        identity_scope,
        model_artifact_bytes,
        model_data_citation,
        model_data_lineage,
        model_hardware_observation,
        model_quantization,
        model_train_citation,
        object_statics,
        owner_eligibility,
        receipt_statics,
        role_constraints,
        sim_external_law,
        space_layout,
        time_strict,
        token_checks,
        train_accumulation,
        train_checks,
        train_data_bridge,
        verifier_run_constraints,
    )
}


_CHECKING_MECHANISMS = {
    "verifier.domains.contracts.actor_decision_record.recheck_actor_decision_record_certificate": (
        actor_decision_record.build_actor_decision_record_certificate,
        actor_decision_record.recheck_actor_decision_record_certificate,
    ),
    "verifier.domains.contracts.agent_ceiling_fixity.recheck_agent_ceiling_fixity_certificate": (
        agent_ceiling_fixity.build_agent_ceiling_fixity_certificate,
        agent_ceiling_fixity.recheck_agent_ceiling_fixity_certificate,
    ),
    "verifier.domains.contracts.arch_shapes.recheck_arch_shapes_certificate": (
        arch_shapes.build_arch_shapes_certificate,
        arch_shapes.recheck_arch_shapes_certificate,
    ),
    "verifier.domains.contracts.bench_checks.recheck_bench_checks_certificate": (
        bench_checks.build_bench_checks_certificate,
        bench_checks.recheck_bench_checks_certificate,
    ),
    "verifier.domains.contracts.bot_inherited_ceiling.recheck_bot_inherited_ceiling_certificate": (
        bot_inherited_ceiling.build_bot_inherited_ceiling_certificate,
        bot_inherited_ceiling.recheck_bot_inherited_ceiling_certificate,
    ),
    "verifier.domains.contracts.collective_constraints.recheck_collective_constraints_certificate": (
        collective_constraints.build_collective_constraints_certificate,
        collective_constraints.recheck_collective_constraints_certificate,
    ),
    "verifier.domains.contracts.data_distribution.recheck_data_distribution_certificate": (
        data_distribution.build_data_distribution_certificate,
        data_distribution.recheck_data_distribution_certificate,
    ),
    "verifier.domains.contracts.env_checks.recheck_env_checks_certificate": (
        env_checks.build_env_checks_certificate,
        env_checks.recheck_env_checks_certificate,
    ),
    "verifier.domains.contracts.event_prerequisites.recheck_event_prerequisites_certificate": (
        event_prerequisites.build_event_prerequisites_certificate,
        event_prerequisites.recheck_event_prerequisites_certificate,
    ),
    "verifier.domains.contracts.graph_statics.recheck_graph_statics_certificate": (
        graph_statics.build_graph_statics_certificate,
        graph_statics.recheck_graph_statics_certificate,
    ),
    "verifier.domains.contracts.hardware_substrate_observations.recheck_hardware_substrate_observations_certificate": (
        hardware_substrate_observations.build_hardware_substrate_observations_certificate,
        hardware_substrate_observations.recheck_hardware_substrate_observations_certificate,
    ),
    "verifier.domains.contracts.harness_gap_boundary.recheck_harness_gap_boundary_certificate": (
        harness_gap_boundary.build_harness_gap_boundary_certificate,
        harness_gap_boundary.recheck_harness_gap_boundary_certificate,
    ),
    "verifier.domains.contracts.human_no_composition.recheck_human_no_composition_certificate": (
        human_no_composition.build_human_no_composition_certificate,
        human_no_composition.recheck_human_no_composition_certificate,
    ),
    "verifier.domains.contracts.hyper_composed_ceiling.recheck_hyper_composed_ceiling_certificate": (
        hyper_composed_ceiling.build_hyper_composed_ceiling_certificate,
        hyper_composed_ceiling.recheck_hyper_composed_ceiling_certificate,
    ),
    "verifier.domains.contracts.identity_scope.recheck_identity_scope_certificate": (
        identity_scope.build_identity_scope_certificate,
        identity_scope.recheck_identity_scope_certificate,
    ),
    "verifier.domains.contracts.model_artifact_bytes.recheck_model_artifact_bytes_certificate": (
        model_artifact_bytes.build_model_artifact_bytes_certificate,
        model_artifact_bytes.recheck_model_artifact_bytes_certificate,
    ),
    "verifier.domains.contracts.model_data_citation.recheck_model_data_certificate": (
        model_data_citation.build_model_data_certificate,
        model_data_citation.recheck_model_data_certificate,
    ),
    "verifier.domains.contracts.model_data_lineage.recheck_model_data_lineage_certificate": (
        model_data_lineage.build_model_data_lineage_certificate,
        model_data_lineage.recheck_model_data_lineage_certificate,
    ),
    "verifier.domains.contracts.model_hardware_observation.recheck_model_hardware_certificate": (
        model_hardware_observation.build_model_hardware_certificate,
        model_hardware_observation.recheck_model_hardware_certificate,
    ),
    "verifier.domains.contracts.model_quantization.recheck_model_quantization_certificate": (
        model_quantization.build_model_quantization_certificate,
        model_quantization.recheck_model_quantization_certificate,
    ),
    "verifier.domains.contracts.model_train_citation.recheck_model_train_certificate": (
        model_train_citation.build_model_train_certificate,
        model_train_citation.recheck_model_train_certificate,
    ),
    "verifier.domains.contracts.object_statics.recheck_object_statics_certificate": (
        object_statics.build_object_statics_certificate,
        object_statics.recheck_object_statics_certificate,
    ),
    "verifier.domains.contracts.owner_eligibility.recheck_owner_eligibility_certificate": (
        owner_eligibility.build_owner_eligibility_certificate,
        owner_eligibility.recheck_owner_eligibility_certificate,
    ),
    "verifier.domains.contracts.receipt_statics.recheck_receipt_statics_certificate": (
        receipt_statics.build_receipt_statics_certificate,
        receipt_statics.recheck_receipt_statics_certificate,
    ),
    "verifier.domains.contracts.role_constraints.recheck_role_constraints_certificate": (
        role_constraints.build_role_constraints_certificate,
        role_constraints.recheck_role_constraints_certificate,
    ),
    "verifier.domains.contracts.sim_external_law.recheck_sim_external_law_certificate": (
        sim_external_law.build_sim_external_law_certificate,
        sim_external_law.recheck_sim_external_law_certificate,
    ),
    "verifier.domains.contracts.space_layout.recheck_space_layout_certificate": (
        space_layout.build_space_layout_certificate,
        space_layout.recheck_space_layout_certificate,
    ),
    "verifier.domains.contracts.time_strict.recheck_time_strict_certificate": (
        time_strict.build_time_strict_certificate,
        time_strict.recheck_time_strict_certificate,
    ),
    "verifier.domains.contracts.token_checks.recheck_token_checks_certificate": (
        token_checks.build_token_checks_certificate,
        token_checks.recheck_token_checks_certificate,
    ),
    "verifier.domains.contracts.train_accumulation.recheck_train_accumulation_certificate": (
        train_accumulation.build_train_accumulation_certificate,
        train_accumulation.recheck_train_accumulation_certificate,
    ),
    "verifier.domains.contracts.verifier_run_constraints.recheck_verifier_run_constraints_certificate": (
        verifier_run_constraints.build_verifier_run_constraints_certificate,
        verifier_run_constraints.recheck_verifier_run_constraints_certificate,
    ),
}


def _memberships() -> dict[str, dict]:
    inventory = core_tier_progression.installed_core_route_inventory()
    return {
        f"{cell['object_kind']}:{route['coordinate']}": {
            "object_kind": cell["object_kind"],
            **route,
        }
        for cell in inventory["family_cells"]
        if cell["tier"] == 3
        for route in cell["registered_route_memberships"]
    }


def _encode_payload(payload: dict) -> bytes:
    raw = core_obligation_union.canonical_bytes(payload)
    return base64.b85encode(zlib.compress(raw, 9))


def _installed_payload() -> dict:
    return json.loads(zlib.decompress(base64.b85decode(tier3_cases._PAYLOAD_B85)))


def _positive_certificate(case: dict) -> tuple[bytes, Callable[..., dict]]:
    builder, rechecker = _CHECKING_MECHANISMS[case["checking_mechanism"]]
    evidence = base64.b64decode(case["evidence_base64"], validate=True)
    certificate = adapters.build_certificate(
        case["builder_adapter"], "POSITIVE", builder,
        case["request"], evidence, case["policy"],
    )
    return certificate, rechecker


def _refused_or_status(rechecker, certificate, request, policy) -> str:
    try:
        return rechecker(certificate, expected_request=request, policy=policy)["status"]
    except ValueError:
        return "REFUSED"


def test_tier3_extension_is_exact_source_bound_and_adapter_explicit() -> None:
    selected = tier3_cases.installed_case_inputs()
    memberships = _memberships()
    review = tier3_cases.installed_source_review()

    assert tier3_cases.CASE_REGISTRY_ENTRY_COUNT == 31
    assert set(selected) == set(memberships)
    assert set(review) == set(selected)
    assert {
        identifier for identifier, row in review.items()
        if row["disposition"] == "RETAIN_UNKNOWN"
    } == set()
    assert set(_CHECKING_MECHANISMS) == {
        case["checking_mechanism"] for case in selected.values()
    }
    assert core_obligation_union.value_digest(selected) \
        == tier3_cases.CASE_REGISTRY_DIGEST
    for identifier, case in selected.items():
        route = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == route["checking_mechanism"]
        assert request["coordinate"] == route["coordinate"]
        assert request["semantic_version"] == route["semantic_version"]
        assert request["proposition_digest"] == route["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])
        expected_pin = (
            review[identifier]["prior_mechanism_digest"]
            if review[identifier]["disposition"] == "RETAIN_UNKNOWN"
            else review[identifier]["reviewed_mechanism_digest"]
        )
        assert case["policy"]["mechanism_digest"] == expected_pin
        assert case["builder_adapter"] == (
            "WINDOWS_MODEL_HARDWARE_OBSERVATION"
            if identifier == "MODEL:MODEL-3.2"
            else "BOUNDED_EVIDENCE_BYTES"
        )
        assert case["negative_adapter"] == "MALFORMED_EVIDENCE_REBIND"
        assert case["unknown_adapter"] == "ABSENT_EVIDENCE"


def test_tier3_extension_rejects_payload_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier3_cases, "_PAYLOAD_B85", b"not-the-payload")

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.installed_case_inputs()


def test_tier3_generator_reproduces_embedded_payload() -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    raw, encoded = module.build_payload()
    second_raw, second_encoded = module.build_payload()

    assert (second_raw, second_encoded) == (raw, encoded)
    assert encoded == tier3_cases._PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier3_cases.CASE_REGISTRY_DIGEST
    assert module.build_source_review() == tier3_cases.installed_source_review()
    assert module.runtime_module_is_current()


def test_tier3_extension_reproduces_native_triads() -> None:
    selected = tier3_cases.installed_case_inputs()
    review = tier3_cases.installed_source_review()
    observed = {}
    for identifier, case in selected.items():
        builder, rechecker = _CHECKING_MECHANISMS[case["checking_mechanism"]]
        request = case["request"]
        policy = case["policy"]
        evidence = base64.b64decode(case["evidence_base64"], validate=True)
        if review[identifier]["disposition"] == "RETAIN_UNKNOWN":
            # Retained stale pin: the coordinate is UNKNOWN, so no triad may PASS.
            with pytest.raises(ValueError, match="policy differs from installed mechanism"):
                certificate = adapters.build_certificate(
                    case["builder_adapter"], "POSITIVE", builder,
                    request, evidence, policy,
                )
                rechecker(certificate, expected_request=request, policy=policy)
            observed[identifier] = {"POSITIVE": "REFUSED"}
            continue
        negative_request, negative_evidence = adapters.negative_case(
            case["negative_adapter"], request, evidence
        )
        built = {
            "POSITIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "POSITIVE", builder,
                    request, evidence, policy,
                ),
                request,
            ),
            "NEGATIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "NEGATIVE", builder,
                    negative_request, negative_evidence, policy,
                ),
                negative_request,
            ),
            "UNKNOWN": (
                adapters.build_certificate(
                    case["builder_adapter"], case["unknown_adapter"],
                    builder, request, evidence, policy,
                ),
                request,
            ),
        }
        observed[identifier] = {
            kind: rechecker(
                certificate,
                expected_request=expected_request,
                policy=policy,
            )["status"]
            for kind, (certificate, expected_request) in built.items()
        }

    assert len(observed) == 31
    for identifier, statuses in observed.items():
        if review[identifier]["disposition"] == "RETAIN_UNKNOWN":
            assert statuses == {"POSITIVE": "REFUSED"}
            continue
        assert statuses["NEGATIVE"] == "FAIL"
        assert statuses["UNKNOWN"] == "UNKNOWN"
        if identifier == "MODEL:MODEL-3.2":
            assert statuses["POSITIVE"] in {"PASS", "UNKNOWN"}
        else:
            assert statuses["POSITIVE"] == "PASS"


def test_graph_coordinate_is_accepted_and_digest_bound() -> None:
    selected = tier3_cases.installed_case_inputs()
    row = tier3_cases.installed_source_review()["GRAPH:GRAPH-3.1"]
    case = selected["GRAPH:GRAPH-3.1"]

    assert row["disposition"] == "ACCEPT_REPIN"
    assert case["policy"]["mechanism_digest"] == row["reviewed_mechanism_digest"]
    assert row["reviewed_mechanism_digest"] != row["prior_mechanism_digest"]
    assert "retained_case_digest" not in row


def test_accepted_reviewed_digests_match_live_mechanisms() -> None:
    review = tier3_cases.installed_source_review()
    for identifier, case in tier3_cases.installed_case_inputs().items():
        builder, _ = _CHECKING_MECHANISMS[case["checking_mechanism"]]
        live = _MECHANISM_MODULES[builder.__module__].mechanism_digest()
        assert live == review[identifier]["reviewed_mechanism_digest"]
        if review[identifier]["disposition"] == "ACCEPT_REPIN":
            assert case["policy"]["mechanism_digest"] == live


def test_stale_prior_pin_is_refused_for_every_accepted_coordinate() -> None:
    selected = tier3_cases.installed_case_inputs()
    review = tier3_cases.installed_source_review()
    checked = 0
    for identifier, case in selected.items():
        if review[identifier]["disposition"] != "ACCEPT_REPIN":
            continue
        certificate, rechecker = _positive_certificate(case)
        stale = {
            **case["policy"],
            "mechanism_digest": review[identifier]["prior_mechanism_digest"],
        }
        with pytest.raises(ValueError, match="policy differs from installed mechanism"):
            rechecker(certificate, expected_request=case["request"], policy=stale)
        checked += 1
    assert checked == 31


def test_wrong_checker_for_a_coordinate_is_refused() -> None:
    selected = tier3_cases.installed_case_inputs()
    actor = selected["ACTOR:ACTOR-3.3"]
    agent = selected["AGENT:AGENT-3.1"]
    certificate, _ = _positive_certificate(actor)
    _, agent_rechecker = _CHECKING_MECHANISMS[agent["checking_mechanism"]]

    assert _refused_or_status(
        agent_rechecker, certificate, actor["request"], agent["policy"]
    ) != "PASS"


def test_weakened_policy_is_refused() -> None:
    case = tier3_cases.installed_case_inputs()["ACTOR:ACTOR-3.3"]
    certificate, rechecker = _positive_certificate(case)
    weakened = (
        {**case["policy"], "trust_roots": ["unreviewed-root"]},
        {**case["policy"], "max_certificate_bytes": 1},
    )
    for policy in weakened:
        assert _refused_or_status(
            rechecker, certificate, case["request"], policy
        ) != "PASS"


def test_source_byte_drift_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    case = tier3_cases.installed_case_inputs()["ACTOR:ACTOR-3.3"]
    certificate, rechecker = _positive_certificate(case)
    drifted_path = pathlib.Path(namespace_module.__file__).resolve()
    original_read = pathlib.Path.read_bytes

    def drifted_read(self: pathlib.Path) -> bytes:
        data = original_read(self)
        if self.resolve() == drifted_path:
            return data + b"\n# drift\n"
        return data

    monkeypatch.setattr(pathlib.Path, "read_bytes", drifted_read)
    with pytest.raises(ValueError, match="policy differs from installed mechanism"):
        rechecker(certificate, expected_request=case["request"], policy=case["policy"])


def test_builder_refuses_source_drift_after_review(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    monkeypatch.setattr(
        actor_decision_record, "mechanism_digest",
        lambda: "sha256:" + "1" * 64,
    )
    with pytest.raises(RuntimeError, match="Tier-3 source review stale: ACTOR:ACTOR-3.3"):
        module.build_payload()


def test_count_preserving_coordinate_swap_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _installed_payload()
    payload["ACTOR:ACTOR-3.3"], payload["AGENT:AGENT-3.1"] = (
        payload["AGENT:AGENT-3.1"], payload["ACTOR:ACTOR-3.3"],
    )
    monkeypatch.setattr(tier3_cases, "_PAYLOAD_B85", _encode_payload(payload))

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.installed_case_inputs()


def test_hand_edited_case_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _installed_payload()
    payload["ACTOR:ACTOR-3.3"]["request"]["subject_id"] = "p-bob"
    monkeypatch.setattr(tier3_cases, "_PAYLOAD_B85", _encode_payload(payload))

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.installed_case_inputs()


def test_hand_edited_registry_digest_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tier3_cases, "CASE_REGISTRY_DIGEST", "sha256:" + "0" * 64,
    )
    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.installed_case_inputs()


def test_hand_edited_source_review_is_refused(
        monkeypatch: pytest.MonkeyPatch) -> None:
    review = deepcopy(tier3_cases.SOURCE_REVIEW)
    review["GRAPH:GRAPH-3.1"]["disposition"] = "RETAIN_UNKNOWN"
    monkeypatch.setattr(tier3_cases, "SOURCE_REVIEW", review)

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.installed_source_review()


def test_generated_block_hand_edit_is_detected(
        monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    text = pathlib.Path(tier3_cases.__file__).read_text(encoding="utf-8")
    edited = text.replace(
        f'SOURCE_REVIEW_DIGEST = "{tier3_cases.SOURCE_REVIEW_DIGEST}"',
        'SOURCE_REVIEW_DIGEST = "sha256:' + "0" * 64 + '"',
        1,
    )
    assert edited != text
    target = tmp_path / "self_polish_native_tier3_cases.py"
    target.write_text(edited, encoding="utf-8")
    monkeypatch.setattr(module, "RUNTIME_MODULE", target)

    assert module.runtime_module_is_current() is False


# MODEL:MODEL-3.7 retained lineage. Its selected MODEL-3.4 and TRAIN-1.5 children
# carry their own nested mechanism pins; a stale pin at any depth is a contract
# refusal, so the installed fixture must pin every nested child to its live module.
_MODEL_3_7 = "MODEL:MODEL-3.7"
_MODEL_3_7_NESTED_PINS = (
    (("model_data_policy",), model_data_citation),
    (("model_data_request", "data_policy"), data_checks),
    (("bridge_policy",), train_data_bridge),
    (("bridge_request", "data_policy"), data_checks),
    (("bridge_request", "train_policy"), train_checks),
)
_STALE_PIN = "sha256:" + "1" * 64


def _model_3_7_input() -> tuple[dict, dict, bytes]:
    case = tier3_cases.installed_case_inputs()[_MODEL_3_7]
    return (deepcopy(case["request"]), deepcopy(case["policy"]),
            base64.b64decode(case["evidence_base64"], validate=True))


def _model_3_7_outcome(request: dict, policy: dict, evidence: bytes) -> tuple[str, str]:
    """Return (status, detail); a refused selection is ("REFUSED", exception text)."""
    try:
        certificate = model_data_lineage.build_model_data_lineage_certificate(
            request, evidence, policy=policy,
        )
        result = model_data_lineage.recheck_model_data_lineage_certificate(
            certificate, expected_request=request, policy=policy,
        )
    except model_data_lineage.ModelDataLineageError as exc:
        return "REFUSED", str(exc)
    return result["status"], result["evaluation"]["details"]


def _assert_model_3_7_nested_pins_live(request: dict) -> None:
    for path, module in _MODEL_3_7_NESTED_PINS:
        node = request
        for key in path:
            node = node[key]
        assert node["mechanism_digest"] == module.mechanism_digest(), path


def _edited_evidence(evidence: bytes, edit: Callable[[dict], None]) -> bytes:
    value = json.loads(evidence.decode("utf-8"))
    edit(value)
    return core_obligation_union.canonical_bytes(value)


def _rehashed(request: dict, evidence: bytes) -> dict:
    request["evidence_ref"] = "sha256:" + hashlib.sha256(evidence).hexdigest()
    return request


def _stale_model_child_pin(request, policy, evidence):
    request["model_data_policy"]["mechanism_digest"] = _STALE_PIN
    return request, policy, evidence


def _stale_bridge_child_pin(request, policy, evidence):
    request["bridge_policy"]["mechanism_digest"] = _STALE_PIN
    return request, policy, evidence


def _swapped_children(request, policy, evidence):
    request["model_data_request"], request["bridge_request"] = (
        request["bridge_request"], request["model_data_request"],
    )
    return request, policy, evidence


def _wrong_child_semantic_version(request, policy, evidence):
    request["model_data_request"]["semantic_version"] = "verifier-current-object-obligations-0"
    return request, policy, evidence


def _wrong_child_coordinate(request, policy, evidence):
    request["bridge_request"]["coordinate"] = "TRAIN-1.4"
    return request, policy, evidence


def _wrong_top_level_policy(request, policy, evidence):
    policy["trust_roots"] = ["unreviewed-root"]
    return request, policy, evidence


def _weakened_child_policy_repinned(request, policy, evidence):
    child = request["model_data_policy"]
    child["trust_roots"] = ["unreviewed-root"]
    request["model_data_request"]["policy_digest"] = (
        "sha256:" + hashlib.sha256(core_obligation_union.canonical_bytes(child)).hexdigest()
    )
    return request, policy, evidence


def _stale_child_certificate_digest(request, policy, evidence):
    request["model_data_certificate_digest"] = "sha256:" + hashlib.sha256(b"not-the-certificate").hexdigest()
    return request, policy, evidence


def _missing_citation_key(request, policy, evidence):
    evidence = _edited_evidence(evidence, lambda value: value.pop("model_data_certificate_b64"))
    return _rehashed(request, evidence), policy, evidence


def _empty_citation(request, policy, evidence):
    evidence = _edited_evidence(evidence, lambda value: value.update(model_data_certificate_b64=""))
    return _rehashed(request, evidence), policy, evidence


def _malformed_child_scalar(request, policy, evidence):
    request["model_data_request"] = "not-a-record"
    return request, policy, evidence


def _malformed_child_empty(request, policy, evidence):
    request["bridge_request"] = {}
    return request, policy, evidence


def _count_preserving_citation_swap(request, policy, evidence):
    def swap(value: dict) -> None:
        value["model_data_certificate_b64"], value["bridge_certificate_b64"] = (
            value["bridge_certificate_b64"], value["model_data_certificate_b64"],
        )
    evidence = _edited_evidence(evidence, swap)
    return _rehashed(request, evidence), policy, evidence


def _batch_view_equals_model_data(request, policy, evidence):
    request["batch_view_subject_id"] = request["model_data_subject_id"]
    return request, policy, evidence


def test_model_3_7_installed_positive_replays_both_children_exactly() -> None:
    request, policy, evidence = _model_3_7_input()

    assert _model_3_7_outcome(request, policy, evidence) == (
        "PASS", "selected MODEL and TRAIN replay over one collection and mediated DATA inventory",
    )


def test_model_3_7_installed_fixture_pins_every_nested_child_to_live_mechanisms() -> None:
    request, _, _ = _model_3_7_input()

    _assert_model_3_7_nested_pins_live(request)


def test_model_3_7_generator_is_deterministic_and_matches_installed_input() -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    first = module.gen_model_3_7()
    second = module.gen_model_3_7()

    assert second == first
    assert first == _model_3_7_input()


@pytest.mark.parametrize(("mutate", "status", "detail"), [
    (_stale_model_child_pin, "REFUSED", "invalid selected child prerequisite"),
    (_stale_bridge_child_pin, "REFUSED", "invalid selected child prerequisite"),
    (_swapped_children, "REFUSED", "invalid selected child prerequisite"),
    (_wrong_child_semantic_version, "REFUSED", "invalid selected child prerequisite"),
    (_wrong_child_coordinate, "REFUSED", "invalid selected child prerequisite"),
    (_wrong_top_level_policy, "REFUSED", "request differs from selected lineage policy"),
    (_weakened_child_policy_repinned, "FAIL", "selected child certificate did not reproduce"),
    (_stale_child_certificate_digest, "FAIL", "retained child bytes differ from external selection"),
    (_missing_citation_key, "FAIL", "evidence fields differ"),
    (_empty_citation, "UNKNOWN", "selected retained child certificate absent"),
    (_malformed_child_scalar, "REFUSED", "selected child request and policy must be plain records"),
    (_malformed_child_empty, "REFUSED", "invalid selected child prerequisite"),
    (_count_preserving_citation_swap, "FAIL", "retained child bytes differ from external selection"),
    (_batch_view_equals_model_data, "REFUSED", "selected children, subjects or collection differ"),
])
def test_model_3_7_adversarial_selection_never_passes(mutate, status, detail) -> None:
    observed_status, reason = _model_3_7_outcome(*mutate(*_model_3_7_input()))

    assert observed_status == status
    assert observed_status != "PASS"
    assert detail in reason


# GRAPH-3.1 reviewed current-source fixture. The installed payload carries the
# accepted live graph_statics triad. Adversaries use an independent fixture
# (mirrors the generator's construction) so the checker is tested directly,
# not through the generator under test.
_GRAPH = "GRAPH:GRAPH-3.1"
_AB = {"source": "a", "target": "b"}
_BC = {"source": "b", "target": "c"}
_AC = {"source": "a", "target": "c"}
_BA = {"source": "b", "target": "a"}


def _graph_triad(nodes: list[str], edges: list[dict[str, str]]) -> tuple[dict, dict, bytes]:
    members = [namespace_module.NamespaceObject.create(name, "ENV", {"fixture": name})
               for name in nodes]
    graph = namespace_module.NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": "sha256:" + canonical_digest(nodes),
        "edges_digest": "sha256:" + canonical_digest(edges),
    }, {"members": list(nodes)})
    objects = [*members, graph]
    evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": nodes, "edges": edges},
    })
    policy = graph_statics.graph_statics_policy(trust_roots=["externally-selected-graph"])
    request = graph_statics.graph_statics_request(
        subject_id="graph",
        object_digest=graph.digest,
        collection_digest=namespace_module.composition_digest(objects),
        nodes_digest="sha256:" + canonical_digest(nodes),
        edges_digest="sha256:" + canonical_digest(edges),
        evidence_ref="sha256:" + canonical_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


def _graph_outcome(request: dict, policy: dict, evidence: bytes | None) -> tuple[str, str]:
    """Return (status, reason); a refused selection is ("REFUSED", exception text)."""
    try:
        certificate = graph_statics.build_graph_statics_certificate(
            request, evidence, policy=policy,
        )
        result = graph_statics.recheck_graph_statics_certificate(
            certificate, expected_request=request, policy=policy,
        )
    except graph_statics.GraphStaticsError as exc:
        return "REFUSED", str(exc)
    return result["status"], result["evaluation"]["details"]


def _graph_base() -> tuple[dict, dict, bytes]:
    return _graph_triad(["a", "b"], [_AB])


def _graph_prior_pin() -> str:
    return tier3_cases.installed_source_review()[_GRAPH]["prior_mechanism_digest"]


def _graph_stale_mechanism_pin(request, policy, evidence):
    stale = {**policy, "mechanism_digest": _graph_prior_pin()}
    return ({**request, "policy_digest": core_obligation_union.value_digest(stale)},
            stale, evidence)


def _graph_wrong_trust_root(request, policy, evidence):
    return request, {**policy, "trust_roots": ["unreviewed-root"]}, evidence


def _graph_vertex_substitution(request, policy, evidence):
    evil = _edited_evidence(evidence, lambda v: v["inputs"].__setitem__("nodes", ["a", "x"]))
    return _rehashed(request, evil), policy, evil


def _graph_edge_count_preserving_swap(request, policy, evidence):
    base_request, base_policy, base_evidence = _graph_triad(["a", "b", "c"], [_AB, _BC])
    evil = _edited_evidence(
        base_evidence, lambda v: v["inputs"].__setitem__("edges", [_AB, _AC]),
    )
    return _rehashed(base_request, evil), base_policy, evil


def _graph_cycle(request, policy, evidence):
    return _graph_triad(["a", "b"], [_AB, _BA])


def _graph_missing_edge_input(request, policy, evidence):
    evil = _edited_evidence(evidence, lambda v: v["inputs"].pop("edges"))
    return _rehashed(request, evil), policy, evil


def _graph_absent_evidence(request, policy, evidence):
    return request, policy, None


def test_graph_fixture_positive_control_passes_and_matches_generator() -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    assert _graph_outcome(*_graph_base())[0] == "PASS"
    assert _graph_base() == module.gen_graph_3_1()


def test_no_prepared_overlay_remains_after_graph_repin() -> None:
    installed = tier3_cases.installed_case_inputs()
    prepared = tier3_cases.prepared_case_inputs()
    review = tier3_cases.installed_source_review()
    case = installed[_GRAPH]

    assert set(prepared) == set(installed)
    assert prepared == installed
    assert case["checking_mechanism"] == installed[_GRAPH]["checking_mechanism"]
    assert case["policy"]["mechanism_digest"] \
        == graph_statics.mechanism_digest() \
        == review[_GRAPH]["reviewed_mechanism_digest"]
    assert case["request"]["policy_digest"] \
        == core_obligation_union.value_digest(case["policy"])
    assert (case["request"], case["policy"],
            base64.b64decode(case["evidence_base64"], validate=True)) == _graph_base()
    assert review[_GRAPH]["disposition"] == "ACCEPT_REPIN"
    assert installed[_GRAPH]["policy"]["mechanism_digest"] != _graph_prior_pin()


def test_prepared_overlay_generator_is_deterministic_and_current() -> None:
    from scripts import build_self_polish_native_tier3_cases as module

    raw, encoded = module.build_prepared_current_payload()

    assert module.build_prepared_current_payload() == (raw, encoded)
    assert encoded == tier3_cases._PREPARED_CURRENT_PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier3_cases.PREPARED_CURRENT_CASE_REGISTRY_DIGEST
    assert module.runtime_module_is_current()


def test_installed_graph_positive_passes_after_reviewed_repin() -> None:
    case = tier3_cases.installed_case_inputs()[_GRAPH]
    certificate, rechecker = _positive_certificate(case)

    assert _refused_or_status(rechecker, certificate, case["request"], case["policy"]) == "PASS"
    assert tier3_cases.prepared_case_inputs()[_GRAPH] == case


def test_prepared_overlay_refuses_stale_mechanism_pin(
        monkeypatch: pytest.MonkeyPatch) -> None:
    stale = {_GRAPH: tier3_cases.installed_case_inputs()[_GRAPH]}
    monkeypatch.setattr(tier3_cases, "_PREPARED_CURRENT_PAYLOAD_B85", _encode_payload(stale))
    monkeypatch.setattr(
        tier3_cases, "PREPARED_CURRENT_CASE_REGISTRY_DIGEST",
        core_obligation_union.bytes_digest(core_obligation_union.canonical_bytes(stale)),
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.prepared_case_inputs()


def test_prepared_overlay_refuses_smuggled_status_field(
        monkeypatch: pytest.MonkeyPatch) -> None:
    promoted = {_GRAPH: {**tier3_cases.prepared_case_inputs()[_GRAPH],
                         "lifecycle_status": "INSTALLED"}}
    monkeypatch.setattr(tier3_cases, "_PREPARED_CURRENT_PAYLOAD_B85", _encode_payload(promoted))
    monkeypatch.setattr(
        tier3_cases, "PREPARED_CURRENT_CASE_REGISTRY_DIGEST",
        core_obligation_union.bytes_digest(core_obligation_union.canonical_bytes(promoted)),
    )

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier3_cases.prepared_case_inputs()


@pytest.mark.parametrize(("mutate", "status", "detail"), [
    (_graph_stale_mechanism_pin, "REFUSED", "policy differs from installed mechanism"),
    (_graph_wrong_trust_root, "REFUSED", "request differs from selected policy"),
    (_graph_vertex_substitution, "FAIL", "retained nodes differ from selected GRAPH direct members"),
    (_graph_edge_count_preserving_swap, "FAIL", "retained graph arrays differ"),
    (_graph_cycle, "FAIL", "retained directed graph contains a cycle"),
    (_graph_missing_edge_input, "UNKNOWN", "retained node or edge evidence absent"),
    (_graph_absent_evidence, "UNKNOWN", "evidence is unavailable"),
])
def test_installed_graph_adversarial_selection_never_passes(mutate, status, detail) -> None:
    observed_status, reason = _graph_outcome(*mutate(*_graph_base()))

    assert observed_status == status
    assert observed_status != "PASS"
    assert detail in reason

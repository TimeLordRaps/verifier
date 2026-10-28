"""Explicit finite native replacement selection and negative consumer controls.

JavaScript Object Notation (JSON); directed acyclic graph (DAG). Metadata
availability and finite fixture replay grant no complete application admission.
"""
from __future__ import annotations

from copy import deepcopy
import base64
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectCoordinate
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import verifier_replacement as native
from verifier.runtime import native_operation_contracts as operations
from verifier.runtime import permission_slot, polish_requirements, tier_progression
from test_verifier_replacement import selected_fixture


def selected_route(certificate: bytes, request: dict, policy: dict, **changes: str) -> dict:
    selection = {'semantic_version': native.SEMANTIC_VERSION,
                 'objective': native.COORDINATE, 'represented_kind': 'VERIFIER'}
    selection.update(changes)
    return routes.replay_current_object_certificate(certificate,
        expected_request=request, policy=policy, **selection)


def test_actual_native_replay_is_read_only_and_keeps_full_corrigibility_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, effects = selected_fixture()
    before = tuple(effects)
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)

    def forbid(*args: object, **kwargs: object) -> None:
        pytest.fail('portable replay entered a live permission-slot operation')

    monkeypatch.setattr(permission_slot.PermissionSlot, 'invoke', forbid)
    monkeypatch.setattr(permission_slot.PermissionSlot, 'grant', forbid)
    result = selected_route(certificate, request, policy)
    assert result['schema_version'] == 'verifier-current-object-route-replay-2'
    assert result['computational_status'] == 'PASS'
    assert result['replay_status'] == 'REPRODUCED'
    assert result['native_result']['finite_replacement'] == 'PASS'
    assert result['native_result']['complete_corrigibility_admission'] == 'UNKNOWN'
    assert result['native_result']['whole_corrigibility_conformance'] == 'NOT_ESTABLISHED'
    assert tuple(effects) == before


def test_metadata_pass_cannot_be_used_as_native_certificate_clearance() -> None:
    request, policy, _, _ = selected_fixture()
    metadata = operations.lookup_native_replay_operation(semantic_version=native.SEMANTIC_VERSION,
        objective=native.COORDINATE, represented_kind='VERIFIER')
    assert metadata['status'] == 'PASS'
    assert metadata['native_replay'] == 'NOT_RUN'
    assert metadata['mandatory_obligation_census'] == 'UNKNOWN'
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        selected_route(canonical_bytes(metadata), request, policy)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        selected_route(canonical_bytes(operations.native_replay_operation_catalog(
            semantic_version=native.SEMANTIC_VERSION)), request, policy)


def test_actual_native_dependency_replay_does_not_clear_missing_lower_ranks() -> None:
    request, policy, evidence, _ = selected_fixture()
    subject = NamespaceObject.create(**json.loads(base64.b64decode(
        json.loads(evidence)['retained_payloads'][request['object_digest']])))
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    certificate_pin = tier_progression.digest(certificate)
    profile = {'schema_version': dag.PROFILE, 'profile_id': 'finite-native10-fixture',
        'profile_version': '1', 'object_kind': 'VERIFIER', 'obligations': [{
            'claim_id': 'replacement', 'semantic_version': native.SEMANTIC_VERSION,
            'objective': native.COORDINATE, 'proposition_digest': native.PROPOSITION_DIGEST,
            'scope': native.SCOPE, 'assumptions': [], 'dependencies': []}]}
    profile_pin = tier_progression.digest(canonical_bytes(profile))
    node = {'node_id': 'replacement', 'object_id': subject.object_id, 'claim_id': 'replacement',
        'certificate_path': 'replacement.json', 'certificate_digest': certificate_pin,
        'request': request, 'checker_policy': policy, 'contract_version': '2',
        'artifact_bindings': [{'path': 'replacement.json', 'digest': certificate_pin}],
        'facet_bindings': {'payload_digest': tier_progression.digest(subject.payload_bytes),
            'operands_digest': tier_progression.digest(canonical_bytes(subject.to_dict()['operands']))}}
    files = {'replacement.json': certificate}
    bundle = {'schema_version': dag.BUNDLE, 'profiles': [profile], 'objects': [subject.to_dict()],
        'nodes': [node], 'edges': []}
    selected_policy = {'schema_version': dag.POLICY, 'approved_profiles': [profile_pin],
        'required_objects': [{'object_id': subject.object_id, 'object_kind': 'VERIFIER',
            'record_digest': subject.digest, 'profile_digest': profile_pin}],
        'required_roots': ['replacement'], 'nodes': deepcopy(bundle['nodes']),
        'artifact_files_digest': dag.artifact_files_digest(files)}
    report = dag.assess_certificate_dependencies_preserving_faults(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(selected_policy), artifact_files=files)
    assert report['status'] == 'PASS', report
    assert report['nodes'][0]['direct_status'] == 'PASS'
    # A selected collection disagreement must be refused before native clearance.
    substituted = deepcopy(bundle)
    substituted['nodes'][0]['request']['collection_digest'] = tier_progression.digest(b'foreign collection')
    substituted_policy = {**selected_policy, 'nodes': deepcopy(substituted['nodes'])}
    refusal = dag.assess_certificate_dependencies_preserving_faults(canonical_bytes(substituted),
        expected_policy_bytes=canonical_bytes(substituted_policy), artifact_files=files)
    assert refusal['status'] == 'FAIL'
    assert refusal['blockers'] == ['DEPENDENCY_CONTRACT_REJECTED']
    assert report['object_profile_conformance'] == 'NOT_ESTABLISHED'
    selection = {'schema_version': tier_progression.SELECTION,
        'semantic_version': tier_progression.PROFILE, 'profile_id': 'finite-native10-fixture',
        'subject': {'object_id': subject.object_id, 'object_kind': 'VERIFIER', 'record_digest': subject.digest},
        'target_tier': 10, 'bundle_digest': tier_progression.digest(canonical_bytes(bundle)),
        'policy_digest': tier_progression.digest(canonical_bytes(selected_policy)),
        'artifact_files_digest': dag.artifact_files_digest(files),
        'ranks': [{'node_id': 'replacement', 'tier': 10}],
        'tiers': [{'tier': rank, 'census': 'COMPLETE' if rank == 10 else 'UNKNOWN',
            'required_nodes': ['replacement'] if rank == 10 else []} for rank in range(1, 11)]}
    raw = canonical_bytes(selection)
    progression = tier_progression.assess_tier_progression(raw, bundle_bytes=canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(selected_policy), artifact_files=files,
        expected_selection_digest=tier_progression.digest(raw),
        expected_mechanism_digest=tier_progression.mechanism_digest())
    assert progression['native_assessment']['status'] == 'PASS'
    assert progression['tiers'][9]['direct_status'] == 'PASS'
    assert progression['status'] == progression['selected_target_status'] == 'UNKNOWN'
    assert progression['selected_depth'] == 0 and progression['can_advance_to'] is None
    assert progression['full_application_status'] == progression['full_required_certificate_instances'] == 'UNKNOWN'
    assert progression['polished'] is False


@pytest.mark.parametrize('changes', [
    {'semantic_version': 'verifier-current-object-obligations-1'},
    {'semantic_version': native.SEMANTIC_VERSION + '-changed'},
    {'objective': 'VERIFIER-6.1'}, {'represented_kind': 'HARNESS'},
])
def test_new_native_certificate_never_falls_back_across_family_or_kind(changes: dict) -> None:
    request, policy, evidence, _ = selected_fixture()
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        selected_route(certificate, request, policy, **changes)


@pytest.mark.parametrize('field,value', [
    ('whole_corrigibility_conformance', 'PASS'), ('complete_corrigibility_admission', 'PASS'),
    ('authority', 'ESTABLISHED'), ('actual_execution', 'ESTABLISHED'),
    ('human_acceptance', 'PASS'), ('production_admission', 'ESTABLISHED'),
    ('finite_replacement', 'NOT_ESTABLISHED'), ('scope', 'whole-application'),
])
def test_dispatcher_refuses_native_result_promotion(monkeypatch: pytest.MonkeyPatch,
        field: str, value: str) -> None:
    request, policy, evidence, _ = selected_fixture()
    certificate = native.build_verifier_replacement_certificate(request, evidence, policy=policy)
    honest = native.recheck_verifier_replacement_certificate(certificate, expected_request=request, policy=policy)
    promoted = deepcopy(honest)
    promoted[field] = value
    monkeypatch.setattr(native, 'recheck_verifier_replacement_certificate', lambda *a, **kw: promoted)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        selected_route(certificate, request, policy)


def test_exact_rank10_structural_admission_keeps_historical_parser_and_polish_fences() -> None:
    # Only the rank fence is exercised here; this modified structural request
    # is not presented as a runnable native certificate or complete DAG.
    from test_ten_tier_native_selection import dag_input
    item, bundle, policy, _ = dag_input()
    bundle['nodes'][0]['request']['coordinate'] = native.COORDINATE
    policy['nodes'] = deepcopy(bundle['nodes'])
    subject = {'object_id': item.object_id, 'object_kind': 'VERIFIER', 'record_digest': item.digest}
    with pytest.raises(ValueError, match='PROGRESSION_NATIVE_TEN_TIER_RANK_DIFFERS'):
        tier_progression._graph(bundle, policy, {'security': 6}, subject)
    assert tier_progression._graph(bundle, policy, {'security': 10}, subject) == bundle['nodes']
    with pytest.raises(ValueError):
        ObjectCoordinate.parse(native.COORDINATE)
    with pytest.raises(polish_requirements.RequirementRefusal):
        polish_requirements.registered_objective_binding(native.SEMANTIC_VERSION, native.COORDINATE, 'VERIFIER')


@pytest.mark.parametrize('kind', ['admission', 'authority', 'observer'])
def test_degenerate_selected_public_key_is_refused_before_signature_replay(kind: str) -> None:
    request, policy, _, _ = selected_fixture()
    policy = deepcopy(policy)
    if kind == 'admission':
        policy['admission_public_key'] = '00' * 32
    else:
        selected = policy[kind + '_keys']
        selected[next(iter(selected))] = '00' * 32
    with pytest.raises(ValueError, match='small-order'):
        native.build_verifier_replacement_certificate(request, None, policy=policy)


def test_earlier_invalid_signature_survives_later_unexpected_backend_outage(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from test_verifier_replacement import outcome, repin_evidence
    request, policy, evidence, _ = selected_fixture()
    value = json.loads(evidence)
    value['authority_attestations'][0]['signature'] = '00' * 64
    unavailable_signature = value['authority_attestations'][1]['signature']
    request, evidence = repin_evidence(request, value)
    original = native._verify_signature

    def interrupted(public: str, signature: str, message: bytes) -> None:
        if signature == unavailable_signature:
            raise RuntimeError('later optional backend unavailable')
        original(public, signature, message)

    monkeypatch.setattr(native, '_verify_signature', interrupted)
    result = outcome(request, policy, evidence)
    assert result['status'] == 'FAIL' and result['replay_status'] == 'REPRODUCED'

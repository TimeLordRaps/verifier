"""Explicit native contract selection and historical tier fences.

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object Notation
(JSON). Finite fixtures establish no complete application or production admission.
"""
from copy import deepcopy
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import verifier_composed_security as composed
from verifier.runtime import polish, polish_requirements, tier_progression
from test_current_verifier_composed_security import fixture, selected, digest


def native():
    data = fixture()
    request, policy, evidence = selected(data)
    cert = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    return data, request, policy, cert


def replay(cert, request, policy, **changes):
    selector = dict(semantic_version=composed.SEMANTIC_VERSION,
                    objective=composed.COORDINATE, represented_kind='VERIFIER')
    selector.update(changes)
    return routes.replay_current_object_certificate(cert, expected_request=request,
                                                    policy=policy, **selector)


def test_closed_catalogs_preserve_historical408_and_two_native_predicates():
    old = routes.current_object_route_catalog()
    new = routes.current_ten_tier_route_catalog()
    assert len(old) == 408
    assert {row['semantic_version'] for row in old} == {'verifier-current-object-obligations-1'}
    assert len(new) == 2
    assert {r['objective'] for r in new} == {'VERIFIER-6.1', 'VERIFIER-10.1'}
    assert all(r['semantic_version'] == composed.SEMANTIC_VERSION for r in new)
    assert all(r['represented_kind_rule'] == 'VERIFIER' for r in new)
    assert all(r['object_profile_conformance'] == 'NOT_ESTABLISHED' for r in new)


def test_exact_native_route_preserves_finite_scope_and_no_full_security():
    _, request, policy, cert = native()
    result = replay(cert, request, policy)
    assert result['schema_version'] == 'verifier-current-object-route-replay-2'
    assert result['computational_status'] == 'PASS'
    assert result['replay_status'] == 'REPRODUCED'
    assert result['native_result']['composed_security_admission'] == 'UNKNOWN'
    assert result['native_result']['actual_execution'] == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('changes', [
    {'semantic_version': 'verifier-current-object-obligations-1'},
    {'semantic_version': 'verifier-current-ten-tier-object-obligations-2'},
    {'objective': 'VERIFIER-9.1'}, {'objective': 'VERIFIER-10.1'},
    {'represented_kind': 'HARNESS'},
])
def test_wrong_family_coordinate_kind_never_falls_back(changes):
    _, request, policy, cert = native()
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        replay(cert, request, policy, **changes)


def test_wrong_external_request_family_cannot_be_selected_from_certificate():
    _, request, policy, cert = native()
    request['semantic_version'] = 'verifier-current-object-obligations-1'
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        replay(cert, request, policy)


def test_missing_candidate_evidence_routes_as_unknown():
    _, request, policy, _ = native()
    cert = composed.build_verifier_composed_security_certificate(request, None, policy=policy)
    result = replay(cert, request, policy)
    assert result['computational_status'] == 'UNKNOWN'
    assert result['replay_status'] == 'REPRODUCED'


def test_honest_missing_native_source_never_reproduces_old_pass(monkeypatch):
    _, request, policy, cert = native()
    def missing():
        raise OSError('test missing installed mechanism')
    monkeypatch.setattr(composed, 'mechanism_digest', missing)
    result = replay(cert, request, policy)
    assert result['computational_status'] == 'UNKNOWN'
    assert result['replay_status'] == 'UNAVAILABLE'


def dag_input():
    data, request, policy, cert = native()
    item = NamespaceObject.create(**json.loads(data['association_evidence'])['subject'])
    route = next(r for r in routes.current_ten_tier_route_catalog() if r['objective'] == composed.COORDINATE)
    profile = {'schema_version': dag.PROFILE, 'profile_id': 'selected-ten-tier-native',
               'profile_version': '1', 'object_kind': 'VERIFIER', 'obligations': [{
        'claim_id': 'security', 'semantic_version': composed.SEMANTIC_VERSION,
        'objective': composed.COORDINATE, 'proposition_digest': route['proposition_digest'],
        'scope': route['scope'], 'assumptions': [], 'dependencies': []}]}
    node = {'node_id': 'security', 'object_id': item.object_id, 'claim_id': 'security',
            'certificate_path': 'security.json', 'certificate_digest': digest(cert),
            'request': request, 'checker_policy': policy, 'contract_version': '2',
            'artifact_bindings': [{'path': 'security.json', 'digest': digest(cert)}],
            'facet_bindings': {'payload_digest': digest(item.payload_bytes),
                              'operands_digest': digest(canonical_bytes(item.to_dict()['operands']))}}
    files = {'security.json': cert}
    pin = digest(canonical_bytes(profile))
    bundle = {'schema_version': dag.BUNDLE, 'profiles': [profile],
              'objects': [item.to_dict()], 'nodes': [node], 'edges': []}
    selected_policy = {'schema_version': dag.POLICY, 'approved_profiles': [pin],
        'required_objects': [{'object_id': item.object_id, 'object_kind': 'VERIFIER',
                             'record_digest': item.digest, 'profile_digest': pin}],
        'required_roots': ['security'], 'nodes': deepcopy(bundle['nodes']),
        'artifact_files_digest': dag.artifact_files_digest(files)}
    return item, bundle, selected_policy, files


def test_selected_native_dependency_dag_replays_without_profile_promotion():
    _, bundle, policy, files = dag_input()
    report = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert report['status'] == 'PASS'
    assert report['nodes'][0]['direct_status'] == 'PASS'
    assert report['object_profile_conformance'] == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('field,value', [('subject_id', 'substituted'),
                                       ('object_digest', 'sha256:' + '0' * 64)])
def test_dag_refuses_native_subject_substitution(field, value):
    _, bundle, policy, files = dag_input()
    bundle['nodes'][0]['request'][field] = value
    policy['nodes'] = deepcopy(bundle['nodes'])
    report = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert report['status'] == 'FAIL'


@pytest.mark.parametrize('version', ['1', '2'])
def test_historical_polish_rejects_new_security_before_privacy_interpretation(version):
    from test_polish import fixture as polish_fixture, rebind
    bundle, request = polish_fixture()
    _, selection, policy, cert = native()
    cert_pin = digest(cert)
    bundle['certificates'][cert_pin] = cert.decode()
    request['requirements'][5]['objectives'] = [{
        'semantic_version': composed.SEMANTIC_VERSION, 'coordinate': composed.COORDINATE,
        'request': selection, 'policy': policy, 'certificate_digest': cert_pin}]
    if version == '2':
        from verifier.runtime.polish_capacity import CEILINGS
        request['schema_version'] = 'verifier-polish-request-2'
        request['limits'] = dict(CEILINGS)
        bundle['schema_version'] = 'verifier-polish-bundle-2'
        bundle['evidence_payloads'] = {}
    rebind(bundle, request)
    report = polish.assess_polish(canonical_bytes(bundle),
        request_bytes=canonical_bytes(request), contract_version=version)
    assert report['status'] == 'FAIL'
    assert report['polished'] is False


def test_historical_requirements_metadata_fences_new_semantics():
    with pytest.raises(polish_requirements.RequirementRefusal):
        polish_requirements.registered_objective_binding(composed.SEMANTIC_VERSION,
                                                       composed.COORDINATE, 'VERIFIER')


def test_native_security_cannot_be_assigned_unrelated_progression_rank():
    item, bundle, policy, _ = dag_input()
    subject = {'object_id': item.object_id, 'object_kind': 'VERIFIER', 'record_digest': item.digest}
    with pytest.raises(ValueError, match='PROGRESSION_NATIVE_TEN_TIER_RANK_DIFFERS'):
        tier_progression._graph(bundle, policy, {'security': 7}, subject)
    assert tier_progression._graph(bundle, policy, {'security': 6}, subject) == bundle['nodes']


@pytest.mark.parametrize('field,value', [
    ('replay_status', None), ('replay_status', 'invented'),
    ('object_kind', 'HARNESS'), ('scope', 'whole-application'),
    ('authority', 'ESTABLISHED'), ('actual_execution', 'ESTABLISHED'),
    ('composed_security_admission', 'PASS')])
def test_native_result_boundary_contradictions_are_refused(monkeypatch, field, value):
    _, request, policy, cert = native()
    honest = composed.recheck_verifier_composed_security_certificate(cert, expected_request=request, policy=policy)
    changed = deepcopy(honest)
    if value is None:
        changed.pop(field, None)
    else:
        changed[field] = value
    monkeypatch.setattr(composed, 'recheck_verifier_composed_security_certificate', lambda *a, **kw: changed)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        replay(cert, request, policy)


def test_historical_dag_does_not_load_unselected_native_catalog(monkeypatch):
    from test_certificate_dag_native_subjects import _fixture
    bundle, policy, files = _fixture('verifier')
    def unselected():
        raise AssertionError('unselected native catalog must not run')
    monkeypatch.setattr(routes, 'current_ten_tier_route_catalog', unselected)
    report = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert report['status'] == 'PASS'


def test_selected_native_catalog_loss_stays_local_unknown(monkeypatch):
    _, bundle, policy, files = dag_input()
    def missing():
        raise ImportError('selected native support unavailable')
    monkeypatch.setattr(routes, 'current_ten_tier_route_catalog', missing)
    report = dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert report['status'] == 'UNKNOWN'
    assert report['nodes'][0]['direct_status'] == 'UNKNOWN'


def test_valid_selected_native_loader_outage_is_explicitly_unavailable(monkeypatch):
    def missing():
        raise ImportError('selected native module missing')
    monkeypatch.setattr(routes, '_ten_tier_routes', missing)
    for objective in (composed.COORDINATE, 'VERIFIER-10.1'):
        with pytest.raises(routes.CurrentObjectRouteUnavailable) as unavailable:
            routes.select_current_object_route(semantic_version=composed.SEMANTIC_VERSION,
                objective=objective, represented_kind='VERIFIER')
        assert type(unavailable.value) is routes.CurrentObjectRouteUnavailable
    with pytest.raises(routes.CurrentObjectRouteRefusal) as refusal:
        routes.select_current_object_route(semantic_version=composed.SEMANTIC_VERSION,
            objective='VERIFIER-10.2', represented_kind='VERIFIER')
    assert type(refusal.value) is routes.CurrentObjectRouteRefusal


def test_old_objective_inventory_plan_and_assessment_fence_native_family():
    from test_polish_inventory import fixture as inventory_fixture, request as inventory_request, plan as inventory_plan
    from verifier.runtime import polish_inventory as inventory
    profile, collection, objects = inventory_fixture()
    profile['kinds'][0]['tiers'][5]['objectives'][0]['semantic_version'] = composed.SEMANTIC_VERSION
    selection = inventory_request(profile, collection, objects)
    arguments = {'profile_bytes':canonical_bytes(profile), 'collection_bytes':canonical_bytes(collection),
                 'request_bytes':canonical_bytes(selection)}
    with pytest.raises(ValueError, match='historical nine-tier inventory semantic version differs'):
        inventory.build_objective_inventory_plan(**arguments)
    proposed = inventory_plan(profile, selection)
    report = inventory.assess_objective_inventory(canonical_bytes(proposed), **arguments)
    assert report['status'] == 'FAIL' and report['polished'] is False

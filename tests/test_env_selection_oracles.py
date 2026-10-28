"""Independent retained environment (ENV) selection and value-domain oracles.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count bytes.
These synthetic retained records establish no live execution or authority.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import env_checks, env_executable, env_configuration_surface, typed_facets


def commitment(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def config_selection(surface: dict[str, Any], values: dict[str, Any], *,
                     declared: dict[str, Any] | None = None,
                     limits: dict[str, int] | None = None,
                     child_limits: dict[str, int] | None = None,
                     scope: str = 'retained-process-observations') -> tuple[Any, dict, dict, bytes]:
    module = env_configuration_surface
    subject = NamespaceObject.create('env-oracle', 'ENV', {
        'scope': scope, 'configuration_surface': surface if declared is None else declared,
        'configuration': values,
    })
    collection = composition_digest([subject])
    child_evidence = canonical_bytes({'schema_version': typed_facets.COLLECTION_VERSION,
                                      'objects': [subject.to_dict()]})
    child_policy = typed_facets.typed_facets_policy(trust_roots=['selected-facets-oracle'])
    child_request = typed_facets.typed_facets_request(object_kind='ENV', subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=collection, evidence_ref=commitment(child_evidence),
        policy=child_policy, limits=child_limits)
    child = typed_facets.build_typed_facets_certificate(child_request, child_evidence, policy=child_policy)
    evidence = canonical_bytes({'schema_version': module.EVIDENCE_VERSION,
        'facets_certificate_b64': base64.b64encode(child).decode('ascii')})
    policy = module.env_configuration_surface_policy(trust_roots=['selected-configuration-oracle'])
    request = module.env_configuration_surface_request(subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=collection, evidence_ref=commitment(evidence),
        required_surface=surface, facets_certificate_digest=commitment(child),
        facets_request=child_request, facets_policy=child_policy, policy=policy, limits=limits)
    return module, request, policy, evidence


def executable_selection(*, same_file: bool = False, corrupt_bytes: bool = False,
                         limits: dict[str, int] | None = None,
                         child_limits: dict[str, int] | None = None) -> tuple[Any, dict, dict, bytes]:
    module = env_executable
    content = {'program': b'finite input', 'interpreter': b'finite runtime'}
    files = {name: commitment(raw) for name, raw in content.items()}
    interpreter = 'program' if same_file else 'interpreter'
    artifact = {'scope': 'retained-process-observations', 'files': files,
        'runtime': {'entrypoint': {'path': 'program', 'version': 'label-A'},
                    'interpreter': {'path': interpreter, 'version': 'label-A' if same_file else 'label-B'}}}
    subject = NamespaceObject.create('env-oracle', 'ENV', artifact)
    collection = composition_digest([subject])
    retained = {'files': {name: {'base64': base64.b64encode(raw).decode('ascii'), 'sha256': files[name]}
                          for name, raw in content.items()}}
    if corrupt_bytes:
        retained['files']['interpreter']['base64'] = base64.b64encode(b'changed bytes').decode('ascii')
    child_evidence = canonical_bytes({'schema_version': env_checks.EVIDENCE_VERSION,
        'objects': [subject.to_dict()], 'inputs': retained})
    child_policy = env_checks.env_checks_policy(trust_roots=['selected-inventory-oracle'])
    child_request = env_checks.env_checks_request(check='closure', subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=collection, evidence_ref=commitment(child_evidence),
        policy=child_policy, limits=child_limits)
    child = env_checks.build_env_checks_certificate(child_request, child_evidence, policy=child_policy)
    evidence = canonical_bytes({'schema_version': module.EVIDENCE_VERSION,
        'inventory_certificate_b64': base64.b64encode(child).decode('ascii')})
    policy = module.env_executable_policy(trust_roots=['selected-executable-oracle'])
    request = module.env_executable_request(subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=collection, evidence_ref=commitment(evidence), entrypoint_path='program',
        entrypoint_digest=files['program'], entrypoint_version='label-A', interpreter_path=interpreter,
        interpreter_digest=files[interpreter], interpreter_version='label-A' if same_file else 'label-B',
        inventory_certificate_digest=commitment(child), inventory_request=child_request,
        inventory_policy=child_policy, policy=policy, limits=limits)
    return module, request, policy, evidence


def selection(kind: str) -> tuple[Any, dict, dict, bytes]:
    return executable_selection() if kind == 'executable' else config_selection({'x': {'kind': 'boolean'}}, {'x': True})


def build(module: Any, request: dict, policy: dict, evidence: bytes | None) -> bytes:
    fn = (module.build_env_executable_certificate if module is env_executable
          else module.build_env_configuration_surface_certificate)
    return fn(request, evidence, policy=policy)


def recheck(module: Any, request: dict, policy: dict, certificate: bytes) -> dict:
    fn = (module.recheck_env_executable_certificate if module is env_executable
          else module.recheck_env_configuration_surface_certificate)
    return fn(certificate, expected_request=request, policy=policy)


def outcome(module: Any, request: dict, policy: dict, evidence: bytes | None) -> str:
    return recheck(module, request, policy, build(module, request, policy, evidence))['status']


VALUES = [None, False, True, -1, 0, 1, 2, 0.0, 1.0, 2.0, '', 'a', 'ab', [], [1], {}, {'x': True}]
DOMAINS = [
    ({'kind': 'literal', 'value': True}, {2}),
    ({'kind': 'literal', 'value': 1}, {5}),
    ({'kind': 'enum', 'values': [False, 1]}, {1, 5}),
    ({'kind': 'boolean'}, {1, 2}),
    ({'kind': 'integer', 'minimum': 0, 'maximum': 1}, {4, 5}),
    ({'kind': 'number', 'minimum': 0, 'maximum': 1}, {4, 5, 7, 8}),
    ({'kind': 'string', 'minimum_length': 1, 'maximum_length': 2}, {11, 12}),
    ({'kind': 'array', 'items': {'kind': 'integer', 'minimum': 0, 'maximum': 2},
      'minimum_length': 1, 'maximum_length': 2}, {14}),
    ({'kind': 'record', 'fields': {'x': {'kind': 'boolean'}}}, {16}),
    ({'kind': 'union', 'options': [{'kind': 'literal', 'value': None},
                                  {'kind': 'literal', 'value': ''}]}, {0, 10}),
]


@pytest.mark.parametrize('domain_index', range(len(DOMAINS)))
@pytest.mark.parametrize('value_index', range(len(VALUES)))
def test_finite_domain_truth_table(domain_index: int, value_index: int) -> None:
    domain, admitted_indices = DOMAINS[domain_index]
    selected = config_selection({'x': domain}, {'x': VALUES[value_index]})
    assert outcome(*selected) == ('PASS' if value_index in admitted_indices else 'FAIL')


@pytest.mark.parametrize('values', [{}, {'x': True, 'extra': 1}])
def test_selected_name_set_is_exact(values: dict) -> None:
    assert outcome(*config_selection({'x': {'kind': 'boolean'}}, values)) == 'FAIL'


@pytest.mark.parametrize('actual,expected', [(True, 1), (False, 0), (1, 1.0)])
def test_surface_equality_preserves_json_types(actual: Any, expected: Any) -> None:
    surface = {'x': {'kind': 'literal', 'value': expected}}
    declared = {'x': {'kind': 'literal', 'value': actual}}
    assert outcome(*config_selection(surface, {'x': expected}, declared=declared)) == 'FAIL'


@pytest.mark.parametrize('domain', [
    {'kind': 'enum', 'values': []}, {'kind': 'enum', 'values': [1, 1]},
    {'kind': 'union', 'options': []}, {'kind': 'union', 'options': [{'kind': 'boolean'}, {'kind': 'boolean'}]},
    {'kind': 'integer', 'minimum': True, 'maximum': 2},
    {'kind': 'integer', 'minimum': 0, 'maximum': 2**53},
    {'kind': 'number', 'minimum': 2, 'maximum': 1},
    {'kind': 'string', 'minimum_length': 0, 'maximum_length': False},
    {'kind': 'boolean', 'extra': 1}, {'kind': 'unknown'},
])
def test_malformed_selected_domains_are_refused(domain: dict) -> None:
    with pytest.raises(env_configuration_surface.EnvConfigurationSurfaceError):
        config_selection({'x': domain}, {'x': 1})


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
@pytest.mark.parametrize('field', ['max_operations', 'max_items', 'max_evidence_bytes', 'max_child_certificate_bytes'])
def test_selected_parent_bound_exhaustion_stays_unknown(kind: str, field: str) -> None:
    module, request, policy, evidence = selection(kind)
    request['limits'][field] = 1
    assert outcome(module, request, policy, evidence) == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
def test_selected_child_operation_exhaustion_stays_unknown(kind: str) -> None:
    case = executable_selection(child_limits={'max_operations': 1}) if kind == 'executable' else config_selection(
        {'x': {'kind': 'boolean'}}, {'x': True}, child_limits={'max_operations': 1})
    assert outcome(*case) == 'UNKNOWN'


def test_large_exact_literal_is_charged_to_parent_budget() -> None:
    value = 'x' * 20000
    assert outcome(*config_selection({'x': {'kind': 'literal', 'value': value}}, {'x': value},
                                     limits={'max_operations': 10000})) == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
@pytest.mark.parametrize('field', ['subject_id', 'object_digest', 'collection_digest'])
def test_selected_child_subject_and_collection_cannot_be_substituted(kind: str, field: str) -> None:
    module, request, policy, evidence = selection(kind)
    prefix = 'inventory' if kind == 'executable' else 'facets'
    request[prefix + '_request'][field] = 'different' if field == 'subject_id' else commitment(b'different')
    with pytest.raises(ValueError):
        build(module, request, policy, evidence)


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
def test_missing_parent_and_child_evidence_stay_unknown(kind: str) -> None:
    module, request, policy, evidence = selection(kind)
    assert outcome(module, request, policy, None) == 'UNKNOWN'
    bundle = json.loads(evidence)
    field_name = ('inventory_' if kind == 'executable' else 'facets_') + 'certificate_b64'
    bundle[field_name] = ''
    evidence = canonical_bytes(bundle); request['evidence_ref'] = commitment(evidence)
    assert outcome(module, request, policy, evidence) == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
def test_forged_child_is_refuted_despite_recomputed_commitments(kind: str) -> None:
    module, request, policy, evidence = selection(kind)
    prefix = 'inventory' if kind == 'executable' else 'facets'
    bundle = json.loads(evidence); child = json.loads(base64.b64decode(bundle[prefix + '_certificate_b64']))
    child['result']['evaluation']['reason'] = 'forged replay'
    child.pop('digest'); child['digest'] = commitment(canonical_bytes(child))
    child_bytes = canonical_bytes(child)
    bundle[prefix + '_certificate_b64'] = base64.b64encode(child_bytes).decode('ascii')
    evidence = canonical_bytes(bundle); request['evidence_ref'] = commitment(evidence)
    request[prefix + '_certificate_digest'] = commitment(child_bytes)
    assert outcome(module, request, policy, evidence) == 'FAIL'


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
def test_forged_parent_and_selected_policy_substitution_are_refused(kind: str) -> None:
    module, request, policy, evidence = selection(kind)
    certificate = build(module, request, policy, evidence)
    value = json.loads(certificate); value['result']['status'] = 'FAIL'
    value.pop('digest'); value['digest'] = commitment(canonical_bytes(value))
    with pytest.raises(ValueError):
        recheck(module, request, policy, canonical_bytes(value))
    changed = deepcopy(policy); changed['trust_roots'] = ['other-authority']
    with pytest.raises(ValueError):
        recheck(module, request, changed, certificate)


@pytest.mark.parametrize('role', ['entrypoint', 'interpreter'])
@pytest.mark.parametrize('field,replacement', [('path', 'missing'), ('version', 'other-label'), ('digest', commitment(b'other'))])
def test_executable_selected_coordinates_are_exact(role: str, field: str, replacement: str) -> None:
    module, request, policy, evidence = executable_selection()
    request[role + '_' + field] = replacement
    assert outcome(module, request, policy, evidence) == 'FAIL'


def test_one_file_can_fill_both_roles_only_with_one_selected_label() -> None:
    module, request, policy, evidence = executable_selection(same_file=True)
    assert outcome(module, request, policy, evidence) == 'PASS'
    request['interpreter_version'] = 'other-label'
    with pytest.raises(env_executable.EnvExecutableError):
        build(module, request, policy, evidence)


def test_changed_retained_file_bytes_refute_parent() -> None:
    assert outcome(*executable_selection(corrupt_bytes=True)) == 'FAIL'


def test_unadmitted_observation_scope_stays_unknown() -> None:
    assert outcome(*config_selection({'x': {'kind': 'boolean'}}, {'x': True}, scope='physical-host')) == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['executable', 'configuration'])
def test_native_pass_does_not_establish_whole_tier_or_authority(kind: str) -> None:
    module, request, policy, evidence = selection(kind)
    result = recheck(module, request, policy, build(module, request, policy, evidence))
    assert result['status'] == 'PASS'
    assert result['object_profile_conformance'] == result['facets_profile_conformance'] == result['authority'] == 'NOT_ESTABLISHED'

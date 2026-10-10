"""Independent finite selected-trace oracles for the incoming environment checker.

Verifier Standard (VSTD); verifiable execution environment (ENV); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Rows and operation counts are dimensionless; evidence limits measure bytes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from itertools import permutations, product
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import env_checks, env_pin_closure as pins


def commitment(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


@pytest.fixture(scope='module')
def selected_trace() -> tuple[dict, dict, dict]:
    files = {'root': b'root bytes', 'library': b'library bytes', 'asset': b'asset bytes'}
    inventory = {name: commitment(raw) for name, raw in files.items()}
    subject = NamespaceObject.create('trace-env', 'ENV', {
        'scope': 'retained-process-observations', 'files': inventory,
    })
    child_evidence = canonical_bytes({
        'schema_version': env_checks.EVIDENCE_VERSION,
        'objects': [subject.to_dict()],
        'inputs': {'files': {name: {'base64': base64.b64encode(raw).decode('ascii'),
                                  'sha256': inventory[name]} for name, raw in files.items()}},
    })
    child_policy = env_checks.env_checks_policy(trust_roots=['independent-finite-inventory'])
    child_request = env_checks.env_checks_request(
        check='closure', subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]), evidence_ref=commitment(child_evidence),
        policy=child_policy,
    )
    child = env_checks.build_env_checks_certificate(child_request, child_evidence, policy=child_policy)
    assert env_checks.recheck_env_checks_certificate(child, expected_request=child_request, policy=child_policy)['status'] == 'PASS'
    required = [
        {'id': 'a', 'requester': '@entry', 'specifier': 'root-name', 'target': 'root'},
        {'id': 'b', 'requester': 'root', 'specifier': 'library-name', 'target': 'library'},
        {'id': 'c', 'requester': 'library', 'specifier': 'asset-name', 'target': 'asset'},
    ]
    value = dict(schema_version=pins.EVIDENCE_VERSION,
                 closure_certificate_b64=base64.b64encode(child).decode('ascii'),
                 observations=[dict(id=row['id'], target=row['target'], digest=inventory[row['target']]) for row in required])
    policy = pins.env_pin_closure_policy(trust_roots=['independent-selected-trace'])
    request = pins.env_pin_closure_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]), evidence_ref=commitment(canonical_bytes(value)),
        pins=inventory, required_resolutions=required, closure_certificate_digest=commitment(child),
        closure_request=child_request, closure_policy=child_policy, policy=policy,
    )
    return request, policy, value


def replay(request: dict, policy: dict, value: dict) -> dict:
    selected = deepcopy(request)
    evidence = canonical_bytes(value)
    selected['evidence_ref'] = commitment(evidence)
    certificate = pins.build_env_pin_closure_certificate(selected, evidence, policy=policy)
    return pins.recheck_env_pin_closure_certificate(certificate, expected_request=selected, policy=policy)


@pytest.mark.parametrize('states', list(product(('exact', 'absent', 'wrong-target', 'wrong-digest'), repeat=3)), ids=lambda v: '_'.join(v))
def test_every_available_selected_contradiction_precedes_missing_rows(selected_trace, states: tuple[str, ...]) -> None:
    request, policy, evidence = deepcopy(selected_trace)
    rows = []
    for row, state in zip(evidence['observations'], states):
        if state == 'absent':
            continue
        if state == 'wrong-target':
            row['target'] = 'different-selected-target'
        elif state == 'wrong-digest':
            row['digest'] = commitment(b'wrong retained bytes')
        rows.append(row)
    evidence['observations'] = rows
    # This truth table follows selected row equality, independently of checker order.
    expected = ('FAIL' if any(s.startswith('wrong-') for s in states)
                else 'UNKNOWN' if 'absent' in states else 'PASS')
    assert replay(request, policy, evidence)['status'] == expected


@pytest.mark.parametrize('order', list(permutations(range(3))))
def test_observation_order_preserves_selected_identifier_meaning(selected_trace, order: tuple[int, ...]) -> None:
    request, policy, evidence = deepcopy(selected_trace)
    evidence['observations'] = [evidence['observations'][i] for i in order]
    assert replay(request, policy, evidence)['status'] == 'PASS'


@pytest.mark.parametrize('change', ['specifier', 'requester', 'target', 'pin', 'subject', 'collection', 'child', 'trust-roots'])
def test_old_certificate_cannot_answer_a_different_external_selection(selected_trace, change: str) -> None:
    request, policy, evidence = deepcopy(selected_trace)
    certificate = pins.build_env_pin_closure_certificate(request, canonical_bytes(evidence), policy=policy)
    if change == 'specifier': request['required_resolutions'][1]['specifier'] = 'different-name'
    elif change == 'requester': request['required_resolutions'][1]['requester'] = 'asset'
    elif change == 'target': request['required_resolutions'][1]['target'] = 'asset'
    elif change == 'pin': request['pins']['asset'] = commitment(b'different asset')
    elif change == 'subject': request['subject_id'] = 'another-environment'
    elif change == 'collection': request['collection_digest'] = commitment(b'different collection')
    elif change == 'child': request['closure_certificate_digest'] = commitment(b'different child')
    elif change == 'trust-roots': policy['trust_roots'] = ['different-root']
    with pytest.raises(pins.EnvPinClosureError):
        pins.recheck_env_pin_closure_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize('limit', ['max_evidence_bytes', 'max_child_certificate_bytes', 'max_operations'])
def test_selected_resource_exhaustion_remains_unknown(selected_trace, limit: str) -> None:
    request, policy, evidence = deepcopy(selected_trace)
    if limit == 'max_evidence_bytes': bound = len(canonical_bytes(evidence)) - 1
    elif limit == 'max_child_certificate_bytes': bound = len(base64.b64decode(evidence['closure_certificate_b64'])) - 1
    else: bound = 1
    request['limits'][limit] = bound
    assert replay(request, policy, evidence)['status'] == 'UNKNOWN'

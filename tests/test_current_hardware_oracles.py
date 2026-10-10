"""Independent finite oracles for retained containment and device envelopes.

Verifier Standard (VSTD); graphics processing unit (GPU).
Graph order is dimensionless; observation quantities
are bytes and timestamp translation is in microseconds. These finite cases
do not establish sensor authenticity, physical topology or credit authority.
"""
from __future__ import annotations

from itertools import permutations, product
import pytest
from test_current_hardware_topology import selected as selected_topology
from test_current_hardware_measurements import selected as selected_measurements
from verifier.domains.contracts import hardware_topology, hardware_measurements


@pytest.mark.parametrize('kind', ['topology', 'measurements'])
def test_shared_evidence_replays_hardware_without_polished_promotion(kind: str) -> None:
    import json
    from verifier.core.certificate import canonical_bytes, canonical_digest
    from verifier.runtime.polish import assess_polish
    from test_polish_capacity import version2

    native = hardware_topology if kind == 'topology' else hardware_measurements
    selected = selected_topology if kind == 'topology' else selected_measurements
    request, policy, evidence = selected()
    build = getattr(native, 'build_hardware_' + kind + '_certificate')
    certificate = build(request, evidence, policy=policy)
    certificate_digest = 'sha256:' + canonical_digest(json.loads(certificate))
    bundle = {
        'schema_version': 'verifier-polish-bundle-1',
        'objects': json.loads(evidence)['objects'],
        'certificates': {certificate_digest: certificate.decode()},
    }
    tier = int(native.COORDINATE.split('-')[1].split('.')[0])
    selection = {
        'schema_version': 'verifier-polish-request-1',
        'root_id': request['subject_id'],
        'collection_digest': request['collection_digest'],
        'bundle_digest': 'sha256:' + canonical_digest(bundle),
        'requirements': [
            {'object_id': request['subject_id'], 'tier': i,
             'applicability': 'REQUIRED', 'rationale': 'Selected retained hardware only',
             'objectives': []} for i in range(1, 10)
        ],
    }
    selection['requirements'][tier - 1]['objectives'] = [{
        'semantic_version': native.SEMANTIC_VERSION, 'coordinate': native.COORDINATE,
        'request': request, 'policy': policy, 'certificate_digest': certificate_digest,
    }]
    packed, selected_request = version2(bundle, selection)
    report = assess_polish(canonical_bytes(packed),
                           request_bytes=canonical_bytes(selected_request),
                           contract_version='2')
    assert report['objectives'][0]['status'] == 'PASS'
    assert report['objectives'][0]['public_checkability'] == 'NOT_ESTABLISHED'
    assert report['status'] == 'UNKNOWN' and report['polished'] is False

@pytest.mark.parametrize('mask',range(512))
def test_all_three_vertex_containment_graphs_against_order_witness(mask: int) -> None:
    names=('a','b','c')
    pairs=list(product(names,repeat=2))
    edges=[edge for i,edge in enumerate(pairs) if mask & (1<<i)]
    has_order=any(all(order.index(a)<order.index(b) for a,b in edges) for order in permutations(names))
    expected='PASS' if has_order else 'FAIL'
    devices=[dict(id=n,kind='OTHER',capacities={'COMPUTE_SLOT':1}) for n in names]
    for ordered in (edges,list(reversed(edges))):
        request,policy,evidence=selected_topology(devices=devices,topology=[dict(parent=a,child=b) for a,b in ordered])
        encoded=hardware_topology.build_hardware_topology_certificate(request,evidence,policy=policy)
        result=hardware_topology.recheck_hardware_topology_certificate(encoded,expected_request=request,policy=policy)
        assert result['status']==expected
        assert result['physical_authenticity']==result['live_availability']==result['credit_authority']=='NOT_ESTABLISHED'


@pytest.mark.parametrize('left,right,capacity_a,capacity_b',product((0,2,8,9),(0,2,8,9),(2,8),(2,8)))
def test_independent_device_envelopes_and_permutation_time_translation(
        left: int, right: int, capacity_a: int, capacity_b: int) -> None:
    expected='PASS' if left<=capacity_a and right<=capacity_b else 'FAIL'
    devices=[dict(id='a',kind='GPU',capacities={'MEMORY_BYTE':capacity_a,'COMPUTE_SLOT':1}),dict(id='b',kind='GPU',capacities={'MEMORY_BYTE':capacity_b,'COMPUTE_SLOT':1})]
    for shift,reverse in ((0,False),(1000000,True)):
        samples=[dict(id='sample-'+str(i),device=name,unit='MEMORY_BYTE',quantity=q,at_us=100+shift) for i,(name,q) in enumerate((('a',left),('b',right)))]
        samples.append(dict(id='same-instant',device='a',unit='MEMORY_BYTE',quantity=left,at_us=100+shift))
        if reverse:samples.reverse()
        request,policy,evidence=selected_measurements(measurements=samples,devices=devices)
        encoded=hardware_measurements.build_hardware_measurements_certificate(request,evidence,policy=policy)
        result=hardware_measurements.recheck_hardware_measurements_certificate(encoded,expected_request=request,policy=policy)
        assert result['status']==expected
        assert result['sensor_authenticity']==result['physical_authenticity']==result['credit_authority']=='NOT_ESTABLISHED'

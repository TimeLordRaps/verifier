"""Independent finite tensor-shape oracles for current architecture statics.

ARCH denotes computational model architecture. MATMUL denotes matrix
multiplication and RELU denotes rectified linear unit; only retained shapes
are checked, not tensor values or execution. All dimensions and counts are
dimensionless. Explicit integer boundary cases avoid floating-point rounding.
"""
from __future__ import annotations

import hashlib
from itertools import permutations,product
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject,composition_digest
from verifier.domains.contracts import arch_shapes


def _digest(value: object) -> str:
    return 'sha256:'+hashlib.sha256(canonical_bytes(value)).hexdigest()


def _node(name: str,op: str,inputs: list[str],shape: list[Any]) -> dict[str,Any]:
    return dict(name=name,op=op,inputs=inputs,shape=shape)


def _verdict(nodes: list[dict[str,Any]],outputs: list[str]) -> str:
    graph=dict(nodes=nodes,outputs=outputs)
    subject=NamespaceObject.create('finite-shape-selection','ARCH',dict(
        scope='retained-static-tensor-graph',graph_digest=_digest(graph)))
    evidence=canonical_bytes(dict(schema_version=arch_shapes.EVIDENCE_VERSION,
        objects=[subject.to_dict()],inputs=dict(graph=graph)))
    policy=arch_shapes.arch_shapes_policy(trust_roots=['independent-shape-oracle'])
    request=arch_shapes.arch_shapes_request(subject_id=subject.object_id,object_digest=subject.digest,
        collection_digest=composition_digest([subject]),evidence_ref='sha256:'+hashlib.sha256(evidence).hexdigest(),policy=policy)
    certificate=arch_shapes.build_arch_shapes_certificate(request,evidence,policy=policy)
    result=arch_shapes.recheck_arch_shapes_certificate(certificate,expected_request=request,policy=policy)
    assert result['execution_equivalence']=='NOT_ESTABLISHED'
    assert result['backend_portability']=='NOT_ESTABLISHED'
    return result['status']


@pytest.mark.parametrize('rows,inner_left,inner_right,columns',list(product((1,2,3),repeat=4)))
@pytest.mark.parametrize('output_case',['selected','wrong-rows','wrong-columns','transpose'])
def test_finite_matrix_shape_oracle(rows: int,inner_left: int,inner_right: int,columns: int,output_case: str) -> None:
    expected_shape=[rows,columns]
    selected={'selected':expected_shape,'wrong-rows':[rows+1,columns],
              'wrong-columns':[rows,columns+1],'transpose':[columns,rows]}[output_case]
    nodes=[_node('a','INPUT',[],[rows,inner_left]),_node('b','INPUT',[],[inner_right,columns]),
           _node('out','MATMUL',['a','b'],selected)]
    # The row-column contraction has one product term per shared inner index.
    expected='PASS' if inner_left==inner_right and selected==expected_shape else 'FAIL'
    assert _verdict(nodes,['out'])==expected


SHAPES=([1],[2],[1,1],[1,2],[2,1],[2,2])


@pytest.mark.parametrize('left,right',list(product(SHAPES,repeat=2)))
@pytest.mark.parametrize('output_case',['left','right','different'])
def test_nonbroadcast_addition_shape_oracle(left: list[int],right: list[int],output_case: str) -> None:
    selected={'left':left,'right':right,'different':[9]}[output_case]
    nodes=[_node('a','INPUT',[],left),_node('b','INPUT',[],right),_node('out','ADD',['a','b'],selected)]
    assert _verdict(nodes,['out'])==('PASS' if left==right==selected else 'FAIL')


@pytest.mark.parametrize('incoming',SHAPES)
@pytest.mark.parametrize('output_case',['same','reversed','different'])
def test_rectified_unit_preserves_each_axis(incoming: list[int],output_case: str) -> None:
    selected={'same':incoming,'reversed':list(reversed(incoming)),'different':[9]}[output_case]
    nodes=[_node('a','INPUT',[],incoming),_node('out','RELU',['a'],selected)]
    assert _verdict(nodes,['out'])==('PASS' if incoming==selected else 'FAIL')


@pytest.mark.parametrize('shape,expected',[
    ([1],'PASS'),([2,3,4,5],'PASS'),([2147483647],'PASS'),
    ([2147483647,4194304],'PASS'),([67108864,134217727],'PASS'),
    ([67108864,134217728],'FAIL'),([2147483647,4194305],'FAIL'),
    ([2147483648],'FAIL'),([0],'FAIL'),([-1],'FAIL'),([True],'FAIL'),
    ([1.0],'FAIL'),(['1'],'FAIL'),([None],'FAIL'),([],'FAIL'),([1,1,1,1,1],'FAIL'),
])
def test_explicit_rank_dimension_and_exact_count_boundaries(shape: list[Any],expected: str) -> None:
    assert _verdict([_node('a','INPUT',[],shape)],['a'])==expected


@pytest.mark.parametrize('order',list(permutations(('a','b','out'))))
def test_only_dependency_respecting_permutations_pass(order: tuple[str,...]) -> None:
    nodes={'a':_node('a','INPUT',[],[2,3]),'b':_node('b','INPUT',[],[3,4]),
           'out':_node('out','MATMUL',['a','b'],[2,4])}
    expected='PASS' if order.index('out')>max(order.index('a'),order.index('b')) else 'FAIL'
    assert _verdict([nodes[name] for name in order],['out'])==expected


@pytest.mark.parametrize('shape,operator,expected',[
    ([2,2],'MATMUL','PASS'),([2,3],'MATMUL','FAIL'),
    ([2,3],'ADD','PASS'),([2,3,4],'ADD','PASS'),
])
def test_repeated_selected_operand_is_permitted_when_equation_holds(shape: list[int],operator: str,expected: str) -> None:
    nodes=[_node('a','INPUT',[],shape),_node('out',operator,['a','a'],shape)]
    assert _verdict(nodes,['out'])==expected

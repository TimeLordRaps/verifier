"""Independent finite directed-graph and hostile-selection oracles.

The GRAPH object is a retained collection with selected directed edges. Node
and edge counts are dimensionless. Exhaustive three-node cases exercise a
bounded family, not class-wide soundness or legacy Graph-profile conformance.
"""
from __future__ import annotations
from itertools import permutations, product
from pathlib import Path
import json
from typing import Any
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_statics as graph
from verifier.runtime import polish

NODES=('a','b','c')
EDGES=tuple(product(NODES,repeat=2))

def selected(mask: int = 2, **limits: int) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    edges=[{'source':a,'target':b} for bit,(a,b) in enumerate(EDGES) if mask & (1<<bit)]
    nodes=list(NODES)
    members=[NamespaceObject.create(n,'ENV',{}) for n in NODES]
    subject=NamespaceObject.create('graph','GRAPH',{'element_kind':'ENV','scope':'retained_directed_graph',
        'nodes_digest':digest(nodes),'edges_digest':digest(edges)},{'members':nodes})
    objects=[*members,subject]
    evidence=canonical_bytes({'schema_version':graph.EVIDENCE_VERSION,'objects':[o.to_dict() for o in objects],
        'inputs':{'nodes':nodes,'edges':edges}})
    policy=graph.graph_statics_policy(trust_roots=['independently-selected-graph'])
    request=graph.graph_statics_request(subject_id=subject.object_id,object_digest=subject.digest,
        collection_digest=composition_digest(objects),nodes_digest=digest(nodes),edges_digest=digest(edges),
        evidence_ref=digest(json.loads(evidence)),policy=policy,limits=limits or None)
    return request,policy,evidence

@pytest.mark.parametrize('mask',range(512))
def test_every_three_node_directed_graph_matches_permutation_oracle(mask: int) -> None:
    # Exhaust all six possible vertex orderings. No adjacency traversal, indegree
    # or shared production algorithm is used by this finite oracle.
    edges=[edge for bit,edge in enumerate(EDGES) if mask & (1<<bit)]
    acyclic=any(all(order.index(a)<order.index(b) for a,b in edges) for order in permutations(NODES))
    request,policy,evidence=selected(mask)
    certificate=graph.build_graph_statics_certificate(request,evidence,policy=policy)
    result=graph.recheck_graph_statics_certificate(certificate,expected_request=request,policy=policy)
    assert result['status']==('PASS' if acyclic else 'FAIL')
    assert result['object_profile_conformance']=='NOT_ESTABLISHED'

class Foreign:
    def __eq__(self, other: object) -> bool:raise AssertionError('foreign equality invoked')
    def __ne__(self, other: object) -> bool:raise AssertionError('foreign inequality invoked')
    def __str__(self) -> str:raise AssertionError('foreign conversion invoked')

@pytest.mark.parametrize('field',('schema_version','semantic_version','coordinate','proposition_digest',
    'object_kind','subject_id','object_digest','collection_digest','nodes_digest','edges_digest','evidence_ref','policy_digest','limits'))
def test_foreign_request_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected(); request[field]=Foreign()
    monkeypatch.setattr(graph,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(graph.GraphStaticsError):graph.build_graph_statics_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('field',('schema_version','mechanism_id','mechanism_digest','trust_roots','max_certificate_bytes'))
def test_foreign_policy_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected(); policy[field]=Foreign()
    monkeypatch.setattr(graph,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(graph.GraphStaticsError):graph.build_graph_statics_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('relative',('domains/contracts/graph_statics.py','standard/CURRENT_GRAPH_STATICS.md'))
def test_changed_native_dependency_changes_polish_digest(relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    original=Path.read_bytes; target=Path(polish.__file__).parents[1]/relative
    before=polish.mechanism_digest()
    def changed(path: Path) -> bytes:
        raw=original(path)
        return raw+b'\nchanged dependency\n' if path==target else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    assert polish.mechanism_digest()!=before

def test_known_acyclic_graph_is_unknown_when_selected_budget_is_exhausted() -> None:
    request,policy,evidence=selected(max_operations=1)
    certificate=graph.build_graph_statics_certificate(request,evidence,policy=policy)
    assert graph.recheck_graph_statics_certificate(certificate,expected_request=request,policy=policy)['status']=='UNKNOWN'

def test_rehashed_cycle_result_cannot_claim_pass() -> None:
    request,policy,evidence=selected(1)
    certificate=graph.build_graph_statics_certificate(request,evidence,policy=policy)
    forged=json.loads(certificate); assert forged['result']['status']=='FAIL'
    forged['result']['status']='PASS';forged.pop('digest');forged['digest']=digest(forged)
    with pytest.raises(graph.GraphStaticsError):graph.recheck_graph_statics_certificate(canonical_bytes(forged),expected_request=request,policy=policy)

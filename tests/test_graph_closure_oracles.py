"""Independent finite reachability-closure and hostile-selection oracles.

Node, edge and closure-pair counts are dimensionless. Exhaustive three-node
cases and one seeded twenty-node family exercise bounded cases, not class-wide
soundness, lineage truth or legacy Graph-profile conformance.
"""
from __future__ import annotations
import base64
from itertools import permutations, product
import hashlib
import json
from typing import Any
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_closure as closure_module
from verifier.domains.contracts import graph_statics as statics

NODES=('a','b','c')
EDGES=tuple(product(NODES,repeat=2))

def warshall(nodes: tuple[str, ...], pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
    # Boolean-matrix closure; no adjacency list, queue or production traversal.
    size=len(nodes); where={n:i for i,n in enumerate(nodes)}
    reach=[[False]*size for _ in range(size)]
    for a,b in pairs: reach[where[a]][where[b]]=True
    for k in range(size):
        for i in range(size):
            for j in range(size): reach[i][j]=reach[i][j] or (reach[i][k] and reach[k][j])
    return [{'node':n,'reachable':[m for m in nodes if reach[where[n]][where[m]]]} for n in nodes]

def selected(pairs: list[tuple[str, str]], nodes: tuple[str, ...] = NODES,
             declared: list[dict[str, Any]] | None = None, **limits: int):
    edges=[{'source':a,'target':b} for a,b in sorted(pairs)]
    names=list(nodes)
    members=[NamespaceObject.create(n,'ENV',{}) for n in nodes]
    subject=NamespaceObject.create('graph','GRAPH',{'element_kind':'ENV','scope':'retained_directed_graph',
        'nodes_digest':digest(names),'edges_digest':digest(edges)},{'members':names})
    objects=[*members,subject]
    child_evidence=canonical_bytes({'schema_version':statics.EVIDENCE_VERSION,'objects':[o.to_dict() for o in objects],
        'inputs':{'nodes':names,'edges':edges}})
    child_policy=statics.graph_statics_policy(trust_roots=['independently-selected-graph'])
    child_request=statics.graph_statics_request(subject_id='graph',object_digest=subject.digest,
        collection_digest=composition_digest(objects),nodes_digest=digest(names),edges_digest=digest(edges),
        evidence_ref=digest(json.loads(child_evidence)),policy=child_policy)
    child=statics.build_graph_statics_certificate(child_request,child_evidence,policy=child_policy)
    rows=warshall(nodes,pairs) if declared is None else declared
    evidence=canonical_bytes({'schema_version':closure_module.EVIDENCE_VERSION,'child_request':child_request,
        'child_policy':child_policy,'child_certificate':base64.b64encode(child).decode('ascii'),'closure':rows})
    policy=closure_module.graph_closure_policy(trust_roots=['independently-selected-closure'])
    request=closure_module.graph_closure_request(subject_id='graph',object_digest=subject.digest,
        collection_digest=composition_digest(objects),child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),child_certificate_digest='sha256:'+hashlib.sha256(child).hexdigest(),
        closure_digest=digest(rows),evidence_ref=digest(json.loads(evidence)),policy=policy,limits=limits or None)
    return request,policy,evidence

def status(request: dict[str, Any], policy: dict[str, Any], evidence: bytes) -> str:
    certificate=closure_module.build_graph_closure_certificate(request,evidence,policy=policy)
    result=closure_module.recheck_graph_closure_certificate(certificate,expected_request=request,policy=policy)
    assert result['legacy_graph_profile_conformance']=='NOT_ESTABLISHED'
    return result['status']

def flipped(rows: list[dict[str, Any]], mask: int) -> list[dict[str, Any]]:
    # Toggle one deterministic (source, target) pair so the declaration is wrong.
    source,target=EDGES[mask%len(EDGES)]
    out=[dict(row,reachable=list(row['reachable'])) for row in rows]
    row=next(r for r in out if r['node']==source)
    row['reachable']=sorted(set(row['reachable'])^{target})
    return out

@pytest.mark.parametrize('mask',range(512))
def test_every_three_node_graph_matches_independent_warshall_closure(mask: int) -> None:
    pairs=[edge for bit,edge in enumerate(EDGES) if mask & (1<<bit)]
    acyclic=any(all(order.index(a)<order.index(b) for a,b in pairs) for order in permutations(NODES))
    request,policy,evidence=selected(pairs)
    assert status(request,policy,evidence)==('PASS' if acyclic else 'FAIL')
    wrong=flipped(warshall(NODES,pairs),mask)
    request,policy,evidence=selected(pairs,declared=wrong)
    assert status(request,policy,evidence)=='FAIL'

def seeded_dag(size: int, seed: int) -> tuple[tuple[str, ...], list[tuple[str, str]]]:
    # Forward edges in a fixed order are acyclic by construction.
    nodes=tuple(f'n{i:02d}' for i in range(size)); state=seed; pairs=[]
    for i in range(size):
        for j in range(i+1,size):
            state=(state*1103515245+12345)%(2**31)
            if state%5==0: pairs.append((nodes[i],nodes[j]))
    return nodes,pairs

@pytest.mark.parametrize('seed',(1,7,42))
def test_seeded_twenty_node_dags_match_warshall_including_long_paths(seed: int) -> None:
    nodes,pairs=seeded_dag(20,seed)
    rows=warshall(nodes,pairs)
    assert sum(len(r['reachable']) for r in rows)>len(pairs)
    request,policy,evidence=selected(pairs,nodes)
    assert status(request,policy,evidence)=='PASS'
    last=max((r for r in rows if r['reachable']),key=lambda r:len(r['reachable']))
    omitted=[dict(r,reachable=r['reachable'][:-1]) if r is last else r for r in rows]
    request,policy,evidence=selected(pairs,nodes,declared=omitted)
    assert status(request,policy,evidence)=='FAIL'

class Foreign:
    def __eq__(self, other: object) -> bool:raise AssertionError('foreign equality invoked')
    def __ne__(self, other: object) -> bool:raise AssertionError('foreign inequality invoked')
    def __str__(self) -> str:raise AssertionError('foreign conversion invoked')

@pytest.mark.parametrize('field',('schema_version','semantic_version','coordinate','proposition_digest',
    'object_kind','subject_id','object_digest','collection_digest','child_request_digest','child_policy_digest',
    'child_certificate_digest','closure_digest','evidence_ref','policy_digest','limits'))
def test_foreign_request_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected([('a','b')]); request[field]=Foreign()
    monkeypatch.setattr(closure_module,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(closure_module.GraphClosureError):
        closure_module.build_graph_closure_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('field',('schema_version','mechanism_id','mechanism_digest','trust_roots','max_certificate_bytes'))
def test_foreign_policy_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected([('a','b')]); policy[field]=Foreign()
    monkeypatch.setattr(closure_module,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(closure_module.GraphClosureError):
        closure_module.build_graph_closure_certificate(request,evidence,policy=policy)

def test_known_closure_is_unknown_when_selected_budget_is_exhausted() -> None:
    request,policy,evidence=selected([('a','b'),('b','c')],max_operations=1)
    assert status(request,policy,evidence)=='UNKNOWN'

def test_rehashed_refuted_closure_cannot_claim_pass() -> None:
    request,policy,evidence=selected([('a','b'),('b','c')],declared=warshall(NODES,[('a','b')]))
    certificate=closure_module.build_graph_closure_certificate(request,evidence,policy=policy)
    forged=json.loads(certificate); assert forged['result']['status']=='FAIL'
    forged['result']['status']='PASS';forged.pop('digest');forged['digest']=digest(forged)
    with pytest.raises(closure_module.GraphClosureError):
        closure_module.recheck_graph_closure_certificate(canonical_bytes(forged),expected_request=request,policy=policy)

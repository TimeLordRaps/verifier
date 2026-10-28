"""Independent least-topological-order and hostile-selection oracles.

Node, edge and order-position counts are dimensionless. Exhaustive three-node
certificates, exhaustive four-node order comparisons and seeded twenty-node
families exercise bounded cases, not class-wide soundness, temporal or lineage
truth, or legacy Graph-profile conformance.
"""
from __future__ import annotations
import base64
from collections import deque
from itertools import permutations, product
import hashlib
import json
from typing import Any
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_order as order_module
from verifier.domains.contracts import graph_statics as statics

NODES=('a','b','c')
EDGES=tuple(product(NODES,repeat=2))

def topological(order: tuple[str, ...] | list[str], pairs: list[tuple[str, str]]) -> bool:
    where={n:i for i,n in enumerate(order)}
    return all(where[a]<where[b] for a,b in pairs)

def least_by_enumeration(nodes: tuple[str, ...], pairs: list[tuple[str, str]]) -> list[str] | None:
    # permutations() of a sorted tuple runs in lexicographic order, so the
    # first topological one is the least. No heap, indegree count or queue.
    for order in permutations(sorted(nodes)):
        if topological(order,pairs): return list(order)
    return None

def least_by_scanning(nodes: tuple[str, ...], pairs: list[tuple[str, str]]) -> list[str] | None:
    # Place the first sorted remaining node whose predecessors are all placed.
    placed: list[str]=[]; remaining=sorted(nodes)
    while remaining:
        ready=[n for n in remaining if all(a in placed for a,b in pairs if b==n)]
        if not ready: return None
        placed.append(ready[0]); remaining.remove(ready[0])
    return placed

def queue_order(nodes: tuple[str, ...], pairs: list[tuple[str, str]]) -> list[str]:
    # The first-in first-out order the GRAPH-3.1 child itself uses for acyclicity.
    indegree={n:0 for n in nodes}
    for _,b in pairs: indegree[b]+=1
    ready=deque(n for n in nodes if indegree[n]==0); out=[]
    while ready:
        node=ready.popleft(); out.append(node)
        for a,b in sorted(pairs):
            if a==node:
                indegree[b]-=1
                if indegree[b]==0: ready.append(b)
    return out

def child(pairs: list[tuple[str, str]], nodes: tuple[str, ...] = NODES):
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
    certificate=statics.build_graph_statics_certificate(child_request,child_evidence,policy=child_policy)
    return subject,objects,child_request,child_policy,certificate

def selected(selected_child, declared: list[str], **limits: int):
    subject,objects,child_request,child_policy,certificate=selected_child
    evidence=canonical_bytes({'schema_version':order_module.EVIDENCE_VERSION,'child_request':child_request,
        'child_policy':child_policy,'child_certificate':base64.b64encode(certificate).decode('ascii'),'order':declared})
    policy=order_module.graph_order_policy(trust_roots=['independently-selected-order'])
    request=order_module.graph_order_request(subject_id='graph',object_digest=subject.digest,
        collection_digest=composition_digest(objects),child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),child_certificate_digest='sha256:'+hashlib.sha256(certificate).hexdigest(),
        order_digest=digest(declared),evidence_ref=digest(json.loads(evidence)),policy=policy,limits=limits or None)
    return request,policy,evidence

def status(request: dict[str, Any], policy: dict[str, Any], evidence: bytes) -> str:
    certificate=order_module.build_graph_order_certificate(request,evidence,policy=policy)
    result=order_module.recheck_graph_order_certificate(certificate,expected_request=request,policy=policy)
    assert result['legacy_graph_profile_conformance']=='NOT_ESTABLISHED'
    return result['status']

@pytest.mark.parametrize('mask',range(512))
def test_every_three_node_graph_and_order_matches_independent_enumeration(mask: int) -> None:
    pairs=[edge for bit,edge in enumerate(EDGES) if mask & (1<<bit)]
    least=least_by_enumeration(NODES,pairs)
    assert least==least_by_scanning(NODES,pairs)
    selected_child=child(pairs)
    child_status=json.loads(selected_child[4])['result']['status']
    assert child_status==('FAIL' if least is None else 'PASS')
    for order in permutations(NODES):
        expected='PASS' if least is not None and list(order)==least else 'FAIL'
        assert status(*selected(selected_child,list(order)))==expected,(pairs,order)

def test_valid_non_least_orders_pass_the_child_but_fail_the_parent() -> None:
    # Every acyclic three-node graph with two or more topological orders.
    controls=0
    for mask in range(512):
        pairs=[edge for bit,edge in enumerate(EDGES) if mask & (1<<bit)]
        least=least_by_enumeration(NODES,pairs)
        valid=[list(o) for o in permutations(NODES) if topological(o,pairs)]
        if least is None or len(valid)<2: continue
        selected_child=child(pairs)
        assert json.loads(selected_child[4])['result']['status']=='PASS'
        for order in valid:
            if order!=least:
                controls+=1
                assert status(*selected(selected_child,order))=='FAIL',(pairs,order)
    assert controls>0

def test_every_four_node_graph_least_order_matches_enumeration() -> None:
    # All 4096 graphs on four nodes without self-loops, checked below certificates.
    nodes=('a','b','c','d')
    off_diagonal=[(x,y) for x in nodes for y in nodes if x!=y]
    acyclic=0
    for mask in range(1<<len(off_diagonal)):
        pairs=[edge for bit,edge in enumerate(off_diagonal) if mask & (1<<bit)]
        least=least_by_enumeration(nodes,pairs)
        edges=[{'source':a,'target':b} for a,b in sorted(pairs)]
        budget=order_module.common_module.Budget(10**6)
        if least is None:
            with pytest.raises(order_module.Refuted):
                order_module._least_order(list(nodes),edges,budget)
        else:
            acyclic+=1
            assert order_module._least_order(list(nodes),edges,budget)==least,mask
            assert least==least_by_scanning(nodes,pairs),mask
    assert acyclic==543  # labelled acyclic digraphs on four nodes (OEIS A003024)

@pytest.mark.parametrize('mask',range(0,1<<12,97))
def test_sampled_four_node_certificates_refuse_the_next_valid_order(mask: int) -> None:
    nodes=('a','b','c','d')
    off_diagonal=[(x,y) for x in nodes for y in nodes if x!=y]
    pairs=[edge for bit,edge in enumerate(off_diagonal) if mask & (1<<bit)]
    least=least_by_enumeration(nodes,pairs)
    selected_child=child(pairs,nodes)
    if least is None:
        assert status(*selected(selected_child,list(nodes)))=='FAIL'
        return
    assert status(*selected(selected_child,least))=='PASS'
    later=[list(o) for o in permutations(nodes) if topological(o,pairs) and list(o)>least]
    for order in later[:1]:
        assert status(*selected(selected_child,order))=='FAIL'

def seeded_dag(size: int, seed: int) -> tuple[tuple[str, ...], list[tuple[str, str]]]:
    # Forward edges along a seeded shuffle are acyclic but not name-ordered.
    nodes=tuple(f'n{i:02d}' for i in range(size)); state=seed; shuffled=list(nodes)
    for i in range(size-1,0,-1):
        state=(state*1103515245+12345)%(2**31); j=state%(i+1)
        shuffled[i],shuffled[j]=shuffled[j],shuffled[i]
    pairs=[]
    for i in range(size):
        for j in range(i+1,size):
            state=(state*1103515245+12345)%(2**31)
            if state%5==0: pairs.append((shuffled[i],shuffled[j]))
    return nodes,pairs

@pytest.mark.parametrize('seed',(1,7,42))
def test_seeded_twenty_node_dags_match_scanning_oracle_and_refuse_near_misses(seed: int) -> None:
    nodes,pairs=seeded_dag(20,seed)
    least=least_by_scanning(nodes,pairs)
    assert least is not None and least!=sorted(nodes)
    selected_child=child(pairs,nodes)
    assert status(*selected(selected_child,least))=='PASS'
    # An adjacent swap with no edge between the two is still topological.
    swaps=[least[:i]+[least[i+1],least[i]]+least[i+2:] for i in range(len(least)-1)
           if (least[i],least[i+1]) not in pairs]
    assert swaps and all(topological(order,pairs) for order in swaps)
    assert status(*selected(selected_child,swaps[0]))=='FAIL'
    assert status(*selected(selected_child,sorted(nodes)))=='FAIL'
    fifo=queue_order(nodes,pairs)
    assert topological(fifo,pairs)
    assert status(*selected(selected_child,fifo))==('PASS' if fifo==least else 'FAIL')

def test_identifier_order_is_code_point_order_not_numeric_or_case_folded() -> None:
    # 'B' < 'a' and 'n10' < 'n9' under code points; no edges, so the least order is sorted().
    nodes=tuple(sorted(('a','B','n9','n10')))
    assert nodes==('B','a','n10','n9')
    selected_child=child([],nodes)
    assert status(*selected(selected_child,list(nodes)))=='PASS'
    for wrong in (['a','B','n10','n9'],['B','a','n9','n10']):
        assert status(*selected(selected_child,wrong))=='FAIL'

class Foreign:
    def __eq__(self, other: object) -> bool:raise AssertionError('foreign equality invoked')
    def __ne__(self, other: object) -> bool:raise AssertionError('foreign inequality invoked')
    def __str__(self) -> str:raise AssertionError('foreign conversion invoked')

@pytest.mark.parametrize('field',('schema_version','semantic_version','coordinate','proposition_digest',
    'object_kind','subject_id','object_digest','collection_digest','child_request_digest','child_policy_digest',
    'child_certificate_digest','order_digest','evidence_ref','policy_digest','limits'))
def test_foreign_request_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected(child([('a','b')]),['a','b','c']); request[field]=Foreign()
    monkeypatch.setattr(order_module,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(order_module.GraphOrderError):
        order_module.build_graph_order_certificate(request,evidence,policy=policy)

@pytest.mark.parametrize('field',('schema_version','mechanism_id','mechanism_digest','trust_roots','max_certificate_bytes'))
def test_foreign_policy_fields_refuse_before_evaluation(field: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request,policy,evidence=selected(child([('a','b')]),['a','b','c']); policy[field]=Foreign()
    monkeypatch.setattr(order_module,'_evaluate',lambda *args:pytest.fail('evaluation before admission'))
    with pytest.raises(order_module.GraphOrderError):
        order_module.build_graph_order_certificate(request,evidence,policy=policy)

def test_least_order_is_unknown_when_selected_budget_is_exhausted() -> None:
    selected_child=child([('a','b'),('b','c')])
    assert status(*selected(selected_child,['a','b','c'],max_operations=1))=='UNKNOWN'

def test_rehashed_refuted_order_cannot_claim_pass() -> None:
    request,policy,evidence=selected(child([('b','a')]),['a','b','c'])
    certificate=order_module.build_graph_order_certificate(request,evidence,policy=policy)
    forged=json.loads(certificate); assert forged['result']['status']=='FAIL'
    forged['result']['status']='PASS';forged.pop('digest');forged['digest']=digest(forged)
    with pytest.raises(order_module.GraphOrderError):
        order_module.recheck_graph_order_certificate(canonical_bytes(forged),expected_request=request,policy=policy)

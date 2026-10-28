"""Selected dataset integrity and lineage (DATA) and GRAPH obligation controls.

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; commitments bind bytes.
Finite native replay does not supply application completeness or safety.
"""
from __future__ import annotations
import base64
from copy import deepcopy
import json
from pathlib import Path
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import certificate_dag as dag, facet_coverage as coverage
from verifier.domains.contracts import data_checks, graph_statics, graph_closure, graph_lineage
from current_token_dependency_fixture import obligation, node, facet
from test_current_data_checks import specimen
from test_current_graph_closure import reference_closure

PROPERTIES = {'selected_retained_data_inventory':'DATA-1.2',
              'selected_retained_data_lineage':'DATA-2.1',
              'selected_retained_graph_statics':'GRAPH-3.1',
              'selected_retained_graph_closure':'GRAPH-4.1',
              'selected_direct_operand_content_lineage':'GRAPH-9.2'}

def fixture(*, false_edge: bool = False, unsupported: bool = False) -> tuple:
    artifact, retained = specimen()
    if unsupported: artifact['transforms'][0]['operation']='future-transform'
    dataset=NamespaceObject.create('d0','DATA',artifact)
    other=NamespaceObject.create('d1','DATA',{})
    names=['d0','d1'];edges=[{'source':'d0','target':'d1'}] if false_edge else []
    graph=NamespaceObject.create('g','GRAPH',{'element_kind':'DATA','scope':'retained_directed_graph',
        'nodes_digest':digest(names),'edges_digest':digest(edges)},{'members':names})
    objects=[dataset,other,graph];collection=composition_digest(objects);files={};nodes=[];native={}
    for item in objects: nodes.append(facet(item,'representation',files))
    data_evidence=canonical_bytes({'schema_version':data_checks.EVIDENCE_VERSION,
        'objects':[o.to_dict() for o in objects],'inputs':retained})
    for check in ('inventory','lineage'):
        policy=data_checks.data_checks_policy(trust_roots=['test:data-selection'])
        request=data_checks.data_checks_request(check=check,subject_id='d0',object_digest=dataset.digest,
            collection_digest=collection,evidence_ref=digest(json.loads(data_evidence)),policy=policy)
        raw=data_checks.build_data_checks_certificate(request,data_evidence,policy=policy)
        nodes.append(node(dataset,check,request,policy,raw,files));native[check]=(request,policy,raw)
    evidence=canonical_bytes({'schema_version':graph_statics.EVIDENCE_VERSION,
        'objects':[o.to_dict() for o in objects],'inputs':{'nodes':names,'edges':edges}})
    policy=graph_statics.graph_statics_policy(trust_roots=['test:child-A'])
    request=graph_statics.graph_statics_request(subject_id='g',object_digest=graph.digest,
        collection_digest=collection,nodes_digest=digest(names),edges_digest=digest(edges),
        evidence_ref=digest(json.loads(evidence)),policy=policy)
    child=graph_statics.build_graph_statics_certificate(request,evidence,policy=policy)
    nodes.append(node(graph,'statics',request,policy,child,files));native['statics']=(request,policy,child)
    closure=reference_closure(names,edges)
    envelope={'schema_version':graph_closure.EVIDENCE_VERSION,'child_request':request,
        'child_policy':policy,'child_certificate':base64.b64encode(child).decode('ascii'),'closure':closure}
    closure_policy=graph_closure.graph_closure_policy(trust_roots=['test:closure'])
    closure_request=graph_closure.graph_closure_request(subject_id='g',object_digest=graph.digest,
        collection_digest=collection,child_request_digest=digest(request),child_policy_digest=digest(policy),
        child_certificate_digest=dag._digest(child),closure_digest=digest(closure),evidence_ref=digest(envelope),policy=closure_policy)
    raw=graph_closure.build_graph_closure_certificate(closure_request,canonical_bytes(envelope),policy=closure_policy)
    nodes.append(node(graph,'closure',closure_request,closure_policy,raw,files));native['closure']=(closure_request,closure_policy,raw)
    index={o.object_id:o for o in objects}
    contents=[{**e,'source_digest':index[e['source']].digest,'target_digest':index[e['target']].digest} for e in edges]
    envelope={'schema_version':graph_lineage.EVIDENCE_VERSION,'objects':[o.to_dict() for o in objects],
        'inputs':{'nodes':names,'edges':edges},'edge_contents':contents,'child_certificate':base64.b64encode(child).decode('ascii')}
    lineage_policy=graph_lineage.graph_lineage_policy(trust_roots=['test:lineage'])
    lineage_request=graph_lineage.graph_lineage_request(subject_id='g',object_digest=graph.digest,
        collection_digest=collection,nodes_digest=digest(names),edges_digest=digest(edges),
        edge_contents_digest=digest(contents),evidence_ref=digest(envelope),child_request=request,child_policy=policy,
        child_certificate_digest=dag._digest(child),policy=lineage_policy)
    raw=graph_lineage.build_graph_lineage_certificate(lineage_request,canonical_bytes(envelope),policy=lineage_policy)
    nodes.append(node(graph,'content',lineage_request,lineage_policy,raw,files));native['content']=(lineage_request,lineage_policy,raw)
    dep={'claim_id':'statics','operand_role':None,'object_kind':'GRAPH','profile_digest':None}
    profiles=[];selections=[]
    for item in objects:
        claims=[obligation('representation','OBJECT-1.1')]
        if item.object_id=='d0': claims.extend([obligation('inventory','DATA-1.2'),obligation('lineage','DATA-2.1')])
        if item.object_id=='g': claims.extend([obligation('statics','GRAPH-3.1'),obligation('closure','GRAPH-4.1',[dep]),obligation('content','GRAPH-9.2',[dep])])
        profile={'schema_version':dag.PROFILE,'profile_id':'test:'+item.object_id,'profile_version':'1',
            'object_kind':item.kind.value,'obligations':claims}
        profiles.append(profile);selections.append({'object_id':item.object_id,'object_kind':item.kind.value,
            'record_digest':item.digest,'profile_digest':dag._digest(canonical_bytes(profile))})
    bundle={'schema_version':dag.BUNDLE,'profiles':profiles,'objects':[o.to_dict() for o in objects],
        'nodes':nodes,'edges':[{'node_id':'g:'+c,'prerequisite_id':'g:statics','operand_role':None} for c in ('closure','content')]}
    selection={'schema_version':dag.POLICY,'approved_profiles':[s['profile_digest'] for s in selections],
        'required_objects':selections,'required_roots':[n['node_id'] for n in nodes],
        'nodes':deepcopy(nodes),'artifact_files_digest':dag.artifact_files_digest(files)}
    return objects,bundle,selection,files,native,evidence

def assess(bundle: dict,selection: dict,files: dict) -> dict:
    return dag.assess_certificate_dependencies(canonical_bytes(bundle),expected_policy_bytes=canonical_bytes(selection),artifact_files=files)

def mapping(objects: list[NamespaceObject]) -> tuple[dict, dict, dict]:
    inventory=coverage.namespace_facet_inventory(objects)
    spec={'schema_version':coverage.SPECIFICATION,'specification_id':'test:finite-data-graph','specification_version':'1',
        'facets':[{'facet_id':f['facet_id'],'properties':['canonical_namespace_record']} for f in inventory['facets']],'interactions':[]}
    for f,row in zip(inventory['facets'],spec['facets']):
        if f['object_id']=='d0' and f['path']==['payload','shards']:row['properties'].append('selected_retained_data_inventory')
        if f['object_id']=='d0' and f['path']==['payload','transforms']:row['properties'].append('selected_retained_data_lineage')
        if f['object_id']=='g' and f['path']==['payload','edges_digest']:row['properties'].extend(list(PROPERTIES)[2:])
    rules=coverage.installed_facet_derivation_rules()
    policy={'schema_version':coverage.POLICY,'inventory_digest':dag._digest(canonical_bytes(inventory)),
        'specification_digest':dag._digest(canonical_bytes(spec)),'rule_set_digest':dag._digest(canonical_bytes(rules)),
        'approved_rule_digests':[r['rule_digest'] for r in rules['rules']]}
    return inventory,spec,policy

def complete(objects: list[NamespaceObject],bundle: dict,selection: dict,files: dict) -> dict:
    inventory,spec,policy=mapping(objects)
    return coverage.assess_facet_completeness(canonical_bytes(inventory),canonical_bytes(spec),
        expected_policy_bytes=canonical_bytes(policy),bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(selection),artifact_files=files)

def target_statuses(result: dict) -> dict:
    ids={o['obligation_id']:o['objective'] for o in result['manifest']['obligations'] if o['objective'] in PROPERTIES.values()}
    return {ids[o['obligation_id']]:o for o in result['obligations'] if o['obligation_id'] in ids}

def test_five_authored_rules_exist_with_shared_statics_output() -> None:
    rules=coverage.installed_facet_derivation_rules()
    selected=[r for r in rules['rules'] if r['property_id'] in PROPERTIES]
    assert {r['property_id'] for r in selected}==set(PROPERTIES)
    outputs=[o for r in selected for o in r['outputs'] if o['objective']=='GRAPH-3.1']
    assert len(outputs)==3 and outputs[0]==outputs[1]==outputs[2]
    assert rules['complete_applicability_profiles']==0
    assert not next(r for r in selected if r['property_id']=='selected_retained_data_lineage')['prerequisites']

@pytest.mark.parametrize('parent',['closure','content'])
@pytest.mark.parametrize('variation',['policy','request'])
def test_different_valid_child_cannot_discharge_selected_parent(parent: str, variation: str) -> None:
    _,bundle,selection,files,native,evidence=fixture()
    assert assess(bundle,selection,files)['status']=='PASS'
    request_a,policy_a,raw_a=native['statics']
    policy_b=graph_statics.graph_statics_policy(trust_roots=['test:child-B']) if variation=='policy' else policy_a
    request_b=graph_statics.graph_statics_request(subject_id=request_a['subject_id'],object_digest=request_a['object_digest'],
        collection_digest=request_a['collection_digest'],nodes_digest=request_a['nodes_digest'],edges_digest=request_a['edges_digest'],
        evidence_ref=request_a['evidence_ref'],policy=policy_b,
        limits={'max_operations':request_a['limits']['max_operations']-1} if variation=='request' else None)
    raw_b=graph_statics.build_graph_statics_certificate(request_b,evidence,policy=policy_b)
    for request,policy,raw in [(request_a,policy_a,raw_a),(request_b,policy_b,raw_b)]:
        assert graph_statics.recheck_graph_statics_certificate(raw,expected_request=request,policy=policy)['status']=='PASS'
    assert raw_a!=raw_b
    if variation=='request':assert policy_a==policy_b and request_a!=request_b
    graph=NamespaceObject.create(**bundle['objects'][-1])
    replacement=node(graph,'statics',request_b,policy_b,raw_b,files)
    bundle['nodes']=[replacement if n['claim_id']=='statics' else n for n in bundle['nodes']]
    selection['nodes']=deepcopy(bundle['nodes']);selection['artifact_files_digest']=dag.artifact_files_digest(files)
    result=assess(bundle,selection,files)
    observed=next(n for n in result['nodes'] if n['node_id']=='g:'+parent)
    assert observed['direct_status']=='PASS'
    assert observed['qualified_status']=='FAIL',result
    assert observed['reason']=='CHILD_CERTIFICATE_SELECTION_MISMATCH'

def test_selected_native_predicates_pass_without_completeness_promotion() -> None:
    objects,bundle,selection,files,native,_=fixture()
    result=complete(objects,bundle,selection,files);statuses=target_statuses(result)
    assert set(statuses)==set(PROPERTIES.values())
    assert all(s['direct_status']==s['completion_status']=='PASS' for s in statuses.values())
    assert result['status']=='UNKNOWN' and result['qualification']=='NOT_ESTABLISHED'
    graph_children=[o for o in result['manifest']['obligations'] if o['objective']=='GRAPH-3.1']
    assert len(graph_children)==1 and len(graph_children[0]['origins'])==3
    assert len(result['manifest']['edges'])==2
    assert result['manifest']['denominators']['complete_applicable_obligations'] is None
    assert native['content'][0]['child_certificate_digest']==native['closure'][0]['child_certificate_digest']==dag._digest(native['statics'][2])
    assert objects[0].to_dict()['operands']=={} and objects[0].to_dict()['payload']['transforms']

def test_data_transform_relations_do_not_create_namespace_edges() -> None:
    objects,bundle,selection,files,_,_=fixture(false_edge=True)
    statuses=target_statuses(complete(objects,bundle,selection,files))
    for c in ('DATA-1.2','DATA-2.1','GRAPH-3.1','GRAPH-4.1'):assert statuses[c]['completion_status']=='PASS'
    assert statuses['GRAPH-9.2']['completion_status']=='FAIL'

def test_unsupported_data_transform_preserves_unknown_despite_graph_passes() -> None:
    objects,bundle,selection,files,_,_=fixture(unsupported=True)
    result=complete(objects,bundle,selection,files);statuses=target_statuses(result)
    assert statuses['DATA-2.1']['completion_status']=='UNKNOWN'
    assert all(statuses[c]['completion_status']=='PASS' for c in ('DATA-1.2','GRAPH-3.1','GRAPH-4.1','GRAPH-9.2'))
    assert result['status']=='UNKNOWN'

def test_missing_external_child_blocks_completion_despite_native_parent_pass() -> None:
    objects,bundle,selection,files,_,_=fixture()
    bundle['nodes']=[n for n in bundle['nodes'] if n['claim_id']!='statics'];bundle['edges']=[]
    selection['nodes']=deepcopy(bundle['nodes']);selection['required_roots']=[n['node_id'] for n in bundle['nodes']]
    statuses=target_statuses(complete(objects,bundle,selection,files))
    for c in ('GRAPH-4.1','GRAPH-9.2'):
        assert statuses[c]['direct_status']=='PASS' and statuses[c]['completion_status']=='UNKNOWN'

@pytest.mark.parametrize('variation',['policy','request'])
def test_derived_graph_child_selection_survives_omitted_profile_edges(variation: str) -> None:
    objects,bundle,selection,files,native,evidence=fixture()
    for profile in bundle['profiles']:
        if profile['object_kind']=='GRAPH':
            for claim in profile['obligations']:claim['dependencies']=[]
            pin=dag._digest(canonical_bytes(profile))
            next(s for s in selection['required_objects'] if s['object_id']=='g')['profile_digest']=pin
    selection['approved_profiles']=[s['profile_digest'] for s in selection['required_objects']]
    bundle['edges']=[]
    # Historical standalone partial profiles remain valid; authored derivation
    # independently requires correlation even when that profile omits the edge.
    assert assess(bundle,selection,files)['status']=='PASS'
    request_a=native['statics'][0]
    policy_b=graph_statics.graph_statics_policy(trust_roots=['test:child-B']) if variation=='policy' else native['statics'][1]
    request_b=graph_statics.graph_statics_request(subject_id='g',object_digest=objects[-1].digest,
        collection_digest=request_a['collection_digest'],nodes_digest=request_a['nodes_digest'],
        edges_digest=request_a['edges_digest'],evidence_ref=request_a['evidence_ref'],policy=policy_b,
        limits={'max_operations':request_a['limits']['max_operations']-1} if variation=='request' else None)
    raw_b=graph_statics.build_graph_statics_certificate(request_b,evidence,policy=policy_b)
    assert graph_statics.recheck_graph_statics_certificate(raw_b,expected_request=request_b,policy=policy_b)['status']=='PASS'
    replacement=node(objects[-1],'statics',request_b,policy_b,raw_b,files)
    bundle['nodes']=[replacement if n['claim_id']=='statics' else n for n in bundle['nodes']]
    selection['nodes']=deepcopy(bundle['nodes']);selection['artifact_files_digest']=dag.artifact_files_digest(files)
    assert assess(bundle,selection,files)['status']=='PASS'
    result=complete(objects,bundle,selection,files)
    statuses=target_statuses(result)
    for coordinate in ('GRAPH-4.1','GRAPH-9.2'):
        assert statuses[coordinate]['direct_status']=='PASS'
        assert statuses[coordinate]['completion_status']=='FAIL',statuses

@pytest.mark.parametrize('mutation',['rule-pin','unapproved','origin','missing-path'])
def test_rule_policy_and_origin_controls_preserve_partial_scope(mutation: str) -> None:
    objects,_,_,_,_,_=fixture();inventory,spec,policy=mapping(objects)
    if mutation=='rule-pin':policy['rule_set_digest']='sha256:'+'0'*64
    elif mutation=='unapproved':policy['approved_rule_digests']=[]
    elif mutation=='origin':
        for row in spec['facets']:
            if 'selected_retained_data_lineage' in row['properties']:row['properties'].remove('selected_retained_data_lineage')
        spec['facets'][0]['properties'].append('selected_retained_data_lineage')
    else:
        payload=objects[0].to_dict()['payload'];payload.pop('transforms')
        objects[0]=NamespaceObject.create('d0','DATA',payload);inventory,spec,policy=mapping(objects)
        anchor=next(f for f in inventory['facets'] if f['object_id']=='d0' and f['path']==['payload','shards'])
        next(r for r in spec['facets'] if r['facet_id']==anchor['facet_id'])['properties'].append('selected_retained_data_lineage')
    policy['specification_digest']=dag._digest(canonical_bytes(spec))
    result=coverage.derive_facet_obligations(canonical_bytes(inventory),canonical_bytes(spec),expected_policy_bytes=canonical_bytes(policy))
    assert result['status']=='FAIL' if mutation=='rule-pin' else result['derivation_status']=='UNKNOWN'
    if mutation in ('origin','missing-path'):assert not any(o['objective']=='DATA-2.1' for o in result['obligations'])

@pytest.mark.parametrize('relative',['domains/data.py','domains/contracts/graph_statics.py','domains/contracts/certificate_dag.py'])
def test_changed_native_source_invalidates_selected_rules(relative: str,monkeypatch: pytest.MonkeyPatch) -> None:
    objects,_,_,_,_,_=fixture();inventory,spec,policy=mapping(objects)
    target=Path(coverage.__file__).parents[2]/relative;original=Path.read_bytes
    def changed(path: Path) -> bytes:
        raw=original(path);return raw+b'changed-source' if path==target else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    result=coverage.derive_facet_obligations(canonical_bytes(inventory),canonical_bytes(spec),expected_policy_bytes=canonical_bytes(policy))
    assert result['status']=='FAIL'
    assert result['diagnostics'][0]['code']=='FACET_SPECIFICATION_OR_BINDING_REJECTED'

@pytest.mark.parametrize('mutation',['scope','origin'])
def test_graph_scope_and_exact_array_origin_are_required(mutation: str) -> None:
    objects,_,_,_,_,_=fixture()
    if mutation=='scope':
        payload=objects[-1].to_dict()['payload'];payload['scope']='unsupported-graph-scope'
        objects[-1]=NamespaceObject.create('g','GRAPH',payload,{'members':['d0','d1']})
    inventory,spec,policy=mapping(objects)
    if mutation=='origin':
        for row in spec['facets']:row['properties']=[p for p in row['properties'] if p not in list(PROPERTIES)[2:]]
        anchor=next(f for f in inventory['facets'] if f['object_id']=='g' and f['path']==['payload','nodes_digest'])
        next(r for r in spec['facets'] if r['facet_id']==anchor['facet_id'])['properties'].extend(list(PROPERTIES)[2:])
    policy['specification_digest']=dag._digest(canonical_bytes(spec))
    result=coverage.derive_facet_obligations(canonical_bytes(inventory),canonical_bytes(spec),expected_policy_bytes=canonical_bytes(policy))
    assert result['derivation_status']=='UNKNOWN'
    assert not any(o['objective'].startswith('GRAPH-') for o in result['obligations'])
    assert any(d['code']=='DATA_GRAPH_SCOPED_PROPERTY_BINDING_UNSUPPORTED' for d in result['diagnostics'])

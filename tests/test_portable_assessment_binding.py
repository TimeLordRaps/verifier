"""Portable unknown reports must retain their independently selected scope.

Secure Hash Algorithm 256-bit (SHA-256); directed acyclic graph (DAG).
Fixtures prove finite byte binding only, not application acceptance.
"""
from copy import deepcopy
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.runtime import application_release as app, tier_progression as gate
from test_application_release import fixture, inputs, assess, repin

def profile():
    return {'schema_version':gate.SELECTION,'semantic_version':gate.PROFILE,'profile_id':'selected',
        'subject':{'object_id':'selected-verifier','object_kind':'VERIFIER','record_digest':'sha256:'+'a'*64},
        'target_tier':1,'bundle_digest':'sha256:'+'b'*64,'policy_digest':'sha256:'+'c'*64,
        'artifact_files_digest':'sha256:'+'d'*64,'ranks':[{'node_id':'required','tier':1}],
        'tiers':[{'tier':n,'census':'COMPLETE' if n==1 else 'UNKNOWN',
            'required_nodes':['required'] if n==1 else []} for n in range(1,11)]}

def progression(value, **changes):
    raw=canonical_bytes(value)
    options={'bundle_bytes':None,'expected_policy_bytes':None,'artifact_files':{},
        'expected_selection_digest':gate.digest(raw),'expected_mechanism_digest':gate.mechanism_digest()}
    options.update(changes)
    return gate.assess_tier_progression(raw,**options)

def test_application_assessment_cannot_be_reused_after_selected_artifact_path_changes():
    first=fixture()
    old=assess(first)
    changed=deepcopy(first)
    changed['files']['different-source.zip']=changed['files'].pop('src.zip')
    changed['selection']['source_archive_path']='different-source.zip'
    repin(changed)
    fresh=assess(changed)
    assert old['status']==fresh['status']=='UNKNOWN'
    assert old['binding_status']==fresh['binding_status']=='PASS'
    assert app.recheck_application_release(canonical_bytes(old),canonical_bytes(changed['selection']),**inputs(changed))['status']=='FAIL'
    assert old['assessment_digest']!=fresh['assessment_digest']

@pytest.mark.parametrize('change',[{'profile_id':'other'},{'target_tier':2},
    {'subject':{'object_id':'another-verifier','object_kind':'VERIFIER','record_digest':'sha256:'+'e'*64}}])
def test_progression_missing_native_inputs_remains_bound_to_exact_selection(change):
    first=profile(); changed={**first,**change}
    old,fresh=progression(first),progression(changed)
    assert old['status']==fresh['status']=='UNKNOWN'
    assert old['assessment_digest']!=fresh['assessment_digest']
    assert fresh['selection_digest']==gate.digest(canonical_bytes(changed))
    assert fresh['subject']==changed['subject']

@pytest.mark.parametrize('engine',['application','progression'])
def test_different_wrong_external_selection_pins_do_not_collapse(engine):
    a,b='sha256:'+'1'*64,'sha256:'+'2'*64
    if engine=='application':
        data=fixture(); one,two=assess(data,expected_selection_digest=a),assess(data,expected_selection_digest=b)
    else:
        data=profile(); one,two=progression(data,expected_selection_digest=a),progression(data,expected_selection_digest=b)
    assert one['status']==two['status']=='FAIL'
    assert one['assessment_digest']!=two['assessment_digest']
    assert one['expected_selection_digest']==a and two['expected_selection_digest']==b

@pytest.mark.parametrize('engine',['application','progression'])
def test_absent_external_pins_remain_null_and_do_not_admit_scope(engine):
    if engine=='application':
        data=fixture(); result=assess(data,expected_selection_digest=None,expected_mechanism_digest=None)
        assert result['root']==data['selection']['root']
    else:
        data=profile(); result=progression(data,expected_selection_digest=None,expected_mechanism_digest=None)
        assert result['subject']==data['subject']
    assert result['status']=='UNKNOWN'
    assert result['expected_selection_digest'] is result['expected_mechanism_digest'] is None

def test_old_application_assessment_family_is_not_silently_upgraded():
    data=fixture(); fresh=assess(data)
    assert fresh['schema_version']=='verifier-application-release-assessment-2'
    old={**fresh,'schema_version':'verifier-application-release-assessment-1'}
    old.pop('assessment_digest'); old['assessment_digest']=app.digest(canonical_bytes(old))
    assert app.recheck_application_release(canonical_bytes(old),canonical_bytes(data['selection']),**inputs(data))['status']=='FAIL'

def test_native_outage_retains_application_selection_and_root(monkeypatch):
    data=fixture()
    def unavailable(*args,**kwargs): raise OSError('selected native replay unavailable')
    monkeypatch.setattr(gate,'assess_tier_progression',unavailable)
    result=assess(data)
    assert result['status']=='UNKNOWN' and result['native_status']=='UNKNOWN'
    assert result['root']==data['selection']['root']
    assert result['selection_digest']==app.digest(canonical_bytes(data['selection']))
    assert result['expected_mechanism_digest']==app.mechanism_digest()

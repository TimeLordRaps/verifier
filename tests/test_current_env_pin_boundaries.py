"""Independent specification negatives for retained environment child and pin binding."""
from copy import deepcopy
import base64
import json
import pytest
from verifier.core.certificate import canonical_bytes
from test_current_env_pin_closure import selected, digest

@pytest.mark.parametrize('change,expected', [
    ('unchanged','PASS'),('absent-observations','UNKNOWN'),
    ('pins-and-observation-substituted','FAIL'),('nontext-target','FAIL'),
    ('nontext-digest','FAIL'),('wrong-row-container','FAIL'),
    ('nontext-child','FAIL'),('malformed-child-base64','FAIL'),
    ('noncanonical-child-base64','FAIL'),('wrong-child-bytes','FAIL'),
    ('wrong-parent-version','FAIL'),('noncanonical-parent','FAIL'),
])
def test_selected_environment_boundaries(change,expected):
    module,request,policy,evidence=selected()
    request=deepcopy(request); retained=json.loads(evidence)
    if change=='absent-observations':retained['observations']=None
    elif change=='pins-and-observation-substituted':
        # Keep the parent internally consistent while contradicting actual
        # rehashed child inventory. Parent self-consistency cannot supply PASS.
        request['pins']['library.py']=digest(b'substituted library')
        retained['observations'][1]['digest']=request['pins']['library.py']
    elif change=='nontext-target':retained['observations'][0]['target']=1
    elif change=='nontext-digest':retained['observations'][0]['digest']=False
    elif change=='wrong-row-container':retained['observations']={}
    elif change=='nontext-child':retained['closure_certificate_b64']=True
    elif change=='malformed-child-base64':retained['closure_certificate_b64']='not base64!'
    elif change=='noncanonical-child-base64':retained['closure_certificate_b64']+='='
    elif change=='wrong-child-bytes':
        raw=base64.b64decode(retained['closure_certificate_b64'])
        retained['closure_certificate_b64']=base64.b64encode(raw+b' ').decode()
    elif change=='wrong-parent-version':retained['schema_version']='substituted-version'
    evidence=canonical_bytes(retained)
    if change=='noncanonical-parent':evidence=json.dumps(retained,indent=2).encode()
    request['evidence_ref']=digest(evidence)
    certificate=module.build_env_pin_closure_certificate(request,evidence,policy=policy)
    result=module.recheck_env_pin_closure_certificate(certificate,expected_request=request,policy=policy)
    assert result['status']==expected
    assert result['live_resolution_completeness']=='NOT_ESTABLISHED'

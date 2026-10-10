"""Public regressions for retained verifier declarations versus executed evidence."""
import pytest
from test_verifier_domain import _sample_verifier_bundle
from verifier.domains.common import digest
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate

@pytest.mark.parametrize('mutation,coordinate', [
    ('bootstrap', 'VERIFIER-1.5'), ('identity', 'VERIFIER-1.5'),
    ('witness', 'VERIFIER-1.2'), ('limit', 'VERIFIER-1.2'),
    ('software', 'VERIFIER-1.3'), ('measurements', 'VERIFIER-1.4'),
])
def test_caller_declarations_never_establish_execution(mutation, coordinate):
    artifact, inputs = _sample_verifier_bundle()
    if mutation == 'bootstrap':
        inputs['bootstrap_receipt'] = {'status': 'PASS'}
        artifact['bootstrap_digest'] = digest(inputs['bootstrap_receipt'])
    if mutation == 'identity':
        inputs['self_attestation']['attested_verifier_id'] = 'unrelated-verifier'
        artifact['self_attestation_digest'] = digest(inputs['self_attestation'])
    if mutation in ('witness', 'limit'):
        inputs['soundness_claims'] = [{'class':'cnf_sat', 'boundary_limit': 1000000 if mutation == 'limit' else 500,
                                     'refutation_witness':'this is not a proof'}]
    if mutation == 'software':
        for run in inputs['runs']:
            run['software_digest'] = 'sha256:' + '0' * 64
        artifact['runs_digest'] = digest(inputs['runs'])
    if mutation == 'measurements':
        inputs['measurements'] = [{'memory_bytes':0, 'wall_seconds':0, 'loop_iterations':0}]
    evidence = {'schema_version':'verifier-domain-evidence-1', 'domain':'VERIFIER',
                'subject_id':'prover:sat-smt', 'artifact':artifact, 'inputs':inputs}
    policy = domain_policy(trust_roots=['test:bounded-evidence'])
    request = domain_request(evidence)
    certificate = build_domain_certificate(request, evidence, policy=policy)
    for result in (certificate['result'], recheck_domain_certificate(certificate, expected_request=request, policy=policy)):
        assert result['checks'][coordinate]['evaluation']['outcome'] != 'PASS'
        assert result['object_profile_conformance'] == 'NOT_ESTABLISHED'

from copy import deepcopy
from verifier.core.certificate import (
    CertificateHeader, ClaimBinding, ClaimCoordinate, ClauseGrounding, CostTier,
    DecisionBlock, DecisionCertificate, EncodingRule, GroundedFact, Grounding,
    PropagationStep, ResourceBounds, UnitPropagationProof, VariableGrounding, Verdict,
)
from verifier.core.kernel import check as kernel_check, reference_descriptor


def native_bundle(*, refutation=False):
    """Independently construct a one-variable model or contradictory-clause proof."""
    artifact, inputs = _sample_verifier_bundle()
    descriptor = reference_descriptor()
    binding = ClaimBinding('retained Boolean formula instance', ClaimCoordinate('formula:one', 'satisfiable'),
                           'policy:retained-rules', 'evidence:retained-facts', descriptor,
                           ResourceBounds(1000, 1000, 10000))
    formula = ((1,), (-1,)) if refutation else ((1,),)
    rules = [EncodingRule('positive', ('x',), ((1, 'x'),))]
    clauses = [ClauseGrounding(0, 'positive', {'x':1}, {'x':'fact:one'})]
    if refutation:
        rules.append(EncodingRule('negative', ('x',), ((-1, 'x'),)))
        clauses.append(ClauseGrounding(1, 'negative', {'x':1}, {'x':'fact:one'}))
    grounding = Grounding((VariableGrounding(1, GroundedFact('fact:one', 'retained', 'true')),), tuple(clauses), tuple(rules))
    decision = DecisionBlock(propagation=UnitPropagationProof((PropagationStep(0, 1),), 1)) if refutation else DecisionBlock(model={1:True})
    cert = DecisionCertificate(CertificateHeader(Verdict.FAIL if refutation else Verdict.PASS, CostTier.UP,
                                                1, len(formula), len(formula), int(refutation), binding.digest()),
                               formula, grounding, decision)
    inputs['toolchain'] = descriptor.to_dict()
    artifact.update(verifier_id='prover:sat-smt', toolchain_digest=digest(inputs['toolchain']),
                    proposition_classes=['cnf_sat'], refutation_boundaries={'cnf_sat':{'max_vars':1, 'max_clauses':2, 'max_steps':1}})
    inputs['soundness_claims'] = [{'class':'cnf_sat','boundary_limit':1,
        'refutation_witness':{'binding':binding.to_dict(),'certificate':cert.to_dict()}}]
    artifact['soundness_claims_digest'] = digest(inputs['soundness_claims'])
    replay = kernel_check(cert, binding=binding, budget=1000)
    assert replay.accepted
    output = [{'certificate_digest':digest(cert.to_dict()), 'binding_digest':digest(binding.to_dict()), 'result':replay.to_dict()}]
    for run in inputs['runs']:
        run.update(input_digest=digest(inputs['soundness_claims']), software_digest=artifact['toolchain_digest'], output_digest=digest(output))
    artifact['runs_digest'] = digest(inputs['runs'])
    inputs['self_attestation']['toolchain_digest'] = artifact['toolchain_digest']
    artifact['self_attestation_digest'] = digest(inputs['self_attestation'])
    return artifact, inputs


def public_result(artifact, inputs, depth=5, **policy_kwargs):
    evidence = {'schema_version':'verifier-domain-evidence-1','domain':'VERIFIER',
                'subject_id':'prover:sat-smt','artifact':artifact,'inputs':inputs}
    policy = domain_policy(trust_roots=['test:bounded-evidence'], **policy_kwargs)
    request = domain_request(evidence, target_depth=depth)
    cert = build_domain_certificate(request, evidence, policy=policy)
    checked = recheck_domain_certificate(cert, expected_request=request, policy=policy)
    assert checked == cert['result']
    return checked


@pytest.mark.parametrize('refutation', [False, True])
def test_retained_native_proof_and_local_replay_are_reachable(refutation):
    artifact, inputs = native_bundle(refutation=refutation)
    result = public_result(artifact, inputs, 3)
    assert result['status'] == 'PASS'
    assert result['domain_depth'] == 3
    proof = result['checks']['VERIFIER-1.2']['evaluation']['observations']
    assert proof['proof_instances_checked'] == 1
    assert proof['class_wide_soundness'] == 'NOT_ESTABLISHED'
    replay = result['checks']['VERIFIER-1.3']['evaluation']['observations']
    assert replay['local_kernel_replays'] == 2
    assert replay['producer_execution'] == 'NOT_ESTABLISHED'
    result = public_result(artifact, inputs)
    assert result['status'] == 'UNKNOWN'
    assert result['domain_depth'] == 3
    for key in ('VERIFIER-1.4','VERIFIER-1.5'):
        assert result['checks'][key]['evaluation']['outcome'] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['model','binding','proof_digest','software','input','output','variable_limit','identity','zero_budget','boolean_bound','extra_binding'])
def test_native_bound_evidence_rejects_mutations(mutation):
    artifact, inputs = native_bundle()
    witness = inputs['soundness_claims'][0]['refutation_witness']
    if mutation == 'model':
        witness['certificate']['decision']['model']['1'] = False
    elif mutation == 'binding':
        witness['binding']['claim'] = 'unrelated claim'
    elif mutation == 'proof_digest':
        artifact['soundness_claims_digest'] = 'sha256:' + '0' * 64
    elif mutation in ('software','input','output'):
        for run in inputs['runs']:
            run[mutation + '_digest'] = 'sha256:' + '0' * 64
        artifact['runs_digest'] = digest(inputs['runs'])
    elif mutation == 'variable_limit':
        inputs['soundness_claims'][0]['boundary_limit'] = 2
    elif mutation == 'identity':
        inputs['self_attestation']['attested_verifier_id'] = 'unrelated'
        artifact['self_attestation_digest'] = digest(inputs['self_attestation'])
    elif mutation == 'zero_budget':
        witness['binding']['bounds']['memory_bound'] = 0
    elif mutation == 'boolean_bound':
        witness['binding']['bounds']['memory_bound'] = True
    elif mutation == 'extra_binding':
        witness['binding']['extra'] = 'ignored?'
    if mutation != 'proof_digest':
        artifact['soundness_claims_digest'] = digest(inputs['soundness_claims'])
    result = public_result(artifact, inputs)
    assert result['status'] == 'FAIL'


def test_proof_replay_budget_exhaustion_is_unknown():
    artifact, inputs = native_bundle()
    result = public_result(artifact, inputs, 3, max_operations=1)
    assert result['status'] == 'UNKNOWN'
    assert result['domain_depth'] == 0


@pytest.mark.parametrize('nested', [None, [], 3])
def test_malformed_bootstrap_result_is_rejected_without_crashing(nested):
    artifact, inputs = native_bundle()
    inputs['bootstrap_receipt'] = {'result':nested}
    artifact['bootstrap_digest'] = digest(inputs['bootstrap_receipt'])
    result = public_result(artifact, inputs)
    assert result['checks']['VERIFIER-1.5']['evaluation']['outcome'] == 'FAIL'


@pytest.mark.parametrize('field,value', [('max_vars', '1'), ('max_vars', True), ('max_clauses',0)])
def test_invalid_boundary_types_are_refuted(field, value):
    artifact, inputs = native_bundle()
    artifact['refutation_boundaries']['cnf_sat'][field] = value
    result = public_result(artifact, inputs, 2)
    assert result['checks']['VERIFIER-1.2']['evaluation']['outcome'] == 'FAIL'


def test_rebound_invalid_refutation_is_rejected_by_kernel():
    artifact, inputs = native_bundle(refutation=True)
    inputs['soundness_claims'][0]['refutation_witness']['certificate']['decision']['propagation']['steps'][0]['forced'] = -1
    artifact['soundness_claims_digest'] = digest(inputs['soundness_claims'])
    result = public_result(artifact, inputs, 2)
    row = result['checks']['VERIFIER-1.2']['evaluation']
    assert row['outcome'] == 'FAIL'
    assert 'retained proof rejected' in row['details']


def test_plain_proof_string_with_bound_digest_is_unknown():
    artifact, inputs = native_bundle()
    inputs['soundness_claims'][0]['refutation_witness'] = 'a convincing-looking proof'
    artifact['soundness_claims_digest'] = digest(inputs['soundness_claims'])
    result = public_result(artifact, inputs, 2)
    row = result['checks']['VERIFIER-1.2']['evaluation']
    assert row['outcome'] == 'UNKNOWN'
    assert 'proof text' in row['details']

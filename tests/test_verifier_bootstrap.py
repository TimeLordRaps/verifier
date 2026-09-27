"""Independent finite bootstrap probes for Verifier Standard (VSTD).

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
Keys are generated only inside tests; no signer identity or production authority
is asserted. conjunctive normal form (CNF) is a conjunction of Boolean clauses.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest
pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: bootstrap signatures require the seal extra")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from test_verifier_grounding import native_bundle
from verifier.core.certificate import canonical_bytes
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
from verifier.domains.common import digest
import verifier.domains.verifier as native


def signed_bundle(*, refutation: bool = False) -> tuple[dict, dict, dict]:
    artifact, inputs = native_bundle(refutation=refutation)
    key = Ed25519PrivateKey.generate()
    oracle_path = Path(native.__file__).with_name('verifier_bootstrap.py')
    oracle_digest = 'sha256:' + hashlib.sha256(oracle_path.read_bytes() if oracle_path.exists() else b'absent').hexdigest()
    payload = {'schema_version': 'verifier-native-bootstrap-1', 'status': 'PASS',
               'verifier_id': artifact['verifier_id'], 'toolchain_digest': artifact['toolchain_digest'],
               'soundness_claims_digest': artifact['soundness_claims_digest'],
               'oracle_digest': oracle_digest, 'key_id': 'test:bootstrap-root'}
    inputs['bootstrap_receipt'] = dict(payload, signature=key.sign(canonical_bytes(payload)).hex())
    artifact['bootstrap_digest'] = digest(inputs['bootstrap_receipt'])
    keys = {'test:bootstrap-root': key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
    return artifact, inputs, keys


def assessment(artifact: dict, inputs: dict, keys: dict) -> dict:
    evidence = {'schema_version': 'verifier-domain-evidence-1', 'domain': 'VERIFIER',
                'subject_id': artifact['verifier_id'], 'artifact': artifact, 'inputs': inputs}
    policy = domain_policy(trust_roots=['test:externally-selected-bootstrap-key'], witness_keys=keys)
    return build_domain_certificate(domain_request(evidence), evidence, policy=policy)['result']


@pytest.mark.parametrize('refutation', [False, True])
def test_admitted_bootstrap_recomputes_finite_formula_with_distinct_algorithm(refutation: bool) -> None:
    artifact, inputs, keys = signed_bundle(refutation=refutation)
    result = assessment(artifact, inputs, keys)
    row = result['checks']['VERIFIER-1.5']['evaluation']
    assert row['outcome'] == 'PASS'
    assert row['observations']['algorithm'] == 'exhaustive-truth-table-1'
    assert row['observations']['general_verifier_soundness'] == 'NOT_ESTABLISHED'
    # Bootstrap admission cannot supply the separately absent resource mechanism.
    assert result['status'] == 'UNKNOWN'
    assert result['checks']['VERIFIER-1.5']['established'] is False


def test_bootstrap_key_must_be_selected_outside_the_evidence() -> None:
    artifact, inputs, keys = signed_bundle()
    assert assessment(artifact, inputs, {})['checks']['VERIFIER-1.5']['evaluation']['outcome'] == 'UNKNOWN'


@pytest.mark.parametrize('field', ['signature', 'verifier_id', 'toolchain_digest', 'soundness_claims_digest', 'oracle_digest', 'key_id'])
def test_rehashed_bootstrap_substitution_never_passes(field: str) -> None:
    artifact, inputs, keys = signed_bundle()
    inputs['bootstrap_receipt'][field] = '00' * 64 if field == 'signature' else 'substituted'
    artifact['bootstrap_digest'] = digest(inputs['bootstrap_receipt'])
    assert assessment(artifact, inputs, keys)['checks']['VERIFIER-1.5']['evaluation']['outcome'] != 'PASS'


def test_independent_algorithm_detects_a_false_native_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    artifact, inputs, keys = signed_bundle()
    inputs['soundness_claims'][0]['refutation_witness']['certificate']['header']['verdict'] = 'FAIL'
    # Admission precedes checking, so sign this deliberately false proposition.
    key = Ed25519PrivateKey.generate()
    keys['test:bootstrap-root'] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    artifact['soundness_claims_digest'] = digest(inputs['soundness_claims'])
    payload = inputs['bootstrap_receipt']; payload.pop('signature')
    payload['soundness_claims_digest'] = artifact['soundness_claims_digest']
    payload['signature'] = key.sign(canonical_bytes(payload)).hex()
    artifact['bootstrap_digest'] = digest(payload)
    monkeypatch.setattr(native, '_proofs', lambda *args: [{'fabricated': 'kernel acceptance'}])
    result = assessment(artifact, inputs, keys)
    assert result['checks']['VERIFIER-1.5']['evaluation']['outcome'] == 'FAIL'

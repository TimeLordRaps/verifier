"""Locally admitted finite Verifier Standard (VSTD) example; no signing key saved.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
The generated demonstration key is selected by the local checker policy. It is
not an organizational identity or a production authority root.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from domain_grounding import specimens
from verifier.core.certificate import canonical_bytes
from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate,
)
from verifier.domains.common import digest
from verifier.domains.verifier_bootstrap import oracle_digest


def specimen() -> tuple[dict, dict]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    evidence = specimens()['VERIFIER']
    artifact, inputs = evidence['artifact'], evidence['inputs']
    artifact['ceilings'] = {'max_memory_bytes': 128 * 1024 * 1024,
                            'max_wall_seconds': 10.0, 'max_loop_iterations': 50000}
    inputs['resource_execution'] = {'mechanism': 'windows-job-native-kernel-1'}
    # Retained consistency record, never the authority for bootstrap admission.
    inputs['self_attestation'] = {'attested_verifier_id': artifact['verifier_id'],
                                 'toolchain_digest': artifact['toolchain_digest'],
                                 'attestation_verdict': 'PASS'}
    artifact['self_attestation_digest'] = digest(inputs['self_attestation'])
    key = Ed25519PrivateKey.generate()
    payload = {'schema_version': 'verifier-native-bootstrap-1', 'status': 'PASS',
               'verifier_id': artifact['verifier_id'], 'toolchain_digest': artifact['toolchain_digest'],
               'soundness_claims_digest': artifact['soundness_claims_digest'],
               'oracle_digest': oracle_digest(), 'key_id': 'example:local-admission'}
    inputs['bootstrap_receipt'] = dict(payload, signature=key.sign(canonical_bytes(payload)).hex())
    artifact['bootstrap_digest'] = digest(inputs['bootstrap_receipt'])
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    policy = domain_policy(trust_roots=['example:explicit-local-demonstration'],
                           witness_keys={'example:local-admission': public})
    return evidence, policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    evidence, policy = specimen()
    request = domain_request(evidence)
    certificate = build_domain_certificate(request, evidence, policy=policy)
    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in [('evidence', evidence), ('policy', policy), ('request', request), ('certificate', certificate)]:
        target = args.output_dir / (name + '.json')
        # Refuse to overwrite a previous run's source coordinate or admission key.
        with target.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
    print(json.dumps({'status': result['status'], 'domain_depth': result['domain_depth'],
                      'object_profile_conformance': result['object_profile_conformance'],
                      'scope': 'local finite native proof admission; no general verifier soundness'}, sort_keys=True), flush=True)
    return {'PASS': 0, 'FAIL': 1, 'UNKNOWN': 2, 'REJECTED': 1}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())

"""Finite independently computed bootstrap evidence for Verifier Standard (VSTD).

conjunctive normal form (CNF) is a conjunction of Boolean clauses. Ed25519 is the
Edwards-curve digital signature algorithm with a 255-bit field. Secure Hash
Algorithm 256-bit (SHA-256) binds bytes, not authority. An externally configured
key admits one exact finite request; exhaustive truth-table evaluation checks its
formula independently of the native proof kernel's algorithm. Neither establishes
general verifier soundness, organizational independence or external factual truth.
Variable, assignment and operation counts are dimensionless; no physical units.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from .common import Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text


def oracle_digest() -> str:
    """Pin this distinct finite checking algorithm's source bytes."""
    return 'sha256:' + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def evaluate_bootstrap(artifact: dict, inputs: dict, budget: Budget, *, witness_keys: dict) -> dict[str, Any]:
    """Check independent finite results and externally admitted exact-scope signature."""
    envelope = obj(need(inputs, 'bootstrap_receipt'), {'schema_version', 'status', 'verifier_id',
        'toolchain_digest', 'soundness_claims_digest', 'oracle_digest', 'key_id', 'signature'})
    same(envelope['schema_version'], 'verifier-native-bootstrap-1', 'unsupported bootstrap mechanism')
    same(digest(envelope), need(artifact, 'bootstrap_digest'), 'bootstrap digest mismatch')
    for name in ('verifier_id', 'toolchain_digest', 'soundness_claims_digest'):
        same(envelope[name], need(artifact, name), 'bootstrap scope differs: ' + name)
    same(envelope['oracle_digest'], oracle_digest(), 'bootstrap finite oracle implementation differs')
    same(envelope['status'], 'PASS', 'bootstrap admission is not positive')
    key_id = text(envelope['key_id'])
    signature = envelope['signature']
    if not isinstance(signature, str) or not re.fullmatch(r'[0-9a-f]{128}', signature):
        raise Refuted('malformed bootstrap signature')

    # A known finite contradiction remains a refutation even when key admission is
    # absent. This algorithm reads raw clauses and never imports the native kernel.
    claims = seq(need(inputs, 'soundness_claims'), budget)
    same(digest(claims), envelope['soundness_claims_digest'], 'bootstrap proof requests differ')
    results = []
    for claim in claims:
        same(claim['class'], 'cnf_sat', 'bootstrap admits only finite Boolean formulas')
        certificate = obj(obj(claim['refutation_witness'])['certificate'])
        formula = seq(certificate['formula'], budget, nonempty=False)
        clauses = []
        highest = 0
        for clause in formula:
            literals = seq(clause, budget, nonempty=False)
            for literal in literals:
                if type(literal) is not int or literal == 0:
                    raise Refuted('finite oracle requires nonzero integer literals')
                highest = max(highest, abs(literal))
            clauses.append(literals)
        if highest > 12:
            raise Unavailable('finite bootstrap oracle supports at most twelve Boolean variables')
        integer(claim['boundary_limit'], minimum=1)
        if highest > claim['boundary_limit']:
            raise Refuted('finite bootstrap formula exceeds its selected variable bound')
        satisfiable = False
        assignments = 0
        for assignment in range(1 << highest):
            budget.tick()
            assignments += 1
            holds = True
            for clause in clauses:
                clause_holds = False
                for literal in clause:
                    budget.tick()
                    value = bool(assignment & (1 << (abs(literal)-1)))
                    clause_holds = clause_holds or (value if literal > 0 else not value)
                holds = holds and clause_holds
            satisfiable = satisfiable or holds
        verdict = obj(certificate['header'])['verdict']
        if verdict not in ('PASS', 'FAIL'):
            raise Unavailable('finite bootstrap needs a decidable retained certificate')
        same(satisfiable, verdict == 'PASS', 'independent truth table refutes native certificate decision')
        results.append({'certificate_digest': digest(certificate), 'satisfiable': satisfiable,
                        'variables': highest, 'assignments_checked': assignments})

    encoded = witness_keys.get(key_id)
    if encoded is None:
        raise Unavailable('bootstrap signer is not admitted by checker-selected witness keys')
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise Unavailable('bootstrap signature verification needs the seal optional dependency') from exc
    payload = {k: v for k, v in envelope.items() if k != 'signature'}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(encoded)).verify(bytes.fromhex(signature), canonical_bytes(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Refuted('bootstrap signature does not bind the admitted request') from exc
    return {'algorithm': 'exhaustive-truth-table-1', 'oracle_digest': oracle_digest(),
            'admitted_key_id': key_id, 'finite_results': results,
            'scope': 'externally admitted retained Boolean formula instances and native decisions',
            'general_verifier_soundness': 'NOT_ESTABLISHED',
            'organizational_independence': 'NOT_ESTABLISHED', 'external_facts': 'NOT_ESTABLISHED'}

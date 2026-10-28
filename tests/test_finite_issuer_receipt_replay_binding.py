"""Retained receipt refutations precede unavailable replay companions.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
The fixtures execute actual finite native/public/authority/local-ledger admission.
Rehashing a contradictory receipt supplies no authority or positive execution.
"""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import finite_record_issuance as issuer
from test_finite_issuer_retained_bindings import finite, primitive_receipt, digest


@pytest.mark.parametrize('contradiction', ['invocation_time', 'fixed_boundary'])
@pytest.mark.parametrize('loss', ['public_commit', 'bundle', 'issue_evidence', 'source'])
def test_current_receipt_refutation_precedes_missing_replay_companion(finite, monkeypatch, contradiction, loss):
    original_receipt = finite.commit()['local_commit']
    finite.postcommit(original_receipt)
    selection = finite.final_selection(original_receipt)
    final = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert final['status'] == 'PASS' and final['polished'] is False
    if contradiction == 'invocation_time':
        changed_receipt = primitive_receipt(finite, 'fixture:other', 110)
    else:
        changed_receipt = deepcopy(original_receipt)
        changed_receipt['claim_boundary'] = 'WORLDWIDE_UNIQUENESS_ESTABLISHED'
        changed_receipt.pop('receipt_digest')
        changed_receipt['receipt_digest'] = digest(canonical_bytes(changed_receipt))
    changed_bytes = canonical_bytes(changed_receipt)
    selection['receipt_bytes'] = changed_bytes
    carried = deepcopy(final)
    carried['receipt_digest'] = digest(changed_bytes)
    carried.pop('assessment_digest')
    carried['assessment_digest'] = digest(canonical_bytes(carried))
    callbacks = []

    def unavailable_source():
        callbacks.append(True)
        raise OSError('negative-only unavailable selected source')

    monkeypatch.setattr(issuer, 'mechanism_digest', unavailable_source)
    if loss != 'source':
        selection[loss + '_bytes'] = None
    report = issuer.recheck_finite_record_issuance(canonical_bytes(carried), finite.proposal, **selection)
    assert report['status'] == 'FAIL' and report['replay_status'] == 'REJECTED'
    assert report['polished'] is False and callbacks == []


def test_available_fixed_receipt_boundary_refuses_before_finalization_source(finite, monkeypatch):
    receipt = finite.commit()['local_commit']
    finite.postcommit(receipt)
    selection = finite.final_selection(receipt)
    changed = deepcopy(receipt)
    changed['claim_boundary'] = 'WORLDWIDE_UNIQUENESS_ESTABLISHED'
    changed.pop('receipt_digest')
    changed['receipt_digest'] = digest(canonical_bytes(changed))
    selection['receipt_bytes'] = canonical_bytes(changed)
    callbacks = []

    def unavailable_source():
        callbacks.append(True)
        raise OSError('negative-only unavailable selected source')

    monkeypatch.setattr(issuer, 'mechanism_digest', unavailable_source)
    report = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert report['status'] == 'FAIL' and report['polished'] is False and callbacks == []

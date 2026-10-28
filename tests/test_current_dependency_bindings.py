"""Independent direct-dependency substitution gates for current certificates.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from verifier.domains.contracts import receipt_chain
from verifier.domains import common
from verifier.core import evidence


@pytest.mark.parametrize("dependency", [common, evidence])
def test_receipt_direct_dependency_bytes_invalidate_selected_policy(dependency: Any, monkeypatch: Any) -> None:
    policy = receipt_chain.receipt_chain_policy(trust_roots=["external-test-selection"])
    original = Path.read_bytes
    target = Path(dependency.__file__)
    def substituted(path: Path) -> bytes:
        data = original(path)
        return data + b"\n# independent dependency substitution\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", substituted)
    assert receipt_chain.mechanism_digest() != policy["mechanism_digest"]
    with pytest.raises(receipt_chain.ReceiptChainError, match="installed mechanism"):
        receipt_chain.receipt_chain_request(domain="test", genesis_digest="sha256:" + "0" * 64,
            first_sequence=0, tip_digest="sha256:" + "1" * 64, evidence_ref="sha256:" + "2" * 64,
            receipt_object_id="test", receipt_object_digest="sha256:" + "3" * 64, policy=policy)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 2 * 1024 * 1024 + 1])
def test_receipt_certificate_bound_requires_supported_plain_integer(limit: Any) -> None:
    with pytest.raises(receipt_chain.ReceiptChainError):
        receipt_chain.receipt_chain_policy(trust_roots=["external-test-selection"], max_certificate_bytes=limit)

"""Guard the maintainer's positive meta-tier and internal-certificate notation."""

from pathlib import Path
import re

import pytest

from verifier.core.namespace import ObjectCoordinate
from verifier.core.profile_obligations import TIER_NAMES


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SURFACES = (
    "docs/ACCOUNTABILITY_RELEASE_SCOPE.md",
    "docs/CONTROL_LEVELS.md",
    "docs/PRIVACY_LEVEL6_REVIEW.md",
    "docs/CONSENT_LEVEL7.md",
    "docs/GOVERNANCE_LEVEL8.md",
    "src/verifier/standard/META_TIERS.md",
    "src/verifier/standard/DOMAIN_OBLIGATIONS.md",
)


def test_meta_tier_notation_is_positive_and_m_is_an_internal_certificate() -> None:
    texts = {name: (ROOT / name).read_text(encoding="utf-8")
             for name in PUBLIC_SURFACES}
    architecture = texts["src/verifier/standard/META_TIERS.md"]
    assert "tier one of 1..9" in architecture
    assert "internal grounding certificate" in architecture
    assert str(ObjectCoordinate.parse("OBJECT-9.1")) == "OBJECT-9.1"
    with pytest.raises(ValueError):
        ObjectCoordinate.parse("OBJECT-10.1")
    bare_tier_shorthand = re.compile(r"(?<![A-Z0-9>\]])-[1-9]\.m(?:s)?\b")
    assert bare_tier_shorthand.search("security -9.m")
    assert not bare_tier_shorthand.search("[OBJECT]-9.m")
    for name, text in texts.items():
        assert not bare_tier_shorthand.search(text), name
        assert not re.search(r"-[1-9]\.ms\b", text), name


def test_runtime_catalogue_does_not_pretend_to_register_all_eight_tiers() -> None:
    # The retained numbered-profile catalogue is a partial historical implementation.
    assert set(TIER_NAMES) == set(range(1, 7))
    architecture = (ROOT / "src/verifier/standard/META_TIERS.md").read_text(encoding="utf-8")
    assert "tiers 7 and 8 are not registered" in architecture
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    routes = {row["objective"]: row for row in current_object_route_catalog()}
    assert routes["RECEIPT-9.1"]["scope"] == "externally_selected_finite_receipt_hash_chain"
    assert "[RECEIPT-9.1](CURRENT_RECEIPT_CHAIN.md)" in architecture
    assert "conformance, which remains NOT_ESTABLISHED" in architecture

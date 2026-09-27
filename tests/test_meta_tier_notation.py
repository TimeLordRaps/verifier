"""Guard the maintainer's positive meta-tier and internal-certificate notation."""

from pathlib import Path
import re

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
    assert "tier one of 1..8" in architecture
    assert "internal grounding certificate" in architecture
    for name, text in texts.items():
        assert not re.search(r"(?<![A-Z0-9>\]])-[1-8]\.m(?:s)?\b", text), name
        assert not re.search(r"-[1-8]\.ms\b", text), name


def test_runtime_catalogue_does_not_pretend_to_register_all_eight_tiers() -> None:
    # The current numbered-profile catalogue is a partial implementation.
    assert set(TIER_NAMES) == set(range(1, 7))
    architecture = (ROOT / "src/verifier/standard/META_TIERS.md").read_text(encoding="utf-8")
    assert "tiers 7 and 8 are not registered" in architecture

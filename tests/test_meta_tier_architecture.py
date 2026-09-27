"""Guard the Verifier Standard (VSTD) namespace against legacy promotion."""
from __future__ import annotations

from pathlib import Path
import re

from verifier.core.namespace import MetaTier, ObjectKind


ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "src/verifier/standard/META_TIERS.md"
DOMAIN = ROOT / "src/verifier/standard/DOMAIN_OBLIGATIONS.md"


def test_current_census_matches_the_admitted_namespace() -> None:
    text = META.read_text(encoding="utf-8")
    current = text.split("## Current namespace census", 1)[1].split(
        "## Legacy corroboration projection", 1
    )[0]
    rows = [line.split("|")[2] for line in current.splitlines() if line.startswith("| ")]
    names = re.findall(r"`([A-Z]+)`", "\n".join(rows))
    assert len(names) == 26
    assert set(names) == {kind.value for kind in ObjectKind}
    assert "VSTD" not in names


def test_current_tiers_do_not_promote_old_adaptation_or_disclosure() -> None:
    text = META.read_text(encoding="utf-8")
    current = text.split("## Current namespace census", 1)[1].split(
        "## Legacy corroboration projection", 1
    )[0]
    meanings = {
        int(number): meaning
        for number, meaning in re.findall(r"^\| ([1-8]) \| \*\*([^*]+)\*\* \|", current, re.M)
    }
    assert meanings == {
        1: "Facets", 2: "Dynamics", 3: "Statics", 4: "Closure",
        5: "Independence", 6: "Privacy", 7: "Consent", 8: "Governance",
    }
    assert {tier.value: tier.name.title() for tier in MetaTier} == meanings
    assert "No legacy numbered-profile PASS transfers" in current
    assert "legacy domain adaptation" in current
    assert "legacy disclosure" in current


def test_legacy_actor_definition_is_explicitly_superseded() -> None:
    architecture = META.read_text(encoding="utf-8")
    legacy = architecture.split("## Legacy corroboration projection", 1)[1]
    assert "ACTOR = ROLE | COLLECTIVE" in legacy
    current = architecture.split("## Legacy corroboration projection", 1)[0]
    assert "\nACTOR = ROLE | COLLECTIVE\n" not in current
    assert "definition below is\nsuperseded" in current
    assert "ACTOR" in architecture.split("## Current namespace census", 1)[1].split(
        "## Legacy corroboration projection", 1
    )[0]
    domain = DOMAIN.read_text(encoding="utf-8")
    assert "legacy numbered-profile catalogue" in domain
    assert "current ACTOR" in domain
    assert "UNKNOWN" in domain.split("## Legacy obligations", 1)[0]

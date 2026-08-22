"""Adversarial checks for the synthetic closed-evaluation profile specimen."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from verifiable.core.certificate import canonical_digest


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "simulacrabench_synthetic"
SPEC = importlib.util.spec_from_file_location(
    "simulacrabench_packet_verifier", EXAMPLE / "verify_packet.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _load(name: str) -> dict:
    value = json.loads((EXAMPLE / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _reseal(document: dict, field: str) -> None:
    document.pop(field, None)
    document[field] = f"sha256:{canonical_digest(document)}"


def test_public_packet_and_non_disclosing_challenge_verify() -> None:
    result = MODULE.verify_all()
    assert result["packet"] == {
        "packet_id": "VSTD-SB-SYNTH-001",
        "packet_digest": "sha256:f182bfce5a5ae8e7137795300d42e285f365e6707b7c3517b3cee7b02331963b",
        "availability_floor": "AVAILABLE",
        "public_reproduction": "UNAVAILABLE",
        "claim_status": "RECORDED_UNDER_DECLARED_SYNTHETIC_EVALUATOR",
    }
    assert result["challenge"]["after_public_filing"] == "CHALLENGED"
    assert result["challenge"]["after_authorized_adjudication"] == "REVOKED"
    assert result["challenge"]["records_disclosed"] == 0


def test_public_packet_excludes_private_score_detail_and_local_locations() -> None:
    packet = _load("public_packet.json")
    public_text = json.dumps(packet, sort_keys=True).lower()
    def keys(value):
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value)) if value else set()
        return set()

    assert {"raw_skill", "log_score", "by_item", "std_error"}.isdisjoint(keys(packet))
    for prohibited in ("e:\\\\", "c:\\\\users"):
        assert prohibited not in public_text
    assert packet["reported_result"]["privacy_policy"]["raw_skill_disclosed"] is False
    assert packet["availability_summary"]["public_reproduction"] == "UNAVAILABLE"


def test_digest_only_private_artifact_cannot_remain_available() -> None:
    packet = _load("public_packet.json")
    mutant = copy.deepcopy(packet)
    hidden = next(
        item
        for item in mutant["evidence_inventory"]
        if item["artifact_id"] == "hidden-synthetic-fixture"
    )
    hidden["locator"] = ""
    _reseal(mutant, "packet_digest")
    with pytest.raises(MODULE.PacketError, match="assessed level"):
        MODULE.verify_packet(mutant)


def test_private_retention_and_packet_staleness_cannot_diverge() -> None:
    packet = _load("public_packet.json")
    mutant = copy.deepcopy(packet)
    mutant["limits"]["stale_after"] = "2026-10-01T00:00:00Z"
    _reseal(mutant, "packet_digest")
    with pytest.raises(MODULE.PacketError, match="stale_after"):
        MODULE.verify_packet(mutant)


def test_challenge_cannot_disclose_a_hidden_record() -> None:
    packet = _load("public_packet.json")
    challenge = _load("challenge_demo.json")
    mutant = copy.deepcopy(challenge)
    mutant["leak_check"]["individual_records"] = 1
    _reseal(mutant, "challenge_digest")
    with pytest.raises(MODULE.PacketError, match="leaks"):
        MODULE.verify_challenge(packet, mutant)


def test_challenge_cannot_substitute_a_different_refutation_surface() -> None:
    packet = _load("public_packet.json")
    challenge = _load("challenge_demo.json")
    mutant = copy.deepcopy(challenge)
    mutant["refutation_surface"]["admissible_refutations"][0][
        "overturning_evidence"
    ] = "A weaker post-hoc condition."
    _reseal(mutant, "challenge_digest")
    with pytest.raises(MODULE.PacketError, match="differs"):
        MODULE.verify_challenge(packet, mutant)

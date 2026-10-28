"""The Verifier Standard (VSTD) namespace gate must check current admission."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from scripts import check_namespace_closure as namespace_gate


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_namespace_closure.py"
CURRENT_OBJECTS = {
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
    "AGENT", "SIM", "BOT", "TOKEN",
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
}
CURRENT_TIERS = {
    1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE",
    5: "INDEPENDENCE", 6: "PRIVACY", 7: "CONSENT", 8: "GOVERNANCE",
    9: "SECURITY",
}


def gate():
    return namespace_gate


def test_gate_binds_current_38_objects_and_nine_meanings() -> None:
    checker = gate()
    assert checker.OBJECTS == CURRENT_OBJECTS
    assert checker.CURRENT_TIERS == CURRENT_TIERS
    assert checker.current_namespace_offenders() == []
    assert checker.current_tier_offenders() == []


def test_gate_rejects_a_silently_omitted_current_object(monkeypatch, capsys) -> None:
    checker = gate()
    monkeypatch.setattr(checker, "OBJECTS", checker.OBJECTS - {"ARCH"})
    assert checker.current_namespace_offenders() == ["ARCH missing from gate"]
    assert checker.main() == 1
    assert "ARCH missing from gate" in capsys.readouterr().out


def test_gate_rejects_a_relabelled_independence_tier(monkeypatch, capsys) -> None:
    checker = gate()
    monkeypatch.setattr(checker, "CURRENT_TIERS", {**checker.CURRENT_TIERS, 5: "ADAPTATION"})
    assert checker.current_tier_offenders() == [
        "tier 5: expected ADAPTATION, runtime INDEPENDENCE"
    ]
    assert checker.main() == 1
    assert "tier 5: expected ADAPTATION, runtime INDEPENDENCE" in capsys.readouterr().out


def test_gate_rejects_a_silently_omitted_security_tier(monkeypatch) -> None:
    checker = gate()
    monkeypatch.setattr(checker, "CURRENT_TIERS", {number: name for number, name in
                        checker.CURRENT_TIERS.items() if number != 9})
    assert checker.current_tier_offenders() == [
        "tier 9: expected None, runtime SECURITY"
    ]


def test_gate_reports_structural_admission_without_full_certification() -> None:
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True,
                            text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "38 object kinds" in result.stdout
    assert "26-kind wire enum" in result.stdout
    assert "nine meta-tiers" in result.stdout
    assert "structural admission only" in result.stdout
    assert "objective certification NOT_ESTABLISHED" in result.stdout
    assert "VSTD and 20 objects" not in result.stdout

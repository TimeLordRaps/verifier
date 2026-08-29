"""Terminology: Verifier Standard (VSTD)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MECHANISM = ROOT / "examples" / "zizk_artifact_first" / "risc0"


def test_zero_knowledge_mechanism_is_optional_and_pinned() -> None:
    host_manifest = (MECHANISM / "host" / "Cargo.toml").read_text(encoding="utf-8")
    guest_manifest = (
        MECHANISM / "methods" / "guest" / "Cargo.toml"
    ).read_text(encoding="utf-8")
    methods_manifest = (MECHANISM / "methods" / "Cargo.toml").read_text(
        encoding="utf-8"
    )

    assert 'version = "=3.0.6"' in host_manifest
    assert 'features = ["disable-dev-mode"]' in host_manifest
    assert 'version = "=3.0.6"' in guest_manifest
    assert 'version = "=3.0.6"' in methods_manifest
    assert "zizk" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()


def test_zero_knowledge_claim_boundary_is_explicit() -> None:
    boundary = (MECHANISM / "CLAIM_BOUNDARY.md").read_text(encoding="utf-8")
    assert "does not prove" in boundary
    assert "bounded reference mechanism" in boundary
    assert "UNKNOWN" in boundary
    assert "CONFLICTED" in boundary


def test_experimental_scope_does_not_absorb_the_governing_architecture() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    experiment_index = (
        ROOT / "experiments" / "artifact_first_mechanisms" / "README.md"
    ).read_text(encoding="utf-8")
    design = (
        ROOT
        / "experiments"
        / "artifact_first_mechanisms"
        / "reverification"
        / "ROUND2_DESIGN_NOTE.md"
    ).read_text(encoding="utf-8")

    assert "Governing VSTD architecture" in readme
    assert "not an optional research" in readme
    assert "architecture, not a side experiment" in architecture
    for phrase in (
        "event serialization",
        "TRUST-transfer algebra",
        "ROT derivation and propagation",
        "RUST concentration and localization",
        "complete hidden-witness trichotomy derivation",
        "specific optional proof backends",
    ):
        assert phrase in experiment_index
    assert "semantic experiment for bounded identity disclosure" not in design
    assert "Zero Identity experiment" not in design
    assert "bounded identity-disclosure reference" in design


def test_zizk_preserves_memetic_causality_without_localization_overclaim() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    ladder = (ROOT / "standard" / "LADDER.md").read_text(encoding="utf-8")
    mechanism = (MECHANISM / "README.md").read_text(encoding="utf-8")

    assert "Zero identity means zero identity-derived verdict weight" in readme
    assert "zero unevidenced knowledge is presumed" in readme
    assert "cryptographic zero knowledge can enclose" in readme
    assert "without attaching TRUST to the prover's identity" in readme
    assert "TRUST is mechanism-earned artifact support" in readme
    assert "ROT is typed, time-indexed degradation" in readme
    assert "RUST is the inverse-TRUST diagnostic mechanic" in readme
    assert "cryptographic zero-knowledge\nenclosure" in mechanism
    assert "without importing prover identity into TRUST" in mechanism
    assert "memetic causal backtrace" in ladder
    assert "genetic or viral language names this inheritance mechanic" in ladder
    assert "does not by itself establish\nintervention-level physical causality" in ladder


def test_private_inputs_are_excluded_and_public_proof_artifacts_are_versioned() -> None:
    ignore = (MECHANISM / ".gitignore").read_text(encoding="utf-8")
    assert "private-*.json" in ignore
    assert "local-artifacts/" in ignore
    tracked = subprocess.run(
        ["git", "ls-files", "--", "examples/zizk_artifact_first/risc0"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert any(path.endswith("recorded-proof/receipt.msgpack") for path in tracked)
    assert any(path.endswith("recorded-proof/public.json") for path in tracked)
    assert any(path.endswith("recorded-proof/self-test-results.json") for path in tracked)
    assert not any("private-" in path and path.endswith(".json") for path in tracked)


def test_recorded_public_proof_artifact_hashes_match_the_reported_run() -> None:
    expected = {
        "receipt.msgpack": "5fd33b0fbf6b54e34d4dd19c5ff068a8f82bacacc21881b5fa2cc5c0a90090df",
        "public.json": "6324c3c5d77ea4df4034f61131059289d5228f190d69e34c59bd7416fa9ac823",
        "self-test-results.json": "e4c1bff21fb6161221276157fa96af6661af8635da35970ba12e462881f2c6fe",
    }
    for name, digest in expected.items():
        artifact = MECHANISM / "recorded-proof" / name
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == digest


def test_recorded_verification_pins_the_historical_program_trust_coordinate() -> None:
    public = json.loads(
        (MECHANISM / "recorded-proof" / "public.json").read_text(encoding="utf-8")
    )
    expected_image_id = public["image_id"]
    script = (MECHANISM / "scripts" / "verify_recorded_proof.sh").read_text(
        encoding="utf-8"
    )
    host = (MECHANISM / "host" / "src" / "main.rs").read_text(encoding="utf-8")

    assert expected_image_id in script
    assert "verify recorded-proof/receipt.msgpack recorded-proof/public.json" in script
    assert "let trusted_id = expected_id.unwrap_or_else(method_id);" in host
    assert "trusted_id != method_id()" not in host

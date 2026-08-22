"""Adversarial and lifecycle tests for the generic proof-carrying computational run
primitive (`verifiable.core.run`).

Covers the acceptance-test flow (capture -> validate -> inspect -> reproduce) plus a
hostile-scrutiny mini-corpus: tampered receipts, tampered outputs, missing declared
inputs/outputs, shell-indirection rejection, non-promotable external evaluation
claims, and determinism-bounded reproduction ceilings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from verifiable.core.run import (
    RunError,
    capture_run,
    find_run_receipts_impacted_by_revocation,
    inspect_run_receipt,
    is_generic_run_receipt,
    reproduce_run_receipt,
    validate_run_receipt,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_tiny_project(tmp_path: Path) -> Path:
    """A minimal deterministic project: script reads input.txt, writes output.json."""
    script = tmp_path / "double.py"
    script.write_text(
        "import json, sys\n"
        "with open(sys.argv[1]) as f:\n"
        "    n = int(f.read().strip())\n"
        "with open(sys.argv[2], 'w') as f:\n"
        "    json.dump({'doubled': n * 2}, f)\n",
        encoding="utf-8",
    )
    (tmp_path / "input.txt").write_text("21", encoding="utf-8")
    return tmp_path


def _base_manifest() -> dict:
    return {
        "claim": {
            "id": "RUN-TEST-000",
            "title": "Doubling test",
            "statement": "double.py doubles the integer in input.txt.",
            "scope": "unit test",
            "limitations": ["toy example"],
            "falsification_condition": "output.json digest changes on rerun",
        },
        "command": [sys.executable, "double.py", "input.txt", "output.json"],
        "cwd": ".",
        "inputs": [{"path": "input.txt", "role": "primary_input"}, {"path": "double.py", "role": "entrypoint_source"}],
        "outputs": [{"path": "output.json", "role": "primary_output"}],
        "determinism_declared": "DETERMINISTIC",
    }


def test_full_lifecycle_capture_validate_inspect_reproduce(tmp_path, capsys):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.execution.outcome == "COMPLETED"
    assert receipt.claims.execution_completed is True
    assert receipt.claims.output_digests_recorded is True
    assert receipt.claims.all_declared_artifacts_present is True

    out_dir = proj
    receipt_file = receipt.save_to_directory(out_dir)
    assert receipt_file.exists()
    assert (out_dir / "receipt_manifest.json").exists()
    assert (out_dir / "report.md").exists()
    assert (out_dir / "logs" / "execution.log").exists()
    # The digest-summary file must never collide with / clobber the user's manifest.
    assert (out_dir / "manifest.json").exists() is False  # test manifest was never written to disk

    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    assert is_generic_run_receipt(data)
    assert data["canonical_digest"] == receipt.canonical_digest
    layer4 = data["layer4_binding"]
    assert layer4["verifier"]["implementation_hash"].startswith("sha256:")
    assert layer4["verifier"]["parser_hash"].startswith("sha256:")
    assert layer4["resource_bounds"] == {
        "verification_cost_bound": 0,
        "memory_bound": 0,
        "certificate_size_bound": 0,
    }
    assert layer4["prior_commitment"] == ""
    assert layer4["refutation_surface"]["admissible_refutations"] == []
    assert "PHYSICAL_WORLD_COMPLETENESS" in layer4["refutation_surface"][
        "excluded_claims"
    ]

    assert validate_run_receipt(out_dir) == 0
    assert inspect_run_receipt(out_dir) == 0

    # Default reproduce: artifact rehash only, no side effects.
    assert reproduce_run_receipt(out_dir) == 0


def test_new_run_receipt_binds_precommitment_bounds_and_refutation_surface(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["prior_commitment"] = "sha256:" + "a" * 64
    manifest["resource_bounds"] = {
        "verification_cost_bound": 1000,
        "memory_bound": 100,
        "certificate_size_bound": 10000,
    }
    manifest["refutation_surface"] = {
        "admissible_refutations": ["evidence_hash_mismatch"],
        "excluded_claims": ["PHYSICAL_WORLD_COMPLETENESS"],
    }
    receipt = capture_run(manifest, manifest_dir=proj)
    before = receipt.canonical_digest
    layer4 = receipt.get_stable_payload()["layer4_binding"]
    assert layer4["prior_commitment"] == manifest["prior_commitment"]
    assert layer4["resource_bounds"] == manifest["resource_bounds"]
    assert layer4["refutation_surface"]["admissible_refutations"] == [
        "evidence_hash_mismatch"
    ]

    layer4["prior_commitment"] = "sha256:" + "b" * 64
    receipt.layer4_binding = layer4
    assert receipt.compute_and_set_digest() != before


def test_historical_generic_run_digest_is_unchanged_by_optional_layer4_block():
    receipt_path = REPO_ROOT / "examples" / "generic_run" / "receipt.json"
    if not receipt_path.exists():
        pytest.skip("historical private-path receipt is intentionally excluded publicly")
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert "layer4_binding" not in data
    assert validate_run_receipt(receipt_path) == 0


def test_missing_input_fails_closed_without_executing(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["inputs"] = [{"path": "does_not_exist.txt", "role": "primary_input"}]
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.execution.outcome == "MISSING_INPUT"
    assert receipt.claims.execution_completed is False
    # The command must never have run: no output.json produced.
    assert not (proj / "output.json").exists()


def test_nonzero_exit_recorded_not_hidden(tmp_path):
    proj = _write_tiny_project(tmp_path)
    (proj / "fail.py").write_text("import sys; sys.exit(3)\n", encoding="utf-8")
    manifest = _base_manifest()
    manifest["command"] = [sys.executable, "fail.py"]
    manifest["inputs"] = [{"path": "fail.py", "role": "entrypoint_source"}]
    manifest["outputs"] = []
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.execution.outcome == "NONZERO_EXIT"
    assert receipt.execution.exit_code == 3
    assert receipt.claims.execution_completed is False


def test_missing_declared_output_after_success(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    # Declare an output the script never writes.
    manifest["outputs"] = [{"path": "output.json", "role": "primary_output"}, {"path": "never_written.json", "role": "extra"}]
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.execution.outcome == "MISSING_OUTPUT"
    assert receipt.claims.execution_completed is False
    assert receipt.claims.output_digests_recorded is False


def test_shell_string_command_rejected(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["command"] = "python double.py input.txt output.json"  # string, not argv list
    with pytest.raises(RunError):
        capture_run(manifest, manifest_dir=proj)


def test_tampered_output_detected_by_reproduce(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt.save_to_directory(proj)

    assert reproduce_run_receipt(proj) == 0

    # Attack: tamper the on-disk output artifact after the receipt was issued.
    (proj / "output.json").write_text('{"doubled": 999}', encoding="utf-8")
    assert reproduce_run_receipt(proj) == 1


def test_tampered_receipt_field_detected_by_validate(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt_file = receipt.save_to_directory(proj)

    assert validate_run_receipt(proj) == 0

    # Attack: mutate a claim field in the stored receipt without recomputing the digest.
    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    data["claim_statement"] = "double.py now claims to triple the input (tampered)."
    receipt_file.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    assert validate_run_receipt(proj) == 1


def test_tampered_execution_outcome_detected_by_validate(tmp_path):
    """Flipping a claims field (e.g. execution_completed) must also break the digest."""
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt_file = receipt.save_to_directory(proj)

    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    data["execution"]["exit_code"] = 1
    data["execution"]["outcome"] = "NONZERO_EXIT"
    receipt_file.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    assert validate_run_receipt(proj) == 1


def test_external_evaluation_never_auto_promoted_to_attested(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    # Manifest author asserts attested=True with no evidence_ref and the default
    # UNVERIFIED_ASSERTION kind — this must be downgraded, not trusted verbatim.
    manifest["external_evaluation"] = {
        "source": "organizer_leaderboard",
        "description": "Claimed leaderboard score, no evidence attached.",
        "reported_value": 0.987,
        "attested": True,
    }
    receipt = capture_run(manifest, manifest_dir=proj)
    ext = receipt.claims.external_evaluation
    assert ext is not None
    assert ext.evidence_kind == "UNVERIFIED_ASSERTION"
    assert ext.attested is False, "an unverified assertion must never be silently promoted to attested"


def test_external_evaluation_with_linked_artifact_and_ref_can_be_attested(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["external_evaluation"] = {
        "source": "organizer_leaderboard",
        "description": "Score backed by a linked, checkable artifact reference.",
        "reported_value": 0.987,
        "evidence_kind": "LINKED_ARTIFACT",
        "evidence_ref": "sha256:deadbeef",
        "attested": True,
    }
    receipt = capture_run(manifest, manifest_dir=proj)
    ext = receipt.claims.external_evaluation
    assert ext.attested is True
    assert ext.evidence_ref == "sha256:deadbeef"


def test_evaluator_claim_reads_true_value_from_output_not_manifest_assertion(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["evaluator_claims"] = [
        {
            "evaluator_name": "builtin",
            "metric_name": "doubled",
            "value": 999999,  # a bogus assertion the manifest author might write
            "read_from_output": {"path": "output.json", "json_pointer": "doubled"},
        }
    ]
    receipt = capture_run(manifest, manifest_dir=proj)
    claim = receipt.claims.evaluator_claims[0]
    assert claim.value == 42  # actual value read from the produced artifact, not the bogus 999999
    assert claim.computed_by == "local_reference_evaluator"
    assert claim.verified_independently is True


def test_nondeterministic_run_cannot_declare_bitwise_ceiling(tmp_path):
    proj = _write_tiny_project(tmp_path)
    script = proj / "rand.py"
    script.write_text(
        "import json, os, sys\n"
        "with open(sys.argv[1], 'w') as f:\n"
        "    json.dump({'token': os.urandom(8).hex()}, f)\n",
        encoding="utf-8",
    )
    manifest = _base_manifest()
    manifest["command"] = [sys.executable, "rand.py", "output.json"]
    manifest["inputs"] = [{"path": "rand.py", "role": "entrypoint_source"}]
    manifest["determinism_declared"] = "NONDETERMINISTIC"
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.reproducibility["declared_ceiling"] != "BITWISE_IDENTICAL"
    assert "BITWISE_IDENTICAL" not in receipt.reproducibility["supported_levels"]


def test_rerun_reproduction_achieves_bitwise_identical_for_deterministic_example(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt.save_to_directory(proj)
    (proj / "manifest.source.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert reproduce_run_receipt(proj, rerun=True) == 0


def test_provenance_linkage_against_real_vfy_data_receipt():
    """Dogfood check: link a run to the real VFY-DATA-000001 hypergraph in this repo."""
    data_receipt_dir = REPO_ROOT / "receipts" / "VFY-DATA-000001"
    if not (data_receipt_dir / "receipt.json").exists():
        pytest.skip("VFY-DATA-000001 receipt not present in this checkout")

    data = json.loads((data_receipt_dir / "receipt.json").read_text(encoding="utf-8"))
    arts = data.get("hypergraph", {}).get("artifacts", [])
    # Artifacts are serialized as a list of dicts on disk (see VerifiableDataReceipt.to_dict
    # -> ProvenanceHypergraph.to_dict); normalize defensively in case that ever changes to a
    # dict keyed by artifact_id.
    if isinstance(arts, dict):
        artifact_ids = list(arts.keys())
    else:
        artifact_ids = [a["artifact_id"] for a in arts]
    assert artifact_ids, "expected at least one artifact in VFY-DATA-000001's hypergraph"

    from verifiable.core.run import _resolve_provenance_linkage

    linkage = _resolve_provenance_linkage(
        REPO_ROOT,
        {"dataset_receipt_path": "receipts/VFY-DATA-000001", "artifact_id": artifact_ids[0]},
    )
    assert linkage.found_in_hypergraph is True
    assert linkage.ancestor_count is not None

    missing = _resolve_provenance_linkage(
        REPO_ROOT,
        {"dataset_receipt_path": "receipts/VFY-DATA-000001", "artifact_id": "art:does_not_exist_12345"},
    )
    assert missing.found_in_hypergraph is False
    assert missing.ancestor_count is None


def test_blast_radius_revocation_flags_dependent_run_receipts(tmp_path):
    """Revoking an upstream VSTD-DATA artifact must surface which recorded runs
    consumed it (directly or via a downstream derivative) — composing dataset
    provenance into run-receipt impact analysis rather than a parallel system.
    """
    data_receipt_dir = REPO_ROOT / "receipts" / "VFY-DATA-000001"
    data_receipt_file = data_receipt_dir / "receipt.json"
    if not data_receipt_file.exists():
        pytest.skip("VFY-DATA-000001 receipt not present in this checkout")

    data = json.loads(data_receipt_file.read_text(encoding="utf-8"))
    artifact_id = data["hypergraph"]["artifacts"][0]["artifact_id"]

    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["provenance_roots"] = [
        {
            "dataset_receipt_path": str(data_receipt_dir),
            "artifact_id": artifact_id,
        }
    ]
    receipt = capture_run(manifest, manifest_dir=proj)
    assert receipt.provenance_linkage[0].found_in_hypergraph is True
    receipt_dir = tmp_path / "receipts_tree" / "RUN-TEST-000"
    receipt.save_to_directory(receipt_dir)

    impacted = find_run_receipts_impacted_by_revocation(
        search_root=tmp_path / "receipts_tree",
        dataset_receipt_file=data_receipt_file,
        revoked_artifact_id=artifact_id,
    )
    assert len(impacted) == 1
    assert impacted[0]["receipt_id"] == "RUN-TEST-000"
    assert impacted[0]["matched_artifact_id"] == artifact_id

    # A run that never linked to this dataset at all must never be implicated.
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other_proj = _write_tiny_project(other_dir)
    other_manifest = _base_manifest()
    other_manifest["claim"]["id"] = "RUN-UNRELATED-000"
    other_receipt = capture_run(other_manifest, manifest_dir=other_proj)
    assert other_receipt.provenance_linkage == ()
    other_receipt.save_to_directory(tmp_path / "receipts_tree" / "RUN-UNRELATED-000")

    impacted_again = find_run_receipts_impacted_by_revocation(
        search_root=tmp_path / "receipts_tree",
        dataset_receipt_file=data_receipt_file,
        revoked_artifact_id=artifact_id,
    )
    matched_ids = {e["receipt_id"] for e in impacted_again}
    assert "RUN-TEST-000" in matched_ids
    assert "RUN-UNRELATED-000" not in matched_ids

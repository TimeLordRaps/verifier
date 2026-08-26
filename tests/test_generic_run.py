"""Terminology: Verifier Standard (VSTD).

Adversarial and lifecycle tests for the generic computational run receipt
primitive (`verifier.core.run`).

Covers the acceptance-test flow (capture -> validate -> inspect -> reproduce) plus a
hostile-scrutiny mini-corpus: tampered receipts, tampered outputs, missing declared
inputs/outputs, shell-indirection rejection, non-promotable external evaluation
claims, and mechanism-bounded reproduction ceilings.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from verifier.core.run import (
    RunError,
    _rebuild_stable_payload_from_dict,
    capture_run,
    find_run_receipts_impacted_by_revocation,
    inspect_run_receipt,
    is_generic_run_receipt,
    reproduce_run_receipt,
    validate_run_receipt,
)
from verifier.core.receipt import compute_canonical_digest
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)
from verifier.runtime.public_cli import _write_reproduction_bundle

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


def test_digest_consistent_empty_generic_receipt_is_rejected(tmp_path, capsys):
    receipt = {"receipt_kind": "generic_computational_run"}
    receipt["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(receipt)
    )
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")

    assert validate_run_receipt(path) == 1
    output = capsys.readouterr().out
    assert "[INTEGRITY OK]" not in output
    assert "missing required fields" in output


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


def _write_data_receipt(tmp_path: Path) -> tuple[Path, str]:
    """Write the smallest public graph fixture needed by linkage/blast-radius tests."""

    graph = ProvenanceHypergraph()
    for artifact_id in ("artifact:source", "artifact:derived"):
        graph.add_artifact(
            ArtifactNode(
                artifact_id,
                artifact_id,
                ArtifactType.CORPUS,
                "a" * 64,
                status=ArtifactStatus.VALID,
            )
        )
    graph.add_transformation(
        TransformationHyperedge(
            "transform:derive",
            "derive",
            TransformationType.EXTRACTION,
            (HyperedgePort("artifact:source", "INPUT"),),
            (HyperedgePort("artifact:derived", "OUTPUT"),),
            {},
            {},
            {},
        )
    )
    receipt_file = tmp_path / "dataset-receipt" / "receipt.json"
    receipt_file.parent.mkdir()
    receipt_file.write_text(
        json.dumps({"hypergraph": graph.to_dict()}),
        encoding="utf-8",
    )
    return receipt_file, "artifact:source"


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
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "receipts" / "schema" / "vstd1_generic_run_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(data)
    assert is_generic_run_receipt(data)
    assert data["canonical_digest"] == receipt.canonical_digest
    legacy_context = data["layer4_binding"]
    assert legacy_context["vstd4_conformance"] == "NOT_EVALUATED"
    assert legacy_context["verifier"]["implementation_hash"].startswith("sha256:")
    assert legacy_context["verifier"]["parser_hash"].startswith("sha256:")
    assert legacy_context["resource_bounds"] == {
        "verification_cost_bound": 0,
        "memory_bound": 0,
        "certificate_size_bound": 0,
    }
    assert legacy_context["prior_commitment"] == ""
    assert legacy_context["refutation_surface"]["admissible_refutations"] == []
    assert "PHYSICAL_WORLD_COMPLETENESS" in legacy_context["refutation_surface"][
        "excluded_claims"
    ]

    assert validate_run_receipt(out_dir) == 0
    assert "[INTEGRITY OK]" in capsys.readouterr().out
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
    legacy_context = receipt.get_stable_payload()["layer4_binding"]
    assert legacy_context["prior_commitment"] == manifest["prior_commitment"]
    assert legacy_context["resource_bounds"] == manifest["resource_bounds"]
    assert legacy_context["refutation_surface"]["admissible_refutations"] == [
        "evidence_hash_mismatch"
    ]

    legacy_context["prior_commitment"] = "sha256:" + "b" * 64
    receipt.layer4_binding = legacy_context
    assert receipt.compute_and_set_digest() != before


@pytest.mark.parametrize("historical_shape", ("pre_v1", "v1_without_marker"))
def test_historical_generic_run_binding_shapes_remain_readable(
    tmp_path, capsys, historical_shape
):
    proj = _write_tiny_project(tmp_path)
    data = capture_run(_base_manifest(), manifest_dir=proj).to_dict()
    if historical_shape == "pre_v1":
        data.pop("layer4_binding")
    else:
        data["layer4_binding"].pop("vstd4_conformance")
    data["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(data)
    )
    path = tmp_path / f"{historical_shape}.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert is_generic_run_receipt(data)
    assert validate_run_receipt(path) == 0
    assert "[INTEGRITY OK]" in capsys.readouterr().out


def test_legacy_container_cannot_claim_vstd4_conformance(tmp_path, capsys):
    proj = _write_tiny_project(tmp_path)
    data = capture_run(_base_manifest(), manifest_dir=proj).to_dict()
    data["layer4_binding"]["vstd4_conformance"] = "PASS"
    data["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(data)
    )
    path = tmp_path / "hostile-vstd4-claim.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert validate_run_receipt(path) == 1
    assert "vstd4_conformance must be NOT_EVALUATED" in capsys.readouterr().out


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


def test_validator_rejects_digest_consistent_independence_and_attestation_upgrades(
    tmp_path,
):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["evaluator_claims"] = [
        {"evaluator_name": "declared", "metric_name": "score", "value": 1}
    ]
    manifest["external_evaluation"] = {
        "source": "declared",
        "description": "unverified",
        "reported_value": 1,
    }
    receipt = capture_run(manifest, manifest_dir=proj)
    original = receipt.to_dict()

    for mutate in (
        lambda data: data["claims"]["evaluator_claims"][0].update(
            verified_independently=True
        ),
        lambda data: data["claims"]["external_evaluation"].update(attested=True),
        lambda data: data.update(unbound_claim_upgrade=True),
    ):
        data = copy.deepcopy(original)
        mutate(data)
        data["canonical_digest"] = compute_canonical_digest(
            _rebuild_stable_payload_from_dict(data)
        )
        path = tmp_path / "hostile-receipt.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        assert validate_run_receipt(path) == 1


@pytest.mark.parametrize(
    ("container_path", "field_name"),
    (
        (("source_state",), "unknown_source_field"),
        (("source_state", "git"), "unknown_git_field"),
        (("source_state", "runtime"), "unknown_runtime_field"),
        (("layer4_binding",), "unknown_binding_field"),
        (("layer4_binding", "verifier"), "unknown_verifier_field"),
        (("layer4_binding", "resource_bounds"), "unknown_bound_field"),
    ),
)
def test_validator_rejects_digest_consistent_unknown_nested_fields(
    tmp_path, container_path, field_name
):
    proj = _write_tiny_project(tmp_path)
    receipt = capture_run(_base_manifest(), manifest_dir=proj)
    data = receipt.to_dict()
    container = data
    for segment in container_path:
        container = container[segment]
    container[field_name] = "attacker-controlled"
    data["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(data)
    )
    path = tmp_path / "hostile-nested-receipt.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert validate_run_receipt(path) == 1


def test_refutation_surface_is_the_explicit_compatible_extension_map(tmp_path):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["refutation_surface"] = {"domain_refutation": "declared extension"}
    receipt = capture_run(manifest, manifest_dir=proj)
    path = receipt.save_to_directory(proj)

    assert (
        receipt.layer4_binding["refutation_surface"]["domain_refutation"]
        == "declared extension"
    )
    assert validate_run_receipt(path) == 0


def test_external_evaluation_reference_remains_unverified_by_capture_runtime(tmp_path):
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
    assert ext.attested is False
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
    assert claim.computed_by == "bound_output_extraction"
    assert claim.verified_independently is False


def test_determinism_declaration_cannot_raise_reproduction_ceiling(tmp_path):
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
    manifest["determinism_declared"] = "DETERMINISTIC"
    receipt = capture_run(manifest, manifest_dir=proj)

    assert receipt.reproducibility["declared_ceiling"] == "CONTENT_IDENTICAL"
    assert receipt.reproducibility["supported_levels"] == ["CONTENT_IDENTICAL"]
    assert receipt.reproducibility["highest_demonstrated_level"] is None


def test_rerun_demonstrates_only_declared_output_content_identity(tmp_path, capsys):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt.save_to_directory(proj)
    (proj / "manifest.source.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert reproduce_run_receipt(proj, rerun=True) == 0
    output = capsys.readouterr().out
    assert "Level: CONTENT_IDENTICAL (declared-output scope)" in output
    assert "BITWISE_IDENTICAL" not in output


def test_relocated_bundle_rerun_keeps_declared_output_scope(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    _write_tiny_project(source)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test" + "@" + "example.invalid"],
        cwd=source,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "VSTD Test"], cwd=source, check=True)
    subprocess.run(["git", "add", "double.py", "input.txt"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=source, check=True)

    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=source)
    bundle = tmp_path / "bundle"
    _write_reproduction_bundle(manifest, source, bundle)
    receipt.save_to_directory(bundle)

    assert reproduce_run_receipt(bundle, rerun=True) == 0
    output = capsys.readouterr().out
    assert "Level: CONTENT_IDENTICAL (declared-output scope)" in output
    assert "Scope: declared output artifacts and execution outcome" in output


def test_same_outcome_with_changed_output_earns_no_reproduction_level(tmp_path, capsys):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt.save_to_directory(proj)
    (proj / "manifest.source.json").write_text(json.dumps(manifest), encoding="utf-8")
    (proj / "input.txt").write_text("22", encoding="utf-8")

    assert reproduce_run_receipt(proj, rerun=True) == 1
    output = capsys.readouterr().out
    assert "Level: NOT_DEMONSTRATED" in output
    assert "RESULT_EQUIVALENT" not in output
    assert "SEMANTIC_REPRODUCTION" not in output


def test_no_declared_outputs_cannot_vacuously_reproduce(tmp_path, capsys):
    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["outputs"] = []
    receipt = capture_run(manifest, manifest_dir=proj)
    receipt.save_to_directory(proj)
    (proj / "manifest.source.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert reproduce_run_receipt(proj, rerun=True) == 1
    assert "Level: NOT_DEMONSTRATED" in capsys.readouterr().out


def test_provenance_linkage_uses_public_graph_fixture(tmp_path):
    """Resolve linkage without depending on a receipt absent from the public tree."""
    data_receipt_file, artifact_id = _write_data_receipt(tmp_path)

    from verifier.core.run import _resolve_provenance_linkage

    linkage = _resolve_provenance_linkage(
        tmp_path,
        {"dataset_receipt_path": str(data_receipt_file.parent.name), "artifact_id": artifact_id},
    )
    assert linkage.found_in_hypergraph is True
    assert linkage.ancestor_count is not None

    missing = _resolve_provenance_linkage(
        tmp_path,
        {"dataset_receipt_path": str(data_receipt_file.parent.name), "artifact_id": "artifact:missing"},
    )
    assert missing.found_in_hypergraph is False
    assert missing.ancestor_count is None


def test_blast_radius_revocation_flags_dependent_run_receipts(tmp_path):
    """Revoking an upstream VSTD-DATA artifact must surface which recorded runs
    consumed it (directly or via a downstream derivative) — composing dataset
    provenance into run-receipt impact analysis rather than a parallel system.
    """
    data_receipt_file, artifact_id = _write_data_receipt(tmp_path)

    proj = _write_tiny_project(tmp_path)
    manifest = _base_manifest()
    manifest["provenance_roots"] = [
        {
            "dataset_receipt_path": str(data_receipt_file.parent),
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

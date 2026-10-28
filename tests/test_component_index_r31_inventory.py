"""R31 public-source inventory controls for the static component index."""
from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile

from scripts import build_component_index as component_index_builder
from verifier.interoperability.component_index import load_component_index
from verifier.interoperability.storage import load_component_package


ROOT = Path(__file__).resolve().parents[1]
REVIEWED_R31_UNTRACKED_PUBLIC_SOURCES = {
    "src/verifier/domains/contracts/dangerous_pathway_security.py",
    "src/verifier/runtime/prdel_evidence.py",
    "src/verifier/runtime/package_self_polish.py",
    "src/verifier/runtime/package_self_polish_recheck.py",
    "src/verifier/runtime/package_obligation_candidate.py",
    "src/verifier/runtime/package_owner_decision.py",
    "src/verifier/runtime/security_cli.py",
    "src/verifier/runtime/self_polish_estate.py",
    "src/verifier/runtime/self_polish_estate_authority.py",
    "src/verifier/runtime/self_polish_estate_evidence.py",
    "src/verifier/runtime/self_polish_estate_native_evidence.py",
    "src/verifier/runtime/self_polish_evidence.py",
    "src/verifier/runtime/self_polish_facet_reasons.py",
    "src/verifier/runtime/self_polish_native_cases.py",
    "src/verifier/runtime/self_polish_native_adapters.py",
    "src/verifier/runtime/self_polish_native_extension_replay.py",
    "src/verifier/runtime/self_polish_native_extensions.py",
    "src/verifier/runtime/self_polish_native_full_candidate.py",
    "src/verifier/runtime/self_polish_native_replay.py",
    "src/verifier/runtime/self_polish_native_sim_case_patch.py",
    "src/verifier/runtime/self_polish_native_tier3_cases.py",
    "src/verifier/runtime/self_polish_native_tier4_cases.py",
    "src/verifier/runtime/self_polish_native_tier5_cases.py",
    "src/verifier/runtime/self_polish_native_tier6_cases.py",
    "src/verifier/runtime/self_polish_native_tier7_cases.py",
    "src/verifier/runtime/self_polish_native_tier8_cases.py",
    "src/verifier/runtime/self_polish_native_tier9_cases.py",
    "src/verifier/runtime/self_polish_tiers.py",
    "src/verifier/runtime/tier_zero.py",
    "src/verifier/runtime/tier_zero_manifest.py",
    "src/verifier/runtime/tier_zero_profile.py",
    "src/verifier/runtime/tier_zero_reasons.py",
    "src/verifier/runtime/tier_zero_reconcile.mjs",
    "src/verifier/schemas/claim-garden-dangerous-pathway-assessment-1.schema.json",
    "src/verifier/schemas/claim-garden-dangerous-pathway-assessment-2.schema.json",
    "src/verifier/schemas/verifier-dangerous-pathway-certificate-1.schema.json",
    "src/verifier/schemas/verifier-dangerous-pathway-request-1.schema.json",
    "src/verifier/schemas/verifier-prdel-replay-plan-1.schema.json",
    "src/verifier/schemas/verifier-package-graph-self-polish-assessment-1.schema.json",
    "src/verifier/schemas/verifier-package-graph-self-polish-recheck-1.schema.json",
    "src/verifier/schemas/verifier-package-obligation-candidate-selection-1.schema.json",
    "src/verifier/schemas/verifier-objects-manifest-1.schema.json",
    "src/verifier/schemas/verifier-self-polish-native-replay-manifest-2.schema.json",
    "src/verifier/schemas/verifier-self-polish-native-replay-receipt-2.schema.json",
    "src/verifier/standard/DANGEROUS_PATHWAY_SECURITY.md",
    "src/verifier/standard/SELF_POLISH_ESTATE.md",
    "src/verifier/standard/SELF_POLISH_EVIDENCE.md",
    "src/verifier/standard/SELF_POLISH_FACET_REASONS.md",
    "src/verifier/standard/SELF_POLISH_TIERS.md",
    "src/verifier/standard/PACKAGE_SELF_POLISH.md",
    "src/verifier/standard/PACKAGE_OWNER_DECISIONS.md",
    "src/verifier/standard/TIER_ZERO.md",
}
R31_MODIFIED_POLISH_PUBLIC_SOURCES = {
    "src/verifier/runtime/polish.py",
    "src/verifier/runtime/polish_requirements.py",
    "src/verifier/standard/POLISH_REQUIREMENTS.md",
}
R31_PUBLIC_SOURCE_PATHS = (
    REVIEWED_R31_UNTRACKED_PUBLIC_SOURCES
    | R31_MODIFIED_POLISH_PUBLIC_SOURCES
    | {
        "src/verifier/domains/contracts/native_child_links.py",
        "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py",
        "src/verifier/domains/contracts/sim_dynamics.py",
        "src/verifier/domains/contracts/sim_external_law.py",
        "src/verifier/profiles/prdel-native-v2-cli-selection-2.json",
        "src/verifier/profiles/prdel-native-v2-selection-2.json",
        "src/verifier/runtime/gate.py",
        "src/verifier/runtime/prdel.py",
        "src/verifier/runtime/prdel_coverage.py",
        "src/verifier/runtime/public_cli.py",
        "src/verifier/schemas/verifier-prdel-2.schema.json",
        "src/verifier/standard/PRDEL_NATIVE_V2.md",
        "src/verifier/standard/PRDEL_NATIVE_V2_CLI.md",
        "src/verifier/standard/CURRENT_SIM_DYNAMICS.md",
        "src/verifier/standard/CURRENT_SIM_EXTERNAL_LAW.md",
    }
)
R31_INAPPLICABLE_ARCHIVE_PATHS = {
    "scripts/build_self_polish_tier1_ledger.py",
    "scripts/check_prdel_v2_selection.py",
    "scripts/check_prdel_v2_selection_r2.py",
    "tests/test_build_self_polish_tier1_ledger.py",
    "tests/test_dangerous_pathway_security.py",
    "tests/test_prdel_v2_evidence_replay.py",
    "tests/test_self_polish_estate_authority.py",
    "tests/test_self_polish_estate_evidence.py",
    "tests/test_self_polish_estate.py",
    "tests/test_self_polish_evidence.py",
    "tests/test_self_polish_tiers.py",
}


def _builder():
    return component_index_builder


def _captured_source_paths(package) -> set[str]:
    artifacts = {item.path: item.content for item in package.artifacts}
    captured = {
        path for path in artifacts if path.startswith("src/verifier/")
    }
    archive_bytes = artifacts.get("source-archive/exact-public-source.zip")
    if archive_bytes is not None:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            inventory = json.loads(archive.read("source-inventory.json"))
        captured.update(row["path"] for row in inventory["files"])
    return captured


def test_reviewed_candidates_are_only_exporter_eligible_public_sources() -> None:
    reviewed = set(_builder().REVIEWED_CANDIDATE_SOURCE_PATHS)

    assert R31_PUBLIC_SOURCE_PATHS <= reviewed
    assert not reviewed & R31_INAPPLICABLE_ARCHIVE_PATHS
    assert all((ROOT / path).is_file() for path in R31_INAPPLICABLE_ARCHIVE_PATHS)
    assert all(
        path.startswith("src/verifier/")
        and Path(path).suffix in {".py", ".json", ".md", ".mjs"}
        for path in reviewed
    )
    assert all((ROOT / path).is_file() for path in reviewed)


def test_worktree_archive_contains_complete_r31_public_source_increment(
        tmp_path: Path) -> None:
    module = _builder()
    output = tmp_path / "components"

    module.build(output, source_ref="WORKTREE")

    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(
        output / entry.package_path,
        expected_digest=entry.package_sha256,
    )
    captured = _captured_source_paths(package)
    assert R31_PUBLIC_SOURCE_PATHS <= captured
    assert not captured & R31_INAPPLICABLE_ARCHIVE_PATHS

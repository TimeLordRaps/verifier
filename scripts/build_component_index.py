#!/usr/bin/env python3
"""Terminology: Hypertext Markup Language (HTML); Hypertext Transfer Protocol Secure
(HTTPS); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource locator (URL);
Verifier Standard (VSTD).

Build a host-neutral static component index from the exact public source checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
DEFAULT_BASE_URL = "https://timelordraps.github.io/verifier/"
FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
REVIEWED_CANDIDATE_SOURCE_PATHS = (
    "src/verifier/domains/contracts/dangerous_pathway_security.py",
    "src/verifier/domains/contracts/native_child_links.py",
    "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py",
    "src/verifier/domains/contracts/sim_dynamics.py",
    "src/verifier/domains/contracts/sim_external_law.py",
    "src/verifier/domains/contracts/verifier_replacement.py",
    "src/verifier/standard/CURRENT_VERIFIER_REPLACEMENT.md",
    "src/verifier/domains/contracts/verifier_composed_security.py",
    "src/verifier/runtime/permission_slot.py",
    "src/verifier/standard/CURRENT_PERMISSION_SLOT.md",
    "src/verifier/standard/CURRENT_VERIFIER_COMPOSED_SECURITY.md",
    "src/verifier/standard/SEMANTIC_CONTRACT_SELECTION.md",
    "src/verifier/runtime/native_operation_contracts.py",
    "src/verifier/runtime/native_operation_cli.py",
    "src/verifier/standard/CURRENT_NATIVE_OPERATION_CONTRACTS.md",
    "src/verifier/schemas/native-replay-operation-descriptor-1.schema.json",
    "src/verifier/schemas/native-replay-operation-lookup-1.schema.json",
    "src/verifier/schemas/verifier-prdel-compilation-shards-1.schema.json",
    "src/verifier/schemas/verifier-prdel-compilation-shards-2.schema.json",
    "src/verifier/schemas/verifier-prdel-shard-description-1.schema.json",
    "src/verifier/profiles/prdel-manifest-2-selection.json",
    "src/verifier/profiles/prdel-native-v2-selection-1.json",
    "src/verifier/profiles/prdel-native-v2-selection-2.json",
    "src/verifier/profiles/prdel-native-v2-cli-selection-2.json",
    "src/verifier/runtime/gate.py",
    "src/verifier/runtime/prdel.py",
    "src/verifier/runtime/prdel_coverage.py",
    "src/verifier/runtime/prdel_evidence.py",
    "src/verifier/runtime/prdel_graph.py",
    "src/verifier/runtime/prdel_rules.py",
    "src/verifier/runtime/prdel_shard_index.py",
    "src/verifier/runtime/prdel_v2_shards.py",
    "src/verifier/runtime/public_cli.py",
    "src/verifier/schemas/verifier-prdel-2.schema.json",
    "src/verifier/schemas/verifier-prdel-cli-2.schema.json",
    "src/verifier/schemas/verifier-prdel-replay-plan-1.schema.json",
    "src/verifier/schemas/verifier-package-graph-self-polish-assessment-1.schema.json",
    "src/verifier/schemas/verifier-package-graph-self-polish-recheck-1.schema.json",
    "src/verifier/schemas/verifier-package-obligation-candidate-selection-1.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-document-shard-1.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-release-subject-2.schema.json",
    "src/verifier/schemas/verifier-prdel-v2-shard-manifest-1.schema.json",
    "src/verifier/standard/PRDEL_NATIVE_V2.md",
    "src/verifier/standard/PRDEL_NATIVE_V2_CLI.md",
    "src/verifier/runtime/core_application_release.py",
    "src/verifier/runtime/core_application_authority.py",
    "src/verifier/runtime/core_security9_accounting.py",
    "src/verifier/runtime/core_obligation_union.py",
    "src/verifier/runtime/core_tier_progression.py",
    "src/verifier/standard/CORE_NINE_TIER_RELEASE.md",
    "src/verifier/standard/CORE_APPLICATION_AUTHORITY.md",
    "src/verifier/standard/CORE_FULL_GATE_REPLAY.md",
    "src/verifier/standard/CORE_SECURITY9_ACCOUNTING.md",
    "src/verifier/standard/CORE_SECURITY9_REQUIREMENTS.md",
    "src/verifier/standard/CORE_OBLIGATION_UNION.md",
    "src/verifier/runtime/application_release.py",
    "src/verifier/standard/APPLICATION_RELEASE_CONSUMER.md",
    "src/verifier/runtime/tier_progression.py",
    "src/verifier/standard/CURRENT_TEN_TIER_PROGRESSION.md",
    "src/verifier/runtime/polish_findings.py",
    "src/verifier/runtime/polish.py",
    "src/verifier/runtime/release_source_binding.py",
    "src/verifier/corrigibility/train_control.py",
    "src/verifier/corrigibility/train_profile.py",
    "src/verifier/standard/TRAIN_CONTROL.md",
    "src/verifier/domains/contracts/subject_security.py",
    "src/verifier/runtime/polish_requirements.py",
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
    # Explicit inert source inventory for admission and its existing package
    # dependencies. Inclusion grants no execution or qualification authority.
    "src/verifier/runtime/namespace_admission.py",
    "src/verifier/runtime/namespace_classification.py",
    "src/verifier/runtime/namespace_cli.py",
    "src/verifier/runtime/namespace_contracts.py",
    "src/verifier/runtime/namespace_discovery.py",
    "src/verifier/runtime/namespace_manifest.py",
    "src/verifier/runtime/namespace_reconcile.mjs",
    "src/verifier/runtime/package_manifest.py",
    "src/verifier/runtime/package_admission.py",
    "src/verifier/runtime/manifest_gate.py",
    "src/verifier/runtime/package_manifest_migration.py",
    "src/verifier/runtime/package_manifest_refresh.py",
    "src/verifier/runtime/package_polish.py",
    "src/verifier/runtime/package_polish_schema_validation.py",
    "src/verifier/runtime/self_polish_statics.py",
    "src/verifier/runtime/self_polish_dynamics.py",
    "src/verifier/runtime/language_runners.py",
    # Explicitly reviewed repository-admission and package-graph implementation.
    # These paths remain inert inputs to the public component index: listing a
    # candidate here neither executes it nor grants it qualification authority.
    "src/verifier/core/run_process_observation.py",
    "src/verifier/runtime/hardware_cli_support.py",
    "src/verifier/runtime/hardware_discovery_cli.py",
    "src/verifier/runtime/hardware_probe_cli.py",
    "src/verifier/runtime/hardware_receipt_cli.py",
    "src/verifier/runtime/hardware_registry_cli.py",
    "src/verifier/runtime/local_ledger_control_checks.py",
    "src/verifier/runtime/local_ledger_controls.py",
    "src/verifier/runtime/local_ledger_execution.py",
    "src/verifier/runtime/local_ledger_worker.py",
    "src/verifier/runtime/manifest_write_execution.py",
    "src/verifier/runtime/manifest_write_worker.py",
    "src/verifier/runtime/namespace_consequences.mjs",
    "src/verifier/runtime/namespace_consequences.py",
    "src/verifier/runtime/namespace_dominance.py",
    "src/verifier/runtime/namespace_exports.py",
    "src/verifier/runtime/namespace_html.py",
    "src/verifier/runtime/namespace_javascript.py",
    "src/verifier/runtime/namespace_javascript_worker.py",
    "src/verifier/runtime/namespace_metadata.py",
    "src/verifier/runtime/namespace_rust_expansions.py",
    "src/verifier/runtime/namespace_source_imports.py",
    "src/verifier/runtime/namespace_svg.py",
    "src/verifier/runtime/namespace_systems.py",
    "src/verifier/runtime/namespace_systems_worker.py",
    "src/verifier/runtime/namespace_workflow_worker.py",
    "src/verifier/runtime/namespace_workflows.py",
    "src/verifier/runtime/package_contract_coverage.py",
    "src/verifier/runtime/package_execution.py",
    "src/verifier/runtime/package_execution_observation.py",
    "src/verifier/runtime/package_graph_representation.py",
    "src/verifier/runtime/package_harness_applicability.py",
    "src/verifier/runtime/package_instance_evidence.py",
    "src/verifier/runtime/package_kind_requirements.py",
    "src/verifier/runtime/package_namespace_review.py",
    "src/verifier/runtime/package_original_review_computation.py",
    "src/verifier/runtime/package_original_review_people.py",
    "src/verifier/runtime/package_original_review_systems.py",
    "src/verifier/runtime/package_semantic_ownership.py",
    "src/verifier/runtime/package_semantic_ownership_domains.py",
    "src/verifier/runtime/package_semantic_ownership_experiments.py",
    "src/verifier/runtime/package_semantic_ownership_hardware_interop.py",
    "src/verifier/runtime/package_semantic_ownership_model.py",
    "src/verifier/runtime/package_semantic_ownership_normative_assets.py",
    "src/verifier/runtime/package_semantic_ownership_public_cli.py",
    "src/verifier/runtime/package_semantic_ownership_python_apps.py",
    "src/verifier/runtime/package_semantic_ownership_repository_assets.py",
    "src/verifier/runtime/package_semantic_ownership_scripts_examples.py",
    "src/verifier/runtime/package_semantic_ownership_tests_fixtures.py",
    "src/verifier/runtime/package_semantic_review_admission.py",
    "src/verifier/runtime/package_semantic_review_commands.py",
    "src/verifier/runtime/package_semantic_review_core.py",
    "src/verifier/runtime/package_semantic_review_hardware_cli.py",
    "src/verifier/runtime/package_semantic_review_operations.py",
    "src/verifier/runtime/package_semantic_review_package_object.py",
    "src/verifier/runtime/package_semantic_review_partitions.py",
    "src/verifier/runtime/package_semantic_review_polish.py",
    "src/verifier/runtime/package_semantic_review_records.py",
    "src/verifier/runtime/package_semantic_review_scripts.py",
    "src/verifier/runtime/package_semantic_review_self_polish.py",
    "src/verifier/runtime/package_semantic_review_subjects.py",
    "src/verifier/runtime/package_semantic_review_verifier.py",
    "src/verifier/runtime/package_source_contracts.py",
    "src/verifier/runtime/polish_cli.py",
    "src/verifier/runtime/polish_workflow_cli.py",
    "src/verifier/runtime/provenance_policy_execution.py",
    "src/verifier/runtime/provenance_policy_worker.py",
    "src/verifier/runtime/resource_measurement_execution.py",
    "src/verifier/runtime/resource_measurement_worker.py",
    "src/verifier/runtime/worker_protocol_execution.py",
    "src/verifier/runtime/worker_protocol_worker.py",
    "src/verifier/schemas/verifier-package-contract-coverage-1.schema.json",
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
    "src/verifier/domains/contracts/sim_fresh_worker.py",
    "src/verifier/domains/contracts/sim_resource_fresh.py",
    "src/verifier/schemas/verifier-manifest-object-gate-1.schema.json",
    "src/verifier/schemas/verifier-manifest-package-polish-1.schema.json",
    "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json",
    "src/verifier/schemas/verifier-manifest-package-polish-publication-rejected-1.schema.json",
    "src/verifier/schemas/verifier-objects-manifest-2.schema.json",
    "src/verifier/schemas/verifier-objects-manifest-3.schema.json",
    "src/verifier/schemas/verifier-objects-manifest-4.schema.json",
    "src/verifier/schemas/verifier-objects-manifest-5.schema.json",
    "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json",
    "src/verifier/schemas/verifier-polish-manifest-refresh-blocked-1.schema.json",
    "src/verifier/standard/EXTENSIBLE_NAMESPACE.md",
    "src/verifier/standard/CURRENT_SIM_RESOURCE_FRESH.md",
    "src/verifier/standard/LANGUAGE_RUNNERS.md",
    "src/verifier/standard/PACKAGE_POLISH.md",
    "src/verifier/standard/SELF_POLISH_STATICS.md",
    "src/verifier/schemas/verifier-objects-manifest-1.schema.json",
    "src/verifier/standard/CURRENT_SUBJECT_SECURITY.md",
    "src/verifier/standard/DANGEROUS_PATHWAY_SECURITY.md",
    "src/verifier/standard/POLISH_REQUIREMENTS.md",
    "src/verifier/standard/PACKAGE_SELF_POLISH.md",
    "src/verifier/standard/PACKAGE_OWNER_DECISIONS.md",
    "src/verifier/standard/SELF_POLISH_ESTATE.md",
    "src/verifier/standard/SELF_POLISH_EVIDENCE.md",
    "src/verifier/standard/SELF_POLISH_FACET_REASONS.md",
    "src/verifier/standard/SELF_POLISH_TIERS.md",
    "src/verifier/standard/TIER_ZERO.md",
    "src/verifier/standard/CURRENT_SIM_DYNAMICS.md",
    "src/verifier/standard/CURRENT_SIM_EXTERNAL_LAW.md",
    "src/verifier/domains/hardware.py",
    "src/verifier/interoperability/authority_composition.py",
    "src/verifier/interoperability/bounded_completeness.py",
    "src/verifier/interoperability/claim_garden.py",
    "src/verifier/interoperability/composition_qualification.py",
    "src/verifier/interoperability/deriver_self_status.py",
    "src/verifier/interoperability/formation_checker.py",
    "src/verifier/interoperability/formation_mechanism.py",
    "src/verifier/interoperability/formation_producer.py",
    "src/verifier/interoperability/formation_receipt.py",
    "src/verifier/interoperability/formation_storage.py",
    "src/verifier/interoperability/formation_wire.py",
    "src/verifier/interoperability/global_cycle_assessment.py",
    "src/verifier/interoperability/network.py",
    "src/verifier/interoperability/proposition_transfer.py",
    "src/verifier/interoperability/relation_boundary.py",
    "src/verifier/interoperability/runtime_authority_correspondence.py",
    "src/verifier/interoperability/source_grounding.py",
    "src/verifier/profiles/bounded-completeness-mechanism-1.json",
    "src/verifier/profiles/deriver-self-status-checker-1.json",
    "src/verifier/profiles/proposition-transfer-rule-1.json",
    "src/verifier/profiles/relation-boundary-mechanism-1.json",
    "src/verifier/profiles/runtime-authority-correspondence-profile-1.json",
    "src/verifier/profiles/source-grounding-mechanism-1.json",
    "src/verifier/profiles/typed-formation-1.json",
    "src/verifier/runtime/network_cli.py",
    "src/verifier/schemas/__init__.py",
    "src/verifier/schemas/artifact-control-1.schema.json",
    "src/verifier/schemas/claim-garden-dangerous-pathway-assessment-1.schema.json",
    "src/verifier/schemas/claim-garden-dangerous-pathway-assessment-2.schema.json",
    "src/verifier/schemas/graph-topology.schema.json",
    "src/verifier/schemas/verifier-artifact-network-1.schema.json",
    "src/verifier/schemas/verifier-authority-model-1.schema.json",
    "src/verifier/schemas/verifier-bounded-completeness-1.schema.json",
    "src/verifier/schemas/verifier-component-index-1.schema.json",
    "src/verifier/schemas/verifier-component-package-1.schema.json",
    "src/verifier/schemas/verifier-component-package-2.schema.json",
    "src/verifier/schemas/verifier-deriver-self-status-1.schema.json",
    "src/verifier/schemas/verifier-dangerous-pathway-certificate-1.schema.json",
    "src/verifier/schemas/verifier-dangerous-pathway-request-1.schema.json",
    "src/verifier/schemas/verifier-global-cycle-assessment-1.schema.json",
    "src/verifier/schemas/verifier-graph-assurance-1.schema.json",
    "src/verifier/schemas/verifier-proposition-transfer-1.schema.json",
    "src/verifier/schemas/verifier-push-request-1.schema.json",
    "src/verifier/schemas/verifier-relation-boundary-1.schema.json",
    "src/verifier/schemas/verifier-self-derivation-mechanism-1.schema.json",
    "src/verifier/schemas/verifier-self-polish-native-replay-manifest-2.schema.json",
    "src/verifier/schemas/verifier-self-polish-native-replay-receipt-2.schema.json",
    "src/verifier/schemas/verifier-silo-assessment-1.schema.json",
    "src/verifier/schemas/verifier-silo-assessment-receipt-1.schema.json",
    "src/verifier/schemas/verifier-silo-composition-1.schema.json",
    "src/verifier/schemas/verifier-silo-composition-assessment-1.schema.json",
    "src/verifier/schemas/verifier-silo-composition-assessment-receipt-1.schema.json",
    "src/verifier/schemas/verifier-silo-formation-receipt-1.schema.json",
    "src/verifier/schemas/verifier-silo-transfer-1.schema.json",
    "src/verifier/schemas/verifier-source-grounding-1.schema.json",
    "src/verifier/schemas/verifier-typed-formation-1.schema.json",
    "src/verifier/standard/BOUNDED_COMPLETENESS.md",
    "src/verifier/standard/DERIVER_SELF_STATUS.md",
    "src/verifier/standard/FINITE_AUTHORITY_COMPOSITION.md",
    "src/verifier/standard/FORMATION_RECEIPT.md",
    "src/verifier/standard/GLOBAL_CYCLE_ASSESSMENT.md",
    "src/verifier/standard/PROPOSITION_TRANSFER.md",
    "src/verifier/standard/RELATION_BOUNDARY.md",
    "src/verifier/standard/RUNTIME_AUTHORITY_CORRESPONDENCE.md",
    "src/verifier/standard/SOURCE_GROUNDING.md",
    "src/verifier/standard/TYPED_FORMATION.md",
)


class ComponentIndexBuildError(RuntimeError):
    """The static index cannot be bound to the requested source coordinate."""


def _bind_checkout_source() -> None:
    """Make imports resolve against this exact checkout, not an installed release."""

    source = str(SOURCE)
    sys.path[:] = [entry for entry in sys.path if entry != source]
    sys.path.insert(0, source)


def _project_version() -> str:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', project, re.MULTILINE)
    if match is None:
        raise ComponentIndexBuildError("project version is not readable")
    return match.group(1)


def _head() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode or not FULL_COMMIT.fullmatch(result.stdout.strip()):
        raise ComponentIndexBuildError("component index requires an exact Git checkout")
    return result.stdout.strip().lower()


def _worktree_dirty() -> bool:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=normal"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ComponentIndexBuildError("component index requires readable Git status")
    return bool(result.stdout)


def _reviewed_untracked_candidate_sources() -> tuple[str, ...]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *REVIEWED_CANDIDATE_SOURCE_PATHS,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ComponentIndexBuildError("cannot inspect reviewed candidate source state")
    return tuple(entry.decode("utf-8") for entry in result.stdout.split(b"\0") if entry)


def _package_version(source_ref: str) -> str:
    base = _project_version()
    if FULL_COMMIT.fullmatch(source_ref):
        return f"{base}+git.{source_ref[:12].lower()}"
    return base


def _base_url(value: str) -> str:
    if not value.startswith("https://") or not value.endswith("/"):
        raise ComponentIndexBuildError("public base URL must be absolute HTTPS with a trailing slash")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise ComponentIndexBuildError("public base URL contains whitespace or control characters")
    return value


def _reference_exporter() -> Any:
    path = ROOT / "examples/stored_components/build_reference_package.py"
    _bind_checkout_source()
    spec = importlib.util.spec_from_file_location("vstd_reference_package_exporter", path)
    if spec is None or spec.loader is None:
        raise ComponentIndexBuildError("cannot load the first-party package exporter")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ComponentIndexBuildError("cannot initialize the first-party package exporter") from exc
    return module


def _render_html(index: Any, *, source_ref: str, base_url: str) -> str:
    report = index.inspect()
    rows: list[str] = []
    for package in index.packages:
        for component in package.registry.components:
            rows.append(
                "<tr>"
                f"<td><code>{html.escape(component.component_id)}</code></td>"
                f"<td>{html.escape(component.label)}</td>"
                f"<td>{html.escape(component.kind.value)}</td>"
                f"<td>{html.escape(component.lifecycle.value)}</td>"
                f"<td>{html.escape(', '.join(mode.value for mode in component.interaction_modes))}</td>"
                f"<td><code>{html.escape(package.package_sha256)}</code></td>"
                "</tr>"
            )
    canonical = base_url + "components/"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Exact, bounded VSTD component declarations from one static index.">
  <title>VSTD component index</title>
  <link rel="canonical" href="{html.escape(canonical, quote=True)}">
  <link rel="stylesheet" href="../assets/site.css">
</head>
<body>
  <a class="skip-link" href="#component-index">Skip to component index</a>
  <header class="wrap"><nav aria-label="Primary">
    <a class="brand" href="../index.html">VSTD</a><div class="links">
      <a href="../guides.html">Guides</a><a href="../reference.html">Reference</a>
      <a href="./" aria-current="page">Components</a>
      <a href="../standard/">Standard</a><a href="../project/ROADMAP.html">Project</a>
      <a href="https://github.com/TimeLordRaps/verifier">GitHub</a>
    </div>
  </nav></header>
  <main class="wrap doc-content" id="component-index">
    <p class="eyebrow">Static discovery · no fetching or execution</p>
    <h1>Component index</h1>
    <p>This page presents unsigned declarations from one exact, content-addressed index.
    Membership and matching do not establish availability, qualification, correctness,
    authorization, ecosystem completeness, or Verifier Standard conformance.</p>
    <dl>
      <dt>Source commit</dt><dd><code>{html.escape(source_ref)}</code></dd>
      <dt>Index digest</dt><dd><code>{html.escape(index.canonical_digest())}</code></dd>
      <dt>Packages</dt><dd>{report['package_count']}</dd>
      <dt>Components</dt><dd>{report['component_count']}</dd>
      <dt>Package availability</dt><dd><code>NOT_CHECKED</code></dd>
      <dt>Native qualification</dt><dd><code>NOT_ESTABLISHED</code></dd>
      <dt>Ecosystem completeness</dt><dd><code>UNKNOWN</code></dd>
    </dl>
    <p><a href="index.json">Canonical index JSON</a> ·
    <a href="index.sha256">Exact index SHA-256 digest</a> ·
    <a href="deployment-coordinate.json">Deployment coordinate</a> ·
    <a href="../docs/COMPONENT_HUB.html">Interpretation and command-line use</a></p>
    <div class="table-scroll"><table>
      <thead><tr><th>Component identifier</th><th>Declared label</th><th>Kind</th>
      <th>Lifecycle</th><th>Interaction modes</th><th>Package digest</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>
    <p class="status">{html.escape(report['claim_boundary'])}</p>
  </main>
  <footer><div class="wrap">VSTD · Apache-2.0 · Maintainer-led alpha · No component execution or ranking.</div></footer>
</body>
</html>
"""


def build(
    output: Path,
    *,
    source_ref: str,
    base_url: str = DEFAULT_BASE_URL,
    include_untracked: Sequence[str] | None = None,
) -> tuple[Path, ...]:
    """Build the static surface into an absent directory and return its files."""

    _bind_checkout_source()
    from verifier.interoperability.component_index import (
        IndexedComponentPackage,
        StoredComponentIndex,
        load_component_index,
        save_component_index,
    )
    from verifier.interoperability.storage import load_component_package, save_component_package

    output = output.resolve()
    if output.exists():
        raise ComponentIndexBuildError("component index output must not already exist")
    source_ref = source_ref.strip()
    if not source_ref or len(source_ref) > 4096:
        raise ComponentIndexBuildError("source_ref must be nonempty bounded text")
    head = _head()
    if source_ref != "WORKTREE" and not FULL_COMMIT.fullmatch(source_ref):
        raise ComponentIndexBuildError("source_ref must be WORKTREE or a full Git commit")
    if FULL_COMMIT.fullmatch(source_ref):
        if source_ref.lower() != head:
            raise ComponentIndexBuildError("source_ref does not identify the exact checkout HEAD")
        if _worktree_dirty():
            raise ComponentIndexBuildError(
                "a commit-addressed component index requires a clean exact checkout"
            )
    public_base_url = _base_url(base_url)

    exporter = _reference_exporter()
    reviewed_untracked = (
        _reviewed_untracked_candidate_sources()
        if source_ref == "WORKTREE" and include_untracked is None
        else tuple(include_untracked or ())
    )
    if reviewed_untracked:
        package = exporter.build_package(
            ROOT,
            _package_version(source_ref),
            include_untracked=reviewed_untracked,
            package_schema_version="verifier-component-package-2",
        )
    else:
        package = exporter.build_package(ROOT, _package_version(source_ref), package_schema_version="verifier-component-package-2")
    entry = IndexedComponentPackage.from_package(package)
    index = StoredComponentIndex(
        index_id="timelordraps/verifier-reference-components",
        index_version=_package_version(source_ref),
        description=(
            "First-party VSTD reference declarations from one exact public source snapshot; "
            "static discovery only, with no fetching, installation, execution, ranking, "
            "latest-version selection, native qualification, or ecosystem-completeness claim."
        ),
        packages=(entry,),
    )

    package_path = output / Path(entry.package_path)
    package_path.parent.mkdir(parents=True)
    save_component_package(package, package_path)
    loaded_package = load_component_package(package_path, expected_digest=entry.package_sha256)
    entry.validate_package(loaded_package)

    index_path = output / "index.json"
    save_component_index(index, index_path)
    loaded_index = load_component_index(index_path, expected_digest=index.canonical_digest())
    if loaded_index != index:
        raise ComponentIndexBuildError("saved component index did not reproduce exactly")

    digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
    if digest != index.canonical_digest():
        raise ComponentIndexBuildError("saved index bytes do not match canonical identity")
    digest_path = output / "index.sha256"
    digest_path.write_text(f"{digest}  index.json\n", encoding="ascii", newline="\n")
    coordinate_path = output / "deployment-coordinate.json"
    coordinate = {
        "schema_version": 1,
        "source_ref": source_ref,
        "base_url": public_base_url,
        "index_path": "index.json",
        "index_sha256": digest,
    }
    coordinate_path.write_text(
        json.dumps(coordinate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    html_path = output / "index.html"
    html_path.write_text(
        _render_html(index, source_ref=source_ref, base_url=public_base_url),
        encoding="utf-8",
        newline="\n",
    )
    return (html_path, index_path, digest_path, coordinate_path, package_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    arguments = parser.parse_args(argv)
    try:
        written = build(
            arguments.output,
            source_ref=arguments.source_ref,
            base_url=arguments.base_url,
        )
    except (ComponentIndexBuildError, OSError, ValueError) as exc:
        parser.exit(2, f"Component index build refused: {exc}\n")
    print(
        f"[COMPONENT INDEX OK] wrote {len(written)} files; "
        f"index digest {Path(arguments.output, 'index.sha256').read_text(encoding='ascii').split()[0]}"
    )
    print("No package was fetched, installed, imported, executed, ranked, or selected as latest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

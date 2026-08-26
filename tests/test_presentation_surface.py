"""Terminology: application programming interface (API); Concise Binary Object Representation (CBOR);
CBOR Object Signing and Encryption (COSE); continuous integration (CI);
Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD).

The public first impression is a checked repository surface."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_professional_presentation_surface_has_no_drift() -> None:
    path = ROOT / "scripts/check_presentation.py"
    spec = importlib.util.spec_from_file_location("check_presentation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.run() == []


def test_acronym_gate_rejects_missing_and_late_first_use(tmp_path: Path) -> None:
    path = ROOT / "scripts/check_acronyms.py"
    spec = importlib.util.spec_from_file_location("check_acronyms_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    docs = tmp_path / "docs"
    docs.mkdir()
    glossary = docs / "ACRONYMS.md"
    glossary.write_text(
        "| Term | Expansion | Note |\n"
        "|---|---|---|\n"
        "| `API` | application programming interface | interface |\n"
        "| `VSTD` | Verifier Standard | standard |\n",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text("# VSTD API\n\nVerifier Standard (VSTD).\n", encoding="utf-8")
    module.ROOT = tmp_path
    module.GLOSSARY = glossary

    errors = module.validate_repo()
    assert any("VSTD appears before its expansion" in error for error in errors)
    assert any("API is not expanded" in error for error in errors)

    readme.write_text(
        "# Verifier Standard (VSTD) application programming interface (API)\n",
        encoding="utf-8",
    )
    assert module.validate_repo() == []


def test_public_boundary_catches_private_coordinates_without_naming_them() -> None:
    path = ROOT / "scripts" / "check_presentation.py"
    spec = importlib.util.spec_from_file_location("check_presentation_boundaries", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    drive_path = "E:" + "\\" + "private-workspace" + "\\" + "plan.md"
    private_locator = "evaluator" + "-vault://artifact"
    local_artifact = "private-model" + ".gguf"
    deployment_field = "model" + "_path"
    assert "drive-qualified local path" in module.public_boundary_violations(drive_path)
    assert "synthetic private locator" in module.public_boundary_violations(private_locator)
    assert "local model artifact filename" in module.public_boundary_violations(local_artifact)
    assert "private deployment field" in module.public_boundary_violations(deployment_field)


def test_maturity_table_requires_each_major_surface_and_explicit_conformance() -> None:
    path = ROOT / "scripts" / "check_presentation.py"
    spec = importlib.util.spec_from_file_location("check_presentation_maturity", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert module.maturity_table_violations(readme) == []

    combined = readme.replace("| VSTD-Graph-3 |", "| VSTD-Graph-2 |", 1)
    errors = module.maturity_table_violations(combined)
    assert any("VSTD-Graph-2" in error and "observed 2" in error for error in errors)
    assert any("VSTD-Graph-3" in error and "observed 0" in error for error in errors)


def test_long_lived_docs_reject_transient_time_state() -> None:
    path = ROOT / "scripts" / "check_presentation.py"
    spec = importlib.util.spec_from_file_location("check_presentation_time", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.transient_time_status_violations("TIME.md is CLEAR today")
    assert module.transient_time_status_violations("TIME == OPEN")
    assert module.transient_time_status_violations(
        "TIME.md is a contradiction annunciator"
    ) == []


def test_lineage_claim_gate_rejects_causal_upgrades_without_blocking_boundaries() -> None:
    path = ROOT / "scripts" / "check_presentation.py"
    spec = importlib.util.spec_from_file_location("check_presentation_lineage", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    causal_lineage = "causal" + " lineage"
    causal_ancestors = "causal" + " ancestors"
    causal_process = "causal" + " process"
    causal_contribution = "causally" + " contributed"
    for phrase in (
        causal_lineage,
        causal_ancestors,
        causal_process,
        causal_contribution,
    ):
        assert module.lineage_causality_violations(phrase)

    assert module.lineage_causality_violations("recorded lineage") == []
    assert module.lineage_causality_violations(
        "The recorded edge does not establish causal influence."
    ) == []


def test_pages_artifact_serves_every_canonical_schema_id(tmp_path: Path) -> None:
    path = ROOT / "scripts/build_pages.py"
    spec = importlib.util.spec_from_file_location("build_pages", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    output = tmp_path / "site"
    copied = module.build(output)
    assert (output / "index.html").is_file()
    assert (output / "guides.html").is_file()
    assert (output / "reference.html").is_file()
    sources = sorted((ROOT / "receipts/schema").glob("*.json"))
    assert [path.name for path in copied] == [path.name for path in sources]
    for source, deployed in zip(sources, copied):
        assert deployed.read_bytes() == source.read_bytes()
        assert json.loads(deployed.read_text(encoding="utf-8"))["$id"].endswith(
            f"/schemas/{deployed.name}"
        )


def test_architecture_map_names_every_published_schema() -> None:
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    for schema in (ROOT / "receipts" / "schema").glob("*.json"):
        assert schema.name in architecture, schema.name


def test_conformance_gate_requires_real_scitt_cose_integration() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    scitt_job = jobs["scitt-crypto"]
    steps = "\n".join(str(step.get("run", "")) for step in scitt_job["steps"])
    assert 'pip install ".[test,scitt]"' in steps
    assert "import cbor2, cryptography, scitt_cose" in steps
    assert "tests/test_scitt_crypto_example.py" in steps
    assert "scitt-crypto" in jobs["conformance-gate"]["needs"]


def test_pages_builder_refuses_to_merge_into_existing_content(tmp_path: Path) -> None:
    path = ROOT / "scripts/build_pages.py"
    spec = importlib.util.spec_from_file_location("build_pages_safety", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    output = tmp_path / "site"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    try:
        module.build(output)
    except module.PagesBuildError:
        pass
    else:
        raise AssertionError("Pages builder merged into non-empty output")
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_generated_reference_covers_commands_and_top_level_exports() -> None:
    """The docs tab is generated and must list its declared live surface."""

    path = ROOT / "scripts/build_reference.py"
    spec = importlib.util.spec_from_file_location("build_reference_coverage", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    page = (ROOT / "docs/reference.html").read_text(encoding="utf-8")
    assert page == module.render()

    import verifier
    from verifier.runtime.public_cli import build_parser

    for command in module._walk(build_parser()):
        anchor = 'id="cli-' + str(command["prog"]).replace(" ", "-") + '"'
        assert anchor in page, f"reference page omits {command['prog']}"
    for name in verifier.__all__:
        assert f'id="api-{name}"' in page, f"reference page omits export {name}"
    assert verifier.__standard__ == "VSTD-4"
    assert verifier.__standard_status__ == "CANDIDATE; CONFORMANCE NOT_ESTABLISHED"
    assert "VSTD-4 CANDIDATE; CONFORMANCE NOT_ESTABLISHED" in page
    assert "Enumeration of the exported result values." in page


def test_generated_reference_detects_drift() -> None:
    path = ROOT / "scripts/build_reference.py"
    spec = importlib.util.spec_from_file_location("build_reference_drift", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.PIPELINE = ((
        "vstd ghost",
        "A command that no longer exists.",
        ("verifier.core.run:not_a_real_entry_point",),
    ),)
    try:
        module.render()
    except module.ReferenceBuildError:
        pass
    else:
        raise AssertionError("reference build published a missing pipeline entry point")

"""Terminology: application programming interface (API); Concise Binary Object Representation (CBOR);
CBOR Object Signing and Encryption (COSE); continuous integration (CI); Hypertext Markup Language (HTML);
Supply Chain Integrity, Transparency, and Trust (SCITT); uniform resource locator (URL);
Verifier Standard (VSTD).

The public first impression is a checked repository surface."""

from __future__ import annotations

from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import unquote

import yaml


ROOT = Path(__file__).resolve().parents[1]


class _BuiltPageLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        for name in ("href", "src"):
            if attributes.get(name):
                self.links.append(attributes[name])


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


def test_terminology_gate_rejects_interchangeable_structural_terms() -> None:
    path = ROOT / "scripts/check_terminology.py"
    spec = importlib.util.spec_from_file_location("check_terminology_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ambiguous = "Graph level 3 depends on lower-layer conformance."
    labels = [label for label, _line in module.terminology_violations(ambiguous)]
    assert "Graph profile called a level" in labels
    assert "profile dependency called lower-layer" in labels
    assert module.terminology_violations(
        "Candidate Graph profile 3 depends on prerequisite-profile conformance."
    ) == []


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
    assert "## The 90-second mental model" in readme
    assert "Exact surface-by-surface matrix for reviewers and integrators" in readme
    assert readme.index("## The 90-second mental model") < readme.index(
        "## Current maturity"
    )

    combined = readme.replace("| VSTD-Graph-3 |", "| VSTD-Graph-2 |", 1)
    errors = module.maturity_table_violations(combined)
    assert any("VSTD-Graph-2" in error and "observed 2" in error for error in errors)
    assert any("VSTD-Graph-3" in error and "observed 0" in error for error in errors)


def test_artifact_state_vocabulary_is_process_bound_and_unambiguous() -> None:
    ladder = (ROOT / "standard" / "LADDER.md").read_text(encoding="utf-8")
    humans = (ROOT / "HUMANS.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")

    for text in (ladder, humans, agents, architecture):
        assert "TRUST" in text
        assert "ROT" in text
        assert "RUST" in text
    assert "whether an actor is good, bad" in ladder
    assert "zero unevidenced knowledge is presumed" in ladder
    assert "bearer- and artifact-bound, never prover-identity-bound" in ladder
    assert "inverse-TRUST diagnostic mechanic" in ladder
    assert "historical receipt" in ladder
    assert "actor ratings" in architecture


def test_standard_orients_readers_before_formal_terminology() -> None:
    ladder = (ROOT / "standard" / "LADDER.md").read_text(encoding="utf-8")
    orientation = ladder.index("### Read this first:")
    terminology = ladder.index("### Terminology contract")
    assert orientation < terminology
    assert "A field, document, or actor merely saying" in ladder
    assert "Its **object profile depth is 1**" in ladder
    assert "The cumulative checklist cannot skip the missing" in ladder
    assert "not a new verdict, evidence-strength rating" in ladder


def test_object_receipts_use_full_ladder_identifiers() -> None:
    vstd1 = json.loads(
        (ROOT / "receipts" / "schema" / "vstd1_receipt.json").read_text(encoding="utf-8")
    )
    generic = json.loads(
        (ROOT / "receipts" / "schema" / "vstd1_generic_run_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    vstd2 = json.loads(
        (ROOT / "receipts" / "schema" / "vstd2_receipt.json").read_text(encoding="utf-8")
    )

    assert vstd1["properties"]["schema_version"]["enum"] == ["VSTD-1"]
    assert vstd1["properties"]["receipt_kind"]["const"] == "claim_mechanics"
    assert generic["properties"]["schema_version"]["const"] == "VSTD-1"
    assert generic["properties"]["receipt_kind"]["const"] == "generic_computational_run"
    assert vstd2["properties"]["schema_version"]["const"] == "VSTD-2"


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
    copied = module.build(output, source_ref="test-commit")
    assert (output / "index.html").is_file()
    assert (output / "guides.html").is_file()
    assert (output / "reference.html").is_file()
    assert (output / "docs/QUICKSTART.html").is_file()
    assert (output / "standard/index.html").is_file()
    assert (output / "standard/ARTIFACT_CONTROL.html").is_file()
    assert (output / "experiments/index.html").is_file()
    assert (output / "project/ROADMAP.html").is_file()
    assert (output / "assets/orientation-previews.js").is_file()
    coordinate = json.loads(
        (output / "documentation-coordinate.json").read_text(encoding="utf-8")
    )
    assert coordinate == {
        "canonical_base_url": "https://timelordraps.github.io/verifier/",
        "documentation_version": "1.2.0",
        "normative_source": "standard/",
        "release_state": "RELEASED",
        "schema_version": 1,
        "source_ref": "test-commit",
    }
    for page in (output / "index.html", output / "guides.html"):
        text = page.read_text(encoding="utf-8")
        assert "released 2026-09-01" in text
        assert "unreleased candidate" not in text.lower()
    sources = sorted(
        (
            *ROOT.joinpath("receipts/schema").glob("*.json"),
            *ROOT.joinpath("standard/schemas").glob("*.json"),
        ),
        key=lambda path: path.name,
    )
    assert [path.name for path in copied] == [path.name for path in sources]
    for source, deployed in zip(sources, copied):
        assert deployed.read_bytes() == source.read_bytes()
        assert json.loads(deployed.read_text(encoding="utf-8"))["$id"].endswith(
            f"/schemas/{deployed.name}"
        )


def test_every_declared_document_is_rendered_with_source_aware_navigation(
    tmp_path: Path,
) -> None:
    path = ROOT / "scripts/build_docs.py"
    spec = importlib.util.spec_from_file_location("build_docs_coverage", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)

    output = tmp_path / "site"
    output.mkdir()
    written = module.build(output, source_ref="test-commit")
    declared = module.documents()
    assert len(written) == len(declared)
    for document in declared:
        target = output / Path(document.route.as_posix())
        assert target.is_file(), f"documentation omits {document.source.relative_to(ROOT)}"
    for target in written:
        assert "\x00" not in target.read_text(encoding="utf-8")

    ladder = (output / "standard/index.html").read_text(encoding="utf-8")
    assert 'class="doc-sidebar"' in ladder
    assert "On this page" in ladder
    assert '>Standard</a>' in ladder
    assert '>Specifications</a>' not in ladder
    assert 'href="VSTD-1.html"' in ladder
    assert 'href="../docs/CONCEPTS_AND_PRECEDENTS.html"' in ladder
    assert (
        '<a href="../docs/CONCEPTS_AND_PRECEDENTS.html"><code>Concept guide and '
        'intellectual precedents</code></a>' in ladder
    )
    releasing = (output / "project/RELEASING.html").read_text(encoding="utf-8")
    assert '<ol start="4"><li>Run ' in releasing
    assert '<li>Confirm <code>python scripts/check_time_status.py</code> passes' in releasing
    assert '<ol start="8"><li>Push the tag ' in releasing
    assert '<ol start="10"><li>Let Zenodo ' in releasing
    assert (
        '<a href="../docs/CONCEPTS_AND_PRECEDENTS.html"><code>concept guide</code></a>'
        in ladder
    )
    assert (
        "github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md"
        not in ladder
    )
    assert "/blob/test-commit/standard/LADDER.md" in ladder
    assert "without changing its status" in ladder
    assert "Evidence for one closure coordinate never supplies evidence for another." in ladder
    assert "An <code>UNKNOWN</code> is never a pass" in ladder
    assert 'data-orientation-preview="repository"' in ladder
    assert 'data-orientation-concept="Defense in depth"' in ladder
    assert 'src="../assets/orientation-previews.js" defer' in ladder

    readme = (output / "project/README.html").read_text(encoding="utf-8")
    assert 'href="../docs/QUICKSTART.html"' in readme
    assert 'href="../standard/index.html"' in readme

    concepts = (output / "docs/CONCEPTS_AND_PRECEDENTS.html").read_text(
        encoding="utf-8"
    )
    assert 'class="orientation-link"' in concepts
    assert 'data-orientation-preview="repository"' in concepts
    assert 'data-orientation-concept="Assurance"' in concepts
    assert (
        'data-orientation-definition="VSTD reports evidence-bounded results, '
        'not universal confidence or institutional accreditation."' in concepts
    )
    assert (
        'data-orientation-boundary="Wikipedia orientation; not a VSTD authority"'
        in concepts
    )
    assert 'rel="noreferrer"' in concepts
    assert 'src="../assets/orientation-previews.js" defer' in concepts
    assert 'href="../reference.html#api-compute_canonical_digest"' in concepts
    assert 'href="../reference.html#api-ReproducibilityLevel"' in concepts
    assert 'href="../reference.html#api-DecisionCertificate"' in concepts

    quickstart = (output / "docs/QUICKSTART.html").read_text(encoding="utf-8")
    assert "orientation-previews.js" not in quickstart


def test_orientation_previews_are_bounded_and_fail_to_ordinary_links() -> None:
    source = (ROOT / "docs/CONCEPTS_AND_PRECEDENTS.md").read_text(encoding="utf-8")
    script = (ROOT / "docs/assets/orientation-previews.js").read_text(encoding="utf-8")

    assert "short definition is versioned in" in source
    assert "popup performs no" in source
    assert "data-orientation-preview=\"repository\"" in script
    assert "dataset.orientationDefinition" in script
    assert "Repository definition · versioned with VSTD" in script
    assert "optional external background" in script
    assert "fetch(" not in script
    assert "w/api.php" not in script
    assert ".textContent = text" in script


def test_generated_api_reference_has_documented_supported_exports() -> None:
    reference = (ROOT / "docs/reference.html").read_text(encoding="utf-8")

    assert "No docstring is declared for this export" not in reference
    assert "Canonical grounded decision certificate (GDC) blocks" in reference
    assert "canonically digested VSTD-1 claim receipt" in reference
    assert "Validate one generic-run receipt" in reference
    assert "Outcome vocabulary returned by the VSTD-1 claim-mechanics checker" in reference


def test_assembled_site_has_no_broken_internal_navigation(tmp_path: Path) -> None:
    path = ROOT / "scripts/build_pages.py"
    spec = importlib.util.spec_from_file_location("build_pages_links", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    output = tmp_path / "site"
    module.build(output, source_ref="test-commit")
    canonical = "https://timelordraps.github.io/verifier/"
    for source in output.rglob("*.html"):
        parser = _BuiltPageLinks()
        parser.feed(source.read_text(encoding="utf-8"))
        for raw in parser.links:
            if raw.startswith(canonical):
                relative = unquote(raw.removeprefix(canonical).split("#", 1)[0])
                target = output / relative
                if not relative or relative.endswith("/"):
                    target /= "index.html"
            elif raw.startswith(("#", "http://", "https://", "mailto:", "data:")):
                continue
            else:
                relative = unquote(raw.split("#", 1)[0])
                target = source.parent / relative
                if relative.endswith("/"):
                    target /= "index.html"
            assert target.exists(), f"{source.relative_to(output)} links missing {raw}"


def test_guides_keep_repository_documentation_inside_the_site() -> None:
    guides = (ROOT / "docs/guides.html").read_text(encoding="utf-8")
    assert '<a href="standard/">Standard</a>' in guides
    assert '>Specifications</a>' not in guides
    assert 'href="docs/QUICKSTART.html"' in guides
    assert 'href="standard/"' in guides
    assert 'href="experiments/"' in guides
    assert 'href="project/ROADMAP.html"' in guides
    assert "github.com/TimeLordRaps/verifier/blob/main/docs/" not in guides
    assert "github.com/TimeLordRaps/verifier/blob/main/standard/" not in guides


def test_pages_explains_artifact_first_state_without_actor_ratings() -> None:
    page = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert "Verify the process, not the actor." in page
    assert "TRUST · FORWARD" in page
    assert "ROT · CURRENT STATE" in page
    assert "RUST · BACKWARD" in page
    assert "cryptographic zero knowledge can enclose" in page
    assert "not acronyms or actor ratings" in page


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


def test_repository_checks_do_not_self_certify_conformance() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guides = (ROOT / "docs" / "guides.html").read_text(encoding="utf-8")
    workflow_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    workflow = yaml.safe_load(workflow_text)

    assert "[![Conformance]" not in readme
    assert "[![Repository checks]" in readme
    assert workflow["name"] == "repository-checks"
    assert "trace poisoned ancestry" not in guides
    assert "examples/zizk_artifact_first" in guides


def test_pull_requests_retain_a_commit_addressed_pages_preview() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    presentation = workflow["jobs"]["presentation"]
    commands = "\n".join(str(step.get("run", "")) for step in presentation["steps"])
    uploads = [
        step
        for step in presentation["steps"]
        if "upload-artifact@" in step.get("uses", "")
    ]

    assert '--source-ref "$GITHUB_SHA"' in commands
    assert uploads[0]["with"]["name"] == "pages-preview-${{ github.sha }}"
    assert uploads[0]["with"]["path"] == "_site"


def test_codeql_is_pinned_and_required_by_the_protected_gate() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    codeql = jobs["codeql"]
    uses = [str(step.get("uses", "")) for step in codeql["steps"]]

    assert any(
        item
        == "github/codeql-action/init@cdf488f595d80d6e07e03d4674febd5ab45fa938"
        for item in uses
    )
    assert any(
        item
        == "github/codeql-action/analyze@cdf488f595d80d6e07e03d4674febd5ab45fa938"
        for item in uses
    )
    assert "codeql" in jobs["conformance-gate"]["needs"]


def test_branch_coverage_is_retained_without_a_global_threshold() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    coverage = jobs["coverage"]
    commands = "\n".join(str(step.get("run", "")) for step in coverage["steps"])
    uploads = [
        step for step in coverage["steps"] if "upload-artifact@" in step.get("uses", "")
    ]

    assert "coverage run --branch --source=src/verifier" in commands
    assert "coverage report --show-missing" in commands
    assert "coverage json --pretty-print -o coverage.json" in commands
    assert "coverage xml -o coverage.xml" in commands
    assert "--fail-under" not in commands
    assert uploads[0]["with"]["name"] == "branch-coverage-python-3.12"
    assert set(uploads[0]["with"]["path"].splitlines()) == {
        "coverage.json",
        "coverage.xml",
    }
    assert "coverage" in jobs["conformance-gate"]["needs"]


def test_cross_platform_comparability_uses_three_native_operating_systems() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    release_platforms = set(jobs["release-integrity"]["strategy"]["matrix"]["os"])
    assert release_platforms == {
        "ubuntu-latest",
        "windows-latest",
        "macos-latest",
    }

    observation = jobs["platform-comparability-observation"]
    runner_platforms = {
        (item["runner"], item["platform"])
        for item in observation["strategy"]["matrix"]["include"]
    }
    assert runner_platforms == {
        ("ubuntu-latest", "Linux"),
        ("windows-latest", "Windows"),
        ("macos-15-intel", "Darwin"),
    }
    observation_setup = next(
        step
        for step in observation["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    assert observation_setup["with"]["python-version"] == "3.12.10"
    observation_commands = "\n".join(
        str(step.get("run", "")) for step in observation["steps"]
    )
    assert "platform.system()" in observation_commands
    assert "vstd validate" in observation_commands
    assert "vstd reproduce" in observation_commands

    aggregate = jobs["platform-comparability"]
    aggregate_commands = "\n".join(
        str(step.get("run", "")) for step in aggregate["steps"]
    )
    assert aggregate["needs"] == ["platform-comparability-observation"]
    aggregate_setup = next(
        step
        for step in aggregate["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    assert aggregate_setup["with"]["python-version"] == "3.12.10"
    assert "vstd compare-platforms" in aggregate_commands
    assert "platform-comparison.json" in aggregate_commands
    assert "platform-comparability-observation" in jobs["conformance-gate"]["needs"]
    assert "platform-comparability" in jobs["conformance-gate"]["needs"]


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
    assert verifier.__standard__ == "VSTD-5"
    assert (
        verifier.__standard_status__
        == "PROJECT SPECIFICATION; EVIDENCE-BOUND REFERENCE MECHANISM"
    )
    assert "VSTD-5 PROJECT SPECIFICATION; EVIDENCE-BOUND REFERENCE MECHANISM" in page
    assert "Monotone reproduction-fidelity states" in page


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

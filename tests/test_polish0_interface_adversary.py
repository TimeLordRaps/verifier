"""Language-neutral adversarial interface completeness regressions for Polish-0.

Acronyms: Scalable Vector Graphics (SVG); Verifier Standard (VSTD);
YAML Ain't Markup Language (YAML).

These tests independently challenge Polish-0 repository admission across
representative registered and unsupported discovery families. Adding an unrepresented
exposed route or interface changes the discovered source coordinate and produces an
exact coverage or gap failure rather than PASS or silent omission.

The baseline is UNKNOWN by construction, never PASS. The fixture attests no kind:
every classification stays the draft's UNRESOLVED decision with no evidence. No
installed closure establishes non-applicability, so a DOES_NOT_APPLY claim cannot
clear VSTD-T0.2 under the 38-kind namespace, and an APPLIES claim would assert a
role the fixture does not have. Each mutation therefore must add exactly the expected
VSTD-T0.4 identities while the VSTD-T0.2 state stays identical.

Optional-language families assert either the exact discovered surfaces or the exact
parser-unavailable UNKNOWN gap. They never PASS by omission.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

import pytest

from verifier.runtime import namespace_admission
from verifier.runtime import namespace_classification
from verifier.runtime import namespace_discovery
from verifier.runtime import namespace_javascript
from verifier.runtime import namespace_refutation
from verifier.runtime import namespace_systems
from verifier.runtime import namespace_workflows
from verifier.runtime.namespace_manifest import REFUTATION
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest

assess = namespace_admission.assess
build_template = namespace_admission.build_template

_UNRESOLVED = "NAMESPACE_CLASSIFICATION_UNRESOLVED"
_NON_APPLICABILITY = "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED"
_UNCOVERED = "NAMESPACE_SURFACE_UNCOVERED"
_LANGUAGE_UNSUPPORTED = "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED"
_JS_MARKER = "Optional JavaScript parser unavailable (NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE)"


def _init_repo(root: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _save_manifest(root: Path, manifest: dict[str, Any]) -> None:
    (root / "objects.vstd").write_bytes(canonical_bytes(manifest) + b"\n")


def _fixture_manifest(root: Path) -> dict[str, Any]:
    """Draft from the current bytes, with reasons and declarations completed but no kind attested.

    Classification keeps the draft's UNRESOLVED decisions with no evidence, so the
    fixture asserts neither applicability nor non-applicability. Evidence hashes in a
    row would go stale after a mutation and turn VSTD-T0.2 into a second, unrelated
    FAIL, so they are not written for decisions.
    """
    draft = build_template(root)
    manifest = draft["manifest"]
    for row in manifest["objects"]:
        row["reason"] = (
            "This object owns the bounded current-source interfaces exercised by "
            "the adversarial repository-admission fixture."
        )
        for binding in row["obligations"].values():
            binding.update(
                reason=(
                    "The fixture binds this declaration to current source without "
                    "asserting later behavioral conformance."
                ),
                evidence=draft["source_evidence"],
            )
            binding["declaration"] = {
                field: "Bounded fixture declaration for " + field + "."
                for field in binding["declaration"]
            }
    return manifest


def _ordered(rows: Any) -> list[tuple[Any, ...]]:
    return sorted(rows, key=lambda row: tuple("" if item is None else str(item) for item in row))


def _coverage(report: dict[str, Any]) -> list[tuple[Any, ...]]:
    """VSTD-T0.4 identities as (status, code, surface_id, object_id), in a fixed order."""
    return _ordered(
        (row["status"], row["code"], row["surface_id"], row["object_id"])
        for row in report["findings"] if row["coordinate"] == "VSTD-T0.4"
    )


def _classification(report: dict[str, Any]) -> list[tuple[Any, ...]]:
    """VSTD-T0.2 identities as (status, code, object_id); must not change under a coverage mutation."""
    return _ordered(
        (row["status"], row["code"], row["object_id"])
        for row in report["findings"] if row["coordinate"] == "VSTD-T0.2"
    )


def _obligation(report: dict[str, Any], coordinate: str) -> dict[str, Any]:
    return next(row for row in report["obligations"] if row["coordinate"] == coordinate)


def _baseline(root: Path, gap: tuple[str, str, str, str] | None = None) -> dict[str, Any] | None:
    """Assess the fixture before mutation and pin its exact non-PASS state.

    Returns the report when the discovery family ran and VSTD-T0.4 PASSes, so an
    omission mutation may follow. ``gap`` is ``(code, reason_marker, surface_id,
    object_id)`` for the family's declared optional parser. When that parser is absent
    the baseline must show exactly that one UNKNOWN, and the caller returns without an
    omission mutation. Either way VSTD-T0.2 must be only the unresolved state.
    """
    _save_manifest(root, _fixture_manifest(root))
    report = assess(root)
    assert report["status"] == "UNKNOWN", report["findings"]
    classification = {(row["status"], row["code"]) for row in report["findings"]
                      if row["coordinate"] == "VSTD-T0.2"}
    assert classification == {("UNKNOWN", _UNRESOLVED)}, report["findings"]
    assert {row["coordinate"] for row in report["findings"]} <= {"VSTD-T0.2", "VSTD-T0.4"}, report["findings"]
    if not _coverage(report):
        assert _obligation(report, "VSTD-T0.4")["status"] == "PASS"
        return report
    assert gap is not None, report["findings"]
    code, marker, surface_id, object_id = gap
    assert _coverage(report) == [("UNKNOWN", code, surface_id, object_id)], report["findings"]
    (row,) = [row for row in report["findings"] if row["coordinate"] == "VSTD-T0.4"]
    assert marker in row["explanation"], row["explanation"]
    assert _obligation(report, "VSTD-T0.4")["status"] == "UNKNOWN"
    return None


def _assert_isolated_coverage_change(base: dict[str, Any], after: dict[str, Any],
                                     expected: list[tuple[Any, ...]]) -> None:
    """The only change from baseline is the expected VSTD-T0.4 identities."""
    assert _coverage(after) == _ordered(expected), after["findings"]
    assert _classification(after) == _classification(base), "VSTD-T0.2 changed under a coverage mutation"
    statuses = {row[0] for row in expected}
    assert after["status"] == ("FAIL" if "FAIL" in statuses else "UNKNOWN")
    t04 = _obligation(after, "VSTD-T0.4")
    assert t04["status"] == ("FAIL" if "FAIL" in statuses else "UNKNOWN")
    assert t04["blockers"] == sorted({row[1] for row in expected})


def _absent_parser(monkeypatch: pytest.MonkeyPatch, module: Any, code: str) -> None:
    """Fault-inject parser absence at the parser boundary, reproducing its real failure path."""
    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError(code)

    monkeypatch.setattr(module, "_run", unavailable)


# ---------------------------------------------------------------------------
# Family 1: Python public definitions, exports, and lazy dispatch
# ---------------------------------------------------------------------------

def test_unrepresented_python_route_changes_coordinate_and_fails_admission(tmp_path: Path) -> None:
    """Adding an unrepresented Python function changes source coordinate and fails coverage."""
    root = _init_repo(tmp_path)
    service = root / "service.py"
    _write(service, "def base_endpoint(): pass\n")
    base = _baseline(root)
    assert base is not None
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(service, "def base_endpoint(): pass\ndef unrepresented_endpoint(): pass\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "python:service.py:unrepresented_endpoint", None),
    ])


def test_unrepresented_lazy_export_alias_changes_coordinate_and_fails_admission(tmp_path: Path) -> None:
    """Adding an unrepresented lazy export alias changes source coordinate and fails coverage."""
    root = _init_repo(tmp_path)
    pkg = root / "pkg"
    pkg.mkdir()
    _write(pkg / "sub.py", "class Core: pass\n")
    init_code = (
        "from importlib import import_module\n"
        '_LAZY_EXPORTS = {"Exposed": ("pkg.sub", "Core")}\n'
        "__all__ = list(_LAZY_EXPORTS)\n"
        "def __getattr__(name):\n"
        "    target = _LAZY_EXPORTS.get(name)\n"
        "    if target is None:\n"
        "        raise AttributeError(f\"module {__name__!r} has no attribute {name!r}\")\n"
        "    module_name, attribute_name = target\n"
        "    value = getattr(import_module(module_name), attribute_name)\n"
        "    globals()[name] = value\n"
        "    return value\n"
    )
    _write(pkg / "__init__.py", init_code)
    base = _baseline(root)
    assert base is not None
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(pkg / "__init__.py", init_code.replace(
        '{"Exposed": ("pkg.sub", "Core")}',
        '{"Exposed": ("pkg.sub", "Core"), "NewAlias": ("pkg.sub", "Core")}',
    ))
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "python-export:pkg/__init__.py:NewAlias", None),
    ])


def test_count_preserving_substitution_fails_exact_identities(tmp_path: Path) -> None:
    """Renaming one definition keeps the surface count but fails both the removed and the new identity."""
    root = _init_repo(tmp_path)
    service = root / "service.py"
    _write(service, "def alpha(): pass\ndef beta(): pass\n")
    base = _baseline(root)
    assert base is not None
    base_python = _python_surfaces(root)

    _write(service, "def alpha(): pass\ndef gamma(): pass\n")
    after = assess(root)

    assert len(_python_surfaces(root)) == len(base_python)
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", "NAMESPACE_SURFACE_NOT_DISCOVERED", "python:service.py:beta", "service.py"),
        ("FAIL", _UNCOVERED, "python:service.py:gamma", None),
    ])


def _python_surfaces(root: Path) -> list[str]:
    return sorted(row["surface_id"] for row in namespace_discovery.discover(root)["surfaces"]
                  if row["surface_id"].startswith("python:service.py:"))


# ---------------------------------------------------------------------------
# Family 2: JavaScript declarations and exports
# ---------------------------------------------------------------------------

def test_javascript_omission_is_refuted_or_parser_unavailability_is_explicit(tmp_path: Path) -> None:
    """Challenge JS omission only after parser-backed baseline admission passes."""
    root = _init_repo(tmp_path)
    module = root / "module.mjs"
    _write(module, "export class Router { handle() {} }\n")
    base = _baseline(root, gap=(_LANGUAGE_UNSUPPORTED, _JS_MARKER, "file:module.mjs", "module.mjs"))
    if base is None:
        return  # The exact parser-unavailable UNKNOWN was asserted; no omission is claimed.
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(module, "export class Router { handle() {} dispatch() {} }\n"
                   "export function unrepresentedExport() {}\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "javascript-export:module.mjs:unrepresentedExport", None),
        ("FAIL", _UNCOVERED, "javascript:module.mjs:Router.dispatch", None),
        ("FAIL", _UNCOVERED, "javascript:module.mjs:unrepresentedExport", None),
    ])


# ---------------------------------------------------------------------------
# Family 3: Rust declarations and re-exports
# ---------------------------------------------------------------------------

def test_rust_omission_is_refuted_or_parser_unavailability_is_explicit(tmp_path: Path) -> None:
    """Challenge Rust omission only after parser-backed baseline admission passes."""
    root = _init_repo(tmp_path)
    device = root / "device.rs"
    _write(device, "pub struct Device { pub status: u32 }\n"
                   "impl Device { pub fn probe(&self) {} }\n")
    base = _baseline(root, gap=(_LANGUAGE_UNSUPPORTED, "install verifier-standard[discovery-rust]",
                                "file:device.rs", "device.rs"))
    if base is None:
        return
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(device, "pub struct Device { pub status: u32, pub unrepresented_telemetry: u64 }\n"
                   "impl Device { pub fn probe(&self) {} pub fn unrepresented_actuate(&self) {} }\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "rust:device.rs:Device.unrepresented_telemetry", None),
        ("FAIL", _UNCOVERED, "rust:device.rs:impl  for Device.unrepresented_actuate", None),
    ])


def test_rust_reexport_gap_or_parser_unavailability_is_explicit(tmp_path: Path) -> None:
    """Adding a Rust re-export changes coordinate and produces an exact unexpanded gap."""
    root = _init_repo(tmp_path)
    lib = root / "lib.rs"
    _write(lib, "pub struct Kernel;\n")
    base = _baseline(root, gap=(_LANGUAGE_UNSUPPORTED, "install verifier-standard[discovery-rust]",
                                "file:lib.rs", "lib.rs"))
    if base is None:
        return
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(lib, "pub struct Kernel;\npub use crate::external::{Alpha, Beta as Sub};\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "rust:lib.rs:<use_declaration@19>", None),
        ("FAIL", _UNCOVERED, "rust:lib.rs:<use_declaration@19>.<export:Alpha@45>", None),
        ("FAIL", _UNCOVERED, "rust:lib.rs:<use_declaration@19>.<export:Sub@52>", None),
        ("UNKNOWN", "NAMESPACE_RUST_EXPORTS_UNRESOLVED", "file:lib.rs", "lib.rs"),
    ])


# ---------------------------------------------------------------------------
# Family 4: Markup and SVG embedded interfaces
# ---------------------------------------------------------------------------

def test_svg_script_omission_is_refuted_or_parser_unavailability_is_explicit(tmp_path: Path) -> None:
    """Challenge embedded JS omission only after parser-backed admission passes."""
    root = _init_repo(tmp_path)
    graphic = root / "graphic.svg"
    _write(graphic, '<svg xmlns="http://www.w3.org/2000/svg"><script>function render() {}</script></svg>')
    base = _baseline(root, gap=(_LANGUAGE_UNSUPPORTED, _JS_MARKER, "file:graphic.svg", "graphic.svg"))
    if base is None:
        return
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(graphic, '<svg xmlns="http://www.w3.org/2000/svg"><script>'
                    'function render() {} function unrepresentedHandler() {}'
                    '</script></svg>')
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "javascript:svg-fragment:svg:graphic.svg:script:2:unrepresentedHandler", None),
    ])


# ---------------------------------------------------------------------------
# Family 5: Workflow and shell command surfaces
# ---------------------------------------------------------------------------

def test_workflow_omission_is_refuted_or_parser_unavailability_is_explicit(tmp_path: Path) -> None:
    """Adding a workflow run step changes coordinate and produces exact uncovered surfaces."""
    root = _init_repo(tmp_path)
    wf_dir = root / ".github/workflows"
    wf_dir.mkdir(parents=True)
    build = wf_dir / "build.yml"
    _write(build, "jobs:\n  compile:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make core\n")
    base = _baseline(root, gap=("NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE",
                                "Optional YAML parser unavailable (",
                                "file:.github/workflows/build.yml", ".github/workflows/build.yml"))
    if base is None:
        return
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(build, "jobs:\n  compile:\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - run: make core\n      - run: make unrepresented_target\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ('FAIL', _UNCOVERED, 'workflow:.github/workflows/build.yml:job/"compile"/steps/1', None),
        ('FAIL', _UNCOVERED, 'workflow:.github/workflows/build.yml:job/"compile"/steps/1/run', None),
        ('FAIL', _UNCOVERED, 'workflow:.github/workflows/build.yml:job/"compile"/steps/1/run/program/1', None),
        ('FAIL', _UNCOVERED,
         'workflow:.github/workflows/build.yml:node/document/value/0/value/0/value/1/item/1', None),
        ('FAIL', _UNCOVERED,
         'workflow:.github/workflows/build.yml:node/document/value/0/value/0/value/1/item/1/key/0', None),
        ('FAIL', _UNCOVERED,
         'workflow:.github/workflows/build.yml:node/document/value/0/value/0/value/1/item/1/value/0', None),
    ])


def test_shell_function_and_command_omissions_are_independently_refuted_or_unavailable(
    tmp_path: Path,
) -> None:
    """Adding a shell function and command changes coordinate and fails coverage."""
    root = _init_repo(tmp_path)
    base_source = "#!/usr/bin/env bash\nbase_fn() { echo start; }\n"
    entry = root / "entry.sh"
    _write(entry, base_source)
    base = _baseline(root, gap=(_LANGUAGE_UNSUPPORTED, "install verifier-standard[discovery-shell]",
                                "file:entry.sh", "entry.sh"))
    if base is None:
        return
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(entry, base_source + "unrepresented_fn() { echo hidden; }\nunrepresented_fn\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "bash:entry.sh:unrepresented_fn", None),
        ("FAIL", _UNCOVERED, "bash:entry.sh:unrepresented_fn.echo", None),
        ("FAIL", _UNCOVERED, "bash:entry.sh:unrepresented_fn@82", None),
    ])


# ---------------------------------------------------------------------------
# Family 6: Absent optional parsers are explicit UNKNOWN, never PASS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module_name, fault, filename, content, gap", [
    (namespace_javascript, "NAMESPACE_JAVASCRIPT_PARSER_UNAVAILABLE", "module.mjs",
     "export class Router { handle() {} }\n",
     (_LANGUAGE_UNSUPPORTED, _JS_MARKER, "file:module.mjs", "module.mjs")),
    (namespace_systems, "NAMESPACE_SYSTEMS_PARSER_UNAVAILABLE", "device.rs",
     "pub struct Device { pub status: u32 }\n",
     (_LANGUAGE_UNSUPPORTED, "install verifier-standard[discovery-rust]", "file:device.rs", "device.rs")),
    (namespace_systems, "NAMESPACE_SYSTEMS_PARSER_UNAVAILABLE", "entry.sh",
     "#!/usr/bin/env bash\nbase_fn() { echo start; }\n",
     (_LANGUAGE_UNSUPPORTED, "install verifier-standard[discovery-shell]", "file:entry.sh", "entry.sh")),
    (namespace_workflows, "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE", ".github/workflows/build.yml",
     "jobs:\n  compile:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make core\n",
     ("NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE", "Optional YAML parser unavailable (",
      "file:.github/workflows/build.yml", ".github/workflows/build.yml")),
])
def test_absent_optional_parser_is_explicit_unknown_never_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module_name: Any, fault: str,
    filename: str, content: str, gap: tuple[str, str, str, str],
) -> None:
    """With the parser absent, the file is an exact UNKNOWN gap and the baseline is never PASS."""
    root = _init_repo(tmp_path)
    target = root / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    _write(target, content)
    _absent_parser(monkeypatch, module_name, fault)

    assert _baseline(root, gap=gap) is None


# ---------------------------------------------------------------------------
# Family 7: Unsupported languages remain explicit UNKNOWN gaps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,content", [
    ("kernel.c", "int execute(void) { return 0; }\n"),
    ("contract.go", "package main\nfunc main() {}\n"),
    ("solver.lean", "theorem unrepresented : True := trivial\n"),
])
def test_unsupported_languages_remain_explicit_unknown_gaps(
    tmp_path: Path, filename: str, content: str,
) -> None:
    """Unsupported language bodies produce explicit UNKNOWN gap, not PASS or omission."""
    root = _init_repo(tmp_path)
    _write(root / filename, content)
    _save_manifest(root, _fixture_manifest(root))

    report = assess(root)
    assert report["status"] == "UNKNOWN"
    assert _coverage(report) == [("UNKNOWN", _LANGUAGE_UNSUPPORTED, f"file:{filename}", filename)]
    gap = next(row for row in report["findings"] if row["coordinate"] == "VSTD-T0.4")
    assert gap["next_action"] == (
        "Install or implement a source discovery adapter for " + filename
        + "; file coverage cannot replace definition coverage."
    )
    t04 = _obligation(report, "VSTD-T0.4")
    assert t04["status"] == "UNKNOWN"
    assert t04["blockers"] == [_LANGUAGE_UNSUPPORTED]


# ---------------------------------------------------------------------------
# Family 8: Dynamic and unresolvable interface case
# ---------------------------------------------------------------------------

def test_dynamic_interface_addition_changes_coordinate_and_retains_unknown_gap(tmp_path: Path) -> None:
    """Adding dynamic module loader construction keeps the dynamic gap UNKNOWN and fails the new static surface."""
    root = _init_repo(tmp_path)
    module = root / "module.py"
    base_source = "def static_op(): pass\n"
    _write(module, base_source)
    base = _baseline(root)
    assert base is not None
    base_coordinate = base["source_coordinate"]["source_census_digest"]

    _write(module, base_source + "import importlib\n"
                   + "def dynamic_dispatch(name):\n"
                   + "    return importlib.import_module(name)\n")
    after = assess(root)

    assert after["source_coordinate"]["source_census_digest"] != base_coordinate
    _assert_isolated_coverage_change(base, after, [
        ("FAIL", _UNCOVERED, "python:module.py:dynamic_dispatch", None),
        ("UNKNOWN", "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED", "file:module.py", "module.py"),
    ])


# ---------------------------------------------------------------------------
# Family 9: Stale production witness never establishes non-applicability
# ---------------------------------------------------------------------------

def _witnessed_fixture(root: Path, kind: str = "HUMAN") -> None:
    """Bind one production executable witness to a DOES_NOT_APPLY row for service.py.

    The witness is built by namespace_refutation.build_witness over the owned file
    and one callee file, so the closure runs fresh and keeps its receipt. The row
    cites only the owned file as evidence, which isolates the callee anchor.
    """
    manifest = _fixture_manifest(root)
    observed = namespace_discovery.discover(root)
    mechanism = value_digest(namespace_admission.mechanism_binding())
    context = namespace_classification.refutation_context(observed, mechanism, root=root)
    surfaces = {row["surface_id"]: row["path"] for row in observed["surfaces"]}
    row = next(item for item in manifest["objects"] if item["object_id"] == "service.py")
    owned = sorted({surfaces[surface] for surface in row["surfaces"] if surface in surfaces})
    decision = row["classification"][kind]
    decision.update(status="DOES_NOT_APPLY", reason="Probe reason for the stale-witness adversary.",
                    evidence=[{"path": "service.py",
                               "sha256": context["inventory"]["service.py"]["sha256"]}])
    review_module = namespace_classification._review_module(set(owned))
    assert review_module is not None, owned
    expected = namespace_refutation.ExpectedReview(
        object_id="service.py", kind=kind, basis=namespace_refutation.BASIS_EXECUTABLE_CLOSURE,
        review_module=review_module,
        review_mechanism_digest=mechanism,
        review_row_digest=value_digest({key: item for key, item in decision.items() if key != REFUTATION}),
    )
    decision[REFUTATION] = namespace_refutation.build_witness(
        expected=expected, source_paths=owned, callee_paths=["helper.py"], inventory=context["inventory"])
    _save_manifest(root, manifest)


def _witness_finding(report: dict[str, Any], kind: str = "HUMAN") -> dict[str, Any]:
    rows = [row for row in report["findings"] if row["coordinate"] == "VSTD-T0.2"
            and row["object_id"] == "service.py" and row["explanation"].startswith(kind + " declares")]
    assert len(rows) == 1, rows
    return rows[0]


@pytest.mark.parametrize("mutated, content, status, detail", [
    ("helper.py", "def helper(): return 1\n", "UNKNOWN", "claim is UNKNOWN (STALE_ANCHOR)"),
    ("service.py", "def served(): return 2\n", "FAIL", "claim is UNKNOWN (STALE_ANCHOR)"),
])
def test_stale_witness_never_establishes_and_names_its_stale_anchor(
    tmp_path: Path, mutated: str, content: str, status: str, detail: str,
) -> None:
    """A fresh clean closure is only DOCUMENTED, and a changed anchored byte is named STALE_ANCHOR, never established."""
    root = _init_repo(tmp_path)
    _write(root / "service.py", "def served(): pass\n")
    _write(root / "helper.py", "def helper(): pass\n")
    _witnessed_fixture(root)

    fresh = assess(root)
    assert [row for row in fresh["findings"] if row["coordinate"] == "VSTD-T0.2"
            and row["object_id"] == "service.py" and row["explanation"].startswith("HUMAN declares")] == []
    service = next(row for row in fresh["object_assessments"] if row["object_id"] == "service.py")
    human = next(row for row in service["classification"] if row["kind"] == "HUMAN")
    assert (human["non_applicability"], human["refutation_status"]) == ("DOCUMENTED", "DOCUMENTED")
    assert _coverage(fresh) == []

    _write(root / mutated, content)
    stale = assess(root)
    stale_row = _witness_finding(stale)
    assert stale_row["status"] == status
    assert stale_row["code"] == _NON_APPLICABILITY
    assert detail in stale_row["explanation"]
    assert "BOUNDED_ABSENCE" not in stale_row["explanation"]
    assert "fresh closure scan" not in stale_row["explanation"]
    assert _coverage(stale) == []
    assert stale["status"] == ("FAIL" if status == "FAIL" else "UNKNOWN")
    assert _obligation(stale, "VSTD-T0.4")["status"] == "PASS"


# ---------------------------------------------------------------------------
# Family 10: Mislabeled consequential route (physical robot/actuator roles)
# ---------------------------------------------------------------------------

def test_physical_role_declaration_cannot_be_evaded_by_generic_object_label(tmp_path: Path) -> None:
    """Labeling physical robot/actuator route as generic OBJECT contradicts source and retains obligations."""
    root = _init_repo(tmp_path)
    _write(root / "robot_arm.py",
           '__vstd_kinds__ = ("ROBOT", "ACTUATOR")\n'
           "def command_position(theta: float): pass\n")
    manifest = _fixture_manifest(root)
    # Adversary attempts to evade physical obligations by labeling as generic OBJECT
    subject = manifest["objects"][0]
    subject["kind"] = "OBJECT"
    subject["specializations"] = []
    subject["classification"] = {}
    _save_manifest(root, manifest)

    report = assess(root)
    assert report["status"] == "FAIL"

    contradictions = [
        row for row in report["findings"]
        if row["code"] == "NAMESPACE_LABEL_CONTRADICTS_SOURCE"
    ]
    assert len(contradictions) == 2
    assert all(row["coordinate"] == "VSTD-T0.2" for row in contradictions)
    assert {row["explanation"].split()[0] for row in contradictions} == {"ROBOT", "ACTUATOR"}

    # All 6 physical obligations for ROBOT and ACTUATOR are accumulated
    required_kinds = {row["kind"] for row in report["required_obligations"]}
    assert required_kinds == {"ROBOT", "ACTUATOR"}
    assert len(report["required_obligations"]) == 6

    req_ids = {row["id"] for row in report["required_obligations"]}
    expected_physical_ids = {
        "ROBOT-0.1-agent-to-actuator-binding",
        "ROBOT-0.2-physical-reach-and-observation",
        "ROBOT-0.3-consequences-and-intervention",
        "ACTUATOR-0.1-command-to-effect",
        "ACTUATOR-0.2-response-and-limits",
        "ACTUATOR-0.3-feedback-and-interlocks",
    }
    assert req_ids == expected_physical_ids
    assert report["tier_1_plus_status"] == "NOT_ESTABLISHED"

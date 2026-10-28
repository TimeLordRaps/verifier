"""Test-first contract for Tier-0 package application programming interface (API) surface admission.

The ten owner rows and their eleven owned ``__init__.py`` files are checked by
static abstract syntax tree (AST) resolution only. Positive cases use the
current repository bytes. Mutation cases use synthetic temporary trees whose
admitted pins are taken from the good tree before each mutation. No subject
package is imported; the import-isolation test enforces that.
"""

from __future__ import annotations

import ast
from dataclasses import asdict, replace
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from verifier.runtime import package_api_surface_admission as admission


ROOT = Path(__file__).resolve().parents[1]
REFUSED_OWNER = "OBJECT"
HARDWARE_PATHS = (
    "src/verifier/hardware/__init__.py",
    "src/verifier/hardware/adapters/__init__.py",
)
# Expected kinds and export counts are the read-only audit values, not values
# copied from the module under test.
AUDITED = {
    "vstd-vgsat-package-marker": ("DATA", ("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py",), 1),
    "vstd-consent-package-api": ("ARCH", ("src/verifier/consent/__init__.py",), 8),
    "vstd-corrigibility-package-api": ("ARCH", ("src/verifier/corrigibility/__init__.py",), 117),
    "vstd-data-package-api": ("ARCH", ("src/verifier/data/__init__.py",), 32),
    "vstd-environments-package-api": ("ARCH", ("src/verifier/environments/__init__.py",), 23),
    "vstd-experimental-workflow-package-api": ("ARCH", ("src/verifier/experimental_workflow/__init__.py",), 13),
    "vstd-hardware-public-api": ("HARDWARE", HARDWARE_PATHS, 56),
    "vstd-identity-package-api": ("ARCH", ("src/verifier/identity/__init__.py",), 15),
    "vstd-interoperability-public-api": ("VERIFIER", ("src/verifier/interoperability/__init__.py",), 46),
    "vstd-layer4-package-api": ("ARCH", ("src/verifier/layer4/__init__.py",), 25),
}
SAMPLE_OWNER = ("tmp-sample-package-api", "ARCH", ("src/verifier/sample/__init__.py",))
SAMPLE_FILES = {
    "src/verifier/sample/__init__.py": (
        '"""Sample package API."""\n'
        "from __future__ import annotations\n\n"
        "from .engine import Widget\n"
        "from .shapes import Circle as Round\n\n"
        '__all__ = ["Round", "VERSION", "Widget"]\n'
        'VERSION = "1"\n'
    ),
    "src/verifier/sample/engine.py": "class Widget:\n    pass\n",
    "src/verifier/sample/shapes.py": "class Circle:\n    pass\n",
}


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))


def _codes(report: admission.AdmissionReport) -> set[str]:
    owner_codes = {finding.code for owner in report.owners for finding in owner.findings}
    return owner_codes | {finding.code for finding in report.unadmitted_findings}


def _finding_status(report: admission.AdmissionReport, code: str) -> set[str]:
    return {f.status for owner in report.owners for f in owner.findings if f.code == code}


def _all_status(report: admission.AdmissionReport, code: str) -> set[str]:
    """Statuses of one finding code across owner-level and catalog-level findings."""
    everything = [f for owner in report.owners for f in owner.findings] + list(report.unadmitted_findings)
    return {f.status for f in everything if f.code == code}


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    _write(tmp_path, SAMPLE_FILES)
    return tmp_path


@pytest.fixture
def admitted(sample: Path) -> tuple[admission.AdmittedOwner, ...]:
    return (admission.derive(sample, *SAMPLE_OWNER),)


def _assess(root: Path, admitted: tuple[admission.AdmittedOwner, ...], declarations=None):
    """Assess a synthetic catalog; by default its declaration is the sample owner, never the repository slice."""
    rows = (admission.Declaration(*SAMPLE_OWNER),) if declarations is None else declarations
    return admission.assess(root, declarations=rows, admitted=admitted)


# --- Exact current-source positive cases -----------------------------------

def test_catalog_names_exactly_the_ten_audited_owners() -> None:
    assert {owner.owner_id for owner in admission.ADMITTED} == set(AUDITED)


def test_current_source_owners_match_audited_kinds_paths_and_counts() -> None:
    report = admission.assess(ROOT)

    got = {o.owner_id: (o.primary_kind, o.owned_paths, o.export_count) for o in report.owners}
    assert got == AUDITED
    for owner in report.owners:
        assert owner.runtime_importability == "NOT_ESTABLISHED"
        assert owner.behavior == "NOT_ESTABLISHED"
        assert owner.consequence_roles == "NOT_ASSESSED"
        assert owner.opening_digest == owner.closing_digest


EXPECTED_ADMITTED_NOW = {
    "vstd-consent-package-api",
    "vstd-experimental-workflow-package-api",
    "vstd-identity-package-api",
    "vstd-interoperability-public-api",
    "vstd-vgsat-package-marker",
}


def _cache_free_copy(dest: Path) -> Path:
    """Copy the repository source and experiment bytes without bytecode caches.

    A local ``__pycache__`` is a generated artefact that the admission rule correctly treats as a
    shadow candidate, so the census measures repository bytes, not whichever caches a checkout holds.
    """
    for name in ("src", "experiments/verifier_guided_sat"):
        shutil.copytree(ROOT / name, dest / name, ignore=shutil.ignore_patterns("__pycache__"))
    return dest


def test_current_source_census_admits_only_owners_without_import_time_blockers(tmp_path: Path) -> None:
    """Measured on cache-free source bytes: seven modules in five owners' import graphs make import-time effects outside the pure allowlist."""
    report = admission.assess(_cache_free_copy(tmp_path))
    statuses = {o.owner_id: o.status for o in report.owners}

    assert {owner for owner, status in statuses.items() if status == "PASS"} == EXPECTED_ADMITTED_NOW
    assert {owner for owner, status in statuses.items() if status == "UNKNOWN"} == set(AUDITED) - EXPECTED_ADMITTED_NOW
    blockers = {f.path for o in report.owners for f in o.findings if f.code == "DYNAMIC_TOP_LEVEL"}
    assert "src/verifier/core/depth.py" in blockers
    assert report.reviewed_status == "UNKNOWN"
    assert report.status == "UNKNOWN"


def test_real_checkout_is_never_report_pass() -> None:
    """Whatever bytecode caches the checkout holds, unreviewed and ancestor surfaces keep the whole-package status UNKNOWN."""
    assert admission.assess(ROOT).status == "UNKNOWN"


def test_hardware_is_one_atomic_owner_over_both_files() -> None:
    report = admission.assess(ROOT)
    hardware = next(o for o in report.owners if o.owner_id == "vstd-hardware-public-api")

    assert hardware.owned_paths == HARDWARE_PATHS
    assert {b.owned_file for b in hardware.bindings} == set(HARDWARE_PATHS)
    assert set(HARDWARE_PATHS) <= {path for path, _digest in hardware.closure}


def test_positive_bindings_resolve_to_the_defining_local_module() -> None:
    report = admission.assess(ROOT)
    consent = next(o for o in report.owners if o.owner_id == "vstd-consent-package-api")
    layer4 = next(o for o in report.owners if o.owner_id == "vstd-layer4-package-api")
    by_export = {b.export: b for b in consent.bindings}
    layer4_by_export = {b.export: b for b in layer4.bindings}

    assert by_export["ConsentContext"].route == "REEXPORT"
    assert by_export["ConsentContext"].target_path == "src/verifier/consent/engine.py"
    assert "class ConsentContext" in (ROOT / by_export["ConsentContext"].target_path).read_text(encoding="utf-8")
    assert layer4_by_export["ChallengeLedger"].target_path == "src/verifier/layer4/challenge.py"


def test_assessment_is_deterministic_on_current_bytes() -> None:
    assert admission.assess(ROOT).report_digest == admission.assess(ROOT).report_digest


def test_assessment_imports_no_subject_package() -> None:
    subject_prefixes = (
        "verifier.consent", "verifier.corrigibility", "verifier.data", "verifier.environments",
        "verifier.experimental_workflow", "verifier.hardware", "verifier.identity",
        "verifier.interoperability", "verifier.layer4",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    observed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-X",
            "importtime",
            "-c",
            (
                "from pathlib import Path; "
                "from verifier.runtime import package_api_surface_admission as admission; "
                "admission.assess(Path.cwd())"
            ),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert observed.returncode == 0, observed.stderr
    imported = {
        line.rpartition("|")[2].strip()
        for line in observed.stderr.splitlines()
        if line.startswith("import time:") and "|" in line
    }
    newly = {name for name in imported if name.startswith(subject_prefixes)}

    assert newly == set()


def test_module_is_stdlib_only_and_never_loads_dynamically() -> None:
    source = Path(admission.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}

    assert imported <= {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
    assert not called & {"__import__", "exec", "eval"}
    assert "import_module" not in source


# --- Good synthetic tree and every mutation class --------------------------

def test_synthetic_good_tree_is_admitted(sample: Path, admitted) -> None:
    report = _assess(sample, admitted)

    # Spec correction (review round 2): a caller-supplied catalog is not whole-package
    # enumeration authority, so the owner is admitted but the report stays UNKNOWN, never PASS.
    assert report.owners[0].status == "PASS", [f for o in report.owners for f in o.findings]
    assert report.status == "UNKNOWN"
    assert _all_status(report, "CATALOG_NOT_ENUMERATED") == {"UNKNOWN"}
    owner = report.owners[0]
    assert owner.export_count == 3
    by_export = {b.export: b for b in owner.bindings}
    assert by_export["Round"].route == "REEXPORT"
    assert by_export["Round"].target_path == "src/verifier/sample/shapes.py"
    assert by_export["VERSION"].route == "LOCAL_DEFINITION"
    assert by_export["Widget"].target_path == "src/verifier/sample/engine.py"


def test_export_added_fails_with_exact_name(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"VERSION", "Widget"]', b'"Gizmo", "VERSION", "Widget"]')
                     .replace(b'VERSION = "1"\n', b'VERSION = "1"\nGizmo = 2\n'))
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "EXPORT_ADDED" in _codes(report)
    assert any(f.code == "EXPORT_ADDED" and "Gizmo" in f.reason for o in report.owners for f in o.findings)


def test_export_dropped_fails(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"Round", "VERSION", "Widget"', b'"Round", "Widget"'))
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "EXPORT_DROPPED" in _codes(report)


def test_export_renamed_fails_as_drop_plus_unbound_add(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"Round"', b'"Ring"'))
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert {"EXPORT_DROPPED", "UNBOUND_EXPORT"} <= _codes(report)


def test_unresolved_binding_fails(sample: Path, admitted) -> None:
    (sample / "src/verifier/sample/engine.py").write_bytes(b"class Gadget:\n    pass\n")
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "UNRESOLVED_SYMBOL" in _codes(report)


def test_duplicate_binding_fails(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes() + b"Widget = 3\n")
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "DUPLICATE_BINDING" in _codes(report)


def test_duplicate_export_name_fails(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"VERSION", "Widget"', b'"VERSION", "VERSION", "Widget"'))
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "DUPLICATE_EXPORT" in _codes(report)


@pytest.mark.parametrize("dynamic", [
    b'__all__ = sorted(["Round", "VERSION", "Widget"])\n',
    b'__all__ = ["Round", "VERSION"]\n__all__ += ["Widget"]\n',
])
def test_dynamic_all_is_unknown_never_pass(sample: Path, admitted, dynamic: bytes) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    lines = init.read_bytes().splitlines(keepends=True)
    init.write_bytes(b"".join(line for line in lines if not line.startswith(b"__all__")) + dynamic)
    report = _assess(sample, admitted)

    # The edited owned file also drifts from its pin, so the aggregate is FAIL;
    # the dynamic-all finding itself must still be UNKNOWN, never PASS.
    assert report.status != "PASS"
    assert _finding_status(report, "DYNAMIC_ALL") == {"UNKNOWN"}


def test_owned_source_drift_fails(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes() + b"# drift\n")
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "OWNED_DIGEST_CHANGED" in _codes(report)


def test_target_source_drift_fails(sample: Path, admitted) -> None:
    engine = sample / "src/verifier/sample/engine.py"
    engine.write_bytes(engine.read_bytes() + b"EXTRA = 1\n")
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert "TARGET_DIGEST_CHANGED" in _codes(report)


def test_concurrent_drift_between_opening_and_closing_reads_is_unknown(sample: Path, admitted, monkeypatch) -> None:
    original = admission._read_bytes
    reads: dict[Path, int] = {}

    def drifting(path: Path) -> bytes:
        reads[path] = reads.get(path, 0) + 1
        data = original(path)
        return data if reads[path] == 1 else data + b"# changed while checked\n"

    monkeypatch.setattr(admission, "_read_bytes", drifting)
    report = _assess(sample, admitted)

    assert report.status == "UNKNOWN"
    assert "SOURCE_CHANGED_DURING_CHECK" in _codes(report)
    assert report.owners[0].opening_digest != report.owners[0].closing_digest


def test_owner_kind_substitution_fails(sample: Path, admitted) -> None:
    owner_id, _kind, paths = SAMPLE_OWNER
    report = _assess(sample, admitted, declarations=(admission.Declaration(owner_id, "DATA", paths),))

    assert report.status == "FAIL"
    assert "KIND_SUBSTITUTED" in _codes(report)


def test_owner_id_substitution_is_unadmitted_and_missing(sample: Path, admitted) -> None:
    _owner_id, kind, paths = SAMPLE_OWNER
    report = _assess(sample, admitted, declarations=(admission.Declaration("tmp-other-owner", kind, paths),))

    assert report.status == "FAIL"
    assert {"OWNER_UNADMITTED", "OWNER_MISSING"} <= _codes(report)


def test_path_removed_and_extra_path_fail(sample: Path, admitted) -> None:
    owner_id, kind, paths = SAMPLE_OWNER
    removed = _assess(sample, admitted, declarations=(admission.Declaration(owner_id, kind, ()),))
    extra = _assess(sample, admitted, declarations=(
        admission.Declaration(owner_id, kind, paths + ("src/verifier/sample/extra/__init__.py",)),))
    not_init = _assess(sample, admitted, declarations=(
        admission.Declaration(owner_id, kind, paths + ("src/verifier/sample/engine.py",)),))

    assert "PATH_REMOVED" in _codes(removed) and removed.status == "FAIL"
    assert "PATH_ADDED" in _codes(extra) and extra.status == "FAIL"
    assert "PATH_NOT_PACKAGE_INIT" in _codes(not_init) and not_init.status == "FAIL"


def test_hardware_partial_owner_fails_atomically(tmp_path: Path) -> None:
    _write(tmp_path, {
        "src/verifier/pair/__init__.py": "from .engine import Widget\n__all__ = [\"Widget\"]\n",
        "src/verifier/pair/engine.py": "class Widget:\n    pass\n",
        "src/verifier/pair/more/__init__.py": "from verifier.pair.engine import Widget as Gizmo\n__all__ = [\"Gizmo\"]\n",
    })
    paths = ("src/verifier/pair/__init__.py", "src/verifier/pair/more/__init__.py")
    entry = admission.derive(tmp_path, "tmp-pair-owner", "HARDWARE", paths)
    partial = _assess(tmp_path, (entry,), declarations=(
        admission.Declaration("tmp-pair-owner", "HARDWARE", (paths[0],)),))

    assert partial.status == "FAIL"
    assert "ATOMIC_OWNER_PARTIAL" in _codes(partial)
    complete = _assess(tmp_path, (entry,), declarations=(admission.Declaration("tmp-pair-owner", "HARDWARE", paths),))
    assert complete.owners[0].status == "PASS"  # report stays UNKNOWN: caller catalogs are not whole-package authority


def test_object_fallback_never_satisfies_ownership(sample: Path, admitted) -> None:
    owner_id, _kind, paths = SAMPLE_OWNER
    by_kind = _assess(sample, admitted, declarations=(admission.Declaration(owner_id, "OBJECT", paths),))
    by_owner = _assess(sample, admitted, declarations=(admission.Declaration("OBJECT", "ARCH", paths),))
    by_directory = _assess(sample, admitted, declarations=(
        admission.Declaration(owner_id, "ARCH", ("src/verifier/sample",)),))

    assert by_kind.status == "FAIL" and "OBJECT_FALLBACK_REFUSED" in _codes(by_kind)
    assert by_owner.status == "FAIL" and "OBJECT_FALLBACK_REFUSED" in _codes(by_owner)
    assert by_directory.status == "FAIL" and "PATH_NOT_PACKAGE_INIT" in _codes(by_directory)
    with pytest.raises(admission.AdmissionError):
        admission.derive(sample, "tmp-object", "OBJECT", paths)


def test_admitted_catalog_row_cannot_be_an_object_fallback_owner(sample: Path, admitted) -> None:
    fallback = (replace(admitted[0], owner_id=REFUSED_OWNER),)
    report = _assess(sample, fallback)

    assert report.status == "FAIL"
    assert "OBJECT_FALLBACK_REFUSED" in _codes(report)


def test_role_like_export_is_never_assigned_a_consequence_role(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"VERSION", "Widget"', b'"ActorLedgerKey", "VERSION", "Widget"')
                     .replace(b'VERSION = "1"\n', b'VERSION = "1"\nActorLedgerKey = 2\n'))
    report = _assess(sample, admitted)

    assert report.owners[0].consequence_roles == "NOT_ASSESSED"
    assert report.status == "FAIL"
    assert {b.export: b.route for b in report.owners[0].bindings}["ActorLedgerKey"] == "LOCAL_DEFINITION"
    assert "EXPORT_ADDED" in _codes(report)
    assert "role" not in {key for key in report.to_dict()["owners"][0] if key != "consequence_roles"}


@pytest.mark.parametrize(("text", "code", "status"), [
    ("from .missing import Widget\n__all__ = [\"Widget\"]\n", "UNRESOLVED_IMPORT_TARGET", "FAIL"),
    ("from os import path as Road\n__all__ = [\"Road\"]\n", "NON_LOCAL_BINDING", "FAIL"),
    ("from .engine import *\n__all__ = [\"Widget\"]\n", "DYNAMIC_IMPORT", "UNKNOWN"),
    ("from .engine import Widget\n__all__ = [\"Widget\"]\nregister(Widget)\n", "DYNAMIC_TOP_LEVEL", "UNKNOWN"),
    ("from .engine import Widget\n__all__ = [\"Widget\"]\ndef broken(:\n", "SOURCE_UNPARSEABLE", "FAIL"),
])
def test_owner_shape_mutations_carry_their_own_status(sample: Path, admitted, text: str, code: str, status: str) -> None:
    (sample / SAMPLE_OWNER[2][0]).write_bytes(text.encode("utf-8"))
    report = _assess(sample, admitted)

    assert code in _codes(report)
    assert _finding_status(report, code) == {status}
    assert report.status != "PASS"


def test_cyclic_reexport_fails(sample: Path, admitted) -> None:
    _write(sample, {
        "src/verifier/sample/__init__.py": "from .shapes import Circle as Round\n__all__ = [\"Round\"]\n",
        "src/verifier/sample/shapes.py": "from .engine import Widget as Circle\n",
        "src/verifier/sample/engine.py": "from .shapes import Circle as Widget\n",
    })
    report = _assess(sample, admitted)

    assert report.status == "FAIL"
    assert _finding_status(report, "CIRCULAR_REEXPORT") == {"FAIL"}


def test_every_finding_names_object_path_obligation_reason_and_next_action(sample: Path, admitted) -> None:
    init = sample / SAMPLE_OWNER[2][0]
    init.write_bytes(init.read_bytes().replace(b'"Round"', b'"Ring"'))
    report = _assess(sample, admitted)
    findings = [f for o in report.owners for f in o.findings] + list(report.unadmitted_findings)

    assert findings
    for finding in findings:
        # Catalog-level findings (for example a caller catalog that is not whole-package authority) name the catalog object.
        assert finding.object_id in {SAMPLE_OWNER[0], "tier0-catalog"}
        assert finding.path
        assert finding.obligation == admission.OBLIGATION
        assert finding.reason and finding.next_action
        assert finding.status in {"FAIL", "UNKNOWN"}


# --- Independent-audit counterexamples -------------------------------------
# Each case is a self-contained tree. ``derive`` pins the mutated bytes itself,
# so a refusal is the mechanism's own verdict on the counterexample, not drift.

ENGINE = "src/verifier/sample/engine.py"
INIT = SAMPLE_OWNER[2][0]


def _derive_findings(root: Path, owner=SAMPLE_OWNER) -> tuple[admission.Finding, ...]:
    """Findings that refuse ``derive`` over ``root``; an empty tuple means the row was admitted."""
    try:
        admission.derive(root, *owner)
    except admission.AdmissionError as exc:
        return exc.findings
    return ()


def _assert_diagnostic(findings, code: str, status: str, path: str) -> None:
    hits = [f for f in findings if f.code == code]
    assert hits, f"expected {code}; got {sorted({f.code for f in findings})}"
    assert {f.status for f in hits} == {status}
    assert any(f.path == path for f in hits), [(f.code, f.path) for f in hits]
    for f in hits:
        assert f.object_id == SAMPLE_OWNER[0]
        assert f.obligation == admission.OBLIGATION
        assert f.reason and f.next_action


# Audit 1: a definition shadowed by a star import must never be admitted.

def test_audit1_target_definition_shadowed_by_later_star_import_is_refused(sample: Path) -> None:
    _write(sample, {
        ENGINE: "class Widget:\n    pass\nfrom .other import *\n",
        "src/verifier/sample/other.py": "class Widget:\n    pass\n",
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_IMPORT", "UNKNOWN", ENGINE)


def test_audit1_owned_definition_shadowed_by_later_star_import_is_refused(sample: Path) -> None:
    _write(sample, {
        INIT: "class Widget:\n    pass\nfrom .other import *\n__all__ = [\"Widget\"]\n",
        "src/verifier/sample/other.py": "class Widget:\n    pass\n",
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_IMPORT", "UNKNOWN", INIT)


# Audit 2: name rebinding by globals(), setattr, module mutation, or decorator replacement.

@pytest.mark.parametrize("extra", [
    'globals()["Widget"] = object()\n',
    'import sys\nsetattr(sys.modules[__name__], "Widget", object())\n',
])
def test_audit2_global_or_setattr_rebinding_of_owned_export_is_refused(sample: Path, extra: str) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__ = ["Widget"]\n' + extra})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", INIT)


def test_audit2_module_attribute_mutation_in_target_is_refused(sample: Path) -> None:
    _write(sample, {ENGINE: "import verifier.sample as pkg\npkg.Widget = object()\nclass Widget:\n    pass\n"})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", ENGINE)


def test_audit2_decorator_replacement_of_target_binding_is_refused(sample: Path) -> None:
    _write(sample, {ENGINE: "def replace(cls):\n    return object()\n\n\n@replace\nclass Widget:\n    pass\n"})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TARGET", "UNKNOWN", ENGINE)


def test_audit2_decorator_replacement_of_owned_binding_is_refused(sample: Path) -> None:
    _write(sample, {
        INIT: 'def replace(cls):\n    return object()\n\n\n@replace\nclass Widget:\n    pass\n__all__ = ["Widget"]\n',
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_BINDING", "UNKNOWN", INIT)


# Audit 3: a transitively imported module that mutates package exports at import time.

def test_audit3_transitive_import_side_effect_mutating_exports_is_refused(sample: Path) -> None:
    _write(sample, {
        ENGINE: "from . import hooks\nclass Widget:\n    pass\n",
        "src/verifier/sample/hooks.py": "import verifier.sample as pkg\npkg.Extra = object()\n",
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", "src/verifier/sample/hooks.py")


# Audit 4: a non-exported import of a symbol the module does not define still fails at import time.

def test_audit4_non_exported_import_of_missing_symbol_is_refused(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\nfrom .engine import Missing\n__all__ = ["Widget"]\n'})
    _assert_diagnostic(_derive_findings(sample), "UNRESOLVED_SYMBOL", "FAIL", ENGINE)


# Audit 5: a relative import that escapes the top-level package is refused.

def test_audit5_relative_import_beyond_top_level_is_refused(sample: Path) -> None:
    _write(sample, {
        "src/engine.py": "class Widget:\n    pass\n",
        INIT: 'from ...engine import Widget\n__all__ = ["Widget"]\n',
    })
    _assert_diagnostic(_derive_findings(sample), "RELATIVE_IMPORT_BEYOND_TOP_LEVEL", "FAIL", INIT)


# Audit 6: exact-case matching on case-insensitive filesystems.

def test_audit6_module_name_differing_only_in_case_is_refused(sample: Path) -> None:
    _write(sample, {INIT: 'from .Engine import Widget\n__all__ = ["Widget"]\n'})
    _assert_diagnostic(_derive_findings(sample), "CASE_MISMATCH", "FAIL", "src/verifier/sample/Engine.py")


def test_audit6_owned_directory_differing_only_in_case_is_refused(sample: Path) -> None:
    findings = _derive_findings(sample, (SAMPLE_OWNER[0], SAMPLE_OWNER[1], ("src/verifier/SAMPLE/__init__.py",)))
    _assert_diagnostic(findings, "CASE_MISMATCH", "FAIL", "src/verifier/SAMPLE/__init__.py")


# Audit 7: sibling extension or bytecode files shadow a source module at import time.

@pytest.mark.parametrize("shadow", [
    "engine.pyd",
    "engine.so",
    "engine.cpython-312-x86_64-linux-gnu.so",
    "engine.pyc",
    "__init__.pyd",
])
def test_audit7_sibling_extension_or_bytecode_shadow_blocks_static_pass(sample: Path, shadow: str) -> None:
    path = "src/verifier/sample/" + shadow
    _write(sample, {path: "not a real binary\n"})
    _assert_diagnostic(_derive_findings(sample), "SHADOW_CANDIDATE", "UNKNOWN", path)


# Audit 8: a junction or symlink that escapes the repository root fails closed.

def test_audit8_junction_escape_from_root_is_refused(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("junction reparse points are a Windows case")
    root, outside = tmp_path / "root", tmp_path / "outside"
    _write(root, SAMPLE_FILES)
    outside.mkdir()
    (outside / "engine.py").write_text("class Widget:\n    pass\n", encoding="utf-8")
    link = root / "src/verifier/sample/linked"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True, capture_output=True)
    _write(root, {INIT: 'from .linked.engine import Widget\n__all__ = ["Widget"]\n'})
    _assert_diagnostic(_derive_findings(root), "PATH_ESCAPE", "FAIL", "src/verifier/sample/linked")


def test_audit8_symlinked_owned_file_escape_is_refused(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside_init.py"
    _write(root, {k: v for k, v in SAMPLE_FILES.items() if k != INIT})
    outside.write_text(SAMPLE_FILES[INIT], encoding="utf-8")
    try:
        os.symlink(outside, root / INIT)
    except OSError as exc:
        # Skip classification per AGENTS.md section 9.2 (docs/TEST_SKIP_RUBRIC.md).
        pytest.skip(f"OS_CAPABILITY_GUARD: symlink creation needs privilege on this host ({exc.__class__.__name__})")
    _assert_diagnostic(_derive_findings(root), "PATH_ESCAPE", "FAIL", INIT)


# Audit 9: __all__ is the only declared scope; __getattr__ and unlisted public names cannot pass silently.

def test_audit9_module_getattr_on_owned_surface_is_refused(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__ = ["Widget"]\n\n\ndef __getattr__(name):\n    raise AttributeError(name)\n'})
    _assert_diagnostic(_derive_findings(sample), "MODULE_GETATTR", "UNKNOWN", INIT)


def test_audit9_unlisted_public_helper_is_not_silently_whole_package_surface(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__ = ["Widget"]\n\n\ndef helper():\n    return 1\n'})
    _assert_diagnostic(_derive_findings(sample), "UNLISTED_PUBLIC_NAME", "UNKNOWN", INIT)


# Audit 10: a candidate created between the opening and closing snapshots must be detected at close.

@pytest.mark.parametrize("shadow", ["engine.pyd", "engine/__init__.py"])
def test_audit10_candidate_created_after_opening_snapshot_is_unknown(sample: Path, admitted, monkeypatch, shadow: str) -> None:
    original = admission._read_bytes
    reads: dict[Path, int] = {}

    def creating(path: Path) -> bytes:
        reads[path] = reads.get(path, 0) + 1
        data = original(path)
        if path.name == "__init__.py" and reads[path] == 2:
            target = path.parent / shadow
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"created after the opening snapshot\n")
        return data

    monkeypatch.setattr(admission, "_read_bytes", creating)
    report = _assess(sample, admitted)

    assert report.status == "UNKNOWN"
    assert "SOURCE_CHANGED_DURING_CHECK" in _codes(report)


# Audit 11: a valid submodule import from a package is not an unresolved symbol.

def test_audit11_valid_submodule_import_from_package_is_admitted_as_submodule(sample: Path) -> None:
    _write(sample, {
        "src/verifier/sample/subpkg/__init__.py": "",
        "src/verifier/sample/subpkg/leaf.py": "VALUE = 1\n",
        INIT: 'from .subpkg import leaf\n__all__ = ["leaf"]\n',
    })
    assert _derive_findings(sample) == ()
    entry = admission.derive(sample, *SAMPLE_OWNER)
    assert entry.bindings[0][1:3] == ("leaf", "SUBMODULE")


# Audit 12: an annotated literal __all__ is deterministic; an annotation without a value is never PASS.

def test_audit12_annotated_literal_all_is_admitted_deterministically(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__: list[str] = ["Widget"]\n'})
    assert _derive_findings(sample) == ()
    assert [row[1] for row in admission.derive(sample, *SAMPLE_OWNER).bindings] == ["Widget"]


def test_audit12_bare_annotated_all_is_unknown_never_pass(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__: list[str]\n__all__ = ["Widget"]\n'})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_ALL", "UNKNOWN", INIT)


# Audit 13: a forged, vacuous, truncated, or relabeled catalog never passes; declarations are independent.

def test_audit13_empty_catalog_never_passes() -> None:
    assert admission.assess(ROOT, admitted=()).status != "PASS"


def test_audit13_truncated_catalog_never_passes() -> None:
    report = admission.assess(ROOT, admitted=admission.ADMITTED[1:])
    assert report.status != "PASS"
    assert "OWNER_UNADMITTED" in _codes(report)


def test_audit13_relabeled_catalog_never_passes() -> None:
    relabeled = (replace(admission.ADMITTED[0], owner_id="vstd-relabeled-package-api"),) + admission.ADMITTED[1:]
    report = admission.assess(ROOT, admitted=relabeled)
    assert report.status != "PASS"
    assert {"OWNER_MISSING", "OWNER_UNADMITTED"} <= _codes(report)


def test_audit13_forged_kind_in_catalog_is_substituted_not_accepted() -> None:
    forged = tuple(
        replace(owner, primary_kind="DATA") if owner.owner_id == "vstd-consent-package-api" else owner
        for owner in admission.ADMITTED
    )
    report = admission.assess(ROOT, admitted=forged)
    assert report.status == "FAIL"
    assert "KIND_SUBSTITUTED" in _codes(report)


# Unreviewed package surfaces are explicit UNKNOWN blockers, never omitted.

def test_unreviewed_package_surfaces_are_explicit_unknown_blockers() -> None:
    reviewed = {path for _kind, paths, _count in AUDITED.values() for path in paths}
    expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / "src/verifier").glob("**/__init__.py")} - reviewed
    assert len(expected) == 10
    report = admission.assess(ROOT)
    blockers = [f for f in report.unadmitted_findings if f.code == "SURFACE_UNREVIEWED"]
    assert {f.path for f in blockers} == expected
    assert {f.status for f in blockers} == {"UNKNOWN"}


def test_claim_boundary_names_binding_closure_not_import_or_runtime_closure() -> None:
    assert "binding closure" in admission.CLAIM_BOUNDARY
    assert "not an import or runtime closure" in admission.CLAIM_BOUNDARY


# Guards that must stay green: identity decorators are admitted; the report digest is path-independent.

def test_guard_dataclass_identity_decorator_is_not_refused(sample: Path) -> None:
    _write(sample, {ENGINE: "from dataclasses import dataclass\n\n\n@dataclass(frozen=True)\nclass Widget:\n    x: int = 1\n"})
    assert _derive_findings(sample) == ()


def test_guard_report_digest_is_independent_of_the_checkout_location(tmp_path: Path) -> None:
    digests = []
    for name in ("first", "second"):
        root = tmp_path / name
        _write(root, SAMPLE_FILES)
        entry = admission.derive(root, *SAMPLE_OWNER)
        digests.append(admission.assess(root, admitted=(entry,), declarations=(admission.Declaration(*SAMPLE_OWNER),)).report_digest)
    assert digests[0] == digests[1]


def test_guard_dotdot_declared_path_is_refused(sample: Path) -> None:
    findings = _derive_findings(sample, (SAMPLE_OWNER[0], SAMPLE_OWNER[1], ("src/verifier/sample/../../../escape/__init__.py",)))
    assert any(f.code == "PATH_NOT_REPOSITORY_FILE" and f.status == "FAIL" for f in findings)


def test_guard_builtin_descriptor_decorators_are_not_import_time_effects(sample: Path) -> None:
    _write(sample, {ENGINE: (
        "class Widget:\n"
        "    @property\n"
        "    def size(self):\n"
        "        return 1\n\n"
        "    @classmethod\n"
        "    def make(cls):\n"
        "        return cls()\n"
    )})
    assert _derive_findings(sample) == ()


def test_reviewed_declarations_are_independent_and_exactly_the_audited_slice() -> None:
    declared = {d.owner_id: (d.primary_kind, d.owned_paths) for d in admission.REVIEWED_DECLARATIONS}

    assert declared == {owner: (kind, paths) for owner, (kind, paths, _count) in AUDITED.items()}
    assert len(admission.REVIEWED_DECLARATIONS) == 10
    assert sum(len(d.owned_paths) for d in admission.REVIEWED_DECLARATIONS) == 11


def test_slice_cardinality_is_enforced_on_the_default_catalog(monkeypatch) -> None:
    monkeypatch.setattr(admission, "REVIEWED_DECLARATIONS", admission.REVIEWED_DECLARATIONS[:-1])
    report = admission.assess(ROOT)

    assert "SLICE_CARDINALITY" in _codes(report)
    assert report.reviewed_status == "FAIL"


# --- Review round 2: fail-closed catalogs, import-graph reach, and shadow candidates ---
# Each test below was observed to fail (WRONG-ADMIT or vacuous PASS) before its repair.

def test_r1_empty_caller_catalog_and_declarations_never_pass() -> None:
    report = admission.assess(ROOT, admitted=(), declarations=())

    assert report.status == "UNKNOWN"
    assert _all_status(report, "CATALOG_NOT_ENUMERATED") == {"UNKNOWN"}
    reason = next(f.reason for f in report.unadmitted_findings if f.code == "CATALOG_NOT_ENUMERATED")
    assert "not whole-package enumeration authority" in reason


def test_r1_truncated_caller_catalog_with_matching_declarations_never_passes() -> None:
    report = admission.assess(ROOT, admitted=admission.ADMITTED[1:], declarations=tuple(
        d for d in admission.REVIEWED_DECLARATIONS if d.owner_id != admission.ADMITTED[0].owner_id))

    assert report.status != "PASS"
    assert _all_status(report, "CATALOG_NOT_ENUMERATED") == {"UNKNOWN"}


def test_r2_from_alias_submodule_import_enqueues_leaf_and_its_mutation_blocks(sample: Path) -> None:
    _write(sample, {
        INIT: 'from .engine import Widget\nfrom .subpkg import leaf as _leaf\n__all__ = ["Widget"]\n',
        "src/verifier/sample/subpkg/__init__.py": "",
        "src/verifier/sample/subpkg/leaf.py": "import verifier.sample as pkg\npkg.Widget = object()\n",
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", "src/verifier/sample/subpkg/leaf.py")


def test_r3_builtin_name_rebound_by_import_is_not_builtin_pure(sample: Path) -> None:
    _write(sample, {
        ENGINE: "from . import helpers\nfrom .helpers import mutate as len\nclass Widget:\n    pass\n_X = len(Widget)\n",
        "src/verifier/sample/helpers.py": "import verifier.sample as pkg\ndef mutate(x):\n    pkg.Widget = object()\n    return x\n",
    })
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", ENGINE)


def test_r3_builtin_origin_established_safe_stays_pure(sample: Path) -> None:
    _write(sample, {ENGINE: "from builtins import len\nclass Widget:\n    pass\n_X = len((1, 2))\n"})
    assert _derive_findings(sample) == ()


def test_r4_lambda_body_reached_at_import_time_is_analysed(sample: Path) -> None:
    _write(sample, {INIT: 'from .engine import Widget\n__all__ = ["Widget"]\n'
                          '_X = sorted([1], key=lambda k: globals().update(Extra=k) or k)\n'})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", INIT)


def test_r5_class_body_non_name_store_is_an_import_time_effect(sample: Path) -> None:
    _write(sample, {ENGINE: "import sys\nclass Widget:\n    sys.modules[__name__].Extra = object()\n"})
    _assert_diagnostic(_derive_findings(sample), "DYNAMIC_TOP_LEVEL", "UNKNOWN", ENGINE)


@pytest.mark.parametrize("shadow", [
    "__pycache__/engine.cpython-312.pyc",
    "__pycache__/engine.pyc",
    "__pycache__/engine.cpython-312.opt-1.pyc",
])
def test_r6_pycache_bytecode_candidate_blocks_static_pass(sample: Path, shadow: str) -> None:
    path = "src/verifier/sample/" + shadow
    _write(sample, {path: "unchecked-hash bytecode placeholder\n"})
    _assert_diagnostic(_derive_findings(sample), "SHADOW_CANDIDATE", "UNKNOWN", path)


def test_r6_pycache_init_bytecode_candidate_blocks_static_pass(sample: Path) -> None:
    path = "src/verifier/sample/__pycache__/__init__.cpython-312.pyc"
    _write(sample, {path: "unchecked-hash bytecode placeholder\n"})
    _assert_diagnostic(_derive_findings(sample), "SHADOW_CANDIDATE", "UNKNOWN", path)


def test_r7_owned_directory_junction_escape_is_refused(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("OS_CAPABILITY_GUARD: directory junctions are a Windows reparse-point case")
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "src/verifier").mkdir(parents=True)
    outside.mkdir()
    (outside / "__init__.py").write_text(SAMPLE_FILES[INIT], encoding="utf-8")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "src/verifier/sample"), str(outside)],
                   check=True, capture_output=True)
    _assert_diagnostic(_derive_findings(root), "PATH_ESCAPE", "FAIL", "src/verifier/sample")


def test_r8_claim_names_ancestor_namespace_as_not_assessed_and_not_runtime() -> None:
    assert "src/verifier/__init__.py is NOT_ASSESSED" in admission.CLAIM_BOUNDARY
    assert "not fresh-process runtime correctness" in admission.CLAIM_BOUNDARY
    report = admission.assess(ROOT)
    ancestor = [f for f in report.unadmitted_findings if f.path == "src/verifier/__init__.py"]

    assert ancestor and {f.status for f in ancestor} == {"UNKNOWN"}
    assert "NOT_ASSESSED" in ancestor[0].reason
    assert report.status == "UNKNOWN"


def _independent_catalog_digest(catalog) -> str:
    """Canonical JavaScript Object Notation (JSON) digest recomputed here with only the standard library, not with the module under test."""
    text = json.dumps([asdict(owner) for owner in catalog], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def test_r10_default_catalog_digest_is_pinned_and_independently_recomputed() -> None:
    assert admission.ADMITTED_CATALOG_DIGEST == _independent_catalog_digest(admission.ADMITTED)
    assert _independent_catalog_digest(admission.ADMITTED) == EXPECTED_CATALOG_DIGEST


def test_r10_caller_catalog_is_reported_unpinned_and_default_is_pinned() -> None:
    caller = admission.assess(ROOT, admitted=admission.ADMITTED)
    default = admission.assess(ROOT)

    assert caller.catalog_pin == "CALLER_SUPPLIED_UNPINNED"
    assert default.catalog_pin == "PINNED_MATCH"
    assert caller.status != "PASS"


def test_r10_default_catalog_drift_from_its_pin_is_fail(monkeypatch) -> None:
    drifted = (replace(admission.ADMITTED[0], owner_id="vstd-relabeled-package-api"),) + admission.ADMITTED[1:]
    monkeypatch.setattr(admission, "ADMITTED", drifted)
    report = admission.assess(ROOT)

    assert report.catalog_pin == "PIN_MISMATCH"
    assert _all_status(report, "CATALOG_PIN_MISMATCH") == {"FAIL"}
    assert report.status == "FAIL"


# Pinned by hand from the independent recomputation above; a change to ADMITTED must update both sources.
EXPECTED_CATALOG_DIGEST = "sha256:3d6f943301c1c06199aa6721e420f2047e7d5a61a6c4858695348a6acdb2d24f"

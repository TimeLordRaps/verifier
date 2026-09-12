"""Explicit installed-wheel composition tests for Verifier Standard (VSTD).

The source-side pytest runner generates inert finite fixtures; only the interpreter
named by VSTD_INSTALLED_PYTHON consumes them, in isolated mode outside the checkout.
JavaScript Object Notation (JSON) command-line interface (CLI) results remain bounded
model diagnostics, not source/runtime correspondence or general agency proofs.
Secure Hash Algorithm 256-bit (SHA-256) checks bind the inspected installed module
bytes to distribution RECORD entries and, when supplied, VSTD_INSTALLED_WHEEL.
This file is explicitly selected, not part of ordinary test_*.py collection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Callable

import pytest

from test_authority_composition import _fixture
from verifier import __version__ as SOURCE_VERSION
from verifier.interoperability.authority_composition import (
    assess_authority_composition, authority_composition_profile_digest,
)
from verifier.interoperability.network import assess_composition, canonical_bytes, digest_bytes


_CHECKOUT = Path(__file__).resolve().parents[1]
_ORIGIN_PROBE = r'''
import base64
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import sys
import sysconfig
import zipfile

checkout = Path(sys.argv[1]).resolve()
assert sys.flags.isolated == 1
assert not Path.cwd().resolve().is_relative_to(checkout), "consumer cwd is inside checkout"
distribution = importlib.metadata.distribution("verifier-standard")
root = Path(distribution.locate_file("")).resolve()
sites = {Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")}
assert root in sites, "distribution is not in this interpreter's installed site-packages"
assert not root.is_relative_to(checkout), "distribution is inside checkout"
direct_url = json.loads(distribution.read_text("direct_url.json") or "{}")
assert not direct_url.get("dir_info", {}).get("editable"), "editable install is not wheel evidence"
files = {str(item).replace("\\", "/"): item for item in distribution.files or ()}
wheel_path = Path(sys.argv[2]).resolve() if sys.argv[2] else None
wheel = zipfile.ZipFile(wheel_path) if wheel_path else None
modules = {}
try:
    for name in (
        "verifier", "verifier.interoperability.composition_qualification",
        "verifier.interoperability.authority_composition", "verifier.interoperability.network",
        "verifier.interoperability.reference_catalog",
        "verifier.runtime.network_cli", "verifier.runtime.public_cli",
    ):
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(root) and not path.is_relative_to(checkout), "module is not installed: " + name
        relative = path.relative_to(root).as_posix()
        record = files.get(relative)
        assert record is not None and record.hash is not None, "module lacks RECORD hash: " + name
        assert record.hash.mode == "sha256", "unsupported RECORD hash: " + name
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).digest()
        recorded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert recorded == record.hash.value and len(payload) == record.size, "installed bytes differ from RECORD: " + name
        if wheel is not None:
            assert payload == wheel.read(relative), "installed bytes differ from wheel: " + name
        modules[name] = {"distribution_path": relative, "sha256": digest.hex(), "record_match": True,
                         "wheel_match": True if wheel is not None else None}
finally:
    if wheel is not None:
        wheel.close()
registry = importlib.import_module("verifier.interoperability.reference_catalog").reference_component_registry()
qualifier = registry.get("component:artifact-network-finite-composition-qualifier")
raw = registry.get("component:artifact-network-authority-composition-assessor")
assert qualifier.implementation_ref == "verifier.interoperability.composition_qualification:qualify_silo_composition"
module_name, attribute = qualifier.implementation_ref.split(":")
resolved = getattr(importlib.import_module(module_name), attribute)
assert resolved is importlib.import_module("verifier.interoperability.composition_qualification").qualify_silo_composition
assert callable(resolved)
assert qualifier.supported_relations == ("relation:qualifies-selected-finite-silo-composition",)
assert qualifier.mechanism_ids == ("mechanism:artifact-network-finite-composition-qualification",)
assert raw.implementation_ref == "verifier.interoperability.authority_composition:assess_authority_composition"
assert raw.supported_relations == ("relation:assesses-finite-authority-composition",)
assert raw.mechanism_ids == ("mechanism:finite-authority-composition-assessment",)
registry_binding = {"qualifier_implementation": qualifier.implementation_ref,
                    "qualifier_relation": qualifier.supported_relations[0], "qualifier_mechanism": qualifier.mechanism_ids[0],
                    "raw_implementation": raw.implementation_ref,
                    "raw_relation": raw.supported_relations[0], "raw_mechanism": raw.mechanism_ids[0]}
print(json.dumps({"scope": "INSTALLED_MODULE_BYTE_IDENTITY", "version": distribution.version,
                  "isolated": True, "outside_checkout": True, "modules": modules,
                  "registry_binding": registry_binding,
                  "wheel_sha256": hashlib.sha256(wheel_path.read_bytes()).hexdigest() if wheel_path else None}, sort_keys=True))
'''


def _consume(interpreter: Path, cwd: Path, arguments: list[str], label: str) -> subprocess.CompletedProcess[str]:
    """Capture the bounded structured response, announcing each isolated invocation."""
    assert not cwd.resolve().is_relative_to(_CHECKOUT), "consumer directory must be outside checkout"
    print(f"INSTALLED_CONSUMER_START {label}: isolated interpreter, outside checkout, timeout=15 seconds", flush=True)
    result = subprocess.run(
        [str(interpreter), "-I", "-u", *arguments], cwd=cwd, text=True,
        encoding="utf-8", capture_output=True, timeout=15, check=False,
    )
    assert len(result.stdout) + len(result.stderr) <= 262144, "consumer diagnostic exceeds bounded output"
    print(f"INSTALLED_CONSUMER_RESULT {label}: exit={result.returncode}", flush=True)
    print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    return result


@pytest.fixture
def installed_interpreter() -> Path:
    configured = os.environ.get("VSTD_INSTALLED_PYTHON")
    assert configured, "VSTD_INSTALLED_PYTHON is required; this explicitly selected suite must not skip"
    interpreter = Path(configured)
    assert interpreter.is_absolute(), "VSTD_INSTALLED_PYTHON must be an exact absolute interpreter path"
    assert interpreter.is_file(), "VSTD_INSTALLED_PYTHON must name an existing interpreter"
    return interpreter


def _origin(interpreter: Path, cwd: Path) -> dict[str, Any]:
    wheel = os.environ.get("VSTD_INSTALLED_WHEEL", "")
    if wheel:
        wheel = str(Path(wheel).resolve(strict=True))
    result = _consume(interpreter, cwd, ["-c", _ORIGIN_PROBE, str(_CHECKOUT), wheel], "module-origin")
    assert result.returncode == 0, "installed origin/RECORD/wheel validation failed"
    assert not result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("omit", [None, "t01"], ids=["exact-product", "omitted-transition"])
def test_installed_strict_composition(
    installed_interpreter: Path, omit: str | None, record_testsuite_property: Callable[[str, object], None],
) -> None:
    with tempfile.TemporaryDirectory(prefix="vstd-installed-composition-") as directory:
        outside = Path(directory).resolve()
        assert not outside.is_relative_to(_CHECKOUT), "fixture directory must be outside checkout"
        origin = _origin(installed_interpreter, outside)
        assert origin["version"] == SOURCE_VERSION
        case = "exact-product" if omit is None else "omitted-transition"
        record_testsuite_property(f"{case}.installed_module_origin", json.dumps(origin, sort_keys=True))
        # Generation uses source fixture helpers; consumer invocations never import these helpers.
        declaration, evidence, pairs = _fixture(outside, omit=omit)
        declaration["profile_digest"] = authority_composition_profile_digest()
        declaration_path = outside / "finite-composition.json"
        declaration_path.write_bytes(canonical_bytes(declaration))
        arguments = ["-m", "verifier.runtime.public_cli", "network", "compose"]
        for index, (commit, store) in enumerate(pairs):
            path = outside / f"commit-{index}.json"
            path.write_bytes(canonical_bytes(commit.to_dict()))
            if index < len(pairs) - 1:
                arguments.extend(("--silo", str(store.root), str(path)))
            else:
                arguments.extend(("--composite-store", str(store.root), "--composite-commit", str(path)))
        arguments.extend(("--require-finite-authority-composition", str(declaration_path)))
        result = _consume(installed_interpreter, outside, arguments, "strict-compose")
        record_testsuite_property(f"{case}.consumer_exit_code", result.returncode)
        assert result.returncode == (0 if omit is None else 1)
        assert not result.stderr
        report = json.loads(result.stdout)
        record_testsuite_property(f"{case}.strict_composition_result", json.dumps(report, sort_keys=True))
        assert report["qualification"] == ("FINITE_COMPOSITION_QUALIFIED" if omit is None else "NOT_QUALIFIED")
        assert report["qualification_scope"] == "EXACT_SELECTED_FINITE_ASYNCHRONOUS_INTERLEAVING"
        assert report["selection_binding"] == "BOUND"
        assert report["coordinates"] == {"members": sorted(commit.canonical_digest() for commit, _store in pairs[:-1]),
                                         "composite": pairs[-1][0].canonical_digest()}
        assert report["declaration_digest"] == digest_bytes(declaration_path.read_bytes())
        # Source-side expected reports are an oracle, not installed-consumer execution evidence.
        assert report["legacy_assessment"] == assess_composition(
            tuple(commit for commit, _store in pairs[:-1]), tuple(store for _commit, store in pairs[:-1]), *pairs[-1],
        )
        assert report["finite_assessment"] == assess_authority_composition(canonical_bytes(declaration), evidence)
        assert report["legacy_assessment"]["result"] == "ADMISSIBLE"
        assert report["legacy_assessment"]["authority_axiom_agency"] == "PRESERVED"
        finite = report["finite_assessment"]
        assert finite["coordinate_binding"] == "BOUND"
        assert finite["transition_correspondence"] == ("MATCHED" if omit is None else "MISMATCH")
        assert finite["agency_preservation"] == ("PRESERVED" if omit is None else "UNKNOWN")
        assert finite["local_addition_preservation"] == ("PRESERVED" if omit is None else "UNKNOWN")
        assert "GENERAL_COMPOSED_AGENCY_NOT_ESTABLISHED" in finite["residual_obligations"]
        assert "FULL_SILO_ASSESSMENT_NOT_PERFORMED" in finite["residual_obligations"]
        assert _origin(installed_interpreter, outside) == origin

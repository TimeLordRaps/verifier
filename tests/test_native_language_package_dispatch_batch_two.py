"""Package-level dispatch for the batch-two native adapters.

The optional ``vstd_languages`` package is imported normally from its source tree
(``extensions/languages/src`` is prepended to ``sys.path``, as the sibling adapter tests
do), never loaded by file path. Toolchains are faked with a recorded ``shutil.which`` so
no compiler starts, except the Assembly end-to-end specimen, which runs only when ``gcc``
is present and is a classified skip otherwise. Core admits these five names only after
explicit language selection; these tests independently pin the package dispatch contract.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "extensions/languages/src"
sys.path.insert(0, str(SOURCE))
import vstd_languages  # noqa: E402
from vstd_languages import extended_batch_two  # noqa: E402

PYPROJECT = REPO / "extensions/languages/pyproject.toml"
PROTOCOL = "verifier-language-runner-1"
ORIGINAL_SIXTEEN = {"javascript", "c", "cpp", "java", "rust", "perl", "sql", "fortran",
                    "php", "lisp", "prolog", "csharp", "go", "r", "swift", "julia"}
BATCH_TWO = {
    "cobol": ("cobc", {".cob", ".cbl"}),
    "object-pascal": ("fpc", {".pas", ".pp"}),
    "ada": ("gnatmake", {".adb"}),
    "objective-c": ("clang", {".m"}),
    "assembly": ("gcc", {".s"}),
}
ENTRY = {"cobol": "specimen.cob", "object-pascal": "specimen.pas", "ada": "specimen.adb",
         "objective-c": "specimen.m", "assembly": "specimen.s"}
ASSEMBLY_SPECIMEN = "    .text\n    .globl main\nmain:\n    movl $42, %eax\n    ret\n"


@pytest.fixture
def package():
    """The installed-source package, imported with the normal import statement."""
    assert Path(vstd_languages.__file__).resolve().is_relative_to(SOURCE.resolve())
    return vstd_languages


@pytest.fixture
def toolchain(monkeypatch):
    """Resolve only the named tool; every lookup is recorded so a fallback cannot hide."""
    def install(tool):
        seen = []

        def which(name, path=None):
            seen.append(name)
            return f"/opt/fake-toolchain/{name}" if name == tool else None

        monkeypatch.setattr(shutil, "which", which)
        return seen

    return install


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return root


def _request(language, root, entry, arguments=()):
    return {"schema_version": PROTOCOL, "language": language, "root": str(root),
            "entry": entry, "arguments": list(arguments)}


# --- registration: exact names, suffixes, tools and entry points -----------

def test_package_registers_exact_names_suffixes_and_tools(package):
    assert set(package.SUFFIXES) == ORIGINAL_SIXTEEN | set(BATCH_TWO)
    for name, (tool, suffixes) in BATCH_TWO.items():
        assert package.TOOLS[name] == tool
        assert package.SUFFIXES[name] == suffixes


def test_entry_point_metadata_declares_each_batch_two_name_on_the_package_callable():
    text = PYPROJECT.read_text(encoding="utf-8")
    section = text.split('[project.entry-points."verifier.language_runners"]', 1)[1].split("\n[", 1)[0]
    declared = dict(re.findall(r'^([A-Za-z0-9_-]+) = "([^"]+)"$', section, flags=re.MULTILINE))
    # The four implemented batch-three names are declared too; Classic Visual Basic is not (NOT_ESTABLISHED).
    implemented_three = {"visual-basic", "scratch", "matlab", "sas"}
    assert declared == {name: "vstd_languages:command"
                        for name in ORIGINAL_SIXTEEN | set(BATCH_TWO) | implemented_three}


@pytest.mark.parametrize("language", sorted(BATCH_TWO))
def test_batch_two_suffixes_have_no_other_claimant(package, language):
    for suffix in BATCH_TWO[language][1]:
        claimants = sorted(name for name, suffixes in package.SUFFIXES.items() if suffix in suffixes)
        assert claimants == [language]


def test_ambiguous_suffix_is_never_auto_selected(package, project):
    # perl and prolog both claim .pl; the package refuses to choose without an explicit language.
    assert sorted(name for name, suffixes in package.SUFFIXES.items() if ".pl" in suffixes) == ["perl", "prolog"]
    (project / "main.pl").write_text("x\n", encoding="utf-8")
    request = {"schema_version": PROTOCOL, "root": str(project), "entry": "main.pl", "arguments": []}
    with pytest.raises(KeyError):
        package.command(request)


# --- dispatch: each batch-two name reaches its worker, exactly once --------

@pytest.mark.parametrize("language", sorted(BATCH_TWO))
def test_package_command_dispatches_each_batch_two_name_to_its_worker(package, toolchain, project, language):
    tool, _ = BATCH_TWO[language]
    (project / ENTRY[language]).write_text("x\n", encoding="utf-8")
    toolchain(tool)
    batch = extended_batch_two
    request = _request(language, project, ENTRY[language], ["--run", "a b"])
    result = package.command(request)
    assert result == batch.command(request)
    assert set(result) == {"schema_version", "language", "argv"}
    assert result["schema_version"] == PROTOCOL
    assert result["language"] == language
    assert result["argv"][4] == batch.WORKER
    assert result["argv"][5] == language
    assert result["argv"][6] == str(Path(f"/opt/fake-toolchain/{tool}").resolve())
    assert result["argv"][8:] == ["--run", "a b"]


@pytest.mark.parametrize("language", sorted(BATCH_TWO))
def test_package_missing_toolchain_is_exact_and_never_falls_back(package, monkeypatch, project, language):
    tool, _ = BATCH_TWO[language]
    (project / ENTRY[language]).write_text("x\n", encoding="utf-8")
    seen = []

    def no_tool(name, path=None):
        seen.append(name)
        return None

    monkeypatch.setattr(shutil, "which", no_tool)
    with pytest.raises(FileNotFoundError) as missing:
        package.command(_request(language, project, ENTRY[language]))
    assert str(missing.value) == f"RUNNER_TOOLCHAIN_MISSING:{tool}"
    assert seen == [tool]


@pytest.mark.parametrize("language,entry", [
    ("cobol", "specimen.pas"), ("object-pascal", "specimen.cob"), ("ada", "specimen.m"),
    ("objective-c", "specimen.s"), ("assembly", "specimen.adb"),
])
def test_package_explicit_selection_still_validates_dialect(package, toolchain, project, language, entry):
    (project / entry).write_text("x\n", encoding="utf-8")
    toolchain(BATCH_TWO[language][0])
    with pytest.raises(ValueError, match="RUNNER_DIALECT_UNSUPPORTED"):
        package.command(_request(language, project, entry))


@pytest.mark.parametrize("entry,code", [
    ("../escape.cob", "RUNNER_ENTRY_INVALID"), ("-o.cob", "RUNNER_ENTRY_INVALID"),
    ("C:evil.cob", "RUNNER_ENTRY_INVALID"), ("name\x00.cob", "RUNNER_ENTRY_INVALID"),
    ("missing.cob", "RUNNER_ENTRY_MISSING"),
])
def test_package_rejects_hostile_entry_paths_with_the_adapter_code(package, toolchain, tmp_path, project, entry, code):
    (tmp_path / "escape.cob").write_text("x\n", encoding="utf-8")
    toolchain("cobc")
    with pytest.raises(ValueError, match=code):
        package.command(_request("cobol", project, entry))


def test_package_keeps_hostile_arguments_one_argv_each(package, toolchain, project):
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    toolchain("gcc")
    hostile = ["--version", "; echo no-shell", "$(touch hostile)", "a b"]
    result = package.command(_request("assembly", project, "specimen.s", hostile))
    assert result["argv"][8:] == hostile
    assert "shell" not in result
    with pytest.raises(ValueError, match="RUNNER_ARGUMENT_INVALID"):
        package.command(_request("assembly", project, "specimen.s", ["a\x00b"]))


def test_unregistered_language_and_protocol_keep_the_legacy_refusal(package, project):
    (project / "main.c").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="RUNNER_EXTENSION_PROTOCOL_DIFFERS"):
        package.command(_request("cobolish", project, "main.c"))
    with pytest.raises(ValueError, match="RUNNER_EXTENSION_PROTOCOL_DIFFERS"):
        package.command({**_request("c", project, "main.c"), "schema_version": "other"})
    with pytest.raises(ValueError, match="RUNNER_EXTENSION_PROTOCOL_DIFFERS"):
        package.command({**_request("cobol", project, "specimen.cob"), "schema_version": "other"})


def test_original_c_adapter_keeps_its_own_worker_and_shape(package, toolchain, project):
    (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    toolchain("gcc")
    result = package.command(_request("c", project, "main.c", ["x"]))
    gcc = str(Path("/opt/fake-toolchain/gcc").resolve())
    assert result == {"schema_version": PROTOCOL, "language": "c",
                      "argv": [sys.executable, "-I", "-B", "-c", package.WORKER, "c", gcc,
                               str(project / "main.c"), "x"]}


def test_original_javascript_adapter_keeps_its_direct_shape(package, toolchain, project):
    (project / "main.js").write_text("console.log(1);\n", encoding="utf-8")
    toolchain("node")
    result = package.command(_request("javascript", project, "main.js"))
    node = str(Path("/opt/fake-toolchain/node").resolve())
    assert result["argv"] == [node, str(project / "main.js")]


# --- end-to-end: only the Assembly specimen, only when GCC is present ------

def test_assembly_end_to_end_through_the_package_when_gcc_is_present(package, project):
    if shutil.which("gcc") is None:
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: RUNNER_TOOLCHAIN_MISSING:gcc (classified skip; not a PASS)")
    (project / "specimen.s").write_text(ASSEMBLY_SPECIMEN, encoding="utf-8")
    result = package.command(_request("assembly", project, "specimen.s"))
    completed = subprocess.run(result["argv"], capture_output=True, timeout=300, shell=False, cwd=str(project))
    assert completed.returncode == 42, completed.stderr.decode("utf-8", errors="replace")
    assert completed.stdout == b""
    assert sorted(os.listdir(project)) == ["specimen.s"]

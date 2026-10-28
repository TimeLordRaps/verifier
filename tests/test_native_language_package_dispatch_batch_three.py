"""Package-level dispatch for the batch-three native adapters.

``vstd_languages`` is imported from its source tree with the normal import statement, as the
batch-two dispatch test does. The four implemented names and Classic Visual Basic reach
``extended_batch_three`` through the package callable and share its worker; nothing is copied.
Toolchains are faked with a recorded ``shutil.which``. The worker runs in-process with a
recorded ``Popen``, so no compiler, virtual machine (VM) or SAS installation starts. Classic Visual Basic must
refuse with a closed blocker before any lookup or process. Core admits the four implemented
batch-three names only after an explicit language selection; these package tests independently
pin their callable and entry-point contracts. The package's batch-two registry is left unchanged
here; Classic Visual Basic is not declared as an entry point because its runner is NOT_ESTABLISHED.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
import zipfile

import pytest

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "extensions/languages/src"
sys.path.insert(0, str(SOURCE))
import vstd_languages  # noqa: E402
from vstd_languages import extended_batch_three  # noqa: E402
from vstd_languages import extended_batch_two  # noqa: E402
from verifier.runtime import language_runners as core_language_runners  # noqa: E402

PROTOCOL = "verifier-language-runner-1"
CLASSIC = "classic-visual-basic"
TOOLS = {"visual-basic": "dotnet", "scratch": "scratch-vm-headless", "matlab": "matlab", "sas": "sas"}
SUFFIX = {"visual-basic": ".vb", "scratch": ".sb3", "matlab": ".m", "sas": ".sas"}
ENTRY = {"visual-basic": "main.vb", "scratch": "main.sb3", "matlab": "main.m", "sas": "main.sas", CLASSIC: "main.bas"}
BODIES = {
    "visual-basic": 'Module Subject\n    Sub Main()\n        System.Console.WriteLine("ok")\n    End Sub\nEnd Module\n',
    "matlab": "disp('ok')\n",
    "sas": "data _null_;\n  put 'ok';\nrun;\n",
}
VALID_PROJECT = {"targets": [{"name": "Stage", "isStage": True, "blocks": {}}],
                 "monitors": [], "extensions": [], "meta": {"semver": "3.0.0"}}
BACKSLASH = "\\"
# Built from pieces so no raw network-share literal appears in source text.
UNC_PREFIX = BACKSLASH * 2 + "server" + BACKSLASH + "share" + BACKSLASH
HOSTILE = ["../escape{s}", "sub/../../escape{s}", "..\\escape{s}", "-o{s}", "name\x00{s}", "missing{s}",
           "C:evil{s}", UNC_PREFIX + "x{s}", "/abs/x{s}"]
CLOSED_ENTRY_CODES = {"RUNNER_CONTRACT_REJECTED", "RUNNER_ENTRY_OUTSIDE_ROOT", "RUNNER_ENTRY_MISSING",
                      "RUNNER_DIALECT_UNSUPPORTED"}


@pytest.fixture
def package():
    """The installed-source package, imported with the normal import statement."""
    assert Path(vstd_languages.__file__).resolve().is_relative_to(SOURCE.resolve())
    return vstd_languages


@pytest.fixture
def batch(package):
    return extended_batch_three


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


class _Child:
    """One fake child that exits with ``code`` and never starts a process."""

    def __init__(self, code):
        self.code = code

    def wait(self, timeout=None):
        return self.code

    def kill(self):
        pass


def _request(language, root, entry, arguments=()):
    return {"schema_version": PROTOCOL, "language": language, "root": str(root),
            "entry": entry, "arguments": list(arguments)}


def _specimen(root, language):
    path = root / ENTRY[language]
    if language == "scratch":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("project.json", json.dumps(VALID_PROJECT))
            archive.writestr("0123456789abcdef0123456789abcdef.svg", b"<svg/>")
    else:
        path.write_text(BODIES.get(language, "x\n"), encoding="utf-8")
    return path


# --- routing: each batch-three name reaches the existing worker, once ----------

@pytest.mark.parametrize("language", sorted(TOOLS))
def test_package_routes_each_implemented_name_to_the_batch_three_command(package, batch, toolchain, project, language):
    _specimen(project, language)
    toolchain(TOOLS[language])
    arguments = ["--run", "a b"] if language == "visual-basic" else []
    request = _request(language, project, ENTRY[language], arguments)
    result = package.command(request)
    assert result == batch.command(request)
    assert set(result) == {"schema_version", "language", "argv"}
    assert result["schema_version"] == PROTOCOL
    assert result["language"] == language
    assert result["argv"][4:6] == [batch.WORKER_LAUNCHER, batch.WORKER_PAYLOAD]
    assert max(map(len, result["argv"])) <= 8192
    assert result["argv"][6] == language
    assert result["argv"][7] == str(Path(f"/opt/fake-toolchain/{TOOLS[language]}").resolve())
    assert result["argv"][8] == str((project / ENTRY[language]).resolve())
    assert result["argv"][9:] == arguments


@pytest.mark.parametrize("language", sorted(TOOLS))
def test_package_missing_toolchain_is_exact_and_never_falls_back(package, monkeypatch, project, language):
    _specimen(project, language)
    seen = []

    def no_tool(name, path=None):
        seen.append(name)
        return None

    monkeypatch.setattr(shutil, "which", no_tool)
    with pytest.raises(FileNotFoundError) as missing:
        package.command(_request(language, project, ENTRY[language]))
    assert str(missing.value) == f"RUNNER_TOOLCHAIN_MISSING:{TOOLS[language]}"
    assert seen == [TOOLS[language]]


# --- hostile paths, names, requests and arguments -------------------------------

@pytest.mark.parametrize("language", sorted(TOOLS))
@pytest.mark.parametrize("template", HOSTILE, ids=[
    "dotdot", "nested-dotdot", "backslash-dotdot", "dash-leading", "nul-byte", "missing",
    "drive-relative", "network-share", "rooted"])
def test_package_rejects_hostile_entry_paths_with_a_closed_code(package, toolchain, tmp_path, project,
                                                                language, template):
    (tmp_path / f"escape{SUFFIX[language]}").write_bytes(b"x")
    toolchain(TOOLS[language])
    with pytest.raises(ValueError) as rejected:
        package.command(_request(language, project, template.format(s=SUFFIX[language])))
    assert str(rejected.value) in CLOSED_ENTRY_CODES


@pytest.mark.parametrize("name", ["Visual Basic", "visualbasic", "vb", "VISUAL-BASIC",
                                  "classic_visual_basic", "classic-vb", "sas9", "matlab-r2026"])
def test_unknown_names_keep_the_legacy_protocol_refusal(package, project, name):
    (project / "main.vb").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="^RUNNER_EXTENSION_PROTOCOL_DIFFERS$"):
        package.command(_request(name, project, "main.vb"))


@pytest.mark.parametrize("language", sorted(TOOLS) + [CLASSIC])
@pytest.mark.parametrize("mutation,code", [
    ({"schema_version": "other"}, "RUNNER_EXTENSION_PROTOCOL_DIFFERS"),
    ({"environment": "container"}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
    ({"environment": None}, "RUNNER_ENVIRONMENT_UNSUPPORTED"),
])
def test_closed_request_surface_for_batch_three(package, project, language, mutation, code):
    (project / ENTRY[language]).write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError, match=f"^{code}$"):
        package.command({**_request(language, project, ENTRY[language]), **mutation})


def test_visual_basic_arguments_stay_one_argv_each_and_are_bounded(package, toolchain, project):
    (project / "main.vb").write_text("x\n", encoding="utf-8")
    toolchain("dotnet")
    hostile = ["--version", "; echo no-shell", "$(touch hostile)", "--argument=--x", "a b"]
    result = package.command(_request("visual-basic", project, "main.vb", hostile))
    assert result["argv"][9:] == hostile
    assert "shell" not in result
    with pytest.raises(ValueError, match="^RUNNER_ARGUMENT_VECTOR_INVALID$"):
        package.command(_request("visual-basic", project, "main.vb", ["a\x00b"]))


@pytest.mark.parametrize("language", ["scratch", "matlab", "sas"])
def test_package_refuses_arguments_without_an_argument_contract(package, toolchain, project, language):
    _specimen(project, language)
    toolchain(TOOLS[language])
    with pytest.raises(ValueError, match="^RUNNER_ARGUMENT_VECTOR_INVALID$"):
        package.command(_request(language, project, ENTRY[language], ["--version"]))


def test_scratch_archive_is_checked_before_any_tool_lookup(package, monkeypatch, project):
    (project / "main.sb3").write_bytes(b"not a zip")
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("tool lookup before archive check"))
    with pytest.raises(ValueError, match="^RUNNER_CONTRACT_REJECTED$"):
        package.command(_request("scratch", project, "main.sb3"))


@pytest.mark.parametrize("name", ["x y.m", "f('x').m", "a;b.m"])
def test_matlab_injection_prone_names_are_refused_through_the_package(package, toolchain, project, name):
    (project / name).write_text("disp('ok')\n", encoding="utf-8")
    toolchain("matlab")
    with pytest.raises(ValueError, match="^RUNNER_CONTRACT_REJECTED$"):
        package.command(_request("matlab", project, name))


# --- classic Visual Basic: closed blocker, no lookup, no process ---------------

def test_classic_visual_basic_is_registered_not_established_in_the_worker_module(batch):
    assert batch.LANGUAGES[CLASSIC]["status"] == "NOT_ESTABLISHED"
    assert batch.LANGUAGES[CLASSIC]["tool"] is None


def test_classic_refusal_code_is_in_the_core_closed_vocabulary(monkeypatch):
    assert "RUNNER_LANGUAGE_UNSUPPORTED" in core_language_runners._BLOCKER_CODES


@pytest.mark.parametrize("entry", ["main.bas", "main.frm", "main.cls", "main.vb"])
def test_classic_visual_basic_refuses_with_a_closed_blocker_and_no_process(package, monkeypatch, project, entry):
    (project / entry).write_text('Attribute VB_Name = "Main"\n', encoding="utf-8")
    seen = []

    def every_tool(name, path=None):
        seen.append(name)
        return f"/opt/fake-toolchain/{name}"

    def no_process(*args, **kwargs):
        pytest.fail("classic Visual Basic must not start a process")

    monkeypatch.setattr(shutil, "which", every_tool)
    monkeypatch.setattr(subprocess, "Popen", no_process)
    monkeypatch.setattr(subprocess, "run", no_process)
    with pytest.raises(ValueError) as refused:
        package.command(_request(CLASSIC, project, entry))
    assert str(refused.value) == "RUNNER_LANGUAGE_UNSUPPORTED"
    assert seen == []


# --- source immutability through the dispatched worker -------------------------

@pytest.mark.parametrize("language", sorted(TOOLS))
def test_dispatched_worker_never_touches_the_subject_source(
    package, batch, monkeypatch, project, language,
):
    entry = _specimen(project, language)
    source = entry.read_bytes()
    listing = sorted(os.listdir(project))
    monkeypatch.setattr(shutil, "which",
                        lambda name, path=None: f"/opt/fake-toolchain/{name}" if name == TOOLS[language] else None)
    children = []

    def popen(argv, **kwargs):
        children.append(kwargs["cwd"])
        return _Child(0)

    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"10.0.100\n", stderr=b"")

    result = package.command(_request(language, project, ENTRY[language]))
    assert result["argv"][4] == batch.WORKER_LAUNCHER
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["-c", *result["argv"][5:]])
    with pytest.raises(SystemExit):
        exec(compile(batch.WORKER_LAUNCHER, "<vstd-batch-three-worker>", "exec"), {"__name__": "__main__"})
    assert children
    assert all(Path(cwd).resolve() != project.resolve() for cwd in children)
    assert not any(Path(cwd).exists() for cwd in children)
    assert entry.read_bytes() == source
    assert sorted(os.listdir(project)) == listing


# --- preserved routes -----------------------------------------------------------

def test_legacy_and_batch_two_routes_still_dispatch_after_batch_three(package, toolchain, project):
    (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (project / "specimen.s").write_text("x\n", encoding="utf-8")
    toolchain("gcc")
    batch_two = extended_batch_two
    assert package.command(_request("c", project, "main.c"))["argv"][4] == package.WORKER
    assert package.command(_request("assembly", project, "specimen.s"))["argv"][4] == batch_two.WORKER


# --- entry-point discovery, alias collisions and load failure -------------------

IMPLEMENTED_THREE = ("visual-basic", "scratch", "matlab", "sas")
ENTRY_POINT_GROUP = "verifier.language_runners"


def _declared_entry_points():
    with (REPO / "extensions/languages/pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["entry-points"][ENTRY_POINT_GROUP]


def test_pyproject_declares_each_implemented_batch_three_name_and_not_classic():
    declared = _declared_entry_points()
    for name in IMPLEMENTED_THREE:
        assert declared.get(name) == "vstd_languages:command"
    assert CLASSIC not in declared


def test_installed_style_discovery_loads_each_implemented_name_to_the_package_command(package, monkeypatch, tmp_path):
    declared = _declared_entry_points()
    dist = tmp_path / "vstd_language_runners-0.1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: vstd-language-runners\nVersion: 0.1.0\n",
                                   encoding="utf-8")
    (dist / "entry_points.txt").write_text(
        f"[{ENTRY_POINT_GROUP}]\n" + "".join(f"{name} = {target}\n" for name, target in declared.items()),
        encoding="utf-8")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(tmp_path), str(SOURCE)))
    probe = (
        "import importlib.metadata,json; "
        f"group={ENTRY_POINT_GROUP!r}; "
        "rows={e.name:(e.load().__module__,e.load().__name__) "
        "for e in importlib.metadata.entry_points(group=group) "
        "if e.dist is not None and e.dist.name=='vstd-language-runners'}; "
        "print(json.dumps(rows,sort_keys=True))"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", probe],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    discovered = json.loads(completed.stdout)
    assert set(discovered) == set(declared)
    assert all(discovered[name] == ["vstd_languages", "command"] for name in IMPLEMENTED_THREE)
    assert package.command is vstd_languages.command


def test_batch_names_are_disjoint_from_each_other_and_from_the_legacy_registry(package, batch):
    batch_two = extended_batch_two
    three, two = set(batch.LANGUAGES), set(batch_two.LANGUAGES)
    legacy = set(package.SUFFIXES) - two
    assert len(legacy) == 16
    assert three.isdisjoint(two)
    assert three.isdisjoint(legacy)
    assert two.isdisjoint(legacy)


def test_shared_matlab_and_objective_c_suffix_routes_only_by_the_explicit_name(package, batch, toolchain, project):
    batch_two = extended_batch_two
    claimants = sorted({name for module in (batch, batch_two) for name, spec in module.LANGUAGES.items()
                        if ".m" in spec["suffixes"]})
    assert claimants == ["matlab", "objective-c"]
    (project / "main.m").write_text("disp('ok')\n", encoding="utf-8")
    toolchain("matlab")
    matlab = package.command(_request("matlab", project, "main.m"))
    assert matlab["argv"][4:6] == [batch.WORKER_LAUNCHER, batch.WORKER_PAYLOAD]
    toolchain("clang")
    objective_c = package.command(_request("objective-c", project, "main.m"))
    assert objective_c["argv"][4] == batch_two.WORKER
    with pytest.raises(KeyError):
        package.command({"schema_version": PROTOCOL, "root": str(project), "entry": "main.m", "arguments": []})


def test_a_broken_batch_module_fails_package_import_instead_of_deferring(tmp_path):
    copy = tmp_path / "src"
    shutil.copytree(SOURCE, copy, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    probe = "import sys; sys.path.insert(0, sys.argv[1]); import vstd_languages; print('LOADED')"
    clean = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(copy)],
                           capture_output=True, text=True, timeout=120)
    assert clean.returncode == 0 and "LOADED" in clean.stdout, clean.stderr
    module = copy / "vstd_languages" / "extended_batch_three.py"
    module.write_text(module.read_text(encoding="utf-8") + '\nraise RuntimeError("RUNNER_EXTENSION_LOAD_PROBE")\n',
                      encoding="utf-8")
    broken = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(copy)],
                            capture_output=True, text=True, timeout=120)
    assert broken.returncode != 0
    assert "RUNNER_EXTENSION_LOAD_PROBE" in broken.stderr
    assert "LOADED" not in broken.stdout

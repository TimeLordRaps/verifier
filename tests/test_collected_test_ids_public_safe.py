"""A test whose generated id the release boundary scan rejects stops the run before the suite starts.

Terminology: continuous integration (CI); Extensible Markup Language (XML).
``scripts/check_release_boundary.py`` rejects a test report that carries an id shaped like a credential, an address or a
workstation path. CI and the pre-push gate run it only after the whole suite has finished, so one such parameter costs a
full run. The collection hook in ``tests/conftest.py`` reports it at collection instead. The strings below are assembled
from parts, so this source never contains the shapes it refuses.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

CONFTEST = Path(__file__).with_name("conftest.py")
BACKSLASH = chr(92)
ADDRESS = "user" + "@" + "example.invalid"
CREDENTIAL_URL = "https://user:pass" + "@" + "example.com/entry.json"
UNIX_HOME = "/home/" + "someone/work"
WINDOWS_HOME = "C:" + BACKSLASH + "Users" + BACKSLASH + "someone"
SAFE_NAMES = ("docs/guide.md", "userinfo-in-authority", "prefix/home/example", "https://example.invalid/Users/example")


def _load_conftest():
    spec = importlib.util.spec_from_file_location("_repository_test_conftest", CONFTEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


repository = _load_conftest()


def _item(name: str, filename: str = "test_module.py") -> SimpleNamespace:
    return SimpleNamespace(name=name, originalname=name.split("[", 1)[0], path=Path(filename))


@pytest.mark.parametrize(
    "text, label",
    [
        (ADDRESS, "email address"),
        (CREDENTIAL_URL, "email address"),
        (UNIX_HOME, "Unix or macOS home path"),
        (WINDOWS_HOME, "local user or home path"),
    ],
    ids=["address", "credential-url", "unix-home", "windows-home"],
)
def test_names_the_boundary_scan_rejects_are_flagged(text: str, label: str) -> None:
    flagged = repository.public_id_violations([f"test_case[{text}]", "test_plain"])
    assert list(flagged) == [f"test_case[{text}]"]
    assert label in flagged[f"test_case[{text}]"]


def test_ordinary_names_are_not_flagged() -> None:
    names = [f"test_case[{name}]" for name in SAFE_NAMES] + ["test_plain"]
    assert repository.public_id_violations(names) == {}


def test_the_hook_refuses_collection_without_repeating_the_id() -> None:
    items = [_item("test_plain"), _item(f"test_case[{CREDENTIAL_URL}]", "test_fetch.py")]
    with pytest.raises(pytest.UsageError) as refusal:
        repository.pytest_collection_modifyitems(None, items)
    message = str(refusal.value)
    assert "test_fetch.py::test_case" in message and "email address" in message
    assert CREDENTIAL_URL not in message and "pass" + "@" not in message
    assert "test_plain" not in message


def test_the_hook_accepts_collections_with_explicit_ids() -> None:
    items = [_item(f"test_case[{name}]") for name in SAFE_NAMES]
    assert repository.pytest_collection_modifyitems(None, items) is None


def test_every_flagged_name_is_reported_and_not_only_the_first() -> None:
    first, second = f"test_a[{ADDRESS}]", f"test_b[{UNIX_HOME}]"
    assert list(repository.public_id_violations([first, "test_plain", second])) == [first, second]
    items = [_item(first, "test_first.py"), _item("test_plain"), _item(second, "test_second.py")]
    with pytest.raises(pytest.UsageError) as refusal:
        repository.pytest_collection_modifyitems(None, items)
    message = str(refusal.value)
    assert "test_first.py::test_a" in message and "test_second.py::test_b" in message


def _run(directory: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    (directory / "conftest.py").write_text(
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('repository_conftest', {str(CONFTEST)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "pytest_collection_modifyitems = module.pytest_collection_modifyitems\n",
        encoding="utf-8", newline="\n",
    )
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider", "-o", "addopts=", *arguments],
        cwd=directory, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, env=environment,
    )


def _write_module(directory: Path, value: str, param_id: str | None = None) -> None:
    parameter = f"pytest.param({value!r}, id={param_id!r})" if param_id else repr(value)
    (directory / "test_ids.py").write_text(
        "import pytest\n\n"
        f"@pytest.mark.parametrize('value', [{parameter}, 'ordinary'])\n"
        "def test_value(value):\n"
        "    assert value\n",
        encoding="utf-8", newline="\n",
    )


def test_the_run_stops_on_a_generated_id_and_names_only_the_function(tmp_path: Path) -> None:
    _write_module(tmp_path, CREDENTIAL_URL)
    result = _run(tmp_path)
    output = result.stdout + result.stderr
    assert result.returncode == 4, output
    assert "test_ids.py::test_value" in output and "email address" in output
    assert CREDENTIAL_URL not in output


def test_the_run_continues_when_the_same_value_has_an_explicit_id(tmp_path: Path) -> None:
    _write_module(tmp_path, CREDENTIAL_URL, "userinfo-in-authority")
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_value[userinfo-in-authority] PASSED" in result.stdout


def test_a_deselected_test_does_not_stop_the_run(tmp_path: Path) -> None:
    _write_module(tmp_path, CREDENTIAL_URL)
    result = _run(tmp_path, "-k", "ordinary")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_value[ordinary] PASSED" in result.stdout

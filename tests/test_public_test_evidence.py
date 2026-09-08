"""Check public test-evidence production without changing test outcomes.

Terminology: Extensible Markup Language (XML); Java unit test report format (JUnit).
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pytest_public_evidence


@pytest.mark.parametrize("collection_skip", (False, True), ids=("runtime", "collection"))
def test_public_plugin_records_relative_skip_location_before_serialization(
    tmp_path: Path, collection_skip: bool
) -> None:
    (tmp_path / "test_probe.py").write_text(
        "import pytest\npytest.importorskip('vstd_missing_optional_fixture')\n"
        if collection_skip else
        "import pytest\ndef test_unavailable():\n"
        "    pytest.skip('capability unavailable (errno=13)')\n",
        encoding="utf-8",
    )
    (tmp_path / "test_passed.py").write_text(
        "def test_passed():\n    assert 1 == 1\n", encoding="utf-8"
    )
    report_path = tmp_path / "evidence.xml"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = subprocess.run(
        [sys.executable, "-u", "-m", "pytest", "-vv", "-s", "--durations=10",
         "--timeout=30", "-p", "pytest_timeout", "-p", "scripts.pytest_public_evidence",
         "--rootdir", str(tmp_path), f"--junitxml={report_path}",
         str(tmp_path / "test_probe.py"), str(tmp_path / "test_passed.py")],
        cwd=ROOT,
        env=environment,
        text=True,
        check=False,
        timeout=45,
    )
    assert result.returncode == 0
    document = ET.parse(report_path).getroot()
    cases = document.findall(".//testcase")
    assert len(cases) == 2
    skipped = document.findall(".//skipped")
    assert len(skipped) == 1
    if collection_skip:
        assert skipped[0].get("message") == "collection skipped"
        assert "vstd_missing_optional_fixture" in skipped[0].text
        assert "test_probe.py" in skipped[0].text
    else:
        assert skipped[0].get("message") == "capability unavailable (errno=13)"
        assert skipped[0].text == "test_probe.py:3: capability unavailable (errno=13)"
    assert str(tmp_path) not in report_path.read_text(encoding="utf-8")
    boundary = subprocess.run(
        [sys.executable, "-u", str(ROOT / "scripts" / "check_release_boundary.py"), str(report_path)],
        text=True, check=False, timeout=30,
    )
    assert boundary.returncode == 0


@pytest.mark.parametrize("outcome", ("passed", "failed", "skipped"))
def test_public_plugin_preserves_outside_root_reports(tmp_path: Path, outcome: str) -> None:
    original = (str(tmp_path.parent / "outside.py"), 17, "original reason")
    report = pytest.TestReport(
        nodeid="tests/test_probe.py::test_case", location=("tests/test_probe.py", 16, "test_case"),
        keywords={}, outcome=outcome, longrepr=original, when="call",
    )
    item = SimpleNamespace(config=SimpleNamespace(rootpath=tmp_path))
    hook = pytest_public_evidence.pytest_runtest_makereport(item)
    next(hook)
    with pytest.raises(StopIteration) as completed:
        hook.send(report)
    assert completed.value.value is report
    assert report.outcome == outcome
    assert report.longrepr == original

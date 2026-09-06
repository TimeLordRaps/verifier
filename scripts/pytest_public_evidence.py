"""Record test-root-relative skip locations before public evidence serialization.

Only locations inside the declared pytest root are translated. Outcomes, reasons,
line numbers, and outside-root locations remain unchanged; the upload boundary
scanner still applies to the resulting bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest


def _relative_skip_location(
    report: pytest.TestReport | pytest.CollectReport, root: Path
) -> None:
    if report.skipped and isinstance(report.longrepr, tuple):
        filename, lineno, reason = report.longrepr
        root = root.resolve()
        source = Path(filename)
        if not source.is_absolute():
            source = root / source
        try:
            relative = source.resolve().relative_to(root).as_posix()
        except ValueError:
            return
        report.longrepr = (relative, lineno, reason)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    _relative_skip_location(report, item.config.rootpath)
    return report


@pytest.hookimpl(wrapper=True)
def pytest_make_collect_report(
    collector: pytest.Collector,
) -> Generator[None, pytest.CollectReport, pytest.CollectReport]:
    report = yield
    _relative_skip_location(report, collector.config.rootpath)
    return report

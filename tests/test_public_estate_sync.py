from __future__ import annotations

"""Terminology: application programming interface (API);
uniform resource locator (URL); Verifier Standard (VSTD).
"""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    path = ROOT / "scripts/check_public_estate_sync.py"
    spec = importlib.util.spec_from_file_location("check_public_estate_sync", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mandatory_documentation_coverage_passes_on_repo():
    module = _load_module()
    version = module.get_package_version(ROOT)
    errors = module.check_mandatory_documentation_coverage(ROOT, version)
    assert errors == [], f"Unexpected documentation coverage errors: {errors}"


def test_mandatory_documentation_coverage_fails_on_missing_file(tmp_path: Path):
    module = _load_module()
    # Create partial tree missing reference.html
    (tmp_path / "docs").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "verifier-standard"\nversion = "1.4.2"\n',
        encoding="utf-8",
    )
    errors = module.check_mandatory_documentation_coverage(tmp_path, "1.4.2")
    assert any("Required documentation file missing" in err for err in errors)


def test_mandatory_documentation_coverage_fails_on_stale_reference(tmp_path: Path):
    module = _load_module()
    docs = tmp_path / "docs"
    docs.mkdir(parents=True)
    # Populate all required files
    for rel in module.REQUIRED_DOCUMENTATION_FILES:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("stub", encoding="utf-8")

    # Set reference.html to wrong version
    (docs / "reference.html").write_text("package version 1.3.0", encoding="utf-8")
    (docs / "guides.html").write_text(
        "USE_CASES.html PYTHON_API_GUIDE.html tutorials/SEAL_AN_ARTIFACT.html tutorials/PUBLISH_A_SILO.html",
        encoding="utf-8",
    )
    (tmp_path / "CHANGELOG.md").write_text("## 1.4.2 - 2026-09-17\n", encoding="utf-8")

    errors = module.check_mandatory_documentation_coverage(tmp_path, "1.4.2")
    assert any("does not declare package version 1.4.2" in err for err in errors)


def test_mandatory_documentation_coverage_fails_when_changelog_defers_docs(tmp_path: Path):
    module = _load_module()
    for rel in module.REQUIRED_DOCUMENTATION_FILES:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("stub", encoding="utf-8")

    (tmp_path / "docs/reference.html").write_text("package version 1.4.2", encoding="utf-8")
    (tmp_path / "docs/guides.html").write_text(
        "USE_CASES.html PYTHON_API_GUIDE.html tutorials/SEAL_AN_ARTIFACT.html tutorials/PUBLISH_A_SILO.html",
        encoding="utf-8",
    )
    (tmp_path / "CHANGELOG.md").write_text(
        "## 1.4.2 - 2026-09-17\n- Features added, documentation deferred to next release\n",
        encoding="utf-8",
    )

    errors = module.check_mandatory_documentation_coverage(tmp_path, "1.4.2")
    assert any("explicitly defers documentation" in err for err in errors)


def test_fetch_pypi_status_handles_network_error():
    module = _load_module()
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network unreachable")):
        res = module.fetch_pypi_status()
        assert res["status"] == "UNKNOWN"
        assert "Network unreachable" in res["error"]
        assert res["latest_version"] is None


def test_fetch_pypi_status_success():
    module = _load_module()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"info": {"version": "1.4.0"}, "releases": {"1.3.0": [], "1.4.0": []}}'
    mock_resp.__enter__.return_value = mock_resp
    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = module.fetch_pypi_status()
        assert res["status"] == "OBSERVED"
        assert res["latest_version"] == "1.4.0"
        assert res["release_count"] == 2


def test_inspect_vstd_labs(tmp_path: Path):
    module = _load_module()
    site = tmp_path / "website"
    site.mkdir()
    (site / "index.html").write_text(
        '<span class="badge badge-accent">v1.4.0 ON PYPI</span>\n'
        '<div class="metric-val">v1.4.0</div>\n'
        'Python 3.10+ &bull; four releases published &bull;\n'
        'The recorded session below pins <code>1.3.0</code> because that is the version\n',
        encoding="utf-8",
    )
    (site / "app.js").write_text('// verifier-standard==1.3.0\nconst EMITTED = {};\n', encoding="utf-8")

    data = module.inspect_vstd_labs(site)
    assert data["status"] == "OBSERVED"
    assert data["hero_badge"] == "v1.4.0 ON PYPI"
    assert data["hero_badge_version"] == "1.4.0"
    assert data["metric_val"] == "v1.4.0"
    assert data["session_pinned_version"] == "1.3.0"
    assert data["app_captured_version"] == "1.3.0"


def test_inspect_claimgarden(tmp_path: Path):
    module = _load_module()
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text(
        '<a href="proposition.html?component=vstd-labs/gdc-sat-kernel">Evidence</a>\n'
        '<span>v1.4.0</span>\n',
        encoding="utf-8",
    )
    (web / "catalog.html").write_text(
        '<a href="proposition.html?component=vstd-labs%2Fgdc-sat-kernel">Evidence</a>\n'
        '<span>v1.4.0</span>\n',
        encoding="utf-8",
    )

    data = module.inspect_claimgarden(web)
    assert data["status"] == "OBSERVED"
    assert data["index_vstd_version"] == "v1.4.0"
    assert data["catalog_vstd_version"] == "v1.4.0"


def test_evaluate_estate_sync_detects_drift(tmp_path: Path):
    module = _load_module()
    # Mock estate directories
    labs = tmp_path / "website"
    labs.mkdir()
    (labs / "index.html").write_text(
        '<span class="badge badge-accent">v1.4.0 ON PYPI</span>\n'
        '<div class="metric-val">v1.4.0</div>\n'
        'The recorded session below pins <code>1.3.0</code>\n',
        encoding="utf-8",
    )
    cg = tmp_path / "web"
    cg.mkdir()
    (cg / "index.html").write_text('vstd-labs/gdc-sat-kernel <span>v1.4.0</span>', encoding="utf-8")
    (cg / "catalog.html").write_text('vstd-labs%2Fgdc-sat-kernel <span>v1.4.0</span>', encoding="utf-8")

    # Evaluate against target version 1.4.2 with target_sync=True
    eval_res = module.evaluate_estate_sync(
        root=ROOT,
        target_version="1.4.2",
        vstd_labs_dir=labs,
        claimgarden_dir=cg,
        offline=True,
        target_sync=True,
    )
    assert eval_res["doc_coverage_status"] == "PASS"
    assert any("vstd-labs.com hero badge reads" in a for a in eval_res["action_items"])
    assert any("vstd-labs.com demo session pins" in a for a in eval_res["action_items"])
    assert any("claimgarden.com index card footer reads" in a for a in eval_res["action_items"])

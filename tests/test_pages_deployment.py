"""Terminology: uniform resource locator (URL).

Tests for exact-commit Pages promotion evidence.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40


def _module():
    path = ROOT / "scripts" / "check_pages_deployment.py"
    spec = importlib.util.spec_from_file_location("check_pages_deployment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_module():
    path = ROOT / "scripts" / "build_pages.py"
    spec = importlib.util.spec_from_file_location("build_pages_manifest", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deployment_documents_bind_commit_and_index_bytes() -> None:
    module = _module()
    index = b'{"component":"bounded"}\n'
    digest = hashlib.sha256(index).hexdigest()
    result = module.validate_documents(
        expected_source_ref=HEAD,
        documentation={"source_ref": HEAD},
        component_coordinate={"source_ref": HEAD, "index_sha256": digest},
        component_index=index,
        published_digest=f"{digest}  index.json\n",
    )
    assert result["source_ref"] == HEAD
    assert result["component_index_sha256"] == digest


def test_promotion_source_requires_successful_checks_on_current_main() -> None:
    run_id = _module().validate_promotion_source(
        expected_source_ref=HEAD,
        current_main_ref=HEAD,
        repository_run={
            "id": 123,
            "head_sha": HEAD,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "path": ".github/workflows/ci.yml",
        },
    )
    assert run_id == "123"


@pytest.mark.parametrize(
    "workflow_path",
    (
        None,
        "ci.yml",
        ".github/workflows/ci.yaml",
        ".github/workflows/release.yml",
    ),
)
def test_promotion_source_rejects_missing_or_substituted_workflow_path(
    workflow_path: str | None,
) -> None:
    module = _module()
    repository_run = {
        "id": 123,
        "head_sha": HEAD,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }
    if workflow_path is not None:
        repository_run["path"] = workflow_path
    with pytest.raises(module.PagesDeploymentError, match="does not qualify"):
        module.validate_promotion_source(
            expected_source_ref=HEAD,
            current_main_ref=HEAD,
            repository_run=repository_run,
        )


def test_stale_automatic_rerun_cannot_deploy_after_main_advances() -> None:
    module = _module()
    with pytest.raises(module.PagesDeploymentError, match="not the current main"):
        module.validate_promotion_source(
            expected_source_ref=HEAD,
            current_main_ref="b" * 40,
            repository_run={
                "id": 123,
                "head_sha": HEAD,
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "path": ".github/workflows/ci.yml",
            },
        )


@pytest.mark.parametrize("surface", ("documentation", "component", "digest"))
def test_deployment_documents_fail_closed_on_coordinate_drift(surface: str) -> None:
    module = _module()
    index = b"index"
    digest = hashlib.sha256(index).hexdigest()
    documentation = {"source_ref": HEAD}
    component = {"source_ref": HEAD, "index_sha256": digest}
    published = digest
    if surface == "documentation":
        documentation["source_ref"] = "b" * 40
    elif surface == "component":
        component["source_ref"] = "b" * 40
    else:
        published = "0" * 64
    with pytest.raises(module.PagesDeploymentError):
        module.validate_documents(
            expected_source_ref=HEAD,
            documentation=documentation,
            component_coordinate=component,
            component_index=index,
            published_digest=published,
        )


def test_base_url_is_normalized_without_losing_project_path() -> None:
    module = _module()
    assert module.normalize_base_url(
        "https://timelordraps.github.io/verifier",
        allowed_host="timelordraps.github.io",
    ) == "https://timelordraps.github.io/verifier/"


@pytest.mark.parametrize(
    "url",
    (
        "http://timelordraps.github.io/verifier/",
        "https://evil.example/verifier/",
        "https://user" + "@timelordraps.github.io/verifier/",
        "https://timelordraps.github.io/verifier/?source=other",
        "https://timelordraps.github.io/verifier/%2e%2e/private/",
    ),
)
def test_base_url_rejects_unbounded_scheme_host_or_path(url: str) -> None:
    module = _module()
    with pytest.raises(module.PagesDeploymentError):
        module.normalize_base_url(url, allowed_host="timelordraps.github.io")


class _Response:
    def __init__(
        self, payload: bytes, *, url: str, length: str | None = None,
        encoding: str | None = None, status: int = 200,
    ) -> None:
        self.payload = payload
        self.url = url
        self.status = status
        self.headers = {}
        if length is not None:
            self.headers["Content-Length"] = length
        if encoding is not None:
            self.headers["Content-Encoding"] = encoding

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


def test_fetch_bounds_response_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 4)
    monkeypatch.setattr(
        module,
        "URL_OPEN",
        lambda *args, **kwargs: _Response(
            b"12345", url="https://timelordraps.github.io/verifier/index.json"
        ),
    )
    with pytest.raises(module.PagesDeploymentError, match="byte limit"):
        module._fetch(
            "https://timelordraps.github.io/verifier/index.json",
            allowed_host="timelordraps.github.io",
        )


def test_fetch_rejects_redirect_to_another_host(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    monkeypatch.setattr(
        module,
        "URL_OPEN",
        lambda *args, **kwargs: _Response(b"{}", url="https://evil.example/index.json"),
    )
    with pytest.raises(module.PagesDeploymentError, match="redirected"):
        module._fetch(
            "https://timelordraps.github.io/verifier/index.json",
            allowed_host="timelordraps.github.io",
        )


def test_fetch_rejects_same_host_redirect_outside_requested_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(
        module,
        "URL_OPEN",
        lambda *args, **kwargs: _Response(
            b"{}", url="https://timelordraps.github.io/other/index.json"
        ),
    )
    with pytest.raises(module.PagesDeploymentError, match="requested route"):
        module._fetch(
            "https://timelordraps.github.io/verifier/index.json",
            allowed_host="timelordraps.github.io",
        )


def _minimal_site(module, root: Path) -> dict[str, bytes]:
    index = b'{"component":"bounded"}\n'
    digest = hashlib.sha256(index).hexdigest()
    payloads = {
        "components/deployment-coordinate.json": (
            '{"index_sha256":"' + digest + '","source_ref":"' + HEAD + '"}\n'
        ).encode(),
        "components/index.json": index,
        "components/index.sha256": f"{digest}  index.json\n".encode(),
        "documentation-coordinate.json": f'{{"source_ref":"{HEAD}"}}\n'.encode(),
        "index.html": b"<!doctype html><title>Verifier</title>\n",
    }
    for relative, payload in payloads.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    files = [
        {"path": path, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        for path, payload in sorted(payloads.items())
    ]
    manifest = {
        "claim_boundary": module.MANIFEST_CLAIM_BOUNDARY,
        "critical_paths": list(module.CRITICAL_PATHS),
        "file_count": len(files),
        "files": files,
        "manifest_path": module.MANIFEST_PATH,
        "schema": module.MANIFEST_SCHEMA,
        "source_ref": HEAD,
        "total_bytes": sum(entry["size"] for entry in files),
    }
    manifest_bytes = module._canonical_json(manifest)
    (root / module.MANIFEST_PATH).write_bytes(manifest_bytes)
    payloads[module.MANIFEST_PATH] = manifest_bytes
    return payloads


def test_local_site_validation_binds_exact_inventory_and_known_good_digest(tmp_path: Path) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    digest = hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest()
    result = module.validate_site_directory(
        tmp_path, expected_source_ref=HEAD, expected_manifest_sha256=digest
    )
    assert result["file_count"] == 5
    assert result["deployment_manifest_sha256"] == digest


def test_pages_builder_manifest_is_deterministic_and_checker_compatible(tmp_path: Path) -> None:
    checker = _module()
    builder = _build_module()
    roots = (tmp_path / "one", tmp_path / "two")
    manifests: list[bytes] = []
    for root in roots:
        _minimal_site(checker, root)
        (root / checker.MANIFEST_PATH).unlink()
        builder._write_deployment_manifest(root, source_ref=HEAD)
        checker.validate_site_directory(root, expected_source_ref=HEAD)
        manifests.append((root / checker.MANIFEST_PATH).read_bytes())
    assert manifests[0] == manifests[1]


@pytest.mark.parametrize("boundary", ("path", "count", "file-bytes", "total-bytes"))
def test_manifest_enforces_path_count_and_byte_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    manifest = module.json.loads(payloads[module.MANIFEST_PATH])
    if boundary == "path":
        manifest["files"][0]["path"] = "../escape"
    elif boundary == "count":
        monkeypatch.setattr(module, "MAX_FILES", 4)
    elif boundary == "file-bytes":
        manifest["files"][0]["size"] = module.MAX_FILE_BYTES + 1
        manifest["total_bytes"] = sum(entry["size"] for entry in manifest["files"])
    else:
        monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(module.PagesDeploymentError):
        module.validate_manifest(manifest, expected_source_ref=HEAD)


@pytest.mark.parametrize("mutation", ("extra", "changed", "wrong-known-good"))
def test_local_site_validation_rejects_inventory_or_byte_drift(
    tmp_path: Path, mutation: str
) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    expected = hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest()
    if mutation == "extra":
        (tmp_path / "extra.html").write_text("extra", encoding="utf-8")
    elif mutation == "changed":
        (tmp_path / "index.html").write_text("changed", encoding="utf-8")
    else:
        expected = "0" * 64
    with pytest.raises(module.PagesDeploymentError):
        module.validate_site_directory(
            tmp_path, expected_source_ref=HEAD, expected_manifest_sha256=expected
        )


def test_live_observation_fetches_manifest_and_every_deployed_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    requested: list[str] = []

    def open_url(request, *, timeout: int):
        assert request.headers["Accept-encoding"] == "identity"
        url = request.full_url
        requested.append(url)
        relative = url.split("/verifier/", 1)[1]
        return _Response(payloads[relative], url=url, length=str(len(payloads[relative])))

    monkeypatch.setattr(module, "URL_OPEN", open_url)
    manifest_digest = hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest()
    receipt = module.observe(
        "https://timelordraps.github.io/verifier/", HEAD,
        allowed_host="timelordraps.github.io", repository_checks_run_id="12",
        deployment_workflow_run_id="34",
        expected_manifest_sha256=manifest_digest,
    )
    assert receipt["checked_route_count"] == 6
    assert len(requested) == 6
    assert receipt["deployment_manifest_sha256"] == hashlib.sha256(
        payloads[module.MANIFEST_PATH]
    ).hexdigest()


def _serve_payloads(module, monkeypatch: pytest.MonkeyPatch, payloads: dict[str, bytes]) -> None:
    def open_url(request, *, timeout: int):
        relative = request.full_url.split("/verifier/", 1)[1]
        payload = payloads[relative]
        return _Response(payload, url=request.full_url, length=str(len(payload)))

    monkeypatch.setattr(module, "URL_OPEN", open_url)


def _substitute_coherent_site(module, payloads: dict[str, bytes]) -> None:
    payloads["index.html"] = b"<!doctype html><title>Substituted</title>\n"
    manifest = module.json.loads(payloads[module.MANIFEST_PATH])
    for entry in manifest["files"]:
        if entry["path"] == "index.html":
            entry["sha256"] = hashlib.sha256(payloads["index.html"]).hexdigest()
            entry["size"] = len(payloads["index.html"])
    manifest["total_bytes"] = sum(entry["size"] for entry in manifest["files"])
    payloads[module.MANIFEST_PATH] = module._canonical_json(manifest)


def test_current_live_observation_rejects_substituted_coherent_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    promoted_digest = hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest()
    _substitute_coherent_site(module, payloads)
    assert hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest() != promoted_digest
    _serve_payloads(module, monkeypatch, payloads)

    with pytest.raises(module.PagesDeploymentError, match="differs from promoted manifest"):
        module.observe(
            "https://timelordraps.github.io/verifier/", HEAD,
            allowed_host="timelordraps.github.io", repository_checks_run_id="12",
            deployment_workflow_run_id="34",
            expected_manifest_sha256=promoted_digest,
        )


def test_recovery_live_observation_rejects_manifest_other_than_retained_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    payloads = _minimal_site(module, tmp_path)
    retained_digest = hashlib.sha256(payloads[module.MANIFEST_PATH]).hexdigest()
    receipt = _receipt(module)
    receipt["deployment_manifest_sha256"] = retained_digest
    coordinate = module.validate_rollback_receipt(
        receipt, expected_source_ref=HEAD,
        expected_deployment_workflow_run_id="34", deployment_run=_deployment_run(),
    )
    _substitute_coherent_site(module, payloads)
    _serve_payloads(module, monkeypatch, payloads)

    with pytest.raises(module.PagesDeploymentError, match="differs from promoted manifest"):
        module.observe(
            "https://timelordraps.github.io/verifier/", HEAD,
            allowed_host="timelordraps.github.io", repository_checks_run_id="12",
            deployment_workflow_run_id="35",
            expected_manifest_sha256=coordinate["deployment_manifest_sha256"],
        )


def test_fetch_rejects_content_encoding_ambiguity(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    url = "https://timelordraps.github.io/verifier/index.html"
    monkeypatch.setattr(
        module, "URL_OPEN",
        lambda *args, **kwargs: _Response(b"encoded", url=url, encoding="gzip"),
    )
    with pytest.raises(module.PagesDeploymentError, match="content encoding"):
        module._fetch(url, allowed_host="timelordraps.github.io")


def _receipt(module) -> dict[str, object]:
    return {
        "base_url": "https://timelordraps.github.io/verifier/",
        "checked_route_count": 6,
        "claim_boundary": module.RECEIPT_CLAIM_BOUNDARY,
        "deployed_file_count": 5,
        "deployed_total_bytes": 123,
        "deployment_manifest_sha256": "d" * 64,
        "deployment_workflow_run_id": "34",
        "repository_checks_run_id": "12",
        "result": "PASS",
        "schema_version": 2,
        "source_ref": HEAD,
    }


def _deployment_run() -> dict[str, object]:
    return {
        "id": 34,
        "name": "pages",
        "path": ".github/workflows/pages.yml",
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_run",
    }


def test_known_good_receipt_supplies_exact_rebuild_coordinate() -> None:
    module = _module()
    result = module.validate_rollback_receipt(
        _receipt(module), expected_source_ref=HEAD,
        expected_deployment_workflow_run_id="34",
        deployment_run=_deployment_run(),
    )
    assert result == {
        "deployment_manifest_sha256": "d" * 64,
        "repository_checks_run_id": "12",
    }


@pytest.mark.parametrize("field", ("source_ref", "deployment_workflow_run_id", "result"))
def test_known_good_receipt_rejects_wrong_identity_or_result(field: str) -> None:
    module = _module()
    receipt = _receipt(module)
    receipt[field] = "wrong"
    with pytest.raises(module.PagesDeploymentError, match="does not qualify"):
        module.validate_rollback_receipt(
            receipt,
            expected_source_ref=HEAD,
            expected_deployment_workflow_run_id="34",
            deployment_run=_deployment_run(),
        )


def test_known_good_receipt_rejects_non_pages_art_run() -> None:
    module = _module()
    deployment_run = _deployment_run()
    deployment_run["name"] = "repository-checks"
    with pytest.raises(module.PagesDeploymentError, match="successful Pages run"):
        module.validate_rollback_receipt(
            _receipt(module), expected_source_ref=HEAD,
            expected_deployment_workflow_run_id="34", deployment_run=deployment_run,
        )


@pytest.mark.parametrize("workflow_path", (None, ".github/workflows/namesake.yml"))
def test_known_good_receipt_rejects_namesake_pages_workflow(workflow_path: str | None) -> None:
    module = _module()
    deployment_run = _deployment_run()
    deployment_run["path"] = workflow_path
    with pytest.raises(module.PagesDeploymentError, match="successful Pages run"):
        module.validate_rollback_receipt(
            _receipt(module), expected_source_ref=HEAD,
            expected_deployment_workflow_run_id="34", deployment_run=deployment_run,
        )

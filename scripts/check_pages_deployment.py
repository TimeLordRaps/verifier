#!/usr/bin/env python3
"""Terminology: Hypertext Transfer Protocol Secure (HTTPS); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8); uniform resource locator (URL);
Verifier Standard (VSTD).

Check a bounded GitHub Pages artifact and live deployment against an exact source commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class PagesDeploymentError(ValueError):
    """Raised when deployed bytes do not satisfy their bounded manifest."""


MANIFEST_PATH = "deployment-manifest.json"
MANIFEST_SCHEMA = "VSTD-PAGES-DEPLOYMENT-MANIFEST-1"
REPOSITORY_CHECKS_WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 4096
MAX_PATH_BYTES = 512
CRITICAL_PATHS = (
    "components/deployment-coordinate.json",
    "components/index.json",
    "components/index.sha256",
    "documentation-coordinate.json",
    "index.html",
)
MANIFEST_CLAIM_BOUNDARY = (
    "The manifest binds every regular deployed payload file other than the manifest itself "
    "to this source commit by path, size, and SHA-256; it does not establish future "
    "availability, absence of hosting-layer transformations, or semantic correctness."
)
RECEIPT_CLAIM_BOUNDARY = (
    "Every manifest-listed live route and the manifest itself matched the exact bounded "
    "bytes at observation time; future availability and future bytes are not established."
)


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _open_url(request: Request, *, timeout: int):  # type: ignore[no-untyped-def]
    return build_opener(_RejectRedirects()).open(request, timeout=timeout)


URL_OPEN = _open_url


def _canonical_json(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_path(path: Any) -> str:
    if not isinstance(path, str) or not path or len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise PagesDeploymentError("deployment path is empty or exceeds its byte limit")
    if (
        path.startswith("/")
        or "\\" in path
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or re.fullmatch(r"[A-Za-z0-9._/-]+", path) is None
    ):
        raise PagesDeploymentError(f"deployment path is not canonical: {path!r}")
    return path


def validate_manifest(document: Any, *, expected_source_ref: str) -> dict[str, Any]:
    """Validate the strict bounded whole-site manifest and return normalized totals."""
    if not isinstance(document, dict) or set(document) != {
        "claim_boundary", "critical_paths", "file_count", "files", "manifest_path",
        "schema", "source_ref", "total_bytes",
    }:
        raise PagesDeploymentError("deployment manifest schema is not exact")
    if document.get("schema") != MANIFEST_SCHEMA:
        raise PagesDeploymentError("deployment manifest identifier is unsupported")
    if document.get("source_ref") != expected_source_ref:
        raise PagesDeploymentError("deployment manifest source_ref does not match")
    if document.get("manifest_path") != MANIFEST_PATH:
        raise PagesDeploymentError("deployment manifest self path is not exact")
    if document.get("claim_boundary") != MANIFEST_CLAIM_BOUNDARY:
        raise PagesDeploymentError("deployment manifest claim boundary is not exact")
    if document.get("critical_paths") != list(CRITICAL_PATHS):
        raise PagesDeploymentError("deployment manifest critical paths are not exact")
    files = document.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise PagesDeploymentError("deployment manifest file count is outside bounds")
    paths: list[str] = []
    total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise PagesDeploymentError("deployment manifest file entry is not exact")
        path = _validate_path(entry.get("path"))
        digest = entry.get("sha256")
        size = entry.get("size")
        if path == MANIFEST_PATH:
            raise PagesDeploymentError("deployment manifest cannot recursively list itself")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise PagesDeploymentError(f"deployment digest is invalid: {path}")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_FILE_BYTES:
            raise PagesDeploymentError(f"deployment file size is outside bounds: {path}")
        paths.append(path)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise PagesDeploymentError("deployment manifest total bytes exceed the limit")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PagesDeploymentError("deployment manifest paths are not unique and sorted")
    if any(path not in paths for path in CRITICAL_PATHS):
        raise PagesDeploymentError("deployment manifest omits a critical path")
    if document.get("file_count") != len(files) or document.get("total_bytes") != total:
        raise PagesDeploymentError("deployment manifest totals do not reconcile")
    return {"file_count": len(files), "total_bytes": total, "paths": paths}


def load_manifest_bytes(payload: bytes, *, expected_source_ref: str) -> dict[str, Any]:
    if len(payload) > MAX_MANIFEST_BYTES:
        raise PagesDeploymentError("deployment manifest exceeds its byte limit")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PagesDeploymentError("deployment manifest is not valid UTF-8 JSON") from exc
    validate_manifest(document, expected_source_ref=expected_source_ref)
    if payload != _canonical_json(document):
        raise PagesDeploymentError("deployment manifest bytes are not canonical")
    return document


def validate_site_directory(
    root: Path, *, expected_source_ref: str, expected_manifest_sha256: str | None = None
) -> dict[str, Any]:
    """Recheck exact local inventory and bytes immediately before artifact upload."""
    root = root.resolve()
    manifest_path = root / MANIFEST_PATH
    manifest_bytes = manifest_path.read_bytes()
    document = load_manifest_bytes(manifest_bytes, expected_source_ref=expected_source_ref)
    manifest_digest = _sha256(manifest_bytes)
    if expected_manifest_sha256 is not None and manifest_digest != expected_manifest_sha256:
        raise PagesDeploymentError("rebuilt manifest does not match the known-good receipt")
    actual_paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PagesDeploymentError("Pages artifact contains a symbolic link")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative != MANIFEST_PATH:
                actual_paths.append(_validate_path(relative))
    entries = document["files"]
    if sorted(actual_paths) != [entry["path"] for entry in entries]:
        raise PagesDeploymentError("local Pages inventory differs from deployment manifest")
    for entry in entries:
        payload = (root / entry["path"]).read_bytes()
        if len(payload) != entry["size"] or _sha256(payload) != entry["sha256"]:
            raise PagesDeploymentError(f"local Pages bytes differ from manifest: {entry['path']}")
    return {
        "deployment_manifest_sha256": manifest_digest,
        "file_count": document["file_count"],
        "source_ref": expected_source_ref,
        "total_bytes": document["total_bytes"],
    }


def _normalized_resource_url(url: str, *, allowed_host: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise PagesDeploymentError("URL has an invalid port") from exc
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https" or host != allowed_host.lower()
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 443) or parsed.query or parsed.fragment
    ):
        raise PagesDeploymentError("URL must be HTTPS on the exact allowed host")
    if any(part == ".." for part in unquote(parsed.path).split("/")):
        raise PagesDeploymentError("URL path must not traverse parent paths")
    return urlunsplit(("https", parsed.netloc, parsed.path or "/", "", ""))


def normalize_base_url(base_url: str, *, allowed_host: str) -> str:
    normalized = _normalized_resource_url(base_url, allowed_host=allowed_host)
    parsed = urlsplit(normalized)
    path = parsed.path if parsed.path.endswith("/") else parsed.path + "/"
    return urlunsplit(("https", parsed.netloc, path, "", ""))


def validate_promotion_source(
    *, expected_source_ref: str, current_main_ref: str, repository_run: dict[str, Any]
) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_ref) is None:
        raise PagesDeploymentError("expected source ref must be a full lowercase commit ID")
    if expected_source_ref != current_main_ref:
        raise PagesDeploymentError("deployment source is not the current main commit")
    if (
        repository_run.get("head_sha") != expected_source_ref
        or repository_run.get("event") != "push"
        or repository_run.get("status") != "completed"
        or repository_run.get("conclusion") != "success"
        or repository_run.get("path") != REPOSITORY_CHECKS_WORKFLOW_PATH
    ):
        raise PagesDeploymentError("repository-check run does not qualify the source commit")
    run_id = str(repository_run.get("id", ""))
    if re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        raise PagesDeploymentError("repository-check run has no valid ID")
    return run_id


def validate_documents(
    *, expected_source_ref: str, documentation: dict[str, Any],
    component_coordinate: dict[str, Any], component_index: bytes,
    published_digest: str,
) -> dict[str, Any]:
    """Retain the focused coordinate check used by local callers and tests."""
    if documentation.get("source_ref") != expected_source_ref:
        raise PagesDeploymentError("documentation source_ref does not match the promoted commit")
    if component_coordinate.get("source_ref") != expected_source_ref:
        raise PagesDeploymentError("component source_ref does not match the promoted commit")
    actual_digest = _sha256(component_index)
    if published_digest.strip().split(maxsplit=1)[0] != actual_digest:
        raise PagesDeploymentError("published component-index digest does not match its bytes")
    if component_coordinate.get("index_sha256") != actual_digest:
        raise PagesDeploymentError("component deployment coordinate has a different index digest")
    return {
        "component_index_sha256": actual_digest,
        "source_ref": expected_source_ref,
    }


def validate_rollback_receipt(
    receipt: Any, *, expected_source_ref: str, expected_deployment_workflow_run_id: str,
    deployment_run: dict[str, Any],
) -> dict[str, str]:
    """Validate retained prior observation input; this does not grant authorization."""
    required = {
        "base_url", "checked_route_count", "claim_boundary", "deployed_file_count",
        "deployed_total_bytes", "deployment_manifest_sha256", "deployment_workflow_run_id",
        "repository_checks_run_id", "result", "schema_version", "source_ref",
    }
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise PagesDeploymentError("known-good deployment receipt schema is not exact")
    if (
        str(deployment_run.get("id")) != expected_deployment_workflow_run_id
        or deployment_run.get("name") != "pages"
        or deployment_run.get("path") != ".github/workflows/pages.yml"
        or deployment_run.get("status") != "completed"
        or deployment_run.get("conclusion") != "success"
        or deployment_run.get("event") not in {"workflow_run", "workflow_dispatch"}
    ):
        raise PagesDeploymentError("known-good receipt run is not a successful Pages run")
    if (
        receipt.get("schema_version") != 2 or receipt.get("result") != "PASS"
        or receipt.get("source_ref") != expected_source_ref
        or receipt.get("deployment_workflow_run_id") != expected_deployment_workflow_run_id
        or receipt.get("claim_boundary") != RECEIPT_CLAIM_BOUNDARY
        or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("deployment_manifest_sha256"))) is None
        or re.fullmatch(r"[1-9][0-9]*", str(receipt.get("repository_checks_run_id"))) is None
        or not isinstance(receipt.get("deployed_file_count"), int)
        or not 1 <= receipt["deployed_file_count"] <= MAX_FILES
        or receipt.get("checked_route_count") != receipt["deployed_file_count"] + 1
        or not isinstance(receipt.get("deployed_total_bytes"), int)
        or not 0 <= receipt["deployed_total_bytes"] <= MAX_TOTAL_BYTES
    ):
        raise PagesDeploymentError("known-good deployment receipt does not qualify")
    return {
        "deployment_manifest_sha256": receipt["deployment_manifest_sha256"],
        "repository_checks_run_id": str(receipt["repository_checks_run_id"]),
    }


def _fetch(url: str, *, allowed_host: str, byte_limit: int | None = None) -> bytes:
    if byte_limit is None:
        byte_limit = MAX_RESPONSE_BYTES
    requested_url = _normalized_resource_url(url, allowed_host=allowed_host)
    request = Request(requested_url, headers={
        "Accept-Encoding": "identity", "Cache-Control": "no-cache",
        "User-Agent": "vstd-pages-check",
    })
    try:
        response_context = URL_OPEN(request, timeout=15)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise PagesDeploymentError("deployment redirects are forbidden") from exc
        raise
    with response_context as response:
        try:
            response_url = _normalized_resource_url(
                response.geturl(), allowed_host=allowed_host
            )
        except PagesDeploymentError as exc:
            raise PagesDeploymentError(
                "deployment response redirected outside the allowed route"
            ) from exc
        if response_url != requested_url:
            raise PagesDeploymentError("deployment response redirected outside the requested route")
        status = getattr(response, "status", 200)
        if status != 200:
            raise PagesDeploymentError(f"deployment response status is not 200: {status}")
        encoding = response.headers.get("Content-Encoding")
        if encoding not in (None, "", "identity"):
            raise PagesDeploymentError("deployment response content encoding is ambiguous")
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_length = int(declared)
            except ValueError as exc:
                raise PagesDeploymentError("deployment response has invalid content length") from exc
            if declared_length < 0 or declared_length > byte_limit:
                raise PagesDeploymentError("deployment response exceeds the byte limit")
        payload = response.read(byte_limit + 1)
        if len(payload) > byte_limit:
            raise PagesDeploymentError("deployment response exceeds the byte limit")
        if declared is not None and declared_length != len(payload):
            raise PagesDeploymentError("deployment response length does not match its header")
        return payload


def observe(
    base_url: str, expected_source_ref: str, *, allowed_host: str,
    repository_checks_run_id: str, deployment_workflow_run_id: str,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_ref) is None:
        raise PagesDeploymentError("expected source ref must be a full lowercase commit ID")
    if re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is None:
        raise PagesDeploymentError("expected deployment-manifest digest is invalid")
    normalized = normalize_base_url(base_url, allowed_host=allowed_host)
    manifest_bytes = _fetch(
        urljoin(normalized, MANIFEST_PATH), allowed_host=allowed_host,
        byte_limit=MAX_MANIFEST_BYTES,
    )
    manifest_digest = _sha256(manifest_bytes)
    if manifest_digest != expected_manifest_sha256:
        raise PagesDeploymentError("live deployment manifest differs from promoted manifest")
    manifest = load_manifest_bytes(manifest_bytes, expected_source_ref=expected_source_ref)
    fetched: dict[str, bytes] = {}
    for entry in manifest["files"]:
        path = entry["path"]
        route = urljoin(normalized, quote(path, safe="/-._~"))
        payload = _fetch(route, allowed_host=allowed_host, byte_limit=MAX_FILE_BYTES)
        if len(payload) != entry["size"] or _sha256(payload) != entry["sha256"]:
            raise PagesDeploymentError(f"live Pages bytes differ from manifest: {path}")
        fetched[path] = payload
    documentation = json.loads(fetched["documentation-coordinate.json"])
    component_coordinate = json.loads(fetched["components/deployment-coordinate.json"])
    if documentation.get("source_ref") != expected_source_ref:
        raise PagesDeploymentError("documentation source_ref does not match the promoted commit")
    if component_coordinate.get("source_ref") != expected_source_ref:
        raise PagesDeploymentError("component source_ref does not match the promoted commit")
    component_digest = _sha256(fetched["components/index.json"])
    published_digest = (
        fetched["components/index.sha256"].decode("ascii").strip().split(maxsplit=1)[0]
    )
    if (
        component_digest != published_digest
        or component_coordinate.get("index_sha256") != component_digest
    ):
        raise PagesDeploymentError("component-index digest surfaces do not match deployed bytes")
    return {
        "base_url": normalized,
        "checked_route_count": manifest["file_count"] + 1,
        "claim_boundary": RECEIPT_CLAIM_BOUNDARY,
        "deployed_file_count": manifest["file_count"],
        "deployed_total_bytes": manifest["total_bytes"],
        "deployment_manifest_sha256": manifest_digest,
        "deployment_workflow_run_id": deployment_workflow_run_id,
        "repository_checks_run_id": repository_checks_run_id,
        "result": "PASS", "schema_version": 2, "source_ref": expected_source_ref,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument("--expected-source-ref", required=True)
    parser.add_argument("--allowed-host")
    parser.add_argument("--validate-source", action="store_true")
    parser.add_argument("--validate-site", type=Path)
    parser.add_argument("--validate-rollback-receipt", type=Path)
    parser.add_argument("--current-main-ref")
    parser.add_argument("--repository-run", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--deployment-workflow-run-id")
    parser.add_argument("--deployment-run", type=Path)
    parser.add_argument("--attempts", type=int, default=6)
    parser.add_argument("--interval-seconds", type=int, default=10)
    parser.add_argument("--workflow-run-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.validate_source:
            if args.current_main_ref is None or args.repository_run is None:
                raise PagesDeploymentError("source validation requires current main and repository run")
            run_id = validate_promotion_source(
                expected_source_ref=args.expected_source_ref,
                current_main_ref=args.current_main_ref,
                repository_run=json.loads(args.repository_run.read_text(encoding="utf-8")),
            )
            print(f"[PAGES SOURCE PASS] exact current main qualified by run {run_id}")
            return 0
        if args.validate_rollback_receipt is not None:
            if args.deployment_workflow_run_id is None or args.deployment_run is None:
                raise PagesDeploymentError("rollback receipt requires its deployment workflow run")
            result = validate_rollback_receipt(
                json.loads(args.validate_rollback_receipt.read_text(encoding="utf-8")),
                expected_source_ref=args.expected_source_ref,
                expected_deployment_workflow_run_id=args.deployment_workflow_run_id,
                deployment_run=json.loads(args.deployment_run.read_text(encoding="utf-8")),
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.validate_site is not None:
            result = validate_site_directory(
                args.validate_site, expected_source_ref=args.expected_source_ref,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
    except (OSError, UnicodeError, json.JSONDecodeError, PagesDeploymentError) as exc:
        print(f"[PAGES VALIDATION FAIL] {exc}")
        return 1
    if (
        args.base_url is None or args.allowed_host is None or args.output is None
        or args.expected_manifest_sha256 is None
    ):
        parser.error(
            "live observation requires base URL, allowed host, expected manifest digest, and output"
        )
    if args.workflow_run_id is None or args.deployment_workflow_run_id is None:
        parser.error("live observation requires repository-check and deployment workflow run IDs")
    if not 1 <= args.attempts <= 12 or not 0 <= args.interval_seconds <= 30:
        print("[PAGES DEPLOYMENT FAIL] retry bounds are invalid")
        return 1
    last_error = "no observation attempted"
    for attempt in range(1, args.attempts + 1):
        print(f"[PAGES DEPLOYMENT] observation {attempt}/{args.attempts}", flush=True)
        try:
            result = observe(
                args.base_url, args.expected_source_ref, allowed_host=args.allowed_host,
                repository_checks_run_id=args.workflow_run_id,
                deployment_workflow_run_id=args.deployment_workflow_run_id,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            args.output.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8", newline="\n",
            )
            print("[PAGES DEPLOYMENT PASS] every manifest-listed live route matched")
            return 0
        except (OSError, URLError, UnicodeError, json.JSONDecodeError, PagesDeploymentError) as exc:
            last_error = str(exc)
            print(f"[PAGES DEPLOYMENT] not current yet: {last_error}", flush=True)
            if attempt < args.attempts:
                time.sleep(args.interval_seconds)
    print(f"[PAGES DEPLOYMENT FAIL] {last_error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

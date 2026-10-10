"""Supply Chain Integrity, Transparency, and Trust (SCITT) transport tests.

Hypertext Transfer Protocol (HTTP); Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Synthetic packages
exercise transport/admission, not native verifier qualification.
"""

from __future__ import annotations

import importlib
import importlib.util
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from types import ModuleType
from typing import Any, Iterator

import pytest

from test_scitt_catalog_entry import entry, files
from test_scitt_package_comparison import comparison, specimen
from test_scitt_native_runner import runner
from verifier.interoperability.storage import StoredComponentPackage


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fetch(entry: ModuleType, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "examples/scitt_native_interop"))
    sys.modules["catalog_entry"] = entry
    spec = importlib.util.spec_from_file_location("scitt_fetch_test", ROOT / "examples/scitt_native_interop/fetch_distribution.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def retained(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path) -> tuple[dict[str, bytes], str, Path]:
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    package, sidecar, _ = files(source, specimen)
    path = source / "entry.json"
    made = entry.create_entry(path, package, sidecar)
    return {item.name: item.read_bytes() for item in (path, package, sidecar)}, made["entry_digest"], output


@contextmanager
def server(bodies: dict[str, bytes], *, mode: str = "normal") -> Iterator[tuple[str, list[str]]]:
    observed: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            observed.append(self.path)
            raw = bodies.get(self.path.rsplit("/", 1)[-1], b"missing")
            try:
                if mode == "headers_wait":
                    time.sleep(1)
                self.send_response(302 if mode == "redirect" else 503 if mode == "status" else 200)
                if mode == "redirect": self.send_header("Location", "/must-not-follow")
                if mode in ("gzip", "duplicate_encoding"):
                    self.send_header("Content-Encoding", "gzip" if mode == "gzip" else "identity")
                    if mode == "duplicate_encoding": self.send_header("Content-Encoding", "identity")
                if mode in ("chunked", "truncated_chunked", "duplicate_transfer", "unknown_transfer"):
                    self.send_header("Transfer-Encoding", "chunked")
                    if mode == "duplicate_transfer": self.send_header("Transfer-Encoding", "chunked")
                    if mode == "unknown_transfer": self.send_header("Transfer-Encoding", "unknown")
                elif mode == "ambiguous":
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Transfer-Encoding", "chunked")
                elif mode == "invalid_length":
                    self.send_header("Content-Length", "-1")
                elif mode != "no_length":
                    self.send_header("Content-Length", str(len(raw) + 5 if mode == "truncated" else 40 * 1024 * 1024 if mode == "oversize" else len(raw)))
                    if mode == "duplicate_length": self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if mode == "drip":
                    for byte in raw:
                        self.wfile.write(bytes((byte,)))
                        self.wfile.flush()
                        time.sleep(0.03)
                elif mode in ("chunked", "truncated_chunked"):
                    self.wfile.write(format(len(raw), "x").encode() + b"\r\n" + raw + (b"\r\n0\r\n\r\n" if mode == "chunked" else b""))
                else:
                    self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=service.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(service.server_port) + "/distribution/entry.json", observed
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def fake_transport(fetch: ModuleType, bodies: dict[str, bytes], monkeypatch: pytest.MonkeyPatch) -> list[str]:
    requested: list[str] = []

    def body(url: str, limit: int, deadline: float) -> bytes:
        requested.append(url)
        value = bodies[url.rsplit("/", 1)[-1]]
        assert len(value) <= limit
        return value

    monkeypatch.setattr(fetch, "_fetch_body", body)
    return requested


def test_fetch_module_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "examples/scitt_native_interop"))
    assert callable(importlib.import_module("fetch_distribution").fetch_distribution)


@pytest.mark.parametrize("mode", ["normal", "chunked", "no_length"])
def test_real_loopback_roundtrip_exact_bytes_and_reinspection(fetch: ModuleType, entry: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    bodies, digest, output = retained
    monkeypatch.setattr(runner, "capture_comparison", lambda *args, **kwargs: pytest.fail("native execution forbidden"))
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with server(bodies, mode=mode) as (url, observed):
        result = fetch.fetch_distribution(url, expected_entry_digest=digest, output_root=output, allow_loopback_http=True)
    assert observed == ["/distribution/entry.json", "/distribution/package.json", "/distribution/sidecar.json"]
    destination = output / digest
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == bodies
    assert result["comparison"] == entry.inspect_entry(destination / "entry.json", expected_entry_digest=digest)["comparison"]
    assert result["native_execution_performed"] is False
    assert result["comparison"]["native_qualification"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mode", ["redirect", "status", "gzip", "duplicate_encoding", "duplicate_length", "duplicate_transfer", "unknown_transfer", "invalid_length", "ambiguous", "truncated", "truncated_chunked", "oversize"])
def test_real_transport_refuses_bad_status_framing_and_lengths(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], mode: str) -> None:
    bodies, digest, output = retained
    with server(bodies, mode=mode) as (url, observed):
        with pytest.raises(ValueError, match="network request refused"):
            fetch.fetch_distribution(url, expected_entry_digest=digest, output_root=output, allow_loopback_http=True)
    assert observed == ["/distribution/entry.json"]
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("mode", ["drip", "headers_wait"])
def test_total_deadline_includes_headers_and_drip_body(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], mode: str) -> None:
    bodies, digest, output = retained
    with server(bodies, mode=mode) as (url, observed):
        started = time.monotonic()
        with pytest.raises(ValueError, match="deadline"):
            fetch.fetch_distribution(url, expected_entry_digest=digest, output_root=output, timeout_seconds=0.3, allow_loopback_http=True)
        assert time.monotonic() - started < 3
    assert len(observed) <= 1
    assert list(output.iterdir()) == []


def test_wrong_entry_stops_before_any_sibling_request(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path]) -> None:
    bodies, _, output = retained
    with server(bodies) as (url, observed):
        with pytest.raises(ValueError, match="no sibling"):
            fetch.fetch_distribution(url, expected_entry_digest="a" * 64, output_root=output, allow_loopback_http=True)
    assert observed == ["/distribution/entry.json"]
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("target", ["package.json", "sidecar.json"])
def test_substituted_sibling_never_reaches_output(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], target: str) -> None:
    bodies, digest, output = retained
    bodies[target] = b"unadmitted bytes"
    with server(bodies) as (url, observed):
        with pytest.raises(ValueError, match="raw digest"):
            fetch.fetch_distribution(url, expected_entry_digest=digest, output_root=output, allow_loopback_http=True)
    assert len(observed) == (2 if target == "package.json" else 3)
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("url", ["http://localhost/entry.json", "http://127.1/entry.json", "http://127.0.0.1/entry.json", "ftp://example.com/entry.json", pytest.param("https://user:pass" + "@" + "example.com/entry.json", id="userinfo-in-authority"), "https://example.com/a/../entry.json", "https://example.com/%65ntry.json", "https://example.com/entry.json?x=1", "https://example.com/entry.json#x", "https://example.com//entry.json", "https://example.com/NUL.json", "https://example.com:0443/entry.json", "https://example.com/entry.json\n"])
def test_bad_urls_refused_before_network(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _, digest, output = retained
    monkeypatch.setattr(fetch, "_fetch_body", lambda *args: pytest.fail("no network permitted"))
    with pytest.raises(ValueError):
        fetch.fetch_distribution(url, expected_entry_digest=digest, output_root=output)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), 0, -1, 121, "30"])
def test_timeout_types_bounds_before_network(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], value: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, digest, output = retained
    monkeypatch.setattr(fetch, "_fetch_body", lambda *args: pytest.fail("no network permitted"))
    with pytest.raises(ValueError):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output, timeout_seconds=value)


@pytest.mark.parametrize("kind", ["directory", "partial", "case_alias", "file"])
def test_existing_destination_refused_before_network(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    _, digest, output = retained
    path = output / (digest.upper() if kind == "case_alias" else digest)
    if kind == "file": path.write_bytes(b"preserve")
    else:
        path.mkdir()
        if kind == "partial": (path / "package.json").write_bytes(b"partial")
    monkeypatch.setattr(fetch, "_fetch_body", lambda *args: pytest.fail("no network permitted"))
    with pytest.raises(FileExistsError):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)
    assert path.exists()


@pytest.mark.parametrize("name", ["../private.json", "https://other.example/secret", "entry.json", "SIDECAR.JSON", "NUL.json"])
def test_admitted_entry_cannot_select_untrusted_sibling_locations(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    bodies, _, output = retained
    manifest = json.loads(bodies["entry.json"])
    manifest["package"]["filename"] = name
    bodies["entry.json"] = comparison.canonical(manifest)
    digest = comparison.sha(bodies["entry.json"])
    requested = fake_transport(fetch, bodies, monkeypatch)
    with pytest.raises(ValueError):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)
    assert len(requested) == 1
    assert list(output.iterdir()) == []


def test_source_drift_during_download_refused_before_mkdir(fetch: ModuleType, entry: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    bodies, digest, output = retained
    requested = fake_transport(fetch, bodies, monkeypatch)
    inventory = entry.source_inventory()
    calls = 0

    def changed() -> dict[str, str]:
        nonlocal calls
        calls += 1
        return inventory if calls == 1 else {**inventory, "src/verifier/added.py": "a" * 64}

    monkeypatch.setattr(entry, "source_inventory", changed)
    with pytest.raises(ValueError, match="sources changed"):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)
    assert list(output.iterdir()) == []
    assert len(requested) == 1


@pytest.mark.parametrize("mutation", ["extra", "tamper", "write_failure"])
def test_postcreate_failures_leave_partial_output_and_refuse_retry(fetch: ModuleType, entry: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    bodies, digest, output = retained
    fake_transport(fetch, bodies, monkeypatch)
    inspect = entry.inspect_entry

    def inspect_then_change(path: Path, **kwargs: Any) -> dict[str, Any]:
        report = inspect(path, **kwargs)
        (path.parent / ("extra.txt" if mutation == "extra" else "package.json")).write_bytes(b"changed")
        return report

    if mutation == "write_failure":
        monkeypatch.setattr(fetch, "_write_new", lambda *args: (_ for _ in ()).throw(OSError("synthetic")))
    else:
        monkeypatch.setattr(entry, "inspect_entry", inspect_then_change)
    with pytest.raises(fetch.DistributionFetchError, match="retained"):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)
    assert (output / digest).is_dir()
    with pytest.raises(FileExistsError):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)


def test_interrupted_communication_kills_and_reaps_transport(fetch: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    class Interrupted:
        returncode: int | None = None
        killed = False
        reaped = False

        def communicate(self, timeout: float) -> tuple[bytes, bytes]:
            if not self.killed:
                raise KeyboardInterrupt()
            self.reaped = True
            self.returncode = -1
            return b"", b""

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed = True

    process = Interrupted()
    monkeypatch.setattr(fetch.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(KeyboardInterrupt):
        fetch._fetch_body("https://example.com/entry.json", 128, time.monotonic() + 30)
    assert process.killed and process.reaped


@pytest.mark.parametrize("mode", ["chunked", "no_length"])
def test_streamed_body_cap_without_usable_declared_length(fetch: ModuleType, mode: str) -> None:
    with server({"entry.json": b"x" * 4097}, mode=mode) as (url, observed):
        with pytest.raises(ValueError, match="network request refused"):
            fetch._fetch_body(url, 4096, time.monotonic() + 5)
    assert len(observed) == 1


def test_source_identity_mismatch_precedes_sibling_requests(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    bodies, _, output = retained
    manifest = json.loads(bodies["entry.json"])
    manifest["reconstruction_sources"]["src/verifier/__init__.py"] = "a" * 64
    bodies["entry.json"] = comparison.canonical(manifest)
    requested = fake_transport(fetch, bodies, monkeypatch)
    with pytest.raises(ValueError, match="source inventory differs"):
        fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=comparison.sha(bodies["entry.json"]), output_root=output)
    assert len(requested) == 1
    assert list(output.iterdir()) == []


def test_secure_connection_uses_default_certificate_and_hostname_checks(fetch: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def connection(hostname: str, port: int | None, *, timeout: float, context: Any) -> Any:
        assert hostname == "example.com" and timeout == 1
        assert context.verify_mode == fetch.ssl.CERT_REQUIRED
        assert context.check_hostname is True
        seen.append(True)
        raise ValueError("synthetic stop before connection")

    monkeypatch.setattr(fetch.http.client, "HTTPSConnection", connection)
    with pytest.raises(ValueError, match="synthetic stop"):
        fetch._network_body("https://example.com/entry.json", 128, 1)
    assert seen == [True]


def test_same_absolute_deadline_for_all_bodies(fetch: ModuleType, retained: tuple[dict[str, bytes], str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    bodies, digest, output = retained
    deadlines: list[float] = []

    def body(url: str, limit: int, deadline: float) -> bytes:
        deadlines.append(deadline)
        return bodies[url.rsplit("/", 1)[-1]]

    monkeypatch.setattr(fetch, "_fetch_body", body)
    fetch.fetch_distribution("https://example.com/entry.json", expected_entry_digest=digest, output_root=output)
    assert len(deadlines) == 3 and len(set(deadlines)) == 1

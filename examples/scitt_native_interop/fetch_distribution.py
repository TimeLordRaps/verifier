"""Supply Chain Integrity, Transparency, and Trust (SCITT) consumer transport.

Hypertext Transfer Protocol (HTTP); Hypertext Transfer Protocol Secure (HTTPS);
uniform resource locator (URL); Transport Layer Security (TLS); American Standard Code for
Information Interchange (ASCII); Secure Hash Algorithm 256-bit
(SHA-256); JavaScript Object Notation (JSON). A separately selected entry digest
admits exactly three downloaded files for existing local source reconstruction.
Trusted local transport subprocesses enforce a total network wall-clock deadline;
they are not native verifiers. No downloaded commands, source imports, redirects,
proxy settings, cookies, installation, publication, or qualification are used.
Local source checks are observations, not loaded-byte attestation or an atomic
filesystem snapshot. Partial output after exclusive creation remains on failure.
"""

from __future__ import annotations

import argparse
import http.client
import math
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit


def _network_body(url: str, limit: int, timeout: float) -> bytes:
    """Trusted child: one request, no redirects, bounded original entity bytes."""
    parsed = urlsplit(url)
    connection = (http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=timeout, context=ssl.create_default_context())
                  if parsed.scheme == "https" else http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout))
    try:
        connection.request("GET", parsed.path, headers={"Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("status refused")
        headers = response.getheaders()
        if sum(len(key) + len(value) for key, value in headers) > 16384:
            raise ValueError("headers exceed bound")
        lengths = response.headers.get_all("Content-Length", [])
        encodings = response.headers.get_all("Content-Encoding", [])
        transfers = response.headers.get_all("Transfer-Encoding", [])
        if len(lengths) > 1 or len(encodings) > 1 or (encodings and encodings != ["identity"]) or (transfers and (transfers != ["chunked"] or lengths)):
            raise ValueError("unsupported body framing or encoding")
        length = None
        if lengths:
            if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                raise ValueError("invalid declared length")
            length = int(lengths[0])
            if length > limit:
                raise ValueError("declared length exceeds bound")
        data = response.read(limit + 1)
        if len(data) > limit or (length is not None and len(data) != length):
            raise ValueError("body length differs or exceeds bound")
        return data
    finally:
        connection.close()


def _network_child(argv: list[str]) -> int:
    try:
        if len(argv) != 3:
            raise ValueError("invalid child arguments")
        url, limit, timeout = argv[0], int(argv[1]), float(argv[2])
        if not 0 <= limit <= 32 * 1024 * 1024 or not 0 < timeout <= 120:
            raise ValueError("invalid child bounds")
        data = _network_body(url, limit, timeout)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Never expose remote headers, response bodies, local paths or exception text.
        sys.stderr.write("bounded network request refused\n")
        return 1


# Isolated network children need no verifier imports or inherited search path.
if __name__ == "__main__" and sys.argv[1:2] == ["--network-body"]:
    raise SystemExit(_network_child(sys.argv[2:]))

import catalog_entry
from native_runner import _ordinary, _write_new, read_regular
from stage_distribution import _exact_names, _refuse_existing_child
from verifier.core.receipt import strict_json_loads


BOUNDARY = "Exact-byte consumer transport and local source reconstruction only; no native verification, publication, publisher authentication, qualification, or runtime attestation."


class DistributionFetchError(ValueError):
    """Post-creation failure leaves the new directory present, possibly partial."""


def _url(value: str, allow_loopback_http: bool) -> tuple[str, str]:
    if type(value) is not str or not 1 <= len(value) <= 2048 or any(ord(char) <= 32 or ord(char) >= 127 for char in value) or any(char in value for char in "%\\?#@"):
        raise ValueError("URL must be bounded plain ASCII without credentials, escapes, query or fragment")
    parsed = urlsplit(value)
    if parsed.scheme not in ("https", "http") or not value.startswith(parsed.scheme + "://") or not parsed.hostname:
        raise ValueError("an absolute HTTPS URL is required")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid URL port")
    hostname = parsed.hostname
    if parsed.scheme == "http" and (not allow_loopback_http or hostname not in ("127.0.0.1", "::1")):
        raise ValueError("HTTP requires explicit numeric loopback opt-in")
    authority = ("[::1]" if hostname == "::1" else hostname) + (":" + str(parsed.port) if parsed.port is not None else "")
    if parsed.netloc != authority or (hostname != "::1" and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname) is None):
        raise ValueError("noncanonical URL authority")
    parts = parsed.path.split("/")
    if len(parts) < 2 or parts[0] != "" or any(not part or part in (".", "..") or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part) is None for part in parts[1:]):
        raise ValueError("URL path must contain literal ordinary segments")
    name = catalog_entry._filename(parts[-1])
    return value.rsplit("/", 1)[0] + "/", name


def _fetch_body(url: str, limit: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("total network deadline exhausted")
    print("network request started; byte cap=" + str(limit), file=sys.stderr, flush=True)
    environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    process = subprocess.Popen([sys.executable, "-I", "-B", "-S", str(Path(__file__).absolute()), "--network-body", url, str(limit), str(remaining)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    try:
        stdout, stderr = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
    except BaseException as exc:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        print("network request stopped; transport child reaped", file=sys.stderr, flush=True)
        if isinstance(exc, subprocess.TimeoutExpired):
            raise ValueError("total network deadline exhausted; transport child stopped") from None
        raise
    print("network request ended; retained bytes=" + str(len(stdout)), file=sys.stderr, flush=True)
    if time.monotonic() > deadline:
        raise ValueError("total network deadline exhausted")
    if process.returncode != 0 or stderr or len(stdout) > limit:
        raise ValueError("bounded network request refused")
    return stdout


def fetch_distribution(entry_url: str, *, expected_entry_digest: str, output_root: Path, timeout_seconds: float = 30, allow_loopback_http: bool = False) -> dict[str, Any]:
    """Download an explicitly selected entry and two exact siblings, then inspect."""
    catalog_entry._digest(expected_entry_digest)
    if type(allow_loopback_http) is not bool or type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ValueError("explicit Boolean opt-in and finite timeout in (0, 120] seconds required")
    base, entry_name = _url(entry_url, allow_loopback_http)
    output_root = Path(os.path.abspath(output_root))
    _ordinary(output_root, directory=True)
    _refuse_existing_child(output_root, expected_entry_digest)
    catalog_entry._check_import_locations()
    sources = catalog_entry.source_inventory()

    def check_sources() -> None:
        catalog_entry._check_import_locations()
        if catalog_entry.source_inventory() != sources:
            raise ValueError("reconstruction sources changed during consumer transport")

    deadline = time.monotonic() + timeout_seconds
    entry_bytes = _fetch_body(entry_url, catalog_entry.MAX_ENTRY_BYTES, deadline)
    if catalog_entry.comparison.sha(entry_bytes) != expected_entry_digest:
        raise ValueError("entry differs from separately supplied digest; no sibling locations admitted")
    manifest = catalog_entry._manifest(strict_json_loads(entry_bytes))
    if catalog_entry.comparison.canonical(manifest) != entry_bytes:
        raise ValueError("entry transport must be canonical")
    if sources != manifest["reconstruction_sources"]:
        raise ValueError("reconstruction source inventory differs")
    check_sources()
    names = [entry_name, manifest["package"]["filename"], manifest["sidecar"]["filename"]]
    if len({name.casefold() for name in names}) != 3:
        raise ValueError("three distinct sibling filenames required")
    limits = {names[0]: catalog_entry.MAX_ENTRY_BYTES, names[1]: catalog_entry.MAX_PACKAGE_BYTES, names[2]: catalog_entry.MAX_SIDECAR_BYTES}
    snapshot = {entry_name: entry_bytes}
    for key in ("package", "sidecar"):
        name = manifest[key]["filename"]
        raw = _fetch_body(base + name, limits[name], deadline)
        if catalog_entry.comparison.sha(raw) != manifest[key]["sha256"]:
            raise ValueError("downloaded sibling differs from admitted raw digest")
        snapshot[name] = raw

    check_sources()
    _refuse_existing_child(output_root, expected_entry_digest)
    destination = output_root / expected_entry_digest
    os.mkdir(destination)
    try:
        for name in (names[1], names[2], names[0]):
            _write_new(destination / name, snapshot[name])
        _exact_names(destination, set(names))
        check_sources()
        inspected = catalog_entry.inspect_entry(destination / entry_name, expected_entry_digest=expected_entry_digest)
        _exact_names(destination, set(names))
        if any(read_regular(destination / name, limits[name]) != raw for name, raw in snapshot.items()):
            raise ValueError("downloaded files changed during inspection")
        check_sources()
    except Exception as exc:
        raise DistributionFetchError("consumer reconstruction failed; newly created destination retained, possibly partial; no cleanup performed") from exc
    return {"entry_digest": expected_entry_digest, "destination": str(destination), "filenames": sorted(names),
            "comparison": inspected["comparison"], "native_execution_performed": False,
            "network_operations_performed": True, "claim_boundary": BOUNDARY}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entry_url")
    parser.add_argument("--expected-entry-sha256", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30)
    parser.add_argument("--allow-loopback-http", action="store_true")
    args = parser.parse_args(argv)
    report = fetch_distribution(args.entry_url, expected_entry_digest=args.expected_entry_sha256, output_root=args.output_root,
                                timeout_seconds=args.timeout_seconds, allow_loopback_http=args.allow_loopback_http)
    print(catalog_entry.comparison.canonical(report).decode("ascii"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

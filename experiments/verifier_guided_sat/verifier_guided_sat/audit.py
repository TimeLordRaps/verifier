"""Create/validate deterministic hashes and scan public experiment text."""

from __future__ import annotations

import gzip
import re
from pathlib import Path
from typing import Iterable

from .canonical import file_digest, read_json, write_json


EXCLUDED_NAMES = {".venv", ".work", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".md", ".json", ".txt", ".lock"}
PUBLIC_LEAK_PATTERNS = {
    "absolute_windows_path": re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|models|Verifiable|verifier)\b"),
    "absolute_private_unix_path": re.compile(
        r"(?i)(?:/ho" r"me/|/Us" r"ers/|/mnt/[a-z]/(?:Us" r"ers|models|Verifiable|verifier)/)"
    ),
    "local_endpoint": re.compile(r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?"),
    "email_address": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "credential_assignment": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"][^'\"]+"),
    "private_key_material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

GENERIC_SURFACE_FILES = (
    "analysis.py",
    "audit.py",
    "benchmark.py",
    "canonical.py",
    "contracts.py",
    "freeze.py",
    "harness.py",
    "independent_validation.py",
    "lm_backend.py",
    "metrics.py",
    "noise.py",
    "prompts.py",
    "result_validator.py",
    "route.py",
    "sat_backend.py",
    "vstd_binding.py",
)
DOMAIN_SURFACE_FILES = (
    "baselines.py",
    "external_verifiers.py",
    "instances.py",
    "reserve_verifiers.py",
)


def public_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TEXT_SUFFIXES
        and not any(part in EXCLUDED_NAMES for part in path.parts)
    )


def artifact_files(root: Path, output: Path | None = None) -> list[Path]:
    """Return every distributable experiment artifact, including binary gzip results."""

    excluded = output.resolve() if output is not None else None
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_NAMES for part in path.parts)
        and (excluded is None or path.resolve() != excluded)
    )


def scan_public_text(root: Path) -> list[str]:
    findings: list[str] = []
    for path in public_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in PUBLIC_LEAK_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(root).as_posix()}: {label}")
    for path in sorted(root.rglob("*.json.gz")):
        if any(part in EXCLUDED_NAMES for part in path.parts):
            continue
        try:
            text = gzip.decompress(path.read_bytes()).decode("utf-8", errors="replace")
        except (OSError, EOFError):
            findings.append(f"{path.relative_to(root).as_posix()}: malformed_gzip")
            continue
        for label, pattern in PUBLIC_LEAK_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(root).as_posix()}: {label}")
    return findings


def write_artifact_manifest(root: Path, paths: Iterable[Path], output: Path) -> None:
    files = {
        path.relative_to(root).as_posix(): file_digest(path)
        for path in sorted(paths)
        if path.is_file()
    }
    write_json(output, {"manifest_version": "vgsat-artifacts-0.1", "files": files})


def write_engineering_surface(root: Path) -> None:
    """Count the preregistered generic and domain-specific implementation surfaces."""

    source = root / "verifier_guided_sat"
    generic = {name: _count_surface_lines(source / name) for name in GENERIC_SURFACE_FILES}
    domain = {name: _count_surface_lines(source / name) for name in DOMAIN_SURFACE_FILES}
    prior = read_json(root / "engineering-surface.json")
    write_json(
        root / "engineering-surface.json",
        {
            "measurement_version": "vgsat-engineering-surface-0.1",
            "count_rule": (
                "nonblank physical lines excluding lines whose first non-whitespace "
                "character is #; module docstrings included"
            ),
            "generic_files": generic,
            "generic_lines": sum(generic.values()),
            "domain_specific_files": domain,
            "domain_specific_lines": sum(domain.values()),
            "tests_excluded": True,
            "vendored_upstream_lines_excluded": True,
            "human_engineering_time": prior.get(
                "human_engineering_time", "UNKNOWN_NOT_PROSPECTIVELY_INSTRUMENTED"
            ),
        },
    )


def _count_surface_lines(path: Path) -> int:
    return sum(
        bool(line.strip()) and not line.lstrip().startswith("#")
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output = root / "artifact-manifest.json"
    findings = scan_public_text(root)
    if findings:
        for finding in findings:
            print(finding)
        return 1
    write_engineering_surface(root)
    write_artifact_manifest(root, artifact_files(root, output), output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

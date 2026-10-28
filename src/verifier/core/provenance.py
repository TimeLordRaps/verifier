"""Terminology: Verifier Standard (VSTD).

Dynamic provenance capture and environment discovery for VSTD."""

from __future__ import annotations

import hashlib
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class FileChecksum:
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class GitProvenance:
    commit_sha: str
    branch: str
    is_dirty: bool
    dirty_files: tuple[str, ...] = ()
    untracked_files: tuple[str, ...] = ()
    remote_origin: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "is_dirty": self.is_dirty,
            "dirty_files": list(self.dirty_files),
            "untracked_files": list(self.untracked_files),
            "remote_origin": self.remote_origin,
        }


@dataclass(frozen=True)
class RuntimeEnvironment:
    python_version: str
    python_implementation: str
    platform_system: str
    platform_release: str
    platform_machine: str
    hostname_masked: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "platform_system": self.platform_system,
            "platform_release": self.platform_release,
            "platform_machine": self.platform_machine,
            "hostname_masked": self.hostname_masked,
        }


@dataclass(frozen=True)
class ProvenanceRecord:
    target_name: str
    portable_repository_id: str
    local_repository_path: str
    git: GitProvenance
    runtime: RuntimeEnvironment
    captured_at_utc: str
    command_executed: str
    source_file_hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "portable_repository_id": self.portable_repository_id,
            "local_repository_path": self.local_repository_path,
            "git": self.git.to_dict(),
            "runtime": self.runtime.to_dict(),
            "captured_at_utc": self.captured_at_utc,
            "command_executed": self.command_executed,
            "source_file_hashes": self.source_file_hashes,
        }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_SCP_REMOTE = re.compile(r"^[^/@:]+@([^:]+):(.+)$")


def portable_remote_origin(remote: str) -> str:
    """Return a credential-free, non-local repository identifier.

    A receipt is expected to move outside the machine that produced it. Raw Git
    remotes may contain web credentials, remote-shell user names, query tokens, or a
    local filesystem path. None is required to identify the repository, and serializing
    it would turn provenance capture into a secret- and path-disclosure mechanism.

    Network addresses retain scheme, host, optional port, and path. A remote written
    as ``user@host:path`` becomes a host/path identifier. Local, rooted,
    network-share and ``file:`` remotes are deliberately represented only as
    ``LOCAL_REMOTE_REDACTED``. A network address the parser cannot read becomes
    ``REMOTE_REDACTED``; it never raises, so one malformed remote cannot discard the
    commit and branch of the same record.
    """
    value = remote.strip()
    if not value:
        return ""
    if _WINDOWS_ABSOLUTE.match(value) or value.startswith(("/", "\\", "file:")):
        return "LOCAL_REMOTE_REDACTED"

    scp_match = _SCP_REMOTE.fullmatch(value)
    if scp_match:
        host, path = scp_match.groups()
        return f"ssh://{host}/{path.lstrip('/')}"

    if "://" not in value:
        return value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if not host:
            return "LOCAL_REMOTE_REDACTED"
        port = parsed.port
    except ValueError:
        return "REMOTE_REDACTED"
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def discover_git_provenance(repo_dir: Path) -> GitProvenance:
    """Discover git commit, branch, and working-tree dirtiness dynamically."""
    if not repo_dir.exists():
        return GitProvenance(
            commit_sha="UNKNOWN_NO_REPO",
            branch="UNKNOWN",
            is_dirty=False,
        )

    try:
        # Check if inside git work tree
        in_git = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if in_git.returncode != 0 or in_git.stdout.strip() != "true":
            return GitProvenance(
                commit_sha="NOT_A_GIT_REPO",
                branch="UNKNOWN",
                is_dirty=False,
            )

        # Commit SHA
        commit_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        commit_sha = commit_res.stdout.strip() if commit_res.returncode == 0 else "UNKNOWN_NO_COMMITS"

        # Branch
        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        branch = branch_res.stdout.strip() if branch_res.returncode == 0 else "UNKNOWN"

        # Remote origin
        remote_res = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        remote_url = portable_remote_origin(
            remote_res.stdout if remote_res.returncode == 0 else ""
        )

        # Status / dirty check
        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )

        dirty_files = []
        untracked_files = []
        is_dirty = False

        if status_res.returncode == 0 and status_res.stdout:
            is_dirty = True
            for line in status_res.stdout.strip().splitlines():
                if not line:
                    continue
                code = line[:2]
                fname = line[3:].strip()
                if "??" in code:
                    untracked_files.append(fname)
                else:
                    dirty_files.append(fname)

        return GitProvenance(
            commit_sha=commit_sha,
            branch=branch,
            is_dirty=is_dirty,
            dirty_files=tuple(dirty_files),
            untracked_files=tuple(untracked_files),
            remote_origin=remote_url,
        )
    except Exception as exc:
        return GitProvenance(
            commit_sha=f"ERROR_DISCOVERING_GIT: {exc}",
            branch="ERROR",
            is_dirty=True,
        )


def discover_runtime_environment() -> RuntimeEnvironment:
    """Capture runtime python and platform details without exposing private credentials."""
    raw_node = platform.node()
    node_hash = hashlib.sha256(raw_node.encode("utf-8")).hexdigest()[:12]
    return RuntimeEnvironment(
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        platform_system=platform.system(),
        platform_release=platform.release(),
        platform_machine=platform.machine(),
        hostname_masked=f"node-{node_hash}",
    )


def capture_provenance(
    repo_dir: Path,
    target_name: str,
    portable_id: str,
    command_executed: str = "",
    key_files: Sequence[Path] = (),
) -> ProvenanceRecord:
    git_prov = discover_git_provenance(repo_dir)
    runtime_env = discover_runtime_environment()
    captured_at = datetime.now(timezone.utc).isoformat()

    file_hashes: dict[str, str] = {}
    for kf in key_files:
        if kf.exists() and kf.is_file():
            rel = (
                kf.relative_to(repo_dir).as_posix()
                if kf.is_relative_to(repo_dir)
                else kf.name
            )
            file_hashes[rel] = sha256_file(kf)

    return ProvenanceRecord(
        target_name=target_name,
        portable_repository_id=portable_id,
        # The absolute producer path is neither portable evidence nor needed to
        # reproduce the repository coordinate. Keep the field for wire compatibility
        # while serializing the portable root marker instead.
        local_repository_path=".",
        git=git_prov,
        runtime=runtime_env,
        captured_at_utc=captured_at,
        command_executed=command_executed,
        source_file_hashes=file_hashes,
    )

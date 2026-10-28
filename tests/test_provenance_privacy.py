"""Portable provenance must not disclose producer paths or Git credentials."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from verifier.core import provenance
from verifier.core.provenance import capture_provenance


def test_capture_uses_a_portable_repository_root_marker(tmp_path: Path) -> None:
    record = capture_provenance(
        repo_dir=tmp_path,
        target_name="test",
        portable_id="example.invalid/project",
    )

    payload = record.to_dict()
    assert payload["local_repository_path"] == "."
    assert str(tmp_path.resolve()) not in json.dumps(payload)


def test_network_remote_drops_credentials_query_and_fragment() -> None:
    userinfo = "user:secret"
    remote = f"https://{userinfo}@example.invalid/org/project.git?token=secret#private"
    assert provenance.portable_remote_origin(remote) == "https://example.invalid/org/project.git"


def test_scp_remote_drops_the_ssh_user() -> None:
    scp_remote = "@".join(("private-user", "example.invalid:org/project.git"))
    assert provenance.portable_remote_origin(scp_remote) == "ssh://example.invalid/org/project.git"


def test_local_remotes_are_not_serialized() -> None:
    drive_local = ":/".join(("X", "private/project"))
    assert provenance.portable_remote_origin(drive_local) == "LOCAL_REMOTE_REDACTED"
    assert provenance.portable_remote_origin("/private/project") == "LOCAL_REMOTE_REDACTED"
    assert provenance.portable_remote_origin("file:///private/project") == "LOCAL_REMOTE_REDACTED"


@pytest.mark.parametrize("remote", ["", "   "])
def test_an_absent_remote_stays_absent(remote: str) -> None:
    assert provenance.portable_remote_origin(remote) == ""


def test_a_discovered_origin_never_reaches_the_record_with_its_credentials(tmp_path: Path) -> None:
    """The wiring, not only the helper: `git config` returns the raw remote that capture serializes."""
    userinfo = "user:secret"
    raw = f"https://{userinfo}@example.invalid/org/project.git?token=hunter2#private"
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", raw], cwd=tmp_path, check=True, capture_output=True)

    record = capture_provenance(repo_dir=tmp_path, target_name="test", portable_id="example.invalid/project")

    payload = record.to_dict()
    assert payload["git"]["remote_origin"] == "https://example.invalid/org/project.git"
    serialized = json.dumps(payload)
    for leaked in ("secret", "hunter2", "private", str(tmp_path.resolve())):
        assert leaked not in serialized


BACKSLASH = chr(92)


@pytest.mark.parametrize(
    "remote",
    [
        # An explicit id: the generated one would put the credential-shaped remote into the test report.
        pytest.param(
            "https://" + "user:secret" + "@example.invalid:notaport/org/project.git",
            id="credentialed-remote-with-invalid-port",
        ),
        "https://[::1/org/project.git",
    ],
)
def test_a_malformed_network_remote_is_redacted_instead_of_raising(remote: str) -> None:
    assert provenance.portable_remote_origin(remote) == "REMOTE_REDACTED"


def test_a_malformed_remote_does_not_discard_the_rest_of_the_git_record(tmp_path: Path) -> None:
    """A remote the parser cannot read must cost only the remote, not the commit or the branch."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://[::1/org/project.git"],
        cwd=tmp_path, check=True, capture_output=True,
    )

    git = capture_provenance(
        repo_dir=tmp_path, target_name="test", portable_id="example.invalid/project"
    ).to_dict()["git"]

    assert git["remote_origin"] == "REMOTE_REDACTED"
    assert not git["commit_sha"].startswith("ERROR_DISCOVERING_GIT")
    assert git["branch"] != "ERROR"


def test_an_untracked_only_repository_is_dirty_and_retains_the_exact_inventory(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "untracked.txt").write_bytes(b"untracked")

    git = provenance.discover_git_provenance(tmp_path)

    assert git.is_dirty is True
    assert git.dirty_files == ()
    assert git.untracked_files == ("untracked.txt",)


def test_an_ipv6_literal_host_keeps_its_brackets() -> None:
    remote = "https://" + "user:secret" + "@[::1]:8080/org/project.git"
    assert provenance.portable_remote_origin(remote) == "https://[::1]:8080/org/project.git"


def test_rooted_and_network_share_local_remotes_are_not_serialized() -> None:
    rooted = BACKSLASH + "private" + BACKSLASH + "project"
    network_share = BACKSLASH * 2 + "server" + BACKSLASH + "share" + BACKSLASH + "project"
    assert provenance.portable_remote_origin(rooted) == "LOCAL_REMOTE_REDACTED"
    assert provenance.portable_remote_origin(network_share) == "LOCAL_REMOTE_REDACTED"

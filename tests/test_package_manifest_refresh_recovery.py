"""Crash/restart regressions for root-manifest refresh publication.

The child process exits without Python cleanup so these tests exercise the
filesystem state left by a real publisher death rather than an exception path.
JavaScript Object Notation (JSON) journal bytes remain outside the repository.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from verifier.runtime import package_manifest_refresh as refresh


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


_SOURCE = _digest(b"recovery-source")
_MECHANISM = _digest(b"recovery-mechanism")


def _document(*, added: bool = False) -> dict:
    objects = []
    if added:
        objects.append({
            "object_id": "recovery-added-object",
            "kind": "OBJECT",
            "payload": {},
            "reason": "The crash fixture retains one additive object.",
            "surfaces": [],
            "specializations": [],
            "operands": {},
            "classification": {},
            "obligations": {},
        })
    return {
        "schema_version": "verifier-objects-manifest-5",
        "repository": {
            "remote": refresh.VERIFIER_REMOTE,
            "revision": "1" * 40,
        },
        "namespace": {
            "schema_version": "test-namespace",
            "extensions": [],
            "instance_checks": [],
            "consequence_graph": [],
            "objects": objects,
            "execution_checks": [],
        },
        "representation_updates": [],
    }


def _plan(root: Path, *, current: bool = False, source: str = _SOURCE) -> dict:
    target = root / "objects.vstd"
    before = target.read_bytes() if current else refresh._canonical(_document())
    after = before if current else refresh._canonical(_document(added=True))
    binding = {
        "status": "BOUND",
        "opening_census_digest": source,
        "closing_census_digest": source,
        "unavailable": None,
    }
    return refresh._seal_plan({
        "schema_version": refresh.PLAN_SCHEMA,
        "status": "CURRENT" if current else "REFRESH_REQUIRED",
        "root": root.resolve(),
        "target": target.resolve(),
        "before": before,
        "after": after,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
        "source_census_digest": source,
        "source_binding": binding,
        "mechanism_digest": _MECHANISM,
        "target_mode": stat.S_IMODE(target.stat().st_mode),
    })


def _journal_base(root: Path, journal: Path) -> Path:
    key = _digest(str(root.resolve()).encode("utf-8")).removeprefix("sha256:")
    return journal / "manifest-refresh" / key


def _files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _phase_receipts(journal: Path, phase: str) -> list[dict]:
    found = []
    for path in _files(journal):
        if path.suffix != ".json":
            continue
        try:
            value = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        if value.get("phase") == phase:
            found.append(value)
    return found


def _patch_publication_observers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(refresh, "_mechanism_digest", lambda: _MECHANISM)
    monkeypatch.setattr(
        refresh, "_source_coordinate", lambda root: (_SOURCE, {})
    )
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), json.loads(Path(path).read_bytes())),
    )


_CRASH_PROGRAM = r"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, sys.argv[1])
from verifier.runtime import package_manifest_refresh as refresh

root = Path(sys.argv[2])
journal = Path(sys.argv[3])
phase = sys.argv[4]
target = root / "objects.vstd"
digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
source = digest(b"recovery-source")
mechanism = digest(b"recovery-mechanism")

def document(added=False):
    objects = []
    if added:
        objects.append({
            "object_id": "recovery-added-object", "kind": "OBJECT",
            "payload": {},
            "reason": "The crash fixture retains one additive object.",
            "surfaces": [], "specializations": [], "operands": {},
            "classification": {}, "obligations": {},
        })
    return {
        "schema_version": "verifier-objects-manifest-5",
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40},
        "namespace": {
            "schema_version": "test-namespace", "extensions": [],
            "instance_checks": [], "consequence_graph": [], "objects": objects,
            "execution_checks": [],
        },
        "representation_updates": [],
    }

before = refresh._canonical(document())
after = refresh._canonical(document(True))
binding = {
    "status": "BOUND", "opening_census_digest": source,
    "closing_census_digest": source, "unavailable": None,
}
plan = refresh._seal_plan({
    "schema_version": refresh.PLAN_SCHEMA, "status": "REFRESH_REQUIRED",
    "root": root.resolve(), "target": target.resolve(),
    "before": before, "after": after,
    "before_digest": digest(before), "after_digest": digest(after),
    "source_census_digest": source, "source_binding": binding,
    "mechanism_digest": mechanism,
    "target_mode": stat.S_IMODE(target.stat().st_mode),
})
refresh._mechanism_digest = lambda: mechanism
refresh._source_coordinate = lambda root: (source, {})
refresh.namespace_manifest.read_manifest = (
    lambda path: (Path(path).read_bytes(), json.loads(Path(path).read_bytes()))
)

original_replace = refresh.os.replace
if phase == "before_replace":
    refresh.os.replace = lambda source_path, target_path: os._exit(91)
elif phase == "after_replace":
    def crash_after_replace(source_path, target_path):
        original_replace(source_path, target_path)
        os._exit(92)
    refresh.os.replace = crash_after_replace
elif phase == "before_committed":
    original_write = refresh._exclusive_or_equal
    def crash_before_committed(path, raw):
        if Path(path).name == "committed.json":
            os._exit(93)
        return original_write(path, raw)
    refresh._exclusive_or_equal = crash_before_committed
elif phase == "after_committed":
    original_write = refresh._exclusive_or_equal
    def crash_after_committed(path, raw):
        result = original_write(path, raw)
        if Path(path).name == "committed.json":
            os._exit(94)
        return result
    refresh._exclusive_or_equal = crash_after_committed
else:
    raise AssertionError(phase)

refresh.publish_manifest_refresh(plan, journal_root=journal)
raise AssertionError("crash injection did not terminate the publisher")
"""


def _crash_publisher(root: Path, journal: Path, phase: str) -> subprocess.CompletedProcess:
    repository = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            _CRASH_PROGRAM,
            str(repository / "src"),
            str(root),
            str(journal),
            phase,
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize(
    ("phase", "exit_code", "retry_replace_count"),
    (
        ("before_replace", 91, 1),
        ("after_replace", 92, 0),
        ("before_committed", 93, 0),
        ("after_committed", 94, 0),
    ),
)
def test_real_process_crash_retry_is_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    exit_code: int,
    retry_replace_count: int,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical(_document())
    after = refresh._canonical(_document(added=True))
    target.write_bytes(before)
    journal = tmp_path / "external-journal"

    crashed = _crash_publisher(root, journal, phase)

    assert crashed.returncode == exit_code, (crashed.stdout, crashed.stderr)
    assert (_journal_base(root, journal) / "active.lock").is_file()
    assert len([path for path in _files(journal) if path.read_bytes() == before]) == 1

    _patch_publication_observers(monkeypatch)
    fresh = _plan(root, current=phase != "before_replace")
    monkeypatch.setattr(refresh, "inspect_manifest_refresh", lambda selected: fresh)
    replacements = 0
    original_replace = refresh.os.replace

    def counted_replace(source: object, destination: object) -> None:
        nonlocal replacements
        replacements += 1
        original_replace(source, destination)

    monkeypatch.setattr(refresh.os, "replace", counted_replace)
    recovered = refresh.ensure_current_manifest(
        root, mode="auto", journal_root=journal
    )

    assert recovered["status"] == "REMIGRATED"
    assert recovered["directory_durability"] == "NOT_ESTABLISHED"
    assert target.read_bytes() == after
    assert replacements == retry_replace_count
    assert len([path for path in _files(journal) if path.read_bytes() == before]) == 1
    assert len(_phase_receipts(journal, "PREPARED")) == 1
    assert len(_phase_receipts(journal, "COMMITTED")) == 1
    assert len(list(journal.rglob("recovered-lock-*.json"))) == 1
    if phase == "before_replace":
        assert len(_phase_receipts(journal, "ABANDONED_PREPARE")) == 1
    else:
        assert _phase_receipts(journal, "ABANDONED_PREPARE") == []
    assert not (_journal_base(root, journal) / "active.lock").exists()


def _snapshot_files(root: Path) -> list[tuple[str, bytes]]:
    """Capture exact journal bytes without changing the recovery surface."""

    if not root.exists():
        return []
    return [
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in _files(root)
    ]


def test_check_mode_refuses_unresolved_current_transaction_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    after = refresh._canonical(_document(added=True))
    target.write_bytes(refresh._canonical(_document()))
    journal = tmp_path / "external-journal"
    crashed = _crash_publisher(root, journal, "after_replace")
    assert crashed.returncode == 92, (crashed.stdout, crashed.stderr)
    lock = _journal_base(root, journal) / "active.lock"
    assert lock.is_file()

    _patch_publication_observers(monkeypatch)
    monkeypatch.setattr(
        refresh, "inspect_manifest_refresh", lambda selected: _plan(root, current=True)
    )
    target_before = target.read_bytes()
    journal_before = _snapshot_files(journal)

    result = refresh.ensure_current_manifest(
        root, mode="check", journal_root=journal
    )

    assert result["status"] == "UNKNOWN"
    assert result["blockers"] == [
        "MANIFEST_REFRESH_RECOVERY_REQUIRED_READ_ONLY"
    ]
    assert target_before == after == target.read_bytes()
    assert journal_before == _snapshot_files(journal)
    assert lock.is_file()


@pytest.mark.parametrize(
    ("phase", "retry_replace_count"),
    (
        ("before_replace", 1),
        ("after_replace", 0),
        ("before_committed", 0),
        ("after_committed", 0),
    ),
)
def test_keyboard_interrupt_preserves_exactly_once_recovery_across_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    retry_replace_count: int,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical(_document())
    after = refresh._canonical(_document(added=True))
    target.write_bytes(before)
    journal = tmp_path / "external-journal"
    _patch_publication_observers(monkeypatch)
    plan = _plan(root)
    original_replace = refresh.os.replace
    original_write = refresh._exclusive_or_equal

    if phase == "before_replace":
        def interrupt_before_replace(source_path: object, target_path: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(refresh.os, "replace", interrupt_before_replace)
    elif phase == "after_replace":
        def interrupt_after_replace(source_path: object, target_path: object) -> None:
            original_replace(source_path, target_path)
            raise KeyboardInterrupt

        monkeypatch.setattr(refresh.os, "replace", interrupt_after_replace)
    elif phase == "before_committed":
        def interrupt_before_committed(path: Path, raw: bytes) -> None:
            if Path(path).name == "committed.json":
                raise KeyboardInterrupt
            original_write(path, raw)

        monkeypatch.setattr(refresh, "_exclusive_or_equal", interrupt_before_committed)
    elif phase == "after_committed":
        def interrupt_after_committed(path: Path, raw: bytes) -> None:
            original_write(path, raw)
            if Path(path).name == "committed.json":
                raise KeyboardInterrupt

        monkeypatch.setattr(refresh, "_exclusive_or_equal", interrupt_after_committed)
    else:  # pragma: no cover - the parameter set above is closed.
        raise AssertionError(phase)

    with pytest.raises(KeyboardInterrupt):
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    lock = _journal_base(root, journal) / "active.lock"
    assert lock.is_file()
    assert target.read_bytes() == (before if phase == "before_replace" else after)

    monkeypatch.setattr(refresh.os, "replace", original_replace)
    monkeypatch.setattr(refresh, "_exclusive_or_equal", original_write)
    fresh = _plan(root, current=phase != "before_replace")
    monkeypatch.setattr(refresh, "inspect_manifest_refresh", lambda selected: fresh)
    replacements = 0

    def counted_replace(source_path: object, target_path: object) -> None:
        nonlocal replacements
        replacements += 1
        original_replace(source_path, target_path)

    monkeypatch.setattr(refresh.os, "replace", counted_replace)
    recovered = refresh.ensure_current_manifest(
        root, mode="auto", journal_root=journal
    )

    assert recovered["status"] == "REMIGRATED"
    assert target.read_bytes() == after
    assert replacements == retry_replace_count
    assert len(_phase_receipts(journal, "COMMITTED")) == 1
    assert not lock.exists()


def test_committed_receipt_failure_remains_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical(_document())
    after = refresh._canonical(_document(added=True))
    target.write_bytes(before)
    journal = tmp_path / "external-journal"
    _patch_publication_observers(monkeypatch)
    original_write = refresh._exclusive_or_equal

    def fail_committed(path: Path, raw: bytes) -> None:
        if Path(path).name == "committed.json":
            raise refresh.ManifestRefreshError("INJECTED_COMMITTED_WRITE_FAILURE")
        original_write(path, raw)

    monkeypatch.setattr(refresh, "_exclusive_or_equal", fail_committed)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(_plan(root), journal_root=journal)

    assert exc.value.code == "MANIFEST_REFRESH_COMMIT_RECEIPT_UNAVAILABLE"
    lock = _journal_base(root, journal) / "active.lock"
    assert target.read_bytes() == after
    assert lock.is_file()
    assert _phase_receipts(journal, "COMMITTED") == []

    monkeypatch.setattr(refresh, "_exclusive_or_equal", original_write)
    monkeypatch.setattr(
        refresh, "inspect_manifest_refresh", lambda selected: _plan(root, current=True)
    )
    recovered = refresh.ensure_current_manifest(
        root, mode="auto", journal_root=journal
    )

    assert recovered["status"] == "REMIGRATED"
    assert target.read_bytes() == after
    assert len(_phase_receipts(journal, "COMMITTED")) == 1
    assert not lock.exists()


@pytest.mark.parametrize("tamper", ("journal", "target", "source"))
def test_recovery_refuses_tampered_or_ambiguous_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical(_document())
    target.write_bytes(before)
    journal = tmp_path / "external-journal"
    phase = "after_replace" if tamper in {"journal", "target"} else "before_replace"
    crashed = _crash_publisher(root, journal, phase)
    assert crashed.returncode in {91, 92}, (crashed.stdout, crashed.stderr)

    _patch_publication_observers(monkeypatch)
    if tamper == "journal":
        [prepared] = list(journal.rglob("prepared.json"))
        body = json.loads(prepared.read_bytes())
        body["source_census_digest"] = _digest(b"forged-source")
        prepared.write_bytes(refresh._canonical(body))
        fresh = _plan(root, current=True)
        expected = "MANIFEST_REFRESH_RECOVERY_JOURNAL_CONFLICT"
    elif tamper == "target":
        target.write_bytes(refresh._canonical({**_document(added=True), "other": True}))
        fresh = _plan(root, current=True)
        expected = "MANIFEST_REFRESH_RECOVERY_TARGET_AMBIGUOUS"
    else:
        fresh = _plan(root, current=False, source=_digest(b"drifted-source"))
        expected = "MANIFEST_REFRESH_RECOVERY_TRANSACTION_MISMATCH"
    monkeypatch.setattr(refresh, "inspect_manifest_refresh", lambda selected: fresh)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.ensure_current_manifest(root, mode="auto", journal_root=journal)

    assert exc.value.code == expected
    assert exc.value.status == "UNKNOWN"
    assert (_journal_base(root, journal) / "active.lock").is_file()
    assert _phase_receipts(journal, "COMMITTED") == []


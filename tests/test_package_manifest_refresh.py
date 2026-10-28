"""Fail-closed publication tests for automatic root-manifest refresh.

Terminology: JavaScript Object Notation (JSON).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from verifier.runtime import package_manifest_refresh as refresh


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


_CENSUS = "sha256:" + "a" * 64
_OTHER_CENSUS = "sha256:" + "b" * 64


@pytest.fixture(autouse=True)
def _isolated_fixture_git_coordinate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Transaction fixtures use a declared Git coordinate without a checkout."""
    original = refresh.self_polish_estate._git_coordinate

    def selected(root: Path) -> dict[str, str]:
        resolved = Path(root).resolve()
        if resolved == tmp_path or tmp_path in resolved.parents:
            return {"repository": refresh.VERIFIER_REMOTE, "revision": "1" * 40}
        return original(root)

    monkeypatch.setattr(refresh.self_polish_estate, "_git_coordinate", selected)


def test_revision_rebinding_requires_exact_live_repository_and_revision() -> None:
    before = {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."}
    live = {"repository": refresh.VERIFIER_REMOTE, "revision": "2" * 40}
    after = {**before, "revision": live["revision"]}
    assert refresh._exact_revision_rebinding(before, after, live)
    assert not refresh._exact_revision_rebinding(before, after, {**live, "revision": "3" * 40})
    assert not refresh._exact_revision_rebinding(before, {**after, "source_root": "elsewhere"}, live)
    assert not refresh._exact_revision_rebinding(before, {**after, "remote": "other"}, live)
    assert not refresh._exact_revision_rebinding(before, after, {**live, "revision": "invalid"})


def test_refresh_source_coordinate_changes_when_head_changes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    migration = refresh.package_manifest_migration
    census = {"schema_version": "fixture", "selection": "fixture", "git_index_digest": "a",
              "git_status_digest": "b", "files": [], "ignored_scan": {}}
    monkeypatch.setattr(migration.self_polish_estate, "capture_candidate_source_census",
                        lambda *args, **kwargs: census)
    selected = {"repository": refresh.VERIFIER_REMOTE, "revision": "1" * 40}
    monkeypatch.setattr(migration.self_polish_estate, "_git_coordinate", lambda root: dict(selected))
    first, _ = migration.source_refresh_coordinate(tmp_path)
    selected["revision"] = "2" * 40
    second, _ = migration.source_refresh_coordinate(tmp_path)
    assert first != second


def test_refresh_source_coordinate_refuses_head_change_during_capture(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    migration = refresh.package_manifest_migration
    census = {"schema_version": "fixture", "selection": "fixture", "git_index_digest": "a",
              "git_status_digest": "b", "files": [], "ignored_scan": {}}
    monkeypatch.setattr(migration.self_polish_estate, "capture_candidate_source_census",
                        lambda *args, **kwargs: census)
    coordinates = iter(({"repository": refresh.VERIFIER_REMOTE, "revision": "1" * 40},
                        {"repository": refresh.VERIFIER_REMOTE, "revision": "2" * 40}))
    monkeypatch.setattr(migration.self_polish_estate, "_git_coordinate", lambda root: next(coordinates))
    with pytest.raises(refresh.self_polish_estate.EstateError, match="GIT_COORDINATE_INVALID"):
        migration.source_refresh_coordinate(tmp_path)


def test_non_weakening_accepts_only_the_exact_core_harness_graph_upgrade() -> None:
    root = Path(__file__).resolve().parents[1]
    stored = json.loads((root / "objects.vstd").read_text(encoding="utf-8"))
    before = refresh.package_manifest_migration.expand_compact_document(stored)
    retained = next(
        row
        for row in before["objects"]
        if row["object_id"] == "verifier-core-self"
    )
    namespace = next(
        row
        for row in before["namespace"]["objects"]
        if row["object_id"] == "verifier-core-self"
    )
    retained["edges"] = {}
    namespace["operands"] = {}
    after = (
        refresh.package_manifest_migration
        ._upgrade_current_or_pre_verifier_core_harness_binding(before)
    )
    regenerated: list[dict] = []

    refresh._require_non_weakening(before, after, regenerated=regenerated)

    assert regenerated == [
        {
            "stage": "regeneration",
            "gap": "VERIFIER_CORE_HARNESS_BINDING_ADDED",
            "object_id": "verifier-core-self",
            "harness_object_id": "vstd-harness",
        }
    ]


def _bound_binding() -> dict:
    """The public census binding a successful preview attaches to its plan."""

    return {
        "status": "BOUND",
        "opening_census_digest": _CENSUS,
        "closing_census_digest": _CENSUS,
        "unavailable": None,
    }


def _census(digest: str = _CENSUS, *, unavailable: str | None = None) -> dict:
    """One opening or closing source-census capture, shaped like the migration's."""

    if unavailable is not None:
        return {"inventory": None, "census_digest": None, "unavailable": unavailable}
    return {
        "inventory": {"src/verifier/example.py": _digest(b"example")},
        "census_digest": digest,
        "unavailable": None,
    }


def _stub_census(monkeypatch: pytest.MonkeyPatch, *captures: dict) -> list[Path]:
    """Serve successive census captures to one preview and record each root."""

    calls: list[Path] = []
    remaining = list(captures or (_census(), _census()))

    def capture(root: Path) -> dict:
        calls.append(Path(root))
        return dict(remaining.pop(0))

    monkeypatch.setattr(
        refresh.package_manifest_migration, "_capture_source_inventory", capture
    )
    return calls


def _clean_gap_report(
    document: dict,
    *,
    root: Path | None = None,
    source_binding: dict | None = None,
) -> dict:
    """A closed review report that exposes only the public census binding."""

    public = (
        None if source_binding is None
        else {key: value for key, value in source_binding.items() if key != "inventory"}
    )
    return {
        "status": "PASS",
        "unresolved_decision_count": 0,
        "incomplete_obligation_count": 0,
        "unowned_evidence_count": 0,
        "source_binding": public,
    }


def test_source_coordinate_preserves_only_fixed_safe_estate_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_root: Path):
        raise refresh.self_polish_estate.EstateError(
            "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED"
        )

    monkeypatch.setattr(
        refresh.package_manifest_migration, "source_refresh_coordinate", refuse
    )

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._source_coordinate(tmp_path)

    assert exc.value.code == "MANIFEST_REFRESH_SOURCE_UNAVAILABLE"
    assert exc.value.status == "UNKNOWN"
    assert exc.value.details == {
        "source_refusal": "CANDIDATE_SOURCE_FILE_CAPACITY_EXHAUSTED"
    }


def test_source_coordinate_never_reflects_unclassified_or_oserror_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    separator = chr(92)
    private_path = "C:" + separator + "private" + separator + "path"
    messages = iter(("SECRET:" + private_path, private_path))

    def refuse(_root: Path):
        message = next(messages)
        if message.startswith("SECRET"):
            raise refresh.self_polish_estate.EstateError(message)
        raise OSError(message)

    monkeypatch.setattr(
        refresh.package_manifest_migration, "source_refresh_coordinate", refuse
    )

    with pytest.raises(refresh.ManifestRefreshError) as unknown:
        refresh._source_coordinate(tmp_path)
    with pytest.raises(refresh.ManifestRefreshError) as operating_system:
        refresh._source_coordinate(tmp_path)

    assert unknown.value.details == {"source_refusal": "UNCLASSIFIED"}
    assert operating_system.value.details == {}
    assert "private" not in repr(unknown.value.details)
    assert "private" not in repr(operating_system.value.details)


def _compact_namespace_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply only the schema-visible effect of the exact namespace encoder."""

    monkeypatch.setattr(
        refresh.namespace_manifest,
        "compact_manifest",
        lambda value: {
            **value, "schema_version": refresh.namespace_manifest.COMPACT_SCHEMA,
        },
    )


def _plan(root: Path, before: bytes, after: bytes) -> dict:
    target = root / "objects.vstd"
    return refresh._seal_plan({
        "schema_version": refresh.PLAN_SCHEMA,
        "root": root,
        "target": target,
        "before": before,
        "after": after,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
        "source_census_digest": _digest(b"source-census"),
        "mechanism_digest": _digest(b"migration-mechanism"),
        "source_binding": _bound_binding(),
        "status": "CURRENT" if before == after else "REFRESH_REQUIRED",
        "target_mode": stat.S_IMODE(target.stat().st_mode),
    })


def _document(*, objects: list[dict] | None = None) -> dict:
    return {
        "schema_version": "verifier-objects-manifest-5",
        "repository": {
            "remote": refresh.VERIFIER_REMOTE,
            "revision": "1" * 40,
            "source_root": ".",
        },
        "namespace": {
            "schema_version": "test-namespace",
            "extensions": [],
            "instance_checks": [],
            "consequence_graph": [],
            "objects": [] if objects is None else objects,
            "execution_checks": [],
        },
        "representation_updates": [],
    }


def _empty_semantic_profile() -> dict:
    body = {
        "schema_version": refresh.package_manifest_migration.SOURCE_SEMANTIC_PROFILE_SCHEMA,
        "reason": "The test profile binds reviewed source semantics.",
        "binding_sets": [],
        "records": [],
    }
    return {
        **body,
        "digest": refresh.tier_zero_profile.value_digest(body),
    }


def _genuine_plan(root: Path, before_document: dict, after_document: dict) -> dict:
    target = root / "objects.vstd"
    before = refresh._canonical(before_document)
    after = refresh._canonical(after_document)
    return refresh._seal_plan({
        "schema_version": refresh.PLAN_SCHEMA,
        "root": root.resolve(),
        "target": target.resolve(),
        "before": before,
        "after": after,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
        "source_census_digest": _digest(b"source-census"),
        "mechanism_digest": refresh._mechanism_digest(),
        "source_binding": _bound_binding(),
        "status": "CURRENT" if before == after else "REFRESH_REQUIRED",
        "target_mode": stat.S_IMODE(target.stat().st_mode),
    })


def _files(root: Path) -> list[Path]:
    return (
        sorted(path for path in root.rglob("*") if path.is_file())
        if root.exists()
        else []
    )


def _exact_backup_files(journal: Path, expected: bytes) -> list[Path]:
    return [path for path in _files(journal) if path.read_bytes() == expected]


def _journal_base(root: Path, journal: Path) -> Path:
    key = _digest(str(root.resolve()).encode("utf-8")).removeprefix("sha256:")
    return journal / "manifest-refresh" / key


def _receipts_by_phase(journal: Path, phase: str) -> list[dict]:
    receipts = []
    for path in _files(journal):
        if path.suffix != ".json":
            continue
        value = json.loads(path.read_bytes())
        if value.get("phase") == phase:
            receipts.append(value)
    return receipts


def _assert_code(exc: pytest.ExceptionInfo[BaseException], code: str) -> None:
    assert code in str(exc.value)


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"OS_CAPABILITY_GUARD: symlink creation unavailable: {exc}")


@pytest.fixture
def publication_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep transaction tests focused on filesystem publication, not JSON shape."""

    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), {}),
    )
    monkeypatch.setattr(
        refresh,
        "_source_coordinate",
        lambda root: (_digest(b"source-census"), {}),
    )
    monkeypatch.setattr(
        refresh,
        "_mechanism_digest",
        lambda: _digest(b"migration-mechanism"),
    )
    monkeypatch.setattr(refresh, "_require_non_weakening", lambda *args, **kwargs: None)


def test_current_manifest_does_not_write_or_create_backup(
    tmp_path: Path, publication_io: None
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    raw = b'{"schema_version":"test"}\n'
    (root / "objects.vstd").write_bytes(raw)

    receipt = refresh.publish_manifest_refresh(
        _plan(root, raw, raw), journal_root=journal
    )

    assert receipt["status"] == "CURRENT"
    assert receipt["before_digest"] == _digest(raw)
    assert receipt["after_digest"] == _digest(raw)
    assert receipt["backup_digest"] is None
    assert (root / "objects.vstd").read_bytes() == raw
    assert _files(journal) == []


def test_mutating_an_inspected_plan_is_refused_before_any_side_effect(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    before_document = _document()
    after_document = _document(objects=[{"object_id": "new-object"}])
    target = root / "objects.vstd"
    target.write_bytes(refresh._canonical(before_document))
    plan = _genuine_plan(root, before_document, after_document)
    plan["after_digest"] = _digest(b"mutated claim")
    journal = tmp_path / "journal"

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_PLAN_MUTATED")
    assert target.read_bytes() == refresh._canonical(before_document)
    assert _files(journal) == []


def test_resealed_plan_cannot_target_a_file_outside_selected_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    before_document = _document()
    after_document = _document(objects=[{"object_id": "new-object"}])
    target = root / "objects.vstd"
    target.write_bytes(refresh._canonical(before_document))
    external = tmp_path / "outside.vstd"
    external.write_bytes(b"outside remains unchanged\n")
    plan = _genuine_plan(root, before_document, after_document)
    plan["target"] = external
    plan = refresh._seal_plan(plan)
    journal = tmp_path / "journal"

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_PLAN_TARGET_MISMATCH")
    assert external.read_bytes() == b"outside remains unchanged\n"
    assert _files(journal) == []


def test_resealed_plan_still_requires_current_mechanism_and_canonical_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    before_document = _document()
    after_document = _document(objects=[{"object_id": "new-object"}])
    target = root / "objects.vstd"
    target.write_bytes(refresh._canonical(before_document))
    journal = tmp_path / "journal"

    mechanism_plan = _genuine_plan(root, before_document, after_document)
    mechanism_plan["mechanism_digest"] = _digest(b"different mechanism")
    mechanism_plan = refresh._seal_plan(mechanism_plan)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(mechanism_plan, journal_root=journal)
    _assert_code(exc, "MANIFEST_REFRESH_MECHANISM_CHANGED")

    document_plan = _genuine_plan(root, before_document, after_document)
    document_plan["after"] = b'{ "noncanonical":true}\n'
    document_plan["after_digest"] = _digest(document_plan["after"])
    document_plan = refresh._seal_plan(document_plan)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(document_plan, journal_root=journal)
    _assert_code(exc, "MANIFEST_REFRESH_PLAN_DOCUMENT_INVALID")
    assert target.read_bytes() == refresh._canonical(before_document)
    assert _files(journal) == []


def test_resealed_plan_cannot_remove_reviewed_object_contract(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    retained = {
        "object_id": "reviewed-object",
        "kind": "OBJECT",
        "payload": {},
        "reason": "The fixture retains a reviewed object.",
        "surfaces": [],
        "specializations": [],
        "operands": {},
        "classification": {},
        "obligations": {},
    }
    before_document = _document(objects=[retained])
    after_document = _document()
    target = root / "objects.vstd"
    target.write_bytes(refresh._canonical(before_document))
    plan = _genuine_plan(root, before_document, after_document)
    journal = tmp_path / "journal"

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_OBJECT_DROPPED")
    assert target.read_bytes() == refresh._canonical(before_document)
    assert _files(journal) == []


def test_changed_manifest_is_atomically_replaced_with_exact_external_backup(
    tmp_path: Path, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "external-journal"
    before = b'{"version":1}\n'
    after = b'{"version":2}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)

    receipt = refresh.publish_manifest_refresh(
        _plan(root, before, after), journal_root=journal
    )

    assert receipt["status"] == "REMIGRATED"
    assert receipt["before_digest"] == _digest(before)
    assert receipt["after_digest"] == _digest(after)
    assert receipt["backup_digest"] == _digest(before)
    assert receipt["source_census_digest"] == _digest(b"source-census")
    assert receipt["migration_mechanism_digest"] == _digest(
        b"migration-mechanism"
    )
    assert target.read_bytes() == after
    backups = _exact_backup_files(journal, before)
    assert len(backups) == 1
    assert root not in backups[0].parents
    assert not any(path.name.startswith(".vstd-refresh-") for path in _files(root))


def test_publication_does_not_count_its_own_temporary_file_as_a_source_change(
    tmp_path: Path, publication_io: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The census sees every untracked file in the root, including a staged temp."""

    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "external-journal"
    before = b'{"version":1}\n'
    after = b'{"version":2}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")

    def listing(selected_root: Path):
        names = sorted(
            item.name for item in Path(selected_root).iterdir()
            if item.name != "objects.vstd"
        )
        return _digest("\n".join(names).encode("utf-8")), {}

    monkeypatch.setattr(refresh, "_source_coordinate", listing)
    unsealed = {
        key: value for key, value in _plan(root, before, after).items()
        if key != "plan_seal"
    }
    unsealed["source_census_digest"] = listing(root)[0]

    receipt = refresh.publish_manifest_refresh(
        refresh._seal_plan(unsealed), journal_root=journal
    )

    assert receipt["status"] == "REMIGRATED"
    assert target.read_bytes() == after
    assert not any(path.name.startswith(".vstd-refresh-") for path in _files(root))


def test_concurrent_target_change_is_refused_without_overwriting_competing_bytes(
    tmp_path: Path, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    competing = b'{"state":"competing-writer"}\n'
    target = root / "objects.vstd"
    target.write_bytes(competing)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(
            _plan(root, before, after), journal_root=journal
        )

    _assert_code(exc, "MANIFEST_REFRESH_CONCURRENT_CHANGE")
    assert target.read_bytes() == competing
    assert not any(path.name.startswith(".vstd-refresh-") for path in _files(root))


def test_inspection_refuses_checkout_that_differs_from_installed_package(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    root = tmp_path / "repo"
    target = root / "objects.vstd"
    target.parent.mkdir(parents=True)
    shutil.copyfile(repository / "objects.vstd", target)
    selected = root / "src/verifier/runtime/package_manifest_migration.py"
    selected.parent.mkdir(parents=True)
    selected.write_bytes(b"# deliberately not the installed implementation\n")

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_INSTALLED_SOURCE_MISMATCH")
    assert target.read_bytes() == (repository / "objects.vstd").read_bytes()


@pytest.mark.parametrize("unsafe_kind", ("symlink", "directory"))
def test_publication_refuses_nonregular_or_symlink_target(
    tmp_path: Path, unsafe_kind: str, publication_io: None
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    target = root / "objects.vstd"
    external = tmp_path / "external.vstd"
    if unsafe_kind == "symlink":
        external.write_bytes(before)
        _symlink_or_skip(target, external)
    else:
        target.mkdir()

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(
            _plan(root, before, after), journal_root=journal
        )

    _assert_code(exc, "MANIFEST_REFRESH_TARGET_UNSAFE")
    if unsafe_kind == "symlink":
        assert target.is_symlink()
        assert external.read_bytes() == before
    else:
        assert target.is_dir()
    assert _files(journal) == []


def test_replace_failure_removes_temporary_and_preserves_target_and_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_io: None
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)

    def unavailable(source: object, destination: object) -> None:
        raise OSError("injected replacement failure")

    monkeypatch.setattr(refresh.os, "replace", unavailable)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(
            _plan(root, before, after), journal_root=journal
        )

    _assert_code(exc, "MANIFEST_REFRESH_REPLACE_FAILED")
    assert target.read_bytes() == before
    assert len(_exact_backup_files(journal, before)) == 1
    assert not any(path.name.startswith(".vstd-refresh-") for path in _files(root))


def test_existing_transaction_lock_refuses_without_removing_owner_lock(
    tmp_path: Path, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    target.write_bytes(before)
    journal = tmp_path / "journal"
    base = _journal_base(root, journal)
    base.mkdir(parents=True)
    lock = base / "active.lock"
    lock.write_bytes(b"other owner\n")

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(
            _plan(root, before, after), journal_root=journal
        )

    _assert_code(exc, "MANIFEST_REFRESH_TRANSACTION_BUSY")
    assert target.read_bytes() == before
    assert lock.read_bytes() == b"other owner\n"
    assert _receipts_by_phase(journal, "COMMITTED") == []


def test_target_change_during_source_recapture_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    competing = b'{"state":"competing"}\n'
    target.write_bytes(before)
    plan = _plan(root, before, after)
    journal = tmp_path / "journal"

    def recapture(_: Path) -> tuple[str, dict]:
        target.write_bytes(competing)
        return plan["source_census_digest"], {}

    monkeypatch.setattr(refresh, "_source_coordinate", recapture)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_CONCURRENT_CHANGE")
    assert target.read_bytes() == competing
    aborted = _receipts_by_phase(journal, "ABORTED_BEFORE_REPLACE")
    assert len(aborted) == 1
    assert aborted[0]["observed_target_digest"] == _digest(competing)
    assert _receipts_by_phase(journal, "COMMITTED") == []
    assert not any(path.name.startswith(".vstd-refresh-") for path in _files(root))


def test_replace_callback_competitor_is_preserved_and_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    competing = b'{"state":"competing"}\n'
    target.write_bytes(before)
    journal = tmp_path / "journal"

    def competing_then_raise(_: object, destination: object) -> None:
        Path(destination).write_bytes(competing)
        raise OSError("injected competing replacement")

    monkeypatch.setattr(refresh.os, "replace", competing_then_raise)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(
            _plan(root, before, after), journal_root=journal
        )

    _assert_code(exc, "MANIFEST_REFRESH_CONCURRENT_CHANGE")
    assert target.read_bytes() == competing
    aborted = _receipts_by_phase(journal, "ABORTED_COMPETING_TARGET")
    assert len(aborted) == 1
    assert aborted[0]["observed_target_digest"] == _digest(competing)
    assert _receipts_by_phase(journal, "COMMITTED") == []


def test_post_replace_source_drift_records_published_stale_without_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    target.write_bytes(before)
    plan = _plan(root, before, after)
    journal = tmp_path / "journal"
    drift = _digest(b"later-source-census")
    coordinates = iter(
        ((plan["source_census_digest"], {}), (drift, {}))
    )
    monkeypatch.setattr(refresh, "_source_coordinate", lambda _: next(coordinates))

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_PUBLISHED_STALE")
    assert target.read_bytes() == after
    stale = _receipts_by_phase(journal, "PUBLISHED_STALE")
    assert len(stale) == 1
    assert stale[0]["target_mutation_occurred"] is True
    assert stale[0]["observed_target_digest"] == _digest(after)
    assert stale[0]["observed_source_census_digest"] == drift
    assert _receipts_by_phase(journal, "COMMITTED") == []


def test_two_publishers_yield_one_commit_and_one_safe_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication_io: None,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"state":"opening"}\n'
    after = b'{"state":"proposed"}\n'
    target.write_bytes(before)
    plan = _plan(root, before, after)
    journal = tmp_path / "journal"
    barrier = threading.Barrier(2)
    validate = refresh._validate_publish_plan

    def synchronized_validate(value: dict):
        result = validate(value)
        barrier.wait(timeout=5)
        return result

    monkeypatch.setattr(refresh, "_validate_publish_plan", synchronized_validate)

    def publish(_: int):
        try:
            return refresh.publish_manifest_refresh(plan, journal_root=journal)
        except refresh.ManifestRefreshError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, range(2)))

    assert sum(
        type(result) is dict and result.get("status") == "REMIGRATED"
        for result in results
    ) == 1
    assert sum(
        result in {
            "MANIFEST_REFRESH_TRANSACTION_BUSY",
            "MANIFEST_REFRESH_CONCURRENT_CHANGE",
        }
        for result in results
        if type(result) is str
    ) == 1
    assert target.read_bytes() == after
    assert len(_receipts_by_phase(journal, "COMMITTED")) == 1


def test_surface_comparison_accepts_python_location_rebinding_and_addition() -> None:
    prior = [
        "file:src/example.py",
        "python:src/example.py:duplicate@40",
        "html:docs/reference.html:element:100:article",
        "html:docs/reference.html:element:100:article:attribute:0:id",
    ]
    current = [
        "file:src/example.py",
        "python:src/example.py:duplicate@94",
        "html:docs/reference.html:element:100:article",
        "html:docs/reference.html:element:100:article:attribute:0:id",
        "html:docs/reference.html:element:101:p",
    ]

    assert refresh._surfaces_do_not_drop(prior, current)


def test_surface_comparison_keeps_markup_structural_ordinal_identity() -> None:
    prior = ["html:docs/reference.html:element:100:button"]
    moved = ["html:docs/reference.html:element:101:button"]

    assert not refresh._surfaces_do_not_drop(prior, moved)


def test_surface_comparison_refuses_semantic_route_removal() -> None:
    prior = [
        "python:src/example.py:retained",
        "python:src/example.py:removed@40",
    ]
    current = ["python:src/example.py:retained"]

    assert not refresh._surfaces_do_not_drop(prior, current)


def _harness_payload(*, source: str = "a", ast_digest: str = "b",
                     call: str = "c", line: int = 10) -> dict:
    digest = lambda value: "sha256:" + value * 64
    return {
        "representation_role": "Verification harness.",
        "direct_launch_denominator": {
            "schema_version": "verifier-package-harness-launch-denominator-1",
            "profile": "verifier-self-direct-python-launches-1",
            "launches": [{
                "launch_id": "src/example.py|scope=<module>|callee=subprocess.run|ordinal=1",
                "path": "src/example.py",
                "embedded_name": None,
                "source_kind": "python-file",
                "scope": "<module>",
                "callee": "subprocess.run",
                "ordinal": 1,
                "line": line,
                "source_sha256": digest(source),
                "source_ast_sha256": digest(ast_digest),
                "call_sha256": digest(call),
                "necessity_reason": "The selected fixture launch is required.",
                "observation_disposition": "SOURCE_ENUMERATION_ONLY",
                "unobserved_gaps": ["reachability"],
            }],
        },
    }


def test_harness_payload_accepts_exact_source_and_line_rebinding_only() -> None:
    assert refresh._harness_payload_rebinds_source_only(
        _harness_payload(), _harness_payload(source="d", line=40)
    )


@pytest.mark.parametrize(
    "changed",
    (
        _harness_payload(ast_digest="d"),
        _harness_payload(call="d"),
    ),
)
def test_harness_payload_refuses_semantic_rebinding(changed: dict) -> None:
    assert not refresh._harness_payload_rebinds_source_only(
        _harness_payload(), changed
    )


def test_graph_payload_accepts_only_source_coordinate_rebinding() -> None:
    prior = {
        "representation_role": "Complete package graph.",
        "source_refresh_coordinate": "sha256:" + "a" * 64,
        "source_semantic_profile": _empty_semantic_profile(),
    }
    current = {
        **prior,
        "source_refresh_coordinate": "sha256:" + "b" * 64,
    }
    assert refresh._graph_payload_rebinds_source_coordinate_only(prior, current)
    current["representation_role"] = "Changed meaning."
    assert not refresh._graph_payload_rebinds_source_coordinate_only(prior, current)


def test_semantic_profile_accepts_python_comment_change_but_names_code_change(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    source = root / "src/example.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1  # initial comment\n", encoding="utf-8")
    rows = {
        "reviewed-object": {
            "classification": {
                "POLICY": {
                    "status": "DOES_NOT_APPLY",
                    "evidence": [{"path": "src/example.py"}],
                }
            },
            "obligations": {
                "OBJECT-0.1": {
                    "reason": "The reviewed source requires this binding.",
                    "declaration": {},
                    "evidence": [{"path": "src/example.py"}],
                }
            },
        }
    }
    profile = refresh.package_manifest_migration.source_semantic_profile(root, rows)

    source.write_text("\nvalue=1 # moved formatting\n", encoding="utf-8")
    assert refresh._source_semantic_deltas(root, profile) == []

    source.write_text("value = 2\n", encoding="utf-8")
    assert refresh._source_semantic_deltas(root, profile) == [{
        "path": "src/example.py",
        "reason": "SOURCE_SEMANTICS_CHANGED",
        "object_id": "reviewed-object",
        "classifications": ["POLICY"],
        "obligations": ["OBJECT-0.1"],
    }]


def test_parallel_semantic_deltas_are_identical_to_sequential_deltas(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    first = root / "src/first.py"
    second = root / "src/second.py"
    first.parent.mkdir(parents=True)
    first.write_text("value = 1\n", encoding="utf-8")
    second.write_text("value = 2\n", encoding="utf-8")
    rows = {
        "reviewed-object": {
            "classification": {
                "POLICY": {
                    "status": "DOES_NOT_APPLY",
                    "evidence": [
                        {"path": "src/first.py"},
                        {"path": "src/second.py"},
                    ],
                }
            },
            "obligations": {},
        }
    }
    profile = refresh.package_manifest_migration.source_semantic_profile(root, rows)
    second.write_text("value = 3\n", encoding="utf-8")

    monkeypatch.setattr(refresh, "_MAX_SEMANTIC_WORKERS", 1)
    sequential = refresh._source_semantic_deltas(root, profile)
    monkeypatch.setattr(refresh, "_PARALLEL_SEMANTIC_THRESHOLD", 1)
    monkeypatch.setattr(refresh, "_MAX_SEMANTIC_WORKERS", 2)
    parallel = refresh._source_semantic_deltas(root, profile)

    assert parallel == sequential


def test_parallel_semantic_profile_is_identical_to_sequential_profile(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    first = root / "src/first.py"
    second = root / "src/second.py"
    first.parent.mkdir(parents=True)
    first.write_text("value = 1\n", encoding="utf-8")
    second.write_text("value = 2\n", encoding="utf-8")
    rows = {
        "reviewed-object": {
            "classification": {
                "POLICY": {
                    "status": "DOES_NOT_APPLY",
                    "evidence": [
                        {"path": "src/first.py"},
                        {"path": "src/second.py"},
                    ],
                }
            },
            "obligations": {},
        }
    }
    migration = refresh.package_manifest_migration
    monkeypatch.setattr(migration, "_MAX_SEMANTIC_PROFILE_WORKERS", 1)
    sequential = migration.source_semantic_profile(root, rows)
    monkeypatch.setattr(migration, "_PARALLEL_SEMANTIC_PROFILE_THRESHOLD", 1)
    monkeypatch.setattr(migration, "_MAX_SEMANTIC_PROFILE_WORKERS", 2)
    parallel = migration.source_semantic_profile(root, rows)

    assert parallel == sequential


def test_mechanism_digest_binds_transitive_installed_provider_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventories = iter((
        {"runtime/review.py": _digest(b"before")},
        {"runtime/review.py": _digest(b"after")},
    ))
    monkeypatch.setattr(refresh, "_package_inventory", lambda root: next(inventories))

    before = refresh._mechanism_digest()
    after = refresh._mechanism_digest()

    assert before != after


def test_matching_source_coordinate_skips_full_remigration(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    raw = b'{"selected":"fixture"}\n'
    target.write_bytes(raw)
    coordinate = "sha256:" + "c" * 64
    document = {
        "schema_version": refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        "repository": {
            "remote": refresh.VERIFIER_REMOTE,
            "revision": "1" * 40,
            "source_root": ".",
        },
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": coordinate},
        }]},
    }
    selected: list[dict] = []
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(refresh, "_source_coordinate", lambda root: (coordinate, {}))
    monkeypatch.setattr(
        refresh.package_manifest,
        "select",
        lambda value, **kwargs: selected.append(value),
    )
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "refresh_selected_manifest",
        lambda *args, **kwargs: pytest.fail("matching census must skip remigration"),
    )

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "CURRENT"
    assert plan["before"] == plan["after"] == raw
    assert selected == [document]


def test_matching_source_coordinate_is_recaptured_before_current(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    raw = b'{"selected":"fixture"}\n'
    target.write_bytes(raw)
    opening = "sha256:" + "c" * 64
    changed = "sha256:" + "d" * 64
    document = {
        "schema_version": refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."},
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": opening},
        }]},
    }
    coordinates = iter(((opening, {}), (changed, {})))
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(refresh, "_source_coordinate", lambda root: next(coordinates))
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "refresh_selected_manifest",
        lambda *args, **kwargs: pytest.fail("matching opening census must use fast path"),
    )

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_CONCURRENT_CHANGE")
    assert target.read_bytes() == raw


def test_source_coordinate_drift_runs_one_full_preview(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"selected":"before"}\n'
    after = b'{"selected":"after"}\n'
    target.write_bytes(before)
    current_coordinate = "sha256:" + "e" * 64
    document = {
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."},
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": "sha256:" + "f" * 64},
        }]},
    }
    migrated = _compact_candidate(current_coordinate)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *args, **kwargs: None)
    previews: list[Path] = []
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    profile = _empty_semantic_profile()
    monkeypatch.setattr(
        refresh, "_selected_source_semantic_profile", lambda document: profile
    )
    monkeypatch.setattr(refresh, "_source_semantic_deltas", lambda *args: [])
    monkeypatch.setattr(
        refresh, "_semantic_profile_transition_deltas", lambda *args: []
    )
    monkeypatch.setattr(
        refresh, "_source_coordinate", lambda root: (current_coordinate, {})
    )
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "refresh_selected_manifest",
        lambda selected_root, selected: previews.append(selected_root) or migrated,
    )
    monkeypatch.setattr(refresh, "_canonical", lambda value: after)
    monkeypatch.setattr(refresh.tier_zero_manifest, "_strict_json_document", lambda raw: None)
    monkeypatch.setattr(refresh, "_require_non_weakening", lambda before, after, **kwargs: None)
    _stub_census(monkeypatch)
    monkeypatch.setattr(
        refresh.package_manifest_migration, "_review_gap_report", _clean_gap_report
    )

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["before"] == before and plan["after"] == after
    assert previews == [root.resolve()]
    assert target.read_bytes() == before


_DRIFT_BEFORE = b'{"selected":"before"}\n'
_STALE_COORDINATE = "sha256:" + "f" * 64
_CURRENT_COORDINATE = "sha256:" + "e" * 64


def _compact_candidate(
        coordinate: str,
        *,
        schema: str = refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
) -> dict:
    return {
        "schema_version": schema,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."},
        "namespace": {
            "schema_version": "test-namespace",
            "objects": [{
                "object_id": "vstd-package-graph",
                "payload": {"source_refresh_coordinate": coordinate},
            }],
        },
        "representation_updates": [],
    }


def _drift_inspection(
        root: Path, monkeypatch: pytest.MonkeyPatch, migrated: dict | None,
        *,
        stale: str = _STALE_COORDINATE,
        schema: str = refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        before: bytes = _DRIFT_BEFORE,
) -> Path:
    """Replay one stale-source inspection whose candidate is supplied verbatim."""

    target = root / "objects.vstd"
    target.write_bytes(before)
    document = {
        "schema_version": schema,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."},
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": stale},
        }]},
    }
    profile = _empty_semantic_profile()
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(
        refresh, "_selected_source_semantic_profile", lambda value: profile
    )
    monkeypatch.setattr(refresh, "_source_semantic_deltas", lambda *args: [])
    monkeypatch.setattr(
        refresh, "_semantic_profile_transition_deltas", lambda *args: []
    )
    monkeypatch.setattr(
        refresh, "_source_coordinate", lambda root: (_CURRENT_COORDINATE, {})
    )
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "refresh_selected_manifest",
        lambda selected_root, selected: migrated,
    )
    monkeypatch.setattr(refresh, "_require_non_weakening", lambda *args, **kwargs: None)
    _stub_census(monkeypatch)
    monkeypatch.setattr(
        refresh.package_manifest_migration, "_review_gap_report", _clean_gap_report
    )
    return target


def test_matching_census_with_stale_revision_still_plans_rebind(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    _drift_inspection(root, monkeypatch, migrated, stale=_CURRENT_COORDINATE)
    live = {"repository": refresh.VERIFIER_REMOTE, "revision": "2" * 40}
    monkeypatch.setattr(refresh.self_polish_estate, "_git_coordinate", lambda root: live)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *args, **kwargs: None)

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert json.loads(plan["after"])["repository"]["revision"] == live["revision"]
    assert (root / "objects.vstd").read_bytes() == _DRIFT_BEFORE


def test_drift_candidate_must_be_compact_v6_before_publication(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    # Neither inline nor compact: an unrelated transport must still be refused.
    migrated = _compact_candidate(
        _CURRENT_COORDINATE,
        schema="verifier-objects-manifest-4",
    )
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_CANDIDATE_NOT_COMPACT_V6")
    assert exc.value.status == "FAIL"
    assert target.read_bytes() == _DRIFT_BEFORE


def test_drift_candidate_must_bind_the_opening_source_coordinate(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate("sha256:" + "9" * 64)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_CANDIDATE_UNBOUND")
    assert exc.value.status == "FAIL"
    assert target.read_bytes() == _DRIFT_BEFORE


def test_drift_candidate_must_be_admitted_by_the_package_selector(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)

    def rejects(*args: object, **kwargs: object) -> None:
        raise ValueError("NAMESPACE_MANIFEST_INVALID")

    monkeypatch.setattr(refresh.package_manifest, "select", rejects)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_CANDIDATE_INCOMPLETE")
    assert exc.value.status == "FAIL"
    assert target.read_bytes() == _DRIFT_BEFORE


def test_bound_compact_candidate_is_planned_without_writing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["before"] == _DRIFT_BEFORE
    assert plan["after"] == refresh._canonical(migrated)
    assert plan["source_census_digest"] == _CURRENT_COORDINATE
    assert target.read_bytes() == _DRIFT_BEFORE


def test_source_change_during_candidate_generation_refuses_without_writing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    coordinates = iter((
        (_CURRENT_COORDINATE, {}),
        ("sha256:" + "8" * 64, {}),
    ))
    monkeypatch.setattr(refresh, "_source_coordinate", lambda root: next(coordinates))

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_CONCURRENT_CHANGE")
    assert target.read_bytes() == _DRIFT_BEFORE


_REFUSAL_CHAIN = (
    "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:VALIDATOR_FAILED:repository_assets:"
    "validate_source_partition:ValueError:REPOSITORY_ASSET_ORIGINAL_KIND_OWNED_CONTENT_DRIFT:"
    "vstd-generated-distribution-metadata"
)


@pytest.mark.parametrize(
    ("problem", "details"),
    (
        (OSError("C:" "/private/arbitrary-provider-message"), {"cause_type": "OSError"}),
        (RuntimeError("runtime-controlled-message"), {"cause_type": "RuntimeError"}),
        (TypeError("type-controlled-message"), {"cause_type": "TypeError"}),
        # A ValueError whose whole message is a stable refusal code is named ...
        (
            ValueError("PACKAGE_MIGRATION_SYNTHETIC_FAILURE"),
            {"cause_type": "ValueError", "cause": "PACKAGE_MIGRATION_SYNTHETIC_FAILURE"},
        ),
        # ... and so is a nested refusal chain of codes and identifiers, which is how
        # catalog validators wrap the refusal that actually needs action.
        (
            ValueError(_REFUSAL_CHAIN),
            {"cause_type": "ValueError", "cause": _REFUSAL_CHAIN},
        ),
        # ... free text, paths and mixed-case prose never are.
        (ValueError("C:" "/private/free text"), {"cause_type": "ValueError"}),
        (ValueError("Mixed case message"), {"cause_type": "ValueError"}),
        (ValueError("PACKAGE_X_FAILED:/private/absolute"), {"cause_type": "ValueError"}),
        (ValueError("PACKAGE_X_FAILED:../escape"), {"cause_type": "ValueError"}),
        (ValueError("PACKAGE_X_FAILED:free text"), {"cause_type": "ValueError"}),
        (ValueError("PACKAGE_X_FAILED:" + "a" * 2048), {"cause_type": "ValueError"}),
    ),
)
def test_migration_failure_is_fail_closed_without_publication(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        problem: Exception, details: dict) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = _drift_inspection(root, monkeypatch, None)

    def fail(*args: object, **kwargs: object) -> None:
        raise problem

    monkeypatch.setattr(
        refresh.package_manifest_migration, "refresh_selected_manifest", fail
    )

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    _assert_code(exc, "MANIFEST_REFRESH_PREVIEW_FAILED")
    assert exc.value.status == "FAIL"
    assert exc.value.details == details
    assert str(problem) not in exc.value.code
    assert target.read_bytes() == _DRIFT_BEFORE


def test_check_mode_refresh_required_is_read_only(
        tmp_path: Path, publication_io: None, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical({
        "schema_version": refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
    })
    after = b'{"selected":"after"}\n'
    target.write_bytes(before)
    plan = _plan(root, before, after)
    monkeypatch.setattr(refresh, "inspect_manifest_refresh", lambda value: plan)
    journal = tmp_path / "journal"

    result = refresh.ensure_current_manifest(root, mode="check", journal_root=journal)

    assert result["status"] == "REFRESH_REQUIRED"
    assert result["blockers"] == ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"]
    assert result["backup_digest"] is None
    assert target.read_bytes() == before
    assert not journal.exists()


def test_default_journal_inside_selected_repository_is_refused_before_side_effects(
        tmp_path: Path, publication_io: None, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = b'{"selected":"before"}\n'
    after = b'{"selected":"after"}\n'
    target.write_bytes(before)
    plan = _plan(root, before, after)
    state = root / "vstd-state"
    monkeypatch.setenv("VSTD_STATE_DIR", str(state))

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan)

    _assert_code(exc, "MANIFEST_REFRESH_JOURNAL_INSIDE_REPOSITORY")
    assert target.read_bytes() == before
    assert not state.exists()


def test_default_journal_root_prefers_explicit_state_directory(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VSTD_STATE_DIR", str(tmp_path / "state"))

    assert refresh._default_journal_root() == tmp_path / "state"


_INLINE_V5_SCHEMA = refresh.package_manifest.PACKAGE_REPRESENTATION_SCHEMA


def test_source_matched_inline_v5_is_refresh_required_not_current(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A matching source census does not certify the inline v5 transport."""

    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(
        root, monkeypatch, migrated,
        stale=_CURRENT_COORDINATE, schema=_INLINE_V5_SCHEMA,
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["before"] == _DRIFT_BEFORE
    assert plan["after"] == refresh._canonical(migrated)
    assert target.read_bytes() == _DRIFT_BEFORE


def test_check_mode_reports_v5_format_upgrade_read_only(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(
        root, monkeypatch, migrated,
        stale=_CURRENT_COORDINATE, schema=_INLINE_V5_SCHEMA,
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    journal = tmp_path / "journal"

    result = refresh.ensure_current_manifest(root, mode="check", journal_root=journal)

    assert result["status"] == "REFRESH_REQUIRED"
    assert result["backup_digest"] is None
    assert result["blockers"] == [
        "MANIFEST_REFRESH_REQUIRED_READ_ONLY",
        "MANIFEST_REFRESH_FORMAT_UPGRADE_REQUIRED",
    ]
    assert target.read_bytes() == _DRIFT_BEFORE
    assert not journal.exists()


def test_check_mode_reports_no_format_reason_for_compact_source_drift(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    _drift_inspection(
        root, monkeypatch, migrated,
        before=refresh._canonical(_compact_candidate(_STALE_COORDINATE)),
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    result = refresh.ensure_current_manifest(
        root, mode="check", journal_root=tmp_path / "journal",
    )

    assert result["status"] == "REFRESH_REQUIRED"
    assert result["blockers"] == ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"]


def test_auto_mode_upgrades_source_matched_v5_exactly_once(
        tmp_path: Path, publication_io: None, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    before = refresh._canonical({
        "schema_version": _INLINE_V5_SCHEMA,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40, "source_root": "."},
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": _CURRENT_COORDINATE},
        }]},
        "representation_updates": [],
    })
    target.write_bytes(before)
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    expected_after = refresh._canonical(migrated)
    profile = _empty_semantic_profile()
    previews: list[Path] = []
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (
            Path(path).read_bytes(),
            json.loads(Path(path).read_bytes()),
        ),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(
        refresh, "_source_coordinate", lambda root: (_CURRENT_COORDINATE, {})
    )
    monkeypatch.setattr(
        refresh, "_selected_source_semantic_profile", lambda value: profile
    )
    monkeypatch.setattr(refresh, "_source_semantic_deltas", lambda *args: [])
    monkeypatch.setattr(
        refresh, "_semantic_profile_transition_deltas", lambda *args: []
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "refresh_selected_manifest",
        lambda selected_root, selected: previews.append(selected_root) or migrated,
    )
    _stub_census(monkeypatch)
    monkeypatch.setattr(
        refresh.package_manifest_migration, "_review_gap_report", _clean_gap_report
    )
    journal = tmp_path / "journal"

    first = refresh.ensure_current_manifest(root, mode="auto", journal_root=journal)

    assert first["status"] == "REMIGRATED"
    assert previews == [root.resolve()]
    assert target.read_bytes() == expected_after
    assert len(_exact_backup_files(_journal_base(root, journal) / "backups", before)) == 1
    journal_after_publish = _files(journal)

    second = refresh.ensure_current_manifest(root, mode="auto", journal_root=journal)

    assert second["status"] == "CURRENT"
    assert previews == [root.resolve()]
    assert target.read_bytes() == expected_after
    assert _files(journal) == journal_after_publish


def test_small_inline_v5_root_is_emitted_as_compact_v6(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A small root must not stay inline forever: refresh emits compact v6."""

    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE, schema=_INLINE_V5_SCHEMA)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    _compact_namespace_stub(monkeypatch)
    expected = _compact_candidate(_CURRENT_COORDINATE)
    expected["namespace"]["schema_version"] = refresh.namespace_manifest.COMPACT_SCHEMA

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["after"] == refresh._canonical(expected)
    assert json.loads(plan["after"])["schema_version"] == (
        refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
    )
    assert target.read_bytes() == _DRIFT_BEFORE


def test_inline_v5_candidate_that_cannot_compact_leaves_original_bytes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE, schema=_INLINE_V5_SCHEMA)
    target = _drift_inspection(
        root, monkeypatch, migrated,
        stale=_CURRENT_COORDINATE, schema=_INLINE_V5_SCHEMA,
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)

    def cannot_compact(value: dict) -> dict:
        raise ValueError("NAMESPACE_MANIFEST_STRUCTURE_CAPACITY")

    monkeypatch.setattr(refresh.namespace_manifest, "compact_manifest", cannot_compact)
    journal = tmp_path / "journal"

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.ensure_current_manifest(root, mode="auto", journal_root=journal)

    _assert_code(exc, "MANIFEST_REFRESH_PREVIEW_FAILED")
    assert exc.value.status == "FAIL"
    assert exc.value.details == {
        "cause_type": "ValueError",
        "cause": "NAMESPACE_MANIFEST_STRUCTURE_CAPACITY",
    }
    assert target.read_bytes() == _DRIFT_BEFORE
    assert not journal.exists()


def test_refresh_preview_binds_the_census_it_opens_and_closes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    calls = _stub_census(monkeypatch, _census(), _census())
    bindings: list[dict | None] = []

    roots: list[Path | None] = []

    def record(
        document: dict,
        *,
        root: Path | None = None,
        source_binding: dict | None = None,
    ) -> dict:
        roots.append(root)
        bindings.append(source_binding)
        return _clean_gap_report(
            document, root=root, source_binding=source_binding
        )

    monkeypatch.setattr(refresh.package_manifest_migration, "_review_gap_report", record)

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "REFRESH_REQUIRED"
    assert calls == [root.resolve(), root.resolve()]
    assert roots == [root.resolve()]
    assert bindings[0] is not None and bindings[0]["status"] == "BOUND"
    assert plan["source_binding"] == _bound_binding()
    assert target.read_bytes() == _DRIFT_BEFORE


@pytest.mark.parametrize(
    ("captures", "code"),
    [
        (
            (_census(unavailable="PACKAGE_MIGRATION_SOURCE_INVENTORY_UNAVAILABLE:OSError"),),
            "MANIFEST_REFRESH_SOURCE_INVENTORY_UNAVAILABLE",
        ),
        (
            (_census(_CENSUS), _census(_OTHER_CENSUS)),
            "MANIFEST_REFRESH_SOURCE_INVENTORY_MUTATED",
        ),
        (
            (
                _census(_CENSUS),
                _census(unavailable="PACKAGE_MIGRATION_SOURCE_INVENTORY_UNAVAILABLE:OSError"),
            ),
            "MANIFEST_REFRESH_SOURCE_INVENTORY_CLOSING_UNAVAILABLE",
        ),
    ],
)
def test_unbound_source_census_refuses_before_any_candidate_write(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        captures: tuple[dict, ...], code: str) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    _stub_census(monkeypatch, *captures)
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "_review_gap_report",
        lambda *a, **k: pytest.fail("an unbound census must not reach review"),
    )
    journal = tmp_path / "journal"

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.ensure_current_manifest(root, mode="auto", journal_root=journal)

    assert exc.value.code == code
    assert exc.value.status == "UNKNOWN"
    assert target.read_bytes() == _DRIFT_BEFORE
    assert not journal.exists()


def test_stable_bytes_never_consult_the_source_census(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CURRENT bytes are certified by the coordinate alone: no census, no ABSENT."""

    root = tmp_path / "repo"
    root.mkdir()
    raw = refresh._canonical(_compact_candidate(_CURRENT_COORDINATE))
    target = root / "objects.vstd"
    target.write_bytes(raw)
    document = json.loads(raw)
    monkeypatch.setattr(
        refresh.namespace_manifest,
        "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(refresh, "_source_coordinate", lambda root: (_CURRENT_COORDINATE, {}))
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "_capture_source_inventory",
        lambda root: pytest.fail("stable bytes must not capture the census"),
    )

    plan = refresh.inspect_manifest_refresh(root)

    assert plan["status"] == "CURRENT"
    assert "source_binding" not in plan


def test_non_passing_review_closure_refuses_even_without_counted_gaps(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    migrated = _compact_candidate(_CURRENT_COORDINATE)
    target = _drift_inspection(root, monkeypatch, migrated)
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    monkeypatch.setattr(
        refresh.package_manifest_migration,
        "_review_gap_report",
        lambda *a, **k: {
            "status": "UNKNOWN",
            "unresolved_decision_count": 0,
            "incomplete_obligation_count": 0,
            "unowned_evidence_count": 0,
        },
    )

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)

    assert exc.value.code == "MANIFEST_REFRESH_REVIEW_GAPS_REMAIN"
    assert exc.value.status == "UNKNOWN"
    assert target.read_bytes() == _DRIFT_BEFORE


@pytest.mark.parametrize(
    "binding",
    [
        None,
        {
            "status": "MUTATED",
            "opening_census_digest": _CENSUS,
            "closing_census_digest": _OTHER_CENSUS,
            "unavailable": None,
        },
    ],
)
def test_publish_refuses_refresh_plan_without_a_bound_census(
        tmp_path: Path, publication_io: None,
        binding: dict | None) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    before = b'{"version":1}\n'
    after = b'{"version":2}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)
    plan = _plan(root, before, after)
    if binding is None:
        plan.pop("source_binding")
    else:
        plan["source_binding"] = binding
    plan = refresh._seal_plan(plan)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=journal)

    assert exc.value.code == "MANIFEST_REFRESH_PLAN_SOURCE_UNBOUND"
    assert exc.value.status == "FAIL"
    assert target.read_bytes() == before
    assert not journal.exists()


def test_plan_seal_covers_the_census_binding(
        tmp_path: Path, publication_io: None) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    before = b'{"version":1}\n'
    after = b'{"version":2}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)
    plan = _plan(root, before, after)
    plan["source_binding"] = {**plan["source_binding"], "status": "MUTATED"}

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.publish_manifest_refresh(plan, journal_root=tmp_path / "journal")

    assert exc.value.code == "MANIFEST_REFRESH_PLAN_MUTATED"
    assert target.read_bytes() == before


def test_committed_journal_records_the_bound_census_not_the_public_receipt(
        tmp_path: Path, publication_io: None) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    journal = tmp_path / "journal"
    before = b'{"version":1}\n'
    after = b'{"version":2}\n'
    target = root / "objects.vstd"
    target.write_bytes(before)
    plan = _plan(root, before, after)

    receipt = refresh.publish_manifest_refresh(plan, journal_root=journal)

    assert "source_binding" not in receipt
    [prepared] = _receipts_by_phase(journal, "PREPARED")
    [committed] = _receipts_by_phase(journal, "COMMITTED")
    assert prepared["source_binding"] == plan["source_binding"]
    assert committed["source_binding"] == plan["source_binding"]


def _graph_commitment_rows(commitments: dict) -> dict:
    """Final expanded rows: the package root over three members with two edges."""

    def member(object_id: str, operands: dict) -> dict:
        return {
            "object_id": object_id,
            "kind": "OBJECT",
            "specializations": [],
            "payload": {"representation_role": "Synthetic member " + object_id},
            "operands": operands,
            "surfaces": [],
            "reason": "Synthetic member.",
            "classification": {},
            "obligations": {},
        }

    return {
        "vstd-package-graph": {
            "object_id": "vstd-package-graph",
            "kind": "GRAPH",
            "specializations": [],
            "payload": {
                "element_kind": "OBJECT",
                "scope": "retained_directed_graph",
                **commitments,
                "source_refresh_coordinate": "sha256:" + "c" * 64,
            },
            "operands": {"members": ["a", "b", "c"]},
            "surfaces": [],
            "reason": "Synthetic package root.",
            "classification": {},
            "obligations": {},
        },
        "a": member("a", {"uses": ["b", "c"]}),
        "b": member("b", {"uses": ["c"]}),
        "c": member("c", {}),
    }


_STALE_COMMITMENTS = {
    "nodes_digest": "sha256:" + "0" * 64,
    "edges_digest": "sha256:" + "1" * 64,
}


def test_derived_graph_commitments_follow_the_final_rows() -> None:
    rows = _graph_commitment_rows(_STALE_COMMITMENTS)

    derived = refresh._derived_graph_commitments(rows)

    assert set(derived) == {"nodes_digest", "edges_digest"}
    assert all(
        value.startswith("sha256:") and len(value) == 71 for value in derived.values()
    )
    assert derived != _STALE_COMMITMENTS
    # The derivation reads the rows; it never edits the caller's declaration.
    assert rows["vstd-package-graph"]["payload"]["nodes_digest"] == (
        _STALE_COMMITMENTS["nodes_digest"]
    )
    # An incomplete member list cannot be projected, so nothing is derived.
    rows["vstd-package-graph"]["operands"]["members"].remove("c")
    assert refresh._derived_graph_commitments(rows) is None


def test_derived_graph_commitments_are_absent_without_a_declared_commitment() -> None:
    assert refresh._derived_graph_commitments(_graph_commitment_rows({})) is None


def test_graph_payload_accepts_only_the_exactly_rederived_dependency_commitments() -> None:
    rows = _graph_commitment_rows(_STALE_COMMITMENTS)
    derived = refresh._derived_graph_commitments(rows)
    prior = {
        "element_kind": "OBJECT",
        "scope": "retained_directed_graph",
        **_STALE_COMMITMENTS,
        "source_refresh_coordinate": "sha256:" + "a" * 64,
        "source_semantic_profile": _empty_semantic_profile(),
    }
    current = {**prior, **derived, "source_refresh_coordinate": "sha256:" + "b" * 64}

    # Without the derivation a changed commitment is still a changed meaning.
    assert not refresh._graph_payload_rebinds_source_coordinate_only(prior, current)
    assert refresh._graph_payload_rebinds_source_coordinate_only(
        prior, current, derived_commitments=derived
    )
    # Only the exact derived value is accepted; a forged commitment is refused.
    forged = {**current, "nodes_digest": "sha256:" + "f" * 64}
    assert not refresh._graph_payload_rebinds_source_coordinate_only(
        prior, forged, derived_commitments=derived
    )
    # The allowance never widens to any other field of the payload.
    widened = {**current, "scope": "another_scope"}
    assert not refresh._graph_payload_rebinds_source_coordinate_only(
        prior, widened, derived_commitments=derived
    )
    # An unchanged payload stays unchanged whatever it declares.
    unchanged = {**prior, "source_refresh_coordinate": "sha256:" + "b" * 64}
    assert refresh._graph_payload_rebinds_source_coordinate_only(
        prior, unchanged, derived_commitments=derived
    )

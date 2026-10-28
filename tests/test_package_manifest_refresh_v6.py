"""Exact semantic gates for version-5/version-6 refresh transport changes."""

from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from verifier.runtime import namespace_manifest
from verifier.runtime import package_manifest
from verifier.runtime import package_manifest_refresh as refresh
from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


def _reference(path: str, digit: str) -> dict[str, str]:
    return {"path": path, "sha256": "sha256:" + digit * 64}


def _inline_namespace() -> dict:
    registry = namespace_registry()
    evidence = [
        _reference("src/subject.py", "a"),
        _reference("tests/test_subject.py", "b"),
    ]
    return {
        "schema_version": namespace_manifest.SCHEMA,
        "registry_digest": registry_document(registry)["digest"],
        "extensions": [],
        "objects": [{
            "object_id": "subject",
            "kind": "OBJECT",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["subject.route"],
            "reason": "The subject is the bounded object under review.",
            "classification": {
                "OBJECT": {
                    "status": "APPLIES",
                    "reason": "The declared subject is an object.",
                    "evidence": deepcopy(evidence),
                }
            },
            "obligations": {
                "OBJECT-0.1-subject-boundary": {
                    "reason": "The object boundary must remain inspectable.",
                    "declaration": {"contract": "subject.route"},
                    "evidence": deepcopy(evidence),
                }
            },
        }],
    }


def _package(namespace: dict, *, compact: bool) -> dict:
    return {
        "schema_version": (
            package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
            if compact
            else package_manifest.PACKAGE_REPRESENTATION_SCHEMA
        ),
        "repository": {
            "remote": refresh.VERIFIER_REMOTE,
            "revision": "1" * 40,
        },
        "namespace": namespace,
        "representation_updates": [],
    }


def _pair() -> tuple[dict, dict]:
    inline = _inline_namespace()
    return (
        _package(inline, compact=False),
        _package(namespace_manifest.compact_manifest(inline), compact=True),
    )


def test_revision_rebinding_requires_live_coordinate_and_preserves_other_contract_fields() -> None:
    before, _ = _pair()
    before["repository"]["source_root"] = "."
    after = deepcopy(before)
    after["repository"]["revision"] = "2" * 40
    live = {"repository": refresh.VERIFIER_REMOTE, "revision": "2" * 40}
    with pytest.raises(refresh.ManifestRefreshError, match="RETAINED_CONTRACT_CHANGED"):
        refresh._require_non_weakening(before, after)
    refresh._require_non_weakening(before, after, live_repository=live)
    wrong = deepcopy(after)
    wrong["repository"]["source_root"] = "elsewhere"
    with pytest.raises(refresh.ManifestRefreshError, match="RETAINED_CONTRACT_CHANGED"):
        refresh._require_non_weakening(before, wrong, live_repository=live)
    with pytest.raises(refresh.ManifestRefreshError, match="RETAINED_CONTRACT_CHANGED"):
        refresh._require_non_weakening(before, after, live_repository={**live, "revision": "3" * 40})


def test_publication_rechecks_revision_binding(
        tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    before, _ = _pair()
    before["repository"]["source_root"] = "."
    after = deepcopy(before)
    after["repository"]["revision"] = "2" * 40
    live = {"repository": refresh.VERIFIER_REMOTE, "revision": "2" * 40}
    monkeypatch.setattr(refresh.self_polish_estate, "_git_coordinate", lambda root: dict(live))
    refresh._require_plan_non_weakening({"root": tmp_path}, before, after)
    live["revision"] = "3" * 40
    with pytest.raises(refresh.ManifestRefreshError, match="RETAINED_CONTRACT_CHANGED"):
        refresh._require_plan_non_weakening({"root": tmp_path}, before, after)


def _assert_code(document_before: dict, document_after: dict, code: str) -> None:
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(document_before, document_after)
    assert exc.value.code == code
    assert exc.value.status == "FAIL"


def test_v5_v6_transition_is_bidirectional_only_for_exact_semantics() -> None:
    version_5, version_6 = _pair()
    before_5 = deepcopy(version_5)
    before_6 = deepcopy(version_6)

    refresh._require_non_weakening(version_5, version_6)
    refresh._require_non_weakening(version_6, version_5)

    assert version_5 == before_5
    assert version_6 == before_6
    assert namespace_manifest.normalize_manifest(version_6["namespace"]) == (
        version_5["namespace"]
    )


def test_transport_comparison_does_not_replace_exact_byte_digest_provenance() -> None:
    version_5, version_6 = _pair()
    before = canonical_bytes(version_5) + b"\n"
    after = canonical_bytes(version_6) + b"\n"
    before_digest = "sha256:" + hashlib.sha256(before).hexdigest()
    after_digest = "sha256:" + hashlib.sha256(after).hexdigest()

    refresh._require_non_weakening(version_5, version_6)

    assert before != after
    assert before_digest != after_digest
    assert refresh._digest(before) == before_digest
    assert refresh._digest(after) == after_digest


@pytest.mark.parametrize("direction", ("upgrade", "downgrade"))
def test_transition_rejects_semantic_substitution_or_evidence_weakening(
    direction: str,
) -> None:
    version_5, version_6 = _pair()
    changed_inline = _inline_namespace()
    decision = changed_inline["objects"][0]["classification"]["OBJECT"]
    decision["evidence"] = decision["evidence"][:1]
    changed_6 = _package(
        namespace_manifest.compact_manifest(changed_inline), compact=True,
    )

    if direction == "upgrade":
        before, after = version_5, changed_6
    else:
        before, after = version_6, _package(changed_inline, compact=False)
    _assert_code(
        before,
        after,
        "MANIFEST_REFRESH_NAMESPACE_TRANSPORT_SEMANTICS_CHANGED",
    )


def test_transition_rejects_missing_and_unused_evidence_sets_at_exact_gate() -> None:
    version_5, version_6 = _pair()
    missing = deepcopy(version_6)
    missing["namespace"]["objects"][0]["evidence_sets"].clear()
    _assert_code(
        version_5,
        missing,
        "NAMESPACE_COMPACT_EVIDENCE_SET_REFERENCE_MISSING",
    )

    unused = deepcopy(version_6)
    evidence = [_reference("unused.py", "c")]
    unused["namespace"]["objects"][0]["evidence_sets"][
        value_digest(evidence)
    ] = evidence
    _assert_code(
        version_5,
        unused,
        "NAMESPACE_COMPACT_EVIDENCE_SET_UNUSED",
    )


def test_outer_and_nested_transport_versions_must_agree() -> None:
    version_5, version_6 = _pair()
    compact_under_v5 = deepcopy(version_5)
    compact_under_v5["namespace"] = deepcopy(version_6["namespace"])
    _assert_code(version_6, compact_under_v5, "NAMESPACE_MANIFEST_VERSION")


def test_unrelated_outer_schema_change_remains_refused() -> None:
    version_5, _ = _pair()
    unrelated = deepcopy(version_5)
    unrelated["schema_version"] = package_manifest.REPRESENTATION_SCHEMA
    _assert_code(version_5, unrelated, "MANIFEST_REFRESH_SCHEMA_CHANGED")


def _grown_pair() -> tuple[dict, dict]:
    """A v5 root and a v6 candidate that also gained an object and a reopened cell."""

    version_5, _ = _pair()
    grown = _inline_namespace()
    extra = deepcopy(grown["objects"][0])
    extra["object_id"] = "added-subject"
    extra["surfaces"] = ["added.route"]
    grown["objects"].append(extra)
    return version_5, _package(namespace_manifest.compact_manifest(grown), compact=True)


def test_strict_policy_still_refuses_new_content_across_a_transport_switch() -> None:
    version_5, grown_6 = _grown_pair()
    _assert_code(
        version_5,
        grown_6,
        "MANIFEST_REFRESH_NAMESPACE_TRANSPORT_SEMANTICS_CHANGED",
    )


def test_recording_policy_allows_growth_across_a_transport_switch() -> None:
    version_5, grown_6 = _grown_pair()
    before = deepcopy(version_5)
    after = deepcopy(grown_6)

    refresh._require_non_weakening(version_5, grown_6, reopened={})

    assert version_5 == before
    assert grown_6 == after


def test_recording_policy_still_compares_every_unreopened_cell() -> None:
    version_5, _ = _pair()
    weakened = _inline_namespace()
    decision = weakened["objects"][0]["classification"]["OBJECT"]
    decision["evidence"] = decision["evidence"][:1]
    weakened_6 = _package(namespace_manifest.compact_manifest(weakened), compact=True)

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(version_5, weakened_6, reopened={})

    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def test_recording_policy_exempts_only_the_reopened_cell_across_a_switch() -> None:
    version_5, _ = _pair()
    reopened = _inline_namespace()
    decision = reopened["objects"][0]["classification"]["OBJECT"]
    decision["status"] = "UNRESOLVED"
    decision["evidence"] = []
    reopened_6 = _package(namespace_manifest.compact_manifest(reopened), compact=True)

    refresh._require_non_weakening(
        version_5,
        reopened_6,
        reopened={"subject": (frozenset({"OBJECT"}), frozenset())},
    )
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(version_5, reopened_6, reopened={})

    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def test_review_gap_report_reads_a_compact_document_like_its_inline_form() -> None:
    from verifier.runtime import package_manifest_migration

    version_5, version_6 = _pair()
    decision = version_6["namespace"]["objects"][0]["classification"]["OBJECT"]
    assert "evidence" not in decision

    inline = package_manifest_migration._review_gap_report(version_5)
    compact = package_manifest_migration._review_gap_report(version_6)

    assert inline["unowned_evidence_count"] > 0
    assert compact == inline


def test_expanded_document_turns_a_compact_root_back_into_its_inline_form() -> None:
    from verifier.runtime import package_manifest_migration

    version_5, version_6 = _pair()
    before = deepcopy(version_6)

    expanded = package_manifest_migration.expand_compact_document(version_6)

    assert expanded == version_5
    assert version_6 == before, "expansion must not mutate the stored document"
    assert package_manifest_migration.expand_compact_document(version_5) is version_5


def test_refresh_hands_the_migration_an_expanded_root(monkeypatch) -> None:
    """The reviewed-answer gates read evidence arrays, which a compact root only points at."""
    from verifier.runtime import package_manifest_migration as migration

    version_5, version_6 = _pair()
    seen: list[dict] = []
    monkeypatch.setattr(migration, "selected_refresh_options",
                        lambda document: {"select_source_semantic_profile": False})
    monkeypatch.setattr(migration, "migrate",
                        lambda root, document, **options: seen.append(document) or document)

    migration.refresh_selected_manifest(None, version_6, record_review_gaps=True,
                                        review_gaps=[], source_deltas=[])

    assert seen == [version_5]

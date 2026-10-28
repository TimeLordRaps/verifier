"""Polish may record review gaps while refreshing; the default still refuses them."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from verifier.runtime import package_manifest_refresh as refresh

_CENSUS = "sha256:" + "a" * 64
_CURRENT = "sha256:" + "e" * 64
_STALE = "sha256:" + "f" * 64
_BEFORE = b'{"selected":"before"}\n'
_AFTER = b'{"selected":"after"}\n'

_DELTA = {
    "path": "src/changed.py",
    "reason": "SOURCE_SEMANTICS_CHANGED",
    "object_id": "vstd-owner",
    "classifications": ["POLICY"],
    "obligations": ["POLICY-0.1-scope"],
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _candidate() -> dict:
    return {
        "schema_version": refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40},
        "namespace": {
            "schema_version": "test-namespace",
            "objects": [{
                "object_id": "vstd-package-graph",
                "payload": {"source_refresh_coordinate": _CURRENT},
            }],
        },
        "representation_updates": [],
    }


def _profile() -> dict:
    body = {
        "schema_version": refresh.package_manifest_migration.SOURCE_SEMANTIC_PROFILE_SCHEMA,
        "reason": "The test profile binds reviewed source semantics.",
        "binding_sets": [],
        "records": [],
    }
    return {**body, "digest": refresh.tier_zero_profile.value_digest(body)}


def _census(digest: str = _CENSUS) -> dict:
    return {
        "inventory": {"src/verifier/example.py": _digest(b"example")},
        "census_digest": digest,
        "unavailable": None,
    }


class _Spy:
    """Records how the refresh was driven so the two policies can be compared."""

    def __init__(self) -> None:
        self.generated: list[tuple[tuple, dict]] = []
        self.weakening: list[tuple[tuple, dict]] = []


def _inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    deltas: list[dict],
    transition: list[dict] | None = None,
    gap_report: dict | None = None,
    gaps_to_record: list[dict] | None = None,
) -> tuple[Path, _Spy]:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "objects.vstd"
    target.write_bytes(_BEFORE)
    document = {
        "schema_version": refresh.package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40},
        "namespace": {"objects": [{
            "object_id": "vstd-package-graph",
            "payload": {"source_refresh_coordinate": _STALE},
        }]},
    }
    spy = _Spy()
    migrated = _candidate()

    def generate(*args, **kwargs):
        spy.generated.append((args, kwargs))
        if kwargs.get("review_gaps") is not None:
            kwargs["review_gaps"].extend(gaps_to_record or [])
        return migrated

    def weakening(*args, **kwargs):
        spy.weakening.append((args, kwargs))

    captures = [_census(), _census()]
    monkeypatch.setattr(
        refresh.namespace_manifest, "read_manifest",
        lambda path: (Path(path).read_bytes(), document),
    )
    monkeypatch.setattr(refresh, "_require_installed_source_match", lambda root: None)
    monkeypatch.setattr(
        refresh, "_selected_source_semantic_profile", lambda value: _profile()
    )
    monkeypatch.setattr(refresh, "_source_semantic_deltas", lambda *args: list(deltas))
    monkeypatch.setattr(
        refresh, "_semantic_profile_transition_deltas",
        lambda *args: list(transition or []),
    )
    monkeypatch.setattr(refresh, "_source_coordinate", lambda root: (_CURRENT, {}))
    monkeypatch.setattr(
        refresh.package_manifest_migration, "refresh_selected_manifest", generate
    )
    monkeypatch.setattr(refresh, "_require_non_weakening", weakening)
    monkeypatch.setattr(refresh, "_canonical", lambda value: _AFTER)
    monkeypatch.setattr(
        refresh.tier_zero_manifest, "_strict_json_document", lambda raw: None
    )
    monkeypatch.setattr(refresh.package_manifest, "select", lambda *a, **k: None)
    monkeypatch.setattr(
        refresh.package_manifest_migration, "_capture_source_inventory",
        lambda root: dict(captures.pop(0)),
    )
    report = gap_report or {
        "status": "PASS",
        "unresolved_decision_count": 0,
        "incomplete_obligation_count": 0,
        "unowned_evidence_count": 0,
    }
    monkeypatch.setattr(
        refresh.package_manifest_migration, "_review_gap_report",
        lambda document, *, root=None, source_binding=None: {
            **report,
            "source_binding": {
                key: value for key, value in (source_binding or {}).items()
                if key != "inventory"
            },
        },
    )
    return root, spy


def test_default_policy_still_refuses_changed_reviewed_source(tmp_path, monkeypatch):
    root, spy = _inspection(tmp_path, monkeypatch, deltas=[_DELTA])
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)
    assert exc.value.code == "MANIFEST_REFRESH_REVIEW_REQUIRED"
    assert spy.generated == []


def test_unknown_policy_is_refused_before_any_work(tmp_path, monkeypatch):
    root, spy = _inspection(tmp_path, monkeypatch, deltas=[])
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root, review_policy="forgive")
    assert exc.value.code == "MANIFEST_REFRESH_REVIEW_POLICY_INVALID"
    assert spy.generated == []


def test_record_policy_regenerates_and_reopens_instead_of_refusing(
    tmp_path, monkeypatch
):
    root, spy = _inspection(
        tmp_path,
        monkeypatch,
        deltas=[_DELTA],
        gaps_to_record=[{"stage": "records", "gap": "STALE_SPECIALIZATION_LABEL"}],
    )

    plan = refresh.inspect_manifest_refresh(root, review_policy="record")

    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["after"] == _AFTER
    (args, kwargs), = spy.generated
    assert kwargs["record_review_gaps"] is True
    assert kwargs["source_deltas"] == [_DELTA]
    # The reopened answers are exempt from the no-weakening comparison; nothing else is.
    (w_args, w_kwargs), = spy.weakening
    assert w_kwargs["reopened"] == {
        "vstd-owner": (frozenset({"POLICY"}), frozenset({"POLICY-0.1-scope"}))
    }
    assert plan["review_gaps"] == [
        {"stage": "records", "gap": "STALE_SPECIALIZATION_LABEL"}
    ]


_UNKNOWN_REPORT = {
    "status": "UNKNOWN",
    "unresolved_decision_count": 11865,
    "incomplete_obligation_count": 12,
    "unowned_evidence_count": 0,
}


def test_record_policy_plans_a_refresh_that_keeps_unanswered_questions(
    tmp_path, monkeypatch
):
    root, _ = _inspection(
        tmp_path,
        monkeypatch,
        deltas=[],
        transition=[{"reason": "NEW_REVIEWED_SOURCE_REQUIRES_SELECTION"}],
        gap_report=_UNKNOWN_REPORT,
    )
    plan = refresh.inspect_manifest_refresh(root, review_policy="record")
    assert plan["status"] == "REFRESH_REQUIRED"
    assert plan["review_gaps"] == []


def test_default_policy_refuses_the_same_remaining_questions(tmp_path, monkeypatch):
    root, _ = _inspection(tmp_path, monkeypatch, deltas=[], gap_report=_UNKNOWN_REPORT)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root)
    assert exc.value.code == "MANIFEST_REFRESH_REVIEW_GAPS_REMAIN"
    assert exc.value.status == "UNKNOWN"


def test_record_policy_still_fails_on_unowned_evidence(tmp_path, monkeypatch):
    # Evidence that cites a file the object does not own is corruption, not a gap.
    root, _ = _inspection(
        tmp_path,
        monkeypatch,
        deltas=[],
        gap_report={
            "status": "FAIL",
            "unresolved_decision_count": 0,
            "incomplete_obligation_count": 0,
            "unowned_evidence_count": 3,
        },
    )
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh.inspect_manifest_refresh(root, review_policy="record")
    assert exc.value.code == "MANIFEST_REFRESH_REVIEW_GAPS_REMAIN"


def test_ensure_current_manifest_forwards_the_policy_only_when_recording(
    tmp_path, monkeypatch
):
    seen = []

    def inspect(root, **kwargs):
        seen.append(kwargs)
        raise refresh.ManifestRefreshError("STOP_HERE")

    monkeypatch.setattr(refresh, "inspect_manifest_refresh", inspect)
    for policy in ("refuse", "record"):
        with pytest.raises(refresh.ManifestRefreshError):
            refresh.ensure_current_manifest(
                tmp_path, mode="check", review_policy=policy
            )
    assert seen == [{}, {"review_policy": "record"}]


def test_reopened_coordinates_group_deltas_by_object():
    deltas = [
        _DELTA,
        {**_DELTA, "path": "src/other.py", "classifications": ["ASSET"],
         "obligations": ["POLICY-0.2-other"]},
        {**_DELTA, "object_id": "vstd-second", "classifications": [], "obligations": []},
    ]
    assert refresh._reopened_coordinates(deltas) == {
        "vstd-owner": (
            frozenset({"POLICY", "ASSET"}),
            frozenset({"POLICY-0.1-scope", "POLICY-0.2-other"}),
        ),
        "vstd-second": (frozenset(), frozenset()),
    }


def _row(status: str, reason: str, paths: list[str]) -> dict:
    return {
        "status": status,
        "reason": reason,
        "evidence": [{"path": path, "sha256": "sha256:" + "0" * 64} for path in paths],
    }


def _doc(classification: dict, obligations: dict) -> dict:
    return {
        "schema_version": "verifier-objects-manifest-5",
        "repository": {"remote": refresh.VERIFIER_REMOTE, "revision": "1" * 40},
        "namespace": {
            "schema_version": "test-namespace",
            "extensions": [],
            "instance_checks": [],
            "consequence_graph": [],
            "objects": [{
                "object_id": "vstd-owner",
                "kind": "VERIFIER",
                "payload": {},
                "reason": "Owner.",
                "surfaces": ["file:src/changed.py"],
                "specializations": [],
                "operands": {},
                "classification": classification,
                "obligations": obligations,
            }],
            "execution_checks": [],
        },
        "representation_updates": [],
    }


def test_non_weakening_exempts_only_the_reopened_coordinates():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    refuted = _row("DOES_NOT_APPLY", "Refuted.", ["src/changed.py"])
    bound = {
        "reason": "Authored.",
        "evidence": applies["evidence"],
        "declaration": {"scope": "Authored."},
    }
    before = _doc({"POLICY": applies, "ASSET": refuted}, {"POLICY-0.1-scope": bound})
    reopened_cell = _row("UNRESOLVED", "Reopened.", [])
    blank = {"reason": "", "evidence": [], "declaration": {"scope": ""}}
    after = _doc(
        {"POLICY": reopened_cell, "ASSET": refuted}, {"POLICY-0.1-scope": blank}
    )

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, after)
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"

    refresh._require_non_weakening(
        before,
        after,
        reopened={
            "vstd-owner": (frozenset({"POLICY"}), frozenset({"POLICY-0.1-scope"}))
        },
    )

    # A cell that was not reopened still may not weaken.
    weakened = _doc(
        {"POLICY": reopened_cell, "ASSET": _row("UNRESOLVED", "Gone.", [])},
        {"POLICY-0.1-scope": blank},
    )
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before,
            weakened,
            reopened={
                "vstd-owner": (frozenset({"POLICY"}), frozenset({"POLICY-0.1-scope"}))
            },
        )
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def _bound(text: str, paths: list[str]) -> dict:
    return {
        "reason": text,
        "evidence": _row("APPLIES", "", paths)["evidence"],
        "declaration": {"scope": text},
    }


def test_regeneration_accepts_rewording_and_records_what_it_reopened():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    refuted = _row("DOES_NOT_APPLY", "Refuted.", ["src/changed.py"])
    before = _doc(
        {"POLICY": applies, "ASSET": refuted, "MARKET": refuted},
        {"POLICY-0.1-scope": _bound("Authored.", ["src/changed.py"])},
    )
    after = _doc(
        {
            "POLICY": _row("APPLIES", "Regenerated wording.", ["src/other.py"]),
            "ASSET": _row("UNRESOLVED", "Not refuted by ownership.", []),
            "MARKET": _row("APPLIES", "Now supported.", ["src/changed.py"]),
        },
        {"POLICY-0.1-scope": _bound("Regenerated wording.", ["src/other.py"])},
    )
    after["namespace"]["objects"][0]["reason"] = "Regenerated owner reason."

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, after, reopened={})
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"

    regenerated: list[dict] = []
    refresh._require_non_weakening(before, after, reopened={}, regenerated=regenerated)

    assert regenerated == [
        {
            "stage": "regeneration",
            "gap": "APPLICABILITY_REOPENED",
            "object_id": "vstd-owner",
            "classification": "ASSET",
            "was": "DOES_NOT_APPLY",
        },
        {
            "stage": "regeneration",
            "gap": "REFUTATION_WITHDRAWN",
            "object_id": "vstd-owner",
            "classification": "MARKET",
            "was": "DOES_NOT_APPLY",
        },
    ]


@pytest.mark.parametrize("was", ("APPLIES", "UNRESOLVED"))
def test_regeneration_never_moves_an_answer_into_does_not_apply(was):
    before = _doc({"ASSET": _row(was, "Before.", [])}, {})
    after = _doc({"ASSET": _row("DOES_NOT_APPLY", "Refuted by regeneration.", [])}, {})
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, after, reopened={}, regenerated=[])
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def test_regeneration_drops_an_obligation_only_when_its_kind_is_reopened():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    bound = {"POLICY-0.1-scope": _bound("Authored.", ["src/changed.py"])}
    before = _doc({"POLICY": applies}, bound)

    kept_open = _doc({"POLICY": _row("UNRESOLVED", "Reopened.", [])}, {})
    refresh._require_non_weakening(before, kept_open, reopened={}, regenerated=[])

    silently_dropped = _doc({"POLICY": applies}, {})
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, silently_dropped, reopened={}, regenerated=[]
        )
    assert exc.value.code == "MANIFEST_REFRESH_OBLIGATION_DROPPED"


def test_regeneration_does_not_relax_the_default_or_structural_comparisons():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    before = _doc({"POLICY": applies}, {})
    reworded = _doc({"POLICY": _row("APPLIES", "Reworded.", ["src/changed.py"])}, {})
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, reworded, reopened={})
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"

    retyped = _doc({"POLICY": applies}, {})
    retyped["namespace"]["objects"][0]["kind"] = "ASSET"
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, retyped, reopened={}, regenerated=[])
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"

    emptied = _doc({"POLICY": applies}, {})
    emptied["namespace"]["objects"][0]["surfaces"] = []
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, emptied, reopened={}, regenerated=[])
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"


def test_regeneration_accepts_only_closed_reviewed_representation_transitions():
    migration = refresh.package_manifest_migration
    transitions = migration._PRE_APPLICABILITY_REPRESENTATION_ROLES
    expected_ids = {
        "vstd-accelerator-profile-reader",
        "vstd-accelerator-profile-registry",
        "vstd-accessibility-artifact-reader",
        "vstd-added-kind-behavioral-verifier",
        "vstd-javascript-parser-protocol",
        "vstd-object-obligation-inventory",
        "vstd-package-manifest-migration-controller",
        "vstd-polish-findings-projection",
        "vstd-systems-parser-protocol",
        "vstd-vgsat-native-verifier-adapters",
        "vstd-vgsat-public-result-records",
        "vstd-workflow-parser-protocol",
    }
    assert set(transitions) == expected_ids

    specs = {
        spec.object_id: spec
        for spec in migration.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
    }
    for object_id, prior_role in transitions.items():
        current_role = specs[object_id].representation_role
        assert migration._is_exact_reviewed_representation_role_transition(
            object_id,
            {"representation_role": prior_role},
            {"representation_role": current_role},
        )

    object_id = "vstd-accelerator-profile-reader"
    before = _doc({}, {})
    after = _doc({}, {})
    for document in (before, after):
        document["namespace"]["objects"][0]["object_id"] = object_id
    before["namespace"]["objects"][0]["payload"] = {
        "representation_role": transitions[object_id]
    }
    after["namespace"]["objects"][0]["payload"] = {
        "representation_role": specs[object_id].representation_role
    }

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, after, reopened={})
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"

    regenerated: list[dict] = []
    refresh._require_non_weakening(
        before, after, reopened={}, regenerated=regenerated
    )
    assert regenerated == [{
        "stage": "regeneration",
        "gap": "OBJECT_REPRESENTATION_ROLE_REGENERATED",
        "object_id": object_id,
    }]

    after["namespace"]["objects"][0]["payload"] = {
        "representation_role": specs[object_id].representation_role + " substituted"
    }
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(before, after, reopened={}, regenerated=[])
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"


def test_polish_parser_records_review_gaps_by_default_and_can_refuse():
    from verifier.runtime import self_polish_tiers

    parser = self_polish_tiers.build_self_polish_tier_parser()
    for tier in ("0", "1", "2", "3"):
        assert parser.parse_args([tier]).manifest_review_policy == "record"
        refused = parser.parse_args([tier, "--manifest-review-policy", "refuse"])
        assert refused.manifest_review_policy == "refuse"
    with pytest.raises(SystemExit):
        parser.parse_args(["0", "--manifest-review-policy", "forgive"])


def test_polish_hands_the_selected_policy_to_the_refresh(tmp_path, monkeypatch):
    from verifier.runtime import self_polish_tiers

    seen = []

    def ensure(root, **kwargs):
        seen.append(kwargs)
        raise refresh.ManifestRefreshError("STOP_HERE")

    monkeypatch.setattr(refresh, "ensure_current_manifest", ensure)
    for flags, expected in (([], "record"), (["--manifest-review-policy", "refuse"], "refuse")):
        self_polish_tiers.handle_self_polish_tier_argv(
            ["0", "--source-root", str(tmp_path), *flags]
        )
    assert [call["review_policy"] for call in seen] == ["record", "refuse"]


def _graph_row(records: list[str]) -> dict:
    return {
        "object_id": "vstd-package-graph",
        "kind": "GRAPH",
        "payload": {
            "source_refresh_coordinate": "sha256:" + records[0][-1] * 64,
            "source_semantic_profile": _profile_with(records),
        },
    }


def _profile_with(records: list[str]) -> dict:
    from verifier.runtime import package_manifest_migration, tier_zero_profile

    binding_set = tier_zero_profile.canonical_bytes(
        [{"classifications": [], "obligations": [], "object_id": "a"}]
    ).decode("utf-8")
    profile = {
        "schema_version": package_manifest_migration.SOURCE_SEMANTIC_PROFILE_SCHEMA,
        "reason": "Test profile.",
        "binding_sets": [binding_set],
        "records": records,
    }
    profile["digest"] = tier_zero_profile.value_digest(profile)
    return profile


def _record(path: str, digit: str) -> str:
    return "\t".join((path, "byte-exact", "sha256:" + digit * 64, "0"))


def test_retired_surfaces_need_a_changed_or_departed_source_file():
    prior = _graph_semantic_identities_for(
        [_record("src/a.py", "1"), _record("src/b.py", "2"), _record("src/c.py", "3")]
    )
    current = _graph_semantic_identities_for(
        [_record("src/a.py", "9"), _record("src/b.py", "2")]
    )
    surfaces = ["python:src/a.py:f", "python:src/b.py:g", "python:src/c.py:h"]

    # a.py changed meaning and c.py left the profile, so their surfaces may retire.
    assert refresh._retired_surface_paths(
        [surfaces[0], surfaces[2]], [surfaces[1]], prior, current
    ) == ["src/a.py", "src/c.py"]
    # b.py is semantically identical, so losing its surface is a lost route.
    assert (
        refresh._retired_surface_paths([surfaces[1]], [], prior, current) is None
    )
    # A surface in a file that was never profiled cannot be shown to have changed.
    assert (
        refresh._retired_surface_paths(["python:src/z.py:f"], [], prior, current)
        is None
    )
    # Nothing dropped retires nothing.
    assert refresh._retired_surface_paths(surfaces, surfaces, prior, current) == []


def test_unprofiled_surface_retirement_requires_the_exact_reviewed_replacements():
    transition = refresh._REVIEWED_SURFACE_RETIREMENTS["vstd-package-object"]
    prior = list(transition)
    current = list(transition.values())
    assert refresh._reviewed_surface_retirement_paths(
        "vstd-package-object", prior, current
    ) == [
        "tests/test_package_semantic_ownership_aggregate.py",
        "tests/test_package_semantic_ownership_domains_agency_collective.py",
    ]

    missing_replacement = current[:-1]
    assert refresh._reviewed_surface_retirement_paths(
        "vstd-package-object", prior, missing_replacement
    ) is None
    substituted = [*current[:-1], current[-1] + "_substituted"]
    assert refresh._reviewed_surface_retirement_paths(
        "vstd-package-object", prior, substituted
    ) is None
    assert refresh._reviewed_surface_retirement_paths(
        "vstd-other", prior, current
    ) is None


def _graph_semantic_identities_for(records: list[str]) -> dict:
    return refresh._graph_semantic_identities(
        {"vstd-package-graph": _graph_row(records)}
    )


def _launch(launch_id: str, **fields) -> dict:
    return {"launch_id": launch_id, "line": 1, "necessity_reason": "Needed.", **fields}


def _harness(launches: list[dict], **payload) -> dict:
    return {
        **payload,
        "direct_launch_denominator": {
            "schema_version": "denominator-1",
            "profile": "profile-1",
            "launches": launches,
        },
    }


def test_launch_denominator_regeneration_names_added_removed_and_changed():
    prior = _harness([_launch("a"), _launch("b"), _launch("c")])
    current = _harness([_launch("a"), _launch("b", line=9), _launch("d")])

    assert refresh._harness_launches_regenerated(prior, current) == {
        "added": ["d"],
        "removed": ["c"],
        "changed": ["b"],
    }
    assert refresh._harness_launches_regenerated(prior, prior) == {
        "added": [],
        "removed": [],
        "changed": [],
    }


def test_launch_denominator_regeneration_refuses_any_other_payload_change():
    prior = _harness([_launch("a")], other="kept")
    assert refresh._harness_launches_regenerated(
        prior, _harness([_launch("a")], other="altered")
    ) is None
    wrong_profile = _harness([_launch("a")], other="kept")
    wrong_profile["direct_launch_denominator"]["profile"] = "profile-2"
    assert refresh._harness_launches_regenerated(prior, wrong_profile) is None
    duplicated = _harness([_launch("a"), _launch("a")], other="kept")
    assert refresh._harness_launches_regenerated(prior, duplicated) is None


def test_regeneration_records_retired_surfaces_and_launch_changes():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    before = _doc({"POLICY": applies}, {})
    after = _doc({"POLICY": applies}, {})
    before["namespace"]["objects"][0]["surfaces"] = ["python:src/a.py:f"]
    after["namespace"]["objects"][0]["surfaces"] = []
    for document, digit in ((before, "1"), (after, "2")):
        document["namespace"]["objects"].append(_graph_row([_record("src/a.py", digit)]))
    harness_before = _doc({}, {})["namespace"]["objects"][0]
    harness_after = _doc({}, {})["namespace"]["objects"][0]
    for row, launches in ((harness_before, [_launch("a")]), (harness_after, [_launch("b")])):
        row["object_id"] = "vstd-harness"
        row["payload"] = _harness(launches)
        row["surfaces"] = []
    before["namespace"]["objects"].append(harness_before)
    after["namespace"]["objects"].append(harness_after)

    regenerated: list[dict] = []
    refresh._require_non_weakening(before, after, reopened={}, regenerated=regenerated)

    assert regenerated == [
        {
            "stage": "regeneration",
            "gap": "SURFACES_RETIRED",
            "object_id": "vstd-owner",
            "paths": ["src/a.py"],
        },
        {
            "stage": "regeneration",
            "gap": "LAUNCH_DENOMINATOR_REGENERATED",
            "object_id": "vstd-harness",
            "added": ["b"],
            "removed": ["a"],
            "changed": [],
        },
    ]


def _sealed(tmp_path, before_document, after_document, **extra):
    """A genuinely sealed refresh plan over a real target file."""

    import stat

    root = tmp_path.resolve()
    target = root / "objects.vstd"
    before = refresh._canonical(before_document)
    after = refresh._canonical(after_document)
    target.write_bytes(before)
    return refresh._seal_plan({
        "schema_version": refresh.PLAN_SCHEMA,
        "root": root,
        "target": target,
        "before": before,
        "after": after,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
        "source_census_digest": _CENSUS,
        "mechanism_digest": refresh._mechanism_digest(),
        "source_binding": {
            "status": "BOUND",
            "opening_census_digest": _CENSUS,
            "closing_census_digest": _CENSUS,
            "unavailable": None,
        },
        "status": "REFRESH_REQUIRED",
        "target_mode": stat.S_IMODE(target.stat().st_mode),
        **extra,
    })


def _reworded_pair():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    reworded = _row("UNRESOLVED", "Reopened by regeneration.", [])
    return _doc({"POLICY": applies}, {}), _doc({"POLICY": reworded}, {})


def test_public_plan_keeps_review_policy_and_gaps_out_of_the_journal(tmp_path):
    before, after = _reworded_pair()
    plan = _sealed(
        tmp_path, before, after, review_policy="record", review_gaps=[{"gap": "x"}]
    )

    assert "review_policy" not in refresh._public_plan(plan)
    assert "review_gaps" not in refresh._public_plan(plan)


def test_the_review_policy_is_sealed_into_the_plan(tmp_path):
    before, after = _reworded_pair()
    strict = _sealed(tmp_path, before, after)
    recording = _sealed(tmp_path, before, after, review_policy="record")

    assert strict["plan_seal"] != recording["plan_seal"]
    forged = dict(strict)
    forged["review_policy"] = "record"
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._validate_publish_plan(forged)
    assert exc.value.code == "MANIFEST_REFRESH_PLAN_MUTATED"


def test_publication_revalidates_a_recording_plan_with_the_recording_policy(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(refresh, "_mechanism_digest", lambda: "sha256:" + "c" * 64)
    before, after = _reworded_pair()
    after["namespace"]["objects"][0]["reason"] = "Regenerated owner reason."

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._validate_publish_plan(_sealed(tmp_path, before, after))
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"

    refresh._validate_publish_plan(
        _sealed(tmp_path, before, after, review_policy="record")
    )


_SOURCE_DIGESTS = {"src/changed.py": "sha256:" + "0" * 64}


def _reopened_then_refuted(refutation: dict) -> tuple[dict, dict]:
    """A reopened kind (and its blanked obligation) that regeneration answers again."""

    blank = {"reason": "", "evidence": [], "declaration": {"scope": ""}}
    reopened = _row("UNRESOLVED", "Reopened: the semantics changed.", [])
    return (
        _doc({"POLICY": reopened}, {"POLICY-0.1-scope": blank}),
        _doc({"POLICY": refutation}, {}),
    )


def test_regeneration_re_answers_a_reopened_kind_only_from_current_bound_evidence():
    before, after = _reopened_then_refuted(
        _row("DOES_NOT_APPLY", "Refuted at the current bytes.", ["src/changed.py"])
    )

    regenerated: list[dict] = []
    refresh._require_non_weakening(
        before, after, reopened={}, regenerated=regenerated,
        source_digests=_SOURCE_DIGESTS,
    )

    assert regenerated == [{
        "stage": "regeneration",
        "gap": "REFUTATION_REANSWERED",
        "object_id": "vstd-owner",
        "classification": "POLICY",
        "was": "UNRESOLVED",
    }]


@pytest.mark.parametrize("refutation,digests", [
    # No evidence at all: a bare DOES_NOT_APPLY would be authored by the generator.
    (_row("DOES_NOT_APPLY", "Bare.", []), _SOURCE_DIGESTS),
    # Evidence that is not the current bytes of that source.
    (_row("DOES_NOT_APPLY", "Stale.", ["src/changed.py"]),
     {"src/changed.py": "sha256:" + "1" * 64}),
    # Evidence for a path the current inventory does not contain.
    (_row("DOES_NOT_APPLY", "Absent.", ["src/changed.py"]), {}),
    # Nothing to compare against: the caller supplied no inventory.
    (_row("DOES_NOT_APPLY", "Unchecked.", ["src/changed.py"]), None),
])
def test_regeneration_refuses_a_refutation_not_bound_to_current_source(refutation, digests):
    before, after = _reopened_then_refuted(refutation)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, after, reopened={}, regenerated=[], source_digests=digests
        )
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def test_regeneration_does_not_turn_an_answered_kind_into_a_refutation():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    refuted = _row("DOES_NOT_APPLY", "Refuted.", ["src/changed.py"])
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            _doc({"POLICY": applies}, {}), _doc({"POLICY": refuted}, {}),
            reopened={}, regenerated=[], source_digests=_SOURCE_DIGESTS,
        )
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def test_checked_documented_retention_preserves_exact_source_refutation_reversal():
    applies = _row("APPLIES", "Reviewed.", ["src/changed.py"])
    refuted = _row("DOES_NOT_APPLY", "Source-only refutation.", ["src/changed.py"])
    prior_binding = _bound("objects.vstd APPLIES.", ["src/changed.py"])
    retained_binding = _bound("reasons.vstd retains demand.", ["src/changed.py"])
    before = _doc(
        {"POLICY": applies}, {"POLICY-0.1-scope": prior_binding}
    )
    after = _doc(
        {"POLICY": refuted}, {"POLICY-0.1-scope": retained_binding}
    )

    regenerated: list[dict] = []
    refresh._require_non_weakening(
        before,
        after,
        reopened={},
        regenerated=regenerated,
        source_digests=_SOURCE_DIGESTS,
        documented_retention_keys=frozenset({("vstd-owner", "POLICY")}),
    )

    assert regenerated == [{
        "stage": "regeneration",
        "gap": "SOURCE_REFUTATION_RESTORED_WITH_DOCUMENTED_RETENTION",
        "object_id": "vstd-owner",
        "classification": "POLICY",
        "was": "APPLIES",
    }]

    for keys, digests in (
        (frozenset({("vstd-owner", "ASSET")}), _SOURCE_DIGESTS),
        (frozenset({("vstd-owner", "POLICY")}), {
            "src/changed.py": "sha256:" + "1" * 64
        }),
    ):
        with pytest.raises(refresh.ManifestRefreshError) as exc:
            refresh._require_non_weakening(
                before,
                after,
                reopened={},
                regenerated=[],
                source_digests=digests,
                documented_retention_keys=keys,
            )
        assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def _documented_withdrawal_pair(
    *, reason_id: str = "tier0-policy-owner",
) -> tuple[dict, dict, dict, dict, dict]:
    refuted = _row(
        "DOES_NOT_APPLY", "Current source refutes POLICY.", ["src/changed.py"]
    )
    registry = refresh.namespace_contracts.namespace_registry()
    obligations = {}
    for requirement in refresh.namespace_contracts.requirements_for(
        registry, ("POLICY",)
    ):
        if requirement["kind"] != "POLICY":
            continue
        obligations[requirement["id"]] = {
            "reason": (
                "reasons.vstd:"
                + reason_id
                + "; fulfillment NOT_ESTABLISHED."
            ),
            "evidence": refuted["evidence"],
            "declaration": {
                field: "NOT_ESTABLISHED"
                for field in requirement["declaration_fields"]
            },
        }
    authority = {
        "path": "reasons.vstd",
        "sha256": "sha256:" + "9" * 64,
        "ir_digest": "sha256:" + "8" * 64,
        "withdrawals": {("vstd-owner", "POLICY"): reason_id},
    }
    digests = {
        **_SOURCE_DIGESTS,
        "reasons.vstd": authority["sha256"],
    }
    observed = {
        "surfaces": [{
            "surface_id": "file:src/changed.py",
            "path": "src/changed.py",
            "source_kinds": [],
        }],
    }
    return (
        _doc({"POLICY": refuted}, obligations),
        _doc({"POLICY": refuted}, {}),
        authority,
        digests,
        observed,
    )


def test_documented_withdrawal_authority_uses_the_full_registered_denominator(
    tmp_path, monkeypatch
):
    from verifier.runtime.tier_zero_reasoning import integration

    (tmp_path / "reasons.vstd").write_text("checked by selector", encoding="utf-8")
    selection = integration.RootReasonSelection(
        authority={
            "path": "reasons.vstd",
            "sha256": "sha256:" + "9" * 64,
        },
        ir={"reasons": []},
        ir_digest="sha256:" + "8" * 64,
        classification_decisions=(
            {
                "reason_id": "added-kind-denial",
                "object_id": "vstd-owner",
                "object_kind": "ACTUATOR",
                "decision": "DOES_NOT_APPLY",
            },
            {
                "reason_id": "unregistered-denial",
                "object_id": "vstd-owner",
                "object_kind": "NOT_A_KIND",
                "decision": "DOES_NOT_APPLY",
            },
        ),
        obligation_decisions=(),
    )
    monkeypatch.setattr(integration, "select_root_reasons", lambda root: selection)

    authority = refresh._documented_withdrawal_authority(tmp_path)

    assert authority is not None
    assert authority["withdrawals"] == {
        ("vstd-owner", "ACTUATOR"): "added-kind-denial"
    }


def test_checked_documented_denial_withdraws_only_its_exact_generated_retention():
    before, after, authority, digests, observed = _documented_withdrawal_pair()
    regenerated: list[dict] = []

    refresh._require_non_weakening(
        before,
        after,
        reopened={},
        regenerated=regenerated,
        source_digests=digests,
        observed=observed,
        documented_withdrawal_authority=authority,
    )

    assert regenerated == [{
        "stage": "regeneration",
        "gap": "DOCUMENTED_RETENTION_WITHDRAWN",
        "object_id": "vstd-owner",
        "classification": "POLICY",
        "reason_id": "tier0-policy-owner",
        "reason_sha256": authority["sha256"],
        "reason_ir_digest": authority["ir_digest"],
    }]


@pytest.mark.parametrize(
    "mutation",
    [
        "reason-id",
        "authored-binding",
        "partial-denominator",
        "independent-specialization",
        "independent-source-kind",
        "stale-refutation",
    ],
)
def test_documented_denial_never_withdraws_a_nonexact_or_independent_obligation(
    mutation,
):
    before, after, authority, digests, observed = _documented_withdrawal_pair()
    if mutation == "reason-id":
        authority["withdrawals"][("vstd-owner", "POLICY")] = "other-reason"
    elif mutation == "authored-binding":
        next(iter(before["namespace"]["objects"][0]["obligations"].values()))[
            "declaration"
        ]["scope"] = "Authored."
    elif mutation == "partial-denominator":
        before["namespace"]["objects"][0]["obligations"].popitem()
    elif mutation == "independent-specialization":
        for document in (before, after):
            document["namespace"]["objects"][0]["specializations"] = ["POLICY"]
    elif mutation == "independent-source-kind":
        observed["surfaces"][0]["source_kinds"] = ["POLICY"]
    elif mutation == "stale-refutation":
        after["namespace"]["objects"][0]["classification"]["POLICY"][
            "evidence"
        ][0]["sha256"] = "sha256:" + "1" * 64

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before,
            after,
            reopened={},
            regenerated=[],
            source_digests=digests,
            observed=observed,
            documented_withdrawal_authority=authority,
        )
    assert exc.value.code in {
        "MANIFEST_REFRESH_OBLIGATION_DROPPED",
        "MANIFEST_REFRESH_CLASSIFICATION_CHANGED",
    }


def test_documented_denial_authority_must_match_the_bound_reason_bytes():
    before, after, authority, digests, observed = _documented_withdrawal_pair()
    digests["reasons.vstd"] = "sha256:" + "7" * 64

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before,
            after,
            reopened={},
            regenerated=[],
            source_digests=digests,
            observed=observed,
            documented_withdrawal_authority=authority,
        )
    assert exc.value.code == "MANIFEST_REFRESH_DOCUMENTED_WITHDRAWAL_INVALID"


def test_publication_binds_a_re_answered_refutation_to_the_plan_roots_inventory(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(refresh, "_mechanism_digest", lambda: "sha256:" + "c" * 64)
    before, after = _reopened_then_refuted(
        _row("DOES_NOT_APPLY", "Refuted at the current bytes.", ["src/changed.py"])
    )
    plan = _sealed(tmp_path, before, after, review_policy="record")
    seen: list = []

    def inventory(digests):
        def capture(root):
            seen.append(root)
            return {"inventory": dict(digests), "census_digest": _CENSUS, "unavailable": None}
        return capture

    migration = refresh.package_manifest_migration
    monkeypatch.setattr(migration, "_capture_source_inventory", inventory(_SOURCE_DIGESTS))
    refresh._validate_publish_plan(plan)
    assert seen == [tmp_path.resolve()]

    # The source moved after planning: the refutation no longer cites the current bytes.
    monkeypatch.setattr(
        migration, "_capture_source_inventory",
        inventory({"src/changed.py": "sha256:" + "1" * 64}),
    )
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._validate_publish_plan(plan)
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


_REOPENED_POLICY = {
    "vstd-owner": (frozenset({"POLICY"}), frozenset({"POLICY-0.1-scope"}))
}


def _reviewed_then_regenerated(answer: dict) -> tuple[dict, dict]:
    """A reviewed kind whose cited source changed, answered again in the same pass."""

    bound = {
        "reason": "Authored.",
        "evidence": _row("APPLIES", "", ["src/changed.py"])["evidence"],
        "declaration": {"scope": "Authored."},
    }
    blank = {"reason": "", "evidence": [], "declaration": {"scope": ""}}
    return (
        _doc({"POLICY": _row("APPLIES", "Reviewed.", ["src/changed.py"])},
             {"POLICY-0.1-scope": bound}),
        _doc({"POLICY": answer}, {"POLICY-0.1-scope": blank}),
    )


def test_a_reopened_kind_may_be_answered_again_in_the_same_pass():
    for answer in (
        _row("UNRESOLVED", "Reopened.", []),
        _row("APPLIES", "Re-reviewed on the new bytes.", ["src/changed.py"]),
    ):
        before, after = _reviewed_then_regenerated(answer)
        refresh._require_non_weakening(
            before, after, reopened=_REOPENED_POLICY, regenerated=[],
            source_digests=_SOURCE_DIGESTS,
        )

    before, after = _reviewed_then_regenerated(
        _row("DOES_NOT_APPLY", "Refuted at the new bytes.", ["src/changed.py"])
    )
    regenerated: list[dict] = []
    refresh._require_non_weakening(
        before, after, reopened=_REOPENED_POLICY, regenerated=regenerated,
        source_digests=_SOURCE_DIGESTS,
    )
    assert regenerated == [{
        "stage": "regeneration",
        "gap": "REFUTATION_REANSWERED",
        "object_id": "vstd-owner",
        "classification": "POLICY",
        "was": "UNRESOLVED",
    }]


@pytest.mark.parametrize("refutation,digests", [
    (_row("DOES_NOT_APPLY", "Bare.", []), _SOURCE_DIGESTS),
    (_row("DOES_NOT_APPLY", "Stale.", ["src/changed.py"]),
     {"src/changed.py": "sha256:" + "1" * 64}),
    (_row("DOES_NOT_APPLY", "Unchecked.", ["src/changed.py"]), None),
])
def test_a_reopened_kind_is_not_a_free_pass_to_an_unbound_refutation(refutation, digests):
    before, after = _reviewed_then_regenerated(refutation)
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, after, reopened=_REOPENED_POLICY, regenerated=[],
            source_digests=digests,
        )
    assert exc.value.code == "MANIFEST_REFRESH_CLASSIFICATION_CHANGED"


def _exact_semantic_catalog_role_pair(
    object_id: str = "vstd-object-context-closure",
    *,
    extra_role: str = "TRANSACTION",
) -> tuple[dict, dict]:
    spec = next(
        item
        for item in refresh.package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if item.object_id == object_id
    )
    before = _doc({}, {})
    after = _doc({}, {})
    for document in (before, after):
        row = document["namespace"]["objects"][0]
        row.update(
            {
                "object_id": spec.object_id,
                "kind": spec.primary_kind,
                "payload": {"representation_role": spec.representation_role},
                "reason": (
                    spec.necessity_reason
                    + " Boundary: "
                    + spec.consequence_boundary
                ),
                "surfaces": ["file:" + path for path in spec.owned_paths],
                "specializations": list(spec.specializations),
                "operands": {
                    role: list(targets) for role, targets in spec.operands
                },
            }
        )
    before["namespace"]["objects"][0]["specializations"].append(extra_role)
    return before, after


def test_regeneration_retires_only_an_exact_catalog_unreviewed_extra_role():
    before, after = _exact_semantic_catalog_role_pair()
    regenerated: list[dict] = []

    refresh._require_non_weakening(
        before, after, reopened={}, regenerated=regenerated
    )

    assert regenerated == [
        {
            "stage": "regeneration",
            "gap": "SEMANTIC_OWNERSHIP_SPECIALIZATION_RETIRED",
            "object_id": "vstd-object-context-closure",
            "classification": "TRANSACTION",
        }
    ]


def test_semantic_role_retirement_refuses_a_nearby_catalog_substitution():
    before, after = _exact_semantic_catalog_role_pair()
    after["namespace"]["objects"][0]["reason"] += " Altered."

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, after, reopened={}, regenerated=[]
        )

    assert exc.value.code == "MANIFEST_REFRESH_SPECIALIZATION_DROPPED"


def test_semantic_role_retirement_does_not_allow_a_generic_role_drop():
    before = _doc({}, {})
    after = _doc({}, {})
    before["namespace"]["objects"][0]["specializations"] = ["TRANSACTION"]

    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, after, reopened={}, regenerated=[]
        )

    assert exc.value.code == "MANIFEST_REFRESH_SPECIALIZATION_DROPPED"


def test_semantic_role_retirement_accepts_only_the_exact_preserved_predecessor():
    object_id = "vstd-polish-findings-projection"
    before, after = _exact_semantic_catalog_role_pair(
        object_id, extra_role="SENSOR"
    )
    predecessor = refresh.package_manifest_migration._PRE_APPLICABILITY_REPRESENTATION_ROLES[
        object_id
    ]
    before["namespace"]["objects"][0]["payload"] = {
        "representation_role": predecessor
    }
    after["namespace"]["objects"][0]["payload"] = {
        "representation_role": predecessor
    }
    regenerated: list[dict] = []

    refresh._require_non_weakening(
        before, after, reopened={}, regenerated=regenerated
    )

    assert regenerated == [
        {
            "stage": "regeneration",
            "gap": "SEMANTIC_OWNERSHIP_SPECIALIZATION_RETIRED",
            "object_id": object_id,
            "classification": "SENSOR",
        }
    ]

    forged = _exact_semantic_catalog_role_pair(
        object_id, extra_role="SENSOR"
    )[1]
    forged["namespace"]["objects"][0]["payload"] = {
        "representation_role": predecessor + " altered"
    }
    with pytest.raises(refresh.ManifestRefreshError) as exc:
        refresh._require_non_weakening(
            before, forged, reopened={}, regenerated=[]
        )
    assert exc.value.code == "MANIFEST_REFRESH_OBJECT_MEANING_CHANGED"

"""Finite private source-derived controls; these do not qualify a core release."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import MetaTier, ObjectKind
from verifier.runtime import application_release as historical_app
from verifier.runtime import tier_progression as historical_tiers
from verifier.runtime import core_application_release as app
from verifier.runtime import core_tier_progression as tiers
from verifier.runtime.public_cli import POLISH_SUBCOMMANDS, build_parser
from test_application_release import fixture as original_application_fixture, repin, inputs as original_inputs
from test_tier_progression import fixture as original_native_fixture, selection as original_native_selection


def selected_native():
    bundle, policy, files = original_native_fixture()
    selected = original_native_selection(bundle, policy, files)
    selected.update(schema_version=tiers.SELECTION, semantic_version=tiers.PROFILE,
                    target_tier_name=tiers.CoreTier(selected["target_tier"]).name)
    selected["tiers"] = [dict(row, tier_name=tiers.CoreTier(row["tier"]).name)
        for row in selected["tiers"] if row["tier"] <= 9]
    selected["ranks"] = [dict(row, tier_name=tiers.CoreTier(row["tier"]).name) for row in selected["ranks"]]
    return bundle, policy, files, selected


def assess_native(bundle, policy, files, selected, **options):
    raw = canonical_bytes(selected)
    return tiers.assess_tier_progression(raw, bundle_bytes=canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files,
        expected_selection_digest=tiers.digest(raw), expected_mechanism_digest=tiers.mechanism_digest(), **options)


def application_input():
    data = original_application_fixture()
    data["selection"].update(schema_version=app.SELECTION, profile_id=app.PROFILE)
    req = data["requirements"]
    req.update(schema_version=app.REQUIREMENTS, profile_id=app.PROFILE, extension=None)
    req["tiers"] = [dict(row, tier_name=tiers.CoreTier(row["tier"]).name)
        for row in req["tiers"] if row["tier"] <= 9]
    req["families"] = [{"object_kind": kind.value, "tier": tier.value, "tier_name": tier.name,
        "census": "COMPLETE" if kind.value == "VERIFIER" and tier.value == 1 else "UNKNOWN",
        "required_instances": [req["instances"][0]["instance_id"]] if kind.value == "VERIFIER" and tier.value == 1 else []}
        for kind in ObjectKind for tier in tiers.CoreTier]
    selected = data["shards"]["one"]["selection"]
    selected.update(schema_version=tiers.SELECTION, semantic_version=tiers.PROFILE, target_tier_name="FACETS")
    selected["tiers"] = [dict(row, tier_name=tiers.CoreTier(row["tier"]).name)
        for row in selected["tiers"] if row["tier"] <= 9]
    selected["ranks"] = [dict(row, tier_name=tiers.CoreTier(row["tier"]).name) for row in selected["ranks"]]
    repin(data)
    return data


def assess_application(data, **options):
    repin(data)
    supplied = original_inputs(data)
    supplied["expected_mechanism_digest"] = app.mechanism_digest()
    return app.assess_core_application_release(canonical_bytes(data["selection"]), **supplied, **options)


def test_public_cli_exposes_distinct_core_and_historical_application_routes():
    parser = build_parser()
    core = parser.parse_args(["polish", "core-application", "assess", "selection.json",
        "--membership", "membership.json", "--source-manifest", "source.json",
        "--operation-definitions", "operations.json", "--contexts", "contexts.json",
        "--requirements", "requirements.json", "--artifacts", "artifacts",
        "--shards", "shards.json", "--selection-digest", "sha256:" + "0" * 64,
        "--mechanism-digest", "sha256:" + "1" * 64])
    historical = parser.parse_args(["polish", "application", "assess", "selection.json",
        "--membership", "membership.json", "--source-manifest", "source.json",
        "--operation-definitions", "operations.json", "--contexts", "contexts.json",
        "--requirements", "requirements.json", "--artifacts", "artifacts",
        "--shards", "shards.json", "--selection-digest", "sha256:" + "0" * 64,
        "--mechanism-digest", "sha256:" + "1" * 64])
    assert core.polish_command == "core-application"
    assert historical.polish_command == "application"
    assert {core.polish_command, historical.polish_command}.issubset(POLISH_SUBCOMMANDS)


def test_names_match_actual_nine_tier_namespace_and_historical_stays_distinct():
    assert {t.name: t.value for t in tiers.CoreTier} == {t.name: t.value for t in MetaTier}
    assert tiers.CoreTier.SECURITY == 9 and historical_tiers.ProgressionTier.SECURITY == 6
    assert historical_tiers.ProgressionTier.CORRIGIBILITY == 10
    assert "COMPLETE_CORRIGIBILITY" in historical_app.FULL_GATES and "COMPLETE_CORRIGIBILITY" not in app.FULL_GATES
    assert {"CORE_SELF_POLISH", "NATIVE_PRDEL", "REQUIRED_TESTS", "ACCEPTANCE"}.issubset(app.FULL_GATES)
    assert "COMPOSED_SECURITY" not in app.FULL_GATES


def test_security9_is_conserved_without_an_invented_universal_gate():
    result = assess_application(application_input())
    security = [row for row in result["family_census"] if row["tier_name"] == "SECURITY"]
    assert len(security) == len(ObjectKind) == 26
    assert {row["object_kind"] for row in security} == {kind.value for kind in ObjectKind}
    assert all(row["tier"] == 9 and row["census"] == "UNKNOWN" for row in security)
    assert result["status"] == "UNKNOWN" and "CORE_FAMILY_REQUIREMENTS_UNKNOWN" in result["blockers"]
    assert "COMPOSED_SECURITY" not in result["full_gates"]
    assert "APPLICATION_COMPOSED_SECURITY_NOT_ESTABLISHED" not in result["blockers"]


def test_security9_missing_native_child_and_unselected_interactions_stay_unknown():
    from test_current_subject_security import fixture as security_fixture, replay as security_replay

    request, policy, evidence, _ = security_fixture("VERIFIER", child_status="UNKNOWN")
    native = security_replay(request, policy, evidence)[1]
    assert native["status"] == "UNKNOWN"
    assert native["security_tier_conformance"] == "NOT_ESTABLISHED"

    result = assess_application(application_input())
    security = [row for row in result["family_census"] if row["tier"] == 9]
    assert all(row["census"] == "UNKNOWN" and row["declared_instances"] == 0 for row in security)
    assert result["status"] == "UNKNOWN" and result["release_authorized"] is False


def test_security9_contract_bytes_bind_both_core_mechanisms(monkeypatch: pytest.MonkeyPatch):
    application_digest = app.mechanism_digest()
    progression_digest = tiers.mechanism_digest()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\nsource substitution" if path.name == "CORE_SECURITY9_REQUIREMENTS.md" else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert app.mechanism_digest() != application_digest
    assert tiers.mechanism_digest() != progression_digest


def test_application_external_mechanism_pin_substitution_refutes():
    data = application_input()
    repin(data)
    supplied = original_inputs(data)
    supplied["expected_mechanism_digest"] = "sha256:" + "0" * 64
    result = app.assess_core_application_release(canonical_bytes(data["selection"]), **supplied)
    assert result["status"] == "FAIL"
    assert "APPLICATION_EXTERNAL_PIN_DIFFERS" in result["blockers"]


@pytest.mark.parametrize("rank,name", [(6, "SECURITY"), (9, "GOVERNANCE"), (10, "CORRIGIBILITY"), (True, "FACETS")])
def test_wrong_named_mapping_is_refuted(rank, name):
    with pytest.raises(tiers._Refused):
        tiers.named_core_tier(rank, name)


def test_actual_native_prefix_replays_without_whole_core_qualification():
    bundle, policy, files, selected = selected_native()
    result = assess_native(bundle, policy, files, selected)
    assert result["status"] == "PASS" and result["native_replay"] == "EXECUTED"
    assert result["selected_depth"] == 2
    assert result["full_application_status"] == "UNKNOWN" and result["polished"] is False
    assert {r["tier_name"] for r in result["tiers"]} == set(tiers.CoreTier.__members__)


def test_current_coordinate_cannot_be_moved_to_security_rank():
    bundle, policy, files, selected = selected_native()
    selected["ranks"][0].update(tier=9, tier_name="SECURITY")
    selected["tiers"][0].update(census="UNKNOWN", required_nodes=[])
    selected["tiers"][8].update(census="COMPLETE", required_nodes=["representation"])
    result = assess_native(bundle, policy, files, selected, cancelled=True)
    assert result["status"] == "FAIL" and "CORE_NATIVE_COORDINATE_TIER_DIFFERS" in result["blockers"]


def test_missing_certificate_remains_unknown():
    bundle, policy, files, selected = selected_native()
    files.pop("representation.json")
    policy["artifact_files_digest"] = tiers.dag.artifact_files_digest(files)
    selected.update(policy_digest=tiers.digest(canonical_bytes(policy)), artifact_files_digest=policy["artifact_files_digest"])
    result = assess_native(bundle, policy, files, selected)
    assert result["status"] == "UNKNOWN" and result["selected_depth"] == 0


def test_proper_cancellation_remains_unknown():
    result = assess_native(*selected_native(), cancelled=True)
    assert result["status"] == "UNKNOWN" and result["native_replay"] == "NOT_RUN"


def test_artifact_refutation_survives_cancellation():
    bundle, policy, files, selected = selected_native()
    files["representation.json"] += b" "
    result = assess_native(bundle, policy, files, selected, cancelled=True)
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("facet", ["payload_digest", "operands_digest"])
def test_available_native_facet_refutation_survives_cancellation(facet):
    bundle, policy, files, selected = selected_native()
    bundle["nodes"][0]["facet_bindings"][facet] = "sha256:" + "0" * 64
    policy["nodes"] = deepcopy(bundle["nodes"])
    selected.update(bundle_digest=tiers.digest(canonical_bytes(bundle)),
                    policy_digest=tiers.digest(canonical_bytes(policy)))
    result = assess_native(bundle, policy, files, selected, cancelled=True)
    assert result["status"] == "FAIL" and "CORE_NATIVE_FACET_BINDING_DIFFERS" in result["blockers"]
    assert result["native_replay"] == "NOT_RUN"


def test_available_native_object_binding_refutation_survives_cancellation():
    bundle, policy, files, selected = selected_native()
    bundle["objects"][0]["payload"]["extra"] = "changed"
    selected.update(bundle_digest=tiers.digest(canonical_bytes(bundle)))
    result = assess_native(bundle, policy, files, selected, cancelled=True)
    assert result["status"] == "FAIL" and "CORE_NATIVE_OBJECT_BINDING_DIFFERS" in result["blockers"]


def test_application_unknown_cells_and_gates_do_not_inherit_native_pass():
    result = assess_application(application_input())
    assert result["status"] == "UNKNOWN" and result["native_status"] == "PASS"
    assert len(result["family_census"]) == 234
    assert result["required_certificate_instance_count"] is None
    assert "CORE_FAMILY_REQUIREMENTS_UNKNOWN" in result["blockers"]
    assert all(value == "UNKNOWN" for value in result["full_gates"].values())
    assert result["polished"] is False and result["release_authorized"] is False


def test_wip_extension_is_separate_and_does_not_waive_core_gaps():
    data = application_input()
    before = assess_application(data)
    data["requirements"]["extension"] = {"schema_version": app.EXTENSION, "profile_id": app.EXTENSION,
        "declared_status": "WIP", "binding_digest": "sha256:" + "0" * 64}
    result = assess_application(data)
    assert result["status"] == "UNKNOWN" and result["native_status"] == before["native_status"] == "PASS"
    assert result["full_gates"] == before["full_gates"]
    assert result["family_census"] == before["family_census"]
    assert result["extension_assessment"]["native_status"] == "NOT_RUN"
    assert result["extension_assessment"]["core_gate_role"] == "SEPARATE_EXTENSION"
    assert not any("COMPLETE_CORRIGIBILITY" in code for code in result["blockers"])


@pytest.mark.parametrize("field,value", [("profile_id", app.PROFILE), ("declared_status", "PASS"), ("schema_version", historical_app.SELECTION)])
def test_wip_or_carried_pass_requires_distinct_extension_profile(field, value):
    data = application_input()
    extension = {"schema_version": app.EXTENSION, "profile_id": app.EXTENSION,
                 "declared_status": "WIP", "binding_digest": "sha256:" + "0" * 64}
    extension[field] = value
    data["requirements"]["extension"] = extension
    result = assess_application(data)
    assert result["status"] == "FAIL" and "CORE_EXTENSION_PROFILE_DIFFERS" in result["blockers"]


def test_unknown_family_cannot_be_falsely_marked_complete_without_instances():
    data = application_input()
    next(row for row in data["requirements"]["families"] if row["object_kind"] == "MODEL")["census"] = "COMPLETE"
    result = assess_application(data)
    assert result["status"] == "FAIL" and "CORE_EMPTY_COMPLETE_FAMILY" in result["blockers"]


@pytest.mark.parametrize("change", ["omit", "duplicate", "wrong-kind", "wrong-name"])
def test_exact_family_conservation_refutes_missing_duplicate_or_misbound_cell(change):
    data = application_input()
    rows = data["requirements"]["families"]
    if change == "omit":
        rows.pop()
    elif change == "duplicate":
        rows[-1] = deepcopy(rows[0])
    elif change == "wrong-kind":
        next(row for row in rows if row["object_kind"] == "VERIFIER" and row["tier"] == 1)["object_kind"] = "MODEL"
    else:
        next(row for row in rows if row["tier"] == 6)["tier_name"] = "SECURITY"
    assert assess_application(data)["status"] == "FAIL"


def test_known_core_failure_survives_wip_extension_and_cancellation():
    data = application_input()
    data["requirements"]["extension"] = {"schema_version": app.EXTENSION, "profile_id": app.EXTENSION,
        "declared_status": "WIP", "binding_digest": "sha256:" + "0" * 64}
    data["shards"]["one"]["bundle"]["nodes"][0]["facet_bindings"]["payload_digest"] = "sha256:" + "0" * 64
    data["shards"]["one"]["policy"]["nodes"] = deepcopy(data["shards"]["one"]["bundle"]["nodes"])
    result = assess_application(data, cancelled=True)
    assert result["status"] == "FAIL"


def test_old_application_selection_is_not_implicitly_upgraded():
    original = original_application_fixture()
    historical = historical_app.assess_application_release(canonical_bytes(original["selection"]), **original_inputs(original))
    new = app.assess_core_application_release(canonical_bytes(original["selection"]), **original_inputs(original))
    assert historical["status"] == "UNKNOWN" and "COMPLETE_CORRIGIBILITY" in historical["full_gates"]
    assert new["status"] == "FAIL" and new["schema_version"] == app.ASSESSMENT


def test_core_input_is_not_accepted_by_historical_ten_module():
    data = application_input()
    result = historical_app.assess_application_release(canonical_bytes(data["selection"]), **original_inputs(data))
    assert result["status"] == "FAIL" and result["schema_version"] == historical_app.ASSESSMENT


def test_recheck_recomputes_exact_selected_input():
    data = application_input()
    report = assess_application(data)
    supplied = original_inputs(data)
    supplied["expected_mechanism_digest"] = app.mechanism_digest()
    checked = app.recheck_core_application_release(canonical_bytes(report), canonical_bytes(data["selection"]), **supplied)
    assert checked == report
    report["status"] = "PASS"
    assert app.recheck_core_application_release(canonical_bytes(report), canonical_bytes(data["selection"]), **supplied)["status"] == "FAIL"


def test_ten_native_semantic_family_cannot_be_cast_into_core():
    from test_ten_tier_native_selection import dag_input
    _, bundle, policy, files = dag_input()
    ranks = {"security": 9}
    subject = {k: policy["required_objects"][0][k] for k in ("object_id", "object_kind", "record_digest")}
    with pytest.raises(tiers._Refused, match="CORE_NATIVE_SEMANTIC_VERSION_DIFFERS"):
        tiers._graph(bundle, policy, ranks, subject)

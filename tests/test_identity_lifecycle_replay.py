"""Finite declared identity lifecycle regression fixtures."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from verifier.domains.contracts.identity_lifecycle_replay import (
    replay_declared_identity_lifecycle,
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def binding(kind="HUMAN"):
    return {
        "schema_version": "verifier-current-identity-lifecycle-binding-1",
        "identity_id": "identity-old", "identity_record_digest": "1" * 64,
        "actor_id": "actor", "representation_id": "represented",
        "represented_kind": kind, "root_human_id": "human-root", "role_id": "role",
        "collective_id": "collective", "scope": "simulation:sim" if kind == "BOT" else "scope",
        "clock_id": "declared-clock", "valid_from": 10, "valid_until": 100,
        "simulation_id": "sim" if kind == "BOT" else None,
        "simulation_record_digest": "2" * 64 if kind == "BOT" else None,
        "assurance_requirement_id": "required-assurance", "relied_attribute_ids": [],
        "revocation_policy_id": "required-revocation-policy",
        "human_exit_policy_id": "required-exit-policy" if kind == "HUMAN" else None,
    }


def history(selected_binding, tail):
    rows = [{"kind": "enrollment", "at": 10,
             "payload": {"enrollment_id": "enrollment", "support_inventory_digest": "3" * 64}}] + tail
    events = []
    previous = "0" * 64
    for position, item in enumerate(rows):
        event = {"schema_version": "verifier-current-identity-lifecycle-event-1",
                 "event_id": item.get("event_id", "event-" + str(position)),
                 "position": position, "binding_digest": digest(selected_binding),
                 "previous_event_digest": previous, "kind": item["kind"],
                 "at": item["at"], "payload": item["payload"],
                 "authority_evidence_ref": None}
        events.append(event)
        previous = digest(event)
    return events


def presentation(selected_binding, at, pid="presentation"):
    return {"schema_version": "verifier-current-identity-presentation-1",
            "presentation_id": pid, "event_id": pid + "-event",
            "binding_digest": digest(selected_binding), "enrollment_id": "enrollment",
            "at": at, "clock_id": selected_binding["clock_id"],
            "scope": selected_binding["scope"], "simulation_id": selected_binding["simulation_id"],
            "context_digest": "4" * 64, "disclosed_field_inventory_digest": "5" * 64,
            "linkability_claim": "not_selected", "linkability_support_requirement_id": None}


def present_event(row):
    return {"kind": "presentation", "at": row["at"], "event_id": row["event_id"],
            "payload": {"presentation_id": row["presentation_id"], "presentation_digest": digest(row)}}


def revoke(at):
    return {"kind": "revocation", "at": at,
            "payload": {"revocation_id": "revocation", "reason_ref": "sha256:" + "6" * 64}}


def replay(selected_binding, events, rows=(), evaluation_at=50, **overrides):
    kwargs = {"expected_binding_digest": digest(selected_binding),
              "expected_events_digest": digest(events),
              "expected_presentations_digest": digest(list(rows)),
              "initial_event_anchor": "0" * 64, "evaluation_at": evaluation_at,
              "renewal_ceiling": 200}
    kwargs.update(overrides)
    return replay_declared_identity_lifecycle(selected_binding, events, list(rows), **kwargs)


def test_declared_grammar_pass_does_not_grant_authority_or_closure():
    b = binding()
    result = replay(b, history(b, []))
    assert result["consistency_status"] == "PASS"
    assert result["declared_reliance_eligibility"] == "PASS"
    assert result["authority_status"] == result["closure_status"] == "UNKNOWN"
    assert result["selected_protocol_status"] == "UNKNOWN"
    assert result["public_checkability"] == "NOT_ESTABLISHED"


def test_prospective_revocation_retains_earlier_presentation_and_valid_history():
    b = binding()
    row = presentation(b, 20)
    events = history(b, [present_event(row), revoke(30)])
    original = copy.deepcopy((b, events, row))
    result = replay(b, events, [row], evaluation_at=40)
    assert result["consistency_status"] == "PASS"
    assert result["presentation_results"][0]["declared_binding_eligibility"] == "PASS"
    assert result["declared_reliance_eligibility"] == "FAIL"
    assert (b, events, row) == original


def test_equal_time_terminal_wins_even_if_serialized_after_presentation():
    b = binding()
    row = presentation(b, 30)
    result = replay(b, history(b, [present_event(row), revoke(30)]), [row])
    assert result["consistency_status"] == "FAIL"
    assert result["presentation_results"][0]["declared_binding_eligibility"] == "FAIL"


@pytest.mark.parametrize("at, expected", [(10, "PASS"), (99, "PASS"), (100, "FAIL")])
def test_validity_is_half_open_without_expiry_event(at, expected):
    b = binding()
    row = presentation(b, at)
    result = replay(b, history(b, [present_event(row)]), [row], evaluation_at=at)
    assert result["consistency_status"] == expected
    assert result["presentation_results"][0]["declared_binding_eligibility"] == expected


def test_renewal_extends_only_while_original_binding_is_active():
    b = binding()
    row = presentation(b, 120)
    tail = [{"kind": "renewal", "at": 90,
             "payload": {"new_valid_until": 150, "support_inventory_digest": "7" * 64}},
            present_event(row)]
    result = replay(b, history(b, tail), [row], evaluation_at=130)
    assert result["consistency_status"] == "PASS"
    assert result["current_valid_until"] == 150
    assert result["closure_status"] == "UNKNOWN"
    tail[0]["at"] = 100
    assert replay(b, history(b, tail), [row])["consistency_status"] == "FAIL"


def test_rehashed_carrier_cannot_substitute_externally_selected_binding():
    b = binding()
    selected = digest(b)
    forged = copy.deepcopy(b)
    forged["representation_id"] = "another-bearer"
    result = replay(forged, history(forged, []), expected_binding_digest=selected)
    assert result["consistency_status"] == "FAIL"


def test_coherent_rehash_does_not_repair_event_chain_or_scope_substitution():
    b = binding()
    row = presentation(b, 20)
    row["scope"] = "wider-scope"
    events = history(b, [present_event(row)])
    assert replay(b, events, [row])["consistency_status"] == "FAIL"
    events = history(b, [revoke(30)])
    events[1]["previous_event_digest"] = "9" * 64
    assert replay(b, events)["consistency_status"] == "FAIL"


def test_bot_sim_terminal_requires_exact_declared_sim_and_still_needs_support():
    b = binding("BOT")
    event = {"kind": "simulation_end", "at": 30,
             "payload": {"simulation_id": "sim", "simulation_record_digest": "2" * 64,
                         "simulation_event_ref": "sha256:" + "8" * 64}}
    result = replay(b, history(b, [event]), evaluation_at=40)
    assert result["consistency_status"] == "PASS"
    assert result["declared_reliance_eligibility"] == "FAIL"
    assert result["selected_protocol_status"] == result["closure_status"] == "UNKNOWN"
    event["payload"]["simulation_id"] = "another-sim"
    assert replay(b, history(b, [event]))["consistency_status"] == "FAIL"


def test_agent_is_supported_without_inventing_human_authenticity():
    b = binding("AGENT")
    result = replay(b, history(b, []))
    assert result["consistency_status"] == "PASS"
    assert "human_authenticity" in result["not_established"]


def test_handover_cannot_mutate_old_identity_and_missing_pair_is_not_full_pass():
    b = binding()
    event = {"kind": "handover_out", "at": 30,
             "payload": {"handover_id": "handover", "replacement_identity_id": "identity-new",
                         "replacement_binding_digest": "a" * 64, "handover_pair_digest": "b" * 64}}
    result = replay(b, history(b, [event]), evaluation_at=40)
    assert result["consistency_status"] == "PASS"
    assert result["declared_reliance_eligibility"] == "FAIL"
    assert result["selected_protocol_status"] == "UNKNOWN"
    assert any("paired replacement" in x for x in result["missing_support"])
    event["payload"]["replacement_identity_id"] = b["identity_id"]
    assert replay(b, history(b, [event]))["consistency_status"] == "FAIL"


def test_human_exit_record_does_not_prove_unilateral_enforcement():
    b = binding()
    event = {"kind": "human_exit", "at": 30,
             "payload": {"exit_request_ref": "sha256:" + "a" * 64,
                         "exit_control_rule_digest": "b" * 64}}
    result = replay(b, history(b, [event]), evaluation_at=40)
    assert result["consistency_status"] == "PASS"
    assert result["declared_reliance_eligibility"] == "FAIL"
    assert result["closure_status"] == "UNKNOWN"
    assert any("exit and enforcement" in x for x in result["missing_support"])


def test_unknown_protocol_and_absent_clock_selection_are_not_green_closure():
    b = binding()
    events = history(b, [])
    result = replay(b, events, evaluation_at=None)
    assert result["declared_reliance_eligibility"] == "UNKNOWN"
    events[0]["kind"] = "candidate-invented-event"
    assert replay(b, events)["consistency_status"] == "UNKNOWN"


def test_budget_exhaustion_keeps_prior_refutation_and_grants_no_partial_rows():
    b = binding()
    row = presentation(b, 40)
    tail = [revoke(30), present_event(row)]
    # Find no guessed cost: use the full draft's reported work count, then remove
    # one unit so the completed-event contradiction precedes second-phase abort.
    full = replay(b, history(b, tail), [row])
    assert full["consistency_status"] == "FAIL"
    bounded = replay(b, history(b, tail), [row], max_steps=full["steps"] - 2)
    assert bounded["consistency_status"] == "FAIL"
    assert bounded["violations"]
    assert bounded["presentation_results"] == []
    assert bounded["declared_reliance_eligibility"] == "UNKNOWN"


def test_bool_time_is_not_an_integer_and_selected_limits_are_not_candidate_fields():
    b = binding()
    b["valid_from"] = True
    assert replay(b, history(b, []))["consistency_status"] == "FAIL"
    with pytest.raises(ValueError):
        replay(binding(), history(binding(), []), max_steps=True)


@pytest.mark.parametrize("missing, malformed", [("binding", "events"), ("presentations", "binding"),
                                                ("events", "presentations")])
def test_missing_companion_does_not_hide_supported_present_record_grammar(missing, malformed):
    b = binding()
    events, rows = history(b, []), []
    if malformed == "binding":
        b["valid_from"] = True
        events = history(b, [])
    elif malformed == "events":
        events[0]["position"] = True
    else:
        rows = [presentation(b, True)]
    kwargs = dict(expected_binding_digest=digest(b), expected_events_digest=digest(events),
        expected_presentations_digest=digest(rows), initial_event_anchor="0" * 64,
        evaluation_at=50, renewal_ceiling=200)
    values = {"binding": b, "events": events, "presentations": rows}
    values[missing] = None
    result = replay_declared_identity_lifecycle(**values, **kwargs)
    assert result["consistency_status"] == "FAIL"
    assert result["presentation_results"] == []
    assert result["declared_reliance_eligibility"] == "UNKNOWN"


def test_unsupported_binding_does_not_mask_supported_event_plain_position_refutation():
    b = binding()
    b["schema_version"] = "unsupported-binding-protocol"
    events = history(b, [])
    events[0]["position"] = True
    result = replay(b, events)
    assert result["consistency_status"] == "FAIL"
    assert any("unsupported selected binding" in reason for reason in result["missing_support"])


@pytest.mark.parametrize("missing", ["presentations", "anchor"])
def test_available_binding_and_events_still_refute_bad_renewal_without_missing_completion(missing):
    b = binding()
    events = history(b, [{"kind": "renewal", "at": 50,
        "payload": {"new_valid_until": 90, "support_inventory_digest": "7" * 64}}])
    result = replay_declared_identity_lifecycle(b, events, None if missing == "presentations" else [],
        expected_binding_digest=digest(b), expected_events_digest=digest(events),
        expected_presentations_digest=digest([]), initial_event_anchor=None if missing == "anchor" else "0" * 64,
        evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "FAIL"
    assert any("renewal extension" in reason for reason in result["violations"])


@pytest.mark.parametrize("missing", ["binding", "events", "presentations", "anchor"])
def test_coherent_partial_records_grant_no_completion_or_eligibility(missing):
    b, events, rows = binding(), history(binding(), []), []
    values = {"binding": b, "events": events, "presentations": rows}
    if missing != "anchor":
        values[missing] = None
    result = replay_declared_identity_lifecycle(**values, expected_binding_digest=digest(b),
        expected_events_digest=digest(events), expected_presentations_digest=digest(rows),
        initial_event_anchor=None if missing == "anchor" else "0" * 64, evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "UNKNOWN"
    assert result["declared_reliance_eligibility"] == "UNKNOWN"
    assert result["presentation_results"] == []


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
@pytest.mark.parametrize("prior_refutation", [False, True])
def test_real_retained_hash_resource_site_preserves_prior_evaluated_refutation(error, prior_refutation, monkeypatch):
    from verifier.domains.contracts import identity_lifecycle_replay as module
    b = binding()
    row = presentation(b, 40)
    events = history(b, ([revoke(30)] if prior_refutation else []) + [present_event(row)])
    kwargs = dict(expected_binding_digest=digest(b), expected_events_digest=digest(events),
        expected_presentations_digest=digest([row]), initial_event_anchor="0" * 64,
        evaluation_at=50, renewal_ceiling=200)
    original, calls = module._digest, 0
    def retained_hash(value):
        nonlocal calls
        if value is row:
            calls += 1
            if calls == 2:  # actual dependent presentation content hash
                raise error("retained canonical hash capacity unavailable")
        return original(value)
    monkeypatch.setattr(module, "_digest", retained_hash)
    result = module.replay_declared_identity_lifecycle(b, events, [row], **kwargs)
    assert result["consistency_status"] == ("FAIL" if prior_refutation else "UNKNOWN")
    assert result["checking_unavailable"] is True
    assert result["presentation_results"] == []
    assert result["declared_reliance_eligibility"] == "UNKNOWN"


def test_retained_plain_depth_is_fenced_before_hash(monkeypatch):
    from verifier.domains.contracts import identity_lifecycle_replay as module
    deep = 0
    for _ in range(65):
        deep = [deep]
    def forbidden(_):
        raise AssertionError("recursive canonical hash before retained depth fence")
    monkeypatch.setattr(module, "_digest", forbidden)
    result = module.replay_declared_identity_lifecycle(deep, None, None,
        expected_binding_digest="1" * 64, expected_events_digest="2" * 64,
        expected_presentations_digest="3" * 64, initial_event_anchor="0" * 64,
        evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "UNKNOWN"


@pytest.mark.parametrize("field, false_value", [("binding_digest", "9" * 64), ("clock_id", "other-clock"),
                                               ("scope", "other-scope"), ("simulation_id", "other-sim")])
@pytest.mark.parametrize("events_available", [False, "unsupported"])
def test_supported_present_row_binding_refutation_precedes_missing_or_unsupported_events(field, false_value, events_available):
    b = binding()
    row = presentation(b, 20)
    row[field] = false_value
    events = history(b, [])
    if events_available:
        events[0]["schema_version"] = "unsupported-event-protocol"
    result = replay_declared_identity_lifecycle(b, events if events_available else None, [row],
        expected_binding_digest=digest(b), expected_events_digest=digest(events),
        expected_presentations_digest=digest([row]), initial_event_anchor="0" * 64,
        evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "FAIL"
    assert result["presentation_results"] == []
    assert result["declared_reliance_eligibility"] == "UNKNOWN"


def test_unrelated_unsupported_row_does_not_mask_supported_row_clock_refutation():
    b = binding()
    unsupported = presentation(b, 20, pid="unsupported")
    unsupported["schema_version"] = "unsupported-presentation-protocol"
    false = presentation(b, 30, pid="supported")
    false["clock_id"] = "other-clock"
    rows = [unsupported, false]
    result = replay_declared_identity_lifecycle(b, None, rows, expected_binding_digest=digest(b),
        expected_events_digest=digest(history(b, [])), expected_presentations_digest=digest(rows),
        initial_event_anchor="0" * 64, evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "FAIL"
    assert any("unsupported selected presentation" in reason for reason in result["missing_support"])


def test_unsupported_binding_supplies_no_clock_scope_or_sim_relation_acceptance():
    b = binding()
    b["schema_version"] = "unsupported-binding-protocol"
    row = presentation(b, 20)
    row.update(clock_id="other-clock", scope="other-scope", simulation_id="other-sim")
    result = replay_declared_identity_lifecycle(b, None, [row], expected_binding_digest=digest(b),
        expected_events_digest=digest(history(b, [])), expected_presentations_digest=digest([row]),
        initial_event_anchor="0" * 64, evaluation_at=50, renewal_ceiling=200)
    assert result["consistency_status"] == "UNKNOWN"
    assert result["declared_reliance_eligibility"] == "UNKNOWN"
    assert result["presentation_results"] == []

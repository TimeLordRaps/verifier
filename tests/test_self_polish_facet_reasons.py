from __future__ import annotations

from copy import deepcopy
import hashlib

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import ObjectKind
from verifier.domains import inventory
from verifier.domains.contracts import application_requirements, typed_facets
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_facet_reasons as reasons


FACETS = (
    "identifier",
    "admitted_kind",
    "canonical_payload",
    "named_ordered_operand_map",
    "declared_typed_composition",
)

DOMAIN_ROUTE_REASONS = {
    "AGENT-1.8": ("AGENT", "agent_harness_binding_surface"),
    "BENCH-1.2": ("BENCH", "bench_problem_inventory"),
    "BENCH-1.4": ("BENCH", "bench_oracle_execution"),
    "BOT-1.6": ("BOT", "bot_child_binding"),
    "DATA-1.2": ("DATA", "selected_retained_data_inventory"),
    "DATA-1.4": ("DATA", "data_record_schema"),
    "ENV-1.2": ("ENV", "env_software_inventory_closure"),
    "ENV-1.3": ("ENV", "env_entrypoint_interpreter_binding"),
    "ENV-1.4": ("ENV", "env_required_configuration_surface"),
    "ENV-1.5": ("ENV", "env_retained_configuration"),
    "HARDWARE-1.2": ("HARDWARE", "hardware_containment_topology"),
    "HARDWARE-1.3": ("HARDWARE", "hardware_device_inventory"),
    "HARNESS-1.6": ("HARNESS", "harness_observation_surface"),
    "MODEL-1.2": ("MODEL", "model_dense_tensor_shape_contract"),
    "MODEL-1.5": ("MODEL", "model_artifact_dependency_binding"),
    "TRAIN-1.2": ("TRAIN", "train_configuration_contract"),
    "TRAIN-1.3": ("TRAIN", "train_checkpoint_inventory_shape"),
    "TRAIN-1.5": ("TRAIN", "train_data_shard_batch_bridge"),
}


def _unchanged_declaration_reason_assessment() -> dict[str, object]:
    """Measure what the pre-ledger declarations actually establish."""
    kinds = tuple(kind.value for kind in ObjectKind)
    structural = application_requirements.installed_families(list(kinds))
    routes = core_tier_progression.installed_core_route_inventory()
    tier1_slots = [row for row in inventory.slot_inventory() if row["tier"] == 1]
    assert all(row["applicability"] == "REQUIRED" for row in tier1_slots)
    assert all(
        row["rationale_status"]
        == "PLANNING_CONTEXT_NOT_NUMBERED_REQUIREMENTS"
        for row in tier1_slots
    )
    denominators = {
        "facet_choice_count": len(kinds) * len(FACETS),
        "structural_membership_count": sum(
            len(row["members"]) for row in structural
        ),
        "route_membership_count": routes[
            "registered_route_membership_count_by_tier"
        ]["1"],
        "slot_count": len(tier1_slots),
    }
    # REQUIRED declarations and planning-context slot prose are not authored,
    # per-choice reasons and therefore qualify for none of the denominators.
    return {
        "status": "UNKNOWN",
        "denominators": denominators,
        "qualifying_reason_counts": {key: 0 for key in denominators},
        "reason_deficits": dict(denominators),
    }


def test_unchanged_required_declarations_do_not_clear_reason_gate() -> None:
    assessment = _unchanged_declaration_reason_assessment()
    assert assessment == {
        "status": "UNKNOWN",
        "denominators": {
            "facet_choice_count": 130,
            "structural_membership_count": 52,
            "route_membership_count": 45,
            "slot_count": 26,
        },
        "qualifying_reason_counts": {
            "facet_choice_count": 0,
            "structural_membership_count": 0,
            "route_membership_count": 0,
            "slot_count": 0,
        },
        "reason_deficits": {
            "facet_choice_count": 130,
            "structural_membership_count": 52,
            "route_membership_count": 45,
            "slot_count": 26,
        },
    }


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _resign_ledger(ledger: dict[str, object]) -> None:
    ledger["ledger_digest"] = _digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )


def _resign_domain_route_reason(row: dict[str, object]) -> None:
    row["route_reason_digest"] = _digest(
        {key: value for key, value in row.items() if key != "route_reason_digest"}
    )


def test_installed_ledger_has_exact_reason_and_projection_denominators() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    assert ledger["schema_version"] == reasons.LEDGER_SCHEMA
    assert ledger["semantic_facets"] == list(FACETS)
    assert ledger["object_kind_count"] == 26
    assert ledger["tier"] == 1
    assert ledger["facet_choice_count"] == len(ledger["choices"]) == 130
    assert len({row["choice_id"] for row in ledger["choices"]}) == 130
    assert {row["choice"] for row in ledger["choices"]} == {"NECESSARY"}
    assert all(len(row["reason"]) >= 80 for row in ledger["choices"])
    assert all(row["counterfactual_consequence"] for row in ledger["choices"])
    assert ledger["structural_projection_count"] == 52
    assert ledger["route_projection_count"] == 45
    assert ledger["slot_projection_count"] == 26
    assert ledger["domain_route_reason_count"] == 18
    assert len(ledger["domain_route_reasons"]) == 18
    assert ledger["domain_route_reasons_digest"] == _digest(
        ledger["domain_route_reasons"]
    )
    assert ledger["structural_projection_digest"] == _digest(
        ledger["structural_projection"]
    )
    assert ledger["route_projection_digest"] == _digest(ledger["route_projection"])
    assert ledger["slot_projection_digest"] == _digest(ledger["slot_projection"])
    assert ledger["polished"] is False
    assert ledger["release_authorized"] is False


def test_every_kind_facet_identity_is_present_once() -> None:
    choices = reasons.installed_facet_reason_ledger()["choices"]
    assert {
        (row["object_kind"], row["tier"], row["facet"]) for row in choices
    } == {
        (kind.value, 1, facet) for kind in ObjectKind for facet in FACETS
    }


def test_primitive_composition_reasons_bind_explicit_empty_role_constraint() -> None:
    choices = reasons.installed_facet_reason_ledger()["choices"]
    primitive_composition = [
        row
        for row in choices
        if row["object_kind"] in reasons.PRIMITIVE_KINDS
        and row["facet"] == "declared_typed_composition"
    ]
    assert len(primitive_composition) == len(reasons.PRIMITIVE_KINDS) == 12
    assert all("explicit empty-role constraint" in row["reason"] for row in primitive_composition)
    assert all("cannot be inferred as N/A" in row["reason"] for row in primitive_composition)


def test_installed_assessment_replays_all_reasons_and_projections() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    result = reasons.installed_facet_reason_assessment()
    assert result["status"] == result["reason_completeness_status"] == "PASS"
    assert result["facet_choice_reason_status"] == "PASS"
    assert result["domain_route_reason_status"] == "PASS"
    assert result["structural_projection_status"] == "PASS"
    assert result["route_projection_status"] == "PASS"
    assert result["slot_projection_status"] == "PASS"
    assert result["source_binding_status"] == "PASS"
    assert result["facet_choice_denominator"] == 130
    assert result["qualifying_facet_choice_reason_count"] == 130
    assert result["facet_choice_reason_deficit"] == 0
    assert result["structural_membership_denominator"] == 52
    assert result["reasoned_structural_membership_count"] == 52
    assert result["structural_membership_reason_deficit"] == 0
    assert result["reasoned_structural_membership_digest"] == ledger[
        "structural_projection_digest"
    ]
    assert result["route_membership_denominator"] == 45
    assert result["domain_route_reason_denominator"] == 18
    assert result["qualifying_domain_route_reason_count"] == 18
    assert result["domain_route_reason_deficit"] == 0
    assert result["reasoned_route_membership_count"] == 45
    assert result["route_membership_reason_deficit"] == 0
    assert result["reasoned_route_membership_digest"] == ledger[
        "route_projection_digest"
    ]
    assert result["slot_denominator"] == 26
    assert result["reasoned_slot_count"] == 26
    assert result["slot_reason_deficit"] == 0
    assert result["reasoned_slot_digest"] == ledger["slot_projection_digest"]
    assert result["ledger_digest"] == ledger["ledger_digest"]
    assert result["blockers"] == []
    assert result["polished"] is False
    assert result["release_authorized"] is False


def test_no_reason_rows_preserve_exact_unknown_deficits() -> None:
    result = reasons.assess_facet_reason_choices([])
    assert result["status"] == result["reason_completeness_status"] == "UNKNOWN"
    assert result["qualifying_facet_choice_reason_count"] == 0
    assert result["facet_choice_reason_deficit"] == 130
    assert result["reasoned_structural_membership_count"] == 0
    assert result["structural_membership_reason_deficit"] == 52
    assert result["reasoned_route_membership_count"] == 0
    assert result["route_membership_reason_deficit"] == 45
    assert result["reasoned_slot_count"] == 0
    assert result["slot_reason_deficit"] == 26
    assert "FACET_REASONS_INCOMPLETE" in result["blockers"]


def test_omitted_domain_route_argument_means_no_route_reasons() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    result = reasons.assess_facet_reason_choices(ledger["choices"])
    assert result["status"] == "UNKNOWN"
    assert result["facet_choice_reason_status"] == "PASS"
    assert result["domain_route_reason_status"] == "UNKNOWN"
    assert result["qualifying_domain_route_reason_count"] == 0
    assert result["domain_route_reason_deficit"] == 18
    assert result["reasoned_route_membership_count"] == 27
    assert result["reasoned_slot_count"] == 17
    assert "DOMAIN_ROUTE_REASONS_MISSING" in result["blockers"]


def test_missing_choice_is_unknown_and_does_not_infer_not_applicable() -> None:
    choices = deepcopy(reasons.installed_facet_reason_ledger()["choices"])
    choices.pop()
    result = reasons.assess_facet_reason_choices(choices)
    assert result["status"] == "UNKNOWN"
    assert result["qualifying_facet_choice_reason_count"] == 129
    assert result["facet_choice_reason_deficit"] == 1
    assert result["reasoned_structural_membership_count"] < 52
    assert result["reasoned_route_membership_count"] < 45
    assert result["reasoned_slot_count"] < 26
    assert "FACET_REASON_CHOICES_MISSING" in result["blockers"]


def test_blank_reason_is_unknown_not_necessary_or_not_applicable() -> None:
    choices = deepcopy(reasons.installed_facet_reason_ledger()["choices"])
    choices[0]["reason"] = ""
    choices[0]["reason_digest"] = _digest("")
    choices[0]["choice_digest"] = _digest(
        {key: value for key, value in choices[0].items() if key != "choice_digest"}
    )
    result = reasons.assess_facet_reason_choices(choices)
    assert result["status"] == "UNKNOWN"
    assert result["qualifying_facet_choice_reason_count"] == 129
    assert result["facet_choice_reason_deficit"] == 1
    assert "FACET_REASON_TEXT_MISSING" in result["blockers"]


def test_blank_reason_does_not_bypass_non_reason_integrity() -> None:
    installed = reasons.installed_facet_reason_ledger()["choices"]

    def blanked() -> list[dict[str, object]]:
        rows = deepcopy(installed)
        rows[0]["reason"] = ""
        rows[0]["reason_digest"] = _digest("")
        rows[0]["choice_digest"] = _digest(
            {key: value for key, value in rows[0].items() if key != "choice_digest"}
        )
        return rows

    wrong_choice = blanked()
    wrong_choice[0]["choice"] = "NOT_NECESSARY"
    wrong_choice[0]["choice_digest"] = _digest(
        {
            key: value
            for key, value in wrong_choice[0].items()
            if key != "choice_digest"
        }
    )
    assert reasons.assess_facet_reason_choices(wrong_choice)["status"] == "FAIL"

    wrong_source = blanked()
    wrong_source[0]["source_binding_digest"] = "sha256:" + "0" * 64
    wrong_source[0]["choice_digest"] = _digest(
        {
            key: value
            for key, value in wrong_source[0].items()
            if key != "choice_digest"
        }
    )
    assert reasons.assess_facet_reason_choices(wrong_source)["status"] == "FAIL"

    wrong_basis = blanked()
    wrong_basis[0]["basis"]["facet_definition"] = "substituted"
    wrong_basis[0]["basis_digest"] = _digest(wrong_basis[0]["basis"])
    wrong_basis[0]["choice_digest"] = _digest(
        {
            key: value
            for key, value in wrong_basis[0].items()
            if key != "choice_digest"
        }
    )
    assert reasons.assess_facet_reason_choices(wrong_basis)["status"] == "FAIL"

    wrong_provenance = blanked()
    wrong_provenance[0]["provenance"]["reason_model"] = "SUBSTITUTED"
    wrong_provenance[0]["provenance_digest"] = _digest(
        wrong_provenance[0]["provenance"]
    )
    wrong_provenance[0]["choice_digest"] = _digest(
        {
            key: value
            for key, value in wrong_provenance[0].items()
            if key != "choice_digest"
        }
    )
    assert reasons.assess_facet_reason_choices(wrong_provenance)["status"] == "FAIL"

    bad_choice_digest = blanked()
    bad_choice_digest[0]["choice_digest"] = "sha256:" + "f" * 64
    assert reasons.assess_facet_reason_choices(bad_choice_digest)["status"] == "FAIL"


def test_source_coordinates_bind_exact_generic_and_typed_authorities() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    required_sources = {
        "core/namespace.py",
        "domains/contracts/object_facets.py",
        "domains/contracts/facet_coverage.py",
        "domains/contracts/typed_facets.py",
        "standard/NAMESPACE_OBJECTS.md",
        "standard/CURRENT_OBJECT_FACETS.md",
        "standard/CURRENT_TYPED_FACETS.md",
        "standard/FACET_OBLIGATION_DERIVATION.md",
    }
    assert required_sources <= set(ledger["source_bindings"])
    expected_roles = {
        "identifier": {"generic_object"},
        "canonical_payload": {"generic_object"},
        "admitted_kind": {"generic_object", "typed_composition"},
        "named_ordered_operand_map": {"generic_object", "typed_composition"},
        "declared_typed_composition": {"typed_composition"},
    }
    for row in ledger["choices"]:
        bindings = row["basis"]["source_coordinate_bindings"]
        assert {binding["authority_role"] for binding in bindings} == expected_roles[
            row["facet"]
        ]
        for binding in bindings:
            if binding["authority_role"] == "generic_object":
                assert binding["coordinate"] == "OBJECT-1.1"
                assert binding["checker_source"] == "domains/contracts/object_facets.py"
                assert binding["specification_source"] == (
                    "standard/CURRENT_OBJECT_FACETS.md"
                )
            else:
                assert binding["coordinate"] == typed_facets.coordinate(
                    row["object_kind"]
                )
                assert binding["checker_source"] == "domains/contracts/typed_facets.py"
                assert binding["specification_source"] == (
                    "standard/CURRENT_TYPED_FACETS.md"
                )
            assert binding["checker_source_digest"] == ledger["source_bindings"][
                binding["checker_source"]
            ]
            assert binding["specification_source_digest"] == ledger[
                "source_bindings"
            ][binding["specification_source"]]


def test_structural_projection_is_generic_four_plus_declared_typed_only() -> None:
    choices = reasons.installed_facet_reason_ledger()["choices"]
    for row in choices:
        coordinates = {
            identity["coordinate"] for identity in row["mapped_structural_identities"]
        }
        if row["facet"] == "declared_typed_composition":
            assert coordinates == {typed_facets.coordinate(row["object_kind"])}
        else:
            assert coordinates == {"OBJECT-1.1"}


def test_nonprimitive_reasons_expose_exact_installed_role_contracts() -> None:
    expected_fixed_roles = {
        "ACTOR": {"representation": {"HUMAN", "AGENT", "BOT"}, "root_human": {"HUMAN"}},
        "COLLECTIVE": {"roles": {"ROLE"}},
        "IDENTITY": {"actor": {"ACTOR"}, "role": {"ROLE"}},
        "OWNER": {"actor": {"ACTOR"}, "object": {kind.value for kind in ObjectKind}},
        "RECEIPT": {"subject": {kind.value for kind in ObjectKind}, "hardware": {"HARDWARE"}},
        "EVENT": {"time": {"TIME"}, "space": {"SPACE"}, "meaning": {kind.value for kind in ObjectKind}},
        "BENCH": {"verifier": {"VERIFIER"}, "data": {"DATA"}},
        "TRAIN": {"data": {"DATA"}, "events": {"EVENT"}, "bench": {"BENCH"}, "arch": {"ARCH"}},
        "MODEL": {"train": {"TRAIN"}, "data": {"DATA"}, "events": {"EVENT"}, "bench": {"BENCH"}, "arch": {"ARCH"}, "env": {"ENV"}, "hardware": {"HARDWARE"}},
        "AGENT": {"model": {"MODEL"}, "harness": {"HARNESS"}, "env": {"ENV"}},
        "SIM": {"data": {"DATA"}, "verifier": {"VERIFIER"}, "objects": {kind.value for kind in ObjectKind}, "env": {"ENV"}},
        "BOT": {"agent": {"AGENT"}, "sim": {"SIM"}, "env": {"ENV"}},
    }
    choices = reasons.installed_facet_reason_ledger()["choices"]
    for kind in sorted({kind.value for kind in ObjectKind} - reasons.PRIMITIVE_KINDS):
        rows = [row for row in choices if row["object_kind"] == kind]
        contract = rows[0]["basis"]["role_contract"]
        assert rows[0]["basis"]["typed_registration"] == typed_facets.registration(kind)
        assert contract["total_target_count_max"] == 4096
        assert "minimum" in contract["contract_text"]
        assert "maximum" in contract["contract_text"]
        assert "4,096" in contract["contract_text"]
        if kind in expected_fixed_roles:
            assert {role["name"] for role in contract["roles"]} == set(
                expected_fixed_roles[kind]
            )
            for role in contract["roles"]:
                assert role["minimum_direct_targets"] == 1
                assert role["maximum_direct_targets"] == 4096
                assert set(role["target_kinds"]) == expected_fixed_roles[kind][
                    role["name"]
                ]
                assert role["name"] in contract["contract_text"]
                assert all(
                    target in contract["contract_text"]
                    for target in role["target_kinds"]
                )
        elif kind == "GRAPH":
            assert contract["role_name_mode"] == "EXACT"
            assert [role["name"] for role in contract["roles"]] == ["members"]
            assert "element_kind" in contract["contract_text"]
            assert "nested" in contract["contract_text"]
        elif kind == "HYPER":
            assert contract["role_name_mode"] == "DECLARED_NONEMPTY"
            assert contract["role_count_min"] == 1
            assert contract["role_count_max"] == 4096
            assert set(contract["dynamic_target_kinds"]) == {
                kind.value for kind in ObjectKind
            }
        else:
            raise AssertionError(kind)
        for facet in (
            "admitted_kind",
            "named_ordered_operand_map",
            "declared_typed_composition",
        ):
            row = next(item for item in rows if item["facet"] == facet)
            assert contract["contract_text"] in row["reason"]


def test_routes_are_not_blanket_attributed_to_every_facet() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    mapped = {
        (identity["object_kind"], identity["coordinate"])
        for row in ledger["choices"]
        for identity in row["mapped_route_identities"]
    }
    typed = {
        (kind.value, typed_facets.coordinate(kind.value)) for kind in ObjectKind
    }
    expected_mapped = {("OBJECT", "OBJECT-1.1"), *typed}
    assert mapped == expected_mapped
    assert ledger["mapped_route_projection_count"] == 27
    assert ledger["unmatched_route_projection_count"] == 18
    assert {
        row["coordinate"] for row in ledger["unmatched_route_projection"]
    } == {
        "AGENT-1.8",
        "BENCH-1.2",
        "BENCH-1.4",
        "BOT-1.6",
        "DATA-1.2",
        "DATA-1.4",
        "ENV-1.2",
        "ENV-1.3",
        "ENV-1.4",
        "ENV-1.5",
        "HARDWARE-1.2",
        "HARDWARE-1.3",
        "HARNESS-1.6",
        "MODEL-1.2",
        "MODEL-1.5",
        "TRAIN-1.2",
        "TRAIN-1.3",
        "TRAIN-1.5",
    }
    assert {
        row["object_kind"] for row in ledger["unmatched_route_projection"]
    } == {
        "AGENT",
        "BENCH",
        "BOT",
        "DATA",
        "ENV",
        "HARDWARE",
        "HARNESS",
        "MODEL",
        "TRAIN",
    }
    for row in ledger["choices"]:
        identities = {
            _digest(identity) for identity in row["mapped_route_identities"]
        }
        rationales = row["route_mapping_rationales"]
        assert {item["route_identity_digest"] for item in rationales} == identities
        assert all(item["mapping_rationale"].strip() for item in rationales)
        assert all(
            item["authority_basis_digest"] == _digest(item["authority_basis"])
            for item in rationales
        )
    result = reasons.installed_facet_reason_assessment()
    assert result["status"] == "PASS"
    assert result["facet_choice_reason_status"] == "PASS"
    assert result["qualifying_facet_choice_reason_count"] == 130
    assert result["domain_route_reason_status"] == "PASS"
    assert result["route_projection_status"] == "PASS"
    assert result["reasoned_route_membership_count"] == 45
    assert result["route_membership_reason_deficit"] == 0
    assert result["reasoned_slot_count"] == 26
    assert result["slot_reason_deficit"] == 0


def test_domain_route_reasons_are_separate_exact_and_source_bound() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    rows = ledger["domain_route_reasons"]
    assert {
        row["coordinate"]: (row["object_kind"], row["category"]) for row in rows
    } == DOMAIN_ROUTE_REASONS
    assert not ({row["route_reason_id"] for row in rows} & {
        row["choice_id"] for row in ledger["choices"]
    })
    for row in rows:
        assert row["choice"] == "NECESSARY"
        assert row["tier"] == 1
        assert row["mapped_route_identity"]["coordinate"] == row["coordinate"]
        assert row["mapped_route_identity"]["object_kind"] == row["object_kind"]
        assert row["basis"]["route_registration"]["objective"] == row["coordinate"]
        assert row["basis"]["route_registration"]["represented_kind_rule"] == (
            row["object_kind"]
        )
        assert row["basis"]["route_registration"]["scope"] == (
            row["mapped_route_identity"]["scope"]
        )
        assert row["basis"]["route_registration"]["proposition_digest"] == (
            row["mapped_route_identity"]["proposition_digest"]
        )
        assert row["basis"]["checking_mechanism"] == (
            row["mapped_route_identity"]["checking_mechanism"]
        )
        checker_source = row["basis"]["checker_source"]
        assert row["basis"]["checker_source_digest"] == ledger["source_bindings"][
            checker_source
        ]
        assert row["basis"]["route_registry_source_digest"] == ledger[
            "source_bindings"
        ]["domains/contracts/current_object_routes.py"]
        assert "Tier 1" in row["reason"]
        assert row["coordinate"] in row["reason"]
        assert "structurally valid" in row["reason"]
        assert row["counterfactual_consequence"].startswith("Without ")
        assert row["reason_digest"] == _digest(row["reason"])
        assert row["basis_digest"] == _digest(row["basis"])
        assert row["provenance_digest"] == _digest(row["provenance"])
        assert row["route_reason_digest"] == _digest(
            {key: value for key, value in row.items() if key != "route_reason_digest"}
        )
    data_inventory = next(row for row in rows if row["coordinate"] == "DATA-1.2")
    assert data_inventory["basis"]["domain_property_id"] == (
        "selected_retained_data_inventory"
    )
    assert data_inventory["basis"]["domain_property_source"] == (
        "domains/contracts/facet_coverage.py"
    )


def test_missing_domain_route_reason_is_unknown_and_blocks_its_slot() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    route_reasons = deepcopy(ledger["domain_route_reasons"])
    removed = route_reasons.pop(0)
    result = reasons.assess_facet_reason_choices(ledger["choices"], route_reasons)
    assert result["status"] == "UNKNOWN"
    assert result["facet_choice_reason_status"] == "PASS"
    assert result["domain_route_reason_status"] == "UNKNOWN"
    assert result["qualifying_domain_route_reason_count"] == 17
    assert result["domain_route_reason_deficit"] == 1
    assert result["reasoned_route_membership_count"] == 44
    assert result["route_membership_reason_deficit"] == 1
    assert result["reasoned_slot_count"] == 25
    assert result["slot_reason_deficit"] == 1
    assert removed["object_kind"] not in result["reasoned_slot_object_kinds"]
    assert "DOMAIN_ROUTE_REASONS_MISSING" in result["blockers"]


def test_domain_route_reason_blank_and_substitutions_fail_closed() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    installed = ledger["domain_route_reasons"]

    blank = deepcopy(installed)
    blank[0]["reason"] = ""
    blank[0]["reason_digest"] = _digest("")
    _resign_domain_route_reason(blank[0])
    result = reasons.assess_facet_reason_choices(ledger["choices"], blank)
    assert result["status"] == "UNKNOWN"
    assert result["qualifying_domain_route_reason_count"] == 17
    assert "DOMAIN_ROUTE_REASON_TEXT_MISSING" in result["blockers"]

    wrong_choice = deepcopy(blank)
    wrong_choice[0]["choice"] = "NOT_NECESSARY"
    _resign_domain_route_reason(wrong_choice[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], wrong_choice
    )["status"] == "FAIL"

    wrong_source = deepcopy(blank)
    wrong_source[0]["source_binding_digest"] = "sha256:" + "0" * 64
    _resign_domain_route_reason(wrong_source[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], wrong_source
    )["status"] == "FAIL"

    wrong_basis = deepcopy(blank)
    wrong_basis[0]["basis"]["route_registration"]["scope"] = "substituted"
    wrong_basis[0]["basis_digest"] = _digest(wrong_basis[0]["basis"])
    _resign_domain_route_reason(wrong_basis[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], wrong_basis
    )["status"] == "FAIL"

    wrong_provenance = deepcopy(blank)
    wrong_provenance[0]["provenance"]["reason_model"] = "SUBSTITUTED"
    wrong_provenance[0]["provenance_digest"] = _digest(
        wrong_provenance[0]["provenance"]
    )
    _resign_domain_route_reason(wrong_provenance[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], wrong_provenance
    )["status"] == "FAIL"

    wrong_route = deepcopy(blank)
    wrong_route[0]["mapped_route_identity"] = deepcopy(
        wrong_route[1]["mapped_route_identity"]
    )
    _resign_domain_route_reason(wrong_route[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], wrong_route
    )["status"] == "FAIL"

    cross_route = deepcopy(installed)
    cross_route[0]["coordinate"] = cross_route[1]["coordinate"]
    _resign_domain_route_reason(cross_route[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], cross_route
    )["status"] == "FAIL"

    bad_digest = deepcopy(blank)
    bad_digest[0]["route_reason_digest"] = "sha256:" + "f" * 64
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], bad_digest
    )["status"] == "FAIL"

    malformed = deepcopy(installed)
    malformed[0].pop("basis_digest")
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], malformed
    )["status"] == "FAIL"

    duplicated = deepcopy(installed)
    duplicated[-1] = deepcopy(duplicated[0])
    assert reasons.assess_facet_reason_choices(
        ledger["choices"], duplicated
    )["status"] == "FAIL"


def test_malformed_duplicate_substituted_and_cross_kind_choices_fail() -> None:
    installed = reasons.installed_facet_reason_ledger()["choices"]

    malformed = deepcopy(installed)
    malformed[0].pop("basis_digest")
    assert reasons.assess_facet_reason_choices(malformed)["status"] == "FAIL"

    duplicated = deepcopy(installed)
    duplicated[-1] = deepcopy(duplicated[0])
    assert reasons.assess_facet_reason_choices(duplicated)["status"] == "FAIL"

    substituted = deepcopy(installed)
    substituted[0]["reason"] += " substituted"
    substituted[0]["reason_digest"] = _digest(substituted[0]["reason"])
    substituted[0]["choice_digest"] = _digest(
        {
            key: value
            for key, value in substituted[0].items()
            if key != "choice_digest"
        }
    )
    result = reasons.assess_facet_reason_choices(substituted)
    assert result["status"] == "FAIL"
    assert "FACET_REASON_CHOICE_SUBSTITUTED" in result["blockers"]

    cross_kind = deepcopy(installed)
    cross_kind[0]["object_kind"] = "TOKEN"
    result = reasons.assess_facet_reason_choices(cross_kind)
    assert result["status"] == "FAIL"
    assert "FACET_REASON_CHOICE_CROSS_KIND_OR_UNKNOWN" in result["blockers"]


def test_ledger_digest_source_and_projection_substitution_fail() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    ledger["ledger_digest"] = "sha256:" + "0" * 64
    result = reasons.replay_facet_reason_ledger(ledger)
    assert result["status"] == "FAIL"
    assert "FACET_REASON_LEDGER_DIGEST_MISMATCH" in result["blockers"]

    source_substitution = reasons.installed_facet_reason_ledger()
    source_substitution["source_bindings"]["core/namespace.py"] = (
        "sha256:" + "1" * 64
    )
    _resign_ledger(source_substitution)
    result = reasons.replay_facet_reason_ledger(source_substitution)
    assert result["status"] == "FAIL"
    assert "FACET_REASON_LEDGER_SUBSTITUTED" in result["blockers"]

    projection_substitution = reasons.installed_facet_reason_ledger()
    projection_substitution["route_projection"].pop()
    projection_substitution["route_projection_count"] -= 1
    projection_substitution["route_projection_digest"] = _digest(
        projection_substitution["route_projection"]
    )
    _resign_ledger(projection_substitution)
    result = reasons.replay_facet_reason_ledger(projection_substitution)
    assert result["status"] == "FAIL"
    assert "FACET_REASON_LEDGER_SUBSTITUTED" in result["blockers"]


def test_bound_sources_and_row_digests_reproduce_exactly() -> None:
    ledger = reasons.installed_facet_reason_ledger()
    bindings = reasons.installed_source_bindings()
    assert ledger["source_bindings"] == bindings
    assert ledger["source_binding_digest"] == _digest(bindings)
    assert ledger["mechanism_digest"] == reasons.mechanism_digest()
    for row in ledger["choices"]:
        assert row["source_binding_digest"] == ledger["source_binding_digest"]
        assert row["reason_digest"] == _digest(row["reason"])
        assert row["basis_digest"] == _digest(row["basis"])
        assert row["provenance_digest"] == _digest(row["provenance"])
        assert row["choice_digest"] == _digest(
            {key: value for key, value in row.items() if key != "choice_digest"}
        )

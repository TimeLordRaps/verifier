"""Terminology: Verifier Standard (VSTD).

The tier-3 statics mechanism and the tier-5 domain adaptation mechanism, which
establish obligations that re-executing a declaration cannot.
"""

from __future__ import annotations

import pytest

from verifier.core.profile_obligations import DOMAIN_OBLIGATIONS
from verifier.domains.catalog import domain_specification_digest
from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.mainstays import (
    CHECKS as ADAPTATION_CHECKS,
    MAINSTAYS,
    evaluate as adapt,
    mainstay_catalog,
    mainstay_digest,
)
from verifier.domains.statics import (
    CHOICE_FIELDS,
    STATICS,
    evaluate as establish,
    statics_catalog,
    statics_digest,
)

WITNESS = "an-independent-observer"


def budget() -> Budget:
    return Budget(200000, 4096)


def probe(measurement: object) -> dict:
    return {"instrument": "probe-1", "observed_by": WITNESS, "observed_at": 1,
            "measurement": measurement, "digest": digest(measurement)}


# --------------------------------------------------------------------- statics

def test_every_statics_profile_ends_in_an_invariance_check() -> None:
    for object_name, rows in STATICS.items():
        assert rows[-1].kind == "invariance", object_name
        assert {s.kind for s in rows} <= {"witness", "recompute", "invariance"}
        assert len([s for s in rows if s.kind == "invariance"]) == 1
        assert object_name in CHOICE_FIELDS


def test_the_statics_row_count_matches_the_catalogued_tier_three_profile() -> None:
    for object_name, rows in STATICS.items():
        catalogued = [o for o in DOMAIN_OBLIGATIONS
                      if o.object_name == object_name and o.profile == 3]
        assert len(rows) == len(catalogued), object_name
        for static, obligation in zip(rows, catalogued):
            assert obligation.mechanism == static.mechanism, obligation.id


def test_a_subject_cannot_witness_its_own_static() -> None:
    artifact = {"arithmetic_probe": probe(ARITHMETIC)}
    assert establish("TRAIN", "arithmetic", artifact, {}, budget(), subject="the-subject")
    artifact["arithmetic_probe"]["observed_by"] = "the-subject"
    with pytest.raises(Refuted, match="witnessed by its own subject"):
        establish("TRAIN", "arithmetic", artifact, {}, budget(), subject="the-subject")


ARITHMETIC = {"binary64_epsilon": 2.0 ** -52, "binary32_epsilon": 2.0 ** -23,
              "ties": "even", "subnormal": True, "nonassociative": True,
              "fused_multiply_add": False}


def test_a_floating_point_probe_is_recomputed_where_it_is_determined() -> None:
    observed = establish("TRAIN", "arithmetic", {"arithmetic_probe": probe(ARITHMETIC)},
                         {}, budget(), subject="subject")
    assert observed["recorded_only"] == ["fused_multiply_add"]
    assert "binary64_epsilon" in observed["determined"]
    lying = dict(ARITHMETIC, binary64_epsilon=1e-3)
    with pytest.raises(Refuted, match="contradicts binary arithmetic"):
        establish("TRAIN", "arithmetic", {"arithmetic_probe": probe(lying)},
                  {}, budget(), subject="subject")


def test_a_clock_cannot_order_events_it_cannot_separate() -> None:
    artifact = {"clock_probe": probe({"resolution": 10}),
                "ordered_pairs": [{"earlier": 0, "later": 20}]}
    inputs = {"timestamps": [0, 20, 40]}
    assert establish("HARNESS", "clock", artifact, inputs, budget(),
                     subject="subject")["resolution"] == 10
    artifact["ordered_pairs"] = [{"earlier": 0, "later": 5}]
    with pytest.raises(Refuted, match="cannot separate"):
        establish("HARNESS", "clock", artifact, inputs, budget(), subject="subject")


def test_a_composition_cannot_claim_a_depth_no_operand_established() -> None:
    operands = {"SIM": {"depth": 1, "substrate": ["VSTD"], "slots": {}, "predicates": ["p"]},
                "AGENT": {"depth": 4, "substrate": ["VSTD"], "slots": {}, "predicates": ["q"]}}
    artifact = {"operands": operands, "declared_depth": 1}
    assert establish("HYPER", "ceiling", artifact, {}, budget())["ceiling"] == 1
    artifact["declared_depth"] = 5
    with pytest.raises(Refuted, match="no operand established"):
        establish("HYPER", "ceiling", artifact, {}, budget())


def test_a_composition_cannot_manufacture_a_predicate() -> None:
    operands = {"A": {"depth": 1, "substrate": [], "slots": {}, "predicates": ["p", "q"]}}
    artifact = {"operands": operands, "predicates": ["p"]}
    assert establish("HYPER", "conservation", artifact, {}, budget())["composed"] == 1
    artifact["predicates"] = ["p", "invented"]
    with pytest.raises(Refuted, match="manufactures evidence"):
        establish("HYPER", "conservation", artifact, {}, budget())


def test_an_agent_declaration_cannot_raise_its_ceiling() -> None:
    artifact = {"harness": {"ceiling": 3, "observed": ["a", "b"]}, "declared_ceiling": 3}
    assert establish("AGENT", "ceiling", artifact, {}, budget())["ceiling"] == 3
    artifact["declared_ceiling"] = 9
    with pytest.raises(Refuted, match="differs from the one its harness fixes"):
        establish("AGENT", "ceiling", artifact, {}, budget())


def test_invariance_refutes_a_fact_that_moves_when_a_choice_is_perturbed() -> None:
    """The heart of tier 3: a static that a declaration can move was never static."""
    base = {"harness": {"ceiling": 3, "observed": ["a"]}, "declared_ceiling": 3,
            "unknowable": {"1": []}, "declarations": {"note": "one"},
            "alternatives": [{"declarations": {"note": "two"}}]}
    inputs = {"steps": [{"available": ["a"], "asserted_known": ["a"]}]}
    observed = establish("AGENT", "impotence", base, inputs, budget())
    assert observed["perturbations"] == 1
    assert observed["choice_fields"] == ["declarations"]

    # An alternative that reaches outside the object's own choices is not a perturbation
    # of a choice, so it cannot establish independence.
    reaching = dict(base, alternatives=[{"declared_ceiling": 9}])
    with pytest.raises(Refuted, match="not this object's choice"):
        establish("AGENT", "impotence", reaching, inputs, budget())
    with pytest.raises(Unavailable, match="changes nothing"):
        establish("AGENT", "impotence",
                  dict(base, alternatives=[{"declarations": {"note": "one"}}]),
                  inputs, budget())


def test_a_statics_verdict_that_moves_is_refuted() -> None:
    moving = {"operands": {"A": {"depth": 2, "substrate": [], "slots": {}, "predicates": ["p"]}},
              "declared_depth": 2, "substrate": [], "predicates": ["p"],
              "composition": {"shape": "flat"},
              "alternatives": [{"composition": {"shape": "nested"}}]}
    assert establish("HYPER", "independence", moving, {}, budget())["perturbations"] == 1


def test_statics_digest_is_its_own_and_moves_with_the_catalogue() -> None:
    assert statics_digest() == statics_digest()
    assert len({statics_digest(), mainstay_digest(), domain_specification_digest()}) == 3
    assert statics_catalog()["schema_version"] == "verifier-statics-catalog-1"
    assert statics_catalog()["tier"] == 3


# ------------------------------------------------------------------ adaptation

def sim_artifact(**overrides: object) -> dict:
    artifact = {
        "mainstay": {"format_id": "gymnasium", "version": "1.0.0",
                     "carrier_digest": "sha256:" + "0" * 64},
        "mapping": {"layout": {"relation": "Env exposes observation-space and action-space",
                               "entity": "observation-space",
                               "pairs": {"channel-a": "Box(3,)"}}},
        "round_trip": {"exported": "sha256:" + "1" * 64,
                       "reimported": "sha256:" + "1" * 64, "loss": []},
    }
    artifact.update(overrides)
    return artifact


def test_every_registered_mainstay_expresses_only_its_own_coordinates() -> None:
    total = 0
    for object_name, rows in MAINSTAYS.items():
        for mainstay in rows:
            assert mainstay.expresses, mainstay.format_id
            for coordinate in mainstay.expresses:
                assert coordinate.startswith(object_name + "-"), mainstay.format_id
                assert int(coordinate.split("-")[-1].split(".")[0]) < 5, coordinate
            assert mainstay.entities and mainstay.relations
            assert set(mainstay.expresses) & set(mainstay.residual()) == set()
            total += 1
    assert total == sum(len(rows) for rows in MAINSTAYS.values())


def test_the_residual_is_computed_not_declared() -> None:
    mainstay = MAINSTAYS["SIM"][0]
    residual = list(mainstay.residual())
    artifact = sim_artifact(residual=residual)
    observed = adapt("SIM", "residual", artifact, {}, budget())
    assert observed["residual"] == residual
    assert observed["by_tier"], "a residual spread over tiers is the point"
    with pytest.raises(Refuted, match="not the complement"):
        adapt("SIM", "residual", sim_artifact(residual=residual[:-1]), {}, budget())


def test_mainstay_formats_carry_facets_and_dynamics_far_more_than_statics() -> None:
    """The finding tier 5 exists to record, asserted as a property of the registry."""
    early = late = 0
    for rows in MAINSTAYS.values():
        for mainstay in rows:
            for coordinate in mainstay.expresses:
                tier = int(coordinate.split("-")[-1].split(".")[0])
                early += tier in (1, 2)
                late += tier in (3, 4)
    assert early > 3 * late, (early, late)


def test_an_unregistered_format_is_refused() -> None:
    assert adapt("SIM", "binding", sim_artifact(), {}, budget())["format_id"] == "gymnasium"
    bogus = sim_artifact()
    bogus["mainstay"]["format_id"] = "not-a-real-format"
    with pytest.raises(Refuted, match="not a registered mainstay"):
        adapt("SIM", "binding", bogus, {}, budget())


def test_a_mapping_must_be_total_over_the_retained_inventory() -> None:
    inputs = {"inventory": ["channel-a"]}
    assert adapt("SIM", "layout", sim_artifact(), inputs, budget())["mapped"] == 1
    with pytest.raises(Refuted, match="not total"):
        adapt("SIM", "layout", sim_artifact(), {"inventory": ["channel-a", "channel-b"]}, budget())


def test_a_mapping_cannot_name_a_relation_the_meta_surface_lacks() -> None:
    artifact = sim_artifact()
    artifact["mapping"]["layout"]["relation"] = "Env teleports to state"
    with pytest.raises(Refuted, match="relation the meta-surface does not carry"):
        adapt("SIM", "layout", artifact, {"inventory": ["channel-a"]}, budget())


def test_a_round_trip_states_its_loss_or_states_none() -> None:
    assert adapt("SIM", "roundtrip", sim_artifact(), {}, budget())["lossless"] is True
    lossy = sim_artifact(round_trip={"exported": "sha256:" + "1" * 64,
                                     "reimported": "sha256:" + "2" * 64, "loss": []})
    with pytest.raises(Refuted, match="names no loss"):
        adapt("SIM", "roundtrip", lossy, {}, budget())
    lying = sim_artifact(round_trip={"exported": "sha256:" + "1" * 64,
                                     "reimported": "sha256:" + "1" * 64,
                                     "loss": ["info dict"]})
    with pytest.raises(Refuted, match="lossless round trip names a loss"):
        adapt("SIM", "roundtrip", lying, {}, budget())


def test_every_adaptation_check_is_bound_by_some_tier_five_obligation() -> None:
    used = {o.mechanism.split(":", 1)[1] for o in DOMAIN_OBLIGATIONS
            if o.profile == 5 and o.mechanized}
    assert used <= set(ADAPTATION_CHECKS)
    assert set(ADAPTATION_CHECKS) - used == set(), sorted(set(ADAPTATION_CHECKS) - used)


def test_mainstay_catalog_is_stable_and_separately_digested() -> None:
    catalog = mainstay_catalog()
    assert catalog["schema_version"] == "verifier-mainstay-catalog-1"
    assert catalog["tier"] == 5
    assert set(catalog["objects"]) == set(MAINSTAYS)
    assert mainstay_digest() == mainstay_digest()

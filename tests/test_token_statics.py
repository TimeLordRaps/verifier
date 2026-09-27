"""Terminology: Verifier Standard (VSTD).

The eight tier-3 statics TOKEN gained when its rungs were widened to fourteen. Each is
exercised twice: once over evidence that establishes it, and once over evidence that
refutes it. A mechanism whose refutation path has never run is prose with a name.

Every proposition here is a known failure of a deployed token format rather than an
invented one -- an accepted algorithm set that admits both a symmetric and an asymmetric
algorithm for one key, a key identifier the token itself resolves, a revocation status
that reports itself current long after its publication schedule expired. The ladder is
meant to be crucial for the decisions the mainstays failed to make, and this is where
that claim is executable rather than asserted.
"""

from __future__ import annotations

import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.statics import STATICS, evaluate

WITNESS = "an-independent-observer"


def budget() -> Budget:
    return Budget(200000, 4096)


def run(check: str, artifact: dict, inputs: dict) -> dict:
    return evaluate("TOKEN", check, artifact, inputs, budget(), subject="the-subject")


# ------------------------------------------------------------------- algorithm

def test_an_accepted_set_mixing_key_kinds_is_algorithm_confusion() -> None:
    signed = {"signed_preimages": [{"token_id": "t-1", "algorithm": "ES256",
                                    "preimage_digest": digest("t-1")}]}
    assert run("algorithm", signed, {"accepted_algorithms": ["ES256"]})["verified"] == 1
    with pytest.raises(Refuted, match="both a symmetric and an asymmetric"):
        run("algorithm", signed, {"accepted_algorithms": ["ES256", "HS256"]})
    with pytest.raises(Refuted, match="accepts unsigned tokens"):
        run("algorithm", signed, {"accepted_algorithms": ["ES256", "none"]})


def test_a_token_verified_outside_the_accepted_set_is_refuted() -> None:
    signed = {"signed_preimages": [{"token_id": "t-2", "algorithm": "RS256",
                                    "preimage_digest": digest("t-2")}]}
    with pytest.raises(Refuted, match="outside the accepted set"):
        run("algorithm", signed, {"accepted_algorithms": ["ES256"]})


# ---------------------------------------------------------------------- keying

def test_a_key_identifier_that_is_not_the_key_digest_names_nothing() -> None:
    honest = {"issuing_keys": [{"key_id": digest("key-bytes"), "key_bytes": "key-bytes"}]}
    assert run("keying", honest, {})["keys"] == 1
    with pytest.raises(Refuted, match="not the digest of the key it names"):
        run("keying", {"issuing_keys": [{"key_id": "whatever-the-token-says",
                                         "key_bytes": "key-bytes"}]}, {})


# ---------------------------------------------------------------------- window

def test_an_empty_window_is_refuted_and_a_skew_wide_one_is_undetermined() -> None:
    artifact = {"clock_skew": 30}
    wide = {"windows": [{"token_id": "t-3", "not_before": 100, "expires_at": 400}]}
    assert run("window", artifact, wide)["narrowest"] == 300
    with pytest.raises(Refuted, match="ends at or before it starts"):
        run("window", artifact, {"windows": [{"token_id": "t-4", "not_before": 400,
                                              "expires_at": 400}]})
    # Narrower than the skew is not invalid; it is a window the two clocks cannot
    # separate, so the verdict is UNKNOWN rather than FAIL.
    with pytest.raises(Unavailable, match="no wider than the stated clock skew"):
        run("window", artifact, {"windows": [{"token_id": "t-5", "not_before": 100,
                                              "expires_at": 120}]})


# ------------------------------------------------------------------ possession

def test_a_bound_confirmation_key_without_a_proof_establishes_nothing() -> None:
    mixed = {"presentations": [
        {"token_id": "t-6", "confirmation_key_id": None, "proof": None},
        {"token_id": "t-7", "confirmation_key_id": "cnf-1", "proof": "signature-over-nonce"}]}
    observed = run("possession", {}, mixed)
    assert (observed["bearer"], observed["confirmed"]) == (1, 1)
    with pytest.raises(Refuted, match="presented without a proof"):
        run("possession", {}, {"presentations": [
            {"token_id": "t-8", "confirmation_key_id": "cnf-2", "proof": None}]})


# ----------------------------------------------------------------- attenuation

def test_a_delegation_step_that_drops_a_caveat_has_widened_the_lease() -> None:
    narrowing = {"delegations": [{"token_id": "t-9", "caveat_sets": [
        ["audience=api"], ["audience=api", "method=GET"],
        ["audience=api", "method=GET", "expires<=epoch-40"]]}]}
    assert run("attenuation", {}, narrowing)["depth"] == 3
    with pytest.raises(Refuted, match="drops a caveat an earlier step imposed"):
        run("attenuation", {}, {"delegations": [{"token_id": "t-10", "caveat_sets": [
            ["audience=api", "method=GET"], ["audience=api"]]}]})


# ------------------------------------------------------------------- freshness

def test_a_stale_status_reporting_itself_current_is_soft_fail() -> None:
    artifact = {"status_schedule": 24, "observed_at": 1000}
    fresh = {"statuses": [{"token_id": "t-11", "published_at": 990, "verdict": "CURRENT"}]}
    assert run("freshness", artifact, fresh)["stale"] == []
    aged = {"statuses": [{"token_id": "t-12", "published_at": 900, "verdict": "STALE"}]}
    assert run("freshness", artifact, aged)["stale"] == ["t-12"]
    with pytest.raises(Refuted, match=r"reports itself\s+current"):
        run("freshness", artifact, {"statuses": [
            {"token_id": "t-13", "published_at": 900, "verdict": "CURRENT"}]})
    with pytest.raises(Refuted, match="published after it was observed"):
        run("freshness", artifact, {"statuses": [
            {"token_id": "t-14", "published_at": 1100, "verdict": "CURRENT"}]})


# ---------------------------------------------------------------------- replay

def test_two_issuances_under_one_replay_identifier_are_one_issuance() -> None:
    distinct = {"issuances": [{"token_id": "t-15", "replay_id": "r-1"},
                              {"token_id": "t-16", "replay_id": "r-2"}]}
    assert run("replay", {}, distinct)["distinct"] == 2
    with pytest.raises(Refuted, match="share a replay identifier"):
        run("replay", {}, {"issuances": [{"token_id": "t-17", "replay_id": "r-3"},
                                         {"token_id": "t-18", "replay_id": "r-3"}]})


# ------------------------------------------------------------------ disclosure

def test_disclosed_and_withheld_must_partition_the_bound_digests() -> None:
    artifact = {"field_digests": [digest("given_name"), digest("birthdate")]}
    partition = {"disclosed": [digest("given_name")], "withheld": [digest("birthdate")]}
    assert run("disclosure", artifact, partition)["bound"] == 2
    with pytest.raises(Refuted, match="neither disclosed nor withheld"):
        run("disclosure", artifact, {"disclosed": [digest("given_name")], "withheld": []})
    with pytest.raises(Refuted, match="both disclosed and withheld"):
        run("disclosure", artifact, {"disclosed": [digest("given_name"), digest("birthdate")],
                                     "withheld": [digest("birthdate")]})
    with pytest.raises(Refuted, match="not among the bound digests"):
        run("disclosure", artifact, {"disclosed": [digest("given_name")],
                                     "withheld": [digest("birthdate"), digest("nationality")]})


# ---------------------------------------------------------------- independence

def test_the_invariance_row_still_closes_the_widened_roster() -> None:
    """Thirteen statics now sit under the invariance check instead of five.

    Every one of them is re-decided under each perturbation, so widening the rung
    widens what independence has to survive. A static missing its evidence returns the
    same UNKNOWN before and after a perturbation, which is a verdict that does not
    move -- absence of evidence is not evidence that a fact is a choice.
    """
    earlier = [s.name for s in STATICS["TOKEN"] if s.kind != "invariance"]
    assert len(earlier) == 13
    artifact = {"issuance": {"salt": "salt-a"},
                "alternatives": [{"issuance": {"salt": "salt-b"}}]}
    observed = run("independence", artifact, {})
    assert observed["perturbations"] == 1
    assert observed["invariant"] == sorted(earlier)
    assert observed["choice_fields"] == ["issuance"]


def test_an_alternative_perturbing_something_that_is_not_a_choice_is_refuted() -> None:
    with pytest.raises(Refuted, match="not this object's choice"):
        run("independence", {"issuance": {"salt": "salt-a"},
                             "alternatives": [{"root_scopes": ["read"]}]}, {})

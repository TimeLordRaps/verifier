"""Selected OWNER fork detection over a retained chain of holdings.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions are dimensionless integers in the
declared order; counts are dimensionless. Expected forks and coverage are
computed here by a per-position brute force, never by the checker under test.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import owner_forks
from verifier.domains.inventory import get_slot


ROOT = Path(__file__).resolve().parents[1]
ROW = ("No two holdings claim the same limb over the same object at the same "
       "position, and a fork is reported rather than resolved.")
HOLDERS = ("alice", "bob", "carol")
OBJECTS = ("artifact", "manual")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def instrument(name: str) -> tuple[str, str]:
    data = ("origin:" + name).encode("utf-8")
    return (base64.b64encode(data).decode("ascii"),
            "sha256:" + hashlib.sha256(data).hexdigest())


ARTIFACT_B64, ARTIFACT_D = instrument("artifact")
MANUAL_B64, MANUAL_D = instrument("manual")


def holding(hid: str, obj: str, holder: str, limbs: list[tuple[str, str]],
            first: int, last: int) -> dict:
    return {"id": hid, "object": obj, "holder": holder + "-actor",
            "limbs": [{"limb": limb, "kind": kind} for limb, kind in sorted(limbs)],
            "first_position": first, "last_position": last}


def base_inputs() -> dict:
    return {
        "instruments": sorted([ARTIFACT_B64, MANUAL_B64]),
        "holdings": [
            holding("h-alice", "artifact", "alice",
                    [("maintain", "discharge_duty"), ("use", "right")], 0, 4),
            holding("h-bob", "artifact", "bob",
                    [("maintain", "discharge_duty"), ("use", "right")], 5, 9),
            # Same position, different limb: not a fork.
            holding("h-carol-report", "artifact", "carol",
                    [("report", "answering_duty")], 0, 9),
            # Same limb name, different object: not a fork.
            holding("h-manual", "manual", "carol", [("use", "right")], 0, 9),
        ],
        "chains": [
            {"object": "artifact", "origin_position": 0,
             "origin_instrument_digest": ARTIFACT_D, "head_position": 9,
             "holdings": ["h-alice", "h-bob"]},
            {"object": "manual", "origin_position": 0,
             "origin_instrument_digest": MANUAL_D, "head_position": 9,
             "holdings": ["h-manual"]},
        ],
    }


def records(inputs: dict) -> tuple[NamespaceObject, list[NamespaceObject]]:
    humans = [NamespaceObject.create(name, "HUMAN", {"fixture": name}) for name in HOLDERS]
    actors = [NamespaceObject.create(name + "-actor", "ACTOR", {"fixture": name + "-actor"},
                                     {"representation": [name], "root_human": [name]})
              for name in HOLDERS]
    held = [NamespaceObject.create(name, "DATA", {"fixture": name}) for name in OBJECTS]
    subject = NamespaceObject.create("holding", "OWNER", {
        "scope": "retained-holding-chain-forks", "inputs_digest": digest(inputs)},
        {"actor": [actor.object_id for actor in actors], "object": list(OBJECTS)})
    return subject, [*humans, *actors, *held, subject]


def selected(inputs: dict | None = None, *, limits: dict | None = None,
             include_evidence: bool = True):
    inputs = base_inputs() if inputs is None else inputs
    subject, objects = records(inputs)
    evidence = canonical_bytes({
        "schema_version": owner_forks.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "inputs": inputs})
    policy = owner_forks.owner_forks_policy(trust_roots=["owner-root"])
    request = owner_forks.owner_forks_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        inputs_digest=digest(inputs),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, (evidence if include_evidence else None)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = owner_forks.build_owner_forks_certificate(
        request, evidence, policy=policy)
    result = owner_forks.recheck_owner_forks_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def brute_forks(inputs: dict) -> list[dict]:
    """Every pair of holdings sharing an object, a limb and a position."""
    rows = inputs["holdings"]
    found = {}
    top = max(row["last_position"] for row in rows)
    for position in range(0, top + 1):
        for i, left in enumerate(rows):
            for right in rows[i + 1:]:
                if left["object"] != right["object"]:
                    continue
                if not (left["first_position"] <= position <= left["last_position"]
                        and right["first_position"] <= position <= right["last_position"]):
                    continue
                shared = ({row["limb"] for row in left["limbs"]}
                          & {row["limb"] for row in right["limbs"]})
                for limb in shared:
                    pair = tuple(sorted((left["id"], right["id"])))
                    found.setdefault((left["object"], limb, pair), position)
    return [{"holdings": list(pair), "object": obj, "limb": limb,
             "first_shared_position": position}
            for (obj, limb, pair), position in sorted(found.items())]


def brute_coverage(inputs: dict, obj: str) -> dict[int, int]:
    chain = [row for row in inputs["chains"] if row["object"] == obj][0]
    members = [row for row in inputs["holdings"] if row["id"] in chain["holdings"]]
    return {position: sum(row["first_position"] <= position <= row["last_position"]
                          for row in members)
            for position in range(chain["origin_position"], chain["head_position"] + 1)}


def test_grounded_row_is_quoted_verbatim_from_the_owner_closure_table():
    spec = (ROOT / "src" / "verifier" / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(
        encoding="utf-8")
    assert "| OWNER-4.3 | Fork detection | " + ROW + " |" in spec
    current = (ROOT / "src" / "verifier" / "standard" / "CURRENT_OWNER_FORKS.md").read_text(
        encoding="utf-8")
    assert ROW in current
    assert owner_forks.COORDINATE == "OWNER-4.3"
    joined = " ".join(owner_forks.registration()["exclusions"])
    for excluded in ("legal title", "liens", "authority", "consent", "personhood",
                     "OWNER-4.4", "OWNER-4.5", "OWNER-4.6"):
        assert excluded in joined


def test_oracle_sees_a_fork_free_gapless_fixture():
    inputs = base_inputs()
    assert brute_forks(inputs) == []
    for obj in OBJECTS:
        assert set(brute_coverage(inputs, obj).values()) == {1}


def test_fork_free_gapless_chain_passes_without_closure_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["fork_freedom"] == "PASS"
    for field in ("admissibility_at_issue_time", "accountability_floor",
                  "chain_closure_result", "whole_owner_closure_tier",
                  "object_profile_conformance", "legal_title", "liens",
                  "authority", "consent", "personhood"):
        assert result[field] == "NOT_ESTABLISHED", field
    assert certificate == owner_forks.build_owner_forks_certificate(
        request, evidence, policy=policy)
    decoded = json.loads(certificate)
    assert base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]]) == evidence
    assert owner_forks.recheck_owner_forks_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))["status"] == "PASS"


def _observations(result: dict) -> dict:
    return result["evaluation"]["observations"]


def test_same_limb_claim_is_reported_as_a_fork_and_never_resolved():
    inputs = base_inputs()
    inputs["holdings"].append(holding("h-carol-use", "artifact", "carol",
                                      [("use", "right")], 6, 7))
    expected = brute_forks(inputs)
    assert expected == [{"holdings": ["h-bob", "h-carol-use"], "object": "artifact",
                         "limb": "use", "first_shared_position": 6}]
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert result["fork_freedom"] == "NOT_ESTABLISHED"
    assert _observations(result) == {"forks": expected, "chain_findings": []}


def test_three_way_fork_reports_every_pair_independent_of_order():
    inputs = base_inputs()
    inputs["holdings"] += [
        holding("h-x", "artifact", "carol", [("maintain", "discharge_duty")], 2, 6),
        holding("h-y", "artifact", "bob", [("maintain", "discharge_duty")], 3, 3),
    ]
    expected = brute_forks(inputs)
    # h-alice, h-x and h-y all claim maintain at position 3; h-bob meets h-x at 5.
    assert [row["holdings"] for row in expected] == [
        ["h-alice", "h-x"], ["h-alice", "h-y"], ["h-bob", "h-x"], ["h-x", "h-y"]]
    reports = []
    for ordering in (inputs["holdings"], list(reversed(inputs["holdings"]))):
        permuted = deepcopy(inputs)
        permuted["holdings"] = deepcopy(ordering)
        request, policy, evidence = selected(permuted)
        result = replay(request, policy, evidence)[1]
        assert result["status"] == "FAIL"
        reports.append(_observations(result))
    assert reports[0] == reports[1] == {"forks": expected, "chain_findings": []}


def test_fence_post_overlap_at_one_position_is_a_fork():
    inputs = base_inputs()
    inputs["holdings"].append(holding("h-edge", "artifact", "carol",
                                      [("use", "right")], 4, 4))
    expected = brute_forks(inputs)
    assert [row["first_shared_position"] for row in expected] == [4]
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert _observations(result)["forks"] == expected


def _unbound_origin(inputs):
    inputs["chains"][0]["origin_instrument_digest"] = "sha256:" + hashlib.sha256(
        b"origin:never-retained").hexdigest()


def _gap(inputs):
    inputs["holdings"][1]["first_position"] = 6


def _doubly_covered(inputs):
    inputs["holdings"][1] = holding("h-bob", "artifact", "bob",
                                    [("audit", "discharge_duty")], 4, 9)


def _chain_starts_after_origin(inputs):
    inputs["holdings"][0]["first_position"] = 1


def _chain_short_of_head(inputs):
    inputs["holdings"][1]["last_position"] = 8


def _label_prefix_holder(inputs):
    inputs["holdings"][2]["holder"] = "human:" + "person:carol"


def _human_record_as_holder(inputs):
    inputs["holdings"][2]["holder"] = "carol"


MUTANTS = {
    "unbound-origin-instrument": _unbound_origin,
    "gap-position": _gap,
    "doubly-covered-position": _doubly_covered,
    "chain-starts-after-origin": _chain_starts_after_origin,
    "chain-short-of-head": _chain_short_of_head,
    "label-prefix-holder": _label_prefix_holder,
    "human-record-as-holder": _human_record_as_holder,
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutant_fails(name):
    inputs = base_inputs()
    MUTANTS[name](inputs)
    if name in ("gap-position", "chain-starts-after-origin", "chain-short-of-head"):
        assert 0 in brute_coverage(inputs, "artifact").values()
    if name == "doubly-covered-position":
        assert brute_coverage(inputs, "artifact")[4] == 2
        assert brute_forks(inputs) == []
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])
    assert result["fork_freedom"] == "NOT_ESTABLISHED"
    if name in ("label-prefix-holder", "human-record-as-holder"):
        assert "ACTOR record" in result["evaluation"]["details"]
    elif name != "unbound-origin-instrument":
        assert _observations(result)["forks"] == []
        assert _observations(result)["chain_findings"]
    else:
        assert any("instrument" in row for row in _observations(result)["chain_findings"])


@pytest.mark.parametrize(("encoded", "reason"), [
    ("!!!!", "invalid base64"),
    ("QR==", "noncanonical base64"),
])
def test_malformed_retained_instrument_bytes_fail(encoded, reason):
    inputs = base_inputs()
    inputs["instruments"] = sorted([*inputs["instruments"], encoded])
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["details"]


def test_absent_chain_stays_unknown_but_a_fork_still_fails():
    inputs = base_inputs()
    inputs["chains"] = inputs["chains"][:1]
    request, policy, evidence = selected(inputs)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    inputs["holdings"].append(holding("h-manual-2", "manual", "bob",
                                      [("use", "right")], 9, 9))
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert _observations(result)["forks"] == brute_forks(inputs)


@pytest.mark.parametrize("limits", [{"max_holdings": 3}, {"max_chains": 1},
                                    {"max_instruments": 1}, {"max_operations": 40}])
def test_exhausted_budget_stays_unknown(limits):
    request, policy, evidence = selected(limits=limits)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["fork_freedom"] == "NOT_ESTABLISHED"


def test_missing_evidence_stays_unknown():
    request, policy, _ = selected(include_evidence=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("offset", [0, 17, 211, -40, -2])
def test_one_bit_flip_in_certificate_is_refused(offset):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    flipped = bytearray(certificate)
    flipped[offset] ^= 0x01
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.recheck_owner_forks_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_or_verdict_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other = deepcopy(request)
    other["subject_id"] = "artifact"
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.recheck_owner_forks_certificate(
            certificate, expected_request=other, policy=policy)
    roots = deepcopy(policy)
    roots["trust_roots"] = ["other-root"]
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.recheck_owner_forks_certificate(
            certificate, expected_request=request, policy=roots)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.recheck_owner_forks_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong_subject = deepcopy(request)
    wrong_subject["subject_id"] = "artifact"
    wrong_subject["object_digest"] = NamespaceObject.create(
        "artifact", "DATA", {"fixture": "artifact"}).digest
    assert replay(wrong_subject, policy, evidence)[1]["status"] == "FAIL"
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.build_owner_forks_certificate(request, evidence + b" ", policy=policy)
    with pytest.raises(owner_forks.OwnerForksError):
        owner_forks.owner_forks_request(
            subject_id="holding", object_digest=request["object_digest"],
            collection_digest=request["collection_digest"],
            inputs_digest=request["inputs_digest"],
            evidence_ref=request["evidence_ref"], policy=policy,
            limits={"max_unknown": 1})


def test_inputs_substituted_under_the_same_subject_fail():
    request, policy, evidence = selected()
    value = json.loads(evidence)
    value["inputs"]["holdings"] = value["inputs"]["holdings"][:3]
    changed = canonical_bytes(value)
    swapped = deepcopy(request)
    swapped["evidence_ref"] = digest(value)
    assert replay(swapped, policy, changed)[1]["status"] == "FAIL"


def test_public_route_and_inventory_select_fork_detection():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=owner_forks.SEMANTIC_VERSION,
        objective=owner_forks.COORDINATE, represented_kind="OWNER",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["chain_closure_result"] == "NOT_ESTABLISHED"
    slot = get_slot("OWNER", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "OWNER-4.3"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.owner_forks.recheck_owner_forks_certificate")


def test_retained_fork_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("OWNER", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


def _generated(seed: int) -> dict:
    chooser = random.Random(seed)
    limbs = ["a", "b", "c"]
    holdings, chains, count = [], [], 0
    for obj in OBJECTS:
        cuts = sorted(chooser.sample(range(1, 12), chooser.randrange(0, 3)))
        bounds = list(zip([0, *cuts], [cut - 1 for cut in cuts] + [11]))
        ids = []
        for first, last in bounds:
            hid = "h" + str(count)
            count += 1
            ids.append(hid)
            holdings.append(holding(hid, obj, chooser.choice(HOLDERS),
                                    [(limb, "right") for limb in chooser.sample(limbs, chooser.randrange(1, 3))],
                                    first, last))
        chains.append({"object": obj, "origin_position": 0,
                       "origin_instrument_digest": ARTIFACT_D if obj == "artifact" else MANUAL_D,
                       "head_position": 11, "holdings": ids})
    for _ in range(chooser.randrange(0, 4)):
        first = chooser.randrange(0, 12)
        hid = "h" + str(count)
        count += 1
        holdings.append(holding(hid, chooser.choice(OBJECTS), chooser.choice(HOLDERS),
                                [(limb, "right") for limb in chooser.sample(limbs, chooser.randrange(1, 3))],
                                first, chooser.randrange(first, 12)))
    chooser.shuffle(holdings)
    return {"instruments": sorted([ARTIFACT_B64, MANUAL_B64]),
            "holdings": holdings, "chains": chains}


@pytest.mark.parametrize("seed", range(40))
def test_differential_fork_report_agrees_with_the_brute_force_oracle(seed):
    inputs = _generated(seed)
    expected = brute_forks(inputs)
    for obj in OBJECTS:
        assert set(brute_coverage(inputs, obj).values()) == {1}
    request, policy, evidence = selected(inputs)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == ("FAIL" if expected else "PASS")
    if expected:
        assert _observations(result) == {"forks": expected, "chain_findings": []}


def test_differential_corpus_reaches_both_verdicts():
    outcomes = {bool(brute_forks(_generated(seed))) for seed in range(40)}
    assert outcomes == {True, False}


@pytest.mark.parametrize("relative", [
    "domains/contracts/owner_forks.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_OWNER_FORKS.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(owner_forks.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        owner_forks.recheck_owner_forks_certificate(
            certificate, expected_request=request, policy=policy)

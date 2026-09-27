"""Adversarial nested Verifier Standard (VSTD) domain-certificate replay."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate,
)
from verifier.domains.common import Budget, digest, inspect_structure


@pytest.fixture(scope="module")
def specimens() -> dict:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("nested_domain_example", root / "examples/domain_grounding.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()


def policy(**kwargs: object) -> dict:
    return domain_policy(trust_roots=["test:current-checker", "test:retained-inputs"], **kwargs)


def resign(certificate: dict) -> None:
    evidence = certificate["evidence"]
    certificate["request"] = domain_request(evidence, target_depth=certificate["request"]["target_depth"])
    certificate.pop("certificate_digest", None)
    certificate["certificate_digest"] = digest(certificate)


def corrupt(bundle: dict, path: tuple[str, ...]) -> None:
    key, *remaining = path
    certificate = bundle["inputs"][key + "_certificate"]
    evidence = certificate["evidence"]
    if remaining:
        corrupt(evidence, tuple(remaining))
    elif evidence["domain"] == "HARNESS":
        evidence["artifact"]["record_count"] += 1
    elif evidence["domain"] == "SIM":
        evidence["inputs"]["states"][1]["x"] = 99.0
        evidence["artifact"]["trajectory_digest"] = digest(evidence["inputs"]["states"])
    elif evidence["domain"] == "ENV":
        entry = next(iter(evidence["inputs"]["files"].values()))
        entry["base64"] = "Zm9yZ2Vk"
    else:
        raise AssertionError("unexpected corruption domain")
    # The attacker updates every unkeyed commitment, but cannot make the false
    # retained computation reproduce. The old clean result remains a forged PASS.
    resign(certificate)
    bundle["artifact"][key + "_certificate_digest"] = digest(certificate)


@pytest.mark.parametrize("domain,path", [
    ("AGENT", ("harness",)),
    ("BOT", ("sim",)),
    ("BOT", ("agent_environment",)),
    ("BOT", ("sim_environment",)),
    ("BOT", ("agent", "harness")),
])
def test_rehashed_child_forgery_cannot_supply_parent_pass(specimens: dict, domain: str, path: tuple[str, ...]) -> None:
    bundle = deepcopy(specimens[domain])
    admitted = policy()
    clean = build_domain_certificate(domain_request(bundle), bundle, policy=admitted)
    assert clean["result"]["status"] == "PASS"
    corrupt(bundle, path)
    request = domain_request(bundle)
    result = build_domain_certificate(request, bundle, policy=admitted)["result"]
    assert result["status"] == "FAIL", result
    # A parent claiming its former PASS must also be rejected by public replay,
    # even after the attacker binds the changed evidence into a fresh request.
    clean["evidence"] = bundle
    resign(clean)
    assert recheck_domain_certificate(clean, expected_request=request, policy=admitted)["status"] == "REJECTED"


def test_current_checker_policy_cannot_borrow_child_numerical_tolerance(specimens: dict) -> None:
    bundle = deepcopy(specimens["BOT"])
    admitted = policy(max_tolerance=0.0)
    result = build_domain_certificate(domain_request(bundle), bundle, policy=admitted)["result"]
    assert result["status"] == "UNKNOWN", result
    assert result["domain_depth"] == 0
    assert "tolerance" in result["checks"]["BOT-1.1"]["evaluation"]["details"]


def test_current_policy_is_distinct_from_historical_child_policy(specimens: dict) -> None:
    bundle = specimens["AGENT"]
    admitted = policy()
    assert bundle["inputs"]["harness_certificate"]["policy_digest"] != digest(admitted)
    certificate = build_domain_certificate(domain_request(bundle), bundle, policy=admitted)
    assert certificate["result"]["status"] == "PASS"
    observed = certificate["result"]["checks"]["AGENT-1.1"]["evaluation"]["observations"]
    assert observed["child_policy"] == "current_checker_policy"
    assert observed["historical_child_policy_reproduction"] == "NOT_ESTABLISHED"
    assert recheck_domain_certificate(certificate, expected_request=domain_request(bundle), policy=admitted)["status"] == "PASS"


def test_nested_work_cannot_reset_parent_operation_allowance(specimens: dict) -> None:
    bundle = specimens["BOT"]
    admission = policy()
    parent = build_domain_certificate(domain_request(bundle, target_depth=1), bundle, policy=admission)
    total = parent["result"]["checks"]["BOT-1.1"]["evaluation"]["observations"]["operations"]
    children = list(bundle["inputs"].values())
    largest_child_check = max(
        row["evaluation"]["observations"]["operations"]
        for child in children for row in child["result"]["checks"].values())
    structural = Budget(1000000)
    inspect_structure(bundle, structural)
    limit = max(structural.used, largest_child_check) + 1
    assert limit < total
    limited = policy(max_operations=limit)
    # Each child and the parent traversal fit independently. Their combination
    # must consume one allowance instead of recursively receiving fresh limits.
    for child in children:
        result = build_domain_certificate(child["request"], child["evidence"], policy=limited)["result"]
        assert result["status"] == "PASS", result
    result = build_domain_certificate(domain_request(bundle, target_depth=1), bundle, policy=limited)["result"]
    assert result["status"] == "UNKNOWN", result
    assert "operation bound" in result["checks"]["BOT-1.1"]["evaluation"]["details"]


def test_nested_depth_is_bounded_without_changing_leaf_verdicts(specimens: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.domains import common
    monkeypatch.setattr(common, "MAX_CERTIFICATE_NESTING", 1)
    admitted = policy()
    leaf = specimens["AGENT"]
    assert build_domain_certificate(domain_request(leaf), leaf, policy=admitted)["result"]["status"] == "PASS"
    nested = specimens["BOT"]
    result = build_domain_certificate(domain_request(nested), nested, policy=admitted)["result"]
    assert result["status"] == "UNKNOWN"
    assert "depth bound" in result["checks"]["BOT-1.1"]["evaluation"]["details"]


def test_child_signature_keys_must_be_admitted_by_current_checker(specimens: dict) -> None:
    # OPTIONAL_DEPENDENCY_ABSENT: signatures need the documented seal extra.
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519",
        reason="OPTIONAL_DEPENDENCY_ABSENT: seal signature backend")
    from cryptography.hazmat.primitives import serialization
    from verifier.core.certificate import canonical_bytes
    import base64

    bundle = deepcopy(specimens["BOT"])
    simulation = bundle["inputs"]["sim_certificate"]["evidence"]
    simulation["artifact"]["shards"]["require_signatures"] = True
    keys = {name: crypto.Ed25519PrivateKey.generate() for name in ("left", "right")}
    public = {name: key.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex() for name, key in keys.items()}
    trusted = policy(witness_keys=public)
    for name, rows in simulation["inputs"]["shards"].items():
        for index, row in enumerate(rows):
            message = {"artifact_digest": digest(simulation["artifact"]), "shard": name,
                       "step": index, "time": row["time"], "state": row["state"]}
            row["signature"] = base64.b64encode(keys[name].sign(canonical_bytes(message))).decode()
    child = build_domain_certificate(domain_request(simulation), simulation, policy=trusted)
    assert child["result"]["status"] == "PASS"
    bundle["inputs"]["sim_certificate"] = child
    bundle["artifact"]["sim_certificate_digest"] = digest(child)
    assert build_domain_certificate(domain_request(bundle), bundle, policy=trusted)["result"]["status"] == "PASS"
    unadmitted = build_domain_certificate(domain_request(bundle), bundle, policy=policy())["result"]
    assert unadmitted["status"] == "UNKNOWN", unadmitted
    wrong_keys = {name: "00" * 32 for name in public}
    wrong = build_domain_certificate(domain_request(bundle), bundle, policy=policy(witness_keys=wrong_keys))["result"]
    assert wrong["status"] == "FAIL", wrong


@pytest.mark.parametrize("field", ["request", "result", "specification_digest"])
def test_child_envelope_is_checked_after_rehashing(specimens: dict, field: str) -> None:
    bundle = deepcopy(specimens["AGENT"])
    child = bundle["inputs"]["harness_certificate"]
    if field == "request":
        child["request"]["subject_id"] = "substituted-child"
    elif field == "result":
        row = child["result"]["checks"]["HARNESS-1.1"]
        row["evaluation"]["observations"] = {"invented": True}
    else:
        child[field] = "sha256:" + "0" * 64
    child.pop("certificate_digest")
    child["certificate_digest"] = digest(child)
    bundle["artifact"]["harness_certificate_digest"] = digest(child)
    result = build_domain_certificate(domain_request(bundle), bundle, policy=policy())["result"]
    assert result["status"] == "FAIL", result

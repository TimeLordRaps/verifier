"""Guards of the bound-certificate primitive.

A retained child certificate is refused when it certifies a different domain than the binding slot
expects (a refutation) and reported as unknown when it was produced by a different mechanism.
Each refusal is attributable to the swap: the unchanged child, re-bound and re-sealed, still binds.
"""

from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.domains.catalog import COORDINATES
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
from verifier.domains.common import digest

BINDINGS = (
    pytest.param("AGENT", "harness", id="agent-harness"),
    pytest.param("BOT", "agent", id="bot-agent"),
    pytest.param("BOT", "sim", id="bot-sim"),
    pytest.param("BOT", "agent_environment", id="bot-agent-environment"),
    pytest.param("BOT", "sim_environment", id="bot-sim-environment"),
)


@pytest.fixture(scope="module")
def specimens() -> dict:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "bound_certificate_guard_example", root / "examples/domain_grounding.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()


def _policy() -> dict:
    return domain_policy(trust_roots=["test:current-checker", "test:retained-inputs"])


def _assess(bundle: dict) -> dict:
    return build_domain_certificate(domain_request(bundle), bundle, policy=_policy())


def _rebind(bundle: dict, key: str, certificate: dict) -> dict:
    changed = deepcopy(bundle)
    changed["inputs"][key + "_certificate"] = certificate
    changed["artifact"][key + "_certificate_digest"] = digest(certificate)
    return changed


def _reseal(certificate: dict) -> dict:
    body = {name: value for name, value in certificate.items() if name != "certificate_digest"}
    return dict(body, certificate_digest=digest(body))


def _first_evaluation(certificate: dict, domain: str) -> dict:
    return certificate["result"]["checks"][COORDINATES[domain][0]]["evaluation"]


@pytest.mark.parametrize(("domain", "key"), BINDINGS)
def test_an_unchanged_child_certificate_still_binds(specimens: dict, domain: str, key: str) -> None:
    bundle = specimens[domain]
    child = bundle["inputs"][key + "_certificate"]
    assert _reseal(child) == child
    baseline = _assess(bundle)
    rebound = _assess(_rebind(bundle, key, child))
    assert baseline["result"]["status"] == "PASS"
    assert _first_evaluation(baseline, domain)["outcome"] == "PASS"
    assert rebound["result"] == baseline["result"]


@pytest.mark.parametrize(("domain", "key"), BINDINGS)
def test_a_certificate_for_another_domain_is_refuted_in_the_slot(
    specimens: dict, domain: str, key: str
) -> None:
    other = _assess(specimens["BOT"])
    assert other["evidence"]["domain"] == "BOT"
    assert other["evidence"]["domain"] != specimens[domain]["inputs"][key + "_certificate"]["evidence"]["domain"]
    certificate = _assess(_rebind(specimens[domain], key, other))
    evaluation = _first_evaluation(certificate, domain)
    assert evaluation["outcome"] == "FAIL"
    assert "different domain" in evaluation["details"]
    assert certificate["result"]["status"] != "PASS"


@pytest.mark.parametrize(("domain", "key"), BINDINGS)
def test_a_certificate_from_another_mechanism_is_unknown(specimens: dict, domain: str, key: str) -> None:
    child = specimens[domain]["inputs"][key + "_certificate"]
    foreign = _reseal(dict(child, mechanism_digest="sha256:" + "1" * 64))
    assert foreign["mechanism_digest"] != child["mechanism_digest"]
    assert foreign["certificate_digest"] != child["certificate_digest"]
    certificate = _assess(_rebind(specimens[domain], key, foreign))
    evaluation = _first_evaluation(certificate, domain)
    assert evaluation["outcome"] == "UNKNOWN"
    assert "different mechanism" in evaluation["details"]
    assert certificate["result"]["status"] != "PASS"

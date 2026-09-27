"""Current ClaimGarden bare-SIM quarantine contract, with no live transport."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
from verifier.domains.common import digest
from verifier.interoperability.artifact_publish import publish_sim_artifact
from verifier.interoperability.claim_garden import ClaimGardenClientError, TransportResponse


PUBLISHER = "publisher:sha256:" + "b" * 64


def specimen():
    model = {"transition": {"x": {"op": "add", "args": [{"var": "x"}, 1.0]}},
             "initial_state": {"x": 0.0}, "units": {"x": "m"},
             "parameters": {"x": {"minimum": 0.0, "maximum": 2.0}},
             "time": {"unit": "s", "step": 0.5, "max_steps": 8},
             "numerics": {"reference": "binary64", "absolute_tolerance": 0.0}, "capabilities": []}
    states, entropy, times = [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}], [0.0, 0.0], [0.0, 0.5, 1.0]
    evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "SIM", "subject_id": "scalar-integrator",
                "artifact": {"transition": model["transition"], "initial_state": model["initial_state"],
                             "trajectory_digest": digest(states), "entropy_digest": digest(entropy),
                             "times_digest": digest(times), "invariants": [{"op": "ge", "args": [{"var": "x"}, 0.0]}]},
                "inputs": {"states": states, "entropy": entropy, "times": times}}
    policy = domain_policy(trust_roots=["fixture:finite-sim"])
    request = domain_request(evidence, target_depth=2)
    certificate = build_domain_certificate(request, evidence, policy=policy)
    artifact = {"kind": "SIM", "title": "Scalar integrator", "description": "Finite synthetic trajectory",
                "rights": {"license": "MIT", "attribution": "fixture", "publisher_statement": "test only"},
                "certification": {"request": request, "certificate": certificate}, "model": model}
    return artifact, request, policy


def prepare(tmp_path, artifact, request, policy):
    path = tmp_path / "sim.json"
    raw = canonical_bytes(artifact)
    path.write_bytes(raw)
    credential = tmp_path / "publisher.token"
    credential.write_text("x" * 48)
    source = "sha256:" + hashlib.sha256(raw).hexdigest()
    args = dict(expected_source_digest=source, expected_request=request, policy=policy,
                publisher_id=PUBLISHER, credential_file=credential)
    return path, raw, args


def status(source, title):
    return {"schema_version": "CLAIM-GARDEN-ARTIFACT-SUBMISSION-1", "source_digest": source,
            "kind": "SIM", "title": title, "state": "PENDING_REVIEW", "revision": 1,
            "reason_code": None, "queue_position": 1, "assessment_state": "RECHECK_PENDING",
            "runnable_digest": None, "assessment": None, "review_digest": None,
            "publication": "PUBLICATION_REQUIRES_HUMAN_REVIEW",
            "rights": "MODERATOR_ATTESTED_NOT_VERIFIED",
            "created_at": "2026-09-27T00:00:00.000Z", "updated_at": "2026-09-27T00:00:00.000Z"}


def test_exact_bare_artifact_goes_to_current_route_after_native_replay(tmp_path):
    artifact, request, policy = specimen()
    path, raw, args = prepare(tmp_path, artifact, request, policy)
    sent = []
    def transport(item):
        sent.append(item)
        return TransportResponse(201, {"content-type": "application/json"},
                                 canonical_bytes(status(args["expected_source_digest"], artifact["title"])))
    result = publish_sim_artifact(path, **args, transport=transport)
    assert result["state"] == "PENDING_REVIEW"
    assert result["publication"] == "NOT_ESTABLISHED"
    assert result["host_response"]["publication"] == "PUBLICATION_REQUIRES_HUMAN_REVIEW"
    assert len(sent) == 1 and sent[0].body == raw
    assert sent[0].url == "https://claimgarden.com/v1/artifacts?publisher_id=" + PUBLISHER
    assert sent[0].headers["Authorization"] == "Bearer " + "x" * 48


@pytest.mark.parametrize("mutation", ["wrapper", "source", "request", "model", "certificate", "missing_certificate"])
def test_broken_intent_or_evidence_never_reaches_transport(tmp_path, mutation):
    artifact, request, policy = specimen()
    artifact = deepcopy(artifact)
    if mutation == "wrapper": artifact["schema_version"] = "legacy-wrapper"
    if mutation == "model": artifact["model"]["transition"]["x"] = 3
    if mutation == "certificate": artifact["certification"]["certificate"]["result"]["domain_depth"] = 5
    if mutation == "missing_certificate": artifact["certification"]["certificate"] = None
    path, _, args = prepare(tmp_path, artifact, request, policy)
    if mutation == "source": args["expected_source_digest"] = "sha256:" + "0" * 64
    if mutation == "request": args["expected_request"] = {**request, "subject_id": "elsewhere"}
    with pytest.raises(ClaimGardenClientError):
        publish_sim_artifact(path, **args, transport=lambda _: pytest.fail("transport reached"))


def test_duplicate_fields_refused_before_transport(tmp_path):
    artifact, request, policy = specimen()
    path, _, args = prepare(tmp_path, artifact, request, policy)
    path.write_bytes(b'{"kind":"SIM","kind":"SIM"}')
    args["expected_source_digest"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ClaimGardenClientError):
        publish_sim_artifact(path, **args, transport=lambda _: pytest.fail("transport reached"))


@pytest.mark.parametrize("mutation", ["source_digest", "queue_position", "assessment_state", "revision"])
def test_unbound_host_response_preserves_unknown_after_transport(tmp_path, mutation):
    artifact, request, policy = specimen()
    path, _, args = prepare(tmp_path, artifact, request, policy)
    forged = status(args["expected_source_digest"], artifact["title"])
    forged[mutation] = {"source_digest": "sha256:" + "0" * 64,
                        "queue_position": 0, "assessment_state": "CURRENT", "revision": True}[mutation]
    result = publish_sim_artifact(path, **args, transport=lambda _: TransportResponse(
        201, {"content-type": "application/json"}, canonical_bytes(forged)))
    assert result == {"result": "INDETERMINATE", "state": "UNKNOWN",
                      "source_digest": args["expected_source_digest"], "transport_performed": True,
                      "publication": "NOT_ESTABLISHED", "reason": "ClaimGardenClientError"}


def test_cli_routes_sim_artifact_with_external_intent(tmp_path, monkeypatch, capsys):
    from verifier.runtime.public_cli import main
    import verifier.interoperability.artifact_publish as client

    artifact, request, policy = specimen()
    path, _, args = prepare(tmp_path, artifact, request, policy)
    request_path, policy_path = tmp_path / "request.json", tmp_path / "policy.json"
    request_path.write_bytes(canonical_bytes(request))
    policy_path.write_bytes(canonical_bytes(policy))
    calls = []

    def fake_submit(*positional, **keyword):
        calls.append((positional, keyword))
        return {"result": "SUBMITTED", "state": "PENDING_REVIEW",
                "source_digest": args["expected_source_digest"], "publication": "NOT_ESTABLISHED"}

    monkeypatch.setattr(client, "publish_sim_artifact", fake_submit)
    command = ["publish", str(path), "--sim-artifact", "--sim-request", str(request_path),
               "--sim-policy", str(policy_path), "--source-digest", args["expected_source_digest"],
               "--publisher-id", PUBLISHER, "--credential-file", str(args["credential_file"]), "--json"]
    assert main(command) == 0
    assert json.loads(capsys.readouterr().out)["publication"] == "NOT_ESTABLISHED"
    assert len(calls) == 1 and calls[0][0] == (str(path),)
    assert calls[0][1]["expected_request"] == request
    assert calls[0][1]["policy"] == policy
    assert calls[0][1]["expected_source_digest"] == args["expected_source_digest"]


def test_cli_refuses_mixed_sim_and_gated_modes(tmp_path):
    from verifier.runtime.public_cli import main
    with pytest.raises(SystemExit):
        main(["publish", str(tmp_path / "missing"), "--sim-artifact", "--gated"])

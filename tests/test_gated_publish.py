"""Verifier Standard (VSTD) gated publication contract tests.

JavaScript Object Notation (JSON); Hypertext Transfer Protocol (HTTP).
All network responses are injected test values, not observations of a live host.
"""
# Terminology: Hypertext Transfer Protocol Secure (HTTPS).

from __future__ import annotations

import importlib
import hashlib
import json
from pathlib import Path
import sys
import urllib.parse

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
from verifier.domains.common import Budget, digest, merkle_root
from verifier.runtime.gate_pipeline import run_pipeline
from verifier.interoperability.claim_garden import TransportResponse


def client():
    return importlib.import_module("verifier.interoperability.gated_publish")


def native_files(root: Path, *, value: object = 3, field: str = "integer", include_artifact: bool = True) -> dict:
    rows = [{"value": value}]
    commitment = {"digest": digest(rows), "records": 1, "bytes": len(canonical_bytes(rows)),
                  "record_digests": [digest(row) for row in rows], "merkle_root": merkle_root(rows, Budget(10000))}
    artifact = {"schema_version":"verifier-domain-evidence-1","domain":"DATA","subject_id":"test:synthetic-dataset",
                "artifact":{"shards":{"records":commitment},"fields":{"value":field}},"inputs":{"shards":{"records":rows}}}
    request = domain_request(artifact,target_depth=2)
    policy = domain_policy(trust_roots=["test:consumer-selected-checker"])
    certificate = build_domain_certificate(request,artifact,policy=policy)
    for name, document in (("artifact",artifact),("request",request),("policy",policy),("certificate",certificate)):
        (root/(name+".json")).write_bytes(canonical_bytes(document)+b"\n")
    inputs = ["request.json","policy.json","certificate.json"] + (["artifact.json"] if include_artifact else [])
    # The gate is genuine local execution; the protocol tests make no external claim.
    manifest = {"schema_version":"verifier-gate-pipeline-1","root":".","inputs":inputs,"overall_timeout_seconds":10,
                "max_output_bytes":65536,"steps":[{"id":"check","argv":[sys.executable,"-B","-c","print('retained command observation')"],
                "needs":[],"timeout_seconds":3}]}
    path = root/"pipeline.json"
    path.write_text(json.dumps(manifest),encoding="utf-8")
    run_pipeline(path,root/"gate_receipt.json")
    return {"artifact_path":root/"artifact.json","request_path":root/"request.json","certificate_path":root/"certificate.json",
            "policy_path":root/"policy.json","gate_receipt_path":root/"gate_receipt.json","manifest_path":path}


def test_projection_omits_execution_coordinates_and_raw_streams(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    projection = client().project_gate_receipt(files["gate_receipt_path"],manifest_path=files["manifest_path"])
    assert projection["schema_version"] == "verifier-gate-publication-1"
    assert projection["evidence_class"] == "UNAUTHENTICATED_LOCAL_REPORT"
    assert set(projection) == {"schema_version","evidence_class","source_receipt_digest","runner_digest","manifest_digest",
                               "inputs","final_inputs","inputs_unchanged","steps","status","projection_digest"}
    encoded = json.dumps(projection)
    assert str(tmp_path) not in encoded and sys.executable not in encoded
    assert "retained command observation" not in encoded and "executables" not in encoded and "manifest_path" not in encoded
    assert set(projection["steps"][0]) == {"id","needs","result_contract","status","exit_code","cleanup","stdout_digest","stderr_digest"}


def test_preparation_preserves_raw_noncanonical_bytes_and_native_binding(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    payload = client().prepare_gated_publication(**files)
    assert set(payload) == {"schema_version","artifact_json","request_json","certificate_json","gate_receipt_json"}
    assert payload["schema_version"] == "CLAIM-GARDEN-GATED-PUBLISH-1"
    assert payload["artifact_json"].endswith("\n")
    certificate = json.loads(payload["certificate_json"])
    assert json.loads(payload["artifact_json"]) == certificate["evidence"]
    assert json.loads(payload["request_json"]) == certificate["request"]
    assert json.loads(payload["gate_receipt_json"])["status"] == "PASS"


@pytest.mark.parametrize("value,field", [("wrong","integer"),(3,"unsupported-type")])
def test_preparation_rejects_native_fail_and_unknown(tmp_path: Path, value: object, field: str) -> None:
    files = native_files(tmp_path,value=value,field=field)
    with pytest.raises(client().GatedPublishError):
        client().prepare_gated_publication(**files)


def test_preparation_rejects_artifact_omitted_from_gate_scope(tmp_path: Path) -> None:
    files = native_files(tmp_path,include_artifact=False)
    with pytest.raises(client().GatedPublishError,match="input"):
        client().prepare_gated_publication(**files)


def test_changed_source_bytes_reject_before_publication(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    with files["request_path"].open("a",encoding="utf-8") as stream:
        stream.write(" ")
    with pytest.raises(client().GatedPublishError):
        client().prepare_gated_publication(**files)


def test_projection_refuses_rehashed_claimed_success_over_nonzero_exit(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    from verifier.runtime.gate_pipeline import _canonical,_digest
    receipt = json.loads(files["gate_receipt_path"].read_text())
    receipt["steps"][0]["exit_code"] = 7
    receipt.pop("receipt_digest")
    receipt["receipt_digest"] = _digest(_canonical(receipt))
    files["gate_receipt_path"].write_text(json.dumps(receipt))
    with pytest.raises(client().GatedPublishError):
        client().project_gate_receipt(files["gate_receipt_path"],manifest_path=files["manifest_path"])


def test_unicode_escaped_local_path_cannot_bypass_disclosure_guard(tmp_path: Path) -> None:
    files = native_files(tmp_path,value="/home/"+"example/private",field="string")
    for key in ("artifact_path","certificate_path"):
        raw = files[key].read_text(encoding="utf-8")
        files[key].write_text(raw.replace("/home/", "/"+chr(92)+"u0068ome/"),encoding="utf-8")
    fresh = tmp_path/"fresh-receipt.json"
    run_pipeline(files["manifest_path"],fresh)
    files["gate_receipt_path"] = fresh
    with pytest.raises(client().GatedPublishError,match="path|secret"):
        client().prepare_gated_publication(**files)


PUBLISHER = "publisher:sha256:" + "1"*64


def hashed(value: object) -> str:
    return "sha256:"+hashlib.sha256(canonical_bytes(value)).hexdigest()


def account(payload: dict, *, used: int = 0) -> dict:
    certificate = json.loads(payload["certificate_json"])
    projection = json.loads(payload["gate_receipt_json"])
    return {"schema_version":"CLAIM-GARDEN-PUBLISH-ACCOUNT-1","publisher_id":PUBLISHER,"linked":True,
            "quota":{"limit_bytes":10000000,"used_bytes":used,"remaining_bytes":10000000-used},
            "limits":{"artifact_bytes":262144,"request_bytes":4096,"certificate_bytes":262144,
                      "gate_receipt_bytes":262144,"assessment_reservation_bytes":65536},
            "coordinate":{"policy_digest":certificate["policy_digest"],"checker_coordinate":"sha256:"+"a"*64,
                          "gate_runner_digest":projection["runner_digest"]}}


def stored(payload: dict, selected_account: dict, *, duplicate: bool = False) -> dict:
    component_digests = {name+"_digest":"sha256:"+hashlib.sha256(payload[name+"_json"].encode("utf-8")).hexdigest()
                         for name in ("artifact","request","certificate","gate_receipt")}
    payload_digest = hashed(component_digests)
    coordinate_digest = hashed(selected_account["coordinate"])
    submission = hashed({"publisher_id":PUBLISHER,"payload_digest":payload_digest,"coordinate_digest":coordinate_digest})
    charged = sum(len(payload[name+"_json"].encode("utf-8")) for name in ("artifact","request","certificate","gate_receipt"))+65536
    return {"schema_version":"CLAIM-GARDEN-GATED-STORED-1","status":"STORED","state":"PENDING_REVIEW","outcome":"PASS",
            "submission_id":submission,"publisher_id":PUBLISHER,"payload_digest":payload_digest,**component_digests,
            "coordinate":selected_account["coordinate"],"charged_bytes":charged,"quota":{"limit_bytes":10000000,"used_bytes":charged,"remaining_bytes":10000000-charged},
            "deduplicated":duplicate,"publication_gate":"HUMAN_REVIEW_REQUIRED","gate_evidence":"UNAUTHENTICATED_LOCAL_REPORT",
            "retrieval_path":"/v1/publish/submissions/"+submission+"?publisher_id="+urllib.parse.quote(PUBLISHER,safe="")}


def response(document: dict, status: int = 200) -> TransportResponse:
    return TransportResponse(status,{"Content-Type":"application/json"},canonical_bytes(document))


@pytest.mark.parametrize("duplicate",[False,True])
def test_injected_account_and_storage_exact_bindings(tmp_path: Path, duplicate: bool) -> None:
    files = native_files(tmp_path)
    payload = client().prepare_gated_publication(**files)
    selected = account(payload)
    receipt = stored(payload,selected,duplicate=duplicate)
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    requests = []
    def transport(request):
        requests.append(request)
        return response(selected) if request.method == "GET" else response(receipt,200 if duplicate else 201)
    result = client().publish_gated(**files,publisher_id=PUBLISHER,credential_file=credential,
                                   endpoint="https://hub.invalid",private_review_consent=True,transport=transport)
    assert result["result"] == "SUBMITTED" and result["state"] == "PENDING_REVIEW"
    assert result["publication"] == "NOT_ESTABLISHED" and result["deduplicated"] is duplicate
    assert [request.method for request in requests] == ["GET","POST"]
    assert requests[0].url == "https://hub.invalid/v1/publish/account?publisher_id="+urllib.parse.quote(PUBLISHER,safe="")
    assert requests[1].headers["X-Claim-Garden-Retention-Consent"] == "private-review"
    assert requests[1].headers["Authorization"] == "Bearer "+"T"*48
    assert json.loads(requests[1].body) == payload


@pytest.mark.parametrize("field,bad",[("artifact_digest","sha256:"+"0"*64),("payload_digest","sha256:"+"0"*64),
    ("submission_id","sha256:"+"0"*64),("state","APPROVED"),("outcome","UNKNOWN"),("charged_bytes",True),
    ("deduplicated",True),("publication_gate","NONE"),("gate_evidence","AUTHENTICATED"),("retrieval_path","/elsewhere")])
def test_changed_storage_response_never_becomes_success(tmp_path: Path, field: str, bad: object) -> None:
    files = native_files(tmp_path)
    payload = client().prepare_gated_publication(**files)
    selected = account(payload)
    receipt = stored(payload,selected)
    receipt[field] = bad
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    with pytest.raises(client().GatedPublishError):
        client().publish_gated(**files,publisher_id=PUBLISHER,credential_file=credential,endpoint="https://hub.invalid",
            private_review_consent=True,transport=lambda req: response(selected) if req.method == "GET" else response(receipt,201))


def test_consent_and_coordinate_mismatch_prevent_submission(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    calls = []
    with pytest.raises(client().GatedPublishError,match="consent"):
        client().publish_gated(**files,publisher_id=PUBLISHER,credential_file=credential,transport=lambda req:calls.append(req))
    assert calls == []
    selected = account(client().prepare_gated_publication(**files))
    selected["coordinate"]["gate_runner_digest"] = "sha256:"+"0"*64
    def transport(request):
        calls.append(request)
        return response(selected)
    with pytest.raises(client().GatedPublishError,match="coordinate"):
        client().publish_gated(**files,publisher_id=PUBLISHER,credential_file=credential,private_review_consent=True,transport=transport)
    assert [request.method for request in calls] == ["GET"]


def cli_arguments(files: dict) -> list[str]:
    return ["publish",str(files["gate_receipt_path"]),"--gated","--artifact",str(files["artifact_path"]),
            "--request",str(files["request_path"]),"--certificate",str(files["certificate_path"]),
            "--policy",str(files["policy_path"]),"--manifest",str(files["manifest_path"]),"--json"]


def test_cli_dry_run_requires_no_credentials_or_transport(tmp_path: Path, monkeypatch, capsys) -> None:
    from verifier.runtime.public_cli import main
    files = native_files(tmp_path)
    capsys.readouterr()
    monkeypatch.setattr(client(),"_default_transport",lambda request: pytest.fail("dry run performed transport"))
    output = tmp_path/"prepared.json"
    assert main(cli_arguments(files)+["--dry-run","--output",str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PREPARED" and result["transport_performed"] is False
    assert result["publication"] == "NOT_ESTABLISHED"
    assert json.loads(output.read_bytes())["artifact_json"] == files["artifact_path"].read_bytes().decode("utf-8")
    original = output.read_bytes()
    assert main(cli_arguments(files)+["--dry-run","--output",str(output)]) == 1
    assert output.read_bytes() == original


def test_cli_unknown_native_result_remains_unknown(tmp_path: Path, capsys) -> None:
    from verifier.runtime.public_cli import main
    files = native_files(tmp_path,field="unsupported-type")
    capsys.readouterr()
    assert main(cli_arguments(files)+["--dry-run"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "UNKNOWN" and result["transport_performed"] is False


def test_cli_account_is_read_only(tmp_path: Path, monkeypatch, capsys) -> None:
    from verifier.runtime.public_cli import main
    files = native_files(tmp_path)
    selected = account(client().prepare_gated_publication(**files))
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    calls = []
    def transport(request):
        calls.append(request)
        return response(selected)
    monkeypatch.setattr(client(),"_default_transport",transport)
    capsys.readouterr()
    assert main(["account","--publisher-id",PUBLISHER,"--credential-file",str(credential),"--endpoint","https://hub.invalid","--json"]) == 0
    assert json.loads(capsys.readouterr().out) == selected
    assert [request.method for request in calls] == ["GET"]


@pytest.mark.parametrize("status,outcome",[(422,"FAIL"),(422,"UNKNOWN"),(422,"REJECTED"),(503,None),(401,None),(429,None)])
def test_negative_host_response_is_never_stored_or_retried(tmp_path: Path,status: int,outcome: str | None) -> None:
    files = native_files(tmp_path)
    payload = client().prepare_gated_publication(**files)
    selected = account(payload)
    positive = stored(payload,selected)
    negative = {"error":{"code":"SYNTHETIC_REFUSAL"}}
    if outcome is not None:
        negative.update(outcome=outcome,**{name:positive[name] for name in ("submission_id","charged_bytes","quota")})
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    calls = []
    def transport(request):
        calls.append(request)
        return response(selected) if request.method == "GET" else response(negative,status)
    with pytest.raises(client().GatedPublishError) as caught:
        client().publish_gated(**files,publisher_id=PUBLISHER,credential_file=credential,private_review_consent=True,transport=transport)
    assert caught.value.submission_attempted is True
    if outcome is not None:
        assert caught.value.details["outcome"] == outcome
    assert [request.method for request in calls] == ["GET","POST"]


@pytest.mark.parametrize("headers",[None,{1:"application/json"},{"Content-Type":None}])
def test_malformed_transport_headers_reject_boundedly(headers) -> None:
    with pytest.raises(client().GatedPublishError):
        client()._response(TransportResponse(200,headers,b"{}"))


def test_projection_rehashes_original_after_local_check(tmp_path: Path,monkeypatch) -> None:
    files = native_files(tmp_path)
    original = client().check_pipeline
    def racing_check(*args,**kwargs):
        checked = original(*args,**kwargs)
        receipt = json.loads(files["gate_receipt_path"].read_bytes())
        receipt["steps"][0]["stdout"] = "modified after local check"
        files["gate_receipt_path"].write_bytes(canonical_bytes(receipt))
        return checked
    monkeypatch.setattr(client(),"check_pipeline",racing_check)
    with pytest.raises(client().GatedPublishError,match="changed"):
        client().project_gate_receipt(files["gate_receipt_path"],manifest_path=files["manifest_path"])


def test_cli_reports_attempted_account_read(tmp_path: Path,monkeypatch,capsys) -> None:
    from verifier.runtime.public_cli import main
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    monkeypatch.setattr(client(),"_default_transport",lambda req: response({"error":{"code":"UNLINKED"}},403))
    assert main(["account","--publisher-id",PUBLISHER,"--credential-file",str(credential),"--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["transport_performed"] is True and result["publication"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("replacement",[3.0,True])
def test_native_input_binding_preserves_json_numeric_types(tmp_path: Path,replacement: object) -> None:
    original = 1 if replacement is True else 3
    files = native_files(tmp_path,value=original)
    artifact = json.loads(files["artifact_path"].read_bytes())
    rows = next(iter(artifact["inputs"]["shards"].values()))
    rows[0]["value"] = replacement
    files["artifact_path"].write_bytes(canonical_bytes(artifact)+b"\n")
    fresh = tmp_path/"mutated-receipt.json"
    run_pipeline(files["manifest_path"],fresh)
    files["gate_receipt_path"] = fresh
    with pytest.raises(client().GatedPublishError,match="differs"):
        client().prepare_gated_publication(**files)


def test_external_request_binding_preserves_integer_type(tmp_path: Path) -> None:
    files = native_files(tmp_path)
    request = json.loads(files["request_path"].read_bytes())
    request["target_depth"] = float(request["target_depth"])
    files["request_path"].write_bytes(canonical_bytes(request)+b"\n")
    fresh = tmp_path/"request-receipt.json"
    run_pipeline(files["manifest_path"],fresh)
    files["gate_receipt_path"] = fresh
    with pytest.raises(client().GatedPublishError,match="differs"):
        client().prepare_gated_publication(**files)


def test_packaged_projection_schema_matches_real_exporter(tmp_path: Path) -> None:
    from importlib.resources import files as resources
    import jsonschema
    schema = json.loads(resources("verifier").joinpath("schemas/verifier-gate-publication-1.schema.json").read_text(encoding="utf-8"))
    files = native_files(tmp_path)
    projection = client().project_gate_receipt(files["gate_receipt_path"],manifest_path=files["manifest_path"])
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(projection,schema)
    for path in ("../private","a/../b","a\\b","/root/private",chr(67) + ":/" + "private","a//b"):
        projection["inputs"][0]["path"] = path
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(projection,schema)


def test_cli_submit_uses_gated_route_and_leaves_human_review(tmp_path: Path,monkeypatch,capsys) -> None:
    from verifier.runtime.public_cli import main
    files = native_files(tmp_path)
    payload = client().prepare_gated_publication(**files)
    selected = account(payload)
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    calls = []
    def transport(request):
        calls.append(request)
        return response(selected) if request.method == "GET" else response(stored(payload,selected),201)
    monkeypatch.setattr(client(),"_default_transport",transport)
    capsys.readouterr()
    assert main(cli_arguments(files)+["--publisher-id",PUBLISHER,"--credential-file",str(credential),"--private-review-consent"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "PENDING_REVIEW" and result["publication"] == "NOT_ESTABLISHED"
    assert len(calls) == 2 and "/v1/publish/submissions?" in calls[-1].url


@pytest.mark.parametrize("endpoint",[
    "https://hub.invalid\n.attacker.invalid",
    "https://hub.invalid\t.attacker.invalid",
    "\x01https://hub.invalid",
    "https://hub.invalid\r.attacker.invalid",
    "https://hub.invalid .attacker.invalid",
    "https://hub.invalid\x7f.attacker.invalid",
    "https://hub.invalid\x80.attacker.invalid",
    "https://hub.invalid\x85.attacker.invalid",
    "https://hub.invalid\x9f.attacker.invalid",
    "https://hub.invalid\u00a0.attacker.invalid",
    "https://hub.invalid\u2003.attacker.invalid",
    "https://hub.invalid\n",
    "", None, 23, b"https://hub.invalid",
],ids=["embedded-newline","embedded-tab","leading-control-zero","embedded-carriage-return",
       "embedded-space","delete-control","control-one-start","control-one-whitespace","control-one-end",
       "nonbreaking-space","em-space","trailing-newline","empty","none","integer","bytes"])
def test_account_endpoint_rejects_raw_controls_before_transport(tmp_path: Path,endpoint: object) -> None:
    """Reject original endpoint text before parsing can silently normalize it."""
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    calls = []
    def transport(request):
        calls.append(request)
        return response({"error":{"code":"SYNTHETIC_REFUSAL"}},401)
    with pytest.raises(client().ClaimGardenClientError):
        client().get_publish_account(PUBLISHER,credential,endpoint=endpoint,transport=transport)
    assert calls == []


@pytest.mark.parametrize("endpoint,expected_origin",[
    ("https://hub.invalid","https://hub.invalid"),
    ("https://hub.invalid/","https://hub.invalid"),
    ("https://hub.invalid:8443/","https://hub.invalid:8443"),
    ("https://[2001:db8::1]:8443/","https://[2001:db8::1]:8443"),
    ("HTTPS://hub.invalid","https://hub.invalid"),
],ids=["origin","trailing-slash","custom-port","internet-protocol-version-six","uppercase-scheme"])
def test_account_endpoint_preserves_supported_https_origins(tmp_path: Path,endpoint: str,expected_origin: str) -> None:
    """Keep custom ports and Internet Protocol version 6 (IPv6) compatibility."""
    credential = tmp_path/"credential"
    credential.write_text("T"*48,encoding="ascii")
    selected = account({"certificate_json":json.dumps({"policy_digest":"sha256:"+"2"*64}),
                        "gate_receipt_json":json.dumps({"runner_digest":"sha256:"+"3"*64})})
    calls = []
    def transport(request):
        calls.append(request)
        return response(selected)
    assert client().get_publish_account(PUBLISHER,credential,endpoint=endpoint,transport=transport) == selected
    assert len(calls) == 1 and calls[0].method == "GET"
    assert calls[0].url == expected_origin+"/v1/publish/account?publisher_id="+urllib.parse.quote(PUBLISHER,safe="")
    assert calls[0].headers["Authorization"] == "Bearer "+"T"*48

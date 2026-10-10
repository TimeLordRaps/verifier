"""Gated Claim Garden preparation and bounded submission for Verifier Standard (VSTD).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8); Hypertext Transfer Protocol (HTTP);
Hypertext Transfer Protocol Secure (HTTPS); uniform resource locator (URL);
command-line interface (CLI). Byte quotas count exact UTF-8 bytes, not characters.
The minimized gate report does not authenticate execution, identity, permission,
or its original receipt. Native domain replay and human review remain separate.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
import urllib.error
import urllib.parse
import urllib.request

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from verifier.domains.certification import recheck_domain_certificate
from verifier.runtime.gate import SECRET_PATTERNS, scan_paths_in_text
from verifier.runtime.gate_pipeline import check_pipeline, _manifest, _relative
from .claim_garden import ClaimGardenClientError, Transport, TransportRequest, TransportResponse, _base_url, _NoRedirect
from .network import NetworkError, _read_bounded_regular

PROJECTION = "verifier-gate-publication-1"
REQUEST = "CLAIM-GARDEN-GATED-PUBLISH-1"
EVIDENCE_CLASS = "UNAUTHENTICATED_LOCAL_REPORT"
LIMITS = {"artifact_bytes": 262144, "request_bytes": 4096, "certificate_bytes": 262144,
          "gate_receipt_bytes": 262144, "assessment_reservation_bytes": 65536}
QUOTA_LIMIT = 10000000
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}")
_PUBLISHER = re.compile(r"publisher:sha256:[0-9a-f]{64}")
_COMPONENTS = ("artifact", "request", "certificate", "gate_receipt")


class GatedPublishError(ClaimGardenClientError):
    """Preparation, account or exact storage binding was not established."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None, submission_attempted: bool = False,
                 transport_performed: bool = False) -> None:
        super().__init__(message)
        self.details = {} if details is None else details
        self.submission_attempted = submission_attempted
        self.transport_performed = transport_performed or submission_attempted


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _object(value: Any, fields: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (fields is not None and set(value) != fields):
        raise GatedPublishError("unexpected or missing protocol fields")
    return value


def _json(raw: str | bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        _object(value)
        canonical_bytes(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise GatedPublishError("strict finite JSON object required") from error


def _read(path: str | Path, maximum: int) -> bytes:
    try:
        return _read_bounded_regular(path, maximum, "publication input")
    except (NetworkError, OSError) as error:
        raise GatedPublishError("publication input must be a bounded regular file") from error


def _portable(value: Any) -> str:
    if (type(value) is not str or not value or len(value) > 1024 or "\\" in value or ":" in value
            or value.startswith("/") or any(ord(char) < 32 for char in value)
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise GatedPublishError("selected input path is not portable")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise GatedPublishError("SHA-256 coordinate required")
    return value


def validate_projection(value: Any, *, require_pass: bool = True) -> dict[str, Any]:
    """Check minimized report structure; never authenticate the omitted original."""
    fields = {"schema_version", "evidence_class", "source_receipt_digest", "runner_digest", "manifest_digest", "inputs",
              "final_inputs", "inputs_unchanged", "steps", "status", "projection_digest"}
    value = _object(value, fields)
    if value["schema_version"] != PROJECTION or value["evidence_class"] != EVIDENCE_CLASS:
        raise GatedPublishError("unsupported minimized gate report")
    for field in ("source_receipt_digest", "runner_digest", "manifest_digest", "projection_digest"):
        _hash(value[field])
    if value["projection_digest"] != _sha(canonical_bytes({key:item for key,item in value.items() if key != "projection_digest"})):
        raise GatedPublishError("gate projection digest differs")
    if type(value["inputs_unchanged"]) is not bool:
        raise GatedPublishError("input comparison must be boolean")
    for inventory in (value["inputs"], value["final_inputs"]):
        if type(inventory) is not list or not 1 <= len(inventory) <= 1024:
            raise GatedPublishError("selected input inventory unavailable")
        names = []
        total = 0
        for row in inventory:
            _object(row, {"path", "size_bytes", "digest"})
            names.append(_portable(row["path"]))
            _hash(row["digest"])
            if type(row["size_bytes"]) is not int or not 0 <= row["size_bytes"] <= 16777216:
                raise GatedPublishError("invalid input byte count")
            total += row["size_bytes"]
        if total > 16777216 or names != sorted(set(names)):
            raise GatedPublishError("input inventory is duplicate, unordered or beyond bounds")
    if type(value["steps"]) is not list or not 1 <= len(value["steps"]) <= 64:
        raise GatedPublishError("bounded step inventory required")
    seen: dict[str, str] = {}
    for step in value["steps"]:
        _object(step, {"id", "needs", "result_contract", "status", "exit_code", "cleanup", "stdout_digest", "stderr_digest"})
        if type(step["id"]) is not str or not _ID.fullmatch(step["id"]) or step["id"] in seen:
            raise GatedPublishError("invalid step identifier")
        if (type(step["needs"]) is not list or any(type(name) is not str or name not in seen for name in step["needs"])
                or len(step["needs"]) != len(set(step["needs"]))):
            raise GatedPublishError("step dependency order is invalid")
        if type(step["result_contract"]) is not str or step["result_contract"] not in {"process-exit", "vstd-verdict"}:
            raise GatedPublishError("unknown result contract")
        if step["exit_code"] is not None and type(step["exit_code"]) is not int:
            raise GatedPublishError("invalid process exit")
        if type(step["cleanup"]) is not str or step["cleanup"] not in {"UNKNOWN", "NOT_STARTED", "OWNED_TREE_TERMINATED", "OWNED_GROUP_SIGNALLED"}:
            raise GatedPublishError("unknown cleanup coordinate")
        if type(step["status"]) is not str or step["status"] not in {"PASS", "FAIL", "UNKNOWN", "ERROR", "TIMEOUT", "OUTPUT_LIMIT", "BLOCKED"}:
            raise GatedPublishError("unknown step status")
        _hash(step["stdout_digest"])
        _hash(step["stderr_digest"])
        if step["status"] == "PASS" and (step["exit_code"] != 0 or step["cleanup"] not in {"OWNED_TREE_TERMINATED", "OWNED_GROUP_SIGNALLED"}
                                         or any(seen[name] != "PASS" for name in step["needs"])):
            raise GatedPublishError("passing step is inconsistent")
        seen[step["id"]] = step["status"]
    if type(value["status"]) is not str or value["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
        raise GatedPublishError("unknown aggregate status")
    positive = value["inputs_unchanged"] is True and value["inputs"] == value["final_inputs"] and all(status == "PASS" for status in seen.values())
    if value["status"] == "PASS" and not positive:
        raise GatedPublishError("passing aggregate is inconsistent")
    if require_pass and (value["status"] != "PASS" or not positive):
        raise GatedPublishError("a passing unchanged gate report is required")
    return value


def project_gate_receipt(receipt_path: str | Path, *, manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Recheck a local original and derive a separate, minimal unauthenticated report."""
    checked = check_pipeline(receipt_path, manifest_path=manifest_path)
    if checked.get("integrity_status") != "PASS":
        raise GatedPublishError("original gate receipt or current selected input context is invalid")
    receipt = _json(_read(receipt_path, 16777216))
    if (receipt["receipt_digest"] != checked["receipt_digest"]
            or _sha(canonical_bytes({key:value for key,value in receipt.items() if key != "receipt_digest"})) != checked["receipt_digest"]):
        raise GatedPublishError("original gate receipt changed during preparation")
    definitions = {step["id"]:step for step in receipt["manifest"]["steps"]}
    steps = []
    for step in receipt["steps"]:
        definition = definitions[step["id"]]
        steps.append({"id":step["id"], "needs":definition["needs"], "result_contract":definition.get("result_contract", "process-exit"),
                      "status":step["status"], "exit_code":step["exit_code"], "cleanup":step["cleanup"],
                      "stdout_digest":_sha(step["stdout"].encode("utf-8")), "stderr_digest":_sha(step["stderr"].encode("utf-8"))})
    projection = {"schema_version":PROJECTION, "evidence_class":EVIDENCE_CLASS,
                  "source_receipt_digest":receipt["receipt_digest"], "runner_digest":receipt["mechanism_digest"],
                  "manifest_digest":receipt["manifest_digest"], "inputs":receipt["inputs"], "final_inputs":receipt["final_inputs"],
                  "inputs_unchanged":receipt["inputs_unchanged"], "steps":steps, "status":receipt["status"]}
    projection["projection_digest"] = _sha(canonical_bytes(projection))
    return validate_projection(projection, require_pass=False)


def prepare_gated_publication(artifact_path: str | Path, request_path: str | Path, certificate_path: str | Path,
                              gate_receipt_path: str | Path, *, policy_path: str | Path,
                              manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Prepare exact bytes locally; no credential read, account lookup or transmission."""
    projection = project_gate_receipt(gate_receipt_path, manifest_path=manifest_path)
    validate_projection(projection)
    receipt = _json(_read(gate_receipt_path, 16777216))
    if manifest_path is None:
        manifest = _relative(Path(gate_receipt_path).resolve().parent, receipt["manifest_path"])
    else:
        manifest = Path(manifest_path)
    _, root, _ = _manifest(manifest)
    if _sha(_read(manifest, 16777216)) != projection["manifest_digest"]:
        raise GatedPublishError("selected manifest changed during preparation")
    inventory = {row["path"]:row for row in projection["inputs"]}
    documents = {}
    for name, path, maximum in (("artifact",artifact_path,LIMITS["artifact_bytes"]), ("request",request_path,LIMITS["request_bytes"]),
                                 ("certificate",certificate_path,LIMITS["certificate_bytes"]), ("policy",policy_path,262144)):
        try:
            relative = Path(path).absolute().relative_to(root).as_posix()
            resolved = _relative(root, relative)
        except (ValueError, OSError) as error:
            raise GatedPublishError("publication input is outside the selected manifest root") from error
        raw = _read(resolved, maximum)
        expected = {"path":relative,"size_bytes":len(raw),"digest":_sha(raw)}
        if inventory.get(relative) != expected:
            raise GatedPublishError("publication input bytes are not bound by the gate receipt")
        _json(raw)
        documents[name] = raw.decode("utf-8")
    artifact, request, certificate, policy = (_json(documents[name]) for name in ("artifact", "request", "certificate", "policy"))
    if (canonical_bytes(artifact) != canonical_bytes(certificate.get("evidence"))
            or canonical_bytes(request) != canonical_bytes(certificate.get("request"))):
        raise GatedPublishError("artifact or request differs from the native certificate")
    result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    if result.get("status") != "PASS":
        raise GatedPublishError("native certificate replay is not PASS: " + str(result.get("status", "UNKNOWN")),
                               details={"outcome":result.get("status", "UNKNOWN")})
    payload = {"schema_version":REQUEST, "artifact_json":documents["artifact"], "request_json":documents["request"],
               "certificate_json":documents["certificate"], "gate_receipt_json":canonical_bytes(projection).decode("utf-8")}
    for name in _COMPONENTS:
        raw = payload[name + "_json"]
        if len(raw.encode("utf-8")) > LIMITS[name + "_bytes"]:
            raise GatedPublishError("prepared component exceeds the protocol byte limit")
        if _contains_disclosure(_json(raw)):
            raise GatedPublishError("prepared payload contains a local path or recognized secret pattern")
    return payload


def publication_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize exact raw component bindings and protocol byte reservation."""
    _object(payload, {"schema_version", *(name + "_json" for name in _COMPONENTS)})
    if payload["schema_version"] != REQUEST or any(type(payload[name+"_json"]) is not str for name in _COMPONENTS):
        raise GatedPublishError("invalid prepared submission envelope")
    hashes = {name+"_digest":_sha(payload[name+"_json"].encode("utf-8")) for name in _COMPONENTS}
    charged = sum(len(payload[name+"_json"].encode("utf-8")) for name in _COMPONENTS) + LIMITS["assessment_reservation_bytes"]
    return {"status":"PREPARED", **hashes, "payload_digest":_sha(canonical_bytes(hashes)), "charged_bytes":charged,
            "transport_performed":False, "publication":"NOT_ESTABLISHED", "gate_evidence":EVIDENCE_CLASS}


def _contains_disclosure(value: Any) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and (scan_paths_in_text(item) or any(pattern.search(item) for _,pattern in SECRET_PATTERNS)):
            return True
    return False


def _default_transport(request: TransportRequest) -> TransportResponse:
    """One bounded HTTPS request, without redirects or retries; preserve error bodies."""
    opener = urllib.request.build_opener(_NoRedirect())
    native = urllib.request.Request(request.url, data=request.body if request.method != "GET" else None,
                                    method=request.method, headers=dict(request.headers))
    try:
        try:
            response = opener.open(native, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.geturl() != request.url:
                raise GatedPublishError("authenticated request changed URL")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > 1048576):
                raise GatedPublishError("response exceeds its declared byte bound")
            raw = response.read(1048577)
            if len(raw) > 1048576 or (length is not None and len(raw) != int(length)):
                raise GatedPublishError("response is overbound or truncated")
            return TransportResponse(response.status, dict(response.headers), raw)
    except (OSError, urllib.error.URLError) as error:
        raise GatedPublishError("request response unavailable; no automatic retry") from error


def _response(response: TransportResponse) -> dict[str, Any]:
    if (not isinstance(response, TransportResponse) or type(response.status) is not int
            or not isinstance(response.headers, Mapping)
            or any(type(key) is not str or type(value) is not str for key,value in response.headers.items())
            or type(response.body) is not bytes or len(response.body) > 1048576):
        raise GatedPublishError("invalid bounded transport response")
    content_type = next((value for key,value in response.headers.items() if key.lower() == "content-type"), "")
    if type(content_type) is not str or content_type.split(";",1)[0].strip().lower() != "application/json":
        raise GatedPublishError("response content type is not JSON")
    return _json(response.body)


def _identity(publisher_id: str, credential_file: str | Path) -> str:
    if type(publisher_id) is not str or not _PUBLISHER.fullmatch(publisher_id):
        raise GatedPublishError("registered publisher:sha256 identity required")
    try:
        token = _read(credential_file, 512).decode("ascii").strip()
    except (UnicodeError, TypeError) as error:
        raise GatedPublishError("publisher credential is malformed") from error
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,512}", token):
        raise GatedPublishError("publisher credential is malformed")
    return token


def _quota(value: Any) -> dict[str, Any]:
    quota = _object(value, {"limit_bytes", "used_bytes", "remaining_bytes"})
    if (any(type(item) is not int or item < 0 for item in quota.values()) or quota["limit_bytes"] != QUOTA_LIMIT
            or quota["used_bytes"] + quota["remaining_bytes"] != quota["limit_bytes"]):
        raise GatedPublishError("quota response is inconsistent")
    return quota


def _coordinate(value: Any) -> dict[str, Any]:
    coordinate = _object(value, {"policy_digest", "checker_coordinate", "gate_runner_digest"})
    for item in coordinate.values():
        _hash(item)
    return coordinate


def _call(transport: Transport, method: str, url: str, token: str, payload: dict[str, Any] | None = None,
          *, consent: bool = False) -> TransportResponse:
    headers = {"Accept":"application/json", "Authorization":"Bearer " + token}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if consent:
        headers["X-Claim-Garden-Retention-Consent"] = "private-review"
    try:
        return transport(TransportRequest(method, url, headers, b"" if payload is None else canonical_bytes(payload)))
    except (OSError, ValueError) as error:
        raise GatedPublishError("request response unavailable; no automatic retry", submission_attempted=method == "POST",transport_performed=True) from error


def _account(base: str, publisher_id: str, token: str, transport: Transport) -> dict[str, Any]:
    try:
        return _read_account(base,publisher_id,token,transport)
    except GatedPublishError as error:
        raise GatedPublishError(str(error),details=error.details,transport_performed=True) from error


def _read_account(base: str, publisher_id: str, token: str, transport: Transport) -> dict[str, Any]:
    response = _call(transport, "GET", base + "/v1/publish/account?publisher_id=" + urllib.parse.quote(publisher_id, safe=""), token)
    document = _response(response)
    if response.status != 200:
        raise GatedPublishError("account authentication, linkage or availability not established", details={"http_status":response.status})
    _object(document, {"schema_version", "publisher_id", "linked", "quota", "limits", "coordinate"})
    if document["schema_version"] != "CLAIM-GARDEN-PUBLISH-ACCOUNT-1" or document["publisher_id"] != publisher_id or document["linked"] is not True:
        raise GatedPublishError("account response does not establish the selected linked publisher")
    _quota(document["quota"])
    limits = _object(document["limits"], set(LIMITS))
    if any(type(value) is not int for value in limits.values()) or limits != LIMITS:
        raise GatedPublishError("host byte-limit contract differs")
    _coordinate(document["coordinate"])
    return document


def get_publish_account(publisher_id: str, credential_file: str | Path, *, endpoint: str = "https://claimgarden.com",
                        transport: Transport | None = None) -> dict[str, Any]:
    """Read authenticated linkage, limits and current host coordinates; submit nothing."""
    token = _identity(publisher_id, credential_file)
    return _account(_base_url(endpoint), publisher_id, token, transport or _default_transport)


def _stored(document: dict[str, Any], status: int, publisher_id: str, payload: dict[str, Any],
            coordinate: dict[str, Any]) -> dict[str, Any]:
    summary = publication_summary(payload)
    coordinate_digest = _sha(canonical_bytes(coordinate))
    submission_id = _sha(canonical_bytes({"publisher_id":publisher_id, "payload_digest":summary["payload_digest"],
                                         "coordinate_digest":coordinate_digest}))
    if status not in {200,201}:
        details: dict[str, Any] = {"http_status":status}
        outcome = document.get("outcome")
        if type(outcome) is str and outcome in {"FAIL", "UNKNOWN", "REJECTED"}:
            if document.get("submission_id") != submission_id or document.get("charged_bytes") != summary["charged_bytes"]:
                raise GatedPublishError("retained negative response binding differs")
            _quota(document.get("quota"))
            details.update(outcome=outcome, submission_id=submission_id, charged_bytes=summary["charged_bytes"], quota=document["quota"])
        raise GatedPublishError("host refused gated submission", details=details, submission_attempted=True)
    fields = {"schema_version", "status", "state", "outcome", "submission_id", "publisher_id", "payload_digest",
              "artifact_digest", "request_digest", "certificate_digest", "gate_receipt_digest", "coordinate", "charged_bytes",
              "quota", "deduplicated", "publication_gate", "gate_evidence", "retrieval_path"}
    _object(document, fields)
    expected = {"schema_version":"CLAIM-GARDEN-GATED-STORED-1", "status":"STORED", "state":"PENDING_REVIEW", "outcome":"PASS",
                "submission_id":submission_id, "publisher_id":publisher_id, "coordinate":coordinate,
                "publication_gate":"HUMAN_REVIEW_REQUIRED", "gate_evidence":EVIDENCE_CLASS,
                "retrieval_path":"/v1/publish/submissions/" + submission_id + "?publisher_id=" + urllib.parse.quote(publisher_id, safe="")}
    expected.update({field:summary[field] for field in ("payload_digest", "artifact_digest", "request_digest", "certificate_digest", "gate_receipt_digest")})
    if (any(document[field] != value for field,value in expected.items()) or type(document["charged_bytes"]) is not int
            or document["charged_bytes"] != summary["charged_bytes"] or type(document["deduplicated"]) is not bool
            or document["deduplicated"] != (status == 200)):
        raise GatedPublishError("storage response does not bind exact bytes, coordinate, charge and review state")
    quota = _quota(document["quota"])
    if quota["used_bytes"] < document["charged_bytes"]:
        raise GatedPublishError("storage charge exceeds reported usage")
    return {**document, "result":"SUBMITTED", "transport_performed":True, "publication":"NOT_ESTABLISHED"}


def publish_gated(artifact_path: str | Path, request_path: str | Path, certificate_path: str | Path,
                   gate_receipt_path: str | Path, *, policy_path: str | Path, publisher_id: str,
                   credential_file: str | Path, manifest_path: str | Path | None = None,
                   endpoint: str = "https://claimgarden.com", private_review_consent: bool = False,
                   expected_checker_coordinate: str | None = None, transport: Transport | None = None) -> dict[str, Any]:
    """Prepare, preflight an account, and submit once for private human review."""
    if private_review_consent is not True:
        raise GatedPublishError("explicit private-review retention consent required")
    payload = prepare_gated_publication(artifact_path,request_path,certificate_path,gate_receipt_path,
                                       policy_path=policy_path,manifest_path=manifest_path)
    token = _identity(publisher_id,credential_file)
    base, execute = _base_url(endpoint), transport or _default_transport
    account = _account(base,publisher_id,token,execute)
    coordinate = account["coordinate"]
    certificate, projection = _json(payload["certificate_json"]), _json(payload["gate_receipt_json"])
    if (coordinate["policy_digest"] != certificate["policy_digest"] or coordinate["gate_runner_digest"] != projection["runner_digest"]
            or (expected_checker_coordinate is not None and coordinate["checker_coordinate"] != _hash(expected_checker_coordinate))):
        raise GatedPublishError("host policy, gate runner or selected checker coordinate differs",transport_performed=True)
    # checker_coordinate is a host deployment digest, not certificate.mechanism_digest.
    try:
        response = _call(execute,"POST",base + "/v1/publish/submissions?publisher_id=" + urllib.parse.quote(publisher_id,safe=""),
                         token,payload,consent=True)
        return _stored(_response(response),response.status,publisher_id,payload,coordinate)
    except GatedPublishError as error:
        raise GatedPublishError(str(error),details=error.details,submission_attempted=True) from error


def add_gated_publish_options(publish_parser: Any, subparsers: Any) -> None:
    """Add explicit opt-in commands while retaining the legacy publish route."""
    publish_parser.add_argument("--gated", action="store_true", help="Prepare or submit native evidence bound to a local gate receipt.")
    for name, help_text in (("artifact","Full native evidence bundle JSON file."),
                            ("request","External native request JSON file."),
                            ("certificate","Native domain certificate JSON file."),
                            ("policy","Independently selected native policy JSON file."),
                            ("manifest","Selected gate pipeline manifest JSON file.")):
        publish_parser.add_argument("--"+name, help=help_text)
    publish_parser.add_argument("--dry-run",action="store_true",help="Prepare locally; read no credentials and perform no transport.")
    publish_parser.add_argument("--output",help="Create a new prepared envelope file during --gated --dry-run; never overwrite.")
    publish_parser.add_argument("--private-review-consent",action="store_true",help="Consent to private retention and charged assessment for human review.")
    publish_parser.add_argument("--expected-checker-coordinate",help="Optional expected host deployment SHA-256 digest from account inspection.")
    account_parser = subparsers.add_parser("account",help="Inspect authenticated Claim Garden linkage, byte quota and host coordinates.")
    account_parser.add_argument("--publisher-id",required=True,help="Registered publisher:sha256 identity.")
    account_parser.add_argument("--credential-file",required=True,help="Publisher bearer credential file.")
    account_parser.add_argument("--endpoint",default="https://claimgarden.com",help="Target Claim Garden HTTPS origin.")
    account_parser.add_argument("--json",action="store_true",help="Emit account JSON.")


def handle_gated_publish_command(args: Any) -> int:
    """Handle account or explicitly gated publication with bounded result states."""
    try:
        if args.command == "account":
            result = get_publish_account(args.publisher_id,args.credential_file,endpoint=args.endpoint)
        else:
            if args.claim or args.expected_head or args.genesis:
                raise GatedPublishError("legacy claim or silo options do not apply to gated publication")
            if not all((args.artifact,args.request,args.certificate,args.policy)):
                raise GatedPublishError("gated publication requires artifact, request, certificate and policy files")
            selected = dict(artifact_path=args.artifact,request_path=args.request,certificate_path=args.certificate,
                            gate_receipt_path=args.receipt,policy_path=args.policy,manifest_path=args.manifest)
            if args.dry_run:
                payload = prepare_gated_publication(**selected)
                if args.output:
                    with Path(args.output).open("xb") as stream:
                        stream.write(canonical_bytes(payload)+b"\n")
                result = publication_summary(payload)
            else:
                if args.output:
                    raise GatedPublishError("--output requires --dry-run")
                if not args.publisher_id or not args.credential_file:
                    raise GatedPublishError("submission requires a publisher identity and credential file")
                result = publish_gated(**selected,publisher_id=args.publisher_id,credential_file=args.credential_file,
                                       endpoint=args.endpoint,private_review_consent=args.private_review_consent,
                                       expected_checker_coordinate=args.expected_checker_coordinate)
    except (ClaimGardenClientError,OSError,ValueError) as error:
        attempted = getattr(error,"submission_attempted",False)
        details = getattr(error,"details",{})
        outcome = details.get("outcome","UNKNOWN" if attempted else "REJECTED")
        result = {"result":"NOT_ESTABLISHED" if attempted else "REJECTED","outcome":outcome,
                  "transport_performed":getattr(error,"transport_performed",attempted),"publication":"NOT_ESTABLISHED",**details,
                  "error":str(error) if isinstance(error,ClaimGardenClientError) else "local preparation or output failed"}
        print(json.dumps(result,sort_keys=True) if args.json else "["+outcome+"] "+result["error"])
        return 2 if outcome == "UNKNOWN" else 1
    print(json.dumps(result,sort_keys=True) if args.json else json.dumps(result,indent=2,sort_keys=True))
    return 0

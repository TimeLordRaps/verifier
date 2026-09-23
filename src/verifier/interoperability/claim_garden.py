"""Experimental Claim Garden transport adapter for inert verifier silo records.

Terminology: command-line interface (CLI);
Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object
Notation (JSON); uniform resource locator (URL); Verifier Standard (VSTD).
Submission ends at pending human review. It does not authorize moderation or
establish publication.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from ..core.receipt import canonical_json_dumps
from .network import (
    MAX_PRIVATE_KEY_BYTES, ContentAddressedStore,
    NetworkError, PublisherRecord, SignedHead, SiloCommit, _base64url_encode,
    _crypto, _read_bounded_regular, canonical_bytes, digest_bytes, rebuild_silo,
)

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CREDENTIAL_BYTES = 512
_TOKEN = re.compile(r"[A-Za-z0-9_-]{40,512}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TRANSACTION = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


class ClaimGardenClientError(NetworkError):
    """A bounded Claim Garden request or response failed closed."""


@dataclass(frozen=True)
class TransportRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


Transport = Callable[[TransportRequest], TransportResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def _base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ClaimGardenClientError("Claim Garden base URL must be a credential-free HTTPS origin")
    return urllib.parse.urlunsplit(("https", parsed.netloc, "", "", ""))


def _default_transport(request: TransportRequest) -> TransportResponse:
    client = urllib.request.build_opener(_NoRedirect())
    native = urllib.request.Request(request.url, data=request.body, method=request.method, headers=dict(request.headers))
    try:
        response = client.open(native, timeout=10)
        with response:
            final_url = response.geturl()
            if final_url != request.url:
                raise ClaimGardenClientError("authenticated request changed URL")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                raise ClaimGardenClientError("Claim Garden response exceeds its declared bound")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES or (length is not None and len(body) != int(length)):
                raise ClaimGardenClientError("Claim Garden response exceeds its byte bound or is truncated")
            return TransportResponse(response.status, dict(response.headers), body)
    except ClaimGardenClientError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise ClaimGardenClientError("Claim Garden request failed without a retry") from exc


def _json_response(response: TransportResponse, expected_status: int) -> Mapping[str, Any]:
    content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ClaimGardenClientError("Claim Garden response is not JSON")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise ClaimGardenClientError("Claim Garden response exceeds its byte bound")
    try:
        value = json.loads(response.body, object_pairs_hook=lambda pairs: _unique(pairs))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ClaimGardenClientError("Claim Garden response is malformed") from exc
    if not isinstance(value, Mapping) or canonical_bytes(value) != response.body:
        raise ClaimGardenClientError("Claim Garden response is not canonical JSON")
    if response.status != expected_status:
        code = value.get("error")
        raise ClaimGardenClientError(f"Claim Garden refused request: {code if isinstance(code, str) else response.status}")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClaimGardenClientError("Claim Garden response contains a duplicate JSON key")
        result[key] = value
    return result


def _request(transport: Transport, method: str, url: str, body: Mapping[str, Any] | bytes,
             *, token: str | None = None, headers: Mapping[str, str] | None = None) -> TransportResponse:
    payload = canonical_bytes(body) if isinstance(body, Mapping) else body
    request_headers = {"Accept": "application/json", "Content-Type": "application/json", **(headers or {})}
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    return transport(TransportRequest(method, url, request_headers, payload))


def _records(root: Path) -> tuple[Mapping[str, Any], PublisherRecord, SiloCommit, SignedHead, ContentAddressedStore]:
    with tempfile.TemporaryDirectory() as temporary:
        manifest = rebuild_silo(root, Path(temporary) / "validated")
    store = ContentAddressedStore(root)
    publisher = PublisherRecord.from_dict(store.read_record("publishers", manifest["publisher_digest"]))
    commit = SiloCommit.from_dict(store.read_record("commits", manifest["commit_digest"]))
    head = SignedHead.from_dict(store.read_record("heads", manifest["head_digest"]))
    return manifest, publisher, commit, head, store


def _private_key(path: str | Path) -> Any:
    _, serialization, (PrivateKey, _) = _crypto()
    key = serialization.load_pem_private_key(_read_bounded_regular(path, MAX_PRIVATE_KEY_BYTES, "publisher private key"), password=None)
    if not isinstance(key, PrivateKey):
        raise ClaimGardenClientError("publisher private key must use Ed25519")
    return key


def register_publisher(export_root: str | Path, base_url: str, private_key: str | Path,
                       issued_at: str, credential_output: str | Path,
                       *, endpoints: tuple[str, ...] = (), transport: Transport = _default_transport) -> Mapping[str, Any]:
    _, publisher, _, _, _ = _records(Path(export_root))
    if publisher.key_continuity_digests:
        raise ClaimGardenClientError("initial registration does not accept an existing key-continuity history")
    key = _private_key(private_key)
    _, serialization, _ = _crypto()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if "publisher:" + digest_bytes(raw) != publisher.publisher_id:
        raise ClaimGardenClientError("registration private key does not match the publisher")
    payload = {"schema_version": "CLAIM-GARDEN-REGISTRATION-0.1", "publisher": publisher.to_dict(),
               "endpoints": list(endpoints), "issued_at": issued_at}
    envelope = {**payload, "signature_base64url": _base64url_encode(key.sign(canonical_bytes(payload)))}
    target = Path(credential_output)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise ClaimGardenClientError("credential destination must be absent and writable") from exc
    try:
        response = _json_response(_request(transport, "POST", _base_url(base_url) + "/v1/publishers/register", envelope), 201)
        if set(response) != {"publisher_id", "access_token"} or response["publisher_id"] != publisher.publisher_id or not isinstance(response["access_token"], str) or not _TOKEN.fullmatch(response["access_token"]):
            raise ClaimGardenClientError("Claim Garden registration response is invalid")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(response["access_token"].encode("ascii"))
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        target.unlink(missing_ok=True)
        raise
    return {"result": "REGISTERED", "publisher_id": publisher.publisher_id, "credential_path": str(target),
            "transport_performed": True, "publication": "NOT_ESTABLISHED"}


def submit_candidate(export_root: str | Path, base_url: str, credential_file: str | Path,
                     *, expected_head_digest: str | None, genesis: bool,
                     transport: Transport = _default_transport) -> Mapping[str, Any]:
    if genesis == (expected_head_digest is not None):
        raise ClaimGardenClientError("select exactly one of genesis or expected head")
    if expected_head_digest is not None and not _DIGEST.fullmatch(expected_head_digest):
        raise ClaimGardenClientError("expected head digest is malformed")
    manifest, publisher, commit, head, store = _records(Path(export_root))
    if head.previous_head_digest != expected_head_digest:
        raise ClaimGardenClientError("selected head does not descend from the declared expected head")
    token_bytes = _read_bounded_regular(credential_file, MAX_CREDENTIAL_BYTES, "publisher credential")
    try:
        token = token_bytes.decode("ascii")
    except UnicodeError as exc:
        raise ClaimGardenClientError("publisher credential is malformed") from exc
    if not _TOKEN.fullmatch(token):
        raise ClaimGardenClientError("publisher credential is malformed")
    base = _base_url(base_url)
    opened = _json_response(_request(transport, "POST", base + "/v1/pushes", {
        "schema_version": "CLAIM-GARDEN-OPEN-PUSH-0.1", "publisher_id": publisher.publisher_id,
        "expected_head_digest": expected_head_digest,
    }, token=token), 201)
    transaction_id = opened.get("id")
    if not isinstance(transaction_id, str) or not _TRANSACTION.fullmatch(transaction_id):
        raise ClaimGardenClientError("Claim Garden open-push response is invalid")
    try:
        seen: set[str] = set()
        for entry in commit.census:
            record = entry.object_record
            if record.object_digest in seen:
                continue
            seen.add(record.object_digest)
            response = _request(transport, "PUT", base + "/v1/pushes/" + transaction_id + "/objects/" + record.object_digest,
                                store.read_object(record), token=token,
                                headers={"Content-Type": record.media_type, "X-Publisher-Id": publisher.publisher_id,
                                         "X-Object-Declaration": canonical_bytes(record.to_dict()).decode("utf-8")})
            _json_response(response, 201)
        finalized = _json_response(_request(transport, "POST", base + "/v1/pushes/" + transaction_id + "/finalize", {
            "schema_version": "CLAIM-GARDEN-FINALIZE-0.1", "publisher_id": publisher.publisher_id,
            "commit": commit.to_dict(), "head": head.to_dict(),
        }, token=token), 202)
        if finalized.get("state") != "PENDING_REVIEW" or finalized.get("commit_digest") != manifest["commit_digest"] or finalized.get("head_digest") != manifest["head_digest"]:
            raise ClaimGardenClientError("Claim Garden finalize response does not bind the submitted candidate")
        return {"result": "SUBMITTED", "state": "PENDING_REVIEW", "transaction_id": transaction_id,
                "publisher_id": publisher.publisher_id, "commit_digest": manifest["commit_digest"],
                "head_digest": manifest["head_digest"], "transport_performed": True,
                "publication": "NOT_ESTABLISHED"}
    except Exception as exc:
        return {"result": "INDETERMINATE", "state": "UNKNOWN", "transaction_id": transaction_id,
                "publisher_id": publisher.publisher_id, "commit_digest": manifest["commit_digest"],
                "head_digest": manifest["head_digest"], "transport_performed": True,
                "publication": "NOT_ESTABLISHED", "reason": type(exc).__name__}


def _read_json_object(path: str | Path) -> Mapping[str, Any]:
    content = _read_bounded_regular(path, MAX_RESPONSE_BYTES, "JSON payload")
    try:
        value = json.loads(content, object_pairs_hook=lambda pairs: _unique(pairs))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ClaimGardenClientError(f"malformed JSON in {path}") from exc
    if not isinstance(value, Mapping):
        raise ClaimGardenClientError(f"JSON in {path} must be an object")
    return value


def _parse_claim_garden_response(response: TransportResponse, expected_status: tuple[int, ...]) -> Mapping[str, Any]:
    content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ClaimGardenClientError("Claim Garden response is not JSON")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise ClaimGardenClientError("Claim Garden response exceeds its byte bound")
    try:
        value = json.loads(response.body, object_pairs_hook=lambda pairs: _unique(pairs))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ClaimGardenClientError("Claim Garden response is malformed") from exc
    if not isinstance(value, Mapping):
        raise ClaimGardenClientError("Claim Garden response must be a JSON object")
    if response.status not in expected_status:
        code = value.get("error") or value.get("message")
        raise ClaimGardenClientError(f"Claim Garden refused request: {code if code else response.status}")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_dumps(value).encode("utf-8")


def publish_claim(
    receipt: str | Path | Mapping[str, Any],
    *,
    claim: str | Path | Mapping[str, Any] | None = None,
    endpoint: str = "https://claimgarden.com",
    publisher_id: str | None = None,
    credential_file: str | Path | None = None,
    expected_head: str | None = None,
    genesis: bool = False,
    transport: Transport = _default_transport,
) -> Mapping[str, Any]:
    """Submit a locally preflighted claim for authenticated storage and human review.

    Evaluates local preflight checks before any network activity:
    1. Verdict verification: must be VERIFIED.
    2. Statement count verification: statements checked must be greater than 0.
    3. Digest verification: recomputed canonical claim digest must match receipt's claim_digest.
    4. Receipt digest integrity: recomputed canonical digest must match if present.

    Publisher identity and credentials are required and never inferred from a notary.
    Storage response binding is checked, but server signatures are not authenticated
    here and successful transport never establishes correctness or publication.
    """
    claim_dict: Mapping[str, Any] | None = None
    receipt_dict: Mapping[str, Any] | None = None

    if isinstance(receipt, (str, Path)):
        receipt_path = Path(receipt)
        if receipt_path.is_dir():
            if (receipt_path / "packet.json").is_file():
                packet_data = _read_json_object(receipt_path / "packet.json")
                if isinstance(packet_data.get("claim"), Mapping) and isinstance(packet_data.get("receipt"), Mapping):
                    claim_dict = packet_data["claim"]
                    receipt_dict = packet_data["receipt"]
            elif (receipt_path / "receipt.json").is_file():
                receipt_dict = _read_json_object(receipt_path / "receipt.json")
                if (receipt_path / "claim.json").is_file() and claim is None:
                    claim_dict = _read_json_object(receipt_path / "claim.json")
            else:
                raise ClaimGardenClientError(f"no readable receipt found in directory: {receipt}")
        elif receipt_path.is_file():
            loaded = _read_json_object(receipt_path)
            if isinstance(loaded.get("claim"), Mapping) and isinstance(loaded.get("receipt"), Mapping):
                claim_dict = loaded["claim"]
                receipt_dict = loaded["receipt"]
            else:
                receipt_dict = loaded
        else:
            raise ClaimGardenClientError(f"receipt path does not exist: {receipt}")
    elif isinstance(receipt, Mapping):
        if "claim" in receipt and "receipt" in receipt and isinstance(receipt["claim"], Mapping) and isinstance(receipt["receipt"], Mapping):
            claim_dict = receipt["claim"]
            receipt_dict = receipt["receipt"]
        else:
            receipt_dict = receipt
    else:
        raise ClaimGardenClientError("receipt must be an existing path or dictionary")

    if claim is not None:
        if isinstance(claim, (str, Path)):
            claim_dict = _read_json_object(claim)
        elif isinstance(claim, Mapping):
            claim_dict = claim
        else:
            raise ClaimGardenClientError("claim must be an existing path or dictionary")

    if claim_dict is None and receipt_dict is not None and isinstance(receipt_dict.get("claim"), Mapping):
        claim_dict = receipt_dict["claim"]

    if claim_dict is None:
        raise ClaimGardenClientError("claim must be provided or bundled with receipt")
    if receipt_dict is None:
        raise ClaimGardenClientError("receipt must be provided")

    # --- Preflight check 1: Verdict verification ---
    verdict = (
        receipt_dict.get("verdict")
        or receipt_dict.get("independent_audit", {}).get("overall_verdict")
        or receipt_dict.get("status")
    )
    if verdict != "VERIFIED":
        raise ClaimGardenClientError(
            f"cannot publish unverified claim; verdict is {verdict!r}, only VERIFIED claims may be published"
        )

    # --- Preflight check 2: Statement count verification (> 0) ---
    statements_checked: int | None = None
    if isinstance(receipt_dict.get("execution_metrics"), Mapping):
        val = receipt_dict["execution_metrics"].get("statements_checked")
        if type(val) is int:
            statements_checked = val
    if statements_checked is None and "statements_checked" in receipt_dict:
        val = receipt_dict["statements_checked"]
        if type(val) is int:
            statements_checked = val
    if statements_checked is None and "statement_count" in receipt_dict:
        val = receipt_dict["statement_count"]
        if type(val) is int:
            statements_checked = val

    if statements_checked is not None:
        if statements_checked <= 0:
            raise ClaimGardenClientError(
                f"statement count must be greater than 0, got {statements_checked}"
            )
    else:
        count = 0
        if isinstance(receipt_dict.get("statements"), (list, tuple)):
            count = len(receipt_dict["statements"])
        elif isinstance(receipt_dict.get("evidence", {}).get("atomic_reasons"), (list, tuple)):
            count = len(receipt_dict["evidence"]["atomic_reasons"])
        elif isinstance(receipt_dict.get("evidence", {}).get("clauses"), (list, tuple)):
            count = len(receipt_dict["evidence"]["clauses"])
        if count <= 0:
            raise ClaimGardenClientError("statement count must be greater than 0")

    # --- Preflight check 3: Claim digest verification ---
    expected_claim_digest = hashlib.sha256(_canonical_json_bytes(claim_dict)).hexdigest()
    if not isinstance(receipt_dict.get("claim_digest"), str):
        raise ClaimGardenClientError("receipt claim digest is required")
    if "claim_digest" in receipt_dict:
        declared_digest = str(receipt_dict["claim_digest"])
        normalized_declared = declared_digest[7:] if declared_digest.startswith("sha256:") else declared_digest
        if normalized_declared != expected_claim_digest:
            raise ClaimGardenClientError(
                f"claim digest mismatch: expected sha256:{expected_claim_digest}, got {declared_digest}"
            )

    # --- Preflight check 4: Receipt canonical digest verification (if present) ---
    if "canonical_digest" in receipt_dict:
        declared_receipt_digest = str(receipt_dict["canonical_digest"])
        normalized_declared_receipt = declared_receipt_digest[7:] if declared_receipt_digest.startswith("sha256:") else declared_receipt_digest
        if receipt_dict.get("schema_version") == "VSTD-1" and receipt_dict.get("receipt_kind") == "claim_mechanics":
            stable = {
                "schema_version": receipt_dict.get("schema_version"),
                "receipt_kind": receipt_dict.get("receipt_kind"),
                "receipt_id": receipt_dict.get("receipt_id"),
                "claim": receipt_dict.get("claim"),
                "evidence": receipt_dict.get("evidence"),
                "target_result": receipt_dict.get("target_result"),
                "independent_audit": receipt_dict.get("independent_audit"),
                "provenance_stable": {
                    "target_name": receipt_dict.get("provenance", {}).get("target_name"),
                    "portable_repository_id": receipt_dict.get("provenance", {}).get("portable_repository_id"),
                    "git_commit_sha": receipt_dict.get("provenance", {}).get("git", {}).get("commit_sha"),
                    "git_branch": receipt_dict.get("provenance", {}).get("git", {}).get("branch"),
                    "git_is_dirty": receipt_dict.get("provenance", {}).get("git", {}).get("is_dirty"),
                    "git_dirty_files": list(receipt_dict.get("provenance", {}).get("git", {}).get("dirty_files", [])),
                    "source_file_hashes": dict(receipt_dict.get("provenance", {}).get("source_file_hashes", {})),
                    "runtime_python_version": receipt_dict.get("provenance", {}).get("runtime", {}).get("python_version"),
                },
                "reproducibility": receipt_dict.get("reproducibility"),
            }
            computed_receipt_digest = hashlib.sha256(_canonical_json_bytes(stable)).hexdigest()
            if normalized_declared_receipt != computed_receipt_digest:
                raise ClaimGardenClientError(
                    f"receipt canonical digest mismatch: expected sha256:{computed_receipt_digest}, got {declared_receipt_digest}"
                )

    # --- Preflight check 5: Notary binding verification (if present) ---
    if "notary_binding" in receipt_dict:
        nb = receipt_dict["notary_binding"]
        if not isinstance(nb, Mapping) or not nb.get("signature") or not nb.get("notary_key_id"):
            raise ClaimGardenClientError("preflight check failed: unsigned receipt missing notary binding")

    # --- Packaging phase ---
    if not isinstance(publisher_id, str) or re.fullmatch(r"publisher:sha256:[0-9a-f]{64}", publisher_id) is None:
        raise ClaimGardenClientError("publisher identity is required and must be a publisher:sha256 coordinate")
    if credential_file is None:
        raise ClaimGardenClientError("publisher credential file is required")
    if expected_head is not None or genesis:
        raise ClaimGardenClientError("claim storage does not support silo lineage options")
    packet = {
        "publisher_id": publisher_id,
        "claim": claim_dict,
        "receipt": receipt_dict,
    }

    # --- Transmission phase ---
    base = _base_url(endpoint)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        token_bytes = _read_bounded_regular(credential_file, MAX_CREDENTIAL_BYTES, "publisher credential")
        token = token_bytes.decode("ascii").strip()
    except (NetworkError, UnicodeError) as exc:
        raise ClaimGardenClientError("publisher credential is unreadable or malformed") from exc
    if not _TOKEN.fullmatch(token):
        raise ClaimGardenClientError("publisher credential is malformed")
    headers["Authorization"] = f"Bearer {token}"

    req = TransportRequest("POST", base + "/v1/claims/publish", headers, _canonical_json_bytes(packet))
    resp = transport(req)
    parsed = _parse_claim_garden_response(resp, (200, 201))
    claim_digest = "sha256:" + expected_claim_digest
    retained = parsed.get("receipt")
    retrieval_path = (f"/v1/claims/records/{claim_digest}?publisher_id="
                      + urllib.parse.quote(publisher_id, safe=""))
    if (parsed.get("schema_version") != "CLAIM-GARDEN-STORED-1.0"
            or parsed.get("status") != "STORED"
            or parsed.get("state") != "PENDING_REVIEW"
            or parsed.get("publication_gate") != "HUMAN_REVIEW_REQUIRED"
            or parsed.get("claim_id") != claim_dict.get("claim_id")
            or not isinstance(parsed.get("claim_id"), str) or not parsed["claim_id"]
            or parsed.get("claim_digest") != claim_digest
            or parsed.get("retrieval_path") != retrieval_path
            or type(parsed.get("deduplicated")) is not bool
            or parsed["deduplicated"] != (resp.status == 200)
            or not isinstance(parsed.get("receipt_id"), str) or not parsed["receipt_id"]
            or not isinstance(retained, Mapping)
            or retained.get("receipt_id") != parsed["receipt_id"]
            or retained.get("claim_id") != parsed["claim_id"]
            or retained.get("claim_digest") != claim_digest
            or retained.get("verdict") != "VERIFIED"):
        raise ClaimGardenClientError("Claim Garden storage response does not bind the submitted claim and review state")
    metrics = retained.get("execution_metrics")
    if (not isinstance(metrics, Mapping) or type(metrics.get("statements_checked")) is not int
            or metrics["statements_checked"] < 1):
        raise ClaimGardenClientError("Claim Garden storage receipt has no positive checked-statement count")

    return {
        "result": "SUBMITTED",
        "status": parsed["status"],
        "publisher_id": publisher_id,
        "claim_id": parsed["claim_id"],
        "receipt_id": parsed["receipt_id"],
        "claim_digest": parsed["claim_digest"],
        "state": parsed["state"],
        "publication_gate": parsed["publication_gate"],
        "deduplicated": parsed["deduplicated"],
        "retrieval_path": parsed["retrieval_path"],
        "transport_performed": True,
        "publication": "NOT_ESTABLISHED",
    }


__all__ = [
    "ClaimGardenClientError",
    "TransportRequest",
    "TransportResponse",
    "publish_claim",
    "register_publisher",
    "submit_candidate",
]

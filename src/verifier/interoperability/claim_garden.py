"""Experimental Claim Garden transport adapter for inert verifier silo records.

Terminology: Hypertext Transfer Protocol Secure (HTTPS); JavaScript Object
Notation (JSON); uniform resource locator (URL); Verifier Standard (VSTD).
Submission ends at pending human review. It does not authorize moderation or
establish publication.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

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


__all__ = ["ClaimGardenClientError", "TransportRequest", "TransportResponse", "register_publisher", "submit_candidate"]

"""Submit a bare SIM (simulation) artifact to ClaimGarden's current quarantine route.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Hypertext Transfer Protocol Secure (HTTPS).

Local replay binds only the retained native certificate and model core. The host
performs its own admission and human review; this client never reports hosting.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from verifier.core.certificate import canonical_bytes
from verifier.domains.certification import recheck_domain_certificate

from .claim_garden import (
    ClaimGardenClientError, MAX_CREDENTIAL_BYTES, Transport, TransportRequest,
    _TOKEN, _base_url, _default_transport, _parse_claim_garden_response,
)
from .network import _read_bounded_regular


MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PUBLISHER = re.compile(r"publisher:sha256:[0-9a-f]{64}\Z")
_FIELDS = {"kind", "title", "description", "rights", "certification", "model"}
_OPTIONAL = {"presets"}
_RESPONSE_FIELDS = {
    "schema_version", "source_digest", "kind", "title", "state", "revision",
    "reason_code", "queue_position", "assessment_state", "runnable_digest",
    "assessment", "review_digest", "publication", "rights", "created_at", "updated_at",
}


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClaimGardenClientError("duplicate artifact field")
        result[key] = value
    return result


def read_sim_artifact(path: str | Path) -> tuple[bytes, dict[str, Any]]:
    """Keep the upload's exact bytes: ClaimGarden hashes the raw request body."""
    try:
        raw = _read_bounded_regular(path, MAX_ARTIFACT_BYTES, "SIM artifact")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, ValueError, OSError, RecursionError) as exc:
        raise ClaimGardenClientError("SIM artifact unreadable or malformed") from exc
    if (type(value) is not dict or set(value) - _OPTIONAL != _FIELDS
            or value.get("kind") != "SIM"):
        raise ClaimGardenClientError("bare SIM artifact shape required")
    return raw, value


def read_intent_object(path: str | Path) -> dict[str, Any]:
    """Read an independently selected native request or policy as strict JSON."""
    try:
        raw = _read_bounded_regular(path, MAX_ARTIFACT_BYTES, "SIM publication intent")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if type(value) is not dict:
            raise ValueError("object required")
        canonical_bytes(value)
        return value
    except (UnicodeError, ValueError, TypeError, OSError, RecursionError) as exc:
        raise ClaimGardenClientError("SIM request or policy unreadable or malformed") from exc


def publish_sim_artifact(
    artifact_file: str | Path, *, expected_source_digest: str,
    expected_request: dict[str, Any], policy: dict[str, Any],
    publisher_id: str, credential_file: str | Path,
    endpoint: str = "https://claimgarden.com", transport: Transport = _default_transport,
) -> Mapping[str, Any]:
    """Recheck local evidence, then submit exact bytes for host review.

    A successful response proves only quarantine at the returned source digest.
    """
    raw, artifact = read_sim_artifact(artifact_file)
    source = "sha256:" + hashlib.sha256(raw).hexdigest()
    if type(expected_source_digest) is not str or not _HASH.fullmatch(expected_source_digest) or source != expected_source_digest:
        raise ClaimGardenClientError("SIM source differs from caller intent")
    envelope = artifact["certification"]
    if type(envelope) is not dict or set(envelope) != {"request", "certificate"}:
        raise ClaimGardenClientError("SIM certification envelope is malformed")
    if canonical_bytes(envelope["request"]) != canonical_bytes(expected_request):
        raise ClaimGardenClientError("SIM request differs from caller intent")
    checked = recheck_domain_certificate(envelope["certificate"],
        expected_request=expected_request, policy=policy)
    if checked.get("status") != "PASS":
        raise ClaimGardenClientError("SIM native certificate did not PASS: " + str(checked.get("status")))
    try:
        model = artifact["model"]
        evidence = envelope["certificate"]["evidence"]
        certified = evidence["artifact"]
        if (type(model) is not dict or canonical_bytes(model["transition"]) != canonical_bytes(certified["transition"])
                or canonical_bytes(model["initial_state"]) != canonical_bytes(certified["initial_state"])):
            raise ClaimGardenClientError("SIM model differs from certified transition or initial state")
    except (KeyError, TypeError, ValueError) as exc:
        raise ClaimGardenClientError("SIM model/certificate binding is malformed") from exc
    if type(publisher_id) is not str or not _PUBLISHER.fullmatch(publisher_id):
        raise ClaimGardenClientError("SIM publisher coordinate required")
    base = _base_url(endpoint)
    try:
        token = _read_bounded_regular(credential_file, MAX_CREDENTIAL_BYTES, "publisher credential").decode("ascii").strip()
    except (UnicodeError, ValueError, OSError) as exc:
        raise ClaimGardenClientError("publisher credential unreadable") from exc
    if not _TOKEN.fullmatch(token):
        raise ClaimGardenClientError("publisher credential malformed")
    try:
        response = transport(TransportRequest(
            "POST", base + "/v1/artifacts?publisher_id=" + quote(publisher_id, safe=":"),
            {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer " + token}, raw,
        ))
        parsed = _parse_claim_garden_response(response, (200, 201))
        if (set(parsed) != _RESPONSE_FIELDS or parsed.get("schema_version") != "CLAIM-GARDEN-ARTIFACT-SUBMISSION-1"
                or parsed.get("source_digest") != source or parsed.get("kind") != "SIM"
                or parsed.get("title") != artifact["title"]
                or parsed.get("publication") != "PUBLICATION_REQUIRES_HUMAN_REVIEW"
                or parsed.get("rights") != "MODERATOR_ATTESTED_NOT_VERIFIED"
                or parsed.get("state") not in {"SUBMITTED", "ASSESSMENT_PENDING", "PENDING_REVIEW", "REJECTED_AUTOMATIC"}
                or type(parsed.get("revision")) is not int or parsed["revision"] < 0
                or parsed.get("assessment_state") not in {"CURRENT", "RECHECK_PENDING"}
                or (parsed.get("assessment") is None and parsed.get("assessment_state") != "RECHECK_PENDING")
                or (parsed.get("state") == "PENDING_REVIEW" and
                    (type(parsed.get("queue_position")) is not int or parsed["queue_position"] < 1))
                or (parsed.get("state") != "PENDING_REVIEW" and parsed.get("queue_position") is not None)
                or (parsed.get("reason_code") is not None and type(parsed["reason_code"]) is not str)
                or (parsed.get("runnable_digest") is not None and
                    (type(parsed["runnable_digest"]) is not str or not _HASH.fullmatch(parsed["runnable_digest"])))
                or (parsed.get("review_digest") is not None and
                    (type(parsed["review_digest"]) is not str or not _HASH.fullmatch(parsed["review_digest"])))
                or type(parsed.get("created_at")) is not str or type(parsed.get("updated_at")) is not str):
            raise ClaimGardenClientError("artifact response does not bind quarantined SIM source")
    except Exception as exc:
        # Once transport was called, storage may have succeeded despite a lost or
        # forged response. Never translate that uncertainty into a refusal claim.
        return {"result": "INDETERMINATE", "state": "UNKNOWN", "source_digest": source,
                "transport_performed": True, "publication": "NOT_ESTABLISHED",
                "reason": type(exc).__name__}
    return {"result": "REJECTED_AUTOMATIC" if parsed["state"] == "REJECTED_AUTOMATIC" else "SUBMITTED",
            "state": parsed["state"], "source_digest": source, "transport_performed": True,
            "publication": "NOT_ESTABLISHED", "host_response": parsed}

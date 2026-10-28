"""Separate bounded consent predicates and their retained reproduction.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256); Coordinated
Universal Time (UTC). Times are integer UTC Unix seconds. Other bounds are
dimensionless. These primitives do not register namespace objectives, establish
all required holders, authenticate clocks, or establish voluntary human consent.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
from typing import Any, Callable

from verifier.consent import engine as native
from verifier.consent import public
from verifier.consent.engine import ConsentContext

RECEIPT_VERSION = "verifier-consent-stages-1"
_STAGES = ("7.1", "7.2", "7.3", "7.4", "7.6")
_VERDICTS = ("PASS", "FAIL", "UNKNOWN", "REJECTED", "CONFLICTED")
_RECEIPT_FIELDS = {"schema_version", "mechanism_digest", "selection", "stages",
    "admission_status", "enforcement", "receipt_digest"}
_SELECTION_FIELDS = {"context", "policy_digest", "evidence_digest", "evaluation_time", "computational_verdict"}


def mechanism_digest() -> str:
    """Bind the stage rules and the complete existing public admission mechanism."""
    specification = Path(__file__).parents[1] / "standard" / "CONSENT_STAGES.md"
    return native._digest({"stages.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "public_mechanism": public.mechanism_digest(),
        "CONSENT_STAGES.md": hashlib.sha256(specification.read_bytes()).hexdigest()})


def _result(check: Callable[[], None], positive: str) -> dict[str, str]:
    try:
        check()
        return {"status": "PASS", "reason": positive}
    except native._Unknown as exc:
        return {"status": "UNKNOWN", "reason": str(exc)}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        return {"status": "FAIL", "reason": str(exc)}


def _require(value: bool, reason: str) -> None:
    if not value:
        raise native._Rejected(reason)


def _grant(envelope: dict[str, Any]) -> dict[str, Any]:
    native._fields(envelope, public._ENVELOPE_FIELDS)
    grant = native._fields(envelope["payload"], native._GRANT_FIELDS)
    _require(grant["schema_version"] == "verifier-consent-public-grant-1", "unsupported grant version")
    for name in ("grant_id", "issuer_id", "actor_id", "object_name"):
        native._text(grant[name])
    public._hex(grant["artifact_digest"], 32)
    for name in ("operations", "observer_ids", "purposes"):
        native._names(grant[name])
    start, end = native._time(grant["not_before"]), native._time(grant["not_after"])
    _require(start < end, "invalid grant interval")
    _require(grant["effect"] in ("ALLOW", "DENY") and type(grant["allow_delegation"]) is bool,
        "invalid effect or delegation flag")
    if grant["parent_digest"] is not None:
        public._hex(grant["parent_digest"], 32)
    return grant


def _authenticate(envelope: dict[str, Any], authority: public._Policy) -> None:
    """Reject a decidable actor/key contradiction before optional verification."""
    native._fields(envelope, public._ENVELOPE_FIELDS)
    key_id = native._text(envelope["key_id"])
    _require(type(envelope["payload"]) is dict, "authentication payload must be an object")
    key = next((row for row in authority.keys if row.key_id == key_id), None)
    if key is not None:
        _require(envelope["payload"].get("issuer_id") == key.actor_id,
            "statement issuer differs from configured key actor")
    public._authenticate(envelope, authority)


def _capture(context: ConsentContext, grants: tuple[dict[str, Any], ...], policy: dict[str, Any] | None,
             revocation: dict[str, Any] | None, evaluation_time: int | None,
             computational_verdict: str) -> tuple[ConsentContext, public._Policy | None, dict[str, Any] | None,
                                                  tuple[dict[str, Any], ...], dict[str, Any] | None, int | None]:
    _require(type(computational_verdict) is str and computational_verdict in _VERDICTS,
        "unsupported computational verdict")
    context = native._capture_context(context)
    public._hex(context.artifact_digest, 32)
    now = None if evaluation_time is None else native._time(evaluation_time)
    captured_policy, descriptor = public._capture_policy(policy)
    _require(type(grants) is tuple and len(grants) <= 16, "bounded plain grant tuple required")
    evidence = native._capture_plain({"grants": grants, "revocation": revocation})
    # Apply the encoded-byte bound before cryptographic work as well as node bounds.
    native._bytes(evidence)
    return context, captured_policy, descriptor, evidence["grants"], evidence["revocation"], now


def _selection(context: ConsentContext, descriptor: dict[str, Any] | None,
               grants: tuple[dict[str, Any], ...], revocation: dict[str, Any] | None,
               now: int | None, computational_verdict: str) -> dict[str, Any]:
    return {"context": asdict(context), "policy_digest": native._digest(descriptor) if descriptor is not None else None,
        "evidence_digest": native._digest({"grants": grants, "revocation": revocation}),
        "evaluation_time": now, "computational_verdict": computational_verdict}


def _combine(stages: dict[str, dict[str, str]]) -> str:
    statuses = [row["status"] for row in stages.values()]
    return "FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"


def evaluate_consent_stages(context: ConsentContext, grants: tuple[dict[str, Any], ...], *,
                            policy: dict[str, Any] | None, revocation: dict[str, Any] | None,
                            evaluation_time: int | None = None,
                            computational_verdict: str = "UNKNOWN") -> dict[str, Any]:
    """Evaluate five distinct predicates; objective 7.5 is the separate rechecker.

    Authority means the externally configured holder/key/artifact relation only.
    Delegation depends on authority and validity, including ancestor revocation.
    This evaluates one holder, never the completeness of a required-holder set.
    """
    selection = None
    try:
        context, authority, descriptor, grants, revocation, now = _capture(
            context, grants, policy, revocation, evaluation_time, computational_verdict)
        selection = _selection(context, descriptor, grants, revocation, now, computational_verdict)

        def need_authority() -> public._Policy:
            if authority is None:
                raise native._Unknown("configured holder policy is unavailable")
            return authority

        def grant_bodies() -> list[dict[str, Any]]:
            if not grants:
                raise native._Unknown("grant chain is unavailable")
            return [_grant(envelope) for envelope in grants]

        def authenticate_all(*, include_status: bool = False, revoked: set[str] | None = None) -> None:
            selected = need_authority()
            unavailable = None
            for envelope in (*grants, *((revocation,) if include_status and revocation is not None else ())):
                try:
                    _authenticate(envelope, selected)
                except native._Unknown as exc:
                    unavailable = exc
                else:
                    if revoked is not None:
                        _require(envelope["payload"].get("grant_id") not in revoked, "grant or ancestor was revoked")
            if unavailable is not None:
                raise unavailable

        def scope() -> None:
            leaf = grant_bodies()[-1]
            _require((leaf["object_name"], leaf["artifact_digest"]) == (context.object_name, context.artifact_digest),
                "terminal grant artifact differs from selected action")
            _require(leaf["actor_id"] == context.actor_id and context.operation in leaf["operations"]
                and context.observer_id in leaf["observer_ids"] and context.purpose in leaf["purposes"],
                "selected action exceeds terminal grant scope")
            _require(leaf["effect"] == "ALLOW", "terminal grant denies the selected action")
            _authenticate(grants[-1], need_authority())

        def holder() -> None:
            selected = need_authority()
            if grants:
                root = grant_bodies()[0]
                _require(grants[0]["key_id"] in selected.root_key_ids and root["issuer_id"] == selected.grantor_id
                    and root["parent_digest"] is None, "grant chain lacks configured root authority")
                _require((root["object_name"], root["artifact_digest"]) == (context.object_name, context.artifact_digest),
                    "root grant artifact differs from selected authority")
            if selected.artifact_bindings:
                _require((context.object_name, context.artifact_digest) in selected.artifact_bindings,
                    "selected artifact is outside configured holder authority")
            authenticate_all(include_status=True)
            grant_bodies()
            if not selected.artifact_bindings:
                raise native._Unknown("configured artifact authority is unavailable")

        def validity() -> None:
            bodies = grant_bodies()
            if now is not None:
                _require(context.timestamp == now, "action time differs from selected trusted time")
                for grant in bodies:
                    _require(grant["not_before"] <= now < grant["not_after"], "grant is inactive or expired")
            selected = need_authority()
            if revocation is None:
                raise native._Unknown("revocation evidence is unavailable")
            native._fields(revocation, public._ENVELOPE_FIELDS)
            state = native._fields(revocation["payload"], {"schema_version", "issuer_id", "policy_id",
                "as_of", "next_update", "revoked_grant_ids"})
            _require(state["schema_version"] == "verifier-consent-public-revocations-1"
                and state["policy_id"] == selected.policy_id, "revocation policy binding differs")
            _require(revocation["key_id"] in selected.revocation_key_ids, "revocation key lacks configured status role")
            start, end = native._time(state["as_of"]), native._time(state["next_update"])
            _require(start < end, "invalid revocation interval")
            revoked = native._names(state["revoked_grant_ids"], empty=True)
            _authenticate(revocation, selected)
            if now is not None and start > now:
                raise native._Unknown("revocation snapshot is from the future")
            authenticate_all(revoked=revoked)
            if now is None:
                raise native._Unknown("selected trusted time is unavailable")
            if now >= end or now - start > selected.max_revocation_age_seconds or start < selected.minimum_revocation_as_of:
                raise native._Unknown("revocation freshness is not established")

        rows = {"7.1": _result(scope, "authenticated terminal scope matches selected action"),
            "7.2": _result(holder, "configured root and statement signatures match selected authority"),
            "7.3": _result(validity, "authenticated validity and revocation cover selected time")}

        def delegation() -> None:
            bodies = grant_bodies(); selected = need_authority()
            _require(len(grants) <= selected.max_chain_length, "delegation exceeds selected chain limit")
            _require(len({row["grant_id"] for row in bodies}) == len(bodies), "duplicate or cyclic grant identifier")
            for index, grant in enumerate(bodies):
                _require((grant["object_name"], grant["artifact_digest"]) == (context.object_name, context.artifact_digest),
                    "delegation changes selected artifact")
                _require(grant["effect"] == "ALLOW", "submitted delegation contains a denial")
                if index:
                    parent = bodies[index - 1]
                    _require(parent["allow_delegation"] and grant["issuer_id"] == parent["actor_id"],
                        "parent does not authorize this delegate")
                    _require(grant["parent_digest"] == grants[index - 1]["payload_digest"], "parent payload commitment differs")
                    _require(grant["not_before"] >= parent["not_before"] and grant["not_after"] <= parent["not_after"]
                        and all(set(grant[name]) <= set(parent[name]) for name in ("operations", "observer_ids", "purposes")),
                        "delegation widens scope or validity")
            prerequisites = {name: rows[name] for name in ("7.2", "7.3")}
            status = _combine(prerequisites)
            if status == "FAIL":
                raise native._Rejected("delegation authority or validity prerequisite failed")
            if status == "UNKNOWN":
                raise native._Unknown("delegation authority or validity prerequisite is unavailable")

        rows["7.4"] = _result(delegation, "complete delegation preserves authority, scope and validity")

        def independent_verdict() -> None:
            observations = []
            for verdict in _VERDICTS:
                report = public.evaluate_public_consent(context, grants, policy=descriptor,
                    revocation=revocation, evaluation_time=now, computational_verdict=verdict).receipt
                _require(report["computational_verdict"] == verdict, "computational verdict was changed")
                observations.append(native._bytes({key: value for key, value in report.items()
                    if key not in {"computational_verdict", "receipt_digest"}}))
            _require(len(set(observations)) == 1, "consent evaluation depends on computational verdict")

        rows["7.6"] = _result(independent_verdict, "all five computational verdicts preserve identical consent evaluation")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        rows = {name: {"status": "FAIL", "reason": str(exc)} for name in _STAGES}
    receipt = {"schema_version": RECEIPT_VERSION, "mechanism_digest": mechanism_digest(), "selection": selection,
        "stages": rows, "admission_status": _combine(rows), "enforcement": "NOT_ESTABLISHED"}
    receipt["receipt_digest"] = native._digest(receipt)
    return receipt


def recheck_consent_stages(receipt: dict[str, Any], context: ConsentContext,
                           grants: tuple[dict[str, Any], ...], *, policy: dict[str, Any] | None,
                           revocation: dict[str, Any] | None, evaluation_time: int | None = None,
                           computational_verdict: str = "UNKNOWN") -> dict[str, Any]:
    """Objective 7.5: independently selected exact reproduction, not admission.

    Missing authentication capability may make historical replay unavailable.
    Known binding or reproduced-stage contradictions reject before that outcome.
    """
    try:
        carried = native._capture_plain(receipt); native._fields(carried, _RECEIPT_FIELDS)
        _require(carried["schema_version"] == RECEIPT_VERSION and carried["mechanism_digest"] == mechanism_digest()
            and carried["receipt_digest"] == native._digest({k: v for k, v in carried.items() if k != "receipt_digest"})
            and carried["enforcement"] == "NOT_ESTABLISHED", "stage receipt identity or digest differs")
        native._fields(carried["selection"], _SELECTION_FIELDS)
        native._fields(carried["stages"], set(_STAGES))
        for row in carried["stages"].values():
            native._fields(row, {"status", "reason"}); native._text(row["reason"])
            _require(row["status"] in ("PASS", "FAIL", "UNKNOWN"), "unsupported carried stage status")
        _require(carried["admission_status"] == _combine(carried["stages"]), "carried stage admission differs")
        positive = {name for name, row in carried["stages"].items() if row["status"] == "PASS"}
        for name in ("policy_digest", "evidence_digest"):
            value = carried["selection"][name]
            if value is not None:
                public._hex(value, 32)
            else:
                _require(not positive.intersection({"7.1", "7.2", "7.3", "7.4"}),
                    "positive predicate lacks required authority or evidence binding")
        if carried["selection"]["evaluation_time"] is not None:
            native._time(carried["selection"]["evaluation_time"])
        else:
            _require(not positive.intersection({"7.3", "7.4"}), "positive validity predicate lacks selected time")
        _require("7.4" not in positive or {"7.2", "7.3"} <= positive,
            "positive delegation lacks positive authority and validity prerequisites")
        context, _, descriptor, grants, revocation, now = _capture(
            context, grants, policy, revocation, evaluation_time, computational_verdict)
        chosen = _selection(context, descriptor, grants, revocation, now, computational_verdict)
        for key, value in chosen.items():
            if key in ("policy_digest", "evaluation_time") and value is None:
                continue
            _require(native._bytes(carried["selection"][key]) == native._bytes(value), "carried stage selection differs")
        current = evaluate_consent_stages(context, grants, policy=descriptor, revocation=revocation,
            evaluation_time=now, computational_verdict=computational_verdict)
        if native._bytes(carried) == native._bytes(current):
            replay, status = "REPRODUCED", "PASS"
        else:
            missing_policy = descriptor is None and carried["selection"]["policy_digest"] is not None
            missing_time = now is None and carried["selection"]["evaluation_time"] is not None
            unavailable_stages = set()
            for name, row in current["stages"].items():
                if row["status"] != "UNKNOWN":
                    continue
                if (row["reason"] in {"public signature backend unavailable", "public signature algorithm unavailable"}
                        or missing_policy and row["reason"] == "configured holder policy is unavailable"
                        or missing_time and row["reason"] == "selected trusted time is unavailable"):
                    unavailable_stages.add(name)
            if (current["stages"]["7.4"]["reason"] == "delegation authority or validity prerequisite is unavailable"
                    and unavailable_stages.intersection({"7.2", "7.3"})):
                unavailable_stages.add("7.4")
            unavailable = missing_policy or missing_time or bool(unavailable_stages)
            known_difference = any(current["stages"][name] != carried["stages"][name]
                and name not in unavailable_stages for name in _STAGES)
            replay, status = ("UNAVAILABLE", "UNKNOWN") if unavailable and not known_difference else ("REJECTED", "FAIL")
        return {"objective": "7.5", "replay_status": replay, "reproduction_status": status,
            "admission_status": current["admission_status"] if replay != "REJECTED" else "NOT_ESTABLISHED",
            "evaluation": current, "enforcement": "NOT_ESTABLISHED"}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return {"objective": "7.5", "replay_status": "REJECTED", "reproduction_status": "FAIL",
            "admission_status": "NOT_ESTABLISHED", "enforcement": "NOT_ESTABLISHED"}

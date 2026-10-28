"""Proposed current capability-token replay certificates, never authority grants.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Epochs, tenure and invocation bounds are
dimensionless. Window instants and skew use one declared microsecond clock.
Native token mechanics are reused under explicit, narrow mappings of retained
legacy predicates; signatures, physical validation and full qualification are
not established. No central registration is performed by importing this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.namespace import NamespaceObject
from verifier.domains import token as token_module
from verifier.domains import statics as statics_module
from verifier.domains.contracts import retained_selection
from verifier.core import signature_keys as signature_keys_module
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-token-checks-request-1"
POLICY_VERSION = "verifier-current-token-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-token-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-token-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-token-checks.1"
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"tenure": "TOKEN-2.1", "windows": "TOKEN-3.1", "delegation": "TOKEN-4.1"}
_CLAIMS = {
    "tenure": "The selected capability-token holding has exactly one declared birth, contiguous retained epoch folds, irreversible retained revocation, and aging claims equal the refolded heads and active-epoch counts.",
    "windows": "Every selected lifetime lease has a nonempty declared-clock window; every finite window is wider than the selected clock skew; unbounded windows are explicitly reported.",
    "delegation": "Every selected lifetime lease resolves through a finite acyclic parent-grant path to the declared birth; scopes, validity windows, invocation bounds, inherited caveats and soulbound delegates do not widen along that path.",
}
_SOURCE_ROWS = {
    "tenure": ["legacy TOKEN-1.4", "legacy TOKEN-2.1..3", "legacy TOKEN-2.11", "legacy TOKEN-4.2"],
    "windows": ["legacy TOKEN-1.10", "legacy TOKEN-3.8"],
    "delegation": ["legacy TOKEN-2.4", "legacy TOKEN-3.4..5", "legacy TOKEN-3.10", "legacy TOKEN-4.3..4"],
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise TokenChecksError("unsupported capability-token check")
    return value


def scope(check: str) -> str:
    return "finite_retained_token_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "TOKEN", "scope": scope(check),
        "proposition": _CLAIMS[check], "source_rows": list(_SOURCE_ROWS[check]),
        "prerequisites": ["independently selected exact TOKEN record, complete finite typed collection, retained native token inventory and per-predicate inputs, installed policy and finite limits",
                          "inline native inventory replay; exactly one fully shaped declared birth and plain-integer ordered lifetime interval syntax (finite not_after greater than its own not_before) are necessary inventory conditions for each selected check, independent of named-clock comparisons; no certificate prerequisite is inferred from a tier number"],
        "exclusions": ["signatures, issuer authenticity, genesis opening, actual presentation or invocation consumption",
                       "physical clock calibration, status authenticity, financial balances or supply conservation",
                       "global holding completeness, legacy complete closure result, real-world authority or enforcement",
                       "unselected objectives, whole tier and object-profile conformance"]}


def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class TokenDescriptor:
    """One exact locally admitted capability-token arithmetic proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class TokenChecksError(ValueError):
    """Malformed external selection or substituted capability-token certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, TokenChecksError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, TokenChecksError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, token_module, statics_module, retained_selection, signature_keys_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TOKEN_CHECKS.md", "DOMAIN_OBLIGATIONS.md", "ZIZK_TOKENS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})



def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=TokenChecksError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def token_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, TokenChecksError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "TOKEN")):
        if type(request[field]) is not str or request[field] != expected:
            raise TokenChecksError("selected capability-token objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise TokenChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise TokenChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def token_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise TokenChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "TOKEN", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _tenure_without_clock(artifact: dict[str, Any], inputs: dict[str, Any],
                          budget: common_module.Budget, held: dict[str, Any],
                          birth: dict[str, Any]) -> dict[str, Any]:
    """Replay the native dimensionless fold and aging claims without time comparisons."""
    epochs = common_module.seq(common_module.need(inputs, "epochs"), budget)
    common_module.same(common_module.digest(epochs), common_module.need(artifact, "epochs_digest"), "retained epochs differ from their bound digest")
    # The fold is seeded by the birth commitment: A at the birth epoch is the
    # commitment itself, and each later epoch folds its predecessor, its own number
    # and the status recorded at it.
    first = birth["birth_epoch"] + 1
    accumulator = birth["commitment"]
    heads, active = {first - 1: accumulator}, {first - 1: 0}
    suspended, revoked_at = [], None
    for offset, step in enumerate(epochs):
        entry = common_module.obj(step, {"epoch", "status", "digest"})
        epoch, status = common_module.integer(entry["epoch"]), entry["status"]
        if epoch != first + offset:
            raise Refuted(f"the retained epochs are not contiguous from the birth epoch: "
                          f"expected {first + offset}, found {epoch}")
        if status not in token_module.STATUSES:
            raise Refuted(f"an epoch status is not ACTIVE, SUSPENDED or REVOKED: epoch {epoch}")
        # Revocation ends tenure from its epoch forward; suspension only halts accrual.
        if revoked_at is not None and status != "REVOKED":
            raise Refuted(f"tenure resumes after its revocation: epoch {epoch}")
        if status == "REVOKED" and revoked_at is None:
            revoked_at = epoch
        if status == "SUSPENDED":
            suspended.append(epoch)
        accumulator = common_module.digest([accumulator, epoch, status])
        common_module.same(entry["digest"], accumulator,
             f"a retained epoch digest is not the fold of the epoch before it: epoch {epoch}")
        heads[epoch] = accumulator
        active[epoch] = active[epoch - 1] + (1 if status == "ACTIVE" else 0)
    last = first + len(epochs) - 1
    gaps = []
    aging = [record for record in held.values() if record["kind"] == "aging"]
    budget.tick(len(held))
    for token in aging:
        token_id = token["token_id"]
        if token["birth_token_id"] != birth["token_id"]:
            raise Refuted("an aging token names a birth the holding does not descend from: " + token_id)
        start, end = token["epoch_start"], token["epoch_end"]
        if not first <= start <= end:
            raise Refuted("an aging token's interval is empty or does not follow its birth epoch: " + token_id)
        if end > last:
            gaps.append("an aging token spans epochs the retained trace does not reach: " + token_id)
            continue
        common_module.same(token["accumulator_digest"], heads[end],
             "an aging token's accumulator is not the refolded chain at its last epoch: " + token_id)
        if token["accumulated_epochs"] != active[end] - active[start - 1]:
            raise Refuted("an aging token's accrued tenure is not the count of active epochs it spans: " + token_id)
        if (token["revocation_status"] == "REVOKED") != (revoked_at is not None and revoked_at <= end):
            raise Refuted("an aging token misreports its revocation status: " + token_id)
    if gaps:
        raise Unavailable(gaps[0])
    return {"birth_epoch": first - 1, "last_epoch": last, "head": accumulator,
            "active_epochs": active[last], "suspended_epochs": suspended, "revoked_at": revoked_at,
            "aging_tokens": len(aging)}


def _delegation_relations(artifact: dict[str, Any], budget: common_module.Budget,
                          held: dict[str, Any], birth: dict[str, Any], *,
                          partial_inventory: bool = False) -> dict[str, Any]:
    """Replay exact parent paths and known relations before unrelated metadata gaps."""
    leases = token_module._leases_of(held)
    if not leases:
        raise Unavailable("the holding retains no lease, so no delegation can be resolved")
    budget.tick(len(leases))
    gaps = []
    for lease_id, lease in leases.items():
        parent_id = lease["parent_grant_id"]
        if parent_id != birth["token_id"] and parent_id not in leases:
            if parent_id in held:
                raise Refuted("a lease names an aging token as its parent grant: " + lease_id)
            if not partial_inventory:
                raise Refuted("a lease's parent grant resolves to nothing in the inventory: " + lease_id)
            # An unsupported retained record may be this named parent. Do not
            # infer its absence, but still inspect other fully supported paths.
            gaps.append("selected parent has no supported capability-token mapping: " + lease_id)
    depths = {}
    for lease_id in leases:
        seen, current = set(), lease_id
        while current != birth["token_id"]:
            if current not in leases:
                break
            if current in seen:
                raise Refuted("a delegation path returns to a lease it already left: " + lease_id)
            seen.add(current)
            budget.tick()
            current = leases[current]["parent_grant_id"]
        if current == birth["token_id"]:
            depths[lease_id] = len(seen)
    root = (set(token_module._names(artifact["root_scopes"], budget, "the root scope set", nonempty=True))
            if "root_scopes" in artifact else None)
    if root is None:
        gaps.append("required evidence absent: root_scopes")
    compare_instants = "clock" in artifact
    for lease_id, lease in leases.items():
        parent = leases.get(lease["parent_grant_id"])
        if parent is None and lease["parent_grant_id"] != birth["token_id"]:
            continue
        grantor = birth if parent is None else parent
        if compare_instants and lease["issued_at"] < grantor["issued_at"]:
            raise Refuted("a lease was issued before its parent grant: " + lease_id)
        ceiling = root if parent is None else set(parent["permitted_scopes"])
        beyond = sorted(set(lease["permitted_scopes"]) - ceiling) if ceiling is not None else []
        if beyond:
            raise Refuted(f"a lease conveys a scope its parent grant lacks: {lease_id}: {beyond[0]}")
        if parent is None:
            continue
        if compare_instants and (lease["not_before"] < parent["not_before"] or token_module._later(lease["not_after"], parent["not_after"])):
            raise Refuted("a lease window reaches outside its parent grant's window: " + lease_id)
        if parent["max_invocations"] is not None and (
                lease["max_invocations"] is None or lease["max_invocations"] > parent["max_invocations"]):
            raise Refuted("a lease permits more invocations than its parent grant: " + lease_id)
        # A caveat is its condition together with what discharges it. Keeping the
        # condition under a different discharge replaces the parent's caveat, so only
        # removing the discharge -- a permanent restriction -- narrows it.
        own = {caveat["condition"]: caveat["discharge"] for caveat in lease["caveats"]}
        for caveat in parent["caveats"]:
            if caveat["condition"] not in own:
                raise Refuted("a delegation step drops a caveat its parent grant imposed: " + lease_id)
            if own[caveat["condition"]] not in (caveat["discharge"], None):
                raise Refuted("a delegation step rewrites how an inherited caveat is discharged: " + lease_id)
        if parent["soulbound"] and (not lease["soulbound"]
                                    or lease["delegate_key_id"] != parent["delegate_key_id"]):
            raise Refuted("a soulbound lease is re-delegated: " + lease_id)
    if gaps:
        raise Unavailable(gaps[0])
    return {"leases": len(leases), "root_leases": sum(1 for d in depths.values() if d == 1),
            "delegation_depth": max(depths.values()),
            "soulbound": sorted(i for i, lease in leases.items() if lease["soulbound"]),
            "scopes_conveyed": sorted({s for lease in leases.values() for s in lease["permitted_scopes"]})}


def _native(check: str, artifact: dict[str, Any], inputs: dict[str, Any],
            budget: common_module.Budget) -> dict[str, Any]:
    """Replay known scoped contradictions before reporting unrelated inventory gaps."""
    tokens = common_module.seq(common_module.need(inputs, "tokens"), budget)
    common_module.same(common_module.digest(tokens), common_module.need(artifact, "tokens_digest"),
                       "token inventory differs from its bound digest")
    supported, unsupported = [], False
    for token in tokens:
        kind = common_module.obj(token).get("kind")
        if type(kind) is str and kind not in token_module.KIND_FIELDS:
            unsupported = True
        else:
            supported.append(token)
    # This exact deterministic projection can expose local refutations. It can
    # never establish inventory completeness or PASS while a record is unsupported.
    projected_artifact = (dict(artifact, tokens_digest=common_module.digest(supported))
                          if unsupported else artifact)
    held, birth, gaps = token_module._inventory(projected_artifact, {"tokens": supported}, budget)
    births = [record for record in held.values() if record["kind"] == "birth"]
    if len(births) > 1:
        raise Refuted("the selected holding declares more than one birth token")
    if birth is None:
        raise Unavailable(gaps[0] if gaps else "required declared birth token absent")
    if check == "tenure":
        result = (token_module._tenure(artifact, inputs, budget, held, birth)
                  if "clock" in artifact else _tenure_without_clock(artifact, inputs, budget, held, birth))
    elif check == "delegation":
        # Unsupported named parents remain unresolved; supported path and
        # relation contradictions are still refutable. Partial replay never PASSes.
        result = _delegation_relations(artifact, budget, held, birth,
                                       partial_inventory=unsupported)
    else:
        common_module.integer(common_module.need(artifact, "clock_skew"))
        leases = list(token_module._leases_of(held).values())
        if not leases:
            raise Unavailable("a nonempty selected lifetime-window inventory is required")
        windows = [{"token_id": token["token_id"], "not_before": token["not_before"],
                    "expires_at": token["not_after"]} for token in leases if token["not_after"] is not None]
        bounded = statics_module.evaluate("TOKEN", "window", artifact, {"windows": windows}, budget) if windows else {
            "windows": 0, "skew": artifact["clock_skew"], "narrowest": None}
        result = {**bounded, "unbounded_windows": sorted(
            token["token_id"] for token in leases if token["not_after"] is None), "leases": len(leases)}
    if unsupported:
        gaps.append("selected TOKEN kind has no capability-token mapping")
    if gaps:
        raise Unavailable(gaps[0])
    return result


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if len(matches) != 1 or matches[0].kind.value != "TOKEN" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained TOKEN subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = _record(matches[0].payload, {"scope", "clock_unit", "artifact"}, "TOKEN payload")
        if payload["scope"] != "retained-capability-token-records" or payload["clock_unit"] != "microsecond":
            raise Unavailable("selected TOKEN scope or clock unit has no admitted mapping")
        artifact = common_module.obj(payload["artifact"])
        if set(artifact) - {"clock", "clock_skew", "root_scopes", "tokens_digest", "epochs_digest"}:
            raise Refuted("unsupported capability-token artifact field")
        if value["inputs"] is None:
            raise Unavailable("retained capability-token inputs absent")
        inputs = common_module.obj(value["inputs"])
        if set(inputs) - {"tokens", "epochs"}:
            raise Refuted("unsupported capability-token input field")
        result = _native(request["check"], artifact, inputs, budget)
        return MechanismDecision(MechanismOutcome.PASS, "selected retained capability-token check reproduced",
                                 {"token": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _TokenChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound capability-token proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained capability-token evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TokenChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_TokenChecksMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": scope(request["check"]),
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "signature_validity": "NOT_ESTABLISHED", "physical_clock": "NOT_ESTABLISHED",
        "holding_completeness": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise TokenChecksError("certificate byte bound exhausted")
    return encoded


def build_token_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise TokenChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TokenChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_token_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TokenChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise TokenChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise TokenChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise TokenChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TokenChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TokenChecksError):
            raise
        raise TokenChecksError("invalid retained capability-token certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "TokenDescriptor", "TokenChecksError", "token_checks_policy",
           "token_checks_request", "build_token_checks_certificate", "recheck_token_checks_certificate"]

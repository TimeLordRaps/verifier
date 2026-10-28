"""Shared retained mechanisms for consequential added kinds.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). The route registry is declarative. The certificate
engine replays bounded retained bytes and never actuates hardware, submits an
order, or moves money. ROBOT and FINBOT use the installed consequence-graph
engine, so reachability, dominance, and bypass semantics have one source.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping

from verifier.core.receipt import strict_json_loads
from verifier.runtime import namespace_consequences, namespace_contracts
from verifier.runtime import policy_enforcement_worker as _policy_oracle
from verifier.runtime.tier_zero_profile import (
    applicability_digest,
    canonical_bytes,
    validate_applicability_binding,
    value_digest,
)


SEMANTIC_VERSION = "verifier-added-kind-behavioral-routes-2"
ADAPTER = "verifier-retained-added-kind-behavioral-1"
# The POLICY enforcement family is separate: its own semantic version, adapter and
# wire identifiers, so a POLICY row can never be recognized as a legacy route.
POLICY_SEMANTIC_VERSION = "verifier-policy-enforcement-routes-1"
POLICY_ADAPTER = "verifier-retained-policy-enforcement-1"
_POLICY_REQUEST_VERSION = "verifier-retained-policy-enforcement-request-1"
_POLICY_POLICY_VERSION = "verifier-retained-policy-enforcement-policy-1"
_POLICY_CERTIFICATE_VERSION = "verifier-retained-policy-enforcement-certificate-1"
_POLICY_EVIDENCE_VERSION = "verifier-retained-policy-enforcement-evidence-1"
_POLICY_MECHANISM_ID = "verifier.policy-enforcement.retained-observations.1"
_HASH_PREFIX = "sha256:"
_LIMIT_CEILINGS = {
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_records": 4096,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class BehavioralRoute:
    """One cumulative route with its reason and bounded claim."""

    check: str
    coordinate: str
    kind: str
    tier: int
    obligation_id: str
    name: str
    reason: str
    proposition: str
    prerequisites: tuple[str, ...]
    exclusions: tuple[str, ...]


ROUTES = (
    BehavioralRoute(
        "lifecycle", "MARKET-1.1-order-access-lifecycle", "MARKET", 1,
        "MARKET-0.1-orders-and-access", "Order and access lifecycle",
        "Orders cannot be matched safely unless participant access, unique identity, validation, cancellation, and terminal states are replayable.",
        "The selected complete retained trace has unique participant and order identities, admitted participants, and legal order-state transitions.",
        ("exact source coordinate", "complete finite retained participant and order trace"),
        ("venue authority", "fair access", "live order-book correspondence", "whole MARKET conformance"),
    ),
    BehavioralRoute(
        "allocation", "MARKET-2.1-matching-pricing-allocation", "MARKET", 2,
        "MARKET-0.2-matching-and-allocation", "Matching, pricing, and allocation",
        "Well-formed orders can still be over-allocated, crossed at an inadmissible price, replayed in a different priority order, or paired with omitted or violating manipulation-control evidence.",
        "The tier-1 trace and every retained match replay with integer price and quantity units, unique priority, compatible sides and prices, and quantity conservation; retained manipulation-control records are sorted and unique, carry canonical evidence digests, and record no retained violation.",
        ("passing cumulative tier-1 evidence", "complete finite retained match trace"),
        ("fair price formation", "absence of manipulation", "manipulation-control rule coverage", "participant identity", "live matching-engine correspondence"),
    ),
    BehavioralRoute(
        "settlement", "MARKET-3.1-settlement-failure-disruption", "MARKET", 3,
        "MARKET-0.3-settlement-and-disruption", "Settlement, failure, and disruption",
        "A match is not a real settled transfer, and omitted participant-failure, disruption, or external-dependency records can leave quantity or cash effects ambiguous.",
        "The tier-1 and tier-2 traces plus retained settlement, disruption, and participant-failure records reconcile every match without duplicate finality; each retained participant failure names an admitted participant, carries a canonical evidence digest, and is marked RECOVERED.",
        ("passing cumulative tiers 1 and 2", "complete finite retained settlement and disruption trace"),
        ("real settlement", "custody", "counterparty solvency", "participant failure completeness", "absence of unretained participant failures", "external settlement dependency completeness", "venue recovery authority"),
    ),
    BehavioralRoute(
        "path", "ROBOT-1.1-agent-harness-controller-actuator-path", "ROBOT", 1,
        "ROBOT-0.1-agent-to-actuator-binding", "Agent-to-actuator path",
        "A physical consequence cannot be attributed or bounded without the actual AGENT, its governing HARNESS, and a CONTROLLER-to-ACTUATOR path.",
        "The installed consequence engine accepts the selected retained source-bound AGENT-HARNESS-CONTROLLER-ACTUATOR path to a real-physical endpoint.",
        ("exact source coordinate", "complete finite retained namespace and consequence declaration"),
        ("runtime correspondence", "physical actuation", "external confinement", "whole ROBOT conformance"),
    ),
    BehavioralRoute(
        "observation", "ROBOT-2.1-physical-reach-and-observation", "ROBOT", 2,
        "ROBOT-0.2-physical-reach-and-observation", "Physical reach and observation",
        "Retained crossing, effect-digest, and confinement records can bind a declared physical path without establishing that an observation is authentic or that a physical effect was caused by the selected command.",
        "The tier-1 path and finite retained command/effect/observation records bind each trace to one ordered SOFTWARE_COMMAND-to-REAL_PHYSICAL crossing, a unique canonical retained-effect digest, and one typed confinement claim per selected actuator whose authenticity is NOT_ESTABLISHED.",
        ("passing cumulative tier-1 evidence", "complete finite retained trace"),
        ("observation authenticity", "physical causal attribution", "physical actuation", "external confinement", "confinement evidence authenticity"),
    ),
    BehavioralRoute(
        "intervention", "ROBOT-3.1-hazards-intervention-and-safe-state-or-continuity", "ROBOT", 3,
        "ROBOT-0.3-consequences-and-intervention", "Hazards, intervention, and safe state or continuity",
        "Physical systems can be harmed both by continuing and by stopping, so each retained hazard needs an explicit bounded response rather than a universal shutdown claim.",
        "The cumulative retained trace maps each selected actuator hazard to an intervention declaring either SAFE_STATE or CONTINUITY with an explicit reason and operating limit.",
        ("passing cumulative tiers 1 and 2", "complete finite retained hazard and intervention declaration"),
        ("safety", "adequacy of operating limits", "successful intervention", "physical recovery"),
    ),
    BehavioralRoute(
        "authority", "FINBOT-1.1-agent-harness-and-financial-authority", "FINBOT", 1,
        "FINBOT-0.1-agent-and-financial-authority", "Agent, harness, and financial authority",
        "A consequential financial decision needs the actual AGENT and HARNESS plus a scope bound to their real-financial endpoint and a declared authority boundary even when execution begins in a simulation.",
        "The installed consequence engine accepts the selected retained AGENT-HARNESS path to a typed real-financial endpoint, and the retained authority record has a structured decision scope whose agent_id, harness_id, and financial_endpoint_id exactly equal that bound path plus a non-empty financial-authority boundary.",
        ("exact source coordinate", "complete finite retained namespace and consequence declaration"),
        ("legal authority", "account ownership", "identity", "whole FINBOT conformance"),
    ),
    BehavioralRoute(
        "exposure", "FINBOT-2.1-real-financial-endpoint-and-exposure", "FINBOT", 2,
        "FINBOT-0.2-financial-exposure-and-dependencies", "Financial endpoint and exposure",
        "Advice and delegated execution can produce real exposure without a direct transaction call, so typed endpoints, retained party and asset registries, amounts, and limits must remain visible without being mistaken for external registry truth.",
        "The tier-1 path and complete retained exposure trace bind integer exposure units to the selected real-financial endpoint without exceeding declared limits, and every exposure's asset_id and party_id correspond to sorted unique identifiers in the retained asset and party registries.",
        ("passing cumulative tier-1 evidence", "complete finite retained exposure trace"),
        ("asset backing", "party identity", "external asset and party registry correspondence", "real balance", "independent limit enforcement"),
    ),
    BehavioralRoute(
        "reconciliation", "FINBOT-3.1-decision-effect-retry-intervention-and-reconciliation", "FINBOT", 3,
        "FINBOT-0.3-decisions-effects-and-recovery", "Decision, effect, retry, intervention, and reconciliation",
        "Retries and interventions can duplicate or obscure financial effects unless retained decisions, idempotency keys, effects, and reconciliation records agree.",
        "The cumulative retained trace binds each decision to one exposure, effect outcome, intervention, and reconciliation record while refusing duplicate applied retries.",
        ("passing cumulative tiers 1 and 2", "complete finite retained decision and reconciliation trace"),
        ("real-money effect", "authorized settlement", "recovery success", "external reconciliation completeness", "independent limit enforcement"),
    ),
)

_KIND_BOUNDARIES = {
    "MARKET": ("venue authority", "fairness", "manipulation absence", "real settlement",
               "runtime correspondence", "whole MARKET conformance"),
    "ROBOT": ("runtime correspondence", "external confinement", "physical actuation",
              "observation authenticity", "causal attribution", "safety",
              "whole ROBOT conformance"),
    "FINBOT": ("runtime correspondence", "external confinement", "legal authority",
               "asset backing", "real balance", "real-money effect",
               "authorized settlement", "recovery success", "whole FINBOT conformance"),
}


@dataclass(frozen=True)
class BehavioralSpec:
    """Mechanism-specific wire identifiers and immutable claim limits."""

    kind: str
    request_version: str
    policy_version: str
    certificate_version: str
    evidence_version: str
    mechanism_id: str
    source_path: Path
    error_type: type[ValueError]
    limitation_fields: tuple[str, ...]
    route_family: str = "behavioral"
    semantic_version: str = SEMANTIC_VERSION
    specification_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class BehavioralEvaluation:
    """One bounded native replay outcome."""

    status: str
    reason: str
    details: Mapping[str, Any]


class BehavioralRefuted(ValueError):
    """Retained bytes contradict the selected bounded proposition."""


class BehavioralUnavailable(ValueError):
    """Retained bytes cannot discharge the selected bounded proposition."""


def routes(kind: str | None = None) -> tuple[BehavioralRoute, ...]:
    """Return the immutable route registry, optionally for one kind."""
    if kind is None:
        return ROUTES
    selected = tuple(route for route in ROUTES if route.kind == kind)
    if not selected:
        raise ValueError("ADDED_KIND_BEHAVIORAL_KIND_UNREGISTERED")
    return selected


def route_for(kind: str, check: str) -> BehavioralRoute:
    selected = [route for route in ROUTES if route.kind == kind and route.check == check]
    if len(selected) != 1:
        raise ValueError("ADDED_KIND_BEHAVIORAL_ROUTE_UNREGISTERED")
    return selected[0]


def registration(kind: str, check: str) -> dict[str, Any]:
    route = route_for(kind, check)
    return {
        "schema_version": "verifier-added-kind-behavioral-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": route.coordinate,
        "subject_kind": route.kind,
        "tier": route.tier,
        "obligation_id": route.obligation_id,
        "name": route.name,
        "reason": route.reason,
        "proposition": route.proposition,
        "prerequisites": list(route.prerequisites),
        "exclusions": list(route.exclusions),
    }


def _mechanisms() -> dict[str, Any]:
    """Import lazily so domain modules can depend on this shared engine."""
    from verifier.domains.contracts import finbot_checks, market_checks, robot_checks
    return {"MARKET": market_checks, "ROBOT": robot_checks, "FINBOT": finbot_checks}


def _applicability(route: BehavioralRoute) -> dict[str, str]:
    domains = {"MARKET": "MARKET behavior", "ROBOT": "a REAL_PHYSICAL consequence path",
               "FINBOT": "a REAL_FINANCIAL consequence path"}
    return {
        "mode": "CONDITIONAL",
        "condition": (
            "The admitted object carries " + domains[route.kind]
            + " and the exact retained evidence selected for " + route.coordinate
            + " is part of its bounded package variant."
        ),
        "when_condition_met": "NECESSARY",
        "unknown_condition": "NOT_EXEMPT",
        "reason": (
            route.reason
            + " A source-bound refutation may establish that this condition does not "
              "trigger for a particular object variant; omission or uncertainty cannot."
        ),
    }


def catalog() -> list[dict[str, Any]]:
    """Return consequential, agency, and POLICY enforcement routes without selecting an instance.

    The adapter has no third-party runtime dependency. Catalog membership is
    not applicability evidence: each conditional route becomes necessary when
    its declared condition is established, and an unknown condition is never an
    exemption. Higher tiers name every earlier short coordinate explicitly.
    """
    modules = _mechanisms()
    recheckers = {
        "MARKET": "recheck_market_checks_certificate",
        "ROBOT": "recheck_robot_checks_certificate",
        "FINBOT": "recheck_finbot_checks_certificate",
    }
    result = []
    for route in ROUTES:
        coordinate = f"{route.kind}-{route.tier}.1"
        module = modules[route.kind]
        applicability = _applicability(route)
        result.append({
            "coordinate": coordinate,
            "obligation_id": route.coordinate,
            "obligation_name": route.name,
            "object_kind": route.kind,
            "tier": route.tier,
            "reason": route.reason,
            "applicability": applicability,
            "applicability_digest": applicability_digest(applicability),
            "predicate": route.proposition,
            "exact_claim": route.proposition,
            "semantic_version": SEMANTIC_VERSION,
            "proposition_digest": value_digest(registration(route.kind, route.check)),
            "mechanism_digest": module.mechanism_digest(),
            "checking_mechanism": module.__name__ + "." + recheckers[route.kind],
            "scope": "finite_retained_" + route.kind.lower() + "_" + route.check,
            "adapter": ADAPTER,
            "runtime_dependencies": [],
            "prerequisite_coordinates": [
                f"{route.kind}-{tier}.1" for tier in range(1, route.tier)
            ],
            "not_established": [{"claim": claim, "status": "NOT_ESTABLISHED"}
                for claim in dict.fromkeys((*_KIND_BOUNDARIES[route.kind], *route.exclusions))],
        })
    # Agency routes are separate so adding ROBOT/FINBOT crosswalk selectors
    # cannot silently widen the legacy check sets derived from ``routes()``.
    from verifier.domains.contracts import agency_surface
    return result + agency_surface.catalog() + policy_catalog()


def is_route(route: Mapping[str, Any]) -> bool:
    """Recognize only an exact current catalog row, including source digests."""
    if not isinstance(route, Mapping):
        return False
    from verifier.domains.contracts import agency_surface
    if route.get("adapter") == agency_surface.ADAPTER:
        return agency_surface.is_route(route)
    if route.get("adapter") == POLICY_ADAPTER:
        return _is_policy_route(route)
    if route.get("adapter") != ADAPTER:
        return False
    try:
        validate_applicability_binding(dict(route))
    except (TypeError, ValueError):
        return False
    selected = [row for row in catalog()
                if row["obligation_id"] == route.get("obligation_id")]
    return len(selected) == 1 and dict(route) == selected[0]


def select_package_route(*, semantic_version: str,
                         coordinate: str) -> dict[str, Any] | None:
    """Select one exact short package route without widening native routing.

    The retained certificates use the full descriptive coordinate stored as the
    package route's ``obligation_id``.  ``instance_checks`` use the short package
    coordinate.  Keeping this selector here makes that adaptation explicit and
    prevents the unrelated current-object route registry from accepting it.
    """
    if semantic_version not in {SEMANTIC_VERSION, POLICY_SEMANTIC_VERSION}:
        return None
    # Agency rows are deliberately not selectable here; only the legacy and POLICY
    # families enter the package-instance path.
    selectable = (ADAPTER, POLICY_ADAPTER)
    selected = [row for row in catalog()
                if row["coordinate"] == coordinate
                and row["semantic_version"] == semantic_version
                and row["adapter"] in selectable]
    return dict(selected[0]) if len(selected) == 1 else None


def recheck_package_certificate(
    route: Mapping[str, Any], certificate_bytes: bytes, *,
    expected_request: dict[str, Any], policy: dict[str, Any],
) -> dict[str, Any]:
    """Replay an exact added-kind certificate through its installed checker.

    This is deliberately separate from ``current_object_routes``.  Those routes
    have different request and result contracts; admitting these nine entries
    there would silently broaden every existing native selection boundary.
    """
    from verifier.domains.contracts import agency_surface
    if route.get("adapter") == agency_surface.ADAPTER:
        return agency_surface.recheck_package_certificate(
            route, certificate_bytes, expected_request=expected_request, policy=policy)
    if route.get("adapter") == POLICY_ADAPTER:
        return recheck_policy_package_certificate(
            route, certificate_bytes, expected_request=expected_request, policy=policy)
    if not is_route(route):
        raise ValueError("ADDED_KIND_PACKAGE_ROUTE_DIFFERS")
    native = route_for(route["object_kind"], expected_request.get("check"))
    if (
        expected_request.get("semantic_version") != route["semantic_version"]
        or expected_request.get("coordinate") != route["obligation_id"]
        or expected_request.get("proposition_digest")
            != route["proposition_digest"]
        or expected_request.get("object_kind") != route["object_kind"]
        or native.coordinate != route["obligation_id"]
    ):
        raise ValueError("ADDED_KIND_PACKAGE_REQUEST_ROUTE_DIFFERS")
    module = _mechanisms()[route["object_kind"]]
    rechecker = getattr(module, {
        "MARKET": "recheck_market_checks_certificate",
        "ROBOT": "recheck_robot_checks_certificate",
        "FINBOT": "recheck_finbot_checks_certificate",
    }[route["object_kind"]])
    replay = rechecker(
        certificate_bytes, expected_request=expected_request, policy=policy,
    )
    expected_scope = (
        "finite_retained_" + route["object_kind"].lower() + "_" + native.check
    )
    if (
        type(replay) is not dict
        or replay.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
        or replay.get("semantic_version") != route["semantic_version"]
        or replay.get("coordinate") != route["obligation_id"]
        or replay.get("object_kind") != route["object_kind"]
        or replay.get("scope") != expected_scope
        or replay.get("object_profile_conformance") != "NOT_ESTABLISHED"
    ):
        raise ValueError("ADDED_KIND_PACKAGE_REPLAY_BOUNDARY_DIFFERS")
    return replay


def _raise(spec: BehavioralSpec, message: str) -> None:
    raise spec.error_type(message)


def _commitment(value: Any, spec: BehavioralSpec, label: str) -> str:
    if (type(value) is not str or not value.startswith(_HASH_PREFIX)
            or len(value) != 71 or any(character not in "0123456789abcdef" for character in value[7:])):
        _raise(spec, label + " requires a canonical SHA-256 commitment")
    return value


def _record(value: Any, fields: set[str], spec: BehavioralSpec, label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(key) is not str for key in value):
        _raise(spec, label + " fields differ")
    return dict(value)


def mechanism_digest(spec: BehavioralSpec) -> str:
    paths = {
        "behavioral_routes": Path(__file__),
        "mechanism": spec.source_path,
        "namespace_consequences": Path(namespace_consequences.__file__),
        "namespace_contracts": Path(namespace_contracts.__file__),
    }
    paths.update({"specification:" + path.name: path
                  for path in spec.specification_paths})
    return value_digest({name: hashlib.sha256(path.read_bytes()).hexdigest()
                         for name, path in sorted(paths.items())})


def _spec_route(spec: BehavioralSpec, check: str) -> BehavioralRoute:
    """Resolve a route without widening the legacy ROBOT/FINBOT check sets."""
    if spec.route_family == "behavioral":
        return route_for(spec.kind, check)
    if spec.route_family == "agency":
        from verifier.domains.contracts import agency_surface
        return agency_surface.route_for(spec.kind, check)
    if spec.route_family == "policy":
        return _policy_route(check)
    _raise(spec, "unsupported route family")


def _spec_registration(spec: BehavioralSpec, check: str) -> dict[str, Any]:
    if spec.route_family == "behavioral":
        return registration(spec.kind, check)
    if spec.route_family == "agency":
        from verifier.domains.contracts import agency_surface
        return agency_surface.registration(spec.kind, check)
    if spec.route_family == "policy":
        return _policy_registration(check)
    _raise(spec, "unsupported route family")


def validate_policy(value: Any, spec: BehavioralSpec) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes"}, spec, "policy")
    if policy["schema_version"] != spec.policy_version or policy["mechanism_id"] != spec.mechanism_id:
        _raise(spec, "policy mechanism differs")
    if _commitment(policy["mechanism_digest"], spec, "mechanism digest") != mechanism_digest(spec):
        _raise(spec, "policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        _raise(spec, "bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        _raise(spec, "certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def make_policy(spec: BehavioralSpec, *, trust_roots: list[str],
                max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return validate_policy({"schema_version": spec.policy_version,
        "mechanism_id": spec.mechanism_id, "mechanism_digest": mechanism_digest(spec),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes}, spec)


def _limits(value: Any, spec: BehavioralSpec) -> dict[str, int]:
    limits = _record(value, set(_LIMIT_CEILINGS), spec, "limits")
    for name, ceiling in _LIMIT_CEILINGS.items():
        if type(limits[name]) is not int or not 1 <= limits[name] <= ceiling:
            _raise(spec, "finite " + name + " is unsupported")
    return limits


def validate_request(value: Any, spec: BehavioralSpec) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "check", "object_kind", "subject_id", "source_digest",
        "evidence_ref", "policy_digest", "limits"}, spec, "request")
    try:
        route = _spec_route(spec, request["check"])
    except ValueError:
        _raise(spec, "unsupported " + spec.kind + " check")
    expected = {"schema_version": spec.request_version, "semantic_version": spec.semantic_version,
        "coordinate": route.coordinate, "object_kind": spec.kind}
    if any(type(request[name]) is not str or request[name] != wanted
           for name, wanted in expected.items()):
        _raise(spec, "selected " + spec.kind + " objective differs")
    for name in ("proposition_digest", "source_digest", "evidence_ref", "policy_digest"):
        _commitment(request[name], spec, name)
    if request["proposition_digest"] != value_digest(_spec_registration(spec, route.check)):
        _raise(spec, "selected proposition differs")
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        _raise(spec, "bounded subject identifier required")
    request["limits"] = _limits(request["limits"], spec)
    return request


def make_request(spec: BehavioralSpec, *, check: str, subject_id: str,
                 source_digest: str, evidence_ref: str, policy: dict[str, Any],
                 limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = validate_policy(policy, spec)
    try:
        route = _spec_route(spec, check)
    except ValueError:
        _raise(spec, "unsupported " + spec.kind + " check")
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_LIMIT_CEILINGS))):
        _raise(spec, "unsupported limit override")
    return validate_request({"schema_version": spec.request_version,
        "semantic_version": spec.semantic_version, "coordinate": route.coordinate,
        "proposition_digest": value_digest(_spec_registration(spec, check)),
        "check": check, "object_kind": spec.kind, "subject_id": subject_id,
        "source_digest": source_digest, "evidence_ref": evidence_ref,
        "policy_digest": value_digest(admitted),
        "limits": {**_LIMIT_CEILINGS, **(limits or {})}}, spec)


def evidence_document(data: bytes, request: dict[str, Any], spec: BehavioralSpec,
                      fields: set[str]) -> dict[str, Any]:
    """Decode canonical retained bytes and bind kind, subject, and source."""
    try:
        value = strict_json_loads(data.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise BehavioralRefuted("retained evidence is not strict JSON") from exc
    if type(value) is not dict or set(value) != fields | {
            "schema_version", "object_kind", "subject_id", "source_digest"}:
        raise BehavioralRefuted("retained evidence fields differ")
    if canonical_bytes(value) != data or value["schema_version"] != spec.evidence_version:
        raise BehavioralRefuted("retained evidence version or canonical bytes differ")
    if value["object_kind"] != spec.kind:
        raise BehavioralRefuted("retained evidence object kind differs")
    if value["subject_id"] != request["subject_id"]:
        raise BehavioralRefuted("retained evidence subject differs")
    if value["source_digest"] != request["source_digest"]:
        raise BehavioralRefuted("retained evidence source coordinate is stale or substituted")
    return dict(value)


def require_sequence(value: Any, *, limit: int, label: str) -> list[Any]:
    if type(value) is not list:
        raise BehavioralRefuted(label + " must be a list")
    if len(value) > limit:
        raise BehavioralUnavailable(label + " exceeds the selected record bound")
    return list(value)


def require_complete(value: Any, label: str) -> None:
    if type(value) is not bool:
        raise BehavioralRefuted(label + " completeness must be boolean")
    if not value:
        raise BehavioralUnavailable(label + " is explicitly incomplete")


def assess_consequence_bundle(value: Any, *, subject_id: str, role: str,
                              domain: str) -> dict[str, Any]:
    """Replay the installed graph semantics for one consequential role."""
    if type(value) is not dict or set(value) != {"rows", "observed", "graph"}:
        raise BehavioralRefuted("consequence bundle fields differ")
    rows, observed, graph = value["rows"], value["observed"], value["graph"]
    if type(rows) is not list or not any(type(row) is dict and row.get("object_id") == subject_id for row in rows):
        raise BehavioralRefuted("selected consequence subject is absent")
    registry = namespace_contracts.namespace_registry()
    assessment = namespace_consequences.assess_consequences(rows, registry, observed, graph)
    if assessment["status"] == "FAIL":
        raise BehavioralRefuted("source-bound consequence graph is refuted")
    if assessment["status"] != "PASS":
        raise BehavioralUnavailable("source-bound consequence graph is unresolved")
    row = next(row for row in rows if row["object_id"] == subject_id)
    labels = {row.get("kind"), *row.get("specializations", [])}
    labels.update(kind for kind, decision in row.get("classification", {}).items()
                  if type(decision) is dict and decision.get("status") == "APPLIES")
    labels.update(assessment["required_kinds"].get(subject_id, []))
    if role not in labels:
        raise BehavioralRefuted("selected subject does not carry the required " + role + " consequence")
    reach = assessment["reachable_effects"].get(subject_id, {}).get(domain)
    if type(reach) is not dict or type(reach.get("effect_object_id")) is not str:
        raise BehavioralRefuted("selected subject does not reach the required " + domain + " endpoint")
    return assessment


Evaluator = Callable[[bytes, dict[str, Any]], BehavioralEvaluation]


def _evaluate(data: bytes | None, request: dict[str, Any], evaluator: Evaluator) -> BehavioralEvaluation:
    if data is None:
        return BehavioralEvaluation("UNKNOWN", "selected retained evidence is unavailable", {})
    try:
        return evaluator(data, request)
    except BehavioralUnavailable as exc:
        return BehavioralEvaluation("UNKNOWN", str(exc), {})
    except (BehavioralRefuted, ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return BehavioralEvaluation("FAIL", str(exc), {})


def build_certificate(spec: BehavioralSpec, request: dict[str, Any], evidence_bytes: bytes | None,
                      *, policy: dict[str, Any], evaluator: Evaluator) -> bytes:
    selected, admitted = validate_request(request, spec), validate_policy(policy, spec)
    if selected["policy_digest"] != value_digest(admitted):
        _raise(spec, "request differs from selected policy")
    payload = None
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]:
            _raise(spec, "immutable bounded evidence bytes required")
        if "sha256:" + hashlib.sha256(evidence_bytes).hexdigest() != selected["evidence_ref"]:
            _raise(spec, "evidence differs from selected byte reference")
        payload = base64.b64encode(evidence_bytes).decode("ascii")
    evaluation = _evaluate(evidence_bytes, selected, evaluator)
    result = {"status": evaluation.status, "semantic_version": spec.semantic_version,
        "coordinate": selected["coordinate"], "object_kind": spec.kind,
        "scope": "finite_retained_" + spec.kind.lower() + "_" + selected["check"],
        "object_profile_conformance": "NOT_ESTABLISHED",
        **{field: "NOT_ESTABLISHED" for field in spec.limitation_fields},
        "evaluation": {"outcome": evaluation.status, "reason": evaluation.reason,
                       "details": dict(evaluation.details)}}
    envelope = {"schema_version": spec.certificate_version, "request": selected,
        "policy_digest": selected["policy_digest"], "mechanism_digest": admitted["mechanism_digest"],
        "proposition_digest": selected["proposition_digest"], "evidence_payload": payload,
        "result": result}
    envelope["digest"] = value_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > admitted["max_certificate_bytes"]:
        _raise(spec, "certificate byte bound exhausted")
    return encoded


def recheck_certificate(spec: BehavioralSpec, certificate_bytes: bytes, *,
                        expected_request: dict[str, Any], policy: dict[str, Any],
                        evaluator: Evaluator) -> dict[str, Any]:
    selected, admitted = validate_request(expected_request, spec), validate_policy(policy, spec)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        _raise(spec, "bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_payload", "result", "digest"}, spec, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != spec.certificate_version:
            _raise(spec, "canonical certificate version differs")
        if value["digest"] != value_digest({key: item for key, item in value.items() if key != "digest"}):
            _raise(spec, "certificate digest differs")
        if value["request"] != selected:
            _raise(spec, "certificate differs from independently selected request")
        if value["policy_digest"] != value_digest(admitted):
            _raise(spec, "certificate policy differs")
        payload = value["evidence_payload"]
        if payload is None:
            evidence = None
        elif type(payload) is str:
            try:
                evidence = base64.b64decode(payload.encode("ascii"), validate=True)
            except (ValueError, UnicodeError):
                _raise(spec, "retained evidence encoding differs")
        else:
            _raise(spec, "retained evidence payload differs")
        rebuilt = build_certificate(spec, selected, evidence, policy=admitted, evaluator=evaluator)
        if rebuilt != certificate_bytes:
            _raise(spec, "certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, spec.error_type):
            raise
        raise spec.error_type("invalid retained " + spec.kind + " certificate") from exc


# --- POLICY enforcement family -------------------------------------------------------------
# A separate retained family for POLICY-1.3, POLICY-2.3 and POLICY-3.3. It is not a
# MARKET, ROBOT, FINBOT, or consequence role. The evidence is the isolated worker's raw
# observations. The installed oracle in policy_enforcement_worker judges them in this
# process, and the pinned engine bytes bind every replay. A PASS is bounded field
# evidence for retained fixtures; it never establishes authority, activation,
# enforcement, legal adoption, key custody, fact truth, or wall-clock currentness.


class PolicyEnforcementRouteError(ValueError):
    """Malformed POLICY enforcement selection or substituted certificate."""


POLICY_ROUTES = (
    BehavioralRoute(
        "rule_semantics", "POLICY-1.3-enforcement-rule-semantics", "POLICY", 1,
        "POLICY-0.1-rules-and-precedence", "Enforcement rule semantics",
        "Enforcement decisions are unsafe unless out-of-scope actions, decision inputs, role defaults, and rule precedence are replayable from one retained policy.",
        "The retained enforcement observations for POLICY-1.3 reproduce under the installed oracle: out-of-scope actions are refused before rules, the selected trust-root commitment and request digest bind the decision, roles without a rule are refused, financial labels do not exempt, and precedence follows the closed-form rule table.",
        ("exact source coordinate", "complete finite retained enforcement observation set"),
        ("authority", "activation", "enforcement", "external legal adoption", "signer or key custody", "fact truth", "unsupplied effects", "wall-clock currentness", "whole POLICY conformance"),
    ),
    BehavioralRoute(
        "exceptions_revisions", "POLICY-2.3-enforcement-exceptions-and-revisions", "POLICY", 2,
        "POLICY-0.2-authority-and-exceptions", "Enforcement exceptions and revisions",
        "A waiver or revision can silently widen enforcement when its window, target, rule, grant, lifetime, duplicate status, or current pointer is not replayed.",
        "The tier-1 observations and the POLICY-2.3 observations reproduce under the installed oracle: a waiver applies only to a deny rule within its grant, action, target, window, and lifetime bounds; duplicate identifiers, altered or superseded revision pointers, and prior-revision grants are refused.",
        ("passing tier-1 enforcement observations", "complete finite retained exception and revision observation set"),
        ("authority", "activation", "signer or key custody", "wall-clock currentness", "external legal adoption", "whole POLICY conformance"),
    ),
    BehavioralRoute(
        "decision_correspondence", "POLICY-3.3-enforcement-decision-correspondence", "POLICY", 3,
        "POLICY-0.3-enforcement-and-decisions", "Enforcement decision correspondence",
        "A decision can pass its own receipt while its evidence, enforcement point, effect claims, or internal faults are not joined to the same request and policy.",
        "The tier-1 and tier-2 observations and the POLICY-3.3 observations reproduce under the installed oracle: decision evidence must match policy, target, pass status, clauses, variable map, member values, and certificate; undeclared points are refused; effect claims reconcile to decisions; and injected stage faults fail closed without an allow.",
        ("passing cumulative tiers 1 and 2", "complete finite retained decision-evidence and effect observation set"),
        ("enforcement points in deployment", "unsupplied effects", "external dependency availability", "fact truth", "wall-clock currentness", "whole POLICY conformance"),
    ),
)

_POLICY_TRUST_ROOTS: list[str] = sorted((_policy_oracle.CLERK, _policy_oracle.DECIDER, _policy_oracle.EXCEPTOR))
_POLICY_OBSERVATION_NONCE = "retained-policy-enforcement-1"
_POLICY_CASE_LIMIT = 4096
_POLICY_SPEC = BehavioralSpec(
    kind="POLICY",
    request_version=_POLICY_REQUEST_VERSION,
    policy_version=_POLICY_POLICY_VERSION,
    certificate_version=_POLICY_CERTIFICATE_VERSION,
    evidence_version=_POLICY_EVIDENCE_VERSION,
    mechanism_id=_POLICY_MECHANISM_ID,
    source_path=Path(_policy_oracle.__file__),
    error_type=PolicyEnforcementRouteError,
    limitation_fields=(
        "authority", "activation", "enforcement", "external_legal_adoption",
        "signer_key_custody", "fact_truth", "unsupplied_effects", "wall_clock_currentness",
    ),
    route_family="policy",
    semantic_version=POLICY_SEMANTIC_VERSION,
    specification_paths=(
        *(Path(_policy_oracle.__file__).with_name(name) for name in (
            "policy_enforcement_execution.py", "policy_enforcement_routes.py", "tier_zero_profile.py",
        )),
        Path(_policy_oracle.__file__).parents[1] / "data" / "policy.py",
    ),
)
POLICY_SPEC = _POLICY_SPEC


def _short_coordinate(route: BehavioralRoute) -> str:
    return "-".join(route.coordinate.split("-", 2)[:2])


def _policy_route(check: Any) -> BehavioralRoute:
    selected = [route for route in POLICY_ROUTES if route.check == check]
    if len(selected) != 1:
        raise PolicyEnforcementRouteError("POLICY_ENFORCEMENT_ROUTE_UNREGISTERED")
    return selected[0]


def _policy_registration(check: Any) -> dict[str, Any]:
    route = _policy_route(check)
    return {
        "schema_version": "verifier-policy-enforcement-proposition-1",
        "semantic_version": POLICY_SEMANTIC_VERSION,
        "coordinate": route.coordinate,
        "subject_kind": route.kind,
        "tier": route.tier,
        "obligation_id": route.obligation_id,
        "name": route.name,
        "reason": route.reason,
        "proposition": route.proposition,
        "prerequisites": list(route.prerequisites),
        "exclusions": list(route.exclusions),
    }


def _policy_applicability(route: BehavioralRoute) -> dict[str, str]:
    return {
        "mode": "CONDITIONAL",
        "condition": (
            "The admitted object explicitly declares a POLICY enforcement decision surface "
            "and selects the retained enforcement observations for " + _short_coordinate(route) + "."
        ),
        "when_condition_met": "NECESSARY",
        "unknown_condition": "NOT_EXEMPT",
        "reason": (
            route.reason
            + " A source-bound refutation may establish that this enforcement route does not "
              "trigger for a particular object variant; omission or unknown applicability cannot."
        ),
    }


def policy_catalog() -> list[dict[str, Any]]:
    """Return the three POLICY enforcement rows with exact short coordinates."""
    result = []
    for route in POLICY_ROUTES:
        applicability = _policy_applicability(route)
        result.append({
            "coordinate": _short_coordinate(route),
            "obligation_id": route.coordinate,
            "obligation_name": route.name,
            "object_kind": route.kind,
            "tier": route.tier,
            "reason": route.reason,
            "applicability": applicability,
            "applicability_digest": applicability_digest(applicability),
            "predicate": route.proposition,
            "exact_claim": route.proposition,
            "semantic_version": POLICY_SEMANTIC_VERSION,
            "proposition_digest": value_digest(_policy_registration(route.check)),
            "mechanism_digest": mechanism_digest(_POLICY_SPEC),
            "checking_mechanism": __name__ + ".recheck_policy_enforcement_certificate",
            "scope": "finite_retained_policy_" + route.check,
            "adapter": POLICY_ADAPTER,
            "runtime_dependencies": [],
            "prerequisite_coordinates": [
                _short_coordinate(prior) for prior in POLICY_ROUTES if prior.tier < route.tier
            ],
            "not_established": [{"claim": claim, "status": "NOT_ESTABLISHED"}
                                for claim in route.exclusions],
        })
    return result


def _is_policy_route(route: Mapping[str, Any]) -> bool:
    try:
        validate_applicability_binding(dict(route))
    except (TypeError, ValueError):
        return False
    selected = [row for row in policy_catalog()
                if row["obligation_id"] == route.get("obligation_id")]
    return len(selected) == 1 and dict(route) == selected[0]


def _admit_policy(policy: Any) -> dict[str, Any]:
    """Refuse any trust-root set other than the installed fixture authorities."""
    if type(policy) is not dict or policy.get("trust_roots") != _POLICY_TRUST_ROOTS:
        raise PolicyEnforcementRouteError("POLICY_TRUST_ROOTS_DIFFER")
    return policy


def policy_enforcement_policy(*, trust_roots: list[str] | None = None,
                              max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    roots = list(_POLICY_TRUST_ROOTS) if trust_roots is None else trust_roots
    if roots != _POLICY_TRUST_ROOTS:
        raise PolicyEnforcementRouteError("POLICY_TRUST_ROOTS_DIFFER")
    return make_policy(_POLICY_SPEC, trust_roots=roots, max_certificate_bytes=max_certificate_bytes)


def policy_enforcement_request(*, check: str, subject_id: str, source_digest: str,
                               evidence_ref: str, policy: dict[str, Any],
                               limits: dict[str, int] | None = None) -> dict[str, Any]:
    return make_request(_POLICY_SPEC, check=check, subject_id=subject_id,
        source_digest=source_digest, evidence_ref=evidence_ref,
        policy=_admit_policy(policy), limits=limits)


def policy_enforcement_evidence(*, subject_id: str, source_digest: str,
                                observations: list[dict[str, Any]],
                                source_pins: dict[str, str]) -> bytes:
    """Canonical retained bytes around one worker observation set and its source pins."""
    return canonical_bytes({
        "schema_version": _POLICY_EVIDENCE_VERSION,
        "object_kind": "POLICY",
        "subject_id": subject_id,
        "source_digest": source_digest,
        "observations": observations,
        "source_pins": source_pins,
    })


def retained_policy_observations(*, timeout: int = 180) -> dict[str, Any]:
    """Run the isolated worker once and return its raw observations and pins.

    The worker is started as ``python -I -S -B``. The echoed nonce and the source
    pins must match, so stale or substituted worker output cannot become evidence.
    """
    request = json.dumps({"schema": _policy_oracle.REQUEST_SCHEMA,
                          "nonce": _POLICY_OBSERVATION_NONCE}).encode()
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(Path(_policy_oracle.__file__))],
            input=request, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise PolicyEnforcementRouteError(
            "POLICY_WORKER_UNAVAILABLE:" + type(error).__name__) from error
    if completed.returncode != 0:
        raise PolicyEnforcementRouteError("POLICY_WORKER_FAILED")
    try:
        payload = json.loads(completed.stdout)
    except ValueError as error:
        raise PolicyEnforcementRouteError("POLICY_WORKER_OUTPUT_INVALID") from error
    if not (type(payload) is dict and payload.get("schema") == _policy_oracle.OBSERVATION_SCHEMA
            and payload.get("nonce") == _POLICY_OBSERVATION_NONCE
            and type(payload.get("observations")) is list):
        raise PolicyEnforcementRouteError("POLICY_WORKER_OUTPUT_INVALID")
    if payload.get("source_pins") != _policy_oracle.source_pins():
        raise PolicyEnforcementRouteError("POLICY_SOURCE_DRIFT")
    return {"source_pins": payload["source_pins"], "observations": payload["observations"]}


def _policy_evaluate(data: bytes, request: dict[str, Any]) -> BehavioralEvaluation:
    """Judge retained observations with the installed oracle, never with the engine.

    Every cumulative prerequisite must be present, and each must reproduce its
    literal expectations. An omitted prerequisite is UNKNOWN; a contradicted one
    is FAIL.
    """
    route = _policy_route(request["check"])
    evidence = evidence_document(data, request, _POLICY_SPEC, {"observations", "source_pins"})
    if evidence["source_pins"] != _policy_oracle.source_pins():
        raise BehavioralRefuted("retained policy enforcement sources differ from the installed sources")
    observations = require_sequence(evidence["observations"], limit=_POLICY_CASE_LIMIT,
                                    label="policy enforcement observations")
    if any(type(item) is not dict for item in observations):
        raise BehavioralRefuted("policy enforcement observations must be objects")
    verdicts, global_refusals = _policy_oracle.check_all(observations)
    if global_refusals:
        raise BehavioralRefuted("retained policy observations are outside the closed case set: "
                                + ";".join(global_refusals))
    # The worker keys observations and verdicts by the full descriptive coordinate.
    cumulative = [item.coordinate for item in POLICY_ROUTES if item.tier <= route.tier]
    present = {item.get("coordinate") for item in observations}
    for coordinate in cumulative:
        if coordinate not in present:
            raise BehavioralUnavailable("retained policy evidence omits " + coordinate)
    for coordinate in cumulative:
        verdict, refusals = verdicts[coordinate]
        if verdict != _policy_oracle.PASS:
            raise BehavioralRefuted(coordinate + " is not reproduced: "
                                    + (refusals[0] if refusals else "UNREPORTED_REFUSAL"))
    return BehavioralEvaluation(
        "PASS", "selected retained POLICY enforcement observations reproduced under the installed oracle",
        {"coordinate": route.coordinate, "verified_coordinates": cumulative,
         "case_count": sum(1 for item in observations if item.get("coordinate") in cumulative),
         "source_pins_digest": value_digest(evidence["source_pins"])},
    )


def build_policy_enforcement_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                         *, policy: dict[str, Any]) -> bytes:
    return build_certificate(_POLICY_SPEC, request, evidence_bytes,
        policy=_admit_policy(policy), evaluator=_policy_evaluate)


def recheck_policy_enforcement_certificate(certificate_bytes: bytes, *,
                                           expected_request: dict[str, Any],
                                           policy: dict[str, Any]) -> dict[str, Any]:
    return recheck_certificate(_POLICY_SPEC, certificate_bytes,
        expected_request=expected_request, policy=_admit_policy(policy),
        evaluator=_policy_evaluate)


def recheck_policy_package_certificate(
    route: Mapping[str, Any], certificate_bytes: bytes, *,
    expected_request: dict[str, Any], policy: dict[str, Any],
) -> dict[str, Any]:
    """Replay a POLICY enforcement certificate against its exact catalog row."""
    if not _is_policy_route(route):
        raise ValueError("ADDED_KIND_PACKAGE_ROUTE_DIFFERS")
    if (expected_request.get("semantic_version") != route["semantic_version"]
            or expected_request.get("coordinate") != route["obligation_id"]
            or expected_request.get("proposition_digest") != route["proposition_digest"]
            or expected_request.get("object_kind") != route["object_kind"]):
        raise ValueError("ADDED_KIND_PACKAGE_REQUEST_ROUTE_DIFFERS")
    replay = recheck_policy_enforcement_certificate(
        certificate_bytes, expected_request=expected_request, policy=policy)
    if (type(replay) is not dict or replay.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
            or replay.get("semantic_version") != POLICY_SEMANTIC_VERSION
            or replay.get("coordinate") != route["obligation_id"]
            or replay.get("object_kind") != route["object_kind"]
            or replay.get("scope") != route["scope"]
            or replay.get("object_profile_conformance") != "NOT_ESTABLISHED"):
        raise ValueError("ADDED_KIND_PACKAGE_REPLAY_BOUNDARY_DIFFERS")
    return replay


__all__ = ["SEMANTIC_VERSION", "ADAPTER", "BehavioralRoute", "BehavioralSpec",
    "BehavioralEvaluation", "BehavioralRefuted", "BehavioralUnavailable", "ROUTES",
    "routes", "route_for", "registration", "catalog", "is_route",
    "select_package_route", "recheck_package_certificate", "mechanism_digest", "make_policy",
    "make_request", "evidence_document", "require_sequence", "require_complete",
    "assess_consequence_bundle", "build_certificate", "recheck_certificate",
    "POLICY_SEMANTIC_VERSION", "POLICY_ADAPTER", "POLICY_ROUTES", "PolicyEnforcementRouteError",
    "POLICY_SPEC", "policy_catalog", "policy_enforcement_policy",
    "policy_enforcement_request", "policy_enforcement_evidence",
    "retained_policy_observations", "build_policy_enforcement_certificate",
    "recheck_policy_enforcement_certificate", "recheck_policy_package_certificate"]

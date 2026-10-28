"""Current finite retained production/checking provenance separation.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Simulation (SIM). This tier-5 objective checks an externally selected
documentary model, never real-world independent witnesses. Source labels and
different signatures cannot establish identity or causal/statistical independence.
Counts are dimensionless; size limits count bytes. No retained artifact executes.
"""
from __future__ import annotations

import base64
import binascii
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
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.contracts import retained_selection, typed_facets

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-independence-checks-request-1"
POLICY_VERSION = "verifier-current-independence-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-independence-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-independence-checks-evidence-1"
TRACE_VERSION = "verifier-current-independence-artifact-trace-1"
COLLECTION_VERSION = typed_facets.COLLECTION_VERSION
MECHANISM_ID = "verifier.current-object.retained-provenance-separation.1"
SCOPE = "finite_selected_artifact_provenance_partition"
KIND_SCOPES = {kind.value: SCOPE for kind in ObjectKind if kind.value != "SIM"}
DIMENSIONS = ("retained_provenance", "actor_identity", "authority", "implementation", "runtime", "common_cause", "causal", "statistical")
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_source_nodes": 1024,
    "max_source_edges": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024, "max_reference_bytes": 4 * 1024 * 1024,
    "max_json_depth": 64, "max_numeric_token_bytes": 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class IndependenceChecksError(ValueError):
    """Malformed external intent, unsupported policy or substituted certificate."""


def _kind(value: Any) -> str:
    if type(value) is not str or value not in KIND_SCOPES:
        raise IndependenceChecksError("supported exact kind required; SIM-5.1 is preserved")
    return value


def coordinate(kind: str) -> str:
    return _kind(kind) + "-5.1"


def registration(kind: str) -> dict[str, Any]:
    kind = _kind(kind)
    facets = typed_facets.registration(kind)["proposition"]
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(kind), "subject_kind": kind, "scope": SCOPE,
        "proposition": "For the externally selected exact " + kind + " record and typed collection, each selected production and checking root retains an exact role trace of the subject record, complete payload commitment, every direct named operand and every transitive operand record. Its nonempty retained source dependency footprint is acyclic and closed within the selected finite documentary graph; production and checking footprints share neither a recorded node nor retained source artifact bytes. Kind prerequisite: " + facets,
        "prerequisites": ["externally selected exact subject, complete collection, source-role roots, graph commitment, evidence and installed checker policy"],
        "exclusions": ["source authenticity or provenance completeness outside the selected documentary graph",
            "real-world actor identity, authority, implementation, runtime, common-cause, causal or statistical independence",
            "actual production, observation, execution or non-self-witnessing",
            "truth of payloads or trace assertions", "whole tier or object-profile conformance"]}


@dataclass(frozen=True)
class IndependenceChecksDescriptor:
    """Kind-bound public metadata; no claim transfers between kinds."""
    kind: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return digest(registration(self.kind))


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection, typed_facets)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TYPED_FACETS.md", "CURRENT_INDEPENDENCE_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _capture(value: Any) -> Any:
    """Own bounded plain selection values before any equality or hashing."""
    nodes = encoded = 0
    def copy(item: Any, depth: int) -> Any:
        nonlocal nodes, encoded
        nodes += 1
        if nodes > 10000 or depth > 64:
            raise IndependenceChecksError("selection structural bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > 1024 * 1024:
                raise IndependenceChecksError("selection text bound exhausted")
            encoded += len(item.encode("utf-8"))
            if encoded > 1024 * 1024:
                raise IndependenceChecksError("selection text bound exhausted")
            return item
        if item is None or kind is bool:
            return item
        if kind is int and item.bit_length() <= 4096:
            return item
        if kind is list and len(item) <= 4096:
            return [copy(child, depth + 1) for child in item]
        if kind is dict and len(item) <= 4096 and all(type(key) is str for key in item):
            return {copy(key, depth + 1): copy(child, depth + 1) for key, child in item.items()}
        raise IndependenceChecksError("bounded plain selection values required")
    try:
        return copy(value, 0)
    except (RuntimeError, RecursionError, UnicodeError) as exc:
        raise IndependenceChecksError("selection cannot be captured") from exc


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, IndependenceChecksError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, IndependenceChecksError)


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise IndependenceChecksError("bounded nonempty source identifier required")
    return value


def _names(value: Any, *, nonempty: bool = True) -> list[str]:
    if type(value) is not list or len(value) > 64 or nonempty and not value:
        raise IndependenceChecksError("bounded selected source array required")
    result = [_text(item) for item in value]
    if result != sorted(set(result)):
        raise IndependenceChecksError("sorted distinct source references required")
    return result


def _policy(value: Any) -> dict[str, Any]:
    value = _record(_capture(value), {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots",
        "max_certificate_bytes", "source_roots", "graph_digest", "required_dimensions"}, "policy")
    selected = retained_selection.policy({key: value[key] for key in
        ("schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes")},
        error_type=IndependenceChecksError, version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)
    roles = _record(value["source_roots"], {"producer", "checker"}, "source roles")
    selected["source_roots"] = {role: _names(roles[role]) for role in ("producer", "checker")}
    selected["graph_digest"] = _hash(value["graph_digest"])
    dims = value["required_dimensions"]
    if (type(dims) is not list or not dims or any(type(item) is not str or item not in DIMENSIONS for item in dims)
            or len(dims) != len(set(dims)) or "retained_provenance" not in dims):
        raise IndependenceChecksError("selected dimensions must include retained_provenance")
    selected["required_dimensions"] = list(dims)
    return selected


def independence_checks_policy(*, trust_roots: list[str], source_roots: dict[str, list[str]],
                               graph_digest: str, required_dimensions: list[str] | None = None,
                               max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes, "source_roots": source_roots,
        "graph_digest": graph_digest, "required_dimensions":
        ["retained_provenance"] if required_dimensions is None else required_dimensions})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(_capture(value), {"schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    kind = _kind(selected["object_kind"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
            ("coordinate", coordinate(kind)), ("proposition_digest", digest(registration(kind)))):
        if type(selected[field]) is not str or selected[field] != expected:
            raise IndependenceChecksError("selected independence objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(selected[field])
    _text(selected["subject_id"])
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS, IndependenceChecksError)
    return selected


def independence_checks_request(*, object_kind: str, subject_id: str, object_digest: str,
                                collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                                limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise IndependenceChecksError("unsupported checker limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate(object_kind), "proposition_digest": digest(registration(object_kind)),
        "object_kind": object_kind, "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _facet_inventory(rows: list[dict[str, Any]], subject_id: str, budget: Budget) -> dict[str, Any]:
    by_id = {row["object_id"]: NamespaceObject.create(**row) for row in rows}
    subject = by_id[subject_id]
    inventory = {"subject_record": subject.digest, "payload": digest(subject.payload), "operands": {}, "dependencies": {}}
    pending = []
    for role, refs in subject.operands:
        inventory["operands"][role] = {}
        for ref in refs:
            budget.tick()
            inventory["operands"][role][ref] = by_id[ref].digest
            pending.append(ref)
    seen = set()
    while pending:
        budget.tick()
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        inventory["dependencies"][ref] = by_id[ref].digest
        pending.extend(target for _, refs in by_id[ref].operands for target in refs)
    return inventory


def _parser_bounds(data: bytes, limits: dict[str, int]) -> None:
    """Bound nesting and numeric parsing before the strict standard-library parser.

    Quote/escape tracking measures tokens; JSON syntax validation is still native.
    A resource ceiling is uncertainty even when malformed content lies beyond it.
    """
    depth = numeric = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted = True
            numeric = 0
        elif byte in (91, 123):
            depth += 1
            numeric = 0
            if depth > limits["max_json_depth"]:
                raise Unavailable("selected evidence parser nesting bound exhausted")
        elif byte in (93, 125):
            depth -= 1
            numeric = 0
        elif byte in b"0123456789eE+.-":
            numeric += 1
            if numeric > limits["max_numeric_token_bytes"]:
                raise Unavailable("selected evidence numeric token bound exhausted")
        else:
            numeric = 0


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    observations: dict[str, Any] = {}
    try:
        limits = request["limits"]
        _parser_bounds(data, limits)
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "collection", "sources", "artifacts"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        native_request = {**request, "limits": {key: limits[key] for key in typed_facets._CEILINGS}}
        native_request["limits"]["max_operations"] = limits["max_composition_operations"]
        native = typed_facets._evaluate(canonical_bytes(value["collection"]), native_request)
        if native.outcome != MechanismOutcome.PASS:
            return native
        budget = Budget(limits["max_operations"])
        inventory = _facet_inventory(value["collection"]["objects"], request["subject_id"], budget)
        observations["facets_checked"] = 2 + sum(len(refs) for refs in inventory["operands"].values()) + len(inventory["dependencies"])
        graph = value["sources"]
        if type(graph) is not dict or any(type(key) is not str for key in graph):
            raise Refuted("plain retained source graph required")
        if len(graph) > limits["max_source_nodes"]:
            raise Unavailable("selected source node bound exhausted")
        if digest(graph) != policy["graph_digest"]:
            raise Refuted("retained graph differs from external commitment")
        edges = 0
        for name, row in graph.items():
            budget.tick()
            _text(name)
            node = _record(row, {"artifact_ref", "parents"}, "source node")
            _hash(node["artifact_ref"])
            parents = _names(node["parents"], nonempty=False)
            edges += len(parents)
            if edges > limits["max_source_edges"]:
                raise Unavailable("selected source edge bound exhausted")
        missing: list[str] = []
        footprints: dict[str, set[str]] = {}
        # Iterative active-stack traversal detects cycles without Python recursion.
        for role in ("producer", "checker"):
            seen: set[str] = set()
            active: set[str] = set()
            for root in policy["source_roots"][role]:
                if root in graph and not graph[root]["parents"]:
                    missing.append("nonempty dependency support for " + role)
                pending = [(root, False)]
                while pending:
                    budget.tick()
                    name, leaving = pending.pop()
                    if leaving:
                        active.remove(name)
                        seen.add(name)
                        continue
                    if name in active:
                        raise Refuted("recorded source dependency cycle")
                    if name in seen:
                        continue
                    if name not in graph:
                        missing.append("source node " + name)
                        continue
                    active.add(name)
                    pending.append((name, True))
                    pending.extend((parent, False) for parent in reversed(graph[name]["parents"]))
            footprints[role] = seen
        if footprints["producer"] & footprints["checker"]:
            raise Refuted("production and checking share a recorded source node")
        artifact_sets = {role: {graph[name]["artifact_ref"] for name in names} for role, names in footprints.items()}
        if artifact_sets["producer"] & artifact_sets["checker"]:
            raise Refuted("production and checking share retained source artifact bytes")
        reached = footprints["producer"] | footprints["checker"]
        # Validate even unselected documentary nodes. Their presence cannot turn
        # absent selected coverage into a false claim or hide a recorded cycle.
        pending = [(name, False) for name in sorted(graph)]
        active = set()
        complete: set[str] = set()
        while pending:
            budget.tick()
            name, leaving = pending.pop()
            if leaving:
                active.remove(name)
                complete.add(name)
                continue
            if name in active:
                raise Refuted("recorded source dependency cycle")
            if name in complete:
                continue
            if name not in graph:
                missing.append("source node " + name)
                continue
            active.add(name)
            pending.append((name, True))
            pending.extend((parent, False) for parent in reversed(graph[name]["parents"]))
        artifacts = value["artifacts"]
        if type(artifacts) is not dict or any(type(key) is not str for key in artifacts):
            raise Refuted("plain retained source artifacts required")
        needed = {node["artifact_ref"] for node in graph.values()}
        if set(artifacts) - needed:
            raise Refuted("unbound source artifact included")
        decoded = {}
        for ref in sorted(needed):
            budget.tick()
            if ref not in artifacts:
                missing.append("source artifact " + ref)
                continue
            if type(artifacts[ref]) is not str:
                raise Refuted("plain retained source artifact encoding required")
            try:
                raw = base64.b64decode(artifacts[ref], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise Refuted("invalid retained source artifact encoding") from exc
            if base64.b64encode(raw).decode("ascii") != artifacts[ref]:
                raise Refuted("noncanonical retained source artifact encoding")
            if "sha256:" + hashlib.sha256(raw).hexdigest() != ref:
                raise Refuted("retained source artifact bytes differ")
            decoded[ref] = raw
        for role in ("producer", "checker"):
            expected = {"schema_version": TRACE_VERSION, "role": role,
                **{key: request[key] for key in ("object_kind", "subject_id", "object_digest", "collection_digest")},
                "facets": inventory}
            for root in policy["source_roots"][role]:
                budget.tick()
                if root in graph:
                    ref = graph[root]["artifact_ref"]
                    if ref in decoded and decoded[ref] != canonical_bytes(expected):
                        raise Refuted("source role trace differs from exact kind, record, collection or complete facets")
        observations.update({"source_nodes_checked": len(reached), "source_artifacts_checked": len(decoded),
            "producer_nodes": sorted(footprints["producer"]), "checker_nodes": sorted(footprints["checker"]),
            "operations_used": budget.used})
        if missing:
            raise Unavailable("required retained coverage absent: " + "; ".join(sorted(set(missing))))
        observations["retained_provenance"] = "PASS"
        if set(policy["required_dimensions"]) - {"retained_provenance"}:
            raise Unavailable("selected real-world independence dimensions are unobserved")
        return MechanismDecision(MechanismOutcome.PASS, "exact selected documentary provenance footprints are disjoint", observations)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc), observations)
    except (RecursionError, MemoryError) as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "evidence parser or checker capacity unavailable: " + type(exc).__name__, observations)
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc), observations)


class _IndependenceMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != retained_selection.parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound provenance partition proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained documentary model is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != digest(policy):
        raise IndependenceChecksError("request differs from independently selected source policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=retained_selection.parameters(request))
    session = VerificationSession(store)
    session.register(_IndependenceMechanism(request, policy))
    evaluation = session.evaluate(binding)
    dimensions = {name: "UNKNOWN" for name in DIMENSIONS}
    if evaluation.outcome == MechanismOutcome.FAIL:
        dimensions["retained_provenance"] = "FAIL"
    elif evaluation.outcome == MechanismOutcome.PASS or evaluation.observations.get("retained_provenance") == "PASS":
        dimensions["retained_provenance"] = "PASS"
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "independence_tier_conformance": "NOT_ESTABLISHED",
        "source_authenticity": "UNKNOWN", "dimensions": dimensions, "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise IndependenceChecksError("certificate byte bound exhausted")
    return encoded


def build_independence_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                         *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise IndependenceChecksError("bounded immutable retained evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise IndependenceChecksError("retained evidence differs from external byte selection")
    return _build(selected, admitted, store)


def recheck_independence_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any],
                                           policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise IndependenceChecksError("bounded immutable certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest",
            "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise IndependenceChecksError("canonical certificate version differs")
        if canonical_bytes(value["request"]) != canonical_bytes(selected):
            raise IndependenceChecksError("certificate differs from independently selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise IndependenceChecksError("retained certificate evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise IndependenceChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, IndependenceChecksError):
            raise
        raise IndependenceChecksError("invalid retained provenance certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CERTIFICATE_VERSION", "EVIDENCE_VERSION", "TRACE_VERSION", "KIND_SCOPES",
    "IndependenceChecksError", "IndependenceChecksDescriptor", "coordinate", "registration", "mechanism_digest",
    "independence_checks_policy", "independence_checks_request", "build_independence_checks_certificate",
    "recheck_independence_checks_certificate"]

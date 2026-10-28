"""ARCH-4.1: finite selected operator-definition and library-byte closure.

Computational model architecture (ARCH); Verifier Standard (VSTD); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless and byte limits count retained encoded bytes. This checks declared
references and commitments, not execution, operator truth or complete submodules.
"""
from __future__ import annotations

import base64
from collections import deque
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ARCH-4.1"
REQUEST_VERSION = "verifier-current-arch-resolution-request-1"
POLICY_VERSION = "verifier-current-arch-resolution-policy-1"
CERTIFICATE_VERSION = "verifier-current-arch-resolution-certificate-1"
EVIDENCE_VERSION = "verifier-current-arch-resolution-evidence-1"
LIBRARY_VERSION = "verifier-current-arch-operator-library-1"
MECHANISM_ID = "verifier.current-arch.selected-operator-definition-closure.1"
SCOPE = "finite_selected_arch_operator_definition_closure"
_CEILINGS = {
    "max_operations": 300000, "max_items": 4096, "max_objects": 256,
    "max_nodes": 512, "max_libraries": 32, "max_definitions": 512,
    "max_references": 4096, "max_depth": 64, "max_composition_operations": 100000,
    "max_library_bytes": 1024 * 1024, "max_total_library_bytes": 4 * 1024 * 1024,
    "max_evidence_bytes": 8 * 1024 * 1024,
    "max_payload_bytes": 2 * 1024 * 1024, "max_reference_bytes": 2 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_CAUGHT = (ValueError, TypeError, KeyError, IndexError, UnicodeError, AttributeError)


class ArchResolutionError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "ARCH", "scope": SCOPE,
        "proposition": (
            "For the exact externally selected primitive ARCH, complete typed namespace "
            "collection and retained tensor graph, the selected operator-tag table binds "
            "each used tag once to an exact retained canonical operator definition; all "
            "declared definition dependencies resolve under externally selected complete "
            "library-byte commitments; the finite reachable definition relation is acyclic "
            "and equals the selected closure manifest with no missing or extra entries; "
            "and every tensor-node input count equals its selected definition's declared arity."
        ),
        "prerequisites": [
            "independently selected exact ARCH/collection/graph, operator-tag bindings, "
            "library-byte inventory, closure manifest, retained evidence and finite policy",
            "canonical versioned library definitions with explicitly declared dependency references",
        ],
        "exclusions": [
            "undeclared references hidden in opaque definition bodies or unretained libraries",
            "submodules or nested architectures absent from the primitive ARCH namespace contract",
            "shape equations, numerical validity, actual execution, operator truth/safety or backend portability",
            "whole ARCH closure tier, full required objective inventory, authority or authenticity",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ArchResolutionDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ArchResolutionError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ArchResolutionError)


def _name(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["NAMESPACE_OBJECTS.md"] = (Path(namespace_module.__file__).parents[1]
                                      / "standard" / "NAMESPACE_OBJECTS.md")
    paths["CURRENT_ARCH_RESOLUTION.md"] = (Path(__file__).parents[2]
                                            / "standard" / "CURRENT_ARCH_RESOLUTION.md")
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ArchResolutionError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def arch_resolution_policy(*, trust_roots: list[str],
                           max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                           ) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest", "graph_digest",
        "bindings_digest", "library_manifest_digest", "closure_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for key, expected in (("schema_version", REQUEST_VERSION),
            ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
            ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "ARCH")):
        if type(request[key]) is not str or request[key] != expected:
            raise ArchResolutionError("selected architecture-resolution objective differs")
    if not _name(request["subject_id"]):
        raise ArchResolutionError("bounded exact subject identifier required")
    for key in ("object_digest", "collection_digest", "graph_digest", "bindings_digest",
                "library_manifest_digest", "closure_digest", "evidence_ref", "policy_digest"):
        _digest(request[key])
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS,
                                                   ArchResolutionError)
    return request


def arch_resolution_request(*, subject_id: str, object_digest: str,
                            collection_digest: str, graph_digest: str,
                            bindings_digest: str, library_manifest_digest: str,
                            closure_digest: str, evidence_ref: str,
                            policy: dict[str, Any], limits: dict[str, int] | None = None
                            ) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise ArchResolutionError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "ARCH",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "graph_digest": graph_digest,
        "bindings_digest": bindings_digest, "library_manifest_digest": library_manifest_digest,
        "closure_digest": closure_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _depth_bound(data: bytes, limit: int) -> None:
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > limit:
                raise Unavailable("selected nesting bound exhausted")
        elif byte in (93, 125):
            depth -= 1


def _acyclic(dependencies: dict[Any, set[Any]], budget: common_module.Budget) -> bool:
    # Only admitted known vertices can prove a cycle. Unknown vertices stay unresolved.
    pending = {key: set(values) & dependencies.keys() for key, values in dependencies.items()}
    dependents: dict[Any, set[Any]] = {key: set() for key in pending}
    for key, values in pending.items():
        budget.tick()
        for value in values:
            budget.tick()
            dependents[value].add(key)
    ready = deque(sorted(key for key, values in pending.items() if not values))
    checked = 0
    while ready:
        budget.tick()
        key = ready.popleft()
        checked += 1
        for parent in sorted(dependents[key]):
            budget.tick()
            pending[parent].remove(key)
            if not pending[parent]:
                ready.append(parent)
    return checked == len(pending)


def _graph(value: Any, request: dict[str, Any], budget: common_module.Budget,
           failures: set[str], unknowns: set[str]) -> list[dict[str, Any]] | None:
    if value is None:
        unknowns.add("selected tensor graph is absent")
        return None
    graph = _record(value, {"nodes", "outputs"}, "tensor graph")
    if "sha256:" + canonical_digest(graph) != request["graph_digest"]:
        failures.add("retained graph differs from external selection")
    rows, outputs = graph["nodes"], graph["outputs"]
    if type(rows) is not list or type(outputs) is not list:
        raise Refuted("tensor nodes and outputs require arrays")
    if max(len(rows), len(outputs)) > request["limits"]["max_nodes"]:
        raise Unavailable("selected tensor-node bound exhausted")
    if not rows or not outputs:
        unknowns.add("nonempty retained tensor nodes and outputs required")
    nodes = []
    dependencies: dict[str, set[str]] = {}
    for row in rows:
        budget.tick()
        node = _record(row, {"name", "op", "inputs", "shape"}, "tensor node")
        if not _name(node["name"]) or not _name(node["op"]):
            raise Refuted("bounded tensor node and operator names required")
        if type(node["inputs"]) is not list or type(node["shape"]) is not list:
            raise Refuted("retained tensor inputs and shape require arrays")
        if node["name"] in dependencies:
            failures.add("tensor node names are repeated")
        if any(not _name(source) for source in node["inputs"]):
            raise Refuted("bounded tensor input references required")
        budget.tick(len(node["inputs"]))
        dependencies[node["name"]] = set(node["inputs"])
        nodes.append(node)
    for sources in dependencies.values():
        if sources - dependencies.keys():
            failures.add("tensor graph contains an unresolved input")
    if not _acyclic(dependencies, budget):
        failures.add("tensor graph contains a cycle")
    if any(not _name(output) for output in outputs) or len(set(outputs)) != len(outputs):
        failures.add("selected tensor outputs are malformed or repeated")
    if set(outputs) - dependencies.keys():
        failures.add("tensor graph contains an unresolved output")
    reached: set[str] = set()
    pending = [output for output in outputs if output in dependencies]
    while pending:
        budget.tick()
        key = pending.pop()
        if key in reached:
            continue
        reached.add(key)
        pending.extend(sorted(dependencies[key] & dependencies.keys()))
    if reached != set(dependencies):
        failures.add("tensor graph contains nodes outside selected output ancestry")
    return nodes


def _reference(value: Any, label: str) -> tuple[tuple[str, str], str]:
    ref = _record(value, {"library_id", "operator_name", "definition_digest"}, label)
    if not _name(ref["library_id"]) or not _name(ref["operator_name"]):
        raise Refuted("bounded operator-reference identifiers required")
    return (ref["library_id"], ref["operator_name"]), _digest(ref["definition_digest"])


def _catalog(value: dict[str, Any], request: dict[str, Any], budget: common_module.Budget,
             failures: set[str], unknowns: set[str]
             ) -> tuple[dict[str, str], dict[tuple[str, str], dict[str, Any]], set[str]]:
    limits = request["limits"]
    manifest, libraries = value["library_manifest"], value["libraries"]
    if manifest is None:
        raise Unavailable("selected library-byte manifest is absent")
    if type(manifest) is not list or len(manifest) > limits["max_libraries"]:
        if type(manifest) is not list:
            raise Refuted("library manifest requires an array")
        raise Unavailable("selected library bound exhausted")
    if "sha256:" + canonical_digest(manifest) != request["library_manifest_digest"]:
        failures.add("library-byte manifest differs from selection")
    selected: dict[str, str] = {}
    ids = []
    for row in manifest:
        budget.tick()
        item = _record(row, {"library_id", "library_digest"}, "library manifest entry")
        if not _name(item["library_id"]):
            raise Refuted("bounded library identifier required")
        ids.append(item["library_id"])
        selected[item["library_id"]] = _digest(item["library_digest"])
    if ids != sorted(set(ids)):
        failures.add("library manifest identifiers are not sorted and unique")
    if libraries is None:
        unknowns.add("retained operator-library bytes are absent")
        return selected, {}, set(selected)
    if type(libraries) is not list:
        raise Refuted("retained libraries require an array")
    if len(libraries) > limits["max_libraries"]:
        raise Unavailable("retained library bound exhausted")
    definitions: dict[tuple[str, str], dict[str, Any]] = {}
    unavailable: set[str] = set()
    retained_ids = []
    total_bytes, definition_count = 0, 0
    for row in libraries:
        budget.tick()
        identifier: str | None = None
        try:
            retained = _record(row, {"library_id", "library_digest", "base64"}, "retained library")
            identifier, claimed = retained["library_id"], _digest(retained["library_digest"])
            if not _name(identifier):
                raise Refuted("bounded retained library identifier required")
            retained_ids.append(identifier)
            if identifier not in selected or claimed != selected[identifier]:
                raise Refuted("retained library reference substitutes selected bytes")
            encoded = retained["base64"]
            if encoded is None:
                unavailable.add(identifier)
                unknowns.add("selected library bytes are explicitly absent")
                continue
            if type(encoded) is not str or not encoded:
                raise Refuted("library bytes require nonempty canonical base64")
            if len(encoded) > 4 * ((limits["max_library_bytes"] + 2) // 3):
                unavailable.add(identifier)
                unknowns.add("selected library byte bound exhausted")
                continue
            data = base64.b64decode(encoded, validate=True)
            total_bytes += len(data)
            if len(data) > limits["max_library_bytes"]:
                unavailable.add(identifier)
                unknowns.add("selected library byte bound exhausted")
                continue
            if total_bytes > limits["max_total_library_bytes"]:
                raise Unavailable("selected aggregate library byte bound exhausted")
            if (base64.b64encode(data).decode("ascii") != encoded
                    or "sha256:" + hashlib.sha256(data).hexdigest() != claimed):
                raise Refuted("retained library bytes are noncanonical or substituted")
            _depth_bound(data, limits["max_depth"])
            library = _record(strict_json_loads(data.decode("utf-8")),
                {"schema_version", "library_id", "definitions"}, "operator library")
            if canonical_bytes(library) != data or library["library_id"] != identifier:
                raise Refuted("operator-library canonical content or identity differs")
            if library["schema_version"] != LIBRARY_VERSION:
                unavailable.add(identifier)
                unknowns.add("selected library semantics are unsupported")
                continue
            common_module.inspect_structure(library, budget)
            rows = library["definitions"]
            if rows is None:
                unavailable.add(identifier)
                unknowns.add("selected operator definitions are explicitly absent")
                continue
            if type(rows) is not list:
                raise Refuted("operator definitions require an array")
            definition_count += len(rows)
            if definition_count > limits["max_definitions"]:
                raise Unavailable("selected definition bound exhausted")
            names = []
            for raw in rows:
                budget.tick()
                definition = _record(raw, {"operator_name", "input_count", "dependencies", "body"},
                                     "operator definition")
                name, arity = definition["operator_name"], definition["input_count"]
                if not _name(name) or type(arity) is not int or not 0 <= arity <= 256:
                    raise Refuted("bounded operator name and plain integer arity required")
                names.append(name)
                if definition["body"] is not None and type(definition["body"]) is not dict:
                    raise Refuted("retained operator body must be a JSON object or explicit null")
                deps = definition["dependencies"]
                if type(deps) is not list:
                    raise Refuted("declared operator dependencies require an array")
                if len(deps) > limits["max_references"]:
                    raise Unavailable("selected per-definition reference bound exhausted")
                refs = []
                for dep in deps:
                    budget.tick()
                    selected_dep = _record(dep, {"library_id", "operator_name"}, "operator dependency")
                    if not _name(selected_dep["library_id"]) or not _name(selected_dep["operator_name"]):
                        raise Refuted("bounded declared dependency identifiers required")
                    refs.append((selected_dep["library_id"], selected_dep["operator_name"]))
                if refs != sorted(set(refs)):
                    failures.add("operator dependencies are not sorted and unique")
                definitions[(identifier, name)] = {"definition": definition,
                    "digest": "sha256:" + canonical_digest(definition), "refs": refs}
            if names != sorted(set(names)):
                failures.add("operator definitions are not sorted and unique")
        except (Unavailable, RecursionError, OverflowError) as exc:
            # Continue other retained libraries to preserve independently checked refutations.
            if identifier is not None and _name(identifier):
                unavailable.add(identifier)
            unknowns.add(str(exc) or "library structural capacity exhausted")
        except _CAUGHT as exc:
            failures.add(str(exc))
    if retained_ids != sorted(set(retained_ids)):
        failures.add("retained library identifiers are not sorted and unique")
    missing = set(selected) - set(retained_ids)
    if missing:
        unavailable.update(missing)
        unknowns.add("selected library entries are absent")
    if set(retained_ids) - set(selected):
        failures.add("retained library inventory contains unselected bytes")
    return selected, definitions, unavailable


def _resolve(value: dict[str, Any], request: dict[str, Any], nodes: list[dict[str, Any]] | None,
             libraries: dict[str, str], definitions: dict[tuple[str, str], dict[str, Any]],
             unavailable: set[str], budget: common_module.Budget,
             failures: set[str], unknowns: set[str]) -> dict[str, Any]:
    limits = request["limits"]
    bindings, closure = value["bindings"], value["closure"]
    roots: dict[str, tuple[tuple[str, str], str]] = {}
    if bindings is None:
        unknowns.add("selected operator-tag bindings are absent")
    else:
        if type(bindings) is not list:
            raise Refuted("operator-tag bindings require an array")
        if len(bindings) > limits["max_definitions"]:
            raise Unavailable("selected binding bound exhausted")
        if "sha256:" + canonical_digest(bindings) != request["bindings_digest"]:
            failures.add("operator-tag table differs from external selection")
        tags = []
        for row in bindings:
            budget.tick()
            binding = _record(row, {"op", "library_id", "operator_name", "definition_digest"},
                              "operator-tag binding")
            if not _name(binding["op"]):
                raise Refuted("bounded operator tag required")
            tags.append(binding["op"])
            roots[binding["op"]] = _reference({key: binding[key] for key in
                ("library_id", "operator_name", "definition_digest")}, "bound operator")
        if tags != sorted(set(tags)):
            failures.add("operator-tag bindings are not sorted and unique")
        if nodes is not None and set(roots) != {node["op"] for node in nodes}:
            failures.add("operator-tag table omits a used tag or contains an unused tag")
    # Select dependency commitments independently of their defining bytes. This
    # permits real declared cycles without requiring circular hash fixed points.
    closure_refs: dict[tuple[str, str], str] = {}
    if closure is None:
        unknowns.add("selected definition-closure manifest is absent")
    else:
        if type(closure) is not list:
            raise Refuted("closure manifest requires an array")
        if len(closure) > limits["max_definitions"]:
            raise Unavailable("selected closure-manifest bound exhausted")
        if "sha256:" + canonical_digest(closure) != request["closure_digest"]:
            failures.add("closure manifest differs from external selection")
        selected_keys = []
        for row in closure:
            budget.tick()
            item = _record(row, {"library_id", "operator_name", "definition_digest", "library_digest"},
                           "closure entry")
            key, expected = _reference({field: item[field] for field in
                ("library_id", "operator_name", "definition_digest")}, "closure reference")
            selected_keys.append(key)
            closure_refs[key] = expected
            claimed = _digest(item["library_digest"])
            if key[0] not in libraries or claimed != libraries.get(key[0]):
                failures.add("closure entry substitutes selected library bytes")
            if key in definitions and definitions[key]["digest"] != expected:
                failures.add("closure entry substitutes retained definition content")
        if selected_keys != sorted(set(selected_keys)):
            failures.add("closure entries are not sorted and unique")
    dependencies: dict[tuple[str, str], set[tuple[str, str]]] = {}
    reached: set[tuple[str, str]] = set()
    pending = list(roots.values())
    references = 0
    while pending:
        budget.tick()
        key, expected = pending.pop()
        references += 1
        if references > limits["max_references"]:
            raise Unavailable("selected total reachable-reference bound exhausted")
        if key[0] not in libraries:
            failures.add("operator reference names an unselected library")
            continue
        target = definitions.get(key)
        if target is None:
            if key[0] in unavailable:
                unknowns.add("referenced operator definition is unavailable")
            else:
                failures.add("retained library has no referenced operator definition")
            continue
        if expected is not None and target["digest"] != expected:
            failures.add("operator reference substitutes selected definition content")
        if key in reached:
            continue
        reached.add(key)
        if target["definition"]["body"] is None:
            unknowns.add("reachable operator-definition body is explicitly absent")
        refs = target["refs"]
        dependencies[key] = set(refs)
        for child in refs:
            if closure is not None and child not in closure_refs:
                failures.add("closure manifest omits a declared reachable dependency")
            pending.append((child, closure_refs.get(child)))
    if not _acyclic(dependencies, budget):
        failures.add("reachable operator-definition relation contains a cycle")
    if nodes is not None:
        for node in nodes:
            budget.tick()
            root = roots.get(node["op"])
            target = definitions.get(root[0]) if root is not None else None
            if target is not None and len(node["inputs"]) != target["definition"]["input_count"]:
                failures.add("tensor-node input count differs from selected operator arity")
    derived = [{"library_id": library, "operator_name": name,
        "definition_digest": definitions[(library, name)]["digest"],
        "library_digest": libraries[library]} for library, name in sorted(reached)]
    # Equality can only be established after every declared definition resolves.
    if closure is not None and not unavailable and bindings is not None:
        if canonical_bytes(derived) != canonical_bytes(closure):
            failures.add("selected closure manifest omits or adds reachable definitions")
        if {key[0] for key in reached} != set(libraries):
            failures.add("selected library-byte inventory includes an unreachable library")
    return {"reachable_definitions": derived, "reachable_definition_count": len(reached),
            "reachable_reference_count": references, "operator_tag_count": len(roots)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    failures: set[str] = set()
    unknowns: set[str] = set()
    observations: dict[str, Any] = {}
    budget = common_module.Budget(limits["max_operations"], limits["max_items"])
    try:
        _depth_bound(data, limits["max_depth"])
        value = _record(strict_json_loads(data.decode("utf-8")), {
            "schema_version", "objects", "graph", "bindings", "library_manifest", "libraries", "closure",
        }, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained resolution evidence version or canonical bytes differ")
        common_module.inspect_structure(value, budget)
        if value["objects"] is None:
            raise Unavailable("selected complete namespace collection is absent")
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("complete collection requires namespace records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            budget.tick()
            record = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**record)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        index = {item.object_id: item for item in objects}
        subject = index.get(request["subject_id"])
        if (len(index) != len(objects) or subject is None or subject.kind.value != "ARCH"
                or subject.digest != request["object_digest"]):
            raise Refuted("selected architecture or unique collection differs")
        composition = namespace_module.assess_composition(objects,
            expected_digest=request["collection_digest"], max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value == "UNKNOWN":
            raise Unavailable(composition.reason)
        if composition.verdict.value != "PASS":
            raise Refuted(composition.reason)
        payload = _record(subject.payload, {"scope", "graph_digest"}, "architecture payload")
        if (payload["scope"] != "retained-static-tensor-graph"
                or _digest(payload["graph_digest"]) != request["graph_digest"]):
            raise Refuted("selected architecture graph binding differs")
        nodes = _graph(value["graph"], request, budget, failures, unknowns)
        libraries, definitions, unavailable = _catalog(value, request, budget, failures, unknowns)
        observations.update(_resolve(value, request, nodes, libraries, definitions,
                                     unavailable, budget, failures, unknowns))
        observations.update({"architecture_namespace_cone_ids": [subject.object_id],
            "library_count": len(libraries), "operations": budget.used})
    except (Unavailable, RecursionError, OverflowError) as exc:
        unknowns.add(str(exc) or "structural capacity exhausted")
    except _CAUGHT as exc:
        failures.add(str(exc))
    if failures:
        return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(failures)), observations)
    if unknowns:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "; ".join(sorted(unknowns)), observations)
    return MechanismDecision(MechanismOutcome.PASS,
        "selected retained operator definitions and declared dependency closure reproduced", observations)


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _ArchResolutionMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound architecture resolution differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained resolution bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ArchResolutionError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ArchResolutionMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ARCH", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED", "whole_tier_conformance": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED",
        "operator_truth_and_safety": "NOT_ESTABLISHED", "numerical_validity": "NOT_ESTABLISHED",
        "broader_submodule_closure": "UNKNOWN", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ArchResolutionError("certificate byte bound exhausted")
    return encoded


def build_arch_resolution_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                      *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ArchResolutionError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ArchResolutionError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_arch_resolution_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ArchResolutionError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ArchResolutionError("canonical certificate version differs")
        if canonical_bytes(value["request"]) != canonical_bytes(selected):
            raise ArchResolutionError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ArchResolutionError("retained resolution evidence differs")
        if any(len(data) > 4 * ((_CEILINGS["max_evidence_bytes"] + 2) // 3)
               for data in payloads.values()):
            raise ArchResolutionError("embedded evidence exceeds implementation byte ceiling")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ArchResolutionError("resolution certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (*_CAUGHT, RecursionError, OverflowError) as exc:
        if isinstance(exc, ArchResolutionError):
            raise
        raise ArchResolutionError("invalid retained resolution certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "LIBRARY_VERSION", "PROPOSITION_DIGEST", "ArchResolutionDescriptor", "ArchResolutionError",
    "registration", "mechanism_digest", "arch_resolution_policy", "arch_resolution_request",
    "build_arch_resolution_certificate", "recheck_arch_resolution_certificate"]

"""Experimental finite authority composition for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
bind inert selected bytes. The fixed asynchronous-interleaving interpretation
checks declared transitions, not runtime execution, enabled permissions, source
grounding or general agency. No existing silo verdict or numbered profile changes.
Limits count bytes or dimensionless records, states and transitions.
"""

from __future__ import annotations

from collections import Counter
import itertools
import json
from typing import Any

from .network import (
    AUTHORITY_ACTOR_SCOPES, AUTHORITY_ACTOR_SCOPE_VERSION,
    AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION,
    AUTHORITY_MODEL_SCHEMA, COMMIT_SCHEMA, AuthorityModel, NetworkError, SiloCommit,
    _digest, _path, _text, authority_actor_scope_digest,
    authority_axiom_agency_digest, canonical_bytes, digest_bytes,
)

DECLARATION_SCHEMA = "VSTD-FINITE-AUTHORITY-COMPOSITION-0.1"
RESULT_SCHEMA = "VSTD-FINITE-AUTHORITY-COMPOSITION-RESULT-0.1"
PROFILE_SCHEMA = "VSTD-FINITE-AUTHORITY-COMPOSITION-PROFILE-0.1"
MIN_MEMBERS = 2
MAX_MEMBERS = 4
MAX_PRODUCT_STATES = 256
MAX_GENERATED_TRANSITIONS = 256
MAX_RECORD_BYTES = 262144
MAX_JSON_DEPTH = 16
MAX_JSON_CONTAINERS = 8192
MAX_EVIDENCE_ENTRIES = 16
MAX_EVIDENCE_BYTES = 8388608
RESIDUAL_OBLIGATIONS = (
    "RUNTIME_MODEL_CORRESPONDENCE_NOT_ESTABLISHED",
    "GENERAL_COMPOSED_AGENCY_NOT_ESTABLISHED",
    "SOURCE_GROUNDING_NOT_ESTABLISHED",
    "SELF_DERIVATION_NOT_ESTABLISHED",
    "SOURCE_RELATION_AND_BOUNDARY_NOT_ESTABLISHED",
    "GLOBAL_CYCLE_NOT_ESTABLISHED",
    "STRONGER_COMPLETENESS_NOT_ESTABLISHED",
    "FULL_SILO_ASSESSMENT_NOT_PERFORMED",
)
_PROFILE = canonical_bytes({
    "schema_version": PROFILE_SCHEMA, "declaration_schema": DECLARATION_SCHEMA,
    "result_schema": RESULT_SCHEMA, "composition_rule": "ASYNCHRONOUS_INTERLEAVING",
    "state_rule": "bijection with member reachable-state tuples; exact product initial states",
    "transition_rule": "one member edge; other coordinates unchanged; preserve actor, action and edge multiplicity",
    "local_addition_rule": "union of reachable member COMPOSITION_PRESERVED additions in every reachable composite state",
    "agency_version": AUTHORITY_AXIOM_AGENCY_VERSION,
    "agency_digest": authority_axiom_agency_digest(),
    "actor_scope_version": AUTHORITY_ACTOR_SCOPE_VERSION,
    "actor_scope_digest": authority_actor_scope_digest(),
    "limits": {"min_members": MIN_MEMBERS, "max_members": MAX_MEMBERS,
               "max_product_states": MAX_PRODUCT_STATES, "max_generated_transitions": MAX_GENERATED_TRANSITIONS,
               "max_record_bytes": MAX_RECORD_BYTES, "max_json_depth": MAX_JSON_DEPTH,
               "max_json_containers": MAX_JSON_CONTAINERS, "max_evidence_entries": MAX_EVIDENCE_ENTRIES,
               "max_evidence_bytes": MAX_EVIDENCE_BYTES},
    "residual_obligations": list(RESIDUAL_OBLIGATIONS),
})


class AuthorityCompositionError(ValueError):
    """A definite admission or coordinate defect."""


class AuthorityCompositionLimit(AuthorityCompositionError):
    """A bounded observation could not be completed."""


class UnsupportedAuthorityComposition(AuthorityCompositionError):
    """An unavailable interpretation, not a refutation."""


def authority_composition_profile_bytes() -> bytes:
    """Return the compiled inert rule declaration; never load supplied code."""
    return _PROFILE


def authority_composition_profile_digest() -> str:
    """Identify the rule bytes, not the complete implementation dependency set."""
    return digest_bytes(_PROFILE)


def _decode(data: bytes, schema: str) -> dict[str, Any]:
    if type(data) is not bytes:
        raise AuthorityCompositionError("record requires ordinary immutable bytes")
    if len(data) > MAX_RECORD_BYTES:
        raise AuthorityCompositionLimit("record byte limit")
    depth = containers = 0
    quoted = escaped = False
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
            containers += 1
            if depth > MAX_JSON_DEPTH or containers > MAX_JSON_CONTAINERS:
                raise AuthorityCompositionLimit("record syntax limit")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise AuthorityCompositionError("unbalanced record")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AuthorityCompositionError("duplicate field")
            result[key] = value
        return result

    value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    if canonical_bytes(value) != data or type(value) is not dict:
        raise AuthorityCompositionError("noncanonical record")
    if type(value.get("schema_version")) is not str:
        raise AuthorityCompositionError("missing schema discriminator")
    if value["schema_version"] != schema:
        raise UnsupportedAuthorityComposition("unsupported schema")
    return value


def _fields(value: Any, fields: set[str]) -> None:
    if type(value) is not dict or set(value) != fields:
        raise AuthorityCompositionError("unexpected fields")


def _selection(value: Any) -> None:
    _fields(value, {"commit_digest", "authority_model_path", "authority_model_digest"})
    _digest(value["commit_digest"])
    _digest(value["authority_model_digest"])
    _path(value["authority_model_path"])


def _declaration(data: bytes) -> dict[str, Any]:
    value = _decode(data, DECLARATION_SCHEMA)
    _fields(value, {"schema_version", "profile_digest", "members", "composite", "state_bindings", "transition_bindings"})
    _digest(value["profile_digest"])
    members = value["members"]
    if type(members) is not list or len(members) < MIN_MEMBERS:
        raise AuthorityCompositionError("at least two members required")
    if len(members) > MAX_MEMBERS:
        raise AuthorityCompositionLimit("member limit")
    for item in members:
        _selection(item)
    _selection(value["composite"])
    digests = [item["commit_digest"] for item in members]
    if digests != sorted(set(digests)) or value["composite"]["commit_digest"] in digests:
        raise AuthorityCompositionError("members must have distinct sorted commit coordinates")
    for key, maximum, fields, identifier in (
        ("state_bindings", MAX_PRODUCT_STATES, {"composite_state_id", "member_state_ids"}, "composite_state_id"),
        ("transition_bindings", MAX_GENERATED_TRANSITIONS, {"composite_transition_id", "member_index", "member_transition_id"}, "composite_transition_id"),
    ):
        records = value[key]
        if type(records) is not list:
            raise AuthorityCompositionError("binding array required")
        if len(records) > maximum:
            raise AuthorityCompositionLimit("binding count limit")
        names = []
        tuples = []
        for item in records:
            _fields(item, fields)
            names.append(_text(item[identifier], identifier, maximum=128))
            if key == "state_bindings":
                coordinates = item["member_state_ids"]
                if type(coordinates) is not list or len(coordinates) != len(members):
                    raise AuthorityCompositionError("state tuple dimension mismatch")
                tuples.append(tuple(_text(name, "member state", maximum=128) for name in coordinates))
            else:
                if type(item["member_index"]) is not int or not 0 <= item["member_index"] < len(members):
                    raise AuthorityCompositionError("member index invalid")
                _text(item["member_transition_id"], "member transition", maximum=128)
        if names != sorted(set(names)) or len(tuples) != len(set(tuples)):
            raise AuthorityCompositionError("duplicate or unsorted bindings")
    return value


def _capture(evidence: dict[str, bytes]) -> dict[str, bytes | None]:
    if type(evidence) is not dict:
        raise UnsupportedAuthorityComposition("ordinary evidence dictionary required")
    if len(evidence) > MAX_EVIDENCE_ENTRIES:
        raise AuthorityCompositionLimit("evidence entry limit")
    retained: dict[str, bytes | None] = {}
    total = 0
    for key, value in evidence.items():
        if type(key) is not str:
            raise UnsupportedAuthorityComposition("ordinary evidence keys required")
        _digest(key)
        # Never invoke custom value conversion, copying or length methods.
        if type(value) is bytes:
            total += len(value)
            if total > MAX_EVIDENCE_BYTES:
                raise AuthorityCompositionLimit("evidence byte limit")
            retained[key] = value
        else:
            retained[key] = None
    return retained


def _payload(retained: dict[str, bytes | None], coordinate: str) -> bytes:
    if coordinate not in retained:
        raise UnsupportedAuthorityComposition("selected evidence absent")
    value = retained[coordinate]
    if value is None:
        raise AuthorityCompositionError("selected evidence is not ordinary bytes")
    if len(value) > MAX_RECORD_BYTES:
        raise AuthorityCompositionLimit("selected evidence byte limit")
    if digest_bytes(value) != coordinate:
        raise AuthorityCompositionError("selected digest mismatch")
    return value


def _model(selection: dict[str, str], retained: dict[str, bytes | None], index: int) -> tuple[dict[str, Any], AuthorityModel | None, bool]:
    report = {"selection_index": index, **selection, "coordinate_binding": "UNKNOWN",
              "model_admission": "UNKNOWN", "reachable_state_ids": [],
              "agency_preservation": "UNKNOWN", "reason_codes": []}
    states: set[str] = set()
    model = commit = None
    model_payload = None
    problems: set[str] = set()
    for role, schema, decoder in (("commit", COMMIT_SCHEMA, SiloCommit.from_dict), ("model", AUTHORITY_MODEL_SCHEMA, AuthorityModel.from_dict)):
        try:
            payload = _payload(retained, selection["commit_digest" if role == "commit" else "authority_model_digest"])
            if role == "model":
                model_payload = payload
            decoded = decoder(_decode(payload, schema))
            if role == "commit":
                commit = decoded
            else:
                model = decoded
        except (AuthorityCompositionLimit, UnsupportedAuthorityComposition):
            problems.add("UNKNOWN")
            report["reason_codes"].append(role.upper() + "_UNAVAILABLE_OR_UNSUPPORTED")
        except (ValueError, TypeError, KeyError, AttributeError, IndexError):
            problems.add("INVALID")
            report["reason_codes"].append(role.upper() + "_INVALID")
            if role == "model":
                report["model_admission"] = "INVALID"
    if commit is not None:
        entry = next((item for item in commit.census if item.path == selection["authority_model_path"]), None)
        if entry is None or commit.authority_model_path != selection["authority_model_path"] or (
            entry.object_record.object_digest, entry.object_record.artifact_kind,
            entry.object_record.declared_schema_id, entry.object_record.media_type,
        ) != (selection["authority_model_digest"], "authority-model", AUTHORITY_MODEL_SCHEMA, "application/json"):
            problems.add("INVALID")
            report["reason_codes"].append("MODEL_CENSUS_BINDING_INVALID")
        elif model_payload is not None and entry.object_record.size_bytes != len(model_payload):
            problems.add("INVALID")
            report["reason_codes"].append("MODEL_CENSUS_SIZE_INVALID")
        if authority_axiom_agency_digest(commit.authority_axiom_agency) != commit.authority_axiom_agency_digest:
            problems.add("INVALID")
            report["reason_codes"].append("COMMIT_AGENCY_DIGEST_INVALID")
        elif commit.authority_axiom_agency_version != AUTHORITY_AXIOM_AGENCY_VERSION or commit.authority_axiom_agency != AUTHORITY_AXIOM_AGENCY:
            problems.add("UNKNOWN")
            report["reason_codes"].append("COMMIT_AGENCY_UNSUPPORTED")
    report["coordinate_binding"] = "INVALID" if "INVALID" in problems else "UNKNOWN" if problems else "BOUND"
    if model is None or report["coordinate_binding"] != "BOUND":
        return report, None, False
    states = {item.state_id for item in model.states}
    transition_ids = {item.transition_id for item in model.transitions}
    if set(model.state_universe) != states or set(model.transition_universe) != transition_ids or not model.initial_state_ids or not set(model.initial_state_ids) <= states or any(
        item.source_state_id not in states or item.target_state_id not in states for item in model.transitions
    ):
        report["model_admission"] = "INVALID"
        report["reason_codes"].append("MODEL_TOPOLOGY_INVALID")
        return report, None, False
    if (model.authority_axiom_agency_version, model.authority_axiom_agency_digest, model.actor_scope_version, model.actor_scope_digest) != (
        AUTHORITY_AXIOM_AGENCY_VERSION, authority_axiom_agency_digest(), AUTHORITY_ACTOR_SCOPE_VERSION, authority_actor_scope_digest(),
    ) or any(item.actor_scope not in AUTHORITY_ACTOR_SCOPES for item in model.transitions) or any(
        addition.actor_scope not in AUTHORITY_ACTOR_SCOPES for state in model.states for addition in state.local_authority_additions
    ):
        report["reason_codes"].append("MODEL_INTERPRETATION_UNSUPPORTED")
        return report, None, False
    report["model_admission"] = "VALID"
    reachable = set(model.initial_state_ids)
    for _ in range(len(states)):
        after = reachable | {item.target_state_id for item in model.transitions if item.source_state_id in reachable}
        if after == reachable:
            break
        reachable = after
    report["reachable_state_ids"] = sorted(reachable)
    closed = reachable == states and model.closure_status == "CLOSED" and not model.residual_obligations
    if any(not set(AUTHORITY_AXIOM_AGENCY) <= set(state.ground_actions) for state in model.states if state.state_id in reachable):
        report["agency_preservation"] = "VIOLATED"
        report["reason_codes"].append("REACHABLE_GROUND_ACTION_REMOVED")
    elif closed and all(state.ground_actions == AUTHORITY_AXIOM_AGENCY for state in model.states):
        report["agency_preservation"] = "PRESERVED"
    elif any(state.ground_actions != AUTHORITY_AXIOM_AGENCY for state in model.states if state.state_id in reachable):
        report["reason_codes"].append("MODEL_GROUND_EXTENSION_UNSUPPORTED")
    if not closed:
        report["reason_codes"].append("MODEL_CLOSURE_NOT_ESTABLISHED")
    return report, model, closed


def _correspondence(declaration: dict[str, Any], models: list[AuthorityModel | None], reports: list[dict[str, Any]], counts: dict[str, int | None]) -> str:
    # A bad reference into an available bound model is not erased by an absent
    # peer. No reference into an unavailable model is assumed valid or invalid.
    for item in declaration["state_bindings"]:
        if models[-1] is not None and item["composite_state_id"] not in models[-1].state_universe:
            return "INVALID"
        for index, name in enumerate(item["member_state_ids"]):
            if models[index] is not None and name not in models[index].state_universe:
                return "INVALID"
    for item in declaration["transition_bindings"]:
        member = models[item["member_index"]]
        if member is not None and item["member_transition_id"] not in member.transition_universe:
            return "INVALID"
        if models[-1] is not None and item["composite_transition_id"] not in models[-1].transition_universe:
            return "INVALID"
    if any(item["model_admission"] == "INVALID" or item["coordinate_binding"] == "INVALID" for item in reports):
        return "INVALID"
    state_map = {item["composite_state_id"]: tuple(item["member_state_ids"]) for item in declaration["state_bindings"]}
    if models[-1] is not None:
        known_transitions = {item.transition_id: item for item in models[-1].transitions}
        for binding in declaration["transition_bindings"]:
            index = binding["member_index"]
            member = models[index]
            if member is None:
                continue
            native = next(item for item in member.transitions if item.transition_id == binding["member_transition_id"])
            composite_edge = known_transitions[binding["composite_transition_id"]]
            if (native.actor_scope, native.action) != (composite_edge.actor_scope, composite_edge.action):
                return "MISMATCH"
            source = state_map.get(composite_edge.source_state_id)
            target = state_map.get(composite_edge.target_state_id)
            if source is not None and source[index] != native.source_state_id:
                return "MISMATCH"
            if target is not None and target[index] != native.target_state_id:
                return "MISMATCH"
            if source is not None and target is not None and any(source[i] != target[i] for i in range(len(models) - 1) if i != index):
                return "MISMATCH"
    if any(item is None for item in models):
        return "UNKNOWN"
    members, composite = models[:-1], models[-1]
    member_states = [set(item["reachable_state_ids"]) for item in reports[:-1]]
    transitions = {item.transition_id: item for item in composite.transitions}
    member_transitions = [{item.transition_id: item for item in model.transitions} for model in members]
    if any(name not in composite.state_universe or any(coordinate not in members[index].state_universe for index, coordinate in enumerate(coordinates)) for name, coordinates in state_map.items()):
        return "INVALID"
    bindings = declaration["transition_bindings"]
    if any(item["composite_transition_id"] not in transitions or item["member_transition_id"] not in member_transitions[item["member_index"]] for item in bindings):
        return "INVALID"
    product_count = 1
    for names in member_states:
        if product_count > MAX_PRODUCT_STATES // len(names):
            raise AuthorityCompositionLimit("product state limit")
        product_count *= len(names)
    counts["product_states"] = product_count
    generated = 0
    for index, table in enumerate(member_transitions):
        edge_count = sum(item.source_state_id in member_states[index] for item in table.values())
        multiplier = product_count // len(member_states[index])
        if edge_count > (MAX_GENERATED_TRANSITIONS - generated) // multiplier:
            raise AuthorityCompositionLimit("generated transition limit")
        generated += edge_count * multiplier
    counts["generated_transitions"] = generated
    expected_states = set(itertools.product(*(sorted(names) for names in member_states)))
    if set(state_map) != set(composite.state_universe) or set(state_map.values()) != expected_states:
        return "MISMATCH"
    expected_initials = set(itertools.product(*(model.initial_state_ids for model in members)))
    if {state_map[name] for name in composite.initial_state_ids} != expected_initials:
        return "MISMATCH"
    if {item["composite_transition_id"] for item in bindings} != set(transitions):
        return "MISMATCH"
    expected: Counter = Counter()
    for index, table in enumerate(member_transitions):
        for transition in table.values():
            for source in expected_states:
                if source[index] == transition.source_state_id:
                    target = (*source[:index], transition.target_state_id, *source[index + 1:])
                    expected[(index, transition.transition_id, source, target, transition.actor_scope, transition.action)] += 1
    actual: Counter = Counter()
    for binding in bindings:
        transition = transitions[binding["composite_transition_id"]]
        actual[(binding["member_index"], binding["member_transition_id"], state_map[transition.source_state_id], state_map[transition.target_state_id], transition.actor_scope, transition.action)] += 1
    return "MATCHED" if actual == expected else "MISMATCH"


def assess_authority_composition(declaration_bytes: bytes, evidence: dict[str, bytes]) -> dict[str, Any]:
    """Recompute a bounded declared interleaving without promoting silo axes.

Definite bound floor/addition counterexamples survive missing peers or positive
closure limits. Admission stop-loss occurs before any observations; no assertion
is made about unexamined bytes or concurrent atomic capture.
"""
    result: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA, "declaration_digest": None,
        "profile_digest": authority_composition_profile_digest(), "coordinates": None,
        "coordinate_binding": "UNKNOWN", "transition_correspondence": "UNKNOWN",
        "agency_preservation": "UNKNOWN", "local_addition_preservation": "UNKNOWN",
        "model_results": [], "counts": {"product_states": None, "generated_transitions": None},
        "reason_codes": [], "residual_obligations": list(RESIDUAL_OBLIGATIONS),
    }
    try:
        declaration = _declaration(declaration_bytes)
        result["declaration_digest"] = digest_bytes(declaration_bytes)
        result["coordinates"] = {"members": declaration["members"], "composite": declaration["composite"]}
        retained = _capture(evidence)
    except (AuthorityCompositionLimit, UnsupportedAuthorityComposition, RuntimeError):
        result["reason_codes"] = ["INPUT_UNAVAILABLE_UNSUPPORTED_OR_LIMITED"]
        return result
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        result.update(coordinate_binding="INVALID", transition_correspondence="INVALID", reason_codes=["INPUT_INVALID"])
        return result
    models = []
    closed = []
    for index, selection in enumerate((*declaration["members"], declaration["composite"])):
        report, model, complete = _model(selection, retained, index)
        result["model_results"].append(report)
        models.append(model)
        closed.append(complete)
    reports = result["model_results"]
    statuses = {item["coordinate_binding"] for item in reports}
    result["coordinate_binding"] = "INVALID" if "INVALID" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "BOUND"
    reasons: set[str] = set()
    supported = declaration["profile_digest"] == authority_composition_profile_digest()
    if supported:
        try:
            correspondence = _correspondence(declaration, models, reports, result["counts"])
            result["transition_correspondence"] = "UNKNOWN" if correspondence == "MATCHED" and not all(closed) else correspondence
        except AuthorityCompositionLimit:
            reasons.add("COMPOSITION_EXPANSION_LIMIT")
    else:
        reasons.add("COMPOSITION_PROFILE_UNSUPPORTED")
    if any(item["agency_preservation"] == "VIOLATED" for item in reports):
        result["agency_preservation"] = "VIOLATED"
    elif result["transition_correspondence"] == "MATCHED" and all(item["agency_preservation"] == "PRESERVED" for item in reports):
        result["agency_preservation"] = "PRESERVED"
    # Known required additions from an available member can refute a reachable
    # composite state even when another member or positive closure is unavailable.
    if supported and models[-1] is not None:
        required = {addition.canonical_digest() for model, report in zip(models[:-1], reports[:-1]) if model is not None for state in model.states if state.state_id in report["reachable_state_ids"] for addition in state.local_authority_additions if addition.propagation == "COMPOSITION_PRESERVED"}
        composite_states = [state for state in models[-1].states if state.state_id in reports[-1]["reachable_state_ids"]]
        if any(not required <= {addition.canonical_digest() for addition in state.local_authority_additions} for state in composite_states):
            result["local_addition_preservation"] = "VIOLATED"
            reasons.add("REACHABLE_REQUIRED_ADDITION_REMOVED")
        elif result["transition_correspondence"] == "MATCHED":
            result["local_addition_preservation"] = "PRESERVED"
    if result["transition_correspondence"] in {"MISMATCH", "INVALID"}:
        reasons.add("TRANSITION_CORRESPONDENCE_" + result["transition_correspondence"])
    result["reason_codes"] = sorted(reasons | {reason for report in reports for reason in report["reason_codes"]})
    return result

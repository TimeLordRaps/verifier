"""Source-bound consequential composition for Verifier Standard (VSTD).

Terminology: command-line interface (CLI).

This graph is separate from the historical operand dependency graph: influence
and feedback can be cyclic. Its closure establishes reachability of DECLARED
effects, not discovery completeness, runtime containment, or safe execution.
Missing or stale evidence never removes a declared effect from the denominator.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from functools import lru_cache
from typing import Any

from verifier.runtime.namespace_contracts import KindContract, ancestors
from verifier.runtime.namespace_dominance import dominance_intervals, dominates
from verifier.runtime.tier_zero_profile import value_digest


SCHEMA = "verifier-consequence-graph-1"
RELATIONS = {"influences", "embodies", "controls", "actuates", "decides"}
DOMAINS = {"REAL_PHYSICAL", "REAL_FINANCIAL", "SIMULATED"}
FINANCIAL = {"LEDGER", "TRANSACTION", "ASSET", "MARKET"}
ROLE = {"REAL_PHYSICAL": "ROBOT", "REAL_FINANCIAL": "FINBOT"}
AGENT_ROLES = frozenset({"AGENT", "BOT", "ROBOT", "FINBOT"})
EMPTY = {"schema_version": SCHEMA, "edges": [], "effects": []}
_BIND_ACTION = "Bind the exact consequence edges, source evidence and typed endpoints; rerun this object gate."
COMPILED_ROLE_REASON = (
    "The current source-bound consequence graph requires {kind} for {object_id}. "
    "This conservative Tier-0 registry adoption keeps its obligations required; "
    "it does not establish external mechanism, authority, effect, checker PASS, "
    "or Tier-1-plus fulfillment."
)
COMPILED_EFFECT_REASON = (
    "The current reviewed {role} applicability for {object_id} declares its "
    "source-typed endpoint as a potential {domain} external boundary. This "
    "compiler-selected declaration retains {role} obligations; it does not "
    "establish execution, authority, occurrence, runtime correspondence, "
    "confinement, safety, or an external effect."
)
_GENERIC_UNRESOLVED_CLASSIFICATION_REASON = (
    "Migration retains this applicability question. Static ownership alone "
    "cannot refute a "
)
_MAX_INLINE_COMPILED_CLASSIFICATION_REASON_BYTES = 768
_COMPILED_CLASSIFICATION_REASON_PREVIEW_BYTES = 256
_REVIEWED_CORE_ROBOT_EDGES = (
    (
        "verifier-core-self",
        "controls",
        "vstd-hardware-cli-protocol",
        (
            (
                "verifier-core-self",
                "ROBOT",
                "src/verifier/runtime/tier_zero_reasoning/witness_runner.py",
            ),
            (
                "vstd-hardware-cli-protocol",
                "CONTROLLER",
                "src/verifier/runtime/hardware_cli.py",
            ),
        ),
        (
            "The reviewed verifier witness boundary can select package code, and "
            "the exact hardware CLI facade is a source-owned reachable controller. "
            "This declares a possible control dependency only; it does not establish "
            "selection, execution, authority, occurrence, confinement, or a physical effect."
        ),
    ),
    (
        "vstd-hardware-cli-protocol",
        "actuates",
        "vstd-accelerator-discovery-command",
        (
            (
                "vstd-hardware-cli-protocol",
                "CONTROLLER",
                "src/verifier/runtime/hardware_cli.py",
            ),
            (
                "vstd-accelerator-discovery-command",
                "ACTUATOR",
                "src/verifier/runtime/hardware_discovery_cli.py",
            ),
        ),
        (
            "The hardware CLI facade directly dispatches its discover subcommand "
            "to the accelerator discovery mechanism, whose selected vendor adapter "
            "may cross a PATH-resolved executable boundary. This declares that "
            "source-owned command path only; it does not establish a device, "
            "execution, authority, occurrence, or physical effect."
        ),
    ),
)


def compiled_role_reason(object_id: str, kind: str) -> str:
    """Return the exact marker for a role compiled from whole-graph consequences."""

    return COMPILED_ROLE_REASON.format(object_id=object_id, kind=kind)


def compiled_classification_reason(status: str, reason: str) -> str:
    """Return the sole digest-bound compact projection of one source rationale."""

    if (
        status == "UNRESOLVED"
        and reason.startswith(_GENERIC_UNRESOLVED_CLASSIFICATION_REASON)
    ):
        return "UNRESOLVED."
    if (
        status not in {"APPLIES", "DOES_NOT_APPLY"}
        or len(reason.encode("utf-8"))
        <= _MAX_INLINE_COMPILED_CLASSIFICATION_REASON_BYTES
    ):
        return reason
    preview = reason.encode("utf-8")[
        :_COMPILED_CLASSIFICATION_REASON_PREVIEW_BYTES
    ].decode("utf-8", errors="ignore").rstrip()
    return preview + " ... [full rationale " + value_digest(reason) + "]"


def compiled_effect_reason(object_id: str, domain: str) -> str:
    """Return the exact non-operational boundary declaration for one endpoint."""

    return COMPILED_EFFECT_REASON.format(
        object_id=object_id, domain=domain, role=ROLE[domain]
    )


def _compile_reviewed_edges(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compile one exact source-reviewed package control route when fully bound.

    The route is atomic: a missing object, governing HARNESS operand, reviewed
    role, or exact evidence path emits no partial edge.  Its declaration binds
    source reachability only; the consequence assessment continues to withhold
    runtime correspondence, occurrence, authority, confinement, and safety.
    """

    by_id = {row.get("object_id"): row for row in rows if type(row) is dict}
    if len(by_id) != len(rows):
        return []
    core = by_id.get("verifier-core-self")
    harness = by_id.get("vstd-harness")
    if (
        type(core) is not dict
        or type(harness) is not dict
        or core.get("operands", {}).get("harness") != ["vstd-harness"]
        or harness.get("kind") != "HARNESS"
    ):
        return []

    result: list[dict[str, Any]] = []
    for source, relation, target, supports, reason in _REVIEWED_CORE_ROBOT_EDGES:
        if source not in by_id or target not in by_id:
            return []
        evidence = []
        for object_id, role, path in supports:
            row = by_id.get(object_id)
            decision = (
                row.get("classification", {}).get(role)
                if type(row) is dict
                else None
            )
            if (
                type(decision) is not dict
                or decision.get("status") != "APPLIES"
                or is_nonstructural_role_decision(object_id, role, decision)
                or type(decision.get("evidence")) is not list
            ):
                return []
            matches = [
                reference
                for reference in decision["evidence"]
                if type(reference) is dict and reference.get("path") == path
            ]
            if len(matches) != 1:
                return []
            evidence.append(deepcopy(matches[0]))
        result.append(
            {
                "source": source,
                "relation": relation,
                "target": target,
                "reason": reason,
                "evidence": sorted(evidence, key=lambda reference: reference["path"]),
            }
        )
    return result


def _reviewed_control_endpoint_effect(
    rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the exact physical boundary selected by the reviewed core route.

    The endpoint's ROBOT decision is demand-only: it keeps ROBOT obligations
    live without turning the command into an AGENT.  The independently reviewed
    controls/actuates route plus the endpoint's source-established ACTUATOR
    decision supplies the structural type.  Both decisions must bind the same
    exact endpoint bytes, so neither prose nor a generic retained role can
    manufacture an effect.
    """

    if not _compile_reviewed_edges(rows):
        return None
    by_id = {row.get("object_id"): row for row in rows if type(row) is dict}
    endpoint_id = "vstd-accelerator-discovery-command"
    endpoint = by_id.get(endpoint_id)
    if type(endpoint) is not dict:
        return None
    actuator = endpoint.get("classification", {}).get("ACTUATOR")
    robot = endpoint.get("classification", {}).get("ROBOT")
    if (
        type(actuator) is not dict
        or actuator.get("status") != "APPLIES"
        or is_nonstructural_role_decision(endpoint_id, "ACTUATOR", actuator)
        or type(robot) is not dict
        or robot.get("status") != "APPLIES"
        or not is_nonstructural_role_decision(endpoint_id, "ROBOT", robot)
        or type(actuator.get("evidence")) is not list
        or type(robot.get("evidence")) is not list
        or actuator["evidence"] != robot["evidence"]
        or len(robot["evidence"]) != 1
        or robot["evidence"][0].get("path")
        != "src/verifier/runtime/hardware_discovery_cli.py"
    ):
        return None
    return {
        "object_id": endpoint_id,
        "domain": "REAL_PHYSICAL",
        "reason": compiled_effect_reason(endpoint_id, "REAL_PHYSICAL"),
        "evidence": deepcopy(robot["evidence"]),
    }


def is_compiled_role_decision(object_id: str, kind: str, decision: Any) -> bool:
    """Recognize only this compiler's exact additive-role adoption record."""

    return (
        type(decision) is dict
        and decision.get("status") == "APPLIES"
        and decision.get("reason") == compiled_role_reason(object_id, kind)
    )


@lru_cache(maxsize=1)
def _obligation_retention_reasons() -> frozenset[tuple[str, str, str]]:
    """Return exact catalog decisions that retain demand without role evidence.

    These records originate in the sole authored reasons.vstd inputs.  They
    intentionally add obligations while making no source-mechanism, structural
    role, or external-effect claim.  Importing lazily keeps the lower-level
    consequence module independent while binding recognition to the catalogs
    that authored each exact decision.
    """

    from verifier.runtime import package_original_kind_catalog_retained
    from verifier.runtime import package_original_kind_catalog_runtime
    from verifier.runtime import package_original_review_people
    from verifier.runtime import package_semantic_ownership_domains_agency_collective
    from verifier.runtime import package_semantic_review_commands
    from verifier.runtime import package_semantic_review_hardware_cli
    from verifier.runtime import package_semantic_review_partitions
    from verifier.runtime import package_semantic_review_verifier

    retained: set[tuple[str, str, str]] = set()
    agency = package_semantic_ownership_domains_agency_collective
    retained.update(
        (object_id, kind, agency.obligation_retention_reason(object_id, kind))
        for object_id, kinds in agency.OBLIGATION_RETENTION_APPLIES.items()
        for kind in kinds
    )

    runtime = package_original_kind_catalog_runtime
    runtime_profile = runtime.RUNTIME_PARTIAL_PROFILE
    runtime_assignments = {
        row.object_id: row for row in runtime_profile.assignments
    }
    for object_id, kind in runtime.OBLIGATION_RETENTION_BEHAVIORAL_CELLS:
        assignment = runtime_assignments[object_id]
        decision = next(row for row in assignment.decisions if row.kind == kind)
        retained.add(
            (
                object_id,
                kind,
                "Audited original-kind profile "
                + runtime_profile.profile_id
                + " revision "
                + str(runtime_profile.revision)
                + " ("
                + runtime_profile.canonical_digest
                + ") binds this object and exact owned source set. "
                + assignment.scope_reason
                + " "
                + decision.reason,
            )
        )

    for review_module in (
        package_original_review_people,
        package_semantic_review_commands,
        package_semantic_review_hardware_cli,
        package_semantic_review_partitions,
        package_semantic_review_verifier,
    ):
        retained.update(
            (
                object_id,
                kind,
                review_module.obligation_retention_reason(object_id, kind),
            )
            for object_id, kinds in review_module.OBLIGATION_RETENTION_APPLIES.items()
            for kind in kinds
        )

    catalog = package_original_kind_catalog_retained
    profile = catalog.RETAINED_PARTIAL_PROFILE
    assignments = {row.object_id: row for row in profile.assignments}
    boundaries = catalog._OBLIGATION_RETENTION_BOUNDARIES
    reason_only = catalog._REASON_ONLY_OBLIGATION_RETENTION
    for audit in catalog.RETAINED_ORIGINAL_KIND_AUDITS:
        boundary = boundaries.get(audit.object_id)
        for question in audit.questions:
            is_reason_only = question.kind in reason_only.get(audit.object_id, ())
            is_boundary_retention = (
                boundary is not None
                and question.path == audit.expected_owned_paths[boundary[0]]
                and question.line == boundary[1]
                and "sole reasons.vstd" in question.reason
                and "retain" in question.reason
            )
            if question.status != "APPLIES" or not (
                is_reason_only or is_boundary_retention
            ):
                continue
            assignment = assignments[audit.object_id]
            decision = next(
                row for row in assignment.decisions if row.kind == question.kind
            )
            reason = (
                "Audited original-kind profile "
                + profile.profile_id
                + " revision "
                + str(profile.revision)
                + " ("
                + profile.canonical_digest
                + ") binds this object and exact owned source set. "
                + assignment.scope_reason
                + " "
                + decision.reason
            )
            retained.add((audit.object_id, question.kind, reason))
    # ``objects.vstd`` is a compiled registry. Long source-review rationales are
    # represented there by one deterministic readable-prefix-plus-digest form.
    # Recognize that exact projection as the same demand-only decision while
    # retaining the full source rationale for predecessor manifests. An altered
    # prefix or digest remains structural and therefore fail-closed.
    retained.update(
        (
            object_id,
            kind,
            compiled_classification_reason("APPLIES", reason),
        )
        for object_id, kind, reason in tuple(retained)
    )
    return frozenset(retained)


def is_nonstructural_role_decision(
    object_id: str, kind: str, decision: Any
) -> bool:
    """Recognize exact demand-retention records that cannot prove a role."""

    return (
        is_compiled_role_decision(object_id, kind, decision)
        or (
            type(decision) is dict
            and decision.get("status") == "APPLIES"
            and (object_id, kind, decision.get("reason"))
            in _obligation_retention_reasons()
        )
    )


def nonstructural_role_binding(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Materialize exact role-evidence semantics for the Node interpreter.

    This is compiled from selected manifest decisions and the same exact
    catalog identities used above.  It contains no derived requirements or
    effects.  The independent interpreter rebinds every entry to the current
    decision digest, so stale or substituted prose cannot inherit this type.
    """

    result = []
    for row in rows:
        object_id = row["object_id"]
        for kind, decision in row["classification"].items():
            if is_nonstructural_role_decision(object_id, kind, decision):
                result.append(
                    {
                        "decision_digest": value_digest(decision),
                        "kind": kind,
                        "object_id": object_id,
                    }
                )
    return sorted(result, key=lambda item: (item["object_id"], item["kind"]))


def validate_graph(graph: Any, identifiers: set[str]) -> None:
    """Admit an exact bounded declaration; do not interpret arbitrary payloads."""
    from verifier.runtime.namespace_manifest import _binding, require
    require(type(graph) is dict and set(graph) == {"schema_version", "edges", "effects"},
            "NAMESPACE_CONSEQUENCE_FIELDS")
    require(graph["schema_version"] == SCHEMA, "NAMESPACE_CONSEQUENCE_VERSION")
    require(type(graph["edges"]) is list and len(graph["edges"]) <= 16384
            and type(graph["effects"]) is list and len(graph["effects"]) <= 8192,
            "NAMESPACE_CONSEQUENCE_CAPACITY")
    for category, fields in (("edges", {"source", "target", "relation"}),
                             ("effects", {"object_id", "domain"})):
        seen = set()
        for record in graph[category]:
            require(type(record) is dict and set(record) == fields | {"reason", "evidence"},
                    "NAMESPACE_CONSEQUENCE_RECORD_FIELDS")
            require(_binding({key: record[key] for key in ("reason", "evidence")}),
                    "NAMESPACE_CONSEQUENCE_BINDING_INVALID")
            require(all(isinstance(record[key], str) for key in fields),
                    "NAMESPACE_CONSEQUENCE_RECORD_INVALID")
            if category == "edges":
                require(record["source"] in identifiers and record["target"] in identifiers,
                        "NAMESPACE_CONSEQUENCE_REFERENCE_UNBOUND")
                require(record["relation"] in RELATIONS, "NAMESPACE_CONSEQUENCE_RELATION_INVALID")
                key = (record["source"], record["relation"], record["target"])
                code = "NAMESPACE_CONSEQUENCE_EDGE_DUPLICATED"
            else:
                require(record["object_id"] in identifiers, "NAMESPACE_CONSEQUENCE_REFERENCE_UNBOUND")
                require(record["domain"] in DOMAINS, "NAMESPACE_CONSEQUENCE_DOMAIN_INVALID")
                key = (record["object_id"], record["domain"])
                code = "NAMESPACE_CONSEQUENCE_EFFECT_DUPLICATED"
            require(key not in seen, code)
            seen.add(key)


def _label_sets(rows: list[dict[str, Any]], registry: dict[str, KindContract],
                observed: dict[str, Any]) -> tuple[dict[str, set[str]],
                                                    dict[str, set[str]]]:
    """Separate obligation demand from evidence of a structural role."""
    surfaces = {item["surface_id"]: item for item in observed["surfaces"]}
    demanded: dict[str, set[str]] = {}
    structural: dict[str, set[str]] = {}
    for row in rows:
        # An unregistered label contributes no ancestors: never fall back to OBJECT.
        # assess_consequences reports every such label as a refutation.
        identifier = row["object_id"]
        declared = {
            label for label in (row["kind"], *row["specializations"])
            if label in registry
        }
        source = {
            kind for surface in row["surfaces"] if surface in surfaces
            for kind in surfaces[surface]["source_kinds"] if kind in registry
        }
        retained = {
            kind for kind, decision in row["classification"].items()
            if kind in registry
            and is_nonstructural_role_decision(identifier, kind, decision)
        }
        reviewed = {
            kind for kind, decision in row["classification"].items()
            if decision["status"] == "APPLIES" and kind in registry
            and kind not in retained
        }
        # Retained labels remain in the demanded denominator.  They are removed
        # only from structural evidence unless independently established by the
        # primary kind or a current source surface.
        structural_labels = {row["kind"]} | source | (
            set(row["specializations"]) - retained
        ) | reviewed
        applicable = declared | source | reviewed | retained
        structural[identifier] = {
            kind for label in structural_labels if label in registry
            for kind in ancestors(registry, label)
        }
        demanded[identifier] = {
            kind for label in applicable for kind in ancestors(registry, label)
        }
    return demanded, structural


def _derive_state(rows: list[dict[str, Any]], registry: dict[str, KindContract],
                  observed: dict[str, Any], graph: dict[str, Any]
                  ) -> tuple[dict[str, Any], dict[str, set[str]],
                             dict[str, set[str]], dict[str, set[str]],
                             dict[str, set[str]]]:
    by_id = {row["object_id"]: row for row in rows}
    demanded, structural_base = _label_sets(rows, registry, observed)
    implied: dict[str, set[str]] = {
        identifier: set() for identifier in structural_base
    }
    edges = {(edge["source"], edge["relation"], edge["target"]) for edge in graph["edges"]}
    for row in rows:
        # Only a native/source BOT receives its operand-defined embodiment.
        # A root-role APPLIES answer still demands BOT obligations, but cannot
        # invent this structural edge.
        if "BOT" in structural_base[row["object_id"]]:
            edges.update((row["object_id"], "embodies", target)
                         for target in row["operands"].get("agent", [])
                         if target in structural_base)
    for source, relation, target in edges:
        if relation == "embodies":
            implied[target].add("AGENT")
        elif relation == "controls":
            implied[source].add("AGENT")
            implied[target].add("CONTROLLER")
        elif relation == "actuates":
            implied[source].add("CONTROLLER")
            implied[target].add("ACTUATOR")
        elif relation == "decides":
            implied[source].add("AGENT")
    structural = {
        identifier: structural_base[identifier] | implied[identifier]
        for identifier in structural_base
    }
    # Consequential roles come from typed, relation-bound endpoints as well as
    # explicit effect labels.  A repository may add SIMULATED context, but it
    # cannot use that mutable label to erase an ACTUATOR or financial route.
    agency = {identifier for identifier in structural
              if structural[identifier] & AGENT_ROLES}
    controlled = {
        target for source, relation, target in edges
        if relation == "controls" and source in agency
        and "CONTROLLER" in structural[target]
    }
    typed_physical = {
        target for source, relation, target in edges
        if relation == "actuates" and source in controlled
        and "ACTUATOR" in structural[target]
    }
    financial_forward: dict[str, set[str]] = {
        identifier: set() for identifier in structural_base
    }
    for source, relation, target in edges:
        if relation in {"embodies", "influences", "decides", "controls"}:
            financial_forward[source].add(target)
    financial_reachable = set(agency)
    pending = deque(sorted(agency))
    while pending:
        for target in sorted(financial_forward[pending.popleft()]):
            if target not in financial_reachable:
                financial_reachable.add(target)
                pending.append(target)
    typed_financial = {
        identifier for identifier in financial_reachable
        if structural[identifier] & FINANCIAL
        and not is_nonstructural_role_decision(
            identifier,
            "FINBOT",
            by_id[identifier].get("classification", {}).get("FINBOT"),
        )
    }
    endpoint_domains = {
        "REAL_PHYSICAL": typed_physical | {
            effect["object_id"] for effect in graph["effects"]
            if effect["domain"] == "REAL_PHYSICAL"
        },
        "REAL_FINANCIAL": typed_financial | {
            effect["object_id"] for effect in graph["effects"]
            if effect["domain"] == "REAL_FINANCIAL"
        },
    }
    reverse: dict[str, set[str]] = {
        identifier: set() for identifier in structural_base
    }
    for source, _, target in edges:
        reverse[target].add(source)
    reach: dict[str, dict[str, Any]] = {
        identifier: {} for identifier in structural_base
    }
    for domain in ROLE:
        endpoints = sorted(endpoint_domains[domain])
        pending = deque(endpoints)
        seen = set(endpoints)
        for endpoint in endpoints:
            reach[endpoint][domain] = {"effect_object_id": endpoint, "next_object_id": None}
        while pending:
            target = pending.popleft()
            for source in sorted(reverse[target]):
                if source not in seen:
                    seen.add(source)
                    pending.append(source)
                    reach[source][domain] = {"effect_object_id": reach[target][domain]["effect_object_id"],
                                             "next_object_id": target}
        for identifier in seen:
            # Demand-only AGENT/BOT decisions must retain the consequence
            # obligations reached by explicit graph edges without becoming
            # structural role evidence. A demand-only ROBOT/FINBOT endpoint is
            # not itself an agent. Using only ``structural`` here erased the
            # downstream roles for a compiler-retained BOT; implicit
            # embodiment and typed endpoint inference above remain
            # structural-only.
            if (
                structural[identifier] & AGENT_ROLES
                or (
                    demanded[identifier] & {"AGENT", "BOT"}
                    and reach[identifier][domain]["next_object_id"] is not None
                )
            ):
                implied[identifier].add(ROLE[domain])
    derived = {"graph_digest": value_digest(graph),
        "required_kinds": {
            identifier: sorted(implied[identifier] - demanded[identifier])
            for identifier in sorted(demanded)
            if implied[identifier] - demanded[identifier]
        },
        "reachable_effects": {
            identifier: reach[identifier]
            for identifier in sorted(reach) if reach[identifier]
        }}
    typed = {"REAL_PHYSICAL": typed_physical, "REAL_FINANCIAL": typed_financial}
    return derived, demanded, structural, endpoint_domains, typed


def compile_reviewed_effect_graph(
    rows: list[dict[str, Any]],
    registry: dict[str, KindContract],
    observed: dict[str, Any],
) -> dict[str, Any]:
    """Compile explicit effect declarations from reviewed applicable roles.

    The source-typed endpoint computation runs against ``EMPTY`` so a stored
    declaration cannot create its own denominator.  Every selected endpoint
    contributes only when it already carries an explicit,
    current-evidence-capable ``APPLIES`` answer for the matching ROBOT or FINBOT
    role.  This compiler's own retained-role marker is not an independent
    review and cannot recursively manufacture an effect declaration.  An
    unreviewed endpoint remains absent so ``assess_consequences`` reports its
    typed-effect obligation as UNKNOWN.  Selected evidence is retained exactly;
    no generic kind label, prose absence claim, execution, authority,
    occurrence, confinement, safety, or actual external effect is inferred.
    """

    by_id = {row["object_id"]: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("NAMESPACE_COMPILED_EFFECT_OBJECT_DUPLICATED")
    edges = _compile_reviewed_edges(rows)
    seed = {"schema_version": SCHEMA, "edges": deepcopy(edges), "effects": []}
    _, _, _, _, typed = _derive_state(rows, registry, observed, seed)
    reviewed_endpoint_effect = _reviewed_control_endpoint_effect(rows)
    effects: list[dict[str, Any]] = []
    for domain in sorted(ROLE):
        role = ROLE[domain]
        for object_id in sorted(typed[domain]):
            decision = by_id[object_id].get("classification", {}).get(role)
            selected_reviewed_endpoint = (
                reviewed_endpoint_effect is not None
                and reviewed_endpoint_effect["object_id"] == object_id
                and reviewed_endpoint_effect["domain"] == domain
            )
            if (
                type(decision) is not dict
                or decision.get("status") != "APPLIES"
                or (
                    is_nonstructural_role_decision(object_id, role, decision)
                    and not selected_reviewed_endpoint
                )
            ):
                continue
            if selected_reviewed_endpoint:
                effects.append(deepcopy(reviewed_endpoint_effect))
                continue
            evidence = decision.get("evidence")
            if type(evidence) is not list or not evidence:
                continue
            effects.append(
                {
                    "object_id": object_id,
                    "domain": domain,
                    "reason": compiled_effect_reason(object_id, domain),
                    "evidence": deepcopy(evidence),
                }
            )
    graph = {"schema_version": SCHEMA, "edges": edges, "effects": effects}
    validate_graph(graph, set(by_id))
    return graph


def _matches_compiled_effect_graph(
    graph: Any,
    rows: list[dict[str, Any]],
    *,
    allow_nonstructural_roles: bool,
    expected_edges: list[dict[str, Any]],
) -> bool:
    """Recognize one exact compiler projection under an explicit role policy."""

    if (
        type(graph) is not dict
        or set(graph) != {"schema_version", "edges", "effects"}
        or graph.get("schema_version") != SCHEMA
        or graph.get("edges") != expected_edges
        or type(graph.get("effects")) is not list
        or not graph["effects"]
    ):
        return False
    by_id = {
        row.get("object_id"): row
        for row in rows
        if type(row) is dict and isinstance(row.get("object_id"), str)
    }
    reviewed_endpoint_effect = _reviewed_control_endpoint_effect(rows)
    identities: list[tuple[str, str]] = []
    for effect in graph["effects"]:
        if (
            type(effect) is not dict
            or set(effect) != {"object_id", "domain", "reason", "evidence"}
            or effect.get("domain") not in ROLE
            or effect.get("object_id") not in by_id
            or effect.get("reason")
            != compiled_effect_reason(effect["object_id"], effect["domain"])
        ):
            return False
        decision = by_id[effect["object_id"]].get("classification", {}).get(
            ROLE[effect["domain"]]
        )
        if (
            type(decision) is not dict
            or decision.get("status") != "APPLIES"
            or (
                not allow_nonstructural_roles
                and is_nonstructural_role_decision(
                    effect["object_id"], ROLE[effect["domain"]], decision
                )
                and effect != reviewed_endpoint_effect
            )
            or type(decision.get("evidence")) is not list
            or not decision["evidence"]
            or effect.get("evidence") != decision["evidence"]
        ):
            return False
        identities.append((effect["domain"], effect["object_id"]))
    return identities == sorted(set(identities))


def is_compiled_effect_graph(graph: Any, rows: list[dict[str, Any]]) -> bool:
    """Recognize only the current exact reviewed-effect projection shape."""

    return _matches_compiled_effect_graph(
        graph,
        rows,
        allow_nonstructural_roles=False,
        expected_edges=_compile_reviewed_edges(rows),
    )


def is_pre_reviewed_control_compiled_effect_graph(
    graph: Any, rows: list[dict[str, Any]]
) -> bool:
    """Recognize the exact edge-empty predecessor of the current compiler."""

    return bool(_compile_reviewed_edges(rows)) and _matches_compiled_effect_graph(
        graph,
        rows,
        allow_nonstructural_roles=False,
        expected_edges=[],
    )


def is_legacy_compiled_effect_graph(graph: Any, rows: list[dict[str, Any]]) -> bool:
    """Recognize the exact prior projection only when it contains the old bug.

    This is migration evidence, never current selection authority.  The legacy
    compiler used the same exact effect reasons and selected evidence but
    allowed a reasons-only retention role to manufacture an effect.
    """

    if not _matches_compiled_effect_graph(
        graph,
        rows,
        allow_nonstructural_roles=True,
        expected_edges=_compile_reviewed_edges(rows),
    ):
        return False
    by_id = {row["object_id"]: row for row in rows}
    reviewed_endpoint_effect = _reviewed_control_endpoint_effect(rows)
    return any(
        is_nonstructural_role_decision(
            effect["object_id"],
            ROLE[effect["domain"]],
            by_id[effect["object_id"]]["classification"][ROLE[effect["domain"]]],
        )
        and effect != reviewed_endpoint_effect
        for effect in graph["effects"]
    )


def is_exact_reviewed_control_path_addition(
    before: Any,
    after: Any,
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
) -> bool:
    """Admit only the compiler's exact two-edge, one-effect route addition."""

    if not (
        is_pre_reviewed_control_compiled_effect_graph(before, before_rows)
        and is_compiled_effect_graph(after, after_rows)
    ):
        return False

    added_identity = (
        "vstd-accelerator-discovery-command",
        "REAL_PHYSICAL",
    )

    def identity(effect: dict[str, Any]) -> tuple[str, str]:
        return effect["object_id"], effect["domain"]

    prior = {identity(effect): effect for effect in before["effects"]}
    current = {identity(effect): effect for effect in after["effects"]}
    return (
        set(current) - set(prior) == {added_identity}
        and set(prior) == set(current) - {added_identity}
        and all(current[key] == effect for key, effect in prior.items())
        and current[added_identity]["reason"]
        == compiled_effect_reason(*added_identity)
    )


def is_exact_retention_prune(
    before: Any,
    after: Any,
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
) -> bool:
    """Admit only removal of effects generated from exact retention decisions."""

    if not (
        is_legacy_compiled_effect_graph(before, before_rows)
        and is_compiled_effect_graph(after, after_rows)
    ):
        return False
    before_by_id = {row["object_id"]: row for row in before_rows}
    after_by_id = {row["object_id"]: row for row in after_rows}
    prior_reviewed_endpoint = _reviewed_control_endpoint_effect(before_rows)
    next_reviewed_endpoint = _reviewed_control_endpoint_effect(after_rows)

    def identity(effect: dict[str, Any]) -> tuple[Any, ...]:
        return (
            effect["object_id"],
            effect["domain"],
            effect["reason"],
            tuple(reference.get("path") for reference in effect["evidence"]),
        )

    retained: list[tuple[Any, ...]] = []
    removed = 0
    for effect in before["effects"]:
        object_id = effect["object_id"]
        domain = effect["domain"]
        role = ROLE[domain]
        prior_row = before_by_id.get(object_id)
        next_row = after_by_id.get(object_id)
        prior_decision = (
            prior_row.get("classification", {}).get(role)
            if type(prior_row) is dict else None
        )
        next_decision = (
            next_row.get("classification", {}).get(role)
            if type(next_row) is dict else None
        )
        if (
            effect == prior_reviewed_endpoint
            and next_reviewed_endpoint is not None
        ):
            retained.append(identity(effect))
            continue
        if (
            is_nonstructural_role_decision(object_id, role, prior_decision)
            and is_nonstructural_role_decision(object_id, role, next_decision)
        ):
            removed += 1
        else:
            retained.append(identity(effect))
    return removed > 0 and [identity(effect) for effect in after["effects"]] == retained


def derive_consequences(rows: list[dict[str, Any]], registry: dict[str, KindContract],
                        observed: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Derive additive types and two-domain reachability in linear graph work.

    One reverse search per real-effect domain visits each vertex/edge at most
    once. A compact next-hop witness avoids enumerating exponentially many paths
    or copying a quadratic collection of full paths. Cycles cannot erase effects.
    """
    return _derive_state(rows, registry, observed, graph)[0]


def assess_consequences(rows: list[dict[str, Any]], registry: dict[str, KindContract],
                        observed: dict[str, Any], graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check evidence freshness and actual declared agency/control dependencies."""
    from verifier.runtime.namespace_classification import binding_status, finding
    graph = EMPTY if graph is None else graph
    by_id = {row["object_id"]: row for row in rows}
    validate_graph(graph, set(by_id))
    derived, demanded, structural, endpoint_domains, typed_endpoints = _derive_state(
        rows, registry, observed, graph)
    for identifier, kinds in derived["required_kinds"].items():
        demanded[identifier].update(kinds)
    findings = []

    def problem(identifier: str, code: str, reason: str, *, status: str = "UNKNOWN",
                obligation_id: str | None = None, action: str = _BIND_ACTION) -> None:
        findings.append(finding(code, status, "VSTD-T0.3", reason, action,
            object_id=identifier, obligation_id=obligation_id))

    # An unregistered label is a refuted declaration, not unknown applicability.
    # Its roles cannot be derived, so the gate must not PASS on the remainder.
    for row in rows:
        labels = [row["kind"], *row["specializations"],
                  *(kind for kind, decision in row["classification"].items() if decision["status"] == "APPLIES")]
        for label in sorted({label for label in labels if label not in registry}):
            problem(row["object_id"], "NAMESPACE_CONSEQUENCE_KIND_UNREGISTERED",
                f"{label} is not a registered kind, so this object's roles cannot be derived from it.",
                status="FAIL", action="Replace the label with a registered kind or remove it, then rerun this object gate.")

    # Each record needs source support from its participating objects. This binds
    # authorship scope, not the truth of the described edge or effect.
    surfaces = {item["surface_id"]: item["path"] for item in observed["surfaces"]}
    files = {item["path"]: item["sha256"] for item in observed["census"]["files"]}
    for record in [*graph["edges"], *graph["effects"]]:
        participants = [record["source"], record["target"]] if "source" in record else [record["object_id"]]
        owned = {surfaces[surface] for identifier in participants for surface in by_id[identifier]["surfaces"]
                 if surface in surfaces}
        status, reason = binding_status(record, files, owned)
        if status != "PASS":
            problem(participants[0], "NAMESPACE_CONSEQUENCE_EVIDENCE_UNRESOLVED", reason, status=status)
    outgoing: dict[tuple[str, str], set[str]] = {}
    for edge in graph["edges"]:
        outgoing.setdefault((edge["source"], edge["relation"]), set()).add(edge["target"])
        if edge["relation"] == "decides" and not structural[edge["target"]] & FINANCIAL:
            problem(edge["target"], "NAMESPACE_FINANCIAL_OBJECT_KIND_UNRESOLVED",
                "A decision dependency needs the applicable LEDGER, TRANSACTION, ASSET or MARKET representation.")
    physical = endpoint_domains["REAL_PHYSICAL"]
    financial = endpoint_domains["REAL_FINANCIAL"]

    # A declared or typed external endpoint needs a governed agent path.
    # Otherwise omitting a controls or actuates edge could silently remove the
    # ROBOT or FINBOT requirement. Such a partial route stays UNKNOWN.
    forward: dict[str, set[str]] = {identifier: set() for identifier in by_id}
    for edge in graph["edges"]:
        forward[edge["source"]].add(edge["target"])
    for row in rows:
        if "BOT" in structural[row["object_id"]]:
            forward[row["object_id"]].update(target for target in row["operands"].get("agent", []) if target in by_id)
    attributed = {identifier for identifier in by_id if demanded[identifier] & AGENT_ROLES}
    pending = deque(attributed)
    while pending:
        for target in forward[pending.popleft()]:
            if target not in attributed:
                attributed.add(target)
                pending.append(target)

    effect_domains: dict[str, set[str]] = {identifier: set() for identifier in by_id}
    for effect in graph["effects"]:
        effect_domains[effect["object_id"]].add(effect["domain"])
    endpoint_contracts = {
        "REAL_PHYSICAL": ("ROBOT", "controls/actuates",
                          "ROBOT-0.1-agent-to-actuator-binding"),
        "REAL_FINANCIAL": ("FINBOT", "consequential influence/control",
                           "FINBOT-0.1-agent-and-financial-authority"),
    }
    for domain, endpoints in typed_endpoints.items():
        role, relation, obligation = endpoint_contracts[domain]
        for identifier in sorted(endpoints):
            declared = effect_domains[identifier]
            if domain in declared:
                continue
            actual = ", ".join(sorted(structural[identifier] & ({"ACTUATOR"} if role == "ROBOT" else FINANCIAL)))
            if declared:
                labels = ", ".join(sorted(declared))
                problem(identifier, "NAMESPACE_EFFECT_DOMAIN_CONTRADICTS_TYPED_ENDPOINT",
                    f"{labels} effect label on typed {actual} endpoint {identifier} contradicts its source-bound "
                    f"{relation} path; simulation context cannot erase {role} consequences.",
                    status="FAIL", obligation_id=obligation,
                    action=f"Declare {domain} alongside any SIMULATED context for this typed endpoint; "
                           f"keep {role} obligations required and rerun this object gate.")
            else:
                problem(identifier, "NAMESPACE_TYPED_ENDPOINT_EFFECT_UNRESOLVED",
                    f"Typed {actual} endpoint {identifier} is reached by a source-bound {relation} path, "
                    f"but no {domain} effect declaration binds its external boundary; {role} applicability remains required.",
                    obligation_id=obligation,
                    action=f"Bind the endpoint's {domain} effect evidence; keep {role} obligations required "
                           "and rerun this object gate.")

    # A typed simulated endpoint reached only through the wrong relation is not
    # promoted to ROBOT or FINBOT, but the unresolved route cannot pass as inert.
    for effect in graph["effects"]:
        if effect["domain"] != "SIMULATED" or effect["object_id"] not in attributed:
            continue
        identifier = effect["object_id"]
        candidates = []
        if "ACTUATOR" in structural[identifier] and identifier not in typed_endpoints["REAL_PHYSICAL"]:
            candidates.append(("ROBOT", "controls/actuates", "ROBOT-0.1-agent-to-actuator-binding"))
        if structural[identifier] & FINANCIAL and identifier not in typed_endpoints["REAL_FINANCIAL"]:
            candidates.append(("FINBOT", "consequential influence/control",
                               "FINBOT-0.1-agent-and-financial-authority"))
        for role, relation, obligation in candidates:
            problem(identifier, "NAMESPACE_TYPED_ENDPOINT_REACHABILITY_UNRESOLVED",
                f"SIMULATED effect on typed endpoint {identifier} is agent-reachable, but the declared path lacks "
                f"the {relation} relation required to decide {role} applicability.",
                obligation_id=obligation,
                action=f"Bind the exact {relation} path or remove the unestablished reachability; "
                       f"keep {role} applicability UNKNOWN and rerun this object gate.")
    for effect in graph["effects"]:
        identifier = effect["object_id"]
        if effect["domain"] in ROLE and identifier not in attributed:
            problem(identifier, "NAMESPACE_EFFECT_UNATTRIBUTED",
                f"{effect['domain']} effect on {identifier} ({', '.join(sorted(structural[identifier]))}) "
                "is reached by no AGENT, BOT, ROBOT or FINBOT path; it has no bound governing agent.",
                action="Declare the governing AGENT and the controls/actuates or influences/decides path that reaches this endpoint, then rerun this object gate.")

    # A wrapper's good agent path cannot discharge its other effect paths. In
    # each reversed domain graph, that same agent must dominate the wrapper.
    # Compute two trees once, not one whole-graph cut per wrapper or path.
    reverse_effects: dict[str, set[str]] = {identifier: set() for identifier in by_id}
    for edge in graph["edges"]:
        reverse_effects[edge["target"]].add(edge["source"])
    for row in rows:
        if "BOT" in structural[row["object_id"]]:
            for target in row["operands"].get("agent", []):
                if target in reverse_effects:
                    reverse_effects[target].add(row["object_id"])
    dominance = {"ROBOT": dominance_intervals(reverse_effects, physical),
                 "FINBOT": dominance_intervals(reverse_effects, financial)}
    agency_obligations = {"ROBOT": "ROBOT-0.1-agent-to-actuator-binding",
                          "FINBOT": "FINBOT-0.1-agent-and-financial-authority"}

    def bypassing(cut_relation: str) -> set[str]:
        # Remove the required relation and ask which objects can STILL reach a
        # physical effect. One good path cannot mask a parallel bypass. These
        # two cuts cost linear graph work, not one path enumeration per agent.
        reverse: dict[str, set[str]] = {identifier: set() for identifier in by_id}
        for edge in graph["edges"]:
            if edge["relation"] != cut_relation:
                reverse[edge["target"]].add(edge["source"])
        for row in rows:
            if "BOT" in structural[row["object_id"]]:
                for target in row["operands"].get("agent", []):
                    if target in reverse:
                        reverse[target].add(row["object_id"])
        seen = set(physical)
        pending = deque(physical)
        while pending:
            for source in reverse[pending.popleft()]:
                if source not in seen:
                    seen.add(source)
                    pending.append(source)
        return seen

    without_control = bypassing("controls")
    without_actuation = bypassing("actuates")
    graph_required_roles = {
        identifier: {
            ROLE[domain]
            for domain, witness in derived["reachable_effects"].get(
                identifier, {}
            ).items()
            if domain in ROLE
            and (
                structural[identifier] & AGENT_ROLES
                or (
                    demanded[identifier] & {"AGENT", "BOT"}
                    and witness["next_object_id"] is not None
                )
            )
        }
        for identifier in structural
    }
    for identifier in financial:
        if not structural[identifier] & FINANCIAL:
            problem(identifier, "NAMESPACE_FINANCIAL_OBJECT_KIND_UNRESOLVED",
                "The financial endpoint cannot be represented by OBJECT alone; select the necessary financial kind(s).")
    for identifier in sorted(demanded):
        # Demand-only applicability keeps every declaration obligation in the
        # denominator but is not evidence that this object is itself a ROBOT or
        # FINBOT.  Structural declarations and roles derived from an actual
        # graph path still receive the full agency, harness and endpoint checks.
        roles = (
            structural[identifier]
            | graph_required_roles.get(identifier, set())
        ) & {"ROBOT", "FINBOT"}
        if not roles:
            continue
        row = by_id[identifier]
        agents = ({identifier} if "AGENT" in structural[identifier] else
                  set(row["operands"].get("agent", [])) if "BOT" in structural[identifier] else
                  outgoing.get((identifier, "embodies"), set()))
        # Explicit embodiment cannot replace a different native BOT/AGENT.
        explicit = outgoing.get((identifier, "embodies"), set())
        if len(agents) != 1 or not agents <= structural.keys() or any("AGENT" not in structural[a] for a in agents) or (explicit and explicit != agents):
            problem(identifier, "NAMESPACE_AGENCY_BINDING_UNRESOLVED",
                "ROBOT and FINBOT require one actual AGENT; an alternate embodiment cannot replace native operands.")
            continue
        agent = next(iter(agents))
        harnesses = by_id[agent]["operands"].get("harness", [])
        harness_bound = (len(harnesses) == 1 and harnesses[0] in structural
                         and "HARNESS" in structural[harnesses[0]])
        for role in sorted(roles):
            if not harness_bound:
                problem(identifier, "NAMESPACE_AGENCY_HARNESS_UNRESOLVED",
                    role + " requires its actual AGENT's one governing HARNESS, not another object's association.",
                    obligation_id=agency_obligations[role])
            if (identifier != agent and identifier in dominance[role]
                    and not dominates(dominance[role], agent, identifier)):
                problem(identifier, "NAMESPACE_AGENCY_EFFECT_BYPASS",
                    role + " has a declared external-effect path bypassing its bound AGENT; one governed path cannot cover that other path.",
                    obligation_id=agency_obligations[role])
        if "ROBOT" in roles:
            controllers = outgoing.get((agent, "controls"), set())
            valid = (harness_bound
                     and agent not in without_control
                     and bool(controllers) and all("CONTROLLER" in structural[c] and c not in without_actuation
                        and bool(outgoing.get((c, "actuates"), set()) & physical) for c in controllers))
            if not valid:
                problem(identifier, "NAMESPACE_ROBOT_CONTROL_CHAIN_UNRESOLVED",
                    "ROBOT: physical reach requires the actual AGENT's HARNESS and a controls/actuates chain to real ACTUATOR endpoints; an influence path alone does not establish it.")
        if "FINBOT" in roles:
            # Advice and delegation remain consequential without a direct
            # transaction edge. Reachability must still terminate at a typed
            # real financial object rather than an unbacked role declaration.
            endpoint = derived["reachable_effects"].get(agent, {}).get("REAL_FINANCIAL", {}).get("effect_object_id")
            if endpoint not in financial or not structural[endpoint] & FINANCIAL:
                problem(identifier, "NAMESPACE_FINBOT_FINANCIAL_PATH_UNRESOLVED",
                    "FINBOT: financial agency needs an influence or decision path from its actual AGENT to a typed real financial endpoint.")
    status = "FAIL" if any(item["status"] == "FAIL" for item in findings) else "UNKNOWN" if findings else "PASS"
    return {**derived, "status": status, "findings": findings,
            "external_confinement_status": "NOT_ESTABLISHED", "runtime_correspondence_status": "NOT_ESTABLISHED",
            "claim_boundary": "Source-bound declared consequence graph and typed agency chains only; no execution, confinement, physical safety or financial correctness proof."}

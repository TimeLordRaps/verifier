"""Facet-first finite obligation derivation and retrofit gap assessment.

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). This sidecar reuses namespace objects, current native
propositions, certificate replay and existing finite-completeness/source-grounding
boundaries. Rules describe listed native predicates only. Domain facet, interaction
and higher-tier applicability completeness remain UNKNOWN; no safety claim.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.domains.contracts import certificate_dag as dag

INVENTORY = "verifier-namespace-facet-inventory-1"
SPECIFICATION = "verifier-facet-obligation-specification-1"
RULES = "verifier-native-facet-derivation-rules-1"
POLICY = "verifier-facet-derivation-policy-1"
MANIFEST = "verifier-derived-facet-obligations-1"
ASSESSMENT = "verifier-facet-coverage-assessment-1"
DEPENDENCY_INVENTORY = "verifier-application-native-dependency-lower-bound-1"
DEPENDENCY_REPLAY = "verifier-application-native-dependency-lower-bound-replay-1"
MAX_FACETS = 256


def namespace_facet_inventory(objects: list[NamespaceObject]) -> dict[str, Any]:
    """Census every retained namespace field, including containers and operand roles.

    This is complete for these exact finite JSON records, not an inventory of
    every mathematical, physical, behavioral or implementation property.
    """
    if type(objects) is not list or len(objects) > dag.MAX_NODES or any(type(o) is not NamespaceObject for o in objects):
        raise ValueError("bounded plain namespace object list required")
    rows = []
    seen = set()
    for item in sorted(objects, key=lambda v: v.object_id):
        if type(item) is not NamespaceObject or item.object_id in seen:
            raise ValueError("unique exact namespace objects required")
        seen.add(item.object_id)
        record_digest = item.digest
        pending = [(item.to_dict(), [])]
        while pending:
            value, path = pending.pop()
            if path:
                if len(rows) >= MAX_FACETS:
                    raise dag._Exhausted("finite facet census bound exhausted")
                rows.append({"facet_id": dag._digest(canonical_bytes([item.object_id, path])),
                    "object_id": item.object_id, "object_kind": item.kind.value, "record_digest": record_digest,
                    "path": path, "value_digest": dag._digest(canonical_bytes(value))})
            if type(value) is dict:
                pending.extend((child, path + [key]) for key, child in sorted(value.items(), reverse=True))
            elif type(value) is list:
                pending.extend((value[i], path + [i]) for i in reversed(range(len(value))))
    return {"schema_version": INVENTORY, "inventory_version": "1",
        "scope": "exact_finite_canonical_namespace_fields", "facets": sorted(rows, key=lambda r: r["facet_id"]),
        "domain_facet_completeness": "UNKNOWN", "interaction_inventory_completeness": "UNKNOWN"}


def installed_facet_derivation_rules() -> dict[str, Any]:
    """Source-pinned authored rules; construction approves no production profile."""
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    catalog = {r["objective"]: r for r in current_object_route_catalog()}
    root = Path(__file__).parents[2]
    definitions = [("canonical_namespace_record", "*", ["OBJECT-1.1"], [],
                    ["CURRENT_OBJECT_FACETS.md"], ["object_facets.py"])]
    for kind in ObjectKind:
        coordinate = "OBJECT-1.2" if kind.value == "OBJECT" else kind.value + "-1.1"
        definitions.append(("declared_operand_structure", kind.value, [coordinate], [],
                            ["CURRENT_TYPED_FACETS.md"], ["typed_facets.py"]))
    definitions.extend([
        ("finite_declared_operand_cone", "HYPER", ["HYPER-4.1"], [],
         ["CURRENT_HYPER_CLOSURE.md"], ["hyper_closure.py"]),
        ("selected_transition_replay", "SIM", ["SIM-2.1"], [],
         ["CURRENT_SIM_DYNAMICS.md"], ["sim_dynamics.py"]),
        ("selected_action_response", "SIM", ["SIM-2.1", "SIM-2.2"], [("SIM-2.2", "SIM-2.1")],
         ["CURRENT_SIM_DYNAMICS.md", "CURRENT_SIM_RESPONSE.md"], ["sim_dynamics.py", "sim_response.py"]),
        ("selected_internal_state", "SIM", ["SIM-2.1", "SIM-2.3"], [("SIM-2.3", "SIM-2.1")],
         ["CURRENT_SIM_DYNAMICS.md", "CURRENT_SIM_INTERNAL_STATE.md"], ["sim_dynamics.py", "sim_internal_state.py"]),
        ("selected_perspective", "SIM", ["SIM-2.1", "SIM-2.3", "SIM-2.5"],
         [("SIM-2.3", "SIM-2.1"), ("SIM-2.5", "SIM-2.3")],
         ["CURRENT_SIM_DYNAMICS.md", "CURRENT_SIM_INTERNAL_STATE.md", "CURRENT_SIM_PERSPECTIVE.md"],
         ["sim_dynamics.py", "sim_internal_state.py", "sim_perspective.py"]),
        ("selected_shard_coverage", "SIM", ["SIM-2.1", "SIM-4.1"], [("SIM-4.1", "SIM-2.1")],
         ["CURRENT_SIM_DYNAMICS.md", "CURRENT_SIM_SHARD_COVERAGE.md"], ["sim_dynamics.py", "sim_shard_coverage.py"]),
    ])
    shared_modules = ["retained_selection.py", "facet_coverage.py", "certificate_dag.py",
        "current_object_routes.py", "../common.py", "../../core/certificate.py",
        "../../core/evidence.py", "../../core/namespace.py", "../../core/receipt.py"]
    shared_specs = ["NAMESPACE_OBJECTS.md", "FACET_OBLIGATION_DERIVATION.md", "CERTIFICATE_DAG.md"]
    definitions.extend([
        ("selected_retained_data_inventory", "DATA", ["DATA-1.2"], [],
         ["CURRENT_DATA_CHECKS.md", *shared_specs], ["data_checks.py", "../data.py", *shared_modules]),
        ("selected_retained_data_lineage", "DATA", ["DATA-2.1"], [],
         ["CURRENT_DATA_CHECKS.md", *shared_specs], ["data_checks.py", "../data.py", *shared_modules]),
        ("selected_retained_graph_statics", "GRAPH", ["GRAPH-3.1"], [],
         ["CURRENT_GRAPH_STATICS.md", *shared_specs], ["graph_statics.py", *shared_modules]),
        ("selected_retained_graph_closure", "GRAPH", ["GRAPH-3.1", "GRAPH-4.1"],
         [("GRAPH-4.1", "GRAPH-3.1")], ["CURRENT_GRAPH_STATICS.md", "CURRENT_GRAPH_CLOSURE.md", *shared_specs],
         ["graph_statics.py", "graph_closure.py", *shared_modules]),
        ("selected_direct_operand_content_lineage", "GRAPH", ["GRAPH-3.1", "GRAPH-9.2"],
         [("GRAPH-9.2", "GRAPH-3.1")], ["CURRENT_GRAPH_STATICS.md", "CURRENT_GRAPH_LINEAGE.md", *shared_specs],
         ["graph_statics.py", "graph_lineage.py", *shared_modules]),
    ])
    from verifier.domains.contracts.token_facets import PROPERTY_CHECKS
    from verifier.domains.contracts.token_checks import CHECKS
    definitions.extend((prop, "TOKEN", [CHECKS[check]], [],
        ["CURRENT_TOKEN_CHECKS.md", "CURRENT_TOKEN_FACET_MAPPING.md",
         "DOMAIN_OBLIGATIONS.md", "ZIZK_TOKENS.md"],
        ["token_checks.py", "token_facets.py", "retained_selection.py",
         "../token.py", "../statics.py", "../common.py", "../../core/evidence.py"])
        for prop, check in PROPERTY_CHECKS.items())
    rows = []
    for prop, kind, coordinates, dependencies, specs, modules in definitions:
        sources = [{"path": "verifier/standard/" + name, "digest": dag._digest((root / "standard" / name).read_bytes())}
                   for name in specs]
        for name in modules:
            source_path = (Path(__file__).parent / name).resolve()
            sources.append({"path": "verifier/" + source_path.relative_to(root).as_posix(),
                            "digest": dag._digest(source_path.read_bytes())})
        outputs = [{"semantic_version": catalog[c]["semantic_version"], "objective": c,
            "proposition_digest": catalog[c]["proposition_digest"], "scope": catalog[c]["scope"],
            "admissible_evidence_schema": catalog[c]["certificate_schema_version"],
            "completion_criteria": ["EXACT_EXTERNALLY_SELECTED_NATIVE_REPLAY_PASS",
                                    "ALL_DERIVED_CERTIFICATE_PREREQUISITES_PASS"],
            "units": {"counts": "dimensionless", "encoded_bytes": "byte", "application_values": "opaque_native_values"}}
            for c in coordinates]
        row = {"rule_id": "native-facet:" + kind + ":" + prop, "rule_version": "1",
            "property_id": prop, "object_kind": kind, "outputs": outputs,
            "prerequisites": [{"dependent": a, "prerequisite": b, "binding": "same_exact_selected_object_and_child_certificate"}
                              for a, b in dependencies], "sources": sources,
            "approval": "AUTHORED_SOURCE_RULE_NOT_PRODUCTION_PROFILE"}
        if prop in PROPERTY_CHECKS:
            from verifier.domains.contracts.token_facets import REQUIRED_PATHS, SCOPE, UNIT
            check = PROPERTY_CHECKS[prop]
            row["required_namespace_values"] = [
                {"path": ["payload", "scope"], "value_digest": dag._digest(canonical_bytes(SCOPE))},
                {"path": ["payload", "clock_unit"], "value_digest": dag._digest(canonical_bytes(UNIT))}]
            row["required_namespace_paths"] = [["payload", "artifact", name]
                                               for name in REQUIRED_PATHS[check]]
            row["required_origin_path"] = ["payload", "artifact", "tokens_digest"]
            row["inline_prerequisites"] = ["EXACT_NAMESPACE_COMPOSITION_PASS", "RETAINED_TOKEN_INVENTORY_PASS"]
            for output in outputs:
                output["completion_criteria"].extend(row["inline_prerequisites"])
                output["units"] = {"window_instants_widths_and_skew": "declared-clock microsecond",
                    "epoch_indices_active_epoch_counts_and_invocation_bounds": "dimensionless",
                    "clock_identity_and_key_identifiers": "opaque declarations"}
        if prop in ("selected_retained_data_inventory", "selected_retained_data_lineage"):
            origin = "shards" if prop == "selected_retained_data_inventory" else "transforms"
            row["required_namespace_values"] = []
            row["required_namespace_paths"] = [["payload", "shards"], ["payload", origin]]
            row["required_origin_path"] = ["payload", origin]
            row["inline_prerequisites"] = ["RETAINED_DATA_INVENTORY_PASS"]
            for output in outputs:
                output["completion_criteria"].extend(row["inline_prerequisites"])
        elif prop in ("selected_retained_graph_statics", "selected_retained_graph_closure",
                      "selected_direct_operand_content_lineage"):
            row["required_namespace_values"] = [{"path": ["payload", "scope"],
                "value_digest": dag._digest(canonical_bytes("retained_directed_graph"))}]
            row["required_namespace_paths"] = [["payload", field]
                for field in ("element_kind", "nodes_digest", "edges_digest")] + [["operands", "members"]]
            row["required_origin_path"] = ["payload", "edges_digest"]
        row["rule_digest"] = dag._digest(canonical_bytes(row))
        rows.append(row)
    return {"schema_version": RULES, "rule_set_version": "1", "rules": rows,
            "complete_applicability_profiles": 0}


_FIXED_NATIVE_DEPENDENCIES = (
    ("ARCH-3.1", "ARCH-2.1", "arch_schedule.py"),
    ("COLLECTIVE-3.1", "COLLECTIVE-2.1", "collective_lifecycle.py"),
    ("COLLECTIVE-3.1", "COLLECTIVE-4.1", "collective_closure.py"),
    ("EVENT-3.1", "EVENT-4.1", "event_closure.py"),
    ("GRAPH-3.1", "GRAPH-2.1", "graph_order.py"),
    ("GRAPH-3.1", "GRAPH-4.1", "graph_closure.py"),
    ("GRAPH-3.1", "GRAPH-9.2", "graph_lineage.py"),
    ("IDENTITY-3.1", "IDENTITY-2.1", "identity_lifecycle.py"),
    ("MODEL-3.1", "MODEL-3.2", "model_hardware_observation.py"),
    ("MODEL-3.4", "MODEL-3.5", "model_train_citation.py"),
    ("MODEL-3.4", "MODEL-3.7", "model_data_lineage.py"),
    ("RECEIPT-3.1", "RECEIPT-4.1", "receipt_prerequisite_closure.py"),
    ("RECEIPT-9.1", "RECEIPT-9.2", "receipt_authenticity.py"),
    ("ROLE-2.1", "ROLE-4.1", "role_closure.py"),
    ("ROLE-3.1", "ROLE-2.1", "role_lifecycle.py"),
    ("ROLE-3.1", "ROLE-4.1", "role_closure.py"),
    ("ROLE-4.1", "COLLECTIVE-4.1", "collective_closure.py"),
    ("SIM-2.1", "SIM-2.2", "sim_response.py"),
    ("SIM-2.1", "SIM-2.3", "sim_internal_state.py"),
    ("SIM-2.1", "SIM-2.4", "sim_resource.py"),
    ("SIM-2.1", "SIM-4.1", "sim_shard_coverage.py"),
    ("SIM-2.3", "SIM-2.5", "sim_perspective.py"),
    ("SIM-4.1", "SIM-4.2", "sim_shard_relations.py"),
    ("SIM-4.2", "SIM-4.3", "sim_shard_signatures.py"),
    ("SIM-4.3", "SIM-4.4", "sim_surface_partition.py"),
    ("SPACE-3.1", "SPACE-2.1", "space_migration.py"),
    ("SPACE-3.1", "SPACE-4.1", "space_closure.py"),
    ("TIME-2.1", "TIME-3.1", "time_strict.py"),
    ("TIME-2.1", "TIME-4.1", "time_closure.py"),
    ("TRAIN-1.5", "MODEL-3.7", "model_data_lineage.py"),
    ("TRAIN-4.1", "TRAIN-1.5", "train_data_bridge.py"),
    ("DATA-1.2", "TRAIN-1.5", "train_data_bridge.py"),
    ("ENV-1.2", "ENV-1.3", "env_executable.py"),
    ("ENV-1.1", "ENV-1.4", "env_configuration_surface.py"),
    ("ENV-1.2", "ENV-4.1", "env_pin_closure.py"),
    ("DATA-1.2", "MODEL-3.4", "model_data_citation.py"),
)
_DYNAMIC_NATIVE_DEPENDENCY_FAMILIES = (
    ("HYPER-2.3:DIRECT_OPERAND_CHILD_SELECTION", "hyper_unknown_absorption.py"),
    ("VERIFIER-3.1:TRACE_CHILD_SELECTION", "verifier_run_constraints.py"),
    ("VERIFIER-4.1:APPROVED_PROFILE_BOUNDARY_SELECTION", "verifier_coverage_closure.py"),
    ("CERTIFICATE-DAG:SELECTED_NODE_PREREQUISITES", "certificate_dag.py"),
)


def installed_native_dependency_inventory() -> dict[str, Any]:
    """Bind a reviewed native-dependency lower bound without selecting it.

    The returned rows describe source-observed consumers. They do not make every
    pair applicable to every profile, close the full inventory, or authorize a
    release. Only an exact externally selected profile instantiates an edge.
    """
    from verifier.domains.contracts import current_object_routes, receipt_chain, subject_security

    root = Path(__file__).parents[2]
    catalog = current_object_routes.current_object_route_catalog()
    coordinates = {row["objective"] for row in catalog}
    fixed = []
    seen = set()
    for prerequisite, dependent, module_name in _FIXED_NATIVE_DEPENDENCIES:
        identity = (prerequisite, dependent)
        if identity in seen or prerequisite not in coordinates or dependent not in coordinates:
            raise ValueError("fixed native dependency is duplicated or unregistered")
        seen.add(identity)
        source_path = root / "domains" / "contracts" / module_name
        row = {"rule_kind": "FIXED_NATIVE_CHILD", "prerequisite": prerequisite,
            "dependent": dependent, "binding": "EXACT_SELECTED_NATIVE_CHILD_INSTANCE",
            "application": "CONDITIONAL_ON_EXTERNAL_PROFILE_SELECTION",
            "source": {"path": "verifier/domains/contracts/" + module_name,
                "digest": dag._digest(source_path.read_bytes())}}
        row["rule_digest"] = dag._digest(canonical_bytes(row))
        fixed.append(row)

    shared_sources = [{"path": "verifier/domains/contracts/" + name,
        "digest": dag._digest((root / "domains" / "contracts" / name).read_bytes())}
        for name in ("receipt_chain.py", "subject_security.py")]
    parametric = []
    for kind in ObjectKind:
        dependent = subject_security.coordinate(kind.value)
        matching = [row for row in catalog
            if row["semantic_version"] == subject_security.SEMANTIC_VERSION
            and row["objective"] == dependent
            and row["represented_kind_rule"] == kind.value]
        if len(matching) != 1 or receipt_chain.COORDINATE not in coordinates:
            raise ValueError("typed subject-security dependency route is absent or ambiguous")
        row = {"rule_kind": "PARAMETRIC_NATIVE_CHILD",
            "parameter": {"object_kind": kind.value},
            "prerequisite": receipt_chain.COORDINATE, "dependent": dependent,
            "binding": "EXACT_SELECTED_SUBJECT_AND_RECEIPT_CHAIN_INSTANCE",
            "application": "CONDITIONAL_ON_EXTERNAL_PROFILE_SELECTION",
            "sources": shared_sources}
        row["rule_digest"] = dag._digest(canonical_bytes(row))
        parametric.append(row)

    inline = []
    for rule in installed_facet_derivation_rules()["rules"]:
        if not rule.get("inline_prerequisites"):
            continue
        row = {"rule_kind": "INLINE_COMPLETION_CRITERION",
            "source_rule_id": rule["rule_id"], "source_rule_digest": rule["rule_digest"],
            "dependent_objectives": sorted(output["objective"] for output in rule["outputs"]),
            "prerequisites": list(rule["inline_prerequisites"]),
            "application": "CONDITIONAL_ON_EXACT_DERIVED_RULE_SELECTION"}
        row["rule_digest"] = dag._digest(canonical_bytes(row))
        inline.append(row)

    dynamic = []
    for family, module_name in _DYNAMIC_NATIVE_DEPENDENCY_FAMILIES:
        source_path = root / "domains" / "contracts" / module_name
        dynamic.append({"family": family,
            "expansion_status": "UNKNOWN_UNTIL_EXTERNAL_SELECTION",
            "application": "NO_FIXED_EDGE_INFERRED",
            "source": {"path": "src/verifier/domains/contracts/" + module_name,
                "sha256": dag._digest(source_path.read_bytes()).removeprefix("sha256:")}})
    result = {"schema_version": DEPENDENCY_INVENTORY,
        "coverage_status": "REVIEWED_SOURCE_LOWER_BOUND",
        "fixed_pairs": sorted(fixed, key=lambda row: (row["dependent"], row["prerequisite"])),
        "parametric_pairs": sorted(parametric, key=lambda row: row["parameter"]["object_kind"]),
        "inline_completion_rules": sorted(inline, key=lambda row: row["source_rule_id"]),
        "unresolved_dynamic_families": dynamic,
        "counts": {"fixed_pairs": len(fixed), "parametric_pairs": len(parametric),
            "inline_completion_rules": len(inline), "unresolved_dynamic_families": len(dynamic)},
        "full_source_dependency_inventory": "UNKNOWN",
        "complete_application_profile": "NOT_SELECTED",
        "release_admissible": False,
        "claim_boundary": "Source-observed lower bound only; no exhaustive denominator, blanket tier dependency, application selection, native replay result, authority, acceptance or release."}
    if result["counts"] != {"fixed_pairs": 36, "parametric_pairs": 26,
            "inline_completion_rules": 5, "unresolved_dynamic_families": 4}:
        raise ValueError("reviewed native dependency lower bound changed")
    return result


def native_dependency_inventory_digest() -> str:
    return dag._digest(canonical_bytes(installed_native_dependency_inventory()))


def recheck_native_dependency_inventory(inventory_bytes: bytes | None, *,
        expected_inventory_digest: str) -> dict[str, Any]:
    """Replay exact inventory identity; never promote application completeness."""
    result = {"schema_version": DEPENDENCY_REPLAY, "status": "UNKNOWN",
        "replay_status": "UNAVAILABLE", "full_source_dependency_inventory": "UNKNOWN",
        "complete_application_profile": "NOT_SELECTED", "release_admissible": False}
    if inventory_bytes is None:
        result["reason"] = "INVENTORY_BYTES_UNAVAILABLE"
        return result
    try:
        expected = dag._hash(expected_inventory_digest)
        observed = dag._digest(inventory_bytes)
        if observed != expected:
            raise ValueError("selected inventory digest differs")
        selected = dag._parse(inventory_bytes)
        installed = installed_native_dependency_inventory()
        installed_bytes = canonical_bytes(installed)
        installed_digest = dag._digest(installed_bytes)
        if selected != installed or installed_digest != expected:
            raise ValueError("selected inventory differs from installed source lower bound")
        result.update(status="PASS", replay_status="REPRODUCED",
            inventory_digest=installed_digest, counts=installed["counts"],
            claim_boundary=installed["claim_boundary"])
    except (OSError, ImportError):
        result["reason"] = "INSTALLED_SOURCE_UNAVAILABLE"
    except (dag._Exhausted, RecursionError, OverflowError):
        result["reason"] = "INVENTORY_RESOURCE_UNAVAILABLE"
    except (ValueError, TypeError, KeyError, UnicodeError):
        result.update(status="FAIL", replay_status="REJECTED",
            reason="INVENTORY_BINDING_REJECTED")
    return result


def native_structural_facet_mapping(objects: list[NamespaceObject]) -> dict[str, Any]:
    """Map the five existing structural specification facets to exact field projections.

    The four generic facets are normative in CURRENT_OBJECT_FACETS; typed
    composition is separately normative in CURRENT_TYPED_FACETS. This mapping
    says nothing about source declarations or full application semantics.
    """
    inventory = namespace_facet_inventory(objects)
    rules = installed_facet_derivation_rules()
    generic_rule = next(r for r in rules["rules"] if r["property_id"] == "canonical_namespace_record")
    typed_rules = {r["object_kind"]: r for r in rules["rules"] if r["property_id"] == "declared_operand_structure"}
    rows = []
    projection = {f["facet_id"]: set() for f in inventory["facets"]}
    for item in sorted(objects, key=lambda o: o.object_id):
        fields = [f for f in inventory["facets"] if f["object_id"] == item.object_id]
        definitions = [
            ("identifier", "object_id", generic_rule, "canonical_namespace_record"),
            ("admitted_kind", "kind", generic_rule, "canonical_namespace_record"),
            ("canonical_payload", "payload", generic_rule, "canonical_namespace_record"),
            ("named_ordered_operand_map", "operands", generic_rule, "canonical_namespace_record"),
            ("declared_typed_composition", None, typed_rules[item.kind.value], "declared_operand_structure"),
        ]
        for name, prefix, rule, prop in definitions:
            selected = sorted(f["facet_id"] for f in fields if prefix is None or f["path"][0] == prefix)
            identity = dag._digest(canonical_bytes([item.object_id, "verifier-current-object-obligations-1", name]))
            rows.append({"semantic_facet_id": identity, "semantic_facet_name": name,
                "semantic_version": "verifier-current-object-obligations-1",
                "object_id": item.object_id, "object_kind": item.kind.value, "record_digest": item.digest,
                "namespace_field_ids": selected, "property_id": prop,
                "native_obligations": rule["outputs"], "specification_sources": rule["sources"],
                "rule_id": rule["rule_id"], "rule_digest": rule["rule_digest"],
                "applicability_scope": "EXISTING_NATIVE_STRUCTURAL_PROPOSITION_ONLY",
                "source_declaration_mapping": "UNKNOWN", "application_semantic_completeness": "UNKNOWN"})
            for fid in selected:
                projection[fid].add(prop)
    return {"schema_version": "verifier-native-structural-facet-mapping-1",
        "mapping_version": "1", "scope": "existing_native_structural_specification_facets",
        "namespace_inventory_digest": dag._digest(canonical_bytes(inventory)),
        "rule_set_digest": dag._digest(canonical_bytes(rules)), "semantic_facets": rows,
        "field_projection": [{"facet_id": fid, "properties": sorted(props)} for fid, props in sorted(projection.items())],
        "known_structural_semantic_facets": len(rows), "full_application_facet_denominator": None,
        "interaction_applicability": "UNKNOWN", "mapping_authority": "NOT_INDEPENDENTLY_ADMITTED",
        "production_profile_approval": "NOT_ESTABLISHED"}


def _diagnostic(code: str, component: str, resolution: str, *, status: str = "UNKNOWN",
                blocked: list[str] | None = None) -> dict[str, Any]:
    return {"code": code, "component": component, "status": status,
            "blocked_descendants": sorted(blocked or []), "required_resolution": resolution}


def derive_facet_obligations(inventory_bytes: bytes, specification_bytes: bytes, *,
                             expected_policy_bytes: bytes | None) -> dict[str, Any]:
    """Derive the finite requirement manifest independently from certificate evidence."""
    result = {"schema_version": MANIFEST, "status": "UNKNOWN", "derivation_status": "UNKNOWN",
        "inventory_digest": dag._digest(inventory_bytes) if type(inventory_bytes) is bytes else None,
        "specification_digest": dag._digest(specification_bytes) if type(specification_bytes) is bytes else None,
        "rule_set_digest": None, "obligations": [], "edges": [], "ledger": [], "diagnostics": [],
        "domain_facet_completeness": "UNKNOWN", "interaction_inventory_completeness": "UNKNOWN",
        "whole_tier_conformance": "NOT_ESTABLISHED", "object_profile_conformance": "NOT_ESTABLISHED"}
    if expected_policy_bytes is None:
        result["diagnostics"] = [_diagnostic("INDEPENDENT_DERIVATION_POLICY_MISSING", "policy",
            "Select exact facet inventory, specification and rule versions independently of submitted certificates.")]
        result["manifest_digest"] = dag._digest(canonical_bytes(result))
        return result
    component = "policy"
    try:
        policy, inventory, specification = (dag._parse(v) for v in
            (expected_policy_bytes, inventory_bytes, specification_bytes))
        dag._record(policy, {"schema_version", "inventory_digest", "specification_digest",
                             "rule_set_digest", "approved_rule_digests"})
        if policy["schema_version"] != POLICY:
            raise ValueError("unsupported facet policy")
        for key in ("inventory_digest", "specification_digest", "rule_set_digest"):
            dag._hash(policy[key])
        if policy["inventory_digest"] != result["inventory_digest"] or policy["specification_digest"] != result["specification_digest"]:
            raise ValueError("independent facet input binding changed")
        rules = installed_facet_derivation_rules()
        result["rule_set_digest"] = dag._digest(canonical_bytes(rules))
        if policy["rule_set_digest"] != result["rule_set_digest"]:
            raise ValueError("selected facet rule version or source changed")
        approved = {dag._hash(v) for v in dag._list(policy["approved_rule_digests"])}
        component = "inventory"
        dag._record(inventory, {"schema_version", "inventory_version", "scope", "facets",
                               "domain_facet_completeness", "interaction_inventory_completeness"})
        if (inventory["schema_version"] != INVENTORY or inventory["inventory_version"] != "1"
                or inventory["scope"] != "exact_finite_canonical_namespace_fields"
                or inventory["domain_facet_completeness"] != "UNKNOWN"
                or inventory["interaction_inventory_completeness"] != "UNKNOWN"):
            raise ValueError("unsupported facet inventory meaning")
        facets = {}
        for row in dag._list(inventory["facets"], MAX_FACETS):
            dag._record(row, {"facet_id", "object_id", "object_kind", "record_digest", "path", "value_digest"})
            for key in ("facet_id", "record_digest", "value_digest"):
                dag._hash(row[key])
            dag._text(row["object_id"]); ObjectKind(row["object_kind"])
            if type(row["path"]) is not list or not row["path"] or len(row["path"]) > 48:
                raise ValueError("exact facet path required")
            if row["facet_id"] in facets:
                raise ValueError("duplicate facet identifier")
            facets[row["facet_id"]] = row
        if not facets:
            result["diagnostics"].append(_diagnostic("EMPTY_FACET_DENOMINATOR", "inventory", "Provide a nonempty source-grounded facet inventory."))
        component = "specification"
        dag._record(specification, {"schema_version", "specification_id", "specification_version", "facets", "interactions"})
        if specification["schema_version"] != SPECIFICATION:
            raise ValueError("unsupported facet specification")
        dag._text(specification["specification_id"]); dag._text(specification["specification_version"])
        definitions = {}
        origins = []
        for row in dag._list(specification["facets"], MAX_FACETS):
            dag._record(row, {"facet_id", "properties"})
            fid = dag._hash(row["facet_id"])
            if fid in definitions or fid not in facets:
                raise ValueError("duplicate or invented specification facet")
            component = fid
            definitions[fid] = row
            properties = dag._list(row["properties"], 16)
            if len(set(properties)) != len(properties):
                raise ValueError("duplicate facet property")
            if not properties:
                result["diagnostics"].append(_diagnostic("FACET_PROPERTY_UNDERSPECIFIED", fid, "Supply source-grounded abstract properties and exact derivation rules."))
            for prop in properties:
                origins.append((fid, [fid], dag._text(prop)))
        for fid in sorted(set(facets) - set(definitions)):
            result["diagnostics"].append(_diagnostic("FACET_SPECIFICATION_MISSING", fid, "Specify the omitted retained facet and its applicability."))
        interaction_ids = set()
        for interaction in dag._list(specification["interactions"], MAX_FACETS):
            dag._record(interaction, {"interaction_id", "facet_ids", "properties"})
            identity = dag._text(interaction["interaction_id"])
            selected = dag._list(interaction["facet_ids"], 16)
            if identity in interaction_ids or len(selected) < 2 or len(set(selected)) != len(selected) or set(selected) - set(facets):
                raise ValueError("invalid facet interaction binding")
            interaction_ids.add(identity)
            for prop in dag._list(interaction["properties"], 16):
                origins.append((identity, selected, dag._text(prop)))
            if not interaction["properties"]:
                result["diagnostics"].append(_diagnostic("INTERACTION_UNDERSPECIFIED", identity, "Specify the interaction property and source-grounded rule."))
        obligations = {}
        edge_keys = set()
        for origin, related, prop in origins:
            kinds = {facets[f]["object_kind"] for f in related}
            objects = {facets[f]["object_id"] for f in related}
            matches = [r for r in rules["rules"] if r["property_id"] == prop
                       and len(kinds) == 1 and r["object_kind"] in kinds | {"*"} and len(objects) == 1]
            if len(matches) != 1:
                result["diagnostics"].append(_diagnostic("DERIVATION_RULE_UNSUPPORTED_OR_AMBIGUOUS", origin,
                    "Provide a supported versioned property/interaction rule; no automatic scientific interpretation is available."))
                continue
            component = origin
            rule = matches[0]; oid = next(iter(objects)); kind = next(iter(kinds))
            if "required_namespace_values" in rule:
                object_facets = [f for f in facets.values() if f["object_id"] == oid]
                def required_path_matches(path):
                    return [f for f in object_facets if f["path"] == path]
                values_supported = all(
                    len(required_path_matches(condition["path"])) == 1
                    and required_path_matches(condition["path"])[0]["value_digest"] == condition["value_digest"]
                    for condition in rule["required_namespace_values"])
                paths_retained = all(len(required_path_matches(path)) == 1
                                     for path in rule["required_namespace_paths"])
                origin_supported = any(facets[f]["path"] == rule["required_origin_path"] for f in related)
                if not values_supported or not paths_retained or not origin_supported:
                    code = "TOKEN_SCOPED_PROPERTY_BINDING_UNSUPPORTED" if kind == "TOKEN" else "DATA_GRAPH_SCOPED_PROPERTY_BINDING_UNSUPPORTED"
                    resolution = ("Retain the exact capability-token scope/unit/required paths and token-inventory origin; "
                        "no financial-token, physical-clock or missing-evidence interpretation is inferred." if kind == "TOKEN" else
                        "Retain the selected DATA shard/transform or GRAPH direct-member/array commitment paths and exact origin; "
                        "payload transformations do not create namespace operand edges or complete applicability.")
                    result["diagnostics"].append(_diagnostic(code, origin, resolution))
                    continue
            if rule["rule_digest"] not in approved:
                result["diagnostics"].append(_diagnostic("DERIVATION_RULE_UNAPPROVED", origin,
                    "Independently admit the exact authored source rule; this does not approve a production object profile."))
            ids = {}
            for output in rule["outputs"]:
                identity = dag._digest(canonical_bytes({"object_id": oid, **output}))
                ids[output["objective"]] = identity
                obligation = obligations.setdefault(identity, {"obligation_id": identity, "object_id": oid,
                    "object_kind": kind, **output, "origins": [], "prerequisites": [], "derivation_rule_admission": "PASS"})
                if rule["rule_digest"] not in approved:
                    obligation["derivation_rule_admission"] = "UNKNOWN"
                provenance = {"origin_id": origin, "facet_ids": sorted(related), "property_id": prop,
                    "rule_id": rule["rule_id"], "rule_version": rule["rule_version"],
                    "rule_digest": rule["rule_digest"], "sources": rule["sources"]}
                if provenance not in obligation["origins"]:
                    obligation["origins"].append(provenance)
            for edge in rule["prerequisites"]:
                a, b = ids[edge["dependent"]], ids[edge["prerequisite"]]
                edge_keys.add((a, b))
                if b not in obligations[a]["prerequisites"]:
                    obligations[a]["prerequisites"].append(b)
        result["obligations"] = [obligations[k] for k in sorted(obligations)]
        result["edges"] = [{"obligation_id": a, "prerequisite_id": b} for a, b in sorted(edge_keys)]
        for fid in sorted(facets):
            for tier in range(1, 10):
                selected = [o["obligation_id"] for o in result["obligations"]
                    if int(o["objective"].split("-")[1].split(".")[0]) == tier
                    and any(fid in origin["facet_ids"] for origin in o["origins"])]
                result["ledger"].append({"facet_id": fid, "object_id": facets[fid]["object_id"], "tier": tier,
                    "applicability": "REQUIRED_FOR_SELECTED_NATIVE_PROPERTY" if selected else "UNKNOWN",
                    "obligation_ids": selected, "evidence": [], "completion_status": "UNKNOWN"})
        result["derivation_status"] = "PASS" if not result["diagnostics"] and facets else "UNKNOWN"
        result["diagnostics"].extend([
            _diagnostic("DOMAIN_FACET_DENOMINATOR_NOT_ESTABLISHED", "inventory",
                "Independently ground the full application facet specification; finite field census is not domain completeness."),
            _diagnostic("INTERACTION_DENOMINATOR_NOT_ESTABLISHED", "interactions",
                "Independently ground applicable cross-facet interactions; a submitted graph cannot define its own denominator."),
            _diagnostic("HIGHER_TIER_APPLICABILITY_NOT_ESTABLISHED", "applicability",
                "Provide source-grounded applicability and admissible exemption rules for unresolved cells; author N/A waivers are unsupported.")])
        result["denominators"] = {"retained_namespace_facets": len(facets),
            "derived_obligations": len(obligations),
            "known_required_facet_tier_cells": sum(bool(r["obligation_ids"]) for r in result["ledger"]),
            "unknown_applicability_cells": sum(not r["obligation_ids"] for r in result["ledger"]),
            "complete_domain_facets": None, "complete_applicable_obligations": None}
    except (dag._Exhausted, RecursionError, OverflowError):
        result["diagnostics"] = [_diagnostic("DERIVATION_RESOURCE_BOUND_EXHAUSTED", "inputs", "Provide inputs within the installed finite bounds.")]
    except (OSError, ImportError):
        result["diagnostics"] = [_diagnostic("DERIVATION_SOURCE_UNAVAILABLE", "rules", "Retain the selected installed specification and rule-source bytes.")]
    except (ValueError, TypeError, KeyError, UnicodeError):
        result["status"], result["derivation_status"] = "FAIL", "FAIL"
        result["diagnostics"] = [_diagnostic("FACET_SPECIFICATION_OR_BINDING_REJECTED", component,
            "Correct the exact invalid or substituted versioned input binding.", status="FAIL")]
    result["manifest_digest"] = dag._digest(canonical_bytes(result))
    return result


def assess_facet_completeness(inventory_bytes: bytes, specification_bytes: bytes, *,
        expected_policy_bytes: bytes | None, bundle_bytes: bytes,
        expected_dependency_policy_bytes: bytes | None, artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Recompute the requirement denominator before matching existing native evidence."""
    derived = derive_facet_obligations(inventory_bytes, specification_bytes, expected_policy_bytes=expected_policy_bytes)
    native = dag.assess_certificate_dependencies(bundle_bytes,
        expected_policy_bytes=expected_dependency_policy_bytes, artifact_files=artifact_files)
    result = {"schema_version": ASSESSMENT,
        "status": "FAIL" if derived["status"] == "FAIL" or native["status"] == "FAIL" else "UNKNOWN",
        "manifest": derived,
        "native_assessment": native, "obligations": [], "ledger": deepcopy(derived["ledger"]),
        "diagnostics": deepcopy(derived["diagnostics"]), "qualification": "NOT_ESTABLISHED"}
    component = "inputs"
    try:
        bundle = dag._parse(bundle_bytes); selected_inventory = dag._parse(inventory_bytes)
        objects = [NamespaceObject.create(row["object_id"], row["kind"], row["payload"], row["operands"]) for row in bundle["objects"]]
        census = namespace_facet_inventory(objects)
        selected = {row["facet_id"]: row for row in selected_inventory["facets"]}
        actual = {row["facet_id"]: row for row in census["facets"]}
        for fid in sorted(set(actual) - set(selected)):
            result["diagnostics"].append(_diagnostic("RETAINED_FACET_OMITTED", fid, "Add the omitted exact namespace facet to the independently selected inventory."))
        if set(selected) - set(actual) or any(selected[f] != actual[f] for f in set(actual) & set(selected)):
            result["status"] = "FAIL"
            result["diagnostics"].append(_diagnostic("FACET_CENSUS_BINDING_MISMATCH", "inventory", "Rebind the exact selected record/facet values.", status="FAIL"))
        object_ids = {o.object_id for o in objects}
        for item in objects:
            for role, targets in item.operands:
                for target in targets:
                    if target not in object_ids:
                        result["diagnostics"].append(_diagnostic("OPERAND_TARGET_UNSELECTED", item.object_id + ":" + role + ":" + target,
                            "Independently select the required operand record, its facet specification and evidence."))
        native_nodes = {n["node_id"]: n for n in native["nodes"]}
        claims = {}
        for claim in dag._list(bundle["nodes"], dag.MAX_NODES):
            identity = dag._text(claim["node_id"])
            component = "certificate:" + identity
            if type(claim["request"]) is not dict:
                raise ValueError("exact native request record required before coverage matching")
            claims[identity] = claim
        component = "inputs"
        checked = {}
        pending = {o["obligation_id"]: set(o["prerequisites"]) for o in derived["obligations"]}
        ready = deque(sorted(oid for oid, refs in pending.items() if not refs))
        by_id = {o["obligation_id"]: o for o in derived["obligations"]}
        while ready:
            oid = ready.popleft(); obligation = by_id[oid]
            matching = [nid for nid, node in claims.items() if node["object_id"] == obligation["object_id"]
                and node["request"].get("semantic_version") == obligation["semantic_version"]
                and node["request"].get("coordinate") == obligation["objective"]
                and node["request"].get("proposition_digest") == obligation["proposition_digest"]]
            observations = [native_nodes[nid] for nid in matching if nid in native_nodes]
            direct = "FAIL" if any(n["direct_status"] == "FAIL" for n in observations) else "PASS" if any(n["direct_status"] == "PASS" for n in observations) else "UNKNOWN"
            prerequisites = [checked[p]["completion_status"] for p in obligation["prerequisites"]]
            child_correlated, child_mismatch = True, False
            if (obligation["semantic_version"] == "verifier-current-object-obligations-1"
                    and obligation["objective"] in ("GRAPH-4.1", "GRAPH-9.2")):
                for prerequisite in obligation["prerequisites"]:
                    if by_id[prerequisite]["objective"] != "GRAPH-3.1":
                        continue
                    selected_children = checked[prerequisite]["certificate_nodes"]
                    for observed in observations:
                        exact_children = [nid for nid in selected_children
                            if dag._selected_graph_child_matches(obligation["objective"],
                                claims[observed["node_id"]]["request"], claims[nid])]
                        if selected_children and not exact_children:
                            child_mismatch = True
                        if not any(nid in native_nodes and native_nodes[nid]["qualified_status"] == "PASS"
                                   for nid in exact_children):
                            child_correlated = False
            completion = "FAIL" if direct == "FAIL" or child_mismatch or "FAIL" in prerequisites else "PASS" if observations and child_correlated and obligation["derivation_rule_admission"] == "PASS" and all(n["qualified_status"] == "PASS" for n in observations) and all(v == "PASS" for v in prerequisites) else "UNKNOWN"
            if child_mismatch:
                result["diagnostics"].append(_diagnostic("DERIVED_CHILD_CERTIFICATE_SELECTION_MISMATCH", oid,
                    "Select the exact GRAPH-3.1 child request, policy and certificate retained by each authored parent obligation.", status="FAIL"))
            checked[oid] = {"obligation_id": oid, "direct_status": direct, "completion_status": completion, "certificate_nodes": matching}
            if not observations:
                result["diagnostics"].append(_diagnostic("DERIVED_OBLIGATION_EVIDENCE_MISSING", oid,
                    "Select exact native certificate/request/policy evidence for " + obligation["objective"] + "."))
            elif direct != "PASS":
                result["diagnostics"].append(_diagnostic("NATIVE_OBLIGATION_REFUTED" if direct == "FAIL" else "NATIVE_OBLIGATION_UNAVAILABLE", oid,
                    "Correct the refuted native representation." if direct == "FAIL" else "Retain exact admitted checker/evidence and rerun the native obligation.", status=direct))
            for descendant in sorted(pending):
                if oid in pending[descendant]:
                    pending[descendant].remove(oid)
                    if not pending[descendant]:
                        ready.append(descendant)
        result["obligations"] = [checked[k] for k in sorted(checked)]
        for row in result["ledger"]:
            values = [checked[o]["completion_status"] for o in row["obligation_ids"] if o in checked]
            row["completion_status"] = "FAIL" if "FAIL" in values else "PASS" if values and all(v == "PASS" for v in values) else "UNKNOWN"
            row["evidence"] = sorted({n for o in row["obligation_ids"] if o in checked for n in checked[o]["certificate_nodes"]})
        for nid, observed in native_nodes.items():
            if observed["direct_status"] != "PASS":
                result["diagnostics"].append(_diagnostic("NATIVE_CERTIFICATE_REFUTED" if observed["direct_status"] == "FAIL" else "NATIVE_CERTIFICATE_UNAVAILABLE", "certificate:" + nid,
                    "Resolve the exact native replay failure or missing admitted checker/evidence.", status=observed["direct_status"]))
        edges = derived["edges"] + [{"obligation_id": "certificate:" + e["node_id"], "prerequisite_id": "certificate:" + e["prerequisite_id"]} for e in bundle["edges"]]
        for diagnostic in result["diagnostics"]:
            reachable = {diagnostic["component"]}
            for _ in range(len(edges) + 1):
                prior = set(reachable)
                reachable.update(e["obligation_id"] for e in edges if e["prerequisite_id"] in reachable)
                if reachable == prior:
                    break
            diagnostic["blocked_descendants"] = sorted(reachable - {diagnostic["component"]})
        if derived["status"] == "FAIL" or native["status"] == "FAIL" or any(o["completion_status"] == "FAIL" for o in result["obligations"]):
            result["status"] = "FAIL"
    except (dag._Exhausted, RecursionError, OverflowError):
        result["diagnostics"].append(_diagnostic("COVERAGE_RESOURCE_BOUND_EXHAUSTED", "inputs", "Provide bounded inventory/graph inputs."))
    except (ValueError, TypeError, KeyError, UnicodeError):
        result["status"] = "FAIL"
        result["diagnostics"].append(_diagnostic("COVERAGE_BINDING_REJECTED", component, "Correct malformed or substituted exact coverage bindings.", status="FAIL"))
    result["assessment_digest"] = dag._digest(canonical_bytes(result))
    return result


__all__ = ["namespace_facet_inventory", "native_structural_facet_mapping", "installed_facet_derivation_rules",
           "installed_native_dependency_inventory", "native_dependency_inventory_digest",
           "recheck_native_dependency_inventory", "derive_facet_obligations", "assess_facet_completeness"]

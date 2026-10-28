"""Scoped capability-token semantic projections from retained native contracts.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Commitment anchors do not establish their retained contents or application completeness.
"""
from __future__ import annotations

from typing import Any
from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject

PROPERTY_CHECKS = {
    "selected_capability_token_tenure": "tenure",
    "selected_capability_token_windows": "windows",
    "selected_capability_token_parent_grants": "delegation",
}
REQUIRED_PATHS = {
    "tenure": ("tokens_digest", "epochs_digest", "clock"),
    "windows": ("tokens_digest", "clock", "clock_skew"),
    "delegation": ("tokens_digest", "clock", "root_scopes"),
}
SCOPE = "retained-capability-token-records"
UNIT = "microsecond"
SEMANTIC_VERSION = "verifier-current-object-obligations-1"

PROJECTIONS = [{'name': 'token-kind',
  'projection': {'fields': ['kind', 'token_id'], 'token_filter': 'all'},
  'boundary': 'Documentary birth/aging/lifetime partition; not namespace-kind retyping.',
  'legacy_clauses': ['TOKEN-1.1']},
 {'name': 'birth-seed',
  'projection': {'fields': ['birth_epoch', 'commitment'], 'token_filter': 'kind=birth'},
  'boundary': 'PARTIAL: opaque declared seed/epoch only; genesis opening and controlling-key '
              'existence remain UNKNOWN.',
  'legacy_clauses': ['TOKEN-1.3']},
 {'name': 'aging-head-interval',
  'projection': {'fields': ['birth_token_id',
                            'epoch_start',
                            'epoch_end',
                            'accumulator_digest',
                            'accumulated_epochs',
                            'revocation_status'],
                 'token_filter': 'kind=aging'},
  'boundary': 'Selected recurrence/interval arithmetic; actual continuous survival and '
              'authenticity remain UNKNOWN.',
  'legacy_clauses': ['TOKEN-1.4']},
 {'name': 'lease-scope-quota',
  'projection': {'fields': ['permitted_scopes', 'max_invocations'],
                 'token_filter': 'kind=lifetime'},
  'boundary': 'Declared scope/quota only; no consumed invocation or real authority inference.',
  'legacy_clauses': ['TOKEN-1.5']},
 {'name': 'issuance-declaration',
  'projection': {'fields': ['issuing_key_id', 'issued_at'], 'token_filter': 'all'},
  'boundary': 'PARTIAL: named digest and instant are recorded; no cryptographic issuer binding or '
              'genesis prerequisite is discharged.',
  'legacy_clauses': ['TOKEN-1.6']},
 {'name': 'validity-window',
  'projection': {'fields': ['not_before', 'not_after'], 'token_filter': 'kind=lifetime'},
  'boundary': 'Expiry null is declared unbounded; finite-expiry proof is absent, not waived.',
  'legacy_clauses': ['TOKEN-1.10']},
 {'name': 'replay-identifier',
  'projection': {'fields': ['replay_id'], 'token_filter': 'all'},
  'boundary': 'Distinctness inside selected inventory; no presentation-event or global issuance '
              'uniqueness inference.',
  'legacy_clauses': ['TOKEN-1.11']},
 {'name': 'caveat-set',
  'projection': {'fields': ['caveats'], 'token_filter': 'kind=lifetime'},
  'boundary': 'Declared condition/discharge relation; actual third-party discharge remains '
              'UNKNOWN.',
  'legacy_clauses': ['TOKEN-1.13']},
 {'name': 'parent-grant-relation',
  'projection': {'fields': ['parent_grant_id'], 'token_filter': 'kind=lifetime'},
  'boundary': 'Source-defined retained relation; full application-facet admission remains UNKNOWN.',
  'legacy_clauses': ['TOKEN-4.3']},
 {'name': 'soulbound-delegate',
  'projection': {'fields': ['soulbound', 'delegate_key_id'], 'token_filter': 'kind=lifetime'},
  'boundary': 'PARTIAL: native conditional declared-soulbound invariant; full normative '
              'mandatory-soulbound lifetime construction remains UNKNOWN.',
  'legacy_clauses': ['TOKEN-3.4']}]
RULE_ORIGINS = {'selected_capability_token_tenure': ['token-kind',
                                      'birth-seed',
                                      'aging-head-interval',
                                      'issuance-declaration',
                                      'replay-identifier'],
 'selected_capability_token_windows': ['token-kind',
                                       'lease-scope-quota',
                                       'validity-window',
                                       'issuance-declaration',
                                       'replay-identifier'],
 'selected_capability_token_parent_grants': ['token-kind',
                                             'birth-seed',
                                             'lease-scope-quota',
                                             'validity-window',
                                             'caveat-set',
                                             'parent-grant-relation',
                                             'soulbound-delegate',
                                             'replay-identifier']}

def native_token_facet_mapping(objects: list[NamespaceObject]) -> dict[str, Any]:
    """Project ten partial semantic origins; actual retained values need native replay."""
    from verifier.domains.contracts import facet_coverage as coverage, certificate_dag as dag
    inventory = coverage.namespace_facet_inventory(objects)
    structural = coverage.native_structural_facet_mapping(objects)
    rules = {r["property_id"]: r for r in coverage.installed_facet_derivation_rules()["rules"]
             if r["property_id"] in PROPERTY_CHECKS}
    projection = {r["facet_id"]: set(r["properties"]) for r in structural["field_projection"]}
    rows, interactions, diagnostics = [], [], []
    for item in sorted(objects, key=lambda o: o.object_id):
        if item.kind.value != "TOKEN":
            continue
        record = item.to_dict()
        payload = record["payload"]
        if (type(payload) is not dict or payload.get("scope") != SCOPE
                or payload.get("clock_unit") != UNIT):
            diagnostics.append({"object_id": item.object_id, "status": "UNKNOWN",
                                "code": "TOKEN_SCOPE_OR_UNIT_UNSUPPORTED"})
            continue
        fields = {tuple(f["path"]): f for f in inventory["facets"] if f["object_id"] == item.object_id}
        anchor = fields.get(("payload", "artifact", "tokens_digest"))
        if anchor is None:
            diagnostics.append({"object_id": item.object_id, "status": "UNKNOWN",
                                "code": "TOKEN_RETAINED_INVENTORY_ANCHOR_MISSING"})
            continue
        eligible = {}
        for prop, check in PROPERTY_CHECKS.items():
            paths = [("payload", "artifact", name) for name in REQUIRED_PATHS[check]]
            if any(path not in fields for path in paths):
                diagnostics.append({"object_id": item.object_id, "property_id": prop,
                                    "status": "UNKNOWN", "code": "TOKEN_PROPERTY_ANCHOR_MISSING"})
                continue
            eligible[prop] = rules[prop]
            projection[anchor["facet_id"]].add(prop)
            other_name = {"tenure": "epochs_digest", "windows": "clock_skew",
                          "delegation": "root_scopes"}[check]
            other = fields[("payload", "artifact", other_name)]
            interactions.append({"interaction_id": item.object_id + ":retained-token:" + check,
                "facet_ids": sorted([anchor["facet_id"], other["facet_id"]]), "properties": [prop]})
        for definition in PROJECTIONS:
            props = sorted(prop for prop, rule in eligible.items()
                           if definition["name"] in RULE_ORIGINS[prop])
            rows.append({"semantic_facet_id": dag._digest(canonical_bytes(
                    [item.object_id, SEMANTIC_VERSION, definition["name"]])),
                "semantic_facet_name": definition["name"], "semantic_version": SEMANTIC_VERSION,
                "object_id": item.object_id, "object_kind": "TOKEN", "record_digest": item.digest,
                "namespace_field_ids": [anchor["facet_id"]],
                "retained_container": ["inputs", "tokens"],
                "retained_projection": definition["projection"],
                "source_clause_coordinates": definition["legacy_clauses"],
                "semantic_boundary": definition["boundary"],
                "properties": props,
                "native_obligations": [output for prop in props for output in eligible[prop]["outputs"]],
                "specification_sources": [source for prop in props for source in eligible[prop]["sources"]],
                "retained_contents_established": "NOT_ESTABLISHED",
                "application_semantic_completeness": "UNKNOWN"})
    specification = {"schema_version": coverage.SPECIFICATION,
        "specification_id": "retained-capability-token-partial-projections",
        "specification_version": "1",
        "facets": [{"facet_id": fid, "properties": sorted(props)}
                   for fid, props in sorted(projection.items())],
        "interactions": interactions}
    return {"schema_version": "verifier-native-token-facet-mapping-1", "mapping_version": "1",
        "namespace_inventory_digest": dag._digest(canonical_bytes(inventory)),
        "scope": SCOPE, "clock_unit": UNIT, "semantic_facets": rows,
        "known_partial_semantic_projections": len(rows), "specification": specification,
        "diagnostics": diagnostics, "full_application_facet_denominator": None,
        "interaction_inventory_completeness": "UNKNOWN", "application_mapping_authority": "UNKNOWN",
        "production_profile_approval": "NOT_ESTABLISHED"}

__all__ = ["native_token_facet_mapping"]

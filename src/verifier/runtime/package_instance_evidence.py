"""Exact package-instance certificate selection for Verifier Standard (VSTD).

Only installed native routes execute. No subject command, module name or claimed
verdict is accepted from the manifest. Retained replay establishes its registered
bounded proposition, never actual execution, domain completeness or authority.
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import base64
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import current_object_routes as routes
from verifier.runtime import added_kind_behavioral_routes
from verifier.runtime.namespace_contracts import KindContract, ancestors
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest
from verifier.runtime.self_polish_estate import bytes_digest


FIELDS = {"object_id", "coordinate", "semantic_version", "proposition_digest", "reason",
          "evidence", "request", "policy", "certificate"}
STRUCTURAL = {"generic_canonical_representation_and_address", "finite_kind_specific_declared_operand_facets"}
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PACKAGE_GRAPH_PAYLOAD_FIELDS = {
    "element_kind", "scope", "nodes_digest", "edges_digest",
    "source_refresh_coordinate", "source_semantic_profile",
}
_GRAPH_STATICS_PAYLOAD_FIELDS = {
    "element_kind", "scope", "nodes_digest", "edges_digest",
}
_SOURCE_SEMANTIC_PROFILE_FIELDS = {
    "schema_version", "reason", "binding_sets", "records", "digest",
}
_CONSEQUENCE_PROJECTION_SCHEMA = "verifier-package-consequence-projection-1"
_CONSEQUENCE_REQUEST_SCHEMA = "verifier-package-consequence-request-1"
_CONSEQUENCE_CERTIFICATE_SCHEMA = "verifier-package-consequence-certificate-1"
_CONSEQUENCE_ROLES = {
    "ROBOT": "REAL_PHYSICAL",
    "FINBOT": "REAL_FINANCIAL",
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    _require(bool(value) and bool(path.parts) and len(value) <= 1024 and "\\" not in value and ":" not in value
             and not path.is_absolute() and str(path) == value and ".." not in path.parts
             and path.name != "objects.vstd" and path.parts != (".",), "PACKAGE_INSTANCE_PATH_INVALID")
    return path


def _source_semantic_profile(value: Any) -> dict[str, Any]:
    """Validate the selected source profile without importing migration code.

    ``package_manifest_migration`` imports this module for ``STRUCTURAL``.  A
    reverse import here would make the package-graph replay depend on import
    order, so the small wire contract is checked locally instead.
    """

    _require(
        type(value) is dict and set(value) == _SOURCE_SEMANTIC_PROFILE_FIELDS,
        "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
    )
    profile = dict(value)
    claimed = profile.pop("digest")
    _require(
        value.get("schema_version") == "verifier-source-semantic-review-profile-1"
        and type(value.get("reason")) is str
        and bool(value["reason"].strip())
        and type(value.get("binding_sets")) is list
        and type(value.get("records")) is list
        and type(claimed) is str
        and _HASH.fullmatch(claimed) is not None
        and claimed == value_digest(profile),
        "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
    )
    decoded_sets = []
    binding_digests = []
    for encoded in value["binding_sets"]:
        _require(
            type(encoded) is str,
            "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
        )
        try:
            bindings = strict_json_loads(encoded)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(
                "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID"
            ) from exc
        _require(
            type(bindings) is list
            and canonical_bytes(bindings).decode("utf-8") == encoded,
            "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
        )
        for binding in bindings:
            _require(
                type(binding) is dict
                and set(binding) == {
                    "object_id", "classifications", "obligations",
                }
                and type(binding["object_id"]) is str
                and bool(binding["object_id"])
                and all(
                    type(binding[field]) is list
                    and binding[field] == sorted(set(binding[field]))
                    and all(type(entry) is str and bool(entry) for entry in binding[field])
                    for field in ("classifications", "obligations")
                ),
                "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
            )
        decoded_sets.append(bindings)
        binding_digests.append(value_digest(bindings))
    _require(
        binding_digests == sorted(set(binding_digests)),
        "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
    )
    paths = []
    for record in value["records"]:
        _require(
            type(record) is str,
            "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
        )
        parts = record.split("\t")
        _require(
            len(parts) == 4,
            "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
        )
        path, semantic_kind, semantic_digest, binding_index_text = parts
        try:
            binding_index = int(binding_index_text)
        except ValueError as exc:
            raise ValueError(
                "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID"
            ) from exc
        pure = PurePosixPath(path)
        _require(
            bool(path)
            and not pure.is_absolute()
            and ".." not in pure.parts
            and "\\" not in path
            and semantic_kind in {"python-location-free-ast", "byte-exact"}
            and _HASH.fullmatch(semantic_digest) is not None
            and str(binding_index) == binding_index_text
            and 0 <= binding_index < len(decoded_sets),
            "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
        )
        paths.append(path)
    _require(
        paths == sorted(set(paths)),
        "PACKAGE_GRAPH_SOURCE_SEMANTIC_PROFILE_INVALID",
    )
    return dict(value)


def _ordered_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic records without accepting duplicate encodings."""
    encoded = [(canonical_bytes(row), row) for row in rows]
    encoded.sort(key=lambda item: item[0])
    _require(
        len({raw for raw, _ in encoded}) == len(encoded),
        "PACKAGE_INSTANCE_CONSEQUENCE_RECORD_DUPLICATED",
    )
    return [dict(row) for _, row in encoded]


def _consequence_denominator(
    objects: tuple[NamespaceObject, ...], rows: list[dict[str, Any]],
) -> None:
    """Bind the projection rows to the same objects as the collection digest."""
    declared = {row.get("object_id"): row for row in rows if type(row) is dict}
    selected = {item.object_id: item for item in objects}
    _require(
        len(declared) == len(rows) == len(selected) == len(objects)
        and set(declared) == set(selected),
        "PACKAGE_INSTANCE_CONSEQUENCE_DENOMINATOR_DIFFERS",
    )
    for identifier, item in selected.items():
        row = declared[identifier]
        _require(
            {
                "object_id": row.get("object_id"),
                "kind": row.get("kind"),
                "payload": row.get("payload"),
                "operands": row.get("operands"),
            } == item.to_dict(),
            "PACKAGE_INSTANCE_CONSEQUENCE_DENOMINATOR_DIFFERS",
        )


def _consequence_projection(
    rows: list[dict[str, Any]], graph: Any, *, subject_id: str, role: str
) -> dict[str, Any]:
    """Project the exact package object and consequence-edge denominator.

    The retained domain check may assess a self-consistent graph.  Package
    conformance additionally requires that graph to be the one admitted by the
    current manifest, rather than a second graph carried only by the certificate.
    """
    from verifier.runtime import namespace_consequences

    if graph is None:
        raise OSError("PACKAGE_INSTANCE_CONSEQUENCE_GRAPH_UNAVAILABLE")
    _require(role in _CONSEQUENCE_ROLES, "PACKAGE_INSTANCE_CONSEQUENCE_ROLE_INVALID")
    _require(type(rows) is list and bool(rows), "PACKAGE_INSTANCE_CONSEQUENCE_OBJECTS_UNAVAILABLE")
    by_id: dict[str, dict[str, Any]] = {}
    objects = []
    for row in rows:
        _require(
            type(row) is dict
            and type(row.get("object_id")) is str
            and row["object_id"] not in by_id
            and type(row.get("kind")) is str
            and type(row.get("specializations", [])) is list
            and all(type(value) is str for value in row.get("specializations", []))
            and len(row.get("specializations", []))
                == len(set(row.get("specializations", [])))
            and type(row.get("classification", {})) is dict
            and type(row.get("surfaces", [])) is list
            and all(type(value) is str for value in row.get("surfaces", []))
            and len(row.get("surfaces", [])) == len(set(row.get("surfaces", [])))
            and type(row.get("payload", {})) is dict
            and type(row.get("operands", {})) is dict
            and all(
                type(name) is str
                and type(targets) is list
                and all(type(target) is str for target in targets)
                and len(targets) == len(set(targets))
                for name, targets in row.get("operands", {}).items()
            ),
            "PACKAGE_INSTANCE_CONSEQUENCE_OBJECT_INVALID",
        )
        by_id[row["object_id"]] = row
        objects.append({
            "object_id": row["object_id"],
            "kind": row["kind"],
            "payload": row.get("payload", {}),
            "specializations": sorted(row.get("specializations", [])),
            "classification": row.get("classification", {}),
            "surfaces": sorted(row.get("surfaces", [])),
            "operands": {
                name: list(targets)
                for name, targets in sorted(row.get("operands", {}).items())
            },
        })
    _require(subject_id in by_id, "PACKAGE_INSTANCE_CONSEQUENCE_SUBJECT_UNBOUND")
    labels = {by_id[subject_id]["kind"], *by_id[subject_id].get("specializations", [])}
    labels.update(
        kind
        for kind, decision in by_id[subject_id].get("classification", {}).items()
        if type(decision) is dict and decision.get("status") == "APPLIES"
    )
    _require(role in labels, "PACKAGE_INSTANCE_CONSEQUENCE_ROLE_UNBOUND")
    namespace_consequences.validate_graph(graph, set(by_id))
    edges = _ordered_records(graph["edges"])
    effects = _ordered_records(graph["effects"])
    objects = _ordered_records(objects)
    projection = {
        "schema_version": _CONSEQUENCE_PROJECTION_SCHEMA,
        "subject_id": subject_id,
        "role": role,
        "domain": _CONSEQUENCE_ROLES[role],
        "object_count": len(objects),
        "edge_count": len(edges),
        "effect_count": len(effects),
        "objects_digest": value_digest(objects),
        "edges_digest": value_digest(edges),
        "effects_digest": value_digest(effects),
    }
    projection["digest"] = value_digest(projection)
    return projection


def _consequence_bundle(certificate: bytes) -> dict[str, Any]:
    """Extract already-rechecked native evidence for package correspondence."""
    envelope = strict_json_loads(certificate.decode("utf-8"))
    _require(type(envelope) is dict, "PACKAGE_INSTANCE_CONSEQUENCE_CERTIFICATE_INVALID")
    payload = envelope.get("evidence_payload")
    _require(type(payload) is str, "PACKAGE_INSTANCE_CONSEQUENCE_EVIDENCE_UNAVAILABLE")
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
        evidence = strict_json_loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("PACKAGE_INSTANCE_CONSEQUENCE_EVIDENCE_INVALID") from exc
    _require(
        type(evidence) is dict and type(evidence.get("consequence_bundle")) is dict,
        "PACKAGE_INSTANCE_CONSEQUENCE_EVIDENCE_INVALID",
    )
    return evidence["consequence_bundle"]


def _consequence_binding(
    *, item: NamespaceObject, collection_digest: str, native_request: dict[str, Any],
    native_certificate: bytes, package_projection: dict[str, Any],
    retained_projection: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build and independently recheck the package-only adaptation receipt."""
    request = {
        "schema_version": _CONSEQUENCE_REQUEST_SCHEMA,
        "subject_id": item.object_id,
        "object_digest": item.digest,
        "collection_digest": collection_digest,
        "role": package_projection["role"],
        "domain": package_projection["domain"],
        "projection_digest": package_projection["digest"],
        "object_count": package_projection["object_count"],
        "edge_count": package_projection["edge_count"],
        "effect_count": package_projection["effect_count"],
        "native_request_digest": value_digest(native_request),
    }
    certificate = {
        "schema_version": _CONSEQUENCE_CERTIFICATE_SCHEMA,
        "request": request,
        "native_certificate_digest": bytes_digest(native_certificate),
        "retained_projection_digest": retained_projection["digest"],
        "retained_object_count": retained_projection["object_count"],
        "retained_edge_count": retained_projection["edge_count"],
        "retained_effect_count": retained_projection["effect_count"],
        "status": "PASS" if retained_projection == package_projection else "FAIL",
    }
    certificate["digest"] = value_digest(certificate)
    _recheck_consequence_binding(
        certificate, expected_request=request,
        native_certificate=native_certificate,
        package_projection=package_projection,
        retained_projection=retained_projection,
    )
    return request, certificate


def _recheck_consequence_binding(
    certificate: Any, *, expected_request: dict[str, Any],
    native_certificate: bytes, package_projection: dict[str, Any],
    retained_projection: dict[str, Any],
) -> None:
    """Reject stale or transplanted package consequence commitments."""
    fields = {
        "schema_version", "request", "native_certificate_digest",
        "retained_projection_digest", "retained_object_count",
        "retained_edge_count", "retained_effect_count", "status", "digest",
    }
    _require(
        type(certificate) is dict and set(certificate) == fields,
        "PACKAGE_INSTANCE_CONSEQUENCE_CERTIFICATE_INVALID",
    )
    unsigned = {key: value for key, value in certificate.items() if key != "digest"}
    _require(
        certificate["schema_version"] == _CONSEQUENCE_CERTIFICATE_SCHEMA
        and certificate["digest"] == value_digest(unsigned),
        "PACKAGE_INSTANCE_CONSEQUENCE_CERTIFICATE_DIGEST_DIFFERS",
    )
    _require(
        certificate["request"] == expected_request,
        "PACKAGE_INSTANCE_CONSEQUENCE_REQUEST_DIFFERS",
    )
    _require(
        certificate["native_certificate_digest"] == bytes_digest(native_certificate),
        "PACKAGE_INSTANCE_CONSEQUENCE_NATIVE_CERTIFICATE_DIFFERS",
    )
    _require(
        expected_request["projection_digest"] == package_projection["digest"]
        and expected_request["object_count"] == package_projection["object_count"]
        and expected_request["edge_count"] == package_projection["edge_count"]
        and expected_request["effect_count"] == package_projection["effect_count"],
        "PACKAGE_INSTANCE_CONSEQUENCE_REQUEST_STALE",
    )
    _require(
        certificate["retained_projection_digest"] == retained_projection["digest"]
        and certificate["retained_object_count"] == retained_projection["object_count"]
        and certificate["retained_edge_count"] == retained_projection["edge_count"]
        and certificate["retained_effect_count"] == retained_projection["effect_count"],
        "PACKAGE_INSTANCE_CONSEQUENCE_RETAINED_BINDING_DIFFERS",
    )
    _require(
        certificate["status"] == "PASS" and retained_projection == package_projection,
        "PACKAGE_INSTANCE_CONSEQUENCE_PROJECTION_DIFFERS",
    )


def validate_checks(checks: Any, rows: list[dict[str, Any]], registry: dict[str, KindContract]) -> None:
    """Validate selection identities without reading subject files or running code."""
    _require(type(checks) is list and len(checks) <= 4096, "PACKAGE_INSTANCE_SELECTION_COUNT_INVALID")
    by_id = {row["object_id"]: row for row in rows}
    seen = set()
    for check in checks:
        _require(type(check) is dict and set(check) == FIELDS, "PACKAGE_INSTANCE_SELECTION_FIELDS")
        _require(all(type(check[name]) is str for name in ("object_id", "coordinate", "semantic_version", "proposition_digest", "reason")),
                 "PACKAGE_INSTANCE_SELECTION_TEXT_INVALID")
        _require(check["object_id"] in by_id, "PACKAGE_INSTANCE_OBJECT_UNBOUND")
        _require(re.fullmatch(r"[A-Z]+-[1-3]\.[1-9][0-9]*", check["coordinate"]) is not None,
                 "PACKAGE_INSTANCE_COORDINATE_UNSUPPORTED")
        identity = check["object_id"], check["coordinate"]
        _require(identity not in seen, "PACKAGE_INSTANCE_SELECTION_DUPLICATED")
        seen.add(identity)
        row = by_id[check["object_id"]]
        kind = ancestors(registry, row["kind"])[-1]
        added = added_kind_behavioral_routes.select_package_route(
            semantic_version=check["semantic_version"],
            coordinate=check["coordinate"],
        )
        if added is not None:
            declared = {row["kind"], *row.get("specializations", [])}
            _require(
                added["object_kind"] in declared,
                "PACKAGE_INSTANCE_ADDED_KIND_NOT_EXPLICIT",
            )
            _require(
                check["proposition_digest"] == added["proposition_digest"],
                "PACKAGE_INSTANCE_PROPOSITION_DIFFERS",
            )
        else:
            selected = routes.select_current_object_route(
                semantic_version=check["semantic_version"],
                objective=check["coordinate"], represented_kind=kind,
            )
            _require(check["proposition_digest"] == selected.module.PROPOSITION_DIGEST,
                     "PACKAGE_INSTANCE_PROPOSITION_DIFFERS")
        _require(type(check["evidence"]) is list and len(check["evidence"]) <= 256,
                 "PACKAGE_INSTANCE_SOURCE_REFERENCES_INVALID")
        refs = [check[name] for name in ("request", "policy", "certificate")] + check["evidence"]
        for ref in refs:
            _require(type(ref) is dict and set(ref) == {"path", "sha256"}
                     and type(ref["path"]) is str and type(ref["sha256"]) is str
                     and _HASH.fullmatch(ref["sha256"]) is not None, "PACKAGE_INSTANCE_REFERENCE_INVALID")
            _path(ref["path"])


class InstanceEvidence:
    """One assessment's bounded byte snapshot, with a mandatory closing recapture.

    Shared files are read once per assessment, not once per route. This cache is
    never persisted or reused across source coordinates. Recapture bypasses it.
    """

    def __init__(self, root: Path, objects: tuple[NamespaceObject, ...], declaration: dict[str, Any], *,
                 package_graph_id: str | None = None,
                 representation_updates: list[dict[str, Any]] | None = None) -> None:
        self.root = root.resolve(strict=True)
        self.objects = objects
        self.package_graph_id = package_graph_id
        self.representations = {row["object_id"]: row for row in representation_updates or []}
        self.collection_digest = composition_digest(objects)
        self.declaration_rows = declaration.get("objects", [])
        self.rows = {row["object_id"]: row for row in self.declaration_rows}
        self.consequence_graph = declaration.get("consequence_graph")
        self.checks = {(row["object_id"], row["coordinate"]): row for row in declaration.get("instance_checks", [])}
        # A composite object can require several independently selected workers.
        # Both successful observations and failures belong to the exact pair.
        self.execution_checks = {(row["object_id"], row["mechanism"]): row
                                 for row in declaration.get("execution_checks", [])}
        self.executions: dict[tuple[str, str], dict[str, Any]] = {}
        self.execution_failures: dict[tuple[str, str], dict[str, str]] = {}
        self.execution_transports: dict[tuple[str, str], dict[str, Any]] = {}
        self.captured: dict[str, tuple[str, bytes]] = {}
        self.used_bytes = 0

    def _read(self, ref: dict[str, str], limit: int) -> bytes:
        relative = _path(ref["path"])
        current = self.root
        for part in relative.parts:
            current = current / part
            info = current.lstat()
            # Reject symbolic links and Windows reparse points, including parent
            # junctions. An apparently relative spelling is not containment.
            _require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                     "PACKAGE_INSTANCE_PATH_INDIRECT")
        _require(stat.S_ISREG(info.st_mode), "PACKAGE_INSTANCE_FILE_NOT_REGULAR")
        _require(current.resolve(strict=True).is_relative_to(self.root), "PACKAGE_INSTANCE_PATH_ESCAPES_ROOT")
        if info.st_size > limit:
            raise OSError("PACKAGE_INSTANCE_EVIDENCE_CAPACITY")
        with current.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise OSError("PACKAGE_INSTANCE_EVIDENCE_CAPACITY")
        _require(bytes_digest(raw) == ref["sha256"], "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS")
        return raw

    def read(self, ref: dict[str, str]) -> bytes:
        if ref["path"] not in self.captured:
            limit = min(MAX_ARTIFACT_BYTES, MAX_TOTAL_BYTES - self.used_bytes)
            if limit <= 0:
                raise OSError("PACKAGE_INSTANCE_EVIDENCE_CAPACITY")
            raw = self._read(ref, limit)
            self.captured[ref["path"]] = ref["sha256"], raw
            self.used_bytes += len(raw)
        expected, raw = self.captured[ref["path"]]
        _require(ref["sha256"] == expected, "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS")
        return raw

    def recapture(self) -> None:
        """Ignored/untracked selected files also participate in closing freshness."""
        for path, (digest, before) in self.captured.items():
            after = self._read({"path": path, "sha256": digest}, MAX_ARTIFACT_BYTES)
            _require(after == before, "PACKAGE_INSTANCE_EVIDENCE_CHANGED")

    def _document(self, ref: dict[str, str]) -> dict[str, Any]:
        raw = self.read(ref)
        value = strict_json_loads(raw.decode("utf-8"))
        _require(type(value) is dict and raw in (canonical_bytes(value), canonical_bytes(value) + b"\n"),
                 "PACKAGE_INSTANCE_INPUT_NOT_CANONICAL")
        return value

    def _fresh_package_graph(
        self, item: NamespaceObject, route: dict[str, Any]
    ) -> dict[str, Any]:
        """Project and replay the current package GRAPH without stale artifacts.

        The package GRAPH carries source-refresh metadata that is deliberately
        outside GRAPH-3.1's four-field statics proposition.  Keep the complete
        current record and collection bound in the adapter receipt, but give
        the unchanged native checker only the exact projection it specifies.
        """

        from verifier.domains.contracts import graph_statics
        from verifier.runtime.package_graph_representation import dependency_inputs

        payload = dict(item.payload)
        _require(
            set(payload) == _PACKAGE_GRAPH_PAYLOAD_FIELDS,
            "PACKAGE_GRAPH_PAYLOAD_FIELDS_DIFFER",
        )
        _require(
            payload["element_kind"] == "OBJECT"
            and payload["scope"] == "retained_directed_graph"
            and all(
                type(payload[field]) is str
                and _HASH.fullmatch(payload[field]) is not None
                for field in ("nodes_digest", "edges_digest")
            ),
            "PACKAGE_GRAPH_STATICS_PAYLOAD_INVALID",
        )
        _require(
            type(payload["source_refresh_coordinate"]) is str
            and _HASH.fullmatch(payload["source_refresh_coordinate"]) is not None,
            "PACKAGE_GRAPH_SOURCE_REFRESH_COORDINATE_INVALID",
        )
        semantic_profile = _source_semantic_profile(
            payload["source_semantic_profile"]
        )

        # The representation update is the source-owned basis for projecting
        # this exact record.  It remains checked, while stale GRAPH-3.1
        # request/policy/certificate files are intentionally never opened.
        owned = {
            surface.split(":", 2)[1]
            for surface in self.rows[item.object_id]["surfaces"]
            if surface.startswith(("file:", "python:"))
        }
        update = self.representations.get(item.object_id)
        if (
            update is None
            or update.get("current_object_digest") != item.digest
            or not update.get("evidence")
            or not any(ref["path"] in owned for ref in update["evidence"])
        ):
            raise OSError("PACKAGE_REPRESENTATION_OWNED_SOURCE_UNAVAILABLE")
        for ref in update["evidence"]:
            self.read(ref)

        inputs = dependency_inputs(self.objects, item.object_id)
        nodes_digest = value_digest(inputs["nodes"])
        edges_digest = value_digest(inputs["edges"])
        _require(
            payload["nodes_digest"] == nodes_digest
            and payload["edges_digest"] == edges_digest,
            "PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS",
        )
        projected_payload = {
            field: payload[field] for field in _GRAPH_STATICS_PAYLOAD_FIELDS
        }
        projected_graph = NamespaceObject.create(
            item.object_id, item.kind.value, projected_payload, dict(item.operands)
        )
        projected_objects = tuple(
            projected_graph if candidate.object_id == item.object_id else candidate
            for candidate in self.objects
        )
        _require(
            sum(candidate.object_id == item.object_id for candidate in self.objects)
            == 1,
            "PACKAGE_GRAPH_SUBJECT_INVALID",
        )
        projected_collection_digest = composition_digest(projected_objects)
        policy = graph_statics.graph_statics_policy(
            trust_roots=["fresh-package-graph-projection-not-external-authority"]
        )
        evidence = canonical_bytes({
            "schema_version": graph_statics.EVIDENCE_VERSION,
            "objects": [candidate.to_dict() for candidate in projected_objects],
            "inputs": inputs,
        })
        request = graph_statics.graph_statics_request(
            subject_id=projected_graph.object_id,
            object_digest=projected_graph.digest,
            collection_digest=projected_collection_digest,
            nodes_digest=nodes_digest,
            edges_digest=edges_digest,
            evidence_ref=bytes_digest(evidence),
            policy=policy,
        )
        certificate = graph_statics.build_graph_statics_certificate(
            request, evidence, policy=policy
        )
        independent = graph_statics.recheck_graph_statics_certificate(
            certificate, expected_request=request, policy=policy
        )
        replay = routes.replay_current_object_certificate(
            certificate,
            semantic_version=route["semantic_version"],
            objective=route["coordinate"],
            represented_kind=item.kind.value,
            expected_request=request,
            policy=policy,
        )
        _require(
            replay.get("native_result") == independent,
            "PACKAGE_GRAPH_INDEPENDENT_RECHECK_DIFFERS",
        )

        adaptation_reason = (
            "The exact package-root GRAPH carries source-refresh bindings in "
            "addition to its GRAPH-3.1 statics payload. The adapter retains the "
            "complete current object and collection digests while projecting "
            "only the native checker's four declared graph-static fields."
        )
        claim_boundary = (
            "Fresh deterministic projection of the exact selected package "
            "GRAPH and its declared operand dependencies only. The source "
            "refresh coordinate and semantic profile remain bound by the "
            "original object and collection digests but are not interpreted "
            "by GRAPH-3.1. This establishes neither source authenticity, "
            "runtime causality, external authority nor whole-tier conformance."
        )
        selection = {
            "schema_version": "verifier-package-graph-projection-selection-1",
            "coordinate": route["coordinate"],
            "semantic_version": route["semantic_version"],
            "proposition_digest": route["proposition_digest"],
            "original_object_digest": item.digest,
            "original_collection_digest": self.collection_digest,
            "projected_object_digest": projected_graph.digest,
            "projected_collection_digest": projected_collection_digest,
            "nodes_digest": nodes_digest,
            "edges_digest": edges_digest,
            "source_refresh_coordinate": payload["source_refresh_coordinate"],
            "source_semantic_profile_digest": semantic_profile["digest"],
            "evidence_digest": bytes_digest(evidence),
            "request_digest": value_digest(request),
            "policy_digest": value_digest(policy),
            "certificate_digest": bytes_digest(certificate),
            "adaptation_reason": adaptation_reason,
            "claim_boundary": claim_boundary,
        }
        selection_digest = value_digest(selection)
        result = {
            "schema_version": "verifier-package-graph-fresh-adapter-1",
            "adapter_id": "verifier-fresh-package-graph-statics-projection-1",
            "status": replay["computational_status"],
            "object_id": item.object_id,
            "object_digest": item.digest,
            "collection_digest": self.collection_digest,
            "coordinate": route["coordinate"],
            "semantic_version": route["semantic_version"],
            "proposition_digest": route["proposition_digest"],
            "checking_mechanism": route["checking_mechanism"],
            "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
            "selection": selection,
            "selection_digest": selection_digest,
            "replay": replay,
            "reason": adaptation_reason,
            "adaptation_reason": adaptation_reason,
            "claim_boundary": claim_boundary,
            "applicability_established": True,
            "applicability_reason": (
                "The selected package root declares a retained directed "
                "dependency GRAPH. Its current node and edge commitments must "
                "cover every selected member and operand reference."
            ),
        }
        result["result_digest"] = value_digest(result)
        return result

    def _added_kind_behavioral(
        self, item: NamespaceObject, route: dict[str, Any], check: dict[str, Any]
    ) -> dict[str, Any]:
        """Replay one explicitly typed retained MARKET, ROBOT, FINBOT, or POLICY check."""
        result: dict[str, Any] = {
            "schema_version": "verifier-package-added-kind-instance-1",
            "adapter_id": route["adapter"],
            "status": "UNKNOWN",
            "object_id": item.object_id,
            "object_digest": item.digest,
            "collection_digest": self.collection_digest,
            "coordinate": route["coordinate"],
            "obligation_id": route["obligation_id"],
            "semantic_version": route["semantic_version"],
            "proposition_digest": route["proposition_digest"],
            "checking_mechanism": route["checking_mechanism"],
            "evidence_origin": "MANIFEST_SELECTED_ADDED_KIND_INSTANCE",
            "selection_digest": value_digest(check),
            "selection": check,
            "replay": None,
            "reason": "Selected added-kind evidence has not yet been replayed.",
            "applicability_established": False,
        }
        try:
            _require(
                added_kind_behavioral_routes.is_route(route),
                "PACKAGE_INSTANCE_ADDED_ROUTE_DIFFERS",
            )
            _require(
                all(
                    check[name] == route[name]
                    for name in ("coordinate", "semantic_version", "proposition_digest")
                ),
                "PACKAGE_INSTANCE_ROUTE_DIFFERS",
            )
            declaration = self.rows[item.object_id]
            declared = {
                declaration["kind"], *declaration.get("specializations", [])
            }
            _require(
                route["object_kind"] in declared,
                "PACKAGE_INSTANCE_ADDED_KIND_NOT_EXPLICIT",
            )
            if not check["reason"].strip() or not check["evidence"]:
                raise OSError("PACKAGE_INSTANCE_SOURCE_REASON_UNAVAILABLE")
            owned = {
                surface.split(":", 2)[1]
                for surface in declaration["surfaces"]
                if surface.startswith(("file:", "python:"))
            }
            owned_refs = [
                ref for ref in check["evidence"] if ref["path"] in owned
            ]
            _require(
                bool(owned_refs), "PACKAGE_INSTANCE_ADDED_SOURCE_UNOWNED"
            )
            for ref in check["evidence"]:
                self.read(ref)
            request = self._document(check["request"])
            policy = self._document(check["policy"])
            certificate = self.read(check["certificate"])
            _require(
                request.get("coordinate") == route["obligation_id"]
                and request.get("semantic_version") == route["semantic_version"]
                and request.get("proposition_digest")
                    == route["proposition_digest"]
                and request.get("object_kind") == route["object_kind"],
                "PACKAGE_INSTANCE_REQUEST_ROUTE_DIFFERS",
            )
            _require(
                request.get("subject_id") == item.object_id,
                "PACKAGE_INSTANCE_SUBJECT_OR_GRAPH_DIFFERS",
            )
            _require(
                request.get("source_digest")
                    in {ref["sha256"] for ref in owned_refs},
                "PACKAGE_INSTANCE_ADDED_SOURCE_DIFFERS",
            )
            replay = added_kind_behavioral_routes.recheck_package_certificate(
                route, certificate, expected_request=request, policy=policy,
            )
            selection: dict[str, Any] = check
            if route["object_kind"] in _CONSEQUENCE_ROLES:
                _consequence_denominator(self.objects, self.declaration_rows)
                package_projection = _consequence_projection(
                    list(self.rows.values()), self.consequence_graph,
                    subject_id=item.object_id, role=route["object_kind"],
                )
                bundle = _consequence_bundle(certificate)
                retained_projection = _consequence_projection(
                    bundle.get("rows"), bundle.get("graph"),
                    subject_id=item.object_id, role=route["object_kind"],
                )
                binding_request, binding_certificate = _consequence_binding(
                    item=item, collection_digest=self.collection_digest,
                    native_request=request, native_certificate=certificate,
                    package_projection=package_projection,
                    retained_projection=retained_projection,
                )
                selection = {
                    "schema_version": "verifier-package-consequence-selection-1",
                    "manifest_check": check,
                    "manifest_check_digest": value_digest(check),
                    "projection": package_projection,
                    "request": binding_request,
                    "certificate": binding_certificate,
                }
            reason = replay.get("evaluation", {}).get("reason")
            _require(
                type(reason) is str and bool(reason.strip()),
                "PACKAGE_INSTANCE_ADDED_REPLAY_REASON_MISSING",
            )
            result.update(
                status=replay["status"], replay=replay, reason=reason,
                selection=selection, selection_digest=value_digest(selection),
                applicability_established=True,
                applicability_reason=(
                    "The manifest explicitly assigns the selected object the "
                    f"{route['object_kind']} role, binds the exact current owned "
                    "source, request, policy and certificate bytes, and selects "
                    "this retained behavioral proposition."
                ),
            )
        except (OSError, ImportError, MemoryError, RecursionError) as exc:
            reason = str(exc)
            result.update(
                status="UNKNOWN",
                reason=(
                    reason if reason.startswith("PACKAGE_")
                    else type(exc).__name__
                ),
            )
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
            result.update(status="FAIL", reason=str(exc) or type(exc).__name__)
        result["result_digest"] = value_digest(result)
        return result

    def evaluate(self, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
        package_graph = (
            route["coordinate"] == "GRAPH-3.1"
            and item.object_id == self.package_graph_id
            and any(
                field in item.payload
                for field in (
                    "source_refresh_coordinate", "source_semantic_profile",
                )
            )
        )
        if package_graph:
            result: dict[str, Any] = {
                "schema_version": "verifier-package-graph-fresh-adapter-1",
                "adapter_id": "verifier-fresh-package-graph-statics-projection-1",
                "status": "UNKNOWN",
                "object_id": item.object_id,
                "object_digest": item.digest,
                "collection_digest": self.collection_digest,
                "coordinate": route["coordinate"],
                "semantic_version": route["semantic_version"],
                "proposition_digest": route["proposition_digest"],
                "checking_mechanism": route["checking_mechanism"],
                "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
                "selection": None,
                "selection_digest": None,
                "replay": None,
                "reason": "Fresh package GRAPH projection has not completed.",
                "applicability_established": False,
            }
            try:
                return self._fresh_package_graph(item, route)
            except (
                OSError, ImportError, MemoryError, RecursionError,
                routes.CurrentObjectRouteUnavailable,
            ) as exc:
                reason = str(exc)
                result.update(
                    status="UNKNOWN",
                    reason=(reason if reason.startswith("PACKAGE_")
                            else type(exc).__name__),
                )
            except (
                ValueError, TypeError, KeyError, UnicodeError, OverflowError,
                routes.CurrentObjectRouteRefusal,
            ) as exc:
                result.update(
                    status="FAIL", reason=str(exc) or type(exc).__name__
                )
            result["result_digest"] = value_digest(result)
            return result
        check = self.checks.get((item.object_id, route["coordinate"]))
        if check is None:
            return None
        if added_kind_behavioral_routes.is_route(route):
            return self._added_kind_behavioral(item, route, check)
        result: dict[str, Any] = {"status": "UNKNOWN", "evidence_origin": "MANIFEST_SELECTED_INSTANCE",
            "object_id": item.object_id, "object_digest": item.digest,
            "collection_digest": self.collection_digest,
            "coordinate": route["coordinate"],
            "obligation_id": route.get("obligation_id", route["coordinate"]),
            "semantic_version": route["semantic_version"],
            "proposition_digest": route["proposition_digest"],
            "checking_mechanism": route["checking_mechanism"],
            "selection_digest": value_digest(check), "selection": check, "replay": None,
            "reason": "Selected evidence has not yet been replayed.", "applicability_established": False}
        try:
            _require(all(check[name] == route[name] for name in ("semantic_version", "proposition_digest")),
                     "PACKAGE_INSTANCE_ROUTE_DIFFERS")
            if not check["reason"].strip() or not check["evidence"]:
                raise OSError("PACKAGE_INSTANCE_SOURCE_REASON_UNAVAILABLE")
            owned = {surface.split(":", 2)[1] for surface in self.rows[item.object_id]["surfaces"]
                     if surface.startswith(("file:", "python:"))}
            update = self.representations.get(item.object_id)
            if update is not None:
                if not update["evidence"] or not any(ref["path"] in owned for ref in update["evidence"]):
                    raise OSError("PACKAGE_REPRESENTATION_OWNED_SOURCE_UNAVAILABLE")
                for ref in update["evidence"]:
                    self.read(ref)
            if not any(ref["path"] in owned for ref in check["evidence"]):
                raise OSError("PACKAGE_INSTANCE_OWNED_SOURCE_UNAVAILABLE")
            for ref in check["evidence"]:
                self.read(ref)
            request, policy = self._document(check["request"]), self._document(check["policy"])
            certificate = self.read(check["certificate"])
            _require(all(request.get(name) == route[name] for name in ("coordinate", "semantic_version", "proposition_digest")),
                     "PACKAGE_INSTANCE_REQUEST_ROUTE_DIFFERS")
            # Closed subject-binding conventions. Native replay additionally
            # enforces its exact request schema: extra inert binding fields cannot
            # turn a weaker legacy request into a graph-bound request.
            if route["scope"] == "generic_canonical_representation_and_address":
                expected = {"object_id": item.object_id, "object_kind": item.kind.value, "record_digest": item.digest}
            elif route["scope"] == "externally_selected_finite_receipt_hash_chain":
                expected = {"receipt_object_id": item.object_id, "receipt_object_digest": item.digest}
            elif {"subject_id", "object_digest", "collection_digest"} <= request.keys():
                expected = {"subject_id": item.object_id, "object_digest": item.digest,
                            "collection_digest": self.collection_digest}
            else:
                raise OSError("PACKAGE_INSTANCE_SUBJECT_BINDING_UNSUPPORTED")
            _require(all(request.get(key) == value for key, value in expected.items()),
                     "PACKAGE_INSTANCE_SUBJECT_OR_GRAPH_DIFFERS")
            replay = routes.replay_current_object_certificate(certificate,
                semantic_version=route["semantic_version"], objective=route["coordinate"],
                represented_kind=item.kind.value, expected_request=request, policy=policy)
            result.update(replay=replay, status=replay["computational_status"], reason=replay["claim_boundary"])
            # A declared record necessarily needs its exact representation and
            # typed layout. This establishes only that registered proposition.
            # Other conditional/domain applicability needs its own predicate;
            # a reason, hash or successful native replay cannot invent one.
            result["applicability_established"] = route["scope"] in STRUCTURAL
        except (OSError, ImportError, MemoryError, RecursionError, routes.CurrentObjectRouteUnavailable) as exc:
            reason = str(exc)
            result.update(status="UNKNOWN", reason=reason if reason.startswith("PACKAGE_") else type(exc).__name__)
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
            result.update(status="FAIL", reason=str(exc) or type(exc).__name__)
        result["result_digest"] = value_digest(result)
        return result

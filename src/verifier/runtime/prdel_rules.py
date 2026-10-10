"""Deterministic Pull Request Domain Explanation Language (PRDEL) compilation.

Terminology: abstract syntax tree (AST); identifier (ID); JavaScript Object
Notation (JSON). Rules populate exact-source facts and selected quotations,
without executing candidate code or inventing developer motivation. Compilation
is an authoring operation; its success grants no verification or publication
clearance. Authored associations are retained as inputs, not behavioral proof.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable

from verifier.runtime import prdel

SCHEMA = "verifier-prdel-compilation-1"
MAX_RULE_OPERATIONS = 200_000
MAX_COMPILED_BYTES = prdel.MAX_DOCUMENT_BYTES
MAX_RECORD_CLAIMS = 256
_ENVELOPE_FIELDS = {
    "schema_version",
    "document",
    "binding",
    "definitions",
    "definition_digest",
    "rule_catalogue",
    "rule_results",
    "residuals",
    "status",
    "operation_status",
    "gate_status",
    "scope",
    "counters",
    "limits",
}


def rule_catalogue() -> list[dict[str, Any]]:
    """Return inspectable fixed expert rules; no learned selection is involved."""
    specifications = [
        (
            "exact-region",
            "source_delta via claim_text",
            "Exact text/ranges and Git modes.",
            ["Retained immutable blobs; supported text region."],
            [
                "Binary or oversized regions are unresolved.",
                "Changed text does not prove changed behavior.",
            ],
        ),
        (
            "empty-diff",
            "no_source_changes via claim_text",
            "Exact equality of retained bytes and modes.",
            ["Both selected snapshots were recomputed."],
            [
                "An unchanged tree does not prove correct behavior.",
                "Dirty workspace bytes are outside scope.",
            ],
        ),
        (
            "syntactic-relationship",
            "ast_relationship via claim_text",
            "Resolved syntactic endpoints only.",
            ["Selected edge is resolved in the retained bounded graph."],
            [
                "Dynamic dispatch is unresolved.",
                "A call edge does not prove compatibility or an invariant.",
            ],
        ),
        (
            "selected-association",
            "exact default contract, authored target or selected predicate target",
            "An explicit association and exact requirement quotation; no causal proof.",
            [
                (
                    "Project requirements are independently "
                    "selected; authored targets are data."
                )
            ],
            [
                "An unrelated requirement cannot attach by list position.",
                "A requirement quote does not prove satisfaction.",
            ],
        ),
        (
            "finite-cases",
            "finite_function_contract via claim_text",
            "Selected finite integer cases under the supported interpreter.",
            [
                (
                    "Expected cases are independently selected; "
                    "supported straight-line syntax."
                )
            ],
            [
                "A contrary expected case refutes the claim.",
                "Calls, branches, loops and unselected inputs are unsupported.",
            ],
        ),
        (
            "explicit-exclusions",
            "all current prdel.LIMITS IDs",
            "Every current supported exclusion is retained.",
            ["Exclusions restrict claims; they do not discharge required checks."],
            [
                "A limit cannot waive missing evidence.",
                "A supported fact does not certify complete qualification.",
            ],
        ),
        (
            "unresolved-frontier",
            "retain generated frontier and targeted question",
            "Reached unknown analysis boundaries stay visible.",
            ["The graph has not resolved this boundary."],
            [
                "Missing edges do not prove absence of consumers.",
                "A chosen pattern cannot hide a frontier.",
            ],
        ),
        (
            "authored-intent",
            "retain definition reference or request authored input",
            "Authored intent stays separate from checked summaries.",
            ["Source text cannot establish historical motivation."],
            [
                "A function named secure does not establish a security motive.",
                "An author's invariant is not execution evidence.",
            ],
        ),
    ]
    return [
        {
            "id": name,
            "version": "1",
            "mechanism": mechanism,
            "support": support,
            "assumptions": assumptions,
            "bounds": {
                "max_operations": MAX_RULE_OPERATIONS,
                "max_document_bytes": MAX_COMPILED_BYTES,
                "max_claims_per_record": MAX_RECORD_CLAIMS,
            },
            "counterexamples": counterexamples,
        }
        for name, mechanism, support, assumptions, counterexamples in specifications
    ]


class _Bound(Exception):
    pass


class _Work:
    def __init__(self) -> None:
        self.operations = 0
        self.output_bytes = 0

    def step(self, count: int = 1) -> None:
        if self.operations + count > MAX_RULE_OPERATIONS:
            raise _Bound(
                "Explanation rule operation bound reached; split the selected scope."
            )
        self.operations += count

    def retain_text(self, text: str) -> None:
        self.output_bytes += len(text.encode("utf-8"))
        if self.output_bytes > MAX_COMPILED_BYTES:
            raise _Bound(
                (
                    "Compiled explanatory text byte bound reached; "
                    "split the selected scope."
                )
            )


def _residual(
    code: str,
    status: str,
    reason: str,
    *,
    required: bool = True,
    obligation_id: str | None = None,
    requirement_id: str | None = None,
    question: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "status": status,
        "required": required,
        "obligation_id": obligation_id,
        "requirement_id": requirement_id,
        "reason": reason,
        "question": question or reason,
    }


def _envelope(
    document: dict[str, Any] | None,
    definitions: dict[str, Any] | None,
    results: list[dict[str, Any]],
    residuals: list[dict[str, Any]],
    work: _Work,
) -> dict[str, Any]:
    blocking = [row for row in residuals if row["required"]]
    status = (
        "FAIL"
        if any(row["status"] == "FAIL" for row in blocking)
        else "UNKNOWN" if blocking else "PASS"
    )
    return {
        "schema_version": SCHEMA,
        "document": document,
        "binding": document["binding"] if document is not None else None,
        "definitions": definitions,
        "definition_digest": (
            prdel.digest(prdel.canonical(definitions))
            if definitions is not None
            else None
        ),
        "rule_catalogue": rule_catalogue(),
        "rule_results": results,
        "residuals": residuals,
        "status": status,
        "operation_status": "GENERATED" if document is not None else "BLOCKED",
        "gate_status": "NOT_ASSESSED",
        "scope": "EXPLANATION_COMPILATION_ONLY",
        "counters": {
            "operations": work.operations,
            "explanatory_text_bytes": work.output_bytes,
        },
        "limits": [
            "Compilation is not gate, runtime or workspace clearance.",
            (
                "Requirement associations and authored intent do not "
                "prove behavioral correspondence."
            ),
            "Required execution evidence is not generated or authenticated.",
        ],
    }


def _targets(
    row: dict[str, Any], nodes: dict[str, dict[str, Any]]
) -> list[tuple[str, str | None]]:
    targets = [(row["path"], None)]
    targets += [(row["path"], symbol) for symbol in row.get("symbols", [])]
    for node_id in row.get("endpoints", []) + (
        [row["consumer_id"]] if row.get("consumer_id") else []
    ):
        if node_id in nodes:
            node = nodes[node_id]
            targets += [(node["path"], None), (node["path"], node["symbol"])]
    return sorted(set(targets), key=lambda pair: (pair[0], pair[1] or ""))


def _renderer(document: dict[str, Any], work: _Work) -> Callable[[dict[str, Any]], str]:
    """Index once, then pass exactly selected data to the existing interpreter.

    ``claim_text`` otherwise rebuilds whole-document indices for every fact.
    These views select from the generated immutable inventory; they do not add
    source facts, and produce the same supported rendering as the full document.
    """
    graph = document["impact_graph"]
    work.step(
        len(document["source_obligations"]) + len(graph["nodes"]) + len(graph["edges"])
    )
    rows = {row["id"]: row for row in document["source_obligations"]}
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {edge["id"]: edge for edge in graph["edges"]}
    requirements = {item["id"]: item for item in document["requirements"]["items"]}

    def render(claim: dict[str, Any]) -> str:
        kind = claim["kind"]
        if kind in {"source_delta", "no_source_changes"}:
            view = {"source_obligations": [rows[claim["obligation_id"]]]}
        elif kind == "ast_relationship":
            edge = edges[claim["edge_id"]]
            view = {
                "impact_graph": {
                    "edges": [edge],
                    "nodes": [nodes[edge["source"]], nodes[edge["target"]]],
                }
            }
        elif kind == "requirement_quote":
            view = {"requirements": {"items": [requirements[claim["requirement_id"]]]}}
        else:
            view = {
                "impact_graph": {
                    "selected_predicates": {
                        claim["requirement_id"]: graph["selected_predicates"][
                            claim["requirement_id"]
                        ]
                    }
                }
            }
        return prdel.claim_text(claim, view)

    return render


# vstd-explanation: begin prdel.self.prdel-rules
# Authored intent (not verified):
#   Generate inspectable explanations using fixed bounded rules and authored
# associations.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): Compilation success is an authoring result, not gate clearance.
# vstd-explanation: end prdel.self.prdel-rules
def compile_prdel(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    definition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile the unchanged version-one bounded single-document representation."""
    return _compile_prdel(root, base, head, requirements_bytes,
        expected_requirements_digest, definition)


def _compile_prdel(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    definition: dict[str, Any] | None = None,
    *, retain_document: bool = False,
) -> dict[str, Any]:
    """Lower supported facts, with explicit residuals for missing/unknown inputs.

    ``definition`` is the canonical ``verifier-explanation-definitions-1`` authored
    inventory. A null symbol explicitly associates its file; a symbol associates
    that lexical definition. No project requirement is assigned by convenience.
    The returned version-one document must still pass independent gate validation.
    """
    work = _Work()
    results: list[dict[str, Any]] = []
    residuals: list[dict[str, Any]] = []
    definitions = None
    try:
        if definition is not None:
            from verifier.runtime.explanation_projection import canonical_definitions

            definitions = prdel.decode(canonical_definitions(definition))
        selected_requirements, _ = prdel._requirements(
            requirements_bytes, expected_requirements_digest
        )
        selected_ids = {item["id"] for item in selected_requirements["items"]}
        for item in (definitions or {}).get("definitions", []):
            for identifier in item["requirement_ids"]:
                if identifier not in selected_ids:
                    residuals.append(
                        _residual(
                            "UNKNOWN_AUTHORED_REQUIREMENT",
                            "FAIL",
                            (
                                "An authored association names a "
                                "requirement absent from the "
                                "independently selected inventory."
                            ),
                            requirement_id=identifier,
                        )
                    )
        document = prdel.generate_prdel(
            Path(root), base, head, requirements_bytes, expected_requirements_digest
        )
    except prdel.PrdelUnavailable as exc:
        residuals.append(_residual("SOURCE_UNAVAILABLE", "UNKNOWN", str(exc)))
        return _envelope(None, definitions, results, residuals, work)
    except OSError:
        residuals.append(
            _residual(
                "SOURCE_UNAVAILABLE",
                "UNKNOWN",
                "Exact source observation is unavailable.",
            )
        )
        return _envelope(None, definitions, results, residuals, work)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        residuals.append(
            _residual(
                "INVALID_COMPILATION_INPUT",
                "FAIL",
                (
                    "Definition or independently selected "
                    "requirements input is malformed, missing or "
                    "outside its bounds."
                ),
            )
        )
        return _envelope(None, definitions, results, residuals, work)

    try:
        graph = document["impact_graph"]
        render = _renderer(document, work)
        nodes = {node["id"]: node for node in graph["nodes"]}
        requirements = {item["id"]: item for item in document["requirements"]["items"]}
        associations: dict[tuple[str, str | None], set[str]] = {}
        authored: dict[tuple[str, str | None], dict[str, Any]] = {}
        authored_intent_ids: set[str] = set()
        for item in (definitions or {}).get("definitions", []):
            work.step()
            target = (item["target"]["path"], item["target"]["symbol"])
            authored[target] = item
            if item["intent"].strip():
                authored_intent_ids.add(item["id"])
            for identifier in item["requirement_ids"]:
                work.step()
                if identifier not in requirements:
                    continue
                else:
                    associations.setdefault(target, set()).add(identifier)
        for item in requirements.values():
            work.step()
            if "predicate" in item:
                target = (item["predicate"]["path"], item["predicate"]["symbol"])
                associations.setdefault(target, set()).add(item["id"])

        # Independently selected predicates run even when no changed row matches;
        # omission of a claim cannot hide a known counterexample.
        evaluated: dict[str, tuple[str, str | None]] = {}
        for identifier in graph.get("selected_predicates", {}):
            work.step()
            claim = {"kind": "finite_function_contract", "requirement_id": identifier}
            try:
                text = render(claim)
                evaluated[identifier] = ("PASS", text)
            except prdel.PrdelRefuted as exc:
                evaluated[identifier] = ("FAIL", None)
                residuals.append(
                    _residual(
                        "CONTRADICTED_SELECTED_REQUIREMENT",
                        "FAIL",
                        str(exc),
                        requirement_id=identifier,
                    )
                )
            except (
                prdel.PrdelError,
                ValueError,
                KeyError,
                TypeError,
                SyntaxError,
            ) as exc:
                evaluated[identifier] = ("UNKNOWN", None)
                residuals.append(
                    _residual(
                        "UNSUPPORTED_SELECTED_REQUIREMENT",
                        "UNKNOWN",
                        str(exc),
                        requirement_id=identifier,
                    )
                )
            results.append(
                {
                    "rule_id": "finite-cases",
                    "rule_version": "1",
                    "status": evaluated[identifier][0],
                    "obligation_id": None,
                    "requirement_id": identifier,
                    "claim": claim,
                    "support_role": "INDEPENDENTLY_SELECTED_FINITE_EXPECTATIONS",
                }
            )

        rows = {row["id"]: row for row in document["source_obligations"]}
        by_record: dict[str, set[str]] = {}
        definition_ids: dict[str, set[str]] = {}
        default = document["requirements"] == prdel.DEFAULT_REQUIREMENTS
        # Establish direct links first so contracts/frontiers can retain explicit
        # associations of the source regions from which they were reached.
        for row in document["source_obligations"]:
            work.step()
            selected: set[str] = set()
            matched: set[str] = set()
            for target in _targets(row, nodes):
                work.step()
                selected.update(associations.get(target, ()))
                if target in authored:
                    matched.add(authored[target]["id"])
            if default:
                selected.add("bounded-source-description")
            if row.get("no_change"):
                # An exact empty diff retains the whole selected snapshot; quote
                # a selected predicate only as a predicate, not a source change.
                selected.update(graph.get("selected_predicates", {}))
            by_record[row["id"]] = selected
            definition_ids[row["id"]] = matched

        used: set[str] = set()
        for record in document["records"]:
            work.step()
            row = rows[record["id"]]
            selected = by_record[row["id"]]
            matched = definition_ids[row["id"]]
            for source_id in row.get("source_obligations", []):
                work.step()
                selected.update(by_record.get(source_id, ()))
                matched.update(definition_ids.get(source_id, ()))
            identifiers = sorted(selected)
            record["requirement_ids"] = identifiers
            record["limits"] = list(prdel.LIMITS)
            used.update(selected)
            if identifiers:
                first = identifiers[0]
                record["why"] = {
                    "requirement_id": first,
                    "quote": requirements[first]["text"],
                }
            else:
                residuals.append(
                    _residual(
                        "MISSING_REQUIREMENT_ASSOCIATION",
                        "FAIL",
                        (
                            "No independently selected requirement "
                            "has an explicit association with this "
                            "obligation."
                        ),
                        obligation_id=row["id"],
                        question=(
                            "Supply an authored target association "
                            "or an independently selected finite "
                            "predicate."
                        ),
                    )
                )

            claims: list[dict[str, Any]] = []
            if row["kind"] == "source":
                claims.append(
                    {
                        "kind": (
                            "no_source_changes"
                            if row.get("no_change")
                            else "source_delta"
                        ),
                        "obligation_id": row["id"],
                    }
                )
            elif row["kind"] == "contract":
                claims.append({"kind": "ast_relationship", "edge_id": row["edge_id"]})
            else:
                residuals.append(
                    _residual(
                        "UNRESOLVED_ANALYSIS_FRONTIER",
                        "UNKNOWN",
                        "No supported rule resolves this retained analysis frontier.",
                        obligation_id=row["id"],
                        question=row["question"],
                    )
                )
                results.append(
                    {
                        "rule_id": "unresolved-frontier",
                        "rule_version": "1",
                        "status": "UNKNOWN",
                        "obligation_id": row["id"],
                        "support_role": "RETAINED_UNRESOLVED_BOUNDARY",
                    }
                )
            for identifier in identifiers:
                work.step()
                claims.append(
                    {
                        "kind": "requirement_quote",
                        "requirement_id": identifier,
                        "quote": requirements[identifier]["text"],
                    }
                )
                if identifier in evaluated:
                    claims.append(
                        {
                            "kind": "finite_function_contract",
                            "requirement_id": identifier,
                        }
                    )
            if len(claims) > MAX_RECORD_CLAIMS:
                raise _Bound(
                    (
                        "Supported record claim count bound reached; "
                        "split associations explicitly."
                    )
                )
            record["claims"] = claims
            rendered = []
            for claim in claims:
                work.step()
                kind = claim["kind"]
                rule_id = {
                    "source_delta": "exact-region",
                    "no_source_changes": "empty-diff",
                    "ast_relationship": "syntactic-relationship",
                    "requirement_quote": "selected-association",
                    "finite_function_contract": "finite-cases",
                }[kind]
                try:
                    if kind == "finite_function_contract":
                        known_status, text = evaluated[claim["requirement_id"]]
                        if known_status == "FAIL":
                            raise prdel.PrdelRefuted(
                                "Selected finite expectation was already refuted."
                            )
                        if known_status == "UNKNOWN":
                            raise prdel.PrdelError(
                                "Selected finite semantics were already unresolved."
                            )
                    else:
                        text = render(claim)
                    work.retain_text(text)
                    rendered.append(text)
                    status = "PASS"
                except prdel.PrdelRefuted as exc:
                    status = "FAIL"
                    residuals.append(
                        _residual(
                            "CONTRADICTED_SUPPORTED_CLAIM",
                            status,
                            str(exc),
                            obligation_id=row["id"],
                        )
                    )
                except (
                    prdel.PrdelError,
                    ValueError,
                    KeyError,
                    TypeError,
                    SyntaxError,
                ) as exc:
                    status = "UNKNOWN"
                    residuals.append(
                        _residual(
                            "UNSUPPORTED_SOURCE_PREDICATE",
                            status,
                            str(exc),
                            obligation_id=row["id"],
                        )
                    )
                results.append(
                    {
                        "rule_id": rule_id,
                        "rule_version": "1",
                        "status": status,
                        "obligation_id": row["id"],
                        "claim": claim,
                        "support_role": (
                            "AUTHORED_OR_SELECTED_ASSOCIATION"
                            if kind == "requirement_quote"
                            else "SUPPORTED_SOURCE_PREDICATE"
                        ),
                    }
                )
            record["summary"] = "\n".join(rendered)
            results.append(
                {
                    "rule_id": "explicit-exclusions",
                    "rule_version": "1",
                    "status": "PASS",
                    "obligation_id": row["id"],
                    "support_role": "LIMITATION",
                    "exclusion_ids": list(prdel.LIMITS),
                }
            )
            results.append(
                {
                    "rule_id": "authored-intent",
                    "rule_version": "1",
                    "status": "NOT_SELECTED" if not matched else "UNKNOWN",
                    "obligation_id": row["id"],
                    "definition_ids": sorted(matched),
                    "support_role": "AUTHORED_INTENT_ONLY",
                }
            )
            if not matched.intersection(authored_intent_ids):
                residuals.append(
                    _residual(
                        "AUTHOR_MOTIVATION_UNRESOLVED",
                        "UNKNOWN",
                        (
                            "Source facts do not establish the "
                            "author's motivation; no authored "
                            "definition targets this obligation."
                        ),
                        required=False,
                        obligation_id=row["id"],
                        question=(
                            "Optionally provide authored intent "
                            "without presenting it as checked source "
                            "evidence."
                        ),
                    )
                )
        for identifier in sorted(set(requirements) - used):
            residuals.append(
                _residual(
                    "UNREPRESENTED_REQUIREMENT",
                    "FAIL",
                    (
                        "The independently selected requirement has "
                        "no explicit explanation association."
                    ),
                    requirement_id=identifier,
                )
            )
    except _Bound as exc:
        residuals.append(_residual("RULE_OPERATION_BOUND", "UNKNOWN", str(exc)))

    if not retain_document and len(prdel.canonical(document)) > MAX_COMPILED_BYTES:
        residuals.append(
            _residual(
                "COMPILED_DOCUMENT_BOUND",
                "UNKNOWN",
                (
                    "Compiled document byte bound exceeded; split "
                    "the exact declared scope."
                ),
            )
        )
        document = None
    return _envelope(document, definitions, results, residuals, work)


def validate_compilation(
    compilation: dict[str, Any],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    definition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay every rule/result and byte binding; this still grants no gate clearance.

    Carried definitions are candidate-authored intent unless an independently
    selected ``definition`` is supplied. Selected requirement authority remains
    external. Passing this replay does not supply missing execution evidence.
    """
    findings = []
    try:
        value = prdel.decode(prdel.canonical(compilation))
        if (
            set(value) != _ENVELOPE_FIELDS
            or value.get("schema_version") != SCHEMA
            or value.get("rule_catalogue") != rule_catalogue()
            or value.get("scope") != "EXPLANATION_COMPILATION_ONLY"
            or value.get("gate_status") != "NOT_ASSESSED"
        ):
            raise prdel.PrdelError(
                "Compilation grammar, rule version or scope differs."
            )
        known_rules = {item["id"] for item in rule_catalogue()}
        if type(value["rule_results"]) is not list or any(
            type(item) is not dict
            or item.get("rule_id") not in known_rules
            or item.get("rule_version") != "1"
            for item in value["rule_results"]
        ):
            raise prdel.PrdelError("Unsupported rule result grammar or version.")
        selected_requirements, selected_digest = prdel._requirements(
            requirements_bytes, expected_requirements_digest
        )
        binding = value["binding"]
        if isinstance(binding, dict):
            for key, selected in (("base", base), ("head", head)):
                if (
                    re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", selected)
                    and binding.get(key) != selected
                ):
                    findings.append(
                        _residual(
                            "STALE_OR_SUBSTITUTED_BINDING",
                            "FAIL",
                            "Carried exact commit differs from the selected commit.",
                        )
                    )
            if binding.get("requirements_digest") != selected_digest:
                findings.append(
                    _residual(
                        "STALE_OR_SUBSTITUTED_REQUIREMENTS",
                        "FAIL",
                        (
                            "Carried requirement digest differs from "
                            "independently selected bytes."
                        ),
                    )
                )
        if (
            isinstance(value["document"], dict)
            and value["document"].get("requirements") != selected_requirements
        ):
            findings.append(
                _residual(
                    "STALE_OR_SUBSTITUTED_REQUIREMENTS",
                    "FAIL",
                    "Carried requirements differ from independently selected bytes.",
                )
            )
        if (
            isinstance(value["document"], dict)
            and value["document"].get("binding") != binding
        ):
            findings.append(
                _residual(
                    "CONTRADICTORY_COMPILATION_BINDING",
                    "FAIL",
                    "Envelope and nested document carry contradictory bindings.",
                )
            )
        from verifier.runtime.explanation_projection import canonical_definitions

        carried_definition = value["definitions"]
        carried_digest = (
            prdel.digest(canonical_definitions(carried_definition))
            if carried_definition is not None
            else None
        )
        if carried_digest != value["definition_digest"]:
            findings.append(
                _residual(
                    "STALE_OR_SUBSTITUTED_DEFINITION",
                    "FAIL",
                    "Carried definition digest differs from its exact canonical bytes.",
                )
            )
        if definition is not None and canonical_definitions(
            definition
        ) != canonical_definitions(carried_definition):
            findings.append(
                _residual(
                    "STALE_OR_SUBSTITUTED_DEFINITION",
                    "FAIL",
                    (
                        "Carried authored definitions differ from "
                        "the independently selected inventory."
                    ),
                )
            )
        selected_definition = (
            definition if definition is not None else value.get("definitions")
        )
        expected = compile_prdel(
            root,
            base,
            head,
            requirements_bytes,
            expected_requirements_digest,
            selected_definition,
        )
        if expected["document"] is None:
            findings.extend(expected["residuals"])
        elif value != expected:
            findings.append(
                _residual(
                    "STALE_OR_SUBSTITUTED_COMPILATION",
                    "FAIL",
                    (
                        "Compilation differs from independently "
                        "replayed rules, exact inputs or selected "
                        "definitions."
                    ),
                )
            )
        else:
            findings.extend(expected["residuals"])
    except (
        prdel.PrdelError,
        ValueError,
        OSError,
        TypeError,
        KeyError,
        RecursionError,
        OverflowError,
    ):
        findings.append(
            _residual(
                "INVALID_COMPILATION",
                "FAIL",
                "The compilation envelope is malformed or exceeds its byte bound.",
            )
        )
    blocking = [row for row in findings if row["required"]]
    status = (
        "FAIL"
        if any(row["status"] == "FAIL" for row in blocking)
        else "UNKNOWN" if blocking else "PASS"
    )
    return {
        "schema_version": "verifier-prdel-compilation-report-1",
        "status": status,
        "scope": "EXPLANATION_COMPILATION_REPLAY_ONLY",
        "gate_status": "NOT_ASSESSED",
        "findings": findings,
    }

"""Source-native Statics with freshly executed repository prerequisites.

Verifier Standard (VSTD) Tier 3 selects exactly the installed Statics routes.
No retained caller verdict is an input. Source equality is not host attestation;
the interpreter, import machinery, standard library and operating system remain
trusted. Native results retain their narrower epistemic and physical boundaries.
"""
from __future__ import annotations

import base64
from pathlib import Path
import re
from typing import Any

from verifier.runtime import core_obligation_union as binding
from verifier.runtime import core_tier_progression
from verifier.runtime import polish
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_replay as native
from verifier.runtime import self_polish_native_tier3_cases as specimens
from verifier.runtime import self_polish_tiers as tiers
from verifier.runtime import tier_zero
from verifier.runtime.tier_zero_profile import validate_applicability_binding


REPORT_SCHEMA = "verifier-self-polish-statics-assessment-1"
REPLAY_SCHEMA = "verifier-self-polish-native-statics-replay-1"
REGISTRY_SCHEMA = "verifier-self-polish-installed-statics-registry-1"
APPLICABILITY_EVIDENCE_SCHEMA = \
    "verifier-self-polish-native-route-applicability-evidence-1"
MAX_REPORT_BYTES = 32 * 1024 * 1024
_ENTRY_KEYS = {"builder_adapter", "checking_mechanism", "evidence_base64",
               "negative_adapter", "policy", "request", "unknown_adapter"}
_RESOURCE_ERRORS = (OSError, ImportError, MemoryError, RecursionError, OverflowError)
_TIER_NAMES = {0: "ADMISSION", 1: "FACETS", 2: "DYNAMICS", 3: "STATICS"}
_APPLICABILITY_EVIDENCE_KEYS = {
    "schema_version", "evidence_origin", "object_kind", "obligation_id",
    "coordinate", "semantic_version", "proposition_digest",
    "applicability_digest", "condition", "condition_status",
    "classification", "reason", "source_coordinate_digest",
    "selected_input_digest", "adaptation_obligation_id",
    "adaptation_result_digest", "evidence_digest",
}

# These reasons describe the selected propositions, not universal requirements
# for every possible object bearing the same kind name.
_NECESSITY = {
    "ACTOR-3.3": "Ending delegation, keys or an actor must not rewrite the selected earlier decision records; compare the retained records across those events.",
    "AGENT-3.1": "A declared agent ceiling must equal its selected harness-bound ceiling; the agent label alone cannot establish fixity.",
    "ARCH-3.1": "A static tensor graph must have compatible selected shapes on every admitted operation and edge before its layout is valid.",
    "BENCH-3.6": "A claimed benchmark budget must satisfy the selected retained budget constraints, not merely report a final score.",
    "BOT-3.1": "A bot cannot claim a ceiling above the selected inherited harness ceiling; the inheritance relation must be checked.",
    "COLLECTIVE-3.1": "Selected collective membership, charter and quorum constraints must hold together for that collective declaration to be consistent.",
    "DATA-3.4": "A claimed exact-value distribution must reproduce from the selected finite data values rather than a separately asserted summary.",
    "ENV-3.3": "Declared environment resource constraints require checking the selected retained resource records against those constraints.",
    "EVENT-3.1": "An event with declared prerequisites must have the selected prerequisite relation checked; an event name does not establish admission.",
    "GRAPH-3.1": "A declared directed graph must satisfy its selected static vertex and edge constraints before graph-level claims can depend on it.",
    "HARDWARE-3.1": "A substrate declaration needs the selected qualified observation records checked for correspondence, without authenticating a physical device.",
    "HARNESS-3.1": "A harness boundary claim must match its retained instrument placements so unobserved gaps cannot be represented as observed coverage.",
    "HUMAN-3.6": "The selected HUMAN collection and arrangements must respect the no-composition constraint; typed records alone do not establish that relation.",
    "HYPER-3.1": "A composed ceiling must not exceed the selected direct operands' admitted tier prefixes; composition cannot manufacture assurance.",
    "IDENTITY-3.1": "A declared identity role needs its selected scope admission checked; a shared identifier does not grant a role.",
    "MODEL-3.1": "A model artifact claim requires the selected architecture and weight bytes to match the retained artifact, not just its filename.",
    "MODEL-3.2": "A local memory-bracket claim requires fresh enforcement and observations below and above the selected caps; retained hardware labels cannot establish consumption.",
    "MODEL-3.3": "A model quantization declaration must match the selected retained quantization specification before it can describe that artifact.",
    "MODEL-3.4": "A model data citation must select the declared DATA operand and replay its inventory; naming a dataset is insufficient.",
    "MODEL-3.5": "A model training citation must select the declared TRAIN operand and replay its data citation rather than asserting training ancestry.",
    "MODEL-3.7": "A model lineage claim requires correspondence of the selected training and two retained data views, not just matching ancestor labels.",
    "OBJECT-3.1": "The selected canonical collection must satisfy object statics before downstream claims rely on its declared structure.",
    "OWNER-3.1": "A declared hardware ownership relation must satisfy the selected eligibility constraints; a record does not establish external legal ownership.",
    "RECEIPT-3.1": "A selected receipt must satisfy canonical static structure before its contents can be interpreted as evidence.",
    "ROLE-3.1": "Selected role occupancy and permission declarations must satisfy their constraints; naming the role does not grant permission.",
    "SIM-3.4": "A simulation declaring an external modelled law must select a distinct law OBJECT and reproduce that exact statement relation; internal agreement cannot establish a physical law.",
    "SPACE-3.1": "Selected logical byte partitions must satisfy layout constraints before they can be claimed to partition that space.",
    "TIME-3.1": "A declared strict clock order must satisfy the selected ordering relation; retained timestamps do not authenticate physical time.",
    "TOKEN-3.1": "Selected token windows must satisfy their declared static constraints before tenure can rely on those windows.",
    "TRAIN-3.2": "An accumulation claim must reproduce both selected binary64 summation orders, since rounding makes their equivalence unsafe to assume.",
    "VERIFIER-3.1": "A verifier run-constraint claim must match the selected run-bound observations; a PASS label alone cannot establish constraint enforcement.",
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise native.NativeReplayError(code)


def _join(statuses: list[str]) -> str:
    return "FAIL" if "FAIL" in statuses else (
        "PASS" if statuses and all(s == "PASS" for s in statuses) else "UNKNOWN")


def _seal(body: dict[str, Any], field: str) -> dict[str, Any]:
    body[field] = binding.value_digest(body)
    return body


def _is_digest(value: Any) -> bool:
    return type(value) is str and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value))


def _applicability_result(
    row: dict[str, Any],
    *,
    status: str,
    classification: str,
    condition_status: str,
    fulfillment_required: bool,
    reason: str,
    declaration: dict[str, str] | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """Keep a failed applicability assessment in the route denominator."""
    return {
        "status": status,
        "classification": classification,
        "condition_status": condition_status,
        "fulfillment_required": fulfillment_required,
        "reason": reason,
        "declaration": declaration,
        "applicability_digest": row.get("applicability_digest"),
        "condition_evidence_digest": evidence_digest,
    }


def _membership_identity_is_exact(row: dict[str, Any]) -> bool:
    kind = row.get("object_kind")
    coordinate = row.get("coordinate")
    return (
        type(kind) is str
        and type(coordinate) is str
        and coordinate.startswith(kind + "-")
        and row.get("obligation_id") == f"{kind}:{coordinate}"
    )


def _assess_membership_applicability(
    row: dict[str, Any], evidence: Any,
) -> dict[str, Any]:
    """Evaluate one installed route declaration against exact condition evidence.

    Package profiles use the same validated necessary-or-conditional declaration
    binding. A conditional route is necessary only after a source-bound trigger;
    a non-trigger needs its necessary source-adaptation receipt. Missing evidence
    stays UNKNOWN and retains fulfillment in the denominator.
    """
    try:
        declaration = validate_applicability_binding(row)
    except (TypeError, ValueError):
        return _applicability_result(
            row, status="FAIL", classification="UNDETERMINED",
            condition_status="UNKNOWN", fulfillment_required=True,
            reason="The installed applicability declaration or digest is invalid.",
        )
    if not _membership_identity_is_exact(row):
        return _applicability_result(
            row, status="FAIL", classification="UNDETERMINED",
            condition_status="UNKNOWN", fulfillment_required=True,
            reason=(
                "The represented kind, coordinate and obligation identity differ; "
                "relabeling as OBJECT cannot bypass the installed membership."
            ), declaration=declaration,
        )
    if declaration["mode"] == "NECESSARY":
        return _applicability_result(
            row, status="PASS", classification="NECESSARY",
            condition_status="TRIGGERED", fulfillment_required=True,
            reason=declaration["reason"], declaration=declaration,
        )
    if type(evidence) is not dict or set(evidence) != _APPLICABILITY_EVIDENCE_KEYS:
        return _applicability_result(
            row, status="UNKNOWN", classification="UNDETERMINED",
            condition_status="UNKNOWN", fulfillment_required=True,
            reason=(
                "The conditional route has no complete exact condition evidence; "
                "UNKNOWN is not an exemption."
            ), declaration=declaration,
        )
    evidence_body = {
        key: value for key, value in evidence.items()
        if key != "evidence_digest"
    }
    exact_fields = (
        "object_kind", "obligation_id", "coordinate", "semantic_version",
        "proposition_digest", "applicability_digest",
    )
    if (
        evidence.get("schema_version") != APPLICABILITY_EVIDENCE_SCHEMA
        or evidence.get("evidence_digest") != binding.value_digest(evidence_body)
        or any(evidence.get(field) != row.get(field) for field in exact_fields)
        or evidence.get("condition") != declaration["condition"]
        or not _is_digest(evidence.get("source_coordinate_digest"))
        or type(evidence.get("reason")) is not str
        or not evidence["reason"].strip()
    ):
        return _applicability_result(
            row, status="FAIL", classification="UNDETERMINED",
            condition_status="UNKNOWN", fulfillment_required=True,
            reason=(
                "The condition evidence is forged, stale, mislabeled or bound to "
                "a different membership identity."
            ), declaration=declaration,
        )
    condition_status = evidence.get("condition_status")
    classification = evidence.get("classification")
    if condition_status == "UNKNOWN" and classification == "UNDETERMINED":
        return _applicability_result(
            row, status="UNKNOWN", classification="UNDETERMINED",
            condition_status="UNKNOWN", fulfillment_required=True,
            reason=evidence["reason"], declaration=declaration,
            evidence_digest=evidence["evidence_digest"],
        )
    if condition_status == "TRIGGERED" and classification == "NECESSARY":
        if (
            evidence.get("evidence_origin")
                != "SOURCE_OWNED_NATIVE_ROUTE_SELECTION"
            or not _is_digest(evidence.get("selected_input_digest"))
            or evidence.get("adaptation_obligation_id") is not None
            or evidence.get("adaptation_result_digest") is not None
        ):
            return _applicability_result(
                row, status="FAIL", classification="UNDETERMINED",
                condition_status="UNKNOWN", fulfillment_required=True,
                reason="The claimed native trigger lacks exact source-owned selection evidence.",
                declaration=declaration,
            )
        return _applicability_result(
            row, status="PASS", classification="NECESSARY",
            condition_status="TRIGGERED", fulfillment_required=True,
            reason=evidence["reason"], declaration=declaration,
            evidence_digest=evidence["evidence_digest"],
        )
    expected_adaptation = (
        f"{row['object_kind']}-3.90-source-representation-statics"
    )
    if condition_status == "NOT_TRIGGERED" and classification == "CONDITION_NOT_MET":
        if (
            evidence.get("evidence_origin")
                != "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
            or evidence.get("selected_input_digest") is not None
            or evidence.get("adaptation_obligation_id") != expected_adaptation
            or not _is_digest(evidence.get("adaptation_result_digest"))
        ):
            return _applicability_result(
                row, status="FAIL", classification="UNDETERMINED",
                condition_status="UNKNOWN", fulfillment_required=True,
                reason=(
                    "The claimed non-trigger lacks its exact source-bound necessary "
                    "adaptation evidence."
                ), declaration=declaration,
            )
        return _applicability_result(
            row, status="PASS", classification="CONDITION_NOT_MET",
            condition_status="NOT_TRIGGERED", fulfillment_required=False,
            reason=evidence["reason"], declaration=declaration,
            evidence_digest=evidence["evidence_digest"],
        )
    return _applicability_result(
        row, status="FAIL", classification="UNDETERMINED",
        condition_status="UNKNOWN", fulfillment_required=True,
        reason=(
            "The condition status contradicts its applicability classification; "
            "the route remains in the denominator."
        ), declaration=declaration,
    )


def _native_applicability_evidence(
    row: dict[str, Any], selected: dict[str, Any], *,
    source_coordinate_digest: str,
) -> dict[str, Any]:
    """Bind the native-condition trigger to this source-owned exact selection."""
    declaration = validate_applicability_binding(row)
    _require(_membership_identity_is_exact(row),
             "STATICS_APPLICABILITY_MEMBERSHIP_IDENTITY_DIFFERS")
    _require(type(selected) is dict and _is_digest(source_coordinate_digest),
             "STATICS_APPLICABILITY_SELECTION_EVIDENCE_INVALID")
    body = {
        "schema_version": APPLICABILITY_EVIDENCE_SCHEMA,
        "evidence_origin": "SOURCE_OWNED_NATIVE_ROUTE_SELECTION",
        **{key: row[key] for key in (
            "object_kind", "obligation_id", "coordinate", "semantic_version",
            "proposition_digest", "applicability_digest",
        )},
        "condition": declaration["condition"],
        "condition_status": "TRIGGERED",
        "classification": "NECESSARY",
        "reason": (
            "This fixed source-native profile selected the exact retained "
            f"runtime-domain instance {row['obligation_id']}; its conditional "
            "native route is therefore necessary."
        ),
        "source_coordinate_digest": source_coordinate_digest,
        "selected_input_digest": binding.value_digest(selected),
        "adaptation_obligation_id": None,
        "adaptation_result_digest": None,
    }
    return _seal(body, "evidence_digest")


def _tier_execution_record(
    tier: int,
    *,
    execution_status: str,
    status: str,
    reason: str,
    evidence_digest: str | None = None,
    blocking_prerequisite: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe execution separately from its epistemic result.

    A dependent tier that was unsafe to execute remains epistemically UNKNOWN;
    ``execution_status`` records the distinct fact that it was NOT_RUN. The
    blocking prerequisite is retained by tier, observed status, digest and
    blocker codes so a cumulative Tier-3 report never makes a skipped tier look
    absent from the denominator.
    """

    _require(tier in _TIER_NAMES, "STATICS_EXECUTION_TIER_INVALID")
    _require(execution_status in {"EXECUTED", "NOT_RUN"},
             "STATICS_EXECUTION_STATUS_INVALID")
    _require(status in {"PASS", "FAIL", "UNKNOWN"},
             "STATICS_EXECUTION_RESULT_INVALID")
    _require(type(reason) is str and bool(reason.strip()),
             "STATICS_EXECUTION_REASON_MISSING")
    body = {
        "schema_version": "verifier-self-polish-tier-execution-1",
        "tier": tier,
        "tier_name": _TIER_NAMES[tier],
        "execution_status": execution_status,
        "status": status,
        "reason": reason,
        "evidence_digest": evidence_digest,
        "blocking_prerequisite": blocking_prerequisite,
    }
    return _seal(body, "execution_record_digest")


def _record_incomplete_tier_execution(
    report: dict[str, Any],
    *,
    failed_tier: int,
    failure_stage: str,
    blocker: str,
    exception_type: str,
) -> None:
    """Close the Tier 0-3 execution ledger after an exceptional exit.

    Calling an assessor is not the same as completing a usable assessment. If
    the call or its result-contract validation raises, the affected tier has no
    admissible evidence receipt and is therefore recorded as ``NOT_RUN`` with
    epistemic status ``UNKNOWN``. Records already sealed for earlier tiers are
    left untouched. Every later tier is recorded as dependency-blocked by the
    same failed stage, so an exception cannot silently remove obligations from
    the cumulative Tier-3 denominator.
    """

    _require(failed_tier in _TIER_NAMES, "STATICS_EXCEPTION_TIER_INVALID")
    _require(type(failure_stage) is str and bool(failure_stage.strip()),
             "STATICS_EXCEPTION_STAGE_MISSING")
    _require(type(blocker) is str and bool(blocker.strip()),
             "STATICS_EXCEPTION_BLOCKER_MISSING")
    _require(type(exception_type) is str and bool(exception_type.strip()),
             "STATICS_EXCEPTION_TYPE_MISSING")
    blocking = {
        "tier": failed_tier,
        "tier_name": _TIER_NAMES[failed_tier],
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": [blocker],
        "failure_stage": failure_stage,
        "exception_type": exception_type,
    }
    for tier in range(failed_tier, 4):
        key = str(tier)
        if key in report["tier_execution"]:
            continue
        if tier == failed_tier:
            reason = (
                f"Tier {tier} {_TIER_NAMES[tier]} did not complete an admissible "
                f"assessment at {failure_stage}; {exception_type} left its status "
                "UNKNOWN and no evidence digest is claimed."
            )
        else:
            reason = (
                f"Tier {tier} {_TIER_NAMES[tier]} was not executed because Tier "
                f"{failed_tier} {_TIER_NAMES[failed_tier]} did not complete at "
                f"{failure_stage}; dependent execution requires PASS."
            )
        report["tier_execution"][key] = _tier_execution_record(
            tier,
            execution_status="NOT_RUN",
            status="UNKNOWN",
            reason=reason,
            blocking_prerequisite=blocking,
        )


def mechanism_digest() -> str:
    return binding.value_digest({
        "module": binding.bytes_digest(Path(__file__).read_bytes()),
        "specification": binding.bytes_digest(Path(__file__).parents[1].joinpath(
            "standard", "SELF_POLISH_STATICS.md").read_bytes()),
        "specimens": binding.bytes_digest(Path(specimens.__file__).read_bytes()),
        "adapters": binding.bytes_digest(Path(adapters.__file__).read_bytes()),
        "native": native.mechanism_digest(), "prerequisites": tiers.mechanism_digest(),
        "admission": tier_zero.mechanism_digest(),
    })


def _registry() -> tuple[dict[str, Any], dict[str, Any]]:
    inventory = core_tier_progression.installed_core_route_inventory()
    declarations = core_tier_progression.installed_core_route_declarations()
    _require(inventory.get("status") == "PASS", "STATICS_ROUTE_INVENTORY_NOT_PASS")
    cells = [cell for cell in inventory["family_cells"] if cell["tier"] == 3]
    rows = []
    for cell in cells:
        for member in cell["registered_route_memberships"]:
            key = cell["object_kind"], 3, member["coordinate"]
            declaration = declarations.get(key)
            _require(type(declaration) is dict,
                     "STATICS_APPLICABILITY_DECLARATION_MISSING")
            _require(
                type(declaration.get("reason")) is str
                and bool(declaration["reason"].strip()),
                "STATICS_APPLICABILITY_REASON_MISSING",
            )
            row = {
                "obligation_id": f"{cell['object_kind']}:{member['coordinate']}",
                "object_kind": cell["object_kind"], "tier": 3,
                **{name: member[name] for name in (
                    "coordinate", "proposition_digest", "semantic_version",
                    "certificate_schema_version", "checking_mechanism", "scope",
                )},
                "route_reason": declaration.get("reason"),
                "applicability": declaration.get("applicability"),
                "applicability_digest": declaration.get("applicability_digest"),
            }
            try:
                validate_applicability_binding(row)
            except (TypeError, ValueError) as exc:
                raise native.NativeReplayError(
                    "STATICS_APPLICABILITY_DECLARATION_INVALID"
                ) from exc
            rows.append(row)
    rows.sort(key=lambda row: row["obligation_id"])
    expected_declaration_keys = {
        (row["object_kind"], row["tier"], row["coordinate"])
        for row in rows
    }
    _require(
        {key for key in declarations if key[1] == 3}
        == expected_declaration_keys,
        "STATICS_APPLICABILITY_DECLARATION_DENOMINATOR_DIFFERS",
    )
    _require(len(cells) == 26 and len(rows) == 31
             and len({row["object_kind"] for row in rows}) == 26
             and len({row["obligation_id"] for row in rows}) == 31,
             "STATICS_ROUTE_DENOMINATOR_DIFFERS")
    _require({row["coordinate"] for row in rows} == set(_NECESSITY)
             and all(type(reason) is str and reason.strip() for reason in _NECESSITY.values()),
             "STATICS_NECESSITY_REASON_COVERAGE_DIFFERS")
    cases = specimens.installed_case_inputs()
    _require(type(cases) is dict and set(cases) == {row["obligation_id"] for row in rows},
             "STATICS_CASE_DENOMINATOR_DIFFERS")
    catalog = polish.polish_catalog()["routes"]
    catalog_bindings = []
    for row in rows:
        matched = [r for r in catalog if r.get("objective") == row["coordinate"]
                   and ("OBJECT" if r.get("represented_kind_rule") == "externally_selected_admitted_kind"
                        else r.get("represented_kind_rule")) == row["object_kind"]]
        _require(len(matched) == 1 and all(matched[0].get(k) == row[k]
                 for k in ("scope", "semantic_version", "proposition_digest", "certificate_schema_version")),
                 "STATICS_OBJECTIVE_BINDING_DIFFERS")
        catalog_bindings.append(binding.value_digest(matched[0]))
        case = cases[row["obligation_id"]]
        _require(type(case) is dict and set(case) == _ENTRY_KEYS
                 and case["checking_mechanism"] == row["checking_mechanism"]
                 and type(case["request"]) is dict and type(case["policy"]) is dict
                 and case["builder_adapter"] == ("WINDOWS_MODEL_HARDWARE_OBSERVATION"
                     if row["coordinate"] == "MODEL-3.2" else "BOUNDED_EVIDENCE_BYTES")
                 and case["negative_adapter"] == "MALFORMED_EVIDENCE_REBIND"
                 and case["unknown_adapter"] == "ABSENT_EVIDENCE",
                 "STATICS_CASE_BINDING_DIFFERS")
        _require(all(case["request"].get(k) == row[k] for k in
                     ("coordinate", "semantic_version", "proposition_digest"))
                 and case["request"].get("policy_digest") == binding.value_digest(case["policy"]),
                 "STATICS_REQUEST_BINDING_DIFFERS")
    registry = _seal({"schema_version": REGISTRY_SCHEMA,
        "status": "PASS", "scope": "INSTALLED_SOURCE_NATIVE_STATICS_ROUTES",
        "family_cell_count": len(cells), "membership_count": len(rows),
        "case_count": len(rows) * 3, "memberships": rows,
        "case_input_digest": binding.value_digest(cases),
        "specimen_module_digest": binding.bytes_digest(Path(specimens.__file__).read_bytes()),
        "catalog_binding_digest": binding.value_digest(catalog_bindings),
        "case_semantics": dict(native.CASE_OUTCOMES)}, "registry_digest")
    return registry, cases


def _package_source_binding(root: Path) -> dict[str, Any]:
    """Compare every installed Python module, including native dependencies."""
    package = Path(__file__).resolve().parents[1]
    files = {}
    for actual in sorted(package.rglob("*.py")):
        relative = actual.relative_to(package).as_posix()
        expected = root / "src" / "verifier" / relative
        _require(expected.is_file() and actual.read_bytes() == expected.read_bytes(),
                 "STATICS_INSTALLED_SOURCE_DIFFERS")
        files["src/verifier/" + relative] = binding.bytes_digest(actual.read_bytes())
    _require(bool(files), "STATICS_INSTALLED_SOURCE_UNAVAILABLE")
    return {"status": "PASS", "module_count": len(files),
            "module_manifest_digest": binding.value_digest(files),
            "claim_boundary": "Selected module file equality under the trusted local interpreter and import machinery; not execution or host attestation."}


_CONTRACT_ERRORS = (ValueError, TypeError, KeyError, AttributeError)
_CONTRACT_CODE = "STATICS_NATIVE_CASE_CONTRACT_REJECTED"
_MEMBERSHIP_CONTRACT_CODE = "STATICS_MEMBERSHIP_CONTRACT_REJECTED"


def _contract_code(exc: BaseException, generic: str) -> str:
    """Return a native-raised exact code, otherwise the supplied generic code.

    Only codes deliberately raised by the native replay or adapter layers are
    surfaced verbatim. Any other exception keeps its generic typed code, so a
    contract rejection is recorded as FAIL and never collapsed to UNKNOWN.
    """
    message = str(exc)
    if (
        isinstance(exc, (native.NativeReplayError, adapters.NativeReplayAdapterError))
        and re.fullmatch(r"[A-Z][A-Z0-9_]*", message)
    ):
        return message
    return generic


def _scope_limit(coordinate: str) -> str:
    if coordinate == "SIM-3.4":
        return "Exact selected SIM-to-distinct-law statement relation only; physical law truth, dimensional correctness, physical applicability and law independence are NOT_ESTABLISHED."
    if coordinate == "MODEL-3.2":
        return "Fresh selected Windows processor committed-memory bracket only; universal minimum memory, physical device authenticity and cross-runtime portability are NOT_ESTABLISHED."
    return "Only the selected native proposition; retained records do not authenticate external history, physical reality or application-wide completeness."


def _case_record(kind: str, **fields: Any) -> dict[str, Any]:
    """One exact polarity record; native_status stays NOT_EXECUTED until a checker returns."""
    return {
        "case_kind": kind,
        "expected_native_status": native.CASE_OUTCOMES[kind],
        "selected_request_digest": None,
        "policy_digest": None,
        "evidence_digest": None,
        "certificate_digest": None,
        "native_result": None,
        "native_result_digest": None,
        "native_status": "NOT_EXECUTED",
        "status": "UNKNOWN",
        "contract_code": None,
        "exception_type": None,
        "contract_detail": None,
        "reason": None,
        **fields,
    }


def _retention(obligation_id: str, selected: dict[str, Any],
               review_row: Any) -> dict[str, Any] | None:
    """Return the retained-UNKNOWN record for a reviewed coordinate, or None.

    A retained coordinate is never executed against its stale pin, so it cannot
    satisfy conformance. The retained digest and prior pin must still match the
    installed selection; a disagreement is a contract rejection, not UNKNOWN.
    """
    if type(review_row) is not dict:
        raise native.NativeReplayError("STATICS_SOURCE_REVIEW_ROUTE_MISSING")
    if review_row.get("disposition") not in ("ACCEPT_REPIN", "RETAIN_UNKNOWN"):
        raise native.NativeReplayError("STATICS_SOURCE_REVIEW_DISPOSITION_INVALID")
    if review_row["disposition"] == "ACCEPT_REPIN":
        return None
    raw_change_class = review_row.get("change_class")
    if type(raw_change_class) is not list or not raw_change_class:
        raise native.NativeReplayError("STATICS_RETAINED_CASE_BINDING_DIFFERS")
    _require(
        all(type(item) is str and item.strip() for item in raw_change_class)
        and _is_digest(review_row.get("retained_case_digest"))
        and _is_digest(review_row.get("prior_mechanism_digest"))
        and _is_digest(review_row.get("reviewed_mechanism_digest"))
        and binding.value_digest(selected) == review_row["retained_case_digest"]
        and selected["policy"].get("mechanism_digest") == review_row["prior_mechanism_digest"]
        and review_row["reviewed_mechanism_digest"] != review_row["prior_mechanism_digest"],
        "STATICS_RETAINED_CASE_BINDING_DIFFERS",
    )
    change_class: list[str] = list(raw_change_class)
    return {
        "disposition": "RETAIN_UNKNOWN",
        "change_class": change_class,
        "prior_mechanism_digest": review_row["prior_mechanism_digest"],
        "reviewed_mechanism_digest": review_row["reviewed_mechanism_digest"],
        "retained_case_digest": review_row["retained_case_digest"],
        "reason": (
            f"{obligation_id} was deliberately RETAIN_UNKNOWN after its checking "
            f"mechanism changed ({', '.join(change_class)}). Its prior pinned triad "
            "is not re-executed, so this coordinate cannot satisfy conformance. "
            "Next action: review the changed mechanism, then regenerate the installed "
            "case and source-review registry with an ACCEPT_REPIN disposition for the "
            "reviewed mechanism digest."
        ),
    }


def _executed_case(kind: str, *, builder: Any, checker: Any, selected: dict[str, Any],
                   case_request: dict[str, Any], case_evidence: bytes,
                   policy: dict[str, Any]) -> dict[str, Any]:
    """Build and recheck one native polarity; contract rejections become FAIL."""
    case = _case_record(
        kind,
        selected_request_digest=binding.value_digest(case_request),
        policy_digest=binding.value_digest(policy),
        evidence_digest=None if kind == "UNKNOWN" else binding.bytes_digest(case_evidence),
    )
    try:
        certificate = adapters.build_certificate(selected["builder_adapter"],
            selected["unknown_adapter"] if kind == "UNKNOWN" else kind,
            builder, case_request, case_evidence, policy)
        _require(type(certificate) is bytes and len(certificate) <= native.MAX_CERTIFICATE_BYTES,
                 "STATICS_CERTIFICATE_CAPACITY_EXHAUSTED")
        result = checker(certificate, expected_request=case_request, policy=policy)
        actual = result.get("status") if type(result) is dict else None
        _require(actual in ("PASS", "FAIL", "UNKNOWN"), "STATICS_NATIVE_OUTCOME_INVALID")
        # Positive UNKNOWN stays UNKNOWN; every other mismatch, including a
        # negative or absent-evidence control returning UNKNOWN, is a FAIL.
        case["status"] = ("PASS" if actual == case["expected_native_status"] else
                          "UNKNOWN" if kind == "POSITIVE" and actual == "UNKNOWN" else "FAIL")
        case.update(native_status=actual, native_result=result,
            native_result_digest=binding.value_digest(result),
            certificate_digest=binding.bytes_digest(certificate))
    except _RESOURCE_ERRORS:
        case["status"] = "FAIL" if case["status"] == "FAIL" else "UNKNOWN"
        case["contract_code"] = "STATICS_NATIVE_MECHANISM_UNAVAILABLE"
    except _CONTRACT_ERRORS as exc:
        case.update(status="FAIL", contract_code=_contract_code(exc, _CONTRACT_CODE),
                    exception_type=type(exc).__name__, contract_detail=str(exc)[:512])
    return case


def _replay_membership(root: Path, row: dict[str, Any], selected: dict[str, Any],
                       review_row: Any, *, registry_digest: str,
                       source_coordinate_digest: str) -> dict[str, Any]:
    applicability = _assess_membership_applicability(row, _native_applicability_evidence(
        row, selected, source_coordinate_digest=source_coordinate_digest,
    ))
    dotted = row["checking_mechanism"]
    module, symbol = dotted.rsplit(".", 1)
    checker, path, source_digest = native._resolve_mechanism(root, dotted)
    _require(symbol.startswith("recheck_"), "STATICS_BUILDER_UNAVAILABLE")
    builder, builder_path, builder_digest = native._resolve_mechanism(
        root, module + "." + symbol.replace("recheck_", "build_", 1))
    _require((path, source_digest) == (builder_path, builder_digest), "STATICS_BUILDER_SOURCE_DIFFERS")
    request, policy = selected["request"], selected["policy"]
    evidence = base64.b64decode(selected["evidence_base64"], validate=True)
    _require(0 < len(evidence) <= native.MAX_CERTIFICATE_BYTES, "STATICS_EVIDENCE_CAPACITY_EXHAUSTED")
    retention = _retention(row["obligation_id"], selected, review_row)
    if retention is None:
        negative = adapters.negative_case(selected["negative_adapter"], request, evidence, policy=policy)
        unavailable = adapters.unknown_case(selected["unknown_adapter"], request, evidence, policy=policy)
        cases = [
            _executed_case(kind, builder=builder, checker=checker, selected=selected,
                           case_request=case_request, case_evidence=case_evidence, policy=policy)
            for kind, (case_request, case_evidence) in zip(
                native.CASE_KINDS, ((request, evidence), negative, unavailable))
        ]
    else:
        # The stale triad is not executed; each polarity is exactly UNKNOWN.
        cases = [
            _case_record(kind, policy_digest=binding.value_digest(policy),
                         status="UNKNOWN", reason=retention["reason"])
            for kind in native.CASE_KINDS
        ]
    status = _join([case["status"] for case in cases] + [applicability["status"]])
    reason = {"classification": applicability["classification"],
        "necessity_reason": _NECESSITY[row["coordinate"]],
        "applicability_status": applicability["status"],
        "applicability_reason": applicability["reason"],
        "condition_status": applicability["condition_status"],
        "fulfillment_required": applicability["fulfillment_required"],
        "applicability_declaration": applicability["declaration"],
        "applicability_digest": applicability["applicability_digest"],
        "condition_evidence_digest": applicability["condition_evidence_digest"],
        "fulfillment_status": status, "fulfillment_reason": (
            "Fresh native building and rechecking must accept the positive, reject the malformed-bound negative, "
            "and preserve UNKNOWN for absent evidence. Unavailable positive evidence never satisfies the obligation."),
        "scope_limit": _scope_limit(row["coordinate"]),
        "selected_input_digest": binding.value_digest(selected),
        "registry_digest": registry_digest,
        "source_coordinate_digest": source_coordinate_digest}
    return _seal({**row, "status": status,
        "mechanism_source_path": path, "mechanism_source_digest": source_digest,
        "retention": retention, "reason": reason, "cases": cases}, "membership_replay_digest")


def _failed_membership(row: dict[str, Any], *, code: str, exception_type: str, detail: str,
                       registry_digest: str, source_coordinate_digest: str) -> dict[str, Any]:
    """Keep one membership's exact identity when its contract is rejected."""
    cases = [
        _case_record(kind, status="FAIL", contract_code=code,
                     exception_type=exception_type, contract_detail=detail)
        for kind in native.CASE_KINDS
    ]
    reason = {"classification": "UNDETERMINED",
        "necessity_reason": _NECESSITY[row["coordinate"]],
        "applicability_status": None,
        "fulfillment_status": "FAIL",
        "fulfillment_reason": "The membership contract was rejected before its native cases could establish conformance; the typed code is retained.",
        "contract_code": code, "exception_type": exception_type,
        "scope_limit": _scope_limit(row["coordinate"]),
        "registry_digest": registry_digest,
        "source_coordinate_digest": source_coordinate_digest}
    return _seal({**row, "status": "FAIL",
        "mechanism_source_path": None, "mechanism_source_digest": None,
        "retention": None, "reason": reason, "cases": cases}, "membership_replay_digest")


def _membership_blockers(memberships: list[dict[str, Any]]) -> list[str]:
    blockers = []
    for membership in memberships:
        obligation = membership["obligation_id"]
        if membership["retention"] is not None:
            blockers.append(f"{obligation}:RETAINED_UNKNOWN")
        applicability_status = membership["reason"]["applicability_status"]
        if applicability_status not in (None, "PASS"):
            blockers.append(f"{obligation}:APPLICABILITY:{applicability_status}")
        for case in membership["cases"]:
            if case["status"] != "PASS":
                blockers.append(f"{obligation}:{case['case_kind']}:{case['status']}")
            if case["contract_code"]:
                blockers.append(case["contract_code"])
    return blockers


def _installed_review() -> dict[str, Any]:
    try:
        return specimens.installed_source_review()
    except ValueError as exc:
        raise native.NativeReplayError("STATICS_SOURCE_REVIEW_INVALID") from exc


def replay_statics(source_root: str | Path, *, source_coordinate_digest: str) -> dict[str, Any]:
    """Execute every source-owned Tier-3 triad with exact per-case tri-state.

    A retained coordinate is never executed against its stale pin and stays
    UNKNOWN. A contract rejection is a typed FAIL for that membership only, so
    every other exact polarity, object and obligation remains in the census.
    Unavailable positives never pass.
    """
    report: dict[str, Any] = {"schema_version": REPLAY_SCHEMA, "tier": 3,
        "status": "UNKNOWN", "source_coordinate_digest": source_coordinate_digest,
        "registry": None, "mechanism_digest": None, "memberships": [],
        "membership_count": 0, "case_count": 0, "reasoned_route_count": 0,
        "blockers": [], "full_application_status": "UNKNOWN", "release_authorized": False,
        "whole_tier_conformance": "NOT_ESTABLISHED"}
    try:
        _require(type(source_coordinate_digest) is str and bool(re.fullmatch(
            r"sha256:[0-9a-f]{64}", source_coordinate_digest)), "STATICS_SOURCE_PIN_INVALID")
        root = Path(source_root).resolve(strict=True)
        report["pre_replay_package_binding"] = _package_source_binding(root)
        report["mechanism_digest"] = mechanism_digest()
        registry, cases = _registry()
        report["registry"] = registry
        review = _installed_review()
        for row in registry["memberships"]:
            try:
                membership = _replay_membership(
                    root, row, cases[row["obligation_id"]], review.get(row["obligation_id"]),
                    registry_digest=registry["registry_digest"],
                    source_coordinate_digest=source_coordinate_digest,
                )
            except _CONTRACT_ERRORS as exc:
                membership = _failed_membership(
                    row, code=_contract_code(exc, _MEMBERSHIP_CONTRACT_CODE),
                    exception_type=type(exc).__name__, detail=str(exc)[:512],
                    registry_digest=registry["registry_digest"],
                    source_coordinate_digest=source_coordinate_digest,
                )
            report["memberships"].append(membership)
        report["post_replay_package_binding"] = _package_source_binding(root)
        _require(report["post_replay_package_binding"] == report["pre_replay_package_binding"]
                 and mechanism_digest() == report["mechanism_digest"], "STATICS_REPLAY_SOURCE_CHANGED")
        report["status"] = _join([row["status"] for row in report["memberships"]])
    except _RESOURCE_ERRORS:
        # Completed FAIL memberships survive a later outage: FAIL dominates.
        observed_failure = any(case["status"] == "FAIL"
                               for row in report["memberships"] for case in row["cases"])
        report["status"] = "FAIL" if observed_failure else "UNKNOWN"
        report["blockers"].append("STATICS_REPLAY_UNAVAILABLE")
    except native.NativeReplayError as exc:
        report["status"] = "FAIL"
        report["blockers"].append(str(exc))
    except _CONTRACT_ERRORS:
        report["status"] = "FAIL"
        report["blockers"].append("STATICS_REPLAY_CONTRACT_REJECTED")
    report["blockers"].extend(_membership_blockers(report["memberships"]))
    report["membership_count"] = len(report["memberships"])
    report["case_count"] = sum(len(row["cases"]) for row in report["memberships"])
    report["reasoned_route_count"] = len(report["memberships"])
    report["blockers"] = sorted(set(report["blockers"]))
    if report["status"] == "PASS" and (report["blockers"] or report["membership_count"] != 31):
        report["status"] = "UNKNOWN"
    return _seal(report, "receipt_digest")


def _capture_coordinate(root: Path) -> dict[str, Any]:
    captured = polish_requirements.capture_core_self_polish_source(root)
    return {"source_head": captured["git_head"], "source_tree": captured["git_tree"],
        "source_worktree_status_digest": captured["worktree_status_digest"],
        "source_manifest_digest": polish_requirements.source_manifest_digest(captured)}


def assess_self_polish_statics(source_root: str | Path | None, *, cancelled: bool = False) -> dict[str, Any]:
    """Fresh admission, Facets and Dynamics followed by the complete Statics union.

    Retained caller reports and external application selections are deliberately
    not accepted by this fixed source-native profile.
    """
    report: dict[str, Any] = {"schema_version": REPORT_SCHEMA, "tier": 3, "tier_name": "STATICS",
        "status": "UNKNOWN", "selected_tier_status": "UNKNOWN", "selected_depth": 0,
        "claim_scope": "SOURCE_BOUND_TIER3_NATIVE_STATICS", "mechanism_digest": None,
        "source_coordinate": None, "source_coordinate_digest": None, "prerequisites": {},
        "tier_execution": {},
        "complete_tier_evidence_replay": None, "blockers": [],
        "whole_tier_conformance": "NOT_ESTABLISHED", "full_application_status": "UNKNOWN",
        "polished": False, "release_authorized": False, "deployment_authorized": False,
        "application_authority": {"authority_status": "NOT_ESTABLISHED", "obligation": {
            "classification": "CONDITIONAL", "condition_status": "NOT_TRIGGERED",
            "condition": "EXTERNAL_APPLICATION_SCOPE_OR_SEMANTIC_COMPLETENESS_CLAIM",
            "necessity_reason": "External adoption or completeness claims require independent application authority; source self-observation cannot establish adoption.",
            "assessment_reason": "This fixed profile asserts only source-native route conformance and bounded source-estate closure. It asserts no external adoption, ownership authority or full-application semantic completeness."}},
        "claim_boundary": "Cumulative source-native Facets, Dynamics and Statics under fresh repository admission. Not full package GRAPH polish, external application qualification, physical truth, historical resource attestation or release authority."}
    active_tier = 0
    active_stage = "SOURCE_COORDINATE_CAPTURE"
    try:
        _require(type(cancelled) is bool, "STATICS_CANCELLATION_INVALID")
        if cancelled or source_root is None:
            report["blockers"].append("STATICS_CANCELLED" if cancelled else "STATICS_SOURCE_ROOT_REQUIRED")
            return _seal(report, "report_digest")
        root = Path(source_root).resolve(strict=True)
        coordinate = _capture_coordinate(root)
        active_stage = "MECHANISM_BINDING"
        report.update(source_coordinate=coordinate, source_coordinate_digest=binding.value_digest(coordinate),
                      mechanism_digest=mechanism_digest())
        for tier in (0, 1, 2):
            active_tier = tier
            active_stage = f"TIER{tier}_{_TIER_NAMES[tier]}_ASSESSMENT"
            if tier == 0:
                prior = tier_zero.assess_tier_zero(root)
            elif tier == 1:
                prior = tiers.assess_self_polish_tier(1, source_root=root)
            else:
                one = report["prerequisites"]["1"]
                prior = tiers.assess_self_polish_tier(2, source_root=root,
                    tier1_report_bytes=binding.canonical_bytes(one),
                    expected_tier1_report_digest=one["report_digest"])
            _require(prior["report_digest"] == binding.value_digest({
                k: v for k, v in prior.items() if k != "report_digest"}), "STATICS_PREREQUISITE_DIGEST_DIFFERS")
            _require(prior["status"] in ("PASS", "FAIL", "UNKNOWN"), "STATICS_PREREQUISITE_STATUS_INVALID")
            if prior["status"] != "PASS":
                report["prerequisites"][str(tier)] = prior
                report["tier_execution"][str(tier)] = _tier_execution_record(
                    tier,
                    execution_status="EXECUTED",
                    status=prior["status"],
                    reason=(
                        f"Fresh Tier {tier} {_TIER_NAMES[tier]} prerequisite "
                        "assessment was executed for this source coordinate."
                    ),
                    evidence_digest=prior["report_digest"],
                )
                report["status"] = prior["status"]
                report["blockers"].append(f"TIER{tier}_FRESH_PASS_REQUIRED")
                report["blockers"].extend(f"TIER{tier}:{b}" for b in prior["blockers"])
                blocking = {
                    "tier": tier,
                    "tier_name": _TIER_NAMES[tier],
                    "required_status": "PASS",
                    "observed_status": prior["status"],
                    "report_digest": prior["report_digest"],
                    "blockers": list(prior["blockers"]),
                }
                for skipped_tier in range(tier + 1, 4):
                    report["tier_execution"][str(skipped_tier)] = \
                        _tier_execution_record(
                            skipped_tier,
                            execution_status="NOT_RUN",
                            status="UNKNOWN",
                            reason=(
                                f"Tier {skipped_tier} {_TIER_NAMES[skipped_tier]} was not "
                                f"executed because fresh Tier {tier} {_TIER_NAMES[tier]} "
                                f"status was {prior['status']}; dependent execution requires PASS."
                            ),
                            blocking_prerequisite=blocking,
                        )
                break
            _require(not prior["blockers"] and prior["polished"] is False
                     and prior["release_authorized"] is False,
                     "STATICS_PREREQUISITE_BOUNDARY_DIFFERS")
            if tier:
                _require(prior["source_coordinate"] == coordinate
                         and prior["source_coordinate_digest"] == report["source_coordinate_digest"]
                         and prior["whole_tier_conformance"] == prior["selected_tier_status"] == "PASS"
                         and prior["post_replay_full_source_recapture"] == "PASS"
                         and prior["repository_package_estate_closure"] == "PASS"
                         and not prior["blockers"], "STATICS_PREREQUISITE_SOURCE_OR_CLOSURE_DIFFERS")
                report["selected_depth"] = tier
            report["prerequisites"][str(tier)] = prior
            report["tier_execution"][str(tier)] = _tier_execution_record(
                tier,
                execution_status="EXECUTED",
                status=prior["status"],
                reason=(
                    f"Fresh Tier {tier} {_TIER_NAMES[tier]} prerequisite assessment "
                    "was executed for this source coordinate."
                ),
                evidence_digest=prior["report_digest"],
            )
        if not report["blockers"]:
            active_tier = 3
            active_stage = "TIER3_STATICS_REPLAY"
            replay = replay_statics(root, source_coordinate_digest=report["source_coordinate_digest"])
            report["complete_tier_evidence_replay"] = replay
            report["tier_execution"]["3"] = _tier_execution_record(
                3,
                execution_status="EXECUTED",
                status=replay["status"],
                reason="The complete fresh Tier 3 Statics union was executed.",
                evidence_digest=(
                    replay.get("receipt_digest") or binding.value_digest(replay)
                ),
            )
            report["status"] = replay["status"]
            report["blockers"].extend(replay["blockers"])
        active_stage = "POST_REPLAY_SOURCE_RECAPTURE"
        recapture = tiers._post_replay_source_recapture(root, coordinate)
        report["post_replay_source_recapture"] = recapture
        report["post_replay_full_source_recapture"] = recapture["status"]
        report["status"] = _join([report["status"], recapture["status"]])
        if recapture["status"] != "PASS":
            report["blockers"].append("STATICS_FULL_SOURCE_RECAPTURE_NOT_PASS")
        _require(mechanism_digest() == report["mechanism_digest"], "STATICS_ASSESSMENT_MECHANISM_CHANGED")
    except (polish_requirements.MechanismBindingUnavailable, *_RESOURCE_ERRORS) as exc:
        report["status"] = "FAIL" if report["status"] == "FAIL" else "UNKNOWN"
        blocker = "STATICS_ASSESSMENT_UNAVAILABLE"
        report["blockers"].append(blocker)
        _record_incomplete_tier_execution(
            report,
            failed_tier=active_tier,
            failure_stage=active_stage,
            blocker=blocker,
            exception_type=type(exc).__name__,
        )
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
        report["status"] = "FAIL"
        blocker = str(exc) or "STATICS_ASSESSMENT_CONTRACT_REJECTED"
        report["blockers"].append(blocker)
        _record_incomplete_tier_execution(
            report,
            failed_tier=active_tier,
            failure_stage=active_stage,
            blocker=blocker,
            exception_type=type(exc).__name__,
        )
    except Exception as exc:
        report["status"] = "FAIL"
        blocker = "STATICS_ASSESSMENT_UNEXPECTED_EXCEPTION"
        report["blockers"].append(blocker)
        _record_incomplete_tier_execution(
            report,
            failed_tier=active_tier,
            failure_stage=active_stage,
            blocker=blocker,
            exception_type=type(exc).__name__,
        )
    if report["status"] == "PASS" and report["blockers"]:
        report["status"] = "UNKNOWN"
    if report["status"] == "PASS":
        report.update(selected_depth=3, whole_tier_conformance="PASS")
    report["selected_tier_status"] = report["status"]
    report["blockers"] = sorted(set(report["blockers"]))
    return _seal(report, "report_digest")

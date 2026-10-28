"""Source-native Dynamics reasons and cumulative route replay.

This is a fixed installed-route progression, not an application certificate
directed acyclic graph (DAG). Caller-authored verdicts are never inputs. Every
assessment rebuilds and replays all Facets and Dynamics native specimens.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from verifier.runtime import core_obligation_union as binding
from verifier.runtime import self_polish_native_replay as native


SCHEMA = "verifier-self-polish-native-dynamics-progression-2"
REASON_SCHEMA = "verifier-self-polish-dynamics-reasons-2"

# Each reason states why this particular bounded Dynamics claim needs evidence.
# Registry membership alone supplies scope, not the reason for the obligation.
_NECESSITY = {
    "ACTOR-2.7": "Declared actor state changes require replay of the selected event order; a final state alone cannot establish the transitions.",
    "AGENT-2.1": "A claimed agent trajectory requires the selected steps to reproduce under its declared transition rules.",
    "AGENT-2.3": "Selected agent actions must correspond to the admitted action rules; a trajectory label does not establish that correspondence.",
    "ARCH-2.1": "A static architecture execution order must respect its selected graph dependencies before the schedule can be claimed valid.",
    "BENCH-2.1": "A benchmark attempt-policy claim requires the selected attempts to obey that policy rather than merely reporting a score.",
    "BOT-2.1": "A bot alignment claim needs correspondence between the selected behavior and its declared alignment constraints.",
    "BOT-2.2": "A bot observation claim requires the selected observation records to satisfy its declared observation contract.",
    "BOT-2.3": "A bot actuation claim requires the selected actuation records to satisfy the declared actuation contract.",
    "COLLECTIVE-2.1": "Collective membership changes require role admission and departure replay so a final roster cannot conceal an invalid transition.",
    "DATA-2.1": "A data-lineage claim requires correspondence across the selected transformations; naming an ancestor does not establish derivation.",
    "ENV-2.3": "Environment reproduction requires replay of the selected reproduction evidence under the declared environment contract.",
    "EVENT-2.1": "Dispatch and acknowledgment claims require correspondence in the selected event records; declaration is not delivery evidence.",
    "GRAPH-2.1": "A claimed least topological order requires checking all selected directed edges and the ordering rule.",
    "HARDWARE-2.1": "Capacity reservations require the selected allocations to respect declared capacity rather than only naming available hardware.",
    "HARDWARE-2.2": "A measurement-envelope claim requires the selected measurements to satisfy the declared envelope, without asserting physical device truth.",
    "HARNESS-2.1": "Harness message behavior requires replay of selected message records against the declared message contract.",
    "HARNESS-2.2": "Harness tool behavior requires replay of selected tool interactions against the declared tool contract.",
    "HARNESS-2.3": "Harness effect behavior requires replay of the selected effects against the declared effect contract.",
    "HUMAN-2.5": "A declared biometric-template irreversibility claim requires checking the selected event log; it does not prove unobserved physical erasure.",
    "HYPER-2.3": "A composed verdict must preserve an unresolved direct operand, or composition could manufacture certainty from missing evidence.",
    "IDENTITY-2.1": "Identity lifecycle consistency requires the selected changes to obey declared lifecycle rules, not merely share a name.",
    "MODEL-2.1": "An inference claim requires correspondence of the selected model inputs and outputs under its admitted inference contract.",
    "OBJECT-2.1": "A version-lineage claim requires the selected linear predecessor relations to hold; a version label alone is insufficient.",
    "OWNER-2.6": "A holding-history claim requires replay of the selected ordered changes rather than trusting a final owner declaration.",
    "RECEIPT-2.1": "Receipt validation must reproduce the selected receipt audit; possession of a receipt is not evidence of its validity.",
    "ROLE-2.1": "Role occupancy requires replay of selected admission and departure transitions to establish the declared lifecycle consistency.",
    "SIM-2.1": "A simulated trajectory requires the installed transition interpreter to reproduce the selected states from the selected inputs.",
    "SIM-2.2": "An action-response claim requires correspondence under the selected simulation model; model-relative response is not physical validation.",
    "SIM-2.3": "An internal-state claim requires consistency with the selected model state, not an unsupported claim about hidden physical state.",
    "SIM-2.4": "A claim of resources actually consumed requires correspondence between the records and the selected execution. A signer can authenticate fabricated numbers, so signature validity alone cannot fulfill this obligation.",
    "SIM-2.5": "A macro-perspective claim requires alignment with the selected simulation projection rather than a separately asserted summary.",
    "SPACE-2.1": "A length-preserving partition migration requires checking the selected source, target, and migration relation for that preservation.",
    "TIME-2.1": "A declared clock order requires consistency of the selected ordered records; it does not establish external physical time.",
    "TOKEN-2.1": "A token-tenure claim requires the selected tenure transitions to satisfy the declared holding contract.",
    "TRAIN-2.1": "A training claim requires correspondence of the selected retained training trajectory under its declared contract.",
    "TRAIN-2.3": "A training-update claim requires the selected update records to satisfy the update rules rather than merely naming a new model.",
    "VERIFIER-2.1": "A verifier outcome claim requires correspondence to the installed simulation checker outcomes, including failure and uncertainty.",
}


def mechanism_digest() -> str:
    return binding.value_digest({
        "module": binding.bytes_digest(Path(__file__).read_bytes()),
        "native_replay": native.mechanism_digest(),
    })


def _join(statuses: list[str]) -> str:
    return ("FAIL" if "FAIL" in statuses else
            "PASS" if statuses and all(s == "PASS" for s in statuses) else "UNKNOWN")


def _replay(tier: int, source_root: str | Path, coordinate: str) -> dict[str, Any]:
    raw = native.build_installed_replay_manifest(
        tier, source_root, source_coordinate_digest=coordinate,
        fresh_execution=True,
    )
    return native.replay_native_obligations(
        raw, source_root, tier=tier,
        expected_manifest_digest=binding.bytes_digest(raw),
        expected_source_coordinate_digest=coordinate,
        fresh_execution=True,
    )


def _reasons(registry: dict, replay: dict, coordinate: str) -> dict[str, Any]:
    routes = registry["tiers"]["2"]
    if ({row["coordinate"] for row in routes} != set(_NECESSITY)
            or any(type(reason) is not str or not reason.strip()
                   for reason in _NECESSITY.values())):
        raise native.NativeReplayError("DYNAMICS_NECESSITY_REASON_COVERAGE_DIFFERS")
    members = {row["obligation_id"]: row for row in replay["memberships"]}
    entries = []
    for route in routes:
        identifier = route["obligation_id"]
        member = members.get(identifier)
        entries.append({
            "obligation_id": identifier,
            "membership": route,
            "classification": "NECESSARY",
            "necessity_reason": _NECESSITY[route["coordinate"]],
            "applicability_status": "PASS",
            "applicability_reason": (
                f"The source-native Dynamics claim explicitly includes {identifier} "
                f"in scope {route['scope']}. The installed registry selects this "
                "route and its positive, negative, and unavailable specimens. "
                + ("The fresh-execution SIM variant is selected; historical signed records are not promoted. "
                   + " ".join(native.sim_resource_fresh.REASONS.values())
                   if identifier == "SIM:SIM-2.4" else "No variant exclusion is claimed.")
            ),
            "fulfillment_status": member["status"] if member else "UNKNOWN",
            "fulfillment_reason": (
                "The installed checker freshly replays all three selected cases. "
                "Only matching native outcomes fulfill this bounded route; a "
                "positive UNKNOWN remains unresolved, never an exemption."
            ),
            "evidence": {
                "registry_digest": registry["registry_digest"],
                "source_coordinate_digest": coordinate,
                "native_replay_receipt_digest": replay["receipt_digest"],
                "membership_replay_digest": member["native_replay_digest"] if member else None,
            },
        })
    body = {
        "schema_version": REASON_SCHEMA,
        "status": "PASS",  # Reason coverage is separate from fulfillment.
        "scope": "INSTALLED_SOURCE_NATIVE_DYNAMICS_ROUTES",
        "reasoned_route_count": len(entries),
        "fulfillment_status": _join([row["fulfillment_status"] for row in entries]),
        "entries": entries,
        "claim_boundary": (
            "Reasons and exact replay bindings for this selected installed route "
            "union only. Not universal applicability for arbitrary repository "
            "objects, physical truth, or a proof that no other reasons can exist."
        ),
    }
    body["assessment_digest"] = binding.value_digest(body)
    return body


def assess_native_dynamics(source_root: str | Path, *,
        source_coordinate_digest: str, subject_id: str,
        prior_report_digest: str, cancelled: bool = False) -> dict[str, Any]:
    """Freshly replay the fixed cumulative 45/37 route selection.

    The numeric adapter must separately validate the retained Tier-1 full-estate
    report and recapture the source before and after this bounded operation.
    This function alone never establishes whole-tier or application conformance.
    """
    report: dict[str, Any] = {
        "schema_version": SCHEMA, "status": "UNKNOWN",
        "selected_target_status": "UNKNOWN", "selected_depth": 0,
        "subject": {"object_id": subject_id}, "tiers": [],
        "source_coordinate_digest": source_coordinate_digest,
        "prior_report_digest": prior_report_digest,
        "native_replay": "NOT_RUN", "native_assessments": {},
        "dynamics_reasons": None, "blockers": [],
        "full_application_status": "UNKNOWN", "polished": False,
        "release_authorized": False, "whole_tier_conformance": "NOT_ESTABLISHED",
        "claim_boundary": (
            "Fixed source-native route progression, not an externally selected "
            "application certificate DAG or historical resource attestation. "
            "Tier-2 clearance requires every Tier-1 and Tier-2 native route. "
            "Certificate-internal dependencies are checked by their native "
            "mechanisms; this report adds only the cumulative tier prerequisite."
        ),
    }
    try:
        if (type(cancelled) is not bool or type(subject_id) is not str or not subject_id
                or any(type(pin) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
                       for pin in (source_coordinate_digest, prior_report_digest))):
            raise native.NativeReplayError("DYNAMICS_SELECTION_INVALID")
        registry = native.installed_native_replay_registry(fresh_execution=True)
        if cancelled:
            report["blockers"].append("DYNAMICS_PROGRESSION_CANCELLED")
        else:
            cumulative = "PASS"
            for tier, name in ((1, "FACETS"), (2, "DYNAMICS")):
                report["native_replay"] = "ATTEMPTED"
                replay = _replay(tier, source_root, source_coordinate_digest)
                report["native_assessments"][str(tier)] = replay
                direct = replay["status"]
                cumulative = _join([cumulative, direct])
                report["tiers"].append({
                    "tier": tier, "tier_name": name,
                    "direct_status": direct, "cumulative_status": cumulative,
                    "required_routes": [row["obligation_id"] for row in registry["tiers"][str(tier)]],
                    "native_replay_receipt_digest": replay["receipt_digest"],
                })
                report["blockers"].extend(replay["invalidators"])
                if cumulative == "PASS":
                    report["selected_depth"] = tier
                # Preserve an observed failure if a later operation is unavailable.
                report["status"] = cumulative
            report["native_replay"] = "EXECUTED"
            report["dynamics_reasons"] = _reasons(
                registry, report["native_assessments"]["2"], source_coordinate_digest,
            )
            report["selected_target_status"] = cumulative
    except native.NativeReplayError as exc:
        report["status"] = "FAIL"
        report["blockers"].append(str(exc))
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError) as exc:
        prior_failure = report["status"] == "FAIL" or getattr(exc, "failure_observed", False)
        report["status"] = "FAIL" if prior_failure else "UNKNOWN"
        report["blockers"].append("DYNAMICS_PROGRESSION_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, AttributeError):
        report["status"] = "FAIL"
        report["blockers"].append("DYNAMICS_PROGRESSION_CONTRACT_REJECTED")
    # An unavailable later replay must not leave a partial PASS as the target.
    if len(report["tiers"]) < 2 and report["status"] == "PASS":
        report["status"] = "UNKNOWN"
    for tier, name in ((1, "FACETS"), (2, "DYNAMICS")):
        if len(report["tiers"]) < tier:
            report["tiers"].append({
                "tier": tier, "tier_name": name, "direct_status": "UNKNOWN",
                "cumulative_status": report["status"], "required_routes": [],
                "native_replay_receipt_digest": None,
            })
    if report["status"] != "PASS":
        report["selected_target_status"] = report["status"]
        # A post-replay reason failure must not leave a qualified Tier-2 depth.
        report["selected_depth"] = min(report["selected_depth"], 1)
    report["blockers"] = sorted(set(report["blockers"]))
    report["assessment_digest"] = binding.value_digest(report)
    return report

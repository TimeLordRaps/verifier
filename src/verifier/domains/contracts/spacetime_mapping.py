"""Retained HYPER relation between declared simulation and host TIME domains.

Simulation (SIM); JavaScript Object Notation (JSON). Mapping is partial and
piecewise over retained points, with explicit branches. It does not interpolate,
authenticate clocks, synchronize them or prove actual simulation execution.
"""
from __future__ import annotations

from typing import Any, Callable, Sequence
from verifier.core.certificate import canonical_digest
from verifier.core.contextual_namespace import ContextualObject, assess_contextual_composition
from verifier.core.namespace import ObjectKind
from verifier.domains.contracts import spacetime_profiles as profile

SUBJECT_VERSION = "verifier-sim-host-time-relation-1"
EVIDENCE_VERSION = "verifier-retained-sim-host-time-mapping-1"
ASSESSMENT_VERSION = "verifier-sim-host-time-mapping-assessment-1"


def assess_mapping(objects: Sequence[ContextualObject], *, subject_id: str,
        expected_subject_digest: str | None, expected_collection_digest: str | None,
        expected_evidence_digest: str | None, expected_run_id: str | None,
        evidence_bytes: bytes | None, cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    report = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "scope": "EXACT_RETAINED_PARTIAL_PIECEWISE_TIME_POINT_RELATION",
        "clock_authenticity_and_synchronization": "UNKNOWN",
        "simulation_execution": "UNKNOWN", "interpolation": "UNSUPPORTED"}
    if any(value is None for value in (expected_subject_digest, expected_collection_digest, expected_evidence_digest, expected_run_id)):
        return {**report, "reason": "independent exact mapping selection absent"}
    identity = assess_contextual_composition(objects, expected_digest=expected_collection_digest)
    if identity["status"] != "PASS":
        return {**report, "status": identity["status"], "reason": identity.get("reason")}
    try:
        if cancelled is not None and cancelled():
            raise profile.Unsupported("mapping replay cancelled")
        evidence = profile.capture(evidence_bytes)
        if "sha256:" + canonical_digest(evidence) != expected_evidence_digest:
            raise ValueError("mapping evidence commitment differs")
        profile.keys(evidence, "schema_version subject_digest collection_digest run_id pieces")
        if evidence["schema_version"] != EVIDENCE_VERSION:
            raise ValueError("separate mapping evidence version required")
        profile.text(expected_run_id)
        if evidence["subject_digest"] != expected_subject_digest or evidence["collection_digest"] != expected_collection_digest or evidence["run_id"] != expected_run_id:
            raise ValueError("independent mapping binding differs")
        by_id = {item.record.object_id: item for item in objects}
        subject = by_id.get(subject_id)
        if subject is None:
            raise profile.Unsupported("selected HYPER subject absent")
        if subject.digest != expected_subject_digest or subject.record.kind is not ObjectKind.HYPER:
            raise ValueError("selected HYPER subject digest/type differs")
        descriptor = subject.record.payload
        profile.keys(descriptor, "schema_version run_id sim_id")
        if descriptor["schema_version"] != SUBJECT_VERSION or descriptor["run_id"] != expected_run_id:
            raise ValueError("HYPER mapping descriptor/run differs")
        roles = dict(subject.record.operands)
        if set(roles) != {"simulation", "sim_times", "host_time"} or len(roles["simulation"]) != 1 or len(roles["host_time"]) != 1 or not roles["sim_times"]:
            raise ValueError("exact typed mapping roles required")
        sim_id, host_id = roles["simulation"][0], roles["host_time"][0]
        if descriptor["sim_id"] != sim_id or by_id[sim_id].record.kind is not ObjectKind.SIM:
            raise ValueError("SIM mapping operand differs")
        times, used = {}, 0
        for name in (*roles["sim_times"], host_id):
            item = by_id[name].record
            if item.kind is not ObjectKind.TIME:
                raise ValueError("mapping TIME operand has wrong kind")
            parsed = profile.time_profile(item.payload)
            used += len(parsed["points"])+len(item.payload["order"])+1
            if used > profile.LIMITS["max_operations"]:
                raise profile.Exhausted("mapping profile replay operation bound exhausted")
            domain = parsed["descriptor"]
            if domain["run_id"] != expected_run_id or domain["branch_id"] is None:
                raise ValueError("mapping TIME run/branch binding differs")
            if domain["profile"] == "logical-partial/1":
                raise profile.Unsupported("scalar mapping of a partial-order domain is unimplemented")
            if name != host_id and domain["profile"] != "logical-strict/1":
                raise profile.Unsupported("SIM mapping requires explicit logical strict trajectories")
            times[name] = parsed
        if host_id in roles["sim_times"]:
            raise ValueError("host and simulation TIME roles must be distinct")
        sim_domains = [times[name]["descriptor"] for name in roles["sim_times"]]
        if len({row["branch_id"] for row in sim_domains}) != len(sim_domains):
            raise ValueError("SIM branch identifiers are ambiguous")
        if any(any(row[field] != sim_domains[0][field] for field in ("domain", "unit", "epoch", "profile")) for row in sim_domains):
            raise ValueError("SIM trajectories mix incompatible declared domains")
        pieces = profile._list(evidence["pieces"], nonempty=True)
        previous_sim, previous_point, previous_host = None, None, None
        visited_branches = set()
        summaries = []
        for piece in pieces:
            if cancelled is not None and cancelled():
                raise profile.Unsupported("mapping replay cancelled")
            profile.keys(piece, "kind sim_time_id host_time_id pairs rollback_from")
            kind, sim_time = piece["kind"], piece["sim_time_id"]
            if kind not in ("advance", "pause", "step", "rollback"):
                raise profile.Unsupported("mapping piece capability is unimplemented")
            if sim_time not in roles["sim_times"] or piece["host_time_id"] != host_id:
                raise ValueError("mapping piece substitutes typed TIME roles")
            pairs = profile._list(piece["pairs"], nonempty=True)
            if kind != "rollback" and len(pairs) < 2:
                raise profile.Unsupported("mapping progression observations incomplete")
            parsed_sim, parsed_host = times[sim_time], times[host_id]
            retained = []
            for pair in pairs:
                used += 1
                if used > profile.LIMITS["max_operations"]:
                    raise profile.Exhausted("mapping operation bound exhausted")
                profile.keys(pair, "sim host")
                if pair["sim"] not in parsed_sim["points"] or pair["host"] not in parsed_host["points"]:
                    raise profile.Unsupported("selected mapping point absent")
                retained.append((pair["sim"], parsed_sim["points"][pair["sim"]], parsed_host["points"][pair["host"]], pair["host"]))
            if kind == "rollback":
                rollback = profile.keys(piece["rollback_from"], "sim_time_id point")
                if previous_sim is None or sim_time in visited_branches or rollback != {"sim_time_id": previous_sim, "point": previous_point}:
                    raise ValueError("rollback requires exact previous endpoint and a distinct retained branch")
                if retained[0][1] >= times[previous_sim]["points"][previous_point]:
                    raise ValueError("rollback does not decrease the selected cross-branch logical coordinate")
            else:
                if piece["rollback_from"] is not None or (previous_sim is not None and sim_time != previous_sim):
                    raise ValueError("trajectory branch changed without explicit rollback")
                if previous_sim is not None and retained[0][1] < times[previous_sim]["points"][previous_point]:
                    raise ValueError("same-branch mapping silently rolls back")
            def host_relation(left_point: str, right_point: str) -> str:
                compared = profile.compare_parsed_time(parsed_host, left_point, parsed_host, right_point)
                if compared["status"] != "PASS":
                    raise profile.Unsupported(compared.get("reason", "retained host order unestablished"))
                return compared["relation"]

            if previous_host is not None and host_relation(previous_host, retained[0][3]) == "AFTER":
                raise ValueError("retained host mapping order decreases")
            rates = []
            for left, right in zip(retained, retained[1:]):
                relation = host_relation(left[3], right[3])
                if relation == "AFTER":
                    raise ValueError("retained host mapping order decreases")
                sim_delta = profile.checked_fraction(right[1] - left[1])
                host_delta = profile.checked_fraction(right[2] - left[2])
                if host_delta < 0 or sim_delta < 0 or (kind == "pause" and (sim_delta != 0 or host_delta <= 0)) or (kind in ("advance", "rollback") and (sim_delta <= 0 or host_delta <= 0)) or (kind == "step" and sim_delta <= 0):
                    raise ValueError("retained piece violates selected pause/step/progression meaning")
                if host_delta == 0:
                    rates.append({"kind": "NONINVERTIBLE_STEP", "ratio": None})
                else:
                    rate = profile.checked_fraction(sim_delta / host_delta)
                    rates.append({"kind": "FINITE_RETAINED_RATE", "ratio": profile.rational(rate.numerator, rate.denominator)})
            summaries.append({"kind": kind, "sim_time_id": sim_time, "host_time_id": host_id,
                "pairs": len(retained), "rates": rates,
                "sim_unit": parsed_sim["descriptor"]["unit"], "host_unit": parsed_host["descriptor"]["unit"]})
            previous_sim, previous_point, previous_host = sim_time, retained[-1][0], retained[-1][3]
            visited_branches.add(sim_time)
        result = {**report, "status": "PASS", "pieces": summaries,
            "evidence_digest": expected_evidence_digest, "collection_digest": expected_collection_digest,
            "subject_digest": expected_subject_digest, "run_id": expected_run_id}
        from verifier.core.certificate import canonical_bytes
        if len(canonical_bytes(result)) > profile.LIMITS["max_bytes"]:
            raise profile.Exhausted("mapping output byte bound exhausted; observations not retained")
        return result
    except (profile.Unsupported, profile.Exhausted) as exc:
        return {**report, "reason": str(exc)[:256]}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)[:256]}

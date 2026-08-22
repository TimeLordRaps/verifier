"""Verify the public SimulacraBench synthetic closed-evaluation packet.

This verifier performs no network access and never receives the hidden synthetic
respondent fixture. It checks public commitments, derives an ``IDENTIFIED`` floor for
the unobserved private artifacts, and admits a structural challenge. It does not
recompute the private-data score, execute retrieval, adjudicate the challenge, or create
an independent trust root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from verifiable.core.certificate import ClaimCoordinate, canonical_bytes, canonical_digest
from verifiable.data.models import ArtifactStatus
from verifiable.layer4.availability import (
    ArtifactAvailability,
    AvailabilityLevel,
    RetentionPolicy,
    assess_bundle,
)
from verifiable.layer4.challenge import Challenge, ChallengeLedger
from verifiable.layer4.surface import (
    AdmissibleRefutation,
    ExcludedClaim,
    RefutationSurface,
    RefutationType,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_PACKET = ROOT / "public_packet.json"
DEFAULT_CHALLENGE = ROOT / "challenge_demo.json"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RETENTION_HORIZON = "2026-09-30T23:59:59Z"
UPSTREAM_REPOSITORY = "https://github.com/SituatedEvals/public"
PINNED_COMMIT = "1bb2d46026fe0d91979448c3d916506be0608513"
SOURCE_PATHS = (
    "README.md",
    "LICENSE",
    "config.yml",
    "data/sample.json",
    "make_sandbox.py",
    "score.py",
    "baseline/marginal_counts/main.py",
    "baseline/marginal_counts/requirements.txt",
    "tools/check_submission_zip.py",
)
EVIDENCE_POLICY = {
    "upstream-01-README-md": (False, "public", "SELF_CONTAINED"),
    "upstream-02-LICENSE": (False, "public", "SELF_CONTAINED"),
    "upstream-03-config-yml": (True, "public", "SELF_CONTAINED"),
    "upstream-04-data-sample-json": (True, "public", "SELF_CONTAINED"),
    "upstream-05-make_sandbox-py": (True, "public", "SELF_CONTAINED"),
    "upstream-06-score-py": (True, "public", "SELF_CONTAINED"),
    "upstream-07-baseline-marginal_counts-main-py": (
        True,
        "public",
        "SELF_CONTAINED",
    ),
    "upstream-08-baseline-marginal_counts-requirements-txt": (
        True,
        "public",
        "SELF_CONTAINED",
    ),
    "upstream-09-tools-check_submission_zip-py": (
        False,
        "public",
        "SELF_CONTAINED",
    ),
    "submission-archive": (True, "public", "SELF_CONTAINED"),
    "public-sandbox-schema-view": (False, "public", "SELF_CONTAINED"),
    "scored-sandbox-schema": (True, "access-controlled", "IDENTIFIED"),
    "hidden-synthetic-fixture": (True, "access-controlled", "IDENTIFIED"),
    "organizer-log": (True, "access-controlled", "IDENTIFIED"),
    "execution-transcript": (True, "access-controlled", "IDENTIFIED"),
    "generator-seed": (False, "access-controlled", "IDENTIFIED"),
    "participant-visible-result": (True, "public", "SELF_CONTAINED"),
}


class PacketError(ValueError):
    """Raised when the public specimen overstates or contradicts its evidence."""


def _record(value: Any, required: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PacketError(f"{label} must be an object")
    missing = sorted(required - set(value))
    if missing:
        raise PacketError(f"{label} is missing fields: {missing}")
    extra = sorted(set(value) - required)
    if extra:
        raise PacketError(f"{label} has unexpected fields: {extra}")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PacketError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PacketError(f"{path} root must be an object")
    return value


def _verify_document_digest(document: dict[str, Any], field: str) -> str:
    stated = document.get(field)
    if not isinstance(stated, str) or not SHA256.fullmatch(stated):
        raise PacketError(f"{field} must be a sha256 content address")
    payload = dict(document)
    del payload[field]
    observed = f"sha256:{canonical_digest(payload)}"
    if observed != stated:
        raise PacketError(f"{field} mismatch: stated {stated}, observed {observed}")
    return observed


def _availability_item(
    entry: Mapping[str, Any], reported_result: Mapping[str, Any]
) -> ArtifactAvailability:
    required = {
        "artifact_id",
        "role",
        "disclosure",
        "content_address",
        "verdict_critical",
        "embedded",
        "bundle_path",
        "locator",
        "anonymous_access",
        "retrieval_procedure",
        "retention",
        "declared_level",
        "assessed_level",
    }
    item = _record(entry, required, f"evidence_inventory[{entry.get('artifact_id', '?')}]")
    artifact_id = item["artifact_id"]
    if not isinstance(artifact_id, str) or artifact_id not in EVIDENCE_POLICY:
        raise PacketError(f"unexpected evidence artifact ID: {artifact_id!r}")
    if not isinstance(item["role"], str) or not item["role"].strip():
        raise PacketError(f"{artifact_id} has no role")
    if type(item["verdict_critical"]) is not bool:
        raise PacketError(f"{artifact_id}.verdict_critical must be a boolean")
    if type(item["embedded"]) is not bool:
        raise PacketError(f"{artifact_id}.embedded must be a boolean")
    if type(item["anonymous_access"]) is not bool:
        raise PacketError(f"{artifact_id}.anonymous_access must be a boolean")
    policy = EVIDENCE_POLICY[artifact_id]
    observed_policy = (
        item["verdict_critical"],
        item["disclosure"],
        item["assessed_level"],
    )
    if observed_policy != policy:
        raise PacketError(
            f"{artifact_id} evidence policy is {observed_policy}, expected {policy}"
        )
    address = str(item["content_address"])
    if not SHA256.fullmatch(address):
        raise PacketError(f"{item['artifact_id']} has an invalid content address")

    retention_value = item["retention"]
    retention = None
    if retention_value is not None:
        retention_record = _record(
            retention_value,
            {"horizon", "custodian", "replicas"},
            f"{item['artifact_id']}.retention",
        )
        retention = RetentionPolicy(
            str(retention_record["horizon"]),
            str(retention_record["custodian"]),
            retention_record["replicas"],
        )
        if (
            not retention.horizon
            or not retention.custodian.strip()
            or type(retention.replicas) is not int
            or retention.replicas != 1
        ):
            raise PacketError(f"{artifact_id}.retention is malformed")

    embedded_bytes = None
    if item["embedded"]:
        if item["artifact_id"] == "participant-visible-result":
            embedded_bytes = canonical_bytes(reported_result)
            if f"sha256:{canonical_digest(reported_result)}" != address:
                raise PacketError("embedded participant result does not match its content address")
        else:
            bundle_path = str(item["bundle_path"])
            local = (ROOT / bundle_path).resolve()
            try:
                local.relative_to(ROOT)
            except ValueError as exc:
                raise PacketError(f"{item['artifact_id']} bundle path escapes the example") from exc
            if not local.is_file():
                raise PacketError(f"{item['artifact_id']} bundle path does not exist")
            embedded_bytes = local.read_bytes()
            if f"sha256:{hashlib.sha256(embedded_bytes).hexdigest()}" != address:
                raise PacketError(f"{item['artifact_id']} bundled bytes do not match their content address")
    elif item["bundle_path"]:
        raise PacketError(f"{item['artifact_id']} names a bundle path but is not embedded")

    try:
        declared = AvailabilityLevel(str(item["declared_level"]))
    except ValueError as exc:
        raise PacketError(f"{item['artifact_id']} has an invalid declared level") from exc

    artifact = ArtifactAvailability(
        artifact_id=artifact_id,
        content_address=address,
        verdict_critical=bool(item["verdict_critical"]),
        embedded_bytes=embedded_bytes,
        locator=str(item["locator"]),
        anonymous_access=bool(item["anonymous_access"]),
        retrieval_procedure=str(item["retrieval_procedure"]),
        retention=retention,
        declared_level=declared,
    )
    if artifact.assess().value != item["assessed_level"]:
        raise PacketError(
            f"{item['artifact_id']} assessed level is {artifact.assess().value}, "
            f"not {item['assessed_level']}"
        )
    if item["disclosure"] == "access-controlled" and artifact.assess() in {
        AvailabilityLevel.PORTABLE,
        AvailabilityLevel.SELF_CONTAINED,
    }:
        raise PacketError(f"{item['artifact_id']} overstates access-controlled evidence")
    return artifact


def verify_packet(document: dict[str, Any]) -> dict[str, Any]:
    required = {
        "packet_format",
        "packet_id",
        "profile",
        "source",
        "claim",
        "execution",
        "reported_result",
        "evidence_inventory",
        "availability_summary",
        "disclosure_interface",
        "refutation_surface",
        "trust",
        "limits",
        "correction",
        "packet_digest",
    }
    _record(document, required, "packet")
    if document["packet_format"] != "VSTD-CLOSED-EVALUATION-PROFILE-0.2":
        raise PacketError("unexpected packet format")
    if document["packet_id"] != "VSTD-SB-SYNTH-002":
        raise PacketError("unexpected packet ID")
    _verify_document_digest(document, "packet_digest")

    correction = _record(
        document["correction"],
        {
            "supersedes_packet_id",
            "supersedes_packet_digest",
            "historical_commit",
            "reason",
        },
        "correction",
    )
    if correction["supersedes_packet_id"] != "VSTD-SB-SYNTH-001":
        raise PacketError("correction does not name the superseded packet")
    if correction["supersedes_packet_digest"] != (
        "sha256:f182bfce5a5ae8e7137795300d42e285f365e6707b7c3517b3cee7b02331963b"
    ):
        raise PacketError("correction does not bind the superseded packet digest")
    if correction["historical_commit"] != (
        "a37e6128fc6eccb66160a2f7c3af2f43341c227e"
    ):
        raise PacketError("correction does not bind the historical public commit")
    if not str(correction["reason"]).strip():
        raise PacketError("correction reason is empty")

    profile = _record(document["profile"], {"name", "version", "normative"}, "profile")
    if profile != {
        "name": "SimulacraBench synthetic closed-evaluation crosswalk",
        "version": "0.2",
        "normative": False,
    }:
        raise PacketError("the target-specific profile must remain non-normative")

    source = _record(document["source"], {"repository", "commit", "artifacts"}, "source")
    commit = str(source["commit"])
    if not COMMIT.fullmatch(commit):
        raise PacketError("source commit must be a full Git commit")
    if source["repository"] != UPSTREAM_REPOSITORY or commit != PINNED_COMMIT:
        raise PacketError("source is not the pinned official repository commit")
    if not isinstance(source["artifacts"], list):
        raise PacketError("source.artifacts must be a list")
    observed_paths = [str(item.get("path", "")) for item in source["artifacts"] if isinstance(item, Mapping)]
    if observed_paths != list(SOURCE_PATHS):
        raise PacketError("source artifact paths or ordering differ from the pinned snapshot")
    for artifact in source["artifacts"]:
        record = _record(
            artifact,
            {"path", "url", "sha256", "bytes", "bundle_path"},
            "source.artifact",
        )
        expected_prefix = f"https://github.com/SituatedEvals/public/blob/{commit}/"
        if str(record["url"]) != expected_prefix + str(record["path"]):
            raise PacketError(f"source URL is not pinned to {commit}: {record['url']}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"])):
            raise PacketError(f"source artifact {record['path']} has an invalid digest")
        if type(record["bytes"]) is not int or record["bytes"] < 1:
            raise PacketError(f"source artifact {record['path']} has an invalid size")
        expected_bundle_path = f"source_snapshot/{record['path']}"
        if record["bundle_path"] != expected_bundle_path:
            raise PacketError(f"source artifact {record['path']} has the wrong bundle path")
        local = (ROOT / expected_bundle_path).resolve()
        try:
            local.relative_to(ROOT)
        except ValueError as exc:
            raise PacketError(f"source artifact {record['path']} escapes the example") from exc
        if not local.is_file() or local.stat().st_size != record["bytes"]:
            raise PacketError(f"source artifact {record['path']} size does not match its snapshot")
        if hashlib.sha256(local.read_bytes()).hexdigest() != record["sha256"]:
            raise PacketError(f"source artifact {record['path']} digest does not match its snapshot")

    claim = _record(
        document["claim"],
        {"claim_id", "statement", "coordinate", "status", "does_not_establish"},
        "claim",
    )
    if claim["status"] != "RECORDED_UNDER_DECLARED_SYNTHETIC_EVALUATOR":
        raise PacketError("claim status exceeds the synthetic evaluator boundary")
    if claim["claim_id"] != "VSTD-SB-SYNTH-002-RESULT":
        raise PacketError("unexpected claim ID")
    if not claim["does_not_establish"]:
        raise PacketError("claim must state explicit exclusions")
    surface = _surface(document["refutation_surface"])
    surface_check = surface.validate()
    if not surface_check.accepted:
        raise PacketError(surface_check.details)
    if surface.coordinate.to_dict() != claim["coordinate"]:
        raise PacketError("refutation surface is not bound to the claim coordinate")

    execution = _record(
        document["execution"],
        {
            "mode",
            "official_policy",
            "observed_local_controls",
            "unobserved_hosted_controls",
            "prior_commitment",
        },
        "execution",
    )
    if execution["mode"] != "LOCAL_SYNTHETIC_REHEARSAL":
        raise PacketError("the specimen must not present itself as a hosted competition run")
    prior_commitment = _record(
        execution["prior_commitment"],
        {"fixture_frozen_before_execution", "externally_timestamped", "limitation"},
        "execution.prior_commitment",
    )
    if prior_commitment["externally_timestamped"] is not False:
        raise PacketError("the local sequence has no external precommitment timestamp")

    reported = _record(
        document["reported_result"],
        {"status", "reported_skill", "printed_result", "phase", "privacy_policy"},
        "reported_result",
    )
    if (
        reported["status"] != "PASS"
        or reported["reported_skill"] != 0.33
        or reported["printed_result"] != "PASS  0.3300  (35.7s)"
        or reported["phase"] != 1
    ):
        raise PacketError("reported result is malformed")

    inventory = document["evidence_inventory"]
    if not isinstance(inventory, list) or not inventory:
        raise PacketError("evidence_inventory must be non-empty")
    artifacts = tuple(_availability_item(entry, reported) for entry in inventory)
    ids = [item.artifact_id for item in artifacts]
    if len(ids) != len(set(ids)):
        raise PacketError("evidence_inventory repeats an artifact ID")
    if set(ids) != set(EVIDENCE_POLICY):
        raise PacketError("evidence_inventory is not the closed expected artifact set")
    assessment = assess_bundle(artifacts, required=AvailabilityLevel.AVAILABLE)
    summary = _record(
        document["availability_summary"],
        {"required", "derived_floor", "accepted", "limiting_artifacts", "public_reproduction"},
        "availability_summary",
    )
    expected_summary = {
        "required": AvailabilityLevel.AVAILABLE.value,
        "derived_floor": assessment.level.value,
        "accepted": assessment.accepted,
        "limiting_artifacts": list(assessment.limiting_artifacts),
        "public_reproduction": "UNAVAILABLE",
    }
    if dict(summary) != expected_summary:
        raise PacketError(f"availability summary mismatch: expected {expected_summary}")

    disclosure = _record(
        document["disclosure_interface"],
        {"committed", "checker_receives", "predicate_checked", "checker_returns", "does_not_follow"},
        "disclosure_interface",
    )
    if not disclosure["checker_receives"] or not disclosure["does_not_follow"]:
        raise PacketError("disclosure interface is incomplete")

    trust = _record(
        document["trust"],
        {"evaluator", "independent", "vstd5_witness", "organizer_affiliation"},
        "trust",
    )
    if trust["independent"] is not False or trust["vstd5_witness"] is not False:
        raise PacketError("founder-operated synthetic evaluation is not independent")
    if trust["organizer_affiliation"] != "NONE":
        raise PacketError("the specimen must not imply organizer affiliation")

    limits = _record(
        document["limits"],
        {"vstd4_depth_claim", "reason", "retention_declaration_horizon"},
        "limits",
    )
    if limits["vstd4_depth_claim"] is not None:
        raise PacketError("component checks do not establish an aggregate VSTD-4 depth")
    if limits["retention_declaration_horizon"] != RETENTION_HORIZON:
        raise PacketError(
            "retention_declaration_horizon must equal the private-artifact declaration"
        )
    for artifact in artifacts:
        if (
            artifact.retention is not None
            and artifact.retention.horizon != limits["retention_declaration_horizon"]
        ):
            raise PacketError(
                f"{artifact.artifact_id} retention does not match the packet declaration"
            )

    return {
        "packet_id": document["packet_id"],
        "packet_digest": document["packet_digest"],
        "availability_floor": assessment.level.value,
        "public_reproduction": summary["public_reproduction"],
        "claim_status": claim["status"],
    }


def _surface(value: Mapping[str, Any]) -> RefutationSurface:
    value = _record(
        value,
        {"coordinate", "admissible_refutations", "excluded_claims"},
        "refutation_surface",
    )
    coordinate_record = _record(value["coordinate"], {"subject", "predicate", "parameters"}, "coordinate")
    if not isinstance(coordinate_record["parameters"], Mapping):
        raise PacketError("coordinate.parameters must be an object")
    if not isinstance(value["admissible_refutations"], list):
        raise PacketError("admissible_refutations must be a list")
    coordinate = ClaimCoordinate(
        str(coordinate_record["subject"]),
        str(coordinate_record["predicate"]),
        {str(k): str(v) for k, v in coordinate_record["parameters"].items()},
    )
    admissible = []
    for raw in value["admissible_refutations"]:
        item = _record(
            raw,
            {"refutation_type", "applies_to", "overturning_evidence", "resulting_status"},
            "admissible_refutation",
        )
        admissible.append(
            AdmissibleRefutation(
                RefutationType(str(item["refutation_type"])),
                tuple(str(entry) for entry in item["applies_to"]),
                str(item["overturning_evidence"]),
                str(item["resulting_status"]),
            )
        )
    if not isinstance(value["excluded_claims"], list):
        raise PacketError("excluded_claims must be a list")
    excluded = tuple(
        ExcludedClaim(
            str(_record(item, {"claim_id", "reason"}, "excluded_claim")["claim_id"]),
            str(_record(item, {"claim_id", "reason"}, "excluded_claim")["reason"]),
        )
        for item in value["excluded_claims"]
    )
    return RefutationSurface(coordinate, tuple(admissible), excluded)


def verify_challenge(packet: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    required = {
        "challenge_format",
        "challenge_id",
        "target_packet_digest",
        "deliberate_mutation",
        "refutation_surface",
        "filing",
        "transitions",
        "localized_effect",
        "leak_check",
        "trust",
        "challenge_digest",
    }
    _record(document, required, "challenge_demo")
    if document["challenge_format"] != "VSTD-CLOSED-EVALUATION-CHALLENGE-0.2":
        raise PacketError("unexpected challenge format")
    if document["challenge_id"] != "VSTD-SB-SYNTH-002-CHALLENGE-001":
        raise PacketError("unexpected challenge ID")
    _verify_document_digest(document, "challenge_digest")
    if document["target_packet_digest"] != packet["packet_digest"]:
        raise PacketError("challenge is not bound to the public packet")

    mutation = _record(
        document["deliberate_mutation"],
        {"field", "original", "mutated", "purpose"},
        "deliberate_mutation",
    )
    if mutation["field"] != "reported_result.reported_skill":
        raise PacketError("challenge must localize to the aggregate result")
    if mutation["original"] != packet["reported_result"]["reported_skill"]:
        raise PacketError("challenge original does not match the packet")
    if mutation["mutated"] != 0.34:
        raise PacketError("challenge mutation must be the declared 0.34 mutant")

    surface = _surface(document["refutation_surface"])
    surface_check = surface.validate()
    if not surface_check.accepted:
        raise PacketError(surface_check.details)
    if surface.to_dict() != packet["refutation_surface"]:
        raise PacketError("challenge refutation surface differs from the target packet")

    filing = _record(
        document["filing"],
        {
            "target_claim_id",
            "target_certificate_id",
            "challenged_predicate",
            "challenge_type",
            "counterevidence",
            "filed_at",
            "challenge_certificate",
        },
        "filing",
    )
    challenge = Challenge(
        str(document["challenge_id"]),
        str(filing["target_claim_id"]),
        str(filing["target_certificate_id"]),
        str(filing["challenged_predicate"]),
        RefutationType(str(filing["challenge_type"])),
        str(filing["counterevidence"]),
        str(filing["filed_at"]),
        str(filing["challenge_certificate"]),
    )
    if challenge.target_claim_id != "VSTD-SB-SYNTH-002-RESULT-MUTANT":
        raise PacketError("challenge does not target the declared mutant claim")
    if challenge.target_certificate_id != packet["packet_id"]:
        raise PacketError("challenge target certificate differs from the packet")
    if challenge.challenged_predicate != packet["claim"]["coordinate"]["predicate"]:
        raise PacketError("challenge predicate differs from the packet coordinate")
    ledger = ChallengeLedger()
    admission = ledger.file(challenge, surface)
    if not admission.admitted:
        raise PacketError(admission.details)
    public_status = ledger.status(challenge.target_claim_id)

    transitions = _record(
        document["transitions"],
        {"after_public_filing"},
        "transitions",
    )
    if transitions["after_public_filing"] != public_status.status.value:
        raise PacketError("public filing transition mismatch")
    if public_status.status is not ArtifactStatus.CHALLENGED:
        raise PacketError("public filing must leave the aggregate claim CHALLENGED")

    leak = _record(
        document["leak_check"],
        {"individual_records", "hidden_item_ids", "hidden_item_text", "labels", "raw_predictions", "raw_traceback"},
        "leak_check",
    )
    if any(value not in (0, False) for value in leak.values()):
        raise PacketError("challenge demo leaks a prohibited hidden-data field")
    trust = _record(
        document["trust"],
        {"independent", "vstd5_witness", "adjudicated"},
        "challenge.trust",
    )
    if (
        trust["independent"] is not False
        or trust["vstd5_witness"] is not False
        or trust["adjudicated"] is not False
    ):
        raise PacketError("public filing is neither independent nor adjudicated")
    localized = _record(
        document["localized_effect"],
        {"challenged", "unchanged"},
        "localized_effect",
    )
    if localized["challenged"] != ["mutated aggregate-result claim"]:
        raise PacketError("challenge filing is not localized to the mutated aggregate")
    if not localized["unchanged"]:
        raise PacketError("challenge demo must name the evidence left unchanged")

    return {
        "challenge_id": document["challenge_id"],
        "challenge_digest": document["challenge_digest"],
        "after_public_filing": public_status.status.value,
        "adjudicated": trust["adjudicated"],
        "records_disclosed": leak["individual_records"],
    }


def verify_all(packet_path: Path = DEFAULT_PACKET, challenge_path: Path = DEFAULT_CHALLENGE) -> dict[str, Any]:
    packet = _load(packet_path)
    challenge = _load(challenge_path)
    return {
        "packet": verify_packet(packet),
        "challenge": verify_challenge(packet, challenge),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--challenge", type=Path, default=DEFAULT_CHALLENGE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_all(args.packet, args.challenge)
    except PacketError as exc:
        print(f"[FAIL] {exc}")
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "[PASS] synthetic closed-evaluation packet: "
            f"availability={result['packet']['availability_floor']}, "
            f"public_reproduction={result['packet']['public_reproduction']}"
        )
        print(
            "[PASS] non-disclosing challenge: "
            f"status={result['challenge']['after_public_filing']}, "
            f"adjudicated={result['challenge']['adjudicated']}, "
            f"records_disclosed={result['challenge']['records_disclosed']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

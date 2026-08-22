from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import jsonschema
import pytest

from verifier.hardware.models import VSTD3Receipt
from verifier.hardware.registry import load_builtin_registry
from verifier.hardware.schema import accelerator_profile_schema, receipt_schema


ROOT = Path(__file__).resolve().parents[1]


def _empty_receipt() -> VSTD3Receipt:
    receipt = VSTD3Receipt(
        schema_version="VSTD-3.0",
        receipt_id="schema-fixture",
        created_at="2026-08-21T18:00:00Z",
        descriptors=(),
        physical_identities=(),
        logical_identities=(),
        partitions=(),
        topology_snapshots=(),
        capability_declarations=(),
        evidence_sources=(),
        attestation_challenges=(),
        attestation_evidence=(),
        executions=(),
        execution_starts=(),
        execution_observations=(),
        execution_ends=(),
        accounting_observations=(),
        continuity_records=(),
        provider_evidence=(),
        fleet_manifests=(),
        fleet_observations=(),
        evidence_gaps=(),
        claim_evaluations=(),
        provenance_artifact_ids=(),
    )
    receipt.compute_and_set_digest()
    return receipt


@pytest.mark.parametrize(
    ("filename", "generated"),
    [
        ("vstd3_receipt.json", receipt_schema),
        ("vstd3_accelerator_profile.json", accelerator_profile_schema),
    ],
)
def test_checked_in_schemas_are_deterministically_generated(
    filename: str, generated: Callable[[], dict[str, object]]
) -> None:
    schema = generated()
    jsonschema.Draft202012Validator.check_schema(schema)
    checked_in = json.loads((ROOT / "receipts" / "schema" / filename).read_text(encoding="utf-8"))
    assert checked_in == schema


def test_receipt_schema_accepts_canonical_receipt_and_rejects_unknown_fields() -> None:
    schema = receipt_schema()
    payload = _empty_receipt().to_dict()
    jsonschema.validate(payload, schema)

    payload["unknown_signed_field"] = "forbidden"
    with pytest.raises(jsonschema.ValidationError, match="Additional properties"):
        jsonschema.validate(payload, schema)


def test_profile_schema_accepts_registry_profile_and_forbids_floats() -> None:
    schema = accelerator_profile_schema()
    payload = load_builtin_registry().get("generic.ai-asic").to_dict()
    jsonschema.validate(payload, schema)
    payload["notes"] = [1.5]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)

"""Build a deterministic experimental Verifier Standard (VSTD) publisher silo.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256). The checked-in transfer uses a public specimen identity and never a
real publisher key. Materialization validates its signature, exact byte closure,
assessment receipt, authority model, and canonical encoding before writing.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from verifier.interoperability.network import (
    MAX_RECORD_BYTES,
    ContentAddressedStore,
    NetworkError,
    SiloCommit,
    assess_silo,
    canonical_bytes,
    digest_bytes,
    materialize_silo_transfer,
)


FIXTURE = Path(__file__).with_name("canonical-wire-fixture.json")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NetworkError(f"duplicate JSON key in specimen fixture: {key}")
        result[key] = value
    return result


def _load_fixture() -> Mapping[str, Any]:
    try:
        with FIXTURE.open("rb") as stream:
            document = stream.read(MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise NetworkError("cannot read the artifact-network specimen fixture") from exc
    if len(document) > MAX_RECORD_BYTES:
        raise NetworkError("artifact-network specimen fixture exceeds its byte bound")
    try:
        value = json.loads(
            document,
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                NetworkError(f"non-finite JSON number in specimen fixture: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NetworkError("artifact-network specimen fixture is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise NetworkError("artifact-network specimen fixture must be one JSON object")
    return value


def build_specimen(destination: Path) -> dict[str, Any]:
    """Materialize and independently reassess the checked-in signed specimen."""

    fixture = _load_fixture()
    try:
        transfer = fixture["records"]["silo_transfer"]
        expected_digest = fixture["expected"]["silo_transfer_digest"]
    except (KeyError, TypeError) as exc:
        raise NetworkError("artifact-network specimen fixture lacks its transfer") from exc
    encoded = canonical_bytes(transfer)
    if digest_bytes(encoded) != expected_digest:
        raise NetworkError("artifact-network specimen transfer digest does not match")
    manifest = materialize_silo_transfer(encoded, destination)
    commit_path = (
        destination
        / "records"
        / "commits"
        / (manifest["commit_digest"].split(":", 1)[1] + ".json")
    )
    commit = SiloCommit.from_dict(json.loads(commit_path.read_bytes()))
    assessment = assess_silo(commit, ContentAddressedStore(destination))
    return {
        "result": "SPECIMEN_BUILT",
        "transfer_digest": expected_digest,
        "publisher_digest": manifest["publisher_digest"],
        "commit_digest": manifest["commit_digest"],
        "head_digest": manifest["head_digest"],
        "assessment_receipt_digest": manifest["assessment_receipt_digest"],
        "commit_path": commit_path.relative_to(destination).as_posix(),
        "head_path": (
            "records/heads/"
            + manifest["head_digest"].split(":", 1)[1]
            + ".json"
        ),
        "assessment": assessment.to_dict(),
        "claim_boundary": (
            "This deterministic public specimen establishes only successful local "
            "materialization and reassessment of its exact checked-in signed transfer. "
            "It does not establish publisher identity, artifact truth, deployment, "
            "independent operation, or completeness beyond SILO_CENSUS."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    try:
        report = build_specimen(arguments.destination)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Artifact-network specimen refused: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""A real retained-dataset workflow for Verifier Standard (VSTD).

DATA means dataset integrity and lineage; JavaScript Object Notation (JSON).
The external contract selects the required record fields. This example checks
the current retained records, not their external origin or usefulness.
"""
from __future__ import annotations

import json
from pathlib import Path

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
from verifier.domains.common import Budget, digest, merkle_root


def read_document(path: Path) -> object:
    """Read one bounded, duplicate-key-rejecting input document."""
    with path.open("rb") as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("example input exceeds one mebibyte")
    return strict_json_loads(raw.decode("utf-8"))


def main() -> int:
    """Recompute a DATA certificate and replay it under the selected local policy."""
    directory = Path(__file__).resolve().parent
    try:
        rows = read_document(directory / "dataset.json")
        contract = read_document(directory / "contract.json")
        if type(rows) is not list or type(contract) is not dict or set(contract) != {"subject_id", "fields"}:
            raise ValueError("record array and exact subject/fields contract required")
        commitment = {"digest": digest(rows), "records": len(rows), "bytes": len(canonical_bytes(rows)),
                      "record_digests": [digest(row) for row in rows], "merkle_root": merkle_root(rows, Budget(10000))}
        evidence = {"schema_version": "verifier-domain-evidence-1", "domain": "DATA",
                    "subject_id": contract["subject_id"], "artifact": {"shards": {"retained": commitment}, "fields": contract["fields"]},
                    "inputs": {"shards": {"retained": rows}}}
        request = domain_request(evidence, target_depth=2)
        # This example explicitly admits the installed local checker. Real consumers
        # select and pin their own policy independently of a received certificate.
        policy = domain_policy(trust_roots=["example:selected-local-checker", "example:retained-dataset"])
        certificate = build_domain_certificate(request, evidence, policy=policy)
        result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        result = {"status": "REJECTED", "reason": str(error)}
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2, "REJECTED": 1}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())

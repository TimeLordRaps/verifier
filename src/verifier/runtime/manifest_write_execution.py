"""Source-bound manifest publication checks for Verifier Standard (VSTD).

These finite checks exercise the installed command handlers in private files.
They do not prove power-loss durability, protection from arbitrary writers, path
confinement, application authority or complete TRANSACTION-kind conformance.
"""
from __future__ import annotations

from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-manifest-publication-1"
SEMANTIC_VERSION = "verifier-manifest-publication-obligations-1"
IMPLEMENTATION = "src/verifier/runtime/namespace_cli.py"
WORKER = "manifest_write_worker.py"
REQUEST_SCHEMA = "verifier-manifest-publication-request-1"
OBSERVATION_SCHEMA = "verifier-manifest-publication-observations-1"
BOUNDARY = ("Fresh finite executions of exact installed manifest handlers in private temporary files. "
            "Not power-loss durability, protection from arbitrary concurrent writers, path confinement, application authority or complete kind/package conformance.")
_CONTRACTS = (
    ("TRANSACTION-1.3", "manifest-input-preconditions", 1,
     "Invalid input must not change an existing manifest; preview must not silently publish it.",
     "Duplicate keys, nonportable numbers and non-object input are refused unchanged; formatting preview returns canonical bytes without writing."),
    ("TRANSACTION-1.4", "manifest-effect-scope", 1,
     "Publication must preserve the declared evidence and distinguish writing a draft from verifying its claims.",
     "Template preview creates no manifest; publication writes that exact draft and preserves its source file; formatting preserves deliberately unverified evidence fields."),
    ("TRANSACTION-2.3", "manifest-publication-boundary", 2,
     "A replacement failure can precede or follow publication, and a detected concurrent edit must not be overwritten.",
     "Injected errors before/after replacement preserve old/new bytes respectively; a detected precheck race is refused; all three paths remove their unpublished temporary file without retry."),
    ("TRANSACTION-2.4", "manifest-partial-create", 2,
     "Exclusive creation is not complete-file atomicity; a partial write must not be mislabeled success or silently retried over retained bytes.",
     "Injected template write failure leaves the observed partial new file and raises an error; a subsequent attempt refuses to overwrite it."),
    ("TRANSACTION-3.3", "manifest-retry-behavior", 3,
     "Repeated publication must have explicit content and overwrite semantics rather than inferred idempotence.",
     "A duplicate template attempt preserves existing bytes; two formatting writes preserve the same canonical content and unrelated files; every explicit template or format operation performs exactly one publication attempt with no hidden retry."),
    ("TRANSACTION-3.4", "manifest-concurrent-create", 3,
     "Separate successful discovery cannot authorize two writers to publish the same previously absent manifest.",
     "Two synchronized template attempts complete discovery before publication; each performs exactly one exclusive-create attempt, exactly one creates the exact draft and the other refuses without overwriting it."),
)


def catalog() -> list[dict[str, Any]]:
    return [{"coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
        "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": "TRANSACTION", "tier": tier,
        "reason": reason, "exact_claim": claim, "semantic_version": SEMANTIC_VERSION,
        "proposition_digest": value_digest({"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
        "checking_mechanism": "verifier.runtime.manifest_write_execution.evaluate",
        "scope": "fresh_manifest_publication_" + slug.replace("-", "_"), "adapter": ADAPTER}
        for coordinate, slug, tier, reason, claim in _CONTRACTS]


def _number(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _exit(value: dict[str, Any], expected: int) -> bool:
    return _number(value["exit"], expected) and value["exception"] is None


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Use exact independent content expectations, not a handler's success text."""
    original = '{ "policy": {"epoch":1}, "labels":["OBJECT","LEDGER"], "evidence":"unverified" }'
    expected = '{"evidence":"unverified","labels":["OBJECT","LEDGER"],"policy":{"epoch":1}}\n'
    if coordinate == "TRANSACTION-1.3":
        row = observed["format"]
        invalid = observed["invalid"]
        cases = ('{"label":"OBJECT","label":"LEDGER"}', '{"amount":0.1}', '[]')
        exceptions = ("TierZeroManifestError", "ValueError", "TierZeroManifestError")
        return (_exit(row["preview"], 0) and row["preview"]["stdout"] == expected
                and row["before"] == row["after_preview"] == original
                and len(invalid) == 3 and all(item["outcome"]["exception"] == error and item["outcome"]["exit"] is None
                    and item["before"] == item["after"] == malformed and item["temporary_files"] == []
                    for item, malformed, error in zip(invalid, cases, exceptions)))
    if coordinate == "TRANSACTION-1.4":
        row, formatted = observed["template"], observed["format"]
        draft = row["draft"]
        return (_exit(row["preview"], 0) and _exit(row["first"], 0) and row["before_exists"] is False
                and row["after_preview_exists"] is False and draft["status"] == "DRAFT"
                and draft["manifest"]["schema_version"] == "verifier-objects-manifest-2"
                and row["published"] == (canonical_bytes(draft["manifest"]) + b"\n").decode()
                and len(draft["manifest"]["objects"]) == 1 and draft["manifest"]["objects"][0]["object_id"] == "subject.py"
                and row["source_after"] == row["source_before"] == 'raise RuntimeError("subject must not execute")\ndef calculate(): pass\n'
                and _exit(formatted["first"], 0) and formatted["after_first"] == expected
                and formatted["sentinel"] == "unrelated")
    if coordinate == "TRANSACTION-2.3":
        cases = observed["publication"]
        return (set(cases) == {"before", "after", "race"}
                and all(row["before"] == original and row["temporary_files"] == [] and row["sentinel"] == "unrelated" for row in cases.values())
                and all(cases[name]["outcome"]["exception"] == "OSError" and cases[name]["outcome"]["exit"] is None
                    and _number(cases[name]["replace_calls"], 1) for name in ("before", "after"))
                and cases["before"]["after"] == original and cases["after"]["after"] == expected
                and cases["race"]["outcome"]["exception"] == "ValueError" and cases["race"]["outcome"]["exit"] is None
                and _number(cases["race"]["replace_calls"], 0)
                and cases["race"]["after"] == '{"concurrent":"preserve"}\n')
    if coordinate == "TRANSACTION-2.4":
        row = observed["partial"]
        expected_prefix = (canonical_bytes(row["draft"]["manifest"]) + b"\n")[:8].decode()
        return (row["before_exists"] is False and row["outcome"]["exception"] == "OSError" and row["outcome"]["exit"] is None
                and _number(row["writes"], 1) and row["partial"] == expected_prefix
                and _exit(row["retry"], 1) and row["after_retry"] == expected_prefix
                and row["source_after"] == row["source_before"])
    if coordinate == "TRANSACTION-3.3":
        row, formatted = observed["template"], observed["format"]
        return (_exit(row["first"], 0) and _exit(row["retry"], 1) and row["after_retry"] == row["published"]
                and _number(row["attempt_limit"], 1)
                and row["publication_attempts"] == {"first": 1, "retry": 1}
                and _exit(formatted["first"], 0) and _exit(formatted["second"], 0)
                and _number(formatted["attempt_limit"], 1)
                and formatted["publication_attempts"] == {"first": 1, "second": 1}
                and formatted["after_first"] == formatted["after_second"] == expected
                and formatted["temporary_files"] == [] and formatted["sentinel"] == "unrelated")
    if coordinate == "TRANSACTION-3.4":
        row = observed["concurrent"]
        return (row["before_exists"] is False and _number(row["discoveries"], 2) and len(row["outcomes"]) == 2
                and _number(row["attempt_limit"], 1) and row["publication_attempts"] == [1, 1]
                and sum(_exit(item, 0) for item in row["outcomes"]) == sum(_exit(item, 1) for item in row["outcomes"]) == 1
                and row["published"] == (canonical_bytes(row["draft"]["manifest"]) + b"\n").decode()
                and row["source_after"] == row["source_before"])
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    from verifier.runtime.package_execution import execute_bound
    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    from verifier.runtime.package_execution import evaluate_selected
    return evaluate_selected(snapshot, item, route)

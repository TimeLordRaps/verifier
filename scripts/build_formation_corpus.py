"""Build bounded native Verifier Standard (VSTD) formation replay specimens.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256), and
uniform resource locator (URL)-safe base64 retain synthetic exact byte inputs.
An integer identifier (ID) selects a node; the ID tag builds an identity path.
Native expected reports are reference outputs, not independent correctness,
source interpretation, execution provenance, completeness, or agency evidence.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Sequence

from verifier.interoperability.formation_checker import check_formation
from verifier.interoperability.formation_storage import inspect_silo_formation
from verifier.interoperability.formation_wire import (
    CERTIFICATE_SCHEMA, SUBJECT_SCHEMA, profile_bytes, profile_digest,
)
from verifier.interoperability.network import (
    AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION, CensusEntry,
    ObjectRecord, SelfDerivationRecord, SiloCommit, authority_axiom_agency_digest,
    canonical_bytes, digest_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/fixtures/formation-interoperability-corpus.json"
MAX_CORPUS_BYTES = 1024 * 1024
SCHEMA_VERSION = "VSTD-FORMATION-INTEROPERABILITY-CORPUS-0.1"
OPAQUE = digest_bytes(b"unretrieved synthetic atom")
PATHS = {"subject_path": "subject.json", "certificate_path": "certificate.json",
         "profile_path": "profile.json", "ground_path": "ground.txt"}
REF_FIELDS = {"ATOM": (), "APPLY": ("argument",), "ID": ("at",),
              "APPLY_STEP": ("source", "target"), "COMPOSE": ("left", "right"),
              "QUOTE": ("value",), "READ": ("code",)}


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _subject(nodes: list[dict[str, Any]], root: int | None = None) -> dict[str, Any]:
    return {"schema_version": SUBJECT_SCHEMA, "profile_digest": profile_digest(),
            "context": {"ground_artifact_digest": digest_bytes(b"synthetic ground"),
                        "authority_axiom_agency_digest": authority_axiom_agency_digest()},
            "nodes": nodes, "root": len(nodes) - 1 if root is None else root}


def _certificate(subject: dict[str, Any]) -> dict[str, Any]:
    # Construct proof-step syntax directly; invalid subjects remain test inputs.
    return {"schema_version": CERTIFICATE_SCHEMA, "subject_digest": digest_bytes(canonical_bytes(subject)),
            "profile_digest": subject["profile_digest"], "root": subject["root"],
            "steps": [{"node": index, "rule": node["tag"],
                       "premises": [node[field] for field in REF_FIELDS.get(node["tag"], ())]}
                      for index, node in enumerate(subject["nodes"])]}


def _pure_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    def add(name: str, subject: dict[str, Any] | bytes,
            certificate: dict[str, Any] | bytes | None = None) -> None:
        if certificate is None:
            assert isinstance(subject, dict)
            certificate = _certificate(subject)
        subject_bytes = subject if type(subject) is bytes else canonical_bytes(subject)
        certificate_bytes = certificate if type(certificate) is bytes else canonical_bytes(certificate)
        report = check_formation(subject_bytes, certificate_bytes)
        cases.append({"case_id": name, "subject_bytes_base64url": encode(subject_bytes),
                      "certificate_bytes_base64url": encode(certificate_bytes),
                      "expected_report": report, "expected_report_digest": digest_bytes(canonical_bytes(report))})

    atom = {"tag": "ATOM", "payload_digest": OPAQUE}
    step = [atom, {"tag": "APPLY", "argument": 0},
            {"tag": "APPLY_STEP", "source": 0, "target": 1}]
    two_steps = step + [{"tag": "APPLY", "argument": 1},
                        {"tag": "APPLY_STEP", "source": 1, "target": 3},
                        {"tag": "COMPOSE", "left": 2, "right": 4}]
    add("atom", _subject([atom]))
    add("application", _subject(step[:2]))
    add("identity", _subject([atom, {"tag": "ID", "at": 0}]))
    add("application-step", _subject(step))
    add("composition", _subject(two_steps))
    add("identity-composition", _subject(step + [{"tag": "ID", "at": 0},
                                                 {"tag": "COMPOSE", "left": 3, "right": 2}]))
    quote_path = two_steps + [{"tag": "QUOTE", "value": 5}]
    add("quoted-path", _subject(quote_path))
    add("read-path", _subject(quote_path + [{"tag": "READ", "code": 6}]))
    nested = [atom, {"tag": "QUOTE", "value": 0}, {"tag": "READ", "code": 1},
              {"tag": "QUOTE", "value": 1}, {"tag": "READ", "code": 3},
              {"tag": "READ", "code": 4}]
    add("nested-quotation", _subject(nested[:4]))
    add("nested-read", _subject(nested))
    add("unrelated-root", _subject([atom, {"tag": "ATOM", "payload_digest": digest_bytes(b"other atom")}]))
    add("wrong-application-target", _subject([atom, {"tag": "ATOM", "payload_digest": OPAQUE}, step[2]]))
    add("wrong-composition-endpoints", _subject(two_steps[:-1] + [{"tag": "COMPOSE", "left": 4, "right": 2}]))
    add("read-form", _subject([atom, {"tag": "READ", "code": 0}]))
    add("apply-code", _subject([atom, {"tag": "QUOTE", "value": 0}, {"tag": "APPLY", "argument": 1}]))
    add("unused-invalid-node", _subject([atom, {"tag": "READ", "code": 0}], 0))
    subject = _subject(two_steps)
    for label, change in (
        ("certificate-premise-order", "premises"), ("certificate-missing-step", "missing"),
        ("certificate-wrong-subject", "subject"), ("certificate-wrong-root", "root"),
        ("certificate-wrong-profile", "profile"),
    ):
        certificate = _certificate(subject)
        if change == "premises":
            certificate["steps"][-1]["premises"] = [4, 2]
        elif change == "missing":
            certificate["steps"].pop()
        elif change == "root":
            certificate["root"] = 0
        else:
            certificate[change + "_digest"] = "sha256:" + "0" * 64
        add(label, subject, certificate)
    unknown = deepcopy(subject)
    unknown["profile_digest"] = "sha256:" + "0" * 64
    add("unsupported-profile", unknown)
    add("swapped-native-roles", canonical_bytes(_certificate(subject)), canonical_bytes(subject))
    boolean = _subject(step[:2]); boolean["nodes"][1]["argument"] = False
    add("boolean-reference", boolean)
    add("forward-reference", _subject([{"tag": "APPLY", "argument": 1}, atom]))
    baseline = _subject([atom]); baseline_bytes = canonical_bytes(baseline)
    add("duplicate-key", baseline_bytes[:-1] + b',"root":0}', _certificate(baseline))
    add("noncanonical-whitespace", baseline_bytes + b"\n", _certificate(baseline))
    add("syntax-depth-limit", b"[" * 17 + b"0" + b"]" * 17, _certificate(baseline))
    add("dependency-depth-limit", _subject([atom] + [{"tag": "APPLY", "argument": index - 1} for index in range(1, 65)]))
    add("record-byte-limit", b" " * 262145, _certificate(baseline))
    return cases


def _specimen() -> tuple[SiloCommit, dict[str, bytes]]:
    ground = b"opaque synthetic ground; no source derivation evidence"
    subject = _subject([{"tag": "ATOM", "payload_digest": OPAQUE}])
    subject["context"]["ground_artifact_digest"] = digest_bytes(ground)
    payloads = {
        "ground.txt": (ground, "text/plain", "opaque-ground", "NOT_DECLARED"),
        "subject.json": (canonical_bytes(subject), "application/json", "typed-formation-subject", SUBJECT_SCHEMA),
        "certificate.json": (canonical_bytes(_certificate(subject)), "application/json", "typed-formation-certificate", CERTIFICATE_SCHEMA),
        "profile.json": (profile_bytes(), "application/json", "typed-formation-profile", "VSTD-TYPED-FORMATION-PROFILE-0.1"),
        "unrelated.txt": (b"retained but not a formation premise", "text/plain", "opaque", "NOT_DECLARED"),
    }
    census = tuple(CensusEntry(path, ObjectRecord.from_payload(*values),
                              "NECESSARY" if path == "ground.txt" else "DISPENSABLE")
                   for path, values in payloads.items())
    witness = SelfDerivationRecord(
        "ground.txt", ("ground.txt",), "ground.txt", ("ground.txt",), "DERIVES",
        False, False, False, False, "ground.txt", "ground.txt", "ground.txt", "ground.txt",
        ("source bridge not established",),
    )
    commit = SiloCommit(
        "publisher:sha256:" + "a" * 64, (), census, ("ground.txt",), (), (),
        ("source bridge not established",), (), "DERIVATIONAL_COVERAGE", (),
        AUTHORITY_AXIOM_AGENCY, AUTHORITY_AXIOM_AGENCY_VERSION, authority_axiom_agency_digest(),
        None, witness, "2026-01-01T00:00:00Z",
    )
    return commit, {digest_bytes(values[0]): values[0] for values in payloads.values()}


def _record(commit: SiloCommit, path: str) -> ObjectRecord:
    return next(entry.object_record for entry in commit.census if entry.path == path)


def _replace_record(commit: SiloCommit, path: str, record: ObjectRecord) -> SiloCommit:
    return replace(commit, census=tuple(replace(entry, object_record=record) if entry.path == path else entry for entry in commit.census))


def _substitute(commit: SiloCommit, evidence: dict[str, bytes], path: str, payload: bytes) -> SiloCommit:
    old = _record(commit, path)
    changed = replace(old, object_digest=digest_bytes(payload), size_bytes=len(payload))
    evidence.pop(old.object_digest, None)
    evidence[changed.object_digest] = payload
    return _replace_record(commit, path, changed)


def _rebind(commit: SiloCommit, evidence: dict[str, bytes], subject: dict[str, Any]) -> SiloCommit:
    commit = _substitute(commit, evidence, "subject.json", canonical_bytes(subject))
    return _substitute(commit, evidence, "certificate.json", canonical_bytes(_certificate(subject)))


def _silo_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    names = (
        "silo-valid", "missing-unrelated", "substituted-unrelated", "wrong-size-unrelated",
        "missing-certificate-context-mismatch", "substituted-subject", "wrong-size-subject",
        "wrong-subject-role", "ground-context-mismatch", "agency-context-mismatch",
        "canonical-agency-reduced", "canonical-agency-extended", "agency-digest-inconsistent",
        "unsupported-profile", "same-digest-alias", "profile-as-opaque-ground",
        "swapped-path-selectors", "malformed-certificate-missing-unrelated",
        "profile-coordinate-mismatch-missing-ground", "alias-size-mismatch",
    )
    for name in names:
        commit, evidence = _specimen()
        paths = dict(PATHS)
        subject = json.loads(evidence[_record(commit, "subject.json").object_digest])
        if name == "missing-unrelated":
            evidence.pop(_record(commit, "unrelated.txt").object_digest)
        elif name in {"substituted-unrelated", "substituted-subject"}:
            path = "unrelated.txt" if name.endswith("unrelated") else "subject.json"
            evidence[_record(commit, path).object_digest] = b"wrong bytes under old digest"
        elif name in {"wrong-size-unrelated", "wrong-size-subject"}:
            path = "unrelated.txt" if name.endswith("unrelated") else "subject.json"
            commit = _replace_record(commit, path, replace(_record(commit, path), size_bytes=_record(commit, path).size_bytes + 1))
        elif name == "wrong-subject-role":
            commit = _replace_record(commit, "subject.json", replace(_record(commit, "subject.json"), artifact_kind="foreign-kind"))
        elif name in {"ground-context-mismatch", "agency-context-mismatch", "missing-certificate-context-mismatch"}:
            field = "authority_axiom_agency_digest" if name == "agency-context-mismatch" else "ground_artifact_digest"
            subject["context"][field] = "sha256:" + "0" * 64
            commit = _rebind(commit, evidence, subject)
            if name.startswith("missing"):
                evidence.pop(_record(commit, "certificate.json").object_digest)
        elif name in {"canonical-agency-reduced", "canonical-agency-extended"}:
            actions = AUTHORITY_AXIOM_AGENCY[:-1] if name.endswith("reduced") else tuple(sorted((*AUTHORITY_AXIOM_AGENCY, "SYNTHETIC_EXTRA_ACTION")))
            agency = authority_axiom_agency_digest(actions)
            commit = replace(commit, authority_axiom_agency=actions, authority_axiom_agency_digest=agency)
            subject["context"]["authority_axiom_agency_digest"] = agency
            commit = _rebind(commit, evidence, subject)
        elif name == "agency-digest-inconsistent":
            commit = replace(commit, authority_axiom_agency=AUTHORITY_AXIOM_AGENCY[:-1])
        elif name == "unsupported-profile":
            payload = b"opaque unsupported profile"
            commit = _substitute(commit, evidence, "profile.json", payload)
            subject["profile_digest"] = digest_bytes(payload)
            commit = _rebind(commit, evidence, subject)
        elif name in {"same-digest-alias", "alias-size-mismatch"}:
            alias = _record(commit, "unrelated.txt")
            if name == "alias-size-mismatch":
                alias = replace(alias, size_bytes=alias.size_bytes + 1)
            commit = replace(commit, census=(*commit.census, CensusEntry("alias.txt", alias, "DISPENSABLE")))
        elif name == "profile-as-opaque-ground":
            commit = replace(commit, ground_paths=("ground.txt", "profile.json"))
            subject["context"]["ground_artifact_digest"] = profile_digest()
            commit = _rebind(commit, evidence, subject)
            paths["ground_path"] = "profile.json"
        elif name == "swapped-path-selectors":
            paths["subject_path"], paths["certificate_path"] = paths["certificate_path"], paths["subject_path"]
        elif name == "malformed-certificate-missing-unrelated":
            commit = _substitute(commit, evidence, "certificate.json", b"malformed certificate")
            evidence.pop(_record(commit, "unrelated.txt").object_digest)
        elif name == "profile-coordinate-mismatch-missing-ground":
            commit = _substitute(commit, evidence, "profile.json", b"mismatching retained profile")
            evidence.pop(_record(commit, "ground.txt").object_digest)
        commit_bytes = canonical_bytes(commit.to_dict())
        report = inspect_silo_formation(commit_bytes, evidence, **paths)
        cases.append({"case_id": name, "commit_bytes_base64url": encode(commit_bytes),
                      "evidence": [{"digest": digest, "bytes_base64url": encode(payload)} for digest, payload in sorted(evidence.items())],
                      "paths": paths, "expected_report": report,
                      "expected_report_digest": digest_bytes(canonical_bytes(report))})
    return cases


def build_corpus() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION,
            "profile": {"bytes_base64url": encode(profile_bytes()), "digest": profile_digest()},
            "pure_cases": _pure_cases(), "silo_cases": _silo_cases()}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=TARGET)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    corpus = build_corpus()
    encoded = canonical_bytes(corpus)
    if len(encoded) > MAX_CORPUS_BYTES:
        parser.error("formation corpus exceeds its one-mebibyte byte ceiling")
    if arguments.check:
        if not arguments.output.is_file() or arguments.output.read_bytes() != encoded:
            print("Formation corpus is absent or differs from current native reference output.")
            return 1
        print(f"Formation corpus matches: {len(corpus['pure_cases'])} pure cases, {len(corpus['silo_cases'])} silo cases, {len(encoded)} bytes.")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(encoded)
        print(f"Generated formation corpus: {len(corpus['pure_cases'])} pure cases, {len(corpus['silo_cases'])} silo cases, {len(encoded)} bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

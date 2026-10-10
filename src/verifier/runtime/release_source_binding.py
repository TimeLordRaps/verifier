"""Dependency-ready exact release-source binding, with no polished admission.

Terminology: command-line interface (CLI); application programming interface (API);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Software Bill of Materials (SBOM); mebibytes (MiB); ZIP archive format (ZIP).
Unicode Normalization Form C (NFC) is required for every selected path; portable
case-folded comparison detects aliases without rewriting selected path bytes.
One selected VERIFIER subject binds the source ZIP, wheel, source distribution,
SBOM and external manifest, the full selected source inventory, public surface
inventory and selected actual harness-execution records. Console aliases share
one entrypoint and are compatibility requirements, not additional subjects.
PASS for byte binding proves only equality with the externally selected finite
commitments. Native replay, inventory completeness/authority, loaded execution,
human acceptance and full application conformance are separate and unestablished.
The proposed application-profile semantics remain UNADOPTED. No input is executed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any
import unicodedata

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads

SCHEMA = "verifier-release-source-binding-selection-1"
REPORT = "verifier-release-source-binding-assessment-1"
MAX_SELECTION_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 8192
MAX_NODES = 100000
MAX_DEPTH = 32
MAX_REPORT_BYTES = 8 * 1024 * 1024
RELEASE_ROLES = frozenset({"source_zip", "wheel", "sdist", "sbom", "external_manifest"})
ALIASES = {name: "verifier.runtime.public_cli:main" for name in ("vstd", "verifier", "verifiable")}
BOUNDARY = ("Exact selected byte binding only. Full source/public-surface applicability, native replay, "
            "independent selector authority, actual execution and polished admission are not established. "
            "The application profile is UNADOPTED; no downstream effect or publication is authorized.")


class _Exhausted(Exception):
    pass


class _UnsupportedScripts(Exception):
    pass


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    return digest(Path(__file__).read_bytes())


def _hash(value: Any) -> bool:
    return type(value) is str and len(value) == 71 and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _portable_path_key(value: str) -> str:
    """Return a comparison key only; selected path bytes are never rewritten."""

    return unicodedata.normalize("NFC", value.casefold())


def _reference(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"path", "sha256"} or not _hash(value["sha256"]):
        raise ValueError("exact path/digest reference required")
    name = value["path"]
    if (type(name) is not str or not name or len(name) > 512 or "\\" in name or ":" in name
            or name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise ValueError("bounded canonical relative path required")
    name.encode("utf-8", "strict")
    if unicodedata.normalize("NFC", name) != name:
        raise ValueError("NFC-normalized path required")
    return value


def _scripts(raw: bytes) -> dict[str, str]:
    """Read only the supported literal scripts-table grammar, without general TOML claims."""
    scripts: dict[str, str] = {}
    selected = False
    seen = False
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if '\"\"\"' in line or "'''" in line:
            # A table-looking line inside a multiline value is data, not a declaration.
            raise _UnsupportedScripts()
        table = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]\s*(?:#.*)?", line)
        if table:
            selected = table[1] == "project.scripts"
            if selected:
                if seen:
                    raise ValueError("duplicate scripts table")
                seen = True
            continue
        if selected:
            entry = re.fullmatch(r'''([A-Za-z0-9_-]+)\s*=\s*(["'])([A-Za-z0-9_.:-]+)\2\s*(?:#.*)?''', line)
            if entry is None:
                raise _UnsupportedScripts()
            if entry[1] in scripts:
                raise ValueError("duplicate console alias")
            scripts[entry[1]] = entry[3]
        elif line.startswith("["):
            # Unknown table syntax could change table membership; refuse rather than guess.
            raise _UnsupportedScripts()
    return scripts


def _record(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise ValueError("bounded immutable selection bytes required")
    if len(raw) > MAX_SELECTION_BYTES:
        raise _Exhausted("selection byte bound exhausted")
    value = strict_json_loads(raw.decode("utf-8"))
    if type(value) is not dict:
        raise ValueError("selection record required")
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise _Exhausted("selection structure bound exhausted")
        if type(item) in (dict, list):
            if type(item) is dict:
                for key in item:
                    key.encode("utf-8")
            pending.extend((child, depth + 1) for child in (item.values() if type(item) is dict else item))
        elif type(item) is str:
            item.encode("utf-8")
    return value


def assess_release_source_binding(selection_bytes: bytes, file_bytes: dict[str, bytes], *,
                                  expected_selection_digest: str | None,
                                  expected_mechanism_digest: str | None,
                                  cancelled: bool = False) -> dict[str, Any]:
    """Check immutable selected source/tuple/run bindings; never issue application acceptance."""
    findings: list[dict[str, Any]] = []
    report: dict[str, Any] = {"schema_version": REPORT, "status": "UNKNOWN", "binding_status": "UNKNOWN",
        "polished": False, "full_application_status": "UNKNOWN", "application_profile": "UNADOPTED",
        "selector_authority": "NOT_ESTABLISHED", "public_surface_completeness": "NOT_ESTABLISHED",
        "source_inventory_completeness": "NOT_ESTABLISHED", "actual_execution": "NOT_ESTABLISHED",
        "subject_record_semantics": "NOT_ASSESSED",
        "required_certificate_instances": "UNKNOWN", "native_objective_replay": "NOT_RUN",
        "report_complete": True, "findings_complete": "SELECTED_BINDING_ONLY",
        "findings": findings, "claim_boundary": BOUNDARY}

    def add(code: str, status: str, pointer: str, **detail: Any) -> None:
        findings.append({"code": code, "status": status, "pointer": pointer, **detail})

    try:
        invalid_pins = set()
        for expected, code in ((expected_selection_digest, "EXTERNAL_SELECTION_PIN"),
                               (expected_mechanism_digest, "EXTERNAL_MECHANISM_PIN")):
            if expected is not None and not _hash(expected):
                invalid_pins.add(code)
                add(code + "_INVALID", "FAIL", "")
        if type(cancelled) is not bool:
            raise ValueError("explicit cancellation boolean required")
        if type(file_bytes) is not dict:
            raise ValueError("bounded immutable file map required")
        if len(file_bytes) > MAX_FILES:
            raise _Exhausted("file count bound exhausted")
        file_bytes = file_bytes.copy()
        if any(type(name) is not str or len(name) > 512 or type(raw) is not bytes for name, raw in file_bytes.items()):
            raise ValueError("immutable file bytes required")
        if (any(len(raw) > MAX_FILE_BYTES for raw in file_bytes.values())
                or sum(len(raw) for raw in file_bytes.values()) > MAX_TOTAL_BYTES):
            raise _Exhausted("file byte or count bound exhausted")
        value = _record(selection_bytes)
        if (set(value) != {"schema_version", "subject", "release_tuple", "source_inventory", "console_scripts",
                           "public_surface_inventory", "applicability_inventory", "harness_executions"}
                or value["schema_version"] != SCHEMA):
            raise ValueError("release selection contract differs")
        subject = value["subject"]
        if (type(subject) is not dict or set(subject) != {"object_id", "object_kind", "record", "instruction_revision", "context_revision"}
                or subject["object_kind"] != "VERIFIER" or type(subject["object_id"]) is not str
                or not subject["object_id"].strip() or len(subject["object_id"]) > 256
                or not all(_hash(subject[key]) for key in ("instruction_revision", "context_revision"))):
            raise ValueError("one exact VERIFIER subject and revision binding required")
        if type(value["release_tuple"]) is not dict or set(value["release_tuple"]) != RELEASE_ROLES:
            raise ValueError("complete five-artifact release tuple required")
        release_references = {
            role: _reference(value["release_tuple"][role]) for role in sorted(RELEASE_ROLES)
        }
        if len({_portable_path_key(row["path"]) for row in release_references.values()}) != len(RELEASE_ROLES):
            raise ValueError("release artifact roles require distinct paths")
        if value["console_scripts"] != ALIASES:
            raise ValueError("all three console aliases must bind the same supported entrypoint")
        sources = value["source_inventory"]
        runs = value["harness_executions"]
        if type(sources) is not list or not sources:
            raise ValueError("nonempty complete selected source inventory required")
        if type(runs) is not list or not runs:
            raise ValueError("selected actual harness-execution records required")
        if len(sources) > MAX_FILES or len(runs) > 256:
            raise _Exhausted("selected source or harness count bound exhausted")
        references = [("/subject/record", _reference(subject["record"]))]
        references += [("/release_tuple/" + role, release_references[role]) for role in sorted(RELEASE_ROLES)]
        source_references = [_reference(row) for row in sources]
        references += [("/source_inventory/" + str(index), row) for index, row in enumerate(source_references)]
        paths = [row["path"] for row in source_references]
        if (paths != sorted(set(paths))
                or len({_portable_path_key(path) for path in paths}) != len(paths)
                or not {"pyproject.toml", "src/verifier/__init__.py", "src/verifier/runtime/public_cli.py"} <= set(paths)):
            raise ValueError("source inventory omits release/entrypoint/API declaration anchors or has ambiguous paths")
        references += [("/" + name, _reference(value[name])) for name in ("public_surface_inventory", "applicability_inventory")]
        for index, run in enumerate(runs):
            pointer = "/harness_executions/" + str(index)
            if (type(run) is not dict or set(run) != {"subject_record_digest", "instruction_revision", "context_revision", "request", "policy", "mechanism", "certificate", "execution"}):
                raise ValueError("complete selected harness tuple required")
            for key, expected in (("subject_record_digest", subject["record"]["sha256"]),
                                  ("instruction_revision", subject["instruction_revision"]), ("context_revision", subject["context_revision"])):
                if not _hash(run[key]):
                    raise ValueError("canonical harness subject and revision digests required")
                if run[key] != expected:
                    add("HARNESS_SUBJECT_OR_REVISION_SUBSTITUTED", "FAIL", pointer + "/" + key, expected=expected, actual=run[key])
            references += [(pointer + "/" + key, _reference(run[key])) for key in ("request", "policy", "mechanism", "certificate", "execution")]
        file_digests: dict[str, str] = {}
        for pointer, reference in references:
            raw = file_bytes.get(reference["path"])
            if raw is None:
                add("SELECTED_FILE_MISSING", "UNKNOWN", pointer, path=reference["path"], expected=reference["sha256"])
            else:
                if reference["path"] not in file_digests:
                    file_digests[reference["path"]] = digest(raw)
                actual = file_digests[reference["path"]]
                if actual != reference["sha256"]:
                    add("SELECTED_FILE_DIGEST_DIFFERS", "FAIL", pointer, path=reference["path"], expected=reference["sha256"], actual=actual)
        declaration = next(row for row in sources if row["path"] == "pyproject.toml")
        project = file_bytes.get("pyproject.toml")
        if project is not None and file_digests["pyproject.toml"] == declaration["sha256"]:
            try:
                if _scripts(project) != ALIASES:
                    add("SOURCE_CONSOLE_ALIASES_DIFFER", "FAIL", "/console_scripts")
            except _UnsupportedScripts:
                add("SOURCE_CONSOLE_ALIASES_UNASSESSED", "UNKNOWN", "/console_scripts")
        for expected, actual, code in ((expected_selection_digest, digest(selection_bytes), "EXTERNAL_SELECTION_PIN"),
                                       (expected_mechanism_digest, mechanism_digest(), "EXTERNAL_MECHANISM_PIN")):
            if expected is None:
                add(code + "_MISSING", "UNKNOWN", "")
            elif code not in invalid_pins and expected != actual:
                add(code + "_DIFFERS", "FAIL", "", expected=expected, actual=actual)
        if cancelled:
            add("CANCELLED", "UNKNOWN", "")
        report.update(selection_digest=digest(selection_bytes), mechanism_digest=mechanism_digest(),
                      subject=subject, release_tuple=value["release_tuple"], console_scripts=value["console_scripts"],
                      source_files=len(sources), selected_harness_executions=len(runs))
    except (_Exhausted, RecursionError) as exc:
        add("SOURCE_BINDING_CAPACITY_EXHAUSTED", "UNKNOWN", "", detail=str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError):
        add("SOURCE_BINDING_CONTRACT_UNMET", "FAIL", "", detail="bounded source-binding contract unmet")
    states = [row["status"] for row in findings]
    report["binding_status"] = "FAIL" if "FAIL" in states else "UNKNOWN" if states else "PASS"
    report["status"] = "FAIL" if "FAIL" in states else "UNKNOWN"
    try:
        report["report_digest"] = digest(canonical_bytes(report))
        if len(canonical_bytes(report)) > MAX_REPORT_BYTES:
            raise _Exhausted("report byte bound exhausted")
    except (_Exhausted, TypeError, ValueError, UnicodeError):
        report = {"schema_version": REPORT, "status": "FAIL" if "FAIL" in states else "UNKNOWN",
            "binding_status": "FAIL" if "FAIL" in states else "UNKNOWN", "polished": False,
            "full_application_status": "UNKNOWN", "application_profile": "UNADOPTED",
            "report_complete": False, "findings_complete": "NOT_ESTABLISHED",
            "findings": [{"code": "SOURCE_BINDING_REPORT_CAPACITY_EXHAUSTED", "status": "UNKNOWN", "pointer": ""}]}
        report["report_digest"] = digest(canonical_bytes(report))
    return report

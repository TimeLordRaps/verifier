"""Reasoned applicability without label-based escapes.

Terminology: Unicode Transformation Format, 8-bit (UTF-8).

Verifier Standard (VSTD) classification is an evidence ledger, not an oracle.
Source declarations impose requirements; source heuristics open questions.
Repository-authored refutations bind a documented interpretation to exact bytes,
but do not prove arbitrary program semantics or independent decision authority.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
import os
import re
import stat
from typing import Any, Callable, Sequence

from verifier.runtime import namespace_refutation as refutation
from verifier.runtime import package_original_kind_review as effects
from verifier.runtime.namespace_contracts import KindContract, ancestors, requirements_for
from verifier.runtime.namespace_manifest import REFUTATION
from verifier.runtime.tier_zero_manifest import MAX_PACKAGE_MANIFEST_BYTES
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


# This denominator bounds graph reasoning independently of the transport
# profile.  A larger v5 envelope may describe more source evidence, but it must
# not turn obligation derivation into an unbounded Cartesian expansion.
MAX_DERIVED_ITEMS = 65_536
MAX_DERIVED_BYTES = MAX_PACKAGE_MANIFEST_BYTES

# An aggregate assessment used to repeat every installed obligation contract,
# repository-authored declaration and trigger sentence in every derived row.
# Repetition is not evidence.  Exact contracts now appear once in a typed
# catalog, and deterministic profiles remove only values recoverable from that
# catalog or an adjacent profile definition.  Actionable rows retain their
# object/obligation identity and all non-profiled repair data.
MAX_PASS_REASON_SUMMARY_BYTES = 128
MAX_PASS_DECLARATION_VALUE_SUMMARY_BYTES = 64
MAX_TRIGGER_SUMMARY_BYTES = 128
SHARED_OBLIGATION_CONTRACT_PROFILE = "SHARED_OBLIGATION_CONTRACT"
MISSING_OBLIGATION_BINDING_PROFILE = "MISSING_OBLIGATION_BINDING"
DOCUMENTED_APPLIES_RETENTION_PROFILE = "DOCUMENTED_APPLIES_RETENTION"
REQUIRED_OBLIGATION_FINDING_PROFILE = "REQUIRED_OBLIGATION_REFERENCE"

# A name-only closure cannot see a renamed write, so an owned consequence in an
# external-write channel keeps absence unestablished for every kind alike.  The
# set is generic: no kind is mapped to a channel here.
_EXTERNAL_WRITE_CHANNELS = frozenset({"filesystem_write", "hardware_device", "network", "subprocess_process"})
_CLOSED_EFFECT_NOT_CLOSED = "CLOSED_EFFECT_AUDIT_NOT_CLOSED"
_EMPTY_CENSUS = "EMPTY_CENSUS"
_CLOSED_EFFECT_CODES = frozenset({_CLOSED_EFFECT_NOT_CLOSED, _EMPTY_CENSUS})
# A DOES_NOT_APPLY is admitted as DOCUMENTED, never ESTABLISHED, only when four things
# hold together: a repository-specific reason, current owned evidence, a fresh clean
# closure scan and a clean owned closed-effect audit of the same bytes.  Without a stored
# witness the scan runs now over the object's exact current owned census, every owned
# file; a stored EXECUTABLE_CLOSURE witness, when present, must bind and judge clean
# instead.  Data files are scanned but cannot execute, so only code goes to the audit.
# DOCUMENTED records the repository's negative interpretation over exact bytes.  It is
# not proof, so it never removes an obligation that a source hint selected and never
# overrides a declared role.
DOCUMENTED = "DOCUMENTED"
DOCUMENTED_CODE = "DOCUMENTED_BOUNDED_ABSENCE"
_PACKAGE_MARKER = "__init__.py"
_EMPTY_FILE_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_MAX_BLOCKER_BYTES = 256


def _utf8_prefix(value: str, limit: int) -> str:
    """Return at most ``limit`` UTF-8 bytes without splitting a code point."""
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def _bounded_text_summary(value: str, *, limit: int, reference: str) -> str:
    """Keep short prose inline and make longer prose visibly referential."""
    if len(value.encode("utf-8")) <= limit:
        return value
    suffix = f" ... [bounded; exact text bound by {reference}]"
    available = max(0, limit - len(suffix.encode("utf-8")))
    return _utf8_prefix(value, available).rstrip() + suffix


def _trigger_summary(values: list[str]) -> tuple[list[str], str, str]:
    """Return exact small triggers or one bounded preview, plus exact digest."""
    selected = sorted(set(values))
    digest = value_digest(selected)
    joined = " ".join(selected)
    if len(canonical_bytes(selected)) <= MAX_TRIGGER_SUMMARY_BYTES:
        return selected, joined, digest
    # Both callers publish ``digest`` in the adjacent typed digest field.  Do
    # not repeat its 71-byte rendering inside every human preview: on the full
    # graph that display-only duplication alone can exhaust the derived-output
    # envelope.  The preview remains visibly referential and the exact identity
    # remains independently machine-checkable beside it.
    suffix = f" ... [{len(selected)} triggers; digest adjacent]"
    available = max(0, MAX_TRIGGER_SUMMARY_BYTES - len(suffix.encode("utf-8")))
    summary = _utf8_prefix(joined, available).rstrip() + suffix
    return [summary], summary, digest


def _bounded_explanation(values: list[str], *, noun: str) -> str:
    selected = sorted(set(values))
    joined = ", ".join(selected)
    if len(joined.encode("utf-8")) <= 4096:
        return joined
    return (
        f"{len(selected)} {noun}; exact sorted identity digest "
        f"{value_digest(selected)}"
    )


def finding(code: str, status: str, coordinate: str, explanation: str, next_action: str,
            *, object_id: str | None = None, obligation_id: str | None = None,
            surface_id: str | None = None,
            gate_id: str = "namespace-admission") -> dict[str, Any]:
    normalized_reason = explanation
    if type(normalized_reason) is not str or not normalized_reason.strip():
        normalized_reason = (code.replace("_", " ").capitalize() + "."
                             if type(code) is str and code.strip()
                             else "Unspecified verification failure.")
    selected = obligation_id or coordinate + "-namespace-admission"
    return {"code": code, "status": status, "coordinate": coordinate,
            "gate_id": gate_id, "object_id": object_id,
            "obligation_id": selected, "surface_id": surface_id,
            "reason": normalized_reason, "explanation": normalized_reason,
            "next_action": next_action,
            "rerun_argv": (["vstd", "gate", "--object", object_id, "--obligation", selected]
                           if object_id else ["vstd", "polish", "0"])}


_OWNER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_NEXT_ACTION_ESTABLISH = ("Record APPLIES for this kind, or clear the blocker named in the reason and rerun; "
                          "DOES_NOT_APPLY is admitted as DOCUMENTED only when a fresh closure scan of every owned "
                          "file and the owned effect audit are clean and its reason binds current owned evidence.")
_NEXT_ACTION_REFERENCE = ("Review the boundary reference the fresh scan found in this object's owned files; record "
                          "APPLIES if the object does that work.  The claim stays unadmitted while the reference "
                          "remains.")
_NEXT_ACTION_EVIDENCE = ("Re-bind this decision's evidence to this object's current owned bytes and rerun; stale or "
                         "self-referential evidence contradicts the claim.")
_NEXT_ACTION_BOUNDED = ("A finite boundary scan alone never admits non-applicability; rerun with the source root so "
                        "the owned effect audit runs, or record APPLIES and keep its obligations required.")
_NEXT_ACTION_SUPPORT = ("Restore a repository-specific reason and evidence that binds this object's current owned "
                        "bytes; the clean scan and effect audit then admit the claim as DOCUMENTED.")
_NEXT_ACTION_CONTRADICTION = ("Resolve the witness contradiction with the current source; "
                              "its obligations stay required meanwhile.")
# Moving another object's helper into this object or deleting a needed write is not an honest
# repository action, so an unclosed audit offers APPLIES or a reviewed audit change, nothing else.
_NEXT_ACTION_CLOSED_EFFECT = ("Record APPLIES if this object does this kind's work; otherwise the claim stays "
                              "unadmitted until the owned effect audit can account for the blocker named in the "
                              "reason, which is a reviewed change to that audit.")
_NEXT_ACTION_EMPTY_CENSUS = ("Bind this object's real surfaces: its owned files are empty or package markers, so no "
                             "scan or audit can show what it does.")


def witness_owner(path: str) -> str | None:
    """Return the dotted identity that owns one repository file, or ``None``.

    The extension stays in the leaf, so ``x.py`` and ``x.mjs`` never share an
    owner.  ``None`` means the path cannot be named as a witness owner, so a
    witness citing it cannot be bound and remains non-admissible.
    """
    directories, _, name = path.rpartition("/")
    stem, dot, suffix = name.rpartition(".")
    if not dot:
        stem, suffix = name, ""
    if not stem:
        return None
    leaf = stem + "_" + suffix if suffix else stem
    dotted = ".".join([*directories.split("/"), leaf]) if directories else leaf
    return dotted if _OWNER_RE.fullmatch(dotted) else None


_WINDOWS_REPARSE_POINT = 0x400


def _is_reparse_point(path: Path) -> bool:
    """Return True for a symbolic link, a Windows junction or any other reparse point.

    An unreadable entry counts as a reparse point, so it is refused rather than
    followed.
    """
    try:
        status = os.lstat(path)
    except OSError:
        return True
    return stat.S_ISLNK(status.st_mode) or bool(getattr(status, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


def _source_reader(root: Path) -> Callable[[str], bytes]:
    """Read one census path under ``root`` for a fresh closure run.

    The reader is not trusted: the closure compares every byte string against the
    census digest before it scans, so a changed or substituted file is STALE.  Every
    path component below ``root`` must be a plain directory or file, so a link
    cannot redirect a read outside the census.  The read is bounded one byte past
    the anchor limit so an oversize file is refused.
    """
    cache: dict[str, bytes] = {}
    base = root.resolve(strict=True)

    def read(path: str) -> bytes:
        if path not in cache:
            target = root / path
            current = root
            for part in path.split("/"):
                current = current / part
                if _is_reparse_point(current):
                    raise OSError("CENSUS_PATH_REPARSE_POINT")
            if not target.is_file():
                raise OSError("CENSUS_PATH_NOT_A_REGULAR_FILE")
            if not target.resolve(strict=True).is_relative_to(base):
                raise OSError("CENSUS_PATH_ESCAPES_ROOT")
            with target.open("rb") as handle:
                cache[path] = handle.read(refutation.MAX_ANCHOR_BYTES + 1)
        return cache[path]

    return read


def refutation_context(observed: dict[str, Any], mechanism_digest: str, *,
                       root: Path | None = None) -> dict[str, Any]:
    """Return the expected installed mechanism, the anchors a witness may cite, and a reader.

    A census file enters the inventory only when the witness validator accepts
    its path, owner and digest.  Any other file is absent, so a witness citing it
    is UNKNOWN rather than causing one malformed inventory to reject every witness.
    Without ``root`` the context has no reader, and no closure can run: every
    DOES_NOT_APPLY then stays UNKNOWN.  ``files`` holds every census digest, so a
    decision without a witness is scanned over its exact owned census.  ``memo`` and
    ``audit_memo`` let one assessment normalize, gate and audit each exact census once
    across kinds; both are keyed by digests that each run verifies.
    """
    files = {row["path"]: row["sha256"] for row in observed["census"]["files"]}
    inventory: dict[str, dict[str, Any]] = {}
    for path, digest in files.items():
        owner = witness_owner(path)
        if owner is None:
            continue
        entry = {"owner": owner, "sha256": digest, "available": True}
        if refutation._inventory_verdict({path: entry}) is None:
            inventory[path] = entry
    return {"mechanism_digest": mechanism_digest, "inventory": inventory, "files": files, "root": root,
            "read": None if root is None else _source_reader(root), "memo": {}, "audit_memo": {}}


def _review_module(owned_paths: set[str]) -> str | None:
    owners = {witness_owner(path) for path in owned_paths}
    if len(owners) != 1:
        return None
    (owner,) = owners
    return owner


def _closed_effect_unknown(code: str, detail: str) -> refutation.Verdict:
    return refutation.Verdict(refutation.UNKNOWN, code, _utf8_prefix(detail, _MAX_BLOCKER_BYTES))


def _closed_effect_blocker(context: dict[str, Any], module: str | None,
                           owned_paths: set[str]) -> refutation.Verdict | None:
    """Return the typed UNKNOWN that keeps a clean closure scan from being admitted.

    The closure scans only owned text, so a helper that escapes the census or a
    renamed write is invisible to it.  The current closed-effect audit therefore runs
    over the object's full owned census: its surface paths plus, for a bound witness's
    review ``module``, every inventory file that module owns.  Data files cannot
    execute, so only code files are audited; any other language still blocks inside
    the audit.  The audit is bound to the census digests, so it judges the bytes the
    scan judged, and one context audits each exact code census once.  Admission as
    DOCUMENTED needs state CLOSED, no blocker, no owned write consequence and at least
    one substantive file.  The first underlying blocker is reported verbatim, bounded,
    so it can be acted on.
    """
    census = set(owned_paths)
    if module is not None:
        census |= {path for path, entry in context["inventory"].items() if entry["owner"] == module}
    if not census:
        return _closed_effect_unknown(_EMPTY_CENSUS, "")
    root = context.get("root")
    if root is None:
        return _closed_effect_unknown(_CLOSED_EFFECT_NOT_CLOSED, "AUDIT_ROOT_ABSENT")
    known = context.get("files")
    if known is None:
        known = {path: entry["sha256"] for path, entry in context["inventory"].items()}
    absent = sorted(path for path in census if path not in known)
    if absent:
        return _closed_effect_unknown(_CLOSED_EFFECT_NOT_CLOSED, "SOURCE_DIGEST_ABSENT:" + absent[0])
    code = {path: known[path] for path in census if not refutation.is_data_path(path)}
    # A data file is substantive when its verified census bytes are not empty.
    substantive = any(known[path] != _EMPTY_FILE_DIGEST for path in census if refutation.is_data_path(path))
    if code:
        audit = _audit_code_census(context, root, code)
        if type(audit) is str:
            return _closed_effect_unknown(_CLOSED_EFFECT_NOT_CLOSED, audit)
        if audit.status != "CLOSED" or audit.blockers:
            first = min(audit.blockers) if audit.blockers else "STATUS:" + str(audit.status)
            return _closed_effect_unknown(_CLOSED_EFFECT_NOT_CLOSED, first)
        writes = sorted((row for row in audit.consequences if row.channel in _EXTERNAL_WRITE_CHANNELS),
                        key=lambda row: (row.path, row.line, row.column, row.channel))
        if writes:
            first = writes[0]
            return _closed_effect_unknown(_CLOSED_EFFECT_NOT_CLOSED,
                                          f"EXTERNAL_WRITE_CONSEQUENCE:{first.channel}:{first.path}:{first.line}")
        substantive = substantive or any(PurePosixPath(row.path).name != _PACKAGE_MARKER and row.byte_count > 0
                                         for row in audit.sources)
    if not substantive:
        return _closed_effect_unknown(_EMPTY_CENSUS, "")
    return None


def _audit_code_census(context: dict[str, Any], root: Path, code: dict[str, str]) -> Any:
    """Run, or reuse from this context, the closed-effect audit of one exact code census.

    The memo key is every path with its census digest, and the audit refuses bytes that
    differ from those digests, so a reused result always describes the same bytes.  An
    audit that cannot run is kept as its error text.
    """
    memo = context.get("audit_memo")
    key = tuple(sorted(code.items()))
    if memo is not None and key in memo:
        return memo[key]
    try:
        outcome: Any = effects.audit_closed_effects(root, sorted(code), expected_source_digests=dict(code))
    except (OSError, ValueError) as exc:
        outcome = str(exc) or type(exc).__name__
    if memo is not None:
        memo[key] = outcome
    return outcome


def _census_verdict(identifier: str, kind: str, decision: dict[str, Any], owned_paths: set[str],
                    context: dict[str, Any]) -> refutation.Verdict:
    """Judge a DOES_NOT_APPLY that carries no witness by a fresh run over its exact owned census.

    Nothing is stored or read back from the manifest.  The registered closure runs now
    over every owned file at its current census digest, and the owned effect audit
    judges the same bytes.  Only a clean scan whose audit is also clean is DOCUMENTED.
    A registered boundary reference is UNKNOWN: no reviewer bound a claim it could
    contradict.  The caller still requires the decision's own reason and current owned
    evidence.
    """
    if not owned_paths:
        return _closed_effect_unknown(_EMPTY_CENSUS, "")
    files = context.get("files") or {}
    absent = sorted(path for path in owned_paths if path not in files)
    if absent:
        return refutation.Verdict(refutation.UNKNOWN, "CENSUS_FILE_ABSENT",
                                  _utf8_prefix(absent[0], _MAX_BLOCKER_BYTES))
    verdict = refutation.judge_census_closure(
        object_id=identifier, kind=kind,
        decision_row_digest=value_digest({key: item for key, item in decision.items() if key != REFUTATION}),
        mechanism_digest=context["mechanism_digest"], census={path: files[path] for path in owned_paths},
        read=context.get("read"), memo=context.get("memo"))
    receipt = verdict.receipt
    if (verdict.code != refutation.BOUNDED_ABSENCE_CODE or receipt is None
            or receipt["status"] != refutation.CLOSURE_PASS):
        return verdict
    blocker = _closed_effect_blocker(context, None, owned_paths)
    if blocker is not None:
        # Keep the fresh receipt, so the blocker still names the bounded scan it demoted.
        return refutation.Verdict(blocker.status, blocker.code, blocker.detail, receipt=receipt)
    return refutation.Verdict(DOCUMENTED, DOCUMENTED_CODE, verdict.detail, receipt=receipt)


def _non_applicability_verdict(identifier: str, kind: str, decision: dict[str, Any],
                               owned_paths: set[str],
                               context: dict[str, Any] | None) -> refutation.Verdict:
    """Judge a DOES_NOT_APPLY decision against exact, current inputs.

    A decision without a stored witness is judged by a fresh closure run over its
    exact owned census (``_census_verdict``).  A stored witness must bind instead: the
    expected review identity comes from this object's owned surfaces and the installed
    mechanism, never from the witness.  The basis is the witness's own claim, so an
    audited document is reported as AUDITED_NOT_ESTABLISHED instead of a mismatch.  No
    installed closure yields ESTABLISHED: a clean fresh run is a bounded observation
    that keeps its receipt.  The census precondition demotes that observation to
    UNKNOWN but never a FAIL, because FAIL outranks UNKNOWN.  Only a clean receipt whose
    owned effect audit also ran clean is DOCUMENTED; the caller still requires the
    decision's own reason and current owned evidence.
    """
    if context is None:
        return refutation.Verdict(refutation.UNKNOWN, "REFUTATION_CONTEXT_ABSENT", "")
    witness = decision.get(REFUTATION)
    if witness is None:
        return _census_verdict(identifier, kind, decision, owned_paths, context)
    module = _review_module(owned_paths)
    if module is None:
        return refutation.Verdict(refutation.UNKNOWN, "REVIEW_MODULE_UNBOUND", "")
    basis = witness.get("basis") if type(witness) is dict else None
    if type(basis) is not str or basis not in refutation.BASES:
        basis = refutation.BASIS_EXECUTABLE_CLOSURE
    expected = refutation.ExpectedReview(
        object_id=identifier,
        kind=kind,
        basis=basis,
        review_module=module,
        review_mechanism_digest=context["mechanism_digest"],
        review_row_digest=value_digest({key: item for key, item in decision.items()
                                        if key != REFUTATION}),
    )
    audited = (type(witness) is dict and basis == refutation.BASIS_EXECUTABLE_CLOSURE
               and context.get("read") is not None)
    closed_effect = _closed_effect_blocker(context, module, owned_paths) if audited else None
    verdict = refutation.establish_dne_witness(
        witness, expected=expected, inventory=context["inventory"], read=context.get("read"))
    if closed_effect is not None and verdict.status != refutation.FAIL:
        # Keep the fresh receipt, so the blocker still names the bounded scan it demoted.
        return refutation.Verdict(closed_effect.status, closed_effect.code, closed_effect.detail,
                                  receipt=verdict.receipt)
    if verdict.code == "EXPECTED_MALFORMED":
        return refutation.Verdict(refutation.UNKNOWN, "REVIEW_IDENTITY_UNBINDABLE", verdict.detail)
    if (audited and verdict.status == refutation.UNKNOWN and verdict.code == refutation.BOUNDED_ABSENCE_CODE
            and verdict.receipt is not None and verdict.receipt["status"] == refutation.CLOSURE_PASS):
        # A fresh clean receipt over a clean owned audit is documented, never established.
        return refutation.Verdict(DOCUMENTED, DOCUMENTED_CODE, verdict.detail, receipt=verdict.receipt)
    return verdict


def _non_applicability_finding(identifier: str, kind: str, verdict: refutation.Verdict,
                               support: str, support_reason: str, *, required: bool) -> dict[str, Any]:
    """State exactly why a DOES_NOT_APPLY claim does not remove the kind's obligations.

    A kind that adds no obligation has none to keep, so the message says only that
    nothing was removed; it never claims obligations that do not exist.
    """
    failed = verdict.status == refutation.FAIL or support == "FAIL"
    consequence = ("its obligations remain required." if required
                   else "it adds no obligation, so no obligation is removed; the unestablished claim still blocks admission.")
    if verdict.status == DOCUMENTED:
        # The scan and the audit are clean, so only the decision's own support keeps it out.
        reason = (kind + " declares DOES_NOT_APPLY, but that claim is not admitted: its fresh closure scan and "
                  "owned effect audit are clean (" + verdict.code + "), yet its reason and evidence do not bind "
                  "current owned bytes; " + consequence + " " + support_reason)
    else:
        reason = (kind + " declares DOES_NOT_APPLY, but that claim is "
                  + verdict.status + " (" + verdict.code + "); " + consequence)
        if support != "PASS":
            reason += " " + support_reason
    receipt = verdict.receipt
    if receipt is not None and receipt["status"] == refutation.CLOSURE_PASS:
        # State exactly what the clean scan supports, so a bounded observation is never read as proof.
        reason += (" The fresh closure scan of " + str(len(receipt["anchors"]))
                   + " anchored files found no registered boundary reference (census "
                   + receipt["census_digest"] + ", closure " + receipt["closure_digest"]
                   + ", receipt " + receipt["receipt_digest"] + "). It supports only the claim: "
                   + str(refutation.closure_claim(kind)) + " A finite scan does not establish non-applicability.")
    if verdict.code == _CLOSED_EFFECT_NOT_CLOSED:
        reason += (" The owned closed-effect audit is not CLOSED; first underlying blocker: "
                   + verdict.detail + ".")
    elif verdict.code == _EMPTY_CENSUS:
        reason += " The owned census holds no substantive source to audit."
    elif verdict.status == refutation.UNKNOWN and verdict.detail and verdict.code != refutation.BOUNDED_ABSENCE_CODE:
        # Name what stopped the claim, such as the file and identifier a fresh scan found.
        reason += " Blocker detail: " + verdict.detail + "."
    if verdict.status == DOCUMENTED:
        next_action = _NEXT_ACTION_SUPPORT
    elif verdict.status == refutation.FAIL:
        next_action = _NEXT_ACTION_CONTRADICTION
    elif failed:
        next_action = _NEXT_ACTION_EVIDENCE
    elif verdict.code == _EMPTY_CENSUS:
        next_action = _NEXT_ACTION_EMPTY_CENSUS
    elif verdict.code in _CLOSED_EFFECT_CODES:
        next_action = _NEXT_ACTION_CLOSED_EFFECT
    elif verdict.code == refutation.REFERENCE_CODE:
        next_action = _NEXT_ACTION_REFERENCE
    elif verdict.code == refutation.BOUNDED_ABSENCE_CODE:
        next_action = _NEXT_ACTION_BOUNDED
    else:
        next_action = _NEXT_ACTION_ESTABLISH
    return finding("NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED", "FAIL" if failed else "UNKNOWN",
                   "VSTD-T0.2", reason, next_action, object_id=identifier)


def binding_status(binding: dict[str, Any] | None, files: dict[str, str],
                   owned_paths: set[str]) -> tuple[str, str]:
    """Check support presence and byte identity, never the truth of prose."""
    if binding is None or not binding["reason"].strip() or not binding["evidence"]:
        return "UNKNOWN", "Provide a repository-specific reason and current source evidence."
    references = binding["evidence"]
    if any(ref["path"] == "objects.vstd" or files.get(ref["path"]) != ref["sha256"] for ref in references):
        return "FAIL", "An evidence reference is missing, stale or self-referential."
    if not any(ref["path"] in owned_paths for ref in references):
        return "UNKNOWN", "Bind at least one source file owned by this object, not only an unrelated document."
    return "PASS", "The stated reason and evidence references are present and bind current owned bytes; semantic fulfillment is not established."


def declaration_status(binding: dict[str, Any] | None, fields: tuple[str, ...]) -> dict[str, Any]:
    """Ask each named question; a reason and file hash cannot answer it implicitly.

    Empty declarations are unfinished work (UNKNOWN). Extra keys are a contract
    error (FAIL), not alternate spellings that silently satisfy a different field.
    Text is a source-bound declaration, never proof that the program enforces it.
    """
    declaration = binding.get("declaration", {}) if binding else {}
    missing = [field for field in fields if not declaration.get(field, "").strip()]
    unexpected = sorted(set(declaration) - set(fields))
    reason = ("Remove unregistered declaration fields: " + ", ".join(unexpected) + "." if unexpected else
              "Describe these required declaration fields: " + ", ".join(missing) + "." if missing else
              "All named declaration fields are present; their truth is not independently established.")
    return {"status": "FAIL" if unexpected else "UNKNOWN" if missing else "PASS", "reason": reason,
            "missing_declaration_fields": missing, "unexpected_declaration_fields": unexpected}


def assess_classification(rows: list[dict[str, Any]], registry: dict[str, KindContract],
                          discovery: dict[str, Any], *,
                          consequence_kinds: dict[str, list[str]] | None = None,
                          refutation_context: dict[str, Any] | None = None,
                          documented_applicability_answers: Sequence[dict[str, str]] = (),
                          derived_item_limit: int = MAX_DERIVED_ITEMS,
                          derived_byte_limit: int = MAX_DERIVED_BYTES) -> dict[str, Any]:
    """Derive requirements before evaluating labels: changing a label cannot prune them.

    Without a ``refutation_context`` no DOES_NOT_APPLY can be admitted, so every
    non-applicability claim keeps its kind's obligations and blocks.
    """
    documented_answers: dict[tuple[str, str], dict[str, str]] = {}
    for answer in documented_applicability_answers:
        if (
            type(answer) is not dict
            or set(answer) != {
                "reason_id", "object_id", "object_kind", "decision",
            }
            or any(type(answer[field]) is not str for field in answer)
            or answer["decision"] != "APPLIES"
        ):
            raise ValueError("NAMESPACE_DOCUMENTED_APPLICABILITY_ANSWER_INVALID")
        key = (answer["object_id"], answer["object_kind"])
        if key in documented_answers:
            raise ValueError("NAMESPACE_DOCUMENTED_APPLICABILITY_ANSWER_DUPLICATE")
        documented_answers[key] = answer

    surfaces = {row["surface_id"]: row for row in discovery["surfaces"]}
    files = {row["path"]: row["sha256"] for row in discovery["census"]["files"]}
    findings, required, objects, verdicts = [], [], [], []
    obligation_contracts: dict[str, dict[str, Any]] = {}
    derived_items = 0
    derived_bytes = 0

    def append_bounded(target: list[dict[str, Any]], item: dict[str, Any]) -> None:
        nonlocal derived_bytes
        derived_bytes += len(canonical_bytes(item))
        if derived_bytes > derived_byte_limit:
            raise ValueError("NAMESPACE_DERIVATION_OUTPUT_CAPACITY")
        target.append(item)

    def record_finding(item: dict[str, Any]) -> None:
        append_bounded(findings, item)

    # Every installed semantic kind except the deliberately generic OBJECT is
    # an applicability question.  Reviewing only additive refinements allowed
    # an AGENT, BOT, SIM, or other original kind to be labeled OBJECT and avoid
    # its higher-tier route denominator whenever no explicit marker was present.
    # Missing decisions stay UNKNOWN; current owned evidence may support a
    # bounded DOES_NOT_APPLY statement, but a label or lexical hint is never
    # promoted into semantic proof.
    review_kinds = set(registry) - {"OBJECT"}
    for row in rows:
        identifier = row["object_id"]
        owned = [surfaces[key] for key in row["surfaces"] if key in surfaces]
        owned_paths = {surface["path"] for surface in owned}
        declared = {kind for label in [row["kind"], *row["specializations"]]
                    for kind in ancestors(registry, label)}
        source = {kind for surface in owned for kind in surface["source_kinds"]}
        hints = {kind for surface in owned for kind in surface["hints"]}
        consequential = set((consequence_kinds or {}).get(identifier, []))
        effective = set(declared)
        necessary = set(declared)
        triggers: dict[str, list[str]] = {}

        def include(kind: str, trigger: str, *, is_necessary: bool) -> None:
            for ancestor in ancestors(registry, kind):
                effective.add(ancestor)
                if is_necessary:
                    necessary.add(ancestor)
                triggers.setdefault(ancestor, []).append(trigger + (
                    " Inherited through " + kind + "." if ancestor != kind else ""))

        for label in [row["kind"], *row["specializations"]]:
            include(label, "Manifest declares " + label + ".", is_necessary=True)
        decisions = []
        if not row["reason"].strip():
            record_finding(finding("NAMESPACE_OBJECT_REASON_REQUIRED", "UNKNOWN", "VSTD-T0.6",
                "This object's role has no repository-specific reason.", "Describe why these exact surfaces belong to this object.", object_id=identifier))
        if any(surface["unresolved_marker"] for surface in owned):
            record_finding(finding("NAMESPACE_SOURCE_LABEL_UNRESOLVED", "UNKNOWN", "VSTD-T0.2",
                "A source kind annotation is not a supported literal nonempty collection for its source language.",
                "Use literal kind names or supply a supported discovery adapter; the subject is never executed.", object_id=identifier))
        reviews = sorted(review_kinds | source | hints | consequential | row["classification"].keys())
        derived_items += len(reviews)
        if derived_items > derived_item_limit:
            raise ValueError("NAMESPACE_DERIVATION_CAPACITY")
        for kind in reviews:
            if kind not in registry:
                record_finding(finding("NAMESPACE_SOURCE_KIND_UNREGISTERED", "FAIL", "VSTD-T0.2",
                    "Source declares unregistered kind " + kind + ".", "Register its additive contract; do not substitute OBJECT.", object_id=identifier))
                continue
            decision = row["classification"].get(kind)
            support, reason = binding_status(decision, files, owned_paths)
            documented_answer = documented_answers.get((identifier, kind))
            reason_applies = documented_answer is not None
            if reason_applies and (
                decision is None
                or decision.get("status") not in {"UNRESOLVED", "DOES_NOT_APPLY"}
            ):
                raise ValueError("NAMESPACE_DOCUMENTED_APPLICABILITY_TARGET_NOT_ANSWERABLE")
            adopted = kind in declared or kind in source or kind in consequential or bool(decision and decision["status"] == "APPLIES")
            # Evidence-bearing UNRESOLVED is an explicit repository selection of
            # a conditional candidate.  Keep its obligations in the denominator
            # even when that evidence is stale, so freshness failure cannot erase
            # work.  This does not adopt the kind or turn uncertainty into APPLIES;
            # an empty draft entry remains inert unless another trigger selects it.
            conditional_candidate = bool(decision and decision["status"] == "UNRESOLVED"
                                         and decision["evidence"])
            # No installed closure establishes non-applicability.  A DOES_NOT_APPLY is
            # admitted as DOCUMENTED only when its reason and current owned evidence, its
            # fresh clean closure receipt and the clean owned effect audit all hold.
            # Prose, source hashes, audited review, stale, forged or unavailable
            # witnesses, and DOCUMENTED claims, never remove what a hint, source,
            # consequence or declaration already requires; unadmitted claims block PASS.
            # They do not add obligations for kinds that nothing selected, which
            # keeps the derived denominator bounded like any undetermined kind.
            # A documented APPLIES answer may conservatively supersede a compiled
            # denial for obligation retention.  The compiled decision remains in
            # the assessment row and semantic adoption remains NOT_ESTABLISHED;
            # only the unsafe subtraction and its blocker are disabled.
            non_applicable = bool(
                decision
                and decision["status"] == "DOES_NOT_APPLY"
                and not reason_applies
            )
            witness = (_non_applicability_verdict(identifier, kind, decision, owned_paths, refutation_context)
                       if non_applicable else None)
            established = witness is not None and witness.is_established and support == "PASS"
            documented = witness is not None and witness.status == DOCUMENTED and support == "PASS"
            if witness is not None and established:
                # The fresh receipt's identity fields are what admission publishes to the
                # independent reconciler; nothing here is read back from the manifest.
                verdicts.append({"object_id": identifier, "kind": kind,
                    "status": refutation.ESTABLISHED,
                    "receipt_digest": witness.receipt["receipt_digest"],
                    "closure_digest": witness.receipt["closure_digest"],
                    "decision_row_digest": witness.receipt["decision_row_digest"]})
            open_non_applicability = non_applicable and not (established or documented)
            # Only an establishment refutes a hint; a DOCUMENTED claim is never published as one.
            refuted = established and not adopted
            supported_cross_root = bool(
                decision
                and decision["status"] == "APPLIES"
                and support == "PASS"
                and registry[kind].extends is None
            )
            if kind in source:
                locations = [surface["surface_id"] for surface in owned if kind in surface["source_kinds"]]
                include(kind, "Source declares " + kind + " at "
                    + _bounded_explanation(locations, noun="source surfaces") + ".", is_necessary=True)
            if decision and decision["status"] == "APPLIES":
                include(kind, "Repository applicability declaration: " + decision["reason"], is_necessary=True)
            if kind in consequential:
                include(kind, "Declared consequence graph requires " + kind + "; simulation or generic labels cannot erase an external path.", is_necessary=True)
            if kind in hints and not refuted:
                locations = [surface["surface_id"] for surface in owned if kind in surface["hints"]]
                include(kind, "Unrefuted source hint at "
                    + _bounded_explanation(locations, noun="hint surfaces") + ".", is_necessary=False)
            if conditional_candidate:
                include(kind, "Repository selected " + kind +
                    " as an evidence-bearing unresolved applicability candidate.", is_necessary=False)
            if reason_applies:
                include(
                    kind,
                    "reasons.vstd: APPLIES; adoption/source truth remain "
                    "NOT_ESTABLISHED.",
                    is_necessary=True,
                )
            if adopted and kind not in declared and not supported_cross_root:
                record_finding(finding("NAMESPACE_LABEL_CONTRADICTS_SOURCE", "FAIL", "VSTD-T0.2",
                    kind + " is required by a source, applicability or consequence declaration but absent from this object's labels.",
                    "Use kind " + kind + " or a compatible specialization; its obligations remain required meanwhile.", object_id=identifier))
            if adopted and decision and decision["status"] == "DOES_NOT_APPLY":
                record_finding(finding("NAMESPACE_REFUTATION_CONTRADICTS_DECLARATION", "FAIL", "VSTD-T0.2",
                    "The non-applicability statement contradicts a declared " + kind + " role.",
                    "Resolve the contradiction with source evidence; a reason alone cannot override it.", object_id=identifier))
            # Every installed non-generic kind is considered, even when no name
            # hints exist. Absence of a heuristic match is not evidence of
            # absence for either an original kind or an additive refinement.
            unresolved = (
                decision is None
                or decision["status"] == "UNRESOLVED"
                or support != "PASS"
            ) and not (reason_applies and support != "FAIL")
            if witness is not None and open_non_applicability:
                record_finding(_non_applicability_finding(identifier, kind, witness, support, reason,
                                                          required=kind in effective))
            elif unresolved:
                status = "FAIL" if support == "FAIL" else "UNKNOWN"
                if decision and decision["status"] == "UNRESOLVED" and support == "PASS":
                    reason = "Current evidence is bound, but applicability has not been decided."
                record_finding(finding("NAMESPACE_CLASSIFICATION_UNRESOLVED", status, "VSTD-T0.2",
                    kind + ": " + reason, "Record APPLIES or an evidenced DOES_NOT_APPLY reason for this kind.", object_id=identifier))
            decision_result = {"kind": kind, "declared": kind in declared, "source_declared": kind in source,
                "hinted": kind in hints, "decision": decision["status"] if decision else "UNRESOLVED",
                "support_status": support,
                "non_applicability": ("EXECUTABLE_WITNESS_ESTABLISHED" if established
                                      else DOCUMENTED if documented else "NOT_ESTABLISHED"),
                "refutation_status": witness.status if witness else None,
                "refutation_code": witness.code if witness else None,
                "refutation_receipt_digest": (witness.receipt["receipt_digest"]
                                              if witness is not None and witness.receipt is not None else None),
                "semantic_classification_status": "NOT_ESTABLISHED"}
            if reason_applies:
                # The profile below defines the four omitted constants once.
                # Their absence is representational only: the compiled decision
                # remains visible, while non-applicability and source truth stay
                # NOT_ESTABLISHED.
                for field in (
                    "non_applicability",
                    "refutation_status",
                    "refutation_code",
                    "refutation_receipt_digest",
                ):
                    decision_result.pop(field)
                decision_result.update(
                    detail_profile=DOCUMENTED_APPLIES_RETENTION_PROFILE,
                    reason_decision="APPLIES",
                    reason_status="DOCUMENTED",
                    reason_id=documented_answer["reason_id"],
                )
            decisions.append(decision_result)
        obligations = requirements_for(registry, effective)
        derived_items += len(obligations) + len(effective)
        if derived_items > derived_item_limit:
            raise ValueError("NAMESPACE_DERIVATION_CAPACITY")
        expected = {obligation["id"] for obligation in obligations}
        for extra in sorted(set(row["obligations"]) - expected):
            record_finding(finding("NAMESPACE_OBLIGATION_NOT_APPLICABLE_OR_REGISTERED", "FAIL", "VSTD-T0.5",
                "The declaration includes an obligation outside the derived kind contract: " + extra,
                "Correct the exact identifier or classification; requirements cannot be self-invented.", object_id=identifier, obligation_id=extra))
        for obligation in obligations:
            contract = dict(obligation)
            previous_contract = obligation_contracts.setdefault(
                obligation["id"], contract,
            )
            if previous_contract != contract:
                raise ValueError("NAMESPACE_OBLIGATION_CONTRACT_IDENTITY_AMBIGUOUS")
            binding = row["obligations"].get(obligation["id"])
            status, reason = binding_status(binding, files, owned_paths)
            declaration = declaration_status(binding, obligation["declaration_fields"])
            if declaration["status"] == "FAIL" or (status != "FAIL" and declaration["status"] != "PASS"):
                status = declaration["status"]
            if declaration["status"] != "PASS":
                reason += " " + declaration["reason"]
            trigger_values = sorted(set(triggers[obligation["kind"]]))
            exact_applicability = " ".join(trigger_values)
            required_row = {
                "id": obligation["id"],
                "kind": obligation["kind"],
                "contract_profile": SHARED_OBLIGATION_CONTRACT_PROFILE,
                "contract_digest": value_digest(contract),
                "object_id": identifier, "applicability_reason": exact_applicability,
                "necessity": "NECESSARY" if obligation["kind"] in necessary else "CONDITIONAL_UNRESOLVED",
                "repository_reason": binding["reason"] if binding else None, "status": status,
                "declaration": binding.get("declaration", {}) if binding else {},
                "declaration_status": declaration["status"],
                "missing_declaration_fields": declaration["missing_declaration_fields"],
                "unexpected_declaration_fields": declaration["unexpected_declaration_fields"],
                "assessment_reason": reason, "semantic_fulfillment": "NOT_ESTABLISHED"}
            if binding is None:
                expected_missing = list(obligation["declaration_fields"])
                expected_assessment = (
                    "Provide a repository-specific reason and current source evidence. "
                    "Describe these required declaration fields: "
                    + ", ".join(expected_missing)
                    + "."
                )
                if (
                    status != "UNKNOWN"
                    or required_row["repository_reason"] is not None
                    or required_row["declaration"] != {}
                    or required_row["declaration_status"] != "UNKNOWN"
                    or required_row["missing_declaration_fields"] != expected_missing
                    or required_row["unexpected_declaration_fields"] != []
                    or required_row["assessment_reason"] != expected_assessment
                    or required_row["semantic_fulfillment"] != "NOT_ESTABLISHED"
                ):
                    raise ValueError("NAMESPACE_MISSING_BINDING_PROFILE_MISMATCH")
                for field in (
                    "repository_reason",
                    "declaration",
                    "declaration_status",
                    "missing_declaration_fields",
                    "unexpected_declaration_fields",
                    "assessment_reason",
                    "semantic_fulfillment",
                ):
                    required_row.pop(field)
                required_row["detail_profile"] = MISSING_OBLIGATION_BINDING_PROFILE
            if status == "PASS":
                # The manifest binding is authoritative.  Keep exact identity,
                # field names and outcomes here, while replacing only verbose
                # successful prose with a digest-bound preview.  A consumer can
                # resolve the reference without guessing an array position.
                exact_declaration = binding.get("declaration", {})
                _, applicability, applicability_digest = _trigger_summary(trigger_values)
                required_row.update(
                    detail_profile="BOUNDED_PASS_REFERENCE",
                    binding_reference={
                        "source": "objects.vstd",
                        "object_id": identifier,
                        "obligation_id": obligation["id"],
                    },
                    binding_digest=value_digest(binding),
                    contract_digest=value_digest(obligation),
                    repository_reason_digest=value_digest(binding["reason"]),
                    declaration_digest=value_digest(exact_declaration),
                    applicability_reason_digest=applicability_digest,
                    applicability_reason=applicability,
                    repository_reason=_bounded_text_summary(
                        binding["reason"],
                        limit=MAX_PASS_REASON_SUMMARY_BYTES,
                        reference="repository_reason_digest",
                    ),
                    declaration={
                        field: _bounded_text_summary(
                            value,
                            limit=MAX_PASS_DECLARATION_VALUE_SUMMARY_BYTES,
                            reference="declaration_digest",
                        )
                        for field, value in exact_declaration.items()
                    },
                )
            append_bounded(required, required_row)
            if status != "PASS":
                repair_fields = [
                    *declaration["missing_declaration_fields"],
                    *declaration["unexpected_declaration_fields"],
                ]
                next_action = (
                    "Correct the exact declaration field(s): "
                    + ", ".join(repair_fields)
                    + "; then rerun."
                    if binding is not None and repair_fields
                    else (
                        "Repair the referenced required-obligation row using its "
                        "assessment and shared obligation contract, then rerun."
                    )
                )
                unresolved_finding = finding(
                    "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED",
                    status,
                    "VSTD-T0.6",
                    (
                        "Why required: "
                        + obligation["reason"]
                        + " The referenced required-obligation assessment is unresolved; "
                        "its exact assessment and contract are retained by object_id "
                        "and obligation_id."
                    ),
                    next_action,
                    object_id=identifier,
                    obligation_id=obligation["id"],
                )
                unresolved_finding["detail_profile"] = (
                    REQUIRED_OBLIGATION_FINDING_PROFILE
                )
                record_finding(unresolved_finding)
        kind_summaries = {
            kind: _trigger_summary(values)
            for kind, values in sorted(triggers.items())
        }
        object_row = {"object_id": identifier, "declared_kinds": sorted(declared),
                        "effective_kinds": sorted(effective), "classification": decisions,
                        "necessary_kinds": sorted(necessary),
                        "kind_reasons": {kind: summary[0] for kind, summary in kind_summaries.items()},
                        "kind_reason_digests": {kind: summary[2] for kind, summary in kind_summaries.items()},
                        "required_obligation_ids": sorted(expected)}
        append_bounded(objects, object_row)
    result = {
              "detail_profiles": {
                  DOCUMENTED_APPLIES_RETENTION_PROFILE: {
                      "non_applicability": "NOT_ESTABLISHED",
                      "refutation_status": None,
                      "refutation_code": None,
                      "refutation_receipt_digest": None,
                  },
                  MISSING_OBLIGATION_BINDING_PROFILE: {
                      "repository_reason": None,
                      "declaration": {},
                      "declaration_status": "UNKNOWN",
                      "missing_declaration_fields": "obligation_contracts[id].declaration_fields",
                      "unexpected_declaration_fields": [],
                      "assessment_reason": (
                          "Provide a repository-specific reason and current source evidence. "
                          "Describe these required declaration fields: "
                          "{obligation_contracts[id].declaration_fields}."
                      ),
                      "semantic_fulfillment": "NOT_ESTABLISHED",
                  },
                  REQUIRED_OBLIGATION_FINDING_PROFILE: {
                      "assessment_reference": "required_obligations[object_id,id]",
                      "contract_reference": "obligation_contracts[id]",
                  },
              },
              "obligation_contracts": [
                  obligation_contracts[key]
                  for key in sorted(obligation_contracts)
              ],
              "objects": objects, "required_obligations": required, "findings": findings,
              "non_applicability_verdicts": sorted(verdicts, key=lambda row: (row["object_id"], row["kind"])),
              "derived_item_count": derived_items, "derived_output_bytes": 0}
    # Include the envelope itself in the byte claim.  The integer reaches a
    # fixed point after at most a few digit-width changes.
    for _ in range(4):
        materialized = len(canonical_bytes(result))
        if result["derived_output_bytes"] == materialized:
            break
        result["derived_output_bytes"] = materialized
    if len(canonical_bytes(result)) > derived_byte_limit:
        raise ValueError("NAMESPACE_DERIVATION_OUTPUT_CAPACITY")
    return result

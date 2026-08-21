"""Translation-boundary assurance: the missing dimension between "a formal
system said yes" and "the formal system was fed an honest encoding of the
real thing."

VERIFIABLE's SAT/FSM verifiers (``VFY-000001``, ``VFY-PUBLIC-000001``) and the
generic run primitive (``verifiable.core.run``) both answer "does this formal
object entail this formal claim" or "did this exact command produce this
exact output." Neither answers a third, distinct question: **when some source
artifact (a schema, a program, a spec) was translated into the formal object
that got checked, did the translation preserve every construct that matters,
or did it silently drop something?**

This module is deliberately narrow. It does NOT attempt general natural-
language-to-logic translation (out of scope per the program's epistemic
priorities). It provides:

1. A reusable, translator-agnostic record shape (:class:`TranslationUnit`,
   :class:`TranslationRecord`) for "source construct at this location mapped
   to this formal constraint, with this status" -- reusing the same
   canonical-JSON/digest machinery as ``verifiable.core.receipt`` so
   translation records compose with the existing receipt/claims ecosystem
   instead of inventing a parallel one.
2. Fail-closed aggregate status: any UNSUPPORTED or AMBIGUOUS unit whose
   construct is not explicitly marked ``trivial=True`` forces the record's
   overall status to a non-full-coverage value. A translator (or its
   caller) cannot claim full coverage by omission.
3. A concrete, empirical classification method -- **differential probing**:
   for a candidate construct, compile the formal constraint both with and
   without that construct present (holding everything else fixed) and
   compare the output. If the output is identical, the construct measurably
   had zero effect on what got checked -- i.e., it was ignored, whether or
   not the translator's documentation claims to support it. This is honest
   about what it does NOT prove: a construct that changes the output is
   merely "not a total no-op", not "translated with correct semantics."
   That gap is recorded explicitly in ``TranslationUnit.note``.

Epistemic law applied here: missing evidence of translation effect =>
UNSUPPORTED, not TRANSLATED. A translator with no readable source (e.g. a
compiled/Rust extension, as with ``outlines_core``) cannot be statically
audited -- so this module never tries to read translator source. It treats
the translator as a black box and only trusts what differential probing
against the *installed, version-recorded* binary actually shows today.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from verifiable.core.receipt import compute_canonical_digest

TRANSLATED = "TRANSLATED"
UNSUPPORTED = "UNSUPPORTED"
IGNORED = "IGNORED"
AMBIGUOUS = "AMBIGUOUS"
_VALID_STATUSES = frozenset({TRANSLATED, UNSUPPORTED, IGNORED, AMBIGUOUS})

FULL_COVERAGE = "FULL_COVERAGE"
DOWNGRADED_PARTIAL_COVERAGE = "DOWNGRADED_PARTIAL_COVERAGE"
FAIL_CLOSED_UNSUPPORTED_SEMANTICS = "FAIL_CLOSED_UNSUPPORTED_SEMANTICS"


@dataclass(frozen=True)
class TranslationUnit:
    """One source construct's fate under translation.

    ``construct``: a stable name for the source-language feature (e.g. a
    JSON Schema keyword, a source-code syntax node kind).
    ``location``: where in the source artifact it occurred (a JSON pointer,
    a file:line, whatever addressing scheme the source format supports).
    ``status``: one of TRANSLATED / UNSUPPORTED / IGNORED / AMBIGUOUS.
    ``formal_constraint``: the fragment of the formal object attributable to
    this construct, if TRANSLATED and attributable; ``None`` otherwise.
    ``trivial``: True only for constructs that are documentation/formatting
    and genuinely carry no semantic weight (e.g. a JSON Schema ``title`` or
    ``description`` field). Fail-closed logic exempts trivial constructs
    from forcing a downgrade; everything else does not get a free pass.
    ``note``: honest caveat about what evidence does/does not show.
    """

    construct: str
    location: str
    status: str
    formal_constraint: Optional[str] = None
    trivial: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid TranslationUnit status {self.status!r}, must be one of {sorted(_VALID_STATUSES)}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "construct": self.construct,
            "location": self.location,
            "status": self.status,
            "formal_constraint": self.formal_constraint,
            "trivial": self.trivial,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TranslationUnit":
        return cls(
            construct=str(d["construct"]),
            location=str(d["location"]),
            status=str(d["status"]),
            formal_constraint=d.get("formal_constraint"),
            trivial=bool(d.get("trivial", False)),
            note=str(d.get("note", "")),
        )


@dataclass
class TranslationRecord:
    """The complete, aggregate translation-boundary assurance record for one
    source-artifact -> formal-object translation event.
    """

    translator_name: str
    translator_version: str
    translator_digest: Optional[str]
    translator_digest_basis: str  # e.g. "sha256 of translator source file" or "UNAVAILABLE: compiled/opaque binary, version string only"
    source_digest: str
    units: list[TranslationUnit] = field(default_factory=list)

    def non_trivial_units(self) -> list[TranslationUnit]:
        return [u for u in self.units if not u.trivial]

    def coverage_ratio(self) -> Optional[float]:
        """TRANSLATED / non-trivial units. None if there are zero non-trivial units."""
        nt = self.non_trivial_units()
        if not nt:
            return None
        translated = sum(1 for u in nt if u.status == TRANSLATED)
        return translated / len(nt)

    def unsupported_or_ambiguous_meaningful_units(self) -> list[TranslationUnit]:
        return [u for u in self.non_trivial_units() if u.status in (UNSUPPORTED, AMBIGUOUS)]

    def overall_status(self) -> str:
        """Fail-closed aggregate. A single meaningful UNSUPPORTED/AMBIGUOUS
        unit is enough to forbid claiming full coverage -- there is no
        partial credit that rounds up to FULL_COVERAGE."""
        blocking = self.unsupported_or_ambiguous_meaningful_units()
        if not blocking:
            return FULL_COVERAGE
        # "Meaningful semantics were dropped" (fail-closed per epistemic law)
        # vs. "coverage is merely partial" both exist; distinguish only when
        # the caller wants a softer bucket, but a true UNSUPPORTED unit
        # (not AMBIGUOUS) with formal_constraint=None on a probed construct
        # is treated as the harder failure mode.
        if any(u.status == UNSUPPORTED for u in blocking):
            return FAIL_CLOSED_UNSUPPORTED_SEMANTICS
        return DOWNGRADED_PARTIAL_COVERAGE

    def to_dict(self) -> dict[str, Any]:
        return {
            "translator_name": self.translator_name,
            "translator_version": self.translator_version,
            "translator_digest": self.translator_digest,
            "translator_digest_basis": self.translator_digest_basis,
            "source_digest": self.source_digest,
            "units": [u.to_dict() for u in self.units],
            "coverage_ratio": self.coverage_ratio(),
            "overall_status": self.overall_status(),
            "unsupported_or_ambiguous_construct_count": len(self.unsupported_or_ambiguous_meaningful_units()),
            "total_units": len(self.units),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TranslationRecord":
        rec = cls(
            translator_name=str(d["translator_name"]),
            translator_version=str(d["translator_version"]),
            translator_digest=d.get("translator_digest"),
            translator_digest_basis=str(d.get("translator_digest_basis", "")),
            source_digest=str(d["source_digest"]),
            units=[TranslationUnit.from_dict(u) for u in d.get("units", [])],
        )
        return rec

    def canonical_digest(self) -> str:
        """Reuses the same canonicalization/digest machinery as VSTD-0.1
        receipts (``verifiable.core.receipt.compute_canonical_digest``)
        rather than inventing a second canonical-JSON scheme."""
        return compute_canonical_digest(self.to_dict())


def validate_translation_record(record: TranslationRecord) -> list[str]:
    """Structural + epistemic-law checks. Returns a list of error strings
    (empty list == valid). Does not raise -- callers decide what to do with
    a non-empty list (typically: fail closed)."""
    errors: list[str] = []
    if not record.translator_name:
        errors.append("translator_name is empty")
    if not record.translator_version:
        errors.append("translator_version is empty")
    if not record.translator_digest:
        # Not necessarily an error -- a compiled/opaque translator may have
        # no independently hashable artifact -- but it must say so honestly.
        if "UNAVAILABLE" not in record.translator_digest_basis.upper():
            errors.append(
                "translator_digest is missing but translator_digest_basis does not explain why "
                "(expected an 'UNAVAILABLE: ...' explanation for opaque/compiled translators)"
            )
    if not record.source_digest:
        errors.append("source_digest is empty")
    for i, u in enumerate(record.units):
        if not u.location:
            errors.append(f"unit[{i}] ({u.construct!r}) has empty location")
        if u.status == TRANSLATED and u.formal_constraint is None:
            errors.append(f"unit[{i}] ({u.construct!r}) is TRANSLATED but has no formal_constraint recorded")
    # Fail-closed consistency: overall_status must not overstate the units.
    blocking = record.unsupported_or_ambiguous_meaningful_units()
    status = record.overall_status()
    if blocking and status == FULL_COVERAGE:
        errors.append("overall_status is FULL_COVERAGE but non-trivial UNSUPPORTED/AMBIGUOUS units exist")
    if not blocking and status != FULL_COVERAGE:
        errors.append(f"overall_status is {status} but no blocking units exist")
    return errors


def differential_probe(
    construct: str,
    location: str,
    compile_fn: Callable[[Any], str],
    with_construct: Any,
    without_construct: Any,
    *,
    trivial: bool = False,
) -> TranslationUnit:
    """Classify one construct by empirically comparing the compiled formal
    output with and without it present (all else held fixed).

    - Identical output => the construct measurably had zero effect on the
      formal object that gets checked => UNSUPPORTED (fail closed: absence
      of observed effect is not evidence of correct-but-invisible handling).
    - Different output => the construct changed the compiled constraint =>
      TRANSLATED. This is NOT proof the resulting constraint is semantically
      correct -- only that the construct was not silently dropped. Recorded
      honestly in ``note``.
    - Either call raising an exception => AMBIGUOUS (the translator itself
      cannot process one of the two variants; a real coverage question, not
      a hard "unsupported", since the failure mode differs from silent drop).
    """
    try:
        out_with = compile_fn(with_construct)
    except Exception as exc:  # noqa: BLE001 - deliberately broad: any translator failure is data
        return TranslationUnit(
            construct=construct,
            location=location,
            status=AMBIGUOUS,
            formal_constraint=None,
            trivial=trivial,
            note=f"compile_fn raised on the with-construct variant: {type(exc).__name__}: {exc}",
        )
    try:
        out_without = compile_fn(without_construct)
    except Exception as exc:  # noqa: BLE001
        return TranslationUnit(
            construct=construct,
            location=location,
            status=AMBIGUOUS,
            formal_constraint=None,
            trivial=trivial,
            note=f"compile_fn raised on the without-construct baseline variant: {type(exc).__name__}: {exc}",
        )
    if out_with == out_without:
        return TranslationUnit(
            construct=construct,
            location=location,
            status=UNSUPPORTED,
            formal_constraint=None,
            trivial=trivial,
            note=(
                "Differential probe: compiled output identical with and without this construct present. "
                "The construct had zero measurable effect on the formal constraint that gets checked."
            ),
        )
    return TranslationUnit(
        construct=construct,
        location=location,
        status=TRANSLATED,
        formal_constraint=out_with,
        trivial=trivial,
        note=(
            "Differential probe: compiled output changed when this construct was present. "
            "This shows the construct was not silently dropped; it does NOT prove the resulting "
            "constraint is a semantically correct encoding of the construct's meaning."
        ),
    )


def canonical_json_digest(obj: Any) -> str:
    """Small helper for hashing an arbitrary source document (e.g. a JSON
    Schema) into ``source_digest``, using plain sorted-key JSON -- not the
    receipt payload schema, since the source document is not itself a
    receipt. Kept separate from ``compute_canonical_digest`` (VSTD-0.1
    stable-payload canonicalization) to avoid implying the source document
    conforms to that schema."""
    import hashlib

    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

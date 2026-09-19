"""Verifier Standard (VSTD) object-profile grounded certification obligations.

An X.M identifier selects obligation M within numbered profile X. It has no
physical unit and is neither a software version nor a confidence score. Existing
VSTD-4 rung identifiers and dependencies retain their exact meanings.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from importlib.resources import files
from typing import Any

from .certificate import canonical_digest
from .depth import RUNGS


@dataclass(frozen=True)
class ProfileObligation:
    """A separately checked proposition with explicit prerequisite obligations."""

    profile: int
    index: int
    name: str
    requirement: str
    depends_on: tuple[str, ...]
    source: str

    @property
    def id(self) -> str:
        return f"{self.profile}.{self.index}"

    @property
    def predicate(self) -> str:
        if self.profile == 4:
            return f"vstd4.rung.{self.id}"
        return f"vstd.obligation.{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "depends_on": list(self.depends_on),
                "id": self.id, "predicate": self.predicate}


def _rows(profile: int, rows: tuple[tuple[str, str, tuple[int, ...], str], ...]) -> tuple[ProfileObligation, ...]:
    return tuple(ProfileObligation(profile, index, name, requirement,
        tuple(f"{profile}.{d}" for d in dependencies), f"VSTD-{profile}.md {section}")
        for index, (name, requirement, dependencies, section) in enumerate(rows, 1))


OBLIGATIONS = (
    *_rows(1, (
        ("Claim coordinate", "The exact subject, proposition, scope, limitations and falsifier are bound.", (), "sections 2 and 4"),
        ("Evidence binding", "Every verdict-material evidence item is identified, available and bound to this claim.", (1,), "section 7"),
        ("Checker and trust boundary", "The actual checker implementation, dependencies and achieved role separation are evidenced without inferring independence.", (1, 2), "section 5"),
        ("Decision replay", "The declared decision follows from rerunning the bound computational checker on the bound evidence within its limits.", (2, 3), "sections 2, 3 and 5"),
        ("Provenance", "Source and execution provenance match the observed evidence and their stated observation boundary.", (2,), "section 7"),
        ("Reproduction fidelity", "The declared reproduction result and fidelity are supported by a checked comparison of the named executions.", (4, 5), "section 6"),
        ("Challenge and correction", "The falsification procedure is executable and any observed challenge or correction is retained without rewriting historical evidence.", (1, 4), "section 8"),
    )),
    *_rows(2, (
        ("Subject and surface", "The primary subject, selected surface, exclusions and coordinate meanings are explicit and bound.", (), "section 3"),
        ("Geometry consistency", "All selected coordinate references, containment relations and seams are internally consistent.", (1,), "sections 3 and 10"),
        ("Translation and reconstruction", "The named translation or reconstruction is checked against its source and exposes information loss and unresolved mappings.", (1, 2), "sections 4 and 8"),
        ("Evidence-earned judgments", "Every relied-on judgment is earned by its exact evidence and executed mechanism rather than a status label.", (1, 2), "sections 2 and 10"),
        ("Residuals and horizons", "Residuals, exclusions and horizons are typed, localized and retained in the assessed scope.", (2, 3), "sections 5 and 6"),
        ("Adjacent verification orders", "Each represented meta-verification order checks its immediate predecessor and retains its evidence and termination horizon.", (2, 4), "section 6.4"),
        ("Bounded surface closure", "The declared closure result is recomputed for the exact selected surface with every blocker preserved.", (3, 4, 5, 6), "sections 6 and 10"),
    )),
    *_rows(3, (
        ("Subject and capability boundary", "Observed devices, execution scope, capability class and unsupported capabilities match the declared substrate boundary.", (), "sections 3, 5, 6 and 7"),
        ("Attestation binding", "Every relied-on attestation binds its challenge, subject, evidence and declared trust root; absent authentication cannot support an attested claim.", (1,), "section 8"),
        ("Firmware accountability", "Firmware identity, measurement and accountability claims are checked under the declared firmware contract and capability boundary.", (1, 2), "section 9"),
        ("Execution binding", "Every claimed execution is linked to the exact workload, inputs, outputs and evidenced execution boundary.", (1, 2), "section 12"),
        ("Accounting and topology", "Reported accounting and partition/topology claims are recomputed from bound evidence with uncertainty and virtualization limits preserved.", (1, 4), "sections 13 and 14"),
        ("Continuity and anchors", "Claimed continuity and external anchors are checked for the declared interval without inferring unobserved continuity.", (2, 3, 4), "sections 10 and 11"),
        ("Provider and fleet scope", "Provider and fleet statements are checked only inside their enumerated evidence boundary; unobserved physical work remains unsupported.", (1, 4, 5), "sections 15 and 16"),
        ("Derived substrate outcome", "The substrate outcome is recomputed from the preceding obligations and capability-specific evidence without promoting an unsupported claim.", (1, 2, 3, 4, 5, 6, 7), "sections 17, 20 and 24"),
    )),
    *(ProfileObligation(4, r.index, r.name, r.requirement,
        tuple(f"4.{i}" for i in r.depends_on), "VSTD-4.md section 2") for r in RUNGS),
    *_rows(5, (
        ("Exact refutability entry", "The exact claim has evidence-bound prerequisite profiles and all fourteen VSTD-4 rungs; a candidate depth cannot admit a witness.", (), "section 1"),
        ("Witness identity binding", "Each witness identity is bound to available identity evidence; duplicate evidence and dangling identities do not create witnesses.", (1,), "sections 2 and 3"),
        ("Operational separation", "Ownership or operational control separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Implementation separation", "Separation of verdict-producing code is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Trust-root separation", "Verifier trust-root separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Evidence-source separation", "Evidence-source or telemetry-provider separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Infrastructure separation", "Separation of infrastructure capable of changing the result is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Financial separation", "Material financial dependence is checked for the exact declarant/witness pair, corroboration and claim commitment.", (2,), "section 3"),
        ("Compulsion separation", "Material jurisdictional or contractual dependence is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Executed corroboration", "Actual witness checking binds the admitted certificate, checker, class, observation time, evidence and result; declarations alone do not satisfy it.", (1, 2, 3, 4, 5, 6, 7, 8, 9), "section 4"),
        ("Disagreement preservation", "All checked disagreements and duplicate-evidence findings are retained; voting or repeated evidence cannot produce independent corroboration.", (10,), "sections 4 and 5"),
    )),
)

BY_ID = {o.id: o for o in OBLIGATIONS}
PROFILE_NAMES = {1: "Claim Mechanics", 2: "Verification Surface",
                 3: "Substrate Accountability", 4: "Refutability", 5: "Witness Corroboration"}


def obligation_catalog() -> dict[str, Any]:
    """Return the fixed object-axis catalogue; no supplied ratings or verdicts."""
    return {"schema_version": "VSTD-OBLIGATIONS-1", "axis": "OBJECT",
            "profiles": {str(p): name for p, name in PROFILE_NAMES.items()},
            "obligations": [o.to_dict() for o in OBLIGATIONS]}


def catalog_digest() -> str:
    return canonical_digest(obligation_catalog())


def specification_digest() -> str:
    """Pin installed normative bytes, without consulting a working directory."""
    import hashlib
    names = ("GROUNDED_CERTIFICATION.md", "LADDER.md", "WIRE_IDENTIFIERS.md",
             *(f"VSTD-{p}.md" for p in range(1, 6)))
    root = files("verifier.specifications")
    return canonical_digest({name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()
                             for name in names})

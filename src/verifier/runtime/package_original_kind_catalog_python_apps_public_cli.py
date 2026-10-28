"""Terminology: application programming interface (API); command-line interface (CLI); directed acyclic graph (DAG); Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).

Literal original-kind audit for imported Python-application and public-CLI rows.

The imported Python-application and public-CLI ownership declarations define
41 objects over 43 owned source paths. Every row lists all 25 original
non-OBJECT questions literally. A question is APPLIES only when the ownership
declaration or an exact owned-source quotation establishes an accumulated role.
It is DOES_NOT_APPLY only when an exact owned-source quotation positively refutes
that kind for the row, the ownership declaration pins that refutation as a root
decision, and the exact owned Python closure is CLOSED under ClosedEffectAudit.
ClosedEffectAudit supports a refutation but never creates one. The current audit
has 18 literal refutations on one exact, closed ontology owner; former negative
prose and type distinctions remain UNRESOLVED with exact blockers. Every other
question is UNRESOLVED. No complement, set difference, filename,
path, primary absence, neighboring object, operand, zero keyword hit, negative
disclaimer, or OBJECT label creates a decision.

The sealed partial profile contains only the rows with at least one decided
question, and within them only decided questions. It establishes no full package
closure, repository admission, mechanism truth, conformance, release, or
deployment. Owned source bytes are bound by SHA-256 digests, and each quotation
must occur verbatim in its owned file. Narrowing a quoted decision to UNRESOLVED
is conservative and is not detected by the row validator.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    owned_path_set_digest,
    seal_profile,
)
from verifier.runtime.package_original_kind_review import audit_closed_effects
from verifier.runtime.package_semantic_ownership_model import SemanticOwnershipSpec
from verifier.runtime.package_semantic_ownership_python_apps import (
    ONTOLOGY_EXCLUDED_ORIGINAL_KINDS,
    PYTHON_APPS_OWNERSHIP_SPECS,
    ontology_role_refutation_reason,
)
from verifier.runtime.package_semantic_ownership_public_cli import (
    PUBLIC_CLI_OWNERSHIP_SPECS,
)

UNRESOLVED = "UNRESOLVED"
PARTIAL_PROFILE_ID = "verifier-python-apps-public-cli-original-kind-review"
OBJECT_DENOMINATOR = 41
OWNED_PATH_DENOMINATOR = 43
DECIDED_ROW_DENOMINATOR = 36
APPLIES_DENOMINATOR = 49
DOES_NOT_APPLY_DENOMINATOR = 18
UNRESOLVED_DENOMINATOR = 958
REPO_ROOT = Path(__file__).resolve().parents[3]
_PREFIX = "PYTHON_APPS_PUBLIC_CLI_ORIGINAL_KIND_"
CLAIM_BOUNDARY = (
    "Exact current-source original-kind review for 41 imported Python-application "
    "and public-CLI ownership rows over 43 owned source paths. Questions without a "
    "declared role or an exact owned-source quotation remain UNRESOLVED. This "
    "partial profile proves no full package closure, repository admission, "
    "mechanism truth, conformance, release, or deployment."
)
_KIND_CRITERIA = {
    "ACTOR": "an accountable decision maker with its own control, instrument, decision-class, delegation, and attribution boundary",
    "AGENT": "an autonomous trajectory whose decisions and claims are bounded by one governing harness",
    "ARCH": "a computational architecture with layer, dependency, and tensor-shape semantics",
    "BENCH": "a finite evaluation benchmark with problems, oracles, scoring, coverage, and budgets",
    "BOT": "one situated closed loop binding an agent, simulation, observations, actions, and execution envelopes",
    "COLLECTIVE": "an organized group with role graph, membership, quorum, and collective-decision semantics",
    "DATA": "a dataset whose content, schema, partitions, lineage, and immutability are the represented subject",
    "ENV": "an execution environment whose software, dependencies, configuration, resources, and reproduction boundary are represented",
    "EVENT": "a represented spatiotemporal occurrence binding time, space, action, and payload",
    "GRAPH": "a collection whose vertices, edges, ordering, lineage, and closure are the represented subject",
    "HARDWARE": "an execution substrate or device inventory with topology, capacity, allocation, and observation envelopes",
    "HARNESS": "an execution scaffold whose instrumented channels, declared gaps, tools, effects, and transcript are the represented subject",
    "HUMAN": "a living-person and human-accountability termination root",
    "HYPER": "a composite entity whose directed operands, dependency cone, ceiling, and absorption rules are represented",
    "IDENTITY": "a bearer-to-role binding with occupancy, scope, presentation, and lifecycle semantics",
    "MODEL": "trained parameter artifacts with architecture binding, forward execution, evaluation, and challenge semantics",
    "OWNER": "an ownership relation linking an actor to held objects, rights, duties, and accountability",
    "RECEIPT": "a portable evidence record binding a subject, execution, prerequisites, and replay",
    "ROLE": "an authority-bearing role class with bearer eligibility, occupancy, permissions, and lifecycle",
    "SIM": "a generative simulation with state, transitions, channels, model-relative causality, and isolation boundary",
    "SPACE": "a spatial, network, or storage coordinate domain with layout and migration semantics",
    "TIME": "a temporal interval, sequence, clock, or epoch coordinate with ordering semantics",
    "TOKEN": "a cryptographic or computational token holding with issuance-key, scope, tenure, lease, and status semantics",
    "TRAIN": "a training run with configuration, checkpoints, batches, optimization, updates, and replay",
    "VERIFIER": "a checking mechanism with exact identity, decision procedure, execution rules, and bounded replay",
}


# Exact blockers for decisions withdrawn to UNRESOLVED. Each names the quotation or
# closure defect that prevented the decision; no other reason text is accepted.
_DOWNGRADE_BLOCKERS = {
    ("vstd-model-reproducibility-profile", "MODEL"): "The quoted 'MODEL:' label describes an abstract risk-profile surface, a lexical match rather than a trained parameter artifact; the ownership declaration states that retained data does not establish the behavior of a MODEL artifact.",
    ("vstd-environment-synthetic-specimens", "BENCH"): "The quoted sentence is a disclaimer ('not learned-model inference or a capability benchmark'), not a positive benchmark identity; the ClosedEffectAudit of specimens.py is UNKNOWN because call targets such as environment.step and imported effects escape the owned set.",
    ("vstd-environment-synthetic-specimens", "MODEL"): "The quoted scripted reference model is a positive identity of the synthetic reference only; the ClosedEffectAudit of specimens.py is UNKNOWN because call targets such as environment.step and imported effects escape the owned set, so no refutation may be recorded.",
    ("vstd-operator-stop-authentication", "HUMAN"): "The quoted sentence is a negative statement about what the module does not do; the ClosedEffectAudit of operator_stop.py is UNKNOWN because signature-verification and dynamic call targets are unresolved and imports escape the owned set.",
    ("vstd-consent-stage-verifier", "HUMAN"): "The quoted 'authenticate clocks, or establish voluntary human consent.' clause is a negative disclaimer about what the predicates do not establish, not a positive living-person or human-accountability identity; the ClosedEffectAudit of stages.py is UNKNOWN because call targets such as verifier.consent.engine._digest and injected callables such as check remain unresolved and imports escape ownership to verifier.consent.engine and verifier.consent.public.",
    ("vstd-training-control-profile", "MODEL"): "The quoted 'TRAIN means an optimization procedure; MODEL means an optimized artifact.' sentence is a type distinction that names a kind, not a refutation of MODEL for this row; the ClosedEffectAudit of train_profile.py is UNKNOWN because getattr dynamic execution and injected callables are unresolved and imports escape ownership to verifier.core.certificate, verifier.core.namespace, and verifier.domains.common.",
    ("vstd-training-control-profile", "TRAIN"): "The quoted 'independent of numerical training' clause is a disclaimer, not a positive identity; the ClosedEffectAudit of train_profile.py is UNKNOWN because getattr dynamic execution is unresolved and imports escape ownership to verifier.core and verifier.domains.",
}


@dataclass(frozen=True)
class OwnedSourceQuote:
    """One exact owned-source quotation that directly decides one kind for one row."""

    path: str
    quote: str


@dataclass(frozen=True)
class PythonAppsPublicCliQuestion:
    """One literal applicability answer; source is set only for quoted decisions."""

    kind: str
    status: str
    reason: str
    source: OwnedSourceQuote | None


@dataclass(frozen=True)
class PythonAppsPublicCliAudit:
    """One exact source coordinate, its owned file bytes, and 25 literal questions."""

    group: str
    object_id: str
    expected_primary: str
    expected_owned_paths: tuple[str, ...]
    expected_owned_path_set_digest: str
    expected_owned_file_digests: tuple[tuple[str, str], ...]
    expected_representation_role: str
    expected_necessity_reason: str
    expected_consequence_boundary: str
    expected_specializations: tuple[str, ...]
    expected_operands: tuple[tuple[str, tuple[str, ...]], ...]
    expected_root_role_decisions: tuple[tuple[str, str, str], ...]
    expected_source_coordinate_digest: str
    scope_reason: str
    questions: tuple[PythonAppsPublicCliQuestion, ...]


def _canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _bytes_digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _source_coordinate_digest(
    object_id: str,
    primary: str,
    paths: tuple[str, ...],
    representation_role: str,
    necessity_reason: str,
    consequence_boundary: str,
    specializations: tuple[str, ...],
    operands: tuple[tuple[str, tuple[str, ...]], ...],
    root_role_decisions: tuple[tuple[str, str, str], ...],
) -> str:
    return _canonical_digest(
        {
            "object_id": object_id,
            "primary": primary,
            "owned_paths": list(paths),
            "representation_role": representation_role,
            "necessity_reason": necessity_reason,
            "consequence_boundary": consequence_boundary,
            "specializations": list(specializations),
            "operands": [[name, list(targets)] for name, targets in operands],
            "root_role_decisions": [
                [kind, status, reason] for kind, status, reason in root_role_decisions
            ],
        }
    )


def _question(
    kind: str,
    status: str,
    path: str = "",
    quote: str = "",
) -> tuple[str, str, str, str]:
    """Name one question literally; no caller-side default is ever a decision."""

    return kind, status, path, quote


def _ontology_refutation_question(kind: str) -> tuple[str, str, str, str]:
    """Bind one negative cell to its literal entry in the owned role table."""

    if kind not in ONTOLOGY_EXCLUDED_ORIGINAL_KINDS:
        raise AssertionError("ontology refutation kind is not declared")
    return _question(
        kind,
        DOES_NOT_APPLY,
        "src/verifier/corrigibility/ontology.py",
        '("' + kind + '", "DOES_NOT_APPLY"),',
    )


_ONTOLOGY_SIM_ROOT_REASON = (
    "Owned source ontology.py states 'Formalizes the situated intelligence "
    "definition: BOT = AGENT + SIM.', so the accumulated BOT formula makes SIM "
    "a constituent role of this row; the record defines that composition, "
    "executes no simulation, and carries no physical or financial consequence."
)
_ONTOLOGY_ROOT_ROLE_DECISIONS = tuple(sorted((
    *(
        (kind, DOES_NOT_APPLY, ontology_role_refutation_reason(kind))
        for kind in ONTOLOGY_EXCLUDED_ORIGINAL_KINDS
    ),
    ("SIM", APPLIES, _ONTOLOGY_SIM_ROOT_REASON),
)))


def audit_row(
    group: str,
    object_id: str,
    expected_primary: str,
    expected_owned_paths: tuple[str, ...],
    expected_owned_file_digests: tuple[tuple[str, str], ...],
    representation_role: str,
    necessity_reason: str,
    consequence_boundary: str,
    expected_specializations: tuple[str, ...],
    expected_operands: tuple[tuple[str, tuple[str, ...]], ...],
    selections: tuple[tuple[str, str, str, str], ...],
    root_role_decisions: tuple[tuple[str, str, str], ...] = (),
) -> PythonAppsPublicCliAudit:
    """Build one row only from literal selections; omissions and unbound evidence fail."""

    paths = tuple(expected_owned_paths)
    if tuple(kind for kind, _status, _path, _quote in selections) != (
        ORIGINAL_NON_OBJECT_KINDS
    ):
        raise AssertionError(object_id + " original-kind question order differs")
    if tuple(path for path, _digest in expected_owned_file_digests) != paths:
        raise AssertionError(object_id + " owned file digest inventory differs")
    # A feature-near root decision is accepted only when this exact row audits the
    # same kind with the same status and an owned-source quotation.
    audited = {kind: (status, path) for kind, status, path, _quote in selections}
    for kind, status, _reason in root_role_decisions:
        if (
            kind not in ORIGINAL_NON_OBJECT_KINDS
            or audited[kind][0] != status
            or audited[kind][1] not in paths
        ):
            raise AssertionError(object_id + ":" + kind + " root role decision is not audited")
    if tuple(sorted(root_role_decisions)) != tuple(root_role_decisions):
        raise AssertionError(object_id + " root role decisions are not kind-sorted")
    scope_reason = (
        representation_role
        + " Necessity: "
        + necessity_reason
        + " Consequence boundary: "
        + consequence_boundary
    )
    questions = []
    for kind, status, path, quote in selections:
        if status not in {APPLIES, DOES_NOT_APPLY, UNRESOLVED}:
            raise AssertionError(object_id + ":" + kind + " contains an invalid status")
        if status == UNRESOLVED:
            if path or quote:
                raise AssertionError(object_id + ":" + kind + " unresolved item carries evidence")
            blocker = _DOWNGRADE_BLOCKERS.get((object_id, kind), "")
            reason = (
                scope_reason
                + " No declared role or exact owned-source quotation establishes or "
                  "positively refutes whether this exact row itself is "
                + _KIND_CRITERIA[kind]
                + ". Operands, inputs, outputs, and neighboring objects are not role "
                  "equivalence, so "
                + kind
                + " remains UNRESOLVED."
                + (" Exact blocker: " + blocker if blocker else "")
            )
            source = None
        elif status == APPLIES and not path:
            if quote:
                raise AssertionError(object_id + ":" + kind + " declared role carries quotation")
            reason = (
                scope_reason
                + " The source-owned ownership declaration explicitly establishes "
                + kind
                + " as this row's original primary or accumulated role. This "
                  "establishes applicability only, not mechanism truth or "
                  "higher-tier conformance."
            )
            source = None
        else:
            if path not in paths or not quote.strip():
                raise AssertionError(object_id + ":" + kind + " decided item lacks an owned-source quotation")
            source = OwnedSourceQuote(path, quote)
            if status == APPLIES:
                reason = (
                    scope_reason
                    + " Owned source "
                    + path
                    + " directly states '" + quote + "', which establishes "
                    + kind
                    + " as this row's accumulated represented role: "
                    + _KIND_CRITERIA[kind]
                    + ". This establishes applicability only, not mechanism truth or "
                      "higher-tier conformance."
                )
            else:
                reason = (
                    scope_reason
                    + " Owned source "
                    + path
                    + " directly states '" + quote + "', which positively refutes "
                    + kind
                    + " as this row's represented role: "
                    + _KIND_CRITERIA[kind]
                    + ". This refutes only the named kind for this exact row."
                )
        questions.append(PythonAppsPublicCliQuestion(kind, status, reason, source))
    return PythonAppsPublicCliAudit(
        group=group,
        object_id=object_id,
        expected_primary=expected_primary,
        expected_owned_paths=paths,
        expected_owned_path_set_digest=owned_path_set_digest(paths),
        expected_owned_file_digests=tuple(expected_owned_file_digests),
        expected_representation_role=representation_role,
        expected_necessity_reason=necessity_reason,
        expected_consequence_boundary=consequence_boundary,
        expected_specializations=tuple(expected_specializations),
        expected_operands=tuple(expected_operands),
        expected_root_role_decisions=tuple(root_role_decisions),
        expected_source_coordinate_digest=_source_coordinate_digest(
            object_id,
            expected_primary,
            paths,
            representation_role,
            necessity_reason,
            consequence_boundary,
            tuple(expected_specializations),
            tuple(expected_operands),
            tuple(root_role_decisions),
        ),
        scope_reason=scope_reason,
        questions=tuple(questions),
    )


PYTHON_APPS_PUBLIC_CLI_AUDITS = (
    # vstd-agent-bot-ontology-architecture: src/verifier/corrigibility/ontology.py
    audit_row(
        "imported-python-apps",
        "vstd-agent-bot-ontology-architecture",
        "ARCH",
        ("src/verifier/corrigibility/ontology.py",),
        (
            ("src/verifier/corrigibility/ontology.py", "sha256:8b8d5bb5fc4cb0fe5f8e39dd466b664d19a635925edfccf9de94c2a160c80634"),
        ),
        "Computational SPACE, TIME, EVENT, AGENT, and BOT ontology record architecture.",
        "Ontology composition applies explicit classification policy to inert structural records and must not inherit behavioral roles from the names it represents.",
        "The records execute no AGENT or BOT, create no confinement, and establish no ROBOT, FINBOT, physical, or financial consequence.",
        ("POLICY",),
        (
        ),
        (
            _ontology_refutation_question("ACTOR"),
            _question(
                "AGENT",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Formalizes the ontological definition: AGENT = MODEL + HARNESS.",
            ),
            _question("ARCH", APPLIES),
            _ontology_refutation_question("BENCH"),
            _question(
                "BOT",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Formalizes the situated intelligence definition: BOT = AGENT + SIM.",
            ),
            _ontology_refutation_question("COLLECTIVE"),
            _ontology_refutation_question("DATA"),
            _ontology_refutation_question("ENV"),
            _question(
                "EVENT",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Ontological foundation: SPACE, TIME, and EVENT computational object classes and the Model-Harness-Agent / Bot triad.",
            ),
            _ontology_refutation_question("GRAPH"),
            _ontology_refutation_question("HARDWARE"),
            _ontology_refutation_question("HARNESS"),
            _ontology_refutation_question("HUMAN"),
            _ontology_refutation_question("HYPER"),
            _ontology_refutation_question("IDENTITY"),
            _ontology_refutation_question("MODEL"),
            _ontology_refutation_question("OWNER"),
            _ontology_refutation_question("RECEIPT"),
            _ontology_refutation_question("ROLE"),
            _question(
                "SIM",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Formalizes the situated intelligence definition: BOT = AGENT + SIM.",
            ),
            _question(
                "SPACE",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Ontological foundation: SPACE, TIME, and EVENT computational object classes and the Model-Harness-Agent / Bot triad.",
            ),
            _question(
                "TIME",
                APPLIES,
                "src/verifier/corrigibility/ontology.py",
                "Ontological foundation: SPACE, TIME, and EVENT computational object classes and the Model-Harness-Agent / Bot triad.",
            ),
            _ontology_refutation_question("TOKEN"),
            _ontology_refutation_question("TRAIN"),
            _ontology_refutation_question("VERIFIER"),
        ),
        root_role_decisions=_ONTOLOGY_ROOT_ROLE_DECISIONS,
    ),
    # vstd-benchmark-suite-verifier: src/verifier/corrigibility/benchmark.py
    audit_row(
        "imported-python-apps",
        "vstd-benchmark-suite-verifier",
        "VERIFIER",
        ("src/verifier/corrigibility/benchmark.py",),
        (
            ("src/verifier/corrigibility/benchmark.py", "sha256:0e2a76199854220174f073363ec720543b16e9dd2acfacf7152fbaf83076ee71"),
        ),
        "Refutable benchmark specifications, score provenance, and non-gaming checks over supplied records.",
        "Benchmark acceptance derives bounded measurements under explicit scoring and integrity policy.",
        "Supplied benchmark records and arithmetic do not execute a workload, authenticate provenance, or establish real capability or safety.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question(
                "BENCH",
                APPLIES,
                "src/verifier/corrigibility/benchmark.py",
                "BENCH: Refutable benchmark specifications, score provenance, and non-gaming invariants.",
            ),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-capability-reward-lock: src/verifier/corrigibility/reward_lock.py
    audit_row(
        "imported-python-apps",
        "vstd-capability-reward-lock",
        "HARNESS",
        ("src/verifier/corrigibility/reward_lock.py",),
        (
            ("src/verifier/corrigibility/reward_lock.py", "sha256:b78c2cb487a0fd9008d599c143dc9e4dd6c10914d95033beecd55efe19422daa"),
        ),
        "Composite reward-lock and computation-proof thaw harness over supplied records.",
        "Lock and thaw evaluation derives bounded measurements under explicit composition and acceptance policy.",
        "Hash and predicate evaluation does not execute training, constrain a live model, hold a real secret, or actuate an external system.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", APPLIES),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-consent-package-api: src/verifier/consent/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-consent-package-api",
        "ARCH",
        ("src/verifier/consent/__init__.py",),
        (
            ("src/verifier/consent/__init__.py", "sha256:f4d2c8f25b6bbb2179aecff2c3b94c7e42f952f9fffad5c6da54c936e59257e7"),
        ),
        "Consent namespace export architecture.",
        "The consent package's public names need an exact source owner distinct from the mechanisms they expose.",
        "Import and export representation alone performs no consent evaluation, authentication, enforcement, or computational-verdict change.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-consent-stage-verifier: src/verifier/consent/stages.py
    audit_row(
        "imported-python-apps",
        "vstd-consent-stage-verifier",
        "VERIFIER",
        ("src/verifier/consent/stages.py",),
        (
            ("src/verifier/consent/stages.py", "sha256:a3438cd6599468df223258ef3a132b18980626318a22ea7d7a6af69af740f68f"),
        ),
        "Bounded staged-consent predicates, authenticated receipt composition, and retained reproduction.",
        "Consent-stage decisions consume selected records and mechanism bytes under explicit policy and protocol rules that generic verification would hide.",
        "The checks do not establish all required holders, authenticate clocks, prove voluntary human consent, or change the underlying computational verdict.",
        ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-corrigibility-containment-contracts: src/verifier/corrigibility/contracts.py
    audit_row(
        "imported-python-apps",
        "vstd-corrigibility-containment-contracts",
        "HARNESS",
        ("src/verifier/corrigibility/contracts.py",),
        (
            ("src/verifier/corrigibility/contracts.py", "sha256:64f0dc78cf9af410cb6498f5b3bcf7e73ea7565124fafdbed4e6f9d0405f9c7b"),
        ),
        "Executable corrigibility contract and invariant harness over supplied state.",
        "Containment and shutdown invariants define a bounded protocol and decision policy distinct from an executing sandbox.",
        "Contract evaluation does not confine a process, deliver a signal, control hardware, or establish corrigibility of a running system.",
        ("POLICY", "PROTOCOL"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", APPLIES),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-corrigibility-environment-profile: src/verifier/corrigibility/environment.py
    audit_row(
        "imported-python-apps",
        "vstd-corrigibility-environment-profile",
        "ENV",
        ("src/verifier/corrigibility/environment.py",),
        (
            ("src/verifier/corrigibility/environment.py", "sha256:a58111db407edb2e5f99cacb84f473bae389cbd29ec53ce8e1b9ace59a92ea11"),
        ),
        "Declared hardware and software substrate profile with isolation and execution-bound checks.",
        "Environment declarations carry measurable resource and isolation claims governed by explicit acceptance policy.",
        "Supplied profile records do not inspect a live host, create isolation, enforce limits, or attest execution occurrence.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", APPLIES),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question(
                "HARDWARE",
                APPLIES,
                "src/verifier/corrigibility/environment.py",
                "Hardware capability profile and accelerator device identity.",
            ),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
        root_role_decisions=(
            ("HARDWARE", APPLIES, "Owned source environment.py declares 'Hardware capability profile and accelerator device identity.' for its HardwareSubstrate, so the declared substrate profile embodies a HARDWARE device-inventory role with capacity and accelerator envelopes; declared capability is not an inspected live device."),
        ),
    ),
    # vstd-corrigibility-package-api: src/verifier/corrigibility/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-corrigibility-package-api",
        "ARCH",
        ("src/verifier/corrigibility/__init__.py",),
        (
            ("src/verifier/corrigibility/__init__.py", "sha256:d8929f1021010f35924ebfc3469d723eda24f823a8e0eab20766af16c1ccec36"),
        ),
        "Corrigibility namespace export architecture.",
        "The namespace aggregates distinct records and mechanisms and therefore needs a public-surface owner separate from their behavioral owners.",
        "Export reachability establishes no model, agent, bot, training, containment, or shutdown behavior.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-corrigibility-provenance-ledger: src/verifier/corrigibility/graph.py
    audit_row(
        "imported-python-apps",
        "vstd-corrigibility-provenance-ledger",
        "LEDGER",
        ("src/verifier/corrigibility/graph.py",),
        (
            ("src/verifier/corrigibility/graph.py", "sha256:545ff5baee2b67249bef9aaa9167ce9cb2cabe40604904497b85852a1e6793d6"),
        ),
        "In-memory computational provenance DAG with lineage and causal-consistency rules.",
        "Ordered node and edge additions rely on correction, duplication, and acyclicity policy and therefore require explicit ledger and transaction roles.",
        "The in-memory DAG is not durable or externally witnessed authoritative history and does not prove runtime causality or provenance truth.",
        ("POLICY", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question(
                "GRAPH",
                APPLIES,
                "src/verifier/corrigibility/graph.py",
                "GRAPH: Directed acyclic graphs of computational provenance, dependencies, and causal proof lineages.",
            ),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-corrigibility-risk-assessor: src/verifier/corrigibility/risk_profile.py
    audit_row(
        "imported-python-apps",
        "vstd-corrigibility-risk-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/risk_profile.py",),
        (
            ("src/verifier/corrigibility/risk_profile.py", "sha256:e14d404b2e346fdc0259e7b959bffccc2f1e2137ef9d87b6ffba81c392aa130a"),
        ),
        "Aggregate corrigibility risk-profile assessor over selected supplied records.",
        "Cross-surface risk conclusions combine finite measurements under explicit aggregation and fail-closed policy.",
        "Aggregation does not independently acquire evidence, run a model or agent, test a sandbox, or establish whole-system corrigibility.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-data-package-api: src/verifier/data/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-data-package-api",
        "ARCH",
        ("src/verifier/data/__init__.py",),
        (
            ("src/verifier/data/__init__.py", "sha256:eb324193f705579b9b241a91b39096d4c06e16d5e4d1ff74e51113b29ae9c69c"),
        ),
        "GRAPH data namespace export architecture.",
        "The data package aggregates record, policy, assurance, and receipt surfaces that require a distinct public namespace owner.",
        "Export reachability performs no graph assessment, evidence acquisition, receipt publication, or mechanism execution.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-data-receipt-lifecycle: src/verifier/data/receipt.py
    audit_row(
        "imported-python-apps",
        "vstd-data-receipt-lifecycle",
        "RECEIPT",
        ("src/verifier/data/receipt.py",),
        (
            ("src/verifier/data/receipt.py", "sha256:544340749cbc3d3fb10929ce8b2e6a51d5585e7a49e9eaabd1132378f00af321"),
        ),
        "GRAPH receipt construction, local artifact publication, validation, and reproduction lifecycle.",
        "The receipt binds a data subject and hardware context while observing and mutating a selected local output directory under explicit policy.",
        "Publication is a non-atomic local multi-file write without external witness or durable truth; it proves neither source claims nor financial or physical effects.",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
            ("hardware", ("vstd-hardware",)),
            ("subject", ("vstd-data",)),
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", APPLIES),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-environment-assessor: src/verifier/environments/assessment.py
    audit_row(
        "imported-python-apps",
        "vstd-environment-assessor",
        "VERIFIER",
        ("src/verifier/environments/assessment.py",),
        (
            ("src/verifier/environments/assessment.py", "sha256:46a8ad37d5786e438901169ba6c092976236d16f247d3c0ecde1d45d3941f114"),
        ),
        "Declared-environment assessment and selected registered-mechanism evaluation.",
        "Explicit evaluation observes evidence and invokes existing verification mechanisms in a bounded policy-governed transaction.",
        "Inspection never executes the environment itself; evaluation establishes neither runtime occurrence, enforcement, actor independence, nor numbered-profile conformance.",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-environment-integration-projection: src/verifier/environments/integration.py
    audit_row(
        "imported-python-apps",
        "vstd-environment-integration-projection",
        "ARCH",
        ("src/verifier/environments/integration.py",),
        (
            ("src/verifier/environments/integration.py", "sha256:42fc8f9cbbac619e53a083ad77ed9ea77cf796d1dcde2627aae87d0e191b5b98"),
        ),
        "Nonexecuting environment catalog, geometry, relation, workload, and package projections.",
        "Cross-package environment representations apply explicit projection and binding policy and need an architecture owner.",
        "Projection and packaging of supplied records confer no verdict, execution permission, runtime occurrence, or enforcement.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-environment-record-contracts: src/verifier/environments/contracts.py
    audit_row(
        "imported-python-apps",
        "vstd-environment-record-contracts",
        "ENV",
        ("src/verifier/environments/contracts.py",),
        (
            ("src/verifier/environments/contracts.py", "sha256:d91dc699506f10499eb7c5c6d513dc3d4648daeef5b697c8b094f3bfc0be1fc0"),
        ),
        "Bounded environment definition, instance, mechanism, component, connection, and run records.",
        "Environment records declare capability and boundary policy that must remain distinct from runtime enforcement.",
        "Canonical records do not execute an environment, enforce isolation, authenticate occurrence, or satisfy a numbered profile.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", APPLIES),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-environment-specimen-checker: src/verifier/environments/specimen_checks.py
    audit_row(
        "imported-python-apps",
        "vstd-environment-specimen-checker",
        "VERIFIER",
        ("src/verifier/environments/specimen_checks.py",),
        (
            ("src/verifier/environments/specimen_checks.py", "sha256:e6a7655156b25f59565409e178b4caa62462842a084b6b2661c062aa88aacbde"),
        ),
        "Independent bounded checker for exact synthetic environment fixture bytes.",
        "Fixture evaluation observes selected bytes and applies explicit comparison and decision policy.",
        "The checker imports no producer and executes no submitted implementation; fixtures prove neither model performance, physical simulation validity, nor independent actors.",
        ("MEASUREMENT", "POLICY", "SENSOR"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-environment-synthetic-specimens: src/verifier/environments/specimens.py
    audit_row(
        "imported-python-apps",
        "vstd-environment-synthetic-specimens",
        "HARNESS",
        ("src/verifier/environments/specimens.py",),
        (
            ("src/verifier/environments/specimens.py", "sha256:d499ea71a6f8a231994e93262a606c7e41220953fff9b1f5f23ee58b93b76046"),
        ),
        "Synthetic in-process environment, scripted reference model, packaging, and evaluation harness.",
        "The specimen changes finite in-memory state, retains selected bytes, and invokes registered checks through explicit control and transaction policy.",
        "It is synthetic and unsandboxed, not learned-model inference, a capability benchmark, an independent witness, a BOT, ROBOT, FINBOT, or physical or financial system.",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question(
                "ENV",
                APPLIES,
                "src/verifier/environments/specimens.py",
                "Runnable, synthetic environment specimens for Verifier Standard (VSTD).",
            ),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", APPLIES),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
        root_role_decisions=(
            ("ENV", APPLIES, "Owned source specimens.py declares 'Runnable, synthetic environment specimens for Verifier Standard (VSTD).', so the row represents an execution environment with in-process software, configuration, and reproduction boundary; it is synthetic and unsandboxed and establishes no physical or financial environment."),
        ),
    ),
    # vstd-environments-package-api: src/verifier/environments/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-environments-package-api",
        "ARCH",
        ("src/verifier/environments/__init__.py",),
        (
            ("src/verifier/environments/__init__.py", "sha256:abe86a2d96a8c94f6a7d14f8165e587ffb6e01648d2202813c186cb4d82996b8"),
        ),
        "Experimental environment namespace export architecture.",
        "The namespace exposes contracts, projections, and assessments with materially different consequences and needs an exact public owner.",
        "Direct imports are experimental; exports do not execute submitted environment implementations or establish support or conformance.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-experimental-workflow-package-api: src/verifier/experimental_workflow/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-experimental-workflow-package-api",
        "ARCH",
        ("src/verifier/experimental_workflow/__init__.py",),
        (
            ("src/verifier/experimental_workflow/__init__.py", "sha256:64c8cca74260dfdff96d387ddd2307f6ca4c65eb3695da74671ba18f3fdecbaf"),
        ),
        "Experimental workflow namespace export architecture.",
        "The non-normative workflow profile, schema, and adapter need one exact public-surface owner separate from their implementations.",
        "Exports remain non-normative and verdict-neutral and execute no workflow or platform operation.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-experimental-workflow-profile: src/verifier/experimental_workflow/profile.py, src/verifier/experimental_workflow/schema.py
    audit_row(
        "imported-python-apps",
        "vstd-experimental-workflow-profile",
        "VERIFIER",
        ("src/verifier/experimental_workflow/profile.py", "src/verifier/experimental_workflow/schema.py"),
        (
            ("src/verifier/experimental_workflow/profile.py", "sha256:b589aa99a59ae8f24ba333fd363e8f13ed1bfc2e27a58ba10f41f081ef6e68d8"),
            ("src/verifier/experimental_workflow/schema.py", "sha256:bea43e83599fc772578ce7dc8a906bbc958c66ebe86d471621895cb4ec6aa353"),
        ),
        "Non-normative workflow manifest schema, validation, digesting, and selected repository-artifact observation.",
        "Profile validation and artifact comparison derive bounded measurements from supplied records and selected local bytes under explicit policy.",
        "The profile does not execute domain verifiers, derive VSTD verdicts, run workflow actions, or treat repository state as verification.",
        ("MEASUREMENT", "POLICY", "SENSOR"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-github-snapshot-event-adapter: src/verifier/experimental_workflow/github.py
    audit_row(
        "imported-python-apps",
        "vstd-github-snapshot-event-adapter",
        "VERIFIER",
        ("src/verifier/experimental_workflow/github.py",),
        (
            ("src/verifier/experimental_workflow/github.py", "sha256:90ed147b74961f38d1f4d2991d7c2373cd20f3b1de53bd30fc56e1872cd3567c"),
        ),
        "Deterministic supplied GitHub-snapshot to workflow-event adapter.",
        "Snapshot normalization applies an exact field and event-classification policy that warrants bounded verification ownership.",
        "The adapter performs no GitHub API call or live observation and does not authenticate, upgrade, or execute the supplied platform events.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-graph-level-verifier: src/verifier/data/graph_level.py
    audit_row(
        "imported-python-apps",
        "vstd-graph-level-verifier",
        "VERIFIER",
        ("src/verifier/data/graph_level.py",),
        (
            ("src/verifier/data/graph_level.py", "sha256:b79f9f9f21c95e7e06934be1f137d848233549f5dcbf3478c8d07b002177449d"),
        ),
        "Evidence-bound graph-level encoding, independent decision checks, and registered-mechanism evaluation.",
        "Graph-level establishment observes selected evidence and invokes registered mechanisms through a bounded policy-governed transaction.",
        "The candidate level depends on caller-supplied ratings and selected mechanisms; it is not a sandbox, universal graph proof, or automatic object conformance.",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question(
                "GRAPH",
                APPLIES,
                "src/verifier/data/graph_level.py",
                "graph_level(C) = max { N : CNF_N(C) is satisfiable }",
            ),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
        root_role_decisions=(
            ("GRAPH", APPLIES, "Owned source graph_level.py defines 'graph_level(C) = max { N : CNF_N(C) is satisfiable }' over a collection C with membership, provenance-closure, and edge-evidence conditions, so the collection is the represented subject and GRAPH accumulates; the candidate level uses caller-supplied ratings and is not conformance."),
        ),
    ),
    # vstd-identity-adversarial-audit: src/verifier/identity/audit.py
    audit_row(
        "imported-python-apps",
        "vstd-identity-adversarial-audit",
        "HARNESS",
        ("src/verifier/identity/audit.py",),
        (
            ("src/verifier/identity/audit.py", "sha256:85a49994476b36b515f82108f1a8989efe15ebfd4c7d4be5926210249d232b1f"),
        ),
        "In-process adversarial identity-slippage fixture harness.",
        "The fixed attack battery measures evaluator behavior under explicit loophole-detection policy.",
        "Passing synthetic cases is not adversarial completeness, independent evidence, sandboxing, live identity verification, or authority.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", APPLIES),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-identity-package-api: src/verifier/identity/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-identity-package-api",
        "ARCH",
        ("src/verifier/identity/__init__.py",),
        (
            ("src/verifier/identity/__init__.py", "sha256:43d20037e43a498048dbc035b640d5a371c19eb5f7aad6ce006c2850eb490144"),
        ),
        "Zero-identity token and offline-evaluation namespace architecture.",
        "The identity namespace exports records, policy, evaluation, and audit surfaces and needs an exact public owner.",
        "Export reachability establishes no actor identity, authentication, authority, liveness, or network observation.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-identity-policy-evaluator: src/verifier/identity/evaluator.py, src/verifier/identity/invariants.py
    audit_row(
        "imported-python-apps",
        "vstd-identity-policy-evaluator",
        "VERIFIER",
        ("src/verifier/identity/evaluator.py", "src/verifier/identity/invariants.py"),
        (
            ("src/verifier/identity/evaluator.py", "sha256:721305e06bc16f02c2fb1e79a28ea652189ec64a2b59685dadb222c24e7d91ce"),
            ("src/verifier/identity/invariants.py", "sha256:c2ba39057392ac1830fffb1b1f29ccf2f3a9845e5a4f6d28ec2888b9439c21d1"),
        ),
        "Offline identity-token evaluator with normative verdict and prohibited-inference policy.",
        "The evaluator observes supplied token fields and derives bounded property measurements under explicit fail-closed identity policy.",
        "Offline evaluation discovers no actor, authenticates no person or clock, grants no authority, and performs no network or physical observation.",
        ("MEASUREMENT", "POLICY", "SENSOR"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-identity-token-records: src/verifier/identity/tokens.py
    audit_row(
        "imported-python-apps",
        "vstd-identity-token-records",
        "TOKEN",
        ("src/verifier/identity/tokens.py",),
        (
            ("src/verifier/identity/tokens.py", "sha256:2a559fe7e95276642f60e66517a7c1f948a4cd779d093648fb4d22f84149d2ce"),
        ),
        "Birth, aging, and lifetime token records with canonical commitment and accumulator chaining.",
        "Token messages and ordered accumulator transitions carry explicit protocol, policy, and retained-history semantics.",
        "Local hash chains are not externally witnessed authoritative history and do not prove a human, legal identity, key ownership, liveness, or authority.",
        ("LEDGER", "POLICY", "PROTOCOL"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", APPLIES),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-layer4-package-api: src/verifier/layer4/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-layer4-package-api",
        "ARCH",
        ("src/verifier/layer4/__init__.py",),
        (
            ("src/verifier/layer4/__init__.py", "sha256:d15ff2bacf9e7d79b3ae6ddd2fdc6738c8b8e5eb5265b51b5b1d5704724efbf5"),
        ),
        "Layer-4 refutability namespace export architecture.",
        "The namespace aggregates refutation, closure, availability, challenge, and precommitment surfaces under one exact public owner.",
        "Exports outside the trusted decision kernel establish no refutability verdict, evidence validity, challenge outcome, or conformance.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-model-reproducibility-profile: src/verifier/corrigibility/model.py
    audit_row(
        "imported-python-apps",
        "vstd-model-reproducibility-profile",
        "DATA",
        ("src/verifier/corrigibility/model.py",),
        (
            ("src/verifier/corrigibility/model.py", "sha256:e2ae7ce69cb174b2668b633942711a124aad157e72d109c3a09b4a6e520d74c8"),
        ),
        "Declarative model reproducibility and risk-profile records with bounded arithmetic checks.",
        "The source represents and measures declared MODEL facets under explicit completeness and acceptance policy.",
        "Retained data and arithmetic do not load, train, infer with, evaluate, or establish the behavior of a MODEL artifact.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", APPLIES),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-module-cli-entrypoint: src/verifier/__main__.py
    audit_row(
        "imported-python-apps",
        "vstd-module-cli-entrypoint",
        "PROTOCOL",
        ("src/verifier/__main__.py",),
        (
            ("src/verifier/__main__.py", "sha256:78f4be5fa67504159df6dd16ac47d01c6293ac40ac3e4249060c44617d1588c8"),
        ),
        "Python module-entry protocol delegating process arguments, streams, and exit status to the public CLI.",
        "Module execution crosses a process-facing command boundary and delegates observation, decision, and effect handling to one selected CLI entrypoint.",
        "Delegation to the installed CLI is not a sandbox and establishes neither command correctness nor the truth of any reported measurement or verdict.",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-operator-stop-authentication: src/verifier/corrigibility/operator_stop.py
    audit_row(
        "imported-python-apps",
        "vstd-operator-stop-authentication",
        "PROTOCOL",
        ("src/verifier/corrigibility/operator_stop.py",),
        (
            ("src/verifier/corrigibility/operator_stop.py", "sha256:67a08b623889f0333e714a207c7a132fc85cfda66b97a402e0fe6740ec3decb9"),
        ),
        "Configured-key authentication protocol for one bounded operator-stop request.",
        "Request signatures, replay fields, time windows, and selected policy form a protocol boundary separate from process control.",
        "Authentication identifies no human and does not stop a process or descendant, deliver a signal, or establish operator authority beyond configured host input.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-provenance-hypergraph-ledger: src/verifier/data/models.py
    audit_row(
        "imported-python-apps",
        "vstd-provenance-hypergraph-ledger",
        "LEDGER",
        ("src/verifier/data/models.py",),
        (
            ("src/verifier/data/models.py", "sha256:9c0b542a6df0ffac8f707b8542ec8c0c8fc76366b4de64da2fe5d98ebd18b47e"),
        ),
        "Artifact, rights, conflict, and transformation-hypergraph records with in-memory mutation rules.",
        "Artifact claims and ordered graph mutations require explicit ASSET, measurement, policy, and transaction consequences.",
        "Recorded claims do not establish actual backing, custody, rights, source truth, durable history, runtime causality, or financial value.",
        ("ASSET", "MEASUREMENT", "POLICY", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question(
                "GRAPH",
                APPLIES,
                "src/verifier/data/models.py",
                "GRAPH provenance models and algorithms.",
            ),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-public-cli-dispatch: src/verifier/runtime/public_cli.py
    audit_row(
        "imported-public-cli",
        "vstd-public-cli-dispatch",
        "PROTOCOL",
        ("src/verifier/runtime/public_cli.py",),
        (
            ("src/verifier/runtime/public_cli.py", "sha256:95b24ba1ac5b7d58d90bd3910e5f15d85c61722df8007e8a575f5a1a17ee31a9"),
        ),
        "Installed public command parser, request router, output protocol and delegated operation controller.",
        "One process-facing entrypoint selects read, verification, filesystem, artifact-lifecycle, subprocess and optional hardware handlers, so its protocol, control, observation, policy, transaction and effect boundaries must remain explicit.",
        "The router delegates rather than proves each handler. Process and filesystem effects are possible, but no downstream effect, sandbox, physical actuation, real-money authority, publication, release, deployment, ROBOT or FINBOT role is established by dispatch alone.",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-python-public-api: src/verifier/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-python-public-api",
        "ARCH",
        ("src/verifier/__init__.py",),
        (
            ("src/verifier/__init__.py", "sha256:791e8b10f24de0aed7b43e55cbad926dcd80e0047d76fe3ce1426dedd60df576"),
        ),
        "Lazy top-level public export architecture and compatibility policy.",
        "The installed symbol map and version/status projection determine the public package architecture under explicit routing policy.",
        "Lazy export reachability does not execute an exported mechanism, establish conformance, or confer release or deployment authority.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", APPLIES),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-refutability-closure-verifier: src/verifier/layer4/closure.py
    audit_row(
        "imported-python-apps",
        "vstd-refutability-closure-verifier",
        "VERIFIER",
        ("src/verifier/layer4/closure.py",),
        (
            ("src/verifier/layer4/closure.py", "sha256:1a5a2da1492ff4c96709523ecd3fbc00df801902a8cebc716241324af31d17e1"),
        ),
        "Structural refutability-closure and minimum-depth verifier.",
        "Closure applies explicit policy to caller-supplied input, transformation, and composition mappings.",
        "Accepted structure leaves certificate references unresolved and conformance NOT_ESTABLISHED; it is not a VSTD-5 entry gate.",
        ("POLICY",),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-refutation-surface-policy: src/verifier/layer4/surface.py
    audit_row(
        "imported-python-apps",
        "vstd-refutation-surface-policy",
        "POLICY",
        ("src/verifier/layer4/surface.py",),
        (
            ("src/verifier/layer4/surface.py", "sha256:5605b0e594c901a27a2a7bc7abfdba0e6d61a9472e712af2487caa81595bbe1e"),
        ),
        "Explicit admissible-refutation and excluded-claim surface policy.",
        "Challenge predicates, coordinates, falsifiers, and permanent physical-world exclusions are normative rules rather than generic records.",
        "A declared surface does not supply evidence, resolve a challenge, prove physical-world completeness, or establish portable-certificate validity.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-schema-package-marker: src/verifier/schemas/__init__.py
    audit_row(
        "imported-python-apps",
        "vstd-schema-package-marker",
        "DATA",
        ("src/verifier/schemas/__init__.py",),
        (
            ("src/verifier/schemas/__init__.py", "sha256:246ad4978d8c0e335372a544b91022879c9801f247bb2df1c5cf3be2f835607e"),
        ),
        "Inert package marker for bundled public schema copies.",
        "The schema package marker needs exact ownership without inheriting validator or policy behavior from neighboring schema artifacts.",
        "The marker contains no schema parser, validation, byte-identity check, admission decision, or conformance mechanism.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", APPLIES),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-sim-trace-assessor: src/verifier/corrigibility/simulation.py
    audit_row(
        "imported-python-apps",
        "vstd-sim-trace-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/simulation.py",),
        (
            ("src/verifier/corrigibility/simulation.py", "sha256:56883fcbf742194f9278bb12984b76a349cb30f4d3c7ca4a4ee14f295dc2cd6b"),
        ),
        "Tiered simulation trace, invariant, abstraction, agent-parity, and sharding assessor.",
        "The assessor invokes selected transition and predicate callbacks, observes state, and applies bounded control and transaction policy across a trace.",
        "Callbacks run in-process without sandboxing; trace checks are not physics validation, a running BOT, ROBOT or FINBOT, or evidence of physical or financial effects.",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question(
                "SIM",
                APPLIES,
                "src/verifier/corrigibility/simulation.py",
                "Abstract, substrate-neutral generative simulation specification (SIM-1..5)",
            ),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),
    # vstd-tesla-cage-contract: src/verifier/corrigibility/tesla_cage.py
    audit_row(
        "imported-python-apps",
        "vstd-tesla-cage-contract",
        "HARNESS",
        ("src/verifier/corrigibility/tesla_cage.py",),
        (
            ("src/verifier/corrigibility/tesla_cage.py", "sha256:8a4c0c9efd05dae32ea6c42794b916136d02eccdaa2a6c126c3d2223a04a15fd"),
        ),
        "Tesla-cage containment declarations, attestations, and invariant checks.",
        "Containment representations carry measurable claims governed by explicit fail-closed policy and need a HARNESS owner rather than a generic object.",
        "The source implements no preemption, process actuation, controller, sandbox launch, ROBOT, or physical containment mechanism.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question(
                "HARDWARE",
                APPLIES,
                "src/verifier/corrigibility/tesla_cage.py",
                "Unauthenticated declaration of mechanical relay properties; not proof.",
            ),
            _question("HARNESS", APPLIES),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
        root_role_decisions=(
            ("HARDWARE", APPLIES, "Owned source tesla_cage.py declares 'Unauthenticated declaration of mechanical relay properties; not proof.' for its device records, so the containment declarations embody declared device inventory and break-response envelopes; these are unauthenticated declarations and establish no physical device."),
        ),
    ),
    # vstd-training-checkpoint-ledger: src/verifier/corrigibility/hyperparameters.py
    audit_row(
        "imported-python-apps",
        "vstd-training-checkpoint-ledger",
        "LEDGER",
        ("src/verifier/corrigibility/hyperparameters.py",),
        (
            ("src/verifier/corrigibility/hyperparameters.py", "sha256:3317d3439dde648a004d69e8a61d19df0a2f69ba6b0b2914caeeb00155c37a77"),
        ),
        "Hyperparameter, training-step, and checkpoint-lineage records with ordered consistency checks.",
        "Checkpoint lineage retains measured training metadata through policy-governed state transitions and additions.",
        "Caller-supplied records are not durable authoritative history, checkpoint-byte acquisition, or evidence that training or numerical updates occurred.",
        ("MEASUREMENT", "POLICY", "TRANSACTION"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question(
                "TRAIN",
                APPLIES,
                "src/verifier/corrigibility/hyperparameters.py",
                "TRAIN: Hyperparameter, checkpoint lineage, and training run traceability.",
            ),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-training-control-profile: src/verifier/corrigibility/train_profile.py
    audit_row(
        "imported-python-apps",
        "vstd-training-control-profile",
        "POLICY",
        ("src/verifier/corrigibility/train_profile.py",),
        (
            ("src/verifier/corrigibility/train_profile.py", "sha256:af2877048e2ddc61598136cf37e0bb5fee3c8ff087178269cb67f1610a3410a3"),
        ),
        "Finite TRAIN control-plan analysis policy.",
        "Protected facets, effect names, relations, and dependency checks are normative selection rules for one explicit application profile.",
        "Plan analysis performs no optimization, model mutation, checkpoint write, authority grant, or whole-system corrigibility assessment.",
        (),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question("DATA", UNRESOLVED),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", UNRESOLVED),
        ),
    ),
    # vstd-training-data-contamination-assessor: src/verifier/corrigibility/data.py
    audit_row(
        "imported-python-apps",
        "vstd-training-data-contamination-assessor",
        "VERIFIER",
        ("src/verifier/corrigibility/data.py",),
        (
            ("src/verifier/corrigibility/data.py", "sha256:878486a829f8cd74214f3feff9c64ef1df9dc980d5143df862eaef88dc7f82d9"),
        ),
        "Training and evaluation dataset provenance, integrity, and contamination assessor.",
        "Contamination conclusions derive measurements from supplied manifests under explicit split and overlap policy.",
        "The assessor does not acquire dataset bytes, authenticate lineage, execute training, or prove absence of unrepresented contamination.",
        ("MEASUREMENT", "POLICY"),
        (
        ),
        (
            _question("ACTOR", UNRESOLVED),
            _question("AGENT", UNRESOLVED),
            _question("ARCH", UNRESOLVED),
            _question("BENCH", UNRESOLVED),
            _question("BOT", UNRESOLVED),
            _question("COLLECTIVE", UNRESOLVED),
            _question(
                "DATA",
                APPLIES,
                "src/verifier/corrigibility/data.py",
                "DATA: Bounded training/eval dataset provenance, integrity digests, and contamination boundaries.",
            ),
            _question("ENV", UNRESOLVED),
            _question("EVENT", UNRESOLVED),
            _question("GRAPH", UNRESOLVED),
            _question("HARDWARE", UNRESOLVED),
            _question("HARNESS", UNRESOLVED),
            _question("HUMAN", UNRESOLVED),
            _question("HYPER", UNRESOLVED),
            _question("IDENTITY", UNRESOLVED),
            _question("MODEL", UNRESOLVED),
            _question("OWNER", UNRESOLVED),
            _question("RECEIPT", UNRESOLVED),
            _question("ROLE", UNRESOLVED),
            _question("SIM", UNRESOLVED),
            _question("SPACE", UNRESOLVED),
            _question("TIME", UNRESOLVED),
            _question("TOKEN", UNRESOLVED),
            _question("TRAIN", UNRESOLVED),
            _question("VERIFIER", APPLIES),
        ),
    ),

)


PARTIAL_PROFILE = seal_profile(
    PARTIAL_PROFILE_ID,
    1,
    CLAIM_BOUNDARY,
    tuple(
        OriginalKindAssignment(
            object_id=row.object_id,
            expected_primary=row.expected_primary,
            expected_owned_paths=row.expected_owned_paths,
            expected_owned_path_set_digest=row.expected_owned_path_set_digest,
            scope_reason=row.scope_reason,
            decisions=tuple(
                OriginalKindDecision(question.kind, question.status, question.reason)
                for question in row.questions
                if question.status in {APPLIES, DOES_NOT_APPLY}
            ),
        )
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
        if any(question.status in {APPLIES, DOES_NOT_APPLY} for question in row.questions)
    ),
)


def current_source_partition() -> tuple[SemanticOwnershipSpec, ...]:
    """Read only the two imported declarations, never the aggregate catalog."""

    return tuple(
        sorted(
            (*PYTHON_APPS_OWNERSHIP_SPECS, *PUBLIC_CLI_OWNERSHIP_SPECS),
            key=lambda spec: spec.object_id,
        )
    )


def _spec_coordinate_digest(spec: SemanticOwnershipSpec) -> str:
    return _source_coordinate_digest(
        spec.object_id,
        spec.primary_kind,
        tuple(spec.owned_paths),
        spec.representation_role,
        spec.necessity_reason,
        spec.consequence_boundary,
        tuple(spec.specializations),
        tuple((name, tuple(targets)) for name, targets in spec.operands),
        tuple(
            (decision.kind, decision.status, decision.reason)
            for decision in spec.root_role_decisions
        ),
    )


def validate_audit_row(
    row: PythonAppsPublicCliAudit,
    spec: SemanticOwnershipSpec,
) -> None:
    """Bind one literal row to one declaration without filling any omitted decision."""

    if spec.object_id != row.object_id:
        raise ValueError(_PREFIX + "SOURCE_PARTITION_INVALID:" + row.object_id)
    if spec.primary_kind != row.expected_primary:
        raise ValueError(_PREFIX + "SOURCE_PRIMARY_DRIFT:" + row.object_id)
    if tuple(spec.owned_paths) != row.expected_owned_paths:
        raise ValueError(_PREFIX + "SOURCE_PATH_DRIFT:" + row.object_id)
    declared_roots = tuple(
        (decision.kind, decision.status, decision.reason)
        for decision in spec.root_role_decisions
    )
    if declared_roots != tuple(row.expected_root_role_decisions):
        raise ValueError(_PREFIX + "ROOT_ROLE_DECISION_UNAUDITED:" + row.object_id)
    if _spec_coordinate_digest(spec) != row.expected_source_coordinate_digest:
        raise ValueError(_PREFIX + "SOURCE_COORDINATE_DRIFT:" + row.object_id)
    review = {question.kind: question for question in row.questions}
    if tuple(review) != ORIGINAL_NON_OBJECT_KINDS:
        raise ValueError(_PREFIX + "QUESTION_DENOMINATOR_DRIFT:" + row.object_id)
    declared = {
        kind for kind in (spec.primary_kind, *spec.specializations)
        if kind in ORIGINAL_NON_OBJECT_KINDS
    }
    for kind, question in review.items():
        if question.status == UNRESOLVED:
            if question.source is not None:
                raise ValueError(_PREFIX + "EVIDENCE_ON_UNRESOLVED:" + row.object_id + ":" + kind)
        elif question.status == DOES_NOT_APPLY:
            if question.source is None:
                raise ValueError(_PREFIX + "EXCLUSION_WITHOUT_OWNED_SOURCE:" + row.object_id + ":" + kind)
            if question.source.path not in spec.owned_paths:
                raise ValueError(_PREFIX + "EVIDENCE_PATH_SUBSTITUTION:" + row.object_id + ":" + kind)
            if kind in declared:
                raise ValueError(_PREFIX + "SOURCE_ROLE_CONFLICT:" + row.object_id + ":" + kind)
            # A quotation alone never refutes a kind; the declaration must pin it too.
            if not any(
                root_kind == kind and root_status == DOES_NOT_APPLY
                for root_kind, root_status, _root_reason in declared_roots
            ):
                raise ValueError(_PREFIX + "EXCLUSION_WITHOUT_ROOT_DECLARATION:" + row.object_id + ":" + kind)
        elif question.source is None:
            if kind not in declared:
                raise ValueError(_PREFIX + "ACCUMULATED_ROLE_DRIFT:" + row.object_id + ":" + kind)
        elif question.source.path not in spec.owned_paths:
            raise ValueError(_PREFIX + "EVIDENCE_PATH_SUBSTITUTION:" + row.object_id + ":" + kind)
    if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS and (
        review[spec.primary_kind].status != APPLIES
    ):
        raise ValueError(_PREFIX + "PRIMARY_REFUTED:" + row.object_id)
    if {
        kind for kind, question in review.items()
        if question.status == APPLIES and question.source is None
    } != declared:
        raise ValueError(_PREFIX + "ACCUMULATED_ROLE_DRIFT:" + row.object_id)


# Consequence channels that cannot carry a represented subject of another kind into
# a closure. Every other channel (process, injected callable, dynamic import, clock,
# randomness, environment, filesystem, network, device) can, so it defeats any
# refutation of this row until a closed per-kind analysis proves otherwise.
_NEUTRAL_EFFECT_CHANNELS = frozenset({"serialization_message_boundary"})


def does_not_apply_closure_blockers(
    root: Path = REPO_ROOT,
    rows: Iterable[PythonAppsPublicCliAudit] = PYTHON_APPS_PUBLIC_CLI_AUDITS,
) -> tuple[str, ...]:
    """Name every DOES_NOT_APPLY that the exact owned closure does not support.

    ClosedEffectAudit supports a refutation only when it is CLOSED at the pinned
    owned bytes and no non-neutral consequence channel is present; it never
    creates one. Each refuted kind of a row that fails either test is an exact
    blocker.
    """

    blockers: list[str] = []
    for row in rows:
        refuted = [
            question.kind
            for question in row.questions
            if question.status == DOES_NOT_APPLY
        ]
        if not refuted:
            continue
        closure = audit_closed_effects(
            Path(root),
            row.expected_owned_paths,
            expected_source_digests=dict(row.expected_owned_file_digests),
        )
        if closure.status != "CLOSED":
            blockers.extend(
                _PREFIX + "DOES_NOT_APPLY_CLOSURE_NOT_CLOSED:" + row.object_id + ":" + kind
                for kind in refuted
            )
            continue
        defeating = ",".join(
            sorted(
                {item.channel for item in closure.consequences}
                - _NEUTRAL_EFFECT_CHANNELS
            )
        )
        if defeating:
            blockers.extend(
                _PREFIX
                + "DOES_NOT_APPLY_EFFECT_DEFEATED:"
                + row.object_id
                + ":"
                + kind
                + ":"
                + defeating
                for kind in refuted
            )
    return tuple(blockers)


def validate_owned_source_bytes(
    root: Path = REPO_ROOT,
    rows: Iterable[PythonAppsPublicCliAudit] = PYTHON_APPS_PUBLIC_CLI_AUDITS,
) -> None:
    """Bind every owned file digest, every quotation, and every refutation's closure."""

    rows = tuple(rows)
    for row in rows:
        for path, digest in row.expected_owned_file_digests:
            try:
                data = (Path(root) / path).read_bytes()
            except OSError as error:
                raise ValueError(_PREFIX + "OWNED_SOURCE_MISSING:" + path) from error
            if _bytes_digest(data) != digest:
                raise ValueError(_PREFIX + "OWNED_SOURCE_DIGEST_DRIFT:" + path)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(_PREFIX + "OWNED_SOURCE_NOT_UTF8:" + path) from error
            for question in row.questions:
                if (
                    question.source is not None
                    and question.source.path == path
                    and question.source.quote not in text
                ):
                    raise ValueError(
                        _PREFIX + "EVIDENCE_QUOTE_MISSING:" + row.object_id + ":" + question.kind
                    )
    blockers = does_not_apply_closure_blockers(Path(root), rows)
    if blockers:
        raise ValueError(blockers[0])


def validate_source_partition(
    specs: Iterable[SemanticOwnershipSpec],
) -> tuple[SemanticOwnershipSpec, ...]:
    """Bind the literal audit to exactly the 41 imported declarations."""

    selected = tuple(sorted(tuple(specs), key=lambda spec: spec.object_id))
    if (
        any(type(spec) is not SemanticOwnershipSpec for spec in selected)
        or len({spec.object_id for spec in selected}) != len(selected)
    ):
        raise ValueError(_PREFIX + "SOURCE_PARTITION_INVALID")
    audits = {row.object_id: row for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}
    source = {spec.object_id: spec for spec in selected}
    if set(source) != set(audits):
        raise ValueError(_PREFIX + "SOURCE_DENOMINATOR_DRIFT")
    for object_id, row in audits.items():
        validate_audit_row(row, source[object_id])
    return selected


def review_document() -> dict[str, Any]:
    """Return the complete 41-by-25 audit without upgrading any UNRESOLVED item."""

    profile_ids = {assignment.object_id for assignment in PARTIAL_PROFILE.assignments}
    return {
        row.object_id: {
            "group": row.group,
            "expected_primary": row.expected_primary,
            "expected_owned_paths": list(row.expected_owned_paths),
            "expected_owned_path_set_digest": row.expected_owned_path_set_digest,
            "expected_source_coordinate_digest": row.expected_source_coordinate_digest,
            "scope_reason": row.scope_reason,
            "questions": {
                question.kind: {
                    "status": question.status,
                    "reason": question.reason,
                    "source": (
                        None
                        if question.source is None
                        else {"path": question.source.path, "quote": question.source.quote}
                    ),
                }
                for question in row.questions
            },
            "partial_profile_digest": (
                PARTIAL_PROFILE.canonical_digest if row.object_id in profile_ids else None
            ),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for row in PYTHON_APPS_PUBLIC_CLI_AUDITS
    }


def _catalog_check() -> None:
    if len(PYTHON_APPS_PUBLIC_CLI_AUDITS) != OBJECT_DENOMINATOR:
        raise AssertionError("python-apps/public-cli object denominator differs")
    if len({row.object_id for row in PYTHON_APPS_PUBLIC_CLI_AUDITS}) != OBJECT_DENOMINATOR:
        raise AssertionError("python-apps/public-cli object ids overlap")
    if sum(len(row.expected_owned_paths) for row in PYTHON_APPS_PUBLIC_CLI_AUDITS) != (
        OWNED_PATH_DENOMINATOR
    ):
        raise AssertionError("python-apps/public-cli owned path denominator differs")
    applies = does_not_apply = unresolved = 0
    for row in PYTHON_APPS_PUBLIC_CLI_AUDITS:
        if tuple(question.kind for question in row.questions) != ORIGINAL_NON_OBJECT_KINDS:
            raise AssertionError(row.object_id + " kind denominator differs")
        if any(not question.reason.strip() for question in row.questions):
            raise AssertionError(row.object_id + " contains a blank reason")
        applies += sum(question.status == APPLIES for question in row.questions)
        does_not_apply += sum(question.status == DOES_NOT_APPLY for question in row.questions)
        unresolved += sum(question.status == UNRESOLVED for question in row.questions)
    if len(PARTIAL_PROFILE.assignments) != DECIDED_ROW_DENOMINATOR:
        raise AssertionError("python-apps/public-cli decided-row denominator differs")
    if applies != APPLIES_DENOMINATOR:
        raise AssertionError("python-apps/public-cli APPLIES denominator differs")
    if does_not_apply != DOES_NOT_APPLY_DENOMINATOR:
        raise AssertionError("python-apps/public-cli DOES_NOT_APPLY denominator differs")
    if unresolved != UNRESOLVED_DENOMINATOR:
        raise AssertionError("python-apps/public-cli UNRESOLVED denominator differs")


_catalog_check()


__all__ = [
    "CLAIM_BOUNDARY",
    "PARTIAL_PROFILE",
    "PARTIAL_PROFILE_ID",
    "PYTHON_APPS_PUBLIC_CLI_AUDITS",
    "PythonAppsPublicCliAudit",
    "PythonAppsPublicCliQuestion",
    "OwnedSourceQuote",
    "UNRESOLVED",
    "audit_row",
    "current_source_partition",
    "does_not_apply_closure_blockers",
    "review_document",
    "validate_audit_row",
    "validate_owned_source_bytes",
    "validate_source_partition",
]

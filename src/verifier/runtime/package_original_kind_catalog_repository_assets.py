"""Literal original-kind audit for repository-asset semantic ownership rows.

The imported partition in ``package_semantic_ownership_repository_assets.py``
defines 40 object rows over exactly 234 owned non-code paths: retained
``.vstd`` evidence inputs, documentation, repository policy, hosted-workflow
declarations, receipt and accelerator wire schemas, and generated distribution
metadata.  Every row answers all 25 original non-``OBJECT`` kinds in order, for
1,000 literal questions in total.  JavaScript Object Notation (JSON) is the wire
form of the sealed profile; Verifier Standard (VSTD) is the surrounding standard.

Decision rule.  ``APPLIES`` is recorded only for a source-declared primary kind
or a source-declared root role decision.  ``DOES_NOT_APPLY`` is recorded only
when all four hold: (1) the whole negated sentence occurs verbatim in the row's
own role, necessity, or boundary text; (2) the sentence denies the row's
identity as that kind, as listed in ``IDENTITY_DENIALS``, rather than an
activity, a proof, an enumerated capability, or a qualified subtype; (3) the
closed owned-source screen (``owned_source_hits``) finds no kind-specific
counterexample in the row's owned bytes or in the project-local modules those
bytes invoke, import, or name; and (4) no effect-boundary blocker in
``UNCLOSED_EFFECT_BLOCKERS`` names a consumer outside that closure.  The closure
is name-based and lexical, so a clean screen is not exhaustive: a clean screen
alone never refutes a kind.  Sentences that deny only activity, proof,
authority lists, or subtypes, and denials whose effect boundary is unclosed, are
demoted to ``UNRESOLVED`` and kept in ``DEMOTED_EXCLUSIONS`` with their basis.
Everything else is ``UNRESOLVED``.
No question is derived from omission, complement, filename, neighboring rows,
a different primary kind, or an ``OBJECT`` label.

The sealed profile contains only the rows with at least one decided answer
(44 ``APPLIES`` and 0 ``DOES_NOT_APPLY``).  It is partial: it proves no package
closure, repository admission, polish conformance, mechanism truth, release,
or deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
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
from verifier.runtime.package_semantic_ownership_model import SemanticOwnershipSpec
from verifier.runtime.package_semantic_ownership_repository_assets import (
    REPOSITORY_ASSET_OWNERSHIP_SPECS,
)

UNRESOLVED = "UNRESOLVED"
EXPECTED_OBJECT_COUNT = 40
EXPECTED_PATH_COUNT = 234
EXPECTED_APPLIES_COUNT = 44
EXPECTED_DOES_NOT_APPLY_COUNT = 0
EXPECTED_UNRESOLVED_COUNT = 956
EXPECTED_PROFILE_ROW_COUNT = 17
_NEGATION_WORDS = frozenset({"not", "no", "neither", "nor", "without", "never"})
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CLOSURE_LIMIT = 200
CLAIM_BOUNDARY = (
    "Exact current-source original-kind review for the 40 repository-asset "
    "semantic ownership rows imported from package_semantic_ownership_repository_assets.py "
    "(234 owned non-code paths). The sealed partial profile contains only the 17 rows "
    "with decided answers; it proves no full package closure, repository admission, "
    "polish conformance, mechanism truth, release, or deployment."
)
# One digest per ownership row, over the ordered ``(path, sha256(bytes))``
# inventory.  The ownership declaration is not evidence about stale or substituted
# asset bytes: validation must bind both before interpreting any role decision.
_EXPECTED_OWNED_CONTENT_DIGESTS = {
    "vstd-accelerator-profile-wire-schema": "sha256:f23529a4aad9cc92a0cb165448b1b4df7c633b33b7aabd17a0957b36f6b5618e",
    "vstd-documentation-adjacent-standards-crosswalks": "sha256:945313446df3403b4da5fbf41a5309309ba2d3538a521bac4639bca3f12a2c67",
    "vstd-documentation-artifact-interoperability-architecture": "sha256:a7839b6d1264882d5d1ed094bea29d0f7649033bd7a8811f83294db5387eeff9",
    "vstd-documentation-claim-boundary-policy": "sha256:e6f33e93a20c836c1e9d5030e696d511cec3a31678828c0a6dc9c79bd4a7bfc0",
    "vstd-documentation-control-domain-candidates": "sha256:b2ffe45908cd26e31078a879b893d821ac949a68605e1ca4c49546418f2c92a3",
    "vstd-documentation-core-architecture": "sha256:9368221858875b42175327b6f56e7514b24df7a8c47964f378812b58715483cc",
    "vstd-documentation-derived-metadata": "sha256:1f1d0448a10146c89657c2b055515292b0ef65dcb355b12b3fd7c34d4a6150b1",
    "vstd-documentation-environment-graph-architecture": "sha256:d1cbdf64b6cda7cbca8bcf177d25b040a11f50f39b272864ecfc6a48b6d7f8b4",
    "vstd-documentation-hosting-protocol": "sha256:823325026b58ad9427e8e7e9e49e20b209b8fef92b5aeee7b90c2dc99420fb66",
    "vstd-documentation-local-tool-protocols": "sha256:3eb478bb6512dd162a6328408cc71e50b7a57b4252ec7b480b7189f0a9ea935f",
    "vstd-documentation-reader-reference": "sha256:4357dae1040931623703ce64b0493c15bb2e1959722260291637a380f61e400b",
    "vstd-documentation-remote-submission-protocols": "sha256:3b75111826e881cb3f3eba525fd002d3128f0b7e1206197ff89b5f8d4055ddeb",
    "vstd-documentation-user-navigation": "sha256:8e435cb2b41617e1bb4c396ec389f3a8369a786545cb7943ede2dbe88037151c",
    "vstd-generated-distribution-metadata": "sha256:ebe9410b2153ea617dfcfbb4a7b8a55dab0b7ec23c3471d36775044054ca0409",
    "vstd-github-contribution-form-policy": "sha256:79c375851d9cc9268c8ca2d685edaa957382b603130731ec40e19dbfc993037a",
    "vstd-github-documentation-deployment-protocol": "sha256:db812ea395dfc5ba070140617a7ad2938242d7256861d692da3cdac1459f07ca",
    "vstd-github-external-link-policy": "sha256:cb514417e6575f2452b744d511f247dd4dfa26670373f064a7f8b08f08d2de0d",
    "vstd-github-promotion-policy-protocols": "sha256:c7c5ef8309ffda98a2008d34566485cebf0adcb99cfbbaeddd4899f1e34b9400",
    "vstd-github-release-workflow-protocol": "sha256:cf18fb6f5eec8bab92c82d659a83262b487d4c52bae48c4f126896796de3dae2",
    "vstd-github-source-description-workflow-protocol": "sha256:47d9078bf07b7fa6b6fd10dbbf2792e5a0f00283566e8cab067dd21564838bb5",
    "vstd-github-verification-workflow-protocols": "sha256:f18b06663888bf5353cdc879fde4af09103ab88733e8f85b16278bb96af3783d",
    "vstd-receipt-wire-schema-catalog": "sha256:bf08951264897003fdd31327fb1c488be75641c1cb445d5cfdd2e8c79e8ecf1d",
    "vstd-repository-agent-operating-policy": "sha256:5c8eed585e08f361368905444a90f13eb71cb692c17506cac21f7cc45f07d2c4",
    "vstd-repository-citation-metadata": "sha256:9901c088d90b1581b951728874a3a6c2462484232175adc7f5bd9cb58578cb60",
    "vstd-repository-community-governance-policy": "sha256:fdea31e77e532e0e049f64a43fee644696393b46c4e9d7a2fb438e93acdde1c9",
    "vstd-repository-file-and-package-policy": "sha256:e9d4ee2dce583a1b82d3c0fad02dd62fcb2c69f7fd86d64194fc103548a14e4a",
    "vstd-repository-history-and-roadmap": "sha256:8a61b72d912d7484c33b49c95b06f342fb49a95ba8a985095ed14895b07d1314",
    "vstd-repository-legal-notices": "sha256:5f797deb6c1358a55b8a524339b471a9de7a89b3b565465577753f3dcea0f5b5",
    "vstd-repository-overview": "sha256:eb2c28d8ae646aa1664027712def0c3399aae589c5194c096a0b64f1fa0185f2",
    "vstd-repository-release-procedure-policy": "sha256:d238dd6fdb3e4c95fb79f729520bf19c88232d6837a3ac45e206230d34a6811f",
    "vstd-repository-source-admission-designs": "sha256:7fac636837a55818e3bff591c29982ab4a6e0d7e1f5648b195fa72aed8a44055",
    "vstd-retained-facet-policy-inputs": "sha256:223572e1edffd57a571deff7a6cb84d4132332b47f6d7e430531504c429965e4",
    "vstd-retained-graph-statics-certificate": "sha256:a9b6d916571cafdf140d0b2bb2f7dcf0b6ad9a58880adb56a38ce497a3f30299",
    "vstd-retained-graph-statics-policy-input": "sha256:9dde44e4a90561ce676762355777fdf21aadce4d5a30eb8957141a70a3d08f42",
    "vstd-retained-graph-statics-request": "sha256:bf3447a31745202dba41ca339222b855176294e520860c97f68689024b68af9d",
    "vstd-retained-object-facet-certificates": "sha256:543fba3a372c60568d708f30e1d394a00be0279bd604cdce1ea391c0dc5edcf7",
    "vstd-retained-object-facet-requests": "sha256:6c0b379ffbdedc409d8bf412aee5db4397158f8f7d938eff30a70656b5f9d293",
    "vstd-retained-typed-facet-certificates": "sha256:be28fd23ca1a704b07f71a3a41e171d5cadd6e43448e322d1f2a5b3fb6157c1f",
    "vstd-retained-typed-facet-requests": "sha256:d53e547964384c02f4980b810c5612cae9b44253ef397bb4c3e88386ecca9341",
    "vstd-root-uv-dependency-resolution": "sha256:f809440f9ac9468ee222a542d556d16add90078622057bdbd98474404c3d8c82",
}
# A DOES_NOT_APPLY decision additionally depends on the exact project-local
# source closure screened for counterexamples.  Pin that closure independently;
# absence of a marker is never accepted from unreviewed or moving source.  No
# denial survives the second adversarial pass, so no closure is pinned.
_EXPECTED_IDENTITY_SCREEN_DIGESTS: dict[tuple[str, str], str] = {}
# Basis for each demotion from DOES_NOT_APPLY to UNRESOLVED.  ACTIVITY_OR_PROOF:
# the sentence denies a run, check, proof, grant, or authority.  ENUMERATED_SUBTYPE:
# it denies named subtypes or records only.  SOURCE_COUNTEREXAMPLE: the closed
# owned-source screen finds kind-specific behavior in the row's owned closure.
# UNCLOSED_EFFECT_BOUNDARY: the identity denial is plausible, but a consumer outside
# the name-based closure reads the row's bytes, so the clean screen is not exhaustive.
ACTIVITY_OR_PROOF = "ACTIVITY_OR_PROOF"
ENUMERATED_SUBTYPE = "ENUMERATED_SUBTYPE"
SOURCE_COUNTEREXAMPLE = "SOURCE_COUNTEREXAMPLE"
UNCLOSED_EFFECT_BOUNDARY = "UNCLOSED_EFFECT_BOUNDARY"
_DEMOTION_BASES = frozenset(
    {ACTIVITY_OR_PROOF, ENUMERATED_SUBTYPE, SOURCE_COUNTEREXAMPLE, UNCLOSED_EFFECT_BOUNDARY}
)
# Identity-level denials that may refute a kind.  Each entry pins the exact sentence
# and the clause that denies the row's identity as that kind.  Empty: the former
# VERIFIER denial of the object-facet requests is demoted to UNRESOLVED below.
IDENTITY_DENIALS: dict[tuple[str, str], tuple[str, str]] = {}
# Exact blocker for each UNCLOSED_EFFECT_BOUNDARY demotion: the consumer module that
# lies outside owned_source_closure, and the schema identifier that binds it to the
# row's owned bytes.  Validation reproduces both; a blocker never upgrades a kind.
UNCLOSED_EFFECT_BLOCKERS: dict[tuple[str, str], tuple[str, str]] = {
    ("vstd-retained-object-facet-requests", "VERIFIER"): (
        "src/verifier/domains/contracts/object_facets.py",
        "verifier-current-object-facets-request-1",
    ),
}
_DECLARATION_PREFIXES = (
    "src/verifier/runtime/package_original_kind_catalog",
    "src/verifier/runtime/package_semantic_ownership",
)
_INVOKED_SOURCE = re.compile(r"\b((?:scripts|src/verifier)/[A-Za-z0-9_./-]+\.py)\b")
_VERIFIER_IMPORT = re.compile(
    r"^\s*(?:from\s+(verifier(?:\.[A-Za-z_]\w*)*)\s+import\s+(\([^)]*\)|[^\n]*)"
    r"|import\s+(verifier(?:\.[A-Za-z_]\w*)*))",
    re.MULTILINE,
)
# Closed, kind-specific lexical screen.  A hit in owned bytes or in the closure is a
# counterexample to a DOES_NOT_APPLY for that kind; absence is not identity proof.
_OWNED_SOURCE_SCREEN: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    kind: tuple((name, re.compile(pattern)) for name, pattern in markers)
    for kind, markers in {
        "ACTOR": (
            ("actor-key", r'"(actor|actor_id|decider|approver|signer)"\s*:'),
            ("signed-or-approved-by", r"\b(signed_by|approved_by)\b\s*[:=]"),
        ),
        "AGENT": (
            ("agent-key", r'"agent(_id)?"\s*:'),
            ("trajectory", r"\btrajectory\s*[:=]"),
        ),
        "ARCH": (
            ("layer-graph", r"\blayer_graph\b"),
            ("tensor-shape", r'"?tensor_shape"?\s*[:=]'),
        ),
        "BENCH": (("benchmark-key", r'"(benchmark_id|scoring_rule|oracle)"\s*:'),),
        "BOT": (("observation-action-envelope", r'"(observations|actions|execution_envelope)"\s*:'),),
        "COLLECTIVE": (("quorum-or-membership", r'"(quorum|membership|role_graph)"\s*:'),),
        "DATA": (("partition-or-rows", r'"(partitions|rows|records)"\s*:\s*\['),),
        "ENV": (
            ("container-directive", r"^\s*(FROM|RUN|ENTRYPOINT)\s"),
            ("install-command", r"\bpip install\b"),
            ("runtime-pin", r'"(python_version|software_digest)"\s*:'),
        ),
        "EVENT": (
            ("event-action-payload", r'"(action|event_name|event_type|payload|occurred_at)"\s*:'),
            ("occurrence-time", r"\boccurred_at\b"),
        ),
        "GRAPH": (("vertices-edges", r'"(vertices|edges|nodes)"\s*:\s*[\[{]'),),
        "HARDWARE": (
            ("device-class", r'"device_class"\s*:'),
            ("device-capacity", r'"(capacity|allocation|topology)"\s*:'),
        ),
        "HARNESS": (("transcript-tools", r'"(transcript|tools)"\s*:\s*\['),),
        "HUMAN": (("living-person", r'"(date_of_birth|living_person)"\s*:'),),
        "HYPER": (("operands", r'"(operands|directed_operands)"\s*:\s*\['),),
        "IDENTITY": (("bearer-holder", r'"(bearer|holder|presentation)"\s*:'),),
        "MODEL": (("weights-architecture", r'"(weights|parameters|architecture)"\s*:'),),
        "OWNER": (
            ("owner-key", r'"(owner|owner_id|owned_by)"\s*:'),
            ("owned-by", r"\bowned_by\b"),
        ),
        "RECEIPT": (("receipt-key", r'"(receipt_id|receipt)"\s*:'),),
        "ROLE": (("role-permission", r'"(role_id|permissions)"\s*:'),),
        "SIM": (("transition-state", r'"(transitions|states)"\s*:\s*\['),),
        "SPACE": (("coordinate-system", r'"(coordinate_system|layout)"\s*:'),),
        "TIME": (("epoch-clock", r'"(epoch|clock)"\s*:'),),
        "TOKEN": (("token-lease", r'"(bearer_token|lease_id|lease)"\s*:'),),
        "TRAIN": (("optimizer-batches", r'"(optimizer|batches|checkpoints)"\s*:'),),
        "VERIFIER": (
            ("verdict-or-checker-key", r'"(verdict|decision|checker|mechanism_id)"\s*:'),
            ("procedure-definition", r"^\s*def\s+(verify|check|replay)\w*\s*\("),
            ("decision-procedure", r"\bdecision_procedure\b"),
        ),
    }.items()
}

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


@dataclass(frozen=True)
class RepositoryAssetOriginalKindQuestion:
    """One literal answer; ``evidence`` names the basis or quotes the refutation."""

    kind: str
    status: str
    evidence: str
    reason: str


@dataclass(frozen=True)
class RepositoryAssetOriginalKindAudit:
    """One exact source row, its path set, its coordinate digest, and 25 answers."""

    object_id: str
    expected_primary: str
    expected_owned_paths: tuple[str, ...]
    expected_owned_path_set_digest: str
    expected_owned_content_digest: str
    expected_source_coordinate_digest: str
    scope: str
    questions: tuple[RepositoryAssetOriginalKindQuestion, ...]


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


def _source_coordinate_digest(spec: SemanticOwnershipSpec) -> str:
    """Bind every declared field of one row, so text drift changes the digest."""
    return _canonical_digest(
        {
            "object_id": spec.object_id,
            "primary": spec.primary_kind,
            "owned_paths": list(spec.owned_paths),
            "representation_role": spec.representation_role,
            "necessity_reason": spec.necessity_reason,
            "consequence_boundary": spec.consequence_boundary,
            "specializations": list(spec.specializations),
            "root_role_decisions": [
                {"kind": decision.kind, "status": decision.status, "reason": decision.reason}
                for decision in spec.root_role_decisions
            ],
        }
    )


def _spec_text(spec: SemanticOwnershipSpec) -> str:
    """The owned declaration text that a refutation phrase must quote verbatim."""
    return "\n".join(
        (spec.representation_role, spec.necessity_reason, spec.consequence_boundary)
    )


def _owned_path(root: Path, relpath: str) -> Path:
    """Resolve one canonical in-root path without accepting aliases or links."""

    pure = PurePosixPath(relpath)
    if (
        not relpath
        or "\\" in relpath
        or pure.is_absolute()
        or str(pure) != relpath
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_PATH_ALIAS:" + relpath)
    selected = Path(root).joinpath(*pure.parts)
    if not selected.is_file():
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_UNAVAILABLE:" + relpath)
    root_resolved = Path(root).resolve()
    cursor = Path(root)
    for part in pure.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_SYMLINK:" + relpath)
    try:
        selected.resolve(strict=True).relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_OUTSIDE_ROOT:" + relpath) from error
    return selected


def owned_content_digest(
    owned_paths: Iterable[str], root: Path = REPOSITORY_ROOT
) -> str:
    """Digest the ordered canonical paths and their exact bytes."""

    inventory = []
    for relpath in tuple(owned_paths):
        path = _owned_path(Path(root), relpath)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_UNAVAILABLE:" + relpath) from error
        inventory.append(
            {"path": relpath, "sha256": "sha256:" + sha256(data).hexdigest()}
        )
    return _canonical_digest(inventory)


def _is_negated(evidence: str) -> bool:
    """True only when a quoted exclusion contains an explicit negation word."""
    words = set(evidence.lower().replace(",", " ").replace(".", " ").split())
    return bool(words & _NEGATION_WORDS)


def _read_owned(root: Path, relpath: str) -> str:
    path = _owned_path(root, relpath)
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_NOT_UTF8:" + relpath) from error
    except OSError as error:
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_UNAVAILABLE:" + relpath) from error


def _import_targets(root: Path, dotted: str, names: str) -> tuple[str, ...]:
    """Module file(s) named by one ``verifier`` import.

    The module itself resolves to its file or package ``__init__``.  A name listed
    after ``from ... import`` adds ``<package>/<name>.py`` only when that submodule
    file exists.  A package that resolves to neither fails closed.
    """
    base = root / "src" / dotted.replace(".", "/")
    targets: list[str] = []
    single = Path(str(base) + ".py")
    if single.is_file():
        targets.append(single.relative_to(root).as_posix())
    elif (base / "__init__.py").is_file():
        targets.append((base / "__init__.py").relative_to(root).as_posix())
    elif not base.is_dir():
        raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_IMPORT_UNRESOLVED:" + dotted)
    for name in re.findall(r"\b[A-Za-z_]\w*\b", names):
        candidate = Path(str(base / name) + ".py")
        if name != "as" and candidate.is_file():
            targets.append(candidate.relative_to(root).as_posix())
    return tuple(targets)


def owned_source_closure(
    owned_paths: Iterable[str], object_id: str = "", root: Path = REPOSITORY_ROOT
) -> tuple[str, ...]:
    """Project-local modules bound to one row's owned bytes, bounded and fail-closed.

    Seeds are the owned Python paths, the scripts or verifier modules the owned
    bytes invoke, and every project-local module that names an owned path or the
    row's object id.  The closure follows ``verifier.*`` imports transitively.
    Declaration modules for this catalog and its ownership partition are excluded
    because they are the audit itself, not behavior of the represented object.
    """
    paths = tuple(owned_paths)
    names = set(paths) | ({object_id} if object_id else set())
    seeds: set[str] = {path for path in paths if path.endswith(".py")}
    for path in paths:
        seeds.update(_INVOKED_SOURCE.findall(_read_owned(root, path)))
    for base in ("src/verifier", "scripts"):
        for module in sorted((root / base).rglob("*.py")):
            relpath = module.relative_to(root).as_posix()
            if "__pycache__" in relpath or relpath.startswith(_DECLARATION_PREFIXES):
                continue
            if any(name in module.read_text(encoding="utf-8") for name in names):
                seeds.add(relpath)
    closure: set[str] = set()
    queue = sorted(seeds)
    while queue:
        relpath = queue.pop()
        if relpath in closure or relpath.startswith(_DECLARATION_PREFIXES):
            continue
        closure.add(relpath)
        if len(closure) > SOURCE_CLOSURE_LIMIT:
            raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_CLOSURE_LIMIT")
        if relpath.endswith(".py"):
            for from_module, names, plain_module in _VERIFIER_IMPORT.findall(
                _read_owned(root, relpath)
            ):
                queue.extend(_import_targets(root, from_module or plain_module, names))
    return tuple(sorted(closure))


def owned_source_hits(
    owned_paths: Iterable[str], kind: str, object_id: str = "", root: Path = REPOSITORY_ROOT
) -> tuple[str, ...]:
    """Every ``path:line:marker`` where the closed screen for ``kind`` matches."""
    paths = tuple(owned_paths)
    hits: list[str] = []
    for relpath in paths + owned_source_closure(paths, object_id, root):
        for number, line in enumerate(_read_owned(root, relpath).splitlines(), 1):
            for name, pattern in _OWNED_SOURCE_SCREEN[kind]:
                if pattern.search(line):
                    hits.append(relpath + ":" + str(number) + ":" + name)
    return tuple(dict.fromkeys(hits))


def owned_screen_digest(
    owned_paths: Iterable[str], object_id: str = "", root: Path = REPOSITORY_ROOT
) -> str:
    """Digest the exact project-local source closure used by a denial screen."""

    inventory = []
    for relpath in owned_source_closure(owned_paths, object_id, root):
        path = _owned_path(Path(root), relpath)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise ValueError("REPOSITORY_ASSET_OWNED_SOURCE_UNAVAILABLE:" + relpath) from error
        inventory.append(
            {"path": relpath, "sha256": "sha256:" + sha256(data).hexdigest()}
        )
    return _canonical_digest(inventory)


def _question(kind: str, status: str, evidence: str = "") -> tuple[str, str, str]:
    """Name one kind literally; no default status is ever filled in."""
    return kind, status, evidence


def _reason(kind: str, status: str, evidence: str, scope: str) -> str:
    if status == APPLIES and evidence == "primary":
        return (
            scope
            + " The source-declared primary kind "
            + kind
            + " establishes this row's original role. This establishes applicability "
              "only, not mechanism truth, conformance, admission, or release."
        )
    if status == APPLIES and evidence == "root_role_decision":
        return (
            scope
            + " The source-declared root role decision APPLIES for "
            + kind
            + ", establishing this accumulated role. This establishes applicability "
              "only, not mechanism truth, conformance, admission, or release."
        )
    if status == DOES_NOT_APPLY:
        return (
            scope
            + " Source-bound exclusion for "
            + kind
            + ": the row's own owned declaration states \""
            + evidence
            + "\", which directly denies that this exact row is "
            + _KIND_CRITERIA[kind]
            + "."
        )
    return (
        scope
        + " No feature-near source decision establishes or refutes whether this exact "
          "row itself is "
        + _KIND_CRITERIA[kind]
        + ". Referenced inputs, outputs, subjects, consequences, and operands are not "
          "role equivalence, so "
        + kind
        + " remains UNRESOLVED."
    )


def _record(
    object_id: str,
    expected_primary: str,
    expected_owned_paths: tuple[str, ...],
    expected_source_coordinate_digest: str,
    scope: str,
    selections: tuple[tuple[str, str, str], ...],
) -> RepositoryAssetOriginalKindAudit:
    if tuple(kind for kind, _status, _evidence in selections) != ORIGINAL_NON_OBJECT_KINDS:
        raise AssertionError(object_id + " original-kind question order differs")
    questions = []
    for kind, status, evidence in selections:
        if status == APPLIES:
            if evidence not in {"primary", "root_role_decision"}:
                raise AssertionError(object_id + ":" + kind + " APPLIES basis invalid")
        elif status == DOES_NOT_APPLY:
            if not evidence.strip():
                raise AssertionError(object_id + ":" + kind + " exclusion lacks a quote")
        elif status == UNRESOLVED:
            if evidence:
                raise AssertionError(object_id + ":" + kind + " UNRESOLVED carries evidence")
        else:
            raise AssertionError(object_id + ":" + kind + " status invalid")
        questions.append(
            RepositoryAssetOriginalKindQuestion(
                kind, status, evidence, _reason(kind, status, evidence, scope)
            )
        )
    return RepositoryAssetOriginalKindAudit(
        object_id=object_id,
        expected_primary=expected_primary,
        expected_owned_paths=tuple(expected_owned_paths),
        expected_owned_path_set_digest=owned_path_set_digest(expected_owned_paths),
        expected_owned_content_digest=_EXPECTED_OWNED_CONTENT_DIGESTS[object_id],
        expected_source_coordinate_digest=expected_source_coordinate_digest,
        scope=scope,
        questions=tuple(questions),
    )


REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS = (
    _record(
        "vstd-accelerator-profile-wire-schema",
        "PROTOCOL",
        (
            "receipts/schema/vstd3_accelerator_profile.json",
        ),
        "sha256:c1bc1b791f885e7e36646df262e8bd38f0cfe1e180c2ab12d28824a2365e8620",
        "Published JavaScript Object Notation schema for a declared VSTD-3 accelerator profile.",
        (
        _question("ACTOR", APPLIES, "root_role_decision"),
        _question("AGENT", APPLIES, "root_role_decision"),
        _question("ARCH", APPLIES, "root_role_decision"),
        _question("BENCH", APPLIES, "root_role_decision"),
        _question("BOT", APPLIES, "root_role_decision"),
        _question("COLLECTIVE", APPLIES, "root_role_decision"),
        _question("DATA", APPLIES, "root_role_decision"),
        _question("ENV", APPLIES, "root_role_decision"),
        _question("EVENT", APPLIES, "root_role_decision"),
        _question("GRAPH", APPLIES, "root_role_decision"),
        _question("HARDWARE", APPLIES, "root_role_decision"),
        _question("HARNESS", APPLIES, "root_role_decision"),
        _question("HUMAN", APPLIES, "root_role_decision"),
        _question("HYPER", APPLIES, "root_role_decision"),
        _question("IDENTITY", APPLIES, "root_role_decision"),
        _question("MODEL", APPLIES, "root_role_decision"),
        _question("OWNER", APPLIES, "root_role_decision"),
        _question("RECEIPT", APPLIES, "root_role_decision"),
        _question("ROLE", APPLIES, "root_role_decision"),
        _question("SIM", APPLIES, "root_role_decision"),
        _question("SPACE", APPLIES, "root_role_decision"),
        _question("TIME", APPLIES, "root_role_decision"),
        _question("TOKEN", APPLIES, "root_role_decision"),
        _question("TRAIN", APPLIES, "root_role_decision"),
        _question("VERIFIER", APPLIES, "root_role_decision"),
        ),
    ),
    _record(
        "vstd-documentation-adjacent-standards-crosswalks",
        "ARCH",
        (
            "docs/standards/ADJACENT_STANDARDS_MATRIX.md",
            "docs/standards/SCITT_SEMANTIC_BOUNDARY.md",
            "docs/standards/VSTD_SCITT_CROSSWALK.md",
        ),
        "sha256:95b91319e45f3a53e43226f90f96c52acdc115650a98c7ea92fa72e9905cf15d",
        "Experimental adjacent-standard and Supply Chain Integrity, Transparency, and Trust interoperability crosswalks.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-artifact-interoperability-architecture",
        "ARCH",
        (
            "docs/ARTIFACT_AWARENESS.md",
            "docs/ARTIFACT_NETWORK.md",
            "docs/COMPONENT_HUB.md",
            "docs/COMPONENT_PACKAGES.md",
            "docs/PLATFORM_INTEROPERABILITY.md",
            "docs/REALMS_AND_TIME_CAPSULES.md",
        ),
        "sha256:b182c77e64a131ee45a42fa4a2ed40ae5e5c1fdc8ebb1b38bba3dd2817a4e393",
        "Artifact-awareness, network, stored-component, platform and temporal-realm architecture documentation.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-claim-boundary-policy",
        "POLICY",
        (
            "docs/ACCOUNTABILITY_RELEASE_SCOPE.md",
            "docs/API_STABILITY.md",
            "docs/CLAIMS_AND_LIMITS.md",
            "docs/CURRENT_CERTIFICATE_EMISSION.md",
            "docs/MAINSTAY_COVERAGE.md",
            "docs/RELEASE_FEATURE_GROUNDING.md",
            "docs/TEST_SKIP_RUBRIC.md",
            "docs/V2_CANDIDATE.md",
        ),
        "sha256:3dcad4ec8ad61cef0a4d189cc84dda0d91a22755c6062810512c19c99a0d5db1",
        "Public claim, compatibility, evidence, skip, candidate and release-description boundaries.",
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
    _record(
        "vstd-documentation-control-domain-candidates",
        "POLICY",
        (
            "docs/CONSENT_LEVEL7.md",
            "docs/CONTROL_LEVELS.md",
            "docs/CORRIGIBILITY_CONTROL.md",
            "docs/GOVERNANCE_LEVEL8.md",
            "docs/PRIVACY_LEVEL6_REVIEW.md",
        ),
        "sha256:04b802d0e4c3f8ca1409dac6fc27970a3e2cb1e7110108da323f37719077c1dd",
        "Candidate privacy, consent, governance and cooperative-control obligation boundaries.",
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
    _record(
        "vstd-documentation-core-architecture",
        "ARCH",
        (
            "docs/ARCHITECTURE.md",
            "docs/GROUNDED_CERTIFICATION.md",
            "docs/MATHEMATICAL_FOUNDATIONS.md",
            "docs/VERIFICATION_DRIVEN_DEVELOPMENT.md",
            "docs/VERIFIER_ADMISSION.md",
        ),
        "sha256:8362420ede72b28d89043d1953b37b13f5b1203cc939e93fc829004377b12fd2",
        "Conformance, grounding, mathematical and verification-development architecture documentation.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-derived-metadata",
        "DATA",
        (
            "docs/API_MEMBER_SUMMARIES.json",
            "docs/PR_SOURCE_FEATURES.json",
            "docs/platform-component-contracts.json",
        ),
        "sha256:0c96d7f53454b410de44b4eebca1f59f03996b2b0c6a514afaeb2d6e7e85415e",
        "Generated application programming interface member summaries, pull-request source features and static platform-component contract data.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-environment-graph-architecture",
        "ARCH",
        (
            "docs/ENVIRONMENTS.md",
            "docs/ENVIRONMENT_CONTRACT.md",
            "docs/GRAPH_TOPOLOGY.md",
        ),
        "sha256:97d87ea2d048e3647a42151e392b317e36f66fe28974a6fa275265d0cd45d825",
        "Environment contract, direct namespace and bounded graph-topology architecture documentation.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-hosting-protocol",
        "PROTOCOL",
        (
            "docs/DOCUMENTATION_HOSTING.md",
        ),
        "sha256:ba2d48d5c57ba2150c8831b1cd2a6ea5bd7f7aedf71587f5334c74c5cfecc7f6",
        "Documentation build, promotion, hosting-coordinate and historical live-observation protocol description.",
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
    _record(
        "vstd-documentation-local-tool-protocols",
        "PROTOCOL",
        (
            "docs/FIRST_RECEIPT.md",
            "docs/GATE_AUTOMATION.md",
            "docs/tutorials/SEAL_AN_ARTIFACT.md",
            "docs/tutorials/YOUR_FIRST_VERIFIABLE_SOFTWARE.md",
        ),
        "sha256:358ca2718ea69a800aad99db9ba5c546d8390ad662fb8ab3241bef1349e6ee9f",
        "Local receipt, gate, artifact-seal and polish tutorial procedures with explicit result boundaries.",
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
    _record(
        "vstd-documentation-reader-reference",
        "DATA",
        (
            "docs/ACRONYMS.md",
            "docs/CONCEPTS_AND_PRECEDENTS.md",
            "docs/ECOSYSTEM.md",
            "docs/USE_CASES.md",
        ),
        "sha256:7c5bee9f17a00fef460de3a0badcdbd58add9f959079b02f008155d66d85c8c7",
        "Reader-facing terminology, precedent, ecosystem and use-case reference material.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-documentation-remote-submission-protocols",
        "PROTOCOL",
        (
            "docs/CLAIMGARDEN_SIM_ARTIFACT.md",
            "docs/GATED_PUBLISH.md",
            "docs/tutorials/PUBLISH_A_CLAIM.md",
            "docs/tutorials/PUBLISH_A_SILO.md",
        ),
        "sha256:10e15306309cda9bee48671e416e1d85dceb1987a0aeb9c3d1414afae97ec5dc",
        "Claim, simulation-artifact and silo submission procedures and response-state boundaries.",
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
    _record(
        "vstd-documentation-user-navigation",
        "DATA",
        (
            "docs/INSTALLATION.md",
            "docs/NEWCOMER_GUIDE.md",
            "docs/PYTHON_API_GUIDE.md",
            "docs/QUICKSTART.md",
            "docs/REPOSITORY_WALKTHROUGH.md",
        ),
        "sha256:c0a7972e2b0728839013560847a9e7c4d07c9295b163d2706a1783d864a63e37",
        "Installation, newcomer, application programming interface, quickstart and repository navigation guides.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-generated-distribution-metadata",
        "DATA",
        (
            "src/verifier_standard.egg-info/PKG-INFO",
            "src/verifier_standard.egg-info/SOURCES.txt",
            "src/verifier_standard.egg-info/dependency_links.txt",
            "src/verifier_standard.egg-info/entry_points.txt",
            "src/verifier_standard.egg-info/requires.txt",
            "src/verifier_standard.egg-info/top_level.txt",
        ),
        "sha256:fbcf056094ef409dfec873cbe746db1c5dfc8643fc0928cb915a21266faa66a9",
        "Generated Python distribution description, source inventory, dependency, entry-point and top-level package metadata.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-github-contribution-form-policy",
        "POLICY",
        (
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/ISSUE_TEMPLATE/counterexample.yml",
            ".github/ISSUE_TEMPLATE/implementation-report.yml",
            ".github/ISSUE_TEMPLATE/specification-ambiguity.yml",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ),
        "sha256:452f384130084486e69433882a05fe8dd68762e8010dfe4545b00b694fcecefc",
        "Issue and pull-request intake forms for counterexamples, implementation reports and specification ambiguity.",
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
    _record(
        "vstd-github-documentation-deployment-protocol",
        "PROTOCOL",
        (
            ".github/workflows/pages.yml",
        ),
        "sha256:7940385ef9e312d7567e3b0f815816f0d201544962612887c66dcfcc94c082c6",
        "Hosted documentation build, promotion, deployment and observation workflow declaration.",
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
    _record(
        "vstd-github-external-link-policy",
        "POLICY",
        (
            ".github/external-links-allowlist.txt",
        ),
        "sha256:7a20428e74f34c0005e003bfc5ce363c58a4d3707ced4814f4f3f38c6c3bdf22",
        "Explicit external-link exceptions for the repository presentation gate.",
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
    _record(
        "vstd-github-promotion-policy-protocols",
        "PROTOCOL",
        (
            ".github/workflows/pr-policy-notification.yml",
            ".github/workflows/pr-policy.yml",
        ),
        "sha256:45134c9dc0962c67447cecb8a097f517434b7c9f0afeb2acecd679d9bae8cc78",
        "Hosted notification and default-branch promotion-policy workflow declarations.",
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
    _record(
        "vstd-github-release-workflow-protocol",
        "PROTOCOL",
        (
            ".github/workflows/release.yml",
        ),
        "sha256:ca0b03dec77a994215576717ae75691de0ebe045531abff05ba831806714815b",
        "Hosted artifact build, comparison, verification and release workflow declaration.",
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
    _record(
        "vstd-github-source-description-workflow-protocol",
        "PROTOCOL",
        (
            ".github/workflows/pr-description.yml",
        ),
        "sha256:4664fcf834c1da3d74dbaed86bf0b1fb4963aa74bcda84aafd8e0d0e0598ae37",
        "Hosted pull-request source-description coverage workflow declaration.",
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
    _record(
        "vstd-github-verification-workflow-protocols",
        "PROTOCOL",
        (
            ".github/workflows/ci.yml",
            ".github/workflows/external-links.yml",
        ),
        "sha256:2a3ab82a8dd256a35f1a3ec218737fe355a75e16eb98df28ede51e7140da2ab9",
        "Hosted continuous-integration and external-link workflow declarations.",
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
    _record(
        "vstd-receipt-wire-schema-catalog",
        "PROTOCOL",
        (
            "receipts/schema/vstd1_generic_run_receipt.json",
            "receipts/schema/vstd1_receipt.json",
            "receipts/schema/vstd2_receipt.json",
            "receipts/schema/vstd3_receipt.json",
            "receipts/schema/vstd4_certificate.json",
            "receipts/schema/vstd4_receipt.json",
            "receipts/schema/vstd5_receipt.json",
            "receipts/schema/vstd_graph_receipt.json",
        ),
        "sha256:30210f1a73922adf22888a631c39145f6b45983792cf25926ea9b5bb8bd8542d",
        "Published JavaScript Object Notation schemas for numbered, graph and generic-run receipt records.",
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
    _record(
        "vstd-repository-agent-operating-policy",
        "POLICY",
        (
            "AGENTS.md",
            "CLAUDE.md",
            "HUMANS.md",
        ),
        "sha256:6bfe5045b38e3250e25a6e0452c9118401e1ed6b2cbc1d456ee379c28cdfeab8",
        "Automated-agent and human operating guidance for repository work.",
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
    _record(
        "vstd-repository-citation-metadata",
        "DATA",
        (
            ".zenodo.json",
            "CITATION.cff",
        ),
        "sha256:0408ab6e10081cebff69b378eeed520b77e2c0268b8a7378d610ccd09c0e79d5",
        "Repository citation and prospective archival-deposit metadata.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-repository-community-governance-policy",
        "POLICY",
        (
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "GOVERNANCE.md",
            "SECURITY.md",
        ),
        "sha256:55d927d4bcd62205498af42a346c68a3d33807f758959782fcd7f7cc6887a9a2",
        "Community conduct, contribution, governance and vulnerability-reporting policy.",
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
    _record(
        "vstd-repository-file-and-package-policy",
        "POLICY",
        (
            ".gitattributes",
            ".gitignore",
            "MANIFEST.in",
        ),
        "sha256:33d13f6c90e3b29fcd84948bb377c5cd5310e28b716b7132d3b74e47c3fb05e2",
        "Repository text-normalization, ignored-path and source-distribution inclusion declarations.",
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
    _record(
        "vstd-repository-history-and-roadmap",
        "DATA",
        (
            "CHANGELOG.md",
            "ROADMAP.md",
        ),
        "sha256:cf3876a24164a4f3808d423c852a87c53751a3675648f2678ce400b00a50cec9",
        "Declared change history and public technical roadmap.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-repository-legal-notices",
        "POLICY",
        (
            "LICENSE",
            "NOTICE",
        ),
        "sha256:5c0e05315f30a4ae9bbf2e521296848640434db1e2d96097250f97ad3afaf7fb",
        "Distributed license terms and repository copyright notice.",
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
    _record(
        "vstd-repository-overview",
        "DATA",
        (
            "README.md",
        ),
        "sha256:8ea33a49a12a03b0222c2f0d8eaf88372eb3c53f63271679c340c561bbc73f6d",
        "Repository orientation, capability summary and bounded public entry points.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
    _record(
        "vstd-repository-release-procedure-policy",
        "POLICY",
        (
            "RELEASING.md",
            "TIME.md",
        ),
        "sha256:f95dd1c592cbbec7a27c06b22cda3ac7ed7f72d776950205ca241ebdd035ca8d",
        "Maintainer release procedure and live repository-contradiction annunciator policy.",
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
    _record(
        "vstd-repository-source-admission-designs",
        "ARCH",
        (
            "ADMITTED_ROOT_BINDING_DESIGN.md",
            "EXACT_MATERIALIZED_MEMBER_ADAPTER_DESIGN.md",
            "EXACT_SOURCE_SCOPE_READER_DESIGN.md",
            "WINDOWS_ANCHORED_MEMBER_OPENER_DESIGN.md",
        ),
        "sha256:76fb0fe588607feeea49b0fab898f9edfcfb37c9ade327c997d741ccdbea641a",
        "Test-first designs for admitted roots, exact selected members and anchored source acquisition.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", APPLIES, "primary"),
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
    _record(
        "vstd-retained-facet-policy-inputs",
        "POLICY",
        (
            ".vstd/instance-evidence/bounded-structural-20261013/generic-policy.json",
            ".vstd/instance-evidence/bounded-structural-20261013/typed-policy.json",
            ".vstd/instance-evidence/current-representations-20261013/policy-0.json",
            ".vstd/instance-evidence/current-representations-20261013/policy-1.json",
        ),
        "sha256:37c3f9f4a96c50a183ac72fd1667489dce65c23573d86e6cfefb3ca14a991437",
        "Retained object-facet and typed-facet mechanism-policy inputs for two dated instance-evidence cohorts.",
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
    _record(
        "vstd-retained-graph-statics-certificate",
        "DATA",
        (
            ".vstd/instance-evidence/current-representations-20261013/graph-statics-certificate.json",
        ),
        "sha256:b845dc80fc6c339339d906b55d54773b3dd9e02ca0eeaa2c5a7a406f6bbfefde",
        "Retained graph-statics certificate record for the dated package-graph request.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
        _question("RECEIPT", APPLIES, "root_role_decision"),
        _question("ROLE", UNRESOLVED),
        _question("SIM", UNRESOLVED),
        _question("SPACE", UNRESOLVED),
        _question("TIME", UNRESOLVED),
        _question("TOKEN", UNRESOLVED),
        _question("TRAIN", UNRESOLVED),
        _question("VERIFIER", UNRESOLVED),
        ),
    ),
    _record(
        "vstd-retained-graph-statics-policy-input",
        "POLICY",
        (
            ".vstd/instance-evidence/current-representations-20261013/graph-statics-policy.json",
        ),
        "sha256:330989581b9bdc4a56af80fcd338fa4fc766b3806d8a63539adc2caf9ece1d15",
        "Retained graph-statics mechanism-policy input for the dated current-representations cohort.",
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
    _record(
        "vstd-retained-graph-statics-request",
        "PROTOCOL",
        (
            ".vstd/instance-evidence/current-representations-20261013/graph-statics-request.json",
        ),
        "sha256:60580f20d9671609ec78517a0b1c2ef1bce5dde29f08621faf129b5c3db80981",
        "Retained graph-statics request message binding the selected package-graph digests and limits.",
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
    _record(
        "vstd-retained-object-facet-certificates",
        "DATA",
        (
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-invocation-ledger-OBJECT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-manifest-write-OBJECT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-object-OBJECT-1.1.certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-invocation-ledger-OBJECT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-manifest-write-OBJECT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-object-OBJECT-1.1-certificate.json",
        ),
        "sha256:f7e23160a85a26101bea2ba2f04533260a806e9e05d51080a4a0351f8f3d4abd",
        "Retained generic object-facet certificate records for two dated instance-evidence cohorts.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
        _question("RECEIPT", APPLIES, "root_role_decision"),
        _question("ROLE", UNRESOLVED),
        _question("SIM", UNRESOLVED),
        _question("SPACE", UNRESOLVED),
        _question("TIME", UNRESOLVED),
        _question("TOKEN", UNRESOLVED),
        _question("TRAIN", UNRESOLVED),
        _question("VERIFIER", UNRESOLVED),
        ),
    ),
    _record(
        "vstd-retained-object-facet-requests",
        "PROTOCOL",
        (
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-invocation-ledger-OBJECT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-manifest-write-OBJECT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-object-OBJECT-1.1.request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-invocation-ledger-OBJECT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-manifest-write-OBJECT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-object-OBJECT-1.1-request.json",
        ),
        "sha256:a402de7743e275e588150b6e0a8210cc828d9245c269ef6fedf6a2664cb912d4",
        "Retained generic object-facet request messages for the selected package, invocation-ledger and manifest-write subjects.",
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
    _record(
        "vstd-retained-typed-facet-certificates",
        "DATA",
        (
            ".vstd/instance-evidence/bounded-structural-20261013/verifier-core-self-VERIFIER-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-actor-ACTOR-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-agent-AGENT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-architecture-ARCH-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-benchmark-BENCH-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-bot-BOT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-collective-COLLECTIVE-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-data-DATA-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-environment-ENV-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-event-EVENT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-hardware-HARDWARE-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-harness-HARNESS-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-human-HUMAN-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-hypergraph-HYPER-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-identity-IDENTITY-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-invocation-ledger-OBJECT-1.2.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-manifest-write-OBJECT-1.2.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-model-MODEL-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-owner-OWNER-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-graph-GRAPH-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-object-OBJECT-1.2.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-receipt-RECEIPT-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-role-ROLE-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-simulation-SIM-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-space-SPACE-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-time-TIME-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-token-TOKEN-1.1.certificate.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-training-TRAIN-1.1.certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/verifier-core-self-VERIFIER-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-actor-ACTOR-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-agent-AGENT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-architecture-ARCH-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-benchmark-BENCH-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-bot-BOT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-collective-COLLECTIVE-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-data-DATA-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-environment-ENV-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-event-EVENT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-hardware-HARDWARE-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-harness-HARNESS-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-human-HUMAN-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-hypergraph-HYPER-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-identity-IDENTITY-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-invocation-ledger-OBJECT-1.2-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-manifest-write-OBJECT-1.2-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-model-MODEL-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-owner-OWNER-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-graph-GRAPH-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-object-OBJECT-1.2-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-receipt-RECEIPT-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-role-ROLE-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-simulation-SIM-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-space-SPACE-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-time-TIME-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-token-TOKEN-1.1-certificate.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-training-TRAIN-1.1-certificate.json",
        ),
        "sha256:baf0157a9dd1c41b624cc1a8cacf07e06c06174fb6e9788e158308e2d3f4377f",
        "Retained typed-facet certificate records for the exact dated subject and coordinate denominator.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
        _question("RECEIPT", APPLIES, "root_role_decision"),
        _question("ROLE", UNRESOLVED),
        _question("SIM", UNRESOLVED),
        _question("SPACE", UNRESOLVED),
        _question("TIME", UNRESOLVED),
        _question("TOKEN", UNRESOLVED),
        _question("TRAIN", UNRESOLVED),
        _question("VERIFIER", UNRESOLVED),
        ),
    ),
    _record(
        "vstd-retained-typed-facet-requests",
        "PROTOCOL",
        (
            ".vstd/instance-evidence/bounded-structural-20261013/verifier-core-self-VERIFIER-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-actor-ACTOR-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-agent-AGENT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-architecture-ARCH-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-benchmark-BENCH-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-bot-BOT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-collective-COLLECTIVE-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-data-DATA-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-environment-ENV-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-event-EVENT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-hardware-HARDWARE-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-harness-HARNESS-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-human-HUMAN-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-hypergraph-HYPER-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-identity-IDENTITY-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-invocation-ledger-OBJECT-1.2.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-manifest-write-OBJECT-1.2.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-model-MODEL-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-owner-OWNER-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-graph-GRAPH-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-package-object-OBJECT-1.2.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-receipt-RECEIPT-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-role-ROLE-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-simulation-SIM-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-space-SPACE-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-time-TIME-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-token-TOKEN-1.1.request.json",
            ".vstd/instance-evidence/bounded-structural-20261013/vstd-training-TRAIN-1.1.request.json",
            ".vstd/instance-evidence/current-representations-20261013/verifier-core-self-VERIFIER-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-actor-ACTOR-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-agent-AGENT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-architecture-ARCH-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-benchmark-BENCH-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-bot-BOT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-collective-COLLECTIVE-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-data-DATA-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-environment-ENV-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-event-EVENT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-hardware-HARDWARE-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-harness-HARNESS-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-human-HUMAN-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-hypergraph-HYPER-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-identity-IDENTITY-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-invocation-ledger-OBJECT-1.2-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-manifest-write-OBJECT-1.2-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-model-MODEL-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-owner-OWNER-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-graph-GRAPH-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-package-object-OBJECT-1.2-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-receipt-RECEIPT-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-role-ROLE-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-simulation-SIM-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-space-SPACE-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-time-TIME-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-token-TOKEN-1.1-request.json",
            ".vstd/instance-evidence/current-representations-20261013/vstd-training-TRAIN-1.1-request.json",
        ),
        "sha256:e5b261cef7f90048422637f5cafeeb619d5c4abc6bed72622aba800875016fd8",
        "Retained typed-facet request messages for the exact dated subject and coordinate denominator.",
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
    _record(
        "vstd-root-uv-dependency-resolution",
        "DATA",
        (
            "uv.lock",
        ),
        "sha256:ed8bca997ef82605c0bb048821da616361d4fa66448c319510a0754f1e197a5c",
        "Retained root uv dependency-resolution record with exact package versions, artifacts, hashes, markers, and resolver revision.",
        (
        _question("ACTOR", UNRESOLVED),
        _question("AGENT", UNRESOLVED),
        _question("ARCH", UNRESOLVED),
        _question("BENCH", UNRESOLVED),
        _question("BOT", UNRESOLVED),
        _question("COLLECTIVE", UNRESOLVED),
        _question("DATA", APPLIES, "primary"),
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
)


# Adversarial passes over the 54 prior DOES_NOT_APPLY cells.  Each entry was recorded
# UNRESOLVED after review; the sentence and its basis are pinned in the tests.
DEMOTED_EXCLUSIONS: tuple[tuple[str, str, str], ...] = (
    ("vstd-documentation-claim-boundary-policy", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-documentation-claim-boundary-policy", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-documentation-core-architecture", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-documentation-hosting-protocol", "ACTOR", ENUMERATED_SUBTYPE),
    ("vstd-documentation-hosting-protocol", "RECEIPT", ENUMERATED_SUBTYPE),
    ("vstd-documentation-reader-reference", "RECEIPT", ENUMERATED_SUBTYPE),
    ("vstd-documentation-reader-reference", "VERIFIER", ENUMERATED_SUBTYPE),
    ("vstd-documentation-remote-submission-protocols", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-documentation-remote-submission-protocols", "IDENTITY", ACTIVITY_OR_PROOF),
    ("vstd-documentation-remote-submission-protocols", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-documentation-environment-graph-architecture", "ENV", ACTIVITY_OR_PROOF),
    ("vstd-github-contribution-form-policy", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-github-documentation-deployment-protocol", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-github-documentation-deployment-protocol", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-github-external-link-policy", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-github-external-link-policy", "IDENTITY", ACTIVITY_OR_PROOF),
    ("vstd-github-promotion-policy-protocols", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-github-promotion-policy-protocols", "EVENT", SOURCE_COUNTEREXAMPLE),
    ("vstd-github-promotion-policy-protocols", "HUMAN", ACTIVITY_OR_PROOF),
    ("vstd-github-promotion-policy-protocols", "RECEIPT", ACTIVITY_OR_PROOF),
    ("vstd-github-promotion-policy-protocols", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-github-promotion-policy-protocols", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-github-release-workflow-protocol", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-github-release-workflow-protocol", "RECEIPT", ENUMERATED_SUBTYPE),
    ("vstd-github-release-workflow-protocol", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-github-source-description-workflow-protocol", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-github-source-description-workflow-protocol", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-github-verification-workflow-protocols", "RECEIPT", ENUMERATED_SUBTYPE),
    ("vstd-github-verification-workflow-protocols", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-receipt-wire-schema-catalog", "IDENTITY", ACTIVITY_OR_PROOF),
    ("vstd-receipt-wire-schema-catalog", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-repository-agent-operating-policy", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-repository-agent-operating-policy", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-repository-agent-operating-policy", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-repository-community-governance-policy", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-repository-community-governance-policy", "IDENTITY", ACTIVITY_OR_PROOF),
    ("vstd-repository-community-governance-policy", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-repository-legal-notices", "IDENTITY", ACTIVITY_OR_PROOF),
    ("vstd-repository-legal-notices", "RECEIPT", ACTIVITY_OR_PROOF),
    ("vstd-repository-release-procedure-policy", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-repository-release-procedure-policy", "RECEIPT", ENUMERATED_SUBTYPE),
    ("vstd-repository-source-admission-designs", "RECEIPT", ACTIVITY_OR_PROOF),
    ("vstd-repository-source-admission-designs", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-retained-graph-statics-certificate", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-retained-graph-statics-policy-input", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-retained-graph-statics-policy-input", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-retained-graph-statics-request", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-retained-object-facet-certificates", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-retained-object-facet-certificates", "VERIFIER", ACTIVITY_OR_PROOF),
    ("vstd-retained-object-facet-requests", "VERIFIER", UNCLOSED_EFFECT_BOUNDARY),
    ("vstd-retained-typed-facet-certificates", "ACTOR", ACTIVITY_OR_PROOF),
    ("vstd-retained-typed-facet-certificates", "ROLE", ACTIVITY_OR_PROOF),
    ("vstd-retained-typed-facet-certificates", "VERIFIER", ACTIVITY_OR_PROOF),
)

REPOSITORY_ASSET_PARTIAL_PROFILE = seal_profile(
    "verifier-repository-asset-original-kind-review",
    1,
    CLAIM_BOUNDARY,
    tuple(
        OriginalKindAssignment(
            object_id=row.object_id,
            expected_primary=row.expected_primary,
            expected_owned_paths=row.expected_owned_paths,
            expected_owned_path_set_digest=row.expected_owned_path_set_digest,
            scope_reason=row.scope,
            decisions=tuple(
                OriginalKindDecision(question.kind, question.status, question.reason)
                for question in row.questions
                if question.status != UNRESOLVED
            ),
        )
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
        if any(question.status != UNRESOLVED for question in row.questions)
    ),
)


def current_source_partition() -> tuple[SemanticOwnershipSpec, ...]:
    """Return the exact imported repository-asset rows, sorted by object id."""
    return tuple(
        sorted(REPOSITORY_ASSET_OWNERSHIP_SPECS, key=lambda spec: spec.object_id)
    )


def _effect_blocker_reproduces(
    owned_paths: Iterable[str], object_id: str, blocker: tuple[str, str], root: Path
) -> bool:
    """True only when the consumer is outside the closure yet reads every owned byte.

    The consumer must hold the schema identifier that the row's owned bytes carry.
    Any unreadable, aliased, or in-closure consumer fails to reproduce the blocker.
    """
    paths = tuple(owned_paths)
    consumer, identifier = blocker
    try:
        consumer_text = _read_owned(root, consumer)
        owned_texts = [_read_owned(root, relpath) for relpath in paths]
    except ValueError:
        return False
    if identifier not in consumer_text or not all(identifier in text for text in owned_texts):
        return False
    return consumer not in owned_source_closure(paths, object_id, root)


def validate_source_partition(
    specs: Iterable[SemanticOwnershipSpec] | None = None,
    audits: Iterable[RepositoryAssetOriginalKindAudit] = (
        REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    ),
    *,
    source_root: Path | None = None,
) -> tuple[SemanticOwnershipSpec, ...]:
    """Fail closed unless the audit matches the live rows exactly.

    Checks the object denominator, primary kind, owned paths, path-set digest,
    full coordinate digest, scope text, every APPLIES basis, and every
    DOES_NOT_APPLY quote, which must be verbatim source text carrying an explicit
    negation.  Each DOES_NOT_APPLY must also be listed in ``IDENTITY_DENIALS`` and
    survive the closed owned-source screen under ``source_root``; a demotion must
    be UNRESOLVED, and a SOURCE_COUNTEREXAMPLE demotion must reproduce its hit.
    An established source role cannot be left UNRESOLVED, and a primary kind
    cannot be refuted.
    """
    root = REPOSITORY_ROOT if source_root is None else Path(source_root)
    selected = tuple(
        sorted(
            current_source_partition() if specs is None else tuple(specs),
            key=lambda spec: spec.object_id,
        )
    )
    if any(type(spec) is not SemanticOwnershipSpec for spec in selected) or len(
        {spec.object_id for spec in selected}
    ) != len(selected):
        raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_SOURCE_PARTITION_INVALID")
    rows = tuple(audits)
    if any(type(row) is not RepositoryAssetOriginalKindAudit for row in rows) or len(
        {row.object_id for row in rows}
    ) != len(rows):
        raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_AUDIT_INVALID")
    source = {spec.object_id: spec for spec in selected}
    if set(source) != {row.object_id for row in rows}:
        raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_DENOMINATOR_DRIFT")
    if set(_EXPECTED_OWNED_CONTENT_DIGESTS) != set(source):
        raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_CONTENT_DENOMINATOR_DRIFT")
    # Snapshot every owned byte before semantic validation.  Recompute after all
    # checks so a concurrent writer cannot produce a mixed-coordinate success.
    before_content = {
        row.object_id: owned_content_digest(row.expected_owned_paths, root)
        for row in rows
    }
    for row in rows:
        if row.expected_owned_content_digest != _EXPECTED_OWNED_CONTENT_DIGESTS[row.object_id]:
            raise ValueError(
                "REPOSITORY_ASSET_ORIGINAL_KIND_CONTENT_DIGEST_SUBSTITUTION:"
                + row.object_id
            )
        if before_content[row.object_id] != row.expected_owned_content_digest:
            raise ValueError(
                "REPOSITORY_ASSET_ORIGINAL_KIND_OWNED_CONTENT_DRIFT:" + row.object_id
            )
    seen_paths: set[str] = set()
    kinds = set(ORIGINAL_NON_OBJECT_KINDS)
    for row in rows:
        spec = source[row.object_id]
        if spec.primary_kind == "OBJECT" or row.expected_primary == "OBJECT":
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_OBJECT_BYPASS:" + row.object_id)
        if spec.primary_kind != row.expected_primary:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_PRIMARY_DRIFT:" + row.object_id)
        if tuple(spec.owned_paths) != row.expected_owned_paths:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_PATH_DRIFT:" + row.object_id)
        if owned_path_set_digest(spec.owned_paths) != row.expected_owned_path_set_digest:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_PATH_DIGEST_DRIFT:" + row.object_id)
        if seen_paths & set(spec.owned_paths):
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_PATH_OVERLAP:" + row.object_id)
        seen_paths.update(spec.owned_paths)
        if _source_coordinate_digest(spec) != row.expected_source_coordinate_digest:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_COORDINATE_DRIFT:" + row.object_id)
        if row.scope != spec.representation_role:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_SCOPE_DRIFT:" + row.object_id)
        if tuple(question.kind for question in row.questions) != ORIGINAL_NON_OBJECT_KINDS:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_DENOMINATOR_DRIFT:" + row.object_id)
        # Source-established roles: the primary kind, specializations that are
        # original kinds, and root decisions with status APPLIES.
        established: dict[str, str] = {}
        if spec.primary_kind in kinds:
            established[spec.primary_kind] = "primary"
        for specialization in spec.specializations:
            if specialization in kinds:
                established.setdefault(specialization, "specialization")
        for decision in spec.root_role_decisions:
            if decision.kind in kinds and decision.status == APPLIES:
                established[decision.kind] = "root_role_decision"
        source_refuted = {
            decision.kind
            for decision in spec.root_role_decisions
            if decision.kind in kinds and decision.status == DOES_NOT_APPLY
        }
        if set(established) & source_refuted:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_SOURCE_ROLE_CONFLICT:" + row.object_id)
        text = _spec_text(spec)
        for question in row.questions:
            if question.status == APPLIES:
                if established.get(question.kind) != question.evidence:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_UNESTABLISHED_APPLIES:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
            elif question.status == DOES_NOT_APPLY:
                if question.kind in established or question.kind == row.expected_primary:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_ESTABLISHED_ROLE_REFUTED:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                if (row.object_id, question.kind) in UNCLOSED_EFFECT_BLOCKERS:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_EFFECT_BOUNDARY_BLOCKED:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                if question.kind not in source_refuted and (
                    not question.evidence or question.evidence not in text
                ):
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_EXCLUSION_NOT_SOURCE_BOUND:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                if not _is_negated(question.evidence):
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_EXCLUSION_NOT_NEGATED:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                denial = IDENTITY_DENIALS.get((row.object_id, question.kind))
                if (
                    denial is None
                    or question.evidence != denial[0]
                    or denial[1] not in question.evidence
                ):
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_DENIAL_NOT_IDENTITY_BASED:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                screen_before = owned_screen_digest(
                    spec.owned_paths, spec.object_id, root
                )
                screen_hits = owned_source_hits(
                    spec.owned_paths, question.kind, spec.object_id, root
                )
                screen_after = owned_screen_digest(
                    spec.owned_paths, spec.object_id, root
                )
                if screen_after != screen_before:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_SCREEN_SOURCE_CHANGED:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                if screen_hits:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_SOURCE_COUNTEREXAMPLE:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
                if _EXPECTED_IDENTITY_SCREEN_DIGESTS.get(
                    (row.object_id, question.kind)
                ) != screen_before:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_SCREEN_COORDINATE_DRIFT:"
                        + row.object_id
                        + ":"
                        + question.kind
                    )
            elif question.status == UNRESOLVED:
                if question.evidence:
                    raise ValueError(
                        "REPOSITORY_ASSET_ORIGINAL_KIND_UNRESOLVED_CARRIES_EVIDENCE:"
                        + row.object_id
                    )
            else:
                raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_STATUS_INVALID")
        applied = {q.kind for q in row.questions if q.status == APPLIES}
        if applied != set(established):
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_ESTABLISHED_ROLE_OMITTED:" + row.object_id)
        refuted = {q.kind for q in row.questions if q.status == DOES_NOT_APPLY}
        if not source_refuted <= refuted:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_SOURCE_EXCLUSION_OMITTED:" + row.object_id)
        for question in row.questions:
            if question.reason != _reason(
                question.kind, question.status, question.evidence, row.scope
            ):
                raise ValueError(
                    "REPOSITORY_ASSET_ORIGINAL_KIND_REASON_DRIFT:"
                    + row.object_id
                    + ":"
                    + question.kind
                )
    rows_by_id = {row.object_id: row for row in rows}
    for object_id, kind, basis in DEMOTED_EXCLUSIONS:
        row = rows_by_id.get(object_id)
        if row is None or basis not in _DEMOTION_BASES or kind not in kinds:
            raise ValueError("REPOSITORY_ASSET_ORIGINAL_KIND_DEMOTION_INVALID:" + object_id)
        status = next(question.status for question in row.questions if question.kind == kind)
        if status != UNRESOLVED:
            raise ValueError(
                "REPOSITORY_ASSET_ORIGINAL_KIND_DEMOTION_NOT_UNRESOLVED:" + object_id + ":" + kind
            )
        if basis == SOURCE_COUNTEREXAMPLE and not owned_source_hits(
            source[object_id].owned_paths, kind, object_id, root
        ):
            raise ValueError(
                "REPOSITORY_ASSET_ORIGINAL_KIND_DEMOTION_WITHOUT_COUNTEREXAMPLE:" + object_id + ":" + kind
            )
        if basis == UNCLOSED_EFFECT_BOUNDARY:
            blocker = UNCLOSED_EFFECT_BLOCKERS.get((object_id, kind))
            if blocker is None or not _effect_blocker_reproduces(
                source[object_id].owned_paths, object_id, blocker, root
            ):
                raise ValueError(
                    "REPOSITORY_ASSET_ORIGINAL_KIND_EFFECT_BOUNDARY_NOT_REPRODUCED:" + object_id + ":" + kind
                )
    for object_id, kind in UNCLOSED_EFFECT_BLOCKERS:
        if (object_id, kind, UNCLOSED_EFFECT_BOUNDARY) not in DEMOTED_EXCLUSIONS:
            raise ValueError(
                "REPOSITORY_ASSET_ORIGINAL_KIND_EFFECT_BOUNDARY_UNLEDGERED:" + object_id + ":" + kind
            )
    after_content = {
        row.object_id: owned_content_digest(row.expected_owned_paths, root)
        for row in rows
    }
    changed = sorted(
        object_id
        for object_id in before_content
        if after_content[object_id] != before_content[object_id]
    )
    if changed:
        raise ValueError(
            "REPOSITORY_ASSET_ORIGINAL_KIND_SOURCE_CHANGED:" + ",".join(changed)
        )
    return selected


def _catalog_check() -> None:
    rows = REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    if len(rows) != EXPECTED_OBJECT_COUNT:
        raise AssertionError("repository-asset original-kind object denominator differs")
    if len({row.object_id for row in rows}) != len(rows):
        raise AssertionError("repository-asset original-kind object ids overlap")
    if set(_EXPECTED_OWNED_CONTENT_DIGESTS) != {row.object_id for row in rows}:
        raise AssertionError("repository-asset owned-content digest denominator differs")
    if any(
        row.expected_owned_content_digest
        != _EXPECTED_OWNED_CONTENT_DIGESTS[row.object_id]
        for row in rows
    ):
        raise AssertionError("repository-asset owned-content digest binding differs")
    recorded_denials = {
        (row.object_id, question.kind)
        for row in rows
        for question in row.questions
        if question.status == DOES_NOT_APPLY
    }
    if set(_EXPECTED_IDENTITY_SCREEN_DIGESTS) != recorded_denials:
        raise AssertionError("repository-asset denial-screen denominator differs")
    if sum(len(row.expected_owned_paths) for row in rows) != EXPECTED_PATH_COUNT:
        raise AssertionError("repository-asset original-kind path denominator differs")
    applies = dne = unresolved = 0
    for row in rows:
        if tuple(question.kind for question in row.questions) != ORIGINAL_NON_OBJECT_KINDS:
            raise AssertionError(row.object_id + " kind denominator differs")
        if any(not question.reason.strip() for question in row.questions):
            raise AssertionError(row.object_id + " contains a blank reason")
        for question in row.questions:
            applies += question.status == APPLIES
            dne += question.status == DOES_NOT_APPLY
            unresolved += question.status == UNRESOLVED
        primary = next(q for q in row.questions if q.kind == row.expected_primary) if (
            row.expected_primary in ORIGINAL_NON_OBJECT_KINDS
        ) else None
        if primary is not None and primary.status != APPLIES:
            raise AssertionError(row.object_id + " primary kind is not APPLIES")
    if (applies, dne, unresolved) != (
        EXPECTED_APPLIES_COUNT,
        EXPECTED_DOES_NOT_APPLY_COUNT,
        EXPECTED_UNRESOLVED_COUNT,
    ):
        raise AssertionError("repository-asset original-kind decision counts differ")
    profile_ids = {assignment.object_id for assignment in REPOSITORY_ASSET_PARTIAL_PROFILE.assignments}
    if len(profile_ids) != EXPECTED_PROFILE_ROW_COUNT:
        raise AssertionError("repository-asset partial-profile row count differs")


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return all 40-by-25 answers; unresolved items are never upgraded."""
    profile_ids = {
        assignment.object_id for assignment in REPOSITORY_ASSET_PARTIAL_PROFILE.assignments
    }
    return {
        row.object_id: {
            "expected_primary": row.expected_primary,
            "expected_owned_paths": list(row.expected_owned_paths),
            "expected_owned_path_set_digest": row.expected_owned_path_set_digest,
            "expected_owned_content_digest": row.expected_owned_content_digest,
            "expected_source_coordinate_digest": row.expected_source_coordinate_digest,
            "scope": row.scope,
            "questions": {
                question.kind: {
                    "status": question.status,
                    "evidence": question.evidence,
                    "reason": question.reason,
                }
                for question in row.questions
            },
            "partial_profile_digest": (
                REPOSITORY_ASSET_PARTIAL_PROFILE.canonical_digest
                if row.object_id in profile_ids
                else None
            ),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for row in REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS
    }


__all__ = [
    "CLAIM_BOUNDARY",
    "DEMOTED_EXCLUSIONS",
    "IDENTITY_DENIALS",
    "REPOSITORY_ASSET_ORIGINAL_KIND_AUDITS",
    "REPOSITORY_ASSET_PARTIAL_PROFILE",
    "RepositoryAssetOriginalKindAudit",
    "RepositoryAssetOriginalKindQuestion",
    "UNCLOSED_EFFECT_BLOCKERS",
    "UNCLOSED_EFFECT_BOUNDARY",
    "UNRESOLVED",
    "current_source_partition",
    "owned_source_closure",
    "owned_content_digest",
    "owned_screen_digest",
    "owned_source_hits",
    "review_document",
    "validate_source_partition",
]

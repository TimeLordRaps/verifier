"""Literal original-kind audit for imported test and normative-asset ownership.

Terminology: Hypertext Markup Language (HTML); JavaScript Object Notation
(JSON); uniform resource identifier (URI).

The aggregate ownership module imports two partitions that the runtime catalog
deliberately excludes: ``package_semantic_ownership_tests_fixtures.py`` (16
test-fixture and regression objects owning 658 paths) and
``package_semantic_ownership_normative_assets.py`` (67 normative contract
objects owning 291 paths).  Every object answers all 25 original non-``OBJECT``
kinds, so the 949-path matrix is 83 by 25 with 2,075 literal questions.

Only two source facts decide a question:

- a source-declared accumulated role (the primary kind, a specialization, or a
  root role decision marked APPLIES) yields APPLIES;
- a verbatim identity denial inside the object's owned declaration (for example
  "not a computational-model ARCH"), or a root role decision marked
  DOES_NOT_APPLY, yields DOES_NOT_APPLY, but only when a closed counterexample
  screen over every owned path and its project-local import closure is recorded
  for that object.  A screen that is UNKNOWN (unresolved calls, dynamic or
  reflective escape, callbacks, subprocess effects, binary assets, external or
  unowned Markdown and JSON reference edges) leaves its denials UNRESOLVED with
  the blocker counts named.  A qualified denial ("not a production HARNESS", "not
  a current RECEIPT", "receipt instances with bound subject") narrows the kind
  and is downgraded to UNRESOLVED; it never decides the unqualified kind.

Everything else stays UNRESOLVED.  Omission, complement, primary-kind
difference, claim-status disclaimers ("establishes no BOT safety"), activity
and instantiation denials ("executes no SIM", "instantiates no BOT"), neighboring
objects, filenames, and OBJECT labeling never decide a question.  A denial must
be an identity predicate: a negated copula ("are not SIMs", "not a computational-model
ARCH") or "does not turn ... into" the subject.  Where a transfer sentence names
an identity boundary ("Testing a HUMAN ... does not turn the test suite into that
subject"), only that identity clause decides, and only for the named kinds.  A
primary original kind cannot be refuted.

Pinned path and declaration digests bind every row to exact current source;
validation rejects substitutions, drift, role conflicts, and OBJECT bypass.  The
sealed profile lists only decided rows and is partial: it proves no package
closure, repository admission, polish conformance, mechanism truth, release, or
deployment.  Verifier Standard (VSTD) ownership records are the source inputs.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Iterator

from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    OriginalKindProfile,
    owned_path_set_digest,
    seal_profile,
)
from verifier.runtime.package_semantic_ownership_model import SemanticOwnershipSpec
from verifier.runtime.package_semantic_ownership_normative_assets import (
    AGENCY_CROSSWALK_APPLIES,
    NORMATIVE_ASSET_OWNERSHIP_SPECS,
)
from verifier.runtime.package_semantic_ownership_tests_fixtures import (
    TEST_FIXTURE_OWNERSHIP_SPECS,
)

UNRESOLVED = "UNRESOLVED"
PROFILE_ID = "verifier-tests-normative-original-kind-review"
# Bounded syntactic screen for an identity denial quote: a negated copula
# ("are not SIMs", "not a computational-model ARCH") or "does not turn ... into".
# Activity or instantiation phrasing ("instantiates no BOT") fails the screen.
# The screen is necessary, not sufficient; each row's identity judgment is
# recorded in REVIEW_ROWS and pinned by its coordinate digest.
_IDENTITY_DENIAL = re.compile(r"\b(?:is|are) not\b|\bnot an? \b|\bdoes not turn\b")
CLAIM_BOUNDARY = (
    "Exact current-source original-kind review for the 16 test-fixture and "
    "67 normative-asset semantic ownership objects imported from "
    "package_semantic_ownership_tests_fixtures.py and "
    "package_semantic_ownership_normative_assets.py (83 objects, 949 owned "
    "paths, 2,075 questions). Only source-declared accumulated roles yield "
    "APPLIES; only verbatim owned-declaration identity denials that also pass a "
    "closed counterexample screen over all owned paths yield DOES_NOT_APPLY; all "
    "other questions remain UNRESOLVED. This partial profile proves no full "
    "package closure, repository admission, polish conformance, mechanism truth, "
    "release, or deployment."
)
# Dynamic, callback, and subprocess effects can route a represented subject to an
# artifact class that no static declaration names, so any one of them keeps the
# screen open for every denial in its object.
_DEFEATING_EFFECTS = frozenset(
    ("callback_injected_callable", "dynamic_import_eval_exec_reflection", "subprocess_process")
)
_ARTIFACT_SUFFIXES = frozenset(
    (
        ".bin", ".ckpt", ".dll", ".dts", ".dtsi", ".exe", ".gguf", ".h5", ".onnx",
        ".pkl", ".pt", ".pth", ".pyc", ".safetensors", ".so", ".wasm",
    )
)
# Words that narrow a kind to a sub-scope ("production HARNESS", "current
# RECEIPT").  A denial through such a word refutes only the narrower class.
_QUALIFIERS = frozenset(
    (
        "authenticated", "authoritative", "candidate", "claimed", "current",
        "durable", "financial", "fresh", "independent", "independently", "individual",
        "legal", "live", "local", "organizational", "package-wide", "passing",
        "physical", "production", "real", "retained", "signed", "synthetic", "trusted",
    )
)
# Words that narrow a kind by a following clause ("instances with bound subject").
_NARROWING_CONNECTIVES = frozenset(
    (
        "bearing", "binding", "bound", "carrying", "for", "from", "having", "in", "of",
        "on", "that", "which", "whose", "with",
    )
)
# Structural reference edges in Markdown: inline link or image, reference
# definition, autolink, and raw HTML href/src.  Prose filename mentions are not
# edges; the screen excludes them by design and says so in counterexample_screen.
_MARKDOWN_EDGE = re.compile(
    r"\]\(\s*<?([^)\s>]+)"
    r"|^[ ]{0,3}\[[^\]\n]+\]:[ \t]*<?([^\s>]+)"
    r"|<((?:https?|mailto|file):[^>\s]+)>"
    r"|\b(?:href|src)\s*=\s*[\"']([^\"']+)[\"']",
    re.MULTILINE | re.IGNORECASE,
)
_URI_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_REPO_ROOT = Path(__file__).resolve().parents[3]
# Identity clause of the current-object consequence boundary, quoted verbatim.
# Only its identity clause ("does not turn the test suite into that subject")
# decides the five named kinds; its evidence-transfer clause is not used.
CURRENT_OBJECT_TRANSFER_DENIAL = (
    "Testing a HUMAN, MODEL, SIM, BOT, HARDWARE, or another represented subject "
    "does not turn the test suite into that subject"
)

# Feature-near criteria for each original kind, used only in UNRESOLVED reasons
# so that an unresolved question names exactly what remains unestablished.
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
class PartitionRow:
    """One pinned object: its exact source coordinate and every decided kind.

    ``applies`` lists kinds the source declares as accumulated roles.
    ``refutes`` pairs each denied kind with the verbatim sentence that denies it;
    a root-decision denial quotes that root decision's reason instead.
    Kinds absent from both tuples are UNRESOLVED, never DOES_NOT_APPLY.
    """

    object_id: str
    primary: str
    path_count: int
    path_set_digest: str
    coordinate_digest: str
    applies: tuple[str, ...] = ()
    refutes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PartitionQuestion:
    """One literal answer for one original kind; status is never inferred."""

    kind: str
    status: str
    reason: str


@dataclass(frozen=True)
class PartitionAudit:
    """One validated object with all 25 original-kind answers in source order."""

    object_id: str
    primary: str
    path_count: int
    path_set_digest: str
    coordinate_digest: str
    questions: tuple[PartitionQuestion, ...]


@dataclass(frozen=True)
class ScreenRecord:
    """Durable counterexample-screen result for one object's complete owned set.

    ``bytes_digest`` binds every owned path to its exact bytes, so any edit
    stales the record.  ``effect_digest`` is the ClosedEffectAudit evidence
    digest over the owned Python sources ("" when there are none).  Project-local
    import resolution reads the repository beyond the owned paths, so an
    effect-bearing record is valid only at the repository root that produced it.
    Only a CLOSED record can support a DOES_NOT_APPLY decision for its object.
    """

    object_id: str
    status: str
    path_count: int
    bytes_digest: str
    effect_digest: str
    blocker_counts: tuple[tuple[str, int], ...]


def _row(
    object_id: str,
    primary: str,
    path_count: int,
    path_set_digest: str,
    coordinate_digest: str,
    *,
    applies: tuple[str, ...] = (),
    refutes: tuple[tuple[str, str], ...] = (),
) -> PartitionRow:
    """Record literal data only; validation happens against source and in audit_row."""

    return PartitionRow(
        object_id=object_id,
        primary=primary,
        path_count=path_count,
        path_set_digest=path_set_digest,
        coordinate_digest=coordinate_digest,
        applies=applies,
        refutes=refutes,
    )


# Pinned coordinates for the 83 imported objects, sorted by object identifier.
# Digests bind each object's owned-path set and its full declaration text; any
# substitution changes a digest and fails validate_source_partition.
REVIEW_ROWS: tuple[PartitionRow, ...] = (
    # Static cross-role table: POLICY primary and PROTOCOL specialization.  The
    # sole authored reasons.vstd conservatively selects APPLIES for every other
    # installed kind, so this row retains all 25 original-kind obligations as
    # source-bound root decisions without claiming subject instantiation.
    _row("vstd-agency-surface-crosswalk-assets", "POLICY", 1, "sha256:d87b525e263160627cffa1a231c19334361832241f17f484351a88b79905ea51", "sha256:2d804324516dec37d38e0dc87660c70a63ce0154c69350c3a335010bab746414", applies=tuple(kind for kind in AGENCY_CROSSWALK_APPLIES if kind in ORIGINAL_NON_OBJECT_KINDS)),
    _row("vstd-artifact-control-assets", "PROTOCOL", 1, "sha256:b80dbcafa49b076edcf6472c48fb1744680f5f7d057be1fc370f65fa8c58a7f3", "sha256:5e440b61224b34db35bf1587f8b64b23d88aafc2b6dd32d6a2a875a867f9ecbb"),
    _row("vstd-artifact-network-wire-assets", "PROTOCOL", 1, "sha256:5a67ec5bccf9417671cda770bee8e2a4289e5d0d97f49dcdb51bc41cb5de73a6", "sha256:9aa39e3c736abef63eeba5ed273622746d82cfaffe5fa64743b679a398f610ea"),
    _row(
        "vstd-bounded-completeness-assets",
        "VERIFIER",
        3,
        "sha256:382b5e3cc5ab0bf7b48fbb66608f86c4bbd4406aedb39cf1b87869830d6a8bc6",
        "sha256:7efb93d75a777e5e3e5313f03683d8042245073a06d0710bcd7e9bb4fd3a289c",
        applies=("VERIFIER",),
    ),
    _row("vstd-certificate-dependency-assets", "POLICY", 1, "sha256:0646486b1ba094f793cfa9f51c902977c4a324c9ce6a7899a7633d5281263883", "sha256:a895ef1bff2f92080376b0070de35bd8f38cbf7c7369ebcdc4fe98994d9ff0e2"),
    _row("vstd-competition-evaluation-profile-assets", "POLICY", 1, "sha256:ed5a091765b2100568b02375fccda45cb91f5a19b2f6dc8a29d11c4df29762f6", "sha256:c5f6fa8127bff1367df15d63061147c47917d420dde232f5fe4ad0fd22dd590d"),
    _row(
        "vstd-component-index-data-assets",
        "DATA",
        1,
        "sha256:4f1b7fc312f3f1ff8ecd2dd7ac6287d0cb4e9217bc8232be914fafbd472c164b",
        "sha256:b2740e6be302d7588d249c09eb5bb983e4f3106d164d68666d5e6af6c615f700",
        applies=("DATA",),
    ),
    _row("vstd-consent-protocol-assets", "PROTOCOL", 3, "sha256:bc69a5e7551d96833d9a18e7c70d42f16ac513883815732f455db846aa35aa25", "sha256:a9d6895884c9a3cc79ec85e426bb37cf3d3e6b86c724bbf9f237d129623b2617"),
    _row("vstd-core-application-release-assets", "POLICY", 8, "sha256:0ae6c150d8880811fbcf81411ab917d37fabc0be414ad5c840ea0fb7ab70ba49", "sha256:27b3cfa5a351d71492dcf18291d732d469d5c39a1267e032260e64f1447a966b"),
    _row("vstd-corrigibility-control-assets", "POLICY", 2, "sha256:2e04c9b815ba56d5324fbe1370a2432f1fac96ed8702b344efa35a8387cbb1c7", "sha256:f5427f884e29e9865f1715c33ad53f07bd42e5969d1a86a9906a2b3afc3a8b54"),
    _row("vstd-current-actor-policy-assets", "POLICY", 3, "sha256:304fad6abaaea29c6f3e339e22e90b3e8985e470049a841c9efe7f098a8f36f2", "sha256:bc644f396d072b1de1964e967ab2462773bb347c8d2ab50f3bc659e920fbc70c"),
    _row("vstd-current-agent-policy-assets", "POLICY", 2, "sha256:9cd3691f3fb1ed67bf7963cab791921b35d7798072ca1d113a091c42bb684d77", "sha256:698ec6c0e6429f30acd7be276ed064c76d13ea8703068906c9fb14822582bbab"),
    _row("vstd-current-arch-policy-assets", "POLICY", 3, "sha256:4167d0d987e75194d78e50bbeeeecad5dd16b2b75785e2043eb26eabd388d4dc", "sha256:85bfb756e1dba54baabba496943e4622016ddd7523b440d2e8589cbeec994127"),
    _row("vstd-current-bench-policy-assets", "POLICY", 3, "sha256:7a95704f3d9f1784a4d3bb470122ef4e252595e6a7b0dbcdbe0c011ab98ffc8f", "sha256:5d662ed9baca9a07817a6b957bb722380111b1a7720ef3d8bb6d1f18fd304c81"),
    # "The policy instantiates no BOT or SIM" is an instantiation denial, not an
    # identity predicate, so BOT and SIM stay UNRESOLVED (same class as the
    # current-arch policy's "instantiate or execute no computational architecture").
    _row(
        "vstd-current-bot-policy-assets",
        "POLICY",
        2,
        "sha256:76955c64bb4fcb59e06baa9a3061bbc33394fdc97da8d628c369c41b2b3b56ed",
        "sha256:a1e600cfbce06fe6fcc82d95bb4393cd50790b0288a83f2a9ae9f73388b42316",
    ),
    _row("vstd-current-collective-protocol-assets", "PROTOCOL", 4, "sha256:0e785bdb9374018ea4605c274a6c0cfeeeffd5ed4935da1849d40884aa820926", "sha256:50df4a8e47c88b1635beb6c0042e45af70c91b2a37b44482c49822f3ca844740"),
    _row("vstd-current-data-policy-assets", "POLICY", 3, "sha256:45768b89fd763b14ed4199e9e5ede8880798cf3c5d30db08898ff216c58c88dd", "sha256:e9470c2fd54144f2e0b857b9c296250e61f7683391118508a5b2a3ccac6391fd"),
    _row("vstd-current-env-policy-assets", "POLICY", 5, "sha256:2e10e8def568eb4c503fff8b092d35f077c70ff3edb183546487bcc8e780ac90", "sha256:61f66b702d9b2c396fa960593e14ba42e72e304f8e5078df1a79580da2ba53f8"),
    _row("vstd-current-event-policy-assets", "POLICY", 3, "sha256:9b93b53dfa4b53b833141622829743bddcef5b3cc7318f7996c500258f9354c6", "sha256:c018f24eb5c931189199dc2cb93ca6a22399b0d82c38d26fdfab77ea21f165be"),
    _row("vstd-current-graph-policy-assets", "POLICY", 4, "sha256:aeba2997baab4cb1ba5918c989a8a27d564098f934dc0f8cc49e135811e47be7", "sha256:f82ac34e5688aa92363054a94bd12e39afa9d1fb8f20b982b61baf781c8469d4"),
    _row("vstd-current-hardware-policy-assets", "POLICY", 6, "sha256:6f93fd72173ee9b9f249a993a4163def5e8ee38d7730c4b0bbde8594d4343bf4", "sha256:12c3cbfb913451a7b00812ec3e6bec8856af52a9194055c93e690e24d48c818c"),
    _row("vstd-current-harness-policy-assets", "POLICY", 2, "sha256:613a9f73d1265e961580e8424ed269b83dc80b5e25f4f96f9b82b9a18c9ddc4a", "sha256:19a595284b5b094cff94a8b53df36688de7f5386368b31629c02e889c91fde34"),
    _row("vstd-current-human-policy-assets", "POLICY", 3, "sha256:c0fc97a74adbcf8fbfca187e6e8d325629e65f7c3dd9eddf8a4fa37df483e6b2", "sha256:77646140c43c92fe91b0925afa9dfc44be61de568efd2dc3e6573a2bb925288e"),
    _row("vstd-current-hyper-policy-assets", "POLICY", 3, "sha256:d28e48b588b409b590aad4eeed332df7d6369d923e07dbaea7f934c2084267ed", "sha256:c86b0b6132fd58a6d7d4ce31d64a08b035ffc1790071b40ad3af7c0e3e8089bb"),
    _row("vstd-current-identity-protocol-assets", "PROTOCOL", 5, "sha256:35cb51a82fdda61a0eb83eb80ee14ba7cd0faffe48ec6991f2ce556abea11c7d", "sha256:eb8efe6a215b181ee331b16bb1216e6e945c95e6f1c613e87adc327def7eb33e"),
    _row("vstd-current-independence-privacy-assets", "POLICY", 3, "sha256:7476473b38fb002f78b67518b25f5d452185ae2d4cd091757b1f0387eb03cf85", "sha256:286bf8202ea27ed404ef0f15bde3b340e82cb2d2bf337e98ed01e2fae24aa3f7"),
    _row("vstd-current-model-policy-assets", "POLICY", 7, "sha256:ddb5e6f21978e2be2ca95e3d6afc13067d95322ee02c2f9bdd33bb034348f05d", "sha256:d2310747b28a5671ad3396b37923d30c077ab9215393394add38d0404e8a8f1f"),
    _row("vstd-current-object-policy-assets", "POLICY", 6, "sha256:43fc60ae8c2689be6a4b29f3ca69cb97dc525a3f5dd772e12421858ee1ed4317", "sha256:a302ec346f61f1e85063578db9a60e80a2d1f5f9624f62f1b8a028f1134d5f63"),
    _row("vstd-current-owner-policy-assets", "POLICY", 3, "sha256:e63904360b32858211f398d015542c210f3d706fbc9d9e871cb2fe1124ac2b29", "sha256:21ed6574d0758fae1368819d098193adfad718d0bee000b299a3d075033c1709"),
    _row("vstd-current-permission-slot-assets", "PROTOCOL", 1, "sha256:5c500d7205505365eec9b3be44268b3f7b895b35553eb6547070e100d2a209cb", "sha256:3c173ffc5a19f6f9993a843ef279762a0879d01dcee6a6187f7767aed3144b0e"),
    _row("vstd-current-receipt-policy-assets", "POLICY", 5, "sha256:d1588e01f90e8b597951928e2b0b31afe82fec0f45b7eba52dcbabc77c526adc", "sha256:74210f968ce495e763f14bcdea6d6793a7f294995ae45dee76de4234090e9c78"),
    _row("vstd-current-role-protocol-assets", "PROTOCOL", 4, "sha256:d4b6f6facd874261da2643b4b88396327fa5e35f3160b15daa1fdc4aba0da493", "sha256:0f7c278522c519f2c059d9efe35e4f116808e17f226b5dd400e53f1c2e46f708"),
    _row("vstd-current-sim-policy-assets", "POLICY", 12, "sha256:ceb488dfbc6c2d548be72879ed1b052db592269d6c3eef9e3f903f651527bf3d", "sha256:9d6fbe1842590103e48e62e909d10a61fb20a45c90b4ed37760401e5c3677d36"),
    _row("vstd-current-space-policy-assets", "POLICY", 3, "sha256:07f8dce666525057d8186cc050d24b9b32b7aa408e3f37f08900469ec286c56a", "sha256:f7a695aa672cd116c880a064161b3573fa22c0f081eb84c8a250d573f8674970"),
    _row("vstd-current-subject-security-assets", "PROTOCOL", 1, "sha256:0d4738a58d2667bf606d6b79b87782263c8be041d267a2422e128dd728e4e1c3", "sha256:17716d7c7fb925ec5a4aac8c44232cc5cc6a16969cb5c3d5ddf361246a71f395"),
    _row("vstd-current-time-policy-assets", "POLICY", 3, "sha256:e9d6f66bd24965dd2eefe3ea836a966812c8e60a0ed62891b6a67bbd4e6f94f5", "sha256:0f2edd9867293748e071ab7c4a5a8d959f7d72c0186be37d150751310d9ccac8"),
    _row("vstd-current-token-policy-assets", "POLICY", 3, "sha256:5e3897117ab4c4779ed3f18d87317df60405374ee405a61099a65b756415b4cc", "sha256:8506ee5a8b9accf4c7570ed48858ea521c2f3fd68a89ddcd24141a27bbcc46a1"),
    _row("vstd-current-train-policy-assets", "POLICY", 3, "sha256:f32b27959dd4a568f2066231472096d492e1363e92307fb79fa22c416abb9d3d", "sha256:f6a16c48b695bf6dce35a748b75b3b4f0deb9c3ae3536af45ad1b8d3a13f13c9"),
    _row("vstd-current-typed-facet-assets", "POLICY", 2, "sha256:4600c214571f6cdfde73a4bd3ed0401e71225e25ba07b09d8a03099611e85db8", "sha256:92faad925d058ea22b9c8b09511b0de3ab3ab10eb7c8cee4dad1c203c4a3f0ea"),
    _row("vstd-current-verifier-policy-assets", "POLICY", 4, "sha256:68c6fb2f4a16e2692fa185420b8ffc76be2a96db0467c91ff974078fab2e938c", "sha256:85674792000dd3ab858eb0362b5e78a0d3631fca567a36b0de76431efb067994"),
    _row(
        "vstd-dangerous-pathway-assets",
        "VERIFIER",
        5,
        "sha256:6d877951a6a2ed116d5becc209069ae16525cbb13bdd950b89f8e258c39facec",
        "sha256:3c15e6df8dae6b5301b03670e7e1f018ed6c76ab3468c7f213a650c2908bdaa3",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-deriver-self-status-assets",
        "VERIFIER",
        3,
        "sha256:fd2214e1ac5e14aeb8e8142245728a406306d5ca3606fdf934ef0352f50b4fb9",
        "sha256:1f8c5242ce94baf3a4d319a78e4602ca916d7ecf4c9172ead4a2e87a0c1d4c86",
        applies=("VERIFIER",),
    ),
    _row("vstd-domain-certification-assets", "PROTOCOL", 6, "sha256:14fb453bf0dce8d226577ad33adf9a09c917baa8ccf19952ca84ed1aa3ddd154", "sha256:479dcadd9448ffe0fc44f3d42c5534015b4b1785325926e201a42662ca7cc5cc"),
    _row("vstd-experimental-workflow-profile-assets", "PROTOCOL", 2, "sha256:f4e4cc6582a8880a67c4b2230c8a8e2058ca7588f5e28127add4ec05eebb65e0", "sha256:8ec6e79cf6d6ad33a321755374840bc08cd5ba23f38f054b2166ff5f4d5c392d"),
    _row(
        "vstd-explanation-definition-data-assets",
        "DATA",
        1,
        "sha256:f77f56adceb16772f19185dc4afc302e9cc18b687067cb89accc12be05a80ae0",
        "sha256:acf22b0fccd8b99ac60bf884b7be952152effe746119d7d1b6efa5365666e171",
        applies=("DATA",),
    ),
    _row("vstd-finite-authority-assets", "POLICY", 2, "sha256:32c4db3cd527af183344b58ff116a94f3de92ad471c6b30a843eef37626a0c8e", "sha256:f59b12b08f23168081b0cf4c6b24399bab1bcb2fe14112ffcf3d8a3f2b5b1f8a"),
    _row("vstd-finite-record-issuance-assets", "PROTOCOL", 2, "sha256:d2dfc7239409317abfc09bb97482b4ff11412b9a5b0843f882618e4e468c3fb1", "sha256:d39d6c8749e824309241b48801266908b879c297708c6c75581f595fd0e9befd"),
    _row(
        "vstd-global-cycle-assets",
        "VERIFIER",
        3,
        "sha256:7a5c3daa099766bb5a2cc06a0fcf53078fa17bc03ced81117198f45bdc7224e4",
        "sha256:683789cc32ac9bdf21f649061918da3dcfb7a36d466772de1fb16c3875cd9e3e",
        applies=("VERIFIER",),
    ),
    _row("vstd-language-runner-isolation-assets", "PROTOCOL", 2, "sha256:ab5a2990a55e0e5998d8e4a02ad70ecd8c670b676903b38ba14728ff69076400", "sha256:93f1dd24435b3869854720d04d9e5ff88bb1852aef3284095cb11f4d6fc8f0e5"),
    _row(
        "vstd-native-replay-metadata-assets",
        "DATA",
        2,
        "sha256:b4149e45f68e6ca6559bd9adfdaac459f4ef9f715c5e6e685b54f956b887759c",
        "sha256:c1fdf368e65a8d9eee447e4867c2403fc3f6c6966656223ad3ded32ab1a9fc57",
        applies=("DATA",),
    ),
    _row("vstd-package-polish-assets", "POLICY", 16, "sha256:a92f5b35d05d57741684c7a5ab6b790647c1bd334f6be131d67c36a2f4b9ee61", "sha256:1f3ad04f42805de4f9bcaf77bda512cbba777415a924dfbf21f5d35ccd28a7da"),
    _row(
        "vstd-package-self-polish-assets",
        "VERIFIER",
        12,
        "sha256:0e5abb880f341fd8913c22a331fdbeb0b0c26305b6ad2c2df3bb701d0b00fe28",
        "sha256:2373c280fa7da6763cb39f68e2462ccc6cd60bbe80d07d592eb45d1b6e113724",
        applies=("VERIFIER",),
    ),
    _row("vstd-prdel-language-assets", "PROTOCOL", 21, "sha256:8172649156954b8bbe5f772de7965eaea975668b2525fe186cf5e98a4eba992c", "sha256:35fe734b97d7ef43425c3f6c23dae5c990ccc6ebc9d697554ee9f7069f50f641"),
    _row(
        "vstd-profile-architecture-assets",
        "POLICY",
        19,
        "sha256:d1949810306ad765555e7a8d9e8acaa761fb728d6d9ba0b23020690e403ec0de",
        "sha256:9ec5c218afe3c7d766e2ec29595c2a527c5743e610cb6615551a94881c8fb80a",
        refutes=(("ARCH", "not a computational-model ARCH"),),
    ),
    _row(
        "vstd-proposition-transfer-assets",
        "VERIFIER",
        3,
        "sha256:05cfaa0847ceb9d69af7df1515a102a1ab48af7fde36fedf484fd2a63e48d86f",
        "sha256:6b8d536365a20725f54ca46d689af28048f9298c861ac740f441eaa47513d395",
        applies=("VERIFIER",),
    ),
    _row("vstd-public-checkability-assets", "PROTOCOL", 1, "sha256:221b0cb430f223aff5a4c52f1aeda46ec6cbbefac32c39cbc902a3dd5ed0dbb7", "sha256:07abc2e9f5f939fc40d8216ae919329d3703cd2a4b4f931922b5b78a009ba4ec"),
    _row(
        "vstd-relation-boundary-assets",
        "VERIFIER",
        3,
        "sha256:ed5fc4eac791671de328ceff30d67b6d987bb243960561e84d58ec449eac95f8",
        "sha256:e69c5a99a76fbae17a4116d1f2209ce4443d5bc0d7f216b81472c50fa8b0bd9f",
        applies=("VERIFIER",),
    ),
    _row("vstd-repository-admission-assets", "POLICY", 25, "sha256:4ad8f93122efdc0e49646581417a39631f7145ceec3b61a1a1a90e1032ba076b", "sha256:9d7de829c3737f376332fa5fcedfe49cee4141b573f25dc7e207a5efa340778a"),
    _row(
        "vstd-runtime-authority-correspondence-assets",
        "VERIFIER",
        2,
        "sha256:e6b0ec89e4829c4e5e0ede4b524dce0fc718637d5d912e10ed3d805fbd20e0f6",
        "sha256:59efdadcd6304bad2509f14338e299be528419fa5c32aa0192bc209003c1c4bd",
        applies=("VERIFIER",),
    ),
    _row("vstd-selected-secret-gate-assets", "POLICY", 1, "sha256:aa1fb6a09b313936d509c71366592665793a7ab2368d2acc0c579b6039d0bd2d", "sha256:3113965d28938033e62c16bbea7525967479e50f7d9321ec789c8f9954165c92"),
    _row("vstd-silo-protocol-assets", "PROTOCOL", 7, "sha256:84a2a9297bf242f6b77be211dec742753f5f68a2e801ff573f0a1a1159ed4ee1", "sha256:4b2087535c45c83ccd944f79c74facf5e50b2233bb746b5420fae159710db62a"),
    _row(
        "vstd-simulation-risk-receipt-assets",
        "PROTOCOL",
        2,
        "sha256:29e46a7d21e15685fd076a07e9822a2247b0491bcdaaceb4885a8aae6fa5f42b",
        "sha256:00626da147c91284e95b9b6a9cc9f500542962eab891c71ab1607ec0f7b56069",
        refutes=(
            ("RECEIPT", "schema documents are not receipt instances with bound subject and hardware operands"),
        ),
    ),
    _row(
        "vstd-source-grounding-assets",
        "VERIFIER",
        3,
        "sha256:4e37bf3f4928df344eaf7db5fec84d72c0a8d71d8fa74364161c6f3d2f9c07f8",
        "sha256:3867eb62518d49d95fcc8249e761e4e8cfe0b222501a78f8a68e611aa020deda",
        applies=("VERIFIER",),
    ),
    _row("vstd-spacetime-context-assets", "POLICY", 1, "sha256:0d34e9312f7e41f2f0c9f76209aed780eb335f04b0325667570c24d09d1ee036", "sha256:b8cc706eb1b4b8c4eba7c95366c07de2ccb9e41004387b9b212473e11b993328"),
    _row(
        "vstd-test-artifact-evidence-regressions",
        "VERIFIER",
        65,
        "sha256:f47d70e147afed66623aeb5989447fc72a24b7128e5c5cf22447942fb23f3673",
        "sha256:b5cc8d819c00c013f299263fc6929469a2e04f5461fc0bd8e0c7a4337f7b8384",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-current-object-regressions",
        "VERIFIER",
        124,
        "sha256:3e54445d1612aef4c4b1405b927c79b8d77c6824969692eee52848be6f7bd180",
        "sha256:1c8f0b2a3b4238b8572d7d43bfc46274647118fe257734d4ee8ac94573037066",
        applies=("VERIFIER",),
        refutes=tuple(
            (kind, CURRENT_OBJECT_TRANSFER_DENIAL)
            for kind in ("HUMAN", "MODEL", "SIM", "BOT", "HARDWARE")
        ),
    ),
    _row(
        "vstd-test-fixture-harness",
        "HARNESS",
        4,
        "sha256:af5f680a272bed92ed8e37ca895e99358d0742f69400dd6937612da0b5ff43bc",
        "sha256:794f8bd9409a15a1353ef7a8d35cf1f79990841c1c86b0c53d59ea8ed94adf55",
        applies=("HARNESS",),
    ),
    _row(
        "vstd-test-formation-fixture-corpus",
        "DATA",
        2,
        "sha256:0a814f95ff9a96322bd45a60d6a3491e7fd1c82cf6acee5eaac505dd0575abff",
        "sha256:55d381da54282a1f69778da8155801d40bd785eddbd701a830207833d666bc22",
        applies=("DATA",),
    ),
    _row(
        "vstd-test-governance-authority-regressions",
        "VERIFIER",
        40,
        "sha256:dff994f893e3c13a8f38750df52bb1cde3acbaece137edef9502e3ef4fcdb0ff",
        "sha256:d5830e68d9fdfc891caa4be0000abacf2cd609703d20f13fa095c161e36285d4",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-graph-composition-regressions",
        "VERIFIER",
        56,
        "sha256:edaeca7c118aea415f2ee370b559a84aa3eb191d0625ff79ffb7103bf6e98a5d",
        "sha256:89da6c61f94c97c973b77027291fde0b9caf823a78056bca42c06f7a42b07704",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-hardware-environment-regressions",
        "VERIFIER",
        23,
        "sha256:a6301110035b5e2bdf7ffd2cd7e8723c09a4254e5a89d4628a6b92a0ba87a06b",
        "sha256:57bbd8e166469446c4d45ed1bb893498b5dd0838aa8c840e9feca1b6b95a3e98",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-namespace-admission-regressions",
        "VERIFIER",
        91,
        "sha256:46b97b7fc0520165540d1a538b625a5b09b9d8c212ee05d283e2d21cabc7c716",
        "sha256:5d3f9ad9f8343587cbc20bc2ab6f4eb7349a5c19e31936ca4ef97597b045f632",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-packaging-compatibility-regressions",
        "VERIFIER",
        22,
        "sha256:5808601b203755ecb82a6f06639660a43d29d082d74ebf54d79135f78208f176",
        "sha256:c34f4f1807caf854d81446d20f0cccd5298017c0d3ac1b382423899167fbcb5e",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-polish-regressions",
        "VERIFIER",
        70,
        "sha256:77623c23dc0d4bfe6bf9cf4159cbfe7eb191249e29439aca650443a157e02cf6",
        "sha256:91b61a47551a96a82cee6f6ba8e4963bd6135056624d60634cb645e651a762ac",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-prdel-regressions",
        "VERIFIER",
        21,
        "sha256:2d7774d383b8a6bd5687ddd529339d8a641ff863befb5d510419b4c24984aa14",
        "sha256:09a08dcd8541d1aa99843c6ed8eb14500f4da396bd2b4440a0e9b4bdb310c500",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-release-publication-regressions",
        "VERIFIER",
        38,
        "sha256:e52bec5e6bd8f6c018e64654edf8500c904cefbd05c3a1d095dfa62ae8eaca72",
        "sha256:cd9354c7fe028c42426662c5e3dd604db64e410348538d6f718566a8cd2f95ef",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-runtime-execution-regressions",
        "VERIFIER",
        60,
        "sha256:0eb1fe993d6350c014ba1b282a0e57d20a58905f0f8cddf548c7753831b02565",
        "sha256:958878e3ef86ecc09e75eacc0ce10ce4e8b2f3b953b8c398b35fac9c79069111",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-security-privacy-regressions",
        "VERIFIER",
        8,
        "sha256:b7c611d05bd7c13e22641f24a447c1266b3f1b44c286b612a22e9717732f62fd",
        "sha256:e3e554e9558852fe6398368736417189c16eb52829bf80632e2cf7568b1c7f6f",
        applies=("VERIFIER",),
    ),
    _row(
        "vstd-test-simulation-model-regressions",
        "VERIFIER",
        33,
        "sha256:c37479b25f89cda492f9a004a7051601c0c14719f28016665f8f45d02d81df8f",
        "sha256:25d85aaf5a9183e879403cbaf26e5790eac8077de63bca3b5423db9a4de82df2",
        applies=("VERIFIER",),
        refutes=(
            ("SIM", "These test definitions are not SIMs, BOTs, ROBOTs, FINBOTs, trained MODEL artifacts"),
            ("BOT", "These test definitions are not SIMs, BOTs, ROBOTs, FINBOTs, trained MODEL artifacts"),
            ("MODEL", "These test definitions are not SIMs, BOTs, ROBOTs, FINBOTs, trained MODEL artifacts"),
        ),
    ),
    _row("vstd-test-spacetime-extension-schema", "PROTOCOL", 1, "sha256:1d02b2080179c88659a99466060860305849b413fbaded322fd6254e12489a14", "sha256:25a37c38eb7206ad05339181d0f8cb3555bba2c7f5e652b57abcb4b232769ee9"),
    _row("vstd-three-hardware-integration-profile-assets", "POLICY", 5, "sha256:14377acb657121f9852af68e5b23cb2cc716ce27b6973c6bdb213c1921adb4f6", "sha256:81cfc6d179e58b1924ad9788d3ca25cbbaaf8f93276cde6483c21099d57249e2"),
    _row("vstd-typed-formation-assets", "PROTOCOL", 4, "sha256:3ee1eeb578a78dd9abd271d0f09199e510fbaed691d90e64c3dc45ca04e06286", "sha256:59c10581ff8087e3656ecdcde74b70401e684f13dea158a12999b9e0504ca4c3"),
    _row("vstd-zero-identity-token-assets", "PROTOCOL", 5, "sha256:74e7e1742915664adde36af075c9a09394afc580c020ca481ac79059209a48b4", "sha256:8fea2310c83c2c74a539419fcbf49a8623b061dc6e15a140d2628f0d3bce8747"),
)
# Pinned counterexample screens for every object with a quoted identity denial.
# A denial is decided only when its object's record is CLOSED.  Recompute with
# recheck_closure_screens(); any byte drift raises PARTITION_ORIGINAL_KIND_SCREEN_STALE.
SCREEN_RECORDS: tuple[ScreenRecord, ...] = (
    # Open: the layout texts link 40 external URIs and 113 repository targets
    # outside the owned set, and the graph-assurance schema $refs an external
    # receipt schema.  Those unowned transitive edges cannot be closed here.
    ScreenRecord(
        object_id="vstd-profile-architecture-assets",
        status="UNKNOWN",
        path_count=19,
        bytes_digest="sha256:232aaa2093d8d42e4367a3199fafbe02d305d9346eb65223650f2562497cc04d",
        effect_digest="",
        blocker_counts=(
            ("REFERENCE_EXTERNAL_URL", 40),
            ("REFERENCE_UNOWNED_TARGET", 113),
        ),
    ),
    ScreenRecord(
        object_id="vstd-simulation-risk-receipt-assets",
        status="CLOSED",
        path_count=2,
        bytes_digest="sha256:011d5e177dad686d887f19e86bfc8b5b67a47cf00b791453834f4a790771942b",
        effect_digest="",
        blocker_counts=(),
    ),
    ScreenRecord(
        object_id="vstd-test-current-object-regressions",
        status="UNKNOWN",
        path_count=124,
        bytes_digest="sha256:009acb5f6dae3d12dda4061567e3fe0948b22ab9ba8a769ec11fa3bd1a15fa08",
        effect_digest="sha256:07b0e0c297f2967f85303c34ee96f20e1f2e173077392c4050b1641fd2b3e21f",
        blocker_counts=(
            ("EFFECT_BLOCKER_CALL_TARGET_UNRESOLVED", 8885),
            ("EFFECT_BLOCKER_DYNAMIC_EXECUTION_UNRESOLVED", 16),
            ("EFFECT_BLOCKER_EXTERNAL_IMPORT_UNACCOUNTED", 193),
            ("EFFECT_BLOCKER_IMPORT_ESCAPES_OWNERSHIP", 930),
            ("EFFECT_BLOCKER_INJECTED_CALLABLE_UNRESOLVED", 642),
            ("EFFECT_callback_injected_callable", 1),
            ("EFFECT_dynamic_import_eval_exec_reflection", 1),
            ("EFFECT_subprocess_process", 1),
        ),
    ),
    ScreenRecord(
        object_id="vstd-test-simulation-model-regressions",
        status="UNKNOWN",
        path_count=33,
        bytes_digest="sha256:962ca9c212ebc9b3552ecaba31892af96e6a67ec06374b3615864ee07d507071",
        effect_digest="sha256:166167682c0747c0d6d2ef2ad79b121572f3aa1d1b7bd920084ffb872b7aacf6",
        blocker_counts=(
            ("EFFECT_BLOCKER_CALL_TARGET_UNRESOLVED", 1769),
            ("EFFECT_BLOCKER_DYNAMIC_EXECUTION_UNRESOLVED", 1),
            ("EFFECT_BLOCKER_EXTERNAL_IMPORT_UNACCOUNTED", 45),
            ("EFFECT_BLOCKER_IMPORT_ESCAPES_OWNERSHIP", 113),
            ("EFFECT_BLOCKER_INJECTED_CALLABLE_UNRESOLVED", 73),
            ("EFFECT_callback_injected_callable", 1),
            ("EFFECT_dynamic_import_eval_exec_reflection", 1),
            ("EFFECT_subprocess_process", 1),
        ),
    ),
)
_SCREEN_BY_OBJECT: dict[str, ScreenRecord] = {
    record.object_id: record for record in SCREEN_RECORDS
}


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
    """Bind every declared field, including the exact denial and scope text."""

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


def _source_roles(spec: SemanticOwnershipSpec) -> tuple[set[str], set[str]]:
    """Return source-declared (APPLIES, DOES_NOT_APPLY) original-kind roles."""

    applies: set[str] = set()
    if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS:
        applies.add(spec.primary_kind)
    applies.update(
        kind for kind in spec.specializations if kind in ORIGINAL_NON_OBJECT_KINDS
    )
    denied: set[str] = set()
    for decision in spec.root_role_decisions:
        if decision.kind not in ORIGINAL_NON_OBJECT_KINDS:
            continue
        if decision.status == APPLIES:
            applies.add(decision.kind)
        elif decision.status == DOES_NOT_APPLY:
            denied.add(decision.kind)
    return applies, denied


_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9-]*")


def _is_kind_token(token: str, kind: str) -> bool:
    """Exact token match for a kind or its plural; substrings never name a kind."""

    return token.upper() in (kind, kind + "S")


def _names_kind(kind: str, quote: str) -> bool:
    """True only when the quote contains the kind as a whole token, not a substring."""

    return any(_is_kind_token(token, kind) for token in _TOKEN.findall(quote))


def _denial_qualifier(kind: str, quote: str) -> str | None:
    """Return the word that narrows ``kind`` in the quote, if any.

    A qualifier placed directly before the kind ("production HARNESS") or a
    restrictive connective in the same clause after it ("receipt instances with
    bound subject") denotes a narrower class than the kind itself.
    """

    words = _TOKEN.findall(quote)
    for index, word in enumerate(words):
        if not _is_kind_token(word, kind):
            continue
        for preceding in words[max(0, index - 2) : index]:
            if preceding.lower() in _QUALIFIERS:
                return preceding.lower()
    for match in _TOKEN.finditer(quote):
        if not _is_kind_token(match.group(), kind):
            continue
        clause = re.split(r"[;,.:]", quote[match.end() :], maxsplit=1)[0]
        for following in _TOKEN.findall(clause)[:2]:
            if following.lower() in _NARROWING_CONNECTIVES:
                return following.lower()
    return None


def _is_uri(value: Any) -> bool:
    return isinstance(value, str) and _URI_SCHEME.match(value) is not None


def _resolve_relative(source: str, target: str) -> str | None:
    """Resolve ``target`` against the directory of ``source``; None if it escapes."""

    if PurePosixPath(target).is_absolute():
        return None
    parts: list[str] = []
    for part in (*PurePosixPath(source).parent.parts, *PurePosixPath(target).parts):
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def _reference_blocker(
    source: str, target: str, owned: frozenset[str], rebased: bool = False
) -> str | None:
    """Classify one structural reference edge from an owned document.

    An in-document anchor is closed.  A URI, or any relative reference under a
    base rebased by an absolute ``$id``, leaves the repository.  A repository
    target closes only when it is an owned path; every other target is an unowned
    transitive dependency that the screen cannot close.
    """

    target = target.strip()
    if target == "" or target.startswith("#"):
        return None
    if _URI_SCHEME.match(target) or rebased:
        return "REFERENCE_EXTERNAL_URL"
    file_part = re.split(r"[#?]", target, maxsplit=1)[0]
    resolved = _resolve_relative(source, file_part)
    return None if resolved in owned else "REFERENCE_UNOWNED_TARGET"


def _markdown_targets(text: str) -> tuple[str, ...]:
    return tuple(
        next(group for group in match.groups() if group is not None)
        for match in _MARKDOWN_EDGE.finditer(text)
    )


def _schema_refs(node: Any) -> Iterator[Any]:
    """Yield every ``$ref`` value; a property literally named ``$ref`` is treated as an edge too."""

    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                yield value
            else:
                yield from _schema_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _schema_refs(item)


def _tally_reference(
    blockers: Counter[str],
    source: str,
    value: Any,
    owned: frozenset[str],
    rebased: bool = False,
) -> None:
    if not isinstance(value, str):
        blockers["REFERENCE_UNREADABLE"] += 1
        return
    reason = _reference_blocker(source, value, owned, rebased)
    if reason is not None:
        blockers[reason] += 1


def _screen_summary(record: ScreenRecord | None) -> str:
    """Name a screen's status and its blocker counts for an UNRESOLVED reason."""

    if record is None:
        return "MISSING"
    if not record.blocker_counts:
        return record.status
    blockers = ", ".join(f"{name} x{count}" for name, count in record.blocker_counts)
    return record.status + " (" + blockers + ")"


def counterexample_screen(
    object_id: str,
    owned_paths: Iterable[str],
    root: str | Path = _REPO_ROOT,
) -> ScreenRecord:
    """Screen every owned path without inferring any original kind.

    Binary assets, JSON instances (documents without ``$schema`` and ``$id``),
    unclassified suffixes, and missing paths are blockers.  Owned Python is
    audited with ClosedEffectAudit, and unresolved calls, external or
    unaccounted imports, callbacks, dynamic or reflective execution, and
    subprocess effects are blockers.  Structural reference edges are blockers
    unless they close inside the owned set: Markdown inline, reference, autolink,
    and href/src targets, and JSON ``$ref`` values.  URIs are
    REFERENCE_EXTERNAL_URL; any other repository target outside the owned set is
    REFERENCE_UNOWNED_TARGET.  Plain prose filename mentions are not edges and are
    excluded by design.  Target existence is not consulted, so the record depends
    only on owned bytes and the owned set.  The record says only whether this
    static closure is closed at these exact bytes.
    """

    from verifier.runtime.package_original_kind_review import audit_closed_effects

    selected = tuple(sorted(owned_paths))
    owned = frozenset(selected)
    base = Path(root)
    blockers: Counter[str] = Counter()
    entries: list[dict[str, Any]] = []
    executable: list[str] = []
    for path in selected:
        target = base / path
        if not target.is_file():
            blockers["MISSING_PATH"] += 1
            continue
        raw = target.read_bytes()
        entries.append(
            {"path": path, "sha256": "sha256:" + sha256(raw).hexdigest(), "byte_count": len(raw)}
        )
        suffix = PurePosixPath(path).suffix
        if suffix == ".py":
            executable.append(path)
        elif suffix == ".md":
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                blockers["MARKDOWN_UNDECODABLE"] += 1
                continue
            for value in _markdown_targets(text):
                _tally_reference(blockers, path, value, owned)
        elif suffix == ".json":
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                blockers["JSON_UNPARSEABLE"] += 1
                continue
            if not (isinstance(document, dict) and "$schema" in document and "$id" in document):
                blockers["JSON_INSTANCE"] += 1
            rebased = isinstance(document, dict) and _is_uri(document.get("$id"))
            for value in _schema_refs(document):
                _tally_reference(blockers, path, value, owned, rebased)
        elif suffix in _ARTIFACT_SUFFIXES:
            blockers["BINARY_ASSET"] += 1
        else:
            blockers["UNCLASSIFIED_SUFFIX"] += 1
    effect_digest = ""
    if executable:
        effect = audit_closed_effects(base, executable)
        effect_digest = effect.evidence_digest
        for item in effect.blockers:
            blockers["EFFECT_BLOCKER_" + item.split(":", 1)[0]] += 1
        for channel in sorted({item.channel for item in effect.consequences} & _DEFEATING_EFFECTS):
            blockers["EFFECT_" + channel] += 1
    counts = tuple(sorted(blockers.items()))
    return ScreenRecord(
        object_id=object_id,
        status="UNKNOWN" if counts else "CLOSED",
        path_count=len(selected),
        bytes_digest=_canonical_digest(entries),
        effect_digest=effect_digest,
        blocker_counts=counts,
    )


def recheck_closure_screens(
    root: str | Path = _REPO_ROOT,
    object_ids: tuple[str, ...] | None = None,
) -> tuple[ScreenRecord, ...]:
    """Recompute pinned screens from current bytes; any drift raises.

    Byte drift is checked for the whole selection before effect drift, so a
    stale file is reported as stale rather than as a downstream closure change.
    """

    source = {spec.object_id: spec for spec in current_source_partition()}
    if object_ids is None:
        if {record.object_id for record in SCREEN_RECORDS} != {
            row.object_id for row in REVIEW_ROWS if row.refutes
        }:
            raise ValueError("PARTITION_ORIGINAL_KIND_SCREEN_COVERAGE_DRIFT")
        selected = SCREEN_RECORDS
    else:
        selected = tuple(record for record in SCREEN_RECORDS if record.object_id in object_ids)
    live_records = [
        counterexample_screen(record.object_id, source[record.object_id].owned_paths, root)
        for record in selected
    ]
    for record, live in zip(selected, live_records):
        if live.bytes_digest != record.bytes_digest:
            raise ValueError("PARTITION_ORIGINAL_KIND_SCREEN_STALE:" + record.object_id)
    for record, live in zip(selected, live_records):
        if live != record:
            raise ValueError("PARTITION_ORIGINAL_KIND_SCREEN_DRIFT:" + record.object_id)
    return tuple(live_records)


def audit_row(row: PartitionRow) -> PartitionAudit:
    """Validate one row alone and answer all 25 original non-OBJECT kinds."""

    if type(row) is not PartitionRow:
        raise ValueError("PARTITION_ORIGINAL_KIND_ROW_INVALID")
    if re.fullmatch(r"[a-z][a-z0-9-]{2,95}", row.object_id) is None:
        raise ValueError("PARTITION_ORIGINAL_KIND_OBJECT_ID_INVALID")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", row.path_set_digest) is None or (
        re.fullmatch(r"sha256:[0-9a-f]{64}", row.coordinate_digest) is None
    ):
        raise ValueError("PARTITION_ORIGINAL_KIND_DIGEST_INVALID")
    if type(row.path_count) is not int or row.path_count < 1:
        raise ValueError("PARTITION_ORIGINAL_KIND_PATH_COUNT_INVALID")
    if row.primary == "OBJECT" or any(
        kind == "OBJECT" for kind in (*row.applies, *(kind for kind, _ in row.refutes))
    ):
        raise ValueError("PARTITION_ORIGINAL_KIND_OBJECT_BYPASS:" + row.object_id)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", row.primary) is None:
        raise ValueError("PARTITION_ORIGINAL_KIND_PRIMARY_INVALID:" + row.object_id)
    if len(set(row.applies)) != len(row.applies) or any(
        kind not in ORIGINAL_NON_OBJECT_KINDS for kind in row.applies
    ):
        raise ValueError("PARTITION_ORIGINAL_KIND_APPLIES_INVALID:" + row.object_id)
    refuted = [kind for kind, _quote in row.refutes]
    if len(set(refuted)) != len(refuted) or any(
        kind not in ORIGINAL_NON_OBJECT_KINDS for kind in refuted
    ):
        raise ValueError("PARTITION_ORIGINAL_KIND_REFUTES_INVALID:" + row.object_id)
    if row.primary in ORIGINAL_NON_OBJECT_KINDS and row.primary not in row.applies:
        raise ValueError("PARTITION_ORIGINAL_KIND_PRIMARY_UNANSWERED:" + row.object_id)
    if set(row.applies) & set(refuted):
        raise ValueError("PARTITION_ORIGINAL_KIND_ROLE_CONFLICT:" + row.object_id)
    for kind, quote in row.refutes:
        if type(quote) is not str or not quote.strip() or len(quote) > 16384:
            raise ValueError("PARTITION_ORIGINAL_KIND_DENIAL_TEXT_INVALID:" + row.object_id)
        if _IDENTITY_DENIAL.search(quote) is None:
            raise ValueError("PARTITION_ORIGINAL_KIND_DENIAL_NOT_IDENTITY:" + row.object_id)
        if not _names_kind(kind, quote):
            raise ValueError("PARTITION_ORIGINAL_KIND_DENIAL_KIND_ABSENT:" + row.object_id)

    questions = []
    refutes = dict(row.refutes)
    narrowed = {kind: _denial_qualifier(kind, quote) for kind, quote in row.refutes}
    record = _SCREEN_BY_OBJECT.get(row.object_id)
    screen_closed = record is not None and record.status == "CLOSED"
    for kind in ORIGINAL_NON_OBJECT_KINDS:
        if kind in row.applies:
            source = (
                "primary_kind of owned declaration "
                if kind == row.primary
                else "source-declared specialization or root role of owned declaration "
            )
            reason = (
                "The "
                + source
                + row.object_id
                + " establishes "
                + kind
                + " as an accumulated role. Applicability only; not mechanism truth "
                "or higher-tier conformance."
            )
            questions.append(PartitionQuestion(kind, APPLIES, reason))
        elif kind in refutes and narrowed.get(kind) is not None:
            qualifier = narrowed[kind]
            reason = (
                "Verbatim denial in owned declaration "
                + row.object_id
                + ": \""
                + refutes[kind]
                + "\" narrows "
                + kind
                + " by the qualifier \""
                + str(qualifier)
                + "\" to a sub-class, so it does not refute the unqualified "
                + kind
                + " identity. "
                + kind
                + " remains UNRESOLVED."
            )
            questions.append(PartitionQuestion(kind, UNRESOLVED, reason))
        elif kind in refutes and not screen_closed:
            screen = _screen_summary(record)
            reason = (
                "Verbatim identity denial in owned declaration "
                + row.object_id
                + ": \""
                + refutes[kind]
                + "\" is recorded, but its bounded counterexample screen is "
                + screen
                + ". "
                + kind
                + " remains UNRESOLVED until a closed screen covers every owned path "
                "and project-local import."
            )
            questions.append(PartitionQuestion(kind, UNRESOLVED, reason))
        elif kind in refutes:
            reason = (
                "Verbatim identity denial in owned declaration "
                + row.object_id
                + ": \""
                + refutes[kind]
                + "\". It refutes only this row's "
                + kind
                + " identity and no other kind."
            )
            questions.append(PartitionQuestion(kind, DOES_NOT_APPLY, reason))
        else:
            reason = (
                "No owned declaration of "
                + row.object_id
                + " establishes or refutes that this row is "
                + _KIND_CRITERIA[kind]
                + "; "
                + kind
                + " remains UNRESOLVED. Operands, consequences, claim-status "
                "disclaimers, and neighboring objects are not role equivalence."
            )
            questions.append(PartitionQuestion(kind, UNRESOLVED, reason))
    return PartitionAudit(
        object_id=row.object_id,
        primary=row.primary,
        path_count=row.path_count,
        path_set_digest=row.path_set_digest,
        coordinate_digest=row.coordinate_digest,
        questions=tuple(questions),
    )


def validate_source_partition(
    specs: Iterable[SemanticOwnershipSpec],
    rows: tuple[PartitionRow, ...] = REVIEW_ROWS,
) -> tuple[PartitionAudit, ...]:
    """Bind every pinned row to exact current source and reject any substitution."""

    selected = tuple(specs)
    if any(type(spec) is not SemanticOwnershipSpec for spec in selected) or len(
        {spec.object_id for spec in selected}
    ) != len(selected):
        raise ValueError("PARTITION_ORIGINAL_KIND_SOURCE_PARTITION_INVALID")
    if type(rows) is not tuple or len({row.object_id for row in rows}) != len(rows):
        raise ValueError("PARTITION_ORIGINAL_KIND_ROWS_INVALID")
    source = {spec.object_id: spec for spec in selected}
    if set(source) != {row.object_id for row in rows}:
        raise ValueError("PARTITION_ORIGINAL_KIND_SOURCE_DENOMINATOR_DRIFT")
    # Each owned path has exactly one owner, so a citation can never be foreign.
    owners: dict[str, str] = {}
    for spec in selected:
        for path in spec.owned_paths:
            if owners.setdefault(path, spec.object_id) != spec.object_id:
                raise ValueError("PARTITION_ORIGINAL_KIND_DUPLICATE_OWNERSHIP:" + path)
    audits = []
    for row in sorted(rows, key=lambda item: item.object_id):
        spec = source[row.object_id]
        object_id = row.object_id
        if spec.primary_kind != row.primary:
            raise ValueError("PARTITION_ORIGINAL_KIND_SOURCE_PRIMARY_DRIFT:" + object_id)
        if len(spec.owned_paths) != row.path_count or owned_path_set_digest(
            spec.owned_paths
        ) != row.path_set_digest:
            raise ValueError("PARTITION_ORIGINAL_KIND_SOURCE_PATH_DRIFT:" + object_id)
        if _source_coordinate_digest(spec) != row.coordinate_digest:
            raise ValueError(
                "PARTITION_ORIGINAL_KIND_SOURCE_COORDINATE_DRIFT:" + object_id
            )
        applies, denied = _source_roles(spec)
        if applies & denied:
            raise ValueError("PARTITION_ORIGINAL_KIND_SOURCE_ROLE_CONFLICT:" + object_id)
        if set(row.applies) != applies:
            raise ValueError(
                "PARTITION_ORIGINAL_KIND_ACCUMULATED_ROLE_DRIFT:" + object_id
            )
        refuted = {kind for kind, _quote in row.refutes}
        if not denied <= refuted:
            raise ValueError("PARTITION_ORIGINAL_KIND_ROOT_DENIAL_UNRECORDED:" + object_id)
        root_reasons = {
            decision.kind: decision.reason
            for decision in spec.root_role_decisions
            if decision.status == DOES_NOT_APPLY
        }
        text = (
            spec.representation_role,
            spec.necessity_reason,
            spec.consequence_boundary,
        )
        for kind, quote in row.refutes:
            if kind in applies:
                raise ValueError(
                    "PARTITION_ORIGINAL_KIND_ROLE_CONFLICT:" + object_id
                )
            if kind in denied:
                if quote not in root_reasons[kind]:
                    raise ValueError(
                        "PARTITION_ORIGINAL_KIND_ROOT_DENIAL_DRIFT:" + object_id
                    )
            elif not _names_kind(kind, quote) or not any(quote in field for field in text):
                raise ValueError(
                    "PARTITION_ORIGINAL_KIND_DENIAL_NOT_SOURCE_BOUND:" + object_id
                )
        audits.append(audit_row(row))
    return tuple(audits)


def current_source_partition() -> tuple[SemanticOwnershipSpec, ...]:
    """Return the two imported partitions after proving they are aggregate members."""

    from verifier.runtime import package_semantic_ownership as ownership

    member_ids = {id(spec) for spec in ownership.SEMANTIC_OWNERSHIP_SPECS}
    selected = (*TEST_FIXTURE_OWNERSHIP_SPECS, *NORMATIVE_ASSET_OWNERSHIP_SPECS)
    if any(id(spec) not in member_ids for spec in selected):
        raise ValueError("PARTITION_ORIGINAL_KIND_NOT_AGGREGATE_MEMBER")
    return tuple(sorted(selected, key=lambda spec: spec.object_id))


def build_partial_profile(
    specs: Iterable[SemanticOwnershipSpec] | None = None,
) -> OriginalKindProfile:
    """Seal only decided rows; undecided objects are never listed as exempt."""

    selected = current_source_partition() if specs is None else tuple(specs)
    audits = validate_source_partition(selected)
    source = {spec.object_id: spec for spec in selected}
    assignments = []
    for audit in audits:
        decisions = tuple(
            OriginalKindDecision(question.kind, question.status, question.reason)
            for question in audit.questions
            if question.status in {APPLIES, DOES_NOT_APPLY}
        )
        if not decisions:
            continue
        assignments.append(
            OriginalKindAssignment(
                object_id=audit.object_id,
                expected_primary=audit.primary,
                expected_owned_paths=tuple(source[audit.object_id].owned_paths),
                expected_owned_path_set_digest=audit.path_set_digest,
                scope_reason=(
                    "Exact owned-path and source-coordinate review for "
                    + audit.object_id
                    + ": primary "
                    + audit.primary
                    + ", "
                    + str(audit.path_count)
                    + " owned paths, coordinate digest "
                    + audit.coordinate_digest
                    + "."
                ),
                decisions=decisions,
            )
        )
    return seal_profile(PROFILE_ID, 1, CLAIM_BOUNDARY, assignments)


AUDITS: tuple[PartitionAudit, ...] = validate_source_partition(
    current_source_partition()
)
# Captured with the audits so the review rows name the exact files each audit
# covered, whatever later selects a partition.
_OWNED_PATHS: dict[str, tuple[str, ...]] = {
    spec.object_id: tuple(sorted(spec.owned_paths))
    for spec in current_source_partition()
}
PARTIAL_PROFILE: OriginalKindProfile = build_partial_profile()


@dataclass(frozen=True)
class CellEvidence:
    """Durable evidence basis for one object-kind cell, without its prose reason."""

    object_id: str
    kind: str
    status: str
    basis: str
    screen_status: str
    coordinate_digest: str


def cell_evidence_records() -> tuple[CellEvidence, ...]:
    """Return one record per cell, in object then source-kind order."""

    rows = {row.object_id: row for row in REVIEW_ROWS}
    records = []
    for audit in AUDITS:
        row = rows[audit.object_id]
        record = _SCREEN_BY_OBJECT.get(audit.object_id)
        for question in audit.questions:
            if question.status == APPLIES:
                basis = "SOURCE_DECLARED_ROLE"
                screen = "NOT_REQUIRED"
            elif question.status == DOES_NOT_APPLY:
                basis = "SOURCE_IDENTITY_DENIAL"
                screen = record.status if record is not None else "MISSING"
            elif question.kind in dict(row.refutes) and _denial_qualifier(
                question.kind, dict(row.refutes)[question.kind]
            ) is not None:
                basis = "IDENTITY_DENIAL_QUALIFIED"
                screen = record.status if record is not None else "MISSING"
            elif question.kind in dict(row.refutes):
                basis = "IDENTITY_DENIAL_SCREEN_UNCLOSED"
                screen = record.status if record is not None else "MISSING"
            else:
                basis = "NO_SOURCE_ROLE"
                screen = "NOT_REQUIRED"
            records.append(
                CellEvidence(
                    object_id=audit.object_id,
                    kind=question.kind,
                    status=question.status,
                    basis=basis,
                    screen_status=screen,
                    coordinate_digest=audit.coordinate_digest,
                )
            )
    return tuple(records)


def cell_evidence_digest() -> str:
    return _canonical_digest(
        [
            [
                record.object_id,
                record.kind,
                record.status,
                record.basis,
                record.screen_status,
                record.coordinate_digest,
            ]
            for record in cell_evidence_records()
        ]
    )


# Pinned digest over every cell's object, kind, status, basis, screen status, and
# coordinate.  A changed decision or screen result requires an explicit repin.
CELL_EVIDENCE_DIGEST = "sha256:4602fae13c18ea6ddf2f1548212766843f9d4adb18344b6330028c01255818d2"


def _catalog_check() -> None:
    if len(AUDITS) != 83 or len(REVIEW_ROWS) != 83:
        raise AssertionError("partition original-kind object denominator differs")
    if sum(row.path_count for row in REVIEW_ROWS) != 949:
        raise AssertionError("partition original-kind owned-path denominator differs")
    if any(len(audit.questions) != len(ORIGINAL_NON_OBJECT_KINDS) for audit in AUDITS):
        raise AssertionError("partition original-kind question denominator differs")
    statuses = [question.status for audit in AUDITS for question in audit.questions]
    if (
        statuses.count(APPLIES) != 52
        or statuses.count(DOES_NOT_APPLY) != 0
        or statuses.count(UNRESOLVED) != 2023
    ):
        raise AssertionError("partition original-kind status counts differ")
    decided = {
        audit.object_id
        for audit in AUDITS
        if any(question.status != UNRESOLVED for question in audit.questions)
    }
    profiled = {assignment.object_id for assignment in PARTIAL_PROFILE.assignments}
    if len(decided) != 28 or decided != profiled:
        raise AssertionError("partition partial-profile membership differs")
    actual_cell_evidence_digest = cell_evidence_digest()
    if actual_cell_evidence_digest != CELL_EVIDENCE_DIGEST:
        raise AssertionError(
            "partition cell evidence digest differs: expected "
            + CELL_EVIDENCE_DIGEST
            + " actual "
            + actual_cell_evidence_digest
        )


_catalog_check()


def review_document() -> dict[str, Any]:
    """Return the complete 83-by-25 audit without upgrading unresolved questions."""

    profiled = {assignment.object_id for assignment in PARTIAL_PROFILE.assignments}
    return {
        audit.object_id: {
            "expected_primary": audit.primary,
            # The aggregate re-hashes exactly these files at the selected bytes, so
            # the row names them rather than leaving only their count and digest.
            "expected_owned_paths": list(_OWNED_PATHS[audit.object_id]),
            "expected_owned_path_count": audit.path_count,
            "expected_owned_path_set_digest": audit.path_set_digest,
            "expected_source_coordinate_digest": audit.coordinate_digest,
            "questions": {
                question.kind: {
                    "status": question.status,
                    "reason": question.reason,
                }
                for question in audit.questions
            },
            "partial_profile_digest": (
                PARTIAL_PROFILE.canonical_digest if audit.object_id in profiled else None
            ),
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for audit in AUDITS
    }


__all__ = [
    "AUDITS",
    "CELL_EVIDENCE_DIGEST",
    "CLAIM_BOUNDARY",
    "PARTIAL_PROFILE",
    "PROFILE_ID",
    "REVIEW_ROWS",
    "SCREEN_RECORDS",
    "CellEvidence",
    "PartitionAudit",
    "PartitionQuestion",
    "PartitionRow",
    "ScreenRecord",
    "UNRESOLVED",
    "audit_row",
    "build_partial_profile",
    "cell_evidence_digest",
    "cell_evidence_records",
    "counterexample_screen",
    "current_source_partition",
    "review_document",
    "recheck_closure_screens",
    "validate_source_partition",
]

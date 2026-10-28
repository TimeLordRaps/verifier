"""Explicit original-kind audit for the domain ownership partition.

The 38 source owners in :data:`DOMAIN_OWNERSHIP_SPECS` each expose all 25
original, non-``OBJECT`` kind questions.  Only source-audited affirmative
decisions enter the sealed profile.  An unlisted question is ``UNRESOLVED``;
this module contains no complement rule and emits no negative decision from
silence, a filename, an operand, a referenced subject kind, or lexical absence.

The only negative decisions are identity refutations of high-risk kinds.  Each
one must pass a conjunctive gate: a ``CLOSED`` import/effect closure of the
exact owned source, a source-bound positive identity claim, and zero bounded
counterexample hits.  Zero lexical hits, an empty or inert file, and a limited
local syntax-tree search are never sufficient.  No owner currently passes the
gate, so the profile carries no negative decision and every proposed cell stays
``UNRESOLVED`` with its exact blocker.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from verifier.runtime import package_original_kind_review
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindDecision,
    owned_path_set_digest,
    seal_profile,
)
from verifier.runtime.package_semantic_ownership_domains import (
    DOMAIN_OWNERSHIP_SPECS,
)


UNRESOLVED = "UNRESOLVED"
_EXPECTED_SOURCE_DIGESTS = {
    "src/verifier/domains/__init__.py": "sha256:0f16ca4601c54a788487ca80d26413c7fffc50fe7ff4250ba186f2ebc353d92f",
    "src/verifier/domains/carriers.py": "sha256:d0b6db3d6a2edba0278ac358d400949c5bbfed71b2c62a0e938d12b492173420",
    "src/verifier/domains/catalog.py": "sha256:8a1d8e0d61857289c4658399ce5851767703d3dcc251d8dc9d07ba8db9ddbc0a",
    "src/verifier/domains/certification.py": "sha256:0d3cccd855c375133548cf791f66a058d4a785e857d83e8e67061ca8bab140ce",
    "src/verifier/domains/common.py": "sha256:f753f64fa23e1615cf5c0449bf8768e3d9381e539f72516a9781e52e1a594b08",
    "src/verifier/domains/contracts/__init__.py": "sha256:5201c75f68b5075f6ed07013ba3a5c80882963a81749186d52ec93225cfb3c1b",
    "src/verifier/domains/inventory.py": "sha256:13667a264342d4e5c1ee53ba08195277c3ec06b12268fd1ffcd5a159da7a2694",
    "src/verifier/domains/mainstay_certification.py": "sha256:b9d918a3da127c822a828df07fcd972d341cf60754974f7a5f3776a134c14920",
    "src/verifier/domains/mainstays.py": "sha256:7660be5d4b8614bdda6ac2daf57d69ba325e0d33f7ecd01d286e397c87eba119",
    "src/verifier/domains/numerical.py": "sha256:ea6f105e65b2d4d6de530e2ae840c5ffaa4f8ae892a114855554eef70a089981",
    "src/verifier/domains/statics.py": "sha256:2ccbd77194ade8316ec64d0cf5c41ac94534082cbfa8e5ad54b05352787b03da",
    "src/verifier/domains/contracts/accountability.py": "sha256:eebf93431bf63b91df1188e7344196a27e2e1c7c24f44936fa273a88c74e63e1",
    "src/verifier/domains/contracts/application_requirements.py": "sha256:cf577a4903b6de7f961d3abcde6ef4defefd9a893dd6793688ae5ca1372dc1f5",
    "src/verifier/domains/contracts/certificate_dag.py": "sha256:b185b4b32c1dcc36701141b6b0853e8351ee7ed1895c9a27fe5c2e4a26b999d7",
    "src/verifier/domains/contracts/consent_checks.py": "sha256:588c94db5f05822e7710d80e501a703816c9d42dfe303aa2e91091b07116ba94",
    "src/verifier/domains/contracts/current_object_routes.py": "sha256:f3b22b1485897fb2661467be2bd44ac42f0915a4a7da3c344ba87006dd92d61d",
    "src/verifier/domains/contracts/dangerous_pathway_security.py": "sha256:2e78156c3256e935a4daa25ce1ded67c9c5e6de7578b74764a59dac7df218010",
    "src/verifier/domains/contracts/facet_coverage.py": "sha256:3e7dbbfece4cb59aa3ef65427ad7f96d8057a878f262097a54369d6962566e9e",
    "src/verifier/domains/contracts/independence_checks.py": "sha256:6786272c6d05cfb4e6c974d47a815b0909f96f8073037290ff38992e6fea1edc",
    "src/verifier/domains/contracts/independence_projection.py": "sha256:4757231ea616dfeca1701ee13a87b7ee34497a9417798bfd17276187f220d9a8",
    "src/verifier/domains/contracts/native_child_links.py": "sha256:0924fca6503e75510766fb868bbc82069ea6daa4efa403b889eea848ec4a535a",
    "src/verifier/domains/contracts/object_address_closure.py": "sha256:344a164a310e933ac5a039cc1b8c4fe0869c9949d4d12ee22096c8adf7b77a8d",
    "src/verifier/domains/contracts/object_facets.py": "sha256:ee31efbeceb35b756957a56e4b24d357263a575fc7b3c76a6bb7332c81884a1c",
    "src/verifier/domains/contracts/object_governance.py": "sha256:87d82c2d398511275cf9aacaa817f871f9561de8438d89ab8dd101a98489ad10",
    "src/verifier/domains/contracts/object_grounding.py": "sha256:0d4c7fac5f4e1c004b9a92dc41a25e0623188ab86ad67f8a75fad7cce4d71d5a",
    "src/verifier/domains/contracts/object_lineage.py": "sha256:c94158b34a751a8e6702cd455d4906651efac2657fad8436238b6a3566d9d5a3",
    "src/verifier/domains/contracts/object_statics.py": "sha256:86ec11b2c52c059bb499e6363e9d1e85e302c2a69a2548c39942c2f01afb295b",
    "src/verifier/domains/contracts/privacy_checks.py": "sha256:f8f109aabda8d3c4d9ab62aabb69c8ddfc69a2b12cc90c6b83eec11854fda1c3",
    "src/verifier/domains/contracts/retained_selection.py": "sha256:a6d4fbbebe7dec3d69b3eab0cc9a8110661fea0087ee20edbe285075608cd77a",
    "src/verifier/domains/contracts/reviewed_conflict_lane_refusals.py": "sha256:797af75ca40059bc841f142924bc8a6b30c4e23f78e0764801ee6ec4596ebbc9",
    "src/verifier/domains/contracts/reviewed_singleton_projections.py": "sha256:8bae476a9b1be52aad88bec041f375f43b35e796d5deabe26171d858aac24995",
    "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py": "sha256:1c806915594a113fcd2292a43a5947110c42f16da935b2f7333b5286f946a826",
    "src/verifier/domains/contracts/selected_native_contexts.py": "sha256:90d280bbd1a4579b249e50a41533db65bbd306fddf80a4327f920b05f88dd4d6",
    "src/verifier/domains/contracts/spacetime_execution.py": "sha256:704ccb530eae8a6a8a427994b0c302bf3235f7f3c8cc6bebd4b735724febdacb",
    "src/verifier/domains/contracts/spacetime_mapping.py": "sha256:bc4c8a911c69c4f915ef1e509cb5d1be55ff1f3751d186a711f69e59a6d303c8",
    "src/verifier/domains/contracts/spacetime_profiles.py": "sha256:b203e6e8a17fa014a6e0ea3810976eefb6005f995698334c05f3f06e6103dc47",
    "src/verifier/domains/contracts/subject_security.py": "sha256:5e2d95f9277fd0fa8987645adb38fd29e8dd7bdd6c5ad9de39327b7d7eb9abf3",
    "src/verifier/domains/contracts/typed_facets.py": "sha256:9a90258e2ca02271bf4aa980709d595e338ceff095657401a65d14b29bd8c516",
    "src/verifier/domains/contracts/typed_facets_projection.py": "sha256:7817969a1d1322f30442b0d5a342af3afb2d6df1a8409236e01e347ed593c36c",
}
SOURCE_BINDING_DIGEST = "sha256:" + sha256(
    "\n".join(
        path + "\t" + digest
        for path, digest in sorted(_EXPECTED_SOURCE_DIGESTS.items())
    ).encode("ascii")
).hexdigest()
_EXPECTED_CROSS_ROOT_DECISIONS = {
    "vstd-certificate-dependency-controller": {"VERIFIER": APPLIES},
    "vstd-object-governance-protocol": {"VERIFIER": APPLIES},
    "vstd-spacetime-capability-measurement": {"VERIFIER": APPLIES},
    "vstd-subject-security-chain-verifier": {"VERIFIER": APPLIES},
}
CLAIM_BOUNDARY = (
    "Exact source-owned original-kind review for the 38 domain ownership "
    "objects. The profile establishes only the literal affirmative and "
    "owner-identity refutation decisions it carries; unresolved questions "
    "remain open and no result establishes "
    "repository admission, mechanism truth, physical or financial effect, "
    "release authority, or higher-tier conformance. Pinned source binding: "
    + SOURCE_BINDING_DIGEST
    + "."
)


@dataclass(frozen=True)
class DomainOriginalKindQuestion:
    """One literal source-audited answer or an honest unresolved question."""

    kind: str
    status: str
    reason: str


@dataclass(frozen=True)
class DomainOriginalKindAudit:
    """One exact domain owner, its source boundary, and all 25 questions."""

    object_id: str
    expected_primary: str
    expected_specializations: tuple[str, ...]
    expected_owned_paths: tuple[str, ...]
    expected_owned_path_set_digest: str
    scope_reason: str
    questions: tuple[DomainOriginalKindQuestion, ...]


_KIND_CRITERIA = {
    "ACTOR": "an accountable decision maker with its own control, instrument, delegation, and attribution boundary",
    "AGENT": "an autonomous trajectory bounded by one governing harness",
    "ARCH": "a computational architecture with dependency and shape semantics",
    "BENCH": "a finite benchmark with problems, oracles, scoring, coverage, and budgets",
    "BOT": "a simulation-situated closed loop binding an agent, observations, actions, and execution envelopes",
    "COLLECTIVE": "an organized group with membership, roles, quorum, and collective decisions",
    "DATA": "a dataset whose content, schema, partitions, lineage, and immutability are represented",
    "ENV": "an execution environment with dependencies, configuration, resources, and reproduction boundaries",
    "EVENT": "a represented spatiotemporal occurrence binding time, space, action, and payload",
    "GRAPH": "a collection whose vertices, edges, ordering, lineage, and closure are represented",
    "HARDWARE": "an execution substrate or device inventory with topology, capacity, allocation, and observation envelopes",
    "HARNESS": "an execution scaffold with instrumented channels, declared gaps, tools, effects, and transcript",
    "HUMAN": "a living-person and human-accountability termination root",
    "HYPER": "a composite entity with directed operands, dependency cone, ceiling, and absorption rules",
    "IDENTITY": "a bearer-to-role binding with occupancy, scope, presentation, and lifecycle semantics",
    "MODEL": "trained parameter artifacts with architecture binding, forward execution, evaluation, and challenges",
    "OWNER": "an ownership relation linking an actor to held objects, rights, duties, and accountability",
    "RECEIPT": "a portable evidence record binding a subject, execution, prerequisites, and replay",
    "ROLE": "an authority-bearing role class with eligibility, occupancy, permissions, and lifecycle",
    "SIM": "a generative simulation with state, transitions, channels, causality, and isolation",
    "SPACE": "a spatial, network, or storage coordinate domain with layout and migration semantics",
    "TIME": "a temporal interval, sequence, clock, or epoch coordinate with ordering semantics",
    "TOKEN": "a cryptographic or computational holding with issuance, scope, tenure, lease, and status semantics",
    "TRAIN": "a training run with configuration, checkpoints, batches, optimization, updates, and replay",
    "VERIFIER": "a checking mechanism with exact identity, decision procedure, execution rules, and bounded replay",
}


REFUTABLE_ORIGINAL_KINDS = ("MODEL", "SIM", "AGENT", "BOT", "HARDWARE")
_COUNTEREXAMPLE_TERMS = {
    "MODEL": ("forward", "logit", "weight", "architecture", "tensor", "safetensor", "parameter"),
    "SIM": ("simulat", "transition", "next_state", "tick", "state_space", "generative"),
    "AGENT": ("agent", "trajector", "autonom"),
    "BOT": ("bot", "closed_loop", "actuat", "envelope", "observation"),
    "HARDWARE": ("device", "hardware", "topolog", "gpu", "cpu", "sensor", "capacity", "allocation"),
}
# Candidate identity refutations proposed by a bounded lexical zero-hit search of
# each owner's syntax tree.  Zero hits are necessary at most, never sufficient:
# a candidate becomes DOES_NOT_APPLY only through _admits_refutation.  Every
# candidate is UNRESOLVED today, with its exact blocker named in the audit.
_PROPOSED_IDENTITY_REFUTATIONS = {
    "vstd-application-requirements-compiler": ("AGENT", "BOT", "HARDWARE", "MODEL", "SIM"),
    "vstd-certificate-dependency-controller": ("AGENT", "BOT", "HARDWARE", "MODEL", "SIM"),
    "vstd-consent-certificate-verifier": ("AGENT", "HARDWARE", "MODEL"),
    "vstd-current-object-replay-router": ("MODEL",),
    "vstd-dangerous-pathway-assessor": ("AGENT", "MODEL"),
    "vstd-domain-carrier-protocols": ("AGENT", "BOT", "HARDWARE"),
    "vstd-domain-checking-primitives": ("AGENT", "HARDWARE", "MODEL"),
    "vstd-domain-contracts-package-marker": ("AGENT", "BOT", "HARDWARE", "MODEL", "SIM"),
    "vstd-domains-package-marker": ("AGENT", "BOT", "HARDWARE", "MODEL", "SIM"),
    "vstd-facet-obligation-compiler": ("AGENT",),
    "vstd-hardware-ownership-eligibility": ("MODEL",),
    "vstd-independence-certificate-verifier": ("AGENT",),
    "vstd-independence-projection-policy": ("MODEL", "SIM"),
    "vstd-mainstay-certificate-engine": ("AGENT", "HARDWARE", "SIM"),
    "vstd-native-child-link-assessor": ("BOT", "HARDWARE", "MODEL"),
    "vstd-object-address-closure-verifier": ("AGENT", "HARDWARE"),
    "vstd-object-facet-verifier": ("AGENT", "HARDWARE", "SIM"),
    "vstd-object-governance-protocol": ("AGENT", "HARDWARE", "SIM"),
    "vstd-object-lineage-verifier": ("AGENT", "HARDWARE"),
    "vstd-object-statics-verifier": ("AGENT", "HARDWARE"),
    "vstd-privacy-certificate-verifier": ("AGENT", "HARDWARE"),
    "vstd-retained-execution-measurement": ("AGENT", "HARDWARE", "MODEL", "SIM"),
    "vstd-retained-model-training-arithmetic": ("AGENT", "BOT", "HARDWARE"),
    "vstd-retained-selection-policy": ("AGENT", "BOT", "HARDWARE", "SIM"),
    "vstd-reviewed-conflict-refusal-policy": ("MODEL",),
    "vstd-selected-native-context-assessor": ("AGENT", "HARDWARE", "MODEL", "SIM"),
    "vstd-sim-grounding-verifier": ("AGENT", "HARDWARE"),
    "vstd-sim-host-time-mapping-verifier": ("HARDWARE", "MODEL"),
    "vstd-spacetime-capability-measurement": ("HARDWARE", "MODEL", "SIM"),
    "vstd-subject-security-chain-verifier": ("AGENT", "SIM"),
    "vstd-typed-facet-projection-policy": ("MODEL", "SIM"),
    "vstd-typed-facet-verifier": ("SIM",),
}
# Source-bound positive identity claims: (object_id, kind) -> (claim, path,
# sha256).  Empty: no owner's own bytes establish a bounded identity different
# from its candidate kind.  A claim is admissible only while its digest equals
# the pinned owned source it describes.
_IDENTITY_CLAIMS: dict[tuple[str, str], tuple[str, str, str]] = {}
# Static closure pins from audit_closed_effects over each candidate owner's exact
# owned source: (status, blocker count, sha256 of the sorted blocker list, first
# blocker).  The test suite recomputes every pin.  Only the two package markers
# close, and a closed marker still fails the gate because the package it names is
# its submodules, which lie outside the closure.
_CLOSURE_PINS = {
    "vstd-domains-package-marker": ("CLOSED", 0, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""),
    "vstd-domain-carrier-protocols": ("UNKNOWN", 190, "sha256:189fe338014a89fe3fe122a7d26f9237694f1f8dc027a0040c36343189ce08c4", "CALL_TARGET_UNRESOLVED:src/verifier/domains/carriers.py:100:26:verifier.domains.common.Refuted"),
    "vstd-domain-checking-primitives": ("UNKNOWN", 27, "sha256:1e496da28875d1727fe9eb9623d0ea0b87f938e22d09ad42b0f9b426cb38c9eb", "CALL_TARGET_UNRESOLVED:src/verifier/domains/common.py:104:23:verifier.core.certificate.canonical_digest"),
    "vstd-domain-contracts-package-marker": ("CLOSED", 0, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""),
    "vstd-mainstay-certificate-engine": ("UNKNOWN", 50, "sha256:fa9903a3bd072742c71504c116292fd5e8f8758e8cfd8325e94ece90115a6ad9", "CALL_TARGET_UNRESOLVED:src/verifier/domains/mainstay_certification.py:113:12:verifier.domains.common.obj"),
    "vstd-retained-model-training-arithmetic": ("UNKNOWN", 46, "sha256:0b3a5ab8b0b4512d187175225bd9472021cc047fcf84b0b418e31746e756d865", "CALL_TARGET_UNRESOLVED:src/verifier/domains/numerical.py:100:14:verifier.domains.common.Unavailable"),
    "vstd-hardware-ownership-eligibility": ("UNKNOWN", 17, "sha256:046c8ff084c9107f18b9317aadc33db660696d8bb90a03c9dbb462b1e4368ef8", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/accountability.py:112:24:simulation.payload.get"),
    "vstd-application-requirements-compiler": ("UNKNOWN", 82, "sha256:733e46a1ebf7983a22f4ff54452bfc07e3270ec4b5eae1cdf5bce71956f98e95", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/application_requirements.py:161:29:<dynamic-call-target>"),
    "vstd-certificate-dependency-controller": ("UNKNOWN", 62, "sha256:ee6155539e4fcd3ff0c48538d8990b1df0ff288b9dedaa60a0316ebbaf75ba6f", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/certificate_dag.py:114:12:verifier.core.receipt.strict_json_loads"),
    "vstd-consent-certificate-verifier": ("UNKNOWN", 72, "sha256:99acdbff4dcc08291f58c9434c7c645b9961449a37240afadd3f7f9c62699bc1", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/consent_checks.py:100:39:selected.items"),
    "vstd-current-object-replay-router": ("UNKNOWN", 275, "sha256:2f400c3a07d7c72c9cadf397d4122b89535ad528d01f98b2632da6463c9ae2b6", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/current_object_routes.py:100:8:verifier.domains.contracts.sim_internal_state.SimInternalStateDescriptor"),
    "vstd-dangerous-pathway-assessor": ("UNKNOWN", 52, "sha256:5eda2bc749433b097723b217b7165924562b0a788b8fcd77595433e82c397d62", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/dangerous_pathway_security.py:1002:14:artifacts.get"),
    "vstd-facet-obligation-compiler": ("UNKNOWN", 136, "sha256:5446806692a415ba50504e5792e1fac71a40237b2a8dea7dc708bfc78e368976", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/facet_coverage.py:116:27:verifier.domains.contracts.token_facets.PROPERTY_CHECKS.items"),
    "vstd-independence-certificate-verifier": ("UNKNOWN", 110, "sha256:7f5820b49eb5161d78499251d76efdfa86a390ac1d68acba6c8a5646b87dc256", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/independence_checks.py:132:11:verifier.domains.contracts.retained_selection.record"),
    "vstd-independence-projection-policy": ("UNKNOWN", 8, "sha256:2d6599cb30c6bc9cb6e892539144e42d97e841c61cd92594838defe9c17e39ab", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/independence_projection.py:144:11:<dynamic-call-target>"),
    "vstd-native-child-link-assessor": ("UNKNOWN", 102, "sha256:0e1e968d967137031698b986ecfe79134f0bc25e3f42f9591560f2d342569b06", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/native_child_links.py:101:14:verifier.domains.contracts.certificate_dag._Exhausted"),
    "vstd-object-address-closure-verifier": ("UNKNOWN", 70, "sha256:3a30ca09f0f81c9f6df004a43c33db50a5e8fa3847a03e581e141b54d3ac7e01", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_address_closure.py:104:11:verifier.domains.contracts.retained_selection.policy"),
    "vstd-object-facet-verifier": ("UNKNOWN", 102, "sha256:738b2b93700caf6940919e60d4449aa303f254fb85785969b0cb11126c7e2cb5", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_facets.py:114:23:verifier.core.certificate.canonical_digest"),
    "vstd-object-governance-protocol": ("UNKNOWN", 108, "sha256:28fcac656f51d40c2a9f9a16cf02ce34dc89848e8070975b22e622e1eeeb16f6", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_governance.py:103:23:verifier.core.certificate.canonical_digest"),
    "vstd-sim-grounding-verifier": ("UNKNOWN", 102, "sha256:52834eb1b1e59f7d454de4bc08209ffbad979f88098c7d869abcdfea612074a7", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_grounding.py:112:24:_LIMIT_CEILINGS.items"),
    "vstd-object-lineage-verifier": ("UNKNOWN", 90, "sha256:efc4ad1608e91a765a587634837c0af5db409d1d3da33e1ce95c8b88918d314a", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_lineage.py:106:23:verifier.core.certificate.canonical_digest"),
    "vstd-object-statics-verifier": ("UNKNOWN", 87, "sha256:6eaa223e1d017306cbc54fb73ef28c1ced5d01a5003afb9c23f25851ed23d7f8", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/object_statics.py:105:23:verifier.core.certificate.canonical_digest"),
    "vstd-privacy-certificate-verifier": ("UNKNOWN", 88, "sha256:d6d10e9884bd3cfda6a0541158ec5ea02bbfbdc0fd1dfb21ba014043967f6d41", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/privacy_checks.py:105:23:verifier.core.certificate.canonical_digest"),
    "vstd-retained-selection-policy": ("UNKNOWN", 13, "sha256:b2aa84febd586538f2cc26ab3b2593828a801ac93bcabae725e68a71023bfb90", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/retained_selection.py:30:33:_HASH.fullmatch"),
    "vstd-reviewed-conflict-refusal-policy": ("UNKNOWN", 5, "sha256:76369625f9662d047b7c80fe24e507a10f704ae7f4f64e65d4002af4b6c374ae", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/reviewed_conflict_lane_refusals.py:1161:26:<dynamic-call-target>"),
    "vstd-selected-native-context-assessor": ("UNKNOWN", 95, "sha256:73556f7e3d14b46667adf9d383cc49fcbbaa68e0884a897e2c2e7d6c33a35339", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/selected_native_contexts.py:101:8:verifier.domains.contracts.application_requirements._native_intent"),
    "vstd-retained-execution-measurement": ("UNKNOWN", 71, "sha256:b07cde0e1e8596f32907695020f7379b679d7cb0ba41aed53978c616dda8792d", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/spacetime_execution.py:103:30:verifier.domains.contracts.spacetime_profiles.rational"),
    "vstd-sim-host-time-mapping-verifier": ("UNKNOWN", 39, "sha256:2c5239c56f6373141518d1d65a7329e4d860980054957bb50fc87fe20a8c5480", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/spacetime_mapping.py:100:22:verifier.domains.contracts.spacetime_profiles.Unsupported"),
    "vstd-spacetime-capability-measurement": ("UNKNOWN", 25, "sha256:ff697c415a225279b7292eec536c22dbccd386a110a7d30faf2e3106ba0e6c94", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/spacetime_profiles.py:102:7:verifier.core.certificate.canonical_bytes"),
    "vstd-subject-security-chain-verifier": ("UNKNOWN", 89, "sha256:9d50ae58b4ba0098e9a9b05b46855de4bd4120697062d6bc39e1f5d97c400669", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/subject_security.py:110:23:verifier.core.certificate.canonical_digest"),
    "vstd-typed-facet-verifier": ("UNKNOWN", 57, "sha256:650d8f8a25cf32341cea33abe9d72b4a8f89e321bd4af6e2ec72a7e533fc2603", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/typed_facets.py:110:33:_HASH.fullmatch"),
    "vstd-typed-facet-projection-policy": ("UNKNOWN", 10, "sha256:f7d60f7b11f01213b226c4a258050b03e072e6f67cc9d5bf44699937432623e6", "CALL_TARGET_UNRESOLVED:src/verifier/domains/contracts/typed_facets_projection.py:222:25:<dynamic-call-target>"),
}


def _counterexample_tokens(raw: bytes) -> tuple[str, ...]:
    """Lowercased identifiers and non-docstring string tokens of exact bytes."""
    tree = ast.parse(raw)
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                if isinstance(node.body[0].value, ast.Constant):
                    docstrings.add(id(node.body[0].value))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.append(node.id)
        elif isinstance(node, ast.Attribute):
            found.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.append(node.name)
        elif isinstance(node, ast.arg):
            found.append(node.arg)
        elif isinstance(node, ast.keyword) and node.arg:
            found.append(node.arg)
        elif isinstance(node, ast.alias):
            found.extend((node.name, node.asname or ""))
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
        elif (
            isinstance(node, ast.Constant)
            and type(node.value) is str
            and id(node) not in docstrings
        ):
            found.append(node.value)
    return tuple(sorted(token.lower() for token in found if token))


def _counterexample_hits(raw_by_path: Mapping[str, bytes], kind: str) -> tuple[str, ...]:
    terms = _COUNTEREXAMPLE_TERMS[kind]
    return tuple(
        path + ":" + token
        for path, raw in sorted(raw_by_path.items())
        for token in _counterexample_tokens(raw)
        if any(term in token for term in terms)
    )


def _refutation_reason(spec: Any, kind: str) -> str:
    return (
        "Identity refutation for "
        + kind
        + ": the exact owned source binding "
        + ", ".join(spec.owned_paths)
        + " names this owner as "
        + spec.representation_role
        + " Its owned syntax tree (identifiers, imports, definitions, arguments, "
        "and non-docstring string tokens) contains no token matching the bounded "
        + kind
        + " counterexample terms "
        + ", ".join(_COUNTEREXAMPLE_TERMS[kind])
        + ", so the owner does not satisfy the "
        + kind
        + " criterion: "
        + _KIND_CRITERIA[kind]
        + ". The search covers only the owned bytes; imported modules outside "
        "ownership are not searched, and this decision refutes only the owner's "
        "own identity, not any represented subject."
    )


def _closure_status(object_id: str) -> str:
    return _CLOSURE_PINS.get(object_id, ("UNKNOWN", 0, "", ""))[0]


def _admits_refutation(
    object_id: str,
    kind: str,
    closure_status: str,
    lexical_hits: tuple[str, ...],
) -> bool:
    """Admit a negative decision only when every conjunct holds.

    A CLOSED closure, zero lexical hits, or an empty marker is not positive
    identity evidence, so each is necessary at most.  The claim must be bound to
    the exact owned bytes it describes.
    """
    claim = _IDENTITY_CLAIMS.get((object_id, kind))
    return (
        claim is not None
        and closure_status == "CLOSED"
        and not lexical_hits
        and _EXPECTED_SOURCE_DIGESTS.get(claim[1]) == claim[2]
    )


def _blocker_clause(object_id: str, kind: str) -> str:
    """Name the exact gate blocker that keeps a proposed refutation UNRESOLVED."""
    status, count, digest, first = _CLOSURE_PINS[object_id]
    if status == "CLOSED":
        blocker = (
            "the owned import/effect closure is CLOSED with zero blockers, but "
            "the package it names is its submodules, which lie outside this "
            "owned file, so these marker bytes do not establish a bounded "
            "identity different from "
            + kind
        )
    else:
        blocker = (
            "the owned import/effect closure is "
            + status
            + " with "
            + str(count)
            + " exact blockers (sha256 of the sorted blocker list "
            + digest
            + "; first blocker "
            + first
            + ")"
        )
    claim = (
        "a source-bound positive identity claim exists but is not admissible"
        if (object_id, kind) in _IDENTITY_CLAIMS
        else "no source-bound positive identity claim exists"
    )
    return (
        " Exact blocker for the proposed "
        + kind
        + " identity refutation: "
        + blocker
        + "; "
        + claim
        + ". A zero-hit lexical search is never admissible as the reason."
    )


def _scope_reason(spec: Any) -> str:
    return (
        spec.representation_role
        + " Necessity: "
        + spec.necessity_reason
        + " Boundary: "
        + spec.consequence_boundary
    )


def _source_decisions(spec: Any) -> tuple[OriginalKindDecision, ...]:
    """Join the literal original primary with explicit cross-root reviews."""
    decisions = {
        decision.kind: OriginalKindDecision(
            decision.kind,
            decision.status,
            decision.reason,
        )
        for decision in spec.root_role_decisions
    }
    if len(decisions) != len(spec.root_role_decisions) or any(
        kind not in ORIGINAL_NON_OBJECT_KINDS for kind in decisions
    ):
        raise AssertionError(spec.object_id + " root-role decisions invalid")
    if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS:
        if spec.primary_kind in decisions:
            raise AssertionError(spec.object_id + " primary role duplicated")
        decisions[spec.primary_kind] = OriginalKindDecision(
            spec.primary_kind,
            APPLIES,
            "The exact owned source set and source-ownership declaration bind "
            "this object to its literal primary "
            + spec.primary_kind
            + " role. This establishes role applicability only, not mechanism "
            "truth or any additional root role.",
        )
    for kind in _PROPOSED_IDENTITY_REFUTATIONS.get(spec.object_id, ()):
        if not _admits_refutation(
            spec.object_id, kind, _closure_status(spec.object_id), ()
        ):
            continue
        if kind in decisions:
            raise AssertionError(spec.object_id + " identity refutation overlaps a decision")
        decisions[kind] = OriginalKindDecision(
            kind,
            DOES_NOT_APPLY,
            _refutation_reason(spec, kind),
        )
    return tuple(sorted(decisions.values(), key=lambda decision: decision.kind))


def _audit(spec: Any) -> DomainOriginalKindAudit:
    explicit = {decision.kind: decision for decision in _source_decisions(spec)}
    questions: list[DomainOriginalKindQuestion] = []
    scope = _scope_reason(spec)
    for kind in ORIGINAL_NON_OBJECT_KINDS:
        decision = explicit.get(kind)
        if decision is not None:
            questions.append(
                DomainOriginalKindQuestion(
                    kind,
                    decision.status,
                    scope
                    + " Source-near original-role "
                    + kind
                    + " decision: "
                    + decision.reason,
                )
            )
        else:
            sources = ", ".join(spec.owned_paths)
            questions.append(
                DomainOriginalKindQuestion(
                    kind,
                    UNRESOLVED,
                    scope
                    + " For exact owned source "
                    + sources
                    + ", this partition has no source-near decision establishing "
                    "that this owner itself is "
                    + _KIND_CRITERIA[kind]
                    + " and no source-grounded bounded refutation of that role. "
                    "Inputs, outputs, operands, callback subjects, filenames, a "
                    "different primary role, and absent declarations are not role "
                    "equivalence or refutation, so "
                    + kind
                    + " remains UNRESOLVED."
                    + (
                        _blocker_clause(spec.object_id, kind)
                        if kind in _PROPOSED_IDENTITY_REFUTATIONS.get(spec.object_id, ())
                        else ""
                    ),
                )
            )
    return DomainOriginalKindAudit(
        object_id=spec.object_id,
        expected_primary=spec.primary_kind,
        expected_specializations=spec.specializations,
        expected_owned_paths=spec.owned_paths,
        expected_owned_path_set_digest=owned_path_set_digest(spec.owned_paths),
        scope_reason=scope,
        questions=tuple(questions),
    )


DOMAIN_ORIGINAL_KIND_AUDITS = tuple(_audit(spec) for spec in DOMAIN_OWNERSHIP_SPECS)

DOMAIN_ORIGINAL_KIND_PROFILE = seal_profile(
    "verifier-domain-original-kind-review",
    2,
    CLAIM_BOUNDARY,
    tuple(
        OriginalKindAssignment(
            object_id=spec.object_id,
            expected_primary=spec.primary_kind,
            expected_owned_paths=spec.owned_paths,
            expected_owned_path_set_digest=owned_path_set_digest(spec.owned_paths),
            scope_reason=_scope_reason(spec),
            decisions=_source_decisions(spec),
        )
        for spec in sorted(DOMAIN_OWNERSHIP_SPECS, key=lambda row: row.object_id)
        if _source_decisions(spec)
    ),
)

_SOURCE_APPLIES = {
    spec.object_id: tuple(
        sorted(
            (
                (spec.primary_kind,)
                if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS
                else ()
            )
            + tuple(
                kind
                for kind, status in _EXPECTED_CROSS_ROOT_DECISIONS.get(
                    spec.object_id, {}
                ).items()
                if status == APPLIES
            )
        )
    )
    for spec in DOMAIN_OWNERSHIP_SPECS
    if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS
    or spec.object_id in _EXPECTED_CROSS_ROOT_DECISIONS
}


def _source_snapshot(root: Path, audit: DomainOriginalKindAudit) -> tuple[dict[str, str], ...]:
    evidence: list[dict[str, str]] = []
    for path in audit.expected_owned_paths:
        try:
            target = (root / path).resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError(path)
            digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_UNAVAILABLE:"
                + audit.object_id
                + ":"
                + path
            ) from exc
        if _EXPECTED_SOURCE_DIGESTS.get(path) != digest:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_PIN_DIFFERS:"
                + audit.object_id
                + ":"
                + path
            )
        evidence.append({"path": path, "sha256": digest})
    return tuple(evidence)


def _owned_paths(row: Mapping[str, Any], object_id: str) -> tuple[str, ...]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(type(item) is not str for item in surfaces):
        raise ValueError("PACKAGE_DOMAIN_ORIGINAL_KIND_SURFACES_INVALID:" + object_id)
    return tuple(
        sorted(
            item.removeprefix("file:")
            for item in surfaces
            if item.startswith("file:")
        )
    )


def _refutation_guard(
    root: Path,
    audit: DomainOriginalKindAudit,
    files: Mapping[str, str],
) -> None:
    """Repeat the admission gate on the exact bytes of every admitted refutation."""
    kinds = tuple(
        question.kind
        for question in audit.questions
        if question.status == DOES_NOT_APPLY
    )
    if not kinds:
        return
    raw_by_path: dict[str, bytes] = {}
    for path in audit.expected_owned_paths:
        try:
            raw = (root / path).read_bytes()
        except OSError as exc:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_UNAVAILABLE:"
                + audit.object_id
                + ":"
                + path
            ) from exc
        if "sha256:" + sha256(raw).hexdigest() != files.get(path):
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_DIFFERS:"
                + audit.object_id
                + ":"
                + path
            )
        raw_by_path[path] = raw
    closure = package_original_kind_review.audit_closed_effects(
        root,
        audit.expected_owned_paths,
        expected_source_digests={
            path: _EXPECTED_SOURCE_DIGESTS[path] for path in audit.expected_owned_paths
        },
    )
    for kind in kinds:
        try:
            hits = _counterexample_hits(raw_by_path, kind)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_UNPARSEABLE:"
                + audit.object_id
                + ":"
                + kind
            ) from exc
        if hits:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_COUNTEREXAMPLE_FOUND:"
                + audit.object_id
                + ":"
                + kind
            )
        if not _admits_refutation(audit.object_id, kind, closure.status, hits):
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_REFUTATION_NOT_ADMITTED:"
                + audit.object_id
                + ":"
                + kind
            )


def apply_domain_original_kind_profile(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Apply the partial profile while preserving every unresolved question.

    All 38 catalog rows are identity-, ownership-, and source-checked even
    though only rows with a literal affirmative decision enter the partial
    profile. Existing decided cells must exactly equal the source-recaptured
    canonical decision; a same-status reason or evidence substitution fails.
    """
    selected_root = Path(root).resolve(strict=True)
    if type(rows) is not dict or type(files) is not dict:
        raise ValueError("PACKAGE_DOMAIN_ORIGINAL_KIND_INPUT_INVALID")
    openings: dict[str, tuple[dict[str, str], ...]] = {}
    explicit = {
        audit.object_id: {
            question.kind: question.status
            for question in audit.questions
            if question.status != UNRESOLVED
        }
        for audit in DOMAIN_ORIGINAL_KIND_AUDITS
    }
    # This partition runs before the added-kind review on a first migration,
    # but sees that review's retained APPLIES specializations on every later
    # refresh.  Accept exactly those two lifecycle shapes.  Import locally to
    # keep catalog construction acyclic; the review module is fully installed
    # before any migration invokes this applicator.
    from verifier.runtime import package_semantic_review_partitions

    reviewed_additions: dict[str, set[str]] = {
        audit.object_id: set() for audit in DOMAIN_ORIGINAL_KIND_AUDITS
    }
    for object_id, kind, _reason in (
        *package_semantic_review_partitions.SOURCE_AUDITED_APPLICABILITY_BASIS,
        *package_semantic_review_partitions.OBLIGATION_RETENTION_APPLICABILITY_BASIS,
    ):
        if object_id in reviewed_additions:
            reviewed_additions[object_id].add(kind)
            explicit[object_id][kind] = APPLIES
    for audit in DOMAIN_ORIGINAL_KIND_AUDITS:
        row = rows.get(audit.object_id)
        if type(row) is not dict or row.get("object_id") != audit.object_id:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_OBJECT_MISSING:" + audit.object_id
            )
        if row.get("kind") != audit.expected_primary:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_PRIMARY_DIFFERS:" + audit.object_id
            )
        if _owned_paths(row, audit.object_id) != audit.expected_owned_paths:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_OWNERSHIP_DIFFERS:" + audit.object_id
            )
        specializations = row.get("specializations")
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SPECIALIZATIONS_INVALID:"
                + audit.object_id
            )
        observed_specializations = tuple(sorted(specializations))
        accumulated_specializations = tuple(sorted(
            set(audit.expected_specializations)
            | reviewed_additions[audit.object_id]
        ))
        if observed_specializations not in {
            audit.expected_specializations,
            accumulated_specializations,
        }:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SPECIALIZATIONS_DIFFER:"
                + audit.object_id
            )
        unreviewed_roles = sorted(
            kind
            for kind in specializations
            if kind in ORIGINAL_NON_OBJECT_KINDS
            and explicit[audit.object_id].get(kind) != APPLIES
        )
        if unreviewed_roles:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_ACCUMULATED_ROLE_UNREVIEWED:"
                + audit.object_id
                + ":"
                + ",".join(unreviewed_roles)
            )
        opening = _source_snapshot(selected_root, audit)
        for reference in opening:
            if files.get(reference["path"]) != reference["sha256"]:
                raise ValueError(
                    "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_DIFFERS:"
                    + audit.object_id
                    + ":"
                    + reference["path"]
                )
        _refutation_guard(selected_root, audit, files)
        openings[audit.object_id] = opening
        classification = row.get("classification")
        if type(classification) is not dict:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_CLASSIFICATION_INVALID:"
                + audit.object_id
            )
        for kind in ORIGINAL_NON_OBJECT_KINDS:
            decision = classification.get(kind)
            if type(decision) is not dict or set(decision) != {
                "status",
                "reason",
                "evidence",
            }:
                raise ValueError(
                    "PACKAGE_DOMAIN_ORIGINAL_KIND_DECISION_INVALID:"
                    + audit.object_id
                    + ":"
                    + kind
                )
            status = decision["status"]
            if status not in {UNRESOLVED, APPLIES, DOES_NOT_APPLY}:
                raise ValueError(
                    "PACKAGE_DOMAIN_ORIGINAL_KIND_STATUS_INVALID:"
                    + audit.object_id
                    + ":"
                    + kind
                )
            if status != UNRESOLVED and explicit[audit.object_id].get(kind) != status:
                raise ValueError(
                    "PACKAGE_DOMAIN_ORIGINAL_KIND_UNREVIEWED_DECISION:"
                    + audit.object_id
                    + ":"
                    + kind
                )

    result = package_original_kind_review.apply_original_kind_profile(
        selected_root,
        rows,
        files,
        DOMAIN_ORIGINAL_KIND_PROFILE,
        source_applies=_SOURCE_APPLIES,
    )

    for assignment in DOMAIN_ORIGINAL_KIND_PROFILE.assignments:
        for decision in assignment.decisions:
            prior = rows[assignment.object_id]["classification"][decision.kind]
            if prior["status"] != UNRESOLVED:
                canonical = result[assignment.object_id]["classification"][decision.kind]
                if prior != canonical and not _is_installed_placeholder(
                    assignment.object_id, decision.kind, prior, canonical
                ):
                    raise ValueError(
                        "PACKAGE_DOMAIN_ORIGINAL_KIND_DECISION_SUBSTITUTION:"
                        + assignment.object_id
                        + ":"
                        + decision.kind
                    )

    for audit in DOMAIN_ORIGINAL_KIND_AUDITS:
        if _source_snapshot(selected_root, audit) != openings[audit.object_id]:
            raise ValueError(
                "PACKAGE_DOMAIN_ORIGINAL_KIND_SOURCE_CHANGED:" + audit.object_id
            )
    return result


_DECLARATION_HEAD = "The package object declares "
_DECLARATION_MIDDLE = " as its primary original namespace kind. Its source-owned object reason is: "
_DECLARATION_TAIL = (
    " This direct role declaration establishes applicability only; it does not "
    "satisfy the kind's obligations or any higher polish tier."
)


def _is_installed_placeholder(
    object_id: str, kind: str, prior: Mapping[str, Any], canonical: Mapping[str, Any]
) -> bool:
    """Recognize an APPLIES cell that earlier generation installed, not a reviewer.

    Two texts qualify, and only with the audited decision's status and evidence:
    the primary-kind declaration discovery writes for a new object (it mirrors
    ``package_manifest_migration._primary_original_kind_reason``; a test pins the
    two together), and the root-role reason the ownership catalog itself carries for
    this exact object and kind.  Neither was ever a reviewed decision, and replacing
    one with the audited decision loosens nothing.  Any other prior reason or
    evidence still fails closed.
    """
    reason = prior.get("reason")
    if (
        type(reason) is not str
        or set(prior) != {"status", "reason", "evidence"}
        or prior.get("status") != APPLIES
        or canonical.get("status") != APPLIES
        or prior.get("evidence") != canonical.get("evidence")
    ):
        return False
    if reason.startswith(_DECLARATION_HEAD + kind + _DECLARATION_MIDDLE) and reason.endswith(
        _DECLARATION_TAIL
    ):
        return True
    return (object_id, kind, reason) in _OWNERSHIP_ROLE_REASONS


_OWNERSHIP_ROLE_REASONS = frozenset(
    (spec.object_id, decision.kind, decision.reason)
    for spec in DOMAIN_OWNERSHIP_SPECS
    for decision in spec.root_role_decisions
    if decision.status == APPLIES
)


def review_document() -> dict[str, Any]:
    """Return the complete 38-by-25 human review surface."""
    profile_ids = {
        assignment.object_id for assignment in DOMAIN_ORIGINAL_KIND_PROFILE.assignments
    }
    return {
        audit.object_id: {
            "expected_primary": audit.expected_primary,
            "expected_specializations": list(audit.expected_specializations),
            "expected_owned_paths": list(audit.expected_owned_paths),
            "expected_owned_path_set_digest": audit.expected_owned_path_set_digest,
            "expected_source_sha256": {
                path: _EXPECTED_SOURCE_DIGESTS[path]
                for path in audit.expected_owned_paths
            },
            "scope_reason": audit.scope_reason,
            "questions": {
                question.kind: {
                    "status": question.status,
                    "reason": question.reason,
                }
                for question in audit.questions
            },
            "profile_digest": DOMAIN_ORIGINAL_KIND_PROFILE.canonical_digest,
            "profile_assignment_member": audit.object_id in profile_ids,
            "claim_boundary": CLAIM_BOUNDARY,
        }
        for audit in DOMAIN_ORIGINAL_KIND_AUDITS
    }


def _catalog_check() -> None:
    expected_ids = tuple(spec.object_id for spec in DOMAIN_OWNERSHIP_SPECS)
    if tuple(audit.object_id for audit in DOMAIN_ORIGINAL_KIND_AUDITS) != expected_ids:
        raise AssertionError("domain original-kind object denominator differs")
    if len(expected_ids) != 38 or len(set(expected_ids)) != 38:
        raise AssertionError("domain original-kind object denominator invalid")
    paths = {
        path
        for audit in DOMAIN_ORIGINAL_KIND_AUDITS
        for path in audit.expected_owned_paths
    }
    if paths != set(_EXPECTED_SOURCE_DIGESTS):
        raise AssertionError("domain original-kind source denominator differs")
    cross_root = {
        spec.object_id: {
            decision.kind: decision.status
            for decision in spec.root_role_decisions
        }
        for spec in DOMAIN_OWNERSHIP_SPECS
        if spec.root_role_decisions
    }
    if cross_root != _EXPECTED_CROSS_ROOT_DECISIONS:
        raise AssertionError("domain original-kind cross-root decisions differ")
    applies = 0
    refuted = 0
    unresolved = 0
    for audit in DOMAIN_ORIGINAL_KIND_AUDITS:
        if tuple(question.kind for question in audit.questions) != ORIGINAL_NON_OBJECT_KINDS:
            raise AssertionError(audit.object_id + " original-kind denominator differs")
        if any(not question.reason.strip() for question in audit.questions):
            raise AssertionError(audit.object_id + " has a blank reason")
        applies += sum(question.status == APPLIES for question in audit.questions)
        refuted += sum(
            question.status == DOES_NOT_APPLY for question in audit.questions
        )
        unresolved += sum(question.status == UNRESOLVED for question in audit.questions)
    proposed = _PROPOSED_IDENTITY_REFUTATIONS
    if not set(proposed) <= set(expected_ids) or any(
        type(kinds) is not tuple
        or not kinds
        or tuple(sorted(kinds)) != kinds
        or any(kind not in REFUTABLE_ORIGINAL_KINDS for kind in kinds)
        for kinds in proposed.values()
    ):
        raise AssertionError("domain original-kind identity refutation table invalid")
    if set(_CLOSURE_PINS) != set(proposed) or any(
        status not in {"CLOSED", "UNKNOWN"} for status, *_ in _CLOSURE_PINS.values()
    ):
        raise AssertionError("domain original-kind closure pins differ")
    if any(
        kind not in proposed.get(object_id, ())
        for object_id, kind in _IDENTITY_CLAIMS
    ):
        raise AssertionError("domain original-kind identity claim is not a proposal")
    admitted = sum(
        _admits_refutation(object_id, kind, _closure_status(object_id), ())
        for object_id, kinds in proposed.items()
        for kind in kinds
    )
    if applies != 28 or refuted != admitted or unresolved != 950 - 28 - admitted:
        raise AssertionError("domain original-kind decision denominator differs")


_catalog_check()


__all__ = [
    "CLAIM_BOUNDARY",
    "DOMAIN_ORIGINAL_KIND_AUDITS",
    "DOMAIN_ORIGINAL_KIND_PROFILE",
    "DomainOriginalKindAudit",
    "DomainOriginalKindQuestion",
    "SOURCE_BINDING_DIGEST",
    "UNRESOLVED",
    "apply_domain_original_kind_profile",
    "review_document",
]

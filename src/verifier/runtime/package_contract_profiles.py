"""Installed package-variant closure profiles for Verifier Standard (VSTD) Polish 1--3.

Terminology: central processing unit (CPU).

The ordinary object routes describe retained runtime subjects.  Verifier's own
``objects.vstd`` instead admits reviewed source representations.  A source
route therefore proves the adaptation boundary while every behavioral route is
still assessed as either necessary or conditionally non-triggered.  These
profiles pin that combined denominator independently of the runtime catalogs so
that three passing ``KIND-N.90`` routes can never erase behavioral work.

Profiles are current-package contracts, not universal claims about every object
variant.  Local namespace extensions need their own profile and remain UNKNOWN.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import inspect
from pathlib import Path
from typing import Any, Iterator, Mapping

from verifier.core.namespace import ObjectKind
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.tier_zero_profile import (
    validate_applicability_binding,
    value_digest,
)


SCHEMA = "verifier-installed-package-contract-profiles-1"
VERSION = "verifier-installed-package-variant-closure-1"
MATRIX_SCHEMA = "verifier-package-tier-zero-through-three-contract-matrix-1"
BASE_CORE_KIND_COUNT = 26
PACKAGE_ADDED_KIND_COUNT = 12
PACKAGE_KIND_COUNT = 38
MATRIX_KIND_DENOMINATOR = PACKAGE_KIND_COUNT
MATRIX_REPOSITORY_ADMISSION_DENOMINATOR = 9
MATRIX_ADMISSION_OBLIGATION_DENOMINATOR = 36
MATRIX_PROFILE_OBLIGATION_DENOMINATOR = 62
MATRIX_FAMILY_OBLIGATION_DENOMINATOR = 71
MATRIX_BASE_CORE_ROUTE_DENOMINATOR = 194
MATRIX_PACKAGE_ADDED_ROUTE_DENOMINATOR = 99
MATRIX_ROUTE_DENOMINATOR = 293
MATRIX_DEFINED_OBLIGATION_DENOMINATOR = 364


# This namespace denominator is independent of the route tables below. A kind
# disappearing from the registry and its profile in the same edit must still
# be reported as an omission rather than accepted as a smaller new universe.
_EXPECTED_BASE_CORE_KINDS = (
    "ACTOR", "AGENT", "ARCH", "BENCH", "BOT", "COLLECTIVE", "DATA", "ENV",
    "EVENT", "GRAPH", "HARDWARE", "HARNESS", "HUMAN", "HYPER", "IDENTITY",
    "MODEL", "OBJECT", "OWNER", "RECEIPT", "ROLE", "SIM", "SPACE", "TIME",
    "TOKEN", "TRAIN", "VERIFIER",
)
_EXPECTED_PACKAGE_ADDED_KINDS = (
    "ACTUATOR", "ASSET", "CONTROLLER", "FINBOT", "LEDGER", "MARKET",
    "MEASUREMENT", "POLICY", "PROTOCOL", "ROBOT", "SENSOR", "TRANSACTION",
)
_EXPECTED_NAMESPACE_KINDS = tuple(sorted(
    {*_EXPECTED_BASE_CORE_KINDS, *_EXPECTED_PACKAGE_ADDED_KINDS}
))

_EXPECTED_REPOSITORY_ADMISSION_COORDINATES = tuple(
    f"VSTD-T0.{index}" for index in range(1, 10)
)
_SOURCE_ROUTE_OBLIGATION_SUFFIXES = {
    1: "source-representation-facets",
    2: "source-representation-dynamics",
    3: "source-representation-statics",
}


# A semantic mapping asks whether an installed finite route tests the declared
# family. Package applicability is a different question and must be recomputed
# from the complete source-owned package review. No static "no carrier" table
# may outlive an APPLIES decision or a newly declared real consequence.
_PACKAGE_INSTANCE_FAMILY_OBLIGATIONS: dict[str, tuple[str, ...]] = {
    "MARKET": (
        "MARKET-0.1-orders-and-access",
        "MARKET-0.2-matching-and-allocation",
        "MARKET-0.3-settlement-and-disruption",
    ),
    "ROBOT": (
        "ROBOT-0.1-agent-to-actuator-binding",
        "ROBOT-0.2-physical-reach-and-observation",
        "ROBOT-0.3-consequences-and-intervention",
    ),
    "FINBOT": (
        "FINBOT-0.1-agent-and-financial-authority",
        "FINBOT-0.2-financial-exposure-and-dependencies",
        "FINBOT-0.3-decisions-effects-and-recovery",
    ),
}
_PACKAGE_INSTANCE_EFFECT_DOMAIN = {
    "MARKET": "REAL_MARKET",
    "ROBOT": "REAL_PHYSICAL",
    "FINBOT": "REAL_FINANCIAL",
}
_PACKAGE_REVIEW_COORDINATE_RECEIPT = {
    "object_id": "vstd-source-provenance-observer",
    "expected_source_coordinate_digest": (
        "sha256:734ee3544cb81511d9abe4c8e0a8dc5d3675fd5c01dd6e125b3e61d32fc1b0be"
    ),
    "source_digests": {
        "src/verifier/runtime/package_semantic_ownership.py": (
            "sha256:cf0cd27f46e147263459579908ad573e504ddbeee4b99cec9ee8f95a30eff4bd"
        ),
        "src/verifier/runtime/package_semantic_review_verifier.py": (
            "sha256:55a26474b8994f802f05073214fda9b96e51f4f3565dbded6ec00f5a21525afd"
        ),
        "src/verifier/runtime/package_original_kind_catalog_runtime.py": (
            "sha256:4d2fc07fa0631f0352a97c564d51781cee595a62d5e695726ca438ad694f1dda"
        ),
    },
    "evidence": (
        "The source partition has 122 rows and the focused observer/catalog lane "
        "passes; ACTUATOR is retired for this object and the fsmonitor claim is "
        "limited to the mutable worktree-state capture."
    ),
    "not_established": (
        "Whole-package conformance, full-application coverage, release, and deployment.",
    ),
}


_ROUTE_BINDING_FIELDS = (
    "coordinate", "obligation_id", "object_kind", "tier", "reason",
    "exact_claim", "semantic_version", "proposition_digest",
    "mechanism_digest", "checking_mechanism", "adapter",
)


# Each credit is a literal result of the source audit. The first five bind the
# newly strengthened fresh-execution adapters to their checker, worker, and
# selected implementation bytes. The retained consequential routes publish a
# mechanism digest over their checker, shared engine, namespace consequence
# logic, and declarations. We pin those four source files independently as
# well: a self-consistent digest change is still source drift, not semantic
# proof. Any route, proposition, mechanism, or selected source drift reopens
# UNKNOWN instead of silently inheriting yesterday's audit.
_ADDED_KIND_SEMANTIC_SOURCE_DIGESTS = {
    "src/verifier/runtime/added_kind_behavioral_routes.py": "sha256:19f121645632ef499d6dc60ff5fc8b7ab7c0ed8a3fc34cdf9d023cbf44687775",
    "src/verifier/runtime/namespace_consequences.py": "sha256:aba836fcadc2e6432a207ddfe1ec4c2b7e891c5d4215bfe767b117b2eb5a20b9",
    "src/verifier/runtime/namespace_contracts.py": "sha256:acd60dc68b87188790a50bd20ba548955dd581e87396c23d3c07c0f73f36470f",
}
_ADDED_KIND_CHECKER_SOURCE_DIGESTS = {
    "MARKET": {
        "src/verifier/domains/contracts/market_checks.py": "sha256:2a7716c17e6ba95be2c0c812d4862037f515baf1b6407560b43cb28bb07ba159",
    },
    "ROBOT": {
        "src/verifier/domains/contracts/robot_checks.py": "sha256:403d84725192917af694d3c84d4a475a22a1fc35a8a15c1b91741bf5f916df00",
    },
    "FINBOT": {
        "src/verifier/domains/contracts/finbot_checks.py": "sha256:c1f75930f077067855ff90cfd9f5ce5c1d1fe287d0427bf2c1c826f4266bf94a",
    },
}


_SEMANTIC_MAPPING_BINDINGS: dict[str, dict[str, Any]] = {
    "LEDGER-0.2-accounting-invariants": {
        "route_coordinate": "LEDGER-2.1",
        "route_binding_digest": "sha256:1c27b52923f19e38cd091ef723f960219cdaddcd24e8d5f0094e0f748eeb1935",
        "proposition_digest": "sha256:d747e792e4f7e8f729b44fbad480ff394d8c2a65f79d0b5e1c588ef02c796a3b",
        "catalog_mechanism_digest": None,
        "source_digests": {
            "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
            "src/verifier/runtime/local_ledger_execution.py": "sha256:e539210fb59ac7d15532b32d3e43d013b639aafd790dfdd4ad5cd33d3cb67f1f",
            "src/verifier/runtime/local_ledger_control_checks.py": "sha256:d78330f346cb80ca09dadc60806cd41e3c3f943968bc0eff18c40822d0d5d7db",
            "src/verifier/runtime/local_ledger_controls.py": "sha256:281ad024e64b074f5a88d455d7dc0362228d23b889a6a09c0e80c002d270bd35",
            "src/verifier/runtime/local_ledger_worker.py": "sha256:acc77fa227ba4f4f5c0a50bbb3cde936907f53a3890356aece472b8e87802045",
            "src/verifier/runtime/polish_invocation_ledger.py": "sha256:ad8d62ff47d8d4d92277fe2fba353bbbf82f088848dda07bc2202b5fdffadd3d",
        },
        "coverage_reason": (
            "LEDGER-2.1 executes one canonical proposal as the accounting unit, "
            "binds receipt sequence and proposal digests to persisted records, "
            "observes two authorized commit sources, treats replay as no source, "
            "observes no sink, and uses exact unrounded integer sequences."
        ),
    },
    "MEASUREMENT-0.2-units-time-and-uncertainty": {
        "route_coordinate": "MEASUREMENT-2.1",
        "route_binding_digest": "sha256:b3fb787e341b0ca79a78652b6ae82ffc5c31accd596a24215ebfc30cfe5adddc",
        "catalog_mechanism_digest": None,
        "source_digests": {
            "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
            "src/verifier/runtime/resource_measurement_execution.py": "sha256:ffafaf207fbcb5b7f3b3b3ae7f193588b868528230296455be897036a28881ab",
            "src/verifier/runtime/resource_measurement_worker.py": "sha256:3d5f78c9bdace5d4b4e58f5d7255a78582ee12f4e23ed486a5d4c2707b4ce030",
            "src/verifier/domains/contracts/sim_resource_fresh.py": "sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",
        },
        "coverage_reason": (
            "MEASUREMENT-2.1 executes two fresh captures, binds nanosecond and "
            "byte units to every selected step and exact workload, requires distinct "
            "process reference frames, and explicitly refuses any inferred physical "
            "or statistical uncertainty estimate beyond the raw software counters."
        ),
    },
    "SENSOR-0.2-calibration-and-envelope": {
        "route_coordinate": "SENSOR-2.1",
        "route_binding_digest": "sha256:dd280f025c75b40d393ccec7b7c2fca3d020aa10fe1b424fc8acd475f3ac92e3",
        "catalog_mechanism_digest": None,
        "source_digests": {
            "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
            "src/verifier/runtime/resource_measurement_execution.py": "sha256:ffafaf207fbcb5b7f3b3b3ae7f193588b868528230296455be897036a28881ab",
            "src/verifier/runtime/resource_measurement_worker.py": "sha256:3d5f78c9bdace5d4b4e58f5d7255a78582ee12f4e23ed486a5d4c2707b4ce030",
            "src/verifier/domains/contracts/sim_resource_fresh.py": "sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",
        },
        "coverage_reason": (
            "SENSOR-2.1 declares physical calibration inapplicable to this digital "
            "instrument, source-binds its calibration substitute, executes the full "
            "two-step acquisition envelope, checks elapsed rather than added clocks "
            "and peak rather than current allocation, and refuses source drift."
        ),
    },
    "CONTROLLER-0.3-intervention-and-failure": {
        "route_coordinate": "CONTROLLER-3.1",
        "route_binding_digest": "sha256:8f85eb11ad118909c588a5400efc28cc3582a537eb18c39eae25d347b9977ee5",
        "catalog_mechanism_digest": None,
        "source_digests": {
            "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
            "src/verifier/runtime/emulator_control_execution.py": "sha256:dabc80aefa46db6b4ec9cadaffc0eb0546360d6b2f33d87fd063b98396013935",
            "src/verifier/runtime/emulator_control_worker.py": "sha256:a8a41560791c94fabc158bdef2beab280dbf269f057db66c4251f0fa9a00d87b",
            "src/verifier/hardware/emulator.py": "sha256:0ae9d764733223ae92ed940e42bb327ea99110aa5e863bd582b0732a3f054683",
        },
        "coverage_reason": (
            "CONTROLLER-3.1 requires typed feedback, refuses missing feedback, "
            "active reconfiguration and replayed competing command identities without "
            "state change, and verifies both failed and successful reset behavior."
        ),
    },
    "PROTOCOL-0.1-participants-and-states": {
        "route_coordinate": "PROTOCOL-1.1",
        "route_binding_digest": "sha256:0efe4edfa7650c17197f290363e308ccf004df673be95028b12d809e37fde89a",
        "catalog_mechanism_digest": None,
        "source_digests": {
            "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
            "src/verifier/runtime/worker_protocol_execution.py": "sha256:5802e7edfc2a1951e8331eb31b230345ea3858907fdd23abaa6da8b79c343c92",
            "src/verifier/runtime/worker_protocol_worker.py": "sha256:48a143de2b0839d58f6a0c6841dd09af389f7bbbcc521d45f2708398d481e659",
            "src/verifier/runtime/local_ledger_execution.py": "sha256:e539210fb59ac7d15532b32d3e43d013b639aafd790dfdd4ad5cd33d3cb67f1f",
            "src/verifier/runtime/local_ledger_worker.py": "sha256:acc77fa227ba4f4f5c0a50bbb3cde936907f53a3890356aece472b8e87802045",
        },
        "coverage_reason": (
            "PROTOCOL-1.1 executes distinct parent-dispatcher and fixed-worker "
            "participants through CREATED_REQUEST, LAUNCHED_FIXED_WORKER, and "
            "DECODED_BOUND_REPLY states and refuses replayed transition aliases."
        ),
    },
    **{
        obligation_id: {
            "route_coordinate": coordinate,
            "route_binding_digest": route_digest,
            "proposition_digest": proposition_digest,
            "catalog_mechanism_digest": mechanism_digest,
            "source_digests": {
                **_ADDED_KIND_SEMANTIC_SOURCE_DIGESTS,
                **_ADDED_KIND_CHECKER_SOURCE_DIGESTS[kind],
            },
            "coverage_reason": reason,
        }
        for obligation_id, coordinate, route_digest, proposition_digest,
        mechanism_digest, kind, reason in (
            ("MARKET-0.1-orders-and-access", "MARKET-1.1", "sha256:0c47466a192f099d4fc9bdcb4407774abe79af6765a8464575df382000279bc2", "sha256:5b061888577a2718eb62076371ce24da197872059d9cd56e04af1d8d7d9ac959", "sha256:5a0f6be8eb67c986318e7dcc929b41db783c9702b83bb4fb1332eac01b59a72e", "MARKET", "The current source-bound retained rechecker covers admitted participant and unique order identities, exact order validation, cancellation transitions, and legal terminal lifecycle transitions. The combined current-hash behavioral, package-integration, consequence, agency, and physical-boundary review lane passes 216 tests; venue authority, fair access, live order-book correspondence, and whole MARKET conformance remain NOT_ESTABLISHED."),
            ("MARKET-0.2-matching-and-allocation", "MARKET-2.1", "sha256:45b504c0eb29207f48aa061491ee0d1403746e46c96589773399316316c5093c", "sha256:8ceaaba9820ef19085e35514f72f8c079ae614a09bc2a7b36e110a97577cacdd", "sha256:9ee8f924c77d0c88cd3b537fc8a807400cba880efc38271fd8ec8b37e07c0cc8", "MARKET", "The retained rechecker covers integer price and quantity units, side and limit compatibility, unique priority, replay identity, quantity conservation, and closed retained manipulation-rule records; it does not establish fair price formation, complete rule coverage, or manipulation absence."),
            ("MARKET-0.3-settlement-and-disruption", "MARKET-3.1", "sha256:4f23207b9181928d844e15b3c3115a16f843ee2799b5087219c14835f9b30fa8", "sha256:6dc3ceeccedfda74c4f0f3b826f909881ee2eb04fb72e172df6ed064a499194a", "sha256:9ee8f924c77d0c88cd3b537fc8a807400cba880efc38271fd8ec8b37e07c0cc8", "MARKET", "The retained rechecker covers settlement arithmetic, duplicate finality, disruption responses, and closed retained participant-failure records while leaving external dependencies, failure completeness, and real settlement unestablished."),
            ("ROBOT-0.1-agent-to-actuator-binding", "ROBOT-1.1", "sha256:c5113fa6fdb0ccba91b202e5223ba69b7fcce9d3e3b57e2bec5bf6461930070f", "sha256:b4847bbabc6f6e85a5b5b134ddc8713f411995a8a3ce1edfbef0a2025c73706f", "sha256:453cd1469357a2376881c8ec3bd549e847927e5704f8c7d22191f1e47e701a21", "ROBOT", "The current source-bound consequence rechecker covers the exact declared AGENT-HARNESS-CONTROLLER-ACTUATOR path to a typed real-physical endpoint. The combined current-hash behavioral, package-integration, consequence, agency, and physical-boundary review lane passes 216 tests; runtime correspondence, physical actuation, confinement, endpoint identity, command authority, and safety remain NOT_ESTABLISHED."),
            ("ROBOT-0.2-physical-reach-and-observation", "ROBOT-2.1", "sha256:839c4e2edc2fa1d27e8e5d1b92d52c1068b5bdc06cb32e61ff9ca677420da549", "sha256:94553241b12faba969036eae3cf295126ab32e62aa81b2ddabae14a1aad606f0", "sha256:726a07298a70fb5f2b22c849b78e06104e86930ab1f10aa90ab6cb5f3054fe94", "ROBOT", "The retained rechecker covers command, effect, and observation identifiers, strict sequence order, one typed software-to-physical crossing per trace, unique retained-effect digests, and typed confinement claims whose authenticity remains NOT_ESTABLISHED."),
            ("ROBOT-0.3-consequences-and-intervention", "ROBOT-3.1", "sha256:e03f34f80c42743a7ce4ccf1407b104f52cbb9c805373ac6a727720f6ef52bae", "sha256:6ad0e0b8eed0b099246f502c143af47bba4e0461b414f14a2dccfe9aa05d8760", "sha256:726a07298a70fb5f2b22c849b78e06104e86930ab1f10aa90ab6cb5f3054fe94", "ROBOT", "The retained rechecker maps every selected actuator hazard to an explicit SAFE_STATE or CONTINUITY intervention with a reason and integer operating limit; adequacy, successful intervention, and physical recovery remain unestablished."),
            ("FINBOT-0.1-agent-and-financial-authority", "FINBOT-1.1", "sha256:42e9d823569d127ac820e95bc886feca4d4b4cf095e7ee7ff938a570b185eb98", "sha256:77dd46051c71eb61d7c84a3b182a6a290f6328d935dfdb264efc4d9f056660b5", "sha256:f01f081ac8115f8e64bc0ed1ae5288f794b4311c03abd92ebce71b150cad934a", "FINBOT", "The retained consequence rechecker covers the exact AGENT-HARNESS path, typed real-financial endpoint, structured scope bound to those identifiers, and presence of a declared authority boundary without establishing identity or legal authority."),
            ("FINBOT-0.2-financial-exposure-and-dependencies", "FINBOT-2.1", "sha256:a926ecc72b7731a707672788ca1ba263f5a0decaf1a4351fce889df27f0eec03", "sha256:5a39707fbbbd7c924bdf6a27de6ee4f14fa847fd2a8a762b17961a7d03da9195", "sha256:f01f081ac8115f8e64bc0ed1ae5288f794b4311c03abd92ebce71b150cad934a", "FINBOT", "The retained rechecker covers the declared endpoint and dependencies, retained party and asset identifiers, integer exposure amounts, and declared limits without asserting external identity, backing, balances, real effects, or independent enforcement."),
            ("FINBOT-0.3-decisions-effects-and-recovery", "FINBOT-3.1", "sha256:9d7d4a9e9896b034dbf204075f6d6dbe1e1cac939640788dccfbeb686c6b9fd8", "sha256:9c36da603cd0ceb510755f59b3a7ceda941300e687bd8c2e895ab59cb6491e14", "sha256:f01f081ac8115f8e64bc0ed1ae5288f794b4311c03abd92ebce71b150cad934a", "FINBOT", "The retained rechecker binds decision, exposure, effect identifier, retry key, intervention, and reconciliation records and refuses duplicate applied retries; real-money effect, settlement, independent limit enforcement, and recovery success remain unestablished."),
        )
    },
}


# Per-source change receipts. Every pinned source digest above must be one of the
# ``pinned_sha256`` values recorded here, and every recorded value must still be pinned.
# A pin that moves without a receipt therefore fails tests/test_package_contract_profiles.py,
# so an aggregate repin cannot hide a semantic change. ACCEPTED means the review proved the
# route predicates, status ceilings, failure/UNKNOWN semantics and NOT_ESTABLISHED boundaries
# unchanged or strengthened. REJECTED and UNKNOWN keep the prior pin, so dependent field
# statuses stay UNKNOWN_SOURCE_OR_ROUTE_DRIFT. Prior bytes are recorded by digest only.
# The legacy MARKET/ROBOT/FINBOT catalog mechanism digests are not source pins:
# 9ee8f924…, 726a0729… and f01f081a… are not reproducible from recovered
# inputs, so no equivalence claim is made about them. A route may instead bind
# the reproducible current mechanism after its predicates, status ceilings,
# adversaries, package integration, and explicit NOT_ESTABLISHED boundaries
# have been independently rerun.
_SOURCE_CHANGE_RECEIPTS: dict[str, dict[str, Any]] = {
    "src/verifier/domains/contracts/agency_surface.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:d7030f608c82578ff62e7fcd74d22ac2457a2656634f40a0dfca769fb2eed297",),
        "observed_sha256": "sha256:d7030f608c82578ff62e7fcd74d22ac2457a2656634f40a0dfca769fb2eed297",
        "evidence": (
            "Current d7030f6… replays exact AGENT/BOT/ROBOT/FINBOT agency "
            "bindings, rejects cross-agent, child, coordinate, certificate, action, "
            "effect, and operational-boundary substitutions, and preserves explicit "
            "external claim limits. Its agency, consequence, package-integration, "
            "and physical-boundary regressions pass in the reviewed current graph."
        ),
        "not_established": (
            "Runtime correspondence, physical actuation, financial execution, authority, confinement, endpoint identity, causal attribution, and safety.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/domains/contracts/finbot_checks.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:c1f75930f077067855ff90cfd9f5ce5c1d1fe287d0427bf2c1c826f4266bf94a",),
        "observed_sha256": "sha256:c1f75930f077067855ff90cfd9f5ce5c1d1fe287d0427bf2c1c826f4266bf94a",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/domains/contracts/market_checks.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:2a7716c17e6ba95be2c0c812d4862037f515baf1b6407560b43cb28bb07ba159",),
        "observed_sha256": "sha256:2a7716c17e6ba95be2c0c812d4862037f515baf1b6407560b43cb28bb07ba159",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/domains/contracts/robot_checks.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:403d84725192917af694d3c84d4a475a22a1fc35a8a15c1b91741bf5f916df00",),
        "observed_sha256": "sha256:403d84725192917af694d3c84d4a475a22a1fc35a8a15c1b91741bf5f916df00",
        "evidence": (
            "Current 403d847… promotes no route and makes seven previously implicit "
            "physical limits explicit in every PASS, FAIL, and UNKNOWN certificate. "
            "The original RED had three absent-evidence UNKNOWN cases missing those "
            "limits; the exact focused suite is now GREEN 4/4, independently rerun."
        ),
        "not_established": (
            "Physical endpoint identity, effect feedback, interlock execution, stability, command authority, operating-limit adequacy, and intervention execution.",
            "Runtime correspondence, external confinement, physical actuation, observation authenticity, causal attribution, and safety.",
            "Whole-package conformance and package-polish closure.",
        ),
    },
    "src/verifier/hardware/emulator.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:0ae9d764733223ae92ed940e42bb327ea99110aa5e863bd582b0732a3f054683",),
        "observed_sha256": "sha256:0ae9d764733223ae92ed940e42bb327ea99110aa5e863bd582b0732a3f054683",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/added_kind_behavioral_routes.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:19f121645632ef499d6dc60ff5fc8b7ab7c0ed8a3fc34cdf9d023cbf44687775",),
        "observed_sha256": "sha256:19f121645632ef499d6dc60ff5fc8b7ab7c0ed8a3fc34cdf9d023cbf44687775",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/local_ledger_control_checks.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:d78330f346cb80ca09dadc60806cd41e3c3f943968bc0eff18c40822d0d5d7db",),
        "observed_sha256": "sha256:d78330f346cb80ca09dadc60806cd41e3c3f943968bc0eff18c40822d0d5d7db",
        "evidence": (
            "Current d78330f… closes every public PASS receipt to an exact local-only "
            "field set, NOT_ESTABLISHED public authority, local claim boundary, and "
            "self-bound receipt digest. Fresh adversaries reject scope relabeling, "
            "injected real-settlement fields, and rehashed ledger-identity substitution; "
            "the focused financial boundary suite passes 11 tests and the owning worker's "
            "direct suite passes 87 tests."
        ),
        "not_established": (
            "Public authority, custody, backing, settlement, finality, market access, and manipulation absence.",
            "Whole-package conformance and package-polish closure.",
        ),
    },
    "src/verifier/runtime/local_ledger_controls.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:281ad024e64b074f5a88d455d7dc0362228d23b889a6a09c0e80c002d270bd35",),
        "observed_sha256": "sha256:281ad024e64b074f5a88d455d7dc0362228d23b889a6a09c0e80c002d270bd35",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/local_ledger_execution.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": (
            "sha256:e539210fb59ac7d15532b32d3e43d013b639aafd790dfdd4ad5cd33d3cb67f1f",
        ),
        "observed_sha256": "sha256:e539210fb59ac7d15532b32d3e43d013b639aafd790dfdd4ad5cd33d3cb67f1f",
        "evidence": (
            "Current e539210… retains the bounded local financial checks and makes "
            "both TRANSACTION Tier-3 predicates reject altered one-attempt or finite "
            "busy-bound observations. This accepts only the fresh isolated SQLite "
            "behavior without claiming equivalence to unrecovered prior bytes."
        ),
        "not_established": (
            "External accounting truth, transaction finality, distributed ordering, public authority, custody, backing, and settlement.",
            "Whole-package conformance and package-polish closure.",
        ),
    },
    "src/verifier/runtime/local_ledger_worker.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:acc77fa227ba4f4f5c0a50bbb3cde936907f53a3890356aece472b8e87802045",),
        "observed_sha256": "sha256:acc77fa227ba4f4f5c0a50bbb3cde936907f53a3890356aece472b8e87802045",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/manifest_write_execution.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:360bb109e60c349a9e3bc4064c08b6a1157d0e3bb25474b3c5fd86cf6df4e0c7",),
        "observed_sha256": "sha256:360bb109e60c349a9e3bc4064c08b6a1157d0e3bb25474b3c5fd86cf6df4e0c7",
        "evidence": (
            "Current 360bb10… requires the Tier-3 manifest routes to bind an exact "
            "one-attempt ceiling for each observed exclusive create or replacement; "
            "altered limits or per-operation counts are refuted."
        ),
        "not_established": (
            "Retry, backoff, or exhaustion behavior outside the fixed fresh worker.",
            "Power-loss durability, arbitrary-writer protection, authority, whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/manifest_write_worker.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:f35b0af2432af8ce488b9e21f294269c1e1013765ef2be0f292f152ca48e69ff",),
        "observed_sha256": "sha256:f35b0af2432af8ce488b9e21f294269c1e1013765ef2be0f292f152ca48e69ff",
        "evidence": (
            "Current f35b0af… counts the actual exclusive-create or replacement edge "
            "for every fixed Tier-3 manifest operation and reports per-call counts."
        ),
        "not_established": (
            "Behavior of callers or writers outside the fixed private worker.",
            "Power-loss durability, authority, whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/namespace_admission.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:9de470e6d3005a189a277757620d816603909f6654c0d15aa0073ec7d8aefa8e",),
        "observed_sha256": "sha256:9de470e6d3005a189a277757620d816603909f6654c0d15aa0073ec7d8aefa8e",
        "evidence": (
            "Current 9de470e… is the exact discovery producer exercised before each "
            "fixed manifest publication attempt; pinning it prevents an unreviewed "
            "producer change from inheriting retry-limit credit."
        ),
        "not_established": (
            "Correctness or authority of arbitrary discovered source.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/namespace_cli.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:70319f32d64fbe25a2a0d49bb46a285d476cd339af632394d2e35325fe0cb7db",),
        "observed_sha256": "sha256:70319f32d64fbe25a2a0d49bb46a285d476cd339af632394d2e35325fe0cb7db",
        "evidence": (
            "Current 70319f3… contains the exact exclusive-create and single-replace "
            "publication edges counted by the fixed manifest worker."
        ),
        "not_established": (
            "Retry guarantees for other commands, callers, or external writers.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/namespace_consequences.py": {
        # This is an accepted semantic repair, not an equivalence claim about
        # unrecovered prior bytes. It closes reproduced ROBOT/FINBOT label
        # escape while retaining typed contradictions as FAIL and absent,
        # unrelated, or unreachable effects as UNKNOWN/non-promoting.
        "decision": "ACCEPTED",
        "pinned_sha256": (
            "sha256:aba836fcadc2e6432a207ddfe1ec4c2b7e891c5d4215bfe767b117b2eb5a20b9",
        ),
        "observed_sha256": "sha256:aba836fcadc2e6432a207ddfe1ec4c2b7e891c5d4215bfe767b117b2eb5a20b9",
        "evidence": (
            "Current aba836f… preserves prior 1909d1…'s reproduced label-escape "
            "repair and atomic source-reviewed core/hardware/discovery route. It "
            "also retains downstream ROBOT/FINBOT obligations for exact "
            "compiler-demanded AGENT/BOT roles reached by explicit edges without "
            "turning them into structural roles; the independent Node interpreter "
            "matches that distinction. The combined consequence, agency, and "
            "physical-boundary suite passes 116 tests at this exact source hash. It "
            "binds every demand-only semantic type to the exact source catalog's "
            "object, kind, and either complete reason or the compiler's sole "
            "readable-prefix-plus-digest projection, so obligations remain required "
            "without inventing an AGENT, ROBOT, FINBOT, harness, control chain, or "
            "external effect. A generic financial kind is not promoted to a "
            "REAL_FINANCIAL endpoint when that object's exact FINBOT decision "
            "expressly withholds financial effect; explicit real-financial effects "
            "and typed endpoints without that boundary are unchanged. The reviewed "
            "accelerator endpoint remains REAL_PHYSICAL only through the separately "
            "bound controls/actuates route and source-established ACTUATOR evidence. "
            "Selection, execution, authority, occurrence, correspondence, "
            "confinement, safety, and actual external effect remain NOT_ESTABLISHED. "
            "A modified projection remains structural and fail-closed. The migration-only "
            "recognizer still cannot delete genuine reviewed effects, and Python/Node "
            "derivation parity remains covered."
        ),
        "not_established": (
            "Byte or semantic equivalence to unrecovered prior 1c74aa… source.",
            "Physical effect, financial effect, external authority, release, and deployment.",
        ),
    },
    "src/verifier/runtime/namespace_contracts.py": {
        # Recovered prior bytes (5c9d37…) differ from current only by additions: zero deleted
        # lines, identical registry (38 kinds, identical values, identical ObjectKind members).
        # Mechanism digests over this file are NOT reproduced by the pinned values (see module note).
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:acd60dc68b87188790a50bd20ba548955dd581e87396c23d3c07c0f73f36470f",),
        "observed_sha256": "sha256:acd60dc68b87188790a50bd20ba548955dd581e87396c23d3c07c0f73f36470f",
        "evidence": (
            "Prior 5c9d37c6… is additive to acd60dc6…: 0 removed lines; namespace_registry() identical "
            "across 38 kinds; new validate_kind_denominators and kind_denominators only."
        ),
        "not_established": (
            "Mechanism digest reproduction for MARKET/ROBOT/FINBOT, which stays UNKNOWN.",
        ),
    },
    "src/verifier/runtime/package_execution.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",),
        "observed_sha256": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
        "evidence": (
            "Current b140adf… retains source-integrity enforcement: stable well-formed pin "
            "contradictions FAIL; missing, malformed, or moving source stays UNKNOWN; stale "
            "cached PASS replays and cannot survive source movement. The exact "
            "source-integrity, observation, execution-role, owned-process, selected "
            "execution, and subject-binding suite passes 175 tests; the dependent "
            "ledger and protocol suites pass 116 and 70 tests."
        ),
        "not_established": (
            "Transaction finality.",
            "Accounting closure.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/polish_invocation_ledger.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:ad8d62ff47d8d4d92277fe2fba353bbbf82f088848dda07bc2202b5fdffadd3d",),
        "observed_sha256": "sha256:ad8d62ff47d8d4d92277fe2fba353bbbf82f088848dda07bc2202b5fdffadd3d",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/provenance_policy_execution.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:f16f776af628dae845d532ac7ed0ff116895f00e823aa8a95c625be8514eee92",),
        "observed_sha256": "sha256:f16f776af628dae845d532ac7ed0ff116895f00e823aa8a95c625be8514eee92",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/runtime/token_asset_execution.py": {
        "decision": "UNCHANGED",
        "pinned_sha256": ("sha256:c4058569d8d7e138ae75592a794bea2c39516b2fa191f38c547113c7c0ac55c9",),
        "observed_sha256": "sha256:c4058569d8d7e138ae75592a794bea2c39516b2fa191f38c547113c7c0ac55c9",
        "evidence": "Pinned bytes equal current bytes.",
        "not_established": (),
    },
    "src/verifier/domains/contracts/sim_resource_fresh.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",),
        "observed_sha256": "sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",
        "evidence": (
            "Current 36a8064… source-binds the fresh CPython resource acquisition, "
            "rechecks the loaded source manifest and exact step bindings, and retains "
            "raw software-counter and nonphysical boundaries. This accepts current "
            "bounded behavior without claiming equivalence to unrecovered prior bytes."
        ),
        "not_established": (
            "Transition-exclusive cost, physical calibration or accuracy, total resource use, host attestation, or external phenomenon truth.",
            "The TIME-open SIM-2.4 package/source-native route identity seam.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:c1a5c46fffb060b5678009a756280923b370375b828b61d2401ecf75d77d0598",),
        "observed_sha256": "sha256:c1a5c46fffb060b5678009a756280923b370375b828b61d2401ecf75d77d0598",
        "evidence": "Current c1a5c46… is the exact isolated source-loading bootstrap bound by the accepted measurement route.",
        "not_established": (
            "Host honesty, confinement, physical accuracy, whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/domains/contracts/sim_fresh_worker.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:937a96ee1afe6c86616364d561426e0cb3a832f96ea789c489ffae1c5124a015",),
        "observed_sha256": "sha256:937a96ee1afe6c86616364d561426e0cb3a832f96ea789c489ffae1c5124a015",
        "evidence": (
            "Current 937a96e… directly reads thread CPU time, monotonic intervals and "
            "traced peak allocation for each selected step and binds each row to the "
            "fresh frame; it does not relabel those software counters as physical truth."
        ),
        "not_established": (
            "Transition-exclusive cost, calibration, physical accuracy, total resource use, or host attestation.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/resource_measurement_worker.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:3d5f78c9bdace5d4b4e58f5d7255a78582ee12f4e23ed486a5d4c2707b4ce030",),
        "observed_sha256": "sha256:3d5f78c9bdace5d4b4e58f5d7255a78582ee12f4e23ed486a5d4c2707b4ce030",
        "evidence": (
            "Current 3d5f78c… independently emits the same closed software-observation "
            "scope that the checker recomputes, performs two fresh acquisitions, and "
            "supplies adversarial instrument and source-binding controls."
        ),
        "not_established": (
            "Equivalence to unrecovered prior bytes, host honesty, physical truth, whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/resource_measurement_execution.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:ffafaf207fbcb5b7f3b3b3ae7f193588b868528230296455be897036a28881ab",),
        "observed_sha256": "sha256:ffafaf207fbcb5b7f3b3b3ae7f193588b868528230296455be897036a28881ab",
        "evidence": (
            "Current ffafaf2… independently recomputes a closed scope that identifies "
            "raw software-counter observations rather than estimates, refuses any "
            "scope substitution, and keeps physical and external truth NOT_ESTABLISHED. "
            "Current behavior is accepted without claiming equivalence to unrecovered prior bytes."
        ),
        "not_established": (
            "Transition-exclusive cost, statistical uncertainty, physical calibration or accuracy, total resource use, host attestation, or external phenomenon truth.",
            "The TIME-open SIM-2.4 package/source-native route identity seam.",
            "Whole-package conformance, release, and deployment.",
        ),
    },
    "src/verifier/runtime/worker_protocol_worker.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:48a143de2b0839d58f6a0c6841dd09af389f7bbbcc521d45f2708398d481e659",),
        "observed_sha256": "sha256:48a143de2b0839d58f6a0c6841dd09af389f7bbbcc521d45f2708398d481e659",
        "evidence": (
            "Current 48a143d… emits the transcript, participant identity, and "
            "fault cases adjudicated by the current checker. The exact protocol "
            "and dependency-relation suite passes 70 tests."
        ),
        "not_established": (
            "Network transport, distributed ordering, liveness, external participant identity, and production protocol compatibility.",
            "Whole-package conformance and package-polish closure.",
        ),
    },
    "src/verifier/runtime/worker_protocol_execution.py": {
        "decision": "ACCEPTED",
        "pinned_sha256": ("sha256:5802e7edfc2a1951e8331eb31b230345ea3858907fdd23abaa6da8b79c343c92",),
        "observed_sha256": "sha256:5802e7edfc2a1951e8331eb31b230345ea3858907fdd23abaa6da8b79c343c92",
        "evidence": (
            "Current 5802e7e… source-binds and rechecks the fixed worker "
            "protocol, including replay, transition, participant, fault, and "
            "dependency adversaries. The exact protocol and dependency-relation "
            "suite passes 70 tests."
        ),
        "not_established": (
            "Network transport, distributed ordering, liveness, external participant identity, and production protocol compatibility.",
            "Whole-package conformance and package-polish closure.",
        ),
    },
    "src/verifier/runtime/emulator_control_worker.py": {
        "decision": "UNKNOWN",
        "pinned_sha256": ("sha256:a8a41560791c94fabc158bdef2beab280dbf269f057db66c4251f0fa9a00d87b",),
        "observed_sha256": "sha256:303f98c01327db0e8fedd8c074f3dcef7dea94c83ea586ac0e90447dcc65ec5c",
        "evidence": "Recovered prior a8a41560… diffed: 271 changed lines; consumer emulator_control_execution.py unrecovered.",
        "not_established": ("Consumer emulator_control_execution.py prior bytes are unrecovered.",),
    },
    "src/verifier/runtime/emulator_control_execution.py": {
        "decision": "UNKNOWN",
        "pinned_sha256": ("sha256:dabc80aefa46db6b4ec9cadaffc0eb0546360d6b2f33d87fd063b98396013935",),
        "observed_sha256": "sha256:d6a3e6f41cdd17f5103a6a2765b28133c8b1e6159724780ce3e025a529034cab",
        "evidence": "Pinned dabc80… bytes are not recovered from any repository, worktree, or stash.",
        "not_established": ("Diff-based review is impossible for this file.",),
    },
}

_SEMANTIC_MAPPING_BLOCKERS: dict[str, str] = {}


# The legacy 26-kind route denominator is intentionally literal.  A changed
# route number is a contract change that must update this table and its tests;
# deriving it from the catalog under test would make omission self-validating.
_CORE_ROUTES: dict[str, dict[int, tuple[str, ...]]] = {
    "ACTOR": {1: ("ACTOR-1.1",), 2: ("ACTOR-2.7",), 3: ("ACTOR-3.3",)},
    "AGENT": {1: ("AGENT-1.1", "AGENT-1.8"), 2: ("AGENT-2.1", "AGENT-2.3"), 3: ("AGENT-3.1",)},
    "ARCH": {1: ("ARCH-1.1",), 2: ("ARCH-2.1",), 3: ("ARCH-3.1",)},
    "BENCH": {1: ("BENCH-1.1", "BENCH-1.2", "BENCH-1.4"), 2: ("BENCH-2.1",), 3: ("BENCH-3.6",)},
    "BOT": {1: ("BOT-1.1", "BOT-1.6", "BOT-1.7"), 2: ("BOT-2.1", "BOT-2.2", "BOT-2.3", "BOT-2.6"), 3: ("BOT-3.1", "BOT-3.5")},
    "COLLECTIVE": {1: ("COLLECTIVE-1.1",), 2: ("COLLECTIVE-2.1",), 3: ("COLLECTIVE-3.1",)},
    "DATA": {1: ("DATA-1.1", "DATA-1.2", "DATA-1.4"), 2: ("DATA-2.1",), 3: ("DATA-3.4",)},
    "ENV": {1: ("ENV-1.1", "ENV-1.2", "ENV-1.3", "ENV-1.4", "ENV-1.5"), 2: ("ENV-2.3",), 3: ("ENV-3.3",)},
    "EVENT": {1: ("EVENT-1.1",), 2: ("EVENT-2.1",), 3: ("EVENT-3.1",)},
    "GRAPH": {1: ("GRAPH-1.1",), 2: ("GRAPH-2.1",), 3: ("GRAPH-3.1",)},
    "HARDWARE": {1: ("HARDWARE-1.1", "HARDWARE-1.2", "HARDWARE-1.3"), 2: ("HARDWARE-2.1", "HARDWARE-2.2"), 3: ("HARDWARE-3.1",)},
    "HARNESS": {1: ("HARNESS-1.1", "HARNESS-1.6"), 2: ("HARNESS-2.1", "HARNESS-2.2", "HARNESS-2.3"), 3: ("HARNESS-3.1",)},
    "HUMAN": {1: ("HUMAN-1.1",), 2: ("HUMAN-2.5",), 3: ("HUMAN-3.6",)},
    "HYPER": {1: ("HYPER-1.1",), 2: ("HYPER-2.3",), 3: ("HYPER-3.1",)},
    "IDENTITY": {1: ("IDENTITY-1.1",), 2: ("IDENTITY-2.1",), 3: ("IDENTITY-3.1",)},
    "MODEL": {1: ("MODEL-1.1", "MODEL-1.2", "MODEL-1.5"), 2: ("MODEL-2.1",), 3: ("MODEL-3.1", "MODEL-3.2", "MODEL-3.3", "MODEL-3.4", "MODEL-3.5", "MODEL-3.7")},
    "OBJECT": {1: ("OBJECT-1.1", "OBJECT-1.2"), 2: ("OBJECT-2.1",), 3: ("OBJECT-3.1",)},
    "OWNER": {1: ("OWNER-1.1",), 2: ("OWNER-2.6",), 3: ("OWNER-3.1",)},
    "RECEIPT": {1: ("RECEIPT-1.1",), 2: ("RECEIPT-2.1",), 3: ("RECEIPT-3.1",)},
    "ROLE": {1: ("ROLE-1.1",), 2: ("ROLE-2.1",), 3: ("ROLE-3.1",)},
    "SIM": {1: ("SIM-1.1",), 2: ("SIM-2.1", "SIM-2.2", "SIM-2.3", "SIM-2.4", "SIM-2.5"), 3: ("SIM-3.4",)},
    "SPACE": {1: ("SPACE-1.1",), 2: ("SPACE-2.1",), 3: ("SPACE-3.1",)},
    "TIME": {1: ("TIME-1.1",), 2: ("TIME-2.1",), 3: ("TIME-3.1",)},
    "TOKEN": {1: ("TOKEN-1.1",), 2: ("TOKEN-2.1",), 3: ("TOKEN-3.1",)},
    "TRAIN": {1: ("TRAIN-1.1", "TRAIN-1.2", "TRAIN-1.3", "TRAIN-1.5"), 2: ("TRAIN-2.1", "TRAIN-2.3"), 3: ("TRAIN-3.2",)},
    "VERIFIER": {1: ("VERIFIER-1.1",), 2: ("VERIFIER-2.1",), 3: ("VERIFIER-3.1",)},
}


# Added kinds map each Tier-0 declaration obligation to the behavioral family
# that must be assessed at the corresponding Polish tier.  Multiple routes are
# allowed where independent implementations exercise distinct variants.
_ADDED_ROUTES: dict[str, dict[int, tuple[str, ...]]] = {
    "LEDGER": {1: ("LEDGER-1.1", "LEDGER-1.2"), 2: ("LEDGER-2.1", "LEDGER-2.2"), 3: ("LEDGER-3.1", "LEDGER-3.2")},
    "TRANSACTION": {1: ("TRANSACTION-1.1", "TRANSACTION-1.2", "TRANSACTION-1.3", "TRANSACTION-1.4"), 2: ("TRANSACTION-2.1", "TRANSACTION-2.2", "TRANSACTION-2.3", "TRANSACTION-2.4"), 3: ("TRANSACTION-3.1", "TRANSACTION-3.2", "TRANSACTION-3.3", "TRANSACTION-3.4")},
    "ASSET": {1: ("ASSET-1.1",), 2: ("ASSET-2.1",), 3: ("ASSET-3.1",)},
    "MARKET": {1: ("MARKET-1.1",), 2: ("MARKET-2.1",), 3: ("MARKET-3.1",)},
    "MEASUREMENT": {1: ("MEASUREMENT-1.1",), 2: ("MEASUREMENT-2.1",), 3: ("MEASUREMENT-3.1",)},
    "SENSOR": {1: ("SENSOR-1.1",), 2: ("SENSOR-2.1",), 3: ("SENSOR-3.1",)},
    "CONTROLLER": {1: ("CONTROLLER-1.1",), 2: ("CONTROLLER-2.1",), 3: ("CONTROLLER-3.1",)},
    "ACTUATOR": {1: ("ACTUATOR-1.1",), 2: ("ACTUATOR-2.1",), 3: ("ACTUATOR-3.1",)},
    "PROTOCOL": {1: ("PROTOCOL-1.1", "PROTOCOL-1.2"), 2: ("PROTOCOL-2.1", "PROTOCOL-2.2"), 3: ("PROTOCOL-3.1", "PROTOCOL-3.2")},
    "POLICY": {
        1: ("POLICY-1.1", "POLICY-1.2", "POLICY-1.3"),
        2: ("POLICY-2.1", "POLICY-2.2", "POLICY-2.3"),
        3: ("POLICY-3.1", "POLICY-3.2", "POLICY-3.3"),
    },
    "ROBOT": {1: ("ROBOT-1.1", "ROBOT-1.2"), 2: ("ROBOT-2.1", "ROBOT-2.2"), 3: ("ROBOT-3.1", "ROBOT-3.2")},
    "FINBOT": {1: ("FINBOT-1.1", "FINBOT-1.2"), 2: ("FINBOT-2.1", "FINBOT-2.2"), 3: ("FINBOT-3.1", "FINBOT-3.2")},
}


# Field-level coverage is deliberately independent of the tier-matched route
# table above.  A route can exercise part of an obligation while leaving one
# declaration field presence-only, boundary-excluded, partial, or absent.  The
# compact audit below records that distinction without pretending the known
# gaps are mechanized.  `_DECLARATION_FIELD_BINDINGS` expands it to one exact
# row per installed declaration field and is checked against the namespace on
# every matrix build.
_DECLARATION_FIELD_STATUS_GROUPS: dict[str, dict[str, tuple[str, ...]]] = {
    "LEDGER-0.1-authoritative-history": {"M": ("history", "state", "ordering"), "B": ("authority",)},
    "LEDGER-0.2-accounting-invariants": {"M": ("units", "balance_rules", "rounding", "sources_and_sinks")},
    "LEDGER-0.3-correction-and-recovery": {"M": ("corrections", "replay"), "P": ("reconciliation", "recovery")},
    "TRANSACTION-0.1-effects-and-authority": {"M": ("effects", "preconditions", "resources"), "P": ("authorization",)},
    "TRANSACTION-0.2-commit-and-failure": {"M": ("commit", "abort", "finality", "partial_failure")},
    "TRANSACTION-0.3-retry-and-replay": {"M": ("duplicate_detection", "idempotency", "replay", "retry_limits")},
    "ASSET-0.1-identity-and-quantity": {
        "M": ("units", "precision"),
        "P": ("identity", "rights"),
    },
    "ASSET-0.2-issuance-and-redemption": {"P": ("supply_changes",), "B": ("issuance_authority", "redemption", "backing_claims")},
    "ASSET-0.3-custody-and-encumbrance": {"M": ("encumbrances", "reconciliation"), "P": ("control",), "B": ("custody",)},
    "MARKET-0.1-orders-and-access": {"M": ("participant_access", "order_states", "validation", "cancellation")},
    "MARKET-0.2-matching-and-allocation": {"M": ("matching", "allocation"), "P": ("price_formation", "manipulation_controls")},
    "MARKET-0.3-settlement-and-disruption": {"M": ("finality", "disruption"), "P": ("settlement_dependencies", "participant_failure")},
    "MEASUREMENT-0.1-phenomenon-and-method": {"M": ("phenomenon", "method", "source", "observation_vs_estimate")},
    "MEASUREMENT-0.2-units-time-and-uncertainty": {"M": ("units", "reference_frame"), "B": ("uncertainty",), "X": ("observation_time", "arrival_time")},
    "MEASUREMENT-0.3-validity-and-missingness": {"M": ("validity", "missingness"), "X": ("freshness", "provenance")},
    "SENSOR-0.1-acquisition-and-observations": {"M": ("acquisition", "phenomena", "measurements"), "B": ("deployment",)},
    "SENSOR-0.2-calibration-and-envelope": {"M": ("calibration_evidence", "operating_range", "drift"), "P": ("calibration_applicability",)},
    "SENSOR-0.3-sampling-and-faults": {"M": ("sampling", "fault_detection"), "X": ("latency", "recovery")},
    "CONTROLLER-0.1-feedback-and-authority": {"M": ("feedback", "commands"), "X": ("objectives", "authority")},
    "CONTROLLER-0.2-timing-and-stability": {"M": ("operating_envelope", "saturation"), "B": ("stability_assumptions",), "X": ("timing",)},
    "CONTROLLER-0.3-intervention-and-failure": {"M": ("intervention", "failure_behavior"), "X": ("feedback_loss", "arbitration")},
    "ACTUATOR-0.1-command-to-effect": {"M": ("commands", "targets"), "P": ("effect_domains",), "X": ("authority",)},
    "ACTUATOR-0.2-response-and-limits": {"M": ("limits", "saturation"), "P": ("units_and_frames",), "X": ("response",)},
    "ACTUATOR-0.3-feedback-and-interlocks": {"M": ("interlocks",), "X": ("effect_feedback", "failure_states", "recovery")},
    "PROTOCOL-0.1-participants-and-states": {"M": ("participants", "roles"), "P": ("states",), "X": ("transitions",)},
    "PROTOCOL-0.2-ordering-and-replay": {"M": ("replay",), "B": ("message_authority",), "X": ("ordering", "compatibility")},
    "PROTOCOL-0.3-failures-and-progress": {"M": ("failure_assumptions", "safety"), "B": ("liveness",), "X": ("recovery",)},
    # POLICY-1.3, 2.3 and 3.3 are retained fixture observations judged by the installed
    # oracle. They establish bounded field behavior only, so no POLICY field is MECHANIZED.
    "POLICY-0.1-rules-and-precedence": {"P": ("scope", "decision_inputs", "defaults", "precedence")},
    "POLICY-0.2-authority-and-exceptions": {"P": ("exceptions", "revisions"), "B": ("authority", "activation")},
    "POLICY-0.3-enforcement-and-decisions": {"P": ("decision_evidence", "bypass_handling", "unavailable_behavior"), "B": ("enforcement_points",)},
    "ROBOT-0.1-agent-to-actuator-binding": {"M": ("agent", "harness", "controllers", "actuators")},
    "ROBOT-0.2-physical-reach-and-observation": {"M": ("domain_crossings",), "P": ("physical_reach", "observations"), "B": ("confinement_evidence",)},
    "ROBOT-0.3-consequences-and-intervention": {"M": ("hazards", "intervention", "safe_state_or_continuity"), "R": ("operating_limits",)},
    "FINBOT-0.1-agent-and-financial-authority": {"M": ("agent", "harness", "decision_scope"), "R": ("financial_authority",)},
    "FINBOT-0.2-financial-exposure-and-dependencies": {"M": ("financial_dependencies", "exposure_limits"), "P": ("assets_and_parties", "real_world_paths")},
    "FINBOT-0.3-decisions-effects-and-recovery": {"M": ("intervention",), "P": ("decision_effect_evidence", "limit_enforcement", "reconciliation_and_recovery")},
}

_FIELD_STATUS_NAMES = {
    "M": "MECHANIZED",
    "P": "PARTIAL",
    "R": "PRESENCE_ONLY",
    "B": "BOUNDARY_EXCLUDED",
    "X": "MISSING",
}
_FIELD_STATUS_REASONS = {
    "M": "A pinned executable route adjudicates this field within its stated boundary.",
    "P": "The installed route adjudicates only part of this field's declared meaning.",
    "R": "The installed route checks presence but not the declared field's behavior or authority.",
    "B": "The installed route explicitly leaves this field outside its established boundary.",
    "X": "No installed executable route adjudicates this declaration field.",
}

# These exact ceilings keep retained text and software replay from being
# promoted into external-world proof. A field can be upgraded only by changing
# this reviewed boundary together with an actually stronger mechanism; merely
# repinning new bytes is rejected as an overclaim.
_BOUNDARY_STATUS_PINS = {
    ("LEDGER-0.1-authoritative-history", "authority"): "BOUNDARY_EXCLUDED",
    ("LEDGER-0.3-correction-and-recovery", "reconciliation"): "PARTIAL",
    ("LEDGER-0.3-correction-and-recovery", "recovery"): "PARTIAL",
    ("MARKET-0.2-matching-and-allocation", "price_formation"): "PARTIAL",
    ("MARKET-0.2-matching-and-allocation", "manipulation_controls"): "PARTIAL",
    ("MARKET-0.3-settlement-and-disruption", "settlement_dependencies"): "PARTIAL",
    ("MARKET-0.3-settlement-and-disruption", "participant_failure"): "PARTIAL",
    ("ROBOT-0.2-physical-reach-and-observation", "physical_reach"): "PARTIAL",
    ("ROBOT-0.2-physical-reach-and-observation", "observations"): "PARTIAL",
    ("ROBOT-0.2-physical-reach-and-observation", "confinement_evidence"): "BOUNDARY_EXCLUDED",
    ("ROBOT-0.3-consequences-and-intervention", "operating_limits"): "PRESENCE_ONLY",
    ("FINBOT-0.1-agent-and-financial-authority", "financial_authority"): "PRESENCE_ONLY",
    ("FINBOT-0.2-financial-exposure-and-dependencies", "assets_and_parties"): "PARTIAL",
    ("FINBOT-0.2-financial-exposure-and-dependencies", "real_world_paths"): "PARTIAL",
    ("FINBOT-0.3-decisions-effects-and-recovery", "decision_effect_evidence"): "PARTIAL",
    ("FINBOT-0.3-decisions-effects-and-recovery", "limit_enforcement"): "PARTIAL",
    ("FINBOT-0.3-decisions-effects-and-recovery", "reconciliation_and_recovery"): "PARTIAL",
    # POLICY ceilings are exact: a route pinned to fixtures may be PARTIAL at most, and
    # the self-declared boundaries of authority, activation and enforcement stay excluded.
    ("POLICY-0.1-rules-and-precedence", "scope"): "PARTIAL",
    ("POLICY-0.1-rules-and-precedence", "decision_inputs"): "PARTIAL",
    ("POLICY-0.1-rules-and-precedence", "defaults"): "PARTIAL",
    ("POLICY-0.1-rules-and-precedence", "precedence"): "PARTIAL",
    ("POLICY-0.2-authority-and-exceptions", "exceptions"): "PARTIAL",
    ("POLICY-0.2-authority-and-exceptions", "revisions"): "PARTIAL",
    ("POLICY-0.2-authority-and-exceptions", "authority"): "BOUNDARY_EXCLUDED",
    ("POLICY-0.2-authority-and-exceptions", "activation"): "BOUNDARY_EXCLUDED",
    ("POLICY-0.3-enforcement-and-decisions", "decision_evidence"): "PARTIAL",
    ("POLICY-0.3-enforcement-and-decisions", "enforcement_points"): "BOUNDARY_EXCLUDED",
    ("POLICY-0.3-enforcement-and-decisions", "bypass_handling"): "PARTIAL",
    ("POLICY-0.3-enforcement-and-decisions", "unavailable_behavior"): "PARTIAL",
}

_DECLARATION_FIELD_ROUTE_DIGESTS = {
    "LEDGER-0.1-authoritative-history": "sha256:d3ab0f9742034f73c6695772c86ef47475f67ad8aa5319058e13fbb41a696c98",
    "LEDGER-0.2-accounting-invariants": "sha256:d7c177e256ec37b0bd9a980900805df9bc551f8e25fc8e35ebf4aec4f4e951c7",
    "LEDGER-0.3-correction-and-recovery": "sha256:97490ea32e21f9959260f62ee1325358546f135a11a4bb6f7e4d42206b2a0fe9",
    "TRANSACTION-0.1-effects-and-authority": "sha256:7663fddf69499b452f42acdb01fd517cd1e5cd387b71fcddeacf3cb16883ed07",
    "TRANSACTION-0.2-commit-and-failure": "sha256:0f574b8aca18e8edc7af22cf28d7645639cf58c3fcdfa5a0ca3c69ab1e41107e",
    "TRANSACTION-0.3-retry-and-replay": "sha256:06cfa82b702c34f2325dd1b54a891e51571ccc76b2a7a4f00a6e7b8ea6fd5f43",
    "ASSET-0.1-identity-and-quantity": "sha256:4f2aa70777874021022937ac2351574929118a1bbe7f856845bd3d01d95f367e",
    "ASSET-0.2-issuance-and-redemption": "sha256:54e3fdf45cb90a0540165938f1f80462d8368e5d87448808954c4934712fe1ad",
    "ASSET-0.3-custody-and-encumbrance": "sha256:ed116a54d365c2a75615f0ca67125860177434bc28c5f228f21b7fcd3dc270d3",
    "MARKET-0.1-orders-and-access": "sha256:c6274380384ad7342c234d93552a2337e1055a20e55ed1dabae63d3b6a77d742",
    "MARKET-0.2-matching-and-allocation": "sha256:4f3982033461c3c91ff91dfcd0d40d51ec067a4e11bbe7dd53bf2923bf6d93d4",
    "MARKET-0.3-settlement-and-disruption": "sha256:c9a164f5a48e1634da3df1805db0160ee1e00f7412664d59de03c668cd53efb9",
    "MEASUREMENT-0.1-phenomenon-and-method": "sha256:49c4b1f7f7850baa3a85bde2b1c19131b7053128d96c627c8c2d4ce5d0bc0ae5",
    "MEASUREMENT-0.2-units-time-and-uncertainty": "sha256:a266e5fd51b5dec1e7c9bff0cdf83642868efbe364de001866c5b52eedf66e2b",
    "MEASUREMENT-0.3-validity-and-missingness": "sha256:337e95f9317c9d40b94ba8e38c1e204311396cbd2f384d5bf982b7e0a5b03aa9",
    "SENSOR-0.1-acquisition-and-observations": "sha256:d15a139c2bf13a035f8afdb291ea688ccbdc90c98e66e63d1861d37b2013a8cf",
    "SENSOR-0.2-calibration-and-envelope": "sha256:80dfe96cf4e82d2b66b196c7b5b19666d3cd989cd29abccd65b80efed8c7ca01",
    "SENSOR-0.3-sampling-and-faults": "sha256:fbc9323f0f78f26cd983fbb9bc7a990172284a4eee6beee04e1571bb031181fc",
    "CONTROLLER-0.1-feedback-and-authority": "sha256:551c365644ffcdb03ab9e79a227cc8fb48a465da1b638d963174aca8b9d8f78a",
    "CONTROLLER-0.2-timing-and-stability": "sha256:ef338ca7aa3a6b6c1c72421b3e88522a59a9f8f6923aff7b2d37b8415d5a644a",
    "CONTROLLER-0.3-intervention-and-failure": "sha256:226ba4a8cb1d57f7c12d829d8c467e9a0dcd3275817fbe3159c9df586112cb7d",
    "ACTUATOR-0.1-command-to-effect": "sha256:9731347cbff02c8c04a77d6aa713d3085e961021884f8ca7688172955717a713",
    "ACTUATOR-0.2-response-and-limits": "sha256:84added2a84707102c60f3db0f4fab19e5b00858b41c17e8e61eb820a7002f90",
    "ACTUATOR-0.3-feedback-and-interlocks": "sha256:efc3bcc714bec7b9078c8fb5d84fde57c8cfaaf5fdbc1f0cc6df39552acf3448",
    "PROTOCOL-0.1-participants-and-states": "sha256:e8cc793c0d68d3de701c7ef2e4d6b6d1d0a145e12e78b811946258d00bae77b7",
    "PROTOCOL-0.2-ordering-and-replay": "sha256:bc5dc7e4dd7e8b5dc09400d80ab36d8d3f339ea485587ecba9b68e67bb8bd147",
    "PROTOCOL-0.3-failures-and-progress": "sha256:d909792a968da36618ec60b841f9f79dab5b3e837b804859e191c2db82d88a4b",
    "POLICY-0.1-rules-and-precedence": "sha256:2ed2ddc5f5aaddc0cea540376ea042f21aba4070a09f9b7e3806360430f5191e",
    "POLICY-0.2-authority-and-exceptions": "sha256:783641fde2eb4db3c82c95fa01fad87bd793be3a927963a9e67a7e2e7f4bc154",
    "POLICY-0.3-enforcement-and-decisions": "sha256:2ca4b8fd2a9402ea19e880cdb6df7a34114c8f62f9bdf25256632bc6765cf6bb",
    "ROBOT-0.1-agent-to-actuator-binding": "sha256:9ad7d5cb461f0d9159f40ce6244b8fa21a5d26d549addff31edd349bb872c38d",
    "ROBOT-0.2-physical-reach-and-observation": "sha256:ea03d006893a23aa819b59054a95be96834def3f985e062a6b4fb0cfaced2373",
    "ROBOT-0.3-consequences-and-intervention": "sha256:3e6bdafb992dfa4996aeff3191f8156b9244789cb76f071dac04b4c972c400dc",
    "FINBOT-0.1-agent-and-financial-authority": "sha256:56bccbbadeba72a5ea80e5e248a92c2008b268ef33fbd685662387e817cb2807",
    "FINBOT-0.2-financial-exposure-and-dependencies": "sha256:e3b097968799174f6b8c73fbb2f015be64aa3077a97f1b17d65d96389bfdc5fa",
    "FINBOT-0.3-decisions-effects-and-recovery": "sha256:15d52c6f67c685609c4a933411fe3fa188e79d7a9c3c66e4c0551cc470b42c74",
}

_DECLARATION_FIELD_SOURCE_DIGESTS = {
    "src/verifier/domains/contracts/agency_surface.py": "sha256:d7030f608c82578ff62e7fcd74d22ac2457a2656634f40a0dfca769fb2eed297",
    "src/verifier/domains/contracts/finbot_checks.py": "sha256:c1f75930f077067855ff90cfd9f5ce5c1d1fe287d0427bf2c1c826f4266bf94a",
    "src/verifier/domains/contracts/market_checks.py": "sha256:2a7716c17e6ba95be2c0c812d4862037f515baf1b6407560b43cb28bb07ba159",
    "src/verifier/domains/contracts/robot_checks.py": "sha256:403d84725192917af694d3c84d4a475a22a1fc35a8a15c1b91741bf5f916df00",
    "src/verifier/runtime/emulator_control_execution.py": "sha256:dabc80aefa46db6b4ec9cadaffc0eb0546360d6b2f33d87fd063b98396013935",
    "src/verifier/runtime/local_ledger_control_checks.py": "sha256:d78330f346cb80ca09dadc60806cd41e3c3f943968bc0eff18c40822d0d5d7db",
    "src/verifier/runtime/local_ledger_controls.py": "sha256:281ad024e64b074f5a88d455d7dc0362228d23b889a6a09c0e80c002d270bd35",
    "src/verifier/runtime/local_ledger_execution.py": "sha256:e539210fb59ac7d15532b32d3e43d013b639aafd790dfdd4ad5cd33d3cb67f1f",
    "src/verifier/runtime/local_ledger_worker.py": "sha256:acc77fa227ba4f4f5c0a50bbb3cde936907f53a3890356aece472b8e87802045",
    "src/verifier/runtime/manifest_write_execution.py": "sha256:360bb109e60c349a9e3bc4064c08b6a1157d0e3bb25474b3c5fd86cf6df4e0c7",
    "src/verifier/runtime/manifest_write_worker.py": "sha256:f35b0af2432af8ce488b9e21f294269c1e1013765ef2be0f292f152ca48e69ff",
    "src/verifier/runtime/namespace_admission.py": "sha256:9de470e6d3005a189a277757620d816603909f6654c0d15aa0073ec7d8aefa8e",
    "src/verifier/runtime/namespace_cli.py": "sha256:70319f32d64fbe25a2a0d49bb46a285d476cd339af632394d2e35325fe0cb7db",
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py": "sha256:c1a5c46fffb060b5678009a756280923b370375b828b61d2401ecf75d77d0598",
    "src/verifier/domains/contracts/sim_fresh_worker.py": "sha256:937a96ee1afe6c86616364d561426e0cb3a832f96ea789c489ffae1c5124a015",
    "src/verifier/domains/contracts/sim_resource_fresh.py": "sha256:36a8064c33cc390386aa7093a06a25107458314a58672b44348a2ffb2cbe1e42",
    "src/verifier/runtime/provenance_policy_execution.py": "sha256:f16f776af628dae845d532ac7ed0ff116895f00e823aa8a95c625be8514eee92",
    "src/verifier/runtime/package_execution.py": "sha256:b140adff50ea2ed06c51098f01e24a541db52400f3a468b7cc74fb724bb0be72",
    "src/verifier/runtime/polish_invocation_ledger.py": "sha256:ad8d62ff47d8d4d92277fe2fba353bbbf82f088848dda07bc2202b5fdffadd3d",
    "src/verifier/runtime/resource_measurement_execution.py": "sha256:ffafaf207fbcb5b7f3b3b3ae7f193588b868528230296455be897036a28881ab",
    "src/verifier/runtime/resource_measurement_worker.py": "sha256:3d5f78c9bdace5d4b4e58f5d7255a78582ee12f4e23ed486a5d4c2707b4ce030",
    "src/verifier/runtime/token_asset_execution.py": "sha256:c4058569d8d7e138ae75592a794bea2c39516b2fa191f38c547113c7c0ac55c9",
    "src/verifier/runtime/worker_protocol_execution.py": "sha256:5802e7edfc2a1951e8331eb31b230345ea3858907fdd23abaa6da8b79c343c92",
    # The POLICY-1.3/2.3/3.3 checker lives in this module, so its bytes are pinned as a checker source.
    "src/verifier/runtime/added_kind_behavioral_routes.py": "sha256:19f121645632ef499d6dc60ff5fc8b7ab7c0ed8a3fc34cdf9d023cbf44687775",
}

# Field-level LEDGER adjudication spans the route predicate, independent state
# predicates, fixed experiment producer, worker, execution envelope, and the
# selected ledger itself.  A change to any one of those bytes reopens the field
# decision; pinning only the public evaluator would leave transitive drift
# invisible to this central audit.
_DECLARATION_FIELD_ADDITIONAL_SOURCE_PATHS = {
    obligation_id: (
        "src/verifier/runtime/local_ledger_control_checks.py",
        "src/verifier/runtime/local_ledger_controls.py",
        "src/verifier/runtime/local_ledger_worker.py",
        "src/verifier/runtime/package_execution.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    )
    for obligation_id in (
        "LEDGER-0.1-authoritative-history",
        "LEDGER-0.2-accounting-invariants",
        "LEDGER-0.3-correction-and-recovery",
    )
}
_DECLARATION_FIELD_ADDITIONAL_SOURCE_PATHS[
    "TRANSACTION-0.3-retry-and-replay"
] = (
    "src/verifier/runtime/local_ledger_controls.py",
    "src/verifier/runtime/local_ledger_worker.py",
    "src/verifier/runtime/manifest_write_worker.py",
    "src/verifier/runtime/namespace_admission.py",
    "src/verifier/runtime/namespace_cli.py",
    "src/verifier/runtime/package_execution.py",
    "src/verifier/runtime/polish_invocation_ledger.py",
)
_DECLARATION_FIELD_ADDITIONAL_SOURCE_PATHS[
    "MEASUREMENT-0.1-phenomenon-and-method"
] = (
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
    "src/verifier/domains/contracts/sim_fresh_worker.py",
    "src/verifier/domains/contracts/sim_resource_fresh.py",
    "src/verifier/runtime/package_execution.py",
    "src/verifier/runtime/resource_measurement_worker.py",
)

_LEDGER_FIELD_STATUS_REASONS = {
    ("LEDGER-0.1-authoritative-history", "history"): (
        "Fresh isolated SQLite executions retain exact selected local proposal rows; "
        "production-history completeness and power-loss durability remain outside the claim."
    ),
    ("LEDGER-0.1-authoritative-history", "state"): (
        "Independent reads compare exact local metadata, rows, and sequence state before and after each tested transition; external ledger state is not inferred."
    ),
    ("LEDGER-0.1-authoritative-history", "ordering"): (
        "The tested local journal has gap-free persisted sequence order across commit, replay, rollback, and lost acknowledgement; distributed ordering and finality remain unestablished."
    ),
    ("LEDGER-0.1-authoritative-history", "authority"): (
        "The local route retains only a syntactically valid authority-status digest and explicitly reports public consumption authentication NOT_ESTABLISHED; it does not authenticate independent authority."
    ),
    ("LEDGER-0.2-accounting-invariants", "units"): (
        "The executed unit is one exact canonical proposal and its persisted integer sequence; it is not money, an asset unit, or a claim about backing."
    ),
    ("LEDGER-0.2-accounting-invariants", "balance_rules"): (
        "Every tested operation compares complete before and after local row state and its exact persisted delta; this does not establish real balances or settlement."
    ),
    ("LEDGER-0.2-accounting-invariants", "rounding"): (
        "The tested sequence and retained-byte deltas use exact integers without rounding; no external financial rounding rule is established."
    ),
    ("LEDGER-0.2-accounting-invariants", "sources_and_sinks"): (
        "The route measures which tested local operations add, retain, or do not add rows and bytes; it does not establish authorized issuance, destruction, or real-world flows."
    ),
    ("LEDGER-0.3-correction-and-recovery", "corrections"): (
        "The tested local commit, replay, and recovery paths refuse a changed proposal for a consumed invocation without rewriting the retained row."
    ),
    ("LEDGER-0.3-correction-and-recovery", "replay"): (
        "Fresh local execution checks duplicate commit refusal, exact receipt replay, and rejection of contradictory retained fields."
    ),
    ("LEDGER-0.3-correction-and-recovery", "reconciliation"): (
        "Read-only local inspection distinguishes selected precommit absence from a retained postcommit row, but no independent or external reconciliation and no settlement are established."
    ),
    ("LEDGER-0.3-correction-and-recovery", "recovery"): (
        "The route exercises read-only recovery after injected process-level commit faults and cancellation; power-loss durability, storage survival, and operational recovery remain unestablished."
    ),
}


_TRANSACTION_FIELD_STATUS_REASONS = {
    ("TRANSACTION-0.3-retry-and-replay", "retry_limits"): (
        "The two local Tier-3 routes refute any selected commit, recovery, or recheck "
        "operation that opens other than one backend connection or uses a busy bound "
        "outside zero-to-five seconds. The two manifest Tier-3 routes count the actual "
        "exclusive-create or replacement edge and require exactly one attempt per "
        "explicit operation. Retry, backoff, and exhaustion outside these fresh bounded "
        "processes remain unestablished."
    ),
}


_MEASUREMENT_FIELD_STATUS_REASONS = {
    ("MEASUREMENT-0.1-phenomenon-and-method", "observation_vs_estimate"): (
        "The worker independently emits and the checker recomputes a closed claim "
        "scope that labels the fresh raw thread-clock and traced-allocation values "
        "OBSERVATION_OF_SOFTWARE_COUNTERS rather than an estimate. Any substitution "
        "refutes every route before its claim-specific predicate; statistical "
        "uncertainty, transition-exclusive cost, physical accuracy and external "
        "phenomenon truth remain NOT_ESTABLISHED."
    ),
}


# These reasons are the honest scope of fixture-bound POLICY observations. None of
# them claims a deployed policy, a real authority, an enforcement point, or the truth
# of an underlying fact; the boundary pins above keep those exclusions reviewed.
_POLICY_FIELD_STATUS_REASONS = {
    ("POLICY-0.1-rules-and-precedence", "scope"): (
        "Fixture cases refuse an out-of-scope action before any rule is consulted; the declared scope of a deployed policy is not established."
    ),
    ("POLICY-0.1-rules-and-precedence", "decision_inputs"): (
        "Fixture requests bind their digests and the selected trust-root commitment; real request provenance and external inputs remain unsupplied."
    ),
    ("POLICY-0.1-rules-and-precedence", "defaults"): (
        "Fixture cases refuse a role without a matching rule and show that a POLICY label does not exempt a financial action; production defaults are not established."
    ),
    ("POLICY-0.1-rules-and-precedence", "precedence"): (
        "Fixture cases exercise deny-over-allow, equal-priority conflict, and union; precedence over every rule set a deployment could load is not established."
    ),
    ("POLICY-0.2-authority-and-exceptions", "exceptions"): (
        "Fixture waivers apply only inside their window, rule, action, target, and lifetime bounds; real exception authority and business justification are not established."
    ),
    ("POLICY-0.2-authority-and-exceptions", "revisions"): (
        "Fixture current-pointer, MAC, superseded-revision, and prior-grant cases are refused; wall-clock currentness and publication of a revision are not established."
    ),
    ("POLICY-0.2-authority-and-exceptions", "authority"): (
        "Grants are verified only against public fixture keys; signer identity, key custody, and legal adoption are boundary-excluded."
    ),
    ("POLICY-0.2-authority-and-exceptions", "activation"): (
        "The active-window refusal is exercised on fixtures; the wall-clock currentness of activation is boundary-excluded."
    ),
    ("POLICY-0.3-enforcement-and-decisions", "decision_evidence"): (
        "Fixture decision evidence is checked for policy, target, pass status, clauses, and certificate binding; the truth of the underlying facts is not established."
    ),
    ("POLICY-0.3-enforcement-and-decisions", "enforcement_points"): (
        "Declared enforcement points are checked as fixtures; no runtime wiring or external enforcement of those points is established."
    ),
    ("POLICY-0.3-enforcement-and-decisions", "bypass_handling"): (
        "Retained effect claims are reconciled to decisions for ghost, refused, and wrong-target effects; unsupplied effects remain UNKNOWN, not absent."
    ),
    ("POLICY-0.3-enforcement-and-decisions", "unavailable_behavior"): (
        "Injected stage faults fail closed with receipts and never allow; behavior under real loss of an external dependency is not established."
    ),
}


def _expand_declaration_field_bindings() -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for obligation_id, groups in _DECLARATION_FIELD_STATUS_GROUPS.items():
        kind = obligation_id.split("-", 1)[0]
        tier = int(obligation_id.split("-0.", 1)[1].split("-", 1)[0])
        routes = _ADDED_ROUTES[kind][tier]
        result[obligation_id] = {
            field: {
                "status": _FIELD_STATUS_NAMES[code],
                "reason": _LEDGER_FIELD_STATUS_REASONS.get(
                    (obligation_id, field),
                    _TRANSACTION_FIELD_STATUS_REASONS.get(
                        (obligation_id, field),
                        _MEASUREMENT_FIELD_STATUS_REASONS.get(
                            (obligation_id, field),
                            _POLICY_FIELD_STATUS_REASONS.get(
                                (obligation_id, field), _FIELD_STATUS_REASONS[code]
                            ),
                        ),
                    ),
                ),
                "route_coordinates": list(routes),
                "evidence_selector": "ROUTE_CHECKING_MECHANISM_SOURCE",
            }
            for code, fields in groups.items()
            for field in fields
        }
    return result


_DECLARATION_FIELD_BINDINGS = _expand_declaration_field_bindings()


_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    "ASSET": ("issuer authority", "signature validity", "real custody", "holding completeness", "redemption", "application enforcement", "supply conservation", "financial backing"),
    "LEDGER": (
        "real balances and monetary correctness",
        "distributed finality and real settlement",
        "authenticated independent operator authority",
        "power-loss durability",
        "independent or external reconciliation",
    ),
    "MEASUREMENT": ("physical calibration", "external phenomenon truth", "host attestation"),
    "SENSOR": ("physical calibration", "physical deployment identity", "continuous observation"),
    "CONTROLLER": ("physical-loop stability", "physical command authority", "safe-state proof"),
    "ACTUATOR": ("physical actuation", "physical feedback", "hardware interlock effectiveness"),
    "PROTOCOL": ("distributed agreement", "universal liveness", "remote participant authority"),
    # Each nonclaim is grounded in TRANSACTION-0.1 through 0.3: authorization of
    # the effect, commit/abort/finality across systems, and retry or replay.
    "TRANSACTION": (
        "external legal authorization of the coordinated effect",
        "real external atomicity or finality across participating systems",
        "compensation or rollback across external systems",
        "retry, backoff, or exhaustion guarantees beyond the bounded process",
        "real-money or settlement effects unless an accumulated financial role establishes them",
    ),
    "POLICY": ("legal authority", "complete downstream enforcement", "external policy adoption"),
    "MARKET": ("venue authority", "economic fairness", "absence of manipulation", "real settlement"),
    "ROBOT": ("physical actuation", "runtime correspondence", "external confinement"),
    "FINBOT": ("real-money action", "financial authority", "external confinement"),
}


def _tier_from_coordinate(coordinate: str) -> int:
    try:
        return int(coordinate.split("-", 1)[1].split(".", 1)[0])
    except (IndexError, ValueError):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_COORDINATE_INVALID") from None


def _profile(kind: str, routes: dict[int, tuple[str, ...]], *, added: bool) -> dict[str, Any]:
    registry = namespace_registry()
    contract = registry[kind]
    if set(routes) != {1, 2, 3} or any(
        not values or any(_tier_from_coordinate(value) != tier for value in values)
        for tier, values in routes.items()
    ):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_ROUTE_TIERS_INVALID")
    flat = [value for tier in (1, 2, 3) for value in routes[tier]]
    if len(flat) != len(set(flat)):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_ROUTE_DUPLICATED")
    obligations = [row.id for row in contract.obligations]
    if added and len(obligations) != 3:
        raise ValueError("PACKAGE_CONTRACT_PROFILE_ADMISSION_MAPPING_INVALID")
    family_mapping = (
        {
            obligations[tier - 1]: [f"{kind}-{tier}.90", *routes[tier]]
            for tier in (1, 2, 3)
        }
        if added else
        {f"{kind}-SOURCE-0.1-installed-review-binding": flat}
    )
    gate_mapping = {
        f"{kind}-{tier}.90-{_SOURCE_ROUTE_OBLIGATION_SUFFIXES[tier]}": [
            f"{kind}-{tier}.90"
        ]
        for tier in (1, 2, 3)
    }
    body = {
        "kind": kind,
        "profile_version": VERSION,
        "reason": contract.reason + " Package polish requires the executable current-source adaptation and every installed route in this bounded variant profile; a tier-matched source route may discharge source-representation conformance for its mapped family, while an explicit implementation refutation closes only the condition proven not to trigger.",
        "source_routes": {str(tier): f"{kind}-{tier}.90" for tier in (1, 2, 3)},
        "behavioral_routes": {str(tier): list(routes[tier]) for tier in (1, 2, 3)},
        # Gate identifiers and semantic-family identifiers are different
        # contracts. Keep both exact so a focused gate failure never reports a
        # tier-collapsed SOURCE-0.1 alias, while the family ledger still maps
        # added Tier-0 declarations (or one bounded legacy source family) onto
        # their cumulative executable routes.
        "obligation_route_mapping": gate_mapping,
        "family_obligation_route_mapping": family_mapping,
        "bounded_exclusions": list(_EXCLUSIONS.get(kind, (
            "runtime-domain truth beyond the selected finite routes",
            "external authority",
            "release and deployment",
        ))),
        "claim_boundary": (
            "PASS establishes only the installed source-package variant through the requested tier. "
            "Necessary routes executed and non-triggered routes retained exact refutation evidence. "
            "The bounded exclusions are not promoted to established facts."
        ),
    }
    return {**body, "profile_digest": value_digest(body)}


def _kind_denominators() -> dict[str, Any]:
    """Name the retained wire partition and the complete package union."""
    return {
        "base_core_kind_count": BASE_CORE_KIND_COUNT,
        "base_core_kind_scope": "RETAINED_OBJECT_KIND_WIRE",
        "base_core_kinds": list(_EXPECTED_BASE_CORE_KINDS),
        "package_added_kind_count": PACKAGE_ADDED_KIND_COUNT,
        "package_added_kinds": list(_EXPECTED_PACKAGE_ADDED_KINDS),
        "package_kind_count": PACKAGE_KIND_COUNT,
        "package_kind_scope": "INSTALLED_PACKAGE_NAMESPACE",
        "package_kinds": list(_EXPECTED_NAMESPACE_KINDS),
        "partition_status": "EXACT_DISJOINT_UNION",
    }


# One polish command asks for a kind's profile thousands of times while the installed
# sources it is built from cannot change.  Inside ``document_scope`` the validated
# document is built once and every caller receives its own copy; outside a scope each
# call revalidates the installed sources.  A refused build is never retained.
_SCOPE_DEPTH = 0
_SCOPED_DOCUMENT: dict[str, Any] | None = None


@contextmanager
def document_scope() -> Iterator[None]:
    """Build the installed profile document once for the enclosed command."""
    global _SCOPE_DEPTH, _SCOPED_DOCUMENT
    _SCOPE_DEPTH += 1
    try:
        yield
    finally:
        _SCOPE_DEPTH -= 1
        if _SCOPE_DEPTH == 0:
            _SCOPED_DOCUMENT = None


def _installed_document() -> dict[str, Any]:
    global _SCOPED_DOCUMENT
    if not _SCOPE_DEPTH:
        return _build_document()
    if _SCOPED_DOCUMENT is None:
        _SCOPED_DOCUMENT = _build_document()
    return _SCOPED_DOCUMENT


def document() -> dict[str, Any]:
    """Return the exact 38-profile registry and reject namespace drift."""
    built = _installed_document()
    return deepcopy(built) if _SCOPE_DEPTH else built


def _build_document() -> dict[str, Any]:
    registry = namespace_registry()
    base_core = set(_EXPECTED_BASE_CORE_KINDS)
    package_added = set(_EXPECTED_PACKAGE_ADDED_KINDS)
    package_kinds = set(_EXPECTED_NAMESPACE_KINDS)
    if (
        len(base_core) != BASE_CORE_KIND_COUNT
        or len(package_added) != PACKAGE_ADDED_KIND_COUNT
        or len(package_kinds) != PACKAGE_KIND_COUNT
        or base_core & package_added
        or base_core | package_added != package_kinds
    ):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_KIND_PARTITION_INVALID")
    if {kind.value for kind in ObjectKind} != base_core:
        raise ValueError("PACKAGE_CONTRACT_PROFILE_OBJECT_KIND_ENUM_DIFFERS")
    if set(_CORE_ROUTES) != base_core:
        raise ValueError("PACKAGE_CONTRACT_PROFILE_BASE_CORE_DIFFERS")
    if set(_ADDED_ROUTES) != package_added:
        raise ValueError("PACKAGE_CONTRACT_PROFILE_ADDED_KINDS_DIFFER")
    if package_kinds != set(registry):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_NAMESPACE_DIFFERS")
    if set(_CORE_ROUTES) & set(_ADDED_ROUTES):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_KIND_DUPLICATED")
    profiles = {
        **{kind: _profile(kind, routes, added=False) for kind, routes in _CORE_ROUTES.items()},
        **{kind: _profile(kind, routes, added=True) for kind, routes in _ADDED_ROUTES.items()},
    }
    # Resolve the exact focused-gate identifier system here, not only in tests.
    # A same-count source catalog with a missing, duplicated, or substituted
    # obligation must not leave a plausible-looking profile mapping behind.
    from verifier.runtime import package_source_contracts

    source_catalog = package_source_contracts.catalog()
    source_coordinates = [row.get("coordinate") for row in source_catalog]
    if (
        len(source_catalog) != PACKAGE_KIND_COUNT * 3
        or len(source_coordinates) != len(set(source_coordinates))
    ):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_DENOMINATOR_INVALID")
    source_by_coordinate = {row["coordinate"]: row for row in source_catalog}
    for selected in profiles.values():
        for obligation_id, coordinates in selected[
            "obligation_route_mapping"
        ].items():
            if len(coordinates) != 1:
                raise ValueError("PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_MAPPING_INVALID")
            route = source_by_coordinate.get(coordinates[0])
            if route is None or route.get("obligation_id") != obligation_id:
                raise ValueError("PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_MAPPING_DIFFERS")
    ordered = {kind: profiles[kind] for kind in sorted(profiles)}
    body = {
        "schema_version": SCHEMA,
        "kind_denominators": _kind_denominators(),
        "profiles": ordered,
        "claim_boundary": (
            "Installed Verifier source-package variant profiles only. The retained "
            "26-kind wire registry is one exact base partition of the complete "
            "38-kind package namespace; local extensions and unprofiled variants "
            "remain UNKNOWN."
        ),
    }
    return {**body, "document_digest": value_digest(body)}


def profile(kind: str) -> dict[str, Any] | None:
    """Return a defensive copy; absence is an explicit UNKNOWN, never exemption."""
    selected = _installed_document()["profiles"].get(kind)
    return deepcopy(selected) if selected is not None else None


def required_coordinates(kind: str, tier: int) -> tuple[str, ...] | None:
    """Return the cumulative source-plus-behavioral denominator."""
    selected = profile(kind)
    if selected is None:
        return None
    if type(tier) is not int or tier not in (1, 2, 3):
        raise ValueError("PACKAGE_CONTRACT_PROFILE_TIER_INVALID")
    source = [selected["source_routes"][str(depth)] for depth in range(1, tier + 1)]
    behavior = [coordinate for depth in range(1, tier + 1)
                for coordinate in selected["behavioral_routes"][str(depth)]]
    return tuple(source + behavior)


def _semantic_mapping_evidence(
    obligation_id: str,
    *,
    catalog: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Revalidate one literal source audit; never infer coverage from presence."""
    binding = _SEMANTIC_MAPPING_BINDINGS.get(obligation_id)
    if binding is None:
        return None
    if catalog is None:
        # The boundary needs only the two source-owning registries for these
        # 14 mappings. Rebuilding the 293-route aggregate once per object would
        # make package-graph cost depend on unrelated route volume.
        from verifier.runtime import (
            added_kind_behavioral_routes,
            package_execution,
        )

        catalog = [
            *package_execution.catalog(),
            *added_kind_behavioral_routes.catalog(),
        ]
    selected = [
        row for row in catalog
        if row.get("coordinate") == binding["route_coordinate"]
    ]
    failures: list[str] = []
    route = selected[0] if len(selected) == 1 else {}
    if len(selected) != 1:
        failures.append("the mapped route is absent or duplicated")
    route_projection = {
        field: route.get(field) for field in _ROUTE_BINDING_FIELDS
    }
    route_digest = value_digest(route_projection)
    if route_digest != binding["route_binding_digest"]:
        failures.append("the audited route binding digest differs")
    expected_proposition = binding.get("proposition_digest")
    if (
        expected_proposition is not None
        and route.get("proposition_digest") != expected_proposition
    ):
        failures.append("the audited proposition digest differs")
    if route.get("mechanism_digest") != binding["catalog_mechanism_digest"]:
        failures.append("the audited catalog mechanism digest differs")
    if not _callable_mechanism(route.get("checking_mechanism")):
        failures.append("the mapped checking mechanism is not callable")

    root = Path(__file__).resolve().parents[3]
    observed_sources: dict[str, str | None] = {}
    for relative, expected_digest in sorted(binding["source_digests"].items()):
        try:
            target = (root / relative).resolve(strict=True)
            target.relative_to(root)
            digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError):
            digest = None
        observed_sources[relative] = digest
        if digest != expected_digest:
            failures.append("selected source differs: " + relative)
    source_binding = {
        "catalog_mechanism_digest": route.get("mechanism_digest"),
        "source_digests": observed_sources,
    }
    expected_source_binding = {
        "catalog_mechanism_digest": binding["catalog_mechanism_digest"],
        "source_digests": dict(sorted(binding["source_digests"].items())),
    }
    body = {
        "obligation_id": obligation_id,
        "route_coordinate": binding["route_coordinate"],
        "route_obligation_id": route.get("obligation_id"),
        "checking_mechanism": route.get("checking_mechanism"),
        "route_binding_digest": route_digest,
        "required_route_binding_digest": binding["route_binding_digest"],
        "proposition_digest": route.get("proposition_digest"),
        "required_proposition_digest": expected_proposition,
        "source_binding_digest": value_digest(source_binding),
        "required_source_binding_digest": value_digest(expected_source_binding),
        "source_bindings": [
            {"path": relative, "sha256": digest}
            for relative, digest in observed_sources.items()
        ],
        "catalog_mechanism_digest": route.get("mechanism_digest"),
        "status": (
            "UNKNOWN" if failures
            else "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE"
        ),
        "reason": (
            "Source-bound semantic mapping audit reopened UNKNOWN because "
            + "; ".join(failures) + "."
            if failures else
            binding["coverage_reason"]
            + " This establishes only a bounded executable mapping; a fresh "
              "applicable package instance must still execute it."
        ),
    }
    return {**body, "evidence_digest": value_digest(body)}


def _checking_mechanism_callable(dotted: Any) -> Any:
    """Resolve only the finite checker graph compiled into this package.

    Direct branch imports preserve lazy loading without granting an arbitrary
    ``import_module`` capability to a route string.  A new checker therefore
    requires an explicit source change and fresh package review.
    """

    if dotted == "verifier.runtime.emulator_control_execution.evaluate":
        from verifier.runtime import emulator_control_execution
        return emulator_control_execution.evaluate
    if dotted == "verifier.runtime.local_ledger_execution.evaluate":
        from verifier.runtime import local_ledger_execution
        return local_ledger_execution.evaluate
    if dotted == "verifier.runtime.manifest_write_execution.evaluate":
        from verifier.runtime import manifest_write_execution
        return manifest_write_execution.evaluate
    if dotted == "verifier.runtime.package_admission.assess":
        from verifier.runtime import package_admission
        return package_admission.assess
    if dotted == "verifier.runtime.package_polish.assess_package_polish":
        from verifier.runtime import package_polish
        return package_polish.assess_package_polish
    if dotted == (
        "verifier.runtime.package_source_contracts."
        "SourceContractAssessment.evaluate"
    ):
        from verifier.runtime import package_source_contracts
        return package_source_contracts.SourceContractAssessment.evaluate
    if dotted == "verifier.runtime.provenance_policy_execution.evaluate":
        from verifier.runtime import provenance_policy_execution
        return provenance_policy_execution.evaluate
    if dotted == "verifier.runtime.resource_measurement_execution.evaluate":
        from verifier.runtime import resource_measurement_execution
        return resource_measurement_execution.evaluate
    if dotted == "verifier.runtime.token_asset_execution.evaluate":
        from verifier.runtime import token_asset_execution
        return token_asset_execution.evaluate
    if dotted == "verifier.runtime.tier_zero.assess_tier_zero":
        from verifier.runtime import tier_zero
        return tier_zero.assess_tier_zero
    if dotted == "verifier.runtime.transaction_execution.check_observations":
        from verifier.runtime import transaction_execution
        return transaction_execution.check_observations
    if dotted == "verifier.runtime.worker_protocol_execution.evaluate":
        from verifier.runtime import worker_protocol_execution
        return worker_protocol_execution.evaluate
    if dotted == (
        "verifier.runtime.added_kind_behavioral_routes."
        "recheck_policy_enforcement_certificate"
    ):
        from verifier.runtime import added_kind_behavioral_routes
        return added_kind_behavioral_routes.recheck_policy_enforcement_certificate
    if dotted == (
        "verifier.domains.contracts.agency_surface."
        "recheck_agency_surface_certificate"
    ):
        from verifier.domains.contracts import agency_surface
        return agency_surface.recheck_agency_surface_certificate
    if dotted == (
        "verifier.domains.contracts.market_checks."
        "recheck_market_checks_certificate"
    ):
        from verifier.domains.contracts import market_checks
        return market_checks.recheck_market_checks_certificate
    if dotted == (
        "verifier.domains.contracts.robot_checks."
        "recheck_robot_checks_certificate"
    ):
        from verifier.domains.contracts import robot_checks
        return robot_checks.recheck_robot_checks_certificate
    if dotted == (
        "verifier.domains.contracts.finbot_checks."
        "recheck_finbot_checks_certificate"
    ):
        from verifier.domains.contracts import finbot_checks
        return finbot_checks.recheck_finbot_checks_certificate
    from verifier.domains.contracts import current_object_routes
    try:
        module = current_object_routes.registered_mechanism_module(dotted)
    except current_object_routes.CurrentObjectRouteRefusal:
        return None
    return getattr(module, dotted.rsplit(".", 1)[-1], None)


def _checking_mechanism_source(
    dotted: Any,
    *,
    root: Path,
) -> tuple[str | None, Any]:
    """Resolve a checker to its repository-relative source and callable."""
    if type(dotted) is not str:
        return None, None
    selected = _checking_mechanism_callable(dotted)
    if not callable(selected):
        return None, selected
    try:
        source = inspect.getsourcefile(selected)
        if source is None:
            return None, selected
        path = Path(source).resolve(strict=True)
        relative = path.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None, selected
    return relative, selected


def _declaration_field_source_inventory(
    catalog: list[dict[str, Any]],
) -> dict[str, str | None]:
    """Hash each selected checker module once for all 145 field decisions."""
    root = Path(__file__).resolve().parents[3]
    paths: set[str] = set()
    for route in catalog:
        coordinate = route.get("coordinate")
        if not any(
            coordinate in binding["route_coordinates"]
            for fields in _DECLARATION_FIELD_BINDINGS.values()
            for binding in fields.values()
        ):
            continue
        relative, _ = _checking_mechanism_source(
            route.get("checking_mechanism"), root=root
        )
        if relative is not None:
            paths.add(relative)
    inventory: dict[str, str | None] = {}
    for relative in sorted(paths | set(_DECLARATION_FIELD_SOURCE_DIGESTS)):
        try:
            target = (root / relative).resolve(strict=True)
            target.relative_to(root)
            inventory[relative] = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError):
            inventory[relative] = None
    return inventory


def declaration_field_evidence(
    obligation_id: str,
    *,
    catalog: list[dict[str, Any]] | None = None,
    source_inventory: Mapping[str, str | None] | None = None,
) -> dict[str, Any] | None:
    """Return exact field-level coverage without promoting partial checks.

    A missing whole-obligation entry is an explicit UNKNOWN.  Once an entry
    exists, its field keys must equal the namespace declaration exactly;
    silently dropping or inventing a field is a broken installed contract.
    """
    registry = namespace_registry()
    declarations = {
        obligation.id: obligation
        for kind in _ADDED_ROUTES
        for obligation in registry[kind].obligations
    }
    declaration = declarations.get(obligation_id)
    if declaration is None:
        return None
    expected_fields = set(declaration.declaration_fields)
    bindings = _DECLARATION_FIELD_BINDINGS.get(obligation_id)
    if bindings is None:
        rows = [{
            "field": field,
            "status": "DECLARATION_FIELDS_UNBOUND",
            "reason": "No installed field-level audit entry binds this declaration field.",
            "route_coordinates": [],
            "evidence": [],
        } for field in declaration.declaration_fields]
        body = {
            "obligation_id": obligation_id,
            "status": "UNKNOWN",
            "route_binding_digest": None,
            "required_route_binding_digest": None,
            "source_binding_digest": None,
            "required_source_binding_digest": value_digest(
                dict(sorted(_DECLARATION_FIELD_SOURCE_DIGESTS.items()))
            ),
            "field_bindings": rows,
            "unmapped_declaration_fields": rows,
            "status_counts": {"DECLARATION_FIELDS_UNBOUND": len(rows)},
            "reason": "The obligation has no installed field-level binding; route PASS cannot close it.",
        }
        return {**body, "evidence_digest": value_digest(body)}
    if set(bindings) != expected_fields:
        raise ValueError(
            "PACKAGE_CONTRACT_DECLARATION_FIELD_KEYS_DIFFER:" + obligation_id
        )
    expected_routes = set(next(iter(bindings.values()))["route_coordinates"])
    for field, binding in bindings.items():
        if (
            set(binding) != {
                "status", "reason", "route_coordinates", "evidence_selector"
            }
            or binding["status"] not in set(_FIELD_STATUS_NAMES.values())
            or type(binding["reason"]) is not str
            or not binding["reason"].strip()
            or binding["evidence_selector"] != "ROUTE_CHECKING_MECHANISM_SOURCE"
            or set(binding["route_coordinates"]) != expected_routes
        ):
            raise ValueError(
                "PACKAGE_CONTRACT_DECLARATION_FIELD_BINDING_INVALID:"
                + obligation_id + ":" + field
            )
        boundary_status = _BOUNDARY_STATUS_PINS.get((obligation_id, field))
        if boundary_status is not None and binding["status"] != boundary_status:
            raise ValueError(
                "PACKAGE_CONTRACT_DECLARATION_FIELD_BOUNDARY_OVERCLAIMED:"
                + obligation_id + ":" + field
            )
    kind = obligation_id.split("-", 1)[0]
    tier = int(obligation_id.split("-0.", 1)[1].split("-", 1)[0])
    if expected_routes != set(_ADDED_ROUTES[kind][tier]):
        raise ValueError(
            "PACKAGE_CONTRACT_DECLARATION_FIELD_ROUTES_DIFFER:" + obligation_id
        )
    if catalog is None:
        from verifier.runtime.manifest_gate import obligation_catalog
        catalog = obligation_catalog()
    if source_inventory is None:
        source_inventory = _declaration_field_source_inventory(catalog)
    by_coordinate: dict[str, list[dict[str, Any]]] = {}
    for route in catalog:
        by_coordinate.setdefault(route.get("coordinate"), []).append(route)
    route_projections: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    failures: list[str] = []
    root = Path(__file__).resolve().parents[3]
    for coordinate in sorted(expected_routes):
        selected = by_coordinate.get(coordinate, [])
        route = selected[0] if len(selected) == 1 else {}
        if len(selected) != 1:
            failures.append("route absent or duplicated: " + coordinate)
        projection = {
            field: route.get(field) for field in _ROUTE_BINDING_FIELDS
        }
        route_projections.append(projection)
        symbol = route.get("checking_mechanism")
        relative, checker = _checking_mechanism_source(symbol, root=root)
        observed_source = (
            source_inventory.get(relative) if relative is not None else None
        )
        required_source = (
            _DECLARATION_FIELD_SOURCE_DIGESTS.get(relative)
            if relative is not None else None
        )
        if not callable(checker):
            failures.append("checking mechanism is not callable: " + coordinate)
        if required_source is None or observed_source != required_source:
            failures.append("checker source differs: " + str(relative))
        evidence.append({
            "coordinate": coordinate,
            "path": relative,
            "symbol": symbol,
            "sha256": observed_source,
            "required_sha256": required_source,
        })
    additional_sources: list[dict[str, Any]] = []
    for relative in _DECLARATION_FIELD_ADDITIONAL_SOURCE_PATHS.get(
        obligation_id, ()
    ):
        observed_source = source_inventory.get(relative)
        required_source = _DECLARATION_FIELD_SOURCE_DIGESTS.get(relative)
        if required_source is None or observed_source != required_source:
            failures.append("supporting source differs: " + relative)
        additional_sources.append({
            "path": relative,
            "sha256": observed_source,
            "required_sha256": required_source,
        })
    route_digest = value_digest(route_projections)
    required_route_digest = _DECLARATION_FIELD_ROUTE_DIGESTS.get(obligation_id)
    if route_digest != required_route_digest:
        failures.append("the audited field route binding digest differs")
    expected_source_subset = {
        row["path"]: row["required_sha256"]
        for row in [*evidence, *additional_sources] if row["path"] is not None
    }
    observed_source_subset = {
        row["path"]: row["sha256"]
        for row in [*evidence, *additional_sources] if row["path"] is not None
    }
    rows: list[dict[str, Any]] = []
    for field in declaration.declaration_fields:
        binding = bindings[field]
        audited_status = binding["status"]
        effective_status = (
            "UNKNOWN_SOURCE_OR_ROUTE_DRIFT"
            if audited_status == "MECHANIZED" and failures
            else audited_status
        )
        rows.append({
            "field": field,
            "status": effective_status,
            "reason": (
                binding["reason"]
                if effective_status == audited_status else
                "The previously adjudicated mechanism drifted from its pinned route or source bytes."
            ),
            "route_coordinates": list(binding["route_coordinates"]),
            "evidence": deepcopy(evidence),
        })
    unmapped = [row for row in rows if row["status"] != "MECHANIZED"]
    counts = {
        status: sum(row["status"] == status for row in rows)
        for status in sorted({row["status"] for row in rows})
    }
    body = {
        "obligation_id": obligation_id,
        "status": "BOUNDED" if not unmapped else "UNKNOWN",
        "route_binding_digest": route_digest,
        "required_route_binding_digest": required_route_digest,
        "source_binding_digest": value_digest(observed_source_subset),
        "required_source_binding_digest": value_digest(expected_source_subset),
        "supporting_source_bindings": deepcopy(additional_sources),
        "field_bindings": rows,
        "unmapped_declaration_fields": deepcopy(unmapped),
        "status_counts": counts,
        "reason": (
            "Every exact declaration field has a pinned bounded executable adjudication."
            if not unmapped else
            "Route PASS cannot close non-mechanized declaration fields: "
            + ", ".join(
                row["field"] + "=" + row["status"] for row in unmapped
            )
            + (". " + "; ".join(failures) if failures else "")
        ),
    }
    return {**body, "evidence_digest": value_digest(body)}


def _compose_semantic_mapping_blocker(
    obligation_id: str,
    mapping: dict[str, Any] | None,
    fields: dict[str, Any] | None,
) -> str | None:
    """Keep every reopened reason in one fixed order: static, mapping, field."""
    blocker = _SEMANTIC_MAPPING_BLOCKERS.get(obligation_id)
    if mapping is not None and mapping["status"] == "UNKNOWN":
        blocker = mapping["reason"]
    if fields is not None and fields["status"] == "UNKNOWN":
        blocker = (
            fields["reason"] if blocker is None
            else blocker + " " + fields["reason"]
        )
    return blocker


def semantic_mapping_blocker(obligation_id: str) -> str | None:
    """Return an audited semantic gap or exact drift, never an absence inference."""
    return _compose_semantic_mapping_blocker(
        obligation_id,
        _semantic_mapping_evidence(obligation_id),
        declaration_field_evidence(obligation_id),
    )


def _package_review_source_snapshot(
    root: Path,
    rows: Mapping[str, Any],
) -> dict[str, str]:
    """Hash the disjoint exact owned-path denominator without following escape links."""
    owners: dict[str, str] = {}
    result: dict[str, str] = {}
    for object_id in sorted(rows):
        row = rows[object_id]
        paths = row.get("owned_paths") if isinstance(row, Mapping) else None
        if type(paths) is not list or not paths:
            raise ValueError(
                "PACKAGE_INSTANCE_APPLICABILITY_OWNED_PATHS_INVALID:" + object_id
            )
        for path in paths:
            if type(path) is not str or not path or Path(path).is_absolute():
                raise ValueError(
                    "PACKAGE_INSTANCE_APPLICABILITY_OWNED_PATH_INVALID:"
                    + object_id
                )
            previous = owners.setdefault(path, object_id)
            if previous != object_id:
                raise ValueError(
                    "PACKAGE_INSTANCE_APPLICABILITY_SOURCE_OWNERSHIP_OVERLAP:"
                    + path
                )
            candidate = root / Path(path)
            try:
                information = candidate.lstat()
                if candidate.is_symlink() or (
                    getattr(information, "st_file_attributes", 0) & 0x400
                ):
                    raise OSError("symbolic or reparse source path")
                target = candidate.resolve(strict=True)
                target.relative_to(root)
                if not target.is_file():
                    raise OSError("source is not a regular file")
                raw = target.read_bytes()
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError(
                    "PACKAGE_INSTANCE_APPLICABILITY_SOURCE_UNAVAILABLE:"
                    + object_id
                    + ":"
                    + path
                ) from exc
            result[path] = "sha256:" + sha256(raw).hexdigest()
    return result


def _source_owned_package_review() -> dict[str, dict[str, Any]]:
    """Read the one migration-owned review denominator without copying its table.

    The migration is the integrator for the feature-near source review modules.
    Reusing that exact module tuple prevents a second, silently divergent list
    here.  This read remains applicability evidence only: it does not execute a
    checker, specimen, package object, or Polish route.
    """
    from verifier.runtime import (
        package_manifest_migration,
        package_original_kind_catalog_runtime,
        package_semantic_ownership,
    )

    root = Path(__file__).resolve().parents[3]
    receipt = _PACKAGE_REVIEW_COORDINATE_RECEIPT
    for relative, expected_digest in receipt["source_digests"].items():
        try:
            target = (root / relative).resolve(strict=True)
            target.relative_to(root)
            observed_digest = "sha256:" + sha256(target.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_INSTANCE_APPLICABILITY_REVIEW_SOURCE_UNAVAILABLE:"
                + relative
            ) from exc
        if observed_digest != expected_digest:
            raise ValueError(
                "PACKAGE_INSTANCE_APPLICABILITY_REVIEW_SOURCE_DIFFERS:"
                + relative
            )
    catalog_rows = package_semantic_ownership.catalog_document(root)["objects"]
    selected = [
        row for row in catalog_rows if row.get("object_id") == receipt["object_id"]
    ]
    if len(selected) != 1:
        raise ValueError("PACKAGE_INSTANCE_APPLICABILITY_REVIEW_COORDINATE_MISSING")
    row = selected[0]
    observed_coordinate_digest = (
        package_original_kind_catalog_runtime._source_coordinate_digest(
            row["object_id"],
            row["primary_kind"],
            tuple(row["owned_paths"]),
            row["representation_role"],
            row["necessity_reason"],
            row["consequence_boundary"],
            tuple(row["specializations"]),
            tuple(
                (item["kind"], item["status"], item["reason"])
                for item in row["root_role_decisions"]
            ),
            tuple(
                (item["name"], tuple(item["targets"]))
                for item in row["operands"]
            ),
        )
    )
    if observed_coordinate_digest != receipt["expected_source_coordinate_digest"]:
        raise ValueError(
            "PACKAGE_INSTANCE_APPLICABILITY_REVIEW_COORDINATE_DIFFERS"
        )

    result: dict[str, dict[str, Any]] = {}
    for module in package_manifest_migration._PACKAGE_REVIEW_MODULES:
        document = module.review_document()
        if type(document) is not dict:
            raise ValueError(
                "PACKAGE_INSTANCE_APPLICABILITY_REVIEW_DOCUMENT_INVALID:"
                + module.__name__
            )
        overlap = set(result).intersection(document)
        if overlap:
            raise ValueError(
                "PACKAGE_INSTANCE_APPLICABILITY_REVIEW_OVERLAP:"
                + min(overlap)
            )
        result.update(deepcopy(document))
    if not result:
        raise ValueError("PACKAGE_INSTANCE_APPLICABILITY_OBJECT_DENOMINATOR_EMPTY")
    return result


def _declares_effect_domain(declarations: Any, marker: str) -> bool:
    """Recognize only a structured exact effect-domain token.

    Prose reasons frequently explain that a marker is absent. They are never
    positive consequence evidence. Only a declaration field explicitly named
    ``effect_domains`` (or a singular consequence-domain equivalent) can select
    a carrier, and the marker must be one complete token.
    """
    if not isinstance(declarations, Mapping):
        return False
    for declaration in declarations.values():
        if not isinstance(declaration, Mapping):
            continue
        for field in ("effect_domains", "effect_domain", "consequence_domain"):
            value = declaration.get(field)
            if type(value) is str and marker in (
                value.replace(",", " ")
                .replace(";", " ")
                .replace("|", " ")
                .split()
            ):
                return True
            if type(value) in {list, tuple, set, frozenset} and marker in value:
                return True
    return False


_PACKAGE_REVIEW_ROW_FIELDS = frozenset({
    "claim_boundary",
    "classification",
    "declarations",
    "owned_paths",
    "primary_kind",
})
_PACKAGE_REVIEW_DEPENDENCY_FIELDS = frozenset({
    "local_endpoint_paths",
    "reason",
    "target_evidence_paths",
    "targets",
})


def _review_row_is_valid(
    object_id: str,
    row: Any,
    *,
    expected_object_ids: frozenset[str],
    all_owned_paths: frozenset[str],
    duplicated_owned_paths: frozenset[str],
) -> bool:
    """Validate one exact review row before it can support either promotion.

    Review modules are source-owned inputs, not trusted exemptions. Unknown row
    fields, invented obligation coordinates, partial declarations, and malformed
    dependency edges therefore reopen UNKNOWN instead of contributing to an
    all-object CONDITION_NOT_MET result or inventing a consequence carrier.
    """
    if not isinstance(row, Mapping):
        return False
    fields = frozenset(row)
    if fields not in {
        _PACKAGE_REVIEW_ROW_FIELDS,
        _PACKAGE_REVIEW_ROW_FIELDS | {"dependency_operands"},
    }:
        return False

    registry = namespace_registry()
    review_kinds = frozenset(
        kind for kind, contract in registry.items() if contract.obligations
    )
    obligation_schema = {
        obligation.id: (kind, frozenset(obligation.declaration_fields))
        for kind in review_kinds
        for obligation in registry[kind].obligations
    }
    if (
        type(row.get("primary_kind")) is not str
        or row["primary_kind"] not in registry
        or type(row.get("claim_boundary")) is not str
        or not row["claim_boundary"].strip()
    ):
        return False

    owned_paths = row.get("owned_paths")
    if (
        type(owned_paths) is not list
        or not owned_paths
        or any(type(path) is not str or not path for path in owned_paths)
        or len(owned_paths) != len(set(owned_paths))
        or bool(set(owned_paths) & duplicated_owned_paths)
    ):
        return False

    classification = row.get("classification")
    if type(classification) is not dict or set(classification) != review_kinds:
        return False
    applies: set[str] = set()
    for selected_kind, decision in classification.items():
        if type(decision) is not dict or set(decision) != {
            "evidence_paths", "reason", "status"
        }:
            return False
        status = decision.get("status")
        reason = decision.get("reason")
        evidence_paths = decision.get("evidence_paths")
        if (
            status not in {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED"}
            or type(reason) is not str
            or not reason.strip()
            or type(evidence_paths) is not list
            or any(type(path) is not str or not path for path in evidence_paths)
            or len(evidence_paths) != len(set(evidence_paths))
            or not set(evidence_paths) <= set(owned_paths)
            or (status == "UNRESOLVED") != (not evidence_paths)
        ):
            return False
        if status == "APPLIES":
            applies.add(selected_kind)

    declarations = row.get("declarations")
    if type(declarations) is not dict:
        return False
    expected_declarations = {
        obligation.id
        for selected_kind in applies
        for obligation in registry[selected_kind].obligations
    }
    if set(declarations) != expected_declarations:
        return False
    for obligation_id, declaration in declarations.items():
        schema = obligation_schema.get(obligation_id)
        if (
            schema is None
            or schema[0] not in applies
            or type(declaration) is not dict
            or set(declaration) != schema[1]
            or any(
                type(value) is not str or not value.strip()
                for value in declaration.values()
            )
        ):
            return False

    dependencies = row.get("dependency_operands", {})
    if type(dependencies) is not dict:
        return False
    for relation, binding in dependencies.items():
        if (
            type(relation) is not str
            or not relation.strip()
            or type(binding) is not dict
            or set(binding) != _PACKAGE_REVIEW_DEPENDENCY_FIELDS
            or type(binding.get("reason")) is not str
            or not binding["reason"].strip()
        ):
            return False
        for key in ("local_endpoint_paths", "target_evidence_paths", "targets"):
            values = binding.get(key)
            if (
                type(values) is not list
                or not values
                or any(type(value) is not str or not value for value in values)
                or len(values) != len(set(values))
            ):
                return False
        if (
            not set(binding["local_endpoint_paths"]) <= set(owned_paths)
            or not set(binding["target_evidence_paths"]) <= all_owned_paths
            or not set(binding["targets"]) <= expected_object_ids
            or object_id in binding["targets"]
        ):
            return False
    return True


def _unknown_applicability(
    kind: str,
    *,
    reason: str,
    object_denominator: int,
    missing_object_ids: list[str] | None = None,
    extra_object_ids: list[str] | None = None,
) -> dict[str, Any]:
    body = {
        "kind": kind,
        "status": "UNKNOWN",
        "reason": reason,
        "effect_domain": _PACKAGE_INSTANCE_EFFECT_DOMAIN[kind],
        "object_denominator": object_denominator,
        "reviewed_object_count": 0,
        "applies_count": 0,
        "does_not_apply_count": 0,
        "unresolved_count": object_denominator,
        "invalid_count": 0,
        "carrier_count": 0,
        "carriers": [],
        "next_unresolved": None,
        "missing_object_ids": list(missing_object_ids or ()),
        "extra_object_ids": list(extra_object_ids or ()),
        "checker_or_specimen_execution_is_carrier_evidence": False,
        "source_binding_digest": None,
        "source_bound_refutation_count": 0,
    }
    return {**body, "evidence_digest": value_digest(body)}


def reconcile_package_instance_applicability(
    kind: str,
    rows: Mapping[str, Any],
    *,
    expected_object_ids: frozenset[str] | set[str] | tuple[str, ...],
    source_inventory: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Reconcile one consequence family over every exact package object.

    A family-wide refutation exists only when every expected object contains a
    source-specific, evidenced DOES_NOT_APPLY decision and no declaration names
    the family's real effect domain. Any unresolved or malformed cell keeps the
    result UNKNOWN. APPLIES or a structured real-effect declaration selects the
    carrier immediately and makes the family necessary. Passing checker or
    specimen fields are deliberately ignored.
    """
    if kind not in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS:
        raise ValueError("PACKAGE_INSTANCE_APPLICABILITY_KIND_INVALID:" + kind)
    expected = frozenset(expected_object_ids)
    if not expected or not isinstance(rows, Mapping):
        return _unknown_applicability(
            kind,
            reason="The exact package applicability review is absent or empty.",
            object_denominator=len(expected),
        )
    actual = frozenset(rows)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        return _unknown_applicability(
            kind,
            reason=(
                "The exact package object denominator differs; a missing or extra "
                "object cannot be treated as a family-wide refutation."
            ),
            object_denominator=len(expected),
            missing_object_ids=missing,
            extra_object_ids=extra,
        )

    owned_path_counts: dict[str, int] = {}
    for candidate_row in rows.values():
        paths = (
            candidate_row.get("owned_paths")
            if isinstance(candidate_row, Mapping) else None
        )
        if type(paths) is list:
            for path in paths:
                if type(path) is str:
                    owned_path_counts[path] = owned_path_counts.get(path, 0) + 1
    all_owned_paths = frozenset(owned_path_counts)
    duplicated_owned_paths = frozenset(
        path for path, count in owned_path_counts.items() if count != 1
    )

    counts = {"APPLIES": 0, "DOES_NOT_APPLY": 0, "UNRESOLVED": 0}
    invalid: list[str] = []
    unresolved: list[str] = []
    carriers: dict[str, str] = {}
    bound_paths: set[str] = set()
    decision_paths: dict[str, list[str]] = {}
    effect_paths: dict[str, list[str]] = {}
    marker = _PACKAGE_INSTANCE_EFFECT_DOMAIN[kind]
    for object_id in sorted(expected):
        row = rows.get(object_id)
        if not _review_row_is_valid(
            object_id,
            row,
            expected_object_ids=expected,
            all_owned_paths=all_owned_paths,
            duplicated_owned_paths=duplicated_owned_paths,
        ):
            invalid.append(object_id)
            continue
        owned_paths = row.get("owned_paths")
        classification = row.get("classification")
        decision = (
            classification.get(kind)
            if isinstance(classification, Mapping)
            else None
        )
        if (
            type(owned_paths) is not list
            or not owned_paths
            or any(type(path) is not str or not path for path in owned_paths)
            or len(owned_paths) != len(set(owned_paths))
            or not isinstance(decision, Mapping)
        ):
            invalid.append(object_id)
            continue
        status = decision.get("status")
        reason = decision.get("reason")
        evidence_paths = decision.get("evidence_paths")
        if (
            status not in counts
            or type(reason) is not str
            or not reason.strip()
            or type(evidence_paths) is not list
            or any(type(path) is not str for path in evidence_paths)
            or len(evidence_paths) != len(set(evidence_paths))
            or not set(evidence_paths) <= set(owned_paths)
            or (status != "UNRESOLVED" and not evidence_paths)
        ):
            invalid.append(object_id)
            continue
        decision_paths[object_id] = list(evidence_paths)
        counts[status] += 1
        if status == "APPLIES":
            carriers[object_id] = "SOURCE_CLASSIFICATION_APPLIES"
        elif status == "UNRESOLVED":
            unresolved.append(object_id)
        if _declares_effect_domain(row.get("declarations"), marker):
            effect_paths[object_id] = list(owned_paths)
            carriers[object_id] = "DECLARED_" + marker + "_EFFECT"

    def bind(paths: list[str]) -> bool:
        if not isinstance(source_inventory, Mapping):
            return False
        if any(
            type(source_inventory.get(path)) is not str
            or not source_inventory[path].startswith("sha256:")
            or len(source_inventory[path]) != 71
            or any(
                character not in "0123456789abcdef"
                for character in source_inventory[path][7:]
            )
            for path in paths
        ):
            return False
        bound_paths.update(paths)
        return True

    # Positive applicability always requires current source binding. A missing
    # binding cannot demote APPLIES to absence; it reopens UNKNOWN instead.
    for object_id in list(carriers):
        paths = (
            effect_paths[object_id]
            if object_id in effect_paths
            else decision_paths[object_id]
        )
        if not bind(paths):
            invalid.append(object_id)
            carriers.pop(object_id)

    source_bound_refutation_count = 0
    # Hashing every package path is required only at the all-DNE promotion
    # boundary. If a cell is already unresolved, the family stays UNKNOWN and
    # no graph-sized source scan is needed merely to rediscover that fact.
    if not carriers and not invalid and not unresolved:
        for object_id in sorted(expected):
            if bind(decision_paths[object_id]):
                source_bound_refutation_count += 1
            else:
                invalid.append(object_id)

    if carriers:
        status = "NECESSARY"
        reason = (
            "At least one exact source-owned package object applies this family or "
            "declares its real consequence domain; package obligations are necessary."
        )
    elif invalid or unresolved:
        status = "UNKNOWN"
        reason = (
            "A family-wide CONDITION_NOT_MET result requires every exact package "
            "object to have a validated DOES_NOT_APPLY decision and no contradictory "
            "real-effect declaration."
        )
    else:
        status = "SOURCE_BOUND_CONDITION_NOT_MET"
        reason = (
            "Every exact package object has a source-specific DOES_NOT_APPLY decision "
            "and no declaration names the family's real consequence domain."
        )
    carrier_rows = [
        {"object_id": object_id, "basis": basis}
        for object_id, basis in sorted(carriers.items())
    ]
    body = {
        "kind": kind,
        "status": status,
        "reason": reason,
        "effect_domain": marker,
        "object_denominator": len(expected),
        "reviewed_object_count": sum(counts.values()),
        "applies_count": counts["APPLIES"],
        "does_not_apply_count": counts["DOES_NOT_APPLY"],
        "unresolved_count": counts["UNRESOLVED"],
        "invalid_count": len(invalid),
        "carrier_count": len(carrier_rows),
        "carriers": carrier_rows,
        "next_unresolved": (
            invalid[0] if invalid else unresolved[0] if unresolved else None
        ),
        "missing_object_ids": [],
        "extra_object_ids": [],
        "checker_or_specimen_execution_is_carrier_evidence": False,
        "source_binding_digest": (
            value_digest({
                "files": [
                    {"path": path, "sha256": source_inventory[path]}
                    for path in sorted(bound_paths)
                ]
            })
            if isinstance(source_inventory, Mapping) else None
        ),
        "source_bound_refutation_count": source_bound_refutation_count,
    }
    return {**body, "evidence_digest": value_digest(body)}


def _package_instance_applicability_assessments() -> dict[str, dict[str, Any]]:
    """Compute all three families from one fresh exact review snapshot."""
    try:
        rows = _source_owned_package_review()
    except (ImportError, OSError, TypeError, ValueError) as exc:
        reason = (
            "The source-owned package applicability review could not be validated "
            "(" + type(exc).__name__ + "); no absence or exemption is inferred."
        )
        return {
            kind: _unknown_applicability(
                kind,
                reason=reason,
                object_denominator=0,
            )
            for kind in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS
        }
    expected = frozenset(rows)
    needs_source_binding = any(
        any(
            isinstance(row, Mapping)
            and (
                isinstance(row.get("classification"), Mapping)
                and isinstance(row["classification"].get(kind), Mapping)
                and row["classification"][kind].get("status") == "APPLIES"
                or _declares_effect_domain(
                    row.get("declarations"),
                    _PACKAGE_INSTANCE_EFFECT_DOMAIN[kind],
                )
            )
            for row in rows.values()
        )
        or all(
            isinstance(row, Mapping)
            and isinstance(row.get("classification"), Mapping)
            and isinstance(row["classification"].get(kind), Mapping)
            and row["classification"][kind].get("status") == "DOES_NOT_APPLY"
            for row in rows.values()
        )
        for kind in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS
    )
    source_inventory: Mapping[str, str] | None = None
    if needs_source_binding:
        try:
            root = Path(__file__).resolve().parents[3]
            opening = _package_review_source_snapshot(root, rows)
            closing = _package_review_source_snapshot(root, rows)
            if closing != opening:
                raise ValueError("PACKAGE_INSTANCE_APPLICABILITY_SOURCE_CHANGED")
            source_inventory = opening
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            reason = (
                "The source-owned carrier or full-refutation evidence could not "
                "be byte-bound (" + type(exc).__name__ + "); applicability remains "
                "UNKNOWN."
            )
            return {
                kind: _unknown_applicability(
                    kind,
                    reason=reason,
                    object_denominator=len(expected),
                )
                for kind in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS
            }
    return {
        kind: reconcile_package_instance_applicability(
            kind,
            rows,
            expected_object_ids=expected,
            source_inventory=source_inventory,
        )
        for kind in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS
    }


def package_instance_applicability_blocker(obligation_id: str) -> str | None:
    """Return a fresh source-bound UNKNOWN, never a static absence shortcut."""
    kind = obligation_id.split("-", 1)[0]
    if obligation_id not in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS.get(kind, ()):
        return None
    assessment = _package_instance_applicability_assessments()[kind]
    return assessment["reason"] if assessment["status"] == "UNKNOWN" else None


def accumulated_roles(registry: Mapping[str, Any], kind: str) -> tuple[str, ...]:
    """Return the exact additive role chain; inheritance never replaces a role."""
    roles: list[str] = []
    selected: str | None = kind
    while selected is not None:
        if selected in roles or selected not in registry:
            raise ValueError("PACKAGE_CONTRACT_MATRIX_ROLE_CHAIN_INVALID:" + kind)
        roles.append(selected)
        selected = registry[selected].extends
    return tuple(roles)


def _callable_mechanism(path: Any) -> bool:
    if type(path) is not str or not path.strip():
        return False
    return callable(_checking_mechanism_callable(path))


def _profile_coordinates(selected: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        [selected["source_routes"][str(tier)] for tier in (1, 2, 3)]
        + [coordinate for tier in (1, 2, 3)
           for coordinate in selected["behavioral_routes"][str(tier)]]
    )


def _route_type(route: Mapping[str, Any]) -> str:
    from verifier.runtime import (
        added_kind_behavioral_routes,
        package_execution,
        package_source_contracts,
    )

    selected = dict(route)
    if package_source_contracts.is_route(selected):
        return "SOURCE_ADAPTER"
    if package_execution.route_mechanism(selected) is not None:
        return "PACKAGE_EXECUTION_ADAPTER"
    if added_kind_behavioral_routes.is_route(selected):
        return "ADDED_KIND_BEHAVIORAL"
    return "NATIVE_RECHECKER"


def _matrix_route(route: Mapping[str, Any]) -> dict[str, Any]:
    try:
        applicability = validate_applicability_binding(dict(route))
    except (TypeError, ValueError):
        applicability = deepcopy(route.get("applicability", {}))
    mode = applicability.get("mode") if isinstance(applicability, Mapping) else None
    mechanism = route.get("checking_mechanism")
    route_type = _route_type(route)
    return {
        "coordinate": route.get("coordinate"),
        "obligation_id": route.get("obligation_id"),
        "tier": route.get("tier"),
        "reason": route.get("reason"),
        "exact_claim": route.get("exact_claim"),
        "semantic_version": route.get("semantic_version"),
        "proposition_digest": route.get("proposition_digest"),
        "mechanism_digest": route.get("mechanism_digest"),
        "certificate_schema_version": route.get("certificate_schema_version"),
        "checking_mechanism": mechanism,
        "mechanism_status": "CALLABLE" if _callable_mechanism(mechanism) else "UNKNOWN",
        "adapter": route.get("adapter"),
        "route_type": route_type,
        "applicability": deepcopy(applicability),
        "applicability_digest": route.get("applicability_digest"),
        "catalog_presence": "PRESENT_NOT_CONFORMANCE",
        "schema_presence": "PRESENT_NOT_CONFORMANCE",
        "package_graph_reachability": "REQUIRES_FRESH_INSTANCE",
        "package_instance_execution_status": "NOT_ASSESSED",
        "source_variant_refutation_reachability": (
            (
                "SOURCE_BOUND_CONDITION_NOT_MET_AVAILABLE_AFTER_FRESH_SOURCE_ADAPTATION"
                if mode == "CONDITIONAL" else
                "PROHIBITED_FOR_NECESSARY"
            )
            if route_type == "NATIVE_RECHECKER" else "REQUIRES_FRESH_INSTANCE"
        ),
        "native_specimen_is_instance_evidence": False,
        "refutation_route": (
            {
                "status": "SOURCE_BOUND_CONDITION_NOT_MET",
                "condition": applicability.get("condition"),
                "unknown_condition": applicability.get("unknown_condition"),
                "classification": "CONDITION_NOT_MET",
                "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
                "claim_boundary": (
                    "A source-bound non-trigger refutes only this exact route; "
                    "it does not establish its obligation family."
                ),
            }
            if mode == "CONDITIONAL" else
            {
                "status": "PROHIBITED_FOR_NECESSARY",
                "condition": applicability.get("condition")
                    if isinstance(applicability, Mapping) else None,
                "claim_boundary": (
                    "A necessary route cannot be discharged by a negative or "
                    "optional disposition."
                ),
            }
        ),
    }


def _repository_admission_route(route: Mapping[str, Any]) -> dict[str, Any]:
    """Project a repository-global Tier-0 gate without recasting it as a kind."""
    try:
        applicability = validate_applicability_binding(dict(route))
    except (TypeError, ValueError):
        applicability = deepcopy(route.get("applicability", {}))
    mechanism = "verifier.runtime.tier_zero.assess_tier_zero"
    return {
        "coordinate": route.get("coordinate"),
        "obligation_id": route.get("obligation_id"),
        "tier": 0,
        "reason": route.get("rationale"),
        "exact_claim": route.get("exact_claim"),
        "required_evidence": deepcopy(route.get("required_evidence", [])),
        "checking_mechanism": mechanism,
        "mechanism_status": "CALLABLE" if _callable_mechanism(mechanism) else "UNKNOWN",
        "applicability": deepcopy(applicability),
        "applicability_digest": route.get("applicability_digest"),
        "catalog_presence": "PRESENT_NOT_CONFORMANCE",
        "schema_presence": "PRESENT_NOT_CONFORMANCE",
        "package_graph_reachability": "REQUIRES_FRESH_POLISH_0_REPOSITORY_ADMISSION",
        "native_specimen_is_instance_evidence": False,
        "refutation_route": {
            "status": "PROHIBITED_FOR_NECESSARY",
            "condition": applicability.get("condition")
                if isinstance(applicability, Mapping) else None,
            "claim_boundary": (
                "A necessary repository-admission gate cannot be discharged by "
                "a negative, optional, catalog-only, or specimen-only disposition."
            ),
        },
    }


def _matrix_body() -> dict[str, Any]:
    """Build the static denominator; this is not a package-conformance result."""
    from verifier.runtime.manifest_gate import _admission_catalog, obligation_catalog

    registry = namespace_registry()
    profile_document = document()
    profiles = profile_document["profiles"]
    repository_admission = [
        _repository_admission_route(row) for row in _admission_catalog()
    ]
    catalog = [deepcopy(row) for row in obligation_catalog() if row["tier"] <= 3]
    field_source_inventory = _declaration_field_source_inventory(catalog)
    field_evidence = {
        obligation.id: declaration_field_evidence(
            obligation.id,
            catalog=catalog,
            source_inventory=field_source_inventory,
        )
        for kind in _ADDED_ROUTES
        for obligation in registry[kind].obligations
    }
    mapping_evidence = {
        obligation_id: _semantic_mapping_evidence(
            obligation_id,
            catalog=catalog,
        )
        for obligation_id in sorted(_SEMANTIC_MAPPING_BINDINGS)
    }
    semantic_mapping_blockers: dict[str, str] = {}
    for obligation_id in sorted(
        set(_SEMANTIC_MAPPING_BLOCKERS)
        | set(mapping_evidence)
        | set(field_evidence)
    ):
        blocker = _compose_semantic_mapping_blocker(
            obligation_id,
            mapping_evidence.get(obligation_id),
            field_evidence.get(obligation_id),
        )
        if blocker is not None:
            semantic_mapping_blockers[obligation_id] = blocker
    package_applicability = _package_instance_applicability_assessments()
    catalog_coordinates = [row.get("coordinate") for row in catalog]
    by_coordinate = {
        row["coordinate"]: row
        for row in catalog
        if type(row.get("coordinate")) is str
    }
    required_coordinates = {
        coordinate
        for selected in profiles.values()
        for coordinate in _profile_coordinates(selected)
    }
    kinds: dict[str, dict[str, Any]] = {}
    for kind in sorted(set(registry) | set(profiles)):
        contract = registry.get(kind)
        selected = profiles.get(kind)
        if contract is None or selected is None:
            continue
        coordinates = _profile_coordinates(selected)
        source_coordinates = set(selected["source_routes"].values())
        covered: dict[str, dict[str, Any]] = {}
        for coordinate in sorted(source_coordinates):
            route = by_coordinate.get(coordinate, {})
            for obligation in route.get("covered_admission_obligations", []):
                if type(obligation) is dict and type(obligation.get("obligation_id")) is str:
                    covered.setdefault(obligation["obligation_id"], obligation)
        declared = {obligation.id: obligation for obligation in contract.obligations}
        profile_obligations = []
        for obligation_id, mapped in selected[
            "family_obligation_route_mapping"
        ].items():
            declaration = declared.get(obligation_id)
            source = covered.get(obligation_id, {})
            reason = declaration.reason if declaration is not None else source.get("reason")
            applicability = (
                deepcopy(declaration.applicability)
                if declaration is not None else
                deepcopy(by_coordinate.get(selected["source_routes"]["1"], {}).get(
                    "applicability", {}
                ))
            )
            semantic_evidence = mapping_evidence.get(obligation_id)
            declaration_evidence = field_evidence.get(obligation_id)
            semantic_blocker = semantic_mapping_blockers.get(obligation_id)
            applicability_assessment = package_applicability.get(kind)
            package_applicability_blocker = (
                applicability_assessment["reason"]
                if applicability_assessment is not None
                and applicability_assessment["status"] == "UNKNOWN"
                else None
            )
            profile_obligations.append({
                "obligation_id": obligation_id,
                "origin": (
                    "NAMESPACE_ADMISSION" if declaration is not None
                    else "SOURCE_ADAPTER"
                ),
                "reason": reason,
                "evidence_requirement": (
                    declaration.evidence_requirement if declaration is not None
                    else "Bind the exact installed review and current owned-source denominator."
                ),
                "declaration_fields": (
                    list(declaration.declaration_fields) if declaration is not None else []
                ),
                "applicability": applicability,
                "mapped_routes": list(mapped),
                # Added-kind declarations map one source route directly.  The
                # 26 retained profiles predate that mapping shape: their one
                # review-binding obligation maps the behavioral denominator,
                # while all three ``.90`` adapters carry its current-source
                # evidence.  Keep both representations explicit here rather
                # than treating absence from the old mapping as an exemption.
                "source_evidence_routes": (
                    [coordinate for coordinate in mapped
                     if coordinate in source_coordinates]
                    if declaration is not None else sorted(source_coordinates)
                ),
                "behavioral_routes": [
                    coordinate for coordinate in mapped
                    if coordinate not in source_coordinates
                ],
                "required_at_every_polish_tier": declaration is not None,
                "earliest_executable_tier": min(
                    _tier_from_coordinate(coordinate) for coordinate in mapped
                ),
                "semantic_mapping_status": (
                    "UNKNOWN" if semantic_blocker is not None
                    else (
                        "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE"
                        if semantic_evidence is not None else
                        "BOUNDED_ROUTE_DECLARED_NOT_CONFORMANCE"
                    )
                ),
                "semantic_mapping_blocker": semantic_blocker,
                "semantic_mapping_evidence": deepcopy(semantic_evidence),
                "declaration_field_evidence": deepcopy(declaration_evidence),
                "unmapped_declaration_fields": (
                    deepcopy(declaration_evidence[
                        "unmapped_declaration_fields"
                    ])
                    if declaration_evidence is not None else []
                ),
                "package_instance_applicability_status": (
                    {
                        "UNKNOWN": "UNKNOWN_SOURCE_BOUND_PACKAGE_APPLICABILITY",
                        "NECESSARY": "NECESSARY_SOURCE_BOUND_PACKAGE_CARRIER",
                        "SOURCE_BOUND_CONDITION_NOT_MET": (
                            "SOURCE_BOUND_CONDITION_NOT_MET"
                        ),
                    }[applicability_assessment["status"]]
                    if applicability_assessment is not None else
                    "REQUIRES_FRESH_INSTANCE_ASSESSMENT"
                ),
                "package_instance_applicability_blocker": (
                    package_applicability_blocker
                ),
                "package_instance_applicability_evidence": (
                    deepcopy(applicability_assessment)
                    if applicability_assessment is not None else None
                ),
                "package_graph_reachability": "REQUIRES_FRESH_INSTANCE",
            })
        kinds[kind] = {
            "kind": kind,
            "extends": contract.extends,
            "reason": contract.reason,
            "accumulated_roles": list(accumulated_roles(registry, kind)),
            "namespace_admission_obligations": [
                {
                    "obligation_id": obligation.id,
                    "reason": obligation.reason,
                    "evidence_requirement": obligation.evidence_requirement,
                    "declaration_fields": list(obligation.declaration_fields),
                    "applicability": deepcopy(obligation.applicability),
                    "applicability_digest": obligation.applicability_digest,
                }
                for obligation in contract.obligations
            ],
            "profile_obligations": profile_obligations,
            "source_evidence_routes": sorted(source_coordinates),
            "routes": [
                _matrix_route(by_coordinate[coordinate])
                for coordinate in coordinates
                if coordinate in by_coordinate
            ],
        }
    return {
        "schema_version": MATRIX_SCHEMA,
        "through_tier": 3,
        "kind_denominators": deepcopy(profile_document["kind_denominators"]),
        "repository_admission_obligation_denominator": len(repository_admission),
        "kind_denominator": len(kinds),
        "namespace_admission_obligation_denominator": sum(
            len(row["namespace_admission_obligations"]) for row in kinds.values()
        ),
        "profile_obligation_denominator": sum(
            len(row["profile_obligations"]) for row in kinds.values()
        ),
        "family_obligation_denominator": (
            len(repository_admission)
            + sum(len(row["profile_obligations"]) for row in kinds.values())
        ),
        "defined_obligation_denominator": len({
            *(
                row["obligation_id"]
                for row in repository_admission
            ),
            *(
                obligation["obligation_id"]
                for row in kinds.values()
                for obligation in row["profile_obligations"]
            ),
            *(
                route["obligation_id"]
                for row in kinds.values()
                for route in row["routes"]
            ),
        }),
        "route_denominator": sum(len(row["routes"]) for row in kinds.values()),
        "base_core_route_denominator": sum(
            len(kinds[kind]["routes"]) for kind in _EXPECTED_BASE_CORE_KINDS
        ),
        "package_added_route_denominator": sum(
            len(kinds[kind]["routes"])
            for kind in _EXPECTED_PACKAGE_ADDED_KINDS
        ),
        "catalog_route_denominator": len(catalog),
        "catalog_duplicate_coordinates": sorted(
            coordinate for coordinate in set(catalog_coordinates)
            if catalog_coordinates.count(coordinate) != 1
        ),
        "profile_routes_missing_catalog": sorted(
            required_coordinates - set(by_coordinate)
        ),
        "unprofiled_catalog_routes": sorted(
            set(by_coordinate) - required_coordinates
        ),
        "repository_admission_obligations": repository_admission,
        "kinds": kinds,
        "semantic_mapping_status": (
            "UNKNOWN" if semantic_mapping_blockers else "BOUNDED"
        ),
        "semantic_mapping_blockers": [
            {"obligation_id": obligation_id, "status": "UNKNOWN", "reason": reason}
            for obligation_id, reason in sorted(semantic_mapping_blockers.items())
        ],
        "package_instance_applicability_status": (
            "UNKNOWN"
            if any(
                row["status"] == "UNKNOWN"
                for row in package_applicability.values()
            )
            else "NECESSARY"
            if any(
                row["status"] == "NECESSARY"
                for row in package_applicability.values()
            )
            else "SOURCE_BOUND_CONDITION_NOT_MET"
        ),
        "package_instance_applicability_assessments": deepcopy(
            package_applicability
        ),
        "package_instance_applicability_blockers": [
            {
                "obligation_id": obligation_id,
                "status": "UNKNOWN",
                "reason": package_applicability[kind]["reason"],
            }
            for kind, obligation_ids in _PACKAGE_INSTANCE_FAMILY_OBLIGATIONS.items()
            if package_applicability[kind]["status"] == "UNKNOWN"
            for obligation_id in obligation_ids
        ],
        "production_preflight_status": "BOUNDED_ROUTE_BINDING_AVAILABLE",
        "production_preflight_blockers": [],
        "production_preflight_route_summary": {
            "native_route_count": 113,
            "conditional_source_refutation_available": 112,
            "necessary_source_refutation_prohibited": 1,
            "necessary_coordinate": "OBJECT-1.1",
            "claim_boundary": (
                "The enclosing production family cell supplies kind and tier, then "
                "the source adapter binds that coordinate to exactly one installed "
                "route. Conditional routes may be refuted only after fresh source "
                "adaptation PASS; OBJECT-1.1 remains necessary and non-refutable."
            ),
        },
        "claim_boundary": (
            "This matrix establishes the exact installed denominator and names each "
            "reason, applicability disposition, callable mechanism, and required "
            "fresh-execution path. It does not establish that a mapped mechanism "
            "covers every declaration-family semantic; those audited gaps remain "
            "UNKNOWN. Semantic mapping quality and current-package applicability "
            "are reported separately. Catalog, schema, adapter, or specimen presence is not "
            "conformance; only fresh package-graph instances can close a route."
        ),
    }


def _matrix_finding(
    code: str,
    kind: str | None,
    reason: str,
    *,
    obligation_id: str | None = None,
    coordinate: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "status": "FAIL",
        "kind": kind,
        "obligation_id": obligation_id,
        "coordinate": coordinate,
        "reason": reason,
        "next_action": ["vstd", "polish", "3"],
    }


def audit_contract_coverage_matrix(
    candidate: Mapping[str, Any],
    *,
    _expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Audit a candidate matrix against independent current namespace/routes."""
    expected = deepcopy(_matrix_body() if _expected is None else _expected)
    selected = deepcopy(dict(candidate)) if isinstance(candidate, Mapping) else {}
    findings: list[dict[str, Any]] = []

    def add(code: str, kind: str | None, reason: str, **focus: Any) -> None:
        findings.append(_matrix_finding(code, kind, reason, **focus))

    candidate_kinds = selected.get("kinds")
    if type(candidate_kinds) is not dict:
        candidate_kinds = {}
        add(
            "PACKAGE_CONTRACT_MATRIX_KINDS_INVALID",
            None,
            "The matrix kinds field is absent or not an object.",
        )
    expected_kinds = set(_EXPECTED_NAMESPACE_KINDS)
    if selected.get("kind_denominators") != expected["kind_denominators"]:
        add(
            "PACKAGE_CONTRACT_MATRIX_KIND_PARTITION_DIFFERS",
            None,
            "The exact 26-kind retained-wire and 12-kind package-addition partition differs from the complete 38-kind package namespace.",
        )
    for kind in sorted(expected_kinds - set(candidate_kinds)):
        add(
            "PACKAGE_CONTRACT_MATRIX_KIND_MISSING",
            kind,
            "The exact installed 38-kind denominator omits this kind.",
        )
    for kind in sorted(set(candidate_kinds) - expected_kinds):
        add(
            "PACKAGE_CONTRACT_MATRIX_KIND_UNEXPECTED",
            kind,
            "A matrix row is outside the installed 38-kind denominator.",
        )

    for field, value in (
        (
            "repository_admission_obligation_denominator",
            MATRIX_REPOSITORY_ADMISSION_DENOMINATOR,
        ),
        ("kind_denominator", MATRIX_KIND_DENOMINATOR),
        (
            "base_core_route_denominator",
            MATRIX_BASE_CORE_ROUTE_DENOMINATOR,
        ),
        (
            "package_added_route_denominator",
            MATRIX_PACKAGE_ADDED_ROUTE_DENOMINATOR,
        ),
        (
            "namespace_admission_obligation_denominator",
            MATRIX_ADMISSION_OBLIGATION_DENOMINATOR,
        ),
        ("profile_obligation_denominator", MATRIX_PROFILE_OBLIGATION_DENOMINATOR),
        ("family_obligation_denominator", MATRIX_FAMILY_OBLIGATION_DENOMINATOR),
        ("defined_obligation_denominator", MATRIX_DEFINED_OBLIGATION_DENOMINATOR),
        ("route_denominator", MATRIX_ROUTE_DENOMINATOR),
        ("catalog_route_denominator", MATRIX_ROUTE_DENOMINATOR),
    ):
        if selected.get(field) != value:
            add(
                "PACKAGE_CONTRACT_MATRIX_DENOMINATOR_DIFFERS",
                None,
                field + " must equal " + str(value) + ".",
            )
    for field in (
        "catalog_duplicate_coordinates",
        "profile_routes_missing_catalog",
        "unprofiled_catalog_routes",
    ):
        if selected.get(field) != []:
            add(
                "PACKAGE_CONTRACT_MATRIX_CATALOG_PROFILE_DIFFERS",
                None,
                field + " must be empty; catalog presence cannot widen profiles.",
            )

    repository_rows = selected.get("repository_admission_obligations")
    repository_by_coordinate = {
        item.get("coordinate"): item
        for item in repository_rows if type(item) is dict
    } if type(repository_rows) is list else {}
    expected_repository_rows = {
        item["coordinate"]: item
        for item in expected["repository_admission_obligations"]
    }
    expected_repository_coordinates = set(
        _EXPECTED_REPOSITORY_ADMISSION_COORDINATES
    )
    for coordinate in sorted(
        expected_repository_coordinates - set(repository_by_coordinate)
    ):
        expected_route = expected_repository_rows.get(coordinate, {})
        add(
            "PACKAGE_CONTRACT_MATRIX_REPOSITORY_ADMISSION_MISSING",
            None,
            "A repository-global Tier-0 obligation is absent from the matrix.",
            obligation_id=expected_route.get("obligation_id"),
            coordinate=coordinate,
        )
    for coordinate in sorted(
        set(repository_by_coordinate) - expected_repository_coordinates
    ):
        route = repository_by_coordinate[coordinate]
        add(
            "PACKAGE_CONTRACT_MATRIX_REPOSITORY_ADMISSION_UNEXPECTED",
            None,
            "A repository-admission row is outside the exact nine-gate denominator.",
            obligation_id=route.get("obligation_id"),
            coordinate=coordinate,
        )
    for coordinate in sorted(
        expected_repository_coordinates & set(repository_by_coordinate)
    ):
        route = repository_by_coordinate[coordinate]
        expected_route = expected_repository_rows.get(coordinate)
        obligation_id = route.get("obligation_id")
        if type(route.get("reason")) is not str or not route["reason"].strip():
            add(
                "PACKAGE_CONTRACT_MATRIX_REASON_MISSING",
                None,
                "Every repository-admission obligation requires its exact reason.",
                obligation_id=obligation_id,
                coordinate=coordinate,
            )
        if not _callable_mechanism(route.get("checking_mechanism")):
            add(
                "PACKAGE_CONTRACT_MATRIX_MECHANISM_MISSING",
                None,
                "The repository-admission obligation lacks its executable mechanism.",
                obligation_id=obligation_id,
                coordinate=coordinate,
            )
        applicability = route.get("applicability")
        if (
            type(applicability) is not dict
            or applicability.get("mode") != "NECESSARY"
            or type(applicability.get("reason")) is not str
            or not applicability["reason"].strip()
            or applicability.get("unknown_condition") != "NOT_EXEMPT"
        ):
            add(
                "PACKAGE_CONTRACT_MATRIX_APPLICABILITY_INVALID",
                None,
                "Repository admission is necessary; UNKNOWN is not exemption.",
                obligation_id=obligation_id,
                coordinate=coordinate,
            )
        if route != expected_route:
            add(
                "PACKAGE_CONTRACT_MATRIX_REPOSITORY_ADMISSION_DIFFERS",
                None,
                "The repository-admission reason, evidence, mechanism or boundary differs.",
                obligation_id=obligation_id,
                coordinate=coordinate,
            )

    selected_blockers = {
        item.get("obligation_id"): item
        for item in selected.get("semantic_mapping_blockers", [])
        if type(item) is dict
    } if type(selected.get("semantic_mapping_blockers")) is list else {}
    expected_blockers = {
        item["obligation_id"]: item
        for item in expected["semantic_mapping_blockers"]
    }
    for obligation_id in sorted(set(expected_blockers) - set(selected_blockers)):
        add(
            "PACKAGE_CONTRACT_MATRIX_SEMANTIC_MAPPING_MISSING",
            obligation_id.split("-", 1)[0],
            "The explicit source-audited UNKNOWN semantic-mapping blocker is absent.",
            obligation_id=obligation_id,
        )
    for obligation_id in sorted(set(selected_blockers) - set(expected_blockers)):
        add(
            "PACKAGE_CONTRACT_MATRIX_SEMANTIC_MAPPING_UNEXPECTED",
            obligation_id.split("-", 1)[0],
            "A semantic-mapping blocker is outside the current source audit.",
            obligation_id=obligation_id,
        )
    for obligation_id in sorted(set(expected_blockers) & set(selected_blockers)):
        if selected_blockers[obligation_id] != expected_blockers[obligation_id]:
            add(
                "PACKAGE_CONTRACT_MATRIX_SEMANTIC_MAPPING_DIFFERS",
                obligation_id.split("-", 1)[0],
                "The source-audited UNKNOWN semantic-mapping reason differs.",
                obligation_id=obligation_id,
            )
    if selected.get("semantic_mapping_status") != expected[
        "semantic_mapping_status"
    ]:
        add(
            "PACKAGE_CONTRACT_MATRIX_SEMANTIC_MAPPING_STATUS_DIFFERS",
            None,
            "Known semantic-mapping UNKNOWNs cannot be promoted or omitted.",
        )
    selected_applicability_blockers = {
        item.get("obligation_id"): item
        for item in selected.get("package_instance_applicability_blockers", [])
        if type(item) is dict
    } if type(selected.get("package_instance_applicability_blockers")) is list else {}
    expected_applicability_blockers = {
        item["obligation_id"]: item
        for item in expected["package_instance_applicability_blockers"]
    }
    if (
        selected.get("package_instance_applicability_status")
            != expected["package_instance_applicability_status"]
        or selected.get("package_instance_applicability_assessments")
            != expected["package_instance_applicability_assessments"]
        or selected_applicability_blockers != expected_applicability_blockers
    ):
        add(
            "PACKAGE_CONTRACT_MATRIX_INSTANCE_APPLICABILITY_DIFFERS",
            None,
            "Current-package carrier UNKNOWNs cannot be omitted, promoted, or recast as semantic-mapping gaps.",
        )
    if (
        selected.get("production_preflight_status")
            != expected["production_preflight_status"]
        or selected.get("production_preflight_blockers")
            != expected["production_preflight_blockers"]
        or selected.get("production_preflight_route_summary")
            != expected["production_preflight_route_summary"]
    ):
        add(
            "PACKAGE_CONTRACT_MATRIX_PRODUCTION_PREFLIGHT_DIFFERS",
            None,
            "The source-audited original-kind production binding, counts, or blocker state differs.",
        )

    expected_rows = expected["kinds"]
    all_obligations: set[str] = set()
    all_route_obligations: set[str] = set()
    all_coordinates: set[str] = set()
    for kind in sorted(expected_kinds & set(candidate_kinds)):
        row = candidate_kinds[kind]
        expected_row = expected_rows.get(kind)
        if type(row) is not dict or expected_row is None:
            add(
                "PACKAGE_CONTRACT_MATRIX_KIND_INVALID",
                kind,
                "The kind row is not a current installed contract row.",
            )
            continue
        if type(row.get("reason")) is not str or not row["reason"].strip():
            add(
                "PACKAGE_CONTRACT_MATRIX_REASON_MISSING",
                kind,
                "Every kind requires its installed necessity reason.",
            )
        if row.get("accumulated_roles") != expected_row["accumulated_roles"]:
            add(
                "PACKAGE_CONTRACT_MATRIX_ACCUMULATED_ROLE_DIFFERS",
                kind,
                "The additive base-role chain differs; a specialization cannot erase its ancestors.",
            )
        for field in ("kind", "extends", "source_evidence_routes"):
            if row.get(field) != expected_row[field]:
                add(
                    "PACKAGE_CONTRACT_MATRIX_KIND_CONTRACT_DIFFERS",
                    kind,
                    field + " differs from the current namespace/profile contract.",
                )

        namespace_obligations = row.get("namespace_admission_obligations")
        namespace_by_id = {
            item.get("obligation_id"): item
            for item in namespace_obligations if type(item) is dict
        } if type(namespace_obligations) is list else {}
        expected_namespace = {
            item["obligation_id"]: item
            for item in expected_row["namespace_admission_obligations"]
        }
        for obligation_id in sorted(set(expected_namespace) - set(namespace_by_id)):
            add(
                "PACKAGE_CONTRACT_MATRIX_NAMESPACE_OBLIGATION_MISSING",
                kind,
                "A namespace-admission obligation is absent from its kind row.",
                obligation_id=obligation_id,
            )
        for obligation_id in sorted(set(namespace_by_id) - set(expected_namespace)):
            add(
                "PACKAGE_CONTRACT_MATRIX_NAMESPACE_OBLIGATION_UNEXPECTED",
                kind,
                "A namespace-admission obligation is outside the kind contract.",
                obligation_id=obligation_id,
            )
        for obligation_id in sorted(set(expected_namespace) & set(namespace_by_id)):
            if namespace_by_id[obligation_id] != expected_namespace[obligation_id]:
                add(
                    "PACKAGE_CONTRACT_MATRIX_NAMESPACE_OBLIGATION_DIFFERS",
                    kind,
                    "The namespace obligation reason, applicability, or evidence differs.",
                    obligation_id=obligation_id,
                )

        obligations = row.get("profile_obligations")
        obligation_rows = {
            item.get("obligation_id"): item
            for item in obligations if type(item) is dict
        } if type(obligations) is list else {}
        expected_obligations = {
            item["obligation_id"]: item
            for item in expected_row["profile_obligations"]
        }
        for obligation_id in sorted(set(expected_obligations) - set(obligation_rows)):
            add(
                "PACKAGE_CONTRACT_MATRIX_OBLIGATION_MISSING",
                kind,
                "A defined Tier-0/profile obligation is absent from the matrix.",
                obligation_id=obligation_id,
            )
        for obligation_id in sorted(set(obligation_rows) - set(expected_obligations)):
            add(
                "PACKAGE_CONTRACT_MATRIX_OBLIGATION_UNEXPECTED",
                kind,
                "An obligation is not present in the installed contract/profile.",
                obligation_id=obligation_id,
            )
        for obligation_id in sorted(set(expected_obligations) & set(obligation_rows)):
            obligation = obligation_rows[obligation_id]
            all_obligations.add(obligation_id)
            if type(obligation.get("reason")) is not str or not obligation["reason"].strip():
                add(
                    "PACKAGE_CONTRACT_MATRIX_REASON_MISSING",
                    kind,
                    "Every obligation requires its exact reason.",
                    obligation_id=obligation_id,
                )
            if not obligation.get("source_evidence_routes"):
                add(
                    "PACKAGE_CONTRACT_MATRIX_EVIDENCE_ROUTE_MISSING",
                    kind,
                    "The obligation has no exact source-evidence route.",
                    obligation_id=obligation_id,
                )
            applicability = obligation.get("applicability")
            if (
                type(applicability) is not dict
                or applicability.get("mode") not in {"NECESSARY", "CONDITIONAL"}
                or type(applicability.get("reason")) is not str
                or not applicability["reason"].strip()
                or applicability.get("unknown_condition") != "NOT_EXEMPT"
            ):
                add(
                    "PACKAGE_CONTRACT_MATRIX_APPLICABILITY_INVALID",
                    kind,
                    "Obligation applicability must be necessary or conditional-with-reason; UNKNOWN is not exemption.",
                    obligation_id=obligation_id,
                )
            if obligation != expected_obligations[obligation_id]:
                add(
                    "PACKAGE_CONTRACT_MATRIX_OBLIGATION_DIFFERS",
                    kind,
                    "The obligation reason, applicability or mapped route set differs.",
                    obligation_id=obligation_id,
                )

        routes = row.get("routes")
        route_rows = {
            item.get("coordinate"): item
            for item in routes if type(item) is dict
        } if type(routes) is list else {}
        expected_routes = {
            item["coordinate"]: item for item in expected_row["routes"]
        }
        for coordinate in sorted(set(expected_routes) - set(route_rows)):
            expected_route = expected_routes[coordinate]
            add(
                "PACKAGE_CONTRACT_MATRIX_ROUTE_MISSING",
                kind,
                "A profile-required Tier 1-3 route is absent.",
                obligation_id=expected_route["obligation_id"],
                coordinate=coordinate,
            )
        for coordinate in sorted(set(route_rows) - set(expected_routes)):
            route = route_rows[coordinate]
            add(
                "PACKAGE_CONTRACT_MATRIX_SYNTHETIC_ONLY_ROUTE",
                kind,
                "Catalog/schema/specimen-shaped presence is outside the package profile and is not reachable conformance.",
                obligation_id=route.get("obligation_id"),
                coordinate=coordinate,
            )
        for coordinate in sorted(set(expected_routes) & set(route_rows)):
            route = route_rows[coordinate]
            expected_route = expected_routes[coordinate]
            all_coordinates.add(coordinate)
            obligation_id = route.get("obligation_id")
            if type(obligation_id) is str:
                all_route_obligations.add(obligation_id)
            if type(route.get("reason")) is not str or not route["reason"].strip():
                add(
                    "PACKAGE_CONTRACT_MATRIX_REASON_MISSING",
                    kind,
                    "Every numbered route requires its exact reason.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )
            mechanism = route.get("checking_mechanism")
            if not _callable_mechanism(mechanism):
                add(
                    "PACKAGE_CONTRACT_MATRIX_MECHANISM_MISSING",
                    kind,
                    "The route lacks a resolvable executable mechanism or adapter.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )
            applicability = route.get("applicability")
            if (
                type(applicability) is not dict
                or applicability.get("mode") not in {"NECESSARY", "CONDITIONAL"}
                or type(applicability.get("reason")) is not str
                or not applicability["reason"].strip()
                or type(applicability.get("condition")) is not str
                or not applicability["condition"].strip()
                or applicability.get("unknown_condition") != "NOT_EXEMPT"
            ):
                add(
                    "PACKAGE_CONTRACT_MATRIX_APPLICABILITY_INVALID",
                    kind,
                    "Applicability must be necessary or conditional-with-reason; optional and unknown exemption are forbidden.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )
            if route.get("native_specimen_is_instance_evidence") is not False:
                add(
                    "PACKAGE_CONTRACT_MATRIX_SPECIMEN_BYPASS",
                    kind,
                    "A passing specimen is not package-graph instance evidence.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )
            if (
                route.get("package_instance_execution_status") != "NOT_ASSESSED"
                or route.get("package_graph_reachability")
                    != "REQUIRES_FRESH_INSTANCE"
            ):
                add(
                    "PACKAGE_CONTRACT_MATRIX_INSTANCE_EXECUTION_OVERCLAIMED",
                    kind,
                    "The static matrix cannot report an unexecuted package route as reached or closed.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )
            if route != expected_route:
                add(
                    "PACKAGE_CONTRACT_MATRIX_ROUTE_DIFFERS",
                    kind,
                    "The route differs from its current catalog/profile/mechanism binding.",
                    obligation_id=obligation_id,
                    coordinate=coordinate,
                )

    if len(all_obligations) != MATRIX_PROFILE_OBLIGATION_DENOMINATOR:
        add(
            "PACKAGE_CONTRACT_MATRIX_OBLIGATION_DENOMINATOR_DIFFERS",
            None,
            "The exact 62 profile-obligation identifiers are not unique and complete.",
        )
    if len(all_coordinates) != MATRIX_ROUTE_DENOMINATOR:
        add(
            "PACKAGE_CONTRACT_MATRIX_ROUTE_DENOMINATOR_DIFFERS",
            None,
            "The exact 293 Tier 1-3 coordinates are not unique and complete.",
        )
    if len(all_route_obligations) != MATRIX_ROUTE_DENOMINATOR:
        add(
            "PACKAGE_CONTRACT_MATRIX_ROUTE_OBLIGATION_DENOMINATOR_DIFFERS",
            None,
            "The exact 293 numbered route-obligation identifiers are not unique and complete.",
        )
    repository_obligation_ids = {
        row.get("obligation_id") for row in repository_by_coordinate.values()
        if type(row.get("obligation_id")) is str
    }
    if len(repository_obligation_ids | all_obligations | all_route_obligations) \
            != MATRIX_DEFINED_OBLIGATION_DENOMINATOR:
        add(
            "PACKAGE_CONTRACT_MATRIX_DEFINED_OBLIGATION_DENOMINATOR_DIFFERS",
            None,
            "The exact 364 repository, family, and numbered route obligations are not unique and complete.",
        )
    incoming_digest = selected.get("matrix_digest")
    incoming_body = {
        key: value for key, value in selected.items() if key != "matrix_digest"
    }
    if incoming_digest != value_digest(incoming_body):
        add(
            "PACKAGE_CONTRACT_MATRIX_DIGEST_DIFFERS",
            None,
            "The candidate matrix digest does not bind its current content.",
        )

    result_status = (
        "FAIL"
        if findings else
        "UNKNOWN"
        if (
            selected.get("package_instance_applicability_status") == "UNKNOWN"
            or selected.get("semantic_mapping_status") == "UNKNOWN"
        ) else
        "PASS"
    )
    result = {
        **selected,
        # Structural completeness cannot turn unresolved current-package
        # consequence applicability into PASS. The matrix remains inspectable
        # and finding-free, but package coverage must carry this UNKNOWN into
        # the verifier-bound cumulative denominator.
        "status": result_status,
        "findings": findings,
    }
    result.pop("matrix_digest", None)
    return {**result, "matrix_digest": value_digest(result)}


def contract_coverage_matrix() -> dict[str, Any]:
    """Return the audited installed 38-kind Tier 0-3 matrix."""
    body = _matrix_body()
    candidate = {
        **body,
        "status": (
            "UNKNOWN"
            if (
                body["package_instance_applicability_status"] == "UNKNOWN"
                or body["semantic_mapping_status"] == "UNKNOWN"
            )
            else "PASS"
        ),
        "findings": [],
    }
    candidate["matrix_digest"] = value_digest(candidate)
    return audit_contract_coverage_matrix(candidate, _expected=body)


__all__ = [
    "BASE_CORE_KIND_COUNT",
    "MATRIX_ADMISSION_OBLIGATION_DENOMINATOR",
    "MATRIX_BASE_CORE_ROUTE_DENOMINATOR",
    "MATRIX_DEFINED_OBLIGATION_DENOMINATOR",
    "MATRIX_FAMILY_OBLIGATION_DENOMINATOR",
    "MATRIX_KIND_DENOMINATOR",
    "MATRIX_PROFILE_OBLIGATION_DENOMINATOR",
    "MATRIX_PACKAGE_ADDED_ROUTE_DENOMINATOR",
    "MATRIX_REPOSITORY_ADMISSION_DENOMINATOR",
    "MATRIX_ROUTE_DENOMINATOR",
    "MATRIX_SCHEMA",
    "PACKAGE_ADDED_KIND_COUNT",
    "PACKAGE_KIND_COUNT",
    "SCHEMA",
    "VERSION",
    "accumulated_roles",
    "audit_contract_coverage_matrix",
    "contract_coverage_matrix",
    "document",
    "package_instance_applicability_blocker",
    "profile",
    "reconcile_package_instance_applicability",
    "required_coordinates",
    "semantic_mapping_blocker",
]

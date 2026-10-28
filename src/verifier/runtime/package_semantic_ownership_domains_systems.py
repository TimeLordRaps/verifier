"""Audited semantic ownership for domain, harness, hardware and manifest-write sources of the Verifier Standard (VSTD).

The declarations cover the 51 source paths that were root-admitted without a
specific semantic owner: 7 HARDWARE files, 15 HARNESS and runner files, 4 DATA
files, 4 TOKEN files, 4 TRAIN files, 5 VERIFIER files, 3 manifest-write files,
and 9 generic ``vstd-package-object`` paths.  Primary kinds follow each named
domain where the source supports it.  Consequence and root applicability roles
come from the source's own mechanisms; a file name, a documented concept, or a
generic catch-all label does not establish a role by itself.

Unresolved slots: a role slot the source does not resolve is recorded as a typed
``UnresolvedRecord`` with status UNKNOWN, never as an absent claim and never as
DOES_NOT_APPLY.  The shared model encodes only registered kinds and APPLIES or
DOES_NOT_APPLY root decisions, so unresolved slots live in this module.  Four
generated pages and raster media have no registered primary that the source
establishes, so each is an UNKNOWN primary blocker rather than a DATA or ENV guess.

Path note: the ninth generic asset named as ``hardware/accelerator_registry.json``
is audited at its exact repository-relative path ``src/verifier/hardware/
accelerator_registry.json``.  No file exists at the shorthand path.

Blocked rows: every TRAIN primary requires nonempty ``data``, ``events``,
``bench`` and ``arch`` operands.  A DATA owner exists in this batch, but no exact
DATA operand binding is source-established for a TRAIN layout.  No EVENT, BENCH or
ARCH owner exists in this batch and the sources name no such object.  Those slots
are exported as ``INTEGRATION_BLOCKERS`` instead of invented target identifiers.
The four TRAIN rows therefore fail the typed-layout check until whole-graph
integration binds real targets; this module never supplies placeholder operands.

Root applicability: a retained root kind is recorded only when the owning source
addresses it.  A root kind with no recorded decision is UNKNOWN and is not exempt.
OBJECT is never used as a fallback.  HARNESS is an observation surface, not an
agent or a sandbox, and a launched process is not automatically AGENT or sandbox.

Carried roles: every row with a specialization or an APPLIES root decision carries
an explicit statement that its necessary admission obligations remain OPEN.  A role
label is not conformance.

Claim boundary: these declarations assign source ownership only.  They claim no
mechanism truth, obligation fulfillment, physical measurement or actuation,
hardware calibration, financial asset or FINBOT effect, sandboxing, release,
deployment, or publication authority.  Repository admission is separate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


# Full-file Secure Hash Algorithm 256-bit (SHA-256) of every audited path at the time these rows were written.
# Drift is a failure: a changed source must be re-audited before its row changes.
AUDITED_SOURCE_DIGESTS = {
    "docs/assets/orientation-previews.js": "f0d0662a50d74245f978c8bc7569401b0915e685f2be7ad90e7a557101185c3b",
    "docs/assets/site.css": "d17c9f10270cc36b311ba8c2e7ddca18c99164cadcb278410a3e927e2efd178b",
    "docs/assets/vstd-overview.png": "46b5ed896a02dfe34b919b1fe3ef4f2a8f7ba35a5d685826b180ef9e30a8cf4e",
    "docs/assets/vstd-overview.svg": "79f5cdfd921f6741f26d00ae7206094af3009c8a3fae3a33b03c49f08be07005",
    "docs/guides.html": "58509dd771877b3be0658609545d9d37fadb28a876bd6806fc697e7a45e30f9a",
    "docs/index.html": "fa69e54d728fb530a72acddc5e0c8aaab493790b5a8ce8ca0bffe52ea3418587",
    "docs/reference.html": "15dcb8a70bf64a0cb1f287fb3f5a67c9a53e86749a468e891e7d0a2cff475274",
    "extensions/languages/pyproject.toml": "8aa5869c187d1a658bc17f4531b9b8450cd101c76b3a22d321593550da09d5a8",
    "extensions/languages/src/vstd_languages/__init__.py": "31efb5309fd781ce6ab46177b49dae74de3eda0e4211685a6cc6d885ed1fc895",
    "pyproject.toml": "7e1aaa7020625e2345952066022ad2e8c980867d3fbdd221f6dac3cb6121a69a",
    "src/verifier/core/run.py": "9ba0ed9ff65d637ab18675d2ab8504067151b41031c8b7ea033c0e82c2b850e0",
    "src/verifier/core/run_impact.py": "ce767572ffef1809b89e22dcaa7a68ed0d5c42e0f0b1b3febef46f94162570ed",
    "src/verifier/core/run_inspection.py": "5d5631128e368f550735dc903371afe80566f071e0351b5534654d9637250ee9",
    "src/verifier/core/run_planning.py": "4bdcbdfb42a0f73806493a5d4a9361b2e8106e49503c29dd0419e563e27c5c82",
    "src/verifier/core/run_process_observation.py": "1ad1652672a34b93b51df5c46f21fc1d5404fa092150f62bec8e74ac6577b6dc",
    "src/verifier/core/run_reproduction.py": "12870325ffd7e8844d132e0b98d90ca5f500b828e2177071c38e618877dcedc8",
    "src/verifier/core/run_support.py": "28d56179e18bc9135940dff934951de68e6b743c4bb35f03a5d6cb82a77612cb",
    "src/verifier/core/run_validation.py": "a22723546e86076a4a853e9d742e01bb84a7a7afecd0bde98ad4c8722368878b",
    "src/verifier/domains/contracts/data_checks.py": "0e799306164671ced01e7a81007d712d52e8ecde8f1ecf024fb4181d58023e3e",
    "src/verifier/domains/contracts/data_checks_projection.py": "b49d001f351cb0597acb6f75b8e5a1198a93e4960ffe0eb540bb666293979e09",
    "src/verifier/domains/contracts/data_distribution.py": "664ce5e47f0ced5dd0f88fa72f219cf945df97505ba528a9f8ddee8670e54ebb",
    "src/verifier/domains/contracts/hardware_capacity.py": "0517c7d1862db06f62e5a0a59a9ba0fb69235b2f93801efb9e47b6d818ec69cf",
    "src/verifier/domains/contracts/hardware_inventory.py": "0a36860b57eeeed7e54466160bc2ad66f445d432e540723f15fabc948ad2b5cf",
    "src/verifier/domains/contracts/hardware_inventory_closure.py": "36dd49b1bd448cfc80357482df1a0f2563fad596ce1e6ef9aa733c8248eed7b7",
    "src/verifier/domains/contracts/hardware_measurements.py": "fd7690e4114314c024c5fbe2d9623eb49695e1012ded559d77411ef4237d6c89",
    "src/verifier/domains/contracts/hardware_substrate_observations.py": "06d595480e2ab1385e44548acfa95542e4129f3ac2273ae0342f91606b8c29cd",
    "src/verifier/domains/contracts/hardware_topology.py": "02764573712dfdd78dda56f668cb0bae999429f4c19582cd06f1559048716cd0",
    "src/verifier/domains/contracts/harness_checks.py": "4b27b7ce1cdb8eaaadf237796687801e07d0b678364322e57ce078fa9ebe378d",
    "src/verifier/domains/contracts/harness_gap_boundary.py": "6b966ed54b0316f8ff83bf16cf11eb9688756bab7f770f7cae072a14ad9f00b9",
    "src/verifier/domains/contracts/token_checks.py": "bc3b900da75a2ead7bce66f04287bc9c240138195a04b8c3fd67417fdd1efd77",
    "src/verifier/domains/contracts/token_checks_projection.py": "a5a06112affcdd213b96bf5fd7cd7b13b2061fbcfd26d25043a2b017a13c8fbf",
    "src/verifier/domains/contracts/token_facets.py": "58513db26c05ed38aeb2d0d3399f8ef5ee646394656d19b5b0a599fd38c65c14",
    "src/verifier/domains/contracts/train_accumulation.py": "87f00f22dcc298b9d9f1c724a84eaf1888d46794ee23ccaa4e654d2f78d07609",
    "src/verifier/domains/contracts/train_checks.py": "75f30a47ad776b7d10ea93d4eb41a49983e1dac208f90bce8e6a36b006ca3a8f",
    "src/verifier/domains/contracts/train_data_bridge.py": "2db111f2b4b9b698fdca6c8b1d563e6d62f3840342342fba437ee6686e49a19a",
    "src/verifier/domains/contracts/verifier_composed_security.py": "005143ab62b837b43ed12373b6c76f9d7d5b6238282a3dc4b9bc79d99033ccf9",
    "src/verifier/domains/contracts/verifier_coverage_closure.py": "046666618f9c0278fc1981d265a6a0e55ffba1af1926a2743365afd7f4b43fe9",
    "src/verifier/domains/contracts/verifier_replacement.py": "3eff4c845b5ac6b1b854263c2d95fb00a8a97bd44d7f1b4b2f7580c1eeb9bfb3",
    "src/verifier/domains/data.py": "9c35441dbf74bacfe5434d04e8a2eff01f474c5153e3c70758843687b7ef87fc",
    "src/verifier/domains/hardware.py": "3045c301c8c443ad6f560ce309b7e8765aa3d49dd4b1d5942bfd99c70b5c5ee7",
    "src/verifier/domains/harness.py": "83a9113e509c0664f6600c23ca1ee68eb9b27443438cf40ae77e03c9c66d4a7a",
    "src/verifier/domains/token.py": "b5435e82e844e85eccad28a69f2cee8b3d58bb0dd9d083532f2227b5dae2cdd6",
    "src/verifier/domains/train.py": "ded2f37a286ad16872efa86647ca5e2456b75ea175f4b411bba74d057e5bb4cd",
    "src/verifier/domains/verifier.py": "01f44b3a51e978f26d2c4cb66673aae7be8c3e8306daee328f3e1a9982459759",
    "src/verifier/domains/verifier_bootstrap.py": "7e58b1b72dee61aa3ffada248b6100b51acf58ffba40b09e02e64d7ed304b338",
    "src/verifier/hardware/accelerator_registry.json": "1decf2efa68c465b77ae3f214bda5d02b4e948cba2b0cfb1865464ff4e6de5e1",
    "src/verifier/runtime/language_runners.py": "953f5b3eec93685c97e85d87cbb6d01ff0a800a9be6a329578cf2a6aa3e6be55",
    "src/verifier/runtime/manifest_write_execution.py": "9f92d06f8a8d12d08b60f2bc13fdd2069645e6573212d28bf893df4f82a6142d",
    "src/verifier/runtime/manifest_write_worker.py": "e5edc802a8f7ac792a540281d1111058daefa64aaa9a724f97b5471ee4fd9297",
    "src/verifier/runtime/namespace_cli.py": "70319f32d64fbe25a2a0d49bb46a285d476cd339af632394d2e35325fe0cb7db",
    "src/verifier/runtime/package_harness_applicability.py": "d0555e317f015491b401801e72384ff85b1fc68422c822a2217437f7353b9d5d",
}


@dataclass(frozen=True)
class IntegrationBlocker:
    """One unresolved typed operand slot that whole-graph integration must bind."""

    object_id: str
    operand_role: str
    required_kind: str
    reason: str
    next_action: str


@dataclass(frozen=True)
class UnresolvedRecord:
    """Typed UNKNOWN for one role slot that the owned source does not resolve.

    ``slot`` is ``primary``, ``specialization`` or ``root``; ``candidate`` names the kind
    under review (``None`` for a primary, whose candidate set is empty).  An absent
    claim is not UNKNOWN: only a record here carries the unresolved status.
    """

    object_id: str
    path: str
    slot: str
    candidate: str | None
    reason: str
    next_action: str
    status: str = "UNKNOWN"


_TRAIN_SLOT_REASONS = (
    ("data", "DATA",
     "A DATA owner exists in this batch (vstd-data-retained-records, vstd-data-native-checks, "
     "vstd-data-distribution-certificate, vstd-data-checks-projection), but no exact DATA operand "
     "binding is source-established for this TRAIN layout.",
     "Bind one exact DATA operand in whole-graph integration; this module supplies no DATA target."),
    ("events", "EVENT",
     "The TRAIN layout requires an EVENT operand. No EVENT owner exists in this batch and the sources name no event object.",
     "Name an exact EVENT owner in a later batch, then bind it in whole-graph integration."),
    ("bench", "BENCH",
     "The TRAIN layout requires a BENCH operand. No BENCH owner exists in this batch and the sources name no bench object.",
     "Name an exact BENCH owner in a later batch, then bind it in whole-graph integration."),
    ("arch", "ARCH",
     "The TRAIN layout requires an ARCH operand. No ARCH owner exists in this batch and the sources name no architecture object.",
     "Name an exact ARCH owner in a later batch, then bind it in whole-graph integration."),
)


# Retained-root applicability reasons reused verbatim across rows.
_AGENT_NOT_HARNESS = (
    "HARNESS is the instrumented observation surface, not the actor; this source "
    "records observable channels and does not act as an agent."
)
_VERIFIER_APPLIES_DOMAIN = (
    "evaluate returns a result only after the selected retained checks succeed and raises "
    "Refuted or Unavailable when the evidence contradicts or cannot establish the check. "
    "That executable decision boundary is VERIFIER behavior; the result dictionary is not "
    "a package verdict or whole-object conformance."
)
_VERIFIER_NO_VERDICT_PROJECTION = (
    "The projection returns accepted projections or refusals and emits no PASS, FAIL, "
    "or UNKNOWN verdict."
)
_VERIFIER_APPLIES_CERTIFICATE = (
    "_evaluate returns a MechanismDecision with PASS, FAIL, or UNKNOWN from the "
    "retained replay of this certificate."
)
_ADMISSION_OPEN_CLAUSE = (
    "Necessary admission obligations for this carried role remain OPEN; "
    "the role label is not conformance."
)


_DOMAIN_SYSTEMS_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    # HARDWARE: retained device records and certificates. None is a live MEASUREMENT.
    # TRANSACTION is UNKNOWN for this row; see UNRESOLVED_RECORDS.
    ownership_spec(
        "vstd-hardware-retained-device-records",
        "HARDWARE",
        ("src/verifier/domains/hardware.py",),
        "Finite retained device-record evaluator for inventory, topology, allocation and measurement checks.",
        "evaluate runs a containment-acyclicity sweep, a half-open allocation occupancy sweep bounded by declared capacities, and quantity and timestamp checks over declared records; no device is accessed.",
        "Declared records and capacities establish neither physical attestation, live availability nor credit authority. The module returns a result dictionary and raises on violations.",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_DOMAIN),
        ),
    ),
    ownership_spec(
        "vstd-hardware-capacity-reservation",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_capacity.py",),
        "Versioned retained-capacity reservation certificate over selected HARDWARE allocations.",
        "The mechanism replays selected retained allocations against declared device capacities and requires the occupancy sweep to close, so reserved quantities stay within declared limits.",
        "Replay over retained reservations establishes no physical device, live availability or credit authority. An empty reservation set is checked only as an exact commitment with the device inventory.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-hardware-inventory-certificate",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_inventory.py",),
        "Versioned retained HARDWARE inventory certificate over declared device records.",
        "The mechanism replays the selected retained inventory and its device capacities against the commitment bound by the subject record and the composed namespace collection.",
        "The inventory declares devices; it does not attest that the devices exist, are available, or are reserved.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-hardware-inventory-closure",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_inventory_closure.py",),
        "Current HARDWARE inventory closure over declared scope members and independent producer labels.",
        "The mechanism replays scope membership and entry coverage against the retained inventory, and counts a producer label as independent only when it differs from the inventory author label.",
        "Independence means only a distinct retained label. The check proves no physical coverage, device identity, isolation or producer independence.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-hardware-measurement-envelope",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_measurements.py",),
        "Versioned retained HARDWARE measurement-envelope certificate over declared quantities and instants.",
        "The mechanism checks retained measurement records against declared capacities and one declared clock. This is a bounded declaration check, not a sensor reading.",
        "MEASUREMENT and SENSOR roles are not assigned: the source validates retained declarations and performs no device, calibration or live acquisition, so no physical quantity is measured here.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-hardware-substrate-observation",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_substrate_observations.py",),
        "Retained qualified substrate-observation certificate with quote and measured-boot event-log replay.",
        "The mechanism decodes retained quote values and measured-boot event logs, replays platform register extension digests, and checks freshness against declared instants.",
        "The replay authenticates no device, observer, signature, quote or clock. A declaration without a qualified record stays UNKNOWN. SENSOR is not assigned because no live observation occurs.",
        "PROTOCOL",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-hardware-containment-topology",
        "HARDWARE",
        ("src/verifier/domains/contracts/hardware_topology.py",),
        "Versioned retained HARDWARE containment-topology certificate.",
        "The mechanism sweeps declared containment edges with a Kahn-style acyclicity check over the selected retained devices, so containment cannot be circular.",
        "Acyclicity applies to containment only. The certificate attests neither physical wiring, communication links, availability, nor credit authority.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    # HARNESS: observation surface, native checks and gap boundary. HARNESS is not AGENT.
    ownership_spec(
        "vstd-harness-observation-surface",
        "HARNESS",
        ("src/verifier/domains/harness.py",),
        "Harness observation-surface evaluator for declared surfaces, effect surfaces and transcripts.",
        "The module names what a deployment could observe, which effect surface it declares, and which transcript positions were retained, so undeclared channels remain visible as named gaps.",
        "The surface records observability only. It does not sandbox the observed process and establishes neither execution nor isolation nor completeness of unnamed channels.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision("AGENT", "DOES_NOT_APPLY", _AGENT_NOT_HARNESS),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_DOMAIN),
        ),
    ),
    ownership_spec(
        "vstd-harness-native-checks",
        "HARNESS",
        ("src/verifier/domains/contracts/harness_checks.py",),
        "Native agent-harness check certificates over retained observation evidence.",
        "The mechanism replays the selected native HARNESS check over retained observations and binds the certificate to a registered proposition.",
        "Retained observations establish neither live execution nor physical isolation. HARNESS is an observation surface, not the agent or a sandbox.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("AGENT", "DOES_NOT_APPLY", _AGENT_NOT_HARNESS),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-harness-gap-boundary",
        "HARNESS",
        ("src/verifier/domains/contracts/harness_gap_boundary.py",),
        "Named HARNESS gap boundary bounded by a retained instrument-placement certificate.",
        "The mechanism checks that declared unobserved gaps lie within the retained placement window on one session clock, so unobserved intervals are named rather than absent.",
        "Declared gaps and placements are retained declarations. They do not establish that unnamed intervals were observed or that instruments were placed as stated.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("AGENT", "DOES_NOT_APPLY", _AGENT_NOT_HARNESS),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    # Generic-run core: launches, observes, validates, and describes runs.
    ownership_spec(
        "vstd-run-harness-capture",
        "HARNESS",
        ("src/verifier/core/run.py",),
        "Generic computational run capture that launches owned process trees and records typed receipts.",
        "The module starts the manifest-declared command under an owned process tree, enforces bounded output capture and a timeout, and records typed endings and provenance links. The PROTOCOL role rests on linkage across several retained artifacts (ArtifactRef, ExternalEvaluationEvidence, ProvenanceLinkage), not on single-artifact replay.",
        "Launching and capture are process effects. A recorded run is not a sandbox, not an agent action, and not a verdict on the computed result.",
        "ACTUATOR",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT",
                "APPLIES",
                "Agency is explicit here: the substrate-immunity invariant names an agent or command executed under a VSTD harness as a subject it must keep from mutating verifier-standard. The wrapper itself selects no goal or next action.",
            ),
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The module records typed endings and claims; no PASS, FAIL, or UNKNOWN verifier verdict is formed here, and receipt validation lives in run_validation.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-run-process-observation",
        "PROTOCOL",
        ("src/verifier/core/run_process_observation.py",),
        "Bounded parent-side process observation record for launched generic runs.",
        "The parent observes its own subprocess launch, retained stream bytes and exit status, and keeps launch attempted, process started and streams complete as separate facts.",
        "The record is intentionally narrower than a whole HARNESS observation. It binds only the bytes and fields the parent observed and is not actor authentication or a process sandbox.",
        "MEASUREMENT",
        root_role_decisions=(
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "The module states that this record is intentionally narrower than a whole HARNESS observation.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-run-validation-protocol",
        "PROTOCOL",
        ("src/verifier/core/run_validation.py",),
        "Fail-closed generic-run receipt structure and canonical-digest validator.",
        "Receipts are rebuilt from their stable payload, checked for missing and unexpected fields, and compared against canonical digests before any consumer treats them as a run record.",
        "Structural and digest agreement establishes receipt shape and byte identity only. It does not confirm the computation, the observed process truth, or environment reproducibility.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "validate_run_receipt returns 0 only after exact receipt-shape and canonical-digest checks, and returns 1 for every rejected receipt path. This bounded validator does not verify the recorded computation or environment.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-run-impact-analysis",
        "POLICY",
        ("src/verifier/core/run_impact.py",),
        "Recorded-ancestry impact analysis over generic-run receipts.",
        "Revocation impact is derived by walking recorded artifact ancestry in validated receipts.",
        "The analysis reports recorded ancestry only. It does not establish unrecorded dependencies, revocation authority, or downstream effects.",
    ),
    ownership_spec(
        "vstd-run-inspection-view",
        "PROTOCOL",
        ("src/verifier/core/run_inspection.py",),
        "Human-readable rendering of structurally valid generic-run receipts.",
        "Inspection renders only receipts that pass structural validation, giving reviewers a stable text view of the recorded fields.",
        "The rendering presents recorded fields. It adds no verification verdict and attests no computation.",
    ),
    ownership_spec(
        "vstd-run-planning-protocol",
        "PROTOCOL",
        ("src/verifier/core/run_planning.py",),
        "Side-effect-free generic-run manifest loading and execution-plan description.",
        "The module parses a manifest and validates its command before describing a run plan, and no process is launched.",
        "The plan describes intended execution only. It does not start, time, or observe the command.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-run-reproduction-protocol",
        "PROTOCOL",
        ("src/verifier/core/run_reproduction.py",),
        "Opt-in rerun and side-effect-free artifact-rehash reproduction assessment.",
        "An opt-in path reruns the planned command, and an always-available path rehashes recorded artifacts to compare them with receipt digests.",
        "Rerun equality is evidence about one environment and one execution. Reproduction assessment does not establish determinism or cross-platform reproducibility.",
        "ACTUATOR",
    ),
    ownership_spec(
        "vstd-run-support-coordinates",
        "POLICY",
        ("src/verifier/core/run_support.py",),
        "Shared generic-run profile coordinates, error types and determinism declaration.",
        "Schema versions, the receipt kind discriminator, the error type, the outcome enumeration and the determinism declaration are defined once and shared by the generic-run modules.",
        "Constants and declarations are coordinates. They establish no run outcome, environment binding, or determinism property.",
    ),
    # Language runners and adapters.
    ownership_spec(
        "vstd-language-runner-selection",
        "HARNESS",
        ("src/verifier/runtime/language_runners.py",),
        "Language-neutral native-runner selection, extension wire protocol and process capture.",
        "The runner selects a language adapter, resolves its host executable, launches the subject entry under bounded capture, and classifies exit status and extension blockers.",
        "The built-in runner is a trusted-local process runner, not a security sandbox. Object isolation requires a separately selected backend, and no adapter or installed extension establishes isolation or corrigibility.",
        "ACTUATOR",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT",
                "APPLIES",
                "Agency is explicit here: the profile table maps AGENT to the agent-open-ended profile, and sandbox_requirements gives that profile NOT_ASSUMED_OPEN_ENDED corrigibility with required controls. The runner is a trusted-local process runner, not a sandbox.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The runner emits PASS, FAIL, and UNKNOWN outcomes, including UNKNOWN for reserved worker exit codes and for drift, and it never rewrites the original receipt.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-language-runner-adapters",
        "PROTOCOL",
        ("extensions/languages/src/vstd_languages/__init__.py",),
        "Native-language adapter command table and worker command builder.",
        "The module maps each supported language to a fixed toolchain command, and refuses a non-admitted language such as Classic Visual Basic before any lookup or process.",
        "Command construction establishes neither toolchain identity, package correctness, nor verification. No obligation is discharged, and no shell, package installation, or build script is used.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The module states that no verification obligation is discharged; it returns command descriptions for the host runner.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-language-runner-extension-package",
        "ENV",
        ("extensions/languages/pyproject.toml",),
        "Zero-dependency native-language adapter package declaration and runner entry points.",
        "The distribution declares an empty runtime dependency list and maps each runner name to the adapter command entry point.",
        "The declaration establishes packaging metadata only. Installation does not establish that a toolchain exists, works, or is authorized to run.",
    ),
    ownership_spec(
        "vstd-harness-applicability-denominator",
        "POLICY",
        ("src/verifier/runtime/package_harness_applicability.py",),
        "Verifier-self static HARNESS launch-syntax applicability denominator.",
        "The mechanism parses Verifier's own Python source with abstract syntax tree (AST) analysis, locates the declared direct launch syntax and its embedded worker, and records whether that syntax still matches the declared bytes.",
        "A passing assessment shows only that declared launch syntax is present. It does not establish reachability, argument values, child behaviour, external effects, sandboxing, or HARNESS conformance, and it never imports subject modules or starts a process.",
        root_role_decisions=(
            root_role_decision(
                "HARNESS",
                "APPLIES",
                "The frozen profile is the bounded HARNESS launch denominator for Verifier's own repository layout and is not a generic requirement for third-party packages.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The denominator emits PASS and UNKNOWN dispositions for launch-site drift and discovery issues.",
            ),
        ),
    ),
    # DATA: retained dataset integrity, lineage and distribution.
    ownership_spec(
        "vstd-data-retained-records",
        "DATA",
        ("src/verifier/domains/data.py",),
        "Dataset integrity, lineage and statistics evaluator over retained records.",
        "The module checks retained dataset records for inventory integrity, class fractions, and entropy under a selected tolerance, which needs explicit retained-record mechanisms.",
        "Retained statistics establish no external ancestry, rights, origin, or population representativeness.",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_DOMAIN),
        ),
    ),
    ownership_spec(
        "vstd-data-native-checks",
        "DATA",
        ("src/verifier/domains/contracts/data_checks.py",),
        "Current DATA native check certificates over retained computational records.",
        "The mechanism replays selected native DATA checks over retained computational records and binds each certificate to a registered proposition.",
        "Retained computational records do not establish external origin, rights, or live data provenance.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-data-checks-projection",
        "DATA",
        ("src/verifier/domains/contracts/data_checks_projection.py",),
        "One-way reconciliation table for five native DATA check registrations.",
        "A fixed table narrows exact structured registrations to proposition text, so each mapped DATA check has one reviewed projection.",
        "The projection grants no reverse equivalence, digest alias, evidence, authority, package, mechanism, profile, completeness, or release credit.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "DOES_NOT_APPLY", _VERIFIER_NO_VERDICT_PROJECTION),
        ),
    ),
    ownership_spec(
        "vstd-data-distribution-certificate",
        "DATA",
        ("src/verifier/domains/contracts/data_distribution.py",),
        "Versioned retained DATA distribution certificate.",
        "The mechanism recomputes class proportions and entropy over the selected retained observations under a declared tolerance.",
        "Retained observations establish no population representativeness, external source, or collection authority.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    # TOKEN: zero-identity capability token replay. Not ASSET or FINBOT.
    ownership_spec(
        "vstd-token-holding-replay",
        "TOKEN",
        ("src/verifier/domains/token.py",),
        "Zero-identity token holding replay over retained signatures, leases, tenure and closure records.",
        "The module replays signed token holdings, lease shapes, tenure folds and closure records against an admitted issuing key and a declared clock, identifying the issuer without naming an actor.",
        "A verified signature shows which admitted key issued the token. It does not show that any named resource is authorized, that a status is current, or that a financial asset or FINBOT effect exists.",
        "PROTOCOL",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "ACTOR",
                "DOES_NOT_APPLY",
                "The module describes a zero-identity zero-knowledge token, so the token itself binds no actor identity.",
            ),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_DOMAIN),
        ),
    ),
    ownership_spec(
        "vstd-token-native-checks",
        "TOKEN",
        ("src/verifier/domains/contracts/token_checks.py",),
        "Proposed current capability-token replay certificates.",
        "The mechanism replays native token mechanics under narrow mappings of retained legacy predicates, so each certificate states the predicate it checked.",
        "The certificates are never authority grants. Signatures, physical validation and full qualification are not established, and importing the module performs no registration.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-token-checks-projection",
        "TOKEN",
        ("src/verifier/domains/contracts/token_checks_projection.py",),
        "Fixed one-way projections for three reviewed TOKEN registrations.",
        "Three reviewed native and route registrations map one way to exact proposition text, so each TOKEN projection has a fixed source binding.",
        "The projections establish no reverse equivalence, no evidence for the source, and no mechanism or authority for the TOKEN object.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "DOES_NOT_APPLY", _VERIFIER_NO_VERDICT_PROJECTION),
        ),
    ),
    ownership_spec(
        "vstd-token-facet-projection",
        "TOKEN",
        ("src/verifier/domains/contracts/token_facets.py",),
        "Scoped capability-token semantic projections from retained native contracts.",
        "The module projects selected native contract properties onto token facets, so each facet names the retained property it reflects.",
        "Commitment anchors do not establish retained contents or application completeness, and the projections grant no authority.",
        root_role_decisions=(
            root_role_decision("VERIFIER", "DOES_NOT_APPLY", _VERIFIER_NO_VERDICT_PROJECTION),
        ),
    ),
    # TRAIN: primaries are typed TRAIN objects whose operand layout is blocked (see INTEGRATION_BLOCKERS).
    ownership_spec(
        "vstd-train-run-specification",
        "TRAIN",
        ("src/verifier/domains/train.py",),
        "Training run specification evaluator for configuration, checkpoint, training, update and lineage replay.",
        "The module replays selected checkpoint trajectories, optimizer updates and batch lineage against committed digests under a declared numerical tolerance.",
        "Replay establishes no live training execution, hardware observation, or physical isolation. The module returns result dictionaries and raises on mismatch.",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_DOMAIN),
        ),
    ),
    ownership_spec(
        "vstd-train-accumulation-certificate",
        "TRAIN",
        ("src/verifier/domains/contracts/train_accumulation.py",),
        "Current TRAIN accumulation certificate that reduces a retained sequence two ways under a bounded effect.",
        "The mechanism compares a retained sequence reduced under two ordered binary64 procedures, so the bounded effect of accumulation order is recorded rather than assumed.",
        "The executing hardware is never observed. Values are dimensionless binary64 results under the selected contract, and no physical training or device claim follows.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("HARDWARE", "DOES_NOT_APPLY", "The source states that the executing hardware is never observed."),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-train-native-checks",
        "TRAIN",
        ("src/verifier/domains/contracts/train_checks.py",),
        "Current TRAIN native check certificates over retained training observations.",
        "The mechanism replays selected native TRAIN checks, pinning each check's binary64 arithmetic ordering and interpreter identity to the selected contract units.",
        "Retained observations do not establish live execution or physical isolation. The runtime identity is a fingerprint of the interpreter, not a sandbox.",
        "POLICY",
        root_role_decisions=(
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    ownership_spec(
        "vstd-train-data-bridge",
        "TRAIN",
        ("src/verifier/domains/contracts/train_data_bridge.py",),
        "Retained TRAIN batch-view to DATA shard-view bridge certificate.",
        "The mechanism binds a retained training batch view to a DATA shard view, so each training batch is checked against the dataset representation it cites.",
        "The bridge checks selected retained representations only. It establishes neither historical consumption, dataset rights, nor the training run's actual data access.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "DATA",
                "APPLIES",
                "The bridge's counterpart is the DATA shard view, which the mechanism checks as a selected retained representation.",
            ),
            root_role_decision("VERIFIER", "APPLIES", _VERIFIER_APPLIES_CERTIFICATE),
        ),
    ),
    # VERIFIER: engine, bootstrap, security composition, coverage closure, replacement replay.
    ownership_spec(
        "vstd-verifier-engine-specification",
        "VERIFIER",
        ("src/verifier/domains/verifier.py",),
        "Computational verifier engine specification for content-bound inventory, retained proof instances and local kernel replay.",
        "The engine checks content-bound inventories, retained proof instances and bounded local kernel replay, which are verifier-integrity mechanisms rather than subject execution.",
        "Checks distinguish producer execution, class-wide soundness, operating-system resource enforcement and bootstrap authority, none of which caller declarations establish. No submitted code is executed.",
    ),
    ownership_spec(
        "vstd-verifier-bootstrap-evidence",
        "VERIFIER",
        ("src/verifier/domains/verifier_bootstrap.py",),
        "Finite independently computed bootstrap evidence for one signed conjunctive normal form (CNF) request.",
        "An externally configured key admits one exact finite request, and exhaustive truth-table evaluation checks its formula independently of the native proof kernel.",
        "Admission and truth-table agreement establish neither general verifier soundness, organizational independence, nor external factual truth. Signatures bind bytes, not authority.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-verifier-composed-security",
        "VERIFIER",
        ("src/verifier/domains/contracts/verifier_composed_security.py",),
        "Ten-tier signed retained-subject association composed from VERIFIER-9.1 and RECEIPT-9.2 children.",
        "The contract composes a native association child with a receipt issuer-key replay child without renaming either, so one signed subject association is checked against both.",
        "A finite PASS is not whole security admission, authority, execution, key custody, human acceptance, or production admission.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The contract composes a RECEIPT-9.2 issuer-key replay child without renaming it.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-verifier-coverage-closure",
        "VERIFIER",
        ("src/verifier/domains/contracts/verifier_coverage_closure.py",),
        "Coverage closure over one declared finite VERIFIER claim class.",
        "The contract enumerates a retained DAG-profile claim class and replays every member and declared counterexample boundary, so closure is over the declared class only.",
        "Completeness beyond the declared finite class remains NOT_ESTABLISHED, and acyclicity of the profile is not a completeness proof.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-verifier-replacement-replay",
        "VERIFIER",
        ("src/verifier/domains/contracts/verifier_replacement.py",),
        "Portable finite ten-tier VERIFIER replacement replay over retained observations.",
        "The contract replays retained admission, attestation, observer and execution observations for a finite replacement claim and never invokes callbacks.",
        "Explicit consumer admission selects keys, source closure, and coverage. Signatures alone supply no admission, and a finite PASS supplies neither whole corrigibility nor production acceptance.",
        "PROTOCOL",
        "POLICY",
    ),
    # Manifest-write: transaction checks, fixed worker, and command-line interface (CLI) publish paths.
    ownership_spec(
        "vstd-manifest-write-execution-checks",
        "TRANSACTION",
        ("src/verifier/runtime/manifest_write_execution.py",),
        "Source-bound manifest publication check coordinates for TRANSACTION observations.",
        "The module applies exact content expectations to observed exclusive-create, partial-write, retry and concurrent-publication outcomes for registered TRANSACTION coordinates, and forwards bound routes to the executor.",
        "The checks do not prove power-loss durability, protection from arbitrary writers, path confinement, application authority, or complete TRANSACTION-kind conformance.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "HARNESS",
                "APPLIES",
                "The execution path forwards bound routes to package_execution, which runs the observed child process through subprocess.run.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "check_observations returns a Boolean only after applying exact coordinate-specific expectations to the retained execution observations. This auxiliary check is not a package route verdict or TRANSACTION conformance.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-manifest-write-worker",
        "HARNESS",
        ("src/verifier/runtime/manifest_write_worker.py",),
        "Fixed private manifest publication experiment worker.",
        "The worker reads one closed request, runs the installed publication handlers and fixed fixtures in a temporary directory with filesystem faults, and emits observations for independent checking.",
        "The temporary directory and the fixture Git invocation are process effects, not a sandbox or a hardened environment. The worker accepts no caller command, subject module, or operator file.",
        "TRANSACTION",
        "ACTUATOR",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT",
                "DOES_NOT_APPLY",
                "The worker accepts no caller command and runs only installed handlers and fixed fixtures, so it selects no goal.",
            ),
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The worker emits observation JavaScript Object Notation (JSON) only; its verdicts are formed by manifest_write_execution.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-manifest-write-cli",
        "TRANSACTION",
        ("src/verifier/runtime/namespace_cli.py",),
        "Human-facing namespace template and format entry points with exclusive draft creation and verified replacement.",
        "Writing a draft is exclusive-create, and the formatter replaces a file only after verifying that its original bytes are unchanged, so each write is a bounded compare-and-publish transaction.",
        "JSON mode is a read-only preview. The CLI establishes no manifest validity, admission result, or application authority beyond the bytes it writes.",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The CLI emits previews or writes drafts and forms no PASS, FAIL, or UNKNOWN verdict.",
            ),
        ),
    ),
    # Generic package objects, split by their functional kind.  Documentation pages and
    # raster media are UNKNOWN primaries (see UNRESOLVED_RECORDS), not rows here.
    ownership_spec(
        "vstd-package-orientation-preview-script",
        "ENV",
        ("docs/assets/orientation-previews.js",),
        "Browser presentation script for repository orientation previews.",
        "The script attaches a hidden preview element to repository links and shows it during link interaction, which is a presentation-environment behaviour with no computation of claims.",
        "The script makes no network, storage, or claim-bearing request and establishes no evidence about the linked repository content.",
    ),
    ownership_spec(
        "vstd-package-site-stylesheet",
        "ENV",
        ("docs/assets/site.css",),
        "Static stylesheet for the generated documentation site.",
        "The stylesheet defines colour, panel, and layout tokens for the generated pages, so it is the rendering environment of the site.",
        "Styling establishes no content, claim, or verification status.",
    ),
    ownership_spec(
        "vstd-package-overview-diagram",
        "POLICY",
        ("docs/assets/vstd-overview.svg",),
        "Vector overview diagram stating the cumulative two-axis VSTD profile policy.",
        "The diagram states that five cumulative object profiles and five cumulative Graph profiles each require separate evidence per coordinate, and that later profiles never substitute for prerequisites.",
        "The diagram documents policy wording only. It does not implement, verify, or evidence any profile coordinate.",
    ),
    ownership_spec(
        "vstd-package-build-metadata",
        "ENV",
        ("pyproject.toml",),
        "Root build-system and project metadata declaration.",
        "The file declares the build backend, pinned build requirements, the empty runtime dependency list, supported Python versions, licence, project uniform resource locator (URL) entries, and the optional test extra.",
        "Declared metadata does not establish an installed or published distribution, a release, or environment reproducibility.",
    ),
    ownership_spec(
        "vstd-package-accelerator-registry",
        "HARDWARE",
        ("src/verifier/hardware/accelerator_registry.json",),
        "Declared accelerator-profile registry for device classes, discovery methods and capability declarations.",
        "The registry names accelerator device classes, discovery methods and capability declarations that the hardware registry loader exposes, so it is the declared hardware profile inventory.",
        "Profiles are declarations. Registry membership grants no core guarantee, several support fields are UNKNOWN or placeholders, and no measured capacity or live observation is established.",
    ),
)


# Typed UNKNOWN records.  Each is an unresolved role slot; none is a claim, and none is
# DOES_NOT_APPLY.  The next action names the evidence that would resolve the slot.
UNRESOLVED_RECORDS: tuple[UnresolvedRecord, ...] = (
    UnresolvedRecord(
        "vstd-hardware-retained-device-records", "src/verifier/domains/hardware.py", "specialization", "POLICY",
        "No POLICY admission or enforcement mechanism is source-established: evaluate returns result dictionaries and raises Unavailable or Refuted on each check, which is replay rather than admission.",
        "Source an exact POLICY admission gate for retained device records, or keep the role UNKNOWN through whole-graph review."),
    UnresolvedRecord(
        "vstd-hardware-retained-device-records", "src/verifier/domains/hardware.py", "specialization", "TRANSACTION",
        "The module evaluates retained records and performs no state transition, so no TRANSACTION commit or rollback is established.",
        "Name a state-changing publish path for these records, or keep TRANSACTION UNKNOWN."),
    UnresolvedRecord(
        "vstd-hardware-capacity-reservation", "src/verifier/domains/contracts/hardware_capacity.py", "specialization", "TRANSACTION",
        "The certificate replays selected reservations and performs no state transition, so no TRANSACTION commit is established.",
        "Name a state-changing reservation path, or keep TRANSACTION UNKNOWN."),
    UnresolvedRecord(
        "vstd-data-retained-records", "src/verifier/domains/data.py", "specialization", "POLICY",
        "Dataset checks raise Unavailable or Refuted as result-level replay; no admission or enforcement mechanism for POLICY is established.",
        "Source an exact admission gate for retained dataset records, or keep POLICY UNKNOWN."),
    UnresolvedRecord(
        "vstd-token-facet-projection", "src/verifier/domains/contracts/token_facets.py", "specialization", "POLICY",
        "The module projects native contract properties onto facets with no admission or refusal gate, so POLICY is not established.",
        "Source an exact admission gate for the facet projection, or keep POLICY UNKNOWN."),
    UnresolvedRecord(
        "vstd-train-run-specification", "src/verifier/domains/train.py", "specialization", "POLICY",
        "The module replays checkpoint and numerical trajectories and raises on mismatch; that is replay, not an admission mechanism for POLICY.",
        "Source an exact admission gate for TRAIN run specifications, or keep POLICY UNKNOWN."),
    UnresolvedRecord(
        "vstd-train-run-specification", "src/verifier/domains/train.py", "specialization", "PROTOCOL",
        "Replay of one retained checkpoint trajectory is a single-artifact check; a multi-artifact protocol is not established.",
        "Name the multi-artifact protocol this run specification participates in, or keep PROTOCOL UNKNOWN."),
    UnresolvedRecord(
        "vstd-verifier-engine-specification", "src/verifier/domains/verifier.py", "specialization", "POLICY",
        "Inventory and bound checks raise Refuted or Unavailable as replay of retained proof instances; no admission mechanism for POLICY is established.",
        "Source an exact admission gate for the verifier engine, or keep POLICY UNKNOWN."),
    UnresolvedRecord(
        "vstd-run-reproduction-protocol", "src/verifier/core/run_reproduction.py", "specialization", "POLICY",
        "Reproduction reruns the planned command and compares artifact digests; it admits or refuses no input, so POLICY is not established.",
        "Source an exact admission gate for reproduction, or keep POLICY UNKNOWN."),
    UnresolvedRecord(
        "vstd-train-native-checks", "src/verifier/domains/contracts/train_checks.py", "specialization", "PROTOCOL",
        "The module replays one native check certificate over retained observations, a single-artifact check; no protocol role is established.",
        "Name the multi-artifact protocol these certificates join, or keep PROTOCOL UNKNOWN."),
    UnresolvedRecord(
        "vstd-verifier-bootstrap-evidence", "src/verifier/domains/verifier_bootstrap.py", "specialization", "PROTOCOL",
        "One signed finite request is checked by truth table; that is single-artifact checking, so PROTOCOL is not established.",
        "Name the multi-artifact protocol the bootstrap evidence joins, or keep PROTOCOL UNKNOWN."),
    UnresolvedRecord(
        "vstd-manifest-write-cli", "src/verifier/runtime/namespace_cli.py", "specialization", "PROTOCOL",
        "The CLI writes one draft by exclusive create or verified replacement of one file; that single-artifact compare-and-publish is not automatically PROTOCOL.",
        "Name the multi-artifact protocol the publish path joins, or keep PROTOCOL UNKNOWN."),
    UnresolvedRecord(
        "vstd-manifest-write-execution-checks", "src/verifier/runtime/manifest_write_execution.py", "specialization", "PROTOCOL",
        "The module applies content expectations to observed outcomes of installed handlers, a single-artifact check; no protocol role is established.",
        "Name the multi-artifact protocol the execution checks join, or keep PROTOCOL UNKNOWN."),
    UnresolvedRecord(
        "vstd-verifier-replacement-replay", "src/verifier/domains/contracts/verifier_replacement.py", "root", "AGENT",
        "The contract replays retained observations and never invokes callbacks; that does not establish whether an agent role applies.",
        "Establish an exact AGENT applicability reason from the replay contract, or keep AGENT UNKNOWN."),
    UnresolvedRecord(
        "vstd-harness-applicability-denominator", "src/verifier/runtime/package_harness_applicability.py", "root", "AGENT",
        "The module reads source text by AST and starts no process; the absence of a launch does not decide whether an agent role applies.",
        "Establish an exact AGENT applicability reason from the denominator contract, or keep AGENT UNKNOWN."),
    UnresolvedRecord(
        "vstd-package-overview-raster", "docs/assets/vstd-overview.png", "primary", None,
        "The file is raster media. No registered kind is source-established for an image: DATA is refused for documentation media, and no document or media kind is registered.",
        "Register a media or document kind with source evidence, or keep the primary UNKNOWN."),
    UnresolvedRecord(
        "vstd-package-guides-page", "docs/guides.html", "primary", None,
        "A generated navigation page has no registered kind in this namespace; DATA is refused because a page is not a dataset.",
        "Register a document kind with source evidence, or keep the primary UNKNOWN."),
    UnresolvedRecord(
        "vstd-package-index-page", "docs/index.html", "primary", None,
        "A generated landing page has no registered kind in this namespace; DATA is refused because a page is not a dataset.",
        "Register a document kind with source evidence, or keep the primary UNKNOWN."),
    UnresolvedRecord(
        "vstd-package-generated-reference", "docs/reference.html", "primary", None,
        "A generated command and Python reference page has no registered kind in this namespace; DATA is refused because a page is not a dataset.",
        "Register a document kind with source evidence, or keep the primary UNKNOWN."),
)


def _carry_open_obligations(spec: SemanticOwnershipSpec) -> SemanticOwnershipSpec:
    """State that a carried consequential role keeps its admission obligations OPEN."""
    carried = bool(spec.specializations) or any(
        decision.status == "APPLIES" for decision in spec.root_role_decisions
    )
    if not carried:
        return spec
    return replace(
        spec,
        consequence_boundary=f"{spec.consequence_boundary} {_ADMISSION_OPEN_CLAUSE}",
    )


_INTEGRATION_BLOCKER_ROWS = tuple(
    IntegrationBlocker(
        object_id=item.object_id,
        operand_role=role,
        required_kind=kind,
        reason=reason,
        next_action=next_action,
    )
    for item in _DOMAIN_SYSTEMS_SPECS
    if item.primary_kind == "TRAIN"
    for role, kind, reason, next_action in _TRAIN_SLOT_REASONS
)


DOMAIN_SYSTEMS_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    sorted(
        (_carry_open_obligations(item) for item in _DOMAIN_SYSTEMS_SPECS),
        key=lambda item: item.object_id,
    )
)
INTEGRATION_BLOCKERS: tuple[IntegrationBlocker, ...] = tuple(
    sorted(_INTEGRATION_BLOCKER_ROWS, key=lambda item: (item.object_id, item.operand_role))
)


__all__ = [
    "AUDITED_SOURCE_DIGESTS",
    "DOMAIN_SYSTEMS_OWNERSHIP_SPECS",
    "INTEGRATION_BLOCKERS",
    "IntegrationBlocker",
    "UNRESOLVED_RECORDS",
    "UnresolvedRecord",
]

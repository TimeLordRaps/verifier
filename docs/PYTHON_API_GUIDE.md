# Python application programming interface (API) guide

> **Acronyms:** command-line interface (CLI); grounded decision certificate (GDC);
> identifier (ID); JavaScript Object Notation (JSON); operating system (OS);
> Secure Hash Algorithm 256-bit (SHA-256).

This guide is organized by task. For exact signatures of every export, read the
[generated reference](reference.html), which is produced from the live implementation at
build time. For what is promised to stay stable, read
[API stability](API_STABILITY.md). This page shows how the pieces fit together.

The Verifier Standard (VSTD) supported surface is exactly `verifier.__all__` — 53 names.
The base package has no required third-party dependencies; seal creation and verification
need the optional `seal` extra.

```python
import verifier

verifier.__version__           # '1.4.0'
verifier.__standard__          # 'VSTD-5'
verifier.__standard_status__   # 'PROJECT SPECIFICATION; EVIDENCE-BOUND REFERENCE MECHANISM'
```

The standard coordinate and status describe this project. They do not claim standards-body
recognition, conformance, adoption, or endorsement.

## Read results before you read values

Almost every result object in this API separates *what was checked* from *what was
established*, and refuses to collapse them. Four vocabularies recur:

| Enumeration | Values |
|---|---|
| `MechanismOutcome` | `PASS`, `FAIL`, `UNKNOWN` |
| `VerificationVerdict` | `VERIFIED`, `FALSIFIED`, `INDETERMINATE`, `UNSUPPORTED` |
| `PlatformComparisonStatus` | `PASS`, `CONFLICTED`, `NOT_ESTABLISHED`, `INVALID` |
| `ReproducibilityLevel` | `BITWISE_IDENTICAL`, `CONTENT_IDENTICAL`, `EVIDENCE_EQUIVALENT`, `RESULT_EQUIVALENT`, `SEMANTIC_REPRODUCTION` |

In each of them, "the check did not run or could not decide" is a distinct value from "the
check ran and the claim is false". Code that treats them as the same thing is discarding
the information this library exists to preserve. Write `if decision.outcome is
MechanismOutcome.PASS`, not `if not failed`.

## Capture and validate a run receipt

`capture_run` executes a manifest-declared command and returns a receipt binding the
command, its declared inputs and outputs, and its claim scope.

```python
import json
from pathlib import Path

from verifier import capture_run, validate_run_receipt

manifest_path = Path("examples/generic_run/manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

receipt = capture_run(manifest, manifest_path.parent)
receipt.save_to_directory(Path("receipt-demo"))

receipt.receipt_kind            # 'generic_computational_run'
receipt.verify_digest_integrity()   # True
validate_run_receipt(Path("receipt-demo"))  # 0
```

`capture_run` runs the declared command. It is not a sandbox; use OS or container isolation
for code you do not trust. `validate_run_receipt` returns a process-style exit code — `0`
for an intact receipt, `1` otherwise — and prints its finding:

```
[INTEGRITY OK] Run receipt RUN-000001 stable digest matches.
```

Change one field in the saved `receipt.json` and the same call reports the mismatch and
returns `1`:

```
[FAIL] Canonical digest mismatch:
  Recorded:   5dbd8fa9defe2bcf1f00ddbe197fdb93b441c43598dbf0040907e58c08c457ad
  Recomputed: 0cb47a2add2631ca9573952a533c30071cf98c5ea06650f30186dc18ff148aa0
```

Validation checks receipt structure and recomputes the stable-payload digest. It does not
rehash declared artifacts, verify external evaluation evidence, or establish that the claim
is true.

To digest a payload directly — for instance to compare a receipt you built by hand —
use `compute_canonical_digest`, which canonicalizes and takes the SHA-256:

```python
from verifier import compute_canonical_digest

compute_canonical_digest(receipt.get_stable_payload())
```

## Freeze, seal, and verify an artifact

```python
from pathlib import Path

from verifier import (
    freeze_artifact, seal_artifact, verify_frozen_artifact,
    thaw_artifact, thawed_artifact_status,
)

freeze = freeze_artifact(Path("payload"), Path("run.vstd"), media_type="application/octet-stream")
seal_artifact(Path("run.vstd"), private_key_path=Path("ed25519-private.pem"))

verification = verify_frozen_artifact(Path("run.vstd"), expected_artifact_id=freeze.artifact_id)
thaw_artifact(Path("run.vstd"), Path("working-copy"))
status = thawed_artifact_status(Path("working-copy"), parent_bundle=Path("run.vstd"))
```

`ArtifactVerification` reports freeze validity, guard validity, valid seal identifiers, key
identifiers, and external-anchor state separately, and raises `ArtifactControlError` rather
than degrading a result when it cannot fail closed. Without `parent_bundle`,
`thawed_artifact_status` returns `NOT_ESTABLISHED` even when the descendant bytes agree
with the sidecar — the sidecar is unkeyed lineage metadata, not evidence.

The full walkthrough, including the failure branches and exit codes, is
[Seal an artifact and detect a change](tutorials/SEAL_AN_ARTIFACT.md).

## Analyze a verification geometry

A VSTD-2 geometry models coordinates, mechanisms, residuals, horizons, and verification
orders. `analyze_verification_surface` derives structured holes from it.

```python
from verifier import analyze_verification_surface, load_verification_geometry

geometry = load_verification_geometry("examples/verification_geometry_residual/geometry.json")
analysis = analyze_verification_surface(geometry)

analysis.ordinary_closed   # True
analysis.self_closed       # False
len(analysis.holes)        # structured diagnostics, one per blocker source
```

That example is closed in the ordinary sense and **not** self-closed, and the analysis says
why in `self_closure_blockers`:

```
material residual 'residual:decimal-separator' is not resolved
horizon 'horizon:locale-observation' terminates derivation without proving what lies beyond it
verification valence 'valence:locale-state' remains HORIZON
mechanism 'mechanism:fixture-test' is not post-verified
...
```

Each `SurfaceHole` carries a `kind` from `SurfaceHoleKind` — `MISSING_JUDGMENT`,
`COORDINATE_STATUS`, `RESIDUAL`, `VALENCE`, `HORIZON`, `MECHANISM`, `VERIFICATION_ORDER`,
or `SELF_CLOSURE_REQUIREMENT` — plus separate `blocks_ordinary_closure` and
`blocks_self_closure` flags, so a caller can plan against exactly the holes that matter to
it. Pass a `ControlSurfaceContext` to record the schema and `InteractionMode` (`STATIC`,
`OFFLINE_REPLAY`, `SIMULATION`, `LIVE_READ_ONLY`, `LIVE_MUTATING`) a plan targets.

Analysis is deterministic and limited to the supplied modeled surface. It does not infer
omitted obligations and does not establish real-world completeness, safety, authority, or
conformance. `load_verification_geometry` raises `GeometryLoadError` on structure it does
not recognize rather than loading a partial geometry.

## Bind evidence and rerun a mechanism

This is the core evidence-bound pattern, and the one worth understanding before anything
built on top of it. A `BoundProposition` names the subject, predicate, expected value,
mechanism, mechanism digest, evidence references, trust roots, and resource bounds. A
`VerificationSession` resolves the evidence from an `EvidenceStore` and reruns *only*
mechanisms that were explicitly registered.

```python
import hashlib
import json

from verifier import (
    BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession,
)


class ExactFactMechanism:
    """Compare exact fact bytes with the bound proposition."""

    mechanism_id = "example.exact-json-fact"
    mechanism_digest = "sha256:" + hashlib.sha256(b"example.ExactFactMechanism:v1").hexdigest()

    def evaluate(self, binding, evidence):
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "exactly one fact required")
        observed = json.loads(evidence[0])
        expected = {
            "subject_id": binding.subject_id,
            "predicate": binding.predicate,
            "expected": binding.expected,
        }
        outcome = MechanismOutcome.PASS if observed == expected else MechanismOutcome.FAIL
        return MechanismDecision(outcome, f"exact fact comparison: {outcome.value}")


store = EvidenceStore()
session = VerificationSession(store)
session.register(ExactFactMechanism())

fact = json.dumps(
    {"subject_id": "model:demo-1", "predicate": "parameter_count", "expected": 7_000_000},
    sort_keys=True,
    separators=(",", ":"),
).encode()
reference = store.add(fact)

proposition = BoundProposition(
    "model:demo-1",
    "parameter_count",
    7_000_000,
    ExactFactMechanism.mechanism_id,
    ExactFactMechanism.mechanism_digest,
    (reference,),
    ("example:exact-fact-policy",),
    EvidenceBounds(max_evidence_items=1, max_evidence_bytes=20_000),
)

decision = session.evaluate(proposition)
decision.outcome              # MechanismOutcome.PASS
decision.observed_evidence_bytes   # 78
```

`store.add` returns a content-addressed reference such as `sha256:57291a27…`; the store
refuses digest collisions and forks. `decision.to_dict()` carries the binding digest,
outcome, mechanism identity, evidence references, trust roots, observed byte count, and
details — everything needed to rerun the decision elsewhere.

### Four ways this returns something other than PASS

Only the first is a `FAIL`:

| Situation | `outcome` | `details` |
|---|---|---|
| evidence disagrees with the expected value | `FAIL` | `exact fact comparison: FAIL` |
| the bound mechanism was never registered | `UNKNOWN` | `bound mechanism is not registered` |
| evidence exceeds the declared byte bound | `UNKNOWN` | `evidence byte bound exceeded` |
| a referenced evidence item is absent | `UNKNOWN` | `evidence is unavailable: sha256:0000…` |

An unregistered mechanism does not silently execute, an over-budget input does not get
evaluated anyway, and a missing reference does not become a negative result. Bounds are
enforced *before* the mechanism is invoked.

The session snapshots canonical binding values before evidence resolution and invokes the
mechanism with a second copy. A mechanism that mutates its invocation copy yields `UNKNOWN`
rather than a bound result. If no digestible snapshot can be taken,
`EvidenceBindingError` is raised before execution rather than a result being invented.

## Establish depth and replay it offline

`establish_vstd4` reruns every bound mechanism and establishes VSTD-4 only if all pass;
`build_evidence_bound_vstd4_receipt` serializes every input needed to rerun it, and
`recheck_evidence_bound_vstd4_receipt` reconstructs the evidence bytes and reruns it
somewhere else. `claim_binding_from_dict` recovers the exact claim binding a receipt
carries.

`vstd4_depth` is the older compatibility computation over caller-supplied references. It
produces a *candidate* result. A candidate does not become a conformance result because
the evidence-bound API also exists; `require_vstd5_entry` rejects an unbound candidate at
the VSTD-5 boundary rather than promoting it.

The witness layer is the same shape one level up: `WitnessBundle` carries claim-bound
identities, ordered separation assertions, and corroborations;
`assess_witness_corroboration` rechecks VSTD-5 entry plus separation and corroboration
evidence and accepts incomplete input so it can return a typed diagnostic;
`build_vstd5_receipt` is stricter and either raises or returns a receipt carrying all
verdict-material evidence bytes; `recheck_vstd5_receipt` replays it. Names are never
treated as trust.

## Compare runs across platforms

```python
from verifier import compare_platform_run_receipts

result = compare_platform_run_receipts(["receipt-linux/receipt.json", "receipt-windows/receipt.json"])
result.status   # PlatformComparisonStatus.PASS | CONFLICTED | NOT_ESTABLISHED | INVALID
```

`PASS` requires complete declared platform coverage, canonical integrity, equal
non-platform bindings, and equal declared result projections. `CONFLICTED`,
`NOT_ESTABLISHED`, and `INVALID` stay distinct: a conflict between platforms, an
incomplete comparison, and a malformed input are different facts. The returned
`PlatformComparisonResult` is a diagnostic object, **not** a VSTD receipt and not a
conformance result.

## Provenance graphs and assurance ledgers

`ProvenanceHypergraph` is an n-ary structure for dataset, training, and artifact lineage.
`establish_graph_level` reruns rating mechanisms before computing a conforming Graph
profile; `graph_collection_binding_digest` binds ratings to one graph, member set,
collection, and claim coordinate; `build_evidence_bound_graph_level_record` and
`recheck_evidence_bound_graph_level_record` are its portable-record pair.

`AssuranceLedger` is an append-only current-state overlay on an immutable provenance graph,
with `ObligationCoordinate` naming an exact technical obligation and the declared scope it
applies in. `recheck_assurance_log` rebuilds and replays a portable log from its embedded
bytes, given the mechanisms to rerun:

```python
from verifier import recheck_assurance_log

rebuilt = recheck_assurance_log(payload, mechanisms=(ExactFactMechanism(),))
rebuilt.to_dict() == payload   # True for an untampered log
```

Editing a recorded detail in the payload makes the replay disagree rather than adopting the
edit.

## The complete export map

| Group | Exports |
|---|---|
| Artifact control | `freeze_artifact`, `seal_artifact`, `verify_frozen_artifact`, `thaw_artifact`, `thawed_artifact_status`, `ArtifactVerification`, `ArtifactControlError` |
| Receipts and runs | `capture_run`, `validate_run_receipt`, `compute_canonical_digest`, `VstdReceipt`, `VerificationVerdict`, `ReproducibilityLevel` |
| Platform comparison | `compare_platform_run_receipts`, `PlatformComparisonResult`, `PlatformComparisonStatus` |
| Geometry | `load_verification_geometry`, `VerificationGeometry`, `GeometryLoadError` |
| Surface analysis | `analyze_verification_surface`, `SurfaceAnalysis`, `SurfaceHole`, `SurfaceHoleKind`, `SurfaceAnalysisError`, `ControlSurfaceContext`, `InteractionMode` |
| Evidence binding | `BoundProposition`, `EvidenceBounds`, `EvidenceStore`, `EvidenceBindingError`, `MechanismDecision`, `MechanismOutcome`, `VerificationSession` |
| Depth (VSTD-4/5) | `establish_vstd4`, `vstd4_depth`, `require_vstd5_entry`, `claim_binding_from_dict`, `build_evidence_bound_vstd4_receipt`, `recheck_evidence_bound_vstd4_receipt` |
| Witness (VSTD-5) | `WitnessBundle`, `assess_witness_corroboration`, `build_vstd5_receipt`, `recheck_vstd5_receipt` |
| Graph profiles | `ProvenanceHypergraph`, `establish_graph_level`, `graph_collection_binding_digest`, `build_evidence_bound_graph_level_record`, `recheck_evidence_bound_graph_level_record` |
| Assurance | `AssuranceLedger`, `ObligationCoordinate`, `recheck_assurance_log` |
| Certificates | `DecisionCertificate`, `certificate_from_canonical_bytes` |

`DecisionCertificate` holds canonical GDC blocks for the bounded checker, and
`certificate_from_canonical_bytes` decodes only the canonical JSON representation used in
commitment digests — not a lenient parse.

The experimental artifact-network surface is reached through
`verifier.interoperability.network` rather than the top-level package, because its `0.1`
wire identifiers may change. See
[Publish a verification-artifact silo](tutorials/PUBLISH_A_SILO.md).

## Where the boundary is

Nothing in this API establishes that a claim is true. It establishes that exact bytes were
retained, that declared mechanisms were rerun under declared bounds, that named evidence
resolved, and that recomputed digests agree — and it reports, separately and by name, every
question it did not answer.

Read [claims and limits](CLAIMS_AND_LIMITS.md) before relying on any result, and
[API stability](API_STABILITY.md) before depending on any name.

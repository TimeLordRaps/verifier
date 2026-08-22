# VSTD-3 threat model

**Layer:** VSTD-3; historical receipt wire identifier `VSTD-3.0`
**Purpose:** defensive verification and conformance; not offensive exploit guidance

## Boundary

The protected claim is not “the host is honest.” It is the narrower statement that a
named evidence producer generated authenticated evidence for a named device,
firmware/runtime state, execution, partition/topology, epoch, and interval. Strength
depends on where the signing key and accounting state live.

The reference emulator models a governed boundary in software. It does not model
physical tamper resistance. Current NVIDIA/AMD/generic adapters primarily observe the
host and therefore remain vulnerable to a hostile administrator suppressing or
fabricating telemetry.

## Adversaries and responses

| Threat | Detection or containment | Residual limit |
|---|---|---|
| Hostile host administrator | Device/firmware signatures and external anchors can make alteration or gaps detectable. Host-only sources cannot pass device or complete-mediation claims. | A host may suppress all evidence or route work around an unmediated device; availability and complete path control require hardware support. |
| Receipt deletion | An external anchor can prove a later claimed history no longer connects to an externally known root. | Deleting every local receipt before any anchor may be indistinguishable from no collection. |
| Receipt replay or duplication | Receipt IDs, challenge IDs, nonces, event IDs, epoch/sequence positions, and rolling roots are checked for reuse and duplicates. | A verifier needs challenge and acceptance-state retention across receipts to detect cross-receipt replay globally. |
| Device substitution / wrong device | Attestation subject, certificate digest, evidence source, and continuity device ID must agree. | Trust in manufacturer/owner certificate roots remains external policy. |
| Firmware replacement or altered measurement | Firmware fields are signature-bound and comparison state is explicit. | Verification needs authentic reference measurements and an appraisal policy. |
| Firmware downgrade | A signed version/digest change is visible. | Whether the version is prohibited requires a freshness/revocation policy; absence of that policy is `UNKNOWN`. |
| Driver/runtime replacement | Workload/runtime/driver commitments are bound into `ExecutionIdentity` and authenticated start-event payloads. | Commodity adapters may not measure every loaded component. Missing commitments are reported. |
| Reset or power cycle | A new reset epoch names prior epoch/root and an external anchor when available. | An honest unanchored reset creates a gap; it cannot prove pre-anchor history. |
| Clock manipulation | Timestamps are signature-bound, timezone-qualified, and checked for rollback within an epoch. | Signed device time is not proof of accurate UTC without a trusted time source. |
| Sequence rollback or wrap | Sequence must increase from zero within each epoch and fit unsigned 64-bit range. | A verifier must retain or anchor previously accepted state to detect an entirely replaced pre-anchor history. |
| Partition reconfiguration | Reconfiguration is an authenticated event and produces a new topology revision; active execution blocks reconfiguration in the emulator. | Host discovery may miss out-of-band configuration. |
| VM migration / logical-device recreation | Logical ID, partition ID, physical lineage, topology snapshot, and execution binding are checked. | Stable identity across providers requires provider/device support; a recreated opaque slice may remain `UNKNOWN`. |
| Wrong nonce or stale evidence | Nonce equality, challenge uniqueness, issue/expiry intervals, and receipt creation time are checked. | Verifier challenge storage and trusted verifier time remain part of the TCB. |
| Forged self-report | Unverified/self/host evidence cannot satisfy strong device, firmware, execution-attestation, continuity, or complete-mediation requirements. | It can still support explicitly weak declared or observed claims. |
| Missing job end | Validation warns, and a recorded complete-mediation `PASS` is rejected. | A genuinely interrupted job is valid only when an authenticated `INTERRUPTED` end is recorded. |
| Partial topology | Every execution device must exist in its bound snapshot; completeness is false by default. | The snapshot may omit devices outside its declared boundary. |
| Missing fleet member | Exact set comparison fails the enrolled-boundary observation. | Enrollment itself may be incomplete unless separately evidenced. |
| Unregistered device | An unexpected enrolled-member identifier fails the fleet observation. | A physically present device outside enrollment is not discoverable from the manifest alone. |
| Unsupported device | Adapter returns `UNSUPPORTED` plus an evidence gap. | No strong hardware statement is available until a collector/verifier exists. |
| Provider evidence without hardware evidence | Provider evidence remains a separate artifact and capability; physical claims remain `UNKNOWN`. | Tenants may be unable to obtain direct device evidence. |
| Hardware evidence without workload identity | The execution record warns when it has no workload commitment beyond a label. | Identity can be partial when firmware cannot measure higher software layers. |
| Altered accounting or estimator labeled exact | Event payload binding detects alteration; constructors reject estimate methods labeled exact. | Counter semantics and physical coverage still depend on vendor documentation/appraisal. |
| Physical plus logical double counting | Aggregator rejects mixed physical/logical geometry and oversubscribed logical definitions. | Cross-system aggregation still needs consistent time and scope boundaries. |

## Trusted computing base by implementation

### Reference emulator

- Python interpreter and VSTD code;
- emulator HMAC secret and key resolver;
- external anchor HMAC secret when used;
- caller control of all execution submission paths.

It proves protocol semantics only.

### Host discovery adapters

- operating system, driver, vendor CLI/library, collector, and fixture source;
- registry profile selection and normalization code.

This boundary is not resistant to a hostile host.

### Future device/firmware adapter

The TCB should reduce to device root of trust, measured firmware, accounting state,
signing key, authenticated transport, reference-value/appraisal policy, verifier nonce
and time state, and external anchor service. Every governed submission path must be
controlled by the measured accounting firmware for complete mediation.

## Security outcomes

- **PASS:** the implemented checks prove the bounded statement.
- **FAIL:** evidence demonstrates inconsistency, tampering, or a violated condition.
- **UNKNOWN:** evidence or verifier capability is missing.
- **UNSUPPORTED:** the mechanism declares it cannot provide the capability.

`UNKNOWN` is not failure and must never be relabeled as success. `FAIL` is not used for
mere lack of access.

## Explicit non-goals

VSTD-3 does not prove global absence of undeclared compute, physical tamper resistance,
correct model behavior, accurate UTC, legal authorization, confidentiality, vendor
endorsement, complete fleet enrollment, or safety. Those require separately evidenced
mechanisms and policies.

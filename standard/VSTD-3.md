# VSTD-3 — Substrate Accountability

**Layer:** 3 of 5 on the object axis (see `LADDER.md`)
**Receipt wire format:** `schema_version = "VSTD-3.0"` — frozen; see `MIGRATION.md`
**Status:** implemented project specification  
**Editor:** Tyler Roost  
**License:** Apache-2.0  
**Canonical schema:** `receipts/schema/vstd3_receipt.json`

VSTD is an independent project specification. It is not an accredited, consensus,
IETF, ISO, DMTF, PCI-SIG, or W3C standard. Product names identify adapter targets and
do not imply vendor participation, certification, or endorsement.

## 1. Scope

VSTD-3 defines an accelerator-neutral evidence path:

```text
Accelerator -> EvidenceSource -> Attestation -> ExecutionAccounting
            -> Continuity -> Provenance -> Policy
```

It specifies how to preserve and evaluate evidence about accelerators, firmware,
runtimes, workloads, accounting events, partitions, topology, provider control planes,
and enrolled fleets. It does not assume CUDA, GPUs, direct tenant firmware access, or
that exact FLOP counters exist.

The normative invariant is:

> Evidence strength MUST monotonically bound claim strength.

The target future property is:

> Within an explicitly identified governed accelerator boundary, execution is
> inseparable from authenticated accounting evidence.

Current host telemetry normally does not establish that property. The reference
emulator does establish it inside its own software boundary, using test-only keys.

## 2. Requirement language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative within this project
specification. A conforming implementation MUST preserve `UNKNOWN` when evidence is
insufficient, MUST return `FAIL` only for an evidenced inconsistency or violation, and
MUST use `UNSUPPORTED` when the declared mechanism lacks a required capability.

## 3. Universal records

The normative typed surface consists of:

- registry: `AcceleratorProfile`, `CapabilityDeclaration`;
- inventory: `AcceleratorDescriptor`, `PhysicalDeviceIdentity`,
  `LogicalDeviceIdentity`, `AcceleratorPartition`;
- topology: `TopologyNode`, `TopologyLink`, `TopologySnapshot`;
- attestation: `AttestationChallenge`, `AttestationEvidence`,
  `FirmwareMeasurement`, `RuntimeMeasurement`, `DeviceCertificateEvidence`;
- workload: `WorkloadIdentity`, `ExecutionIdentity`, `ExecutionStart`,
  `ExecutionObservation`, `ExecutionEnd`;
- accounting: `AccountingQuantity`, `ComputeAccountingObservation`,
  `AccountingEvent`;
- continuity: `ContinuityRecord`, `ContinuityAnchor`, `ResetEpoch`, `EvidenceGap`;
- provider and fleet: `ProviderEvidence`, `FleetBoundary`, `FleetMember`,
  `FleetManifest`, `FleetObservation`;
- decisions: `ClaimEvaluation`, `VSTD3Receipt`.

Unknown future accelerators are represented through a registry profile plus an
adapter. Product identity MUST NOT change core claim semantics.

## 4. Canonical serialization

1. Signed records MUST use UTF-8 JSON with lexicographically sorted object keys,
   compact separators, and no NaN or infinity.
2. JSON floating-point values MUST NOT occur in signed records. Decimal quantities
   MUST be strings; exact integers MAY be JSON integers.
3. Every dataclass field is part of its canonical surface unless a record explicitly
   defines a stable payload. `VSTD3Receipt.canonical_digest` is excluded from the
   payload it digests.
4. Unknown fields in signed records MUST be rejected. They MUST NOT be silently
   dropped.
5. Evidence adapters SHOULD preserve original bytes in `raw_evidence_b64` and MUST
   bind them with `raw_evidence_digest` using SHA-256.
6. Normalization MUST NOT replace or destroy access to the original evidence bytes.

The JSON Schema is structural. The typed validator additionally performs reference,
semantic, freshness, topology, signature, continuity, and overclaim checks.

## 5. Registry

`accelerator_registry.json` is data, not policy. An `AcceleratorProfile` describes
discovery methods, partition modes, evidence methods, protocols, documented support,
references, confidence, and limitations. A profile declaration is not proof that a
particular device or deployment demonstrated the capability.

A new family normally requires only:

1. registry metadata;
2. capability declarations;
3. an evidence adapter;
4. conformance fixtures and tests.

No product name may automatically grant a claim.

## 6. Evidence capabilities

Capabilities are independent predicates, not a numeric score:

- `SELF_REPORTED`;
- `HOST_OBSERVED`;
- `EXECUTION_OBSERVED`;
- `SOFTWARE_SIGNED`;
- `PROVIDER_ATTESTED`;
- `DEVICE_IDENTITY_ATTESTED`;
- `FIRMWARE_ATTESTED`;
- `EXECUTION_ATTESTED`;
- `EXECUTION_ACCOUNTING_EVIDENCED`;
- `CONTINUITY_ATTESTED`;
- `COMPLETE_MEDIATION_ATTESTED`;
- `FLEET_BOUNDARY_ATTESTED`.

The reference implication graph is explicit. In particular:

- firmware attestation does not imply execution attestation;
- execution attestation does not imply exact compute accounting;
- continuity does not imply complete mediation outside its interval;
- provider attestation does not imply physical-device attestation;
- fleet-boundary attestation does not imply physical-world completeness.

`VERIFIED` flags inside a receipt are not self-authenticating. A verifier MUST
independently reproduce signature and continuity checks before using those flags to
accept a strong `PASS`.

## 7. Incremental conformance profiles

An implementation MAY conform to a weaker profile without claiming a stronger one:

| Profile | Minimum demonstrated capability |
|---|---|
| `VSTD3-DISCOVERY` | `HOST_OBSERVED` |
| `VSTD3-DEVICE-IDENTITY` | `DEVICE_IDENTITY_ATTESTED` |
| `VSTD3-FIRMWARE-ATTESTATION` | `FIRMWARE_ATTESTED` |
| `VSTD3-EXECUTION-EVIDENCE` | `EXECUTION_ATTESTED` |
| `VSTD3-EXECUTION-ACCOUNTING` | `EXECUTION_ACCOUNTING_EVIDENCED` |
| `VSTD3-CONTINUITY` | `CONTINUITY_ATTESTED` |
| `VSTD3-COMPLETE-MEDIATION` | verified firmware/device source plus passing continuity and `COMPLETE_MEDIATION_ATTESTED` |
| `VSTD3-FLEET` | `FLEET_BOUNDARY_ATTESTED` |

Conformance is always scoped to the named mechanism, evidence, subject, boundary, and
time interval.

## 8. Attestation challenge and evidence

An attestation used for a strong claim MUST:

1. reference an issued challenge;
2. repeat the challenge nonce exactly;
3. contain at least 64 nonce bits in the reference implementation;
4. be issued within the challenge interval and be unexpired at receipt creation;
5. bind its subject identity, challenge, nonce, time interval, evidence source,
   firmware and runtime measurements, certificate evidence, and capabilities;
6. be verified through an implemented signature algorithm and trusted key resolver;
7. bind certificate evidence to the declared physical identity when that identity
   carries a certificate digest.

Challenge reuse, a wrong nonce, a wrong device, stale evidence, an altered signed
field, or an invalid implemented signature is `FAIL`. An absent key or unsupported
signature verifier is `UNKNOWN`, not `PASS`.

The core currently implements `HMAC-SHA256-TEST-ONLY` for deterministic conformance
fixtures. This algorithm is not a physical root of trust. Vendor evidence is accepted
as opaque preserved bytes until an adapter implements certificate-chain, nonce,
signature, and measurement appraisal for the actual format.

## 9. Firmware Accountability Contract

The normative future firmware state machine is:

```text
BOOT -> IDENTITY_ESTABLISHED -> FIRMWARE_MEASURED -> EPOCH_OPEN
     -> EXEC_START -> zero or more EXEC_OBSERVATION -> EXEC_END
     -> rolling state update -> optional external anchor
     -> explicit RESET into a new epoch
```

Firmware claiming `VSTD3-COMPLETE-MEDIATION` MUST ensure that all governed submission
paths enter this state machine. An execution path that can bypass accounting violates
the profile. Installing measured firmware alone does not prove that bypass is absent.

The reference `VirtualVSTDAccelerator` rejects execution before boot, unknown logical
devices, replayed execution identifiers, observations for inactive executions,
partition changes during active execution, duplicate challenges, and receipt finality
while an execution remains active.

## 10. Authenticated continuity

For reset epoch `e`, genesis is:

```text
G[e] = SHA256(canonical_json({
  domain: "VSTD3-CONTINUITY-1:GENESIS",
  device_identity_id, epoch, boot_id,
  prior_epoch, prior_rolling_root, external_anchor_id
}))
```

For event `n`, the rolling state is:

```text
R[n] = SHA256(canonical_json({
  domain: "VSTD3-CONTINUITY-1:EVENT",
  previous_root, event_type, device_identity_id, partition_id,
  execution_id, epoch, sequence, timestamp, event_payload_digest
}))
```

The device signs `R[n]`. Sequence numbers are unsigned 64-bit values and MUST begin at
zero in each epoch. The verifier checks duplicate identifiers, duplicate positions,
replay, forks, rollback, missing prefixes, gaps, predecessor roots, rolling roots,
signatures, event ordering, timezone-qualified nondecreasing timestamps, reset chains,
and anchors.

A missing event produces an explicit `EvidenceGap`. A cryptographic inconsistency is
`FAIL`. Missing verification keys, absent events, or an honest unanchored reset are
`UNKNOWN`. A reset MUST create a new epoch; it MUST NOT erase prior history. A later
epoch SHOULD name an external anchor for the prior rolling root.

Wall-clock time remains a declared device clock even when signed. Signing detects
alteration and rollback relative to recorded order; it does not prove UTC accuracy.

## 11. External anchors

`AnchorProvider` separates continuity from any one transparency service. The reference
implementation includes deterministic in-memory and append-only file-backed test
providers. Both use test-only HMAC signatures and reject anchor forks. Remote,
enterprise, cloud, management-plane, and public transparency providers may implement
the same interface, but are not present merely because the interface exists.

## 12. Workload and execution binding

`WorkloadIdentity` represents independent commitments to executable code, source tree,
container, model, inputs, datasets, environment, compiler, accelerator runtime,
driver, libraries, kernels, invocation, orchestration job, cloud resource, tenant, and
parent run. Private content need not be disclosed; a cryptographic commitment is
sufficient when its construction is declared.

An authenticated `EXEC_START` event MUST bind the complete `ExecutionIdentity`.
`EXEC_OBSERVATION` MUST bind the corresponding accounting record. `EXEC_END` MUST bind
the outcome and output commitments. The validator checks these payload digests and
timestamps. A workload with only a human label and no commitment is reported as a
limitation.

## 13. Compute accounting

Every quantity contains a decimal-string value, unit, method, source, scope, exactness,
and optional uncertainty/vendor extension. Methods are:

`HARDWARE_COUNTER`, `FIRMWARE_COUNTER`, `COMPILER_EXACT`, `COMPILER_ESTIMATE`,
`RUNTIME_ESTIMATE`, `MODEL_ESTIMATE`, `CAPACITY_TIME_UPPER_BOUND`, `PROVIDER_REPORT`,
`SELF_REPORT`, `VENDOR_SPECIFIC`, and `UNKNOWN`.

Only hardware, firmware, and compiler-exact methods may be labeled
`EXACT_FOR_DECLARED_SCOPE`. Capacity-time MUST be an `UPPER_BOUND`. Exactness is still
limited to the stated counter semantics and scope; an exact instruction counter is not
automatically exact physical FLOPs.

Accounting device scopes MUST lie within the execution's logical devices or their
physical parents. Aggregation MUST NOT combine a physical total with its logical
partition totals. Registered logical capacity for one physical device MUST NOT exceed
1,000,000 parts per million.

## 14. Topology, partitions, and virtualization

Physical and logical identities are distinct. Every logical identity MUST retain
physical lineage. Partition membership, capacity, and parent identity must agree.
Execution logical devices MUST occur in the bound topology snapshot. Partition changes
after boot are authenticated events and produce a new topology revision in the
reference emulator.

Topology may include switches, DPUs, SmartNICs, PCIe functions, fabric adapters,
management controllers, packages, chiplets, pods, clusters, and cloud slices. A
snapshot's `completeness_claimed` flag may pass only with separately verified fleet
boundary evidence.

## 15. Provider evidence

Provider evidence is a separate control-plane statement. Its signature, resource,
claims, validity interval, and hardware-evidence references are preserved and checked
where an implemented verifier is configured. It does not become physical-device or
firmware attestation merely because a cloud provider signed it.

The reference package provides strict offline boundaries for Google Cloud TPU, AWS
Neuron (Trainium/Inferentia), and Microsoft Azure Maia fixture evidence. These adapters
do not call provider APIs, discover tenant-invisible devices, or assert undocumented
firmware access.

## 16. Fleet boundary

A fleet manifest identifies organization, site, cluster, rack, host, and accelerator
set, plus enrollment, retirement, and replacement state. A fleet observation compares
exact enrolled member identifiers with observed, missing, and unexpected identifiers.

`FLEET_COMPLETENESS` means only:

> Every accelerator enrolled in fleet boundary F supplied the required evidence for
> observation interval T.

The completeness of enrollment itself requires separate evidence.
`PHYSICAL_WORLD_COMPLETENESS` is always `UNSUPPORTED` in ordinary VSTD-3 receipts.

## 17. Claim lattice and outcomes

| Claim | Minimum evidence | Prohibited inference |
|---|---|---|
| `DEVICE_IDENTITY` | authenticated device identity | workload ran or all paths were mediated |
| `FIRMWARE_INTEGRITY` | authenticated measurement appraised against a reference | every execution was logged |
| `EXECUTION_OBSERVED` | source-specific positive execution observation | device-origin evidence |
| `EXECUTION_ATTESTATION` | authenticated execution evidence | exact compute quantity |
| `EXECUTION_ACCOUNTING` | typed accounting evidence | exact physical FLOPs outside declared scope |
| `ACCOUNTING_CONTINUITY` | passing authenticated sequence | history outside evidenced interval |
| `COMPLETE_MEDIATION` | explicit device/firmware capability plus passing continuity | ungoverned paths or other devices were absent |
| `FLEET_COMPLETENESS` | exact observation of an evidenced enrolled boundary | all physical hardware was enumerated |
| `PHYSICAL_WORLD_COMPLETENESS` | none available | no undeclared compute occurred anywhere |

`PASS` requires every minimum capability. `FAIL` requires an evidenced violation.
`UNKNOWN` means support may exist but available evidence is insufficient.
`UNSUPPORTED` means the declared mechanism lacks the capability.

## 18. Real-hardware adapters

- Generic fixtures and current NVIDIA `nvidia-smi`/NVML-style discovery normalize
  host-visible inventory as `HOST_OBSERVED`.
- NVIDIA fixture envelopes may preserve opaque SPDM/NVTrust/NVSwitch evidence, but the
  core does not verify their certificate chains, RIM appraisal, nonce, or signature.
- AMD SMI/ROCm fixtures normalize host-visible device, firmware metadata, and
  partitions. Opaque DICE/platform evidence is preserved but not promoted.
- Intel Gaudi has a registry and generic fixture boundary; absent a configured
  collector it returns `UNSUPPORTED` with an evidence gap.
- Other product families use the generic registry/fixture interface and declare
  unsupported capabilities honestly.

No core installation requires a vendor SDK. Unsupported hardware is not a failed
attestation; it is an explicit gap or `UNSUPPORTED` result.

## 19. Provenance composition

Validated hardware sources, identities, measurements, topology, execution,
accounting, continuity, provider evidence, and receipts become artifact nodes in the
existing VSTD-Graph hypergraph. Transformations connect those artifacts to existing
model, checkpoint, dataset, evaluation, or deployment artifacts. Revoking upstream
hardware or firmware evidence therefore reaches downstream artifacts through the
existing blast-radius algorithm. VSTD-3 does not create a second lineage graph.

Composition is transactional and refuses receipts whose recorded `PASS` claims cannot
be independently reproduced.

## 20. Verification algorithm

A verifier MUST, in order:

1. parse with strict field rejection;
2. recompute the receipt canonical digest;
3. verify identifiers and all references;
4. verify raw evidence byte digests;
5. validate challenge freshness, nonce uniqueness, subject, and certificate binding;
6. independently verify implemented attestation and provider signatures;
7. validate topology and partition lineage;
8. bind starts, observations, accounting, ends, and workload identity to events;
9. verify event continuity, resets, and anchors;
10. verify the exact fleet boundary when present;
11. recompute every recorded passing claim from independently accepted evidence;
12. reject any stronger recorded `PASS`.

Receipt digest integrity alone completes only steps 1–2.

## 21. Privacy and disclosure

Commitments MAY replace private workload, tenant, input, model, or dataset contents.
The commitment scheme and salt/key custody must be declared where relevant. A bare hash
of low-entropy private data may enable guessing and is not confidentiality. VSTD does
not itself provide access control, encryption at rest, or legal authorization.

## 22. Interoperability boundary

VSTD-3 can wrap or reference SPDM, DICE/DPE, Caliptra-rooted evidence, RATS/EAT,
PCIe TDISP/IDE state, and vendor formats. It does not reproduce restricted
specification text. Format support must name the exact parser/verifier version and
trust anchors. Merely labeling bytes `SPDM`, `EAT`, or `DICE` is not verification.

## 23. Compatibility

VSTD-3 adds record and enum values. It does not reinterpret VSTD-1, VSTD-Graph-1,
VSTD-2, or their historical wire identifiers. Existing readers remain valid
for their versioned surfaces. VSTD-3 hardware nodes use additive artifact and
transformation enum values in the existing hypergraph.

## 24. Falsification conditions

VSTD-3 conformance is falsified for a claimed surface if any of these occurs:

- a weak source produces a strong accepted claim;
- signed bytes or normalized semantic fields can change without detection;
- a missing, duplicate, replayed, reordered, forked, or rollback event still verifies
  as continuous;
- reset discards prior history without an explicit gap;
- logical compute loses physical lineage or is double counted;
- a provider response is treated as physical attestation without referenced hardware
  evidence;
- fleet completeness escapes its enrolled boundary;
- global absence of undeclared compute is derived from an ordinary receipt.

Implementation limitations and the complete threat model are in
`../docs/layers/vstd-3/threat-model.md`; vendor requirements are in
`../docs/layers/vstd-3/vendor-integration.md`.

# VSTD-3 accelerator vendor integration kit

> Reader aid: [concept glossary and primary precedents](../../CONCEPTS_AND_PRECEDENTS.md).

This is the minimum review surface for a firmware or silicon security team evaluating
VSTD-3. It does not require adopting VSTD product names in firmware.

## 1. Select the honest profile

Implement only the profiles the device can demonstrate:

1. `VSTD3-DEVICE-IDENTITY`
2. `VSTD3-FIRMWARE-ATTESTATION`
3. `VSTD3-EXECUTION-EVIDENCE`
4. `VSTD3-EXECUTION-ACCOUNTING`
5. `VSTD3-CONTINUITY`
6. `VSTD3-COMPLETE-MEDIATION`

Discovery alone is useful. Complete mediation is not required for weaker conformance.

## 2. Minimum device identity

Expose a device-unique or renewable device identity rooted outside mutable host
software. Provide the certificate/endorsement chain, algorithm identifiers, lifecycle
state, revocation inputs, and a stable way to bind physical and logical identities.
Document the root of trust and which host components can request or suppress evidence.

## 3. Measurement evidence

Measure every firmware/configuration component relevant to the claimed boundary.
Export component name, algorithm, digest, version, security/debug state, and enough
identity to select authentic reference values. Clearly distinguish measurement from
appraisal; reporting a digest is not the same as approving it.

## 4. Challenge and signature

- Accept a verifier nonce with at least 64 bits; 128 bits or more is recommended.
- Bind nonce, device/logical identity, measurement set, validity interval, capability
  declaration, and any execution/accounting state into the signed response.
- Reject or make detectable nonce replay.
- Publish certificate-chain and signature verification vectors.
- Define key rotation, ownership transfer, revocation, and failure behavior.

## 5. Accounting event interface

For every governed job expose:

```text
EXEC_START(execution identity, logical device, topology revision)
EXEC_OBSERVATION(typed counters and exact scope)
EXEC_END(outcome, output commitments)
```

Each event needs device ID, partition ID, execution ID, epoch, uint64 sequence,
timezone-qualified timestamp or explicitly non-wall-clock time, payload digest,
predecessor root, rolling root, and signature.

Document every counter's unit, increment rule, overflow behavior, reset behavior,
precision, uncertainty, and whether it is exact, estimated, or an upper bound.

## 6. Continuity and reset

- Start sequence zero in an explicit boot/reset epoch.
- Persist or externally anchor the current rolling root.
- Make missing positions, forks, replay, rollback, and wrap detectable.
- A reset must create a new epoch naming the prior epoch and root.
- Bind the prior root to an external anchor where the platform permits.
- Never silently relabel an unavailable pre-reset history as continuous.

## 7. Partition and topology semantics

Expose parent physical identity for MIG-like slices, SR-IOV/VFs, cloud slices,
packages/chiplets, shared devices, pods, and multi-device logical accelerators. Report
partition configuration changes as authenticated events. Bind executions to an exact
topology revision. Define a non-overlapping capacity/accounting rule that prevents
physical/logical double counting.

Include trust-bearing switches, DPUs, SmartNICs, fabric adapters, PCIe functions, and
management controllers when they are inside the attested execution boundary.

## 8. Complete-mediation review

Before claiming `VSTD3-COMPLETE-MEDIATION`, answer with implementation evidence:

1. Which submission paths can cause governed execution?
2. What hardware/firmware gate forces each path through accounting?
3. Can host, debug, management, recovery, or peer-device paths bypass the gate?
4. Can the host suppress events while execution continues?
5. What happens on power loss, reset, update, counter overflow, and key rotation?
6. How does an external verifier detect a missing terminal event or epoch?

Any unanswered material path keeps this profile `UNKNOWN` or `UNSUPPORTED`.

## 9. Adapter deliverable

Provide:

- registry profile and capability declaration;
- lawful public format documentation;
- collector with optional vendor dependencies isolated from the core package;
- raw byte preservation plus normalized VSTD records;
- certificate, signature, nonce, reference-measurement, and freshness verifier;
- deterministic valid and adversarial fixtures;
- trust-root and reference-value provisioning instructions;
- explicit unsupported capabilities and evidence gaps.

Do not require tests to own production hardware.

## 10. Required conformance vectors

At minimum include normal boot, valid nonce, wrong nonce, stale evidence, altered
measurement, invalid signature, device substitution, two jobs, partition change,
interrupted job, deleted/reordered/duplicate/forked event, reset with and without prior
anchor, sequence rollback/wrap boundary, wrong topology, and estimator mislabeled
exact. The expected result for each vector must be one of `PASS`, `FAIL`, `UNKNOWN`, or
`UNSUPPORTED`.

## 11. Evidence package handoff

The verifier must be able to reconstruct exactly which bytes were authenticated and
which policy approved each measurement. If a proprietary library is required, publish
its version, inputs/outputs, error mapping, and a public fixture verifier where legally
possible. VSTD will not treat an opaque “verified” Boolean as self-authenticating.

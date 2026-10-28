# SIM-2.4 fresh source-bound execution variant

Simulation (SIM); central processing unit (CPU). The semantic identifier is
`verifier-sim-resource-fresh-execution-1`, separate from the registered historical
[signed-resource contract](CURRENT_SIM_RESOURCE.md). Numeric `vstd polish 2`
selects this variant explicitly in its replay registry and reason ledger.
General historical route dispatch is unchanged. No old certificate gains PASS.

## Necessity, applicability, and scope

Resource records are necessary because the selected interpreter actually
executes transitions. Limits and operation counters do not measure consumption.
For this variant the resources claimed are thread CPU nanoseconds and peak
traced Python allocation bytes, for every transition in one exact selected
passing SIM-2.1 finite trajectory. Missing, reordered, substituted or nonnumeric
step records refute the bounded correspondence. Zero CPU ticks are permitted:
the operating-system clock can have coarser resolution than a short transition.

The meter brackets each transition, excluding validation, child startup, imports
and post-measurement state comparison. CPU includes interpreter and tracing
overhead; allocations include traced interpreter overhead. Traced allocation
peaks are neither total memory nor resident memory. Metrics are not subtracted,
normalized to a fabricated baseline, or compared across runs for equality.

Historical execution attribution is conditional on making a historical claim.
No such claim is made here: every recheck starts a new process. Therefore the
historical condition is not triggered for this selected proposition, with the
new invocation and its bindings serving as the reason. Historical signed-record
claims remain UNKNOWN; signature possession is not collector honesty.

Physical-model reliability, whole-device utilization, energy, accelerator use,
cloud billing and production-customer workloads are outside this variant's
declared proposition. Claims about them need separately applicable mechanisms.
This scope is a bounded fulfillment variant, not a waiver of SIM-2.4, nor proof
that other resource obligations can never apply to another object variant.

## Direct source provenance

The invocation certificate contains only selected data, exact child request and
policy, workload digest and source policy. It contains no PASS and no metrics.
The parent snapshots a closed nine-module package dependency set (including an
explicit empty namespace package). Numeric replay compares all those bytes and
the bootstrap against the selected repository, including for an installed wheel.

An isolated `python -I -S -B` child receives the parent's fresh random challenge,
workload and installed source snapshot. It verifies and materializes those exact
bytes under a private temporary import root, refuses Verifier imports outside
the manifest, and rechecks every imported file before measurement; bytecode and
alternate installed Verifier packages cannot supply executed code.
The bootstrap itself is passed as exact selected bytes. The child records which
module bytes it loaded. The parent checks the entire loaded manifest, challenge,
workload, method, run identity, complete step inventory and exact state digests,
then rechecks source and mechanism stability. Caller requests cannot supply code.
The full observation, not merely its hash, is retained in the native receipt.

The installed parent mechanism, CPython and standard library, operating system,
process pipes, thread clock and allocation tracer remain explicit trusted
components. This is direct local source provenance, not independent execution
attestation, secure-enclave evidence, or protection against a hostile host.
Source pins alone do not prove execution. A copied observation cannot be fed
back as an invocation certificate. Reading a retained observation cannot
authenticate its historical metrics; reproducing it means making a NEW run.

Timeout or unavailable execution yields UNKNOWN; a binding contradiction yields
FAIL. Input, output, transition-operation and item counts are bounded. The child
is not an operating-system memory sandbox; no such safety claim is made.

## Numeric Tier-2 integration

The selected denominator remains 37 Dynamics obligations, with 111 control
cases. SIM-2.4 uses this explicit variant's positive fresh execution, malformed
input refutation and absent-evidence UNKNOWN. The original historical route's
own positive remains UNKNOWN and is regression-tested separately. Catalog
closure retains the original route identity plus the selected variant digest.

Two fresh native replays must agree on exact selections, source, all statuses
and every deterministic result field. Their distinct observations and resulting
digest chains are both retained. Selection comparison is not authentication of
either historical observation. Whole-application conformance, host attestation,
release authority, publication and deployment remain unestablished.

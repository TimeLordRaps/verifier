# Current native simulation-checker dynamics

Verifier Standard (VSTD) registers `VERIFIER-2.1` under semantic version
`verifier-current-object-obligations-1`. Simulation (SIM) means the generative
simulation specification. This is one bounded dynamics objective for a VERIFIER
whose executable checking operation is `verifier.domains.sim.evaluate`.

## Exact proposition

For the independently selected installed native simulation checker, exact finite
input cases, check names, expected outcomes and resource bounds, every selected
invocation reproduces its selected positive result or explicit refutation.

This establishes finite input/output correspondence. Expected outcomes must come
from separately selected acceptance conditions, such as an analytic oracle. The
request formatter never runs cases to invent those expectations. A positive
correspondence result does not establish that the selected expectations are a
complete or correct specification of arbitrary simulations or of the checker.
A selected expected refutation may match a native FAIL while the correspondence
objective passes: the underlying simulation claim remains refuted. Native UNKNOWN
never supplies a passing correspondence result. A demonstrated mismatch remains
FAIL even if another invocation is unavailable.

## Selection and mechanism

The request binds the subject identifier and exact namespace object record digest,
fixed installed checker, exact case-set digest,
ordered case/check pairs, each input digest, expected native outcome, per-invocation
operation limits, aggregate operation limit, item and capture limits, proposition
registration and independently supplied policy. Duplicate invocation pairs, unsupported
check names and missing external selection refuse admission. The policy binds the
installed mechanism, native checker, shared primitives, evidence engine, canonical
encoding, strict reader, namespace implementation, this specification and interpreter implementation/version.
Trust-root labels are declarations of selected assumptions, not authenticated authority.

Evidence is retained canonical JavaScript Object Notation (JSON), containing the
exact `checker_object` and selected case identifiers with each case's artifact and inputs.
The object is a `VERIFIER` with no operands and exactly three payload fields:
`checker_kind=CHECKER`, `checker=verifier.domains.sim.evaluate` and the policy's
`mechanism_digest`. Reconstructing the namespace record must reproduce the selected
identifier, digest and canonical bytes. This narrow record describes the fixed
installed checker; it establishes no collection closure. Secure Hash
Algorithm 256-bit (SHA-256) digests bind exact retained bytes and canonical input
records under the collision-resistance assumption. The evidence engine resolves the
selected bytes before the checker executes. Every selected native call receives a
fresh bounded operation budget capped by remaining aggregate work. The same installed
native implementation runs again during certificate replay; producer result text
cannot substitute for this execution. Complete rebuilt certificate bytes must match.

Admission captures plain built-in values before callbacks. Transport is capped at
four mebibytes of evidence and eight mebibytes of certificate bytes; capture depth
is at most 48 and integer width at most 4,096 bits. Caller-selected limits can lower
the evidence, capture-node, native-item, invocation-count and aggregate-operation
ceilings. Operation, item, node and invocation counts are dimensionless; byte bounds
measure retained or encoded bytes. Model state, actions and time retain the supplied
model's units. These bounds do not establish a physical memory or wall-clock sandbox.

The fixed check set is replay, invariants, refinement, channels and shards. No arbitrary
code, plugin path or producer-supplied executable is loaded. No witness keys are
admitted by this objective, so native checks requiring an external witness key remain
UNKNOWN. Resource exhaustion, absent evidence and unsupported native expression
semantics remain UNKNOWN. Inconsistent case inventories, input commitments or expected
outcomes FAIL. Malformed external requests and substituted certificates refuse replay.

## Boundaries and compatibility

`class_wide_soundness`, `historical_execution`, `effect_confinement`,
`public_checkability`, `object_profile_conformance` and `authority` remain
`NOT_ESTABLISHED`. The trusted installed code, interpreter and host are assumptions;
source hashes do not attest runtime integrity or historical producer execution.
Reward, episode-ending and physical-law claims outside selected native checks are
excluded. Local checking grants no authority to publish retained evidence.

This objective is separate from current `SIM-5.1` effect confinement and from the
legacy VERIFIER proof-certificate catalogue. No legacy receipt changes meaning and
no legacy PASS transfers by shared coordinate spelling. One registered dynamics
objective does not discharge the whole tier, the remaining numbered objectives,
or the nine-tier object profile. A future class-wide checker-soundness objective
requires its own exact proposition, mechanism and independently justified oracle.

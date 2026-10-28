# Current HARDWARE-2.1 retained capacity reservations

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python reference checker replays one
bounded proposition. JavaScript Object Notation (JSON) retains exact bytes and
Secure Hash Algorithm 256-bit (SHA-256) names commitments. MEMORY_BYTE and
STORAGE_BYTE measure bytes. COMPUTE_SLOT and SAMPLE_SLOT are dimensionless
counts local to a named device. Times are nonnegative integer microseconds on
one declared clock; this check does not authenticate that clock.

The pair `verifier-current-object-obligations-1` / `HARDWARE-2.1` selects the
current dynamics proposition that simultaneous declared occupancy in retained
half-open reservation intervals never exceeds the declared capacity for each
device and unit. It is distinct from the retained legacy domain-certificate
`HARDWARE-2.1` wire meaning; its native arithmetic is reused only after new
selection, evidence retention and replay. A coordinate without its semantic
version cannot select this certificate. Current `HARDWARE-1.3` checks retained
inventory consistency but does not check reservations.

The externally selected exact HARDWARE namespace record occurs once in a
selected finite typed collection whose commitment replays. Its payload contains
exactly `scope=retained-hardware-records`, `clock`, `devices_digest`, and
`allocations_digest`. Retained `devices` and `allocations` rehash to those
commitments. Each device has a unique identifier, supported kind and typed
nonnegative integer per-unit capacities. Every reservation has a unique
identifier, a named device and declared unit, positive integer quantity and a
nonempty half-open `[start_us,end_us)` interval. Overlap is swept separately for
each device and unit; releases at an instant precede acquisitions at that same
instant. Empty allocations may PASS only after a nonempty retained device
inventory has reproduced. The checker does not pool capacities across devices
or unlike units.

The request binds semantic version, proposition digest, exact subject and
collection digests, retained byte reference, selected policy and finite limits.
The policy selects the installed source/specification digest, labelled trust
roots and certificate byte bound. The certificate retains the evidence bytes;
public replay reconstructs it under separately selected request and policy.
`PASS` means only this finite declared occupancy relation reproduced. `FAIL`
means retained records contradict it. `UNKNOWN` means required retained bytes
or selected checker capacity is unavailable. Substituted request, policy or
certificate is rejected before a computational verdict.

Trust-root labels do not authenticate the devices, observer or clock. Physical
capacity, live availability, actual reservation enforcement, delivered work,
resource ownership, capacity-backed credit issuance, privacy, consent,
governance, security, whole HARDWARE dynamics tier and object-profile
conformance remain `NOT_ESTABLISHED`. No scheduling, spending or publication
authority follows from this certificate.

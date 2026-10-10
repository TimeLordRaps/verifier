# Current HARDWARE-2.2 retained measurement envelope

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python reference checker replays one
bounded proposition. JavaScript Object Notation (JSON) retains exact bytes and
Secure Hash Algorithm 256-bit (SHA-256) names commitments. MEMORY_BYTE and
STORAGE_BYTE measure bytes. COMPUTE_SLOT and SAMPLE_SLOT are dimensionless
counts local to one device. Quantities, capacities and instants are bounded
integers from zero through `2^53-1`; instants are microseconds on one declared
clock. This route does not authenticate that clock.

The pair `verifier-current-object-obligations-1` / `HARDWARE-2.2` checks that
each retained integer observation names one declared device and capacity unit,
has a unique identifier and declared instant, and lies from zero through that
device's declared capacity inclusive. It reuses the older native measurement
envelope arithmetic under a distinct current selection, retained evidence and
certificate. The old domain-certificate wire meaning is unchanged. A coordinate
without its semantic version cannot select this objective.

The externally selected exact HARDWARE namespace record occurs once in a
selected finite typed collection whose commitment replays. Its payload has
exactly `scope=retained-hardware-records`, `clock`, `devices_digest`, and
`measurements_digest`. Retained `devices` and `measurements` rehash to those
commitments. The devices have unique identifiers, supported kinds and typed
nonnegative integer capacities. Measurements have unique identifiers and
exactly `id`, `device`, `unit`, `quantity`, and `at_us`. A nonempty device list
with an exact empty measurement commitment may PASS with zero observations.
Unlike reservations, samples are not summed even when they name the same
instant. This route does not infer a trend, sampling completeness or a current
reading.

The request binds semantic version, proposition digest, exact subject and
collection digests, retained byte reference, selected policy and finite
limits. The policy selects the installed source/specification digest, labelled
trust roots and certificate byte bound. The certificate retains the evidence
bytes; public replay reconstructs it under separately selected request and
policy. `PASS` means only this finite declared envelope reproduced. `FAIL`
means retained records contradict it. `UNKNOWN` means required retained bytes
or selected checker capacity is unavailable. Substituted request, policy or
certificate is rejected before a computational verdict.

Trust-root labels do not authenticate the physical devices, observers,
sensors or clock. Calibration, sensor accuracy, signed observation authority,
live availability, actual delivered work, ownership, compute credits,
privacy, consent, governance, security, whole HARDWARE dynamics tier and
object-profile conformance remain `NOT_ESTABLISHED`. No scheduling, spending
or publication authority follows from this certificate.

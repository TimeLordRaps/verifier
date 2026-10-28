# Current simulation resource capture: selected per-step local measurement

Verifier Standard (VSTD) registers a bounded `SIM-2.4` replay under
`verifier-current-object-obligations-1` while retaining its actual-consumption
correspondence as UNKNOWN. Simulation (SIM) is a generative simulation
specification. This mechanism investigates one part of the legacy numbered-profile
wording, “The resources the transition actually consumes per step are recorded.”
It does not reinterpret legacy receipts.

## Proposition and measurement method

For an exact passing `SIM-2.1` child trace, the bundled fixed meter runs the
native finite transition interpreter in an isolated CPython
subprocess. It records thread central processing unit (CPU) time in nanoseconds
using `time.thread_time_ns`, and peak traced Python allocations in bytes using
`tracemalloc`. One nanosecond is 10^-9 second. The allocation counter covers
Python allocations traced between per-step start and stop; it is not resident
set size. Per-step timing includes interpreter and tracing overhead. The meter
first checks the complete selected transition trace, then measures each exact
transition again and checks its output state. Values may vary between runs.
It returns a random run identifier, local process identifier, target version,
worker-source digest and one record per selected step. These identifiers bind
records within the local execution; they do not attest the host or signer.

`assess_fresh_sim_resource` invokes that fixed worker from the current
Verifier process. A `PASS` from this application programming interface (API)
means the new bounded replay produced one local observation per selected step
under the installed interpreter and host assumptions. A second call starts a
second run with a different run identity and potentially different timing and
allocation values. It never compares those numbers with retained historical
producer metrics. A wrong child, incomplete step inventory, altered state
commitment, worker failure or timeout refuses the local observation. This is
a measured current-workload sample, not a portable historical-use certificate.

The auxiliary `capture_sim_resource_evidence` helper may sign an exact fresh
record, including child bytes, input/output state commitments, method, target,
run identity and measured values. The signer key must be explicitly admitted
by the external policy for signed-record replay.

The signing public key must be explicitly admitted by the external policy.
The auxiliary checker independently rechecks the exact `SIM-2.1` certificate,
requires one structurally valid step per selected transition, binds each to
the exact retained state commitments, checks the installed meter source digest
and verifies the collector's Ed25519 signature. A changed signed metric,
wrong child, missing step or substituted state fails the signed-record check.
Missing selected capture or unavailable child is `UNKNOWN`; a failed child is
`FAIL`. Malformed external selections and substituted certificates are
refused. The certificate
itself is deterministic because it rechecks retained signed measurements;
it does not demand numerically identical new profiling samples. The current-object
route replays this exact bounded certificate. The certificate reports
`signed_record_status` separately, but its overall status remains `UNKNOWN` for
a valid signed record because actual historical consumption correspondence is
unproved. It therefore cannot pass a polished `SIM-2.4` objective. A structural
or cryptographic contradiction remains `FAIL`.

The signature and source digest authenticate a **statement under an admitted
key**, not the honesty of the collector or whether that key ran this meter.
The capture helper runs the bundled meter, but a caller controlling a signing
key can sign false numbers. Real-world collector identity, host attestation,
historical execution, physical device attribution, whole-device CPU, total
memory, energy, graphics processing unit (GPU) consumption and billing remain
`NOT_ESTABLISHED`. The subprocess has an input/output bound and a wall timeout;
the current Windows worker has no operating-system memory cap. Resource caps
and the interpreter's deterministic operation budget are not measurements.

This helper does not establish the whole dynamics tier, object profile,
privacy, consent, governance, security, or publication authority. A public
reader can recheck bytes and signature under the named trust root but must
make its own decision about that collector's legitimacy. A fresh verifier-owned
measurement may establish observations of its **new bounded replay** only;
it cannot validate the retained historical metrics by approximate resemblance.

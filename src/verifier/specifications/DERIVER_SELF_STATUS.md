# Experimental actual deriver self-status

Verifier Standard (VSTD) actual deriver self-status is a direct-module version
0.1 experiment. It records one bounded process invocation and independently
reruns the same exact invocation before classifying the declared output. It is
distinct from the retained structural `self_derivability` axis.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8); American Standard Code
for Information Interchange (ASCII); identifier (ID). Byte sizes and elapsed
milliseconds are the only dimensional record fields; other counts and IDs are
dimensionless.

## 1. Declaration and runtime coordinate

`VSTD-DERIVER-SELF-STATUS-0.1` binds the deriver ID, subject digest, exact
executable and runtime coordinate, ordered arguments, sorted public environment,
base64url-encoded standard input and digest, expected standard-output and
standard-error digests, expected exit code, timeout, and output bound.

The runtime coordinate contains runner ID, operating system family and release,
machine identifier, Python operating-system name, executable digest, and
executable byte size. The registered runner is
`vstd.bounded-subprocess.0.1`; supported operating-system families are Darwin,
Linux, and Windows. This is exact-coordinate compatibility, not a claim that one
run transfers across operating systems.

Environment names are uppercase ASCII identifiers. Values are retained in
clear text and therefore may contain only explicitly public, non-secret values.
The runner supplies a fresh empty working directory and only that declared
environment. It is not a sandbox and does not bound processor or memory use.

## 2. Invocation receipt and recheck

`VSTD-DERIVER-SELF-STATUS-RECEIPT-0.1` retains the declaration and runtime
coordinate, invocation state, exact standard-output and standard-error bytes and
digests, process exit or termination signal, elapsed time, declared bounds,
checker-profile digest, and sorted reason codes. Invocation states distinguish
`COMPLETED`, `NOT_RUN`, `TIMED_OUT`, `OUTPUT_LIMIT_EXCEEDED`, `START_FAILED`,
and `CAPTURE_FAILED`.

The checker profile is retained as
`verifier/profiles/deriver-self-status-checker-0.1.json`. A receipt is an
observation record, not the final self-status. The rechecker:

1. strictly decodes and binds declaration, receipt, profile, runtime, and exact
   executable bytes;
2. requires a completed recorded invocation;
3. reruns the exact invocation in another fresh empty directory;
4. requires byte-identical standard output and error plus the same process
   disposition; and
5. compares the reproduced result with the declaration's expected output.

The returned in-memory assessment uses `ESTABLISHED`, `REFUTED`, `UNKNOWN`, or
`INVALID`. `ESTABLISHED` means two bounded invocations at the same exact runtime
coordinate reproduced the declared exit and output bytes. `REFUTED` means the
reproduced transcript is stable but disagrees with the declared expectation.
Unavailable coordinates and resource exhaustion remain `UNKNOWN`; malformed,
substituted, or internally contradictory evidence is `INVALID`.

Public JSON Schema validation is structural only. It cannot prove canonical
encoding, exact executable identity, runtime availability, invocation, transcript
reproduction, or assessment status.

## 3. Bounds and claim boundary

Declarations are at most 131,072 bytes; executables 67,108,864 bytes; standard
input 65,536 bytes; combined captured output 1,048,576 bytes; timeout 60,000
milliseconds; arguments 64; and public environment entries 32.

An `ESTABLISHED` assessment does not establish source semantics, structural
self-derivability, ground origin, general determinism, completeness, global
behavior, safety, authorization, confidentiality, sandboxing, producer
independence, a different runtime, or a numbered VSTD profile.


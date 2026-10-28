# Selected validation: retained grocery-list bytes

This experimental Verifier Standard (VSTD) example defaults to one selected-validation
round, with an optional bounded two-file loop: full geometry analysis → bound plan → host-approved selection →
builtin check over retained bytes → coordinate-only update → full reassessment → replay.
It is follow-on development in the unreleased 2.0.0 source, not part of any tagged release.

## Run

From a source checkout with its `src` directory on `PYTHONPATH`:

```sh
python -u examples/selected_validation/demo.py
```

No optional dependencies, network, package installation, or arbitrary component execution
are involved. The example reads at most 4097 bytes from the adjacent
[`artifact.txt`](artifact.txt), rejects inputs exceeding 4096 bytes, and prints a
JavaScript Object Notation (JSON) execution record. It writes no files.

The expectation is a literal digest pinned in [`demo.py`](demo.py), separate from
runtime acquisition. The file contains `apples`, `bread`, and `tea`, each followed by
a single line-feed byte. Secure Hash Algorithm 256-bit (SHA-256) checks the exact
supplied bytes against that expectation; changing line endings or adding an item
changes the result. Computing the expectation from the bytes under test would check
a tautology and is not this example's runtime procedure. The pinned expectation is
maintainer-supplied demonstration data, not independent provenance.

## Bind a retained component package

```sh
python -u examples/selected_validation/demo.py --package
```

This mode additionally captures the checkout's builtin primary source file and license
text, at most one megabyte each, into a stored component package. It does not download,
extract, install, or import that package. The package is retained in the request, and
the plan keeps `binding_scope=STORED_PACKAGE` with its exact `package_digest` through
execution and replay. The ordinary invocation remains `REGISTRY_ONLY`.

The package-selected implementation must explicitly bind `src/verifier/core/evidence.py`.
Its retained digest must match both the bound proposition and the host's builtin mechanism
digest. This checks primary-source byte correspondence, not loaded-code attestation,
dependency completeness, interpreter qualification, publisher authenticity, or a license
grant. The host still supplies its already-installed builtin explicitly; source bytes
in the package never become executable authority.

Attached dependencies of the selected implementation are rejected as unresolved even if
their bytes are retained. Dependencies of unselected implementations remain in the full
package and plan without being treated as executed or resolved. The host runtime and
its imports remain an explicit trust boundary. The reference catalog's larger source
snapshot is not thereby qualified for execution.

Changing any retained package bytes or declarations changes the request and plan and
invalidates reuse of its previous host approval. There is no silent conversion from
package-bound planning to registry-only execution. Registry-only records retain
`verifier-selected-digest-execution-1`; package-bound records use the distinct
`verifier-selected-digest-execution-2` identifier. Mixed formats are rejected.

## Bounded multi-step loop

```sh
python -u examples/selected_validation/demo.py --loop
python -u examples/selected_validation/demo.py --loop --package
```

The loop checks two predeclared byte coordinates, for `artifact.txt` and
[`pantry.txt`](pantry.txt), in that order. Each has a separately pinned literal digest.
Every target must already be eligible in the complete initial geometry; a missing or
unsupported target rejects the whole contract before execution. There is no dynamic
candidate search or silent skipping of an ineligible target.
After every attempt it reanalyzes and replans the **complete** updated geometry, including
after a terminal negative or uncertain result. It retains each selected-execution record
and the final geometry, analysis, and plan. Package mode preserves the same package in
every child request; registry-only mode remains explicitly separate.

The example host approves the exact initial loop contract: geometry, registry, optional
package, ordered distinct targets, expectations, evidence references, mechanism identity
and digest, and work limits. Child requests and approvals are derived only inside this
approved bounded operation, never from fields in a supplied execution record. There are
no arbitrary component callbacks, adaptive authority expansion, or mid-loop revocation
and expiry checks. The previously described host-process trust boundary still applies.

The default limits are two attempted steps and 8192 reserved evidence bytes. Before each
attempt, its declared 4096-byte cap is charged against that reservation budget, without
refunds for smaller or unavailable inputs. These are admission ceilings, not measured
work, bytes verified, elapsed time, or total record size. The demonstration acquires its
two local files first with separate 4096-byte limits; the loop does not perform filesystem
acquisition. Host transport and input-memory limits remain separate.
The existing evidence-store lookup rehashes a supplied payload before checking its
admission size, so the reservation does not bound pre-admission hashing work. Hosts
must bound acquisition and store population separately, as this example does.

The loop admits only digest-checked input within the step's cap. Missing, corrupt, or
oversized caller input becomes unavailable `UNKNOWN`; it does not retain oversized bytes
or claim why external input was unavailable. Replay uses each step's retained admitted
snapshot rather than merging evidence availability across steps. It derives the order,
requests, geometry transitions, reservations, stop reason, and final plan again.
Replay snapshots the complete input record at entry, so later caller mutation cannot
change its comparison target. This is input binding, not hostile-process isolation.

Stops are explicit: `TARGETS_EXHAUSTED`, `STEP_BUDGET_EXHAUSTED`,
`EVIDENCE_BUDGET_EXHAUSTED`, `FAILED`, or `UNKNOWN`. Before an attempt, exhausted targets
take precedence over the step limit, which takes precedence over its evidence reservation.
After an attempt, `FAIL` or `UNKNOWN` stops immediately following full reassessment.
Malformed or unauthorized contracts are rejected before execution, not converted to a
passing stop. Unattempted targets remain in the record.

The unchanged two-file example ends at `TARGETS_EXHAUSTED` with two passing byte checks.
That is **not** complete verification geometry: shopping-list completeness and mechanism
self-verification remain unresolved, so ordinary and self closure remain false.
This loop is still a follow-on experimental interface in the unreleased 2.0.0 source, not
part of any tagged release or a general conflict adjudicator or verifier-discovery service.

## Single-step result and common limits

The unchanged specimen produces `PASS` and changes only its byte-digest coordinate
from `INDETERMINATE` to `VERIFIED`. A mismatched specimen produces `FAIL` and
`FALSIFIED`. Missing evidence, absent checker registration, or exceeded execution
evidence bounds produce `UNKNOWN`, leaving the coordinate `INDETERMINATE`.
Malformed, stale, unsupported, or unauthorized requests are rejected before invocation.

The separate shopping-list completeness coordinate stays `INDETERMINATE`.
`ordinary_closed` and `self_closed` remain false. Assumptions, limitations, other
judgments, and unresolved mechanism boundaries remain in the reassessed geometry.
A passing invocation does not make its mechanism `post_verified`.

`DigestHostPolicy` defaults to denying execution. This example explicitly configures
the trusted local host to approve this exact request and builtin checker. Approval
is not read from the portable record, and replay needs separately supplied host approval.
Policies are reusable: expiry, revocation, freshness, and one-time use are not enforced
by this module and remain the host's responsibility. A caller
controlling the host's Python process can replace its policy: this is not authentication,
privilege isolation, or a sandbox. Evidence bounds limit item counts and bytes, not
wall-clock time or transport parsing; the host must separately limit incoming record
size. The executor binds the declared address to the supplied bytes; it
does not independently retrieve or attest that address.

The output retains evidence bytes and the original request, evaluation, and full
before/after analyses. Replay rehashes the bytes, reruns the checker, and compares
the complete record. Matching replay establishes reproducibility with this checker,
not independent correctness, historical authorization, or numbered-profile conformance.
For untrusted JSON text use `verifier.core.receipt.strict_json_loads` before the
record reader; ordinary parsers can discard duplicate keys before validation sees them.

This direct experimental module does not execute package-supplied code, discover arbitrary
verifiers, adjudicate conflicts, acquire remote evidence, enforce confidentiality of
awareness, or complete every surface hole. The existing planning/readiness facade
remains nonexecuting. See the [application programming interface (API) boundary](../../docs/API_STABILITY.md).

## Reproduce the focused tests

With the repository's test dependencies installed:

```sh
python -u -m pytest tests/test_selected_execution.py tests/test_selected_package_execution.py tests/test_selected_validation_example.py tests/test_validation_loop.py tests/test_validation_loop_example.py -vv -s --durations=10 --timeout=60
```

These tests concern this selected byte-identity mechanism and its boundaries; they
are not cross-platform, independent-implementation, deployment, or release evidence.

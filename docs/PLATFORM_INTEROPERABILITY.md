# Platform interoperability

> **Acronyms:** 64-bit Arm instruction-set architecture (ARM64);
> application programming interface (API);
> Concise Binary Object Representation (CBOR); command-line interface (CLI);
> CBOR Object Signing and Encryption (COSE); continuous integration (CI);
> Java unit test report format (JUnit); JavaScript Object Notation (JSON);
> operating system (OS); reduced instruction set computer (RISC);
> Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD);
> Windows Subsystem for Linux 2 (WSL2); ZIP archive format (ZIP).

This document records where the Verifier Standard (VSTD) reference repository has
platform evidence and where it does not. Its machine-checked reference-component
table is separate from the broader evidence-surface summary. Neither is a declaration
that every verifier, prover, solver, adapter, or dependency works on every operating
system (OS).

## Evidence coordinates and freshness

Three surfaces must stay separate: source-controlled **test intent**, an exact hosted
**observation**, and the **candidate being evaluated now**. The generated component
table below records intent. Its `CONFIGURED_UNRUN` labels do not assert that a component
has never run; they cannot be promoted to support claims inside a source manifest.

For the current candidate, select its successful `repository-checks` run from
[pull request #31](https://github.com/TimeLordRaps/verifier/pull/31) or the
[workflow history](https://github.com/TimeLordRaps/verifier/actions/workflows/ci.yml).
These are discovery links, not immutable evidence. Require the exact head, base,
executed checkout, run identifier and attempt in the retained reports. Retargeting a
request or retaining an earlier green check does not establish fresh integration.
Publication additionally requires a successful push run on the exact final `main`
commit, as specified in [the release procedure](../RELEASING.md).

A changed implementation, catalog, test, workflow or dependency requires reassessment;
the prior run remains an observation of its own coordinate. Native results do not
inherit another component's tests, and recorded environment metadata is not hardware
or runtime attestation.

## Recorded candidate observation

[Run 34077770237](https://github.com/TimeLordRaps/verifier/actions/runs/34077770237),
attempt 1, completed successfully for head
`b6b1a82b862219ffc3c44bb2f4b544444d921715`, base
`499c0613c93232628abfdeb497d907549fd593fc`, and executed pull-request merge
`884b3cfc9dd36ac0914a5482bece0c13abf33f64`. The executed and head trees both equal
`5135df58006e602606e9a8f304ac43d4e83d186e`. This is a pre-retarget observation, not
evidence for a later candidate or the final release commit.

All four component reports were reconstructed byte-for-byte from their retained raw
environment and JUnit documents with the repository builder. That is reproducibility
of report construction, not a second native execution or an independently implemented
checker. Each environment records CPython 3.12.10; all four record zero failures/errors.

| Recorded coordinate | Passed test instances | Skipped test instances | Skipped collection placeholders |
|---|---:|---:|---:|
| Linux x86-64 / Ubuntu 24.04 | 1,114 | 1 | 1 |
| Windows x86-64 / Windows Server 2025 | 1,109 | 6 | 1 |
| Intel macOS / macOS 15 | 1,114 | 1 | 1 |
| Apple ARM64 macOS / macOS 15 | 1,114 | 1 | 1 |

Collection placeholders are not executed tests. Parameterized instances are not counts
of independent mechanisms. The reports map 18 catalog entries through 13 test modules
and 413 mapped instances; shared tests and wrappers do not become independent verifiers.
The raw reports retain the exact skip reasons. Unavailable optional mechanisms and
platform-specific filesystem cases do not earn passing coverage.

## Evidence classes

- **Hosted execution**: a CI job executes the named component on the named OS. A
  successful exact run is still bounded by its runner image and inputs.
- **Packaging only**: the distribution is built and checked on that OS; this does not
  exercise every installed mechanism.
- **Static or artifact-only**: tests inspect source, configuration, or recorded bytes
  without executing the native mechanism.
- **Documented local execution**: the repository records a local run and reproduction
  procedure, but CI does not currently repeat it.
- **Unsupported by this repository path**: the checked-in procedure does not offer a
  native path for that OS. This says nothing about what an upstream project might
  support.
- **Unknown**: no current repository evidence establishes support or incompatibility.

## Evidence-surface summary

The observations in this table refer only to the recorded candidate above. For another
head, apply the freshness rules and inspect its own run. A complete-suite pass covers
collected, non-skipped cases, not every possible behavior of every exported function.

| Surface | Recorded execution or packaging scope | Boundary |
|---|---|---|
| Python reference contracts | Python 3.10–3.13 on Linux; complete Python 3.12 suite on Linux, Windows, Intel macOS and Apple ARM64 macOS | Exact tests and optional profiles, with skips retained; no universal native-adapter qualification. |
| Generic-run capture and platform comparison | Linux, Windows and Intel macOS run the same portable specimen; an aggregate compares their declared receipt results | Isolates the operating-system dimension only when non-platform bindings match; Apple ARM64 contract tests do not establish cross-architecture equivalence. |
| Release artifact byte reproducibility | Builds on Linux, Windows and macOS; aggregate compares the artifact sets | Packaging reproducibility, not runtime equivalence. |
| Installed-wheel smoke | Selected public commands exercised on Linux outside the source checkout | Not an installed-wheel claim for every platform or command. |
| Core receipts, geometry, Graph, evidence replay, catalog, packages, planning and workflow | Their collected Python cases are included in the four-coordinate suite | Each native result retains its scope; planning and workflow metadata do not become execution or conformance. |
| SCITT cryptographic example | Optional profile exercised on all four coordinates using local test keys and a local test log | Signature and inclusion checking do not establish public registration, payload truth, independent implementations or issuer authority. |
| Artifact freeze, finite seal and thaw | Optional cryptographic profile exercised on all four coordinates | Filesystem-specific skips remain excluded; no privileged-write prevention, trusted time or general network-filesystem guarantee. |
| RISC Zero native prover/verifier | Hosted checks inspect source and recorded artifacts, not a fresh native proof execution; the documented local path is Linux x86-64 under WSL2 | No native Windows path or established macOS support from this repository evidence; no external witness-truth or VSTD receipt-mapping claim. |
| Other native prover, verifier, solver, hardware or vendor adapters | `UNKNOWN` without their own exact mechanism and execution evidence | No support is inherited from a descriptor, wrapper, package or unrelated Python test. |

## Machine-checked reference-component contract intent

The new [stored component format](COMPONENT_PACKAGES.md) is also exercised by the
complete-suite jobs, including a fixed canonical-digest specimen, exact binary-byte
round trips and package-selected planning. The recorded observation establishes only
those executed cases at its named coordinate; changed candidates require their own
reports. Portable storage does not qualify a retained native implementation.
Storage is supporting infrastructure, not an extra
independent verifier counted in the 18-component inventory below.

The source-controlled
[`platform-component-contracts.json`](platform-component-contracts.json) manifest
enumerates exactly the current reference catalog and four separate execution
coordinates. `CONFIGURED_UNRUN` records configured intent only; it is not hosted
execution, compatibility, or support evidence. `BEHAVIOR` means the mapped tests call
the component on bounded positive or adversarial cases. It never means the tests cover
every native input, dependency, filesystem, trust root, or external implementation.

Intel macOS cryptographic coverage is an experimental source-build target.
The pinned `cryptography==50.0.0` dependency follows the upstream
[removal of Intel macOS support](https://cryptography.io/en/50.0.0/changelog/#v49-0-0).
The Intel job explicitly builds `cryptography` and `cbor2` from source with the hosted
runner's Rust and C compilers and Homebrew OpenSSL 3, following the upstream
[source-build prerequisites](https://cryptography.io/en/50.0.0/installation/#building-cryptography-on-macos).
It must pass installation and the complete suite before emitting a report. A successful
run supplies only evidence for that exact build and runner; it does not restore upstream
support or qualify other Intel macOS environments. Apple ARM64 is a separate coordinate.

Raw environment and JUnit files are boundary-checked before artifact upload, including
after a failing test command. Missing or prohibited evidence fails the job and is not
uploaded. The gate does not redact or rewrite the evidence bytes.
The explicit `scripts.pytest_public_evidence` plugin records skip source locations
relative to the declared test root before serialization. It preserves outcomes, reasons,
and line numbers; outside-root locations remain unchanged and subject to the upload gate.

After the complete test command succeeds, CI emits a separate, platform-neutral
`platform-component-contract.json` artifact. Its artifact name includes the workflow run
identifier, run attempt, and platform coordinate. That runtime report binds the exact Git
and workflow coordinate, workflow-file digest, test command, runner image, interpreter,
catalog version and digest, source
manifest digest, the exact raw environment-document digest, JUnit result, component identifiers, test modules, dependency profiles,
and bounded test scopes. The builder also requires at least one successful, non-skipped
test case from every mapped module and rejects malformed or contradictory JUnit suite
counts; a green unrelated subset or summary-only failure cannot populate all component
rows. The environment loader rejects unknown or duplicate fields before binding the raw
document bytes. The raw environment record is uploaded after later-step failures, and the JUnit
report is included whenever the test command produced it. The component report is not
created or uploaded after failure. These hosted artifacts are retained for 30 days; their
presence during that window is not the long-term release record.

For a release, the owner supplies the exact successful `repository-checks` push-run
identifier. The release workflow requires that run to target the tagged commit on the
protected default branch and contain one successful `conformance-gate`. It downloads all
four component reports plus their raw environment and JUnit evidence, independently
reconstructs every report from those raw inputs, and rejects a missing coordinate, mixed
run or attempt, pull-request synthetic merge, changed workflow/catalog/manifest, failed
or contradictory test evidence, altered environment bytes, or byte-altered report. The resulting deterministic platform-evidence ZIP
contains an internal manifest binding every member digest and byte length to the release
tag, repository, commit, run, attempt, and bounded claim. The ZIP is boundary-scanned,
attested, and attached to the immutable release. It retains `verification_effect = NONE`:
durable evidence does not strengthen what the mapped tests establish.

<!-- BEGIN GENERATED PLATFORM COMPONENT CONTRACTS -->
| Reference component | Linux x86-64 | Windows x86-64 | macOS Intel x86-64 | macOS Apple ARM64 | Coverage kind | Test modules | Dependency profile | Bounded test scope |
|---|---|---|---|---|---|---|---|---|
| Artifact freeze and seal verifier<br>`component:artifact-bundle-verifier` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_artifact_control.py` | `seal`, `test` | Exercise exact-byte freeze, finite cryptographic seal, external-anchor, verification, and thaw behavior. Passing does not establish privileged-write prevention, trusted time, or untested filesystem semantics. |
| VSTD-1 generic-run receipt validator<br>`component:generic-run-validator` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_public_cli.py` | `test` | Execute the bounded command fixture, validate and inspect its receipt, and rerun it through the public command-line interface. |
| Experimental exact-graph-bound topology analyzer<br>`component:graph-topology-analyzer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_graph_topology.py`<br>`tests/test_graph_topology_integration.py` | `test` | Exercise exact graph and port binding, structural cycles without inferred contradiction, bounded simultaneous classical Boolean equations, temporal-offset consistency per clock and unit, and public planning integration. Passing does not establish physical causality, runtime control, assurance, or external verifier qualification. |
| Bounded operating-system result comparator<br>`component:platform-run-comparator` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_platform_comparison.py` | `test` | Exercise positive, conflicted, incomplete, malformed, and binding-drift platform-comparison cases over recorded receipts. |
| Recorded provenance policy verifier<br>`component:provenance-policy-verifier` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_public_data.py` | `test` | Exercise provenance-policy acceptance and rejection over bounded data-receipt fixtures. |
| SCITT native-evidence consumer<br>`component:scitt-evidence-consumer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_scitt_crypto_example.py`<br>`tests/test_scitt_interop.py` | `scitt`, `test` | Exercise semantic SCITT evidence mapping plus the local-key cryptographic example. Passing does not establish public transparency infrastructure or production trust roots. |
| VSTD and SCITT adjacent-result composer<br>`component:scitt-result-composer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_scitt_crypto_example.py`<br>`tests/test_scitt_interop.py` | `scitt`, `test` | Exercise bounded adjacent-result composition, mismatch preservation, and the local-key cryptographic example without strengthening either native result. |
| VSTD-Graph assurance-log rechecker<br>`component:vstd-graph-assurance-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise bounded assurance-log replay, dependency handling, and failure preservation. |
| Evidence-bound VSTD-Graph profile rechecker<br>`component:vstd-graph-level-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise evidence-bound Graph-level record rechecking and unresolved-evidence behavior. |
| VSTD-Graph receipt validator<br>`component:vstd-graph-receipt-validator` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_public_data.py` | `test` | Exercise bounded Graph receipt validation, malformed input rejection, and policy interactions. |
| VSTD-1 satisfiability and grounding auditor<br>`component:vstd1-independent-auditor` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_core_receipt_integrity.py` | `test` | Exercise the bundled satisfiability and grounding audit while constructing adversarial receipt-integrity fixtures. |
| Strict VSTD-2 geometry loader and semantic validator<br>`component:vstd2-geometry-loader` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_geometry_io.py` | `test` | Exercise valid geometry loading, canonical normalization, and adversarial structural and numeric rejection. |
| VSTD-3 hardware receipt validator<br>`component:vstd3-receipt-validator` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_vstd3_emulator.py` | `test` | Exercise hardware-receipt validation using deterministic emulated evidence; no physical-device or vendor attestation is established. |
| VSTD-4 evidence-bound receipt rechecker<br>`component:vstd4-evidence-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise evidence-bound receipt replay, mechanism binding, and non-establishment when evidence or mechanisms drift. |
| VSTD-4 grounded decision certificate kernel<br>`component:vstd4-grounded-certificate-kernel` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_public_cli.py` | `test` | Exercise grounded certificate acceptance and refutation through the deterministic public demonstration scenarios. |
| VSTD-4 reverse-unit-propagation proof checker<br>`component:vstd4-refutation-checker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_refutation_certificate.py` | `test` | Exercise accepted and rejected reverse-unit-propagation certificates without inferring formula grounding or external truth. |
| Bounded VSTD-4 refutation proof producer<br>`component:vstd4-refutation-producer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_refutation_certificate.py` | `test` | Exercise satisfiable, unsatisfiable, and resource-bounded proof search with independently checked emitted refutations. |
| VSTD-5 witness corroboration rechecker<br>`component:vstd5-witness-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise witness rechecking while preserving refuted, unknown, conflicted, and independence-limited outcomes. |
<!-- END GENERATED PLATFORM COMPONENT CONTRACTS -->

## Reading a platform-comparison result

The comparator classifies supplied recorded results; it does not certify an OS or a
component in the abstract:

- `PASS` means the complete declared receipt set had matching bound non-platform
  coordinates and matching declared result projections.
- `CONFLICTED` means comparable receipts disagreed on a declared result surface.
- `NOT_ESTABLISHED` means required coverage or comparability evidence was absent or
  did not isolate the OS dimension.
- `INVALID` means an input was malformed, canonically inconsistent, or internally
  contradictory.

A mechanism may be cross-platform compatible even when this repository reports
`UNKNOWN`; the missing fact is evidence, not necessarily capability. Conversely, a
successful generic Python example cannot upgrade a native prover, verifier, solver,
hardware integration, or third-party adapter from `UNKNOWN`.

## Release maintenance rule

For each release candidate, update this matrix only from evidence at the exact release
coordinate. A new platform claim requires, at minimum, a named component and version,
the native or interpreted execution boundary, the OS and machine family, the checking
mechanism, positive and adversarial results, and the exact hosted run or reproducible
local receipt. When any of those dependencies changes, prior evidence remains
historical and current support returns to `UNKNOWN` until it is re-established.

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

- **H1 — historical hosted run:** pull-request head
  [`5c42c4c139553b5fa3f2463289c94112c4b76612`](https://github.com/TimeLordRaps/verifier/commit/5c42c4c139553b5fa3f2463289c94112c4b76612),
  base `56ea9ab1de4ea34a0dc6beabc753444cd2d2c8fb`, and executed synthetic merge
  checkout `582cfa3655d680ef55c773e3e327e166ce8fa379` in
  [GitHub Actions run 33788300817](https://github.com/TimeLordRaps/verifier/actions/runs/33788300817).
  The run was green for its configured jobs. Rows below that say hosted execution or
  packaging refer to H1 unless they name another coordinate.
- **Development delta after H1:** every changed implementation, test, workflow, or
  documentation surface after the H1 pull-request head is outside H1's evidence. A new
  job being configured, a local test passing, or a source change carrying its own tests
  does not turn that delta into hosted platform evidence. Affected rows remain configured
  or `UNKNOWN` until a later exact commit and workflow run supplies the named evidence.

H1 remains historical evidence for unchanged surfaces; it is not evidence for a later
development delta. A release candidate must replace these coordinates with its own
commit and hosted run before any current support statement is promoted.

Continuous-integration configuration describes the checks that a run is
expected to perform. A green hosted result is evidence only for the exact Git commit,
workflow run, runner image, interpreter, inputs, and declared result surfaces in that
run. The matrix does not treat configured-but-unrun jobs, package construction, static
source inspection, or one component's result as execution evidence for another
component.

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

| Component or evidence surface | Linux | Windows | macOS | What the evidence establishes | What it does not establish |
|---|---|---|---|---|---|
| Python reference implementation test suite | Hosted execution on Python 3.10 through 3.13 | Unknown; the full suite is not run there | Unknown; the full suite is not run there | The exact tested propositions pass on the hosted Linux runner for a successful run | Equivalent behavior on Windows or macOS, native-adapter support, or correctness beyond the tests |
| Complete Python 3.12 contract suite and optional integrations | Not exercised by H1; the later workflow configuration targets Ubuntu 24.04 x86-64 | Not exercised by H1; the later workflow configuration targets Windows Server 2025 x86-64 | Not exercised by H1; the later workflow configuration targets macOS 15 Intel and ARM64 separately | A later successful exact run can exercise the complete collected Python suite, including the optional artifact-seal and cryptographic SCITT profiles, while its JUnit report preserves platform-specific skips | Native RISC Zero execution, hardware-vendor attestation, a proposition beyond the tests, or any platform claim before that later run succeeds |
| Generic-run capture, strict validation, and output rerun | Hosted execution on Python 3.12.10 | Hosted execution on Python 3.12.10 | Hosted execution on Python 3.12.10 using an Intel runner; Python records the OS as `Darwin` | Each runner reports the expected OS and executes, validates, and reruns the dependency-free word-frequency specimen | Universal Python portability, other commands or dependencies, native execution attestation, Apple silicon behavior, or independent actors |
| Bounded platform comparator | H1 executed the aggregate on hosted Linux over three uploaded receipts; any later implementation is a development delta until rerun | H1 supplied a hosted Windows receipt to the aggregate | H1 supplied a hosted macOS Intel receipt to the aggregate | `PASS` can establish equality only for one complete set of canonically intact receipts with matching bound non-platform coordinates and declared result projections | That H1 validates a later comparator, that the declaration proved compatibility, that receipt metadata attests native execution, or that all machines and versions agree |
| Release artifact construction and byte reproducibility | Packaging-only build and verification | Packaging-only build and verification | Packaging-only build and verification | A successful aggregate rejects byte differences among the generated archive, wheel, source distribution, manifest, and software-bill-of-materials artifact sets | Runtime equivalence, semantic correctness, or execution of every packaged feature |
| Installed-wheel command smoke | Hosted execution on Linux outside the source checkout | Unknown | Unknown | The Linux-installed wheel exposes selected commands and artifact operations outside the checkout | Installation or command behavior on Windows or macOS |
| Core receipt, numbered-profile, Graph, and evidence-bound mechanisms | Hosted execution through the Linux test suite | Unknown | Unknown | The precise Linux tests exercise their documented reference paths | A platform-independent native result, external implementation, or cross-platform semantic equivalence |
| Interoperability catalog, modeled-hole detection, and candidate planning | H1 hosted its then-current experimental catalog/planner tests; later additions require their own hosted run | Unknown | Unknown | Deterministic catalog matching and nonexecuting candidate planning over modeled geometry at the exact tested coordinate | Checker execution, completed validation, closure, safety, authority to act, or interoperability of a native component |
| Experimental workflow and platform-event adapter | Hosted execution through the Linux test suite | Unknown | Unknown | The adapter preserves native platform results with `verification_effect = NONE` in its tested cases | That a platform event upgrades a VSTD result or that an external workflow implementation interoperates |
| Supply Chain Integrity, Transparency, and Trust interoperability using Concise Binary Object Representation and CBOR Object Signing and Encryption | Hosted execution of the optional cryptographic example on Linux under local test keys and a local test log | Unknown | Unknown | Signature, registration, inclusion, adapter, and adjacent-result behavior for the exact local test construction | A public Transparency Service, production trust roots, payload correctness, VSTD conformance, or Windows/macOS support |
| Artifact freeze, finite seal, and thaw | Hosted execution of the optional cryptographic suite on Linux | Unknown | Unknown | The tested exact-byte, signature, external-anchor, and thaw propositions under the Linux test environment | Privileged-write prevention, trusted time, network-filesystem behavior, or equivalent Windows/macOS behavior |
| RISC Zero zero-knowledge virtual machine prover/verifier example | Documented local execution on Linux x86-64 under Windows Subsystem for Linux 2; CI performs static and recorded-artifact checks but does not rebuild or execute the native prover/verifier | Unsupported by the repository's native Windows path; the documented path is Linux under Windows Subsystem for Linux 2 | Unknown | The tracked source, locked dependencies, recorded proof bytes, expected image identifier, and documented Linux reproduction boundary are inspectable; the recorded local result is bounded to its stated coordinate | A fresh hosted native proof, native Windows or macOS support, independent reproduction, universal proof-system portability, witness truth, or a VSTD receipt mapping |
| Other native prover, verifier, solver, hardware, scientific, or vendor adapters | Unknown unless a component-specific receipt and test says otherwise | Unknown unless a component-specific receipt and test says otherwise | Unknown unless a component-specific receipt and test says otherwise | Nothing is inherited merely because the Python framework can represent an adapter descriptor or result | Installation, execution, semantic preservation, trust-root validity, or cross-platform support |

## Machine-checked reference-component contract intent

The source-controlled
[`platform-component-contracts.json`](platform-component-contracts.json) manifest
enumerates exactly the current reference catalog and four separate execution
coordinates. `CONFIGURED_UNRUN` records configured intent only; it is not hosted
execution, compatibility, or support evidence. `BEHAVIOR` means the mapped tests call
the component on bounded positive or adversarial cases. It never means the tests cover
every native input, dependency, filesystem, trust root, or external implementation.

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
| Bounded operating-system result comparator<br>`component:platform-run-comparator` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_platform_comparison.py` | `test` | Exercise positive, conflicted, incomplete, malformed, and binding-drift platform-comparison cases over recorded receipts. |
| Recorded provenance policy verifier<br>`component:provenance-policy-verifier` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_public_data.py` | `test` | Exercise provenance-policy acceptance and rejection over bounded data-receipt fixtures. |
| SCITT native-evidence consumer<br>`component:scitt-evidence-consumer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_scitt_crypto_example.py`<br>`tests/test_scitt_interop.py` | `scitt`, `test` | Exercise semantic SCITT evidence mapping plus the local-key cryptographic example. Passing does not establish public transparency infrastructure or production trust roots. |
| VSTD and SCITT adjacent-result composer<br>`component:scitt-result-composer` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_scitt_crypto_example.py`<br>`tests/test_scitt_interop.py` | `scitt`, `test` | Exercise bounded adjacent-result composition, mismatch preservation, and the local-key cryptographic example without strengthening either native result. |
| VSTD-Graph assurance-log rechecker<br>`component:vstd-graph-assurance-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise bounded assurance-log replay, dependency handling, and failure preservation. |
| Evidence-bound VSTD-Graph level rechecker<br>`component:vstd-graph-level-rechecker` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `CONFIGURED_UNRUN` | `BEHAVIOR` | `tests/test_evidence_bound_assurance.py` | `test` | Exercise evidence-bound Graph-level record rechecking and unresolved-evidence behavior. |
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

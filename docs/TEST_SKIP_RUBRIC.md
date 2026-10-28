# Test Skip Rubric and Skip-Slippage Prevention Standard

> **Acronyms:** 64-bit Arm instruction-set architecture (ARM64);
> application programming interface (API); central processing unit (CPU);
> continuous integration (CI); command-line interface (CLI); graphics processing unit (GPU);
> identifier (ID); JavaScript Object Notation (JSON); operating system (OS);
> Secure Hash Algorithm 256-bit (SHA-256); tensor processing unit (TPU);
> uniform resource locator (URL); Verifier Standard (VSTD).

This standard establishes the normative definitional rubric for test skip justification,
classification, and disclosure across all repositories maintained by Tyler Roost
(@TimeLordRaps).

## 1. The problem of skip slippage

In automated verification and continuous testing, **skip slippage** is the unmonitored,
silent accumulation of skipped tests across local developer runs, pull requests, and
hosted continuous integration (CI) jobs. When tests are skipped without rigorous,
rubricized justification:

1. Platform-specific regressions hide behind generic skip notices;
2. Agents and contributors skip failing checks instead of addressing root causes;
3. Environmental gaps (such as unprivileged execution tokens or missing optional extras)
   are conflated with product code defects;
4. The repository appears unprofessional or unmaintained when high skip counts (e.g. 39
   skipped tests) appear without clear, accounted-for rationale.

Under Verifier Standard (VSTD) principles, an unrun or skipped check cannot earn passing
coverage, and an unevidenced skip cannot be excused. Every skipped test must be explicitly
disclosed and classified against the definitional rubric defined below.

## 2. Definitional rubric categories

Every skipped test in this repository and downstream maintained repositories MUST fall into
exactly one of the following eight formal rubric categories:

| Rubric identifier | Category name | Definitional scope |
|---|---|---|
| `OS_CAPABILITY_GUARD` | Operating System Capability Guard | The test requires an operating system (OS) capability, kernel privilege, or filesystem primitive unavailable on the runner host. |
| `OPTIONAL_DEPENDENCY_ABSENT` | Missing Optional Dependency or Extra | The test exercises an optional package extra, third-party library, or native accelerator binding not installed in the minimal environment. |
| `EXTERNAL_SERVICE_BOUNDARY` | External Network Service Boundary | The test requires an external network endpoint, remote service, or cloud provider application programming interface (API) deliberately isolated during hermetic testing. |
| `ARCHITECTURAL_PLATFORM_UNSUPPORTED` | Architecturally Unsupported Platform | The test targets a hardware central processing unit (CPU) architecture or endianness variant unavailable on the execution machine. |
| `HARDWARE_DEVICE_UNAVAILABLE` | Hardware Device Unavailable | The test requires specialized physical hardware, a hardware security module, graphics processing unit (GPU), or tensor processing unit (TPU) absent from the environment. |
| `PRIVILEGE_OR_CREDENTIAL_BOUNDARY` | Privilege or Credential Boundary | The test requires administrative/root execution rights or secret production credentials intentionally withheld from untrusted environments. |
| `PERFORMANCE_OR_DURATION_EXCLUSION` | Performance or Long-Duration Exclusion | The test is an explicitly designated benchmark, stress test, or soak harness excluded from rapid pre-push gates by explicit tag. |
| `QUARANTINED_DEFECT` | Quarantined Tracked Defect | The test exposes an actively tracked upstream defect with an authoritative issue uniform resource locator (URL), quarantined to prevent blocking unrelated work. |

When zero tests are skipped or omitted, the sole valid designation is `NOT_APPLICABLE`.

### 2.1 OS_CAPABILITY_GUARD

- **Criteria**: The executing platform lacks an operating system primitive, such as
  POSIX-specific special filesystem nodes (`os.mkfifo`), Unix domain socket features,
  or unprivileged symbolic link creation (e.g. Windows unprivileged environments where
  `SeCreateSymbolicLinkPrivilege` is unavailable and Developer Mode is disabled).
- **Required disclosure**: Exact operating system name and version, the specific system call
  or primitive, and the observed error code (e.g. `errno=22, winerror=1314`).
- **Forbidden usage**: Skipping generic portable logic that could be refactored to work
  cross-platform; skipping tests on an operating system where the feature is officially supported.

### 2.2 OPTIONAL_DEPENDENCY_ABSENT

- **Criteria**: The feature tested is documented as an optional package extra in
  `pyproject.toml` or `package.json` (such as `scitt` or `seal` extras in VSTD) and is
  deliberately not installed in the base runtime environment to enforce stdlib-purity.
- **Required disclosure**: The exact optional extra name, the missing module identifier (ID),
  and reference to the dedicated CI matrix job where the dependency is installed and tested.
- **Forbidden usage**: Skipping tests because a *mandatory* dependency failed to install;
  skipping tests without declaring the extra in the package configuration.

### 2.3 EXTERNAL_SERVICE_BOUNDARY

- **Criteria**: The test verifies integration with a public network service or cloud API
  that is unreachable in offline, sandboxed, or air-gapped test runners.
- **Required disclosure**: Target service domain, protocol, and the local mock/stub test
  proving offline contract validity.
- **Forbidden usage**: Calling external network services without a mock fallback in standard
  unit test suites.

### 2.4 ARCHITECTURAL_PLATFORM_UNSUPPORTED

- **Criteria**: The test exercises assembly instructions, CPU register behaviors, or memory
  endianness models specific to a microarchitecture not present on the runner (e.g. 64-bit Arm instruction-set architecture (ARM64)
  NEON vector extensions executed on an x86_64 host).
- **Required disclosure**: Target CPU architecture and runner CPU architecture.
- **Forbidden usage**: Marking high-level algorithmic code as architecture-dependent when
  standard language constructs suffice.

### 2.5 HARDWARE_DEVICE_UNAVAILABLE

- **Criteria**: The test exercises physical hardware accelerators (GPU, TPU, hardware
  security tokens) unavailable in standard software runner containers.
- **Required disclosure**: Expected hardware device ID and proof that software emulation
  or mock verification is performed where possible.
- **Forbidden usage**: Skipping tests whose hardware dependencies can be fully mocked or
  emulated in software.

### 2.6 PRIVILEGE_OR_CREDENTIAL_BOUNDARY

- **Criteria**: The test requires elevated operating system permissions (such as root or
  Windows Administrator) or access to restricted cryptographic key material not distributed
  to public pull-request runners.
- **Required disclosure**: Exact permission or secret name required, accompanied by proof
  that mock keys or test certificates are used for standard developer paths.
- **Forbidden usage**: Hiding test failures caused by expired or missing local test keys.

### 2.7 PERFORMANCE_OR_DURATION_EXCLUSION

- **Criteria**: The test is a multi-hour stress test, fuzzing harness, or statistical
  benchmarking run explicitly categorized as non-blocking for interactive pre-push validation.
- **Required disclosure**: Test execution duration bound and the schedule/event where the
  long-running test is executed.
- **Forbidden usage**: Marking ordinary slow unit tests as performance exclusions to avoid
  optimizing them.

### 2.8 QUARANTINED_DEFECT

- **Criteria**: A confirmed defect in an external upstream dependency or an active tracked
  internal issue prevents test success, and the issue is actively being resolved.
- **Required disclosure**: Full issue URL, assigned engineer or agent, and expiration date
  or milestone for re-evaluation.
- **Forbidden usage**: Indefinite quarantine; skipping tests for defects without an open,
  tracked issue URL.

## 3. Baseline skip inventory for VSTD on unprivileged Windows

In `verifier`, running the complete test suite on an unprivileged Windows developer machine
produces exactly 39 skipped tests. Every single skip is accounted for under the
`OS_CAPABILITY_GUARD` rubric:

1. **33 tests in `tests/test_artifact_control.py:109`**
   - **Rubric category**: `OS_CAPABILITY_GUARD`
   - **Technical reason**: `symlink creation is unavailable (errno=22, winerror=1314)`.
     On Windows, creating symbolic links requires `SeCreateSymbolicLinkPrivilege`. This
     privilege is granted to elevated Administrators or when Windows Developer Mode is enabled.
     In standard unprivileged developer shells, the Win32 API returns error code 1314
     (`ERROR_PRIVILEGE_NOT_HELD`), mapped by Python to `OSError(22, 'Invalid argument')`.
   - **Claim consequence**: Symbolic link preservation and thaw paths remain unverified on
     unprivileged Windows environments; they are fully verified in CI Windows Server 2025
     runners (where Developer Mode is active) and all Linux/macOS runners.
2. **5 tests in `tests/test_artifact_control.py:117`**
   - **Rubric category**: `OS_CAPABILITY_GUARD`
   - **Technical reason**: `first-in, first-out special objects are unavailable`.
     The POSIX `os.mkfifo` special filesystem node primitive is not provided by the Windows
     NT kernel or Microsoft Visual C++ runtime.
   - **Claim consequence**: Artifact rejection of FIFO objects is verified on POSIX systems;
     Windows filesystem trees cannot construct POSIX FIFO nodes.
3. **1 test in `tests/test_graph_topology_integration.py:160`**
   - **Rubric category**: `OS_CAPABILITY_GUARD`
   - **Technical reason**: `named pipe creation requires Unix`.
     `test_topology_document_reader_rejects_pipe_without_waiting` creates a POSIX FIFO via
     `os.mkfifo` to verify that non-regular files are rejected without blocking.
   - **Claim consequence**: Rejection of named pipe inputs without blocking is verified on
     Unix coordinates; Windows handles non-file rejection through directory fixtures.

## 4. Contributor and agent workflow requirements

Automated agents and human contributors MUST observe the following rules:

1. **Pre-push verification**: Run `python scripts/preflight.py --audit-skips` locally. The
   audit will verify that all skipped tests correspond to recognized rubric classifications.
2. **Pull request disclosure**: Every pull request must include the completed
   `## Test skip rubric disclosure` section with:
   - The rubric checklist indicating which categories apply;
   - The itemized inventory mapping each skipped test or homogeneous test group to its
     rubric category, technical rationale, and claim consequence;
   - The checklist confirmation that every skip has been categorized.
3. **Zero tolerance for unclassified skips**: A pull request that introduces an unclassified
   skip or fails to provide technical rationale will be rejected by the automated pull-request
   policy gate (`scripts/check_pr_policy.py`).

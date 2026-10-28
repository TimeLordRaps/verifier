# Language-neutral runners and object-specific sandbox requirements

abstract syntax tree (AST); Verifier Standard (VSTD); JavaScript Object Notation (JSON); application programming
interface (API); operating system (OS); Windows Subsystem for Linux (WSL); virtual
machine (VM); graphics processing unit (GPU); simulation (SIM); command-line
interface (CLI); central processing unit (CPU); Secure Hash Algorithm 256-bit (SHA-256).

## Standard, implementation and extension boundaries

VSTD object, relation, obligation, applicability, evidence and verdict semantics
must be language- and implementation-agnostic. Python is the default shipped
runner and orchestration host of this reference implementation, not a normative
restriction on what the standard can represent. Another implementation can
implement the same contracts without translating its subject into Python.

Language discovery, exposed-object extraction, execution and verification are
distinct capabilities. Filename detection does not establish semantic coverage.
Extensions must eventually discover and bind the native language's exports,
declarations, callbacks, event transitions, rule/query surfaces, macros and runtime
objects as applicable. No universal function/class-shaped source model is assumed.
An abstract syntax tree alone cannot establish dynamic exposure or process behavior.

All reference language adapters feed the same Python orchestration and receipt
path. They may use external interpreters, compilers, engines, parsers, databases,
containers or licenses. Their dependencies belong to the selected extension, not
the dependency-free core. A toolchain being installed is not a qualified runner.
Detection never installs a toolchain, imports repository code, selects a non-Python
language for execution, or silently substitutes another language or dialect.

## Implemented command boundary

```console
vstd runner catalog --json
vstd runner detect . --json
vstd runner plan main.py --json
vstd runner plan main.js --language javascript --json
vstd runner run trusted_example.py --trusted-local --json
vstd runner plan training.py --object-kind MODEL --activity train --sandbox openshell --json
```

`--root` chooses the repository; `--argument=VALUE` supplies one entry argument.
Absent `--language`, Python remains the default. Detection reports all filename
candidates and ambiguity (for example, `.m` can mean MATLAB or Objective-C).
The bounded scanner excludes reported dependency/build directories and symlinks;
it is not the exhaustive source census required by package polish.

The basic runner reuses `core.run.capture_run`: argument-vector subprocess
execution, declared-entry capture, timeout and the existing generic receipt.
The receipt includes a capture-owned bounded parent-process observation. Runner
`execution_performed` is derived from that observation's `process_started` state:
`YES` maps to true, `NO` to false, and `UNKNOWN` remains null. Returning a receipt
alone does not establish that a process started.
It requires explicit `--trusted-local`. It does not sandbox repository code,
bound output memory, prevent networking, isolate credentials, or guarantee child
process-tree cleanup. Inherited environment and undeclared dependencies remain
outside its observation boundary. Use only trusted local checks on this path.
An exit-zero PASS is only a process result: `sandbox_status=NOT_ESTABLISHED`,
`obligation_status=UNKNOWN`, and `polished=false` remain explicit.

Installed language adapters use the explicitly named optional
`vstd-language-runners` package and its `vstd_languages.command` callable.
OpenShell uses the separate `vstd-openshell` package and
`vstd_openshell.run`. The base runner checks only those fixed package names;
it does not scan host entry-point metadata or admit a caller-selected module.
Only the explicitly selected package is imported, only for execution after
admission; detection and planning inspect availability without loading it.
Missing packages remain UNKNOWN.
The adapter callable receives a JSON-compatible record with `schema_version`
`verifier-language-runner-1`, `language`, `root`, relative `entry` and `arguments`.
Sandbox execution additionally supplies `environment=sandbox-linux`; paths and
tool names then refer to the sandbox, never the host toolchain.
It returns exactly `schema_version`, matching `language`, and an `argv` array.
The Python host captures the actual command through the shared process runner.
For a compiled or interpreted extension this binds only that selected outer adapter
command. Compiler processes, target processes, and other descendants remain explicitly
unobserved unless a separate extension mechanism provides source-bound evidence.
For an explicitly selected non-Python extension, worker exit codes 124, 125, 126 and 127
are reserved for the worker's own timeout, output-capacity, resource-unavailable and
toolchain-unavailable conditions. Each yields `status=UNKNOWN` with one closed blocker
(`RUNNER_EXTENSION_EXIT_TIMEOUT`, `RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY`,
`RUNNER_EXTENSION_EXIT_RESOURCE_UNAVAILABLE`, or `RUNNER_EXTENSION_EXIT_TOOLCHAIN_UNAVAILABLE`),
and the receipt and parent process observation are retained. Only an exact integer exit code
is read: stderr and stdout never select or add a blocker. A non-`None` exit value whose
exact type is not an integer is an invalid process observation and remains `UNKNOWN`.
Other exact-integer nonzero exits remain `FAIL`, and Python default runs keep their
historical exact-integer exit semantics. Collision boundary:
a subject or compiler that naturally returns a reserved code is also reported `UNKNOWN`,
never `PASS`. These codes establish neither descendant cleanup nor the failing stage;
the receipt records the exit only.
This is trusted extension code, not a secure in-process plugin sandbox or a
qualified source-to-obligation mapping. Versioned dialect/toolchain selection,
adapter code provenance and native extraction contracts remain required work.

The runner command is separate from `objects.vstd` version 1 admission. It does
not widen that fixed manifest or discharge package-instance obligations. Direct
integration requires a versioned manifest contract and source-bound runner evidence.

## Language rollout denominator

The initial popularity baseline is the [TIOBE October 2026 index](https://www.tiobe.com/tiobe-index/),
positions 2 through 25 after Python. The 24 extension targets are:

C, C++, Java, C#, JavaScript, Visual Basic, R, Structured Query Language (SQL),
Rust, Go, PHP, Fortran, Swift, Scratch, COBOL, Perl, Julia, Delphi/Object Pascal,
MATLAB, Ada, SAS, Assembly language, Classic Visual Basic and Objective-C.

This baseline is not a universal importance ordering. Lisp, TypeScript and Prolog
are additional discovery targets so the requested recursive-list, event-driven
and declarative cases cannot disappear behind a popularity cutoff. Extensions
must select actual dialects and engines: Lisp is not one interchangeable runtime,
SQL requires a named database dialect, Assembly a target architecture, Scratch
an event engine, and proprietary languages their explicitly supplied toolchains.

Only the Python process path is built in. The separate `vstd-language-runners`
source distribution in `extensions/languages` implements eleven adapters:
Node.js JavaScript, GCC C17 and C++17 single translation units, Java 11+ single-source
launch, Rust 2021 single-source compilation, Perl scripts, SQLite scripts, GNU
Fortran 2018, PHP command-line scripts, Steel Bank Common Lisp (SBCL) scripts and
SWI-Prolog scripts. Scheme is not accepted by the Common Lisp adapter. PHP skips
host configuration; Lisp and Prolog skip personal startup files. Prolog errors
halt with a failing exit rather than falling through to a successful interactive session.
Fortran modules and compiler output stay in its fresh temporary build directory.
Compiled artifacts use fresh temporary directories and never reuse a stale binary.
Repository tests do not invoke C, C++, Fortran, or Rust compilers merely because
they are installed. Maintainers must explicitly set `VSTD_RUN_NATIVE_TOOLCHAINS=1`
to run those isolated compiler specimens; the default suite exercises protocol,
selection, missing-runtime, and fail-closed behavior without producing binaries.
SQLite uses an in-memory database and denies database attachment and extension loading;
this narrows its process contract, not the host security boundary. Other catalog entries
remain NOT_IMPLEMENTED. Install these local distributions from the source checkout;
this is not a claim that they have been published to a package index.
Each extension needs positive execution, wrong-language and wrong-dialect rejection,
source/receipt binding, missing-runtime behavior, timeout/error handling and
cross-language obligation equivalence tests before being called supported.

## Separate object profiles, not numbered assurance tiers

| Profile | Meaning and required evidence |
| --- | --- |
| process-basic | Trusted local Python-hosted process capture; no security sandbox claim. |
| model-corrigibility | MODEL training/inference containment plus authorized intervention, checkpoint integrity and bounded corrigibility evidence. Being typed MODEL does not prove those properties. |
| agent-open-ended | AGENT remains open-ended and non-corrigible by classification. A HARNESS may constrain an execution's operational permissions; containment is not a claim of semantic corrigibility. |
| bot-isolated | Exact AGENT, HARNESS and isolated SIM bindings, confined observation/action channels and applicable correction/intervention evidence. It must not acquire external AGENT authority by relabeling. |
| sim-contained | Explicit SIM boundary and lifecycle policy, with containment independent of the simulated workload's liveness. Correction and continuity requirements are conditionally applicable with reasons. |

These are orthogonal policy selections, not stronger/weaker numbered VSTD tiers.
Selecting training requires MODEL safeguards even if a caller omits a MODEL label.
Nonbasic profiles refuse the basic process path with
`RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED`, including when `--trusted-local` is set.
Selecting `--sandbox openshell` requires the separately installed adapter and
`--sandbox-config`; missing components remain UNKNOWN, never host fallback.
Profile selection scopes diagnostic execution; it does not claim that the object
already satisfies the profile's obligations.

`--continuity-required` adds a declared failure model, redundant capacity and
failover/recovery evidence. A watchdog or restart flag does not establish continuous
availability. Claims must specify observation horizon, tolerated failures, recovery
time and state-loss bounds, and be challenged by fault injection and partition
tests. Eternal uptime under arbitrary failures is not a bounded verifiable claim.
Neither stopping a SIM nor losing its control plane may release its contents onto
the host. Operator emergency authority, service continuity and containment need
separate, explicit policies; "cannot stop" is not a substitute for those contracts.

No corrigibility checker is completed by these profiles. The existing
[corrigibility research boundary](CORRIGIBILITY_RESEARCH.md) remains in force.

## NVIDIA OpenShell integration candidate

As inspected on 2026-10-12, NVIDIA documents OpenShell v0.1.3 as a sandbox runtime
with enforcement and policy controls; NemoClaw builds agent workflows on top of it.
The appropriate reference-backend candidate is OpenShell, not a requirement that
VSTD subjects use NemoClaw or any particular agent framework.

Its [extension contracts](https://docs.nvidia.com/openshell/latest/extensibility/overview)
separate supervisor middleware (allowed traffic), gateway interceptors (lifecycle
and policy operations), compute/credential drivers (infrastructure), and isolation
backends (workload processes and runtime boundaries). VSTD should attach evidence
capture and lifecycle checks at these existing boundaries instead of bypassing
the gateway or claiming an agent's self-report is host enforcement evidence.

The [support matrix](https://docs.nvidia.com/openshell/latest/about/support-matrix)
lists Linux and Apple Silicon macOS support, experimental WSL 2 plus Docker
Desktop on Windows, and Docker, Podman, Kubernetes and MicroVM runtimes. A backend
must actively qualify the required kernel capabilities and exact runtime, not
infer support from a version string or the presence of a container executable.
NVIDIA's [gateway high-availability documentation](https://docs.nvidia.com/openshell/latest/kubernetes/high-availability)
also requires separate database resilience and describes interrupted streams;
gateway replication alone does not establish uninterrupted SIM execution.

The optional `vstd-openshell` source distribution in `extensions/openshell` now
implements a pinned 0.1.3 CLI transport. Live qualification remains NOT_ESTABLISHED.
It creates a fresh labelled sandbox with explicit target/workspace/image/resources,
hard-required Landlock enforcement, non-root identity, no network grants or providers,
no port exposure and an ephemeral stop-contained lifecycle. Only the entry file and
explicit repeated `--input` files are copied: at most 256 files and 8 MiB total;
symlinks and escaping paths are rejected. Source hashes are checked inside the sandbox
before and after execution. Writable source endpoint hashes do not prove continuous
immutability or independent measurement of an adversarial runtime image.

Before subject execution, positive workspace access and negative filesystem/network
controls must pass. A missing file, connection refusal or timeout is not accepted as a
policy denial. Effective policy, sandbox identity and process generation are compared
around execution. The CLI has a deadline and a 1 MiB cap per captured output stream;
cleanup stops only an ownership-labelled sandbox and confirms deletion through a
successful empty, unpaginated listing. Unknown cleanup prevents PASS. A transport
failure can leave `execution_performed=null`: it cannot prove remote code never ran.
Exec disables shell startup hooks and directs temporary compiler outputs into the
writable sandbox workspace, not a possibly non-executable system temporary mount.

The trusted gateway and selected workload image remain assumptions. These checks are
not exhaustive escape testing, gateway authentication attestation, enforcement proof
for all resource limits, production MODEL corrigibility or physical SIM fidelity.
No installer, provider configuration or gateway startup is performed by the adapter.
`--continuity-required` is rejected before creation: this ephemeral backend cannot
establish redundant continuous service. BOT config requires exact declared AGENT,
SIM and HARNESS digests; declarations alone do not prove the actual channel topology.

## OpenShell setup and live validation

These instructions target OpenShell 0.1.3 on Linux/amd64. The Windows route is
experimental upstream. The four specimens and five negative runs (nonzero exit,
deadline, output flooding, source mutation and forbidden-file access) were exercised
against one selected configuration with verified cleanup. These are bounded live
observations, not general isolation, ENV conformance or production-object qualification.
Docker inspection during all four runs confirmed subject-container settings of
1 CPU, 512 MiB, 128 processes, no Docker network and no privileged flag. This
observes configuration, not exhaustion enforcement. The separate trusted supervisor
used host networking with no observed CPU, memory or process cap; those subject
limits must not be advertised as a bound on the entire OpenShell control plane.

1. On Windows, check `wsl --list --verbose` and start the intended distribution.
   It must be version 2 and actually boot; a listed distro with a missing virtual disk
   is not usable. Do not unregister or recreate an existing distro as a shortcut.
   In Docker Desktop, enable the WSL 2 engine and **Settings → Resources → WSL
   Integration → the intended distro**. Inside that distro, `docker info` must
   reach the Linux server (Docker 28.0+), and `python3 --version` must be 3.10+.
   Merely finding a Windows Docker executable on the Linux path does not suffice.
   If changing Desktop integration would disturb existing jobs, an advanced scoped
   route was verified with Desktop 4.93.0: set `DOCKER_HOST` to
   `unix:///mnt/wsl/docker-desktop/shared-sockets/host-services/docker.proxy.sock`
   and prepend `/mnt/wsl/docker-desktop/cli-tools/usr/bin` to that shell's `PATH`.
   Require `docker version` and `docker ps` to identify the intended Linux daemon;
   this runtime-discovered path is not a portable Docker API guarantee. No daemon
   restart, unauthenticated TCP socket, default-distro change or global setting is
   necessary. A containerized gateway can instead use its mounted Docker socket.
2. Check free space on Docker Desktop's configured disk-image drive, not just Linux's
   virtual free-space number. Reserve at least 2 GiB for this small validation setup
   and more for toolchains/models. This is a conservative setup allowance, not a
   measured installed footprint. Never prune unrelated containers, volumes or images
   to satisfy it. Keep antivirus enabled; a detection requires investigation, not
   automatic exclusions or restoration.
3. Inside the Linux distro, follow NVIDIA's
   [pinned installer procedure](https://docs.nvidia.com/openshell/latest/about/installation).
   Download and inspect the release script before executing it:

   ```bash
   curl -fLo openshell-install.sh https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.3/install.sh
   less openshell-install.sh
   OPENSHELL_VERSION=v0.1.3 sh openshell-install.sh
   openshell --version
   openshell gateway list
   openshell status
   ```

   The installer changes the Linux environment and starts a gateway. If telemetry is
   unwanted, add `OPENSHELL_TELEMETRY_ENABLED=false` to the existing
   `~/.config/openshell/gateway.env`, preserving other settings, and restart only that
   gateway with `systemctl --user restart openshell-gateway`. The adapter's client
   environment alone does not disable gateway telemetry. Use the installer's local
   authenticated gateway; do not disable authentication to make a check pass.
4. In a Linux checkout of this repository, install the core and selected extensions
   into a virtual environment. Do not use Windows Python for this backend:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install . ./extensions/openshell ./extensions/languages
   ```

   For self-assessment of the Verifier checkout, build extension wheels from a
   separate staging copy. Local packaging can leave ignored `extensions/*/build`
   source duplicates; the Tier-0 ignored-source gate intentionally rejects those.
   Preserve or remove only your own generated build copies before package admission;
   do not relax the census to conceal extra source.

5. Select a Linux workload image containing Python 3 and `/bin/sleep`, plus any chosen
   language toolchains. Its reference must include an actual registry digest, not
   `latest`. For the Python-only live specimens, this Linux/amd64 Python 3.12 slim
   image was resolved on 2026-10-12 and used for the bounded live specimens:

   ```bash
   docker pull python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
   ```

   Save this JSON as `openshell.json`. Replace `YOUR_REGISTERED_GATEWAY` with the
   exact name from `openshell gateway list`; retain the explicit workspace you own.

   ```json
   {
     "schema_version": "verifier-openshell-config-1",
     "gateway": "YOUR_REGISTERED_GATEWAY",
     "workspace": "default",
     "image": "python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe",
     "cpu": 1,
     "memory": "512Mi",
     "reason": "Bounded offline specimen containment and lifecycle checks, not production conformance.",
     "lifecycle": "ephemeral-stop-contained"
   }
   ```

6. Run the live suite once per selected host/runtime/configuration. The output
   directory must not already exist; retain it for refutation and rechecking:

   ```bash
   python -m vstd_openshell.live --config openshell.json --output openshell-results
   ```

   Each object gets a fresh sandbox and all common admission/denial/source/cleanup
   checks. There is no mock fallback:

   | Object | Additional bounded specimen behavior |
   | --- | --- |
   | MODEL | Controller terminates a cooperative child; child writes an atomic checkpoint; controller reads and hashes it. General model corrigibility remains UNKNOWN. |
   | AGENT | Open-ended classification retained; a three-step harness budget bounds this run, without relabeling the AGENT corrigible. |
   | BOT | Exact source digests bind AGENT, SIM and HARNESS; a valid move succeeds and an out-of-channel command is rejected. |
   | SIM | A simulated child exits; a subsequent process remains denied access outside the declared filesystem policy. Continuous availability is not claimed. |

   Any missing dependency, failed probe, policy/source change, runtime failure or
   unconfirmed cleanup is retained in the object receipt. Inspect the recorded sandbox
   name if cleanup is UNKNOWN; do not assume the workload stopped. The suite is not a
   substitute for fresh package GRAPH obligation checks.

   The optional backend also emits a canonical `NamespaceObject` of kind ENV,
   retained as `environment.json` beside each live receipt. Its explicit applicability
   condition is selection of OpenShell, not installation of the base package. The
   payload retains requested configuration, observed gateway version, software
   commitments, before/after sandbox generation and policy, named controls, cleanup,
   and a digest of command evidence. Its `env` operand-binding fragment binds the
   exact subject source hashes; it does not invent the subject's other operands,
   alter root `objects.vstd`, prove complete software inventory, or issue ENV PASS.
   Unselected/basic execution does not import the optional ENV projection.

### Download versus installed footprint

Registry manifests inspected on 2026-10-12 report the following compressed
Linux/amd64 layer totals for 0.1.3:

| Image | Compressed layer bytes |
| --- | ---: |
| `ghcr.io/nvidia/openshell/sandbox:0.1.3` | 4,523,767 |
| `ghcr.io/nvidia/openshell/supervisor:0.1.3` | 20,435,034 |
| `ghcr.io/nvidia/openshell/gateway:0.1.3` | 53,320,250 |
| Selected Python workload above | 43,259,288 |

The OpenShell rows sum to 78,279,051 bytes before deduplicating shared layers.
The gateway image is unnecessary when using the native package-managed gateway.
Installed disk use is larger and depends on image expansion, shared layers, retained
sandboxes, logs and toolchains. Measure it after pulling with `docker system df -v`
and `docker image inspect IMAGE --format '{{.Size}}'`; these observations do not
include every Docker Desktop virtual-disk allocation. The observed local image
listing rounded gateway/supervisor/sandbox/Python to 188/75.5/15.4/177 MB; these are
engine accounting values, not an additive physical-space guarantee. The existing
virtual-disk file did not grow during the initial live suite. Check host free space
again before expanding toolchains or retaining additional workloads.

## Debugger observations are evidence inputs

Default debuggers are useful starting points, not a universal obligation mechanism.
Adapters may collect source locations, stack transitions, exceptions, coverage and
runtime identities through Python debugging hooks, Node.js Inspector or a native
debugger. They must bind toolchain, source, arguments, observation scope and missing
events. The current adapters capture process receipts; they do not yet implement
those debugger protocols. Optimized-away state, event queues, macros, database
transactions and nondeterministic behavior need language-specific observation
contracts. A checker must still evaluate the exact obligation, including reasons
for conditional applicability. Container isolation complements those observations;
neither debugger access nor a container label establishes the obligation verdict.

## Verifier self-package HARNESS applicability

Verifier's own package has a manifest-owned direct-launch denominator for repository
admission and polish. The current denominator contains 30 ordinary direct process
launch sites and two embedded language-worker launch sites. It is selected only
when the root manifest assigns the applicability checker itself to exactly one
owner whose accumulated declared roles include `HARNESS`. The HARNESS payload binds
the reviewed reasons and gaps, complete launch identities, call AST digests and
whole-source canonical AST digests. Automatic polish remigration may refresh only
byte hashes and diagnostic line coordinates when those semantic bindings remain
identical. Added or removed launches, changed call shapes, or any changed source AST
fail closed for explicit review.

The package-wide reviewed-source profile applies the same principle outside the
HARNESS denominator. Python and stub evidence uses the dependency-free standard
library AST. Evidence from every other language is currently byte-exact: even a
comment change requires review until that language runner or discovery extension
selects a bounded canonical syntax mechanism. Filename detection or an installed
runner is not such a selection. A refusal names the evidence path, object,
classification and obligation identifiers that need focused review.

The static vocabulary is explicitly bounded to enumerated `subprocess`, `asyncio`
and `os` calls. Dynamic or conditionally rebound callees refute discovery instead
of disappearing, and recognized `multiprocessing.Process.start` sites are reported
as outside the denominator. This does not claim exhaustive detection of native,
operating-system-specific or third-party launch APIs.

This is deliberately a verifier-self mechanism. A third-party repository is not
covered merely because it uses a supported language runner, and a static match does
not prove that a process ran, was confined, or satisfies the complete `HARNESS`
surface. Those propositions require their own execution observations, sandbox
evidence, and obligation-specific mechanisms.

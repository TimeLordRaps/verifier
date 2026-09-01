# Recorded reduced instruction set computer (RISC) Zero proof-mechanism report

> **Acronyms:** gigabyte (GB); identifier (ID); random-access memory (RAM); reduced instruction set computer (RISC);
> RISC Zero (RISC0); random number generator (RNG); software development kit (SDK);
> Secure Hash Algorithm 256-bit (SHA-256); scalable transparent argument of knowledge (STARK);
> Verifier Standard (VSTD); Windows Subsystem for Linux 2 (WSL2); zero-identity/zero-knowledge (ZIZK);
> zero-knowledge virtual machine (zkVM).

**Original run:** 2026-08-23
**Recorded artifact refresh:** 2026-08-31
**Status:** completed real-proof run refreshed against the tracked guest image; non-secret
proof artifacts tracked as a bounded reference mechanism; no VSTD receipt mapping

## Repository coordinates

- Repository: `TimeLordRaps/verifier`
- Original development base: `598c545be3833d6d81bb7e252ca5837f3bb2a449`
- Regeneration source commit: `e9d2b13eb22342934789bf94ee894bb5faed6d98`
- Regeneration source tree: `6fcf0a4d391815f7218a61fb32ca6bac0b71df63`
- Branch: `codex/post-1.2-professionalization`
- Worktree: the pull-request worktree; its machine-specific absolute path is
  intentionally excluded from this public report
- Existing serialized receipt identifiers modified: no
- The proof command performed no Git or network publication action. No merge, tag,
  release, or publication was performed.

## Selected proof system

Exactly one proof system was selected and used:

| Coordinate | Value |
|---|---|
| SDK and verifier | RISC Zero zkVM `3.0.6` |
| Receipt kind | composite STARK |
| Program trust coordinate | RISC Zero image ID |
| Image ID | `91df751f5764f81ba4995994afb43e87928dc32d23c81799c767794c27eabcff` |
| Tool manager | `rzup 0.5.0` |
| Prover executable | `r0vm 3.0.6` |
| Guest build tool | `cargo-risczero 3.0.6` |
| Guest Rust toolchain | `rustc 1.97.0-dev` |
| Tested platform | Linux x86-64 under WSL2 |
| Trusted setup | transparent STARK setup; no experiment-specific ceremony |

The official installer script used in the local environment had SHA-256
`5699878af779351ec0f931fa84c3d5e35263279f66bd915af225f530a77341bf`.
The experiment pins every direct Rust dependency and commits both host and guest lock
files:

- workspace `Cargo.lock`: `9b6f1a739c2acbe01581828fa37691af7288adb4642d158cb5f6a7383470483d`
- guest `Cargo.lock`: `1c1ef45133eb24090dfc136a479c1e007b0d2a6bab9b9ae0954a25f03dea27e9`

No alternative proof system was attempted.

## Selection basis

RISC Zero was selected because its official 3.0 documentation supports local real-proof
generation on x86-64 Linux, describes `Receipt` as a zero-knowledge proof of execution,
binds verification to an image ID and authenticated journal, and provides a transparent
STARK path. The local environment had more than the documented 16 GB minimum RAM.

The host crate compiles with `disable-dev-mode`, rejects `InnerReceipt::Fake`, requires
the selected `Composite` receipt variant, and rejects a truthy `RISC0_DEV_MODE` value.

## Proved predicate

The private witness contains:

- one to 64 evidence bytes;
- a private 32-byte salt;
- a private measurement; and
- an experiment-local candidate state.

The fixed guest accepts only an experiment-local `Supported` candidate state and a
measurement at least as large as the public threshold. It commits an authenticated public
journal containing the exact profile and predicate digests, subject digest, policy
digest, challenge, threshold, salted evidence commitment, and satisfied result.

The proof does not establish whether the private input was truthful or whether the
`Supported` tag was assigned correctly.

## Completeness, soundness, and zero-knowledge basis

### Completeness

One satisfying input produced a receipt that verified against the expected image ID and
authenticated journal. This is direct implementation evidence for the tested program and
environment, not a general proof about every possible input or platform.

### Soundness

The soundness basis is the selected RISC Zero STARK construction and its published
analysis, including the Fiat-Shamir transformation and documented hash assumptions. The
negative tests below provide implementation-level falsification attempts; they do not
replace the cryptographic analysis or an independent audit.

### Zero knowledge

The zero-knowledge basis is the RISC Zero protocol and verified non-fake receipt, which
hide guest execution inputs while exposing the journal. The exact private evidence and
salt byte strings were additionally scanned against every generated public artifact and
were absent. That byte scan checks this serializer path only; absence from files alone is
not a proof of zero knowledge.

## Commands and observed results

Toolchain and build:

```text
rzup show
cargo-risczero 3.0.6; r0vm 3.0.6; rust 1.97.0

cargo check --locked --workspace
PASS

cargo build --locked --release -p vstd-zk-host
PASS

two clean target directories:
vstd-zk-host image-id
91df751f5764f81ba4995994afb43e87928dc32d23c81799c767794c27eabcff
```

Real proof plus automated negative cases:

```text
RISC0_DEV_MODE=0 CARGO_NET_OFFLINE=true \
  ./scripts/run_real_proof.sh
PASS
```

Offline verifier invocation without the witness:

```text
CARGO_NET_OFFLINE=true ./scripts/verify_recorded_proof.sh
PASS
```

Repository validation:

```text
python -m pytest -q
552 passed, 38 skipped

python scripts/build_experiment_index.py --check
[EXPERIMENT INDEX OK] manifests and repository artifacts verified

python scripts/build_reference.py --check
[REFERENCE OK] docs/reference.html matches the implementation

python scripts/check_presentation.py
[PRESENTATION OK] links, accessibility, versions, boundaries, paths, maturity, transient
status, visual assets, generated reference, experiment index, acronym expansion, and
structural terminology

python -m compileall -q src scripts
PASS
```

The three guest panic messages printed during self-test are the expected rejection paths
for below-threshold, `Unknown`, and `Conflicted` inputs. They do not contain witness bytes.

## Negative-test results

| Test | Result |
|---|---|
| valid proof and matching public inputs | pass |
| below-threshold private measurement | rejected |
| experiment-local `Unknown` input | rejected |
| experiment-local `Conflicted` input | rejected |
| mutated public threshold | rejected |
| wrong image ID | rejected |
| corrupted proof bytes | rejected |
| tampered authenticated journal | rejected |
| subject and challenge transplantation | rejected |
| private evidence or salt copied to public artifacts | not detected; test passed |

All ten recorded Boolean checks were `true`.

## Recorded public artifacts

The exact receipt, public envelope, and self-test result are tracked under
[`recorded-proof/`](recorded-proof/) so a consumer can verify the recorded run rather than
only generating a new proof. The governed offline command first requires the locked build
of the tracked guest to reproduce the recorded image ID. The ephemeral private witness
and salt remain excluded.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `receipt.msgpack` | 301835 | `04813c4757ba4efbdad9d51d50d7402f3a98f6c23e53b9b58cce8af12ef9caa2` |
| `public.json` | 2590 | `188098e6ba1ac940475f15e0a4304ff08d678d98a9ed708dbe41dc6dde596b76` |
| `self-test-results.json` | 377 | `e4c1bff21fb6161221276157fa96af6661af8635da35970ba12e462881f2c6fe` |
| `corrupted-receipt.msgpack` | 301835 | `a37fbceb5cd234a991deb8c530d29551534fe04be881defa716d9fdcf1cbcf1f` |
| `tampered-journal.msgpack` | 301835 | `e210702b95557d76d4a2c285b14c738f4ddb7160017e92ae082dd6d9ef48b4f8` |
| `mutated-public.json` | 2590 | `c04651e41f50682bdae40049bdd73084d1ac2a98816f8e051ace7ed3ca24d360` |
| `transplanted-public.json` | 2590 | `997ac9107ab917838517acddbaf2bf2d01ad074e4c08b01e251b1bb3d7dc1db7` |

## Unresolved assumptions

- The selected cryptographic implementation and transitive dependencies were not
  independently audited in this work.
- Two clean builds in the same recorded WSL2 environment produced the same image ID. A
  build on an independent host and an independent implementation remain unavailable.
- The host, compiler, installer, and operating system remain trusted for witness secrecy.
- The experiment does not establish constant-time or side-channel-resistant proving.
- The challenge is cryptographically bound, but challenge issuance, expiry, uniqueness,
  and replay storage are external.
- Salt quality is generated from the host operating-system RNG but is not itself proved.
- The public subject and policy digests need external resolution and provenance rules.
- A private `Supported` tag is merely an input to this predicate, not independently
  established VSTD evidence.

## Public claims currently justified

The local evidence justifies saying that the bounded RISC Zero 3.0.6 reference mechanism
produced and re-verified a real composite STARK receipt for one bounded hidden-witness
predicate, with the recorded negative cases rejected, and that two clean builds under the
same recorded local environment produced its recorded image ID. It does not establish an
independent build environment, implementation, or distinct prover/verifier actors.

It also supports keeping VSTD core disclosure-neutral: this result demonstrates one
optional privacy mechanism without requiring or invalidating full-disclosure receipts.

## Claims still prohibited

Do not claim that this experiment proves:

- real-world truth, completeness, provenance, authorization, independence, identity,
  uniqueness, freshness, revocation, or legal compliance;
- protection against a malicious or compromised prover host;
- general zero-knowledge support for every VSTD predicate;
- independent implementation, third-party audit, external adoption, or production
  readiness;
- a frozen `ZIZK-VSTD` wire profile; or
- that zero knowledge should be mandatory for VSTD.

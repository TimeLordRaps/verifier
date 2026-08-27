# Recorded reduced instruction set computer (RISC) Zero proof-mechanism report

> **Acronyms:** gigabyte (GB); identifier (ID); random-access memory (RAM); reduced instruction set computer (RISC);
> RISC Zero (RISC0); random number generator (RNG); software development kit (SDK);
> Secure Hash Algorithm 256-bit (SHA-256); scalable transparent argument of knowledge (STARK);
> Verifier Standard (VSTD); Windows Subsystem for Linux 2 (WSL2); zero-identity/zero-knowledge (ZIZK);
> zero-knowledge virtual machine (zkVM).

**Date:** 2026-08-23
**Status:** completed recorded run; non-secret proof artifacts tracked as a bounded
reference mechanism; no VSTD receipt mapping

## Repository coordinates

- Repository: `TimeLordRaps/verifier`
- Immutable base: `598c545be3833d6d81bb7e252ca5837f3bb2a449`
- Branch: `codex/zizk-zero-knowledge`
- Worktree: isolated worktree named `zizk-zk-codex`; its machine-specific absolute
  path is intentionally excluded from this public report
- Primary worktree modified: no
- Existing frozen wire identifiers modified: no
- Push, pull request, merge, tag, release, or publication performed: no

## Selected proof system

Exactly one proof system was selected and used:

| Coordinate | Value |
|---|---|
| SDK and verifier | RISC Zero zkVM `3.0.6` |
| Receipt kind | composite STARK |
| Program trust coordinate | RISC Zero image ID |
| Image ID | `e1e9bf4f68ef60ff9af6b50e144082bc475cc20cab47e8187201153da597dcd8` |
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
```

Real proof plus automated negative cases:

```text
RISC0_DEV_MODE=0 vstd-zk-host self-test local-artifacts/recorded-final
PASS
elapsed wall time: 6.10 seconds
maximum resident set: 1,214,664 KiB
```

Offline verifier invocation without the witness:

```text
RISC0_DEV_MODE=0 vstd-zk-host verify receipt.msgpack public.json
PASS
elapsed wall time: 0.10 seconds
maximum resident set: 5,632 KiB
```

Repository validation:

```text
python -m pytest -q
258 passed, 3 skipped

python scripts/check_presentation.py
[PRESENTATION OK] links, versions, boundaries, paths, and visual assets

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
only generating a new proof. The ephemeral private witness and salt remain excluded.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `receipt.msgpack` | 301811 | `5fd33b0fbf6b54e34d4dd19c5ff068a8f82bacacc21881b5fa2cc5c0a90090df` |
| `public.json` | 2575 | `6324c3c5d77ea4df4034f61131059289d5228f190d69e34c59bd7416fa9ac823` |
| `self-test-results.json` | 377 | `e4c1bff21fb6161221276157fa96af6661af8635da35970ba12e462881f2c6fe` |
| `corrupted-receipt.msgpack` | 301811 | `389117e63a429e55c3f3616b9cbf2339fb1c99b48712ef7a3e5f5f16b32b6d81` |
| `tampered-journal.msgpack` | 301811 | `4e443f5084b8665a7185e6e4e62fd72eed5130673b3d7bfde488cdc6c405555c` |
| `mutated-public.json` | 2575 | `c2a056b71b2019daa8ac9f3aefcb4c2cc28a1b56ef97f8c61947bf37c5f2b7b9` |
| `transplanted-public.json` | 2575 | `95cf0d97e20777e2ad49234b7b27074dc8931ee7de215632a7d22a6b5466f2b6` |

## Unresolved assumptions

- The selected cryptographic implementation and transitive dependencies were not
  independently audited in this work.
- The image ID was produced once in this environment; a second independent build has not
  yet corroborated it.
- The host, compiler, installer, and operating system remain trusted for witness secrecy.
- The experiment does not establish constant-time or side-channel-resistant proving.
- The challenge is cryptographically bound, but challenge issuance, expiry, uniqueness,
  and replay storage are external.
- Salt quality is generated from the host operating-system RNG but is not itself proved.
- The public subject and policy digests need external resolution and provenance rules.
- A private `Supported` tag is merely an input to this predicate, not independently
  established VSTD evidence.

## Public claims currently justified

The local evidence justifies saying that the bounded RISC Zero 3.0.6 reference mechanism produced
and re-verified within the reference program a real composite STARK receipt for one bounded
hidden-witness predicate, with the recorded negative cases rejected. It does not establish
distinct prover/verifier actors.

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

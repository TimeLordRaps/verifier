# Proof-carrying reference mechanism for Verifier Standard (VSTD)

> **Acronyms:** gigabyte (GB); identifier (ID); random-access memory (RAM); reduced instruction set computer (RISC);
> RISC Zero (RISC0); software development kit (SDK); Secure Hash Algorithm 256-bit (SHA-256);
> scalable transparent argument of knowledge (STARK); Windows Subsystem for Linux 2 (WSL2);
> zero-knowledge virtual machine (zkVM).

**Status:** bounded reference mechanism under VSTD's governing
zero-identity/zero-knowledge (ZIZK) artifact-first architecture; not a VSTD layer, wire
identifier, conformance level, or compatibility promise. The proof backend is optional;
the artifact-first and zero-actor-trust architecture is not.

This directory answers one narrow question: can a prover show that a hidden, bounded
evidence payload satisfies a fixed predicate while publishing enough authenticated
coordinates for another party to verify the proof? It does not make all VSTD receipts
zero knowledge. Existing full-disclosure receipts remain valid and unchanged.

## Selected system

The reference mechanism selects exactly one proof system: **RISC Zero zkVM 3.0.6**, using its
local composite STARK receipt. The selection is pinned in every Cargo manifest and in
`Cargo.lock`.

Reasons for selection:

- the official SDK describes a `Receipt` as a zero-knowledge proof of execution;
- `Receipt::verify` checks successful execution, the expected image ID, and journal
  integrity;
- arbitrary Rust guest code can express the bounded predicate without designing a
  new arithmetic circuit;
- the composite STARK path uses transparent setup rather than a mechanism-specific
  trusted ceremony; and
- the documented local prover requires at least 16 GB of RAM, which the tested Linux
  x86-64 environment satisfies.

Primary references:

- [RISC Zero installation](https://dev.risczero.com/api/zkvm/install)
- [RISC Zero real-proof quick start](https://dev.risczero.com/api/zkvm/quickstart)
- [`Receipt` verification contract](https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/struct.Receipt.html)
- [`DevModeProver` warning](https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/struct.DevModeProver.html)
- [RISC Zero proof-system analysis](https://dev.risczero.com/proof-system-in-detail.pdf)

The host crate enables `disable-dev-mode`. It also rejects the `Fake` receipt variant
and refuses a truthy `RISC0_DEV_MODE` setting. Development-mode output cannot satisfy
this reference mechanism.

## Statement, witness, and public output

The fixed predicate is defined byte-for-byte by `PREDICATE_TEXT` in the shared types
crate. A successful proof establishes that one private input accepted by the pinned
guest program contained:

- a nonempty evidence byte string no longer than 64 bytes;
- a mechanism-local `Supported` input tag rather than `Unknown` or `Conflicted`;
- a private measurement at least as large as the public threshold; and
- a private 32-byte salt used in the evidence commitment.

The private witness consists of the evidence bytes, salt, measurement, and candidate
state. The authenticated public journal contains:

- SHA-256 digests of the historical mechanism profile and exact predicate text;
- subject and policy digests;
- a public challenge;
- the public threshold;
- a salted commitment to the private evidence, length, and measurement; and
- the Boolean result of the fixed predicate.

The RISC Zero image ID is the program trust coordinate. The verifier supplies or uses
the compiled expected image ID; it does not trust the convenience metadata in
`public.json`. RISC Zero receipt metadata is not cryptographically bound and is not an
acceptance input here.

Canonical evidence commitment input:

`UTF8` means Unicode Transformation Format, 8-bit (UTF-8) encoding; `U32_BE` and
`U64_BE` mean unsigned 32-bit and unsigned 64-bit big-endian encoding.

```text
UTF8("vstd-zk-evidence-commitment-v1\\0")
|| U32_BE(evidence_length)
|| evidence_bytes
|| salt_32_bytes
|| U64_BE(private_measurement)
```

The commitment is SHA-256 of those bytes. The journal itself is encoded by the pinned
RISC Zero serde codec and authenticated by the receipt.

## Platform and pinned setup

The tested platform is Linux x86-64 under WSL2. The RISC Zero documentation lists
x86-64 Linux as a supported installer target. The selected components are:

```text
rzup 0.5.0
cargo-risczero 3.0.6
r0vm 3.0.6
RISC Zero Rust guest toolchain 1.97.0-dev
risc0-zkvm 3.0.6
```

Install the official tool manager and then the pinned components:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://risczero.com/install -o /tmp/rzup-install.sh
bash /tmp/rzup-install.sh
export PATH="$HOME/.risc0/bin:$HOME/.cargo/bin:$PATH"
rzup install cargo-risczero 3.0.6
rzup install r0vm 3.0.6
rzup install rust 1.97.0
rzup default cargo-risczero 3.0.6
rzup default r0vm 3.0.6
rzup default rust 1.97.0
```

No dependency from this Rust workspace is added to the `verifier-standard` Python
distribution.

## Verify the recorded public proof artifact

The exact non-secret artifacts from the recorded run are tracked under
[`recorded-proof/`](recorded-proof/):

| Artifact | Bytes | Secure Hash Algorithm 256-bit (SHA-256) |
|---|---:|---|
| `receipt.msgpack` | 301811 | `5fd33b0fbf6b54e34d4dd19c5ff068a8f82bacacc21881b5fa2cc5c0a90090df` |
| `public.json` | 2575 | `6324c3c5d77ea4df4034f61131059289d5228f190d69e34c59bd7416fa9ac823` |
| `self-test-results.json` | 377 | `e4c1bff21fb6161221276157fa96af6661af8635da35970ba12e462881f2c6fe` |

The private witness and salt are not tracked and are not required for verification.
After installing the pinned toolchain and obtaining the locked Cargo dependencies, run
this command from this directory:

```bash
./scripts/verify_recorded_proof.sh
```

The script executes this direct verifier command:

```bash
export PATH="$HOME/.risc0/bin:$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="${HOME}/.cache/vstd-zk-target"
export RISC0_DEV_MODE=0
cargo run --locked --release -p vstd-zk-host -- \
  verify recorded-proof/receipt.msgpack recorded-proof/public.json \
  e1e9bf4f68ef60ff9af6b50e144082bc475cc20cab47e8187201153da597dcd8
```

The final argument is the exact RISC Zero guest image identifier recorded by the
public envelope and independently pinned by this repository. It is an explicit
program trust coordinate, not actor identity or reputation. Omitting it verifies
newly produced artifacts against the guest image built by the current checkout;
supplying it permits offline verification of this immutable historical receipt
without silently substituting the current build's image identifier. To require Cargo to
use only an already populated local cache, run
`CARGO_NET_OFFLINE=true ./scripts/verify_recorded_proof.sh`.

The expected successful output is:

```text
PASS: real RISC Zero receipt and public statement verified
```

## Reproduce the proof and negative tests

From this directory in the supported Linux environment:

```bash
export PATH="$HOME/.risc0/bin:$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="${HOME}/.cache/vstd-zk-target"
export RISC0_DEV_MODE=0
cargo run --locked --release -p vstd-zk-host -- self-test local-artifacts/self-test
```

The self-test produces one real receipt, verifies it, and then exercises the negative
fixtures described in `fixtures/README.md`. Generated receipts and private inputs are
ignored by Git.

For a separate prove/verify flow:

```bash
mkdir -p local-artifacts/manual
cargo run --locked --release -p vstd-zk-host -- \
  generate-inputs local-artifacts/private-witness.json local-artifacts/manual/statement.json
cargo run --locked --release -p vstd-zk-host -- \
  prove local-artifacts/private-witness.json local-artifacts/manual/statement.json \
  local-artifacts/manual/receipt.msgpack local-artifacts/manual/public.json
rm local-artifacts/private-witness.json
cargo run --locked --release -p vstd-zk-host -- \
  verify local-artifacts/manual/receipt.msgpack local-artifacts/manual/public.json
```

The last command is the verifier path. It needs the receipt, public envelope, pinned
verifier implementation, and expected image ID. It does not need the private witness or
a network service; Cargo itself may need the network until the locked dependencies and
toolchain have been installed or cached.

## Interpretation

The reference mechanism provides a concrete cryptographic privacy option for one bounded
predicate. It does not establish that zero knowledge should be mandatory for VSTD.
See `CLAIM_BOUNDARY.md` and `THREAT_MODEL.md` before making any public claim.

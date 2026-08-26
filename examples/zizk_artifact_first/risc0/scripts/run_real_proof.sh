#!/usr/bin/env bash
# Terminology: reduced instruction set computer (RISC); RISC Zero (RISC0); Verifier Standard (VSTD).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.risc0/bin:${HOME}/.cargo/bin:${PATH}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/vstd-zk-target}"
export RISC0_DEV_MODE=0

cd "${EXPERIMENT_DIR}"
cargo run --locked --release -p vstd-zk-host -- \
  self-test local-artifacts/self-test

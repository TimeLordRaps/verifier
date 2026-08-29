#!/usr/bin/env bash
# Terminology: reduced instruction set computer (RISC); RISC Zero (RISC0);
# Verifier Standard (VSTD).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MECHANISM_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.risc0/bin:${HOME}/.cargo/bin:${PATH}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/vstd-zk-target}"
export RISC0_DEV_MODE=0

cd "${MECHANISM_DIR}"
cargo run --locked --release -p vstd-zk-host -- \
  verify recorded-proof/receipt.msgpack recorded-proof/public.json \
  e1e9bf4f68ef60ff9af6b50e144082bc475cc20cab47e8187201153da597dcd8

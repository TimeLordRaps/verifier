#!/usr/bin/env bash
# Terminology: identifier (ID); reduced instruction set computer (RISC); RISC Zero (RISC0);
# Verifier Standard (VSTD).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MECHANISM_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export PATH="${HOME}/.risc0/bin:${HOME}/.cargo/bin:${PATH}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/vstd-zk-target}"
export RISC0_DEV_MODE=0

cd "${MECHANISM_DIR}"
EXPECTED_IMAGE_ID="91df751f5764f81ba4995994afb43e87928dc32d23c81799c767794c27eabcff"
ACTUAL_IMAGE_ID="$(
  cargo run --locked --release -q -p vstd-zk-host -- image-id
)"
if [[ "${ACTUAL_IMAGE_ID}" != "${EXPECTED_IMAGE_ID}" ]]; then
  printf 'FAIL: tracked guest image ID %s differs from recorded proof image ID %s\n' \
    "${ACTUAL_IMAGE_ID}" "${EXPECTED_IMAGE_ID}" >&2
  exit 1
fi

cargo run --locked --release -p vstd-zk-host -- \
  verify recorded-proof/receipt.msgpack recorded-proof/public.json \
  "${EXPECTED_IMAGE_ID}"

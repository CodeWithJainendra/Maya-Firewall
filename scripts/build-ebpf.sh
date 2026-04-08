#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/crates/maya-network-ebpf/Cargo.toml"

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "error: bpf-linker not found. Install it with: cargo install bpf-linker" >&2
  exit 1
fi

rustup component add rust-src --toolchain nightly >/dev/null

cargo +nightly build \
  --manifest-path "$MANIFEST_PATH" \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release \
  --target-dir "$ROOT_DIR/target"

echo "Built eBPF object at: $ROOT_DIR/target/bpfel-unknown-none/release/maya-network-ebpf"
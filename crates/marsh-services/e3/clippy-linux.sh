#!/usr/bin/env bash
# clippy for the Linux-only code paths (pins), in the guest toolchain.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm -v "$REPO":/src:ro -v e3-target:/target \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry -v "$HOME/.cargo/config.toml":/usr/local/cargo/config.toml:ro \
  -w /src -e CARGO_TARGET_DIR=/target-clippy \
  rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea \
  sh -c 'rustup component add clippy >/dev/null 2>&1; cargo clippy --locked -p marsh-services --all-targets --features dev-harness,test-breaks -- -D warnings 2>&1 | tail -30; cargo test --locked -p marsh-services --lib 2>&1 | grep "test result"'

#!/usr/bin/env bash
# The in-process witnesses (e3/witness.sh) in the guest toolchain, where the
# Linux-only tests (POLLHUP semantics, pins) run.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm -v "$REPO":/src:ro -v e3-target:/target \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry -v "$HOME/.cargo/config.toml":/usr/local/cargo/config.toml:ro \
  -w /src -e CARGO_TARGET_DIR=/target-test -e CARGO_NET_OFFLINE=true \
  rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea \
  bash crates/marsh-services/e3/witness.sh

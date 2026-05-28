#!/bin/sh
# Run one conformance probe under the real-Linux ORACLE (docker arm64
# ubuntu:24.04) and print its stdout. The probe authoring loop is
# scripts/build-probes.sh + this script; carrick-side verification batches
# via `cargo test --release --test conformance` once a probe is committed.
#
# Usage: scripts/probe-docker.sh <probe-name>

set -e
name="$1"
if [ -z "$name" ]; then
  echo "usage: $0 <probe-name>" >&2
  exit 64
fi
cd "$(dirname "$0")/.."
probe="conformance-probes/target/aarch64-unknown-linux-musl/release/$name"
if [ ! -x "$probe" ]; then
  echo "$probe not found; run scripts/build-probes.sh" >&2
  exit 66
fi
base64 < "$probe" | docker run --rm --platform linux/arm64 -i ubuntu:24.04 \
  sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'

#!/bin/sh
# Scaffold a new conformance probe at conformance-probes/src/bin/<name>.rs.
# Drops a deterministic header doc + helper imports + an empty main, so I (the
# coding agent) can dive straight to the INVARIANT instead of re-creating the
# same 30 lines of preamble. The Docker-diff loop after authoring is:
#
#   scripts/build-probes.sh && \
#   PROBE=conformance-probes/target/aarch64-unknown-linux-musl/release/<name> && \
#   docker run --rm --platform linux/arm64 -i ubuntu:24.04 \
#     sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' < <(base64 < $PROBE)
#
# Add the probe to probe-inventory.json and the derived conformance-next shard.
# Refresh its committed Docker oracle deliberately, then use the signed,
# in-process cached lane for Carrick iteration:
#
#   CARRICK_PROBE_FILTER=<name> just conformance-probes
#
# Do not add it to the legacy carrick-cli conformance runner. The retained
# manifest is only for reviewed live-oracle or process-isolation exceptions.

set -e
name="$1"
if [ -z "$name" ]; then
  echo "usage: $0 <probe-name>" >&2
  echo "  example: $0 timersignal" >&2
  exit 64
fi
cd "$(dirname "$0")/.."
out="conformance-probes/src/bin/$name.rs"
if [ -e "$out" ]; then
  echo "error: $out already exists" >&2
  exit 17
fi
cat > "$out" <<EOF
//! TODO: one-line summary of the invariant family this probe codifies.
//!
//! Stands in for LTP <test ids>.
//!
//! Invariants encoded (one per line below; each becomes one report! line):
//!   * TODO
//!
//! Deterministic output only — booleans/equality, never times/PIDs/addresses.
//! Harness diffs stdout byte-for-byte against the Linux oracle.

use conformance_probes::{report};

fn main() {
    unsafe {
        // TODO: encode the invariant. Use report!(key = value, …) for output.
    }
}
EOF
echo "created $out"
echo "next: edit, classify in probe-inventory.json, refresh the Docker oracle, then run CARRICK_PROBE_FILTER=$name just conformance-probes"

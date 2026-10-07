#!/usr/bin/env bash
# Lockfile drift gate for the nested fixture workspaces (fixtures/*/Cargo.toml).
#
# Each fixture is a standalone `[workspace]` with its own Cargo.lock, so the
# root `cargo ... --locked` gates never see it. Before this gate only
# `just fixtures-publish` built them with `--locked`, so a stale fixture lock
# (e.g. a path dependency such as carrick-el1-abi bumped in crates/) surfaced
# only on the Linux publisher. Here every fixture manifest is resolved with
# `--locked`: `cargo fetch` fails if the lock would change and populates the
# registry cache, then `cargo metadata --offline` proves the lock resolves
# without the network. The fixture set is globbed, never hand-listed; a
# manifest without a committed Cargo.lock is itself a failure.
#
# Usage: scripts/check-fixture-lockfiles.sh [ROOT]   (ROOT defaults to the repo)
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
shopt -s nullglob
manifests=("$root"/fixtures/*/Cargo.toml)
if [ "${#manifests[@]}" -eq 0 ]; then
    echo "fixture lockfile gate: no fixtures/*/Cargo.toml under $root" >&2
    exit 1
fi
failed=0
for manifest in "${manifests[@]}"; do
    dir="$(dirname "$manifest")"
    name="${dir#"$root"/}"
    if [ ! -f "$dir/Cargo.lock" ]; then
        echo "fixture lockfile gate: $name has no committed Cargo.lock" >&2
        failed=1
        continue
    fi
    if ! cargo fetch --locked --quiet --manifest-path "$manifest" ||
        ! cargo metadata --locked --offline --format-version 1 \
            --manifest-path "$manifest" >/dev/null; then
        echo "fixture lockfile gate: $name/Cargo.lock is out of date" \
            "(run cargo update -w --manifest-path $name/Cargo.toml and commit)" >&2
        failed=1
    fi
done
if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "fixture lockfile gate: ${#manifests[@]} fixture workspace(s) locked"

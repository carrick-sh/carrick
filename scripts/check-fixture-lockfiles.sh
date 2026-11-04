#!/usr/bin/env bash
# Resolve locked workspaces offline. --prepare is the sole CI network phase,
# run after rust-cache restore and bounded by the CI step's timeout-minutes.
# A failed preparation is infrastructure (exit 75), never a test verdict.
set -euo pipefail
prepare=0
if [ "${1:-}" = --prepare ]; then prepare=1; shift; fi
root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
shopt -s nullglob
manifests=("$root"/fixtures/*/Cargo.toml)
if [ "${#manifests[@]}" -eq 0 ]; then
    echo 'fixture lockfile gate: no fixtures/*/Cargo.toml' >&2
    exit 1
fi
if [ "$prepare" = 1 ]; then
    # Extend the existing fixture preparation to every active nested lockfile.
    while IFS= read -r -d '' lock; do
        manifest="$root/${lock%Cargo.lock}Cargo.toml"
        [ ! -f "$manifest" ] || manifests+=("$manifest")
    done < <(git -C "$root" ls-files -z Cargo.lock 'conformance-probes/*Cargo.lock' \
        'crates/*Cargo.lock' 'fuzz/*Cargo.lock' 'scripts/*Cargo.lock')
fi
for manifest in "${manifests[@]}"; do
    if [ ! -f "${manifest%Cargo.toml}Cargo.lock" ]; then
        echo "missing lockfile: $manifest" >&2
        exit 1
    fi
    if [ "$prepare" = 1 ]; then
        # Check the restored cache first. No retry loop or hidden online fallback
        # is permitted after this explicit preparation step.
        if ! cargo fetch --locked --offline --manifest-path "$manifest" &&
           ! CARGO_NET_OFFLINE=false CARGO_NET_RETRY=0 CARGO_HTTP_TIMEOUT=30 \
               cargo fetch --locked --manifest-path "$manifest"; then
            echo "::error title=Infrastructure::Cargo cache preparation failed: $manifest" >&2
            exit 75
        fi
    elif ! cargo metadata --locked --offline --format-version 1 \
        --manifest-path "$manifest" >/dev/null; then
        echo "fixture lockfile gate: offline resolution failed: $manifest" >&2
        exit 1
    fi
done
echo "fixture lockfile gate: ${#manifests[@]} workspace(s) locked"

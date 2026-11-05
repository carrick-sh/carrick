#!/usr/bin/env bash
# Resolve locked workspaces using the caller's Cargo network policy.
# --prepare is the sole CI network phase,
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
        # A cache miss is expected here, so the offline attempt's output is held
        # back and shown only if the online fetch fails too: its "error: no
        # matching package" lines otherwise read as the step's failure (misread
        # on 2026-11-05 as an infrastructure flake while the step had passed).
        offline_log=$(mktemp)
        if ! cargo fetch --locked --offline --manifest-path "$manifest" 2>"$offline_log" &&
           ! CARGO_NET_OFFLINE=false CARGO_NET_RETRY=0 CARGO_HTTP_TIMEOUT=30 \
               cargo fetch --locked --manifest-path "$manifest"; then
            echo "offline attempt (restored cache) for $manifest:" >&2
            cat "$offline_log" >&2
            rm -f "$offline_log"
            echo "::error title=Infrastructure::Cargo cache preparation failed: $manifest" >&2
            exit 75
        fi
        rm -f "$offline_log"
    elif ! cargo metadata --locked --format-version 1 \
        --manifest-path "$manifest" >/dev/null; then
        echo "fixture lockfile gate: locked resolution failed: $manifest" >&2
        exit 1
    fi
done
echo "fixture lockfile gate: ${#manifests[@]} workspace(s) locked"

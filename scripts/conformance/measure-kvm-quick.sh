#!/usr/bin/env bash
# Measurement for #1795. Never fills or refreshes an oracle: a cache miss is
# evidence of missing coverage, not permission to launch a broad Docker pass.
# Usage: scripts/conformance/measure-kvm-quick.sh /absolute/new/evidence-dir
# Uses the existing smoke tier (the tier behind conformance-quick).
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:?usage: measure-kvm-quick.sh /absolute/new/evidence-dir}
[[ $# == 1 && "$out" == /* ]] || exit 2
mkdir -- "$out"
cd -- "$repo"
# Reuses the dispatch job's inherited VM-local gate lease. Never requests
# physical-host custody. Keep builds and guest execution in the same lease.
exec just lease gate bash -euo pipefail -c '
    out=$1
    export CARRICK_REQUIRE_KVM=1
    export CARRICK_RUN_ID="issue1795-quick-$$"
    {
        git rev-parse HEAD
        uname -a
        id
        ls -l /dev/kvm
        printf "run_id=%s\n" "$CARRICK_RUN_ID"
        if command -v docker; then docker version || :; else echo "Docker unavailable"; fi
    } > "$out/host.txt" 2>&1
    cargo build --locked -p carrick-cli --no-default-features \
        --features platform-linux --release > "$out/build-cli.log" 2>&1
    cargo build --locked -p carrick-conformance --release \
        > "$out/build-harness.log" 2>&1
    sha256sum target/release/carrick target/release/carrick-conformance \
        scripts/conformance/suites.toml scripts/conformance/oracle-cache.jsonl \
        > "$out/inputs.sha256"
    target/release/carrick-conformance --lane kvm-local --tier smoke \
        --ecosystem ltp --ecosystem go --ecosystem node --ecosystem cpython \
        --dry-run > "$out/plan.log" 2>&1
    touch "$out/raw-start"
    status=0
    target/release/carrick-conformance --lane kvm-local --tier smoke \
        --ecosystem ltp --ecosystem go --ecosystem node --ecosystem cpython \
        --require-cached-oracle --no-image-refresh --force --flake-retries 0 \
        --jsonl "$out/results.jsonl" > "$out/quick.log" 2>&1 || status=$?
    printf "%s\n" "$status" > "$out/quick.exit"
    # Retain both streams of any workloads that actually started. The harness
    # names these in results.jsonl; cache-admission failure starts no workload.
    if [[ -d target/conformance/raw ]]; then
        mkdir "$out/raw"
        find target/conformance/raw -maxdepth 1 -type f -newer "$out/raw-start" \
            -exec cp -t "$out/raw" -- {} +
    fi
    exit "$status"
' bash "$out"

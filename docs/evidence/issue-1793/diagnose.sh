#!/usr/bin/env bash
# Separate launch diagnostics, never substituted for the eight scoreboard rows.
# Run from repository root under just lease gate after run.sh has finished.
set -euo pipefail
out=$(realpath "${1:?new output directory required}")
mkdir -p "$out"
[[ ! -e "$out/status.tsv" ]]
export CARRICK_REQUIRE_KVM=1
bin=$(realpath target/release/carrick)
active_id=
cleanup() {
    if [[ -n "$active_id" ]]; then bash scripts/sudo/kill.sh "$active_id" >> "$out/$active_id.cleanup" 2>&1; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'diagnostic\trun_id\texit\n' > "$out/status.tsv"
run() {
    local label=$1 rc
    shift
    active_id="i1793-diag-$(date -u +%Y%m%dT%H%M%S)-$label"
    printf '%q ' "$bin" "$@" > "$out/$label.command"
    printf '\n' >> "$out/$label.command"
    set +e
    CARRICK_RUN_ID="$active_id" timeout --foreground --signal=KILL 120s "$bin" "$@" < /dev/null > "$out/$label.out" 2> "$out/$label.err"
    rc=$?
    set -e
    cleanup
    printf '%s\t%s\t%s\n' "$label" "$active_id" "$rc" >> "$out/status.tsv"
    active_id=
}
run shell run --json --platform linux/amd64 --pull never --entrypoint /bin/sh golang:1.24 -c 'printf "shell-ok\n"'
run loader run --json --platform linux/amd64 --pull never --entrypoint /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 golang:1.24 /usr/bin/dash -c 'printf "loader-shell-ok\n"'

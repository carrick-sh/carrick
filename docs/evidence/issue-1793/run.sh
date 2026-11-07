#!/usr/bin/env bash
# Issue 1793 measurement only. Invoke from the repository root under just lease gate.
# Images are pulled separately; a pull failure means NOT MEASURED, never FAIL.
set -euo pipefail
out=$(realpath "${1:?output directory required (must be new)}")
mkdir -p "$out"
if [[ -e "$out/rows.tsv" ]]; then echo 'refusing to overwrite a run' >&2; exit 2; fi
bin=$(realpath "${CARRICK_BIN:-target/release/carrick}")
export CARRICK_REQUIRE_KVM=1
active_id=
cleanup() {
    if [[ -n "$active_id" ]]; then
        bash scripts/sudo/kill.sh "$active_id" >> "$out/$active_id.cleanup" 2>&1
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Known answers: preserve nonzero status, capture both streams, enforce deadline.
set +e
timeout --foreground --signal=KILL 1s bash -c 'echo known-out; echo known-err >&2; exit 7' > "$out/known.out" 2> "$out/known.err"
known=$?
timeout --foreground --signal=KILL 1s sleep 5 > "$out/deadline.out" 2> "$out/deadline.err"
deadline=$?
set -e
[[ $known == 7 && $deadline == 137 ]]
[[ $(cat "$out/known.out") == known-out && $(cat "$out/known.err") == known-err ]]
printf 'exit_status=%s deadline_status=%s\n' "$known" "$deadline" > "$out/known-answer.txt"
{
    date -u +%FT%TZ
    git rev-parse HEAD
    sha256sum "$bin"
    uname -a
    id
    ls -l /dev/kvm
    printf 'CARRICK_REQUIRE_KVM=%s\nlease_socket=%s\n' "$CARRICK_REQUIRE_KVM" "${CARRICK_HOST_LEASE_SOCKET:-unset}"
    "$bin" --version
} > "$out/identity.txt" 2>&1
printf 'row\timage\trun_id\tstatus\texit\n' > "$out/rows.tsv"
for image in golang:1.24 python:3.12 node:24; do
    key=${image/:/-}
    set +e
    timeout --foreground --signal=KILL 120s "$bin" pull --platform linux/amd64 "$image" > "$out/pull-$key.out" 2> "$out/pull-$key.err"
    rc=$?
    set -e
    printf '%s\n' "$rc" > "$out/pull-$key.status"
done
"$bin" images > "$out/images.txt" 2>&1
row() {
    local name=$1 image=$2 cmd=$3 key=${2/:/-} rc
    if [[ -n ${ONLY_ROW:-} && $name != "$ONLY_ROW" ]]; then return; fi
    active_id="i1793-$(date -u +%Y%m%dT%H%M%S)-$name"
    printf '%s\n' "$cmd" > "$out/$name.command"
    if [[ $(cat "$out/pull-$key.status") != 0 ]]; then
        printf '%s\t%s\t%s\tnot measured (pull failed)\t-\n' "$name" "$image" "$active_id" >> "$out/rows.tsv"
        active_id=
        return
    fi
    set +e
    CARRICK_RUN_ID="$active_id" timeout --foreground --signal=KILL 120s "$bin" run --platform linux/amd64 --pull never --entrypoint /bin/sh "$image" -c "$cmd" < /dev/null > "$out/$name.out" 2> "$out/$name.err"
    rc=$?
    set -e
    cleanup
    printf '%s\t%s\t%s\texecuted\t%s\n' "$name" "$image" "$active_id" "$rc" >> "$out/rows.tsv"
    active_id=
}
row go-version golang:1.24 'go version'
row go-run golang:1.24 'printf '\''package main\nimport "fmt"\nfunc main(){fmt.Println("hello-ok")}\n'\'' > /tmp/hello.go; go run /tmp/hello.go'
row py-start python:3.12 'python3 -c '\''import sys; print(sys.version.split()[0], flush=True)'\'
row py-thread python:3.12 'python3 -c '\''import threading; t=threading.Thread(target=lambda: print("thread-ok", flush=True)); t.start(); t.join()'\'
row py-fork python:3.12 'python3 -c '\''import os; p=os.fork(); print("child-ok" if p==0 else "parent-ok", flush=True); os._exit(0) if p==0 else os.waitpid(p,0)'\'
row py-subprocess python:3.12 'python3 -c '\''import subprocess; subprocess.run(["/bin/echo", "sub-ok"], check=True)'\'
row node-version node:24 'node -e '\''console.log(process.version)'\'
row node-child node:24 'node -e '\''process.stdout.write(require("child_process").execSync("echo child-ok"))'\'

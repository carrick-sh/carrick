#!/usr/bin/env bash
# Ad hoc issue investigation, not a conformance gate. Run under just lease gate.
set -euo pipefail
out=$(realpath "${1:?new output directory}")
mkdir -p "$out"
[[ ! -e "$out/status.tsv" ]]
bin=$(realpath "${CARRICK_BIN:-target/release/carrick}")
export CARRICK_REQUIRE_KVM=1 RUST_LOG=carrick=debug
printf 'case\trun_id\texit\telapsed_seconds\n' > "$out/status.tsv"
run() {
    local label=$1 rc started=$SECONDS run_id
    shift
    run_id="i1793-launch-$(date -u +%Y%m%dT%H%M%S)-$label"
    printf 'RUST_LOG=carrick=debug CARRICK_REQUIRE_KVM=1 CARRICK_RUN_ID=%q timeout --foreground --signal=KILL 120s ' "$run_id" > "$out/$label.command"
    printf '%q ' "$bin" "$@" >> "$out/$label.command"
    printf '\n' >> "$out/$label.command"
    set +e
    CARRICK_RUN_ID="$run_id" CARRICK_EL1_CENSUS="$out/census" timeout --foreground --signal=KILL 120s "$bin" "$@" < /dev/null > "$out/$label.out" 2> "$out/$label.err" &
    local waiter=$!
    # Snapshots identify setup vs guest execution; no performance claim.
    for delay in 2 8 20; do
        sleep "$delay"
        kill -0 "$waiter" 2>/dev/null || break
        {
            date -u +%FT%TZ
            ps -eo pid,ppid,stat,wchan:32,comm
            for pid in $(pgrep -u "$(id -u)" -f "carrick:$run_id|^$bin"); do
                printf '\npid=%s\n' "$pid"
                ls -l "/proc/$pid/fd"
                cat "/proc/$pid/io" "/proc/$pid/wchan"
            done
        } > "$out/$label-snapshot-$delay.txt" 2>&1
        timeout --foreground --signal=KILL 5s "$bin" debug capture --run-id "$run_id" --output-dir "$out/$label-capture-$delay" > "$out/$label-capture-$delay.out" 2> "$out/$label-capture-$delay.err"
    done
    wait "$waiter"
    rc=$?
    bash scripts/sudo/kill.sh "$run_id" > "$out/$label.cleanup" 2>&1
    set -e
    printf '%s\t%s\t%s\t%s\n' "$label" "$run_id" "$rc" "$((SECONDS-started))" >> "$out/status.tsv"
}
case "${DIAG_SET:-minimal}" in
minimal)
    run alpine run --rm --json --platform linux/amd64 alpine:3 /bin/echo hi
    run busybox run --rm --json --platform linux/amd64 busybox /bin/echo hi
    ;;
pull)
    run pull-go pull --platform linux/amd64 golang:1.24
    run pull-python pull --platform linux/amd64 python:3.12
    run pull-node pull --platform linux/amd64 node:24
    ;;
ecosystem)
    run go-version run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/go/bin/go golang:1.24 version
    run go-run run --rm --json --platform linux/amd64 --pull never --volume "$(realpath docs/evidence/issue-1793/hello.go):/tmp/hello.go:ro" --entrypoint /usr/local/go/bin/go golang:1.24 run /tmp/hello.go
    run py-start run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/python3 python:3.12 -c 'import sys; print(sys.version.split()[0], flush=True)'
    run py-thread run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/python3 python:3.12 -c 'import threading; t=threading.Thread(target=lambda: print("thread-ok", flush=True)); t.start(); t.join()'
    run py-fork run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/python3 python:3.12 -c 'import os; p=os.fork(); print("child-ok" if p==0 else "parent-ok", flush=True); os._exit(0) if p==0 else os.waitpid(p,0)'
    run py-subprocess run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/python3 python:3.12 -c 'import subprocess; subprocess.run(["/bin/echo", "sub-ok"], check=True)'
    run node-version run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/node node:24 -e 'console.log(process.version)'
    run node-child run --rm --json --platform linux/amd64 --pull never --entrypoint /usr/local/bin/node node:24 -e 'process.stdout.write(require("child_process").execSync("echo child-ok"))'
    ;;
*) echo 'unknown DIAG_SET' >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Linux/macOS harness for scripts/lib/test-signed-run.sh (#1114): drive the
# production per-test runner with a fake libtest executable. A test that
# aborts (SIGKILL, the d9dd906c7c `el1_ipc_pairs_blocking` shape) must not
# stop the tests after it; a hang is a deadline row; a clean zero-test exit
# fails; a spent binary budget turns every unrun test into a not-run row.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
export TMPDIR="$root"
. scripts/lib/test-signed-run.sh

fake="$root/el1_fake"
cat >"$fake" <<'FAKE'
#!/usr/bin/env bash
# Invoked as `<exe> [flags] <test> --exact`; the test name precedes --exact.
name=""
prev=""
for arg in "$@"; do
    [ "$arg" = --exact ] && name="$prev"
    prev="$arg"
done
printf '%s %s\n' "$name" "$CARRICK_RUN_ID" >>"$FAKE_LOG"
# Run whole (the opt-out): no `--exact`; FAKE_WHOLE picks the binary's fate.
if [ -z "$name" ]; then
    [ "${FAKE_WHOLE:-ok}" = abort ] && kill -9 $$
    printf 'running 2 tests\ntest one ... ok\ntest two ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n'
    exit 0
fi
case "$name" in
    aborts) kill -9 $$ ;;
    hangs) exec sleep 30 ;;
    empty) echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;' ;;
    *) printf 'running 1 test\ntest %s ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n' "$name" ;;
esac
FAKE
chmod +x "$fake"

reap_run_id() { printf '%s\n' "$1" >>"$root/reaped"; }
capture_deadline_diagnostics() { echo "diagnostics for $3"; }
stop_watchdog() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

run_case() {
    selected="$root/selected"
    : >"$selected"
    for name in "$@"; do printf '%s\t%s\n' "$fake" "$name" >>"$selected"; done
    receipt_tmp="$root/receipt"
    : >"$receipt_tmp"
    : >"$root/reaped"
    export FAKE_LOG="$root/invoked"
    : >"$FAKE_LOG"
    run_id=harness
    requested_filter_json=null
    scratch=()
    active_exe_pid="" active_watchdog_pid="" active_exe_run_id=""
    failed=0
    test_signed_run_executable_tests "$fake" "exe-id" 1 --nocapture >"$root/log" 2>&1
}
status_of() { jq -r --arg t "$1" 'select(.test_name == $t) | .terminal_status' "$root/receipt"; }

# 1. An aborting test, then tests that still run.
test_deadline_secs=5 binary_deadline_secs=0
run_case passes aborts after empty
[ "$failed" = 1 ]
[ "$(status_of passes)" = passed ]
[ "$(status_of aborts)" = failed ]
[ "$(status_of after)" = passed ]
[ "$(status_of empty)" = failed ]
[ "$(jq -s length "$root/receipt")" = 4 ]
grep -Fxq 'test aborts ... FAILED' "$root/log"
grep -Fxq 'test empty ... FAILED' "$root/log"
grep -q 'test-signed: running .*el1_fake ' "$root/log"
# Every test ran in its own process with its own run id, reaped after it.
[ "$(cut -d' ' -f2 "$root/invoked" | sort -u | wc -l | tr -d ' ')" = 4 ]
grep -Fxq 'harness-b1-t2' "$root/reaped"
grep -Fxq 'harness-b1-t3-cli' "$root/reaped"
# The run's flags reach each test; the filter does not.
grep -Fq 'after harness-b1-t3' "$root/invoked"

# 2. A hang is killed at its deadline and recorded, and the next test runs.
test_deadline_secs=1 binary_deadline_secs=0
run_case hangs after
[ "$(status_of hangs)" = deadline ]
[ "$(status_of after)" = passed ]
grep -q 'test-signed: DEADLINE .*el1_fake hangs' "$root/log"

# 3. A spent binary budget leaves every unrun test as an itemized not-run.
test_deadline_secs=0 binary_deadline_secs=1
run_case hangs one two
[ "$(status_of hangs)" = deadline ]
[ "$(status_of one)" = not-run ]
[ "$(status_of two)" = not-run ]
grep -Fxq 'test one ... FAILED' "$root/log"

# 4. All passing: no failure.
test_deadline_secs=5 binary_deadline_secs=0
run_case passes after
[ "$failed" = 0 ]

# 5. CARRICK_TEST_SIGNED_PER_TEST=0 is the exact opt-out: the binary runs
#    whole, once, and is receipted only if it exits 0 (the pre-#1114 shape).
export CARRICK_TEST_SIGNED_PER_TEST=0
FAKE_WHOLE=ok run_case one two
[ "$failed" = 0 ]
[ "$(wc -l <"$root/invoked" | tr -d ' ')" = 1 ]
[ "$(status_of one)" = passed ] && [ "$(status_of two)" = passed ]
grep -Fxq 'harness-b1' "$root/reaped"
export FAKE_WHOLE=abort
run_case one two
unset FAKE_WHOLE
[ "$failed" = 1 ]
[ "$(jq -s length "$root/receipt")" = 0 ]
grep -q 'test-signed: FAIL .*el1_fake' "$root/log"
# Any other value is refused rather than guessed at.
export CARRICK_TEST_SIGNED_PER_TEST=yes
run_case one
[ "$failed" = 1 ]
[ ! -s "$root/invoked" ]
unset CARRICK_TEST_SIGNED_PER_TEST
printf 'signed per-test runner harness: passed\n'

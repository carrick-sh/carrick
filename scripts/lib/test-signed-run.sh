#!/usr/bin/env bash
# Run one signed executable's selected tests, each in its own process (#1114).
#
# A whole-binary run lost every test after one that hung or aborted: the
# binary's deadline (or a kernel abort) killed the process, and the receipt
# could not tell a new failure from a test that never ran (#352, #353; main
# d9dd906c7c lost two el1_sched tests behind an aborting
# el1_ipc_pairs_blocking). Here each selected test runs as
# `<exe> <flags> <test> --exact` with its own CARRICK_RUN_ID, its own
# deadline and diagnostics, and a scoped reap before the next test starts,
# and gets one receipt row: passed, failed, deadline or not-run.
#
# A dead or crashed test process is an itemized failure, never a missing
# row; a clean exit that ran no test (an `--exact` mismatch) fails too. The
# log keeps libtest's `test <name> ... ok|FAILED` lines under the
# `test-signed: running <exe>` header, so `xtask accept` itemizes them.
# The per-binary deadline remains as a backstop budget: once it is spent,
# every test not yet run is an itemized not-run failure.
#
# `CARRICK_TEST_SIGNED_PER_TEST=0` (exactly) is the opt-out: each binary
# runs whole, with all its selected tests in one process under the
# per-binary deadline, receipted passed only if the binary exits 0 (the
# shape before #1114). Any other value but unset or `1` is refused.
#
# Callers provide: `selected` (tab-separated exe/test lines), `run_id`,
# `receipt_tmp`, `requested_filter_json`, `binary_deadline_secs`,
# `test_deadline_secs`, `scratch` (array), and the functions
# `reap_run_id <id>`, `capture_deadline_diagnostics <exe> <pid> <id>` and
# `stop_watchdog <pid>`. Sets `failed=1` on any failure.

# test_signed_record_execution <executable_id> <test> <status>
test_signed_record_execution() {
    jq -nc \
        --arg schema "carrick.signed-embed-test.v1" \
        --arg executable_id "$1" \
        --arg test_name "$2" \
        --arg terminal_status "$3" \
        --argjson requested_filter "$requested_filter_json" \
        '{schema:$schema,record_type:"execution",executable_id:$executable_id,test_name:$test_name,requested_test_filter:$requested_filter,terminal_status:$terminal_status}' \
        >>"$receipt_tmp"
}

# test_signed_run_executable_tests <exe> <executable_id> <exe_index> [libtest args...]
test_signed_run_executable_tests() {
    case "${CARRICK_TEST_SIGNED_PER_TEST:-1}" in
        1) test_signed_run_tests_isolated "$@" ;;
        0) test_signed_run_binary_whole "$@" ;;
        *)
            echo "test-signed: invalid CARRICK_TEST_SIGNED_PER_TEST: ${CARRICK_TEST_SIGNED_PER_TEST} (expected 0 or 1)" >&2
            failed=1
            ;;
    esac
}

# The opt-out: one process for the binary's selected tests.
test_signed_run_binary_whole() {
    local exe="$1" executable_id="$2" exe_index="$3"
    shift 3
    local tid="$run_id-b$exe_index"
    active_exe_run_id="$tid"
    echo "test-signed: running $exe $*"
    local marker diag
    marker="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-deadline-fired.XXXXXX")"
    diag="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-deadline-diag.XXXXXX")"
    scratch+=("$marker" "$diag")
    env RUST_TEST_THREADS=1 CARRICK_RUN_ID="$tid" "$exe" "$@" &
    active_exe_pid=$!
    if [ "$binary_deadline_secs" -gt 0 ]; then
        test_signed_arm_watchdog "$exe" "$tid" "$binary_deadline_secs" "$marker" "$diag"
    fi
    local rc=0
    wait "$active_exe_pid" || rc=$?
    active_exe_pid=""
    test_signed_disarm_watchdog "$marker"
    if [ -s "$marker" ]; then
        cat "$diag" >&2
        echo "test-signed: DEADLINE $exe (${binary_deadline_secs}s, CARRICK_RUN_ID=$tid)" >&2
        echo "test-signed: FAIL $exe" >&2
        failed=1
    elif [ "$rc" -eq 0 ]; then
        local selected_exe test_name
        while IFS="$(printf '\t')" read -r selected_exe test_name; do
            [ "$selected_exe" = "$exe" ] || continue
            test_signed_record_execution "$executable_id" "$test_name" passed
        done <"$selected"
    else
        echo "test-signed: FAIL $exe" >&2
        failed=1
    fi
    rm -f "$marker" "$diag"
    for id in "$tid" "$tid-cli"; do
        if ! reap_run_id "$id"; then
            echo "test-signed: scoped cleanup failed for $id" >&2
            failed=1
        fi
    done
    active_exe_run_id=""
}

# Kill `active_exe_pid` after <secs>, capturing diagnostics and reaping <id>.
test_signed_arm_watchdog() {
    local exe="$1" id_base="$2" secs="$3" marker="$4" diag="$5"
    (
        set +e
        sleep "$secs" >/dev/null 2>&1 &
        sleep_pid=$!
        trap 'kill -9 "$sleep_pid" 2>/dev/null || true; exit 0' TERM INT
        wait "$sleep_pid" 2>/dev/null || exit 0
        if kill -0 "$active_exe_pid" 2>/dev/null; then
            printf '1\n' >"$marker"
            capture_deadline_diagnostics "$exe" "$active_exe_pid" "$id_base" >"$diag" 2>&1
            for id in "$id_base" "$id_base-cli"; do
                reap_run_id "$id" >>"$diag" 2>&1 || true
            done
            kill -9 "$active_exe_pid" 2>/dev/null || true
        fi
    ) >/dev/null 2>&1 &
    active_watchdog_pid=$!
}

test_signed_disarm_watchdog() {
    if [ -n "$active_watchdog_pid" ]; then
        if [ -s "$1" ]; then
            wait "$active_watchdog_pid" 2>/dev/null || true
        else
            stop_watchdog "$active_watchdog_pid"
        fi
        active_watchdog_pid=""
    fi
}

# The default: one process per selected test.
test_signed_run_tests_isolated() {
    local exe="$1" executable_id="$2" exe_index="$3"
    shift 3
    # Forward the run's flags; the filter and --exact become `<test> --exact`.
    local flags=() arg
    for arg in "$@"; do
        case "$arg" in
            --exact) ;;
            -*) flags+=("$arg") ;;
        esac
    done
    local tests=() selected_exe test_name
    while IFS="$(printf '\t')" read -r selected_exe test_name; do
        [ "$selected_exe" = "$exe" ] && tests+=("$test_name")
    done <"$selected"
    echo "test-signed: running $exe $* (${#tests[@]} test(s), one process each)"
    local budget_end=0
    if [ "$binary_deadline_secs" -gt 0 ]; then
        budget_end=$(($(date +%s) + binary_deadline_secs))
    fi
    local index=0 name
    for name in ${tests[@]+"${tests[@]}"}; do
        index=$((index + 1))
        local tid="$run_id-b$exe_index-t$index"
        if [ "$budget_end" -gt 0 ] && [ "$(date +%s)" -ge "$budget_end" ]; then
            echo "test $name ... FAILED"
            echo "test-signed: NOT-RUN $exe $name (binary budget of ${binary_deadline_secs}s spent)" >&2
            test_signed_record_execution "$executable_id" "$name" not-run
            failed=1
            continue
        fi
        local deadline=$test_deadline_secs
        if [ "$budget_end" -gt 0 ]; then
            local left=$((budget_end - $(date +%s)))
            if [ "$deadline" -eq 0 ] || [ "$left" -lt "$deadline" ]; then
                deadline=$left
            fi
        fi
        local out marker diag
        out="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-test-out.XXXXXX")"
        marker="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-test-deadline.XXXXXX")"
        diag="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-test-diag.XXXXXX")"
        scratch+=("$out" "$marker" "$diag")
        active_exe_run_id="$tid"
        env RUST_TEST_THREADS=1 CARRICK_RUN_ID="$tid" "$exe" ${flags[@]+"${flags[@]}"} "$name" --exact >"$out" 2>&1 &
        active_exe_pid=$!
        if [ "$deadline" -gt 0 ]; then
            test_signed_arm_watchdog "$exe" "$tid" "$deadline" "$marker" "$diag"
        fi
        local rc=0
        wait "$active_exe_pid" || rc=$?
        active_exe_pid=""
        test_signed_disarm_watchdog "$marker"
        cat "$out"
        local status
        if [ -s "$marker" ]; then
            cat "$diag" >&2
            echo "test $name ... FAILED"
            echo "test-signed: DEADLINE $exe $name (${deadline}s, CARRICK_RUN_ID=$tid)" >&2
            status=deadline
        elif [ "$rc" -eq 0 ] && grep -aq ' 1 passed; 0 failed; 0 ignored;' "$out"; then
            status=passed
        else
            if [ "$rc" -eq 0 ]; then
                echo "test-signed: $exe $name exited cleanly but ran no test" >&2
            else
                echo "test-signed: $exe $name exited with status $rc" >&2
            fi
            echo "test $name ... FAILED"
            status=failed
        fi
        test_signed_record_execution "$executable_id" "$name" "$status"
        [ "$status" = passed ] || failed=1
        for id in "$tid" "$tid-cli"; do
            if ! reap_run_id "$id"; then
                echo "test-signed: scoped cleanup failed for $id" >&2
                failed=1
            fi
        done
        active_exe_run_id=""
        rm -f "$out" "$marker" "$diag"
    done
    echo "test-signed: finished $exe (${#tests[@]} test(s))"
}

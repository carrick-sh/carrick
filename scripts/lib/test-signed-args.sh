#!/bin/sh
# Fail-closed argument validation shared by scripts/test-signed.sh and its
# host-only behavior tests. This file is sourced; it performs no work itself.

test_signed_validate_run_id() {
    local run_id="$1"

    if [ -z "$run_id" ] || [ "${#run_id}" -gt 120 ]; then
        echo "test-signed: invalid CARRICK_RUN_ID: expected 1..120 safe component characters" >&2
        return 2
    fi
    case "$run_id" in
        [A-Za-z0-9]*) ;;
        *)
            echo "test-signed: invalid CARRICK_RUN_ID: must begin with an ASCII alphanumeric character" >&2
            return 2
            ;;
    esac
    case "$run_id" in
        *[!A-Za-z0-9._-]*)
            echo "test-signed: invalid CARRICK_RUN_ID: only ASCII alphanumeric, '.', '_', and '-' are allowed" >&2
            return 2
            ;;
    esac
    if [ "$run_id" = "--all" ]; then
        echo "test-signed: invalid CARRICK_RUN_ID: --all is reserved for manual global cleanup" >&2
        return 2
    fi
}

test_signed_parse_libtest_args() {
    TEST_SIGNED_REQUESTED_FILTER=""
    TEST_SIGNED_HAS_EXACT=0
    TEST_SIGNED_IGNORED_ONLY=0
    TEST_SIGNED_INCLUDE_IGNORED=0

    local arg
    for arg in "$@"; do
        case "$arg" in
            --exact)
                TEST_SIGNED_HAS_EXACT=1
                ;;
            --ignored)
                TEST_SIGNED_IGNORED_ONLY=1
                ;;
            --include-ignored)
                TEST_SIGNED_INCLUDE_IGNORED=1
                ;;
            --nocapture|--show-output)
                ;;
            -*)
                echo "test-signed: unsupported receipted libtest arguments: $arg" >&2
                return 2
                ;;
            *)
                if [ -n "$TEST_SIGNED_REQUESTED_FILTER" ]; then
                    echo "test-signed: unsupported receipted libtest arguments: only one test filter is allowed" >&2
                    return 2
                fi
                TEST_SIGNED_REQUESTED_FILTER="$arg"
                ;;
        esac
    done

    if [ "$TEST_SIGNED_HAS_EXACT" -eq 1 ] && [ -z "$TEST_SIGNED_REQUESTED_FILTER" ]; then
        echo "test-signed: --exact requires one requested test filter" >&2
        return 2
    fi
    if [ "$TEST_SIGNED_IGNORED_ONLY" -eq 1 ] && [ "$TEST_SIGNED_INCLUDE_IGNORED" -eq 1 ]; then
        echo "test-signed: --ignored and --include-ignored cannot be combined in a receipted run" >&2
        return 2
    fi
}

test_signed_publish_receipt() {
    local temporary_receipt="$1"
    local canonical_receipt="$2"
    local success_message="${3:-}"

    if mv -f "$temporary_receipt" "$canonical_receipt"; then
        echo "test-signed: receipt $canonical_receipt"
        if [ -n "$success_message" ]; then
            echo "$success_message"
        fi
        return 0
    fi

    echo "test-signed: failed to publish receipt $canonical_receipt" >&2
    return 1
}

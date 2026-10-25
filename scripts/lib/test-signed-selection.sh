#!/usr/bin/env bash
# Shared unsigned libtest census and filter resolution for the signed runner
# and host-only harness. Inputs: exes, filter/ignored flags, negative_test.
# Outputs: run_exes, sign_exes, carrier, negative_test_name, exact_name,
# selected census path; temporary files append to the caller's scratch array.
test_signed_select_executables() {
    # 2. Enumerate every test before execution, including the ignored subset, then
    #    resolve the invocation's exact/non-exact filter fail-closed.
    census="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-census.XXXXXX")"
    ignored_census="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-ignored.XXXXXX")"
    selected="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-selected.XXXXXX")"
    scratch+=("$census" "$ignored_census" "$selected")
    for exe in "${exes[@]}"; do
        list_log="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-list.XXXXXX")"
        ignored_log="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-ignored-list.XXXXXX")"
        scratch+=("$list_log" "$ignored_log")
        "$exe" --list >"$list_log"
        "$exe" --list --ignored >"$ignored_log"
        while IFS= read -r listed; do
            case "$listed" in
                *': test') printf '%s\t%s\n' "$exe" "${listed%: test}" >>"$census" ;;
            esac
        done <"$list_log"
        while IFS= read -r listed; do
            case "$listed" in
                *': test') printf '%s\t%s\n' "$exe" "${listed%: test}" >>"$ignored_census" ;;
            esac
        done <"$ignored_log"
    done

    exact_name=""
    exact_matches=0
    while IFS="$(printf '\t')" read -r exe name; do
        [ -n "$exe" ] || continue
        is_ignored=0
        if grep -Fqx "$exe$(printf '\t')$name" "$ignored_census"; then
            is_ignored=1
        fi
        if [ "$ignored_only" -eq 1 ] && [ "$is_ignored" -ne 1 ]; then
            continue
        fi
        if [ "$ignored_only" -eq 0 ] && [ "$include_ignored" -eq 0 ] && [ "$is_ignored" -eq 1 ]; then
            continue
        fi

        if [ "$has_exact" -eq 1 ]; then
            if [ "$name" = "$requested_filter" ] || [[ "$name" == *"::$requested_filter" ]]; then
                exact_name="$name"
                exact_matches=$((exact_matches + 1))
                printf '%s\t%s\n' "$exe" "$name" >>"$selected"
            fi
        elif [ -n "$requested_filter" ]; then
            case "$name" in
                *"$requested_filter"*) printf '%s\t%s\n' "$exe" "$name" >>"$selected" ;;
            esac
        else
            printf '%s\t%s\n' "$exe" "$name" >>"$selected"
        fi
    done <"$census"

    if [ "$has_exact" -eq 1 ] && [ "$exact_matches" -ne 1 ]; then
        echo "test-signed: exact filter $requested_filter matched $exact_matches tests; expected exactly one" >&2
        exit 1
    fi
    resolved_count="$(wc -l <"$selected" | tr -d ' ')"
    if [ "$resolved_count" -eq 0 ]; then
        echo "test-signed: filter ${requested_filter:-<unfiltered>} resolved zero tests" >&2
        exit 1
    fi

    run_exes=()
    while IFS= read -r exe; do
        [ -n "$exe" ] && run_exes+=("$exe")
    done < <(awk -F '\t' '!seen[$1]++ { print $1 }' "$selected")

    # Select on unsigned libtest listings: listing never boots a VM. Preserve
    # unfiltered signing, while filtered runs sign only matching binaries and
    # the negative-control carrier. Reuse the census instead of listing again.
    carrier=""
    negative_test_name=""
    negative_matches=0
    while IFS="$(printf '\t')" read -r exe name; do
        if [ "$name" = "$negative_test" ] || [[ "$name" == *"::$negative_test" ]]; then
            carrier="$exe"
            negative_test_name="$name"
            negative_matches=$((negative_matches + 1))
        fi
    done <"$census"
    if [ "$negative_matches" -ne 1 ]; then
        echo "test-signed: $negative_test matched $negative_matches tests; expected exactly one" >&2
        exit 1
    fi
    sign_exes=()
    for exe in "${exes[@]}"; do
        if [ -z "$requested_filter" ] || [ "$exe" = "$carrier" ] ||
            awk -F '\t' -v exe="$exe" '$1 == exe { found=1 } END { exit !found }' "$selected"; then
            sign_exes+=("$exe")
        fi
    done
}

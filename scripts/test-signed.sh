#!/usr/bin/env bash
# Sign and run a crate's cargo test executables so they can boot HVF guests.
#
# A guest under macOS/HVF only runs from an executable carrying the
# com.apple.security.hypervisor entitlement — and the executable that calls
# hv_vm_create is the TEST BINARY (target/debug/deps/<crate>-<hash>), which
# nothing else signs. A bare `cargo test` therefore dies HV_DENIED
# (0xfae94007) on its first guest. This is the test-executable counterpart of
# scripts/build-signed.sh: build the package's test executables without
# running them, push each through the SAME post-link path the shipped CLI
# uses (scripts/lib/post-link-sign.sh: vtool build-version stamp + ad-hoc
# codesign with scripts/entitlements.plist), prove the entitlement landed,
# then run each serially (HVF allows ONE VM per process; the guest tests also
# redirect the process's own fd 1 for the Inherit case).
#
# FAIL-CLOSED by design: an unsigned executable is a FAILURE here, never a
# skip (AGENTS.md: a test no gate executes is not a test). The embed crate
# maps HV_DENIED to `EmbedError::Entitlement`, its guest tests assert that
# variant never appears, and this script additionally runs the NEGATIVE
# control: an ad-hoc-signed copy WITHOUT the entitlement (exactly a bare
# `cargo test` executable) must produce `EmbedError::Entitlement`. A signing
# regression cannot pass silently in either direction.
#
# Usage: scripts/test-signed.sh <package> [test-filter] [supported libtest flags]
#   scripts/test-signed.sh carrick-embed
#   scripts/test-signed.sh carrick-embed captured_ --nocapture
# Receipted runs accept at most one positional filter plus `--exact`,
# `--ignored`, `--include-ignored`, `--nocapture`, and `--show-output`. Other
# libtest options fail closed because a value such as `--skip TEST` cannot be
# reconciled with one truthful execution row per selected test. Accepted args
# go straight to each libtest executable (no cargo in between); do not add a
# `--` separator.
#
# Written for the macOS system bash (3.2): no mapfile, no `${arr[@]}` on an
# empty array under `set -u`, `+=` array appends only.
#
# Cleanup is run-id scoped: every guest these executables launch carries
# CARRICK_RUN_ID (default embed-signed-<pid>), stamped into the carrier's
# proctitle as `carrick:<run-id>:`; scripts/sudo/kill.sh <run-id> reaps only
# those on exit (plus the `<run-id>-cli` child the CLI-parity test spawns —
# kill.sh anchors on the literal `carrick:<id>:` token, so the `-cli` id needs
# its own call). Never `pkill -f carrick`. Logs are never truncated (tail/grep
# on a gate destroys evidence): every executable's full output goes to the
# terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/post-link-sign.sh
. scripts/lib/test-signed-args.sh

pkg="${1:?usage: scripts/test-signed.sh <package> [libtest args...]}"
shift

case "$pkg" in
    ''|*[!A-Za-z0-9._-]*|.*)
        echo "test-signed: invalid package component: $pkg" >&2
        exit 2
        ;;
esac

if [ "${CARRICK_RUN_ID+x}" = "x" ]; then
    run_id="$CARRICK_RUN_ID"
else
    run_id="embed-signed-$$"
fi
test_signed_validate_run_id "$run_id"
test_signed_parse_libtest_args "$@"
requested_filter="$TEST_SIGNED_REQUESTED_FILTER"
has_exact="$TEST_SIGNED_HAS_EXACT"
ignored_only="$TEST_SIGNED_IGNORED_ONLY"
include_ignored="$TEST_SIGNED_INCLUDE_IGNORED"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "test-signed: macOS/HVF only — the entitlement requirement does not exist on this host" >&2
    exit 1
fi
for tool in cargo jq codesign /usr/bin/vtool otool shasum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "test-signed: missing required tool: $tool" >&2
        exit 1
    fi
done

entitlements="scripts/entitlements.plist"
negative_test="unsigned_executable_maps_hv_denied_to_entitlement"

export CARRICK_RUN_ID="$run_id"
source_head="$(git rev-parse HEAD)"
arguments_json="$(jq -nc --args '$ARGS.positional' -- "$@")"

receipt_dir="target/test-results"
receipt_path="$receipt_dir/$pkg-signed-artifacts.jsonl"
mkdir -p "$receipt_dir"
receipt_tmp="$(mktemp "$receipt_dir/.$pkg-signed-artifacts.XXXXXX")"
receipt_ready=0

if [ -n "$requested_filter" ]; then
    requested_filter_json="$(jq -nc --arg value "$requested_filter" '$value')"
else
    requested_filter_json="null"
fi
jq -nc \
    --arg schema "carrick.signed-embed-test.v1" \
    --arg source_head "$source_head" \
    --arg package "$pkg" \
    --arg run_id "$run_id" \
    --argjson arguments "$arguments_json" \
    --argjson requested_filter "$requested_filter_json" \
    '{schema:$schema,record_type:"header",source_head:$source_head,package:$package,arguments:$arguments,requested_test_filter:$requested_filter,carrick_run_id:$run_id}' \
    >"$receipt_tmp"
scratch=()
cleanup() {
    status=$?
    trap - EXIT
    set +e
    cleanup_ok=1
    # Scoped reap of anything this run (or its CLI-parity child) left wedged.
    # Guests are same-user processes, so a direct call reaps them; `sudo -n`
    # first (NOPASSWD on the rig: scripts/sudo/ is under carrick/*/*/*) also
    # catches root-owned `carrick trace` front-ends carrying the same id.
    for id in "$run_id" "$run_id-cli"; do
        cleanup_log="$(mktemp -t carrick-test-signed-cleanup)"
        if sudo -n scripts/sudo/kill.sh "$id" >"$cleanup_log" 2>&1; then
            :
        elif scripts/sudo/kill.sh "$id" >"$cleanup_log" 2>&1; then
            :
        else
            cleanup_ok=0
        fi
        cat "$cleanup_log"
        rm -f "$cleanup_log"
    done
    if [ "${#scratch[@]}" -gt 0 ]; then
        rm -f "${scratch[@]}"
    fi
    if [ "$cleanup_ok" -ne 1 ]; then
        echo "test-signed: scoped cleanup failed for $run_id" >&2
        status=1
    fi

    if [ "$status" -eq 0 ] && [ "$receipt_ready" -eq 1 ]; then
        jq -nc \
            --arg schema "carrick.signed-embed-test.v1" \
            --arg run_id "$run_id" \
            '{schema:$schema,record_type:"cleanup",carrick_run_id:$run_id,remaining_processes:0}' \
            >>"$receipt_tmp"
        if ! jq -s -e '
            all(.[]; .schema == "carrick.signed-embed-test.v1") and
            ([.[] | select(.record_type == "header")] | length == 1) and
            ([.[] | select(.record_type == "executable")] | length >= 1) and
            ([.[] | select(.record_type == "execution")] | length >= 1) and
            ([.[] | select(.record_type == "unentitled_negative_control")] | length == 1) and
            ([.[] | select(.record_type == "cleanup" and .remaining_processes == 0)] | length == 1) and
            (all(.[] | select(.record_type == "executable");
                (.executable_id | length) > 0 and
                (.canonical_path | length) > 0 and
                (.sha256 | length) > 0 and
                (.cdhash | length) > 0 and
                (.lc_uuid | length) > 0 and
                (.entitlement_digest | length) > 0 and
                .entitlement_present == true and
                .dof_carrick_present == true)) and
            (([.[] | select(.record_type == "executable") | .executable_id]) as $ids |
                all(.[] | select(.record_type == "execution");
                    (.executable_id as $id | ($ids | index($id)) != null)))
        ' "$receipt_tmp" >/dev/null; then
            echo "test-signed: receipt validation failed" >&2
            status=1
        elif test_signed_publish_receipt \
            "$receipt_tmp" \
            "$receipt_path" \
            "test-signed: OK ($pkg: ${#run_exes[@]} invoked signed executable(s) passed, ${#exes[@]} signed, negative control passed)"
        then
            receipt_tmp=""
        else
            status=1
        fi
    fi
    if [ -n "$receipt_tmp" ]; then
        rm -f "$receipt_tmp"
    fi
    exit "$status"
}
trap cleanup EXIT

# Build carrick-embed's immutable raw-syscall fixture in a native arm64 Linux
# container, and wait for that Docker phase to exit before any signed HVF test
# process is started.
if [ "$pkg" = "carrick-embed" ]; then
    scripts/build-embed-interceptor-probe.sh
fi

# 1. Build (never run) the package's test executables and collect their
#    paths. Only the package's OWN test-profile artifacts carry
#    `profile.test == true` plus an `executable`; dependencies compile with
#    `test: false`. The JSON goes to a file first so a build failure stops the
#    script (a process substitution's exit status would not).
json_log="$(mktemp -t carrick-test-signed-build)"
scratch+=("$json_log")
if [ "$pkg" = "carrick-embed" ]; then
    cargo test -p "$pkg" --features test-support --no-run --message-format=json >"$json_log"
else
    cargo test -p "$pkg" --no-run --message-format=json >"$json_log"
fi
exes=()
while IFS= read -r exe; do
    [ -n "$exe" ] && exes+=("$exe")
done < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' "$json_log")
if [ "${#exes[@]}" -eq 0 ]; then
    echo "test-signed: cargo produced no test executables for $pkg" >&2
    exit 1
fi

# 2. Sign each executable in place through the shared post-link path, and
#    PROVE the entitlement is on the file before trusting it.
for exe in "${exes[@]}"; do
    scratch+=("$exe.raw.$$" "$exe.tmp.$$")
    carrick_post_link_sign "$exe" "$exe" "$entitlements"
    if ! codesign -d --entitlements - "$exe" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
        echo "test-signed: $exe does not carry com.apple.security.hypervisor after signing" >&2
        exit 1
    fi
    echo "test-signed: signed $exe"
done

# 3. Enumerate every test before execution, including the ignored subset, then
#    resolve the invocation's exact/non-exact filter fail-closed.
census="$(mktemp -t carrick-test-signed-census)"
ignored_census="$(mktemp -t carrick-test-signed-ignored)"
selected="$(mktemp -t carrick-test-signed-selected)"
scratch+=("$census" "$ignored_census" "$selected")
for exe in "${exes[@]}"; do
    list_log="$(mktemp -t carrick-test-signed-list)"
    ignored_log="$(mktemp -t carrick-test-signed-ignored-list)"
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

if [ "$has_exact" -eq 1 ]; then
    rebuilt_args=()
    replaced_filter=0
    for arg in "$@"; do
        if [ "$replaced_filter" -eq 0 ] && [ "$arg" = "$requested_filter" ]; then
            rebuilt_args+=("$exact_name")
            replaced_filter=1
        else
            rebuilt_args+=("$arg")
        fi
    done
    set -- "${rebuilt_args[@]}"
    echo "test-signed: resolved exact filter $requested_filter -> $exact_name"
fi

record_executable() {
    exe="$1"
    exe_dir="$(dirname "$exe")"
    exe_base="$(basename "$exe")"
    canonical_path="$(cd "$exe_dir" && pwd -P)/$exe_base"
    sha256="$(shasum -a 256 "$exe" | awk '{print $1}')"
    cdhash="$(codesign -dvvv "$exe" 2>&1 | awk -F= '$1 == "CDHash" { print $2; exit }')"
    lc_uuid="$(otool -l "$exe" | awk '$1 == "cmd" && $2 == "LC_UUID" { seen=1; next } seen && $1 == "uuid" { print $2; exit }')"
    entitlements_dump="$(mktemp -t carrick-test-signed-entitlements)"
    scratch+=("$entitlements_dump")
    codesign -d --entitlements :- "$exe" >"$entitlements_dump" 2>/dev/null
    if ! grep -q 'com.apple.security.hypervisor' "$entitlements_dump"; then
        echo "test-signed: executable identity lacks hypervisor entitlement: $exe" >&2
        exit 1
    fi
    entitlement_digest="$(shasum -a 256 "$entitlements_dump" | awk '{print $1}')"
    if ! otool -l "$exe" | grep -q '__dof_carrick'; then
        echo "test-signed: executable identity lacks __dof_carrick: $exe" >&2
        exit 1
    fi
    for value in "$canonical_path" "$sha256" "$cdhash" "$lc_uuid" "$entitlement_digest"; do
        if [ -z "$value" ]; then
            echo "test-signed: missing executable identity field for $exe" >&2
            exit 1
        fi
    done
    last_executable_id="$sha256:$canonical_path"
    jq -nc \
        --arg schema "carrick.signed-embed-test.v1" \
        --arg executable_id "$last_executable_id" \
        --arg canonical_path "$canonical_path" \
        --arg sha256 "$sha256" \
        --arg cdhash "$cdhash" \
        --arg lc_uuid "$lc_uuid" \
        --arg entitlement_digest "$entitlement_digest" \
        '{schema:$schema,record_type:"executable",executable_id:$executable_id,canonical_path:$canonical_path,sha256:$sha256,cdhash:$cdhash,lc_uuid:$lc_uuid,entitlement_digest:$entitlement_digest,entitlement_present:true,dof_carrick_present:true}' \
        >>"$receipt_tmp"
}

# 4. Run each selected signed executable serially (one VM per process).
failed=0
for exe in "${run_exes[@]}"; do
    record_executable "$exe"
    executable_id="$last_executable_id"
    echo "test-signed: running $exe $*"
    if env RUST_TEST_THREADS=1 "$exe" "$@"; then
        while IFS="$(printf '\t')" read -r selected_exe test_name; do
            [ "$selected_exe" = "$exe" ] || continue
            jq -nc \
                --arg schema "carrick.signed-embed-test.v1" \
                --arg executable_id "$executable_id" \
                --arg test_name "$test_name" \
                --argjson requested_filter "$requested_filter_json" \
                '{schema:$schema,record_type:"execution",executable_id:$executable_id,test_name:$test_name,requested_test_filter:$requested_filter,terminal_status:"passed"}' \
                >>"$receipt_tmp"
        done <"$selected"
    else
        echo "test-signed: FAIL $exe" >&2
        failed=1
    fi
done

# 5. Negative control. The executable carrying the negative test is copied
#    and re-signed ad-hoc WITHOUT the entitlement — byte-for-byte the state
#    of a bare `cargo test` binary — and must classify HV_DENIED as
#    EmbedError::Entitlement. The test is #[ignore] so step 4 skips it.
carrier=""
negative_test_name=""
negative_matches=0
for exe in "${exes[@]}"; do
    while IFS= read -r listed; do
        name="${listed%: test}"
        if [ "$name" = "$negative_test" ] || [[ "$name" == *"::$negative_test" ]]; then
            carrier="$exe"
            negative_test_name="$name"
            negative_matches=$((negative_matches + 1))
        fi
    done < <("$exe" --list 2>/dev/null)
done
if [ "$negative_matches" -ne 1 ]; then
    echo "test-signed: $negative_test matched $negative_matches tests in $pkg; expected exactly one for the negative control" >&2
    exit 1
fi
noent="$carrier.noent.$$"
scratch+=("$noent")
cp -f "$carrier" "$noent"
codesign --force --sign - "$noent"
if codesign -d --entitlements - "$noent" 2>&1 | grep -q 'com.apple.security.hypervisor'; then
    echo "test-signed: $noent still carries the hypervisor entitlement; the negative control would prove nothing" >&2
    exit 1
fi
neg_log="$(mktemp -t carrick-test-signed-negative)"
scratch+=("$neg_log")
echo "test-signed: negative control on $noent"
neg_rc=0
env RUST_TEST_THREADS=1 "$noent" --ignored --exact "$negative_test_name" >"$neg_log" 2>&1 || neg_rc=$?
cat "$neg_log"
if [ "$neg_rc" -ne 0 ] || ! grep -aq '^test result: ok. 1 passed' "$neg_log"; then
    echo "test-signed: FAIL negative control ($negative_test did not pass on the unentitled copy, rc=$neg_rc)" >&2
    failed=1
else
    source_dir="$(dirname "$carrier")"
    source_base="$(basename "$carrier")"
    source_canonical="$(cd "$source_dir" && pwd -P)/$source_base"
    source_sha="$(shasum -a 256 "$carrier" | awk '{print $1}')"
    source_executable_id="$source_sha:$source_canonical"
    noent_dir="$(dirname "$noent")"
    noent_base="$(basename "$noent")"
    noent_canonical="$(cd "$noent_dir" && pwd -P)/$noent_base"
    noent_sha="$(shasum -a 256 "$noent" | awk '{print $1}')"
    noent_cdhash="$(codesign -dvvv "$noent" 2>&1 | awk -F= '$1 == "CDHash" { print $2; exit }')"
    noent_uuid="$(otool -l "$noent" | awk '$1 == "cmd" && $2 == "LC_UUID" { seen=1; next } seen && $1 == "uuid" { print $2; exit }')"
    noent_entitlements="$(mktemp -t carrick-test-signed-noent-entitlements)"
    scratch+=("$noent_entitlements")
    codesign -d --entitlements :- "$noent" >"$noent_entitlements" 2>/dev/null || true
    noent_entitlement_digest="$(shasum -a 256 "$noent_entitlements" | awk '{print $1}')"
    if grep -q 'com.apple.security.hypervisor' "$noent_entitlements"; then
        echo "test-signed: negative identity unexpectedly carries entitlement" >&2
        failed=1
    elif ! otool -l "$noent" | grep -q '__dof_carrick'; then
        echo "test-signed: negative identity lacks __dof_carrick" >&2
        failed=1
    else
        for value in "$source_executable_id" "$noent_canonical" "$noent_sha" "$noent_cdhash" "$noent_uuid" "$noent_entitlement_digest"; do
            if [ -z "$value" ]; then
                echo "test-signed: missing negative-control identity field" >&2
                failed=1
            fi
        done
    fi
    if [ "$failed" -eq 0 ]; then
        noent_executable_id="$noent_sha:$noent_canonical"
        jq -nc \
            --arg schema "carrick.signed-embed-test.v1" \
            --arg source_executable_id "$source_executable_id" \
            --arg executable_id "$noent_executable_id" \
            --arg canonical_path "$noent_canonical" \
            --arg sha256 "$noent_sha" \
            --arg cdhash "$noent_cdhash" \
            --arg lc_uuid "$noent_uuid" \
            --arg entitlement_digest "$noent_entitlement_digest" \
            --arg test_name "$negative_test_name" \
            '{schema:$schema,record_type:"unentitled_negative_control",source_executable_id:$source_executable_id,executable_id:$executable_id,canonical_path:$canonical_path,sha256:$sha256,cdhash:$cdhash,lc_uuid:$lc_uuid,entitlement_digest:$entitlement_digest,entitlement_present:false,dof_carrick_present:true,test_name:$test_name,terminal_status:"passed"}' \
            >>"$receipt_tmp"
    fi
fi

if [ "$failed" -ne 0 ]; then
    echo "test-signed: FAILED ($pkg)" >&2
    exit 1
fi
receipt_ready=1

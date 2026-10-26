#!/usr/bin/env bash
# Shared metadata readers for the signed runner and its VM-free witnesses.
# Drain through EOF and wait for the producer's exit before returning. Under
# pipefail an early awk exit or grep -q can SIGPIPE codesign/otool and abort the
# gate before the next executable starts. Keep the first match without closing
# its pipe; retain producer failures even when valid metadata preceded them.
test_signed_cdhash() {
    codesign -dvvv "$1" 2>&1 | awk -F= '!found && $1 == "CDHash" { print $2; found=1 }'
}

test_signed_lc_uuid() {
    otool -l "$1" | awk '$1 == "cmd" && $2 == "LC_UUID" { seen=1; next } !found && seen && $1 == "uuid" { print $2; found=1 }'
}

test_signed_has_entitlement() {
    codesign -d --entitlements - "$1" 2>&1 | grep 'com.apple.security.hypervisor' >/dev/null
}

test_signed_has_dof() {
    otool -l "$1" | grep '__dof_carrick' >/dev/null
}

# Population is an admission snapshot, never a peak or timing measurement.
test_signed_receipt_header() {
    jq -nc \
        --arg schema "carrick.signed-embed-test.v1" \
        --arg source_head "$source_head" \
        --arg package "$pkg" \
        --arg run_id "$run_id" \
        --arg lease_mode "$CARRICK_HOST_LEASE_MODE" \
        --argjson concurrent_holders "$CARRICK_HOST_LEASE_CONCURRENT_HOLDERS" \
        --argjson arguments "$arguments_json" \
        --argjson requested_filter "$requested_filter_json" \
        --argjson enabled_features "$enabled_features_json" \
        --argjson test_target "$test_target_json" \
        ${contract_header_arg[@]+"${contract_header_arg[@]}"} \
        "{schema:\$schema,record_type:\"header\",holder_count_scope:\"at-admission\",lease_mode:\$lease_mode,concurrent_holders:\$concurrent_holders,source_head:\$source_head,package:\$package,arguments:\$arguments,requested_test_filter:\$requested_filter,carrick_run_id:\$run_id,test_target:\$test_target,enabled_features:\$enabled_features$contract_header_entry}"
}

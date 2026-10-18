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

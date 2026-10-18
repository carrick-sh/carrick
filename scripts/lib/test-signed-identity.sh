#!/usr/bin/env bash
# Shared metadata readers for the signed runner and its VM-free witnesses.
test_signed_cdhash() {
    codesign -dvvv "$1" 2>&1 | awk -F= '$1 == "CDHash" { print $2; exit }'
}

test_signed_lc_uuid() {
    otool -l "$1" | awk '$1 == "cmd" && $2 == "LC_UUID" { seen=1; next } seen && $1 == "uuid" { print $2; exit }'
}

test_signed_has_entitlement() {
    codesign -d --entitlements - "$1" 2>&1 | grep -q 'com.apple.security.hypervisor'
}

test_signed_has_dof() {
    otool -l "$1" | grep -q '__dof_carrick'
}

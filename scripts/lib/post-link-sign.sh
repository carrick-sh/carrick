#!/bin/sh
# Carrick's post-link contract for ANY executable that calls hv_vm_create:
# the shipped CLI (scripts/build-signed.sh) AND cargo test executables that
# boot guests in-process (scripts/test-signed.sh). SOURCED, not executed:
#
#     . scripts/lib/post-link-sign.sh
#     carrick_post_link_sign <built> <dest> <entitlements.plist>
#
# Steps, in order, exactly as build-signed.sh has always done them:
#   1. copy <built> to <dest>.raw.$$ (vtool needs distinct input/output paths);
#   2. stamp the build version. XNU's arm64 exception-return policy preserves
#      physical x18 for binaries linked against the pre-macOS-13 ABI. Tier D
#      proves that behavior again at runtime before using x18; if Apple
#      changes it, Carrick refuses dynamic code rather than trusting this
#      metadata. The private custom-x18 entitlement is intentionally NOT
#      used: ad-hoc signed binaries carrying it are killed by AMFI;
#   3. ad-hoc codesign with the hypervisor entitlement — a bare `cargo build`
#      strips it and every guest then dies HV_DENIED (0xfae94007);
#   4. rename(2) <dest>.tmp.$$ over <dest> ATOMICALLY, so a concurrent exec
#      sees the complete old or new binary, never a torn one.
# Temporaries are <dest>.raw.$$ and <dest>.tmp.$$; callers that want cleanup
# on failure trap on exactly those names. <built> may equal <dest>.
# POSIX sh only: it is sourced by a /bin/sh script and by bash 3.2.
carrick_post_link_sign() {
    _cpls_built="$1"
    _cpls_dest="$2"
    _cpls_entitlements="$3"
    _cpls_raw="$_cpls_dest.raw.$$"
    _cpls_tmp="$_cpls_dest.tmp.$$"
    cp -f "$_cpls_built" "$_cpls_raw"
    /usr/bin/vtool -set-build-version macos 11.0 12.0 -replace -output "$_cpls_tmp" "$_cpls_raw"
    codesign --force --sign - --entitlements "$_cpls_entitlements" "$_cpls_tmp"
    mv -f "$_cpls_tmp" "$_cpls_dest"
    rm -f "$_cpls_raw"
}

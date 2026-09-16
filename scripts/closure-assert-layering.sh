#!/usr/bin/env bash
# Layering gate: a lower crate must not have a higher crate in its normal
# dependency closure, and no VMM crate may depend on the kernel. Mirrors
# scripts/closure-assert-no-hvf.sh for the in-tree layering rather than the
# platform closure.
#
# Rules (crate : forbidden in its normal closure):
#   carrick-vfs            : carrick-kernel carrick-runtime carrick-vmm-* applevisor*
#   carrick-kernel         : carrick-runtime carrick-vmm-* applevisor*
#   carrick-kernel-example : carrick-runtime carrick-vmm-* applevisor*
#   carrick-vmm-*          : carrick-kernel
# A crate that does not exist yet is skipped (the gate lands before the
# crates it guards, so Phase 0 passes trivially).
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
# `jq` over the package list, not a comma-split/sed scrape: every crate here
# declares an explicit `[lib] name = "carrick_..."` (underscored), so the only
# hyphenated "name" fields that land on a comma boundary belong to `[[bin]]`
# targets. A text scrape would silently drop every lib-only crate (including
# carrick-vmm-hvf) from `members`, and this gate would report them "skipped"
# forever instead of actually walking their closure.
members="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name' | sort -u)"

check() {
  local crate="$1"; shift
  if ! grep -qx "$crate" <<<"$members"; then
    echo "layering: $crate not in workspace yet, skipped"
    return
  fi
  local tree
  tree="$(cargo tree -p "$crate" --edges normal --prefix none 2>/dev/null | awk '{print $1}' | sort -u)"
  for forbidden in "$@"; do
    if grep -Eq "^${forbidden}$" <<<"$tree"; then
      echo "layering FAIL: $crate depends on $forbidden"
      cargo tree -p "$crate" --edges normal --invert "$(grep -E "^${forbidden}$" <<<"$tree" | head -1)" 2>/dev/null | head -20 || true
      fail=1
    fi
  done
  echo "layering: $crate ok"
}

check carrick-vfs            'carrick-kernel' 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel         'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel-example 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
for vmm in $(grep -E '^carrick-vmm-' <<<"$members"); do check "$vmm" 'carrick-kernel'; done
exit $fail

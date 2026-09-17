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
# Product-closure feature rule (selection : forbidden feature):
#   the argument-less selection (root `default-members`, what the signed
#   product build in scripts/build-signed.sh resolves) : carrick-kernel and
#   carrick-hal `test-support`
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

# check() takes an optional cargo-tree target/feature override as its 2nd
# arg (a single space-separated string of flags, or '' for none), so a
# call-site can pin resolution to a specific platform instead of silently
# trusting whatever target the invoking host defaults to. See the
# `native_target_for` comment below for why the carrick-vmm-* loop needs
# this and the plain crate checks do not (yet).
check() {
  local crate="$1" target_args="$2"; shift 2
  if ! grep -qx "$crate" <<<"$members"; then
    echo "layering: $crate not in workspace yet, skipped"
    return
  fi
  local tree
  # shellcheck disable=SC2086 -- target_args is a fixed, script-controlled
  # flag string (e.g. "--target x86_64-unknown-linux-gnu --all-features"),
  # never user input; word-splitting it is intentional here.
  tree="$(cargo tree -p "$crate" --edges normal --prefix none $target_args 2>/dev/null | awk '{print $1}' | sort -u)"
  for forbidden in "$@"; do
    if grep -Eq "^${forbidden}$" <<<"$tree"; then
      echo "layering FAIL: $crate depends on $forbidden"
      # shellcheck disable=SC2086
      cargo tree -p "$crate" --edges normal --invert "$(grep -E "^${forbidden}$" <<<"$tree" | head -1)" $target_args 2>/dev/null | head -20 || true
      fail=1
    fi
  done
  echo "layering: $crate ok"
}

check carrick-vfs            '' 'carrick-kernel' 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel         '' 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel-example '' 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'

# `cargo tree` resolves each [target.'cfg(...)'.dependencies] block for
# exactly ONE target: the invoking host by default, or whatever `--target`
# names. Checking a carrick-vmm-* crate under the host's default target is
# therefore not the same rule as "walk this crate's normal dependency
# closure" the moment the crate's own manifest gates a dependency behind
# `cfg(target_os = ...)`, which is exactly how carrick-vmm-kvm/bhyve/nvmm are
# wired (kvm-ioctls/kvm-bindings/vmm-sys-util/carrick-host under
# `cfg(target_os = "linux")` for kvm; bhyve/nvmm gate their whole crate body
# the same way for freebsd/netbsd). Empirically verified on a macOS host:
# `cargo tree -p carrick-vmm-kvm --edges normal` omits kvm-ioctls,
# kvm-bindings and vmm-sys-util entirely; adding
# `--target x86_64-unknown-linux-gnu` is what surfaces them. A future
# `carrick-vmm-kvm -> carrick-kernel` edge added the same way (gated on
# `cfg(target_os = "linux")`) would be invisible to this gate run on macOS
# without this. `cargo tree --target <triple>` only resolves the dependency
# graph for that target; it needs no rustup toolchain component installed
# for that target to work (verified against an uninstalled triple), so this
# adds no new environment requirement. `--all-features` is added on top as a
# cheap hedge against the same crate later gating an edge behind a Cargo
# feature instead of (or in addition to) a target cfg; verified it changes
# nothing in today's tree for any of the four crates (identical output with
# and without it), so it costs nothing now and only helps later.
native_target_for() {
  case "$1" in
    carrick-vmm-hvf) echo aarch64-apple-darwin ;;
    carrick-vmm-kvm) echo x86_64-unknown-linux-gnu ;;
    carrick-vmm-bhyve) echo x86_64-unknown-freebsd ;;
    carrick-vmm-nvmm) echo x86_64-unknown-netbsd ;;
    *) echo '' ;;
  esac
}

for vmm in $(grep -E '^carrick-vmm-' <<<"$members"); do
  target="$(native_target_for "$vmm")"
  if [[ -z "$target" ]]; then
    # Fail closed: a 5th carrick-vmm-* crate with no entry above must not
    # print a plausible-looking "ok" that in fact checked nothing but the
    # invoking host's own default target.
    echo "layering FAIL: $vmm has no native target mapped in" \
      "scripts/closure-assert-layering.sh (native_target_for) -- add one" \
      "before trusting this gate for it"
    fail=1
    continue
  fi
  check "$vmm" "--target $target --all-features" 'carrick-kernel'
done

# Product-closure feature rule. The shipped binary is built by an
# argument-less `cargo build --release` (scripts/build-signed.sh), whose
# package selection is the root manifest's `default-members`. Under
# resolver 2 a NORMAL dependency's features unify across every package in
# one selection, so a non-product member that enables `test-support` on
# carrick-kernel / carrick-hal (carrick-kernel-example does, for the Null
# bridges its backend boots on) compiles that test-only surface --
# `SyscallDispatcher::new()`, the Null bridges, the CarrierProcess doubles
# -- into `carrick` the moment it shares the product's selection. That is
# exactly what a whole-workspace selection did while the root manifest had
# no `default-members` (found in review of the example crate, 2026-09-16).
# This rule resolves the SAME argument-less selection the product build
# uses (no -p, no --workspace) and fails closed: an unresolvable package or
# a closure that does not even contain the crate is a FAIL, never an "ok"
# that checked nothing. A `--workspace` selection (clippy, doc, test) does
# unify the feature, on purpose: that is what lints and renders the gated
# surface.
default_members="$(cargo metadata --no-deps --format-version 1 | jq -r '.workspace_default_members[]' | sed -E 's#^(path\+file://)?##; s#\#.*$##' | xargs -n1 basename | sort | paste -sd ' ' -)"
echo "layering: product selection (default-members) = ${default_members}"
product_feature_rule() {
  local crate="$1" tree
  if ! tree="$(cargo tree --edges normal,features --invert "$crate" --prefix none 2>&1)"; then
    echo "layering FAIL: cargo tree could not resolve $crate in the product selection:"
    head -5 <<<"$tree"
    fail=1
    return
  fi
  if ! grep -Eq "^${crate} v" <<<"$tree"; then
    echo "layering FAIL: $crate is not in the product selection's closure -- this rule would check nothing"
    fail=1
    return
  fi
  if grep -Eq "^${crate} feature \"test-support\"$" <<<"$tree"; then
    echo "layering FAIL: the product selection enables $crate feature \"test-support\" (test-only surface in the shipped binary); enabled through:"
    cargo tree --edges normal,features --invert "$crate" 2>/dev/null | grep -E -A3 "^.*${crate} feature \"test-support\"" | head -12 || true
    fail=1
    return
  fi
  echo "layering: product selection enables no $crate test-support ok"
}
product_feature_rule carrick-kernel
product_feature_rule carrick-hal
exit $fail

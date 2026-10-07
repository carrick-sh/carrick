#!/usr/bin/env bash
# L1 closure assertion: a Linux-target carrick-cli build must link NO macOS
# hypervisor. The build target alone selects the backend (carrick-runtime and
# carrick-cli scope every VMM/host crate to a `cfg(target_os)` dependency
# table), so the plain default-feature tree for a Linux target is exactly what
# `cargo build` on a Linux host links. Used by `just check-linux` and CI.
set -euo pipefail

target="aarch64-unknown-linux-gnu"

echo "cargo tree -p carrick-cli --target $target ..."
tree="$(cargo tree -p carrick-cli \
  --target "$target" --edges normal 2>&1)"

if echo "$tree" | grep -E -i 'carrick-vmm-hvf|applevisor'; then
  echo >&2
  echo "FAIL: Linux-target closure still contains carrick-vmm-hvf / applevisor." >&2
  echo "      A backend dependency is not scoped to its target_os table." >&2
  exit 1
fi

if ! echo "$tree" | grep -q 'carrick-vmm-kvm'; then
  echo >&2
  echo "FAIL: Linux-target closure does not contain carrick-vmm-kvm." >&2
  echo "      The target did not select the KVM backend." >&2
  exit 1
fi

echo "OK: Linux-target closure links carrick-vmm-kvm and no carrick-vmm-hvf / applevisor."

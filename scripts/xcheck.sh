#!/usr/bin/env bash
# Cross-platform compile-check harness for the structural-leverage refactors.
# Typechecks every backend's platform from a single macOS host (no run).
#
# NOTE: the full `carrick-cli` pulls `ring` (via reqwest/rustls for OCI image
# pulls), whose build.rs needs a C cross-toolchain and will NOT cross-compile.
# So cross-targets check the BACKEND CRATES (which don't depend up on
# carrick-runtime / carrick-image / ring), mirroring CI's `check-linux`; the
# full cli is checked only natively on macOS. Each target compiles exactly the
# host/arch lane that platform actually runs (KVM virtualizes the host ISA, so
# aarch64-linux runs the aarch64 lane, x86-linux the x86 lane).
set -uo pipefail
cd "$(dirname "$0")/.."

run() {
  local name="$1"; shift
  echo "::: $name :::"
  if "$@"; then echo "OK   $name"; else echo "FAIL $name"; return 1; fi
}

ok=0
check_macos()     { run macos     cargo check -p carrick-cli; }
check_linux_arm() { run linux-arm cargo check --target aarch64-unknown-linux-gnu -p carrick-hal -p carrick-vmm-kvm; }
check_linux_x86() { run linux-x86 cargo check --target x86_64-unknown-linux-gnu  -p carrick-vmm-kvm -p carrick-x86; }
check_freebsd()   { run freebsd   cargo check --target x86_64-unknown-freebsd    -p carrick-vmm-bhyve -p carrick-x86; }
check_netbsd()    { run netbsd    cargo check --target x86_64-unknown-netbsd      -p carrick-vmm-nvmm -p carrick-x86; }

case "${1:-all}" in
  macos)     check_macos ;;
  linux-arm) check_linux_arm ;;
  linux-x86) check_linux_x86 ;;
  freebsd)   check_freebsd ;;
  netbsd)    check_netbsd ;;
  all)
    check_macos     || ok=1
    check_linux_arm || ok=1
    check_linux_x86 || ok=1
    check_freebsd   || ok=1
    check_netbsd    || ok=1
    exit $ok ;;
  *) echo "unknown: $1"; exit 2 ;;
esac

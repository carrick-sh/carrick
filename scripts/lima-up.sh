#!/usr/bin/env bash
# One-time setup of the local L2 lane: a lima `vz` (Virtualization.framework)
# Ubuntu VM with nestedVirtualization, so the guest gets real /dev/kvm.
#
# Apple Silicon M3+ / macOS 15+ ONLY — nested virt is a Virtualization.framework
# feature; qemu's HVF backend cannot provide it ("HVF does not support providing
# Virtualization extensions to the guest CPU"). The repo is mounted into the
# guest at the same absolute path. Override the instance name with $LIMA_INSTANCE.
set -euo pipefail

vm="${LIMA_INSTANCE:-carrick}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v limactl >/dev/null || {
  echo "lima is not installed. Install it with: brew install lima" >&2
  exit 2
}

if limactl list -q 2>/dev/null | grep -qx "$vm"; then
  echo "lima VM '$vm' already exists; ensuring it is running..."
  limactl start "$vm" --tty=false >/dev/null 2>&1 || true
else
  echo "creating lima VM '$vm' (vz + nestedVirtualization, Ubuntu 24.04 aarch64)..."
  limactl start "template://ubuntu-24.04" --name "$vm" \
    --vm-type vz --set '.nestedVirtualization = true' \
    --cpus 6 --memory 8 --disk 30 --mount "$repo" --tty=false
fi

echo "provisioning kvm group + build toolchain in '$vm'..."
limactl shell "$vm" -- bash -lc '
  set -e
  sudo usermod -aG kvm "$(id -un)" || true
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential curl >/dev/null
  if [ ! -x "$HOME/.cargo/bin/rustc" ]; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable >/dev/null
  fi
  echo "guest ready: $("$HOME/.cargo/bin/rustc" --version)"
  ls -l /dev/kvm
'
echo "OK: lima L2 lane ready. Run: just kvm-smoke-lima"

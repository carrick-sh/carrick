#!/usr/bin/env bash
# Provision a carrick x86 agent-worker VM (Debian 13 cloud image). Run as root
# inside the VM. Idempotent: re-running converges the same toolchain.
#
# Pinned to the toolchain the willow x86-w1/w2 workers run, so a worker built
# here and one built there give the same answers. agy is not downloadable; copy
# its binary from an existing worker into ~/.local/bin/agy. Logins (codex, gh,
# agy) stay per-host and are done by the owner; never copy auth files between
# hosts (a shared refresh token rotates and kills the other copies).
#
# Host side, as used for ctb-w1..w4 on the Contabo Proxmox host (issue #283):
#   - NAT bridge: vmbr1 10.77.0.1/24 with a MASQUERADE rule out of vmbr0;
#     workers are reached only through the host (ssh ProxyJump).
#   - Template 9000 from debian-13-genericcloud-amd64.qcow2 (SHA512 checked):
#     cpu host, virtio-scsi-single, serial console, qemu agent, cloud-init user
#     `carrick` with the owner's keys. Run this script, then
#     `cloud-init clean --logs --machine-id`, delete the SSH host keys, power
#     off and `qm template 9000`.
#   - Workers: `qm clone 9000 <id> --full 1`, 10 cores, 24 GiB with no
#     balloon, `qm disk resize <id> scsi0 200G`, a static ipconfig0 on vmbr1.
set -euo pipefail

U=carrick
NODE_VER=v22.20.0
BUN_VER=1.4.2
CODEX_VER=0.162.1
GH_VER=2.94.0
ACTIONLINT_VER=1.7.12
CARGO_DENY_VER=0.20.2
SEMGREP_VER=1.179.0
RUST_TOOLCHAINS="1.96.0 1.97.0"
RUST_TARGETS="aarch64-unknown-linux-gnu aarch64-unknown-linux-musl aarch64-unknown-none aarch64-unknown-none-softfloat aarch64-apple-darwin x86_64-unknown-linux-musl x86_64-unknown-none x86_64-unknown-freebsd x86_64-unknown-netbsd"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q full-upgrade
apt-get -y -q install \
  build-essential clang lld pkg-config git jq just lsof rsync socat tcpdump screen tmux \
  gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
  curl ca-certificates unzip xz-utils zstd python3 python3-venv \
  qemu-guest-agent unattended-upgrades psmisc pciutils traceroute ethtool
systemctl enable --now qemu-guest-agent

# Willow template rules: overcommit for big link steps, umask 022, home 755.
echo 'vm.overcommit_memory = 1' > /etc/sysctl.d/90-carrick.conf
sysctl -q --system
chmod 755 /home/$U
usermod -aG kvm $U  # KVM carrier lanes open /dev/kvm as the worker user

sudo -u $U -H bash -euo pipefail <<EOS
cd ~
grep -q 'carrick worker PATH' ~/.profile || cat >> ~/.profile <<'EOP'
# carrick worker PATH
export PATH=\$HOME/.local/node/bin:\$HOME/.bun/bin:\$HOME/.local/bin:\$HOME/.cargo/bin:\$PATH
umask 022
EOP
grep -q '^umask 022' ~/.bashrc || echo 'umask 022' >> ~/.bashrc
export PATH=\$HOME/.local/node/bin:\$HOME/.bun/bin:\$HOME/.local/bin:\$HOME/.cargo/bin:\$PATH
mkdir -p ~/.local/bin ~/dev
T=\$(mktemp -d)

# Rust
[ -x ~/.cargo/bin/rustup ] || curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
for tc in $RUST_TOOLCHAINS; do
  rustup toolchain install \$tc --profile minimal -c rustfmt -c clippy -c rust-src
  rustup target add --toolchain \$tc $RUST_TARGETS
done
rustup default 1.96.0
cargo deny --version 2>/dev/null | grep -q $CARGO_DENY_VER || cargo install --locked cargo-deny@$CARGO_DENY_VER

# node
if ! ~/.local/node/bin/node --version 2>/dev/null | grep -qx $NODE_VER; then
  curl -fsSL https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.xz -o \$T/node.tar.xz
  curl -fsSL https://nodejs.org/dist/$NODE_VER/SHASUMS256.txt | grep " node-$NODE_VER-linux-x64.tar.xz\\\$" | sed "s#node-.*#\$T/node.tar.xz#" | sha256sum -c -
  rm -rf ~/.local/node && mkdir -p ~/.local/node && tar -xJf \$T/node.tar.xz -C ~/.local/node --strip-components=1
fi

# bun + codex
[ -x ~/.bun/bin/bun ] || curl -fsSL https://bun.sh/install | bash -s "bun-v$BUN_VER"
~/.bun/bin/bun add -g @openai/codex@$CODEX_VER

# gh
curl -fsSL https://github.com/cli/cli/releases/download/v$GH_VER/gh_${GH_VER}_linux_amd64.tar.gz -o \$T/gh.tgz
curl -fsSL https://github.com/cli/cli/releases/download/v$GH_VER/gh_${GH_VER}_checksums.txt | grep " gh_${GH_VER}_linux_amd64.tar.gz\\\$" | sed "s#gh_.*#\$T/gh.tgz#" | sha256sum -c -
tar -xzf \$T/gh.tgz -C \$T && install -m755 \$T/gh_${GH_VER}_linux_amd64/bin/gh ~/.local/bin/gh

# actionlint
curl -fsSL https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VER/actionlint_${ACTIONLINT_VER}_linux_amd64.tar.gz -o \$T/al.tgz
curl -fsSL https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VER/actionlint_${ACTIONLINT_VER}_checksums.txt | grep " actionlint_${ACTIONLINT_VER}_linux_amd64.tar.gz\\\$" | sed "s#actionlint_.*#\$T/al.tgz#" | sha256sum -c -
tar -xzf \$T/al.tgz -C \$T actionlint && install -m755 \$T/actionlint ~/.local/bin/actionlint

# uv + semgrep
[ -x ~/.local/bin/uv ] || curl -fsSL https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh
~/.local/bin/uv tool install --force semgrep==$SEMGREP_VER

rm -rf \$T
EOS
echo PROVISION-DONE

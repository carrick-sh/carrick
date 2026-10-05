#!/usr/bin/env bash
# Root on Willow only. Builds VM 300; never allocates or operates a clone.
# Dependencies are existing PVE tools; no host package/service/network changes.
set -euo pipefail
umask 077
[[ ${EUID} == 0 && $(hostname -s) == willow ]] || { echo 'Run as root on Willow' >&2; exit 1; }
[[ $# == 3 ]] || { echo 'Usage: build-template-debian.sh INPUT_DIR SCRIPT_COMMIT X86_LINUX_XTASK' >&2; exit 1; }
inputs=$(realpath "$1")
commit=$2
xtask=$(realpath "$3")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ -f $inputs/rust-toolchain.toml && -f $inputs/Cargo.lock ]] || exit 1
for tool in qm pvesh curl jq genisoimage sha512sum; do command -v "$tool" >/dev/null; done
pve_call() {
  # The credential exists only in this on-host pipe, never argv or output.
  jq -r '"header = \"Authorization: PVEAPIToken=" + .["full-tokenid"] + "=" + .value + "\""' /root/carrick-ci-token.json |
    curl --fail --silent --show-error --max-time 40 --config - \
      --resolve willow.atxconsulting.com:8006:127.0.0.1 --request "$1" \
      "https://willow.atxconsulting.com:8006/api2/json$2"
}
! qm status 300 >/dev/null 2>&1 || { echo 'VM 300 already exists; refusing replacement' >&2; exit 1; }
pvesh get /pools/carrick-ci --output-format json | jq -e '.poolid == "carrick-ci"' >/dev/null
[[ $(cat /sys/module/kvm_amd/parameters/nested) == 1 ]] || { echo 'Nested SVM is disabled; director action required' >&2; exit 1; }
work=/root/carrick-ci/template-300
mkdir -p "$work/seed"
cd "$work"
image=debian-13-generic-amd64-20261001-2618.qcow2
image_url=https://cloud.debian.org/images/cloud/trixie/20261001-2618/$image
image_sha512=6f0f93335bdef4ccf523c4317cc663ea52ca23b862667785f3d6d186ab4674a937385ccff0c55996b4b2e4c19e440cdf211e2a75ffa2f6548037ab43950c841d
runner_version=2.337.0
runner_sha256=70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613
sccache_version=0.18.0
sccache_sha256=45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89
rustup_sha256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
curl -fSL --retry 2 "$image_url" -o "$image"
printf '%s  %s\n' "$image_sha512" "$image" | sha512sum -c -
curl -fSL "https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-x64-${runner_version}.tar.gz" -o seed/runner.tar.gz
printf '%s  %s\n' "$runner_sha256" seed/runner.tar.gz | sha256sum -c -
curl -fSL "https://github.com/mozilla/sccache/releases/download/v${sccache_version}/sccache-v${sccache_version}-x86_64-unknown-linux-musl.tar.gz" -o seed/sccache.tar.gz
printf '%s  %s\n' "$sccache_sha256" seed/sccache.tar.gz | sha256sum -c -
curl -fSL https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init -o seed/rustup-init
printf '%s  %s\n' "$rustup_sha256" seed/rustup-init | sha256sum -c -
cp "$xtask" seed/carrick-xtask
cp "$inputs/rust-toolchain.toml" "$inputs/Cargo.lock" seed/
cp "$inputs/scripts/ci/runner-once.sh" seed/
cat > seed/meta-data <<'DATA'
instance-id: carrick-template-300
local-hostname: carrick-template-300
DATA
cat > seed/user-data <<'DATA'
#cloud-config
users:
  - name: runner
    shell: /bin/bash
    groups: [kvm]
    lock_passwd: true
    sudo: false
ssh_pwauth: false
disable_root: true
ssh_deletekeys: true
ssh_genkeytypes: [ed25519, rsa]
package_update: true
packages: [build-essential, clang, git, curl, jq, just, qemu-guest-agent, openssh-server, nftables, libicu76, libssl3t64, libkrb5-3, zlib1g]
runcmd:
  - [bash, -c, 'mkdir -p /mnt/carrick-seed; mount -o ro /dev/disk/by-label/cidata /mnt/carrick-seed; bash /mnt/carrick-seed/provision.sh']
DATA
cat > seed/provision.sh <<'PROVISION'
#!/bin/bash
set -euo pipefail
cd /mnt/carrick-seed
install -m 755 carrick-xtask /usr/local/bin/carrick-xtask
install -m 755 runner-once.sh /usr/local/bin/carrick-ci-run-once
install -d -o runner -g runner /home/runner/actions-runner
# Downloaded official distribution only: config.sh is never invoked here.
tar xf runner.tar.gz -C /home/runner/actions-runner
mkdir -p /tmp/sccache-extract
tar xf sccache.tar.gz -C /tmp/sccache-extract
install -m 755 /tmp/sccache-extract/sccache-*/sccache /usr/local/bin/sccache
install -m 755 rustup-init /tmp/rustup-init
cp rust-toolchain.toml /home/runner/rust-toolchain.toml
chown -R runner:runner /home/runner
channel=$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)
runuser -u runner -- /tmp/rustup-init -y --profile minimal --default-toolchain "$channel"
runuser -u runner -- bash -c 'cd /home/runner; . "$HOME/.cargo/env"; rustup show; rustup target add x86_64-unknown-none; rustc --version; cargo --version'
systemctl enable --now qemu-guest-agent
# Guest-only firewall: permit replies to the controller's SSH connection and
# DHCP/DNS, but deny job-initiated connections to management/private networks.
cat > /etc/nftables.conf <<'FIREWALL'
#!/usr/sbin/nft -f
flush ruleset
table inet ci_boundary {
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    ct state established,related accept
    udp dport { 53, 67 } accept
    tcp dport 53 accept
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } reject
    ip6 daddr { fc00::/7, fe80::/10 } reject
  }
}
FIREWALL
systemctl enable --now nftables
# Proxmox cloud-init can otherwise grant its selected user passwordless sudo.
# This unit is started by the controller after cloud-final, before JIT.
# Enabling it under multi-user.target would cycle with cloud-final's After.
# No service is installed on Willow.
cat > /etc/systemd/system/carrick-ci-ready.service <<'READY'
[Unit]
Description=Remove cloud-init administrative authority from CI runner
After=cloud-final.service
Requires=cloud-final.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/carrick-ci-ready
RemainAfterExit=yes
READY
cat > /usr/local/bin/carrick-ci-ready <<'GUEST_READY'
#!/bin/bash
set -euo pipefail
rm -f /etc/sudoers.d/90-cloud-init-users
install -d -m 755 /run/carrick-ci
install -m 660 -o root -g runner /dev/null /run/carrick-ci/admission.lock
GUEST_READY
chmod 755 /usr/local/bin/carrick-ci-ready
cat > /usr/local/bin/carrick-ci-admit-job <<'ADMIT'
#!/bin/sh
exec /usr/local/bin/carrick-xtask ci-scaler admit-job
ADMIT
chmod 755 /usr/local/bin/carrick-ci-admit-job
systemctl daemon-reload
runuser -u runner -- /usr/local/bin/carrick-xtask ci-scaler verify-kvm
mkdir -p /var/lib/carrick-ci
jq -n --arg kernel "$(uname -r)" --arg rust "$(runuser -u runner -- /home/runner/.cargo/bin/rustc --version)" \
  '{kernel:$kernel,rust:$rust,kvm_api:12,user:"runner",svm:true,runner_registered:false}' > /var/lib/carrick-ci/qualification.json
dpkg-query -W -f='${Package}=${Version}\n' > /var/lib/carrick-ci/packages.txt
rm -rf /tmp/rustup-init /tmp/sccache-extract
PROVISION
genisoimage -quiet -output /var/lib/vz/template/iso/carrick-template-300-seed.iso -volid cidata -joliet -rock seed
# Root qm operations below apply ONLY to the approved template build.
qm create 300 --name carrick-debian13-kvm --pool carrick-ci --cores 2 --memory 4096 --balloon 0 --cpulimit 2 --cpu host \
  --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci --serial0 socket --vga serial0 --agent enabled=1
qm importdisk 300 "$image" local-lvm
qm set 300 --scsi0 local-lvm:vm-300-disk-0 --boot order=scsi0 --ide2 local:iso/carrick-template-300-seed.iso,media=cdrom
qm disk resize 300 scsi0 64G
# Measure current CPU utilization AND load average, conservatively reserve two threads.
read -ra before < /proc/stat
sleep 5
read -ra after < /proc/stat
busy=$(awk -v a="${before[*]}" -v b="${after[*]}" -v n="$(nproc)" -v load="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN {
  split(a,x); split(b,y); t=0; for(i=2;i<=9;i++) t+=y[i]-x[i];
  idle=y[5]-x[5]+y[6]-x[6]; u=(t>0?1-idle/t:1); if(load/n>u) u=load/n;
  printf "%.6f",u+2/n;
}')
awk -v projected="$busy" 'BEGIN { print "template projected CPU=" projected; exit !(projected<0.85) }'
awk '/MemAvailable:/ {exit !($2 >= 10485760)}' /proc/meminfo
pve_call POST /nodes/willow/qemu/300/status/start
# Provisioning is bounded; the clone readiness deadline is separately five minutes.
qualified=false
for ((attempt=0; attempt<180; attempt++)); do
  if qm guest exec 300 -- /bin/test -s /var/lib/carrick-ci/qualification.json 2>/dev/null | jq -e '.exitcode == 0' >/dev/null; then qualified=true; break; fi
  sleep 10
done
[[ $qualified == true ]] || { echo 'Template provisioning failed; preserve VM 300 for diagnosis' >&2; exit 1; }
qm guest exec 300 -- /bin/cat /var/lib/carrick-ci/qualification.json | jq -r '."out-data"' > qualification.json
qm guest exec 300 -- /bin/cat /var/lib/carrick-ci/packages.txt | jq -r '."out-data"' > packages.txt
# Clean clone identities/SSH credentials and shut down from inside the template.
qm guest exec 300 -- /bin/bash -c 'cloud-init clean --logs --machine-id; rm -f /etc/ssh/ssh_host_* /home/runner/.ssh/authorized_keys; rm -rf /var/lib/cloud/instances /home/runner/.cache; sync'
pve_call POST /nodes/willow/qemu/300/status/stop
for ((attempt=0; attempt<60; attempt++)); do
  [[ $(qm status 300) == 'status: stopped' ]] && break
  sleep 2
done
[[ $(qm status 300) == 'status: stopped' ]] || { echo 'Template did not stop' >&2; exit 1; }
qm set 300 --ide2 local-lvm:cloudinit --ciuser runner --ipconfig0 ip=dhcp
qm template 300
jq -n --arg commit "$commit" --arg script_hash "$(sha256sum "$inputs/scripts/ci/build-template-debian.sh" | cut -d' ' -f1)" \
  --arg image_url "$image_url" --arg image_sha512 "$image_sha512" --arg runner_version "$runner_version" --arg runner_sha256 "$runner_sha256" \
  --arg sccache_sha256 "$sccache_sha256" --arg rustup_sha256 "$rustup_sha256" --arg toolchain_hash "$(sha256sum seed/rust-toolchain.toml | cut -d' ' -f1)" \
  --arg lock_hash "$(sha256sum seed/Cargo.lock | cut -d' ' -f1)" --arg xtask_hash "$(sha256sum seed/carrick-xtask | cut -d' ' -f1)" \
  --arg packages_hash "$(sha256sum packages.txt | cut -d' ' -f1)" --slurpfile qualification qualification.json \
  --arg bootstrap_hash "$(sha256sum seed/runner-once.sh | cut -d' ' -f1)" \
  '{vmid:300,pool:"carrick-ci",cpu:"host",vcpus:2,memory_mib:4096,disk_gib:64,storage:"local-lvm",bridge:"vmbr0",script_commit:$commit,
    script_sha256:$script_hash,image_url:$image_url,image_sha512:$image_sha512,runner_version:$runner_version,runner_sha256:$runner_sha256,
    sccache_sha256:$sccache_sha256,rustup_sha256:$rustup_sha256,toolchain_sha256:$toolchain_hash,cargo_lock_sha256:$lock_hash,
    xtask_sha256:$xtask_hash,bootstrap_sha256:$bootstrap_hash,packages_sha256:$packages_hash,qualification:$qualification[0]}' > manifest.json
qm config 300
cat manifest.json

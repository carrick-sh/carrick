#!/usr/bin/env bash
# Root on a known KVM clone site (Willow or the Contabo host, issue #287)
# only. Builds approved template 300 or 9000; never allocates or operates a clone. The site's node,
# storage, bridge and template size come from `carrick-xtask ci-scaler site`,
# the same typed table the controller authenticates the template against.
# Dependencies are existing PVE tools; no host package/service/network changes.
set -euo pipefail
umask 077
[[ ${EUID} == 0 ]] || { echo 'Run as root on a KVM clone site' >&2; exit 1; }
[[ $# == 3 || $# == 4 ]] || { echo 'Usage: build-template-debian.sh INPUT_DIR SCRIPT_COMMIT X86_LINUX_XTASK [kvm|agent]' >&2; exit 1; }
profile=${4:-kvm}
[[ $profile == kvm || $profile == agent ]] || { echo "bad template profile" >&2; exit 1; }
inputs=$(realpath "$1")
commit=$2
xtask=$(realpath "$3")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || exit 1
[[ -f $inputs/rust-toolchain.toml && -f $inputs/Cargo.lock ]] || exit 1
for tool in qm pvesh curl jq genisoimage sha512sum objdump; do command -v "$tool" >/dev/null; done
# The guest is Debian 13 (glibc 2.41). A static (musl) xtask or a glibc build
# needing at most GLIBC_2.41 runs there; provisioning also executes it
# (verify-kvm). Refuse an incompatible binary before creating any VM.
file_type=$(od -An -tx1 -N20 "$xtask" | tr -d ' \n')
[[ ${file_type:0:8} == 7f454c46 && ${file_type:36:4} == 3e00 ]] || { echo 'xtask is not an x86-64 ELF' >&2; exit 1; }
glibc_max=$(objdump -T "$xtask" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1 || true)
if [[ -n $glibc_max ]] && [[ $(printf '%s\n2.41\n' "$glibc_max" | sort -V | tail -1) != 2.41 ]]; then
  echo "xtask needs GLIBC_$glibc_max; Debian 13 guests provide 2.41" >&2; exit 1
fi
# Unknown hosts fail inside xtask; every value is re-validated here.
declare -A site=()
while IFS='=' read -r name value; do
  [[ $name =~ ^SITE_[A-Z_]+$ && $value =~ ^[A-Za-z0-9._=/,-]+$ ]] || { echo "bad site line: $name" >&2; exit 1; }
  site[$name]=$value
done < <("$xtask" ci-scaler site --lane "$profile")
for name in SITE_NODE SITE_API_HOST SITE_STORAGE SITE_DISK_FORMAT SITE_BRIDGE SITE_CORES SITE_MEMORY_MIB SITE_DISK_GIB SITE_TEMPLATE_IPCONFIG SITE_NAMESERVER SITE_VM_FIREWALL SITE_API_CA SITE_ALLOW_KSM SITE_TEMPLATE_VMID; do
  [[ -n ${site[$name]:-} ]] || { echo "site lacks $name" >&2; exit 1; }
done
[[ ${site[SITE_NODE]} == $(hostname -s) ]] || { echo 'site node is not this host' >&2; exit 1; }
template=${site[SITE_TEMPLATE_VMID]}
case $profile:$template in kvm:300|agent:9000) ;; *) echo "bad profile template" >&2; exit 1 ;; esac
node=${site[SITE_NODE]} api_host=${site[SITE_API_HOST]} storage=${site[SITE_STORAGE]}
disk_format=${site[SITE_DISK_FORMAT]} bridge=${site[SITE_BRIDGE]}
cores=${site[SITE_CORES]} memory_mib=${site[SITE_MEMORY_MIB]} disk_gib=${site[SITE_DISK_GIB]}
ipconfig=${site[SITE_TEMPLATE_IPCONFIG]} nameserver=${site[SITE_NAMESERVER]} vm_firewall=${site[SITE_VM_FIREWALL]}
[[ $vm_firewall == 0 || $vm_firewall == 1 ]] || { echo 'bad site firewall flag' >&2; exit 1; }
# A PVE-cluster-CA-signed API certificate needs that CA; ACME uses system trust.
api_ca_args=()
if [[ ${site[SITE_API_CA]} != system ]]; then
  [[ ${site[SITE_API_CA]} == /* && -f ${site[SITE_API_CA]} ]] || { echo 'site API CA missing' >&2; exit 1; }
  api_ca_args=(--cacert "${site[SITE_API_CA]}")
fi
pve_call() {
  # The credential exists only in this on-host pipe, never argv or output.
  jq -r '"header = \"Authorization: PVEAPIToken=" + .["full-tokenid"] + "=" + .value + "\""' /root/carrick-ci-token.json |
    curl --disable --fail --silent --show-error --max-time 40 --config - \
      --resolve "$api_host:8006:127.0.0.1" ${api_ca_args[@]+"${api_ca_args[@]}"} --request "$1" \
      "https://$api_host:8006/api2/json$2"
}
! qm status "$template" >/dev/null 2>&1 || { echo "VM $template already exists; refusing replacement" >&2; exit 1; }
pvesh get /pools/carrick-ci --output-format json | jq -e '.poolid == "carrick-ci"' >/dev/null
[[ $(cat /sys/module/kvm_amd/parameters/nested) == 1 ]] || { echo 'Nested SVM is disabled; director action required' >&2; exit 1; }
work=/root/carrick-ci/template-${template}
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
gh_version=2.102.0
gh_sha256=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
curl -fSL --retry 2 "$image_url" -o "$image"
printf '%s  %s\n' "$image_sha512" "$image" | sha512sum -c -
curl -fSL "https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-x64-${runner_version}.tar.gz" -o seed/runner.tar.gz
printf '%s  %s\n' "$runner_sha256" seed/runner.tar.gz | sha256sum -c -
curl -fSL "https://github.com/mozilla/sccache/releases/download/v${sccache_version}/sccache-v${sccache_version}-x86_64-unknown-linux-musl.tar.gz" -o seed/sccache.tar.gz
printf '%s  %s\n' "$sccache_sha256" seed/sccache.tar.gz | sha256sum -c -
curl -fSL https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init -o seed/rustup-init
printf '%s  %s\n' "$rustup_sha256" seed/rustup-init | sha256sum -c -
curl -fSL "https://github.com/cli/cli/releases/download/v${gh_version}/gh_${gh_version}_linux_amd64.tar.gz" -o seed/gh.tar.gz
printf '%s  %s\n' "$gh_sha256" seed/gh.tar.gz | sha256sum -c -
cp "$xtask" seed/carrick-xtask
cp "$inputs/rust-toolchain.toml" "$inputs/Cargo.lock" seed/
cp "$inputs/scripts/ci/runner-once.sh" seed/
cp "$inputs/scripts/ci/admit-job.sh" seed/
cp "$inputs/scripts/ci/inputs/codex-sdk-requirements.txt" seed/
printf '%s\n' "$profile" > seed/profile
printf '%s\n' "$gh_version" > seed/gh-version
cat > seed/meta-data <<DATA
instance-id: carrick-template-${template}
local-hostname: carrick-template-${template}
DATA
# A bridge without DHCP gets the template's static address in the seed
# (NoCloud network-config v2); a DHCP site keeps the image default.
if [[ $ipconfig != ip=dhcp ]]; then
  # Validate the resolver first: each =~ replaces BASH_REMATCH.
  [[ $nameserver =~ ^[0-9.]+$ ]] || { echo 'bad static site resolver' >&2; exit 1; }
  [[ $ipconfig =~ ^ip=([0-9.]+/24),gw=([0-9.]+)$ ]] || { echo 'bad static site network' >&2; exit 1; }
  address=${BASH_REMATCH[1]} route=${BASH_REMATCH[2]}
  cat > seed/network-config <<NET
version: 2
ethernets:
  primary:
    match: {name: "e*"}
    addresses: [$address]
    routes: [{to: default, via: $route}]
    nameservers: {addresses: [$nameserver]}
NET
fi
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
packages: [sudo, build-essential, clang, git, curl, jq, just, python3-venv, util-linux, procps, qemu-guest-agent, openssh-server, nftables, libicu76, libssl3t64, libkrb5-3, zlib1g]
runcmd:
  - [bash, -c, 'mkdir -p /mnt/carrick-seed; mount -o ro /dev/disk/by-label/cidata /mnt/carrick-seed; bash /mnt/carrick-seed/provision.sh']
DATA
cat > seed/provision.sh <<'PROVISION'
#!/bin/bash
set -euo pipefail
cd /mnt/carrick-seed
if [[ $(cat profile) == agent ]]; then
  /usr/sbin/useradd --system --user-group --no-create-home --shell /usr/sbin/nologin carrick-dispatch-agent
  /usr/sbin/usermod -aG carrick-dispatch-agent runner
  printf '%s\n' 'runner ALL=(carrick-dispatch-agent) NOPASSWD: ALL' > /etc/sudoers.d/carrick-dispatch-agent
  chmod 0440 /etc/sudoers.d/carrick-dispatch-agent
  /usr/sbin/useradd --system --user-group --no-create-home --shell /usr/sbin/nologin carrick-dispatch-loop
  /usr/sbin/usermod -aG carrick-dispatch-loop runner
  printf '%s\n' 'runner ALL=(carrick-dispatch-loop) NOPASSWD: ALL' > /etc/sudoers.d/carrick-dispatch-loop
  chmod 0440 /etc/sudoers.d/carrick-dispatch-loop
  /usr/sbin/visudo -c
  # The codex dispatch tier's pinned SDK, built once from hash-locked wheels.
  # Root-owned and read-only for the agent; the driver points the launcher
  # at it so no job installs packages at run time (#773).
  python3 -m venv /opt/carrick-agent/codex-sdk
  /opt/carrick-agent/codex-sdk/bin/pip install --quiet --disable-pip-version-check \
    --no-deps --only-binary=:all: --require-hashes -r codex-sdk-requirements.txt
  sed -n 's/^openai-codex==\([^ ]*\) .*/\1/p' codex-sdk-requirements.txt > /opt/carrick-agent/codex-sdk/.agy-director-sdk
  chmod -R a+rX,go-w /opt/carrick-agent
fi
install -m 755 carrick-xtask /usr/local/bin/carrick-xtask
install -m 755 runner-once.sh /usr/local/bin/carrick-ci-run-once
install -d -o runner -g runner /home/runner/actions-runner
# Downloaded official distribution only: config.sh is never invoked here.
tar xf runner.tar.gz -C /home/runner/actions-runner
mkdir -p /tmp/sccache-extract
tar xf sccache.tar.gz -C /tmp/sccache-extract
install -m 755 /tmp/sccache-extract/sccache-*/sccache /usr/local/bin/sccache
mkdir -p /tmp/gh-extract
tar xf gh.tar.gz -C /tmp/gh-extract
install -m 755 /tmp/gh-extract/gh_*/bin/gh /usr/local/bin/gh
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
# No service is installed on the PVE host by this builder.
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
install -m 755 admit-job.sh /usr/local/bin/carrick-ci-admit-job.sh
systemctl daemon-reload
runuser -u runner -- /usr/local/bin/carrick-xtask ci-scaler verify-kvm
gh_version=$(cat gh-version)
gh_first_line=$(gh --version </dev/null | head -n1)
if ! [[ $gh_first_line =~ ^gh[[:space:]]+version[[:space:]]+([0-9.]+) && ${BASH_REMATCH[1]} == "$gh_version" ]]; then
  echo "unexpected gh version: $gh_first_line (expected $gh_version)" >&2
  exit 1
fi
if ! gh api --help </dev/null | grep -q -- '--slurp'; then
  echo "gh api missing --slurp" >&2
  exit 1
fi
mkdir -p /var/lib/carrick-ci
jq -n --arg kernel "$(uname -r)" --arg rust "$(runuser -u runner -- /home/runner/.cargo/bin/rustc --version)" \
  --arg gh "$gh_version" \
  '{kernel:$kernel,rust:$rust,gh:$gh,kvm_api:12,user:"runner",svm:true,runner_registered:false}' > /var/lib/carrick-ci/qualification.json
dpkg-query -W -f='${Package}=${Version}\n' > /var/lib/carrick-ci/packages.txt
rm -rf /tmp/rustup-init /tmp/sccache-extract /tmp/gh-extract
PROVISION
genisoimage -quiet -output /var/lib/vz/template/iso/carrick-template-${template}-seed.iso -volid cidata -joliet -rock seed
# Root qm operations below apply ONLY to the approved template build.
# A shared private bridge gets the PVE VM firewall on net0; PVE copies
# the template firewall to every clone, so a job that undoes the guest firewall still
# cannot reach other VMs, the host or any private range (public IPv4 only).
net0="virtio,bridge=$bridge"
create_extra=()
template_pool=
if [[ $profile == kvm ]]; then
  template_pool=carrick-ci
  create_extra+=(--pool "$template_pool")
fi
# Sites whose clones share the host with credential-holding VMs keep CI out
# of KSM page merging (a cross-VM timing side channel); linked clones
# inherit the setting and the controller checks it before each boot.
case ${site[SITE_ALLOW_KSM]} in
  1) ;;
  0) create_extra+=(--allow-ksm 0) ;;
  *) echo 'bad site KSM flag' >&2; exit 1 ;;
esac
if [[ $vm_firewall == 1 ]]; then
  # The datacenter firewall must be on for a VM firewall to apply.
  awk '/^\[/{o=($0=="[OPTIONS]")} o && $1=="enable:" && $2=="1"{f=1} END{exit !f}' /etc/pve/firewall/cluster.fw ||
    { echo 'datacenter firewall is not enabled' >&2; exit 1; }
  [[ ! -e /etc/pve/firewall/${template}.fw ]] || { echo "stale $template.fw; owner inspection needed" >&2; exit 1; }
  # The rule set comes from the site table; the controller verifies the same
  # rules on the template and on every clone before it boots.
  "$xtask" ci-scaler vm-firewall --lane "$profile" > /etc/pve/firewall/${template}.fw.new
  mv /etc/pve/firewall/${template}.fw.new /etc/pve/firewall/${template}.fw
  net0="$net0,firewall=1"
  # ipfilter admits only the addresses in ipconfig0, so the template needs
  # its static address there while it provisions from the seed ISO.
  create_extra+=(--ipconfig0 "$ipconfig")
fi
qm create "$template" --name "carrick-debian13-$profile" --cores "$cores" --memory "$memory_mib" --balloon 0 --cpulimit "$cores" --cpu host \
  --net0 "$net0" --scsihw virtio-scsi-pci --serial0 socket --vga serial0 --agent enabled=1 "${create_extra[@]}"
qm importdisk "$template" "$image" "$storage" --format "$disk_format"
# The imported volume's name depends on the storage type; attach exactly it.
disk=$(qm config "$template" | sed -n 's/^unused0: //p')
[[ $disk == "$storage:"* ]] || { echo 'imported disk is not on the site storage' >&2; exit 1; }
qm set "$template" --scsi0 "$disk" --ide2 local:iso/carrick-template-${template}-seed.iso,media=cdrom
# Boot order only after the disk exists: combined with the attach in one
# `qm set`, PVE 9 kept `order=net0;ide2` and the guest PXE/CD-looped with
# "No bootable device" until the provisioning deadline.
qm set "$template" --boot order=scsi0
qm config "$template" | grep -qx 'boot: order=scsi0' || { echo "VM $template boot order is not scsi0" >&2; exit 1; }
qm disk resize "$template" scsi0 "${disk_gib}G"
# Measure current CPU utilization AND load average, conservatively reserve two threads.
read -ra before < /proc/stat
sleep 5
read -ra after < /proc/stat
busy=$(awk -v a="${before[*]}" -v b="${after[*]}" -v n="$(nproc)" -v loadavg="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN {
  split(a,x); split(b,y); t=0; for(i=2;i<=9;i++) t+=y[i]-x[i];
  idle=y[5]-x[5]+y[6]-x[6]; u=(t>0?1-idle/t:1); if(loadavg/n>u) u=loadavg/n;
  printf "%.6f",u+2/n;
}')
awk -v projected="$busy" 'BEGIN { print "template projected CPU=" projected; exit !(projected<=0.80) }'
awk '/MemAvailable:/ {exit !($2 >= 10485760)}' /proc/meminfo
if [[ $profile == agent ]]; then qm start "$template"; else
  pve_call POST "/nodes/$node/qemu/$template/status/start"
fi
# Provisioning is bounded; the clone readiness deadline is separately five minutes.
qualified=false
for ((attempt=0; attempt<180; attempt++)); do
  if qm guest exec "$template" -- /bin/test -s /var/lib/carrick-ci/qualification.json 2>/dev/null | jq -e '.exitcode == 0' >/dev/null; then qualified=true; break; fi
  sleep 10
done
[[ $qualified == true ]] || {
  echo "Template provisioning failed; preserve VM $template for diagnosis." >&2
  echo 'Console: (printf "\r"; sleep 8) | timeout 15 socat -T 10 - UNIX-CONNECT:/var/run/qemu-server/${template}.serial0' >&2
  exit 1
}
qm guest exec "$template" -- /bin/cat /var/lib/carrick-ci/qualification.json | jq -r '."out-data"' > qualification.json
qm guest exec "$template" -- /bin/cat /var/lib/carrick-ci/packages.txt | jq -r '."out-data"' > packages.txt
# Clean clone identities/SSH credentials and shut down from inside the template.
qm guest exec "$template" -- /bin/bash -c 'cloud-init clean --logs --machine-id; rm -f /etc/ssh/ssh_host_* /home/runner/.ssh/authorized_keys; rm -rf /var/lib/cloud/instances /home/runner/.cache; sync'
if [[ $profile == agent ]]; then qm stop "$template"; else
  pve_call POST "/nodes/$node/qemu/$template/status/stop"
fi
for ((attempt=0; attempt<60; attempt++)); do
  [[ $(qm status "$template") == 'status: stopped' ]] && break
  sleep 2
done
[[ $(qm status "$template") == 'status: stopped' ]] || { echo 'Template did not stop' >&2; exit 1; }
qm set "$template" --ide2 "$storage:cloudinit" --ciuser runner --ipconfig0 "$ipconfig"
if [[ $nameserver != none ]]; then qm set "$template" --nameserver "$nameserver"; fi
qm template "$template"
jq -n --arg commit "$commit" --arg script_hash "$(sha256sum "$inputs/scripts/ci/build-template-debian.sh" | cut -d' ' -f1)" \
  --arg image_url "$image_url" --arg image_sha512 "$image_sha512" --arg runner_version "$runner_version" --arg runner_sha256 "$runner_sha256" \
  --arg sccache_sha256 "$sccache_sha256" --arg rustup_sha256 "$rustup_sha256" --arg gh_sha256 "$gh_sha256" --arg toolchain_hash "$(sha256sum seed/rust-toolchain.toml | cut -d' ' -f1)" \
  --arg lock_hash "$(sha256sum seed/Cargo.lock | cut -d' ' -f1)" --arg xtask_hash "$(sha256sum seed/carrick-xtask | cut -d' ' -f1)" \
  --arg packages_hash "$(sha256sum packages.txt | cut -d' ' -f1)" --slurpfile qualification qualification.json \
  --arg pool "$template_pool" --argjson vmid "$template" --arg profile "$profile" --arg node "$node" --arg storage "$storage" --arg bridge "$bridge" \
  --argjson cores "$cores" --argjson memory_mib "$memory_mib" --argjson disk_gib "$disk_gib" \
  --arg bootstrap_hash "$(sha256sum seed/runner-once.sh | cut -d' ' -f1)" --arg hook_hash "$(sha256sum seed/admit-job.sh | cut -d' ' -f1)" \
  '{vmid:$vmid,profile:$profile,node:$node,pool:$pool,cpu:"host",vcpus:$cores,memory_mib:$memory_mib,disk_gib:$disk_gib,storage:$storage,bridge:$bridge,script_commit:$commit,
    script_sha256:$script_hash,image_url:$image_url,image_sha512:$image_sha512,runner_version:$runner_version,runner_sha256:$runner_sha256,
    sccache_sha256:$sccache_sha256,rustup_sha256:$rustup_sha256,gh_sha256:$gh_sha256,toolchain_sha256:$toolchain_hash,cargo_lock_sha256:$lock_hash,
    xtask_sha256:$xtask_hash,bootstrap_sha256:$bootstrap_hash,hook_sha256:$hook_hash,packages_sha256:$packages_hash,qualification:$qualification[0]}' > manifest.json
qm config "$template"
cat manifest.json

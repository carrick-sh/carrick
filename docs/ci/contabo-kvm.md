# Contabo self-hosted KVM lane

The merge queue's KVM lane runs on a throwaway JIT clone on the dedicated
Contabo host (issue #287). This replaces the per-run GCP VMs
([gcp-kvm.md](gcp-kvm.md)), which remain as a fallback. The design,
admission and teardown are the Willow standing controller's, unchanged
([willow-pilot.md](willow-pilot.md)). Only the clone placement differs, and
it comes from the typed site table in `crates/carrick-xtask/src/ci_scaler/site.rs`.
A clone that GitHub assigns a job from a run other than the one it was minted
for admits it only after the controller re-vets that run
([willow-pilot.md](willow-pilot.md#actual-assignments-are-re-vetted-333));
the controller binary in `/root/carrick-ci/bin` carries this, so deploying it
needs a controller restart, not a template rebuild.

The same standing service also serves issue-label agent clones from template
9000; see [dispatch-worker.md](dispatch-worker.md) for the four-clone budget,
runner-independent credentials and VM-local leases. The KVM placement
and its one-clone budget below stay the same.

This is trusted-ref CI infrastructure for an experimental project, not an
adversarial isolation boundary.

## Site

| | Willow | Contabo |
|---|---|---|
| PVE node (`/etc/hostname`) | `willow` | `carrick-ctb` (FQDN `carrick-ctb.turkey-moth.ts.net`, its Tailscale name) |
| Clone storage | `local-lvm` (thin pool, `lvs` headroom) | `local` directory (PVE storage-status headroom) |
| Bridge, addressing | `vmbr0`, LAN DHCP | `vmbr1` NAT, static `10.77.0.(VMID-200)/24`, resolver 1.1.1.1 |
| Template 300 and each clone | 2 vCPU, 4 GiB, 64 GiB | 8 vCPU, 16 GiB, 100 GiB |
| VMs the token must not touch | 105 | 101-104 (agent workers); 9000 is licensed for agent clones after dispatch cutover |
| KSM page merging | allowed (PVE default) | off (`allow-ksm: 0` on template 300, inherited by clones, checked before each boot) |

Selection is by `/etc/hostname` and fails closed: an unknown host is refused,
never treated as Willow. Both sites use pool `carrick-ci`, template VMID 300
and clone VMIDs 308-349. `--max-concurrency` stays 1. Contabo has 48 threads. Before dispatch cutover, the four static agent
workers hold 40 vCPU and 96 GiB; agent clones must also pass headroom
admission until those workers are retired. The 80% CPU admission
ceiling remains an additional admission check; it is not cross-VM isolation.
Each VM serializes its own builds, gates and oracle phases with a local lease.

On Contabo, clones sit on the private NAT bridge, which they share with the
agent workers 10.77.0.11-14 (which hold codex and gh credentials). There is no
DHCP server and no host firewall opening. Two layers keep a job off that
subnet:

- The guest firewall from the template rejects private destinations. A job
  that gained root inside the clone could undo it.
- The PVE VM firewall on the template's `net0` (`firewall=1`,
  `/etc/pve/firewall/300.fw`, written by `carrick-xtask ci-scaler vm-firewall`
  from the site table) denies by default in both directions, with `ipfilter`
  and `macfilter` on. Inbound, it admits only SSH from the gateway (the
  controller). Outbound, it drops every RFC 1918, link-local and RFC 6598
  (100.64/10) range and the host's own public address 154.38.161.112 (so the
  agent workers, other clones, the gateway and every host service), then
  admits the remaining IPv4; IPv6 falls to the DROP policy. PVE copies the file to every linked
  clone. The controller checks the exact options and ordered rules over the
  API, on the template at startup and on each clone before it boots, and
  requires the datacenter firewall to be enabled. Any difference refuses
  service.

DNS to the public resolver and NAT to the internet still work.

## Backend selection

The `kvm-tests-willow` job and its `willow-kvm` runner labels are served from
Contabo; there is no separate workflow arm. Only one standing controller may
serve those labels, so Willow's stays stopped. To select the lane, set
`CARRICK_KVM_BACKEND=willow` and `CARRICK_SELF_HOSTED_KVM=true`. To fall
back to GCP, unset `CARRICK_KVM_BACKEND`, with `CARRICK_GCP_KVM=true`.
Flip the variables only after a green `workflow_dispatch` on main through a
Contabo clone.

## Host setup (root on Contabo)

1. Create pool `carrick-ci`, PVE user `ci-scaler@pve` (no password) and
   privilege-separated token `ci-scaler@pve!elastic`. Grant the user and the
   token the same roles as on Willow: `PVEPoolUser` and `PVEVMAdmin` on
   `/pool/carrick-ci`, `PVEDatastoreUser` on `/storage/local`, and
   `PVESDNUser` on `/sdn/zones/localnetwork`. Write the token's JSON
   (`full-tokenid`, `value`) to `/root/carrick-ci-token.json`, mode 0600,
   without printing it. The controller refuses to start if the token has any
   rights over a protected VM.
2. Build `carrick-xtask` on a Debian 13 x86 worker (glibc at most 2.41), and
   copy it with a `git archive` of `scripts/ci`, `Cargo.lock` and
   `rust-toolchain.toml` to `/root/carrick-ci`. Install `genisoimage`, `jq`
   and `binutils`, and put the official `gh` (2.102.0, the same as Willow,
   SHA-256 checked) at `/root/carrick-ci/bin/gh`: the controller calls it
   for JIT registration. Run one template build at a time; two builders
   on VM 300 race and the manifest records the wrong commit.
3. Because VM firewalls sit behind the host's NAT on `vmbr1`, add Proxmox's
   documented conntrack-zone rule to the `vmbr1` stanza in
   `/etc/network/interfaces`, then `ifreload -a`:
   `post-up iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1` (and the
   matching `post-down ... -D ...`).
4. `scripts/ci/build-template-debian.sh INPUT_DIR FULL_COMMIT XTASK` builds
   and qualifies template 300 from the site row (`carrick-xtask ci-scaler site`).
5. Run the controller as a systemd unit, so it survives reboots and session
   exits:

```ini
# /etc/systemd/system/carrick-ci-standing.service
[Unit]
Description=carrick ci-scaler standing KVM controller (issue #287)
After=network-online.target pve-cluster.service pveproxy.service
Wants=network-online.target

[Service]
LoadCredentialEncrypted=gh-token:/etc/credstore.encrypted/carrick-ci-gh-token
Environment=PATH=/root/carrick-ci/bin:/usr/sbin:/usr/bin:/sbin:/bin
# `$$` passes `$` to the shell; systemd would otherwise substitute it.
ExecStart=/bin/sh -c 'GH_TOKEN=$$(cat "$${CREDENTIALS_DIRECTORY}/gh-token"); export GH_TOKEN; exec /root/carrick-ci/bin/carrick-xtask ci-scaler standing --runner-group-id 1 --max-concurrency 1'
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

The GitHub token exists only in that controller process's environment; the
unit file and the journal never contain it. A CPU-ceiling stop or a frozen
admission exits non-zero and restarts after a minute, and the ledger in
`/root/carrick-ci/state` carries over.

## GitHub credential

The owner's GitHub token is stored as a systemd encrypted credential at
`/etc/credstore.encrypted/carrick-ci-gh-token` (root 0600, credential name
`gh-token`), piped in by the owner and never printed. This departs from
Willow's "forward over SSH stdin, never write it on the host", because a
standing service must survive reboots. See
[the security review](willow-pilot-security-review.md#contabo-standing-credential).

## VM-local leases (owner decision #639)

[Owner decision #639](https://github.com/carrick-sh/carrick/issues/639)
supersedes the physical-host broker design from #565. Leases are per VM,
never the whole hypervisor. The standing controller takes no shared or
exclusive physical-host lock for either KVM or agent clones. Each clone runs
its build/test work under its local lease. A local `gate` lease excludes
other local work; it does not promise a quiet physical host or isolate other VMs.

The owner disabled `/etc/carrick/host-lease.toml` on ctb-w1..w4 on
2026-10-18. With no broker config, `HostLease` selects the VM-local lock.
The owner also retires that config from VM 110 and the templates, the
`carrick-lease` broker account, its authorized keys and sshd drop-in. Workers
must not perform those administrative changes or reinstall the broker.
The generic broker implementation remains available for separately configured
hosts; it is not part of Contabo clone custody.

The [agent dispatch provider](dispatch-worker.md) shares the existing ledger,
VMID pool, admission checks, assignment re-vetting, deadlines and destruction
path with `willow-kvm`. Its template is VM 9000, with 8 vCPU and 20 GiB per
clone and at most four live agent clones. KVM capacity is counted separately.
Clones are destroyed after one job, including failed or timed-out jobs. The
owner deploys the controller and verifies the live trial; portable tests alone
do not establish deployed acceptance.

## Debugging

- `journalctl -u carrick-ci-standing` shows admission, clone lifecycle and
  backoff lines.
- Ledger: `/root/carrick-ci/state/ledger.json`. Clones are `carrick-ci` pool
  members 308-349: `pvesh get /pools/carrick-ci`.
- A clone's console: `qm terminal <vmid>` (serial0).

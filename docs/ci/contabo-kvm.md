# Contabo self-hosted KVM lane

The trusted post-landing KVM lane runs on a throwaway JIT clone on the dedicated
Contabo host (issue #287). The design,
admission and teardown are the Willow standing controller's, unchanged
([willow-pilot.md](willow-pilot.md)). Only the clone placement differs, and
it comes from the typed site table in `crates/carrick-xtask/src/ci_scaler/site.rs`.
A clone that GitHub assigns a job from a run other than the one it was minted
for admits it only after the controller re-vets that run
([willow-pilot.md](willow-pilot.md#actual-assignments-are-re-vetted-333));
the controller binary in `/root/carrick-ci/bin` carries this, so deploying it
needs a controller restart, not a template rebuild.

This is trusted-ref CI infrastructure for an experimental project, not an
adversarial isolation boundary.

## Site

| | Willow | Contabo |
|---|---|---|
| PVE node (`/etc/hostname`) | `willow` | `carrick-ctb` (FQDN `carrick-ctb.turkey-moth.ts.net`, its Tailscale name) |
| Clone storage | `local-lvm` (thin pool, `lvs` headroom) | `local` directory (PVE storage-status headroom) |
| Bridge, addressing | `vmbr0`, LAN DHCP | `vmbr1` NAT, static `10.77.0.(VMID-200)/24`, resolver 1.1.1.1 |
| Template 300 and each clone | 2 vCPU, 4 GiB, 64 GiB | 8 vCPU, 16 GiB, 100 GiB |
| VMs the token must not touch | 105 | 101-104 (agent workers), 9000 (worker template) |
| KSM page merging | allowed (PVE default) | off (`allow-ksm: 0` on template 300, inherited by clones, checked before each boot) |

Selection is by `/etc/hostname` and fails closed: an unknown host is refused,
never treated as Willow. Both sites use pool `carrick-ci`, template VMID 300
and clone VMIDs 308-349. `--max-concurrency` stays 1. Contabo has 48 threads,
and the agent workers already hold 40 vCPU and 96 GiB. The 80% CPU admission
ceiling remains an additional admission check; it is not cross-VM isolation.
The physical-host lease below serializes gates, clones and oracle phases.

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

## Runner lane

The `kvm-tests-willow` job and its `willow-kvm` runner labels are served from
Contabo; there is no separate workflow arm. Only one standing controller may
serve those labels, so Willow's stays stopped. The lane runs when
`CARRICK_SELF_HOSTED_KVM=true`.

## Events and receipts

`kernel-runtime.yml` runs `kvm-tests-willow` on each `push` to `main` and
owner `workflow_dispatch` on `main`, when this backend is selected. The
standing controller and job-start hook admit exactly those events for this
workflow (dispatch requires both `actor` and `triggering_actor` to be
`tjfontaine`); merge groups, pull requests and schedules are refused. The HVF
lane runs on the same events on cloudmac. The optional HVF full-conformance
closure runs only on owner dispatch when enabled, on a separate runner.
`ci.yml` continues running its own PR, merge-group, push, schedule and
dispatch lanes; only `ci-ok` is required for merging. Pre-merge hardware
evidence belongs to the director; these post-landing runs are the backstop.

The standing KVM controller, like cloudmac, serves only the newest queued
main push before owner dispatches. Each poll durably records and logs older
queued runs as `superseded by <newer sha>` before API cancellation. Superseded
run attempts cannot mint another local runner or pass a hook. An owner re-run
has a new attempt and undergoes normal admission. Every
standing assignment must rendezvous; the old reservation shortcut is removed.
The approval decision is durable under the same admission lock as supersession,
so an already approved local run cannot be superseded.

Cancellation is cleanup after releasing that lock. Before POST, a fresh GET
of all jobs in the run must show the target queued or waiting and no in-progress
job; other hardware (HVF) must be queued, waiting or completed.
A populated `started_at` on a queued job does not mean it is running.
Observed running work defers cleanup, retaining the intent across polls and
restarts. Completed work does not prevent cancelling a superseded queued lane.
Each controller applies this rule independently, without a cross-controller
acknowledgement protocol. **A superseded job never starts through our admission;
a raced cancellation can only affect a superseded run.** Another lane can
start between GET and POST; this bound does not promise never to cancel
running work. Cleanup is scoped to the superseded run ID. Pending intents
survive API errors and restarts. Per-entry cleanup errors log Deferred without
blocking newest-push admission; a 404 settles the entry as Gone. The receipt
gate reports skipped commits
as a range. Deploying this policy requires updated controllers and hooks.


Supersession retention follows queue lifetime: remove an entry only when
GitHub confirms completion/cancellation, the run is Gone, its attempt has
been replaced, or 25 hours have elapsed since first observation (the 24-hour
queue limit plus one hour). An accepted cancellation request alone is not
completion. The lifecycle loop owns pruning; stale assignment publications
cannot restore retired entries.

The live-entry limit is 4096. If pruning leaves more, keep **every** live
record, stop minting new runners and persist the distinct capacity error in
`ledger.json`'s `supersession_error` status field. Cleanup continues; once the
live set falls within the limit, the status clears and admission resumes.
Inspect this field alongside controller logs; no live denial is evicted to
make space.

On push, a selector built from trusted event.before walks back at most 50
first-parent commits to the nearest trusted KVM receipt. Zero/non-ancestor
before values fail closed. The comparison runs from a clean checkout/build
of the chosen receipted commit, reusing the selector build if it is the same
commit. It grades the candidate receipt without building candidate Rust.
The summary and notice name that baseline and list intervening commits
without their own receipts as **covered as a range, not individually**.
Missing ancestry-root baselines and exhausted walks fail distinctly as
**No baseline** and **Baseline walk limit**, without claiming a regression.
Owner dispatch seeds the current main tip without a baseline comparison.
See [baseline selection and seeding](mac-jit.md#seeding-baselines), including
the first-rollout selector bootstrap requirement.

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

## Physical-host lease (owner-applied, #565)

**These steps are not applied by the PR or by workers.** Drain the controller,
clones, worker builds/gates and oracle phases before installing or replacing the
broker, its binary, keys or lock file. The four workers remain CCD-pinned;
there is no dedicated quiet CCD (#564 owner decision).

`just lease carrick` shares the physical lock; `gate` and `docker` exclude all
other leases. The broker holds a real flock on an existing regular file at
`/run/carrick/host-lease.lock` (never `O_CREAT`) for the SSH session lifetime.
Requests are bounded JSON on stdin (`mode`, `wait_ms`); stdout is `waiting` then
`acquired` (or `waiting` then `timeout` on wait expiry), or just `acquired` when
uncontended. Invalid requests, excess waits, timeouts and transport failures
exit nonzero, never skip or use a local fallback. One `HOST_LEASE_WAIT_LIMIT`
(one hour) bounds admission; the broker's initial request and client transport
validation deadlines are five seconds.

### Host installation (root on carrick-ctb)

1. Install a reviewed Linux `carrick-xtask` at
   `/usr/local/libexec/carrick-xtask`, owned root:root, mode 0755.
   Create a dedicated account, with no password login, sudo or supplementary
   groups: `useradd --system --create-home --home-dir /var/lib/carrick-lease
   --shell /bin/sh carrick-lease`. A valid shell is needed for sshd's forced
   command; it does not grant an interactive login with the restricted key.
   Follow the site's sshd/PAM policy for key-only system accounts.
2. Install `/etc/tmpfiles.d/carrick-host-lease.conf`:

   ```text
   d /run/carrick 0750 root carrick-lease -
   f /run/carrick/host-lease.lock 0660 carrick-lease carrick-lease -
   ```

   Run `systemd-tmpfiles --create /etc/tmpfiles.d/carrick-host-lease.conf`.
   The directory is not writable by the broker account: it cannot replace the
   lock inode. The broker requires an existing regular file and does not create
   or chmod the lock. **Never unlink or replace a live lock**; tmpfiles `f`
   preserves it. The root controller opens this exact path directly, independent
   of VM client configuration.
3. Generate a separate Ed25519 key **on each worker/oracle**, not on a CI clone,
   with no passphrase for unattended gates. Transfer only the public keys to
   the host. Keep each private key readable only by the VM's gate user
   (for example root:carrick 0640 in root-owned `/etc/carrick`).
4. Use a root-owned authorized-key file, not one the broker account can edit,
   e.g. `/etc/ssh/authorized_keys/carrick-lease`, and add each public key as
   one line (substitute its verified public key):

   ```text
   restrict,from="10.77.0.0/24",command="/usr/local/libexec/carrick-xtask host-lease broker" ssh-ed25519 PUBLIC_KEY worker-name
   ```

   `restrict` disables pty, agent/X11/TCP forwarding and user rc execution.
   The broker ignores `SSH_ORIGINAL_COMMAND`: it cannot execute a supplied
   command or select a lock path from client input. Add defense in depth in a
   reviewed sshd drop-in (do not broaden existing access or firewall policy):

   ```text
   Match User carrick-lease
       AuthorizedKeysFile /etc/ssh/authorized_keys/%u
       AuthenticationMethods publickey
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       DisableForwarding yes
       PermitTTY no
       PermitUserRC no
       ForceCommand /usr/local/libexec/carrick-xtask host-lease broker
       ClientAliveInterval 5
       ClientAliveCountMax 3
   Match all
   ```

   Validate `sshd -t` before reloading sshd. Verify no other authorized key
   source or authentication mechanism admits this account. Keep the current
   administration connection open. No worker applies these changes.
5. Deploy the updated standing-controller binary and restart it only after
   draining its active clones. After trusted-ref and resource admission checks
   pass, it acquires `gate` immediately before `ledger.reserve`, retains it
   through clone POST, boot, execution, recovery and teardown, and releases on
   any non-reserving path or once every ledger row is destroyed. An idle
   controller holds no lease. Active-ledger recovery uses a zero-wait try: if
   contended, it refuses new admission, reconciles immediately to reap/quarantine
   surviving clones without booting unstarted ones, and retries on the next pass.
   Lease contention backs off without terminating the standing controller.
   Willow's admission is unchanged.

### VM client installation (owner/director)

Install `scripts/ci/contabo-host-lease.toml` at
`/etc/carrick/host-lease.toml` on **every worker and oracle VM**. Provision its
private key and `/etc/carrick/host-lease.known_hosts`; verify the host key
fingerprint through the existing trusted administration channel, never trust
an unauthenticated `ssh-keyscan` alone. All three files and their directory
must be protected from unrelated users. The client disables ambient SSH
configuration, multiplexing, agent use and forwarding, and requires the pinned
host key. It uses the existing `just lease`, `accept`, `impact`, `fixtures
restore`/`prepare`, and `target-prune` (`try_exclusive`) entry points.
Build commands needing isolation must also run under `just lease carrick`.
The lease is cooperative: unwrapped builds are not stopped by flock.

`CARRICK_HOST_LEASE_CONFIG` selects an explicit configuration file (missing or
malformed files fail). With no site file, other hosts retain local flock.
`CARRICK_HOST_LEASE_PATH` cannot override a configured broker. Do not distribute
the VM config or SSH private key to JIT clones: their controller already owns
the exclusive physical lease and their firewall forbids access to the broker.
They keep the existing local lease for their inner gate and nested signed-run
semantics.

Checkout admission still comes **before** host admission; no lease holder may
acquire a remote checkout lock or upgrade `carrick` to `gate`/`docker`. Nested
commands authenticate the same local validation capability and workload scope
and reuse one SSH session. A `gate` may contain either mode without downgrading;
`docker` may only contain `docker`, and `carrick` only `carrick`.

### Failure model and qualification

EOF or a killed broker/SSH connection releases flock. During contention the
broker observes stdin closure rather than waiting out the hour. The supervisor
spawns `ssh` in its own session (`setsid`) so group-directed signals to the
supervisor's process group do not drop broker custody before the five-second
workload cleanup completes. Lost client connections cancel supervised work and
report a failed run; the client's keepalive window (`ServerAliveInterval=2`,
`ServerAliveCountMax=3` = 6 s) is strictly shorter than the server's
(`ClientAliveInterval 5`, `ClientAliveCountMax 3` = 15 s) minus the five-second
cleanup limit (`6 s < 15 s - 5 s = 10 s`). This is not a partition-proof fencing
service: the remote lock may release before cancellation finishes, and a
controller crash releases its in-process lease while a clone could still be
running. Drain/reconcile surviving clones before admitting manual gates after a
controller failure. Do not claim crash-proof quietness or adversarial isolation.
Remote supervised cleanup on Linux requires procfs child enumeration to exclude
the custody SSH process from workload cancellation; unavailable enumeration
fails the existing bounded cleanup explicitly. Remote custody is not supported
by the Darwin guardian; macOS continues to use its local lease.

The portable `host_lease_broker` integration target runs the actual broker
binary over local stdio (the client transport wrapper execs that binary, never
synthesizes replies). It covers all shared/exclusive pairs, a waiting second
client proceeding after EOF/SIGKILL, bounded contention, disconnected waiters,
single-session nesting/no upgrade, malformed config and connection-loss
cancellation. It does not claim a deployed two-VM witness.

After owner installation, qualify from two VMs: hold
`just lease gate /bin/sleep 30` on one; on another run
`just lease docker /bin/echo admitted` and observe waiting then admission.
Repeat with the first VM's exact SSH-holder PID killed, and verify nonzero
holder status plus second-client admission. Repeat while a controller-owned
clone is active (worker/oracle must wait until destruction), and verify an idle
controller no longer excludes the oracle. Record exact binary hashes, PIDs and
results on #565 before claiming physical-host acceptance.

## Debugging

- `journalctl -u carrick-ci-standing` shows admission, clone lifecycle and
  backoff lines.
- Ledger: `/root/carrick-ci/state/ledger.json`. Clones are `carrick-ci` pool
  members 308-349: `pvesh get /pools/carrick-ci`.
- A clone's console: `qm terminal <vmid>` (serial0).

# Willow one-job runner pilot

This is the owner-approved phase-two pilot from design PR #4, not an elastic
production service. It admits one clone (2 vCPU, 4 GiB, 64 GiB), leaves VM 210
and every protected machine alone, and installs no host service or network
configuration. The foreground controller runs **on Willow** through SSH from
the Mac: the PVE secret remains in `/root/carrick-ci-token.json` and on-host
memory/pipes. Jobs receive only one-use JIT material.

The [pilot receipt](willow-pilot-evidence.md) records the successful job,
artifact digest, scoped API teardown and unchanged protected VM census.

## Build and supervise

Build `carrick-xtask` for x86 Linux away from the hypervisor. On the Mac, the
installed musl target can link this pure-Rust tool with:

```sh
RUSTFLAGS='-C force-frame-pointers=yes -C linker=rust-lld -C linker-flavor=ld.lld -C relocation-model=static -C link-arg=--no-pie' cargo build --locked --release -p carrick-xtask --target x86_64-unknown-linux-musl
```

This linker setting is scoped to the **Linux tool**, never the macOS Carrick
binary/USDT path. Transfer the binary plus a committed archive of `scripts/ci`,
`Cargo.lock` and `rust-toolchain.toml` to `/root/carrick-ci` on Willow. Run:

```sh
scripts/ci/build-template-debian.sh INPUT_DIR FULL_SCRIPT_COMMIT X86_LINUX_XTASK
```

The builder refuses an existing VM 300. Root `qm` builds/converts only 300;
start/stop use the scoped token API. Guest provisioning uses the existing
cloud image and a disposable local seed ISO, then removes identities/SSH keys
before conversion. The root-only manifest and package inventory are under
`/root/carrick-ci/template-300/`. The template contains neither a registered
runner nor GitHub/PVE credentials. Package versions are recorded after install;
apt packages are not snapshot-pinned, so a rebuild needs fresh qualification.

Put a checksum-verified official `gh` binary in `/root/carrick-ci/bin` without
installing a system package/service. Forward the director's GitHub credential
through SSH stdin into the foreground controller's environment; never place
it in command arguments, a seed disk, a job, or a log. Example, with a literal
reviewed commit substituted for `FULL_APPROVED_SHA`:

```sh
gh auth token | ssh root@willow 'IFS= read -r GH_TOKEN; export GH_TOKEN; export PATH=/root/carrick-ci/bin:$PATH; exec /root/carrick-ci/bin/carrick-xtask ci-scaler pilot --approved-sha FULL_APPROVED_SHA --runner-group-id 1 --one-job'
```

Runner group 1 is the GitHub default group; the JIT endpoint must accept that
ID for this repository. No organization settings or credential scope expansion
is performed by the controller. Dispatch exactly:

```sh
gh workflow run willow-pilot.yml --ref work/willow-pilot
```

## Authority and recovery

Demand requires the complete four-label set, `workflow_dispatch`, this
repository's `willow-pilot.yml`, `work/willow-pilot`, and the approved SHA.
GitHub can assign a different compatible job; the reservation never binds a
job ID. A guest job-start hook checks repository/event/workflow ref/SHA before
workflow steps. The launcher isolates listener/worker/hook in a fresh process
group; rejection kills that entire group with SIGKILL, so `always()` and
`failure()` workflow steps cannot continue after a failed authorization.
The ledger
records the actual assigned job, including completed alternate assignments.

Reservations count before clone POST, are fsynced before side effects, and
retain job deduplication after destruction. Every mutation checks typed clone
range, pool membership and exact ledger-generated VM identity. Unknown objects
are quarantined, never adopted. Clone, configure, start, stop, guest-agent and
delete operations all use the scoped token. The controller records PVE task
IDs and checks that the token has no rights over VM 105.

Admission uses a five-second CPU sample and one-minute load average, taking
the larger value and reserving two additional threads within the director's
80% ceiling. Exceeding that ceiling stops the foreground controller and
preserves the ledger for owner follow-up. It retains
6 GiB host memory, 150 GiB thin-pool data headroom, and metadata below 80%.
It checks again before boot. A shared five-minute deadline spans start,
guest-agent checks, authenticated host-key discovery and SSH readiness.
Before JIT registration, the controller requires completed cloud-init with
no errors; it accepts only the observed PVE deprecated `user` warning when
cloud-init exits 2. It explicitly starts the existing guest cleanup unit and
verifies it is active, then qualifies non-root KVM access. The controller
installs the canonical public launcher and `.sh` job hook embedded in its
own binary through the scoped guest-agent API. Template and controller share
these source files; cached template bootstrap bytes cannot select an older
hook. These preparations stay within the same five-minute deadline.

Every 60 seconds reconciliation preserves busy/unknown assignments. After
15 minutes, an unassigned registered guest is drained under the same flock as
the job-start hook, then its assignment is rechecked before removal. A passed
hook leaves a busy marker; a competing drain prevents steps from starting.
Completed jobs export runner stdout, stop and delete the clone through the
API, verify absence, then remove any remaining registration. Persisted
`Reaping` is durable teardown authorization: restart continues from owned VM
state without querying assignment, including when registration is already
gone or the VM is already stopped. Preparation errors do not grant that
authorization. GitHub job artifacts preserve capability,
build and CPL0 execution logs.

Restart recovers successful JIT registration by its exact ledger name. Failed
recorded tasks and absent reservations are distinguished from ambiguous clone
POST outcomes. A successful recorded clone resumes preparation in place only
for the same queued job/attempt, labels and approved SHA, using its live
configuration and existing transport key. Historical failures stay in the
ledger; a successful one-job controller exit requires an actual recorded
assignment and teardown. Check the GitHub job conclusion separately: that
exit does not assert that the workflow passed.
An ambiguous submission with neither an observable VM nor a
recorded task deliberately freezes admission for owner investigation; it is
never silently retried or released. API errors while a VM is active also
freeze admission and retain the ledger.

The clone firewall is guest-local: established connections, loopback and
DHCP/DNS are allowed; new private/link-local destination traffic is rejected.
Cloud-init administrative grants are removed before runner qualification.
This remains trusted-workflow infrastructure, not an adversarial isolation
claim. No load generator or Docker oracle is part of the pilot.

Authenticated curl calls use `--disable` as the first argument to prevent an
ambient `.curlrc` from tracing Authorization headers. Cloud-init exit 2 must
include at least one exact allowlisted Proxmox deprecation; an empty warning
map is not qualified. Template boot uses the same 80% CPU ceiling as clones.

The [security review regressions](willow-pilot-security-review.md) cover these
controls locally. The historical live receipt predates these fixes; no new
live Willow operations or deployment were performed for this review.

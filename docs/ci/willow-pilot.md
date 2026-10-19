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

Build `carrick-xtask` for x86 Linux away from the hypervisor, on the x86
Linux worker (carrick-vm), with its native glibc toolchain:

```sh
cargo build --locked --release -p carrick-xtask
```

Both consumers are Debian 13 (glibc 2.41): the Willow host (PVE 9) runs the
controller and every clone guest runs the job-start hook. A glibc build that
needs at most `GLIBC_2.41` runs on both; `build-template-debian.sh` refuses a
non-x86-64 or newer-glibc binary before creating VM 300, and provisioning
executes it (`verify-kvm`). A static musl build is not required: it is not
currently buildable (`carrick-portable` does not compile for musl and `ring`
needs a C cross-compiler on the Mac), and it would buy nothing while the guest
is pinned to Debian 13. Build on a host whose glibc is no newer than the
guest's.

Transfer the binary plus a committed archive of `scripts/ci`,
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

## Standing mode (main pushes and owner dispatch)

The standing controller now runs on the Contabo host
([contabo-kvm.md](contabo-kvm.md)); Willow's stays stopped, because only one
controller may serve the `willow-kvm` labels.
`ci-scaler standing` reuses this controller for `kernel-runtime.yml`'s
`kvm-tests-willow` job (selected when `CARRICK_SELF_HOSTED_KVM` is `true`):
pushes to main and owner dispatches on
main (`Admission::Standing`; see the
[security review](willow-pilot-security-review.md#standing-admission-surface)).
Before minting each runner it re-vets the reserved run (same admission and
attempt and exact SHA) and writes the guest's root-owned
`/etc/carrick-ci/policy` as `standing run=<id> attempt=<n> sha=<sha>`. That
reservation records demand provenance; every assignment still requires
controller approval. It admits at most
`--max-concurrency` clones (1 by default, never more than 2). Demand lists
only this workflow's runs. GitHub/PVE admission failures back off (30 s
doubling to 10 min) and never end the loop; the 80% CPU ceiling still stops
it. A job whose clone closed without a job is served again, at most three
times per job key.

### Receipt chain

Pushes to main create runs; both controllers coalesce queued pushes to the
newest run, recording older ones as `superseded by <newer sha>` before
cancellation. No merge-group, PR or schedule runs are admitted. The trusted pre-push selector walks back from event.before
to the nearest receipted first-parent ancestor (50 commits maximum). The
comparison uses that ancestor's code and reports unreceipted commits as a
range in the summary/notice. Missing baselines and walk-limit exhaustion
have distinct visible failures. Owner dispatch on main seeds receipts without a comparison. See
[events and receipts](contabo-kvm.md#events-and-receipts).

### Actual assignments are re-vetted (#333)

GitHub assigns a queued job to *any* idle runner with matching labels, not to
the run a clone was minted for: a clone minted for a main push can receive a
different main push's KVM job. The standing hook (`standing_hook_script`) therefore
runs `admit-job --controller` for every assignment, including its reservation,
the same credential-free rendezvous as cloudmac ([mac-jit.md](mac-jit.md)):

1. The hook writes its actual run id, attempt and SHA into the runner-owned
   `/run/carrick-ci/assignment.json` (created by the controller before JIT
   delivery) under the admission flock, then waits at most four minutes for
   `/run/carrick-ci/approved-policy`.
2. A dedicated assignment worker reads that request as root through the
   scoped guest agent, with a one-second timer between passes and under the same flock. It authenticates the job by this
   clone's runner id and the exact `willow-kvm` label set, re-vets the actual
   run through `Github::vet_assignment` (main push or owner dispatch admission), and fsyncs the actual job into the
   ledger (`assigned`, `assigned_key`, `approved`). Approval and supersession
   use the same controller admission lock; a superseded run gets no approval.
3. Only then does it publish the root-owned `approved-policy`, bound to the
   actual run, attempt and SHA; the hook verifies it and starts the job. An
   inadmissible assignment (another workflow, untrusted event, ref or repository) is recorded once in the ledger's
   refusal list and gets no approval, so the hook kills the session before
   any step.

A clone assigned another job neither holds its reservation nor consumes one
of its serves, so the reserved job is served by the next clone. The decision
code is shared with cloudmac (`ci_scaler/assignment.rs`). Before JIT the
controller requires the template's guest xtask to offer
`admit-job --controller` (every template built since the cloudmac re-vet,
#273, does) and otherwise refuses the clone, naming the template rebuild. Assignment serving continues while the lifecycle loop provisions another clone,
reconciles teardown, or backs off. The two loops publish through a short-held
ledger mutex: assignment writes preserve lifecycle state, lifecycle writes
preserve authenticated assignments, and every publication is fsynced before
approval. Refusal history retains at most 4096 job keys; evicted keys still
undergo full admission vetting if encountered again.

### GitHub credential for standing mode

Use a **fine-grained personal access token** limited to this repository and
to runner registration/removal and Actions demand, assignment and
cancellation. The owner creates it:

1. GitHub, Settings, Developer settings, Personal access tokens,
   Fine-grained tokens, Generate new token.
2. Resource owner `carrick-sh`; Repository access "Only select
   repositories": `carrick-sh/carrick`.
3. Repository permissions: **Administration: Read and write** (required by
   `generate-jitconfig` and runner removal) and **Actions: Read and write** (run
   and job status for demand/assignment, plus superseded-run cancellation). Metadata read-only is implied.
   Grant nothing else.
4. Set a short expiry and keep the token in the director's password manager;
   never write it on Willow. If the organization requires approval for
   fine-grained tokens, approve it for this repository only.

Forward it only through SSH stdin, exactly like the pilot:

```sh
read -rs WILLOW_GH_TOKEN   # paste the fine-grained token
printf '%s\n' "$WILLOW_GH_TOKEN" | ssh root@willow 'IFS= read -r GH_TOKEN; export GH_TOKEN; export PATH=/root/carrick-ci/bin:$PATH; exec /root/carrick-ci/bin/carrick-xtask ci-scaler standing --runner-group-id 1'
```

The parent receipt comparison runs in a hosted job, so guests need no `gh`. The pilot (`ci-scaler pilot`) writes `pilot
<sha>` to the same file and keeps its one-clone, one-job contract. Every
budget, ownership, recovery and hook rule below applies to both modes.

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

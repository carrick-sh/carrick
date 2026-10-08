> Historical inventory references below are retired. Do not execute the
> positional reconciliation or remote capture instructions. Current landing
> uses `just lint-domains` and fresh authority discovery with monotone ceilings.

# Runner-first CI and a reactive PR bus

Status: **plan of record; approved by the owner on 2026-10-05, with the
modification to bring elastic FreeBSD and NetBSD vetting onto willow**.
The runner-first direction was approved on 2026-10-04.
This is a docs-only revision, not a deployment or acceptance claim. Infrastructure
activation remains subject to the decisions below. Reported operational evidence
is dated 2026-10-04; capabilities without a live qualification are **UNVERIFIED**.

## Workflow and why it changes

1. Agents build and run focused tests locally, push early, and open PRs. They
   stop running full gates (`just accept`, `remote-accept`) themselves.
2. Runners execute gates as required PR checks. The GitHub merge queue tests the
   merged result: **a merge group IS the batch gate**, replacing the director's
   manual batch assembly. PR evidence never substitutes for merged-result checks.
3. Agents react to results. PR-bus phase 2 sends a failed check and its failure
   log to the PR's primary driver as an agy follow-up; the driver fixes and pushes.
4. The director reviews diffs, runs independent read-only reviews, and handles
   escalation and enqueueing. Independent reviews caught real defects in every
   batch-5 PR on 2026-10-04; green checks do not replace review.

The owner's 2026-10-04 operational evidence explains the change:

- Six or more workers each queued 20–35 minutes behind one exclusive VM host
  lease; gates ran one at a time.
- `remote-accept` refused immediately when cloudmac's gate-worktree lock was
  held, forcing the director to hand-sequence access.
- Stale or superseded runs held locks; a waiting gate acquired the lease after
  priority had been reassigned.
- A worker's cancellation SIGTERMed another checkout's gate because its process
  filter was not bound to its checkout.
- cloudmac's data volume was a USB drive delivering about 2 MB/s under load.
  Worktrees and caches were moved to an internal SSD volume with a 100 GiB quota
  and a guard agent. This fixes the reported storage placement problem; it does
  not establish runner throughput or eliminate lease serialization.

## Gate placement

| Gate | Runner and boundary |
| --- | --- |
| fmt, clippy, doc, test, cross-check, BSD builds | GitHub-hosted Ubuntu and **`macos-15` pinned**: the `hv_gic` APIs require SDK 15. Hosted macOS cannot run Hypervisor.framework guests. Hosted BSD builds/cross-checks do not prove bhyve/NVMM runtime behavior. |
| `linux-portable`, x86 KVM/CPL0 | willow Proxmox clones (additional provider TBD) |
| FreeBSD/bhyve and NetBSD/NVMM vetting | Ephemeral BSD targets on willow, driven by one-job JIT Linux proxy runners in the same `carrick-ci` pool; `merge_group` and owner dispatch first. Advisory pilots, then required merge-group inputs to `ci-ok` after qualification. Hosted cross-checks remain required. |
| aarch64 Linux with KVM | provider TBD (owner's biggest gap) |
| Signed HVF | **cloudmac self-hosted runner — OWNER APPROVED 2026-10-04.** JIT ephemeral registration; only `merge_group` and owner-triggered `workflow_dispatch`, never untrusted `pull_request` events. Workers stop using cloudmac directly for gates. |
| Docker oracle | Dedicated director-controlled job/host, never sharing a host with Carrick runs. Native ARM Linux for the canonical ARM oracle; x86 results prove only x86. No Docker on cloudmac or VM 210. |
| EC2 Mac fallback only | On-demand Dedicated Host, **24 h minimum**, no Spot. Obtain a current quote and approval before use; minute-scale elasticity does not apply. |

## Prerequisites, in order

1. Land [PR #3, ci-green](https://github.com/carrick-sh/carrick/pull/3), so main's
   hosted CI is green.
2. Fix all four merge-queue blockers below. Each would break merge-group runs;
   changing runner capacity alone cannot fix them. Numbers are the director's
   blocker identifiers, not assumed GitHub PR numbers.

   | Blocker | Required change and proof |
   | --- | --- |
   | (9) Rustdoc exemption receipt binds the exact PR base SHA | Bind the exemption to covered inputs: reviewed file hashes plus toolchain. An unrelated merge must preserve validity; a covered-input change must invalidate it. This does not relax exact-SHA gate/artifact receipts. |
   | (12) Source-hash-pinned schedule replay receipts | Futex wake/exit and setid receipts currently fail after any unrelated kernel source edit. Scope validation to the replay's actual covered inputs and prove unrelated edits preserve validity while relevant changes invalidate it; do not simply disable freshness checks. |
   | (11) Failed `remote-recapture` leaks `gate-worktree.lock` | Release on failure/cancellation and prove the next checkout can acquire it; preserve checkout-before-host-lease ordering. |
   | (13) `remote-accept` refuses a held checkout lock | Queue with an explicit bound, report the holder, and prove timeout/cancellation removes the waiter. Cleanup must be bound to the checkout and run ID, never another checkout's gate. |

3. Land [PR #2, merge-queue workflows](https://github.com/carrick-sh/carrick/pull/2),
   then enable the main ruleset: PRs, merge queue, required checks. Review identity
   remains an owner decision. Reconcile the companion migration's persistent/two-Mac
   proposal with cloudmac-only JIT and separate oracle provisioning before enabling
   it. Required checks must run for `merge_group`, validate its exact event SHA,
   and fail on missing evidence or skipped required tests. Keep check names and
   ruleset requirements aligned (`host-linux-arm64`, `host-linux-x86-kvm`,
   `macos-host`, `signed`, `merge-queue`); signed checks are required at the merge
   group stage, not an impossible untrusted-PR prerequisite.
4. Register runners: willow Linux pilot first, then a template-build milestone
   and single-job pilot for each BSD OS before shared-pool elastic admission
   (see BSD vetting below).
5. Enable PR-bus phase 2, then switch every worker brief to **push-and-react**.
   Update conflicting full-gate requirements in AGENTS.md, skills and hooks in
   that cutover PR. Do not describe workers as switched while briefs still demand
   local acceptance. Until required runner coverage is qualified, keep the queue
   paused where coverage is missing; do not treat missing checks as success.

## Additional elastic capacity (provider TBD)

AWS was evaluated on 2026-10-04 (c8i nested-virt spot, c7g.metal spot) and declined by the owner on cost. The cloud capacity provider will be chosen later.

Any provider must meet these requirements: an x86_64 host exposing KVM to the
guest (nested virtualization or bare metal) for `linux-portable` and CPL0; an
aarch64 host with KVM for the ARM lanes; ephemeral JIT runners; idle termination;
a hard spend cap; no SSH (or a managed equivalent); non-root scoped credentials.

## Willow runner pool

[Pilot PR #18](https://github.com/carrick-sh/carrick/pull/18) reports template
**300**, a scoped token, a **single-clone** limit and an **80% projected CPU**
admission ceiling. Template qualification and clone lifecycle operations are
reported proven; the first job is pending a quiet window. A successful Actions
job plus teardown remains **UNVERIFIED**. The wider scaler below is a proposal,
not a claim that the pilot has delivered the fleet.

Owner-supplied capacity snapshot: 16 threads, about 75% busy; 62 GB RAM, about
12 GB free; VM 210 uses 40 GB/12 vCPU and VM 106 uses 8 GB. Free storage was
local-lvm 815 GB and external ZFS 440 GB. These measurements are **UNVERIFIED in
this revision** and need recapture before expansion. Protected VMs **105, 106,
200–203, 210 and 211 must never be touched by template builders, runners, the
scaler or its janitor**; objects outside the CI pool are also excluded. Any owner
decision to resize VM 210 is a separate operation outside this rollout.

The landed pilot is implemented in `crates/carrick-xtask/src/ci_scaler.rs` and
`crates/carrick-xtask/src/ci_scaler/live.rs`, with
`scripts/ci/build-template-debian.sh` and `.github/workflows/willow-pilot.yml`.
It currently accepts only the approved pilot workflow's owner dispatch and SHA,
uses template 300, allows one clone and delivers JIT material over authenticated
SSH. BSD OS/template selection, proxy/target reservations and merge-group
admission extend this controller and ledger; they are not already implemented.

Extend the existing pilot with a small Rust controller under `carrick-xtask`,
running as an unprivileged service on willow, with a durable job/VM ledger
outside runner disks. It invokes
`gh api` with argument arrays, owns no worker conversations, and scales to zero.
Build or helper code never executes on the hypervisor itself.

| Component | Concrete proposal and acceptance proof |
| --- | --- |
| Namespace | Pool `carrick-ci`; reserve VMIDs **300–349**, templates 300–307 (four variants, two generations), clones 308–349. Preserve pilot reservations and verify remaining IDs are unused before expansion. Mutation/deletion requires pool membership **and** range **and** ledger identity/tag. Never adopt a VM just because its name matches. |
| Golden image | Extend the pilot template builder toward checksum-pinned Debian 13 image, package snapshot, Rust from `rust-toolchain.toml`, Cargo.lock, just, cargo-deny, Semgrep, jq, clang/cross toolchains, sccache and checksum-pinned official runner. Manifest records inputs, script commit, image hash and qualification results. Repeatable inputs, not an unsupported claim of bit-identical disks. |
| Variants | Base Linux/build image; KVM capability from the same base. Oracle images belong on a separate director-controlled host, not this Carrick pool. No Docker in VM 210 workers. Templates contain no owner login, SSH private key, GitHub credential or registered runner. Regenerate machine IDs/SSH host keys at first boot. |
| Storage | Linked clones on supported local-lvm thin storage; dedicate a CI allocation capped at **300 GiB**, retain at most two image generations. 64-GiB clone disks; 96 GiB for heavy jobs. Keep at least 150 GiB actual thin-pool free space; stop admission on low data **or metadata** headroom. External ZFS is optional image/log storage after approval, not an implicit grant over its existing volumes. |
| Nested x86 | Willow is Ryzen: qualify host `kvm_amd nested=1`, expose `cpu: host`/SVM to clones, open `/dev/kvm` as the job user, require KVM API version 12 and live vCPU execution. Configuration changes need approval; existence of the device or a compile pass is insufficient. |
| PVE credential | Privilege-separated, expiring `ci-scaler@pve!elastic` token; VM rights scoped to `/pool/carrick-ci`, template clone rights only on dedicated templates. No root/global VM, `Sys.Modify`, permission management, migration or backup privileges. |
| ACL qualification | Pool-scoped VM privileges alone may not authorize cloning: allocation needs dedicated-storage `Datastore.AllocateSpace`/audit and an approved bridge's `SDN.Use`. Owner preconfigures those narrow resource ACLs; never broaden to shared storage administration to fix a 403. Use API-viewer permission checks on **installed 9.2**, then prove clone/start/stop/delete in-pool succeeds and outside-pool access is denied. If namespace isolation cannot be expressed, stop and redesign the allocation broker. |
| Secret boundary | GitHub runner-administration credential and PVE token stay in the supervisor, not cloud-init disks, job environment or PR-controlled config. Deliver only short-lived JIT material via authenticated one-use bootstrap; erase it after consumption. Deny runner access to the PVE management network, other VMs and controller state. |
| Cache | Private content-addressed sccache keyed by OS/ISA/toolchain/flags/template; cap at 100 GiB within the storage budget. Trusted reviewed jobs alone can write a shared namespace. Public PR jobs use isolated caches; do not share mutable target directories or credentials. |

[Proxmox permissions and token separation](https://pve.proxmox.com/pve-docs/chapter-pveum.html)
describe the ACL model; [VM documentation](https://pve.proxmox.com/pve-docs/chapter-qm.html)
describes templates, clones and resource controls. A pool is an authorization
group, not a resource quota or a numeric VMID fence: the controller must enforce
budgets and reservation rules as well.

Preserve the pilot's root-local token boundary for every OS: the PVE secret is
stored **only on willow as root-owned, root-only
`root:/root/carrick-ci-token.json`**, never copied to this worker, a proxy, BSD
target, template, seed disk, checkout, artifact or log. The existing transport
reads it locally and passes authorization through stdin, never command-line
arguments. Any unprivileged supervisor extension must use that local credential
broker rather than relocating or widening access to the token. GitHub
administration credentials likewise stay controller-side; proxies receive only
short-lived one-use JIT configuration, and BSD targets receive neither.

### Demand, JIT and cleanup

| Signal | Tradeoff | Recommendation |
| --- | --- | --- |
| `workflow_job` webhook (`queued`, `in_progress`, `completed`) | Fast and label-aware; needs a reachable TLS receiver/relay, HMAC verification, durable delivery deduplication and reconciliation after missed events. | Later, only if polling latency is material. Never expose the PVE API to GitHub. |
| Outbound `gh api` polling | No inbound reachability; modest delay and API load. REST exposes runs/jobs, not a replayable `workflow_job` event stream. | **Start here:** every 30 s, paginate queued/in-progress runs, then each run attempt's jobs; reconcile a full outstanding-job inventory every 5 min. Track rate-limit headers, ETags and exponential API backoff. |

Use [workflow run/job APIs](https://docs.github.com/en/rest/actions/workflow-jobs)
and [runner JIT configuration](https://docs.github.com/en/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-a-repository).
Deduplicate by `(repository, run_id, run_attempt, job_id)`. Count booting and idle
reservations against demand so repeated polling cannot launch duplicates. Prefer
merge-group jobs, then oldest eligible PR work, with aging to prevent starvation.
Match complete label sets against an allowlisted tier map, not arbitrary labels
chosen by a PR.

| Lifecycle | Rule |
| --- | --- |
| Admit | Check repository, collaborator permissions, allowed event/workflow revision, exact SHA, tier and live resource budget. Fork/unknown-workflow requests get hosted checks only. PR workflow guards and runner labels are not security boundaries. |
| Reserve → boot | Persist a reservation before an asynchronous PVE clone/start task; record task ID, generation, VMID and deadline. Default boot deadline 5 min; journal failures before removing the reservation. |
| Register | After readiness, supervisor obtains repository JIT config with a unique runner name and the actual approved runner-group ID; supply `self-hosted,Linux,X64,<tier>` and a fresh work folder to `run.sh --jitconfig …`. Runner-administration write permission is required; job tokens remain `contents: read`. |
| Assign → run | JIT handles one job. GitHub may assign any matching eligible job; a runner reservation is **not** a binding to the observed job ID. Reconcile the actual assignment before reporting evidence. Re-register a fresh runner for the next job, never reuse the consumed config. |
| Complete | Export full job/runner logs, receipts, SHA and image/capability manifest before scoped shutdown/deletion; remove any stale runner registration. Retain evidence 30 days outside the clone. An external janitor covers cancellation and lost `always()` steps. |
| Reconcile | Every 60 s compare ledger, pool inventory, PVE tasks and GitHub runner/job state. Reap unassigned clones after 15 min; running clones only after confirmed terminal state or declared job deadline plus 10-min cleanup allowance. Short heartbeat loss triggers investigation, not killing live work. |
| Recover | Unknown pool objects are quarantined for owner inspection. Controller restart resumes recorded tasks; API outage freezes new admission and preserves active jobs. Runner/image updates are tested and refreshed regularly; respect GitHub's runner update deadline. |

GitHub documents [one-job ephemeral runners and webhook scaling](https://docs.github.com/en/actions/reference/runners/self-hosted-runners).
Start with build job deadlines of 120 min, backend jobs 180 min; different
deadlines need a reviewed workload budget. Infra replacement after a failed boot
is distinct from retrying a failing conformance test; preserve each failure.

### Size and throughput

All figures below are **UNVERIFIED planning estimates**, not measured build performance.
Treat the supplied GB measurements conservatively as approximate GiB and
recapture actual bytes before deployment. Reserve **6 GiB for willow/controller**
and **4 CPU-thread equivalents for host/Windows demand**; do not resize VM 106.

| Stage | Proposed capacity |
| --- | --- |
| Pilot | Leave VM 210 unchanged; one **2-vCPU/4-GiB/64-GiB** clone, Cargo jobs=2, lightweight work only. |
| After owner drains/resizes VM 210 | Candidate: 210 at **24 GiB/6 vCPU**, CPU limit **4**. Pool max **8 CPU equivalents/20 GiB**, at most **3 clones**. Two **4-vCPU/8-GiB** runners or one **8-vCPU/20-GiB** heavy runner, never both. |
| Approved BSD vetting pair (after capacity qualification) | **2-vCPU/2-GiB** Linux proxy plus **4-vCPU/8-GiB** BSD target: **2 clones, 6 CPU equivalents/10 GiB** total, charged to the same pool. Heavy mode excludes pairs. The current one-clone pilot cannot admit a pair. |

At the supplied 75% CPU utilization, reserving two additional busy threads would
project 87.5%, above the admission limit: the pilot initially waits for a quieter
window (at most 67.5% existing utilization). The present host has disk space, not
immediately available heavy-build capacity.

Reserve both CPUs and memory atomically; `cpulimit`/Cargo jobs constrain real
parallelism, fixed RAM avoids balloon-induced gate failures. Admit only if measured
memory retains the reserve and projected CPU use stays below 80%; pause admission
after sustained pressure, without throttling or cancelling a live correctness
gate. Shrinking vCPU counts alone does not remove the current worker load: drain
sessions first and reduce admitted worker/build work. Developer OOM or loss of
interactive capacity is a rollback trigger, not permission to overcommit RAM.

Throughput is `slots × 60 / (job minutes + lifecycle minutes)`; a PR may require
several jobs and another merge-group build. Measure p50/p95 queue, boot, build,
cache hit, RAM peak and steal time over 20 jobs before expanding. **No claimed PR
landing rate:** cloudmac remains the serial bottleneck. Nested lane performance
evidence requires exclusive quiet-host admission, including other willow guests;
if owner workloads cannot be quieted, collect semantic evidence only.

## Signed HVF on cloudmac

**OWNER APPROVED 2026-10-04**, confirmed through the director during this
revision: cloudmac is the signed HVF runner, using JIT ephemeral registration
only for `merge_group` jobs and owner-triggered `workflow_dispatch`, never
untrusted `pull_request` events; workers stop using cloudmac directly for gates.
The supervisor design admits one runner at a time and excludes all
`pull_request` jobs. Deployment and live qualification remain **UNVERIFIED**.
The repository is already restricted to collaborators only per the owner. Still authenticate event, actor, reviewed workflow and SHA before
admission; labels alone are not a trust boundary. The director's Mac is excluded.

Use a dedicated non-admin job account, credential-free checkout and no personal
keychain/SSH/agy credentials or general sudo. Supervisor credentials remain
inaccessible to jobs. One-job registration limits reuse; account/workspace reset
is not machine reimaging. Suspected compromise blocks admission.

All users share the durable physical-host lease. Preserve checkout lock → host
lease → build/tests ordering; never unlink a live lock or upgrade shared to
exclusive. Workers no longer request direct gates. Schedule authorized debugging
separately, never overlapping signed acceptance. Cancel only recorded job-owned
processes using checkout identity and `CARRICK_RUN_ID`; use
`scripts/sudo/kill.sh <run-id>`, never a broad process filter. Failed cleanup
blocks the next job. Never shut down, reboot or sleep cloudmac.

Build with signed scripts and Apple ld64. Record SHA, artifact SHA-256, CDHash,
LC_UUID, entitlement and `__dof_carrick`; preserve the tested binary between
rungs. Upload logs and receipts on failure as well as success. Reap only the
job's workspace, runner registration and processes after exporting evidence.

Replace any companion workflow's host-Docker fixture preparation before
activation: the dedicated native ARM oracle/build host publishes immutable,
source/executable-hash-validated fixtures for the exact SHA; cloudmac verifies
and restores them. No Docker or nested Linux workaround on cloudmac. Move portable
work to hosted/Linux runners while retaining Darwin host, signing, HVF, USDT and
artifact identity coverage. KVM success cannot qualify HVF behavior.

Qualification is **UNVERIFIED**: require one full merge group, correct artifact
identity, no skipped required tests, cancellation scoped to its checkout, and
supervisor restart recovery without rebooting the host. Measure queue/gate/cleanup
p50/p95 before setting capacity expectations; JIT registration does not make one
physical HVF host parallel.

## Elastic BSD vetting on willow

**OWNER APPROVED 2026-10-05** as the modification to this runner-first plan:
ephemeral FreeBSD/bhyve and NetBSD/NVMM lanes run alongside the Linux KVM lane
on willow Proxmox. Deployment and runtime qualification remain **UNVERIFIED**.
Keep the existing hosted BSD cross-checks; extend the same controller, pool,
VMID fence, ledger, admission rules and cleanup rather than introducing another
scaler. An official one-job Linux JIT runner drives one disposable BSD target;
do not assume a native GitHub runner distribution for BSD.

### Per-OS templates and capability

Use separate checksum-pinned FreeBSD and NetBSD templates within **300–307**,
preserving Debian template 300 and at most two generations per variant. Allocate
both proxy and target clones from **308–349**, always in **`carrick-ci`**. Reserve
unused template IDs after inventory inspection; do not repurpose protected VMs
**105, 106, 200–203, 210 or 211**. Follow the Debian builder's input manifests,
pinned toolchain/package inventory, credential-free image and regenerated
machine/SSH identities, with OS-specific unattended provisioning and readiness.
BSD builders are new milestones, not existing scripts or deployed templates.

| Template | Qualification and vetting surface |
| --- | --- |
| FreeBSD/bhyve | Pin a FreeBSD release/image and package repository; the earlier FreeBSD 15 proposal must be qualified separately from hosted CI's **14.3-RELEASE** sysroot. Install the native Rust/C toolchain, just and dependencies; provision `vmm.ko`, `/dev/vmm` access and narrowly scoped backend cleanup before job admission. Build the `platform-freebsd` CLI/runtime and bhyve closure; prove live nested vCPU execution. |
| NetBSD/NVMM | Pin a NetBSD release/image and matching kernel/module sources; the earlier NetBSD 11 (or explicitly pinned prerelease) proposal is not a qualification claim. Install the native toolchain/dependencies, load NVMM and provision `/dev/nvmm` access. Build the NVMM backend and `platform-netbsd` CLI/runtime closure; prove live nested vCPU execution. Record any required eager-GPA-fault module preparation from `scripts/netbsd/load-nvmm-eager-gpa-fault.sh` and its patch in the template manifest; do not silently treat patched and stock kernels as equivalent. |

Willow is Ryzen/x86_64: start with **amd64 BSD hosts and x86_64 Linux guests**.
Require host `kvm_amd nested=1`, `cpu: host` with exposed SVM/NPT and actual
bhyve/NVMM machine creation, vCPU run and teardown inside each BSD clone.
Aarch64 is an option only on a future willow capability that is separately
qualified for that ISA and backend; emulated aarch64 builds do not prove nested
bhyve/NVMM. Read [HAL](../../hal.md) and the
[bhyve memory contract](../../bhyve-shared-memory.md); device presence or a
cross-compile is insufficient. Qualify non-root backend access or a reviewed,
fixed privileged test helper where existing live tests require root; never give
workflow code general sudo. Unsupported nesting blocks the runtime milestone
with explicit evidence.

### Jobs, triggers and aggregate result

The existing `cross-check-freebsd` and `cross-check-netbsd` jobs in
`.github/workflows/ci.yml` run on hosted Ubuntu and already feed `ci-ok`.
Their `justfile` recipes are the compile baseline: `just check-freebsd` checks
the x86_64 FreeBSD CLI/runtime with `platform-freebsd`, including all targets;
`just check-netbsd` checks all targets of `carrick-vmm-nvmm`, without claiming
the broader CLI/runtime closure. Willow adds native linking and execution:

- FreeBSD: locked native build of `carrick-cli` and `carrick-runtime` with
  `--no-default-features --features platform-freebsd`, including the bhyve
  backend, then the qualified kernel-semantics subset.
- NetBSD: locked native build of `carrick-vmm-nvmm`, plus the CLI/runtime with
  `--no-default-features --features platform-netbsd`, then the qualified
  kernel-semantics subset. Broader portability gaps remain visible failures,
  not evidence inferred from the narrower hosted cross-check.
- Start VM-free semantics with `just test-kernel-semantics` from
  `crates/carrick-kernel-example`; commit an explicit nonempty per-OS case
  manifest and expected counts during qualification. Add live backend smoke
  and reviewed conformance selections for `bhyve-local` and `nvmm-local` from
  `docs/conformance-testing.md` and `scripts/conformance/suites.toml`. Preserve
  OS-specific results and overlays in `scripts/conformance/baseline.bhyve.jsonl`
  and `scripts/conformance/baseline.nvmm.jsonl`; this is bring-up coverage, not
  full Linux or HVF closure. No retries or weakened work budgets to make green.

No Docker on willow CI clones or VM 210. Differential selections require the
director's separate native x86 Linux oracle host and exact-input fixture/image
and oracle identities. The current harness runs a Docker phase; splitting or
replaying that evidence must be implemented and qualified before enabling such
jobs. Until then use kernel-semantics plus live backend smoke, never invoke the
unchanged differential harness as a Docker-free shortcut. x86 evidence does not
substitute for the canonical native ARM oracle.

Initially admit only **`merge_group` and owner-triggered `workflow_dispatch`**,
like cloudmac's signed runner; no `pull_request` jobs. Authenticate actor,
repository, event, reviewed workflow revision and exact event SHA both before
provisioning and in the proxy's job-start admission hook. Extend the pilot's
allowlist deliberately. Use full Linux/X64 label sets with separate allowlisted
tiers (proposed `willow-bhyve` and `willow-nvmm`) to select OS templates; labels
alone do not authorize work. Obtain fresh JIT configuration per job on the
controller, reconcile the actual assignment, and consume it only once.

Single-job pilots publish **advisory** OS-specific checks and logs; they confer
no required coverage and do not relax today's hosted inputs to `ci-ok`.
After each OS qualifies build, selected case counts, live backend capability
and lifecycle, promote its check independently to a **required merge-group
input to `ci-ok`**, with a reviewed aggregate/ruleset change. Expected checks
missing, cancelled, failed or unexpectedly skipped must fail the aggregate;
missing capacity leaves work queued, never green. PRs retain hosted checks;
owner dispatch produces evidence but cannot satisfy a different merge-group
SHA. This phase-in changes no workflows or aggregate policy in this revision.

### Shared capacity, staging and teardown

The current **one-clone total** cap applies across OSes; it cannot fit a
proxy/target pair. Build/qualify templates serially under resource admission,
then admit each single-job BSD pilot only after recaptured host capacity permits
an explicitly configured **two-clone** pair budget. Under the proposed expanded
pool's **three-clone, 8-CPU-equivalent/20-GiB** ceiling, one BSD pair can coexist
with at most one lightweight **2-vCPU/4-GiB** Linux clone: **8 CPU/14 GiB** total.
Two BSD pairs or a pair plus a heavy runner cannot fit. These are shared totals,
not per-OS entitlements or authorization to resize VM 210.

Reserve proxy and target VM slots, CPU, memory and storage atomically, including
booting/idle reservations. Retain the **80% projected CPU** ceiling, **6-GiB
host reserve**, storage headroom and pressure rules above. If a whole pair
cannot fit, keep the job queued with its capacity reason and queue age; launch
neither half. Prioritize merge groups with aging across Linux and both BSD OSes;
freeze new admission on API/pressure/cleanup failure and preserve active gates.
Nested performance measurements additionally need quiet-host admission.

| Milestone | Required evidence before proceeding |
| --- | --- |
| FreeBSD template build | Pinned image/packages/toolchain manifest, isolated bootstrap, fresh identities, authorized bhyve device access and live nested execution/cleanup; preserved template 300 and protected VMs. |
| NetBSD template build | Same evidence for NVMM, plus kernel/module/patch identity and nested GPA-fault qualification; no changes to reference VMs. |
| One FreeBSD job, then one NetBSD job | Separate owner-dispatched pilots: exact-SHA native build, nonempty semantics selection, backend smoke, actual JIT assignment, exported logs and one-job proxy/target teardown. Qualify cancellation and restart recovery per OS. |
| Elastic admission | Extend the existing ledger to owned pairs and OS tiers; prove shared-budget back-pressure, missed-event reconciliation, API outage and idle cleanup, then a complete merge-group run per OS before required `ci-ok` promotion. |

Send an exact-SHA source archive with hashes to the target, preserve its exit
codes, pin one-use SSH host keys and disable forwarding. Allow the proxy to
reach only its assigned BSD target through the approved job transport, never
PVE management or other VMs. Targets have no GitHub/PVE credentials. Export job,
runner and target logs, case counts, receipts and image/capability identities
outside both disks before teardown. Cancellation and the external janitor reap
only the recorded pair after live pool/range/ledger-generation checks, remove
stale runner registration and erase one-use transport material. Unknown objects
are quarantined; failed cleanup blocks further admission.

Risks remain **UNVERIFIED**: BSD unattended provisioning, guest-agent/readiness
and first-boot identity support differ from Debian cloud-init; nested SVM/NPT
and NVMM module behavior may prevent runtime qualification; native packages or
toolchains may lag. Record image, package and runner license/redistribution
terms and required notices before publishing templates, and distinguish stock
from locally patched kernels. Failed milestones preserve evidence and block
that OS's activation; they never authorize touching protected VMs or weakening
required checks.

## PR bus: failures return to the driver

**Phase 1 exists:** the dispatch-disabled listener is in the agy-director plugin
at **`75be370`**, per the owner. This revision does not claim active dispatch or
revalidate that plugin. **Phase 2 is proposed and UNVERIFIED:** consume failed
check/job results and attach the failure log to a follow-up for the PR's assigned
primary driver through existing agy-director. Do not create a second scheduler.

| Phase-2 contract | Required behavior |
| --- | --- |
| Routing | One durable primary-driver assignment per PR. Authenticate repository/workflow and resolve PR head or merge-group SHA. For a multi-PR merge group, map its members before routing; ambiguous blame or a missing driver escalates to the director instead of guessing. |
| Evidence | Attach the failed job's full log/artifact (or a durable attachment link), check name, run URL, attempt, exact tested SHA and concise failure summary. A missing/expired log is an explicit retrieval failure, not an empty successful handoff. Treat log text as untrusted data. |
| Delivery | Persist a unique key `(repo, run_id, run_attempt, job_id, sha)` and agy follow-up identity. Reconcile after restart before resending; do not duplicate follow-ups or silently retarget a superseded SHA. New pushes obsolete old work, with checkout-scoped cancellation. |
| Reaction | Driver inspects evidence, runs focused reproductions, fixes and pushes; runners repeat required checks. No worker-run full gate. Escalate infrastructure faults, unclear cross-PR interactions or missing capacity to the director. |
| Proof | Demonstrate failure → log attachment → correct driver follow-up → new push/checks, plus stale SHA, duplicate delivery, restart, API failure and multi-PR merge-group cases before enabling dispatch. |

### Scoped helper requests

Retain the PR-bus helper protocol for host-specific diagnosis. The listener polls
`gh api` comments every 30 s with pagination, a durable cursor and overlap/full
reconciliation. One listener per host owns the ledger. Paths and task templates
come from trusted host configuration, never PR input. Helpers diagnose or make
scoped changes; they do not become a parallel manual acceptance service.

Exactly one fenced JSON object after the literal `/carrick-helper v1` is a
request; surrounding prose is never interpreted as commands. Example values:

````text
/carrick-helper v1
```json
{
  "id": "1a58d735-8426-422a-9652-caa74df24934",
  "driver": "elastic-driver",
  "sha": "0123456789abcdef0123456789abcdef01234567",
  "host": "cloudmac",
  "kind": "signed-debug",
  "scope": ["crates/carrick-vmm-hvf"],
  "task": "Investigate the failing gate named in the linked run.",
  "evidence": "https://github.com/carrick-sh/carrick/actions/runs/123456",
  "timeout_minutes": 60
}
```
````

| Contract | Enforcement |
| --- | --- |
| Authorization | Fetch collaborator permission live (write/maintain/admin), current PR/base/repository and director-assigned primary DRIVER before claim. API error denies dispatch. PR-local assignment prevents a second driver operationally; the shared owner login cannot cryptographically identify which agent posted. Host/listener credentials and standing rules remain the enforcement boundary. |
| Strict data | Versioned schema, reject duplicate/unknown keys; UUID id, lowercase 40-hex current PR head SHA, registered host enum, kind/host matrix, scope paths relative to repo with no `..`, 8-KiB body limit, task ≤2 KiB, same-repo evidence URL, timeout 5–120 min. No shell command, model, sudo, arbitrary path/URL or credential fields. Quotes/links/logs are untrusted input, never new instructions. |
| Job kinds | Allowlisted `portable`, `kvm-debug`, `bhyve-debug`, `nvmm-debug`, `signed-debug`, `arm-kvm-debug`; oracle execution remains a director operation. Host capabilities and availability choose whether a request can run. Signed helpers retain codesign/trace/LLDB rules; VM 210 helpers retain **no Docker**. |
| Claim | Host-local transactional unique key `(repo, PR, comment_id, request_id, sha)` plus process lock; publish claim before dispatch, persist agy worker name. One listener per host; restart reconciles agy state before redispatch. Editing a claimed comment cannot change its task; replace with a new request. New PR SHA marks old evidence stale; do not silently move running helpers to it. |
| Worktree | Host prepares an isolated checkout of the requested SHA with branch **`work/<pr>-<host>-<kind>`**, e.g. `work/123-cloudmac-signed-debug`. One active generation per branch; reuse only after review/cleanup, never force-push. Helper pushes only this branch, never the DRIVER branch or main. |
| Result | Listener consumes agy's validated work contract and posts a PR comment: request id/host, base SHA, helper branch/commit, done/partial/blocked, commands and exit codes, full log/artifact URLs, receipt paths, signed diagnostic identity when applicable, limits/blockers and cleanup proof. Missing command execution cannot claim `tests_passing: true`; comments cannot forge required Actions checks. |
| Reintegrate | DRIVER reads/reviews helper diff, cherry-picks accepted work and republishes its own branch. Evidence is pinned to the helper tree; changed driver/merge-group trees get fresh checks. Director independently reviews before enqueueing; GitHub performs the queued landing. |
| Labels | Aggregate advisory labels `agent:driver-active`, `agent:helper-requested`, `agent:helper-running`, `agent:blocked`, `agent:driver-review`, `agent:director-review`; `host:cloudmac`, `host:willow-kvm`, `host:freebsd`, `host:netbsd`, `host:arm-linux`. Recompute from all requests so one completed helper cannot hide another blocked one. Labels are not acceptance or authorization. |
| Caps | Initially **1 helper/PR**, **2 VM helpers**, **1 cloudmac helper**; **3 global** maximum, additionally bounded by existing agy capacity and physical budgets. cloudmac helper and CI never overlap; signed queue gets priority with scheduled helper windows. Per PR: at most 2 new requests/day and 120 helper-minutes/day; operator-configured provider/token spend ceiling. Exhausted quota leaves a visible queued/blocked reason; helpers cannot recursively dispatch. |

## Open owner decisions

| Decision | Proposed choice / activation boundary |
| --- | --- |
| Elastic capacity provider | choose an elastic capacity provider for x86 KVM and aarch64 KVM (AWS declined on cost) |
| Review identity | Agents share the owner's GitHub identity, which cannot provide an independent approving review of its own PR. Choose a distinct authorized reviewer identity or an explicit revised review policy before enabling the ruleset. Read-only agent reviews remain required director evidence. |
| VM 210 sizing | Keep pilot sizing until the owner decides whether to drain/resize 210 to 24 GiB/6 vCPU/CPU limit 4. Expanded pool/storage/network ACLs require approval and recaptured host capacity. |

## Rollout evidence and rollback

No phase weakens checks to manufacture green. Follow the ordered prerequisites;
then require pilot job/teardown, fleet interruption/idle cleanup, a complete
merge-group gate and phase-2 delivery proofs. Exercise controller restart,
stale registration, API outage and checkout-scoped cancellation. Preserve logs,
receipts, image manifests and failed-attempt identity outside disposable runners.

If admission, isolation or cleanup fails, freeze new jobs, preserve evidence and
reap only ledger-owned resources. Pause affected merge-queue admission; keep
hosted checks running. Disable bus dispatch independently while retaining its
ledger and listener. Escalate to the director rather than returning workers to
hand-sequenced full gates. Never touch protected VMs or power-cycle cloudmac.

## Verification of this revision

Requested docs-only verification:

```sh
test -s docs/superpowers/plans/2026-10-04-elastic-ci-and-pr-bus.md && just fmt-check
```

This check does not qualify any runner, AWS capacity, hypervisor, PR-bus dispatch
or merge-queue behavior. No infrastructure, workflow or ruleset changes are made
by this revision, and no acceptance receipts or runtime results are claimed.

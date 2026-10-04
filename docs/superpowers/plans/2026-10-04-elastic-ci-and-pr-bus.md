# Elastic CI and a PR bus

Status: **proposal, 2026-10-04**. This document authorizes no deployment. Pool
creation, templates, credentials, runner registration, VM resizing, purchases and
GitHub settings need separate owner approval. All implementation paths below are
proposed; this change creates only this document.

## Decisions and compatibility

| Boundary | Design |
| --- | --- |
| Landing | PRs and GitHub merge queue; the director reviews, enqueues and owns landing. A helper result never authorizes a merge. |
| Companion | Read the [merge-queue migration at `0410065d`](https://github.com/carrick-sh/carrick/blob/0410065d0597a86548fc3860f77f4121f8b91942/docs/superpowers/plans/2026-10-04-merge-queue-migration.md). Retain checks `host-linux-arm64`, `host-linux-x86-kvm`, `macos-host`, `signed`, `merge-queue`, exact event-SHA receipts and failure-on-skip aggregate behavior. |
| Superseded hardware proposal | The companion proposes two Macs and persistent runners. Owner decisions here exclude the director's Mac from runners and propose supervised JIT registration on **cloudmac only**, pending approval. Reconcile that plan before activation. |
| Trust | Collaborators drive work; agents share the owner's GitHub account. The repository is **public**, confirmed with `gh repo view`; collaborators-only work does not prevent outside PRs/comments. Authenticate every privileged request and retain the companion's workflow review/admission boundary. |
| Ownership | Exactly one DRIVER per PR, recorded by the director in a durable assignment ledger; HELPERS have scoped tasks and their own branches. Shared GitHub identity cannot enforce separation between those roles. |
| Capacity | Willow/PVE 9.2: supplied measurements are 16 threads, about 75% busy; 62 GB RAM, about 12 GB free; VM 210 uses 40 GB/12 vCPU, VM 106 uses 8 GB. Free storage: local-lvm 815 GB, external ZFS 440 GB. |
| Evidence limit | `ssh root@willow` failed DNS; read-only SSH to `100.122.248.80` timed out. These measurements were supplied by the owner, not independently recaptured. No Proxmox mutation occurred. |
| Protected machines | Never touch VMs 105/106 or any VM outside the dedicated CI pool. VMs 200–203/211, including BSD references 201/211, are reference evidence only. VM 210 resizing/migration is an explicit owner operation, outside the scaler. |
| Oracle | Director owns Docker oracle execution. x86 Docker proves the x86 lane only; the canonical ARM oracle needs native ARM Linux. Never overlap Carrick and Docker phases on a physical host. |

The shared owner account also cannot supply an independent GitHub approving
review of its own PR. The companion's review rules require a distinct authorized
reviewer identity, or a deliberately revised owner-approved review policy before
activation; labels and comments do not solve that constraint.

## Willow runner pool

Use a small Rust controller under `carrick-xtask`, running as an unprivileged
service on willow, with a durable job/VM ledger outside runner disks. It invokes
`gh api` with argument arrays, owns no worker conversations, and scales to zero.
Build or helper code never executes on the hypervisor itself.

| Component | Concrete proposal and acceptance proof |
| --- | --- |
| Namespace | Pool `carrick-ci`; reserve VMIDs **300–349**, templates 300–307 (four variants, two generations), clones 308–349. Verify that the range is unused before reservation. Mutation/deletion requires pool membership **and** range **and** ledger identity/tag. Never adopt a VM just because its name matches. |
| Golden image | Future repo script `scripts/ci/build-template-debian.sh`: checksum-pinned Debian 13 image, package snapshot, Rust from `rust-toolchain.toml`, Cargo.lock, just, cargo-deny, Semgrep, jq, clang/cross toolchains, sccache and checksum-pinned official runner. Manifest records inputs, script commit, image hash and qualification results. Repeatable inputs, not an unsupported claim of bit-identical disks. |
| Variants | Base Linux/build image; KVM capability from the same base; Docker-enabled x86 oracle variant for director-approved jobs. No Docker in VM 210 workers. Templates contain no owner login, SSH private key, GitHub credential or registered runner. Regenerate machine IDs/SSH host keys at first boot. |
| Storage | Linked clones on supported local-lvm thin storage; dedicate a CI allocation capped at **300 GiB**, retain at most two image generations. 64-GiB clone disks; 96 GiB for heavy/oracle jobs. Keep at least 150 GiB actual thin-pool free space; stop admission on low data **or metadata** headroom. External ZFS is optional image/log storage after approval, not an implicit grant over its existing volumes. |
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

All figures below are **planning estimates**, not measured build performance.
Treat the supplied GB measurements conservatively as approximate GiB and
recapture actual bytes before deployment. Reserve **6 GiB for willow/controller**
and **4 CPU-thread equivalents for host/Windows demand**; do not resize VM 106.

| Operating mode | VM 210 and pool budget | Eligible runner mix | Estimated service rate |
| --- | --- | --- | --- |
| Today: pilot only | Leave 210 at 40 GiB/12 vCPU; pool max 1 clone, **2 vCPU/4 GiB**. About 8 GiB of supplied free memory remains after allocation. | One lightweight lint/cross-check job, Cargo jobs=2. No heavy build or credible performance comparison under 75% host load. | Assuming 15–30 min work + 2 min boot/cleanup: **1.9–3.5 jobs/h** when admitted. |
| Recommended after draining sessions | Owner reduces 210 to **24 GiB/6 vCPU**, CPU limit **4**. Pool max **8 CPU equivalents/20 GiB**, at most **3 clones**. Memory budget: 24 + 8 (106) + 6 reserve + 20 pool = **58 GiB**, leaving about 4 GiB extra. | Two normal **4-vCPU/8-GiB** Linux/KVM runners; or one **8-vCPU/20-GiB** heavy runner, Cargo jobs=6; not both. | Two normal jobs at 20–35 min + 2 min overhead: **3.2–5.5 jobs/h**. One heavy job at 35–60 min + 2 min: **1.0–1.6 jobs/h**. |
| BSD job in recommended mode | One **2-vCPU/2-GiB** Linux proxy plus one **4-vCPU/8-GiB** BSD target; both count toward clone cap. | One BSD pair plus one **2-vCPU/4-GiB** lightweight job fits at **8 vCPU/14 GiB**, 3 clones. Heavy mode excludes BSD pairs. | BSD pair at 25–45 min + 3 min overhead: **1.25–2.1 jobs/h**, plus independent lightweight work. |
| Retire 210 later | Owner drains/saves sessions, replaces them with persistent development storage and dedicated-pool work VMs; 210 remains excluded from deletion. Pool could rise to **12 CPU/36 GiB**, after recapture. | Three **4-vCPU/10-GiB** normal jobs, or one **8-vCPU/20-GiB** heavy plus one normal. | Three normal jobs: **4.9–8.2 jobs/h** under the same assumed durations; worker sessions consume this same budget. |

At the supplied 75% CPU utilization, reserving two additional busy threads would
project 87.5%, above the admission limit: the pilot initially waits for a quieter
window (at most 72.5% existing utilization). The present host has disk space, not
immediately available heavy-build capacity.

Reserve both CPUs and memory atomically; `cpulimit`/Cargo jobs constrain real
parallelism, fixed RAM avoids balloon-induced gate failures. Admit only if measured
memory retains the reserve and projected CPU use stays below 85%; pause admission
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

## FreeBSD/bhyve and NetBSD/NVMM

GitHub's [official supported runner OSes](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
exclude BSDs. Recommend an official ephemeral **Linux proxy runner** that drives
one disposable BSD target over SSH. The proxy reports the GitHub check and uploads
target evidence; Carrick compilation/tests execute on BSD, never on the proxy.

| Approach | Security and maintenance | Choice |
| --- | --- | --- |
| Linux proxy + BSD clone | Extra small VM and SSH transport, but official job lifecycle/actions/artifact handling. Supervisor provisions one-use SSH access, pins generated host keys, disables agent forwarding, passes no GitHub/PVE credentials to BSD, and destroys both VMs. Proxy cannot allocate arbitrary targets. Preserve remote exit codes and fail on disconnect/missing logs/skips. | **Use for both BSD lanes.** Send a source archive for the exact SHA and hashes; no blanket shared-tree rsync. Cancellation asks the supervisor to reap only that job's target. |
| [Community `github-act-runner`](https://github.com/ChristopherHX/github-act-runner) in BSD | Go/act implementation advertises FreeBSD support; NetBSD, JIT/one-job behavior, action compatibility and cancellation need qualification on pinned versions. Places runner credentials and a second protocol implementation in each BSD image; upstream compatibility and incident response become our responsibility. | Research alternative, not initial acceptance infrastructure. Require checkout, shell, artifacts, cancellation and credential-erasure proofs before considering it. |

| Template/build script proposed | Qualification before scheduling | Size |
| --- | --- | --- |
| `scripts/ci/build-template-freebsd.sh`: checksum-pinned **FreeBSD 15** image/package repository, Rust pin, LLVM/libclang, just/git, non-root CI user, scripted `vmm` loading and guest device permissions. | `cpu: host` exposes SVM; load `vmm`, open `/dev/vmm`, build `--no-default-features --features platform-freebsd`; execute real bhyve guest tests and cleanup. Use [HAL](../../hal.md) and [bhyve memory contract](../../bhyve-shared-memory.md), not an old native-backend pass. | 4 vCPU/8 GiB/64 GiB + proxy 2 vCPU/2 GiB. |
| `scripts/ci/build-template-netbsd.sh`: checksum-pinned **NetBSD 11** release or explicitly pinned prerelease if no approved release exists, pkgsrc/package snapshot, Rust/LLVM pin, SSH bootstrap and NVMM module/device permissions. | SVM visible; open `/dev/nvmm`, query its capability/version, execute live NVMM vCPU tests with `platform-netbsd`; record precise kernel/CPU/nesting manifest. VM 201/211 references stay stopped/untouched. [Older native-lane evidence](../../netbsd-native-lane-evidence.md) proves neither NetBSD 11 nor NVMM. | Same; one pair initially. |

Both scripts use the Debian script's manifest/secret-erasure contract and produce
templates in the dedicated pool. Nested SVM availability does not prove bhyve or
NVMM works: an unsupported lane remains visibly blocked and cannot supply a green
required check. Add BSD required checks only after live qualification and a
reviewed merge-queue aggregate update; until then existing cross-checks retain
their narrower meaning.

## Native ARM Linux and ARM BSD capacity

Willow cannot hardware-accelerate ARM guests. Emulation/cross-compilation does
not fill the native ARM oracle or KVM gap. Rank purchases after trying the free
hosted tier and an authorized local capability experiment.

| Rank/use | Capacity, cost and limitations | First proof |
| --- | --- | --- |
| **1. GitHub-hosted `ubuntu-24.04-arm`** | Native ARM host tests and director-approved Docker oracle jobs; standard hosted jobs are free for this public repository, subject to service limits. Keep these jobs hosted instead of moving ARM work to willow. Disk headroom and image pulls need measurement. [GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). | Record `uname -m`, image digest and `docker info` architecture; run native `linux/arm64`, never QEMU/Rosetta. Separately try opening `/dev/kvm`, KVM API 12, VM/vCPU creation and execution. Hosted ARM KVM is **unproven**; absence means blocked KVM capability, not a passing runtime gate. |
| **2. Dedicated permanent ARM Linux box** | Recommend procurement budget **$350–500 all-in** for an RK3588 **32-GB** board, NVMe, PSU and cooling: one 4-core/12-GiB build and one 2-core/6-GiB service VM, or one exclusive oracle/KVM phase. Budget is an allowance, not a vendor quote. [Radxa's 32-GB RK3588 option](https://docs.radxa.com/en/rock5/rock5itx/getting-started/introduction). | Verify firmware exposes EL2, supported kernel/KVM/GIC, a 4-KiB page configuration and thermal stability. Boot ARM FreeBSD/NetBSD under QEMU/KVM with recorded image/UEFI hashes. Prefer this recurring resource over using cloudmac's small RAM pool. |
| **2b. Used M1/M2 mini with Asahi** | Alternative procurement allowance **$250–500**, subject to a real quote; choose at least 16 GB, preferably a 24-GB M2. Dedicated purchased machine only. Faster build candidate, less RAM than the 32-GB board, distribution/kernel maintenance and 16-KiB-page compatibility costs. [Asahi page-size compatibility notes](https://asahilinux.org/docs/sw/broken-software/). | Native Linux KVM does not require Apple's M3 VZ nesting feature. Prove actual KVM and ARM BSD boot on this kernel; a supported desktop install is insufficient. Never reinstall either existing Mac. |
| **3. On-demand Graviton `c7g.metal`, preferably Spot after qualification** | [AWS specifies 64 cores/128 GiB](https://docs.aws.amazon.com/ec2/latest/instancetypes/co.html). Budget example, **not a live quote**: $1/host-hour Spot allowance, $2.32/host-hour on-demand assumption; one exclusive 1-h job costs $1 or $2.32 plus boot/EBS/egress. Four independent 8-core/16-GiB builds amortize to $0.25 or $0.58/job-hour at full occupancy. Quiet oracle/performance jobs use the whole host. | Owner selects region/AZ, verifies metal Spot availability and [current Spot history](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-spot-instances-history.html)/on-demand quote. Test `/dev/kvm`, live Carrick and ARM BSD guests on the actual image. Cap one instance, 2 h/job, $10/day initially; termination exports evidence and marks interrupted acceptance incomplete. Non-metal Graviton is not assumed to expose EL2. |
| **Experiment only: M4 + VZ Linux nesting** | Director Mac: **32 GB**, manual experiments only, never a runner. cloudmac: **16 GB**, signed gate first. Both macOS **27**, per director; cloudmac M4/16 GB independently confirmed read-only. Linux VMs can be native ARM Docker/KVM hosts if qualified, but consume the same physical CPU/RAM as signed work. | First use director-operated Tart Linux VM, **4 vCPU/8 GiB/64 GiB**, with `tart run --nested`; reserve at least 12 GiB for the 32-GB host. On cloudmac, only an approved idle-window test, **2 vCPU/4 GiB**, Cargo jobs=2, then shut down before any signed work. Never run a signed gate and Linux VM together. |

Concrete M4 experiment: pin Tart/image versions, query
`VZGenericPlatformConfiguration.isNestedVirtualizationSupported`, start an
ARM Ubuntu VM with nesting enabled, verify `aarch64`, then **open** `/dev/kvm`
and issue `KVM_GET_API_VERSION` (`ioctl 0xae00`, expect 12). Run
`cargo test -p carrick-vmm-kvm --lib -- --nocapture`, require the ARM live
`trap_engine::execve_tests` to execute with **zero SKIP lines**, and run
`just kvm-smoke` (builds fixture/backend and checks guest stdout/exit). Archive
host/guest kernel, page size, vCPU capability and full results; an ioctl alone
does not prove a usable vCPU. ARM BSD guests are a subsequent **8–12-GiB** Linux
VM experiment using QEMU/KVM and disposable image overlays, suitable for the
32-GB director experiment or a dedicated ARM box, not cloudmac during gate work.

Tart/VZ documentation currently describes [M3/M4, macOS 15+ nesting for **Linux guests**](https://tart.run/faq/#nested-virtualization-support).
That supports testing Linux KVM, not an assertion that a macOS VM can itself run
Carrick HVF. macOS 27 behavior still needs a live capability test. ARM BSD boot
and host tests do not imply ARM bhyve/NVMM Carrick backends: the repo's current
BSD VMM lanes are x86, as documented in HAL.

Docker inside a Linux VM on cloudmac runs no Docker daemon on macOS, but still
uses cloudmac's resources and must honor its physical-host lease. It **does not
automatically satisfy** the owner's no-host-Docker intent: approve or reject that
interpretation explicitly. Default recommendation is hosted/dedicated ARM
Linux oracle execution, with cloudmac reserved for signing.

## The macOS signed tier

| Item | Proposal |
| --- | --- |
| Admission | After explicit approval, a trusted cloudmac supervisor starts **one JIT runner per job**, never two. Labels include `self-hosted,macOS,ARM64,carrick-signed,macos-host`; `macos-host` then `signed` are separate one-job registrations for the same merge-group SHA. No persistent runner service is necessary; the supervisor persists. |
| Trust boundary | Only reviewed merge groups and authorized main dispatches. Dedicated non-admin job account, no personal keychain/SSH/agy credentials, credential-free checkout, no general sudo. Root-owned supervisor/config and controller tokens are inaccessible to jobs. JIT limits reuse, but account/workspace reset is **not machine reimaging**; suspected compromise quarantines the host. |
| Ordering | One cloudmac-wide queue covers Actions, helpers, remote-accept and any approved Linux VM. Lock order remains remote checkout lock → physical-host lease → build/tests; Actions uses its own checkout. All accounts use the same durable absolute `CARRICK_HOST_LEASE_PATH`; never unlink it or upgrade shared to exclusive. Accept holds exclusive `gate`; diagnostics use the existing signed/shared rules. |
| Artifact | `just build`/signed scripts, Apple ld64, entitlement and `__dof_carrick`; record full SHA, SHA-256, CDHash, LC_UUID and scoped cleanup. Preserve the tested binary; no rebuild/re-sign between evidence rungs. Upload complete logs/receipts even on failure, and fail the aggregate on skips. |
| Between jobs | Stop job-owned processes by recorded run IDs (`scripts/sudo/kill.sh`), confirm no guest/helper remains, remove that job's workspace/runner directory and revoke stale registration, then release admission. Never delete shared gate worktrees/leases. Failed cleanup blocks the next job; crash recovery is external to Actions. |
| No host Docker | Companion currently provisions signed fixtures with host Docker. Replace this before activation: director-approved native ARM Linux build publishes immutable, executable-hash/source-hash-validated fixtures keyed to the **exact SHA**; cloudmac verifies the manifest and restores the required paths. Altered/absent inputs fail. A Linux VM alternative remains an owner decision; this document does not implement either. |
| Shrink the tier | Move portable kernel/semantics, Linux host tests, lint/build/license/cross-checks and deterministic budgets to Linux; keep Darwin host behavior, codesign/HVF/USDT, physical artifact identity and live signed closure on cloudmac. KVM parity cannot prove HVF faults, Darwin races or signing. Remove Mac work only after equivalent coverage is demonstrated, without weakening budgets. |

| macOS isolation alternative | First experiment and cost boundary |
| --- | --- |
| Physical cloudmac JIT | Lowest incremental rental cost; reserve a 1–2 h off-peak supervisor/cleanup trial, max one job. A 16-GB host cannot promise a concurrent nested build VM plus the signed gate. Owner approves the runner account and permitted use first. |
| Tart/VZ macOS clone | Cheap copy-on-write isolation for source builds, but nested **HVF in a macOS guest is unproven** and current Tart documents Linux-only nesting. First check API support/platform validation, then an entitled minimal `hv_vm_create` in the macOS guest if configuration is supported; only after that test signed Carrick/DOF/cleanup and compare physical-host ratios. Budget 2 engineer-hours and existing-machine idle time; no purchase justified by a compile-only success. |
| EC2 Mac | [AWS requires a Dedicated Host for at least **24 h**, one Mac per host, on-demand only](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-mac-instances.html). A 1-h probe still buys a day. Illustrative $1.50/h allowance means **$36 minimum**, plus storage/transfer/tax, not a quoted rate; obtain the region/type price and a $50 experiment cap first. Qualify entitlement/HVF/DTrace/lease just as on cloudmac. Batch day-long gate work; unsuitable for per-job minute-scale elasticity. |

Expected signed throughput is `60 / (macos-host + signed + provisioning/cleanup
minutes)` merge groups/h. At an illustrative 15 + 60 + 5 min it is **0.75
groups/h**, with at most one group admitted initially; a four-PR merge limit does
not guarantee four PRs share a build. Measure the real gate before choosing the
queue timeout; do not add the director's Mac to conceal the bottleneck.

## PR bus: DRIVER requests a HELPER

A future Rust listener polls `gh api` comments on open PRs every 30 s (pagination,
durable cursor plus overlap/reconciliation). One host listener owns each host's
dispatch ledger. It translates validated data into an allowlisted task template
for the **existing agy-director**, rather than creating another agent scheduler.

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
| Result | Listener consumes agy's validated work contract and posts a PR comment: request id/host, base SHA, helper branch/commit, done/partial/blocked, commands and exit codes, full log/artifact URLs, receipt paths, signed identity when applicable, limits/blockers and cleanup proof. Missing command execution cannot claim `tests_passing: true`; comments cannot forge required Actions checks. |
| Reintegrate | DRIVER reads/reviews helper diff, cherry-picks accepted work and republishes its own branch. Evidence is pinned to the helper tree; changed driver/merge-group trees get fresh checks. Director independently reviews before enqueueing; GitHub performs the queued landing. |
| Labels | Aggregate advisory labels `agent:driver-active`, `agent:helper-requested`, `agent:helper-running`, `agent:blocked`, `agent:driver-review`, `agent:director-review`; `host:cloudmac`, `host:willow-kvm`, `host:freebsd`, `host:netbsd`, `host:arm-linux`. Recompute from all requests so one completed helper cannot hide another blocked one. Labels are not acceptance or authorization. |
| Caps | Initially **1 helper/PR**, **2 VM helpers**, **1 cloudmac helper**; **3 global** maximum, additionally bounded by existing agy capacity and physical budgets. cloudmac helper and CI never overlap; signed queue gets priority with scheduled helper windows. Per PR: at most 2 new requests/day and 120 helper-minutes/day; operator-configured provider/token spend ceiling. Exhausted quota leaves a visible queued/blocked reason; helpers cannot recursively dispatch. |

Integration sketch (future listener constructs argv; these are not deployment
commands executed by this change):

```sh
python3 ~/.claude/local-marketplaces/agy-director/agy-director/scripts/agy_worker.py \
  --host cloudmac --run pr-123 capacity
python3 ~/.claude/local-marketplaces/agy-director/agy-director/scripts/agy_worker.py \
  --host cloudmac --run pr-123 dispatch --name pr123-signed-debug \
  --dir /host-approved/worktrees/pr123-cloudmac-signed-debug \
  --prompt-file /listener-owned/validated-request.txt \
  --backend auto --class hard --timeout 60m
python3 ~/.claude/local-marketplaces/agy-director/agy-director/scripts/agy_worker.py \
  --run pr-123 inbox --all-hosts --follow
```

The plugin path above is the director's configured installation. This VM has
`/home/carrick/agy-director/scripts/agy_worker.py`; read-only inspection confirmed
`--host`, `capacity`, `dispatch`, prompt shipping and merged inbox support. Paths
are host-registry configuration, not PR input. A listener generates prompts from
a fixed policy plus clearly delimited task data; prompt-injection resistance is
also enforced through host permissions, branch/scope fencing and credentials.
Never assume a prompt alone isolates an agent with an owner account.

## Phases, decisions and rollback

Every phase is a separate reviewed implementation PR and approval to change the
named infrastructure. No phase may weaken existing required checks to look green.

| Phase | Deliverable / owner decision | Proof before enabling | Risk and rollback |
| --- | --- | --- | --- |
| **0. Agree boundaries** | Reconcile companion Mac/Docker/reviewer conflicts; confirm merge-queue eligibility, cloudmac approval, token ownership, budgets and range/pool/storage/network ACLs. Record willow telemetry; retain bootstrap remote-accept until cutover. | Reviewed plan, named independent reviewer/policy, source/host trust decision and exact existing check inventory. | Incorrect permission/identity assumptions: keep existing hosted checks and manual director gates; register nothing. |
| **1. Hosted ARM + bus dry run** | Keep ARM host tier hosted; owner authorizes hosted native ARM oracle workflow. Implement parser/dedup/quota listener with **dispatch disabled**, then approve one helper host. No ARM KVM claim yet. | Unauthorized/malformed/stale/edited/duplicate requests rejected; API outage, restart, quota, result/label reconciliation demonstrated. Native oracle architecture/digests/logs preserved. | Prompt injection or duplicate spend: disable listeners, drain named agy workers, preserve ledger/evidence; resume explicit director dispatch. Remove oracle scheduling, preserve canonical cache. |
| **2. One willow pilot** | Approve pool, dedicated Debian template script, narrow token and 2-vCPU/4-GiB pilot; boot/JIT/reap controller. Limit to trusted lightweight jobs. | In/out-of-pool ACL denial, unique allocation, cancellation, stale registration, lost completion/controller crash, storage exhaustion and zero leaked job VMs. | Leak/ACL/resource error: freeze scaling, revoke token, drain/reap only ledger-owned pool clones; restore hosted Linux routing. Never touch legacy VMs. |
| **3. Capacity + BSD** | Owner drains/resizes 210 to 24 GiB/6 vCPU/CPU limit 4; approve FreeBSD 15/NetBSD 11 template scripts and proxy pairs. Activate normal/heavy budget only after recapture. | 20-job queue/resource measurements; nested KVM/bhyve/NVMM live proofs, exact exit propagation and pair cleanup; BSD aggregate policy reviewed separately. | Session OOM, nested failure, disk pressure: freeze/drain pool, restore owner-recorded 210 configuration after shutdown; keep failed BSD lane blocked and existing cross-checks, not a fake runtime pass. |
| **4. cloudmac JIT** | Explicit owner approval; implement supervisor, host lease/account cleanup and exact-SHA ARM fixture transfer replacing host Docker. Reconcile migration workflow before activation. | One complete merge group through fresh host/signed registrations, exact artifact identity, no skips, cancellation/cleanup and supervisor reboot tested. | Cleanup/isolation or provisioning failure: stop admission, quarantine/reset account if necessary, retain evidence; pause queue and use director-controlled exact-SHA remote acceptance. Never fall back to director-Mac runner registration. |
| **5. ARM KVM/BSD** | Approve a manual M4 Linux-nesting experiment; prefer permanent 32-GB ARM box if hosted KVM fails. Decide used Asahi alternative, cloudmac Linux-VM/Docker interpretation or capped Graviton experiment. | Device open + VM/vCPU execution + Carrick live tests without skips; native ARM oracle and ARM BSD boot/host tests separately evidenced; actual price quote before purchase/launch. | Unsupported EL2/pages, throttling, Spot loss or signed contention: remove capability label, export failure, destroy only owned overlays/instances; retain hosted ARM semantics/oracle and physical cloudmac signing. |

Open approvals: pool/range and exact PVE ACLs; VM 210 worker-session tradeoff;
cloudmac runner account and cleanup authority; signed fixture supply without host
Docker; collaborator/shared-account review policy; hosted oracle authorization;
ARM hardware/cloud spend; whether cloudmac Linux-VM Docker is allowed. Polling,
proxy BSD runners and the initial sizing are recommendations, not installed facts.

## Verification of this document

Markdown lint/render and link/structure checks validate the document. The director
waived acceptance gates for this docs-only change. Earlier CI/portable attempts
were stopped and cloudmac host acceptance was lock-blocked; the PR records these
limits without claiming acceptance receipts.
Those checks cannot qualify the proposed scaler, BSD nesting, ARM KVM, runner
isolation or merge queue. Signed/HVF and Docker oracle execution are not performed
on this Linux worker. No runner, infrastructure or GitHub setting is changed here.

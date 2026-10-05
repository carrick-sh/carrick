# Willow pilot evidence, 2026-10-04

**Live pilot passed.** [Run 37238869509, attempt 4](https://github.com/carrick-sh/carrick/actions/runs/37238869509/attempts/4)
completed successfully on a fresh VM 308. The controller destroyed the clone
through the scoped PVE token API. No clone or runner registration remains;
protected VM rows and PIDs match the pre-run census.

Draft implementation: [PR #18](https://github.com/carrick-sh/carrick/pull/18).
The run retained guest SHA `a482b71eed7c0954c098c6b18ced6914bea1198b`,
branch `work/willow-pilot`, event `workflow_dispatch`, and exactly the labels
`[self-hosted, Linux, X64, willow-kvm]`. Workflow, KVM/CPL0 sources, toolchain
and lockfile are unchanged by the subsequent controller fixes.

## Admission and artifact identity

The controller ran on Willow in the foreground over SSH from the Mac. The
PVE secret stayed in `/root/carrick-ci-token.json` and on-host memory/pipes.
No host service, kernel, sysfs or network configuration was changed.

Controller source: `e41955d5aaa7472d2c0c6f16606b4e3badc2f889`.
Deployed x86 Linux ELF SHA256:
`e665000e2d407224e448e182f54862374d7c050aaecf98e46af72f386b78dcda`.

Both samples admitted one additional 2-vCPU clone on 16 online CPUs, below
the director's stricter 80% ceiling:

| Sample | Five-second CPU utilization | One-minute load / CPUs | Projected | Available memory |
|---|---:|---:|---:|---:|
| Before reservation | 30.3% | 35.3% | 47.8% | 13,758,578,688 bytes |
| Before boot | 31.5% | 35.5% | 48.0% | 14,042,128,384 bytes |

Utilization came from `/proc/stat` deltas; load came from `/proc/loadavg`.
The larger load value limited admission in both samples; the projection
reserved another `2 / 16` of host capacity. Readiness completed within the
unchanged five-minute deadline, including non-root KVM API 12 qualification.

## Registration, exact job and uploaded logs

GitHub's completed job response and setup logs establish registration and
actual assignment:

- [Job `111584561977`](https://github.com/carrick-sh/carrick/actions/runs/37238869509/job/111584561977),
  name `kvm`, attempt 4, conclusion `success`.
- Runner ID `22`, group `1` / `Default`, name
  `carrick-ci-37238869509-4-111584561977-1791165191`.
- The durable ledger recorded both runner ID 22 and assigned job
  `111584561977`; the job-start hook logged
  `approved pilot workflow and SHA admitted` before checkout.
- The guest ran as UID/GID 1000 (`runner`), in group 992 (`kvm`), with
  `/dev/kvm` mode `0660`, nested `svm`, and `KVM_GET_API_VERSION=12`.
  Fresh machine ID: `fb4489f6eb6744b1939bd95570e2d734`.
- `cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none`
  succeeded, followed by
  `cargo test --locked -p carrick-vmm-kvm --test cpl0_entry -- --nocapture`:
  **2 passed, 0 failed, 0 ignored**. Both tests boot a real KVM carrier:
  `two_live_tasks_serve_robust_lists_without_host_forwards` and
  `entry_and_return_kicks_never_republish_or_recomplete`.

[Artifact `11321119501`](https://github.com/carrick-sh/carrick/actions/runs/37238869509/artifacts/11321119501),
name `willow-pilot-37238869509-4`, contains `capability.log`,
`image-build.log` and `cpl0-entry.log`. Upload completed at
`2026-10-05T01:55:29Z`. The downloaded 2,465-byte ZIP matched the GitHub API
digest:
`sha256:37a2d78245146897bffaad1aa8fc7ac7e6cf8c931c509ed66002e5f86fd6ece0`.
GitHub currently records expiry `2027-01-03T01:51:51Z`; this receipt preserves
the assertion results and digest beyond artifact retention.

The runner deregistered after its single job. The final GitHub runner census
was empty. A runner-list snapshot taken after completion was also empty;
registration evidence is the actual job's runner identity and durable ledger,
not a claimed live-busy listing.

## Teardown and VM census

The scoped token completed deletion:
`UPID:willow:00112B89:0E74D8BA:6AC303AC:qmdestroy:308:ci-scaler@pve!elastic:`.
The controller observed VM absence, removed owned transport key/public-key
and known-hosts files, fsynced ledger state `Destroyed`, and exited zero.
The ledger retained runner 22, assigned job `111584561977`, deletion task,
and `failure=null`. Runner output remains in the on-host evidence directory.
GitHub's independent job conclusion supplies the workflow success verdict.

`qm list` before attempt 4:

```text
VMID NAME                 STATUS     MEM(MB) BOOTDISK(GB) PID
105  win                  stopped    32768   200.00       0
106  winserver-oracle     running    8192    80.00        1079152
200  VM 200               stopped    32768   0.00         0
201  netbsd-nvmm          stopped    8192    40.00        0
202  omnios-bhyve         stopped    8192    40.00        0
203  openbsd-vmm          stopped    8192    40.00        0
210  carrick-x86-vm       running    40960   250.00       2340549
211  netbsd11-nvmm        stopped    8192    40.00        0
300  carrick-debian13-kvm stopped    4096    64.00        0
```

The running census had the same rows and only this additional clone:

```text
308 carrick-ci-37238869509-4-111584561977-1791165191 running 4096 64.00 1119248
```

`qm list` after teardown:

```text
VMID NAME                 STATUS     MEM(MB) BOOTDISK(GB) PID
105  win                  stopped    32768   200.00       0
106  winserver-oracle     running    8192    80.00        1079152
200  VM 200               stopped    32768   0.00         0
201  netbsd-nvmm          stopped    8192    40.00        0
202  omnios-bhyve         stopped    8192    40.00        0
203  openbsd-vmm          stopped    8192    40.00        0
210  carrick-x86-vm       running    40960   250.00       2340549
211  netbsd11-nvmm        stopped    8192    40.00        0
300  carrick-debian13-kvm stopped    4096    64.00        0
```

The raw censuses were compared: before equals after; running minus 308 equals
before. No protected VM changed status, configuration or PID.

## Qualified template and public preparation payload

VM 300 remains stopped, a template in `carrick-ci`: 2 vCPU, 4096 MiB, 64 GiB,
`cpu=host`, `local-lvm`, `vmbr0`. Non-root `runner` qualified nested SVM and
KVM API 12; Rust 1.96.0 and the unregistered official runner are installed.
No PVE/GitHub credentials were baked into the guest.

[Input manifest](willow-pilot-template-manifest.json) is the unchanged public
copy of `/root/carrick-ci/template-300/manifest.json`. The package inventory
remains beside that root-only manifest. Actual template script commit:
`09cb8d774c81e27bce05ce30e9f42805fb542d2e`.

The template was not rebuilt for attempts 3 or 4. Before JIT registration,
the current controller installs the exact public launcher and `.sh` hook
bytes embedded in its ELF through the scoped guest-agent API. Their source
files are shared with the builder. This records current bootstrap identity
in the controller artifact without rewriting the actual template's input
manifest or exposing JIT material to cloud-init.

## Earlier attempts and red-first fixes

All five historical clone rows remain `Destroyed`; none was erased or
manually released to bypass the budget. Every clone was VM 308, sequentially.

- Run `37236462599`, attempt 1, job `111536433121`: cached pool identity
  disagreed with live configuration; failed before registration. Delete:
  `UPID:willow:000AE19E:0E5F7D95:6AC2CD00:qmdestroy:308:ci-scaler@pve!elastic:`.
- Run `37238869509`, attempt 1, job `111543354578`: missing cached name, then
  PVE HTTP400 for raw `sshkeys`; failed before registration. Delete:
  `UPID:willow:000C3875:0E641007:6AC2D8B5:qmdestroy:308:ci-scaler@pve!elastic:`.
- Attempt 2 initially refused admission at busy 83.5%, projected 96.0%,
  without a reservation. In the owner-approved quiet window it admitted
  54.3% / 55.5%, then failed the unchanged readiness deadline. Cloud-init
  reported done, no errors and its exact deprecated PVE `user` warning
  (exit 2); the cleanup unit was inactive. No runner registered. The queued
  attempt was cancelled; the 15-minute reaper deleted its unassigned clone:
  `UPID:willow:00107F6F:0E72B4BB:6AC2FE31:qmdestroy:308:ci-scaler@pve!elastic:`.
- Attempt 3 admitted 73.8% / 72.4%, registered runner 21 and assigned job
  `111581597117`. The official runner rejected the extensionless job hook
  before workflow steps, so no artifact existed. Delete:
  `UPID:willow:0010A9B5:0E7340AD:6AC2FF98:qmdestroy:308:ci-scaler@pve!elastic:`.

Exact provider response fixtures proved URL-encoded sshkeys red-first.
Guaranteed-rejected `cores=0` API validation proved corrected fields without
mutating template 300. New red-first regressions require completed cloud-init
with only that observed warning, a supported `.sh` hook extension, and exact
literal public script installation. Cleanup is explicitly activated by the
controller. Other warnings/errors still fail closed; readiness/reap deadlines,
budget, approved guest SHA and concurrency remain unchanged.

## Verification and limits

Scoped xtask tests, clippy with `-D warnings`, and `just fmt-check` passed
on controller source `e41955d5a`. Full `just ci` reached rustdoc and failed
on inherited unchanged MMU, signal and EL1 ABI documentation; the director
authorized publication with this red and assigned repair to PR #3. This
successful pilot does not claim full-CI acceptance or adversarial isolation.
Apt versions are recorded rather than snapshot-pinned. Policy mocks and wire
fixtures cover critical guards, not every production API lifecycle.

Raw logs, API metadata, downloaded artifact, source hashes and before/during/
after censuses are under `/tmp/willow-pilot-evidence/quiet-window/` on the Mac;
the on-host ledger is `/root/carrick-ci/state/ledger.json`. These receipts
contain no credentials. The controller is stopped after this one-job proof.

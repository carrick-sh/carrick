# Willow pilot evidence, 2026-10-04

**Live job proof is incomplete.** The director instructed the controller to
remain stopped until Willow's existing workers and gates are quiet. No job
has executed, so this receipt confers neither workload nor landing acceptance.

Draft implementation: [PR #18](https://github.com/carrick-sh/carrick/pull/18).
Queued pilot: [run 37238869509, attempt 2](https://github.com/carrick-sh/carrick/actions/runs/37238869509/attempts/2),
job `111553512377`, guest SHA `a482b71eed7c0954c098c6b18ced6914bea1198b`.
Guest workflow/KVM sources are unchanged by subsequent controller fixes.

## Qualified template

VM 300 is stopped, a template in `carrick-ci`: 2 vCPU, 4096 MiB, 64 GiB,
`cpu=host`, `local-lvm`, `vmbr0`. Non-root `runner` qualified nested SVM and
`KVM_GET_API_VERSION=12`; Rust 1.96.0 and the unregistered official runner
are installed. No PVE/GitHub credentials were baked into the guest.

[Input manifest](willow-pilot-template-manifest.json) is the public copy of
`/root/carrick-ci/template-300/manifest.json`. The package inventory remains
beside that root-only manifest. Script commit:
`09cb8d774c81e27bce05ce30e9f42805fb542d2e`.

## Attempts and cleanup

Two earlier clones of VM 308 failed before boot or JIT registration. The
controller destroyed both via the scoped token; their ledger rows remain
`Destroyed`, `runner=null`, `assigned=null`, preserving failure history.

- Run `37236462599`, attempt 1, job `111536433121`: live configuration identity
  was incorrectly compared with cached pool identity. Deletion receipt:
  `UPID:willow:000AE19E:0E5F7D95:6AC2CD00:qmdestroy:308:ci-scaler@pve!elastic:`.
- Run `37238869509`, attempt 1, job `111543354578`: missing cached name, then
  PVE HTTP400 for raw `sshkeys` on resumption. Deletion receipt:
  `UPID:willow:000C3875:0E641007:6AC2D8B5:qmdestroy:308:ci-scaler@pve!elastic:`.

PVE requires URL-encoded `sshkeys` even inside JSON. The exact HTTP400 fixture
failed red before the fix. Scoped-token validation with deliberately invalid
`cores=0` guaranteed rejection before mutation; encoding removed the sshkeys
error, leaving only the expected minimum-cores error. All other config fields
passed the provider's validation.

Attempt 2 used controller commit `5aa5bf6face8d983927b26fa298918e504efad4c`,
Linux ELF SHA256
`5ffcc06e80a7de0791ebeb31f44b83c59294fd8de2f89aa4a2e551790e7767a2`.
It stopped **before ledger reservation or cloning** at busy 83.5%, projected
96.0%, exceeding the director's 80% ceiling. That older log did not distinguish
five-second utilization from one-minute load; the admission log now prints
both `/proc` sources, online CPU count and the limiting source. That new log
has not been live exercised because the director instructed no restart.

## VM census

The original and final `qm list` rows for protected machines are identical:

| VMID | Name | Status | MiB | Disk GiB | PID |
|---|---|---|---:|---:|---:|
| 105 | win | stopped | 32768 | 200 | 0 |
| 106 | winserver-oracle | running | 8192 | 80 | 1079152 |
| 200 | VM 200 | stopped | 32768 | 0 | 0 |
| 201 | netbsd-nvmm | stopped | 8192 | 40 | 0 |
| 202 | omnios-bhyve | stopped | 8192 | 40 | 0 |
| 203 | openbsd-vmm | stopped | 8192 | 40 | 0 |
| 210 | carrick-x86-vm | running | 40960 | 250 | 2340549 |
| 211 | netbsd11-nvmm | stopped | 8192 | 40 | 0 |

The final census adds only stopped template 300 (`4096 MiB`, `64 GiB`, PID0).
No clone or GitHub runner registration remains.

## Verification and resumption

Scoped xtask tests, clippy with `-D warnings`, and `just fmt-check` passed.
Full `just ci` reached rustdoc and failed on inherited unchanged MMU, signal
and EL1 ABI documentation; the director authorized publication with this red
and assigned the repair to PR #3. Local raw receipts and logs are under
`/tmp/willow-pilot-evidence/`; the on-host ledger is
`/root/carrick-ci/state/ledger.json`. These contain no credentials.

After the director approves a quiet window, resume the queued attempt with
its exact guest SHA using the foreground command in [the runbook](willow-pilot.md).
Preserve both failed ledger rows. Capture running clone identity, job logs,
actual assignment and successful API deletion before marking this pilot done.

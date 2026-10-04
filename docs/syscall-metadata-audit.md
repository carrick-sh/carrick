# Syscall support metadata audit (2026-10-04)

Source inspected: `b1167c6e1`, before this metadata correction. This is a
code/coverage audit, not fresh guest acceptance. No Docker or signed HVF run
was performed on the Linux worker. Existing LTP baseline MATCH rows that
contain TBROK/TCONF are not evidence of successful syscall execution.

`SupportLevel` is reporting metadata, not a dispatch gate. The explicit task
constraint is to leave partially implemented calls at their existing level.
`BringUp` elsewhere can include partial support; this audit does not equate it
with ABI completeness. The handwritten emulation map is not generated.

## Verified changes

- `sched_get_priority_max` (125), `sched_get_priority_min` (126):
  `dispatch/proc.rs` routes both to `sched_priority_for`, which returns 99/1
  for FIFO/RR, 0/0 for OTHER/BATCH/IDLE/DEADLINE and EINVAL for unknown policies.
  `conformance-probes/src/bin/schedparam.rs` exercises OTHER, FIFO and RR.
  These queries do not need a real-time scheduler implementation. Promote
  Deferred → BringUp and name their Process metadata owner.
- `rseq` (293): `dispatch/proc.rs::rseq` unconditionally returns ENOSYS.
  `crates/carrick-kernel/tests/integration/syscall_creds.rs::rseq_reports_clean_bootstrap_fallback`
  explicitly asserts errno 38. Demote BringUp → Deferred; keep its Process
  owner because its refusal is dispatched.

## Requested calls: partial, levels unchanged

- `execveat` (281): `dispatch/proc.rs` routes `EXECVEAT => execveat`.
  The handler validates flags, resolves path/dirfd, supports AT_EMPTY_PATH,
  and emits Execve with argv/env. `fexecveprobe.rs` exercises self-fd and
  image-layer `/bin/sh` after chdir; `procexeidentity.rs` exercises retained
  `/proc/self/exe` via execveat. However,
  `dispatch/fd_table.rs::OpenDescription::retained_exec_source` only retains
  ProcExecutable sources. Ordinary File/HostFile fds recover their recorded
  path, so unlink/replacement loses the opened executable's inode identity.
  Keep Planned, correct the false ENOSYS note and name the Lifecycle owner.
- `clone3` (435): `dispatch/proc.rs` routes `CLONE3 => sys_clone3 => clone3`.
  Sizes, flags, stack pairs and exit signals are validated; supported calls
  emit Fork/CloneThread, including pidfd and tid-pointer outcomes.
  `dispatch/tests.rs::clone3_preserves_parent_and_tid_pointer_semantics_for_fork_path`
  checks parent and tid pointers. Existing `clone3args.rs`,
  `lifecycleflagmatrix.rs`, `clone3pidfdsig.rs`, `clone3signalflight.rs`, and
  `clone3exithandled.rs` cover validation/lifecycle paths (some explicitly
  accept oracle ENOSYS). The decoded set_tid, set_tid_size and cgroup fields
  are ignored, and namespace creation is restricted. Keep Planned and make
  the missing semantics explicit in the note.

Probe paths above are relative to `conformance-probes/src/bin/`; dispatch
paths are relative to `crates/carrick-kernel/src/`.

## Complete dispatch census

The census compared every canonical table row with all `syscall_table!` and
`mutation_syscall_table!` arms, and checked that `dispatch/routing.rs` chains
all declaring modules. **All 246 original BringUp rows have an arm.** This
proves routing membership, not semantic completeness. The unconditional
ENOSYS `rseq` body is the verified overstatement; `userfaultfd` (282) also
has no emulation but deliberately models container-policy EPERM/ENOSYS,
explicitly documented by its existing compat note, so it is retained.

The two Planned-but-dispatched rows are listed above. All 25 original
Deferred-but-dispatched rows follow; none lacks a dispatch arm. Retained
rows need further semantic work or verification before promotion under the
task's constraint. An explicit ENOSYS handler is consistent with Deferred.

| Canonical numbers / names | Dispatch evidence | Decision / limitation |
|---|---|---|
| 51 `chroot` | `fs.rs` → `fs/mount.rs::chroot`; `fs/tests.rs::chroot_rebases_absolute_resolution` | Retain; capability admission uses root euid rather than CAP_SYS_CHROOT. |
| 84 `sync_file_range` | `fs.rs::sync_file_range`; `syncfilerange.rs` probe | Retain; whole-file best-effort flush, host errors discarded, no range flush semantics. |
| 100 `get_robust_list` | `proc.rs::get_robust_list`; `robustlist.rs` probe | Retain; every existing peer returns EPERM, no authorized peer robust-list read. |
| 107–111 `timer_create`, `timer_gettime`, `timer_getoverrun`, `timer_settime`, `timer_delete` | `time.rs` timer handlers; `posixtimers.rs` probe | Retain; limited timer notifications and clock model, not full POSIX timer behavior. |
| 118–121 `sched_setparam`, `sched_setscheduler`, `sched_getscheduler`, `sched_getparam` | `proc.rs` scheduling handlers; `schedparam.rs`, `schedprio.rs` probes | Retain; SCHED_OTHER / priority-zero model, no arbitrary scheduling policy updates. |
| 125–126 `sched_get_priority_max`, `sched_get_priority_min` | `proc.rs::sched_priority_for`; `schedparam.rs` | Promote as above; policy range queries are implemented independently of scheduling. |
| 127 `sched_rr_get_interval` | `proc.rs::sched_rr_get_interval`; `schedparam.rs` | Retain; fixed SCHED_OTHER slice, no real-time policy-dependent quantum. |
| 163 `getrlimit` | `time.rs::getrlimit`; `rlimitresource.rs`, `rlimitroundtrip.rs` | Retain; NULL destination currently succeeds instead of EFAULT. |
| 234 `remap_file_pages` | `mem.rs` → `mem/mmap.rs::remap_file_pages`; `sysv.rs::remap_file_pages_observes_removed_attached_generation` | Retain; snapshot copying / SysV bookkeeping, not general nonlinear shared remapping. |
| 240 `rt_tgsigqueueinfo` | `signal.rs::rt_tgsigqueueinfo`; `m5_peer_rt_tgsigqueueinfo_targets_root_group`, `tgsigqueue.rs`, `sigwaitmatrix.rs` | Retain; delivery is implemented, but pending-signal quota is per-process rather than per-user (`sigpending_limit_exceeded`). |
| 275 `sched_getattr` | `proc.rs::sched_getattr`; `schedgetattr.rs` | Retain; returns constant SCHED_OTHER/nice-zero attributes. |
| 286–287 `preadv2`, `pwritev2` | `fs.rs` → `fs/rw.rs::preadv`, `pwritev` | Retain; RWF flags partly advisory, NOWAIT refused, full flag semantics not verified. |
| 427 `io_uring_register` | `mem.rs` → `mem/madvise.rs::io_uring_register` | Consistent; unconditional ENOSYS. |
| 441 `epoll_pwait2` | `net.rs` → `net/epoll_ops.rs::epoll_pwait2` | Retain; timespec nanoseconds truncate to milliseconds, positive sub-ms waits become nonblocking. |
| 449 `futex_waitv` | `proc.rs` → `futex.rs::dispatch_futex_waitv_args` | Retain; parks only on the last vector entry, not any member. |
| 451 `cachestat` | `fs.rs::cachestat` | Retain; fabricates all in-file pages as cached, with zero dirty/writeback/eviction counts. |

## x86_64 and derived artifacts

`crates/carrick-abi/src/syscall_x86_64.rs` has no independent support levels.
It directly maps execveat 322 → 281, clone3 435 → 435, priority queries
146/147 → 125/126, and rseq 334 → 293. Its compile-time canonical-name guard
checks these mappings. `carrick-hal/src/x8664_arch.rs::clone3_is_not_swapped`
checks clone3's struct-based argument routing. No x86 table edit is needed.

Regenerate `conformance-contracts/inventory.json` with `just inventory` and
`docs/support-matrix.md` with `just matrix`; the latter is derived from the
unchanged baseline and may produce no diff. Update the handwritten emulation
map and AGENTS counts to **247 BringUp, 89 Deferred, 2 Planned** (338 entries).
Remove the comment-only `SupportLevel::Deferred` match so the requested grep
counts count rows accurately.

Contract exemption: changes to `crates/carrick-abi/src/syscall.rs`,
`crates/carrick-kernel/tests/integration/syscall_table.rs`,
`conformance-contracts/inventory.json`, `AGENTS.md`, and these two documentation
files alter reporting only relative to `b1167c6e1`. Process/lifecycle/scheduling
execution and work budgets are unchanged: neither resolver nor handlers consult
SupportLevel or handler_for_aarch64 for execution routing. Existing metadata
assertions are updated to match the inspected handlers. Existing probes and
kernel tests establish the inspected paths; fresh guest conformance remains
outside this Linux worker's evidence.

Red-first metadata verification: the updated `syscall_table` integration tests
fail against `b1167c6e1` metadata (Deferred instead of BringUp for the priority
query; Unimplemented instead of Lifecycle for execveat). All seven pass with
the corrected table. The existing `rseq_reports_clean_bootstrap_fallback`
integration test also passes, independently confirming errno 38.

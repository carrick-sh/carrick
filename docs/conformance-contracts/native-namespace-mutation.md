# Native namespace mutations (#1335, #1933)

## Round 3: chmod and chown (#231)

apt warned `chown ... (38)` and `chmod 0755 ... (38)`. Linux authority:
chmod(2) and chown(2). Four wire operations (24-27) extend the record:
`Fchmod` and `Fchown` of a host-backed descriptor, `Fchmodat` and
`Fchownat` of a staged path. All four lead their input with the caller's
access context: only the owner or a privileged caller may change a mode,
and only a privileged caller may give a file away, so the credentials that
decide EPERM are the caller's own (its ring task row), never the carrier's.
chown(2)'s owner rule, in the shared `chown_permission_errno`: an
unprivileged caller acts only on a file it owns (as stat reports the
owner), may leave the uid as it is (-1 or its own uid) and may set the group
to its fsgid or a supplementary group; any other explicit id is EPERM, and
-1/-1 is never refused (#2406 review P0-1).

- `fchmod`/`fchown` follow the descriptor, as `ftruncate` does: a ring
  file's call is staged for the run root too (a delegated stdio stream keeps
  its host route). The ring answers EBADF for a closed descriptor and for an
  O_PATH one; an in-zone object keeps its route.
- `fchmodat`/`fchmodat2`/`fchownat` are the descendant's mutation venue; the
  run root keeps its host-task route. `fchmodat` ignores its fourth register
  as Linux does; `fchmodat2` and `fchownat` refuse unknown flags with EINVAL.
  `fchownat(fd, "", AT_EMPTY_PATH)` is the descriptor's own chown.
- x86 legacy `chmod` (90), `chown` (92) and `lchown` (94) normalize to the
  `*at` forms in one place (`normalize_legacy_attr`), used by the ring entry,
  the HAL host route and the root's forward classifier. The crossing
  allowlist is unchanged: they cross as the existing `fchmodat`/`fchownat`.
- The carrier serves them through the host task's own cores, moved out of
  the syscall wrappers (`chmod_description`, `chown_description`,
  `chmod_path`, `chown_path`). Watched and synthetic paths refuse before
  effects, as round 2's mutations do.

Witnesses, red first on #2401's head: `native_file_attr.S` (50 steps)
against the native oracle on the production x86 KVM path, root and fork
child, including the legacy calls' ENOENT, ENOTDIR, EFAULT, ENAMETOOLONG,
EACCES and EPERM, and lchown changing a link where chown follows it;
`arm_fork_child_chmod_chown_on_ring_files` and
`arm_fork_child_owner_chown_keeps_its_own_ids` on the production ARM
dispatch; a carrier matrix with root and unprivileged callers.

Boundary: a run root's filesystem calls are served under its host task's
credentials, which its ring `setresuid` does not reach, so the root's EPERM
after dropping privilege is not compared (#1861 owns root resource authority
transfer). Record locks and `flock` on ring files are a separate mechanism.

## Round 2: shared mutation cores

Native descendants now stage mkdirat, unlinkat/rmdir, symlinkat, linkat,
renameat/renameat2, utimensat, truncate and ftruncate through the existing
host-file venue. Initial tasks retain their existing host-task syscall route.
Both routes reuse the same path or description core; native calls carry their
own stamped filesystem authority and never manufacture a PID-1 `SyscallCtx`.
The crossing allowlist and round-1 redirected-Write admission are unchanged.

The nearest existing authorities are `NativeFsAuthority`/`with_native_fs_scope`,
the root filesystem's namespace transaction and the HostIpc physical-description
hold. They are reused; this round adds no lock, lifetime owner or name index.
Wire operations 13-21 extend the existing record without changing its header or
older operation values. Paired names are NUL-delimited; timestamp records retain
explicit times, NOW/OMIT, NULL pathname and NULL-times distinctions. The latter
uses one container-clock sample for both times. Truncation records retain signed
length and stamp the exact caller's file-size limit through the existing helper.

Each family has a committed, compiled red-first witness (`-38`, required `0`)
followed by a passing public-venue witness. These tests perform real ring fork,
shared production staging and carrier serving; the native scope guard rejects
host-file-table escapes. They check names, contents, inode identity, exact times,
caller umask, inherited physical descriptions after parent host close and errno
matrices. The 48-test venue suite also checks preserved Write/listing behavior,
zero effects for watched mutations and finite/unstamped truncation limits, and
composed filesystem sequences. It does not execute a shell or ELF, or prove the
whole service-notice/cancellation lifecycle.

At path lengths 1 and 4095, aligned and mixed-alignment paired-path staging has
at most four page-bounded copies, 8192 copied bytes, 8191 encoded input bytes
and no output preparation. This is a deterministic staging budget, not a
versioned signed WorkObservation or a bound for the whole VFS algorithm.

### Deliberate boundaries

Native rename serves cheaply proven physical Host-rootfs regular files and
symlinks, including same-inode no-op and supported exchange behavior. The director
approved refusing directory, Memory and mount-local publication rather than
silently skipping `rename_open_paths` or native `TaskFs` updates. Those cases
need a shared named-description index and filesystem-context publication follow-up.

Watched and task-relative synthetic mutations refuse before effects. Existing
host-backed relative dirfds remain refused; absent and in-zone relative dirfds
retain EBADF/ENOTDIR. Truncation with finite or unstamped RLIMIT_FSIZE remains
refused rather than approximating per-task SIGXFSZ/EFBIG. Memory path truncate
retains EROFS; descriptor resize retains access, seals and sparse-data behavior.
Rootfs timestamp failures deliberately retain the root wrapper's best-effort
success (mount failures still propagate); this inherited Linux divergence needs
separate follow-up. Readlink belongs to #1900; fchmodat is served by round 3.
CPL0's existing staging-Fault refusal rather than supply/retry is also unchanged.

The director still owns signed artifact identity, Mac execution, full mutation
service settlement, native ARM Docker comparison and paired runtime ratios.
Expected restored Mac cases are mkdir (05/14), hardlink (08), truncate (10),
touch/listing (16), regular physical rename (17) and mkdir/rmdir (21); redirected
and append Write (12/20) must stay preserved. Case 07 additionally needs #1900,
09 still needs fchmodat, and actual `cp` metadata behavior in 19 is unproved.
These are predictions, not signed acceptance.

## Slice 1: retained no-IPC defect census

The following historical evidence describes a fixture without an installed
guest IPC venue. Its refusal expectations remain a diagnostic negative control,
not the shipping round-2 mutation behavior.

`kernel.native.namespace-mutation` binds the missing typed namespace service
before any behavior change. Linux owns the semantics; a forward allowlist
entry supplies neither child authority nor a host task.

The production ARM native entry fixture admits a root, forks live children
through real stock reservation/publication, and dispatches six ordinals from
both children. They retain distinct fork-time cwd, umask and file tables.
Each call must complete with errno 38, increment served/refused exactly once,
and publish no carrier service notice. This is a defect census, not a claim
that ENOSYS is correct Linux behavior. The existing unclaimed-call negative
control remains unchanged.

Shared boundaries retain their own contracts:
`process.native.arm-admission` owns admission and exact task binding;
`kernel.el1.thread-lifecycle` owns [fork-child admission](native-fork-child-admission.md);
`kernel.native.host-file-venue` owns existing typed file calls;
`kernel.fs.directory-copyout` owns getdents64 cursor and copyout authority.
The new contract does not weaken any of their budgets.

The fixture calls native syscall dispatch and the shipping unclaimed-capture
policy separately. It does not install a simulated guest IPC venue or host
reply. Slice 2 needs a typed capture/venue binding in this harness before a
successful namespace operation can be proved; changing an expected result to
zero alone cannot provide that binding.

The director's signed reference reports six missing calls (mkdirat, unlinkat,
renameat, symlinkat, readlinkat, fchmodat), with statx, getdents64, openat
O_CREAT and write working. VM-free routing alone cannot repeat those host
venue results. The existing successful child exec, adoption, exit, reap and
slot-reuse fixture now dispatches the same six calls after adoption, retaining one counted refusal
and no carrier notice per call. Its process context is the shared VM-free x86
owner with an ARM syscall frame; it does not execute an ELF or install ARM
hardware page tables. Signed population/venue attribution,
image/artifact identity and original CLI regression remain open evidence.

Slice 2 must settle wire layout review, both ISA bindings, VFS mutation
ownership and cross-crate lock order before changing routing. Its first
witness must require successful mkdirat here and fail on this baseline;
then prove caller umask/dirfd, directory identity and parent visibility,
EEXIST/EFAULT and both filesystem venues. No raw syscall fallback or carrier
ambient credentials are licensed. Cancellation after a committed mutation
must settle once without replay. Budgets for staging and resolution must be
chosen from the existing owner algorithm, before measuring a candidate.

The measured VM-free baseline is two attempts, two completions and two ring
refusals per ordinal in the two-child fixture; the exec successor adds one
attempt, completion and ring refusal per ordinal. Both require zero carrier
notices. This covers 18 completed calls, not a signed workload population.
No mutation, carrier venue success or runtime ratio was measured.

Red-first semantic check: temporarily requiring mkdirat success in the same
production-entry fixture fails at child 0, ordinal 34: actual -38, required 0.
The committed assertion restores the explicit defect baseline. This red result
is not a CLI witness and does not replace slice 4's process-boundary check.

The lineage assertion was separately red: the two-child fixture recorded two
total ring refusals but zero descendant refusals. Final unclaimed-child
capture now uses `Counters::record_refusal` with descendant origin and ring
venue. Both fixtures require all refusals in that descendant population and
zero carrier refusals. The existing unclaimed-ordinal negative control keeps
its errno and total count and now checks the lineage too. This diagnostic
correction changes neither routing nor the six missing namespace services.

Refusal accounting excludes service contention. The shared
`diagnostics.syscall-refusal` contract also retains the host-request-during-park
witnesses: a concurrent host request yields and then reparks the same operation,
without a quarantine fatal or a second service notice. Those witnesses and the
namespace refusal bindings are complementary; neither replaces the other when
rebasing this slice.

### Legacy x86 entry (#2221)

The static CPL0 fixture runs raw x86 namespace syscalls as the initial task
and as a fork child. It checks results against the same fixture on x86 Docker
Linux and requires zero refused calls. The Linux path semantics are documented
in mkdir(2), rmdir(2), unlink(2), rename(2), link(2), symlink(2) and readlink(2).
The entry lowering only reshapes a fixed set of register operands. Each legacy
operation reaches the same owner and has the same dispatch and mutation
budget as its canonical form.

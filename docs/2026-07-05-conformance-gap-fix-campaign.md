# Conformance gap-fix campaign — 2026-07-05

From the honest-conformance audit (docs/2026-07-05-honest-conformance-audit.md). Root-cause triage of the exposed backlog.

## Tally

123 exposed gaps total: 90 REAL-CARRICK-GAPs (fix targets), 14 ORACLE-SIDE (oracle also fails or carrick is more correct — NOT our bug), 18 KNOWN-UNIMPL-REPORTONLY (16 keyring add_key/keyctl/request_key + 2 pidfd_getfd — already honest-ENOSYS+report-only, excluded), 1 FLAKY-PERF (epoll_wait02 tst_timer 'slept too long' under HVF). Per-cluster real-gap counts: fs-meta-io 22, socket 15, misc 9, ns-cred-proc 7, mem 6, signal-timer 6, splice-pipe 6, epoll-poll 5, wait-reap 5, exec-fork 4, process_vm 4, xattr 1. Of the 90 real gaps, ~44 collapse into 19 shared-cause fixes; the rest are single-suite. ~9 real gaps are large/architectural (ptrace11, tgkill02, fork14, lseek11, setsockopt02/AF_PACKET, sendto02/SCTP, chroot re-root, process_vm01 transfer) and are low-ROI relative to the quick wins.

## Shared-cause quick wins (one fix closes many)

- **[small] closes 4** (waitid05, waitpid11, waitpid12, waitpid13): In wait4 (proc.rs:2316-2323) translate pid<-1 via ns_to_host_pgid(->-host_pgid, None=>ECHILD); in waitid P_PGID branch (proc.rs:2166) translate id via ns_to_host_pgid. Leave pid==0/-1 untouched. Mirrors existing kill(-pgid) callers.
- **[small] closes 4** (preadv202, preadv202_64, pwritev202, pwritev202_64): Add a preadv2/pwritev2 path that parses RWF_*: unknown bits->EINVAL, RWF_NOWAIT on a regular buffered host file->EOPNOTSUPP. One handler closes all four.
- **[medium] closes 3** (epoll_pwait01, epoll_pwait02, epoll_pwait03): Factor the epoll_pwait wait core (multiplexer drain + WaitOnFds park) into a helper (timeout_ms,sig_mask,block_signals,max_events) and call it from epoll_pwait2 after its existing *timespec->ms decode.
- **[medium] closes 3** (truncate03, truncate03_64, link04): Add a shared may_write(dir/file) helper wired into truncate and linkat; also stat linkat's new-path parent (missing->ENOENT, non-dir->ENOTDIR). Note: truncate03's EROFS/ELOOP subtests are LTP RO-loopback-mount artifacts unfixable under --fs host — expect to close only the EACCES cases.
- **[small] closes 2** (recvmmsg01, sendmmsg02): Propagate the DispatchError's real errno (route through the same path standalone recvmsg/sendmsg use) instead of forcing EFAULT for the first entry. Near-trivial.
- **[small] closes 2** (capset02, capset03): After reading (eff,prm,inh) reject EPERM if a new pI bit is not in (bounding|old_inheritable); with the CAP_SETPCAP branch: lacking CAP_SETPCAP reject pI not in (old_permitted|old_inheritable). CapabilitySet already carries .bounding/.inheritable.
- **[small] closes 2** (pwrite04, pwrite04_64): If description.append is set, ignore the offset and write at EOF (macOS pwrite on O_APPEND returns EINVAL, so lseek(END)+write or plain write).
- **[small] closes 2** (getsockopt01, setsockopt01): Return EOPNOTSUPP for unknown level and map host EINVAL/ENOPROTOOPT for unsupported optnames to EOPNOTSUPP; replace the ignored write_bytes with write_sockopt_value so EFAULT surfaces.
- **[small] closes 2** (madvise02, madvise05): Derive range validity from this.mem.dynamic_maps VMA metadata; WILLNEED returns 0 for any in-VMA range; DONTNEED-on-locked/disallowed-shared returns EINVAL from metadata; never physically probe a page to validate.
- **[small] closes 2** (sendfile09, sendfile09_64): Report the real backing free space (f_bavail from the underlying macOS volume) for the overlay tmpdir in statfs/statvfs, then re-check large-file sendfile.
- **[medium] closes 2** (socket01, socketpair01): Validate (domain,type,protocol) against a small Linux-canonical table before/around host_socket_install/libc::socketpair: unknown type->EINVAL; unsupported/mismatched protocol and raw-needs-root->EPROTONOSUPPORT.
- **[medium] closes 2** (lstat02, lstat02_64): Track and consult the guest supplementary group set when choosing owner/group/other in check_search_access.
- **[medium] closes 2** (sched_setparam05, sched_setaffinity01): A single guest-process-table-backed resolver: an ns-pid naming no carrick-tracked task->ESRCH; a live OtherGuest under euid!=0->EPERM. Stop probing arbitrary host pids with libc::kill.
- **[medium] closes 2** (fcntl36, fcntl36_64): Do not issue a blocking host F_OFD_SETLKW on the dispatch thread; poll with non-blocking F_OFD_SETLK in a retry/park loop, or model OFD-lock conflict/wait in carrick's own record-lock table.
- **[medium] closes 2** (splice07, splice08): Add an is_char_device_pipe distinction so a char-device HostPipe never counts as a genuine pipe end, and synthesize zeros on demand for the char-device read side (generate min(count,room) zeros directly rather than draining a finite backing).
- **[medium] closes 2** (splice07, splice03): One validation pass in splice: classify each fd as genuine-guest-pipe, require exactly one pipe end else EINVAL BEFORE any read; reject non-readable/O_PATH fd_in with EBADF; map socket-source recv errors to EINVAL/EBADF.
- **[medium] closes 2** (execve03, execveat02): Refactor read_exec_file/resolve to return Result<Vec<u8>,LinuxErrno> propagating ENOENT/ENOTDIR/EACCES/ENAMETOOLONG/ELOOP; add mode&0o111->EACCES and PATH_MAX->ENAMETOOLONG gates; map ELF-parse Err->ENOEXEC. (execveat02 also needs its own AT_SYMLINK_NOFOLLOW handling — listed as a single gap.)
- **[medium] closes 4** (process_vm01, process_vm_readv02, process_vm_readv03, process_vm_writev02): Add a proc.rs handler claiming 270+271: validate flags==0/iov/pid (EINVAL/EFAULT/ESRCH/EPERM) then cross-process guest-VA translate-and-copy iovec-by-iovec. Error-path suites (readv02/03,writev02) fall out of correct arg validation (medium); process_vm01 needs the real cross-VM transfer (large).
- **[large] closes 2** (chroot02, chroot04): Record a per-process chroot root honored in resolve_at_path (absolute paths resolve under it) and add a search(x)-permission DAC check during chroot path resolution (EACCES) ordered before the CAP_SYS_CHROOT check.

## Batch order

### Batch 1 — Quick-win errno/flag/pgid corrections (trivial+small shared causes, max leverage) (17 suites)
`waitid05, waitpid11, waitpid12, waitpid13, preadv202, preadv202_64, pwritev202, pwritev202_64, recvmmsg01, sendmmsg02, pwrite04, pwrite04_64, capset02, capset03, readlink03, timerfd_settime02, setgroups03`
17 suites closed by 7 small/trivial, mostly-isolated fixes: pgid-wait-translation (4), preadv2/pwritev2 RWF flag (4), mmsg first-entry EBADF (2), pwrite O_APPEND (2), capset pI validation (2), plus 3 one-liners (readlink ENOENT, timerfd flag mask, setgroups EPERM). Highest suites-per-effort of the whole plan; each touches a single handler with existing infra.

### Batch 2 — Socket errno/EFAULT canonicalization (net.rs) (5 suites)
`socket01, socketpair01, getsockopt01, setsockopt01, recvmsg01`
Coherent net.rs unit: a shared Linux-canonical (domain,type,protocol) errno table for socket/socketpair (2), an EOPNOTSUPP+EFAULT translation pass for get/setsockopt (2), and the MSG_ERRQUEUE->EAGAIN one-liner (1). All small, same file, same 'map macOS errno to Linux-canonical' theme.

### Batch 3 — fs flag/errno + missing-handler quick wins (fs.rs/sysv.rs) (7 suites)
`open02, open11, fchdir03, readahead01, shmat03, memfd_create04, membarrier01`
Small self-contained corrections across the memory/fs syscall surface: O_NOATIME EPERM, O_CREAT-on-dir EISDIR, fchdir search-perm, readahead no-op handler, shmat mmap_min_addr floor, MFD_HUGE bit acceptance, membarrier real supported-mask. Each is a localized guard/handler add.

### Batch 4 — DAC permission wiring into path mutators (fs.rs) (6 suites)
`truncate03, truncate03_64, link04, lstat02, lstat02_64, setxattr02`
One coherent DAC-enforcement pass: a shared may_write() helper into truncate+linkat (3, plus linkat parent existence), supplementary-group class in check_search_access (2), and user.* file-type EPERM in setxattr (1). All reuse the existing check_search_access/dac_open_check/xattr-owner infrastructure — missing wiring, not greenfield.

### Batch 5 — epoll_pwait2 + poll validation (net.rs) (5 suites)
`epoll_pwait01, epoll_pwait02, epoll_pwait03, ppoll01, select03`
Delegating epoll_pwait2 to the real epoll_pwait wait core closes 3 suites; ppoll01 (POLLPRI mask + nfds guard) and select03 (PROT_NONE enforcement in pselect6) are the same poll/wait subsystem. select03's broad-scope mprotect enforcement also helps other tst_get_bad_addr cases.

### Batch 6 — sched/cred guest-pid model + proc metadata (proc.rs/creds.rs/vfs) (4 suites)
`sched_setparam05, sched_setaffinity01, setpriority02, getpgid01`
A single guest-process-table-backed pid resolver fixes both sched_* suites (over- and under-inclusive resolution); setpriority02 (which-class EACCES + target ownership EPERM) and getpgid01 (/proc comm sanitize) round out the process-identity theme.

### Batch 7 — Memory-mapping fidelity (mem.rs + fcntl sealing) (4 suites)
`madvise02, madvise05, mincore03, memfd_create01`
madvise VMA-based validation (2, stop probing pages -> no SIGBUS/false-ENOMEM), mincore lazy-residency wiring (1), and file-sealing F_ADD/GET_SEALS which unblocks a 157-subtest suite (1). Coherent VMA/mapping-metadata unit.

### Batch 8 — splice/pipe subsystem (fs.rs/fd_table.rs) (6 suites)
`splice07, splice08, splice03, tee01, pipe12, pipe15`
Two shared causes: char-device-vs-genuine-pipe distinction for /dev/zero (splice07/08) and splice fd validation (splice07/03). tee01 (userspace tee), pipe12 (capacity/host-buffer reconcile) and pipe15 (pipe-user-pages sysctl) share the pipe backing model. One reviewer holding the whole pipe/splice mental model.

### Batch 9 — signal/timer completeness (signal.rs/time.rs/timer-core) (5 suites)
`alarm07, tgkill03, timer_settime03, timer_delete01, tgkill02`
fork-child timer reset (alarm07), tgkill tgid-membership ESRCH (tgkill03), overrun saturation (timer_settime03), timer_delete SIGABRT teardown trace, and the larger RLIMIT_SIGPENDING accounting (tgkill02). Grouped by the signal/timer delivery machinery; timer_delete01 needs a trace so keep it with a debugger-in-hand session.

### Batch 10 — exec/fork errno differentiation (exec.rs/proc.rs) (3 suites)
`execve03, execveat02, execve02`
The G1 read_exec_file Result-propagation refactor differentiates ENOENT/ENOTDIR/EACCES/ENAMETOOLONG/ENOEXEC/ELOOP across execve03+execveat02; execveat02 also needs AT_SYMLINK_NOFOLLOW handling and execve02 needs ETXTBSY writer-refcount bookkeeping. One exec-path unit.

### Batch 11 — Remaining medium fs singles (fs.rs) (11 suites)
`utime07, inotify10, inotify11, pathconf02, readlinkat01, realpath01, llseek01, creat05, fcntl36, fcntl36_64, waitid10`
Independent medium fs.rs gaps that don't share a cause but share the file/reviewer: symlink-follow in utimensat, inotify ordering + blocking-read, pathconf empty/EACCES ordering, O_PATH modeling, getcwd-after-rmdir, RLIMIT_FSIZE, creat05 EMFILE, the OFD-lock blocking-hang pair, and waitid10 (core_pattern node + CLD_DUMPED). Sized as a mop-up batch.

### Batch 12 — process_vm cross-process transfer feature (proc.rs) (4 suites)
`process_vm01, process_vm_readv02, process_vm_readv03, process_vm_writev02`
One medium-large feature: a proc.rs handler claiming 270/271 with arg validation (closes the 3 error-path suites) plus real cross-VM guest-VA translate-and-copy (process_vm01). Isolated new feature, best done as its own focused unit.

### Batch 13 — Large/architectural + macOS-unsupportable (deferred, low ROI) (7 suites)
`chroot02, chroot04, ptrace11, fork14, lseek11, setsockopt02, sendto02`
Deprioritize: chroot real per-process-root (large), cross-process ptrace (large unbuilt), 16TB sparse mmap reservation, sparse SEEK_HOLE backing, AF_PACKET, and SCTP. The last four have no macOS backing — consider report-only markers / non-gating rather than emulation.

## Oracle-side (no carrick fix)

14 oracle-side gaps need NO carrick fix. (A) carrick is MORE correct than the container oracle: vhangup02 (carrick's no-op-success matches Linux-root; container fails for lack of a tty/CAP_SYS_TTY_CONFIG), nice01 and unshare01 (carrick models the guest as holding CAP_SYS_NICE/CAP_SYS_ADMIN so the positive test passes; the unprivileged Docker container returns EPERM and the LTP positive assertion fails there). These are candidates for a report-only marker noting the privilege-inversion so they don't read as gating regressions. (B) carrick ENOSYS AND oracle also fails: delete_module02 and syslog12 (module/kernel-log infrastructure the container lacks; leaving ENOSYS is defensible), kcmp01/02/03 (need CAP_SYS_PTRACE/yama the container lacks — docker fails all), pivot_root01 and nice05 (docker TBROK/fails), setns01 (docker passes only 5 arg-validation cases, fails the 20 namespace cases). (C) docker overlayfs TBROK: lgetxattr01, lgetxattr02, llistxattr01 — the container fs can't lsetxattr security.*/the symlink's own attr in setup, so the oracle never establishes ground truth. NOTE a genuine-but-non-gate-measurable carrick deficiency underlies (C): the l-variant nofollow flag is decoded then DISCARDED (fs.rs:8278/8295/8310) and xattr_target_path always follows the final symlink, so lgetxattr/lsetxattr/llistxattr operate on the target not the link — worth a correctness follow-up (thread the follow arg through, nofollow-resolve the final component) even though it won't move the gate. Separately, setns01's 5 arg-validation error cases (EBADF/EINVAL) are a small recoverable win if desired. Also flag two macOS-unsupportable large singletons (setsockopt02 AF_PACKET/TPACKET_V3, sendto02 SCTP) as report-only candidates — honest ENOPROTOOPT/EPROTONOSUPPORT rather than emulation. The 18 keyring (16) + pidfd_getfd (2) known-unimpl suites are already honest-ENOSYS+report-only and excluded from the backlog. FLAKY: epoll_wait02 is pure tst_timer 'slept too long' latency under HVF (6/7 under the quieter gate) — deprioritize; creat05 may also be perf-adjacent (verify EMFILE is reached before treating as correctness).
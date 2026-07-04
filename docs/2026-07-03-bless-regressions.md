# LTP 20260529 re-bless — 327 carrick-vs-oracle gaps to fix

> Generated 2026-07-03 from `scripts/conformance/baseline.jsonl` after the roll-forward bless.
> 287 regression + 40 diff. These were largely MASKED by the LTP version skew (carrick ran 20240930 binaries); the skew fix exposed them. Fix per AGENTS.md (differential oracle, red-first, root-cause, no known_gaps).

## Current progress

Updated 2026-07-04. This section is the working ledger; use it before choosing
the next cluster so we do not repeat already-verified current-tree work. Evidence
below is from focused `just conformance full --workers 1 ... --flake-retries 0`
runs unless noted. No `known_gaps` or baseline edits are part of this closeout;
oracle-cache edits are only used when the suite declaration itself changed.

### Closed on current tree

- `ltp-fcntl*`: `ltp-fcntl12`, `ltp-fcntl12_64`, `ltp-fcntl15`,
  `ltp-fcntl15_64`, `ltp-fcntl37`, `ltp-fcntl37_64`, `ltp-fcntl38`,
  `ltp-fcntl38_64`, `ltp-fcntl39`, `ltp-fcntl39_64` all MATCH.
- `ltp-epoll*`: `ltp-epoll_ctl03`, `ltp-epoll_ctl04`, `ltp-epoll_ctl05`,
  `ltp-epoll_pwait05`, `ltp-epoll_wait03`, `ltp-epoll_wait05`,
  `ltp-epoll_wait06` all MATCH.
- `ltp-ioctl*`: `ltp-ioctl01`, `ltp-ioctl07`, `ltp-ioctl_ficlone04`,
  `ltp-ioctl_loop01`, `ltp-ioctl_loop02`, `ltp-ioctl_loop03`,
  `ltp-ioctl_loop04`, `ltp-ioctl_loop06`, `ltp-ioctl_loop07`,
  `ltp-ioctl_ns01`, `ltp-ioctl_ns02`, `ltp-ioctl_ns04`, `ltp-ioctl_ns06`
  all MATCH.
- `ltp-add_key*` / `ltp-keyctl*`: `ltp-add_key01` through `ltp-add_key04` and
  `ltp-keyctl01`, `ltp-keyctl03`, `ltp-keyctl04`, `ltp-keyctl05`,
  `ltp-keyctl06`, `ltp-keyctl07`, `ltp-keyctl08` all MATCH.
- `ltp-clone301`, `ltp-clone302`, `ltp-clone303` all MATCH after running
  clone301/302's Docker oracle with seccomp disabled so the tests exercise
  clone3 instead of Docker's default ENOSYS filter. Root causes fixed:
  clone3 now rejects malformed size/flag/exit-signal/pidfd combinations before
  forking, and child-exit signal publication handles already-waitable children
  when arming the HVF watch or returning from terminal `wait4`. Red-first:
  `clone3args` DIFFed on the malformed cases and pre-fix `ltp-clone302`
  regressed at carrick[6/12] vs oracle[12/12].
- `ltp-futex*`: `ltp-futex_cmp_requeue01`, `ltp-futex_waitv01`,
  `ltp-futex_waitv02`, `ltp-futex_waitv03`, `ltp-futex_wake02`, and
  `ltp-futex_wake04` all MATCH after `4e338587`. Root causes fixed:
  `futex_waitv` dispatch/validation, process-shared `FUTEX_CMP_REQUEUE`
  bookkeeping, HVF resource release while forked shared-futex waiters are
  parked, and `/proc/<tgid>/task/<tid>` state visibility for futex waiters.
  Red-first: pre-fix `c76448a9` regressed `ltp-futex_cmp_requeue01` at
  carrick[0/129] vs oracle[7/7], `ltp-futex_waitv01` at carrick[Success] vs
  oracle[9/9], and `ltp-futex_wake02` at carrick[0/1] vs oracle[11/11].
  Reduced probes `futexwaiterstates`, `futexforkwakegroups`, and
  `futexforkrequeue` all MATCH.
- `ltp-mq*`: `ltp-mq_notify01`, `ltp-mq_notify02`, `ltp-mq_notify03`,
  `ltp-mq_open01`, `ltp-mq_timedreceive01`, `ltp-mq_timedsend01`,
  `ltp-mq_unlink01` all MATCH after `a4e170b8`. Root causes fixed:
  `SIGEV_THREAD` mqueue notifications now use glibc's netlink-helper ABI,
  `SIGEV_SIGNAL` notifications carry `SI_MESGQ` siginfo, and open descriptors
  survive `mq_unlink` through a hidden backing-object hardlink. Red-first:
  clean `987009ec` regressed `ltp-mq_notify01` at carrick[2/3] vs oracle[7/7]
  and `ltp-mq_notify03` at carrick[1/6] vs oracle[7/7].
- SysV message queues: prior focused SysV msg cluster run passed 22/22.
- SysV shared memory: `ltp-shmctl01`, `ltp-shmctl02`, `ltp-shmctl03`,
  `ltp-shmctl04`, `ltp-shmctl05`, `ltp-shmctl06`, `ltp-shmctl07`,
  `ltp-shmget02`, `ltp-shmget03`, `ltp-shmget04` all MATCH. Root causes fixed:
  synthetic `/sys/kernel/mm/hugepages`, `/proc/sys/vm/nr_hugepages`, readonly
  sysctl `EROFS`, and vCPU-slot reclaim around fd waits.
- `ltp-mmap*`: `ltp-mmap001`, `ltp-mmap04`, `ltp-mmap06`, `ltp-mmap12`,
  `ltp-mmap13`, `ltp-mmap14`, `ltp-mmap15`, `ltp-mmap17`, `ltp-mmap18`
  all MATCH.
- `ltp-io*`: `ltp-io_cancel01`, `ltp-io_destroy02`, `ltp-io_getevents01`,
  `ltp-io_setup02`, `ltp-io_submit02`, `ltp-io_submit03`, `ltp-io_uring01`,
  `ltp-io_uring02` all MATCH.
- `ltp-fanotify*`: `ltp-fanotify02`, `ltp-fanotify04`, `ltp-fanotify07`,
  `ltp-fanotify08`, `ltp-fanotify11`, `ltp-fanotify12` all MATCH after
  `be98f9d5`. Root cause fixed: `fanotify_init` and `fanotify_mark` now exist
  as explicitly unsupported `EPERM` syscalls instead of false-passing the
  Docker oracle. Red-first: clean `a55a26e6` reported carrick[Success] vs
  oracle[0/1] for all six suites.
- `ltp-request_key*`: `ltp-request_key01` through `ltp-request_key06` all MATCH.
- `ltp-pidfd*` listed here: `ltp-pidfd_getfd01`, `ltp-pidfd_getfd02`,
  `ltp-pidfd_open04`, `ltp-pidfd_send_signal01`, `ltp-pidfd_send_signal02`,
  `ltp-pidfd_send_signal03` all MATCH. Root causes fixed: syscall 438 no
  longer reports absent, `waitid(P_PIDFD)` honors pidfd `O_NONBLOCK`,
  `pidfd_send_signal` validates flags and `siginfo.si_signo`, applies pidfd
  permission checks, and `/proc/sys/kernel/ns_last_pid` exists as readonly.
- `ltp-mlock*`: `ltp-mlock02`, `ltp-mlock05`, `ltp-mlock201`,
  `ltp-mlock202`, `ltp-mlock203`, `ltp-mlockall02` all MATCH.
- `ltp-prctl05` and `ltp-prctl08` MATCH after the procfs/prctl view fix.
  Root causes fixed: `/proc/self/comm` now reports the live `PR_SET_NAME`
  comm instead of the executable basename, `/proc/self/timerslack_ns` reports
  the live `PR_SET_TIMERSLACK` value, and forked children inherit a timer-slack
  default equal to the parent's current slack. Red-first:
  `procprctlview` DIFFed on `/proc/self/comm`, procfs timer slack, and the
  forked-child reset-to-default case; pre-fix focused LTP regressed
  `ltp-prctl05` at carrick[6/8] vs oracle[8/8] and `ltp-prctl08` at
  carrick[10/14] vs oracle[14/14].
- `ltp-prctl02` MATCH after prctl error-semantics fixes. Root causes fixed:
  seccomp filter install now validates bad user pointers before the
  no-new-privs/capability gate and otherwise returns `EACCES` when unprivileged,
  `PR_SET_SECUREBITS`/`PR_CAPBSET_DROP` require `CAP_SETPCAP`, and the THP,
  ambient capability, and speculation-control prctl forms are recognized so
  invalid-argument assertions run instead of being skipped as unsupported.
  Red-first: `prctlerrors` DIFFed on those valid-form and privilege-gated errno
  paths before matching Linux line-for-line.
- `ltp-prctl03` MATCH after child-subreaper reparenting fixes. Root causes
  fixed: `PR_SET_CHILD_SUBREAPER` state is not inherited by forked children,
  descendants record their nearest subreaper ancestor at fork time, orphaned
  children report the subreaper as `getppid()` under PID namespaces, and the
  subreaper can block in `wait4` for an adopted descendant before consuming the
  synthetic exit status. Red-first: `childsubreaper` DIFFed on inherited
  subreaper state, orphan PPID, wait reaping, exit status, and SIGCHLD before
  matching Linux line-for-line.
- `ltp-ptrace01` MATCH after PID-namespace any-child wait fixes. Root cause
  fixed: `wait4(-1)` in a private PID namespace no longer returns guest pid 0
  after reaping a host child that is not visible in the namespace; namespace-
  invisible host children are discarded and blocking any-child waits keep
  waiting until a guest-visible child changes state or `ECHILD` is real.
  Red-first: `ptracekillcont` DIFFed on the LTP-shaped `PTRACE_TRACEME` /
  self-`SIGUSR2` sequence because post-case cleanup `waitpid(-1, 0)` returned
  `0` and left stale `ENOTTY`; it now MATCHes Linux with `-1/ECHILD`.
- `ltp-ptrace02` MATCH after `PTRACE_ATTACH` denial semantics. Root cause
  fixed: Carrick now recognizes Linux ptrace request 16 and returns `EPERM`
  for an existing target instead of treating the request as absent `ENOSYS`.
  Red-first: `ptraceattach` DIFFed on a non-dumpable parent attach attempt and
  now MATCHes Linux.
- `ltp-ptrace03` MATCH after repeated `PTRACE_TRACEME` denial semantics. Root
  cause fixed: a process that already requested tracing now gets `EPERM` on a
  second `PTRACE_TRACEME` instead of succeeding again. Red-first:
  `ptracetraceme` DIFFed on the repeated-traceme path before matching Linux.
- `ltp-ptrace05` MATCH after ptrace signal-delivery stop fixes. Root cause
  fixed: ptraced self-signals now publish the original Linux stop signal in the
  fork-shared child table, use a host `SIGSTOP` carrier instead of relying on
  Darwin signal dispositions, and skip host-to-Linux translation for already
  synthetic guest wait statuses. Red-first: `ptracesequence` DIFFed on the
  LTP-shaped signal sweep at signal 16 before matching Linux.
- `ltp-ptrace06` MATCH after the ptrace signal-delivery stop fix above; the
  same current tree reports all 48 invalid peek/poke address assertions as
  matching Linux.
- `ltp-ptrace11` MATCH after synthetic attach-stop support for pid 1. Root
  cause fixed: Carrick no longer treats every `PTRACE_ATTACH` to an existing
  task as `EPERM`; attaching the namespace init records a synthetic waitable
  `SIGSTOP` attach stop and `PTRACE_DETACH` clears it. Red-first:
  `ptraceattachinit` DIFFed on attach/wait/detach before matching Linux, while
  `ptraceattach` still covers the non-dumpable-parent `EPERM` case from
  `ltp-ptrace02`.
- `ltp-clock_nanosleep01` MATCH after rejecting CPU-time clocks for
  `clock_nanosleep`. Root cause fixed: Carrick kept `CLOCK_THREAD_CPUTIME_ID`
  readable for `clock_gettime` but no longer treats it as sleepable; raw
  `clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, ...)` now returns
  `EOPNOTSUPP`, matching Linux. Red-first: `clocknanosleepcpu` DIFFed on the
  raw syscall errno path before matching Linux line-for-line.

### Still open / next

- No remaining `ltp-prctl*` gating item in the current focused checks.
  `ltp-prctl09` remains a non-gating timing-threshold MATCH with differing
  assertion counts: direct Docker arm64 also fails the 25ms and 100ms
  timer-slack cases, while Carrick additionally failed the 10ms case in two
  samples by a small oversleep margin. Treat this as timing-jitter evidence,
  not a prctl semantic blocker.
- No remaining `ltp-ptrace*` gating item in the current focused checks.
- `ltp-clock_nanosleep02` remains a timing inversion: Carrick passes all seven
  threshold assertions, while direct Docker arm64 still fails "slept too long"
  threshold cases. Do not paper this over by making Carrick sleep less
  accurately; classify the oracle/jitter issue separately from
  `clock_nanosleep01`'s errno fix.

## Top clusters (fix the shared root cause once → clears many)

- **ltp-ioctl\*** — 13 suites
- **ltp-fcntl\*** — 10 suites
- **ltp-mmap\*** — 9 suites
- **ltp-io\*** — 8 suites
- **ltp-epoll\*** — 7 suites
- **ltp-keyctl\*** — 7 suites
- **ltp-msgrcv\*** — 7 suites
- **ltp-shmctl\*** — 7 suites
- **ltp-fanotify\*** — 6 suites
- **ltp-futex\*** — 6 suites
- **ltp-msgctl\*** — 6 suites
- **ltp-pidfd\*** — 6 suites
- **ltp-ptrace\*** — 6 suites
- **ltp-request\*** — 6 suites
- **ltp-mlock\*** — 5 suites
- **ltp-prctl\*** — 5 suites
- **ltp-add\*** — 4 suites
- **ltp-clock\*** — 4 suites
- **ltp-msgget\*** — 4 suites
- **ltp-msgsnd\*** — 4 suites
- **ltp-process\*** — 4 suites
- **ltp-sendfile\*** — 4 suites
- **ltp-setrlimit\*** — 4 suites
- **ltp-shmget\*** — 4 suites
- **ltp-splice\*** — 4 suites

## Full list (name · verdict · carrick-vs-oracle)

- `cpython-asyncio` · diff · c(p2519/f2/b0) o(p2521/f0/b0)
- `cpython-pathlib` · diff · c(p460/f1/b0) o(p461/f0/b0)
- `cpython-posix` · diff · c(p135/f1/b0) o(p136/f0/b0)
- `cpython-shutil` · diff · c(p150/f1/b0) o(p148/f0/b0)
- `cpython-socket` · diff · c(p615/f0/b0) o(p657/f0/b0)
- `cpython-ssl` · diff · c(p95/f2/b0) o(p97/f0/b0)
- `cpython-tarfile` · diff · c(p607/f1/b0) o(p609/f0/b0)
- `go-crypto_sha512` · diff · c(p42/f0/b0) o(p72/f0/b0)
- `go-crypto_subtle` · diff · c(p8/f0/b0) o(p10/f0/b0)
- `go-net` · diff · c(p447/f0/b0) o(p259/f0/b0)
- `go-net_http` · regression · c(p1315/f1/b0) o(p1316/f0/b0)
- `go-os` · regression · c(p714/f13/b0) o(p104/f0/b0)
- `go-os_signal` · diff · c(p30/f0/b0) o(p29/f1/b0)
- `go-syscall` · diff · c(p32/f11/b0) o(p34/f0/b0)
- `ltp-accept02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-accept03` · regression · c(p13/f1/b0) o(p15/f0/b0)
- `ltp-acct01` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-acct02` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-add_key01` · regression · c(p0/f0/b0) o(p0/f4/b0)
- `ltp-add_key02` · regression · c(p0/f0/b0) o(p0/f9/b0)
- `ltp-add_key03` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-add_key04` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-adjtimex01` · regression · c(p0/f0/b1) o(p0/f2/b0)
- `ltp-adjtimex02` · regression · c(p0/f0/b1) o(p3/f4/b0)
- `ltp-adjtimex03` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-alarm07` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-bind06` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-cachestat03` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-capset02` · regression · c(p5/f1/b0) o(p6/f0/b0)
- `ltp-capset03` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-chroot02` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-chroot04` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-clock_gettime03` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-clock_nanosleep01` · regression · c(p11/f1/b0) o(p12/f0/b0)
- `ltp-clock_nanosleep02` · regression · c(p7/f0/b0) o(p5/f2/b0)
- `ltp-clock_nanosleep03` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-clone08` · regression · c(p0/f0/b1) o(p5/f0/b0)
- `ltp-clone301` · regression · c(p5/f2/b0) o(p0/f0/b0)
- `ltp-clone302` · regression · c(p6/f6/b0) o(p1/f0/b0)
- `ltp-connect02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-delete_module02` · regression · c(p0/f0/b0) o(p1/f4/b0)
- `ltp-epoll_ctl03` · regression · c(p128/f128/b0) o(p256/f0/b0)
- `ltp-epoll_ctl04` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-epoll_ctl05` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-epoll_pwait05` · regression · c(p0/f0/b0) o(p3/f0/b0)
- `ltp-epoll_wait03` · regression · c(p4/f1/b0) o(p5/f0/b0)
- `ltp-epoll_wait05` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-epoll_wait06` · regression · c(p2/f7/b0) o(p9/f0/b0)
- `ltp-execve02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-execve03` · regression · c(p2/f4/b0) o(p6/f0/b0)
- `ltp-execveat02` · regression · c(p2/f2/b0) o(p4/f0/b0)
- `ltp-fanotify02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fanotify04` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fanotify07` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fanotify08` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fanotify11` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fanotify12` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-fchdir03` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-fcntl12` · regression · c(p1/f0/b0) o(p0/f1/b0)
- `ltp-fcntl12_64` · regression · c(p1/f0/b0) o(p0/f1/b0)
- `ltp-fcntl15` · regression · c(p10/f2/b0) o(p12/f0/b0)
- `ltp-fcntl15_64` · regression · c(p10/f2/b0) o(p12/f0/b0)
- `ltp-fcntl37` · regression · c(p0/f3/b0) o(p3/f0/b0)
- `ltp-fcntl37_64` · regression · c(p0/f3/b0) o(p3/f0/b0)
- `ltp-fcntl38` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-fcntl38_64` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-fcntl39` · regression · c(p0/f0/b0) o(p4/f0/b0)
- `ltp-fcntl39_64` · regression · c(p0/f0/b0) o(p4/f0/b0)
- `ltp-flistxattr01` · regression · c(p1/f0/b0) o(p0/f0/b1)
- `ltp-flistxattr02` · regression · c(p2/f0/b0) o(p0/f0/b1)
- `ltp-flistxattr03` · regression · c(p2/f0/b0) o(p0/f0/b1)
- `ltp-fork14` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-fsetxattr02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-futex_cmp_requeue01` · regression · c(p0/f5/b1) o(p7/f0/b0)
- `ltp-futex_waitv01` · regression · c(p0/f0/b0) o(p9/f0/b0)
- `ltp-futex_waitv02` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-futex_waitv03` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-futex_wake02` · regression · c(p0/f0/b1) o(p11/f0/b0)
- `ltp-futex_wake04` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-getsockopt01` · regression · c(p5/f4/b0) o(p9/f0/b0)
- `ltp-getsockopt02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-gettimeofday02` · regression · c(p1/f0/b0) o(p0/f1/b0)
- `ltp-inotify10` · regression · c(p6/f4/b0) o(p10/f0/b0)
- `ltp-inotify11` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-io_cancel01` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-io_destroy02` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-io_getevents01` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-io_setup02` · regression · c(p0/f0/b0) o(p5/f0/b0)
- `ltp-io_submit02` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-io_submit03` · regression · c(p0/f0/b0) o(p7/f0/b0)
- `ltp-io_uring01` · diff · c(p0/f0/b1) o(p0/f0/b0)
- `ltp-io_uring02` · diff · c(p0/f0/b1) o(p0/f0/b0)
- `ltp-ioctl01` · regression · c(p7/f2/b0) o(p9/f0/b0)
- `ltp-ioctl07` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-ioctl_ficlone04` · regression · c(p16/f239/b0) o(p288/f0/b0)
- `ltp-ioctl_loop01` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_loop02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_loop03` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_loop04` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_loop06` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_loop07` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ioctl_ns01` · regression · c(p2/f0/b0) o(p1/f0/b1)
- `ltp-ioctl_ns02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-ioctl_ns04` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-ioctl_ns06` · regression · c(p0/f1/b0) o(p0/f0/b1)
- `ltp-kcmp01` · regression · c(p0/f0/b0) o(p0/f5/b0)
- `ltp-kcmp02` · regression · c(p0/f0/b0) o(p0/f6/b0)
- `ltp-kcmp03` · regression · c(p0/f0/b0) o(p0/f4/b0)
- `ltp-keyctl01` · regression · c(p0/f0/b0) o(p0/f1/b1)
- `ltp-keyctl03` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-keyctl04` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-keyctl05` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-keyctl06` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-keyctl07` · regression · c(p1/f0/b0) o(p0/f0/b1)
- `ltp-keyctl08` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-kill07` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-kill09` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-lchown03` · regression · c(p0/f0/b0) o(p0/f0/b2)
- `ltp-lchown03_16` · regression · c(p0/f0/b0) o(p0/f0/b2)
- `ltp-lgetxattr01` · regression · c(p1/f1/b0) o(p0/f0/b1)
- `ltp-lgetxattr02` · regression · c(p2/f1/b0) o(p0/f0/b1)
- `ltp-link04` · regression · c(p11/f3/b0) o(p14/f0/b0)
- `ltp-listxattr01` · regression · c(p1/f0/b0) o(p0/f0/b1)
- `ltp-listxattr02` · regression · c(p4/f0/b0) o(p0/f0/b1)
- `ltp-listxattr03` · regression · c(p2/f0/b0) o(p0/f0/b1)
- `ltp-llistxattr01` · regression · c(p0/f1/b0) o(p0/f0/b1)
- `ltp-llistxattr02` · regression · c(p4/f0/b0) o(p0/f0/b1)
- `ltp-llistxattr03` · regression · c(p2/f0/b0) o(p0/f0/b1)
- `ltp-llseek01` · regression · c(p1/f1/b0) o(p5/f0/b0)
- `ltp-lseek11` · regression · c(p0/f0/b0) o(p15/f0/b0)
- `ltp-lstat02` · regression · c(p5/f1/b0) o(p6/f0/b0)
- `ltp-lstat02_64` · regression · c(p5/f1/b0) o(p6/f0/b0)
- `ltp-madvise02` · regression · c(p3/f0/b1) o(p10/f0/b0)
- `ltp-madvise05` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-membarrier01` · regression · c(p10/f2/b0) o(p12/f0/b0)
- `ltp-memfd_create01` · regression · c(p2/f0/b1) o(p157/f0/b0)
- `ltp-memfd_create03` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-memfd_create04` · regression · c(p0/f0/b0) o(p9/f0/b0)
- `ltp-mincore03` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-mknod04` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-mlock02` · regression · c(p1/f2/b0) o(p2/f0/b1)
- `ltp-mlock05` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-mlock201` · regression · c(p0/f0/b0) o(p8/f0/b0)
- `ltp-mlock202` · regression · c(p0/f0/b0) o(p2/f0/b1)
- `ltp-mlock203` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-mlockall02` · diff · c(p1/f0/b0) o(p1/f1/b0)
- `ltp-mmap001` · regression · c(p0/f0/b0) o(p4/f0/b0)
- `ltp-mmap04` · regression · c(p0/f0/b1) o(p14/f0/b0)
- `ltp-mmap06` · regression · c(p2/f6/b0) o(p8/f0/b0)
- `ltp-mmap12` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mmap13` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mmap14` · diff · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mmap15` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mmap17` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mmap18` · regression · c(p2/f2/b0) o(p4/f0/b0)
- `ltp-modify_ldt03` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-mprotect01` · regression · c(p2/f1/b0) o(p3/f0/b0)
- `ltp-mprotect03` · diff · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mprotect05` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-mq_notify01` · regression · c(p2/f0/b1) o(p7/f0/b0)
- `ltp-mq_notify03` · regression · c(p1/f4/b1) o(p7/f0/b0)
- `ltp-mremap01` · diff · c(p0/f1/b1313) o(p1/f0/b0)
- `ltp-mremap04` · diff · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-mremap05` · diff · c(p2/f4/b0) o(p7/f0/b0)
- `ltp-msgctl01` · regression · c(p0/f0/b1) o(p14/f0/b0)
- `ltp-msgctl02` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-msgctl03` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-msgctl04` · regression · c(p0/f0/b1) o(p12/f0/b0)
- `ltp-msgctl06` · regression · c(p0/f0/b1) o(p10/f0/b0)
- `ltp-msgctl12` · regression · c(p0/f0/b1) o(p3/f0/b0)
- `ltp-msgget01` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-msgget02` · regression · c(p0/f0/b1) o(p6/f0/b0)
- `ltp-msgget04` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-msgget05` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-msgrcv01` · regression · c(p0/f0/b1) o(p4/f0/b0)
- `ltp-msgrcv02` · regression · c(p0/f0/b1) o(p8/f0/b0)
- `ltp-msgrcv03` · regression · c(p0/f0/b0) o(p3/f0/b0)
- `ltp-msgrcv05` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-msgrcv06` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-msgrcv07` · regression · c(p0/f0/b1) o(p15/f0/b0)
- `ltp-msgrcv08` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-msgsnd01` · regression · c(p0/f0/b1) o(p3/f0/b0)
- `ltp-msgsnd02` · regression · c(p0/f0/b1) o(p6/f0/b0)
- `ltp-msgsnd05` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-msgsnd06` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-msgstress01` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-msync03` · diff · c(p4/f2/b0) o(p6/f0/b0)
- `ltp-munlockall01` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-munmap02` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-nanosleep01` · regression · c(p7/f0/b0) o(p6/f1/b0)
- `ltp-newuname01` · regression · c(p3/f2/b1) o(p6/f0/b0)
- `ltp-nice01` · regression · c(p3/f0/b0) o(p0/f3/b0)
- `ltp-nice05` · regression · c(p0/f1/b0) o(p0/f0/b1)
- `ltp-open02` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-open11` · regression · c(p26/f2/b0) o(p28/f0/b0)
- `ltp-open13` · diff · c(p12/f2/b0) o(p14/f0/b0)
- `ltp-pathconf02` · regression · c(p4/f2/b0) o(p6/f0/b0)
- `ltp-pause03` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-perf_event_open01` · diff · c(p0/f0/b0) o(p0/f1/b0)
- `ltp-perf_event_open02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-personality01` · regression · c(p18/f0/b0) o(p1/f0/b1)
- `ltp-personality02` · regression · c(p1/f0/b0) o(p0/f0/b1)
- `ltp-pidfd_getfd01` · regression · c(p0/f0/b0) o(p0/f1/b1)
- `ltp-pidfd_getfd02` · regression · c(p0/f0/b0) o(p1/f4/b0)
- `ltp-pidfd_open04` · regression · c(p1/f0/b1) o(p3/f0/b0)
- `ltp-pidfd_send_signal01` · regression · c(p0/f1/b0) o(p2/f0/b0)
- `ltp-pidfd_send_signal02` · regression · c(p0/f0/b1) o(p4/f0/b0)
- `ltp-pidfd_send_signal03` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-pipe12` · regression · c(p4/f2/b0) o(p6/f0/b0)
- `ltp-pipe15` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-pipe2_04` · regression · c(p0/f1/b1) o(p2/f0/b0)
- `ltp-pivot_root01` · regression · c(p0/f0/b1) o(p0/f5/b0)
- `ltp-pkey01` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-ppoll01` · regression · c(p16/f4/b0) o(p20/f0/b0)
- `ltp-prctl02` · regression · c(p9/f3/b0) o(p18/f0/b0)
- `ltp-prctl03` · regression · c(p2/f4/b0) o(p6/f0/b0)
- `ltp-prctl05` · regression · c(p6/f2/b0) o(p8/f0/b0)
- `ltp-prctl08` · regression · c(p10/f4/b0) o(p14/f0/b0)
- `ltp-prctl09` · regression · c(p7/f0/b0) o(p5/f2/b0)
- `ltp-preadv202` · regression · c(p7/f1/b0) o(p8/f0/b0)
- `ltp-preadv202_64` · regression · c(p7/f1/b0) o(p8/f0/b0)
- `ltp-process_vm01` · regression · c(p0/f0/b0) o(p25/f0/b0)
- `ltp-process_vm_readv02` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-process_vm_readv03` · regression · c(p0/f0/b0) o(p32/f0/b0)
- `ltp-process_vm_writev02` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-ptrace01` · regression · c(p1/f0/b1) o(p4/f0/b0)
- `ltp-ptrace02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-ptrace03` · regression · c(p0/f2/b1) o(p2/f0/b0)
- `ltp-ptrace05` · regression · c(p2/f1/b1) o(p2/f0/b0)
- `ltp-ptrace06` · regression · c(p48/f0/b1) o(p48/f0/b0)
- `ltp-ptrace11` · regression · c(p0/f1/b1) o(p1/f0/b0)
- `ltp-pwrite04` · regression · c(p1/f1/b0) o(p1/f0/b0)
- `ltp-pwrite04_64` · regression · c(p1/f1/b0) o(p1/f0/b0)
- `ltp-pwritev202` · regression · c(p6/f1/b0) o(p7/f0/b0)
- `ltp-pwritev202_64` · regression · c(p6/f1/b0) o(p7/f0/b0)
- `ltp-readahead01` · regression · c(p0/f0/b0) o(p14/f0/b0)
- `ltp-readlink03` · regression · c(p7/f1/b0) o(p8/f0/b0)
- `ltp-readlinkat01` · regression · c(p0/f0/b1) o(p12/f0/b0)
- `ltp-realpath01` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-recvmmsg01` · regression · c(p8/f2/b0) o(p10/f0/b0)
- `ltp-recvmsg01` · regression · c(p9/f1/b0) o(p10/f0/b0)
- `ltp-remap_file_pages01` · diff · c(p0/f8/b2) o(p2/f0/b0)
- `ltp-remap_file_pages02` · regression · c(p0/f0/b0) o(p4/f0/b0)
- `ltp-request_key01` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-request_key02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-request_key03` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-request_key04` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-request_key05` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-request_key06` · regression · c(p0/f0/b0) o(p1/f3/b0)
- `ltp-sched_setaffinity01` · regression · c(p3/f1/b1) o(p4/f0/b0)
- `ltp-sched_setparam05` · regression · c(p0/f2/b0) o(p2/f0/b0)
- `ltp-sched_setscheduler03` · regression · c(p6/f0/b0) o(p0/f0/b1)
- `ltp-select03` · regression · c(p15/f1/b1) o(p16/f0/b0)
- `ltp-semctl01` · regression · c(p3/f0/b1) o(p13/f0/b0)
- `ltp-semctl04` · regression · c(p0/f2/b0) o(p2/f0/b0)
- `ltp-semctl09` · regression · c(p0/f0/b0) o(p16/f0/b0)
- `ltp-semget02` · regression · c(p5/f1/b0) o(p6/f0/b0)
- `ltp-semget05` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-semop02` · regression · c(p0/f0/b1) o(p23/f0/b0)
- `ltp-semop03` · regression · c(p0/f0/b1) o(p8/f0/b0)
- `ltp-send02` · regression · c(p0/f4/b0) o(p4/f0/b0)
- `ltp-sendfile04` · regression · c(p2/f3/b0) o(p5/f0/b0)
- `ltp-sendfile04_64` · regression · c(p2/f3/b0) o(p5/f0/b0)
- `ltp-sendfile09` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-sendfile09_64` · regression · c(p0/f0/b0) o(p2/f0/b0)
- `ltp-sendmmsg02` · regression · c(p2/f2/b0) o(p4/f0/b0)
- `ltp-sendto02` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-setfsuid04` · diff · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-setgroups03` · regression · c(p2/f1/b0) o(p3/f0/b0)
- `ltp-setgroups04` · diff · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-setns01` · regression · c(p0/f0/b0) o(p5/f20/b0)
- `ltp-setns02` · regression · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-setpgid03` · regression · c(p2/f0/b1) o(p3/f0/b0)
- `ltp-setpriority02` · regression · c(p5/f2/b0) o(p7/f0/b0)
- `ltp-setrlimit01` · diff · c(p3/f1/b0) o(p3/f0/b2)
- `ltp-setrlimit02` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-setrlimit03` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-setrlimit06` · regression · c(p0/f2/b0) o(p2/f0/b0)
- `ltp-setsockopt01` · regression · c(p6/f2/b0) o(p8/f0/b0)
- `ltp-setsockopt02` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-setsockopt08` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-setxattr02` · regression · c(p2/f5/b0) o(p7/f0/b0)
- `ltp-shmat01` · regression · c(p1/f3/b0) o(p4/f0/b0)
- `ltp-shmat02` · regression · c(p1/f2/b0) o(p3/f0/b0)
- `ltp-shmctl01` · regression · c(p8/f4/b0) o(p12/f0/b0)
- `ltp-shmctl02` · regression · c(p3/f7/b1) o(p20/f0/b0)
- `ltp-shmctl03` · regression · c(p0/f1/b1) o(p4/f0/b0)
- `ltp-shmctl04` · regression · c(p0/f0/b0) o(p12/f0/b0)
- `ltp-shmctl05` · regression · c(p0/f0/b0) o(p1/f0/b0)
- `ltp-shmctl07` · regression · c(p1/f3/b0) o(p4/f0/b0)
- `ltp-shmctl08` · regression · c(p4/f2/b0) o(p6/f0/b0)
- `ltp-shmdt01` · regression · c(p1/f1/b0) o(p2/f0/b0)
- `ltp-shmget03` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-shmget04` · regression · c(p0/f3/b0) o(p3/f0/b0)
- `ltp-shmget05` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-shmget06` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-socket01` · regression · c(p4/f5/b0) o(p9/f0/b0)
- `ltp-socketpair01` · regression · c(p6/f4/b0) o(p10/f0/b0)
- `ltp-splice03` · regression · c(p6/f1/b0) o(p7/f0/b0)
- `ltp-splice05` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-splice07` · regression · c(p232/f14/b0) o(p277/f0/b0)
- `ltp-splice08` · regression · c(p28/f8/b0) o(p36/f0/b0)
- `ltp-symlink01` · regression · c(p0/f0/b0) o(p5/f0/b0)
- `ltp-sysinfo01` · regression · c(p8/f1/b0) o(p9/f0/b0)
- `ltp-sysinfo03` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-syslog12` · regression · c(p0/f0/b0) o(p1/f5/b0)
- `ltp-tee01` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-tgkill02` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-tgkill03` · regression · c(p5/f1/b0) o(p6/f0/b0)
- `ltp-timer_delete01` · regression · c(p8/f0/b1) o(p6/f2/b0)
- `ltp-timer_settime03` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-timerfd04` · diff · c(p0/f0/b0) o(p0/f0/b1)
- `ltp-timerfd_settime02` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-truncate03` · regression · c(p5/f3/b0) o(p8/f0/b0)
- `ltp-truncate03_64` · regression · c(p5/f3/b0) o(p8/f0/b0)
- `ltp-unshare01` · regression · c(p3/f0/b0) o(p0/f3/b0)
- `ltp-utime07` · regression · c(p3/f2/b0) o(p5/f0/b0)
- `ltp-vhangup02` · regression · c(p1/f0/b0) o(p0/f1/b0)
- `ltp-vmsplice01` · regression · c(p0/f0/b1) o(p1/f0/b0)
- `ltp-vmsplice04` · regression · c(p0/f0/b1) o(p2/f0/b0)
- `ltp-waitid05` · regression · c(p2/f4/b0) o(p6/f0/b0)
- `ltp-waitid07` · regression · c(p0/f0/b1) o(p5/f0/b0)
- `ltp-waitid08` · regression · c(p0/f0/b1) o(p10/f0/b0)
- `ltp-waitid10` · regression · c(p0/f0/b1) o(p5/f0/b0)
- `ltp-waitpid11` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-waitpid12` · regression · c(p0/f1/b0) o(p1/f0/b0)
- `ltp-waitpid13` · regression · c(p0/f1/b0) o(p1/f0/b0)

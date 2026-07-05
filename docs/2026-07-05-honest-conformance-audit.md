# Honest conformance audit — 2026-07-05

Audit of the LTP re-bless campaign (`47a8bb10..HEAD`) baseline integrity, triggered by a
direction review. Companion to `docs/superpowers/plans/2026-07-05-conformance-direction-remediation.md`.

## Headline: the campaign's conformance metric is inflated by broken/broken false-matches

The committed baseline (`scripts/conformance/baseline.jsonl`) reports **1977 / 2064 MATCH (95.8%)**.
But **1128 of those 1977 "matches" (57.1%) are `pairs=['broken','broken']`** — at bless time
BOTH carrick AND the Docker oracle were unrunnable on the suite, and the harness scores
`broken == broken` as MATCH. Only **574** are genuine `ok/ok` matches; 275 are mixed.

The false-match list includes basic syscalls that obviously should run (access, bind, brk,
alarm, adjtimex), i.e. the **oracle itself was systemically broken** for a large swath of the
suite at bless time. So over half the headline number reflects "we couldn't test this, and
neither could the oracle" — not carrick's real Linux compatibility.

## The oracle can now run all 1128 — so we measured carrick's real state

The campaign's last commit refreshed the oracle cache; a join shows **all 1128 broken/broken
suites are now runnable by the oracle** (843 oracle-success, 285 oracle-failure, 0 still-broken).
Running carrick against that now-runnable oracle (carrick-only, cached oracle, `--force`,
workers 4) over all 1126 that executed:

| carrick's REAL result on the 1126 previously-untested suites | Count | |
|---|---|---|
| **MATCH (genuine)** | **968** | **86.0%** |
| carrick-correct (oracle itself broken) | 18 | carrick is right |
| known-unimplemented (Phase-1 keyring/pidfd, report-only) | 18 | already honest |
| **Functional gaps to fix** | **105** | real carrick bugs |
| **Perf-slow / timeout (architectural)** | **17** | HVF vmexit cost |

**carrick's true conformance on the previously-untested half is ~86% MATCH** — the metric was
inflated (95.8% → ~86% real on this block), but the underlying runtime is solid. The gap is a
concrete, fixable backlog the false-matches were hiding.

## The path to an honest bless
1. **Re-bless honestly** — the oracle runs all 1128; a fresh bless replaces broken/broken
   false-matches with real verdicts. Mostly mechanical (oracle cache already refreshed).
2. **Fix the 105 functional gaps** (below) — real carrick syscall bugs, most normal-speed/fixable.
3. **Triage the 17 perf-slow gaps** — fuzzy_sync/raw-syscall timing tests 14–99× slower under
   carrick (HVF vmexit cost); architectural, the "orders of magnitude slower" judgment category.

## Genuine fix backlog (exposed by the honest re-run)

# Exposed functional gaps (fix backlog) — carrick fails where the now-runnable oracle passes
# 105 suites, from honest re-run of previously broken/broken baseline matches

ltp-accept02
ltp-alarm07
ltp-capset02
ltp-capset03
ltp-chroot02
ltp-chroot04
ltp-connect02
ltp-creat05
ltp-delete_module02
ltp-epoll_pwait01
ltp-epoll_pwait02
ltp-epoll_pwait03
ltp-epoll_wait02
ltp-execve02
ltp-execve03
ltp-execveat02
ltp-fchdir03
ltp-fcntl36
ltp-fcntl36_64
ltp-fork14
ltp-getpgid01
ltp-getsockopt01
ltp-getsockopt02
ltp-inotify10
ltp-inotify11
ltp-kcmp01
ltp-kcmp02
ltp-kcmp03
ltp-lgetxattr01
ltp-lgetxattr02
ltp-link04
ltp-llistxattr01
ltp-llseek01
ltp-lseek11
ltp-lstat02
ltp-lstat02_64
ltp-madvise02
ltp-madvise05
ltp-membarrier01
ltp-memfd_create01
ltp-memfd_create04
ltp-mincore03
ltp-nice01
ltp-nice05
ltp-open02
ltp-open11
ltp-pathconf02
ltp-pipe12
ltp-pipe15
ltp-pivot_root01
ltp-ppoll01
ltp-preadv202
ltp-preadv202_64
ltp-process_vm01
ltp-process_vm_readv02
ltp-process_vm_readv03
ltp-process_vm_writev02
ltp-ptrace11
ltp-pwrite04
ltp-pwrite04_64
ltp-pwritev202
ltp-pwritev202_64
ltp-readahead01
ltp-readlink03
ltp-readlinkat01
ltp-realpath01
ltp-recvmmsg01
ltp-recvmsg01
ltp-sched_setaffinity01
ltp-sched_setparam05
ltp-select03
ltp-send02
ltp-sendfile09
ltp-sendfile09_64
ltp-sendmmsg02
ltp-sendto02
ltp-setgroups03
ltp-setns01
ltp-setpriority02
ltp-setsockopt01
ltp-setsockopt02
ltp-setxattr02
ltp-shmat03
ltp-socket01
ltp-socketpair01
ltp-splice03
ltp-splice07
ltp-splice08
ltp-syslog12
ltp-tee01
ltp-tgkill02
ltp-tgkill03
ltp-timer_delete01
ltp-timer_settime03
ltp-timerfd_settime02
ltp-truncate03
ltp-truncate03_64
ltp-unshare01
ltp-utime07
ltp-vhangup02
ltp-waitid05
ltp-waitid10
ltp-waitpid11
ltp-waitpid12
ltp-waitpid13

# Perf-slow / timeout gaps (architectural HVF-vmexit slowness) — 17

ltp-clone08  (14.6x)
ltp-fcntl14_64  (10.1x)
ltp-fork_procs  (30.2x)
ltp-futex_cmp_requeue01  (29.6x)
ltp-inotify09  (4.0x)
ltp-link05  (99.3x)
ltp-pipe07  (29.9x)
ltp-setpgid03  (13.2x)
ltp-setrlimit06  (8.5x)
ltp-shmctl05  (1.5x)
ltp-splice02  (38.0x)
ltp-splice05  (37.7x)
ltp-vmsplice01  (38.0x)
ltp-vmsplice04  (38.0x)
ltp-waitid07  (49.9x)
ltp-waitid08  (50.0x)
ltp-waitpid08  (15.2x)

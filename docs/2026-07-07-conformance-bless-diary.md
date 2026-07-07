# 2026-07-07 conformance bless diary

## clone08 regression

Hypothesis:
`ltp-clone08` is a real runtime clone-semantics bug, not load or timing. The
process-like clone path drops `CLONE_PARENT`, `CLONE_PARENT_SETTID`, and
`CLONE_CHILD_SETTID` before the runtime fork code can model them. Separately,
the thread path classifies only Carrick's `THREAD_MASK` superset as a thread,
so a Linux-valid `CLONE_THREAD|CLONE_VM|CLONE_SIGHAND|CLONE_CHILD_CLEARTID`
shape falls through to a real process fork.

Tests:
- Focused Carrick run:
  `target/conformance/logs/ltp-clone08-focus-013314.carrick.log`
- Focused Docker oracle:
  `target/conformance/logs/ltp-clone08-focus-013314.docker.log`
- Carrick trace:
  `target/conformance/logs/clone08-trace-013656.trace`

Outcome:
Docker passes all five clone08 assertions. Carrick fails all five. The trace
shows the `CLONE_THREAD` subtest issuing `clone` with flags `0x210911`, then
Carrick records a new process pid and a private-futex wait instead of an
in-process thread exit clear/wake. Code inspection confirmed fork-like clone
outcomes carried only pidfd, signal, stack, and vfork metadata.

Fix under test:
Classify any valid `CLONE_THREAD` request as `CloneThread` after the existing
`THREAD => SIGHAND => VM` validation. Preserve process-clone parent/TID
metadata through `DispatchOutcome::Fork`, write `pid_t` values in the parent
and child fork arms, and register `CLONE_PARENT` children through the
fork-coherent adopted-child table.

Follow-up:
The first patched focused run improved Carrick from 0/5 to 3/5 and reduced the
raw run from about 6s to about 1s, but `CLONE_PARENT_SETTID` still failed. A
second trace showed the failing shape was `CLONE_PARENT_SETTID|CLONE_VM`; the
LTP child checks `ptid` after clone. Because Carrick models this as a CoW fork
rather than a shared-VM process clone, the Linux-visible store must be mirrored
into the child branch too, not only the parent branch.

Second follow-up:
The next focused run returned success but only produced 4 TPASS lines. Carrick's
thread subtest changed `ctid` to the thread id instead of clearing it to 0,
which let the parent observe `EWOULDBLOCK` and exit before the child thread's
own assertion ran. Root cause: the thread outcome conflated
`CLONE_CHILD_SETTID` and `CLONE_CHILD_CLEARTID`. These are distinct Linux
effects: set-tid writes at clone return, clear-tid registers an exit-time clear
and futex wake.

Third follow-up:
After splitting set-tid and clear-tid, the thread child actually ran and crashed
with SIGSEGV. The next root cause is the TLS handoff: Carrick encoded "no
`CLONE_SETTLS`" as `tls = 0`, but still installed `Some(0)` in the sibling vCPU.
For clone08's thread case, Linux preserves the caller's TLS because SETTLS is
absent. The runtime outcome now carries `tls: Option<u64>` so no-SETTLS clones
leave the child TLS register alone.

Verified:
- Focused raw run `ltp-clone08-fix4-020037`: Carrick 5/5 in 969ms, Docker 5/5
  in 477ms. This is about 2.03x for the focused command, down from the
  full-harness failure's 14.89x outlier.
- Harness run:
  `target/release/carrick-conformance --suite ltp-clone08 --jsonl target/conformance/clone08-fix.jsonl`
  reported `MATCH carrick[5/5] oracle[5/5]`.

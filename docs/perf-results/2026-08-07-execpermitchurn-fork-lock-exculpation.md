# execpermitchurn's delta-gate entry: fork-lock deadlock, not E1

**What this receipt is.** During Move-3 Task 5 (the E1 file-backed
`MAP_PRIVATE` mmap lowering, `f2a42bc3`), the one-worker conformance-probes
delta gate showed `execpermitchurn` ENTERING the failure set (TIMEOUT at
45 s) on the candidate run. A probe entering the set is exactly what the
delta gate exists to catch, so the exculpation must be evidence, not
assertion. This document is that evidence; the raw files live in
`target/perf/task5-e1/` (`execpermitchurn-offarm-resample.log`,
`execpermitchurn-onarm-resample.log`, `execpermitchurn-wedge-offarm-bt.txt`).

**Binary:** `19a1a017acc35dacace774eff6b1d545a878ce1713b4efdd4ee2f7e6d7399ceb`
(the exact candidate binary the delta gate ran). Fixture:
`scripts/run-probe.sh`'s invocation shape — probe base64-injected into
`carrick run ubuntu:24.04 --raw --fs host /bin/sh -c …`, `CARRICK_RUN_ID`
stamped, `scripts/sudo/kill.sh` reaping.

## The exculpating fact: the wedge fires with the lowering DISABLED

Sampled on 2026-08-07, same binary, alternating only the hatch:

| arm | wedges / runs | source |
|---|---:|---|
| default (lowering ON) — session round 1 | 2 / 8 | direct timed loop (45.02 s / 45.02 s timeouts) |
| `CARRICK_MMAP_FILE_BACKED=0` — round 1 | 1 / 8 | direct timed loop (one 45.02 s timeout) |
| `CARRICK_MMAP_FILE_BACKED=0` — receipt round | **1 / 1** (run 1) | `execpermitchurn-offarm-resample.log` |
| default (lowering ON) — receipt round | 0 / 8 | `execpermitchurn-onarm-resample.log` |

The wedge is load-probabilistic and fires in BOTH hatch states of the same
binary; the `=0` arm is behaviourally the pre-change snapshot path. No
hatch correlation survives the samples.

## The mechanism: fork-inherited process-global mutex

Live lldb backtrace of the wedged fork child (0 cputime, captured on the
`=0` arm; full file `execpermitchurn-wedge-offarm-bt.txt` — an
ON-arm wedge earlier the same day produced the byte-identical stack):

```
frame #0: libsystem_kernel`__psynch_cvwait
frame #6: parking_lot::raw_mutex::RawMutex::lock_slow
frame #9: carrick_thread::thread::set_current_futex_table  (thread.rs:223)
frame #12: NativeThreadRuntime::new_current                (native_darwin.rs:5016)
frame #13: NativeThreadRuntime::reset_after_fork_child     (native_darwin.rs:5054)
frame #14: handle_native_fork                              (native_darwin.rs:7586)
```

The child forked while another parent thread held the process-global
`CURRENT_FUTEX_TABLE` `parking_lot::Mutex`
(`crates/carrick-thread/src/thread.rs:222-225`); the fork child inherits
the lock word locked with no owner thread, and its very first post-fork
step (`reset_after_fork_child`) blocks on it forever. Textbook
fork-unsafe in-process global (AGENTS.md: in-memory state is not
fork-coherent). No mmap, VFS, or E1 frame appears anywhere in the stack.

## Disposition

- NOT an E1 regression; the delta-gate entry is attributed.
- Root-cause fix is chip-filed ("Fix fork-inherited lock in
  `set_current_futex_table`"): reinitialize the global in the shared
  post-fork reset (`carrick-runtime/src/native/fork_child.rs`) or acquire
  it under the fork-quiesce protocol, red-first.
- Until that lands, `execpermitchurn` (and its sibling `execfromthread`,
  which sat in the pinned BASELINE failure set the same way) belong to the
  load-probabilistic fork-churn family: sample ≥2× before reading either
  as a regression signal.

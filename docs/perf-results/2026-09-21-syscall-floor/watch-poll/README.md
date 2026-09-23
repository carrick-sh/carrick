# Production resident poll diagnostic

Three independent release-process medians: 985.40, 959.48, 935.02 ns per
invalid-descriptor inotify pair. Each process uses one warmup and 21 samples
of 65,536 pairs. Every request is consumed, every completed value is Linux
-EBADF, completion ownership returns idle, and trap/entry/errno populations
close exactly. All three runs pass.

The test invokes ProductionHvpatchLoopJob::poll_with_engine with a scripted
engine. It includes production resident control, job-control/quiesce checks,
watchdog, guest-entry publication and invalidation checks, run-state accounting,
request preparation/dispatch/completion and signal return. The task binding
owns the actual test process's Stage1MmLease with matching TTBR/ASID identity;
its executor is registered for ASID observation and resident metadata. It does
not rely on cfg(test)'s missing-invalidation-binding bypass. No hardware is
loaded/dirtied, and no concurrent invalidation or signal is injected.

Two initial fixture failures are retained as rejected transcripts: missing
Stage1MmLease and missing executor observer registration. Neither produced
usable timing. Fixing the fixture preserved production fail-closed checks.

Remaining omissions: outer worker lease transfer/settlement and scheduler
boundary checks; persistent quantum mutex/type-erasure/injected-lease wrappers;
poll_with_engine_typed's current-MM TLS scope; real engine register/memory and
completion operations; guest execution and HVF transition. Test signal/platform
services and cfg(test) remain. This is not the entire runtime or hardware floor.

Comparison ladder (different contexts, not subtractable attribution): direct
kernel ~303 ns/pair; production service/completion ~542; with idle signal-return
~609; resident poll ~960; full signed guest ~2,944. These locate measurement
boundaries, not optimization wins. The gap cannot be named pure trapping cost.

Next decisive work: complete worker-wrapper attribution or use a controlled
signed intervention on a measured candidate, then require an untraced workload
benefit. Do not keep optimizing recurring leaf/context functions based solely
on profile frequency. Preserve concurrent scaling and exact authority checks.

Raw outputs, measured source snapshot, executable SHA, and build log are here.
Only ignored diagnostics changed; no production runtime speedup is claimed.

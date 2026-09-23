# Invalid-descriptor direct dispatch diagnostic

Three independent release-process runs: median pair cost 304.26, 302.57,
303.31 ns. Each process has one warmup and 21 samples of 65,536 pairs.
Both calls must return Linux -EBADF; reporter entry, successful return and
errno return counts must match the actual dispatch population. All runs exit 0.
Existing getpid/fstat phases and stat-content validation also execute.

The same inotify syscall numbers, fd=-1, valid guest pathname and IN_MODIFY mask
are used as in the signed watch-only reducer. Observer completion is retained.
This is still diagnostic, not a matched runtime ablation: TaskMemory,
ExampleProcess, held MM admission and null signal/timer bridges differ from
HVF. The full runtime's prepared-dispatch path, current-context ownership,
completion/signal machinery and execution transitions are absent. Do not call
the difference from 2,944 ns/pair trapping overhead or an achievable speedup.

Next discriminator: run the same request stream through production threaded
runtime preparation and completion with a scripted execution backend. The old
run_syscall_loop integration fixture and FakeBinding executor test are not
sufficient substitutes: the former is not the current threaded path, and the
latter fabricates syscall steps. Preserve actual dispatch, task context and
completion behavior. Document remaining memory/backend differences explicitly.

Artifact SHA and process medians are in runs.json; raw stdout/stderr are retained.
probe-source.rs is the exact pre-rustfmt source used to build the measured binary.
The working source subsequently received formatting-only changes. Build completed
with existing unused-mut warnings in contracts.rs. No product runtime changed.
This closes a missing diagnostic measurement, not the active near-parity goal.

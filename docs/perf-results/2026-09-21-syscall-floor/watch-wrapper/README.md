# Paired production quantum-wrapper diagnostic

Eight independent release processes, order direct/wrapped/wrapped/direct then
wrapped/direct/direct/wrapped. Each process warms once and records 21 samples
of 65,536 invalid-inotify pairs. Same executable and shared fixture implementation.

Median of process medians: direct resident poll 933.53 ns/pair; production
quantum wrapper 1002.30 ns/pair; difference 68.76 ns/pair, or 34.38
ns/syscall. All requests and errno completions match; all eight tests pass.

The wrapped arm adds the real HvpatchTaskQuantum mutex, PersistentQuantumJob
engine downcast, injected execution-lease publication/teardown, production poll
routing and MM-quiesce TLS scopes. Both arms retain exact stage-1 MM and executor
observer metadata from the prior probe. Engine calls remain scripted.

This is a controlled wrapper-inclusion comparison, not a product optimization.
The outer persistent worker's lease movement, authority recovery, CPU receipt,
scheduler note_syscall_boundary/should_preempt, and pool event recording remain
outside both arms. No HVF entry or real register/mailbox operation is measured.

Priority decision: do not pursue duplicate MM TLS binding first. Source shows
nested binds in poll_production and poll_with_engine_typed, but the complete
wrapper adds only about 34 ns/call in this context. That does not establish its
removable cost in a signed guest, and cannot explain the full multi-microsecond
pair gap. Finish the worker-boundary/engine comparison and choose a signed
intervention based on its actual untraced benefit.

No absolute floor, native parity or production speedup is claimed. Raw samples,
binary SHA, measured source and build log are retained. The measured build has
one diagnostic-only unused-mut warning; the working source removes that mut
without semantic changes after this measurement.

# Paired signal-return cost diagnostic

Three independent release processes. Each alternates service/completion alone
and service/completion plus the production service_signals_threaded return
boundary; order reverses each sample. One warmup per arm, 21 samples per arm,
65,536 invalid-inotify pairs per sample. Same binary, state and completion log.

| Process | Without signal boundary, ns/pair | With signal boundary, ns/pair |
| --- | ---: | ---: |
| 0 | 541.34 | 609.52 |
| 1 | 540.73 | 606.26 |
| 2 | 543.21 | 609.84 |

The paired diagnostic adds approximately 65-68 ns per pair (33-34 ns/call).
Both calls return exact Linux EBADF, every engine completion is checked, and
reporter entry/errno counts close across both arms. All three processes pass.
The signal arm also requires no unexpected terminal signal outcome.

This is the no-pending-signal case with null/test platform bridges, not signal
delivery latency. Omitting signal handling is a diagnostic control and is NOT
an authorized product optimization. The measured difference does not promise
a saving in the full guest. Do not subtract it from unmatched guest medians.

The result argues against prioritizing this idle signal-return check to explain
the multi-microsecond full-guest pair. Remaining domains include executor poll,
run-state accounting, exact binding/invalidation checks, engine completion and
hardware/guest entry. Next measure those without dropping production obligations.

Audit warning: enter_hvpatch_guest_or_service_invalidation_inner allows a missing
exact executor/MM invalidation binding under cfg(test), while production rejects
it. A naive scripted poll using HvpatchQuantumControl::for_test must therefore
not be presented as the complete production envelope. Qualify exact binding or
retain the omission explicitly in any estimate. No lower native floor or speedup
has been established.

Raw output, source snapshot, executable SHA and build log are retained. This
changes only the ignored diagnostic test; production signal behavior is intact.

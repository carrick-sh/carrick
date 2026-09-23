# Production syscall service/completion diagnostic

Release-mode runtime unit diagnostic, three independent processes, one warmup
and 21 internal samples of 65,536 invalid-fd inotify pairs per process.
Process medians: 541.63, 534.56, 549.32 ns per pair. Exact Linux EBADF,
engine completions, idle completion ownership, reporter entries and errno
returns all pass. No successful return is reported for an error.

This invokes the actual ThreadRuntimeState::service_threaded_syscall and
complete_errno paths: context capture, policy preparation, completion token,
prepared dispatch, and production completion reporting. It uses an HVPatch
process-context test fixture and a scripted engine. Test engine completion
storage is preallocated; each sample validates every recorded result.

It does NOT run the executor pool's per-call poll, preemption/watchdog,
job-control checks, signal boundary handling, guest entry, hardware transition,
or full HVF engine memory/register behavior. Null/test platform services and
cfg(test) code mean this is a diagnostic subset, not signed guest acceptance.
The test contains no HVF VM creation and needs no guest entitlement.

Interpretation: the measured service/completion subset is substantially below
the full guest's 2,944 ns/pair. Its presence in CPU profiles does not establish
that optimizing it offers the largest attainable workload gain. Direct kernel
303 ns, this subset 542 ns, and full guest 2,944 ns have differing execution
contexts; subtracting them is not a causal allocation of transport cost.

Next experiment must cover the actual production poll/control and signal-return
boundary, with the same syscall stream and completion assertions. Avoid using
the legacy simple run_syscall_loop or executor FakeBinding as substitutes.
Only then choose a bounded intervention and verify its effect in untraced
signed guest measurements and representative workloads.

Raw output, exact executable SHA, source snapshot and patch, and build log are
retained here. The diagnostic is opt-in/ignored in routine unit runs. No product
behavior changed and no performance improvement or near-parity is claimed.

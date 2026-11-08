# Prepared-fork argument-copy diagnostic (#1877, round 10)

Contract: `kernel.memory.owner-wait`. This diagnostic changes no owner
preparation, syscall result, wait policy or work budget. It adds no runtime
correctness claim. The default `prepared-fork` sequence remains the control;
`prepared-fork-touch` performs volatile stores to every pollfd and timespec
field immediately before the parent's ppoll and reports
`pollfd_touched=true timespec_touched=true` on `prepared-fork-steps`.

The production ARM path enters `dispatch_arm_syscall_with_native_process`
from `dispatch.rs`, or the owner-free fallback when lifecycle admission is
unavailable. The poll family reads its timespec, signal mask and fd array
through `copy_argument`. `lifecycle.rs` uses the production `ValidatedCopy`:
AT S1E0R validates each page and LDTRB copies under exception fixup. The vector
in `carrick-mem/src/memory.rs` redirects an armed copy fault to failure; it
does not resolve the page there. A failed copy with no matching process
venue returns Fault/EFAULT. Otherwise `wait_guest_copy` reaches
`NativeProcessAdapter::prepare_guest_input` and exact-MM preparation, which
may independently return EFAULT. A COW-readable page should pass S1E0R.
The host projection instead checks the lower half and TEST_USER_ACCESS, then
copies host memory. Its green result cannot prove the ARM translation path.

Read the carrier's mapped counters using `carrick el1-counters` in the
existing LLDB plugin. `copy-refusal` records carry canonical ordinal, VA,
length, argument index (6 means derived), direction, reason and matching
owner presence. The first 16 records are immutable, individually published
with release/acquire ordering, without locks or allocation. Full storage
retains its prefix; this is diagnostic sampling, not a complete census.
No large record is returned on the EL1 stack. The ABI hash changes so host
and image must be rebuilt together.

Reasons distinguish forbidden range, validator refusal, guarded instruction
fault, and owner EFAULT. ARM validator refusals include a fresh PAR.FST
sample at the refused byte, distinguishing translation from permission faults.
This sample is observational: page tables may change between validation and
sampling. Permission failures do not prove COW; Busy is a continuation, not
EFAULT. Owner=0 includes both an absent owner and a binding mismatch.
Instrumentation covers shared lifecycle argument copies, their immediate
owner-preparation result, and immediate retained poll output completion.
A later asynchronous output failure and legacy boolean-only copy callers
are not comprehensively instrumented by this slice.

The director must run both variants on signed HVF and inspect these records.
No cause fix is claimed until that evidence identifies the failing branch.

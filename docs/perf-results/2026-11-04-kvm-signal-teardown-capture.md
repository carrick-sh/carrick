# KVM signal teardown capture attempt

The teardown hang in [#1559](https://github.com/carrick-sh/carrick/issues/1559)
did not reproduce on the admitted main `af83bd8b90`. All seven reported signal
cases passed in two full KVM-lane attempts. This leaves the regression's
introducing commit and blocked teardown call **unattributed**. This report is
capture-round evidence, not a fix or acceptance of the original regression.

## Host and method

The dedicated dispatch clone was Linux x86_64, Debian kernel
`6.12.111+deb13-amd64`, with eight CPUs, about 20 GiB RAM and read/write
`/dev/kvm`. The worker ran as `carrick-dispatch-agent`, in group `kvm`, with no
effective capabilities. The existing job's VM-local gate lease remained in
force; no hypervisor lease was acquired.

Both attempts invoked the unchanged `just test-kvm` recipe. This is the
selection used by the merge-queue KVM job's acceptance step: KVM backend unit
tests, coordinator unit tests, then every Cargo-metadata KVM test target, with
the normal parallel and `serial_host` partitions. Neither timeouts nor test
concurrency were changed. `CARRICK_REQUIRE_KVM=1` was set by the recipe.
Run scopes were `dispatch-1559-capture` and `dispatch-1559-capture-2`.

A shell observer outside the checkout polled process/thread states from test
start. It sampled `ps -L` wait channels and `/proc/<pid>/task/*/{comm,wchan,
syscall,stack}` for test processes and carriers older than three seconds, then
attempted `eu-stack -p` and GDB `thread apply all bt` at four seconds. These
attachments stop threads and can perturb timing; these are not uninstrumented
performance runs.

The first observer recognized the test binary but missed carriers whose Linux
comm had become `carrick: /hello`. The second recognized that name too, but
serialized debugger captures could still miss short-lived carriers while
unwinding the test process. Neither attempt captured a hung signal carrier.
An asynchronous observer was therefore calibrated separately on the existing
intentionally parked deadline witness, as described below. The two successful
CLI populations do not establish that observation could not mask the race.

## Full-population results

| Selection | First attempt | Second attempt |
|---|---|---|
| KVM backend unit tests | 46 passed | 46 passed |
| CPL0 host coordinator unit tests | 94 passed | 94 passed |
| `x86_kvm_run`, parallel | 72 passed, 12 ignored | 72 passed, 12 ignored |
| `x86_kvm_run`, serial | 1 passed | 1 passed |
| Remaining KVM integration targets | One fixture-path failure | 106 passed, 1 ignored |

Every selected test binary finished. The first parallel CLI population took
12.75 seconds and the second 13.22 seconds. All seven issue cases passed in
both: `chld_killed`, `concurrent_timeouts`, `failed_frame_setup`,
`fault_badstack`, `handler_and_rt_sigreturn`, `handler_direction_flag`, and
`ignored_fault` (with their `mounted_static_x86_signal_` prefix and existing
suffixes).

The first lane's sole failure was `live_vcpu_x86::test_m2_musl_static_hello`:
its expected fixture path did not exist. The runner exports `CARGO_TARGET_DIR`,
so the recipe's fixture build wrote into the checkout-wide target directory,
while this test looks in the fixture crate's own target directory. An explicit
fixture build with that expected `--target-dir` supplied the missing artifact
before attempt two. No source or assertion was changed. Attempt two exited
zero: 319 passed, 13 ignored across the lane. There was no historical receipt
comparison against `0847bf644f`, so this is not a receipt-based `NEW=[]` claim.

## Observed waits, and their limits

The first parallel test process (PID 23716) was captured while still running.
GDB showed libtest waiting for completed tests and test threads in:

```text
poll
wait_timeout::imp::State::wait_timeout                  src/unix.rs:148
x86_kvm_run::run_mounted_binary_with_capture             x86_kvm_run.rs:1884
x86_kvm_run::run_mounted_binary                         x86_kvm_run.rs:1830
```

These are normal waits for live child processes. The population later finished
with no failed tests. They do not name a blocked teardown lock.

The separate calibration used
`serial_host::mounted_static_x86_deadline_captures_parked_wait`, scope
`dispatch-1559-calibrate`. Its fixture deliberately waits forever. Before
attachment, `ps -L` showed carrier PID 34728's main thread in
`futex_wait_queue`, executor TID 34738 in `futex_wait_queue`, and executor TID
34739 in `kvm_vcpu_block`. `eu-stack` captured:

```text
main:    Thread::park -> mpsc::Receiver::recv
         -> run_prepared_kvm_pool_with_debug
34738:   parking_lot::Condvar::wait -> RunQueue::take_row_bound
         -> executor::next_runnable
34739:   ioctl -> VcpuFd::run -> KvmVcpu::run -> run_member
         -> CarrierCpu::run_idle_peer -> executor::next_runnable
```

The main wait is `completed_rx.recv()` in
`crates/carrick-runtime/src/prepare.rs:406`, before pool teardown. The parked
executor waits on `cpu.idle_condvar` in
`crates/carrick-kernel/src/kernel/scheduler.rs:2995`. The other executor is in
KVM's idle-peer guest wait. These are the expected shape of the deliberately
blocked fixture, not evidence that a completed signal task is stuck tearing
down. A kernel-created `kvm-nx-lpage-re` thread also appeared; its failed
userspace unwind is not a guest executor stack.

The asynchronous calibration's GDB attachment overlapped the fixture's
existing debug request deadline. The request timed out, the harness killed its
scoped child, and GDB's later frames reported inaccessible memory. That
calibration **failed**, and its partial GDB output is not a successful
all-thread capture or a reproduction of the original hang. The complete
`eu-stack` output and pre-attach wait channels remain useful calibration data.
No deadlines were extended to accommodate the observer.

## Privileges and remaining work

Same-user GDB and `eu-stack` attachment work with the host's
`ptrace_scope=0`; no additional ptrace privilege was needed. Reading even
`/proc/self/stack` returns `Permission denied`. Kernel stack capture needs
scoped root/`CAP_SYS_ADMIN` access under this host's kernel policy. The shipped
deadline stack helper also attempted `sudo -n lldb` and failed; there is no
usable sudo LLDB capture in this clone. That failure leaves an empty
`backtrace.txt` even when the separate kernel post-mortem succeeds.

No Docker executable or macOS/HVF lane is available. Neither was run. There
was no attempt to change system privilege policy, use SIGQUIT without a known
handler, or infer kernel lock ownership from an empty stack file.

The next reproduction needs an observer that captures carriers independently
of test-process unwinding and records a live kernel snapshot before stopping
them. If a teardown hang occurs, capture both executor stacks and the main
thread's exact wait before the harness kills the scoped carrier. Only that
capture can distinguish a completion-channel wait, pool join, live KVM entry,
and retirement lock contention. The evidence here does not select among them.

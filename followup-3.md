# follow-up: a busy vfork/fork answers EAGAIN to the guest (go-hello's compile spawn)

**Labels:** follow-up, conformance (contention surfaced as an errno)

Round 2 of #2276 did not reach this with a reproduction (the signed receipt for
go-hello is on the director host only). What the code shows, for whoever owns
fork contention next:

- `NativeProcessEntry::fork` (`crates/carrick-el1-linux/src/native_process_runtime.rs`,
  the `ProcessNative::fork` impl) answers every `fork_owned` error with
  `self.fail(error)`, and `NativeProcessError::errno` maps `Busy` and `Exhausted`
  to `-11` (EAGAIN). A fork that loses a race for the parent's MM (another
  thread's COW fault, an unsettled earlier fork, a space editor; see
  `native_fork_busy_diagnostic_names_parent_space_editor` and
  `fork_reserve_refusal_retains_diagnostic_stage_and_retryable_errno`) is
  therefore guest-visible EAGAIN. AGENTS.md: contention is "not now", never an
  errno. Go's `os/exec` does not retry a clone EAGAIN, so `go run`'s compile
  spawn fails with `fork/exec ...: resource temporarily unavailable`, which
  matches the row's second symptom. A multithreaded Go parent makes this race
  likely: its other threads keep faulting while one thread forks.
- After the child is published, `vfork_suspend` errors are also turned into an
  errno with `self.fail(error)`, while the child stays alive and queued: the
  parent sees clone fail although a child exists. A published child must
  never be followed by an error return (the parent should return the pid, or
  park).

Acceptance: a fork/vfork that meets `Busy` keeps its owned operation, enrols
on the holder's release, probes once and reruns (witness "Busy once, then
success" with a second live thread faulting in the parent), and no path
returns an errno after the child is published.

# follow-up: go-hello's sidecar `fork/exec ...: bad address` (EFAULT) not yet placed

The vfork child's EFAULT (go-hello, native-child `go`) is reported by Go for
whichever child step failed (setsid, chdir, dup3 or execve), always as
`fork/exec <path>`. Round 2 did not reproduce it: x86 CPL0 still refuses a
native child's exec (`settle_native_exec_without_successor`, counted ENOSYS),
so the x86 KVM lane on the worker VM cannot run the go row, and ARM needs the
signed Mac. Candidates read in code:
`dispatch::native_exec_stage_request` returns `NativeExecStage::Fault` only for
an EFAULT from staging with a recorded address, which the owner fault selector
then resolves (`native_service_decision`, Fault stage); a fault the selector
cannot resolve becomes the guest's EFAULT. `scripts/dtrace/go-sidecar-fault.d`
records `hvpatch-first-touch-refused`, `el1-native-diagnostic` and every failing
syscall return on the sidecar path; one signed trace of
`go_run_hello_from_shell_prints_go_ok` names the step.

# follow-up: `entry_binding NativeServiceQuarantined` at dispatch.rs `native_service_completion`

go-hello's fatal (`at=1893:34` on main `59a2b28ab`) is
`native_service_completion(result, phase).unwrap_or_else(invalid_completion)`
in `arm_native_service_exit`: the begun native service returned
`NativeProcessError::Quarantined`. `begin_native_service` returns `Quarantined`
for (a) an exec payload or host-file stage that arrives with an owner wait,
(b) a `retry_exec_stage` whose operation is not a fault, and (c) a staged exit
with no operation; `begin_service_inner`/`settle_service_exit` can return it
too. Which one fired needs the signed trace (`el1-native-diagnostic` reason
string). If (a), it is contention turned fatal, against AGENTS.md: the owner
wait should be kept and the exit rerun after the release.

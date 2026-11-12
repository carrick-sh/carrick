# Post-no-return `execve` termination verdict (`process.exec.custody`)

Part of #1093 (S4c slice a).

## Authority and invariant

Per `execve(2)`, once `execve` passes the point of no return (predecessor
thread-group drain / old-MM teardown), it cannot restore the caller or return an
errno: *"the kernel kills the process with a `SIGSEGV` (`SIGKILL` until Linux
3.17) signal"*. `wait(2)` / `waitid(2)` therefore observe `WIFSIGNALED(status)`
with `WTERMSIG(status) == SIGSEGV` (`11`, `CLD_KILLED`, and no core-dump bit
when no core file is written; see `signal-abort-without-core.md`).

Carrick expresses that rule once in `carrick_signal_core::policy::ExecPastNoReturn`
(`ExecPastNoReturn::SIGNAL == Signal::SEGV`) and consumes it from:

- `carrick-el1-linux` native-child service completion (`service.rs`):
  `kill_refused_exec` is split into `exec_past_no_return()` (`SIGSEGV` when this
  exec fails after arming) and `retire_lost_exec_race()` (when a concurrent
  `exec`, `exit_group`, or fatal `SIGKILL` already won process closing, keeping
  that winner's terminal status via `resume_pending_lifecycle`);
- `carrick-runtime` root exec venue (`ThreadRuntimeState::exec_failed_past_no_return`);
- `#2152` follow-up: wire `RootExecVenue::fail_past_no_return` to
  `ExecPastNoReturn::SIGNAL` once `#2152` merges.

## VM-free witnesses (both ISAs)

- `carrick_signal_core::policy::tests::exec_past_no_return_verdict_is_terminal_sigsegv`
- `carrick_el1_linux::native_process_runtime::host_test_support::post_arm_exec_adoption_failure_is_sigsegv`
  (red at `097a7aa54`: `Some(9)` vs `Some(11)`; green on both
  `ParkedContextWords` / `X86Mmu` and `Aarch64ParkedContext` / `Aarch64Mmu`)
- `carrick_el1_linux::native_process_runtime::host_test_support::refused_exec_preparation_is_cancelled_exactly_once`
  (both ISAs)
- `carrick_el1_linux::native_process_runtime::host_test_support::{lost_exec_race_keeps_winner_signal_instead_of_sigsegv,exit_group_wins_over_an_in_progress_native_exec_drain,sigkill_wins_over_an_in_progress_native_exec_drain}`
  (both ISAs: concurrent `exit_group` or `SIGKILL` preserves the winner's status
  rather than overwriting it with `SIGSEGV`).

## Docker-oracle probe sketch (for director blessing)

Docker was not run in this worker slice. Proposed probe
`exec_past_no_return_sigsegv` for director oracle validation and blessing:

1. **Setup:** Set `RLIMIT_CORE` to `{0, 0}` so `WCOREDUMP` is deterministically
   clear across oracle and Carrick runs.
2. **Crafted ELF64 trigger (past `begin_new_exec`):** Write a temporary `+x`
   ELF64 binary matching the target architecture (`EM_AARCH64` on arm64,
   `EM_X86_64` on amd64) that passes initial header / `PT_INTERP` validation and
   crosses the point of no return before failing segment installation — for
   example, an `ET_EXEC` binary with a valid first `PT_LOAD` segment and a
   second `PT_LOAD` segment at an unmappable user address (above `TASK_SIZE` /
   non-canonical range), or a valid dynamically linked binary whose `PT_INTERP`
   passes ELF header validation and fails late `PT_LOAD` mapping in
   `load_elf_interp`.
3. **Single-thread child case:** `fork()` a child that installs a `SIGSEGV`
   handler and blocks `SIGSEGV` in its signal mask (verifying forced default
   `SIGSEGV` termination rather than predecessor handler entry), then calls
   `execve(trigger_path, argv, envp)`. If `execve` returns `-1`, `_exit(100)` so
   any pre-no-return errno is rejected immediately during oracle bring-up.
   Parent observes with `waitid(P_PID, child, &siginfo, WEXITED | WNOWAIT)` and
   reaps with `wait4(child, &status, 0, NULL)`, asserting:
   - `siginfo.si_code == CLD_KILLED` (`2`) and `siginfo.si_status == 11` (`SIGSEGV`);
   - `WIFSIGNALED(status)`, `WTERMSIG(status) == 11`, and `!WCOREDUMP(status)`.
4. **Two-live-thread child case:** `fork()` a child that spawns one sibling
   thread (`CLONE_VM | CLONE_THREAD | CLONE_SIGHAND`) parked on an in-process
   futex after publishing a readiness word, then invokes `execve(trigger_path,
   ...)` from the non-leader thread. Parent reaps once and asserts the same
   single `WIFSIGNALED(status) && WTERMSIG(status) == 11` termination after
   sibling drain (pairing with #1093 S4c slice e).
5. **Promotion order:** Validate the trigger binary first against the pinned
   native `arm64` Docker oracle (confirming exit via `SIGSEGV` rather than an
   early errno), cache the oracle verdict, and bind signed `carrick-embed` on
   ARM HVF and x86 KVM once S4c slices (b)–(e) complete x86 native-child exec.

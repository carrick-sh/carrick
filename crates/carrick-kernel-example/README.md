# carrick-kernel-example

This is the template for a bring-your-own execution backend. It has no VM:
tasks are host threads and guest memory is a `Vec<u8>`. What it implements is
exactly what your backend must: construct the kernel with your bridges,
translate your trap source into `SyscallRequest`, interpret every
`DispatchOutcome` you meet. What it deliberately does not do: run real guest
code, fork host processes, or emulate a CPU.

It is built from `pub` items of `carrick-kernel`, `carrick-hal`,
`carrick-guest-mem` and `carrick-abi` alone. `just check-layering` asserts
that no `carrick-runtime`, `carrick-vmm-*` or `applevisor*` crate is in its
closure.

## The proof

`tests/fork_pipe_wait.rs` runs one Linux process through
`SyscallDispatcher`:

```text
pipe2 -> fork -> (child: write "hi", exit_group 7) -> read -> wait4 -> exit_group 0
```

and asserts the read returned `"hi"`, the wait status is `7 << 8`
(`WEXITSTATUS(7)`) and two tasks ran. No VM, no host fork, no guest code. A
`pub` that regresses to `pub(crate)` on any item the backend names fails the
test at compile time.

Run it with `cargo test -p carrick-kernel-example`. `just test` names it on
its own line (`cargo test -p carrick-kernel-example --tests`) right after the
parallel workspace lane, because that lane is `--lib --bins` and never reaches
a crate's `tests/` directory; it forks no host process, so it needs no serial
slot.

## What a backend writes, file by file

| File | What it implements |
|---|---|
| `src/process.rs` | The three per-process seams. `ExampleProcess` is the `CarrierProcess` (the exact task binding, the kernel graph, per-tid contexts, the two mm-authority bindings). `ExampleMmBackend` is the `MmBackend` the root boots on: it reports the VMA source the dispatcher publishes at bind time and no frame inventory, because guest memory is one `Vec` per task. `ExampleStage1Projection` is the `Stage1MmProjection`: an ASID label this backend allocates and a root derived from it, with no page tables behind either. |
| `src/scripted.rs` | The trap source and the run loop. A script of `Step`s stands in for a guest's syscall entry; `Task::issue` is the backend's outcome interpreter, and `on_fork`/`on_exit` are the `Fork` and `Exit` arms written against the public kernel operations (`reserve_fork` -> `prepare_with_mm_backend` -> `prepare_fork_mm` + `fork_clone_with_prepared_mm_authorized` -> `PreparedFork::commit` -> `into_parts`; `retire_hvpatch_process_fds` -> `exit_task_key_eventually`). |
| `tests/fork_pipe_wait.rs` | The end-to-end proof above. |

Guest memory is `carrick_kernel::dispatch::LinearMemory`, the kernel's own
witness that `SyscallDispatcher::dispatch`'s `CurrentMmMemory` bound is
satisfiable from a plain `Vec`; a backend with a different memory model
implements `GuestMemory + CurrentMmMemory` itself.

## The outcomes it interprets

| Outcome | Here |
|---|---|
| `Returned` / `Errno` | The syscall's value; an errno fails the run (a scripted task has nothing to do with one). |
| `Exit` | `on_exit`: retire the process's fds, publish the zombie with `(code & 0xff) << 8`. |
| `Fork` | `on_fork`: a plain fork only. `CLONE_PIDFD`, `CLONE_PARENT`, tid stores, a child stack and vfork are refused by name rather than half-done. |
| `WaitOnHvpatchChild` / `WaitOnFds` | Re-dispatch after `yield_now`, bounded by `WAIT_BOUND` (5 s). There is no continuation reactor; a lost wake is a failed run, not a hang. |
| `SchedulerYield` | Complete with 0 and yield the host thread, the only execution lease this backend holds. |
| anything else | `ExampleError::Unsupported`, naming the outcome. |

## What it does not do, on purpose

- No signal delivery: a child's exit posts no `SIGCHLD`; the parent's `wait4`
  observes the zombie directly.
- No foreign-mm access: `mm_access_authority` is `None`, so
  `process_vm_readv`-class syscalls have no endpoint.
- No frame inventory: nothing is mapped, shared or COW-tracked.
- No `execve`, threads, futexes or timers: the script vocabulary is the six
  syscalls the proof needs. Adding one is adding a `Sys` variant and, if it
  can block, an outcome arm in `Task::issue`.

## Status

Experimental, like the kernel it drives. It is not on the product path, the
`carrick` binary ships none of it, and its API changes with the kernel's.

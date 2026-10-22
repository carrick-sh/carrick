# Issue #735: scheduler verdict attribution

The supplied `/tmp/735-evidence.txt` and issue comments distinguish guest
failure from the host test's later scheduling assertions. Signed attribution
remains provisional until the owner reruns the corrected artifact on HVF.

- `el1_sched_preemption_reaches_compute_loops`: the 8 ms, zero-preemption
  sample fails `assert!(measured.result.success())`, with exit 139 and the
  std sleep panic (errno 14 versus 4). It never reaches `preemptions >= 2`.
  `compute_pair` calls `sleep_ms(30)` after starting the sibling. That calls
  `std::thread::sleep`, whose Unix nanosleep failure assertion expects EINTR.
- `el1_sched_host_woken_thread_preempts_a_compute_loop`: the same success
  assertion fails after the same sleep panic. `pipe_compute` also calls
  `sleep_ms(30)`. Separately its `b_first_ms < 100` assertion measures host
  descheduling as well as guest scheduling; its pipe is now in-zone, despite
  the test's promise to exercise host completion.
- `el1_sched_pipe_pingpong_stays_in_guest`: `pingpong_rates` fails its guest
  success assertion, before checking any host-work slope. Guest iteration
  1199 is the final exchange of 200 warmups plus 1000 measured rounds. The
  fixture does not currently report which syscall failed or its return value.
  A sibling exits after writing that final byte, so memory edits during exit
  can coincide with the reader resuming. This ordering is a hypothesis, not
  a live trace proving the exact historical interleaving.

## Production refusal paths

The sleep input path is `dispatch_time::{nanosleep,clock_nanosleep}` ->
`read_timespec` -> `read_kernel_struct` -> `read_kernel_prefix`. The final
helper applies `map_err(|_| LINUX_EFAULT)` to `GuestMemory::read_bytes`.
On admitted ARM roots, `Aarch64EngineCore::read_bytes_raw` calls
`read_owner_bytes` / `continue_owner_read`; owner-lock, physical and supply
waits return `MemoryError::ReadSuspended` with a retained transfer. The ABI
helper discards that transfer and manufactures EFAULT. This is a product
error; no guest pointer fault is required.

The pipe adapter's `ipc::run` returns `written as i64` for any resumed
`StepStatus::Fault` on `PipeRead`, including zero bytes. `ValidatedCopy`
returns false if the live memory validator cannot authorize the destination.
Consequently a resumed read can report EOF while its pipe still contains the
byte. The operation must preserve its description and transfer custody and
hand back for memory resolution when no byte was copied. A partial read must
still return its positive prefix.

Applicable contracts: `kernel.el1.guest-scheduler`,
`kernel.el1.guest-run-queue`, and the IPC read/write contract. Deterministic
VM-free witnesses must exercise these production adapters before fixes;
no change to timing budgets, retries, concurrency or scheduler polling is
justified by this evidence. HVF and Docker are unavailable on this worker.

# Core dumps and crash capture: the port plan

**Status: guest core dumps and `WCOREDUMP` DO NOT WORK under HVPatch today.**
That is verified, not suspected:

- `finalize_persistent_process_terminal` calls `run.wait_status_encoding(false)`
  at `crates/carrick-runtime/src/vcpu_loop/mod.rs:2913`, and that is the ONLY
  call site of `wait_status_encoding` in the tree.
- `crates/carrick-runtime/src/run_result.rs:120` encodes
  `(signum & 0x7f) | if core_dumped { 0x80 } else { 0 }`, so a hardcoded `false`
  clears the core bit unconditionally.
- Every core-publication symbol has zero callers: their only callers lived in
  `run_vcpu_until_exit_inner`, deleted in `807174fa2`.

So a guest that dies on SIGSEGV/SIGABRT writes no core file, and `wait4` reports
a status whose `WCOREDUMP` bit is always 0.

This is the THIRD capability found to have lost its only caller in the welded
loop's deletion — after guest fault-signal delivery and `SignalThread` — and
unlike those two, nothing has hung or crashed to reveal it. It fails silently
and looks like a guest that simply did not dump.

## Ordering hazards — the part that makes this hard

A port that runs these calls in the wrong order produces an EMPTY core file,
which reads as success. In order:

- Crash Register Capture vs Sibling Teardown: capture_core_for_publication MUST execute while sibling threads and their vCPUs are still live (before begin_persistent_exit_sibling_drain and before withdraw_persistent_terminal_owner_runtime). If sibling threads are drained or retired first, their register files cannot be read, causing CrashQuorum to timeout (10s stall) or omit sibling NT_PRSTATUS notes.
- Process Metadata Snapshot vs Concurrent VM Mutations: dispatcher.core_process_snapshot must be invoked while all task threads are quiesced at the fork barrier, guaranteeing auxv, VMA maps (project_core_maps), and file mappings form an atomic snapshot without mid-crash mmap/exec drift.
- Core Memory Reads vs Address Space Retirement: engine.read_core_bytes must complete before begin_address_space_retirement / retire_in_process_address_space and before frame inventory commit. Retiring the MM/ASID first frees physical frames, causing core memory reads to fail or snapshot recycled memory.
- Child Output Flush vs FD Retirement & Parent Notification: write_hvpatch_child_output must flush stdout/stderr before retire_hvpatch_process_fds and before process.publish_exit_status wakes the parent. Otherwise, the parent can observe child termination and read EOF on redirected pipes before output is flushed.
- Atomic Core Publication vs Exit Status Publication: publish_core_atomic must succeed and atomically rename the core file before process.publish_exit_status publishes the wait status encoding. If exit status is published first with WCOREDUMP set, a racing parent wait4 can observe WCOREDUMP before the core file exists on disk.
- Core Publication Rollback on Terminal Failure: If process.publish_exit_status fails after publish_core_atomic succeeds, rollback_core_publication must delete the published core file to avoid leaving orphan artifacts when exit publication aborts.

## The sequence a correct port must implement

1. Guest EL0 triggers a synchronous fault (e.g. invalid memory dereference triggering SEGV_MAPERR) or receives an unhandled core-dumping signal.
2. HVF exits to host; ProductionHvpatchLoopJob::poll_with_engine receives TrapError::EL0Fault and calls lower_el0_fault(syndrome, elr, far) to obtain (signum, si_code, si_addr).
3. deliver_fault_signal in crates/carrick-runtime/src/vcpu_loop/signal.rs records the crash via kernel.record_fatal_signal(FatalSignalRecord { image_generation, tid, signo, code, addr }) and returns VcpuLoopOutcome::ProcessExit.
4. poll_with_engine routes the outcome via enter_terminal_with_outcome to begin_persistent_process_terminal(engine, PersistentTerminal::Outcome(outcome), context).
5. begin_persistent_process_terminal claims process exit (ProcessExitClaim::Owner) and evaluates fatal_for_terminal_owner(kernel.fatal_signal.recorded_for(fatal_image_generation), ...) to check for a core-dumping signal.
6. capture_core_for_publication runs BEFORE sibling drain: issues CrashCaptureGeneration from crash_capture, calls publish_crash_registers_if_requested on the crashing thread, raises the quiesce barrier to stop siblings and collect register votes via CrashQuorum, calls dispatcher.core_process_snapshot(&context) (invoking project_core_maps with boot_region_is_carrick_kernel_hole), reads readable memory regions via engine.read_core_bytes, formats ELF NT_PRSTATUS notes using core_note_resume_pair, serializes the ELF core via to_bytes_bounded, and produces PreparedCorePublication.
7. begin_persistent_process_terminal initiates begin_persistent_exit_sibling_drain to drain and retire sibling threads/vCPUs.
8. When sibling drain is complete, finalize_persistent_process_terminal is reached.
9. If process.is_child(), finalize_persistent_process_terminal flushes child buffered output using write_hvpatch_child_output(1, stdout) and write_hvpatch_child_output(2, stderr).
10. finalize_persistent_process_terminal publishes the core file atomically via kernel.dispatcher.publish_core_atomic(&prepared.snapshot, prepared.generation, prepared.bytes), creating <cwd>/core (or /core) and returning CorePublication.
11. finalize_persistent_process_terminal computes core_dumped = core_publication.is_some() and encodes wait status via run.wait_status_encoding(core_dumped) (setting the 0x80 WCOREDUMP bit).
12. finalize_persistent_process_terminal publishes the wait status via process.publish_exit_status(LinuxWaitStatus::from_wait_encoding(wait_encoding), ...), waking parent waiters.
13. The parent process reaps the child via wait4, observing WIFSIGNALED(status) == true, WTERMSIG(status) == signo, WCOREDUMP(status) == true, and finds the valid ELF core dump file at <cwd>/core.

## Per-symbol disposition

Every one of the 19 was assessed PORT — none redundant, none already live.

| symbol | file:line | role | port target |
|---|---|---|---|
| `boot_region_is_carrick_kernel_hole` | `dispatch/mem.rs:906` | Identifies memory regions inside Carrick's EL1 kernel-only address hole to exclude them from core dump PT_LOAD segments. | crates/carrick-runtime/src/dispatch/mem.rs:966 in project_core_maps during core_process_snapshot execution. |
| `project_core_maps` | `dispatch/mem.rs:961` | Projects the sanitized, sorted Linux-visible VMA list for core dumps, filtering kernel holes and hidden reservations, an | crates/carrick-runtime/src/dispatch/mod.rs:4259 in core_process_snapshot under MemState lock. |
| `CoreProcessSnapshot` | `dispatch/mod.rs:2449` | Represents a quiesced snapshot of user-space process state (identity, auxv, maps, file mappings, cwd, rlimit_core, dumpa | crates/carrick-runtime/src/vcpu_loop/mod.rs:5210 in capture_core_for_publication; constructed from kernel context and dispatcher locks during the quiesced crash safe poin |
| `CoreProcessSnapshot fields (auxv, maps, file` | `dispatch/mod.rs:2451` | Fields of CoreProcessSnapshot carrying the auxv vector, memory maps, file mappings, RLIMIT_CORE limit, and dumpable flag | crates/carrick-runtime/src/vcpu_loop/mod.rs:5245-5565 in capture_core_for_publication; accessed under dispatcher locks to format ELF auxv, VMA load segments, and mapping  |
| `CorePublication` | `dispatch/mod.rs:2460` | Receipt of an atomically published core dump file holding final path, byte count, and generation for rollback and wait-s | crates/carrick-runtime/src/vcpu_loop/mod.rs:2908 in finalize_persistent_process_terminal; returned from publish_core_atomic to set core_dumped = true for wait_status_enco |
| `CorePublication::generation` | `dispatch/mod.rs:2463` | Crash capture generation identifier on CorePublication correlating atomic temporary files, probe events, and rollbacks. | crates/carrick-runtime/src/vcpu_loop/mod.rs:2910 in finalize_persistent_process_terminal; used for USDT lifecycle probes and rollback tracking. |
| `CorePublicationError` | `dispatch/mod.rs:2467` | Typed error enum for failures during process snapshotting, serialization, filesystem creation, fsync, and atomic rename  | crates/carrick-runtime/src/vcpu_loop/mod.rs:5210 in capture_core_for_publication and line 2908 in finalize_persistent_process_terminal to fail closed on core write errors |
| `CorePublicationError variants (KernelIdentit` | `dispatch/mod.rs:2469` | Error variants indicating missing Kernel task identity or malformed 16-byte auxv image during core process snapshotting. | crates/carrick-runtime/src/dispatch/mod.rs:4241, 4245 in core_process_snapshot; returned when kernel task identity is unresolvable or auxv length is malformed. |
| `take_signal_pump_request` | `dispatch/mod.rs:4186` | Atomically swaps out the boolean flag requesting the host signal pump to start after a guest installs a signal handler v | crates/carrick-runtime/src/vcpu_loop/mod.rs:3845/4738 in poll_with_engine / service_outcome immediately after service_threaded_syscall returns, invoking kernel.fork.start |
| `core_process_snapshot` | `dispatch/mod.rs:4234` | Captures the authoritative process identity, auxv, VMA maps, file mappings, cwd, and core limits into a CoreProcessSnaps | crates/carrick-runtime/src/vcpu_loop/mod.rs:5275 in capture_core_for_publication, invoked from begin_persistent_process_terminal before sibling drain. |
| `publish_core_atomic` | `dispatch/mod.rs:4288` | Writes serialized core dump bytes to a temporary path in guest rootfs and atomically renames it to destination /core. | crates/carrick-runtime/src/vcpu_loop/mod.rs:2908 in finalize_persistent_process_terminal, after sibling drain completes and before process.publish_exit_status. |
| `publish_crash_registers` | `kernel/objects.rs:5485` | Publishes a thread's AArch64 register file to its crash_vote slot for a specific CrashCaptureGeneration. | crates/carrick-runtime/src/vcpu_loop/mod.rs:5188 in publish_crash_registers_if_requested, called for the fatal thread in capture_core_for_publication and for sibling thre |
| `withdraw_from_crash_capture` | `kernel/objects.rs:5506` | Records a withdrawal vote for a thread parked without a readable register file, allowing CrashQuorum to complete without | crates/carrick-runtime/src/vcpu_loop/mod.rs:5207 in withdraw_from_crash_capture, called from suspend_for_process_quiesce and blocking wait paths when a thread lacks a liv |
| `core_note_resume_pair` | `vcpu_loop/mod.rs:1221` | Selects (elr_el1, spsr_el1) for a synchronous fatal owner vs (resume_pc, resume_pstate) for sibling threads when buildin | crates/carrick-runtime/src/vcpu_loop/mod.rs:5389 in capture_core_for_publication when formatting NT_PRSTATUS registers for the core dump. |
| `recorded_for` | `vcpu_loop/mod.rs:1281` | Retrieves the FatalSignalRecord for a given image_generation from FatalSignalAuthority. | crates/carrick-runtime/src/vcpu_loop/mod.rs:2960 in begin_persistent_process_terminal (or line 2824 in finalize_persistent_process_terminal) to retrieve the recorded fata |
| `fatal_for_terminal_owner` | `vcpu_loop/mod.rs:1289` | Filters a recorded fatal signal to ensure it matches current image generation, terminal owner TID, and terminating signa | crates/carrick-runtime/src/vcpu_loop/mod.rs:2960 in begin_persistent_process_terminal (or line 2824 in finalize_persistent_process_terminal) to validate fatal signal auth |
| `ThreadRuntimeState::crash_capture` | `vcpu_loop/mod.rs:1904` | Holds the CrashCaptureAuthority reference on ThreadRuntimeState to query collection generations and issue crash capture  | crates/carrick-runtime/src/vcpu_loop/mod.rs:1904 / line 5239 in capture_core_for_publication on the persistent path. |
| `PreparedCorePublication` | `vcpu_loop/mod.rs:1961` | Carries the snapshot, serialized core bytes, generation, and fatal TID between preparation and publication across termin | crates/carrick-runtime/src/vcpu_loop/mod.rs:2822-2915 in begin_persistent_process_terminal (captured) and finalize_persistent_process_terminal (published). |
| `write_hvpatch_child_output` | `vcpu_loop/mod.rs:6818` | Flushes buffered stdout (fd 1) and stderr (fd 2) of an exiting multiplexed child process to host output descriptors. | crates/carrick-runtime/src/vcpu_loop/mod.rs:2920 in finalize_persistent_process_terminal, immediately after record_process_exit_begin and before publish_exit_status when  |

## Provenance and how much to trust this

Produced by a read-only Antigravity worker directed for this purpose, then
checked. The decisive claim — that `wait_status_encoding(false)` is hardcoded and
is the only call site — was verified directly against the tree before this
document was written, and it holds.

The rest is a MAP, not a verdict. Two cautions:

- It returned `open_questions: []`. Every automated pass in this campaign has
  come back fully confident, and three "CORPSE, confidence: certain" verdicts
  from an earlier pass turned out to be live production code. Empty
  open-questions means unexamined confidence, not absence of doubt.
- The port is only done when `coredumpfile` passes. `AGENTS.md`: "Definition of
  Done = live-verified end-to-end, not 'it compiles'." Read
  `conformance-probes/src/bin/coredumpfile.rs` for the observable result, and
  note that probe forks, so it also depends on the fork lifecycle being sound.

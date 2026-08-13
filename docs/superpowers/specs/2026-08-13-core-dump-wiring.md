# Wiring the ELF core writer to the crash path

**Status:** spec, 2026-08-13. The writer
(`carrick-runtime/src/core_dump.rs`) and the validator
(`carrick debug core`) are landed and externally validated; this is the
remaining third of the hybrid.md crash-dump criterion.

## The divergence that exists today

`SyscallDispatcher::core_dumped_si_code` (`dispatch/proc.rs`) reports
**`CLD_DUMPED`** to a waiting parent whenever the terminating signal is a
core-dumping one and `RLIMIT_CORE` is nonzero. carrick then writes **no core
file**. So the guest is told a core exists and none does.

Linux sets that bit only when it actually produced a dump. This is a
crash-dump semantic sourced from a guess rather than from carrick's own
kernel — exactly what hybrid.md says carrick must own. Note the honest
alternative is NOT to stop setting the bit: Docker sets it, so clearing it
would trade one divergence for another. The fix is to dump.

## What the writer needs, and where each piece already lives

`CoreDump` (see `core_dump.rs`) needs six things. K1 already owns five:

| field | source |
| --- | --- |
| `ProcessIdentity` (pid/ppid/pgrp/session, comm) | `Task` — `key()`, `parent()`, `process_group()`, `session()`, and the `Zombie::diagnostic_name` already captured at exit |
| `ThreadState` per thread | `Task::threads()` for the set; registers must come from each thread's saved register file |
| `SignalInfo` | the terminating signal is already known at `core_dumped_si_code`; `si_addr` comes from the fault that raised it |
| `FileMapping` (`NT_FILE`) | the VMA inventory — `kernel/snapshot.rs`'s `VmaSummary` and hvpatch `banked_mm`'s vma source |
| `MemoryRegion` (`PT_LOAD`) | same VMA inventory for extents; bytes read through the guest address space |
| `auxv` | already materialised for the guest at exec |

The one genuinely missing input is **per-thread registers at the moment of
death**. That is also the piece the M:N executor design
(`2026-08-13-mn-scheduler-design.md`) requires as its step 2 — "make the
`Thread` register file the authority" — so the two efforts converge here and
should share it rather than each growing a copy.

## Order of work

1. **Register file into `Thread`.** GPRs, PC, PSTATE, `TPIDR_EL0`, FP/SIMD.
   The 2026 SIMD/FP restore bug (`set_simd_fp_reg` zeroing V-registers) is the
   standing reminder that a partial register file is a silent corruptor — a
   core with wrong registers is worse than no core, because it is believed.
2. **Capture at the fatal signal**, before teardown releases the mm: the VMA
   list and the terminating `siginfo`.
3. **Write the core** where `core_dumped_si_code` decides `CLD_DUMPED`, so the
   bit and the file are decided by ONE condition and cannot disagree.
4. **Honour `RLIMIT_CORE`** as a size bound, and `/proc/sys/kernel/core_pattern`
   for the path, defaulting to `core` in the cwd.

## Verification

Red-first, and against the oracle rather than against ourselves — the same
method that caught the validator's `LINUX`-owner-note bug:

- a guest that dereferences null must leave a core that `carrick debug core`
  summarises with the right pid, comm, signal 11, and a `pc` inside the
  faulting function;
- the same program under native arm64 Docker produces a core whose note set
  and PT_LOAD shape carrick's must match;
- a conformance probe asserting `WCOREDUMP` and the file's existence together,
  so the bit can never again be set without a dump.

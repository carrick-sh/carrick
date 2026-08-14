# HVPatch live crash core: implementation and evidence

Date: 2026-08-14  
Base: `ec55da029009821215bb6ecb1c3b846364b7ca05`  
Implementation: `2a84f4cb5a5f318f129aab761ea5d763c8b6f93e`  
Validated code HEAD: `0b076654c1ad66624657268d3c7d2541514e6d31`
Lane: signed macOS/arm64 HVPatch, native-arm64 Docker oracle serialized after Carrick

## Result

Task 5/KD is implemented. A real fatal HVPatch guest signal now takes one
task-local all-vCPU safe point, captures the exact AArch64 register state of
every live guest thread and a coherent task/mm snapshot, serializes the existing
Linux ELF `CoreDump`, and atomically publishes `core` in the crashing task's
guest cwd. The authoritative exit publication sets WCOREDUMP/CLD_DUMPED only
when that same atomic publication succeeded.

The final signed run produced an 11,341,824-byte core with three exact threads,
13 ELF notes, 26 PT_LOADs, nine NT_FILE mappings, 18 auxv entries, and samples
from private-COW, shared, stack, heap, and file-backed memory. Carrick's strict
validator, LLVM readelf, and LLDB independently read the crash-produced file.
The lifecycle receipt's SHA-256 equals the archived artifact byte-for-byte.

## Source and authority survey

The implementation followed these existing authorities rather than creating a
second model:

- `Thread`/`Task` and Task 3's low Linux PID/TID, parent, pgrp, session, mm and
  ASID identities are the process/thread authority.
- `Aarch64EngineCore`/the live vCPU is the architectural register authority at
  the stop point. The captured shape is x0-x30, SP_EL0, PC/PSTATE,
  ELR_EL1/SPSR_EL1, TPIDR_EL0, V0-V31, FPSR, and FPCR.
- `MemState` supplies the exec auxv and current VMA inventory. The hidden heap
  reservation is projected only as the live `[heap_base, brk_current)` VMA;
  dynamic mappings retain private/shared permissions and guest file paths.
- Task 4's live stage-1 leaf and current global-frame owner supply memory bytes.
  A core read never treats an IPA or host address as a guest pointer.
- The existing `core_dump.rs` writer remains the one ELF format definition.
  It now emits Linux AArch64 FP/TLS notes and rejects incomplete generations and
  hard-size-bound violations.
- The existing guest overlay is the publication namespace. Its temporary-file,
  fsync, and same-directory rename operations are the only success edge.

## RED and root causes

The signed pre-change differential was run before implementation:

```
CARRICK_PROBE_RUN_ID=cr-69318-28387
DIFF coredumpfile (- linux + carrick)
< wcoredump_set=true
> wcoredump_set=false
remaining carrick procs = 0
```

The base code had an ELF writer and validator, but no live crash caller and no
complete per-thread register authority. Its previous wait-status guess could
describe a core-dumping signal without an artifact, so the immediate honest
state was WCOREDUMP clear.

The first expanded live implementation exposed a second, useful RED during the
final snapshot audit: the coherent VMA projection correctly included the live
brk prefix, but generic guest reads rejected it because the larger private
HVPatch backing reservation is PROT_NONE in syscall protection metadata.
Descriptor fallback and a stage-1 observer alone did not change that result.
The fix is deliberately narrow: after the task is fully quiesced and the exact
VMA snapshot has proved the range readable, `read_core_bytes` uses a backing-only
read. It loads the software page-table observer from the live TTBR when needed,
walks the current stage-1 leaf, and pins the exact current global-frame owner
generation across the volatile copy. Missing leaf/owner/backing remains a named
failure and never falls back to a retired descriptor.

## Crash generation and lock ordering

One terminal owner performs the following transaction:

1. Claim the process exit and bind the recorded fatal signal to the same Linux
   TID and `RunResult` terminating signal. A losing fatal thread cannot attach
   its state to another owner.
2. Acquire the process-local fork/exec admission barrier and publish a nonzero
   crash generation.
3. Snapshot the fatal owner's vCPU, set the quiesce flag, kick/wake every
   sibling, and wait. Each sibling publishes its complete vCPU snapshot into
   its exact Kernel `Thread` before unregistering/parking.
4. With every task thread stopped, load the live page-table observer, capture
   identity/auxv/VMA/cwd/RLIMIT, require one same-generation register record per
   task thread, and read every readable VMA through the current Task 4 view.
5. Serialize under RLIMIT_CORE, emit context/census/hash receipts, create a
   same-directory temporary, write+fsync it, and atomically rename to `core`.
6. Publish the Kernel wait status from `core_publication.is_some()`. Only then
   emit the lifecycle commit edge and proceed with fd/mm/frame/ASID retirement.

The quiesce barrier is task-local, so another HVPatch process sharing the VM is
not frozen. The process snapshot is taken inside the same all-thread safe point
as the register files. Error, bounded-policy decline, timeout, and interruption
all clear the advertised generation and release the barrier; none set WCOREDUMP.

## Artifact and reader proof

The final signed binary provenance is in
`2026-08-14-hvpatch-live-core-artifacts/signed-provenance.txt`:

- binary SHA-256 `a59a2e711c47eb127f5aacece202181ea96228770ef1106b967e1608812144e8`
- Mach-O UUID `2440CE07-746B-378A-8CAA-533E393176F9`
- `com.apple.security.hypervisor=true`, valid codesign, and
  `__TEXT,__dof_carrick` present
- expanded probe SHA-256
  `140554b5782e570bdab27f59e9bac459db8de0afee9efa82776dfbcc055fe03d`

Final signed serialized differential:

```
CARRICK_EXEC_BACKEND=hvpatch scripts/run-probe.sh coredumpfile
CARRICK_PROBE_RUN_ID=cr-96830-1620
MATCH coredumpfile                    # all 28 observations
remaining carrick procs = 0
```

The probe forks then execs its crash child, installs named private-COW/shared/file
mappings, starts one executing and one blocked sibling with distinct GPR,
SP, TPIDR_EL0, SIMD, FPSR and FPCR state, faults at exact `str x19,[x0]`, and
self-parses the resulting core. The same binary and assertions run in Docker;
there is no Carrick validator in the oracle half.

The archived actual core and raw receipt are:

- `coredumpfile.core`: SHA-256
  `a643fbc2d3d258fa6db99abd5ff3dda85dbcd2effa3c309f9d376a1c7aa8c7ef`
- `hvpatch-core-lifecycle.raw`: SHA-256
  `abec059e3a82e1a2aede6248409433ad8555f629c22e12af1e2e9661c94ce188`
- receipt `sha256=`:
  `a643fbc2d3d258fa6db99abd5ff3dda85dbcd2effa3c309f9d376a1c7aa8c7ef`

`carrick trace --profile hvpatch-core-lifecycle` exited 0 and its strict reader
reported generation 1, PID/TID 5, mm 495, ASID 5, required/collected threads
3/3, mappings/notes/loads 9/13/26, size 11,341,824, all six lifecycle phases,
and zero failed, drift, bounded, DTrace-error, and drop counts. The durable D
script states its provider ABI and its fixed nine-event-per-crash perturbation.

`carrick debug core` recovered signal 11, code 1, fault address 0, PID 5,
PPID 4, three distinct TIDs and exact GPR/PC/SP/PSTATE/TLS/SIMD/FP markers.
LLVM readelf found one PT_NOTE, 26 PT_LOADs, and the exact note population:
three each of PRSTATUS/FPREGSET/ARM_TLS plus PRPSINFO/SIGINFO/AUXV/FILE.
LLDB independently showed three threads, the SIGSEGV at `str x19,[x0]`, the
executing and syscall-blocked sibling PCs, distinct stacks/SIMD/FP state, and
read the private-COW mapping at guest VA `0x6700000000`.

## Negative and compatibility proof

On the same final signed binary, all 17 deterministic failpoints passed:
capture timeout/interruption/register absence/generation race/thread absence,
mm/auxv/VMA/file identity absence, memory read, validator, before-create,
unwritable path, short write, fsync, rename, and post-publication rollback.
Every row returned a normally completed parent probe with the child dead by
SIGSEGV, WCOREDUMP clear, no final core, no temporary, and scoped cleanup zero.
The complete run-ID table is in `failpoint-matrix.txt`.

RLIMIT_CORE=0 and RLIMIT_CORE=4096 also left WCOREDUMP clear and no final or
temporary file. The small limit failed before allocating/serializing the full
artifact because 11,332,377 readable bytes already exceeded the bound.

Final serialized Docker differentials were also MATCH with cleanup zero:

- `coredumpbit`, run `cr-96876-6588`
- `waitidspec`, run `cr-96924-12465`
- `sigchld`, run `cr-96968-16525`
- `signalexit`, run `cr-96820-31662`

## Tests and review fixes

Focused tests cover the bounded writer, exact FP/TLS validator, duplicate/missing
architecture notes, generation-bound Kernel register storage, atomic publication
and rollback, strict lifecycle parsing, terminal-owner binding, and translated
versus semantic/global-frame read resolution. Counts are archived in
`focused-tests.txt`.

The final audit fixed four issues before the implementation commit:

- moved identity/auxv/VMA/cwd/RLIMIT capture inside the all-thread quiesce;
- projected the live heap to brk instead of dumping the hidden reservation and
  added the VMA-authorized backing read described above;
- bound fatal authority to the exact terminal owner/signum so a losing fatal
  race is fail-closed;
- made core/profile readers reject duplicate per-thread architecture notes,
  missing/duplicate record classes, non-final summaries, generation drift,
  incomplete census, producer failure, loss, errors, drops, and bounds.

The exact-HEAD full gate then exposed that the VMA-authority projection still
retained the complete hidden heap reservation before unioning the live brk
prefix. The isolated test was RED 0/1. Commit `0b076654` excludes every hidden
reservation from the VMA summary and adds only `[heap_base, brk_current)`; the
exact test then passed 1/1, the VMA family 11/11, and memory-authority tests 3/3.
Because that authority gates core memory reads, all signed receipt/core,
validator, readelf, LLDB, failpoint, RLIMIT, and Docker differential evidence
above was recaptured after the fix on the validated HEAD.

Fresh `RUST_TEST_THREADS=1 just ci` at the validated HEAD exited 0. A preceding
full sample reached the unrelated probabilistic native-DSR kick oracle and
missed its microarchitectural exclusive-store landing class; the test's own
contract identifies that shape as coverage sampling rather than recovery
failure. Its exact retry passed 3/3, and the subsequent complete gate passed it
in-suite before finishing green.

## Known limitations

- Live crash publication is intentionally HVPatch/AArch64-only in this task.
  Other execution backends retain the HAL's fail-closed no-register default.
- The shipped synthetic `/proc/sys/kernel/core_pattern` is the plain relative
  name `core`; pipes, absolute paths, and `%` substitutions remain unsupported.
- `ProcMapsEntry` does not yet retain the original file-page offset, so NT_FILE
  page offsets are zero. Path, address extent, permissions, and actual bytes are
  retained; the differential's named mapping is offset zero.
- The guest overlay exposes no directory-fsync operation. The file contents are
  fsynced and rename visibility is atomic; host-power-loss directory durability
  is not claimed.
- DTrace per-CPU buffering can reorder lifecycle lines from different host
  threads. The strict reader therefore joins six unique phase IDs by one exact
  generation and validates producer counts/census/outcome instead of treating
  textual line order as a total order. The archived final receipt is ordered.

## Evidence inventory

All referenced receipts are under
`docs/perf-results/2026-08-14-hvpatch-live-core-artifacts/`:

- signed RED and cleanup
- final MATCH and cleanup
- real crash-produced core and raw lifecycle receipt
- strict validator JSON, LLVM note census, and LLDB transcript
- signed provenance and hashes
- 17-row failpoint matrix, RLIMIT matrix, wait/signal differentials
- focused-test counts

The implementation is independently review-ready after the exact evidence-HEAD
`RUST_TEST_THREADS=1 just ci` result recorded in the Task 5 handoff report.

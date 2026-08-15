# HVPatch live crash core: implementation and evidence

Date: 2026-08-14
Base: `ec55da029009821215bb6ecb1c3b846364b7ca05`
Implementation: `2a84f4cb5a5f318f129aab761ea5d763c8b6f93e`
Validated review-round code HEAD: `67f7227613e82fa8ebbb160ed276325819383de9`
Lane: signed macOS/arm64 HVPatch, native-arm64 Docker oracle serialized after Carrick

## Result

Task 5/KD is implemented. A real fatal HVPatch guest signal now takes one
task-local all-vCPU safe point, captures the exact AArch64 register state of
every live guest thread and a coherent task/mm snapshot, serializes the existing
Linux ELF `CoreDump`, and atomically publishes `core` in the crashing task's
guest cwd. The authoritative exit publication sets WCOREDUMP/CLD_DUMPED only
when that same atomic publication succeeded.

The final signed review run produced an 11,350,016-byte core with three exact
threads, 13 ELF notes, 27 PT_LOADs, five exact NT_FILE mappings, 18 auxv entries, and samples
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
  boot and dynamic mappings retain private/shared permissions, exact guest
  paths, and exact file-page offsets. Anonymous executable mappings are never
  promoted to file identity.
- Task 4's live stage-1 leaf and current global-frame owner supply memory bytes.
  A core read never treats an IPA or host address as a guest pointer.
- The existing `core_dump.rs` writer remains the one ELF format definition.
  It now emits Linux AArch64 FP/TLS notes and rejects incomplete generations and
  hard-size-bound violations. The actual serialized bytes are re-read and
  structurally validated before publication.
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
5. Serialize under RLIMIT_CORE, validate the exact serialized bytes, and emit
   context/census/hash receipts. Drain siblings and complete every fallible
   terminal-inventory edge before creating/writing/fsyncing/renaming `core`.
6. Retain rollback ownership across authoritative wait publication. Any late
   failure removes temporary/final state and leaves WCOREDUMP clear. Only a
   successful wait commit emits the lifecycle commit edge and permits
   fd/mm/frame/ASID retirement.

The quiesce barrier is task-local, so another HVPatch process sharing the VM is
not frozen. The process snapshot is taken inside the same all-thread safe point
as the register files. Error, bounded-policy decline, timeout, and interruption
all clear the advertised generation and release the barrier; none set WCOREDUMP.

## Artifact and reader proof

The final signed binary provenance is in
`2026-08-14-hvpatch-live-core-artifacts/signed-provenance.txt`:

- binary SHA-256 `1614190db25abf74a1123c5e4b57334aaf384c4f54d94f302e98f1ca5f597199`
- Mach-O UUID `368A4393-463C-3897-A7A2-8BA180495BD4`
- `com.apple.security.hypervisor=true`, valid codesign, and
  `__TEXT,__dof_carrick` present
- expanded probe SHA-256
  `16825b23f3bc3dc4ae1f1646391a4403b42f43062637f4474a5790675069dd4f`
- DTrace script SHA-256
  `9d15b22d1aaed5b54eb3fd361df801dbf5d094024f5b72fe2423ec5827321d7d`

Final signed serialized differential:

```
CARRICK_EXEC_BACKEND=hvpatch scripts/run-probe.sh coredumpfile
CARRICK_PROBE_RUN_ID=cr-20949-13766
MATCH coredumpfile                    # all 31 observations
remaining carrick procs = 0
```

The probe forks then execs its crash child, installs named private-COW/shared/file
mappings, starts one executing and one blocked sibling with distinct GPR,
SP, TPIDR_EL0, SIMD, FPSR and FPCR state, faults at exact `str x19,[x0]`, and
self-parses the resulting core. It also proves `/tmp/p` boot identity, a
`/tmp/coredumpfile/mapped.bin` mapping at file-page offset one, absence of an
anonymous executable mapping from NT_FILE, and instruction reconstruction from
the note's exact path/offset tuple. The same binary and assertions run in
Docker; there is no Carrick validator in the oracle half.

The archived actual core and raw receipt are:

- `coredumpfile.core`: SHA-256
  `0e040266fac5bb2b2001d60e49cb737636a0f60619d86b4cee1491c70b0f5af7`
- `hvpatch-core-lifecycle.raw`: SHA-256
  `fdbc23e3f35f6123363012d8875ede2e35a37beb8b3e57a5c842c2f2e86fbd5c`
- receipt `sha256=`:
  `0e040266fac5bb2b2001d60e49cb737636a0f60619d86b4cee1491c70b0f5af7`

`carrick trace --profile hvpatch-core-lifecycle` exited 0 and its strict reader
reported generation 1, PID/TID 5, mm 492, ASID 5, required/collected threads
3/3, mappings/notes/loads 5/13/27, size 11,350,016, all six lifecycle phases,
and zero failed, drift, bounded, DTrace-error, drop, join, and producer-order
counts. Every event carries its producer-time sequence 1 through 9. The CLI
sorts DTrace's per-CPU transport output by that sequence and validates the exact
phase/sequence relation before authenticating the supplied artifact's bytes.

`carrick debug core` recovered signal 11, code 1, fault address 0, PID 5,
PPID 4, three distinct TIDs and exact GPR/PC/SP/PSTATE/TLS/SIMD/FP markers.
LLVM readelf found one PT_NOTE, 27 PT_LOADs, and the exact note population:
three each of PRSTATUS/FPREGSET/ARM_TLS plus PRPSINFO/SIGINFO/AUXV/FILE.
LLDB independently showed three threads, the SIGSEGV at `str x19,[x0]`, the
executing and syscall-blocked sibling PCs, distinct stacks/SIMD/FP state, and
read the private-COW mapping at guest VA `0x6700000000`.

## Negative and compatibility proof

On the same final signed binary, all 19 deterministic failpoints passed:
capture timeout/interruption/register absence/generation race/thread absence,
mm/auxv/VMA/file identity absence, memory read, validator, sibling drain,
before-create, unwritable path, short write, fsync, rename, post-publication,
and authoritative wait-commit rollback.
Every row returned a normally completed parent probe with the child dead by
SIGSEGV, WCOREDUMP clear, no final core, no temporary, and scoped cleanup zero.
The complete run-ID table is in `failpoint-matrix.txt`.

RLIMIT_CORE=0 and RLIMIT_CORE=4096 also left WCOREDUMP clear and no final or
temporary file. The small limit failed before allocating/serializing the full
artifact because 11,332,377 readable bytes already exceeded the bound.

The final signed `CARRICK_NO_FPSIMD=1` control also completed the parent probe
with the child dead by SIGSEGV but WCOREDUMP clear and no final or temporary
file. The runtime named the missing live FP/SIMD authority; it never published
a zero-fabricated complete register set.

Five direct `carrick debug core` mutations of the live artifact (zero/short
`e_phentsize`, overflowing `e_phoff`, maximal `e_phnum`, and overflowing note
descriptor size) all exited nonzero without a panic. Unit mutations additionally
cover duplicate PT_NOTE, load offset/size overflow, and strict note/load bounds.

Final serialized Docker differentials were also MATCH with cleanup zero:

- `coredumpbit`, run `cr-20994-1896`
- `waitidspec`, run `cr-21040-22794`
- `sigchld`, run `cr-21084-26854`
- `signalexit`, run `cr-21127-14075`

## Tests and review fixes

Focused tests cover the bounded writer, exact FP/TLS validator, duplicate/missing
architecture notes, generation-bound Kernel register storage, atomic publication
and rollback, strict lifecycle parsing, terminal-owner binding, and translated
versus semantic/global-frame read resolution. Counts are archived in
`focused-tests.txt`.

Review round 1 then addressed every Important finding from the independent
`baa1aa63` review:

1. Fatal signal authority is image-generation-bound, clears only after a fully
   successful exec commit, and rejects a deterministically delayed pre-exec
   fatal participant. A current-image fatal record subsequently produced the
   signed live core above.
2. Disabled FP/SIMD capture is a named fail-closed condition, proven by the
   signed control above.
3. Boot and dynamic NT_FILE records preserve exact guest path and file-page
   offset, while anonymous executable mappings remain unlabeled. The live
   differential proves a nonzero-offset mapping and reconstruction of the
   fault instruction from the mapping tuple.
4. The bounded writer checks program-header counts and every layout operation,
   then validates the actual serialized ELF identity, PT_NOTE uniqueness, and
   strict note/load bounds before any rename.
5. Publication remains rollback-owned through sibling drain, terminal
   inventory, and authoritative wait commit; the two new late failpoints prove
   no final/temp file and no WCOREDUMP survive.
6. Durability reopen now distinguishes an unsupported descriptor-less backend
   from a disk-backed I/O failure. The latter is fatal to publication.
7. The CLI reader validates exact ELF/program-header geometry, checked table
   and segment arithmetic, one bounded PT_NOTE, and note payload shapes. Both
   unit and actual-live-artifact mutation suites reject malformed inputs.
8. The lifecycle producer records explicit sequence authority and producer
   order errors. The CLI reconstructs DTrace transport order, demands exact
   temporal phases, and authenticates the receipt digest/byte count against the
   explicitly supplied core. Sequence, arbitrary-digest, and artifact-byte
   mutations are all RED.

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

The exact review evidence commit is followed by a fresh
`RUST_TEST_THREADS=1 just ci`; its receipt is recorded in the ignored Task 5
handoff report so the gate names the exact review-ready HEAD.

## Known limitations

- Live crash publication is intentionally HVPatch/AArch64-only in this task.
  Other execution backends retain the HAL's fail-closed no-register default.
- The shipped synthetic `/proc/sys/kernel/core_pattern` is the plain relative
  name `core`; pipes, absolute paths, and `%` substitutions remain unsupported.
- The guest overlay exposes no directory-fsync operation. The file contents are
  fsynced and rename visibility is atomic; host-power-loss directory durability
  is not claimed.
- DTrace per-CPU buffering can reorder text emitted by different host threads.
  Producer-time `seq` fields are therefore the temporal authority; the strict
  reader reconstructs by sequence and rejects a sequence/phase mismatch.

## Evidence inventory

All referenced receipts are under
`docs/perf-results/2026-08-14-hvpatch-live-core-artifacts/`:

- signed RED and cleanup
- final MATCH and cleanup
- real crash-produced core and raw lifecycle receipt
- strict validator JSON, LLVM note census, and LLDB transcript
- signed provenance and hashes
- 19-row failpoint matrix, RLIMIT matrix, wait/signal differentials
- signed no-FP/SIMD control and malformed core reader matrix
- focused-test counts

The implementation is independently review-ready after the exact evidence-HEAD
`RUST_TEST_THREADS=1 just ci` result recorded in the Task 5 handoff report.

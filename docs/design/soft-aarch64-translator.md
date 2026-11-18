# Soft aarch64 translator: native copy-through (M2-0, M2-1)

Part of #1236. Status: M2-0 design approved; M2-1 host adapter per the
director's rulings (carrick-host-jit, carrick-softcpu-aarch64-host). Source: the
Arm Architecture Reference Manual (DDI0487) only; no third-party emulator,
decoder or JIT source was read.

**Ruling this design implements.** On an arm64 host the primary engine is
*native copy-through*: register-only guest instructions run as host code inside
translated blocks; every instruction whose meaning depends on guest privilege,
guest memory or guest control flow exits to a Rust handler. There is no
interpreter in M2.

## Existing-mechanism inventory

| Mechanism | Where | Reused how |
| --- | --- | --- |
| Typed A64 decode, 100% of production ELF and loader/vector words | `carrick-softcpu-aarch64` `decode_instruction` | The splitter classifies `Instruction` values, never raw bit patterns. |
| Virtual EL0/EL1 state, MRS/MSR access checks, EL0 traps | `carrick-softcpu-aarch64/src/state.rs` (`CpuState::mrs`/`msr`) | Exit handlers call these unchanged. |
| Exception entry/return (#2494) | `src/exception.rs` (`take_exception`, `eret`) | SVC/BRK/undefined/system-access handlers call these; HVC stays a `ProviderExit`. |
| Production word enumeration | `tests/typed_el1_image.rs` (`CARRICK_A64_ELF`), `tests/loader.rs` (`CARRICK_A64_LOADER_SPANS`), `carrick debug a64-census` | Same env-gated inputs drive the splitter witness. |
| x86 soft CPU block planning and emission | `carrick-softcpu-x86/src/cpu.rs`, `context.rs` | Model only: plan a block, emit, publish, run, exit with exact RIP. Its emitter is x86-specific and is not shared. |
| `JitCodeBuffer` (mmap RW, copy, mprotect RX) | moved whole (M2-1) to `carrick-host-jit`; `carrick-softcpu-x86` re-exports it | Both soft CPUs share it. M2-1 adds the aarch64 I-cache publication to `publish`. |
| aarch64 I-cache helpers | `carrick-vmm-kvm/src/kvm.rs` (IC IVAU only), `carrick-aarch64/src/icache.rs` (macOS `sys_icache_invalidate`) | Not moved here: one director-filed `seam` follow-up covers both. |
| Translation cache and budget (#616) | `carrick-softcpu-x86/src/cpu.rs` (`blocks: BTreeMap<BlockKey, CachedBlock>`, FIFO `block_order`, `TRANSLATION_CACHE_CAPACITY`) | **Not neutral yet.** It lives inside `SoftCpu`. This slice writes *no* cache: the dispatcher re-translates on each dispatch (see "Cache" below), so there is no second cache to retire later. |
| Invalidation authority (#601/#684/#681) | `carrick-core/src/mm/retirement/invalidation.rs`, `carrick-softmmu/src/retirement.rs` (`SoftVcpuSeat`) | Plugs in at the cache slice; see "Self-modifying code". |
| Soft machine seam | `carrick-vmm-soft` | Not on main (open in #2518). Host adapter placement below. |

**New in this slice:** the block splitter, the A64-to-A64 emitter with
entry/exit stubs, the exit handlers, the dispatcher over an `ExecuteBlock`
trait, and (M2-1) the arm64 host adapter that publishes and calls a block.

## Block model

A block starts at a guest PC and runs straight-line until the first
instruction that is not copy-through (an exit or a branch), or until a
structural budget (64 guest instructions, and never across a 4 KiB guest page:
the page is the unit of code invalidation). The terminator is part of the block.

### Register convention

Guest X0..X30 live **identity-mapped** in host X0..X30 inside a block. Copy-
through words then run unchanged, with no register renaming and no per-word
cost. That leaves only host SP for the engine:

- **Host SP points at the engine frame** while a block runs. The frame is the
  top of a dedicated, 16-byte-aligned host region (64 KiB) owned by the host
  adapter, so a host signal delivered mid-block writes below the frame into
  that region, never into guest-owned or adapter state.
- **Guest SP lives in the frame**, never in host SP: a guest SP is a guest
  virtual address, not a host one. Copy-through words that name SP (`ADD/SUB`
  immediate or extended with Rd/Rn=SP, logical immediate with Rd=SP) are
  rewritten: spill a scratch host register to the frame, load guest SP into
  it, run the word with each SP field replaced by the scratch, store it back if
  SP was written, reload the scratch. The scratch is chosen from X16, X17, X15
  so that it is not named by any operand field of that word.
- **NZCV lives in host NZCV** inside a block: loaded by the entry stub and
  saved by the exit stub before anything else can set flags.
- **PC is static**: every exit site knows its guest PC at emission time, so the
  exit stub records only an exit index. The dispatcher maps the index to the
  guest PC through the block's exit table.

Frame layout (64-bit slots; `translate::frame` constants):

| Offset | Content |
| --- | --- |
| 0x000..0x0f8 | guest X0..X30 |
| 0x0f8 | guest SP (the current banked SP, `CpuState::sp()`) |
| 0x100 | guest NZCV, in MRS NZCV format (bits 31:28) |
| 0x108 | saved host SP |
| 0x110 | scratch spill |

### Entry and exit stubs

A translated block is an AAPCS64 function `extern "C" fn(frame) -> exit_index`.

- **Entry:** save host x19..x30 on the host stack (`stp x29, x30, [sp, #-96]!`,
  then `stp` pairs), store host SP into `frame+0x108`, `mov sp, x0`, load NZCV
  through x1 (`ldr x1, [sp, #0x100]; msr nzcv, x1`), then load guest X0..X30
  (`ldp` pairs, `ldr x30`).
- **Exit site i:** `stp x0, x1, [sp]; movz x0, #i; b common_exit`. None of
  these sets flags.
- **Common exit:** store guest X2..X30, `mrs x1, nzcv; str x1, [sp, #0x100]`,
  restore host SP from the frame, restore x19..x30, `ret` with x0 = exit index.

An exit therefore returns an exact restart state: every instruction before the
exit site retired, none after it did, all GPRs, SP and NZCV are in the frame,
and the exit table gives the PC.

The only `unsafe` the host needs is: allocate, write, publish, and call that
function pointer. The stubs themselves are emitted words, built and checked by
safe code on x86.

## Instruction classes

| Class | Instructions | Lowering |
| --- | --- | --- |
| COPY | add/sub (imm, shifted, extended, with carry; flag-setting too), logical (imm, shifted), move-wide, bitfield, extract, conditional select/compare, multiply/divide, variable shifts, CLZ/CLS/RBIT/REV, NOP/YIELD, DMB/DSB | Word verbatim. SP-naming forms use the scratch rewrite. Barriers are EL0-legal; guest memory is reached only through handlers, so a native barrier orders the handler's host accesses too. Divide by zero yields 0 in A64, so no copy word can fault. |
| EXIT | ISB | End the block and retire ISB before fetching at the next guest PC (Arm ARM B2.3.4). |
| COPY (rewritten) | ADR, ADRP | The guest PC is known, so Rd gets a host `movz`/`movk` immediate sequence. Rd=XZR emits nothing. |
| EXIT memory | every load/store, pair, unprivileged (LDTR/STTR), literal, acquire/release, exclusive, LSE (LDADD) | v1: all memory operations exit. The handler computes the address from the frame, reads or writes `GuestMemory` and applies writeback. A fast path through the soft TLB is a later slice. Exclusives use a virtual per-CPU monitor in the handler state, never a host reservation. |
| EXIT system | MRS, MSR (register and PSTATE immediate), TLBI, AT, CLREX | `CpuState::mrs`/`msr`, with an EL0 trap taken through `take_exception`. TLBI is a typed event for the dispatcher's owner. MSR SCTLR_EL1 setting M stops the slice-0 probe (flat memory has no stage-1 walk). |
| EXIT exception | SVC, HVC, BRK, SMC, HLT, DCPS, ERET | `take_exception` / `eret`. HVC is a provider exit. SMC/HLT/DCPS are undefined in this EL0/EL1 profile. Guest SVC/HVC are never issued against the host. |
| EXIT wait | WFI, WFE, SEV, SEVL | Typed events; v1 stops on a wait. |
| EXIT undefined | `Unallocated`, SIMD/FP census gaps | Undefined-instruction exception (EC 0). A host JIT bug is a distinct `TranslateError`, never a guest exception. |
| BRANCH direct | B, BL | Exit to the target PC; BL first sets X30 = PC+4 with an immediate sequence. |
| BRANCH conditional | B.cond, CBZ/CBNZ, TBZ/TBNZ | The condition is evaluated natively: the word is copied with its offset relocated to a local taken stub. Both edges are exits. |
| BRANCH indirect | BR, BLR, RET | Always exit; the handler reads Rn from the frame, writes X30 for BLR, and sets PC. |

v1 never chains blocks: every edge returns to the dispatcher. Chaining direct
edges is a later slice and needs the invalidation hooks below.

## Cache, self-modifying code and the I-cache

- **Cache:** the dispatcher translates the block at each dispatch. This is the
  smallest honest slice: correctness first, no second cache. The N2 slice
  (design spec "N2: cache and code publication") extracts the x86 cache storage
  into a neutral crate. Cache identity includes guest PC, execution mode and
  profile, translation regime, the address-space root incarnation and ASID,
  and the physical code frame identity and generation of each covered page.
  Re-translation per dispatch is a known pathological cost
  and blocks any performance claim until N2 lands.
- **Guest IC IVAU / IC IALLU / code-page writes:** a guest code-page write or
  IC operation becomes an invalidation request to the shared authority
  (#601/#684/#681: `InvalidationGeneration`, `SoftVcpuSeat` members, the soft
  TLB code-page revoke). With no cache in v1 there is nothing to invalidate; once
  the cache lands, v1 of that may conservatively flush every block of the
  affected page.
- **Host I-cache publication:** after writing a block, the adapter cleans the
  data cache and invalidates the instruction cache to the point of unification
  for the written range, then ISB (`DC CVAU`, `DSB ISH`, `IC IVAU`, `DSB ISH`,
  `ISB`, with line sizes from `CTR_EL0`; Linux EL0 may read `CTR_EL0`).

## Host executable memory and where `unsafe` lives

`carrick-softcpu-aarch64` stays `#![forbid(unsafe_code)]`. All translation
(guest words to host words, stubs, exit tables) is safe code there and is
unit-tested on x86.

The `unsafe` is split across two crates, each `unsafe` block small and
commented:

- **`carrick-host-jit`** (neutral, `libc` only): `JitCodeBuffer` (mmap RW,
  write, mprotect RX; never W and X together), moved whole from the x86 soft
  CPU. `publish` makes the written range visible to instruction fetch before
  the RX switch. On aarch64 it runs the Arm ARM B2.4.4 sequence: `DC CVAU` per
  data line, `DSB ISH`, `IC IVAU` per instruction line, `DSB ISH`, `ISB`. Line
  sizes come from CTR_EL0 (DminLine, IminLine), and the clean or invalidate is
  skipped when CTR_EL0.IDC or DIC say it is not needed. On x86_64 it is a no-op,
  and any other host refuses. All of the crate's inline assembly is in
  `src/publish.rs`.
- **`carrick-softcpu-aarch64-host`**: `HostBlockRunner` implementing
  `carrick_softcpu_aarch64::dispatch::ExecuteBlock`. It publishes the block's
  words and copies the frame into the last frame of a 64 KiB region. It then
  calls the block's AAPCS64 function (the entry stub saves x19..x30 and host
  SP, the common exit restores them and returns the exit index) and copies the
  frame back. The only `unsafe` is that call. It runs only on Linux arm64;
  every other host gets `HostError::UnsupportedHost` from `new()`, never a fake
  success.

macOS (later): `MAP_JIT`, `pthread_jit_write_protect_np` toggled around the
write, `sys_icache_invalidate`, and the `com.apple.security.cs.allow-jit`
entitlement. Darwin reserves X18 and may clobber it, so on macOS guest X18 must
use the same frame-slot rewrite as SP. Linux leaves X18 to the program.

## Test plan

On x86 (this VM and every CI lane):

- Splitter: every production ELF code word and every loader/vector span word
  classifies, with 0 undefined; block count and size statistics are printed
  (env-gated, no pinned counts).
- Emitter: copy-through identity, rewritten immediates, relocated branch
  offsets, exact stub words, all hand-encoded from the Arm ARM and checked with
  `llvm-objdump` when `CARRICK_LLVM_OBJDUMP` is set.
- Handlers: known answers from the Arm ARM pseudocode. Apply each mutation
  independently, run the named handler integration test or dispatcher unit
  test, and restore the source before the next mutation. Each mutation below
  compiles and fails its named test.

  | File | One-line mutation | Test |
  | --- | --- | --- |
  | `handler.rs` | Replace the SPSel immediate arm's `if !el0` with `if false`. | `spsel_immediates_switch_the_active_stack_at_el1_only` |
  | `handler.rs` | Replace the PAN immediate arm's `if !el0` with `if false`. | `pan_immediates_set_and_clear_at_el1_only` |
  | `handler.rs` | Replace the UAO immediate arm's `if !el0` with `if false`. | `uao_immediates_set_and_clear_at_el1_only` |
  | `handler.rs` | Replace the DAIF immediate trap condition with `if el0`. | `uma_allows_daif_immediates_at_el0` |
  | `handler.rs` | Replace the AT arm's `if cpu.pstate.el == ExceptionLevel::El0` with `if false`. | `el1_at_requires_a_walk_and_el0_at_is_undefined` |
  | `handler.rs` | Replace the AT arm's `\|\| !matches!(` with `\|\| false && !matches!(`. | `higher_el_tlbi_and_at_are_undefined_at_el1` |
  | `handler.rs` | Replace the ERET error arm with `Err(_) => { next(cpu); Outcome::Continue },`. | `eret_and_hvc_are_undefined_at_el0` |
  | `handler.rs` | Change HVC's exception to `Exception::Svc(immediate)`. | `eret_and_hvc_are_undefined_at_el0` |
  | `state.rs` | Delete the access guard line for SP_EL0 with `StackSelect::El0`. | `sp_el0_sysreg_access_requires_the_el1_stack_bank` |
  | `state.rs` | Replace the VBAR write's `VirtualAddress(v & !0x7ff)` with `VirtualAddress(v)`. | `vbar_el1_write_discards_res0_bits` |
  | `state.rs` | Change the nTWE bit from 18 to 16. | `el0_waits_trap_under_their_own_sctlr_control` |
  | `dispatch.rs` | Add `&& !cpu.pstate.il` to the PC alignment fault condition. | `misaligned_pc_takes_priority_over_illegal_execution_state` |
  | `dispatch.rs` | Replace `else if cpu.pstate.il` with `else if false && cpu.pstate.il`. | `restored_il_takes_an_exception_before_the_next_guest_instruction` |
  | `exception.rs` | Delete `cpu.signal_local_event();` from ERET. | `svc_and_eret_restore_the_origin_and_signal_one_local_event` |
- Dispatcher: a `cfg(test)`-only `ExecuteBlock` double runs blocks of a small
  fixed instruction subset, only to test the dispatcher's exit mapping, PC
  continuation and stop reasons. It is never a product path.

On the arm64 runner (`#[cfg(all(target_arch = "aarch64", target_os = "linux"))]`;
`carrick-softcpu-aarch64-host/tests/native.rs` and `tests/boot_probe.rs`):

- Differential: the same register-only words run through the engine and
  directly in an AAPCS64 leaf published by `JitCodeBuffer`. X0–X15 and NZCV
  must match each other and the hand-derived answers.
- Fault delivery: execute up to ISB, then fetch the next block. An undefined
  AT or a misaligned LDAR reaches the EL1h vector with the matching ESR, ELR
  and FAR visible through native dispatch.
- Wait and prefetch traps: native dispatch observes the EL1 vector for WFI,
  WFE, illegal execution state and PC alignment. Under the flat memory profile,
  PC alignment precedes illegal execution state and both precede the first
  block fetch. A stage-1 walker must give instruction aborts priority over IL.
- Exit round trip: a block ending in MRS/SVC exits with the exact restart PC,
  and the handler resumes. An EL0 SVC vector reads SPSR_EL1 and ELR_EL1 then
  executes ERET. ERET restores the origin and sets the local event register,
  so the first WFE retires and the second reports a wait. SEV and SEVL also set
  this local bit. External wakeups and inter-CPU event delivery are separate.
- I-cache publication: a published function is rewritten at the same address
  and must return the new value (`carrick-host-jit`).
- Boot probe: the production EL1 image is entered at `carrick_el1_syscall`
  the way the loader's vector code enters it: EL1h, x0 = a trap frame for an
  SVC from EL0, x30 = a return sentinel. It runs on flat memory (PT_LOAD
  segments, a stack and the frame) under a block budget and prints
  `boots to PC=... after N blocks / fails at ...`. A diagnostic second pass
  maps each faulting page as zero to show what comes next. The stage-1 walker
  is a later shared-crate slice.

## System registers in the production image

The typed census follows the ELF's code mapping symbols and decodes the
generated loader/vector spans separately. The ELF entry symbol is
`carrick_el1_syscall`. Its function body has no MRS or MSR. Elsewhere in the
ELF the decoded accesses are:

| Access | Registers |
| --- | --- |
| Read | MPIDR_EL1, PAR_EL1, CNTFRQ_EL0, CNTVCT_EL0, ICC_IAR1_EL1 |
| Write | TTBR1_EL1, CNTV_CTL_EL0, CNTV_CVAL_EL0, ICC_EOIR1_EL1, ICC_SGI1R_EL1 |
| Read and write | TTBR0_EL1, SP_EL0, CONTEXTIDR_EL1, TPIDR_EL0, TPIDRRO_EL0, DAIF, FPCR, FPSR |

The generated vector spans also read TTBR0_EL1 and SP_EL0, and read and
write ELR_EL1, SPSR_EL1, ESR_EL1, FAR_EL1 and TPIDR_EL1. The splitter
witness checks every decoded access against the virtual EL1h register bank
on each census run. The handler tests give known answers for all observed
directions. On arm64, a native block sequence reads back CONTEXTIDR_EL1,
FPCR, FPSR, virtual MPIDR_EL1 and virtual CNTFRQ_EL0.

The EL1h bank holds passive timer and interrupt-controller state. CNTV_CTL_EL0
writes update ENABLE and IMASK and preserve the provider's ISTATUS bit.
FPCR and FPSR hold baseline AArch64 control and status fields. CONTEXTIDR_EL1,
CNTFRQ_EL0, MPIDR_EL1 and SPSR_EL1 enforce their register widths or fixed
reserved bits. Instruction-side FP state and feature extensions are separate.

The measured code contains no MSR to SCTLR_EL1. The probe enters a
syscall vector's callee with a fabricated trap frame, so the presence of
GIC or timer accesses elsewhere in the ELF cannot establish pre-MMU
execution of those instructions.

## Open questions for the director

1. (Ruled) `carrick-host-jit` and `carrick-softcpu-aarch64-host`, plus their
   `surfaces.toml` entries.
2. (Ruled) The reviewed assembly boundary is `carrick-host-jit/src/publish.rs`
   in the Semgrep and Rust-token authority checks (#2521).
3. Confirm that per-dispatch re-translation is acceptable until N2 extracts
   the cache.

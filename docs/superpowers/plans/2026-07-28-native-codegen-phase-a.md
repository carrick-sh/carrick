# Codegen Phase A: reserved address scratch

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the per-memory-access scratch spill/restore — 33.5% of
translated-execution samples — by reserving one GPR for the biased-address
computation, so an access computes its host address with no context traffic.

**Architecture:** Guest registers map 1:1 onto host registers today, so the
memory lowering has no free register and borrows a guest one per access,
spilling it to `DsrContext` slots 1120/1128 and restoring it. Reserve a third
register the way x18 and x28 already are: its guest value lives permanently in
a context slot, guest instructions naming it are virtualized through the
existing parameterized emitters, and the memory lowering owns the physical
register outright.

**Tech Stack:** Rust, AArch64 `dynasmrt`, `bad64` decode, the existing DSR
recovery matrix, Python for the offline census.

## Global Constraints

- Darwin/AArch64 native DSR only; no VMM/HVF, x86, KVM, bhyve or NVMM change.
- The recovery contract is non-negotiable: at every interruptible emitted word
  a fault or asynchronous kick must reconstruct exact guest register, SP, PC
  and memory state.
- Every behaviour change is red-first: the test fails for the intended reason
  before the implementation, and is shown red again by reverting the
  production mapping.
- The phase ships behind `CARRICK_DSR_RESERVED_SCRATCH=0|1` so both arms of a
  wall screen come from one binary (the method that produced the clean Spike 1
  rejection in `c4a5504c`).
- No wall-time claim without a paired alternating screen; no retention without
  the mechanism gate (the targeted census category must fall).
- Commits use Conventional Commit subjects with a body and
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Sample-weighted guest register census

Choose the reserved register from measurement, not from ABI folklore. Guest
instructions are emitted verbatim (`InstAction::Copy`), so the existing shape
census already contains them; this counts GPR usage inside the words the
classifier labels `guest:*`, weighted by how often each was sampled.

**Files:**
- Modify: `scripts/perf/shape_classify.py`
- Test: run against the committed census artifacts

**Interfaces:**
- Produces: `--registers` mode printing, per GPR x0-x30, the sample-weighted
  count of guest-classified words that name it.
- Consumers: Task 2 reserves the least-used GPR.

- [ ] **Step 1: Add the register-extraction helper**

Add to `scripts/perf/shape_classify.py`. AArch64 fixed-position register
fields cover the shapes that dominate guest code; anything else is skipped
rather than guessed, and the skipped weight is reported so the result cannot
silently under-count.

```python
def guest_registers(word: int) -> set[int] | None:
    """GPRs named by a verbatim guest word, or None if the shape is unmodelled.

    Rd/Rn/Rm sit at fixed positions for data-processing and load/store forms,
    which is what `coarse_family` already classifies as guest work. Returning
    None (rather than an empty set) keeps unmodelled encodings out of the
    tally instead of biasing it toward "register unused".
    """
    top = word >> 24
    regs: set[int] = set()
    # Unconditional/conditional branches and system: no GPR operands.
    if (word & 0x7C000000) == 0x14000000 or top == 0x54:
        return regs
    # Compare-and-branch / test-and-branch name Rt only.
    if top in (0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37):
        return {word & 0x1F}
    # Load/store (imm, unscaled, pair, reg-offset) and data-processing.
    if (word & 0x0A000000) == 0x08000000 or (word & 0x1C000000) == 0x08000000:
        regs |= {word & 0x1F, (word >> 5) & 0x1F}
        if (word & 0x3A000000) == 0x28000000:      # pair: Rt2
            regs.add((word >> 10) & 0x1F)
        if (word & 0x3B200C00) == 0x38200800:      # register offset: Rm
            regs.add((word >> 16) & 0x1F)
        return regs
    if (word & 0x1F000000) in (0x11000000, 0x0B000000, 0x0A000000, 0x1B000000):
        regs |= {word & 0x1F, (word >> 5) & 0x1F}
        if (word & 0x1F000000) in (0x0B000000, 0x0A000000, 0x1B000000):
            regs.add((word >> 16) & 0x1F)
        return regs
    if (word & 0x1F800000) in (0x12800000, 0x12000000):   # mov/logic immediate
        return {word & 0x1F}
    return None
```

- [ ] **Step 2: Add the `--registers` mode**

In `main()`, after the existing classification loop, gated on the new flag:

```python
    if args.registers:
        used: collections.Counter[int] = collections.Counter()
        modelled = unmodelled = 0
        for (family, word), count in hot_words.items():
            if not family.startswith("guest:"):
                continue
            regs = guest_registers(word)
            if regs is None:
                unmodelled += count
                continue
            modelled += count
            for reg in regs:
                if reg != 31:          # 31 is xzr/sp, never allocatable
                    used[reg] += count
        print(f"\n== guest register use (weighted; modelled {modelled}, "
              f"unmodelled {unmodelled}) ==")
        for reg in range(31):
            print(f"  x{reg:<2} {used[reg]:>7}")
        print("\nleast-used allocatable GPRs:",
              [f"x{r}" for r, _ in sorted(used.items(), key=lambda kv: kv[1])[:6]])
```

Register the flag with the other arguments:

```python
    parser.add_argument("--registers", action="store_true",
                        help="report sample-weighted guest GPR usage")
```

- [ ] **Step 3: Run it against the committed census**

Run:

```sh
python3 scripts/perf/shape_classify.py target/perf/native-shape-census-c.raw \
  --snapshots target/perf/native-shape-snapshots-b --registers
```

Expected: a full x0-x30 tally with `unmodelled` well below `modelled`. Record
the six least-used GPRs. If `unmodelled` exceeds `modelled`, stop and widen
`guest_registers` before trusting the ranking — an under-modelled decoder
would recommend a register that is actually hot.

- [ ] **Step 4: Record the choice**

Append one row to `docs/perf-results/native-dsr-shape-census.jsonl` with
schema `carrick.native-dsr-shape-census.v1`, record
`guest-register-census`, the full tally, the modelled/unmodelled split, and
the selected register with its rank. Call the selection `RESERVED_SCRATCH`.

- [ ] **Step 5: Commit**

Subject: `diagnostics(native): census guest register use for scratch selection`

---

### Task 2: Classify and virtualize the reserved register

Teach decode that the reserved register is host-owned, so any guest
instruction naming it is virtualized exactly as x18/x28 already are. The
emitters (`rewritten_virtual_word`, `emit_virtualized_register`) are already
parameterized by register index and context slot; only classification and the
action taxonomy are hardcoded to {18, 28}.

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/decode.rs`
- Modify: `crates/carrick-dsr-aarch64/src/types.rs`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`

**Interfaces:**
- Produces: `RESERVED_SCRATCH: u32` and `CTX_GUEST_RESERVED_SCRATCH` (the new
  context slot) in `gateway.rs`; `InstAction::VirtualizedReserved { word, op }`
  and `MemoryVirtualization::Reserved`.
- Consumes: Task 1's selected register index.
- Consumers: Task 3 uses the physical register as the address scratch.

- [ ] **Step 1: Add the context slot, with the offset pinned**

The `DsrContext` ABI is asserted on both the Rust and assembly sides; append
rather than insert so no existing offset moves. In `gateway.rs`, add the field
after the current tail and add its `offset_of!` assertion alongside the
others:

```rust
    /// Guest value of the reserved address scratch. The physical register is
    /// owned by the memory lowering, so the guest's value lives here for the
    /// lifetime of the process, exactly like guest x18 (slot 144) and guest
    /// x28 (slot 224).
    pub guest_reserved_scratch: u64,
```

```rust
const _: () = assert!(
    std::mem::offset_of!(DsrContext, guest_reserved_scratch)
        == CTX_GUEST_RESERVED_SCRATCH as usize
);
```

- [ ] **Step 2: Write the failing classification test**

In `crates/carrick-dsr-aarch64/src/decode.rs` tests:

```rust
#[test]
fn instructions_naming_the_reserved_scratch_are_virtualized() {
    // ldr x0, [xR] where R is the reserved scratch: must not classify as a
    // plain memory access, because the physical register is host-owned.
    let word = 0xf940_0000 | (crate::gateway::RESERVED_SCRATCH << 5);
    let action = classify(word, GuestVa(0x4000)).expect("classify");
    assert!(
        matches!(action, InstAction::Memory(memory)
            if memory.virtualization == MemoryVirtualization::Reserved),
        "got {action:?}"
    );
}
```

- [ ] **Step 3: Run and verify RED**

Run:

```sh
cargo test -p carrick-dsr-aarch64 instructions_naming_the_reserved_scratch
```

Expected: compile failure — `RESERVED_SCRATCH`, `MemoryVirtualization::Reserved`
do not exist.

- [ ] **Step 4: Implement classification**

Add `Reserved` to `MemoryVirtualization` and `VirtualizedReserved` to
`InstAction` in `types.rs`. In `decode.rs`, wherever the existing code tests
for register 18 or 28 to select a virtualization, add the same test against
`RESERVED_SCRATCH` producing the `Reserved` variants. Route the emit side
through the existing parameterized helpers with the new slot:

```rust
    InstAction::VirtualizedReserved { word, .. } => emit_virtualized_register(
        &mut assembler,
        &mut entries,
        plan,
        instruction.guest,
        word,
        RESERVED_SCRATCH,
        CTX_GUEST_RESERVED_SCRATCH,
        &mut recovery,
    )?,
```

Exclude the register from scratch selection so nothing else can borrow it:

```rust
    for register in (9_u32..=17).rev().chain((0_u32..=8).rev()).chain([30, 29, 27]) {
        if register == RESERVED_SCRATCH { continue; }
```

- [ ] **Step 5: Verify GREEN and prove the test is adversarial**

Run:

```sh
cargo test -p carrick-dsr-aarch64
```

Expected: all pass. Then temporarily change the classification to ignore
`RESERVED_SCRATCH`, confirm
`instructions_naming_the_reserved_scratch_are_virtualized` goes red, and
restore. Restore by editing the line back — never `git checkout` a file that
holds unrelated edits.

- [ ] **Step 6: Commit**

Subject: `feat(native): reserve a host register for biased addressing`

---

### Task 3: Spill-free memory lowering

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`

**Interfaces:**
- Consumes: `RESERVED_SCRATCH` from Task 2.
- Produces: a biased memory lowering that emits no context store/load for its
  address scratch, behind `CARRICK_DSR_RESERVED_SCRATCH`.

- [ ] **Step 1: Write the failing sequence test**

```rust
#[test]
fn reserved_scratch_lowering_emits_no_context_spill() {
    let words = assemble_biased_words(
        super::super::types::MemoryAccess {
            word: 0xf900_0420,                      // str x0, [x1, #8]
            op: bad64::Op::STR,
            base: super::super::types::MemoryBase::Register(bad64::Reg::X1),
            effective_address:
                super::super::types::MemoryEffectiveAddress::Immediate(8),
            writeback: super::super::types::MemoryWriteback::None,
            class: super::super::types::MemoryClass::Scalar,
            virtualization: super::super::types::MemoryVirtualization::None,
        },
        0x80_0000_0000,
    );
    // No store or load targeting the memory-scratch slots may remain.
    for word in &words {
        let is_ctx = (word & 0xFFC0_03E0) == 0xF900_0380
            || (word & 0xFFC0_03E0) == 0xF940_0380;
        let slot = ((word >> 10) & 0xFFF) * 8;
        assert!(
            !(is_ctx && matches!(slot, 1120 | 1128 | 1160 | 1168)),
            "scratch spill survived: 0x{word:08x}"
        );
    }
    assert!(
        words.iter().any(|word| word & 0x1F == RESERVED_SCRATCH),
        "the lowering must compute into the reserved register"
    );
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```sh
cargo test -p carrick-dsr-aarch64 reserved_scratch_lowering_emits_no_context_spill
```

Expected: FAIL — the current lowering spills to slot 1120.

- [ ] **Step 3: Implement**

In `emit_biased_memory`, when `reserved_scratch_enabled()`, use
`RESERVED_SCRATCH` as the address register and skip both the spill prologue
and the restore epilogue. The recovery action keeps `scratch_count: 0`,
because there is no borrowed guest register to restore; the base commit for
writeback forms is unchanged. Add the switch beside the existing compact one:

```rust
fn reserved_scratch_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DSR_RESERVED_SCRATCH").as_deref()
            != Some(std::ffi::OsStr::new("0"))
    })
}
```

- [ ] **Step 4: Verify GREEN and run the recovery matrix**

Run:

```sh
cargo test -p carrick-dsr-aarch64
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 'native_darwin::dsr::oracle::'
```

Expected: all pass, including
`biased_recovery_matrix_routes_every_offset_through_finish_exit`,
`compact_chained_writeback_scratch_survives_every_recovery_point` and
`dsr_live_kick_inside_compact_biased_writeback_keeps_the_base_unbiased`.
A failure here means recovery no longer reconstructs exact guest state — fix
before proceeding, never weaken the assertion.

- [ ] **Step 5: Commit**

Subject: `perf(native): compute biased addresses without spilling a guest register`

---

### Task 4: Gate the phase

**Files:**
- Modify: `docs/perf-results/native-wall-time-campaign.md`
- Modify: `docs/perf-results/native-dsr-shape-census.jsonl`

- [ ] **Step 1: Signed build and live smoke**

Run:

```sh
just build
just conformance-native smoke --workers 4
```

Expected: 23/23 MATCH. `go-sync` and `cpython-threading` break first on
register-allocation errors; a regression there blocks the phase.

- [ ] **Step 2: Mechanism gate — the census must move**

Run one traced go-build with `CARRICK_DSR_CODE_SNAPSHOT_DIR` set, then:

```sh
python3 scripts/perf/shape_classify.py <raw> --snapshots <dir>
```

Expected: combined slot-1120/1128/1160/1168 traffic falls from 33.5% of
matched JIT samples toward zero. If it does not fall, the phase is rejected
regardless of wall time — record the row and stop.

- [ ] **Step 3: Wall gate — paired alternating screen**

Six pairs, ABBA order, `CARRICK_DSR_RESERVED_SCRATCH=1` against `=0`, one
binary, using the same harness shape as the Spike 1 screen. Report the median
ratio and paired wins.

- [ ] **Step 4: Record and commit**

Append a `native-dsr-shape-census.jsonl` row with both gates and a RETAIN or
REJECT verdict, and update the campaign tracker's hypothesis table. State the
result candidly — Spike 1's value came from an honest rejection.

Subject: `perf(native): record the reserved-scratch phase result`

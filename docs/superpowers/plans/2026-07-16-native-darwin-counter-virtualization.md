# Native Darwin Counter Virtualization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Darwin-native guest `CNTVCT_EL0` reads use the same suspend-excluding timeline as `CLOCK_UPTIME_RAW` while preserving an inline vDSO fast path on known Apple counter modes.

**Architecture:** Decode `CNTVCT_EL0` into a typed counter action. A focused counter module selects a host source from Darwin's commpage mode: mode 1 uses `CNTVCT_EL0`, mode 3 uses `S3_4_C15_C10_6`, and other modes terminate at a correctness-first `mach_absolute_time` sensitive exit. Known modes emit a seqlocked commpage-offset sequence inside DSR and participate in signal/kick recovery and artifact normalization.

**Tech Stack:** Rust 1.96.0, edition 2024, bad64, dynasmrt AArch64 emission, Darwin commpage timebase, `libc::mach_absolute_time`, Carrick DSR execution oracle, signed native16k runtime.

## Global Constraints

- Never read Linux kernel source; use Carrick's clock contract and differential probes.
- Preserve direct `CNTFRQ_EL0` reads and the existing vvar ABI.
- Mode 1 and this host's mode 3 must stay inline; unknown modes must use `mach_absolute_time`, never raw `CNTVCT_EL0`.
- Every production change follows a witnessed red test.
- Build runnable artifacts with `just build`; use a unique `CARRICK_RUN_ID`; never run Carrick and Docker concurrently.
- Preserve the primary worktree's untracked `.codex/` and `last_1000_commits.txt` during integration.

## File Structure

- Create `crates/carrick-runtime/src/native_darwin/dsr/counter.rs` for commpage constants, typed mode selection, counter encodings, and fallback reads.
- Modify `types.rs`, `decode.rs`, and `block.rs` for the typed action and inline/fallback planning.
- Modify `emit.rs`, `mod.rs`, `artifact_spike.rs`, and `oracle.rs` for inline lowering, recovery, replay, and execution proof.
- Modify `profile.rs` and `native_darwin.rs` for diagnostics, fallback handling, and the host hazard gate.
- Modify `handoff.md` with final authority.

---

### Task 1: Darwin Counter Source Contract

**Files:**
- Create: `crates/carrick-runtime/src/native_darwin/dsr/counter.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`

**Interfaces:**
- Produces `HostCounterSource::{Cntvct, AppleTimebase, MachAbsoluteTime}`.
- Produces `host_counter_source()`, `counter_word(source, destination)`, `COMMPAGE_TIMEBASE_ADDRESS`, and `mach_absolute_time_ticks()`.

- [ ] **Step 1: Add red source-selection tests**

```rust
#[test]
fn known_modes_select_inline_sources() {
    assert_eq!(source_for_mode(1), HostCounterSource::Cntvct);
    assert_eq!(source_for_mode(3), HostCounterSource::AppleTimebase);
}

#[test]
fn unproved_modes_select_fallback() {
    for mode in [0, 2, 4, u8::MAX] {
        assert_eq!(source_for_mode(mode), HostCounterSource::MachAbsoluteTime);
    }
}

#[test]
fn source_words_preserve_destination() {
    assert_eq!(counter_word(HostCounterSource::Cntvct, 2), Some(0xd53b_e042));
    assert_eq!(counter_word(HostCounterSource::AppleTimebase, 2), Some(0xd53c_fac2));
    assert_eq!(counter_word(HostCounterSource::MachAbsoluteTime, 2), None);
}
```

- [ ] **Step 2: Witness RED**

Run `cargo test -p carrick-runtime native_darwin::dsr::counter::tests --lib`.
Expected: compilation fails because the source contract does not exist.

- [ ] **Step 3: Implement the minimal contract**

```rust
pub(super) const COMMPAGE_TIMEBASE_ADDRESS: u64 = 0x0000_000f_ffff_c088;
const COMMPAGE_MODE_ADDRESS: u64 = COMMPAGE_TIMEBASE_ADDRESS + 8;
const MRS_CNTVCT_X0: u32 = 0xd53b_e040;
const MRS_APPLE_TIMEBASE_X0: u32 = 0xd53c_fac0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostCounterSource { Cntvct, AppleTimebase, MachAbsoluteTime }

pub(super) const fn source_for_mode(mode: u8) -> HostCounterSource {
    match mode { 1 => HostCounterSource::Cntvct, 3 => HostCounterSource::AppleTimebase, _ => HostCounterSource::MachAbsoluteTime }
}

pub(super) const fn counter_word(source: HostCounterSource, destination: u32) -> Option<u32> {
    let base = match source {
        HostCounterSource::Cntvct => MRS_CNTVCT_X0,
        HostCounterSource::AppleTimebase => MRS_APPLE_TIMEBASE_X0,
        HostCounterSource::MachAbsoluteTime => return None,
    };
    if destination <= 31 { Some(base | destination) } else { None }
}
```

On aarch64 macOS, cache a volatile byte read at `COMMPAGE_MODE_ADDRESS` in a `OnceLock`. Off-target builds select fallback. Implement `mach_absolute_time_ticks()` with the existing `libc::mach_absolute_time` binding.

- [ ] **Step 4: Verify GREEN and commit**

Run `cargo test -p carrick-runtime native_darwin::dsr::counter::tests --lib -- --nocapture`.
Expected: all tests pass and this host reports `AppleTimebase`.

Commit as `feat(runtime): classify Darwin counter sources` with a why/what/verified body and `Co-Authored-By: Codex <codex@openai.com>`.

### Task 2: Typed Decode and Correctness Fallback

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/profile.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Consumes Task 1's `HostCounterSource`.
- Produces `CounterDestination::{Gpr(u8), Discard}`, `CounterRead`, `InstAction::CounterRead`, and `SensitiveKind::ReadCounter`.

- [ ] **Step 1: Change decoder and planner assertions to RED**

```rust
assert!(matches!(
    classify(0xd53b_e042, PC),
    Ok(InstAction::CounterRead(CounterRead { destination: CounterDestination::Gpr(2) }))
));
assert!(matches!(
    classify(0xd53b_e05f, PC),
    Ok(InstAction::CounterRead(CounterRead { destination: CounterDestination::Discard }))
));
assert!(matches!(classify(0xd53b_e002, PC), Ok(InstAction::Copy(_))));
```

Add a planner test that injects fallback mode and requires `PlannedExit::Sensitive` with `SensitiveKind::ReadCounter`.

- [ ] **Step 2: Witness RED**

Run `cargo test -p carrick-runtime dsr_counter_register_reads --lib` and `cargo test -p carrick-runtime counter_fallback_terminates --lib`.
Expected: the typed action and fallback do not exist.

- [ ] **Step 3: Implement typed decode and planning**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CounterDestination { Gpr(u8), Discard }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CounterRead { pub(super) destination: CounterDestination }
```

Split the MRS decoder: `CNTVCT_EL0` becomes `CounterRead`, while `CNTFRQ_EL0` remains `Copy`. The block planner keeps counter reads in the body for `Cntvct` and `AppleTimebase`; fallback becomes a `SensitiveExit { kind: ReadCounter, register, resume }` at the counter PC.

Add `SensitiveClass::ReadCounter`. The native sensitive handler writes `mach_absolute_time_ticks()` to a GPR and advances without a write for `Discard`.

- [ ] **Step 4: Verify GREEN and commit**

Run the two focused tests plus `cargo clippy -p carrick-runtime --lib -- -D warnings`.
Expected: typed decode, fallback planning/handling, and Clippy all pass.

Commit as `fix(runtime): type native virtual counter reads` with red-first evidence and the required co-author trailer.

### Task 3: Inline Commpage Lowering and Recovery

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/artifact_spike.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/oracle.rs`

**Interfaces:**
- Consumes Task 2's typed action and Task 1's counter word/address.
- Produces `emit_counter_read(...)` and `RecoveryAction::RecoverCounterRead`.

- [ ] **Step 1: Add suspended-host and destination-matrix oracle tests**

Execute a one-instruction x2 counter plan and bracket it with `host_clock_uptime_ns()`:

```rust
let before = crate::trap::host_clock_uptime_ns();
enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute counter");
let after = crate::trap::host_clock_uptime_ns();
let observed = ticks_to_ns(snapshot.x[2], crate::trap::host_counter().1);
assert!(before.saturating_sub(1_000) <= observed);
assert!(observed <= after.saturating_add(1_000));
```

Add table cases for x2, x15, x16, x17, x18, x28, and XZR. Initialize unrelated registers with distinct sentinels and assert they survive.

- [ ] **Step 2: Witness RED**

Run `cargo test -p carrick-runtime dsr_virtual_counter --lib -- --nocapture`.
Expected: emission rejects the new action or returns the raw counter roughly 8.7 hours ahead.

- [ ] **Step 3: Implement inline lowering**

Emit this logical sequence, using existing context slots for physical x15/x16/x17 preservation:

```text
save scratch registers
retry: materialize 0x0000000fffffc088
load offset_before
read mode-selected counter
load offset_after
compare offsets and retry if different
add stable offset
commit GPR, virtual x18/x28, or discard
restore non-destination scratch registers
```

Every emitted word maps to the guest counter PC. The live offset is loaded at execution and never stored in an artifact. `RecoverCounterRead` restores scratch and retries before commit; after commit it preserves the destination and resumes at PC+4.

- [ ] **Step 4: Extend replay and kick recovery proof**

Add the recovery variant to `WireRecoveryAction`. Extend fresh-versus-replay equivalence with a counter block. Add pre-commit and post-commit kick oracle cases asserting PC and register sentinels.

- [ ] **Step 5: Verify GREEN and commit**

Run:

```bash
cargo test -p carrick-runtime dsr_virtual_counter --lib -- --nocapture
cargo test -p carrick-runtime native_darwin::dsr::artifact_spike::tests --lib
cargo clippy -p carrick-runtime --lib -- -D warnings
```

Expected: all destination/recovery cases pass, the uptime bracket is green, and known modes produce no sensitive gateway.

Commit as `fix(runtime): inline suspend-safe native counters` with the suspended-host and no-gateway evidence.

### Task 4: Signed Runtime Proof and Integration

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `handoff.md`

**Interfaces:**
- Consumes Tasks 1-3.
- Produces a host-state-independent hazard gate and integration authority.

- [ ] **Step 1: Replace the obsolete raw-equivalence gate**

Rename the test to `native_virtual_counter_reads_track_clock_uptime_raw`. Execute the DSR-adjusted counter path rather than `host_counter().0`, keep the frequency/monotonic checks, and assert this host is not using fallback.

- [ ] **Step 2: Verify the formerly failing test**

Run:

```bash
cargo test -p carrick-runtime native_darwin::tests::native_virtual_counter_reads_track_clock_uptime_raw --lib -- --exact --nocapture
```

Expected: PASS without rebooting this host.

- [ ] **Step 3: Build, sign, and run the live proof**

```bash
just build
codesign --verify --verbose=2 target/release/carrick
codesign -d --entitlements - target/release/carrick 2>&1 | rg 'com.apple.security.hypervisor'
CARRICK_RUN_ID=native-counter-v1 target/release/carrick run --rm --pull never \
  --exec-backend native --native-page-profile native16k --pid private \
  --max-traps 18446744073709551615 localhost:5050/ltp:arm64 \
  /opt/ltp/testcases/bin/clock_gettime04
scripts/sudo/kill.sh native-counter-v1
```

Expected: entitlement present, guest exits, and no suspend-sized vDSO/syscall divergence. Preserve unrelated LTP/oracle noise separately and do not refresh the oracle cache.

- [ ] **Step 4: Record authority and run full CI**

Update `handoff.md` with raw/uptime measurements, mode 3, inline/fallback policy, and signed result. Run `RUST_TEST_THREADS=1 just ci` and require exit 0.

- [ ] **Step 5: Commit and fast-forward local main**

Commit as `test(runtime): prove native counter clock coherence` with signed and full-CI evidence. In `/Volumes/CaseSensitive/carrick`, verify `git rev-list --left-right --count main...codex/biased-exclusive-fusion-coverage` is `0 <positive>`, run `git merge --ff-only codex/biased-exclusive-fusion-coverage`, and verify the count becomes `0 0`. Preserve `.codex/` and `last_1000_commits.txt`; do not push origin.

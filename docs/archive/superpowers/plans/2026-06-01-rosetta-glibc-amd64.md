# Rosetta glibc `linux/amd64` — land + broaden Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the unmerged TTBR1/JIT layer that runs unmodified `linux/amd64` glibc-dynamic containers under Apple Rosetta 2 onto current `main`, then broaden it from `uname -m` to the arm64 flagship workloads (`python3 -m http.server`, `apt-get install`), backed by unit tests and a self-skipping amd64 conformance lane.

**Architecture:** Carrick runs Linux user-space binaries as native macOS threads inside per-process HVF vCPUs (EL0), trapping `svc #0` at EL1→EL2 and servicing Linux syscalls in Rust. For amd64, the x86-64 ELF is redirected to Apple's `rosetta` AArch64 interpreter (already on `main`), which JITs x86-64→AArch64 in guest space. This plan re-applies the *intent* of 5 commits from the stale `feat/rosetta-ttbr1` branch into today's refactored code (`trap.rs` moved `carrick-runtime`→`carrick-hvf`; `PageTableManager` moved into `carrick-mem`; the signal subsystem rewritten) — **not** a cherry-pick/merge. Each commit's original hunk and the current-`main` anchor are quoted inline.

**Tech Stack:** Rust (Cargo workspace), Apple Hypervisor.framework via the `applevisor` crate, AArch64 stage-1 MMU (TTBR0/TTBR1), Apple Rosetta 2 for Linux, Docker (differential oracle), DTrace USDT probes.

---

## Preamble — read before starting

**Branch:** all work is on `feat/rosetta-glibc-amd64` (already created off `main` at `f3a3097`).

**Build/run rules (from README):**
- **Never run a guest from a bare `cargo build` binary** — macOS strips the codesign signature and every run fails `HV_DENIED` (`0xfae94007`). Use `just build` (`scripts/build-signed.sh`) which re-applies the `com.apple.security.hypervisor` entitlement.
- `cargo build`/`cargo test` are fine for **compile-checking and host unit tests** (no HVF/Docker needed). The conformance integration tests re-sign the binary themselves (`ensure_signed`).
- No-panic gate: `cargo clippy --all-targets` must stay green — `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` are denied crate-wide (test code exempt). Do **not** add `-D warnings`.
- Guest runs require `CARRICK_ACCEPT_ROSETTA_TERMS=1`.

**Canonical commands:**
```sh
just build                                   # signed release binary at target/release/carrick
cargo test -p carrick-runtime --lib          # runtime host unit tests
cargo test -p carrick-abi -p carrick-spec --lib
cargo clippy --all-targets                   # no-panic gate
CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/amd64 --fs host debian:stable /bin/uname -m
CARRICK_TRACE_TRAPS=1 ...                     # raw per-syscall stream for bring-up
```

**What is ALREADY on `main` (do NOT re-port — verified by the anchor survey):**
- The amd64 *base*: `Platform` enum + `--platform`, per-platform image cache, `maybe_redirect_to_rosetta`, the licence/info ioctl handshake (`rosetta_handshake_ioctl`, `dispatch/mod.rs`), the TSO path end-to-end (`prctl` `PR_*_MEM_MODEL` → `DispatchOutcome::SetMemoryModel` → both run-loop arms in `runtime.rs` → `set_memory_model` → `set_hardware_tso` writing `ACTLR_EL1.EnTSO` bit 1, `carrick-hvf/src/trap.rs`), the `MapHostAlias` outcome + `map_aliased` (`carrick-mem/src/page_table.rs`) + the file-backed high-VA path, the vDSO `SHT_DYNSYM` table, `/proc/self/exe`.
- **`SCTLR_EL1` UCI(26)/UCT(15)/DZE(14)** at both vCPU bring-up sites — already present. **Drop** that part of the re-port.
- **`rt_tgsigqueueinfo(240)`** — already present and *superior* (propagates the caller siginfo via `record_pending_siginfo`, handles PID namespaces; the branch version discarded `_uinfo`). **Drop** the branch's add.

**What still needs porting (this plan):** TTBR1 enablement (TCR + `TTBR1_EL1`), the high-VA mmap canonical-check + pointer-tag strip + `no_access` overlay fix, EL0 feature-ID MRS emulation, the `CarrickSigframe` reorder + `esr_context`, `uname`→x86_64, `getrlimit(163)`.

**Hard coupling:** the TCR `TBI0/TBI1` bits (Task 5) and the 16-bit tag strip + `bits_55:48` canonical test (Tasks 4, 6) are interdependent — if `TBI` isn't set the top byte is part of the VA and the canonical test misclassifies tagged pointers. Land Tasks 4/5/6 together before the Phase 1 gate; do not run a guest between them.

---

## Phase 0 — Baseline & gap confirmation

### Task 0: Confirm the gap on current `main` and the arm64 baseline

**Files:** none (verification only).

- [ ] **Step 1: Build the signed binary**

Run: `just build`
Expected: `target/release/carrick` exists and is codesigned (build script prints the entitlement re-sign).

- [ ] **Step 2: Confirm arm64 is green (regression baseline)**

Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/arm64 --fs host debian:stable /bin/uname -m`
Expected: prints `aarch64`, exit 0.

- [ ] **Step 3: Confirm the amd64 gap exists on `main`**

Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 CARRICK_TRACE_TRAPS=1 target/release/carrick run --platform linux/amd64 --fs host debian:stable /bin/uname -m 2>&1 | tail -40`
Expected: does **not** print `x86_64`; Rosetta init fails. The trace should show the high-half `mmap` (an address with bits 63:48 set, e.g. `0xffff…`) being rejected — this is the TTBR0-only ceiling the plan fixes. Record the trap count and the failing syscall for comparison after Phase 1.

- [ ] **Step 4: Establish the unit-test baseline is green**

Run: `cargo test -p carrick-runtime -p carrick-abi -p carrick-spec --lib`
Expected: PASS. Run `cargo clippy --all-targets` → no new panics.

---

## Phase 1 — Re-port the unlanded core

Order: pure/unit-testable first (Tasks 1–3), then the coupled MMU triplet (4–6), then the HVF emulation pieces (7–8). The MMU/HVF pieces are gated by the real run at the **Phase 1 exit gate**, not by unit tests, because they require a live vCPU.

### Task 1: `CarrickSigframe` → Linux `rt_sigframe` layout (siginfo at offset 0)

Original commit `ef37588`. Rosetta's signal trampoline does `mov x1, sp; bl handler` — it reconstructs the `siginfo` pointer from `SP`, so `siginfo` MUST sit at `SP+0`. `main`'s `inject_signal` already computes `x1`/`x2` via `offset_of!`, so glibc/Go stay correct automatically after the move.

**Files:**
- Modify: `crates/carrick-abi/src/lib.rs` (`struct CarrickSigframe` ~1103–1114 and `impl CarrickSigframe::empty` ~1116–1131)

- [ ] **Step 1: Write the failing test**

Append to the test module in `crates/carrick-abi/src/lib.rs` (find the existing `#[cfg(test)] mod` with the `offset_of!` layout assertions, ~lines 2292–2383 per the survey):

```rust
#[test]
fn carrick_sigframe_has_siginfo_at_offset_zero() {
    // Rosetta's trampoline does `mov x1, sp`, so SP_EL0 must point at siginfo.
    assert_eq!(core::mem::offset_of!(CarrickSigframe, siginfo), 0);
    // ucontext immediately follows siginfo (Linux struct rt_sigframe order).
    assert_eq!(
        core::mem::offset_of!(CarrickSigframe, ucontext),
        core::mem::size_of::<LinuxSiginfo>()
    );
}
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `cargo test -p carrick-abi --lib carrick_sigframe_has_siginfo_at_offset_zero`
Expected: FAIL — on `main` `siginfo` sits after `magic/signum/_pad0/saved_x/saved_pc/saved_sp/saved_spsr` (offset ≠ 0).

- [ ] **Step 3: Reorder the struct**

In `crates/carrick-abi/src/lib.rs`, change the struct from (current):

```rust
pub struct CarrickSigframe {
    pub magic: u64,
    pub signum: u32,
    pub _pad0: u32,
    pub saved_x: [u64; 31],
    pub saved_pc: u64,
    pub saved_sp: u64,
    pub saved_spsr: u64,
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
    pub _reserved: [u64; 6],
}
```

to (siginfo/ucontext first; carrick-private bookkeeping after; `_reserved` stays last):

```rust
pub struct CarrickSigframe {
    // siginfo + ucontext FIRST so SP_EL0 points directly at siginfo, matching
    // Linux `struct rt_sigframe`. Apple Rosetta's trampoline does `mov x1, sp`
    // and reconstructs the siginfo pointer from SP, so it MUST live at SP+0.
    // glibc/Go read x1/x2 (which inject_signal sets via offset_of!) and are
    // unaffected by the move.
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
    // carrick-private bookkeeping for rt_sigreturn (not part of the Linux ABI):
    pub magic: u64,
    pub signum: u32,
    pub _pad0: u32,
    pub saved_x: [u64; 31],
    pub saved_pc: u64,
    pub saved_sp: u64,
    pub saved_spsr: u64,
    pub _reserved: [u64; 6],
}
```

Mirror the field order in `impl CarrickSigframe::empty()` (move the `siginfo:`/`ucontext:` initializers to the top, keep all fields).

- [ ] **Step 4: Run the test, verify it passes**

Run: `cargo test -p carrick-abi --lib carrick_sigframe_has_siginfo_at_offset_zero`
Expected: PASS. Also run the whole abi suite: `cargo test -p carrick-abi --lib` (the existing layout/offset_of tests must stay green).

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-abi/src/lib.rs
git commit -m "rosetta: CarrickSigframe -> Linux rt_sigframe layout (siginfo at offset 0)

Re-port of ef37588 onto main. Rosetta's signal trampoline reconstructs the
siginfo pointer from SP, so siginfo must sit at SP+0. inject_signal already
uses offset_of! for x1/x2 so glibc/Go are unaffected.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 2: `uname` reports `x86_64` under Rosetta

Original commit `bb28946`. `carrick_x86_64()` does NOT exist on `main`; `uname` is hardcoded to `carrick_aarch64()`.

**Files:**
- Modify: `crates/carrick-abi/src/lib.rs` (`impl LinuxUtsname`, after `carrick_aarch64()` ~line 764)
- Modify: `crates/carrick-runtime/src/dispatch/proc.rs` (`fn uname` ~1203–1212)

- [ ] **Step 1: Write the failing test (abi)**

Append to `crates/carrick-abi/src/lib.rs` test module:

```rust
#[test]
fn carrick_x86_64_reports_x86_64_machine() {
    let u = LinuxUtsname::carrick_x86_64();
    assert!(u.machine.starts_with(b"x86_64\0"));
    // Everything else matches the aarch64 utsname.
    let a = LinuxUtsname::carrick_aarch64();
    assert_eq!(u.sysname, a.sysname);
    assert_eq!(u.release, a.release);
}
```

- [ ] **Step 2: Run, verify it fails to compile**

Run: `cargo test -p carrick-abi --lib carrick_x86_64_reports_x86_64_machine`
Expected: FAIL — `no function ... carrick_x86_64`.

- [ ] **Step 3: Add `carrick_x86_64()`**

In `crates/carrick-abi/src/lib.rs`, inside `impl LinuxUtsname`, after `carrick_aarch64()`:

```rust
    /// Same as [`Self::carrick_aarch64`] but reports `machine = x86_64`. Used
    /// for amd64 containers running under Rosetta translation, so the x86_64
    /// guest — and Rosetta itself — sees its real emulated architecture.
    pub fn carrick_x86_64() -> Self {
        let mut utsname = Self::carrick_aarch64();
        utsname.machine = [0; LINUX_UTSNAME_FIELD_SIZE];
        write_linux_c_field(&mut utsname.machine, b"x86_64");
        utsname
    }
```

- [ ] **Step 4: Run, verify it passes**

Run: `cargo test -p carrick-abi --lib carrick_x86_64_reports_x86_64_machine`
Expected: PASS.

- [ ] **Step 5: Select it in the `uname` handler**

In `crates/carrick-runtime/src/dispatch/proc.rs`, replace the body of `fn uname`:

```rust
        fn uname(this, cx, address: GuestPtr) {
            let memory = &mut *cx.memory;
            // Under Rosetta translation the guest is x86_64 — report that
            // machine (we know it's Rosetta because the loaded executable is
            // the interpreter). Otherwise report native aarch64.
            let uts = if this.proc.lock().executable_path == crate::runtime::ROSETTA_INTERPRETER {
                LinuxUtsname::carrick_x86_64()
            } else {
                LinuxUtsname::carrick_aarch64()
            };
            if memory.write_bytes(address.0, uts.abi_bytes()).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }
```

`ROSETTA_INTERPRETER` (`crate::runtime`, `pub(crate) const`) and `executable_path` (on the proc struct) both exist on `main`.

- [ ] **Step 6: Compile-check + clippy**

Run: `cargo build -p carrick-runtime` then `cargo clippy --all-targets`
Expected: builds; no new panics. (Behaviour is asserted live at the Phase 1 gate and in the conformance lane, Task 12.)

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-abi/src/lib.rs crates/carrick-runtime/src/dispatch/proc.rs
git commit -m "rosetta: uname reports x86_64 for Rosetta guests (re-port bb28946)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 3: `getrlimit(163)` sharing `prlimit64`'s limits

Original commit `e168597`. `163` is NOT registered; `prlimit64` was rewritten since the branch (dynamic `NOFILE` via `this.io.nofile_soft`, `STACK` via `LINUX_RLIMIT_STACK_SOFT`, a `resource >= 16` EINVAL guard, a NOFILE write-back path). **Do not lift the original helper verbatim** — extract from `main`'s current `prlimit64` match instead.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/time.rs` (`fn prlimit64` ~593–683; add `fn getrlimit` + a shared `rlimit_for_resource` free fn)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs` (syscall table — add `163 => getrlimit`)

- [ ] **Step 1: Extract the limit-selection into a shared free fn**

In `crates/carrick-runtime/src/dispatch/time.rs`, lift the current `match resource { … }` body out of `prlimit64` into a module-level free fn that takes the dynamic inputs as parameters (so it does not need `&self`). Replace the inline `let limit = match resource { … };` inside `prlimit64` with a call to it, and define:

```rust
/// The resource limit carrick reports for `getrlimit`/`prlimit64`. Shared so
/// the old 2-arg and new 4-arg forms agree. `nofile_soft` is threaded in
/// because RLIMIT_NOFILE's soft cap is dynamic (set by setrlimit).
fn rlimit_for_resource(resource: u64, nofile_soft: u64) -> LinuxRlimit {
    const LINUX_RLIMIT_DATA: u64 = 2;
    const LINUX_RLIMIT_STACK: u64 = 3;
    const LINUX_RLIMIT_NPROC: u64 = 6;
    const LINUX_RLIMIT_NOFILE: u64 = 7;
    const LINUX_RLIMIT_AS: u64 = 9;
    match resource {
        LINUX_RLIMIT_NOFILE => LinuxRlimit::new(nofile_soft, 1024 * 1024),
        LINUX_RLIMIT_NPROC => LinuxRlimit::new(8192, 8192),
        LINUX_RLIMIT_STACK => {
            LinuxRlimit::new(crate::memory::LINUX_RLIMIT_STACK_SOFT, LINUX_RLIM_INFINITY)
        }
        LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
            LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
        }
        _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
    }
}
```

In `prlimit64`, replace its limit-selection with `let limit = rlimit_for_resource(resource, this.io.nofile_soft.load(std::sync::atomic::Ordering::Relaxed));` (keep `prlimit64`'s existing `resource >= LINUX_RLIM_NLIMITS` EINVAL guard, pid validation, and NOFILE write-back untouched). **Verify** the exact constant names against the file before editing (`LINUX_RLIMIT_STACK_SOFT` vs the original's `LINUX_STACK_SIZE` — use whatever `main` defines).

- [ ] **Step 2: Add the `getrlimit` handler**

In `crates/carrick-runtime/src/dispatch/time.rs`, add next to `prlimit64`:

```rust
        // getrlimit(2) (syscall 163) — the older 2-arg form glibc and Apple
        // Rosetta still use. Equivalent to prlimit64 reading the current limit.
        fn getrlimit(this, cx, resource: u64, rlimit: GuestPtr) {
            const LINUX_RLIM_NLIMITS: u64 = 16;
            if resource >= LINUX_RLIM_NLIMITS {
                return Ok(LINUX_EINVAL.into());
            }
            let memory = &mut *cx.memory;
            let limit = rlimit_for_resource(
                resource,
                this.io.nofile_soft.load(std::sync::atomic::Ordering::Relaxed),
            );
            if rlimit.0 != 0 && write_kernel_struct_raw(memory, rlimit.0, &limit).is_err() {
                return Ok(LINUX_EFAULT.into());
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }
```

- [ ] **Step 3: Register it in the syscall table**

In `crates/carrick-runtime/src/dispatch/mod.rs`, add to the `define_syscall!`/match table (order is immaterial — dispatch is by number; put it near the other limit syscalls):

```rust
        163 => getrlimit,
```

- [ ] **Step 4: Write a unit test for the shared helper**

In `crates/carrick-runtime/src/dispatch/time.rs`, add a `#[cfg(test)] mod` (or extend an existing one):

```rust
#[cfg(test)]
mod rlimit_tests {
    use super::*;
    #[test]
    fn nofile_uses_dynamic_soft_cap() {
        let r = rlimit_for_resource(7, 2048); // RLIMIT_NOFILE
        assert_eq!(r.rlim_cur(), 2048);
        assert_eq!(r.rlim_max(), 1024 * 1024);
    }
    #[test]
    fn unknown_resource_is_infinity() {
        let r = rlimit_for_resource(99, 1024);
        assert_eq!(r.rlim_cur(), LINUX_RLIM_INFINITY);
    }
}
```

Adjust the accessor names (`rlim_cur`/`rlim_max`) to whatever `LinuxRlimit` exposes — check the struct before writing.

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test -p carrick-runtime --lib rlimit_tests` then `cargo clippy --all-targets`
Expected: PASS; no new panics.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/time.rs crates/carrick-runtime/src/dispatch/mod.rs
git commit -m "rosetta: getrlimit(163) sharing prlimit64 limits (re-port e168597)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 4: 16-bit pointer-tag strip in syscall-path mapping lookups

Original commit `1d9bc11`. Apple Rosetta tags pointers in the top 16 bits (a 48-bit `TaggedPointer` space, broader than the 8-bit hardware TBI). The syscall-path region lookups must strip it so a tagged guest pointer resolves to its backing region. **Couple with Task 5 (TBI) and Task 6.**

**Files:**
- Modify: `crates/carrick-hvf/src/trap.rs` (add `strip_pointer_tag`; use it in `mapping_for_range` ~2292 and `mapping_for_range_mut` ~2298)

- [ ] **Step 1: Write the failing test**

Add a test next to the trap engine's unit tests in `crates/carrick-hvf/src/trap.rs` (gate it for the platform the fn is compiled on):

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tag_strip_tests {
    use super::strip_pointer_tag;
    #[test]
    fn strips_top_16_bits() {
        // Rosetta's RWX ExecutableHeap hint, and an x86-64 high-half address.
        assert_eq!(strip_pointer_tag(0xffff_fff7_ff70_0000), 0x0000_fff7_ff70_0000);
        assert_eq!(strip_pointer_tag(0xffff_ffff_fff3_a000), 0x0000_ffff_fff3_a000);
        // Native (top-byte-zero) pointers are untouched.
        assert_eq!(strip_pointer_tag(0x0000_0001_2345_6000), 0x0000_0001_2345_6000);
    }
}
```

- [ ] **Step 2: Run, verify it fails to compile**

Run: `cargo test -p carrick-hvf --lib tag_strip_tests`
Expected: FAIL — `strip_pointer_tag` undefined.

- [ ] **Step 3: Add the helper and apply it**

In `crates/carrick-hvf/src/trap.rs`, add a module-level fn:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
fn strip_pointer_tag(address: u64) -> u64 {
    // Rosetta tags pointers in bits 63:48 (a 48-bit value space). Strip them
    // so syscall-path region lookups resolve to the 48-bit backing mapping.
    // Pairs with TCR_EL1.TBI0/TBI1 (hardware ignores the top byte) and the
    // mmap-hint strip in dispatch/mem.rs.
    address & 0x0000_FFFF_FFFF_FFFF
}
```

Prepend `let address = strip_pointer_tag(address);` as the first line of both `mapping_for_range` and `mapping_for_range_mut` (the strip lives inside the two lookups, so every caller — `read_guest_bytes`, `write_guest_bytes`, `guest_range_is_writable`, `shared_futex_host_addr`, etc. — benefits without per-caller edits). For non-macOS/non-aarch64 builds where `strip_pointer_tag` isn't compiled, guard the call with the same `cfg` or make a no-op fallback so the crate still builds on other hosts.

- [ ] **Step 4: Run the test, verify it passes**

Run: `cargo test -p carrick-hvf --lib tag_strip_tests`
Expected: PASS.

- [ ] **Step 5: Stage (commit with Task 5/6 at the gate, or commit now if compiling cleanly)**

```bash
git add crates/carrick-hvf/src/trap.rs
git commit -m "rosetta: strip 16-bit pointer tag in syscall-path mapping lookups (re-port 1d9bc11)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 5: Enable TTBR1 / upper-half translation at both vCPU bring-up sites

Original commit `e168597`. `main` boots TTBR0-only (`EPD1=1`, the `(1 << 23)` term) and never sets `TTBR1_EL1`. This is the central change. **Factor the TCR value into one shared const** so the two bring-up sites cannot drift. **Couple with Tasks 4 and 6.**

**Files:**
- Modify: `crates/carrick-hvf/src/trap.rs` (`map_address_space` bring-up ~1372–1396, and the execve replace path ~3306–3316)

- [ ] **Step 1: Verify the `applevisor` `SysReg` enum exposes `TTBR1_EL1`**

Run: `cargo doc -p applevisor 2>/dev/null; grep -rn "TTBR1_EL1" ~/.cargo/registry/src/*/applevisor*/ 2>/dev/null | head`
Expected: `SysReg::TTBR1_EL1` exists. (It is used by the original; confirm at the pinned version. If absent, use the raw FFI precedent already in `trap.rs` for other sysregs.)

- [ ] **Step 2: Replace the TCR const + add the `TTBR1_EL1` set at the `map_address_space` site**

Current (`crates/carrick-hvf/src/trap.rs` ~1382):

```rust
            const T0SZ: u64 = 16;
            const TCR_EL1_BOOTSTRAP: u64 =
                T0SZ | (0b11 << 8) | (0b11 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32);
```

Replace with (drop `EPD1` `(1<<23)`; add the TTBR1 fields + TBI):

```rust
            // TCR_EL1: TTBR0 (lower half) and TTBR1 (upper half) both active.
            // TTBR1 (EPD1=0) lets x86-64 high-half addresses translate; it
            // shares the TTBR0 page-table root because a walk indexes VA[47:0]
            // regardless of which TTBR selected it, and carrick's lower-half
            // mappings and the upper-half alias projections occupy disjoint L0
            // slots. TG1=0b10 is 4 KiB (TG1's encoding differs from TG0's).
            // TBI0/TBI1: the MMU ignores the top byte on translation — Rosetta
            // tags pointers there and asserts unless hardware ignores it.
            const T0SZ: u64 = 16;
            const T1SZ: u64 = 16;
            const TCR_EL1_BOOTSTRAP: u64 = T0SZ
                | (0b11 << 8) | (0b11 << 10) | (0b11 << 12)   // IRGN0/ORGN0/SH0
                | (T1SZ << 16)
                | (0b11 << 24) | (0b11 << 26) | (0b11 << 28)  // IRGN1/ORGN1/SH1
                | (0b10 << 30)                                 // TG1 = 4 KiB
                | (0b010 << 32)                                // IPS = 40-bit
                | (1 << 37) | (1 << 38);                       // TBI0/TBI1
```

Then, immediately after the `set_sys_reg(SysReg::TTBR0_EL1, pt_base)` call at this site, insert:

```rust
            self.inner
                .vcpu
                .set_sys_reg(SysReg::TTBR1_EL1, pt_base)
                .map_err(hvf_error)?;
```

- [ ] **Step 3: Apply the identical change at the execve replace site (~3306)**

The execve path uses `self.vcpu` (not `self.inner.vcpu`). Replace its `const TCR_EL1_BOOTSTRAP` with the **same** value as Step 2 (consider hoisting a single `const` to module scope shared by both sites to prevent drift), and insert after its `set_sys_reg(SysReg::TTBR0_EL1, pt_base)`:

```rust
            self.vcpu
                .set_sys_reg(SysReg::TTBR1_EL1, pt_base)
                .map_err(hvf_error)?;
```

- [ ] **Step 4: Compile-check**

Run: `cargo build -p carrick-hvf` then `cargo clippy --all-targets`
Expected: builds; no new panics. (Behaviour is verified at the Phase 1 gate — this needs a live vCPU.)

- [ ] **Step 5: Stage (do not run a guest yet — Task 6 must land first)**

```bash
git add crates/carrick-hvf/src/trap.rs
git commit -m "rosetta: enable TTBR1/upper-half translation at both bring-up sites (re-port e168597)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 6: High-VA mmap — route x86-64 high-half to MapHostAlias (canonical check + tag strip + no_access fix)

Original commits `e168597` (canonical check, exact length) + `1d9bc11` (hint strip) + `0057b5c` (`no_access` overlay fix). On `main`, the anon high-VA block (`dispatch/mem.rs` ~540–573) still **rejects** `address >= VA_48` with `EEXIST`/`ENOMEM` — that is precisely why Rosetta's high-half `mmap` fails. With TTBR1 on (Task 5) + the tag strip, those addresses become translatable and must route to `MapHostAlias`.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs` (`fn mmap`: the hint-strip site ~268–301, and the anon high-VA `MapHostAlias` block ~540–573; evaluate the file-backed high-VA block ~369–444)

- [ ] **Step 1: Strip the 16-bit tag from the mmap address hint**

Near the top of the `mmap` handler, before the `MAP_FIXED_NOREPLACE`/alignment validation, add:

```rust
        // Rosetta passes tagged x86-64 pointers (bits 63:48) as the mmap hint;
        // strip the tag so the request resolves into the 48-bit VA space (TBI
        // makes the hardware ignore the top byte too). No-op for native guests.
        let requested = GuestPtr(requested.0 & 0x0000_FFFF_FFFF_FFFF);
```

(Confirm the binding name is `requested` and it is `GuestPtr`; adjust to the actual local.)

- [ ] **Step 2: Replace the `address >= VA_48` reject with the canonical-bits test**

In the anon high-VA block, replace:

```rust
                const VA_48: u64 = 1 << 48;
                if address >= VA_48 {
                    if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                        return Ok(linux_errno::EEXIST.into());
                    }
                    return Ok(LINUX_ENOMEM.into());
                }
```

with a canonicality check on the (original, pre-strip) address — reject only genuinely non-canonical addresses (bits 55:48 neither all-0 nor all-1):

```rust
                // With TBI on, canonicality is decided by bits 55:48 (not 63:48).
                // A canonical high-half address is translatable via TTBR1 and is
                // aliased below; a non-canonical one (mixed 55:48) is rejected.
                let bits_55_48 = (orig_address >> 48) & 0xff;
                let canonical = bits_55_48 == 0x00 || bits_55_48 == 0xff;
                if !canonical {
                    if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                        return Ok(linux_errno::EEXIST.into());
                    }
                    return Ok(LINUX_ENOMEM.into());
                }
```

This needs the *original* (un-stripped) address to judge canonicality. If Step 1 reassigned `requested`/`address` in place, capture `let orig_address = <original requested.0>;` **before** the strip and use it here. (The cleanest shape: strip into a new `let address = requested.0 & MASK;` for the alias VA, and keep `orig_address` for the canonical test. Reconcile the exact local names against the function — the survey shows `address` is derived from `requested` upstream.)

- [ ] **Step 3: Map the exact page-aligned length + clear the no_access overlay**

In the same block, after the `let ipa = { … };` reservation and before `return Ok(DispatchOutcome::MapHostAlias { … })`, add the `no_access` clear (fix from `0057b5c`):

```rust
                // A high-VA mmap frequently overlays an earlier PROT_NONE
                // reservation (Rosetta reserves the x86 stack/binary span anon
                // PROT_NONE, then MAP_FIXEDs RW/file segments in). The guest's
                // own accesses translate via map_aliased's page tables, but
                // carrick's syscall-path EFAULT check consults `no_access` —
                // clear it here or reads/writes of guest buffers in this range
                // (e.g. getrandom's output on the x86 stack) wrongly EFAULT.
                memory.set_no_access(address, length_usize, prot_none);
```

`memory`, `length_usize`, and `prot_none` are all in scope at this point per the survey. Also align the emitted `len` with the proven intent: emit the **page-aligned request length** for the VA mapping while still bumping the IPA arena by the 2 MiB-rounded `alias_len` (mirror the file-backed path's `map_len`/`alias_len` split). Keep `file: None`.

- [ ] **Step 4: Evaluate the file-backed high-VA path**

Inspect the file-backed `MapHostAlias` branch (~369–444). If it can also overlay a `PROT_NONE` reservation (it can, for `MAP_FIXED` file segments into Rosetta's reserved span), add the same `memory.set_no_access(...)` treatment there. Note the decision in the commit message.

- [ ] **Step 5: Compile-check + clippy**

Run: `cargo build -p carrick-runtime` then `cargo clippy --all-targets`
Expected: builds; no new panics.

- [ ] **Step 6: Commit Tasks 4–6 together**

```bash
git add crates/carrick-runtime/src/dispatch/mem.rs
git commit -m "rosetta: route x86-64 high-half mmap to MapHostAlias (re-port e168597/1d9bc11/0057b5c)

Strip the 16-bit pointer tag from the mmap hint, judge canonicality by bits
55:48 (TBI on), and clear carrick's no_access overlay on the aliased range.
Couples with the TTBR1 TBI0/TBI1 enablement.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 7: EL0 feature-ID register MRS emulation

Original commit `e168597`. Rosetta reads `ID_AA64MMFR1_EL1` (and friends) at startup; without emulation the EL0 `MRS` takes a fatal undef. `main` refactored EL0 sysreg decode into `decode_el0_sys64_read` (`trap/sysreg.rs`) with an `El0SysRegRead` enum — extend that rather than copying the original's inline ESR-decode (the ISS-encoding helper differs).

**Files:**
- Modify: `crates/carrick-hvf/src/trap/sysreg.rs` (`El0SysRegRead` enum + `decode_el0_sys64_read` ~57–71)
- Modify: `crates/carrick-hvf/src/trap.rs` (`emulate_el0_sys64_read` ~2065–2088 — add the match arm)

- [ ] **Step 1: Verify the `applevisor` `SysReg` enum exposes the ID registers**

Run: `grep -rn "ID_AA64MMFR1_EL1\|ID_AA64PFR0_EL1\|MIDR_EL1" ~/.cargo/registry/src/*/applevisor*/ 2>/dev/null | head`
Expected: the `SysReg` variants exist. If some are missing at the pinned version, fall back to returning `0` (read-as-zero) for those encodings rather than failing to compile.

- [ ] **Step 2: Recognize the feature-ID space in the decoder**

In `crates/carrick-hvf/src/trap/sysreg.rs`, add a variant to `El0SysRegRead` carrying the decoded ID register (or the raw encoding), and in `decode_el0_sys64_read` recognize the `Op0==3, Op1==0, CRn==0` feature-ID space using **sysreg.rs's existing ISS shift scheme** (do not paste the original's `0xc0xx` magic — recompute against the local encoding helper). Map the encodings to the live `SysReg` ID registers (`MIDR_EL1`, `ID_AA64PFR0/1`, `ID_AA64DFR0/1`, `ID_AA64ISAR0/1`, `ID_AA64MMFR0/1/2`); other `CRn==0` slots read-as-zero.

- [ ] **Step 3: Service the new variant in `emulate_el0_sys64_read`**

In the `match reg { … }` in `crates/carrick-hvf/src/trap.rs::emulate_el0_sys64_read`, add an arm for the feature-ID variant that reads the real value from the vCPU (`self.vcpu.get_sys_reg(reg)`), or `0` for read-as-zero slots. Reuse the existing `GPR_TABLE.get(rt)` write-back and the `ELR += 4` single-step-over-MRS that the surrounding code already does. The trap dispatch caller (~1896) needs no change.

- [ ] **Step 4: Compile-check + clippy**

Run: `cargo build -p carrick-hvf` then `cargo clippy --all-targets`
Expected: builds; no new panics. (Verified live at the gate — Rosetta's ID-reg read happens during init.)

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-hvf/src/trap.rs crates/carrick-hvf/src/trap/sysreg.rs
git commit -m "rosetta: emulate EL0 feature-ID MRS reads (re-port e168597)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 8: `esr_context` record in the fault signal frame

Original commit `ef37588`. The arm64 kernel records the fault `ESR` as an `esr_context` in the signal frame's `uc_mcontext.__reserved`; Rosetta's signal handler requires it. **Reconciliation:** `main` added a *second* fault path the branch didn't have (the direct-EL0-abort block), and has **four** `HvfInner` construction sites.

**Files:**
- Modify: `crates/carrick-hvf/src/trap.rs` (`struct HvfInner` ~674–712; `inject_signal` after `save_fpsimd_into` ~2610; the HVC-underlying EL0Fault return ~1951; the direct-EL0-abort return ~1868; four construction sites ~1251/2992/3117/3249)

- [ ] **Step 1: Add the `last_fault_esr` field**

In `struct HvfInner`, after `last_exit_class: u64,`:

```rust
    /// ESR_EL1 of the most recent EL0 synchronous fault. The arm64 kernel puts
    /// it in the signal frame's esr_context; Apple Rosetta's handler requires
    /// that record. Captured at fault detection, consumed by inject_signal.
    last_fault_esr: u64,
```

- [ ] **Step 2: Initialize it at all four construction sites**

Add `last_fault_esr: 0,` to each `HvfInner { … }` literal — startup (~1251), fork-clone (~2992), thread-spawn (~3117), execve (~3249). Map by role, not line number. Resetting to 0 on fork/clone/execve is correct (the field is only live between fault-detect and the immediately-following `inject_signal`).

- [ ] **Step 3: Capture the ESR at both fault returns**

Before the HVC-underlying `EL0Fault` return (~1951, after the `pt_fault_walk` probe), add `self.last_fault_esr = underlying;`. Before the direct-EL0-abort `EL0Fault` return (~1868, the `is_aarch64_el0_abort_exception` block), add `self.last_fault_esr = exception.syndrome;` (this second site is the additive reconciliation — the original predates it).

- [ ] **Step 4: Write the esr_context into the signal frame**

In `inject_signal`, immediately after `self.save_fpsimd_into(&mut mcontext)?;` and before `let mut ucontext = …`, insert:

```rust
        // For a synchronous fault, the arm64 kernel also records an esr_context
        // (the fault ESR) in __reserved after the fpsimd record. Rosetta's
        // handler requires it. The zero-filled tail is the terminating null.
        if fault_siginfo.is_some() {
            const ESR_MAGIC: u32 = 0x4553_5201; // 'ESR\x01'
            let off = if fpsimd_save_enabled() {
                core::mem::size_of::<crate::linux_abi::LinuxFpsimdContext>()
            } else {
                0
            };
            if off + 16 <= mcontext.__reserved.len() {
                mcontext.__reserved[off..off + 4].copy_from_slice(&ESR_MAGIC.to_le_bytes());
                mcontext.__reserved[off + 4..off + 8].copy_from_slice(&16u32.to_le_bytes());
                mcontext.__reserved[off + 8..off + 16]
                    .copy_from_slice(&self.last_fault_esr.to_le_bytes());
            }
        }
```

Confirm the parameter name (`fault_siginfo: Option<…>`), and that `fpsimd_save_enabled()` and `LinuxFpsimdContext` resolve at this path (the survey confirms they do).

- [ ] **Step 5: Compile-check + clippy**

Run: `cargo build -p carrick-hvf` then `cargo clippy --all-targets`
Expected: builds; no new panics.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-hvf/src/trap.rs
git commit -m "rosetta: write esr_context into fault signal frames (re-port ef37588)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 9: Verify `map_aliased` needs no upper-half branch (collision guard)

Under the shared-root + 48-bit-mask design, `map_aliased` (`carrick-mem/src/page_table.rs`) needs **no signature/body change** — the dispatcher strips the tag so the alias VA is `< 2^48` and `indices()` lands it in the correct L0 slot. But this relies on Rosetta's mapped base **not** colliding with the boot identity `L0[0..1]`.

**Files:**
- Modify (test only): `crates/carrick-mem/src/page_table.rs` (add an assertion test)

- [ ] **Step 1: Add a collision-guard unit test**

Append to the page_table test module:

```rust
#[test]
fn rosetta_alias_base_does_not_collide_with_boot_identity_l0() {
    // Rosetta's stripped RWX/base VA (e.g. 0xfff7_ff70_0000) must index an L0
    // slot disjoint from carrick's low identity mappings (L0[0..1]).
    let l0 = |va: u64| (va >> 39) & 0x1ff;
    let rosetta_base = 0xfff7_ff70_0000u64 & 0x0000_FFFF_FFFF_FFFF;
    assert!(l0(rosetta_base) >= 2, "alias base collides with identity L0[0..1]");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p carrick-mem --lib rosetta_alias_base_does_not_collide`
Expected: PASS. If it FAILS, `map_aliased` needs an offset/remap branch — escalate before the gate.

- [ ] **Step 3: Commit**

```bash
git add crates/carrick-mem/src/page_table.rs
git commit -m "rosetta: assert alias base is disjoint from boot identity L0 slots

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 10: Phase 1 exit gate — reproduce the proven demo on `main`

**Files:** none (verification only).

- [ ] **Step 1: Signed build + no-panic gate**

Run: `just build && cargo clippy --all-targets`
Expected: builds signed; clippy green.

- [ ] **Step 2: amd64 glibc end-to-end**

Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/amd64 --fs host debian:stable /bin/uname -m`
Expected: prints `x86_64`, exit 0. (The branch reported ~209 translated syscalls.)

- [ ] **Step 3: arm64 regression unchanged**

Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/arm64 --fs host debian:stable /bin/uname -m`
Expected: prints `aarch64`, exit 0.

- [ ] **Step 4: Full host unit-test suite**

Run: `cargo test --workspace --lib`
Expected: PASS.

- [ ] **Step 5: If Step 2 fails** — trace and debug with the systematic-debugging skill:

```sh
CARRICK_ACCEPT_ROSETTA_TERMS=1 CARRICK_TRACE_TRAPS=1 target/release/carrick run --platform linux/amd64 --fs host debian:stable /bin/uname -m 2>&1 | tail -60
# or the DTrace fault probe (page-table walk on a fault):
target/release/carrick trace --script scripts/dtrace/rosetta-fault.d -- run --platform linux/amd64 --fs host debian:stable /bin/uname -m
```
Compare the failing trap against Phase 0 Step 3. Likely suspects in order: TBI/strip mismatch (Tasks 4/5/6 not landed together), the canonical-bits test rejecting a valid high-half address, or a missing ID-reg encoding (Task 7).

---

## Phase 2 — Bring-up ladder to flagship workloads

These rungs are **discovery** work: the exact gaps are unknown until traced, so each is a procedure, not fabricated fix-code. For every gap: use the **systematic-debugging skill**, make the minimal fix, add a regression test (unit test if the surface is pure; otherwise extend the conformance lane in Phase 3), keep the no-panic gate green, and commit. Surface any gap that materially expands scope rather than silently absorbing it. Run each rung on a **glibc** image (debian/ubuntu) — musl/static-PIE is out of scope.

### Task 11: Climb the ladder

**Files:** varies per gap (most likely `crates/carrick-runtime/src/dispatch/*.rs`).

- [ ] **Rung 1 — `/bin/sh` pipeline.**
Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/amd64 --fs host ubuntu:24.04 /bin/sh -c 'ls -la / | wc -l'`
Expected: a number, exit 0. Diagnose any gap; fix; regression-test; commit.

- [ ] **Rung 2 — `python3` script.**
Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/amd64 --fs host ubuntu:24.04 python3 -c 'import os,sys; open("/tmp/x","w").write("hi"); print(open("/tmp/x").read(), sys.version_info[0])'`
Expected: `hi 3`, exit 0.

- [ ] **Rung 3 — `python3 -m http.server`.**
Run it with `-t`/background, then `curl` the host-mapped port; expect a directory listing. Exercises socket/bind/listen/accept under Rosetta. Verify clean shutdown.

- [ ] **Rung 4 — `apt-get install`.**
Run: `CARRICK_ACCEPT_ROSETTA_TERMS=1 target/release/carrick run --platform linux/amd64 --fs host ubuntu:24.04 /bin/sh -c 'apt-get update && apt-get install -y --no-install-recommends hello && hello'`
Expected: `Hello, world!`, exit 0. This is the broadest surface (network, fork/exec of maintainer scripts, dpkg). If the long tail is large, capture remaining gaps in a follow-up plan rather than blocking.

- [ ] **After each rung:** re-run the Phase 1 gate commands (Task 10 Steps 2–3) to confirm no regression, and `cargo clippy --all-targets`.

---

## Phase 3 — Tests + amd64 conformance lane

### Task 12: Add Rosetta unit tests against existing surfaces

**Files:**
- Modify: `crates/carrick-runtime/src/runtime.rs` (`mod rosetta_tests` ~3083)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs` (`mod rosetta_handshake_tests` ~4917)
- Modify: `crates/carrick-spec/src/lib.rs` (`mod tests` ~210)

- [ ] **Step 1: Redirect-argv edge cases** — in `mod rosetta_tests`, add a `#[test]` asserting `maybe_redirect_to_rosetta` produces the binfmt argv `[ROSETTA_INTERPRETER, target, ...args]` for a multi-arg x86_64 program, and is a no-op (`None`) for an `EM_AARCH64` ELF. Use the existing `synthetic_elf(e_machine)` helper and the `Some(Ok)|Some(Err(LINUX_ENOENT))` host-tolerant match idiom.

- [ ] **Step 2: ioctl handshake coverage** — in `mod rosetta_handshake_tests`, add `#[test]`s for the second licence code `0x80456122`, for blob truncation to the request size field, and the Rosetta-absent branch (gated on `crate::runtime::rosetta_license_blob().is_some()`). Use the `LinearMemory::new(BASE, vec![0xAB; 256])` idiom.

- [ ] **Step 3: Platform round-trip** — in `carrick-spec` `mod tests`, add a `#[test]` asserting `Platform::from_oci_str(p.oci_arch()) == Some(p)` for both variants, and a serde `RunSpec` round-trip (no `platform` key → `Aarch64`; `"platform":"amd64"` → `Amd64`).

- [ ] **Step 4: Run + commit**

Run: `cargo test -p carrick-runtime -p carrick-spec --lib rosetta` then `cargo clippy --all-targets`
```bash
git add crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-spec/src/lib.rs
git commit -m "test(rosetta): redirect-argv, ioctl-handshake, platform round-trip units

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 13: amd64 build path for conformance probes

**Files:**
- Modify: `scripts/build-probes.sh`

- [ ] **Step 1: Add an x86_64-musl container build**

Add a second `docker run --platform linux/amd64 … rust:alpine` invocation building `--target x86_64-unknown-linux-musl`, producing `conformance-probes/target/x86_64-unknown-linux-musl/release/` (the exact path the lane-aware `probes_dir()` will read in Task 14). Keep the `ls | grep -v '.'` enumeration.

- [ ] **Step 2: Run it**

Run: `sh scripts/build-probes.sh`
Expected: both `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` probe dirs populated.

- [ ] **Step 3: Commit**

```bash
git add scripts/build-probes.sh
git commit -m "build: cross-build conformance probes for x86_64-musl too

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 14: Parameterize the conformance harness into an amd64 lane

**Files:**
- Modify: `crates/carrick-cli/tests/conformance.rs` (the `const PLATFORM`/`const IMAGE`, `run_carrick`/`run_docker`/`ensure_image`/`run_docker_probe`, `probes_dir()`, and the three `#[test]` fns)

- [ ] **Step 1: Introduce a `Lane` and a Rosetta-availability skip gate**

Replace the two module-level consts with a small lane descriptor and iterate the existing per-case body over both lanes:

```rust
struct Lane {
    platform: &'static str,   // "linux/arm64" | "linux/amd64"
    image: &'static str,
    probes_subdir: &'static str, // "aarch64-unknown-linux-musl" | "x86_64-unknown-linux-musl"
}
const ARM64: Lane = Lane { platform: "linux/arm64", image: "docker.io/library/ubuntu:24.04", probes_subdir: "aarch64-unknown-linux-musl" };
const AMD64: Lane = Lane { platform: "linux/amd64", image: "docker.io/library/ubuntu:24.04", probes_subdir: "x86_64-unknown-linux-musl" };

/// The amd64 lane needs Apple Rosetta installed; skip it otherwise so CI on
/// non-Rosetta hosts stays green.
fn rosetta_available() -> bool {
    std::path::Path::new("/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta").exists()
}
```

Thread `lane.platform`/`lane.image` through `ensure_image`, `run_docker`, `run_docker_probe` (the `--platform`/`CreateContainerOptions.platform`/`CreateImageOptions.from_image`), and pass the platform selector to `carrick run` in `run_carrick` (append `--platform <lane.platform>` to the args). Make `probes_dir()` take `lane.probes_subdir`.

- [ ] **Step 2: Loop the three tests over lanes, with the gate**

In `conformance`, `conformance_probes`, and `conformance_go_fixture`, loop over `[ARM64, AMD64]`; for `AMD64`, `continue` (skip with a logged message) when `!rosetta_available()` or the amd64 probe dir is absent. Give the amd64 lane its **own** known-gap list (Rosetta divergences differ from native arm64) — clone the `KNOWN_PROBE_GAPS`/`GATE_SKIP_PROBES` mechanism per lane. The `normalize()`→`==` (shell cases) and `diff_lines()`→`ProbeOutcome` (probes) assertion model carries over unchanged.

- [ ] **Step 3: Run the lane**

Run: `just build && cargo test -p carrick-cli --test conformance -- --nocapture`
Expected: arm64 lane green; amd64 lane green where Rosetta is present (it is, here). `uname -m`/`dpkg --print-architecture` cases must show `x86_64`/`amd64` on the amd64 lane. Triage divergences into the amd64 known-gap list or back into Phase 2 fixes.

- [ ] **Step 4: Commit**

```bash
git add crates/carrick-cli/tests/conformance.rs
git commit -m "test(conformance): add a self-skipping linux/amd64 Rosetta lane

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 15: Fold `rosetta-demo.sh` into the suite

**Files:**
- Modify: `scripts/rosetta-demo.sh` (re-create from the `feat/rosetta-ttbr1` version if absent on `main`)

- [ ] **Step 1: Restore/refresh the demo script**

Bring `scripts/rosetta-demo.sh` over from `origin/feat/rosetta-ttbr1` (`git show origin/feat/rosetta-ttbr1:scripts/rosetta-demo.sh`), updating the default image to a glibc image and keeping the arm64=>aarch64 assertion plus the documented Alpine static-PIE `exit 139` known-limitation check (soft NOTE, not a hard fail).

- [ ] **Step 2: Run it**

Run: `sh scripts/rosetta-demo.sh`
Expected: amd64=>x86_64 PASS, arm64=>aarch64 PASS, Alpine NOTE (exit 139).

- [ ] **Step 3: Commit**

```bash
git add scripts/rosetta-demo.sh
git commit -m "test(rosetta): restore end-to-end demo script (glibc + arm64 + Alpine note)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Phase 4 — Documentation

### Task 16: Rewrite `docs/rosetta.md` to "done"

**Files:**
- Modify: `docs/rosetta.md`

- [ ] **Step 1: Flip the status**

Rewrite the "Current frontier — TTBR1" section (which calls TTBR1 "the next architectural step") to document the landed state: TTBR1/upper-half enabled, x86_64 glibc-dynamic runs end-to-end (`debian:stable uname -m` → `x86_64`), the flagship workloads supported (per Phase 2 results), and the static-PIE-musl limitation (Apple translator; `docker/for-mac#6773`). Drop the stale pre-implementation "Open Questions" (Q1–Q4 are answered by the merged base). Keep the architecture/handshake/TSO sections.

- [ ] **Step 2: Commit**

```bash
git add docs/rosetta.md
git commit -m "docs(rosetta): TTBR1/glibc-amd64 landed; x86_64 runs end-to-end

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (completed during planning)

- **Spec coverage:** Part 1 re-port → Tasks 1–9 (with SCTLR and `rt_tgsigqueueinfo` correctly dropped as already-on-`main`; the high-VA canonical-check elevated to essential). Part 1 gate → Task 10. Part 2 ladder → Task 11. Part 3 tests+lane → Tasks 12–15. Docs → Task 16. No spec requirement is unmapped.
- **Placeholder scan:** the only deliberately non-literal steps are Phase 2's bring-up rungs (genuine discovery — fabricating fix-code would be a lie) and the few "reconcile the exact local name against the file" notes where the survey gave the surrounding context but line numbers will have drifted. Every code edit shows the actual code.
- **Type/name consistency:** `carrick_x86_64()`, `strip_pointer_tag`, `rlimit_for_resource(resource, nofile_soft)`, `last_fault_esr`, `Lane`/`rosetta_available()` are used consistently across tasks. `ROSETTA_INTERPRETER`, `MapHostAlias`, `set_no_access`, `SetMemoryModel`, `DispatchOutcome::Returned`/`Errno` match the verbatim surfaces.
- **Ordering:** Tasks 4/5/6 are flagged as a coupled triplet that must land before any guest run (TBI ↔ tag-strip ↔ canonical-bits interdependence). Task 9 guards the `map_aliased` no-change assumption.

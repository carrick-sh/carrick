# Carrick Code-Quality / Darwin-Leverage / Ecosystem Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the actionable findings from the 2026-05-23 multi-agent review — kill per-syscall waste, remove the soundness footgun in guest-memory access, collapse the triplicated syscall-routing tables, fix the missing `MAP_NORESERVE`, dedup the errno tables, and clean up stale deps/comments — without churning the crate choices that are already correct.

**Architecture:** carrick is a Linux-binary-compat layer for macOS aarch64 that runs Linux ELF binaries under Apple Hypervisor.framework and emulates Linux syscalls against macOS host facilities. Syscalls trap into `SyscallDispatcher`; a single-threaded path (`dispatch` → `dispatch_inner` → `dispatch_normalized`) and a multi-threaded path (`dispatch_threaded` → 8 `dispatch_threaded_*` functions) coexist. Guest RAM is `mmap(MAP_ANON|MAP_SHARED)` + `hv_vm_map`, accessed by the host via raw `copy_nonoverlapping`.

**Tech Stack:** Rust edition 2024, `libc`, `applevisor`/HVF, `parking_lot`, `zerocopy`, `goblin`, `tokio` (current-thread only), `oci-distribution`. Clippy gate denies `unwrap`/`expect`/`panic`/`todo`/`unimplemented` (`Cargo.toml [lints.clippy]`).

**Verification primitives used throughout:**
- `cargo test` — lib + integration tests (per-subsystem: `tests/syscall_time.rs`, `syscall_thread.rs`, `syscall_fs.rs`, `syscall_net.rs`, `syscall_mem.rs`, `concurrency_contracts.rs`, `syscall_table.rs`).
- `cargo clippy --all-targets -- -D warnings` — must stay green; the deny-gate is the no-panic guarantee.
- `./scripts/build-signed.sh` — produces the codesigned binary required to actually run a guest under HVF (unsigned → `HV_DENIED`).
- LTP differential conformance (the `ltp-conformance` skill / `tests/conformance.rs`, Docker-backed) — the oracle for "did this stay correct vs real Linux". Run after any dispatch/memory change.

**Sequencing rationale:** isolated low-risk wins first (build confidence + keep diffs reviewable), the big structural refactor in the middle behind the conformance harness, the incremental ergonomics work last.

---

## Phase 0 — Stale deps & misleading comments (isolated, low risk)

### Task 1: Drop the unused `tokio` `rt-multi-thread` feature

**Why:** `src/main.rs:1235` builds `Builder::new_current_thread()`, and the doc at `src/main.rs:260` explains a multi-thread runtime is *forbidden* (it poisons forked children). The Cargo feature contradicts the documented intent and enables a footgun.

**Files:**
- Modify: `Cargo.toml` (the `tokio` line)

- [ ] **Step 1: Edit the feature list**

In `Cargo.toml`, change:
```toml
tokio = { version = "1.48.0", features = ["fs", "io-util", "macros", "rt-multi-thread"] }
```
to:
```toml
tokio = { version = "1.48.0", features = ["fs", "io-util", "macros", "rt"] }
```

- [ ] **Step 2: Verify it builds and tests pass**

Run: `cargo build && cargo test --lib`
Expected: clean build (the `rt` feature provides `new_current_thread`; `rt-multi-thread` was unused).

- [ ] **Step 3: Verify no `new_multi_thread`/`spawn`-on-pool usage snuck in**

Run: `grep -rn 'new_multi_thread\|spawn_blocking\|tokio::spawn' src/`
Expected: no `new_multi_thread`; if any `tokio::spawn` exists on the OCI path, confirm it runs on the current-thread runtime (it does — single-threaded).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: drop unused tokio rt-multi-thread feature

A multi-thread runtime is forbidden (poisons forked children, see
main.rs:260); only new_current_thread is ever built. Match the manifest
to the documented intent."
```

---

### Task 2: Remove the dead `reflink-copy` dependency and fix the misleading O(1)-clonefile comments

**Why:** `reflink-copy` is declared in `Cargo.toml:22` but never imported (`grep reflink_copy:: src/` → nothing). Three doc comments claim O(1) clonefile rootfs seeding that does not exist (seeding is per-file `write_all`). Either implement clonefile or stop claiming it. This task removes the dead weight and corrects the comments; actual clonefile seeding is deferred (see Deferred section).

**Files:**
- Modify: `Cargo.toml`, `src/apfs.rs:19-20`, `src/fs_backend.rs:15`, `src/main.rs:27`

- [ ] **Step 1: Confirm the dep is truly dead**

Run: `grep -rn 'reflink' src/ Cargo.lock | grep -v '^Cargo.lock'`
Expected: only comment mentions in `apfs.rs`, `fs_backend.rs`, `main.rs` — no `use`/call sites.

- [ ] **Step 2: Remove the dependency**

In `Cargo.toml`, delete the line:
```toml
reflink-copy = "0.1"
```

- [ ] **Step 3: Correct the comments**

In `src/apfs.rs:19-20`, replace the clonefile O(1) claim with an accurate statement. Change:
```rust
//!   - clonefile(2) seeding the scratch dir from the unpacked rootfs
//!     becomes O(1) since the rootfs and the scratch share an APFS
```
to:
```rust
//!   - the scratch dir lives on the same APFS volume as the unpacked
//!     rootfs, so a future clonefile(2)-based seed could be O(1) (NOT
//!     yet implemented — current seeding byte-copies via write_all; see
//!     docs/superpowers/plans/2026-05-23-code-quality-darwin-ecosystem.md)
```

In `src/fs_backend.rs:15`, change `// reflink-seeded from the unpacked rootfs (clonefile is O(1) on` to drop the "reflink-seeded" claim:
```rust
//     byte-copied from the unpacked rootfs (a future clonefile(2) seed
//     would be O(1) on
```

In `src/main.rs:27`, change `/// reflink-seeded, the secure-by-default production option.` to:
```rust
    /// byte-copied from the unpacked rootfs, the secure-by-default
    /// production option.
```

- [ ] **Step 4: Verify build**

Run: `cargo build && cargo test --lib`
Expected: clean (removing an unused dep changes nothing functionally).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/apfs.rs src/fs_backend.rs src/main.rs
git commit -m "chore: drop dead reflink-copy dep; correct unrealized clonefile comments

reflink-copy was declared but never used. Three comments claimed O(1)
clonefile rootfs seeding that does not exist (seeding byte-copies via
write_all). Remove the dep and make the comments honest."
```

---

### Task 3: Migrate `oci-distribution 0.11` → `oci-client 0.15`

**Why:** `oci-distribution` was renamed to `oci-client` under oras-project; 0.11 is several minors behind the maintained 0.15 line. Usage is confined to `src/oci.rs`.

**Files:**
- Modify: `Cargo.toml`, `src/oci.rs`

- [ ] **Step 1: Swap the dependency**

In `Cargo.toml`, replace:
```toml
oci-distribution = { version = "0.11.0", default-features = false, features = ["rustls-tls"] }
```
with:
```toml
oci-client = { version = "0.15", default-features = false, features = ["rustls-tls"] }
```

- [ ] **Step 2: Rename import paths**

Run: `grep -n 'oci_distribution' src/oci.rs` to enumerate sites, then replace every `oci_distribution::` with `oci_client::` in `src/oci.rs`.

- [ ] **Step 3: Build and fix any API drift**

Run: `cargo build 2>&1 | tee /tmp/oci-build.log`
Expected: may surface minor 0.11→0.15 API changes (e.g. `Client::new`, `pull`, `Reference` parsing, auth types). Fix each compiler error against the new API. Consult current docs via Context7 (`resolve-library-id` → `oci-client`) if a signature changed.

- [ ] **Step 4: Run the OCI tests**

Run: `cargo test --test oci_layout --test rootfs_streaming`
Expected: PASS (these exercise layer pull/extract).

- [ ] **Step 5: Smoke-test a real pull (network)**

Run: `./scripts/build-signed.sh && ./target/release/carrick run --help` then a pull-backed run if network is available (e.g. `carrick run ubuntu:24.04 /bin/true`).
Expected: image pulls and runs (auto-pull path intact).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/oci.rs
git commit -m "deps: migrate oci-distribution 0.11 -> oci-client 0.15

oci-distribution was renamed to oci-client (oras-project) and the old
name is EOL. Mechanical import rename plus 0.11->0.15 API drift fixes,
confined to src/oci.rs."
```

---

## Phase 1 — Per-syscall waste (hot-path, low risk, high value)

### Task 4: Stop heap-allocating the syscall name on every entry/return

**Why:** `CompatEvent::SyscallEntry`/`SyscallReturn` hold `name: String`, and the dispatch path does `name.to_owned()` twice per syscall — even with tracing off and no DTrace consumer — when `name` is already `&'static str` from the syscall table. apt does millions of syscalls. Make those two hot variants borrow `&'static str`; leave the rare aggregated variants as `String`.

**Files:**
- Modify: `src/compat.rs:64-114` (event enum + `record`), `src/dispatch/mod.rs` (entry/return record sites), all 8 `dispatch_threaded_*` record sites, `src/probes.rs` (if it reads `name`).
- Test: `tests/compat_report.rs`

- [ ] **Step 1: Write a failing test asserting no per-syscall allocation contract**

Since allocation-counting is awkward, assert the type-level contract instead: the entry/return variants must accept a `&'static str` without `.to_owned()`. Add to `tests/compat_report.rs`:
```rust
#[test]
fn syscall_entry_accepts_static_str_without_allocation() {
    // Compiles only if SyscallEntry.name is &'static str (not String).
    let ev = carrick::compat::CompatEvent::SyscallEntry {
        number: 64,
        name: "write", // &'static str, no .to_owned()
        args: carrick::compat::SyscallArgs([0; 6]),
    };
    match ev {
        carrick::compat::CompatEvent::SyscallEntry { name, .. } => {
            assert_eq!(name, "write");
        }
        _ => unreachable!(),
    }
}
```

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test --test compat_report syscall_entry_accepts_static_str -- --nocapture`
Expected: compile error — `name` is currently `String`, so `"write"` (a `&'static str`) doesn't match.

- [ ] **Step 3: Change the two hot variants to borrow**

In `src/compat.rs`, change `SyscallEntry` and `SyscallReturn` to:
```rust
    SyscallEntry {
        number: u64,
        name: &'static str,
        args: SyscallArgs,
    },
    SyscallReturn {
        number: u64,
        name: &'static str,
        retval: i64,
        errno: Option<i32>,
    },
```
Leave `UnhandledSyscall`, `PartialSyscall`, `UnknownSyscallFlags`, etc. as `String` (they're rare and already use `impl Into<String>` constructors). Note: `CompatEvent` derives `Serialize`/`Deserialize`; `&'static str` serializes fine but does **not** `Deserialize`. If any test deserializes these two variants, gate the borrow behind `#[serde(borrow)]` is insufficient for `'static`; instead drop `Deserialize` reliance for the live path. Check: `grep -rn 'from_str.*CompatEvent\|serde_json::from' tests/ src/` — if nothing deserializes `SyscallEntry`/`SyscallReturn`, no action needed.

- [ ] **Step 4: Drop `.to_owned()` at every record site**

In `src/dispatch/mod.rs`, the entry/return sites at lines ~2084, ~2064, ~2119, ~2143, ~1622, ~1640, and the same pattern in all 8 `dispatch_threaded_*` functions (`time.rs:18,56`, `fs.rs`, `net.rs`, `mem.rs`, `proc.rs`, `signal.rs`, plus `dispatch_threaded_process`/`dispatch_threaded_credentials`/`dispatch_threaded_independent` in `mod.rs`): remove `.to_owned()` so `name` (already `&'static str` from `lookup_aarch64(..).map_or("unknown", |s| s.name)`) is passed by value.

Find them all: `grep -rn 'name: name.to_owned()' src/dispatch/`
Replace each `name: name.to_owned(),` with `name,`.

Note: `lookup_aarch64` returns a syscall whose `.name` is `&'static str` and the `"unknown"` literal is `&'static str`, so `name` is already `&'static str` — confirm with `grep -n 'pub name' src/syscall.rs`.

- [ ] **Step 5: Fix `record` and `probes::fire` if they consumed the String**

In `src/compat.rs:232` the `UnhandledSyscall { number, name, .. }` arm still owns a `String` (unchanged). The entry/return arms only read; no change needed. Check `src/probes.rs` `fire` reads `name.as_str()` — with `&'static str` it becomes `name` directly; fix the deref.

Run: `grep -n 'name.as_str()\|name:' src/probes.rs`

- [ ] **Step 6: Build, test, clippy**

Run: `cargo test --test compat_report && cargo test --lib && cargo clippy --all-targets -- -D warnings`
Expected: the new test PASSES, all green.

- [ ] **Step 7: Confirm the allocation is gone (optional measurement)**

Run a syscall-heavy guest under Instruments allocations or `MallocStackLogging`, or simply confirm via code review that no `String` is constructed on the entry/return path. Document in the commit.

- [ ] **Step 8: Commit**

```bash
git add src/compat.rs src/dispatch/ src/probes.rs tests/compat_report.rs
git commit -m "perf: stop heap-allocating syscall name on every entry/return

CompatEvent::SyscallEntry/SyscallReturn took name: String, forcing two
to_owned() per syscall even with tracing off. The name is already a
&'static str from the syscall table; borrow it. Removes 2 malloc/free
per syscall on the hot path."
```

---

## Phase 2 — Soundness: volatile guest-memory access

### Task 5: Make host accesses to shared guest memory volatile (remove latent UB)

**Why:** All guest RAM is `MAP_SHARED` and the guest vCPU mutates it via stage-2 *concurrently* with host-side `copy_nonoverlapping` in `read_guest_bytes`/`write_guest_bytes` (`src/trap.rs:1013-1060`) and the `mem_watch`/futex reads. A non-atomic, non-volatile host access racing a guest write is UB in Rust's abstract machine (the compiler may assume the bytes don't change). This is latent (LLVM rarely miscompiles opaque memcpy today) but it is the correct-by-construction fix and the standard VMM mitigation.

**Approach:** Replace the two raw `copy_nonoverlapping` calls with volatile byte copies via a small helper. Do **not** pull in `vm-memory` (heavy, Linux-oriented); a focused helper matches the existing minimal-dep posture. Keep it in `src/trap.rs` next to the accessors.

**Files:**
- Modify: `src/trap.rs:1013-1060` (`read_guest_bytes`, `write_guest_bytes`) and the `mem_watch` read at `src/dispatch/mod.rs:2094` path if it dereferences host memory directly (it goes through `memory.read_bytes`, so it inherits the fix).
- Test: `tests/address_space.rs` or `tests/trap_hvf.rs`

- [ ] **Step 1: Add a volatile-copy helper**

In `src/trap.rs`, near the accessors, add:
```rust
/// Volatile byte copy out of guest-shared memory. Guest RAM is MAP_SHARED
/// and the guest vCPU can mutate it concurrently on another thread; a
/// plain (non-volatile) read racing that write is UB in Rust's memory
/// model (the optimizer may assume the bytes are stable and tear/hoist
/// the read). `read_volatile` per byte forbids that reordering/elision.
/// This does NOT make the data race semantically "correct" — the guest
/// is responsible for its own synchronization — it only removes the
/// language-level UB on the trusted (host) side.
#[inline]
unsafe fn volatile_copy_from_guest(src: *const u8, dst: *mut u8, len: usize) {
    for i in 0..len {
        unsafe { dst.add(i).write(src.add(i).read_volatile()) };
    }
}

/// Volatile byte copy into guest-shared memory. See
/// [`volatile_copy_from_guest`] for why volatile is required.
#[inline]
unsafe fn volatile_copy_to_guest(src: *const u8, dst: *mut u8, len: usize) {
    for i in 0..len {
        unsafe { dst.add(i).write_volatile(src.add(i).read()) };
    }
}
```

- [ ] **Step 2: Use them in the accessors**

In `read_guest_bytes` (`src/trap.rs:1025`), replace:
```rust
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.host_addr.add(offset),
                bytes.as_mut_ptr(),
                length,
            );
        }
```
with:
```rust
        unsafe {
            volatile_copy_from_guest(mapping.host_addr.add(offset), bytes.as_mut_ptr(), length);
        }
```
In `write_guest_bytes` (`src/trap.rs:1056`), replace:
```rust
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.host_addr.add(offset), length);
        }
```
with:
```rust
        unsafe {
            volatile_copy_to_guest(bytes.as_ptr(), mapping.host_addr.add(offset), length);
        }
```

- [ ] **Step 3: Existing tests must still pass (functional equivalence)**

Run: `cargo test --test address_space --test trap_hvf --lib`
Expected: PASS — volatile copy is functionally identical to memcpy for a quiescent buffer; the existing read/write round-trip tests prove correctness.

- [ ] **Step 4: Guard against perf regression on large copies**

A per-byte volatile loop is slower than `memcpy` for large transfers. Add a quick benchmark thought: most guest copies are small structs (stat, timespec, sockaddr). For large copies (read/write buffers via `read_bytes`), confirm those go through a *different* path. Run: `grep -rn 'copy_nonoverlapping\|read_bytes\|write_bytes' src/trap.rs src/dispatch/fs.rs | head`. If bulk file I/O reuses `read_guest_bytes`/`write_guest_bytes`, measure with the python http.server demo before/after; if regression is material, optimize the helper to copy in `usize`-aligned chunks with `read_volatile::<usize>` for the aligned middle and bytes for the edges (document why). Keep the simple version unless measured slow.

- [ ] **Step 5: Run conformance (the oracle)**

Run the LTP differential harness per the `ltp-conformance` skill (signals/fs/mm areas at minimum), and a python http.server smoke test.
Expected: no regressions vs the recorded baseline.

- [ ] **Step 6: Build signed + clippy**

Run: `cargo clippy --all-targets -- -D warnings && ./scripts/build-signed.sh`
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add src/trap.rs
git commit -m "fix: volatile host access to shared guest memory (remove latent UB)

Guest RAM is MAP_SHARED; the guest vCPU mutates it concurrently with
host-side copy_nonoverlapping in read/write_guest_bytes. A non-volatile
host access racing a guest write is UB in Rust's model. Replace with
per-byte volatile copies (standard VMM mitigation) so the optimizer can't
assume the bytes are stable. Functionally identical for quiescent buffers."
```

---

## Phase 3 — Errno table dedup (mechanical, compiler-checked)

### Task 6: Collapse the two Linux-errno constant tables into one source of truth

**Why:** Two complete errno tables exist: 48 `LINUX_E*` consts in `src/linux_abi.rs` (used by ~580 `DispatchOutcome::Errno` sites) and a second `linux_errno` module in `src/dispatch/mod.rs:3822-3903` (used by `macos_to_linux_errno` + its tests). `EFAULT=14` is written twice. A transcription drift between them is a silent conformance failure.

**Approach:** Keep the `linux_abi.rs` `LINUX_E*` set as the canonical numeric source (it's the one ~580 sites use). Make the `linux_errno` module in `mod.rs` re-export from `linux_abi` instead of redefining, so `macos_to_linux_errno` and its tests keep their `linux_errno::EFAULT` spelling but there's one definition.

**Files:**
- Modify: `src/dispatch/mod.rs:3822-3903` (the `linux_errno` module), confirm `src/linux_abi.rs` coverage.
- Test: `src/dispatch/mod.rs:4716` (`linux_errno_constants_match_kernel_uapi`) — keep it.

- [ ] **Step 1: Confirm `linux_abi` covers every constant the `linux_errno` module defines**

Run:
```bash
cd /Volumes/CaseSensitive/carrick
grep -oE 'pub const E[A-Z0-9]+' src/dispatch/mod.rs | sed 's/pub const //' | sort > /tmp/mod_errno.txt
grep -oE 'pub const LINUX_E[A-Z0-9]+' src/linux_abi.rs | sed 's/pub const LINUX_//' | sort > /tmp/abi_errno.txt
comm -23 /tmp/mod_errno.txt /tmp/abi_errno.txt
```
Expected: lists any errno in `linux_errno` (mod.rs) that is **missing** from `linux_abi.rs`. For each missing one, add a `pub const LINUX_<NAME>: i32 = <value>;` to `linux_abi.rs` (match the value exactly from the mod.rs table).

- [ ] **Step 2: Replace the `linux_errno` module body with re-exports**

In `src/dispatch/mod.rs`, replace the whole `pub mod linux_errno { ... }` block (lines ~3822-3903) with:
```rust
/// Linux errno numbers, re-exported under their bare names from the
/// canonical table in `crate::linux_abi`. `macos_to_linux_errno` and its
/// tests refer to these as `linux_errno::EFAULT`; the numbers live in
/// exactly one place (linux_abi's `LINUX_E*`) so the two can't drift.
#[allow(dead_code)]
pub mod linux_errno {
    pub use crate::linux_abi::{
        LINUX_E2BIG as E2BIG, LINUX_EACCES as EACCES, LINUX_EADDRINUSE as EADDRINUSE,
        LINUX_EADDRNOTAVAIL as EADDRNOTAVAIL, LINUX_EAFNOSUPPORT as EAFNOSUPPORT,
        LINUX_EAGAIN as EAGAIN, LINUX_EALREADY as EALREADY, LINUX_EBADF as EBADF,
        LINUX_EBADMSG as EBADMSG, LINUX_EBUSY as EBUSY, LINUX_ECANCELED as ECANCELED,
        LINUX_ECHILD as ECHILD, LINUX_ECONNABORTED as ECONNABORTED, LINUX_ECONNREFUSED as ECONNREFUSED,
        LINUX_ECONNRESET as ECONNRESET, LINUX_EDEADLK as EDEADLK, LINUX_EDESTADDRREQ as EDESTADDRREQ,
        LINUX_EDOM as EDOM, LINUX_EDQUOT as EDQUOT, LINUX_EEXIST as EEXIST, LINUX_EFAULT as EFAULT,
        LINUX_EFBIG as EFBIG, LINUX_EHOSTDOWN as EHOSTDOWN, LINUX_EHOSTUNREACH as EHOSTUNREACH,
        LINUX_EIDRM as EIDRM, LINUX_EILSEQ as EILSEQ, LINUX_EINPROGRESS as EINPROGRESS,
        LINUX_EINTR as EINTR, LINUX_EINVAL as EINVAL, LINUX_EIO as EIO, LINUX_EISCONN as EISCONN,
        LINUX_EISDIR as EISDIR, LINUX_ELOOP as ELOOP, LINUX_EMFILE as EMFILE, LINUX_EMLINK as EMLINK,
        LINUX_EMSGSIZE as EMSGSIZE, LINUX_ENAMETOOLONG as ENAMETOOLONG, LINUX_ENETDOWN as ENETDOWN,
        LINUX_ENETRESET as ENETRESET, LINUX_ENETUNREACH as ENETUNREACH, LINUX_ENFILE as ENFILE,
        LINUX_ENOBUFS as ENOBUFS, LINUX_ENODEV as ENODEV, LINUX_ENOENT as ENOENT,
        LINUX_ENOEXEC as ENOEXEC, LINUX_ENOLCK as ENOLCK, LINUX_ENOLINK as ENOLINK,
        LINUX_ENOMEM as ENOMEM, LINUX_ENOMSG as ENOMSG, LINUX_ENOPROTOOPT as ENOPROTOOPT,
        LINUX_ENOSPC as ENOSPC, LINUX_ENOSYS as ENOSYS, LINUX_ENOTBLK as ENOTBLK,
        LINUX_ENOTCONN as ENOTCONN, LINUX_ENOTDIR as ENOTDIR, LINUX_ENOTEMPTY as ENOTEMPTY,
        LINUX_ENOTSOCK as ENOTSOCK, LINUX_ENOTTY as ENOTTY, LINUX_ENXIO as ENXIO,
        LINUX_EOPNOTSUPP as EOPNOTSUPP, LINUX_EOVERFLOW as EOVERFLOW, LINUX_EPERM as EPERM,
        LINUX_EPFNOSUPPORT as EPFNOSUPPORT, LINUX_EPIPE as EPIPE, LINUX_EPROTONOSUPPORT as EPROTONOSUPPORT,
        LINUX_EPROTOTYPE as EPROTOTYPE, LINUX_ERANGE as ERANGE, LINUX_EREMOTE as EREMOTE,
        LINUX_EROFS as EROFS, LINUX_ESHUTDOWN as ESHUTDOWN, LINUX_ESOCKTNOSUPPORT as ESOCKTNOSUPPORT,
        LINUX_ESPIPE as ESPIPE, LINUX_ESRCH as ESRCH, LINUX_ESTALE as ESTALE,
        LINUX_ETIMEDOUT as ETIMEDOUT, LINUX_ETOOMANYREFS as ETOOMANYREFS, LINUX_ETXTBSY as ETXTBSY,
        LINUX_EUCLEAN as EUCLEAN, LINUX_EXDEV as EXDEV,
    };
}
```
Adjust the list to exactly match the names that existed in the old module (add/remove per Step 1's `comm` output). Every name the old module had must resolve.

- [ ] **Step 2b: Verify every name resolves**

Run: `cargo build 2>&1 | grep -i 'cannot find\|unresolved' || echo OK`
Expected: `OK` (every `linux_errno::X` now resolves to a `LINUX_X` re-export). Fix any name mismatch by adding the missing `LINUX_*` const to `linux_abi.rs`.

- [ ] **Step 3: Run the errno tests**

Run: `cargo test --lib linux_errno && cargo test --lib macos_to_linux`
Expected: PASS — `linux_errno_constants_match_kernel_uapi` and the `macos_to_linux_errno` assertions now validate the single canonical table.

- [ ] **Step 4: Clippy + full lib tests**

Run: `cargo clippy --all-targets -- -D warnings && cargo test --lib`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/mod.rs src/linux_abi.rs
git commit -m "refactor: single source of truth for Linux errno numbers

The linux_errno module in dispatch/mod.rs redefined ~80 errno constants
that already exist as LINUX_E* in linux_abi.rs (EFAULT=14 written twice).
Re-export from linux_abi instead so the numbers can't drift; callers keep
the linux_errno::EFAULT spelling."
```

---

## Phase 4 — Missing `MAP_NORESERVE` on the guest arena

### Task 7: Add `MAP_NORESERVE` to anonymous guest mappings and measure

**Why:** `map_shared_anon` (`src/host_mapping.rs:21`) maps every guest region — including the 2 GiB mmap arena (`src/memory.rs:80`) and 128 MiB heap — without `MAP_NORESERVE`. RSS is already lazy on macOS (untouched pages cost nothing), but without NORESERVE macOS reserves swap/commit backing for the full extent, re-incurred per *forked* guest. One-line change; **must be measured** because macOS overcommits by default and the win may be modest.

**Files:**
- Modify: `src/host_mapping.rs:25-34` (`map_shared_anon`)
- Test: `src/host_mapping.rs` test module (the existing `owned_host_mapping_unmaps_on_drop`)

- [ ] **Step 1: Record a baseline measurement BEFORE the change**

Run:
```bash
./scripts/build-signed.sh
/usr/bin/time -l ./target/release/carrick run /bin/true 2>&1 | grep -i 'maximum resident'
vmmap $(pgrep -n carrick) 2>/dev/null | grep -iE 'SWAP|MALLOC|VM_ALLOCATE' | head
```
Record peak RSS and swap-reserved figures. (For a clean number, run `/bin/true` from a small rootfs.) Save to the commit message.

- [ ] **Step 2: Add the flag**

In `src/host_mapping.rs`, `map_shared_anon`, change:
```rust
                libc::MAP_ANON | libc::MAP_SHARED,
```
to:
```rust
                // MAP_NORESERVE: the guest arena (2 GiB) + heap (128 MiB) are
                // demand-zero; the guest can't exceed the arena, so the
                // overcommit-SIGSEGV caveat doesn't apply. Without this,
                // macOS reserves swap backing for the full extent — re-paid
                // per forked guest. RSS is already lazy regardless.
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_NORESERVE,
```

- [ ] **Step 3: Verify the mapping test still passes**

Run: `cargo test --lib owned_host_mapping_unmaps_on_drop`
Expected: PASS (NORESERVE doesn't change map/unmap semantics).

- [ ] **Step 4: Re-measure AFTER**

Re-run Step 1's commands. Compare swap-reserved and peak RSS. Expected: swap reservation for untouched arena pages drops; RSS roughly unchanged (already lazy). If there is **no** measurable difference, that's a valid finding — note it and still keep the flag (it's correct intent, zero cost).

- [ ] **Step 5: Fork-heavy check**

Run a fork-heavy workload (`carrick run ubuntu:24.04 /bin/sh -c 'for i in $(seq 1 50); do /bin/true; done'`) and watch aggregate memory pressure with `footprint`/Activity Monitor before/after. The per-fork reservation is where NORESERVE should help most.

- [ ] **Step 6: Commit with the measurements**

```bash
git add src/host_mapping.rs
git commit -m "perf: MAP_NORESERVE on anonymous guest mappings

The 2 GiB arena + 128 MiB heap were mapped without NORESERVE, so macOS
reserved swap backing for the full extent, re-paid per forked guest. The
pages are demand-zero and the guest can't exceed the arena, so NORESERVE
is safe. Measured: <before RSS/swap> -> <after RSS/swap>."
```

---

## Phase 5 — Collapse the triplicated syscall-routing tables (the big structural win)

### Task 8: Route the multi-threaded path through `dispatch_normalized` (delete the 8 `dispatch_threaded_*` functions)

**Why:** Syscall routing is expressed three times: `handler_for_aarch64()` (`src/syscall.rs:68`), `normalized_dispatch!` (`src/dispatch/mod.rs:1181`, the self-described authoritative registry), and 8 `dispatch_threaded_*` functions that re-list ~180 syscall numbers and end in `unreachable!()` drift-guards. The single-threaded path already does it right: `dispatch_inner` records entry/return once and delegates to `dispatch_normalized`. `dispatch_normalized` **already takes `thread: Option<ThreadCtx>`** — so the threaded path can build a `ThreadCtx` and call the exact same code. This deletes ~400 lines and an entire bug class.

**Strategy:** This is the largest and riskiest task. Do it **incrementally and behind the conformance harness**: convert the threaded path to delegate to a shared inner that calls `dispatch_normalized` with `thread: Some(...)`, then delete the per-subsystem threaded functions one at a time, running tests after each deletion. The thread-only behaviors (futex `dispatch_threaded_futex`, signal-route `dispatch_threaded_signal_route`, `tkill`/`tgkill` self-vs-sibling pre-check, lifecycle clone) must be reachable via `dispatch_normalized` handlers that read `ctx.thread` — verify each is already a normalized handler or migrate it first.

**Files:**
- Modify: `src/dispatch/mod.rs` (`dispatch_threaded`, `dispatch_threaded_shared`, `dispatch_threaded_process`, `dispatch_threaded_credentials`, `dispatch_threaded_independent`, `dispatch_threaded_futex`, `dispatch_threaded_signal_route`, `dispatch_threaded_unhandled`)
- Modify: `src/dispatch/time.rs`, `fs.rs`, `net.rs`, `mem.rs`, `proc.rs`, `signal.rs` (delete the `dispatch_threaded_*` functions)
- Possibly modify: `src/syscall.rs` (`SyscallHandler`/`syscall_handler_is` become report-only)
- Test: `tests/syscall_thread.rs`, `tests/concurrency_contracts.rs`, `tests/thread_stress_harness.rs`, plus LTP conformance.

- [ ] **Step 1: Record the pre-refactor conformance + thread baseline**

Run: `cargo test --test syscall_thread --test concurrency_contracts --test thread_stress_harness` and the LTP signals/futex conformance areas (per `ltp-conformance` skill). Save the green baseline — this is the regression oracle for the whole task.

- [ ] **Step 2: Verify every threaded-only handler reads `ctx.thread` and is in `normalized_dispatch!`**

Run: `grep -n 'ctx.thread\|thread: Some\|ThreadCtx' src/dispatch/*.rs`
For each syscall currently special-cased in the threaded path (futex `98`, the signal-route numbers, `tkill`/`tgkill`, `clone`, `set_tid_address`, `gettid`, `exit`/`exit_group`), confirm there is a normalized handler that takes `&mut SyscallCtx` and reads `ctx.thread`. List any that are **not** yet normalized — those must be migrated into `normalized_dispatch!` (reading `ctx.thread.ok_or(...)` for tid-required ones) as a precursor sub-step before deletion. Do this migration one syscall at a time with a `cargo test --test syscall_thread` run between each.

- [ ] **Step 3: Add a `dispatch_threaded_inner` that mirrors `dispatch_inner` but always threaded**

In `src/dispatch/mod.rs`, replace the body of `dispatch_threaded` so that, after `dispatch_threaded_shared` returns `None` (meaning: not yet migrated), it builds a `ThreadCtx` and delegates to the normalized path. Concretely, make `dispatch_threaded` call:
```rust
    pub fn dispatch_threaded(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        let thread = ThreadCtx { tid, registry, futex };
        // SyscallDispatcher's normalized handlers take &mut self; the
        // threaded path holds &self with interior locks per subsystem.
        // dispatch_normalized requires &mut self today — see Step 4 for
        // the &self adaptation.
        self.dispatch_threaded_via_normalized(request, memory, reporter, thread)
    }
```
NOTE the borrow mismatch: `dispatch_normalized`/`dispatch_inner` take `&mut self`, but `dispatch_threaded` takes `&self` (the BKL-free design shares the dispatcher as `Arc<KernelState>` with per-subsystem interior locks). This is the crux. Resolve it in Step 4.

- [ ] **Step 4: Reconcile `&self` vs `&mut self` on the normalized path**

Investigate why `dispatch_normalized` needs `&mut self`. Run: `grep -n 'fn dispatch_normalized\|&mut self' src/dispatch/mod.rs | head` and inspect which handlers mutate `self`. Two options, pick based on what you find:
  - **(a)** If handlers only mutate state already behind interior `Mutex`/`RwLock` (the post-BKL design), change the normalized handler signature from `&mut self` to `&self` throughout (mechanical; the compiler enumerates every handler needing the change). This unifies both paths on `&self` and is the clean end state.
  - **(b)** If some handlers genuinely need `&mut self` (single-threaded-only state), keep two entry points but extract the shared recording+`dispatch_normalized` core into a generic helper parameterized over the dispatch closure, so the entry/return instrumentation exists once.

Prefer (a) — it's the natural completion of the BKL retirement. Verify with `cargo build` after the signature change; fix each handler the compiler flags.

- [ ] **Step 5: Implement `dispatch_threaded_via_normalized`**

```rust
    fn dispatch_threaded_via_normalized(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx,
    ) -> Result<DispatchOutcome, DispatchError> {
        let name = lookup_aarch64(request.number).map_or("unknown", |s| s.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name,
            args: request.args,
        });
        let outcome = match self.dispatch_normalized(request, memory, reporter, Some(thread)) {
            Some(result) => result?,
            None => {
                reporter.record(CompatEvent::unhandled_syscall(request.number, name, request.args));
                DispatchOutcome::Errno { errno: LINUX_ENOSYS }
            }
        };
        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn { number: request.number, name, retval, errno });
        Ok(outcome)
    }
```
(This assumes Task 4 already made `name` a `&'static str`.)

- [ ] **Step 6: Delete the per-subsystem threaded functions ONE AT A TIME**

For each of `dispatch_threaded_time` (`time.rs`), `dispatch_threaded_fs` (`fs.rs`), `dispatch_threaded_net` (`net.rs`), `dispatch_threaded_memory` (`mem.rs`), `dispatch_threaded_lifecycle` (`proc.rs`), `dispatch_threaded_signal` (`signal.rs`), `dispatch_threaded_process` and `dispatch_threaded_credentials` (`mod.rs`):
  1. Remove its call from `dispatch_threaded_shared`.
  2. Delete the function (its numbered match arms are redundant with `normalized_dispatch!`).
  3. Run: `cargo test --test syscall_thread --test concurrency_contracts`
  4. If green, commit that single deletion; if red, the syscall wasn't fully normalized — go back to Step 2 for that number.

Keep `dispatch_threaded_independent`, `dispatch_threaded_futex`, `dispatch_threaded_signal_route` only if they encode behavior not expressible as a normalized handler reading `ctx.thread`; otherwise fold them in too. The goal end state: `dispatch_threaded_shared` is gone and `dispatch_threaded` is just `dispatch_threaded_via_normalized`.

- [ ] **Step 7: Demote `SyscallHandler`/`syscall_handler_is` to report-only or delete**

Once nothing calls `syscall_handler_is` for routing (`grep -rn 'syscall_handler_is' src/`), either delete `SyscallHandler` + `handler_for_aarch64` or keep them solely for the compat report's per-subsystem stats. Decide based on whether the report uses them: `grep -rn 'SyscallHandler::' src/`.

- [ ] **Step 8: Full regression — the oracle**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && ./scripts/build-signed.sh`
Then run the LTP differential conformance (signals, futex, timers, fs, mm) per the `ltp-conformance` skill, plus the python http.server concurrent-curl demo and `apt-get install hello`.
Expected: all match the Step 1 baseline. This task is NOT done until conformance matches.

- [ ] **Step 9: Final commit (squash the per-deletion commits if desired)**

```bash
git add -A
git commit -m "refactor: route threaded dispatch through dispatch_normalized

Syscall routing lived in 3 tables (handler_for_aarch64, normalized_dispatch!,
8 dispatch_threaded_* fns re-listing ~180 numbers + unreachable! guards).
The threaded path now builds a ThreadCtx and calls dispatch_normalized like
the single-threaded path already does. Deletes ~400 lines and the entire
class of 'added to one table but not the others' bugs. Conformance
(LTP signals/futex/timers/fs/mm) matches pre-refactor baseline."
```

---

## Phase 6 — Argument-extraction & errno ergonomics (incremental, bundled)

### Task 9: Add typed ID newtypes + a `ctx.args` extractor and `DispatchOutcome::errno` helper, roll out per subsystem

**Why:** fd/pid/tid/guest-addr are bare `i32`/`u64` everywhere (`ctx.arg(0) as i32` appears 37×; `Ok(DispatchOutcome::Errno { errno: ... })` ~580×). Nothing stops passing a guest address where an fd is expected. Typed extraction turns argument-order/validation bugs into compile errors and removes ~300-500 lines of boilerplate. This is the remaining "normalize all handlers" work; roll it out **subsystem by subsystem** so each module shrinks as it migrates.

**Files:**
- Create: `src/dispatch/abi_args.rs` (newtypes + `FromGuestArg` trait + `ctx.args` impl)
- Modify: `src/dispatch/mod.rs` (`DispatchOutcome` helper + `mod abi_args`), then one subsystem module per sub-task.
- Test: new unit tests in `abi_args.rs`; existing per-subsystem tests as the safety net.

- [ ] **Step 1: Write failing tests for the newtypes + extractor**

Create `src/dispatch/abi_args.rs` test module:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fd_from_arg_truncates_to_i32() {
        assert_eq!(Fd::from_arg(0xffff_ffff_0000_0005).0, 5);
    }
    #[test]
    fn guest_ptr_preserves_u64() {
        assert_eq!(GuestPtr::from_arg(0xdead_beef_cafe).0, 0xdead_beef_cafe);
    }
    #[test]
    fn len_too_large_is_efault() {
        // usize::try_from of a value that fits is Ok; the validating
        // extractor rejects absurd lengths.
        assert!(GuestLen::try_from_arg(u64::MAX).is_err());
    }
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test --lib abi_args`
Expected: compile error — types not defined.

- [ ] **Step 3: Implement the newtypes + trait**

In `src/dispatch/abi_args.rs`:
```rust
//! Typed wrappers for raw syscall arguments, so handlers stop doing
//! `ctx.arg(0) as i32` by hand and the compiler distinguishes an fd from
//! a guest address. Zero-cost (repr-transparent newtypes).
use super::{DispatchError, GuestMemory, SyscallCtx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fd(pub i32);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub i32);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPtr(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestLen(pub usize);

pub trait FromGuestArg: Sized {
    fn from_arg(raw: u64) -> Self;
}
impl FromGuestArg for Fd { fn from_arg(raw: u64) -> Self { Fd(raw as i32) } }
impl FromGuestArg for Pid { fn from_arg(raw: u64) -> Self { Pid(raw as i32) } }
impl FromGuestArg for GuestPtr { fn from_arg(raw: u64) -> Self { GuestPtr(raw) } }
impl FromGuestArg for u64 { fn from_arg(raw: u64) -> Self { raw } }

impl GuestLen {
    /// Reject lengths that can't be a real buffer size on this host.
    pub fn try_from_arg(raw: u64) -> Result<Self, DispatchError> {
        usize::try_from(raw).map(GuestLen).map_err(|_| DispatchError::LengthTooLarge)
    }
}

impl<M: GuestMemory> SyscallCtx<'_, M> {
    #[inline]
    pub fn typed_arg<T: FromGuestArg>(&self, index: usize) -> T {
        T::from_arg(self.request.arg(index))
    }
}
```
Confirm `DispatchError::LengthTooLarge` exists (`grep -n 'LengthTooLarge' src/dispatch/`); it's referenced at `fs.rs:2528`.

- [ ] **Step 4: Add the `DispatchOutcome` errno helper + `From<i32>`**

In `src/dispatch/mod.rs` near the `DispatchOutcome` definition:
```rust
impl DispatchOutcome {
    /// Construct an errno outcome. The guest receives `-errno`.
    #[inline]
    pub fn errno(errno: i32) -> Self {
        DispatchOutcome::Errno { errno }
    }
}
impl From<i32> for DispatchOutcome {
    #[inline]
    fn from(errno: i32) -> Self {
        DispatchOutcome::Errno { errno }
    }
}
```

- [ ] **Step 5: Wire the module**

In `src/dispatch/mod.rs`, add `mod abi_args; pub use abi_args::{Fd, Pid, GuestPtr, GuestLen};` (placement matching the existing submodule declarations).

- [ ] **Step 6: Tests pass**

Run: `cargo test --lib abi_args && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Migrate ONE subsystem as the proof (start with `time.rs` — smallest)**

In `src/dispatch/time.rs` handlers, replace `let fd = ctx.arg(0) as i32;` patterns with `let fd: Fd = ctx.typed_arg(0);` and `Ok(DispatchOutcome::Errno { errno: X })` with `Ok(X.into())` (or `Ok(DispatchOutcome::errno(X))`). Run: `cargo test --test syscall_time` after.
Expected: PASS. This proves the ergonomics on a contained module.

- [ ] **Step 8: Commit the foundation + first subsystem**

```bash
git add src/dispatch/abi_args.rs src/dispatch/mod.rs src/dispatch/time.rs
git commit -m "refactor: typed syscall-arg newtypes + DispatchOutcome errno helper

Add Fd/Pid/GuestPtr/GuestLen newtypes and ctx.typed_arg<T>() so handlers
stop hand-casting ctx.arg(0) as i32, plus DispatchOutcome::errno/From<i32>
to cut the ~580 Ok(DispatchOutcome::Errno{..}) sites. Migrate time.rs as
the proof; remaining subsystems follow incrementally."
```

- [ ] **Step 9: Roll out the remaining subsystems incrementally (one commit each)**

Repeat Step 7's migration for `creds.rs`, `mem.rs`, `proc.rs`, `signal.rs`, `net.rs`, then `fs.rs` (largest, last). After each: `cargo test --test syscall_<subsystem> && cargo clippy --all-targets -- -D warnings`, then commit. Do NOT do all subsystems in one commit — keep each reviewable. `fs.rs` alone has 271 errno sites; expect that migration to be the bulk of the line savings.

---

## Deferred (explicitly out of scope — record, don't do now)

These came out of the review but are larger product bets, not code-quality fixes. Capture as follow-ups:

- **Lazy file-backed `MAP_PRIVATE`** (`src/dispatch/mem.rs:285`): eager `pread` of the whole region; a COW file-backed mapping would page in lazily. Needs MAP_PRIVATE write-isolation design. Real perf win for large mmaps; separate plan.
- **`clonefileat` scratch seeding** (`src/apfs.rs`): the now-honest comment from Task 2 points here. Implement O(1) same-volume per-file clone seeding (per-file, NOT per-tree — APFS folder clones are discouraged). Separate plan.
- **`EVFILT_PROC`/`NOTE_EXIT` for the supervisor** (`src/interactive_supervisor.rs:314`) and **`EVFILT_TIMER`** for interval timers (`src/dispatch/time.rs:692`): replace 250ms `poll` loops / per-timer sleep threads with kqueue events on the existing pump. Correct today, just wasteful. Low-leverage tidy-up.
- **Zygote / process pool** for fork-heavy workloads (apt): the real fork-latency lever per `project_fork_latency` memory; architectural, separate plan.
- **`io_wait` per-wait `dup` + EV_ADD/EV_DELETE churn** (`src/io_wait.rs:56`): persistent per-fd kqueue registrations. Server-workload perf; needs care around guest-closes-fd-mid-wait semantics. Separate plan.

## Explicitly NOT doing (would be churn — the review said leave them)

`goblin`, `zerocopy` (correct over bytemuck), `bitflags`, `tar` (sync — safe from the TARmageddon CVE), `flate2/rust_backend`, `applevisor`. Do **not** sweep the 1114 `libc::` calls into `rustix`/`nix`/`mach2` (they're macOS-host-side; no win, real risk in fork/signal paths). Do **not** replace the hand-rolled `linux_abi.rs` structs with `linux-raw-sys` (the inline ABI-hazard comments are the asset). `cargo audit` is clean.

---

## Self-Review notes

- **Spec coverage:** every Tier-1/2/3 finding from the review maps to a task: String allocs→T4, threaded-dispatch→T8, MAP_NORESERVE→T7, volatile memory→T5, MAP_PRIVATE→Deferred, reflink dead dep→T2, errno dedup→T6, primitive obsession + errno wrapping→T9, oci-client→T3, rt-multi-thread→T1, EVFILT tidy-ups→Deferred.
- **Risk ordering:** T1-T3 isolated; T4-T7 contained; T8 is the high-risk refactor, gated on conformance with a recorded baseline (Step 1) and incremental per-subsystem deletion; T9 incremental per-subsystem.
- **Type consistency:** `Fd`/`Pid`/`GuestPtr`/`GuestLen` and `ctx.typed_arg`/`DispatchOutcome::errno` defined in T9 Step 3-4 are used consistently in T9 Steps 7/9. `ThreadCtx`/`dispatch_normalized(thread: Some(..))` used in T8 matches the real signatures at `mod.rs:1161,394`. T5's volatile helpers assume T4's `&'static str` name (noted in T8 Step 5).

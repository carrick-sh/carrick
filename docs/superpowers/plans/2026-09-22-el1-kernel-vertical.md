# EL1 kernel — first vertical (foundation, files, inotify, transport) Implementation Plan

> **For agentic workers:** Tasks 1, 2, 3, 4 are dispatched to Antigravity workers
> by the director (agy-director). Each worker gets its own worktree. Steps use
> checkbox (`- [ ]`) syntax. Read `AGENTS.md` (Rule 0 codesign, `just` recipes,
> TDD red-first, commit style) before touching code.

**Goal:** Serve inotify09's hot-loop syscalls inside the VM at EL1 with zero HVF
exits, behind a default-on `CARRICK_EL1=0` hatch, with Linux semantics intact.

**Architecture:** A `no_std` `carrick-el1` image, built for
`aarch64-unknown-none-softfloat` and embedded in the host binary, is loaded into a
kernel-only guest region. The existing mailbox EL1 vector calls it on every
EL0 SVC; it returns SERVED (eret with x0) or FORWARD (fall through to the
existing `hvc #2` mailbox capture). Kernel objects are delegated whole (typed
`Delegated` state on the host, recall to take them back), never by field.

**Tech Stack:** Rust 1.96.0, `no_std` + `aarch64-unknown-none-softfloat`, `rust-lld`,
`rust-objcopy`, applevisor/HVF, existing `carrick-conformance-contract`.

**Spec:** `docs/superpowers/specs/2026-09-22-el1-kernel-design.md`

## Global Constraints

- Default ON; `CARRICK_EL1=0` restores today's exact vector bytes (bisection hatch).
- EL1 region is never EL0-mapped (stage-1 AP=00, PXN/UXN as appropriate).
- Guest-side logic that is not arch glue must be host-testable (`cargo test -p carrick-el1 --features host-test`).
- No widened budgets, retries, timeouts; red-first test before every behaviour change.
- Stop rule: if Tasks 3+4 do not make inotify09's hot loop exit-free, stop and report.
- Commit style per AGENTS.md; trailer `Co-Authored-By: Antigravity <agy@google.com>` for worker commits.

## File map

| Path | Responsibility | Task |
|---|---|---|
| `crates/carrick-el1-abi/` (new, `no_std`) | Region layout, trap frame, action codes, object table layout, recall words, counters | 1 |
| `crates/carrick-el1/` (new, `no_std`) | EL1 kernel: entry, dispatch table, allocator, locks; later file + inotify ops | 1, 3, 4 |
| `crates/carrick-el1-image/` (new, host) | `build.rs` builds `carrick-el1` for `aarch64-unknown-none`, objcopies, exposes `pub static IMAGE: &[u8]` | 1 |
| `crates/carrick-mem/src/memory.rs` | Region constants; stage-1 kernel-only mapping; vector hook | 1 |
| `crates/carrick-kernel/src/dispatch/fd_table.rs`, new `crates/carrick-kernel/src/el1_delegation.rs` | `Delegated` description state, delegate-at-open, recall | 3 |
| `crates/carrick-kernel/src/inotify.rs` | Delegated inotify instances + recall | 4 |
| `crates/carrick-vmm-hvf/src/trap.rs`, `hvf_aarch64_engine.rs` | Exit-path slimming | 2 |
| `conformance-contracts/contracts/el1-*.toml`, `transport-exit-overhead.toml` | Contracts | 1–4 |

---

### Task 1: EL1 foundation (transparent image on every SVC)

**Files:** create `crates/carrick-el1-abi/{Cargo.toml,src/lib.rs}`,
`crates/carrick-el1/{Cargo.toml,src/lib.rs,src/entry.rs,src/alloc.rs,src/lock.rs,link.ld}`,
`crates/carrick-el1-image/{Cargo.toml,build.rs,src/lib.rs}`; modify
`Cargo.toml` (workspace members; exclude `carrick-el1` from default host build
if needed), `rust-toolchain.toml` (add `aarch64-unknown-none`),
`crates/carrick-mem/src/memory.rs`, `crates/carrick-mem/Cargo.toml`.

**Interfaces produced:**
- `carrick_el1_abi::{EL1_REGION_BASE, EL1_REGION_SIZE, EL1_IMAGE_OFFSET, EL1_STACKS_OFFSET, EL1_STACK_SIZE, EL1_HEAP_OFFSET, EL1_COUNTERS_OFFSET}`
- `#[repr(C)] pub struct TrapFrame { pub x: [u64; 31], pub elr: u64, pub spsr: u64, pub esr: u64, pub slot: u64 }`
- `pub enum Action { Served = 0, Forward = 1 }` (returned in x0 of the entry)
- `#[repr(C)] pub struct Counters { pub served: [u64; 512], pub forwarded: [u64; 512] }` indexed by syscall nr
- Image entry symbol `carrick_el1_syscall(frame: *mut TrapFrame) -> u64` at `EL1_IMAGE_OFFSET` + value of a header word (image header: magic `b"CEL1"`, version u32, entry offset u64, image size u64).
- `carrick_el1_image::IMAGE: &'static [u8]`

Steps:
- [x] Task 1 landed on main at c1dac9055 (softfloat image, atomic counters, shared region, one kernel-only range predicate).
- [ ] Pick `EL1_REGION_BASE` in an unused VA/IPA range (verify against every `LINUX_*` constant in `memory.rs`; add a `const _: () = assert!` non-overlap check). Size 64 MiB.
- [ ] Red test in `carrick-mem`: memory image built with EL1 enabled contains a region at `EL1_REGION_BASE` whose first bytes are the image header, and stage-1 walk of that VA from EL0 permission is denied, from EL1 permitted. Run `cargo test -p carrick-mem --lib el1_region` → FAIL.
- [ ] Implement abi crate, image crate (`build.rs` runs `cargo build -p carrick-el1 --target aarch64-unknown-none --release` into `OUT_DIR/el1-target`, then `rust-objcopy -O binary`; fail the build loudly if the target is missing), region mapping through the same generic region list the identity page uses. Test → PASS.
- [ ] Red test: vector bytes with EL1 enabled differ from `el1_vectors_bytes_mailbox(true)` only by the hook; with `CARRICK_EL1=0` they are byte-identical. Implement the hook: before `mailbox_capture`, save x0–x30/ELR/SPSR/ESR to the per-slot EL1 stack (`EL1_STACKS_OFFSET + slot*EL1_STACK_SIZE`, slot derived from SP_EL1's mailbox slot index), switch SP, `blr` the entry, on `Served` restore x1–x30, set x0 from frame, `eret`; on `Forward` restore everything and branch to `mailbox_capture`. Test → PASS.
- [ ] Guest kernel increments `Counters.forwarded[nr]` and returns `Forward` for every call. Host-testable unit test of the dispatch table.
- [ ] Signed proof: `just build`, then `just conformance-probes` must be unchanged vs `CARRICK_EL1=0`; an embed test reads `Counters.forwarded[172 or 64]` > 0 after a guest runs (`just test-embed el1_`).
- [ ] Contract `conformance-contracts/contracts/el1-transparent.toml` (id `kernel.el1.transparent`), bound to the tests above. `cargo run -p carrick-conformance-contract --bin check-contracts -- --root .` passes.
- [ ] `just ci` exit 0. Commit.

### Task 2: Transport slimming (parallel, independent)

**Files:** `crates/carrick-vmm-hvf/src/trap.rs` (exit path only),
`crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`,
`conformance-contracts/contracts/transport-exit-overhead.toml`. Do not touch
`carrick-mem` or any `carrick-el1*` crate.

- [ ] Measure: `carrick trace -s scripts/dtrace/hvf-syscall-transport.d` on the `perf_trap_floor` probe (`/bin/sh -c 'exec /p/perf_trap_floor'`); record reg reads/writes and phases per exit. Current `invalid_seek_batch_p50_us` = 1.388 (binary 0f657b02); bare exit floor 0.65 µs.
- [ ] Red contract `kernel.transport.exit-overhead`: structural budget on host register accesses and host syscalls per forwarded syscall (take the measured counts as red, target the minimum the ABI needs); timing screen invalid-fd lseek < 1.0 µs.
- [ ] Remove per-exit work not required by the ABI (redundant get/set_reg, per-exit host syscalls, per-exit probe argument construction when disabled). One change per commit, each re-measured.
- [ ] `just ci` exit 0; signed `just conformance-probes` unchanged. Commit.

### Task 3: Delegated rootfs regular files (after Task 1)

**Files:** `carrick-el1-abi` (file object layout), `carrick-el1/src/file.rs`,
`carrick-el1/src/pagecache.rs`, `crates/carrick-kernel/src/el1_delegation.rs`
(new), `crates/carrick-kernel/src/dispatch/fd_table.rs` (add `Delegated`),
`crates/carrick-kernel/src/dispatch/fs/{open.rs,rw.rs,close_dup.rs,stat.rs}`
(delegate at open, recall at dup/close/fork/exec/proc readlink), contract
`el1-files.toml`.

- [ ] Red host-testable tests in `carrick-el1`: read/write/pread/pwrite/readv/writev/lseek/fstat on a delegated file object match a reference model (offset, size, EFAULT prefix semantics per `dispatch::fs::tests::readonly_destination_offsets`, SEEK_DATA/HOLE via forward).
- [ ] Red VM-free tests in `carrick-kernel`: delegation eligibility (private rootfs regular file, no fanotify/inotify-on-host observer, not `--fs host`); recall restores exact offset/size/bytes; dup shares the delegated object; fork keeps it (share count); exec with O_CLOEXEC recalls/closes.
- [ ] Implement; `just test-kernel` passes.
- [ ] Signed: embed test runs a guest doing 10k `write`+`lseek` pairs; `Counters.served[64]` and `[62]` ≥ 10k and host dispatch count for those nrs is 0 in the loop. Docker differential: the `syscall_write_destinations` fixture and the write-seek contract fixture unchanged.
- [ ] `just ci`; commit.

### Task 4: Delegated inotify (after Task 3)

**Files:** `carrick-el1/src/inotify.rs`, abi layout, `crates/carrick-kernel/src/inotify.rs`, contract `el1-inotify.toml`.

- [ ] Red host-testable tests: add/rm watch, IN_IGNORED ordering, event emission from delegated write/lseek, queue overflow, descriptor reuse and coalescing matching the oracle rows in `docs/perf-results/2026-09-21-syscall-floor/inotify-first-principles/`.
- [ ] Recall of an inotify instance when a watched object is recalled or a non-delegated path is watched.
- [ ] Signed: inotify09 hot loop served count ≥ iterations×5 and zero forwarded for nrs 26/27/28/62/64/113 inside the loop; LTP inotify09 TPASS under the harness wrapper.
- [ ] `just ci`; commit.

### Task 5 (director): acceptance

- [ ] Freeze signed artifacts (SHA, CDHash, LC_UUID, entitlement, DOF); `just conformance-probes`, `just conformance smoke`, `just conformance`.
- [ ] Balanced untraced inotify09 timing vs `CARRICK_EL1=0`, then Docker serially. Screen: < 12 s.
- [ ] Update handoff, contracts' unresolved bindings, memory.

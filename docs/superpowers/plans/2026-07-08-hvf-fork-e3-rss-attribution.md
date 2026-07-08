# HVF Fork E3 RSS Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Attribute HVF host-fork resident footprint by guest mapping class and decide whether E3 has a safe RSS reduction or must hand off a blocked reduction track.

**Architecture:** Add a backend hook that the shared AArch64 engine calls immediately before `libc::fork`, beside the existing total `fork__footprint` probe. The default hook is a no-op for non-HVF backends; HVF uses its live `HvfMappedRegion` list to classify mappings, bound the mmap-arena scan to the published high-water mark, count resident pages with `mincore`, and emit per-class USDT samples for DTrace.

**Tech Stack:** Rust 2024 workspace, macOS HVF, Carrick USDT probes, DTrace, `just build`, AArch64 Linux conformance probes.

## Global Constraints

- Preserve Carrick's one-Linux-process-to-one-host-process invariant.
- Do not introduce a hot-path daemon, supervisor RPC on fork/block/wake, M:N scheduler, or guest-kernel fallback.
- Do not optimize VM/vCPU create, teardown, admission, or stage-2 replay unless fresh E3 evidence overturns E2.2.
- Use `just build` before HVF guest/probe runs.
- Never run Carrick and the Docker oracle concurrently.
- Keep unrelated dirty files out of commits.
- Current code and fresh measurements win over prior narrative.

---

### Task 1: Stable Mapping Classification

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`

**Interfaces:**
- Produces: `fork_footprint_class_id(start: u64, guest_shared: bool, guest_writable: bool) -> i32`
- Produces: numeric class IDs emitted by Task 3:
  - `1`: private mmap arena
  - `2`: private heap
  - `3`: private overlay
  - `4`: private high-VA alias
  - `5`: private writable other
  - `6`: private read-only/internal
  - `7`: shared aperture
  - `8`: shared other
  - `9`: private page tables

- [x] **Step 1: Write the failing classifier test**

Add this test to the existing `#[cfg(test)]` tests in `crates/carrick-vmm-hvf/src/trap.rs`:

```rust
#[test]
fn fork_footprint_classifies_guest_mapping_roles() {
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_MMAP_BASE, false, true),
        FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA
    );
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_HEAP_BASE, false, true),
        FORK_FOOTPRINT_CLASS_PRIVATE_HEAP
    );
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_PRIVATE_OVERLAY_BASE, false, true),
        FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY
    );
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_SHARED_FILE_BASE, true, true),
        FORK_FOOTPRINT_CLASS_SHARED_APERTURE
    );
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_HIGH_VA_THRESHOLD, false, true),
        FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS
    );
    assert_eq!(
        fork_footprint_class_id(0x4000, false, false),
        FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL
    );
    assert_eq!(
        fork_footprint_class_id(crate::memory::LINUX_PAGE_TABLES_BASE, false, true),
        FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES
    );
}
```

- [x] **Step 2: Run the test and verify it fails for the expected reason**

Run:

```bash
cargo test -p carrick-vmm-hvf --lib fork_footprint_classifies_guest_mapping_roles
```

Expected: compile failure naming `fork_footprint_class_id` or the `FORK_FOOTPRINT_CLASS_*` constants.

- [x] **Step 3: Add the classifier constants and helper**

Add near the fork helper section in `crates/carrick-vmm-hvf/src/trap.rs`:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA: i32 = 1;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_HEAP: i32 = 2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY: i32 = 3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS: i32 = 4;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_WRITABLE_OTHER: i32 = 5;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL: i32 = 6;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_SHARED_APERTURE: i32 = 7;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_SHARED_OTHER: i32 = 8;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES: i32 = 9;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_footprint_class_id(start: u64, guest_shared: bool, guest_writable: bool) -> i32 {
    if guest_shared {
        if start == crate::memory::LINUX_SHARED_FILE_BASE {
            return FORK_FOOTPRINT_CLASS_SHARED_APERTURE;
        }
        return FORK_FOOTPRINT_CLASS_SHARED_OTHER;
    }
    if start == crate::memory::LINUX_MMAP_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_MMAP_ARENA;
    }
    if start == crate::memory::LINUX_HEAP_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_HEAP;
    }
    if start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_OVERLAY;
    }
    if start == crate::memory::LINUX_PAGE_TABLES_BASE {
        return FORK_FOOTPRINT_CLASS_PRIVATE_PAGE_TABLES;
    }
    if crate::memory::is_high_va(start) {
        return FORK_FOOTPRINT_CLASS_PRIVATE_HIGH_ALIAS;
    }
    if guest_writable {
        FORK_FOOTPRINT_CLASS_PRIVATE_WRITABLE_OTHER
    } else {
        FORK_FOOTPRINT_CLASS_PRIVATE_RO_OR_INTERNAL
    }
}
```

- [x] **Step 4: Run the classifier test and verify it passes**

Run:

```bash
cargo test -p carrick-vmm-hvf --lib fork_footprint_classifies_guest_mapping_roles
```

Expected: `test result: ok`.

### Task 2: Probe Surface and AArch64 Hook

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-aarch64/src/vmm.rs`
- Modify: `crates/carrick-aarch64/src/engine.rs`

**Interfaces:**
- Produces: `carrick_observability::probes::fork_footprint_class(class_id, region_count, scan_bytes, resident_bytes, flags)`
- Produces: `Aarch64Vmm::emit_fork_footprint_attribution(&self, arena_high_water: u64)`

- [x] **Step 1: Add the USDT probe declaration, real wrapper, and stub**

Add `fn fork__footprint__class(_: i32, _: u64, _: u64, _: u64, _: u64) {}` beside `fork__footprint`.

Add this real wrapper beside `fork_footprint`:

```rust
pub fn fork_footprint_class(
    class_id: i32,
    region_count: u64,
    scan_bytes: u64,
    resident_bytes: u64,
    flags: u64,
) {
    carrick_usdt::fork__footprint__class!(|| {
        (class_id, region_count, scan_bytes, resident_bytes, flags)
    });
}
```

Add this stub mirror:

```rust
stub!(fork_footprint_class(class_id: i32, region_count: u64, scan_bytes: u64, resident_bytes: u64, flags: u64));
```

- [x] **Step 2: Add the default AArch64 VMM hook**

Add this default method to `Aarch64Vmm` in `crates/carrick-aarch64/src/vmm.rs` near the fork hooks:

```rust
fn emit_fork_footprint_attribution(&self, _arena_high_water: u64) {}
```

- [x] **Step 3: Call the hook at the fork boundary**

In `Aarch64EngineCore::fork`, call the hook immediately after `emit_fork_footprint(0, self.fork_arena_high_water);` and before `libc::fork()`:

```rust
self.vm
    .emit_fork_footprint_attribution(self.fork_arena_high_water);
```

- [x] **Step 4: Run a focused check**

Run:

```bash
cargo check -p carrick-observability -p carrick-aarch64
```

Expected: check passes.

### Task 3: HVF Residency Attribution

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`

**Interfaces:**
- Consumes: `Aarch64Vmm::emit_fork_footprint_attribution`
- Consumes: `carrick_observability::probes::fork_footprint_class`
- Produces: `HvfVmState::emit_fork_footprint_attribution(arena_high_water: u64)`

- [x] **Step 1: Add class accumulator and flags**

Add an internal accumulator with these flag bits. The scan is invoked through
`carrick_observability::probes::with_fork_footprint_class_probe`, so the closure
only runs when DTrace enables `fork-footprint-class`.

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_CHILD_OBSERVES: u64 = 1 << 0;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_PARENT_SHARED: u64 = 1 << 1;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_COW_COPY: u64 = 1 << 2;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_GUEST_WRITABLE: u64 = 1 << 3;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const FORK_FOOTPRINT_FLAG_CHILD_SNAPSHOT: u64 = 1 << 4;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Default)]
struct ForkFootprintClassSample {
    region_count: u64,
    scan_bytes: u64,
    resident_bytes: u64,
    flags: u64,
}
```

- [x] **Step 2: Add resident-page counting**

Add a helper that calls `mincore` only on live known mappings:

```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn resident_bytes_for_host_range(host_addr: *mut u8, len: usize) -> u64 {
    if host_addr.is_null() || len == 0 {
        return 0;
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page <= 0 { 16 * 1024 } else { page as usize };
    let pages = len.div_ceil(page);
    let mut resident = vec![0u8; pages];
    let rc = unsafe {
        libc::mincore(
            host_addr.cast::<libc::c_void>(),
            len,
            resident.as_mut_ptr().cast::<libc::c_char>(),
        )
    };
    if rc != 0 {
        return 0;
    }
    resident
        .iter()
        .filter(|flag| **flag & 1 != 0)
        .count()
        .saturating_mul(page) as u64
}
```

- [x] **Step 3: Add HVF attribution emission**

Add `HvfVmState::emit_fork_footprint_attribution` that:

1. Iterates `self.mappings`.
2. Classifies each region with `fork_footprint_class_id`.
3. Uses `arena_high_water - LINUX_MMAP_BASE` capped to the region size for class `1`; other classes scan the full mapping.
4. Counts resident bytes with `resident_bytes_for_host_range`.
5. Emits one `fork_footprint_class` sample per non-empty class.

The flags are:

```rust
let mut flags = FORK_FOOTPRINT_FLAG_CHILD_OBSERVES;
if m.guest_shared {
    flags |= FORK_FOOTPRINT_FLAG_PARENT_SHARED;
} else if m.start == crate::memory::LINUX_PAGE_TABLES_BASE {
    flags |= FORK_FOOTPRINT_FLAG_CHILD_SNAPSHOT;
} else {
    flags |= FORK_FOOTPRINT_FLAG_COW_COPY;
}
if m.guest_writable {
    flags |= FORK_FOOTPRINT_FLAG_GUEST_WRITABLE;
}
```

- [x] **Step 4: Wire the HVF trait override**

In `impl Aarch64Vmm for HvfAarch64Vmm`, add:

```rust
fn emit_fork_footprint_attribution(&self, arena_high_water: u64) {
    self.state.emit_fork_footprint_attribution(arena_high_water);
}
```

- [x] **Step 5: Run focused checks**

Run:

```bash
cargo check -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf
```

Expected: check passes.

### Task 4: DTrace Class Output and Signed Measurements

**Files:**
- Modify: `scripts/dtrace/fork-phases.d`
- Create: `target/conformance/logs/hvf-fork-e3/`

**Interfaces:**
- Consumes: `fork-footprint-class` DTrace probe.
- Produces: small/large `perf_fork`, `perf_fork_exec`, and `fork-phases.d` logs.

- [x] **Step 1: Update DTrace output**

Add a `fork-footprint-class` clause:

```d
carrick*:::fork-footprint-class
/(pid == $target || progenyof($target)) && arg0 != 0/
{
    printf("[%d] fork-footprint-class class=%d regions=%d scan_bytes=%d resident_bytes=%d flags=%d\n",
        pid, (int)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
    @footprint_class_regions[(int)arg0] = avg((uint64_t)arg1);
    @footprint_class_scan_bytes[(int)arg0] = avg((uint64_t)arg2);
    @footprint_class_resident_bytes[(int)arg0] = avg((uint64_t)arg3);
    @footprint_class_flags[(int)arg0] = avg((uint64_t)arg4);
    @footprint_class_count[(int)arg0] = count();
}
```

Add matching `printa` lines in `dtrace:::END`.

- [x] **Step 2: Format and compile-check**

Run:

```bash
cargo fmt -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf
cargo check -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf
```

Expected: both pass.

- [x] **Step 3: Build signed binary and probes**

Run:

```bash
just build
scripts/build-probes.sh
otool -l target/release/carrick | rg -a 'dof|__dof_carrick|segname|sectname'
codesign -d --entitlements - target/release/carrick
```

Expected: build succeeds, `__dof_carrick` is present, and `com.apple.security.hypervisor` is true.

- [x] **Step 4: Run Carrick-only perf probes**

Run the four Carrick-only commands from `docs/2026-07-08-hvf-fork-e22-evidence.md`, writing logs under `target/conformance/logs/hvf-fork-e3/`:

```bash
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 240 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 360 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && FORK_MEM_MB=256 /tmp/p'
```

Expected: each command exits 0 and prints p50/p95/min.

- [x] **Step 5: Run focused DTrace samples**

Run:

```bash
timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'
timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 256'
```

Expected: each exits 0 and prints both `fork-footprint` and `fork-footprint-class` rows.

### Task 5: E3 Evidence, Reduction Decision, and Commit

**Files:**
- Create: `docs/2026-07-08-hvf-fork-e3-evidence.md`
- Modify only if implementation requires it: source/probe files from Tasks 1-4

**Interfaces:**
- Consumes: logs in `target/conformance/logs/hvf-fork-e3/`
- Produces: the committed E3 verdict artifact required by the goal.

- [x] **Step 1: Write the evidence artifact**

The document must include:

```markdown
# HVF Fork Floor E3 Host Fork RSS Attribution Evidence

Date: 2026-07-08

## Verdict

[State confirmed reduction, no safe reduction, or blocked attribution.]

## Mapping Class Legend

| Class | Meaning | Flags | Child requirement |
|---:|---|---|---|
| 1 | private mmap arena | CHILD_OBSERVES, COW_COPY, GUEST_WRITABLE | ordinary fork child must observe parent bytes |
| 2 | private heap | CHILD_OBSERVES, COW_COPY, GUEST_WRITABLE | ordinary fork child must observe parent bytes |
| 3 | private overlay | CHILD_OBSERVES, COW_COPY, GUEST_WRITABLE | ordinary fork child must observe parent bytes |
| 4 | private high-VA alias | CHILD_OBSERVES, COW_COPY, usually GUEST_WRITABLE | ordinary fork child must observe parent bytes |
| 5 | private writable other | CHILD_OBSERVES, COW_COPY, GUEST_WRITABLE | ordinary fork child must observe parent bytes |
| 6 | private read-only/internal | CHILD_OBSERVES, COW_COPY | runtime and guest must observe bytes |
| 7 | shared aperture | CHILD_OBSERVES, PARENT_SHARED, maybe GUEST_WRITABLE | child must observe shared object |
| 8 | shared other | CHILD_OBSERVES, PARENT_SHARED, maybe GUEST_WRITABLE | child must observe shared object |
| 9 | private page tables | CHILD_OBSERVES, CHILD_SNAPSHOT, GUEST_WRITABLE | child receives explicit sparse snapshot |

## Performance Measurements

[small/large p50 and p95 for perf_fork and perf_fork_exec]

## Focused DTrace Samples

[host fork timing and footprint class table]

## Reduction Decision

[If safe: describe code reduction and before/after effect. If not safe: state blocker and next experiment.]

## Verification Commands

[exact commands and results]
```

- [x] **Step 2: Decide whether a narrow reduction is safe**

Use the DTrace class table:

- If large-footprint growth is in class `1` and flags include `CHILD_OBSERVES|COW_COPY|GUEST_WRITABLE`, do not discard or mark `VM_INHERIT_NONE`; ordinary Linux `fork()` requires child reads to observe the parent's bytes until one side writes.
- If growth is in a class without `CHILD_OBSERVES`, implement a narrow reduction for that class and rerun the measurement commands.
- If the data is insufficient to identify class ownership, write a blocker handoff naming the missing signal and the next exact probe.

- [x] **Step 3: Run final verification**

Run:

```bash
cargo fmt -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf
cargo check -p carrick-observability -p carrick-aarch64 -p carrick-vmm-hvf
just build
```

Expected: all pass.

- [x] **Step 4: Stage only scoped files**

Run:

```bash
git status --short
git add docs/superpowers/plans/2026-07-08-hvf-fork-e3-rss-attribution.md docs/2026-07-08-hvf-fork-e3-evidence.md crates/carrick-observability/src/probes.rs crates/carrick-aarch64/src/vmm.rs crates/carrick-aarch64/src/engine.rs crates/carrick-vmm-hvf/src/trap.rs crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs scripts/dtrace/fork-phases.d
git diff --cached --stat
```

Expected: staged files exclude the pre-existing unrelated dirty files.

- [x] **Step 5: Commit**

Run:

```bash
git commit -m "diagnostics(hvf): attribute fork rss by mapping class"
```

The commit body must state why E3 needed class attribution, what probe/hook was added, the reduction decision, and the verification commands/results.

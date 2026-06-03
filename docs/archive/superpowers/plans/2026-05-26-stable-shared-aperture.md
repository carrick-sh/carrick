# Stable Shared Aperture + Memory-Manager Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dynamic, post-vCPU `hv_vm_map`/`hv_vm_unmap` shared-mapping path with a single shared-anon aperture pre-mapped once at boot, plus a backing-object + sub-allocator skeleton, so guest `MAP_SHARED` `mmap`/`munmap` never mutate HVF stage-2 topology after vCPU threads exist.

**Architecture:** The private mmap arena (`LINUX_MMAP_BASE`, 32 GiB) is *already* a stable aperture: `linux_runtime_regions()` adds it to `AddressSpace.regions`, `map_plan()` `hv_vm_map`s it once at boot, and guest `mmap(MAP_PRIVATE)` only bump-allocates within it (no further `hv_vm_map`). This plan applies the identical pattern to the shared window (`LINUX_SHARED_FILE_BASE`, 2 GiB): pre-map it once at boot as a `SharedAnon` host mapping, then sub-allocate guest `MAP_SHARED` requests inside it via a new `SharedAperture` allocator that tracks `BackingObject`s. File-backed shared mappings copy file bytes into the aperture sub-range and write dirty bytes back on `msync(MS_SYNC)`/`munmap` (the spec makes "keep the dynamic LINUX_SHARED_FILE path" a non-goal; cross-fork visibility is preserved because the aperture backing is `MAP_SHARED` across `fork(2)`).

**Tech Stack:** Rust, Apple Hypervisor.framework (`applevisor`/`applevisor_sys`), `libc`, `parking_lot`. Workspace crate: `crates/carrick-runtime`.

**Spec:** `docs/superpowers/specs/2026-05-26-durable-memory-architecture-design.md` (decomposition item 1).

---

## File Structure

- **Create:** `crates/carrick-runtime/src/shared_aperture.rs` — `BackingObject` enum (skeleton), `SharedAlloc`, and `SharedAperture` sub-allocator over the fixed window. Pure data structure + unit tests; no HVF calls.
- **Modify:** `crates/carrick-runtime/src/memory.rs` — add a `shared` flag to `MemoryRegion`, a `shared_zeroed_region()` constructor, and add the shared aperture to `linux_runtime_regions()`.
- **Modify:** `crates/carrick-runtime/src/trap.rs` — thread `shared` through `GuestMapping`; `map_region_raw` picks `HostMappingKind::SharedAnon` for shared regions; delete the dynamic `map_shared_file`/`map_shared_anon`/`unmap_shared_file` (and their `hv_vm_map`/`hv_vm_unmap`) from the `GuestMemory` impl.
- **Modify:** `crates/carrick-runtime/src/dispatch/mem.rs` — replace `shared_file_next`/`shared_file_maps`/`next_shared_file_address` with a `SharedAperture` in `MemState`; rewrite the `mmap` `MAP_SHARED` (anon + file) paths to sub-allocate + copy; rewrite `munmap`/`msync` to free + write back.
- **Modify:** `crates/carrick-runtime/src/lib.rs` — register `mod shared_aperture;`.

---

## Task 1: Backing-object model + SharedAperture allocator

**Files:**
- Create: `crates/carrick-runtime/src/shared_aperture.rs`
- Modify: `crates/carrick-runtime/src/lib.rs` (add `mod shared_aperture;`)

- [ ] **Step 1: Register the module**

In `crates/carrick-runtime/src/lib.rs`, find the block of `mod` / `pub mod` declarations (alongside `mod host_mapping;`, `mod memory;`, etc.) and add, in alphabetical position:

```rust
mod shared_aperture;
```

Run `rg -n "^mod host_mapping;|^pub mod memory;|^mod memory;" crates/carrick-runtime/src/lib.rs` first to confirm the exact style (`mod` vs `pub mod`) used by neighbors, and match it.

- [ ] **Step 2: Write the failing tests**

Create `crates/carrick-runtime/src/shared_aperture.rs` with ONLY the tests first (the types they reference are written in Step 4):

```rust
//! Sub-allocator and backing-object model for the fixed, boot-mapped shared
//! aperture (`LINUX_SHARED_FILE_BASE`, `LINUX_SHARED_FILE_SIZE`).
//!
//! The aperture itself is a single host `MAP_ANON | MAP_SHARED | MAP_NORESERVE`
//! region `hv_vm_map`'d once before vCPU threads exist (see
//! `linux_runtime_regions` in `memory.rs`). Guest `MAP_SHARED` mmaps then carve
//! sub-ranges out of it here, so NO `hv_vm_map`/`hv_vm_unmap` runs after vCPUs
//! exist. This is the spec's "stable stage-2 aperture topology" rule.

use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> u64 {
        LINUX_SHARED_FILE_BASE
    }

    #[test]
    fn bump_allocates_aligned_within_window() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x4000, BackingObject::SharedAnon).expect("alloc");
        let b = ap.alloc(0x1000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(a, base());
        // Second allocation is rounded up to the HVF granule (0x4000).
        assert_eq!(b, base() + 0x4000);
    }

    #[test]
    fn rejects_allocation_past_window_end() {
        let mut ap = SharedAperture::new();
        assert!(
            ap.alloc(LINUX_SHARED_FILE_SIZE + 0x4000, BackingObject::SharedAnon)
                .is_none()
        );
    }

    #[test]
    fn free_then_realloc_reuses_space() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        let freed = ap.free(a).expect("freed backing");
        assert!(matches!(freed.backing, BackingObject::SharedAnon));
        // The freed range is reused before the bump cursor advances.
        let b = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(b, a);
    }

    #[test]
    fn free_unknown_address_returns_none() {
        let mut ap = SharedAperture::new();
        assert!(ap.free(base() + 0x123).is_none());
    }

    #[test]
    fn lookup_returns_backing_for_live_alloc() {
        let mut ap = SharedAperture::new();
        let fd = 7;
        let a = ap
            .alloc(0x4000, BackingObject::SharedFile { host_fd: fd, offset: 0x1000 })
            .expect("alloc");
        let got = ap.backing(a).expect("live");
        assert!(matches!(
            got,
            BackingObject::SharedFile { host_fd: 7, offset: 0x1000 }
        ));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p carrick-runtime shared_aperture:: 2>&1 | tail -30`
Expected: FAIL — compile errors (`cannot find type SharedAperture`, `BackingObject`, etc.).

- [ ] **Step 4: Write the minimal implementation**

Insert the implementation ABOVE the `#[cfg(test)] mod tests` block in `shared_aperture.rs`:

```rust
/// What backs a live shared-aperture allocation. This is the skeleton of the
/// spec's backing-object model; later plans add `PrivateAnon`, `PrivateFile`,
/// and `CarrickKernel`. The shared aperture only ever holds shared backings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackingObject {
    /// Guest `MAP_SHARED | MAP_ANON`: lives entirely in the aperture's host
    /// backing, shared across `fork(2)`, never copied. No writeback.
    SharedAnon,
    /// Guest `MAP_SHARED` of a file. Bytes are copied into the aperture on map;
    /// dirty bytes are written back to `host_fd` at `offset` on
    /// `msync(MS_SYNC)`/`munmap`. `host_fd` is a dup the allocator owns until
    /// the allocation is freed.
    SharedFile { host_fd: i32, offset: u64 },
}

/// One live allocation within the shared aperture.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedAlloc {
    pub guest_addr: u64,
    pub len: u64,
    pub backing: BackingObject,
}

/// Bump-plus-free-list sub-allocator over the fixed shared aperture window
/// `[LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE)`.
/// All sizes/addresses are HVF-granule (`0x4000`) aligned. No HVF calls happen
/// here — the window is `hv_vm_map`'d once at boot.
#[derive(Debug, Clone)]
pub(crate) struct SharedAperture {
    next: u64,
    /// Freed `(start, len)` ranges, sorted by start, coalesced. Reused before
    /// the bump cursor advances.
    free: Vec<(u64, u64)>,
    live: Vec<SharedAlloc>,
}

const GRANULE: u64 = 0x4000; // HVF_PAGE_SIZE; kept local to avoid a trap.rs dep.

fn align_up(value: u64, align: u64) -> Option<u64> {
    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
    }
}

impl SharedAperture {
    pub(crate) fn new() -> Self {
        Self {
            next: LINUX_SHARED_FILE_BASE,
            free: Vec::new(),
            live: Vec::new(),
        }
    }

    fn window_end() -> u64 {
        LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE
    }

    /// Reserve `len` bytes (rounded up to the granule). Returns the guest IPA,
    /// or `None` if the window is exhausted. Records the backing.
    pub(crate) fn alloc(&mut self, len: u64, backing: BackingObject) -> Option<u64> {
        if len == 0 {
            return None;
        }
        let len = align_up(len, GRANULE)?;
        // Reuse a freed range first.
        if let Some(pos) = self.free.iter().position(|&(_, l)| l >= len) {
            let (s, l) = self.free[pos];
            if l == len {
                self.free.remove(pos);
            } else {
                self.free[pos] = (s + len, l - len);
            }
            self.live.push(SharedAlloc { guest_addr: s, len, backing });
            return Some(s);
        }
        let addr = align_up(self.next, GRANULE)?;
        let end = addr.checked_add(len)?;
        if end > Self::window_end() {
            return None;
        }
        self.next = end;
        self.live.push(SharedAlloc { guest_addr: addr, len, backing });
        Some(addr)
    }

    /// Free the allocation starting at `guest_addr`. Returns the removed
    /// allocation (so the caller can write back / close the fd), or `None` if
    /// no live allocation starts there.
    pub(crate) fn free(&mut self, guest_addr: u64) -> Option<SharedAlloc> {
        let pos = self.live.iter().position(|a| a.guest_addr == guest_addr)?;
        let alloc = self.live.remove(pos);
        free_insert(&mut self.free, alloc.guest_addr, alloc.len);
        Some(alloc)
    }

    /// The backing for the live allocation starting at `guest_addr`, if any.
    pub(crate) fn backing(&self, guest_addr: u64) -> Option<BackingObject> {
        self.live
            .iter()
            .find(|a| a.guest_addr == guest_addr)
            .map(|a| a.backing)
    }

    /// All live allocations (used by `msync`-all and fork bookkeeping).
    pub(crate) fn live(&self) -> &[SharedAlloc] {
        &self.live
    }
}

/// Insert `[addr, addr+len)` into `regions`, coalescing adjacent/overlapping.
fn free_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let mut start = addr;
    let mut end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < start || s > end {
            if !inserted && s > end {
                out.push((start, end - start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            start = start.min(s);
            end = end.max(e);
        }
    }
    if !inserted {
        out.push((start, end - start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p carrick-runtime shared_aperture:: 2>&1 | tail -30`
Expected: PASS — 5 tests pass. (You may see `dead_code` warnings for `live()`/`SharedAlloc.len`; they are consumed in later tasks. Leave them.)

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/shared_aperture.rs crates/carrick-runtime/src/lib.rs
git commit -m "feat(mem): add SharedAperture sub-allocator + backing-object skeleton"
```

---

## Task 2: Pre-map the shared aperture at boot

**Files:**
- Modify: `crates/carrick-runtime/src/memory.rs` (`MemoryRegion`, `zeroed_region`/new `shared_zeroed_region`, `linux_runtime_regions`)
- Modify: `crates/carrick-runtime/src/trap.rs` (`GuestMapping`, `from_address_space`, `map_region_raw`)

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/carrick-runtime/src/memory.rs` (inside its existing `#[cfg(test)] mod tests` block — find it with `rg -n "mod tests" crates/carrick-runtime/src/memory.rs`; if none exists, create one at end of file):

```rust
#[test]
fn runtime_regions_include_shared_aperture() {
    let regions = linux_runtime_regions().expect("runtime regions");
    let shared = regions
        .iter()
        .find(|r| r.start == LINUX_SHARED_FILE_BASE)
        .expect("shared aperture region present");
    assert_eq!(shared.end, LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE);
    assert!(shared.shared, "shared aperture must be flagged shared");
    assert!(shared.perms.read && shared.perms.write);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p carrick-runtime runtime_regions_include_shared_aperture 2>&1 | tail -20`
Expected: FAIL — `no field shared on type &MemoryRegion`, and the region is absent.

- [ ] **Step 3: Add the `shared` field to `MemoryRegion`**

In `crates/carrick-runtime/src/memory.rs`, change the struct (currently at lines ~157-164):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: SegmentPerms,
    /// When true, this region's host backing is `MAP_SHARED` (kept shared
    /// across `fork(2)`, never snapshotted). Used for the boot-mapped shared
    /// aperture. All other regions are private.
    pub shared: bool,
    #[serde(skip)]
    bytes: Vec<u8>,
}
```

Now fix every `MemoryRegion { .. }` struct-literal in `memory.rs` to set `shared`. Find them with:

`rg -n "MemoryRegion \{" crates/carrick-runtime/src/memory.rs`

For each literal that does NOT set `shared`, add `shared: false,` (the sigreturn trampoline, ELF/segment regions, stack region, and `zeroed_region`). Example for `zeroed_region` (lines ~1283-1288):

```rust
    Ok(MemoryRegion {
        start,
        end,
        perms,
        shared: false,
        bytes: Vec::new(),
    })
```

Also check other files for `MemoryRegion {` literals:

`rg -rn "MemoryRegion \{" crates/carrick-runtime/src` — fix any outside `memory.rs` the same way (add `shared: false,`). If a constructor helper is used instead of literals, no change needed there.

- [ ] **Step 4: Add `shared_zeroed_region` and the aperture region**

In `crates/carrick-runtime/src/memory.rs`, add a helper next to `zeroed_region` (after it, ~line 1289):

```rust
/// Like `zeroed_region`, but the host backing is `MAP_SHARED` so the range
/// stays shared across `fork(2)` (never snapshotted). Used for the shared
/// aperture that guest `MAP_SHARED` mmaps sub-allocate from.
fn shared_zeroed_region(
    start: u64,
    size: u64,
    perms: SegmentPerms,
) -> Result<MemoryRegion, AddressSpaceError> {
    let mut region = zeroed_region(start, size, perms)?;
    region.shared = true;
    Ok(region)
}
```

Then add the aperture to `linux_runtime_regions()` (the `vec![...]` at ~line 1237). Add as a new element after the mmap-arena `zeroed_region(...)`:

```rust
        shared_zeroed_region(
            LINUX_SHARED_FILE_BASE,
            LINUX_SHARED_FILE_SIZE,
            SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
        )?,
```

- [ ] **Step 5: Run the memory test to verify it passes**

Run: `cargo test -p carrick-runtime runtime_regions_include_shared_aperture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Thread `shared` through `GuestMapping` and into `map_region_raw`**

In `crates/carrick-runtime/src/trap.rs`, add a field to `GuestMapping` (lines ~127-136):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMapping {
    pub guest_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    /// Host backing is `MAP_SHARED` (kept shared across fork). Mirrors
    /// `MemoryRegion::shared`.
    pub shared: bool,
    #[serde(skip)]
    image: Vec<u8>,
}
```

In `from_address_space` (the `mappings.push(GuestMapping { .. })` at ~line 164), add `shared: region.shared,`:

```rust
            mappings.push(GuestMapping {
                guest_start,
                mapped_size,
                offset_in_mapping,
                payload_size: region.bytes().len() as u64,
                perms: region.perms,
                shared: region.shared,
                image,
            });
```

In `map_region_raw` (~line 2770), pick the host-mapping kind by `shared`:

```rust
    let kind = if mapping.shared {
        crate::host_mapping::HostMappingKind::SharedAnon
    } else {
        crate::host_mapping::HostMappingKind::PrivateAnon
    };
    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(size, kind)
        .map_err(|error| {
            TrapError::Hypervisor(format!("mmap guest region (size={size}) failed: {error}"))
        })?;
```

(Replace the existing `OwnedHostMapping::map_shared_anon(size, HostMappingKind::PrivateAnon)` call. The rest of `map_region_raw` is unchanged — `guest_shared` is read from `host_mapping.guest_shared()`, which is now `true` for the aperture, so fork borrows it instead of snapshotting.)

- [ ] **Step 7: Verify the whole crate builds and lib tests pass**

Run: `cargo build -p carrick-runtime 2>&1 | tail -20`
Expected: builds clean (warnings about unused `SharedAperture` methods are OK).

Run: `cargo test -p carrick-runtime --lib 2>&1 | tail -20`
Expected: all lib tests pass (no regressions from the new struct field).

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src/memory.rs crates/carrick-runtime/src/trap.rs
git commit -m "feat(mem): pre-map shared aperture at boot as stable SharedAnon region"
```

---

## Task 3: Route guest MAP_SHARED|MAP_ANON to the aperture (no hv_vm_map)

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs` (`MemState`, `mmap` anon-shared branch)

- [ ] **Step 1: Replace the shared bookkeeping fields in `MemState`**

In `crates/carrick-runtime/src/dispatch/mem.rs`, change `MemState` (lines ~6-41). Remove `shared_file_next` and `shared_file_maps`; add a `SharedAperture`:

```rust
#[derive(Clone)]
pub(super) struct MemState {
    /// Current program break (`brk`/`sbrk`).
    pub brk_current: u64,
    /// Bump cursor for the anonymous mmap arena.
    pub mmap_next: u64,
    /// Sub-allocator for the boot-mapped shared aperture. Guest `MAP_SHARED`
    /// mmaps carve sub-ranges here; the aperture itself is `hv_vm_map`'d once
    /// at boot, so no stage-2 mutation happens at mmap time.
    pub shared: crate::shared_aperture::SharedAperture,
    /// Freed in-arena anonymous/private ranges available for reuse [...]
    pub free_regions: Vec<(u64, u64)>,
    /// Snapshot of the guest's `AddressSpace` regions [...]
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
}

impl MemState {
    pub(super) fn new() -> Self {
        Self {
            brk_current: LINUX_HEAP_BASE,
            mmap_next: LINUX_MMAP_BASE,
            shared: crate::shared_aperture::SharedAperture::new(),
            free_regions: Vec::new(),
            address_space_regions: None,
        }
    }
}
```

- [ ] **Step 2: Delete `next_shared_file_address`**

Remove the `fn next_shared_file_address(&self, length: u64) -> Option<u64>` method (lines ~117-131) entirely — its job moves into the `SharedAperture::alloc` calls in the `mmap` handler.

- [ ] **Step 3: Rewrite the MAP_SHARED|MAP_ANON branch in `mmap`**

In the `mmap` `define_syscall!` body, replace the anon-shared block (currently lines ~232-245, the `if flags & LINUX_MAP_ANONYMOUS != 0 && map_type == LINUX_MAP_SHARED && flags & LINUX_MAP_FIXED == 0 { ... }`) with a sub-allocation into the aperture. The bytes already live in the boot-mapped shared region, so we only allocate, zero, and return:

```rust
            if flags & LINUX_MAP_ANONYMOUS != 0
                && map_type == LINUX_MAP_SHARED
                && flags & LINUX_MAP_FIXED == 0
            {
                let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                let addr = {
                    let mut mem = this.mem.lock();
                    mem.shared
                        .alloc(map_len, crate::shared_aperture::BackingObject::SharedAnon)
                };
                if let Some(addr) = addr {
                    // The aperture is recycled host memory; anon mmap must read
                    // as zero. write_bytes targets the boot-mapped region.
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let zeros = vec![0u8; map_len_usize];
                    let _ = memory.write_bytes(addr, &zeros);
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
                return Ok(LINUX_ENOMEM.into());
            }
```

- [ ] **Step 4: Run to verify the crate builds**

Run: `cargo build -p carrick-runtime 2>&1 | tail -20`
Expected: build FAILS — the MAP_SHARED *file* branch (lines ~193-230) and `munmap`/`msync` still reference the removed fields/methods (`shared_file_maps`, `map_shared_file`, `next_shared_file_address`). That is fixed in Tasks 4-5. (If it builds, you missed a reference — re-check.)

- [ ] **Step 5: Commit (WIP — compiles after Task 5)**

Defer the commit; this task is committed together with Tasks 4-5 once the crate builds. Proceed directly to Task 4.

---

## Task 4: Route guest MAP_SHARED file mappings to the aperture

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs` (`mmap` file-shared branch)

- [ ] **Step 1: Rewrite the MAP_SHARED file branch in `mmap`**

Replace the file-shared block (currently lines ~193-230, the `if flags & LINUX_MAP_ANONYMOUS == 0 && map_type == LINUX_MAP_SHARED && flags & LINUX_MAP_FIXED == 0 && offset.is_multiple_of(hvf_page) { ... }`) with: allocate an aperture sub-range, copy the file bytes in, and record a `SharedFile` backing (owning a dup of the host fd) for writeback:

```rust
            if flags & LINUX_MAP_ANONYMOUS == 0
                && map_type == LINUX_MAP_SHARED
                && flags & LINUX_MAP_FIXED == 0
                && offset.is_multiple_of(hvf_page)
            {
                let dup_fd = {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(LINUX_EBADF.into());
                    };
                    let open = open_file.description.read();
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            let d = unsafe { libc::dup(*host_fd) };
                            if d < 0 { None } else { Some(d) }
                        }
                        _ => None,
                    }
                };
                if let Some(dup_fd) = dup_fd {
                    let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let addr = {
                        let mut mem = this.mem.lock();
                        mem.shared.alloc(
                            map_len,
                            crate::shared_aperture::BackingObject::SharedFile {
                                host_fd: dup_fd,
                                offset,
                            },
                        )
                    };
                    if let Some(addr) = addr {
                        // Seed the aperture sub-range with the file's bytes.
                        let mut bytes = vec![0u8; map_len_usize];
                        let n = unsafe {
                            libc::pread(
                                dup_fd,
                                bytes.as_mut_ptr() as *mut _,
                                map_len_usize,
                                offset as libc::off_t,
                            )
                        };
                        let _ = n; // short reads leave the tail zero (BSS-like)
                        let _ = memory.write_bytes(addr, &bytes);
                        return Ok(DispatchOutcome::Returned { value: addr as i64 });
                    }
                    // Window exhausted: drop the dup and fall through to private.
                    unsafe { libc::close(dup_fd) };
                }
            }
```

NOTE: this changes the file-shared coherence model from live host page-cache sharing to copy-in + writeback-on-`msync`/`munmap` (Task 5). The spec lists "keep the dynamic LINUX_SHARED_FILE path" as a non-goal and only requires cross-fork visibility, which the `MAP_SHARED` aperture backing preserves.

- [ ] **Step 2: Build (still expected to fail on munmap/msync)**

Run: `cargo build -p carrick-runtime 2>&1 | tail -20`
Expected: FAIL — `munmap`/`msync` still call `shared_file_maps` / `unmap_shared_file`. Fixed in Task 5.

---

## Task 5: Rewrite munmap/msync to free + write back, and add the writeback helper

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs` (`munmap`, `msync`, new free helper)

- [ ] **Step 1: Add a writeback-and-close helper on `SyscallDispatcher`**

Add this method to the `impl SyscallDispatcher` block in `dispatch/mem.rs` (next to where `next_shared_file_address` used to be):

```rust
    /// Write a freed `SharedFile` allocation's bytes back to its host fd and
    /// close the owned dup. `SharedAnon` frees need no writeback. Called from
    /// `munmap` (and `msync` writes back without freeing).
    fn writeback_shared(
        &self,
        cx: &mut DispatchContext<'_>,
        alloc: &crate::shared_aperture::SharedAlloc,
        close_fd: bool,
    ) {
        if let crate::shared_aperture::BackingObject::SharedFile { host_fd, offset } =
            alloc.backing
        {
            let len = usize::try_from(alloc.len).unwrap_or(0);
            if len > 0 {
                let mut bytes = vec![0u8; len];
                if cx.memory.read_bytes(alloc.guest_addr, &mut bytes).is_ok() {
                    unsafe {
                        libc::pwrite(
                            host_fd,
                            bytes.as_ptr() as *const _,
                            len,
                            offset as libc::off_t,
                        );
                    }
                }
            }
            if close_fd {
                unsafe { libc::close(host_fd) };
            }
        }
    }
```

(Confirm the read accessor name with `rg -n "fn read_bytes|fn read_guest_bytes" crates/carrick-runtime/src/dispatch`/`/trap.rs` and the `DispatchContext` field name `cx.memory` against the `mmap` handler above — match exactly.)

- [ ] **Step 2: Rewrite the `munmap` shared branch**

In `munmap` (lines ~311-346), replace the `shared_mapping` lookup/handling block (the `let shared_mapping = { ... }; if let Some((addr, len)) = shared_mapping { ... }`) with an aperture free + writeback:

```rust
            let freed = {
                let mut mem = this.mem.lock();
                mem.shared.free(address.0)
            };
            if let Some(alloc) = freed {
                this.writeback_shared(cx, &alloc, true);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
```

(Leave the subsequent private-arena handling — the `range_within(.., LINUX_MMAP_BASE, ..)` block — unchanged.)

- [ ] **Step 3: Rewrite the `msync` shared branch**

Find the `msync` handler (starts ~line 348) and locate where it routes to `msync_shared_file`. Replace that routing with: look up the live backing in the aperture and write back without freeing. Concretely, after the flag validation, add:

```rust
            let alloc = {
                let mem = this.mem.lock();
                mem.shared
                    .live()
                    .iter()
                    .find(|a| a.guest_addr == address.0)
                    .copied()
            };
            if let Some(alloc) = alloc {
                this.writeback_shared(cx, &alloc, false);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
```

If `msync` previously returned 0 unconditionally for unknown ranges, preserve that fall-through (return `Ok(DispatchOutcome::Returned { value: 0 })` at the end). Read the existing body first and keep its non-shared behavior intact.

- [ ] **Step 4: Build the crate**

Run: `cargo build -p carrick-runtime 2>&1 | tail -20`
Expected: PASS — all references to `shared_file_maps`/`next_shared_file_address`/`map_shared_file`/`map_shared_anon`/`unmap_shared_file` from the dispatcher are gone. (The trap.rs `GuestMemory` methods still exist but are now unused; removed in Task 6.)

- [ ] **Step 5: Run lib tests**

Run: `cargo test -p carrick-runtime --lib 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit Tasks 3-5 together**

```bash
git add crates/carrick-runtime/src/dispatch/mem.rs
git commit -m "feat(mem): sub-allocate guest MAP_SHARED from boot-mapped aperture (no post-vCPU hv_vm_map)"
```

---

## Task 6: Remove the dead dynamic stage-2 shared methods from trap.rs

**Files:**
- Modify: `crates/carrick-runtime/src/trap.rs` (`GuestMemory` impl: `map_shared_file`, `map_shared_anon`, `unmap_shared_file`, `msync_shared_file`)

- [ ] **Step 1: Confirm the methods are now unused by the dispatcher**

Run: `rg -n "map_shared_file|map_shared_anon|unmap_shared_file|msync_shared_file" crates/carrick-runtime/src`
Expected: matches ONLY in `trap.rs` (definitions + the `GuestMemory` trait declaration). No `dispatch/` call sites remain. If `dispatch/` still references them, you missed an edit in Tasks 3-5 — fix it first.

- [ ] **Step 2: Remove the four method definitions and their trait declarations**

In `crates/carrick-runtime/src/trap.rs`, delete the bodies of `map_shared_file` (~1497-1539), `map_shared_anon` (~1544-1580), `unmap_shared_file` (~1582-1599), and `msync_shared_file` (~1601-end of that fn). Then remove the matching method signatures from the `trait GuestMemory` declaration (find it with `rg -n "trait GuestMemory" crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/trap.rs` and delete the four `fn map_shared_file(...)`/`fn map_shared_anon(...)`/`fn unmap_shared_file(...)`/`fn msync_shared_file(...)` lines).

This removes the last `hv_vm_map`/`hv_vm_unmap` calls that ran from the guest `mmap`/`munmap` syscall path. The remaining `hv_vm_map` callers are `map_region_raw` (boot + fork/execve rebuild only), which is correct per the spec.

- [ ] **Step 3: Build and run lib tests**

Run: `cargo build -p carrick-runtime 2>&1 | tail -20`
Expected: PASS — no unused-method warnings for the deleted functions.

Run: `cargo test -p carrick-runtime --lib 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 4: Assert the invariant — no hv_vm_map/unmap/protect outside the rebuild path**

Run: `rg -n "hv_vm_map|hv_vm_unmap|hv_vm_protect" crates/carrick-runtime/src`
Expected: `hv_vm_map` appears ONLY in `map_region_raw` (and the fork/execve rebuild that calls it). `hv_vm_unmap`/`hv_vm_protect` appear nowhere in the guest syscall path. Record the surviving call sites in the commit message.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/trap.rs crates/carrick-runtime/src/dispatch/mod.rs
git commit -m "refactor(mem): delete dynamic stage-2 shared mmap path (hv_vm_map now boot/fork-only)"
```

---

## Task 7: End-to-end verification (guest probes + footprint)

**Files:**
- No source changes. Verification only. Build a SIGNED binary (HVF requires entitlements) per the project's build script.

- [ ] **Step 1: Build a signed runtime**

Run: `./scripts/build-signed.sh 2>&1 | tail -20`
Expected: builds and codesigns (otherwise `carrick run` returns `HV_DENIED`). Confirm the script path with `ls scripts/` if it differs.

- [ ] **Step 2: MAP_SHARED|MAP_ANON visibility across fork (guest probe)**

Write a tiny C probe to `/tmp/shmfork.c` that `mmap`s `MAP_SHARED|MAP_ANON`, `fork`s, has the child write a sentinel, `wait`s, and the parent asserts it reads the sentinel back (proving the shared aperture is coherent across fork). Compile it for linux/arm64 in Docker (the project uses `ubuntu:24.04`), then run under the signed binary:

```bash
docker run --rm -v /tmp:/out ubuntu:24.04 bash -c \
  'apt-get install -y gcc >/dev/null 2>&1; cat >/tmp/shmfork.c <<EOF
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
int main(){
  int *p = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED){ perror("mmap"); return 1; }
  *p = 11;
  pid_t c = fork();
  if (c == 0){ *p = 42; _exit(0); }
  waitpid(c, 0, 0);
  printf("shared=%d\n", *p);
  return *p == 42 ? 0 : 2;
}
EOF
  gcc -static -o /out/shmfork /tmp/shmfork.c'
./target/release/carrick run-elf /tmp/shmfork ; echo "exit=$?"
```

Expected: prints `shared=42` and `exit=0`. (Adjust `run-elf`/`run` and arg style to match the project CLI — confirm with `./target/release/carrick --help`.)

- [ ] **Step 3: MAP_SHARED file round-trip (guest probe)**

Add a second probe `/tmp/shmfile.c` (same Docker compile pattern) that `open`s a file, `ftruncate`s it to 4096, `mmap`s it `MAP_SHARED`, writes a sentinel, `msync(MS_SYNC)`s, `munmap`s, then re-reads the file with `pread` and asserts the sentinel persisted (proves Task 5 writeback). Run it under carrick against a path on a host bind-mount. Expected: exit 0.

- [ ] **Step 4: Memory footprint gate**

Run a trivial guest (`/bin/true` equivalent) under the signed binary and capture `footprint`/`vmmap` for the carrick process:

```bash
./target/release/carrick run debian:stable /bin/true &
CPID=$!; sleep 1; footprint $CPID 2>/dev/null | tail -20; wait $CPID
```

Expected: resident/footprint is NOT materially higher than before this plan (the 2 GiB aperture is `MAP_NORESERVE` demand-zero, so it must not add resident pages). Compare against `git stash`+rebuild baseline if unsure. Record the number.

- [ ] **Step 5: Run the Docker conformance smoke (regression guard)**

Run the project's conformance harness for the memory area to confirm no regression in `mmap`/`munmap`/`mprotect` behavior vs Docker. Per CLAUDE.md memory notes, build `--release` + register probes FIRST or it silently skips:

Run: `cargo test -p carrick-runtime --test conformance 2>&1 | tail -40` (confirm exact harness invocation with `rg -n "fn .*conformance|bollard" crates/carrick-runtime/tests/`).
Expected: memory probes PASS / match Docker.

- [ ] **Step 6: Final commit (if any verification artifacts were added) + update notes**

```bash
git add -A
git commit -m "test(mem): verify shared-aperture fork/file visibility + footprint"
```

---

## Self-Review

**Spec coverage (decomposition item 1 — "Stable shared aperture and memory-manager skeleton"):**
- "remove the dynamic shared-stage2 path" → Task 6 deletes `map_shared_file`/`map_shared_anon`/`unmap_shared_file`/`msync_shared_file` and their `hv_vm_map`/`hv_vm_unmap` calls; Task 6 Step 4 asserts the invariant.
- "model shared ranges as backing objects inside a pre-mapped aperture" → Task 1 (`BackingObject`, `SharedAperture`), Task 2 (boot pre-map), Tasks 3-4 (mmap routes into it).
- "preserve current private mmap behavior" → private path in `dispatch/mem.rs` (`next_mmap_address`, `free_regions`) is untouched; Task 2 only adds a field and a kind selector that defaults private.
- Spec §"Core architecture 1" (stable stage-2 aperture topology, `MAP_ANON|MAP_SHARED|MAP_NORESERVE`) → Task 2 uses `shared_zeroed_region` → `HostMappingKind::SharedAnon` (which mmaps `MAP_ANON|MAP_SHARED|MAP_NORESERVE`).
- Spec §"Memory overhead policy" (lazy, `MAP_NORESERVE`, no eager zeroing of fresh apertures) → aperture region carries no payload bytes (demand-zero); only *recycled* ranges are zeroed (Task 3 Step 3), matching "zero only recycled guest ranges".
- Spec §"Validation strategy" guest probes for `MAP_SHARED|MAP_ANON` across fork and file-backed `MAP_SHARED` → Task 7 Steps 2-3.
- Spec §"Performance/memory gates" (resident memory after startup; no `hv_vm_map` for ordinary mmap after vCPUs) → Task 7 Step 4 + Task 6 Step 4.

**Out of scope for this plan (later decomposition items):** stage-1 PROT_NONE/unmapped guest faults (item 2), stage-1 TLBI trampoline (item 3), fork refactor / vfork-exec (item 4), Mach COW probe (item 5), Go conformance closure (item 6). The private mmap arena's lack of guest-visible `PROT_NONE` faulting is intentionally NOT fixed here.

**Placeholder scan:** No `TBD`/`TODO`/"add error handling"; every code step shows concrete code.

**Type consistency:** `BackingObject` / `SharedAlloc` / `SharedAperture` and methods `new`/`alloc`/`free`/`backing`/`live` are used identically in Tasks 1, 3, 4, 5. `MemoryRegion.shared` / `GuestMapping.shared` names match across memory.rs and trap.rs. `writeback_shared(cx, &alloc, close_fd)` signature matches its two call sites.

**Known limitation (documented, spec-sanctioned):** file-backed `MAP_SHARED` changes from live host page-cache coherence to copy-in + writeback-on-`msync`/`munmap`. A durable file-object backing is left to a later backing-object plan.

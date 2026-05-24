# mmap arena reclaim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `munmap` reclaim arena address space so a long-running guest that churns mmap/munmap (thread stacks, transient buffers) reuses freed ranges instead of monotonically exhausting the 32 GiB bump arena.

**Architecture:** The anonymous mmap arena `[LINUX_MMAP_BASE, +LINUX_MMAP_SIZE)` is FLAT stage-2-mapped (one `hv_vm_map`, lazily demand-zeroed by HVF), so a freed range stays mapped — reclaim needs no HVF teardown, only (a) a coalesced free-list of freed in-arena ranges, (b) first-fit reuse in the bump allocator, and (c) zeroing a reused range before returning it (the anonymous-mmap zero contract; fresh bump ranges stay demand-zero, so we must NOT zero those or we defeat lazy backing).

**Tech Stack:** Rust, carrick memory dispatch (`src/dispatch/mem.rs`), `GuestMemory::write_bytes`, conformance probes, Docker arm64 oracle on `localhost:5050`.

**Pre-req:** `export CARRICK_INSECURE_REGISTRIES=localhost:5050`; build with `./scripts/build-signed.sh`. Kill stray guests before timing runs: `pkill -9 -f carrick`.

---

### Task 1: Failing probe — churn beyond arena size must keep succeeding and read back zero

**Files:**
- Create: `conformance-probes/src/bin/mmaprecl.rs`

- [ ] **Step 1: Write the probe**

```rust
//! mmap arena reclaim: allocate+touch+free a 64 MiB anonymous mapping many more
//! times than fit in the arena. Without reclaim the cumulative bump exhausts the
//! arena and a later mmap fails. Also verify a reused region reads back ZERO
//! (anonymous-mmap contract), not stale data. Deterministic booleans.

const CHUNK: usize = 64 * 1024 * 1024; // 64 MiB, like a Go heap arena
const ITERS: usize = 800; // 800 * 64 MiB = 50 GiB cumulative > 32 GiB arena

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut all_ok = true;
    let mut reuse_zero = true;
    for i in 0..ITERS {
        let p = libc::mmap(
            std::ptr::null_mut(),
            CHUNK,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            all_ok = false;
            break;
        }
        let bytes = p as *mut u8;
        // On a reused range, this must read 0 before we write (zeroed on reuse).
        if i > 0 && *bytes != 0 {
            reuse_zero = false;
        }
        *bytes = 0xAB; // dirty the first page so reuse must re-zero it
        *bytes.add(CHUNK - 1) = 0xCD; // touch the last page too
        libc::munmap(p, CHUNK);
    }
    println!("churn_ok={all_ok}");
    println!("reuse_zero={reuse_zero}");
}
```

- [ ] **Step 2: Build and run carrick vs Docker — expect carrick churn_ok=false**

```bash
./scripts/build-probes.sh
P=conformance-probes/target/aarch64-unknown-linux-musl/release/mmaprecl
docker run --rm --platform linux/arm64 -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" alpine /p/mmaprecl
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$PWD/$P"
```

Expected: Docker `churn_ok=true reuse_zero=true`; carrick `churn_ok=false` (arena exhausts after ~512 iters with no reclaim). Failing state confirmed.

---

### Task 2: Add the free-list to `MemState` with coalescing unit tests

**Files:**
- Modify: `src/dispatch/mem.rs` — `MemState` struct (near line 8–32) and `MemState::new`/`Default`

- [ ] **Step 1: Add the field**

In `MemState` add (next to `mmap_next`):

```rust
    /// Freed in-arena anonymous/private ranges available for reuse, kept sorted
    /// by start and coalesced. Reclaiming `munmap`'d space so a churning guest
    /// doesn't exhaust the bump arena. NOT used for MAP_FIXED or shared-file
    /// maps (those have their own lifecycles).
    pub free_regions: Vec<(u64, u64)>,
```

Initialise it to `Vec::new()` wherever `MemState` is constructed (the `mmap_next: LINUX_MMAP_BASE` site, near line 29).

- [ ] **Step 2: Write coalescing helper + unit tests (test first)**

Add a free function in `mem.rs`:

```rust
/// Insert `[addr, addr+len)` into `regions` (sorted by start), coalescing any
/// adjacent or overlapping ranges. `len` must be > 0.
fn free_regions_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let end = addr.saturating_add(len);
    let mut new_start = addr;
    let mut new_end = end;
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < new_start || s > new_end {
            // Disjoint. Emit in order.
            if !inserted && s > new_end {
                out.push((new_start, new_end - new_start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            // Overlap/adjacent — merge.
            new_start = new_start.min(s);
            new_end = new_end.max(e);
        }
    }
    if !inserted {
        out.push((new_start, new_end - new_start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}
```

And tests (in the existing `#[cfg(test)] mod tests` of `mem.rs`, or add one):

```rust
#[test]
fn free_regions_coalesce_adjacent() {
    let mut r = vec![];
    free_regions_insert(&mut r, 0x1000, 0x1000); // [0x1000,0x2000)
    free_regions_insert(&mut r, 0x3000, 0x1000); // [0x3000,0x4000)
    free_regions_insert(&mut r, 0x2000, 0x1000); // bridges → one [0x1000,0x4000)
    assert_eq!(r, vec![(0x1000, 0x3000)]);
}

#[test]
fn free_regions_coalesce_overlap_and_keep_disjoint() {
    let mut r = vec![];
    free_regions_insert(&mut r, 0x1000, 0x2000); // [0x1000,0x3000)
    free_regions_insert(&mut r, 0x2000, 0x2000); // overlaps → [0x1000,0x4000)
    free_regions_insert(&mut r, 0x9000, 0x1000); // disjoint
    assert_eq!(r, vec![(0x1000, 0x3000), (0x9000, 0x1000)]);
}
```

- [ ] **Step 3: Run the unit tests**

Run: `cargo test --release --lib free_regions -- --test-threads=1`
Expected: PASS (2 tests).

---

### Task 3: Reclaim on `munmap` (with top-of-bump fast path)

**Files:**
- Modify: `src/dispatch/mem.rs` — `munmap` (near line 340), the in-arena tail that currently returns `Ok(Returned{0})` without reclaiming

- [ ] **Step 1: Reclaim the freed in-arena range**

Replace the final in-arena branch of `munmap`:

```rust
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(LINUX_EINVAL.into());
        }
        Ok(DispatchOutcome::Returned { value: 0 })
```

with:

```rust
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(LINUX_EINVAL.into());
        }
        // Reclaim the range. Page-align length up (mmap rounds up); the arena is
        // flat stage-2-mapped so there is no host/HVF unmap to do — only mark the
        // VA reusable.
        if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
            let mut mem = self.mem.lock();
            // Fast path: freeing the top of the bump just lowers the cursor, then
            // absorb any free region now sitting at the new top.
            if address.checked_add(len) == Some(mem.mmap_next) {
                mem.mmap_next = address;
                while let Some(pos) = mem
                    .free_regions
                    .iter()
                    .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                {
                    let (s, _l) = mem.free_regions.remove(pos);
                    mem.mmap_next = s;
                }
            } else {
                free_regions_insert(&mut mem.free_regions, address, len);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
```

> Do NOT touch the earlier `shared_file_maps` branch of `munmap` — shared-file/shared-anon maps keep their existing `unmap_shared_file` teardown and are not added to `free_regions`.

- [ ] **Step 2: Build, confirm no regression yet** (reuse comes in Task 4)

```bash
./scripts/build-signed.sh
cargo test --release --lib -- --test-threads=1
```
Expected: lib tests PASS. (Probe still fails until Task 4 wires reuse.)

---

### Task 4: First-fit reuse + zero-on-reuse in the allocator

**Files:**
- Modify: `src/dispatch/mem.rs` — `next_mmap_address` (near line 281) and its caller in `mmap` (near line 194)

- [ ] **Step 1: Change `next_mmap_address` to report reuse**

Change its return type to `Option<(u64, bool)>` (address, reused). In the final bump section, before bumping, try the free-list:

```rust
        let mut mem = self.mem.lock();
        // Reuse a freed in-arena region first (first-fit) so a churning guest
        // doesn't grow the bump cursor forever.
        if let Some(pos) = mem.free_regions.iter().position(|&(_, l)| l >= length) {
            let (s, l) = mem.free_regions[pos];
            if l == length {
                mem.free_regions.remove(pos);
            } else {
                mem.free_regions[pos] = (s + length, l - length);
            }
            return Some((s, true)); // reused → caller must zero it
        }
        let address = align_up_u64(mem.mmap_next, LINUX_PAGE_SIZE)?;
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return None;
        }
        mem.mmap_next = address.checked_add(length)?;
        Some((address, false))
```

Update the two earlier `return Some(requested);` / `return Some(address);` sites in `next_mmap_address` (the MAP_FIXED path and the valid-hint path) to `return Some((requested, false));` (fresh placements are demand-zero, never need zeroing).

- [ ] **Step 2: Update the `mmap` caller to zero reused ranges**

In `mmap`, change:

```rust
        let address = match self.next_mmap_address(requested, length, prot, flags) {
            Some(address) => address,
            None => {
                return Ok(LINUX_ENOMEM.into());
            }
        };
```

to:

```rust
        let (address, reused) = match self.next_mmap_address(requested, length, prot, flags) {
            Some(pair) => pair,
            None => {
                return Ok(LINUX_ENOMEM.into());
            }
        };
        // A reused arena range carries the previous mapping's bytes; anonymous
        // mmap must hand back zeroed memory. Fresh bump ranges are demand-zero
        // (HVF), so zero ONLY on reuse — zeroing a fresh range would force it
        // resident and defeat the lazy 32 GiB arena.
        if reused {
            let zeros = vec![0u8; length_usize];
            let _ = memory.write_bytes(address, &zeros);
        }
```

> `length_usize` is already computed above in `mmap`. `memory` is bound. If `write_bytes` of a 64 MiB zero buffer is a measurable cost, a follow-up can add a `GuestMemory::zero_range(addr, len)` that memsets the backing directly; correctness first.

- [ ] **Step 3: Build and verify the probe passes**

```bash
./scripts/build-signed.sh
P=conformance-probes/target/aarch64-unknown-linux-musl/release/mmaprecl
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$PWD/$P"
```

Expected: `churn_ok=true` AND `reuse_zero=true`, matching Docker.

---

### Task 5: Regression-check and commit

- [ ] **Step 1: Full suite + Go fixture (clean system)**

```bash
export CARRICK_INSECURE_REGISTRIES=localhost:5050
pkill -9 -f carrick
cargo test --release --lib -- --test-threads=1
cargo test --release --test conformance
FIX="$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$FIX" | grep Graceful
pkill -9 -f carrick; ./target/release/carrick run-elf --raw --fs host "$FIX" -- -benchmark -c 10 -n 300 | grep -oE "req/sec"
```

Expected: lib PASS (incl. the 2 new free_regions tests + mmaprecl in conformance), Go fixture `Graceful shutdown…`, benchmark completes (~30k req/s). RSS should stay low (reclaim must not force the arena resident — spot-check with `ps -o rss`).

- [ ] **Step 2: LTP mm sweep — no over-reclaim regressions**

```bash
.claude/skills/ltp-conformance/scripts/ltp-check.sh mmap01 mmap02 munmap01 munmap02 mremap01 brk01
```

Expected: no NEW DIFFs vs the pre-change baseline (if unsure, stash and compare per the ltp-conformance skill).

- [ ] **Step 3: Commit**

```bash
git add src/dispatch/mem.rs conformance-probes/src/bin/mmaprecl.rs
git commit -m "$(cat <<'EOF'
feat(mm): reclaim munmap'd arena space (free-list + zero-on-reuse)

The anonymous mmap arena was a pure bump allocator; munmap of a private/anon
mapping never reclaimed VA, so a churning guest exhausted the 32 GiB arena over
time. Add a coalesced free-list: munmap reclaims (top-of-bump fast path lowers
the cursor; else insert+coalesce), and the allocator first-fit-reuses a freed
range, zeroing it on reuse (the arena is flat stage-2-mapped, so no HVF teardown;
fresh bump ranges stay demand-zero to preserve lazy backing). New mmaprecl probe
churns 50 GiB through the 32 GiB arena and reads reused ranges back as zero.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review notes
- Spec coverage: implements §2 of `2026-05-23-go-bringup-followups-design.md`.
- Type consistency: `free_regions: Vec<(u64,u64)>` used consistently in Tasks 2–4; `next_mmap_address` returns `Option<(u64,bool)>` and all three `Some(...)` sites + the caller are updated together (Task 4 Steps 1–2).
- Zero-on-reuse only (not on fresh bump) is the load-bearing correctness + lazy-backing invariant — called out in Task 4 Step 2.
- Out of scope (left to existing paths): MAP_FIXED placement, shared-file/shared-anon maps, `mremap` (does its own grow-in-place; not adding to free-list).

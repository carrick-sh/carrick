//! The host-OS seam: what a native-lane host crate must provide.
//!
//! First cut: JIT code-cache W^X management, the only host surface the
//! translation cache (`cache.rs`, next extraction slice) touches. The trap
//! transport, kick, and altstack contracts land with the host crates
//! themselves (M0.6/M0.7 of the seams design) so they are born against a
//! verified consumer rather than speculated here.
//!
//! Two real implementations with different W^X shapes:
//!
//!  * **Darwin** (`carrick-native-darwin`): one `MAP_JIT` RWX mapping;
//!    writability is a PER-THREAD hardware toggle
//!    (`pthread_jit_write_protect_np`), so the write pointer IS the exec
//!    pointer and `begin/end_thread_write` flip the calling thread's bit.
//!    `flush_icache` is mandatory (AArch64 non-coherent I-cache).
//!  * **FreeBSD** (`carrick-native-freebsd`): no MAP_JIT and `mprotect`
//!    flips would be process-wide (a writer would yank X from under
//!    concurrently-executing guest threads), so the region is DUAL-MAPPED —
//!    one RX mapping for execution, one RW alias for writers —
//!    `begin/end_thread_write` are no-ops, and `flush_icache` is a no-op on
//!    x86 (coherent I-cache; cross-modification ordering is the ARCH
//!    crate's problem at its patch sites).
//!
//! The cache addresses code by EXEC va and derives the write destination
//! via [`JitRegion::write_ptr_for`], so both shapes fall out of one calling
//! convention with no cfg at the call sites.

use std::ptr::NonNull;

/// A mapped JIT code cache. `exec_base` is where translated code runs;
/// `write_base` is where its bytes are written. Equal on Darwin (MAP_JIT);
/// distinct on a dual-mapped host.
#[derive(Debug)]
pub struct JitRegion {
    pub exec_base: NonNull<u8>,
    pub write_base: NonNull<u8>,
    pub capacity: usize,
}

impl JitRegion {
    /// Translate an exec-side pointer inside this region to its write-side
    /// alias. `None` if `exec_ptr` is outside the region (caller bug).
    pub fn write_ptr_for(&self, exec_ptr: *mut u8) -> Option<*mut u8> {
        let exec = exec_ptr as usize;
        let base = self.exec_base.as_ptr() as usize;
        let offset = exec.checked_sub(base)?;
        if offset >= self.capacity {
            return None;
        }
        // SAFETY: offset < capacity, so the add stays inside the write alias.
        Some(unsafe { self.write_base.as_ptr().add(offset) })
    }

    /// Slice out a `len`-byte sub-region starting at byte `offset` within
    /// this region: both aliases shifted by the same `offset`, `capacity`
    /// replaced by `len`. `None` if `offset..offset+len` does not fit inside
    /// `self` (caller bug -- bounds must come from the same allocator that
    /// produced `self.capacity`, e.g. a fixed-size per-thread slice carved
    /// out of one big process-wide reservation).
    ///
    /// The returned `JitRegion` aliases the SAME memory as `self` -- it does
    /// not map or own anything new. Combine with
    /// [`crate::cache::TranslationCache::from_region`] to give each slice its
    /// own typed bump-allocator without asking the host to map a fresh
    /// region per slice.
    pub fn sub_region(&self, offset: usize, len: usize) -> Option<JitRegion> {
        let end = offset.checked_add(len)?;
        if end > self.capacity {
            return None;
        }
        // SAFETY: `offset + len <= self.capacity`, so both shifted bases
        // stay within the bounds of the original mapping (one-past-the-end
        // is the worst case, when `len == 0`).
        let exec_base = unsafe { self.exec_base.as_ptr().add(offset) };
        let write_base = unsafe { self.write_base.as_ptr().add(offset) };
        Some(JitRegion {
            exec_base: NonNull::new(exec_base)?,
            write_base: NonNull::new(write_base)?,
            capacity: len,
        })
    }
}

/// Outcome of [`NativeHostJit::remap_for_fork_child`]: what the fork CHILD
/// must do with its inherited [`JitRegion`] before any guest thread runs.
///
/// * `Inherited` — the inherited mapping is safe for the child to keep
///   executing from as-is (e.g. Darwin's `MAP_JIT` is `MAP_PRIVATE`, so the
///   child already holds its own copy-on-write pages; nothing to replace).
/// * `Fresh(region)` — the inherited mapping is UNSAFE to share (e.g. a
///   `MAP_SHARED` dual map: a child that appended translations into it would
///   clobber the parent's live code through the same physical pages) and the
///   child must adopt `region` instead of the one it inherited.
#[derive(Debug)]
pub enum ForkChildJit {
    Inherited,
    Fresh(JitRegion),
}

/// Host W^X JIT plumbing for the translation cache. Implementations are
/// stateless (all state lives in the [`JitRegion`]); every method is safe to
/// call from any guest thread — hence the `Send + Sync` supertraits, which
/// let the cache hold a `&'static dyn NativeHostJit` across threads. This is
/// the translation SLOW path — trait dispatch cost is irrelevant; translated
/// code never calls back through it.
pub trait NativeHostJit: Send + Sync {
    /// Fail-closed capability probe (Darwin: per-thread JIT write protection
    /// must be supported; others: whatever the mapping strategy requires).
    /// Called once before the first `map_code_cache`.
    fn supported(&self) -> Result<(), &'static str>;

    /// Map a `capacity`-byte code cache (already page-rounded by the caller).
    fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion>;

    /// Unmap a region created by [`Self::map_code_cache`].
    ///
    /// # Safety
    /// No thread may execute from or hold pointers into the region afterward.
    unsafe fn unmap(&self, region: &JitRegion);

    /// Make the cache writable for the CALLING thread (Darwin: flip the
    /// per-thread W^X bit; dual-mapped hosts: no-op — writes go through the
    /// write alias, which is always writable).
    fn begin_thread_write(&self);

    /// Revert [`Self::begin_thread_write`] for the calling thread.
    ///
    /// This is also the sole fork-child protection repair for every host:
    /// [`crate::cache::TranslationCache::after_fork_child`] calls straight
    /// through to this method, not through a separate per-host fork hook.
    /// A `NativeHostJit::after_fork_child` method used to exist alongside it
    /// (documented as the "IN-PLACE repair hook" for lanes whose region
    /// survives fork, e.g. Darwin re-asserting the MAP_JIT write-protect
    /// bit) but the Phase-1 seams audit found no production call site ever
    /// invoked it — Darwin's own impl just called `end_thread_write` again,
    /// redundantly — so it was removed rather than kept as dead API surface.
    fn end_thread_write(&self);

    /// Make `len` freshly written bytes at `exec_ptr` (EXEC va) visible to
    /// instruction fetch (AArch64: icache invalidate; x86: no-op).
    fn flush_icache(&self, exec_ptr: *const u8, len: usize);

    /// Fork-repair contract. Called in the CHILD immediately after
    /// `fork(2)` by lanes whose fork path routes region repair through this seam
    /// (currently: FreeBSD's `fork_child_rebuild`); Darwin's CoW lane does not
    /// consult it. `prior` is the region the child inherited (the parent's,
    /// byte-for-byte, at fork). `Inherited` means the child may keep executing
    /// from it as-is; `Fresh(region)` means the inherited region is unsafe to
    /// share and the child must adopt `region` — of the same capacity as
    /// `prior`, mapped fresh for this child — instead. No default impl: every
    /// host answers explicitly (see [`ForkChildJit`] for the per-shape rationale).
    fn remap_for_fork_child(&self, prior: &JitRegion) -> std::io::Result<ForkChildJit>;
}

#[cfg(test)]
mod sub_region_tests {
    //! Pure pointer-arithmetic proof for `JitRegion::sub_region`, independent
    //! of any real mapping (the pointers below are never dereferenced --
    //! `cache.rs`'s `from_region_tests` cover the mapped, end-to-end case).

    use super::JitRegion;
    use std::ptr::NonNull;

    fn fake_region(exec: usize, write: usize, capacity: usize) -> JitRegion {
        JitRegion {
            exec_base: NonNull::new(exec as *mut u8).expect("nonzero exec base"),
            write_base: NonNull::new(write as *mut u8).expect("nonzero write base"),
            capacity,
        }
    }

    #[test]
    fn sub_region_shifts_both_aliases_by_the_same_offset() {
        let region = fake_region(0x1000, 0x9000, 0x10000);
        let slice = region.sub_region(0x100, 0x200).expect("in-bounds slice");
        assert_eq!(slice.exec_base.as_ptr() as usize, 0x1100);
        assert_eq!(slice.write_base.as_ptr() as usize, 0x9100);
        assert_eq!(slice.capacity, 0x200);
    }

    #[test]
    fn sub_region_accepts_a_range_that_exactly_fills_the_remainder() {
        let region = fake_region(0x1000, 0x9000, 0x10000);
        let slice = region.sub_region(0xff00, 0x100).expect("exact-fit slice");
        assert_eq!(slice.exec_base.as_ptr() as usize, 0x1000 + 0xff00);
        assert_eq!(slice.capacity, 0x100);

        // A zero-length slice at the very end (offset == capacity) is a
        // degenerate but valid "no bytes" view, not an error.
        let empty_tail = region
            .sub_region(0x10000, 0)
            .expect("zero-length tail slice");
        assert_eq!(empty_tail.capacity, 0);
    }

    #[test]
    fn sub_region_rejects_ranges_that_overrun_the_parent() {
        let region = fake_region(0x1000, 0x9000, 0x10000);
        assert!(region.sub_region(0x10000, 1).is_none());
        assert!(region.sub_region(1, 0x10000).is_none());
        assert!(region.sub_region(usize::MAX, 1).is_none());
        assert!(region.sub_region(usize::MAX, usize::MAX).is_none());
    }
}

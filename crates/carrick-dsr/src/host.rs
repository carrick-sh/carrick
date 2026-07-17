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
    fn end_thread_write(&self);

    /// Make `len` freshly written bytes at `exec_ptr` (EXEC va) visible to
    /// instruction fetch (AArch64: icache invalidate; x86: no-op).
    fn flush_icache(&self, exec_ptr: *const u8, len: usize);

    /// Repair per-thread protection state inherited by the sole surviving
    /// thread after `fork(2)` (Darwin: re-assert the write-protect bit; the
    /// child reuses the inherited mapping and must NOT re-map).
    fn after_fork_child(&self);
}

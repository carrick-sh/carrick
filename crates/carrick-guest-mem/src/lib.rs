//! Foundational guest-memory hub types shared across carrick.
//!
//! These three types were the cause of the `memory ↔ dispatch` dependency cycle
//! that forced `carrick-runtime` to stay monolithic: `GuestMemory`/`MemoryError`
//! were defined in `dispatch/mod.rs` yet `memory.rs` depended on them, while
//! `dispatch` depends back on `memory`. Lifting them into this leaf crate breaks
//! that cycle (docs/build-decomposition-design.md §3.A-A2) so `memory`/`dispatch`
//! can later become independent crates. They are self-contained: only primitives,
//! `serde::Serialize`, and `thiserror::Error`.

use serde::Serialize;
use thiserror::Error;

/// The Linux AArch64 syscall argument registers carrick reads at an `svc` trap
/// (`x0`–`x5` args, `x8` syscall number).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Aarch64SyscallFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x8: u64,
}

/// The guest physical/virtual memory a syscall handler reads and writes. The
/// backend may be the real HVF-backed address space or the in-memory
/// `LinearMemory` used by unit tests.
pub trait GuestMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;

    /// Zero `[address, address+len)` in the PHYSICAL backing, bypassing the
    /// guest-visible protection (`set_no_access` / a non-writable mapping).
    /// Used to scrub a reused anon region whose stale content must never reach
    /// the guest: a region just reclaimed from `munmap` (stage-1-invalidated) or
    /// mapped `PROT_NONE` has no write permission, so the permission-checked
    /// `write_bytes` deliberately faults and CANNOT scrub it — leaving the prior
    /// mapping's bytes to surface after a later `mprotect`. Default: the checked
    /// `write_bytes` (the in-memory backend models no protection, so it always
    /// writes); the HVF backend overrides this to write the host backing raw.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.write_bytes(address, &vec![0u8; len])
    }

    /// Mark a guest range `PROT_NONE` (`no_access=true`) or accessible again
    /// (`false`). carrick backs the whole mmap arena with one accessible host
    /// region, so a `PROT_NONE` mmap is otherwise readable/writable on the
    /// syscall path — a guest passing such a buffer to a syscall must instead
    /// see EFAULT (LTP's `tst_get_bad_addr` mmaps a `PROT_NONE` page as a
    /// guaranteed-faulting address). The backend records these ranges and makes
    /// `read_bytes`/`write_bytes` fault on overlap, so every handler that maps a
    /// memory error to EFAULT gets it for free. Default: no-op (the in-memory
    /// backend and unit tests don't model protections).
    fn set_no_access(&mut self, _address: u64, _len: usize, _no_access: bool) {}

    /// Change the guest-VISIBLE protection of `[address, address+len)` by
    /// editing the EL1 stage-1 page descriptors and flushing the stage-1 TLB,
    /// so a guest access that violates `prot` faults during EL0 execution
    /// (delivered as SIGSEGV) — not only on host-side `read_bytes` checks.
    /// `prot` is the Linux PROT mask (0 = PROT_NONE). Default: no-op (the
    /// in-memory backend has no stage-1 tables; it relies on `set_no_access`).
    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Make `[address, address+len)` unmapped in stage-1 (faults until reused),
    /// for guest `munmap`. Default: no-op.
    fn unmap_range(&mut self, _address: u64, _len: usize) -> Result<(), MemoryError> {
        Ok(())
    }

    /// `munmap` of a high-VA alias mapping: like `unmap_range`, but the HVF
    /// backend ALSO reclaims the now-empty per-alias stage-1 sub-table back to
    /// the spare pool (a high-VA alias is torn down completely, vs the low-VA
    /// arena whose pages are reused in place). Default: same as `unmap_range`
    /// (the in-memory backend has no sub-table pool to leak).
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.unmap_range(address, len)
    }

    /// Repoint guest VA `[va, va+len)` to a slot in the boot-mapped PRIVATE
    /// overlay aperture (`overlay_ipa`, identity IPA==VA), seeding the slot with
    /// `content` first. Used for `MAP_FIXED|MAP_PRIVATE` over a shared-aperture
    /// VA: after this, the guest's stores to `va` hit the per-process overlay
    /// page, not the shared backing. The repoint is a stage-1 page-table edit +
    /// TLB flush only — the overlay window was `hv_vm_map`'d at boot, so no
    /// post-vCPU stage-2 mutation happens. Default: no-op (the in-memory backend
    /// and unit tests have no stage-1 tables and don't model the overlay).
    fn repoint_private(
        &mut self,
        _va: u64,
        _overlay_ipa: u64,
        _len: usize,
        _content: &[u8],
    ) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Host virtual address of the byte at `guest_addr`, but ONLY when it lies
    /// in a host-`MAP_SHARED` guest region — i.e. the boot-mapped shared
    /// aperture that backs guest `MAP_SHARED` mmaps. That backing is shared
    /// across `fork(2)`, so the same physical page is visible to every carrick
    /// process — which makes it a valid target for a cross-process futex via
    /// the public `os_sync_wait_on_address` API with
    /// `OS_SYNC_WAIT_ON_ADDRESS_SHARED` (keyed on the physical page; see
    /// `crate::ulock`). Returns `None` for private/anon guest memory (those
    /// futexes stay in-process via the parking-lot table). Default: `None`.
    fn shared_futex_host_addr(&self, _guest_addr: u64) -> Option<usize> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryError {
    #[error("guest memory read is out of bounds at 0x{address:x} for {length} bytes")]
    OutOfBounds { address: u64, length: usize },
    /// The backend can't service a real shared file-backed mapping (e.g.
    /// the non-HVF AddressSpace/LinearMemory used in unit tests). Callers
    /// fall back to the private-snapshot mmap path.
    #[error("operation unsupported by this guest-memory backend")]
    Unsupported,
    /// A host-side mapping operation (mmap/hv_vm_map/...) failed.
    #[error("host mapping operation failed: {0}")]
    HostMap(String),
}

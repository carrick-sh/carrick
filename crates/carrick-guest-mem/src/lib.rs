//! Foundational guest-memory hub types shared across carrick.
//!
//! THEORY OF OPERATION
//!
//! Every carrick syscall handler reads its arguments from, and writes its
//! results back into, *guest* memory — the AArch64 Linux process's address
//! space — and it does so through one narrow trait, [`GuestMemory`]. This crate
//! owns that trait, the syscall-argument register frame ([`Aarch64SyscallFrame`])
//! the trap engine hands the dispatcher, and the [`MemoryError`] those accesses
//! fail with. Nothing else. It is the seam between "how the bytes are stored"
//! and "what the syscall does with them".
//!
//! The single most important design fact here is that [`GuestMemory`] is
//! polymorphic over TWO backends that look nothing alike:
//!
//!  - the real HVF-backed address space, where guest memory is a host `mmap`
//!    region published into the VM via `hv_vm_map`, protections live in EL1
//!    stage-1 page-table descriptors, and a bad guest pointer must surface as a
//!    real fault; and
//!  - an in-memory `LinearMemory` used by unit tests, which is a flat byte
//!    buffer modelling NO protections, NO page tables, and NO host mapping.
//!
//! Keeping both behind one trait is what lets the ~hundreds of syscall handlers
//! be exercised by fast, hermetic unit tests (no hypervisor, no guest binary)
//! while running unmodified against the live VM. The trait is therefore written
//! so the *default* method bodies are the correct behaviour for the modelless
//! test backend, and the HVF backend OVERRIDES the methods that need real
//! page-table or host-mapping machinery. A handler that only ever calls
//! `read_bytes`/`write_bytes` is automatically testable; a handler that needs
//! protection or unmap semantics gets a faithful default (usually a no-op that
//! the test backend can't observe) and the real thing under HVF.
//!
//! INVARIANTS THE TRAIT ENCODES (read the per-method docs for the full story):
//!
//!  - `read_bytes`/`write_bytes` are the PERMISSION-CHECKED path: they honour
//!    the guest-visible protection so that a guest handing a syscall a
//!    `PROT_NONE` buffer gets EFAULT, exactly as Linux would. `zero_backing` is
//!    the deliberate BYPASS — it scrubs the physical backing of a region the
//!    guest can't currently write (a `munmap`'d or `PROT_NONE` page) so stale
//!    bytes from a prior mapping never resurface after a later `mprotect`.
//!  - `set_no_access` vs `protect_range`/`unmap_range` is a two-level model: the
//!    former makes only the HOST-SIDE syscall-read path fault (cheap, no page
//!    tables); the latter edits the real stage-1 descriptors so the GUEST faults
//!    mid-EL0-execution. The test backend, having no tables, implements only the
//!    former and no-ops the latter.
//!  - `shared_futex_host_addr` is the hook that turns a guest `MAP_SHARED` futex
//!    into a cross-PROCESS rendezvous: it yields a stable host VA only for the
//!    shared aperture (the same physical page in every forked carrick process),
//!    which `crate::ulock` keys an `os_sync_wait_on_address` SHARED wait on.
//!    Private/anon memory returns `None` and stays in the in-process parking-lot
//!    table. This is the one trait method whose return value crosses the
//!    process boundary.
//!
//! WHY THIS IS ITS OWN LEAF CRATE
//!
//! These three types caused the `memory ↔ dispatch` dependency cycle that forced
//! `carrick-runtime` to stay one monolithic ~41k-line crate: `GuestMemory` and
//! `MemoryError` were defined in `dispatch/mod.rs`, yet `memory.rs` depended on
//! them, while `dispatch` depends back on `memory`. Lifting the hub types here
//! cuts the cycle (docs/build-decomposition-design.md §3.A-A2) so `memory` and
//! `dispatch` can later become independent crates and editing a syscall handler
//! no longer recompiles the address-space code (and vice versa). The crate is
//! kept deliberately tiny and dependency-light — only primitives,
//! `serde::Serialize`, and `thiserror::Error` — precisely so it sits at the
//! bottom of the build graph and almost never has to be rebuilt.

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

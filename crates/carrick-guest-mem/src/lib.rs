//! Foundational guest-memory hub types shared across carrick.
//!
//! THEORY OF OPERATION
//!
//! Every carrick syscall handler reads its arguments from, and writes its
//! results back into, *guest* memory — the Linux process's address space — and
//! it does so through one narrow trait, [`GuestMemory`]. This crate
//! owns that trait, the syscall-argument register frame ([`Aarch64SyscallFrame`])
//! the trap engine hands the dispatcher, and the [`MemoryError`] those accesses
//! fail with. Nothing else. It is the seam between "how the bytes are stored"
//! and "what the syscall does with them".
//!
//! The single most important design fact here is that [`GuestMemory`] is
//! polymorphic over TWO backends that look nothing alike:
//!
//!  - the real backend-backed address space, where guest memory is host-backed
//!    memory published to the active VMM, protections live in backend page-table
//!    or memory-slot state, and a bad guest pointer must surface as a real
//!    fault; and
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
//! cuts the cycle (docs/archive/build-decomposition-design.md §3.A-A2) so `memory` and
//! `dispatch` can later become independent crates and editing a syscall handler
//! no longer recompiles the address-space code (and vice versa). The crate is
//! kept deliberately tiny and dependency-light — only primitives,
//! `serde::Serialize`, and `thiserror::Error` — precisely so it sits at the
//! bottom of the build graph and almost never has to be rebuilt.

use serde::Serialize;
use thiserror::Error;

/// Neutral guest-memory region lookup + the combined PROT_NONE/region access
/// gate ([`region::find_region_for_gpa`], [`region::safe_guest_access`]) — the
/// recurrence guard that keeps a backend from wiring up the region lookup while
/// forgetting the PROT_NONE gate (or vice versa). See the module docs.
pub mod region;

/// Process-wide PROT_NONE range bookkeeping — the single shared host-side EFAULT
/// gate the [`GuestMemory`] default `read_bytes`/`write_bytes` run.
pub mod protections;

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

/// The Linux x86_64 syscall argument registers carrick reads at a SYSCALL trap.
/// Per syscall(2) (man7.org), "Architecture calling conventions": number in
/// rax; args rdi, rsi, rdx, r10, r8, r9; return in rax; rcx/r11 are the
/// hardware SYSCALL clobbers (return RIP/RFLAGS) and never carry arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct X8664SyscallFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

/// The guest physical/virtual memory a syscall handler reads and writes. The
/// backend may be the real HVF-backed address space or the in-memory
/// `LinearMemory` used by unit tests.
pub trait GuestMemory {
    /// The process-wide PROT_NONE set this backend enforces on the syscall path,
    /// or `None` for a modelless backend (the in-memory test models). When
    /// `Some`, the default [`read_bytes`](Self::read_bytes) /
    /// [`write_bytes`](Self::write_bytes) fault any buffer overlapping a recorded
    /// range with `EFAULT` BEFORE touching backing — the single shared host-side
    /// gate every real backend (HVF, KVM, and every x86 VMM) inherits for free.
    /// A new backend gets the gate just by surfacing its protections here.
    fn protections(&self) -> Option<&protections::MemoryProtections> {
        None
    }

    /// PERMISSION-CHECKED guest read. DEFAULT: run the PROT_NONE gate
    /// (`protections()`), then delegate to [`read_bytes_raw`](Self::read_bytes_raw).
    /// Backends must NOT override this — implement `read_bytes_raw` instead so the
    /// one shared gate always runs.
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if length > 0
            && self
                .protections()
                .is_some_and(|p| p.range_no_access(address, length))
        {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.read_bytes_raw(address, length)
    }

    /// PERMISSION-CHECKED guest write. DEFAULT: PROT_NONE gate then
    /// [`write_bytes_raw`](Self::write_bytes_raw). (The per-mapping WRITE
    /// permission gate is backend-local; HVF enforces it inside `write_bytes_raw`.)
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !bytes.is_empty()
            && self
                .protections()
                .is_some_and(|p| p.range_no_access(address, bytes.len()))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    /// Backing-only read: copy `length` bytes at `address` from the physical
    /// backing, WITHOUT the PROT_NONE gate (the default `read_bytes` already ran
    /// it). Real backends implement the host-pointer copy here; the test models
    /// copy out of their flat buffer. May still fault OUT-OF-BOUNDS / NULL-guard /
    /// reserved-page semantics — those are backing facts, not PROT_NONE.
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;

    /// Backing-only write, no PROT_NONE gate. HVF additionally enforces the
    /// guest-visible WRITE permission here (a read-only mapping → EFAULT).
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;

    /// Read exactly `dst.len()` bytes at `address` into `dst`. DEFAULT: run the
    /// PROT_NONE gate once, then delegate to [`read_into_raw`](Self::read_into_raw).
    /// Do not override — override `read_into_raw` for a no-alloc fast path.
    fn read_into(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        if !dst.is_empty()
            && self
                .protections()
                .is_some_and(|p| p.range_no_access(address, dst.len()))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: dst.len(),
            });
        }
        self.read_into_raw(address, dst)
    }

    /// Backing-only fixed-size read into `dst`, no PROT_NONE gate (the default
    /// `read_into` ran it). Default: `read_bytes_raw` + copy (the in-memory test
    /// backend has nothing to gain). The HVF backend overrides this to
    /// `volatile`-copy straight into `dst`, removing the per-call `Vec` on the
    /// hot fixed-size-read path (`read_u32`/`read_u64`/struct-header reads).
    fn read_into_raw(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        let bytes = self.read_bytes_raw(address, dst.len())?;
        dst.copy_from_slice(&bytes);
        Ok(())
    }

    /// Write `bytes` at `address` WITHOUT enforcing the guest-visible write
    /// permission (`guest_writable`). For carrick-INTERNAL frames the guest must
    /// receive even into a guest-read-only mapping (vdso vvar, the signal frame,
    /// bootstrap): the host backing page is writable; only the guest-visible
    /// permission is bypassed. Default: the permission-checked `write_bytes` (the
    /// in-memory backend and the KVM backend model no such distinction). The HVF
    /// backend overrides this to its unchecked writer.
    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.write_bytes_raw(address, bytes)
    }

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
        // Raw write: scrubbing a reused PROT_NONE / unmapped region must bypass
        // the gate (the checked path would EFAULT and leave stale bytes).
        self.write_bytes_raw(address, &vec![0u8; len])
    }

    /// Whether every byte of `[address, address+length)` is currently guest-WRITABLE
    /// (used by signal delivery to detect an unwritable SA_ONSTACK alt-stack →
    /// Linux force_sigsegv). Default: `true` (the in-memory backend models no
    /// protection). The HVF backend overrides this.
    fn guest_range_is_writable(&self, _address: u64, _length: usize) -> bool {
        true
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

    /// Host pointer for a CONTIGUOUS guest range usable for zero-copy host I/O
    /// (send straight out of / recv straight into guest memory), valid IFF the
    /// whole `[address, address+len)` lives in one mapped region so the host
    /// backing is contiguous. Returns `None` when zero-copy is not applicable
    /// (multi-region, unmapped, or — for writes — not guest-writable); the
    /// caller MUST then fall back to `read_bytes`/`write_bytes`. The pointer is
    /// valid only for the current syscall dispatch (the issuing vCPU is in its
    /// own trap handler and the op runs before any lock-releasing wait); an
    /// EAGAIN-parked syscall re-dispatches and re-resolves. Default: `None`
    /// (the in-memory backend has no contiguous host backing to expose).
    ///
    /// SAFETY (using the pointer): touch at most `len` bytes. A concurrent guest
    /// write to those bytes is a guest bug (matches Linux) and tolerated; the
    /// mapping itself stays put for the dispatch.
    fn host_ptr_for_read(&self, _address: u64, _len: usize) -> Option<*const u8> {
        None
    }
    fn host_ptr_for_write(&mut self, _address: u64, _len: usize) -> Option<*mut u8> {
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

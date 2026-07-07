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
//!  - `shared_futex_location` is the hook that turns a guest `MAP_SHARED` futex
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

// ─── Address-domain newtypes (the mapping/translation seam) ─────────────────
//
// The three address domains a mapping call juggles — guest VIRTUAL, guest
// PHYSICAL, host VIRTUAL — were all bare `u64`s sitting ADJACENT in the same
// signatures (`map_aliased(va, gpa, len)`, `map_host_alias(va, ipa, len)`), so
// transposing two of them compiles clean and, because both sides are
// page-aligned, sails past every alignment guard. These wrappers make that
// swap a type error at the seam; page-table internals unwrap with `raw()`.

/// A GUEST VIRTUAL address (what guest code dereferences; stage-1 translated).
///
/// Distinct from [`Gpa`] and [`HostVa`] because the three were adjacent bare
/// `u64`s in mapping signatures like `map_aliased(va, gpa, len)` — a va↔gpa
/// transposition is page-aligned on both sides, so alignment guards cannot
/// catch it; only the type can.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize)]
pub struct GuestVa(pub u64);

impl GuestVa {
    /// The raw guest-virtual address value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A GUEST PHYSICAL address (stage-2 / memslot space; aarch64 calls it IPA).
///
/// Distinct from [`GuestVa`] and [`HostVa`] because the three were adjacent
/// bare `u64`s in mapping signatures like `map_aliased(va, gpa, len)` — a
/// va↔gpa transposition is page-aligned on both sides, so alignment guards
/// cannot catch it; only the type can.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize)]
pub struct Gpa(pub u64);

impl Gpa {
    /// The raw guest-physical (IPA) address value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A HOST VIRTUAL address (a real pointer in carrick's own address space).
///
/// Distinct from [`GuestVa`] and [`Gpa`] because the translation chain
/// (guest VA → GPA → host pointer, e.g. `shared_futex_location`) carried all
/// three as adjacent bare integers — a swap is page-aligned and alignment
/// guards cannot catch it; only the type can. Deref via `raw()` at the
/// pointer boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize)]
pub struct HostVa(pub usize);

impl HostVa {
    /// The raw host address value (cast to a pointer at the deref site).
    #[inline]
    pub const fn raw(self) -> usize {
        self.0
    }
}

/// Fork-coherent host location for a guest `MAP_SHARED` futex word.
///
/// [`SharedFutexLocation::Direct`] means the host address is the actual guest
/// futex word and can be waited/woken directly. [`SharedFutexLocation::Mirror`]
/// means the backend uses a separate fork-shared mirror word and supplies the
/// explicit waiter-counter address, if the host futex primitive needs one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum SharedFutexLocation {
    Direct {
        word: HostVa,
        waiter_key: usize,
    },
    Mirror {
        word: HostVa,
        waiter_count: HostVa,
        waiter_key: usize,
    },
}

impl SharedFutexLocation {
    #[inline]
    pub const fn wait_addr(self) -> HostVa {
        match self {
            SharedFutexLocation::Direct { word, .. }
            | SharedFutexLocation::Mirror {
                word,
                waiter_count: _,
                waiter_key: _,
            } => word,
        }
    }

    #[inline]
    pub const fn waiter_key(self) -> usize {
        match self {
            SharedFutexLocation::Direct { waiter_key, .. }
            | SharedFutexLocation::Mirror { waiter_key, .. } => waiter_key,
        }
    }

    #[inline]
    pub const fn waiter_count_addr(self) -> Option<HostVa> {
        match self {
            SharedFutexLocation::Direct { .. } => None,
            SharedFutexLocation::Mirror {
                word: _,
                waiter_count,
                waiter_key: _,
            } => Some(waiter_count),
        }
    }

    #[inline]
    pub const fn is_mirror(self) -> bool {
        matches!(self, SharedFutexLocation::Mirror { .. })
    }
}

/// One page of zeros, streamed by the chunked guest-zeroing helpers. Zeroing a
/// guest range must never allocate a `len`-sized temporary — a guest can ask
/// `select`/`munmap`/`mremap` to clear a large range — so the helpers write
/// slices of this single static block instead of `vec![0u8; len]`.
const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];

/// Zero `[address, address+len)` by streaming `ZERO_CHUNK` through `write`,
/// never allocating a `len`-sized buffer. `write` is the caller's backing
/// writer: the permission-CHECKED [`GuestMemory::write_bytes`] for a guest-owned
/// buffer, or an unchecked raw / `write_gpa` writer for a backing scrub. Stops
/// and returns the error on the first chunk `write` rejects, so a single
/// faulting chunk behaves like the one `write_bytes` it replaces (guest ranges
/// never reach the top of the address space, so the chunk-stride add cannot wrap
/// in practice; `saturating_add` keeps it panic-free under release overflow checks).
pub fn zero_range_chunked<F>(address: u64, len: usize, mut write: F) -> Result<(), MemoryError>
where
    F: FnMut(u64, &[u8]) -> Result<(), MemoryError>,
{
    let mut off = 0usize;
    while off < len {
        let chunk = (len - off).min(ZERO_CHUNK.len());
        write(address.saturating_add(off as u64), &ZERO_CHUNK[..chunk])?;
        off += chunk;
    }
    Ok(())
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
    /// [`write_bytes_raw`](Self::write_bytes_raw). Backends/engines that model
    /// guest read-only syscall buffers add the no-write gate in their concrete
    /// write path so carrick-internal unchecked writes can bypass it.
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // The SHARED default gates a write on the PROT_NONE set only. The READ-ONLY
        // write gate (`range_no_write`, the analog of HVF's
        // `validate_guest_write_range`) is backend-specific — HVF enforces it inside
        // its own `write_bytes_raw`, and the x86 engine OVERRIDES this method to add
        // the `no_write` check — so it deliberately does NOT live here (carrick's own
        // content loads use the unchecked path to bypass it).
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
        // Streamed in fixed chunks so a large scrub allocates nothing.
        zero_range_chunked(address, len, |addr, bytes| {
            self.write_bytes_raw(addr, bytes)
        })
    }

    /// PERMISSION-CHECKED zeroing of a guest range, the counterpart to
    /// [`zero_backing`](Self::zero_backing): use this when the guest legitimately
    /// OWNS the bytes and a PROT_NONE / read-only overlap must EFAULT — e.g.
    /// `select`/`pselect` zeroing its fd-sets on timeout, an `mremap` clearing a
    /// reused destination, or io_uring ring init. Streams `ZERO_CHUNK` through
    /// the gated [`write_bytes`](Self::write_bytes) so a large clear allocates
    /// nothing; on the first faulting chunk it returns the error and stops,
    /// exactly as the single `write_bytes` it replaces. Do NOT override — override
    /// `write_bytes_raw` for a faster backing path.
    fn zero_guest_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        zero_range_chunked(address, len, |addr, bytes| self.write_bytes(addr, bytes))
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

    /// Mark a guest range read-only for syscall writes (`no_write=true`) or clear
    /// it when the range becomes writable/unmapped. This is the host-side EFAULT
    /// counterpart to guest-visible page-table write protection: a syscall that
    /// writes into a `PROT_READ` buffer must fail with `EFAULT`, while reads from
    /// the same buffer remain allowed. Default: no-op for memory models that do
    /// not track read-only syscall buffers.
    fn set_no_write(&mut self, _address: u64, _len: usize, _no_write: bool) {}

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

    /// Fork-coherent host location for the guest futex word at `guest_addr`, but
    /// ONLY when it lies in a guest `MAP_SHARED` region. Returns `None` for
    /// private/anon guest memory, which stays in-process via the parking-lot
    /// table. Default: `None`.
    fn shared_futex_location(&self, _guest_addr: u64) -> Option<SharedFutexLocation> {
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

#[cfg(test)]
mod zero_tests {
    use super::*;
    use crate::protections::MemoryProtections;

    /// Minimal Vec-backed [`GuestMemory`] for exercising the zero helpers without
    /// a hypervisor: `write_bytes_raw`/`read_bytes_raw` hit a flat buffer, and the
    /// `protections()` gate is honoured by the trait's default `write_bytes`.
    struct MockMem {
        buf: Vec<u8>,
        prot: MemoryProtections,
    }

    impl MockMem {
        fn new(len: usize, fill: u8) -> Self {
            Self {
                buf: vec![fill; len],
                prot: MemoryProtections::default(),
            }
        }
    }

    impl GuestMemory for MockMem {
        fn protections(&self) -> Option<&MemoryProtections> {
            Some(&self.prot)
        }
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let a = address as usize;
            self.buf
                .get(a..a + length)
                .map(<[u8]>::to_vec)
                .ok_or(MemoryError::OutOfBounds { address, length })
        }
        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            let a = address as usize;
            match self.buf.get_mut(a..a + bytes.len()) {
                Some(slot) => {
                    slot.copy_from_slice(bytes);
                    Ok(())
                }
                None => Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                }),
            }
        }
    }

    #[test]
    fn zero_range_chunked_streams_contiguous_chunks_without_full_alloc() {
        // 2 full chunks + a partial: proves the helper never hands the writer a
        // slice larger than ZERO_CHUNK (no len-sized temp), the slices are all
        // zero, and together they cover [base, base+len) exactly once, contiguously.
        let len = ZERO_CHUNK.len() * 2 + 1234;
        let base = 0x4000u64;
        let mut chunks: Vec<(u64, usize)> = Vec::new();
        let mut all_zero = true;
        zero_range_chunked(base, len, |addr, bytes| {
            all_zero &= bytes.iter().all(|&b| b == 0);
            assert!(bytes.len() <= ZERO_CHUNK.len(), "chunk exceeds ZERO_CHUNK");
            chunks.push((addr, bytes.len()));
            Ok(())
        })
        .expect("chunked zero succeeds");
        assert!(all_zero, "every chunk is zero bytes");
        assert_eq!(chunks.len(), 3, "two full chunks + remainder");
        let mut cursor = base;
        let mut total = 0usize;
        for (addr, n) in &chunks {
            assert_eq!(*addr, cursor, "chunks are contiguous, no gaps/overlap");
            cursor += *n as u64;
            total += *n;
        }
        assert_eq!(total, len, "covers the whole range");
    }

    #[test]
    fn zero_range_chunked_zero_len_never_calls_writer() {
        let mut calls = 0u32;
        zero_range_chunked(0x1000, 0, |_, _| {
            calls += 1;
            Ok(())
        })
        .expect("zero-length is a no-op Ok");
        assert_eq!(calls, 0, "no writer call for an empty range");
    }

    #[test]
    fn zero_range_chunked_propagates_writer_error() {
        let err = zero_range_chunked(0x1000, 10, |_, _| {
            Err(MemoryError::OutOfBounds {
                address: 0x1000,
                length: 10,
            })
        })
        .unwrap_err();
        assert!(matches!(err, MemoryError::OutOfBounds { .. }));
    }

    #[test]
    fn zero_guest_range_zeros_a_writable_range_across_chunks() {
        let len = ZERO_CHUNK.len() + 7;
        let mut mem = MockMem::new(0x2000 + len, 0xAB);
        mem.zero_guest_range(0x2000, len)
            .expect("zero a writable range");
        assert!(
            mem.buf[0x2000..0x2000 + len].iter().all(|&b| b == 0),
            "target range zeroed"
        );
        assert!(
            mem.buf[..0x2000].iter().all(|&b| b == 0xAB),
            "bytes before the range are untouched"
        );
    }

    #[test]
    fn zero_guest_range_faults_on_prot_none_and_scrubs_nothing() {
        // The permission-checked path: a range overlapping a PROT_NONE window must
        // EFAULT and write nothing — identical to the single `write_bytes` it replaces.
        let mut mem = MockMem::new(0x100, 0xAB);
        mem.prot.set_no_access(0x40, 0x20, true);
        let err = mem.zero_guest_range(0x30, 0x40).unwrap_err();
        assert!(matches!(err, MemoryError::OutOfBounds { .. }));
        assert!(
            mem.buf[0x30..0x70].iter().all(|&b| b == 0xAB),
            "no bytes scrubbed when the gate faults"
        );
    }

    #[test]
    fn zero_backing_bypasses_the_prot_none_gate() {
        // zero_backing is the deliberate BYPASS — scrubbing a reused PROT_NONE /
        // unmapped region is its entire purpose, so it must succeed where
        // zero_guest_range faults.
        let mut mem = MockMem::new(0x100, 0xAB);
        mem.prot.set_no_access(0x40, 0x20, true);
        mem.zero_backing(0x30, 0x40)
            .expect("backing scrub ignores the gate");
        assert!(
            mem.buf[0x30..0x70].iter().all(|&b| b == 0),
            "the protected range is scrubbed"
        );
    }

    #[test]
    fn zero_backing_scrubs_across_multiple_chunks() {
        let len = ZERO_CHUNK.len() * 2 + 1;
        let mut mem = MockMem::new(len, 0xCD);
        mem.zero_backing(0, len).expect("multi-chunk scrub");
        assert!(mem.buf.iter().all(|&b| b == 0), "whole region scrubbed");
    }
}

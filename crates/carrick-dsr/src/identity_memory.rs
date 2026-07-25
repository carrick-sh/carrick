//! The identity guest-memory model: guest VA == host VA.
//!
//! Extracted from `carrick-runtime/src/native_freebsd.rs` (Phase 2 of the
//! native-lane seam plan; see
//! `docs/superpowers/specs/2026-07-23-identity-memory-neutralization-notes.md`).
//! Every FreeBSD/x86_64 native-lane guest mapping lives at the SAME address in
//! this process, so [`GuestMemory`] reads/writes are plain host memory
//! accesses at the guest address rather than a translated page-table walk —
//! this is the model a future NetBSD native lane (also identity-mapped) would
//! reuse wholesale, hence "the NetBSD floor" framing in the parent plan.
//!
//! # Why this module is generic over `A: ExecutableMutationAuthority`
//!
//! [`IdentityGuestMemory`]'s mutating [`GuestMemory`] methods must serialize a
//! guest-code WRITE against concurrently-running JIT'd translations of the
//! same (or overlapping) code region. On the x86/FreeBSD lane that
//! coordination is `ExecutableEpoch` — the thread-loop's JIT-admission/
//! quiescence coordinator (`native_freebsd.rs`, ~4.2K lines, Phase-3 loop-merge
//! territory) — but this module only ever calls its `begin_mutation` method
//! once, so [`ExecutableMutationAuthority`] names exactly that one method
//! rather than pulling in the coordinator itself (which would invert the
//! crate graph: `carrick-dsr` would depend on `carrick-runtime`).
//!
//! # Why this module is NOT generic over `NativeHost`/`GuestIsa`
//!
//! Two small host-specific behaviors remain: a fork-coherent shared-futex
//! waiter key (FreeBSD `kern.proc.vmmap`; Darwin has no equivalent) and the
//! extra `mmap(2)` flag bit that makes a `MAP_FIXED` request atomically fail
//! on collision instead of silently replacing bytes (FreeBSD `MAP_EXCL`;
//! Darwin/NetBSD have no such flag). Both are passed in by value via
//! [`IdentityHostSeam`] rather than threaded as a second generic parameter —
//! `IdentityGuestMemory<A>` needing two unrelated generic axes (mutation
//! authority AND host behavior) for no shared reason would be needless
//! complexity for a runtime constant. The x86-64 canonical-VA boundary
//! (`X86_64_USER_END_EXCLUSIVE`) is likewise kept a plain constant rather than
//! parameterized over `GuestIsa`: today's only three callers (this module,
//! `native_freebsd.rs`'s x86-instruction-fetch cluster, and
//! `carrick-dsr-x86`'s `cflow` glue) are all x86-64-only, and threading a
//! second generic parameter through this module's ~30 interconnected
//! functions for a single always-x86-64 constant is not warranted until a
//! second ISA actually needs this module.
//!
//! # Process-global statics
//!
//! [`IDENTITY_PROTECTIONS`] and [`IDENTITY_HOST_MAPPING_LOCK`] move here
//! UNCHANGED from `native_freebsd.rs`: still bare process-global `static`s,
//! not per-run state. This is a real, intentional constraint carried forward
//! from the pre-extraction design (not a regression introduced by the move):
//! exactly one native x86/FreeBSD run may be live per OS process at a time
//! (see `native_freebsd.rs`'s own `RUN_LOCK` doc comment), so process-global
//! guest-mapping metadata is safe. A future multi-run-per-process host would
//! need to make these per-run instead — out of scope here.
//!
//! # Orphan-rule routing note
//!
//! Only the bare `impl ControlFlowMemory for IdentityGuestMemory<A>` is
//! orphan-forced out of this crate (to `carrick-dsr-x86`, which owns the
//! `ControlFlowMemory` trait) — everything else in this module's closure
//! stays here. `IdentityXstateMemoryReader`/`IdentityXstateMemoryWriter`
//! (x86 xstate transfer) stay in `native_freebsd.rs`: they are local wrapper
//! types over the concrete `IdentityGuestMemory<ExecutableEpoch>`
//! instantiation, so the orphan rule never forces them anywhere, and
//! genericizing them over `A` would buy `carrick-dsr-x86` nothing it needs.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use carrick_abi as linux_abi;
use carrick_guest_mem::{GuestMemory, GuestVa, MemoryError, RepointPrivateError};

use crate::native_error::NativeMemoryError;
/// Executable-mutation coordination [`IdentityGuestMemory`] needs to serialize
/// a guest-code WRITE against concurrently-running JIT'd translations of the
/// same (or overlapping) code region. One method, because
/// `mapping_write_for_mutation`/`mapping_read_for_write` are the ONLY call
/// sites — this is provably sufficient: the lease's own `Drop` is what
/// releases the coordinator, so no second "end_mutation" method is needed.
///
/// This decouples the shared identity-memory model from the x86 thread-loop's
/// `ExecutableEpoch` (Phase-3 territory): `ExecutableEpoch` implements this
/// trait additively (zero changes to its own body) so `IdentityGuestMemory`
/// can live in `carrick-dsr`, one crate upstream of where `ExecutableEpoch`
/// stays.
pub trait ExecutableMutationAuthority: Send + Sync {
    type Lease;
    type Error: std::fmt::Debug;

    /// Mirrors `ExecutableEpoch::begin_mutation`'s exact receiver: the lease
    /// holds its own `Arc<Self>` clone, so borrowing through the Arc (not
    /// `&self`) is required, not stylistic.
    fn begin_mutation(self: &std::sync::Arc<Self>) -> Result<Self::Lease, Self::Error>;
}

/// The subset of a native lane's host behavior [`IdentityGuestMemory`] needs,
/// passed in by value rather than threaded as a second generic parameter
/// alongside `A: ExecutableMutationAuthority` (two unrelated generic axes on
/// one struct for no shared reason). Both fields default to the value every
/// non-FreeBSD host wants unconditionally: no other native lane calls
/// `shared_futex_location` on this type or reaches the MAP_FIXED collision
/// path these back.
#[derive(Clone, Copy)]
pub struct IdentityHostSeam {
    /// Real body: `carrick_dsr::lane::NativeHost::shared_futex_waiter_key`.
    pub shared_futex_waiter_key: fn(usize) -> Option<usize>,
    /// Real body: `carrick_dsr::lane::NativeHost::exclusive_fixed_map_flag`.
    pub exclusive_fixed_map_flag: i32,
}

impl Default for IdentityHostSeam {
    fn default() -> Self {
        Self {
            shared_futex_waiter_key: |_host_addr| None,
            exclusive_fixed_map_flag: 0,
        }
    }
}

/// A guest address space where guest VA == host VA: `GuestMemory` reads and
/// writes are plain host memory accesses at the guest address. The native
/// model maps the guest image and every guest mapping into THIS process's
/// address space, so no translation is needed. Out-of-bounds/unmapped guest
/// pointers are not gated here — a bad pointer faults, and the fault shim
/// turns an in-JIT fault into a typed Signal exit (a syscall-path bad pointer
/// is a genuine EFAULT the handlers surface).
pub struct IdentityGuestMemory<A: ExecutableMutationAuthority> {
    /// The active run's executable-mutation authority. Loader-only memory used
    /// before a run's coordinator exists intentionally carries `None`; every
    /// live main/clone/fork thread binds the coordinator owned by its active
    /// run.
    executable_epoch: Option<Arc<A>>,
    /// The [`GuestMemory`] metadata setters predate fallible host mappings and
    /// therefore cannot return a [`MemoryError`]. Keep the first host-mapping
    /// failure typed until the surrounding native dispatch boundary consumes
    /// it; the failed range is simultaneously left fail-closed in the registry.
    mapping_failure: Option<carrick_guest_mem::MemoryError>,
    /// The seam bits sourced from the concrete native lane's `NativeHost`
    /// (see [`IdentityHostSeam`]) — never a second generic parameter.
    host: IdentityHostSeam,
}

// `#[derive(Clone, Default)]` on a generic struct adds a spurious `A: Clone`/
// `A: Default` bound (derive macros bound EVERY type parameter, even ones a
// field only uses inside an `Arc`/`Option` that doesn't itself need it).
// `ExecutableEpoch` implements neither, so these are hand-written to bound
// only what the fields actually require.
impl<A: ExecutableMutationAuthority> Clone for IdentityGuestMemory<A> {
    fn clone(&self) -> Self {
        Self {
            executable_epoch: self.executable_epoch.clone(),
            mapping_failure: self.mapping_failure.clone(),
            host: self.host,
        }
    }
}

impl<A: ExecutableMutationAuthority> Default for IdentityGuestMemory<A> {
    fn default() -> Self {
        Self {
            executable_epoch: None,
            mapping_failure: None,
            host: IdentityHostSeam::default(),
        }
    }
}

impl<A: ExecutableMutationAuthority> IdentityGuestMemory<A> {
    pub fn uncoordinated() -> Self {
        Self::default()
    }

    pub fn for_run(executable_epoch: &Arc<A>, host: IdentityHostSeam) -> Self {
        Self {
            executable_epoch: Some(Arc::clone(executable_epoch)),
            mapping_failure: None,
            host,
        }
    }

    /// General constructor for callers that already hold an
    /// `Option<Arc<A>>` (e.g. re-deriving one memory view's coordinator
    /// binding for another, such as a signal-delivery view that reuses this
    /// type only to share the checked-write helpers).
    pub fn from_epoch(executable_epoch: Option<Arc<A>>, host: IdentityHostSeam) -> Self {
        Self {
            executable_epoch,
            mapping_failure: None,
            host,
        }
    }

    fn record_mapping_failure(
        &mut self,
        address: u64,
        len: usize,
        error: carrick_guest_mem::MemoryError,
    ) {
        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        if self.mapping_failure.is_none() {
            self.mapping_failure = Some(error);
        }
    }

    pub fn take_mapping_failure(&mut self) -> Option<carrick_guest_mem::MemoryError> {
        self.mapping_failure.take()
    }

    /// Drop the inherited Arc without touching its mutex. A fork child has no
    /// sibling JIT threads and may perform child-tid writes before the run loop
    /// builds its fresh SharedRun; those writes must not acquire the parent's
    /// possibly sibling-owned coordinator.
    pub fn abandon_inherited_epoch_after_fork(&mut self) {
        self.executable_epoch = None;
    }

    pub fn rebind_after_fork(&mut self, executable_epoch: &Arc<A>) {
        self.executable_epoch = Some(Arc::clone(executable_epoch));
    }
}

pub const X86_64_USER_END_EXCLUSIVE: u64 = 1 << 47;
// Carrick exposes Linux's default `/proc/sys/vm/mmap_min_addr` (64 KiB);
// no guest mapping can legally back a syscall pointer below it.
pub const LINUX_MMAP_MIN_ADDR: u64 = 0x1_0000;
/// Native guest page size for this module's (x86_64) identity mappings.
pub const PAGE: u64 = 4096;

/// First byte outside Carrick's raw identity guest-pointer domain.
pub fn identity_raw_fault_address(address: u64, length: usize) -> Option<u64> {
    if length == 0 {
        return None;
    }
    if length > isize::MAX as usize
        || !(LINUX_MMAP_MIN_ADDR..X86_64_USER_END_EXCLUSIVE).contains(&address)
    {
        return Some(address);
    }
    match address.checked_add(length as u64) {
        Some(end) if end <= X86_64_USER_END_EXCLUSIVE => None,
        Some(_) => Some(X86_64_USER_END_EXCLUSIVE),
        None => Some(address),
    }
}

/// Linux x86-64 userspace occupies the low canonical half. Reject a raw range
/// before turning it into a host pointer if it crosses that boundary, wraps, or
/// exceeds Rust's slice size limit. This is a syscall-memory boundary: malformed
/// guest pointers must become EFAULT, never a host SIGSEGV or slice UB.
pub fn identity_raw_range_valid(address: u64, length: usize) -> bool {
    identity_raw_fault_address(address, length).is_none()
}

pub static IDENTITY_PROTECTIONS: std::sync::LazyLock<
    carrick_guest_mem::protections::MemoryProtections,
> = std::sync::LazyLock::new(carrick_guest_mem::protections::MemoryProtections::default);
/// Serializes raw host mapping transitions against fault-intolerant Rust-side
/// signal-frame copies. Guest JIT accesses remain governed by the fault shim;
/// this lock only prevents `mprotect`/`munmap`/`MAP_FIXED` from racing a host
/// the kernel-contained copy after its metadata check.
pub static IDENTITY_HOST_MAPPING_LOCK: parking_lot::RwLock<()> = parking_lot::RwLock::new(());

pub fn identity_host_mapping_write_until(
    deadline: std::time::Instant,
) -> Option<parking_lot::RwLockWriteGuard<'static, ()>> {
    loop {
        if let Some(guard) = IDENTITY_HOST_MAPPING_LOCK.try_write() {
            return Some(guard);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::yield_now();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeMappingOperation {
    General,
    IdentityBacking,
    IdentityProtection,
    ElfReservation,
    ElfSegment,
    GuestStack,
    Scratch,
    Vvar,
    VvarProtection,
    Vdso,
    HostAlias,
}

#[cfg(any(test, feature = "test-hooks"))]
impl NativeMappingOperation {
    const COUNT: usize = 11;

    const fn index(self) -> usize {
        match self {
            Self::General => 0,
            Self::IdentityBacking => 1,
            Self::IdentityProtection => 2,
            Self::ElfReservation => 3,
            Self::ElfSegment => 4,
            Self::GuestStack => 5,
            Self::Scratch => 6,
            Self::Vvar => 7,
            Self::VvarProtection => 8,
            Self::Vdso => 9,
            Self::HostAlias => 10,
        }
    }
}

#[cfg(any(test, feature = "test-hooks"))]
#[derive(Clone, Copy, Debug)]
pub enum InjectedMmapResult {
    Failed,
    WrongAddress,
}

#[cfg(any(test, feature = "test-hooks"))]
pub struct NativeMappingFaultInjection {
    mmap: Option<(NativeMappingOperation, usize, InjectedMmapResult)>,
    mmap_calls: [usize; NativeMappingOperation::COUNT],
    mprotect: Option<(NativeMappingOperation, usize)>,
    mprotect_calls: [usize; NativeMappingOperation::COUNT],
    munmap: Option<usize>,
    munmap_calls: usize,
    munmaps: Vec<(u64, usize, i32)>,
}

#[cfg(any(test, feature = "test-hooks"))]
impl Default for NativeMappingFaultInjection {
    fn default() -> Self {
        Self {
            mmap: None,
            mmap_calls: [0; NativeMappingOperation::COUNT],
            mprotect: None,
            mprotect_calls: [0; NativeMappingOperation::COUNT],
            munmap: None,
            munmap_calls: 0,
            munmaps: Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "test-hooks"))]
std::thread_local! {
    static NATIVE_MAPPING_FAULTS: std::cell::RefCell<NativeMappingFaultInjection> =
        std::cell::RefCell::new(NativeMappingFaultInjection::default());
}

// This scaffold's only consumers are `carrick-runtime`'s (cross-crate,
// test-hooks-gated) native_freebsd fault-injection tests, which this
// extraction deliberately left in place (see the module doc) rather than
// relocating wholesale — so carrick-dsr's OWN test binary never constructs
// one, and dead-code analysis has no in-crate evidence these are reachable.
#[cfg(any(test, feature = "test-hooks"))]
#[allow(dead_code)]
pub struct NativeMappingFaultGuard;

#[cfg(any(test, feature = "test-hooks"))]
#[allow(dead_code, clippy::new_without_default)]
impl NativeMappingFaultGuard {
    pub fn new() -> Self {
        NATIVE_MAPPING_FAULTS.with(|faults| *faults.borrow_mut() = Default::default());
        Self
    }

    pub fn fail_mmap(&self, operation: NativeMappingOperation, result: InjectedMmapResult) {
        self.fail_mmap_at(operation, 0, result);
    }

    pub fn fail_mmap_at(
        &self,
        operation: NativeMappingOperation,
        index: usize,
        result: InjectedMmapResult,
    ) {
        NATIVE_MAPPING_FAULTS.with(|faults| {
            faults.borrow_mut().mmap = Some((operation, index, result));
        });
    }

    pub fn fail_mprotect(&self, operation: NativeMappingOperation) {
        self.fail_mprotect_at(operation, 0);
    }

    pub fn fail_mprotect_at(&self, operation: NativeMappingOperation, index: usize) {
        NATIVE_MAPPING_FAULTS.with(|faults| {
            faults.borrow_mut().mprotect = Some((operation, index));
        });
    }

    pub fn fail_next_munmap(&self) {
        self.fail_munmap_at(0);
    }

    pub fn fail_munmap_at(&self, index: usize) {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow_mut().munmap = Some(index));
    }

    pub fn mmap_call_count(&self, operation: NativeMappingOperation) -> usize {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().mmap_calls[operation.index()])
    }

    pub fn mprotect_call_count(&self, operation: NativeMappingOperation) -> usize {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().mprotect_calls[operation.index()])
    }

    pub fn munmaps(&self) -> Vec<(u64, usize, i32)> {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().munmaps.clone())
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Drop for NativeMappingFaultGuard {
    fn drop(&mut self) {
        NATIVE_MAPPING_FAULTS.with(|faults| *faults.borrow_mut() = Default::default());
    }
}

/// Every caller documents, at its own call site, why `address` is a valid
/// target for this operation (an owned reservation, an exact prior mapping,
/// or a null/floating request) — matching this module's existing SAFETY-
/// comment convention rather than pushing the contract into the type system
/// via `unsafe fn` (which would ripple through every call site, in this crate
/// and `carrick-runtime`, for no behavior change).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn host_mmap(
    _operation: NativeMappingOperation,
    address: *mut libc::c_void,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: libc::off_t,
) -> *mut libc::c_void {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(injected) = NATIVE_MAPPING_FAULTS.with(|faults| {
        let mut faults = faults.borrow_mut();
        let operation_index = _operation.index();
        let call_index = faults.mmap_calls[operation_index];
        faults.mmap_calls[operation_index] = call_index.saturating_add(1);
        match faults.mmap {
            Some((site, target_index, result))
                if site == _operation && target_index == call_index =>
            {
                faults.mmap = None;
                Some(result)
            }
            _ => None,
        }
    }) {
        return match injected {
            InjectedMmapResult::Failed => {
                // Injected host failures must carry a real errno; route through
                // the portable errno accessor (Darwin/FreeBSD `__error`, NetBSD
                // `__errno`, Linux `__errno_location`) rather than a per-OS deref.
                carrick_portable::set_errno(libc::ENOMEM);
                libc::MAP_FAILED
            }
            // Allocate a real, separately-owned mapping so exact-address
            // validation must clean it up rather than merely rejecting a fake
            // pointer which could not prove rollback.
            InjectedMmapResult::WrongAddress => unsafe {
                let first = libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                );
                if first != libc::MAP_FAILED && first == address {
                    // The allocator may immediately reuse the just-freed
                    // requested hole. Occupy it while asking for a second map,
                    // then release it so the injected result is deterministically
                    // wrong without leaving an unowned mapping behind.
                    let second = libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        prot,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    );
                    libc::munmap(first, len);
                    second
                } else {
                    first
                }
            },
        };
    }
    // SAFETY: each caller documents ownership and validates the returned map.
    unsafe { libc::mmap(address, len, prot, flags, fd, offset) }
}

pub fn take_injected_mprotect_failure(_operation: NativeMappingOperation) -> bool {
    #[cfg(any(test, feature = "test-hooks"))]
    return NATIVE_MAPPING_FAULTS.with(|faults| {
        let mut faults = faults.borrow_mut();
        let operation_index = _operation.index();
        let call_index = faults.mprotect_calls[operation_index];
        faults.mprotect_calls[operation_index] = call_index.saturating_add(1);
        if matches!(
            faults.mprotect,
            Some((site, target_index)) if site == _operation && target_index == call_index
        ) {
            faults.mprotect = None;
            true
        } else {
            false
        }
    });
    #[cfg(not(any(test, feature = "test-hooks")))]
    {
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn host_mprotect(
    operation: NativeMappingOperation,
    address: *mut libc::c_void,
    len: usize,
    prot: i32,
) -> i32 {
    if take_injected_mprotect_failure(operation) {
        // Route the injected errno through the portable accessor (per-OS
        // errno location handled by carrick-portable).
        carrick_portable::set_errno(libc::EIO);
        return -1;
    }
    // SAFETY: callers hold the identity mapping writer for owned guest ranges.
    unsafe { libc::mprotect(address, len, prot) }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn host_munmap(address: *mut libc::c_void, len: usize) -> i32 {
    #[cfg(any(test, feature = "test-hooks"))]
    let injected_failure = NATIVE_MAPPING_FAULTS.with(|faults| {
        let mut faults = faults.borrow_mut();
        let call_index = faults.munmap_calls;
        faults.munmap_calls = call_index.saturating_add(1);
        if faults.munmap == Some(call_index) {
            faults.munmap = None;
            true
        } else {
            false
        }
    });
    #[cfg(not(any(test, feature = "test-hooks")))]
    let injected_failure = false;
    // SAFETY: callers invoke this only for mappings whose ownership they hold.
    let result = if injected_failure {
        // Route the injected errno through the portable accessor (per-OS
        // errno location handled by carrick-portable).
        #[cfg(any(test, feature = "test-hooks"))]
        carrick_portable::set_errno(libc::EIO);
        -1
    } else {
        unsafe { libc::munmap(address, len) }
    };
    #[cfg(any(test, feature = "test-hooks"))]
    NATIVE_MAPPING_FAULTS.with(|faults| {
        faults
            .borrow_mut()
            .munmaps
            .push((address as u64, len, result));
    });
    result
}

impl<A: ExecutableMutationAuthority> IdentityGuestMemory<A> {
    fn epoch_error(error: A::Error) -> carrick_guest_mem::MemoryError {
        carrick_guest_mem::MemoryError::HostMap(format!(
            "native executable epoch failed: {error:?}"
        ))
    }

    fn begin_executable_mutation(
        &self,
    ) -> Result<Option<A::Lease>, carrick_guest_mem::MemoryError> {
        self.executable_epoch
            .as_ref()
            .map(|epoch| epoch.begin_mutation().map_err(Self::epoch_error))
            .transpose()
    }

    /// Obtain the executable epoch (when needed) before the host mapping writer.
    /// A range initially classified as data is rechecked under the mapping lock;
    /// if it became executable while the lock was being acquired, release and
    /// retry in the required epoch-first order.
    pub fn mapping_write_for_mutation(
        &self,
        address: u64,
        len: usize,
        requested_executable: bool,
    ) -> Result<
        (Option<A::Lease>, parking_lot::RwLockWriteGuard<'static, ()>),
        carrick_guest_mem::MemoryError,
    > {
        if self.executable_epoch.is_none() {
            return Ok((None, IDENTITY_HOST_MAPPING_LOCK.write()));
        }
        let mut mutation =
            if requested_executable || IDENTITY_PROTECTIONS.range_has_executable(address, len) {
                self.begin_executable_mutation()?
            } else {
                None
            };
        loop {
            let mapping = IDENTITY_HOST_MAPPING_LOCK.write();
            if mutation.is_some() || !IDENTITY_PROTECTIONS.range_has_executable(address, len) {
                return Ok((mutation, mapping));
            }
            drop(mapping);
            mutation = self.begin_executable_mutation()?;
        }
    }

    /// Raw/checked host copies use the mapping reader, but executable overlap
    /// still requires the epoch first. The under-lock recheck closes the same
    /// data-to-text classification race as the mapping-writer helper.
    pub fn mapping_read_for_write(
        &self,
        address: u64,
        len: usize,
    ) -> Result<
        (Option<A::Lease>, parking_lot::RwLockReadGuard<'static, ()>),
        carrick_guest_mem::MemoryError,
    > {
        if self.executable_epoch.is_none() {
            return Ok((None, IDENTITY_HOST_MAPPING_LOCK.read()));
        }
        let mut mutation = if IDENTITY_PROTECTIONS.range_has_executable(address, len) {
            self.begin_executable_mutation()?
        } else {
            None
        };
        loop {
            let mapping = IDENTITY_HOST_MAPPING_LOCK.read();
            if mutation.is_some() || !IDENTITY_PROTECTIONS.range_has_executable(address, len) {
                return Ok((mutation, mapping));
            }
            drop(mapping);
            mutation = self.begin_executable_mutation()?;
        }
    }
}

pub fn ensure_identity_backed_with_registry(
    address: u64,
    len: usize,
    protections: &carrick_guest_mem::protections::MemoryProtections,
    exclusive_map_flag: i32,
) -> Result<(), MemoryError> {
    if len == 0 || address < PAGE {
        return Ok(());
    }
    let end = address.checked_add(len as u64).ok_or_else(|| {
        MemoryError::HostMap(format!(
            "native identity range overflows at 0x{address:x} for {len} bytes"
        ))
    })?;
    let mut holes = protections.unmapped_intersections(address, len);
    if holes.is_empty() {
        let mut residency = 0u8;
        // `mincore` is a non-faulting host mapping query. Fresh shared-aperture
        // allocations have no protection metadata yet and no host mapping.
        let start_is_mapped = unsafe {
            libc::mincore(
                address as *mut libc::c_void,
                PAGE as usize,
                (&mut residency as *mut u8).cast(),
            ) == 0
        };
        if start_is_mapped {
            return Ok(());
        }
        holes.push((address, end));
    }

    let holes = holes
        .into_iter()
        .map(|(hole_start, hole_end)| {
            usize::try_from(hole_end - hole_start)
                .map(|hole_len| (hole_start, hole_end, hole_len))
                .map_err(|_| {
                    MemoryError::HostMap(format!(
                        "native identity hole length does not fit host: \
                         [0x{hole_start:x},0x{hole_end:x})"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut candidate = NativeMappingTransaction::new("identity backing candidate");
    for &(hole_start, _hole_end, hole_len) in &holes {
        let mapped = host_mmap(
            NativeMappingOperation::IdentityBacking,
            hole_start as *mut libc::c_void,
            hole_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | exclusive_map_flag | libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        );
        if mapped == libc::MAP_FAILED {
            let primary = NativeMemoryError::Unsupported(format!(
                "native identity mmap at 0x{hole_start:x} for {hole_len} bytes failed: {}",
                std::io::Error::last_os_error()
            ));
            return Err(MemoryError::HostMap(
                candidate.rollback(primary).to_string(),
            ));
        }
        let mapping = NativeMapping::claim(
            mapped as u64,
            hole_len,
            NativeMappingOperation::IdentityBacking,
            "identity backing hole",
        );
        if mapped as u64 != hole_start {
            let returned = mapped as u64;
            let cleanup = mapping.teardown().err();
            let detail = cleanup
                .map(|error| format!("; wrong-address cleanup failed: {error}"))
                .unwrap_or_default();
            let primary = NativeMemoryError::Unsupported(format!(
                "native identity mmap requested 0x{hole_start:x} but returned 0x{returned:x}{detail}"
            ));
            return Err(MemoryError::HostMap(
                candidate.rollback(primary).to_string(),
            ));
        }
        if let Err(error) = candidate.acquire(mapping) {
            return Err(MemoryError::HostMap(candidate.rollback(error).to_string()));
        }
    }

    // Clear metadata only after every exact hole has live backing. Ownership
    // then transfers from the candidate to the ordinary VMA/munmap lifecycle.
    for &(hole_start, _hole_end, hole_len) in &holes {
        protections.set_unmapped(hole_start, hole_len, false);
    }
    candidate.commit_to_vma();
    Ok(())
}

pub fn ensure_identity_backed(
    address: u64,
    len: usize,
    exclusive_map_flag: i32,
) -> Result<(), MemoryError> {
    ensure_identity_backed_with_registry(address, len, &IDENTITY_PROTECTIONS, exclusive_map_flag)
}

pub fn identity_read_bytes_raw_unlocked(
    address: u64,
    length: usize,
) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if !identity_raw_range_valid(address, length)
        || IDENTITY_PROTECTIONS.range_unmapped(address, length)
    {
        return Err(carrick_guest_mem::MemoryError::OutOfBounds { address, length });
    }
    // SAFETY: the mapping lock prevents host unmap/protection transitions while
    // this identity host slice is live.
    Ok(unsafe { std::slice::from_raw_parts(address as *const u8, length).to_vec() })
}

/// Copy into a range whose complete guest-writable permission was validated
/// before the caller retained the identity mapping writer and protection
/// snapshot. Those exact guards make re-reading protection metadata here both
/// unnecessary and deadlocking; canonical-range validation remains checked.
pub fn identity_write_prevalidated_unlocked(
    address: u64,
    bytes: &[u8],
) -> Result<(), carrick_guest_mem::MemoryError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if !identity_raw_range_valid(address, bytes.len()) {
        return Err(carrick_guest_mem::MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        });
    }
    // SAFETY: service_fork retains both IDENTITY_HOST_MAPPING_LOCK's writer and
    // IDENTITY_PROTECTIONS' exclusive guard from prevalidation through copy.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
    }
    Ok(())
}

pub fn identity_write_bytes_raw_unlocked(
    address: u64,
    bytes: &[u8],
) -> Result<(), carrick_guest_mem::MemoryError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if !identity_raw_range_valid(address, bytes.len())
        || IDENTITY_PROTECTIONS.range_unmapped(address, bytes.len())
    {
        return Err(carrick_guest_mem::MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        });
    }
    // SAFETY: the mapping lock prevents host unmap/protection transitions while
    // this identity host copy is in progress. Callers that enforce guest write
    // permissions check `range_write_denied` under the same read guard.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
    }
    Ok(())
}

pub fn identity_apply_host_protection_preserving_bus(
    address: u64,
    len: usize,
    host_prot: i32,
) -> Result<Vec<(u64, u64)>, MemoryError> {
    let bus_faults = IDENTITY_PROTECTIONS.bus_fault_intersections(address, len);
    let end = address
        .checked_add(u64::try_from(len).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: len,
        })?)
        .ok_or(MemoryError::OutOfBounds {
            address,
            length: len,
        })?;
    let apply = |start: u64, range_end: u64, protection: i32| -> Result<(), MemoryError> {
        let range_len = range_end.saturating_sub(start);
        if range_len == 0 {
            return Ok(());
        }
        let range_len = usize::try_from(range_len).map_err(|_| MemoryError::OutOfBounds {
            address: start,
            length: len,
        })?;
        if host_mprotect(
            NativeMappingOperation::IdentityProtection,
            start as *mut libc::c_void,
            range_len,
            protection,
        ) != 0
        {
            return Err(MemoryError::HostMap(format!(
                "native identity mprotect at 0x{start:x} for {range_len} bytes failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    };

    let mut cursor = address;
    for &(bus_start, bus_end) in &bus_faults {
        apply(cursor, bus_start, host_prot)?;
        apply(bus_start, bus_end, libc::PROT_NONE)?;
        cursor = bus_end;
    }
    apply(cursor, end, host_prot)?;
    Ok(bus_faults)
}

impl<A: ExecutableMutationAuthority> GuestMemory for IdentityGuestMemory<A> {
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&IDENTITY_PROTECTIONS)
    }

    fn has_complete_mapping_metadata(&self) -> bool {
        true
    }

    fn supports_concurrent_exec_protection(&self) -> bool {
        true
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        if !no_access
            && let Err(error) =
                ensure_identity_backed(address, len, self.host.exclusive_fixed_map_flag)
        {
            self.record_mapping_failure(address, len, error);
            return;
        }
        IDENTITY_PROTECTIONS.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        IDENTITY_PROTECTIONS.set_no_write(address, len, no_write);
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        // Route straight to the shared metadata's `set_unmapped` — the trait
        // default would reclassify the hole through `set_no_access` first.
        if !unmapped
            && let Err(error) =
                ensure_identity_backed(address, len, self.host.exclusive_fixed_map_flag)
        {
            self.record_mapping_failure(address, len, error);
            return;
        }
        IDENTITY_PROTECTIONS.set_unmapped(address, len, unmapped);
    }

    fn set_mapping_protection(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        // Establish backing before changing either host permission or metadata.
        if let Err(error) = ensure_identity_backed(address, len, self.host.exclusive_fixed_map_flag)
        {
            self.record_mapping_failure(address, len, error);
            return;
        }
        let host_prot = if no_access {
            libc::PROT_NONE
        } else if no_write {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        let bus_faults =
            match identity_apply_host_protection_preserving_bus(address, len, host_prot) {
                Ok(bus_faults) => bus_faults,
                Err(error) => {
                    self.record_mapping_failure(address, len, error);
                    return;
                }
            };
        // mprotect changes permission only: preserve the VMA's backing-sharing
        // and EOF-tail classifications while publishing the new permission.
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, no_access, no_write);
        for (bus_start, bus_end) in bus_faults {
            let Ok(bus_len) = usize::try_from(bus_end - bus_start) else {
                self.record_mapping_failure(
                    address,
                    len,
                    MemoryError::OutOfBounds {
                        address: bus_start,
                        length: len,
                    },
                );
                return;
            };
            IDENTITY_PROTECTIONS.set_no_access(bus_start, bus_len, true);
            IDENTITY_PROTECTIONS.set_executable(bus_start, bus_len, false);
        }
    }

    fn set_mapping_sharing(
        &mut self,
        address: u64,
        len: usize,
        sharing: carrick_guest_mem::MappingSharing,
    ) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        IDENTITY_PROTECTIONS.set_mapping_sharing(address, len, sharing);
    }

    fn set_mapping_protection_and_sharing(
        &mut self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
        sharing: carrick_guest_mem::MappingSharing,
    ) {
        let (_mutation, _mapping_guard) = match self.mapping_write_for_mutation(address, len, false)
        {
            Ok(guards) => guards,
            Err(error) => {
                self.record_mapping_failure(address, len, error);
                return;
            }
        };
        // Shared metadata is a statement about a live host backing. Establish
        // both backing and requested host protection first, then atomically
        // replace permission/sharing metadata. The registry clears stale execute
        // permission here; protect_range publishes the new execute state later.
        if let Err(error) = ensure_identity_backed(address, len, self.host.exclusive_fixed_map_flag)
        {
            self.record_mapping_failure(address, len, error);
            return;
        }
        let host_prot = if no_access {
            libc::PROT_NONE
        } else if no_write {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        if len != 0
            && host_mprotect(
                NativeMappingOperation::IdentityProtection,
                address as *mut libc::c_void,
                len,
                host_prot,
            ) != 0
        {
            let error = MemoryError::HostMap(format!(
                "native identity mprotect at 0x{address:x} for {len} bytes failed: {}",
                std::io::Error::last_os_error()
            ));
            self.record_mapping_failure(address, len, error);
            return;
        }
        IDENTITY_PROTECTIONS
            .set_mapping_protection_and_sharing(address, len, no_access, no_write, sharing);
    }

    fn protect_range(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        if let Some(error) = self.take_mapping_failure() {
            return Err(error);
        }
        let requested_executable = prot & linux_abi::LINUX_PROT_EXEC != 0;
        let (_mutation, _mapping_guard) =
            match self.mapping_write_for_mutation(address, len, requested_executable) {
                Ok(guards) => guards,
                Err(error) => {
                    IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
                    return Err(error);
                }
            };
        if let Err(error) = ensure_identity_backed(address, len, self.host.exclusive_fixed_map_flag)
        {
            IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
            return Err(error);
        }
        let readable = prot & (linux_abi::LINUX_PROT_READ | linux_abi::LINUX_PROT_EXEC) != 0;
        let writable = prot & linux_abi::LINUX_PROT_WRITE != 0;
        let executable = requested_executable;
        // DSR never executes guest pages directly: executable mappings need a
        // host-readable translation view, not host PROT_EXEC. Enforce guest
        // stores with host read-only pages and PROT_NONE with inaccessible ones.
        let host_prot = match (readable, writable) {
            (_, true) => libc::PROT_READ | libc::PROT_WRITE,
            (true, false) => libc::PROT_READ,
            (false, false) => libc::PROT_NONE,
        };
        let bus_faults =
            match identity_apply_host_protection_preserving_bus(address, len, host_prot) {
                Ok(bus_faults) => bus_faults,
                Err(error) => {
                    IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
                    return Err(error);
                }
            };
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, prot == 0, !writable);
        IDENTITY_PROTECTIONS.set_executable(address, len, executable);
        for (bus_start, bus_end) in bus_faults {
            let bus_len =
                usize::try_from(bus_end - bus_start).map_err(|_| MemoryError::OutOfBounds {
                    address: bus_start,
                    length: len,
                })?;
            IDENTITY_PROTECTIONS.set_no_access(bus_start, bus_len, true);
            IDENTITY_PROTECTIONS.set_executable(bus_start, bus_len, false);
        }
        Ok(())
    }

    fn read_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
        if length != 0 && IDENTITY_PROTECTIONS.range_no_access(address, length) {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds { address, length });
        }
        identity_read_bytes_raw_unlocked(address, length)
    }

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
        identity_read_bytes_raw_unlocked(address, length)
    }

    fn write_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let (_mutation, _mapping_guard) = self.mapping_read_for_write(address, bytes.len())?;
        if !bytes.is_empty() && IDENTITY_PROTECTIONS.range_write_denied(address, bytes.len()) {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        identity_write_bytes_raw_unlocked(address, bytes)
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let (_mutation, _mapping_guard) = self.mapping_read_for_write(address, bytes.len())?;
        identity_write_bytes_raw_unlocked(address, bytes)
    }

    /// Guest `munmap`/`mremap`-shrink actually releases the host pages, so the
    /// freed range faults on access (guest `SIGSEGV`/`SEGV_MAPERR`) and `mincore`
    /// reports it unmapped (ENOMEM) — matching Linux. A no-op left the identity
    /// arena pages mapped+RW, so a raw read of a freed tail still succeeded and
    /// `mincore` said mapped (`mremapshrink`, `mremapmove`, `mremapsharedshrink`).
    /// `munmap` at the identity VA (guest VA == host VA) creates a genuine hole;
    /// a later guest mmap that reuses this VA re-establishes backing through
    /// `zero_backing` (which re-maps the hole before scrubbing it).
    fn unmap_range(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        if len == 0 || address < PAGE {
            return Ok(());
        }
        let (_mutation, _mapping_guard) = self.mapping_write_for_mutation(address, len, false)?;
        if host_munmap(address as *mut libc::c_void, len) != 0 {
            return Err(MemoryError::HostMap(format!(
                "native identity munmap at 0x{address:x} for {len} bytes failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Record the hole so a syscall-path read/write returns EFAULT (not a host
        // fault) and mincore reports it unmapped; a guest JIT access still faults
        // the real hole and is caught by the fault shim as SEGV_MAPERR.
        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        Ok(())
    }

    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), RepointPrivateError> {
        if content.len() != len {
            return Err(RepointPrivateError::clean(MemoryError::OutOfBounds {
                address: va,
                length: content.len(),
            }));
        }
        let (_mutation, _mapping_guard) = self
            .mapping_write_for_mutation(va, len, false)
            .map_err(RepointPrivateError::clean)?;
        // VMM backends repoint stage-1 into a private overlay IPA. Identity
        // execution has no page tables, so MAP_FIXED atomically replaces this
        // process's mapping with anonymous MAP_PRIVATE storage. The complete
        // file/zero snapshot was prepared before this call; copying it cannot
        // fail after replacement. Mapping-sharing and execute metadata remain
        // conservatively unchanged until the dispatcher publishes them after
        // this physical transaction returns.
        let mapped = host_mmap(
            NativeMappingOperation::IdentityBacking,
            va as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        );
        if mapped == libc::MAP_FAILED {
            return Err(RepointPrivateError::clean(MemoryError::HostMap(format!(
                "native private repoint at 0x{va:x} for {len} bytes failed: {}",
                std::io::Error::last_os_error()
            ))));
        }
        if mapped as u64 != va {
            let misplaced = NativeMapping::claim(
                mapped as u64,
                len,
                NativeMappingOperation::IdentityBacking,
                "misplaced private repoint",
            );
            if misplaced.teardown().is_err() && misplaced.teardown().is_err() {
                std::process::abort();
            }
            return Err(RepointPrivateError::clean(MemoryError::HostMap(format!(
                "native private repoint requested 0x{va:x} but returned 0x{:x}",
                mapped as u64
            ))));
        }
        // SAFETY: the exact MAP_FIXED result owns `len == content.len()` writable
        // bytes at `va`; the dispatcher-owned snapshot is disjoint host storage.
        unsafe { std::ptr::copy_nonoverlapping(content.as_ptr(), va as *mut u8, len) };
        // Physical replacement is complete and this infallible metadata update
        // retires any boot/shared classification before a direct caller can ask
        // for an unflagged shared-futex key. The dispatcher republishes the full
        // protection tuple after this transaction returns.
        IDENTITY_PROTECTIONS.set_mapping_sharing(
            va,
            len,
            carrick_guest_mem::MappingSharing::Private,
        );
        Ok(())
    }

    /// Scrub private anonymous backing. The typed reuse hook below performs the
    /// actual replacement so this legacy bypass cannot silently pick a sharing
    /// mode at an identity-host mapping boundary.
    fn zero_backing(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        self.zero_anonymous_reuse(address, len, carrick_guest_mem::MappingSharing::Private)
    }

    /// Re-establish zero-filled anonymous backing while preserving the guest
    /// mapping's physical sharing. A reused `MAP_SHARED` hole must remain a real
    /// host `MAP_SHARED` object so writes after `fork` stay visible in both
    /// processes; `zero_backing` historically remapped every hole MAP_PRIVATE.
    fn zero_anonymous_reuse(
        &mut self,
        address: u64,
        len: usize,
        sharing: carrick_guest_mem::MappingSharing,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        if len == 0 {
            return Ok(());
        }
        let (_mutation, _mapping_guard) = self.mapping_write_for_mutation(address, len, false)?;
        let map_sharing = match sharing {
            carrick_guest_mem::MappingSharing::Private => libc::MAP_PRIVATE,
            carrick_guest_mem::MappingSharing::Shared => libc::MAP_SHARED,
        };
        // Identity VA. MAP_FIXED atomically replaces any current mapping (or
        // fills a munmap hole) with fresh zero-filled anonymous RW pages. A
        // failed exact replacement leaves the old host object, bytes, and guest
        // sharing metadata untouched; scrubbing that old object and publishing
        // the requested sharing would falsely claim a private mapping is shared.
        let p = host_mmap(
            NativeMappingOperation::IdentityBacking,
            address as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_ANON | map_sharing,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return Err(MemoryError::HostMap(format!(
                "native anonymous reuse replacement at 0x{address:x} for {len} bytes failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if p as u64 != address {
            let misplaced = NativeMapping::claim(
                p as u64,
                len,
                NativeMappingOperation::IdentityBacking,
                "misplaced anonymous reuse replacement",
            );
            if misplaced.teardown().is_err() && misplaced.teardown().is_err() {
                // Drop is also fail-stop, but abort here makes the checked retry
                // contract explicit and avoids returning while ownership is live.
                std::process::abort();
            }
            return Err(MemoryError::HostMap(format!(
                "native anonymous reuse replacement requested 0x{address:x} but returned 0x{:x}",
                p as u64
            )));
        }
        IDENTITY_PROTECTIONS
            .set_mapping_protection_and_sharing(address, len, false, false, sharing);
        Ok(())
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
        identity_raw_range_valid(address, length)
            && !IDENTITY_PROTECTIONS.range_write_denied(address, length)
    }

    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        (identity_raw_range_valid(address, len)
            && !IDENTITY_PROTECTIONS.range_unmapped(address, len)
            && !IDENTITY_PROTECTIONS.range_no_access(address, len))
        .then_some(address as *const u8)
    }

    fn host_ptr_for_write(&mut self, _address: u64, _len: usize) -> Option<*mut u8> {
        // The trait cannot attach an IDENTITY_HOST_MAPPING_LOCK guard to the raw
        // pointer's lifetime. A sibling could otherwise mprotect/munmap or start
        // an executable mutation after this method returns but before the host
        // kernel/libc consumes the pointer. Keep the copy path, whose epoch and
        // mapping guards span the complete write.
        None
    }

    fn resident_pages(
        &self,
        start: carrick_guest_mem::GuestVa,
        page_count: u64,
        page_size: u64,
    ) -> Option<Vec<u8>> {
        let pages = usize::try_from(page_count).ok()?;
        let len = page_count.checked_mul(page_size)?;
        let len = usize::try_from(len).ok()?;
        if pages == 0 {
            return Some(Vec::new());
        }
        let mut residency = vec![0u8; pages];
        // SAFETY: identity guest VA is the live host mapping. `residency` has
        // exactly one byte per queried FreeBSD page; this lane's guest and host
        // page sizes are both 4 KiB.
        if unsafe {
            libc::mincore(
                start.raw() as *mut libc::c_void,
                len,
                residency.as_mut_ptr().cast(),
            )
        } != 0
        {
            return None;
        }
        Some(
            residency
                .into_iter()
                .map(|byte| u8::from(byte & 1 != 0))
                .collect(),
        )
    }

    /// A SHARED (non-`FUTEX_PRIVATE`) futex word resolves to a fork-coherent host
    /// word so a wake from ANOTHER forked process reaches a waiter parked here. In
    /// the identity model the guest VA already IS that host word (a guest
    /// `MAP_SHARED` page is genuinely shared across the host `fork`), so the
    /// location is `Direct` at the address itself; the driver then waits/wakes on
    /// it with FreeBSD `_umtx_op(UMTX_OP_WAIT_UINT/WAKE)`, whose non-private key is
    /// the shared VM object + offset and so spans the fork. The dispatcher only
    /// calls this after excluding `FUTEX_PRIVATE` and clear-child-tid words, so a
    /// process-private futex never reaches here and keeps using the in-process
    /// parking-lot `FutexTable`.
    fn shared_futex_location(
        &self,
        guest_addr: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !guest_addr.is_multiple_of(std::mem::align_of::<u32>() as u64)
            || !IDENTITY_PROTECTIONS
                .range_mutable_shared_backing(guest_addr, std::mem::size_of::<u32>())
        {
            return None;
        }
        let host_addr = guest_addr as usize;
        Some(carrick_guest_mem::SharedFutexLocation::Direct {
            word: carrick_guest_mem::HostVa(host_addr),
            waiter_key: (self.host.shared_futex_waiter_key)(host_addr).unwrap_or(host_addr),
        })
    }
}

pub const IDENTITY_KERNEL_COPY_PIPE_BOUND: usize = 1024;
/// Keep every pipe transfer comfortably below FreeBSD's atomic pipe-write bound
/// and split again at guest page boundaries so an EFAULT names the first page
/// whose backing is inaccessible.
pub const IDENTITY_KERNEL_COPY_CHUNK: usize = 512;
/// Host signals can interrupt a syscall repeatedly. A guest-memory service must
/// still terminate deterministically rather than spin forever under the mapping
/// lock, so every no-progress EINTR path has this explicit retry budget.
pub const IDENTITY_KERNEL_COPY_EINTR_LIMIT: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityCheckedReadError {
    Fault(carrick_guest_mem::protections::GuestMemoryFault),
    BusAddress { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityCheckedWriteError {
    Fault(carrick_guest_mem::protections::GuestMemoryFault),
    BusAddress { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityKernelCopyError {
    GuestFault { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

pub fn identity_checked_read_fault(
    fault: carrick_guest_mem::protections::GuestMemoryFault,
) -> IdentityCheckedReadError {
    if fault.kind == carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied
        && IDENTITY_PROTECTIONS.range_bus_fault(fault.address.raw(), 1)
    {
        IdentityCheckedReadError::BusAddress {
            address: fault.address,
        }
    } else {
        IdentityCheckedReadError::Fault(fault)
    }
}

pub fn identity_checked_write_fault(
    fault: carrick_guest_mem::protections::GuestMemoryFault,
) -> IdentityCheckedWriteError {
    if fault.kind == carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied
        && IDENTITY_PROTECTIONS.range_bus_fault(fault.address.raw(), 1)
    {
        IdentityCheckedWriteError::BusAddress {
            address: fault.address,
        }
    } else {
        IdentityCheckedWriteError::Fault(fault)
    }
}

#[cfg(any(test, feature = "test-hooks"))]
std::thread_local! {
    static IDENTITY_KERNEL_COPY_PIPE_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn reset_identity_kernel_copy_pipe_census() {
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(|census| census.set(0));
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn identity_kernel_copy_pipe_census() -> usize {
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn reset_identity_kernel_copyin_operation_census() {
    IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS.with(|census| census.set(0));
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn identity_kernel_copyin_operation_census() -> usize {
    IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn reset_identity_kernel_copyout_operation_census() {
    IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS.with(|census| census.set(0));
}

#[cfg(any(test, feature = "test-hooks"))]
pub fn identity_kernel_copyout_operation_census() -> usize {
    IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS.with(std::cell::Cell::get)
}

/// Portable `pipe2(O_CLOEXEC|O_NONBLOCK)` equivalent. Darwin has no `pipe2(2)`
/// syscall — confirmed absent from the vendored `libc` crate's Apple bindings
/// (present only under the BSD-like/Linux-like/etc. modules) — so this
/// composes the identical end state from `pipe(2)` + `fcntl(2)`, a portable
/// pattern rather than a behavior change: pipe creation here is a one-time
/// setup, never a hot path. The io error is captured immediately after the
/// failing syscall, before any cleanup `close(2)` call can disturb errno.
fn portable_pipe_cloexec_nonblock() -> Result<[libc::c_int; 2], std::io::Error> {
    let mut raw_fds = [-1; 2];
    // SAFETY: `raw_fds` names two writable integers.
    if unsafe { libc::pipe(raw_fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for &fd in &raw_fds {
        // SAFETY: `fd` is one of the two descriptors `pipe` just created;
        // both remain open (not yet wrapped in an owning type) until this
        // function returns.
        let ok = unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) == 0
        };
        if !ok {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors are exclusively owned by this failed
            // setup (no `OwnedFd` exists yet); closing them here is the only
            // way to avoid a leak.
            unsafe {
                libc::close(raw_fds[0]);
                libc::close(raw_fds[1]);
            }
            return Err(error);
        }
    }
    Ok(raw_fds)
}

pub fn identity_kernel_copy_pipe(
    address: GuestVa,
    operation: &'static str,
) -> Result<(OwnedFd, OwnedFd), IdentityKernelCopyError> {
    let raw_fds;
    let mut interruptions = 0usize;
    loop {
        // On success ownership moves immediately into `OwnedFd`; failures own
        // no descriptors (see `portable_pipe_cloexec_nonblock`'s own cleanup).
        match portable_pipe_cloexec_nonblock() {
            Ok(fds) => {
                raw_fds = fds;
                break;
            }
            Err(error) => {
                if error.raw_os_error() == Some(libc::EINTR)
                    && interruptions < IDENTITY_KERNEL_COPY_EINTR_LIMIT
                {
                    interruptions += 1;
                    continue;
                }
                let detail = if error.raw_os_error() == Some(libc::EINTR) {
                    format!(
                        "creating private {operation} pipe exceeded the {}-interrupt retry bound",
                        IDENTITY_KERNEL_COPY_EINTR_LIMIT
                    )
                } else {
                    format!("creating private {operation} pipe failed: {error}")
                };
                return Err(IdentityKernelCopyError::Backend { address, detail });
            }
        }
    }
    #[cfg(any(test, feature = "test-hooks"))]
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(|census| census.set(census.get() + 1));
    // SAFETY: successful `pipe2` returned two fresh owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(raw_fds[0]) };
    // SAFETY: ownership of the distinct write descriptor transfers once.
    let writer = unsafe { OwnedFd::from_raw_fd(raw_fds[1]) };
    Ok((reader, writer))
}

pub fn identity_kernel_copy_chunk(
    address: GuestVa,
    completed: usize,
    remaining: usize,
    operation: &'static str,
) -> Result<(GuestVa, usize), IdentityKernelCopyError> {
    let completed = u64::try_from(completed).map_err(|_| IdentityKernelCopyError::Backend {
        address,
        detail: format!("kernel-contained {operation} offset is not representable"),
    })?;
    let current =
        address
            .raw()
            .checked_add(completed)
            .ok_or_else(|| IdentityKernelCopyError::Backend {
                address,
                detail: format!("kernel-contained {operation} address overflowed"),
            })?;
    let page_remaining =
        usize::try_from(PAGE - current % PAGE).map_err(|_| IdentityKernelCopyError::Backend {
            address: GuestVa(current),
            detail: format!("kernel-contained {operation} page extent is not representable"),
        })?;
    Ok((
        GuestVa(current),
        remaining
            .min(page_remaining)
            .min(IDENTITY_KERNEL_COPY_CHUNK),
    ))
}

pub fn identity_kernel_copyin_exact_using(
    address: GuestVa,
    destination: &mut [u8],
    pipe: Option<(&OwnedFd, &OwnedFd)>,
) -> Result<(), IdentityKernelCopyError> {
    if destination.len() > IDENTITY_KERNEL_COPY_PIPE_BOUND {
        return Err(IdentityKernelCopyError::Backend {
            address,
            detail: format!(
                "kernel-contained guest read of {} bytes exceeds the {}-byte pipe bound",
                destination.len(),
                IDENTITY_KERNEL_COPY_PIPE_BOUND
            ),
        });
    }
    if destination.is_empty() {
        return Ok(());
    }

    let owned_pipe;
    let (reader, writer) = match pipe {
        Some(pipe) => pipe,
        None => {
            owned_pipe = identity_kernel_copy_pipe(address, "copyin")?;
            (&owned_pipe.0, &owned_pipe.1)
        }
    };
    let mut completed = 0usize;
    while completed < destination.len() {
        let (chunk_start, chunk_len) = identity_kernel_copy_chunk(
            address,
            completed,
            destination.len() - completed,
            "guest read",
        )?;
        #[cfg(any(test, feature = "test-hooks"))]
        IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS.with(|census| census.set(census.get() + 1));
        let mut interruptions = 0usize;
        let accepted = loop {
            // SAFETY: the source is intentionally an untrusted guest pointer.
            // FreeBSD validates and copies it; Rust never dereferences it.
            let copied = unsafe {
                libc::write(
                    writer.as_raw_fd(),
                    chunk_start.raw() as usize as *const libc::c_void,
                    chunk_len,
                )
            };
            if copied >= 0 {
                break usize::try_from(copied).map_err(|_| IdentityKernelCopyError::Backend {
                    address: chunk_start,
                    detail: "private copyin pipe write returned an invalid length".into(),
                })?;
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) if interruptions < IDENTITY_KERNEL_COPY_EINTR_LIMIT => {
                    interruptions += 1;
                }
                Some(libc::EINTR) => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: format!(
                            "private copyin pipe write exceeded the {}-interrupt retry bound",
                            IDENTITY_KERNEL_COPY_EINTR_LIMIT
                        ),
                    });
                }
                Some(libc::EAGAIN) => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: "private copyin pipe was not empty before a nonblocking write"
                            .into(),
                    });
                }
                Some(libc::EFAULT) => {
                    return Err(IdentityKernelCopyError::GuestFault {
                        address: chunk_start,
                    });
                }
                _ => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: format!("private copyin pipe write failed: {error}"),
                    });
                }
            }
        };
        if accepted == 0 || accepted > chunk_len {
            return Err(IdentityKernelCopyError::Backend {
                address: chunk_start,
                detail: format!(
                    "private copyin pipe write returned {accepted} bytes for a {chunk_len}-byte chunk"
                ),
            });
        }

        let mut drained = 0usize;
        let mut interruptions = 0usize;
        while drained < accepted {
            // SAFETY: this pointer stays within the caller-owned destination.
            // The pipe contains exactly `accepted - drained` bytes of guest data.
            let copied = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    destination.as_mut_ptr().add(completed + drained).cast(),
                    accepted - drained,
                )
            };
            if copied < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) if interruptions < IDENTITY_KERNEL_COPY_EINTR_LIMIT => {
                        interruptions += 1;
                        continue;
                    }
                    Some(libc::EINTR) => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: chunk_start,
                            detail: format!(
                                "private copyin pipe drain exceeded the {}-interrupt retry bound",
                                IDENTITY_KERNEL_COPY_EINTR_LIMIT
                            ),
                        });
                    }
                    Some(libc::EAGAIN) => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: chunk_start,
                            detail: format!(
                                "private copyin pipe drain reached EAGAIN after accepting {accepted} bytes"
                            ),
                        });
                    }
                    _ => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: chunk_start,
                            detail: format!("private copyin pipe read failed: {error}"),
                        });
                    }
                }
            }
            let copied = usize::try_from(copied).map_err(|_| IdentityKernelCopyError::Backend {
                address: chunk_start,
                detail: "private copyin pipe read returned an invalid length".into(),
            })?;
            if copied == 0 || copied > accepted - drained {
                return Err(IdentityKernelCopyError::Backend {
                    address: chunk_start,
                    detail: format!(
                        "private copyin pipe read returned {copied} bytes with {} bytes pending",
                        accepted - drained
                    ),
                });
            }
            drained += copied;
            interruptions = 0;
        }
        completed += accepted;
    }
    Ok(())
}

pub fn identity_kernel_copyin_exact(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityKernelCopyError> {
    identity_kernel_copyin_exact_using(address, destination, None)
}

pub fn identity_kernel_copyout_exact(
    address: GuestVa,
    source: &[u8],
) -> Result<(), IdentityKernelCopyError> {
    if source.len() > IDENTITY_KERNEL_COPY_PIPE_BOUND {
        return Err(IdentityKernelCopyError::Backend {
            address,
            detail: format!(
                "kernel-contained guest write of {} bytes exceeds the {}-byte pipe bound",
                source.len(),
                IDENTITY_KERNEL_COPY_PIPE_BOUND
            ),
        });
    }
    if source.is_empty() {
        return Ok(());
    }

    let (reader, writer) = identity_kernel_copy_pipe(address, "copyout")?;
    let mut completed = 0usize;
    while completed < source.len() {
        let (chunk_start, chunk_len) = identity_kernel_copy_chunk(
            address,
            completed,
            source.len() - completed,
            "guest write",
        )?;
        let mut interruptions = 0usize;
        let accepted = loop {
            // SAFETY: the source is a valid Rust slice and the requested chunk
            // remains within it. The nonblocking pipe is empty by construction.
            let copied = unsafe {
                libc::write(
                    writer.as_raw_fd(),
                    source.as_ptr().add(completed).cast(),
                    chunk_len,
                )
            };
            if copied >= 0 {
                break usize::try_from(copied).map_err(|_| IdentityKernelCopyError::Backend {
                    address: chunk_start,
                    detail: "private copyout pipe write returned an invalid length".into(),
                })?;
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) if interruptions < IDENTITY_KERNEL_COPY_EINTR_LIMIT => {
                    interruptions += 1;
                }
                Some(libc::EINTR) => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: format!(
                            "private copyout pipe write exceeded the {}-interrupt retry bound",
                            IDENTITY_KERNEL_COPY_EINTR_LIMIT
                        ),
                    });
                }
                Some(libc::EAGAIN) => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: "private copyout pipe was not empty before a nonblocking write"
                            .into(),
                    });
                }
                _ => {
                    return Err(IdentityKernelCopyError::Backend {
                        address: chunk_start,
                        detail: format!("private copyout pipe write failed: {error}"),
                    });
                }
            }
        };
        if accepted == 0 || accepted > chunk_len {
            return Err(IdentityKernelCopyError::Backend {
                address: chunk_start,
                detail: format!(
                    "private copyout pipe write returned {accepted} bytes for a {chunk_len}-byte chunk"
                ),
            });
        }

        let mut drained = 0usize;
        let mut interruptions = 0usize;
        while drained < accepted {
            let destination = chunk_start
                .raw()
                .checked_add(drained as u64)
                .ok_or_else(|| IdentityKernelCopyError::Backend {
                    address: chunk_start,
                    detail: "kernel-contained guest write address overflowed".into(),
                })?;
            #[cfg(any(test, feature = "test-hooks"))]
            IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS.with(|census| census.set(census.get() + 1));
            // SAFETY: the destination is intentionally an untrusted guest
            // pointer. FreeBSD validates it while copying out of the pipe.
            let copied = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    destination as usize as *mut libc::c_void,
                    accepted - drained,
                )
            };
            if copied < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) if interruptions < IDENTITY_KERNEL_COPY_EINTR_LIMIT => {
                        interruptions += 1;
                        continue;
                    }
                    Some(libc::EINTR) => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: GuestVa(destination),
                            detail: format!(
                                "private copyout pipe drain exceeded the {}-interrupt retry bound",
                                IDENTITY_KERNEL_COPY_EINTR_LIMIT
                            ),
                        });
                    }
                    Some(libc::EAGAIN) => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: GuestVa(destination),
                            detail: format!(
                                "private copyout pipe drain reached EAGAIN after accepting {accepted} bytes"
                            ),
                        });
                    }
                    Some(libc::EFAULT) => {
                        return Err(IdentityKernelCopyError::GuestFault {
                            address: GuestVa(destination),
                        });
                    }
                    _ => {
                        return Err(IdentityKernelCopyError::Backend {
                            address: GuestVa(destination),
                            detail: format!("private copyout pipe read failed: {error}"),
                        });
                    }
                }
            }
            let copied = usize::try_from(copied).map_err(|_| IdentityKernelCopyError::Backend {
                address: GuestVa(destination),
                detail: "private copyout pipe read returned an invalid length".into(),
            })?;
            if copied == 0 || copied > accepted - drained {
                return Err(IdentityKernelCopyError::Backend {
                    address: GuestVa(destination),
                    detail: format!(
                        "private copyout pipe read returned {copied} bytes with {} bytes pending",
                        accepted - drained
                    ),
                });
            }
            drained += copied;
            interruptions = 0;
        }
        completed += accepted;
    }
    Ok(())
}

pub fn identity_checked_read_exact(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityCheckedReadError> {
    let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
    identity_checked_read_exact_under_mapping_lock(address, destination)
}

/// Inner checked read for callers that already hold the identity-mapping read
/// lock. Keeping the lock outside a multi-byte instruction fetch makes execute,
/// access, backing, and direct-or-kernel copy decisions one coherent mapping
/// observation.
pub fn identity_checked_read_exact_under_mapping_lock(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityCheckedReadError> {
    if destination.len() > IDENTITY_KERNEL_COPY_PIPE_BOUND {
        return Err(IdentityCheckedReadError::Backend {
            address,
            detail: format!(
                "architectural guest read of {} bytes exceeds the {}-byte kernel-copy bound",
                destination.len(),
                IDENTITY_KERNEL_COPY_PIPE_BOUND
            ),
        });
    }
    if destination.is_empty() {
        return Ok(());
    }
    if let Some(fault_address) = identity_raw_fault_address(address.raw(), destination.len()) {
        return Err(IdentityCheckedReadError::Fault(
            carrick_guest_mem::protections::GuestMemoryFault {
                address: GuestVa(fault_address),
                kind: carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped,
            },
        ));
    }
    if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
        address,
        destination.len(),
        carrick_guest_mem::protections::GuestMemoryAccess::Read,
    ) {
        return Err(identity_checked_read_fault(fault));
    }
    if !IDENTITY_PROTECTIONS.range_mutable_shared_backing(address.raw(), destination.len()) {
        // SAFETY: raw-domain and complete read access were validated before
        // either pointer is dereferenced. The mapping reader excludes Carrick
        // VMA transitions, while the mutable-shared exclusion proves the source
        // is anonymous/private materialized backing that cannot be invalidated
        // by an external vnode truncate. Checked-read destinations are
        // Rust-owned architectural buffers and cannot overlap guest backing.
        unsafe {
            std::ptr::copy_nonoverlapping(
                address.raw() as usize as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        return Ok(());
    }
    match identity_kernel_copyin_exact(address, destination) {
        Ok(()) => Ok(()),
        Err(IdentityKernelCopyError::GuestFault {
            address: fault_address,
        }) => {
            // A Carrick mapping transition cannot occur while the reader is
            // held, but classify again after kernel copyin so any registry
            // fault always retains Linux MAPERR/ACCERR precedence.
            if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
                address,
                destination.len(),
                carrick_guest_mem::protections::GuestMemoryAccess::Read,
            ) {
                Err(identity_checked_read_fault(fault))
            } else {
                Err(IdentityCheckedReadError::BusAddress {
                    address: fault_address,
                })
            }
        }
        Err(IdentityKernelCopyError::Backend { address, detail }) => {
            Err(IdentityCheckedReadError::Backend { address, detail })
        }
    }
}

pub fn identity_checked_write_exact<A: ExecutableMutationAuthority>(
    memory: &IdentityGuestMemory<A>,
    address: GuestVa,
    source: &[u8],
) -> Result<(), IdentityCheckedWriteError> {
    let (_mutation, _mapping_guard) = memory
        .mapping_read_for_write(address.raw(), source.len())
        .map_err(|error| IdentityCheckedWriteError::Backend {
            address,
            detail: error.to_string(),
        })?;
    identity_checked_write_exact_under_mapping_lock(address, source)
}

pub fn identity_checked_write_range_under_mapping_lock(
    address: GuestVa,
    length: usize,
) -> Result<(), IdentityCheckedWriteError> {
    if let Some(fault_address) = identity_raw_fault_address(address.raw(), length) {
        return Err(IdentityCheckedWriteError::Fault(
            carrick_guest_mem::protections::GuestMemoryFault {
                address: GuestVa(fault_address),
                kind: carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped,
            },
        ));
    }
    if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
        address,
        length,
        carrick_guest_mem::protections::GuestMemoryAccess::Write,
    ) {
        return Err(identity_checked_write_fault(fault));
    }
    Ok(())
}

/// Lower-level checked copyout used only after `mapping_read_for_write` has
/// arbitrated executable mutation and retained its lease plus mapping reader.
/// It must not be exposed as an independent write path.
pub fn identity_checked_write_exact_under_mapping_lock(
    address: GuestVa,
    source: &[u8],
) -> Result<(), IdentityCheckedWriteError> {
    if source.len() > IDENTITY_KERNEL_COPY_PIPE_BOUND {
        return Err(IdentityCheckedWriteError::Backend {
            address,
            detail: format!(
                "architectural guest write of {} bytes exceeds the {}-byte kernel-copy bound",
                source.len(),
                IDENTITY_KERNEL_COPY_PIPE_BOUND
            ),
        });
    }
    if source.is_empty() {
        return Ok(());
    }
    identity_checked_write_range_under_mapping_lock(address, source.len())?;
    if !IDENTITY_PROTECTIONS.range_mutable_shared_backing(address.raw(), source.len()) {
        // SAFETY: raw-domain and complete write access were validated before
        // either pointer is dereferenced. The caller retains both the mapping
        // reader and any executable-mutation lease, and the mutable-shared
        // exclusion proves the destination cannot be invalidated by an external
        // vnode truncate. Architectural source buffers are Rust-owned and do
        // not overlap guest backing.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.as_ptr(),
                address.raw() as usize as *mut u8,
                source.len(),
            );
        }
        return Ok(());
    }
    match identity_kernel_copyout_exact(address, source) {
        Ok(()) => Ok(()),
        Err(IdentityKernelCopyError::GuestFault {
            address: fault_address,
        }) => {
            if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
                address,
                source.len(),
                carrick_guest_mem::protections::GuestMemoryAccess::Write,
            ) {
                Err(identity_checked_write_fault(fault))
            } else {
                Err(IdentityCheckedWriteError::BusAddress {
                    address: fault_address,
                })
            }
        }
        Err(IdentityKernelCopyError::Backend { address, detail }) => {
            Err(IdentityCheckedWriteError::Backend { address, detail })
        }
    }
}

pub fn identity_checked_read_sigframe(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityCheckedReadError> {
    let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
    let mut completed = 0usize;
    for chunk in destination.chunks_mut(IDENTITY_KERNEL_COPY_PIPE_BOUND) {
        let offset = u64::try_from(completed).map_err(|_| IdentityCheckedReadError::Backend {
            address,
            detail: "signal-frame read offset is not representable".into(),
        })?;
        let chunk_address = address
            .raw()
            .checked_add(offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedReadError::Backend {
                address,
                detail: "signal-frame read address overflowed".into(),
            })?;
        identity_checked_read_exact_under_mapping_lock(chunk_address, chunk)?;
        completed += chunk.len();
    }
    Ok(())
}

/// Write a complete signal-frame extent while retaining the executable-mutation
/// lease and mapping reader in the ordinary outer-to-inner order. Registry
/// permission is validated for the complete frame before the first byte is
/// copied; mutable-shared chunks retain kernel containment for vnode-hole SIGBUS.
pub fn identity_checked_write_sigframe<A: ExecutableMutationAuthority>(
    memory: &IdentityGuestMemory<A>,
    address: GuestVa,
    source: &[u8],
) -> Result<(), IdentityCheckedWriteError> {
    let (_mutation, _mapping_guard) = memory
        .mapping_read_for_write(address.raw(), source.len())
        .map_err(|error| IdentityCheckedWriteError::Backend {
            address,
            detail: error.to_string(),
        })?;
    identity_checked_write_range_under_mapping_lock(address, source.len())?;
    let mut completed = 0usize;
    for chunk in source.chunks(IDENTITY_KERNEL_COPY_PIPE_BOUND) {
        let offset = u64::try_from(completed).map_err(|_| IdentityCheckedWriteError::Backend {
            address,
            detail: "signal-frame write offset is not representable".into(),
        })?;
        let chunk_address = address
            .raw()
            .checked_add(offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedWriteError::Backend {
                address,
                detail: "signal-frame write address overflowed".into(),
            })?;
        identity_checked_write_exact_under_mapping_lock(chunk_address, chunk)?;
        completed += chunk.len();
    }
    Ok(())
}

/// Whether a fixed `mmap` claims a range exclusively (must not silently
/// replace an existing mapping) or deliberately replaces one this process
/// already owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedRwReservation {
    /// Initial ownership acquisition: a collision must fail without replacing
    /// even one byte of the pre-existing host mapping.
    Exclusive,
    /// Exec retains the original arena owner while replacing its backing.
    ReplaceOwned,
}

/// `mmap(2)` a fixed-or-floating anonymous range. `exclusive_map_flag` is the
/// host's atomic-collision-detection bit for [`FixedRwReservation::Exclusive`]
/// (FreeBSD/NetBSD `MAP_EXCL`; `0` — a no-op — on hosts with no such flag,
/// e.g. Darwin, where `NativeMappingTransaction`'s own disjoint-range check is
/// the only protection). Callers source this from
/// `carrick_dsr::lane::NativeHost::exclusive_fixed_map_flag`; this function
/// itself never references a host-specific flag constant.
pub fn map_prot_at(
    operation: NativeMappingOperation,
    len: usize,
    prot: i32,
    fixed_at: Option<u64>,
    reservation: FixedRwReservation,
    exclusive_map_flag: i32,
) -> *mut u8 {
    let (addr, mut flags) = match fixed_at {
        Some(a) => (
            a as *mut libc::c_void,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
        ),
        None => (std::ptr::null_mut(), libc::MAP_PRIVATE | libc::MAP_ANON),
    };
    if fixed_at.is_some() && reservation == FixedRwReservation::Exclusive {
        flags |= exclusive_map_flag;
    }
    host_mmap(operation, addr, len, prot, flags, -1, 0).cast()
}

const NATIVE_MAPPING_LIVE: u8 = 0;
const NATIVE_MAPPING_TEARING_DOWN: u8 = 1;
const NATIVE_MAPPING_UNMAPPED: u8 = 2;

pub struct NativeMapping {
    pub base: u64,
    pub len: usize,
    state: std::sync::atomic::AtomicU8,
    pub operation: NativeMappingOperation,
    pub label: &'static str,
}

impl NativeMapping {
    pub fn claim(
        base: u64,
        len: usize,
        operation: NativeMappingOperation,
        label: &'static str,
    ) -> Self {
        Self {
            base,
            len,
            state: std::sync::atomic::AtomicU8::new(NATIVE_MAPPING_LIVE),
            operation,
            label,
        }
    }

    pub fn map_anonymous(
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        fixed_at: Option<u64>,
        label: &'static str,
        exclusive_map_flag: i32,
    ) -> Result<Self, NativeMemoryError> {
        let mapped = map_prot_at(
            operation,
            len,
            prot,
            fixed_at,
            FixedRwReservation::Exclusive,
            exclusive_map_flag,
        );
        if mapped.cast::<libc::c_void>() == libc::MAP_FAILED {
            return Err(NativeMemoryError::Unsupported(format!(
                "map native {label} ({operation:?}, {len} bytes) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mapping = Self::claim(mapped as u64, len, operation, label);
        if let Some(expected) = fixed_at
            && mapping.base != expected
        {
            let returned = mapping.base;
            let cleanup = mapping.teardown().err();
            let detail = cleanup
                .map(|error| format!("; wrong-address cleanup failed: {error}"))
                .unwrap_or_default();
            return Err(NativeMemoryError::Unsupported(format!(
                "map native {label} requested 0x{expected:x} but returned 0x{returned:x}{detail}"
            )));
        }
        Ok(mapping)
    }

    /// Optional fixed mappings (vvar/vDSO) may be unavailable, but a misplaced
    /// successful allocation is still owned and must be explicitly rolled back.
    pub fn map_optional_fixed(
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        expected: u64,
        label: &'static str,
        exclusive_map_flag: i32,
    ) -> Result<Option<Self>, NativeMemoryError> {
        let mapped = map_prot_at(
            operation,
            len,
            prot,
            Some(expected),
            FixedRwReservation::Exclusive,
            exclusive_map_flag,
        );
        if mapped.cast::<libc::c_void>() == libc::MAP_FAILED {
            return Ok(None);
        }
        let mapping = Self::claim(mapped as u64, len, operation, label);
        if mapping.base != expected {
            mapping.teardown()?;
            return Ok(None);
        }
        Ok(Some(mapping))
    }

    pub fn protect(
        &self,
        operation: NativeMappingOperation,
        prot: i32,
    ) -> Result<(), NativeMemoryError> {
        if self.state.load(std::sync::atomic::Ordering::Acquire) != NATIVE_MAPPING_LIVE {
            return Err(NativeMemoryError::Unsupported(format!(
                "protect non-live native {} ({:?})",
                self.label, self.operation
            )));
        }
        if host_mprotect(operation, self.base as *mut libc::c_void, self.len, prot) != 0 {
            return Err(NativeMemoryError::Unsupported(format!(
                "protect native {} at 0x{:x} for {} bytes failed: {}",
                self.label,
                self.base,
                self.len,
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Transfer a successfully installed dynamic mapping to the VMA lifecycle.
    /// The bytes remain mapped; this owner is merely disarmed so its Drop cannot
    /// tear down a mapping now tracked by the dispatcher's mmap/munmap state.
    pub fn relinquish_to_vma(&mut self) {
        *self.state.get_mut() = NATIVE_MAPPING_UNMAPPED;
    }

    pub fn teardown(&self) -> Result<(), NativeMemoryError> {
        match self.state.compare_exchange(
            NATIVE_MAPPING_LIVE,
            NATIVE_MAPPING_TEARING_DOWN,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(NATIVE_MAPPING_UNMAPPED) => return Ok(()),
            Err(_) => {
                return Err(NativeMemoryError::Unsupported(format!(
                    "concurrent native {} teardown ({:?})",
                    self.label, self.operation
                )));
            }
        }
        if host_munmap(self.base as *mut libc::c_void, self.len) == 0 {
            self.state.store(
                NATIVE_MAPPING_UNMAPPED,
                std::sync::atomic::Ordering::Release,
            );
            Ok(())
        } else {
            self.state
                .store(NATIVE_MAPPING_LIVE, std::sync::atomic::Ordering::Release);
            Err(NativeMemoryError::Unsupported(format!(
                "unmap native {} at 0x{:x} for {} bytes failed: {}",
                self.label,
                self.base,
                self.len,
                std::io::Error::last_os_error()
            )))
        }
    }
}

impl Drop for NativeMapping {
    fn drop(&mut self) {
        if *self.state.get_mut() == NATIVE_MAPPING_UNMAPPED {
            return;
        }
        if host_munmap(self.base as *mut libc::c_void, self.len) == 0 {
            *self.state.get_mut() = NATIVE_MAPPING_UNMAPPED;
            return;
        }
        // This is the final ownership backstop. Returning would lose the only
        // record of a live mapping and permit a later independent owner of the
        // same range. Fail-stop without unwinding or a panic payload.
        std::process::abort();
    }
}

pub fn teardown_native_mappings_collect(mappings: &[NativeMapping]) -> Vec<String> {
    mappings
        .iter()
        .filter_map(|mapping| mapping.teardown().err().map(|error| error.to_string()))
        .collect()
}

pub fn teardown_native_mappings(mappings: &[NativeMapping]) -> Result<(), NativeMemoryError> {
    let errors = teardown_native_mappings_collect(mappings);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(NativeMemoryError::Unsupported(format!(
            "native mapping teardown failed: {}",
            errors.join("; ")
        )))
    }
}

pub struct NativeMappingTransaction {
    label: &'static str,
    mappings: Vec<NativeMapping>,
}

impl NativeMappingTransaction {
    pub fn new(label: &'static str) -> Self {
        Self {
            label,
            mappings: Vec::new(),
        }
    }

    /// The candidate's own diagnostic label, for callers that fold a rollback
    /// into their own error vocabulary (see [`Self::rollback_teardown_errors`]).
    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn acquire(&mut self, mapping: NativeMapping) -> Result<usize, NativeMemoryError> {
        let Some(end) = mapping.base.checked_add(mapping.len as u64) else {
            let primary = NativeMemoryError::Unsupported(format!(
                "native {} range overflows at 0x{:x} for {} bytes",
                mapping.label, mapping.base, mapping.len
            ));
            let cleanup = mapping.teardown().err();
            return Err(match cleanup {
                Some(error) => NativeMemoryError::Unsupported(format!(
                    "{primary}; overflowing mapping rollback failed: {error}"
                )),
                None => primary,
            });
        };
        if let Some(existing) = self.mappings.iter().find(|existing| {
            let existing_end = existing.base.saturating_add(existing.len as u64);
            mapping.base < existing_end && existing.base < end
        }) {
            let primary = NativeMemoryError::Unsupported(format!(
                "native candidate ranges overlap: {} [0x{:x},0x{end:x}) and {} [0x{:x},0x{:x})",
                mapping.label,
                mapping.base,
                existing.label,
                existing.base,
                existing.base.saturating_add(existing.len as u64)
            ));
            let cleanup = mapping.teardown().err();
            return Err(match cleanup {
                Some(error) => NativeMemoryError::Unsupported(format!(
                    "{primary}; overlapping mapping rollback failed: {error}"
                )),
                None => primary,
            });
        }
        let index = self.mappings.len();
        self.mappings.push(mapping);
        Ok(index)
    }

    pub fn map_anonymous(
        &mut self,
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        fixed_at: Option<u64>,
        label: &'static str,
        exclusive_map_flag: i32,
    ) -> Result<usize, NativeMemoryError> {
        let mapping = NativeMapping::map_anonymous(
            operation,
            len,
            prot,
            fixed_at,
            label,
            exclusive_map_flag,
        )?;
        self.acquire(mapping)
    }

    pub fn map_optional_fixed(
        &mut self,
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        expected: u64,
        label: &'static str,
        exclusive_map_flag: i32,
    ) -> Result<Option<usize>, NativeMemoryError> {
        NativeMapping::map_optional_fixed(
            operation,
            len,
            prot,
            expected,
            label,
            exclusive_map_flag,
        )?
        .map(|mapping| self.acquire(mapping))
        .transpose()
    }

    pub fn mapping(&self, index: usize) -> &NativeMapping {
        &self.mappings[index]
    }

    pub fn teardown_mapping(&mut self, index: usize) -> Result<(), NativeMemoryError> {
        self.mappings[index].teardown()?;
        self.mappings.remove(index);
        Ok(())
    }

    pub fn commit(mut self) -> Vec<NativeMapping> {
        std::mem::take(&mut self.mappings)
    }

    pub fn commit_to_vma(mut self) {
        for mapping in &mut self.mappings {
            mapping.relinquish_to_vma();
        }
    }

    /// Tear down every acquired mapping and report any teardown failures as
    /// plain strings, without bundling them into any particular error type.
    /// Every caller — this module's own [`Self::rollback`] and the
    /// `carrick-runtime` call sites that still construct their own primary
    /// error (`RuntimeError`) before this extraction — combines these with
    /// its own primary failure using its own error vocabulary. This keeps the
    /// transaction itself independent of which vocabulary the caller uses,
    /// so a caller's primary error is folded in (or passed through verbatim
    /// when nothing failed to roll back) without a lossy Display round-trip
    /// through a foreign error type.
    pub fn rollback_teardown_errors(self) -> Vec<String> {
        let mut rollback_errors = teardown_native_mappings_collect(&self.mappings);
        if !rollback_errors.is_empty() {
            // A one-shot host interruption or injected failure is reportable
            // only after ownership has actually been discharged. Retry every
            // still-live owner once; persistent failure reaches Drop and aborts
            // rather than returning with an ownerless mapping.
            let retry_errors = teardown_native_mappings_collect(&self.mappings);
            rollback_errors.extend(
                retry_errors
                    .into_iter()
                    .map(|error| format!("retry failed: {error}")),
            );
        }
        rollback_errors
    }

    pub fn rollback(self, primary: NativeMemoryError) -> NativeMemoryError {
        let label = self.label;
        let rollback_errors = self.rollback_teardown_errors();
        if rollback_errors.is_empty() {
            primary
        } else {
            NativeMemoryError::Unsupported(format!(
                "{primary}; {label} rollback failed: {}",
                rollback_errors.join("; ")
            ))
        }
    }
}

pub fn map_fixed_replacement(
    operation: NativeMappingOperation,
    address: u64,
    len: usize,
    prot: i32,
    label: &'static str,
) -> Result<(), NativeMemoryError> {
    // PT_LOAD pages intentionally replace bytes inside the reservation whose
    // sole owner remains the surrounding `NativeMapping`. `ReplaceOwned` never
    // consults the exclusive-map flag (see `map_prot_at`), so `0` here is
    // inert, not a silently-wrong Darwin default.
    let mapped = map_prot_at(
        operation,
        len,
        prot,
        Some(address),
        FixedRwReservation::ReplaceOwned,
        0,
    );
    if mapped.cast::<libc::c_void>() == libc::MAP_FAILED {
        return Err(NativeMemoryError::Unsupported(format!(
            "map native {label} at 0x{address:x} failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if mapped as u64 != address {
        let returned = mapped as u64;
        let misplaced = NativeMapping::claim(returned, len, operation, label);
        let cleanup = misplaced.teardown().err();
        let detail = cleanup
            .map(|error| format!("; wrong-address cleanup failed: {error}"))
            .unwrap_or_default();
        return Err(NativeMemoryError::Unsupported(format!(
            "map native {label} requested 0x{address:x} but returned 0x{returned:x}{detail}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::protections::{GuestMemoryFault, GuestMemoryFaultKind};
    #[cfg(target_os = "freebsd")]
    use std::os::fd::AsRawFd;

    /// Test-only, no-op `ExecutableMutationAuthority`: every test in this
    /// module uses `IdentityGuestMemory::uncoordinated()`, whose
    /// `executable_epoch` is always `None`, so this trait's own method is
    /// never actually invoked — it exists only because `IdentityGuestMemory<A>`
    /// needs a concrete `A` to monomorphize against.
    struct TestMutationAuthority;

    impl ExecutableMutationAuthority for TestMutationAuthority {
        type Lease = ();
        type Error = std::convert::Infallible;

        fn begin_mutation(self: &Arc<Self>) -> Result<Self::Lease, Self::Error> {
            unreachable!("uncoordinated() never binds an executable_epoch")
        }
    }

    /// Serializes this module's fork-based tests against each other (they
    /// mutate the same process-global `IDENTITY_PROTECTIONS`/mapping state a
    /// forked child also observes) — mirrors `native_freebsd.rs`'s own
    /// `lock_native_mapping_tests` for the tests that moved out of it. Its
    /// only caller is FreeBSD-gated (see the module doc on why the two
    /// truncated-shared-mapping/fork-repoint tests pin FreeBSD-specific host
    /// kernel behavior), so this is too on non-FreeBSD hosts rather than
    /// carrying a blanket `allow(dead_code)`.
    #[cfg(target_os = "freebsd")]
    static NATIVE_MAPPING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "freebsd")]
    fn lock_native_mapping_tests() -> std::sync::MutexGuard<'static, ()> {
        NATIVE_MAPPING_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn accepts_low_canonical_guest_ranges() {
        assert!(identity_raw_range_valid(0x1_0000, 1));
        assert!(identity_raw_range_valid((1 << 47) - 4096, 4096));
    }

    #[test]
    fn rejects_null_wrapping_and_noncanonical_ranges() {
        assert!(!identity_raw_range_valid(0, 1));
        assert!(!identity_raw_range_valid(0x1000, 1));
        assert!(!identity_raw_range_valid(u64::MAX - 1, 4));
        assert!(!identity_raw_range_valid(1 << 47, 1));
        assert!(!identity_raw_range_valid((1 << 47) - 1, 2));
    }

    #[test]
    fn zero_length_access_never_forms_a_pointer() {
        assert!(identity_raw_range_valid(0, 0));
        assert!(identity_raw_range_valid(u64::MAX, 0));
    }

    #[test]
    fn exact_checked_reader_uses_direct_materialized_copy_and_validates_before_mutation() {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        let source = [0x11, 0x22, 0x33, 0x44];
        let mut snapshot = vec![0u8; 8192];
        snapshot[4094..4098].copy_from_slice(&source);
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            8192,
            false,
            false,
            carrick_guest_mem::MappingSharing::Shared,
        );
        let mut memory = IdentityGuestMemory::<TestMutationAuthority>::uncoordinated();
        memory
            .repoint_private(address, 0, 8192, &snapshot)
            .expect("physically materialize checked-read backing");
        memory.set_mapping_protection_and_sharing(
            address,
            8192,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );

        let mut destination = [0u8; 4];
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyin_operation_census();
        identity_checked_read_exact(carrick_guest_mem::GuestVa(address + 4094), &mut destination)
            .expect("exact cross-page read");
        assert_eq!(destination, source);
        assert_eq!(identity_kernel_copy_pipe_census(), 0);
        assert_eq!(
            identity_kernel_copyin_operation_census(),
            0,
            "anonymous checked read must not create or operate a private pipe"
        );

        IDENTITY_PROTECTIONS.set_no_access(address + 4096, 4096, true);
        destination.fill(0x7e);
        let denied = identity_checked_read_exact(
            carrick_guest_mem::GuestVa(address + 4094),
            &mut destination,
        );
        assert_eq!(
            denied,
            Err(IdentityCheckedReadError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::AccessDenied,
            }))
        );
        assert_eq!(
            destination, [0x7e; 4],
            "complete-range ACCERR validation must precede destination mutation"
        );
        IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, true);
        assert_eq!(
            identity_checked_read_exact(
                carrick_guest_mem::GuestVa(address + 4096),
                &mut destination[..1],
            ),
            Err(IdentityCheckedReadError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + 4096),
            }),
            "the same AccessDenied registry fault is BUS_ADRERR only for a published EOF tail"
        );
        IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, false);
        IDENTITY_PROTECTIONS.set_no_access(address + 4096, 4096, false);

        IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, true);
        destination.fill(0x5d);
        let unmapped = identity_checked_read_exact(
            carrick_guest_mem::GuestVa(address + 4094),
            &mut destination,
        );
        assert_eq!(
            unmapped,
            Err(IdentityCheckedReadError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::Unmapped,
            }))
        );
        assert_eq!(
            destination, [0x5d; 4],
            "complete-range MAPERR validation must precede destination mutation"
        );
        IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, false);

        let mut empty = [];
        identity_checked_read_exact(carrick_guest_mem::GuestVa(0), &mut empty)
            .expect("zero-length read never forms a host pointer");
        assert_eq!(identity_kernel_copy_pipe_census(), 0);
        assert_eq!(identity_kernel_copyin_operation_census(), 0);
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, 8192, true);
            assert_eq!(unsafe { libc::munmap(mapping, 8192) }, 0);
        }
    }

    #[test]
    fn exact_checked_writer_uses_direct_materialized_copy_and_validates_before_mutation() {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            8192,
            false,
            false,
            carrick_guest_mem::MappingSharing::Shared,
        );
        let mut memory = IdentityGuestMemory::<TestMutationAuthority>::uncoordinated();
        memory
            .repoint_private(address, 0, 8192, &[0; 8192])
            .expect("physically materialize checked-write backing");
        memory.set_mapping_protection_and_sharing(
            address,
            8192,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );
        let source = [0x19, 0x2a, 0x3b, 0x4c];

        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyout_operation_census();
        identity_checked_write_exact(&memory, carrick_guest_mem::GuestVa(address + 4094), &source)
            .expect("exact cross-page private write");
        // SAFETY: the test owns both mapped pages and the checked write succeeded.
        let written = unsafe { std::slice::from_raw_parts((address + 4094) as *const u8, 4) };
        assert_eq!(written, source);
        assert_eq!(identity_kernel_copy_pipe_census(), 0);
        assert_eq!(
            identity_kernel_copyout_operation_census(),
            0,
            "anonymous checked write must not create or operate a private pipe"
        );

        let original = [0x61, 0x72, 0x83, 0x94];
        // SAFETY: the test owns this writable cross-page destination.
        unsafe { std::ptr::copy_nonoverlapping(original.as_ptr(), (address + 4094) as *mut u8, 4) };
        IDENTITY_PROTECTIONS.set_no_write(address + 4096, 4096, true);
        assert_eq!(
            identity_checked_write_exact(
                &memory,
                carrick_guest_mem::GuestVa(address + 4094),
                &source,
            ),
            Err(IdentityCheckedWriteError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::AccessDenied,
            }))
        );
        // SAFETY: complete-range validation must leave this owned mapping live.
        assert_eq!(
            unsafe { std::slice::from_raw_parts((address + 4094) as *const u8, 4) },
            original,
            "complete-range ACCERR validation must precede guest mutation"
        );
        IDENTITY_PROTECTIONS.set_no_access(address + 4096, 4096, true);
        IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, true);
        assert_eq!(
            identity_checked_write_exact(
                &memory,
                carrick_guest_mem::GuestVa(address + 4096),
                &source[..1],
            ),
            Err(IdentityCheckedWriteError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + 4096),
            }),
            "private EOF AccessDenied must remain a typed BUS_ADRERR write"
        );
        IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, false);
        IDENTITY_PROTECTIONS.set_no_access(address + 4096, 4096, false);
        IDENTITY_PROTECTIONS.set_no_write(address + 4096, 4096, false);

        IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, true);
        assert_eq!(
            identity_checked_write_exact(
                &memory,
                carrick_guest_mem::GuestVa(address + 4094),
                &source,
            ),
            Err(IdentityCheckedWriteError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::Unmapped,
            }))
        );
        // SAFETY: metadata-only test hole leaves the host mapping readable.
        assert_eq!(
            unsafe { std::slice::from_raw_parts((address + 4094) as *const u8, 4) },
            original,
            "complete-range MAPERR validation must precede guest mutation"
        );
        IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, false);

        identity_checked_write_exact(&memory, carrick_guest_mem::GuestVa(0), &[])
            .expect("zero-length write never forms a host pointer");
        assert_eq!(identity_kernel_copy_pipe_census(), 0);
        assert_eq!(identity_kernel_copyout_operation_census(), 0);
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, 8192, true);
            assert_eq!(unsafe { libc::munmap(mapping, 8192) }, 0);
        }
    }

    // FreeBSD-only: pins real host-kernel fork+MAP_FIXED-replacement
    // coherence behavior, not a portability bug in `repoint_private` itself
    // (the mmap/fork syscalls it uses exist identically on Darwin). Darwin's
    // xnu returns EINVAL for this exact MAP_FIXED replacement immediately
    // after `fork`; `IdentityGuestMemory` is only ever instantiated by the
    // FreeBSD/x86_64 native lane in production, so — like the cflow
    // truncated-mapping test in `carrick-dsr-x86` — this is the "moved code
    // compiles everywhere, this one assertion is host-specific" case the
    // parent plan anticipated.
    #[test]
    #[cfg(target_os = "freebsd")]
    fn middle_private_repoint_isolates_only_replaced_page_across_fork() {
        const PAGE: usize = 4096;
        const LEN: usize = 3 * PAGE;
        let _test_guard = lock_native_mapping_tests();
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        unsafe {
            std::ptr::write_bytes(address as *mut u8, 0x11, PAGE);
            std::ptr::write_bytes((address as usize + PAGE) as *mut u8, 0x22, PAGE);
            std::ptr::write_bytes((address as usize + (2 * PAGE)) as *mut u8, 0x33, PAGE);
        }
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            LEN,
            false,
            false,
            carrick_guest_mem::MappingSharing::Shared,
        );

        let mut release = [-1; 2];
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork partial replacement sibling failed");
        if child == 0 {
            unsafe { libc::close(release[1]) };
            let mut byte = 0u8;
            if unsafe { libc::read(release[0], (&mut byte as *mut u8).cast(), 1) } != 1 {
                unsafe { libc::_exit(91) };
            }
            unsafe {
                if (address as *const u8).read_volatile() != 0x11
                    || ((address as usize + PAGE) as *const u8).read_volatile() != 0x22
                    || ((address as usize + (2 * PAGE)) as *const u8).read_volatile() != 0x33
                {
                    libc::_exit(92);
                }
                (address as *mut u8).write_volatile(0x55);
                ((address as usize + PAGE) as *mut u8).write_volatile(0x44);
                ((address as usize + (2 * PAGE)) as *mut u8).write_volatile(0x66);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(release[0]) };

        let mut memory = IdentityGuestMemory::<TestMutationAuthority>::uncoordinated();
        memory
            .repoint_private(address + PAGE as u64, 0, PAGE, &[0x99; PAGE])
            .expect("replace only middle shared page");
        memory.set_mapping_protection_and_sharing(
            address + PAGE as u64,
            PAGE,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );
        assert_eq!(
            unsafe { libc::write(release[1], [1u8].as_ptr().cast(), 1) },
            1
        );
        unsafe { libc::close(release[1]) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x55);
        assert_eq!(
            unsafe { ((address as usize + PAGE) as *const u8).read_volatile() },
            0x99,
            "child must retain the old shared middle page"
        );
        assert_eq!(
            unsafe { ((address as usize + (2 * PAGE)) as *const u8).read_volatile() },
            0x66
        );
        assert!(IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, 1));
        assert!(!IDENTITY_PROTECTIONS.range_mutable_shared_backing(address + PAGE as u64, 1));
        assert!(IDENTITY_PROTECTIONS.range_mutable_shared_backing(address + (2 * PAGE) as u64, 1));

        memory
            .unmap_range(address, LEN)
            .expect("retire split replacement mapping");
    }

    // FreeBSD-only: same class as `cflow_write_contains_truncated_shared_mapping_bus_faults`
    // in `carrick-dsr-x86` — the kernel-copyin containment trick's EFAULT on a
    // truncated MAP_SHARED file mapping is a real FreeBSD-specific kernel
    // behavior, not a bug in the (identically-available) syscalls it uses.
    #[test]
    #[cfg(target_os = "freebsd")]
    fn exact_checked_reader_contains_readable_file_mapping_bus_faults() {
        const LEN: usize = 8192;
        const FILE_END: u64 = 4096;
        const HEADER_OFFSET: u64 = FILE_END + 512;

        let file = tempfile::tempfile().expect("temporary file backing");
        file.set_len(LEN as u64).expect("size file backing");
        // SAFETY: this test owns the file and releases the complete mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address,
                LEN,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
        }

        let valid_tail = [0x91u8, 0xa2];
        // SAFETY: the temporary file is live and the write stays inside its
        // first page, which remains backed after the truncation below.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    file.as_raw_fd(),
                    valid_tail.as_ptr().cast(),
                    valid_tail.len(),
                    (FILE_END - valid_tail.len() as u64) as libc::off_t,
                )
            },
            valid_tail.len() as isize
        );
        file.set_len(FILE_END)
            .expect("truncate after installing readable shared mapping");

        let mut crossing = [0u8; 4];
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_read_exact(
                carrick_guest_mem::GuestVa(address + FILE_END - 2),
                &mut crossing,
            ),
            Err(IdentityCheckedReadError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + FILE_END),
            }),
            "a valid page tail followed by truncated backing must fault at the next page boundary"
        );
        assert_eq!(&crossing[..2], &valid_tail);
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(
            identity_kernel_copyin_operation_census() > 0,
            "truncatable shared reads must retain kernel-contained copyin"
        );

        let mut destination = [0u8; 64];
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_read_exact(
                carrick_guest_mem::GuestVa(address + HEADER_OFFSET),
                &mut destination,
            ),
            Err(IdentityCheckedReadError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + HEADER_OFFSET),
            }),
            "kernel copyin must contain host SIGBUS and name the exact source range"
        );
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(identity_kernel_copyin_operation_census() > 0);

        file.set_len(LEN as u64).expect("repair file backing");
        let expected = [0x5au8; 64];
        // SAFETY: expected is a valid local buffer and the repaired file range
        // is wholly within the now-extended backing.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    file.as_raw_fd(),
                    expected.as_ptr().cast(),
                    expected.len(),
                    HEADER_OFFSET as libc::off_t,
                )
            },
            expected.len() as isize
        );
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyin_operation_census();
        identity_checked_read_exact(
            carrick_guest_mem::GuestVa(address + HEADER_OFFSET),
            &mut destination,
        )
        .expect("repaired file-backed source must copy exactly");
        assert_eq!(destination, expected);
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(identity_kernel_copyin_operation_census() > 0);

        let mut oversized = vec![0u8; IDENTITY_KERNEL_COPY_PIPE_BOUND + 1];
        assert!(matches!(
            identity_checked_read_exact(
                carrick_guest_mem::GuestVa(address + FILE_END),
                &mut oversized,
            ),
            Err(IdentityCheckedReadError::Backend { detail, .. })
                if detail.contains("exceeds") && detail.contains("kernel-copy bound")
        ));

        {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
            // SAFETY: this test owns the complete mapping.
            assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
        }
    }

    #[test]
    fn direct_host_pointer_validation_does_not_make_pages_resident() {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let memory = IdentityGuestMemory::<TestMutationAuthority>::uncoordinated();
        let start = carrick_guest_mem::GuestVa(page as u64);
        assert_eq!(memory.resident_pages(start, 2, 4096), Some(vec![0, 0]));
        // Host backing alone is insufficient: the syscall pointer gate follows
        // the complete guest VMA registry, so validation needs no host mincore.
        IDENTITY_PROTECTIONS.set_unmapped(page as u64, 8192, true);
        assert!(memory.host_ptr_for_read(page as u64, 8192).is_none());
        IDENTITY_PROTECTIONS.set_mapping_protection(page as u64, 8192, false, false);
        assert!(memory.host_ptr_for_read(page as u64, 8192).is_some());
        assert_eq!(memory.resident_pages(start, 2, 4096), Some(vec![0, 0]));
        unsafe { (page as *mut u8).write_volatile(0) };
        assert_eq!(memory.resident_pages(start, 2, 4096), Some(vec![1, 0]));
        unsafe { libc::munmap(page, 8192) };
    }
}

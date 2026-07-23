//! The FreeBSD/amd64 native (DSR) execution driver.
//!
//! This is the x86 sibling of the aarch64/Darwin native driver
//! (`native_darwin.rs`): it EXECUTES a static Linux x86_64 ELF as host-native
//! code through the `carrick-dsr-x86` gateway and services its Linux syscalls
//! through the SHARED, backend-neutral [`SyscallDispatcher`] — the exact
//! dispatcher the bhyve/KVM/NVMM x86 VMM lanes feed. The lane reuses, rather
//! than reimplements, the syscall machinery:
//!
//! - guest memory is an IDENTITY map (guest VA == host VA), so
//!   [`IdentityGuestMemory`] satisfies [`GuestMemory`] with plain host
//!   reads/writes;
//! - a `syscall` gateway exit is adapted into the SAME
//!   [`carrick_hal::RawSyscall`] the VMM engine produces, via
//!   [`X8664GuestArch::normalize_syscall`] (rax + rdi/rsi/rdx/r10/r8/r9,
//!   fork/vfork/poll/select desugaring, arch_prctl split);
//! - `arch_prctl(ARCH_SET_FS)` sets the gateway's `guest_fsbase` (the x86
//!   analog of the aarch64 TPIDR handling) instead of touching VMM state.
//!
//! Scope (first M2-runtime rung): a SINGLE-THREADED static binary. Threads,
//! fork/clone, the blocking-wait outcomes (`WaitOnFds`/…), and the full
//! signal machinery are the next rungs; this driver services the
//! straight-line + returned/errno/exit dispatch outcomes and surfaces the
//! rest as a typed error rather than guessing. Guest faults become typed
//! `Signal` gateway exits via `carrick-native-freebsd`'s shim.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use std::convert::Infallible;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use carrick_dsr::host::{JitRegion, NativeHostJit};
use carrick_dsr_x86::block::{X86BlockPlanError, X86Exit};
use carrick_dsr_x86::decode::{X86InstClass, classify};
use carrick_dsr_x86::gateway::{
    CTX_FAULT_RECORD, CTX_KICK_RESTORE_RCX, CTX_SCRATCH2, kick_stub_addr, reg, signal_stub_addr,
};
#[cfg(test)]
use carrick_dsr_x86::plan_block;
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86FxStateError, X86FxStatePlan, X86GuestGsBase,
    X86IdentityStamp, X86IndirectCacheEntry, X86LegacyX87Error, X86LegacyX87Plan,
    X86UcontextSnapshot, X86X87ExceptionKind, X86XstateMemoryReader, X86XstateMemoryWriter,
    X86XstateRestoreError, X86XstateRestorePlan, X86XstateSaveError, X86XstateSavePlan, cflow,
    emit::{ScratchRestore, emit_block_linked},
    plan_block_with_reader,
};
use carrick_guest_mem::{
    GuestMemory, GuestVa, MemoryError, RepointPrivateError, X8664SyscallFrame,
};
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_hal::{GuestArch, Reg, RegAccess};
use carrick_native_freebsd::{FreebsdHostJit, fault};
use goblin::elf::Elf;
use goblin::elf::header::{EM_X86_64, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};

use carrick_mem::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, mmap_arena_size};

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{DispatchOutcome, HostAliasOwnedFd, SyscallDispatcher, SyscallRequest};
use crate::run_result::{RunResult, RuntimeError};

/// The guest brk-heap and mmap arenas, reserved as real host backing at the
/// dispatcher's fixed layout addresses (`MemoryLayout::hvf_default`: heap at
/// 384-ish GiB, mmap arena at 384 GiB). The dispatcher's `brk`/`mmap`
/// handlers hand out addresses INSIDE these arenas and expect the
/// `GuestMemory` to have backing there (`brk` only moves a pointer; `mmap`
/// zeroes the new region THROUGH the memory). In the identity model that
/// backing is real host pages at the same VA. FreeBSD overcommits anonymous
/// RW maps (pages commit on first touch), so reserving the full 32 GiB mmap
/// arena is cheap. A guest `mmap(PROT_NONE)` guard page reads back as zero
/// rather than faulting — a fidelity gap, not a crash; enforcing guest-visible
/// per-page protection is a later rung.
struct GuestArenas {
    mappings: Vec<NativeMapping>,
}

impl GuestArenas {
    fn reserve() -> Result<Self, RuntimeError> {
        let heap_len = LINUX_HEAP_SIZE as usize;
        let mmap_len = mmap_arena_size() as usize;
        let mut candidate = NativeMappingTransaction::new("guest arena candidate");
        let result = (|| {
            let heap = reserve_fixed_rw(
                LINUX_HEAP_BASE,
                heap_len,
                FixedRwReservation::Exclusive,
                "guest heap arena",
            )?;
            candidate.acquire(NativeMapping::claim(
                heap,
                heap_len,
                NativeMappingOperation::General,
                "guest heap arena",
            ))?;
            let mmap = reserve_fixed_rw(
                LINUX_MMAP_BASE,
                mmap_len,
                FixedRwReservation::Exclusive,
                "guest mmap arena",
            )?;
            candidate.acquire(NativeMapping::claim(
                mmap,
                mmap_len,
                NativeMappingOperation::General,
                "guest mmap arena",
            ))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Self {
                mappings: candidate.commit(),
            }),
            Err(error) => Err(candidate.rollback(error)),
        }
    }

    fn teardown(&self) -> Result<(), RuntimeError> {
        teardown_native_mappings(&self.mappings)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedRwReservation {
    /// Initial ownership acquisition: a collision must fail without replacing
    /// even one byte of the pre-existing host mapping.
    Exclusive,
    /// Exec retains the original arena owner while replacing its backing.
    ReplaceOwned,
}

/// Map `[base, base+len)` as anonymous RW at exactly `base`.
///
/// Initial ownership uses FreeBSD `MAP_FIXED|MAP_EXCL`, while exec's deliberate
/// replacement of an arena it already owns uses plain `MAP_FIXED`. A successful
/// wrong-address result is still owned and its cleanup failure is part of the
/// returned diagnostic.
fn reserve_fixed_rw(
    base: u64,
    len: usize,
    reservation: FixedRwReservation,
    label: &'static str,
) -> Result<u64, RuntimeError> {
    let p = map_prot_at(
        NativeMappingOperation::General,
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        Some(base),
        reservation,
    );
    if p == libc::MAP_FAILED.cast() {
        return Err(RuntimeError::Unsupported(format!(
            "map fixed native {label} at 0x{base:x} for {len} bytes ({reservation:?}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if p as u64 != base {
        let returned = p as u64;
        let misplaced = NativeMapping::claim(returned, len, NativeMappingOperation::General, label);
        let cleanup = misplaced.teardown().err();
        let detail = cleanup
            .map(|error| format!("; wrong-address cleanup failed: {error}"))
            .unwrap_or_default();
        return Err(RuntimeError::Unsupported(format!(
            "map fixed native {label} requested 0x{base:x} but returned 0x{returned:x}{detail}"
        )));
    }
    Ok(p as u64)
}

fn remap_exec_arenas() -> Result<(), RuntimeError> {
    for (base, len, name) in [
        (LINUX_HEAP_BASE, LINUX_HEAP_SIZE as usize, "heap"),
        (LINUX_MMAP_BASE, mmap_arena_size() as usize, "mmap"),
    ] {
        reserve_fixed_rw(
            base,
            len,
            FixedRwReservation::ReplaceOwned,
            match name {
                "heap" => "exec guest heap arena",
                _ => "exec guest mmap arena",
            },
        )?;
    }
    Ok(())
}

/// `ARCH_SET_FS` (arch_prctl(2)) — the musl/glibc TLS thread-pointer set.
const ARCH_SET_FS: u64 = 0x1002;
/// `ARCH_SET_GS`.
const ARCH_SET_GS: u64 = 0x1001;
/// `ARCH_GET_FS`.
const ARCH_GET_FS: u64 = 0x1003;
/// `ARCH_GET_GS`.
const ARCH_GET_GS: u64 = 0x1004;
/// `EINVAL`, as a negated Linux errno return.
const NEG_EINVAL: i64 = -22;

/// A guest address space where guest VA == host VA: `GuestMemory` reads and
/// writes are plain host memory accesses at the guest address. The native
/// model maps the guest image and every guest mapping into THIS process's
/// address space, so no translation is needed. Out-of-bounds/unmapped guest
/// pointers are not gated here — a bad pointer faults, and the fault shim
/// turns an in-JIT fault into a typed Signal exit (a syscall-path bad pointer
/// is a genuine EFAULT the handlers surface).
#[derive(Clone, Default)]
struct IdentityGuestMemory {
    /// The active run's executable-mutation authority. Loader-only memory used
    /// before a [`SharedRun`] exists intentionally carries `None`; every live
    /// main/clone/fork thread binds the coordinator owned by its active run.
    executable_epoch: Option<Arc<ExecutableEpoch>>,
    /// The [`GuestMemory`] metadata setters predate fallible host mappings and
    /// therefore cannot return a [`MemoryError`]. Keep the first host-mapping
    /// failure typed until the surrounding native dispatch boundary consumes
    /// it; the failed range is simultaneously left fail-closed in the registry.
    mapping_failure: Option<carrick_guest_mem::MemoryError>,
}

impl IdentityGuestMemory {
    fn uncoordinated() -> Self {
        Self::default()
    }

    fn for_run(shared: &SharedRun) -> Self {
        Self {
            executable_epoch: Some(Arc::clone(&shared.executable_epoch)),
            mapping_failure: None,
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

    fn take_mapping_failure(&mut self) -> Option<carrick_guest_mem::MemoryError> {
        self.mapping_failure.take()
    }

    /// Drop the inherited Arc without touching its mutex. A fork child has no
    /// sibling JIT threads and may perform child-tid writes before the run loop
    /// builds its fresh SharedRun; those writes must not acquire the parent's
    /// possibly sibling-owned coordinator.
    fn abandon_inherited_epoch_after_fork(&mut self) {
        self.executable_epoch = None;
    }

    fn rebind_after_fork(&mut self, shared: &SharedRun) {
        self.executable_epoch = Some(Arc::clone(&shared.executable_epoch));
    }
}

/// Resolve a mapped vnode page to a process-independent futex waiter key using
/// FreeBSD's documented `kern.proc.vmmap` ABI. Linux keys a shared futex by its
/// backing object and byte offset, not by the caller's VA; after exec the same
/// checkpoint file is commonly remapped at a different address. `_umtx_op`
/// already uses that backing identity for the physical wait/wake. Carrick needs
/// the same identity for its fork-shared waiter-count side table so WAKE returns
/// Linux's count rather than a false zero.
fn freebsd_shared_waiter_key(address: usize) -> Option<usize> {
    let pid = unsafe { libc::getpid() };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_VMMAP, pid];
    let mut needed = 0usize;
    // SAFETY: first sysctl call requests the required buffer size only.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || needed < std::mem::size_of::<libc::kinfo_vmentry>()
    {
        return None;
    }
    let mut bytes = vec![0u8; needed];
    // SAFETY: `bytes` owns `needed` writable bytes and this is a read-only MIB.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    let mut cursor = 0usize;
    while cursor
        .checked_add(std::mem::size_of::<libc::kinfo_vmentry>())
        .is_some_and(|end| end <= needed)
    {
        // SAFETY: the bounds check above covers one complete ABI entry. Sysctl
        // entries need not be naturally aligned inside the byte buffer.
        let entry = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(cursor).cast::<libc::kinfo_vmentry>())
        };
        let entry_size = usize::try_from(entry.kve_structsize).ok()?;
        if entry_size == 0
            || cursor
                .checked_add(entry_size)
                .is_none_or(|end| end > needed)
        {
            break;
        }
        let address = address as u64;
        if entry.kve_start <= address && address < entry.kve_end && entry.kve_vn_fileid != 0 {
            let backing_offset = entry
                .kve_offset
                .checked_add(address.saturating_sub(entry.kve_start))?;
            // Stable 64-bit avalanche over vnode fsid/fileid + byte offset.
            let mut key = entry.kve_vn_fsid
                ^ entry.kve_vn_fileid.rotate_left(21)
                ^ backing_offset.rotate_left(42)
                ^ 0x9e37_79b9_7f4a_7c15;
            key ^= key >> 30;
            key = key.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            key ^= key >> 27;
            key = key.wrapping_mul(0x94d0_49bb_1331_11eb);
            key ^= key >> 31;
            return Some((key as usize) | 1);
        }
        cursor += entry_size;
    }
    None
}

const X86_64_USER_END_EXCLUSIVE: u64 = 1 << 47;
// Carrick exposes Linux's default `/proc/sys/vm/mmap_min_addr` (64 KiB);
// no guest mapping can legally back a syscall pointer below it.
const LINUX_MMAP_MIN_ADDR: u64 = 0x1_0000;

/// First byte outside Carrick's raw identity guest-pointer domain.
fn identity_raw_fault_address(address: u64, length: usize) -> Option<u64> {
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
fn identity_raw_range_valid(address: u64, length: usize) -> bool {
    identity_raw_fault_address(address, length).is_none()
}

#[cfg(test)]
mod identity_raw_range_tests {
    use super::{
        IDENTITY_PROTECTIONS, IdentityGuestMemory, PublishedFaultEntry, SharedWaitAssignment,
        X86GatewayX87Witness, calibrate_x86_vvar_clock, cflow_guest_memory_fault,
        cflow_memory_backend_error, cflow_raw_memory_fault, exclude_vfork_shared_ranges,
        freebsd_shared_waiter_key, host_clock_ns, identity_checked_fetch_x86_instruction,
        identity_checked_read_exact, identity_checked_write_exact,
        identity_kernel_copy_pipe_census, identity_kernel_copyin_operation_census,
        identity_kernel_copyout_operation_census, identity_raw_range_valid,
        init_shared_waiter_table, normalize_x86_gateway_x87_fip, parse_loadable_elf,
        recover_x86_fault_snapshot, reset_identity_kernel_copy_pipe_census,
        reset_identity_kernel_copyin_operation_census,
        reset_identity_kernel_copyout_operation_census, shared_futex_requeue_umtx,
        shared_futex_wait_umtx, shared_futex_wake_umtx, shared_waiter_slot,
        take_shared_wait_assignment, tsc_ns, wait_requeued_umtx,
    };
    use carrick_guest_mem::GuestMemory;
    use carrick_guest_mem::protections::{GuestMemoryFault, GuestMemoryFaultKind};
    use std::os::fd::AsRawFd;

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
    fn cflow_only_exposes_guest_access_failures_as_retryable_faults() {
        use carrick_dsr_x86::cflow::{CflowError, CflowMemoryAccess, CflowMemoryFaultKind};

        let address = 0x1234_5000;
        assert_eq!(
            cflow_guest_memory_fault(
                CflowMemoryAccess::Read,
                GuestMemoryFault {
                    address: carrick_guest_mem::GuestVa(address),
                    kind: GuestMemoryFaultKind::AccessDenied,
                },
            ),
            CflowError::MemoryRead {
                address,
                kind: CflowMemoryFaultKind::AccessDenied,
            }
        );
        assert_eq!(
            cflow_raw_memory_fault(CflowMemoryAccess::Read, (1 << 47) - 4, 8),
            Some(CflowError::MemoryRead {
                address: 1 << 47,
                kind: CflowMemoryFaultKind::Unmapped,
            }),
            "cross-boundary faults name the first inaccessible byte"
        );
        assert_eq!(
            cflow_memory_backend_error(
                CflowMemoryAccess::Write,
                address,
                carrick_guest_mem::MemoryError::HostMap("injected coordinator failure".into()),
            ),
            CflowError::MemoryBackend {
                access: CflowMemoryAccess::Write,
                address,
                detail: "host mapping operation failed: injected coordinator failure".into(),
            }
        );
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
        let mut memory = IdentityGuestMemory::uncoordinated();
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
            Err(super::IdentityCheckedReadError::Fault(GuestMemoryFault {
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
            Err(super::IdentityCheckedReadError::BusAddress {
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
            Err(super::IdentityCheckedReadError::Fault(GuestMemoryFault {
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
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
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
        let mut memory = IdentityGuestMemory::uncoordinated();
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
            Err(super::IdentityCheckedWriteError::Fault(GuestMemoryFault {
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
            Err(super::IdentityCheckedWriteError::BusAddress {
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
            Err(super::IdentityCheckedWriteError::Fault(GuestMemoryFault {
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
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, 8192, true);
            assert_eq!(unsafe { libc::munmap(mapping, 8192) }, 0);
        }
    }

    #[test]
    fn executable_private_repoint_isolates_fork_sibling_and_refreshes_direct_fetch() {
        let _test_guard = super::tests::lock_native_mapping_tests();
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        // SAFETY: the test owns this writable shared page.
        unsafe { (address as *mut u8).write(0x90) };
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            4096,
            false,
            true,
            carrick_guest_mem::MappingSharing::Shared,
        );
        IDENTITY_PROTECTIONS.set_executable(address, 4096, true);

        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address))
                .expect("fetch old shared instruction"),
            vec![0x90]
        );
        assert!(
            identity_kernel_copyin_operation_census() > 0,
            "live shared backing must not reach the direct fetch branch"
        );

        let epoch = super::ExecutableEpoch::new();
        let registration = epoch
            .register_current()
            .expect("register replacement owner");
        let generation = epoch.current_generation().expect("old code generation");
        let mut release = [-1; 2];
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork shared sibling failed");
        if child == 0 {
            unsafe { libc::close(release[1]) };
            let mut byte = 0u8;
            let read =
                unsafe { libc::read(release[0], (&mut byte as *mut u8).cast::<libc::c_void>(), 1) };
            if read != 1 {
                unsafe { libc::_exit(91) };
            }
            // This child retained the old physically shared object: it must not
            // observe the parent's replacement bytes, and the parent must not
            // observe this later executable mutation.
            unsafe {
                if (address as *const u8).read_volatile() != 0x90 {
                    libc::_exit(92);
                }
                (address as *mut u8).write_volatile(0xf4);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(release[0]) };

        let mut private_snapshot = vec![0u8; 4096];
        private_snapshot[..2].copy_from_slice(&[0xc3, 0x7a]);
        let mut memory = IdentityGuestMemory {
            executable_epoch: Some(std::sync::Arc::clone(&epoch)),
            mapping_failure: None,
        };
        memory
            .repoint_private(address, 0, 4096, &private_snapshot)
            .expect("replace shared object with private materialized snapshot");
        memory.set_mapping_protection_and_sharing(
            address,
            4096,
            false,
            true,
            carrick_guest_mem::MappingSharing::Private,
        );
        memory
            .protect_range(
                address,
                4096,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            )
            .expect("publish executable private replacement");
        let release_byte = [1u8];
        assert_eq!(
            unsafe {
                libc::write(
                    release[1],
                    release_byte.as_ptr().cast::<libc::c_void>(),
                    release_byte.len(),
                )
            },
            1
        );
        unsafe { libc::close(release[1]) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        // SAFETY: the parent still owns the replacement page, now host-readable.
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0xc3);
        assert!(
            !IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, 4096),
            "private provenance is published only for detached backing"
        );
        assert!(IDENTITY_PROTECTIONS.range_executable(address, 4096));
        assert!(!IDENTITY_PROTECTIONS.range_translation_requires_ephemeral(address, 4096));
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address))
                .expect("fetch detached private instruction"),
            vec![0xc3]
        );
        assert_eq!(
            identity_kernel_copyin_operation_census(),
            0,
            "only the physically materialized replacement may use direct fetch"
        );
        assert!(matches!(
            epoch
                .admit(&registration, generation)
                .expect("admit after executable replacement"),
            super::JitAdmission::Refresh(_)
        ));

        memory
            .unmap_range(address, 4096)
            .expect("retire private replacement");
    }

    #[test]
    fn middle_private_repoint_isolates_only_replaced_page_across_fork() {
        const PAGE: usize = 4096;
        const LEN: usize = 3 * PAGE;
        let _test_guard = super::tests::lock_native_mapping_tests();
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

        let mut memory = IdentityGuestMemory::uncoordinated();
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

    #[test]
    fn unflagged_private_overlay_futex_does_not_cross_wake_but_shared_does() {
        const PAGE: usize = 4096;
        const LEN: usize = 2 * PAGE;
        let _test_guard = super::tests::lock_native_mapping_tests();
        init_shared_waiter_table();
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
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            LEN,
            false,
            false,
            carrick_guest_mem::MappingSharing::Shared,
        );
        let memory = IdentityGuestMemory::uncoordinated();

        let wait_until_parked = |key: usize| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                if shared_waiter_slot(key)
                    .is_some_and(|slot| slot.count.load(std::sync::atomic::Ordering::SeqCst) != 0)
                {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "fork child never parked on shared futex"
                );
                std::thread::yield_now();
            }
        };

        let shared_location = memory
            .shared_futex_location(address)
            .expect("genuine shared futex location");
        let shared_child = unsafe { libc::fork() };
        assert!(shared_child >= 0, "fork shared futex waiter failed");
        if shared_child == 0 {
            let child_memory = IdentityGuestMemory::uncoordinated();
            let Some(location) = child_memory.shared_futex_location(address) else {
                unsafe { libc::_exit(91) };
            };
            let result = shared_futex_wait_umtx(
                location.wait_addr().raw(),
                location.waiter_key(),
                0,
                Some(std::time::Duration::from_secs(2)),
                &|| false,
            );
            unsafe { libc::_exit(i32::from(result != 0)) };
        }
        wait_until_parked(shared_location.waiter_key());
        assert_eq!(
            shared_futex_wake_umtx(
                shared_location.wait_addr().raw(),
                shared_location.waiter_key(),
                1,
            ),
            1
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(shared_child, &mut status, 0) },
            shared_child
        );
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

        let private_address = address + PAGE as u64;
        let old_shared_location = memory
            .shared_futex_location(private_address)
            .expect("pre-overlay shared futex location");
        let private_child = unsafe { libc::fork() };
        assert!(private_child >= 0, "fork private-overlay waiter failed");
        if private_child == 0 {
            let result = shared_futex_wait_umtx(
                old_shared_location.wait_addr().raw(),
                old_shared_location.waiter_key(),
                0,
                Some(std::time::Duration::from_millis(300)),
                &|| false,
            );
            unsafe {
                libc::_exit(i32::from(
                    result != crate::linux_abi::LINUX_ETIMEDOUT.guest_retval(),
                ))
            };
        }
        wait_until_parked(old_shared_location.waiter_key());
        let mut parent_memory = IdentityGuestMemory::uncoordinated();
        parent_memory
            .repoint_private(private_address, 0, PAGE, &[0; PAGE])
            .expect("replace same VA with private backing");
        assert_eq!(
            parent_memory.shared_futex_location(private_address),
            None,
            "omitting FUTEX_PRIVATE_FLAG must not override private VMA provenance"
        );
        // Even an explicit host shared-style wake at the same VA now addresses
        // the parent's detached private VM object and cannot release the child
        // still parked on the inherited shared object.
        unsafe {
            libc::syscall(
                super::SYS_UMTX_OP,
                private_address as *mut libc::c_void,
                super::UMTX_OP_WAKE,
                1 as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        assert_eq!(
            unsafe { libc::waitpid(private_child, &mut status, 0) },
            private_child
        );
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

        parent_memory
            .unmap_range(address, LEN)
            .expect("retire futex provenance test mapping");
    }

    #[test]
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
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
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
            Err(super::IdentityCheckedReadError::BusAddress {
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
            Err(super::IdentityCheckedReadError::BusAddress {
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

        let mut oversized = vec![0u8; super::IDENTITY_KERNEL_COPY_PIPE_BOUND + 1];
        assert!(matches!(
            identity_checked_read_exact(
                carrick_guest_mem::GuestVa(address + FILE_END),
                &mut oversized,
            ),
            Err(super::IdentityCheckedReadError::Backend { detail, .. })
                if detail.contains("exceeds") && detail.contains("kernel-copy bound")
        ));

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
            // SAFETY: this test owns the complete mapping.
            assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
        }
    }

    #[test]
    fn typed_x86_fetch_faults_at_cross_page_execute_boundary_and_retries() {
        const LEN: usize = 8192;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        // SAFETY: this test owns both mapped pages.
        unsafe {
            (mapping as *mut u8).add(4095).write(0x66);
            (mapping as *mut u8).add(4096).write(0x90);
        }
        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection(address, LEN, false, false);
            IDENTITY_PROTECTIONS.set_executable(address, 4096, true);
        }

        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address + 4095)),
            Err(super::IdentityCheckedReadError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::AccessDenied,
            })),
            "the continuation byte, not the instruction PC, carries SEGV_ACCERR"
        );
        assert_eq!(
            identity_kernel_copyin_operation_census(),
            0,
            "private identity fetch must not enter the pipe copy path"
        );

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, true);
        }
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address + 4095)),
            Err(super::IdentityCheckedReadError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + 4096),
            }),
            "an executable private EOF continuation is BUS_ADRERR, not ordinary ACCERR"
        );

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_bus_fault(address + 4096, 4096, false);
            IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, true);
        }
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address + 4095)),
            Err(super::IdentityCheckedReadError::Fault(GuestMemoryFault {
                address: carrick_guest_mem::GuestVa(address + 4096),
                kind: GuestMemoryFaultKind::Unmapped,
            })),
            "a truncated direct fetch reports SEGV_MAPERR at the first hole byte"
        );
        assert_eq!(identity_kernel_copyin_operation_census(), 0);

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address + 4096, 4096, false);
            IDENTITY_PROTECTIONS.set_executable(address + 4096, 1, true);
        }
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address + 4095))
                .expect("repaired executable continuation retries exactly"),
            vec![0x66, 0x90]
        );
        assert_eq!(identity_kernel_copyin_operation_census(), 0);

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_executable(address + 4096, 1, false);
        }
        // SAFETY: this test still owns the final byte of the first page.
        unsafe { (mapping as *mut u8).add(4095).write(0x90) };
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(address + 4095))
                .expect("a complete one-byte instruction never overfetches"),
            vec![0x90],
            "the direct-copy result contains only the decoded instruction"
        );
        assert_eq!(identity_kernel_copyin_operation_census(), 0);

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
            // SAFETY: this test owns the complete mapping.
            assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
        }
    }

    #[test]
    fn typed_x86_fetch_contains_truncated_executable_backing_and_retries() {
        const LEN: usize = 8192;
        const FILE_END: u64 = 4096;
        let file = tempfile::tempfile().expect("temporary executable backing");
        file.set_len(LEN as u64).expect("size executable backing");
        let instruction = [0x66u8, 0x90];
        assert_eq!(
            unsafe {
                libc::pwrite(
                    file.as_raw_fd(),
                    instruction.as_ptr().cast(),
                    instruction.len(),
                    (FILE_END - 1) as libc::off_t,
                )
            },
            instruction.len() as isize
        );
        // SAFETY: this test owns the shared file mapping and releases it below.
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
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address,
                LEN,
                false,
                true,
                carrick_guest_mem::MappingSharing::Shared,
            );
            IDENTITY_PROTECTIONS.set_executable(address, LEN, true);
        }
        file.set_len(FILE_END)
            .expect("truncate executable backing at the page boundary");

        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(
                address + FILE_END - 1,
            )),
            Err(super::IdentityCheckedReadError::BusAddress {
                address: carrick_guest_mem::GuestVa(address + FILE_END),
            }),
            "FreeBSD SIGBUS must remain a typed BUS_ADRERR at the continuation byte"
        );
        assert!(
            identity_kernel_copyin_operation_census() > 0,
            "mutable shared fetch must retain kernel-contained copyin"
        );

        file.set_len(LEN as u64).expect("repair executable backing");
        assert_eq!(
            unsafe {
                libc::pwrite(
                    file.as_raw_fd(),
                    instruction[1..].as_ptr().cast(),
                    1,
                    FILE_END as libc::off_t,
                )
            },
            1
        );
        reset_identity_kernel_copyin_operation_census();
        assert_eq!(
            identity_checked_fetch_x86_instruction(carrick_guest_mem::GuestVa(
                address + FILE_END - 1,
            ))
            .expect("repaired executable backing retries exactly"),
            instruction
        );
        assert!(identity_kernel_copyin_operation_census() > 0);

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
            // SAFETY: this test owns the complete mapping.
            assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
        }
    }

    #[test]
    fn cflow_write_contains_truncated_shared_mapping_bus_faults() {
        use carrick_dsr_x86::cflow::{CflowError, CflowMemoryFaultKind, ControlFlowMemory};

        const LEN: usize = 8192;
        const FILE_END: u64 = 4096;
        let file = tempfile::tempfile().expect("temporary file backing");
        file.set_len(LEN as u64).expect("size file backing");
        // SAFETY: this test owns the file and complete shared mapping.
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
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address,
                LEN,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
        }
        file.set_len(FILE_END)
            .expect("truncate writable shared mapping");

        let value = 0x8877_6655_4433_2211u64;
        let mut memory = IdentityGuestMemory::uncoordinated();
        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_no_access(address + FILE_END, 4096, true);
        }
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::AccessDenied,
            }),
            "registry ACCERR must take precedence over truncated backing"
        );
        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_no_access(address + FILE_END, 4096, false);
            IDENTITY_PROTECTIONS.set_unmapped(address + FILE_END, 4096, true);
        }
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::Unmapped,
            }),
            "registry MAPERR must take precedence over truncated backing"
        );
        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
            IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
                address + FILE_END,
                4096,
                false,
                false,
                carrick_guest_mem::MappingSharing::Shared,
            );
        }
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyout_operation_census();
        assert_eq!(
            memory.write_u64(address + FILE_END, value),
            Err(CflowError::MemoryWrite {
                address: address + FILE_END,
                kind: CflowMemoryFaultKind::BusAddress,
            }),
            "kernel copyout must contain host SIGBUS and keep the cflow write retryable"
        );
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(
            identity_kernel_copyout_operation_census() > 0,
            "truncatable shared writes must retain kernel-contained copyout"
        );

        file.set_len(LEN as u64).expect("repair file backing");
        reset_identity_kernel_copy_pipe_census();
        reset_identity_kernel_copyout_operation_census();
        memory
            .write_u64(address + FILE_END, value)
            .expect("repaired shared stack slot accepts the retried push");
        assert!(identity_kernel_copy_pipe_census() > 0);
        assert!(identity_kernel_copyout_operation_census() > 0);
        let mut found = [0u8; 8];
        // SAFETY: `found` is writable and the repaired file range is live.
        assert_eq!(
            unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    found.as_mut_ptr().cast(),
                    found.len(),
                    FILE_END as libc::off_t,
                )
            },
            found.len() as isize
        );
        assert_eq!(found, value.to_le_bytes());

        {
            let _mapping_guard = super::IDENTITY_HOST_MAPPING_LOCK.write();
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
        let memory = IdentityGuestMemory::uncoordinated();
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

    #[test]
    fn shared_waiter_key_follows_vnode_offset_not_mapping_address() {
        const LEN: usize = 8192;
        let file = tempfile::tempfile().expect("temporary backing file");
        file.set_len(LEN as u64).expect("size backing file");
        let map = || unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        let first = map();
        let second = map();
        assert_ne!(first, libc::MAP_FAILED);
        assert_ne!(second, libc::MAP_FAILED);
        assert_ne!(first, second);

        let first_key = freebsd_shared_waiter_key(first as usize).expect("first vnode key");
        let alias_key = freebsd_shared_waiter_key(second as usize).expect("alias vnode key");
        let next_page_key =
            freebsd_shared_waiter_key(first as usize + 4096).expect("second-page vnode key");
        assert_eq!(first_key, alias_key);
        assert_ne!(first_key, next_page_key);

        unsafe {
            libc::munmap(first, LEN);
            libc::munmap(second, LEN);
        }
    }

    #[test]
    fn shared_requeue_credit_survives_wake_before_destination_park() {
        use std::sync::atomic::Ordering;

        init_shared_waiter_table();
        let words = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(words, libc::MAP_FAILED);
        let from_word = words as usize;
        let to_word = from_word + 4;
        let from_key = from_word;
        let to_key = to_word;
        let source = shared_waiter_slot(from_key).expect("source waiter slot");
        source.count.store(1, Ordering::SeqCst);

        assert_eq!(
            shared_futex_requeue_umtx(from_word, from_key, to_key, 0, 1),
            (0, 1)
        );
        let assignment = take_shared_wait_assignment(Some(source));
        source.count.store(0, Ordering::SeqCst);
        let SharedWaitAssignment::Requeue {
            waiter_key,
            generation,
        } = assignment
        else {
            panic!("waiter was not assigned to the destination");
        };

        // Wake BEFORE the moved waiter begins its destination park. The logical
        // credit must make the subsequent wait complete without blocking.
        assert_eq!(shared_futex_wake_umtx(to_word, to_key, 1), 1);
        assert_eq!(
            wait_requeued_umtx(
                waiter_key,
                generation,
                Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                &|| false,
            ),
            0
        );
        assert_eq!(
            shared_waiter_slot(to_key)
                .expect("destination waiter slot")
                .logical_requeued
                .load(Ordering::SeqCst),
            0
        );

        unsafe { libc::munmap(words, 4096) };
    }

    #[test]
    fn x86_fault_recovery_restores_guest_pc_and_spilled_register() {
        let mut snapshot = carrick_dsr_x86::X86UcontextSnapshot::new();
        snapshot.gpr[carrick_dsr_x86::gateway::reg::RAX] = 0xdead;
        let mut context = carrick_dsr_x86::X86DsrContext::new(snapshot, 0x8000, 0x4000);
        context.fault.host_rip = 0x8012;
        context.scratch = 0x1234;
        let entries = [PublishedFaultEntry {
            host_start: 0x8010,
            host_end: 0x8014,
            guest_va: 0x4010,
            is_copied_x87: false,
            restores: vec![carrick_dsr_x86::emit::ScratchRestore {
                snapshot_gpr: carrick_dsr_x86::gateway::reg::RAX,
                scratch_index: 0,
            }],
        }];

        assert_eq!(
            recover_x86_fault_snapshot(
                &entries,
                context.fault.host_rip,
                [context.scratch, context.scratch2],
                &mut context.snapshot,
            ),
            Some(0x4010)
        );
        assert_eq!(context.snapshot.rip, 0x4010);
        assert_eq!(
            context.snapshot.gpr[carrick_dsr_x86::gateway::reg::RAX],
            0x1234
        );
    }

    #[test]
    fn x87_gateway_fip_normalization_is_exact_and_preserves_identity_fdp() {
        let entries = [PublishedFaultEntry {
            host_start: 0x8010,
            host_end: 0x8014,
            guest_va: 0x4010,
            is_copied_x87: true,
            restores: Vec::new(),
        }];
        let mut snapshot = carrick_dsr_x86::X86UcontextSnapshot::new();
        snapshot.xsave[8..16].copy_from_slice(&0x8012_u64.to_le_bytes());
        snapshot.xsave[16..24].copy_from_slice(&0x55_000_u64.to_le_bytes());

        normalize_x86_gateway_x87_fip(
            &entries,
            0x8000..0x9000,
            X86GatewayX87Witness {
                entry_fip: 0x1234,
                entry_fdp: 0,
                completed_guest_va: 0,
                completed_guest_data_va: 0,
                completed_data_valid: false,
            },
            &mut snapshot,
        )
        .expect("unique copied x87 instruction must reverse-map");
        assert_eq!(snapshot.x87_instruction_pointer(), 0x4010);
        assert_eq!(
            u64::from_le_bytes(snapshot.xsave[16..24].try_into().unwrap_or([0; 8])),
            0x55_000,
            "identity-native FDP is already a guest VA"
        );
        assert_eq!(snapshot.x87_fcs(), carrick_abi::LINUX_X8664_USER_CS);
        assert_eq!(snapshot.x87_fds(), carrick_abi::LINUX_X8664_USER_DS);
    }

    #[test]
    fn x87_gateway_fip_normalization_uses_completed_instruction_witness() {
        let mut snapshot = carrick_dsr_x86::X86UcontextSnapshot::new();
        // FreeBSD XSAVEOPT can leave FIP in architectural initial state even
        // though the copied FLD completed in the JIT.
        snapshot.xsave[8..16].fill(0);

        normalize_x86_gateway_x87_fip(
            &[],
            0x8000..0x9000,
            X86GatewayX87Witness {
                entry_fip: 0,
                entry_fdp: 0,
                completed_guest_va: 0x4010,
                completed_guest_data_va: 0,
                completed_data_valid: false,
            },
            &mut snapshot,
        )
        .expect("the completed x87 instruction witness must normalize FIP");
        assert_eq!(snapshot.x87_instruction_pointer(), 0x4010);
        assert_eq!(snapshot.x87_fcs(), carrick_abi::LINUX_X8664_USER_CS);
        assert_eq!(snapshot.x87_fds(), carrick_abi::LINUX_X8664_USER_DS);
    }

    #[test]
    fn x87_gateway_witness_imports_zero_fdp_only_when_valid() {
        let mut snapshot = carrick_dsr_x86::X86UcontextSnapshot::new();
        snapshot.xsave[16..24].copy_from_slice(&0x55_000_u64.to_le_bytes());
        normalize_x86_gateway_x87_fip(
            &[],
            0x8000..0x9000,
            X86GatewayX87Witness {
                entry_fip: 0,
                entry_fdp: 0x55_000,
                completed_guest_va: 0x4010,
                completed_guest_data_va: 0,
                completed_data_valid: true,
            },
            &mut snapshot,
        )
        .expect("a valid zero data witness is an architectural address");
        assert_eq!(snapshot.x87_instruction_pointer(), 0x4010);
        assert_eq!(snapshot.x87_data_pointer(), 0);

        let mut register_only = carrick_dsr_x86::X86UcontextSnapshot::new();
        register_only.xsave[16..24].copy_from_slice(&0x55_000_u64.to_le_bytes());
        normalize_x86_gateway_x87_fip(
            &[],
            0x8000..0x9000,
            X86GatewayX87Witness {
                entry_fip: 0,
                entry_fdp: 0x55_000,
                completed_guest_va: 0x4020,
                completed_guest_data_va: 0,
                completed_data_valid: false,
            },
            &mut register_only,
        )
        .expect("a register-only x87 instruction must retain entry FDP");
        assert_eq!(register_only.x87_data_pointer(), 0x55_000);
    }

    #[test]
    fn x87_gateway_fip_normalization_fails_closed_on_ambiguous_metadata() {
        let entries = [
            PublishedFaultEntry {
                host_start: 0x8010,
                host_end: 0x8014,
                guest_va: 0x4010,
                is_copied_x87: true,
                restores: Vec::new(),
            },
            PublishedFaultEntry {
                host_start: 0x8012,
                host_end: 0x8016,
                guest_va: 0x5010,
                is_copied_x87: true,
                restores: Vec::new(),
            },
        ];
        let mut snapshot = carrick_dsr_x86::X86UcontextSnapshot::new();
        snapshot.xsave[8..16].copy_from_slice(&0x8012_u64.to_le_bytes());

        assert_eq!(
            normalize_x86_gateway_x87_fip(
                &entries,
                0x8000..0x9000,
                X86GatewayX87Witness {
                    entry_fip: 0x1234,
                    entry_fdp: 0,
                    completed_guest_va: 0,
                    completed_guest_data_va: 0,
                    completed_data_valid: false,
                },
                &mut snapshot,
            ),
            Err(super::X86X87FipNormalizationError::AmbiguousInstruction { host_fip: 0x8012 })
        );
        assert_eq!(snapshot.x87_instruction_pointer(), 0x8012);
    }

    #[test]
    fn calibrated_x86_vvar_tracks_host_clocks() {
        let clock = calibrate_x86_vvar_clock().expect("FreeBSD amd64 TSC frequency");
        let tsc = unsafe { std::arch::x86_64::_rdtsc() };
        let counter_ns = tsc_ns(tsc, clock.frequency);
        let vvar_realtime = counter_ns.wrapping_add(clock.realtime_off_ns);
        let vvar_monotonic = counter_ns.wrapping_add(clock.monotonic_off_ns);
        let host_realtime = host_clock_ns(libc::CLOCK_REALTIME).expect("host realtime");
        let host_monotonic = host_clock_ns(libc::CLOCK_MONOTONIC).expect("host monotonic");
        assert!(
            vvar_realtime.abs_diff(host_realtime) < 50_000_000,
            "vvar realtime calibration drifted: vvar={vvar_realtime}, host={host_realtime}"
        );
        assert!(
            vvar_monotonic.abs_diff(host_monotonic) < 50_000_000,
            "vvar monotonic calibration drifted: vvar={vvar_monotonic}, host={host_monotonic}"
        );
    }

    #[test]
    fn elf_preflight_rejects_wrong_machine_and_non_executable_type() {
        let mut elf = std::fs::read(std::env::current_exe().expect("current test executable"))
            .expect("read current test executable");
        assert!(parse_loadable_elf(&elf, false).is_ok());

        let original_machine = [elf[18], elf[19]];
        elf[18..20].copy_from_slice(&goblin::elf::header::EM_AARCH64.to_le_bytes());
        assert!(parse_loadable_elf(&elf, false).is_err());
        elf[18..20].copy_from_slice(&original_machine);

        elf[16..18].copy_from_slice(&goblin::elf::header::ET_REL.to_le_bytes());
        assert!(parse_loadable_elf(&elf, false).is_err());
    }

    #[test]
    fn vfork_inheritance_excludes_existing_shared_vmas() {
        assert_eq!(
            exclude_vfork_shared_ranges(
                vec![(0x1000, 0x8000), (0x20_000, 0x1000)],
                &[(0x3000, 0x2000), (0x7000, 0x1000)],
            ),
            vec![
                (0x1000, 0x2000),
                (0x5000, 0x2000),
                (0x8000, 0x1000),
                (0x20_000, 0x1000),
            ]
        );
    }
}

/// Process-wide syscall-path protection metadata for the identity lane. Each
/// `IdentityGuestMemory` carries only its run's executable coordinator; the
/// VMA-classification sets (`no_access` / `no_write` / post-`munmap`
/// `unmapped`) live in ONE global that every instance's `protections()` gate
/// reads. The dispatcher's mmap/munmap/mprotect handlers already publish into
/// this via `set_no_access`/`set_unmapped`/`set_mapping_protection`, so a syscall
/// that touches a `PROT_NONE` or freed guest range returns `EFAULT` instead of
/// raw-faulting the host, and `mincore` (which probes through gated `read_bytes`)
/// reports the freed range unmapped. Fork inherits the parent's COW mappings, so
/// the child correctly starts from a copy of this set.
static IDENTITY_PROTECTIONS: std::sync::LazyLock<
    carrick_guest_mem::protections::MemoryProtections,
> = std::sync::LazyLock::new(carrick_guest_mem::protections::MemoryProtections::default);
/// Serializes raw host mapping transitions against fault-intolerant Rust-side
/// signal-frame copies. Guest JIT accesses remain governed by the fault shim;
/// this lock only prevents `mprotect`/`munmap`/`MAP_FIXED` from racing a host
/// the kernel-contained copy after its metadata check.
static IDENTITY_HOST_MAPPING_LOCK: parking_lot::RwLock<()> = parking_lot::RwLock::new(());

fn identity_host_mapping_write_until(
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
enum NativeMappingOperation {
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

#[cfg(test)]
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

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum InjectedMmapResult {
    Failed,
    WrongAddress,
}

#[cfg(test)]
struct NativeMappingFaultInjection {
    mmap: Option<(NativeMappingOperation, usize, InjectedMmapResult)>,
    mmap_calls: [usize; NativeMappingOperation::COUNT],
    mprotect: Option<(NativeMappingOperation, usize)>,
    mprotect_calls: [usize; NativeMappingOperation::COUNT],
    munmap: Option<usize>,
    munmap_calls: usize,
    munmaps: Vec<(u64, usize, i32)>,
}

#[cfg(test)]
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

#[cfg(test)]
std::thread_local! {
    static NATIVE_MAPPING_FAULTS: std::cell::RefCell<NativeMappingFaultInjection> =
        std::cell::RefCell::new(NativeMappingFaultInjection::default());
}

#[cfg(test)]
struct NativeMappingFaultGuard;

#[cfg(test)]
impl NativeMappingFaultGuard {
    fn new() -> Self {
        NATIVE_MAPPING_FAULTS.with(|faults| *faults.borrow_mut() = Default::default());
        Self
    }

    fn fail_mmap(&self, operation: NativeMappingOperation, result: InjectedMmapResult) {
        self.fail_mmap_at(operation, 0, result);
    }

    fn fail_mmap_at(
        &self,
        operation: NativeMappingOperation,
        index: usize,
        result: InjectedMmapResult,
    ) {
        NATIVE_MAPPING_FAULTS.with(|faults| {
            faults.borrow_mut().mmap = Some((operation, index, result));
        });
    }

    fn fail_mprotect(&self, operation: NativeMappingOperation) {
        self.fail_mprotect_at(operation, 0);
    }

    fn fail_mprotect_at(&self, operation: NativeMappingOperation, index: usize) {
        NATIVE_MAPPING_FAULTS.with(|faults| {
            faults.borrow_mut().mprotect = Some((operation, index));
        });
    }

    fn fail_next_munmap(&self) {
        self.fail_munmap_at(0);
    }

    fn fail_munmap_at(&self, index: usize) {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow_mut().munmap = Some(index));
    }

    fn mmap_call_count(&self, operation: NativeMappingOperation) -> usize {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().mmap_calls[operation.index()])
    }

    fn mprotect_call_count(&self, operation: NativeMappingOperation) -> usize {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().mprotect_calls[operation.index()])
    }

    fn munmaps(&self) -> Vec<(u64, usize, i32)> {
        NATIVE_MAPPING_FAULTS.with(|faults| faults.borrow().munmaps.clone())
    }
}

#[cfg(test)]
impl Drop for NativeMappingFaultGuard {
    fn drop(&mut self) {
        NATIVE_MAPPING_FAULTS.with(|faults| *faults.borrow_mut() = Default::default());
    }
}

fn host_mmap(
    _operation: NativeMappingOperation,
    address: *mut libc::c_void,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: libc::off_t,
) -> *mut libc::c_void {
    #[cfg(test)]
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
                // SAFETY: FreeBSD exposes the calling thread's errno through
                // `__error`; injected host failures must carry a real errno.
                unsafe { *libc::__error() = libc::ENOMEM };
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

fn take_injected_mprotect_failure(_operation: NativeMappingOperation) -> bool {
    #[cfg(test)]
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
    #[cfg(not(test))]
    {
        false
    }
}

fn host_mprotect(
    operation: NativeMappingOperation,
    address: *mut libc::c_void,
    len: usize,
    prot: i32,
) -> i32 {
    if take_injected_mprotect_failure(operation) {
        // SAFETY: FreeBSD exposes the calling thread's errno through __error.
        unsafe { *libc::__error() = libc::EIO };
        return -1;
    }
    // SAFETY: callers hold the identity mapping writer for owned guest ranges.
    unsafe { libc::mprotect(address, len, prot) }
}

fn host_munmap(address: *mut libc::c_void, len: usize) -> i32 {
    #[cfg(test)]
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
    #[cfg(not(test))]
    let injected_failure = false;
    // SAFETY: callers invoke this only for mappings whose ownership they hold.
    let result = if injected_failure {
        #[cfg(test)]
        // SAFETY: FreeBSD exposes the calling thread's errno through __error.
        unsafe {
            *libc::__error() = libc::EIO;
        }
        -1
    } else {
        unsafe { libc::munmap(address, len) }
    };
    #[cfg(test)]
    NATIVE_MAPPING_FAULTS.with(|faults| {
        faults
            .borrow_mut()
            .munmaps
            .push((address as u64, len, result));
    });
    result
}

/// A checked executable-code epoch observed atomically with JIT admission.
/// Keeping this as a domain value prevents registration ids, guest addresses,
/// and raw atomics from being substituted for the cache-validity generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableGeneration(u64);

impl ExecutableGeneration {
    const INITIAL: Self = Self(1);

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Monotonic publication sequence for outer executable stops. Unlike the code
/// generation, this advances for pure fork quiescence too, so a kicked thread
/// can classify a stop after the parent has already finished it unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableStopSequence(u64);

impl ExecutableStopSequence {
    const INITIAL: Self = Self(0);

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableAdmission {
    generation: ExecutableGeneration,
    stop_sequence: ExecutableStopSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ExecutableThreadId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutableThreadState {
    /// Registration exists but its pthread has not bound yet. Fork drain must
    /// wait for it to bind-and-park or unregister; it is never implicitly safe.
    Starting,
    /// Runtime/dispatcher code may own any subsystem mutex.
    HostUnsafe,
    /// The thread is in a declared lock-free host wait after dispatch returned
    /// and every subsystem guard was dropped. It may wake, but cannot re-enter
    /// the dispatcher while an exact host-fork stop remains published.
    HostWaitSafe,
    /// Exact acknowledgement of one host-fork stop sequence.
    ForkParked {
        stop_sequence: ExecutableStopSequence,
    },
    InJit {
        generation: ExecutableGeneration,
    },
    /// A join-required clone pthread has left Carrick's guest-thread body, but
    /// its Rust closure/TLS/pthread teardown is not yet proven complete. Only
    /// the parent that joins its exact handle may remove this tombstone.
    Retiring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutableRegistrationLifetime {
    /// Main/direct registrations may retire on their owning pthread once the
    /// run-loop outcome has been classified.
    Direct,
    /// Clone registrations remain authoritative until a parent joins the exact
    /// pthread handle and confirms host-thread termination.
    JoinRequired,
}

#[derive(Clone, Copy, Debug)]
struct ExecutableThreadRecord {
    pthread: Option<libc::pthread_t>,
    creator_pthread: libc::pthread_t,
    state: ExecutableThreadState,
    lifetime: ExecutableRegistrationLifetime,
}

#[derive(Clone, Copy, Debug)]
struct ExecutableMutationOwner {
    thread: std::thread::ThreadId,
    depth: usize,
    /// Sticky across nested leases: one dirty inner mutation makes the outer
    /// release advance the generation even if it calls `finish_unchanged`.
    dirty: bool,
}

/// Exact owner of a process-snapshot stop. The registration id prevents a
/// recycled pthread from acquiring or releasing another thread's reservation;
/// the stop sequence prevents an old parked acknowledgement authorizing a
/// later fork by the same registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableHostForkOwner {
    thread: ExecutableThreadId,
    host_thread: std::thread::ThreadId,
    stop_sequence: ExecutableStopSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableHostForkState {
    owner: ExecutableHostForkOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutableTerminalPhase {
    Retiring,
    Installing,
    TimedOut,
    Aborted,
}

/// Exact registration identity of the thread replacing the process image.
/// The stop sequence prevents a stale retirement/commit token from authorizing
/// a later terminal transition by the same recycled host pthread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableTerminalOwner {
    thread: ExecutableThreadId,
    stop_sequence: ExecutableStopSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableTerminalState {
    owner: ExecutableTerminalOwner,
    phase: ExecutableTerminalPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableTerminalStop {
    owner: ExecutableTerminalOwner,
    phase: ExecutableTerminalPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutableEpochError {
    RegistrationExhausted,
    GenerationExhausted,
    StopSequenceExhausted,
    QuiescenceTimedOut,
    HostForkBusy,
    TerminalActive { owner: ExecutableTerminalOwner },
    HostForkTimedOut,
    HostForkOwnerMismatch,
    HostForkOwnerNotUnsafe,
    HostWaitStateInvalid,
    SafePointTimedOut,
    UnknownRegistration,
    RegistrationNotBound,
    RegistrationNotRetiring,
    RetiringThreadsPresent,
    VforkInheritanceRestoreFailed,
    MutationNestingExhausted,
    TerminalStopped,
    TerminalAborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutableTerminalError {
    Lost { owner: ExecutableTerminalOwner },
    TimedOut { owner: ExecutableTerminalOwner },
    Aborted { owner: ExecutableTerminalOwner },
    OwnerMismatch,
    OwnerNotHost,
    RetirementIncomplete,
    Epoch(ExecutableEpochError),
}

impl From<ExecutableEpochError> for ExecutableTerminalError {
    fn from(error: ExecutableEpochError) -> Self {
        Self::Epoch(error)
    }
}

struct ExecutableEpochState {
    generation: ExecutableGeneration,
    stop_sequence: ExecutableStopSequence,
    next_thread: u64,
    threads: std::collections::HashMap<ExecutableThreadId, ExecutableThreadRecord>,
    mutation: Option<ExecutableMutationOwner>,
    host_fork: Option<ExecutableHostForkState>,
    terminal: Option<ExecutableTerminalState>,
    failed: Option<ExecutableEpochError>,
}

impl Default for ExecutableEpochState {
    fn default() -> Self {
        Self {
            generation: ExecutableGeneration::INITIAL,
            stop_sequence: ExecutableStopSequence::INITIAL,
            next_thread: 1,
            threads: std::collections::HashMap::new(),
            mutation: None,
            host_fork: None,
            terminal: None,
            failed: None,
        }
    }
}

/// Bounded fail-stopped wait for already-admitted translated instructions.
/// Long REP/string instructions are not interrupted at an arbitrary PC: if
/// they do not reach a semantic gateway boundary within this deadline, the run
/// fails with its stop still published rather than mutating executable memory.
const EXECUTABLE_QUIESCENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// A parked sibling gets longer than the reserving fork's drain deadline so a
/// precise rollback normally releases it first. Expiry is fail-stopped: letting
/// a thread re-enter dispatcher code while the snapshot owner is uncertain is
/// worse than terminating the run loudly.
const EXECUTABLE_SAFE_POINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Diagnostic deadline for terminal exec retirement. Expiry reports a fatal
/// error but never authorizes old-image teardown or clears either stop source.
const EXECUTABLE_TERMINAL_RETIREMENT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

/// SharedRun-owned admission and ownership authority for executable mappings.
///
/// Admission and generation observation share `state`'s mutex. A mutation or
/// exact host-fork reservation publishes `stop_word` before waiting. Fork drain
/// additionally classifies every exact registration as `HostUnsafe`,
/// `HostWaitSafe`, `ForkParked`, `Starting`, or `InJit`, so `libc::fork` never
/// snapshots a dispatcher mutex held by a vanished sibling. Ordinary syscall
/// dispatch takes no process-global coordinator lease: the common fast path is
/// one boundary check and the existing admission mutex only.
struct ExecutableEpoch {
    stop_word: std::sync::atomic::AtomicU32,
    /// Permanent atomic failure latch for the ordinary boundary fast path.
    /// `stop_word` must also remain asserted after failure, but this second
    /// monotonic word prevents a stale/accidentally-cleared zero from reopening
    /// admission without putting the coordinator mutex on every syscall.
    failed_word: std::sync::atomic::AtomicBool,
    state: std::sync::Mutex<ExecutableEpochState>,
    cv: std::sync::Condvar,
}

impl ExecutableEpoch {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stop_word: std::sync::atomic::AtomicU32::new(0),
            failed_word: std::sync::atomic::AtomicBool::new(false),
            state: std::sync::Mutex::new(ExecutableEpochState::default()),
            cv: std::sync::Condvar::new(),
        })
    }

    fn publish_failure_locked(
        &self,
        state: &mut ExecutableEpochState,
        error: ExecutableEpochError,
    ) -> ExecutableEpochError {
        let failure = *state.failed.get_or_insert(error);
        self.failed_word
            .store(true, std::sync::atomic::Ordering::Release);
        self.stop_word
            .store(1, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();
        failure
    }

    fn recompute_stop_word_locked(&self, state: &ExecutableEpochState) {
        let stopped = state.failed.is_some()
            || state.mutation.is_some()
            || state.host_fork.is_some()
            || state.terminal.is_some();
        self.stop_word
            .store(u32::from(stopped), std::sync::atomic::Ordering::Release);
    }

    fn abort_after_false_safe_ack() -> ! {
        // Returning or unwinding after advertising ForkParked would let the
        // process-snapshot owner inherit locks from code that continued past
        // the acknowledgement. There is no safe recovery once the exact
        // reservation cannot be observed through release.
        std::process::abort()
    }

    fn register_with_lifetime(
        self: &Arc<Self>,
        lifetime: ExecutableRegistrationLifetime,
    ) -> Result<ExecutableThreadRegistration, ExecutableEpochError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        let id = ExecutableThreadId(state.next_thread);
        state.next_thread = state
            .next_thread
            .checked_add(1)
            .ok_or(ExecutableEpochError::RegistrationExhausted)?;
        state.threads.insert(
            id,
            ExecutableThreadRecord {
                pthread: None,
                creator_pthread: unsafe { libc::pthread_self() },
                state: ExecutableThreadState::Starting,
                lifetime,
            },
        );
        Ok(ExecutableThreadRegistration {
            epoch: Arc::clone(self),
            id,
            lifetime,
            registered: true,
        })
    }

    #[cfg(test)]
    fn register_starting(
        self: &Arc<Self>,
    ) -> Result<ExecutableThreadRegistration, ExecutableEpochError> {
        self.register_with_lifetime(ExecutableRegistrationLifetime::Direct)
    }

    fn register_clone_starting(
        self: &Arc<Self>,
    ) -> Result<ExecutableThreadRegistration, ExecutableEpochError> {
        self.register_with_lifetime(ExecutableRegistrationLifetime::JoinRequired)
    }

    fn register_current(
        self: &Arc<Self>,
    ) -> Result<ExecutableThreadRegistration, ExecutableEpochError> {
        let mut registration =
            self.register_with_lifetime(ExecutableRegistrationLifetime::Direct)?;
        registration.bind_current()?;
        Ok(registration)
    }

    fn current_generation(&self) -> Result<ExecutableGeneration, ExecutableEpochError> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.failed.map_or(Ok(state.generation), Err)
    }

    /// Exact native-thread safe point. A stop racing this boundary changes the
    /// caller's registration to `ForkParked { sequence }` under the same mutex
    /// that published the reservation, then waits for parent rollback/release.
    /// No dispatcher or mapping lock may be held by callers.
    fn fork_safe_boundary_with_timeout(
        &self,
        registration: &ExecutableThreadRegistration,
        timeout: std::time::Duration,
    ) -> Result<(), ExecutableEpochError> {
        // Ordinary host/JIT/syscall boundaries pay one acquire load only. A
        // racing publisher still observes this registration as HostUnsafe and
        // waits for its next exact boundary; no global runtime BKL is taken.
        if self.stop_word.load(std::sync::atomic::Ordering::Acquire) == 0
            && !self.failed_word.load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        if !registration.registered || !std::ptr::eq(self, Arc::as_ptr(&registration.epoch)) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let deadline = std::time::Instant::now() + timeout;
        let current_pthread = unsafe { libc::pthread_self() };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            let fork = state.host_fork;
            let record = state
                .threads
                .get(&registration.id)
                .copied()
                .ok_or(ExecutableEpochError::UnknownRegistration)?;
            if record.pthread != Some(current_pthread) {
                return Err(ExecutableEpochError::RegistrationNotBound);
            }
            if let Some(error) = state.failed {
                let acknowledged_live_fork = fork.is_some_and(|fork| {
                    fork.owner.thread != registration.id
                        && record.state
                            == (ExecutableThreadState::ForkParked {
                                stop_sequence: fork.owner.stop_sequence,
                            })
                });
                if acknowledged_live_fork {
                    drop(state);
                    Self::abort_after_false_safe_ack();
                }
                return Err(error);
            }
            let Some(fork) = fork else {
                match record.state {
                    ExecutableThreadState::HostUnsafe => return Ok(()),
                    ExecutableThreadState::ForkParked { .. } => {
                        if let Some(record) = state.threads.get_mut(&registration.id) {
                            record.state = ExecutableThreadState::HostUnsafe;
                        }
                        self.cv.notify_all();
                        return Ok(());
                    }
                    ExecutableThreadState::HostWaitSafe => {
                        return Err(ExecutableEpochError::HostWaitStateInvalid);
                    }
                    ExecutableThreadState::Starting => {
                        return Err(ExecutableEpochError::RegistrationNotBound);
                    }
                    ExecutableThreadState::InJit { .. } => {
                        return Err(ExecutableEpochError::HostForkOwnerNotUnsafe);
                    }
                    ExecutableThreadState::Retiring => {
                        return Err(ExecutableEpochError::RetiringThreadsPresent);
                    }
                }
            };
            if fork.owner.thread == registration.id {
                return if record.state == ExecutableThreadState::HostUnsafe {
                    Ok(())
                } else {
                    Err(ExecutableEpochError::HostForkOwnerNotUnsafe)
                };
            }
            if !matches!(
                record.state,
                ExecutableThreadState::HostUnsafe
                    | ExecutableThreadState::HostWaitSafe
                    | ExecutableThreadState::ForkParked { .. }
            ) {
                return Err(ExecutableEpochError::HostForkOwnerNotUnsafe);
            }
            if let Some(record) = state.threads.get_mut(&registration.id) {
                record.state = ExecutableThreadState::ForkParked {
                    stop_sequence: fork.owner.stop_sequence,
                };
            }
            self.cv.notify_all();

            let now = std::time::Instant::now();
            if now >= deadline {
                self.publish_failure_locked(&mut state, ExecutableEpochError::SafePointTimedOut);
                drop(state);
                Self::abort_after_false_safe_ack();
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_state, _) = self
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
        }
    }

    fn fork_safe_boundary(
        &self,
        registration: &ExecutableThreadRegistration,
    ) -> Result<(), ExecutableEpochError> {
        self.fork_safe_boundary_with_timeout(registration, EXECUTABLE_SAFE_POINT_TIMEOUT)
    }

    fn begin_host_wait_safe<'a>(
        self: &Arc<Self>,
        registration: &'a ExecutableThreadRegistration,
    ) -> Result<ExecutableHostWaitGuard<'a>, ExecutableEpochError> {
        if !registration.registered || !Arc::ptr_eq(self, &registration.epoch) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let current_pthread = unsafe { libc::pthread_self() };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        let record = state
            .threads
            .get_mut(&registration.id)
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.pthread != Some(current_pthread)
            || record.state != ExecutableThreadState::HostUnsafe
        {
            return Err(ExecutableEpochError::HostWaitStateInvalid);
        }
        record.state = ExecutableThreadState::HostWaitSafe;
        self.cv.notify_all();
        Ok(ExecutableHostWaitGuard {
            epoch: Arc::clone(self),
            registration,
            active: true,
            not_send: std::marker::PhantomData,
        })
    }

    /// Reserve and drain one exact host-fork stop. The wake callback runs while
    /// the registration table is locked, so a selected pthread cannot retire
    /// and be reused between classification and `pthread_kill`. It must only
    /// perform async-safe, non-locking wake operations.
    fn prepare_host_fork(
        self: &Arc<Self>,
        registration: &ExecutableThreadRegistration,
        deadline: std::time::Instant,
        mut wake: impl FnMut(&[libc::pthread_t]),
    ) -> Result<ExecutableHostForkLease, ExecutableEpochError> {
        if !registration.registered || !Arc::ptr_eq(self, &registration.epoch) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let current = std::thread::current().id();
        let current_pthread = unsafe { libc::pthread_self() };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        if let Some(terminal) = state.terminal {
            return Err(ExecutableEpochError::TerminalActive {
                owner: terminal.owner,
            });
        }
        if state.host_fork.is_some() {
            return Err(ExecutableEpochError::HostForkBusy);
        }
        let record = state
            .threads
            .get(&registration.id)
            .copied()
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.pthread != Some(current_pthread)
            || record.state != ExecutableThreadState::HostUnsafe
        {
            return Err(ExecutableEpochError::HostForkOwnerNotUnsafe);
        }
        let Some(stop_sequence) = state.stop_sequence.next() else {
            let error = self
                .publish_failure_locked(&mut state, ExecutableEpochError::StopSequenceExhausted);
            return Err(error);
        };
        state.stop_sequence = stop_sequence;
        let owner = ExecutableHostForkOwner {
            thread: registration.id,
            host_thread: current,
            stop_sequence,
        };
        state.host_fork = Some(ExecutableHostForkState { owner });
        self.stop_word
            .store(1, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();

        loop {
            let targets: Vec<libc::pthread_t> = state
                .threads
                .iter()
                .filter_map(|(id, record)| {
                    (*id != owner.thread
                        && matches!(
                            record.state,
                            ExecutableThreadState::HostUnsafe | ExecutableThreadState::HostWaitSafe
                        ))
                    .then_some(record.pthread)
                    .flatten()
                })
                .collect();
            if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                wake(&targets);
            })) {
                Self::rollback_host_fork_locked(&mut state, owner);
                self.recompute_stop_word_locked(&state);
                self.cv.notify_all();
                drop(state);
                std::panic::resume_unwind(payload);
            }

            if state.threads.iter().any(|(id, record)| {
                *id != owner.thread && record.state == ExecutableThreadState::Retiring
            }) {
                Self::rollback_host_fork_locked(&mut state, owner);
                self.recompute_stop_word_locked(&state);
                self.cv.notify_all();
                return Err(ExecutableEpochError::RetiringThreadsPresent);
            }
            let drained = state.threads.iter().all(|(id, record)| {
                *id == owner.thread
                    || record.state == ExecutableThreadState::HostWaitSafe
                    || record.state == ExecutableThreadState::ForkParked { stop_sequence }
            });
            if drained {
                return Ok(ExecutableHostForkLease {
                    epoch: Arc::clone(self),
                    owner,
                    active: true,
                    not_send: std::marker::PhantomData,
                });
            }

            let now = std::time::Instant::now();
            if now >= deadline {
                Self::rollback_host_fork_locked(&mut state, owner);
                self.recompute_stop_word_locked(&state);
                self.cv.notify_all();
                return Err(ExecutableEpochError::HostForkTimedOut);
            }
            // Re-send only on the fork path. This closes signal-before-host-park
            // without adding polling or syscalls to ordinary guest execution.
            let retry = deadline
                .saturating_duration_since(now)
                .min(std::time::Duration::from_millis(1));
            let (next_state, _) = self
                .cv
                .wait_timeout(state, retry)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
            if let Some(error) = state.failed {
                return Err(error);
            }
            if state.host_fork != Some(ExecutableHostForkState { owner }) {
                return Err(ExecutableEpochError::HostForkOwnerMismatch);
            }
        }
    }

    fn rollback_host_fork_locked(state: &mut ExecutableEpochState, owner: ExecutableHostForkOwner) {
        if state.host_fork != Some(ExecutableHostForkState { owner }) {
            return;
        }
        state.host_fork = None;
        for record in state.threads.values_mut() {
            if record.state
                == (ExecutableThreadState::ForkParked {
                    stop_sequence: owner.stop_sequence,
                })
            {
                record.state = ExecutableThreadState::HostUnsafe;
            }
        }
    }

    fn release_host_fork(&self, owner: ExecutableHostForkOwner) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.host_fork != Some(ExecutableHostForkState { owner }) {
            self.publish_failure_locked(&mut state, ExecutableEpochError::HostForkOwnerMismatch);
            return;
        }
        Self::rollback_host_fork_locked(&mut state, owner);
        self.recompute_stop_word_locked(&state);
        self.cv.notify_all();
    }

    fn admit<'a>(
        self: &Arc<Self>,
        registration: &'a ExecutableThreadRegistration,
        local_generation: ExecutableGeneration,
    ) -> Result<JitAdmission<'a>, ExecutableEpochError> {
        if !registration.registered || !Arc::ptr_eq(self, &registration.epoch) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(error) = state.failed {
                return Err(error);
            }
            let record = state
                .threads
                .get(&registration.id)
                .copied()
                .ok_or(ExecutableEpochError::UnknownRegistration)?;
            if record.pthread.is_none() || record.state == ExecutableThreadState::Starting {
                return Err(ExecutableEpochError::RegistrationNotBound);
            }
            if state.host_fork.is_some() {
                drop(state);
                self.fork_safe_boundary(registration)?;
                state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                continue;
            }
            if let Some(terminal) = state.terminal {
                return Ok(JitAdmission::Stopped(ExecutableTerminalStop {
                    owner: terminal.owner,
                    phase: terminal.phase,
                }));
            }
            if record.state != ExecutableThreadState::HostUnsafe {
                return Err(ExecutableEpochError::HostWaitStateInvalid);
            }
            if state.mutation.is_some() {
                state = self.cv.wait(state).unwrap_or_else(|p| p.into_inner());
                continue;
            }
            if state.generation != local_generation {
                return Ok(JitAdmission::Refresh(state.generation));
            }
            let admission = ExecutableAdmission {
                generation: state.generation,
                stop_sequence: state.stop_sequence,
            };
            let record = state
                .threads
                .get_mut(&registration.id)
                .ok_or(ExecutableEpochError::UnknownRegistration)?;
            record.state = ExecutableThreadState::InJit {
                generation: admission.generation,
            };
            return Ok(JitAdmission::Entered(InJitGuard {
                epoch: Arc::clone(self),
                id: registration.id,
                admission,
                active: true,
                registration: std::marker::PhantomData,
                not_send: std::marker::PhantomData,
            }));
        }
    }

    fn terminal_stop_for_nonowner(
        self: &Arc<Self>,
        registration: &ExecutableThreadRegistration,
    ) -> Result<Option<ExecutableTerminalStop>, ExecutableEpochError> {
        if !registration.registered || !Arc::ptr_eq(self, &registration.epoch) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        if !state.threads.contains_key(&registration.id) {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        Ok(state.terminal.and_then(|terminal| {
            (terminal.owner.thread != registration.id).then_some(ExecutableTerminalStop {
                owner: terminal.owner,
                phase: terminal.phase,
            })
        }))
    }

    /// Reserve exact terminal ownership before waking any old-image host wait.
    ///
    /// `on_reserved` runs only for the winning registration, after the terminal
    /// owner and stop word are published under the coordinator lock and after
    /// that lock is released. It therefore owns every wake it publishes. The
    /// callback deliberately precedes the bounded wait for an ordinary/vfork
    /// mutation already in flight: that wake may be what releases the retained
    /// vfork-parent mutation lease.
    fn begin_terminal<'a>(
        self: &Arc<Self>,
        registration: &'a ExecutableThreadRegistration,
        on_reserved: impl FnOnce(),
    ) -> Result<ExecutableTerminalLease<'a>, ExecutableTerminalError> {
        // Once terminal ownership is published, its callback wakes every
        // old-image host wait that can retain an ordinary/vfork mutation.
        // Waiting here is a lifecycle rendezvous, not a retryable safe-point:
        // timing it out would abort a valid sibling exec racing a slow vfork.
        self.begin_terminal_inner(registration, None, on_reserved)
    }

    #[cfg(test)]
    fn begin_terminal_with_timeout<'a>(
        self: &Arc<Self>,
        registration: &'a ExecutableThreadRegistration,
        timeout: std::time::Duration,
        on_reserved: impl FnOnce(),
    ) -> Result<ExecutableTerminalLease<'a>, ExecutableTerminalError> {
        self.begin_terminal_inner(registration, Some(timeout), on_reserved)
    }

    fn begin_terminal_inner<'a>(
        self: &Arc<Self>,
        registration: &'a ExecutableThreadRegistration,
        timeout: Option<std::time::Duration>,
        on_reserved: impl FnOnce(),
    ) -> Result<ExecutableTerminalLease<'a>, ExecutableTerminalError> {
        if !registration.registered || !Arc::ptr_eq(self, &registration.epoch) {
            return Err(ExecutableTerminalError::Epoch(
                ExecutableEpochError::UnknownRegistration,
            ));
        }
        let current = std::thread::current().id();
        let current_pthread = unsafe { libc::pthread_self() };
        let owner = loop {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(error) = state.failed {
                return Err(ExecutableTerminalError::Epoch(error));
            }
            if let Some(host_fork) = state.host_fork {
                if host_fork.owner.thread == registration.id {
                    return Err(ExecutableTerminalError::Epoch(
                        ExecutableEpochError::HostForkBusy,
                    ));
                }
                // This old-image exec contender must acknowledge the exact fork
                // stop before it can wait. The acknowledgement may be what lets
                // the competing owner call fork, so terminal's own timeout does
                // not begin until that exact reservation has released.
                drop(state);
                self.fork_safe_boundary(registration)
                    .map_err(ExecutableTerminalError::Epoch)?;
                continue;
            }
            if let Some(terminal) = state.terminal {
                return Err(match terminal.phase {
                    ExecutableTerminalPhase::TimedOut => ExecutableTerminalError::TimedOut {
                        owner: terminal.owner,
                    },
                    ExecutableTerminalPhase::Aborted => ExecutableTerminalError::Aborted {
                        owner: terminal.owner,
                    },
                    ExecutableTerminalPhase::Retiring | ExecutableTerminalPhase::Installing => {
                        ExecutableTerminalError::Lost {
                            owner: terminal.owner,
                        }
                    }
                });
            }
            let record = state.threads.get(&registration.id).copied().ok_or(
                ExecutableTerminalError::Epoch(ExecutableEpochError::UnknownRegistration),
            )?;
            if record.state != ExecutableThreadState::HostUnsafe
                || record.pthread != Some(current_pthread)
            {
                return Err(ExecutableTerminalError::OwnerNotHost);
            }
            let Some(stop_sequence) = state.stop_sequence.next() else {
                let error = self.publish_failure_locked(
                    &mut state,
                    ExecutableEpochError::StopSequenceExhausted,
                );
                return Err(ExecutableTerminalError::Epoch(error));
            };
            state.stop_sequence = stop_sequence;
            let owner = ExecutableTerminalOwner {
                thread: registration.id,
                stop_sequence,
            };
            state.terminal = Some(ExecutableTerminalState {
                owner,
                phase: ExecutableTerminalPhase::Retiring,
            });
            self.stop_word
                .store(1, std::sync::atomic::Ordering::Release);
            self.cv.notify_all();
            break owner;
        };

        // If the owned wake panics, reservation Drop keeps this exact terminal
        // owner published as Aborted with the stop asserted.
        let mut reservation = ExecutableTerminalReservation {
            epoch: Arc::clone(self),
            owner,
            active: true,
        };
        on_reserved();

        let deadline = timeout.map(|timeout| std::time::Instant::now() + timeout);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(error) = state.failed {
                return Err(ExecutableTerminalError::Epoch(error));
            }
            let terminal = state
                .terminal
                .ok_or(ExecutableTerminalError::OwnerMismatch)?;
            if terminal.owner != owner || terminal.phase != ExecutableTerminalPhase::Retiring {
                return Err(ExecutableTerminalError::OwnerMismatch);
            }
            match state.mutation {
                None => {
                    // Only after the prior mutation is gone does the reserved
                    // terminal owner become the outer dirty mutation owner.
                    state.mutation = Some(ExecutableMutationOwner {
                        thread: current,
                        depth: 1,
                        dirty: true,
                    });
                    reservation.active = false;
                    return Ok(ExecutableTerminalLease {
                        epoch: Arc::clone(self),
                        owner,
                        mutation_owner: current,
                        active: true,
                        registration: std::marker::PhantomData,
                        not_send: std::marker::PhantomData,
                    });
                }
                Some(mutation) if mutation.thread == current => {
                    // Waiting for our own ordinary mutation would deadlock. The
                    // reservation Drop below turns Retiring into Aborted while
                    // retaining both the exact owner and the published stop.
                    return Err(ExecutableTerminalError::RetirementIncomplete);
                }
                Some(_) => {}
            }

            let Some(deadline) = deadline else {
                state = self.cv.wait(state).unwrap_or_else(|p| p.into_inner());
                continue;
            };
            let now = std::time::Instant::now();
            if now >= deadline {
                state.terminal = Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::TimedOut,
                });
                self.stop_word
                    .store(1, std::sync::atomic::Ordering::Release);
                self.cv.notify_all();
                reservation.active = false;
                return Err(ExecutableTerminalError::TimedOut { owner });
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_state, wait) = self
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
            if wait.timed_out() && state.mutation.is_some() {
                state.terminal = Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::TimedOut,
                });
                self.stop_word
                    .store(1, std::sync::atomic::Ordering::Release);
                self.cv.notify_all();
                reservation.active = false;
                return Err(ExecutableTerminalError::TimedOut { owner });
            }
        }
    }

    /// Wait until the exact terminal owner registration is the only record
    /// left. Host interrupts are selected while holding the coordinator lock
    /// from records that are currently `Host`; an `InJit` record is never
    /// signalled, and a `Starting` record must bind or unregister before this
    /// can succeed.
    fn wait_for_terminal_retirement(
        &self,
        owner: ExecutableTerminalOwner,
        deadline: std::time::Instant,
        mut interrupt_host: impl FnMut(&[libc::pthread_t]),
    ) -> Result<ExecutableTerminalRetirement, ExecutableTerminalError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(error) = state.failed {
                return Err(ExecutableTerminalError::Epoch(error));
            }
            let terminal = state
                .terminal
                .ok_or(ExecutableTerminalError::OwnerMismatch)?;
            if terminal.owner != owner {
                return Err(ExecutableTerminalError::OwnerMismatch);
            }
            match terminal.phase {
                ExecutableTerminalPhase::Aborted => {
                    return Err(ExecutableTerminalError::Aborted { owner });
                }
                ExecutableTerminalPhase::TimedOut => {
                    return Err(ExecutableTerminalError::TimedOut { owner });
                }
                ExecutableTerminalPhase::Retiring | ExecutableTerminalPhase::Installing => {}
            }
            let owner_is_host = state.threads.get(&owner.thread).is_some_and(|record| {
                record.state == ExecutableThreadState::HostUnsafe && record.pthread.is_some()
            });
            if !owner_is_host {
                return Err(ExecutableTerminalError::OwnerNotHost);
            }
            if state.threads.iter().any(|(id, record)| {
                *id != owner.thread && record.state == ExecutableThreadState::Retiring
            }) {
                if std::time::Instant::now() >= deadline {
                    state.terminal = Some(ExecutableTerminalState {
                        owner,
                        phase: ExecutableTerminalPhase::TimedOut,
                    });
                    self.stop_word
                        .store(1, std::sync::atomic::Ordering::Release);
                    self.cv.notify_all();
                    return Err(ExecutableTerminalError::TimedOut { owner });
                }
                return Err(ExecutableTerminalError::Epoch(
                    ExecutableEpochError::RetiringThreadsPresent,
                ));
            }
            if state.threads.keys().all(|id| *id == owner.thread) {
                state.terminal = Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::Installing,
                });
                self.cv.notify_all();
                return Ok(ExecutableTerminalRetirement { owner });
            }

            let targets: Vec<libc::pthread_t> = state
                .threads
                .iter()
                .filter_map(|(id, record)| {
                    (*id != owner.thread
                        && matches!(
                            record.state,
                            ExecutableThreadState::HostUnsafe | ExecutableThreadState::HostWaitSafe
                        ))
                    .then_some(record.pthread)
                    .flatten()
                })
                .collect();
            // Keep the coordinator lock across pthread_kill selection + send:
            // Drop cannot retire/reuse a captured pthread between the state
            // classification and the signal. The transport handler takes no
            // coordinator or mapping locks.
            interrupt_host(&targets);

            let now = std::time::Instant::now();
            if now >= deadline {
                state.terminal = Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::TimedOut,
                });
                self.stop_word
                    .store(1, std::sync::atomic::Ordering::Release);
                self.cv.notify_all();
                return Err(ExecutableTerminalError::TimedOut { owner });
            }
            let remaining = deadline.saturating_duration_since(now);
            let retry = remaining.min(std::time::Duration::from_millis(1));
            let (next_state, _) = self
                .cv
                .wait_timeout(state, retry)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
        }
    }

    fn commit_terminal(
        &self,
        owner: ExecutableTerminalOwner,
        mutation_owner: std::thread::ThreadId,
        retirement: ExecutableTerminalRetirement,
    ) -> Result<ExecutableGeneration, ExecutableTerminalError> {
        if retirement.owner != owner {
            return Err(ExecutableTerminalError::OwnerMismatch);
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(ExecutableTerminalError::Epoch(error));
        }
        let terminal = state
            .terminal
            .ok_or(ExecutableTerminalError::OwnerMismatch)?;
        if terminal.owner != owner {
            return Err(ExecutableTerminalError::OwnerMismatch);
        }
        match terminal.phase {
            ExecutableTerminalPhase::Aborted => {
                return Err(ExecutableTerminalError::Aborted { owner });
            }
            ExecutableTerminalPhase::TimedOut => {
                return Err(ExecutableTerminalError::TimedOut { owner });
            }
            ExecutableTerminalPhase::Retiring => {
                return Err(ExecutableTerminalError::RetirementIncomplete);
            }
            ExecutableTerminalPhase::Installing => {}
        }
        if !state.threads.keys().all(|id| *id == owner.thread) {
            return Err(ExecutableTerminalError::RetirementIncomplete);
        }
        let mutation = state
            .mutation
            .ok_or(ExecutableTerminalError::OwnerMismatch)?;
        if mutation.thread != mutation_owner || mutation.depth != 1 || !mutation.dirty {
            return Err(ExecutableTerminalError::RetirementIncomplete);
        }
        let Some(generation) = state.generation.next() else {
            let error =
                self.publish_failure_locked(&mut state, ExecutableEpochError::GenerationExhausted);
            return Err(ExecutableTerminalError::Epoch(error));
        };
        state.generation = generation;
        state.mutation = None;
        state.terminal = None;
        self.recompute_stop_word_locked(&state);
        self.cv.notify_all();
        if let Some(error) = state.failed {
            Err(ExecutableTerminalError::Epoch(error))
        } else {
            Ok(generation)
        }
    }

    fn abort_terminal_reservation(&self, owner: ExecutableTerminalOwner) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.terminal.is_none()
            || state.terminal.is_some_and(|terminal| {
                terminal.owner == owner && terminal.phase == ExecutableTerminalPhase::Retiring
            })
        {
            state.terminal = Some(ExecutableTerminalState {
                owner,
                phase: ExecutableTerminalPhase::Aborted,
            });
        }
        // The reservation never owns a mutation to release. Keep any prior
        // mutation intact and retain the terminal stop so teardown stays
        // unauthorized after callback panic or acquisition failure.
        self.stop_word
            .store(1, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();
    }

    fn abort_terminal(
        &self,
        owner: ExecutableTerminalOwner,
        mutation_owner: std::thread::ThreadId,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state
            .terminal
            .is_some_and(|terminal| terminal.owner == owner)
            && state
                .mutation
                .is_some_and(|mutation| mutation.thread == mutation_owner)
        {
            state.terminal = Some(ExecutableTerminalState {
                owner,
                phase: ExecutableTerminalPhase::Aborted,
            });
        }
        // A dropped terminal lease is deliberately not a mutation release.
        // Preserve the owner, outer depth, dirty state, and published stop so
        // neither the old mappings nor a partial replacement can run again.
        self.stop_word
            .store(1, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();
    }

    fn begin_mutation(self: &Arc<Self>) -> Result<ExecutableMutationLease, ExecutableEpochError> {
        self.begin_mutation_with_timeout(EXECUTABLE_QUIESCENCE_TIMEOUT)
    }

    fn begin_mutation_with_timeout(
        self: &Arc<Self>,
        timeout: std::time::Duration,
    ) -> Result<ExecutableMutationLease, ExecutableEpochError> {
        let current = std::thread::current().id();
        let current_pthread = unsafe { libc::pthread_self() };
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(error) = state.failed {
                return Err(error);
            }
            // Reentrant mutation is owned by this pthread's outer critical
            // transaction. It must remain legal even when a host-fork stop was
            // published after the outer lease: the fork still sees this thread
            // HostUnsafe and cannot drain until the complete nested alias
            // commit/rollback reaches its post-dispatch boundary.
            let terminal_allows_reentry = state.terminal.is_none_or(|terminal| {
                !matches!(
                    terminal.phase,
                    ExecutableTerminalPhase::TimedOut | ExecutableTerminalPhase::Aborted
                )
            });
            if terminal_allows_reentry
                && let Some(owner) = state.mutation.as_mut()
                && owner.thread == current
            {
                owner.depth = owner
                    .depth
                    .checked_add(1)
                    .ok_or(ExecutableEpochError::MutationNestingExhausted)?;
                return Ok(ExecutableMutationLease {
                    epoch: Arc::clone(self),
                    owner: current,
                    active: true,
                    not_send: std::marker::PhantomData,
                });
            }
            if let Some(host_fork) = state.host_fork
                && host_fork.owner.host_thread != current
            {
                let registered_current = state.threads.iter().find_map(|(id, record)| {
                    (record.pthread == Some(current_pthread)).then_some((*id, record.state))
                });
                if let Some((id, record_state)) = registered_current {
                    if !matches!(
                        record_state,
                        ExecutableThreadState::HostUnsafe
                            | ExecutableThreadState::ForkParked { .. }
                    ) {
                        return Err(ExecutableEpochError::HostWaitStateInvalid);
                    }
                    if let Some(record) = state.threads.get_mut(&id) {
                        record.state = ExecutableThreadState::ForkParked {
                            stop_sequence: host_fork.owner.stop_sequence,
                        };
                    }
                    self.cv.notify_all();

                    // This acknowledgement may authorize the owner to call
                    // fork. It is therefore irrevocable until this exact stop
                    // sequence is released; a timeout must kill the host, not
                    // return HostForkBusy into dispatcher/mapping code.
                    loop {
                        if state.failed.is_some() {
                            drop(state);
                            Self::abort_after_false_safe_ack();
                        }
                        if state.host_fork != Some(host_fork) {
                            break;
                        }
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            self.publish_failure_locked(
                                &mut state,
                                ExecutableEpochError::SafePointTimedOut,
                            );
                            drop(state);
                            Self::abort_after_false_safe_ack();
                        }
                        let (next_state, _) = self
                            .cv
                            .wait_timeout(state, deadline.saturating_duration_since(now))
                            .unwrap_or_else(|p| p.into_inner());
                        state = next_state;
                    }
                    continue;
                }

                // Process-external helper mutators are absent from the guest
                // registration snapshot, so waiting cannot block its drain and
                // no safe acknowledgement has been published on timeout.
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(ExecutableEpochError::HostForkBusy);
                }
                let (next_state, _) = self
                    .cv
                    .wait_timeout(state, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|p| p.into_inner());
                state = next_state;
                continue;
            }
            if let Some(terminal) = state.terminal {
                return Err(
                    if matches!(
                        terminal.phase,
                        ExecutableTerminalPhase::TimedOut | ExecutableTerminalPhase::Aborted
                    ) {
                        ExecutableEpochError::TerminalAborted
                    } else {
                        ExecutableEpochError::TerminalStopped
                    },
                );
            }
            if state.mutation.is_some() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(ExecutableEpochError::QuiescenceTimedOut);
                }
                let (next_state, wait) = self
                    .cv
                    .wait_timeout(state, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|p| p.into_inner());
                state = next_state;
                if wait.timed_out() && state.mutation.is_some() {
                    return Err(ExecutableEpochError::QuiescenceTimedOut);
                }
                continue;
            }
            let Some(stop_sequence) = state.stop_sequence.next() else {
                let error = self.publish_failure_locked(
                    &mut state,
                    ExecutableEpochError::StopSequenceExhausted,
                );
                return Err(error);
            };
            state.stop_sequence = stop_sequence;
            state.mutation = Some(ExecutableMutationOwner {
                thread: current,
                depth: 1,
                dirty: false,
            });
            self.stop_word
                .store(1, std::sync::atomic::Ordering::Release);
            break;
        }

        while state
            .threads
            .values()
            .any(|record| matches!(record.state, ExecutableThreadState::InJit { .. }))
        {
            let now = std::time::Instant::now();
            if now >= deadline {
                state.mutation = None;
                // Fail stopped: no caller receives a mutation lease and future
                // admissions/mutations observe the typed terminal error.
                let error = self
                    .publish_failure_locked(&mut state, ExecutableEpochError::QuiescenceTimedOut);
                return Err(error);
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_state, wait) = self
                .cv
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
            if let Some(error) = state.failed {
                return Err(error);
            }
            if wait.timed_out()
                && state
                    .threads
                    .values()
                    .any(|record| matches!(record.state, ExecutableThreadState::InJit { .. }))
            {
                state.mutation = None;
                let error = self
                    .publish_failure_locked(&mut state, ExecutableEpochError::QuiescenceTimedOut);
                return Err(error);
            }
        }
        Ok(ExecutableMutationLease {
            epoch: Arc::clone(self),
            owner: current,
            active: true,
            not_send: std::marker::PhantomData,
        })
    }

    fn finish_mutation(&self, owner: std::thread::ThreadId, advance_generation: bool) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(mut mutation) = state.mutation else {
            return;
        };
        if mutation.thread != owner {
            self.publish_failure_locked(&mut state, ExecutableEpochError::UnknownRegistration);
            return;
        }
        mutation.dirty |= advance_generation;
        if mutation.depth > 1 {
            mutation.depth -= 1;
            state.mutation = Some(mutation);
            return;
        }
        if mutation.dirty {
            let Some(generation) = state.generation.next() else {
                state.mutation = None;
                self.publish_failure_locked(&mut state, ExecutableEpochError::GenerationExhausted);
                return;
            };
            state.generation = generation;
        }
        state.mutation = None;
        // A terminal reservation may have been published while this older
        // ordinary/vfork mutation was held. Its stop owns the wake now and must
        // remain asserted until terminal commit or fail-stopped abort.
        self.recompute_stop_word_locked(&state);
        self.cv.notify_all();
    }

    /// Remove a join-required clone tombstone only after the parent has joined
    /// the exact associated `JoinHandle`. A live/starting record is never
    /// reaped by observation alone.
    fn confirm_joined(&self, id: ExecutableThreadId) -> Result<(), ExecutableEpochError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let record = state
            .threads
            .get(&id)
            .copied()
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.lifetime != ExecutableRegistrationLifetime::JoinRequired
            || record.state != ExecutableThreadState::Retiring
        {
            return Err(ExecutableEpochError::RegistrationNotRetiring);
        }
        state.threads.remove(&id);
        self.cv.notify_all();
        Ok(())
    }

    fn fail_permanently(&self, error: ExecutableEpochError) -> ExecutableEpochError {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.publish_failure_locked(&mut state, error)
    }

    fn explains_kick(&self, admitted: ExecutableAdmission) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.mutation.is_some()
            || state.host_fork.is_some()
            || state.terminal.is_some()
            || state.generation != admitted.generation
            || state.stop_sequence != admitted.stop_sequence
            || self.stop_word.load(std::sync::atomic::Ordering::Acquire) != 0
    }
}

struct ExecutableThreadRegistration {
    epoch: Arc<ExecutableEpoch>,
    id: ExecutableThreadId,
    lifetime: ExecutableRegistrationLifetime,
    registered: bool,
}

impl ExecutableThreadRegistration {
    fn bind_current(&mut self) -> Result<(), ExecutableEpochError> {
        if !self.registered {
            return Err(ExecutableEpochError::UnknownRegistration);
        }
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        let host_fork = state.host_fork;
        let record = state
            .threads
            .get_mut(&self.id)
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.state != ExecutableThreadState::Starting {
            return Err(ExecutableEpochError::RegistrationNotBound);
        }
        record.pthread = Some(unsafe { libc::pthread_self() });
        let parked = host_fork.is_some_and(|host_fork| host_fork.owner.thread != self.id);
        record.state = match host_fork {
            Some(host_fork) if parked => ExecutableThreadState::ForkParked {
                stop_sequence: host_fork.owner.stop_sequence,
            },
            _ => ExecutableThreadState::HostUnsafe,
        };
        self.epoch.cv.notify_all();
        drop(state);

        // Publishing ForkParked can grant the snapshot owner authority to call
        // host fork. Binding is not complete until that exact reservation has
        // released us back to HostUnsafe.
        if parked {
            self.epoch.fork_safe_boundary(self)?;
        }
        Ok(())
    }

    /// Fork children must not lock a coordinator whose mutex may have been
    /// owned by a vanished sibling pthread. The inherited Arc is simply
    /// abandoned; the fresh child SharedRun supplies a new coordinator.
    fn abandon_inherited_after_fork(&mut self) {
        self.registered = false;
    }

    fn rebind_after_fork(
        &mut self,
        epoch: &Arc<ExecutableEpoch>,
    ) -> Result<(), ExecutableEpochError> {
        let replacement = epoch.register_current()?;
        *self = replacement;
        Ok(())
    }
}

impl Drop for ExecutableThreadRegistration {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        let current_pthread = unsafe { libc::pthread_self() };
        let deadline = std::time::Instant::now() + EXECUTABLE_SAFE_POINT_TIMEOUT;
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            let Some(record) = state.threads.get(&self.id).copied() else {
                return;
            };
            // An unbound clone whose host spawn failed has no JoinHandle. Its
            // spawning pthread may cancel the exact Starting record safely.
            if record.pthread.is_none() && record.state == ExecutableThreadState::Starting {
                if state.host_fork.is_none() {
                    // Only the pthread that published the unbound record may
                    // cancel a failed spawn. A transferred/dropped token on an
                    // unrelated pthread leaves a conservative tombstone.
                    if record.creator_pthread == current_pthread {
                        state.threads.remove(&self.id);
                        self.epoch.cv.notify_all();
                    }
                    return;
                }
                // Never erase Starting while a fork is deriving authority from
                // the exact table. It cannot acknowledge; wait for bounded
                // rollback, then retry creator-authorized cancellation.
                let now = std::time::Instant::now();
                if now >= deadline {
                    return;
                }
                let (next_state, _) = self
                    .epoch
                    .cv
                    .wait_timeout(state, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|p| p.into_inner());
                state = next_state;
                continue;
            }
            // Every bound registration is pthread-owned. Removing or
            // tombstoning it from another pthread could authorize a snapshot
            // while the real owner still runs cleanup code.
            if record.pthread != Some(current_pthread)
                || record.lifetime != self.lifetime
                || record.state == ExecutableThreadState::Retiring
            {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            let Some(host_fork) = state.host_fork else {
                if self.lifetime == ExecutableRegistrationLifetime::JoinRequired {
                    if let Some(record) = state.threads.get_mut(&self.id) {
                        record.state = ExecutableThreadState::Retiring;
                    }
                } else {
                    state.threads.remove(&self.id);
                }
                self.epoch.cv.notify_all();
                return;
            };
            if self.lifetime == ExecutableRegistrationLifetime::JoinRequired {
                if !matches!(
                    record.state,
                    ExecutableThreadState::HostUnsafe | ExecutableThreadState::HostWaitSafe
                ) {
                    drop(state);
                    ExecutableEpoch::abort_after_false_safe_ack();
                }
                // Clone body retirement revokes a racing snapshot before it can
                // authorize fork. The tombstone remains through closure/TLS/
                // pthread teardown; prepare_host_fork rolls back and SharedRun
                // boundedly reaps the exact handle before retrying.
                if let Some(record) = state.threads.get_mut(&self.id) {
                    record.state = ExecutableThreadState::Retiring;
                }
                self.epoch.cv.notify_all();
                return;
            }
            if host_fork.owner.thread == self.id {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }

            // Direct registrations that retire during a fork remain exact
            // snapshot authority until the reservation releases them.
            if !matches!(
                record.state,
                ExecutableThreadState::HostUnsafe
                    | ExecutableThreadState::HostWaitSafe
                    | ExecutableThreadState::ForkParked { .. }
            ) {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            if let Some(record) = state.threads.get_mut(&self.id) {
                record.state = ExecutableThreadState::ForkParked {
                    stop_sequence: host_fork.owner.stop_sequence,
                };
            }
            self.epoch.cv.notify_all();

            if state.failed.is_some() {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                self.epoch
                    .publish_failure_locked(&mut state, ExecutableEpochError::SafePointTimedOut);
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            let (next_state, _) = self
                .epoch
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
        }
    }
}

/// Declares a lock-free blocking host wait. Dispatcher callbacks must use
/// `with_host_unsafe` so a published fork stop parks them before they reacquire
/// any subsystem mutex. `finish` similarly cannot return to dispatcher code
/// while the snapshot is frozen.
struct ExecutableHostWaitGuard<'a> {
    epoch: Arc<ExecutableEpoch>,
    registration: &'a ExecutableThreadRegistration,
    active: bool,
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExecutableHostWaitGuard<'_> {
    fn with_host_unsafe<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<T, ExecutableEpochError> {
        let current_pthread = unsafe { libc::pthread_self() };
        {
            let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(error) = state.failed {
                return Err(error);
            }
            let host_fork_active = state.host_fork.is_some();
            let record = state
                .threads
                .get_mut(&self.registration.id)
                .ok_or(ExecutableEpochError::UnknownRegistration)?;
            if record.pthread != Some(current_pthread)
                || record.state != ExecutableThreadState::HostWaitSafe
            {
                return Err(ExecutableEpochError::HostWaitStateInvalid);
            }
            if !host_fork_active {
                record.state = ExecutableThreadState::HostUnsafe;
                self.epoch.cv.notify_all();
            } else {
                drop(state);
                self.epoch.fork_safe_boundary(self.registration)?;
            }
        }

        let result = operation();
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        let record = state
            .threads
            .get_mut(&self.registration.id)
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.pthread != Some(current_pthread)
            || record.state != ExecutableThreadState::HostUnsafe
        {
            return Err(ExecutableEpochError::HostWaitStateInvalid);
        }
        record.state = ExecutableThreadState::HostWaitSafe;
        self.epoch.cv.notify_all();
        Ok(result)
    }

    fn finish(mut self) -> Result<(), ExecutableEpochError> {
        let current_pthread = unsafe { libc::pthread_self() };
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(error) = state.failed {
            return Err(error);
        }
        let record = state
            .threads
            .get(&self.registration.id)
            .copied()
            .ok_or(ExecutableEpochError::UnknownRegistration)?;
        if record.pthread != Some(current_pthread)
            || record.state != ExecutableThreadState::HostWaitSafe
        {
            return Err(ExecutableEpochError::HostWaitStateInvalid);
        }
        if state.host_fork.is_some() {
            drop(state);
            self.epoch.fork_safe_boundary(self.registration)?;
        } else {
            if let Some(record) = state.threads.get_mut(&self.registration.id) {
                record.state = ExecutableThreadState::HostUnsafe;
            }
            self.epoch.cv.notify_all();
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for ExecutableHostWaitGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let current_pthread = unsafe { libc::pthread_self() };
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        let host_fork = state.host_fork;
        let valid = if let Some(record) = state.threads.get_mut(&self.registration.id)
            && record.pthread == Some(current_pthread)
        {
            if let Some(host_fork) = host_fork {
                record.state = ExecutableThreadState::ForkParked {
                    stop_sequence: host_fork.owner.stop_sequence,
                };
            } else {
                record.state = ExecutableThreadState::HostUnsafe;
            }
            true
        } else {
            false
        };
        self.epoch.cv.notify_all();
        drop(state);

        // Drop runs during panic unwinding as well as normal error exits. Once
        // it publishes ForkParked the rest of that unwind is host-unsafe and
        // must remain suspended until the exact fork reservation releases.
        if host_fork.is_some() {
            if !valid || self.epoch.fork_safe_boundary(self.registration).is_err() {
                ExecutableEpoch::abort_after_false_safe_ack();
            }
        }
        self.active = false;
    }
}

/// Exact reservation held only from a fully drained host-thread snapshot until
/// the parent has completed `fork` (or an error path rolls back). The child
/// must abandon its inherited copy without locking the coordinator.
struct ExecutableHostForkLease {
    epoch: Arc<ExecutableEpoch>,
    owner: ExecutableHostForkOwner,
    active: bool,
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExecutableHostForkLease {
    fn abandon_after_fork_child(mut self) {
        self.active = false;
        std::mem::forget(self);
    }
}

impl Drop for ExecutableHostForkLease {
    fn drop(&mut self) {
        if self.active {
            self.epoch.release_host_fork(self.owner);
            self.active = false;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutableTerminalRetirement {
    owner: ExecutableTerminalOwner,
}

/// RAII guard for the gap between publishing the terminal owner and installing
/// it as the outer mutation owner. Unwind or any unhandled error in that gap is
/// fail-stopped rather than silently abandoning an owned wake.
struct ExecutableTerminalReservation {
    epoch: Arc<ExecutableEpoch>,
    owner: ExecutableTerminalOwner,
    active: bool,
}

impl Drop for ExecutableTerminalReservation {
    fn drop(&mut self) {
        if self.active {
            self.epoch.abort_terminal_reservation(self.owner);
            self.active = false;
        }
    }
}

struct ExecutableTerminalLease<'a> {
    epoch: Arc<ExecutableEpoch>,
    owner: ExecutableTerminalOwner,
    mutation_owner: std::thread::ThreadId,
    active: bool,
    registration: std::marker::PhantomData<&'a ExecutableThreadRegistration>,
    /// Terminal ownership and nested mutation ownership are both tied to the
    /// acquiring host thread.
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExecutableTerminalLease<'_> {
    fn owner(&self) -> ExecutableTerminalOwner {
        self.owner
    }

    fn commit(
        mut self,
        retirement: ExecutableTerminalRetirement,
    ) -> Result<ExecutableGeneration, ExecutableTerminalError> {
        let result = self
            .epoch
            .commit_terminal(self.owner, self.mutation_owner, retirement);
        if result.is_ok() {
            self.active = false;
        }
        result
    }
}

impl Drop for ExecutableTerminalLease<'_> {
    fn drop(&mut self) {
        if self.active {
            self.epoch.abort_terminal(self.owner, self.mutation_owner);
            self.active = false;
        }
    }
}

enum JitAdmission<'a> {
    Entered(InJitGuard<'a>),
    Refresh(ExecutableGeneration),
    Stopped(ExecutableTerminalStop),
}

struct InJitGuard<'a> {
    epoch: Arc<ExecutableEpoch>,
    id: ExecutableThreadId,
    admission: ExecutableAdmission,
    active: bool,
    registration: std::marker::PhantomData<&'a ExecutableThreadRegistration>,
    /// JIT admission is thread-owned: leaving on another pthread could
    /// acknowledge a stop the real owner never observed.
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl InJitGuard<'_> {
    fn admission(&self) -> ExecutableAdmission {
        self.admission
    }
}

impl Drop for InJitGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let current_pthread = unsafe { libc::pthread_self() };
        let deadline = std::time::Instant::now() + EXECUTABLE_SAFE_POINT_TIMEOUT;
        let mut state = self.epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        let host_fork = state.host_fork;
        let parked = host_fork.is_some_and(|host_fork| host_fork.owner.thread != self.id);
        let next_state = match state.threads.get(&self.id).copied() {
            Some(ExecutableThreadRecord {
                pthread: Some(pthread),
                state: ExecutableThreadState::InJit { generation },
                ..
            }) if pthread == current_pthread && generation == self.admission.generation => {
                match host_fork {
                    Some(host_fork) if parked => ExecutableThreadState::ForkParked {
                        stop_sequence: host_fork.owner.stop_sequence,
                    },
                    _ => ExecutableThreadState::HostUnsafe,
                }
            }
            _ => {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
        };
        if let Some(record) = state.threads.get_mut(&self.id) {
            record.state = next_state;
        }
        self.epoch.cv.notify_all();

        while parked && state.host_fork == host_fork {
            if state.failed.is_some() {
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                self.epoch
                    .publish_failure_locked(&mut state, ExecutableEpochError::SafePointTimedOut);
                drop(state);
                ExecutableEpoch::abort_after_false_safe_ack();
            }
            let (next_state, _) = self
                .epoch
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner());
            state = next_state;
        }
        self.active = false;
    }
}

struct ExecutableMutationLease {
    epoch: Arc<ExecutableEpoch>,
    owner: std::thread::ThreadId,
    active: bool,
    /// A mutation lease is thread-owned because nested acquisition is keyed by
    /// the current host thread. Prevent moving its Drop to another thread.
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExecutableMutationLease {
    /// Release a pure quiescence lease without invalidating translations. Host
    /// `fork()` uses this in the parent: all JIT intervals must be out while the
    /// address-space snapshot is taken, but the parent's executable bytes did
    /// not change. The fork child forgets its inherited lease and binds a fresh
    /// coordinator rather than touching a possibly sibling-owned mutex.
    fn finish_unchanged(mut self) {
        if self.active {
            self.epoch.finish_mutation(self.owner, false);
            self.active = false;
        }
    }
}

impl Drop for ExecutableMutationLease {
    fn drop(&mut self) {
        if self.active {
            self.epoch.finish_mutation(self.owner, true);
            self.active = false;
        }
    }
}

#[cfg(test)]
mod executable_epoch_tests {
    use super::*;
    use static_assertions::assert_not_impl_any;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    assert_not_impl_any!(InJitGuard<'static>: Send);

    fn wait_for_stop(epoch: &ExecutableEpoch) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while epoch.stop_word.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "stop word was not published"
            );
            std::thread::yield_now();
        }
    }

    fn wait_for_exact_fork_park(
        epoch: &ExecutableEpoch,
        thread: ExecutableThreadId,
        stop_sequence: ExecutableStopSequence,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if state.threads.get(&thread).is_some_and(|record| {
                record.state == ExecutableThreadState::ForkParked { stop_sequence }
            }) {
                return;
            }
            let now = std::time::Instant::now();
            assert!(now < deadline, "thread did not park at exact fork boundary");
            let (next, wait) = epoch
                .cv
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner());
            state = next;
            assert!(
                !wait.timed_out(),
                "thread did not park at exact fork boundary"
            );
        }
    }

    fn assert_sigabrt_in_child(operation: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe {
                libc::setrlimit(libc::RLIMIT_CORE, &no_core);
            }
            operation();
            unsafe { libc::_exit(95) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[test]
    fn clone_tombstone_denies_fork_until_exact_join_confirmation() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let clone_registration = epoch
            .register_clone_starting()
            .expect("register clone starting");
        let clone_id = clone_registration.id;
        let (retiring_tx, retiring_rx) = std::sync::mpsc::sync_channel(1);
        let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(1);
        let clone = std::thread::spawn(move || {
            let mut clone_registration = clone_registration;
            clone_registration.bind_current().expect("bind clone");
            // Guest-body retirement occurs before closure/TLS/pthread teardown.
            drop(clone_registration);
            retiring_tx.send(()).expect("publish Retiring tombstone");
            finish_rx.recv().expect("finish pthread cleanup");
        });
        retiring_rx.recv().expect("clone reached cleanup tail");

        assert!(matches!(
            epoch.prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_millis(50),
                |_| {},
            ),
            Err(ExecutableEpochError::RetiringThreadsPresent)
        ));
        assert!(
            epoch
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .host_fork
                .is_none(),
            "Retiring record must roll back snapshot authority"
        );

        finish_tx.send(()).expect("release pthread tail");
        clone.join().expect("join exact clone pthread");
        // Thread completion alone is insufficient until the parent confirms the
        // exact handle/registration association.
        assert!(matches!(
            epoch.prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_millis(50),
                |_| {},
            ),
            Err(ExecutableEpochError::RetiringThreadsPresent)
        ));
        epoch
            .confirm_joined(clone_id)
            .expect("reap exact tombstone");
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("fork succeeds after exact join confirmation");
        drop(lease);
    }

    #[test]
    fn clone_retirement_racing_snapshot_forces_reap_retry() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let clone_registration = epoch
            .register_clone_starting()
            .expect("register clone starting");
        let clone_id = clone_registration.id;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (retire_tx, retire_rx) = std::sync::mpsc::sync_channel(1);
        let (retired_tx, retired_rx) = std::sync::mpsc::sync_channel(1);
        let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(1);
        let clone = std::thread::spawn(move || {
            let mut clone_registration = clone_registration;
            clone_registration.bind_current().expect("bind clone");
            ready_tx.send(()).expect("clone ready");
            retire_rx.recv().expect("retire guest body");
            drop(clone_registration);
            retired_tx.send(()).expect("tombstone published");
            finish_rx.recv().expect("finish pthread tail");
        });
        ready_rx.recv().expect("clone bound");
        let mut retire_tx = Some(retire_tx);
        assert!(matches!(
            epoch.prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {
                    if let Some(tx) = retire_tx.take() {
                        tx.send(()).expect("race clone retirement");
                    }
                },
            ),
            Err(ExecutableEpochError::RetiringThreadsPresent)
        ));
        retired_rx.recv().expect("Retiring observed after rollback");
        finish_tx.send(()).expect("finish clone cleanup");
        clone.join().expect("join clone");
        epoch.confirm_joined(clone_id).expect("confirm exact join");
        drop(
            epoch
                .prepare_host_fork(
                    &owner,
                    std::time::Instant::now() + Duration::from_secs(1),
                    |_| {},
                )
                .expect("retry succeeds after reap"),
        );
    }

    #[test]
    fn host_fork_published_after_alias_boundary_parks_before_lease_acquisition() {
        let epoch = ExecutableEpoch::new();
        let fork_owner = epoch.register_current().expect("register fork owner");
        let alias_registration = epoch.register_starting().expect("register alias thread");
        let alias_id = alias_registration.id;
        let alias_epoch = Arc::clone(&epoch);
        let (boundary_tx, boundary_rx) = std::sync::mpsc::sync_channel(0);
        let (published_tx, published_rx) = std::sync::mpsc::sync_channel(1);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(0);
        let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(0);
        let alias_thread = std::thread::spawn(move || {
            let mut alias_registration = alias_registration;
            alias_registration
                .bind_current()
                .expect("bind alias thread");
            let mut alias_critical = None;
            begin_threaded_dispatch_iteration_after_boundary(
                &alias_epoch,
                &alias_registration,
                carrick_abi::CanonicalNr(222),
                &mut alias_critical,
                || {
                    boundary_tx.send(()).expect("report prior boundary");
                    published_rx.recv().expect("observe published host fork");
                },
            )
            .expect("acquire alias lease after fork release");
            assert!(alias_critical.is_some(), "alias lease was not acquired");
            acquired_tx.send(()).expect("report alias lease");
            finish_rx.recv().expect("finish alias dispatch");
            finish_alias_dispatch_critical(&mut alias_critical);
        });

        boundary_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("alias thread crossed prior boundary");
        let mut published_tx = Some(published_tx);
        let host_fork = epoch
            .prepare_host_fork(
                &fork_owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {
                    if let Some(tx) = published_tx.take() {
                        tx.send(()).expect("publish fork into alias gap");
                    }
                },
            )
            .expect("fork drains alias thread before mutation acquisition");
        {
            let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                state.mutation.is_none(),
                "fork-parked alias thread retained executable mutation ownership"
            );
            assert_eq!(
                state.threads.get(&alias_id).map(|record| record.state),
                Some(ExecutableThreadState::ForkParked {
                    stop_sequence: host_fork.owner.stop_sequence,
                }),
                "alias thread did not park at the post-boundary mutation gate"
            );
        }
        assert!(
            acquired_rx.try_recv().is_err(),
            "parked alias thread acquired its mutation lease"
        );

        drop(host_fork);
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("alias lease acquired after exact fork release");
        finish_tx.send(()).expect("release alias lease");
        alias_thread.join().expect("join alias thread");
    }

    #[test]
    fn alias_outcome_resolves_before_post_dispatch_fork_boundary() {
        let epoch = ExecutableEpoch::new();
        let alias_owner = epoch.register_current().expect("register alias owner");
        let outer = epoch.begin_mutation().expect("outer alias critical lease");
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = IdentityGuestMemory::uncoordinated();
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    [
                        crate::memory::LINUX_HIGH_VA_THRESHOLD,
                        PAGE,
                        crate::linux_abi::LINUX_PROT_READ,
                        crate::linux_abi::LINUX_MAP_PRIVATE | crate::linux_abi::LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]
                    .into(),
                ),
                &mut memory,
                &CompatReporter::default(),
            )
            .expect("dispatch alias outcome");
        assert!(matches!(&outcome, DispatchOutcome::MapHostAlias { .. }));

        let fork_registration = epoch.register_starting().expect("register fork thread");
        let fork_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
        let fork_thread = std::thread::spawn(move || {
            let mut fork_registration = fork_registration;
            fork_registration.bind_current().expect("bind fork thread");
            ready_tx.send(()).expect("fork thread ready");
            let lease = fork_epoch
                .prepare_host_fork(
                    &fork_registration,
                    std::time::Instant::now() + Duration::from_secs(1),
                    |_| {},
                )
                .expect("fork drains after alias boundary");
            acquired_tx.send(()).expect("report fork authority");
            drop(lease);
        });
        ready_rx.recv().expect("fork thread bound");
        wait_for_stop(&epoch);
        assert!(
            acquired_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "fork gained authority while alias transaction was unresolved"
        );
        let nested = epoch
            .begin_mutation()
            .expect("same-thread alias mutation remains reentrant after fork publish");
        drop(nested);

        // Dropping the deferred outcome completes its rollback transaction.
        // Only then does the outer lease release and the exact boundary park.
        drop(outcome);
        outer.finish_unchanged();
        epoch
            .fork_safe_boundary(&alias_owner)
            .expect("publish post-alias boundary");
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("fork authority after alias rollback");
        fork_thread.join().expect("join fork thread");
    }

    #[test]
    fn vfork_prepare_partial_rollback_failure_latches_epoch() {
        let len = (PAGE * 2) as usize;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as u64;
        let epoch = ExecutableEpoch::new();
        // First SHARE succeeds, second SHARE fails, COPY rollback fails.
        let _failures = NativeMinheritFailureGuard::install([false, true, true]);
        let error = NativeVforkShare::prepare_ranges(
            vec![(base, PAGE as usize), (base + PAGE, PAGE as usize)],
            &epoch,
        )
        .expect_err("prepare must report partial rollback failure");
        assert!(error.rollback_failed);
        assert_eq!(
            epoch.state.lock().unwrap_or_else(|p| p.into_inner()).failed,
            Some(ExecutableEpochError::VforkInheritanceRestoreFailed)
        );
        drop(_failures);
        let _ = NativeVforkShare::restore_ranges(&[(base, PAGE as usize)]);
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
    }

    #[test]
    fn vfork_post_child_restore_failure_latches_epoch() {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as u64;
        assert_eq!(
            native_minherit(base, PAGE as usize, carrick_portable::FREEBSD_INHERIT_SHARE,),
            0
        );
        let state = NativeVforkShare {
            ranges: vec![(base, PAGE as usize)],
            pipe: [-1, -1],
        };
        let epoch = ExecutableEpoch::new();
        let _failure = NativeMinheritFailureGuard::install([true]);
        assert!(state.restore_parent_inheritance(&epoch).is_err());
        assert_eq!(
            epoch.state.lock().unwrap_or_else(|p| p.into_inner()).failed,
            Some(ExecutableEpochError::VforkInheritanceRestoreFailed)
        );
        drop(_failure);
        let _ = NativeVforkShare::restore_ranges(&state.ranges);
        assert_eq!(unsafe { libc::munmap(mapping, PAGE as usize) }, 0);
    }

    #[test]
    fn mutation_waits_for_admitted_guard() {
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register current thread");
        let generation = epoch.current_generation().expect("initial generation");
        let guard = match epoch
            .admit(&registration, generation)
            .expect("admit current thread")
        {
            JitAdmission::Entered(guard) => guard,
            JitAdmission::Refresh(_) => panic!("fresh registration unexpectedly needed refresh"),
            JitAdmission::Stopped(_) => panic!("fresh registration unexpectedly stopped"),
        };

        let mutator_epoch = Arc::clone(&epoch);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            let lease = mutator_epoch.begin_mutation().expect("begin mutation");
            acquired_tx.send(()).expect("report acquired mutation");
            release_rx.recv().expect("release mutation");
            drop(lease);
        });

        wait_for_stop(&epoch);
        assert!(
            acquired_rx.try_recv().is_err(),
            "mutation passed an InJit guard"
        );
        drop(guard);
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation acquired after JIT leave");
        release_tx.send(()).expect("release mutation lease");
        mutator.join().expect("join mutator");
    }

    #[test]
    fn in_jit_guard_drop_aborts_on_pthread_mismatch() {
        assert_sigabrt_in_child(|| {
            let epoch = ExecutableEpoch::new();
            let registration = epoch.register_current().expect("register current thread");
            let generation = epoch.current_generation().expect("initial generation");
            let guard = match epoch
                .admit(&registration, generation)
                .expect("admit current thread")
            {
                JitAdmission::Entered(guard) => guard,
                JitAdmission::Refresh(_) => panic!("unexpected refresh"),
                JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
            };
            {
                let mut state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
                let record = state
                    .threads
                    .get_mut(&registration.id)
                    .expect("registration record");
                record.pthread = None;
            }
            drop(guard);
        });
    }

    #[test]
    fn in_jit_guard_drop_aborts_on_generation_mismatch() {
        assert_sigabrt_in_child(|| {
            let epoch = ExecutableEpoch::new();
            let registration = epoch.register_current().expect("register current thread");
            let generation = epoch.current_generation().expect("initial generation");
            let guard = match epoch
                .admit(&registration, generation)
                .expect("admit current thread")
            {
                JitAdmission::Entered(guard) => guard,
                JitAdmission::Refresh(_) => panic!("unexpected refresh"),
                JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
            };
            {
                let mut state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
                let record = state
                    .threads
                    .get_mut(&registration.id)
                    .expect("registration record");
                record.state = ExecutableThreadState::InJit {
                    generation: generation.next().expect("next generation"),
                };
            }
            drop(guard);
        });
    }

    #[test]
    fn in_jit_guard_drop_aborts_on_missing_registration() {
        assert_sigabrt_in_child(|| {
            let epoch = ExecutableEpoch::new();
            let registration = epoch.register_current().expect("register current thread");
            let generation = epoch.current_generation().expect("initial generation");
            let guard = match epoch
                .admit(&registration, generation)
                .expect("admit current thread")
            {
                JitAdmission::Entered(guard) => guard,
                JitAdmission::Refresh(_) => panic!("unexpected refresh"),
                JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
            };
            epoch
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .threads
                .remove(&registration.id);
            drop(guard);
        });
    }

    #[test]
    fn stop_blocks_admission_and_completion_yields_refresh() {
        let epoch = ExecutableEpoch::new();
        let generation = epoch.current_generation().expect("initial generation");
        let lease = epoch.begin_mutation().expect("begin mutation");
        let registration = epoch.register_starting().expect("register starting thread");
        let entrant_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (admitted_tx, admitted_rx) = std::sync::mpsc::sync_channel(1);
        let entrant = std::thread::spawn(move || {
            let mut registration = registration;
            registration.bind_current().expect("bind entrant");
            bound_tx.send(()).expect("report bound entrant");
            let refreshed = matches!(
                entrant_epoch
                    .admit(&registration, generation)
                    .expect("admit after mutation"),
                JitAdmission::Refresh(_)
            );
            admitted_tx.send(refreshed).expect("report admission");
        });
        bound_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("entrant bound");
        assert!(
            admitted_rx.try_recv().is_err(),
            "stop permitted new admission"
        );
        drop(lease);
        assert!(
            admitted_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("admission woke after mutation"),
            "completed mutation did not force Refresh"
        );
        entrant.join().expect("join entrant");
    }

    #[test]
    fn unchanged_quiescence_does_not_invalidate_translations() {
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register current thread");
        let generation = epoch.current_generation().expect("initial generation");

        epoch
            .begin_mutation()
            .expect("begin quiescence")
            .finish_unchanged();

        assert!(matches!(
            epoch
                .admit(&registration, generation)
                .expect("admit after unchanged quiescence"),
            JitAdmission::Entered(_)
        ));
    }

    #[test]
    fn finished_unchanged_stop_still_explains_prior_kick() {
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register current thread");
        let generation = epoch.current_generation().expect("initial generation");
        let guard = match epoch
            .admit(&registration, generation)
            .expect("admit current thread")
        {
            JitAdmission::Entered(guard) => guard,
            JitAdmission::Refresh(_) => panic!("unexpected refresh"),
            JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
        };
        let admission = guard.admission();

        let mutator_epoch = Arc::clone(&epoch);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            mutator_epoch
                .begin_mutation()
                .expect("begin unchanged stop")
                .finish_unchanged();
            finished_tx.send(()).expect("report stop completion");
        });
        wait_for_stop(&epoch);
        drop(guard);
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("unchanged stop completed before classification");

        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 0);
        assert_eq!(
            epoch.current_generation().expect("unchanged generation"),
            generation
        );
        assert!(
            epoch.explains_kick(admission),
            "the monotonic stop sequence must survive finish_unchanged"
        );
        mutator.join().expect("join unchanged mutator");
    }

    #[test]
    fn nested_dirty_mutation_overrides_outer_finish_unchanged() {
        let epoch = ExecutableEpoch::new();
        let generation = epoch.current_generation().expect("initial generation");
        let outer = epoch.begin_mutation().expect("outer mutation");
        let inner = epoch.begin_mutation().expect("inner mutation");

        drop(inner);
        outer.finish_unchanged();

        assert_ne!(
            epoch.current_generation().expect("advanced generation"),
            generation,
            "a dirty nested lease must remain sticky at outer release"
        );
    }

    #[test]
    fn quiescence_timeout_grants_no_lease_and_remains_stopped() {
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register current thread");
        let generation = epoch.current_generation().expect("initial generation");
        let guard = match epoch
            .admit(&registration, generation)
            .expect("admit current thread")
        {
            JitAdmission::Entered(guard) => guard,
            JitAdmission::Refresh(_) => panic!("unexpected refresh"),
            JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
        };

        let mutator_epoch = Arc::clone(&epoch);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            let error = match mutator_epoch.begin_mutation_with_timeout(Duration::from_millis(20)) {
                Ok(lease) => {
                    drop(lease);
                    panic!("timed out quiescence granted a mutation lease");
                }
                Err(error) => error,
            };
            result_tx.send(error).expect("report timeout");
        });
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("bounded quiescence returned"),
            ExecutableEpochError::QuiescenceTimedOut
        );
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(state.failed, Some(ExecutableEpochError::QuiescenceTimedOut));
        assert!(state.mutation.is_none(), "no lease owner remains published");
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        drop(state);
        drop(guard);
        mutator.join().expect("join timed out mutator");

        // Exercise both normal stop-clearing paths after the timeout. Neither
        // an exact host-fork release nor the last mutation finish may reopen a
        // coordinator whose failure latch is permanent.
        let owner = {
            let mut state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            let owner = ExecutableHostForkOwner {
                thread: registration.id,
                host_thread: std::thread::current().id(),
                stop_sequence: state.stop_sequence,
            };
            state.host_fork = Some(ExecutableHostForkState { owner });
            state.mutation = Some(ExecutableMutationOwner {
                thread: std::thread::current().id(),
                depth: 1,
                dirty: false,
            });
            owner
        };
        epoch.release_host_fork(owner);
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        epoch.finish_mutation(std::thread::current().id(), false);
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);

        // Even a diagnostic corruption of the summary word cannot bypass the
        // independent monotonic failure latch on the fast boundary.
        epoch.stop_word.store(0, Ordering::Release);
        assert_eq!(
            epoch.fork_safe_boundary(&registration),
            Err(ExecutableEpochError::QuiescenceTimedOut)
        );
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        epoch.recompute_stop_word_locked(&state);
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
    }

    #[test]
    fn stop_sequence_overflow_fails_stopped() {
        let epoch = ExecutableEpoch::new();
        epoch
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .stop_sequence = ExecutableStopSequence(u64::MAX);

        assert!(matches!(
            epoch.begin_mutation(),
            Err(ExecutableEpochError::StopSequenceExhausted)
        ));
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        assert_eq!(
            epoch.state.lock().unwrap_or_else(|p| p.into_inner()).failed,
            Some(ExecutableEpochError::StopSequenceExhausted)
        );
    }

    #[test]
    fn concurrent_mutation_leases_serialize() {
        let epoch = ExecutableEpoch::new();
        let first_epoch = Arc::clone(&epoch);
        let (first_tx, first_rx) = std::sync::mpsc::sync_channel(1);
        let (release_first_tx, release_first_rx) = std::sync::mpsc::sync_channel(1);
        let first = std::thread::spawn(move || {
            let lease = first_epoch.begin_mutation().expect("first mutation");
            first_tx.send(()).expect("report first lease");
            release_first_rx.recv().expect("release first lease");
            drop(lease);
        });
        first_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first lease acquired");

        let second_epoch = Arc::clone(&epoch);
        let (second_tx, second_rx) = std::sync::mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            let lease = second_epoch.begin_mutation().expect("second mutation");
            second_tx.send(()).expect("report second lease");
            drop(lease);
        });
        assert!(
            second_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "concurrent mutation acquired a second lease"
        );
        release_first_tx.send(()).expect("release first mutation");
        second_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second mutation acquired after first");
        first.join().expect("join first mutator");
        second.join().expect("join second mutator");
    }

    #[test]
    fn wrong_thread_registration_drop_helper() {
        if std::env::var_os("CARRICK_WRONG_THREAD_REGISTRATION_DROP_HELPER").is_none() {
            return;
        }
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        }
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("bind registration");
        let wrong = std::thread::spawn(move || drop(registration));
        let _ = wrong.join();
    }

    #[test]
    fn bound_registration_drop_on_wrong_pthread_fails_stopped_without_fork() {
        let status = std::process::Command::new(
            std::env::current_exe().expect("locate current unit-test binary"),
        )
        .args(["wrong_thread_registration_drop_helper", "--nocapture"])
        .env("CARRICK_WRONG_THREAD_REGISTRATION_DROP_HELPER", "1")
        .status()
        .expect("launch wrong-thread Drop helper");
        assert!(
            !status.success(),
            "wrong pthread silently erased a bound exact registration"
        );
    }

    #[test]
    fn registration_drop_wakes_waiting_mutation() {
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register current thread");
        let generation = epoch.current_generation().expect("initial generation");
        let guard = match epoch
            .admit(&registration, generation)
            .expect("admit current thread")
        {
            JitAdmission::Entered(guard) => guard,
            JitAdmission::Refresh(_) => panic!("unexpected refresh"),
            JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
        };
        let mutator_epoch = Arc::clone(&epoch);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            drop(mutator_epoch.begin_mutation().expect("mutation after drop"));
            done_tx.send(()).expect("report mutation completion");
        });
        wait_for_stop(&epoch);
        drop(guard);
        drop(registration);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("registration/guard drop did not wake mutation");
        mutator.join().expect("join mutator");
    }

    #[test]
    fn host_fork_waits_for_unsafe_registration_then_drop_wakes_boundary() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register unsafe sibling");
            ready_tx.send(()).expect("report unsafe sibling");
            release_rx
                .recv()
                .expect("release simulated dispatcher lock");
            sibling_epoch
                .fork_safe_boundary(&registration)
                .expect("park at fork boundary");
            done_tx.send(()).expect("report boundary release");
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("unsafe sibling registered");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release unsafe sibling");
        });
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("drain after sibling boundary");
        assert!(done_rx.try_recv().is_err(), "parked sibling resumed early");
        drop(lease);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("lease Drop woke parked sibling");
        releaser.join().expect("join unsafe releaser");
        sibling.join().expect("join unsafe sibling");
    }

    #[test]
    fn host_wait_safe_cannot_reenter_dispatch_while_snapshot_is_frozen() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (safe_tx, safe_rx) = std::sync::mpsc::sync_channel(1);
        let (reenter_tx, reenter_rx) = std::sync::mpsc::sync_channel(1);
        let (attempt_tx, attempt_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register wait-safe sibling");
            let guard = sibling_epoch
                .begin_host_wait_safe(&registration)
                .expect("declare wait safe");
            safe_tx.send(()).expect("report wait-safe state");
            attempt_rx.recv().expect("attempt dispatcher callback");
            guard
                .with_host_unsafe(|| reenter_tx.send(()).expect("report reentry"))
                .expect("dispatcher callback after fork release");
            guard.finish().expect("finish wait-safe guard");
        });
        safe_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sibling declared wait safe");
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("wait-safe sibling is explicit safe state");
        attempt_tx.send(()).expect("start reentry attempt");
        assert!(
            reenter_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "HostWaitSafe callback re-entered dispatcher during frozen snapshot"
        );
        drop(lease);
        reenter_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("dispatcher callback resumed after lease Drop");
        sibling.join().expect("join wait-safe sibling");
    }

    #[test]
    fn bind_current_cannot_return_after_acknowledging_active_host_fork() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let starting = epoch.register_starting().expect("register clone starter");
        let (bind_tx, bind_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let mut registration = starting;
            bind_rx.recv().expect("bind starting clone");
            registration.bind_current().expect("bind clone pthread");
            done_tx.send(()).expect("report bind return");
        });
        let binder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            bind_tx.send(()).expect("release clone bind");
        });
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("starting clone bound and parked");
        assert!(
            done_rx.try_recv().is_err(),
            "bind_current returned after publishing ForkParked"
        );
        drop(lease);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("bind returned after exact fork release");
        binder.join().expect("join clone binder");
        sibling.join().expect("join starting clone");
    }

    #[test]
    fn host_wait_guard_unwind_stays_parked_through_fork_release() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (safe_tx, safe_rx) = std::sync::mpsc::sync_channel(1);
        let (panic_tx, panic_rx) = std::sync::mpsc::sync_channel(1);
        let (unwound_tx, unwound_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register wait-safe sibling");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = sibling_epoch
                    .begin_host_wait_safe(&registration)
                    .expect("declare wait safe");
                safe_tx.send(()).expect("report wait-safe state");
                panic_rx.recv().expect("start guarded unwind");
                panic!("injected host wait unwind");
            }));
            unwound_tx
                .send(result.is_err())
                .expect("report completed unwind");
        });
        safe_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sibling declared wait safe");
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("wait-safe sibling permits reservation");
        panic_tx.send(()).expect("start unwind during reservation");
        assert!(
            unwound_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "catch_unwind continued past ForkParked while lease was usable"
        );
        drop(lease);
        assert!(
            unwound_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("unwind completed after fork release")
        );
        sibling.join().expect("join unwinding sibling");
    }

    #[test]
    fn bound_registration_drop_parks_before_retirement() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (drop_tx, drop_rx) = std::sync::mpsc::sync_channel(1);
        let (retired_tx, retired_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register dropping sibling");
            ready_tx.send(()).expect("report bound registration");
            drop_rx.recv().expect("drop registration during fork");
            drop(registration);
            retired_tx.send(()).expect("report registration retirement");
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sibling registration bound");
        let dropper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop_tx.send(()).expect("start registration Drop");
        });
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("registration Drop acknowledged exact fork");
        assert!(
            retired_rx.try_recv().is_err(),
            "bound record retired and continued destructors before fork release"
        );
        drop(lease);
        retired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("registration retired after release");
        dropper.join().expect("join registration dropper");
        sibling.join().expect("join dropping sibling");
    }

    #[test]
    fn caller_owned_registration_covers_post_run_cleanup_and_destructors() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let cleanup_lock = Arc::new(std::sync::Mutex::new(()));
        let sibling_cleanup_lock = Arc::clone(&cleanup_lock);
        let (returned_tx, returned_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (cleaned_tx, cleaned_rx) = std::sync::mpsc::sync_channel(1);
        let (retired_tx, retired_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register cleanup sibling");
            // Model `run_x86_thread` returning while caller-owned cleanup state
            // still has lock-taking work and local destructors to run.
            returned_tx.send(()).expect("report guest loop returned");
            let cleanup = sibling_cleanup_lock
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            release_rx.recv().expect("release post-run cleanup");
            drop(cleanup);
            cleaned_tx.send(()).expect("report cleanup complete");
            drop(registration);
            retired_tx.send(()).expect("report registration retired");
        });
        returned_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("guest loop returned with registration alive");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release post-run cleanup");
        });
        let host_fork = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("registration Drop parks after cleanup");
        cleaned_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("post-run cleanup completed before fork authority");
        assert!(
            retired_rx.try_recv().is_err(),
            "registration Drop returned while host fork lease remained usable"
        );
        drop(host_fork);
        retired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("registration retired after host fork release");
        releaser.join().expect("join cleanup releaser");
        sibling.join().expect("join cleanup sibling");
    }

    #[test]
    fn starting_registration_drop_cannot_grant_false_fork_authority() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let starting = epoch.register_starting().expect("register clone starter");
        let drop_epoch = Arc::clone(&epoch);
        let (retired_tx, retired_rx) = std::sync::mpsc::sync_channel(1);
        let dropper = std::thread::spawn(move || {
            wait_for_stop(&drop_epoch);
            drop(starting);
            retired_tx.send(()).expect("report starting retirement");
        });
        let result = epoch.prepare_host_fork(
            &owner,
            std::time::Instant::now() + Duration::from_millis(40),
            |_| {},
        );
        assert!(matches!(
            result,
            Err(ExecutableEpochError::HostForkTimedOut)
        ));
        retired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("starting Drop completed after rollback");
        dropper.join().expect("join starting dropper");
    }

    #[test]
    fn registered_mutator_parks_instead_of_blocking_host_fork_drain() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (mutate_tx, mutate_rx) = std::sync::mpsc::sync_channel(1);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let _registration = sibling_epoch
                .register_current()
                .expect("register mutating sibling");
            ready_tx.send(()).expect("report mutator registration");
            mutate_rx.recv().expect("start mutation after fork publish");
            let lease = sibling_epoch.begin_mutation().expect("retry mutation");
            acquired_tx.send(()).expect("report mutation acquisition");
            drop(lease);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutating sibling registered");
        let starter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            mutate_tx.send(()).expect("start racing mutation");
        });
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("registered mutator parked and drained");
        assert!(
            acquired_rx.try_recv().is_err(),
            "mutation entered while exact fork reservation remained active"
        );
        drop(lease);
        acquired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mutation retried after fork release");
        starter.join().expect("join mutation starter");
        sibling.join().expect("join registered mutator");
    }

    #[test]
    fn host_fork_wake_panic_rolls_back_exact_reservation() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let result = std::panic::catch_unwind(|| {
            let _lease = epoch.prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| panic!("injected host-fork wake panic"),
            );
        });
        assert!(result.is_err(), "wake panic must unwind");
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            state.host_fork.is_none(),
            "panicked wake retained fork owner"
        );
        assert!(
            state.failed.is_none(),
            "exact panic rollback need not fail-stop"
        );
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 0);
    }

    #[test]
    fn host_fork_timeout_rolls_back_without_fork_authority() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let starting = epoch.register_starting().expect("unbound clone starter");
        let result = epoch.prepare_host_fork(
            &owner,
            std::time::Instant::now() + Duration::from_millis(20),
            |_| {},
        );
        assert!(matches!(
            result,
            Err(ExecutableEpochError::HostForkTimedOut)
        ));
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            state.host_fork.is_none(),
            "timed-out reservation remained owned"
        );
        assert!(
            state.failed.is_none(),
            "exact timeout rollback need not fail-stop"
        );
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 0);
        drop(state);
        drop(starting);
    }

    #[test]
    fn exact_host_drain_precedes_alias_exclusion_without_inversion() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let dispatcher = Arc::new(SyscallDispatcher::new());
        let sibling_epoch = Arc::clone(&epoch);
        let sibling_dispatcher = Arc::clone(&dispatcher);
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register alias sibling");
            let alias = sibling_dispatcher.begin_host_alias_dispatch();
            held_tx.send(()).expect("report alias dispatch held");
            release_rx.recv().expect("release alias dispatch");
            drop(alias);
            sibling_epoch
                .fork_safe_boundary(&registration)
                .expect("park after alias dispatch release");
        });
        held_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sibling entered alias dispatch");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release alias sibling");
        });

        // Production order: publish/drain the exact stop first. The HostUnsafe
        // alias owner completes its operation, reaches the boundary and parks;
        // only then can the forker acquire alias exclusion without waiting on a
        // sibling that is already advertising safe authority.
        let host_fork = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("drain alias owner at exact boundary");
        let alias_exclusion = dispatcher
            .begin_host_alias_dispatch_until(std::time::Instant::now() + Duration::from_secs(1))
            .expect("acquire alias exclusion after drain");
        drop(alias_exclusion);
        drop(host_fork);
        releaser.join().expect("join alias releaser");
        sibling.join().expect("join alias sibling");
    }

    #[test]
    fn real_fork_child_can_reset_dispatcher_after_proc_mutex_holder_parks() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register real fork owner");
        let dispatcher = Arc::new(SyscallDispatcher::new());
        let sibling_epoch = Arc::clone(&epoch);
        let sibling_dispatcher = Arc::clone(&dispatcher);
        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register proc-lock sibling");
            sibling_dispatcher.hold_proc_mutex_for_native_fork_test(
                || locked_tx.send(()).expect("report proc mutex locked"),
                || release_rx.recv().expect("release proc mutex"),
            );
            sibling_epoch
                .fork_safe_boundary(&registration)
                .expect("park after proc mutex release");
        });
        locked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("sibling holds real dispatcher proc mutex");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release proc mutex holder");
        });
        let host_fork = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("proc holder released and parked");
        let signal_locks = crate::host_signal::try_hold_signal_locks_for_fork_until(
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect("acquire signal fork locks");
        let pid = unsafe { libc::fork() };
        drop(signal_locks);
        assert!(
            pid >= 0,
            "real host fork failed: {}",
            std::io::Error::last_os_error()
        );
        if pid == 0 {
            host_fork.abandon_after_fork_child();
            let fresh = ExecutableEpoch::new();
            let _fresh_registration = fresh
                .register_current()
                .unwrap_or_else(|_| unsafe { libc::_exit(121) });
            native_after_fork_child(&dispatcher);
            unsafe { libc::_exit(0) };
        }
        drop(host_fork);
        releaser.join().expect("join proc mutex releaser");
        sibling.join().expect("join proc mutex sibling");

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                break;
            }
            assert_eq!(
                waited,
                0,
                "waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("fork child deadlocked in native_after_fork_child");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn real_fork_freezes_timer_helper_before_child_registry_reset() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register real fork owner");
        let tid = crate::thread::ThreadId::main_from_host_pid();
        let parent_kicker: Arc<carrick_hal::GenericVcpuRegistry> =
            Arc::new(carrick_hal::GenericVcpuRegistry::new());
        crate::timer_delivery::register(parent_kicker as Arc<dyn carrick_hal::VcpuRegistry>, tid);

        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let helper = std::thread::spawn(move || {
            crate::timer_delivery::hold_critical_section_for_native_fork_test(
                || locked_tx.send(()).expect("report timer mutex locked"),
                || release_rx.recv().expect("release timer helper"),
            );
        });
        locked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timer helper holds actual delivery mutex");

        let host_fork = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("reserve host fork around unregistered timer helper");
        let executable = epoch.begin_mutation().expect("freeze executable epoch");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release timer helper");
        });
        let signal_locks = crate::host_signal::try_hold_signal_locks_for_fork_until(
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect("complete signal+timer bundle waits for helper");
        let pid = unsafe { libc::fork() };
        drop(signal_locks);
        assert!(
            pid >= 0,
            "real host fork failed: {}",
            std::io::Error::last_os_error()
        );
        if pid == 0 {
            host_fork.abandon_after_fork_child();
            std::mem::forget(executable);
            let child_tid = crate::thread::ThreadId::main_from_host_pid();
            let registry = Arc::new(crate::thread::ThreadRegistry::new(child_tid));
            crate::thread::set_current_registry(registry);
            let futex = Arc::new(crate::thread::FutexTable::new());
            crate::thread::set_current_futex_table(&futex);
            let child_kicker: Arc<carrick_hal::GenericVcpuRegistry> =
                Arc::new(carrick_hal::GenericVcpuRegistry::new());
            crate::timer_delivery::reset_after_fork_child(
                child_kicker as Arc<dyn carrick_hal::VcpuRegistry>,
                child_tid,
            );
            native_after_fork_child(&SyscallDispatcher::new());
            unsafe { libc::_exit(0) };
        }
        drop(host_fork);
        executable.finish_unchanged();
        releaser.join().expect("join timer releaser");
        helper.join().expect("join timer helper");

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                break;
            }
            assert_eq!(
                waited,
                0,
                "waitpid failed: {}",
                std::io::Error::last_os_error()
            );
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("fork child deadlocked resetting timer delivery");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn vfork_releases_exact_host_drain_but_retains_executable_mutation() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register vfork owner");
        let host_fork = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("prepare host vfork");
        let executable = epoch.begin_mutation().expect("snapshot executable epoch");

        // Model the successful parent return from libc::fork: Linux vfork
        // suspends only this caller, so the exact sibling drain ends now while
        // the mapping/executable transaction remains retained.
        drop(host_fork);
        {
            let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                state.host_fork.is_none(),
                "exact vfork drain must be released"
            );
            assert!(
                state.mutation.is_some(),
                "vfork executable mutation must survive child sharing"
            );
            assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        }
        executable.finish_unchanged();
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 0);
    }

    #[test]
    fn terminal_exec_cannot_compete_with_exact_host_fork_owner() {
        let epoch = ExecutableEpoch::new();
        let owner = epoch.register_current().expect("register fork owner");
        let lease = epoch
            .prepare_host_fork(
                &owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("prepare host fork");
        assert!(matches!(
            epoch.begin_terminal(&owner, || {}),
            Err(ExecutableTerminalError::Epoch(
                ExecutableEpochError::HostForkBusy
            ))
        ));
        drop(lease);
    }

    #[test]
    fn fork_owner_releases_exec_contender_into_terminal_without_timeout() {
        let epoch = ExecutableEpoch::new();
        let fork_owner = epoch.register_current().expect("register fork owner");
        let exec_starting = epoch.register_starting().expect("register exec contender");
        let exec_id = exec_starting.id;
        let exec_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let exec = std::thread::spawn(move || {
            let mut registration = exec_starting;
            registration.bind_current().expect("bind exec contender");
            let wait_guard = exec_epoch
                .begin_host_wait_safe(&registration)
                .expect("declare contender wait safe");
            bound_tx.send(()).expect("report exec bound");
            start_rx.recv().expect("start exec arbitration");
            wait_guard
                .with_host_unsafe(|| {
                    let terminal = exec_epoch
                        .begin_terminal_with_timeout(&registration, Duration::ZERO, || {})
                        .expect("exec timeout starts only after exact fork release");
                    let retirement = exec_epoch
                        .wait_for_terminal_retirement(
                            terminal.owner(),
                            std::time::Instant::now() + Duration::from_secs(1),
                            |_| {},
                        )
                        .expect("fork owner retired");
                    terminal.commit(retirement).expect("commit exec terminal");
                })
                .expect("cross exact fork release");
            wait_guard.finish().expect("leave wait-safe state");
            result_tx.send(()).expect("report exec success");
        });
        bound_rx.recv().expect("exec contender bound");
        let host_fork = epoch
            .prepare_host_fork(
                &fork_owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("reserve host fork");
        let stop_sequence = host_fork.owner.stop_sequence;
        start_tx.send(()).expect("release exec contender");
        wait_for_exact_fork_park(&epoch, exec_id, stop_sequence);
        drop(host_fork);
        drop(fork_owner);
        result_rx.recv().expect("exec acquired after fork release");
        exec.join().expect("join exec contender");
    }

    #[test]
    fn terminal_owner_makes_fork_contender_retire_without_fault() {
        let epoch = ExecutableEpoch::new();
        let exec_owner = epoch.register_current().expect("register exec owner");
        let fork_starting = epoch.register_starting().expect("register fork contender");
        let fork_id = fork_starting.id;
        let fork_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let fork = std::thread::spawn(move || {
            let mut registration = fork_starting;
            registration.bind_current().expect("bind fork contender");
            bound_tx.send(()).expect("report fork bound");
            start_rx.recv().expect("start fork arbitration");
            let result = fork_epoch.prepare_host_fork(
                &registration,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            );
            result_tx
                .send(result.err())
                .expect("report fork disposition");
        });
        bound_rx.recv().expect("fork contender bound");
        let terminal = epoch
            .begin_terminal(&exec_owner, || {})
            .expect("reserve terminal exec");
        let owner = terminal.owner();
        start_tx.send(()).expect("release fork contender");
        assert_eq!(
            result_rx.recv().expect("fork contender disposition"),
            Some(ExecutableEpochError::TerminalActive { owner })
        );
        fork.join().expect("fork contender retired");
        assert!(
            !epoch
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .threads
                .contains_key(&fork_id),
            "terminal-active fork loser retired its exact registration"
        );
        let retirement = epoch
            .wait_for_terminal_retirement(
                owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("fork loser retired");
        terminal.commit(retirement).expect("commit terminal exec");
    }

    #[test]
    fn slow_vfork_sibling_exec_reserves_wakes_and_waits_for_mutation() {
        let epoch = ExecutableEpoch::new();
        let vfork_owner = epoch.register_current().expect("register vfork owner");
        let exec_starting = epoch.register_starting().expect("register exec contender");
        let exec_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let (wake_tx, wake_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let exec = std::thread::spawn(move || {
            let mut registration = exec_starting;
            registration.bind_current().expect("bind exec contender");
            let wait_guard = exec_epoch
                .begin_host_wait_safe(&registration)
                .expect("exec contender waits outside dispatcher locks");
            bound_tx.send(()).expect("report exec bound");
            start_rx.recv().expect("start slow-vfork arbitration");
            wait_guard
                .with_host_unsafe(|| {
                    let terminal = exec_epoch
                        .begin_terminal(&registration, || {
                            wake_tx.send(()).expect("wake vfork parent")
                        })
                        .expect("terminal waits for retained vfork mutation");
                    let retirement = exec_epoch
                        .wait_for_terminal_retirement(
                            terminal.owner(),
                            std::time::Instant::now() + Duration::from_secs(1),
                            |_| {},
                        )
                        .expect("vfork owner retired");
                    terminal.commit(retirement).expect("commit exec terminal");
                })
                .expect("exec crosses released vfork drain");
            wait_guard.finish().expect("finish exec host wait");
            result_tx.send(()).expect("report terminal success");
        });
        bound_rx.recv().expect("exec contender bound");
        let host_fork = epoch
            .prepare_host_fork(
                &vfork_owner,
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("reserve vfork snapshot");
        let executable = epoch.begin_mutation().expect("retain vfork mutation");
        drop(host_fork);
        let vfork_wait = epoch
            .begin_host_wait_safe(&vfork_owner)
            .expect("vfork pipe wait is host-wait safe");

        start_tx.send(()).expect("release exec contender");
        wake_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal reservation wakes slow vfork parent");
        assert!(
            matches!(
                result_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "exec must wait for retained vfork mutation"
        );
        vfork_wait.finish().expect("finish vfork wait boundary");
        executable.finish_unchanged();
        drop(vfork_owner);
        result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("exec proceeds after mutation release");
        exec.join().expect("join exec contender");
    }

    #[test]
    fn second_fork_releases_exact_drain_after_native_guard_timeout() {
        let epoch = ExecutableEpoch::new();
        let vfork_owner = epoch.register_current().expect("register vfork owner");
        let held_native_fork =
            NativeForkGuard::acquire_until(std::time::Instant::now() + Duration::from_secs(1))
                .expect("retain vfork native guard");
        let second_starting = epoch.register_starting().expect("register second forker");
        let second_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (drain_tx, drain_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            let mut registration = second_starting;
            registration.bind_current().expect("bind second forker");
            bound_tx.send(()).expect("report second forker bound");
            let lease = second_epoch
                .prepare_host_fork(
                    &registration,
                    std::time::Instant::now() + Duration::from_secs(1),
                    |_| {
                        let _ = drain_tx.try_send(());
                    },
                )
                .expect("second fork drains exact registrations");
            let result = NativeForkGuard::acquire_until(
                std::time::Instant::now() + Duration::from_millis(20),
            );
            drop(lease);
            result_tx.send(result.err()).expect("report retry result");
        });
        bound_rx.recv().expect("second forker bound");
        drain_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second fork published exact drain");
        epoch
            .fork_safe_boundary(&vfork_owner)
            .expect("vfork owner acknowledges second drain");
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("guard timeout"),
            Some(ExecutableEpochError::HostForkTimedOut)
        );
        assert!(
            epoch
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .host_fork
                .is_none(),
            "retryable second fork releases its exact sibling drain"
        );
        drop(held_native_fork);
        second.join().expect("join second forker");
    }

    #[test]
    fn fork_rebuild_uses_fresh_epoch_state() {
        let inherited = ExecutableEpoch::new();
        let mut inherited_registration = inherited
            .register_current()
            .expect("register inherited current thread");
        drop(inherited.begin_mutation().expect("advance inherited epoch"));
        inherited_registration.abandon_inherited_after_fork();

        let fresh = ExecutableEpoch::new();
        let fresh_registration = fresh.register_current().expect("bind fresh child epoch");
        assert_eq!(
            fresh.current_generation().expect("fresh generation"),
            ExecutableGeneration::INITIAL
        );
        assert_eq!(fresh.stop_word.load(Ordering::Acquire), 0);
        assert_eq!(
            fresh
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .threads
                .len(),
            1
        );
        drop(fresh_registration);
    }

    #[test]
    fn terminal_owned_callback_precedes_prior_mutation_wait() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let mutator_epoch = Arc::clone(&epoch);
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            let mutation = mutator_epoch.begin_mutation().expect("hold prior mutation");
            held_tx.send(()).expect("report prior mutation");
            release_rx.recv().expect("release prior mutation");
            mutation.finish_unchanged();
        });
        held_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("prior mutation acquired");

        let terminal = epoch
            .begin_terminal(&owner_registration, || {
                let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
                let terminal = state.terminal.expect("terminal owner published");
                assert_eq!(terminal.owner.thread, owner_registration.id);
                assert_eq!(terminal.phase, ExecutableTerminalPhase::Retiring);
                assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
                assert!(
                    state.mutation.is_some(),
                    "callback must run before waiting for the prior mutation"
                );
                drop(state);
                release_tx
                    .send(())
                    .expect("owned wake releases prior mutation");
            })
            .expect("acquire terminal after prior mutation");
        mutator.join().expect("join prior mutator");
        let retirement = epoch
            .wait_for_terminal_retirement(
                terminal.owner(),
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("terminal owner is sole registration");
        terminal.commit(retirement).expect("commit terminal image");
    }

    #[test]
    fn terminal_prior_mutation_timeout_retains_exact_owner_and_stop() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let mutator_epoch = Arc::clone(&epoch);
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let mutator = std::thread::spawn(move || {
            let mutation = mutator_epoch.begin_mutation().expect("hold prior mutation");
            held_tx.send(()).expect("report prior mutation");
            release_rx.recv().expect("release prior mutation");
            mutation.finish_unchanged();
        });
        held_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("prior mutation acquired");

        let error = match epoch.begin_terminal_with_timeout(
            &owner_registration,
            Duration::from_millis(20),
            || {},
        ) {
            Ok(_) => panic!("prior mutation wait unexpectedly granted terminal lease"),
            Err(error) => error,
        };
        let owner = match error {
            ExecutableTerminalError::TimedOut { owner } => owner,
            other => panic!("unexpected terminal reservation error: {other:?}"),
        };
        assert_eq!(owner.thread, owner_registration.id);
        {
            let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(
                state.terminal,
                Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::TimedOut,
                })
            );
            assert!(state.mutation.is_some(), "prior mutation remains owned");
            assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        }

        release_tx.send(()).expect("release timed-out mutation");
        mutator.join().expect("join prior mutator");
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(state.mutation.is_none());
        assert_eq!(
            state.terminal,
            Some(ExecutableTerminalState {
                owner,
                phase: ExecutableTerminalPhase::TimedOut,
            })
        );
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
    }

    #[test]
    fn terminal_callback_panic_aborts_exact_reservation() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let result = std::panic::catch_unwind(|| {
            let _terminal = epoch.begin_terminal(&owner_registration, || {
                panic!("owned wake failed");
            });
        });
        assert!(result.is_err(), "callback panic must unwind");

        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        let terminal = state.terminal.expect("aborted terminal retained");
        assert_eq!(terminal.owner.thread, owner_registration.id);
        assert_eq!(terminal.phase, ExecutableTerminalPhase::Aborted);
        assert!(state.mutation.is_none(), "reservation owned no mutation");
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
    }

    #[test]
    fn terminal_rejects_new_admission_until_successful_commit() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let old_generation = epoch.current_generation().expect("initial generation");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("acquire terminal owner");

        assert!(matches!(
            epoch
                .admit(&owner_registration, old_generation)
                .expect("owner admission result"),
            JitAdmission::Stopped(_)
        ));

        // A registration created after terminal publication may bind Host, but
        // it receives a typed stop immediately rather than waiting to enter the
        // replacement image later.
        let starting = epoch.register_starting().expect("register racing starter");
        let entrant_epoch = Arc::clone(&epoch);
        let entrant = std::thread::spawn(move || {
            let mut starting = starting;
            starting.bind_current().expect("bind racing starter");
            assert!(matches!(
                entrant_epoch
                    .admit(&starting, old_generation)
                    .expect("terminal admission"),
                JitAdmission::Stopped(_)
            ));
        });
        entrant.join().expect("join stopped entrant");

        let retirement = epoch
            .wait_for_terminal_retirement(
                terminal.owner(),
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("all nonowners retired");
        // Image-install writes nest through the terminal mutation owner and
        // preserve sticky dirty state for the terminal commit.
        drop(epoch.begin_mutation().expect("nested install mutation"));
        let generation = terminal.commit(retirement).expect("commit terminal image");
        assert_ne!(generation, old_generation);
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 0);
        assert!(matches!(
            epoch
                .admit(&owner_registration, old_generation)
                .expect("post-commit admission"),
            JitAdmission::Refresh(found) if found == generation
        ));
    }

    #[test]
    fn terminal_wait_includes_in_jit_guard_until_registration_retires() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let old_generation = epoch.current_generation().expect("initial generation");
        let sibling_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register JIT sibling");
            let guard = match sibling_epoch
                .admit(&registration, old_generation)
                .expect("admit JIT sibling")
            {
                JitAdmission::Entered(guard) => guard,
                JitAdmission::Refresh(_) => panic!("unexpected refresh"),
                JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
            };
            ready_tx.send(()).expect("report admitted sibling");
            release_rx.recv().expect("release JIT sibling");
            drop(guard);
            assert!(
                sibling_epoch
                    .terminal_stop_for_nonowner(&registration)
                    .expect("terminal disposition")
                    .is_some(),
                "guard return must lead to registration retirement"
            );
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("JIT sibling admitted");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("acquire terminal owner");
        wait_for_stop(&epoch);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release sibling guard");
        });
        let retirement = epoch
            .wait_for_terminal_retirement(
                terminal.owner(),
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("guard and registration retired");
        releaser.join().expect("join guard releaser");
        sibling.join().expect("join JIT sibling");
        terminal.commit(retirement).expect("commit terminal image");
    }

    #[test]
    fn terminal_wait_includes_bound_host_and_drop_wakes_exact_retirement() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let sibling_epoch = Arc::clone(&epoch);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let sibling = std::thread::spawn(move || {
            let registration = sibling_epoch
                .register_current()
                .expect("register Host sibling");
            ready_tx.send(()).expect("report Host sibling");
            release_rx.recv().expect("release Host sibling");
            drop(registration);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Host sibling bound");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("acquire terminal owner");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            release_tx.send(()).expect("release Host sibling");
        });
        let retirement = epoch
            .wait_for_terminal_retirement(
                terminal.owner(),
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("registration Drop woke retirement wait");
        releaser.join().expect("join Host releaser");
        sibling.join().expect("join Host sibling");
        terminal.commit(retirement).expect("commit terminal image");
    }

    #[test]
    fn terminal_timeout_keeps_stop_published_and_drop_aborts() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let starting = epoch
            .register_starting()
            .expect("register Starting sibling");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("acquire terminal owner");
        let owner = terminal.owner();
        assert_eq!(
            epoch.wait_for_terminal_retirement(
                owner,
                std::time::Instant::now() + Duration::from_millis(20),
                |_| {},
            ),
            Err(ExecutableTerminalError::TimedOut { owner })
        );
        {
            let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(
                state.terminal,
                Some(ExecutableTerminalState {
                    owner,
                    phase: ExecutableTerminalPhase::TimedOut,
                })
            );
            assert!(state.mutation.is_some());
            assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        }
        drop(terminal);
        drop(starting);
        let state = epoch.state.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            state.terminal,
            Some(ExecutableTerminalState {
                owner,
                phase: ExecutableTerminalPhase::Aborted,
            })
        );
        assert!(state.mutation.is_some(), "aborted lease must stay owned");
        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
    }

    #[test]
    fn aborted_terminal_remains_fail_stopped() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let generation = epoch.current_generation().expect("initial generation");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("acquire terminal owner");
        let owner = terminal.owner();
        drop(terminal);

        assert_eq!(epoch.stop_word.load(Ordering::Acquire), 1);
        assert!(matches!(
            epoch
                .admit(&owner_registration, generation)
                .expect("aborted admission result"),
            JitAdmission::Stopped(ExecutableTerminalStop {
                owner: found,
                phase: ExecutableTerminalPhase::Aborted,
            }) if found == owner
        ));
        assert!(matches!(
            epoch.begin_mutation(),
            Err(ExecutableEpochError::TerminalAborted)
        ));
        assert!(matches!(
            epoch.begin_terminal(&owner_registration, || {}),
            Err(ExecutableTerminalError::Aborted { owner: found }) if found == owner
        ));
    }

    #[test]
    fn competing_terminal_owner_loses_and_retires() {
        let epoch = ExecutableEpoch::new();
        let owner_registration = epoch.register_current().expect("register terminal owner");
        let contender_starting = epoch.register_starting().expect("register contender");
        let contender_epoch = Arc::clone(&epoch);
        let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel(1);
        let (contend_tx, contend_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let losing_callback_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let contender_callback = Arc::clone(&losing_callback_invoked);
        let contender = std::thread::spawn(move || {
            let mut registration = contender_starting;
            registration.bind_current().expect("bind contender");
            bound_tx.send(()).expect("report bound contender");
            contend_rx.recv().expect("start competing terminal");
            let result = match contender_epoch.begin_terminal(&registration, || {
                contender_callback.store(true, Ordering::Release);
            }) {
                Ok(_) => false,
                Err(ExecutableTerminalError::Lost { .. }) => true,
                Err(_) => false,
            };
            result_tx.send(result).expect("report terminal loss");
        });
        bound_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("contender bound");
        let terminal = epoch
            .begin_terminal(&owner_registration, || {})
            .expect("first contender owns terminal");
        contend_tx.send(()).expect("release contender");
        assert!(
            result_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("competing result"),
            "second terminal contender must lose"
        );
        contender.join().expect("join losing contender");
        assert!(
            !losing_callback_invoked.load(Ordering::Acquire),
            "a losing terminal contender must not publish a wake"
        );
        let retirement = epoch
            .wait_for_terminal_retirement(
                terminal.owner(),
                std::time::Instant::now() + Duration::from_secs(1),
                |_| {},
            )
            .expect("loser registration retired");
        terminal
            .commit(retirement)
            .expect("commit winning terminal");
    }

    #[test]
    fn mutable_executable_policy_refuses_blocks_edges_and_return_cache() {
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_mapping_protection_and_sharing(
            0x4000,
            0x1000,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );
        protections.set_executable(0x4000, 0x1000, true);
        assert!(native_x86_translation_is_ephemeral(&protections, 0x4000, 1));
        assert!(!native_x86_edge_target_is_cacheable(
            &protections,
            GuestVa(0x4000),
            1,
        ));

        protections.set_no_write(0x4000, 0x1000, true);
        assert!(!native_x86_translation_is_ephemeral(
            &protections,
            0x4000,
            1
        ));
        assert!(native_x86_edge_target_is_cacheable(
            &protections,
            GuestVa(0x4000),
            1,
        ));

        protections.set_mapping_protection_and_sharing(
            0x8000,
            0x1000,
            false,
            true,
            carrick_guest_mem::MappingSharing::Shared,
        );
        protections.set_executable(0x8000, 0x1000, true);
        let shared_source_ephemeral = native_x86_translation_is_ephemeral(&protections, 0x8000, 1);
        assert!(shared_source_ephemeral, "shared RX blocks stay ephemeral");
        assert!(
            !native_x86_edge_target_is_cacheable(&protections, GuestVa(0x8000), 1),
            "shared RX targets never receive direct or pending edges"
        );
        assert!(
            !native_x86_return_cache_is_armable(
                &protections,
                shared_source_ephemeral,
                GuestVa(0x4000),
                1,
            ),
            "a shared RX return site never arms"
        );
        assert!(
            !native_x86_return_cache_is_armable(&protections, false, GuestVa(0x8000), 1,),
            "a return cache never arms a shared RX target"
        );
        assert!(native_x86_return_cache_is_armable(
            &protections,
            false,
            GuestVa(0x4000),
            1,
        ));
    }

    #[test]
    fn page_straddling_rx_prefix_with_wx_suffix_is_ephemeral() {
        let start = 0x4fff;
        let block = plan_block(start, 256, PAGE, |va| {
            if va == start {
                vec![0x66, 0x90, 0x90, 0x90]
            } else {
                Vec::new()
            }
        })
        .expect("plan first instruction across page boundary");
        assert_eq!(block.end, 0x5001);
        let guest_len = usize::try_from(block.end - block.start).expect("small block span");

        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_executable(start, guest_len, true);
        protections.set_no_write(start, 1, true);
        assert!(
            !native_x86_translation_is_ephemeral(&protections, start, 1),
            "the first RX byte alone is cacheable"
        );
        assert!(
            native_x86_translation_is_ephemeral(&protections, start, guest_len),
            "the complete emitted instruction span includes the W+X suffix"
        );
    }

    #[test]
    fn uncached_edge_target_crossing_private_rx_into_shared_rx_gets_no_waiter() {
        let start = GuestVa(0x4fff);
        let bytes = [0xe9, 0, 0, 0, 0]; // direct jmp, five-byte planned span
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_mapping_protection_and_sharing(
            start.0,
            1,
            false,
            true,
            carrick_guest_mem::MappingSharing::Private,
        );
        protections.set_mapping_protection_and_sharing(
            start.0 + 1,
            bytes.len() - 1,
            false,
            true,
            carrick_guest_mem::MappingSharing::Shared,
        );
        protections.set_executable(start.0, bytes.len(), true);

        let planned_len = native_x86_uncached_target_guest_len(start, |va| {
            Ok::<_, ()>(if va == start.0 {
                bytes.to_vec()
            } else {
                Vec::new()
            })
        });
        assert_eq!(planned_len, Some(bytes.len()));
        let mut pending_waiters = 0usize;
        if planned_len.is_some_and(|guest_len| {
            native_x86_edge_target_is_cacheable(&protections, start, guest_len)
        }) {
            pending_waiters += 1;
        }
        assert_eq!(
            pending_waiters, 0,
            "a full-span shared RX target must never publish pending edge state"
        );
    }

    #[test]
    fn executable_host_write_waits_for_jit_and_advances_epoch() {
        let _run_guard = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        IDENTITY_PROTECTIONS.set_mapping_protection(address, PAGE as usize, false, false);
        IDENTITY_PROTECTIONS.set_executable(address, PAGE as usize, true);

        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register JIT thread");
        let generation = epoch.current_generation().expect("initial generation");
        let guard = match epoch
            .admit(&registration, generation)
            .expect("admit JIT thread")
        {
            JitAdmission::Entered(guard) => guard,
            JitAdmission::Refresh(_) => panic!("unexpected refresh"),
            JitAdmission::Stopped(_) => panic!("unexpected terminal stop"),
        };
        let writer_epoch = Arc::clone(&epoch);
        let (written_tx, written_rx) = std::sync::mpsc::sync_channel(1);
        let writer = std::thread::spawn(move || {
            let mut memory = IdentityGuestMemory {
                executable_epoch: Some(writer_epoch),
                mapping_failure: None,
            };
            memory
                .write_bytes_raw(address, &[0x5a])
                .expect("write executable byte");
            written_tx.send(()).expect("report write");
        });
        wait_for_stop(&epoch);
        assert!(written_rx.try_recv().is_err(), "write raced admitted JIT");
        drop(guard);
        written_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("write completed after JIT leave");
        writer.join().expect("join writer");
        assert_eq!(unsafe { *(address as *const u8) }, 0x5a);
        assert!(matches!(
            epoch
                .admit(&registration, generation)
                .expect("refresh after executable write"),
            JitAdmission::Refresh(_)
        ));

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(unsafe { libc::munmap(mapping, PAGE as usize) }, 0);
    }
}

impl IdentityGuestMemory {
    fn epoch_error(error: ExecutableEpochError) -> carrick_guest_mem::MemoryError {
        carrick_guest_mem::MemoryError::HostMap(format!(
            "native executable epoch failed: {error:?}"
        ))
    }

    fn begin_executable_mutation(
        &self,
    ) -> Result<Option<ExecutableMutationLease>, carrick_guest_mem::MemoryError> {
        self.executable_epoch
            .as_ref()
            .map(|epoch| epoch.begin_mutation().map_err(Self::epoch_error))
            .transpose()
    }

    /// Obtain the executable epoch (when needed) before the host mapping writer.
    /// A range initially classified as data is rechecked under the mapping lock;
    /// if it became executable while the lock was being acquired, release and
    /// retry in the required epoch-first order.
    fn mapping_write_for_mutation(
        &self,
        address: u64,
        len: usize,
        requested_executable: bool,
    ) -> Result<
        (
            Option<ExecutableMutationLease>,
            parking_lot::RwLockWriteGuard<'static, ()>,
        ),
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
    fn mapping_read_for_write(
        &self,
        address: u64,
        len: usize,
    ) -> Result<
        (
            Option<ExecutableMutationLease>,
            parking_lot::RwLockReadGuard<'static, ()>,
        ),
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

/// Re-establish host backing for only the exact holes inside
/// `[address,address+len)`. Replacing the whole query because one subrange is
/// absent would silently zero adjacent live pages. Tracked holes are snapshotted
/// and clipped under the protection registry lock; an entirely untracked range
/// is mapped exactly only when `mincore` proves its first page absent (the fresh
/// native shared-aperture case).
fn ensure_identity_backed_with_registry(
    address: u64,
    len: usize,
    protections: &carrick_guest_mem::protections::MemoryProtections,
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
                (&mut residency as *mut u8).cast::<libc::c_char>(),
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
            libc::MAP_FIXED | libc::MAP_EXCL | libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        );
        if mapped == libc::MAP_FAILED {
            let primary = RuntimeError::Unsupported(format!(
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
            let primary = RuntimeError::Unsupported(format!(
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

fn ensure_identity_backed(address: u64, len: usize) -> Result<(), MemoryError> {
    ensure_identity_backed_with_registry(address, len, &IDENTITY_PROTECTIONS)
}

fn identity_read_bytes_raw_unlocked(
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
fn identity_write_prevalidated_unlocked(
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

fn identity_write_bytes_raw_unlocked(
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

fn identity_apply_host_protection_preserving_bus(
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

impl GuestMemory for IdentityGuestMemory {
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
        if !no_access && let Err(error) = ensure_identity_backed(address, len) {
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
        if !unmapped && let Err(error) = ensure_identity_backed(address, len) {
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
        if let Err(error) = ensure_identity_backed(address, len) {
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
        if let Err(error) = ensure_identity_backed(address, len) {
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
        let requested_executable = prot & crate::linux_abi::LINUX_PROT_EXEC != 0;
        let (_mutation, _mapping_guard) =
            match self.mapping_write_for_mutation(address, len, requested_executable) {
                Ok(guards) => guards,
                Err(error) => {
                    IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
                    return Err(error);
                }
            };
        if let Err(error) = ensure_identity_backed(address, len) {
            IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
            return Err(error);
        }
        let readable =
            prot & (crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC) != 0;
        let writable = prot & crate::linux_abi::LINUX_PROT_WRITE != 0;
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
        let mut residency = vec![0i8; pages];
        // SAFETY: identity guest VA is the live host mapping. `residency` has
        // exactly one byte per queried FreeBSD page; this lane's guest and host
        // page sizes are both 4 KiB.
        if unsafe {
            libc::mincore(
                start.raw() as *mut libc::c_void,
                len,
                residency.as_mut_ptr(),
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
            waiter_key: freebsd_shared_waiter_key(host_addr).unwrap_or(host_addr),
        })
    }
}

fn cflow_memory_backend_error(
    access: cflow::CflowMemoryAccess,
    address: u64,
    error: impl std::fmt::Display,
) -> cflow::CflowError {
    cflow::CflowError::MemoryBackend {
        access,
        address,
        detail: error.to_string(),
    }
}

/// The largest architectural payload read by one XRSTOR component. Individual
/// kernel transfers are smaller and page-contained; this bound prevents an
/// accidental general-purpose copy API from growing behind the checked seam.
const IDENTITY_KERNEL_COPY_PIPE_BOUND: usize = 1024;
/// Keep every pipe transfer comfortably below FreeBSD's atomic pipe-write bound
/// and split again at guest page boundaries so an EFAULT names the first page
/// whose backing is inaccessible.
const IDENTITY_KERNEL_COPY_CHUNK: usize = 512;
/// Host signals can interrupt a syscall repeatedly. A guest-memory service must
/// still terminate deterministically rather than spin forever under the mapping
/// lock, so every no-progress EINTR path has this explicit retry budget.
const IDENTITY_KERNEL_COPY_EINTR_LIMIT: usize = 16;

#[derive(Debug, PartialEq, Eq)]
enum IdentityCheckedReadError {
    Fault(carrick_guest_mem::protections::GuestMemoryFault),
    BusAddress { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

#[derive(Debug, PartialEq, Eq)]
enum IdentityCheckedWriteError {
    Fault(carrick_guest_mem::protections::GuestMemoryFault),
    BusAddress { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

#[derive(Debug, PartialEq, Eq)]
enum IdentityKernelCopyError {
    GuestFault { address: GuestVa },
    Backend { address: GuestVa, detail: String },
}

fn identity_checked_read_fault(
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

fn identity_checked_write_fault(
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

#[cfg(test)]
std::thread_local! {
    static IDENTITY_KERNEL_COPY_PIPE_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_identity_kernel_copy_pipe_census() {
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(|census| census.set(0));
}

#[cfg(test)]
fn identity_kernel_copy_pipe_census() -> usize {
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn reset_identity_kernel_copyin_operation_census() {
    IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS.with(|census| census.set(0));
}

#[cfg(test)]
fn identity_kernel_copyin_operation_census() -> usize {
    IDENTITY_KERNEL_COPYIN_OPERATION_CENSUS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn reset_identity_kernel_copyout_operation_census() {
    IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS.with(|census| census.set(0));
}

#[cfg(test)]
fn identity_kernel_copyout_operation_census() -> usize {
    IDENTITY_KERNEL_COPYOUT_OPERATION_CENSUS.with(std::cell::Cell::get)
}

fn identity_kernel_copy_pipe(
    address: GuestVa,
    operation: &'static str,
) -> Result<(OwnedFd, OwnedFd), IdentityKernelCopyError> {
    let mut raw_fds = [-1; 2];
    let mut interruptions = 0usize;
    loop {
        // SAFETY: `raw_fds` names two writable integers. On success ownership
        // moves immediately into `OwnedFd`; failures own no descriptors.
        if unsafe { libc::pipe2(raw_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
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
    #[cfg(test)]
    IDENTITY_KERNEL_COPY_PIPE_CENSUS.with(|census| census.set(census.get() + 1));
    // SAFETY: successful `pipe2` returned two fresh owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(raw_fds[0]) };
    // SAFETY: ownership of the distinct write descriptor transfers once.
    let writer = unsafe { OwnedFd::from_raw_fd(raw_fds[1]) };
    Ok((reader, writer))
}

fn identity_kernel_copy_chunk(
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

/// Ask the FreeBSD kernel to copy one guest range into a private nonblocking
/// pipe, draining after every successful or partial write. `write(2)` performs
/// copyin under kernel fault containment: a readable file mapping whose backing
/// was truncated reports EFAULT instead of delivering host SIGBUS to Carrick.
/// Every write starts with an empty pipe, is page-contained and at most 512
/// bytes, and no guest address is ever used to construct a Rust slice.
fn identity_kernel_copyin_exact_using(
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
        #[cfg(test)]
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

fn identity_kernel_copyin_exact(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityKernelCopyError> {
    identity_kernel_copyin_exact_using(address, destination, None)
}

/// Symmetric kernel-contained copyout. Rust-owned bytes enter an empty private
/// nonblocking pipe, then `read(2)` asks FreeBSD to copy them into the guest in
/// page-contained, at-most-512-byte units. A writable MAP_SHARED page whose
/// vnode was truncated therefore returns EFAULT instead of killing Carrick with
/// host SIGBUS. Partial transfers are drained completely before the next write.
fn identity_kernel_copyout_exact(
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
            #[cfg(test)]
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

/// Copy one exact architectural range from the identity guest mapping.
///
/// The host-mapping read lock spans raw-domain validation, complete-range
/// protection and backing classification, and the copy. Mapping/protection
/// transitions take the writer in the same outer-to-inner order, so a
/// successful check cannot race `mprotect`, `munmap`, or `MAP_FIXED`.
/// Anonymous/private materialized backing is copied directly after validation;
/// mutable shared vnode backing retains FreeBSD copyin so an external truncate
/// becomes a typed `BusAddress` instead of a host SIGBUS.
fn identity_checked_read_exact(
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
fn identity_checked_read_exact_under_mapping_lock(
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

/// Architectural maximum encoded length of one x86 instruction.
const X86_MAX_INSTRUCTION_LENGTH: usize = 15;

fn identity_execute_fault_under_mapping_lock(address: GuestVa) -> Option<IdentityCheckedReadError> {
    if let Some(fault_address) = identity_raw_fault_address(address.raw(), 1) {
        return Some(IdentityCheckedReadError::Fault(
            carrick_guest_mem::protections::GuestMemoryFault {
                address: GuestVa(fault_address),
                kind: carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped,
            },
        ));
    }
    if IDENTITY_PROTECTIONS.range_executable(address.raw(), 1) {
        return None;
    }
    if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
        address,
        1,
        carrick_guest_mem::protections::GuestMemoryAccess::Read,
    ) {
        return Some(identity_checked_read_fault(fault));
    }
    Some(identity_checked_read_fault(
        carrick_guest_mem::protections::GuestMemoryFault {
            address,
            kind: carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied,
        },
    ))
}

/// Read an already-decoded executable span without constructing a guest-backed
/// Rust slice. Execute permission and kernel-contained copyin share the mapping
/// lock, so a concurrent Carrick VMA transition cannot invalidate the check.
fn identity_checked_read_executable_exact(
    address: GuestVa,
    destination: &mut [u8],
) -> Result<(), IdentityCheckedReadError> {
    let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
    for offset in 0..destination.len() {
        let offset = u64::try_from(offset).map_err(|_| IdentityCheckedReadError::Backend {
            address,
            detail: "executable guest-read offset is not representable".into(),
        })?;
        let current = address
            .raw()
            .checked_add(offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedReadError::Backend {
                address,
                detail: "executable guest-read address overflowed".into(),
            })?;
        if let Some(error) = identity_execute_fault_under_mapping_lock(current) {
            return Err(error);
        }
    }
    let mut completed = 0usize;
    for chunk in destination.chunks_mut(IDENTITY_KERNEL_COPY_PIPE_BOUND) {
        let offset = u64::try_from(completed).map_err(|_| IdentityCheckedReadError::Backend {
            address,
            detail: "executable guest-read chunk offset is not representable".into(),
        })?;
        let chunk_start = address
            .raw()
            .checked_add(offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedReadError::Backend {
                address,
                detail: "executable guest-read chunk address overflowed".into(),
            })?;
        identity_checked_read_exact_under_mapping_lock(chunk_start, chunk)?;
        completed += chunk.len();
    }
    Ok(())
}

/// Find the executable prefix beginning at `address`, bounded by x86's
/// architectural instruction length. The common case samples the complete
/// 15-byte range once; only a real boundary needs byte-wise fault discovery.
fn identity_contiguous_executable_span_under_mapping_lock(
    address: GuestVa,
) -> Result<(usize, Option<IdentityCheckedReadError>), IdentityCheckedReadError> {
    if identity_raw_fault_address(address.raw(), X86_MAX_INSTRUCTION_LENGTH).is_none()
        && IDENTITY_PROTECTIONS.range_executable(address.raw(), X86_MAX_INSTRUCTION_LENGTH)
    {
        return Ok((X86_MAX_INSTRUCTION_LENGTH, None));
    }

    for offset in 0..X86_MAX_INSTRUCTION_LENGTH {
        let raw_offset = u64::try_from(offset).map_err(|_| IdentityCheckedReadError::Backend {
            address,
            detail: "x86 instruction-fetch offset is not representable".into(),
        })?;
        let current = address
            .raw()
            .checked_add(raw_offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedReadError::Backend {
                address,
                detail: "x86 instruction-fetch address overflowed".into(),
            })?;
        if let Some(error) = identity_execute_fault_under_mapping_lock(current) {
            return Ok((offset, Some(error)));
        }
    }
    Ok((X86_MAX_INSTRUCTION_LENGTH, None))
}

/// Fetch one instruction from mutable shared backing through FreeBSD copyin.
/// Bytes are acquired lazily so a short instruction immediately before a
/// truncated vnode page does not false-fault by overfetching that page.
fn identity_checked_fetch_x86_instruction_mutable_shared_under_mapping_lock(
    address: GuestVa,
) -> Result<Vec<u8>, IdentityCheckedReadError> {
    let (reader, writer) =
        identity_kernel_copy_pipe(address, "instruction fetch").map_err(|error| match error {
            IdentityKernelCopyError::GuestFault { address } => {
                IdentityCheckedReadError::BusAddress { address }
            }
            IdentityKernelCopyError::Backend { address, detail } => {
                IdentityCheckedReadError::Backend { address, detail }
            }
        })?;
    let mut bytes = Vec::with_capacity(X86_MAX_INSTRUCTION_LENGTH);
    for offset in 0..X86_MAX_INSTRUCTION_LENGTH {
        let offset = u64::try_from(offset).map_err(|_| IdentityCheckedReadError::Backend {
            address,
            detail: "x86 instruction-fetch offset is not representable".into(),
        })?;
        let current = address
            .raw()
            .checked_add(offset)
            .map(GuestVa)
            .ok_or_else(|| IdentityCheckedReadError::Backend {
                address,
                detail: "x86 instruction-fetch address overflowed".into(),
            })?;
        if let Some(error) = identity_execute_fault_under_mapping_lock(current) {
            return Err(error);
        }
        let mut byte = [0u8; 1];
        match identity_kernel_copyin_exact_using(current, &mut byte, Some((&reader, &writer))) {
            Ok(()) => {}
            Err(IdentityKernelCopyError::GuestFault {
                address: fault_address,
            }) => {
                if let Some(fault) = IDENTITY_PROTECTIONS.first_access_fault(
                    current,
                    1,
                    carrick_guest_mem::protections::GuestMemoryAccess::Read,
                ) {
                    return Err(identity_checked_read_fault(fault));
                }
                return Err(IdentityCheckedReadError::BusAddress {
                    address: fault_address,
                });
            }
            Err(IdentityKernelCopyError::Backend { address, detail }) => {
                return Err(IdentityCheckedReadError::Backend { address, detail });
            }
        }
        bytes.push(byte[0]);
        match classify(&bytes, address.raw()) {
            Ok(_) => return Ok(bytes),
            Err(carrick_dsr_x86::X86DecodeError::Truncated { .. }) => {}
            Err(_) => return Ok(bytes),
        }
    }
    Ok(bytes)
}

/// Fetch exactly one x86 instruction while preserving typed execute faults.
///
/// Mapping publication marks every live host-file alias `mutable_shared_backing`;
/// private file mappings and ELF payloads are copied into anonymous identity
/// backing before that metadata becomes executable. Therefore, while the host
/// mapping reader is held, a complete executable prefix with no mutable-shared
/// overlap cannot be externally truncated and is safe to copy directly. Shared
/// vnode mappings retain the byte-wise kernel-contained path above so FreeBSD
/// contains past-EOF SIGBUS as EFAULT. Neither route reads a non-executable byte.
fn identity_checked_fetch_x86_instruction(
    address: GuestVa,
) -> Result<Vec<u8>, IdentityCheckedReadError> {
    let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
    let (executable_len, boundary_fault) =
        identity_contiguous_executable_span_under_mapping_lock(address)?;
    if executable_len == 0 {
        return match boundary_fault {
            Some(error) => Err(error),
            None => Err(IdentityCheckedReadError::Backend {
                address,
                detail: "empty executable instruction-fetch span had no boundary fault".into(),
            }),
        };
    }

    if IDENTITY_PROTECTIONS.range_mutable_shared_backing(address.raw(), executable_len) {
        return identity_checked_fetch_x86_instruction_mutable_shared_under_mapping_lock(address);
    }

    let mut copied = [0u8; X86_MAX_INSTRUCTION_LENGTH];
    // SAFETY: every copied byte belongs to the registry-proven executable
    // prefix. The mapping reader excludes Carrick VMA transitions, and the
    // mutable-shared exclusion proves this is anonymous/materialized backing
    // rather than a live vnode alias that an external truncate could invalidate.
    unsafe {
        std::ptr::copy_nonoverlapping(
            address.raw() as usize as *const u8,
            copied.as_mut_ptr(),
            executable_len,
        );
    }
    let copied = &copied[..executable_len];
    match classify(copied, address.raw()) {
        Ok(instruction) => {
            let instruction_len = usize::from(instruction.len);
            copied
                .get(..instruction_len)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| IdentityCheckedReadError::Backend {
                    address,
                    detail: format!(
                        "x86 decoder returned length {instruction_len} from {executable_len} copied bytes"
                    ),
                })
        }
        Err(carrick_dsr_x86::X86DecodeError::Truncated { .. }) => match boundary_fault {
            Some(error) => Err(error),
            None => Ok(copied.to_vec()),
        },
        Err(carrick_dsr_x86::X86DecodeError::Undecodable { .. }) => Ok(copied.to_vec()),
    }
}

/// Copy one exact architectural write into the identity guest mapping while
/// retaining the executable-mutation lease, mapping reader, and complete-range
/// protection/backing classification. The lease is the required cache
/// invalidation hook for executable aliases and remains live through either the
/// direct copy or kernel-contained copyout. Registry faults keep MAPERR/ACCERR
/// precedence; only a still-mapped writable vnode hole is BUS_ADRERR.
fn identity_checked_write_exact(
    memory: &IdentityGuestMemory,
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

fn identity_checked_write_range_under_mapping_lock(
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
fn identity_checked_write_exact_under_mapping_lock(
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

/// Read an arbitrary signal-frame extent under one coherent mapping snapshot,
/// splitting only at the bounded checked-copy seam. The destination is
/// Rust-owned, so a late checked failure cannot expose a partially restored
/// architectural state.
fn identity_checked_read_sigframe(
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
fn identity_checked_write_sigframe(
    memory: &IdentityGuestMemory,
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

struct IdentityXstateMemoryReader;

impl X86XstateMemoryReader for IdentityXstateMemoryReader {
    type Error = IdentityCheckedReadError;

    fn read_exact(&mut self, address: GuestVa, destination: &mut [u8]) -> Result<(), Self::Error> {
        identity_checked_read_exact(address, destination)
    }
}

struct IdentityXstateMemoryWriter<'a> {
    memory: &'a IdentityGuestMemory,
}

impl X86XstateMemoryWriter for IdentityXstateMemoryWriter<'_> {
    type Error = IdentityCheckedWriteError;

    fn write_exact(&mut self, address: GuestVa, source: &[u8]) -> Result<(), Self::Error> {
        identity_checked_write_exact(self.memory, address, source)
    }
}

fn cflow_guest_memory_fault(
    access: cflow::CflowMemoryAccess,
    fault: carrick_guest_mem::protections::GuestMemoryFault,
) -> cflow::CflowError {
    let address = fault.address.raw();
    let kind = match fault.kind {
        carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
            cflow::CflowMemoryFaultKind::Unmapped
        }
        carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
            cflow::CflowMemoryFaultKind::AccessDenied
        }
    };
    match access {
        cflow::CflowMemoryAccess::Read => cflow::CflowError::MemoryRead { address, kind },
        cflow::CflowMemoryAccess::Write => cflow::CflowError::MemoryWrite { address, kind },
    }
}

#[cfg(test)]
fn cflow_raw_memory_fault(
    access: cflow::CflowMemoryAccess,
    address: u64,
    length: usize,
) -> Option<cflow::CflowError> {
    identity_raw_fault_address(address, length).map(|address| match access {
        cflow::CflowMemoryAccess::Read => cflow::CflowError::MemoryRead {
            address,
            kind: cflow::CflowMemoryFaultKind::Unmapped,
        },
        cflow::CflowMemoryAccess::Write => cflow::CflowError::MemoryWrite {
            address,
            kind: cflow::CflowMemoryFaultKind::Unmapped,
        },
    })
}

impl cflow::ControlFlowMemory for IdentityGuestMemory {
    fn read_u64(&mut self, address: u64) -> Result<u64, cflow::CflowError> {
        const LENGTH: usize = std::mem::size_of::<u64>();
        let mut bytes = [0u8; LENGTH];
        identity_checked_read_exact(GuestVa(address), &mut bytes).map_err(|error| match error {
            IdentityCheckedReadError::Fault(fault) => {
                cflow_guest_memory_fault(cflow::CflowMemoryAccess::Read, fault)
            }
            IdentityCheckedReadError::BusAddress { address } => cflow::CflowError::MemoryRead {
                address: address.raw(),
                kind: cflow::CflowMemoryFaultKind::BusAddress,
            },
            IdentityCheckedReadError::Backend { address, detail } => {
                cflow_memory_backend_error(cflow::CflowMemoryAccess::Read, address.raw(), detail)
            }
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), cflow::CflowError> {
        identity_checked_write_exact(self, GuestVa(address), &value.to_le_bytes()).map_err(
            |error| match error {
                IdentityCheckedWriteError::Fault(fault) => {
                    cflow_guest_memory_fault(cflow::CflowMemoryAccess::Write, fault)
                }
                IdentityCheckedWriteError::BusAddress { address } => {
                    cflow::CflowError::MemoryWrite {
                        address: address.raw(),
                        kind: cflow::CflowMemoryFaultKind::BusAddress,
                    }
                }
                IdentityCheckedWriteError::Backend { address, detail } => {
                    cflow_memory_backend_error(
                        cflow::CflowMemoryAccess::Write,
                        address.raw(),
                        detail,
                    )
                }
            },
        )
    }
}

/// A `RegAccess + GuestMemory` view over a live `X86UcontextSnapshot`, so the
/// shared, byte-exact x86-64 `rt_sigframe` builder/restorer
/// ([`X8664GuestArch::build_sigframe`] / [`restore_sigframe`]) drives THIS
/// lane's snapshot directly. Register reads/writes hit the snapshot fields;
/// memory reads/writes are identity (guest VA == host VA). Full x86 signal
/// xstate travels through the architecture-specific batch seam below; the
/// AArch64-shaped per-vector accessors remain deliberately unused.
struct SigframeEngine<'a> {
    snap: &'a mut X86UcontextSnapshot,
    executable_epoch: Option<Arc<ExecutableEpoch>>,
}

impl RegAccess for SigframeEngine<'_> {
    fn get_reg(&self, r: Reg) -> Result<u64, carrick_hal::OsError> {
        Ok(match r {
            Reg::Rax => self.snap.gpr[reg::RAX],
            Reg::Rbx => self.snap.gpr[reg::RBX],
            Reg::Rcx => self.snap.gpr[reg::RCX],
            Reg::Rdx => self.snap.gpr[reg::RDX],
            Reg::Rsi => self.snap.gpr[reg::RSI],
            Reg::Rdi => self.snap.gpr[reg::RDI],
            Reg::Rbp => self.snap.gpr[reg::RBP],
            Reg::Rsp => self.snap.gpr[reg::RSP],
            Reg::R8 => self.snap.gpr[reg::R8],
            Reg::R9 => self.snap.gpr[reg::R9],
            Reg::R10 => self.snap.gpr[reg::R10],
            Reg::R11 => self.snap.gpr[reg::R11],
            Reg::R12 => self.snap.gpr[reg::R12],
            Reg::R13 => self.snap.gpr[reg::R13],
            Reg::R14 => self.snap.gpr[reg::R14],
            Reg::R15 => self.snap.gpr[reg::R15],
            Reg::Rip => self.snap.rip,
            Reg::Rflags => self.snap.rflags,
            // aarch64 register views are never used on this lane.
            _ => 0,
        })
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), carrick_hal::OsError> {
        match r {
            Reg::Rax => self.snap.gpr[reg::RAX] = v,
            Reg::Rbx => self.snap.gpr[reg::RBX] = v,
            Reg::Rcx => self.snap.gpr[reg::RCX] = v,
            Reg::Rdx => self.snap.gpr[reg::RDX] = v,
            Reg::Rsi => self.snap.gpr[reg::RSI] = v,
            Reg::Rdi => self.snap.gpr[reg::RDI] = v,
            Reg::Rbp => self.snap.gpr[reg::RBP] = v,
            Reg::Rsp => self.snap.gpr[reg::RSP] = v,
            Reg::R8 => self.snap.gpr[reg::R8] = v,
            Reg::R9 => self.snap.gpr[reg::R9] = v,
            Reg::R10 => self.snap.gpr[reg::R10] = v,
            Reg::R11 => self.snap.gpr[reg::R11] = v,
            Reg::R12 => self.snap.gpr[reg::R12] = v,
            Reg::R13 => self.snap.gpr[reg::R13] = v,
            Reg::R14 => self.snap.gpr[reg::R14] = v,
            Reg::R15 => self.snap.gpr[reg::R15] = v,
            Reg::Rip => self.snap.rip = v,
            Reg::Rflags => self.snap.rflags = v,
            _ => {}
        }
        Ok(())
    }

    fn get_sys_reg(&self, _r: carrick_hal::SysReg) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }
    fn set_sys_reg(
        &mut self,
        _r: carrick_hal::SysReg,
        _v: u64,
    ) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }
    fn get_vreg(&self, _n: u32) -> Result<u128, carrick_hal::OsError> {
        Ok(0)
    }
    fn set_vreg(&mut self, _n: u32, _v: u128) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }
    fn get_fpcr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }
    fn set_fpcr(&mut self, _v: u64) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }
    fn get_fpsr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }
    fn set_fpsr(&mut self, _v: u64) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }

    fn x86_xstate_capabilities(
        &self,
    ) -> Result<carrick_hal::X86XstateCapabilities, carrick_hal::OsError> {
        let native = carrick_dsr_x86::signal_xstate_capabilities()
            .map_err(|_| carrick_hal::OsError::from_raw(libc::EIO))?;
        let mut components = [carrick_hal::X86XstateComponent::default(); 64];
        for (destination, source) in components.iter_mut().zip(native.components) {
            *destination = carrick_hal::X86XstateComponent::new(source.offset, source.size);
        }
        Ok(carrick_hal::X86XstateCapabilities {
            supported_features: native.supported_features,
            standard_size: native.standard_size,
            mxcsr_mask: native.mxcsr_mask,
            components,
        })
    }

    fn save_x86_signal_xstate(
        &mut self,
    ) -> Result<carrick_hal::X86SignalXstate, carrick_hal::OsError> {
        let (bytes, xfeatures, virtual_pkru, virtual_x87_fcs, virtual_x87_fds) = self
            .snap
            .export_signal_xstate()
            .map_err(|_| carrick_hal::OsError::from_raw(libc::EIO))?;
        Ok(carrick_hal::X86SignalXstate {
            bytes,
            xfeatures,
            virtual_pkru,
            virtual_x87_fcs,
            virtual_x87_fds,
        })
    }

    fn restore_x86_signal_xstate(
        &mut self,
        state: &carrick_hal::X86SignalXstate,
    ) -> Result<(), carrick_hal::OsError> {
        self.snap
            .restore_signal_xstate(
                &state.bytes,
                state.xfeatures,
                state.virtual_pkru,
                state.virtual_x87_fcs,
                state.virtual_x87_fds,
            )
            .map_err(|_| carrick_hal::OsError::from_raw(libc::EINVAL))
    }
}

fn sigframe_guest_memory_error(address: u64, length: usize) -> carrick_guest_mem::MemoryError {
    carrick_guest_mem::MemoryError::OutOfBounds { address, length }
}

impl GuestMemory for SigframeEngine<'_> {
    /// Gate the sigframe build/restore on the SAME syscall-path protections the
    /// identity backend enforces: `build_sigframe` writes the frame through the
    /// permission-checked `write_bytes`, so a SA_ONSTACK handler whose alternate
    /// stack is `PROT_NONE`/unmapped (tracked no-access) makes that write EFAULT
    /// → `build_sigframe` returns Err → the caller force-`SIGSEGV`s the guest,
    /// matching Linux `force_sigsegv` (`sigbadstack`).
    fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
        Some(&IDENTITY_PROTECTIONS)
    }

    fn read_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let mut bytes = vec![0u8; length];
        identity_checked_read_sigframe(GuestVa(address), &mut bytes)
            .map_err(|_| sigframe_guest_memory_error(address, length))?;
        Ok(bytes)
    }

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        let mut bytes = vec![0u8; length];
        identity_checked_read_sigframe(GuestVa(address), &mut bytes)
            .map_err(|_| sigframe_guest_memory_error(address, length))?;
        Ok(bytes)
    }

    fn write_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let memory = IdentityGuestMemory {
            executable_epoch: self.executable_epoch.as_ref().map(Arc::clone),
            mapping_failure: None,
        };
        identity_checked_write_sigframe(&memory, GuestVa(address), bytes)
            .map_err(|_| sigframe_guest_memory_error(address, bytes.len()))
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        let memory = IdentityGuestMemory {
            executable_epoch: self.executable_epoch.as_ref().map(Arc::clone),
            mapping_failure: None,
        };
        identity_checked_write_sigframe(&memory, GuestVa(address), bytes)
            .map_err(|_| sigframe_guest_memory_error(address, bytes.len()))
    }
}

/// Deliver `signum` (a LINUX signal number) into the guest's registered
/// handler by building the x86-64 `rt_sigframe` on the guest stack and
/// redirecting `snapshot` to the handler (SA_SIGINFO ABI: rdi=signum,
/// rsi=&siginfo, rdx=&ucontext). Returns `Ok(true)` when a handler ran,
/// `Ok(false)` when the guest installed no handler (caller applies the
/// default action), or `Err(())` when the frame could not be written to the
/// guest stack (Linux force_sigsegv — caller dies by SIGSEGV).
#[allow(clippy::too_many_arguments)]
fn deliver_x86_signal(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    signum: i32,
    fault_siginfo: Option<(i32, u64)>,
    queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
    pending_syscall_retval: Option<i64>,
    interrupted_pc: Option<u64>,
    orig_rax: u64,
    restart_syscall: bool,
) -> Result<bool, ()> {
    let dispatcher = &shared.dispatcher;
    let Some(action) = dispatcher.registered_signal_handler(signum) else {
        return Ok(false);
    };
    let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
        dispatcher.signal_altstack(tid)
    } else {
        None
    };
    let sa_restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
        action.sa_restorer
    } else {
        0
    };
    // Blocks the signal (+ sa_mask) for the handler and applies SA_RESETHAND,
    // returning the pre-handler mask to embed in the frame (restored by
    // rt_sigreturn).
    let saved_sigmask = dispatcher.enter_signal_handler(tid, signum, action).raw();
    let rflags = snapshot.rflags;
    let params = carrick_hal::sigframe::InjectParams {
        signum,
        handler: action.sa_handler,
        sa_restorer,
        pending_syscall_retval,
        interrupted_pc,
        altstack,
        saved_sigmask,
        fault_siginfo,
        queued_siginfo,
        restart_syscall,
        pstate_source: rflags,
        orig_x0: orig_rax,
        fault_esr: 0,
        fpsimd_enabled: true,
        sigreturn_trampoline_base: shared.current_image().sigreturn_trampoline,
    };
    let mut engine = SigframeEngine {
        snap: snapshot,
        executable_epoch: Some(Arc::clone(&shared.executable_epoch)),
    };
    match X8664GuestArch::build_sigframe(&mut engine, params) {
        Ok(_) => Ok(true),
        Err(_) => Err(()),
    }
}

/// Restore guest state from the x86-64 `rt_sigframe` at the guest stack on
/// `rt_sigreturn(2)`, restore the saved signal mask, and return the resume RIP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SynchronousFaultDelivery {
    RetryAt(u64),
    /// The final guest-visible terminating signal. A failed frame build forces
    /// SIGSEGV even when the original synchronous fault was SIGBUS.
    Fatal(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SynchronousFaultTermination {
    Blocked,
    DefaultAction,
    FrameBuildFailed,
}

fn synchronous_fault_termination<F>(
    blocked: bool,
    deliver_handler: F,
) -> Option<SynchronousFaultTermination>
where
    F: FnOnce() -> Result<bool, ()>,
{
    if blocked {
        return Some(SynchronousFaultTermination::Blocked);
    }
    match deliver_handler() {
        Ok(true) => None,
        Ok(false) => Some(SynchronousFaultTermination::DefaultAction),
        Err(()) => Some(SynchronousFaultTermination::FrameBuildFailed),
    }
}

fn synchronous_fault_final_signum(
    original_signum: i32,
    termination: SynchronousFaultTermination,
) -> i32 {
    match termination {
        SynchronousFaultTermination::Blocked | SynchronousFaultTermination::DefaultAction => {
            original_signum
        }
        SynchronousFaultTermination::FrameBuildFailed => crate::linux_abi::LINUX_SIGSEGV,
    }
}

/// Deliver a retryable synchronous signal at the still-unexecuted guest
/// instruction. Instruction fetch, translated-code host faults, checked control
/// flow, and sensitive-instruction emulation use this path so handler/default
/// action and forced termination cannot drift. Callers apply the returned final
/// signum to both exit status and fork-child signal death. A blocked synchronous
/// signal terminates immediately instead of being queued; `rt_sigreturn` restores
/// `interrupted_pc` only after successful handler
/// injection, causing an exact retry.
#[allow(clippy::too_many_arguments)]
fn deliver_synchronous_x86_fault(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    interrupted_pc: u64,
    signum: i32,
    code: i32,
    address: u64,
) -> SynchronousFaultDelivery {
    snapshot.rip = interrupted_pc;
    let termination =
        synchronous_fault_termination(shared.dispatcher.signal_blocked(tid, signum), || {
            deliver_x86_signal(
                shared,
                tid,
                snapshot,
                signum,
                Some((code, address)),
                None,
                None,
                Some(interrupted_pc),
                0,
                false,
            )
        });
    let Some(termination) = termination else {
        return SynchronousFaultDelivery::RetryAt(snapshot.rip);
    };
    SynchronousFaultDelivery::Fatal(synchronous_fault_final_signum(signum, termination))
}

fn deliver_x86_instruction_fetch_error(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    interrupted_pc: u64,
    error: IdentityCheckedReadError,
) -> Result<SynchronousFaultDelivery, String> {
    let (signum, code, address) = match error {
        IdentityCheckedReadError::Fault(fault) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            (crate::linux_abi::LINUX_SIGSEGV, code, fault.address.raw())
        }
        IdentityCheckedReadError::BusAddress { address } => (
            crate::linux_abi::LINUX_SIGBUS,
            crate::linux_abi::LINUX_BUS_ADRERR,
            address.raw(),
        ),
        IdentityCheckedReadError::Backend { address, detail } => {
            return Err(format!(
                "native x86 instruction fetch at guest PC 0x{interrupted_pc:x} failed at 0x{:x}: {detail}",
                address.raw()
            ));
        }
    };
    Ok(deliver_synchronous_x86_fault(
        shared,
        tid,
        snapshot,
        interrupted_pc,
        signum,
        code,
        address,
    ))
}

fn restore_x86_sigreturn(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<u64, ()> {
    let mut engine = SigframeEngine {
        snap: snapshot,
        executable_epoch: Some(Arc::clone(&shared.executable_epoch)),
    };
    let restore = X8664GuestArch::restore_sigframe(&mut engine, true).map_err(|_| ())?;
    shared
        .dispatcher
        .restore_signal_mask(tid, carrick_abi::SigSet::from_raw(restore.sigmask));
    Ok(snapshot.rip)
}

/// A minimal [`carrick_hal::SyscallTrap`] over the live snapshot, just enough to
/// drive the SHARED [`crate::vcpu_loop::deliver_pending_signal`] — which owns
/// all the async-delivery policy (blocked/ignored signals, queued siginfo from
/// rt_sigqueueinfo, SI_USER synthesis, child-exit siginfo, SA_RESTART). Only
/// `inject_signal`, `restore_from_sigframe`, and `last_syscall_nr` are
/// exercised; the VMM-shaped methods are never reached on this lane.
struct NativeX86Trap<'a> {
    snap: &'a mut X86UcontextSnapshot,
    last_syscall_nr: Option<u64>,
    orig_rax: u64,
    sigreturn_trampoline: u64,
    executable_epoch: Arc<ExecutableEpoch>,
}

impl carrick_hal::SyscallTrap for NativeX86Trap<'_> {
    fn next_syscall(&mut self) -> Result<Option<carrick_hal::RawSyscall>, carrick_hal::TrapError> {
        Err(carrick_hal::TrapError::UnsupportedPlatform)
    }
    fn current_pc(&self) -> Result<u64, carrick_hal::TrapError> {
        Ok(self.snap.rip)
    }
    fn complete_syscall(&mut self, _return_value: i64) -> Result<(), carrick_hal::TrapError> {
        Ok(())
    }
    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, carrick_hal::TrapError> {
        Err(carrick_hal::TrapError::UnsupportedPlatform)
    }
    fn execve_into(
        &mut self,
        _new_image: &carrick_mem::memory::AddressSpace,
    ) -> Result<(), carrick_hal::TrapError> {
        Err(carrick_hal::TrapError::UnsupportedPlatform)
    }
    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }
    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), carrick_hal::TrapError> {
        // Real x86 `syscall` stashes the user return RIP in RCX; the shared
        // builder reads RCX as the syscall-boundary resume_rip. The DSR gateway
        // instead leaves the resume VA in `snapshot.rip` and does NOT clobber
        // RCX, so mirror hardware here (only on the syscall-boundary path,
        // where interrupted_pc is None) — otherwise the handler returns through
        // a garbage RIP.
        if interrupted_pc.is_none() {
            self.snap.gpr[reg::RCX] = self.snap.rip;
        }
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source: self.snap.rflags,
            orig_x0: self.orig_rax,
            fault_esr: 0,
            fpsimd_enabled: true,
            sigreturn_trampoline_base: self.sigreturn_trampoline,
        };
        let mut engine = SigframeEngine {
            snap: self.snap,
            executable_epoch: Some(Arc::clone(&self.executable_epoch)),
        };
        X8664GuestArch::build_sigframe(&mut engine, params).map(|_| ())
    }
    fn restore_from_sigframe(&mut self) -> Result<u64, carrick_hal::TrapError> {
        let mut engine = SigframeEngine {
            snap: self.snap,
            executable_epoch: Some(Arc::clone(&self.executable_epoch)),
        };
        let restore = X8664GuestArch::restore_sigframe(&mut engine, true)?;
        Ok(restore.saved_pc)
    }
}

/// Deliver any pending, deliverable signals into the guest at a syscall-return
/// safe point (reuses the shared policy engine). If a default-action signal has
/// no handler, terminates/stops the process accordingly. Mutates `snapshot` to
/// enter a handler when one is delivered.
/// Deliver pending, deliverable signals at a syscall-return safe point.
/// Returns `Some(signum)` if a default-action fatal signal with no guest handler
/// must TERMINATE this guest — the caller routes it as [`Step::SignalDeath`] so
/// the run loop can die-by-signal (fork child) or report `exit=128+signum`
/// (top-level) rather than the runner dying by the signal itself. `None` means
/// continue (nothing pending, or a handler was entered — `snapshot.rip` updated).
fn run_pending_signals(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    last_retval: Option<i64>,
    syscall_nr: Option<u64>,
    orig_rax: u64,
) -> Option<i32> {
    run_pending_signals_at(
        shared,
        tid,
        snapshot,
        last_retval,
        syscall_nr,
        orig_rax,
        None,
    )
}

fn run_pending_signals_at(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    last_retval: Option<i64>,
    syscall_nr: Option<u64>,
    orig_rax: u64,
    interrupted_pc: Option<u64>,
) -> Option<i32> {
    drain_native_child_exit_watches(false);
    let mut trap = NativeX86Trap {
        snap: snapshot,
        last_syscall_nr: syscall_nr,
        orig_rax,
        sigreturn_trampoline: shared.current_image().sigreturn_trampoline,
        executable_epoch: Arc::clone(&shared.executable_epoch),
    };
    let action = crate::vcpu_loop::deliver_pending_signal(
        &mut trap,
        &shared.dispatcher,
        last_retval,
        tid,
        interrupted_pc,
    );
    match action {
        Ok(Some(action)) => {
            if let Some(sig) = action.stop_signal {
                crate::exec_helpers::stop_by_signal(sig);
            }
            if let Some(sig) = action.term_signal {
                // Terminating signal, no handler: hand the decision (die vs
                // report) up to the run loop, which knows `forked`.
                return Some(sig);
            }
        }
        Ok(None) => {}
        // A pending signal whose guest-controlled frame cannot be built is a
        // Linux force-SIGSEGV outcome. Never swallow the error and continue
        // with a half-entered handler or unprotected interrupted state.
        Err(_) => return Some(crate::linux_abi::LINUX_SIGSEGV),
    }
    None
}

/// ASYNC-SIGNAL-SAFE host handler for the four "pumped" standard signals
/// (SIGHUP/SIGINT/SIGQUIT/SIGTERM). On the VMM lanes these are owned by the
/// kick-backend signal pump, which catches the host signal and routes it into
/// the guest; the native lane has NO pump, so without this handler a sibling
/// guest process's cross-process `kill(child, SIGINT)` (which the dispatcher
/// delivers as a direct `libc::kill` — these signals are is_claimed-excluded
/// from the routed-handler mirror AND, outside a pid namespace, from the xsig
/// ring route) takes the HOST default action and TERMINATES the receiver
/// instead of running its guest handler (`pauseinterrupt2`, `waitrestart`,
/// `waitsiblingsigchld`). Mirrors `carrick_signal_core`'s `shared_routed_handler`
/// verbatim: translate host→Linux signum, record the sender pid, publish the
/// signal process-directed pending, and poke so a parked run-loop wait breaks.
/// The generic `deliver_pending_signal` then honors the guest disposition
/// (handler → inject frame; SIG_IGN → drop; SIG_DFL → default action, i.e.
/// die-by-signal for a fork child so its parent's wait4 sees WIFSIGNALED).
extern "C" fn native_pumped_signal_handler(
    host_sig: i32,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    let linux_sig = crate::host_signal::host_to_linux_signum(host_sig);
    if !info.is_null() {
        // One atomic store — async-signal-safe.
        let si_pid = unsafe { (*info).si_pid() };
        carrick_signal_core::record_sender(linux_sig, si_pid);
    }
    carrick_signal_core::publish_process_signal(linux_sig);
    // No pump on this lane: the host-signal delivery itself EINTRs the parked
    // wait, and the io_wait predicate re-checks pending; the poke matches the
    // nudge handler and is a harmless no-op when no self-pipe is armed.
    carrick_hal::signal_pump::poke();
}

static NATIVE_CHILD_EXIT_DIRTY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Host SIGCHLD is only a wakeup. The requested Linux clone exit signal lives
/// in the child-watch record and may be SIGCHLD, another signal, or zero; an
/// async handler cannot safely lock that table or call waitid.
extern "C" fn native_sigchld_handler(_sig: i32) {
    NATIVE_CHILD_EXIT_DIRTY.store(true, std::sync::atomic::Ordering::Release);
    carrick_hal::signal_pump::poke();
}

fn drain_native_child_exit_watches(force: bool) {
    if force || NATIVE_CHILD_EXIT_DIRTY.swap(false, std::sync::atomic::Ordering::AcqRel) {
        carrick_hal::signal_pump::publish_exited_child_watches();
    }
}

/// Unblock the host signals Carrick owns as runtime transport after `fork`.
///
/// The guest signal mask is virtual and is migrated separately in
/// `native_after_fork_child`; it must never control these host-only wakeups. A
/// host `fork` can nevertheless inherit a transiently blocked mask from the
/// forking thread. GNU make exposed this under `-j8`: the child make inherited
/// blocked SIGCHLD/kick/nudge signals, accumulated eight zombies, and slept in
/// the bounded ppoll backstop forever because the pending SIGCHLD handler could
/// not run. Reset only Carrick-owned transport signals, preserving unrelated
/// host mask state and the guest-visible mask kept by the dispatcher.
fn native_transport_signal_set() -> libc::sigset_t {
    // SAFETY: zeroed sigset followed by libc initialization and valid host
    // signal insertion.
    unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        for signal in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGCHLD,
            FREEBSD_NATIVE_EXIT_KICK_SIGNAL,
            FREEBSD_NATIVE_EXIT_KICK_SIGNAL + 1,
        ] {
            libc::sigaddset(&mut signals, signal);
        }
        signals
    }
}

fn block_native_transport_signals_for_fork() -> std::io::Result<libc::sigset_t> {
    let signals = native_transport_signal_set();
    // SAFETY: current-thread host mask update with initialized sets. This call
    // is immediately adjacent to fork while every snapshot guard is held.
    unsafe {
        let mut previous: libc::sigset_t = std::mem::zeroed();
        if libc::sigprocmask(libc::SIG_BLOCK, &signals, &mut previous) != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(previous)
        }
    }
}

fn restore_native_host_signal_mask(mask: &libc::sigset_t) {
    // SAFETY: `mask` was returned by sigprocmask for this pthread.
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, mask, std::ptr::null_mut());
    }
}

fn unblock_native_transport_signals_after_fork() {
    let signals = native_transport_signal_set();
    // SAFETY: valid host signal numbers and a current-thread sigprocmask update.
    // `sigprocmask` is async-signal-safe and therefore valid in the post-fork
    // child before it returns to ordinary runtime execution.
    unsafe {
        libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut());
    }
}

/// Install guest signal routing on host numbers. Ordinary process signals can
/// publish directly; SIGCHLD uses the deferred child-watch scanner above so the
/// guest receives the clone-requested exit signal rather than a hardcoded CHLD.
fn install_native_pumped_handlers() {
    for &linux_sig in &[
        carrick_abi::LINUX_SIGHUP,
        carrick_abi::LINUX_SIGINT,
        carrick_abi::LINUX_SIGQUIT,
        carrick_abi::LINUX_SIGTERM,
    ] {
        let host = crate::host_signal::linux_to_host_signum(linux_sig);
        // SAFETY: zeroed sigaction = "no flags, empty mask"; we set a valid
        // `extern "C"` SA_SIGINFO handler on a valid host signum.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = native_pumped_signal_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(host, &action, std::ptr::null_mut());
        }
    }

    // SAFETY: valid handler and host SIGCHLD. No SA_RESTART: the interrupted
    // wait reaches a safe point that resolves the child watch with waitid.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = native_sigchld_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_NOCLDSTOP;
        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
    }
}

/// A loaded static-pie ELF in the host address space (guest VA == host VA).
struct LoadedImage {
    /// Every host mapping owned by this image candidate/live image. Ownership
    /// moves into the eventual `Arc<LoadedImage>`; individual Arc clones never
    /// own mappings and therefore cannot tear a live image down accidentally.
    mappings: Vec<NativeMapping>,
    entry: u64,
    stack: u64,
    stack_len: usize,
    rsp: u64,
    /// Kept mapped for the lifetime of the run (argv/AT_RANDOM scratch); its
    /// tail also holds the rt_sigreturn trampoline.
    scratch: u64,
    scratch_len: usize,
    /// Guest VA of the `mov $15,%eax; syscall` rt_sigreturn trampoline, used as
    /// a signal frame's return address when the handler had no `sa_restorer`.
    sigreturn_trampoline: u64,
    /// Guest VA where the synthesized x86-64 vDSO ELF is mapped (published as
    /// `AT_SYSINFO_EHDR`), or 0 if the vDSO could not be mapped. The vvar page
    /// lives at the fixed `LINUX_VVAR_BASE` the vDSO code references directly.
    #[cfg_attr(not(test), allow(dead_code))]
    vdso_base: u64,
    /// The page-rounded [start, end) VA ranges of the mapped PT_LOAD segments,
    /// sorted and coalesced. The reserved span can contain UNMAPPED gaps
    /// between segments; the typed instruction fetcher consults live VMA
    /// protections and never constructs a Rust slice across such a gap.
    segments: Vec<(u64, u64)>,
    /// Requested Linux R/W/X flags for each loader-owned mapping. Unlike
    /// `segments`, these are not coalesced because adjacent PT_LOADs commonly
    /// carry different permissions.
    segment_protections: Vec<(u64, u64, u64)>,
}

/// Reset the identity backend's syscall-pointer gate for a fresh process image.
/// Start with the complete low-canonical userspace range unmapped, then publish
/// only the loader-owned image/stack plus the persistent heap+mmap arenas. Every
/// later guest mmap/mprotect/munmap updates the same interval set through the
/// `GuestMemory` hooks. This makes an arbitrary canonical-but-unmapped pointer
/// EFAULT before Rust constructs a host slice.
fn protect_existing_identity_range(
    memory: &IdentityGuestMemory,
    protections: &carrick_guest_mem::protections::MemoryProtections,
    address: u64,
    len: usize,
    prot: u64,
) -> Result<(), MemoryError> {
    let requested_executable = prot & crate::linux_abi::LINUX_PROT_EXEC != 0;
    let (_mutation, _mapping_guard) =
        memory.mapping_write_for_mutation(address, len, requested_executable)?;
    let readable =
        prot & (crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC) != 0;
    let writable = prot & crate::linux_abi::LINUX_PROT_WRITE != 0;
    let host_prot = match (readable, writable) {
        (_, true) => libc::PROT_READ | libc::PROT_WRITE,
        (true, false) => libc::PROT_READ,
        (false, false) => libc::PROT_NONE,
    };
    if len != 0
        && host_mprotect(
            NativeMappingOperation::IdentityProtection,
            address as *mut libc::c_void,
            len,
            host_prot,
        ) != 0
    {
        return Err(MemoryError::HostMap(format!(
            "publish native identity protection at 0x{address:x} for {len} bytes failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    protections.set_mapping_protection(address, len, prot == 0, !writable);
    protections.set_executable(address, len, requested_executable);
    Ok(())
}

fn reset_identity_vmas_with_registry(
    image: &LoadedImage,
    protections: &carrick_guest_mem::protections::MemoryProtections,
) -> Result<(), MemoryError> {
    const USER_START: u64 = 0x1_0000;
    const USER_END_EXCLUSIVE: u64 = 1 << 47;
    let user_len = (USER_END_EXCLUSIVE - USER_START) as usize;
    protections.reset_to_unmapped(USER_START, user_len);
    let memory = IdentityGuestMemory::uncoordinated();
    let publication = (|| {
        for &(start, end, prot) in &image.segment_protections {
            protect_existing_identity_range(
                &memory,
                protections,
                start,
                (end - start) as usize,
                prot,
            )?;
        }
        protect_existing_identity_range(
            &memory,
            protections,
            image.stack,
            image.stack_len,
            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
        )?;
        protections.set_mapping_protection(LINUX_HEAP_BASE, LINUX_HEAP_SIZE as usize, false, false);
        protections.set_mapping_protection(
            LINUX_MMAP_BASE,
            mmap_arena_size() as usize,
            false,
            false,
        );
        // vvar and vDSO are explicit entries in `segment_protections`; the
        // vvar entry is published read-only (`no_write=true`) only after its
        // checked host PROT_READ transition succeeds.
        Ok(())
    })();
    if publication.is_err() {
        // A partially published candidate must never become a permissive VMA
        // registry. The terminal exec path remains stopped and the complete
        // user range returns to the fail-closed state.
        protections.reset_to_unmapped(USER_START, user_len);
    }
    publication
}

fn reset_identity_vmas(image: &LoadedImage) -> Result<(), MemoryError> {
    reset_identity_vmas_with_registry(image, &IDENTITY_PROTECTIONS)
}

impl LoadedImage {
    /// Unmap everything the loader mapped. Each mapping records successful
    /// teardown independently, so retries after a partial host failure are
    /// idempotent. Field `Drop` remains the rollback backstop.
    fn teardown(&self) -> Result<(), RuntimeError> {
        teardown_native_mappings(&self.mappings)
    }
}

const PAGE: u64 = 4096;
const GUEST_STACK_LEN: usize = 8 * 1024 * 1024;
/// Per-run JIT code-cache size. In the single-thread case one guest thread
/// owns the whole span; with guest threads it is carved into per-thread slices
/// (see `run_static_x86_elf`).
const CODE_CACHE_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct X86VvarClock {
    frequency: u64,
    realtime_off_ns: u64,
    monotonic_off_ns: u64,
}

fn freebsd_sysctl_i32(name: &std::ffi::CStr) -> Option<i32> {
    let mut value = 0i32;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: `name` is NUL-terminated; output points to a writable i32 and
    // `len` advertises its exact size.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut i32).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<i32>()).then_some(value)
}

fn tsc_vdso_is_safe(invariant_tsc: i32, smp_tsc: i32) -> bool {
    invariant_tsc != 0 && smp_tsc != 0
}

fn freebsd_tsc_vdso_is_safe() -> bool {
    let invariant = freebsd_sysctl_i32(c"kern.timecounter.invariant_tsc").unwrap_or(0);
    let smp = freebsd_sysctl_i32(c"kern.timecounter.smp_tsc").unwrap_or(0);
    tsc_vdso_is_safe(invariant, smp)
}

fn freebsd_tsc_frequency() -> Option<u64> {
    let mut frequency = 0u64;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: the name is NUL-terminated; output points to a writable u64 and
    // `len` advertises its exact size. FreeBSD exports this on amd64 when TSC
    // is available, independently of the selected host timecounter.
    let rc = unsafe {
        libc::sysctlbyname(
            c"machdep.tsc_freq".as_ptr(),
            (&mut frequency as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len == std::mem::size_of::<u64>() && frequency != 0).then_some(frequency)
}

fn host_clock_ns(clock: libc::clockid_t) -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid output timespec.
    (unsafe { libc::clock_gettime(clock, &mut value) } == 0).then(|| {
        (value.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(value.tv_nsec as u64)
    })
}

fn tsc_ns(tsc: u64, frequency: u64) -> u64 {
    ((tsc as u128 * 1_000_000_000u128) / frequency as u128) as u64
}

fn tsc_clock_offset(clock: libc::clockid_t, frequency: u64) -> Option<u64> {
    // Bracket clock_gettime with TSC reads and use their midpoint. This bounds
    // calibration error to half the host call latency while retaining the exact
    // frequency FreeBSD reports for this virtual/physical CPU.
    let before = unsafe { std::arch::x86_64::_rdtsc() };
    let clock_ns = host_clock_ns(clock)?;
    let after = unsafe { std::arch::x86_64::_rdtsc() };
    let midpoint = before.wrapping_add(after.wrapping_sub(before) / 2);
    Some(clock_ns.wrapping_sub(tsc_ns(midpoint, frequency)))
}

fn calibrate_x86_vvar_clock() -> Option<X86VvarClock> {
    // A frequency alone does not make TSC a valid clocksource. FreeBSD guests
    // commonly expose `machdep.tsc_freq` while selecting kvmclock and marking
    // TSC non-invariant/non-SMP-safe; those counters can move backwards after
    // a host-vCPU migration. Leave frequency zero in that case so the vDSO's
    // built-in Linux syscall fallback supplies coherent host-clock semantics.
    if !freebsd_tsc_vdso_is_safe() {
        return None;
    }
    let frequency = freebsd_tsc_frequency()?;
    Some(X86VvarClock {
        frequency,
        realtime_off_ns: tsc_clock_offset(libc::CLOCK_REALTIME, frequency)?,
        monotonic_off_ns: tsc_clock_offset(libc::CLOCK_MONOTONIC, frequency)?,
    })
}

fn stamp_x86_vvar(vvar: *mut u8) -> Option<X86VvarClock> {
    let clock = calibrate_x86_vvar_clock()?;
    for (offset, value) in [
        (crate::vdso::VVAR_OFF_FREQ, clock.frequency),
        (crate::vdso::VVAR_OFF_REALTIME_OFF_NS, clock.realtime_off_ns),
        (
            crate::vdso::VVAR_OFF_MONOTONIC_OFF_NS,
            clock.monotonic_off_ns,
        ),
    ] {
        // SAFETY: the caller provides the freshly mapped writable vvar page;
        // every published field is an aligned u64 wholly inside that page.
        unsafe { vvar.add(offset).cast::<u64>().write(value) };
    }
    Some(clock)
}

fn map_prot_at(
    operation: NativeMappingOperation,
    len: usize,
    prot: i32,
    fixed_at: Option<u64>,
    reservation: FixedRwReservation,
) -> *mut u8 {
    let (addr, mut flags) = match fixed_at {
        Some(a) => (
            a as *mut libc::c_void,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
        ),
        None => (std::ptr::null_mut(), libc::MAP_PRIVATE | libc::MAP_ANON),
    };
    if fixed_at.is_some() && reservation == FixedRwReservation::Exclusive {
        flags |= libc::MAP_EXCL;
    }
    host_mmap(operation, addr, len, prot, flags, -1, 0).cast()
}

const NATIVE_MAPPING_LIVE: u8 = 0;
const NATIVE_MAPPING_TEARING_DOWN: u8 = 1;
const NATIVE_MAPPING_UNMAPPED: u8 = 2;

/// Exclusive ownership of one native host mapping. It is deliberately not
/// cloneable: ownership moves from the loader transaction into `LoadedImage`,
/// while `Arc<LoadedImage>` clones only share that one owner.
struct NativeMapping {
    base: u64,
    len: usize,
    state: std::sync::atomic::AtomicU8,
    operation: NativeMappingOperation,
    label: &'static str,
}

impl NativeMapping {
    fn claim(
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

    fn map_anonymous(
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        fixed_at: Option<u64>,
        label: &'static str,
    ) -> Result<Self, RuntimeError> {
        let mapped = map_prot_at(
            operation,
            len,
            prot,
            fixed_at,
            FixedRwReservation::Exclusive,
        );
        if mapped.cast::<libc::c_void>() == libc::MAP_FAILED {
            return Err(RuntimeError::Unsupported(format!(
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
            return Err(RuntimeError::Unsupported(format!(
                "map native {label} requested 0x{expected:x} but returned 0x{returned:x}{detail}"
            )));
        }
        Ok(mapping)
    }

    /// Optional fixed mappings (vvar/vDSO) may be unavailable, but a misplaced
    /// successful allocation is still owned and must be explicitly rolled back.
    fn map_optional_fixed(
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        expected: u64,
        label: &'static str,
    ) -> Result<Option<Self>, RuntimeError> {
        let mapped = map_prot_at(
            operation,
            len,
            prot,
            Some(expected),
            FixedRwReservation::Exclusive,
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

    fn protect(&self, operation: NativeMappingOperation, prot: i32) -> Result<(), RuntimeError> {
        if self.state.load(std::sync::atomic::Ordering::Acquire) != NATIVE_MAPPING_LIVE {
            return Err(RuntimeError::Unsupported(format!(
                "protect non-live native {} ({:?})",
                self.label, self.operation
            )));
        }
        if host_mprotect(operation, self.base as *mut libc::c_void, self.len, prot) != 0 {
            return Err(RuntimeError::Unsupported(format!(
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
    fn relinquish_to_vma(&mut self) {
        *self.state.get_mut() = NATIVE_MAPPING_UNMAPPED;
    }

    fn teardown(&self) -> Result<(), RuntimeError> {
        match self.state.compare_exchange(
            NATIVE_MAPPING_LIVE,
            NATIVE_MAPPING_TEARING_DOWN,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(NATIVE_MAPPING_UNMAPPED) => return Ok(()),
            Err(_) => {
                return Err(RuntimeError::Unsupported(format!(
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
            Err(RuntimeError::Unsupported(format!(
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

fn teardown_native_mappings_collect(mappings: &[NativeMapping]) -> Vec<String> {
    mappings
        .iter()
        .filter_map(|mapping| mapping.teardown().err().map(|error| error.to_string()))
        .collect()
}

fn teardown_native_mappings(mappings: &[NativeMapping]) -> Result<(), RuntimeError> {
    let errors = teardown_native_mappings_collect(mappings);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native mapping teardown failed: {}",
            errors.join("; ")
        )))
    }
}

/// Explicit ownership transaction for a not-yet-published native address
/// space. Every acquired mapping is range-checked against prior independent
/// owners. All loader errors call `rollback`; `NativeMapping::Drop` is only the
/// fail-stop backstop if a future call site bypasses that protocol.
struct NativeMappingTransaction {
    label: &'static str,
    mappings: Vec<NativeMapping>,
}

impl NativeMappingTransaction {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            mappings: Vec::new(),
        }
    }

    fn acquire(&mut self, mapping: NativeMapping) -> Result<usize, RuntimeError> {
        let Some(end) = mapping.base.checked_add(mapping.len as u64) else {
            let primary = RuntimeError::Unsupported(format!(
                "native {} range overflows at 0x{:x} for {} bytes",
                mapping.label, mapping.base, mapping.len
            ));
            let cleanup = mapping.teardown().err();
            return Err(match cleanup {
                Some(error) => RuntimeError::Unsupported(format!(
                    "{primary}; overflowing mapping rollback failed: {error}"
                )),
                None => primary,
            });
        };
        if let Some(existing) = self.mappings.iter().find(|existing| {
            let existing_end = existing.base.saturating_add(existing.len as u64);
            mapping.base < existing_end && existing.base < end
        }) {
            let primary = RuntimeError::Unsupported(format!(
                "native candidate ranges overlap: {} [0x{:x},0x{end:x}) and {} [0x{:x},0x{:x})",
                mapping.label,
                mapping.base,
                existing.label,
                existing.base,
                existing.base.saturating_add(existing.len as u64)
            ));
            let cleanup = mapping.teardown().err();
            return Err(match cleanup {
                Some(error) => RuntimeError::Unsupported(format!(
                    "{primary}; overlapping mapping rollback failed: {error}"
                )),
                None => primary,
            });
        }
        let index = self.mappings.len();
        self.mappings.push(mapping);
        Ok(index)
    }

    fn map_anonymous(
        &mut self,
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        fixed_at: Option<u64>,
        label: &'static str,
    ) -> Result<usize, RuntimeError> {
        let mapping = NativeMapping::map_anonymous(operation, len, prot, fixed_at, label)?;
        self.acquire(mapping)
    }

    fn map_optional_fixed(
        &mut self,
        operation: NativeMappingOperation,
        len: usize,
        prot: i32,
        expected: u64,
        label: &'static str,
    ) -> Result<Option<usize>, RuntimeError> {
        NativeMapping::map_optional_fixed(operation, len, prot, expected, label)?
            .map(|mapping| self.acquire(mapping))
            .transpose()
    }

    fn mapping(&self, index: usize) -> &NativeMapping {
        &self.mappings[index]
    }

    fn teardown_mapping(&mut self, index: usize) -> Result<(), RuntimeError> {
        self.mappings[index].teardown()?;
        self.mappings.remove(index);
        Ok(())
    }

    fn commit(mut self) -> Vec<NativeMapping> {
        std::mem::take(&mut self.mappings)
    }

    fn commit_to_vma(mut self) {
        for mapping in &mut self.mappings {
            mapping.relinquish_to_vma();
        }
    }

    fn rollback(self, primary: RuntimeError) -> RuntimeError {
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
        if rollback_errors.is_empty() {
            primary
        } else {
            RuntimeError::Unsupported(format!(
                "{primary}; {} rollback failed: {}",
                self.label,
                rollback_errors.join("; ")
            ))
        }
    }
}

fn map_fixed_replacement(
    operation: NativeMappingOperation,
    address: u64,
    len: usize,
    prot: i32,
    label: &'static str,
) -> Result<(), RuntimeError> {
    // PT_LOAD pages intentionally replace bytes inside the reservation whose
    // sole owner remains the surrounding `NativeMapping`.
    let mapped = map_prot_at(
        operation,
        len,
        prot,
        Some(address),
        FixedRwReservation::ReplaceOwned,
    );
    if mapped.cast::<libc::c_void>() == libc::MAP_FAILED {
        return Err(RuntimeError::Unsupported(format!(
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
        return Err(RuntimeError::Unsupported(format!(
            "map native {label} requested 0x{address:x} but returned 0x{returned:x}{detail}"
        )));
    }
    Ok(())
}

struct MappedElf {
    bias: u64,
    entry: u64,
    phdr: u64,
    segments: Vec<(u64, u64)>,
    protections: Vec<(u64, u64, u64)>,
}

/// Map one x86_64 ELF into the identity address space without involving the
/// dynamic linker. `apply_relative_relocations` is only for self-relocating
/// static PIE; a PT_INTERP executable and its interpreter perform their own
/// relocations after the kernel-style initial entry contract is established.
fn map_one_elf(
    candidate: &mut NativeMappingTransaction,
    bytes: &[u8],
    apply_relative_relocations: bool,
) -> Result<MappedElf, RuntimeError> {
    let elf = parse_loadable_elf(bytes, apply_relative_relocations).map_err(|_| {
        RuntimeError::Unsupported("native x86 lane requires a loadable x86_64 ELF".to_string())
    })?;

    let mut lo = u64::MAX;
    let mut hi = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type == PT_LOAD {
            lo = lo.min(ph.p_vaddr & !(PAGE - 1));
            hi = hi.max((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1));
        }
    }
    if lo == u64::MAX {
        return Err(RuntimeError::Unsupported(
            "ELF has no PT_LOAD segments".to_string(),
        ));
    }
    let span_len = (hi - lo) as usize;
    let (reservation_index, bias) = match elf.header.e_type {
        ET_DYN => {
            let index = candidate.map_anonymous(
                NativeMappingOperation::ElfReservation,
                span_len,
                libc::PROT_NONE,
                None,
                "ELF reservation",
            )?;
            let bias = candidate.mapping(index).base - lo;
            (index, bias)
        }
        ET_EXEC => (
            candidate.map_anonymous(
                NativeMappingOperation::ElfReservation,
                span_len,
                libc::PROT_NONE,
                Some(lo),
                "fixed ELF reservation",
            )?,
            0,
        ),
        other => {
            return Err(RuntimeError::Unsupported(format!(
                "native x86 lane requires ET_DYN or ET_EXEC, found ELF type {other}"
            )));
        }
    };
    let reservation = candidate.mapping(reservation_index);
    let reservation_start = reservation.base;
    let reservation_end = reservation_start.saturating_add(reservation.len as u64);

    let mut segments = Vec::new();
    let mut protections = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_lo = (ph.p_vaddr & !(PAGE - 1)) + bias;
        let seg_hi = ((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1)) + bias;
        if seg_lo < reservation_start || seg_hi > reservation_end || seg_hi <= seg_lo {
            return Err(RuntimeError::Unsupported(format!(
                "ELF segment [0x{seg_lo:x},0x{seg_hi:x}) escapes owned reservation \
                 [0x{reservation_start:x},0x{reservation_end:x})"
            )));
        }
        segments.push((seg_lo, seg_hi));
        let mut guest_prot = 0u64;
        if ph.p_flags & PF_R != 0 {
            guest_prot |= crate::linux_abi::LINUX_PROT_READ;
        }
        if ph.p_flags & PF_W != 0 {
            guest_prot |= crate::linux_abi::LINUX_PROT_WRITE;
        }
        if ph.p_flags & PF_X != 0 {
            guest_prot |= crate::linux_abi::LINUX_PROT_EXEC;
        }
        protections.push((seg_lo, seg_hi, guest_prot));
        map_fixed_replacement(
            NativeMappingOperation::ElfSegment,
            seg_lo,
            (seg_hi - seg_lo) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            "ELF segment",
        )?;
        let file_start = ph.p_offset as usize;
        let file_end = (ph.p_offset + ph.p_filesz) as usize;
        let src = bytes.get(file_start..file_end).ok_or_else(|| {
            RuntimeError::Unsupported("ELF PT_LOAD file range is out of bounds".to_string())
        })?;
        // SAFETY: destination is inside the freshly mapped RW segment.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), (ph.p_vaddr + bias) as *mut u8, src.len())
        };
    }

    if apply_relative_relocations {
        for rela in elf.dynrelas.iter() {
            if rela.r_type != R_X86_64_RELATIVE {
                return Err(RuntimeError::Unsupported(format!(
                    "native x86 lane: unsupported static relocation type {}",
                    rela.r_type
                )));
            }
            let where_ = rela.r_offset + bias;
            let value = bias.wrapping_add(rela.r_addend.unwrap_or(0) as u64);
            // SAFETY: validated static PIE relocation into its mapped image.
            unsafe { (where_ as *mut u64).write_unaligned(value) };
        }
    }

    let phdr = elf
        .program_headers
        .iter()
        .find(|ph| {
            elf.header.e_phoff >= ph.p_offset
                && elf.header.e_phoff < ph.p_offset.saturating_add(ph.p_filesz)
        })
        .map(|ph| bias + ph.p_vaddr + (elf.header.e_phoff - ph.p_offset))
        .unwrap_or(bias + elf.header.e_phoff);
    Ok(MappedElf {
        bias,
        entry: elf.entry + bias,
        phdr,
        segments,
        protections,
    })
}

/// Map the main ELF and optional PT_INTERP, then build the kernel-style entry
/// stack. Dynamic relocation belongs to the interpreter, not Carrick.
fn load_static_pie(
    bytes: &[u8],
    interpreter_bytes: Option<&[u8]>,
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
) -> Result<LoadedImage, RuntimeError> {
    let mut candidate = NativeMappingTransaction::new("native image candidate");
    let result = (|| {
        let elf =
            Elf::parse(bytes).map_err(|e| RuntimeError::Unsupported(format!("parse ELF: {e}")))?;
        let main = map_one_elf(&mut candidate, bytes, interpreter_bytes.is_none())?;
        let interpreter = interpreter_bytes
            .map(|bytes| map_one_elf(&mut candidate, bytes, false))
            .transpose()?;
        let mut segments = main.segments.clone();
        let mut segment_protections = main.protections.clone();
        if let Some(interpreter) = &interpreter {
            segments.extend(interpreter.segments.iter().copied());
            segment_protections.extend(interpreter.protections.iter().copied());
        }

        let stack_index = candidate.map_anonymous(
            NativeMappingOperation::GuestStack,
            GUEST_STACK_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            None,
            "guest stack",
        )?;
        let stack = candidate.mapping(stack_index).base;
        let scratch_index = candidate.map_anonymous(
            NativeMappingOperation::Scratch,
            PAGE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            None,
            "signal scratch",
        )?;
        let scratch = candidate.mapping(scratch_index).base;

        // Map the synthesized x86-64 vDSO so `getauxval(AT_SYSINFO_EHDR)` resolves
        // and `__vdso_clock_gettime`/`__vdso_gettimeofday`/`__vdso_time` resolve to
        // real, callable fast paths. Stamp FreeBSD's invariant-TSC frequency and
        // calibrated realtime/monotonic offsets into the vvar page; if calibration
        // is unavailable, its zero frequency deliberately selects the syscall
        // fallback. The vDSO code references the vvar at the fixed absolute
        // `LINUX_VVAR_BASE`, so that page must be mapped there exactly; the image is
        // position-
        // independent and published to the guest via `AT_SYSINFO_EHDR`.
        let vdso_base = {
            let vvar_base = crate::vdso::LINUX_VVAR_BASE;
            let vdso_base = crate::vdso::LINUX_VDSO_BASE;
            let vdso_bytes = crate::vdso::x8664_vdso_image_bytes();
            let vdso_len = ((vdso_bytes.len() as u64 + PAGE - 1) & !(PAGE - 1)) as usize;
            match candidate.map_optional_fixed(
                NativeMappingOperation::Vvar,
                crate::vdso::LINUX_VVAR_SIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                vvar_base,
                "vvar",
            )? {
                Some(vvar_index) => match candidate.map_optional_fixed(
                    NativeMappingOperation::Vdso,
                    vdso_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    vdso_base,
                    "vDSO",
                )? {
                    Some(vdso_index) => {
                        let vvar_address = candidate.mapping(vvar_index).base;
                        let vdso_address = candidate.mapping(vdso_index).base;
                        // SAFETY: both mappings are exact, checked, writable,
                        // non-overlapping, and owned by this candidate.
                        unsafe {
                            std::ptr::write_bytes(
                                vvar_address as *mut u8,
                                0,
                                crate::vdso::LINUX_VVAR_SIZE as usize,
                            );
                            std::ptr::copy_nonoverlapping(
                                vdso_bytes.as_ptr(),
                                vdso_address as *mut u8,
                                vdso_bytes.len(),
                            );
                        }
                        let _ = stamp_x86_vvar(vvar_address as *mut u8);
                        candidate
                            .mapping(vvar_index)
                            .protect(NativeMappingOperation::VvarProtection, libc::PROT_READ)?;
                        segments.push((vdso_base, vdso_base + vdso_len as u64));
                        segment_protections.push((
                            vvar_base,
                            vvar_base + crate::vdso::LINUX_VVAR_SIZE,
                            crate::linux_abi::LINUX_PROT_READ,
                        ));
                        segment_protections.push((
                            vdso_base,
                            vdso_base + vdso_len as u64,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        ));
                        vdso_base
                    }
                    None => {
                        // Optional vDSO absence is recoverable only after the
                        // exact vvar candidate has been explicitly retired.
                        candidate.teardown_mapping(vvar_index)?;
                        0
                    }
                },
                None => 0,
            }
        };

        let rsp = build_initial_stack(
            stack + GUEST_STACK_LEN as u64,
            argv,
            env,
            &elf,
            main.phdr,
            main.entry,
            interpreter.as_ref().map_or(0, |image| image.bias),
            vdso_base,
        )?;

        // The rt_sigreturn trampoline: when a guest signal handler was registered
        // WITHOUT an explicit sa_restorer (Linux falls back to the kernel VDSO
        // `__kernel_rt_sigreturn`), the sigframe's pretcode points here so the
        // handler's `ret` lands on `mov $15, %eax; syscall` (rt_sigreturn). Placed
        // in the scratch page and published as a translatable code segment.
        const SIGRETURN_STUB: [u8; 7] = [0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let sigreturn_trampoline = scratch + PAGE - SIGRETURN_STUB.len() as u64;
        // SAFETY: writing into the mapped RW scratch page's tail.
        unsafe {
            std::ptr::copy_nonoverlapping(
                SIGRETURN_STUB.as_ptr(),
                sigreturn_trampoline as *mut u8,
                SIGRETURN_STUB.len(),
            );
        }
        // Publish the whole scratch page as a translatable segment so the block
        // planner can read the trampoline bytes.
        segments.push((scratch, scratch + PAGE));
        // The page hosts the translated rt_sigreturn stub. It remains RWX for the
        // existing native signal-frame/trampoline contract.
        segment_protections.push((
            scratch,
            scratch + PAGE,
            crate::linux_abi::LINUX_PROT_READ
                | crate::linux_abi::LINUX_PROT_WRITE
                | crate::linux_abi::LINUX_PROT_EXEC,
        ));

        // Sort + coalesce adjacent segments for diagnostics and loader-owned
        // protection bookkeeping.
        segments.sort_unstable();
        let mut coalesced: Vec<(u64, u64)> = Vec::with_capacity(segments.len());
        for (s, e) in segments {
            match coalesced.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => coalesced.push((s, e)),
            }
        }

        let entry = interpreter.as_ref().map_or(main.entry, |image| image.entry);
        Ok(LoadedImage {
            mappings: Vec::new(),
            entry,
            stack,
            stack_len: GUEST_STACK_LEN,
            rsp,
            scratch,
            scratch_len: PAGE as usize,
            sigreturn_trampoline,
            vdso_base,
            segments: coalesced,
            segment_protections,
        })
    })();
    match result {
        Ok(mut image) => {
            image.mappings = candidate.commit();
            Ok(image)
        }
        Err(error) => Err(candidate.rollback(error)),
    }
}

/// Only the R_X86_64_RELATIVE dynamic reloc type is supported by the loader.
const R_X86_64_RELATIVE: u32 = 8;

/// Parse and preflight everything the in-process mapper can reject without
/// actually reserving virtual addresses. Exec performs this before retiring
/// the old image, so malformed main/interpreter images return ENOEXEC rather
/// than becoming a fatal post-point-of-no-return load failure.
fn parse_loadable_elf(
    bytes: &[u8],
    apply_relative_relocations: bool,
) -> Result<Elf<'_>, crate::linux_abi::LinuxErrno> {
    let elf = Elf::parse(bytes).map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?;
    if !elf.is_64
        || elf.header.e_machine != EM_X86_64
        || !matches!(elf.header.e_type, ET_DYN | ET_EXEC)
    {
        return Err(crate::linux_abi::LINUX_ENOEXEC);
    }
    let mut has_load = false;
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        has_load = true;
        if ph.p_filesz > ph.p_memsz
            || ph
                .p_offset
                .checked_add(ph.p_filesz)
                .is_none_or(|end| end > bytes.len() as u64)
            || ph
                .p_vaddr
                .checked_add(ph.p_memsz)
                .and_then(|end| end.checked_add(PAGE - 1))
                .is_none()
        {
            return Err(crate::linux_abi::LINUX_ENOEXEC);
        }
    }
    if !has_load
        || (apply_relative_relocations
            && elf
                .dynrelas
                .iter()
                .any(|rela| rela.r_type != R_X86_64_RELATIVE))
    {
        return Err(crate::linux_abi::LINUX_ENOEXEC);
    }
    Ok(elf)
}

fn validate_loadable(bytes: &[u8]) -> Result<(), crate::linux_abi::LinuxErrno> {
    let elf = Elf::parse(bytes).map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?;
    parse_loadable_elf(bytes, elf.interpreter.is_none()).map(|_| ())
}

fn load_interpreter_bytes(
    dispatcher: &SyscallDispatcher,
    executable: &[u8],
) -> Result<Option<Vec<u8>>, crate::linux_abi::LinuxErrno> {
    let elf = Elf::parse(executable).map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?;
    let Some(path) = elf.interpreter else {
        return Ok(None);
    };
    let bytes = dispatcher
        .read_exec_file(path)
        .ok_or(crate::linux_abi::LINUX_ENOENT)?;
    parse_loadable_elf(&bytes, false)?;
    Ok(Some(bytes))
}

/// Resolve + read an `execve(2)` target through the dispatcher's exec path
/// (rootfs/overlay/mounts, then the host-FS fallback), following `#!` shebangs,
/// and validate that the resulting bytes are loadable. Returns the file bytes,
/// the resolved absolute path, and the (possibly shebang-rewritten) argv. All
/// failures return a Linux errno the guest observes from the failed `execve` —
/// nothing is torn down here, so the old image survives a failed exec. Mirrors
/// `native_darwin::load_native_execve_image` but for the simpler static-PIE
/// FreeBSD loader.
#[allow(clippy::type_complexity)]
fn load_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    argv: Vec<Vec<u8>>,
) -> Result<(Vec<u8>, Option<Vec<u8>>, String, Vec<Vec<u8>>), crate::linux_abi::LinuxErrno> {
    // Linux requires a non-empty argv; a guest that passes an empty vector gets
    // argv[0] = the program path (matching musl/glibc's fallback).
    let argv = if argv.is_empty() {
        vec![path.as_bytes().to_vec()]
    } else {
        argv
    };
    let raw = path.to_string();
    let absolute = dispatcher.resolve_exec_path(path);
    let (resolved, argv) = crate::exec_helpers::resolve_shebang(dispatcher, absolute, argv)?;
    let host_fallback = dispatcher.exec_host_fs_fallback();
    // Host-FS fallback tries the resolved (cwd-absolutized) path first, then the
    // RAW guest path relative to the runner's cwd — the native lane runs a probe
    // by a host-relative path and its self-`execve(argv[0])` re-execs that same
    // relative string, which resolve_exec_path would absolutize away from the
    // host file. Matches the initial `std::fs::read(path)` load.
    let file = dispatcher
        .read_exec_file(&resolved)
        .or_else(|| {
            if host_fallback {
                std::fs::read(&resolved)
                    .ok()
                    .or_else(|| std::fs::read(&raw).ok())
            } else {
                None
            }
        })
        .ok_or(crate::linux_abi::LINUX_ENOENT)?;
    validate_loadable(&file)?;
    let interpreter = load_interpreter_bytes(dispatcher, &file)?;
    Ok((file, interpreter, resolved, argv))
}

/// Build the Linux x86_64 initial stack:
/// `[argc][argv..][NULL][envp..][NULL][auxv..][AT_NULL]`, with argv/env byte
/// strings and a 16-byte AT_RANDOM block in the mapped stack. Returns the guest
/// rsp (argc), 16-aligned. argv/env are opaque Linux-ABI byte strings (a guest
/// execve may pass non-UTF-8 args/env). Keeping them on the 8 MiB stack avoids
/// the former one-page scratch overflow on ordinary autotools command lines.
#[allow(clippy::too_many_arguments)]
fn build_initial_stack(
    stack_top: u64,
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
    elf: &Elf,
    phdr_va: u64,
    main_entry: u64,
    interpreter_base: u64,
    vdso_base: u64,
) -> Result<u64, RuntimeError> {
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_ENTRY: u64 = 9;
    const AT_SYSINFO_EHDR: u64 = 33;
    const AT_RANDOM: u64 = 25;

    let stack_bottom = stack_top
        .checked_sub(GUEST_STACK_LEN as u64)
        .ok_or_else(|| RuntimeError::Unsupported("native x86 initial stack underflow".into()))?;
    let mut cur = stack_top;
    let mut place = |bytes: &[u8]| -> Result<u64, RuntimeError> {
        let len = u64::try_from(bytes.len())
            .ok()
            .and_then(|len| len.checked_add(1))
            .ok_or_else(|| {
                RuntimeError::Unsupported("native x86 exec arguments too large".into())
            })?;
        cur = cur
            .checked_sub(len)
            .filter(|at| *at >= stack_bottom)
            .ok_or_else(|| {
                RuntimeError::Unsupported("native x86 exec arguments exceed stack".into())
            })?;
        // SAFETY: the checked range lies inside the mapped guest stack.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), cur as *mut u8, bytes.len());
            *((cur + len - 1) as *mut u8) = 0;
        }
        Ok(cur)
    };
    let mut arg_ptrs = Vec::with_capacity(argv.len());
    for arg in argv {
        arg_ptrs.push(place(arg)?);
    }
    let mut env_ptrs = Vec::with_capacity(env.len());
    for variable in env {
        env_ptrs.push(place(variable)?);
    }

    // Keep AT_RANDOM naturally aligned below the strings.
    cur &= !0xf;
    cur = cur
        .checked_sub(16)
        .filter(|at| *at >= stack_bottom)
        .ok_or_else(|| {
            RuntimeError::Unsupported("native x86 exec arguments exceed stack".into())
        })?;
    let random_ptr = cur;
    // SAFETY: the checked range lies inside the mapped guest stack.
    unsafe { std::ptr::write_bytes(random_ptr as *mut u8, 0x5a, 16) };

    // Build the pointer/auxv image and place it below all strings.
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64); // argc
    words.extend(arg_ptrs.iter().copied()); // argv[]
    words.push(0); // argv NULL
    words.extend(env_ptrs.iter().copied()); // envp[]
    words.push(0); // envp NULL
    let mut auxv: Vec<(u64, u64)> = vec![
        (AT_PHDR, phdr_va),
        (AT_PHENT, elf.header.e_phentsize as u64),
        (AT_PHNUM, elf.header.e_phnum as u64),
        (AT_PAGESZ, PAGE),
        (AT_ENTRY, main_entry),
        (AT_RANDOM, random_ptr),
    ];
    if interpreter_base != 0 {
        auxv.push((AT_BASE, interpreter_base));
    }
    // Only advertise the vDSO when it was successfully mapped; a 0 base would
    // make `getauxval(AT_SYSINFO_EHDR)` resolve to a null pointer the guest
    // would then parse as an ELF.
    if vdso_base != 0 {
        auxv.push((AT_SYSINFO_EHDR, vdso_base));
    }
    auxv.push((AT_NULL, 0));
    for (k, v) in auxv {
        words.push(k);
        words.push(v);
    }

    let bytes = u64::try_from(words.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or_else(|| RuntimeError::Unsupported("native x86 exec vector too large".into()))?;
    // 16-align argc; the ABI wants (rsp) 16-aligned at _start.
    let rsp = cur
        .checked_sub(bytes)
        .map(|value| value & !0xf)
        .filter(|at| *at >= stack_bottom)
        .ok_or_else(|| RuntimeError::Unsupported("native x86 exec vector exceeds stack".into()))?;
    for (i, w) in words.iter().enumerate() {
        // SAFETY: the checked vector lies inside the mapped guest stack.
        unsafe { ((rsp + (i as u64) * 8) as *mut u64).write(*w) };
    }
    Ok(rsp)
}

/// How a guest thread's per-thread run loop is seeded.
enum ThreadStart {
    /// The process's initial thread: start at the ELF entry with a fresh
    /// snapshot and the initial stack pointer.
    Initial { entry: u64, rsp: u64 },
    /// A `clone(CLONE_VM|CLONE_THREAD…)` child: resume from a cloned snapshot
    /// (rax already 0, rsp already the child stack) with the child's fsbase.
    #[allow(dead_code)]
    Detached {
        snapshot: Box<X86UcontextSnapshot>,
        fsbase: u64,
    },
}

/// Terminal outcome of a guest thread's per-thread run loop.
enum ThreadRunOutcome {
    /// The guest exited (`exit_group`, or `exit(2)` as the last live thread):
    /// the whole process should terminate with `code`.
    Exit { code: i32, traps: usize },
    /// This single thread exited (`exit(2)`, not last): only this host thread
    /// ends. Carries whether it was the last live thread for the caller.
    #[allow(dead_code)]
    ThreadDone { traps: usize },
    /// Terminal exec ownership belongs to another guest thread. This thread's
    /// old-image guest body has retired without publishing a process exit.
    RetiredForExec { traps: usize },
    /// The run loop hit the trap limit with no exit/fault.
    TrapLimit { traps: usize },
    /// The run loop stopped on an unserviced condition (guest fault, an
    /// unsupported instruction, or an unhandled dispatch outcome).
    Fault { detail: String, traps: usize },
}

/// The result of running one translated block through the gateway: where to go
/// next, or a terminal signal.
fn notify_vfork_completion(fd: &mut Option<i32>) {
    let Some(fd) = fd.take() else {
        return;
    };
    let byte = 1u8;
    let _ = unsafe { libc::write(fd, (&byte as *const u8).cast::<libc::c_void>(), 1) };
    unsafe { libc::close(fd) };
}

enum Step {
    Continue(u64),
    Exit(i32),
    /// A `exit(2)` from a thread that was NOT the last live thread: end just
    /// this host thread (the run loop returns `ThreadDone`).
    ThreadEnd,
    /// This old-image thread lost/observed terminal exec ownership and retires
    /// without publishing a process exit.
    RetiredForExec,
    Fault(String),
    /// A `fork()` just made THIS process a fork child (guest `rax` already set
    /// to 0). The run loop marks itself a descendant so its eventual exit
    /// `_exit`s directly (reaped by the parent's `wait4`) instead of returning
    /// a `RunResult` up through `native_run`.
    BecameForkChild {
        resume: u64,
        vfork_completion_fd: Option<i32>,
    },
    /// A default-action fatal signal with no guest handler. A fork DESCENDANT
    /// must die BY the signal so its parent's `wait4` sees `WIFSIGNALED`; the
    /// TOP-LEVEL guest instead reports `exit=128+signum` so the driver returns a
    /// `RunResult` (native_run / the `carrick run` supervisor report it) rather
    /// than the runner dying by the signal itself. The run loop decides which,
    /// since only it knows the `forked` flag.
    SignalDeath(i32),
    /// `execve(2)`/`execveat(2)`: replace the current process image in place. The
    /// run loop retires the old `LoadedImage`, loads the new static-PIE ELF into
    /// the identity space, rebuilds the initial stack + auxv from the raw argv/
    /// env bytes, resets the dispatcher's memory/signal exec state and the per-
    /// thread JIT caches, and resumes at the new entry (execve does not return).
    Execve {
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    },
}

/// A minimal multiply-based hasher for the guest-VA block cache. The default
/// `HashMap` uses SipHash (DoS-resistant but slow), and an lldb backtrace of a
/// hot guest loop showed SipHash dominating — the cache is looked up once per
/// block per iteration, millions of times. The keys are our OWN guest VAs (no
/// adversarial input), so a single FxHash-style multiply is both correct and
/// far cheaper. Only `write_u64` is exercised (u64 keys); other inputs fold in
/// byte-wise so the impl is still a valid `Hasher`.
#[derive(Default)]
struct VaHasher(u64);

impl std::hash::Hasher for VaHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, value: u64) {
        // FxHash's rotate-xor-multiply step (rustc's `rustc-hash`).
        const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(K);
    }
}

type VaBuildHasher = std::hash::BuildHasherDefault<VaHasher>;

/// Patch a chainable branch's 5-byte `jmp` slot to jump straight to a
/// translated successor block. `patch_abs` is the exec-alias address of the
/// slot's 4-byte `rel32` field; `next_abs` is the address just after it (the
/// jmp's own next-instruction address the rel32 is relative to); `target_exec`
/// is the successor's exec VA. Both endpoints live in the <4 MiB JIT cache, so
/// the displacement always fits `i32`. The write goes through the region's RW
/// alias (the exec alias is not writable).
fn patch_slot(
    region: &JitRegion,
    jit: &FreebsdHostJit,
    patch_abs: u64,
    next_abs: u64,
    target_exec: u64,
) -> bool {
    let rel = (target_exec as i64 - next_abs as i64) as i32;
    let Some(w) = region.write_ptr_for(patch_abs as *mut u8) else {
        return false;
    };
    // SAFETY: `w` is the RW alias of the 4-byte rel32 field inside the JIT.
    unsafe { std::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), w, 4) };
    jit.flush_icache(patch_abs as *mut u8, 4);
    true
}

#[derive(Clone, Copy, Debug)]
struct GuardedChainPatch {
    entry_patch_abs: u64,
    entry_next_abs: u64,
    guard_exec: u64,
    guard_target_patch_abs: u64,
    guard_target_next_abs: u64,
}

/// Publish one hot direct edge target-first. Until the final entry displacement
/// is written, the original branch still reaches its cold Rust-exit stub. Once
/// the entry points at the guard, its separately-published target is complete.
fn publish_guarded_chain_edge(
    region: &JitRegion,
    jit: &FreebsdHostJit,
    patch: GuardedChainPatch,
    target_exec: u64,
) {
    if !patch_slot(
        region,
        jit,
        patch.guard_target_patch_abs,
        patch.guard_target_next_abs,
        target_exec,
    ) {
        return;
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    let _ = patch_slot(
        region,
        jit,
        patch.entry_patch_abs,
        patch.entry_next_abs,
        patch.guard_exec,
    );
}

/// Serializes in-process runs. This driver mutates PROCESS-GLOBAL state — the
/// fixed guest arenas (MAP_FIXED at the layout addresses) and the process-wide
/// fault-redirect sigaction/code-region registration — so two concurrent runs
/// in one process would clobber each other's arenas and fault state. Real
/// usage forks a process per guest (single run per process); the lock makes
/// the in-process case (e.g. parallel test threads) safe by serializing. Held
/// at RUN granularity (not per guest thread): a run's guest threads share the
/// one code cache + fault shim set up under this lock.
static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn teardown_jit_region(region: &JitRegion) -> Result<(), RuntimeError> {
    let mappings = [
        NativeMapping::claim(
            region.exec_base.as_ptr() as u64,
            region.capacity,
            NativeMappingOperation::General,
            "JIT executable alias",
        ),
        NativeMapping::claim(
            region.write_base.as_ptr() as u64,
            region.capacity,
            NativeMappingOperation::General,
            "JIT writable alias",
        ),
    ];
    teardown_native_mappings(&mappings)
}

struct JitSetupCandidate {
    region: Option<JitRegion>,
}

impl JitSetupCandidate {
    fn new(region: JitRegion) -> Self {
        Self {
            region: Some(region),
        }
    }

    fn register(&self, cache_len: usize) {
        if let Some(region) = &self.region {
            fault::register_code_region(region.exec_base.as_ptr() as u64, cache_len as u64);
        }
    }

    fn commit(mut self) -> JitRegion {
        self.region.take().unwrap_or_else(|| std::process::abort())
    }

    fn rollback(mut self, primary: RuntimeError) -> RuntimeError {
        fault::unregister_code_region();
        let cleanup = self
            .region
            .take()
            .and_then(|region| teardown_jit_region(&region).err());
        match cleanup {
            Some(error) => RuntimeError::Unsupported(format!(
                "{primary}; JIT candidate rollback failed: {error}"
            )),
            None => primary,
        }
    }
}

impl Drop for JitSetupCandidate {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        fault::unregister_code_region();
        // `teardown_jit_region` wraps each alias in fail-stop NativeMapping
        // ownership; a persistent host unmap failure aborts before returning.
        let _ = teardown_jit_region(&region);
    }
}

fn rollback_initial_native_resources(
    image: &LoadedImage,
    arenas: Option<&GuestArenas>,
    primary: RuntimeError,
) -> RuntimeError {
    let mut cleanup = Vec::new();
    if let Err(error) = image.teardown() {
        cleanup.push(format!("image: {error}"));
    }
    if let Some(arenas) = arenas
        && let Err(error) = arenas.teardown()
    {
        cleanup.push(format!("arenas: {error}"));
    }
    if cleanup.is_empty() {
        primary
    } else {
        RuntimeError::Unsupported(format!(
            "{primary}; initial native candidate rollback failed: {}",
            cleanup.join("; ")
        ))
    }
}

fn rollback_started_native_run(
    shared: &SharedRun,
    arenas: &GuestArenas,
    primary: RuntimeError,
) -> RuntimeError {
    fault::unregister_code_region();
    let mut cleanup = Vec::new();
    if let Err(error) = teardown_jit_region(&shared.region) {
        cleanup.push(format!("JIT: {error}"));
    }
    if let Err(error) = shared.current_image().teardown() {
        cleanup.push(format!("image: {error}"));
    }
    if let Err(error) = arenas.teardown() {
        cleanup.push(format!("arenas: {error}"));
    }
    if cleanup.is_empty() {
        primary
    } else {
        RuntimeError::Unsupported(format!(
            "{primary}; started native run rollback failed: {}",
            cleanup.join("; ")
        ))
    }
}
// `guest_cpu::prepare_child_record_pre_fork` publishes its record reference
// through a process-global child-side stash. Serialize prepare+fork so a sibling
// guest thread cannot replace that stash before this fork snapshots it. An
// atomic guard is deliberate: unlike a pthread/std mutex it has no inherited
// waiter queue to strand in the multithreaded fork child; parent and child each
// release their COW copy with one store immediately after fork.
static FORK_IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct NativeForkGuard;

impl NativeForkGuard {
    fn acquire_until(deadline: std::time::Instant) -> Result<Self, ExecutableEpochError> {
        use std::sync::atomic::Ordering;
        loop {
            if FORK_IN_PROGRESS
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(Self);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ExecutableEpochError::HostForkTimedOut);
            }
            // Fork-only contention path; ordinary syscalls never poll or touch
            // this process-global reservation.
            std::thread::yield_now();
        }
    }
}

impl Drop for NativeForkGuard {
    fn drop(&mut self) {
        FORK_IN_PROGRESS.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Per-guest-thread JIT code-cache slice size. A guest thread bump-allocates
/// its translated blocks within its own slice, so concurrent threads never
/// collide in the cache. The identity code pages are shared and immutable, so
/// re-JITing the same guest block per thread is correct (just not compact).
const JIT_SLICE_LEN: usize = CODE_CACHE_LEN;
/// Number of concurrent guest-thread JIT slices. The whole cache is ONE
/// contiguous reservation registered once with the fault shim; slices are
/// handed out (and returned on thread exit) from a free-list, so a program
/// that recycles threads reuses the space. `clone` fails with EAGAIN if all
/// slices are in use at once.
const JIT_SLICE_COUNT: usize = 129;

/// The process-exit rendezvous. `exit_group` from any guest thread — or the
/// LAST thread's `exit(2)` — terminates the whole process with the recorded
/// code. The initial (host) thread owns surfacing the `RunResult`, so a sibling
/// that exits records the code + flag here and the initial thread observes it
/// (at a run-loop boundary, blocking-wait interrupt, or by waiting on the
/// condvar once its own guest thread has ended).
struct ExitState {
    code: std::sync::Mutex<Option<i32>>,
    cv: std::sync::Condvar,
    requested: std::sync::atomic::AtomicBool,
    /// Set by a thread performing `execve(2)` while siblings are live: all OTHER
    /// guest threads must STOP running guest code (Linux kills the thread group,
    /// keeping only the execing task) WITHOUT recording a process exit code —
    /// the new image's eventual exit decides that.
    exec_stop: std::sync::atomic::AtomicBool,
    /// A vfork parent sleeps in host `poll(2)`, not a timed polling loop. An
    /// execing sibling writes this nonblocking pipe to retire that parent at
    /// once, avoiding both latency and repeated host syscalls.
    vfork_waiting: std::sync::atomic::AtomicBool,
    vfork_wake: [i32; 2],
}

impl ExitState {
    fn new() -> Self {
        let mut vfork_wake = [-1; 2];
        // Failure is non-fatal: vfork wait checks the atomic before blocking,
        // while the normal FreeBSD path has a real pipe and zero polling.
        if unsafe { libc::pipe2(vfork_wake.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0
        {
            vfork_wake = [-1; 2];
        }
        Self {
            code: std::sync::Mutex::new(None),
            cv: std::sync::Condvar::new(),
            requested: std::sync::atomic::AtomicBool::new(false),
            exec_stop: std::sync::atomic::AtomicBool::new(false),
            vfork_waiting: std::sync::atomic::AtomicBool::new(false),
            vfork_wake,
        }
    }

    /// Signal every OTHER guest thread to stop for an `execve` takeover.
    fn request_exec_stop(&self) {
        self.exec_stop
            .store(true, std::sync::atomic::Ordering::Release);
        if self
            .vfork_waiting
            .load(std::sync::atomic::Ordering::Acquire)
            && self.vfork_wake[1] >= 0
        {
            let byte = 1u8;
            let _ = unsafe {
                libc::write(
                    self.vfork_wake[1],
                    (&byte as *const u8).cast::<libc::c_void>(),
                    1,
                )
            };
        }
    }

    fn exec_stop_requested(&self) -> bool {
        self.exec_stop.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Clear only after the executable terminal lease commits a fully
    /// installed replacement image. Timeout/abort paths intentionally never
    /// call this, so every old-image waiter remains interrupted and stopped.
    fn clear_exec_stop(&self) {
        self.exec_stop
            .store(false, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();
    }

    fn begin_vfork_wait(&self) {
        self.vfork_waiting
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn end_vfork_wait(&self) {
        self.vfork_waiting
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn vfork_wake_fd(&self) -> i32 {
        self.vfork_wake[0]
    }

    /// Record the process exit code (first writer wins) and wake any waiter.
    fn request(&self, code: i32) {
        let mut guard = self.code.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(code);
        }
        self.requested
            .store(true, std::sync::atomic::Ordering::Release);
        self.cv.notify_all();
    }

    fn requested(&self) -> bool {
        self.requested.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Block until a process exit code is recorded (used by the initial thread
    /// after its OWN guest thread exited but siblings are still live).
    fn wait_for_code(&self) -> i32 {
        let mut guard = self.code.lock().unwrap_or_else(|p| p.into_inner());
        while guard.is_none() {
            guard = self.cv.wait(guard).unwrap_or_else(|p| p.into_inner());
        }
        guard.unwrap()
    }

    fn code(&self) -> Option<i32> {
        *self.code.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for ExitState {
    fn drop(&mut self) {
        for fd in self.vfork_wake {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

// FreeBSD's fixed SIGRTMIN. The libc crate does not expose it on this target;
// unlike glibc, FreeBSD reserves no leading RT signals for pthread internals.
const FREEBSD_NATIVE_EXIT_KICK_SIGNAL: i32 = 65;

/// Everything a guest thread needs that is SHARED across the whole run: the
/// interior-mutable dispatcher, the thread registry + futex table, the loaded
/// image, the one contiguous JIT code cache, and the exit rendezvous. Cloned
/// (Arc) into every spawned host thread.
struct SharedRun {
    dispatcher: Arc<SyscallDispatcher>,
    registry: Arc<crate::thread::ThreadRegistry>,
    futex: Arc<crate::thread::FutexTable>,
    reporter: Arc<CompatReporter>,
    image: std::sync::RwLock<Arc<LoadedImage>>,
    region: JitRegion,
    jit: FreebsdHostJit,
    max_traps: usize,
    /// Free JIT-slice offsets (`i * JIT_SLICE_LEN`). Popped on spawn, pushed
    /// back on thread exit.
    free_slices: std::sync::Mutex<Vec<usize>>,
    /// Join handles of spawned guest pthreads, paired with the exact executable
    /// registration whose Retiring tombstone only this handle may reap.
    threads: std::sync::Mutex<Vec<NativeGuestThreadHandle>>,
    /// Host pthreads currently executing guest threads. Process exit repeatedly
    /// sends the non-restarting native kick until every sibling unregisters,
    /// interrupting host `ppoll`, `_umtx_op`, `fcntl(F_SETLKW)`, and shared-word
    /// waits without polling or retaining raw guest addresses.
    host_threads:
        std::sync::Mutex<std::collections::HashMap<crate::thread::ThreadId, libc::pthread_t>>,
    host_threads_cv: std::sync::Condvar,
    executable_epoch: Arc<ExecutableEpoch>,
    exit: ExitState,
}

// SAFETY: the only non-`Send`/`Sync` field is `region`'s `NonNull` code-cache
// pointers. The region is immutable for the whole run; each guest thread writes
// ONLY into its own non-overlapping slice (via `write_ptr_for`) and executes
// only from that slice, so there is no data race on the shared reservation.
unsafe impl Send for SharedRun {}
unsafe impl Sync for SharedRun {}

struct NativeGuestThreadHandle {
    registration_id: ExecutableThreadId,
    /// False only when bind failed and the unbound Starting record canceled
    /// itself safely before the handle was published.
    bound: bool,
    handle: std::thread::JoinHandle<()>,
}

impl SharedRun {
    fn current_image(&self) -> Arc<LoadedImage> {
        Arc::clone(&self.image.read().unwrap_or_else(|p| p.into_inner()))
    }

    fn publish_image(&self, image: Arc<LoadedImage>) {
        *self.image.write().unwrap_or_else(|p| p.into_inner()) = image;
    }

    fn alloc_slice(&self) -> Option<usize> {
        self.free_slices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop()
    }

    fn free_slice(&self, off: usize) {
        self.free_slices
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(off);
    }

    fn confirm_joined_handle(
        &self,
        joined: NativeGuestThreadHandle,
    ) -> Result<(), ExecutableEpochError> {
        let _ = joined.handle.join();
        if joined.bound {
            self.executable_epoch
                .confirm_joined(joined.registration_id)?;
        }
        Ok(())
    }

    /// Opportunistically reap only handles whose pthread has already finished.
    /// `is_finished` is merely a selection hint: authority transfers only after
    /// the exact `join` returns and `confirm_joined` removes its tombstone.
    fn reap_finished_clone_threads(&self) -> Result<usize, ExecutableEpochError> {
        let finished = {
            let mut handles = self.threads.lock().unwrap_or_else(|p| p.into_inner());
            let mut finished = Vec::new();
            let mut index = handles.len();
            while index != 0 {
                index -= 1;
                if handles[index].handle.is_finished() {
                    finished.push(handles.swap_remove(index));
                }
            }
            finished
        };
        let count = finished.len();
        for joined in finished {
            self.confirm_joined_handle(joined)?;
        }
        Ok(count)
    }

    /// Join every spawned guest thread only after exit was requested or terminal
    /// exec transferred old-image ownership away from the orchestrator.
    fn join_threads(&self) -> Result<(), ExecutableEpochError> {
        let handles = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
        for joined in handles {
            self.confirm_joined_handle(joined)?;
        }
        Ok(())
    }

    fn prepare_host_fork_with_reaping(
        self: &Arc<Self>,
        registration: &ExecutableThreadRegistration,
        deadline: std::time::Instant,
        mut wake: impl FnMut(&[libc::pthread_t]),
    ) -> Result<ExecutableHostForkLease, ExecutableEpochError> {
        loop {
            self.reap_finished_clone_threads()?;
            match self
                .executable_epoch
                .prepare_host_fork(registration, deadline, &mut wake)
            {
                Err(ExecutableEpochError::RetiringThreadsPresent)
                    if std::time::Instant::now() < deadline =>
                {
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }

    fn register_host_thread(&self, tid: crate::thread::ThreadId) {
        let pthread = unsafe { libc::pthread_self() };
        self.host_threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tid, pthread);
    }

    fn unregister_host_thread(&self, tid: crate::thread::ThreadId) {
        self.host_threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&tid);
        self.host_threads_cv.notify_all();
    }

    fn rekey_host_thread_after_exec(
        &self,
        old: crate::thread::ThreadId,
        new: crate::thread::ThreadId,
    ) -> Result<(), String> {
        if old == new {
            return Ok(());
        }
        let current = unsafe { libc::pthread_self() };
        let mut threads = self.host_threads.lock().unwrap_or_else(|p| p.into_inner());
        if threads.contains_key(&new) {
            return Err(format!(
                "exec host-thread target tid {new} is still occupied"
            ));
        }
        let pthread = threads
            .remove(&old)
            .ok_or_else(|| format!("exec host-thread source tid {old} is absent"))?;
        if pthread != current {
            threads.insert(old, pthread);
            return Err(format!(
                "exec host-thread source tid {old} is not current pthread"
            ));
        }
        threads.insert(new, pthread);
        self.host_threads_cv.notify_all();
        Ok(())
    }

    /// Repeated non-restarting signals close the signal-before-host-park race:
    /// the exit publisher waits on a condvar, not a polling/yield loop, and
    /// retries only while a sibling remains registered.
    fn interrupt_host_threads_for_exit(&self) {
        let current = unsafe { libc::pthread_self() };
        let mut threads = self.host_threads.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            let targets: Vec<libc::pthread_t> = threads
                .values()
                .copied()
                .filter(|pthread| *pthread != current)
                .collect();
            if targets.is_empty() {
                return;
            }
            drop(threads);
            for pthread in targets {
                unsafe {
                    libc::pthread_kill(pthread, FREEBSD_NATIVE_EXIT_KICK_SIGNAL);
                }
            }
            threads = self.host_threads.lock().unwrap_or_else(|p| p.into_inner());
            let waited = self
                .host_threads_cv
                .wait_timeout(threads, std::time::Duration::from_millis(1));
            let (next, _) = waited.unwrap_or_else(|p| p.into_inner());
            threads = next;
        }
    }

    /// Publish the exec-stop predicate before waking host-blocked siblings.
    /// The executable coordinator, not the thread registry, is the teardown
    /// authority; its retirement wait repeatedly signals only records observed
    /// in `Host` state and never an admitted JIT interval.
    fn request_exec_stop(&self) {
        self.exit.request_exec_stop();
        self.futex.notify_signal_pending();
        self.dispatcher.notify_inmem_epoll();
    }

    fn wait_for_exec_retirement(
        &self,
        owner: ExecutableTerminalOwner,
        deadline: std::time::Instant,
    ) -> Result<ExecutableTerminalRetirement, ExecutableTerminalError> {
        loop {
            self.reap_finished_clone_threads()
                .map_err(ExecutableTerminalError::Epoch)?;
            match self
                .executable_epoch
                .wait_for_terminal_retirement(owner, deadline, |targets| {
                    for pthread in targets {
                        unsafe {
                            libc::pthread_kill(*pthread, FREEBSD_NATIVE_EXIT_KICK_SIGNAL);
                        }
                    }
                }) {
                Err(ExecutableTerminalError::Epoch(
                    ExecutableEpochError::RetiringThreadsPresent,
                )) if std::time::Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }

    /// Publish a process-wide exit and release every sibling from a blocking
    /// wait. `exit_group(2)` may be issued by any guest thread while the
    /// initial thread is indefinitely parked in a host syscall; recording the
    /// flag alone leaves that thread asleep forever and prevents terminal state.
    fn request_exit(&self, code: i32) {
        self.exit.request(code);
        self.futex.notify_signal_pending();
        self.dispatcher.notify_inmem_epoll();
        self.interrupt_host_threads_for_exit();
    }
}

struct NativeHostThreadRegistration {
    shared: Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    registered: bool,
}

impl NativeHostThreadRegistration {
    fn new(shared: &Arc<SharedRun>, tid: crate::thread::ThreadId) -> Self {
        shared.register_host_thread(tid);
        Self {
            shared: Arc::clone(shared),
            tid,
            registered: true,
        }
    }

    /// Stop Drop from locking the inherited parent registry in a fork child.
    /// The old map is COW-private and discarded with the old SharedRun.
    fn abandon_inherited_after_fork(&mut self) {
        self.registered = false;
    }

    /// Rebind in a freshly-forked child without touching the inherited parent
    /// registry mutex. Its owner may have been a sibling pthread that vanished
    /// at fork, so locking it in the child can deadlock permanently.
    fn rebind_after_fork(&mut self, shared: &Arc<SharedRun>, tid: crate::thread::ThreadId) {
        shared.register_host_thread(tid);
        self.shared = Arc::clone(shared);
        self.tid = tid;
        self.registered = true;
    }

    fn rekey_after_exec(&mut self, tid: crate::thread::ThreadId) -> Result<(), String> {
        if !self.registered {
            return Err("exec host-thread registration is inactive".to_string());
        }
        self.shared.rekey_host_thread_after_exec(self.tid, tid)?;
        self.tid = tid;
        Ok(())
    }
}

impl Drop for NativeHostThreadRegistration {
    fn drop(&mut self) {
        if self.registered {
            self.shared.unregister_host_thread(self.tid);
        }
    }
}

/// A guest `clone(CLONE_VM|CLONE_THREAD…)` request, normalized from the
/// dispatch outcome plus the parent's live register/TLS state.
struct CloneThreadRequest {
    parent_snapshot: X86UcontextSnapshot,
    resume: u64,
    parent_fsbase: u64,
    stack: u64,
    tls: Option<u64>,
    parent_tid_addr: u64,
    child_tid_addr: u64,
    clear_child_tid_addr: u64,
}

#[derive(Debug)]
enum CloneThreadStart {
    Run,
    Cancel,
}

#[derive(Debug)]
enum CloneThreadReady {
    Gated,
    Failed { bound: bool },
}

#[derive(Debug)]
enum CloneThreadSpawnError {
    Errno(i64),
    Fatal(String),
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_NATIVE_CLONE_THREAD_SPAWN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

fn spawn_native_clone_host_thread(
    name: String,
    body: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    #[cfg(test)]
    if FAIL_NEXT_NATIVE_CLONE_THREAD_SPAWN.with(|fail| fail.replace(false)) {
        return Err(std::io::Error::other(
            "injected native clone thread spawn failure",
        ));
    }
    std::thread::Builder::new().name(name).spawn(body)
}

fn retire_gated_clone_thread(
    shared: &SharedRun,
    child_tid: crate::thread::ThreadId,
    slice_off: usize,
) {
    shared.registry.exit(child_tid);
    shared.dispatcher.forget_thread_signal_state(child_tid);
    shared.free_slice(slice_off);
}

fn join_failed_clone_thread(
    shared: &Arc<SharedRun>,
    executable_registration: &ExecutableThreadRegistration,
    child_registration_id: ExecutableThreadId,
    bound: bool,
    handle: std::thread::JoinHandle<()>,
) -> Result<(), String> {
    let joined = with_host_wait_safe(&shared.executable_epoch, executable_registration, |_| {
        handle.join()
    })
    .map_err(|error| format!("clone cancellation wait boundary failed: {error:?}"))?;
    joined.map_err(|_| "gated clone child panicked".to_string())?;
    if bound {
        shared
            .executable_epoch
            .confirm_joined(child_registration_id)
            .map_err(|error| format!("gated clone retirement failed: {error:?}"))?;
    }
    Ok(())
}

fn validate_clone_thread_tid_outputs(
    memory: &impl GuestMemory,
    parent_tid_addr: u64,
    child_tid_addr: u64,
) -> Result<(), crate::linux_abi::LinuxErrno> {
    [parent_tid_addr, child_tid_addr]
        .into_iter()
        .filter(|address| *address != 0)
        .try_for_each(|address| {
            memory
                .guest_range_is_writable(address, std::mem::size_of::<u32>())
                .then_some(())
                .ok_or(crate::linux_abi::LINUX_EFAULT)
        })
}

/// Spawn a guest thread transactionally. Both complete four-byte TID outputs
/// are validated before creating any task state. The host pthread then binds an
/// exact executable registration and waits behind a start gate; only after both
/// checked writes succeed may it execute one guest instruction.
fn spawn_clone_thread(
    shared: &Arc<SharedRun>,
    parent_tid: crate::thread::ThreadId,
    req: CloneThreadRequest,
    executable_registration: &ExecutableThreadRegistration,
) -> Result<crate::thread::ThreadId, CloneThreadSpawnError> {
    let mut tid_memory = IdentityGuestMemory::for_run(shared);
    validate_clone_thread_tid_outputs(&tid_memory, req.parent_tid_addr, req.child_tid_addr)
        .map_err(|errno| CloneThreadSpawnError::Errno(errno.guest_retval()))?;

    let slice_off = shared.alloc_slice().ok_or_else(|| {
        CloneThreadSpawnError::Errno(crate::linux_abi::LINUX_EAGAIN.guest_retval())
    })?;
    let child_tid = shared.registry.register_child(req.clear_child_tid_addr);
    shared
        .dispatcher
        .inherit_thread_signal_mask(parent_tid, child_tid);

    let mut child_snapshot = req.parent_snapshot;
    child_snapshot.gpr[reg::RAX] = 0;
    if req.stack != 0 {
        child_snapshot.gpr[reg::RSP] = req.stack;
    }
    child_snapshot.rip = req.resume;
    let child_fsbase = req.tls.unwrap_or(req.parent_fsbase);

    let child_shared = Arc::clone(shared);
    let child_epoch_registration = match shared.executable_epoch.register_clone_starting() {
        Ok(registration) => registration,
        Err(_) => {
            retire_gated_clone_thread(shared, child_tid, slice_off);
            return Err(CloneThreadSpawnError::Errno(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            ));
        }
    };
    let child_registration_id = child_epoch_registration.id;
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<CloneThreadReady>(1);
    let (start_tx, start_rx) = std::sync::mpsc::sync_channel::<CloneThreadStart>(1);
    let handle = match spawn_native_clone_host_thread(
        format!("carrick-guest-tid-{}", child_tid.raw()),
        move || {
            let mut child_epoch_registration = child_epoch_registration;
            if child_epoch_registration.bind_current().is_err() {
                retire_gated_clone_thread(&child_shared, child_tid, slice_off);
                let _ = ready_tx.send(CloneThreadReady::Failed { bound: false });
                return;
            }
            let wait_guard = match child_shared
                .executable_epoch
                .begin_host_wait_safe(&child_epoch_registration)
            {
                Ok(guard) => guard,
                Err(_) => {
                    retire_gated_clone_thread(&child_shared, child_tid, slice_off);
                    let _ = ready_tx.send(CloneThreadReady::Failed { bound: true });
                    return;
                }
            };
            if ready_tx.send(CloneThreadReady::Gated).is_err() {
                let _ = wait_guard.finish();
                retire_gated_clone_thread(&child_shared, child_tid, slice_off);
                return;
            }
            let start = start_rx.recv().unwrap_or(CloneThreadStart::Cancel);
            if wait_guard.finish().is_err() || matches!(start, CloneThreadStart::Cancel) {
                retire_gated_clone_thread(&child_shared, child_tid, slice_off);
                return;
            }

            let mut memory = IdentityGuestMemory::for_run(&child_shared);
            let mut waiter = crate::io_wait::ThreadWaiter::new(child_tid);
            let outcome = run_x86_thread(
                ThreadStart::Detached {
                    snapshot: Box::new(child_snapshot),
                    fsbase: child_fsbase,
                },
                &child_shared,
                child_tid,
                slice_off,
                JIT_SLICE_LEN,
                &mut memory,
                &mut waiter,
                &mut child_epoch_registration,
            );
            child_shared.free_slice(slice_off);
            match outcome {
                ThreadRunOutcome::Exit { code, .. } => child_shared.request_exit(code),
                ThreadRunOutcome::TrapLimit { .. } => child_shared.request_exit(125),
                ThreadRunOutcome::Fault { detail, .. } => {
                    let msg = format!("native x86 guest thread {}: {detail}\n", child_tid.raw());
                    unsafe {
                        libc::write(2, msg.as_ptr().cast(), msg.len());
                    }
                    child_shared.request_exit(125);
                }
                ThreadRunOutcome::ThreadDone { .. } | ThreadRunOutcome::RetiredForExec { .. } => {}
            }
        },
    ) {
        Ok(handle) => handle,
        Err(_) => {
            retire_gated_clone_thread(shared, child_tid, slice_off);
            return Err(CloneThreadSpawnError::Errno(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            ));
        }
    };

    let ready = match with_host_wait_safe(&shared.executable_epoch, executable_registration, |_| {
        ready_rx.recv()
    }) {
        Ok(Ok(ready)) => ready,
        Ok(Err(_)) => {
            let _ = handle.join();
            return Err(CloneThreadSpawnError::Fatal(
                "clone child exited before reporting its start gate".to_string(),
            ));
        }
        Err(error) => {
            let _ = start_tx.send(CloneThreadStart::Cancel);
            let _ = handle.join();
            return Err(CloneThreadSpawnError::Fatal(format!(
                "clone start-gate wait failed: {error:?}"
            )));
        }
    };
    if let CloneThreadReady::Failed { bound } = ready {
        join_failed_clone_thread(
            shared,
            executable_registration,
            child_registration_id,
            bound,
            handle,
        )
        .map_err(CloneThreadSpawnError::Fatal)?;
        return Err(CloneThreadSpawnError::Errno(
            crate::linux_abi::LINUX_EAGAIN.guest_retval(),
        ));
    }

    if shared.exit.requested() || shared.exit.exec_stop_requested() {
        let _ = start_tx.send(CloneThreadStart::Cancel);
        join_failed_clone_thread(
            shared,
            executable_registration,
            child_registration_id,
            true,
            handle,
        )
        .map_err(CloneThreadSpawnError::Fatal)?;
        return Err(CloneThreadSpawnError::Errno(
            crate::linux_abi::LINUX_EAGAIN.guest_retval(),
        ));
    }

    let tid_bytes = (child_tid.raw() as u32).to_le_bytes();
    let write_result = (|| {
        if req.parent_tid_addr != 0 {
            tid_memory.write_bytes(req.parent_tid_addr, &tid_bytes)?;
        }
        if req.child_tid_addr != 0 {
            tid_memory.write_bytes(req.child_tid_addr, &tid_bytes)?;
        }
        Ok::<(), carrick_guest_mem::MemoryError>(())
    })();
    if let Err(error) = write_result {
        let _ = start_tx.send(CloneThreadStart::Cancel);
        join_failed_clone_thread(
            shared,
            executable_registration,
            child_registration_id,
            true,
            handle,
        )
        .map_err(CloneThreadSpawnError::Fatal)?;
        return Err(CloneThreadSpawnError::Fatal(format!(
            "prevalidated clone TID publication failed: {error}"
        )));
    }

    if start_tx.send(CloneThreadStart::Run).is_err() {
        join_failed_clone_thread(
            shared,
            executable_registration,
            child_registration_id,
            true,
            handle,
        )
        .map_err(CloneThreadSpawnError::Fatal)?;
        return Err(CloneThreadSpawnError::Fatal(
            "gated clone child exited before guest start".to_string(),
        ));
    }
    shared
        .threads
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(NativeGuestThreadHandle {
            registration_id: child_registration_id,
            bound: true,
            handle,
        });
    Ok(child_tid)
}

/// Build a fresh, PRIVATE `SharedRun` for a `fork()` child. The parent's code
/// cache is a `SHM_ANON` `MAP_SHARED` dual-map, so it survives fork as the SAME
/// physical pages — a child that re-JITs into it at its own cursor clobbers the
/// parent's live code. Map a brand-new SHM_ANON cache (private to this child),
/// register it with the fault shim (re-registration replaces the parent-
/// inherited region in this child process), and give the child its own thread
/// registry + futex table (fork copied only the calling thread, so the child's
/// thread group is just itself). The dispatcher (its COW copy), reporter,
/// image (COW-identical VAs), and max_traps carry over. Slice 0 is reserved for
/// the child's main thread; guest threads it spawns take slices 1..N.
fn fork_child_rebuild(parent: &Arc<SharedRun>) -> Result<Arc<SharedRun>, String> {
    let cache_len = JIT_SLICE_LEN * JIT_SLICE_COUNT;
    let region = parent
        .jit
        .map_code_cache(cache_len)
        .map_err(|e| format!("fork child: map fresh code cache: {e:?}"))?;
    fault::register_code_region(region.exec_base.as_ptr() as u64, cache_len as u64);

    let tid = crate::thread::ThreadId::main_from_host_pid();
    let registry = Arc::new(crate::thread::ThreadRegistry::new(tid));
    crate::thread::set_current_registry(Arc::clone(&registry));
    let futex = Arc::new(crate::thread::FutexTable::new());
    crate::thread::set_current_futex_table(&futex);
    let timer_kicker: Arc<carrick_hal::GenericVcpuRegistry> =
        Arc::new(carrick_hal::GenericVcpuRegistry::new());
    crate::timer_delivery::reset_after_fork_child(
        timer_kicker as Arc<dyn carrick_hal::VcpuRegistry>,
        tid,
    );

    let free_slices: Vec<usize> = (1..JIT_SLICE_COUNT).map(|i| i * JIT_SLICE_LEN).collect();
    Ok(Arc::new(SharedRun {
        dispatcher: Arc::clone(&parent.dispatcher),
        registry,
        futex,
        reporter: Arc::clone(&parent.reporter),
        image: std::sync::RwLock::new(parent.current_image()),
        region,
        jit: FreebsdHostJit,
        max_traps: parent.max_traps,
        free_slices: std::sync::Mutex::new(free_slices),
        threads: std::sync::Mutex::new(Vec::new()),
        host_threads: std::sync::Mutex::new(std::collections::HashMap::new()),
        host_threads_cv: std::sync::Condvar::new(),
        executable_epoch: ExecutableEpoch::new(),
        exit: ExitState::new(),
    }))
}

/// Run the dispatcher + runtime fork-child resets in a fresh fork descendant, so
/// the child starts with the POSIX-correct post-`fork` state instead of the
/// parent's inherited process-global bookkeeping. Mirrors
/// `native_darwin::native_after_fork_child`: clear buffered stdout/stderr (the
/// child must not re-flush the parent's pending bytes), reinit the event ring +
/// host-signal (empty pending set, no inherited timers) + FIFO beacons, and run
/// each dispatcher subsystem's fork-child hook — `proc_after_fork_child` resets
/// timerslack to the default, re-seeds the subreaper ancestor to the child
/// itself, and clears inherited itimers/membarrier registration
/// (`procprctlview`, `childsubreaper`, `forkaltstack`, `forkexecpthread`);
/// `mem`/`sysv`/`epoll` drop inherited mm/SysV/epoll fork state.
fn native_after_fork_child(dispatcher: &SyscallDispatcher) {
    NATIVE_CHILD_EXIT_DIRTY.store(false, std::sync::atomic::Ordering::Release);
    dispatcher.clear_output_buffers();
    crate::event_ring::reinit_after_fork();
    crate::host_signal::reinit_after_fork();
    crate::dispatch::reset_fifo_beacons_after_fork_child();
    dispatcher.network_after_fork_child();
    dispatcher.epoll_after_fork_child();
    dispatcher.proc_after_fork_child();
    dispatcher.mem_after_fork_child();
    dispatcher.sysv_after_fork_child();
}

/// Run a static x86_64 Linux ELF natively on FreeBSD/amd64 through the shared
/// dispatcher. The `dispatcher` is fully constructed by the caller (rootfs,
/// fd table, identity, container policy) exactly as the VMM path receives it.
pub(crate) fn run_static_x86_elf<A, E>(
    path: &Path,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let argv = argv.into_iter().map(String::into_bytes).collect();
    let env = env.into_iter().map(String::into_bytes).collect();
    let bytes = std::fs::read(path)
        .map_err(|e| RuntimeError::Unsupported(format!("read {}: {e}", path.display())))?;
    run_static_x86_elf_bytes(&bytes, dispatcher, argv, env, max_traps)
}

/// Run an already-resolved static x86_64 ELF image. OCI execution uses this
/// entry so it can load the executable through the container VFS without
/// materializing a second host-path copy or rebuilding a VMM address space.
pub(crate) fn run_static_x86_elf_bytes(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    // Held for the whole run: the fixed arenas and the process-wide fault
    // shim cannot be shared across concurrent in-process runs.
    let _run_guard = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Guest instructions execute as ordinary host instructions on this lane,
    // so host process CPU accounting is authoritative (and is inherited by
    // fork children for wait4/waitid RUSAGE_CHILDREN rollup).
    crate::guest_cpu::set_native_host_provider();

    let interpreter = load_interpreter_bytes(&dispatcher, bytes).map_err(|errno| {
        RuntimeError::Unsupported(format!(
            "resolve native x86 PT_INTERP failed with Linux errno {}",
            errno.get()
        ))
    })?;
    let image = load_static_pie(bytes, interpreter.as_deref(), &argv, &env)?;

    // Publish the complete initial identity layout before a JIT mapping or
    // fault-region registration exists. A protection failure can now retire
    // only loader/arena mappings; no code-cache alias or redirect registration
    // can leak from this pre-run phase.
    let arenas = match GuestArenas::reserve() {
        Ok(arenas) => arenas,
        Err(error) => return Err(rollback_initial_native_resources(&image, None, error)),
    };
    if let Err(error) = reset_identity_vmas(&image) {
        let primary = RuntimeError::Unsupported(format!(
            "publish initial native x86 identity VMAs failed: {error}"
        ));
        return Err(rollback_initial_native_resources(
            &image,
            Some(&arenas),
            primary,
        ));
    }

    let jit = FreebsdHostJit;
    if let Err(error) = jit.supported() {
        let primary = RuntimeError::Unsupported(format!("host JIT unsupported: {error:?}"));
        return Err(rollback_initial_native_resources(
            &image,
            Some(&arenas),
            primary,
        ));
    }
    // ONE contiguous code cache covering every guest thread's slice, registered
    // with the fault shim exactly once (the handler reads the per-thread fault
    // record via %r15, so a single covering span is all it needs).
    let cache_len = JIT_SLICE_LEN * JIT_SLICE_COUNT;
    let region = match jit.map_code_cache(cache_len) {
        Ok(region) => region,
        Err(error) => {
            let primary = RuntimeError::Unsupported(format!("map code cache: {error:?}"));
            return Err(rollback_initial_native_resources(
                &image,
                Some(&arenas),
                primary,
            ));
        }
    };
    let jit_candidate = JitSetupCandidate::new(region);
    if let Err(error) = fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD) {
        let primary = RuntimeError::Unsupported(format!("install fault redirect: {error}"));
        let primary = jit_candidate.rollback(primary);
        return Err(rollback_initial_native_resources(
            &image,
            Some(&arenas),
            primary,
        ));
    }
    if let Err(error) = fault::install_kick_redirect(
        FREEBSD_NATIVE_EXIT_KICK_SIGNAL,
        kick_stub_addr(),
        fault::KickRcxRecovery {
            active_offset: CTX_KICK_RESTORE_RCX as u32,
            scratch_offset: CTX_SCRATCH2 as u32,
        },
    ) {
        let primary = RuntimeError::Unsupported(format!("install kick redirect: {error}"));
        let primary = jit_candidate.rollback(primary);
        return Err(rollback_initial_native_resources(
            &image,
            Some(&arenas),
            primary,
        ));
    }
    jit_candidate.register(cache_len);

    let tid = crate::thread::ThreadId::main_from_host_pid();

    // Shared, thread-safe syscall machinery. The dispatcher is interior-mutable
    // (`dispatch_threaded(&self, …)`), so guest `clone` threads drive the SAME
    // dispatcher; the thread registry + futex table are the cross-thread
    // rendezvous the futex/clone/exit outcomes read. Publishing the registry +
    // futex table lets the shared `/proc/<tid>` synthesis and helper-thread
    // signal wakes reach this process's live threads.
    let registry = Arc::new(crate::thread::ThreadRegistry::new(tid));
    crate::thread::set_current_registry(Arc::clone(&registry));
    let futex = Arc::new(crate::thread::FutexTable::new());
    crate::thread::set_current_futex_table(&futex);

    // Wire process-directed interval-timer delivery (setitimer/alarm/POSIX
    // timers). The dispatch arm (dispatch/time.rs) finds no owning backend on
    // this lane and spawns the shared wall-clock fallback thread, whose fire
    // action calls `crate::timer_delivery::deliver`. That path only publishes
    // (into the shared process-directed pending mask) + kicks when a delivery
    // handle is registered; without this call `deliver` is a silent no-op and
    // SIGALRM/SIGVTALRM/SIGPROF never reach the guest (`preemptsigstorm`'s
    // `alrm_delivered=false`). A busy guest thread consumes the published
    // signal at its next syscall-return safe point; the kicker is a no-op until
    // guest threads register a kick handle, which they do not need here.
    let timer_kicker: Arc<carrick_hal::GenericVcpuRegistry> =
        Arc::new(carrick_hal::GenericVcpuRegistry::new());
    crate::timer_delivery::register(
        Arc::clone(&timer_kicker) as Arc<dyn carrick_hal::VcpuRegistry>,
        tid,
    );

    // Cross-process guest-signal plumbing. MUST run pre-fork (before any guest
    // `fork` inside `run_x86_thread`) so the `MAP_SHARED` xsignal ring + FASYNC
    // table are inherited by every descendant, and the nudge handler is armed in
    // both parent and child. Without it, a guest `sigqueue`/`kill`/`tgkill` to a
    // forked sibling process could not enqueue into the ring (`xsig_enqueue`
    // returned false → the dispatcher reported EAGAIN, e.g. `sigqueueusr1`'s
    // `queue_ok=false`), and a delivered nudge (host `SIGRTMIN+1`) would take the
    // host default action and terminate the receiver instead of draining the
    // ring. Idempotent across the reused in-process test-harness runs.
    carrick_signal_core::host_glue::init_xsig::<crate::host_signal::ActiveGlue>();
    // Route the pump-owned standard signals (SIGHUP/SIGINT/SIGQUIT/SIGTERM) to
    // the guest on this pump-less lane (see the handler doc); pre-fork so every
    // descendant inherits the routing.
    install_native_pumped_handlers();
    // Freeze runtime-owned IPC object names before any guest fork. Without an
    // explicit run/container id the fallback scope is based on the top-level
    // runtime pid; descendants must inherit it rather than recomputing their own
    // pid and losing the parent's SysV message queues.
    dispatcher.init_sysv_run_scope();
    // Fork-shared cross-process futex waiter-count table, so a shared FUTEX_WAKE
    // can report how many waiters it woke (Linux semantics; native _umtx_op does
    // not). Pre-fork so every descendant maps the same physical pages.
    init_shared_waiter_table();
    // Act as the guest's PID-namespace init: become a FreeBSD reaper so an
    // orphaned guest grandchild (its middle parent exited) REPARENTS to this
    // process instead of host init, letting the guest's wait4(-1) reap it —
    // pid_namespaces(7) "pid 1 reaps orphans" (`pidnsorphanreap`), and the
    // reparent target for PR_SET_CHILD_SUBREAPER (`childsubreaper`). Idempotent:
    // a second acquire returns EBUSY, ignored.
    // SAFETY: procctl with a valid cmd + NULL data.
    unsafe {
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_REAP_ACQUIRE,
            std::ptr::null_mut(),
        );
    }

    let free_slices: Vec<usize> = (0..JIT_SLICE_COUNT).map(|i| i * JIT_SLICE_LEN).collect();
    // Normal SharedRun cleanup takes ownership only after every pre-run setup
    // step above has completed. Until this exact move, candidate Drop unregisters
    // the fault region and explicitly retires both JIT aliases on unwind.
    let region = jit_candidate.commit();
    let shared = Arc::new(SharedRun {
        dispatcher: Arc::new(dispatcher),
        registry,
        futex,
        reporter: Arc::new(CompatReporter::default()),
        image: std::sync::RwLock::new(Arc::new(image)),
        region,
        jit,
        max_traps,
        free_slices: std::sync::Mutex::new(free_slices),
        threads: std::sync::Mutex::new(Vec::new()),
        host_threads: std::sync::Mutex::new(std::collections::HashMap::new()),
        host_threads_cv: std::sync::Condvar::new(),
        executable_epoch: ExecutableEpoch::new(),
        exit: ExitState::new(),
    });

    // The process's initial guest thread runs inline on THIS host thread over
    // its own JIT slice. Guest `clone` threads carve their own slice and run on
    // spawned host threads.
    let mut main_epoch_registration = match shared.executable_epoch.register_current() {
        Ok(registration) => registration,
        Err(error) => {
            let primary = RuntimeError::Unsupported(format!(
                "native x86 main thread epoch registration failed: {error:?}"
            ));
            return Err(rollback_started_native_run(&shared, &arenas, primary));
        }
    };
    let main_slice = match shared.alloc_slice() {
        Some(slice) => slice,
        None => {
            let primary =
                RuntimeError::Unsupported("native x86 main thread has no JIT slice".to_string());
            return Err(rollback_started_native_run(&shared, &arenas, primary));
        }
    };
    let mut memory = IdentityGuestMemory::for_run(&shared);
    // The blocking-I/O waiter (fd wait / poll / select / sleep / blocking
    // write), shared with the KVM/bhyve single-thread loop.
    let mut waiter = crate::io_wait::ThreadWaiter::new(tid);
    let initial_image = shared.current_image();
    let outcome = run_x86_thread(
        ThreadStart::Initial {
            entry: initial_image.entry,
            rsp: initial_image.rsp,
        },
        &shared,
        tid,
        main_slice,
        JIT_SLICE_LEN,
        &mut memory,
        &mut waiter,
        &mut main_epoch_registration,
    );
    shared.free_slice(main_slice);

    // Classify the run-loop outcome while the exact main registration remains
    // live through slice retirement. Publish any process exit first, then
    // explicitly retire the main guest registration. From that point this
    // stack is an unregistered orchestrator helper: it may wait on ExitState or
    // join pthreads without falsely advertising HostWaitSafe snapshot authority.
    let (immediate_exit, traps, trap_limit_hit, mut fault) = match outcome {
        ThreadRunOutcome::Exit { code, traps } => {
            shared.request_exit(code);
            (Some(code), traps, false, None)
        }
        ThreadRunOutcome::ThreadDone { traps } | ThreadRunOutcome::RetiredForExec { traps } => {
            (None, traps, false, None)
        }
        ThreadRunOutcome::TrapLimit { traps } => {
            shared.request_exit(125);
            (Some(125), traps, true, None)
        }
        ThreadRunOutcome::Fault { detail, traps } => {
            shared.request_exit(125);
            (Some(125), traps, false, Some(detail))
        }
    };
    drop(main_epoch_registration);

    // Ordinary main-thread exit waits for a remaining guest thread to publish
    // process exit. RetiredForExec waits for the replacement-image owner. Both
    // waits run only after the orchestrator ceased being a guest registration.
    let exit_code = immediate_exit.unwrap_or_else(|| shared.exit.wait_for_code());

    // Joining is legal only after process exit was requested (or terminal exec
    // transferred ownership and subsequently produced the code above). Exact
    // clone tombstones are removed only after their associated join returns.
    if let Err(error) = shared.join_threads() {
        fault.get_or_insert_with(|| format!("native x86 guest thread join/reap failed: {error:?}"));
    }

    // Drain the guest's stdout/stderr from the SHARED dispatcher buffer (every
    // guest thread's writes accumulate here); surface them in the RunResult
    // exactly as the VMM lanes' buffered path does.
    let stdout = shared.dispatcher.stdout();
    let stderr = shared.dispatcher.stderr();

    fault::unregister_code_region();
    // The initial thread returned and every spawned guest thread was joined, so
    // both JIT aliases can be retired under explicit checked ownership.
    let mut cleanup = Vec::new();
    if let Err(error) = teardown_jit_region(&shared.region) {
        cleanup.push(format!("JIT: {error}"));
    }
    if let Err(error) = shared.current_image().teardown() {
        cleanup.push(format!("image: {error}"));
    }
    if let Err(error) = arenas.teardown() {
        cleanup.push(format!("arenas: {error}"));
    }

    if let Some(detail) = fault {
        let cleanup = if cleanup.is_empty() {
            String::new()
        } else {
            format!("; cleanup failed: {}", cleanup.join("; "))
        };
        return Err(RuntimeError::Unsupported(format!(
            "native x86 run stopped before exit: {detail}{cleanup}"
        )));
    }
    if !cleanup.is_empty() {
        return Err(RuntimeError::Unsupported(format!(
            "native x86 run cleanup failed: {}",
            cleanup.join("; ")
        )));
    }

    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        traps,
        report: CompatReport::default(),
        trap_limit_hit,
    })
}

#[derive(Clone, Debug)]
struct PublishedFaultEntry {
    host_start: u64,
    host_end: u64,
    guest_va: u64,
    is_copied_x87: bool,
    restores: Vec<ScratchRestore>,
}

/// One generation-scoped translated block and the complete guest instruction
/// span that produced it. The span is reclassified atomically on every reuse so
/// an RX prefix with mutable W+X or shared backing can never reuse or receive a
/// stale edge.
#[derive(Clone, Copy, Debug)]
struct CachedBlock {
    exec: u64,
    has_edges: bool,
    uses_fpu: bool,
    has_indirect_cache: bool,
    guest_len: usize,
}

fn apply_captured_return(
    snapshot: &mut X86UcontextSnapshot,
    target: u64,
    stack_adjust: u64,
) -> u64 {
    snapshot.gpr[reg::RSP] = snapshot.gpr[reg::RSP].wrapping_add(stack_adjust);
    target
}

#[derive(Clone, Copy, Debug)]
struct PendingChainEdge {
    entry_patch_abs: u64,
    entry_next_abs: u64,
    guard_exec: u64,
    guard_target_patch_abs: u64,
    guard_target_next_abs: u64,
    source: GuestVa,
    source_uses_fpu: bool,
    source_requires_guest_pkru: bool,
}

fn parse_native_x86_guest_va(value: &str) -> Option<GuestVa> {
    let value = value.trim();
    let raw = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(raw, 16).ok().map(GuestVa)
}

fn native_x86_trace_pcs() -> Vec<GuestVa> {
    std::env::var("CARRICK_NATIVE_X86_TRACE_PC")
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .filter_map(parse_native_x86_guest_va)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn native_x86_trace_xstate_graph() -> bool {
    std::env::var("CARRICK_NATIVE_X86_TRACE_XSTATE_GRAPH")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

/// Native xstate residency policy. Conservative remains the default rollback.
/// Neutral domains keep locally state-using targets cold and enter proven
/// neutral blocks with host-resident physical state; the guest PKRU guard can
/// force guest residency for every block. The unsafe local mode exists only
/// for deterministic red-first diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum NativeX86XstatePolicy {
    #[default]
    Conservative,
    NeutralDomains,
    UnsafeLocalDiagnostic,
}

impl NativeX86XstatePolicy {
    fn from_environment() -> Self {
        match std::env::var("CARRICK_NATIVE_X86_XSTATE_POLICY").as_deref() {
            Ok("neutral-domains" | "unsafe-target-barrier-diagnostic") => Self::NeutralDomains,
            Ok("unsafe-local-diagnostic") => Self::UnsafeLocalDiagnostic,
            _ => Self::Conservative,
        }
    }

    fn save_required(
        self,
        has_edges: bool,
        uses_fpu: bool,
        guest_pkru_requires_residency: bool,
    ) -> bool {
        guest_pkru_requires_residency
            || match self {
                Self::Conservative => has_edges || uses_fpu,
                Self::NeutralDomains | Self::UnsafeLocalDiagnostic => uses_fpu,
            }
    }

    fn keeps_state_targets_cold(self) -> bool {
        self == Self::NeutralDomains
    }

    /// Make the rejected local policy deterministically red instead of relying
    /// on incidental Rust/libc vector use between gateway entries. Production
    /// never selects this policy. A later state-using target must restore G or
    /// it observes the all-ones host `xmm0` installed here.
    fn configure_stress(self, save_required: bool, context: &mut X86DsrContext) {
        if self == Self::UnsafeLocalDiagnostic && !save_required {
            context.diagnostic_flags = 1;
        }
    }
}

/// Opt-in cold-edge barrier used to bisect the first transitive xstate
/// dependency. Values are `all`, a source PC, or `source->target`, separated by
/// commas. A selected edge remains pointed at its emitted cold stub.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeX86EdgeBarriers {
    all: bool,
    sources: Vec<GuestVa>,
    pairs: Vec<(GuestVa, GuestVa)>,
}

impl NativeX86EdgeBarriers {
    fn parse(value: &str) -> Self {
        let mut barriers = Self::default();
        for selector in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if selector == "all" {
                barriers.all = true;
                continue;
            }
            if let Some((source, target)) = selector.split_once("->") {
                if let (Some(source), Some(target)) = (
                    parse_native_x86_guest_va(source),
                    parse_native_x86_guest_va(target),
                ) {
                    barriers.pairs.push((source, target));
                }
            } else if let Some(source) = parse_native_x86_guest_va(selector) {
                barriers.sources.push(source);
            }
        }
        barriers
    }

    fn from_environment() -> Self {
        std::env::var("CARRICK_NATIVE_X86_EDGE_BARRIER")
            .ok()
            .map_or_else(Self::default, |value| Self::parse(&value))
    }

    fn contains(&self, source: GuestVa, target: GuestVa) -> bool {
        self.all || self.sources.contains(&source) || self.pairs.contains(&(source, target))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum NativeX86XstateEvent {
    Entry = 1,
    PatchCachedTarget = 2,
    RegisterPendingEdge = 3,
    PatchPendingEdge = 4,
    BarrierEdge = 5,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeX86XstateDecision {
    source_uses_fpu: bool,
    target_uses_fpu: bool,
    has_edges: bool,
    save_required: bool,
    cache_hit: bool,
    unsafe_local_policy: bool,
    target_barrier_policy: bool,
}

impl NativeX86XstateDecision {
    fn flags(self) -> u64 {
        u64::from(self.source_uses_fpu)
            | (u64::from(self.target_uses_fpu) << 1)
            | (u64::from(self.has_edges) << 2)
            | (u64::from(self.save_required) << 3)
            | (u64::from(self.cache_hit) << 4)
            | (u64::from(self.unsafe_local_policy) << 5)
            | (u64::from(self.target_barrier_policy) << 6)
    }
}

fn native_x86_trace_xstate(
    trace_pcs: &[GuestVa],
    trace_graph: bool,
    source: GuestVa,
    target: GuestVa,
    event: NativeX86XstateEvent,
    decision: NativeX86XstateDecision,
    snapshot: &X86UcontextSnapshot,
) {
    let selected_pc = trace_pcs.contains(&source) || trace_pcs.contains(&target);
    let selected_graph_edge = trace_graph
        && matches!(
            event,
            NativeX86XstateEvent::PatchCachedTarget | NativeX86XstateEvent::PatchPendingEdge
        );
    if !selected_pc && !selected_graph_edge {
        return;
    }
    if !selected_pc {
        crate::probes::native_x86_xstate_edge(crate::probes::NativeX86XstateProbe {
            source: source.0,
            target: target.0,
            event: event as u64,
            flags: decision.flags(),
            xstate_bv: snapshot.xstate_bv(),
            fcw: 0,
            mxcsr: 0,
            pkru: 0,
            legacy_hash: 0,
            ymm_hash: 0,
            opmask_zmm_hash: 0,
            extended_hash: 0,
        });
        return;
    }
    let summary = snapshot.xstate_summary();
    crate::probes::native_x86_xstate(crate::probes::NativeX86XstateProbe {
        source: source.0,
        target: target.0,
        event: event as u64,
        flags: decision.flags(),
        xstate_bv: summary.xstate_bv,
        fcw: summary.fcw,
        mxcsr: summary.mxcsr,
        pkru: summary.pkru,
        legacy_hash: summary.legacy_hash,
        ymm_hash: summary.ymm_hash,
        opmask_zmm_hash: summary.opmask_zmm_hash,
        extended_hash: summary.extended_hash,
    });
}

fn native_x86_identity_stamp(
    active: &SharedRun,
    tid: crate::thread::ThreadId,
) -> Option<X86IdentityStamp> {
    let live_gate = active.dispatcher.identity_fast_path_word()?;
    let guest_tid = crate::dispatch::guest_visible_tid(tid, &active.registry)?;
    let live_gate = live_gate as *const std::sync::atomic::AtomicU32 as u64;
    Some(X86IdentityStamp::live(
        live_gate,
        active.dispatcher.identity_pid(),
        guest_tid,
    ))
}

fn native_x86_translation_is_ephemeral(
    protections: &carrick_guest_mem::protections::MemoryProtections,
    guest_pc: u64,
    guest_len: usize,
) -> bool {
    protections.range_translation_requires_ephemeral(guest_pc, guest_len)
}

fn native_x86_edge_target_is_cacheable(
    protections: &carrick_guest_mem::protections::MemoryProtections,
    target: GuestVa,
    guest_len: usize,
) -> bool {
    !native_x86_translation_is_ephemeral(protections, target.0, guest_len)
}

/// Plan an uncached direct-edge target before a waiter is published. The first
/// x86 instruction may cross a page/protection boundary, so classifying one byte
/// can arm a persistent edge into a mutable shared suffix. Any typed guest-fetch
/// or decode/planning failure returns `None`; this path is speculative, so the
/// caller keeps the edge cold and authoritative execution later delivers the
/// fault instead of signaling before the branch is taken.
fn native_x86_uncached_target_guest_len<E>(
    target: GuestVa,
    read: impl FnMut(u64) -> Result<Vec<u8>, E>,
) -> Option<usize> {
    let block = plan_block_with_reader(target.0, 256, PAGE, read).ok()?;
    let len = block.end.checked_sub(block.start)?;
    usize::try_from(len).ok().filter(|len| *len != 0)
}

fn native_x86_return_cache_is_armable(
    protections: &carrick_guest_mem::protections::MemoryProtections,
    source_translation_ephemeral: bool,
    target: GuestVa,
    target_guest_len: usize,
) -> bool {
    !source_translation_ephemeral
        && native_x86_edge_target_is_cacheable(protections, target, target_guest_len)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum X86X87FipNormalizationError {
    #[error("native x86 JIT executable range overflows")]
    JitRangeOverflow,
    #[error("native x86 x87 FIP 0x{host_fip:x} remained in JIT coordinates across an entry")]
    UnchangedJitPointer { host_fip: u64 },
    #[error("native x86 x87 FIP 0x{host_fip:x} has no exact translated instruction metadata")]
    MissingInstruction { host_fip: u64 },
    #[error("native x86 x87 FIP 0x{host_fip:x} has ambiguous translated instruction metadata")]
    AmbiguousInstruction { host_fip: u64 },
    #[error("native x86 x87 FIP 0x{host_fip:x} maps to non-x87 translated metadata")]
    NonX87Instruction { host_fip: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X86GatewayX87Witness {
    entry_fip: u64,
    entry_fdp: u64,
    completed_guest_va: u64,
    completed_guest_data_va: u64,
    completed_data_valid: bool,
}

fn normalize_x86_gateway_x87_fip(
    entries: &[PublishedFaultEntry],
    jit_range: std::ops::Range<u64>,
    witness: X86GatewayX87Witness,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<(), X86X87FipNormalizationError> {
    let X86GatewayX87Witness {
        entry_fip,
        entry_fdp,
        completed_guest_va: last_copied_x87_guest_va,
        completed_guest_data_va: last_copied_x87_guest_data_va,
        completed_data_valid: last_copied_x87_data_valid,
    } = witness;
    const X87_FEATURE: u64 = 1;

    if last_copied_x87_guest_va != 0 {
        // XSAVEOPT may leave a host's x87 FIP initial even after a copied x87
        // stack instruction. The emitter records only after that instruction
        // has completed, so this is an exact guest coordinate, not a block
        // boundary guess.
        snapshot.normalize_identity_native_x87_execution(
            last_copied_x87_guest_va,
            last_copied_x87_data_valid.then_some(last_copied_x87_guest_data_va),
        );
        return Ok(());
    }
    let host_fip = snapshot.x87_instruction_pointer();
    let host_fdp = snapshot.x87_data_pointer();
    if last_copied_x87_guest_va == 0 && host_fdp == 0 && entry_fdp != 0 {
        // An x87-free translated interval cannot architecturally replace FDP.
        // Preserve the imported virtual data pointer when host XSAVEOPT emits
        // its initial zero representation.
        snapshot.xsave[16..24].copy_from_slice(&entry_fdp.to_le_bytes());
    }
    if snapshot.xstate_bv() & X87_FEATURE == 0 {
        if entry_fip == 0 {
            return Ok(());
        }
        // No copied x87 instruction completed in this entry, but host
        // XSAVEOPT omitted the initial-looking x87 component. Its header bit
        // therefore cannot invalidate the authoritative virtual environment
        // imported at the previous boundary. Restore the exact entry FIP and
        // materialize x87 without changing the guest's imported selectors.
        snapshot.xsave[8..16].copy_from_slice(&entry_fip.to_le_bytes());
        let xstate_bv =
            u64::from_le_bytes(snapshot.xsave[512..520].try_into().unwrap_or([0; 8])) | X87_FEATURE;
        snapshot.xsave[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        return Ok(());
    }
    if !jit_range.contains(&host_fip) {
        if host_fip == 0 && entry_fip != 0 {
            // XRSTOR can carry a virtual FIP that the following host
            // XSAVEOPT reports as zero even while keeping x87 materialized.
            // With no completed copied-x87 witness, the entry environment is
            // authoritative and must survive the non-x87 translated interval.
            snapshot.xsave[8..16].copy_from_slice(&entry_fip.to_le_bytes());
            let xstate_bv =
                u64::from_le_bytes(snapshot.xsave[512..520].try_into().unwrap_or([0; 8]))
                    | X87_FEATURE;
            snapshot.xsave[512..520].copy_from_slice(&xstate_bv.to_le_bytes());
        }
        // Restored/native identity pointers are already guest VAs. In
        // particular, FDP needs no translation and is intentionally untouched.
        return Ok(());
    }
    if host_fip == entry_fip {
        // A guest can restore an arbitrary numeric FIP inside the host JIT
        // range. Without an observed change this boundary cannot distinguish
        // that value from an execution at the same host PC, so never guess.
        return Err(X86X87FipNormalizationError::UnchangedJitPointer { host_fip });
    }

    let mut matching = entries
        .iter()
        .filter(|entry| host_fip >= entry.host_start && host_fip < entry.host_end);
    let entry = matching
        .next()
        .ok_or(X86X87FipNormalizationError::MissingInstruction { host_fip })?;
    if matching.next().is_some() {
        return Err(X86X87FipNormalizationError::AmbiguousInstruction { host_fip });
    }
    if !entry.is_copied_x87 {
        return Err(X86X87FipNormalizationError::NonX87Instruction { host_fip });
    }
    snapshot.normalize_identity_native_x87_execution(entry.guest_va, None);
    Ok(())
}

fn recover_x86_fault_snapshot(
    entries: &[PublishedFaultEntry],
    host_rip: u64,
    scratch: [u64; 2],
    snapshot: &mut X86UcontextSnapshot,
) -> Option<u64> {
    let entry = entries
        .iter()
        .find(|entry| host_rip >= entry.host_start && host_rip < entry.host_end)?;
    for restore in &entry.restores {
        snapshot.gpr[restore.snapshot_gpr] = *scratch.get(restore.scratch_index)?;
    }
    snapshot.rip = entry.guest_va;
    Some(entry.guest_va)
}

/// Run one guest thread's translate/execute/service loop to completion. The
/// process's initial thread runs this inline; a `clone` child runs it on its
/// own host thread. `slice_off`/`slice_len` bound this thread's non-overlapping
/// window into the shared JIT code cache (its own cursor + block cache), so
/// concurrent threads never collide in the cache. All guest memory is identity-
/// mapped, so the block cache is per-thread but the translated bytes are the
/// same for a given VA.
#[allow(clippy::too_many_arguments)]
fn run_x86_thread(
    start: ThreadStart,
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    slice_off: usize,
    slice_len: usize,
    memory: &mut IdentityGuestMemory,
    waiter: &mut crate::io_wait::ThreadWaiter,
    executable_registration: &mut ExecutableThreadRegistration,
) -> ThreadRunOutcome {
    // The "active" shared run: normally the caller's, but a `fork()` child
    // swaps to a FRESH private code cache (its own `SharedRun`) so it never
    // re-JITs into pages the parent also writes (the SHM_ANON code cache is
    // MAP_SHARED and survives fork). The image is COW-identical after fork (the
    // guest's code pages keep their VAs), so it stays borrowed from the caller.
    let mut active = Arc::clone(shared);
    let mut tid = tid;
    let mut host_registration = NativeHostThreadRegistration::new(&active, tid);
    // Mutable so an in-place `execve` can retire this and swap in the new image.
    let mut image = shared.current_image();
    let jit = FreebsdHostJit;
    let max_traps = shared.max_traps;

    let (snapshot, guest_fsbase, mut next) = match start {
        ThreadStart::Initial { entry, rsp } => {
            let mut snapshot = X86UcontextSnapshot::new();
            snapshot.gpr[reg::RSP] = rsp;
            (snapshot, 0u64, entry)
        }
        ThreadStart::Detached { snapshot, fsbase } => {
            let snapshot = *snapshot;
            let next = snapshot.rip;
            (snapshot, fsbase, next)
        }
    };
    // One persistent context owns the guest register/XSAVE state for this host
    // thread. The hot loop mutates only scalar entry fields; rebuilding this
    // 33 KiB value per block made GCC spend most host samples in `memcpy`.
    let mut context = X86DsrContext::new(snapshot, 0, next);
    context.guest_fsbase = guest_fsbase;
    let mut cursor = slice_off;
    let mut cursor_limit = slice_off + slice_len;
    let mut traps = 0usize;
    let mut exit_code: Option<i32> = None;
    let mut fault_detail: Option<String> = None;
    // Detached guest threads can start after a host fork and therefore never
    // observe this loop's `BecameForkChild` transition. Derive the initial
    // process identity from the dispatcher; the in-thread fork transition below
    // still flips this to true for the thread that creates a descendant.
    let mut forked = active.dispatcher.is_forked_guest_process();
    // Write end inherited by a CLONE_VFORK child. Closing on `_exit` produces
    // EOF; successful in-process exec explicitly writes then closes it.
    let mut vfork_completion_fd: Option<i32> = None;

    // Generation-scoped translations keyed by guest VA. Each `CachedBlock`
    // retains its full planned guest span so reuse, incoming edges, and return
    // targets atomically re-check mixed immutable/mutable executable spans
    // rather than sampling only the first byte. Cursor is monotonic.
    let mut cache: std::collections::HashMap<u64, CachedBlock, VaBuildHasher> =
        std::collections::HashMap::default();
    // Predecoded plans for genuine indirect exits. Perl/m4 execute millions of
    // returns; decoding the same `ret` with iced-x86 on every trip dominated
    // their runtime even though the translated block itself was cached.
    let mut cflow_plans: std::collections::HashMap<u64, cflow::ControlFlowPlan, VaBuildHasher> =
        std::collections::HashMap::default();
    // One thread-local, generation-scoped monomorphic entry per emitted return
    // site. Emitted code publishes a one-based index; the gateway consumes the
    // slice only while this loop is inside `enter_translated`, so growth and
    // replacement happen solely at gateway boundaries.
    let mut indirect_cache_entries: Vec<X86IndirectCacheEntry> = Vec::new();
    // Chain edges awaiting their target's translation. When `target_va` is
    // translated, each guard target is published first and its original branch
    // is redirected from the cold stub to that guard last.
    let mut pending: std::collections::HashMap<u64, Vec<PendingChainEdge>, VaBuildHasher> =
        std::collections::HashMap::default();
    let mut fault_entries: Vec<PublishedFaultEntry> = Vec::new();
    let mut code_generation = active
        .executable_epoch
        .current_generation()
        .unwrap_or(ExecutableGeneration::INITIAL);
    // An ephemeral block's fault metadata lives only through its one gateway
    // entry. Retire it at the following Rust boundary, after a possible Signal
    // exit has had the opportunity to reverse-map the live JIT fault RIP.
    let mut retired_ephemeral_fault_range: Option<(u64, u64)> = None;
    // Breadcrumb ring: the last guest VAs entered, for diagnosing where an
    // unhandled scenario was reached from.
    let mut history: Vec<u64> = Vec::new();
    let trace_pcs = native_x86_trace_pcs();
    let trace_xstate_graph = native_x86_trace_xstate_graph();
    let xstate_policy = NativeX86XstatePolicy::from_environment();
    let edge_barriers = NativeX86EdgeBarriers::from_environment();
    // Namespace-visible pid/tid and the live-gate ADDRESS are stable for this
    // host thread until fork swaps `active`. Computing them at every gateway
    // entry turned Kaniko's snapshot walk into millions of host getpid(2)
    // calls even though the emitted identity syscall itself never trapped.
    let mut identity_stamp = native_x86_identity_stamp(&active, tid);

    'run: while traps < max_traps {
        // Common host boundary: one coordinator mutex round-trip, no global
        // runtime lock. A fork stop racing clone admission or a prior blocking
        // wait parks this exact registration before any dispatcher mutex.
        if let Err(error) = active
            .executable_epoch
            .fork_safe_boundary(executable_registration)
        {
            fault_detail = Some(format!(
                "native x86 host-fork boundary failed before guest loop: {error:?}"
            ));
            break 'run;
        }
        // Another guest thread requested process exit (`exit_group`, or the
        // last thread's `exit(2)`): stop this thread's loop and surface the
        // recorded code. The initial thread turns this into the `RunResult`;
        // a sibling thread just ends (its closure re-requests idempotently). A
        // fork descendant exits through the same lifecycle helper as a direct
        // syscall path, preserving buffered output and orphan publication.
        if active.exit.requested() {
            let code = active.exit.code().unwrap_or(0);
            if forked {
                crate::exec_helpers::forked_child_exit(
                    code,
                    active.dispatcher.stdout(),
                    active.dispatcher.stderr(),
                );
            }
            return ThreadRunOutcome::Exit { code, traps };
        }
        // A terminal exec owner retires every exact sibling registration. This
        // coordinator check is authoritative even in the short interval before
        // the auxiliary exec-stop atomic is published. Returning drops this
        // registration and wakes the owner's retirement CV; no ack counter can
        // authorize teardown early.
        match active
            .executable_epoch
            .terminal_stop_for_nonowner(executable_registration)
        {
            Ok(Some(stop)) => {
                let _ = (stop.owner, stop.phase);
                return ThreadRunOutcome::RetiredForExec { traps };
            }
            Ok(None) => {}
            Err(error) => {
                fault_detail = Some(format!(
                    "native x86 executable terminal state failed: {error:?}"
                ));
                break 'run;
            }
        }
        if active.exit.exec_stop_requested() {
            return ThreadRunOutcome::RetiredForExec { traps };
        }
        if let Some((start, end)) = retired_ephemeral_fault_range.take() {
            fault_entries.retain(|entry| entry.host_start < start || entry.host_start >= end);
        }
        history.push(next);
        if history.len() > 64 {
            history.remove(0);
        }
        if trace_pcs.contains(&GuestVa(next)) {
            let rsp = context.snapshot.gpr[reg::RSP];
            let return_pc = memory
                .read_bytes_raw(rsp, 8)
                .ok()
                .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            crate::probes::native_x86_pc(
                next,
                rsp,
                context.snapshot.gpr[reg::RDI],
                context.snapshot.gpr[reg::RBP],
                return_pc,
            );
        }
        let entry_execute_error = {
            let _mapping_guard = IDENTITY_HOST_MAPPING_LOCK.read();
            identity_execute_fault_under_mapping_lock(GuestVa(next))
        };
        if let Some(error) = entry_execute_error {
            match deliver_x86_instruction_fetch_error(
                &active,
                tid,
                &mut context.snapshot,
                next,
                error,
            ) {
                Ok(SynchronousFaultDelivery::RetryAt(rip)) => {
                    next = rip;
                    continue;
                }
                Ok(SynchronousFaultDelivery::Fatal(final_signum)) => {
                    if forked {
                        crate::exec_helpers::forked_child_die_by_signal(
                            final_signum,
                            active.dispatcher.stdout(),
                            active.dispatcher.stderr(),
                        );
                    }
                    exit_code = Some(128 + final_signum);
                    break 'run;
                }
                Err(detail) => {
                    fault_detail = Some(detail);
                    break 'run;
                }
            }
        }
        let cached_block = cache.get(&next).copied();
        let mut source_translation_ephemeral = false;
        let guest_pkru_requires_residency = context.snapshot.pkru().requires_guest_residency();
        let mut cache_hit = false;
        let mut ephemeral_cflow_plan: Option<(u64, cflow::ControlFlowPlan)> = None;
        let mut ephemeral_return_adjust: Option<u64> = None;
        let mut current_ephemeral_fault_range: Option<(u64, u64)> = None;
        let (exec, has_edges, uses_fpu, has_indirect_cache) = if let Some(hit) = cached_block
            .filter(|hit| {
                native_x86_edge_target_is_cacheable(
                    &IDENTITY_PROTECTIONS,
                    GuestVa(next),
                    hit.guest_len,
                )
            }) {
            cache_hit = true;
            (
                hit.exec,
                hit.has_edges,
                hit.uses_fpu,
                hit.has_indirect_cache,
            )
        } else {
            // This thread's JIT region (the fork child swapped `active` to its
            // own private cache). Re-borrowed each translation so a mid-run swap
            // is picked up; the borrow never outlives this branch.
            let region = &active.region;
            // Plan bounded to the 4 KiB guest page so a block stays within one
            // mapped PT_LOAD segment (segments are page-aligned; a larger span
            // could read across an unmapped gap between them). `plan_block`
            // always includes its first instruction even if it spans the page
            // boundary (an internal, in-segment boundary), so it never returns
            // an empty `Continue{target: start}` — which the chainer would turn
            // into an infinite self-jump.
            let block = match plan_block_with_reader(next, 256, PAGE, |va| {
                identity_checked_fetch_x86_instruction(GuestVa(va))
            }) {
                Ok(block) => block,
                Err(X86BlockPlanError::Read { va, error }) => {
                    match deliver_x86_instruction_fetch_error(
                        &active,
                        tid,
                        &mut context.snapshot,
                        va,
                        error,
                    ) {
                        Ok(SynchronousFaultDelivery::RetryAt(rip)) => {
                            next = rip;
                            continue 'run;
                        }
                        Ok(SynchronousFaultDelivery::Fatal(final_signum)) => {
                            if forked {
                                crate::exec_helpers::forked_child_die_by_signal(
                                    final_signum,
                                    active.dispatcher.stdout(),
                                    active.dispatcher.stderr(),
                                );
                            }
                            exit_code = Some(128 + final_signum);
                            break 'run;
                        }
                        Err(detail) => {
                            fault_detail = Some(detail);
                            break 'run;
                        }
                    }
                }
                Err(X86BlockPlanError::Block(error)) => {
                    fault_detail = Some(format!("plan_block at 0x{next:x}: {error}"));
                    break 'run;
                }
            };
            // Defensive: a block that plans zero instructions AND only
            // CONTINUES at its own start makes no progress (a page-spanning
            // instruction that could not be planned, or the guest ran off
            // mapped code). A block whose first instruction is a TERMINATOR
            // (call/jmp/jcc/syscall/sensitive) also has zero copy-instructions
            // and `exit.va() == start` — that is normal, so match only the
            // `Continue` shape. Emit a LOUD breadcrumb on the real no-progress
            // case so an unhandled scenario is debuggable without guessing.
            let empty_self_continue = block.instructions.is_empty()
                && matches!(block.exit, X86Exit::Continue { target, .. } if target == next);
            if empty_self_continue {
                let fetch = identity_checked_fetch_x86_instruction(GuestVa(next))
                    .map(|bytes| format!("{bytes:02x?}"))
                    .unwrap_or_else(|error| format!("fetch-error={error:?}"));
                let in_seg = image.segments.iter().any(|&(s, e)| next >= s && next < e);
                let recent: Vec<String> = history
                    .iter()
                    .rev()
                    .take(8)
                    .map(|v| format!("0x{v:x}"))
                    .collect();
                fault_detail = Some(format!(
                    "no-progress block at 0x{next:x}: exit={:?} in_segment={in_seg} \
                     bytes={fetch} segments={:x?} recent_blocks={:?}",
                    block.exit, image.segments, recent,
                ));
                break;
            }
            let guest_len = match block
                .end
                .checked_sub(block.start)
                .and_then(|len| usize::try_from(len).ok())
            {
                Some(len) if len != 0 => len,
                _ => {
                    fault_detail = Some(format!(
                        "invalid native x86 guest block span 0x{:x}..0x{:x}",
                        block.start, block.end
                    ));
                    break;
                }
            };
            // Classify the complete planned instruction span before publishing
            // cache metadata, edges, or a return-cache site. In particular, the
            // planner may include its first instruction across a page boundary.
            source_translation_ephemeral =
                native_x86_translation_is_ephemeral(&IDENTITY_PROTECTIONS, block.start, guest_len);
            let mut body = vec![0u8; guest_len];
            if let Err(error) =
                identity_checked_read_executable_exact(GuestVa(block.start), &mut body)
            {
                match deliver_x86_instruction_fetch_error(
                    &active,
                    tid,
                    &mut context.snapshot,
                    next,
                    error,
                ) {
                    Ok(SynchronousFaultDelivery::RetryAt(rip)) => {
                        next = rip;
                        continue 'run;
                    }
                    Ok(SynchronousFaultDelivery::Fatal(final_signum)) => {
                        if forked {
                            crate::exec_helpers::forked_child_die_by_signal(
                                final_signum,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(128 + final_signum);
                        break 'run;
                    }
                    Err(detail) => {
                        fault_detail = Some(detail);
                        break 'run;
                    }
                }
            }
            let control_flow_plan = match block.exit {
                X86Exit::ControlFlow { va, .. } => {
                    let offset = va
                        .checked_sub(block.start)
                        .and_then(|offset| usize::try_from(offset).ok());
                    let Some(bytes) = offset.and_then(|offset| body.get(offset..)) else {
                        fault_detail = Some(format!(
                            "cflow plan at 0x{va:x} is outside block 0x{:x}..0x{:x}",
                            block.start, block.end
                        ));
                        break 'run;
                    };
                    match cflow::ControlFlowPlan::decode(bytes, va) {
                        Ok(plan) => Some((va, plan)),
                        Err(error) => {
                            fault_detail = Some(format!("cflow plan at 0x{va:x}: {error}"));
                            break 'run;
                        }
                    }
                }
                _ => None,
            };
            let mut linked = match emit_block_linked(&body, &block) {
                Ok(t) => t,
                Err(e) => {
                    // Loud: include the already checked terminator bytes so an
                    // unsupported instruction is identifiable without another
                    // uncontained guest-memory read.
                    let at = block.exit.va();
                    let terminator_bytes = at
                        .checked_sub(block.start)
                        .and_then(|offset| usize::try_from(offset).ok())
                        .and_then(|offset| body.get(offset..))
                        .unwrap_or(&[]);
                    fault_detail = Some(format!(
                        "emit_block at 0x{next:x} ({:?}): {e} — insn bytes at 0x{at:x} = {terminator_bytes:02x?}",
                        block.exit,
                    ));
                    break;
                }
            };
            if linked.bytes.len() > slice_len {
                fault_detail = Some(format!(
                    "single translated block exceeds the {slice_len}-byte JIT slice at 0x{next:x}"
                ));
                break;
            }
            if cursor + linked.bytes.len() > cursor_limit {
                // The guest is back at a gateway boundary, so no code in this
                // thread's private slice is executing. Recycle the whole slice
                // instead of imposing a lifetime translation-volume limit:
                // large static Go programs such as Kaniko execute far more than
                // 4 MiB of distinct emitted code during startup. Guest return
                // addresses remain guest VAs, so dropping every block/edge map
                // and translating `next` at the slice base is safe.
                cursor = cursor_limit - slice_len;
                cache.clear();
                cflow_plans.clear();
                indirect_cache_entries.clear();
                pending.clear();
                fault_entries.clear();
            }
            if let Some(site) = linked.indirect_cache {
                if source_translation_ephemeral {
                    // Site id zero keeps the gateway cache cold, while the
                    // emitted probe still captures `[rsp]` exactly once for the
                    // Rust resolver below. No persistent cache entry is created.
                    ephemeral_return_adjust = Some(site.stack_adjust);
                } else {
                    let Some(site_id) = indirect_cache_entries
                        .len()
                        .checked_add(1)
                        .and_then(|id| u32::try_from(id).ok())
                    else {
                        fault_detail = Some("native x86 indirect-cache site id overflow".into());
                        break;
                    };
                    linked.bytes[site.site_id_imm_off..site.site_id_imm_off + 4]
                        .copy_from_slice(&site_id.to_le_bytes());
                    indirect_cache_entries
                        .push(X86IndirectCacheEntry::return_site(site.stack_adjust));
                }
            }
            // SAFETY: the JIT region is mapped for the run; cursor is in range.
            let exec = unsafe { region.exec_base.as_ptr().add(cursor) };
            let wptr = match region.write_ptr_for(exec) {
                Some(p) => p,
                None => {
                    fault_detail = Some("JIT write alias out of range".to_string());
                    break;
                }
            };
            // SAFETY: wptr is the RW alias of exec; linked.bytes fits.
            unsafe {
                std::ptr::copy_nonoverlapping(linked.bytes.as_ptr(), wptr, linked.bytes.len())
            };
            jit.flush_icache(exec, linked.bytes.len());
            let exec_u64 = exec as u64;
            fault_entries.extend(linked.fault_map.iter().map(|entry| PublishedFaultEntry {
                host_start: exec_u64 + entry.emitted_start as u64,
                host_end: exec_u64 + entry.emitted_end as u64,
                guest_va: entry.guest_va,
                is_copied_x87: entry.is_copied_x87,
                restores: entry.restores.clone(),
            }));
            cursor += linked.bytes.len();
            let entry = if source_translation_ephemeral {
                current_ephemeral_fault_range =
                    Some((exec_u64, exec_u64 + linked.bytes.len() as u64));
                CachedBlock {
                    exec: exec_u64,
                    has_edges: false,
                    uses_fpu: block.uses_fpu,
                    has_indirect_cache: false,
                    guest_len,
                }
            } else {
                CachedBlock {
                    exec: exec_u64,
                    has_edges: !linked.edges.is_empty() || linked.indirect_cache.is_some(),
                    uses_fpu: block.uses_fpu,
                    has_indirect_cache: linked.indirect_cache.is_some(),
                    guest_len,
                }
            };
            if !source_translation_ephemeral {
                cache.insert(next, entry);
            }
            if let Some((va, plan)) = control_flow_plan {
                if source_translation_ephemeral {
                    ephemeral_cflow_plan = Some((va, plan));
                } else {
                    cflow_plans.insert(va, plan);
                }
            }
            // Mutable executable blocks are one-entry translations: discard
            // incoming waiters and publish neither outgoing edges nor return-
            // cache state. Only private immutable RX text retains the normal
            // guarded chaining path.
            if source_translation_ephemeral {
                pending.remove(&next);
            } else {
                // Register this block's outgoing edges; patch any whose target is
                // already translated (a self-edge sees this block, now cached).
                for edge in &linked.edges {
                    let source = GuestVa(next);
                    let target = GuestVa(edge.target_va);
                    let entry_patch_abs = exec_u64 + edge.entry_rel32_off as u64;
                    let entry_next_abs = entry_patch_abs + 4;
                    let guard_exec = exec_u64 + edge.guard_off as u64;
                    let guard_target_patch_abs = exec_u64 + edge.guard_target_rel32_off as u64;
                    let guard_target_next_abs = guard_target_patch_abs + 4;
                    let source_save = xstate_policy.save_required(
                        true,
                        block.uses_fpu,
                        guest_pkru_requires_residency,
                    );
                    let unsafe_local_policy =
                        xstate_policy == NativeX86XstatePolicy::UnsafeLocalDiagnostic;
                    let target_barrier_policy = xstate_policy.keeps_state_targets_cold();
                    let cached_target = cache.get(&edge.target_va).copied();
                    let target_uses_fpu = cached_target.is_some_and(|block| block.uses_fpu);
                    let target_guest_len =
                        cached_target.map(|block| block.guest_len).or_else(|| {
                            native_x86_uncached_target_guest_len(target, |va| {
                                identity_checked_fetch_x86_instruction(GuestVa(va))
                            })
                        });
                    if target_guest_len.is_none_or(|guest_len| {
                        !native_x86_edge_target_is_cacheable(
                            &IDENTITY_PROTECTIONS,
                            target,
                            guest_len,
                        )
                    }) || edge_barriers.contains(source, target)
                        || (target_barrier_policy && target_uses_fpu)
                    {
                        native_x86_trace_xstate(
                            &trace_pcs,
                            trace_xstate_graph,
                            source,
                            target,
                            NativeX86XstateEvent::BarrierEdge,
                            NativeX86XstateDecision {
                                source_uses_fpu: block.uses_fpu,
                                target_uses_fpu,
                                has_edges: true,
                                save_required: source_save,
                                cache_hit: cached_target.is_some(),
                                unsafe_local_policy,
                                target_barrier_policy,
                            },
                            &context.snapshot,
                        );
                        continue;
                    }
                    if let Some(target_block) = cached_target {
                        native_x86_trace_xstate(
                            &trace_pcs,
                            trace_xstate_graph,
                            source,
                            target,
                            NativeX86XstateEvent::PatchCachedTarget,
                            NativeX86XstateDecision {
                                source_uses_fpu: block.uses_fpu,
                                target_uses_fpu,
                                has_edges: true,
                                save_required: source_save,
                                unsafe_local_policy,
                                target_barrier_policy,
                                ..NativeX86XstateDecision::default()
                            },
                            &context.snapshot,
                        );
                        publish_guarded_chain_edge(
                            region,
                            &jit,
                            GuardedChainPatch {
                                entry_patch_abs,
                                entry_next_abs,
                                guard_exec,
                                guard_target_patch_abs,
                                guard_target_next_abs,
                            },
                            target_block.exec,
                        );
                    } else {
                        native_x86_trace_xstate(
                            &trace_pcs,
                            trace_xstate_graph,
                            source,
                            target,
                            NativeX86XstateEvent::RegisterPendingEdge,
                            NativeX86XstateDecision {
                                source_uses_fpu: block.uses_fpu,
                                has_edges: true,
                                save_required: source_save,
                                unsafe_local_policy,
                                target_barrier_policy,
                                ..NativeX86XstateDecision::default()
                            },
                            &context.snapshot,
                        );
                        pending
                            .entry(edge.target_va)
                            .or_default()
                            .push(PendingChainEdge {
                                entry_patch_abs,
                                entry_next_abs,
                                guard_exec,
                                guard_target_patch_abs,
                                guard_target_next_abs,
                                source,
                                source_uses_fpu: block.uses_fpu,
                                source_requires_guest_pkru: guest_pkru_requires_residency,
                            });
                    }
                }
                // Patch any earlier-translated blocks that were waiting for THIS VA.
                if let Some(waiters) = pending.remove(&next) {
                    for waiter in waiters {
                        let source_save = xstate_policy.save_required(
                            true,
                            waiter.source_uses_fpu,
                            waiter.source_requires_guest_pkru,
                        );
                        let target_barrier_policy = xstate_policy.keeps_state_targets_cold();
                        let keep_cold = target_barrier_policy && block.uses_fpu;
                        native_x86_trace_xstate(
                            &trace_pcs,
                            trace_xstate_graph,
                            waiter.source,
                            GuestVa(next),
                            if keep_cold {
                                NativeX86XstateEvent::BarrierEdge
                            } else {
                                NativeX86XstateEvent::PatchPendingEdge
                            },
                            NativeX86XstateDecision {
                                source_uses_fpu: waiter.source_uses_fpu,
                                target_uses_fpu: block.uses_fpu,
                                has_edges: true,
                                save_required: source_save,
                                unsafe_local_policy: xstate_policy
                                    == NativeX86XstatePolicy::UnsafeLocalDiagnostic,
                                target_barrier_policy,
                                ..NativeX86XstateDecision::default()
                            },
                            &context.snapshot,
                        );
                        if !keep_cold {
                            publish_guarded_chain_edge(
                                region,
                                &jit,
                                GuardedChainPatch {
                                    entry_patch_abs: waiter.entry_patch_abs,
                                    entry_next_abs: waiter.entry_next_abs,
                                    guard_exec: waiter.guard_exec,
                                    guard_target_patch_abs: waiter.guard_target_patch_abs,
                                    guard_target_next_abs: waiter.guard_target_next_abs,
                                },
                                exec_u64,
                            );
                        }
                    }
                }
            }
            (
                entry.exec,
                entry.has_edges,
                entry.uses_fpu,
                entry.has_indirect_cache,
            )
        };

        // A chainable block runs many blocks with live FPU state, so production
        // execution restores/saves around every chainable entry. The explicitly
        // unsafe diagnostic policies recreate rejected gating experiments solely
        // for a targeted transition bisect.
        // A return cache can hit only while guest xstate is resident. Force a
        // guest-resident entry when Rust enters the return block directly;
        // a chained host-resident arrival retains save_fpu=0 and the gateway
        // keeps that site cold.
        let save_required = has_indirect_cache
            || xstate_policy.save_required(has_edges, uses_fpu, guest_pkru_requires_residency);
        native_x86_trace_xstate(
            &trace_pcs,
            trace_xstate_graph,
            GuestVa(next),
            GuestVa(next),
            NativeX86XstateEvent::Entry,
            NativeX86XstateDecision {
                source_uses_fpu: uses_fpu,
                target_uses_fpu: uses_fpu,
                has_edges,
                save_required,
                cache_hit,
                unsafe_local_policy: xstate_policy == NativeX86XstatePolicy::UnsafeLocalDiagnostic,
                target_barrier_policy: xstate_policy.keeps_state_targets_cold(),
            },
            &context.snapshot,
        );
        let in_jit = match active
            .executable_epoch
            .admit(executable_registration, code_generation)
        {
            Ok(JitAdmission::Entered(guard)) => guard,
            Ok(JitAdmission::Refresh(generation)) => {
                cache.clear();
                cflow_plans.clear();
                indirect_cache_entries.clear();
                pending.clear();
                fault_entries.clear();
                retired_ephemeral_fault_range = None;
                code_generation = generation;
                continue 'run;
            }
            Ok(JitAdmission::Stopped(stop)) => {
                if stop.owner.thread != executable_registration.id {
                    return ThreadRunOutcome::RetiredForExec { traps };
                }
                fault_detail = Some(format!(
                    "native x86 terminal owner attempted JIT admission during {:?}",
                    stop.phase
                ));
                break 'run;
            }
            Err(error) => {
                fault_detail = Some(format!(
                    "native x86 executable epoch admission failed: {error:?}"
                ));
                break 'run;
            }
        };
        context.prepare_entry(
            exec,
            next,
            save_required,
            if has_edges { identity_stamp } else { None },
            Some(&active.executable_epoch.stop_word),
        );
        xstate_policy.configure_stress(save_required, &mut context);
        // SAFETY: the thread-local vector is mutated only at gateway
        // boundaries. It remains stable for the complete translated interval.
        unsafe { context.publish_indirect_cache(&indirect_cache_entries) };
        // SAFETY: exec holds a freshly translated block ending in an exit stub
        // (or chaining to one); rsp is a valid guest stack.
        let admitted = in_jit.admission();
        let entry_x87_fip = context.snapshot.x87_instruction_pointer();
        let entry_x87_fdp = context.snapshot.x87_data_pointer();
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut context) };
        // FXSAVE64 records copied x87 instructions in host/JIT coordinates.
        // Normalize the authoritative snapshot immediately at every gateway
        // exit, before signal delivery, syscall service, or any other consumer.
        let jit_start = active.region.exec_base.as_ptr() as u64;
        let x87_normalization = u64::try_from(active.region.capacity)
            .ok()
            .and_then(|capacity| jit_start.checked_add(capacity))
            .ok_or(X86X87FipNormalizationError::JitRangeOverflow)
            .and_then(|jit_end| {
                normalize_x86_gateway_x87_fip(
                    &fault_entries,
                    jit_start..jit_end,
                    X86GatewayX87Witness {
                        entry_fip: entry_x87_fip,
                        entry_fdp: entry_x87_fdp,
                        completed_guest_va: context.last_copied_x87_guest_va,
                        completed_guest_data_va: context.last_copied_x87_guest_data_va,
                        completed_data_valid: context.last_copied_x87_data_valid != 0,
                    },
                    &mut context.snapshot,
                )
            });
        // Mark host-unsafe (or exact fork-parked when a stop raced the return)
        // immediately after gateway return. Then complete the safe boundary
        // before interpreting status or touching dispatcher/mapping state.
        drop(in_jit);
        if let Err(error) = active
            .executable_epoch
            .fork_safe_boundary(executable_registration)
        {
            fault_detail = Some(format!(
                "native x86 host-fork boundary failed after gateway return: {error:?}"
            ));
            break 'run;
        }
        retired_ephemeral_fault_range = current_ephemeral_fault_range;
        if let Err(error) = x87_normalization {
            fault_detail = Some(error.to_string());
            break 'run;
        }
        match active
            .executable_epoch
            .terminal_stop_for_nonowner(executable_registration)
        {
            Ok(Some(_)) => return ThreadRunOutcome::RetiredForExec { traps },
            Ok(None) => {}
            Err(error) => {
                fault_detail = Some(format!(
                    "native x86 executable terminal boundary failed: {error:?}"
                ));
                break 'run;
            }
        }

        // With chaining the EXITING block may differ from the entered one, so
        // dispatch on the exit STATUS + snapshot.rip, not the entered block.
        match X86ExitStatus::from_raw(raw) {
            Some(X86ExitStatus::Kicked) => {
                if active.exit.requested() {
                    // Process exit is terminal, so the arbitrary interrupted PC
                    // recorded by its asynchronous signal is never resumed.
                    continue;
                }
                if active.executable_epoch.explains_kick(admitted) {
                    // Executable-stop guards publish an exact semantic retry
                    // boundary: a direct successor or the still-unexecuted ret.
                    // Reusing the entry-loop's old `next` would replay the
                    // entered block and duplicate its side effects.
                    next = context.snapshot.rip;
                    continue;
                }
                fault_detail = Some("native x86 received a kick without an exit request".into());
                break 'run;
            }
            Some(X86ExitStatus::Signal) => {
                // A synchronous guest fault (SIGSEGV/SIGBUS/SIGFPE/SIGILL). The
                // shim recorded the host JIT RIP and data address. Reverse-map
                // that RIP to the exact guest instruction and restore emitter
                // scratch registers before building the signal frame, so a
                // handler can mprotect the page and retry precisely.
                let fault = context.fault;
                let scratch = [context.scratch, context.scratch2];
                let mut linux_sig = crate::host_signal::host_to_linux_signum(fault.signal);
                let Some(fault_pc) = recover_x86_fault_snapshot(
                    &fault_entries,
                    fault.host_rip,
                    scratch,
                    &mut context.snapshot,
                ) else {
                    fault_detail = Some(format!(
                        "native x86 fault at unregistered JIT RIP 0x{:x} addr=0x{:x}",
                        fault.host_rip, fault.addr
                    ));
                    break 'run;
                };
                // Shared-anonymous mappings begin inaccessible so first touch
                // can update portable residency metadata. This is an internal
                // demand fault, not a guest SIGSEGV: restore the requested
                // protection and retry the exact instruction.
                if let Some(plan) = active.dispatcher.resident_fault_plan(fault.addr)
                    && memory
                        .protect_range(plan.page(), PAGE as usize, plan.prot())
                        .is_ok()
                {
                    active.dispatcher.commit_resident_fault(plan);
                    next = fault_pc;
                    continue;
                }
                let fault_code = if linux_sig == crate::linux_abi::LINUX_SIGSEGV
                    && active.dispatcher.mmap_fault_is_sigbus(fault.addr)
                {
                    // A materialized MAP_PRIVATE file tail is physically
                    // PROT_NONE, so FreeBSD reports host SIGSEGV. The exact
                    // dispatcher EOF registry distinguishes it from an ordinary
                    // guest PROT_NONE access without weakening ACCERR handling.
                    linux_sig = crate::linux_abi::LINUX_SIGBUS;
                    crate::linux_abi::LINUX_BUS_ADRERR
                } else if linux_sig == crate::linux_abi::LINUX_SIGSEGV
                    && IDENTITY_PROTECTIONS.range_fault_is_access_error(fault.addr, 1)
                {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                } else {
                    fault.code
                };
                // Record every guest-visible synchronous fault, including one
                // consumed by a guest signal handler. Toolchains such as GCC
                // install a SIGSEGV handler and convert memory corruption into
                // an internal compiler error, so fatal-only probes lose the
                // registers at the actual fault boundary.
                crate::probes::native_x86_fault(
                    fault_pc,
                    fault.addr,
                    context.snapshot.gpr[reg::RSP],
                    context.snapshot.gpr[reg::RAX],
                    context.snapshot.gpr[reg::RCX],
                    context.snapshot.gpr[reg::RDX],
                    context.snapshot.gpr[reg::RDI],
                    context.snapshot.gpr[reg::RSI],
                    context.snapshot.gpr[reg::R8],
                    context.snapshot.rflags,
                );
                let fault_rsp = context.snapshot.gpr[reg::RSP];
                let mut fault_stack_words = [0; 4];
                for (word, offset) in fault_stack_words
                    .iter_mut()
                    .zip([0x18_u64, 0x20, 0x30, 0x38])
                {
                    if let Ok(bytes) = memory.read_bytes_raw(fault_rsp.saturating_add(offset), 8)
                        && let Ok(array) = <[u8; 8]>::try_from(bytes.as_slice())
                    {
                        *word = u64::from_le_bytes(array);
                    }
                }
                crate::probes::native_x86_fault_stack(
                    context.snapshot.gpr[reg::RBP],
                    fault_stack_words,
                );
                let mut fault_history = [0; 5];
                for (slot, pc) in fault_history.iter_mut().rev().zip(history.iter().rev()) {
                    *slot = *pc;
                }
                crate::probes::native_x86_fault_history(fault_history);
                match deliver_synchronous_x86_fault(
                    &active,
                    tid,
                    &mut context.snapshot,
                    fault_pc,
                    linux_sig,
                    fault_code,
                    fault.addr,
                ) {
                    SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                    SynchronousFaultDelivery::Fatal(final_signum) => {
                        // A fork descendant dies BY the final signal
                        // (WIFSIGNALED) so its parent's wait4 sees it; the
                        // top-level guest reports exit=128+signum instead of
                        // the runner dying by the signal. A failed frame build
                        // force-SIGSEGVs even when the original fault was SIGBUS.
                        if forked {
                            let fetch = identity_checked_fetch_x86_instruction(GuestVa(fault_pc))
                                .map(|bytes| format!("{bytes:02x?}"))
                                .unwrap_or_else(|error| format!("fetch-error={error:?}"));
                            let message = format!(
                                "native x86 fork child {} fatal signal {final_signum} at \
                                 pc=0x{fault_pc:x} addr=0x{:x} code={fault_code}; \
                                 rsp=0x{:x} rdi=0x{:x} rsi=0x{:x}; bytes={fetch}; \
                                 segments={:x?}\n",
                                tid.raw(),
                                fault.addr,
                                context.snapshot.gpr[reg::RSP],
                                context.snapshot.gpr[reg::RDI],
                                context.snapshot.gpr[reg::RSI],
                                image.segments,
                            );
                            // SAFETY: best-effort breadcrumb on a fatal child path.
                            unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
                            crate::exec_helpers::forked_child_die_by_signal(
                                final_signum,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(128 + final_signum);
                        break 'run;
                    }
                }
            }
            Some(X86ExitStatus::Syscall) => {
                traps += 1;
                match service_syscall(
                    &active,
                    memory,
                    waiter,
                    tid,
                    &mut context.snapshot,
                    &mut context.guest_fsbase,
                    executable_registration,
                ) {
                    Step::Continue(rip) => next = rip,
                    Step::ThreadEnd => {
                        // This thread exited via `exit(2)` and was NOT the last
                        // live thread: end just this host thread.
                        return ThreadRunOutcome::ThreadDone { traps };
                    }
                    Step::RetiredForExec => {
                        return ThreadRunOutcome::RetiredForExec { traps };
                    }
                    Step::BecameForkChild {
                        resume: rip,
                        vfork_completion_fd: completion_fd,
                    } => {
                        // This process is now a fork descendant; its exit must
                        // be reaped by the parent, not returned up.
                        forked = true;
                        vfork_completion_fd = completion_fd;
                        next = rip;
                        // Swap onto a FRESH private code cache: the parent's
                        // SHM_ANON cache is MAP_SHARED and survives fork, so
                        // re-JITing into it at our own cursor would clobber the
                        // parent's live code (deterministic SIGBUS). Fork copied
                        // only this thread, so rebuilding execution state is
                        // safe. Every prior translation pointed into the old
                        // shared region — clear the caches and re-JIT from
                        // scratch into the new one.
                        // The tid the parent thread was running as: fork(2)
                        // clones only this thread, but the rebuilt child registry
                        // re-anchors the main tid to the child's own host pid, so
                        // the per-tid signal state (mask + SA_ONSTACK alt stack)
                        // is orphaned under the parent's tid unless re-keyed.
                        let parent_tid = tid;
                        host_registration.abandon_inherited_after_fork();
                        executable_registration.abandon_inherited_after_fork();
                        match fork_child_rebuild(&active) {
                            Ok(child) => {
                                active = child;
                                tid = active.registry.main_tid();
                                identity_stamp = native_x86_identity_stamp(&active, tid);
                                host_registration.rebind_after_fork(&active, tid);
                                if let Err(error) = executable_registration
                                    .rebind_after_fork(&active.executable_epoch)
                                {
                                    fault_detail = Some(format!(
                                        "fork child: bind fresh executable epoch: {error:?}"
                                    ));
                                    break;
                                }
                                memory.rebind_after_fork(&active);
                                cursor = 0;
                                cursor_limit = JIT_SLICE_LEN;
                                cache.clear();
                                cflow_plans.clear();
                                indirect_cache_entries.clear();
                                pending.clear();
                                fault_entries.clear();
                                // XSAVEOPT's destination-init guarantee is
                                // process-local. Seed the fork child's COW copy
                                // with one full host XSAVE before optimized
                                // saves resume.
                                context.host_xsave_initialized = 0;
                                // POSIX fork-child resets on the (shared)
                                // dispatcher + runtime globals: timerslack /
                                // subreaper-ancestor / itimers / membarrier and
                                // the empty pending-signal set, so the child does
                                // not observe the parent's inherited proc state.
                                native_after_fork_child(&active.dispatcher);
                                // Re-key the forking thread's own signal state to
                                // the child's new main tid (fork inherits the
                                // sigaltstack + blocked mask per POSIX), after
                                // retiring the parent's SIBLING per-tid entries
                                // (those threads don't exist in the child and
                                // could collide with the child's tid base).
                                // `forkaltstack`: without this the inherited alt
                                // stack is lost.
                                active
                                    .dispatcher
                                    .retire_sibling_thread_signal_state(parent_tid);
                                active
                                    .dispatcher
                                    .migrate_thread_signal_state(parent_tid, tid);
                                if let Err(error) = active.dispatcher.rlimit_cpu_after_fork_child()
                                {
                                    fault_detail = Some(format!(
                                        "fork child: rearm finite RLIMIT_CPU helper: {error}"
                                    ));
                                    break;
                                }
                                // LAST: host-signal reinit, dispatcher pending
                                // reset/rekey, and CPU-limit rearm are complete.
                                // A post-fork arrival can no longer be published
                                // and subsequently erased.
                                unblock_native_transport_signals_after_fork();
                            }
                            Err(detail) => {
                                fault_detail = Some(detail);
                                break;
                            }
                        }
                    }
                    Step::Exit(code) => {
                        // A fork child exits through the shared lifecycle helper:
                        // besides `_exit`, it reparents the child's descendants in
                        // Carrick's fork-coherent child table and publishes terminal
                        // state for an adopted orphan. A raw `_exit` left `wait4(-1)`
                        // believing there were no children after the direct child
                        // died (`pidnsorphanreap`).
                        if forked {
                            crate::exec_helpers::forked_child_exit(
                                code,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(code);
                        break 'run;
                    }
                    Step::SignalDeath(signum) => {
                        // Fork descendant: die BY the signal so the parent's
                        // wait4 sees WIFSIGNALED. Top-level guest: report
                        // exit=128+signum so the driver returns a RunResult
                        // instead of the runner dying by the signal itself.
                        if forked {
                            crate::exec_helpers::forked_child_die_by_signal(
                                signum,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(128 + signum);
                        break 'run;
                    }
                    Step::Execve { path, argv, env } => {
                        // In-process image replacement. `snapshot.rip` is the
                        // post-syscall resume the guest returns to if the exec
                        // FAILS (an error return from execve). Resolve + read +
                        // validate the target while the OLD image is still live;
                        // only on success do we retire it (Linux's exec point of
                        // no return). Sibling guest threads: Linux execve kills
                        // the whole thread group, keeping only the execing task.
                        match load_execve_image(&active.dispatcher, &path, argv) {
                            Err(errno) => {
                                // Exec failed with the old image intact: return
                                // the errno to the guest and resume.
                                context.snapshot.gpr[reg::RAX] = (-(errno.get() as i64)) as u64;
                                next = context.snapshot.rip;
                            }
                            Ok((bytes, interpreter, resolved, argv)) => {
                                // Acquire terminal ownership before publishing
                                // the host-wait wake. A competing exec loses
                                // without touching the old image and retires by
                                // dropping its exact coordinator registration.
                                // Wake a sibling vfork/futex/poll host wait
                                // before terminal acquisition waits behind an
                                // already-owned ordinary quiescence lease. This
                                // predicate is monotonic until the eventual
                                // terminal commit, so an acquisition failure is
                                // fail-stopped rather than a resume authority.
                                let terminal = match active
                                    .executable_epoch
                                    .begin_terminal(executable_registration, || {
                                        active.request_exec_stop()
                                    }) {
                                    Ok(terminal) => terminal,
                                    Err(ExecutableTerminalError::Lost { .. }) => {
                                        return ThreadRunOutcome::RetiredForExec { traps };
                                    }
                                    Err(
                                        error @ (ExecutableTerminalError::TimedOut { owner }
                                        | ExecutableTerminalError::Aborted { owner }),
                                    ) if owner.thread != executable_registration.id => {
                                        // Another exact owner failed stopped;
                                        // this contender must retire without
                                        // disturbing its terminal state.
                                        let _ = error;
                                        return ThreadRunOutcome::RetiredForExec { traps };
                                    }
                                    Err(error) => {
                                        fault_detail = Some(format!(
                                            "execve terminal acquisition failed: {error:?}"
                                        ));
                                        break;
                                    }
                                };
                                let retirement_deadline = std::time::Instant::now()
                                    + EXECUTABLE_TERMINAL_RETIREMENT_TIMEOUT;
                                let retirement = match active
                                    .wait_for_exec_retirement(terminal.owner(), retirement_deadline)
                                {
                                    Ok(retirement) => retirement,
                                    Err(error) => {
                                        // Diagnostic timeout is fail-stopped:
                                        // `terminal` Drop publishes Aborted and
                                        // neither this path nor ExitState clears
                                        // the stop. The old image is untouched.
                                        fault_detail = Some(format!(
                                            "execve terminal retirement failed: {error:?}"
                                        ));
                                        break;
                                    }
                                };

                                // Exact registration retirement, not a count,
                                // has now proved this is the sole executable
                                // thread. Only now may the guest thread registry
                                // and old image be retired.
                                active.registry.remove_all_except(tid);
                                // A nonleader exec is re-threaded permanently,
                                // not merely presented as the tgid while the
                                // live count happens to be one. Move every
                                // process-local identity seam before any new
                                // image code or future clone can observe it.
                                let prior_tid = tid;
                                let rekey = match active.registry.rekey_exec_survivor(prior_tid) {
                                    Ok(rekey) => rekey,
                                    Err(error) => {
                                        fault_detail = Some(format!(
                                            "execve survivor registry rekey failed: {error:?}"
                                        ));
                                        break;
                                    }
                                };
                                let exec_tid = rekey.current();
                                if let Err(error) = host_registration.rekey_after_exec(exec_tid) {
                                    fault_detail =
                                        Some(format!("execve host-thread rekey failed: {error}"));
                                    break;
                                }
                                active
                                    .dispatcher
                                    .rekey_thread_signal_state_after_exec(prior_tid, exec_tid);
                                tid = exec_tid;
                                waiter.rekey_after_exec(tid);
                                identity_stamp = native_x86_identity_stamp(&active, tid);
                                // Reset the dispatcher's per-process exec state:
                                // fresh brk/mmap bookkeeping, signal handlers to
                                // default, close O_CLOEXEC fds, new /proc identity.
                                active.dispatcher.reset_memory_state_on_execve();
                                active.dispatcher.reset_signal_handlers_on_execve();
                                active.dispatcher.close_cloexec_fds();
                                let argv_strings: Vec<String> = argv
                                    .iter()
                                    .map(|a| String::from_utf8_lossy(a).into_owned())
                                    .collect();
                                let process_title = argv_strings.join(" ");
                                active.dispatcher.set_executable_identity(
                                    resolved,
                                    argv_strings,
                                    env.clone(),
                                );
                                // `reset_signal_handlers_on_execve` deliberately
                                // preserves this surviving thread's blocked mask
                                // and pending signals while clearing its altstack
                                // and old-image handler frames. Do not retire the
                                // whole per-thread record here: that is an exit
                                // operation and would violate execve semantics.
                                // The terminal lease remains the outer executable
                                // mutation across raw teardown, all loader writes
                                // and protections, VMA/image publication, and the
                                // surviving thread's cache/context reset.
                                if let Err(error) = image.teardown() {
                                    // The old image is already beyond the exec
                                    // point of no return. Keep terminal state
                                    // aborted and never notify a vfork parent.
                                    fault_detail =
                                        Some(format!("execve old-image teardown failed: {error}"));
                                    break;
                                }
                                // Linux exec installs a fresh address space.
                                // Replace the persistent identity heap/mmap
                                // arenas for every exec, not just vfork: stale
                                // allocator bytes and host protections from the
                                // old image otherwise corrupt the replacement
                                // dynamic linker's early state.
                                if let Err(error) = remap_exec_arenas() {
                                    fault_detail = Some(format!("replace exec arenas: {error:?}"));
                                    break;
                                }
                                match load_static_pie(&bytes, interpreter.as_deref(), &argv, &env) {
                                    Ok(new_image) => {
                                        crate::probes::execve_loaded(
                                            &path,
                                            new_image.entry,
                                            new_image.rsp,
                                            new_image.segments.len() as u64,
                                        );
                                        if let Err(error) = reset_identity_vmas(&new_image) {
                                            let rollback = new_image
                                                .teardown()
                                                .err()
                                                .map(|cleanup| {
                                                    format!(
                                                        "; candidate rollback failed: {cleanup}"
                                                    )
                                                })
                                                .unwrap_or_default();
                                            fault_detail = Some(format!(
                                                "execve identity VMA publication failed: {error}{rollback}"
                                            ));
                                            break;
                                        }
                                        image = Arc::new(new_image);
                                        // Future clone threads must start from
                                        // this replacement image, not the
                                        // pre-exec image retained in SharedRun.
                                        active.publish_image(Arc::clone(&image));
                                        // FreeBSD setproctitle state survives
                                        // host fork. Refresh it only after the
                                        // replacement image is installed, so a
                                        // failed exec preserves the old title
                                        // while successful descendants retain
                                        // the scoped run-id prefix with their
                                        // own argv as the descriptive suffix.
                                        crate::dispatch::set_host_process_name(
                                            process_title.as_bytes(),
                                        );
                                    }
                                    Err(e) => {
                                        // Past the point of no return: the old
                                        // image is gone. Terminal Drop remains
                                        // fail-stopped; never resume old or
                                        // partially-installed mappings.
                                        fault_detail = Some(format!(
                                            "execve load after image retirement: {e:?}"
                                        ));
                                        break;
                                    }
                                }
                                // PTRACE_TRACEME survives exec and reports the
                                // mandatory SIGTRAP stop before the replacement
                                // image runs its first instruction.
                                crate::exec_helpers::stop_after_traced_exec(&active.dispatcher);
                                // Reset this thread's JIT caches + register state
                                // and resume at the new entry. Every translated
                                // block pointed into the old image's code; clear
                                // the block/pending maps so the new image re-JITs
                                // from scratch. The cursor stays MONOTONIC within
                                // this thread's current JIT window (a fork child
                                // runs from a different window base than
                                // `slice_off`, so re-seeding from `slice_off`
                                // would be wrong) — the old blocks become dead
                                // space, harmless for the probe's single exec.
                                cache.clear();
                                cflow_plans.clear();
                                indirect_cache_entries.clear();
                                pending.clear();
                                fault_entries.clear();
                                retired_ephemeral_fault_range = None;
                                context.guest_fsbase = 0;
                                context.snapshot = X86UcontextSnapshot::new();
                                context.snapshot.gpr[reg::RSP] = image.rsp;
                                next = image.entry;
                                if let Err(error) = terminal.commit(retirement) {
                                    fault_detail =
                                        Some(format!("execve terminal commit failed: {error:?}"));
                                    break;
                                }
                                // Admission reopens only after the complete new
                                // image and thread context are published. Clear
                                // the auxiliary blocking predicate after the
                                // coordinator commit; the next admission sees
                                // the advanced generation and refreshes.
                                active.exit.clear_exec_stop();
                                notify_vfork_completion(&mut vfork_completion_fd);
                            }
                        }
                    }
                    Step::Fault(detail) => {
                        fault_detail = Some(detail);
                        break;
                    }
                }
            }
            Some(X86ExitStatus::Indirect) => {
                if context.chain_patch_site != 0 {
                    // Chain miss: a cold stub already resolved the successor VA
                    // into snapshot.rip; the pending machinery patches the slot
                    // when the target is translated (this iteration or later).
                    next = context.snapshot.rip;
                } else {
                    // Genuine indirect branch (call/ret/jmp r/m): reuse the
                    // plan decoded when its translated block was published.
                    let va = context.snapshot.rip;
                    let plan = ephemeral_cflow_plan
                        .as_ref()
                        .filter(|(plan_va, _)| *plan_va == va)
                        .map(|(_, plan)| plan)
                        .or_else(|| cflow_plans.get(&va));
                    let Some(plan) = plan else {
                        fault_detail = Some(format!("missing cflow plan at 0x{va:x}"));
                        break;
                    };
                    let indirect_cache_index = context
                        .indirect_cache_site
                        .checked_sub(1)
                        .and_then(|index| usize::try_from(index).ok());
                    // A cold CALL/RET/indirect-memory attempt must remain at
                    // its architectural boundary when the resolver's one guest
                    // memory access faults. The signal frame below owns these
                    // original values; rt_sigreturn retries this exact cflow
                    // instruction rather than replaying its preceding block.
                    let attempt_rsp = context.snapshot.gpr[reg::RSP];
                    let resolved = if let Some(stack_adjust) = ephemeral_return_adjust {
                        // Ephemeral return sites publish no cache entry. Their
                        // emitted cold probe captured `[rsp]` once; consume that
                        // value directly rather than rereading mutable guest memory.
                        Ok(apply_captured_return(
                            &mut context.snapshot,
                            context.indirect_actual_target,
                            stack_adjust,
                        ))
                    } else if let Some(index) = indirect_cache_index {
                        let Some(entry) = indirect_cache_entries.get(index) else {
                            fault_detail = Some(format!(
                                "invalid indirect-cache site {} at 0x{va:x}",
                                context.indirect_cache_site
                            ));
                            break;
                        };
                        // The emitted return probe already consumed `[rsp]`
                        // inside the registered JIT fault region. Retire that
                        // single captured value; rereading in Rust would make
                        // one architectural `ret` observe memory twice and can
                        // fault outside the JIT redirect after a concurrent
                        // stack rewrite/unmap.
                        Ok(apply_captured_return(
                            &mut context.snapshot,
                            context.indirect_actual_target,
                            entry.rsp_adjust,
                        ))
                    } else {
                        plan.resolve_with_memory(&mut context.snapshot, memory)
                    };
                    match resolved {
                        Ok(target) => {
                            if let Some(entry) = indirect_cache_index
                                .and_then(|index| indirect_cache_entries.get_mut(index))
                                && let Some(target_block) = cache.get(&target).copied()
                                && native_x86_return_cache_is_armable(
                                    &IDENTITY_PROTECTIONS,
                                    source_translation_ephemeral,
                                    GuestVa(target),
                                    target_block.guest_len,
                                )
                            {
                                entry.arm(target, target_block.exec);
                            }
                            if trace_pcs.contains(&GuestVa(va)) {
                                crate::probes::native_x86_resolve(
                                    va,
                                    target,
                                    context.snapshot.gpr[reg::RSP],
                                    context.snapshot.gpr[reg::RDI],
                                    context.snapshot.gpr[reg::RBP],
                                );
                            }
                            next = target;
                        }
                        Err(
                            cflow::CflowError::MemoryRead { address, kind }
                            | cflow::CflowError::MemoryWrite { address, kind },
                        ) => {
                            context.snapshot.rip = va;
                            context.snapshot.gpr[reg::RSP] = attempt_rsp;
                            let (signum, code) = match kind {
                                cflow::CflowMemoryFaultKind::Unmapped => (
                                    crate::linux_abi::LINUX_SIGSEGV,
                                    crate::linux_abi::LINUX_SEGV_MAPERR,
                                ),
                                cflow::CflowMemoryFaultKind::AccessDenied => (
                                    crate::linux_abi::LINUX_SIGSEGV,
                                    crate::linux_abi::LINUX_SEGV_ACCERR,
                                ),
                                cflow::CflowMemoryFaultKind::BusAddress => (
                                    crate::linux_abi::LINUX_SIGBUS,
                                    crate::linux_abi::LINUX_BUS_ADRERR,
                                ),
                            };
                            match deliver_synchronous_x86_fault(
                                &active,
                                tid,
                                &mut context.snapshot,
                                va,
                                signum,
                                code,
                                address,
                            ) {
                                SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                                SynchronousFaultDelivery::Fatal(final_signum) => {
                                    if forked {
                                        crate::exec_helpers::forked_child_die_by_signal(
                                            final_signum,
                                            active.dispatcher.stdout(),
                                            active.dispatcher.stderr(),
                                        );
                                    }
                                    exit_code = Some(128 + final_signum);
                                    break 'run;
                                }
                            }
                        }
                        Err(e) => {
                            fault_detail = Some(format!("cflow resolve at 0x{va:x}: {e}"));
                            break;
                        }
                    }
                }
            }
            Some(X86ExitStatus::Sensitive) => {
                // Re-decode the sensitive instruction at the self-set resume VA
                // to recover its kind and length.
                let va = context.snapshot.rip;
                let bytes = match identity_checked_fetch_x86_instruction(GuestVa(va)) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        match deliver_x86_instruction_fetch_error(
                            &active,
                            tid,
                            &mut context.snapshot,
                            va,
                            error,
                        ) {
                            Ok(SynchronousFaultDelivery::RetryAt(rip)) => {
                                next = rip;
                                continue 'run;
                            }
                            Ok(SynchronousFaultDelivery::Fatal(final_signum)) => {
                                if forked {
                                    crate::exec_helpers::forked_child_die_by_signal(
                                        final_signum,
                                        active.dispatcher.stdout(),
                                        active.dispatcher.stderr(),
                                    );
                                }
                                exit_code = Some(128 + final_signum);
                                break 'run;
                            }
                            Err(detail) => {
                                fault_detail = Some(detail);
                                break 'run;
                            }
                        }
                    }
                };
                match classify(&bytes, va) {
                    Ok(c) => match c.class {
                        X86InstClass::Sensitive(
                            carrick_dsr_x86::decode::X86SensitiveKind::XstateSave(kind),
                        ) => match service_xstate_save(
                            va,
                            kind,
                            &bytes,
                            context.guest_fsbase,
                            &context.snapshot,
                            memory,
                        ) {
                            Ok(resume) => next = resume,
                            Err(X86XstateServiceError::Signal {
                                signum,
                                code,
                                address,
                            }) => {
                                match deliver_synchronous_x86_fault(
                                    &active,
                                    tid,
                                    &mut context.snapshot,
                                    va,
                                    signum,
                                    code,
                                    address,
                                ) {
                                    SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                                    SynchronousFaultDelivery::Fatal(final_signum) => {
                                        if forked {
                                            crate::exec_helpers::forked_child_die_by_signal(
                                                final_signum,
                                                active.dispatcher.stdout(),
                                                active.dispatcher.stderr(),
                                            );
                                        }
                                        exit_code = Some(128 + final_signum);
                                        break 'run;
                                    }
                                }
                            }
                            Err(X86XstateServiceError::Fatal(detail)) => {
                                fault_detail = Some(detail);
                                break;
                            }
                        },
                        X86InstClass::Sensitive(
                            carrick_dsr_x86::decode::X86SensitiveKind::XstateRestore(_),
                        ) => match service_xstate_restore(
                            va,
                            &bytes,
                            context.guest_fsbase,
                            &mut context.snapshot,
                        ) {
                            Ok(resume) => next = resume,
                            Err(X86XstateServiceError::Signal {
                                signum,
                                code,
                                address,
                            }) => {
                                match deliver_synchronous_x86_fault(
                                    &active,
                                    tid,
                                    &mut context.snapshot,
                                    va,
                                    signum,
                                    code,
                                    address,
                                ) {
                                    SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                                    SynchronousFaultDelivery::Fatal(final_signum) => {
                                        if forked {
                                            crate::exec_helpers::forked_child_die_by_signal(
                                                final_signum,
                                                active.dispatcher.stdout(),
                                                active.dispatcher.stderr(),
                                            );
                                        }
                                        exit_code = Some(128 + final_signum);
                                        break 'run;
                                    }
                                }
                            }
                            Err(X86XstateServiceError::Fatal(detail)) => {
                                fault_detail = Some(detail);
                                break;
                            }
                        },
                        X86InstClass::Sensitive(
                            kind @ (carrick_dsr_x86::decode::X86SensitiveKind::FxState(_)
                            | carrick_dsr_x86::decode::X86SensitiveKind::LegacyX87(_)),
                        ) => match service_legacy_state_transfer(
                            va,
                            kind,
                            &bytes,
                            context.guest_fsbase,
                            &mut context.snapshot,
                            memory,
                        ) {
                            Ok(resume) => next = resume,
                            Err(X86XstateServiceError::Signal {
                                signum,
                                code,
                                address,
                            }) => {
                                match deliver_synchronous_x86_fault(
                                    &active,
                                    tid,
                                    &mut context.snapshot,
                                    va,
                                    signum,
                                    code,
                                    address,
                                ) {
                                    SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                                    SynchronousFaultDelivery::Fatal(final_signum) => {
                                        if forked {
                                            crate::exec_helpers::forked_child_die_by_signal(
                                                final_signum,
                                                active.dispatcher.stdout(),
                                                active.dispatcher.stderr(),
                                            );
                                        }
                                        exit_code = Some(128 + final_signum);
                                        break 'run;
                                    }
                                }
                            }
                            Err(X86XstateServiceError::Fatal(detail)) => {
                                fault_detail = Some(detail);
                                break;
                            }
                        },
                        X86InstClass::Sensitive(kind) => {
                            match service_sensitive(kind, &mut context.snapshot) {
                                Ok(()) => next = va + c.len as u64,
                                Err(X86SensitiveServiceError::Signal {
                                    signum,
                                    code,
                                    address,
                                }) => {
                                    match deliver_synchronous_x86_fault(
                                        &active,
                                        tid,
                                        &mut context.snapshot,
                                        va,
                                        signum,
                                        code,
                                        address,
                                    ) {
                                        SynchronousFaultDelivery::RetryAt(rip) => next = rip,
                                        SynchronousFaultDelivery::Fatal(final_signum) => {
                                            if forked {
                                                crate::exec_helpers::forked_child_die_by_signal(
                                                    final_signum,
                                                    active.dispatcher.stdout(),
                                                    active.dispatcher.stderr(),
                                                );
                                            }
                                            exit_code = Some(128 + final_signum);
                                            break 'run;
                                        }
                                    }
                                }
                                Err(X86SensitiveServiceError::Fatal(detail)) => {
                                    fault_detail = Some(detail);
                                    break;
                                }
                            }
                        }
                        other => {
                            fault_detail =
                                Some(format!("sensitive exit at 0x{va:x} decoded as {other:?}"));
                            break;
                        }
                    },
                    Err(e) => {
                        fault_detail = Some(format!("sensitive re-decode at 0x{va:x}: {e}"));
                        break;
                    }
                }
            }
            None => {
                fault_detail = Some(format!("gateway returned unknown status {raw}"));
                break;
            }
        }
    }

    if let Some(detail) = fault_detail {
        if forked {
            let recent: Vec<String> = history
                .iter()
                .rev()
                .take(12)
                .rev()
                .map(|va| format!("0x{va:x}"))
                .collect();
            let message = format!(
                "native x86 fork child {} stopped after {traps} traps: {detail}; \
                 rip=0x{:x} rsp=0x{:x} rdi=0x{:x}; segments={:?}; recent=[{}]\n",
                tid.raw(),
                context.snapshot.rip,
                context.snapshot.gpr[reg::RSP],
                context.snapshot.gpr[reg::RDI],
                image.segments,
                recent.join(", ")
            );
            // SAFETY: a single best-effort diagnostic write on an already
            // failing fork-child path; avoids losing the root cause when the
            // descendant cannot return a RunResult to the original runner.
            unsafe {
                libc::write(2, message.as_ptr().cast(), message.len());
            }
            crate::exec_helpers::forked_child_exit(
                125,
                active.dispatcher.stdout(),
                active.dispatcher.stderr(),
            );
        }
        return ThreadRunOutcome::Fault { detail, traps };
    }
    if let Some(code) = exit_code {
        return ThreadRunOutcome::Exit { code, traps };
    }
    // The while-condition failed with no exit and no fault: the trap limit.
    ThreadRunOutcome::TrapLimit { traps }
}

/// Adapt a `syscall` gateway exit into the shared dispatcher. Builds the same
/// [`carrick_hal::RawSyscall`] the x86 VMM engine produces, drives it through
/// the shared single-threaded [`crate::runtime::service_syscall`] (which
/// services the blocking-I/O outcomes — fd wait / poll / select / sleep /
/// blocking write — by parking on the `waiter` and re-dispatching), writes the
/// terminal return value into `snapshot.rax`, and returns the resume RIP.
/// `arch_prctl(SET_FS)` sets `guest_fsbase` (VMM state has no analog here).
#[allow(clippy::too_many_arguments)]
fn service_syscall(
    shared: &Arc<SharedRun>,
    memory: &mut IdentityGuestMemory,
    waiter: &mut crate::io_wait::ThreadWaiter,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
    guest_fsbase: &mut u64,
    executable_registration: &mut ExecutableThreadRegistration,
) -> Step {
    let dispatcher = &shared.dispatcher;
    let reporter = &shared.reporter;
    let registry = &shared.registry;
    let futex = &shared.futex;
    let frame = X8664SyscallFrame {
        rax: snapshot.gpr[reg::RAX],
        rdi: snapshot.gpr[reg::RDI],
        rsi: snapshot.gpr[reg::RSI],
        rdx: snapshot.gpr[reg::RDX],
        r10: snapshot.gpr[reg::R10],
        r8: snapshot.gpr[reg::R8],
        r9: snapshot.gpr[reg::R9],
    };
    let resume = snapshot.rip;

    let raw = match X8664GuestArch::normalize_syscall(&frame) {
        SyscallNorm::ArchPrctl { code, addr } => {
            let ret = service_arch_prctl(code, addr, snapshot, guest_fsbase, memory);
            snapshot.gpr[reg::RAX] = ret as u64;
            return Step::Continue(resume);
        }
        SyscallNorm::Plain(raw) => raw,
    };

    // The guest's original RAX (= x86 syscall number) so an SA_RESTART restart
    // re-executes the `syscall` with the right number, and the canonical number
    // for the restartable-syscall check.
    let orig_rax = frame.rax;
    let request = SyscallRequest::from_raw(raw).with_current_guest_sp(Some(snapshot.gpr[reg::RSP]));
    let syscall_nr = request.number.raw();
    // Canonical mmap/mremap/shmat acquire this inside the threaded servicer,
    // immediately after each exact fork boundary. A returned MapHostAlias
    // keeps it owned through the caller's backend commit/rollback.
    let mut alias_critical = None;
    let outcome = match service_syscall_threaded(
        dispatcher,
        request,
        memory,
        reporter,
        waiter,
        tid,
        registry,
        futex,
        &shared.exit,
        &shared.executable_epoch,
        executable_registration,
        &mut alias_critical,
    ) {
        Ok(o) => o,
        Err(NativeSyscallServiceError::Dispatch(error)) => {
            return Step::Fault(format!("dispatch error: {error:?}"));
        }
        Err(NativeSyscallServiceError::Memory(error)) => {
            return Step::Fault(format!("native identity mapping error: {error}"));
        }
        Err(NativeSyscallServiceError::Epoch(error)) => {
            return Step::Fault(format!("native host-fork safe point failed: {error:?}"));
        }
        Err(NativeSyscallServiceError::AliasInvariant { number, detail }) => {
            return Step::Fault(format!(
                "native alias syscall invariant failed for {number:?}: {detail}"
            ));
        }
    };
    let outcome = match outcome {
        DispatchOutcome::MapHostAlias {
            transaction,
            va,
            len,
            payload,
            file,
            shared: alias_shared,
            prot,
            prot_none,
            ..
        } => {
            let step = service_map_host_alias(
                dispatcher,
                transaction,
                va.raw(),
                len,
                &payload,
                file,
                alias_shared,
                prot,
                prot_none,
                snapshot,
                memory,
                resume,
            );
            // Host alias commit/rollback and transaction Drop are complete
            // before this outer lease publishes the post-dispatch boundary.
            finish_alias_dispatch_critical(&mut alias_critical);
            if let Err(error) = shared
                .executable_epoch
                .fork_safe_boundary(executable_registration)
            {
                return Step::Fault(format!(
                    "native host-fork post-alias boundary failed: {error:?}"
                ));
            }
            return step;
        }
        other => other,
    };
    // Non-alias terminal outcomes return with no mutation lease. A host-fork
    // reservation may race the final wait return. Recheck before
    // signal delivery, fork setup, or any other outcome handling can lock the
    // dispatcher again.
    if let Err(error) = shared
        .executable_epoch
        .fork_safe_boundary(executable_registration)
    {
        return Step::Fault(format!(
            "native host-fork post-dispatch boundary failed: {error:?}"
        ));
    }

    match outcome {
        // A syscall that returns to the guest: write the retval, then deliver
        // any pending, deliverable signals at this syscall-return safe point
        // (self/kill-raised signals, SIGCHLD, rt_sigqueueinfo, …). If a handler
        // is entered, `snapshot.rip` now points at it.
        DispatchOutcome::Returned { value } => {
            snapshot.gpr[reg::RAX] = value as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(value),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        DispatchOutcome::Errno { errno } => {
            let retval = -(errno.get() as i64);
            snapshot.gpr[reg::RAX] = retval as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(retval),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        DispatchOutcome::Exit { code } => Step::Exit(code),
        // A default-action fatal signal with no guest handler (abort/raise/
        // kill/tgkill of SIGABRT/SIGTERM/SIGKILL…): the process must actually
        // DIE BY that signal so a parent's wait4 reports WIFSIGNALED &&
        // WTERMSIG==signum (not a plain exit of 128+signum). This drains the
        // guest's stdout/stderr, resets the host disposition to default,
        // unblocks it, and raises it — killing the whole process (all host
        // threads). A fork descendant dies here too (its parent reaps it); on a
        // BSD where the mapped host signal is not Linux-faithful a sigdeath
        // marker lets the parent's wait4 reconstruct WIFSIGNALED(signum). Never
        // returns.
        DispatchOutcome::SignalDeath { signum } => Step::SignalDeath(signum),
        // fork()/clone(SIGCHLD): in the identity model a guest fork is a REAL
        // host fork — the child inherits the whole address space (guest memory,
        // JIT cache, arenas) copy-on-write, and is a real host child so the
        // parent's wait4 reaps it via host waitpid. The dispatcher's proc model
        // already distinguishes the child by `getpid() != bootstrap_host_pid`.
        DispatchOutcome::Fork {
            clone_parent,
            parent_tid_addr,
            child_tid_addr,
            child_stack,
            pidfd_out,
            exit_signal,
            vfork,
        } => service_fork(
            shared,
            NativeForkRequest {
                clone_parent,
                parent_tid_addr,
                child_tid_addr,
                child_stack,
                pidfd_out,
                parent_tid: tid.raw(),
                exit_signal,
                vfork,
            },
            snapshot,
            memory,
            resume,
            executable_registration,
        ),
        // Consumed above while the canonical mmap/mremap/shmat outer critical
        // lease still excludes host-fork snapshot authority.
        DispatchOutcome::MapHostAlias { .. } => unreachable!("alias outcome consumed early"),
        // `FUTEX_WAIT`/`futex_waitv` whose value-check passed under the
        // dispatcher lock: park on the shared futex table until a sibling's
        // `FUTEX_WAKE` advances the generation, the timeout elapses, or a
        // signal interrupts. The dispatcher could not block under its own lock,
        // so it handed the prepared wait token out here.
        DispatchOutcome::FutexWait { wait, timeout } => {
            let value = match wait_x86_futex(shared, tid, wait, timeout, 0, executable_registration)
            {
                Ok(value) => value,
                Err(error) => {
                    return Step::Fault(format!(
                        "native futex host-fork safe point failed: {error:?}"
                    ));
                }
            };
            snapshot.gpr[reg::RAX] = value as u64;
            // A signal-interrupted futex (EINTR) delivers its handler here.
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(value),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        DispatchOutcome::FutexWaitv {
            wait,
            timeout,
            index,
        } => {
            // On a wake, `futex_waitv` returns the INDEX of the woken futex.
            let value =
                match wait_x86_futex(shared, tid, wait, timeout, index, executable_registration) {
                    Ok(value) => value,
                    Err(error) => {
                        return Step::Fault(format!(
                            "native futex-waitv host-fork safe point failed: {error:?}"
                        ));
                    }
                };
            snapshot.gpr[reg::RAX] = value as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(value),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        // A SHARED (non-`FUTEX_PRIVATE`) `FUTEX_WAIT` on a `MAP_SHARED` word: the
        // waker may live in ANOTHER forked process, so the in-process parking-lot
        // table can't reach it. Park on the host word with FreeBSD `_umtx_op`,
        // whose non-private key spans the fork (identity: the guest word IS the
        // host word). `futexshare`'s child blocks here until the parent flips the
        // word and `SharedFutexWake`s it.
        DispatchOutcome::SharedFutexWait {
            location,
            value,
            timeout,
            ..
        } => {
            // Reflect the parked thread as 'S' (interruptible sleep) in the
            // registry so `/proc/<tid>/stat` synthesis reports it as sleeping
            // while it blocks on the shared word, then back to 'R' once woken —
            // matching the private-futex path (`wait_x86_futex`). LTP futex
            // helpers (e.g. `threadstatstate`, which passes FUTEX_PRIVATE_FLAG=0
            // and so lands here) poll for state `S`.
            crate::thread::set_current_thread_state(tid, 'S');
            let retval =
                match with_host_wait_safe(&shared.executable_epoch, executable_registration, |_| {
                    shared_futex_wait_umtx(
                        location.wait_addr().raw(),
                        location.waiter_key(),
                        value,
                        timeout,
                        &|| shared.exit.requested() || shared.exit.exec_stop_requested(),
                    )
                }) {
                    Ok(value) => value,
                    Err(error) => {
                        return Step::Fault(format!(
                            "native shared-futex host-fork safe point failed: {error:?}"
                        ));
                    }
                };
            crate::thread::set_current_thread_state(tid, 'R');
            snapshot.gpr[reg::RAX] = retval as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(retval),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        // `futex_waitv` over a SHARED word: same cross-process park; a wake returns
        // the woken futex's index instead of 0.
        DispatchOutcome::SharedFutexWaitv {
            location,
            value,
            timeout,
            index,
            ..
        } => {
            crate::thread::set_current_thread_state(tid, 'S');
            let retval =
                match with_host_wait_safe(&shared.executable_epoch, executable_registration, |_| {
                    shared_futex_wait_umtx(
                        location.wait_addr().raw(),
                        location.waiter_key(),
                        value,
                        timeout,
                        &|| shared.exit.requested() || shared.exit.exec_stop_requested(),
                    )
                }) {
                    Ok(value) => value,
                    Err(error) => {
                        return Step::Fault(format!(
                            "native shared-futex-waitv host-fork safe point failed: {error:?}"
                        ));
                    }
                };
            crate::thread::set_current_thread_state(tid, 'R');
            let retval = if retval == 0 { index } else { retval };
            snapshot.gpr[reg::RAX] = retval as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(retval),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        // The cross-process wake counterpart: wake up to `count` waiters parked on
        // the shared word (possibly in a peer process) via `_umtx_op(UMTX_OP_WAKE)`.
        DispatchOutcome::SharedFutexWake {
            location, count, ..
        } => {
            let retval =
                shared_futex_wake_umtx(location.wait_addr().raw(), location.waiter_key(), count);
            snapshot.gpr[reg::RAX] = retval as u64;
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(retval),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        // `FUTEX_CMP_REQUEUE`/`FUTEX_REQUEUE` across shared words. FreeBSD umtx
        // cannot atomically relink queues, so the fork-shared waiter table
        // publishes direct-vs-destination assignments before physically
        // releasing the selected source waiters; moved waiters transparently
        // continue their original wait on `to`.
        DispatchOutcome::SharedFutexRequeue {
            from,
            to,
            wake,
            requeue,
            ..
        } => {
            let (woken, moved) = shared_futex_requeue_umtx(
                from.wait_addr().raw(),
                from.waiter_key(),
                to.waiter_key(),
                wake,
                requeue,
            );
            snapshot.gpr[reg::RAX] = u64::from(woken + moved);
            if let Some(sig) = run_pending_signals(
                shared,
                tid,
                snapshot,
                Some(i64::from(woken + moved)),
                Some(syscall_nr),
                orig_rax,
            ) {
                return Step::SignalDeath(sig);
            }
            Step::Continue(snapshot.rip)
        }
        // `tgkill`/`tkill` targeting a SIBLING guest thread: publish the signal
        // pending for the target and unpark it (a futex/blocking waiter observes
        // the pending signal and returns EINTR, delivering the handler at its
        // next syscall boundary). Completes with 0, or -ESRCH if the target
        // already exited.
        DispatchOutcome::SignalThread {
            tid: target,
            signum,
        } => {
            let retval = if registry.is_live(target) {
                crate::host_signal::publish_pending_for_with_wake(
                    target.raw(),
                    signum,
                    crate::host_signal::PublicationWake::CallerManaged,
                );
                futex.notify_signal_pending_for(target);
                0
            } else {
                crate::linux_abi::LINUX_ESRCH.guest_retval()
            };
            snapshot.gpr[reg::RAX] = retval as u64;
            Step::Continue(resume)
        }
        // Thread-creating `clone(CLONE_VM|CLONE_THREAD…)`: spawn a real host
        // thread sharing this (identity) address space. `clone` returns the
        // child tid in the parent; the child starts at the post-syscall RIP
        // with rax=0.
        DispatchOutcome::CloneThread {
            stack,
            tls,
            flags: _,
            parent_tid_addr,
            child_tid_addr,
            clear_child_tid_addr,
        } => {
            let req = CloneThreadRequest {
                // Linux clone duplicates the architectural register/xstate
                // image once for the new task. Keep this required copy explicit;
                // gateway round trips reuse the parent's persistent context.
                parent_snapshot: snapshot.clone(),
                resume,
                parent_fsbase: *guest_fsbase,
                stack,
                tls,
                parent_tid_addr,
                child_tid_addr,
                clear_child_tid_addr,
            };
            match spawn_clone_thread(shared, tid, req, executable_registration) {
                Ok(child_tid) => {
                    snapshot.gpr[reg::RAX] = i64::from(child_tid.raw()) as u64;
                    Step::Continue(resume)
                }
                Err(CloneThreadSpawnError::Errno(errno)) => {
                    snapshot.gpr[reg::RAX] = errno as u64;
                    Step::Continue(resume)
                }
                Err(CloneThreadSpawnError::Fatal(detail)) => Step::Fault(detail),
            }
        }
        // A single thread exited via `exit(2)` (NOT exit_group): wake its
        // CLONE_CHILD_CLEARTID futex (glibc/musl `pthread_join` waits on it),
        // retire it from the registry, and end just this host thread — unless
        // it was the last live thread, in which case the whole process exits.
        DispatchOutcome::ThreadExit { code } => {
            if let Some(addr) = registry.clear_child_tid(tid)
                && addr != 0
            {
                // The word may legally live on executable storage. Route the
                // clear through the identity backend so mapping/protection
                // guards and executable-generation invalidation apply. The
                // futex wake remains unconditional, matching the existing
                // thread-retirement contract even when the guest pointer fails.
                let _ = memory.write_bytes(addr, &[0; std::mem::size_of::<u32>()]);
                futex.wake(addr, 1);
            }
            let last = registry.exit(tid);
            crate::thread::set_current_thread_state(tid, 'Z');
            dispatcher.forget_thread_signal_state(tid);
            if last {
                Step::Exit(code)
            } else {
                Step::ThreadEnd
            }
        }
        // `rt_sigreturn(2)`: pop the x86-64 rt_sigframe the handler is returning
        // through, restore the pre-signal register state + signal mask, and
        // resume at the saved RIP (NOT advanced past the syscall).
        DispatchOutcome::SigReturn => match restore_x86_sigreturn(shared, tid, snapshot) {
            Ok(rip) => {
                // Restoring the pre-handler mask can make a signal that arrived
                // during the handler immediately deliverable. Linux checks that
                // pending set before executing one instruction at the restored
                // RIP; waiting for another syscall would let pure guest code run
                // indefinitely with an unblocked signal pending.
                snapshot.rip = rip;
                match run_pending_signals_at(shared, tid, snapshot, None, None, 0, Some(rip)) {
                    Some(signum) => Step::SignalDeath(signum),
                    None => Step::Continue(snapshot.rip),
                }
            }
            Err(()) => Step::SignalDeath(crate::linux_abi::LINUX_SIGSEGV),
        },
        // `execve(2)`/`execveat(2)`: the dispatcher resolved the target and
        // handed the raw argv/env byte strings out. The image swap must happen
        // in the run loop (it owns the `LoadedImage` + JIT caches), so surface a
        // dedicated Step. `snapshot.rip` is the post-syscall resume the run loop
        // uses for the error path (a failed exec returns errno to the guest).
        DispatchOutcome::Execve { path, argv, env } => {
            crate::probes::execve_argv(&path, &argv);
            Step::Execve { path, argv, env }
        }
        other => Step::Fault(format!(
            "native x86 driver does not service dispatch outcome {other:?} yet \
             (vfork is a later rung)"
        )),
    }
}

// Cross-process shared-futex WAITER COUNT table. FreeBSD's native
// `_umtx_op(UMTX_OP_WAKE)` returns 0, not the number of threads it woke; Linux
// `FUTEX_WAKE` returns that count (FreeBSD's OWN linuxulator does too, via
// `umtxq_signal_mask` returning the woken count into `td_retval[0]` — but that
// path is only reachable through the Linux-ABI sysent, and it keys futexes as
// `TYPE_FUTEX` where native `_umtx_op(UMTX_OP_WAIT_UINT)` uses `TYPE_SIMPLE_WAIT`,
// so a native binary cannot borrow it). We reconstruct the count the same way
// the kernel does — by tracking how many waiters are parked on each key — in a
// small MAP_SHARED table inherited across `fork` (identity: the guest futex word
// is a host VA identical in every process). Each shared waiter increments its
// word's slot before parking and decrements after; a WAKE returns
// `min(requested, parked)`. This unblocks `futexwakecount` (asserts the woken
// count is >= N) and `futexsharedalias` (asserts a single wake returns exactly 1).
#[repr(C)]
struct WaiterSlot {
    /// Stable shared-backing waiter key for this slot, or 0 when free. Unlike
    /// the host VA, this remains identical when the same file offset is mapped
    /// at a different address after exec.
    key: std::sync::atomic::AtomicU64,
    /// Live parked-waiter count on `key`.
    count: std::sync::atomic::AtomicU32,
    /// Requeue assignments consumed by waiters physically released from this
    /// source bucket. Direct-wake assignments are consumed before moves.
    requeue_direct: std::sync::atomic::AtomicU32,
    requeue_moved: std::sync::atomic::AtomicU32,
    requeue_to_key: std::sync::atomic::AtomicU64,
    requeue_to_generation: std::sync::atomic::AtomicU32,
    /// Requeued waiters park on this internal generation rather than re-checking
    /// the destination guest word. Credits make wake-before-park lossless.
    logical_generation: std::sync::atomic::AtomicU32,
    logical_requeued: std::sync::atomic::AtomicU32,
    logical_wake: std::sync::atomic::AtomicU32,
}
const WAITER_SLOTS: usize = 1024;
static SHARED_WAITER_TABLE: std::sync::atomic::AtomicPtr<WaiterSlot> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Allocate the fork-shared waiter-count table (idempotent). MUST run pre-fork so
/// every descendant maps the SAME physical pages (MAP_SHARED|MAP_ANON survives
/// `fork` as genuinely shared).
fn init_shared_waiter_table() {
    use std::sync::atomic::Ordering;
    if !SHARED_WAITER_TABLE.load(Ordering::Acquire).is_null() {
        return;
    }
    let bytes = WAITER_SLOTS * std::mem::size_of::<WaiterSlot>();
    // SAFETY: a fresh anonymous shared mapping; zero-filled (key 0 = free).
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return;
    }
    // First writer wins; a loser unmaps its spare (another thread already
    // published, exceedingly unlikely under RUN_LOCK but kept correct).
    if SHARED_WAITER_TABLE
        .compare_exchange(
            std::ptr::null_mut(),
            p as *mut WaiterSlot,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: `p` is our own fresh mapping; nobody else references it.
        unsafe { libc::munmap(p, bytes) };
    }
}

/// The `WaiterSlot` for a stable shared-backing `waiter_key`, claiming a free
/// slot on first use (open-addressed, linear probe). `None` if the table is
/// unmapped or full.
fn shared_waiter_slot(waiter_key: usize) -> Option<&'static WaiterSlot> {
    use std::sync::atomic::Ordering;
    let base = SHARED_WAITER_TABLE.load(Ordering::Acquire);
    if base.is_null() {
        return None;
    }
    // SAFETY: `base` is a live mapping of exactly WAITER_SLOTS entries.
    let table = unsafe { std::slice::from_raw_parts(base, WAITER_SLOTS) };
    let key = waiter_key as u64;
    let mut idx = (waiter_key >> 2) % WAITER_SLOTS;
    for _ in 0..WAITER_SLOTS {
        let slot = &table[idx];
        let cur = slot.key.load(Ordering::Acquire);
        if cur == key {
            return Some(slot);
        }
        if cur == 0 {
            match slot
                .key
                .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(slot),
                Err(existing) if existing == key => return Some(slot),
                Err(_) => {} // lost the slot to a different key; probe on
            }
        }
        idx = (idx + 1) % WAITER_SLOTS;
    }
    None
}

// FreeBSD `_umtx_op(2)` — the host primitive for a cross-PROCESS futex. The
// NON-private op keys on the shared VM object + offset, so a wait/wake on a
// guest `MAP_SHARED` word (identity: guest VA == host VA) reaches a peer parked
// in another forked process — exactly what the in-process parking-lot
// `FutexTable` cannot do across a `fork`.
const SYS_UMTX_OP: libc::c_int = 454;
const UMTX_OP_WAIT_UINT: libc::c_int = 11;
const UMTX_OP_WAKE: libc::c_int = 3;
// `_umtx_op` reads a relative timeout as a bare `struct timespec` when its
// `uaddr` (4th) arg equals `sizeof(struct timespec)`; `uaddr2` (5th) points at it.
const UMTX_TIMESPEC_SIZE: usize = std::mem::size_of::<libc::timespec>();

enum SharedWaitAssignment {
    Direct,
    Requeue { waiter_key: usize, generation: u32 },
}

fn consume_waiter_assignment(counter: &std::sync::atomic::AtomicU32) -> bool {
    use std::sync::atomic::Ordering;
    let mut current = counter.load(Ordering::Acquire);
    while current != 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
    false
}

fn take_shared_wait_assignment(slot: Option<&WaiterSlot>) -> SharedWaitAssignment {
    use std::sync::atomic::Ordering;
    let Some(slot) = slot else {
        return SharedWaitAssignment::Direct;
    };
    if consume_waiter_assignment(&slot.requeue_direct) {
        return SharedWaitAssignment::Direct;
    }
    if consume_waiter_assignment(&slot.requeue_moved) {
        return SharedWaitAssignment::Requeue {
            waiter_key: slot.requeue_to_key.load(Ordering::Acquire) as usize,
            generation: slot.requeue_to_generation.load(Ordering::Acquire),
        };
    }
    SharedWaitAssignment::Direct
}

fn decrement_logical_requeued(slot: &WaiterSlot) {
    use std::sync::atomic::Ordering;
    let _ = slot
        .logical_requeued
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_sub(1))
        });
}

fn reserve_logical_wakes(slot: &WaiterSlot, requested: u32) -> u32 {
    use std::sync::atomic::Ordering;
    let mut credits = slot.logical_wake.load(Ordering::Acquire);
    loop {
        let pending = slot.logical_requeued.load(Ordering::Acquire);
        let reserved = requested.min(pending.saturating_sub(credits));
        if reserved == 0 {
            return 0;
        }
        match slot.logical_wake.compare_exchange_weak(
            credits,
            credits.saturating_add(reserved),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return reserved,
            Err(next) => credits = next,
        }
    }
}

/// Complete a logically requeued wait. The destination slot's internal
/// generation + wake credits close the wake-before-park race without depending
/// on the destination guest VA being identical in every process.
fn wait_requeued_umtx(
    waiter_key: usize,
    mut generation: u32,
    deadline: Option<std::time::Instant>,
    interrupted: &dyn Fn() -> bool,
) -> i64 {
    use std::sync::atomic::Ordering;
    let Some(slot) = shared_waiter_slot(waiter_key) else {
        return crate::linux_abi::LINUX_EAGAIN.guest_retval();
    };
    loop {
        if interrupted() {
            decrement_logical_requeued(slot);
            return crate::linux_abi::LINUX_EINTR.guest_retval();
        }
        if consume_waiter_assignment(&slot.logical_wake) {
            decrement_logical_requeued(slot);
            return 0;
        }
        let remaining = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    decrement_logical_requeued(slot);
                    return crate::linux_abi::LINUX_ETIMEDOUT.guest_retval();
                }
                Some(remaining)
            }
            None => None,
        };
        let current = slot.logical_generation.load(Ordering::Acquire);
        if current != generation {
            generation = current;
            continue;
        }
        // Bound each host park so a wake racing before umtx enrollment is
        // observed from its already-published logical credit within 20 ms.
        let slice = remaining
            .unwrap_or(std::time::Duration::from_millis(20))
            .min(std::time::Duration::from_millis(20));
        let ts = libc::timespec {
            tv_sec: slice.as_secs() as libc::time_t,
            tv_nsec: slice.subsec_nanos() as libc::c_long,
        };
        let uaddr = UMTX_TIMESPEC_SIZE as *mut libc::c_void;
        let uaddr2 = (&ts as *const libc::timespec)
            .cast_mut()
            .cast::<libc::c_void>();
        let generation_word = (&slot.logical_generation as *const std::sync::atomic::AtomicU32)
            .cast_mut()
            .cast::<libc::c_void>();
        // SAFETY: the generation word lives in the pre-fork MAP_SHARED waiter
        // table and remains mapped for the run's lifetime.
        let rc = unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                generation_word,
                UMTX_OP_WAIT_UINT,
                generation as libc::c_ulong,
                uaddr,
                uaddr2,
            )
        } as libc::c_long;
        if rc == 0 {
            generation = slot.logical_generation.load(Ordering::Acquire);
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::EAGAIN => {
                generation = slot.logical_generation.load(Ordering::Acquire);
            }
            libc::EINTR => {
                if consume_waiter_assignment(&slot.logical_wake) {
                    decrement_logical_requeued(slot);
                    return 0;
                }
                decrement_logical_requeued(slot);
                return crate::linux_abi::LINUX_EINTR.guest_retval();
            }
            libc::ETIMEDOUT => {
                // Slice timeout, not necessarily the guest deadline. Loop to
                // re-check logical credit and the absolute deadline.
            }
            _ => {
                decrement_logical_requeued(slot);
                return crate::linux_abi::LINUX_EAGAIN.guest_retval();
            }
        }
    }
}

/// Cross-process shared-futex WAIT via `_umtx_op(UMTX_OP_WAIT_UINT)`. `word` is a
/// live host address of the 4-byte futex word; the kernel re-checks `*word ==
/// value` atomically before parking (closing the classic set-then-wake race with
/// a peer process), then blocks until a `shared_futex_wake_umtx` on the same page
/// wakes it, the relative `timeout` elapses, or a signal interrupts. A waiter
/// selected by `FUTEX_REQUEUE` transparently continues on the destination while
/// retaining the original absolute deadline. Returns the Linux `FUTEX_WAIT`
/// retval: 0 (woken), `-EAGAIN` (value mismatch), `-ETIMEDOUT`, or `-EINTR`.
fn shared_futex_wait_umtx(
    word: usize,
    waiter_key: usize,
    value: u32,
    timeout: Option<std::time::Duration>,
    interrupted: &dyn Fn() -> bool,
) -> i64 {
    use std::sync::atomic::Ordering;
    if interrupted() {
        return crate::linux_abi::LINUX_EINTR.guest_retval();
    }
    let deadline = timeout.and_then(|duration| std::time::Instant::now().checked_add(duration));
    let remaining = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return crate::linux_abi::LINUX_ETIMEDOUT.guest_retval();
            }
            Some(remaining)
        }
        None => None,
    };
    let ts = remaining.map(|duration| libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    });
    let (uaddr, uaddr2) = match &ts {
        Some(ts) => (
            UMTX_TIMESPEC_SIZE as *mut libc::c_void,
            ts as *const libc::timespec as *mut libc::c_void,
        ),
        None => (std::ptr::null_mut(), std::ptr::null_mut()),
    };
    // Announce this parked waiter under its stable backing key so a peer's
    // WAKE can report how many it woke even when it mapped the same file at
    // another VA after exec. Increment before the park and decrement after
    // every return path.
    let slot = shared_waiter_slot(waiter_key);
    if let Some(slot) = slot {
        slot.count.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: `word` is an identity host VA of a guest-mapped,
    // 4-byte-aligned shared futex word; `_umtx_op` only reads it.
    let rc = unsafe {
        libc::syscall(
            SYS_UMTX_OP,
            word as *mut u32 as *mut libc::c_void,
            UMTX_OP_WAIT_UINT,
            value as libc::c_ulong,
            uaddr,
            uaddr2,
        )
    } as libc::c_long;
    if let Some(slot) = slot {
        slot.count.fetch_sub(1, Ordering::SeqCst);
    }
    if rc == 0 {
        return match take_shared_wait_assignment(slot) {
            SharedWaitAssignment::Direct => 0,
            SharedWaitAssignment::Requeue {
                waiter_key: next_key,
                generation,
            } => wait_requeued_umtx(next_key, generation, deadline, interrupted),
        };
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::ETIMEDOUT => crate::linux_abi::LINUX_ETIMEDOUT.guest_retval(),
        libc::EINTR => crate::linux_abi::LINUX_EINTR.guest_retval(),
        // `*word != value` at entry (a peer already advanced it): Linux returns
        // EAGAIN and the guest retry loop re-reads the word.
        libc::EAGAIN => crate::linux_abi::LINUX_EAGAIN.guest_retval(),
        _ => crate::linux_abi::LINUX_EAGAIN.guest_retval(),
    }
}

/// Implement Linux `FUTEX_REQUEUE` over FreeBSD's non-requeueing umtx ABI.
/// The source waiters are physically released, but each consumes an assignment
/// from the fork-shared slot: the first `wake_count` return to the guest and the
/// next `requeue_count` transparently park on the destination. Publishing the
/// assignments before `_umtx_op(WAKE)` closes the assignment race.
fn shared_futex_requeue_umtx(
    from_word: usize,
    from_key: usize,
    to_key: usize,
    wake_count: u32,
    requeue_count: u32,
) -> (u32, u32) {
    use std::sync::atomic::Ordering;
    let Some(slot) = shared_waiter_slot(from_key) else {
        return (0, 0);
    };
    let parked = slot.count.load(Ordering::SeqCst);
    let direct = parked.min(wake_count);
    let destination = shared_waiter_slot(to_key);
    let moved = if destination.is_some() {
        parked.saturating_sub(direct).min(requeue_count)
    } else {
        0
    };
    let total = direct.saturating_add(moved);
    if total == 0 {
        return (0, 0);
    }
    let generation = destination
        .map(|slot| {
            slot.logical_requeued.fetch_add(moved, Ordering::AcqRel);
            slot.logical_generation.load(Ordering::Acquire)
        })
        .unwrap_or(0);
    slot.requeue_to_key.store(to_key as u64, Ordering::Relaxed);
    slot.requeue_to_generation
        .store(generation, Ordering::Relaxed);
    slot.requeue_moved.store(moved, Ordering::Release);
    slot.requeue_direct.store(direct, Ordering::Release);

    // SAFETY: source is the live shared futex word. The side-table assignments
    // are visible before the physical wake, so every released waiter either
    // returns directly or continues at the destination.
    let rc = unsafe {
        libc::syscall(
            SYS_UMTX_OP,
            from_word as *mut u32 as *mut libc::c_void,
            UMTX_OP_WAKE,
            total as libc::c_ulong,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc < 0 {
        slot.requeue_direct.store(0, Ordering::Release);
        slot.requeue_moved.store(0, Ordering::Release);
        return (0, 0);
    }
    (direct, moved)
}

/// Cross-process shared-futex WAKE via `_umtx_op(UMTX_OP_WAKE)`: wake up to
/// `count` waiters parked (possibly in another forked process) on `word`, and
/// return how many were woken — the Linux `FUTEX_WAKE` retval. FreeBSD's native
/// `_umtx_op(UMTX_OP_WAKE)` returns 0 rather than the count (unlike its own
/// linuxulator futex), so we read the fork-shared waiter-count table
/// [`shared_waiter_slot`] under the stable shared-backing key BEFORE the wake
/// and return `min(count, parked)` — the
/// same number `umtxq_signal_mask` would have reported. Zero parked yields 0,
/// matching Linux on a page nothing is parked on (`futexghost`).
fn shared_futex_wake_umtx(word: usize, waiter_key: usize, count: u32) -> i64 {
    use std::sync::atomic::Ordering;
    let Some(slot) = shared_waiter_slot(waiter_key) else {
        return 0;
    };
    // Logically requeued waiters are counted even before they park on the
    // destination's internal generation. Reserve their credits first; this
    // makes a destination wake lossless across the requeue-to-park window.
    let logical_woke = reserve_logical_wakes(slot, count);
    if logical_woke != 0 {
        slot.logical_generation.fetch_add(1, Ordering::AcqRel);
        let generation_word = (&slot.logical_generation as *const std::sync::atomic::AtomicU32)
            .cast_mut()
            .cast::<libc::c_void>();
        // SAFETY: the generation word is in the run-lifetime MAP_SHARED table.
        // Credits, not the physical wake count, select exactly which waiters
        // complete, so waking all sleepers is safe.
        unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                generation_word,
                UMTX_OP_WAKE,
                u32::MAX as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
    }
    let remaining = count.saturating_sub(logical_woke);
    // Snapshot ordinary parked waiters before waking; released waiters race to
    // decrement as they return from the kernel.
    let normal_woke = remaining.min(slot.count.load(Ordering::SeqCst));
    if normal_woke != 0 {
        // SAFETY: as in `shared_futex_wait_umtx`; WAKE neither reads nor writes
        // the guest word.
        unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                word as *mut u32 as *mut libc::c_void,
                UMTX_OP_WAKE,
                normal_woke as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
    }
    i64::from(logical_woke.saturating_add(normal_woke))
}

/// Park this thread on `wait` until woken, timed out, or interrupted by a
/// pending (deliverable) signal, and map the outcome to the Linux futex return
/// value. `woken_value` is 0 for `FUTEX_WAIT` and the woken index for
/// `futex_waitv`. A sibling `tgkill`/`tkill` publishes a thread-directed signal
/// and calls `notify_signal_pending_for`, which unparks this waiter; the
/// interrupt predicate then observes the pending signal and returns EINTR so
/// the syscall boundary delivers the handler.
fn wait_x86_futex(
    shared: &SharedRun,
    tid: crate::thread::ThreadId,
    wait: crate::thread::FutexWait,
    timeout: Option<std::time::Duration>,
    woken_value: i64,
    executable_registration: &ExecutableThreadRegistration,
) -> Result<i64, ExecutableEpochError> {
    // Reflect the parked thread as 'S' (interruptible sleep) in the registry so
    // `/proc/<tid>/stat` synthesis reports it as sleeping while it blocks, then
    // back to 'R' (running) once it is woken.
    crate::thread::set_current_thread_state(tid, 'S');
    let guard = shared
        .executable_epoch
        .begin_host_wait_safe(executable_registration)?;
    let interrupted = || {
        guard
            .with_host_unsafe(|| {
                shared.exit.requested()
                    || shared.exit.exec_stop_requested()
                    || crate::host_signal::has_unblocked_pending_for(
                        tid.raw(),
                        carrick_abi::SigBlockMask::NONE,
                    )
            })
            .unwrap_or(true)
    };
    let outcome = shared
        .futex
        .wait_prepared_for_thread(wait, timeout, tid, &interrupted);
    guard.finish()?;
    crate::thread::set_current_thread_state(tid, 'R');
    Ok(match outcome {
        crate::thread::FutexWaitOutcome::Woken => woken_value,
        crate::thread::FutexWaitOutcome::TimedOut => {
            crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()
        }
        crate::thread::FutexWaitOutcome::Interrupted => {
            crate::linux_abi::LINUX_EINTR.guest_retval()
        }
    })
}

/// The thread-aware sibling of [`crate::runtime::service_syscall`]: dispatch one
/// syscall through `dispatch_threaded(&self, …, tid, registry, futex)` and
/// service the blocking-I/O outcomes (fd wait / poll / select / sleep /
/// blocking write / signal / proc wait) inline on the `waiter`, re-dispatching
/// on readiness. Interior mutability makes it shareable across guest threads;
/// the body mirrors the single-threaded servicer exactly, only the dispatch
/// call differs. Terminal and thread-specific outcomes (Returned/Errno/Exit/
/// CloneThread/FutexWait/ThreadExit/…) fall through to the caller.
#[derive(Debug)]
enum NativeSyscallServiceError {
    Dispatch(crate::dispatch::DispatchError),
    Memory(MemoryError),
    Epoch(ExecutableEpochError),
    AliasInvariant {
        number: carrick_abi::CanonicalNr,
        detail: &'static str,
    },
}

fn is_alias_mapping_syscall(number: carrick_abi::CanonicalNr) -> bool {
    matches!(number.raw(), 196 | 216 | 222)
}

fn finish_alias_dispatch_critical(alias_critical: &mut Option<ExecutableMutationLease>) {
    if let Some(lease) = alias_critical.take() {
        lease.finish_unchanged();
    }
}

fn begin_threaded_dispatch_iteration(
    executable_epoch: &Arc<ExecutableEpoch>,
    executable_registration: &ExecutableThreadRegistration,
    number: carrick_abi::CanonicalNr,
    alias_critical: &mut Option<ExecutableMutationLease>,
) -> Result<(), NativeSyscallServiceError> {
    begin_threaded_dispatch_iteration_after_boundary(
        executable_epoch,
        executable_registration,
        number,
        alias_critical,
        || {},
    )
}

/// Enter one dispatch attempt in the only safe order: exact host-fork
/// boundary, then (for mmap/mremap/shmat only) executable mutation ownership.
/// The callback is an empty production seam used by the deterministic race test
/// to publish a host fork in the otherwise instruction-sized gap.
fn begin_threaded_dispatch_iteration_after_boundary(
    executable_epoch: &Arc<ExecutableEpoch>,
    executable_registration: &ExecutableThreadRegistration,
    number: carrick_abi::CanonicalNr,
    alias_critical: &mut Option<ExecutableMutationLease>,
    after_boundary: impl FnOnce(),
) -> Result<(), NativeSyscallServiceError> {
    executable_epoch
        .fork_safe_boundary(executable_registration)
        .map_err(NativeSyscallServiceError::Epoch)?;
    after_boundary();
    if !is_alias_mapping_syscall(number) {
        return Ok(());
    }
    if alias_critical.is_some() {
        finish_alias_dispatch_critical(alias_critical);
        return Err(NativeSyscallServiceError::AliasInvariant {
            number,
            detail: "dispatch retry reached its boundary while the prior alias lease was owned",
        });
    }
    *alias_critical = Some(
        executable_epoch
            .begin_mutation()
            .map_err(NativeSyscallServiceError::Epoch)?,
    );
    Ok(())
}

fn is_wait_outcome(outcome: &DispatchOutcome) -> bool {
    matches!(
        outcome,
        DispatchOutcome::FutexWait { .. }
            | DispatchOutcome::FutexWaitv { .. }
            | DispatchOutcome::SharedFutexWait { .. }
            | DispatchOutcome::SharedFutexWaitv { .. }
            | DispatchOutcome::WaitOnSharedWord { .. }
            | DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::BlockingHostWrite(_)
            | DispatchOutcome::BlockingRecordLock(_)
            | DispatchOutcome::WaitOnFdsSelect { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::WaitOnProcExit { .. }
            | DispatchOutcome::WaitOnProcState { .. }
            | DispatchOutcome::WaitOnSignals { .. }
            | DispatchOutcome::WaitOnSleep { .. }
    )
}

fn with_host_wait_safe<T>(
    epoch: &Arc<ExecutableEpoch>,
    registration: &ExecutableThreadRegistration,
    operation: impl FnOnce(&ExecutableHostWaitGuard<'_>) -> T,
) -> Result<T, NativeSyscallServiceError> {
    let guard = epoch
        .begin_host_wait_safe(registration)
        .map_err(NativeSyscallServiceError::Epoch)?;
    let result = operation(&guard);
    guard.finish().map_err(NativeSyscallServiceError::Epoch)?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn service_syscall_threaded(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &mut IdentityGuestMemory,
    reporter: &CompatReporter,
    waiter: &mut crate::io_wait::ThreadWaiter,
    tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
    futex: &crate::thread::FutexTable,
    exit: &ExitState,
    executable_epoch: &Arc<ExecutableEpoch>,
    executable_registration: &ExecutableThreadRegistration,
    alias_critical: &mut Option<ExecutableMutationLease>,
) -> Result<DispatchOutcome, NativeSyscallServiceError> {
    use crate::io_wait::{WaitFd, WaitResult};
    const EINTR: crate::linux_abi::LinuxErrno = crate::linux_abi::LINUX_EINTR;
    // A blocking wait (sleep/poll/select/proc-exit) must break with EINTR when a
    // deliverable (unblocked) signal becomes pending for this thread, so the run
    // loop's syscall-return `run_pending_signals` enters the handler. Guest
    // signals are published into the shared pending mask (self/kill-raise, a
    // sibling `tgkill`, an itimer/alarm timer, an async child-exit) WITHOUT a
    // host signal being sent, so — unlike the futex wait, which already carries
    // this predicate — the plain `ppoll` slice would otherwise run to its
    // timeout and never surface EINTR. `ppoll_wait_inner` caps each slice at a
    // short backstop and re-checks this predicate, so the latency is bounded.
    // The predicate honors the wait's atomic sigmask policy: for `ppoll`/
    // `pselect6` (`WaitSigMask::Replace`) a signal the temporary mask unblocks
    // must interrupt even if the thread persistently blocks it (`ppollunblock`
    // raises a blocked SIGUSR1, then unblocks it via ppoll's mask). It checks
    // BOTH the shared host_signal pending set (self/kill/timer/child-exit) and
    // the dispatcher's own per-thread pending set (a blocked-then-unblocked
    // raise lands there), matching the shared KVM servicer.
    let signal_pending = |mask: carrick_abi::WaitSigMask,
                          wait_guard: &ExecutableHostWaitGuard<'_>| {
        wait_guard
            .with_host_unsafe(|| {
                if exit.requested() || exit.exec_stop_requested() {
                    return true;
                }
                drain_native_child_exit_watches(false);
                dispatcher.drain_xsignals_process_directed();
                crate::host_signal::has_unblocked_pending_for(tid.raw(), mask.block_mask())
                    || dispatcher.has_deliverable_dispatch_pending_for_wait(tid, mask)
            })
            .unwrap_or(true)
    };
    let mut poll_deadline: Option<std::time::Instant> = None;
    let mut sleep_deadline: Option<std::time::Instant> = None;
    let alias_syscall = is_alias_mapping_syscall(request.number);
    loop {
        begin_threaded_dispatch_iteration(
            executable_epoch,
            executable_registration,
            request.number,
            alias_critical,
        )?;
        drain_native_child_exit_watches(false);
        let outcome = dispatcher.dispatch_threaded(request, memory, reporter, tid, registry, futex);
        if let Some(error) = memory.take_mapping_failure() {
            // A successful dispatch can already own a deferred transaction.
            // Roll it back before releasing the lease that excludes host fork.
            drop(outcome);
            finish_alias_dispatch_critical(alias_critical);
            return Err(NativeSyscallServiceError::Memory(error));
        }
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                finish_alias_dispatch_critical(alias_critical);
                return Err(NativeSyscallServiceError::Dispatch(error));
            }
        };
        let wait_outcome = is_wait_outcome(&outcome);
        if wait_outcome {
            // No thread may advertise HostWaitSafe or hand a wait back to the
            // caller while it owns executable mutation. Every retry therefore
            // crosses a fresh exact boundary before reacquiring.
            finish_alias_dispatch_critical(alias_critical);
            if alias_syscall {
                return Err(NativeSyscallServiceError::AliasInvariant {
                    number: request.number,
                    detail: "mapping syscall returned a blocking wait outcome",
                });
            }
        } else if matches!(&outcome, DispatchOutcome::MapHostAlias { .. }) {
            if !alias_syscall || alias_critical.is_none() {
                drop(outcome);
                finish_alias_dispatch_critical(alias_critical);
                return Err(NativeSyscallServiceError::AliasInvariant {
                    number: request.number,
                    detail: "MapHostAlias returned without its outer executable mutation lease",
                });
            }
        } else {
            finish_alias_dispatch_critical(alias_critical);
        }
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => match with_host_wait_safe(
                executable_epoch,
                executable_registration,
                |wait_guard| {
                    waiter.wait_with_dispatch_pending(&fds, timeout, sig_mask.block_mask(), || {
                        signal_pending(sig_mask, wait_guard)
                    })
                },
            )? {
                WaitResult::Ready => continue,
                WaitResult::TimedOut => {
                    return Ok(DispatchOutcome::Returned { value: on_timeout });
                }
                WaitResult::Interrupted => {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
            },
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => {
                let timeout = match timeout {
                    Some(duration) => {
                        let deadline = *poll_deadline
                            .get_or_insert_with(|| std::time::Instant::now() + duration);
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            return Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        Some(deadline - now)
                    }
                    None => {
                        poll_deadline = None;
                        None
                    }
                };
                match with_host_wait_safe(
                    executable_epoch,
                    executable_registration,
                    |wait_guard| {
                        waiter.wait_poll_with_dispatch_pending(
                            &fds,
                            timeout,
                            sig_mask.block_mask(),
                            || signal_pending(sig_mask, wait_guard),
                        )
                    },
                )? {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnFdsSelect {
                fds,
                timeout,
                sig_mask,
                clear_on_timeout,
            } => match with_host_wait_safe(
                executable_epoch,
                executable_registration,
                |wait_guard| {
                    waiter.wait_with_dispatch_pending(&fds, timeout, sig_mask.block_mask(), || {
                        signal_pending(sig_mask, wait_guard)
                    })
                },
            )? {
                WaitResult::Ready => continue,
                WaitResult::TimedOut => {
                    for (addr, len) in &clear_on_timeout {
                        let _ = memory.zero_guest_range(*addr, *len);
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                WaitResult::Interrupted => {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
            },
            DispatchOutcome::WaitOnSleep {
                duration,
                remaining,
            } => {
                let deadline =
                    *sleep_deadline.get_or_insert_with(|| std::time::Instant::now() + duration);
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                match with_host_wait_safe(
                    executable_epoch,
                    executable_registration,
                    |wait_guard| {
                        waiter.wait_with_dispatch_pending(
                            &[],
                            Some(deadline - now),
                            carrick_abi::SigBlockMask::NONE,
                            || signal_pending(carrick_abi::WaitSigMask::NONE, wait_guard),
                        )
                    },
                )? {
                    WaitResult::Ready | WaitResult::TimedOut => {
                        if std::time::Instant::now() >= deadline {
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        continue;
                    }
                    WaitResult::Interrupted => {
                        return Ok(crate::dispatch::complete_interrupted_sleep(
                            memory,
                            remaining,
                            deadline.saturating_duration_since(std::time::Instant::now()),
                        ));
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::BlockingHostWrite(mut write) => loop {
                match crate::dispatch::drive_blocking_host_write(&mut write) {
                    crate::dispatch::BlockingHostWriteStep::Done(o) => return Ok(o),
                    crate::dispatch::BlockingHostWriteStep::Wait => {
                        match with_host_wait_safe(
                            executable_epoch,
                            executable_registration,
                            |_| {
                                waiter.wait_with_dispatch_pending(
                                    &[WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                    None,
                                    carrick_abi::SigBlockMask::NONE,
                                    || exit.requested() || exit.exec_stop_requested(),
                                )
                            },
                        )? {
                            WaitResult::Ready => continue,
                            WaitResult::Interrupted | WaitResult::TimedOut => {
                                return Ok(DispatchOutcome::Returned {
                                    value: write.offset() as i64,
                                });
                            }
                            WaitResult::Errno(errno) => {
                                if write.offset() > 0 {
                                    return Ok(DispatchOutcome::Returned {
                                        value: write.offset() as i64,
                                    });
                                }
                                return Ok(DispatchOutcome::Errno { errno });
                            }
                        }
                    }
                }
            },
            DispatchOutcome::BlockingRecordLock(lock) => {
                if exit.requested() || exit.exec_stop_requested() {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                return with_host_wait_safe(executable_epoch, executable_registration, |_| {
                    crate::dispatch::drive_blocking_record_lock(&lock)
                });
            }
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout,
            } => {
                // A `sigwait`/`sigtimedwait` target signal can become pending
                // WITHOUT any host signal being sent: a sibling guest thread's
                // `kill(getpid(), sig)` publishes it process-directed via
                // `raise_for_self`, and a `tgkill` of a wait-set signal marks it
                // in the dispatcher's own pending set. A bare `ppoll` park (no
                // predicate) only wakes on a host EINTR, so a BOUNDED
                // sigtimedwait ran to its full timeout and returned EAGAIN
                // instead of dequeuing the signal (`sigwaitthread`,
                // `sigwaitalarm`). Poll both pending stores so the park breaks
                // promptly and the re-dispatch's `take_pending_in_from` /
                // `take_pending_in_for` returns the signum.
                let wait_result =
                    with_host_wait_safe(executable_epoch, executable_registration, |wait_guard| {
                        let pending = move || {
                            wait_guard
                                .with_host_unsafe(|| {
                                    if exit.requested() || exit.exec_stop_requested() {
                                        return true;
                                    }
                                    drain_native_child_exit_watches(false);
                                    dispatcher.drain_xsignals_process_directed();
                                    crate::host_signal::has_unblocked_pending_for(
                                        tid.raw(),
                                        block_mask,
                                    ) || dispatcher.has_deliverable_dispatch_pending_for_wait(
                                        tid,
                                        carrick_abi::WaitSigMask::Replace(
                                            carrick_abi::SigSet::from_raw(block_mask.raw()),
                                        ),
                                    )
                                })
                                .unwrap_or(true)
                        };
                        waiter.wait_with_dispatch_pending(&[], timeout, block_mask, pending)
                    })?;
                match wait_result {
                    WaitResult::Ready => continue,
                    WaitResult::Interrupted => {
                        if exit.requested() || exit.exec_stop_requested() {
                            return Ok(DispatchOutcome::Errno { errno: EINTR });
                        }
                        // A pending signal OUTSIDE the wait set completes with
                        // EINTR; a wait-set signal (or a spurious wake) re-dispatches
                        // so `rt_sigtimedwait` dequeues + returns it.
                        if dispatcher.signal_wait_should_eintr(waiter.tid(), wait_set, block_mask) {
                            return Ok(DispatchOutcome::Errno { errno: EINTR });
                        }
                        continue;
                    }
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EAGAIN,
                        });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                match with_host_wait_safe(
                    executable_epoch,
                    executable_registration,
                    |wait_guard| {
                        waiter.wait_proc_exit_with_dispatch_pending(
                            pid,
                            sig_mask.block_mask(),
                            || signal_pending(sig_mask, wait_guard),
                        )
                    },
                )? {
                    // Ready (child exited) -> re-dispatch the waitid to reap.
                    WaitResult::Ready => continue,
                    // A deliverable signal interrupted the blocking wait4/waitid:
                    // return EINTR so the run loop's delivery tail runs the guest
                    // handler and, for SA_RESTART, restarts the syscall (LTP's
                    // SAFE_WAITPID under an SA_RESTART SIGALRM heartbeat —
                    // `waitrestart`). Returning ECHILD here (the old behaviour)
                    // told the guest it had no children mid-wait, aborting the
                    // reap. Matches the shared single-thread lane (runtime.rs).
                    WaitResult::Interrupted | WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnProcState { sig_mask, .. } => {
                match with_host_wait_safe(executable_epoch, executable_registration, |_| {
                    waiter.wait_proc_state_with_dispatch_pending(sig_mask.block_mask(), || {
                        exit.requested() || exit.exec_stop_requested()
                    })
                })? {
                    WaitResult::Ready | WaitResult::TimedOut => continue,
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnSharedWord {
                location, value, ..
            } => {
                // Runtime-owned fork-shared state (currently SysV message
                // queues): the word change is only a wake hint, never the
                // syscall result. Park through FreeBSD's cross-process umtx,
                // then re-dispatch under fresh queue state. A value race before
                // the park is EAGAIN and means the same thing: re-check now.
                if exit.requested() || exit.exec_stop_requested() {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                let retval =
                    with_host_wait_safe(executable_epoch, executable_registration, |_| {
                        carrick_host::shared_word::wait(location.wait_addr().raw(), value, 0)
                    })?;
                if retval == 0 {
                    continue;
                }
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval() {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                return Ok(DispatchOutcome::Returned { value: retval });
            }
            // Terminal + thread-specific (Returned/Errno/Exit/CloneThread/
            // FutexWait/ThreadExit/…): the caller drives these.
            terminal => return Ok(terminal),
        }
    }
}

/// Runtime-owned fields of a process-creating clone outcome.
struct NativeForkRequest {
    clone_parent: bool,
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    child_stack: u64,
    pidfd_out: Option<u64>,
    parent_tid: i32,
    exit_signal: u32,
    vfork: Option<u64>,
}

fn validate_native_fork_parent_outputs(
    memory: &impl GuestMemory,
    request: &NativeForkRequest,
) -> Result<(), crate::linux_abi::LinuxErrno> {
    request
        .pidfd_out
        .into_iter()
        .chain(request.parent_tid_addr)
        .try_for_each(|address| {
            memory
                .guest_range_is_writable(address, std::mem::size_of::<i32>())
                .then_some(())
                .ok_or(crate::linux_abi::LINUX_EFAULT)
        })
}

#[derive(Debug)]
struct NativeVforkShare {
    ranges: Vec<(u64, usize)>,
    pipe: [i32; 2],
}

struct NativeVforkPrepareError {
    source: std::io::Error,
    rollback_failed: bool,
}

#[cfg(test)]
thread_local! {
    static NATIVE_MINHERIT_FAILURE_SCRIPT: std::cell::RefCell<std::collections::VecDeque<bool>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    static NATIVE_FORK_GATE_WRITE_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn native_fork_gate_write(fd: i32, byte: &u8) -> libc::ssize_t {
    #[cfg(test)]
    if NATIVE_FORK_GATE_WRITE_FAILURES.with(|failures| {
        let remaining = failures.get();
        if remaining == 0 {
            false
        } else {
            failures.set(remaining - 1);
            true
        }
    }) {
        // SAFETY: FreeBSD exposes this thread's errno through __error().
        unsafe { *libc::__error() = libc::EIO };
        return -1;
    }
    // SAFETY: `byte` owns one readable byte for the duration of the syscall.
    unsafe { libc::write(fd, (byte as *const u8).cast::<libc::c_void>(), 1) }
}

fn release_native_fork_gate(write_fd: i32) -> std::io::Result<()> {
    let release = 1u8;
    loop {
        let rc = native_fork_gate_write(write_fd, &release);
        if rc == 1 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if rc < 0 && error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(if rc < 0 {
            error
        } else {
            std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!("fork gate write returned {rc}, expected 1"),
            )
        });
    }
}

fn kill_and_reap_native_fork_child(pid: i32) {
    // The child is still behind the private parent-output gate. Keep its write
    // end open until SIGKILL is sent so EOF cannot accidentally release it.
    unsafe {
        if libc::kill(pid, libc::SIGKILL) != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            std::process::abort();
        }
        let mut status = 0;
        loop {
            let rc = libc::waitpid(pid, &mut status, 0);
            if rc == pid
                || (rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                break;
            }
            if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            std::process::abort();
        }
    }
}

#[cfg(test)]
struct NativeForkGateWriteFailureGuard;

#[cfg(test)]
impl NativeForkGateWriteFailureGuard {
    fn fail_next() -> Self {
        NATIVE_FORK_GATE_WRITE_FAILURES.with(|failures| failures.set(1));
        Self
    }
}

#[cfg(test)]
impl Drop for NativeForkGateWriteFailureGuard {
    fn drop(&mut self) {
        NATIVE_FORK_GATE_WRITE_FAILURES.with(|failures| failures.set(0));
    }
}

fn native_minherit(address: u64, len: usize, inheritance: libc::c_int) -> libc::c_int {
    #[cfg(test)]
    if NATIVE_MINHERIT_FAILURE_SCRIPT
        .with(|script| script.borrow_mut().pop_front().unwrap_or(false))
    {
        return -1;
    }
    unsafe { carrick_portable::freebsd_minherit(address as *mut libc::c_void, len, inheritance) }
}

#[cfg(test)]
struct NativeMinheritFailureGuard;

#[cfg(test)]
impl NativeMinheritFailureGuard {
    fn install(script: impl IntoIterator<Item = bool>) -> Self {
        NATIVE_MINHERIT_FAILURE_SCRIPT.with(|state| {
            *state.borrow_mut() = script.into_iter().collect();
        });
        Self
    }
}

#[cfg(test)]
impl Drop for NativeMinheritFailureGuard {
    fn drop(&mut self) {
        NATIVE_MINHERIT_FAILURE_SCRIPT.with(|state| state.borrow_mut().clear());
    }
}

fn exclude_vfork_shared_ranges(
    ranges: Vec<(u64, usize)>,
    exclusions: &[(u64, usize)],
) -> Vec<(u64, usize)> {
    let mut result = Vec::new();
    for (start, len) in ranges {
        let Some(end) = start.checked_add(len as u64) else {
            continue;
        };
        let mut pieces = vec![(start, end)];
        for &(exclude_start, exclude_len) in exclusions {
            let exclude_end = exclude_start.saturating_add(exclude_len as u64);
            let mut next = Vec::new();
            for (piece_start, piece_end) in pieces {
                if exclude_end <= piece_start || exclude_start >= piece_end {
                    next.push((piece_start, piece_end));
                    continue;
                }
                if piece_start < exclude_start {
                    next.push((piece_start, exclude_start));
                }
                if exclude_end < piece_end {
                    next.push((exclude_end, piece_end));
                }
            }
            pieces = next;
        }
        result.extend(pieces.into_iter().filter_map(|(piece_start, piece_end)| {
            usize::try_from(piece_end.saturating_sub(piece_start))
                .ok()
                .filter(|len| *len != 0)
                .map(|len| (piece_start, len))
        }));
    }
    result.sort_unstable_by_key(|&(start, _)| start);
    let mut coalesced: Vec<(u64, usize)> = Vec::new();
    for (start, len) in result {
        if let Some((last_start, last_len)) = coalesced.last_mut() {
            let last_end = last_start.saturating_add(*last_len as u64);
            if start <= last_end {
                let end = start.saturating_add(len as u64).max(last_end);
                *last_len = (end - *last_start) as usize;
                continue;
            }
        }
        coalesced.push((start, len));
    }
    coalesced
}

fn native_private_inheritance_ranges(shared: &SharedRun) -> Vec<(u64, usize)> {
    let image = shared.current_image();
    let mut ranges: Vec<(u64, usize)> = image
        .segments
        .iter()
        .filter_map(|&(start, end)| {
            usize::try_from(end.saturating_sub(start))
                .ok()
                .map(|len| (start, len))
        })
        .collect();
    ranges.extend([
        (image.stack, image.stack_len),
        (image.scratch, image.scratch_len),
        (LINUX_HEAP_BASE, LINUX_HEAP_SIZE as usize),
        (LINUX_MMAP_BASE, mmap_arena_size() as usize),
    ]);
    ranges.extend(shared.dispatcher.private_dynamic_mapping_ranges());
    // Existing MAP_SHARED mappings already cross fork correctly. Never run
    // them through INHERIT_COPY: FreeBSD documents that this permanently
    // severs their backing-store sharing.
    exclude_vfork_shared_ranges(ranges, &shared.dispatcher.shared_dynamic_mapping_ranges())
}

impl NativeVforkShare {
    fn restore_ranges(ranges: &[(u64, usize)]) -> std::io::Result<()> {
        let mut first_error = None;
        for &(start, len) in ranges.iter().rev() {
            if native_minherit(start, len, carrick_portable::FREEBSD_INHERIT_COPY) != 0
                && first_error.is_none()
            {
                first_error = Some(std::io::Error::last_os_error());
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn prepare_ranges(
        ranges: Vec<(u64, usize)>,
        epoch: &ExecutableEpoch,
    ) -> Result<Self, NativeVforkPrepareError> {
        for (applied, &(start, len)) in ranges.iter().enumerate() {
            if native_minherit(start, len, carrick_portable::FREEBSD_INHERIT_SHARE) != 0 {
                let source = std::io::Error::last_os_error();
                let rollback_failed = Self::restore_ranges(&ranges[..applied]).is_err();
                if rollback_failed {
                    epoch.fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
                }
                return Err(NativeVforkPrepareError {
                    source,
                    rollback_failed,
                });
            }
        }
        let mut pipe = [-1; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            let source = std::io::Error::last_os_error();
            let rollback_failed = Self::restore_ranges(&ranges).is_err();
            if rollback_failed {
                epoch.fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
            }
            return Err(NativeVforkPrepareError {
                source,
                rollback_failed,
            });
        }
        Ok(Self { ranges, pipe })
    }

    fn prepare(shared: &SharedRun) -> Result<Self, NativeVforkPrepareError> {
        Self::prepare_ranges(
            native_private_inheritance_ranges(shared),
            &shared.executable_epoch,
        )
    }

    fn restore_parent_inheritance(&self, epoch: &ExecutableEpoch) -> std::io::Result<()> {
        let result = Self::restore_ranges(&self.ranges);
        if result.is_err() {
            epoch.fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
        }
        result
    }
}

fn wait_native_vfork_completion(read_fd: i32, exit: &ExitState) -> bool {
    loop {
        if exit.exec_stop_requested() {
            return false;
        }
        let wake_fd = exit.vfork_wake_fd();
        let mut pollfds = [
            libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            },
        ];
        // The normal path blocks in one host syscall until child completion or
        // sibling exec. Only the pipe-creation fallback uses a bounded wait.
        let timeout = if wake_fd >= 0 { -1 } else { 20 };
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as u32, timeout) };
        if rc < 0 {
            // Signals are wake hints: re-check exec_stop and the completion fd.
            continue;
        }
        if exit.exec_stop_requested() {
            return false;
        }
        if pollfds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let mut byte = 0u8;
            let read =
                unsafe { libc::read(read_fd, (&mut byte as *mut u8).cast::<libc::c_void>(), 1) };
            if read >= 0 {
                return true;
            }
        }
    }
}

/// Perform a guest `fork()` as a host `fork()`. Sets guest `rax` (0 in the
/// child, the child pid in the parent), runs the child on `child_stack` if
/// given, and honors CLONE_PARENT_SETTID / CLONE_CHILD_SETTID. Returns
/// [`Step::BecameForkChild`] in the child so the run loop `_exit`s it directly.
///
/// # Host-fork lock order
///
/// Exact `ExecutableHostForkLease` drain -> unregistered bridge/RLIMIT_CPU
/// helper gates -> `NativeForkGuard` -> `HostAliasDispatchGuard` ->
/// `ExecutableMutationLease` -> signal+timer fork guards ->
/// `IDENTITY_HOST_MAPPING_LOCK` writer -> `MemoryProtections` exclusive guard.
/// The exact host lease is published first: no sibling may block on a helper,
/// fork, or alias gate while still advertised HostUnsafe. It remains held
/// across every bounded acquisition and through `fork`, then the successful
/// parent releases it immediately: Linux vfork suspends only the caller. The
/// native-fork, alias, mapping, protection, and executable-mutation guards keep
/// excluding a second actual fork or mapping change until vfork restoration.
/// Every child-side guard is dropped or explicitly abandoned before
/// `native_after_fork_child` touches dispatcher state.
fn service_fork(
    shared: &Arc<SharedRun>,
    request: NativeForkRequest,
    snapshot: &mut X86UcontextSnapshot,
    memory: &mut IdentityGuestMemory,
    resume: u64,
    executable_registration: &mut ExecutableThreadRegistration,
) -> Step {
    let dispatcher = &shared.dispatcher;
    // Publish the exact host stop FIRST. Release every lock-free host wait and
    // interrupt a syscall racing its registration boundary; the coordinator
    // callback itself performs only async-safe pthread signals while holding
    // the exact registration table.
    shared.futex.notify_signal_pending();
    dispatcher.notify_inmem_epoll();
    let mut contention_retried = false;
    let mut host_fork_lease = loop {
        let reservation_deadline = std::time::Instant::now() + EXECUTABLE_QUIESCENCE_TIMEOUT;
        match shared.prepare_host_fork_with_reaping(
            executable_registration,
            reservation_deadline,
            |targets| {
                for pthread in targets {
                    unsafe {
                        libc::pthread_kill(*pthread, FREEBSD_NATIVE_EXIT_KICK_SIGNAL);
                    }
                }
            },
        ) {
            Ok(lease) => break Some(lease),
            Err(ExecutableEpochError::TerminalActive { owner })
                if owner.thread != executable_registration.id =>
            {
                // Another thread owns terminal exec. This old-image syscall
                // body must disappear without publishing process exit 125.
                return Step::RetiredForExec;
            }
            Err(ExecutableEpochError::HostForkBusy) => {
                // Both forkers crossed the post-dispatch boundary before either
                // published its reservation. Park this exact registration so
                // the winner can drain and release; then make one fresh bounded
                // reservation attempt. A second loss returns EAGAIN only after
                // crossing the second exact release, never while its owner is
                // waiting for this registration.
                if let Err(error) = shared
                    .executable_epoch
                    .fork_safe_boundary(executable_registration)
                {
                    return Step::Fault(format!(
                        "native host fork contention boundary failed: {error:?}"
                    ));
                }
                if contention_retried {
                    snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64;
                    return Step::Continue(resume);
                }
                contention_retried = true;
            }
            Err(error) => {
                return Step::Fault(format!(
                    "native host fork drain failed without calling fork: {error:?}"
                ));
            }
        }
    };
    // Time spent parked behind an exact competing fork is not charged against
    // this reservation's gate acquisitions.
    let deadline = std::time::Instant::now() + EXECUTABLE_QUIESCENCE_TIMEOUT;

    // Only a fully drained registration snapshot may wait on gates owned by
    // unregistered helpers. Bridge publication nests gate->registry; RLIMIT_CPU
    // nests gate->timer/signal. Holding both here proves their child copies are
    // unlocked, without adding a mutex to healthy syscall/boundary paths.
    let network_fork_guard = match dispatcher.begin_network_fork_guard_until(deadline) {
        Some(guard) => Some(guard),
        None => {
            // No host fork happened. Release the exact sibling drain and report
            // Linux's retryable resource-contention result.
            snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64;
            return Step::Continue(resume);
        }
    };
    let rlimit_cpu_fork_guard = match dispatcher.begin_rlimit_cpu_fork_guard_until(deadline) {
        Some(guard) => Some(guard),
        None => {
            // The helper is between CPU accounting and signal publication, but
            // no host fork has occurred. Roll back the exact drain and expose
            // ordinary retryable fork pressure instead of killing the run.
            snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64;
            return Step::Continue(resume);
        }
    };
    let mut fork_guard = match NativeForkGuard::acquire_until(deadline) {
        Ok(guard) => Some(guard),
        Err(ExecutableEpochError::HostForkTimedOut) => {
            // A vfork parent retains this process-global reservation while its
            // child shares mappings. This contender already drained siblings;
            // dropping its exact host lease before returning lets that parent
            // finish the boundary and matches Linux's retryable fork pressure.
            snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64;
            return Step::Continue(resume);
        }
        Err(error) => {
            return Step::Fault(format!(
                "native host fork reservation failed without calling fork: {error:?}"
            ));
        }
    };
    let mut alias_exclusion = match dispatcher.begin_host_alias_dispatch_until(deadline) {
        Some(guard) => Some(guard),
        None => {
            return Step::Fault(
                "native host fork timed out acquiring alias dispatch exclusion without calling fork"
                    .to_string(),
            );
        }
    };

    // Linux completes both parent outputs before making clone success visible.
    // Validate the COMPLETE four-byte ranges through GuestMemory's writable
    // permission seam before allocating a namespace pid, preparing a child
    // record, creating a gate, changing vfork inheritance, or calling fork.
    // The exact host stop plus alias exclusion prevents a guest mapping change
    // until the mapping/protection snapshot guards below retain this result.
    if let Err(errno) = validate_native_fork_parent_outputs(memory, &request) {
        snapshot.gpr[reg::RAX] = errno.guest_retval() as u64;
        return Step::Continue(resume);
    }

    let current = std::process::id();
    let child_parent = if request.clone_parent {
        dispatcher.clone_parent_host_pid()
    } else {
        current
    };
    let explicit_subreaper = dispatcher.subreaper_for_fork_child();
    // FreeBSD's PROC_REAP_ACQUIRE makes the top-level native process act as
    // the guest's init. When no guest explicitly selected a subreaper, retain
    // that init as the orphan-adoption target in the fork-coherent child table.
    // `ProcState::subreaper_ancestor` remains zero, which lets getppid expose
    // this implementation adoption as guest PID 1 rather than the host pid.
    let child_subreaper = if explicit_subreaper == 0 {
        dispatcher.bootstrap_host_pid()
    } else {
        explicit_subreaper
    };
    let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
    let prepared = match crate::guest_cpu::prepare_child_record_pre_fork(
        child_parent,
        child_subreaper,
        child_ns_pid.unwrap_or(0),
        request.clone_parent && child_parent != current,
        0,
    ) {
        Ok(record) => record,
        Err(_) => {
            snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64;
            return Step::Continue(resume);
        }
    };

    // Parent output publication is atomic from the guest's perspective: the
    // child cannot run user code before pidfd installation and both checked
    // four-byte writes complete. The private host pipe never enters the guest
    // fd table. PARENT_SETTID uses the same gate even without CLONE_PIDFD.
    let pidfd_gate = if request.pidfd_out.is_some() || request.parent_tid_addr.is_some() {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            crate::guest_cpu::abort_prepared_child_record();
            drop(fork_guard);
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE);
            snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
            return Step::Continue(resume);
        }
        Some(fds)
    } else {
        None
    };

    // Vfork inheritance is changed only after the executable/mapping/protection
    // snapshot guards below are all retained. Until then no rollback is needed.
    let mut vfork_share: Option<NativeVforkShare> = None;

    // Stop every admitted JIT interval before host fork snapshots the process
    // mappings. No arbitrary-PC signal redirect is needed: hot edge/return
    // guards reach exact semantic boundaries and admission stays closed until
    // the parent has forked. The child must never drop this inherited lease;
    // its fresh SharedRun installs a fresh coordinator after the fork boundary.
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let mut fork_epoch_lease = match shared
        .executable_epoch
        .begin_mutation_with_timeout(remaining)
    {
        Ok(lease) => Some(lease),
        Err(error) => {
            if let Some([read_fd, write_fd]) = pidfd_gate {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            crate::guest_cpu::abort_prepared_child_record();
            drop(fork_guard);
            return Step::Fault(format!(
                "native host fork executable snapshot failed without calling fork: {error:?}"
            ));
        }
    };

    // Siblings are now either exact-parked or declared lock-free waiters, so
    // these snapshot locks cannot be inherited from a vanished guest thread.
    // Auxiliary signal publishers are pinned explicitly as well, with the same
    // absolute deadline rather than an unbounded std-mutex acquisition.
    let Some(fork_signal_locks) =
        crate::host_signal::try_hold_signal_locks_for_fork_until(deadline)
    else {
        if let Some(lease) = fork_epoch_lease.take() {
            lease.finish_unchanged();
        }
        if let Some([read_fd, write_fd]) = pidfd_gate {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
        }
        crate::guest_cpu::abort_prepared_child_record();
        drop(fork_guard);
        return Step::Fault(
            "native host fork timed out acquiring signal fork locks without calling fork"
                .to_string(),
        );
    };
    let Some(fork_mapping_guard) = identity_host_mapping_write_until(deadline) else {
        if let Some(lease) = fork_epoch_lease.take() {
            lease.finish_unchanged();
        }
        if let Some([read_fd, write_fd]) = pidfd_gate {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
        }
        crate::guest_cpu::abort_prepared_child_record();
        drop(fork_signal_locks);
        drop(fork_guard);
        return Step::Fault(
            "native host fork timed out acquiring identity mapping writer without calling fork"
                .to_string(),
        );
    };
    let mut fork_mapping_guard = Some(fork_mapping_guard);
    let Some(fork_protections_guard) = IDENTITY_PROTECTIONS.exclusive_for_fork_until(deadline)
    else {
        if let Some(lease) = fork_epoch_lease.take() {
            lease.finish_unchanged();
        }
        if let Some([read_fd, write_fd]) = pidfd_gate {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
        }
        crate::guest_cpu::abort_prepared_child_record();
        drop(fork_mapping_guard.take());
        drop(fork_signal_locks);
        drop(fork_guard);
        return Step::Fault(
            "native host fork timed out acquiring protection snapshot without calling fork"
                .to_string(),
        );
    };
    let mut fork_protections_guard = Some(fork_protections_guard);

    // Only now are alias publication, executable mutation, identity mapping,
    // and protection snapshots all excluded for every prepare rollback.
    if request.vfork.is_some() {
        match NativeVforkShare::prepare(shared) {
            Ok(state) => vfork_share = Some(state),
            Err(error) => {
                if error.rollback_failed {
                    shared
                        .executable_epoch
                        .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
                }
                if let Some([read_fd, write_fd]) = pidfd_gate {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                crate::guest_cpu::abort_prepared_child_record();
                drop(fork_protections_guard.take());
                drop(fork_mapping_guard.take());
                drop(fork_signal_locks);
                if let Some(lease) = fork_epoch_lease.take() {
                    lease.finish_unchanged();
                }
                drop(alias_exclusion.take());
                drop(fork_guard.take());
                if error.rollback_failed {
                    return Step::Fault(format!(
                        "native vfork prepare rollback failed permanently: {}",
                        error.source
                    ));
                }
                let errno = error.source.raw_os_error().unwrap_or(libc::EAGAIN);
                snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
                return Step::Continue(resume);
            }
        }
    }

    let previous_host_mask = match block_native_transport_signals_for_fork() {
        Ok(mask) => mask,
        Err(error) => {
            let restore_failed = vfork_share.as_ref().is_some_and(|state| {
                state
                    .restore_parent_inheritance(&shared.executable_epoch)
                    .is_err()
            });
            if restore_failed {
                shared
                    .executable_epoch
                    .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
            }
            if let Some(state) = &vfork_share {
                unsafe {
                    libc::close(state.pipe[0]);
                    libc::close(state.pipe[1]);
                }
            }
            if let Some([read_fd, write_fd]) = pidfd_gate {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
            }
            crate::guest_cpu::abort_prepared_child_record();
            drop(fork_protections_guard.take());
            drop(fork_mapping_guard.take());
            drop(fork_signal_locks);
            if let Some(lease) = fork_epoch_lease.take() {
                lease.finish_unchanged();
            }
            drop(alias_exclusion.take());
            drop(fork_guard.take());
            return Step::Fault(format!(
                "native host fork failed to block transport signals: {error}"
            ));
        }
    };
    // SAFETY: a plain process fork. Ordinary forks inherit guest mappings CoW;
    // CLONE_VFORK mappings were temporarily marked INHERIT_SHARE above.
    let pid = unsafe { libc::fork() };
    let fork_error = (pid < 0).then(std::io::Error::last_os_error);
    if pid == 0 {
        if let Some(lease) = host_fork_lease.take() {
            lease.abandon_after_fork_child();
        }
    } else if pid > 0 {
        // The host snapshot is complete. Release the exact sibling drain before
        // any other parent-side cleanup: Linux vfork suspends only its caller.
        // Stronger fork/alias/mapping/protection/executable guards remain held.
        drop(host_fork_lease.take());
    }
    // The parent (including fork failure) restores its exact prior host mask.
    // The child deliberately keeps Carrick transport blocked until every
    // post-fork pending-state reset has completed.
    if pid != 0 {
        restore_native_host_signal_mask(&previous_host_mask);
    }
    drop(fork_signal_locks);
    // Reverse helper nesting before any child-side provider/timer hook.
    drop(rlimit_cpu_fork_guard);
    drop(network_fork_guard);

    if pid == 0 {
        // The child must discard every inherited parent-side snapshot before
        // any dispatcher, signal, timer, pid-record, or accounting hook.
        drop(fork_protections_guard.take());
        drop(fork_mapping_guard.take());
        drop(alias_exclusion.take());
    }

    if pid < 0 {
        let restore_error = vfork_share.as_ref().and_then(|state| {
            state
                .restore_parent_inheritance(&shared.executable_epoch)
                .err()
        });
        if restore_error.is_some() {
            shared
                .executable_epoch
                .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
        }
        if let Some(state) = &vfork_share {
            unsafe {
                libc::close(state.pipe[0]);
                libc::close(state.pipe[1]);
            }
        }
        if let Some([read_fd, write_fd]) = pidfd_gate {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
        }
        // Keep serialization until the process-global pending-record stash is
        // cleared. Dropping the guard first lets a sibling prepare its record,
        // which this failure path would then abort instead of our own.
        crate::guest_cpu::abort_prepared_child_record();
        // Restoration was checked while alias/mapping/protection/mutation and
        // the exact sibling stop were all still retained. Release only now.
        drop(fork_protections_guard.take());
        drop(fork_mapping_guard.take());
        if let Some(lease) = fork_epoch_lease.take() {
            lease.finish_unchanged();
        }
        drop(alias_exclusion.take());
        drop(host_fork_lease.take());
        drop(fork_guard.take());
        if let Some(error) = restore_error {
            return Step::Fault(format!(
                "native vfork fork-failure restoration failed permanently: {error}"
            ));
        }
        let errno = fork_error
            .and_then(|error| error.raw_os_error())
            .unwrap_or(libc::EAGAIN);
        snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
        return Step::Continue(resume);
    }
    if pid == 0 {
        // The inherited coordinator must never be locked or dropped in the
        // single-threaded child. Its exact registration and reservation are
        // abandoned before any child dispatcher hook; the run loop binds a
        // fresh coordinator immediately after this service step returns.
        executable_registration.abandon_inherited_after_fork();
        if let Some(lease) = fork_epoch_lease.take() {
            // The inherited coordinator mutex may have been owned by a vanished
            // sibling at the instant of fork. Do not run Drop in the child; the
            // old address space and Arc are abandoned when the fresh run binds.
            std::mem::forget(lease);
        }
        memory.abandon_inherited_epoch_after_fork();
    } else if vfork_share.is_none()
        && let Some(lease) = fork_epoch_lease.take()
    {
        lease.finish_unchanged();
    }
    // The process-global child-record serializer remains retained through all
    // parent-output publication and gate release. Otherwise another forker can
    // replace the pending-record stash before a post-fork failure aborts this
    // exact child. A vfork parent retains it across the INHERIT_SHARE window too.
    if pid == 0 {
        drop(fork_guard.take());
        // The child must discard the parent's host/native CPU accounting cache
        // before completing its prepared record or rearming RLIMIT_CPU later in
        // the rebuilt run. Otherwise child usage is charged from stale parent
        // baselines.
        crate::guest_cpu::reset();
        // Child: complete the record inherited from the serialized pre-fork
        // preparation before it can fork children or expose process identity.
        crate::guest_cpu::complete_child_record_post_fork_child();
        if let Some([read_fd, write_fd]) = pidfd_gate {
            unsafe { libc::close(write_fd) };
            let mut release = 0u8;
            let mut rc;
            loop {
                rc = unsafe {
                    libc::read(read_fd, (&mut release as *mut u8).cast::<libc::c_void>(), 1)
                };
                if rc >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            unsafe { libc::close(read_fd) };
            if rc != 1 || release != 1 {
                unsafe { libc::_exit(127) };
            }
        }
        snapshot.gpr[reg::RAX] = 0;
        if request.child_stack != 0 {
            snapshot.gpr[reg::RSP] = request.child_stack;
        }
        if let Some(addr) = request.child_tid_addr {
            let cpid = crate::namespace::pid::self_ns_pid();
            if memory.write_bytes(addr, &cpid.to_le_bytes()).is_err() {
                // The child-side output cannot be reported back through the
                // parent's clone return. Fail this child loudly rather than run
                // with a silently missing CHILD_SETTID publication.
                unsafe { libc::_exit(127) };
            }
        }
        let vfork_completion_fd = vfork_share.as_ref().map(|state| {
            unsafe { libc::close(state.pipe[0]) };
            state.pipe[1]
        });
        Step::BecameForkChild {
            resume,
            vfork_completion_fd,
        }
    } else {
        if let Some(state) = &vfork_share {
            unsafe { libc::close(state.pipe[1]) };
        }
        if let Some([read_fd, _]) = pidfd_gate {
            unsafe { libc::close(read_fd) };
        }
        let installed_pidfd = if request.pidfd_out.is_some() {
            match dispatcher.install_child_pidfd(pid) {
                Ok(fd) => Some(fd),
                Err(errno) => {
                    // The child is still behind the private gate. Remove it and
                    // the unpublished process record so clone fails atomically.
                    kill_and_reap_native_fork_child(pid);
                    if let Some([_, write_fd]) = pidfd_gate {
                        unsafe { libc::close(write_fd) };
                    }
                    crate::guest_cpu::abort_prepared_child_record();
                    let restore_error = vfork_share.as_ref().and_then(|state| {
                        unsafe { libc::close(state.pipe[0]) };
                        state
                            .restore_parent_inheritance(&shared.executable_epoch)
                            .err()
                    });
                    if restore_error.is_some() {
                        shared
                            .executable_epoch
                            .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
                    }
                    // PIDFD failure restoration is checked before releasing any
                    // mapping/executable/sibling snapshot authority.
                    drop(fork_protections_guard.take());
                    drop(fork_mapping_guard.take());
                    if let Some(lease) = fork_epoch_lease.take() {
                        lease.finish_unchanged();
                    }
                    drop(alias_exclusion.take());
                    drop(host_fork_lease.take());
                    drop(fork_guard.take());
                    if let Some(error) = restore_error {
                        return Step::Fault(format!(
                            "native vfork pidfd-failure restoration failed permanently: {error}"
                        ));
                    }
                    snapshot.gpr[reg::RAX] = errno.guest_retval() as u64;
                    return Step::Continue(resume);
                }
            }
        } else {
            None
        };

        let guest_pid = child_ns_pid.unwrap_or(pid as u32);
        let parent_output_result = (|| -> Result<(), String> {
            if let (Some(addr), Some(pidfd)) = (request.pidfd_out, installed_pidfd) {
                identity_write_prevalidated_unlocked(addr, &pidfd.to_le_bytes())
                    .map_err(|error| format!("CLONE_PIDFD output failed after fork: {error}"))?;
            }
            if let Some(addr) = request.parent_tid_addr {
                identity_write_prevalidated_unlocked(addr, &guest_pid.to_le_bytes())
                    .map_err(|error| format!("PARENT_SETTID output failed after fork: {error}"))?;
            }
            if let Some([_, write_fd]) = pidfd_gate {
                release_native_fork_gate(write_fd)
                    .map_err(|error| format!("parent-output gate release failed: {error}"))?;
            }
            Ok(())
        })();
        if let Err(detail) = parent_output_result {
            // No output-gated child may survive an ambiguous post-fork parent
            // publication. Kill/reap before closing the gate, remove the exact
            // freshly-installed pidfd, and keep every snapshot retained until
            // vfork inheritance restoration has been checked.
            kill_and_reap_native_fork_child(pid);
            if let Some([_, write_fd]) = pidfd_gate {
                unsafe { libc::close(write_fd) };
            }
            if let Some(pidfd) = installed_pidfd
                && !dispatcher.remove_installed_child_pidfd(pidfd, pid)
            {
                std::process::abort();
            }
            crate::guest_cpu::abort_prepared_child_record();
            let restore_error = vfork_share.as_ref().and_then(|state| {
                unsafe { libc::close(state.pipe[0]) };
                state
                    .restore_parent_inheritance(&shared.executable_epoch)
                    .err()
            });
            if restore_error.is_some() {
                shared
                    .executable_epoch
                    .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
            }
            drop(fork_protections_guard.take());
            drop(fork_mapping_guard.take());
            if let Some(lease) = fork_epoch_lease.take() {
                lease.finish_unchanged();
            }
            drop(alias_exclusion.take());
            drop(host_fork_lease.take());
            drop(fork_guard.take());
            if let Some(error) = restore_error {
                return Step::Fault(format!(
                    "native vfork parent-output failure restoration failed permanently: {error}; {detail}"
                ));
            }
            return Step::Fault(detail);
        }
        if let Some([_, write_fd]) = pidfd_gate {
            unsafe { libc::close(write_fd) };
        }

        // Publish by exact prepared-record reference only after pidfd install,
        // checked outputs, and explicit gate delivery all succeeded.
        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, pid as u32);
        crate::namespace::pid::notify_child_registered();
        crate::host_signal::register_child_exit_watch(
            pid,
            request.parent_tid,
            i32::try_from(request.exit_signal).unwrap_or(0),
        );
        snapshot.gpr[reg::RAX] = u64::from(guest_pid);
        if let Some(state) = &vfork_share {
            shared.exit.begin_vfork_wait();
            // The exact host-fork stop was released immediately after fork, so
            // unrelated siblings run. This pipe wait is lock-free from the
            // snapshot's perspective and may advertise HostWaitSafe: a second
            // forker can drain it, but NativeForkGuard prevents another actual
            // fork until restoration. Terminal exec reserves its owner first,
            // wakes this wait, then waits for the retained mutation to release.
            let completed = match with_host_wait_safe(
                &shared.executable_epoch,
                executable_registration,
                |_| wait_native_vfork_completion(state.pipe[0], &shared.exit),
            ) {
                Ok(completed) => completed,
                Err(error) => {
                    shared.exit.end_vfork_wait();
                    kill_and_reap_native_fork_child(pid);
                    unsafe { libc::close(state.pipe[0]) };
                    let restore_error = state
                        .restore_parent_inheritance(&shared.executable_epoch)
                        .err();
                    drop(fork_protections_guard.take());
                    drop(fork_mapping_guard.take());
                    drop(fork_epoch_lease.take());
                    drop(alias_exclusion.take());
                    drop(fork_guard.take());
                    if let Some(restore_error) = restore_error {
                        return Step::Fault(format!(
                            "native vfork wait failed ({error:?}) and inheritance restoration failed permanently: {restore_error}"
                        ));
                    }
                    return Step::Fault(format!(
                        "native vfork parent wait boundary failed: {error:?}"
                    ));
                }
            };
            shared.exit.end_vfork_wait();
            unsafe { libc::close(state.pipe[0]) };
            let restore_error = state
                .restore_parent_inheritance(&shared.executable_epoch)
                .err();
            if restore_error.is_some() {
                shared
                    .executable_epoch
                    .fail_permanently(ExecutableEpochError::VforkInheritanceRestoreFailed);
            }
            // Restore is checked while all exact exclusions remain retained;
            // only afterward may siblings resume or mapping writers proceed.
            drop(fork_protections_guard.take());
            drop(fork_mapping_guard.take());
            drop(fork_epoch_lease.take());
            drop(alias_exclusion.take());
            drop(host_fork_lease.take());
            drop(fork_guard.take());
            if let Some(error) = restore_error {
                return Step::Fault(format!(
                    "native vfork post-child restoration failed permanently: {error}"
                ));
            }
            if !completed {
                return Step::RetiredForExec;
            }
        } else {
            // Ordinary fork also released the exact sibling drain immediately
            // after the host snapshot. Retain only the stronger publication and
            // mapping exclusions through checked outputs and record publication.
            drop(fork_protections_guard.take());
            drop(fork_mapping_guard.take());
            drop(alias_exclusion.take());
            drop(host_fork_lease.take());
            drop(fork_guard.take());
        }
        // Close the fast-child race for ungated forks and publish any child that
        // exited immediately after the pidfd gate opened. WNOWAIT leaves the
        // zombie for the guest's wait syscall.
        drain_native_child_exit_watches(true);
        Step::Continue(resume)
    }
}

/// Install a file-backed or high-VA anonymous mmap at guest VA `va` (== host
/// VA). A `Some((fd, offset, prot))` maps the file `MAP_SHARED|MAP_FIXED` over
/// the reserved arena (guest writes hit the page cache, coherent across fork);
/// otherwise the arena is already RW-backed and the `payload` snapshot is
/// copied in. `prot_none` then makes the range guest-inaccessible.
#[allow(clippy::too_many_arguments)]
fn service_map_host_alias(
    dispatcher: &SyscallDispatcher,
    transaction: crate::dispatch::HostAliasTransaction,
    va: u64,
    len: u64,
    payload: &[u8],
    file: Option<(HostAliasOwnedFd, libc::off_t, libc::c_int)>,
    shared: bool,
    prot: u64,
    _prot_none: bool,
    snapshot: &mut X86UcontextSnapshot,
    memory: &mut IdentityGuestMemory,
    resume: u64,
) -> Step {
    let file = file.map(|(fd, offset, prot)| (fd.into_owned_fd(), offset, prot));
    let Ok(len_usize) = usize::try_from(len) else {
        snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
        return Step::Continue(resume);
    };
    if payload.len() > len_usize {
        snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
        return Step::Continue(resume);
    }
    let requested_executable = prot & crate::linux_abi::LINUX_PROT_EXEC != 0;
    let (_mutation, mapping_guard) =
        match memory.mapping_write_for_mutation(va, len_usize, requested_executable) {
            Ok(guards) => guards,
            Err(_) => {
                snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
                return Step::Continue(resume);
            }
        };
    let readable =
        prot & (crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC) != 0;
    let writable = prot & crate::linux_abi::LINUX_PROT_WRITE != 0;
    let host_prot = match (readable, writable) {
        (_, true) => libc::PROT_READ | libc::PROT_WRITE,
        (true, false) => libc::PROT_READ,
        (false, false) => libc::PROT_NONE,
    };
    // Inject protection failure before MAP_FIXED replaces an existing host VMA;
    // this test-only preflight proves dispatcher/runtime rollback against the
    // real prior mapping rather than manufacturing a post-replacement hole.
    #[cfg(test)]
    if take_injected_mprotect_failure(NativeMappingOperation::HostAlias) {
        snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
        return Step::Continue(resume);
    }
    // All recoverable validation/quiescence work is complete. From this claim
    // onward every failure is either a proven no-mutation mmap refusal or
    // fail-stop: no path resumes the guest after ambiguous replacement state.
    let Some(install) = transaction.claim() else {
        snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
        return Step::Continue(resume);
    };
    let bus_fault = match install.bus_fault_range() {
        Some((bus_start, bus_len)) => {
            let Ok(bus_len) = usize::try_from(bus_len) else {
                std::process::abort();
            };
            Some((bus_start, bus_len))
        }
        None => None,
    };
    let prior_protections = IDENTITY_PROTECTIONS.snapshot_mapping_range(va, len_usize);
    let p = if let Some((fd, offset, host_prot)) = file.as_ref() {
        host_mmap(
            NativeMappingOperation::HostAlias,
            va as *mut libc::c_void,
            len_usize,
            *host_prot,
            libc::MAP_SHARED | libc::MAP_FIXED,
            fd.as_raw_fd(),
            *offset,
        )
    } else {
        let flags = libc::MAP_FIXED
            | libc::MAP_ANON
            | if shared {
                libc::MAP_SHARED
            } else {
                libc::MAP_PRIVATE
            };
        host_mmap(
            NativeMappingOperation::HostAlias,
            va as *mut libc::c_void,
            len_usize,
            if payload.is_empty() {
                host_prot
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            },
            flags,
            -1,
            0,
        )
    };
    if p as u64 != va {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOMEM);
        if p != libc::MAP_FAILED && host_munmap(p, len_usize) != 0 && host_munmap(p, len_usize) != 0
        {
            std::process::abort();
        }
        IDENTITY_PROTECTIONS.restore_mapping_range(prior_protections);
        snapshot.gpr[reg::RAX] = (-(i64::from(errno))) as u64;
        return Step::Continue(resume);
    }
    IDENTITY_PROTECTIONS.set_unmapped(va, len_usize, false);
    if !payload.is_empty() && identity_write_bytes_raw_unlocked(va, payload).is_err() {
        if host_munmap(va as *mut libc::c_void, len_usize) != 0
            && host_munmap(va as *mut libc::c_void, len_usize) != 0
        {
            std::process::abort();
        }
        IDENTITY_PROTECTIONS.restore_mapping_range(prior_protections);
        std::process::abort();
    }
    // Finish the host permission + metadata transition while the alias writer
    // is still held. The subsequent protect_range call also publishes execute
    // eligibility/generation, but no signal/syscall copy may observe an old
    // host mapping under newly-writable metadata in between these phases.
    if !payload.is_empty()
        && host_mprotect(
            NativeMappingOperation::HostAlias,
            va as *mut libc::c_void,
            len_usize,
            host_prot,
        ) != 0
    {
        if host_munmap(va as *mut libc::c_void, len_usize) != 0
            && host_munmap(va as *mut libc::c_void, len_usize) != 0
        {
            std::process::abort();
        }
        IDENTITY_PROTECTIONS.restore_mapping_range(prior_protections);
        std::process::abort();
    }
    // Publish every live vnode alias as mutable shared backing. `file` is only
    // populated for MAP_SHARED; MAP_PRIVATE file mappings and ELF payloads
    // arrive as `payload` and were materialized into the anonymous mapping
    // above. Typed instruction fetch relies on this classification to exclude
    // externally truncatable backing from its direct-copy fast path.
    IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
        va,
        len_usize,
        prot == 0,
        !writable,
        if shared {
            carrick_guest_mem::MappingSharing::Shared
        } else {
            carrick_guest_mem::MappingSharing::Private
        },
    );
    IDENTITY_PROTECTIONS.set_executable(va, len_usize, requested_executable);

    if let Some((bus_start, bus_len)) = bus_fault {
        if host_mprotect(
            NativeMappingOperation::HostAlias,
            bus_start as *mut libc::c_void,
            bus_len,
            libc::PROT_NONE,
        ) != 0
        {
            if host_munmap(va as *mut libc::c_void, len_usize) != 0
                && host_munmap(va as *mut libc::c_void, len_usize) != 0
            {
                std::process::abort();
            }
            IDENTITY_PROTECTIONS.restore_mapping_range(prior_protections);
            std::process::abort();
        }
        IDENTITY_PROTECTIONS.set_no_access(bus_start, bus_len, true);
        IDENTITY_PROTECTIONS.set_bus_fault(bus_start, bus_len, true);
    }

    if dispatcher.commit_host_alias_install(install).is_err() {
        if host_munmap(va as *mut libc::c_void, len_usize) != 0
            && host_munmap(va as *mut libc::c_void, len_usize) != 0
        {
            std::process::abort();
        }
        IDENTITY_PROTECTIONS.restore_mapping_range(prior_protections);
        std::process::abort();
    }
    drop(mapping_guard);
    snapshot.gpr[reg::RAX] = va;
    Step::Continue(resume)
}

/// Service `arch_prctl(code, addr)`: SET_FS installs the guest thread pointer
/// into the gateway's `guest_fsbase`; SET_GS is refused (no gs virtualization
/// yet); GET_FS/GET_GS write the current base to `*addr`.
fn service_arch_prctl(
    code: u64,
    addr: u64,
    _snapshot: &mut X86UcontextSnapshot,
    guest_fsbase: &mut u64,
    memory: &mut IdentityGuestMemory,
) -> i64 {
    match code {
        ARCH_SET_FS => {
            *guest_fsbase = addr;
            0
        }
        ARCH_GET_FS => {
            if memory
                .write_bytes(addr, &guest_fsbase.to_le_bytes())
                .is_err()
            {
                return -14; // EFAULT
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => NEG_EINVAL,
        _ => NEG_EINVAL,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeCpuidRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn virtualize_native_cpuid(
    leaf: u32,
    subleaf: u32,
    mut registers: NativeCpuidRegisters,
    xstate: Option<carrick_dsr_x86::X86SnapshotXstateLayout>,
) -> Result<NativeCpuidRegisters, carrick_dsr_x86::X86SnapshotXstateError> {
    if leaf == 7 && subleaf == 0 {
        registers.ebx &= !(1 << 14); // MPX
        // Carrick models exact non-REX FCS/FDS state independently of the host,
        // so expose the non-deprecated selector contract on every native host.
        registers.ebx &= !(1 << 13);
        registers.ecx &= !((1 << 3) | (1 << 4) | (1 << 7)); // PKU/OSPKE, CET_SS
        registers.edx &= !((1 << 22) | (1 << 24) | (1 << 25)); // AMX
    } else if leaf == 7 && subleaf == 1 {
        registers.eax &= !(1 << 21); // AMX-FP16
        registers.edx &= !((1 << 8) | (1 << 18)); // AMX-COMPLEX, CET_SSS
    }

    if leaf != 0x0d {
        return Ok(registers);
    }
    let Some(layout) = xstate else {
        return Ok(NativeCpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        });
    };
    let xstate = layout.capabilities();
    let virtualized = match subleaf {
        0 => NativeCpuidRegisters {
            eax: xstate.supported_features as u32,
            ebx: xstate.standard_size,
            ecx: xstate.standard_size,
            edx: (xstate.supported_features >> 32) as u32,
        },
        1 => NativeCpuidRegisters {
            // Checked emulation makes XSAVEOPT/XSAVEC independent of physical
            // host support. XGETBV(1), XSAVES/XRSTORS, and IA32_XSS stay hidden.
            eax: 0b11,
            ebx: layout.compacted_size_for(xstate.supported_features)?,
            ecx: 0,
            edx: 0,
        },
        component if component < 64 && xstate.supported_features & (1u64 << component) != 0 => {
            let metadata = xstate.components[component as usize];
            NativeCpuidRegisters {
                eax: metadata.size,
                ebx: metadata.offset,
                ecx: if layout.compacted_align64_features() & (1u64 << component) != 0 {
                    1 << 1
                } else {
                    0
                },
                edx: 0,
            }
        }
        _ => NativeCpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
    };
    Ok(virtualized)
}

#[derive(Debug, PartialEq, Eq)]
enum X86XstateServiceError {
    Signal {
        signum: i32,
        code: i32,
        address: u64,
    },
    Fatal(String),
}

fn xstate_decode_runtime_error(
    va: u64,
    error: X86XstateRestoreError<std::convert::Infallible>,
) -> X86XstateServiceError {
    match error {
        X86XstateRestoreError::GeneralProtection(_) | X86XstateRestoreError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86XstateRestoreError::Read(never) => match never {},
        X86XstateRestoreError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 XRSTOR decode at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn xstate_emulation_runtime_error(
    va: u64,
    error: X86XstateRestoreError<IdentityCheckedReadError>,
) -> X86XstateServiceError {
    match error {
        X86XstateRestoreError::GeneralProtection(_) | X86XstateRestoreError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86XstateRestoreError::Read(IdentityCheckedReadError::Fault(fault)) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code,
                address: fault.address.raw(),
            }
        }
        X86XstateRestoreError::Read(IdentityCheckedReadError::BusAddress { address }) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGBUS,
                code: crate::linux_abi::LINUX_BUS_ADRERR,
                address: address.raw(),
            }
        }
        X86XstateRestoreError::Read(IdentityCheckedReadError::Backend { address, detail }) => {
            X86XstateServiceError::Fatal(format!(
                "native x86 XRSTOR checked read at 0x{:x} while servicing 0x{va:x} failed internally: {detail}",
                address.raw()
            ))
        }
        X86XstateRestoreError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 XRSTOR emulation at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn xstate_save_decode_runtime_error(
    va: u64,
    error: X86XstateSaveError<std::convert::Infallible, std::convert::Infallible>,
) -> X86XstateServiceError {
    match error {
        X86XstateSaveError::GeneralProtection(_) | X86XstateSaveError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86XstateSaveError::Read(never) => match never {},
        X86XstateSaveError::Write(never) => match never {},
        X86XstateSaveError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 XSAVE decode at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn xstate_save_emulation_runtime_error(
    va: u64,
    error: X86XstateSaveError<IdentityCheckedReadError, IdentityCheckedWriteError>,
) -> X86XstateServiceError {
    match error {
        X86XstateSaveError::GeneralProtection(_) | X86XstateSaveError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86XstateSaveError::Read(IdentityCheckedReadError::Fault(fault)) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code,
                address: fault.address.raw(),
            }
        }
        X86XstateSaveError::Read(IdentityCheckedReadError::BusAddress { address }) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGBUS,
                code: crate::linux_abi::LINUX_BUS_ADRERR,
                address: address.raw(),
            }
        }
        X86XstateSaveError::Read(IdentityCheckedReadError::Backend { address, detail }) => {
            X86XstateServiceError::Fatal(format!(
                "native x86 XSAVE checked read at 0x{:x} while servicing 0x{va:x} failed internally: {detail}",
                address.raw()
            ))
        }
        X86XstateSaveError::Write(IdentityCheckedWriteError::Fault(fault)) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code,
                address: fault.address.raw(),
            }
        }
        X86XstateSaveError::Write(IdentityCheckedWriteError::BusAddress { address }) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGBUS,
                code: crate::linux_abi::LINUX_BUS_ADRERR,
                address: address.raw(),
            }
        }
        X86XstateSaveError::Write(IdentityCheckedWriteError::Backend { address, detail }) => {
            X86XstateServiceError::Fatal(format!(
                "native x86 XSAVE checked write at 0x{:x} while servicing 0x{va:x} failed internally: {detail}",
                address.raw()
            ))
        }
        X86XstateSaveError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 XSAVE emulation at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn service_xstate_save(
    va: u64,
    kind: carrick_dsr_x86::decode::X86XstateSaveKind,
    bytes: &[u8],
    guest_fsbase: u64,
    snapshot: &X86UcontextSnapshot,
    memory: &IdentityGuestMemory,
) -> Result<u64, X86XstateServiceError> {
    let plan = X86XstateSavePlan::decode_for_kind(
        kind,
        bytes,
        snapshot,
        guest_fsbase,
        X86GuestGsBase::Zero,
    )
    .map_err(|error| xstate_save_decode_runtime_error(va, error))?;
    let layout = carrick_dsr_x86::signal_xstate_layout().map_err(|error| {
        X86XstateServiceError::Fatal(format!(
            "native x86 XSAVE xstate layout at 0x{va:x} is unavailable: {error}"
        ))
    })?;
    let mut reader = IdentityXstateMemoryReader;
    let mut writer = IdentityXstateMemoryWriter { memory };
    snapshot
        .emulate_xsave_with_memory(plan, &layout, &mut reader, &mut writer)
        .map_err(|error| xstate_save_emulation_runtime_error(va, error))?;
    va.checked_add(u64::from(plan.instruction_len()))
        .ok_or_else(|| {
            X86XstateServiceError::Fatal(format!("native x86 XSAVE resume overflow at 0x{va:x}"))
        })
}

fn service_xstate_restore(
    va: u64,
    bytes: &[u8],
    guest_fsbase: u64,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<u64, X86XstateServiceError> {
    let plan = X86XstateRestorePlan::decode(bytes, snapshot, guest_fsbase, X86GuestGsBase::Zero)
        .map_err(|error| xstate_decode_runtime_error(va, error))?;
    let layout = carrick_dsr_x86::signal_xstate_layout().map_err(|error| {
        X86XstateServiceError::Fatal(format!(
            "native x86 XRSTOR xstate layout at 0x{va:x} is unavailable: {error}"
        ))
    })?;
    let mut reader = IdentityXstateMemoryReader;
    snapshot
        .emulate_xrstor_with_reader(plan, &layout, &mut reader)
        .map_err(|error| xstate_emulation_runtime_error(va, error))?;
    va.checked_add(u64::from(plan.instruction_len()))
        .ok_or_else(|| {
            X86XstateServiceError::Fatal(format!("native x86 XRSTOR resume overflow at 0x{va:x}"))
        })
}

fn checked_read_state_transfer_error(
    va: u64,
    family: &str,
    error: IdentityCheckedReadError,
) -> X86XstateServiceError {
    match error {
        IdentityCheckedReadError::Fault(fault) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code,
                address: fault.address.raw(),
            }
        }
        IdentityCheckedReadError::BusAddress { address } => X86XstateServiceError::Signal {
            signum: crate::linux_abi::LINUX_SIGBUS,
            code: crate::linux_abi::LINUX_BUS_ADRERR,
            address: address.raw(),
        },
        IdentityCheckedReadError::Backend { address, detail } => {
            X86XstateServiceError::Fatal(format!(
                "native x86 {family} checked read at 0x{:x} while servicing 0x{va:x} failed internally: {detail}",
                address.raw()
            ))
        }
    }
}

fn checked_write_state_transfer_error(
    va: u64,
    family: &str,
    error: IdentityCheckedWriteError,
) -> X86XstateServiceError {
    match error {
        IdentityCheckedWriteError::Fault(fault) => {
            let code = match fault.kind {
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped => {
                    crate::linux_abi::LINUX_SEGV_MAPERR
                }
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied => {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                }
            };
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code,
                address: fault.address.raw(),
            }
        }
        IdentityCheckedWriteError::BusAddress { address } => X86XstateServiceError::Signal {
            signum: crate::linux_abi::LINUX_SIGBUS,
            code: crate::linux_abi::LINUX_BUS_ADRERR,
            address: address.raw(),
        },
        IdentityCheckedWriteError::Backend { address, detail } => {
            X86XstateServiceError::Fatal(format!(
                "native x86 {family} checked write at 0x{:x} while servicing 0x{va:x} failed internally: {detail}",
                address.raw()
            ))
        }
    }
}

fn fxstate_decode_error(
    va: u64,
    error: X86FxStateError<Infallible, Infallible>,
) -> X86XstateServiceError {
    match error {
        X86FxStateError::GeneralProtection(_) | X86FxStateError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86FxStateError::Read(never) | X86FxStateError::Write(never) => match never {},
        X86FxStateError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 FXSAVE-family decode at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn fxstate_save_emulation_error(
    va: u64,
    error: X86FxStateError<Infallible, IdentityCheckedWriteError>,
) -> X86XstateServiceError {
    match error {
        X86FxStateError::GeneralProtection(_) | X86FxStateError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86FxStateError::Read(never) => match never {},
        X86FxStateError::Write(error) => checked_write_state_transfer_error(va, "FXSAVE", error),
        X86FxStateError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 FXSAVE emulation at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn fxstate_restore_emulation_error(
    va: u64,
    error: X86FxStateError<IdentityCheckedReadError, Infallible>,
) -> X86XstateServiceError {
    match error {
        X86FxStateError::GeneralProtection(_) | X86FxStateError::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86FxStateError::Read(error) => checked_read_state_transfer_error(va, "FXRSTOR", error),
        X86FxStateError::Write(never) => match never {},
        X86FxStateError::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 FXRSTOR emulation at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn x87_exception_signal_code(exception: X86X87ExceptionKind) -> i32 {
    match exception {
        X86X87ExceptionKind::Invalid => 7,      // FPE_FLTINV
        X86X87ExceptionKind::Denormal => 5,     // FPE_FLTUND
        X86X87ExceptionKind::DivideByZero => 3, // FPE_FLTDIV
        X86X87ExceptionKind::Overflow => 4,     // FPE_FLTOVF
        X86X87ExceptionKind::Underflow => 5,    // FPE_FLTUND
        X86X87ExceptionKind::Precision => 6,    // FPE_FLTRES
    }
}

fn legacy_x87_pending_signal(va: u64, exception: X86X87ExceptionKind) -> X86XstateServiceError {
    X86XstateServiceError::Signal {
        signum: crate::linux_abi::LINUX_SIGFPE,
        code: x87_exception_signal_code(exception),
        address: va,
    }
}

fn legacy_x87_decode_error(
    va: u64,
    error: X86LegacyX87Error<Infallible, Infallible>,
) -> X86XstateServiceError {
    match error {
        X86LegacyX87Error::GeneralProtection(_) | X86LegacyX87Error::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86LegacyX87Error::PendingException(exception) => legacy_x87_pending_signal(va, exception),
        X86LegacyX87Error::Read(never) | X86LegacyX87Error::Write(never) => match never {},
        X86LegacyX87Error::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 legacy x87 decode at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn legacy_x87_save_emulation_error(
    va: u64,
    error: X86LegacyX87Error<Infallible, IdentityCheckedWriteError>,
) -> X86XstateServiceError {
    match error {
        X86LegacyX87Error::GeneralProtection(_) | X86LegacyX87Error::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86LegacyX87Error::PendingException(exception) => legacy_x87_pending_signal(va, exception),
        X86LegacyX87Error::Read(never) => match never {},
        X86LegacyX87Error::Write(error) => {
            checked_write_state_transfer_error(va, "legacy x87", error)
        }
        X86LegacyX87Error::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 legacy x87 save at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn legacy_x87_restore_emulation_error(
    va: u64,
    error: X86LegacyX87Error<IdentityCheckedReadError, Infallible>,
) -> X86XstateServiceError {
    match error {
        X86LegacyX87Error::GeneralProtection(_) | X86LegacyX87Error::StackSegment(_) => {
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        }
        X86LegacyX87Error::PendingException(exception) => legacy_x87_pending_signal(va, exception),
        X86LegacyX87Error::Read(error) => {
            checked_read_state_transfer_error(va, "legacy x87", error)
        }
        X86LegacyX87Error::Write(never) => match never {},
        X86LegacyX87Error::Internal(reason) => X86XstateServiceError::Fatal(format!(
            "native x86 legacy x87 restore at 0x{va:x} failed internally: {reason}"
        )),
    }
}

fn service_legacy_state_transfer(
    va: u64,
    kind: carrick_dsr_x86::decode::X86SensitiveKind,
    bytes: &[u8],
    guest_fsbase: u64,
    snapshot: &mut X86UcontextSnapshot,
    memory: &IdentityGuestMemory,
) -> Result<u64, X86XstateServiceError> {
    match kind {
        carrick_dsr_x86::decode::X86SensitiveKind::FxState(fx_kind) => {
            let plan = X86FxStatePlan::decode_for_kind(
                fx_kind,
                bytes,
                snapshot,
                guest_fsbase,
                X86GuestGsBase::Zero,
            )
            .map_err(|error| fxstate_decode_error(va, error))?;
            let mxcsr_mask = carrick_dsr_x86::signal_xstate_layout()
                .map_err(|error| {
                    X86XstateServiceError::Fatal(format!(
                        "native x86 FXSAVE-family xstate layout at 0x{va:x} is unavailable: {error}"
                    ))
                })?
                .capabilities()
                .mxcsr_mask;
            if fx_kind.is_save() {
                let mut writer = IdentityXstateMemoryWriter { memory };
                snapshot
                    .emulate_fxsave_with_writer(plan, mxcsr_mask, &mut writer)
                    .map_err(|error| fxstate_save_emulation_error(va, error))?;
            } else {
                let mut reader = IdentityXstateMemoryReader;
                snapshot
                    .emulate_fxrstor_with_reader(plan, mxcsr_mask, &mut reader)
                    .map_err(|error| fxstate_restore_emulation_error(va, error))?;
            }
            va.checked_add(u64::from(plan.instruction_len()))
        }
        carrick_dsr_x86::decode::X86SensitiveKind::LegacyX87(legacy_kind) => {
            let plan = X86LegacyX87Plan::decode_for_kind(
                legacy_kind,
                bytes,
                snapshot,
                guest_fsbase,
                X86GuestGsBase::Zero,
            )
            .map_err(|error| legacy_x87_decode_error(va, error))?;
            if legacy_kind.is_save() {
                let mut writer = IdentityXstateMemoryWriter { memory };
                snapshot
                    .emulate_legacy_x87_save(plan, &mut writer)
                    .map_err(|error| legacy_x87_save_emulation_error(va, error))?;
            } else {
                let mut reader = IdentityXstateMemoryReader;
                snapshot
                    .emulate_legacy_x87_restore(plan, &mut reader)
                    .map_err(|error| legacy_x87_restore_emulation_error(va, error))?;
            }
            va.checked_add(u64::from(plan.instruction_len()))
        }
        other => {
            return Err(X86XstateServiceError::Fatal(format!(
                "native x86 non-state instruction {other:?} reached legacy transfer service"
            )));
        }
    }
    .ok_or_else(|| {
        X86XstateServiceError::Fatal(format!(
            "native x86 legacy state-transfer resume overflow at 0x{va:x}"
        ))
    })
}

#[derive(Debug, PartialEq, Eq)]
enum X86SensitiveServiceError {
    Signal {
        signum: i32,
        code: i32,
        address: u64,
    },
    Fatal(String),
}

/// Service a sensitive (non-syscall) exit. On a same-ISA native lane the guest
/// and host CPU are identical, so `rdtsc`/`rdtscp`/`cpuid` are HONEST host
/// passthrough — the guest sees the real CPU it is running on. Architecturally
/// invalid operands return a typed synchronous guest signal; missing Carrick
/// support remains a typed backend-fatal diagnostic.
fn service_sensitive(
    kind: carrick_dsr_x86::decode::X86SensitiveKind,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<(), X86SensitiveServiceError> {
    use carrick_dsr_x86::decode::X86SensitiveKind::*;
    match kind {
        Rdtsc { with_processor_id } => {
            let mut aux = 0u32;
            // SAFETY: rdtsc/rdtscp are unprivileged on x86_64.
            let tsc = unsafe {
                if with_processor_id {
                    core::arch::x86_64::__rdtscp(&mut aux)
                } else {
                    core::arch::x86_64::_rdtsc()
                }
            };
            snapshot.gpr[reg::RAX] = tsc & 0xffff_ffff;
            snapshot.gpr[reg::RDX] = tsc >> 32;
            if with_processor_id {
                snapshot.gpr[reg::RCX] = aux as u64;
            }
            Ok(())
        }
        Cpuid => {
            let leaf = snapshot.gpr[reg::RAX] as u32;
            let subleaf = snapshot.gpr[reg::RCX] as u32;
            // cpuid is unprivileged; the intrinsic is safe on x86_64 targets.
            let host = core::arch::x86_64::__cpuid_count(leaf, subleaf);
            let xstate = if leaf == 0x0d || (leaf == 7 && subleaf == 0) {
                Some(carrick_dsr_x86::signal_xstate_layout().map_err(|error| {
                    X86SensitiveServiceError::Fatal(format!(
                        "native x86 CPUID xstate unavailable: {error}"
                    ))
                })?)
            } else {
                None
            };
            let virtualized = virtualize_native_cpuid(
                leaf,
                subleaf,
                NativeCpuidRegisters {
                    eax: host.eax,
                    ebx: host.ebx,
                    ecx: host.ecx,
                    edx: host.edx,
                },
                xstate,
            )
            .map_err(|error| {
                X86SensitiveServiceError::Fatal(format!(
                    "native x86 CPUID xstate layout is invalid: {error}"
                ))
            })?;
            snapshot.gpr[reg::RAX] = u64::from(virtualized.eax);
            snapshot.gpr[reg::RBX] = u64::from(virtualized.ebx);
            snapshot.gpr[reg::RCX] = u64::from(virtualized.ecx);
            snapshot.gpr[reg::RDX] = u64::from(virtualized.edx);
            Ok(())
        }
        ExtendedControl => {
            let index = snapshot.gpr[reg::RCX] as u32;
            if index != 0 {
                return Err(X86SensitiveServiceError::Signal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    code: crate::linux_abi::LINUX_SI_KERNEL,
                    address: 0,
                });
            }
            let value = carrick_dsr_x86::signal_xstate_layout()
                .map_err(|error| {
                    X86SensitiveServiceError::Fatal(format!(
                        "native x86 XGETBV xstate unavailable: {error}"
                    ))
                })?
                .capabilities()
                .supported_features;
            snapshot.gpr[reg::RAX] = value & 0xffff_ffff;
            snapshot.gpr[reg::RDX] = value >> 32;
            Ok(())
        }
        ProtectionKey { write } => {
            if snapshot.gpr[reg::RCX] as u32 != 0 || (write && snapshot.gpr[reg::RDX] as u32 != 0) {
                return Err(X86SensitiveServiceError::Signal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    code: crate::linux_abi::LINUX_SI_KERNEL,
                    address: 0,
                });
            }
            if write {
                snapshot.apply_guest_pkru_write(snapshot.gpr[reg::RAX] as u32);
            } else {
                snapshot.gpr[reg::RAX] = u64::from(snapshot.pkru().raw());
                snapshot.gpr[reg::RDX] = 0;
            }
            Ok(())
        }
        // Guest CPUID and XCR0 expose no CET shadow-stack state. In that
        // disabled state RDSSPD/RDSSPQ preserve the complete destination
        // register and RFLAGS, so preserving this snapshot is the exact
        // architectural result for both widths.
        ReadShadowStackPointer => Ok(()),
        XstateSave(save_kind) => Err(X86SensitiveServiceError::Fatal(format!(
            "native x86 {save_kind:?} reached the memory-unaware service_sensitive path"
        ))),
        XstateRestore(restore_kind) => Err(X86SensitiveServiceError::Fatal(format!(
            "native x86 {restore_kind:?} reached the memory-unaware service_sensitive path"
        ))),
        FxState(fx_kind) => Err(X86SensitiveServiceError::Fatal(format!(
            "native x86 {fx_kind:?} reached the memory-unaware service_sensitive path"
        ))),
        LegacyX87(legacy_kind) => Err(X86SensitiveServiceError::Fatal(format!(
            "native x86 {legacy_kind:?} reached the memory-unaware service_sensitive path"
        ))),
        X87Wait => {
            if let Some(exception) = snapshot.x87_pending_exception() {
                Err(X86SensitiveServiceError::Signal {
                    signum: crate::linux_abi::LINUX_SIGFPE,
                    code: x87_exception_signal_code(exception),
                    address: snapshot.rip,
                })
            } else {
                Ok(())
            }
        }
        SegmentBase { .. } | SegmentPrefixed { .. } | Syscall | Int80 => {
            Err(X86SensitiveServiceError::Fatal(format!(
                "native x86 first-rung driver does not service sensitive {kind:?} yet"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NATIVE_MAPPING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(super) fn lock_native_mapping_tests() -> std::sync::MutexGuard<'static, ()> {
        NATIVE_MAPPING_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn readonly_parent_fork_outputs_fail_before_child_side_effect() {
        let _test_guard = lock_native_mapping_tests();
        let len = 8192usize;
        // SAFETY: private anonymous test mapping, released before return.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        // Make only the second page read-only so the pidfd output crosses the
        // permission boundary. PARENT_SETTID lives wholly inside that page.
        assert_eq!(
            unsafe { libc::mprotect(mapping.add(4096), 4096, libc::PROT_READ) },
            0
        );
        IDENTITY_PROTECTIONS.set_mapping_protection(address, 4096, false, false);
        IDENTITY_PROTECTIONS.set_mapping_protection(address + 4096, 4096, false, true);
        let memory = IdentityGuestMemory::uncoordinated();
        let mut child_side_effects = 0usize;
        for request in [
            NativeForkRequest {
                clone_parent: false,
                parent_tid_addr: None,
                child_tid_addr: None,
                child_stack: 0,
                pidfd_out: Some(address + 4094),
                parent_tid: 1,
                exit_signal: 0,
                vfork: None,
            },
            NativeForkRequest {
                clone_parent: false,
                parent_tid_addr: Some(address + 4096),
                child_tid_addr: None,
                child_stack: 0,
                pidfd_out: None,
                parent_tid: 1,
                exit_signal: 0,
                vfork: None,
            },
        ] {
            let result = validate_native_fork_parent_outputs(&memory, &request);
            if result.is_ok() {
                child_side_effects += 1;
            }
            assert_eq!(result, Err(crate::linux_abi::LINUX_EFAULT));
        }
        assert_eq!(child_side_effects, 0, "validation precedes child creation");

        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
    }

    #[test]
    fn clone_thread_tid_outputs_require_complete_writable_ranges() {
        let _test_guard = lock_native_mapping_tests();
        let len = 8192usize;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        assert_eq!(
            unsafe { libc::mprotect(mapping.add(4096), 4096, libc::PROT_READ) },
            0
        );
        IDENTITY_PROTECTIONS.set_mapping_protection(address, 4096, false, false);
        IDENTITY_PROTECTIONS.set_mapping_protection(address + 4096, 4096, false, true);
        let memory = IdentityGuestMemory::uncoordinated();

        assert_eq!(
            validate_clone_thread_tid_outputs(&memory, address + 4094, 0),
            Err(crate::linux_abi::LINUX_EFAULT),
            "cross-page parent TID output must validate all four bytes"
        );
        assert_eq!(
            validate_clone_thread_tid_outputs(&memory, 0, address + 4096),
            Err(crate::linux_abi::LINUX_EFAULT),
            "read-only child TID output must fail before task creation"
        );
        assert_eq!(
            validate_clone_thread_tid_outputs(&memory, u64::MAX - 1, 0),
            Err(crate::linux_abi::LINUX_EFAULT),
            "overflowing TID output must fail validation"
        );

        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
    }

    #[test]
    fn injected_clone_thread_spawn_failure_publishes_no_tid_bytes() {
        let _test_guard = lock_native_mapping_tests();
        FAIL_NEXT_NATIVE_CLONE_THREAD_SPAWN.with(|fail| fail.set(true));
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/clone-thread-tid-transaction-x86_64-linux"
        );

        let result = run_static_x86_elf(
            Path::new(fixture),
            SyscallDispatcher::new(),
            [fixture.to_string()],
            std::iter::empty::<String>(),
            10_000,
        )
        .expect("clone TID transaction fixture must complete");

        assert_eq!(
            result.exit_code,
            0,
            "spawn failure changed a TID word or exposed a child: {:?}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn injected_parent_gate_write_failure_keeps_child_blocked_and_reaps_it() {
        let _test_guard = lock_native_mapping_tests();
        let mut gate = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::close(gate[1]) };
            let mut byte = 0u8;
            let rc = unsafe { libc::read(gate[0], (&mut byte as *mut u8).cast(), 1) };
            unsafe { libc::_exit(if rc == 1 && byte == 1 { 91 } else { 92 }) };
        }

        unsafe { libc::close(gate[0]) };
        let _failure = NativeForkGateWriteFailureGuard::fail_next();
        let error = release_native_fork_gate(gate[1]).expect_err("inject gate write failure");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        kill_and_reap_native_fork_child(child);
        unsafe { libc::close(gate[1]) };
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "failed gate child was already reaped"
        );
    }

    #[test]
    fn signal_frame_on_read_only_stack_is_guest_fault_not_host_write() {
        let len = 16 * 1024usize;
        // SAFETY: private anonymous test mapping, released before return.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        // SAFETY: mapping above is live for `len` bytes.
        assert_eq!(unsafe { libc::mprotect(mapping, len, libc::PROT_READ) }, 0);
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, false, true);

        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.gpr[reg::RSP] = address + len as u64;
        let mut engine = SigframeEngine {
            snap: &mut snapshot,
            executable_epoch: None,
        };
        let result = X8664GuestArch::build_sigframe(
            &mut engine,
            carrick_hal::sigframe::InjectParams {
                signum: crate::linux_abi::LINUX_SIGUSR1,
                handler: 1,
                sa_restorer: 2,
                pending_syscall_retval: None,
                interrupted_pc: Some(3),
                altstack: None,
                saved_sigmask: 0,
                fault_siginfo: None,
                queued_siginfo: None,
                restart_syscall: false,
                pstate_source: 2,
                orig_x0: 0,
                fault_esr: 0,
                fpsimd_enabled: true,
                sigreturn_trampoline_base: 0,
            },
        );
        assert!(matches!(
            result,
            Err(carrick_hal::TrapError::SignalDeliveryFault)
        ));

        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        // SAFETY: mapping above is still live.
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
    }

    #[test]
    fn file_backed_signal_frame_bus_faults_are_guest_delivery_failures() {
        const LEN: usize = 64 * 1024;
        let file = tempfile::tempfile().expect("temporary signal-stack backing");
        file.set_len(LEN as u64).expect("size signal-stack backing");
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

        let params = || carrick_hal::sigframe::InjectParams {
            signum: crate::linux_abi::LINUX_SIGUSR1,
            handler: 1,
            sa_restorer: 2,
            pending_syscall_retval: None,
            interrupted_pc: Some(3),
            altstack: None,
            saved_sigmask: 0,
            fault_siginfo: None,
            queued_siginfo: None,
            restart_syscall: false,
            pstate_source: 2,
            orig_x0: 0,
            fault_esr: 0,
            fpsimd_enabled: true,
            sigreturn_trampoline_base: 0,
        };
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.gpr[reg::RSP] = address + LEN as u64;
        let built = {
            let mut engine = SigframeEngine {
                snap: &mut snapshot,
                executable_epoch: None,
            };
            X8664GuestArch::build_sigframe(&mut engine, params())
                .expect("build frame before truncating its backing")
        };

        file.set_len(4096)
            .expect("truncate live shared signal-stack mapping");
        snapshot.gpr[reg::RSP] = built.new_sp + 8;
        let restore = {
            let mut engine = SigframeEngine {
                snap: &mut snapshot,
                executable_epoch: None,
            };
            X8664GuestArch::restore_sigframe(&mut engine, true)
        };
        assert!(matches!(
            restore,
            Err(carrick_hal::TrapError::SignalDeliveryFault)
        ));
        assert_eq!(
            snapshot.gpr[reg::RSP],
            built.new_sp + 8,
            "failed restore must not commit register state"
        );

        let mut build_snapshot = X86UcontextSnapshot::new();
        build_snapshot.gpr[reg::RSP] = address + LEN as u64;
        let rebuild = {
            let mut engine = SigframeEngine {
                snap: &mut build_snapshot,
                executable_epoch: None,
            };
            X8664GuestArch::build_sigframe(&mut engine, params())
        };
        assert!(matches!(
            rebuild,
            Err(carrick_hal::TrapError::SignalDeliveryFault)
        ));

        IDENTITY_PROTECTIONS.set_unmapped(address, LEN, true);
        assert_eq!(unsafe { libc::munmap(mapping, LEN) }, 0);
    }

    fn reserve_then_unmap_test_range(len: usize) -> u64 {
        // SAFETY: private anonymous test mapping, immediately released to leave
        // a known hole whose address remains suitable for MAP_FIXED testing.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
        mapping as u64
    }

    type FixedAliasDispatchOutcome = (
        crate::dispatch::HostAliasTransaction,
        Vec<u8>,
        Option<(HostAliasOwnedFd, libc::off_t, libc::c_int)>,
        bool,
        bool,
    );

    fn dispatch_fixed_alias_for_test(
        dispatcher: &mut SyscallDispatcher,
        memory: &mut IdentityGuestMemory,
        address: u64,
        len: u64,
        prot: u64,
        flags: u64,
    ) -> FixedAliasDispatchOutcome {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    [
                        address,
                        len,
                        prot,
                        flags
                            | crate::linux_abi::LINUX_MAP_FIXED
                            | crate::linux_abi::LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]
                    .into(),
                ),
                memory,
                &CompatReporter::default(),
            )
            .expect("dispatch fixed host alias");
        let DispatchOutcome::MapHostAlias {
            transaction,
            va,
            len: mapped_len,
            payload,
            file,
            shared,
            prot_none,
            ..
        } = outcome
        else {
            panic!("expected pending host alias, got {outcome:?}");
        };
        assert_eq!(va.raw(), address);
        assert_eq!(mapped_len, len);
        (transaction, payload, file, shared, prot_none)
    }

    #[test]
    fn injected_host_alias_map_failure_leaves_fresh_vma_unpublished() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = IdentityGuestMemory::uncoordinated();
        let (transaction, payload, file, shared, prot_none) = dispatch_fixed_alias_for_test(
            &mut dispatcher,
            &mut memory,
            address,
            PAGE,
            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            crate::linux_abi::LINUX_MAP_PRIVATE,
        );
        assert!(dispatcher.dynamic_mapping_for_test(address).is_none());
        faults.fail_mmap(
            NativeMappingOperation::HostAlias,
            InjectedMmapResult::Failed,
        );
        let mut snapshot = X86UcontextSnapshot::new();
        let _ = service_map_host_alias(
            &dispatcher,
            transaction,
            address,
            PAGE,
            &payload,
            file,
            shared,
            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
            prot_none,
            &mut snapshot,
            &mut memory,
            0x1234,
        );
        assert!((snapshot.gpr[reg::RAX] as i64) < 0);
        assert!(dispatcher.dynamic_mapping_for_test(address).is_none());
        assert!(IDENTITY_PROTECTIONS.range_unmapped(address, PAGE as usize));
    }

    #[test]
    fn post_replacement_alias_failure_aborts_with_sigabrt() {
        let _test_guard = lock_native_mapping_tests();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        let prior = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(prior as u64, address);
        unsafe { (address as *mut u8).write(0x3c) };
        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, false);
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            PAGE as usize,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );

        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork post-replacement alias failure child failed"
        );
        if child == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let faults = NativeMappingFaultGuard::new();
            let mut dispatcher = SyscallDispatcher::new();
            let mut memory = IdentityGuestMemory::uncoordinated();
            let (transaction, mut payload, file, shared, prot_none) = dispatch_fixed_alias_for_test(
                &mut dispatcher,
                &mut memory,
                address,
                PAGE,
                crate::linux_abi::LINUX_PROT_READ,
                crate::linux_abi::LINUX_MAP_PRIVATE,
            );
            payload.push(0x5a);
            faults.fail_mprotect_at(
                NativeMappingOperation::HostAlias,
                faults.mprotect_call_count(NativeMappingOperation::HostAlias) + 1,
            );
            let mut snapshot = X86UcontextSnapshot::new();
            let _ = service_map_host_alias(
                &dispatcher,
                transaction,
                address,
                PAGE,
                &payload,
                file,
                shared,
                crate::linux_abi::LINUX_PROT_READ,
                prot_none,
                &mut snapshot,
                &mut memory,
                0x1234,
            );
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
        assert_eq!(unsafe { (address as *const u8).read() }, 0x3c);
        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(unsafe { libc::munmap(prior, PAGE as usize) }, 0);
    }

    #[test]
    fn injected_alias_protection_failure_preserves_fixed_prior_vma_and_host_mapping() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = IdentityGuestMemory::uncoordinated();

        let prior_prot = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC;
        let (transaction, payload, file, shared, prot_none) = dispatch_fixed_alias_for_test(
            &mut dispatcher,
            &mut memory,
            address,
            PAGE,
            prior_prot,
            crate::linux_abi::LINUX_MAP_SHARED,
        );
        let mut first = X86UcontextSnapshot::new();
        let _ = service_map_host_alias(
            &dispatcher,
            transaction,
            address,
            PAGE,
            &payload,
            file,
            shared,
            prior_prot,
            prot_none,
            &mut first,
            &mut memory,
            0x1234,
        );
        assert_eq!(first.gpr[reg::RAX], address);
        let prior_map = dispatcher
            .dynamic_mapping_for_test(address)
            .expect("committed prior alias VMA");
        assert!(IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, PAGE as usize));
        assert!(IDENTITY_PROTECTIONS.range_executable(address, PAGE as usize));
        assert!(IDENTITY_PROTECTIONS.range_no_write(address, PAGE as usize));

        let replacement_prot =
            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
        let (transaction, payload, file, shared, prot_none) = dispatch_fixed_alias_for_test(
            &mut dispatcher,
            &mut memory,
            address,
            PAGE,
            replacement_prot,
            crate::linux_abi::LINUX_MAP_PRIVATE,
        );
        faults.fail_mprotect_at(
            NativeMappingOperation::HostAlias,
            faults.mprotect_call_count(NativeMappingOperation::HostAlias),
        );
        let mut failed = X86UcontextSnapshot::new();
        let _ = service_map_host_alias(
            &dispatcher,
            transaction,
            address,
            PAGE,
            &payload,
            file,
            shared,
            replacement_prot,
            prot_none,
            &mut failed,
            &mut memory,
            0x1234,
        );
        assert!((failed.gpr[reg::RAX] as i64) < 0);
        assert_eq!(
            dispatcher.dynamic_mapping_for_test(address),
            Some(prior_map)
        );
        assert!(IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, PAGE as usize));
        assert!(IDENTITY_PROTECTIONS.range_executable(address, PAGE as usize));
        assert!(IDENTITY_PROTECTIONS.range_no_write(address, PAGE as usize));
        // The preflight injection fires before MAP_FIXED, so the real prior host
        // mapping remains readable rather than becoming an untracked hole.
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0);

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, PAGE as usize) },
            0
        );
    }

    #[test]
    fn shared_alias_mremap_shrink_preserves_fork_coherent_prefix_backing() {
        let _test_guard = lock_native_mapping_tests();
        let _faults = NativeMappingFaultGuard::new();
        let len = PAGE * 2;
        let address = reserve_then_unmap_test_range(len as usize);
        IDENTITY_PROTECTIONS.set_unmapped(address, len as usize, true);
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = IdentityGuestMemory::uncoordinated();
        let prot = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
        let (transaction, payload, file, shared, prot_none) = dispatch_fixed_alias_for_test(
            &mut dispatcher,
            &mut memory,
            address,
            len,
            prot,
            crate::linux_abi::LINUX_MAP_SHARED,
        );
        let mut mapped = X86UcontextSnapshot::new();
        let _ = service_map_host_alias(
            &dispatcher,
            transaction,
            address,
            len,
            &payload,
            file,
            shared,
            prot,
            prot_none,
            &mut mapped,
            &mut memory,
            0x1234,
        );
        assert_eq!(mapped.gpr[reg::RAX], address);
        unsafe { (address as *mut u8).write_volatile(0x31) };

        let shrink = dispatcher
            .dispatch(
                SyscallRequest::new(216, [address, len, PAGE, 0, 0, 0].into()),
                &mut memory,
                &CompatReporter::default(),
            )
            .expect("dispatch shared alias shrink");
        assert_eq!(
            shrink,
            DispatchOutcome::Returned {
                value: address as i64
            }
        );
        let map = dispatcher
            .dynamic_mapping_for_test(address)
            .expect("shrunk shared alias VMA");
        assert_eq!(map.end, address + PAGE);
        assert_eq!(map.sharing, crate::vfs::ProcMapSharing::Shared);

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork after shared shrink failed");
        if child == 0 {
            unsafe {
                (address as *mut u8).write_volatile(0x7c);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x7c);

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, PAGE as usize) },
            0
        );
    }

    #[test]
    fn reused_anonymous_backing_preserves_shared_and_private_fork_semantics() {
        let _test_guard = lock_native_mapping_tests();
        let _faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        let mut memory = IdentityGuestMemory::uncoordinated();
        memory
            .zero_anonymous_reuse(
                address,
                PAGE as usize,
                carrick_guest_mem::MappingSharing::Shared,
            )
            .expect("install reused shared anonymous backing");
        unsafe { (address as *mut u8).write_volatile(0x11) };

        let shared_child = unsafe { libc::fork() };
        assert!(shared_child >= 0, "shared fork failed");
        if shared_child == 0 {
            unsafe {
                (address as *mut u8).write_volatile(0x5a);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(shared_child, &mut status, 0) },
            shared_child
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x5a);

        memory
            .zero_anonymous_reuse(
                address,
                PAGE as usize,
                carrick_guest_mem::MappingSharing::Private,
            )
            .expect("install reused private anonymous backing");
        unsafe { (address as *mut u8).write_volatile(0x22) };
        let private_child = unsafe { libc::fork() };
        assert!(private_child >= 0, "private fork failed");
        if private_child == 0 {
            unsafe {
                (address as *mut u8).write_volatile(0xa5);
                libc::_exit(0);
            }
        }
        assert_eq!(
            unsafe { libc::waitpid(private_child, &mut status, 0) },
            private_child
        );
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x22);

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, PAGE as usize) },
            0
        );
    }

    #[test]
    fn private_to_shared_anonymous_reuse_failure_preserves_bytes_and_metadata() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        let mapped = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_eq!(mapped as u64, address);
        unsafe { (address as *mut u8).write_volatile(0x6d) };
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            PAGE as usize,
            false,
            false,
            carrick_guest_mem::MappingSharing::Private,
        );
        faults.fail_mmap(
            NativeMappingOperation::IdentityBacking,
            InjectedMmapResult::Failed,
        );
        let mut memory = IdentityGuestMemory::uncoordinated();

        assert!(matches!(
            memory.zero_anonymous_reuse(
                address,
                PAGE as usize,
                carrick_guest_mem::MappingSharing::Shared,
            ),
            Err(MemoryError::HostMap(_))
        ));
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x6d);
        assert!(
            !IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, PAGE as usize),
            "failed replacement must not publish requested MAP_SHARED metadata"
        );
        assert!(!IDENTITY_PROTECTIONS.range_unmapped(address, PAGE as usize));

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(
            unsafe { libc::munmap(address as *mut libc::c_void, PAGE as usize) },
            0
        );
    }

    #[test]
    fn private_repoint_mmap_failure_preserves_shared_backing_and_provenance() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        let mapping = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert_eq!(mapping as u64, address);
        // SAFETY: this test owns the exact writable shared mapping.
        unsafe { (address as *mut u8).write_volatile(0x6d) };
        IDENTITY_PROTECTIONS.set_mapping_protection_and_sharing(
            address,
            PAGE as usize,
            false,
            false,
            carrick_guest_mem::MappingSharing::Shared,
        );
        faults.fail_mmap(
            NativeMappingOperation::IdentityBacking,
            InjectedMmapResult::Failed,
        );
        let mut memory = IdentityGuestMemory::uncoordinated();
        let snapshot = vec![0x41; PAGE as usize];

        assert!(matches!(
            memory.repoint_private(address, 0, PAGE as usize, &snapshot),
            Err(RepointPrivateError::Clean(MemoryError::HostMap(_)))
        ));
        assert_eq!(unsafe { (address as *const u8).read_volatile() }, 0x6d);
        assert!(
            IDENTITY_PROTECTIONS.range_mutable_shared_backing(address, PAGE as usize),
            "a refused exact replacement must retain prior Shared provenance"
        );
        assert!(!IDENTITY_PROTECTIONS.range_unmapped(address, PAGE as usize));

        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        assert_eq!(unsafe { libc::munmap(mapping, PAGE as usize) }, 0);
    }

    #[test]
    fn identity_backing_mmap_failure_keeps_metadata_unmapped() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        protections.set_unmapped(address, PAGE as usize, true);
        faults.fail_mmap(
            NativeMappingOperation::IdentityBacking,
            InjectedMmapResult::Failed,
        );

        assert!(matches!(
            ensure_identity_backed_with_registry(address, PAGE as usize, &protections),
            Err(MemoryError::HostMap(_))
        ));
        assert!(protections.range_unmapped(address, PAGE as usize));
    }

    #[test]
    fn identity_mapping_setter_preserves_typed_backing_failure() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        IDENTITY_PROTECTIONS.set_unmapped(address, PAGE as usize, true);
        faults.fail_mmap(
            NativeMappingOperation::IdentityBacking,
            InjectedMmapResult::Failed,
        );
        let mut memory = IdentityGuestMemory::uncoordinated();

        memory.set_mapping_protection(address, PAGE as usize, false, false);

        assert!(matches!(
            memory.take_mapping_failure(),
            Some(MemoryError::HostMap(_))
        ));
        assert!(IDENTITY_PROTECTIONS.range_unmapped(address, PAGE as usize));
    }

    #[test]
    fn identity_backing_wrong_address_is_rolled_back_before_metadata_change() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        protections.set_unmapped(address, PAGE as usize, true);
        faults.fail_mmap(
            NativeMappingOperation::IdentityBacking,
            InjectedMmapResult::WrongAddress,
        );

        assert!(matches!(
            ensure_identity_backed_with_registry(address, PAGE as usize, &protections),
            Err(MemoryError::HostMap(_))
        ));
        assert!(protections.range_unmapped(address, PAGE as usize));
        let rolled_back = faults.munmaps();
        assert_eq!(rolled_back.len(), 1);
        assert_ne!(rolled_back[0].0, address);
        assert_eq!(rolled_back[0].2, 0, "misplaced mapping cleanup failed");
    }

    #[test]
    fn fixed_reservation_wrong_address_reports_cleanup_and_retains_owner_until_retry() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let address = reserve_then_unmap_test_range(PAGE as usize);
        faults.fail_mmap(
            NativeMappingOperation::General,
            InjectedMmapResult::WrongAddress,
        );
        faults.fail_munmap_at(0);

        let error = reserve_fixed_rw(
            address,
            PAGE as usize,
            FixedRwReservation::Exclusive,
            "wrong-address test",
        )
        .expect_err("wrong fixed address must fail");
        assert!(error.to_string().contains("wrong-address cleanup failed"));
        assert_eq!(
            faults
                .munmaps()
                .iter()
                .map(|&(_, _, result)| result)
                .collect::<Vec<_>>(),
            vec![-1, 0],
            "Drop must retain and discharge the misplaced owner after the reportable failure"
        );
    }

    #[test]
    fn identity_backing_restores_only_holes_and_preserves_adjacent_live_bytes() {
        let _test_guard = lock_native_mapping_tests();
        let _faults = NativeMappingFaultGuard::new();
        let len = (PAGE * 3) as usize;
        // SAFETY: private test mapping, retired below after the middle page is
        // removed and restored through the identity-backing transaction.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as u64;
        // SAFETY: first/last addresses lie in the live three-page mapping.
        unsafe {
            (address as *mut u8).write(0x5a);
            ((address + PAGE * 2) as *mut u8).write(0xa5);
            assert_eq!(
                libc::munmap((address + PAGE) as *mut libc::c_void, PAGE as usize),
                0
            );
        }
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        protections.set_unmapped(address + PAGE, PAGE as usize, true);

        ensure_identity_backed_with_registry(address, len, &protections)
            .expect("restore exact middle hole");

        // SAFETY: all three pages are live after the checked restoration.
        unsafe {
            assert_eq!((address as *const u8).read(), 0x5a);
            assert_eq!(((address + PAGE) as *const u8).read(), 0);
            assert_eq!(((address + PAGE * 2) as *const u8).read(), 0xa5);
            assert_eq!(libc::munmap(mapping, len), 0);
        }
        assert!(!protections.range_unmapped(address, len));
    }

    #[test]
    fn reset_identity_vmas_propagates_mprotect_failure_and_fails_closed() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        let mapping = NativeMapping::map_anonymous(
            NativeMappingOperation::General,
            (PAGE * 2) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            None,
            "reset test image",
        )
        .expect("map reset test image");
        let base = mapping.base;
        let image = LoadedImage {
            mappings: vec![mapping],
            entry: base,
            stack: base + PAGE,
            stack_len: PAGE as usize,
            rsp: base + PAGE * 2,
            scratch: base,
            scratch_len: PAGE as usize,
            sigreturn_trampoline: base,
            vdso_base: 0,
            segments: vec![(base, base + PAGE)],
            segment_protections: vec![(base, base + PAGE, crate::linux_abi::LINUX_PROT_READ)],
        };
        faults.fail_mprotect(NativeMappingOperation::IdentityProtection);

        assert!(matches!(
            reset_identity_vmas_with_registry(&image, &protections),
            Err(MemoryError::HostMap(_))
        ));
        assert!(protections.range_unmapped(base, (PAGE * 2) as usize));
        image.teardown().expect("clean reset test image");
    }

    #[test]
    fn later_identity_protection_failure_rolls_back_publication() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        let image = load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[])
            .expect("map protection candidate");
        faults.fail_mprotect_at(NativeMappingOperation::IdentityProtection, 2);

        assert!(matches!(
            reset_identity_vmas_with_registry(&image, &protections),
            Err(MemoryError::HostMap(_))
        ));
        assert_eq!(
            faults.mprotect_call_count(NativeMappingOperation::IdentityProtection),
            3,
            "the indexed failure must reach the third publication"
        );
        for mapping in &image.mappings {
            assert!(protections.range_unmapped(mapping.base, mapping.len));
        }
        image.teardown().expect("clean protection candidate");
    }

    #[test]
    fn scratch_mmap_failure_rolls_back_main_interpreter_and_stack() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let main = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/dynamic-main-x86_64-linux"
        ))
        .expect("read dynamic main fixture");
        let interpreter = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/dynamic-interpreter-x86_64-linux"
        ))
        .expect("read dynamic interpreter fixture");
        faults.fail_mmap(NativeMappingOperation::Scratch, InjectedMmapResult::Failed);

        assert!(load_static_pie(&main, Some(&interpreter), &[b"candidate".to_vec()], &[]).is_err());
        let rolled_back = faults.munmaps();
        assert!(
            rolled_back.len() >= 3,
            "main, interpreter, and stack must roll back: {rolled_back:x?}"
        );
        assert!(
            rolled_back
                .iter()
                .any(|&(_, len, result)| len == GUEST_STACK_LEN && result == 0)
        );
        assert!(
            rolled_back.iter().all(|&(_, _, result)| result == 0),
            "candidate rollback host unmap failed: {rolled_back:x?}"
        );
    }

    #[test]
    fn later_elf_segment_failure_explicitly_rolls_back_reservation() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        faults.fail_mmap_at(
            NativeMappingOperation::ElfSegment,
            1,
            InjectedMmapResult::Failed,
        );

        let error = match load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[]) {
            Err(error) => error,
            Ok(image) => {
                image.teardown().expect("clean unexpected image");
                panic!("second segment map must fail");
            }
        };
        assert!(error.to_string().contains("ELF segment"));
        assert_eq!(
            faults.mmap_call_count(NativeMappingOperation::ElfSegment),
            2
        );
        assert!(
            faults.munmaps().iter().any(|&(_, _, result)| result == 0),
            "the owning ELF reservation must roll back"
        );
    }

    #[test]
    fn loader_reports_rollback_failure_after_discharge_retry() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let main = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/dynamic-main-x86_64-linux"
        ))
        .expect("read dynamic main fixture");
        let interpreter = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/dynamic-interpreter-x86_64-linux"
        ))
        .expect("read dynamic interpreter fixture");
        faults.fail_mmap(NativeMappingOperation::Scratch, InjectedMmapResult::Failed);
        faults.fail_munmap_at(0);

        let error = match load_static_pie(&main, Some(&interpreter), &[b"candidate".to_vec()], &[])
        {
            Err(error) => error,
            Ok(image) => {
                image.teardown().expect("clean unexpected image");
                panic!("scratch allocation must fail");
            }
        };
        assert!(
            error.to_string().contains("rollback failed"),
            "rollback failure missing from diagnostic: {error}"
        );
        let results = faults
            .munmaps()
            .iter()
            .map(|&(_, _, result)| result)
            .collect::<Vec<_>>();
        assert_eq!(results.first(), Some(&-1));
        assert!(
            results.iter().skip(1).all(|result| *result == 0),
            "all owners must be discharged after the injected transient: {results:?}"
        );
    }

    #[test]
    fn vvar_protection_failure_rolls_back_complete_candidate() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        faults.fail_mprotect(NativeMappingOperation::VvarProtection);

        let error = match load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[]) {
            Err(error) => error,
            Ok(image) => {
                image.teardown().expect("clean unexpected image");
                panic!("vvar PROT_READ transition must be checked");
            }
        };
        assert!(error.to_string().contains("protect native vvar"));
        assert_eq!(
            faults.mprotect_call_count(NativeMappingOperation::VvarProtection),
            1
        );
        assert!(faults.munmaps().iter().all(|&(_, _, result)| result == 0));
    }

    #[test]
    fn optional_vdso_failure_explicitly_releases_vvar_candidate() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        faults.fail_mmap(NativeMappingOperation::Vdso, InjectedMmapResult::Failed);

        let image = load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[])
            .expect("vDSO absence remains optional");
        assert_eq!(image.vdso_base, 0);
        assert!(faults.munmaps().iter().any(|&(address, len, result)| {
            address == crate::vdso::LINUX_VVAR_BASE
                && len == crate::vdso::LINUX_VVAR_SIZE as usize
                && result == 0
        }));
        image.teardown().expect("clean optional-vDSO candidate");
    }

    #[test]
    fn successful_image_owner_lifetime_and_teardown_are_exactly_once() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        let image = load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[])
            .expect("map successful image");
        let owned = image.mappings.len();
        let before = faults.munmaps().len();

        image.teardown().expect("tear down successful image");
        assert_eq!(faults.munmaps().len() - before, owned);
        image.teardown().expect("idempotent image teardown");
        assert_eq!(faults.munmaps().len() - before, owned);
        drop(image);
        assert_eq!(
            faults.munmaps().len() - before,
            owned,
            "Drop must not double-unmap explicitly retired owners"
        );
    }

    #[test]
    fn fixed_exec_collision_preserves_existing_owner_and_bytes() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/identity-loop-x86_64-linux"
        ))
        .expect("read ET_EXEC fixture");
        let elf = Elf::parse(&bytes).expect("parse ET_EXEC fixture");
        assert_eq!(elf.header.e_type, ET_EXEC);
        let start = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .map(|header| header.p_vaddr & !(PAGE - 1))
            .min()
            .expect("ET_EXEC PT_LOAD start");
        let end = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .map(|header| (header.p_vaddr + header.p_memsz + PAGE - 1) & !(PAGE - 1))
            .max()
            .expect("ET_EXEC PT_LOAD end");
        let occupant = NativeMapping::map_anonymous(
            NativeMappingOperation::General,
            (end - start) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            Some(start),
            "fixed collision occupant",
        )
        .expect("occupy ET_EXEC range exclusively");
        // SAFETY: the occupant owns a writable byte at `start`.
        unsafe { (start as *mut u8).write(0x6d) };

        assert!(load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[]).is_err());
        // SAFETY: MAP_FIXED|MAP_EXCL made the failed loader reservation leave
        // the occupant intact.
        assert_eq!(unsafe { (start as *const u8).read() }, 0x6d);
        let before = faults.munmaps().len();
        occupant.teardown().expect("retire collision occupant");
        occupant.teardown().expect("idempotent collision teardown");
        drop(occupant);
        assert_eq!(faults.munmaps().len() - before, 1);
    }

    #[test]
    fn fixed_vvar_collision_is_optional_without_replacing_existing_owner() {
        let _test_guard = lock_native_mapping_tests();
        let _faults = NativeMappingFaultGuard::new();
        let occupant = NativeMapping::map_anonymous(
            NativeMappingOperation::General,
            crate::vdso::LINUX_VVAR_SIZE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            Some(crate::vdso::LINUX_VVAR_BASE),
            "vvar collision occupant",
        )
        .expect("occupy fixed vvar range exclusively");
        // SAFETY: the test owner holds the writable vvar-range mapping.
        unsafe { (crate::vdso::LINUX_VVAR_BASE as *mut u8).write(0x3c) };
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");

        let image = load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[])
            .expect("vvar collision is optional");
        assert_eq!(image.vdso_base, 0);
        // SAFETY: exclusive fixed mapping made the loader leave the owner live.
        assert_eq!(
            unsafe { (crate::vdso::LINUX_VVAR_BASE as *const u8).read() },
            0x3c
        );
        image.teardown().expect("clean colliding image");
        assert_eq!(
            unsafe { (crate::vdso::LINUX_VVAR_BASE as *const u8).read() },
            0x3c,
            "image teardown must not retire the independent collision owner"
        );
        occupant.teardown().expect("retire vvar collision occupant");
    }

    #[test]
    fn vvar_is_host_read_only_and_published_no_write() {
        let _test_guard = lock_native_mapping_tests();
        let _faults = NativeMappingFaultGuard::new();
        let protections = carrick_guest_mem::protections::MemoryProtections::default();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-dsr-x86/tests/fixtures/tinyguest-x86_64-linux"
        ))
        .expect("read static PIE fixture");
        let image = load_static_pie(&bytes, None, &[b"candidate".to_vec()], &[])
            .expect("map image with vvar");
        assert_ne!(image.vdso_base, 0, "fixed vvar/vDSO must be available");
        assert!(image.segment_protections.iter().any(|&(start, end, prot)| {
            start == crate::vdso::LINUX_VVAR_BASE
                && end == crate::vdso::LINUX_VVAR_BASE + crate::vdso::LINUX_VVAR_SIZE
                && prot == crate::linux_abi::LINUX_PROT_READ
        }));

        reset_identity_vmas_with_registry(&image, &protections)
            .expect("publish checked image protections");
        assert!(protections.range_no_write(
            crate::vdso::LINUX_VVAR_BASE,
            crate::vdso::LINUX_VVAR_SIZE as usize
        ));
        image.teardown().expect("clean vvar image");
    }

    #[test]
    fn mapping_drop_backstop_aborts_on_unmap_failure() {
        let _test_guard = lock_native_mapping_tests();
        // SAFETY: the child performs only mmap, thread-local fault setup, and
        // the intentional aborting Drop; the parent waits synchronously.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: child-local resource limit; failure only affects whether
            // the intentional abort emits a disposable core.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let faults = NativeMappingFaultGuard::new();
            let mapping = NativeMapping::map_anonymous(
                NativeMappingOperation::General,
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                None,
                "drop fail-stop test",
            )
            .unwrap_or_else(|_| unsafe { libc::_exit(91) });
            faults.fail_next_munmap();
            drop(mapping);
            unsafe { libc::_exit(92) };
        }
        let mut status = 0;
        // SAFETY: `pid` is the live child created above and `status` is writable.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[test]
    fn old_image_teardown_failure_aborts_terminal_without_reopening() {
        let _test_guard = lock_native_mapping_tests();
        let faults = NativeMappingFaultGuard::new();
        let mapping = NativeMapping::map_anonymous(
            NativeMappingOperation::General,
            PAGE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            None,
            "terminal teardown test",
        )
        .expect("map terminal teardown test image");
        let epoch = ExecutableEpoch::new();
        let registration = epoch.register_current().expect("register terminal owner");
        let generation = epoch.current_generation().expect("initial generation");
        let terminal = epoch
            .begin_terminal(&registration, || {})
            .expect("acquire terminal owner");
        faults.fail_next_munmap();

        assert!(mapping.teardown().is_err());
        let owner = terminal.owner();
        drop(terminal);
        assert!(matches!(
            epoch.admit(&registration, generation),
            Ok(JitAdmission::Stopped(ExecutableTerminalStop {
                owner: found,
                phase: ExecutableTerminalPhase::Aborted,
            })) if found == owner
        ));
        mapping.teardown().expect("retry terminal image teardown");
        assert_eq!(
            faults
                .munmaps()
                .iter()
                .map(|&(_, _, result)| result)
                .collect::<Vec<_>>(),
            vec![-1, 0]
        );
    }

    #[test]
    fn tsc_vdso_requires_invariant_and_smp_safe_host_counter() {
        assert!(tsc_vdso_is_safe(1, 1));
        assert!(!tsc_vdso_is_safe(0, 1));
        assert!(!tsc_vdso_is_safe(1, 0));
        assert!(!tsc_vdso_is_safe(0, 0));
    }

    #[test]
    fn xstate_edge_barriers_parse_sources_pairs_and_all() {
        let barriers = NativeX86EdgeBarriers::parse("0x10, 20->0x30,all,bad");
        assert!(barriers.contains(GuestVa(0x10), GuestVa(0x99)));
        assert!(barriers.contains(GuestVa(0x20), GuestVa(0x30)));
        assert!(barriers.contains(GuestVa(0x77), GuestVa(0x88)));

        let selected = NativeX86EdgeBarriers::parse("10,20->30");
        assert!(selected.contains(GuestVa(0x10), GuestVa(0x99)));
        assert!(selected.contains(GuestVa(0x20), GuestVa(0x30)));
        assert!(!selected.contains(GuestVa(0x20), GuestVa(0x31)));
    }

    #[test]
    fn unsafe_xstate_policies_skip_chainable_integer_entry_transfers() {
        let conservative = NativeX86XstatePolicy::Conservative;
        let local = NativeX86XstatePolicy::UnsafeLocalDiagnostic;
        let target_barrier = NativeX86XstatePolicy::NeutralDomains;
        assert!(conservative.save_required(true, false, false));
        assert!(!local.save_required(true, false, false));
        assert!(!target_barrier.save_required(true, false, false));
        assert!(conservative.save_required(false, true, false));
        assert!(local.save_required(false, true, false));
        assert!(target_barrier.save_required(false, true, false));
        assert!(!conservative.save_required(false, false, false));
        assert!(!local.save_required(false, false, false));
        assert!(!target_barrier.save_required(false, false, false));
        assert!(conservative.save_required(false, false, true));
        assert!(local.save_required(false, false, true));
        assert!(target_barrier.save_required(false, false, true));
        assert!(!local.keeps_state_targets_cold());
        assert!(target_barrier.keeps_state_targets_cold());
    }

    #[test]
    fn captured_return_applies_one_target_and_one_stack_adjustment() {
        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.gpr[reg::RSP] = u64::MAX - 3;
        snapshot.rflags = 0xCD7;

        let target = apply_captured_return(&mut snapshot, 0x1234_5678, 8 + 0x20);

        assert_eq!(target, 0x1234_5678);
        assert_eq!(snapshot.gpr[reg::RSP], 0x24);
        assert_eq!(snapshot.rflags, 0xCD7);
    }

    #[test]
    fn xsave_header_read_faults_use_guest_retry_policy_and_backend_errors_are_fatal() {
        for (kind, expected_code) in [
            (
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped,
                crate::linux_abi::LINUX_SEGV_MAPERR,
            ),
            (
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied,
                crate::linux_abi::LINUX_SEGV_ACCERR,
            ),
        ] {
            let error: X86XstateSaveError<_, IdentityCheckedWriteError> = X86XstateSaveError::Read(
                IdentityCheckedReadError::Fault(carrick_guest_mem::protections::GuestMemoryFault {
                    address: GuestVa(0x1234),
                    kind,
                }),
            );
            assert_eq!(
                xstate_save_emulation_runtime_error(0x4000, error),
                X86XstateServiceError::Signal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    code: expected_code,
                    address: 0x1234,
                }
            );
        }

        let backend: X86XstateSaveError<_, IdentityCheckedWriteError> =
            X86XstateSaveError::Read(IdentityCheckedReadError::Backend {
                address: GuestVa(0x5678),
                detail: "mapping lock poisoned".to_owned(),
            });
        assert!(matches!(
            xstate_save_emulation_runtime_error(0x4000, backend),
            X86XstateServiceError::Fatal(detail)
                if detail.contains("checked read at 0x5678")
                    && detail.contains("mapping lock poisoned")
        ));
    }

    #[test]
    fn cpuid_filter_hides_unsupported_state_without_hiding_rdt() {
        let host = NativeCpuidRegisters {
            eax: u32::MAX,
            ebx: u32::MAX,
            ecx: u32::MAX,
            edx: u32::MAX,
        };
        let mut components = [carrick_dsr_x86::X86SnapshotXstateComponent::default(); 64];
        components[2] = carrick_dsr_x86::X86SnapshotXstateComponent {
            offset: 576,
            size: 256,
        };
        let layout = carrick_dsr_x86::X86SnapshotXstateLayout::new(
            carrick_dsr_x86::X86SnapshotXstateCapabilities {
                supported_features: 0x7,
                standard_size: 832,
                mxcsr_mask: 0xffff,
                components,
            },
            0,
        )
        .expect("valid CPUID test layout");

        let leaf7 = virtualize_native_cpuid(7, 0, host, Some(layout)).expect("non-xstate leaf");
        assert_eq!(leaf7.ebx & (1 << 14), 0, "MPX hidden");
        assert_eq!(
            leaf7.ebx & (1 << 13),
            0,
            "virtual selectors expose non-deprecated FCS/FDS semantics"
        );
        assert_ne!(leaf7.ebx & (1 << 15), 0, "RDT allocation preserved");
        assert_eq!(leaf7.ecx & ((1 << 3) | (1 << 4) | (1 << 7)), 0);
        let leaf7_1 = virtualize_native_cpuid(7, 1, host, None).expect("non-xstate leaf");
        assert_eq!(leaf7_1.edx & (1 << 18), 0, "CET supervisor state hidden");

        assert_eq!(
            virtualize_native_cpuid(0x0d, 0, host, Some(layout)).expect("valid standard geometry"),
            NativeCpuidRegisters {
                eax: 0x7,
                ebx: 832,
                ecx: 832,
                edx: 0,
            },
            "D.0 advertises only the enabled, safely transferable geometry"
        );
        assert_eq!(
            virtualize_native_cpuid(0x0d, 1, host, Some(layout)).expect("valid compacted geometry"),
            NativeCpuidRegisters {
                eax: 0b11,
                ebx: 832,
                ecx: 0,
                edx: 0,
            },
            "D.1 hides XGETBV1, XSAVES, and IA32_XSS"
        );
        assert_eq!(
            virtualize_native_cpuid(0x0d, 2, host, Some(layout))
                .expect("virtual AVX component metadata"),
            NativeCpuidRegisters {
                eax: 256,
                ebx: 576,
                ecx: 0,
                edx: 0,
            },
            "D component metadata comes from the validated virtual layout"
        );
        for component in [9, 11, 12, 63] {
            assert_eq!(
                virtualize_native_cpuid(0x0d, component, host, Some(layout))
                    .expect("valid hidden-component geometry"),
                NativeCpuidRegisters {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                }
            );
        }

        let no_xstate = virtualize_native_cpuid(7, 0, host, None)
            .expect("selector contract does not depend on host xstate geometry");
        assert_eq!(
            no_xstate.ebx & (1 << 13),
            0,
            "CPUID bit 13 stays clear even when the host layout is unavailable"
        );
    }

    #[test]
    fn cpuid_d1_reports_sparse_compacted_enabled_extent() {
        let host = NativeCpuidRegisters {
            eax: u32::MAX,
            ebx: u32::MAX,
            ecx: u32::MAX,
            edx: u32::MAX,
        };
        let mut components = [carrick_dsr_x86::X86SnapshotXstateComponent::default(); 64];
        components[2] = carrick_dsr_x86::X86SnapshotXstateComponent {
            offset: 1024,
            size: 32,
        };
        components[5] = carrick_dsr_x86::X86SnapshotXstateComponent {
            offset: 2048,
            size: 16,
        };
        components[6] = carrick_dsr_x86::X86SnapshotXstateComponent {
            offset: 2304,
            size: 24,
        };
        components[7] = carrick_dsr_x86::X86SnapshotXstateComponent {
            offset: 3072,
            size: 32,
        };
        let layout = carrick_dsr_x86::X86SnapshotXstateLayout::new(
            carrick_dsr_x86::X86SnapshotXstateCapabilities {
                supported_features: 0xe7,
                standard_size: 3104,
                mxcsr_mask: 0xffff,
                components,
            },
            (1 << 5) | (1 << 7),
        )
        .expect("valid sparse xstate layout");

        let leaf = virtualize_native_cpuid(0x0d, 1, host, Some(layout))
            .expect("validated compacted geometry");
        assert_eq!(leaf.eax, 0b11);
        assert_eq!(leaf.ebx, 736);
        assert_eq!(leaf.ecx, 0);
        assert_eq!(leaf.edx, 0);
        assert_eq!(
            virtualize_native_cpuid(0x0d, 5, host, Some(layout))
                .expect("aligned compacted component metadata"),
            NativeCpuidRegisters {
                eax: 16,
                ebx: 2048,
                ecx: 1 << 1,
                edx: 0,
            }
        );
    }

    #[test]
    fn sensitive_pkru_access_is_virtual_and_preserves_host_memory_rights() {
        use carrick_dsr_x86::decode::X86SensitiveKind::{Cpuid, ExtendedControl, ProtectionKey};

        let mut feature_snapshot = X86UcontextSnapshot::new();
        feature_snapshot.gpr[reg::RAX] = 7;
        service_sensitive(Cpuid, &mut feature_snapshot).unwrap();
        assert_eq!(
            feature_snapshot.gpr[reg::RBX] & (1 << 13),
            0,
            "CPUID exposes modeled non-deprecated selector semantics"
        );
        assert_eq!(
            feature_snapshot.gpr[reg::RCX] & ((1 << 3) | (1 << 4) | (1 << 7)),
            0,
            "MPX, PKU/OSPKE, and CET_SS stay hidden"
        );
        feature_snapshot.gpr[reg::RAX] = 7;
        feature_snapshot.gpr[reg::RCX] = 1;
        service_sensitive(Cpuid, &mut feature_snapshot).unwrap();
        assert_eq!(
            feature_snapshot.gpr[reg::RDX] & (1 << 18),
            0,
            "CET supervisor state stays hidden"
        );
        feature_snapshot.gpr[reg::RAX] = 0x0d;
        feature_snapshot.gpr[reg::RCX] = 0;
        service_sensitive(Cpuid, &mut feature_snapshot).unwrap();
        let cpuid_d0_enabled =
            feature_snapshot.gpr[reg::RAX] | (feature_snapshot.gpr[reg::RDX] << 32);
        let layout = carrick_dsr_x86::signal_xstate_layout().unwrap();
        let capabilities = layout.capabilities();
        assert_eq!(cpuid_d0_enabled, capabilities.supported_features);
        assert_eq!(
            feature_snapshot.gpr[reg::RBX],
            u64::from(capabilities.standard_size)
        );
        assert_eq!(
            feature_snapshot.gpr[reg::RCX],
            u64::from(capabilities.standard_size)
        );
        feature_snapshot.gpr[reg::RAX] = 0x0d;
        feature_snapshot.gpr[reg::RCX] = 1;
        service_sensitive(Cpuid, &mut feature_snapshot).unwrap();
        assert_eq!(feature_snapshot.gpr[reg::RAX] & ((1 << 2) | (1 << 3)), 0);
        assert_eq!(
            feature_snapshot.gpr[reg::RBX],
            u64::from(
                layout
                    .compacted_size_for(capabilities.supported_features)
                    .unwrap()
            )
        );
        assert_eq!(feature_snapshot.gpr[reg::RCX], 0);
        assert_eq!(feature_snapshot.gpr[reg::RDX], 0);

        feature_snapshot.gpr[reg::RAX] = 0x0d;
        feature_snapshot.gpr[reg::RCX] = 9;
        service_sensitive(Cpuid, &mut feature_snapshot).unwrap();
        assert_eq!(feature_snapshot.gpr[reg::RAX], 0);
        assert_eq!(feature_snapshot.gpr[reg::RBX], 0);
        assert_eq!(feature_snapshot.gpr[reg::RCX], 0);
        assert_eq!(feature_snapshot.gpr[reg::RDX], 0);
        feature_snapshot.gpr[reg::RCX] = 0;
        service_sensitive(ExtendedControl, &mut feature_snapshot).unwrap();
        let virtual_xcr0 = feature_snapshot.gpr[reg::RAX] | (feature_snapshot.gpr[reg::RDX] << 32);
        assert_eq!(
            virtual_xcr0, cpuid_d0_enabled,
            "XGETBV(0) must equal CPUID D.0's enabled component mask"
        );
        feature_snapshot.gpr[reg::RCX] = 1;
        assert_eq!(
            service_sensitive(ExtendedControl, &mut feature_snapshot),
            Err(X86SensitiveServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }),
            "unsupported XGETBV indexes take the typed synchronous #GP delivery path"
        );

        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.gpr[reg::RAX] = 3;
        service_sensitive(ProtectionKey { write: true }, &mut snapshot).unwrap();
        assert_eq!(snapshot.pkru().raw(), 3);

        snapshot.gpr[reg::RAX] = 0;
        snapshot.gpr[reg::RDX] = u64::MAX;
        service_sensitive(ProtectionKey { write: false }, &mut snapshot).unwrap();
        assert_eq!(snapshot.gpr[reg::RAX], 3);
        assert_eq!(snapshot.gpr[reg::RDX], 0);
    }

    #[test]
    fn invalid_pkru_operands_are_retryable_synchronous_general_protection() {
        use carrick_dsr_x86::decode::X86SensitiveKind::ProtectionKey;

        let expected = Err(X86SensitiveServiceError::Signal {
            signum: crate::linux_abi::LINUX_SIGSEGV,
            code: crate::linux_abi::LINUX_SI_KERNEL,
            address: 0,
        });
        for (write, rcx, rdx) in [(false, 1, 0), (true, 1, 0), (true, 0, 1)] {
            let mut snapshot = X86UcontextSnapshot::new();
            snapshot.gpr[reg::RAX] = 0x5a5a_a5a5;
            snapshot.gpr[reg::RCX] = rcx;
            snapshot.gpr[reg::RDX] = rdx;
            snapshot.apply_guest_pkru_write(0x1357_2468);
            let before = snapshot.clone();

            assert_eq!(
                service_sensitive(ProtectionKey { write }, &mut snapshot),
                expected,
                "invalid PKRU operands must use unified synchronous #GP delivery"
            );
            assert_eq!(
                snapshot.gpr, before.gpr,
                "faulting operands remain repairable"
            );
            assert_eq!(snapshot.pkru(), before.pkru(), "fault is transactional");
        }
    }

    #[test]
    fn virtual_x87_wait_faults_without_touching_host_fpu_state() {
        use carrick_dsr_x86::decode::X86SensitiveKind::X87Wait;

        let mut snapshot = X86UcontextSnapshot::new();
        snapshot.rip = 0x401234;
        snapshot.xsave[2..4].copy_from_slice(&0x0081u16.to_le_bytes());
        let before = snapshot.clone();
        assert_eq!(
            service_sensitive(X87Wait, &mut snapshot),
            Err(X86SensitiveServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGFPE,
                code: 7,
                address: 0x401234,
            })
        );
        assert_eq!(snapshot.xsave, before.xsave);
        assert_eq!(snapshot.gpr, before.gpr);
        assert_eq!(snapshot.rip, before.rip);

        snapshot.xsave[2..4].copy_from_slice(&0u16.to_le_bytes());
        service_sensitive(X87Wait, &mut snapshot).expect("clear WAIT must complete");
    }

    #[test]
    fn blocked_synchronous_fault_terminates_without_entering_handler() {
        let termination = synchronous_fault_termination(true, || {
            panic!("a blocked synchronous signal must not attempt handler injection")
        });
        assert_eq!(termination, Some(SynchronousFaultTermination::Blocked));
        assert_eq!(
            synchronous_fault_final_signum(
                crate::linux_abi::LINUX_SIGBUS,
                termination.expect("blocked faults terminate"),
            ),
            crate::linux_abi::LINUX_SIGBUS,
            "a blocked synchronous fault terminates with its original signal"
        );
    }

    #[test]
    fn synchronous_fault_default_action_preserves_original_signum() {
        let termination = synchronous_fault_termination(false, || Ok(false));
        assert_eq!(
            termination,
            Some(SynchronousFaultTermination::DefaultAction)
        );
        assert_eq!(
            synchronous_fault_final_signum(
                crate::linux_abi::LINUX_SIGFPE,
                termination.expect("default action terminates"),
            ),
            crate::linux_abi::LINUX_SIGFPE
        );
    }

    #[test]
    fn synchronous_fault_frame_failure_forces_final_sigsegv() {
        let termination = synchronous_fault_termination(false, || Err(()));
        assert_eq!(
            termination,
            Some(SynchronousFaultTermination::FrameBuildFailed)
        );
        let final_signum = synchronous_fault_final_signum(
            crate::linux_abi::LINUX_SIGBUS,
            termination.expect("failed frame build terminates"),
        );
        assert_eq!(
            final_signum,
            crate::linux_abi::LINUX_SIGSEGV,
            "failure to build a synchronous SIGBUS frame force-SIGSEGVs"
        );
        assert_eq!(
            SynchronousFaultDelivery::Fatal(crate::linux_abi::LINUX_SIGSEGV),
            SynchronousFaultDelivery::Fatal(final_signum)
        );
    }

    #[test]
    fn xstate_restore_errors_map_to_retryable_guest_faults_or_fatal_internal_diagnostics() {
        let va = 0x1234_5000;
        assert_eq!(
            xstate_decode_runtime_error(
                va,
                X86XstateRestoreError::GeneralProtection(
                    carrick_dsr_x86::X86XstateRestoreGpReason::MisalignedAddress,
                ),
            ),
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGSEGV,
                code: crate::linux_abi::LINUX_SI_KERNEL,
                address: 0,
            }
        );
        for (kind, code) in [
            (
                carrick_guest_mem::protections::GuestMemoryFaultKind::Unmapped,
                crate::linux_abi::LINUX_SEGV_MAPERR,
            ),
            (
                carrick_guest_mem::protections::GuestMemoryFaultKind::AccessDenied,
                crate::linux_abi::LINUX_SEGV_ACCERR,
            ),
        ] {
            assert_eq!(
                xstate_emulation_runtime_error(
                    va,
                    X86XstateRestoreError::Read(IdentityCheckedReadError::Fault(
                        carrick_guest_mem::protections::GuestMemoryFault {
                            address: GuestVa(va + 0x80),
                            kind,
                        },
                    )),
                ),
                X86XstateServiceError::Signal {
                    signum: crate::linux_abi::LINUX_SIGSEGV,
                    code,
                    address: va + 0x80,
                }
            );
        }
        assert_eq!(
            xstate_emulation_runtime_error(
                va,
                X86XstateRestoreError::Read(IdentityCheckedReadError::BusAddress {
                    address: GuestVa(va + 0x200),
                }),
            ),
            X86XstateServiceError::Signal {
                signum: crate::linux_abi::LINUX_SIGBUS,
                code: crate::linux_abi::LINUX_BUS_ADRERR,
                address: va + 0x200,
            }
        );
        assert!(matches!(
            xstate_emulation_runtime_error(
                va,
                X86XstateRestoreError::Read(IdentityCheckedReadError::Backend {
                    address: GuestVa(va + 0x40),
                    detail: "injected impossible copy failure".into(),
                }),
            ),
            X86XstateServiceError::Fatal(detail)
                if detail.contains("failed internally") && detail.contains("injected")
        ));
    }

    #[test]
    fn xstate_restore_cannot_reach_the_memory_unaware_sensitive_service() {
        let snapshot = X86UcontextSnapshot::new();
        let mut actual = snapshot.clone();
        let error = service_sensitive(
            carrick_dsr_x86::decode::X86SensitiveKind::XstateRestore(
                carrick_dsr_x86::X86XstateRestoreKind::Xrstor,
            ),
            &mut actual,
        )
        .expect_err("memory-unaware XRSTOR must fail closed");
        assert!(matches!(
            error,
            X86SensitiveServiceError::Fatal(detail)
                if detail.contains("memory-unaware service_sensitive path")
        ));
        assert_eq!(actual.gpr, snapshot.gpr);
        assert_eq!(actual.rip, snapshot.rip);
        assert_eq!(actual.rflags, snapshot.rflags);
        assert_eq!(actual.pkru(), snapshot.pkru());
        assert_eq!(actual.xsave, snapshot.xsave);
    }

    #[test]
    fn disabled_cet_shadow_stack_read_preserves_complete_guest_state() {
        use carrick_dsr_x86::decode::X86SensitiveKind::ReadShadowStackPointer;

        let mut snapshot = X86UcontextSnapshot::new();
        for (index, value) in snapshot.gpr.iter_mut().enumerate() {
            *value = 0x1122_3344_5566_7700 | index as u64;
        }
        snapshot.rip = 0x1234_5678;
        snapshot.rflags = 0xcd7;
        let before = snapshot.clone();

        service_sensitive(ReadShadowStackPointer, &mut snapshot)
            .expect("disabled CET RDSSP must be a compatibility no-op");

        assert_eq!(snapshot.gpr, before.gpr);
        assert_eq!(snapshot.rip, before.rip);
        assert_eq!(snapshot.rflags, before.rflags);
        assert_eq!(snapshot.pkru(), before.pkru());
        assert_eq!(snapshot.xsave, before.xsave);
    }

    #[test]
    fn xstate_probe_flags_keep_transition_decisions_distinct() {
        let flags = NativeX86XstateDecision {
            source_uses_fpu: true,
            target_uses_fpu: false,
            has_edges: true,
            save_required: true,
            cache_hit: false,
            unsafe_local_policy: true,
            target_barrier_policy: false,
        }
        .flags();
        assert_eq!(flags, 0b10_1101);

        let target_barrier = NativeX86XstateDecision {
            target_barrier_policy: true,
            ..NativeX86XstateDecision::default()
        }
        .flags();
        assert_eq!(target_barrier, 0b100_0000);
    }

    #[test]
    fn fork_child_guest_cpu_reset_clears_inherited_child_accounting() {
        crate::guest_cpu::add_reaped_child(12_345, 6_789);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if crate::guest_cpu::child_user_us() < 12_345
                || crate::guest_cpu::child_system_us() < 6_789
            {
                unsafe { libc::_exit(91) };
            }
            crate::guest_cpu::reset();
            let clean =
                crate::guest_cpu::child_user_us() == 0 && crate::guest_cpu::child_system_us() == 0;
            unsafe { libc::_exit(if clean { 0 } else { 92 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn fork_transport_arrival_is_delivered_only_after_child_reset_window() {
        install_native_pumped_handlers();
        NATIVE_CHILD_EXIT_DIRTY.store(false, std::sync::atomic::Ordering::Release);
        let previous = block_native_transport_signals_for_fork().expect("block transports");
        assert_eq!(unsafe { libc::raise(libc::SIGCHLD) }, 0);
        assert!(
            !NATIVE_CHILD_EXIT_DIRTY.load(std::sync::atomic::Ordering::Acquire),
            "blocked transport published inside the reset window"
        );
        // Model the child pending-state erasure, then perform the required LAST
        // unblock. The kernel-pending SIGCHLD must publish afterward, not before.
        NATIVE_CHILD_EXIT_DIRTY.store(false, std::sync::atomic::Ordering::Release);
        unblock_native_transport_signals_after_fork();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !NATIVE_CHILD_EXIT_DIRTY.load(std::sync::atomic::Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "SIGCHLD stayed blocked"
            );
            std::thread::yield_now();
        }
        restore_native_host_signal_mask(&previous);
    }

    #[test]
    fn post_fork_reset_unblocks_runtime_transport_signals() {
        // Model the transient host mask observed in the wedged GNU make child.
        // Query and restore the test thread's original mask before asserting so
        // a failing assertion cannot poison another test on this worker thread.
        unsafe {
            let mut original: libc::sigset_t = std::mem::zeroed();
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            let mut current: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut original),
                0
            );
            libc::sigemptyset(&mut blocked);
            let transport = [
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                libc::SIGCHLD,
                FREEBSD_NATIVE_EXIT_KICK_SIGNAL,
                FREEBSD_NATIVE_EXIT_KICK_SIGNAL + 1,
            ];
            for signal in transport {
                libc::sigaddset(&mut blocked, signal);
            }
            assert_eq!(
                libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()),
                0
            );

            unblock_native_transport_signals_after_fork();
            assert_eq!(
                libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut current),
                0
            );
            let still_blocked = transport
                .into_iter()
                .filter(|signal| libc::sigismember(&current, *signal) == 1)
                .collect::<Vec<_>>();
            libc::sigprocmask(libc::SIG_SETMASK, &original, std::ptr::null_mut());
            assert!(still_blocked.is_empty(), "still blocked: {still_blocked:?}");
        }
    }

    #[test]
    fn initial_stack_keeps_large_exec_vectors_inside_the_stack_mapping() {
        let bytes =
            include_bytes!("../../carrick-dsr-x86/tests/fixtures/identity-loop-x86_64-linux");
        let elf = Elf::parse(bytes).unwrap();
        let mut stack = vec![0_u8; GUEST_STACK_LEN];
        let stack_bottom = stack.as_mut_ptr() as u64;
        let stack_top = stack_bottom + stack.len() as u64;
        let argv: Vec<Vec<u8>> = (0..160)
            .map(|index| format!("argument-{index:03}-{}", "x".repeat(40)).into_bytes())
            .collect();
        let env = vec![b"PATH=/bin:/usr/bin".to_vec()];

        let rsp =
            build_initial_stack(stack_top, &argv, &env, &elf, 0x400040, 0x401000, 0, 0).unwrap();

        assert!(rsp >= stack_bottom);
        assert!(rsp < stack_top);
        // SAFETY: `rsp` and the vector slots were written into `stack` above.
        assert_eq!(unsafe { *(rsp as *const u64) }, argv.len() as u64);
        for (index, expected) in argv.iter().enumerate() {
            // SAFETY: each argv slot is within the checked stack vector.
            let ptr = unsafe { *((rsp + 8 + index as u64 * 8) as *const u64) };
            assert!((stack_bottom..stack_top).contains(&ptr));
            // SAFETY: every pointed-to argument was copied into `stack` with a
            // trailing NUL; `expected.len()` remains within that allocation.
            let actual = unsafe { std::slice::from_raw_parts(ptr as *const u8, expected.len()) };
            assert_eq!(actual, expected);
        }
    }
}

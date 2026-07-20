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

use std::path::Path;
use std::sync::Arc;

use carrick_dsr::host::{JitRegion, NativeHostJit};
use carrick_dsr_x86::block::{X86Block, X86Exit};
use carrick_dsr_x86::decode::{X86InstClass, classify};
use carrick_dsr_x86::gateway::{CTX_FAULT_RECORD, kick_stub_addr, reg, signal_stub_addr};
use carrick_dsr_x86::{
    X86DsrContext, X86ExitStatus, X86UcontextSnapshot, cflow,
    emit::{ScratchRestore, emit_block_linked},
    plan_block,
};
use carrick_guest_mem::{GuestMemory, X8664SyscallFrame};
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_hal::{GuestArch, Reg, RegAccess};
use carrick_native_freebsd::{FreebsdHostJit, fault};
use goblin::elf::Elf;
use goblin::elf::header::{EM_X86_64, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};

use carrick_mem::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, mmap_arena_size};

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
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
    heap: u64,
    heap_len: usize,
    mmap: u64,
    mmap_len: usize,
}

impl GuestArenas {
    fn reserve() -> Result<Self, RuntimeError> {
        let heap_len = LINUX_HEAP_SIZE as usize;
        let mmap_len = mmap_arena_size() as usize;
        let heap = reserve_fixed_rw(LINUX_HEAP_BASE, heap_len).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "reserve guest heap arena at 0x{LINUX_HEAP_BASE:x} ({heap_len} bytes) failed"
            ))
        })?;
        let mmap = match reserve_fixed_rw(LINUX_MMAP_BASE, mmap_len) {
            Some(a) => a,
            None => {
                // SAFETY: unmapping the heap arena we just reserved.
                unsafe { libc::munmap(heap as *mut libc::c_void, heap_len) };
                return Err(RuntimeError::Unsupported(format!(
                    "reserve guest mmap arena at 0x{LINUX_MMAP_BASE:x} ({mmap_len} bytes) failed"
                )));
            }
        };
        Ok(Self {
            heap,
            heap_len,
            mmap,
            mmap_len,
        })
    }

    fn teardown(&self) {
        // SAFETY: unmapping the arenas this struct reserved.
        unsafe {
            libc::munmap(self.heap as *mut libc::c_void, self.heap_len);
            libc::munmap(self.mmap as *mut libc::c_void, self.mmap_len);
        }
    }
}

/// Reserve `[base, base+len)` as anonymous RW at EXACTLY `base` (MAP_FIXED).
/// Returns `None` if the kernel could not place it there.
fn reserve_fixed_rw(base: u64, len: usize) -> Option<u64> {
    let p = map_prot(len, libc::PROT_READ | libc::PROT_WRITE, Some(base));
    if p as isize == -1 || p as u64 != base {
        None
    } else {
        Some(p as u64)
    }
}

fn remap_exec_arenas() -> Result<(), RuntimeError> {
    for (base, len, name) in [
        (LINUX_HEAP_BASE, LINUX_HEAP_SIZE as usize, "heap"),
        (LINUX_MMAP_BASE, mmap_arena_size() as usize, "mmap"),
    ] {
        if reserve_fixed_rw(base, len).is_none() {
            return Err(RuntimeError::Unsupported(format!(
                "exec: remap private {name} arena at 0x{base:x} ({len} bytes) failed"
            )));
        }
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
struct IdentityGuestMemory;

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

/// Linux x86-64 userspace occupies the low canonical half. Reject a raw range
/// before turning it into a host pointer if it crosses that boundary, wraps, or
/// exceeds Rust's slice size limit. This is a syscall-memory boundary: malformed
/// guest pointers must become EFAULT, never a host SIGSEGV or slice UB.
fn identity_raw_range_valid(address: u64, length: usize) -> bool {
    if length == 0 {
        return true;
    }
    const X86_64_USER_END_EXCLUSIVE: u64 = 1 << 47;
    // Carrick exposes Linux's default `/proc/sys/vm/mmap_min_addr` (64 KiB);
    // no guest mapping can legally back a syscall pointer below it.
    const LINUX_MMAP_MIN_ADDR: u64 = 0x1_0000;
    address >= LINUX_MMAP_MIN_ADDR
        && length <= isize::MAX as usize
        && address
            .checked_add(length.saturating_sub(1) as u64)
            .is_some_and(|end| end < X86_64_USER_END_EXCLUSIVE)
}

#[cfg(test)]
mod identity_raw_range_tests {
    use super::{
        IDENTITY_PROTECTIONS, IdentityGuestMemory, PublishedFaultEntry, SharedWaitAssignment,
        calibrate_x86_vvar_clock, exclude_vfork_shared_ranges, freebsd_shared_waiter_key,
        host_clock_ns, identity_raw_range_valid, init_shared_waiter_table, parse_loadable_elf,
        recover_x86_fault_snapshot, shared_futex_requeue_umtx, shared_futex_wake_umtx,
        shared_waiter_slot, take_shared_wait_assignment, tsc_ns, wait_requeued_umtx,
    };
    use carrick_guest_mem::GuestMemory;
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
        let memory = IdentityGuestMemory;
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
            restores: vec![carrick_dsr_x86::emit::ScratchRestore {
                snapshot_gpr: carrick_dsr_x86::gateway::reg::RAX,
                scratch_index: 0,
            }],
        }];

        assert_eq!(
            recover_x86_fault_snapshot(&entries, &context, &mut snapshot),
            Some(0x4010)
        );
        assert_eq!(snapshot.rip, 0x4010);
        assert_eq!(snapshot.gpr[carrick_dsr_x86::gateway::reg::RAX], 0x1234);
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

/// Process-wide syscall-path protection metadata for the identity lane. Because
/// `IdentityGuestMemory` is a stateless unit struct constructed at every call
/// site, the VMA-classification sets (`no_access` / `no_write` / post-`munmap`
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
/// Advances on mapping/protection transitions that can change executable bytes
/// or eligibility. Threads invalidate their translated metadata at the next
/// gateway boundary; no host syscall is added to block entry.
static IDENTITY_CODE_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Re-establish host backing for `[address, address+len)` IFF it overlaps a
/// tracked `munmap` hole. Guest `munmap`/`mremap`-shrink genuinely releases the
/// pages (so JIT accesses fault and `mincore` reports unmapped), but when the
/// dispatcher then re-establishes a mapping over that VA (mmap-reuse, mremap
/// grow tail / move destination) the host pages must exist again before its
/// zero/copy raw writes touch them — otherwise the runtime itself faults. A
/// `MAP_FIXED` anonymous RW remap fills the hole with zeroed pages; ranges with
/// no hole (e.g. a live-data `mprotect`) are left untouched so content survives.
fn ensure_identity_backed(address: u64, len: usize) {
    if len == 0 || address < PAGE {
        return;
    }
    let tracked_hole = IDENTITY_PROTECTIONS.range_unmapped(address, len);
    let mut residency = 0u8;
    // `mincore` is a non-faulting host mapping query. A fresh shared-aperture
    // allocation (high guest VA) was boot-backed on VMM lanes but has no host
    // mapping in the identity lane, while a recycled low-arena range is marked
    // explicitly as a hole. Either case needs backing before dispatcher code
    // touches it; an existing live/PROT_NONE mapping must remain intact.
    let start_is_mapped = unsafe {
        libc::mincore(
            address as *mut libc::c_void,
            PAGE as usize,
            (&mut residency as *mut u8).cast::<libc::c_char>(),
        ) == 0
    };
    if !tracked_hole && start_is_mapped {
        return;
    }
    // SAFETY: identity VA; MAP_FIXED atomically fills the absent/freed range
    // with fresh zero-filled anonymous RW pages. Use MAP_SHARED because the only
    // initially-unbacked dispatcher allocation is the shared aperture; a later
    // MapHostAlias outcome replaces private/file aliases with their exact
    // backing before returning to the guest.
    unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        );
    }
    // The range is mapped again — drop its unmapped/no-access gate.
    IDENTITY_PROTECTIONS.set_unmapped(address, len, false);
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
        if !no_access {
            // Transition back to accessible: re-establish backing if this range
            // was a munmap hole, so a following raw scrub/copy does not fault.
            ensure_identity_backed(address, len);
        }
        IDENTITY_PROTECTIONS.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        IDENTITY_PROTECTIONS.set_no_write(address, len, no_write);
    }

    fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
        // Route straight to the shared metadata's `set_unmapped` — the trait
        // DEFAULT would call `set_no_access(true)`, which reclassifies the hole
        // out of the `unmapped` set (that setter clears it), and then
        // `ensure_identity_backed`'s `range_unmapped` check would miss the hole
        // and never re-back a reused munmap range (a guest fault on mremap-grow).
        if !unmapped {
            ensure_identity_backed(address, len);
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
        // Establishing a mapping over a range that was a munmap hole (mmap-reuse,
        // mremap grow tail / move destination) must re-back the host pages FIRST,
        // so the dispatcher's subsequent zero/copy raw writes land on real pages
        // instead of faulting the host. A guest `mprotect` on LIVE data hits no
        // hole, so its content is left intact (no re-map).
        ensure_identity_backed(address, len);
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, no_access, no_write);
    }

    fn protect_range(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        ensure_identity_backed(address, len);
        let had_executable = IDENTITY_PROTECTIONS.range_has_executable(address, len);
        let readable =
            prot & (crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC) != 0;
        let writable = prot & crate::linux_abi::LINUX_PROT_WRITE != 0;
        let executable = prot & crate::linux_abi::LINUX_PROT_EXEC != 0;
        // DSR never executes guest pages directly: executable mappings need a
        // host-readable translation view, not host PROT_EXEC. Enforce guest
        // stores with host read-only pages and PROT_NONE with inaccessible ones.
        let host_prot = match (readable, writable) {
            (_, true) => libc::PROT_READ | libc::PROT_WRITE,
            (true, false) => libc::PROT_READ,
            (false, false) => libc::PROT_NONE,
        };
        if unsafe { libc::mprotect(address as *mut libc::c_void, len, host_prot) } != 0 {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, prot == 0, !writable);
        IDENTITY_PROTECTIONS.set_executable(address, len, executable);
        // Data-only mmap/mprotect churn (especially one stack per pthread) does
        // not invalidate translated code. Rebuild only when execute permission
        // changes; otherwise every new thread forces every sibling to discard
        // and duplicate its JIT cache.
        if had_executable != executable {
            IDENTITY_CODE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        Ok(())
    }

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        // A length-0 read is a no-op — but `from_raw_parts` still requires a
        // non-null, aligned pointer even for len 0, and a syscall with an empty
        // buffer at a null/unset pointer is legal (e.g. clone's ptid/ctid when
        // the flag is off), so short-circuit rather than form a slice from null.
        if length == 0 {
            return Ok(Vec::new());
        }
        // A null-page, wrapping, or non-canonical guest range is never a valid
        // Linux userspace mapping. Surface it as EFAULT before constructing a
        // host slice (`mlock2`, legacy-aio, and sched-thread bad-pointer probes).
        if !identity_raw_range_valid(address, length)
            || IDENTITY_PROTECTIONS.range_unmapped(address, length)
        {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds { address, length });
        }
        // SAFETY: identity map — `address` is a host VA; the caller asserts the
        // range is guest-mapped.
        Ok(unsafe { std::slice::from_raw_parts(address as *const u8, length).to_vec() })
    }

    fn write_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        if !bytes.is_empty() && IDENTITY_PROTECTIONS.range_write_denied(address, bytes.len()) {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn write_bytes_raw(
        &mut self,
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
        // SAFETY: identity map — `address` is a host VA into a guest-writable
        // mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
        }
        Ok(())
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
        let had_executable = IDENTITY_PROTECTIONS.range_has_executable(address, len);
        // SAFETY: identity VA; releasing guest-owned host pages. A partial/failed
        // munmap is non-fatal here — the range is being torn down regardless.
        unsafe {
            libc::munmap(address as *mut libc::c_void, len);
        }
        // Record the hole so a syscall-path read/write returns EFAULT (not a host
        // fault) and mincore reports it unmapped; a guest JIT access still faults
        // the real hole and is caught by the fault shim as SEGV_MAPERR.
        IDENTITY_PROTECTIONS.set_unmapped(address, len, true);
        if had_executable {
            IDENTITY_CODE_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        Ok(())
    }

    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        // VMM backends repoint stage-1 into a private overlay IPA. Identity
        // execution has no page tables, so replace this process's mapping at the
        // guest VA with an anonymous MAP_PRIVATE object. Across host fork this
        // detaches the child from the inherited shared object exactly like
        // Linux MAP_FIXED|MAP_PRIVATE.
        let mapped = unsafe {
            libc::mmap(
                va as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED || mapped as u64 != va {
            return Err(carrick_guest_mem::MemoryError::OutOfBounds {
                address: va,
                length: len,
            });
        }
        if !content.is_empty() {
            self.write_bytes_raw(va, content)?;
        }
        IDENTITY_PROTECTIONS.set_mapping_protection(va, len, false, false);
        Ok(())
    }

    /// Scrub a reused/`MAP_FIXED` anonymous region to zero. If a prior
    /// `unmap_range` left this VA a hole, the default raw-write scrub would fault
    /// the host, so first re-establish zero-filled RW backing with an anonymous
    /// `MAP_FIXED` remap (which both maps and zeroes); an already-mapped region is
    /// scrubbed in place. Callers exclude file/alias regions, so the anonymous
    /// remap never clobbers file-backed content.
    fn zero_backing(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        if len == 0 {
            return Ok(());
        }
        // SAFETY: identity VA. MAP_FIXED atomically replaces any current mapping
        // (or fills a munmap hole) with fresh zero-filled anonymous RW pages.
        let p = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED || p as u64 != address {
            // Remap failed (out of arena, etc.): fall back to a gated raw scrub,
            // which is correct whenever the range is already mapped.
            return carrick_guest_mem::zero_range_chunked(address, len, |addr, bytes| {
                self.write_bytes_raw(addr, bytes)
            });
        }
        // The range is mapped + zeroed again: clear any stale unmapped/no-access
        // gate so a reused hole is syscall-accessible.
        IDENTITY_PROTECTIONS.set_mapping_protection(address, len, false, false);
        // Fresh anonymous pages are already zero.
        Ok(())
    }

    fn host_ptr_for_read(&self, address: u64, len: usize) -> Option<*const u8> {
        (identity_raw_range_valid(address, len)
            && !IDENTITY_PROTECTIONS.range_unmapped(address, len)
            && !IDENTITY_PROTECTIONS.range_no_access(address, len))
        .then_some(address as *const u8)
    }

    fn host_ptr_for_write(&mut self, address: u64, len: usize) -> Option<*mut u8> {
        (identity_raw_range_valid(address, len)
            && !IDENTITY_PROTECTIONS.range_unmapped(address, len)
            && !IDENTITY_PROTECTIONS.range_write_denied(address, len))
        .then_some(address as *mut u8)
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
        let host_addr = guest_addr as usize;
        Some(carrick_guest_mem::SharedFutexLocation::Direct {
            word: carrick_guest_mem::HostVa(host_addr),
            waiter_key: freebsd_shared_waiter_key(host_addr).unwrap_or(host_addr),
        })
    }
}

/// A `RegAccess + GuestMemory` view over a live `X86UcontextSnapshot`, so the
/// shared, byte-exact x86-64 `rt_sigframe` builder/restorer
/// ([`X8664GuestArch::build_sigframe`] / [`restore_sigframe`]) drives THIS
/// lane's snapshot directly. Register reads/writes hit the snapshot fields;
/// memory reads/writes are identity (guest VA == host VA). FP save/restore is
/// disabled for now (`fpsimd_enabled = false`), so the vector getters are never
/// called.
struct SigframeEngine<'a> {
    snap: &'a mut X86UcontextSnapshot,
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

    fn read_bytes_raw(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
        IdentityGuestMemory.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_mem::MemoryError> {
        IdentityGuestMemory.write_bytes_raw(address, bytes)
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
        fpsimd_enabled: false,
        sigreturn_trampoline_base: shared.current_image().sigreturn_trampoline,
    };
    let mut engine = SigframeEngine { snap: snapshot };
    match X8664GuestArch::build_sigframe(&mut engine, params) {
        Ok(_) => Ok(true),
        Err(_) => Err(()),
    }
}

/// Restore guest state from the x86-64 `rt_sigframe` at the guest stack on
/// `rt_sigreturn(2)`, restore the saved signal mask, and return the resume RIP.
fn restore_x86_sigreturn(
    shared: &Arc<SharedRun>,
    tid: crate::thread::ThreadId,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<u64, ()> {
    let mut engine = SigframeEngine { snap: snapshot };
    let restore = X8664GuestArch::restore_sigframe(&mut engine, false).map_err(|_| ())?;
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
            fpsimd_enabled: false,
            sigreturn_trampoline_base: self.sigreturn_trampoline,
        };
        let mut engine = SigframeEngine { snap: self.snap };
        X8664GuestArch::build_sigframe(&mut engine, params).map(|_| ())
    }
    fn restore_from_sigframe(&mut self) -> Result<u64, carrick_hal::TrapError> {
        let mut engine = SigframeEngine { snap: self.snap };
        let restore = X8664GuestArch::restore_sigframe(&mut engine, false)?;
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
    drain_native_child_exit_watches(false);
    let mut trap = NativeX86Trap {
        snap: snapshot,
        last_syscall_nr: syscall_nr,
        orig_rax,
        sigreturn_trampoline: shared.current_image().sigreturn_trampoline,
    };
    let action = crate::vcpu_loop::deliver_pending_signal(
        &mut trap,
        &shared.dispatcher,
        last_retval,
        tid,
        None,
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
        Err(_) => {}
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
    /// Main executable and optional PT_INTERP reservations. They are distinct
    /// VM spans and must both survive until exec/teardown.
    spans: Vec<(u64, usize)>,
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
    vdso_base: u64,
    /// Page-rounded length of the mapped vDSO image, for teardown.
    vdso_len: usize,
    /// The page-rounded [start, end) VA ranges of the mapped PT_LOAD segments,
    /// sorted and coalesced. The reserved span can contain UNMAPPED gaps
    /// between segments; the block planner must not read across one (it would
    /// fault or decode garbage), so `code_bytes` reads only up to the end of
    /// the range containing a VA.
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
fn reset_identity_vmas(image: &LoadedImage) {
    const USER_START: u64 = 0x1_0000;
    const USER_END_EXCLUSIVE: u64 = 1 << 47;
    IDENTITY_PROTECTIONS.reset_to_unmapped(USER_START, (USER_END_EXCLUSIVE - USER_START) as usize);
    let mut memory = IdentityGuestMemory;
    for &(start, end, prot) in &image.segment_protections {
        let len = (end - start) as usize;
        // Loader mappings already have backing. Publish them live before
        // protect_range so its mmap-hole recovery cannot MAP_FIXED fresh zero
        // pages over the loaded ELF/vDSO bytes.
        IDENTITY_PROTECTIONS.set_mapping_protection(start, len, false, false);
        let _ = memory.protect_range(start, len, prot);
    }
    IDENTITY_PROTECTIONS.set_mapping_protection(image.stack, image.stack_len, false, false);
    let _ = memory.protect_range(
        image.stack,
        image.stack_len,
        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
    );
    IDENTITY_PROTECTIONS.set_mapping_protection(
        LINUX_HEAP_BASE,
        LINUX_HEAP_SIZE as usize,
        false,
        false,
    );
    IDENTITY_PROTECTIONS.set_mapping_protection(
        LINUX_MMAP_BASE,
        mmap_arena_size() as usize,
        false,
        false,
    );
    if image.vdso_base != 0 {
        IDENTITY_PROTECTIONS.set_mapping_protection(
            crate::vdso::LINUX_VVAR_BASE,
            crate::vdso::LINUX_VVAR_SIZE as usize,
            false,
            false,
        );
    }
}

impl LoadedImage {
    /// Unmap everything the loader mapped.
    fn teardown(&self) {
        // SAFETY: teardown of mappings this loader owns; nothing executes from
        // them once the run loop has returned.
        unsafe {
            for &(span_base, span_len) in &self.spans {
                libc::munmap(span_base as *mut libc::c_void, span_len);
            }
            libc::munmap(self.stack as *mut libc::c_void, self.stack_len);
            libc::munmap(self.scratch as *mut libc::c_void, self.scratch_len);
            if self.vdso_base != 0 {
                libc::munmap(self.vdso_base as *mut libc::c_void, self.vdso_len);
                libc::munmap(
                    crate::vdso::LINUX_VVAR_BASE as *mut libc::c_void,
                    crate::vdso::LINUX_VVAR_SIZE as usize,
                );
            }
        }
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

fn map_prot(len: usize, prot: i32, fixed_at: Option<u64>) -> *mut u8 {
    let (addr, flags) = match fixed_at {
        Some(a) => (
            a as *mut libc::c_void,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
        ),
        None => (std::ptr::null_mut(), libc::MAP_PRIVATE | libc::MAP_ANON),
    };
    // SAFETY: an anonymous mapping request we own.
    unsafe { libc::mmap(addr, len, prot, flags, -1, 0) }.cast()
}

struct MappedElf {
    span: (u64, usize),
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
fn map_one_elf(bytes: &[u8], apply_relative_relocations: bool) -> Result<MappedElf, RuntimeError> {
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
    let (span, bias) = match elf.header.e_type {
        ET_DYN => {
            let span = map_prot(span_len, libc::PROT_NONE, None);
            if span as isize == -1 {
                return Err(RuntimeError::Unsupported(
                    "reserve guest PIE span failed".to_string(),
                ));
            }
            (span, span as u64 - lo)
        }
        ET_EXEC => {
            let span = map_prot(span_len, libc::PROT_NONE, Some(lo));
            if span as isize == -1 || span as u64 != lo {
                return Err(RuntimeError::Unsupported(format!(
                    "reserve fixed guest executable span at 0x{lo:x} failed"
                )));
            }
            (span, 0)
        }
        other => {
            return Err(RuntimeError::Unsupported(format!(
                "native x86 lane requires ET_DYN or ET_EXEC, found ELF type {other}"
            )));
        }
    };

    let mut segments = Vec::new();
    let mut protections = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_lo = (ph.p_vaddr & !(PAGE - 1)) + bias;
        let seg_hi = ((ph.p_vaddr + ph.p_memsz + PAGE - 1) & !(PAGE - 1)) + bias;
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
        let addr = map_prot(
            (seg_hi - seg_lo) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            Some(seg_lo),
        );
        if addr as u64 != seg_lo {
            return Err(RuntimeError::Unsupported(format!(
                "MAP_FIXED segment at 0x{seg_lo:x} failed"
            )));
        }
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
        span: (span as u64, span_len),
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
    let elf =
        Elf::parse(bytes).map_err(|e| RuntimeError::Unsupported(format!("parse ELF: {e}")))?;
    let main = map_one_elf(bytes, interpreter_bytes.is_none())?;
    let interpreter = interpreter_bytes
        .map(|bytes| map_one_elf(bytes, false))
        .transpose()?;
    let mut segments = main.segments.clone();
    let mut segment_protections = main.protections.clone();
    let mut spans = vec![main.span];
    if let Some(interpreter) = &interpreter {
        segments.extend(interpreter.segments.iter().copied());
        segment_protections.extend(interpreter.protections.iter().copied());
        spans.push(interpreter.span);
    }

    let stack = map_prot(GUEST_STACK_LEN, libc::PROT_READ | libc::PROT_WRITE, None);
    if stack as isize == -1 {
        return Err(RuntimeError::Unsupported(
            "guest stack mmap failed".to_string(),
        ));
    }
    let scratch = map_prot(PAGE as usize, libc::PROT_READ | libc::PROT_WRITE, None);

    // Map the synthesized x86-64 vDSO so `getauxval(AT_SYSINFO_EHDR)` resolves
    // and `__vdso_clock_gettime`/`__vdso_gettimeofday`/`__vdso_time` resolve to
    // real, callable fast paths. Stamp FreeBSD's invariant-TSC frequency and
    // calibrated realtime/monotonic offsets into the vvar page; if calibration
    // is unavailable, its zero frequency deliberately selects the syscall
    // fallback. The vDSO code references the vvar at the fixed absolute
    // `LINUX_VVAR_BASE`, so that page must be mapped there exactly; the image is
    // position-
    // independent and published to the guest via `AT_SYSINFO_EHDR`.
    let (vdso_base, vdso_len) = {
        let vvar_base = crate::vdso::LINUX_VVAR_BASE;
        let vdso_base = crate::vdso::LINUX_VDSO_BASE;
        let vvar = map_prot(
            crate::vdso::LINUX_VVAR_SIZE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            Some(vvar_base),
        );
        let vdso_bytes = crate::vdso::x8664_vdso_image_bytes();
        let vdso_len = ((vdso_bytes.len() as u64 + PAGE - 1) & !(PAGE - 1)) as usize;
        let vdso = map_prot(
            vdso_len,
            libc::PROT_READ | libc::PROT_WRITE,
            Some(vdso_base),
        );
        if vvar as u64 == vvar_base && vdso as u64 == vdso_base {
            // SAFETY: `vvar` is the freshly-mapped RW vvar page. Zeroing first
            // keeps frequency=0 as the fail-safe syscall fallback.
            unsafe {
                std::ptr::write_bytes(vvar as *mut u8, 0, crate::vdso::LINUX_VVAR_SIZE as usize)
            };
            let _ = stamp_x86_vvar(vvar);
            // SAFETY: `vdso` is the freshly-mapped RW page(s); the image fits.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    vdso_bytes.as_ptr(),
                    vdso as *mut u8,
                    vdso_bytes.len(),
                )
            };
            // Publish the vDSO code page(s) as a translatable segment so the
            // block planner can read/execute the resolved stubs.
            segments.push((vdso_base, vdso_base + vdso_len as u64));
            segment_protections.push((
                vdso_base,
                vdso_base + vdso_len as u64,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            ));
            (vdso_base, vdso_len)
        } else {
            // Could not place the vvar/vDSO at their required VAs — run without
            // a vDSO (auxv omits AT_SYSINFO_EHDR; the guest uses raw syscalls).
            if vvar as isize != -1 && vvar as u64 != vvar_base {
                // SAFETY: unmap the misplaced vvar mapping we just made.
                unsafe {
                    libc::munmap(
                        vvar as *mut libc::c_void,
                        crate::vdso::LINUX_VVAR_SIZE as usize,
                    )
                };
            }
            if vdso as isize != -1 && vdso as u64 != vdso_base {
                // SAFETY: unmap the misplaced vDSO mapping we just made.
                unsafe { libc::munmap(vdso as *mut libc::c_void, vdso_len) };
            }
            (0, 0)
        }
    };

    let rsp = build_initial_stack(
        stack as u64 + GUEST_STACK_LEN as u64,
        scratch as u64,
        argv,
        env,
        &elf,
        main.phdr,
        main.entry,
        interpreter.as_ref().map_or(0, |image| image.bias),
        vdso_base,
    );

    // The rt_sigreturn trampoline: when a guest signal handler was registered
    // WITHOUT an explicit sa_restorer (Linux falls back to the kernel VDSO
    // `__kernel_rt_sigreturn`), the sigframe's pretcode points here so the
    // handler's `ret` lands on `mov $15, %eax; syscall` (rt_sigreturn). Placed
    // in the scratch page's tail (argv data lives at its head) and published as
    // a translatable code segment.
    const SIGRETURN_STUB: [u8; 7] = [0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let sigreturn_trampoline = scratch as u64 + PAGE - SIGRETURN_STUB.len() as u64;
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
    segments.push((scratch as u64, scratch as u64 + PAGE));
    // argv strings and AT_RANDOM remain writable, while the tail hosts the
    // translated rt_sigreturn stub: Linux page granularity makes this RWX.
    segment_protections.push((
        scratch as u64,
        scratch as u64 + PAGE,
        crate::linux_abi::LINUX_PROT_READ
            | crate::linux_abi::LINUX_PROT_WRITE
            | crate::linux_abi::LINUX_PROT_EXEC,
    ));

    // Sort + coalesce adjacent segments so `code_bytes` can read across
    // touching PT_LOADs but never across a real gap.
    segments.sort_unstable();
    let mut coalesced: Vec<(u64, u64)> = Vec::with_capacity(segments.len());
    for (s, e) in segments {
        match coalesced.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => coalesced.push((s, e)),
        }
    }

    Ok(LoadedImage {
        spans,
        entry: interpreter.as_ref().map_or(main.entry, |image| image.entry),
        stack: stack as u64,
        stack_len: GUEST_STACK_LEN,
        rsp,
        scratch: scratch as u64,
        scratch_len: PAGE as usize,
        sigreturn_trampoline,
        vdso_base,
        vdso_len,
        segments: coalesced,
        segment_protections,
    })
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
/// strings and a 16-byte AT_RANDOM block in the scratch page. Returns the guest
/// rsp (argc), 16-aligned. argv/env are opaque Linux-ABI byte strings (a guest
/// execve may pass non-UTF-8 args/env), NUL-terminated in the scratch page.
fn build_initial_stack(
    stack_top: u64,
    scratch: u64,
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
    elf: &Elf,
    phdr_va: u64,
    main_entry: u64,
    interpreter_base: u64,
    vdso_base: u64,
) -> u64 {
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_ENTRY: u64 = 9;
    const AT_SYSINFO_EHDR: u64 = 33;
    const AT_RANDOM: u64 = 25;

    // Lay argv strings + AT_RANDOM into the scratch page.
    let mut cur = scratch;
    let random_ptr = cur;
    // 16 pseudo-random bytes (fixed here; a later rung seeds from the host).
    // SAFETY: scratch is a mapped RW page with room for these small writes.
    unsafe {
        std::ptr::write_bytes(random_ptr as *mut u8, 0x5a, 16);
    }
    cur += 16;
    // Lay argv, then env, byte strings (NUL-terminated) into the scratch page.
    let mut place = |bytes: &[u8]| -> u64 {
        let at = cur;
        // SAFETY: within the scratch page (argv/env for a probe is tiny).
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len());
            *((at + bytes.len() as u64) as *mut u8) = 0;
        }
        cur += bytes.len() as u64 + 1;
        at
    };
    let arg_ptrs: Vec<u64> = argv.iter().map(|a| place(a)).collect();
    let env_ptrs: Vec<u64> = env.iter().map(|e| place(e)).collect();

    // Build the stack image bottom-up as a word vector, then place it so argc
    // lands 16-aligned.
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64); // argc
    words.extend(arg_ptrs.iter().copied()); // argv[]
    words.push(0); // argv NULL
    words.extend(env_ptrs.iter().copied()); // envp[]
    words.push(0); // envp NULL
    // auxv pairs
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

    let bytes = (words.len() * 8) as u64;
    // 16-align argc; the ABI wants (rsp) 16-aligned at _start.
    let rsp = (stack_top - bytes) & !0xf;
    for (i, w) in words.iter().enumerate() {
        // SAFETY: within the guest stack mapping.
        unsafe { ((rsp + (i as u64) * 8) as *mut u64).write(*w) };
    }
    rsp
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
) {
    let rel = (target_exec as i64 - next_abs as i64) as i32;
    if let Some(w) = region.write_ptr_for(patch_abs as *mut u8) {
        // SAFETY: `w` is the RW alias of the 4-byte rel32 field inside the JIT.
        unsafe { std::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), w, 4) };
        jit.flush_icache(patch_abs as *mut u8, 4);
    }
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
// `guest_cpu::prepare_child_record_pre_fork` publishes its record reference
// through a process-global child-side stash. Serialize prepare+fork so a sibling
// guest thread cannot replace that stash before this fork snapshots it. An
// atomic guard is deliberate: unlike a pthread/std mutex it has no inherited
// waiter queue to strand in the multithreaded fork child; parent and child each
// release their COW copy with one store immediately after fork.
static FORK_IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct NativeForkGuard;

impl NativeForkGuard {
    fn acquire() -> Self {
        use std::sync::atomic::Ordering;
        while FORK_IN_PROGRESS
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        Self
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
    /// How many siblings have acknowledged `exec_stop` by leaving their run
    /// loop. The execing thread waits on this before retiring the old image so
    /// no sibling faults on a mapping being torn out from under it.
    exec_acks: std::sync::atomic::AtomicUsize,
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
            exec_acks: std::sync::atomic::AtomicUsize::new(0),
            vfork_waiting: std::sync::atomic::AtomicBool::new(false),
            vfork_wake,
        }
    }

    /// Signal every OTHER guest thread to stop for an `execve` takeover.
    fn request_exec_stop(&self) {
        self.exec_acks
            .store(0, std::sync::atomic::Ordering::Release);
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

    /// A sibling acknowledges it has left its run loop for the exec takeover.
    fn ack_exec_stop(&self) {
        self.exec_acks
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.cv.notify_all();
    }

    /// Park until at least `n` siblings have acked the stop. A condvar avoids
    /// amplifying one guest exec into hundreds of thousands of host
    /// `sched_yield(2)` calls while retaining the existing three-second
    /// backstop for an uninterruptible sibling.
    fn wait_exec_acks(&self, n: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut guard = self.code.lock().unwrap_or_else(|p| p.into_inner());
        while self.exec_acks.load(std::sync::atomic::Ordering::Acquire) < n {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            let waited = self
                .cv
                .wait_timeout(guard, deadline.saturating_duration_since(now));
            let (next_guard, _) = waited.unwrap_or_else(|p| p.into_inner());
            guard = next_guard;
        }
        drop(guard);
        // The takeover is complete; clear the flag so the new image's own
        // future threads are not spuriously stopped.
        self.exec_stop
            .store(false, std::sync::atomic::Ordering::Release);
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
    /// Join handles of spawned guest-thread host threads.
    threads: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Host pthreads currently executing guest threads. Process exit repeatedly
    /// sends the non-restarting native kick until every sibling unregisters,
    /// interrupting host `ppoll`, `_umtx_op`, `fcntl(F_SETLKW)`, and shared-word
    /// waits without polling or retaining raw guest addresses.
    host_threads:
        std::sync::Mutex<std::collections::HashMap<crate::thread::ThreadId, libc::pthread_t>>,
    host_threads_cv: std::sync::Condvar,
    exit: ExitState,
}

// SAFETY: the only non-`Send`/`Sync` field is `region`'s `NonNull` code-cache
// pointers. The region is immutable for the whole run; each guest thread writes
// ONLY into its own non-overlapping slice (via `write_ptr_for`) and executes
// only from that slice, so there is no data race on the shared reservation.
unsafe impl Send for SharedRun {}
unsafe impl Sync for SharedRun {}

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

    /// Join every spawned guest thread after process exit has been published.
    /// The exit wake makes even indefinitely parked siblings leave their run
    /// loops, so teardown no longer has to leak the JIT and guest arenas until
    /// host-process termination.
    fn join_threads(&self) {
        let handles = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|p| p.into_inner()));
        for handle in handles {
            let _ = handle.join();
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

/// Spawn a guest thread for a `CloneThread` outcome: register the child tid,
/// write the parent/child tid words, seed a cloned snapshot (rax=0, rsp=child
/// stack, fsbase=tls if CLONE_SETTLS), and run the per-thread loop on a fresh
/// host thread over its own JIT slice. Returns the child tid, or a negated
/// Linux errno the parent's `clone` should return.
fn spawn_clone_thread(
    shared: &Arc<SharedRun>,
    parent_tid: crate::thread::ThreadId,
    req: CloneThreadRequest,
) -> Result<crate::thread::ThreadId, i64> {
    let slice_off = match shared.alloc_slice() {
        Some(off) => off,
        // Out of JIT slices: Linux `clone` reports EAGAIN when it cannot
        // allocate a task's resources.
        None => return Err(crate::linux_abi::LINUX_EAGAIN.guest_retval()),
    };

    let child_tid = shared.registry.register_child(req.clear_child_tid_addr);
    shared
        .dispatcher
        .inherit_thread_signal_mask(parent_tid, child_tid);

    // Write the child tid into the parent/child tid words (identity memory).
    let tid_bytes = (child_tid.raw() as u32).to_le_bytes();
    if req.parent_tid_addr != 0 {
        // SAFETY: identity map — a guest-writable word.
        unsafe {
            std::ptr::copy_nonoverlapping(tid_bytes.as_ptr(), req.parent_tid_addr as *mut u8, 4);
        }
    }
    if req.child_tid_addr != 0 {
        // SAFETY: identity map — a guest-writable word.
        unsafe {
            std::ptr::copy_nonoverlapping(tid_bytes.as_ptr(), req.child_tid_addr as *mut u8, 4);
        }
    }

    // Clone the parent's register snapshot for the child: rax=0 (clone's child
    // return), rsp=child stack, resume at the post-syscall RIP.
    let mut child_snapshot = req.parent_snapshot;
    child_snapshot.gpr[reg::RAX] = 0;
    if req.stack != 0 {
        child_snapshot.gpr[reg::RSP] = req.stack;
    }
    child_snapshot.rip = req.resume;
    let child_fsbase = req.tls.unwrap_or(req.parent_fsbase);

    let child_shared = Arc::clone(shared);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let spawn = std::thread::Builder::new()
        .name(format!("carrick-guest-tid-{}", child_tid.raw()))
        .spawn(move || {
            // Publish readiness only AFTER the child is registered so the
            // parent's `clone` returns to a guest that can already observe the
            // child tid as live.
            let _ = ready_tx.send(());
            let mut memory = IdentityGuestMemory;
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
            );
            child_shared.free_slice(slice_off);
            match outcome {
                ThreadRunOutcome::Exit { code, .. } => child_shared.request_exit(code),
                ThreadRunOutcome::TrapLimit { .. } => child_shared.request_exit(125),
                ThreadRunOutcome::Fault { detail, .. } => {
                    let msg = format!("native x86 guest thread {}: {detail}\n", child_tid.raw());
                    // SAFETY: a straight write to host stderr.
                    unsafe {
                        libc::write(2, msg.as_ptr().cast(), msg.len());
                    }
                    child_shared.request_exit(125);
                }
                // A plain thread exit (`exit(2)`, not last): nothing to do — the
                // host thread just ends and its slice is already freed.
                ThreadRunOutcome::ThreadDone { .. } => {}
            }
        });
    let handle = match spawn {
        Ok(handle) => handle,
        Err(err) => {
            // Undo the registration/slice on a spawn failure.
            shared.registry.exit(child_tid);
            shared.dispatcher.forget_thread_signal_state(child_tid);
            shared.free_slice(slice_off);
            let _ = err;
            return Err(crate::linux_abi::LINUX_EAGAIN.guest_retval());
        }
    };
    // Wait until the child thread has started (it is already registered).
    let _ = ready_rx.recv();
    let mut threads = shared.threads.lock().unwrap_or_else(|p| p.into_inner());
    let exiting = shared.exit.requested();
    threads.push(handle);
    if exiting {
        // Never join here: the child may be the exit_group publisher and be
        // waiting for this parent thread to leave its run loop. Publishing the
        // handle first lets the top-level teardown join it after every guest
        // thread has unregistered.
        Err(crate::linux_abi::LINUX_EAGAIN.guest_retval())
    } else {
        Ok(child_tid)
    }
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

    let jit = FreebsdHostJit;
    jit.supported()
        .map_err(|e| RuntimeError::Unsupported(format!("host JIT unsupported: {e:?}")))?;
    // ONE contiguous code cache covering every guest thread's slice, registered
    // with the fault shim exactly once (the handler reads the per-thread fault
    // record via %r15, so a single covering span is all it needs).
    let cache_len = JIT_SLICE_LEN * JIT_SLICE_COUNT;
    let region = jit
        .map_code_cache(cache_len)
        .map_err(|e| RuntimeError::Unsupported(format!("map code cache: {e:?}")))?;

    fault::install_fault_redirect(signal_stub_addr(), CTX_FAULT_RECORD)
        .map_err(|e| RuntimeError::Unsupported(format!("install fault redirect: {e}")))?;
    fault::install_kick_redirect(FREEBSD_NATIVE_EXIT_KICK_SIGNAL, kick_stub_addr())
        .map_err(|e| RuntimeError::Unsupported(format!("install kick redirect: {e}")))?;
    fault::register_code_region(region.exec_base.as_ptr() as u64, cache_len as u64);

    // Back the guest brk-heap and mmap arenas with real host pages at the
    // dispatcher's fixed layout addresses, so `brk`/`mmap` (which move a
    // pointer / zero a region THROUGH the memory) resolve onto live backing
    // instead of faulting the host.
    let arenas = GuestArenas::reserve()?;
    reset_identity_vmas(&image);

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
        exit: ExitState::new(),
    });

    // The process's initial guest thread runs inline on THIS host thread over
    // its own JIT slice. Guest `clone` threads carve their own slice and run on
    // spawned host threads.
    let main_slice = shared.alloc_slice().ok_or_else(|| {
        RuntimeError::Unsupported("native x86 main thread has no JIT slice".to_string())
    })?;
    let mut memory = IdentityGuestMemory;
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
    );
    shared.free_slice(main_slice);

    // Resolve the process exit code. If the initial guest thread itself
    // `exit(2)`'d while siblings are still live, block until a sibling records
    // the process exit (the last thread to exit, or an `exit_group`).
    let (exit_code, traps, trap_limit_hit, fault) = match outcome {
        ThreadRunOutcome::Exit { code, traps } => {
            shared.request_exit(code);
            (code, traps, false, None)
        }
        ThreadRunOutcome::ThreadDone { traps } => {
            let code = shared.exit.wait_for_code();
            (code, traps, false, None)
        }
        ThreadRunOutcome::TrapLimit { traps } => {
            shared.request_exit(125);
            (125, traps, true, None)
        }
        ThreadRunOutcome::Fault { detail, traps } => {
            shared.request_exit(125);
            (125, traps, false, Some(detail))
        }
    };

    // Linux exit_group does not merely publish an exit code: every sibling is
    // gone before the process is observable as terminal. The wake above makes
    // all blocking paths leave, and joining here closes the lifetime before we
    // read final output or retire shared mappings.
    shared.join_threads();

    // Drain the guest's stdout/stderr from the SHARED dispatcher buffer (every
    // guest thread's writes accumulate here); surface them in the RunResult
    // exactly as the VMM lanes' buffered path does.
    let stdout = shared.dispatcher.stdout();
    let stderr = shared.dispatcher.stderr();

    fault::unregister_code_region();
    // SAFETY: the initial thread returned and every spawned guest thread was
    // joined above, so nothing can execute from the JIT region now.
    unsafe { shared.jit.unmap(&shared.region) };
    shared.current_image().teardown();
    arenas.teardown();

    if let Some(detail) = fault {
        return Err(RuntimeError::Unsupported(format!(
            "native x86 run stopped before exit: {detail}"
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
    restores: Vec<ScratchRestore>,
}

fn recover_x86_fault_snapshot(
    entries: &[PublishedFaultEntry],
    context: &X86DsrContext,
    snapshot: &mut X86UcontextSnapshot,
) -> Option<u64> {
    let entry = entries.iter().find(|entry| {
        context.fault.host_rip >= entry.host_start && context.fault.host_rip < entry.host_end
    })?;
    let scratch = [context.scratch, context.scratch2];
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
) -> ThreadRunOutcome {
    // The "active" shared run: normally the caller's, but a `fork()` child
    // swaps to a FRESH private code cache (its own `SharedRun`) so it never
    // re-JITs into pages the parent also writes (the SHM_ANON code cache is
    // MAP_SHARED and survives fork). The image is COW-identical after fork (the
    // guest's code pages keep their VAs), so it stays borrowed from the caller.
    let mut active = Arc::clone(shared);
    let mut tid = tid;
    let mut host_registration = NativeHostThreadRegistration::new(&active, tid);
    // Mutable so an in-place `execve` can retire this and swap in the new image;
    // every guest-code reader below re-borrows it, so the swap is picked up. All
    // guest-code reads go through the segment-aware `image.code_bytes`, which
    // never crosses an unmapped gap between PT_LOAD segments.
    let mut image = shared.current_image();
    let jit = FreebsdHostJit;
    let max_traps = shared.max_traps;
    // DSR may execute loader text, vDSO/signal stubs, or executable anonymous
    // mmap pages. Read through the identity map, page-bounded, and only when
    // the live VMA carries Linux PROT_EXEC. Host pages remain readable because
    // translation—not direct execution—consumes these bytes.
    let code_bytes = |va: u64| -> Vec<u8> {
        if !IDENTITY_PROTECTIONS.range_executable(va, 1) {
            return Vec::new();
        }
        let len = (0..16usize)
            .take_while(|offset| IDENTITY_PROTECTIONS.range_executable(va + *offset as u64, 1))
            .count();
        IdentityGuestMemory
            .read_bytes_raw(va, len)
            .unwrap_or_default()
    };
    let read_block = |block: &X86Block| -> Vec<u8> {
        let want = block.end.max(block.exit.va());
        let mut out = Vec::new();
        let mut va = block.start;
        while va < want.saturating_add(16) {
            let chunk = code_bytes(va);
            if chunk.is_empty() {
                break;
            }
            va += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        out
    };

    let (mut snapshot, mut guest_fsbase, mut next) = match start {
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
    let mut cursor = slice_off;
    let mut cursor_limit = slice_off + slice_len;
    let mut traps = 0usize;
    let mut exit_code: Option<i32> = None;
    let mut fault_detail: Option<String> = None;
    // True once this process is a `fork()` descendant (see `Step::Exit`).
    let mut forked = false;
    // Write end inherited by a CLONE_VFORK child. Closing on `_exit` produces
    // EOF; successful in-process exec explicitly writes then closes it.
    let mut vfork_completion_fd: Option<i32> = None;

    // Translated-block cache keyed by guest VA: `(exec VA, has_edges,
    // uses_fpu)`. Guest text is read-only here (no self-modifying code), so a
    // VA always translates to the same bytes and the entry is valid for the
    // whole run. Cursor is monotonic. `has_edges` means the block ends in a
    // chainable direct branch; `uses_fpu` drives the FPU save/restore skip.
    let mut cache: std::collections::HashMap<u64, (u64, bool, bool), VaBuildHasher> =
        std::collections::HashMap::default();
    // Chain edges awaiting their target's translation: `target_va -> [(rel32
    // patch address, next-instruction address)]`. When `target_va` is
    // translated, every waiting slot is patched to jump straight to it.
    let mut pending: std::collections::HashMap<u64, Vec<(u64, u64)>, VaBuildHasher> =
        std::collections::HashMap::default();
    let mut fault_entries: Vec<PublishedFaultEntry> = Vec::new();
    let mut code_generation = IDENTITY_CODE_GENERATION.load(std::sync::atomic::Ordering::Acquire);
    // Breadcrumb ring: the last guest VAs entered, for diagnosing where an
    // unhandled scenario was reached from.
    let mut history: Vec<u64> = Vec::new();
    // True once THIS thread performed an in-process `execve` takeover: it keeps
    // running the new image and must ignore the `exec_stop` it raised for its
    // (now-retired) siblings.
    let mut exec_owner = false;

    'run: while traps < max_traps {
        // Another guest thread requested process exit (`exit_group`, or the
        // last thread's `exit(2)`): stop this thread's loop and surface the
        // recorded code. The initial thread turns this into the `RunResult`;
        // a sibling thread just ends (its closure re-requests idempotently). A
        // fork descendant `_exit`s directly so the parent's wait4 reaps it.
        if active.exit.requested() {
            let code = active.exit.code().unwrap_or(0);
            if forked {
                // SAFETY: _exit performs no unwinding; the child's COW mappings
                // are released by the kernel.
                unsafe { libc::_exit(code) };
            }
            return ThreadRunOutcome::Exit { code, traps };
        }
        // A sibling thread is taking over the process via `execve`: Linux kills
        // the rest of the thread group, keeping only the execing task. Stop
        // running guest code and END this host thread WITHOUT recording a
        // process exit code (the new image decides that). Ack so the execing
        // thread knows it is safe to retire the old image. The execing thread
        // itself (`exec_owner`) ignores its own signal and keeps running.
        if !exec_owner && active.exit.exec_stop_requested() {
            active.exit.ack_exec_stop();
            return ThreadRunOutcome::ThreadDone { traps };
        }
        let current_generation =
            IDENTITY_CODE_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        if current_generation != code_generation {
            cache.clear();
            pending.clear();
            fault_entries.clear();
            code_generation = current_generation;
        }
        history.push(next);
        if history.len() > 64 {
            history.remove(0);
        }
        if !IDENTITY_PROTECTIONS.range_executable(next, 1) {
            let code = if IDENTITY_PROTECTIONS.range_unmapped(next, 1) {
                crate::linux_abi::LINUX_SEGV_MAPERR
            } else {
                crate::linux_abi::LINUX_SEGV_ACCERR
            };
            match deliver_x86_signal(
                &active,
                tid,
                &mut snapshot,
                crate::linux_abi::LINUX_SIGSEGV,
                Some((code, next)),
                None,
                None,
                Some(next),
                0,
                false,
            ) {
                Ok(true) => {
                    next = snapshot.rip;
                    continue;
                }
                Ok(false) => {
                    if forked {
                        crate::exec_helpers::forked_child_die_by_signal(
                            crate::linux_abi::LINUX_SIGSEGV,
                            active.dispatcher.stdout(),
                            active.dispatcher.stderr(),
                        );
                    }
                    exit_code = Some(128 + crate::linux_abi::LINUX_SIGSEGV);
                    break 'run;
                }
                Err(()) => {
                    if forked {
                        crate::exec_helpers::forked_child_die_by_signal(
                            crate::linux_abi::LINUX_SIGSEGV,
                            active.dispatcher.stdout(),
                            active.dispatcher.stderr(),
                        );
                    }
                    exit_code = Some(128 + crate::linux_abi::LINUX_SIGSEGV);
                    break 'run;
                }
            }
        }
        let (exec, has_edges, uses_fpu) = if let Some(&hit) = cache.get(&next) {
            hit
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
            let block = match plan_block(next, 256, PAGE, code_bytes) {
                Ok(b) => b,
                Err(e) => {
                    fault_detail = Some(format!("plan_block at 0x{next:x}: {e}"));
                    break;
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
                let bytes = code_bytes(next);
                let in_seg = image.segments.iter().any(|&(s, e)| next >= s && next < e);
                let recent: Vec<String> = history
                    .iter()
                    .rev()
                    .take(8)
                    .map(|v| format!("0x{v:x}"))
                    .collect();
                fault_detail = Some(format!(
                    "no-progress block at 0x{next:x}: exit={:?} in_segment={in_seg} \
                     bytes={:02x?} segments={:x?} recent_blocks={:?}",
                    block.exit, bytes, image.segments, recent,
                ));
                break;
            }
            let body = read_block(&block);
            let linked = match emit_block_linked(&body, &block) {
                Ok(t) => t,
                Err(e) => {
                    // Loud: include the terminator VA's bytes so an unsupported
                    // instruction is identifiable without a debugger round-trip.
                    let at = block.exit.va();
                    fault_detail = Some(format!(
                        "emit_block at 0x{next:x} ({:?}): {e} — insn bytes at 0x{at:x} = {:02x?}",
                        block.exit,
                        code_bytes(at),
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
                pending.clear();
                fault_entries.clear();
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
                restores: entry.restores.clone(),
            }));
            cursor += linked.bytes.len();
            let entry = (exec_u64, !linked.edges.is_empty(), block.uses_fpu);
            cache.insert(next, entry);
            // Register this block's outgoing edges; patch any whose target is
            // already translated (a self-edge sees this block, now cached).
            for edge in &linked.edges {
                let patch_abs = exec_u64 + edge.rel32_off as u64;
                let next_abs = patch_abs + 4;
                if let Some(&(target_exec, _, _)) = cache.get(&edge.target_va) {
                    patch_slot(region, &jit, patch_abs, next_abs, target_exec);
                } else {
                    pending
                        .entry(edge.target_va)
                        .or_default()
                        .push((patch_abs, next_abs));
                }
            }
            // Patch any earlier-translated blocks that were waiting for THIS VA.
            if let Some(waiters) = pending.remove(&next) {
                for (patch_abs, next_abs) in waiters {
                    patch_slot(region, &jit, patch_abs, next_abs, exec_u64);
                }
            }
            entry
        };

        let mut ctx = X86DsrContext::new(snapshot, exec, next);
        ctx.guest_fsbase = guest_fsbase;
        // A chainable block runs many blocks with live FPU state, so the
        // per-block skip is unsound across a chain — restore/save around any
        // chainable entry; keep the skip only for blocks that exit immediately.
        ctx.save_fpu = if has_edges { 1 } else { u32::from(uses_fpu) };
        // Cleared so a stale value can't misread a genuine indirect exit as a
        // chain miss; only a cold stub sets it.
        ctx.chain_patch_site = 0;
        // SAFETY: exec holds a freshly translated block ending in an exit stub
        // (or chaining to one); rsp is a valid guest stack.
        let raw = unsafe { carrick_dsr_x86::enter_translated(&mut ctx) };
        snapshot = ctx.snapshot;

        // With chaining the EXITING block may differ from the entered one, so
        // dispatch on the exit STATUS + snapshot.rip, not the entered block.
        match X86ExitStatus::from_raw(raw) {
            Some(X86ExitStatus::Kicked) => {
                if active.exit.requested() {
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
                let linux_sig = crate::host_signal::host_to_linux_signum(ctx.fault.signal);
                let Some(fault_pc) =
                    recover_x86_fault_snapshot(&fault_entries, &ctx, &mut snapshot)
                else {
                    fault_detail = Some(format!(
                        "native x86 fault at unregistered JIT RIP 0x{:x} addr=0x{:x}",
                        ctx.fault.host_rip, ctx.fault.addr
                    ));
                    break 'run;
                };
                // Shared-anonymous mappings begin inaccessible so first touch
                // can update portable residency metadata. This is an internal
                // demand fault, not a guest SIGSEGV: restore the requested
                // protection and retry the exact instruction.
                if let Some((page, prot)) = active.dispatcher.resident_fault_plan(ctx.fault.addr)
                    && memory.protect_range(page, PAGE as usize, prot).is_ok()
                {
                    active.dispatcher.commit_resident_fault(page);
                    next = fault_pc;
                    continue;
                }
                let fault_code = if linux_sig == crate::linux_abi::LINUX_SIGSEGV
                    && IDENTITY_PROTECTIONS.range_fault_is_access_error(ctx.fault.addr, 1)
                {
                    crate::linux_abi::LINUX_SEGV_ACCERR
                } else {
                    ctx.fault.code
                };
                let fault_info = Some((fault_code, ctx.fault.addr));
                match deliver_x86_signal(
                    &active,
                    tid,
                    &mut snapshot,
                    linux_sig,
                    fault_info,
                    None,
                    None,
                    Some(fault_pc),
                    0,
                    false,
                ) {
                    Ok(true) => next = snapshot.rip,
                    // No handler: a fork descendant dies BY the signal
                    // (WIFSIGNALED) so its parent's wait4 sees it; the top-level
                    // guest reports exit=128+signum instead of the runner dying
                    // by the signal. Buffered output is drained either way.
                    Ok(false) => {
                        if forked {
                            let message = format!(
                                "native x86 fork child {} fatal signal {linux_sig} at \
                                 pc=0x{fault_pc:x} addr=0x{:x} code={fault_code}; \
                                 rsp=0x{:x} rdi=0x{:x} rsi=0x{:x}; bytes={:02x?}; \
                                 segments={:x?}\n",
                                tid.raw(),
                                ctx.fault.addr,
                                snapshot.gpr[reg::RSP],
                                snapshot.gpr[reg::RDI],
                                snapshot.gpr[reg::RSI],
                                code_bytes(fault_pc),
                                image.segments,
                            );
                            // SAFETY: best-effort breadcrumb on a fatal child path.
                            unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
                            crate::exec_helpers::forked_child_die_by_signal(
                                linux_sig,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(128 + linux_sig);
                        break 'run;
                    }
                    // The frame could not be written to the guest stack
                    // (force_sigsegv): SIGSEGV.
                    Err(()) => {
                        if forked {
                            crate::exec_helpers::forked_child_die_by_signal(
                                crate::linux_abi::LINUX_SIGSEGV,
                                active.dispatcher.stdout(),
                                active.dispatcher.stderr(),
                            );
                        }
                        exit_code = Some(128 + crate::linux_abi::LINUX_SIGSEGV);
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
                    &mut snapshot,
                    &mut guest_fsbase,
                ) {
                    Step::Continue(rip) => next = rip,
                    Step::ThreadEnd => {
                        // This thread exited via `exit(2)` and was NOT the last
                        // live thread: end just this host thread.
                        return ThreadRunOutcome::ThreadDone { traps };
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
                        match fork_child_rebuild(&active) {
                            Ok(child) => {
                                active = child;
                                tid = active.registry.main_tid();
                                host_registration.rebind_after_fork(&active, tid);
                                cursor = 0;
                                cursor_limit = JIT_SLICE_LEN;
                                cache.clear();
                                pending.clear();
                                fault_entries.clear();
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
                                snapshot.gpr[reg::RAX] = (-(errno.get() as i64)) as u64;
                                next = snapshot.rip;
                            }
                            Ok((bytes, interpreter, resolved, argv)) => {
                                // Retire every sibling guest thread: after exec
                                // only the execing task survives (`execfromthread`
                                // execs from a non-leader while main keeps
                                // running). Signal siblings to stop and WAIT for
                                // them to leave their run loops before touching
                                // the shared image, so none faults on a mapping
                                // torn out from under it. Then this thread is the
                                // sole survivor and owns the exec.
                                let siblings = active.registry.live_count().saturating_sub(1);
                                if siblings > 0 {
                                    active.exit.request_exec_stop();
                                    active.exit.wait_exec_acks(siblings);
                                }
                                active.registry.remove_all_except(tid);
                                exec_owner = true;
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
                                // Retire the old image, then map the new one. The
                                // vDSO/vvar live at FIXED VAs, so the old must be
                                // unmapped BEFORE the new maps over them.
                                image.teardown();
                                // Linux exec installs a fresh address space.
                                // Replace the persistent identity heap/mmap
                                // arenas for every exec, not just vfork: stale
                                // allocator bytes and host protections from the
                                // old image otherwise corrupt the replacement
                                // dynamic linker's early state.
                                if let Err(error) = remap_exec_arenas() {
                                    notify_vfork_completion(&mut vfork_completion_fd);
                                    fault_detail = Some(format!("replace exec arenas: {error:?}"));
                                    break;
                                }
                                match load_static_pie(&bytes, interpreter.as_deref(), &argv, &env) {
                                    Ok(new_image) => {
                                        reset_identity_vmas(&new_image);
                                        image = Arc::new(new_image);
                                        // Future clone threads must start from
                                        // this replacement image, not the
                                        // pre-exec image retained in SharedRun.
                                        active.publish_image(Arc::clone(&image));
                                        // The exec point of no return is the
                                        // installed replacement image, not the
                                        // dispatcher's earlier path resolution.
                                        notify_vfork_completion(&mut vfork_completion_fd);
                                    }
                                    Err(e) => {
                                        // Past the point of no return: the old
                                        // image is gone. Fail the run loudly.
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
                                pending.clear();
                                fault_entries.clear();
                                guest_fsbase = 0;
                                snapshot = X86UcontextSnapshot::new();
                                snapshot.gpr[reg::RSP] = image.rsp;
                                next = image.entry;
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
                if ctx.chain_patch_site != 0 {
                    // Chain miss: a cold stub already resolved the successor VA
                    // into snapshot.rip; the pending machinery patches the slot
                    // when the target is translated (this iteration or later).
                    next = snapshot.rip;
                } else {
                    // Genuine indirect branch (call/ret/jmp r/m): re-decode it
                    // at the self-set resume VA and resolve from the snapshot.
                    let va = snapshot.rip;
                    let branch = code_bytes(va);
                    match cflow::resolve(&branch, va, &mut snapshot) {
                        Ok(t) => next = t,
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
                let va = snapshot.rip;
                let bytes = code_bytes(va);
                match classify(&bytes, va) {
                    Ok(c) => match c.class {
                        X86InstClass::Sensitive(kind) => {
                            match service_sensitive(kind, &mut snapshot) {
                                Ok(()) => next = va + c.len as u64,
                                Err(detail) => {
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
                snapshot.rip,
                snapshot.gpr[reg::RSP],
                snapshot.gpr[reg::RDI],
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
    ) {
        Ok(o) => o,
        Err(e) => return Step::Fault(format!("dispatch error: {e:?}")),
    };

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
        ),
        // A file-backed (or high-VA anonymous) mmap: in the identity model the
        // guest VA IS the host VA, so map the file (or copy the payload) right
        // there over the reserved arena, then PROT_NONE it if requested.
        DispatchOutcome::MapHostAlias {
            va,
            len,
            payload,
            file,
            shared,
            prot,
            prot_none,
            ..
        } => service_map_host_alias(
            va.raw(),
            len,
            &payload,
            file,
            shared,
            prot,
            prot_none,
            snapshot,
            memory,
            resume,
        ),
        // `FUTEX_WAIT`/`futex_waitv` whose value-check passed under the
        // dispatcher lock: park on the shared futex table until a sibling's
        // `FUTEX_WAKE` advances the generation, the timeout elapses, or a
        // signal interrupts. The dispatcher could not block under its own lock,
        // so it handed the prepared wait token out here.
        DispatchOutcome::FutexWait { wait, timeout } => {
            let value = wait_x86_futex(futex, &shared.exit, tid, wait, timeout, 0);
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
            let value = wait_x86_futex(futex, &shared.exit, tid, wait, timeout, index);
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
            let retval = shared_futex_wait_umtx(
                location.wait_addr().raw(),
                location.waiter_key(),
                value,
                timeout,
                &|| shared.exit.requested(),
            );
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
            let retval = shared_futex_wait_umtx(
                location.wait_addr().raw(),
                location.waiter_key(),
                value,
                timeout,
                &|| shared.exit.requested(),
            );
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
                parent_snapshot: *snapshot,
                resume,
                parent_fsbase: *guest_fsbase,
                stack,
                tls,
                parent_tid_addr,
                child_tid_addr,
                clear_child_tid_addr,
            };
            match spawn_clone_thread(shared, tid, req) {
                Ok(child_tid) => {
                    snapshot.gpr[reg::RAX] = i64::from(child_tid.raw()) as u64;
                }
                Err(errno) => {
                    snapshot.gpr[reg::RAX] = errno as u64;
                }
            }
            Step::Continue(resume)
        }
        // A single thread exited via `exit(2)` (NOT exit_group): wake its
        // CLONE_CHILD_CLEARTID futex (glibc/musl `pthread_join` waits on it),
        // retire it from the registry, and end just this host thread — unless
        // it was the last live thread, in which case the whole process exits.
        DispatchOutcome::ThreadExit { code } => {
            if let Some(addr) = registry.clear_child_tid(tid)
                && addr != 0
            {
                // SAFETY: identity map — the guest's own clear-tid word.
                unsafe {
                    std::ptr::write_bytes(addr as *mut u8, 0, 4);
                }
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
            Ok(rip) => Step::Continue(rip),
            Err(()) => Step::SignalDeath(crate::linux_abi::LINUX_SIGSEGV),
        },
        // `execve(2)`/`execveat(2)`: the dispatcher resolved the target and
        // handed the raw argv/env byte strings out. The image swap must happen
        // in the run loop (it owns the `LoadedImage` + JIT caches), so surface a
        // dedicated Step. `snapshot.rip` is the post-syscall resume the run loop
        // uses for the error path (a failed exec returns errno to the guest).
        DispatchOutcome::Execve { path, argv, env } => Step::Execve { path, argv, env },
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
    futex: &crate::thread::FutexTable,
    exit: &ExitState,
    tid: crate::thread::ThreadId,
    wait: crate::thread::FutexWait,
    timeout: Option<std::time::Duration>,
    woken_value: i64,
) -> i64 {
    // Reflect the parked thread as 'S' (interruptible sleep) in the registry so
    // `/proc/<tid>/stat` synthesis reports it as sleeping while it blocks, then
    // back to 'R' (running) once it is woken.
    crate::thread::set_current_thread_state(tid, 'S');
    let interrupted = || {
        exit.requested()
            || crate::host_signal::has_unblocked_pending_for(
                tid.raw(),
                carrick_abi::SigBlockMask::NONE,
            )
    };
    let outcome = futex.wait_prepared_for_thread(wait, timeout, tid, &interrupted);
    crate::thread::set_current_thread_state(tid, 'R');
    match outcome {
        crate::thread::FutexWaitOutcome::Woken => woken_value,
        crate::thread::FutexWaitOutcome::TimedOut => {
            crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()
        }
        crate::thread::FutexWaitOutcome::Interrupted => {
            crate::linux_abi::LINUX_EINTR.guest_retval()
        }
    }
}

/// The thread-aware sibling of [`crate::runtime::service_syscall`]: dispatch one
/// syscall through `dispatch_threaded(&self, …, tid, registry, futex)` and
/// service the blocking-I/O outcomes (fd wait / poll / select / sleep /
/// blocking write / signal / proc wait) inline on the `waiter`, re-dispatching
/// on readiness. Interior mutability makes it shareable across guest threads;
/// the body mirrors the single-threaded servicer exactly, only the dispatch
/// call differs. Terminal and thread-specific outcomes (Returned/Errno/Exit/
/// CloneThread/FutexWait/ThreadExit/…) fall through to the caller.
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
) -> Result<DispatchOutcome, crate::dispatch::DispatchError> {
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
    let signal_pending = |mask: carrick_abi::WaitSigMask| {
        move || {
            if exit.requested() {
                return true;
            }
            drain_native_child_exit_watches(false);
            dispatcher.drain_xsignals_process_directed();
            crate::host_signal::has_unblocked_pending_for(tid.raw(), mask.block_mask())
                || dispatcher.has_deliverable_dispatch_pending_for_wait(tid, mask)
        }
    };
    let mut poll_deadline: Option<std::time::Instant> = None;
    let mut sleep_deadline: Option<std::time::Instant> = None;
    loop {
        drain_native_child_exit_watches(false);
        let outcome =
            dispatcher.dispatch_threaded(request, memory, reporter, tid, registry, futex)?;
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => match waiter.wait_with_dispatch_pending(
                &fds,
                timeout,
                sig_mask.block_mask(),
                signal_pending(sig_mask),
            ) {
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
                match waiter.wait_poll_with_dispatch_pending(
                    &fds,
                    timeout,
                    sig_mask.block_mask(),
                    signal_pending(sig_mask),
                ) {
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
            } => match waiter.wait_with_dispatch_pending(
                &fds,
                timeout,
                sig_mask.block_mask(),
                signal_pending(sig_mask),
            ) {
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
                match waiter.wait_with_dispatch_pending(
                    &[],
                    Some(deadline - now),
                    carrick_abi::SigBlockMask::NONE,
                    signal_pending(carrick_abi::WaitSigMask::NONE),
                ) {
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
                        match waiter.wait_with_dispatch_pending(
                            &[WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                            None,
                            carrick_abi::SigBlockMask::NONE,
                            || exit.requested(),
                        ) {
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
                if exit.requested() {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                return Ok(crate::dispatch::drive_blocking_record_lock(&lock));
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
                let pending = move || {
                    if exit.requested() {
                        return true;
                    }
                    drain_native_child_exit_watches(false);
                    dispatcher.drain_xsignals_process_directed();
                    crate::host_signal::has_unblocked_pending_for(tid.raw(), block_mask)
                        || dispatcher.has_deliverable_dispatch_pending_for_wait(
                            tid,
                            carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(
                                block_mask.raw(),
                            )),
                        )
                };
                match waiter.wait_with_dispatch_pending(&[], timeout, block_mask, pending) {
                    WaitResult::Ready => continue,
                    WaitResult::Interrupted => {
                        if exit.requested() {
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
                match waiter.wait_proc_exit_with_dispatch_pending(
                    pid,
                    sig_mask.block_mask(),
                    signal_pending(sig_mask),
                ) {
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
                match waiter.wait_proc_state_with_dispatch_pending(sig_mask.block_mask(), || {
                    exit.requested()
                }) {
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
                if exit.requested() {
                    return Ok(DispatchOutcome::Errno { errno: EINTR });
                }
                let retval = carrick_host::shared_word::wait(location.wait_addr().raw(), value, 0);
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

struct NativeVforkShare {
    ranges: Vec<(u64, usize)>,
    pipe: [i32; 2],
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
    fn prepare(shared: &SharedRun) -> std::io::Result<Self> {
        let ranges = native_private_inheritance_ranges(shared);
        let mut applied = 0usize;
        for &(start, len) in &ranges {
            if unsafe {
                carrick_portable::freebsd_minherit(
                    start as *mut libc::c_void,
                    len,
                    carrick_portable::FREEBSD_INHERIT_SHARE,
                )
            } != 0
            {
                for &(rollback_start, rollback_len) in ranges[..applied].iter().rev() {
                    unsafe {
                        carrick_portable::freebsd_minherit(
                            rollback_start as *mut libc::c_void,
                            rollback_len,
                            carrick_portable::FREEBSD_INHERIT_COPY,
                        )
                    };
                }
                return Err(std::io::Error::last_os_error());
            }
            applied += 1;
        }
        let mut pipe = [-1; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            for &(start, len) in ranges.iter().rev() {
                unsafe {
                    carrick_portable::freebsd_minherit(
                        start as *mut libc::c_void,
                        len,
                        carrick_portable::FREEBSD_INHERIT_COPY,
                    )
                };
            }
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { ranges, pipe })
    }

    fn restore_parent_inheritance(&self) {
        for &(start, len) in self.ranges.iter().rev() {
            unsafe {
                carrick_portable::freebsd_minherit(
                    start as *mut libc::c_void,
                    len,
                    carrick_portable::FREEBSD_INHERIT_COPY,
                )
            };
        }
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
fn service_fork(
    shared: &Arc<SharedRun>,
    request: NativeForkRequest,
    snapshot: &mut X86UcontextSnapshot,
    memory: &mut IdentityGuestMemory,
    resume: u64,
) -> Step {
    let dispatcher = &shared.dispatcher;
    let mut fork_guard = Some(NativeForkGuard::acquire());
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

    // CLONE_PIDFD must be atomic from the guest's perspective: the child cannot
    // run user code before the parent installs its pidfd and output pointer. A
    // private host pipe gates only that path; it never enters the guest fd table.
    let pidfd_gate = if request.pidfd_out.is_some() {
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

    let vfork_share = if request.vfork.is_some() {
        match NativeVforkShare::prepare(shared) {
            Ok(state) => Some(state),
            Err(error) => {
                if let Some([read_fd, write_fd]) = pidfd_gate {
                    unsafe {
                        libc::close(read_fd);
                        libc::close(write_fd);
                    }
                }
                crate::guest_cpu::abort_prepared_child_record();
                drop(fork_guard);
                let errno = error.raw_os_error().unwrap_or(libc::EAGAIN);
                snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
                return Step::Continue(resume);
            }
        }
    } else {
        None
    };

    // SAFETY: a plain process fork. Ordinary forks inherit guest mappings CoW;
    // CLONE_VFORK mappings were temporarily marked INHERIT_SHARE above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        if let Some(state) = &vfork_share {
            unsafe {
                libc::close(state.pipe[0]);
                libc::close(state.pipe[1]);
            }
            state.restore_parent_inheritance();
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
        drop(fork_guard);
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(11);
        snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
        return Step::Continue(resume);
    }
    // Ordinary fork releases serialization immediately. A vfork parent keeps
    // it across the INHERIT_SHARE window so a sibling fork cannot accidentally
    // inherit shared guest mappings. The child's COW guard copy is independent.
    if vfork_share.is_none() {
        drop(fork_guard.take());
    }
    if pid == 0 {
        drop(fork_guard.take());
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
            let _ = memory.write_bytes(addr, &cpid.to_le_bytes());
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
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        if let Some([_, write_fd]) = pidfd_gate {
                            libc::close(write_fd);
                        }
                        let mut status = 0;
                        while libc::waitpid(pid, &mut status, 0) < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        {
                        }
                    }
                    crate::guest_cpu::abort_prepared_child_record();
                    if let Some(state) = &vfork_share {
                        unsafe { libc::close(state.pipe[0]) };
                        state.restore_parent_inheritance();
                    }
                    snapshot.gpr[reg::RAX] = errno.guest_retval() as u64;
                    return Step::Continue(resume);
                }
            }
        } else {
            None
        };

        // Parent: publish by the exact prepared-record reference only after all
        // fallible CLONE_PIDFD setup has succeeded.
        crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared, pid as u32);
        crate::namespace::pid::notify_child_registered();
        crate::host_signal::register_child_exit_watch(
            pid,
            request.parent_tid,
            i32::try_from(request.exit_signal).unwrap_or(0),
        );
        if let (Some(addr), Some(pidfd)) = (request.pidfd_out, installed_pidfd) {
            let _ = memory.write_bytes(addr, &pidfd.to_le_bytes());
        }
        let guest_pid = child_ns_pid.unwrap_or(pid as u32);
        snapshot.gpr[reg::RAX] = u64::from(guest_pid);
        if let Some(addr) = request.parent_tid_addr {
            let _ = memory.write_bytes(addr, &guest_pid.to_le_bytes());
        }
        if let Some([_, write_fd]) = pidfd_gate {
            let release = 1u8;
            let _ =
                unsafe { libc::write(write_fd, (&release as *const u8).cast::<libc::c_void>(), 1) };
            unsafe { libc::close(write_fd) };
        }
        if let Some(state) = &vfork_share {
            shared.exit.begin_vfork_wait();
            let completed = wait_native_vfork_completion(state.pipe[0], &shared.exit);
            shared.exit.end_vfork_wait();
            unsafe { libc::close(state.pipe[0]) };
            state.restore_parent_inheritance();
            drop(fork_guard.take());
            if !completed {
                shared.exit.ack_exec_stop();
                return Step::ThreadEnd;
            }
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
    va: u64,
    len: u64,
    payload: &[u8],
    file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    shared: bool,
    prot: u64,
    _prot_none: bool,
    snapshot: &mut X86UcontextSnapshot,
    memory: &mut IdentityGuestMemory,
    resume: u64,
) -> Step {
    let len_usize = len as usize;
    if let Some((fd, offset, _host_prot)) = file {
        // SAFETY: `va` is a page-aligned host VA inside the reserved mmap arena;
        // MAP_FIXED replaces the anon backing with the file mapping.
        let p = unsafe {
            libc::mmap(
                va as *mut libc::c_void,
                len_usize,
                // Map writable for initialization when requested; executable
                // DSR pages need host READ, never host EXEC.
                if prot & crate::linux_abi::LINUX_PROT_WRITE != 0 {
                    libc::PROT_READ | libc::PROT_WRITE
                } else if prot
                    & (crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC)
                    != 0
                {
                    libc::PROT_READ
                } else {
                    libc::PROT_NONE
                },
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                offset,
            )
        };
        // The fd is a dup the runtime owns; close it after mapping.
        unsafe { libc::close(fd) };
        if p as u64 != va {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(12);
            snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
            return Step::Continue(resume);
        }
        // The explicit MAP_FIXED file mapping is now the authoritative
        // backing. Clear the old arena-hole marker before protect_range, or
        // ensure_identity_backed would replace this live alias with anonymous
        // memory and sever MAP_SHARED coherence.
        IDENTITY_PROTECTIONS.set_unmapped(va, len_usize, false);
    } else {
        // Anonymous alias mappings live outside the pre-reserved low mmap
        // arena, so install real backing at the identity VA before either the
        // guest or a syscall-path validation touches it. Preserve MAP_SHARED
        // across host fork; private aliases use ordinary CoW backing.
        let flags = libc::MAP_FIXED
            | libc::MAP_ANON
            | if shared {
                libc::MAP_SHARED
            } else {
                libc::MAP_PRIVATE
            };
        // SAFETY: `va` is the dispatcher-selected page-aligned guest identity
        // address and `len_usize` is its validated mapping length.
        let p = unsafe {
            libc::mmap(
                va as *mut libc::c_void,
                len_usize,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if p as u64 != va {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(12);
            snapshot.gpr[reg::RAX] = (-(errno as i64)) as u64;
            return Step::Continue(resume);
        }
        IDENTITY_PROTECTIONS.set_unmapped(va, len_usize, false);
        if !payload.is_empty() {
            let _ = memory.write_bytes_raw(va, payload);
        }
    }
    if memory.protect_range(va, len_usize, prot).is_err() {
        snapshot.gpr[reg::RAX] = crate::linux_abi::LINUX_ENOMEM.guest_retval() as u64;
        return Step::Continue(resume);
    }
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

/// Service a sensitive (non-syscall) exit. On a same-ISA native lane the guest
/// and host CPU are identical, so `rdtsc`/`rdtscp`/`cpuid` are HONEST host
/// passthrough — the guest sees the real CPU it is running on. fs/gs base
/// instructions and gs-prefixed accesses are not yet virtualized here.
fn service_sensitive(
    kind: carrick_dsr_x86::decode::X86SensitiveKind,
    snapshot: &mut X86UcontextSnapshot,
) -> Result<(), String> {
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
            let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
            snapshot.gpr[reg::RAX] = r.eax as u64;
            snapshot.gpr[reg::RBX] = r.ebx as u64;
            snapshot.gpr[reg::RCX] = r.ecx as u64;
            snapshot.gpr[reg::RDX] = r.edx as u64;
            Ok(())
        }
        SegmentBase { .. } | SegmentPrefixed { .. } | Syscall | Int80 => Err(format!(
            "native x86 first-rung driver does not service sensitive {kind:?} yet"
        )),
    }
}

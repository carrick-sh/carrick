//! Darwin mappings for the container-lifetime live translation arena.
//!
//! Code and control use distinct unlinked regular files — the `kernel_arena`
//! idiom, and the only backing this host lets carrick both share across
//! `fork(2)`+`execve` and map executable. Code is mapped through separate
//! permanently-RW and permanently-RX aliases; no returned or retained live
//! alias is both writable and executable, and each alias's MAXIMUM protection
//! is clamped with `mach_vm_protect(set_maximum)` so no holder can escalate
//! one afterwards.
//!
//! The RX alias is built `mmap(PROT_READ)` + `mprotect(PROT_READ|PROT_EXEC)`:
//! Darwin's AMFI refuses `mmap(PROT_EXEC)` of an unsigned file outright
//! (EPERM), but the `mprotect` route is open to an ad-hoc, non-hardened
//! process — the same signing state `jit.rs` documents for `MAP_JIT`. Every
//! step is qualified live on this host in
//! `docs/perf-results/2026-08-05-fd-transport-probe-receipts.txt`; the design
//! is `docs/superpowers/specs/2026-08-05-live-arena-fd-transport-design.md`.
//!
//! Transport is fd inheritance: the fds ARE the capability, so a guest
//! `fork(2)` child can carry the arena through its own host self-exec. No
//! Mach name exists anywhere in this module's transport, which is why an
//! `Arc<DarwinLiveArena>` unwinding in a fork child is purely process-local
//! (`munmap` + `close`).

use carrick_dsr::cache::{PageGenerationDomain, PageGenerationObservation, TranslationCache};
use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
use carrick_dsr_aarch64::emit::{
    ExpectedLivePublication, LivePrebindOutcome, PreparedSharedInitial,
    validate_live_shared_initial_hot,
};
use carrick_dsr_aarch64::live_arena::{
    LIVE_ARENA_OBJECT_HEADER_BYTES, LIVE_SOURCE_PAGE_BYTES, LiveArenaCapacities,
    LiveArenaControlLayout, LiveBlockExtents, LiveLookup, LiveMappedWritePermit, LivePrivateReason,
    LiveProcessViewBrand, LivePublishClaim, LiveReadyLookup, LiveReservedPublishClaim,
    LiveTranslationArenaView, ValidatedLiveBlockRecord,
};
use carrick_dsr_aarch64::shared_cache::TranslationUnitKey;
use carrick_dsr_aarch64::types::CacheOffset;
use carrick_guest_mem::{GuestVa, HostVa};
use mach2::kern_return::{KERN_SUCCESS, kern_return_t};
use mach2::mach_port::mach_port_deallocate;
use mach2::port::MACH_PORT_NULL;
use mach2::traps::mach_task_self;
use mach2::vm::{mach_vm_protect, mach_vm_region};
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_NONE, VM_PROT_READ, VM_PROT_WRITE, vm_prot_t};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const LIVE_ARENA_TRANSIT_SCHEMA_V2: u32 = 2;
const LIVE_OBJECT_HEADER_LEN: usize = LIVE_ARENA_OBJECT_HEADER_BYTES;
const LIVE_OBJECT_MAGIC: [u8; 8] = *b"CRKLIVE\0";
const LIVE_OBJECT_CODE: u32 = 1;
const LIVE_OBJECT_CONTROL: u32 = 2;

static LIVE_ARENA_FILE_SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaTransitV2 {
    pub schema: u32,
    pub code_len: u64,
    pub control_len: u64,
    pub nonce: [u8; 16],
}

/// One backing object's inherited-descriptor authority for a host self-exec.
///
/// The fd IS the capability: `fork(2)` and `execve` both carry it, and nothing
/// else in the successor can name this object. `original_host_fd_flags` plus
/// the `fstat` triple are what make adoption *authenticated* rather than
/// merely inherited — the exact `KernelArenaReexecAuthority` shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaObjectAuthority {
    pub host_fd: RawFd,
    pub original_host_fd_flags: libc::c_int,
    pub host_device: u64,
    pub host_inode: u64,
    pub host_size: u64,
}

/// The complete cross-exec authority for one live arena: the unchanged V2
/// transit record (schema/lengths/nonce) plus both objects' fd authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaReexecAuthority {
    pub transit: LiveArenaTransitV2,
    pub code: LiveArenaObjectAuthority,
    pub control: LiveArenaObjectAuthority,
}

/// Create one unlinked regular file of exactly `len` bytes.
///
/// The `KernelArena::create` convention: a pid+serial name in `temp_dir()`,
/// `O_EXCL` so no stale object is ever adopted by accident, unlinked
/// immediately so the fd is the only handle and the filesystem reclaims the
/// extents at last close. `O_CLOEXEC` makes the steady state close-on-exec —
/// the capsule's `HostFdFlagTransaction` clears it for exactly the deliberate
/// self-exec window and restores it if the exec returns.
fn create_backing_object(label: &str, len: usize) -> io::Result<OwnedFd> {
    let serial = LIVE_ARENA_FILE_SERIAL.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "carrick-live-arena-{}-{serial}-{label}",
        std::process::id()
    ));
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_input("live arena backing path contains NUL"))?;
    let raw = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(backing_error(label, "open", io::Error::last_os_error()));
    }
    // SAFETY: `open` returned a fresh descriptor this scope now owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Every failure below leaves an UNLINKED object: the descriptor closes on
    // drop and the filesystem reclaims the extents, so nothing survives.
    // Failing to unlink at all is the one case that leaves a path behind, and
    // it fails the whole creation rather than proceeding with a named object —
    // a linked backing file is exactly the stale state `O_EXCL` exists to
    // prevent, and the process would otherwise leak a `temp_dir()` entry it can
    // no longer name. The path is reported so an operator can find it.
    if unsafe { libc::unlink(cpath.as_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "live arena {label} backing unlink: {error} (leaving {} on disk)",
                path.display()
            ),
        ));
    }
    let size = libc::off_t::try_from(len)
        .map_err(|_| invalid_input(format!("{label} arena length exceeds off_t")))?;
    if unsafe { libc::ftruncate(fd.as_raw_fd(), size) } != 0 {
        return Err(backing_error(
            label,
            "ftruncate",
            io::Error::last_os_error(),
        ));
    }
    Ok(fd)
}

fn backing_error(label: &str, operation: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("live arena {label} backing {operation}: {error}"),
    )
}

fn object_authority(fd: &OwnedFd, label: &str) -> io::Result<LiveArenaObjectAuthority> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(backing_error(label, "F_GETFD", io::Error::last_os_error()));
    }
    let identity = fd_identity(raw, label)?;
    Ok(LiveArenaObjectAuthority {
        host_fd: raw,
        original_host_fd_flags: flags,
        host_device: identity.0,
        host_inode: identity.1,
        host_size: identity.2,
    })
}

/// `(device, inode, size)` for one descriptor.
fn fd_identity(fd: RawFd, label: &str) -> io::Result<(u64, u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(backing_error(label, "fstat", io::Error::last_os_error()));
    }
    // SAFETY: `fstat` succeeded, so the buffer is initialized.
    let stat = unsafe { stat.assume_init() };
    let size = u64::try_from(stat.st_size)
        .map_err(|_| invalid_input(format!("live arena {label} object has a negative size")))?;
    // `st_dev` is i32 on Darwin and u64 elsewhere; the widening cast is an
    // identity here and load-bearing on the other hosts this shape came from.
    #[allow(clippy::unnecessary_cast)]
    Ok((stat.st_dev as u64, stat.st_ino, size))
}

/// Re-own one inherited transport descriptor, authenticated before it is used.
///
/// Order is load-bearing and each step has its own named refusal: the fd must
/// be plausible, its size must equal the length the V2 transit record claims,
/// its flags must be exactly the creator's minus `FD_CLOEXEC` (proving this is
/// the deliberate capsule transit and nothing tampered in between), and its
/// `fstat` identity must match the creator's snapshot. Only then is it
/// duplicated into a close-on-exec descriptor this process owns.
///
/// The transport descriptor itself is NOT closed here: it is released by
/// [`DarwinLiveArena::adopt_reexec`] once the whole arena has authenticated,
/// so a refusal never leaves one object consumed and the other not.
fn adopt_transport_object(
    label: &str,
    authority: LiveArenaObjectAuthority,
    expected_len: u64,
) -> io::Result<OwnedFd> {
    if authority.host_fd < 0 {
        return Err(invalid_input(format!(
            "live arena {label} transport descriptor {} is not a descriptor",
            authority.host_fd
        )));
    }
    if authority.host_size != expected_len {
        return Err(invalid_input(format!(
            "live arena {label} transport size {} does not match transit length {expected_len}",
            authority.host_size
        )));
    }
    let flags = unsafe { libc::fcntl(authority.host_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(backing_error(label, "F_GETFD", io::Error::last_os_error()));
    }
    if flags != authority.original_host_fd_flags & !libc::FD_CLOEXEC {
        return Err(invalid_input(format!(
            "live arena {label} transport fd flags changed: observed={flags} expected={}",
            authority.original_host_fd_flags & !libc::FD_CLOEXEC
        )));
    }
    let identity = fd_identity(authority.host_fd, label)?;
    if identity
        != (
            authority.host_device,
            authority.host_inode,
            authority.host_size,
        )
    {
        return Err(invalid_input(format!(
            "live arena {label} transport fd identity changed: observed={identity:?} expected={:?}",
            (
                authority.host_device,
                authority.host_inode,
                authority.host_size
            )
        )));
    }
    let owned = unsafe { libc::fcntl(authority.host_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if owned < 0 {
        return Err(backing_error(
            label,
            "F_DUPFD_CLOEXEC",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: `F_DUPFD_CLOEXEC` returned a fresh descriptor this scope owns.
    Ok(unsafe { OwnedFd::from_raw_fd(owned) })
}

/// Release one transport descriptor once its duplicate is the retained handle.
/// This is what keeps the resumed process's fd space free of the transport
/// numbers the capsule named.
fn release_transport_object(authority: LiveArenaObjectAuthority) {
    unsafe { libc::close(authority.host_fd) };
}

struct VmMapping {
    address: u64,
    len: u64,
}

impl VmMapping {
    /// Map one alias of a backing object at `current` protection, with its
    /// MAXIMUM protection clamped to `maximum`, and refuse anything else.
    ///
    /// The RX alias cannot be requested directly: Darwin refuses
    /// `mmap(PROT_EXEC)` of an unsigned file with `EPERM`, so an executable
    /// alias is mapped `PROT_READ` and raised with `mprotect`. It is never
    /// writable at any point, so no W|X window exists even transiently.
    ///
    /// The clamp is what makes [`validate_protections`]'s equality check hold
    /// verbatim on this backing (a fresh file mapping's max is `rwx`), and it
    /// is what forecloses a later escalation of either alias by any holder.
    ///
    /// [`validate_protections`]: VmMapping::validate_protections
    fn map_shared_file(
        fd: RawFd,
        len: usize,
        current: vm_prot_t,
        maximum: vm_prot_t,
    ) -> io::Result<Self> {
        for protection in [current, maximum] {
            if protection & VM_PROT_WRITE != 0 && protection & VM_PROT_EXECUTE != 0 {
                return Err(invalid_input(
                    "live arena mapping may not be writable and executable",
                ));
            }
        }
        if current & !maximum != 0 {
            return Err(invalid_input(
                "live arena mapping current protection exceeds its maximum",
            ));
        }
        let mapped_len =
            u64::try_from(len).map_err(|_| invalid_input("mapping length exceeds u64"))?;
        let executable = current & VM_PROT_EXECUTE != 0;
        let initial = if executable {
            libc::PROT_READ
        } else {
            posix_protection(current)
        };
        let address =
            unsafe { libc::mmap(std::ptr::null_mut(), len, initial, libc::MAP_SHARED, fd, 0) };
        if address == libc::MAP_FAILED {
            return Err(mapping_error("mmap", io::Error::last_os_error()));
        }
        let mapping = Self {
            address: address as u64,
            len: mapped_len,
        };
        if executable && unsafe { libc::mprotect(address, len, posix_protection(current)) } != 0 {
            return Err(mapping_error("mprotect", io::Error::last_os_error()));
        }
        check_kr("mach_vm_protect live arena alias maximum", unsafe {
            mach_vm_protect(mach_task_self(), mapping.address, mapped_len, 1, maximum)
        })?;
        mapping.validate_address_and_size()?;
        mapping.validate_protections(current, maximum)?;
        Ok(mapping)
    }

    fn validate_address_and_size(&self) -> io::Result<()> {
        let page = host_page_size()?;
        if self.address == 0 || !self.address.is_multiple_of(page as u64) || self.len == 0 {
            return Err(io::Error::other(format!(
                "invalid live arena mapping address/size: address=0x{:x} size={}",
                self.address, self.len
            )));
        }
        let region = query_region(self.address)?;
        let region_end = region
            .address
            .checked_add(region.len)
            .ok_or_else(|| io::Error::other("Mach region end overflowed"))?;
        let mapping_end = self
            .address
            .checked_add(self.len)
            .ok_or_else(|| io::Error::other("Mach mapping end overflowed"))?;
        if region.address > self.address || region_end < mapping_end {
            return Err(io::Error::other(format!(
                "live arena mapping does not cover requested size: requested address=0x{:x} size={} returned region address=0x{:x} size={}",
                self.address, self.len, region.address, region.len
            )));
        }
        Ok(())
    }

    /// The mandatory fail-closed guard against a silently-downgraded alias.
    ///
    /// This is not defensive decoration: on POSIX shared memory this host's
    /// kernel accepts `mmap(PROT_READ|PROT_EXEC)` and then silently strips
    /// EXEC (probe P2-shm), which would leave the arena serving unexecutable
    /// "code". Equality — current AND maximum exactly as requested — is what
    /// turns that shape into a named refusal instead of a SIGBUS later.
    fn validate_protections(
        &self,
        expected_current: vm_prot_t,
        expected_max: vm_prot_t,
    ) -> io::Result<()> {
        let region = query_region(self.address)?;
        if region.current != expected_current || region.maximum != expected_max {
            return Err(io::Error::other(format!(
                "live arena mapping protections differ: current={} max={} expected_current={expected_current} expected_max={expected_max}",
                region.current, region.maximum
            )));
        }
        Ok(())
    }

    fn base(&self) -> usize {
        self.address as usize
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len as usize
    }
}

impl Drop for VmMapping {
    fn drop(&mut self) {
        // Address-space-local, exactly like `close` is fd-table-local: a fork
        // child unwinding an inherited arena unmaps only its own mappings.
        let _ = unsafe { libc::munmap(self.address as *mut libc::c_void, self.len as usize) };
    }
}

/// Mach and POSIX protection bits coincide on Darwin; convert explicitly
/// rather than casting so the two domains stay distinguishable at the call.
fn posix_protection(protection: vm_prot_t) -> libc::c_int {
    let mut posix = 0;
    if protection & VM_PROT_READ != 0 {
        posix |= libc::PROT_READ;
    }
    if protection & VM_PROT_WRITE != 0 {
        posix |= libc::PROT_WRITE;
    }
    if protection & VM_PROT_EXECUTE != 0 {
        posix |= libc::PROT_EXEC;
    }
    posix
}

fn mapping_error(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("live arena alias {operation}: {error}"),
    )
}

struct RegionInfo {
    address: u64,
    len: u64,
    current: vm_prot_t,
    maximum: vm_prot_t,
}

fn query_region(address: u64) -> io::Result<RegionInfo> {
    let mut observed = address;
    let mut len = 0;
    let mut info = vm_region_basic_info_64::default();
    let mut count = vm_region_basic_info_64::count();
    let mut object_name = MACH_PORT_NULL;
    let result = unsafe {
        mach_vm_region(
            mach_task_self(),
            &mut observed,
            &mut len,
            VM_REGION_BASIC_INFO_64,
            (&raw mut info).cast::<i32>(),
            &mut count,
            &mut object_name,
        )
    };
    if object_name != MACH_PORT_NULL {
        let _ = unsafe { mach_port_deallocate(mach_task_self(), object_name) };
    }
    check_kr("mach_vm_region live arena mapping", result)?;
    Ok(RegionInfo {
        address: observed,
        len,
        current: info.protection,
        maximum: info.max_protection,
    })
}

pub struct DarwinLiveArena {
    code_object: OwnedFd,
    control_object: OwnedFd,
    code_rw: VmMapping,
    code_rx: VmMapping,
    control_rw: VmMapping,
    code_len: usize,
    control_len: usize,
    nonce: [u8; 16],
    control_layout: LiveArenaControlLayout,
}

impl DarwinLiveArena {
    pub fn new(capacities: LiveArenaCapacities) -> io::Result<Self> {
        let layout = LiveArenaControlLayout::new(capacities, host_page_size()?)
            .map_err(|error| invalid_input(error.to_string()))?;
        let code_len = layout.code_len();
        let control_len = layout.control_len();
        validate_arena_len("code", code_len)?;
        validate_arena_len("control", control_len)?;

        let code_object = create_backing_object("code", code_len)?;
        let control_object = create_backing_object("control", control_len)?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|error| io::Error::other(format!("generate live arena nonce: {error}")))?;
        let arena = Self::map_objects(
            code_object,
            control_object,
            code_len,
            control_len,
            nonce,
            layout,
        )?;
        arena.write_object_headers()?;
        // SAFETY: the creator owns the fresh control object exclusively, its
        // RW mapping covers the canonical layout, and the arena retains that
        // mapping beyond the temporary typed view.
        unsafe {
            LiveTranslationArenaView::initialize_in_place(
                NonNull::new(arena.control_rw.base() as *mut u8)
                    .ok_or_else(|| invalid_input("live control mapping is null"))?,
                arena.control_len,
                layout,
                nonce,
            )
        }
        .map_err(|error| invalid_input(error.to_string()))?;
        Ok(arena)
    }

    /// Adopt the arena a host self-exec transported as two inherited
    /// descriptors.
    ///
    /// Authentication is layered and every layer keeps its own named refusal:
    /// per-fd flags and `fstat` identity (this object, deliberately handed
    /// over) per descriptor, then the outer object headers, then the
    /// unchanged V2 directory nonce/schema/ABI/geometry validation. A wrong,
    /// recycled, or tampered descriptor fails one of them.
    pub fn adopt_reexec(authority: LiveArenaReexecAuthority) -> io::Result<Self> {
        validate_transit(authority.transit)?;
        let code_len = authority.transit.code_len as usize;
        let control_len = authority.transit.control_len as usize;
        let code_object =
            adopt_transport_object("code", authority.code, authority.transit.code_len)?;
        let control_object =
            adopt_transport_object("control", authority.control, authority.transit.control_len)?;
        let arena = Self::map_adopted_objects(
            code_object,
            control_object,
            code_len,
            control_len,
            authority.transit.nonce,
        )?;
        // The LOAD-BEARING protocol validation already ran inside
        // `map_adopted_objects`: it checks both outer object headers BEFORE any
        // typed reference exists, then rebuilds and validates the complete
        // canonical layout with `adopt_discovered_in_place`
        // (nonce/schema/translator-ABI/count/stride/alignment/overlap/bounds).
        // The second pass below adds one thing the first cannot: it re-reads
        // the mapped directory and requires the SAME geometry back, so a
        // directory mutated between the two reads — the shared object is
        // writable by every holder — cannot leave this arena resolving offsets
        // against a layout that no longer describes it.
        arena.validate_object_headers(authority.transit)?;
        arena.validate_control_protocol(authority.transit)?;
        // Both-or-neither: the transport descriptors are released only once
        // the complete arena has authenticated.
        release_transport_object(authority.code);
        release_transport_object(authority.control);
        Ok(arena)
    }

    fn map_objects(
        code_object: OwnedFd,
        control_object: OwnedFd,
        code_len: usize,
        control_len: usize,
        nonce: [u8; 16],
        control_layout: LiveArenaControlLayout,
    ) -> io::Result<Self> {
        validate_arena_len("code", code_len)?;
        validate_arena_len("control", control_len)?;
        let code_rw = VmMapping::map_shared_file(
            code_object.as_raw_fd(),
            code_len,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
        )?;
        let code_rx = VmMapping::map_shared_file(
            code_object.as_raw_fd(),
            code_len,
            VM_PROT_READ | VM_PROT_EXECUTE,
            VM_PROT_READ | VM_PROT_EXECUTE,
        )?;
        let control_rw = VmMapping::map_shared_file(
            control_object.as_raw_fd(),
            control_len,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
        )?;

        if code_rw.address == code_rx.address
            || code_rw.address == control_rw.address
            || code_rx.address == control_rw.address
        {
            return Err(io::Error::other("overlapping live arena aliases"));
        }
        Ok(Self {
            code_object,
            control_object,
            code_rw,
            code_rx,
            control_rw,
            code_len,
            control_len,
            nonce,
            control_layout,
        })
    }

    fn map_adopted_objects(
        code_object: OwnedFd,
        control_object: OwnedFd,
        code_len: usize,
        control_len: usize,
        nonce: [u8; 16],
    ) -> io::Result<Self> {
        let expected = LiveArenaTransitV2 {
            schema: LIVE_ARENA_TRANSIT_SCHEMA_V2,
            code_len: code_len as u64,
            control_len: control_len as u64,
            nonce,
        };
        let arena = {
            validate_arena_len("code", code_len)?;
            validate_arena_len("control", control_len)?;
            let code_rw = VmMapping::map_shared_file(
                code_object.as_raw_fd(),
                code_len,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
            )?;
            let code_rx = VmMapping::map_shared_file(
                code_object.as_raw_fd(),
                code_len,
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE,
            )?;
            let control_rw = VmMapping::map_shared_file(
                control_object.as_raw_fd(),
                control_len,
                VM_PROT_READ | VM_PROT_WRITE,
                VM_PROT_READ | VM_PROT_WRITE,
            )?;
            validate_object_header(&code_rw, LIVE_OBJECT_CODE, expected)?;
            validate_object_header(&control_rw, LIVE_OBJECT_CONTROL, expected)?;
            let base = NonNull::new(control_rw.base() as *mut u8)
                .ok_or_else(|| invalid_input("live control mapping is null"))?;
            // SAFETY: both outer headers were validated before fixed-directory
            // discovery; mappings remain owned by the returned arena.
            let view = unsafe {
                LiveTranslationArenaView::adopt_discovered_in_place(
                    base,
                    control_len,
                    code_len,
                    host_page_size()?,
                    nonce,
                )
            }
            .map_err(|error| invalid_input(error.to_string()))?;
            let control_layout = view.layout();
            if code_rw.address == code_rx.address
                || code_rw.address == control_rw.address
                || code_rx.address == control_rw.address
            {
                return Err(io::Error::other("overlapping live arena aliases"));
            }
            Self {
                code_object,
                control_object,
                code_rw,
                code_rx,
                control_rw,
                code_len,
                control_len,
                nonce,
                control_layout,
            }
        };
        Ok(arena)
    }

    fn write_object_headers(&self) -> io::Result<()> {
        let transit = self.transit_v2();
        write_object_header(&self.code_rw, LIVE_OBJECT_CODE, transit)?;
        write_object_header(&self.control_rw, LIVE_OBJECT_CONTROL, transit)
    }

    fn validate_object_headers(&self, expected: LiveArenaTransitV2) -> io::Result<()> {
        validate_object_header(&self.code_rw, LIVE_OBJECT_CODE, expected)?;
        validate_object_header(&self.control_rw, LIVE_OBJECT_CONTROL, expected)
    }

    fn validate_control_protocol(&self, expected: LiveArenaTransitV2) -> io::Result<()> {
        let base = NonNull::new(self.control_rw.base() as *mut u8)
            .ok_or_else(|| invalid_input("live control mapping is null"))?;
        // SAFETY: the outer transport headers and mapping lengths were checked
        // first. The portable adopter reads only the fixed directory until it
        // has rebuilt and validated the complete canonical layout.
        let view = unsafe {
            LiveTranslationArenaView::adopt_discovered_in_place(
                base,
                self.control_len,
                self.code_len,
                host_page_size()?,
                expected.nonce,
            )
        }
        .map_err(|error| invalid_input(error.to_string()))?;
        if view.layout() != self.control_layout {
            return Err(io::Error::other(
                "adopted live control layout changed after validation",
            ));
        }
        Ok(())
    }

    /// Returns a portable protocol view dominated by this mapping owner.
    ///
    /// ```compile_fail
    /// use carrick_dsr_aarch64::live_arena::LiveTranslationArenaView;
    /// use carrick_native_darwin::live_arena::DarwinLiveArena;
    ///
    /// fn escape(arena: &DarwinLiveArena) -> LiveTranslationArenaView<'static> {
    ///     arena.control_view().unwrap()
    /// }
    /// ```
    fn control_view(&self) -> io::Result<LiveTranslationArenaView<'_>> {
        let layout = self.control_layout();
        let base = NonNull::new(self.control_rw.base() as *mut u8)
            .ok_or_else(|| invalid_input("live control mapping is null"))?;
        // SAFETY: this arena owns the validated mapping for the returned view's
        // lifetime and only protocol atomics/payload cells mutate afterward.
        unsafe {
            LiveTranslationArenaView::adopt_in_place(base, self.control_len, layout, self.nonce)
        }
        .map_err(|error| invalid_input(error.to_string()))
    }

    pub fn control_layout(&self) -> LiveArenaControlLayout {
        self.control_layout
    }

    pub fn code_payload_base(&self) -> usize {
        self.control_layout().code_payload_base()
    }

    pub fn transit_v2(&self) -> LiveArenaTransitV2 {
        LiveArenaTransitV2 {
            schema: LIVE_ARENA_TRANSIT_SCHEMA_V2,
            code_len: self.code_len as u64,
            control_len: self.control_len as u64,
            nonce: self.nonce,
        }
    }

    /// This process's complete cross-exec authority for the arena.
    ///
    /// Buildable by ANY holder of the arena — including a guest `fork(2)`
    /// child, which is the whole point: the descriptors are inherited, so
    /// there is no per-child capability-minting step that a fresh IPC space
    /// could invalidate. Both descriptors stay owned here; the capsule only
    /// carries their numbers, flags, and identity.
    pub fn reexec_authority(&self) -> io::Result<LiveArenaReexecAuthority> {
        Ok(LiveArenaReexecAuthority {
            transit: self.transit_v2(),
            code: object_authority(&self.code_object, "code")?,
            control: object_authority(&self.control_object, "control")?,
        })
    }

    #[cfg(test)]
    fn jit_region(&self, range: Range<usize>) -> io::Result<BorrowedLiveJitRegion<'_>> {
        let layout = self.control_layout();
        let logical_capacity = usize::try_from(layout.capacities().code)
            .map_err(|_| invalid_input("live code capacity exceeds usize"))?;
        let capacity = checked_range(&range, logical_capacity, "JIT subregion")?;
        let actual_start = layout
            .code_payload_base()
            .checked_add(range.start)
            .ok_or_else(|| invalid_input("JIT subregion offset overflowed"))?;
        let write = self
            .code_rw
            .base()
            .checked_add(actual_start)
            .and_then(|address| NonNull::new(address as *mut u8))
            .ok_or_else(|| invalid_input("JIT write address overflowed"))?;
        let exec = self
            .code_rx
            .base()
            .checked_add(actual_start)
            .and_then(|address| NonNull::new(address as *mut u8))
            .ok_or_else(|| invalid_input("JIT exec address overflowed"))?;
        Ok(BorrowedLiveJitRegion {
            exec_base: exec,
            write_base: write,
            capacity,
            _arena: PhantomData,
        })
    }

    /// Raw local mapping ranges for cross-exec transport qualification. The
    /// addresses are process-local and must never be serialized as arena
    /// authority or used to construct an owned JIT region.
    ///
    /// # Safety
    ///
    /// The caller must treat these values only as transient diagnostic ranges
    /// and must not dereference or retain them beyond this arena's lifetime.
    pub unsafe fn local_mapping_ranges_for_transport_proof(&self) -> io::Result<[Range<usize>; 3]> {
        let code_rw_end = self
            .code_rw
            .base()
            .checked_add(self.code_len)
            .ok_or_else(|| invalid_input("live code RW mapping end overflowed"))?;
        let code_rx_end = self
            .code_rx
            .base()
            .checked_add(self.code_len)
            .ok_or_else(|| invalid_input("live code RX mapping end overflowed"))?;
        let control_end = self
            .control_rw
            .base()
            .checked_add(self.control_len)
            .ok_or_else(|| invalid_input("live control mapping end overflowed"))?;
        Ok([
            self.code_rw.base()..code_rw_end,
            self.code_rx.base()..code_rx_end,
            self.control_rw.base()..control_end,
        ])
    }

    pub fn revoke_rx(&self, range: Range<usize>) -> io::Result<()> {
        self.protect_rx(range, VM_PROT_NONE)
    }

    #[cfg(test)]
    fn restore_rx_for_test(&self, range: Range<usize>) -> io::Result<()> {
        self.protect_rx(range, VM_PROT_READ | VM_PROT_EXECUTE)
    }

    fn protect_rx(&self, range: Range<usize>, protection: vm_prot_t) -> io::Result<()> {
        let layout = self.control_layout();
        let logical_capacity = usize::try_from(layout.capacities().code)
            .map_err(|_| invalid_input("live code capacity exceeds usize"))?;
        let len = checked_page_range(&range, logical_capacity, "RX protection range")?;
        let actual_start = layout
            .code_payload_base()
            .checked_add(range.start)
            .ok_or_else(|| invalid_input("RX protection offset overflowed"))?;
        let address = self
            .code_rx
            .address
            .checked_add(actual_start as u64)
            .ok_or_else(|| invalid_input("RX protection address overflowed"))?;
        check_kr("mach_vm_protect live arena RX alias", unsafe {
            mach_vm_protect(mach_task_self(), address, len as u64, 0, protection)
        })
    }
}

/// Cloneable ownership of one process-local mapping view of a live arena.
///
/// The Mach objects may be the same in another process (or another mapping in
/// this process), but every constructor creates a fresh portable process-view
/// brand. Shared offsets are therefore reusable while local addresses and
/// claim authority are not.
///
/// ```compile_fail
/// use carrick_native_darwin::live_arena::DarwinLiveArena;
///
/// fn safe_native_api_does_not_expose_raw_portable_claim(arena: &DarwinLiveArena) {
///     let _raw_portable_view = arena.control_view().unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct LiveArenaProcessView {
    inner: Arc<LiveArenaProcessViewInner>,
}

struct LiveArenaProcessViewInner {
    arena: Arc<DarwinLiveArena>,
    process_brand: LiveProcessViewBrand,
    generation_domain: PageGenerationDomain,
    layout: LiveArenaControlLayout,
}

impl LiveArenaProcessView {
    pub fn new(
        arena: Arc<DarwinLiveArena>,
        generation_domain: PageGenerationDomain,
    ) -> io::Result<Self> {
        let control = arena.control_view()?;
        let layout = control.layout();
        if layout != arena.control_layout() {
            return Err(io::Error::other(
                "live arena process view geometry changed after adoption",
            ));
        }
        Ok(Self {
            inner: Arc::new(LiveArenaProcessViewInner {
                arena,
                process_brand: LiveProcessViewBrand::new(generation_domain.clone()),
                generation_domain,
                layout,
            }),
        })
    }

    pub fn acquire_ready_or_miss(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
    ) -> DarwinLiveReadyLookup {
        let Ok(control) = self.inner.arena.control_view() else {
            return DarwinLiveReadyLookup::Private(LivePrivateReason::InvalidRecord);
        };
        match control.acquire_ready_or_miss(&self.inner.process_brand, key, guest_start) {
            LiveReadyLookup::Ready(record) => {
                DarwinLiveReadyLookup::Ready(ValidatedLiveBlockHandle {
                    inner: Arc::clone(&self.inner),
                    record,
                })
            }
            LiveReadyLookup::Miss => DarwinLiveReadyLookup::Miss,
            LiveReadyLookup::Private(reason) => DarwinLiveReadyLookup::Private(reason),
        }
    }

    pub fn claim_eligible(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        block_end: GuestVa,
        generation: &PageGenerationObservation,
        owner_pid: i32,
    ) -> DarwinLiveLookup<'_> {
        let Ok(control) = self.inner.arena.control_view() else {
            return DarwinLiveLookup::Private(LivePrivateReason::InvalidRecord);
        };
        match control.claim_eligible(
            &self.inner.process_brand,
            key,
            guest_start,
            block_end,
            generation,
            owner_pid,
        ) {
            LiveLookup::Publish(claim) => {
                let guest_start = claim.guest_start();
                DarwinLiveLookup::Publish(DarwinLivePublishClaim {
                    inner: &self.inner,
                    claim,
                    guest_start,
                })
            }
            LiveLookup::Ready(record) => DarwinLiveLookup::Ready(ValidatedLiveBlockHandle {
                inner: Arc::clone(&self.inner),
                record,
            }),
            LiveLookup::Private(reason) => DarwinLiveLookup::Private(reason),
        }
    }

    #[cfg(test)]
    fn lookup(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        generation: &PageGenerationObservation,
        owner_pid: i32,
    ) -> DarwinLiveLookup<'_> {
        match self.acquire_ready_or_miss(key, guest_start) {
            DarwinLiveReadyLookup::Ready(ready) => DarwinLiveLookup::Ready(ready),
            DarwinLiveReadyLookup::Private(reason) => DarwinLiveLookup::Private(reason),
            DarwinLiveReadyLookup::Miss => self.claim_eligible(
                key,
                guest_start,
                GuestVa(guest_start.raw() + 12),
                generation,
                owner_pid,
            ),
        }
    }

    pub fn acquire(
        &self,
        ready: ValidatedLiveBlockHandle,
        generation: &PageGenerationObservation,
    ) -> Result<LiveArenaExecutable, LivePrivateReason> {
        if !generation.belongs_to(&self.inner.generation_domain)
            || !Arc::ptr_eq(&self.inner, &ready.inner)
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let control = self
            .inner
            .arena
            .control_view()
            .map_err(|_| LivePrivateReason::InvalidRecord)?;
        let record = control
            .revalidate_ready(&self.inner.process_brand, &ready.record)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        if generation.page().raw() != record.source_page()
            || generation.expected() != carrick_dsr_aarch64::types::CodeGeneration::INITIAL
            || generation.current() != carrick_dsr_aarch64::types::CodeGeneration::INITIAL
            || record.entry_offset() != 0
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let extents = record.extents();
        let code = self
            .inner
            .resolve_code(extents.code.offset, extents.code.len)?;
        let hot = self.inner.resolve_control(
            self.inner.layout.hot_base(),
            self.inner.layout.capacities().hot,
            extents.hot.offset,
            extents.hot.len,
        )?;
        let _cold_geometry = self.inner.resolve_control(
            self.inner.layout.cold_base(),
            self.inner.layout.capacities().cold,
            extents.cold.offset,
            extents.cold.len,
        )?;
        // SAFETY: both immutable ranges were checked against the retained
        // mapping geometry and READY makes their contents immutable. COLD is
        // intentionally left unresolved and lazy on this hot acquire path.
        let code_bytes = unsafe { std::slice::from_raw_parts(code.exec.as_ptr(), code.len) };
        let hot_bytes = unsafe { std::slice::from_raw_parts(hot.as_ptr(), hot.len) };
        if <[u8; 32]>::from(Sha256::digest(code_bytes)) != record.code_sha256()
            || validate_live_shared_initial_hot(hot_bytes, extents.code.len).is_err()
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        if generation.current() != carrick_dsr_aarch64::types::CodeGeneration::INITIAL {
            return Err(LivePrivateReason::InvalidRecord);
        }
        record_live_arena_test_event(LiveArenaTestEvent::ConsumerInvalidate {
            start: code.exec.as_ptr() as usize,
            len: code.len,
        });
        crate::jit::clear_icache(code.exec.as_ptr(), code.len);
        Ok(LiveArenaExecutable {
            inner: Arc::clone(&self.inner),
            record,
        })
    }
}

pub enum DarwinLiveLookup<'view> {
    Ready(ValidatedLiveBlockHandle),
    Publish(DarwinLivePublishClaim<'view>),
    Private(LivePrivateReason),
}

// READY lookup is the future translation hot path. Keep its copied,
// offset-only handle inline rather than heap-allocating every successful hit.
#[allow(clippy::large_enum_variant)]
pub enum DarwinLiveReadyLookup {
    Ready(ValidatedLiveBlockHandle),
    Miss,
    Private(LivePrivateReason),
}

pub struct ValidatedLiveBlockHandle {
    inner: Arc<LiveArenaProcessViewInner>,
    record: ValidatedLiveBlockRecord,
}

impl ValidatedLiveBlockHandle {
    pub fn extents(&self) -> LiveBlockExtents {
        self.record.extents()
    }

    pub fn code_sha256(&self) -> [u8; 32] {
        self.record.code_sha256()
    }
}

pub struct DarwinLivePublishClaim<'view> {
    inner: &'view Arc<LiveArenaProcessViewInner>,
    claim: LivePublishClaim<'view>,
    guest_start: GuestVa,
}

impl<'view> DarwinLivePublishClaim<'view> {
    pub fn reserve(
        self,
        prepared: PreparedSharedInitial,
    ) -> Result<DarwinLiveReservedPublication<'view>, LivePrivateReason> {
        let claim = self.claim.bind_prepared_identity(&prepared)?;
        let lengths = prepared.lengths();
        let reserved = claim.reserve(lengths.code, lengths.hot, lengths.cold)?;
        let extents = reserved.extents();

        let code = self
            .inner
            .resolve_code(extents.code.offset, extents.code.len)?;
        let hot = self.inner.resolve_control(
            self.inner.layout.hot_base(),
            self.inner.layout.capacities().hot,
            extents.hot.offset,
            extents.hot.len,
        )?;
        let cold = self.inner.resolve_control(
            self.inner.layout.cold_base(),
            self.inner.layout.capacities().cold,
            extents.cold.offset,
            extents.cold.len,
        )?;
        if code.write == code.exec {
            return Err(LivePrivateReason::InvalidRecord);
        }
        Ok(DarwinLiveReservedPublication {
            inner: self.inner,
            guest_start: self.guest_start,
            reserved,
            prepared,
            code,
            hot,
            cold,
        })
    }
}

pub struct DarwinLiveReservedPublication<'view> {
    inner: &'view Arc<LiveArenaProcessViewInner>,
    guest_start: GuestVa,
    reserved: LiveReservedPublishClaim<'view>,
    prepared: PreparedSharedInitial,
    code: CheckedCodeRange,
    hot: CheckedControlRange,
    cold: CheckedControlRange,
}

impl DarwinLiveReservedPublication<'_> {
    pub fn prebind(
        &mut self,
        candidate_index: usize,
        target: &LiveArenaExecutable,
    ) -> Result<LivePrebindOutcome, LivePrivateReason> {
        if !Arc::ptr_eq(self.inner, &target.inner) {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let candidate = self
            .prepared
            .link_candidates()
            .get(candidate_index)
            .copied()
            .ok_or(LivePrivateReason::InvalidRecord)?;
        let source_page = self.guest_start.raw() / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
        let source_page_end = source_page
            .checked_add(LIVE_SOURCE_PAGE_BYTES)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        if candidate.target.raw() != target.record.guest_start()
            || !(self.guest_start.raw()..source_page_end).contains(&candidate.source.raw())
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let target_extents = target.record.extents();
        let target_code = self
            .inner
            .resolve_code(target_extents.code.offset, target_extents.code.len)?;
        let target_entry = target_code
            .exec
            .as_ptr()
            .addr()
            .checked_add(target.record.entry_offset() as usize)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        // SAFETY: Arc identity proves the target capability and source
        // reservation use this exact process view. Both addresses are derived
        // from checked local RX extents; the emitter rechecks slot geometry and
        // AArch64 branch reachability before mutating only prepared bytes.
        unsafe {
            self.prepared.prebind_live_direct_link(
                candidate_index,
                HostVa(self.code.exec.as_ptr().addr()),
                HostVa(target_entry),
            )
        }
        .map_err(|_| LivePrivateReason::InvalidRecord)
    }

    pub fn publish(mut self) -> Result<ValidatedLiveBlockHandle, LivePrivateReason> {
        // SAFETY: the unique claim still owns these exact mapped ranges; the
        // permit is acquired before any metadata or code byte is written.
        let mut permit = unsafe { self.reserved.begin_mapped_write() }?;
        record_live_arena_test_event(LiveArenaTestEvent::PermitBegun);
        // SAFETY: the process view resolved both aliases and metadata pools
        // from this exact reservation. The cache borrow is tied to the permit,
        // process view, and current stack/thread.
        let cache = unsafe {
            LiveArenaTranslationCache::new(self.inner, &mut permit, self.code, self.hot, self.cold)
        };
        let expected = cache.publish(self.prepared)?;

        // The claim-bound cache and every address-bearing emitted value were
        // consumed and dropped before certification begins.
        let code_bytes =
            unsafe { std::slice::from_raw_parts(self.code.exec.as_ptr(), self.code.len) };
        let hot_bytes = unsafe { std::slice::from_raw_parts(self.hot.as_ptr(), self.hot.len) };
        let cold_bytes = unsafe { std::slice::from_raw_parts(self.cold.as_ptr(), self.cold.len) };
        // SAFETY: the exact mapped code/HOT/COLD ranges, INITIAL observation,
        // real cache publication, and post-publication digest are established
        // above. No mutable alias remains live at certification.
        let written = unsafe {
            permit.certify_mapped(
                code_bytes,
                hot_bytes,
                cold_bytes,
                GuestVa(self.guest_start.raw() / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES),
                0,
                expected,
            )
        }?;
        let record = self.reserved.publish(written)?;
        Ok(ValidatedLiveBlockHandle {
            inner: Arc::clone(self.inner),
            record,
        })
    }
}

/// Owned READY capability. It retains its process-local mappings and exposes
/// only shared offset metadata; executable address resolution stays private.
pub struct LiveArenaExecutable {
    inner: Arc<LiveArenaProcessViewInner>,
    record: ValidatedLiveBlockRecord,
}

impl LiveArenaExecutable {
    pub fn extents(&self) -> LiveBlockExtents {
        let _retained_process_view = &self.inner;
        self.record.extents()
    }

    pub fn code_sha256(&self) -> [u8; 32] {
        self.record.code_sha256()
    }

    /// Address-free receipt for the exact consumer-local RX range invalidated
    /// before this executable authority was returned.
    pub fn invalidated_code_extent(&self) -> carrick_dsr_aarch64::live_arena::LiveReservation {
        self.record.extents().code
    }
}

#[derive(Clone, Copy)]
struct CheckedCodeRange {
    write: NonNull<u8>,
    exec: NonNull<u8>,
    len: usize,
}

#[derive(Clone, Copy)]
struct CheckedControlRange {
    base: NonNull<u8>,
    len: usize,
}

impl CheckedControlRange {
    const fn as_ptr(self) -> *mut u8 {
        self.base.as_ptr()
    }
}

impl LiveArenaProcessViewInner {
    fn resolve_code(
        &self,
        logical_offset: u64,
        logical_len: u64,
    ) -> Result<CheckedCodeRange, LivePrivateReason> {
        let offset =
            usize::try_from(logical_offset).map_err(|_| LivePrivateReason::InvalidRecord)?;
        let len = usize::try_from(logical_len).map_err(|_| LivePrivateReason::InvalidRecord)?;
        let capacity = usize::try_from(self.layout.capacities().code)
            .map_err(|_| LivePrivateReason::InvalidRecord)?;
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= capacity)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        if offset == end {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let actual = self
            .layout
            .code_payload_base()
            .checked_add(offset)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        let write = self
            .arena
            .code_rw
            .base()
            .checked_add(actual)
            .and_then(|value| NonNull::new(value as *mut u8))
            .ok_or(LivePrivateReason::InvalidRecord)?;
        let exec = self
            .arena
            .code_rx
            .base()
            .checked_add(actual)
            .and_then(|value| NonNull::new(value as *mut u8))
            .ok_or(LivePrivateReason::InvalidRecord)?;
        Ok(CheckedCodeRange { write, exec, len })
    }

    fn resolve_control(
        &self,
        payload_base: usize,
        payload_capacity: u64,
        logical_offset: u64,
        logical_len: u64,
    ) -> Result<CheckedControlRange, LivePrivateReason> {
        let offset =
            usize::try_from(logical_offset).map_err(|_| LivePrivateReason::InvalidRecord)?;
        let len = usize::try_from(logical_len).map_err(|_| LivePrivateReason::InvalidRecord)?;
        let capacity =
            usize::try_from(payload_capacity).map_err(|_| LivePrivateReason::InvalidRecord)?;
        let logical_end = offset
            .checked_add(len)
            .filter(|end| *end <= capacity)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        if offset == logical_end {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let actual = payload_base
            .checked_add(offset)
            .ok_or(LivePrivateReason::InvalidRecord)?;
        actual
            .checked_add(len)
            .filter(|end| *end <= self.layout.control_len())
            .ok_or(LivePrivateReason::InvalidRecord)?;
        let base = self
            .arena
            .control_rw
            .base()
            .checked_add(actual)
            .and_then(|value| NonNull::new(value as *mut u8))
            .ok_or(LivePrivateReason::InvalidRecord)?;
        Ok(CheckedControlRange { base, len })
    }
}

/// A claim-bound cache that cannot leave this stack or cross a thread. Its
/// only operation consumes one prepared block into the exact mapped extent.
struct LiveArenaTranslationCache<'borrow, 'claim, 'view> {
    cache: TranslationCache,
    _view: &'borrow LiveArenaProcessViewInner,
    _permit: &'borrow mut LiveMappedWritePermit<'claim, 'view>,
    code: CheckedCodeRange,
    hot: CheckedControlRange,
    cold: CheckedControlRange,
    _thread: PhantomData<Rc<()>>,
}

impl<'borrow, 'claim, 'view> LiveArenaTranslationCache<'borrow, 'claim, 'view> {
    unsafe fn new(
        view: &'borrow LiveArenaProcessViewInner,
        permit: &'borrow mut LiveMappedWritePermit<'claim, 'view>,
        code: CheckedCodeRange,
        hot: CheckedControlRange,
        cold: CheckedControlRange,
    ) -> Self {
        let region = JitRegion {
            exec_base: code.exec,
            write_base: code.write,
            capacity: code.len,
        };
        Self {
            cache: TranslationCache::from_region(region, &LIVE_ARENA_HOST_JIT),
            _view: view,
            _permit: permit,
            code,
            hot,
            cold,
            _thread: PhantomData,
        }
    }

    fn publish(
        mut self,
        prepared: PreparedSharedInitial,
    ) -> Result<ExpectedLivePublication, LivePrivateReason> {
        let lengths = prepared.lengths();
        let expected_code =
            usize::try_from(lengths.code).map_err(|_| LivePrivateReason::InvalidRecord)?;
        if expected_code != self.code.len
            || usize::try_from(lengths.hot) != Ok(self.hot.len)
            || usize::try_from(lengths.cold) != Ok(self.cold.len)
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        // This proof is intentionally derived only after the caller's optional
        // same-view prebinding has completed and immediately before mapped
        // bytes are committed.
        let expected = prepared.expected_publication();
        record_live_arena_test_event(LiveArenaTestEvent::MetadataWrite);
        // SAFETY: `_permit` is the unique mapped-write authority for these
        // exact pool-bounded ranges, and all lengths were checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(
                prepared.hot_bytes().as_ptr(),
                self.hot.as_ptr(),
                self.hot.len,
            );
            std::ptr::copy_nonoverlapping(
                prepared.cold_bytes().as_ptr(),
                self.cold.as_ptr(),
                self.cold.len,
            );
        }
        let emitted = prepared
            .publish(&mut self.cache)
            .map_err(|_| LivePrivateReason::InvalidRecord)?;
        if emitted.entry().host().raw() != self.code.exec.as_ptr() as usize
            || emitted.len() != expected_code
            || emitted.trusted_entry() != Some(CacheOffset::published(0))
            || self.cache.used_bytes() != expected_code
            || self.cache.capacity_bytes() != expected_code
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        drop(emitted);
        Ok(expected)
    }
}

static LIVE_ARENA_HOST_JIT: LiveArenaHostJit = LiveArenaHostJit;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveArenaTestEvent {
    PermitBegun,
    MetadataWrite,
    PublisherFlush { start: usize, len: usize },
    ConsumerInvalidate { start: usize, len: usize },
}

#[cfg(test)]
thread_local! {
    static LIVE_ARENA_TEST_EVENTS: std::cell::RefCell<Vec<LiveArenaTestEvent>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn record_live_arena_test_event(event: LiveArenaTestEvent) {
    LIVE_ARENA_TEST_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(not(test))]
fn record_live_arena_test_event(_event: LiveArenaTestEvent) {}

#[cfg(test)]
fn clear_live_arena_test_events() {
    LIVE_ARENA_TEST_EVENTS.with(|events| events.borrow_mut().clear());
}

#[cfg(test)]
fn take_live_arena_test_events() -> Vec<LiveArenaTestEvent> {
    LIVE_ARENA_TEST_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

/// A checked view of matching RW/RX aliases whose lifetime is tied to its
/// arena. It intentionally cannot produce an owned [`JitRegion`]: reservation
/// authority and unique writer ranges come from the Task 2 allocation protocol,
/// while byte writes through the raw pointer remain unsafe.
///
/// ```compile_fail
/// use carrick_dsr::host::JitRegion;
/// use carrick_native_darwin::live_arena::DarwinLiveArena;
///
/// fn escape_owned_region(arena: &DarwinLiveArena) -> JitRegion {
///     arena
///         .jit_region(0..8)
///         .unwrap()
///         .sub_region(0, 8)
///         .unwrap()
/// }
/// ```
#[cfg(test)]
struct BorrowedLiveJitRegion<'a> {
    exec_base: NonNull<u8>,
    write_base: NonNull<u8>,
    capacity: usize,
    _arena: PhantomData<&'a DarwinLiveArena>,
}

#[cfg(test)]
impl BorrowedLiveJitRegion<'_> {
    fn exec_base(&self) -> BorrowedLiveJitPointer<'_> {
        BorrowedLiveJitPointer {
            pointer: self.exec_base,
            _region: PhantomData,
        }
    }

    fn write_base(&self) -> BorrowedLiveJitPointer<'_> {
        BorrowedLiveJitPointer {
            pointer: self.write_base,
            _region: PhantomData,
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }
}

/// A pointer token whose lifetime is bounded by a checked live-arena region.
/// It has no safe conversion to a raw pointer or owned [`JitRegion`].
#[cfg(test)]
struct BorrowedLiveJitPointer<'a> {
    pointer: NonNull<u8>,
    _region: PhantomData<&'a BorrowedLiveJitRegion<'a>>,
}

#[cfg(test)]
impl BorrowedLiveJitPointer<'_> {
    /// Exposes the checked alias pointer for low-level code emission or entry.
    ///
    /// # Safety
    ///
    /// The pointer must not be retained beyond this token's lifetime. This
    /// conversion does not establish exclusive write authority: a caller that
    /// writes through it must hold the unique range granted by the Task 2
    /// reservation protocol and obey the alias's current Mach protection.
    unsafe fn as_ptr(&self) -> *mut u8 {
        self.pointer.as_ptr()
    }
}

pub struct LiveArenaHostJit;

impl NativeHostJit for LiveArenaHostJit {
    fn supported(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn map_code_cache(&self, _capacity: usize) -> io::Result<JitRegion> {
        Err(io::Error::other(
            "live arena JIT regions are borrowed from DarwinLiveArena",
        ))
    }

    unsafe fn unmap(&self, _region: &JitRegion) {}

    fn begin_thread_write(&self) {}

    fn end_thread_write(&self) {}

    fn flush_icache(&self, exec_ptr: *const u8, len: usize) {
        record_live_arena_test_event(LiveArenaTestEvent::PublisherFlush {
            start: exec_ptr as usize,
            len,
        });
        crate::jit::clear_icache(exec_ptr, len);
    }

    fn remap_for_fork_child(&self, _prior: &JitRegion) -> io::Result<ForkChildJit> {
        Ok(ForkChildJit::Inherited)
    }
}

fn host_page_size() -> io::Result<usize> {
    let page = unsafe { mach2::vm_page_size::vm_page_size };
    if page == 0 || !page.is_power_of_two() {
        return Err(io::Error::other(format!("invalid Mach page size {page}")));
    }
    Ok(page)
}

fn validate_arena_len(label: &str, len: usize) -> io::Result<()> {
    let page = host_page_size()?;
    if len == 0 || !len.is_multiple_of(page) {
        return Err(invalid_input(format!(
            "{label} arena length {len} is not a nonzero multiple of host page size {page}"
        )));
    }
    u64::try_from(len).map_err(|_| invalid_input(format!("{label} arena length exceeds u64")))?;
    Ok(())
}

fn validate_transit(transit: LiveArenaTransitV2) -> io::Result<()> {
    if transit.schema != LIVE_ARENA_TRANSIT_SCHEMA_V2 {
        return Err(invalid_input(format!(
            "unsupported live arena schema {}",
            transit.schema
        )));
    }
    let code_len = usize::try_from(transit.code_len)
        .map_err(|_| invalid_input("live code length exceeds usize"))?;
    let control_len = usize::try_from(transit.control_len)
        .map_err(|_| invalid_input("live control length exceeds usize"))?;
    validate_arena_len("code", code_len)?;
    validate_arena_len("control", control_len)
}

fn object_header(kind: u32, transit: LiveArenaTransitV2) -> [u8; LIVE_OBJECT_HEADER_LEN] {
    let mut header = [0_u8; LIVE_OBJECT_HEADER_LEN];
    header[0..8].copy_from_slice(&LIVE_OBJECT_MAGIC);
    header[8..12].copy_from_slice(&kind.to_le_bytes());
    header[12..16].copy_from_slice(&transit.schema.to_le_bytes());
    header[16..24].copy_from_slice(&transit.code_len.to_le_bytes());
    header[24..32].copy_from_slice(&transit.control_len.to_le_bytes());
    header[32..48].copy_from_slice(&transit.nonce);
    header
}

fn write_object_header(
    mapping: &VmMapping,
    kind: u32,
    transit: LiveArenaTransitV2,
) -> io::Result<()> {
    if mapping.len < LIVE_OBJECT_HEADER_LEN as u64 {
        return Err(invalid_input(
            "live arena object is smaller than its header",
        ));
    }
    let header = object_header(kind, transit);
    unsafe {
        std::ptr::copy_nonoverlapping(header.as_ptr(), mapping.base() as *mut u8, header.len());
    }
    Ok(())
}

fn validate_object_header(
    mapping: &VmMapping,
    kind: u32,
    transit: LiveArenaTransitV2,
) -> io::Result<()> {
    if mapping.len < LIVE_OBJECT_HEADER_LEN as u64 {
        return Err(invalid_input(
            "live arena object is smaller than its header",
        ));
    }
    let mut observed = [0_u8; LIVE_OBJECT_HEADER_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(
            mapping.base() as *const u8,
            observed.as_mut_ptr(),
            observed.len(),
        );
    }
    if observed != object_header(kind, transit) {
        return Err(io::Error::other(format!(
            "live arena object header does not match {kind} metadata"
        )));
    }
    Ok(())
}

fn checked_range(range: &Range<usize>, capacity: usize, label: &str) -> io::Result<usize> {
    if range.start >= range.end || range.end > capacity {
        return Err(invalid_input(format!(
            "{label} {:?} is empty, reversed, or outside capacity {capacity}",
            range
        )));
    }
    range
        .end
        .checked_sub(range.start)
        .ok_or_else(|| invalid_input(format!("{label} length overflowed")))
}

fn checked_page_range(range: &Range<usize>, capacity: usize, label: &str) -> io::Result<usize> {
    let len = checked_range(range, capacity, label)?;
    let page = host_page_size()?;
    if !range.start.is_multiple_of(page) || !len.is_multiple_of(page) {
        return Err(invalid_input(format!(
            "{label} {:?} is not host-page aligned ({page})",
            range
        )));
    }
    Ok(len)
}

fn check_kr(operation: &'static str, result: kern_return_t) -> io::Result<()> {
    if result == KERN_SUCCESS {
        Ok(())
    } else {
        Err(mach_error(operation, result))
    }
}

fn mach_error(operation: &'static str, result: kern_return_t) -> io::Error {
    io::Error::other(format!("{operation}: kern_return={result}"))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
const PIPE_EINTR_RETRY_LIMIT: usize = 8;

#[cfg(test)]
fn retry_one_byte_pipe_io(mut operation: impl FnMut() -> (libc::ssize_t, libc::c_int)) -> bool {
    let mut interrupted = 0;
    loop {
        let (result, errno) = operation();
        if result == 1 {
            return true;
        }
        if result != -1 || errno != libc::EINTR || interrupted == PIPE_EINTR_RETRY_LIMIT {
            return false;
        }
        interrupted += 1;
    }
}

#[cfg(test)]
fn read_pipe_byte(fd: libc::c_int) -> Option<u8> {
    let mut byte = 0;
    retry_one_byte_pipe_io(|| {
        let result = unsafe { libc::read(fd, (&raw mut byte).cast(), 1) };
        let errno = if result == -1 {
            unsafe { *libc::__error() }
        } else {
            0
        };
        (result, errno)
    })
    .then_some(byte)
}

#[cfg(test)]
fn write_pipe_byte(fd: libc::c_int, byte: u8) -> bool {
    retry_one_byte_pipe_io(|| {
        let result = unsafe { libc::write(fd, (&raw const byte).cast(), 1) };
        let errno = if result == -1 {
            unsafe { *libc::__error() }
        } else {
            0
        };
        (result, errno)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::cache::PageGenerationTable;
    use carrick_dsr::host::NativeHostJit;
    use carrick_dsr_aarch64::block::{BlockPlan, PlannedExit, PlannedInst};
    use carrick_dsr_aarch64::emit::{
        EmitAddressMode, PreparedSharedInitial, prepare_shared_initial,
    };
    use carrick_dsr_aarch64::live_arena::{LiveArenaCapacities, LiveArenaControlDirectoryV2};
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        NativePageProfileIdentity, SourceFingerprint, TranslationUnitKey,
    };
    use carrick_dsr_aarch64::types::{CodeGeneration, DirectExit, DirectKind, InstAction};
    use carrick_guest_mem::GuestVa;
    use static_assertions::assert_not_impl_any;
    use std::ops::Range;
    use std::sync::Arc;

    assert_not_impl_any!(LiveArenaTranslationCache<'static, 'static, 'static>: Send, Sync);

    const CODE: Range<usize> = 0..8;

    #[test]
    fn private_live_cache_cannot_escape_or_cross_thread() {
        assert!(
            !std::any::type_name::<LiveArenaTranslationCache<'static, 'static, 'static>>()
                .is_empty()
        );
    }

    #[test]
    fn safe_native_api_does_not_expose_raw_portable_claim() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(arena, generations.domain()).expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let claim = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 40) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        assert!(std::any::type_name_of_val(&claim).contains("DarwinLivePublishClaim"));
        drop(claim);
    }

    fn page() -> usize {
        host_page_size().expect("valid Mach host page size")
    }

    fn return_immediate(value: u16) -> [u8; 8] {
        let mov_w0 = 0x5280_0000_u32 | (u32::from(value) << 5);
        let ret = 0xd65f_03c0_u32;
        let mut code = [0_u8; 8];
        code[..4].copy_from_slice(&mov_w0.to_le_bytes());
        code[4..].copy_from_slice(&ret.to_le_bytes());
        code
    }

    unsafe fn exec_ptr(region: &BorrowedLiveJitRegion<'_>) -> *mut u8 {
        unsafe { region.exec_base().as_ptr() }
    }

    unsafe fn write_ptr(region: &BorrowedLiveJitRegion<'_>) -> *mut u8 {
        unsafe { region.write_base().as_ptr() }
    }

    unsafe fn call_u32(region: &BorrowedLiveJitRegion<'_>) -> u32 {
        let entry: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(exec_ptr(region)) };
        unsafe { entry() }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn writer_and_rx_alias_execute_coherent_code() {
        let arena = protocol_arena();
        let region = arena.jit_region(CODE).expect("code subregion");
        let jit = LiveArenaHostJit;

        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(42).as_ptr(), write_ptr(&region), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&region) }, 8);
        assert_eq!(unsafe { call_u32(&region) }, 42);

        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(43).as_ptr(), write_ptr(&region), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&region) }, 8);
        assert_eq!(unsafe { call_u32(&region) }, 43);
    }

    #[test]
    fn fd_objects_map_at_unrelated_addresses() {
        assert!(DarwinLiveArena::new(LiveArenaCapacities::new(0, 0, 0)).is_err());
        let arena = protocol_arena();
        let code = fd_identity(arena.code_object.as_raw_fd(), "code").expect("code identity");
        let control =
            fd_identity(arena.control_object.as_raw_fd(), "control").expect("control identity");
        assert_ne!(
            (code.0, code.1),
            (control.0, control.1),
            "code and control must be distinct backing objects"
        );
        assert_eq!(code.2, arena.control_layout().code_len() as u64);
        assert_eq!(control.2, arena.control_layout().control_len() as u64);
        assert_ne!(arena.code_rw.base(), arena.code_rx.base());
        assert_ne!(arena.code_rw.base(), arena.control_rw.base());
        assert_ne!(arena.code_rx.base(), arena.control_rw.base());
        assert_eq!(arena.code_rw.len(), arena.control_layout().code_len());
        assert_eq!(arena.code_rx.len(), arena.control_layout().code_len());
        assert_eq!(arena.control_rw.len(), arena.control_layout().control_len());
        assert_eq!(
            mapping_protections_for_test(arena.code_rw.base()),
            Some((VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE))
        );
        assert_eq!(
            mapping_protections_for_test(arena.code_rx.base()),
            Some((
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE
            ))
        );
        assert_eq!(
            mapping_protections_for_test(arena.control_rw.base()),
            Some((VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE))
        );
        for address in [
            arena.code_rw.base(),
            arena.code_rx.base(),
            arena.control_rw.base(),
        ] {
            let (current, _) = mapping_protections_for_test(address).expect("mapped alias");
            assert_ne!(
                current & (VM_PROT_WRITE | VM_PROT_EXECUTE),
                VM_PROT_WRITE | VM_PROT_EXECUTE,
                "returned live alias must never be W+X"
            );
        }
        let transit = arena.transit_v2();
        assert_eq!(transit.schema, LIVE_ARENA_TRANSIT_SCHEMA_V2);
        assert_eq!(transit.code_len, arena.control_layout().code_len() as u64);
        assert_eq!(
            transit.control_len,
            arena.control_layout().control_len() as u64
        );
    }

    /// The dual-alias write/execute/republish cycle on fd backing, in the
    /// production types: probe receipts P2-file `exec_child`,
    /// `exec_appended_same_page`, and `exec_overwritten`.
    ///
    /// Appending to an ALREADY-EXECUTED page and overwriting live code both
    /// matter for the arena's steady state — a chunk is filled block by block
    /// long after its first block has been entered — and neither needs a
    /// remap, only the publisher's I-cache flush.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn fd_arena_dual_aliases_execute_published_code() {
        let arena = protocol_arena();
        let jit = LiveArenaHostJit;
        let first = arena.jit_region(0..8).expect("first code subregion");
        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(42).as_ptr(), write_ptr(&first), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&first) }, 8);
        assert_eq!(unsafe { call_u32(&first) }, 42);

        // Append a second function to the same, already-executed page.
        let appended = arena.jit_region(128..136).expect("appended code subregion");
        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(43).as_ptr(), write_ptr(&appended), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&appended) }, 8);
        assert_eq!(unsafe { call_u32(&appended) }, 43);
        assert_eq!(
            unsafe { call_u32(&first) },
            42,
            "the first block still runs"
        );

        // Overwrite the first function through the RW alias.
        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(44).as_ptr(), write_ptr(&first), 8)
        };
        jit.flush_icache(unsafe { exec_ptr(&first) }, 8);
        assert_eq!(unsafe { call_u32(&first) }, 44);
    }

    /// Both aliases must read back `current == max == requested`, and neither
    /// may be escalatable afterwards.
    ///
    /// A fresh file mapping's maximum protection is `rwx` on this host, so
    /// without the `mach_vm_protect(set_maximum)` clamp any holder could
    /// `mprotect` the RW alias executable or the RX alias writable. The clamp
    /// is also what makes the equality check above hold verbatim — the check
    /// that turns a silently-downgraded alias into a named refusal.
    #[test]
    fn fd_arena_alias_protections_are_clamped_and_validated() {
        let arena = protocol_arena();
        for (address, expected) in [
            (arena.code_rw.base(), VM_PROT_READ | VM_PROT_WRITE),
            (arena.code_rx.base(), VM_PROT_READ | VM_PROT_EXECUTE),
            (arena.control_rw.base(), VM_PROT_READ | VM_PROT_WRITE),
        ] {
            assert_eq!(
                mapping_protections_for_test(address),
                Some((expected, expected)),
                "every alias must read back current == max == requested"
            );
        }
        let page = page();
        for (address, escalation) in [
            (
                arena.code_rw.base(),
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ),
            (arena.code_rx.base(), libc::PROT_READ | libc::PROT_WRITE),
            (
                arena.control_rw.base(),
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ),
        ] {
            let refused =
                unsafe { libc::mprotect(address as *mut libc::c_void, page, escalation) } != 0;
            assert!(
                refused,
                "the clamped maximum must refuse escalating 0x{address:x} to {escalation:#x}"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES)
            );
        }
        // A rejected escalation must not have disturbed the live protections.
        assert_eq!(
            mapping_protections_for_test(arena.code_rx.base()),
            Some((
                VM_PROT_READ | VM_PROT_EXECUTE,
                VM_PROT_READ | VM_PROT_EXECUTE
            ))
        );
    }

    /// A transport-shaped authority over fresh DUPLICATES of the arena's
    /// descriptors, prepared exactly as the capsule prepares them (close-on-exec
    /// cleared for the exec window).
    ///
    /// Adoption consumes the duplicates, so the creator's own descriptors are
    /// untouched — the same separation a real successor gets by inheriting one
    /// fd-table entry while the creator keeps its own in another process.
    fn transport_authority_for_test(arena: &DarwinLiveArena) -> LiveArenaReexecAuthority {
        let mut authority = arena.reexec_authority().expect("creator authority");
        for object in [&mut authority.code, &mut authority.control] {
            let transport = unsafe { libc::fcntl(object.host_fd, libc::F_DUPFD, 0) };
            assert!(transport >= 0, "duplicate transport descriptor");
            assert_eq!(
                unsafe {
                    libc::fcntl(
                        transport,
                        libc::F_SETFD,
                        object.original_host_fd_flags & !libc::FD_CLOEXEC,
                    )
                },
                0
            );
            object.host_fd = transport;
        }
        authority
    }

    #[allow(clippy::panic)]
    fn expect_adoption_refusal(result: io::Result<DarwinLiveArena>, expectation: &str) -> String {
        match result {
            Ok(_) => panic!("{expectation}"),
            Err(error) => error.to_string(),
        }
    }

    fn close_transport_for_test(authority: &LiveArenaReexecAuthority) {
        for object in [&authority.code, &authority.control] {
            unsafe { libc::close(object.host_fd) };
        }
    }

    /// Adoption is authenticated, not merely inherited. Each drift shape has
    /// its own named refusal, and a refusal consumes nothing.
    #[test]
    fn fd_arena_adoption_rejects_identity_or_flag_drift() {
        let arena = protocol_arena();
        let creator = arena.reexec_authority().expect("creator authority");
        // The steady state of a backing descriptor is close-on-exec: an exec
        // that is not the deliberate capsule transit leaks nothing.
        assert_eq!(
            creator.code.original_host_fd_flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );
        assert_eq!(
            creator.control.original_host_fd_flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC
        );

        // Wrong descriptor: it names a different object than the snapshot.
        let stranger = create_backing_object("stranger", creator.code.host_size as usize)
            .expect("stranger backing object");
        assert_eq!(
            unsafe { libc::fcntl(stranger.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let mut wrong_fd = transport_authority_for_test(&arena);
        let displaced = std::mem::replace(&mut wrong_fd.code.host_fd, stranger.as_raw_fd());
        let error = expect_adoption_refusal(
            DarwinLiveArena::adopt_reexec(wrong_fd),
            "a descriptor naming another object must be refused",
        );
        assert!(error.contains("identity changed"), "{error}");
        wrong_fd.code.host_fd = displaced;
        close_transport_for_test(&wrong_fd);

        // Changed flags: close-on-exec still set means this descriptor was
        // never prepared for the capsule transit.
        let changed_flags = transport_authority_for_test(&arena);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    changed_flags.control.host_fd,
                    libc::F_SETFD,
                    libc::FD_CLOEXEC,
                )
            },
            0
        );
        let error = expect_adoption_refusal(
            DarwinLiveArena::adopt_reexec(changed_flags),
            "un-prepared descriptor flags must be refused",
        );
        assert!(error.contains("fd flags changed"), "{error}");
        close_transport_for_test(&changed_flags);

        // Wrong size: the claimed object size and the transit length disagree.
        let mut wrong_size = transport_authority_for_test(&arena);
        wrong_size.control.host_size -= page() as u64;
        let error = expect_adoption_refusal(
            DarwinLiveArena::adopt_reexec(wrong_size),
            "a size disagreeing with the transit length must be refused",
        );
        assert!(error.contains("does not match transit length"), "{error}");
        close_transport_for_test(&wrong_size);

        // Wrong nonce: genuine descriptors that name another arena.
        let mut wrong_nonce = transport_authority_for_test(&arena);
        wrong_nonce.transit.nonce = [0xff; 16];
        let error = expect_adoption_refusal(
            DarwinLiveArena::adopt_reexec(wrong_nonce),
            "a foreign nonce must be refused",
        );
        assert!(error.contains("object header"), "{error}");
        close_transport_for_test(&wrong_nonce);

        // The exact authority still adopts, and every refusal above left the
        // creator's own arena and descriptors intact.
        let good = transport_authority_for_test(&arena);
        let adopted = DarwinLiveArena::adopt_reexec(good).expect("the exact authority adopts");
        assert_eq!(adopted.transit_v2(), creator.transit);
        // The adopter re-owns through `F_DUPFD_CLOEXEC`, so its steady state
        // is close-on-exec again, and it releases the transport numbers: an
        // exec that is not the next deliberate capsule transit leaks nothing.
        let adopted_authority = adopted.reexec_authority().expect("adopted authority");
        for object in [adopted_authority.code, adopted_authority.control] {
            assert_eq!(
                object.original_host_fd_flags & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC
            );
        }
        for object in [good.code, good.control] {
            assert_ne!(object.host_fd, adopted_authority.code.host_fd);
            assert_ne!(object.host_fd, adopted_authority.control.host_fd);
            assert!(
                unsafe { libc::fcntl(object.host_fd, libc::F_GETFD) } < 0,
                "the transport descriptor must be released after adoption"
            );
        }
        assert_eq!(
            arena.reexec_authority().expect("creator authority").transit,
            creator.transit
        );
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn task_local_rx_revoke_does_not_revoke_parent() {
        let arena = protocol_arena();
        let region = arena.jit_region(CODE).expect("code subregion");
        unsafe {
            std::ptr::copy_nonoverlapping(return_immediate(42).as_ptr(), write_ptr(&region), 8)
        };
        LiveArenaHostJit.flush_icache(unsafe { exec_ptr(&region) }, 8);

        let mut ready_pipe = [-1; 2];
        let mut restore_pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(ready_pipe.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(restore_pipe.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe {
                libc::close(ready_pipe[0]);
                libc::close(restore_pipe[1]);
            }
            let mut status = 0;
            if arena.revoke_rx(0..page()).is_err()
                || mapping_protections_for_test(arena.code_rx.base() + arena.code_payload_base())
                    != Some((VM_PROT_NONE, VM_PROT_READ | VM_PROT_EXECUTE))
            {
                status = 1;
            }

            if status == 0 {
                let fault_child = unsafe { libc::fork() };
                if fault_child < 0 {
                    status = 2;
                } else if fault_child == 0 {
                    unsafe {
                        libc::signal(libc::SIGBUS, libc::SIG_DFL);
                        libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                        let _ = call_u32(&region);
                        libc::_exit(90);
                    }
                } else {
                    let mut fault_status = 0;
                    if unsafe { libc::waitpid(fault_child, &mut fault_status, 0) } != fault_child
                        || !libc::WIFSIGNALED(fault_status)
                        || libc::WTERMSIG(fault_status) != libc::SIGBUS
                    {
                        status = 3;
                    }
                }
            }

            if status == 0 && !write_pipe_byte(ready_pipe[1], 0xa5) {
                status = 4;
            }
            let restore = if status == 0 {
                read_pipe_byte(restore_pipe[0])
            } else {
                None
            };
            if status == 0 && restore.is_none() {
                status = 5;
            }
            if status == 0
                && (restore != Some(0x5a)
                    || arena.restore_rx_for_test(0..page()).is_err()
                    || mapping_protections_for_test(
                        arena.code_rx.base() + arena.code_payload_base(),
                    ) != Some((
                        VM_PROT_READ | VM_PROT_EXECUTE,
                        VM_PROT_READ | VM_PROT_EXECUTE,
                    )))
            {
                status = 6;
            }
            unsafe {
                libc::close(ready_pipe[1]);
                libc::close(restore_pipe[0]);
            }
            unsafe { libc::_exit(status) };
        }

        unsafe {
            libc::close(ready_pipe[1]);
            libc::close(restore_pipe[0]);
        }
        let ready = read_pipe_byte(ready_pipe[0]);
        let parent_result = if ready == Some(0xa5) {
            Some(unsafe { call_u32(&region) })
        } else {
            None
        };
        let restore_delivered = ready.is_some() && write_pipe_byte(restore_pipe[1], 0x5a);
        unsafe {
            libc::close(ready_pipe[0]);
            // Close before waitpid on success and every delivery failure. If
            // the child is blocked in read, EOF makes it exit nonzero.
            libc::close(restore_pipe[1]);
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(ready, Some(0xa5));
        assert_eq!(parent_result, Some(42));
        assert!(restore_delivered);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn drop_unmaps_aliases_and_closes_backing_objects() {
        let arena = protocol_arena();
        let addresses = [
            arena.code_rw.base(),
            arena.code_rx.base(),
            arena.control_rw.base(),
        ];
        let object_ids = addresses.map(|address| {
            mapping_object_id_for_test(address).expect("live alias has Mach object identity")
        });
        assert_eq!(
            object_ids[0], object_ids[1],
            "both code aliases must map the same backing object"
        );
        assert_ne!(object_ids[0], object_ids[2]);
        let backing = [
            (
                arena.code_object.as_raw_fd(),
                fd_identity(arena.code_object.as_raw_fd(), "code").expect("code identity"),
            ),
            (
                arena.control_object.as_raw_fd(),
                fd_identity(arena.control_object.as_raw_fd(), "control").expect("control identity"),
            ),
        ];
        drop(arena);

        for (address, old_object_id) in addresses.into_iter().zip(object_ids) {
            assert_ne!(
                mapping_object_id_for_test(address),
                Some(old_object_id),
                "the dropped alias's original object must no longer occupy its VA"
            );
        }
        for (fd, identity) in backing {
            assert!(
                fd_no_longer_refers_to_for_test(fd, identity),
                "the dropped arena must have closed its backing descriptor"
            );
        }
    }

    #[test]
    fn subregion_exposes_matching_rw_and_rx_offsets() {
        let arena = protocol_arena();
        let range = 32..96;
        let region = arena.jit_region(range.clone()).expect("code subregion");
        assert_eq!(region.capacity(), range.len());
        assert_eq!(
            unsafe { write_ptr(&region) } as usize - arena.code_rw.base(),
            arena.code_payload_base() + range.start
        );
        assert_eq!(
            unsafe { exec_ptr(&region) } as usize - arena.code_rx.base(),
            arena.code_payload_base() + range.start
        );
        let capacity = arena.control_layout().capacities().code as usize;
        assert!(arena.jit_region(capacity - 4..capacity + 4).is_err());
    }

    /// EMPIRICAL BOUNDARY (Task 6T1): the 6C2 blocker test, inverted.
    ///
    /// 6C2 measured that a guest `fork(2)` child inherits the arena's
    /// `VM_INHERIT_SHARE` bytes but NOT the Mach rights that carried it, so it
    /// could not transport the arena through its own host self-exec — and a
    /// guest `fork`+`execve` is how essentially every real workload creates a
    /// process, which made the container-lifetime arena reach none of them.
    ///
    /// On fd backing there is no per-child capability to mint: the descriptors
    /// are inherited, so the child holds the bytes AND can build the exact
    /// authority its own capsule will carry. This test is the durable record
    /// that the campaign-critical crossing is open.
    #[test]
    fn a_fork_child_inherits_arena_mappings_and_its_fd_transport() {
        let arena = protocol_arena();
        let parent_authority = arena.reexec_authority().expect("parent authority");
        let control = arena.control_rw.base() as *mut u8;
        // A byte only the parent could have written, read back by the child.
        unsafe { control.add(LIVE_OBJECT_HEADER_LEN).write_volatile(0x6c) };

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let mut status = 0;
            if unsafe { control.add(LIVE_OBJECT_HEADER_LEN).read_volatile() } != 0x6c {
                status = 1; // mapping not inherited
            }
            match arena.reexec_authority() {
                Ok(child_authority) => {
                    if status == 0 && child_authority != parent_authority {
                        status = 2; // the inherited authority is not the same object
                    }
                }
                Err(_) if status == 0 => status = 3, // no transport buildable at all
                Err(_) => {}
            }
            // The child writes through its inherited RW alias; the parent must
            // observe it, proving the sharing is live in both directions.
            unsafe { control.add(LIVE_OBJECT_HEADER_LEN + 1).write_volatile(0xc6) };
            unsafe { libc::_exit(status) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "1=mapping not inherited, 2=inherited authority names another object, \
             3=the child cannot build its exec transport"
        );
        assert_eq!(
            unsafe { control.add(LIVE_OBJECT_HEADER_LEN + 1).read_volatile() },
            0xc6,
            "the parent must observe the child's write"
        );
        // The child's exit disturbed nothing the parent owns.
        assert_eq!(
            arena.reexec_authority().expect("parent authority"),
            parent_authority
        );
    }

    /// Teardown is address-space-local and fd-table-local, by construction.
    ///
    /// This is the durable pin for the hazard the fd design DISSOLVED rather
    /// than fixed: the retired `MachSendRight::drop` unconditionally called
    /// `mach_port_deallocate` in whatever task ran it, so an inherited
    /// `Arc<DarwinLiveArena>` unwinding in a fork child would have dropped a
    /// ref on a parent-space name inside the child's own IPC space. `munmap`
    /// and `close` have no such cross-process reach, and no Mach name exists
    /// in this transport to deallocate.
    #[test]
    fn fd_arena_teardown_in_fork_child_is_local() {
        let arena = Arc::new(protocol_arena());
        let control = arena.control_rw.base() as *mut u8;
        unsafe { control.add(LIVE_OBJECT_HEADER_LEN).write_volatile(0x7d) };
        let addresses = [
            arena.code_rw.base(),
            arena.code_rx.base(),
            arena.control_rw.base(),
        ];
        let object_ids = addresses.map(|address| {
            mapping_object_id_for_test(address).expect("live alias has object identity")
        });
        let backing = [
            (
                arena.code_object.as_raw_fd(),
                fd_identity(arena.code_object.as_raw_fd(), "code").expect("code identity"),
            ),
            (
                arena.control_object.as_raw_fd(),
                fd_identity(arena.control_object.as_raw_fd(), "control").expect("control identity"),
            ),
        ];

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            // The child holds the only `Arc` in its own address space, so
            // this unwinds the whole arena here.
            drop(arena);
            let mut status = 0;
            for (address, old_object_id) in addresses.into_iter().zip(object_ids) {
                if mapping_object_id_for_test(address) == Some(old_object_id) {
                    status = 1; // the child did not unmap its own alias
                }
            }
            for (fd, identity) in backing {
                if !fd_no_longer_refers_to_for_test(fd, identity) {
                    status = 2; // the child did not close its own descriptor
                }
            }
            unsafe { libc::_exit(status) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "1=child kept its mappings, 2=child kept its descriptors"
        );

        // Everything the parent owns survived the child's complete teardown.
        for (address, old_object_id) in addresses.into_iter().zip(object_ids) {
            assert_eq!(
                mapping_object_id_for_test(address),
                Some(old_object_id),
                "a fork child's unwind must not disturb the parent's mappings"
            );
        }
        for (fd, identity) in backing {
            assert!(
                !fd_no_longer_refers_to_for_test(fd, identity),
                "a fork child's unwind must not disturb the parent's descriptors"
            );
        }
        assert_eq!(
            unsafe { control.add(LIVE_OBJECT_HEADER_LEN).read_volatile() },
            0x7d,
            "the backing object outlives every non-final holder"
        );
        assert!(arena.reexec_authority().is_ok());
    }

    fn protocol_arena() -> DarwinLiveArena {
        DarwinLiveArena::new(LiveArenaCapacities::V2).expect("create mapped protocol arena")
    }

    fn live_key() -> TranslationUnitKey {
        live_key_with_executable(0x42)
    }

    fn live_key_with_executable(executable_byte: u8) -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([executable_byte; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(page() as u64).expect("nonzero image length"),
            GuestVa(0x4000_0000),
            GuestCodeLen::new(page() as u64).expect("nonzero guest length"),
            SourceFingerprint([0x7a; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        )
    }

    fn prepared_publication() -> PreparedSharedInitial {
        prepared_publication_for_key(&live_key())
    }

    fn prepared_publication_for_key(key: &TranslationUnitKey) -> PreparedSharedInitial {
        prepare_shared_initial(
            key,
            &BlockPlan {
                start: GuestVa(0x4000_0000),
                end: GuestVa(0x4000_000c),
                generation: CodeGeneration::INITIAL,
                instructions: vec![
                    PlannedInst {
                        guest: GuestVa(0x4000_0000),
                        action: InstAction::Copy(0xd503_201f),
                    },
                    PlannedInst {
                        guest: GuestVa(0x4000_0004),
                        action: InstAction::Copy(0x9100_0400),
                    },
                ],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(0x4000_0008),
                    resume: GuestVa(0x4000_000c),
                },
                extensions: Vec::new(),
            },
            EmitAddressMode::Direct,
            Vec::new(),
        )
        .expect("prepare real shared INITIAL publication")
    }

    fn prepared_publication_for_span(
        key: &TranslationUnitKey,
        start: GuestVa,
        end: GuestVa,
    ) -> PreparedSharedInitial {
        prepare_shared_initial(
            key,
            &BlockPlan {
                start,
                end,
                generation: CodeGeneration::INITIAL,
                instructions: vec![PlannedInst {
                    guest: start,
                    action: InstAction::Copy(0xd503_201f),
                }],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(start.raw() + 4),
                    resume: end,
                },
                extensions: Vec::new(),
            },
            EmitAddressMode::Direct,
            Vec::new(),
        )
        .expect("prepare shared INITIAL publication for exact span")
    }

    fn prepared_target() -> PreparedSharedInitial {
        prepare_shared_initial(
            &live_key(),
            &BlockPlan {
                start: GuestVa(0x4000_1000),
                end: GuestVa(0x4000_100c),
                generation: CodeGeneration::INITIAL,
                instructions: vec![
                    PlannedInst {
                        guest: GuestVa(0x4000_1000),
                        action: InstAction::Copy(0xd503_201f),
                    },
                    PlannedInst {
                        guest: GuestVa(0x4000_1004),
                        action: InstAction::Copy(0x9100_0400),
                    },
                ],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(0x4000_1008),
                    resume: GuestVa(0x4000_100c),
                },
                extensions: Vec::new(),
            },
            EmitAddressMode::Direct,
            Vec::new(),
        )
        .expect("prepare target shared INITIAL publication")
    }

    fn prepared_direct_source() -> PreparedSharedInitial {
        prepare_shared_initial(
            &live_key(),
            &BlockPlan {
                start: GuestVa(0x4000_0000),
                end: GuestVa(0x4000_0004),
                generation: CodeGeneration::INITIAL,
                instructions: Vec::new(),
                exit: PlannedExit::Direct {
                    guest: GuestVa(0x4000_0000),
                    word: 0x1400_0400,
                    exit: DirectExit {
                        kind: DirectKind::Branch,
                        target: GuestVa(0x4000_1000),
                        resume: GuestVa(0x4000_0004),
                        condition: None,
                        register: None,
                        bit: None,
                    },
                },
                extensions: Vec::new(),
            },
            EmitAddressMode::Direct,
            Vec::new(),
        )
        .expect("prepare direct source shared INITIAL publication")
    }

    #[test]
    fn claim_rejects_same_length_prepared_block_from_another_guest_start() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let view = LiveArenaProcessView::new(arena, generations.domain()).expect("process view");
        let claim = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 61) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        assert!(claim.reserve(prepared_target()).is_err());
    }

    #[test]
    fn claim_rejects_same_start_prepared_block_from_another_unit_digest() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let view = LiveArenaProcessView::new(arena, generations.domain()).expect("process view");
        let claim = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 62) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        let other_key = live_key_with_executable(0x43);
        assert!(
            claim
                .reserve(prepared_publication_for_key(&other_key))
                .is_err()
        );
    }

    #[test]
    fn claim_accepts_prepared_block_with_exact_claimed_span() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let key = live_key();
        let start = GuestVa(0x4000_0000);
        let end = GuestVa(0x4000_000c);
        let generation = generations.observe(start).expect("generation");
        let before = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        let claim = match view.claim_eligible(&key, start, end, &generation, 63) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };

        claim
            .reserve(prepared_publication_for_span(&key, start, end))
            .expect("exact prepared span reserves")
            .publish()
            .expect("exact prepared span publishes");
        let after = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        assert_eq!(after.private_fallbacks, before.private_fallbacks);
        assert!(matches!(
            view.acquire_ready_or_miss(&key, start),
            DarwinLiveReadyLookup::Ready(_)
        ));
    }

    #[test]
    fn claim_rejects_prepared_block_with_different_same_page_end_before_allocation() {
        let arena = Arc::new(protocol_arena());
        let before = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let key = live_key();
        let start = GuestVa(0x4000_0000);
        let claimed_end = GuestVa(0x4000_000c);
        let different_end = GuestVa(0x4000_0010);
        let generation = generations.observe(start).expect("generation");
        let claim = match view.claim_eligible(&key, start, claimed_end, &generation, 64) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };

        assert!(matches!(
            claim.reserve(prepared_publication_for_span(&key, start, different_end)),
            Err(LivePrivateReason::InvalidRecord)
        ));
        let after = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        assert_eq!(after.next_chunk, before.next_chunk);
        assert_eq!(after.hot, before.hot);
        assert_eq!(after.cold, before.cold);
        assert_eq!(after.leaked_extents, before.leaked_extents);
        assert_eq!(after.leaked_chunks, before.leaked_chunks);
        assert_eq!(after.private_fallbacks, before.private_fallbacks + 1);
        assert!(matches!(
            view.acquire_ready_or_miss(&key, start),
            DarwinLiveReadyLookup::Private(LivePrivateReason::Failed)
        ));
    }

    #[test]
    fn claim_rejects_prepared_block_whose_end_crosses_claimed_source_page() {
        let arena = Arc::new(protocol_arena());
        let before = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        let generations = PageGenerationTable::new(page() as u64 * 2).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x42; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(page() as u64 * 2).expect("nonzero image length"),
            GuestVa(0x4000_0000),
            GuestCodeLen::new(page() as u64 * 2).expect("nonzero guest length"),
            SourceFingerprint([0x7a; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        );
        let start = GuestVa(0x4000_3ff8);
        let claimed_end = GuestVa(0x4000_3ffc);
        let crossing_end = GuestVa(0x4000_4004);
        let generation = generations.observe(start).expect("generation");
        let claim = match view.claim_eligible(&key, start, claimed_end, &generation, 64) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };

        assert!(matches!(
            claim.reserve(prepared_publication_for_span(&key, start, crossing_end)),
            Err(LivePrivateReason::InvalidRecord)
        ));
        let after = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        assert_eq!(after.next_chunk, before.next_chunk);
        assert_eq!(after.hot, before.hot);
        assert_eq!(after.cold, before.cold);
        assert_eq!(after.leaked_extents, before.leaked_extents);
        assert_eq!(after.leaked_chunks, before.leaked_chunks);
        assert_eq!(after.private_fallbacks, before.private_fallbacks + 1);
        assert!(matches!(
            view.acquire_ready_or_miss(&key, start),
            DarwinLiveReadyLookup::Private(LivePrivateReason::Failed)
        ));
    }

    #[test]
    fn foreign_initial_generation_cannot_publish_or_acquire() {
        let arena = Arc::new(protocol_arena());
        let authoritative = PageGenerationTable::new(page() as u64).expect("authoritative table");
        let view = LiveArenaProcessView::new(arena, authoritative.domain()).expect("process view");
        let foreign = PageGenerationTable::new(page() as u64).expect("foreign table");
        let foreign_initial = foreign
            .observe(GuestVa(0x4000_0000))
            .expect("foreign INITIAL observation");
        assert!(matches!(
            view.lookup(&live_key(), GuestVa(0x4000_0000), &foreign_initial, 63),
            DarwinLiveLookup::Private(LivePrivateReason::InvalidRecord)
        ));

        let arena = Arc::new(protocol_arena());
        let authoritative = PageGenerationTable::new(page() as u64).expect("authoritative table");
        let generation = authoritative
            .observe(GuestVa(0x4000_0000))
            .expect("authoritative INITIAL observation");
        let view = LiveArenaProcessView::new(arena, authoritative.domain()).expect("process view");
        match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 64) {
            DarwinLiveLookup::Publish(claim) => {
                claim
                    .reserve(prepared_publication())
                    .expect("same-domain INITIAL reserves")
                    .publish()
                    .expect("same-domain INITIAL publishes");
            }
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        }
        let foreign = PageGenerationTable::new(page() as u64).expect("foreign table");
        let foreign_initial = foreign
            .observe(GuestVa(0x4000_0000))
            .expect("foreign INITIAL observation");
        let foreign_ready = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 65) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(view.acquire(foreign_ready, &foreign_initial).is_err());
        let same_domain_ready =
            match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 66) {
                DarwinLiveLookup::Ready(ready) => ready,
                DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
                DarwinLiveLookup::Private(reason) => {
                    panic!("READY lookup went private: {reason:?}")
                }
            };
        assert!(view.acquire(same_domain_ready, &generation).is_ok());
    }

    #[test]
    fn same_view_prebinding_mutates_only_still_prepared_source() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");

        let target_handle = match view.lookup(&live_key(), GuestVa(0x4000_1000), &generation, 54) {
            DarwinLiveLookup::Publish(claim) => claim
                .reserve(prepared_target())
                .expect("reserve target")
                .publish()
                .expect("publish target"),
            DarwinLiveLookup::Ready(_) => panic!("fresh target unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("target went private: {reason:?}"),
        };
        let target_ready = match view.lookup(&live_key(), GuestVa(0x4000_1000), &generation, 55) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("target READY was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("target READY went private: {reason:?}"),
        };
        let target = view
            .acquire(target_ready, &generation)
            .expect("acquire target");
        assert_eq!(target.extents(), target_handle.extents());
        let other_view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("distinct process view");
        let other_ready =
            match other_view.lookup(&live_key(), GuestVa(0x4000_1000), &generation, 57) {
                DarwinLiveLookup::Ready(ready) => ready,
                DarwinLiveLookup::Publish(_) => panic!("target READY was claimed again"),
                DarwinLiveLookup::Private(reason) => {
                    panic!("target READY went private: {reason:?}")
                }
            };
        let other_target = other_view
            .acquire(other_ready, &generation)
            .expect("acquire target through distinct view");

        let prepared = prepared_direct_source();
        let link = prepared.link_candidates()[0];
        let slot = link.slot.get() as usize;
        let source_start = GuestVa(0x4000_0000);
        let source_end = GuestVa(0x4000_0004);
        let source_handle =
            match view.claim_eligible(&live_key(), source_start, source_end, &generation, 56) {
                DarwinLiveLookup::Publish(claim) => {
                    let mut reserved = claim.reserve(prepared).expect("reserve source");
                    assert!(reserved.prebind(0, &other_target).is_err());
                    assert_eq!(
                        reserved.prebind(0, &target).expect("same-view prebind"),
                        LivePrebindOutcome::Bound,
                    );
                    reserved.publish().expect("publish source")
                }
                DarwinLiveLookup::Ready(_) => panic!("fresh source unexpectedly READY"),
                DarwinLiveLookup::Private(reason) => panic!("source went private: {reason:?}"),
            };
        let source = source_handle.extents().code;
        let source_word = unsafe {
            std::ptr::read_unaligned(
                (arena.code_rx.base() + arena.code_payload_base() + source.offset as usize + slot)
                    as *const u32,
            )
        };
        let source_rx = arena.code_rx.base() + arena.code_payload_base() + source.offset as usize;
        let target_extent = target.extents().code;
        let target_rx =
            arena.code_rx.base() + arena.code_payload_base() + target_extent.offset as usize;
        let expected = carrick_dsr_aarch64::translator::encode_aarch64_direct_branch(
            carrick_dsr::cache::LinkSite {
                source: carrick_dsr_aarch64::types::CacheVa::published(HostVa(source_rx)),
                slot: link.slot,
            },
            carrick_dsr_aarch64::types::CacheVa::published(HostVa(target_rx)),
        )
        .expect("reachable exact live branch");
        assert_eq!(source_word, expected);
    }

    #[test]
    fn claim_transaction_writes_only_exact_reserved_ranges() {
        let arena = Arc::new(protocol_arena());
        let before = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let process_view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("validated process view");
        let prepared = prepared_publication();
        let expected_lengths = prepared.lengths();
        let expected_code = prepared.code_bytes().to_vec();
        let expected_hot = prepared.hot_bytes().to_vec();
        let expected_cold = prepared.cold_bytes().to_vec();
        let layout = arena.control_layout();
        let code_capacity = layout.capacities().code as usize;
        let hot_capacity = layout.capacities().hot as usize;
        let cold_capacity = layout.capacities().cold as usize;
        let code_base = arena.code_rw.base() + layout.code_payload_base();
        let hot_base = arena.control_rw.base() + layout.hot_base();
        let cold_base = arena.control_rw.base() + layout.cold_base();
        let code_before =
            unsafe { std::slice::from_raw_parts(code_base as *const u8, code_capacity).to_vec() };
        let hot_before =
            unsafe { std::slice::from_raw_parts(hot_base as *const u8, hot_capacity).to_vec() };
        let cold_before =
            unsafe { std::slice::from_raw_parts(cold_base as *const u8, cold_capacity).to_vec() };
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");

        let handle = match process_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 41) {
            DarwinLiveLookup::Publish(claim) => claim
                .reserve(prepared)
                .expect("reserve exact publication")
                .publish()
                .expect("safe exact publication"),
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };

        let after = arena
            .control_view()
            .expect("control view")
            .cursor_snapshot();
        let extents = handle.extents();
        assert_eq!(after.next_chunk - before.next_chunk, 1);
        assert_eq!(extents.hot.offset, before.hot.next_multiple_of(8));
        assert_eq!(after.hot, extents.hot.end().expect("HOT end"));
        assert_eq!(extents.cold.offset, before.cold.next_multiple_of(8));
        assert_eq!(after.cold, extents.cold.end().expect("COLD end"));
        assert_eq!(extents.code.len, expected_lengths.code);
        assert_eq!(extents.hot.len, expected_lengths.hot);
        assert_eq!(extents.cold.len, expected_lengths.cold);
        let code_after =
            unsafe { std::slice::from_raw_parts(code_base as *const u8, code_capacity) };
        let hot_after = unsafe { std::slice::from_raw_parts(hot_base as *const u8, hot_capacity) };
        let cold_after =
            unsafe { std::slice::from_raw_parts(cold_base as *const u8, cold_capacity) };
        assert_eq!(&code_after[..expected_code.len()], &expected_code);
        assert_eq!(&hot_after[..expected_hot.len()], &expected_hot);
        assert_eq!(&cold_after[..expected_cold.len()], &expected_cold);
        assert_eq!(
            &code_after[expected_code.len()..],
            &code_before[expected_code.len()..]
        );
        assert_eq!(
            &hot_after[expected_hot.len()..],
            &hot_before[expected_hot.len()..]
        );
        assert_eq!(
            &cold_after[expected_cold.len()..],
            &cold_before[expected_cold.len()..]
        );
    }

    #[test]
    fn consumer_rehashes_rx_and_exact_validates_hot_before_entry() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let process_view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("validated process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let published =
            match process_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 41) {
                DarwinLiveLookup::Publish(claim) => claim
                    .reserve(prepared_publication())
                    .expect("reserve exact publication")
                    .publish()
                    .expect("safe exact publication"),
                DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
                DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
            };
        let extents = published.extents();
        let region = arena
            .jit_region(extents.code.offset as usize..extents.code.end().unwrap() as usize)
            .expect("published code region");
        unsafe { *write_ptr(&region) ^= 0x01 };

        let ready = match process_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 42) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(process_view.acquire(ready, &generation).is_err());

        let arena = Arc::new(protocol_arena());
        let process_view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("validated process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let published =
            match process_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 43) {
                DarwinLiveLookup::Publish(claim) => claim
                    .reserve(prepared_publication())
                    .expect("reserve exact publication")
                    .publish()
                    .expect("safe exact publication"),
                DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
                DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
            };
        let hot = published.extents().hot;
        let hot_address =
            arena.control_rw.base() + arena.control_layout().hot_base() + hot.offset as usize;
        unsafe { *(hot_address as *mut u8) ^= 0x01 };
        let ready = match process_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 44) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(process_view.acquire(ready, &generation).is_err());
    }

    #[test]
    fn consumer_rejects_handle_from_another_process_view() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let first = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("first process view");
        let second = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("second process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        match first.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 45) {
            DarwinLiveLookup::Publish(claim) => {
                claim
                    .reserve(prepared_publication())
                    .expect("reserve exact publication")
                    .publish()
                    .expect("publish READY");
            }
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        }
        let first_ready = match first.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 46) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(second.acquire(first_ready, &generation).is_err());
    }

    #[test]
    fn consumer_refuses_non_initial_or_wrong_source_generation() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 47) {
            DarwinLiveLookup::Publish(claim) => {
                claim
                    .reserve(prepared_publication())
                    .expect("reserve exact publication")
                    .publish()
                    .expect("publish READY");
            }
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        }

        let wrong_page = generations
            .observe(GuestVa(0x4000_4000))
            .expect("wrong page");
        let ready = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 48) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(view.acquire(ready, &wrong_page).is_err());

        generations
            .note_guest_code_write(GuestVa(0x4000_0000)..GuestVa(0x4000_0004))
            .expect("advance source generation");
        let ready = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 49) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        assert!(view.acquire(ready, &generation).is_err());
    }

    #[test]
    fn same_arena_distinct_process_views_reject_claim_and_token() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let first = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("first process view");
        let second = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("second process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let claim = match first.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 50) {
            DarwinLiveLookup::Publish(claim) => claim,
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        let lengths = prepared_publication().lengths();
        let reserved = claim
            .claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve first-view claim");
        assert!(!reserved.belongs_to_process_view(&second.inner.process_brand));
        drop(reserved);
    }

    #[test]
    fn publisher_flushes_exact_local_rx_range() {
        clear_live_arena_test_events();
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let published = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 51) {
            DarwinLiveLookup::Publish(claim) => claim
                .reserve(prepared_publication())
                .expect("reserve exact publication")
                .publish()
                .expect("publish READY"),
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        let code = published.extents().code;
        let exact_rx_start =
            arena.code_rx.base() + arena.code_payload_base() + code.offset as usize;
        assert_eq!(
            take_live_arena_test_events(),
            vec![
                LiveArenaTestEvent::PermitBegun,
                LiveArenaTestEvent::MetadataWrite,
                LiveArenaTestEvent::PublisherFlush {
                    start: exact_rx_start,
                    len: code.len as usize,
                },
            ]
        );
    }

    #[test]
    fn consumer_flushes_its_own_exact_local_rx_range() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let published = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 52) {
            DarwinLiveLookup::Publish(claim) => claim
                .reserve(prepared_publication())
                .expect("reserve exact publication")
                .publish()
                .expect("publish READY"),
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        let code = published.extents().code;
        clear_live_arena_test_events();
        let ready = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 53) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        let executable = view.acquire(ready, &generation).expect("acquire READY");
        assert_eq!(executable.extents(), published.extents());
        let exact_rx_start =
            arena.code_rx.base() + arena.code_payload_base() + code.offset as usize;
        assert_eq!(
            take_live_arena_test_events(),
            vec![LiveArenaTestEvent::ConsumerInvalidate {
                start: exact_rx_start,
                len: code.len as usize,
            }]
        );
    }

    #[test]
    fn same_objects_at_different_vas_share_records_cursors_and_bytes() {
        let creator_arena = Arc::new(protocol_arena());
        let transit = creator_arena.transit_v2();
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let creator_view =
            LiveArenaProcessView::new(Arc::clone(&creator_arena), generations.domain())
                .expect("creator view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let creator_handle =
            match creator_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 58) {
                DarwinLiveLookup::Publish(claim) => claim
                    .reserve(prepared_publication())
                    .expect("reserve publication")
                    .publish()
                    .expect("publish READY"),
                DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
                DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
            };
        let creator_ranges = unsafe {
            creator_arena
                .local_mapping_ranges_for_transport_proof()
                .expect("creator ranges")
        };
        let adopted_arena = Arc::new(
            remap_and_adopt_for_test(&creator_arena, transit).expect("adopt same Mach objects"),
        );
        let adopted_ranges = unsafe {
            adopted_arena
                .local_mapping_ranges_for_transport_proof()
                .expect("adopted ranges")
        };
        for (creator, adopted) in creator_ranges.iter().zip(&adopted_ranges) {
            assert_ne!(creator.start, adopted.start);
        }
        assert_eq!(
            creator_arena
                .control_view()
                .expect("creator control")
                .cursor_snapshot(),
            adopted_arena
                .control_view()
                .expect("adopted control")
                .cursor_snapshot(),
        );

        let adopted_view =
            LiveArenaProcessView::new(Arc::clone(&adopted_arena), generations.domain())
                .expect("adopted view");
        let ready = match adopted_view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 59) {
            DarwinLiveLookup::Ready(ready) => ready,
            DarwinLiveLookup::Publish(_) => panic!("READY record was claimed again"),
            DarwinLiveLookup::Private(reason) => panic!("READY lookup went private: {reason:?}"),
        };
        clear_live_arena_test_events();
        let executable = adopted_view
            .acquire(ready, &generation)
            .expect("acquire through fresh mapping view");
        assert_eq!(executable.extents(), creator_handle.extents());
        let extents = executable.extents();
        let creator_layout = creator_arena.control_layout();
        let adopted_layout = adopted_arena.control_layout();
        let equal_bytes = |left: usize, right: usize, len: u64| unsafe {
            std::slice::from_raw_parts(left as *const u8, len as usize)
                == std::slice::from_raw_parts(right as *const u8, len as usize)
        };
        assert!(equal_bytes(
            creator_arena.code_rx.base()
                + creator_layout.code_payload_base()
                + extents.code.offset as usize,
            adopted_arena.code_rx.base()
                + adopted_layout.code_payload_base()
                + extents.code.offset as usize,
            extents.code.len,
        ));
        assert!(equal_bytes(
            creator_arena.control_rw.base()
                + creator_layout.hot_base()
                + extents.hot.offset as usize,
            adopted_arena.control_rw.base()
                + adopted_layout.hot_base()
                + extents.hot.offset as usize,
            extents.hot.len,
        ));
        assert!(equal_bytes(
            creator_arena.control_rw.base()
                + creator_layout.cold_base()
                + extents.cold.offset as usize,
            adopted_arena.control_rw.base()
                + adopted_layout.cold_base()
                + extents.cold.offset as usize,
            extents.cold.len,
        ));
        assert_eq!(
            take_live_arena_test_events(),
            vec![LiveArenaTestEvent::ConsumerInvalidate {
                start: adopted_arena.code_rx.base()
                    + adopted_layout.code_payload_base()
                    + extents.code.offset as usize,
                len: extents.code.len as usize,
            }]
        );
    }

    /// Adopt the SAME backing objects again, through the production
    /// authenticated path, from fresh duplicates of this arena's descriptors.
    ///
    /// This is the in-process stand-in for a successor's inherited fds: the
    /// 6B2 different-VA proof obligations re-run unchanged on fd backing.
    fn remap_and_adopt_for_test(
        source: &DarwinLiveArena,
        expected: LiveArenaTransitV2,
    ) -> io::Result<DarwinLiveArena> {
        let mut authority = transport_authority_for_test(source);
        authority.transit = expected;
        let adopted = DarwinLiveArena::adopt_reexec(authority);
        if adopted.is_err() {
            close_transport_for_test(&authority);
        }
        adopted
    }

    unsafe fn protocol_directory_mut(
        arena: &mut DarwinLiveArena,
    ) -> &mut LiveArenaControlDirectoryV2 {
        let address = arena
            .control_rw
            .base()
            .checked_add(arena.control_layout().directory_offset())
            .expect("directory address");
        // SAFETY: tests hold the only protocol user while deliberately
        // corrupting the initialized shared directory before adoption.
        unsafe { &mut *(address as *mut LiveArenaControlDirectoryV2) }
    }

    #[test]
    fn object_headers_do_not_overlap_protocol_payloads() {
        let arena = protocol_arena();
        let layout = arena.control_layout();

        assert_eq!(layout.directory_offset(), LIVE_OBJECT_HEADER_LEN);
        assert!(layout.block_records_offset() >= layout.directory_end());
        assert!(arena.code_payload_base() >= LIVE_OBJECT_HEADER_LEN);
        assert!(arena.code_payload_base().is_multiple_of(page()));
        assert_eq!(
            &unsafe { std::slice::from_raw_parts(arena.code_rw.base() as *const u8, 8) },
            &LIVE_OBJECT_MAGIC,
        );
        assert_eq!(
            &unsafe { std::slice::from_raw_parts(arena.control_rw.base() as *const u8, 8) },
            &LIVE_OBJECT_MAGIC,
        );
    }

    #[test]
    fn logical_code_zero_remains_payload_page_aligned() {
        let arena = protocol_arena();
        let region = arena.jit_region(0..8).expect("logical code offset zero");
        let write_offset = unsafe { write_ptr(&region) } as usize - arena.code_rw.base();
        let exec_offset = unsafe { exec_ptr(&region) } as usize - arena.code_rx.base();

        assert_eq!(write_offset, arena.code_payload_base());
        assert_eq!(exec_offset, arena.code_payload_base());
        assert!(write_offset.is_multiple_of(page()));
    }

    #[test]
    fn rw_and_rx_aliases_remain_distinct_during_transaction() {
        let arena = Arc::new(protocol_arena());
        let generations = PageGenerationTable::new(page() as u64).expect("generation table");
        let view = LiveArenaProcessView::new(Arc::clone(&arena), generations.domain())
            .expect("process view");
        let generation = generations
            .observe(GuestVa(0x4000_0000))
            .expect("generation");
        let handle = match view.lookup(&live_key(), GuestVa(0x4000_0000), &generation, 60) {
            DarwinLiveLookup::Publish(claim) => claim
                .reserve(prepared_publication())
                .expect("reserve publication")
                .publish()
                .expect("publish READY"),
            DarwinLiveLookup::Ready(_) => panic!("fresh arena unexpectedly READY"),
            DarwinLiveLookup::Private(reason) => panic!("fresh claim went private: {reason:?}"),
        };
        let code = handle.extents().code;
        let resolved = view
            .inner
            .resolve_code(code.offset, code.len)
            .expect("resolve exact transaction code");
        assert_ne!(resolved.write, resolved.exec);
        assert_eq!(
            resolved.write.as_ptr() as usize - arena.code_rw.base(),
            resolved.exec.as_ptr() as usize - arena.code_rx.base(),
        );
    }

    #[test]
    fn adopt_rejects_control_layout_or_translator_abi_mismatch() {
        let mut arena = protocol_arena();
        let transit = arena.transit_v2();
        unsafe { protocol_directory_mut(&mut arena) }.translator_abi =
            carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT + 1;

        assert!(remap_and_adopt_for_test(&arena, transit).is_err());

        let mut arena = protocol_arena();
        let transit = arena.transit_v2();
        unsafe { protocol_directory_mut(&mut arena) }.control_len -= page() as u64;
        assert!(remap_and_adopt_for_test(&arena, transit).is_err());
    }

    #[test]
    fn adopt_rejects_bad_nonce_stride_alignment_or_overlap() {
        let corruptions: [fn(&mut LiveArenaControlDirectoryV2); 4] = [
            |directory| directory.nonce = [0xff; 16],
            |directory| directory.block_record_stride += 64,
            |directory| directory.block_records_offset += 1,
            |directory| directory.hot_base = directory.block_records_offset,
        ];
        for corrupt in corruptions {
            let mut arena = protocol_arena();
            let transit = arena.transit_v2();
            corrupt(unsafe { protocol_directory_mut(&mut arena) });
            assert!(remap_and_adopt_for_test(&arena, transit).is_err());
        }
    }

    fn mapping_protections_for_test(address: usize) -> Option<(vm_prot_t, vm_prot_t)> {
        query_region(address as u64)
            .ok()
            .map(|region| (region.current, region.maximum))
    }

    fn mapping_object_id_for_test(address: usize) -> Option<u64> {
        let requested = address as u64;
        let mut depth = 0;
        loop {
            let mut observed = requested;
            let mut len = 0;
            let mut info = mach2::vm_region::vm_region_submap_info_64::default();
            let mut count = mach2::vm_region::vm_region_submap_info_64::count();
            let result = unsafe {
                mach2::vm::mach_vm_region_recurse(
                    mach_task_self(),
                    &mut observed,
                    &mut len,
                    &mut depth,
                    (&raw mut info).cast::<i32>(),
                    &mut count,
                )
            };
            if result != KERN_SUCCESS
                || observed > requested
                || requested >= observed.checked_add(len)?
            {
                return None;
            }
            if info.is_submap != 0 {
                depth = depth.checked_add(1)?;
                continue;
            }
            return Some(info.object_id_full);
        }
    }

    /// Whether `fd` no longer names the object with this `(device, inode,
    /// size)` identity — closed, or reused by something else.
    fn fd_no_longer_refers_to_for_test(fd: RawFd, identity: (u64, u64, u64)) -> bool {
        !fd_identity(fd, "probe").is_ok_and(|observed| observed == identity)
    }
}

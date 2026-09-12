//! Memory allocation, protection, and address space layout syscall implementations.

use super::*;
use carrick_fatal::carrick_fatal;
use carrick_guest_mem::*;
use std::os::fd::{FromRawFd, OwnedFd};

/// Why a guest `mmap` was refused — and whether the guest can work that out
/// from its own errno.
///
/// A `MAP_FAILED` carrick cannot explain is a diagnostic hole in its own right.
/// glibc's `dlopen` renders any failed segment mapping as the single line
/// "failed to map segment from shared object", so when carrick refuses one of
/// its own mappings and says nothing, the only evidence left is that string.
/// Ten CPython suites died on exactly that, silently, for as long as CPython
/// had been running on this lane. Every refusal in [`mmap`](SyscallDispatcher)
/// now reports itself through [`MmapRequest::refused`].
///
/// [`SyscallDispatcher::mmap`]: SyscallDispatcher
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MmapRefusal {
    /// Linux itself rejects this request, so the errno handed back IS the
    /// explanation. Logged at `debug`: LTP provokes these by the hundred on
    /// purpose, and promoting them would bury the refusals that matter.
    Spec(&'static str),
    /// Carrick exhausted one of its own arenas, or an internal publication
    /// step failed. Nothing in the guest's arguments predicts it and the
    /// errno names no resource, so it is logged at `warn` — visible under
    /// carrick's default filter — and always names what ran out.
    Internal(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SharedFileFixedMremapError {
    #[error("shared file alias entry missing for range 0x{old_address:x}..0x{old_end:x}")]
    MissingAliasEntry { old_address: u64, old_end: u64 },
    #[error("new length {new_size} exceeds usize")]
    NewLengthOverflow { new_size: u64 },
    #[error("old length {old_size} exceeds usize")]
    OldLengthOverflow { old_size: u64 },
    #[error("destination address grant refused for 0x{va:x}..0x{end:x}")]
    DestinationGrantRefused { va: u64, end: u64 },
    #[error("repoint shared leaf failed: {source}")]
    RepointSharedLeaf {
        #[source]
        source: carrick_guest_mem::MemoryError,
    },
    #[error("destination guest memory range invalid for 0x{va:x}..0x{end:x}")]
    InvalidDestinationRange { va: u64, end: u64 },
    #[error("failed to project fork semantics onto destination 0x{va:x}..0x{end:x}")]
    ForkSemanticsProjectFailed { va: u64, end: u64 },
}

/// The guest's `mmap` arguments exactly as they arrived, captured before any
/// normalization so a refusal reports what the guest asked for rather than
/// what carrick rewrote it to.
#[derive(Clone, Copy, Debug)]
struct MmapRequest {
    pid: i32,
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: i32,
    offset: u64,
}

impl MmapRequest {
    /// Record this refusal and build the outcome that carries it to the guest.
    ///
    /// Every `mmap` error return goes through here; there is deliberately no
    /// bare `DispatchOutcome::errno` left in the handler, so a future branch
    /// cannot reintroduce a silent `MAP_FAILED`.
    fn refused(self, refusal: MmapRefusal, errno: LinuxErrno) -> DispatchOutcome {
        self.refused_by(refusal, errno, format_args!("-"))
    }

    /// Same, carrying the failing operation's own error text.
    ///
    /// Use this wherever a fallible host/stage-1 operation produced the
    /// refusal: "protection publication failed" without the backend's reason,
    /// and without the address carrick actually chose, is half a diagnosis —
    /// the guest only ever asked for `addr=0`.
    fn refused_by(
        self,
        refusal: MmapRefusal,
        errno: LinuxErrno,
        cause: std::fmt::Arguments<'_>,
    ) -> DispatchOutcome {
        let Self {
            pid,
            addr,
            length,
            prot,
            flags,
            fd,
            offset,
        } = self;
        match refusal {
            MmapRefusal::Spec(reason) => {
                tracing::debug!(
                    target: "carrick::mmap",
                    pid,
                    reason,
                    errno = errno.get(),
                    addr = format_args!("{addr:#x}"),
                    length = format_args!("{length:#x}"),
                    prot = format_args!("{prot:#x}"),
                    flags = format_args!("{flags:#x}"),
                    fd,
                    offset = format_args!("{offset:#x}"),
                    cause,
                    "mmap refused: invalid request",
                )
            }
            MmapRefusal::Internal(reason) => {
                tracing::warn!(
                    target: "carrick::mmap",
                    pid,
                    reason,
                    errno = errno.get(),
                    addr = format_args!("{addr:#x}"),
                    length = format_args!("{length:#x}"),
                    prot = format_args!("{prot:#x}"),
                    flags = format_args!("{flags:#x}"),
                    fd,
                    offset = format_args!("{offset:#x}"),
                    cause,
                    "mmap refused: carrick internal limit",
                )
            }
        }
        DispatchOutcome::errno(errno)
    }
}

impl<'a> MemView<'a> {
    define_syscall! {
        mm_mutation fn mmap(this, cx, requested: GuestPtr, length: u64, prot: u64, flags: u64, fd: Fd, offset: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch(&permit);
            let mut flags = flags;
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();

            // Apple Rosetta tags pointers in bits 63:48 (a 16-bit value space)
            // and maps its translated ELF into the x86-64 high half. Strip the
            // tag so the request resolves into the 48-bit VA space the stage-1
            // tables address; with TCR_EL1.TBI the guest's own accesses ignore
            // the top byte, and TTBR1 (shared root) translates the canonical
            // high half (bits[47:0] index the same slot as the stripped VA). The
            // un-stripped value is kept to reject a non-canonical hint below.
            // No-op for native (top-16-zero) guests.
            let requested_raw = requested.0;
            // The exact request, for `MmapRequest::refused`. Captured before
            // MAP_FIXED_NOREPLACE normalization and page rounding so a refusal
            // reports the guest's own arguments, not carrick's rewrite of them.
            let pid = cx.kernel.task().key().id.raw();
            let request = MmapRequest {
                pid,
                addr: requested_raw,
                length,
                prot,
                flags,
                fd: fd.0,
                offset,
            };
            let requested = GuestPtr(requested.0 & 0x0000_FFFF_FFFF_FFFF);

            let fixed_noreplace = flags & LINUX_MAP_FIXED_NOREPLACE != 0;
            if fixed_noreplace {
                flags |= LINUX_MAP_FIXED;
            }
            // Parse once after FIXED_NOREPLACE -> FIXED normalization; raw
            // syscall words stay at this boundary.
            let map_flags = LinuxMmapFlags::from_bits_retain(flags);
            let prot_flags = LinuxProtFlags::from_bits_retain(prot);

            // Linux validates the fd FIRST for a file mapping: ksys_mmap_pgoff
            // does fget(fd) and returns EBADF before do_mmap ever checks the
            // length/prot/flags (which would yield EINVAL). So a bad fd beats a
            // bad length — LTP mmap08 maps length 0 on a closed fd and expects
            // EBADF, not EINVAL. (Anonymous mappings take no fd → skip.)
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS) && this.open_file(fd.0).is_none() {
                return Ok(request.refused(
                    MmapRefusal::Spec("file mapping on a descriptor that is not open"),
                    LINUX_EBADF,
                ));
            }
            // `/proc/*/maps` and NT_FILE identify the backing pathname, not
            // merely that a mapping was file-backed. Preserve the guest path
            // before the mapping branches borrow or duplicate the descriptor.
            // Host-backed overlay files carry that guest-relative authority in
            // RootFsMetadata; never expose the host scratch path from F_GETPATH.
            let proc_map_path = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                String::new()
            } else {
                this.open_file(fd.0)
                    .map(|open_file| {
                        let Some(open) = open_file.description.read() else {
                            return String::new();
                        };
                        match &*open {
                            OpenDescription::File { path, .. }
                            | OpenDescription::SyntheticFile { path, .. }
                            | OpenDescription::InMemoryFile { path, .. } => path.clone(),
                            OpenDescription::HostFile { metadata, .. } => {
                                metadata.path.to_string_lossy().into_owned()
                            }
                            OpenDescription::SyntheticDevice { kind, .. } => {
                                match kind {
                                    crate::vfs::SyntheticDeviceKind::Null => "/dev/null".to_string(),
                                    crate::vfs::SyntheticDeviceKind::Zero => "/dev/zero".to_string(),
                                    crate::vfs::SyntheticDeviceKind::Full => "/dev/full".to_string(),
                                    crate::vfs::SyntheticDeviceKind::Random => "/dev/random".to_string(),
                                    crate::vfs::SyntheticDeviceKind::Urandom => "/dev/urandom".to_string(),
                                }
                            }
                            OpenDescription::Packet { .. } => "[packet_ring]".to_string(),
                            _ => String::new(),
                        }
                    })
                    .unwrap_or_default()
            };

            // glibc's vDSO getrandom state page is mapped MAP_ANONYMOUS|
            // MAP_DROPPABLE (0x28) with NO MAP_PRIVATE/MAP_SHARED bit; the kernel
            // treats MAP_DROPPABLE as a private anon mapping, so default the type
            // to PRIVATE rather than rejecting it with EINVAL.
            let map_sharing = {
                let t = map_flags & (LinuxMmapFlags::SHARED | LinuxMmapFlags::PRIVATE);
                if t == (LinuxMmapFlags::SHARED | LinuxMmapFlags::PRIVATE) {
                    // MAP_SHARED_VALIDATE (0x3): a valid map type that, unlike
                    // plain MAP_SHARED, STRICTLY validates the flag word — an
                    // unknown flag bit is EOPNOTSUPP, not the EINVAL that
                    // plain MAP_SHARED gets (which silently ignores unknown
                    // bits for back-compat). mmap20. Otherwise behaves like
                    // MAP_SHARED.
                    let refusal = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                        Some((
                            "MAP_SHARED_VALIDATE is invalid for anonymous memory",
                            LINUX_EINVAL,
                        ))
                    } else if map_flags.bits() & !LinuxMmapFlags::SUPPORTED_MASK != 0 {
                        Some((
                            "MAP_SHARED_VALIDATE with an unknown flag bit",
                            crate::linux_abi::LINUX_EOPNOTSUPP,
                        ))
                    } else {
                        None
                    };
                    if let Some((reason, errno)) = refusal {
                        return Ok(request.refused(MmapRefusal::Spec(reason), errno));
                    }
                    Some(MmapSharing::Shared)
                } else if t == LinuxMmapFlags::SHARED {
                    Some(MmapSharing::Shared)
                } else if t == LinuxMmapFlags::PRIVATE
                    || (t.is_empty() && map_flags.contains(LinuxMmapFlags::DROPPABLE))
                {
                    Some(MmapSharing::Private)
                } else {
                    None
                }
            };
            // `mmap` and `mprotect` differ here, and `memflagmatrix` asserts
            // both: `mprotect` rejects unknown protection bits with EINVAL,
            // while `mmap` IGNORES them and maps the range with whatever known
            // access bits are present (`mmap_invalid_prot_result=success` for
            // `prot = 1 << 28`). carrick rejected them in both, so a mapping
            // Linux creates came back EINVAL. Unknown bits are simply not
            // consulted below; only READ/WRITE/EXEC are.
            if length == 0
                || map_flags.bits() & !LinuxMmapFlags::SUPPORTED_MASK != 0
                || map_sharing.is_none()
                || (!map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                    && !offset.is_multiple_of(page_size))
                || (map_flags.contains(LinuxMmapFlags::FIXED)
                    && !requested.0.is_multiple_of(page_size))
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("zero length, unsupported flag bits, no map type, or a misaligned offset/fixed address"),
                    LINUX_EINVAL,
                ));
            }
            let Some(map_sharing) = map_sharing else {
                return Ok(request.refused(
                    MmapRefusal::Spec("neither MAP_SHARED nor MAP_PRIVATE"),
                    LINUX_EINVAL,
                ));
            };
            let private_file_description = if map_sharing == MmapSharing::Private
                && !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
            {
                this.open_file(fd.0).and_then(|open| open.description.retain_mapping())
            } else {
                None
            };
            let length = match align_up_u64(length, page_size) {
                Some(length) => length,
                None => {
                    return Ok(request.refused(
                        MmapRefusal::Spec("length rounds up past the end of the address space"),
                        LINUX_ENOMEM,
                    ));
                }
            };
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;

            // RLIMIT_AS / RLIMIT_DATA admission before any allocator, backing
            // or VMA mutation. A MAP_FIXED replacement is charged only for the
            // bytes not already mapped. If both limits are infinite (default),
            // no MemState lock, no overlap calculation, and no VMA walk occurs.
            {
                let data = mapping_is_data(
                    prot_flags.contains(LinuxProtFlags::WRITE),
                    map_sharing == MmapSharing::Private,
                    map_flags.contains(LinuxMmapFlags::GROWSDOWN),
                );
                if let Some((as_limit, data_limit)) = this.address_space_limits_apply(data) {
                    let mem_authority_rlimit = this.mem();
                    let mem = mem_authority_rlimit.lock();
                    let grow = if map_flags.contains(LinuxMmapFlags::FIXED) {
                        length.saturating_sub(mapped_overlap_bytes(&mem, requested.0, length))
                    } else {
                        length
                    };
                    if let Err(errno) = this.check_address_space_limits_locked(
                        &mem, as_limit, data_limit, grow, data,
                    ) {
                        return Ok(request.refused(
                            MmapRefusal::Spec("RLIMIT_AS or RLIMIT_DATA soft limit reached"),
                            errno,
                        ));
                    }
                }
            }

            // io_uring mappings are ordinary MAP_SHARED host aliases. The file
            // description owns the persistent bytes; this mm receives only an
            // attachment after the runtime has installed the alias successfully.
            if let Some(description) = this.io_uring_description(fd.0) {
                let Some(backing) = description
                    .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
                else {
                    carrick_fatal!(
                        "dispatch::mmap_ioring",
                        "ring file description missing concrete backing"
                    );
                };
                let Some((region, region_layout)) = backing.region(offset) else {
                    return Ok(request.refused(
                        MmapRefusal::Spec("offset does not name an io_uring region"),
                        LINUX_EINVAL,
                    ));
                };
                if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                    || map_sharing != MmapSharing::Shared
                    || length < region_layout.required_len
                    || length > region_layout.mapped_extent
                {
                    return Ok(request.refused(
                        MmapRefusal::Spec("io_uring mapping must be MAP_SHARED and cover exactly its region"),
                        LINUX_EINVAL,
                    ));
                }
                if fixed_noreplace && this.dynamic_mapping_overlaps(requested.0, length) {
                    return Ok(request.refused(
                        MmapRefusal::Spec("MAP_FIXED_NOREPLACE over a live io_uring mapping"),
                        linux_errno::EEXIST,
                    ));
                }
                let Some(owned_fd) = backing.dup_data_fd() else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("io_uring backing descriptor could not be duplicated"),
                        LINUX_ENOMEM,
                    ));
                };
                let fixed_va = map_flags.contains(LinuxMmapFlags::FIXED);
                let Some(ipa) = alloc_alias_ipa_for_publication(length, fixed_va) else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("alias IPA arena exhausted (io_uring mapping)"),
                        LINUX_ENOMEM,
                    ));
                };
                let address = if fixed_va {
                    requested.0
                } else {
                    crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE)
                };
                let Some(end) = address.checked_add(length) else {
                    return Ok(request.refused(
                        MmapRefusal::Spec("io_uring mapping end overflows the address space"),
                        LINUX_ENOMEM,
                    ));
                };
                let mut host_prot = 0;
                if prot_flags.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                    host_prot |= libc::PROT_READ;
                }
                if prot_flags.contains(LinuxProtFlags::WRITE) {
                    host_prot |= libc::PROT_WRITE;
                }
                let mapping = crate::dispatch::ioring::IoUringMapping {
                    description,
                    region,
                    start: address,
                    end,
                    backing_offset: region_layout.backing_offset,
                };
                let mm = this.captured_mm();
                let transaction = host_alias_dispatch
                    .publish(HostAliasCommit::io_uring_mmap(
                        HostAliasMmapCommit {
                            start: address,
                            len: length,
                            prot: prot_flags,
                            sharing: ProcMapSharing::Shared,
                            path: "anon_inode:[io_uring]".to_owned(),
                            file_page_offset: None,
                            droppable: false,
                            semantic_vmas: None,
                            locked: this.prepare_mmap_locked_range(map_flags, address, length)?,
                            resident: true,
                            bus_fault: None,
                            write_sealed_shared: false,
                            read_only_shared_file: false,
                            secretmem: false,
                            writable_memfd: None,
                            private_file: None,
                            shared_file_alias: None,
                        },
                        mapping,
                        mm,
                    ))
                    .map_err(|_| DispatchError::Errno(linux_errno::ENOMEM))?;
                return Ok(DispatchOutcome::MapHostAlias {
                    success_retval: address as i64,
                    transaction,
                    va: GuestVa(address),
                    ipa: Gpa(ipa),
                    len: length,
                    payload: Vec::new(),
                    backing: HostAliasBacking::File {
                        fd: HostAliasOwnedFd::from(owned_fd),
                        offset: region_layout.backing_offset as libc::off_t,
                        host_prot,
                        sharing: HostAliasSharing::Shared,
                    },
                    prot,
                    prot_none: prot_flags.is_empty(),
                });
            }

            // An O_PATH descriptor is not open for I/O — mmap on it returns
            // EBADF (LTP open13 maps an O_PATH fd and expects failure).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && open_file.description.common().status_flags() & crate::linux_abi::LINUX_O_PATH != 0
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("mmap of an O_PATH descriptor"),
                    LINUX_EBADF,
                ));
            }

            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && (open_file.description.common().status_flags() & carrick_abi::LINUX_O_ACCMODE)
                    == carrick_abi::LINUX_O_WRONLY
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("mmap of a write-only descriptor"),
                    LINUX_EACCES,
                ));
            }

            // mprotect(2) EACCES ceiling: a MAP_SHARED mapping of a file opened
            // read-only can never be made PROT_WRITE, and asking for PROT_WRITE
            // at map time is EACCES outright. Decided here from the GUEST's
            // status flags — the host fd's access mode is carrick's business
            // (a live alias upgrades it to O_RDWR below) and must never leak
            // into this answer — and recorded on the mapping because the
            // backing fd can be closed long before the mprotect. MAP_PRIVATE
            // is deliberately excluded: Linux keeps VM_MAYWRITE for a private
            // map of a read-only file, since its stores are COW and never
            // reach the file.
            let mut mmap_read_only_shared_file = false;
            if map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
            {
                mmap_read_only_shared_file = (open_file.description.common().status_flags()
                    & carrick_abi::LINUX_O_ACCMODE)
                    == carrick_abi::LINUX_O_RDONLY;
            }
            if mmap_read_only_shared_file && prot_flags.contains(LinuxProtFlags::WRITE) {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_SHARED|PROT_WRITE of a read-only descriptor"),
                    LINUX_EACCES,
                ));
            }

            // A memfd sealed F_SEAL_WRITE (or F_SEAL_FUTURE_WRITE) cannot back a
            // shared, writable mapping — Linux returns EPERM (memfd_create01
            // check_mmap_fail). A private (MAP_PRIVATE) writable mapping is fine:
            // its stores never reach the sealed backing.
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && prot_flags.contains(LinuxProtFlags::WRITE)
                && let Some(open_file) = this.open_file(fd.0)
                && let Some(seals) = open_file
                    .description
                    .common()
                    .seals()
                    .and_then(carrick_abi::LinuxMemfdSeals::from_bits)
                && seals.intersects(
                    carrick_abi::LinuxMemfdSeals::WRITE
                        | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
                )
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("shared writable mapping of a write-sealed memfd"),
                    LINUX_EPERM,
                ));
            }

            // memfd_secret mappings must be MAP_SHARED: secretmem rejects a
            // MAP_PRIVATE mmap with EINVAL (memfdsecret probe
            // `mmap_private_errno=22`). Classified here, ahead of every
            // private/file-backed lowering decision, so no path can materialize
            // a private view of secret memory.
            let secretmem_backed = !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && this
                    .open_file(fd.0)
                    .is_some_and(|open_file| open_file.description.common().secretmem());
            if secretmem_backed && map_sharing == MmapSharing::Private {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_PRIVATE mapping of a memfd_secret fd"),
                    LINUX_EINVAL,
                ));
            }

            let fixed_write_exec_alias = if map_flags.contains(LinuxMmapFlags::FIXED) {
                let layout = this.mem().lock().layout;
                !range_within(requested.0, length, layout.mmap_base, layout.mmap_size)
            } else {
                false
            };
            if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                && let Some(reason) = this.native16k_write_exec_rejection(
                    &*memory,
                    cx.thread,
                    map_sharing == MmapSharing::Shared,
                    fixed_write_exec_alias,
                )
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mmap",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(request.refused(
                    MmapRefusal::Internal("PROT_WRITE|PROT_EXEC is unsupported on this backend"),
                    LINUX_EOPNOTSUPP,
                ));
            }

            if fixed_noreplace && this.dynamic_mapping_overlaps(requested.0, length) {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_FIXED_NOREPLACE over a live mapping"),
                    linux_errno::EEXIST,
                ));
            }

            if map_flags.contains(LinuxMmapFlags::FIXED)
                && requested_raw >> 48 == 0xffff
                && this.proc.lock().reported_arch()
                    == crate::vfs::GuestReportedArch::Aarch64
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_FIXED at a high-half address on an aarch64 guest"),
                    LINUX_ENOMEM,
                ));
            }

            // MAP_FIXED|MAP_PRIVATE landing on a shared-aperture VA needs a
            // genuine per-process backing object before any Private provenance or
            // executable cacheability is published. File mappings are eagerly
            // snapshotted into a complete zero-tailed payload first; anonymous
            // mappings use the same transaction with an all-zero snapshot. Then
            // repoint stage-1 into a fresh private-overlay slot. The boot-mapped
            // overlay avoids post-vCPU stage-2 mutation, and native identity
            // backends atomically replace the host mapping with MAP_PRIVATE anon.
            if map_flags.contains(LinuxMmapFlags::FIXED)
                && map_sharing == MmapSharing::Private
                && crate::memory::va_in_shared_aperture(requested.0, length)
            {
                let snapshot = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                    PrivateMmapSnapshot {
                        bytes: vec![0u8; length_usize],
                        bus_fault_offset: None,
                    }
                } else {
                    match this.snapshot_private_mmap_file(fd, offset, length_usize) {
                        Ok(snapshot) => snapshot,
                        Err(errno) => return Ok(request.refused(
                            MmapRefusal::Internal("private-overlay snapshot of the mapped file failed"),
                            errno,
                        )),
                    }
                };
                let bus_fault = snapshot.bus_fault_offset.and_then(|bus_offset| {
                    Some((
                        requested.0.checked_add(bus_offset)?,
                        length.checked_sub(bus_offset)?,
                    ))
                });
                let locked_range =
                    this.prepare_mmap_locked_range(map_flags, requested.0, length)?;
                // Keep every prior overlay fragment live until the fresh
                // replacement is installed. A clean repoint failure can then free
                // only the candidate and leave old translation/ownership exact.
                // Exact sub-granule fragments stay quarantined in the aperture
                // free list until they coalesce into an aligned allocation.
                let (overlay_va, displaced_shared_preview) = {
                    let mem_authority_14 = this.mem();
                    let mut mem = mem_authority_14.lock();
                    if !mem
                        .overlay
                        .source_range_is_carvable(requested.0, length, None)
                        || !mem.shared.guest_range_is_carvable(requested.0, length)
                    {
                        return Ok(request.refused(
                            MmapRefusal::Internal("shared-aperture range is not carvable for a private overlay"),
                            LINUX_ENOMEM,
                        ));
                    }
                    let Some(displaced) = mem.shared.guest_range_fragments(requested.0, length)
                    else {
                        return Ok(request.refused(
                            MmapRefusal::Internal("shared-aperture range exposes no carvable fragments"),
                            LINUX_ENOMEM,
                        ));
                    };
                    let overlay = mem.overlay.alloc_sourced(
                        length,
                        crate::shared_aperture::BackingObject::PrivateAnon,
                        Some(requested.0),
                    );
                    (overlay, displaced)
                };
                let Some(overlay_va) = overlay_va else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("private overlay aperture exhausted"),
                        LINUX_ENOMEM,
                    ));
                };
                // Capture exact SharedFile fragments while the old translation
                // is live, but defer pwrite until repoint succeeds. A clean
                // backend failure therefore leaves ownership and writeback both
                // uncommitted.
                let displaced_shared_snapshots = displaced_shared_preview
                    .iter()
                    .map(|alloc| this.snapshot_shared_writeback(memory, alloc))
                    .collect::<Vec<_>>();
                if let Err(failure) = memory.repoint_private(
                    requested.0,
                    overlay_va,
                    length_usize,
                    &snapshot.bytes,
                ) {
                    match this.recover_private_repoint_failure(overlay_va, failure) {
                        PrivateRepointRecovery::RecoveredCleanly => {
                            return Ok(request.refused(
                                MmapRefusal::Internal("stage-1 repoint into the private overlay failed"),
                                LINUX_ENOMEM,
                            ));
                        }
                        PrivateRepointRecovery::FailStopRetainingOwners => {
                            // Live translation state is unknown. Retain BOTH the
                            // fresh candidate and prior owners; recycling either
                            // could hand active guest leaves to another mapping.
                            carrick_fatal!(
                                "dispatch::mmap_overlay",
                                "private repoint failure entered indeterminate state during overlay"
                            );
                        }
                    }
                }
                for (alloc, bytes) in displaced_shared_preview
                    .iter()
                    .zip(&displaced_shared_snapshots)
                {
                    if let Some(bytes) = bytes {
                        this.writeback_shared_snapshot(alloc, bytes);
                    }
                }
                let displaced_shared = {
                    let mem_authority_15 = this.mem();
                    let mut mem = mem_authority_15.lock();
                    if mem
                        .overlay
                        .carve_source_range(requested.0, length, Some(overlay_va))
                        .is_none()
                    {
                        // Backend publication succeeded, so ownership cannot be
                        // recovered if the validated carve transaction disappeared.
                        carrick_fatal!(
                            "dispatch::mmap_overlay",
                            "overlay carve_source_range failed after backend publication succeeded"
                        );
                    }
                    let Some(displaced) = mem
                        .shared
                        .reserve_private_range(requested.0, length)
                    else {
                        carrick_fatal!(
                            "dispatch::mmap_overlay",
                            "shared reserve_private_range failed after backend publication succeeded"
                        );
                    };
                    displaced
                };
                drop(displaced_shared);
                drop(displaced_shared_preview);
                let prot_none = prot_flags.is_empty();
                memory.set_mapping_protection_and_sharing(
                    requested.0,
                    length_usize,
                    prot_none,
                    !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                    carrick_guest_mem::MappingSharing::Private,
                );
                if memory
                    .protect_range(requested.0, length_usize, prot)
                    .is_err()
                {
                    // Repoint succeeded, so the prior mapping cannot be restored.
                    // Match the runtime alias transaction: do not return to the
                    // guest with split backing/metadata ownership after a
                    // post-replacement failure.
                    mark_range_unmapped(memory, requested.0, length_usize);
                    carrick_fatal!(
                        "dispatch::mmap_overlay",
                        "protect_range failed on repointed memory range during private overlay"
                    );
                }
                if let Some((bus_start, bus_len)) = bus_fault {
                    let Ok(bus_len_usize) = usize::try_from(bus_len) else {
                        carrick_fatal!(
                            "dispatch::mmap_overlay",
                            "bus-fault length exceeds usize during private overlay"
                        );
                    };
                    if memory
                        .protect_range(bus_start, bus_len_usize, 0)
                        .is_err()
                    {
                        mark_range_unmapped(memory, requested.0, length_usize);
                        carrick_fatal!(
                            "dispatch::mmap_overlay",
                            "protect_range failed on bus fault range during overlay setup"
                        );
                    }
                    memory.set_mapping_protection(bus_start, bus_len_usize, true, false);
                    if let Some(protections) = memory.protections() {
                        protections.set_bus_fault(bus_start, bus_len_usize, true);
                    }
                }
                // The physical replacement and every required protection are
                // now infallible history. Retire the exact predecessor range from
                // all dispatcher classifications, then publish the new EOF tail,
                // residency/lock state, and VMA as one ordered metadata commit.
                this.commit_host_alias_mmap(HostAliasMmapCommit {
                    start: requested.0,
                    len: length,
                    prot: prot_flags,
                    sharing: ProcMapSharing::Private,
                    path: proc_map_path.clone(),
                    file_page_offset: (!proc_map_path.is_empty()).then_some(
                        offset / crate::core_dump::GUEST_PAGE as u64,
                    ),
                    droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                    semantic_vmas: None,
                    locked: locked_range,
                    resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                        || map_flags.contains(LinuxMmapFlags::POPULATE),
                    bus_fault,
                    write_sealed_shared: false,
                    read_only_shared_file: false,
                    secretmem: false,
                    writable_memfd: None,
                    private_file: PrivateFileMapEntry::for_mapping(
                        &private_file_description, requested.0, length, offset,
                    ),
                    shared_file_alias: None,
                });
                return Ok(DispatchOutcome::returned_ptr(requested)?);
            }

            let hvf_page = crate::trap::HVF_PAGE_SIZE;
            // Guest MAP_SHARED of a file: back the guest region with the host
            // file's page cache LIVE, via an aliased stage-2 mapping at a fresh
            // high VA. `mmap(MAP_SHARED, fd)` on the host means guest writes hit
            // the page cache directly — coherent with any other opener (and with
            // a sibling mapping of the same file) and inherited across fork,
            // because the backing kernel object is the file, not a snapshot.
            // This replaces the old aperture-snapshot+msync-writeback model,
            // which was only coherent at msync/munmap time (the memmap b_*
            // invariant). The dispatcher reserves the alias IPA and hands the
            // runtime a MapHostAlias carrying a dup'd fd; the runtime mmaps it
            // and builds the VA->IPA stage-1 path.
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::FIXED)
                && offset.is_multiple_of(hvf_page)
            {
                let mut alias_description: Option<Arc<crate::kernel::FileDescription>> = None;
                // Sealing bookkeeping for a memfd alias, computed exactly as the
                // snapshot path below computes it: a mapping of a memfd sealed
                // F_SEAL_WRITE/F_SEAL_FUTURE_WRITE is read-only and must refuse
                // a later mprotect(PROT_WRITE); a writable mapping of an
                // unsealed memfd makes F_ADD_SEALS F_SEAL_WRITE EBUSY.
                let mut alias_write_sealed_shared = false;
                let mut alias_writable_memfd: Option<Arc<crate::kernel::FileDescription>> = None;
                let dup_fd = {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(request.refused(
                            MmapRefusal::Internal("file description vanished mid-dispatch (shared file alias)"),
                            LINUX_EBADF,
                        ));
                    };
                    // The WRITE guard: an in-place host-fd upgrade below copies
                    // the file offset across the swap, and read/write hold
                    // this same guard across their host I/O, so no offset
                    // can move underneath it.
                    let open = open_file.description.write();
                    // A host regular file (`HostFile`) or a memfd whose bytes
                    // live in an unlinked host file (`File`/`HostBacked`) both
                    // have a host inode the guest mapping can view live.
                    let alias_host_fd = match open.as_deref() {
                        Some(OpenDescription::HostFile { host_fd, .. }) => Some((host_fd.raw(), true)),
                        Some(OpenDescription::File { contents, .. }) => {
                            contents.host_backed_fd().map(|raw| (raw, false))
                        }
                        _ => None,
                    };
                    match alias_host_fd {
                        Some((raw_fd, is_host_file)) => {
                            // Two named preconditions decide the live alias, so
                            // neither is discovered as an opaque hypervisor
                            // error deep inside the VMM backend: the mapping
                            // must not run past EOF (that tail is BUS_ADRERR,
                            // served by the snapshot path below), and the host
                            // fd must be able to carry a write max-protection.
                            // A guest-read-only description holds an O_RDONLY
                            // host fd (opens carry the guest's own access
                            // mode); this is the one place that needs more, so
                            // the backend re-opens it O_RDWR in place when the
                            // file is one it may vouch for. The guest's own
                            // view stays read-only: `mmap_read_only_shared_file`
                            // above already refused PROT_WRITE and pins the
                            // mprotect ceiling on the commit. A memfd's host
                            // file is always O_RDWR and has no path to re-open.
                            let beyond_eof = host_fd_file_len(raw_fd)
                                .and_then(|len| {
                                    shared_file_bus_offset(len, offset, length, page_size)
                                })
                                .is_some();
                            let can_alias = host_fd_can_back_shared_alias(raw_fd)
                                || (is_host_file
                                    && this
                                        .fs
                                        .rootfs_vfs
                                        .overlay
                                        .upgrade_host_fd_for_shared_map(raw_fd));
                            if beyond_eof || !can_alias {
                                None
                            } else {
                                let d = unsafe { libc::dup(raw_fd) };
                                if d < 0 {
                                    None
                                } else {
                                    // Retain the description: the dup above is
                                    // the runtime's and is closed right after
                                    // mapping, so this is the only way a later
                                    // `mremap` can ask where the file ends.
                                    alias_description =
                                        Some(std::sync::Arc::clone(&open_file.description));
                                    let seals = open_file
                                        .description
                                        .common()
                                        .seals()
                                        .and_then(carrick_abi::LinuxMemfdSeals::from_bits);
                                    alias_write_sealed_shared = matches!(
                                        seals,
                                        Some(s) if s.intersects(
                                            carrick_abi::LinuxMemfdSeals::WRITE
                                                | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
                                        )
                                    );
                                    if prot_flags.contains(LinuxProtFlags::WRITE)
                                        && seals.is_some()
                                    {
                                        alias_writable_memfd =
                                            Some(std::sync::Arc::clone(&open_file.description));
                                    }
                                    Some(d)
                                }
                            }
                        }
                        None => None,
                    }
                };
                if let Some(dup_fd) = dup_fd {
                    let locked_len = match this.prepare_fresh_mmap_locked_length(map_flags, length)
                    {
                        Ok(length) => length,
                        Err(errno) => {
                            unsafe { libc::close(dup_fd) };
                            return Ok(request.refused(
                                MmapRefusal::Spec("MAP_LOCKED refused by RLIMIT_MEMLOCK (shared file alias)"),
                                errno,
                            ));
                        }
                    };
                    // Reserve a FRESH alias IPA (2 MiB-block-aligned so no two
                    // file mappings share a stage-1 block). The allocator is
                    // PROCESS-TREE-GLOBAL and monotonic — never reused — because
                    // the one shared `hv_vm`'s stage-2 TLB can't be flushed on
                    // arm64, so reusing an IPA across host-forked guests reads a
                    // stale page (a latent cross-process coherence hazard; NOT
                    // the go-build crash, which is a separate trap-path bug).
                    // The stage-1 mapping still covers EXACTLY the guest's
                    // page-aligned `length`; map_host_alias rounds the
                    // host/hv_vm_map size up to the 16 KiB HVF granule.
                    let Some(ipa) = crate::memory::alloc_alias_ipa(length) else {
                        // Alias arena exhausted: drop the dup, surface ENOMEM.
                        unsafe { libc::close(dup_fd) };
                        return Ok(request.refused(
                            MmapRefusal::Internal("alias IPA arena exhausted (shared file mapping)"),
                            LINUX_ENOMEM,
                        ));
                    };
                    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
                    let locked_range = match locked_len {
                        Some(length) => match va.checked_add(length).and_then(|end| {
                            crate::vfs::GuestMemoryRange::new(GuestVa(va), GuestVa(end))
                        }) {
                            Some(range) => Some(range),
                            None => {
                                unsafe { libc::close(dup_fd) };
                                return Ok(request.refused(
                                    MmapRefusal::Internal("alias VA range overflows the address space"),
                                    LINUX_ENOMEM,
                                ));
                            }
                        },
                        None => None,
                    };
                    // Host mmap prot MUST match the guest's request (and thus the
                    // fd's access mode) for READ/WRITE: MAP_SHARED|PROT_WRITE of a
                    // read-only fd is EACCES. Translate the guest PROT_* bits to
                    // host PROT_*. NOTE: deliberately DROP PROT_EXEC. The guest
                    // executes through HVF's stage-2 (mapped RWX) and its own
                    // stage-1 page tables (UXN clear), never through carrick's host
                    // pointer (which we only ever read for syscall emulation), so
                    // the host backing needs no exec right. macOS's hardened
                    // runtime REJECTS MAP_SHARED|PROT_EXEC of an ordinary file with
                    // EPERM — forwarding the guest's PROT_EXEC here failed the host
                    // mmap and wedged the guest. Linux maps such files fine (the
                    // dynamic loader; CPython test_mmap test_access_parameter's
                    // `mmap(fd, n, prot=PROT_READ|PROT_EXEC)`), and so must we.
                    let pf = prot_flags;
                    let mut host_prot = 0;
                    if pf.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                        // PROT_EXEC implies a host-readable backing (carrick reads
                        // it to service the guest's reads; the exec right itself
                        // lives in the guest's stage-1/stage-2, not the host map).
                        host_prot |= libc::PROT_READ;
                    }
                    if pf.contains(LinuxProtFlags::WRITE) {
                        host_prot |= libc::PROT_WRITE;
                    }
                    // Host-side EFAULT gate for a PROT_NONE file mapping. The
                    // runtime publishes permission + Shared metadata only after
                    // the live host file mapping succeeds; publishing here would
                    // expose a transient private/cacheable executable view.
                    let prot_none = pf.is_empty();
                    let transaction = host_alias_dispatch
                        .publish(HostAliasCommit::mmap(
                            HostAliasMmapCommit {
                                start: va,
                                len: length,
                                prot: prot_flags,
                                sharing: ProcMapSharing::Shared,
                                path: proc_map_path.clone(),
                                file_page_offset: (!proc_map_path.is_empty()).then_some(
                                    offset / crate::core_dump::GUEST_PAGE as u64,
                                ),
                                droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                                semantic_vmas: None,
                                locked: locked_range,
                                resident: true,
                                bus_fault: None,
                                write_sealed_shared: alias_write_sealed_shared,
                                read_only_shared_file: mmap_read_only_shared_file,
                                secretmem: false,
                                writable_memfd: alias_writable_memfd,
                                private_file: None,
                                shared_file_alias: alias_description.map(|description| {
                                    SharedFileAliasCommit {
                                        description,
                                        extent_base: Gpa(ipa.saturating_sub(offset)),
                                        row_file_offset: offset,
                                    }
                                }),
                            },
                        ))
                        .map_err(|_| DispatchError::Errno(linux_errno::ENOMEM))?;
                    return Ok(DispatchOutcome::MapHostAlias {
                        success_retval: va as i64,
                        transaction,
                        va: GuestVa(va),
                        ipa: Gpa(ipa),
                        len: length,
                        payload: Vec::new(),
                        backing: HostAliasBacking::File {
                            // SAFETY: `dup_fd` is the successful, uniquely-owned
                            // descriptor created above and is transferred into
                            // the non-cloneable outcome exactly once.
                            fd: HostAliasOwnedFd::from(unsafe { OwnedFd::from_raw_fd(dup_fd) }),
                            offset: offset as libc::off_t,
                            host_prot,
                            sharing: HostAliasSharing::Shared,
                        },
                        prot,
                        prot_none,
                    });
                }
            }

            // Guest MAP_SHARED|MAP_ANON: a sub-range of the shared aperture.
            // The bytes already live in the boot-mapped shared region, so we
            // only allocate, zero (recycled memory), and return.
            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::FIXED)
                // Linux treats a usable non-fixed address as an advisory hint.
                // Keep high canonical hints on the alias path so a later
                // PROT_NONE -> writable commit can install the exact hinted VA
                // while preserving the original MAP_SHARED provenance.
                && (requested.0 == 0
                    || !mmap_address_uses_alias(requested.0, length, this.mem().lock().layout))
            {
                let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                let alloc = {
                    let mem_authority_16 = this.mem();
                    let mut mem = mem_authority_16.lock();
                    mem.shared.alloc_sourced_with_reuse(
                        length,
                        crate::shared_aperture::BackingObject::SharedAnon,
                        None,
                    )
                };
                if let Some((addr, reused)) = alloc {
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let locked_range = this.prepare_mmap_locked_range(map_flags, addr, length)?;
                    if reused
                        && let Err(error) = memory.zero_anonymous_reuse(
                            addr,
                            map_len_usize,
                            carrick_guest_mem::MappingSharing::Shared,
                        )
                    {
                        this.mem().lock().shared.free(addr);
                        return Ok(request.refused_by(
                            MmapRefusal::Internal("anonymous-reuse scrub failed (shared aperture)"),
                            LINUX_ENOMEM,
                            format_args!("at {addr:#x}+{map_len:#x}: {error}"),
                        ));
                    }
                    let needs_identity_restore = this.mem()
                        .lock()
                        .shared
                        .range_needs_identity_restore(addr, map_len);
                    if needs_identity_restore {
                        if memory.restore_shared_identity(addr, map_len_usize).is_err() {
                            // The page-table edit may already be live even when
                            // its required TLB flush reports failure. Recycling
                            // this VA would publish unowned translation state.
                            carrick_fatal!(
                                "dispatch::mmap_shared",
                                "restore_shared_identity backend operation failed"
                            );
                        }
                        if this.mem()
                            .lock()
                            .shared
                            .mark_identity_restored(addr, map_len)
                            .is_none()
                        {
                            carrick_fatal!(
                                "dispatch::mmap_shared",
                                "mark_identity_restored failed in shared aperture tracking"
                            );
                        }
                    }
                    // Make the REQUESTED protection guest-visible: the
                    // aperture is boot-mapped RW, so without this a store
                    // to a PROT_READ anon-shared mapping silently succeeds
                    // (Go runtime/debug TestPanicOnFault: "write did not
                    // fault"). Also restores RW for a recycled chunk whose
                    // prior owner was read-only/none. Best-effort outside
                    // the eager arena (mirrors the file-mmap arm); the
                    // host-side no_access gate is kept in sync for EFAULT.
                    let prot_none = prot_flags.is_empty();
                    memory.set_mapping_protection_and_sharing(
                        addr,
                        map_len_usize,
                        prot_none,
                        !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                        carrick_guest_mem::MappingSharing::Shared,
                    );
                    let protection = if prot_none {
                        memory.protect_range(addr, map_len_usize, 0)
                    } else if memory
                        .resident_pages(GuestVa(addr), 1, this.linux_page_size())
                        .is_none()
                    {
                        // Backends without live host residency use a temporary
                        // inaccessible mapping to observe the first touch.
                        let protected = memory.protect_range(addr, map_len_usize, 0);
                        if protected.is_ok() {
                            this.track_resident_fault_range(addr, length, prot_flags);
                            // The temporary backing state is not the guest VMA
                            // permission. Preserve the requested Linux metadata.
                            memory.set_mapping_protection(
                                addr,
                                map_len_usize,
                                false,
                                !prot_flags.contains(LinuxProtFlags::WRITE),
                            );
                            if let Some(protections) = memory.protections() {
                                protections.set_executable(
                                    addr,
                                    map_len_usize,
                                    prot_flags.contains(LinuxProtFlags::EXEC),
                                );
                            }
                        }
                        protected
                    } else {
                        // Native identity mappings expose real host residency;
                        // apply the requested guest permission directly without
                        // manufacturing a demand fault. This call also consumes
                        // a failure recorded by the preceding void metadata
                        // setter; an error must roll the allocation back.
                        memory.protect_range(addr, map_len_usize, prot)
                    };
                    if let Err(error) = protection
                        && memory.supports_concurrent_exec_protection()
                    {
                        this.rollback_shared_anon_mapping(
                            memory,
                            addr,
                            length,
                            map_len_usize,
                        )?;
                        return Ok(request.refused_by(
                            MmapRefusal::Internal(
                                "protection publication failed (shared anonymous mapping)",
                            ),
                            LINUX_ENOMEM,
                            format_args!("at {addr:#x}+{map_len:#x}: {error}"),
                        ));
                    }
                    if let Err(errno) = this.commit_mmap_locked_range(memory, locked_range) {
                        memory.set_mapping_protection(addr, map_len_usize, false, false);
                        let _ = memory.protect_range(
                            addr,
                            map_len_usize,
                            crate::linux_abi::LINUX_PROT_READ
                                | crate::linux_abi::LINUX_PROT_WRITE,
                        );
                        this.rollback_shared_anon_mapping(
                            memory,
                            addr,
                            length,
                            map_len_usize,
                        )?;
                        return Ok(request.refused(
                            MmapRefusal::Spec("MAP_LOCKED population refused by RLIMIT_MEMLOCK (shared anonymous)"),
                            errno,
                        ));
                    }
                    this.record_dynamic_mapping_with_file_offset(
                        addr,
                        length,
                        prot_flags,
                        ProcMapSharing::Shared,
                        String::new(),
                        DynamicMappingSemantics {
                            file_page_offset: None,
                            droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                            semantic_vmas: None,
                        },
                    );
                    if map_flags.contains(LinuxMmapFlags::POPULATE) {
                        this.mark_range_resident(addr, length);
                    }
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::returned_u64(addr)?);
                }
                return Ok(request.refused(
                    MmapRefusal::Internal("shared aperture exhausted"),
                    LINUX_ENOMEM,
                ));
            }

            // Address-independent half of the file-backed lowering check (the
            // full candidate test follows once the grant is known). It also
            // picks the grant's congruence: a page-cache view needs
            // `address ≡ offset (mod host page)`.
            let file_lowering_eligible = map_sharing == MmapSharing::Private
                && !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && !map_flags.contains(LinuxMmapFlags::GROWSDOWN)
                && mmap_file_backed_lowering_enabled()
                && this.open_file(fd.0).is_some_and(|open_file| {
                    open_file
                        .description
                        .read()
                        .as_deref()
                        .and_then(OpenDescription::shared_alias_host_fd)
                        .is_some()
                });
            let congruence = if file_lowering_eligible {
                MmapGrantCongruence::for_file_offset(offset, page_size)
            } else {
                MmapGrantCongruence::Any
            };
            let (address, reused) =
                match this.next_mmap_address(requested.0, length, prot, flags, congruence) {
                Some(pair) => pair,
                None => {
                    // A length that could not fit an EMPTY address space is a
                    // property of the request, and Linux answers ENOMEM for it
                    // too — CPython's `test_io` asks for 0x8000_0000_0000_1000
                    // on purpose. Only a request that would have fitted, and did
                    // not, is carrick's address space running out.
                    let refusal = if length > (1u64 << 48) {
                        MmapRefusal::Spec("length exceeds the entire mmap address-space arena")
                    } else {
                        MmapRefusal::Internal("no free address-space region: mmap arena exhausted")
                    };
                    return Ok(request.refused(refusal, LINUX_ENOMEM));
                }
            };

            let fixed_anonymous = map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_flags.contains(LinuxMmapFlags::FIXED);
            let layout = this.mem().lock().layout;
            let in_arena = range_within(address, length, layout.mmap_base, layout.mmap_size);
            let address_uses_alias = mmap_request_uses_alias(
                map_flags.contains(LinuxMmapFlags::FIXED),
                mmap_address_uses_alias(address, length, layout),
                memory.read_bytes_raw(address, 1).is_ok(),
                in_arena,
            );
            // Move-3 E1: an eligible MAP_PRIVATE file mmap lowers to ONE host
            // file-backed `MAP_PRIVATE|MAP_FIXED` mapping (demand-paged from
            // the unified buffer cache) instead of the eager full-length
            // `vec![0]` + `pread` + arena-copy materialization, whose three
            // whole-length passes put 36% of the cold build's zero-fill
            // faults inside guest mmap service windows
            // (docs/perf-results/2026-08-06-build-lane-amplification-ledger.md §7).
            // Eligibility is narrow and explicit; every other shape keeps the
            // snapshot path below, each exclusion for a named reason:
            //   * Private only (a Shared mapping's stores must reach the file);
            //   * no GROWSDOWN (stack-shaped file maps stay on the audited path);
            //   * PROT_EXEC admitted (stage-2 is RWX on the frame and stage-1
            //     carries the guest UXN/AP permission, cleared on protect_range);
            //   * `OpenDescription::HostFile` only (in-memory VFS contents
            //     have no host object to map; chardevs keep their zero-fill);
            //   * a non-alias VA (alias IPAs publish via `MapHostAlias`, whose
            //     payload transaction owns the backing);
            //   * the backend's own refusals (identity host ownership,
            //     host-page alignment, linux4k subpage sharing, may-execute).
            // The beyond-EOF tail is then published as BUS_ADRERR through the
            // same bus machinery the Shared path uses — which the eager arena
            // path never did for private maps (it zero-filled instead; Linux
            // faults). Probe `mmapprivfile`'s beyond_eof_page clause is the
            // conformance receipt for that correction.
            // Opt-out hatch for bisection: CARRICK_MMAP_FILE_BACKED=0.
            //
            // Two phases: the CANDIDATE check here (so no snapshot buffer is
            // materialized for a mapping about to demand-page), and the actual
            // backend replacement in the general path below — strictly AFTER
            // `prepare_mmap_locked_range`, the last fallible pre-step, so a
            // failed mmap still leaves a MAP_FIXED target's prior mapping
            // intact (Linux's failure atomicity; the eager path gets this for
            // free by building its buffer before touching backing).
            let lowering_candidate = file_lowering_eligible && !address_uses_alias;
            // A lowering candidate defers this scrub: `zero_anonymous_reuse`
            // materializes anonymous backing under the range, which would turn
            // the sparse hole the page-cache view needs into live pages and
            // force the eager snapshot. The lowering block below scrubs on its
            // fallback path instead, before the `pread` lands.
            let reuse_scrub_needed = (reused || fixed_anonymous) && !address_uses_alias;
            if reuse_scrub_needed && !lowering_candidate {
                // Scrub the reused region's PHYSICAL backing. MUST bypass the
                // guest-visible permission: a region just reclaimed from munmap
                // is stage-1-invalidated (no-access) and a PROT_NONE mmap is not
                // writable, so the permission-checked write_bytes silently faults
                // and leaves the prior mapping's bytes — which then surface after
                // the guest mprotects the region to RW (CPython multiprocessing
                // Pool built on a freed 16 MiB b'X' buffer → 0x58.. ptr → SIGSEGV).
                // MAP_FIXED|ANON also overwrites a caller-selected range, so it
                // cannot rely on the bump allocator's pristine-tail invariant.
                if let Err(error) = memory.zero_anonymous_reuse(
                    address,
                    length_usize,
                    map_sharing.guest_mapping_sharing(),
                ) {
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("anonymous-reuse scrub failed (mmap arena)"),
                        LINUX_ENOMEM,
                        format_args!("at {address:#x}+{length:#x}: {error}"),
                    ));
                }
            }

            // Restore guest-visible stage-1 validity for arena allocations: a
            // page reclaimed from a prior munmap (which invalidated it) must be
            // valid+RW again, and a PROT_NONE mmap must actually fault. No-op
            // (no TLBI) when the page is already at the target protection.
            let prot_none = prot_flags.is_empty();
            if prot_none && map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                memory.set_mapping_protection_and_sharing(
                    address,
                    length_usize,
                    true,
                    false,
                    map_sharing.guest_mapping_sharing(),
                );
                // protect_range runs UNCONDITIONALLY so a demand-paged backend
                // (bhyve) records a reservation across the WHOLE mmap arena,
                // not just the first `mmap_arena_size()` bytes — Go's page
                // allocator bumps its summary mmaps well past that. The error
                // is fatal only inside the eager arena (where eager backends
                // must succeed); an out-of-arena protect_range failure is
                // benign (KVM/NVMM host-map lazily, HVF maps the arena eagerly).
                if let Err(error) = memory.protect_range(address, length_usize, 0)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("PROT_NONE reservation failed in the mmap arena"),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                if let Err(errno) = this.commit_mmap_locked_range(memory, locked_range) {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("mmap locked range population failed"),
                        errno,
                        format_args!("at {address:#x}+{length:#x}: errno={errno:?}"),
                    ));
                }
                if map_flags.contains(LinuxMmapFlags::PRIVATE) {
                    if let Err(error) = this
                        .mem()
                        .lock()
                        .deferred_anonymous
                        .reserve_fresh(GuestVa(address), length_usize)
                    {
                        mark_range_unmapped(memory, address, length_usize);
                        return Ok(request.refused_by(
                            MmapRefusal::Spec("invalid deferred anonymous range"),
                            LINUX_EINVAL,
                            format_args!("at {address:#x}+{length:#x}: {error}"),
                        ));
                    }
                }
                this.record_dynamic_mapping_with_file_offset(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                    DynamicMappingSemantics {
                        file_page_offset: None,
                        droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                        semantic_vmas: None,
                    },
                );
                if map_flags.contains(LinuxMmapFlags::POPULATE) {
                    this.mark_range_resident(address, length);
                }
                if address_uses_alias {
                    this.record_alias_vma(address, length);
                }
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::returned_u64(address)?);
            }

            let defer_anonymous = memory.supports_lazy_anonymous_mmap()
                && this.linux_page_size() == 4096
                && map_flags.contains(LinuxMmapFlags::PRIVATE)
                && !map_flags.intersects(LinuxMmapFlags::POPULATE | LinuxMmapFlags::LOCKED)
                && !fixed_anonymous;

            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && (!address_uses_alias || defer_anonymous)
            {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                if fixed_anonymous {
                    let _ = memory.unmap_range(address, length_usize);
                    this.remove_mapping_metadata(address, length);
                }
                memory.set_mapping_protection_and_sharing(
                    address,
                    length_usize,
                    false,
                    !prot_flags.contains(LinuxProtFlags::WRITE),
                    map_sharing.guest_mapping_sharing(),
                );
                // A backend opting in must service kernel copyin as well as
                // guest faults from unmaterialized anonymous ranges. Keep
                // fixed replacement eager until its unmap transaction proves
                // that the previous backing has actually been retired.
                let initial_prot = if defer_anonymous { 0 } else { prot };
                // Unconditional (see the PROT_NONE arm above): reserve across
                // the whole arena for demand-paged backends; fatal only in-arena.
                if let Err(error) = memory.protect_range(address, length_usize, initial_prot)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("protection publication failed (anonymous mapping)"),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                if let Err(errno) = this.commit_mmap_locked_range(memory, locked_range) {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("mmap locked range population failed"),
                        errno,
                        format_args!("at {address:#x}+{length:#x}: errno={errno:?}"),
                    ));
                }
                if defer_anonymous {
                    if let Err(error) = this.mem().lock().deferred_anonymous
                        .reserve_fresh(GuestVa(address), length_usize)
                    {
                        mark_range_unmapped(memory, address, length_usize);
                        return Ok(request.refused_by(
                            MmapRefusal::Spec("invalid deferred anonymous range"),
                            LINUX_EINVAL,
                            format_args!("at {address:#x}+{length:#x}: {error}"),
                        ));
                    }
                }
                // Observe the FIRST TOUCH of each page, so `mincore` can tell a
                // written page from an untouched one.
                //
                // carrick publishes a mapping valid up front, so the guest's
                // stores never trap and the dispatcher's metadata cannot
                // distinguish them -- it reported every page of a live VMA as
                // resident where Linux reports only the touched ones. The host
                // cannot answer either: host pages are 16 KiB against 4 KiB
                // guest pages, so a host residency query (measured live:
                // `mach_vm_page_range_query` is exact per HOST page) blurs four
                // guest pages together and calls an untouched page resident
                // because a neighbour was written. Per-guest-page truth needs a
                // per-guest-page fault.
                //
                // That is a real cost -- one trap per anonymous page on first
                // touch -- paid deliberately, and it is the same mechanism the
                // shared-anonymous path already uses. `CARRICK_MINCORE_EXACT=0`
                // turns it off for bisection.
                if defer_anonymous
                    || (map_flags.contains(LinuxMmapFlags::PRIVATE)
                    && !map_flags.contains(LinuxMmapFlags::POPULATE)
                    && !prot_flags.is_empty()
                    && in_arena
                    && std::env::var("CARRICK_MINCORE_EXACT").as_deref() != Ok("0")
                    && memory
                        .resident_pages(GuestVa(address), 1, this.linux_page_size())
                        .is_none()
                    && memory.protect_range(address, length_usize, 0).is_ok())
                {
                    this.track_resident_fault_range(address, length, prot_flags);
                    // The temporary inaccessible backing is NOT the guest's VMA
                    // permission; keep reporting what the guest asked for.
                    memory.set_mapping_protection(
                        address,
                        length_usize,
                        false,
                        !prot_flags.contains(LinuxProtFlags::WRITE),
                    );
                    if let Some(protections) = memory.protections() {
                        protections.set_executable(
                            address,
                            length_usize,
                            prot_flags.contains(LinuxProtFlags::EXEC),
                        );
                    }
                }
                this.record_dynamic_mapping_with_file_offset(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                    DynamicMappingSemantics {
                        file_page_offset: None,
                        droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                        semantic_vmas: None,
                    },
                );
                if map_flags.contains(LinuxMmapFlags::POPULATE) {
                    this.mark_range_resident(address, length);
                }
                if address_uses_alias {
                    this.record_alias_vma(address, length);
                }
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::returned_u64(address)?);
            }

            let mut bus_fault_offset = None;
            // A MAP_SHARED mapping of a memfd sealed F_SEAL_WRITE is created
            // read-only here (a writable one already returned EPERM above); record
            // it so a later mprotect(PROT_WRITE) is rejected.
            let mut mmap_write_sealed_shared = false;
            // A live MAP_SHARED, PROT_WRITE mapping of an (unsealed) memfd — its
            // backing description is recorded so F_ADD_SEALS F_SEAL_WRITE can
            // EBUSY while it is mapped.
            let mut writable_memfd_desc: Option<Arc<crate::kernel::FileDescription>> = None;
            let mut packet_socket_desc: Option<Arc<super::net::packet::PacketSocket>> = None;
            let bytes = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) || lowering_candidate {
                Vec::new()
            } else {
                let mut bytes = vec![0; length_usize];
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description vanished mid-dispatch (content load)"),
                        LINUX_EBADF,
                    ));
                };
                // Independently opened in-memory descriptions are snapshots of
                // one shared overlay inode. Another process can extend/write
                // that inode after this description was opened (Go telemetry
                // does exactly this before MAP_SHARED). Refresh at map time so
                // EOF classification and the initial mapped bytes come from the
                // live inode rather than a stale per-open snapshot.
                if map_sharing == MmapSharing::Shared {
                    let path = match open_file.description.read().as_deref() {
                        Some(OpenDescription::File { path, .. }) => Some(path.clone()),
                        _ => None,
                    };
                    if let Some(path) = path
                        && let Some(live) = this.fs.rootfs_vfs.overlay.file_contents(&path)
                    {
                        if let Some(mut open) = open_file.description.write() {
                            if let OpenDescription::File {
                                path: open_path,
                                contents,
                                metadata,
                                ..
                            } = &mut *open
                                && *open_path == path
                            {
                                metadata.size = live.len();
                                *contents = FileContents::dense(live);
                            }
                        }
                    }
                }
                let Some(open) = open_file.description.read() else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description vanished mid-dispatch (content load)"),
                        LINUX_EBADF,
                    ));
                };
                let offset_usize =
                    usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
                match &*open {
                    OpenDescription::File { contents, .. } => {
                        let file_len = match contents.len() {
                            Ok(len) => len,
                            Err(errno) => {
                                return Ok(request.refused(
                                    MmapRefusal::Internal(
                                        "file length lookup failed during mmap populate",
                                    ),
                                    errno,
                                ));
                            }
                        };
                        if let Some(bus_offset) = shared_file_bus_offset(
                            file_len,
                            offset,
                            length,
                            page_size,
                        ) {
                            bus_fault_offset = Some(bus_offset);
                        }
                        if map_sharing == MmapSharing::Shared
                            && matches!(
                                open_file
                                    .description
                                    .common()
                                    .seals()
                                    .and_then(carrick_abi::LinuxMemfdSeals::from_bits),
                                Some(s) if s.intersects(
                                    carrick_abi::LinuxMemfdSeals::WRITE
                                        | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
                                )
                            )
                        {
                            mmap_write_sealed_shared = true;
                        }
                        if map_sharing == MmapSharing::Shared
                            && prot_flags.contains(LinuxProtFlags::WRITE)
                            && open_file.description.common().seals().is_some()
                        {
                            writable_memfd_desc =
                                Some(std::sync::Arc::clone(&open_file.description));
                        }
                        if let Err(errno) = contents.read_at(offset, &mut bytes[..length_usize]) {
                            return Ok(request.refused(
                                MmapRefusal::Internal("file read failed during mmap populate"),
                                errno,
                            ));
                        }
                    }
                    OpenDescription::SyntheticFile { contents, path, .. } => {
                        if let Some(bus_offset) = shared_file_bus_offset(
                                contents.len() as u64,
                                offset,
                                length,
                                page_size,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
                        }
                        if offset_usize < contents.len() {
                            let available = &contents[offset_usize..];
                            let copy_len = available.len().min(length_usize);
                            bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                        }
                    }
                    OpenDescription::InMemoryFile { contents, .. } => {
                        let data = contents.read();
                        if let Some(bus_offset) = shared_file_bus_offset(
                                data.len() as u64,
                                offset,
                                length,
                                page_size,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
                        }
                        let read_bytes = data.read_range(offset_usize, length_usize);
                        bytes[..read_bytes.len()].copy_from_slice(&read_bytes);
                    }
                    OpenDescription::HostFile { host_fd, .. } => {
                        if let Some(file_len) = host_fd_file_len(host_fd.raw())
                            && let Some(bus_offset) =
                                shared_file_bus_offset(file_len, offset, length, page_size)
                        {
                            bus_fault_offset = Some(bus_offset);
                        }
                        let n = unsafe {
                            libc::pread(
                                host_fd.raw(),
                                bytes.as_mut_ptr() as *mut _,
                                length_usize,
                                offset as libc::off_t,
                            )
                        };
                        let _ = n;
                    }
                    // `/dev/zero` (and other zero-fill char devices) open as a
                    // HostPipe — carrick routes all `/dev/*` chardevs through the
                    // pipe variant. Linux maps `/dev/zero` as zero-fill memory, so
                    // MAP_PRIVATE of it must SUCCEED with a zeroed region, not the
                    // spurious EBADF this catch-all gave (LTP mmap10 maps
                    // `/dev/zero` MAP_PRIVATE and asserts success). `bytes` is
                    // already zeroed; only fail a genuine pipe/FIFO (not a char
                    // device), which Linux rejects with ENODEV. Narrow probe via
                    // fstat S_IFCHR so a real pipe still fails.
                    OpenDescription::HostPipe { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        let is_chardev = unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0
                            && (st.st_mode as u32 & libc::S_IFMT as u32)
                                == libc::S_IFCHR as u32;
                        if !is_chardev {
                            return Ok(request.refused(
                                MmapRefusal::Spec("mmap of a pipe or FIFO"),
                                linux_errno::ENODEV,
                            ));
                        }
                        // chardev zero-fill: keep `bytes` zeroed (no read).
                    }
                    OpenDescription::SyntheticDevice { kind, .. } => {
                        if *kind != crate::vfs::SyntheticDeviceKind::Zero {
                            return Ok(request.refused(
                                MmapRefusal::Spec("mmap of a non-zero synthetic device"),
                                linux_errno::ENODEV,
                            ));
                        }
                        // /dev/zero zero-fill: keep `bytes` zeroed (no read).
                    }
                    OpenDescription::Packet { socket, .. } => {
                        if offset != 0 {
                            return Ok(request.refused(
                                MmapRefusal::Spec("mmap of packet ring with non-zero offset"),
                                LINUX_EINVAL,
                            ));
                        }
                        let init = match socket.initial_ring_bytes() {
                            Some(b) => b,
                            None => {
                                return Ok(request.refused(
                                    MmapRefusal::Spec("mmap of packet socket without ring"),
                                    LINUX_EBUSY,
                                ));
                            }
                        };
                        if length_usize != init.len() {
                            return Ok(request.refused(
                                MmapRefusal::Spec("mmap size does not match packet ring size"),
                                LINUX_EINVAL,
                            ));
                        }
                        let copy_len = init.len().min(bytes.len());
                        bytes[..copy_len].copy_from_slice(&init[..copy_len]);
                        packet_socket_desc = Some(Arc::clone(socket));
                    }
                    _ => {
                        return Ok(request.refused(
                            MmapRefusal::Spec("mmap of a descriptor with no mappable backing"),
                            LINUX_EBADF,
                        ));
                    }
                }
                bytes
            };

            // Auxiliary memfd/seal state is published only after every
            // fallible backing/protection operation below succeeds. Recording
            // it here would leave a ghost live mapping when an identity-host
            // mprotect fails before dynamic VMA publication.

            // Guest-chosen mmap addresses outside Carrick's low identity arenas
            // use alias backing. VAs >= 1 TiB need this because HVF's IPA is
            // 40 bits; lower canonical hints in the free gap above the shared
            // aperture use the same machinery so Linux-style advisory hints
            // (notably Go's 0xc000000000 arena probe) are preserved instead of
            // being relocated into the low mmap arena.
            if address_uses_alias {
                if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                    && let Some(reason) =
                        this.native16k_write_exec_rejection(&*memory, cx.thread, false, true)
                {
                    cx.reporter.record(CompatEvent::partial_syscall(
                        cx.number(),
                        "mmap",
                        cx.raw_args(),
                        reason,
                    ));
                    return Ok(request.refused(
                        MmapRefusal::Internal("PROT_WRITE|PROT_EXEC is unsupported on this backend (alias VA)"),
                        LINUX_EOPNOTSUPP,
                    ));
                }
                // Reject a genuinely non-canonical hint (bits 55:48 of the
                // ORIGINAL address neither all-0 nor all-1). With TCR_EL1.TBI on,
                // canonicality is decided by bits 55:48, not 63:48. A canonical
                // high-half address is translatable via TTBR1 and is aliased
                // below; MAP_FIXED_NOREPLACE is a hint the caller retries without.
                let bits_55_48 = (requested_raw >> 48) & 0xff;
                if bits_55_48 != 0x00 && bits_55_48 != 0xff {
                    if map_flags.contains(LinuxMmapFlags::FIXED_NOREPLACE) {
                        return Ok(request.refused(
                            MmapRefusal::Spec("MAP_FIXED_NOREPLACE at a non-canonical address"),
                            linux_errno::EEXIST,
                        ));
                    }
                    return Ok(request.refused(
                        MmapRefusal::Spec("non-canonical address hint"),
                        LINUX_ENOMEM,
                    ));
                }
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                // The guest VA is final. Mature VMM consumes a fresh monotonic
                // alias IPA; HVPatch supplies a sentinel that its reusable
                // GlobalFrameStage2Lease replaces before stage-2 publication.
                // Stage-1 still covers exactly the guest page-aligned length.
                let Some(ipa) = alloc_alias_ipa_for_publication(length, true) else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("alias IPA arena exhausted (guest-chosen VA)"),
                        LINUX_ENOMEM,
                    ));
                };
                // Alias VMA/lock/residency/bus/seal state is a pending commit:
                // no dispatcher metadata changes until the runtime reports the
                // host mapping and every subrange protection successful.
                let bus_fault = bus_fault_offset.and_then(|bus_offset| {
                    Some((
                        address.checked_add(bus_offset)?,
                        length.checked_sub(bus_offset)?,
                    ))
                });
                let transaction = host_alias_dispatch
                    .publish(HostAliasCommit::mmap(
                        HostAliasMmapCommit {
                            start: address,
                            len: length,
                            prot: prot_flags,
                            sharing: map_sharing.proc_map_sharing(),
                            path: proc_map_path.clone(),
                            file_page_offset: (!proc_map_path.is_empty()).then_some(
                                offset / crate::core_dump::GUEST_PAGE as u64,
                            ),
                            droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                            semantic_vmas: None,
                            locked: locked_range,
                            resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                                || map_flags.contains(LinuxMmapFlags::POPULATE),
                            bus_fault,
                            write_sealed_shared: mmap_write_sealed_shared,
                            read_only_shared_file: mmap_read_only_shared_file,
                            secretmem: secretmem_backed,
                            writable_memfd: writable_memfd_desc,
                            private_file: PrivateFileMapEntry::for_mapping(
                                &private_file_description, address, length, offset,
                            ),
                            shared_file_alias: None,
                        },
                    ))
                    .map_err(|_| DispatchError::Errno(linux_errno::ENOMEM))?;
                if let Some(socket) = &packet_socket_desc {
                    socket.set_mapped_va(GuestVa(address));
                }
                return Ok(DispatchOutcome::MapHostAlias {
                    success_retval: address as i64,
                    transaction,
                    va: GuestVa(address),
                    ipa: Gpa(ipa),
                    len: length,
                    payload: bytes,
                    backing: HostAliasBacking::Anonymous {
                        sharing: if map_sharing == MmapSharing::Shared {
                            HostAliasSharing::Shared
                        } else {
                            HostAliasSharing::Private
                        },
                    },
                    prot,
                    prot_none,
                });
            }

            let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
            // Move-3 E1, phase 2: replace the arena backing with the host file
            // mapping now that every fallible pre-step has passed. On backend
            // refusal (alignment, ownership, may-execute, linux4k, host mmap
            // failure) — or an unstattable fd — fall back to the legacy eager
            // materialization INLINE, bit-compatible with the pre-E1 arena
            // path: a zeroed buffer plus a best-effort `pread` whose failure
            // leaves zeros. The fallback must not introduce ANY new errno
            // here: by this point the address/scrub steps have already run, so
            // a fresh failure would break mmap's failure atomicity exactly
            // where the eager path never failed (it read best-effort and
            // succeeded). A known map-time EOF still publishes BUS_ADRERR for
            // every whole page beyond it: snapshot materialization changes the
            // backing primitive, not Linux's private-file fault contract.
            let mut bytes = bytes;
            let mut lowered_file_backed = false;
            let mut deferred_file_backed_len = None;
            if lowering_candidate {
                let Some(open_file) = this.open_file(fd.0) else {
                    // The description vanished mid-dispatch; the eager path's
                    // own EBADF position for the same state.
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description vanished mid-dispatch (file-backed lowering)"),
                        LINUX_EBADF,
                    ));
                };
                let open = open_file.description.read();
                let Some(host_fd) = open.as_deref().and_then(OpenDescription::shared_alias_host_fd)
                else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description changed type mid-dispatch (file-backed lowering)"),
                        LINUX_EBADF,
                    ));
                };
                let source = match open.as_deref() {
                    Some(OpenDescription::HostFile { host_fd, .. }) => host_fd.private_file_source(),
                    _ => carrick_guest_mem::PrivateFileSource::Mutable,
                };
                use carrick_observability::probes::MmapLoweringOutcome;
                let lowering_outcome;
                if let Some(file_len) = host_fd_file_len(host_fd) {
                    bus_fault_offset =
                        shared_file_bus_offset(file_len, offset, length, page_size);
                    let lazy_len = bus_fault_offset.unwrap_or(length);
                    let defer_file = source
                        == carrick_guest_mem::PrivateFileSource::ImmutableLower
                        && memory.supports_lazy_private_file_mmap()
                        && page_size == 4096
                        && lazy_len != 0
                        && !map_flags.intersects(
                            LinuxMmapFlags::FIXED
                                | LinuxMmapFlags::POPULATE
                                | LinuxMmapFlags::LOCKED,
                        );
                    // SAFETY: the description read guard (`open`) keeps the
                    // owning fd (a `HostFdRef`, or the memfd's `OwnedFd`) alive
                    // across the borrow.
                    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(host_fd) };
                    let lowering = if defer_file {
                        memory.defer_private_file_backed(
                            address,
                            lazy_len as usize,
                            borrowed,
                            offset,
                            source,
                        )
                    } else {
                        memory.map_private_file_backed(
                            address,
                            length_usize,
                            borrowed,
                            offset,
                            source,
                        )
                    };
                    match lowering {
                        Ok(true) => {
                            lowered_file_backed = true;
                            deferred_file_backed_len = defer_file.then_some(lazy_len);
                            lowering_outcome = MmapLoweringOutcome::Installed;
                        }
                        Ok(false) => {
                            lowering_outcome = MmapLoweringOutcome::Refused;
                        }
                        Err(e) => {
                            lowering_outcome = MmapLoweringOutcome::Error;
                            carrick_observability::probes::mmap_lowering_error(
                                address,
                                length,
                                offset,
                                &e,
                            );
                        }
                    }
                } else {
                    lowering_outcome = MmapLoweringOutcome::MetadataUnavailable;
                }
                carrick_observability::probes::mmap_lowering_verdict(
                    address,
                    length,
                    offset,
                    lowering_outcome,
                );
                if !lowered_file_backed {
                    if reuse_scrub_needed
                        && let Err(error) = memory.zero_anonymous_reuse(
                            address,
                            length_usize,
                            map_sharing.guest_mapping_sharing(),
                        )
                    {
                        return Ok(request.refused_by(
                            MmapRefusal::Internal("anonymous-reuse scrub failed (mmap arena)"),
                            LINUX_ENOMEM,
                            format_args!("at {address:#x}+{length:#x}: {error}"),
                        ));
                    }
                    let mut fallback = vec![0; length_usize];
                    let n = unsafe {
                        libc::pread(
                            host_fd,
                            fallback.as_mut_ptr() as *mut _,
                            length_usize,
                            offset as libc::off_t,
                        )
                    };
                    let _ = n;
                    bytes = fallback;
                }
            }
            // Stamp file content through the unchecked path: this is carrick
            // loading the mapping, not a guest write. The dynamic loader often
            // reserves a whole DSO as PROT_NONE before MAP_FIXED segment loads;
            // on identity-native backends that is a real host mprotect, so make
            // the backing temporarily writable before memcpy and apply the
            // requested Linux permission immediately afterward.
            if !bytes.is_empty() {
                let rw = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
                if let Err(error) = memory.protect_range(address, length_usize, rw)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal(
                            "temporary writable protection failed while loading file content",
                        ),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                if let Err(error) = memory.write_bytes_unchecked(address, &bytes) {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("file content could not be copied into the mapping"),
                        LINUX_ENOMEM,
                        format_args!("at {address:#x}+{length:#x}: {error}"),
                    ));
                }
            }
            memory.set_mapping_protection_and_sharing(
                address,
                length_usize,
                prot_none,
                !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                map_sharing.guest_mapping_sharing(),
            );
            // Make the requested protection guest-visible (also restores RW for
            // a reused range). prot==0 here means file-backed PROT_NONE.
            // Unconditional: reserve across the whole arena; fatal only in-arena.
            let initial_prot = if deferred_file_backed_len.is_some() {
                0
            } else {
                prot
            };
            if let Err(error) = memory.protect_range(address, length_usize, initial_prot)
                && (in_arena || memory.supports_concurrent_exec_protection())
            {
                if deferred_file_backed_len.is_some() {
                    let _ = this
                        .mem()
                        .lock()
                        .deferred_anonymous
                        .retire(GuestVa(address), length_usize);
                }
                mark_range_unmapped(memory, address, length_usize);
                return Ok(request.refused_by(
                    MmapRefusal::Internal("requested protection could not be published"),
                    LINUX_ENOMEM,
                    format_args!("at {address:#x}+{length:#x} in_arena={in_arena}: {error}"),
                ));
            }
            if let Some(bus_offset) = bus_fault_offset
                && let Some(bus_start) = address.checked_add(bus_offset)
                && let Some(bus_len) = length.checked_sub(bus_offset)
                && let Ok(bus_len_usize) = usize::try_from(bus_len)
            {
                memory.set_no_access(bus_start, bus_len_usize, true);
                if let Err(error) = memory.protect_range(bus_start, bus_len_usize, 0)
                    && memory.supports_concurrent_exec_protection()
                {
                    if deferred_file_backed_len.is_some() {
                        let _ = this
                            .mem()
                            .lock()
                            .deferred_anonymous
                            .retire(GuestVa(address), length_usize);
                    }
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("beyond-EOF SIGBUS protection could not be published"),
                        LINUX_ENOMEM,
                        format_args!("at {bus_start:#x}+{bus_len:#x}: {error}"),
                    ));
                }
                this.record_mmap_bus_fault_range(bus_start, bus_len);
            }
            if let Some(deferred_len) = deferred_file_backed_len
                && !prot_flags.is_empty()
            {
                this.track_resident_fault_range(address, deferred_len, prot_flags);
            }
            // A file-backed mapping's content is loaded eagerly (above), and
            // MAP_POPULATE prefaults anonymous pages — so mincore must report
            // those pages resident even before the guest touches them (LTP
            // mincore04 mlocks in a child, then the parent queries mincore).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                || map_flags.contains(LinuxMmapFlags::POPULATE)
            {
                this.mark_range_resident(address, length);
            }
            this.commit_mmap_locked_range(memory, locked_range)?;
            if mmap_write_sealed_shared {
                this.record_write_sealed_shared_map(address, length);
            }
            if mmap_read_only_shared_file {
                this.record_read_only_shared_file_map(address, length);
            }
            if secretmem_backed {
                this.record_secretmem_map(address, length);
            }
            if let Some(description) = writable_memfd_desc {
                this.record_writable_memfd_map(address, length, description);
            }
            let file_page_offset = (!proc_map_path.is_empty())
                .then_some(offset / crate::core_dump::GUEST_PAGE as u64);
            this.record_dynamic_mapping_with_file_offset(
                address,
                length,
                prot_flags,
                map_sharing.proc_map_sharing(),
                proc_map_path,
                DynamicMappingSemantics {
                    file_page_offset,
                    droppable: map_flags.contains(LinuxMmapFlags::DROPPABLE),
                    semantic_vmas: None,
                },
            );
            if let Some(source) = PrivateFileMapEntry::for_mapping(
                &private_file_description, address, length, offset,
            ) {
                this.mem().lock().private_file_maps.push(source);
            }
            if let Some(socket) = &packet_socket_desc {
                socket.set_mapped_va(GuestVa(address));
            }
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::returned_u64(address)?)
        }

        mm_mutation fn munmap(this, cx, address: GuestPtr, length: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch(&permit);
            let page_size = this.linux_page_size();
            // Linux munmap EINVAL edges (__vm_munmap): the address must be
            // page-aligned and the length non-zero. LTP munmap03 munmaps the
            // address of a BSS global (8-aligned, not page-aligned) and that
            // address + 8, expecting EINVAL — carrick lacked the alignment gate.
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(aligned_len) = align_up_u64(length, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let had_vma = guest_vma_overlaps_locked(&this.mem().lock(), address.0, aligned_len);
            let (
                shared_owned,
                shared_carvable,
                shared_preview,
                overlay_owned,
                overlay_carvable,
            ) = {
                let mem_authority_17 = this.mem();
                let mem = mem_authority_17.lock();
                (
                    mem.shared.guest_range_has_owner(address.0, aligned_len),
                    mem.shared.guest_range_is_carvable(address.0, aligned_len),
                    mem.shared.guest_range_fragments(address.0, aligned_len),
                    mem.overlay.source_range_has_owner(address.0, aligned_len),
                    mem.overlay
                        .source_range_is_carvable(address.0, aligned_len, None),
                )
            };
            if shared_owned && !shared_carvable || overlay_owned && !overlay_carvable {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !shared_owned && overlay_owned {
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if cx.memory.unmap_range(address.0, len_usize).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                if this.mem()
                    .lock()
                    .overlay
                    .carve_source_range(address.0, aligned_len, None)
                    .is_none()
                {
                    carrick_fatal!(
                        "dispatch::munmap_overlay",
                        "overlay carve_source_range failed during private overlay munmap"
                    );
                }
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if shared_owned {
                // SharedFile fragments write their exact dirty intervals back;
                // SharedAnon removes are pure bookkeeping. The aperture stays
                // stage-2 mapped — no hv_vm_unmap.
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let Some(shared_preview) = shared_preview else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Capture while the shared guest translation is still live;
                // commit pwrite only after backend unmap succeeds.
                let shared_snapshots = shared_preview
                    .iter()
                    .map(|alloc| this.snapshot_shared_writeback(&mut *cx.memory, alloc))
                    .collect::<Vec<_>>();
                if cx.memory.unmap_range(address.0, len_usize).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                let displaced_shared = {
                    let mem_authority_18 = this.mem();
                    let mut mem = mem_authority_18.lock();
                    if mem
                        .overlay
                        .carve_source_range(address.0, aligned_len, None)
                        .is_none()
                    {
                        carrick_fatal!(
                            "dispatch::munmap_overlay",
                            "overlay carve_source_range failed during shared/overlay munmap"
                        );
                    }
                    let Some(displaced) = mem.shared.carve_guest_range(address.0, aligned_len) else {
                        carrick_fatal!(
                            "dispatch::munmap_shared",
                            "shared aperture carve_guest_range failed during munmap"
                        );
                    };
                    displaced
                };
                for (alloc, bytes) in shared_preview.iter().zip(&shared_snapshots) {
                    if let Some(bytes) = bytes {
                        this.writeback_shared_snapshot(alloc, bytes);
                    }
                }
                drop(displaced_shared);
                drop(shared_preview);
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A canonical alias-window guest VA is a dynamic alias mapping:
            // either a MAP_SHARED file region (carrick-chosen VA in the narrow
            // alias window, backed LIVE by the host page cache, so no writeback
            // is owed), a MAP_FIXED mapping at a guest-chosen high VA (Apple
            // Rosetta maps its translated ELF + arenas in the x86-64 high half),
            // or a Linux-style advisory hint in the free gap above Carrick's
            // shared aperture. All are valid mappings/reservations, so munmap
            // must succeed. Best-effort stage-1 invalidate so use-after-munmap
            // faults; arm64 HVF has no stage-2 unmap, so the alias IPA + any dup
            // fd are reclaimed at process teardown.
            // Misaligned addresses (e.g. RLIM_INFINITY, which LTP munmap03 passes
            // to assert EINVAL) are already rejected by the alignment gate above;
            // addresses >= 2^48 stay EINVAL via the range check below.
            let layout = this.mem().lock().layout;
            if this.range_is_alias_vma(address.0, length)
                || mmap_address_uses_alias(address.0, length, layout)
            {
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Alias teardown: invalidate AND reclaim the now-empty per-
                // alias stage-1 sub-table (each MAP_SHARED file mapping took
                // its own 2 MiB block + L3 table) — else the spare pool leaks
                // one table per alias and a churning guest hits OutOfTables.
                if cx
                    .memory
                    .unmap_alias_range(address.0, len_usize)
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !range_within(address.0, length, layout.mmap_base, layout.mmap_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Ok(len_usize) = usize::try_from(aligned_len) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Invalidate the freed range before removing any dispatcher VMA
            // metadata or returning it to the allocator.
            if cx.memory.unmap_range(address.0, len_usize).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
            this.remove_mapping_metadata(address.0, aligned_len);
            let mem_authority_19 = this.mem();
            let mut mem = mem_authority_19.lock();
            if mem
                .overlay
                .carve_source_range(address.0, aligned_len, None)
                .is_none()
            {
                carrick_fatal!(
                    "dispatch::munmap_overlay",
                    "overlay carve_source_range failed during anonymous arena munmap"
                );
            }
            if address.0.checked_add(aligned_len) == Some(mem.mmap_next) {
                let mem = &mut *mem;
                lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, address.0);
            } else {
                free_regions_insert(&mut mem.free_regions, address.0, aligned_len);
            }
            drop(mem);
            if had_vma {
                this.mark_vma_dispatch(&mut host_alias_dispatch);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn mremap(this, cx, old_address: GuestPtr, old_size: u64, new_size_req: u64, flags: u64, new_address: GuestPtr) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch(&permit);
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();
            // Errno precedence below is oracle-derived (real Linux 6.12.76,
            // docker gcc:latest, 2026-07-23 — see
            // .superpowers/sdd/mremap-ruling-report.md) and follows man 2 mremap's
            // documented EINVAL conditions: no unrecognized flag bits,
            // new_size != 0, MREMAP_FIXED/MREMAP_DONTUNMAP only paired with
            // MREMAP_MAYMOVE, and MREMAP_DONTUNMAP only with old_size ==
            // new_size. Real Linux validates ALL of these — even for
            // requests that use MREMAP_FIXED or MREMAP_DONTUNMAP, since real
            // Linux actually implements both flags — before it would ever
            // attempt the remap. So every one of these well-formedness
            // checks must run BEFORE carrick's own "not yet implemented"
            // refusal just below: a malformed request (e.g. an unrelated
            // garbage bit ORed onto MREMAP_FIXED) must surface the EINVAL
            // real Linux would give, not carrick's EOPNOTSUPP stand-in for a
            // shape real Linux would have actually performed.
            if new_size_req == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `man 2 mremap`: `old_address` must be page aligned, and EINVAL is
            // documented for "old_address was not page aligned". Carrick
            // validated the MREMAP_FIXED `new_address` alignment but never the
            // source, so a misaligned request ran the whole move: it published
            // the destination, then could not reclaim the misaligned source
            // (`MemoryError::Unsupported`) and hit the fail-stop `abort()`
            // below, taking the carrier down. `memflagmatrix` is an
            // argument-matrix probe and asks for exactly this
            // (`old_address = 0x6000006001`, `old_size = 4096`,
            // `new_size = 8192`), so the whole shard-2 executable aborted.
            // Ordering against the other EINVAL well-formedness checks is
            // unobservable — they all yield EINVAL — but this must precede the
            // size rounding below, which answers ENOMEM.
            if !old_address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `man 2 mremap`: a zero `old_size` asks for a NEW mapping of the
            // same pages, which is only meaningful for a shareable mapping and
            // necessarily relocates -- so it requires MREMAP_MAYMOVE. Without
            // it Linux answers EINVAL; carrick rounded the zero up and tried to
            // resize in place (`memflagmatrix` `mremap_old_len_zero_einval`).
            if old_size == 0 && flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(old_size) = align_up_u64(old_size, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Some(new_size) = align_up_u64(new_size_req, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let move_fixed = flags & LINUX_MREMAP_FIXED != 0;
            let dontunmap = flags & LINUX_MREMAP_DONTUNMAP != 0;
            if (move_fixed || dontunmap) && flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if dontunmap && new_size != old_size {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // Two more well-formedness checks real Linux performs on a
            // MREMAP_FIXED request, both EINVAL, both BEFORE it would attempt
            // the move — so they must precede carrick's "not yet implemented"
            // EOPNOTSUPP stand-in below for the same reason the checks above
            // do. Without them a malformed fixed request reported carrick's
            // refusal instead of the errno Linux gives (mremap05 cases 2/3:
            // "new_addr has to be page aligned" and "old/new area must not
            // overlap", both answered EOPNOTSUPP).
            if move_fixed {
                if !new_address.0.is_multiple_of(page_size) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if ranges_overlap(
                    old_address.0,
                    old_size,
                    new_address.0,
                    new_address.0.saturating_add(new_size),
                ) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            if this
                .captured_mm()
                .io_uring_mapping_overlaps(old_address.0, old_size)
            {
                // Moving or resizing a ring attachment without a matching host
                // alias transaction would stale the mm join. Fail before any
                // page-table, allocator, or VMA mutation.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            // MREMAP_FIXED and MREMAP_DONTUNMAP both RELOCATE by definition:
            // the guest names the destination, or keeps the source mapped. So
            // every in-place path below is skipped for them -- each of those
            // returns `old_address`, which is exactly the answer a relocation
            // must never give. This flag gates them at their five top-level
            // guards rather than at the seven returns.
            let must_relocate = move_fixed || dontunmap;
            let layout = this.mem().lock().layout;
            let source_in_arena =
                range_within(old_address.0, old_size, layout.mmap_base, layout.mmap_size);
            if !source_in_arena && memory.read_bytes(old_address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let source_metadata = match this.mremap_mapping_metadata(memory, old_address.0, old_size) {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let is_shared_file_fixed = move_fixed
                && !dontunmap
                && source_metadata.sharing == ProcMapSharing::Shared
                && this.shared_file_alias_description(old_address.0, old_size).is_some();

            if must_relocate {
                // Relocation below moves a mapping by COPYING it. That is
                // correct for a PRIVATE mapping and wrong for a shared one:
                // every mapper of a `MAP_SHARED` object must keep observing the
                // same bytes, and a copy silently unshares it -- the same
                // reason the grow path refuses to move a shared mapping. Keep
                // the honest refusal for that shape.
                if source_metadata.sharing != ProcMapSharing::Private && !is_shared_file_fixed {
                    return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
                }
                // `MREMAP_DONTUNMAP` is defined only for private ANONYMOUS
                // memory; Linux answers EINVAL for anything file-backed,
                // because "leave the source as fresh zero pages" has no meaning
                // for a mapping whose pages come from a file.
                if dontunmap && !source_metadata.path.is_empty() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            if new_size > old_size {
                // RLIMIT_AS / RLIMIT_DATA on the growth, before any page-table,
                // allocator or VMA mutation. A move is charged like an in-place
                // grow (`new_size - old_size`): the source is unmapped again.
                // If both limits are infinite (default), no MemState lock is taken.
                let data = mapping_is_data(
                    source_metadata.prot.contains(LinuxProtFlags::WRITE),
                    source_metadata.sharing == ProcMapSharing::Private,
                    false,
                );
                if let Some((as_limit, data_limit)) = this.address_space_limits_apply(data) {
                    let mem_authority_rlimit = this.mem();
                    let mem = mem_authority_rlimit.lock();
                    if this
                        .check_address_space_limits_locked(
                            &mem,
                            as_limit,
                            data_limit,
                            new_size - old_size,
                            data,
                        )
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                }
            }
            let publish_shared_file_alias_outcome =
                |host_alias_dispatch: crate::dispatch::HostAliasDispatchGuard<'_>,
                 va: u64,
                 ipa: u64,
                 new_size: u64,
                 pf: LinuxProtFlags,
                 host_prot: i32,
                 file_offset: u64,
                 file_page_offset: Option<u64>,
                 droppable: bool,
                 path: String,
                 semantic_vmas: Option<Vec<SemanticVma>>,
                 bus_fault: Option<(u64, u64)>,
                 read_only_shared_file: bool,
                 description: Arc<crate::kernel::FileDescription>,
                 dup_fd: i32|
                 -> DispatchOutcome {
                    let transaction =
                        match host_alias_dispatch.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
                            start: va,
                            len: new_size,
                            prot: pf,
                            sharing: ProcMapSharing::Shared,
                            path,
                            file_page_offset,
                            droppable,
                            semantic_vmas,
                            locked: None,
                            resident: true,
                            bus_fault,
                            write_sealed_shared: false,
                            read_only_shared_file,
                            secretmem: false,
                            writable_memfd: None,
                            private_file: None,
                            shared_file_alias: Some(SharedFileAliasCommit {
                                description,
                                extent_base: Gpa(ipa.saturating_sub(file_offset)),
                                row_file_offset: file_offset,
                            }),
                        })) {
                            Ok(transaction) => transaction,
                            Err(_) => return DispatchOutcome::errno(LINUX_ENOMEM),
                        };
                    DispatchOutcome::MapHostAlias {
                        success_retval: va as i64,
                        transaction,
                        va: GuestVa(va),
                        ipa: Gpa(ipa),
                        len: new_size,
                        payload: Vec::new(),
                        backing: HostAliasBacking::File {
                            fd: HostAliasOwnedFd::from(unsafe { OwnedFd::from_raw_fd(dup_fd) }),
                            offset: file_offset as libc::off_t,
                            host_prot,
                            sharing: HostAliasSharing::Shared,
                        },
                        prot: pf.bits(),
                        prot_none: pf.is_empty(),
                    }
                };
            if is_shared_file_fixed {
                let va = new_address.0;
                let fail = |error: SharedFileFixedMremapError,
                            extent_base: Option<carrick_guest_mem::Gpa>,
                            offset: Option<u64>| {
                    tracing::error!(
                        va = format_args!("{va:#x}"),
                        len = format_args!("{new_size:#x}"),
                        extent_base = format_args!("{:#x}", extent_base.map_or(0, |b| b.raw())),
                        offset = format_args!("{:#x}", offset.unwrap_or(0)),
                        %error,
                        "HVPatch shared-file fixed mremap lowering failed; guest mremap lowered to ENOMEM"
                    );
                    Ok(DispatchOutcome::errno(LINUX_ENOMEM))
                };
                let Some(alias_entry) =
                    this.shared_file_alias_entry(old_address.0, old_size)
                else {
                    return fail(
                        SharedFileFixedMremapError::MissingAliasEntry {
                            old_address: old_address.0,
                            old_end: old_address.0.saturating_add(old_size),
                        },
                        None,
                        None,
                    );
                };
                let Ok(new_len) = usize::try_from(new_size) else {
                    return fail(
                        SharedFileFixedMremapError::NewLengthOverflow { new_size },
                        Some(alias_entry.extent_base),
                        None,
                    );
                };
                let Ok(old_len) = usize::try_from(old_size) else {
                    return fail(
                        SharedFileFixedMremapError::OldLengthOverflow { old_size },
                        Some(alias_entry.extent_base),
                        None,
                    );
                };
                let delta = old_address.0.saturating_sub(alias_entry.range.start().raw());
                let source_file_offset = alias_entry.row_file_offset.saturating_add(delta);
                let destination_leaf_ipa = memory
                    .translate_va(old_address.0)
                    .unwrap_or_else(|| {
                        alias_entry
                            .extent_base
                            .raw()
                            .saturating_add(source_file_offset)
                    });

                let pf = source_metadata.prot;
                let desc = &alias_entry.description;
                let bus_fault = (|| {
                    let open = desc.read();
                    let file_len = open
                        .as_deref()
                        .and_then(OpenDescription::shared_alias_host_fd)
                        .and_then(host_fd_file_len)?;
                    let bus_offset = shared_file_bus_offset(file_len, source_file_offset, new_size, page_size)?;
                    Some((
                        va.checked_add(bus_offset)?,
                        new_size.checked_sub(bus_offset)?,
                    ))
                })();
                let read_only_shared_file =
                    this.range_is_read_only_shared_file(old_address.0, old_size);

                // MREMAP_FIXED replaces whatever was at the destination range.
                if new_len > 0 {
                    if this.range_is_alias_vma(va, new_size)
                        || mmap_address_uses_alias(va, new_size, layout)
                    {
                        let _ = memory.unmap_alias_range(va, new_len);
                    } else {
                        let _ = memory.unmap_range(va, new_len);
                    }
                    mark_range_unmapped(memory, va, new_len);
                    this.remove_mapping_metadata(va, new_size);
                }
                if this
                    .next_mmap_address(
                        va,
                        new_size,
                        pf.bits(),
                        LINUX_MAP_FIXED,
                        MmapGrantCongruence::Any,
                    )
                    .is_none()
                {
                    return fail(
                        SharedFileFixedMremapError::DestinationGrantRefused {
                            va,
                            end: va.saturating_add(new_size),
                        },
                        Some(alias_entry.extent_base),
                        Some(source_file_offset),
                    );
                }

                // Repoint destination stage-1 leaf to the existing shared extent.
                if let Err(err) = memory
                    .repoint_shared_leaf(va, destination_leaf_ipa, new_len)
                {
                    return fail(
                        SharedFileFixedMremapError::RepointSharedLeaf { source: err },
                        Some(carrick_guest_mem::Gpa(
                            destination_leaf_ipa.saturating_sub(source_file_offset),
                        )),
                        Some(source_file_offset),
                    );
                }

                // Reclaim the source range.
                if old_len > 0 {
                    if this.range_is_alias_vma(old_address.0, old_size)
                        || mmap_address_uses_alias(old_address.0, old_size, layout)
                    {
                        let _ = memory.unmap_alias_range(old_address.0, old_len);
                    } else {
                        let _ = memory.unmap_range(old_address.0, old_len);
                    }
                    mark_range_unmapped(memory, old_address.0, old_len);
                    this.remove_mapping_metadata(old_address.0, old_size);
                    if source_in_arena {
                        let mem_authority = this.mem();
                        let mut mem = mem_authority.lock();
                        if old_address.0.checked_add(old_size) == Some(mem.mmap_next) {
                            let mem = &mut *mem;
                            lower_mmap_next(
                                &mut mem.mmap_next,
                                &mut mem.free_regions,
                                old_address.0,
                            );
                        } else {
                            free_regions_insert(&mut mem.free_regions, old_address.0, old_size);
                        }
                    }
                }

                let prot_none = pf.is_empty();
                memory.set_mapping_protection(
                    va,
                    new_len,
                    prot_none,
                    !prot_none && !pf.contains(LinuxProtFlags::WRITE),
                );
                memory.set_mapping_sharing(
                    va,
                    new_len,
                    carrick_guest_mem::MappingSharing::Shared,
                );

                let Some(dest_range) = crate::vfs::GuestMemoryRange::new(
                    GuestVa(va),
                    GuestVa(va.saturating_add(new_size)),
                ) else {
                    return fail(
                        SharedFileFixedMremapError::InvalidDestinationRange {
                            va,
                            end: va.saturating_add(new_size),
                        },
                        Some(carrick_guest_mem::Gpa(
                            destination_leaf_ipa.saturating_sub(source_file_offset),
                        )),
                        Some(source_file_offset),
                    );
                };
                let new_alias_entry = SharedFileAliasEntry {
                    range: dest_range,
                    description: Arc::clone(&alias_entry.description),
                    extent_base: carrick_guest_mem::Gpa(
                        destination_leaf_ipa.saturating_sub(source_file_offset),
                    ),
                    row_file_offset: source_file_offset,
                };

                let file_page_offset =
                    Some(source_file_offset / crate::core_dump::GUEST_PAGE as u64);
                let Some(semantic_vmas) =
                    source_metadata.fork_semantics.project(va, new_size)
                else {
                    return fail(
                        SharedFileFixedMremapError::ForkSemanticsProjectFailed {
                            va,
                            end: va.saturating_add(new_size),
                        },
                        Some(alias_entry.extent_base),
                        Some(source_file_offset),
                    );
                };

                this.record_dynamic_mapping_with_file_offset(
                    va,
                    new_size,
                    source_metadata.prot,
                    source_metadata.sharing,
                    source_metadata.path.clone(),
                    DynamicMappingSemantics {
                        file_page_offset,
                        droppable: source_metadata.droppable,
                        semantic_vmas: Some(semantic_vmas),
                    },
                );

                {
                    let mem_authority = this.mem();
                    let mut mem = mem_authority.lock();
                    locked_ranges_insert(&mut mem.host_alias_backed_ranges, dest_range);
                    locked_ranges_insert(&mut mem.alias_vma_ranges, dest_range);
                    locked_ranges_insert(&mut mem.resident_ranges, dest_range);
                    if read_only_shared_file {
                        locked_ranges_insert(&mut mem.read_only_shared_file_maps, dest_range);
                    }
                    if let Some((start, len)) = bus_fault {
                        mem.bus_fault_ranges.push((start, len));
                    }
                    mem.shared_file_alias_maps.push(new_alias_entry);
                }

                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::returned_u64(va)?);
            }
            let shared_aperture_alloc = this.mem()
                .lock()
                .shared
                .live()
                .iter()
                .find(|alloc| {
                    ranges_overlap(
                        old_address.0,
                        old_size,
                        alloc.guest_addr,
                        alloc.guest_addr.saturating_add(alloc.live_len),
                    )
                })
                .cloned();
            if let Some(ref alloc) = shared_aperture_alloc
                && (alloc.guest_addr != old_address.0
                    || old_size != alloc.live_len
                    || source_metadata.start != old_address.0
                    || source_metadata.end != old_address.0.saturating_add(old_size))
            {
                // Carrick cannot split one shared-aperture backing owner during
                // mremap. Reject prefix/suffix shrink before touching page tables,
                // residency, VMA metadata, or the aperture free list.
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            // A shared mapping cannot be grown by copying it somewhere bigger:
            // the whole point of MAP_SHARED is that every mapper of the object
            // observes the same bytes, and a copy would silently unshare it.
            // Linux instead keeps the backing object exactly where it is, so
            // carrick grows the aperture allocation in place. Only a
            // shared-aperture allocation that this request covers exactly can
            // do that; anything else keeps the pre-existing ENOMEM.
            //
            // Measured against real Linux 6.12 (docker gcc:latest, arm64,
            // 2026-08-17): `MAP_SHARED|MAP_ANONYMOUS` 1 page grown to 2 with
            // MREMAP_MAYMOVE succeeds, and WITHOUT MREMAP_MAYMOVE it reports
            // ENOMEM — which is why the grow below is gated on the flag.
            //
            // Restricted to SharedAnon: a SharedFile allocation's grown tail
            // must show the FILE's bytes at the matching offset (measured: a
            // 1-page MAP_SHARED window onto a 4-page file grows and the new
            // page reads and writes the file), and the aperture's granules
            // would come up zeroed instead. That shape still reports ENOMEM
            // here — an honest gap, not a silent wrong answer.
            let shared_grow_in_place = !must_relocate
                && new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && matches!(
                    shared_aperture_alloc,
                    Some(ref alloc)
                        if alloc.guest_addr == old_address.0
                            && alloc.live_len == old_size
                            && alloc.backing == crate::shared_aperture::BackingObject::SharedAnon
                );
            // File length and mapping offset behind a live MAP_SHARED alias, if
            // this range is one. Shared by the grow plan and the diagnostic
            // below so both report the same numbers.
            let alias_file_extent = (|| {
                let description = this.shared_file_alias_description(old_address.0, old_size)?;
                let file_offset = source_metadata
                    .file_page_offset
                    .unwrap_or(0)
                    .checked_mul(crate::core_dump::GUEST_PAGE as u64)?;
                let open = description.read();
                let file_len = match open.as_deref() {
                    Some(description) => description
                        .shared_alias_host_fd()
                        .and_then(host_fd_file_len),
                    None => None,
                }?;
                Some((file_len, file_offset))
            })();

            // The other shared shape carrick can grow: a live MAP_SHARED file
            // alias whose growth lands entirely PAST the file's end. Linux keeps
            // the object and its live page-cache sharing exactly as they are and
            // simply extends the VMA; every page from EOF on has no backing and
            // faults SIGBUS. Carrick can reproduce that without touching the
            // alias at all — extend the VMA and record the tail as a bus-fault
            // range — which is strictly better than re-establishing the mapping,
            // because the existing alias IS the shared page cache.
            //
            // `ltp-mremap01` is exactly this: a 0x3e8000 MAP_SHARED window onto
            // a 0x3e8000 file, grown to 0x7d0000 with MREMAP_MAYMOVE.
            let shared_file_alias_grow = (!must_relocate
                && new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && shared_aperture_alloc.is_none())
            .then(|| {
                let (file_len, file_offset) = alias_file_extent?;
                // Where SIGBUS starts inside the GROWN mapping. The growth is
                // reproducible in place only when every added byte is already
                // past that point; otherwise part of the new tail must show real
                // file bytes, which extending the VMA alone would not deliver.
                let bus_start = shared_file_bus_offset(file_len, file_offset, new_size, page_size)?;
                (bus_start <= old_size).then_some(bus_start)
            })
            .flatten();
            // Offset within the mapping at which SIGBUS starts, when the
            // mapping ALREADY ends past its file's EOF. Read off the bus records
            // the original `mmap` published rather than re-derived from a
            // descriptor: an arena snapshot keeps no fd, and the guest may well
            // have closed its own by now.
            //
            // Read the records directly — `mmap_fault_is_sigbus` opens its own
            // host-alias dispatch guard and `mremap` already holds one, so
            // calling it here DEADLOCKED the guest (the run wedged in mremap and
            // timed out with no output past the mmap).
            let shared_arena_grow_past_eof = (!must_relocate
                && new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && source_in_arena
                && old_size != 0)
            .then(|| {
                let last = old_address.0.saturating_add(old_size) - 1;
                this.mem()
                    .lock()
                    .bus_fault_ranges
                    .iter()
                    .find(|&&(start, len)| {
                        start
                            .checked_add(len)
                            .is_some_and(|end| last >= start && last < end)
                    })
                    .map(|&(start, _)| start.saturating_sub(old_address.0))
            })
            .flatten();
            // Grow of a live alias whose larger extent is still wholly inside
            // the file: re-established over the same fd below.
            let alias_regrow_within_eof = new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && shared_aperture_alloc.is_none()
                && alias_file_extent.is_some_and(|(file_len, file_offset)| {
                    shared_file_bus_offset(file_len, file_offset, new_size, page_size).is_none()
                });
            if new_size > old_size && std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                // Which grow plan (if any) matched, and the facts each one keys
                // on. A refused grow is otherwise indistinguishable from a dozen
                // other ENOMEM sources in this handler, and the shapes that need
                // one differ by backing rather than by anything the guest can
                // see. Same hatch as the mmap BUS line above.
                eprintln!(
                    "[FAULTDBG] mremap GROW addr={:#x} old={old_size:#x} new={new_size:#x} \
                     flags={flags:#x} sharing={:?} in_arena={source_in_arena} \
                     aperture={:?} anon_plan={shared_grow_in_place} \
                     arena_past_eof={shared_arena_grow_past_eof:?} \
                     alias_plan={shared_file_alias_grow:?} \
                     alias_file_extent={alias_file_extent:?} \
                     alias_regrow={alias_regrow_within_eof} path={:?}",
                    old_address.0,
                    source_metadata.sharing,
                    shared_aperture_alloc
                        .as_ref()
                        .map(|a| (a.guest_addr, a.live_len, a.len)),
                    source_metadata.path,
                );
            }
            if source_metadata.sharing == ProcMapSharing::Shared
                && new_size > old_size
                && !shared_grow_in_place
                && shared_arena_grow_past_eof.is_none()
                && shared_file_alias_grow.is_none()
                && !alias_regrow_within_eof
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !source_in_arena {
                // The mapping is not in the mmap arena: it's a MAP_SHARED file
                // alias (high VA) or a MAP_SHARED anonymous shared-aperture
                // region. CPython's mmap.resize() shrinks both of these
                // (test_mmap test_basic on a file mapping, test_resize_past_pos
                // on an anonymous one), tolerating only success or SystemError —
                // never the OSError we raised by rejecting them here.
                //
                // Support resize-DOWN: the backing stays at the same VA with a
                // smaller logical size. CPython already ftruncate'd a file
                // backing to the new size; the freed tail is not accessed (Python
                // tracks the new size/position), so we return the unchanged base.
                // Shrink revokes the tail in both backend and sharing metadata;
                // retaining a logically removed shared executable tail would let
                // native translation classify replacement bytes from stale VMA
                // state. A grow without MAYMOVE cannot be placed in situ, which
                // Linux reports as ENOMEM. Musl relies on that distinction while
                // probing the main stack VMA.
                if memory.read_bytes(old_address.0, 1).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // Grow a live MAP_SHARED file alias whose LARGER extent is still
                // entirely inside the file. Linux backs the added pages from the
                // file, so carrick has to as well — and the only way to keep
                // sharing exact is to re-establish the alias over the same fd at
                // the new length. Re-mmapping the same descriptor aliases the
                // same page cache, so unlike a byte copy this preserves
                // coherence with every other mapper.
                //
                // `ltp-mremap01` is this shape. It builds a SPARSE file with
                // lseek+write (which is why a naive read of its `write` calls
                // suggests a 1-byte file), maps 0x3e8000 of it, EXTENDS the file
                // to 0x7d0001, and then grows the mapping to 0x7d0000 — all
                // inside EOF.
                if let Some((file_len, file_offset)) = alias_file_extent
                    && new_size > old_size
                    && flags & LINUX_MREMAP_MAYMOVE != 0
                    && source_metadata.sharing == ProcMapSharing::Shared
                    && shared_aperture_alloc.is_none()
                    && shared_file_bus_offset(file_len, file_offset, new_size, page_size).is_none()
                {
                    let Some(description) =
                        this.shared_file_alias_description(old_address.0, old_size)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let dup_fd = {
                        let open = description.read();
                        match open.as_deref().and_then(OpenDescription::shared_alias_host_fd) {
                            Some(raw_fd) if host_fd_can_back_shared_alias(raw_fd) => {
                                let d = unsafe { libc::dup(raw_fd) };
                                (d >= 0).then_some(d)
                            }
                            _ => None,
                        }
                    };
                    let Some(dup_fd) = dup_fd else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let Some(ipa) = crate::memory::alloc_alias_ipa(new_size) else {
                        unsafe { libc::close(dup_fd) };
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
                    // Same translation as the mmap path: PROT_EXEC is dropped
                    // (the guest executes through its own stage-1/stage-2, and
                    // macOS refuses MAP_SHARED|PROT_EXEC of an ordinary file).
                    let pf = source_metadata.prot;
                    let mut host_prot = 0;
                    if pf.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                        host_prot |= libc::PROT_READ;
                    }
                    if pf.contains(LinuxProtFlags::WRITE) {
                        host_prot |= libc::PROT_WRITE;
                    }
                    // Linux unmaps the source. Reclaim the old alias BEFORE
                    // publishing the new one; the destination IPA is freshly
                    // allocated and never reused, so it cannot collide with the
                    // source, and the ordering keeps `mmap_next`-independent
                    // alias VA bookkeeping single-valued. If the runtime's host
                    // mmap then fails the transaction aborts and the guest has
                    // lost the source mapping, where Linux would have kept it —
                    // a divergence confined to that failure path.
                    // The mprotect(PROT_WRITE) ceiling of a read-only shared
                    // file map moves with the mapping; read it before the
                    // source's metadata is removed.
                    let read_only_shared_file =
                        this.range_is_read_only_shared_file(old_address.0, old_size);
                    if let Ok(old_len) = usize::try_from(old_size)
                        && old_len > 0
                    {
                        let _ = memory.unmap_alias_range(old_address.0, old_len);
                        mark_range_unmapped(memory, old_address.0, old_len);
                        this.remove_mapping_metadata(old_address.0, old_size);
                    }
                    return Ok(publish_shared_file_alias_outcome(
                        host_alias_dispatch,
                        va,
                        ipa,
                        new_size,
                        pf,
                        host_prot,
                        file_offset,
                        source_metadata.file_page_offset,
                        source_metadata.droppable,
                        source_metadata.path.clone(),
                        Some(
                            source_metadata
                                .fork_semantics
                                .project(va, new_size)
                                .unwrap_or_else(|| {
                                    carrick_fatal!(
                                        "dispatch::mremap",
                                        "mremap fork semantics projection failed"
                                    )
                                }),
                        ),
                        None,
                        read_only_shared_file,
                        Arc::clone(&description),
                        dup_fd,
                    ));
                }
                if let Some(bus_start) = shared_file_alias_grow {
                    // Leave the live alias exactly as it is — it IS the shared
                    // page cache, and re-establishing it would be both slower
                    // and a chance to lose coherence — and give the mapping the
                    // unbacked tail Linux gives it. The VA above the alias has
                    // to be free, because nothing is moving.
                    let Some(new_end) = old_address.0.checked_add(new_size) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let old_end = old_address.0.saturating_add(old_size);
                    let tail_occupied = this.mem()
                        .lock()
                        .dynamic_maps
                        .iter()
                        .any(|map| map.start < new_end && map.end > old_end);
                    if tail_occupied {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    // Every page from `bus_start` on is past EOF and must fault
                    // SIGBUS, not read as zeroes. Nothing is mapped there, so
                    // the access takes a translation fault and this record is
                    // what turns the resulting SIGSEGV into the SIGBUS Linux
                    // delivers.
                    this.record_mmap_bus_fault_range(
                        old_address.0.saturating_add(bus_start),
                        new_size.saturating_sub(bus_start),
                    );
                    this.record_remapped_dynamic_mapping(
                        old_address.0,
                        new_size,
                        &source_metadata,
                        );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::returned_ptr(old_address)?);
                }
                if shared_grow_in_place {
                    // Extend the existing aperture allocation rather than
                    // allocating a bigger one and copying: the backing object
                    // must keep its identity so every other mapper (a forked
                    // child, a second mmap of the same object) still sees this
                    // mapping's stores.
                    let claimed = this.mem().lock().shared.grow(old_address.0, new_size);
                    let Some((claim_start, claim_len)) = claimed else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    if claim_len != 0 {
                        // The claimed granules may still hold a previous
                        // owner's bytes, and Linux hands out zeroed pages for
                        // anonymous shared memory. Scrub before anything can
                        // read them. The aperture rounds to the host granule,
                        // so this range is already host-page aligned.
                        let Ok(claim_len_usize) = usize::try_from(claim_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        };
                        if memory
                            .zero_anonymous_reuse(
                                claim_start,
                                claim_len_usize,
                                carrick_guest_mem::MappingSharing::Shared,
                            )
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        if this.mem()
                            .lock()
                            .shared
                            .range_needs_identity_restore(claim_start, claim_len)
                        {
                            if memory
                                .restore_shared_identity(claim_start, claim_len_usize)
                                .is_err()
                            {
                                // The page-table edit may already be live even
                                // when its TLB flush reports failure; recycling
                                // this VA would publish unowned translation.
                                carrick_fatal!(
                                    "dispatch::mremap_shared",
                                    "restore_shared_identity failed during mremap"
                                );
                            }
                            if this.mem()
                                .lock()
                                .shared
                                .mark_identity_restored(claim_start, claim_len)
                                .is_none()
                            {
                                carrick_fatal!(
                                    "dispatch::mremap_shared",
                                    "mark_identity_restored failed during mremap"
                                );
                            }
                        }
                        // The aperture is boot-mapped RW, so the grown tail
                        // needs this mapping's protection published over it
                        // exactly as a fresh MAP_SHARED|MAP_ANON does —
                        // otherwise a store to a read-only mapping's new pages
                        // silently succeeds.
                        let prot_none = source_metadata.prot.is_empty();
                        memory.set_mapping_protection_and_sharing(
                            claim_start,
                            claim_len_usize,
                            prot_none,
                            !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
                            carrick_guest_mem::MappingSharing::Shared,
                        );
                        if memory
                            .protect_range(claim_start, claim_len_usize, source_metadata.prot.bits())
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                    }
                    this.record_remapped_dynamic_mapping(
                        old_address.0,
                        new_size,
                        &source_metadata,
                        );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::returned_ptr(old_address)?);
                }
                if !must_relocate && new_size <= old_size {
                    let tail_start = old_address.0.saturating_add(new_size);
                    let tail_len = old_size.saturating_sub(new_size);
                    if tail_len != 0 {
                        let Ok(tail_len_usize) = usize::try_from(tail_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        };
                        let tracked_shared = shared_aperture_alloc.is_some();
                        let (tracked_overlay, overlay_tail_carvable) = {
                            let mem_authority_21 = this.mem();
                            let mem = mem_authority_21.lock();
                            (
                                mem.overlay.source_range_has_owner(tail_start, tail_len),
                                mem.overlay
                                    .source_range_is_carvable(tail_start, tail_len, None),
                            )
                        };
                        if tracked_overlay && !overlay_tail_carvable {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        let unmap_result = if !tracked_shared
                            && !tracked_overlay
                            && (this.range_is_alias_vma(old_address.0, old_size)
                                 || mmap_address_uses_alias(old_address.0, old_size, layout))
                        {
                            memory.unmap_alias_range(tail_start, tail_len_usize)
                        } else {
                            memory.unmap_range(tail_start, tail_len_usize)
                        };
                        if unmap_result.is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        mark_range_unmapped(memory, tail_start, tail_len_usize);
                        this.remove_mapping_metadata(tail_start, tail_len);
                        if tracked_shared
                            && this.mem()
                                .lock()
                                .shared
                                .shrink(old_address.0, new_size)
                                .is_none()
                        {
                            // The backend tail is already gone. Preflight above
                            // proved this exact shrink valid, so failure here is
                            // an internal ownership/accounting violation.
                            carrick_fatal!(
                                "dispatch::mremap_shared",
                                "shrinking shared aperture allocation in mremap failed"
                            );
                        }
                        if tracked_overlay
                            && this.mem()
                                .lock()
                                .overlay
                                .carve_source_range(tail_start, tail_len, None)
                                .is_none()
                        {
                            // The SOURCE tail is no longer reachable after the
                            // backend unmap. Losing the preflighted overlay carve
                            // would leave reusable storage with stale ownership.
                            carrick_fatal!(
                                "dispatch::mremap_overlay",
                                "carving source overlay range in mremap failed"
                            );
                        }
                    }
                    this.record_remapped_dynamic_mapping(
                        old_address.0,
                        new_size,
                        &source_metadata,
                        );
                    if new_size != old_size {
                        this.mark_vma_dispatch(&mut host_alias_dispatch);
                    }
                    return Ok(DispatchOutcome::returned_ptr(old_address)?);
                }
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !must_relocate && new_size <= old_size {
                // Linux mremap shrink unmaps the freed tail [old+new_size,
                // old+old_size); carrick used to leave it mapped (a leak, and
                // the stale bytes there could later be misread). Reclaim the
                // whole-page tail exactly as munmap does — invalidate stage-1,
                // then lower mmap_next (if it's the high-water) or return it to
                // free_regions (a future mmap reuse zero-fills it).
                let tail_start = old_address.0 + new_size; // new_size is page-aligned ≤ old_size
                let tail_end = old_address
                    .0
                    .checked_add(old_size)
                    .map(|e| page_floor(e, page_size));
                if let Some(tail_end) = tail_end
                    && tail_end > tail_start
                {
                    let tail_len = tail_end - tail_start;
                    let Ok(tl) = usize::try_from(tail_len) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    // Invalidate guest translation first, then publish the
                    // post-unmap VMA state last so backend protection hooks
                    // cannot overwrite it with live PROT_NONE metadata.
                    if memory.unmap_range(tail_start, tl).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    mark_range_unmapped(memory, tail_start, tl);
                    this.remove_mapping_metadata(tail_start, tail_len);
                    let mem_authority_22 = this.mem();
                    let mut mem = mem_authority_22.lock();
                    if tail_end == mem.mmap_next {
                        let mem = &mut *mem;
                        lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, tail_start);
                    } else {
                        free_regions_insert(&mut mem.free_regions, tail_start, tail_len);
                    }
                }
                this.record_remapped_dynamic_mapping(
                    old_address.0,
                    new_size,
                    &source_metadata,
                    );
                if new_size != old_size {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::returned_ptr(old_address)?);
            }

            // A MAP_SHARED file mapping that already ends past its file's EOF,
            // living in the arena as an eager snapshot. `ltp-mremap01` is this
            // shape. The whole growth is past EOF too — nothing to materialize,
            // just VA to reserve and a tail that has to fault SIGBUS — so it is
            // grown in place rather than moved and copied.
            //
            // "Past EOF" is read off the bus records the original mmap
            // published rather than re-derived from a descriptor: an arena
            // snapshot keeps no fd, and the guest may well have closed its own
            // by now. If the mapping's LAST byte already faults SIGBUS then the
            // file ends at or before it, so every added byte is past EOF too.
            if let Some(bus_rel) = shared_arena_grow_past_eof {
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let old_end = old_address.0.saturating_add(old_size);
                let can_extend_in_place = old_end == this.mem().lock().mmap_next
                    && range_within(old_address.0, new_size, layout.mmap_base, layout.mmap_size);
                if !can_extend_in_place {
                    // Something already owns the space directly above, so this
                    // has to MOVE — which is what Linux does here too. Moving a
                    // snapshot is a copy, but only of the bytes that exist: the
                    // region from `bus_rel` on is past EOF and is deliberately
                    // inaccessible, so reading it to copy it would EFAULT.
                    let Some((new_addr, reused)) = this.next_mmap_address(
                        0,
                        new_size,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        0,
                    MmapGrantCongruence::Any,
                ) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let (Ok(new_len), Ok(copy_len)) = (
                        usize::try_from(new_size),
                        usize::try_from(bus_rel.min(old_size)),
                    ) else {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let copied = if copy_len == 0 {
                        Vec::new()
                    } else {
                        match memory.read_bytes_raw(old_address.0, copy_len) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                    };
                    if reused && memory.zero_backing(new_addr, new_len).is_err() {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    memory.set_mapping_protection_and_sharing(
                        new_addr,
                        new_len,
                        false,
                        false,
                        proc_mapping_sharing(source_metadata.sharing),
                    );
                    if memory
                        .protect_range(new_addr, new_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                        .is_err()
                    {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    if !copied.is_empty()
                        && memory.write_bytes_unchecked(new_addr, &copied).is_err()
                    {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    let prot_none = source_metadata.prot.is_empty();
                    memory.set_mapping_protection(
                        new_addr,
                        new_len,
                        prot_none,
                        !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
                    );
                    if memory
                        .protect_range(new_addr, new_len, source_metadata.prot.bits())
                        .is_err()
                    {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    // Re-publish the past-EOF tail at the destination exactly as
                    // `mmap` publishes it: no access, then the bus record that
                    // turns the resulting fault into SIGBUS.
                    let bus_start_abs = new_addr.saturating_add(bus_rel);
                    let bus_len = new_size.saturating_sub(bus_rel);
                    if let Ok(bus_len_usize) = usize::try_from(bus_len)
                        && bus_len_usize != 0
                    {
                        memory.set_no_access(bus_start_abs, bus_len_usize, true);
                        let _ = memory.protect_range(bus_start_abs, bus_len_usize, 0);
                    }
                    this.record_mmap_bus_fault_range(bus_start_abs, bus_len);
                    this.record_remapped_dynamic_mapping(
                        new_addr,
                        new_size,
                        &source_metadata,
                        );
                    // Linux unmaps the source. Reclaim it exactly like munmap so
                    // a later access faults and the VA is reusable.
                    if let Ok(old_len) = usize::try_from(old_size)
                        && old_len > 0
                        && memory.unmap_range(old_address.0, old_len).is_ok()
                    {
                        mark_range_unmapped(memory, old_address.0, old_len);
                        this.remove_mapping_metadata(old_address.0, old_size);
                        let mem_authority_23 = this.mem();
                        let mut mem = mem_authority_23.lock();
                        if old_end == mem.mmap_next {
                            let mem = &mut *mem;
                            lower_mmap_next(
                                &mut mem.mmap_next,
                                &mut mem.free_regions,
                                old_address.0,
                            );
                        } else {
                            free_regions_insert(&mut mem.free_regions, old_address.0, old_size);
                        }
                    }
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::returned_u64(new_addr)?);
                }
                let grow_len_u64 = new_size - old_size;
                // Deliberately NO page-table work: the tail is above the arena
                // bump pointer and so has no stage-1 mapping, which is exactly
                // the state an access has to find. Publishing a PROT_NONE
                // mapping over it instead HUNG the guest (the backend tries to
                // protect backing that was never established), and it would be
                // pointless anyway — reserving the VA and recording the bus
                // range is the whole job.
                {
                    let mem_authority_24 = this.mem();
                    let mut mem = mem_authority_24.lock();
                    mem.mmap_next = new_end;
                }
                this.record_mmap_bus_fault_range(old_end, grow_len_u64);
                this.record_remapped_dynamic_mapping(
                    old_address.0,
                    new_size,
                    &source_metadata,
                    );
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::returned_ptr(old_address)?);
            }
            if !must_relocate
                && old_address.0.checked_add(old_size) == Some(this.mem().lock().mmap_next)
            {
                let Some(old_end) = old_address.0.checked_add(old_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if range_within(old_address.0, new_size, layout.mmap_base, layout.mmap_size) {
                    // Re-validate the freshly-grown tail with the source VMA's
                    // exact protection and sharing. Sharing is published before
                    // execute permission, so an RX shared grow can never appear
                    // transiently private/cacheable to native translation.
                    let grow_len_u64 = new_size - old_size;
                    let Ok(grow_len) = usize::try_from(grow_len_u64) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let prot_none = source_metadata.prot.is_empty();
                    memory.set_mapping_protection_and_sharing(
                        old_end,
                        grow_len,
                        prot_none,
                        !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
                        proc_mapping_sharing(source_metadata.sharing),
                    );
                    if memory
                        .protect_range(old_end, grow_len, source_metadata.prot.bits())
                        .is_err()
                    {
                        mark_range_unmapped(memory, old_end, grow_len);
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    {
                        let mem_authority_25 = this.mem();
                        let mut mem = mem_authority_25.lock();
                        mem.mmap_next = new_end;
                        // The dirty high-water stays monotonic so a later
                        // munmap+rebump cannot expose bytes dirtied in this tail.
                        mem.mmap_writable_high = mem.mmap_writable_high.max(new_end);
                    }
                    this.record_remapped_dynamic_mapping(
                        old_address.0,
                        new_size,
                        &source_metadata,
                        );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::returned_ptr(old_address)?);
                }
            }

            if flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let (new_addr, reused) = if move_fixed {
                // `MREMAP_FIXED` names the destination and REPLACES whatever is
                // there, exactly like `MAP_FIXED` -- Linux unmaps the old
                // occupant rather than failing. The source cannot overlap it
                // (checked above), so reclaiming here cannot touch the bytes
                // about to be copied. Reserve the exact range through the same
                // allocator seam `mmap(MAP_FIXED)` uses, so the free list and
                // bump cursor learn about it; handing out arena VA without
                // telling both is what once let a live mapping be scrubbed.
                if let Ok(dst_len) = usize::try_from(new_size)
                    && dst_len > 0
                {
                    let _ = memory.unmap_range(new_address.0, dst_len);
                    mark_range_unmapped(memory, new_address.0, dst_len);
                    this.remove_mapping_metadata(new_address.0, new_size);
                }
                match this.next_mmap_address(
                    new_address.0,
                    new_size,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_FIXED,
                    MmapGrantCongruence::Any,
                ) {
                    // Treat a fixed destination as reused: it may carry a prior
                    // owner's bytes, and the copy below fills only `copy_len`.
                    Some((granted, _)) => (granted, true),
                    None => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
                }
            } else {
                let Some(granted) = this.next_mmap_address(
                    0,
                    new_size,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    0,
                    MmapGrantCongruence::Any,
                ) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                granted
            };
            let new_len = match usize::try_from(new_size) {
                Ok(n) => n,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
            };
            let copy_len = match usize::try_from(old_size.min(new_size)) {
                Ok(len) => len,
                Err(_) => {
                    this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };
            let copied = if copy_len == 0 {
                Vec::new()
            } else {
                match memory.read_bytes_raw(old_address.0, copy_len) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            if reused && memory.zero_backing(new_addr, new_len).is_err() {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // Publish the destination as non-executable RW while copying, but
            // with its final sharing already installed. This is restrictive for
            // RX sources and prevents a stale executable replacement from being
            // observed as private/cacheable during the move.
            memory.set_mapping_protection_and_sharing(
                new_addr,
                new_len,
                false,
                false,
                proc_mapping_sharing(source_metadata.sharing),
            );
            if memory
                .protect_range(new_addr, new_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !copied.is_empty()
                && memory
                    .write_bytes_unchecked(new_addr, &copied)
                    .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let prot_none = source_metadata.prot.is_empty();
            memory.set_mapping_protection(
                new_addr,
                new_len,
                prot_none,
                !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
            );
            if memory
                .protect_range(new_addr, new_len, source_metadata.prot.bits())
                .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            this.record_remapped_dynamic_mapping(
                new_addr,
                new_size,
                &source_metadata,
                );
            // mremap MOVE on Linux UNMAPS the source [old, old+old_size) (unless
            // MREMAP_DONTUNMAP — refused above, so never true here: this handler
            // always reclaims the source). carrick previously LEAKED it: the
            // source VA stayed mapped with its stale bytes and was never
            // returned to the allocator, so `mmap_next` ran away and glibc's
            // view of which VAs are mapped diverged from carrick's (glibc
            // considers the source freed). Reclaim the source exactly like
            // munmap, so a later access faults and the VA is reusable —
            // matching Linux and keeping the mmapped-chunk bookkeeping
            // coherent across the BytesIO/recv_bytes realloc-grow cascade
            // (test_multiprocessing test_connection's 16 MiB round-trip).
            // Guard: the destination must not overlap the source (it never does —
            // `new_addr` is freshly bump-allocated or a disjoint free region —
            // but reclaiming an overlapping source would unmap the live copy).
            let dst_overlaps_src = new_addr < old_address.0.wrapping_add(old_size)
                && old_address.0 < new_addr.wrapping_add(new_size);
            if dontunmap {
                // `MREMAP_DONTUNMAP` keeps the source MAPPED, as fresh
                // zero-filled anonymous memory: the pages move to the
                // destination and the old address reads back zero rather than
                // faulting. carrick copies instead of re-pointing page tables,
                // so zeroing the source produces the same guest-visible result
                // -- the destination holds the bytes, the source reads zero,
                // and the VMA and its allocator bookkeeping stay exactly as
                // they were.
                if let Ok(old_len) = usize::try_from(old_size)
                    && old_len > 0
                    && memory.zero_backing(old_address.0, old_len).is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            } else if !dst_overlaps_src
                && let Ok(old_len) = usize::try_from(old_size)
                    && old_len > 0
                {
                    if let Err(first) = memory.unmap_range(old_address.0, old_len)
                        && let Err(retry) = memory.unmap_range(old_address.0, old_len)
                    {
                        // The destination is already published; returning would
                        // expose two owners while reporting failure. Retain
                        // fail-stop semantics so host teardown reclaims both --
                        // but SAY WHY. This aborted with no output at all, so
                        // locating it needed a 7.5 GiB core; an abort that
                        // prints nothing is indistinguishable from a crash.
                        eprintln!(
                            "carrick: FATAL: mremap MOVE published                              0x{new_addr:x}+0x{new_size:x} but could not reclaim source                              0x{:x}+0x{old_len:x}: {first}; retry: {retry}",
                            old_address.0
                        );
                        carrick_fatal!(
                            "dispatch::mremap",
                            "mremap move could not reclaim source address range"
                        );
                    }
                    mark_range_unmapped(memory, old_address.0, old_len);
                    this.remove_mapping_metadata(old_address.0, old_size);
                    let mem_authority_26 = this.mem();
                    let mut mem = mem_authority_26.lock();
                    if old_address.0.checked_add(old_size) == Some(mem.mmap_next) {
                        let mem = &mut *mem;
                        lower_mmap_next(
                            &mut mem.mmap_next,
                            &mut mem.free_regions,
                            old_address.0,
                        );
                    } else {
                        free_regions_insert(&mut mem.free_regions, old_address.0, old_size);
                    }
                }
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::returned_u64(new_addr)?)
        }

        mm_mutation fn mprotect(this, cx, address: GuestPtr, length: u64, prot: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch(&permit);
            let page_size = this.linux_page_size();
            if prot & !LinuxProtFlags::SUPPORTED_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let prot_flags = LinuxProtFlags::from_bits_retain(prot);
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(length) = align_up_u64(length, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Ok(len) = usize::try_from(length) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Linux mprotect returns ENOMEM when the range covers unmapped VA
            // (a hole in the address space). carrick previously SUCCEEDED on any
            // page-aligned address regardless of whether it was mapped (LTP
            // mprotect01's "call succeeded unexpectedly" — it mprotects an
            // unmapped page at addr=NULL and asserts ENOMEM). Probe the start
            // page with the BACKING-ONLY read (`read_bytes_raw`), NOT the
            // PROT_NONE-gated `read_bytes`: a legitimately-mapped region the guest
            // already mprotect'd to PROT_NONE (glibc/Go/jemalloc guard pages —
            // the dominant re-mprotect pattern) is no_access, so the gated read
            // would FALSELY report it unmapped and ENOMEM the common case.
            // `read_bytes_raw` catches an address with no backing (e.g. NULL),
            // while the explicit unmapped set catches retained arena backing
            // after munmap across the whole rounded range. Probe BEFORE changing
            // protection metadata so a hole cannot be resurrected as a VMA.
            let metadata_says_unmapped = cx
                .memory
                .protections()
                .is_some_and(|p| p.range_unmapped(address.0, len));
            let layout = this.mem().lock().layout;
            let address_is_alias_vma = this.range_is_alias_vma(address.0, length)
                || mmap_address_uses_alias(address.0, length, layout);
            // Complete VMA metadata answers whether the Linux address range is
            // mapped; it does NOT answer whether a deliberately-lazy anonymous
            // high-VA reservation has acquired physical alias backing. The
            // dispatcher's committed-alias inventory is authoritative for that
            // second fact: a raw host-pointer read can succeed through a stale
            // post-unmap view even after this mm's stage-1/stage-2 translations
            // were retired. Only a successful host-alias transaction publishes
            // the range, and unmap/replacement trims it with the VMA metadata.
            let lazy_alias_reservation = (!metadata_says_unmapped
                && !prot_flags.is_empty()
                && address_is_alias_vma
                && !this.range_has_host_alias_backing(address.0, length))
            .then(|| this.mremap_mapping_metadata(cx.memory, address.0, length).ok())
            .flatten();
            // A committed kernel VMA can deliberately precede physical
            // backing: HVPatch's low sparse arena and the existing high-alias
            // reservation both materialize on the first accessible
            // protection. Raw backing is therefore only a hole oracle when
            // neither complete backend metadata nor committed VMA metadata
            // covers the request. Explicit post-munmap state still wins above.
            let committed_vma_covers_range =
                guest_vma_covers_locked(&this.mem().lock(), address.0, length);
            let incomplete_backend_says_unmapped = !committed_vma_covers_range
                && !cx.memory.has_complete_mapping_metadata()
                && cx.memory.read_bytes_raw(address.0, 1).is_err();
            if metadata_says_unmapped
                || lazy_alias_reservation.is_some()
                || incomplete_backend_says_unmapped
            {
                // LAZY ALIAS COMMIT. An anonymous PROT_NONE reservation in the
                // alias window is deliberately given no backing at `mmap` time
                // — it is address space, not memory, and eagerly aliasing every
                // reservation exhausts the 64 GiB alias IPA arena, which is
                // never reused because arm64 HVF cannot flush stage-2 TLB.
                // (Measured: eagerly aliasing them breaks `go build` with a
                // child stage-1 VA→IPA mismatch.)
                //
                // So the backing is installed HERE, when the guest actually
                // commits part of the reservation — which is what `mprotect`
                // means. Only the committed subrange costs IPA. This is V8's
                // `AllocateAlignedMemory` shape, and without it Node.js 22 dies
                // in startup-snapshot deserialization: carrick's backing probe
                // sees no backing, reads that as "no mapping", and answers
                // ENOMEM where Linux commits and returns 0.
                //
                // `metadata_says_unmapped` still wins: a range explicitly
                // munmapped is a real hole, and NULL and genuine holes keep
                // answering ENOMEM (LTP mprotect01).
                if !metadata_says_unmapped
                    && !prot_flags.is_empty()
                    && address_is_alias_vma
                    && let Some(ipa) = alloc_alias_ipa_for_publication(length, true)
                {
                    // The reservation's VMA is the source of truth. `mprotect`
                    // replaces only its committed subrange; it must not
                    // manufacture MAP_PRIVATE metadata for a MAP_SHARED
                    // anonymous reservation merely because the backing is being
                    // created late.
                    let Some(reservation) = lazy_alias_reservation.or_else(|| {
                        this.mremap_mapping_metadata(cx.memory, address.0, length)
                            .ok()
                    }) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let shared = reservation.sharing == ProcMapSharing::Shared;
                    let transaction = host_alias_dispatch
                        .publish(HostAliasCommit::mmap(HostAliasMmapCommit {
                            start: address.0,
                            len: length,
                            prot: prot_flags,
                            sharing: reservation.sharing,
                            path: reservation.path,
                            file_page_offset: reservation.file_page_offset,
                            droppable: reservation.droppable,
                            semantic_vmas: Some(
                                reservation
                                    .fork_semantics
                                    .project(address.0, length)
                                    .unwrap_or_else(|| {
                                        carrick_fatal!(
                                            "dispatch::mprotect",
                                            "mprotect reservation fork semantics projection failed"
                                        )
                                    }),
                            ),
                            locked: None,
                            resident: false,
                            bus_fault: None,
                            write_sealed_shared: false,
                            read_only_shared_file: false,
                            secretmem: false,
                            writable_memfd: None,
                            private_file: None,
                            shared_file_alias: None,
                        }))
                        .map_err(|_| DispatchError::Errno(linux_errno::ENOMEM))?;
                    return Ok(DispatchOutcome::MapHostAlias {
                        // mprotect answers 0, not the address.
                        success_retval: 0,
                        transaction,
                        va: GuestVa(address.0),
                        ipa: Gpa(ipa),
                        len: length,
                        payload: Vec::new(),
                        backing: HostAliasBacking::Anonymous {
                            sharing: if shared {
                                HostAliasSharing::Shared
                            } else {
                                HostAliasSharing::Private
                            },
                        },
                        prot,
                        prot_none: false,
                    });
                }
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A shared mapping of a F_SEAL_WRITE memfd cannot be upgraded to
            // writable (memfd_create01 check_mfd_non_writeable).
            if prot & LINUX_PROT_WRITE != 0 && this.range_is_write_sealed_shared(address.0, length) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // A MAP_SHARED mapping of a read-only file cannot be upgraded to
            // writable: its stores would have to reach a file the process never
            // opened for writing (mprotect(2) EACCES; LTP mprotect01 case 3,
            // which carrick used to answer with success).
            if prot & LINUX_PROT_WRITE != 0
                && this.range_is_read_only_shared_file(address.0, length)
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }
            let layout = this.mem().lock().layout;
            if prot_flags.contains(LinuxProtFlags::EXEC)
                && let Some(reason) =
                    this.native16k_exec_transition_rejection(cx.memory, cx.thread)
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mprotect",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                && let Some(reason) = this.native16k_write_exec_rejection(
                    cx.memory,
                    cx.thread,
                    this.range_intersects_shared_mapping(address.0, length),
                    address_is_alias_vma,
                )
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mprotect",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            // Preserve file-hole identity across the permission transition.
            // Linux mprotect changes VMA permissions but never turns a page
            // wholly beyond the mapped file's map-time EOF into zero backing.
            // Snapshot before any backend edit; the protection registry keeps
            // this backing classification independent of R/W/X permission.
            let bus_faults = cx
                .memory
                .protections()
                .map(|protections| protections.bus_fault_intersections(address.0, len))
                .unwrap_or_default();

            // Make the new protection guest-VISIBLE (a violating access
            // faults during EL0 execution) by editing the stage-1/PML4
            // page tables. In the private mmap arena a failed edit is
            // fatal (eager backends must succeed there). The identity
            // image/heap/interpreter ranges are edited BEST-EFFORT: the
            // ELF loader now boots .text/.rodata read-only, so a guest
            // mprotect there (ld.so RELRO, a test unprotecting .rodata)
            // must actually flip the leaves — but a hole inside the
            // range (unmapped identity VA on x86) degrades to the
            // historical host-side-only behaviour instead of failing.
            // Unbacked shared/overlay apertures keep host-side checks only.
            // A committed high-VA alias has a live stage-1 translation, so its
            // protection must be edited just like the mmap arena below.
            if range_within(address.0, length, layout.mmap_base, layout.mmap_size) {
                if let Err(error) = cx.memory.protect_range(address.0, len, prot) {
                    tracing::error!(
                        address = address.0,
                        length,
                        prot,
                        %error,
                        "mprotect failed to publish mmap-arena protection"
                    );
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                // THE SECOND MARK POINT. `mmap` is the first: together they are
                // the only two ways an arena range becomes guest-writable, and
                // the watermark is only sound because BOTH raise it. A
                // `PROT_NONE` reserve that is later committed RW here must push
                // the watermark past itself, or a post-`munmap` bump could hand
                // those written pages back unscrubbed. See
                // `mmap_writable_high`.
                if prot_flags.contains(LinuxProtFlags::WRITE)
                    && let Some(end) = address.0.checked_add(length)
                {
                    let mem_authority_27 = this.mem();
                    let mut mem = mem_authority_27.lock();
                    mem.mmap_writable_high = mem.mmap_writable_high.max(end);
                }
                if let Err(error) = this.rearm_first_touch_after_mprotect(
                    cx.memory,
                    address.0,
                    length,
                    prot_flags,
                ) {
                    tracing::error!(
                        address = address.0,
                        length,
                        prot,
                        %error,
                        "mprotect failed to re-arm first-touch residency"
                    );
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            } else if mprotect_range_in_identity_image(address.0, length, layout) {
                if cx.memory.protect_range(address.0, len, prot).is_err()
                    && this.page_geometry.native_profile
                        == Some(carrick_spec::NativePageProfile::Native16k)
                {
                    cx.reporter.record(CompatEvent::partial_syscall(
                        cx.number(),
                        "mprotect",
                        cx.raw_args(),
                        "native16k backend protection failure",
                    ));
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            } else if (this.range_has_host_alias_backing(address.0, length)
                || cx.memory.supports_concurrent_exec_protection())
                && cx.memory.protect_range(address.0, len, prot).is_err()
            {
                // HVPatch reaches this branch under the syscall's stage-1
                // exclusivity/pause; DSR-backed native aliases use their
                // concurrent host-mapping path. Either backend must fail the
                // syscall when it cannot publish the guest-visible permission.
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A backend protection call above may have made the whole VMA
            // accessible. Re-apply the physical hole before publishing the new
            // permission metadata, including on legacy shared/overlay aliases
            // whose ordinary mprotect path is host-side-only.
            for (bus_start, bus_end) in bus_faults {
                let Ok(bus_len) = usize::try_from(bus_end - bus_start) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if cx.memory.protect_range(bus_start, bus_len, 0).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }
            let prot_none = LinuxProtFlags::from_bits_truncate(prot).is_empty();
            cx.memory.set_mapping_protection(
                address.0,
                len,
                prot_none,
                !prot_none && prot & LINUX_PROT_WRITE == 0,
            );
            this.update_dynamic_mapping_prot(address.0, length, prot_flags);
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        mm_mutation fn remap_file_pages(this, cx, addr: u64, size: u64, prot: u64, pgoff: u64, _flags: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let _host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            if addr == 0 || size == 0 || prot != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(end) = addr.checked_add(size) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            match this.note_sysv_remap_file_pages(addr, end) {
                Ok(true) => return Ok(DispatchOutcome::Returned { value: 0 }),
                Ok(false) => {}
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
            let shared_map = {
                this.mem()
                    .lock()
                    .dynamic_maps
                    .iter()
                    .find(|map| map.sharing == ProcMapSharing::Shared && addr >= map.start && end <= map.end)
                    .cloned()
            };
            if let Some(map) = shared_map {
                let map_len = map.end.saturating_sub(map.start);
                let snapshot = {
                    let mem_authority_28 = this.mem();
                    let mut mem = mem_authority_28.lock();
                    if let Some(snapshot) = mem.remap_snapshots.get(&map.start) {
                        snapshot.clone()
                    } else {
                        let Ok(map_len_usize) = usize::try_from(map_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        };
                        let Ok(bytes) = cx.memory.read_bytes(map.start, map_len_usize) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        mem.remap_snapshots.insert(map.start, bytes.clone());
                        bytes
                    }
                };
                let source_offset = match pgoff
                    .checked_mul(this.linux_page_size())
                    .and_then(|off| usize::try_from(off).ok())
                {
                    Some(off) => off,
                    None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                };
                let size_usize = match usize::try_from(size) {
                    Ok(size) => size,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                };
                let Some(source_end) = source_offset.checked_add(size_usize) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let Some(bytes) = snapshot.get(source_offset..source_end) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if cx.memory.write_bytes(addr, bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // Linux rejects remap_file_pages for addresses that are not in a
            // MAP_SHARED mapping; carrick does not emulate nonlinear remapping, so
            // the valid no-op path is limited to ranges that already identify one.
            Ok(DispatchOutcome::errno(LINUX_EINVAL))
        }
    }
}

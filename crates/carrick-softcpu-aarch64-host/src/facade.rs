//! Soft AArch64 VMM + vCPU facade (`Aarch64Vmm` + `Aarch64Vcpu`) over
//! [`carrick_softcpu_aarch64`] and [`carrick_softmmu::ExtentTable`].
//!
//! `SoftAarch64Engine<X>` is a type alias to
//! `carrick_aarch64::Aarch64EngineCore<SoftAarch64Vmm<X>>`, reusing the one
//! shared AArch64 trap/stage-1/guest-memory engine (`ONE LANE`) with stage-2
//! GPA translation, execute-permission enforcement, extent-backed code-page
//! generation tracking, and `HVC #2` `Aarch64SyscallMailbox` transport.

use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use carrick_aarch64::esr::decode_el0_sys64_read;
use carrick_aarch64::mailbox::{
    AARCH64_SYSCALL_MAILBOX_SIZE, Aarch64SyscallMailbox, HvcImmediateKind, MailboxSlot,
    classify_hvc_immediate,
};
use carrick_aarch64::staged_cpu::{RootBootFields, StagedCpu};
use carrick_aarch64::user_transfer::{
    ErasedPhysicalCustody, ErasedTransferCustody, RetainedCopy, TransferBytes, TransferCustody,
    TransferPin, TransferPreparation, TransferTarget,
};
use carrick_aarch64::{
    Aarch64EngineCore, Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy,
};
use carrick_core::mm::own::{
    BackendResult, CarrierCore, CarrierId, CoreVenue, GenerationId, GpaExtent, Holding,
    MappingSpec, Pin as CorePin, PinRefusal, Retire,
};
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_SIZE, EL1_IPC_BASE, EL1_IPC_POOL_BASE,
    EL1_REGION_BASE, EL1_REGION_SIZE, EL1_STACK_GUARD_TABLES_BASE, IpcWindowBacking,
    MetadataResolutionError, is_el1_stack_guard,
};
use carrick_guest_arch::FrameGpa;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{
    Gpa, GuestVa, HostVa, LegacyProtectionRead, MemoryError, SharedFutexLocation,
    UserMemoryAuthority, zero_range_chunked,
};
use carrick_hal::retained_metadata::{
    RetainedMetadataBacking, RetainedMetadataExtent, RetainedMetadataMapper,
};
use carrick_hal::{
    FrameInventoryCommit, FrameInventoryEvent, FrameInventoryReservation, FrameLength,
    GenericVcpuRegistry, GuestEntryRegs, GuestVmBackend, HostAliasBacking, HostAliasSharing,
    MappingGeneration, MemPerms, OsError, Reg, SysReg, TrapError, VcpuKick, VcpuRegistry,
};
use carrick_mem::memory::{
    AddressSpace, CarrierMaintenanceRoot, LINUX_CARRIER_MAINT_ROOT_BASE, LINUX_EL1_IMAGE_SIZE,
    LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE, LINUX_FD_CEILING_CONTROL_BASE,
    LINUX_FD_CEILING_CONTROL_SIZE, LINUX_SYSCALL_MAILBOX_BASE, el1_stack_guard_tables,
    stage1_carrier_maintenance_page_tables,
};
use carrick_mmu_core::aarch64::PageTableError;
use carrick_softcpu_aarch64::dispatch::{
    AARCH64_RESIDENCY, DispatchCache, ExecuteBlock, RunControl, RunWork, Stop, run_controlled,
};
use carrick_softcpu_aarch64::exception::Syndrome;
use carrick_softcpu_aarch64::handler::{
    CodeGeneration, Event, ExclusiveMonitor, GuestMemory as SoftGuestMemory, InlineRam, MemoryFault,
};
use carrick_softcpu_aarch64::state::{
    CounterSource, CpuState, ProgramCounter, Pstate, RegisterValue, SavedPstate, Sctlr,
    StackPointer, SystemValue, VirtualAddress,
};
use carrick_softcpu_aarch64::translate::BlockLimits;
use carrick_softcpu_aarch64::{Gpr, Hint, OperandRegister};
use carrick_softmmu::block_cache::{ResidencyBudget, ResidencyCensus};
use carrick_softmmu::{ExtentRecord, ExtentTable, OwnerGeneration, PAGE_SIZE_4K};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::HostBlockRunner;

/// Architectural guest page granule (4 KiB) decoupled from host mmap backing.
pub const GUEST_PAGE_BYTES: u64 = PAGE_SIZE_4K;
const PAGE_BYTES_USIZE: usize = GUEST_PAGE_BYTES as usize;
const OWNER: OwnerGeneration = OwnerGeneration::FIRST;

/// Stage-2 GPA cursor for dynamic `MapHostAlias` installations (`< 1 TiB` 40-bit IPA).
pub const SOFT_ALIAS_GPA_BASE: u64 = 0x30_0000_0000;
const SOFT_ALIAS_GPA_LIMIT: u64 = 0xFF_0000_0000;

/// Default soft-CPU block slice per `run_controlled` poll and total slice cap per exit.
const DEFAULT_BLOCK_QUANTUM: u64 = 250_000;
const DEFAULT_MAX_QUANTA_PER_EXIT: u64 = 400;
/// The virtual counter counts nanoseconds since the vCPU's boot, so a
/// counter value is directly a host duration from it.
const DEFAULT_CNTFRQ_HZ: u64 = 1_000_000_000;
const MPIDR_AFF0_RES1: u64 = 0x8000_0000;
const _: () = assert!(
    carrick_softcpu_aarch64::gic::VIRTUAL_TIMER_INTID == carrick_el1_abi::GIC_VTIMER_INTID,
    "the soft CPU's timer PPI is the one Carrick's EL1 acknowledges"
);

/// The soft carrier's physical count: nanoseconds since one process epoch.
/// A vCPU's virtual count is this less its boot count, so the guest
/// programs, compares and is interrupted against one live count, and a
/// host deadline converts it back to an instant.
fn soft_physical_count() -> u64 {
    u64::try_from(soft_counter_epoch().elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn soft_counter_epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

#[cfg(target_os = "linux")]
const MAP_NORESERVE_OPT: libc::c_int = libc::MAP_NORESERVE;
#[cfg(not(target_os = "linux"))]
const MAP_NORESERVE_OPT: libc::c_int = 0;

/// Separation between 4 KiB logical guest pages and the host kernel's mmap page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingGeometry {
    pub guest_page_bytes: u64,
    pub host_backing_granule: u64,
}

impl MappingGeometry {
    #[must_use]
    pub fn probe() -> Self {
        // SAFETY: `sysconf(_SC_PAGESIZE)` is thread-safe and reads process configuration.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let host = u64::try_from(raw)
            .ok()
            .filter(|v| *v >= GUEST_PAGE_BYTES && v.is_power_of_two())
            .unwrap_or(GUEST_PAGE_BYTES);
        Self {
            guest_page_bytes: GUEST_PAGE_BYTES,
            host_backing_granule: host,
        }
    }

    #[must_use]
    pub const fn align_up_guest(&self, len: u64) -> Option<u64> {
        let mask = self.guest_page_bytes - 1;
        match len.checked_add(mask) {
            Some(v) => Some(v & !mask),
            None => None,
        }
    }

    #[must_use]
    pub const fn align_up_host(&self, len: u64) -> Option<u64> {
        let mask = self.host_backing_granule - 1;
        match len.checked_add(mask) {
            Some(v) => Some(v & !mask),
            None => None,
        }
    }
}

impl Default for MappingGeometry {
    fn default() -> Self {
        Self::probe()
    }
}

/// Access class that triggered a stage-2 GPA refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2AbortAccess {
    Read,
    Write,
    Fetch,
}

/// Why a stage-2 GPA access was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2AbortReason {
    Unmapped,
    PermissionDenied,
}

/// Typed stage-2 GPA abort diagnostic recorded on refused guest physical access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2Abort {
    pub gpa: u64,
    pub access: Stage2AbortAccess,
    pub reason: Stage2AbortReason,
}

enum WindowBacking {
    OwnedMmap {
        base: NonNull<u8>,
        mapped_len: usize,
    },
    External,
}

impl Drop for WindowBacking {
    fn drop(&mut self) {
        if let Self::OwnedMmap { base, mapped_len } = *self
            && mapped_len > 0
        {
            // SAFETY: `base` and `mapped_len` came from a successful `libc::mmap` owned
            // exclusively by this `WindowBacking`.
            unsafe {
                let _ = libc::munmap(base.as_ptr().cast(), mapped_len);
            }
        }
    }
}

/// What one soft stage-2 window's backend mapping owns in the carrier core:
/// its host backing and its default permissions. The core keeps it until
/// the window's unmap or the carrier's destroy, so the host memory outlives
/// every pin taken inside it.
struct WindowHost {
    default_perms: MemPerms,
    shared: bool,
    _backing: WindowBacking,
}

// SAFETY: `WindowHost` owns an isolated `mmap` or caller-pinned shared window
// accessed only through `ExclusiveStage2`'s Acquire/Release borrow guard.
unsafe impl Send for WindowHost {}

/// A copy of one installed window's geometry, read from the core.
#[derive(Clone, Copy)]
struct Stage2Window {
    start: u64,
    end: u64,
    host: NonNull<u8>,
    default_perms: MemPerms,
    shared: bool,
}

/// The soft carrier's one answer to a broken invariant of its records: a
/// core dropped holding something, a ticket the core refused at once, or a
/// pin outliving its window. It ends the carrier (`carrick_fatal`).
#[cold]
fn soft_carrier_broken(what: core::fmt::Arguments<'_>) -> ! {
    carrick_fatal::carrick_fatal!("softcpu::carrier_core", "{what}")
}

/// The soft carrier's venue: a core dropped holding a mapping or a pin is a
/// broken invariant, and ends the carrier.
enum SoftCoreVenue {}

impl CoreVenue for SoftCoreVenue {
    fn dropped_holding(holding: Holding) -> ! {
        soft_carrier_broken(format_args!(
            "soft carrier core dropped holding {holding:?}"
        ))
    }
}

/// The soft carrier's records: every window is one backend mapping with one
/// frame extent carved over it, so a transfer pins the core's extent.
type SoftCore = CarrierCore<SoftCoreVenue, WindowHost, ()>;

/// A carrier identity no other live soft core holds.
fn next_soft_carrier() -> CarrierId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let raw = NEXT.fetch_add(1, Ordering::Relaxed);
    let raw = NonZeroU64::new(raw)
        .unwrap_or_else(|| soft_carrier_broken(format_args!("soft carrier identities wrapped")));
    // SAFETY: a process-wide monotonic counter, never reused.
    unsafe { CarrierId::assume_unique(raw) }
}

/// Stage-2 GPA translation, permission enforcement, and `ExtentTable` code-page
/// generation authority for the soft AArch64 VMM.
pub struct SoftStage2 {
    geometry: MappingGeometry,
    extents: ExtentTable,
    core: SoftCore,
    page_perms: BTreeMap<u64, MemPerms>,
    last_abort: Option<Stage2Abort>,
    _ipc_pin: Option<Arc<dyn IpcWindowBacking>>,
    /// Carrier custody of retained EL1 metadata mapped by
    /// [`SoftStage2::map_retained_metadata`], keyed by its aperture GPA. A
    /// backing leaves only with its successful unmap, or with this carrier.
    retained_metadata: BTreeMap<u64, Arc<dyn RetainedMetadataBacking>>,
}

impl Drop for SoftStage2 {
    /// End the carrier's generation through the core: every window's host
    /// backing comes back and drops here, before the retained metadata and
    /// IPC backings the external windows borrow. A transfer pin still held
    /// leaves a terminal extent, and the core's drop check ends the carrier.
    fn drop(&mut self) {
        let Ok((ticket, _destroy)) = self.core.begin_destroy() else {
            return;
        };
        match self.core.finish_destroy(ticket, BackendResult::Done) {
            Ok(destroyed) => drop(destroyed),
            Err(refused) => soft_carrier_broken(format_args!(
                "soft destroy ticket refused at once: {:?}",
                refused.reason
            )),
        }
    }
}

impl SoftStage2 {
    pub fn new() -> Result<Self, TrapError> {
        let extents = ExtentTable::new()
            .map_err(|e| TrapError::Hypervisor(format!("soft stage-2 extent table: {e:?}")))?;
        let mut core = SoftCore::new(next_soft_carrier());
        // The soft VM has no backend object to create: its generation is live
        // from the start, and ends with this stage 2.
        core.create()
            .and_then(|_| core.commit_create())
            .map_err(|e| TrapError::Hypervisor(format!("soft carrier generation: {e:?}")))?;
        Ok(Self {
            geometry: MappingGeometry::probe(),
            extents,
            core,
            page_perms: BTreeMap::new(),
            last_abort: None,
            _ipc_pin: None,
            retained_metadata: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn geometry(&self) -> MappingGeometry {
        self.geometry
    }

    #[must_use]
    pub const fn last_abort(&self) -> Option<Stage2Abort> {
        self.last_abort
    }

    pub fn retain_ipc_backing(&mut self, ipc: Arc<dyn IpcWindowBacking>) {
        self._ipc_pin = Some(ipc);
    }

    /// Map retained ABI storage read/write, never executable, at the lowest
    /// free range of the EL1-only dynamic metadata aperture, without copying
    /// it. This carrier keeps `backing` until the exact mapping retires.
    pub fn map_retained_metadata(
        &mut self,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<u64, MetadataResolutionError> {
        let len = u64::try_from(backing.mapped_len())
            .map_err(|_| MetadataResolutionError::InvalidExtent)?;
        let host = NonNull::new(backing.host_base().raw() as *mut u8)
            .ok_or(MetadataResolutionError::InvalidExtent)?;
        if len == 0
            || len > EL1_DYNAMIC_METADATA_SIZE
            || !len.is_multiple_of(GUEST_PAGE_BYTES)
            || !(host.as_ptr() as usize).is_multiple_of(PAGE_BYTES_USIZE)
        {
            return Err(MetadataResolutionError::InvalidExtent);
        }
        let gpa = self
            .allocate_free_gpa(
                EL1_DYNAMIC_METADATA_BASE,
                EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE,
                len,
            )
            .ok_or(MetadataResolutionError::Busy)?;
        let rw = MemPerms {
            read: true,
            write: true,
            exec: false,
        };
        // SAFETY: `retained_metadata` keeps `backing`, and with it the range,
        // until `retire_retained_metadata` unmaps this exact window or the
        // carrier drops.
        unsafe { self.map_external_stage2(gpa, host, len, rw, true) }
            .map_err(|_| MetadataResolutionError::Busy)?;
        self.retained_metadata.insert(gpa, backing);
        Ok(gpa)
    }

    /// Whether the retained mapping at `gpa` is still this carrier's.
    #[must_use]
    pub fn retains_metadata_at(&self, gpa: u64) -> bool {
        self.retained_metadata.contains_key(&gpa)
    }

    /// Unmap the retained mapping at `gpa`, then release its backing.
    pub fn retire_retained_metadata(&mut self, gpa: u64) -> Result<(), TrapError> {
        let backing = self.retained_metadata.get(&gpa).ok_or_else(|| {
            TrapError::Hypervisor(format!("no retained metadata mapping at {gpa:#x}"))
        })?;
        let len = u64::try_from(backing.mapped_len())
            .map_err(|_| TrapError::Hypervisor("retained metadata length overflow".to_owned()))?;
        self.unmap_stage2(gpa, len)?;
        self.retained_metadata.remove(&gpa);
        Ok(())
    }

    fn window_for_range(&self, gpa: u64, len: usize) -> Option<Stage2Window> {
        let end = gpa.checked_add(u64::try_from(len).ok()?)?;
        let view = self.core.installed_at_or_below(gpa)?;
        let window = Stage2Window {
            start: view.extent.ipa(),
            end: view.extent.end(),
            host: NonNull::new(view.host_addr as *mut u8)?,
            default_perms: view.host.default_perms,
            shared: view.host.shared,
        };
        if len == 0 {
            (gpa <= window.end).then_some(window)
        } else {
            (end <= window.end).then_some(window)
        }
    }

    fn perms_for_frame(&self, window: Stage2Window, frame_gpa: u64) -> MemPerms {
        self.page_perms
            .get(&frame_gpa)
            .copied()
            .unwrap_or(window.default_perms)
    }

    fn checked_window_extent(start: u64, end: u64) -> Result<GpaExtent, TrapError> {
        if !start.is_multiple_of(GUEST_PAGE_BYTES)
            || !end.is_multiple_of(GUEST_PAGE_BYTES)
            || end <= start
        {
            return Err(TrapError::Hypervisor(format!(
                "unaligned or empty stage-2 range {start:#x}..{end:#x}"
            )));
        }
        GpaExtent::new(start, end - start).ok_or_else(|| {
            TrapError::Hypervisor(format!("stage-2 range {start:#x}..{end:#x} overflows"))
        })
    }

    /// Install one window in the carrier core: reserve its extent, map it
    /// (the soft backend's map is the record itself, so it completes at
    /// once), and carve one frame extent over it for transfer pins. A
    /// refusal hands the host backing back, so a failed install unmaps it.
    fn install_window(
        &mut self,
        extent: GpaExtent,
        host: NonNull<u8>,
        window: WindowHost,
    ) -> Result<(), TrapError> {
        let spec = MappingSpec {
            extent,
            host_addr: host.as_ptr() as usize,
            host: window,
        };
        let (ticket, _map) = self.core.begin_map(spec).map_err(|refused| {
            TrapError::Hypervisor(format!(
                "soft stage-2 window {:#x}..{:#x} refused: {:?}",
                extent.ipa(),
                extent.end(),
                refused.reason
            ))
        })?;
        if let Err(refused) = self.core.finish_map(ticket, BackendResult::Done) {
            soft_carrier_broken(format_args!(
                "soft map ticket refused at once: {:?}",
                refused.reason
            ));
        }
        if let Err(refused) = self.core.carve(extent, ()) {
            soft_carrier_broken(format_args!(
                "soft window {:#x} could not carve its own extent: {:?}",
                extent.ipa(),
                refused.reason
            ));
        }
        Ok(())
    }

    /// Find the lowest unmapped 4 KiB-aligned GPA range of size `len` within
    /// `[min_gpa, limit_gpa)`.
    #[must_use]
    pub fn allocate_free_gpa(&self, min_gpa: u64, limit_gpa: u64, len: u64) -> Option<u64> {
        let len = self.geometry.align_up_guest(len).filter(|v| *v > 0)?;
        let mut cursor = self.geometry.align_up_guest(min_gpa)?;
        for window in self.core.reserved_extents() {
            if window.end() <= cursor {
                continue;
            }
            if cursor
                .checked_add(len)
                .is_some_and(|end| end <= window.ipa() && end <= limit_gpa)
            {
                return Some(cursor);
            }
            cursor = self.geometry.align_up_guest(window.end())?;
            if cursor >= limit_gpa {
                return None;
            }
        }
        cursor
            .checked_add(len)
            .filter(|end| *end <= limit_gpa)
            .map(|_| cursor)
    }

    /// Allocate and map a demand-paged anonymous stage-2 window `[gpa, gpa + len)`.
    pub fn map_owned_anonymous(
        &mut self,
        gpa: u64,
        len: u64,
        perms: MemPerms,
        shared: bool,
    ) -> Result<NonNull<u8>, TrapError> {
        let guest_len = self
            .geometry
            .align_up_guest(len)
            .filter(|v| *v > 0)
            .ok_or_else(|| TrapError::Hypervisor(format!("invalid stage-2 length {len:#x}")))?;
        let end = gpa
            .checked_add(guest_len)
            .ok_or_else(|| TrapError::Hypervisor("stage-2 GPA overflow".to_owned()))?;
        let extent = Self::checked_window_extent(gpa, end)?;

        let host_len_u64 = self
            .geometry
            .align_up_host(guest_len)
            .ok_or_else(|| TrapError::Hypervisor("host backing length overflow".to_owned()))?;
        let mapped_len = usize::try_from(host_len_u64)
            .map_err(|_| TrapError::Hypervisor("stage-2 window exceeds host usize".to_owned()))?;
        let map_flags = if shared {
            libc::MAP_SHARED | libc::MAP_ANON | MAP_NORESERVE_OPT
        } else {
            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_NORESERVE_OPT
        };
        // SAFETY: anonymous `mmap` with `addr = null` creates a fresh host mapping.
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                map_flags,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(OsError::last("soft stage-2 anonymous mmap").into());
        }
        let base = NonNull::new(raw.cast::<u8>())
            .ok_or_else(|| TrapError::Hypervisor("mmap returned null".to_owned()))?;
        let backing = WindowBacking::OwnedMmap { base, mapped_len };
        self.install_window(
            extent,
            base,
            WindowHost {
                default_perms: perms,
                shared,
                _backing: backing,
            },
        )?;
        self.install_code_record(extent)?;
        Ok(base)
    }

    /// Register an installed window with the code-generation table; a
    /// refusal removes the window again.
    fn install_code_record(&mut self, extent: GpaExtent) -> Result<(), TrapError> {
        if self.extents.install(ExtentRecord::new(
            FrameGpa::new(extent.ipa()),
            extent.len().get(),
            OWNER,
        )) {
            return Ok(());
        }
        self.remove_window(extent)?;
        Err(TrapError::Hypervisor(format!(
            "ExtentTable refused stage-2 install at {:#x}..{:#x}",
            extent.ipa(),
            extent.end()
        )))
    }

    /// Retire the window's frame extent and unmap it from the core, which
    /// hands its host backing back to drop. A window pinned by a transfer
    /// can't be removed: the soft carrier has one vCPU, and a pin lives only
    /// inside one crossing's copy, so a pin across a removal is a broken
    /// invariant.
    fn remove_window(&mut self, extent: GpaExtent) -> Result<(), TrapError> {
        let view = self
            .core
            .installed_at_or_below(extent.ipa())
            .filter(|view| view.extent == extent)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!("no soft window at {:#x}", extent.ipa()))
            })?;
        let mapping = view.id;
        if let Some(carved) = self.core.live_extent_at(extent.ipa()) {
            match self.core.retire_extent(carved) {
                Ok(Retire::Released(_)) => {}
                Ok(Retire::Deferred) => soft_carrier_broken(format_args!(
                    "soft window {:#x} removed while a transfer pins it",
                    extent.ipa()
                )),
                Err(reason) => {
                    return Err(TrapError::Hypervisor(format!(
                        "soft window extent retire refused: {reason:?}"
                    )));
                }
            }
        }
        let (ticket, _unmap) = self.core.begin_unmap(mapping).map_err(|reason| {
            TrapError::Hypervisor(format!("soft window unmap refused: {reason:?}"))
        })?;
        match self.core.finish_unmap(ticket, BackendResult::Done) {
            Ok(host) => drop(host),
            Err(refused) => soft_carrier_broken(format_args!(
                "soft unmap ticket refused at once: {:?}",
                refused.reason
            )),
        }
        Ok(())
    }

    /// Pin the frame extent holding `[ipa, ipa + len)` for one transfer.
    fn pin_transfer(&mut self, ipa: u64, len: u64) -> Result<CorePin, PinRefusal> {
        self.core.pin(ipa, len)
    }

    fn unpin_transfer(&mut self, pin: CorePin) {
        match self.core.unpin(pin) {
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => {
                soft_carrier_broken(format_args!("a soft transfer pin outlived its window"))
            }
        }
    }

    fn generation(&self) -> GenerationId {
        self.core.generation().0
    }

    /// Advance the code generation of every 4 KiB frame a transfer wrote
    /// through its pin, as `write_gpa_bytes` does for host writes.
    fn invalidate_transfer_write(&mut self, ipa: u64, len: u64) -> bool {
        let Some(end) = ipa.checked_add(len).filter(|_| len > 0) else {
            return false;
        };
        let mut frame = ipa & !(GUEST_PAGE_BYTES - 1);
        while frame < end {
            if self
                .extents
                .invalidate_host_written_page(FrameGpa::new(frame), OWNER)
                .is_err()
            {
                return false;
            }
            frame += GUEST_PAGE_BYTES;
        }
        true
    }
}

/// Host file backing parameters for [`SoftStage2::map_file_alias`].
#[derive(Debug, Clone, Copy)]
pub struct FileAliasSpec {
    pub raw_fd: libc::c_int,
    pub offset: libc::off_t,
    pub host_prot: libc::c_int,
    pub sharing: HostAliasSharing,
    pub perms: MemPerms,
}

impl SoftStage2 {
    /// Map a host file backing into stage-2 `[gpa, gpa + len)`.
    pub fn map_file_alias(
        &mut self,
        gpa: u64,
        len: u64,
        spec: FileAliasSpec,
    ) -> Result<(), TrapError> {
        let FileAliasSpec {
            raw_fd,
            offset,
            host_prot,
            sharing,
            perms,
        } = spec;
        let guest_len = self
            .geometry
            .align_up_guest(len)
            .filter(|v| *v > 0)
            .ok_or_else(|| TrapError::Hypervisor(format!("invalid file alias length {len:#x}")))?;
        let end = gpa
            .checked_add(guest_len)
            .ok_or_else(|| TrapError::Hypervisor("file alias GPA overflow".to_owned()))?;
        let extent = Self::checked_window_extent(gpa, end)?;

        let host_len_u64 = self
            .geometry
            .align_up_host(guest_len)
            .ok_or_else(|| TrapError::Hypervisor("file alias host length overflow".to_owned()))?;
        let mapped_len = usize::try_from(host_len_u64)
            .map_err(|_| TrapError::Hypervisor("file alias exceeds host usize".to_owned()))?;

        let offset_u64 = u64::try_from(offset)
            .map_err(|_| TrapError::Hypervisor(format!("negative file alias offset {offset}")))?;
        let shared = sharing.is_shared();

        // When a 16 KiB/64 KiB host runs a 4 KiB-offset private file segment,
        // `mmap` rejects the unaligned offset; materialize into an owned anonymous
        // mapping via `pread` so 4 KiB guest page geometry remains exact.
        if !shared && !offset_u64.is_multiple_of(self.geometry.host_backing_granule) {
            let ptr = self.map_owned_anonymous(gpa, guest_len, perms, false)?;
            let mut read_total = 0usize;
            let target_len = usize::try_from(guest_len).unwrap_or(mapped_len);
            while read_total < target_len {
                let cur_off = offset
                    .saturating_add(libc::off_t::try_from(read_total).unwrap_or(libc::off_t::MAX));
                // SAFETY: `ptr` points to `mapped_len >= target_len` writable bytes.
                let n = unsafe {
                    libc::pread(
                        raw_fd,
                        ptr.as_ptr().add(read_total).cast(),
                        target_len - read_total,
                        cur_off,
                    )
                };
                if n < 0 {
                    let err = OsError::last("soft stage-2 pread unaligned alias");
                    let _ = self.unmap_stage2(gpa, guest_len);
                    return Err(err.into());
                }
                if n == 0 {
                    break;
                }
                read_total += n as usize;
            }
            return Ok(());
        }

        let (flags, prot) = match sharing {
            HostAliasSharing::Shared => (libc::MAP_SHARED, host_prot),
            HostAliasSharing::Private => (libc::MAP_PRIVATE, libc::PROT_READ | libc::PROT_WRITE),
        };
        // SAFETY: `raw_fd` is a valid open descriptor owned by the caller across `mmap`.
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                mapped_len,
                prot,
                flags,
                raw_fd,
                offset,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(OsError::last("soft stage-2 file mmap").into());
        }
        let base = NonNull::new(raw.cast::<u8>())
            .ok_or_else(|| TrapError::Hypervisor("file mmap returned null".to_owned()))?;
        let backing = WindowBacking::OwnedMmap { base, mapped_len };
        self.install_window(
            extent,
            base,
            WindowHost {
                default_perms: perms,
                shared,
                _backing: backing,
            },
        )?;
        self.install_code_record(extent)
    }

    /// Map caller-retained external host memory into stage-2 `[gpa, gpa + len)`.
    ///
    /// # Safety
    ///
    /// `host` must point to at least `len` bytes of valid memory that remains
    /// live until `unmap_stage2` or `SoftStage2` drop.
    pub unsafe fn map_external_stage2(
        &mut self,
        gpa: u64,
        host: NonNull<u8>,
        len: u64,
        perms: MemPerms,
        shared: bool,
    ) -> Result<(), TrapError> {
        let guest_len = self
            .geometry
            .align_up_guest(len)
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!("invalid external stage-2 len {len:#x}"))
            })?;
        let end = gpa
            .checked_add(guest_len)
            .ok_or_else(|| TrapError::Hypervisor("external stage-2 GPA overflow".to_owned()))?;
        let extent = Self::checked_window_extent(gpa, end)?;
        self.install_window(
            extent,
            host,
            WindowHost {
                default_perms: perms,
                shared,
                _backing: WindowBacking::External,
            },
        )?;
        self.install_code_record(extent)
    }

    /// Update stage-2 permissions on 4 KiB logical frames in `[gpa, gpa + len)`.
    pub fn protect_stage2(&mut self, gpa: u64, len: u64, perms: MemPerms) -> Result<(), TrapError> {
        if len == 0 {
            return Ok(());
        }
        let end = gpa
            .checked_add(len)
            .ok_or_else(|| TrapError::Hypervisor("protect_stage2 overflow".to_owned()))?;
        if !gpa.is_multiple_of(GUEST_PAGE_BYTES) || !end.is_multiple_of(GUEST_PAGE_BYTES) {
            return Err(TrapError::Hypervisor(format!(
                "unaligned protect_stage2 {gpa:#x}..{end:#x}"
            )));
        }
        let len_usize = usize::try_from(len)
            .map_err(|_| TrapError::Hypervisor("protect_stage2 len overflow".to_owned()))?;
        let window_default = self
            .window_for_range(gpa, len_usize)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!("protect_stage2 {gpa:#x}..{end:#x} unmapped"))
            })?
            .default_perms;
        let mut frame = gpa;
        while frame < end {
            if !perms.exec {
                let _ = self
                    .extents
                    .invalidate_host_written_page(FrameGpa::new(frame), OWNER);
            }
            if perms == window_default {
                self.page_perms.remove(&frame);
            } else {
                self.page_perms.insert(frame, perms);
            }
            frame += GUEST_PAGE_BYTES;
        }
        Ok(())
    }

    /// Retire an exact stage-2 window starting at `gpa`.
    pub fn unmap_stage2(&mut self, gpa: u64, len: u64) -> Result<(), TrapError> {
        let Some(window) = self
            .window_for_range(gpa, 0)
            .filter(|window| window.start == gpa)
        else {
            return Err(TrapError::Hypervisor(format!(
                "unmap_stage2: no window at {gpa:#x}"
            )));
        };
        let expected_end = gpa
            .checked_add(len)
            .ok_or_else(|| TrapError::Hypervisor("unmap_stage2 overflow".to_owned()))?;
        if window.end != expected_end {
            return Err(TrapError::Hypervisor(format!(
                "unmap_stage2: partial window unmap {gpa:#x}..{expected_end:#x} vs {:#x}..{:#x}",
                window.start, window.end
            )));
        }
        if let Some(retirement) = self
            .extents
            .remove(FrameGpa::new(gpa), None)
            .map_err(|e| TrapError::Hypervisor(format!("extent remove {gpa:#x}: {e:?}")))?
        {
            let completion = retirement
                .pending
                .try_complete()
                .map_err(|e| TrapError::Hypervisor(format!("extent complete {gpa:#x}: {e:?}")))?;
            self.extents.reclaim(&completion);
        }
        let stale_keys: Vec<u64> = self
            .page_perms
            .range(gpa..expected_end)
            .map(|(k, _)| *k)
            .collect();
        for key in stale_keys {
            self.page_perms.remove(&key);
        }
        let extent = Self::checked_window_extent(window.start, window.end)?;
        self.remove_window(extent)
    }

    #[must_use]
    pub fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        let window = self.window_for_range(gpa, len)?;
        let offset = usize::try_from(gpa - window.start).ok()?;
        // SAFETY: `window_for_range` verified `[gpa, gpa + len)` lies within `window`.
        Some(unsafe { window.host.as_ptr().add(offset) })
    }

    #[must_use]
    pub fn shared_futex_host_addr(&self, gpa: u64, len: usize) -> Option<u64> {
        let window = self.window_for_range(gpa, len)?;
        if !window.shared {
            return None;
        }
        let offset = usize::try_from(gpa - window.start).ok()?;
        // SAFETY: `window_for_range` verified `[gpa, gpa + len)` lies within `window`.
        Some(unsafe { window.host.as_ptr().add(offset) } as usize as u64)
    }

    pub fn read_gpa_bytes(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TrapError> {
        if dst.is_empty() {
            return Ok(());
        }
        let src = self.host_ptr(gpa, dst.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "soft stage-2: read_gpa {gpa:#x}+{} unmapped",
                dst.len()
            ))
        })?;
        // SAFETY: `host_ptr` verified `dst.len()` readable bytes in one live window.
        unsafe {
            core::ptr::copy_nonoverlapping(src.cast_const(), dst.as_mut_ptr(), dst.len());
        }
        Ok(())
    }

    /// Host-side write to guest physical memory; revokes `ExtentTable` code
    /// generations for every touched 4 KiB frame before mutating bytes.
    pub fn write_gpa_bytes(&mut self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let end = gpa
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| TrapError::Hypervisor("soft stage-2: write_gpa overflow".to_owned()))?;
        let dst = self.host_ptr(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "soft stage-2: write_gpa {gpa:#x}+{} unmapped",
                bytes.len()
            ))
        })?;
        let first = gpa & !(GUEST_PAGE_BYTES - 1);
        let last = (end - 1) & !(GUEST_PAGE_BYTES - 1);
        let mut frame = first;
        while frame <= last {
            self.extents
                .invalidate_host_written_page(FrameGpa::new(frame), OWNER)
                .map_err(|e| {
                    TrapError::Hypervisor(format!(
                        "soft stage-2: invalidate code frame {frame:#x}: {e:?}"
                    ))
                })?;
            frame += GUEST_PAGE_BYTES;
        }
        // SAFETY: `host_ptr` verified `bytes.len()` writable bytes in one live window.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        }
        Ok(())
    }

    fn guest_read_with_access(
        &mut self,
        address: VirtualAddress,
        mut bytes: &mut [u8],
        access: Stage2AbortAccess,
    ) -> Result<(), MemoryFault> {
        if self.extents.is_terminal() {
            self.last_abort = Some(Stage2Abort {
                gpa: address.0,
                access,
                reason: Stage2AbortReason::Unmapped,
            });
            return Err(MemoryFault { address });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(end) = address.0.checked_add(bytes.len() as u64) else {
            self.last_abort = Some(Stage2Abort {
                gpa: address.0,
                access,
                reason: Stage2AbortReason::Unmapped,
            });
            return Err(MemoryFault { address });
        };
        let mut at = address.0;
        while at < end {
            let frame = at & !(GUEST_PAGE_BYTES - 1);
            let offset_in_page = (at - frame) as usize;
            let chunk_len = bytes.len().min(PAGE_BYTES_USIZE - offset_in_page);
            let Some(window) = self.window_for_range(at, chunk_len) else {
                self.last_abort = Some(Stage2Abort {
                    gpa: at,
                    access,
                    reason: Stage2AbortReason::Unmapped,
                });
                return Err(MemoryFault {
                    address: VirtualAddress(at),
                });
            };
            let perms = self.perms_for_frame(window, frame);
            let allowed = match access {
                Stage2AbortAccess::Read => perms.read,
                Stage2AbortAccess::Fetch => perms.read && perms.exec,
                Stage2AbortAccess::Write => perms.write,
            };
            if !allowed {
                self.last_abort = Some(Stage2Abort {
                    gpa: at,
                    access,
                    reason: Stage2AbortReason::PermissionDenied,
                });
                return Err(MemoryFault {
                    address: VirtualAddress(at),
                });
            }
            let win_offset = (at - window.start) as usize;
            // SAFETY: `window_for_range` verified `chunk_len` bytes from `win_offset`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    window.host.as_ptr().add(win_offset).cast_const(),
                    bytes.as_mut_ptr(),
                    chunk_len,
                );
            }
            bytes = &mut bytes[chunk_len..];
            at += chunk_len as u64;
        }
        Ok(())
    }
}

impl SoftGuestMemory for SoftStage2 {
    fn stage1_is_local(&self) -> bool {
        true
    }

    /// Every write to guest RAM that can change code advances the frame's
    /// generation in this inventory: guest stores, `write_gpa_bytes`, and
    /// `publish_user_executable` for each new EL0-executable leaf. Removing
    /// execute permission and retiring a window clear the frame as well.
    fn code_cache_domain(&self) -> Option<carrick_softmmu::ExtentTableId> {
        Some(self.extents.identity())
    }

    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.guest_read_with_access(address, bytes, Stage2AbortAccess::Read)
    }

    fn fetch(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.guest_read_with_access(address, bytes, Stage2AbortAccess::Fetch)
    }

    fn write(&mut self, address: VirtualAddress, mut bytes: &[u8]) -> Result<(), MemoryFault> {
        if self.extents.is_terminal() {
            self.last_abort = Some(Stage2Abort {
                gpa: address.0,
                access: Stage2AbortAccess::Write,
                reason: Stage2AbortReason::Unmapped,
            });
            return Err(MemoryFault { address });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let Some(end) = address.0.checked_add(bytes.len() as u64) else {
            self.last_abort = Some(Stage2Abort {
                gpa: address.0,
                access: Stage2AbortAccess::Write,
                reason: Stage2AbortReason::Unmapped,
            });
            return Err(MemoryFault { address });
        };
        let first = address.0 & !(GUEST_PAGE_BYTES - 1);
        let last = (end - 1) & !(GUEST_PAGE_BYTES - 1);
        let mut frame = first;
        while frame <= last {
            let fault_at = address.0.max(frame);
            let Some(window) = self.window_for_range(fault_at, 1) else {
                self.last_abort = Some(Stage2Abort {
                    gpa: fault_at,
                    access: Stage2AbortAccess::Write,
                    reason: Stage2AbortReason::Unmapped,
                });
                return Err(MemoryFault {
                    address: VirtualAddress(fault_at),
                });
            };
            if !self.perms_for_frame(window, frame).write {
                self.last_abort = Some(Stage2Abort {
                    gpa: fault_at,
                    access: Stage2AbortAccess::Write,
                    reason: Stage2AbortReason::PermissionDenied,
                });
                return Err(MemoryFault {
                    address: VirtualAddress(fault_at),
                });
            }
            frame += GUEST_PAGE_BYTES;
        }
        let mut frame = first;
        while frame <= last {
            self.extents
                .invalidate_host_written_page(FrameGpa::new(frame), OWNER)
                .map_err(|_| MemoryFault {
                    address: VirtualAddress(address.0.max(frame)),
                })?;
            frame += GUEST_PAGE_BYTES;
        }
        let mut at = address.0;
        while at < end {
            let frame_base = at & !(GUEST_PAGE_BYTES - 1);
            let offset_in_page = (at - frame_base) as usize;
            let chunk_len = bytes.len().min(PAGE_BYTES_USIZE - offset_in_page);
            let Some(window) = self.window_for_range(at, chunk_len) else {
                self.last_abort = Some(Stage2Abort {
                    gpa: at,
                    access: Stage2AbortAccess::Write,
                    reason: Stage2AbortReason::Unmapped,
                });
                return Err(MemoryFault {
                    address: VirtualAddress(at),
                });
            };
            let win_offset = (at - window.start) as usize;
            // SAFETY: permissions and bounds were verified above, and code
            // generations were invalidated prior to mutation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    window.host.as_ptr().add(win_offset),
                    chunk_len,
                );
            }
            bytes = &bytes[chunk_len..];
            at += chunk_len as u64;
        }
        Ok(())
    }

    fn inline_ram(&mut self, read: Option<FrameGpa>, write: Option<FrameGpa>) -> InlineRam<'_> {
        if self.extents.is_terminal() {
            return InlineRam::None;
        }
        let read_ptr = read.and_then(|frame| {
            let win = self.window_for_range(frame.raw(), PAGE_BYTES_USIZE)?;
            if !self.perms_for_frame(win, frame.raw()).read {
                return None;
            }
            let off = usize::try_from(frame.raw() - win.start).ok()?;
            // SAFETY: `window_for_range` verified a full 4 KiB page inside `win`.
            Some((frame, unsafe {
                win.host.as_ptr().add(off).cast::<[u8; PAGE_BYTES_USIZE]>()
            }))
        });
        let write_ptr = write.and_then(|frame| {
            let win = self.window_for_range(frame.raw(), PAGE_BYTES_USIZE)?;
            if !self.perms_for_frame(win, frame.raw()).write {
                return None;
            }
            let page = self.extents.authenticate_frame(frame, OWNER)?;
            if self.extents.is_code_page(page) {
                return None;
            }
            let off = usize::try_from(frame.raw() - win.start).ok()?;
            // SAFETY: `window_for_range` verified a full 4 KiB non-code page inside `win`.
            Some((frame, unsafe {
                win.host.as_ptr().add(off).cast::<[u8; PAGE_BYTES_USIZE]>()
            }))
        });
        match (read_ptr, write_ptr) {
            (Some((rf, _)), Some((wf, wp))) if rf == wf => {
                // SAFETY: `&mut self` holds exclusive access to `SoftStage2` for the
                // block launch, and `rf == wf` creates one unique mutable reference.
                InlineRam::Shared(unsafe { &mut *wp })
            }
            (Some((rf, rp)), Some((wf, wp))) if rf != wf => {
                // SAFETY: `rf != wf` are distinct 4 KiB GPA frames in non-overlapping
                // stage-2 windows, so `&*rp` and `&mut *wp` never alias.
                unsafe {
                    InlineRam::Separate {
                        read: Some(&*rp),
                        write: Some(&mut *wp),
                    }
                }
            }
            (None, Some((_, wp))) => {
                // SAFETY: `&mut self` holds exclusive access to `SoftStage2`.
                InlineRam::Separate {
                    read: None,
                    write: Some(unsafe { &mut *wp }),
                }
            }
            (Some((_, rp)), None) => {
                // SAFETY: `&mut self` holds exclusive access to `SoftStage2`.
                InlineRam::Separate {
                    read: Some(unsafe { &*rp }),
                    write: None,
                }
            }
            _ => InlineRam::None,
        }
    }

    fn invalidate_code_frame(&mut self, frame: FrameGpa) -> Result<bool, MemoryFault> {
        if self
            .window_for_range(frame.raw(), PAGE_BYTES_USIZE)
            .is_some()
        {
            self.extents
                .invalidate_host_written_page(frame, OWNER)
                .map_err(|_| MemoryFault {
                    address: VirtualAddress(frame.raw()),
                })?;
        }
        Ok(true)
    }

    fn mark_code_page(&mut self, frame: FrameGpa) -> Option<CodeGeneration> {
        let win = self.window_for_range(frame.raw(), PAGE_BYTES_USIZE)?;
        let perms = self.perms_for_frame(win, frame.raw());
        if !(perms.read && perms.exec) {
            return None;
        }
        let page = self.extents.authenticate_frame(frame, OWNER)?;
        let generation = self.extents.mark_code_page(page, &mut []);
        (generation != 0).then_some(CodeGeneration(generation))
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        let win = self.window_for_range(frame.raw(), PAGE_BYTES_USIZE)?;
        let perms = self.perms_for_frame(win, frame.raw());
        if !(perms.read && perms.exec) {
            return None;
        }
        let page = self.extents.authenticate_frame(frame, OWNER)?;
        self.extents
            .is_code_page(page)
            .then(|| CodeGeneration(self.extents.code_generation(page)))
    }
}

/// Lock-free single-borrow cell sharing `SoftStage2` between `SoftAarch64Vmm`
/// and `SoftAarch64Vcpu` inside `Aarch64EngineCore` without `RawLock` debt.
struct ExclusiveStage2 {
    borrowed: AtomicBool,
    /// The carrier identity of the core inside, fixed for its life.
    carrier: CarrierId,
    inner: UnsafeCell<SoftStage2>,
}

// SAFETY: `ExclusiveStage2` grants mutable/shared access to `SoftStage2` only
// after winning an `Acquire` CAS on `borrowed` and releases with `Release`,
// refusing concurrent borrows instead of aliasing.
unsafe impl Send for ExclusiveStage2 {}
unsafe impl Sync for ExclusiveStage2 {}

struct Stage2Guard<'a> {
    cell: &'a ExclusiveStage2,
}

impl Drop for Stage2Guard<'_> {
    fn drop(&mut self) {
        self.cell.borrowed.store(false, Ordering::Release);
    }
}

impl core::ops::Deref for Stage2Guard<'_> {
    type Target = SoftStage2;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `Stage2Guard` holds the exclusive `borrowed` token.
        unsafe { &*self.cell.inner.get() }
    }
}

impl core::ops::DerefMut for Stage2Guard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: `Stage2Guard` holds the exclusive `borrowed` token.
        unsafe { &mut *self.cell.inner.get() }
    }
}

impl ExclusiveStage2 {
    fn new(stage2: SoftStage2) -> Self {
        Self {
            borrowed: AtomicBool::new(false),
            carrier: stage2.core.carrier(),
            inner: UnsafeCell::new(stage2),
        }
    }

    fn try_borrow(&self) -> Result<Stage2Guard<'_>, TrapError> {
        self.borrowed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Stage2Guard { cell: self })
            .map_err(|_| TrapError::Hypervisor("concurrent SoftStage2 access refused".to_owned()))
    }
}

/// One soft carrier's authority to map retained ABI storage into its EL1
/// dynamic metadata aperture ([`RetainedMetadataMapper`]). It names its
/// carrier weakly: once that stage 2 drops, every call fails `StaleOwner`.
#[derive(Clone)]
pub struct SoftRetainedMetadata {
    stage2: Weak<ExclusiveStage2>,
}

/// One retained mapping in its exact soft carrier.
pub struct SoftRetainedExtent {
    stage2: Weak<ExclusiveStage2>,
    gpa: u64,
}

impl RetainedMetadataMapper for SoftRetainedMetadata {
    type Extent = SoftRetainedExtent;

    fn region(&self) -> Result<NonNull<u8>, MetadataResolutionError> {
        let stage2 = self
            .stage2
            .upgrade()
            .ok_or(MetadataResolutionError::StaleOwner)?;
        let stage2 = stage2
            .try_borrow()
            .map_err(|_| MetadataResolutionError::Busy)?;
        stage2
            .host_ptr(EL1_REGION_BASE, EL1_REGION_SIZE as usize)
            .and_then(NonNull::new)
            .ok_or(MetadataResolutionError::StaleOwner)
    }

    fn map_retained(
        &self,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<SoftRetainedExtent, MetadataResolutionError> {
        let stage2 = self
            .stage2
            .upgrade()
            .ok_or(MetadataResolutionError::StaleOwner)?;
        let gpa = stage2
            .try_borrow()
            .map_err(|_| MetadataResolutionError::Busy)?
            .map_retained_metadata(backing)?;
        Ok(SoftRetainedExtent {
            stage2: Arc::downgrade(&stage2),
            gpa,
        })
    }
}

impl RetainedMetadataExtent for SoftRetainedExtent {
    fn guest_base(&self) -> Result<GuestVa, MetadataResolutionError> {
        let stage2 = self
            .stage2
            .upgrade()
            .ok_or(MetadataResolutionError::StaleOwner)?;
        let stage2 = stage2
            .try_borrow()
            .map_err(|_| MetadataResolutionError::Busy)?;
        stage2
            .retains_metadata_at(self.gpa)
            .then_some(GuestVa::new(self.gpa))
            .ok_or(MetadataResolutionError::StaleOwner)
    }

    fn try_retire(self) -> Result<(), Self> {
        // A dropped carrier released this mapping and its backing with it.
        let Some(stage2) = self.stage2.upgrade() else {
            return Ok(());
        };
        let Ok(mut guard) = stage2.try_borrow() else {
            return Err(self);
        };
        if guard.retire_retained_metadata(self.gpa).is_err() {
            drop(guard);
            return Err(self);
        }
        Ok(())
    }
}

/// One soft vCPU's run seat: the requests its dispatcher services at block
/// boundaries, and the wake a WFI parks on.
#[derive(Default)]
struct SoftRunSeat {
    control: RunControl,
    parked: Mutex<()>,
    wake: Condvar,
}

impl SoftRunSeat {
    /// Request the vCPU leave `run`, and end a WFI park.
    fn kick(&self) {
        self.control.kick();
        // Publish under the park lock: a parking vCPU either probes the
        // request after enrolling or is already waiting for this notify.
        drop(self.parked.lock().unwrap_or_else(|p| p.into_inner()));
        self.wake.notify_all();
    }

    /// D1.16.2 WFI: wait until a kick, or until `deadline` (the virtual
    /// timer's), whichever is first. Enrol on the wake, then probe once;
    /// a spurious condvar return re-probes.
    fn park(&self, deadline: Option<Instant>) {
        let mut guard = self.parked.lock().unwrap_or_else(|p| p.into_inner());
        while !self.control.requested() {
            let now = Instant::now();
            guard = match deadline {
                Some(deadline) if deadline <= now => return,
                Some(deadline) => {
                    self.wake
                        .wait_timeout(guard, deadline - now)
                        .unwrap_or_else(|p| p.into_inner())
                        .0
                }
                None => self.wake.wait(guard).unwrap_or_else(|p| p.into_inner()),
            };
        }
    }
}

/// Cross-thread kick handle interrupting `SoftAarch64Vcpu::run` at a block
/// boundary, or in its WFI park.
#[derive(Clone)]
pub struct SoftKickHandle {
    seat: Arc<SoftRunSeat>,
}

impl VcpuKick for SoftKickHandle {
    fn kick(&self) {
        self.seat.kick();
    }
}

/// Soft AArch64 vCPU implementing [`carrick_aarch64::Aarch64Vcpu`].
pub struct SoftAarch64Vcpu<X: ExecuteBlock> {
    cpu: CpuState,
    monitor: ExclusiveMonitor,
    executor: X,
    /// Compiled code kept across `run` calls; `None` under
    /// `CARRICK_SOFT_AARCH64_HANDOFF_CACHE=0`.
    code: Option<DispatchCache<X::Code>>,
    stage2: Arc<ExclusiveStage2>,
    seat: Arc<SoftRunSeat>,
    mailbox: Option<MailboxSlot>,
    actlr_el1: u64,
    cpacr_el1: u64,
    tpidrro_pending: AtomicU64,
    tpidrro_dirty: AtomicBool,
    sp_pending: AtomicU64,
    sp_dirty: AtomicBool,
    /// The physical count at this vCPU's boot: its virtual count's offset.
    boot_count: u64,
    block_quantum: u64,
    max_quanta_per_exit: u64,
    work: RunWork,
    idle_parks: u64,
    /// The vCPU has run guest code. Until its first run it caches no
    /// translation: its stage-1 TLB model and block cache start empty.
    ran: bool,
}

impl<X: ExecuteBlock> SoftAarch64Vcpu<X> {
    /// Guest-engine work accumulated across every `run` of this vCPU.
    #[must_use]
    pub const fn run_work(&self) -> RunWork {
        self.work
    }

    /// Code kept across `run` calls now, and its high-water mark; `None`
    /// when the handoff cache is off.
    #[must_use]
    pub fn code_residency(&self) -> Option<ResidencyCensus> {
        self.code.as_ref().map(DispatchCache::census)
    }

    /// How many times a WFI parked this vCPU's thread.
    #[must_use]
    pub const fn idle_parks(&self) -> u64 {
        self.idle_parks
    }

    /// Advance the virtual counter to the host's monotonic clock.
    fn sample_counter(&mut self) {
        self.cpu.sample_counter();
    }

    /// The host instant the virtual counter reaches `count`.
    fn counter_instant(&self, count: u64) -> Option<Instant> {
        soft_counter_epoch().checked_add(Duration::from_nanos(count.checked_add(self.boot_count)?))
    }

    fn sync_shared_overrides(&mut self) {
        if self.tpidrro_dirty.swap(false, Ordering::AcqRel) {
            self.cpu.named.tpidrroel0 = SystemValue(self.tpidrro_pending.load(Ordering::Acquire));
        }
        if self.sp_dirty.swap(false, Ordering::AcqRel) {
            self.cpu.sp_el0 = StackPointer(self.sp_pending.load(Ordering::Acquire));
        }
    }

    fn effective_sp_el0(&self) -> u64 {
        if self.sp_dirty.load(Ordering::Acquire) {
            self.sp_pending.load(Ordering::Acquire)
        } else {
            self.cpu.sp_el0.0
        }
    }

    fn effective_tpidrro(&self) -> u64 {
        if self.tpidrro_dirty.load(Ordering::Acquire) {
            self.tpidrro_pending.load(Ordering::Acquire)
        } else {
            self.cpu.named.tpidrroel0.0
        }
    }

    fn read_gpr(&self, index: u8) -> Result<u64, TrapError> {
        let gpr = Gpr::new(index)
            .ok_or_else(|| TrapError::Hypervisor(format!("invalid AArch64 GPR X{index}")))?;
        Ok(self.cpu.read_operand(OperandRegister::Gpr(gpr)).0)
    }

    fn write_gpr(&mut self, index: u8, value: u64) -> Result<(), TrapError> {
        let gpr = Gpr::new(index)
            .ok_or_else(|| TrapError::Hypervisor(format!("invalid AArch64 GPR X{index}")))?;
        self.cpu
            .write_operand(OperandRegister::Gpr(gpr), RegisterValue(value));
        Ok(())
    }
}

impl<X: ExecuteBlock + Send> Aarch64Vcpu for SoftAarch64Vcpu<X>
where
    X::Error: core::fmt::Debug,
{
    fn mailbox_slot(&self) -> Option<usize> {
        self.mailbox.as_ref().map(|_| 0)
    }

    /// Stage-1 maintenance owed before this vCPU's first run has nothing to
    /// invalidate (it has cached no translation), so it is discharged here
    /// without running the maintenance trampoline.
    fn defer_stage1_maintenance(
        &mut self,
        _maintenance: carrick_aarch64::vmm::Stage1Maintenance,
    ) -> bool {
        !self.ran
    }

    /// The loaded task's roots when EL1 may install them itself: one root
    /// for both halves, under a process ASID (ASID 0 is the carrier
    /// maintenance root's). The soft CPU has no per-task memory model, so
    /// nothing else of the task's translation state stays behind a switch.
    fn el1_switchable_roots(&self) -> Option<(u64, u64)> {
        let (ttbr0, ttbr1) = (self.cpu.named.ttbr0.0, self.cpu.named.ttbr1.0);
        (ttbr0 >> 48 != 0 && ttbr1 == ttbr0).then_some((ttbr0, ttbr1))
    }

    fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
        match r {
            Reg::X(n) if n <= 30 => self.read_gpr(n as u8),
            Reg::Sp => Ok(self.effective_sp_el0()),
            Reg::Pc => Ok(self.cpu.pc.0),
            Reg::Pstate => Ok(self.cpu.pstate.save().0),
            Reg::SpEl1 => Ok(self.cpu.sp_el1.0),
            Reg::ElrEl1 => Ok(self.cpu.el1.elr.0),
            Reg::SpsrEl1 => Ok(self.cpu.el1.spsr.0),
            other => Err(TrapError::Hypervisor(format!(
                "unsupported register {other:?} on SoftAarch64Vcpu"
            ))),
        }
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
        self.sync_shared_overrides();
        match r {
            Reg::X(n) if n <= 30 => self.write_gpr(n as u8, v),
            Reg::Sp => {
                self.cpu.sp_el0 = StackPointer(v);
                Ok(())
            }
            Reg::Pc => {
                self.cpu.pc = ProgramCounter(v);
                Ok(())
            }
            Reg::Pstate => {
                self.cpu.pstate = Pstate::restore(SavedPstate(v)).ok_or_else(|| {
                    TrapError::Hypervisor(format!("illegal AArch64 PSTATE {v:#x}"))
                })?;
                Ok(())
            }
            Reg::SpEl1 => {
                self.cpu.sp_el1 = StackPointer(v);
                Ok(())
            }
            Reg::ElrEl1 => {
                self.cpu.el1.elr = ProgramCounter(v);
                Ok(())
            }
            Reg::SpsrEl1 => {
                self.cpu.el1.spsr = SavedPstate(v & 0xffff_ffff);
                Ok(())
            }
            other => Err(TrapError::Hypervisor(format!(
                "unsupported register {other:?} on SoftAarch64Vcpu"
            ))),
        }
    }

    fn get_sys_reg(&self, r: SysReg) -> Result<u64, TrapError> {
        match r {
            SysReg::Sctlr => Ok(self.cpu.el1.sctlr.0),
            SysReg::Ttbr0 => Ok(self.cpu.named.ttbr0.0),
            SysReg::Ttbr1 => Ok(self.cpu.named.ttbr1.0),
            SysReg::Tcr => Ok(self.cpu.el1.tcr.0),
            SysReg::Mair => Ok(self.cpu.el1.mair.0),
            SysReg::Vbar => Ok(self.cpu.el1.vbar.0),
            SysReg::Cpacr => Ok(self.cpacr_el1),
            SysReg::CntkctlEl1 => Ok(self.cpu.el1.cntkctl.0),
            SysReg::TpidrEl0 => Ok(self.cpu.named.tpidrel0.0),
            SysReg::FsBase | SysReg::GsBase => Err(TrapError::Hypervisor(format!(
                "unsupported x86 sysreg {r:?} on SoftAarch64Vcpu"
            ))),
        }
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), TrapError> {
        self.sync_shared_overrides();
        match r {
            SysReg::Sctlr => self.cpu.el1.sctlr = Sctlr(v),
            SysReg::Ttbr0 => self.cpu.named.ttbr0 = SystemValue(v),
            SysReg::Ttbr1 => self.cpu.named.ttbr1 = SystemValue(v),
            SysReg::Tcr => self.cpu.el1.tcr = SystemValue(v),
            SysReg::Mair => self.cpu.el1.mair = SystemValue(v),
            SysReg::Vbar => self.cpu.el1.vbar = VirtualAddress(v & !0x7ff),
            SysReg::Cpacr => self.cpacr_el1 = v,
            SysReg::CntkctlEl1 => self.cpu.el1.cntkctl = SystemValue(v),
            SysReg::TpidrEl0 => self.cpu.named.tpidrel0 = SystemValue(v),
            SysReg::FsBase | SysReg::GsBase => {
                return Err(TrapError::Hypervisor(format!(
                    "unsupported x86 sysreg {r:?} on SoftAarch64Vcpu"
                )));
            }
        }
        Ok(())
    }

    fn get_vreg(&self, n: u32) -> Result<u128, TrapError> {
        self.cpu
            .vectors
            .get(n as usize)
            .copied()
            .ok_or_else(|| TrapError::Hypervisor(format!("SIMD register V{n} out of range")))
    }

    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), TrapError> {
        let slot = self
            .cpu
            .vectors
            .get_mut(n as usize)
            .ok_or_else(|| TrapError::Hypervisor(format!("SIMD register V{n} out of range")))?;
        *slot = v;
        Ok(())
    }

    fn get_fpcr(&self) -> Result<u64, TrapError> {
        Ok(self.cpu.named.fpcr.0)
    }

    fn set_fpcr(&mut self, v: u64) -> Result<(), TrapError> {
        self.cpu.named.fpcr = SystemValue(v & 0xffff_ffff);
        Ok(())
    }

    fn get_fpsr(&self) -> Result<u64, TrapError> {
        Ok(self.cpu.named.fpsr.0)
    }

    fn set_fpsr(&mut self, v: u64) -> Result<(), TrapError> {
        self.cpu.named.fpsr = SystemValue(v & 0xffff_ffff);
        Ok(())
    }

    fn get_esr_el1(&self) -> Result<u64, TrapError> {
        Ok(self.cpu.el1.esr.0)
    }

    fn get_far_el1(&self) -> Result<u64, TrapError> {
        Ok(self.cpu.el1.far.0)
    }

    fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
        let mut gprs = [0u64; 31];
        for (i, dst) in gprs.iter_mut().enumerate() {
            *dst = self.read_gpr(i as u8)?;
        }
        Ok(Aarch64VcpuSnapshot {
            gprs,
            pc: self.cpu.pc.0,
            pstate: self.cpu.pstate.save().0,
            sp_el0: self.effective_sp_el0(),
            sp_el1: self.cpu.sp_el1.0,
            elr_el1: self.cpu.el1.elr.0,
            spsr_el1: self.cpu.el1.spsr.0,
            ttbr0: self.cpu.named.ttbr0.0,
            ttbr1: self.cpu.named.ttbr1.0,
            tcr: self.cpu.el1.tcr.0,
            sctlr: self.cpu.el1.sctlr.0,
            mair: self.cpu.el1.mair.0,
            vbar: self.cpu.el1.vbar.0,
            cpacr: self.cpacr_el1,
            cntkctl_el1: self.cpu.el1.cntkctl.0,
            tpidr_el0: self.cpu.named.tpidrel0.0,
            tpidrro_el0: self.effective_tpidrro(),
            tpidr_el1: self.cpu.el1.tpidr.0,
            contextidr_el1: self.cpu.named.contextidr.0,
            actlr_el1: self.actlr_el1,
            vregs: self.cpu.vectors,
            fpsr: self.cpu.named.fpsr.0 as u32,
            fpcr: self.cpu.named.fpcr.0 as u32,
        })
    }

    fn restore(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        let pstate = Pstate::restore(SavedPstate(snap.pstate)).ok_or_else(|| {
            TrapError::Hypervisor(format!("restore illegal AArch64 PSTATE {:#x}", snap.pstate))
        })?;
        self.tpidrro_dirty.store(false, Ordering::Release);
        self.sp_dirty.store(false, Ordering::Release);
        for (i, &val) in snap.gprs.iter().enumerate() {
            self.write_gpr(i as u8, val)?;
        }
        self.cpu.pc = ProgramCounter(snap.pc);
        self.cpu.pstate = pstate;
        self.cpu.sp_el0 = StackPointer(snap.sp_el0);
        self.cpu.sp_el1 = StackPointer(snap.sp_el1);
        self.cpu.el1.elr = ProgramCounter(snap.elr_el1);
        self.cpu.el1.spsr = SavedPstate(snap.spsr_el1 & 0xffff_ffff);
        self.cpu.named.ttbr0 = SystemValue(snap.ttbr0);
        self.cpu.named.ttbr1 = SystemValue(snap.ttbr1);
        self.cpu.el1.tcr = SystemValue(snap.tcr);
        self.cpu.el1.sctlr = Sctlr(snap.sctlr);
        self.cpu.el1.mair = SystemValue(snap.mair);
        self.cpu.el1.vbar = VirtualAddress(snap.vbar & !0x7ff);
        self.cpacr_el1 = snap.cpacr;
        self.cpu.el1.cntkctl = SystemValue(snap.cntkctl_el1);
        self.cpu.named.tpidrel0 = SystemValue(snap.tpidr_el0);
        self.cpu.named.tpidrroel0 = SystemValue(snap.tpidrro_el0);
        self.cpu.el1.tpidr = SystemValue(snap.tpidr_el1);
        self.cpu.named.contextidr = SystemValue(snap.contextidr_el1);
        self.actlr_el1 = snap.actlr_el1;
        self.cpu.vectors = snap.vregs;
        self.cpu.named.fpsr = SystemValue(u64::from(snap.fpsr));
        self.cpu.named.fpcr = SystemValue(u64::from(snap.fpcr));
        Ok(())
    }

    fn complete_syscall_return(&mut self, return_value: i64) -> Result<(), TrapError> {
        if let Some(mailbox) = self.mailbox.as_mut() {
            return mailbox.publish_normal_return(return_value).map_err(|e| {
                TrapError::Hypervisor(format!("aarch64 syscall mailbox protocol error: {e:?}"))
            });
        }
        self.set_reg(Reg::X(0), return_value as u64)
    }

    fn complete_native_signal_return(
        &mut self,
        return_value: i64,
        restart_eligible: bool,
    ) -> Result<(), TrapError> {
        if let Some(mailbox) = self.mailbox.as_mut() {
            return mailbox
                .publish_native_signal_return(return_value, restart_eligible)
                .map_err(|e| {
                    TrapError::Hypervisor(format!("aarch64 syscall mailbox protocol error: {e:?}"))
                });
        }
        self.complete_syscall_return(return_value)
    }

    fn pending_syscall_return(&self) -> Result<Option<i64>, TrapError> {
        let Some(mailbox) = self.mailbox.as_ref() else {
            return Ok(None);
        };
        mailbox.pending_normal_return().map_err(|e| {
            TrapError::Hypervisor(format!("aarch64 syscall mailbox protocol error: {e:?}"))
        })
    }

    fn prepare_register_resume(&mut self) -> Result<(), TrapError> {
        if let Some(mailbox) = self.mailbox.as_mut() {
            mailbox.prepare_register_resume().map_err(|e| {
                TrapError::Hypervisor(format!("aarch64 syscall mailbox protocol error: {e:?}"))
            })?;
        }
        Ok(())
    }

    fn stamp_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        self.tpidrro_pending.store(tid, Ordering::Relaxed);
        self.tpidrro_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn kick(&self) -> Result<(), TrapError> {
        self.seat.kick();
        Ok(())
    }

    /// The owed kick is the kick SGI made pending in this vCPU's
    /// redistributor, and withdrawn once served (as on HVF's GIC).
    fn set_pending_irq(&mut self, pending: bool) -> Result<(), TrapError> {
        self.cpu
            .gic
            .set_pending(carrick_el1_abi::GIC_KICK_INTID, pending);
        Ok(())
    }

    fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
        self.ran = true;
        self.sync_shared_overrides();
        let stage2_owner = Arc::clone(&self.stage2);
        let mut stage2 = stage2_owner.try_borrow()?;
        let mut discarded = DispatchCache::default();
        let mut quanta = 0;
        while quanta < self.max_quanta_per_exit {
            self.sample_counter();
            let code = match self.code.as_mut() {
                Some(code) => code,
                None => {
                    discarded.clear();
                    &mut discarded
                }
            };
            let report = run_controlled(
                &mut self.cpu,
                &mut self.monitor,
                &mut *stage2,
                &mut self.executor,
                BlockLimits::default(),
                self.block_quantum,
                &self.seat.control,
                code,
            );
            self.work.accumulate(report.work);
            match report.stop {
                Stop::Budget => quanta += 1,
                Stop::Kicked => return Ok(Aarch64Exit::Kicked),
                // The WFI retired. It completes when the GIC asserts this
                // PE's IRQ input, masked or not; until then the thread parks
                // outside the stage-2 borrow for the timer or a kick.
                Stop::Event {
                    event: Event::Hint(Hint::Wfi),
                    ..
                } => {
                    self.sample_counter();
                    if self.cpu.irq_pending() {
                        continue;
                    }
                    let deadline = self
                        .cpu
                        .virtual_timer_deadline()
                        .and_then(|count| self.counter_instant(count));
                    drop(stage2);
                    self.idle_parks += 1;
                    self.seat.park(deadline);
                    stage2 = stage2_owner.try_borrow()?;
                }
                Stop::Event {
                    event: Event::Hint(Hint::Wfe),
                    ..
                } => return Ok(Aarch64Exit::Halt),
                Stop::Event {
                    event: Event::ProviderExit(exit),
                    ..
                } => match classify_hvc_immediate(exit.immediate.value()) {
                    HvcImmediateKind::Maintenance | HvcImmediateKind::ServiceReturn => {
                        return Ok(Aarch64Exit::MaintenanceDone);
                    }
                    HvcImmediateKind::Kick => return Ok(Aarch64Exit::Kicked),
                    HvcImmediateKind::Idle => return Ok(Aarch64Exit::Halt),
                    HvcImmediateKind::MetadataGrant
                        if self.read_gpr(0)? == carrick_el1_abi::GRANT_OP_ROOT_EXIT =>
                    {
                        // The in-ring root owner's terminal crossing. A
                        // refused one leaves EL1 to fail closed.
                        let exit = authenticated_root_exit(
                            &stage2,
                            self.read_gpr(1)?,
                            self.read_gpr(2)?,
                            self.cpu.named.ttbr0.0,
                        );
                        self.write_gpr(
                            0,
                            if exit.is_some() {
                                carrick_el1_abi::METADATA_GRANT_SUCCESS
                            } else {
                                carrick_el1_abi::METADATA_GRANT_ERR_DENIED
                            },
                        )?;
                        match exit {
                            Some(exit) => return Ok(exit),
                            None => quanta += 1,
                        }
                    }
                    HvcImmediateKind::MetadataGrant => {
                        // Single-process soft bring-up does not run a dynamic
                        // metadata allocator; fail closed with `ERR_DENIED`
                        // rather than echoing unallocated request arguments.
                        if let Some(mb) = carrick_el1_abi::metadata_mailbox_host()
                            && mb.claim_request().is_some()
                        {
                            mb.publish_response(
                                carrick_el1_abi::METADATA_GRANT_ERR_DENIED,
                                0,
                                0,
                                0,
                            );
                        }
                        quanta += 1;
                    }
                    HvcImmediateKind::SyscallOrFault => {
                        if let Some(mailbox) = self.mailbox.as_mut() {
                            match mailbox.take_request() {
                                Ok(Some(req)) => {
                                    // Keep `cpu.el1.esr` synchronized with the
                                    // mailbox's saved syndrome for fault diagnostics.
                                    self.cpu.el1.esr = Syndrome(req.esr);
                                    return Ok(Aarch64Exit::Syscall {
                                        frame: req.frame,
                                        resume_pc: req.resume_pc,
                                        current_guest_sp: Some(req.sp),
                                    });
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    return Err(TrapError::Hypervisor(format!(
                                        "aarch64 syscall mailbox protocol error: {err:?}"
                                    )));
                                }
                            }
                        }
                        let syndrome = self.cpu.el1.esr.0;
                        if decode_el0_sys64_read(syndrome).is_some() {
                            return Ok(Aarch64Exit::Sys64Read { esr: syndrome });
                        }
                        return Ok(Aarch64Exit::EL0Fault {
                            syndrome,
                            elr: self.cpu.el1.elr.0,
                            far: self.cpu.el1.far.0,
                            x16: self.read_gpr(16)?,
                            x17: self.read_gpr(17)?,
                            x29: self.read_gpr(29)?,
                            x30: self.read_gpr(30)?,
                            sp: self.cpu.sp_el0.0,
                            from_el0_direct: false,
                        });
                    }
                    HvcImmediateKind::CurrentElFault => {
                        return Err(TrapError::UnexpectedException {
                            syndrome: self.cpu.el1.esr.0,
                            virtual_address: self.cpu.el1.far.0,
                            physical_address: self.cpu.el1.elr.0,
                        });
                    }
                    HvcImmediateKind::Unknown(imm) => {
                        return Err(TrapError::UnexpectedExit {
                            reason: format!(
                                "unallocated HVC #{imm} at PC={:#x} ELR={:#x} ESR={:#x}",
                                self.cpu.pc.0, self.cpu.el1.elr.0, self.cpu.el1.esr.0
                            ),
                        });
                    }
                },
                Stop::Fetch(va) => {
                    return Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "soft CPU instruction fetch fault at VA={:#x} stage2_abort={:?}",
                            va.0,
                            stage2.last_abort()
                        ),
                    });
                }
                Stop::Event {
                    instruction,
                    event: Event::MemoryFault(fault),
                } => {
                    return Err(TrapError::UnexpectedExit {
                        reason: format!(
                            "soft CPU stage-2 memory fault at GPA={:#x} PC={:#x} abort={:?}",
                            fault.address.0,
                            instruction.pc().0,
                            stage2.last_abort()
                        ),
                    });
                }
                other => {
                    return Err(TrapError::UnexpectedExit {
                        reason: format!("soft CPU stopped: {other:?} at PC={:#x}", self.cpu.pc.0),
                    });
                }
            }
        }
        Err(TrapError::UnexpectedExit {
            reason: format!(
                "soft CPU block budget ({}) exhausted at PC={:#x}",
                self.block_quantum.saturating_mul(self.max_quanta_per_exit),
                self.cpu.pc.0
            ),
        })
    }
}

enum PendingAliasInventory {
    Armed(FrameInventoryReservation),
    Committed(FrameInventoryCommit<()>),
}

/// Soft AArch64 VM backend implementing [`Aarch64Vmm`] over [`SoftStage2`].
pub struct SoftAarch64Vmm<X = HostBlockRunner> {
    stage2: Arc<ExclusiveStage2>,
    protections: Arc<MemoryProtections>,
    seat: Arc<SoftRunSeat>,
    next_alias_gpa: u64,
    pending_alias_inventory: Option<PendingAliasInventory>,
    next_inventory_generation: u64,
    executor_marker: core::marker::PhantomData<fn() -> X>,
}

/// Shared AArch64 trap/stage-1 engine parameterized over [`SoftAarch64Vmm`].
pub type SoftAarch64Engine<X = HostBlockRunner> = Aarch64EngineCore<SoftAarch64Vmm<X>>;

impl SoftAarch64Vmm<HostBlockRunner> {
    /// Bring up a [`SoftAarch64Engine`] using the native Linux arm64 [`HostBlockRunner`].
    pub fn bring_up(
        image: &AddressSpace,
        el1_elf_override: Option<&[u8]>,
        ipc: Option<Arc<dyn IpcWindowBacking>>,
    ) -> Result<SoftAarch64Engine<HostBlockRunner>, TrapError> {
        let executor = HostBlockRunner::new()
            .map_err(|e| TrapError::Hypervisor(format!("HostBlockRunner::new: {e:?}")))?;
        Self::bring_up_with_executor(image, el1_elf_override, ipc, executor)
    }
}

impl<X: ExecuteBlock + Send + 'static> SoftAarch64Vmm<X>
where
    X::Error: core::fmt::Debug,
{
    /// Bring up a [`SoftAarch64Engine`] over any [`ExecuteBlock`] implementation.
    pub fn bring_up_with_executor(
        image: &AddressSpace,
        el1_elf_override: Option<&[u8]>,
        ipc: Option<Arc<dyn IpcWindowBacking>>,
        executor: X,
    ) -> Result<SoftAarch64Engine<X>, TrapError> {
        let stage2 = populate_stage2_for_image(image, el1_elf_override, ipc)?;
        let mailbox_ptr = stage2
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .and_then(|p| NonNull::new(p.cast::<Aarch64SyscallMailbox>()));
        // SAFETY: `mailbox_ptr` points to the 4 KiB-aligned `LINUX_SYSCALL_MAILBOX_BASE`
        // window owned by `stage2`, which outlives `vcpu`.
        let mailbox = mailbox_ptr.map(|ptr| unsafe { MailboxSlot::new(ptr, 1) });

        let stage2 = Arc::new(ExclusiveStage2::new(stage2));
        let protections = Arc::new(MemoryProtections::default());
        let seat = Arc::new(SoftRunSeat::default());

        let staged = StagedCpu::initial_root(&RootBootFields {
            entry: image.entry(),
            initial_stack_pointer: image.initial_stack_pointer(),
            el0_trampoline_entry: image.el0_trampoline_entry(),
            el1_vectors_base: image.el1_vectors_base(),
            stage1_page_tables_base: image.stage1_page_tables_base(),
        });
        let mut cpu = CpuState::default();
        cpu.named.cntfrq = SystemValue(DEFAULT_CNTFRQ_HZ);
        let boot_count = soft_physical_count();
        cpu.counter = CounterSource::provider(soft_physical_count, boot_count);
        cpu.sample_counter();
        cpu.named.mpidr = SystemValue(MPIDR_AFF0_RES1);
        // What a driver's CPU bring-up programs on every carrier's GIC (HVF:
        // `carrick-vmm-hvf/src/gic.rs`): Carrick's three private interrupts
        // enabled in group 1 with their priorities, and the priority mask.
        cpu.gic.enable(
            carrick_el1_abi::GIC_VTIMER_INTID,
            carrick_el1_abi::GIC_VTIMER_PRIORITY,
        );
        cpu.gic.enable(
            carrick_el1_abi::GIC_RESCHED_INTID,
            carrick_el1_abi::GIC_RESCHED_PRIORITY,
        );
        cpu.gic.enable(
            carrick_el1_abi::GIC_KICK_INTID,
            carrick_el1_abi::GIC_KICK_PRIORITY,
        );
        cpu.gic.configure(carrick_el1_abi::GIC_PRIORITY_MASK, true);

        let mut vcpu = SoftAarch64Vcpu {
            cpu,
            monitor: ExclusiveMonitor::default(),
            executor,
            code: (std::env::var_os("CARRICK_SOFT_AARCH64_HANDOFF_CACHE").as_deref()
                != Some(std::ffi::OsStr::new("0")))
            .then(|| DispatchCache::new(ResidencyBudget::for_owner(AARCH64_RESIDENCY))),
            stage2: Arc::clone(&stage2),
            seat: Arc::clone(&seat),
            mailbox,
            actlr_el1: 0,
            cpacr_el1: 0,
            tpidrro_pending: AtomicU64::new(0),
            tpidrro_dirty: AtomicBool::new(false),
            sp_pending: AtomicU64::new(0),
            sp_dirty: AtomicBool::new(false),
            boot_count,
            block_quantum: DEFAULT_BLOCK_QUANTUM,
            max_quanta_per_exit: DEFAULT_MAX_QUANTA_PER_EXIT,
            work: RunWork::default(),
            idle_parks: 0,
            ran: false,
        };
        vcpu.restore(&staged.snapshot())?;
        if vcpu.mailbox.is_some() {
            vcpu.cpu.sp_el1 = StackPointer(LINUX_SYSCALL_MAILBOX_BASE);
        }

        let vmm = Self {
            stage2,
            protections,
            seat,
            next_alias_gpa: SOFT_ALIAS_GPA_BASE,
            pending_alias_inventory: None,
            next_inventory_generation: 1,
            executor_marker: core::marker::PhantomData,
        };
        Ok(Aarch64EngineCore::from_parts(vmm, vcpu))
    }
}

impl<X> SoftAarch64Vmm<X> {
    pub fn stage2_geometry(&self) -> Result<MappingGeometry, TrapError> {
        Ok(self.stage2.try_borrow()?.geometry())
    }

    pub fn last_stage2_abort(&self) -> Result<Option<Stage2Abort>, TrapError> {
        Ok(self.stage2.try_borrow()?.last_abort())
    }

    pub fn protect_stage2(&mut self, gpa: u64, len: u64, perms: MemPerms) -> Result<(), TrapError> {
        self.stage2.try_borrow()?.protect_stage2(gpa, len, perms)
    }

    pub fn code_generation(&self, frame: FrameGpa) -> Result<Option<CodeGeneration>, TrapError> {
        Ok(self.stage2.try_borrow()?.code_generation(frame))
    }

    /// This carrier's retained-metadata mapping capability.
    #[must_use]
    pub fn retained_metadata(&self) -> SoftRetainedMetadata {
        SoftRetainedMetadata {
            stage2: Arc::downgrade(&self.stage2),
        }
    }

    /// Issue this carrier's birth and MM source over its EL1 zone tables, the
    /// one issuer EL1 and the host kernel share for task, thread and MM
    /// identities and the PID namespace. Each call issues a distinct source
    /// identity: a kernel binds exactly one.
    pub fn birth_serial_source(
        &self,
    ) -> Result<Arc<dyn carrick_hal::birth_serial::BirthSerialSource>, TrapError> {
        let zone = self
            .stage2
            .try_borrow()?
            .host_ptr(
                EL1_REGION_BASE + carrick_el1_abi::EL1_ZONE_OFFSET,
                size_of::<carrick_el1_abi::ZoneTables>(),
            )
            .and_then(|ptr| NonNull::new(ptr.cast::<carrick_el1_abi::ZoneTables>()))
            .filter(|ptr| ptr.is_aligned())
            .ok_or_else(|| TrapError::Hypervisor("soft carrier EL1 zone is not mapped".into()))?;
        let stage2 = Arc::downgrade(&self.stage2);
        let identity = carrick_hal::birth_serial::BirthSourceIdentity::from_backend_identity(
            Arc::new(stage2.clone()),
            NonZeroU64::new(zone.as_ptr() as u64)
                .ok_or_else(|| TrapError::Hypervisor("null soft carrier EL1 zone".into()))?,
            NonZeroU64::MIN,
        );
        Ok(Arc::new(SoftBirthZone {
            stage2,
            zone,
            identity,
        }))
    }
}

/// The soft carrier's one vCPU, on mailbox slot 0.
const SOFT_CPU: carrick_guest_arch::CpuId = carrick_guest_arch::CpuId::new(0);

/// Authenticate a stopped soft vCPU's native root-exit crossing
/// (`GRANT_OP_ROOT_EXIT`) as HVF does: the record lies on this CPU's EL1
/// stack and names the issued execution installed under `ttbr0`.
fn authenticated_root_exit(
    stage2: &SoftStage2,
    record_va: u64,
    cpu: u64,
    ttbr0: u64,
) -> Option<Aarch64Exit> {
    use carrick_aarch64::stopped_abi::{RetainedAbiRegion, root_stack_record, stopped_execution};

    if !record_va.is_multiple_of(64) || cpu != u64::from(SOFT_CPU.raw()) {
        return None;
    }
    let base = stage2.host_ptr(EL1_REGION_BASE, EL1_REGION_SIZE as usize)?;
    // SAFETY: the borrowed stage 2 retains the initialized EL1 region, and
    // its only vCPU is stopped at this crossing.
    let region = unsafe { RetainedAbiRegion::new(base, EL1_REGION_SIZE as usize) }?;
    let execution = stopped_execution(region, SOFT_CPU, ttbr0)?;
    let record = root_stack_record(
        region,
        SOFT_CPU,
        carrick_guest_arch::KernelVa::new(record_va),
    )?;
    Some(Aarch64Exit::NativeRootExit {
        status: record.status_for(execution.binding)?,
        binding: execution.binding,
    })
}

/// One soft carrier's EL1 zone tables, retained for birth and MM issuance.
/// It names its carrier weakly: once that stage 2 drops, issuance refuses.
struct SoftBirthZone {
    stage2: Weak<ExclusiveStage2>,
    zone: NonNull<carrick_el1_abi::ZoneTables>,
    identity: carrick_hal::birth_serial::BirthSourceIdentity,
}

impl core::fmt::Debug for SoftBirthZone {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SoftBirthZone")
            .field(&self.identity)
            .finish()
    }
}

// SAFETY: `zone` points into the EL1 region the stage 2 owns; it is only
// dereferenced while an upgraded `stage2` keeps that mapping alive, and only
// the zone's atomic issuers and leaf-locked namespace are touched.
unsafe impl Send for SoftBirthZone {}
unsafe impl Sync for SoftBirthZone {}

impl carrick_hal::birth_serial::RetainedBirthZone for SoftBirthZone {
    type Context = carrick_el1_abi::Aarch64ParkedContext;

    fn source_identity(&self) -> &carrick_hal::birth_serial::BirthSourceIdentity {
        &self.identity
    }

    fn with_retained_zone<T>(
        &self,
        op: impl FnOnce(&carrick_el1_abi::ZoneTables) -> T,
    ) -> Result<T, carrick_hal::birth_serial::BirthSourceError> {
        let _stage2 = self
            .stage2
            .upgrade()
            .ok_or(carrick_hal::birth_serial::BirthSourceError::StaleOwner)?;
        // SAFETY: the upgraded stage 2 owns the EL1 region mapping, which is
        // never unmapped before the stage 2 drops; `zone` is aligned inside it.
        Ok(op(unsafe { self.zone.as_ref() }))
    }
}

fn populate_stage2_for_image(
    image: &AddressSpace,
    el1_elf_override: Option<&[u8]>,
    ipc: Option<Arc<dyn IpcWindowBacking>>,
) -> Result<SoftStage2, TrapError> {
    let mut stage2 = SoftStage2::new()?;
    for region in image.regions() {
        let len = region.len();
        if len == 0 {
            continue;
        }
        let perms = MemPerms {
            read: region.perms.read,
            write: region.perms.write,
            exec: region.perms.execute,
        };
        stage2.map_owned_anonymous(region.start, len, perms, region.shared)?;
        let (init_off, bytes) = region.shared_initialized_bytes();
        if !bytes.is_empty() {
            let init_gpa = region
                .start
                .checked_add(init_off)
                .ok_or_else(|| TrapError::Hypervisor("region init offset overflow".to_owned()))?;
            stage2.write_gpa_bytes(init_gpa, &bytes)?;
        }
    }

    // Ensure the carrier maintenance root exists when an EL1 kernel region
    // is present.
    if stage2
        .host_ptr(LINUX_EL1_KERNEL_BASE, PAGE_BYTES_USIZE)
        .is_some()
    {
        if let Some(el1_elf) = el1_elf_override {
            overlay_el1_elf(&mut stage2, el1_elf)?;
        }
        // Enforce EL1 stack guard pages at stage 2 in addition to stage 1.
        let mut page = LINUX_EL1_KERNEL_BASE;
        while page < LINUX_EL1_KERNEL_BASE + LINUX_EL1_KERNEL_SIZE {
            if is_el1_stack_guard(page) {
                stage2.protect_stage2(
                    page,
                    GUEST_PAGE_BYTES,
                    MemPerms {
                        read: false,
                        write: false,
                        exec: false,
                    },
                )?;
            }
            page += GUEST_PAGE_BYTES;
        }
        // The dynamic metadata aperture stays unmapped at stage 2 until the
        // carrier maps retained ABI storage into it
        // (`SoftStage2::map_retained_metadata`), as on HVF.
        if stage2
            .host_ptr(LINUX_CARRIER_MAINT_ROOT_BASE, PAGE_BYTES_USIZE)
            .is_none()
        {
            let maint_tables = stage1_carrier_maintenance_page_tables();
            stage2.map_owned_anonymous(
                LINUX_CARRIER_MAINT_ROOT_BASE,
                maint_tables.len() as u64,
                MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                true,
            )?;
            stage2.write_gpa_bytes(LINUX_CARRIER_MAINT_ROOT_BASE, &maint_tables)?;
        }
        if stage2
            .host_ptr(LINUX_FD_CEILING_CONTROL_BASE, PAGE_BYTES_USIZE)
            .is_none()
        {
            stage2.map_owned_anonymous(
                LINUX_FD_CEILING_CONTROL_BASE,
                LINUX_FD_CEILING_CONTROL_SIZE,
                MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                true,
            )?;
        }
    }

    if let Some(ipc) = ipc {
        let dir_ptr = NonNull::new(ipc.directory_ptr())
            .ok_or_else(|| TrapError::Hypervisor("null IPC directory pointer".to_owned()))?;
        let pool_ptr = NonNull::new(ipc.pool_ptr())
            .ok_or_else(|| TrapError::Hypervisor("null IPC pool pointer".to_owned()))?;
        let dir_len = ipc.directory_len() as u64;
        let pool_len = ipc.pool_len() as u64;
        let rw = MemPerms {
            read: true,
            write: true,
            exec: false,
        };
        // SAFETY: `stage2.retain_ipc_backing(ipc)` pins both allocations for the
        // entire lifetime of `stage2`.
        unsafe {
            stage2.map_external_stage2(EL1_IPC_BASE, dir_ptr, dir_len, rw, true)?;
            stage2.map_external_stage2(EL1_IPC_POOL_BASE, pool_ptr, pool_len, rw, true)?;
        }
        stage2.retain_ipc_backing(ipc);
    }

    Ok(stage2)
}

fn overlay_el1_elf(stage2: &mut SoftStage2, el1_elf: &[u8]) -> Result<(), TrapError> {
    let plan = carrick_mem::elf::plan_elf_load_bytes_for(el1_elf, 183)
        .map_err(|e| TrapError::Hypervisor(format!("parse EL1 ELF override: {e}")))?;
    let image_span = usize::try_from(LINUX_EL1_IMAGE_SIZE.raw())
        .map_err(|_| TrapError::Hypervisor("EL1 image size overflow".to_owned()))?;
    zero_range_chunked(LINUX_EL1_KERNEL_BASE, image_span, |addr, zeros| {
        stage2
            .write_gpa_bytes(addr, zeros)
            .map_err(|_| MemoryError::OutOfBounds {
                address: addr,
                length: zeros.len(),
            })
    })
    .map_err(|e| TrapError::Hypervisor(format!("zero EL1 image: {e}")))?;
    for seg in &plan.segments {
        let file_off = usize::try_from(seg.file_offset)
            .map_err(|_| TrapError::Hypervisor("EL1 segment offset overflow".to_owned()))?;
        let file_sz = usize::try_from(seg.file_size)
            .map_err(|_| TrapError::Hypervisor("EL1 segment size overflow".to_owned()))?;
        let slice = el1_elf
            .get(file_off..file_off.saturating_add(file_sz))
            .ok_or_else(|| TrapError::Hypervisor("EL1 segment truncated".to_owned()))?;
        stage2.write_gpa_bytes(seg.virtual_address, slice)?;
    }
    if let Some(loaded_ptr) = stage2.host_ptr(LINUX_EL1_KERNEL_BASE, image_span) {
        // SAFETY: `loaded_ptr` spans `image_span` initialized bytes in `stage2`.
        let loaded_image =
            unsafe { core::slice::from_raw_parts(loaded_ptr.cast_const(), image_span) };
        carrick_el1_abi::check_image_abi(loaded_image)
            .map_err(|e| TrapError::Hypervisor(format!("EL1 image ABI mismatch: {e:?}")))?;
    }
    stage2.write_gpa_bytes(EL1_STACK_GUARD_TABLES_BASE, &el1_stack_guard_tables())?;
    Ok(())
}

impl<X> GuestVmBackend for SoftAarch64Vmm<X> {
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.stage2.try_borrow().ok()?.host_ptr(gpa, len)
    }

    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        self.stage2.try_borrow()?.write_gpa_bytes(gpa, bytes)
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        ForkRamStrategy::Cow
    }

    fn wait_for_vcpu_slot() {}
}

impl<X: ExecuteBlock + Send + 'static> Aarch64Vmm for SoftAarch64Vmm<X>
where
    X::Error: core::fmt::Debug,
{
    type Vcpu = SoftAarch64Vcpu<X>;
    type AnonymousDiscard = ();
    type KickHandle = SoftKickHandle;
    type SiblingBuilder = ();
    type ProcessBuilder = ();

    fn publish_user_executable(&self, output: u64, len: u64) -> Result<(), PageTableError> {
        let mut stage2 = self
            .stage2
            .try_borrow()
            .map_err(|_| PageTableError::UnresolvedArena(output))?;
        let size = usize::try_from(len).map_err(|_| PageTableError::BadAddress)?;
        if stage2.host_ptr(output, size).is_none() {
            return Err(PageTableError::UnresolvedArena(output));
        }
        let end = output.checked_add(len).ok_or(PageTableError::BadAddress)?;
        let first = output & !(GUEST_PAGE_BYTES - 1);
        let last = end.saturating_sub(1) & !(GUEST_PAGE_BYTES - 1);
        let mut frame = first;
        while frame <= last {
            let _ = stage2.invalidate_code_frame(FrameGpa::new(frame));
            frame += GUEST_PAGE_BYTES;
        }
        Ok(())
    }

    fn carrier_maintenance_root(&self) -> Result<CarrierMaintenanceRoot, TrapError> {
        Ok(CarrierMaintenanceRoot::new(Gpa::new(
            LINUX_CARRIER_MAINT_ROOT_BASE,
        )))
    }

    fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: MemPerms,
    ) -> Result<(), TrapError> {
        let ptr = NonNull::new(host)
            .ok_or_else(|| TrapError::Hypervisor("map_stage2 given null host ptr".to_owned()))?;
        // SAFETY: `Aarch64Vmm::map_stage2` caller retains `host` for the mapping's life.
        unsafe {
            self.stage2
                .try_borrow()?
                .map_external_stage2(ipa, ptr, len, perms, false)
        }
    }

    fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        let mut out = vec![0u8; len];
        self.stage2.try_borrow()?.read_gpa_bytes(gpa, &mut out)?;
        Ok(out)
    }

    fn protections(&self) -> Option<LegacyProtectionRead<'_>> {
        Some(LegacyProtectionRead::borrowed(&self.protections))
    }

    fn exec_protections(&self) -> Option<UserMemoryAuthority> {
        Some(UserMemoryAuthority::from_legacy(Arc::clone(
            &self.protections,
        )))
    }

    fn translated_read(&self, va: u64, ipa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let mut out = vec![0u8; len];
        self.translated_read_into(va, ipa, &mut out)?;
        Ok(out)
    }

    fn translated_read_into(&self, va: u64, ipa: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        self.stage2
            .try_borrow()
            .map_err(|e| MemoryError::HostMap(e.to_string()))?
            .read_gpa_bytes(ipa, dst)
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: dst.len(),
            })
    }

    fn translated_write(&mut self, va: u64, ipa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.stage2
            .try_borrow()
            .map_err(|e| MemoryError::HostMap(e.to_string()))?
            .write_gpa_bytes(ipa, bytes)
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: bytes.len(),
            })
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        let mut stage2 = self
            .stage2
            .try_borrow()
            .map_err(|e| MemoryError::HostMap(e.to_string()))?;
        zero_range_chunked(address, len, |addr, zeros| {
            stage2
                .write_gpa_bytes(addr, zeros)
                .map_err(|_| MemoryError::OutOfBounds {
                    address: addr,
                    length: zeros.len(),
                })
        })
    }

    fn begin_alias_inventory(
        &mut self,
        reservation: FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        if self.pending_alias_inventory.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping soft AArch64 alias inventory transaction".to_owned(),
            ));
        }
        self.pending_alias_inventory = Some(PendingAliasInventory::Armed(reservation));
        Ok(())
    }

    fn take_alias_inventory(&mut self) -> Option<FrameInventoryCommit<()>> {
        match self.pending_alias_inventory.take() {
            Some(PendingAliasInventory::Committed(commit)) => Some(commit),
            other => {
                self.pending_alias_inventory = other;
                None
            }
        }
    }

    fn abandon_alias_inventory(&mut self) -> bool {
        self.pending_alias_inventory.take().is_some()
    }

    fn shared_futex_location(&self, backing_gpa: Gpa) -> Option<SharedFutexLocation> {
        let word = self
            .stage2
            .try_borrow()
            .ok()?
            .shared_futex_host_addr(backing_gpa.raw(), 4)?;
        let word_usize = usize::try_from(word).ok()?;
        Some(SharedFutexLocation::Direct {
            word: HostVa::new(word_usize),
            waiter_key: word_usize,
        })
    }

    fn add_alias(
        &mut self,
        _va: u64,
        _ipa: u64,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(u64, bool), TrapError> {
        let mut stage2 = self.stage2.try_borrow()?;
        let aligned_len = stage2
            .geometry()
            .align_up_guest(len)
            .filter(|v| *v > 0)
            .ok_or_else(|| TrapError::Hypervisor(format!("invalid alias length {len:#x}")))?;
        let gpa = stage2
            .allocate_free_gpa(self.next_alias_gpa, SOFT_ALIAS_GPA_LIMIT, aligned_len)
            .or_else(|| {
                stage2.allocate_free_gpa(SOFT_ALIAS_GPA_BASE, SOFT_ALIAS_GPA_LIMIT, aligned_len)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor("soft stage-2 alias arena exhausted".to_owned())
            })?;

        let writable = match &backing {
            HostAliasBacking::Anonymous { .. } => true,
            HostAliasBacking::File {
                host_prot, sharing, ..
            } => match sharing {
                HostAliasSharing::Private => true,
                HostAliasSharing::Shared => (*host_prot & libc::PROT_WRITE) != 0,
            },
        };
        let perms = MemPerms::ReadWriteExec;

        match backing {
            HostAliasBacking::Anonymous { sharing } => {
                stage2.map_owned_anonymous(gpa, aligned_len, perms, sharing.is_shared())?;
                if !payload.is_empty() {
                    stage2.write_gpa_bytes(gpa, payload)?;
                }
            }
            HostAliasBacking::File {
                fd,
                offset,
                host_prot,
                sharing,
            } => {
                stage2.map_file_alias(
                    gpa,
                    aligned_len,
                    FileAliasSpec {
                        raw_fd: fd.as_raw_fd(),
                        offset,
                        host_prot,
                        sharing,
                        perms,
                    },
                )?;
            }
        }
        if aligned_len <= 0x1_0000_0000
            && let Some(next) = gpa.checked_add(aligned_len)
            && next < SOFT_ALIAS_GPA_LIMIT
        {
            self.next_alias_gpa = next;
        }
        drop(stage2);

        if let Some(PendingAliasInventory::Armed(mut reservation)) =
            self.pending_alias_inventory.take()
        {
            let transaction = reservation.transaction();
            let frame = reservation
                .claim_frame()
                .map_err(|e| TrapError::Hypervisor(format!("alias claim_frame: {e}")))?;
            let mapping = reservation
                .claim_mapping()
                .map_err(|e| TrapError::Hypervisor(format!("alias claim_mapping: {e}")))?;
            let raw_gen = NonZeroU64::new(self.next_inventory_generation).ok_or_else(|| {
                TrapError::Hypervisor("alias generation wrapped to zero".to_owned())
            })?;
            self.next_inventory_generation = self.next_inventory_generation.saturating_add(1);
            let generation = MappingGeneration::from_backend_counter(raw_gen);
            let length_nz = NonZeroU64::new(aligned_len)
                .ok_or_else(|| TrapError::Hypervisor("alias zero aligned_len".to_owned()))?;
            let length = FrameLength::from_mapping_extent(length_nz);
            let inv_perms = MemPerms {
                read: true,
                write: writable,
                exec: false,
            };
            reservation
                .push(FrameInventoryEvent::PrepareMapping {
                    transaction,
                    frame,
                    mapping,
                    generation,
                    gpa: Gpa::new(gpa),
                    length,
                    permissions: inv_perms,
                })
                .map_err(|e| TrapError::Hypervisor(format!("alias PrepareMapping: {e}")))?;
            reservation
                .push(FrameInventoryEvent::PublishMapping {
                    transaction,
                    mapping,
                    generation,
                })
                .map_err(|e| TrapError::Hypervisor(format!("alias PublishMapping: {e}")))?;
            self.pending_alias_inventory =
                Some(PendingAliasInventory::Committed(reservation.commit(())));
        }

        Ok((gpa, writable))
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        Err(TrapError::Hypervisor(
            "SoftAarch64Vmm single-process facade does not implement sibling vCPUs (#1236 M2 R1)"
                .to_owned(),
        ))
    }

    fn execve_rebuild(
        &mut self,
        _vcpu: &mut Self::Vcpu,
        _new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "SoftAarch64Vmm single-process facade does not implement execve_rebuild (#1236 M2 R1)"
                .to_owned(),
        ))
    }

    fn kick_handle(&self) -> Self::KickHandle {
        SoftKickHandle {
            seat: Arc::clone(&self.seat),
        }
    }

    fn build_sibling_builder(
        &self,
        _vcpu: &Self::Vcpu,
        _entry: GuestEntryRegs,
    ) -> Result<Self::SiblingBuilder, TrapError> {
        Err(TrapError::Hypervisor(
            "SoftAarch64Vmm single-process facade does not implement sibling threads (#1236 M2 R1)"
                .to_owned(),
        ))
    }

    fn materialize_sibling(
        _builder: Self::SiblingBuilder,
    ) -> Result<(Self, Self::Vcpu), TrapError> {
        Err(TrapError::Hypervisor(
            "SoftAarch64Vmm single-process facade does not implement sibling threads (#1236 M2 R1)"
                .to_owned(),
        ))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        vcpu.sp_pending.store(sp, Ordering::Relaxed);
        vcpu.sp_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
        Arc::new(GenericVcpuRegistry::new())
    }

    /// The soft root's MM is portal-admitted through this custody (#2814).
    fn owner_transfer_custody(&self) -> Option<Box<ErasedPhysicalCustody>> {
        Some(Box::new(ErasedTransferCustody(SoftTransferCustody {
            stage2: Arc::downgrade(&self.stage2),
            carrier: self.stage2.carrier.raw(),
        })))
    }

    /// Soft file windows are mapped whole when they are added, so no lazy
    /// file grant is ever owed. One reaching here fails the run loudly; it
    /// must never decline and turn a valid page into the fault's `SIGSEGV`.
    fn prepare_owner_frame_grant(
        &self,
        _target: TransferTarget,
        _window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<TransferPreparation, TrapError> {
        Err(SoftTransferCustody::refuse("lazy file grants"))
    }
}

/// The soft carrier's physical half of UserTransfer (#2814, #1236 step 1b).
/// EL1 selects and authorizes the user VA; this resolves only its IPA, by
/// pinning the carrier core's frame extent that holds it. The byte rules are
/// the shared [`RetainedCopy`]'s.
struct SoftTransferCustody {
    stage2: Weak<ExclusiveStage2>,
    carrier: NonZeroU64,
}

impl SoftTransferCustody {
    fn refuse(what: &str) -> TrapError {
        TrapError::Hypervisor(format!(
            "the soft carrier does not serve {what} yet (#1236 step 1b)"
        ))
    }
}

impl TransferCustody for SoftTransferCustody {
    type Pin = SoftRetainedUserData;

    fn carrier(&self) -> NonZeroU64 {
        self.carrier
    }

    /// Soft guest RAM is host-backed when its window is mapped, so an owner
    /// grant is never needed to back it. One reaching here is a defect to
    /// find, so it fails the run loudly rather than declining.
    fn prepare(
        &self,
        _target: TransferTarget,
        _window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<TransferPreparation, TrapError> {
        Err(Self::refuse("owner grants"))
    }

    fn publish_executable(
        &self,
        _target: TransferTarget,
        _request: carrick_core_abi::PortalExecutablePublication,
    ) -> bool {
        false
    }

    /// No copy-on-write state exists before the soft carrier can fork.
    fn refill_cow(
        &self,
        _target: TransferTarget,
        _window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<bool, TrapError> {
        Ok(false)
    }

    fn retain(
        &self,
        selected: carrick_el1_abi::PortalSelectedData,
        len: usize,
        intent: carrick_el1_abi::PortalTransferIntent,
    ) -> Result<Option<Self::Pin>, TrapError> {
        let invariant =
            || TrapError::Hypervisor("soft UserTransfer custody invariant refused".to_owned());
        if len == 0 || len > PAGE_BYTES_USIZE {
            return Err(invariant());
        }
        let cell = self.stage2.upgrade().ok_or_else(invariant)?;
        let mut stage2 = cell.try_borrow()?;
        let pin = match stage2.pin_transfer(selected.ipa, len as u64) {
            Ok(pin) => pin,
            // Absent backing: the owner may select again.
            Err(PinRefusal::NoLiveExtent) => return Ok(None),
            // A known extent overrun, or an exhausted pin count, is permanent.
            Err(reason) => {
                return Err(TrapError::Hypervisor(format!(
                    "soft UserTransfer pin refused: {reason:?}"
                )));
            }
        };
        let identity = carrick_el1_abi::PortalRetainedData {
            record: pin.extent().record(),
            vm_generation: NonZeroU64::new(stage2.generation().0).ok_or_else(invariant)?,
            owner: None,
        };
        let pointer = pin.host_addr() as *mut u8;
        drop(stage2);
        // SAFETY: the core pin keeps the frame extent, and with it the
        // window's host backing, alive until `SoftRetainedUserData` drops.
        let bytes =
            unsafe { RetainedCopy::new(self.carrier, identity, selected, intent, pointer, len) };
        Ok(Some(SoftRetainedUserData {
            stage2: Arc::downgrade(&cell),
            pin: Some(pin),
            bytes,
        }))
    }
}

/// One soft transfer's retention: a core pin on the frame extent, and the
/// shared byte rules over its host bytes.
struct SoftRetainedUserData {
    stage2: Weak<ExclusiveStage2>,
    pin: Option<CorePin>,
    bytes: RetainedCopy,
}

impl SoftRetainedUserData {
    /// A completed write advances the written frames' code generations.
    fn publish_completed_write(&self, len: usize) -> bool {
        let Some(cell) = self.stage2.upgrade() else {
            return false;
        };
        let Ok(mut stage2) = cell.try_borrow() else {
            return false;
        };
        stage2.invalidate_transfer_write(self.bytes.selected().ipa, len as u64)
    }
}

impl TransferPin for SoftRetainedUserData {
    fn identity(&self) -> carrick_el1_abi::PortalRetainedData {
        self.bytes.identity()
    }

    fn copy(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &mut [u8]) -> bool {
        if self.bytes.intent().is_write() {
            self.copy_out(request, bytes)
        } else {
            self.bytes.copy(request, TransferBytes::Read(bytes))
        }
    }

    fn copy_out(&mut self, request: carrick_el1_abi::PortalCopyRequest<'_>, bytes: &[u8]) -> bool {
        if !self.bytes.intent().is_write() || !self.bytes.copy(request, TransferBytes::Write(bytes))
        {
            return false;
        }
        if !self.publish_completed_write(bytes.len()) {
            soft_carrier_broken(format_args!("completed write publication failed"));
        }
        true
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        request: carrick_el1_abi::PortalCopyRequest<'_>,
        expected: u32,
        desired: u32,
    ) -> Option<u32> {
        let observed = self
            .bytes
            .compare_exchange_u32(request, expected, desired)?;
        if observed == expected && !self.publish_completed_write(4) {
            return None;
        }
        Some(observed)
    }
}

impl Drop for SoftRetainedUserData {
    /// Return the core pin. The soft carrier has one vCPU, and a transfer
    /// drops its pin between guest instructions, so the stage 2 is never
    /// borrowed here; if it were, the pin would leak into a terminal extent
    /// and the carrier's drop check would end it.
    fn drop(&mut self) {
        let Some(pin) = self.pin.take() else {
            return;
        };
        let Some(cell) = self.stage2.upgrade() else {
            return;
        };
        match cell.try_borrow() {
            Ok(mut stage2) => stage2.unpin_transfer(pin),
            Err(_) => soft_carrier_broken(format_args!(
                "a transfer pin dropped while the soft stage 2 was borrowed"
            )),
        }
    }
}

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
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use carrick_aarch64::esr::decode_el0_sys64_read;
use carrick_aarch64::mailbox::{
    AARCH64_SYSCALL_MAILBOX_SIZE, Aarch64SyscallMailbox, HvcImmediateKind, MailboxSlot,
    classify_hvc_immediate,
};
use carrick_aarch64::staged_cpu::{RootBootFields, StagedCpu};
use carrick_aarch64::{
    Aarch64EngineCore, Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy,
};
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_SIZE, EL1_IPC_BASE, EL1_IPC_POOL_BASE,
    EL1_STACK_GUARD_TABLES_BASE, IpcWindowBacking, is_el1_stack_guard,
};
use carrick_guest_arch::FrameGpa;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{
    Gpa, HostVa, LegacyProtectionRead, MemoryError, SharedFutexLocation, UserMemoryAuthority,
    zero_range_chunked,
};
use carrick_hal::{
    GenericVcpuRegistry, GuestEntryRegs, GuestVmBackend, HostAliasBacking, HostAliasSharing,
    MemPerms, OsError, Reg, SysReg, TrapError, VcpuKick, VcpuRegistry,
};
use carrick_mem::memory::{
    AddressSpace, CarrierMaintenanceRoot, LINUX_CARRIER_MAINT_ROOT_BASE, LINUX_EL1_IMAGE_SIZE,
    LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE, LINUX_FD_CEILING_CONTROL_BASE,
    LINUX_FD_CEILING_CONTROL_SIZE, LINUX_SYSCALL_MAILBOX_BASE, el1_stack_guard_tables,
    stage1_carrier_maintenance_page_tables,
};
use carrick_mmu_core::aarch64::PageTableError;
use carrick_softcpu_aarch64::dispatch::{ExecuteBlock, RunControl, Stop, run_controlled};
use carrick_softcpu_aarch64::exception::Syndrome;
use carrick_softcpu_aarch64::handler::{
    CodeGeneration, Event, ExclusiveMonitor, GuestMemory as SoftGuestMemory, InlineRam, MemoryFault,
};
use carrick_softcpu_aarch64::state::{
    CpuState, ProgramCounter, Pstate, RegisterValue, SavedPstate, Sctlr, StackPointer, SystemValue,
    VirtualAddress,
};
use carrick_softcpu_aarch64::translate::BlockLimits;
use carrick_softcpu_aarch64::{Gpr, Hint, OperandRegister};
use carrick_softmmu::{ExtentRecord, ExtentTable, OwnerGeneration, PAGE_SIZE_4K};

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
const DEFAULT_CNTFRQ_HZ: u64 = 1_000_000_000;
const MPIDR_AFF0_RES1: u64 = 0x8000_0000;

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

struct Stage2Window {
    start: u64,
    end: u64,
    host: NonNull<u8>,
    default_perms: MemPerms,
    shared: bool,
    _backing: WindowBacking,
}

// SAFETY: `Stage2Window` owns an isolated `mmap` or caller-pinned shared window
// accessed only through `ExclusiveStage2`'s Acquire/Release borrow guard.
unsafe impl Send for Stage2Window {}

/// Stage-2 GPA translation, permission enforcement, and `ExtentTable` code-page
/// generation authority for the soft AArch64 VMM.
pub struct SoftStage2 {
    geometry: MappingGeometry,
    extents: ExtentTable,
    windows: BTreeMap<u64, Stage2Window>,
    page_perms: BTreeMap<u64, MemPerms>,
    last_abort: Option<Stage2Abort>,
    _ipc_pin: Option<Arc<dyn IpcWindowBacking>>,
}

impl SoftStage2 {
    pub fn new() -> Result<Self, TrapError> {
        let extents = ExtentTable::new()
            .map_err(|e| TrapError::Hypervisor(format!("soft stage-2 extent table: {e:?}")))?;
        Ok(Self {
            geometry: MappingGeometry::probe(),
            extents,
            windows: BTreeMap::new(),
            page_perms: BTreeMap::new(),
            last_abort: None,
            _ipc_pin: None,
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

    fn window_for_range(&self, gpa: u64, len: usize) -> Option<&Stage2Window> {
        let end = gpa.checked_add(u64::try_from(len).ok()?)?;
        let (_, window) = self.windows.range(..=gpa).next_back()?;
        if len == 0 {
            (gpa <= window.end).then_some(window)
        } else {
            (end <= window.end).then_some(window)
        }
    }

    fn perms_for_frame(&self, window: &Stage2Window, frame_gpa: u64) -> MemPerms {
        self.page_perms
            .get(&frame_gpa)
            .copied()
            .unwrap_or(window.default_perms)
    }

    fn check_no_overlap(&self, start: u64, end: u64) -> Result<(), TrapError> {
        if !start.is_multiple_of(GUEST_PAGE_BYTES)
            || !end.is_multiple_of(GUEST_PAGE_BYTES)
            || end <= start
        {
            return Err(TrapError::Hypervisor(format!(
                "unaligned or empty stage-2 range {start:#x}..{end:#x}"
            )));
        }
        if let Some((_, prev)) = self.windows.range(..end).next_back()
            && prev.end > start
        {
            return Err(TrapError::Hypervisor(format!(
                "overlapping stage-2 window {start:#x}..{end:#x} vs {:#x}..{:#x}",
                prev.start, prev.end
            )));
        }
        Ok(())
    }

    /// Find the lowest unmapped 4 KiB-aligned GPA range of size `len` within
    /// `[min_gpa, limit_gpa)`.
    #[must_use]
    pub fn allocate_free_gpa(&self, min_gpa: u64, limit_gpa: u64, len: u64) -> Option<u64> {
        let len = self.geometry.align_up_guest(len).filter(|v| *v > 0)?;
        let mut cursor = self.geometry.align_up_guest(min_gpa)?;
        for window in self.windows.values() {
            if window.end <= cursor {
                continue;
            }
            if cursor
                .checked_add(len)
                .is_some_and(|end| end <= window.start && end <= limit_gpa)
            {
                return Some(cursor);
            }
            cursor = self.geometry.align_up_guest(window.end)?;
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
        self.check_no_overlap(gpa, end)?;

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
        if !self
            .extents
            .install(ExtentRecord::new(FrameGpa::new(gpa), guest_len, OWNER))
        {
            return Err(TrapError::Hypervisor(format!(
                "ExtentTable refused stage-2 install at {gpa:#x}..{end:#x}"
            )));
        }
        self.windows.insert(
            gpa,
            Stage2Window {
                start: gpa,
                end,
                host: base,
                default_perms: perms,
                shared,
                _backing: backing,
            },
        );
        Ok(base)
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
        self.check_no_overlap(gpa, end)?;

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
        if !self
            .extents
            .install(ExtentRecord::new(FrameGpa::new(gpa), guest_len, OWNER))
        {
            return Err(TrapError::Hypervisor(format!(
                "ExtentTable refused file alias at {gpa:#x}..{end:#x}"
            )));
        }
        self.windows.insert(
            gpa,
            Stage2Window {
                start: gpa,
                end,
                host: base,
                default_perms: perms,
                shared,
                _backing: backing,
            },
        );
        Ok(())
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
        self.check_no_overlap(gpa, end)?;
        if !self
            .extents
            .install(ExtentRecord::new(FrameGpa::new(gpa), guest_len, OWNER))
        {
            return Err(TrapError::Hypervisor(format!(
                "ExtentTable refused external stage-2 install at {gpa:#x}..{end:#x}"
            )));
        }
        self.windows.insert(
            gpa,
            Stage2Window {
                start: gpa,
                end,
                host,
                default_perms: perms,
                shared,
                _backing: WindowBacking::External,
            },
        );
        Ok(())
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
        let Some(window) = self.windows.get(&gpa) else {
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
        self.windows.remove(&gpa);
        Ok(())
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

/// Cross-thread kick handle interrupting `SoftAarch64Vcpu::run` at a block boundary.
#[derive(Clone)]
pub struct SoftKickHandle {
    control: Arc<RunControl>,
}

impl VcpuKick for SoftKickHandle {
    fn kick(&self) {
        self.control.kick();
    }
}

/// Sibling vCPU materialization payload for `SoftAarch64Vmm`.
pub struct SoftSiblingBuilder<X> {
    stage2: Arc<ExclusiveStage2>,
    protections: Arc<MemoryProtections>,
    make_executor: Arc<dyn Fn() -> Result<X, TrapError> + Send + Sync>,
    boot_instant: Instant,
}

/// Soft AArch64 vCPU implementing [`carrick_aarch64::Aarch64Vcpu`].
pub struct SoftAarch64Vcpu<X> {
    cpu: CpuState,
    monitor: ExclusiveMonitor,
    executor: X,
    stage2: Arc<ExclusiveStage2>,
    control: Arc<RunControl>,
    mailbox: Option<MailboxSlot>,
    actlr_el1: u64,
    cpacr_el1: u64,
    tpidrro_pending: AtomicU64,
    tpidrro_dirty: AtomicBool,
    sp_pending: AtomicU64,
    sp_dirty: AtomicBool,
    boot_instant: Instant,
    block_quantum: u64,
    max_quanta_per_exit: u64,
}

impl<X> SoftAarch64Vcpu<X> {
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
            return mailbox
                .publish_normal_return(return_value)
                .map_err(|e| TrapError::Hypervisor(e.to_string()));
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
                .map_err(|e| TrapError::Hypervisor(e.to_string()));
        }
        self.complete_syscall_return(return_value)
    }

    fn pending_syscall_return(&self) -> Result<Option<i64>, TrapError> {
        let Some(mailbox) = self.mailbox.as_ref() else {
            return Ok(None);
        };
        mailbox
            .pending_normal_return()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn prepare_register_resume(&mut self) -> Result<(), TrapError> {
        if let Some(mailbox) = self.mailbox.as_mut() {
            mailbox
                .prepare_register_resume()
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }
        Ok(())
    }

    fn stamp_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        self.tpidrro_pending.store(tid, Ordering::Relaxed);
        self.tpidrro_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn kick(&self) -> Result<(), TrapError> {
        self.control.kick();
        Ok(())
    }

    fn set_pending_irq(&mut self, pending: bool) -> Result<(), TrapError> {
        if pending {
            self.control.request_irq();
        }
        Ok(())
    }

    fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
        self.sync_shared_overrides();
        let mut stage2 = self.stage2.try_borrow()?;
        for _ in 0..self.max_quanta_per_exit {
            let elapsed_ns =
                u64::try_from(self.boot_instant.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.cpu.named.cntvct = SystemValue(elapsed_ns);
            let report = run_controlled(
                &mut self.cpu,
                &mut self.monitor,
                &mut *stage2,
                &mut self.executor,
                BlockLimits::default(),
                self.block_quantum,
                &self.control,
            );
            match report.stop {
                Stop::Budget => continue,
                Stop::Kicked => return Ok(Aarch64Exit::Kicked),
                Stop::Event {
                    event: Event::Hint(Hint::Wfi | Hint::Wfe),
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
                    HvcImmediateKind::MetadataGrant => {
                        // `SoftStage2` backs the full `EL1_DYNAMIC_METADATA_SIZE`
                        // window on demand; complete any pending grant request in place.
                        if let Some(mb) = carrick_el1_abi::metadata_mailbox_host()
                            && let Some(req) = mb.claim_request()
                        {
                            mb.publish_response(0, req.arg1, req.arg2, req.arg3);
                        }
                        continue;
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
                                    return Err(TrapError::Hypervisor(err.to_string()));
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

/// Soft AArch64 VM backend implementing [`Aarch64Vmm`] over [`SoftStage2`].
pub struct SoftAarch64Vmm<X = HostBlockRunner> {
    stage2: Arc<ExclusiveStage2>,
    protections: Arc<MemoryProtections>,
    control: Arc<RunControl>,
    next_alias_gpa: u64,
    make_executor: Arc<dyn Fn() -> Result<X, TrapError> + Send + Sync>,
    boot_instant: Instant,
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
        Self::bring_up_with_executor(
            image,
            el1_elf_override,
            ipc,
            executor,
            Arc::new(|| {
                HostBlockRunner::new()
                    .map_err(|e| TrapError::Hypervisor(format!("HostBlockRunner::new: {e:?}")))
            }),
        )
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
        make_executor: Arc<dyn Fn() -> Result<X, TrapError> + Send + Sync>,
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
        let control = Arc::new(RunControl::default());
        let boot_instant = Instant::now();

        let staged = StagedCpu::initial_root(&RootBootFields {
            entry: image.entry(),
            initial_stack_pointer: image.initial_stack_pointer(),
            el0_trampoline_entry: image.el0_trampoline_entry(),
            el1_vectors_base: image.el1_vectors_base(),
            stage1_page_tables_base: image.stage1_page_tables_base(),
        });
        let mut cpu = CpuState::default();
        cpu.named.cntfrq = SystemValue(DEFAULT_CNTFRQ_HZ);
        cpu.named.mpidr = SystemValue(MPIDR_AFF0_RES1);

        let mut vcpu = SoftAarch64Vcpu {
            cpu,
            monitor: ExclusiveMonitor::default(),
            executor,
            stage2: Arc::clone(&stage2),
            control: Arc::clone(&control),
            mailbox,
            actlr_el1: 0,
            cpacr_el1: 0,
            tpidrro_pending: AtomicU64::new(0),
            tpidrro_dirty: AtomicBool::new(false),
            sp_pending: AtomicU64::new(0),
            sp_dirty: AtomicBool::new(false),
            boot_instant,
            block_quantum: DEFAULT_BLOCK_QUANTUM,
            max_quanta_per_exit: DEFAULT_MAX_QUANTA_PER_EXIT,
        };
        vcpu.restore(&staged.snapshot())?;
        if vcpu.mailbox.is_some() {
            vcpu.cpu.sp_el1 = StackPointer(LINUX_SYSCALL_MAILBOX_BASE);
        }

        let vmm = Self {
            stage2,
            protections,
            control,
            next_alias_gpa: SOFT_ALIAS_GPA_BASE,
            make_executor,
            boot_instant,
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

    // Ensure the dynamic metadata window and carrier maintenance root exist
    // when an EL1 kernel region is present.
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
        if stage2
            .host_ptr(EL1_DYNAMIC_METADATA_BASE, PAGE_BYTES_USIZE)
            .is_none()
        {
            stage2.map_owned_anonymous(
                EL1_DYNAMIC_METADATA_BASE,
                EL1_DYNAMIC_METADATA_SIZE,
                MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
                true,
            )?;
        }
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
    type SiblingBuilder = SoftSiblingBuilder<X>;
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
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: dst.len(),
            })?
            .read_gpa_bytes(ipa, dst)
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: dst.len(),
            })
    }

    fn translated_write(&mut self, va: u64, ipa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.stage2
            .try_borrow()
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: bytes.len(),
            })?
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
            .map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        zero_range_chunked(address, len, |addr, zeros| {
            stage2
                .write_gpa_bytes(addr, zeros)
                .map_err(|_| MemoryError::OutOfBounds {
                    address: addr,
                    length: zeros.len(),
                })
        })
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
        Ok((gpa, writable))
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        let executor = (self.make_executor)()?;
        let mailbox_ptr = self
            .stage2
            .try_borrow()?
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .and_then(|p| NonNull::new(p.cast::<Aarch64SyscallMailbox>()));
        // SAFETY: `mailbox_ptr` points to the live mailbox slot in `self.stage2`.
        let mailbox = mailbox_ptr.map(|ptr| unsafe { MailboxSlot::new(ptr, 1) });
        let mut cpu = CpuState::default();
        cpu.named.cntfrq = SystemValue(DEFAULT_CNTFRQ_HZ);
        cpu.named.mpidr = SystemValue(MPIDR_AFF0_RES1);
        Ok(SoftAarch64Vcpu {
            cpu,
            monitor: ExclusiveMonitor::default(),
            executor,
            stage2: Arc::clone(&self.stage2),
            control: Arc::clone(&self.control),
            mailbox,
            actlr_el1: 0,
            cpacr_el1: 0,
            tpidrro_pending: AtomicU64::new(0),
            tpidrro_dirty: AtomicBool::new(false),
            sp_pending: AtomicU64::new(0),
            sp_dirty: AtomicBool::new(false),
            boot_instant: self.boot_instant,
            block_quantum: DEFAULT_BLOCK_QUANTUM,
            max_quanta_per_exit: DEFAULT_MAX_QUANTA_PER_EXIT,
        })
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        let new_stage2 = populate_stage2_for_image(new_image, None, None)?;
        let mailbox_ptr = new_stage2
            .host_ptr(
                LINUX_SYSCALL_MAILBOX_BASE,
                AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .and_then(|p| NonNull::new(p.cast::<Aarch64SyscallMailbox>()));
        // SAFETY: `mailbox_ptr` points to `new_stage2`'s freshly mapped mailbox slot.
        vcpu.mailbox = mailbox_ptr.map(|ptr| unsafe { MailboxSlot::new(ptr, 1) });
        {
            let mut guard = self.stage2.try_borrow()?;
            *guard = new_stage2;
        }
        self.protections = Arc::new(MemoryProtections::default());
        self.next_alias_gpa = SOFT_ALIAS_GPA_BASE;
        let staged = StagedCpu::initial_root(&RootBootFields {
            entry: new_image.entry(),
            initial_stack_pointer: new_image.initial_stack_pointer(),
            el0_trampoline_entry: new_image.el0_trampoline_entry(),
            el1_vectors_base: new_image.el1_vectors_base(),
            stage1_page_tables_base: new_image.stage1_page_tables_base(),
        });
        vcpu.restore(&staged.snapshot())
    }

    fn kick_handle(&self) -> Self::KickHandle {
        SoftKickHandle {
            control: Arc::clone(&self.control),
        }
    }

    fn build_sibling_builder(
        &self,
        _vcpu: &Self::Vcpu,
        _entry: GuestEntryRegs,
    ) -> Result<Self::SiblingBuilder, TrapError> {
        Ok(SoftSiblingBuilder {
            stage2: Arc::clone(&self.stage2),
            protections: Arc::clone(&self.protections),
            make_executor: Arc::clone(&self.make_executor),
            boot_instant: self.boot_instant,
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let executor = (builder.make_executor)()?;
        let control = Arc::new(RunControl::default());
        let mut cpu = CpuState::default();
        cpu.named.cntfrq = SystemValue(DEFAULT_CNTFRQ_HZ);
        cpu.named.mpidr = SystemValue(MPIDR_AFF0_RES1);
        let vcpu = SoftAarch64Vcpu {
            cpu,
            monitor: ExclusiveMonitor::default(),
            executor,
            stage2: Arc::clone(&builder.stage2),
            control: Arc::clone(&control),
            mailbox: None,
            actlr_el1: 0,
            cpacr_el1: 0,
            tpidrro_pending: AtomicU64::new(0),
            tpidrro_dirty: AtomicBool::new(false),
            sp_pending: AtomicU64::new(0),
            sp_dirty: AtomicBool::new(false),
            boot_instant: builder.boot_instant,
            block_quantum: DEFAULT_BLOCK_QUANTUM,
            max_quanta_per_exit: DEFAULT_MAX_QUANTA_PER_EXIT,
        };
        let vmm = Self {
            stage2: builder.stage2,
            protections: builder.protections,
            control,
            next_alias_gpa: SOFT_ALIAS_GPA_BASE,
            make_executor: builder.make_executor,
            boot_instant: builder.boot_instant,
        };
        Ok((vmm, vcpu))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        vcpu.sp_pending.store(sp, Ordering::Relaxed);
        vcpu.sp_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
        Arc::new(GenericVcpuRegistry::new())
    }
}

//! Shared CPL0 KVM carrier and its retained guest-MM/metadata backing.
//! Hardware fixtures and the initial production process use the same image;
//! fixture observation ports remain separate from the production transport.

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_MP_STATE_RUNNABLE, Msrs, kvm_guest_debug,
    kvm_mp_state, kvm_msi, kvm_msr_entry,
};
use kvm_ioctls::VcpuExit as KvmExit;
use kvm_ioctls::VmFd;

use carrick_core_abi::X86_CPL0_INITIAL_EXTENT_MAX_SIZE;
#[cfg(test)]
use carrick_core_abi::{X86_INITIAL_BOOT_HEADER_GPA, X86InitialBootHeader};
use carrick_el1::memory::reservations::{
    NoRootWait, X86Cpl0Reservations, X86Cpl0RootReleaseVenue, X86Cpl0Zone,
};
use carrick_el1_abi::Lifecycle;
use carrick_el1_abi::{
    BlockedMask, Counters, CurrentTask, ReservationMm, ThreadControlSlot, ThreadLifecyclePage,
};
use carrick_guest_arch::FrameGpa;
use carrick_guest_arch::{RootGpa, UserVa};
use carrick_hal::PhysicalFrameInventory;
use carrick_hal::{HvVcpu, TrapError, VcpuExit, VcpuKick};
#[cfg(test)]
use carrick_kernel::kernel::{FrameInventoryAuthority, ObjectIdRegistry};
use carrick_mmu_core::x86::descriptor_txn::{Access, translate_leaf};
use carrick_sched_core::spaces::notification::SpaceReleaseVenue;
use carrick_sched_core::{SlotId, Waker};
use carrick_x86::cpl0_entry::*;
use carrick_x86::{X86Reg, X86Vcpu};

pub use carrick_x86_cpl0_host::carrier_cpu::{CarrierChildBindings, CarrierRunExit};
pub use carrick_x86_cpl0_host::carrier_memory::{
    BackingExtent, BackingHandle, CarrierMemory, InventoryTransaction, PreparedBacking,
};
pub use carrick_x86_cpl0_host::cpl0_boot::*;
pub use carrick_x86_cpl0_host::guest_ram::{GuestRam, WindowKind};

use crate::carrier_cpu::{KvmCarrierCpu, KvmCpuIo};
use crate::carrier_memory::CarrierMachine;
use crate::{KvmKickHandle, KvmVcpu, KvmVm};

const _: [(); carrick_x86_cpl0_host::cpl0_boot::MAX_CPUID_ENTRIES] =
    [(); kvm_bindings::KVM_MAX_CPUID_ENTRIES];

pub type ProductionWorkerParts =
    carrick_x86_cpl0_host::cpl0_boot::ProductionWorkerParts<KvmCpuIo, KvmVm>;
pub type ProductionCpuFactory =
    carrick_x86_cpl0_host::cpl0_boot::ProductionCpuFactory<KvmCpuIo, KvmVm>;
pub type ProductionCpuLease = carrick_x86_cpl0_host::cpl0_boot::ProductionCpuLease<KvmCpuIo, KvmVm>;
type KvmBootstrapCustody = carrick_x86_cpl0_host::cpl0_boot::BootstrapCustody<KvmVm>;
pub type ForwardVenue<'a> = carrick_x86_cpl0_host::cpl0_boot::ForwardVenue<'a, KvmCpuIo, KvmVm>;

pub struct Watchdog {
    control: std::sync::mpsc::Sender<WatchdogControl>,
    worker: Option<std::thread::JoinHandle<()>>,
    pub(crate) expired: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
}
enum WatchdogControl {
    Resume,
    Pause,
    Cancel,
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
enum FixtureStopCondition {
    UserByte(u64, u8),
    PendingKick(usize),
}

impl Watchdog {
    pub(crate) fn start() -> Self {
        Self::start_with_timeout(Duration::from_secs(5))
    }
    fn start_with_timeout(timeout: Duration) -> Self {
        let kick = crate::KvmKickHandle::for_current_thread();
        let (control, receiver) = std::sync::mpsc::channel();
        let expired = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&expired);
        let active = Arc::new(AtomicBool::new(false));
        let in_guest = Arc::clone(&active);
        let worker = std::thread::spawn(move || {
            let mut armed = false;
            loop {
                let event = if armed {
                    receiver.recv_timeout(timeout).ok()
                } else {
                    receiver.recv().ok()
                };
                match event {
                    Some(WatchdogControl::Resume) => armed = true,
                    Some(WatchdogControl::Pause) => armed = false,
                    Some(WatchdogControl::Cancel) => break,
                    None if armed && in_guest.load(Ordering::Acquire) => {
                        signal.store(true, Ordering::Release);
                        kick.kick();
                        break;
                    }
                    None => break,
                }
            }
        });
        Self {
            control,
            worker: Some(worker),
            expired,
            active,
        }
    }
    pub(crate) fn during_guest<T>(&self, run: impl FnOnce() -> T) -> T {
        self.active.store(true, Ordering::Release);
        let _ = self.control.send(WatchdogControl::Resume);
        let result = run();
        self.active.store(false, Ordering::Release);
        let _ = self.control.send(WatchdogControl::Pause);
        result
    }
    pub(crate) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }
}
impl carrick_x86_cpl0_host::carrier_cpu::FixtureWatchdog for Watchdog {
    fn start() -> Self {
        Self::start()
    }
    fn during_guest<T>(&self, run: impl FnOnce() -> T) -> T {
        self.during_guest(run)
    }
    fn expired(&self) -> bool {
        self.expired()
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.control.send(WatchdogControl::Cancel);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn stopped_at_interruptible_user(cpu: &KvmVcpu) -> Result<bool, TrapError> {
    let sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
    let regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
    let events = cpu
        .fd()
        .get_vcpu_events()
        .map_err(|e| fail(e.to_string()))?;
    Ok(sregs.cs.dpl == 3
        && sregs.cs.selector & 3 == 3
        && regs.rflags & (1 << 9) != 0
        && events.interrupt.shadow == 0
        && events.interrupt.injected == 0)
}

/// One KVM vCPU and its VM's MSI route, as the shared production run
/// admission drives them.
struct KvmMember<'a> {
    cpu: &'a mut KvmVcpu,
    vm: &'a VmFd,
}

impl ProductionMemberCpu for KvmMember<'_> {
    fn stopped_cpl(&self) -> Result<u8, TrapError> {
        Ok(self
            .cpu
            .fd()
            .get_sregs()
            .map_err(|e| fail(e.to_string()))?
            .cs
            .dpl)
    }
    fn stopped_at_interruptible_user(&self) -> Result<bool, TrapError> {
        stopped_at_interruptible_user(self.cpu)
    }
    fn queue_reentry_kick(&mut self) -> Result<(), TrapError> {
        let lapic = self.cpu.fd().get_lapic().map_err(|e| fail(e.to_string()))?;
        let apic_id = u32::from_le_bytes([
            lapic.regs[0x20] as u8,
            lapic.regs[0x21] as u8,
            lapic.regs[0x22] as u8,
            lapic.regs[0x23] as u8,
        ]) >> 24;
        let delivered = self
            .vm
            .signal_msi(kvm_msi {
                address_lo: 0xfee0_0000 | (apic_id << 12),
                data: u32::from(carrick_x86::interrupts::KICK_VECTOR),
                ..Default::default()
            })
            .map_err(|e| fail(format!("KVM_SIGNAL_MSI reentry: {e}")))?;
        if delivered <= 0 {
            return Err(fail("reentry shootdown MSI was blocked"));
        }
        Ok(())
    }
    fn run_guest(&mut self) -> Result<VcpuExit, TrapError> {
        Ok(HvVcpu::run(self.cpu)?)
    }
}

pub(crate) fn run_member(
    cpu: &mut KvmVcpu,
    table: &ShootdownTable,
    slot: usize,
    vm: &VmFd,
    actual_run: Option<&AtomicU32>,
    execution: &RwLock<()>,
) -> Result<VcpuExit, TrapError> {
    run_production_member(
        &mut KvmMember { cpu, vm },
        table,
        slot,
        actual_run,
        execution,
    )
}

/// Physical run authority retained by a worker after the carrier's vCPU is
/// moved out of its bootstrap owner. The RAM owner keeps the atomic shootdown
/// table alive; the slot is a physical identity, never a Linux task identity.
#[derive(::core::clone::Clone)]
pub(crate) struct ProductionRunContext {
    ram: Arc<GuestRam>,
    vm: Arc<VmFd>,
    actual_run: Arc<[AtomicU32; 2]>,
    file_execution: Arc<RwLock<()>>,
    slot: usize,
    pub(crate) maintenance_root: Option<RootGpa>,
}

impl ProductionRunContext {
    pub(crate) fn physical_slot(&self) -> carrick_guest_arch::CpuId {
        carrick_guest_arch::CpuId::new(self.slot as u32)
    }
    pub(crate) fn run(&self, cpu: &mut KvmVcpu) -> Result<VcpuExit, TrapError> {
        let table = self
            .ram
            .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
            .ok_or_else(|| fail("retained shootdown table backing"))?
            .cast::<ShootdownTable>();
        // SAFETY: the retained RAM owns this aligned table for the entire
        // worker lifetime. The guest and host access its published atomics.
        let table = unsafe { &*table };
        let exit = run_member(
            cpu,
            table,
            self.slot,
            &self.vm,
            Some(&self.actual_run[self.slot]),
            &self.file_execution,
        )?;
        if matches!(
            exit,
            VcpuExit::IoOut {
                port: FATAL_PORT,
                ..
            }
        ) {
            crate::fatal_hold::hold_at_fatal(cpu, table, self.slot, &self.ram);
        }
        Ok(exit)
    }
}

pub struct Cpl0Carrier {
    pub(crate) cpus: [KvmVcpu; 2],
    pub(crate) custody: KvmBootstrapCustody,
    /// The delta-free realtime calibration published at load, if any.
    realtime_host_off: Option<u64>,
}

/// A live holder of two production-zone readiness-lane locks, from
/// [`Cpl0Carrier::fixture_hold_ipc_readiness_lanes`]. Dropping it releases.
#[cfg(feature = "test-fixtures")]
pub struct FixtureReadinessLaneHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<bool>>,
}

#[cfg(feature = "test-fixtures")]
impl FixtureReadinessLaneHold {
    /// Release both locks. `true` when this request released them, `false`
    /// when the holder had already given up at its bound.
    pub fn release(mut self) -> bool {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.thread
            .take()
            .is_some_and(|thread| thread.join().unwrap_or(false))
    }
}

#[cfg(feature = "test-fixtures")]
impl Drop for FixtureReadinessLaneHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The editors a full owed-return table's drain held (#1482 P0-1), from
/// [`Cpl0Carrier::fixture_hold_owed_return_holders`]: the census of what
/// the holds met and the release that gives them back.
#[cfg(feature = "test-fixtures")]
pub struct FixtureOwedReturnHolderHold {
    release: carrick_x86_cpl0_host::cpl0_boot::anonymous_owner::OwedReturnHolderRelease<KvmVm>,
}

#[cfg(feature = "test-fixtures")]
impl FixtureOwedReturnHolderHold {
    /// The holders whose editors the drain held.
    pub fn held(&self) -> Vec<carrick_el1_abi::ReservationMm> {
        self.release.hold().held()
    }
    /// Settlement doorbells answered while the editors were held.
    pub fn doorbells_while_held(&self) -> u64 {
        self.release.hold().doorbells_while_held()
    }
    /// Wait, at most `bound`, for the first full-table drain to hold the
    /// editors.
    pub fn wait_claimed(&self, bound: Duration) -> bool {
        self.release.hold().wait_claimed(bound)
    }
    /// Records parked on the held holders' `Editor` releases.
    pub fn enrolled(&self) -> Result<u32, TrapError> {
        self.release.enrolled()
    }
    /// Give every held editor back and publish each holder's exact `Editor`
    /// release. Returns how many were released.
    pub fn release(&self) -> Result<usize, TrapError> {
        self.release.release()
    }
}

impl Cpl0Carrier {
    /// At the first drain that finds the shared owed-return table full, the
    /// carrier holds every holder's real editor word, as active ring editors
    /// would, until [`FixtureOwedReturnHolderHold::release`]. The hold
    /// retains the carrier RAM.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_hold_owed_return_holders(&mut self) -> FixtureOwedReturnHolderHold {
        FixtureOwedReturnHolderHold {
            release: self.custody.fixture_hold_owed_return_holders(),
        }
    }

    fn initial_mm_key(&self) -> u64 {
        self.custody.initial_mm_key()
    }
    fn run_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError> {
        let context = self.production_run_context(index)?;
        context.run(&mut self.cpus[index])
    }
    /// Size one private retained aperture for the host-staged PT_LOAD bytes,
    /// the boot record, and guest-owned table/data grants. Capacity follows
    /// the submitted image rather than reserving a carrier-wide RAM pool.
    pub fn initial_extent_bytes_for(
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
    ) -> Result<usize, TrapError> {
        use carrick_mem::vdso::{X86NativeVvar, x8664_vdso_image_bytes};
        let vdso = x8664_vdso_image_bytes();
        let vvar = [0; X86NativeVvar::BYTE_LEN];
        let sized = image.clone().with_vdso(&vvar, &vdso);
        carrick_x86_cpl0_host::cpl0_boot::initial_extent_bytes_for(
            sized.as_ref().unwrap_or(image),
            argv,
            env,
        )
    }
    pub fn physical_slot_count(&self) -> usize {
        self.custody.memory().slot_count()
    }

    /// Inspect the carrier's one admitted production reservation authority.
    /// The store and zone are two offsets into the same retained metadata
    /// extent; a fixture carrier with no production root returns false.
    pub fn initial_reservation_admitted(&self) -> bool {
        let (Some(table), Some(zone), Some(mm)) = (
            self.custody.ram().host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            ),
            self.custody.ram().host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            ),
            ReservationMm::new(self.initial_mm_key()),
        ) else {
            return false;
        };
        // SAFETY: retained aligned carrier metadata outlives this stopped
        // observation; both typed objects were initialized before EL0 entry.
        let (table, zone) = unsafe {
            (
                &*table.cast::<X86Cpl0Reservations>(),
                &*zone.cast::<X86Cpl0Zone>(),
            )
        };
        zone.spaces
            .find(mm.raw())
            .is_some_and(|index| table.admitted(index.index(), mm))
    }

    /// Observe the stopped boot owner's actual mapping census used by fork.
    pub fn initial_reservation_census(
        &self,
    ) -> Result<Vec<carrick_core::mm::reservation::Mapping>, TrapError> {
        let table = self
            .custody
            .ram()
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            )
            .ok_or_else(|| fail("initial census table"))?;
        let zone = self
            .custody
            .ram()
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("initial census zone"))?;
        // SAFETY: the stopped carrier retains both aligned initialized records
        // in one metadata region for the entire observation and root guard.
        let (table, zone) = unsafe {
            (
                &*table.cast::<X86Cpl0Reservations>(),
                &*zone.cast::<X86Cpl0Zone>(),
            )
        };
        let mm =
            ReservationMm::new(self.initial_mm_key()).ok_or_else(|| fail("initial census MM"))?;
        let index = zone
            .spaces
            .find(mm.raw())
            .ok_or_else(|| fail("initial census space"))?;
        let wake_error = std::cell::RefCell::new(None);
        let deliver = |zone: &X86Cpl0Zone,
                       waker: Waker,
                       owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            if let Err(error) = unexpected_boot_wake(zone, waker, owned) {
                *wake_error.borrow_mut() = Some(error);
            }
        };
        let release = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &deliver,
            ),
        };
        let mut root = X86Cpl0RootReleaseVenue::new(table, release)
            .and_then(|venue| venue.lock(index.index(), mm, &NoRootWait))
            .map_err(|error| fail(format!("initial census authority: {error:?}")))?;
        let mut mappings = Vec::new();
        root.observe_mappings(&mut |mapping| mappings.push(mapping))
            .map_err(|error| fail(format!("initial census: {error:?}")))?;
        drop(root);
        if let Some(error) = wake_error.into_inner() {
            return Err(error);
        }
        Ok(mappings)
    }

    /// The initial host-loaded task retains an x86-shaped scheduler record
    /// in the same zone that owns its MM notifications.
    pub fn initial_thread_custody(&self) -> bool {
        let Some(zone) = self.custody.ram().host_ptr(
            META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
            size_of::<X86Cpl0Zone>(),
        ) else {
            return false;
        };
        // SAFETY: this typed production zone is retained for the stopped
        // carrier; the fixed metadata window supplies its alignment.
        let zone = unsafe { &*zone.cast::<X86Cpl0Zone>() };
        let slot = SlotId::new(0);
        let Some(record) = zone.slot(slot).host_record() else {
            return false;
        };
        let identity = zone.record(record).identity();
        let (tid, serial, birth_serial) = self.custody.initial_task().map_or(
            (
                41,
                101,
                carrick_sched_core::process::TaskSerial::from_raw_u64(11),
            ),
            |root| (root.thread.tid, root.thread.serial, Some(root.task.serial)),
        );
        let expected_birth = birth_serial.and_then(|birth| {
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::EntryTaskKey::from_raw(tid),
                carrick_core_abi::BirthSerial::of_task(birth),
                carrick_core_abi::EntryThreadGeneration::from_raw(serial),
            )
        });
        zone.record(record).home() == Some(slot)
            && identity.tid == tid
            && identity.serial == serial
            && identity.mm == self.initial_mm_key()
            && identity.lifecycle_page == METADATA_VA
            && identity.control_slot == METADATA_VA + CONTROL_OFFSET
            && expected_birth.is_some_and(|birth| self.slot(0).host_birth_identity() == Some(birth))
    }

    /// Initial data publications belong to the carrier's one frame inventory,
    /// which remains available to subsequent fault and fork services.
    pub fn initial_inventory_custody(&self) -> bool {
        self.custody.initial_inventory_custody()
    }

    pub fn retained_bytes(&self) -> usize {
        self.custody.memory().retained_bytes()
    }

    /// Stopped-vCPU control state for the production KVM boot contract.
    pub fn supervisor_cr4(&self, index: usize) -> Result<u64, TrapError> {
        let cpu = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        cpu.fd()
            .get_sregs()
            .map(|state| state.cr4)
            .map_err(|error| fail(format!("KVM_GET_SREGS: {error}")))
    }

    /// Enable architectural SMAP before either fixture vCPU starts. The
    /// caller uses this only on KVM hosts whose guest CPUID advertises SMAP.
    pub fn enable_smap(&mut self) -> Result<(), TrapError> {
        for cpu in &mut self.cpus {
            let mut state = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            state.cr4 |= 1 << 21;
            cpu.fd()
                .set_sregs(&state)
                .map_err(|e| fail(e.to_string()))?;
            let observed = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            if observed.cr4 & (1 << 21) == 0 {
                return Err(fail("KVM refused CR4.SMAP"));
            }
        }
        Ok(())
    }

    /// Read a stopped fixture's 4 KiB terminal descriptor.
    pub fn fixture_user_leaf(&self, va: u64) -> Result<u64, TrapError> {
        let entry = self.fixture_user_leaf_raw(va)?;
        if entry & 1 == 0 {
            return Err(fail("fixture requires a present 4 KiB leaf"));
        }
        Ok(entry)
    }

    /// Inspect an invalid retained terminal after all fixture vCPUs stop.
    pub fn fixture_user_leaf_raw(&self, va: u64) -> Result<u64, TrapError> {
        if !matches!(
            va,
            USER_CODE | 0x3_0000 | 0x3_2000 | 0x3_3000 | 0x3_4000 | 0x3_6000 | 0x3_7000
        ) {
            return Err(fail("fixture leaf outside admitted user page"));
        }
        let mut table = LAYOUT.pml4_base;
        for shift in [39, 30, 21, 12] {
            let address = table + ((va >> shift) & 511) * 8;
            let ptr = self
                .custody
                .ram()
                .host_ptr(address, 8)
                .ok_or_else(|| fail("fixture descriptor outside table backing"))?
                .cast::<u64>();
            // SAFETY: the vCPUs are stopped at a fixture control exit and the
            // guest table backing remains mapped until carrier teardown.
            let entry = unsafe { ptr.read_volatile() };
            if shift == 12 {
                return Ok(entry);
            }
            if entry & 1 == 0 || (shift == 30 || shift == 21) && entry & (1 << 7) != 0 {
                return Err(fail("fixture requires a present 4 KiB leaf"));
            }
            table = entry & 0x000f_ffff_ffff_f000;
        }
        Err(fail("fixture leaf walk incomplete"))
    }

    /// Inspect the stopped bootstrap's supervisor direct-window permissions.
    pub fn bootstrap_supervisor_access(&self, gpa: u64, access: Access) -> Result<bool, TrapError> {
        if !(IMAGE_GPA + IMAGE_SIZE..META_GPA).contains(&gpa) {
            return Err(fail("supervisor access outside bootstrap window"));
        }
        let root = RootGpa::page_aligned(FrameGpa::new(LAYOUT.pml4_base))
            .ok_or_else(|| fail("bootstrap root alignment"))?;
        Ok(translate_leaf(
            &self.custody.memory().words(),
            root,
            UserVa::new(DIRECT_VA + gpa),
            access,
            false,
        )
        .is_ok())
    }

    /// Inspect the stopped bootstrap root's native xAPIC MMIO mapping.
    pub fn bootstrap_lapic_mapped(&self) -> Result<bool, TrapError> {
        let root = RootGpa::page_aligned(FrameGpa::new(LAYOUT.pml4_base))
            .ok_or_else(|| fail("bootstrap root alignment"))?;
        Ok(translate_leaf(
            &self.custody.memory().words(),
            root,
            UserVa::new(carrick_x86::interrupts::LAPIC_VA),
            Access::Write,
            false,
        )
        .is_ok_and(|leaf| leaf.output.raw() == carrick_x86::interrupts::LAPIC_BASE))
    }

    pub fn boot(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: &Path,
        programs: [&[u8]; 2],
    ) -> Result<Self, TrapError> {
        Self::boot_inner(frame_inventory, image, programs, false)
    }

    pub fn boot_with_interrupts(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: &Path,
        programs: [&[u8]; 2],
    ) -> Result<Self, TrapError> {
        Self::boot_inner(frame_inventory, image, programs, true)
    }

    /// Boot the compiled production image in the same retained carrier used
    /// by the hardware fixtures. Guest MM publication follows while stopped.
    pub fn boot_production(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        initial_extent_bytes: usize,
        ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
    ) -> Result<Self, TrapError> {
        const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/carrick-x86-cpl0"));
        Self::boot_production_image(frame_inventory, IMAGE, initial_extent_bytes, ipc)
    }

    /// Boot a caller-selected build of the production entry. Integration
    /// tests use this to keep instrumentation in a separate image artifact.
    pub fn boot_production_image(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: &[u8],
        initial_extent_bytes: usize,
        ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
    ) -> Result<Self, TrapError> {
        if initial_extent_bytes == 0
            || initial_extent_bytes > X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize
            || !initial_extent_bytes.is_multiple_of(4096)
        {
            return Err(fail("invalid initial guest MM extent size"));
        }
        Self::boot_bytes_inner(
            frame_inventory,
            image,
            [&[], &[]],
            false,
            Some(initial_extent_bytes),
            false,
            ipc,
        )
    }

    pub fn birth_serial_source(
        &self,
    ) -> Result<Arc<dyn carrick_hal::birth_serial::BirthSerialSource>, TrapError> {
        self.custody.birth_serial_source()
    }

    /// The in-kernel KVM statistics of this carrier's two vCPUs, scoped to
    /// this carrier: the handle outlives the run that consumes the carrier,
    /// so a witness reads exactly the exits its own guest caused. An absent
    /// `KVM_GET_STATS_FD` is an error, never an empty census.
    pub fn kernel_stats(&self) -> Result<crate::kvm::CarrierKernelStats, TrapError> {
        let cpus = self
            .cpus
            .iter()
            .map(|cpu| crate::kvm::VcpuKernelStats::open(cpu.fd()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| fail(format!("KVM_GET_STATS_FD: {error}")))?;
        Ok(crate::kvm::CarrierKernelStats::new(cpus))
    }

    /// Replace the bootstrap's provisional identity with the exact root
    /// issued by the shared kernel, before the initial MM is admitted.
    pub fn bind_initial_task_identity(
        &mut self,
        identity: InitialTaskBinding,
    ) -> Result<(), TrapError> {
        self.custody.bind_initial_task_identity(identity)
    }

    /// Transfer the two physical CPUs to executor adapters after completing
    /// the bootstrap I/O steps. The returned root image is the state to
    /// publish under the kernel scheduler's first execution lease.
    pub fn into_worker_parts(
        mut self,
        max_exits: usize,
    ) -> Result<ProductionWorkerParts, TrapError> {
        // The issued root and its initial MM must exist before the peer starts.
        self.custody
            .initial_task()
            .ok_or_else(|| fail("worker handoff has no issued root task"))?;
        let mm = NonZeroU64::new(self.initial_mm_key()).ok_or_else(|| fail("initial MM key"))?;
        self.custody
            .memory()
            .root(mm)
            .ok_or_else(|| fail("worker handoff has no initial MM"))?;
        self.start_initial_peer(max_exits)?;
        for cpu in &mut self.cpus {
            cpu.complete_pending_io_exit()
                .map_err(|error| fail(format!("complete bootstrap I/O: {error}")))?;
        }
        let root_state = self
            .custody
            .worker_root_state(&carrick_x86::snapshot(&self.cpus[0])?)?;
        let runs = [
            self.production_run_context(0)?,
            self.production_run_context(1)?,
        ];
        let shared_vm = self.custody.memory().vm().vm_handle();
        // The clock owner took its ring realtime word before the split.
        let Self {
            cpus: [first, second],
            custody,
            realtime_host_off: _,
        } = self;
        let children = crate::carrier_cpu::CarrierChildBindings::default();
        let first = KvmCarrierCpu::from_production(
            first,
            crate::KvmVm::from_shared_vm(shared_vm.clone()),
            LAYOUT,
            runs[0].clone(),
            children.clone(),
        )?;
        let second = KvmCarrierCpu::from_production(
            second,
            crate::KvmVm::from_shared_vm(shared_vm),
            LAYOUT,
            runs[1].clone(),
            children,
        )?;
        Ok(ProductionWorkerParts::new(
            [first, second],
            custody,
            root_state,
        ))
    }

    /// The guest MM owner supplies the executable and stack publication here.
    /// This is the sole unbound seam between a stopped production carrier and
    /// EL0 admission; no fixture user page is used as an ELF loader.
    pub fn load_guest_mm(
        &mut self,
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
        limits: InitialReservationLimits,
    ) -> Result<(), TrapError> {
        self.load_guest_mm_for_clock(image, argv, env, limits, Some(0))
    }

    /// Map the fast path only for a native clock domain. The supplied
    /// realtime delta is owned by the already admitted container clock.
    pub fn load_guest_mm_for_clock(
        &mut self,
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
        limits: InitialReservationLimits,
        native_realtime_delta: Option<i64>,
    ) -> Result<(), TrapError> {
        let vvar = native_realtime_delta.and_then(|delta| self.calibrate_vvar(delta));
        let vdso = carrick_mem::vdso::x8664_vdso_image_bytes();
        let vvar_bytes = vvar.map(carrick_mem::vdso::X86NativeVvar::bytes);
        let with_vdso = vvar_bytes
            .as_ref()
            .and_then(|vvar| image.clone().with_vdso(vvar, &vdso).ok())
            .filter(|image| image.regions.len() <= carrick_core_abi::X86_INITIAL_MAX_REGIONS);
        carrick_x86_cpl0_host::cpl0_boot::load_guest_mm(
            self,
            with_vdso.as_ref().unwrap_or(image),
            argv,
            env,
            limits,
        )?;
        // The syscall clock reads this ring-owned copy, never the user page.
        if let Some(vvar) = vvar {
            self.publish_realtime_offset(vvar.realtime_offset())?;
            self.realtime_host_off = native_realtime_delta
                .map(|delta| vvar.realtime_offset().wrapping_sub(delta as u64));
        }
        self.custody
            .set_clock_vvar(vvar.filter(|_| with_vdso.is_some()));
        Ok(())
    }

    fn publish_realtime_offset(&self, offset_ns: u64) -> Result<(), TrapError> {
        publish_zone_realtime_offset(self.custody.ram(), offset_ns)
            .ok_or_else(|| fail("realtime calibration zone"))
    }

    /// The ring realtime word's owner after load: the delta-free calibration
    /// and a publisher into this carrier's zone, for the container's clock
    /// (`ClockDomain::bind_ring_realtime`). `None` without a calibrated clock.
    pub fn ring_realtime_word(&self) -> Option<(u64, impl Fn(u64) + Send + Sync + 'static)> {
        let host_off = self.realtime_host_off?;
        let ram = Arc::clone(self.custody.ram());
        Some((host_off, move |offset_ns| {
            let _ = publish_zone_realtime_offset(&ram, offset_ns);
        }))
    }

    fn calibrate_vvar(&self, delta: i64) -> Option<carrick_mem::vdso::X86NativeVvar> {
        let freq = NonZeroU64::new(self.binding(0).tsc_hz.load(Ordering::Acquire))?;
        let tsc = self.cpus[0]
            .read_msr(carrick_x86::vdso::MSR_IA32_TSC)
            .ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let wall_ns = u64::try_from(now.as_nanos()).ok()?;
        Some(carrick_mem::vdso::X86NativeVvar::new(
            freq, tsc, wall_ns, delta,
        ))
    }

    /// Resume the published initial MM through the existing shared Linux
    /// personality. Only host-crossing calls leave CPL0 through FORWARD_PORT.
    fn start_initial_peer(&mut self, max_exits: usize) -> Result<(), TrapError> {
        // READY is a one-way physical boot receipt. Resuming a bounded run
        // preserves CPU1's native context; it must never initialize it twice.
        if self.custody.peer_ready() {
            return Ok(());
        }
        let peer = self
            .custody
            .peer_entry()
            .ok_or_else(|| fail("initial peer entry absent"))?;
        let stack = self.binding(1).kernel_stack;
        let initial = self
            .custody
            .memory()
            .root(NonZeroU64::new(self.initial_mm_key()).ok_or_else(|| fail("initial MM"))?)
            .ok_or_else(|| fail("initial peer root"))?;
        let cpu = &mut self.cpus[1];
        let mut sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
        sregs.cr3 = initial.root.address().raw();
        sregs.cs = crate::kvm_x86_engine::KvmSegment::from(carrick_x86::SegmentDescriptor::code64(
            carrick_x86::SegmentDpl::Kernel,
        ))
        .0;
        sregs.ss = crate::kvm_x86_engine::KvmSegment::from(
            carrick_x86::SegmentDescriptor::flat_data(carrick_x86::SegmentDpl::Kernel, 0),
        )
        .0;
        sregs.gs.base = METADATA_VA + BINDING_OFFSET + STRIDE;
        cpu.fd()
            .set_sregs(&sregs)
            .map_err(|e| fail(e.to_string()))?;
        let msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: 0xc000_0102,
            data: 0,
            ..Default::default()
        }])
        .map_err(|e| fail(e.to_string()))?;
        if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 1 {
            return Err(fail("initial peer UserGS"));
        }
        let mut regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
        regs.rip = peer.raw();
        regs.rsp = stack
            .checked_sub(8)
            .ok_or_else(|| fail("initial peer entry stack"))?;
        regs.rflags = 2;
        cpu.fd().set_regs(&regs).map_err(|e| fail(e.to_string()))?;
        if max_exits == 0 {
            return Err(fail("initial peer readiness exit budget exceeded"));
        }
        match self.run_cpu(1)? {
            VcpuExit::IoOut {
                port: carrick_el1_abi::NATIVE_PEER_READY_PORT,
                ..
            } => {
                if self.cpus[1].get_gpr(X86Reg::Rax)? != 1 {
                    return Err(fail("initial peer ready physical slot"));
                }
                self.custody.admit_peer();
                Ok(())
            }
            VcpuExit::Kicked => Err(fail("initial peer cancelled")),
            _ => Err(fail("initial peer readiness exit before READY")),
        }
    }

    /// Exact carrier publication used by both stopped host and guest consumers.
    pub fn file_region_binding(&self) -> carrick_el1_abi::FileRegionBinding {
        self.custody.file_region_binding()
    }

    /// Acquire stopped-carrier proof and authenticate the retained registration.
    pub fn ipc_table_map(
        &self,
    ) -> Result<Arc<dyn carrick_el1_abi::ipc_tables::IpcTableMapBacking>, TrapError> {
        self.custody.ipc_table_map()
    }

    /// The carrier-scoped zone wake sink the host IPC owner binds, so host
    /// releases (exit drains) wake tasks parked in this carrier's zone.
    pub fn carrier_zone_wake(
        &self,
    ) -> Result<
        Arc<dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>>,
        TrapError,
    > {
        self.custody.carrier_zone_wake()
    }

    pub fn file_tables(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<StoppedFileTables<'_>, carrick_el1_abi::FileRegionError> {
        self.custody.file_tables(binding)
    }

    /// Deliberately replace a stopped fixture CPU's publication to exercise
    /// guest authentication. This cannot mutate a running worker's binding.
    pub fn fixture_bind_file_region(
        &mut self,
        index: usize,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown file-region fixture CPU"));
        }
        let mapped = self
            .custody
            .ram()
            .host_ptr(
                META_GPA + BINDING_OFFSET + index as u64 * STRIDE,
                size_of::<CpuBinding>(),
            )
            .ok_or_else(|| fail("file-region fixture binding"))?
            .cast::<CpuBinding>();
        // SAFETY: this carrier exclusively owns both stopped CPUs and binding.
        unsafe {
            (*mapped).file_region = binding;
        }
        Ok(())
    }

    /// Withdraw the region with both fixture CPUs stopped; subsequent entry
    /// must refuse without consulting the retired tables.
    pub fn fixture_retire_file_region(&mut self) {
        self.custody.retire_file_region();
    }

    /// Counters from the stopped production carrier, including its initial
    /// image entry and each guest-to-host syscall forward.
    pub fn initial_execution_witness(&self) -> (u64, u64) {
        (
            self.binding(0).entries.load(Ordering::Acquire),
            self.custody.host_forwards(),
        )
    }

    /// Pages whose PRIVATE native descriptors and physical custody were
    /// checked at the stopped guest's applied owner-grant completion.
    pub fn anonymous_private_pages(&self) -> u64 {
        self.custody.anonymous_private_pages()
    }

    /// Shared fork-stock counters: loans, counted capacity refusals (each
    /// lowered to `EAGAIN` by the guest), quarantined and returned children.
    pub fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.custody.fork_stock_counters()
    }

    /// The exec owner's census: receipts reserved at claim, sealed, retired
    /// by reason, and settlements with their commit effects.
    pub fn exec_owner_census(&self) -> carrick_hal::exec_owner::ExecOwnerCensus {
        self.custody.exec_owner_census()
    }

    pub fn physical_crossing_counts(&self) -> [(PhysicalCrossingFamily, u64); 5] {
        self.custody.physical_crossing_counts()
    }

    /// Read the per-ordinal CPL0 refusal counter for a native syscall ordinal.
    /// Ordinals >= 512 are read from the overflow bucket.
    pub fn refusal_count(&self, nr: carrick_abi::NativeNr) -> u64 {
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        if let Ok(index @ 0..=511) = usize::try_from(nr.raw()) {
            return counters.refused[index].load(Ordering::Acquire);
        }
        counters.refused[512].load(Ordering::Acquire)
    }

    /// Read the CPL0 refusal counter overflow bucket (unknown/unmapped/out-of-range ordinals).
    pub fn refusal_overflow_count(&self) -> u64 {
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        counters.refused[512].load(Ordering::Acquire)
    }

    pub(crate) fn boot_inner(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: &Path,
        programs: [&[u8]; 2],
        interrupts: bool,
    ) -> Result<Self, TrapError> {
        let fixture_image = image
            .file_name()
            .is_some_and(|name| name == "carrick-x86-cpl0-fixture");
        let bytes = ::std::fs::read(image).map_err(|e| fail(format!("CPL0 image: {e}")))?;
        Self::boot_bytes_inner(
            frame_inventory,
            &bytes,
            programs,
            interrupts,
            None,
            fixture_image,
            None,
        )
    }

    fn boot_bytes_inner(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        bytes: &[u8],
        programs: [&[u8]; 2],
        interrupts: bool,
        initial_extent_bytes: Option<usize>,
        fixture_image: bool,
        ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
    ) -> Result<Self, TrapError> {
        let prepared = prepare_boot(
            &*frame_inventory,
            bytes,
            programs,
            interrupts,
            initial_extent_bytes,
            fixture_image,
            ipc,
        )?;
        let vm = KvmVm::create_empty().map_err(|e| fail(e.to_string()))?;
        let BootMemory {
            memory,
            files,
            kernel_region,
            initial_extent,
        } = install_boot_memory(
            vm,
            &*frame_inventory,
            &prepared,
            interrupts,
            initial_extent_bytes,
        )?;
        let PreparedBoot {
            ram,
            plan,
            boot,
            hardware_interrupts,
            kernel_pod_storage,
            ..
        } = prepared;
        let machine = CarrierMachine::from_memory(memory, 2).map_err(|e| fail(e.to_string()))?;
        let (cpus, vm) = machine.into_parts();
        let [mut a, mut b]: [KvmVcpu; 2] =
            cpus.try_into().map_err(|_| fail("carrier vCPU count"))?;
        for (index, cpu) in [&mut a, &mut b].into_iter().enumerate() {
            let state = BootCpuState::new(
                plan.entry,
                &boot,
                carrick_guest_arch::CpuId::new(index as u32),
                hardware_interrupts,
                initial_extent_bytes.is_some(),
            )?;
            state.program_entry(cpu)?;
            let mut system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            if initial_extent_bytes.is_some() {
                let cpuid = cpu
                    .fd()
                    .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                    .map_err(|error| fail(format!("KVM_GET_CPUID2: {error}")))?;
                let features = cpuid
                    .as_slice()
                    .iter()
                    .find(|entry| entry.function == 7 && entry.index == 0)
                    .map_or(0, |entry| entry.ebx);
                if features & state.cpuid_leaf7_required != state.cpuid_leaf7_required {
                    return Err(fail("production CPL0 requires CPUID SMEP and SMAP"));
                }
                system.cr4 |= state.cr4_required;
            }
            system.gdt.base = state.gdt_base;
            system.idt.base = state.idt_base;
            system.tr = crate::kvm_x86_engine::KvmSegment::from(state.tr).0;
            if let Some(apic_base) = state.apic_base {
                system.apic_base = apic_base;
            }
            cpu.fd()
                .set_sregs(&system)
                .map_err(|e| fail(e.to_string()))?;
            cpu.set_syscall_msrs(state.lstar, state.star, state.sfmask)?;
            if hardware_interrupts {
                // KVM_CREATE_IRQCHIP leaves the secondary vCPU awaiting SIPI.
                // Both native CPL0 entry states were installed while stopped;
                // admit each CPU before exposing the carrier to its owner.
                cpu.fd()
                    .set_mp_state(kvm_mp_state {
                        mp_state: KVM_MP_STATE_RUNNABLE,
                    })
                    .map_err(|e| fail(format!("CPL0 CPU admission: {e}")))?;
            }
            let msrs = Msrs::from_entries(&[kvm_msr_entry {
                index: 0xc000_0102,
                data: state.kernel_gs_base,
                ..Default::default()
            }])
            .map_err(|e| fail(e.to_string()))?;
            if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 1 {
                return Err(fail("KERNEL_GS_BASE not installed"));
            }
            let system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            if initial_extent_bytes.is_some()
                && system.cr4 & ((1 << 20) | (1 << 21)) != (1 << 20) | (1 << 21)
            {
                return Err(fail("KVM refused production CR4.SMEP/SMAP"));
            }
            if system.tr.base
                != DIRECT_VA
                    + carrick_x86::fault_slot_gpa(
                        carrick_x86::fault_tss_base(LAYOUT),
                        index as u64,
                    )?
                || system.idt.base
                    != DIRECT_VA
                        + carrick_x86::fault_slot_gpa(
                            carrick_x86::fault_idt_base(LAYOUT),
                            index as u64,
                        )?
            {
                return Err(fail("private TSS/IDT not installed"));
            }
        }
        let mut apic_ids = [0_u16; 2];
        for (index, cpu) in [&a, &b].into_iter().enumerate() {
            let khz = cpu
                .fd()
                .get_tsc_khz()
                .map_err(|e| fail(format!("KVM_GET_TSC_KHZ: {e}")))?;
            let hz = u64::from(khz)
                .checked_mul(1000)
                .filter(|hz| *hz != 0)
                .ok_or_else(|| fail("KVM reported no usable TSC frequency"))?;
            let binding = ram
                .host_ptr(
                    META_GPA + BINDING_OFFSET + index as u64 * STRIDE,
                    size_of::<CpuBinding>(),
                )
                .ok_or_else(|| fail("CPU binding backing"))?
                .cast::<CpuBinding>();
            // SAFETY: both vCPUs are stopped and the retained binding was
            // initialized above; atomic publication precedes guest entry.
            unsafe { (*binding).tsc_hz.store(hz, Ordering::Release) };
            if hardware_interrupts {
                let mut lapic = cpu
                    .fd()
                    .get_lapic()
                    .map_err(|e| fail(format!("KVM_GET_LAPIC: {e}")))?;
                let id_word = u32::from_le_bytes([
                    lapic.regs[0x20] as u8,
                    lapic.regs[0x21] as u8,
                    lapic.regs[0x22] as u8,
                    lapic.regs[0x23] as u8,
                ]);
                apic_ids[index] = u16::try_from((id_word >> 24) + 1)
                    .map_err(|_| fail("APIC ID outside xAPIC destination range"))?;
                // Each stopped vCPU needs its own software-enabled LAPIC
                // before peer IPIs can be accepted, including the AP before
                // its first guest syscall. The guest later owns its timer LVT.
                let svr = 0x100_u32 | u32::from(carrick_x86::interrupts::SPURIOUS_VECTOR);
                for (byte, value) in lapic.regs[0xf0..0xf4].iter_mut().zip(svr.to_le_bytes()) {
                    *byte = value as i8;
                }
                cpu.fd()
                    .set_lapic(&lapic)
                    .map_err(|e| fail(format!("KVM_SET_LAPIC: {e}")))?;
            }
        }
        if hardware_interrupts {
            if apic_ids[0] == apic_ids[1] {
                return Err(fail("duplicate KVM xAPIC destination"));
            }
            let routes = ram
                .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
                .ok_or_else(|| fail("APIC route table backing"))?
                .cast::<PublishedApicIds>();
            // SAFETY: stopped bootstrap initialized this retained table;
            // no guest or host reader exists before publication completes.
            let routes = unsafe { &*routes };
            for (slot, encoded) in apic_ids.into_iter().enumerate() {
                let apic = u8::try_from(encoded - 1)
                    .map_err(|_| fail("APIC ID outside xAPIC destination range"))?;
                if !routes.publish(
                    carrick_guest_arch::CpuId::new(slot as u32),
                    PublishedApicId(apic),
                ) {
                    return Err(fail("duplicate or invalid APIC slot publication"));
                }
            }
        }
        Ok(Self {
            cpus: [a, b],
            custody: KvmBootstrapCustody::new(
                vm,
                ram,
                initial_extent,
                kernel_region,
                files,
                frame_inventory,
                kernel_pod_storage,
            )?,
            realtime_host_off: None,
        })
    }

    /// References are private and used only while both vCPUs are stopped.
    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: the stopped bootstrap owns initialized metadata at these offsets.
        unsafe { self.custody.metadata(offset) }
    }
    pub(crate) fn binding(&self, index: usize) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + index as u64 * STRIDE)
    }
    /// Override the stopped fixture CPU's published clock for a source-order
    /// witness. The KVM clock itself is unchanged; only the guest binding is
    /// sampled by the frequency syscall below.
    pub fn fixture_publish_tsc_hz(&mut self, index: usize, hz: u64) -> Result<(), TrapError> {
        if index >= self.cpus.len() || hz == 0 {
            return Err(fail("invalid fixture TSC binding"));
        }
        self.binding(index).tsc_hz.store(hz, Ordering::Release);
        Ok(())
    }
    /// Publish a distinct architectural CPUID rate before the fixture vCPU
    /// runs, so the witness can prove the carrier binding wins the selection.
    pub fn fixture_publish_cpuid_tsc_hz(&mut self, index: usize, hz: u32) -> Result<(), TrapError> {
        let cpu = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        if hz == 0 {
            return Err(fail("invalid fixture CPUID clock"));
        }
        let cpuid = cpu
            .fd()
            .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| fail(format!("KVM_GET_CPUID2: {e}")))?;
        let mut entries: Vec<CpuidEntry> = cpuid
            .as_slice()
            .iter()
            .map(|e| CpuidEntry {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
                padding: e.padding,
            })
            .collect();
        fixture_cpuid_with_tsc_hz(&mut entries, hz)
            .map_err(|error| fail(format!("fixture CPUID clock: {error:?}")))?;
        let kvm_entries: Vec<kvm_bindings::kvm_cpuid_entry2> = entries
            .into_iter()
            .map(|e| kvm_bindings::kvm_cpuid_entry2 {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
                padding: e.padding,
            })
            .collect();
        let cpuid = kvm_bindings::CpuId::from_entries(&kvm_entries)
            .map_err(|e| fail(format!("fixture CPUID entries: {e}")))?;
        cpu.fd()
            .set_cpuid2(&cpuid)
            .map_err(|e| fail(format!("KVM_SET_CPUID2: {e}")))
    }
    /// Observe the stopped fixture vCPU's local timer configuration.
    pub fn lapic_register(&self, index: usize, offset: usize) -> Result<u32, TrapError> {
        let cpu = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        let lapic = cpu
            .fd()
            .get_lapic()
            .map_err(|e| fail(format!("KVM_GET_LAPIC: {e}")))?;
        let bytes = lapic
            .regs
            .get(offset..offset + 4)
            .ok_or_else(|| fail("LAPIC register offset"))?;
        Ok(u32::from_le_bytes([
            bytes[0] as u8,
            bytes[1] as u8,
            bytes[2] as u8,
            bytes[3] as u8,
        ]))
    }
    /// Inject a fixture interrupt into a stopped production vCPU. The IRQ is
    /// delivered only after the guest next runs with IF enabled.
    pub fn fixture_inject_irq(&self, index: usize, vector: u8) -> Result<(), TrapError> {
        let apic = self.lapic_register(index, 0x20)? >> 24;
        let apic = u8::try_from(apic).map_err(|_| fail("xAPIC destination width"))?;
        let routed = self
            .custody
            .memory()
            .vm()
            .vm
            .signal_msi(kvm_bindings::kvm_msi {
                address_lo: carrick_x86::interrupts::LAPIC_BASE as u32 | (u32::from(apic) << 12),
                data: u32::from(vector),
                ..Default::default()
            })
            .map_err(|error| fail(format!("KVM_SIGNAL_MSI: {error}")))?;
        if routed != 1 {
            return Err(fail("fixture interrupt not routed"));
        }
        Ok(())
    }
    /// Read the retained native IRQ mailbox after the guest exits.
    pub fn fixture_pending_irqs(&self, index: usize) -> Result<u32, TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        Ok(self.binding(index).pending_irqs.load(Ordering::Acquire))
    }

    /// Bind a stopped fixture reader to the editor's exact page-table root.
    /// Both retained tasks then name the same MM generation for this witness.
    pub fn fixture_share_root(&mut self, reader: usize, editor: usize) -> Result<(), TrapError> {
        if reader == editor || reader >= self.cpus.len() || editor >= self.cpus.len() {
            return Err(fail("invalid fixture root sharing slots"));
        }
        let root = self.cpus[editor]
            .fd()
            .get_sregs()
            .map_err(|e| fail(e.to_string()))?
            .cr3;
        let mut reader_sregs = self.cpus[reader]
            .fd()
            .get_sregs()
            .map_err(|e| fail(e.to_string()))?;
        reader_sregs.cr3 = root;
        self.cpus[reader]
            .fd()
            .set_sregs(&reader_sregs)
            .map_err(|e| fail(e.to_string()))?;
        // The fixed 0x600000 descriptor fixture issues MM key 1. Bind both
        // tasks to that exact owner before either enters the shared root.
        self.task(editor).mm.key.store(1, Ordering::Release);
        self.task(reader).mm.key.store(1, Ordering::Release);
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        table.members[editor].publish(root, 1, 1);
        table.members[reader].publish(root, 1, 1);
        Ok(())
    }

    /// Bind one stopped descriptor fixture to its fixed MM editor identity.
    /// The fixture's EditOwner names MM key 1 for the 0x600000 root.
    pub fn fixture_bind_descriptor_owner(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let root = self.cpus[index]
            .fd()
            .get_sregs()
            .map_err(|e| fail(e.to_string()))?
            .cr3;
        if root != LAYOUT.pml4_base {
            return Err(fail("descriptor fixture requires first root"));
        }
        self.task(index).mm.key.store(1, Ordering::Release);
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        table.members[index].publish(root, 1, 1);
        Ok(())
    }

    /// A live host party of `object`'s previous incarnation: it binds both
    /// readiness lanes of `object` in the production native zone, then holds
    /// their real queue locks on its own thread until told to release, or
    /// until `bound`. The hold retains the carrier RAM, so it may outlive a
    /// run that consumed this carrier.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_hold_ipc_readiness_lanes(
        &self,
        object: carrick_el1_abi::ipc::IpcObjectHandle,
        bound: Duration,
    ) -> Result<FixtureReadinessLaneHold, TrapError> {
        use carrick_el1_abi::ipc::{object_wait_key, pipe::WaitFor};
        let keys = [WaitFor::Readable, WaitFor::Writable]
            .map(|lane| object_wait_key(object, lane).ok_or_else(|| fail("IPC lane key")));
        let [readable, writable] = keys;
        let keys = [readable?, writable?];
        let ram = Arc::clone(self.custody.ram());
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let complete = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >| {
                let _ = owned.into_parts();
            };
            let Some(zone) = ram.host_ptr(
                PRODUCTION_METADATA_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            ) else {
                let _ = held_tx.send(Err("production zone backing"));
                return false;
            };
            // SAFETY: boot initialized the aligned production zone in this
            // retained window, and `ram` keeps it mapped; every access is
            // through the zone's own atomic lock protocol.
            let zone = unsafe { &*zone.cast::<X86Cpl0Zone>() };
            let spin = carrick_sched_core::BoundedSpin(1 << 20);
            let mut guards = Vec::new();
            for key in keys {
                if zone.bind_object_wait(key, &spin, &complete).is_err() {
                    let _ = held_tx.send(Err("bind previous incarnation lane"));
                    return false;
                }
                match zone.object_wait(key, &spin, &complete) {
                    Ok(guard) => guards.push(guard),
                    Err(_) => {
                        let _ = held_tx.send(Err("hold previous incarnation lane"));
                        return false;
                    }
                }
            }
            let _ = held_tx.send(Ok(()));
            let requested = release_rx.recv_timeout(bound).is_ok();
            drop(guards);
            requested
        });
        match held_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(FixtureReadinessLaneHold {
                release: Some(release),
                thread: Some(thread),
            }),
            Ok(Err(reason)) => Err(fail(reason)),
            Err(_) => Err(fail("readiness lane holder did not report")),
        }
    }

    /// Stage an exact byte in a stopped fixture's retained backing.
    pub fn fixture_write_backing_byte(&mut self, gpa: u64, value: u8) -> Result<(), TrapError> {
        if !matches!(gpa, 0xd1_1000 | 0x4_0000 | 0x4_0008) {
            return Err(fail("fixture byte outside admitted backing"));
        }
        self.custody
            .memory_mut()
            .write(FrameGpa::new(gpa), &[value])
            .map_err(|e| fail(e.to_string()))
    }

    /// Queue the native KICK on a stopped CPL3 vCPU before its next KVM_RUN.
    /// KVM_INTERRUPT rejects an in-kernel IRQ chip; the retained APIC ID
    /// addresses an MSI directly to this CPU's local APIC instead.
    pub fn queue_resume_kick(&mut self, index: usize) -> Result<(), TrapError> {
        let cpu = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        let sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
        let regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
        if sregs.cs.dpl != 3 || sregs.cs.selector & 3 != 3 || regs.rflags & (1 << 9) == 0 {
            return Err(fail(format!(
                "resume kick requires CPL3 with IF set: cs={:#x} dpl={} rip={:#x} rflags={:#x}",
                sregs.cs.selector, sregs.cs.dpl, regs.rip, regs.rflags
            )));
        }
        let events = cpu
            .fd()
            .get_vcpu_events()
            .map_err(|e| fail(e.to_string()))?;
        if events.interrupt.shadow != 0 || events.interrupt.injected != 0 {
            return Err(fail(
                "resume kick has an interrupt shadow or injected vector",
            ));
        }
        let apic_id = self.lapic_register(index, 0x20)? >> 24;
        let msi = kvm_msi {
            address_lo: 0xfee0_0000 | (apic_id << 12),
            data: u32::from(carrick_x86::interrupts::KICK_VECTOR),
            ..Default::default()
        };
        if self
            .custody
            .memory()
            .vm()
            .vm
            .signal_msi(msi)
            .map_err(|e| fail(format!("KVM_SIGNAL_MSI: {e}")))?
            <= 0
        {
            return Err(fail("resume kick MSI was blocked"));
        }
        Ok(())
    }

    fn fixture_run_until(
        &mut self,
        index: usize,
        condition: FixtureStopCondition,
    ) -> Result<(), TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let (address, pending) = match condition {
            FixtureStopCondition::UserByte(gpa, _) => {
                let pointer = self
                    .custody
                    .ram()
                    .host_ptr(gpa, 1)
                    .ok_or_else(|| fail("fixture user flag outside backing"))?;
                (pointer as usize, false)
            }
            FixtureStopCondition::PendingKick(slot) => {
                let offset = BINDING_OFFSET + slot as u64 * STRIDE;
                let pointer = self
                    .custody
                    .ram()
                    .host_ptr(META_GPA + offset, size_of::<CpuBinding>())
                    .ok_or_else(|| fail("fixture IRQ binding outside backing"))?
                    .cast::<CpuBinding>();
                // SAFETY: the retained metadata page contains this initialized
                // per-CPU binding through both the watcher and stopped vCPU.
                let pending = unsafe { &(*pointer).pending_irqs };
                (pending as *const AtomicU32 as usize, true)
            }
        };
        let retained_ram = Arc::clone(self.custody.ram());
        let stopped = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let kick = KvmKickHandle::for_current_thread();
            let stopped_ref = &stopped;
            let watcher = scope.spawn(move || {
                let _retained_ram = retained_ram;
                let start = std::time::Instant::now();
                loop {
                    // SAFETY: the retained GuestRam owns the backing; the
                    // guest writes the byte atomically and the binding field
                    // is AtomicU32. The watcher never mutates either record.
                    let reached = unsafe {
                        if pending {
                            (&*(address as *const AtomicU32)).load(Ordering::Acquire) & 2 != 0
                        } else {
                            let FixtureStopCondition::UserByte(_, expected) = condition else {
                                return false;
                            };
                            (&*(address as *const AtomicU8)).load(Ordering::Acquire) == expected
                        }
                    };
                    if reached {
                        kick.kick();
                        return true;
                    }
                    if stopped_ref.load(Ordering::Acquire) {
                        return false;
                    }
                    if start.elapsed() >= Duration::from_secs(5) {
                        kick.kick();
                        return false;
                    }
                    std::hint::spin_loop();
                }
            });
            let exit = self.run_cpu(index);
            stopped.store(true, Ordering::Release);
            let reached = watcher
                .join()
                .map_err(|_| fail("fixture stop watcher panicked"))?;
            if !reached {
                return Err(fail("fixture stop condition was not reached"));
            }
            if !matches!(exit?, VcpuExit::Kicked) {
                return Err(fail("fixture stop did not interrupt KVM_RUN"));
            }
            Ok(())
        })
    }

    /// Stop a running CPL3 loop only after its first user byte store reached
    /// retained host backing. This leaves the exact guest registers stopped.
    pub fn fixture_stop_after_user_byte(
        &mut self,
        index: usize,
        gpa: u64,
    ) -> Result<(), TrapError> {
        self.fixture_run_until(index, FixtureStopCondition::UserByte(gpa, 1))
    }

    pub fn fixture_stop_after_user_value(
        &mut self,
        index: usize,
        gpa: u64,
        value: u8,
    ) -> Result<(), TrapError> {
        self.fixture_run_until(index, FixtureStopCondition::UserByte(gpa, value))
    }

    /// Observe the actual #PF record after resuming a stopped CPL3 load.
    /// A stale TLB entry instead keeps the user loop alive until the watchdog
    /// cancels KVM_RUN; that is a failed witness, not an accepted timeout.
    pub fn fixture_run_until_user_fault(
        &mut self,
        index: usize,
        rip: u64,
        va: u64,
    ) -> Result<(), TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let watchdog = Watchdog::start();
        let mut words = Vec::with_capacity(carrick_x86::X86_FAULT_RECORD_U32_WORDS);
        while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
            let exit = watchdog.during_guest(|| self.run_cpu(index))?;
            if watchdog.expired() {
                return Err(fail("stopped user load did not fault before deadline"));
            }
            let VcpuExit::IoOut {
                port: carrick_x86::FAULT_DOORBELL_PORT,
                data,
            } = exit
            else {
                return Err(fail("stopped user load exited without fault record"));
            };
            words.push(u32::from_le_bytes(
                data.as_slice()
                    .try_into()
                    .map_err(|_| fail("fixture fault word width"))?,
            ));
        }
        let record = carrick_x86::FaultDoorbellRecord::from_u32_words(&words)?;
        if record.vector != 14 || record.rip != rip || record.cr2 != va || record.cs & 3 != 3 {
            return Err(fail(format!("unexpected stopped user fault: {record:?}")));
        }
        Ok(())
    }

    /// Single-step a stopped fixture until the next instruction is the exact
    /// requested user RIP. This does not edit guest registers or execute the
    /// instruction at `rip`; every step is bounded and the debug control is
    /// removed before the vCPU returns to its ordinary owner.
    pub fn fixture_stop_before_user_rip(
        &mut self,
        index: usize,
        rip: u64,
    ) -> Result<(), TrapError> {
        let cpu = self
            .cpus
            .get_mut(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        let debug = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            ..Default::default()
        };
        cpu.fd()
            .set_guest_debug(&debug)
            .map_err(|e| fail(format!("KVM_SET_GUEST_DEBUG: {e}")))?;
        let watchdog = Watchdog::start();
        let result = (|| {
            for _ in 0..16 {
                let regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
                let sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
                if sregs.cs.dpl != 3 || sregs.cs.selector & 3 != 3 {
                    return Err(fail("fixture single-step left CPL3"));
                }
                if regs.rip == rip {
                    return Ok(());
                }
                let exit = watchdog
                    .during_guest(|| cpu.fd_mut().run())
                    .map_err(|e| fail(format!("KVM_RUN single-step: {e}")))?;
                if watchdog.expired() {
                    return Err(fail("fixture single-step exceeded deadline"));
                }
                if !matches!(exit, KvmExit::Debug(_)) {
                    return Err(fail("fixture single-step exited without debug trap"));
                }
            }
            Err(fail("fixture did not stop at requested user RIP"))
        })();
        cpu.fd()
            .set_guest_debug(&kvm_guest_debug::default())
            .map_err(|e| fail(format!("KVM_SET_GUEST_DEBUG reset: {e}")))?;
        result
    }

    /// Stop the resumed CPU as soon as its own native KICK gate published the
    /// pending mailbox bit, before another fixture operation changes state.
    pub fn fixture_run_until_pending_kick(&mut self, index: usize) -> Result<(), TrapError> {
        self.fixture_run_until(index, FixtureStopCondition::PendingKick(index))
    }

    /// Run the vCPU until it stops on FORWARD_PORT in CPL0, returning the saved
    /// control frame and setting its frame result to zero so it can resume transparently.
    pub fn fixture_run_until_forward(&mut self, index: usize) -> Result<NativeFrame, TrapError> {
        let exit = self.run_cpu(index)?;
        let VcpuExit::IoOut {
            port: FORWARD_PORT, ..
        } = exit
        else {
            return Err(fail("expected FORWARD_PORT exit"));
        };
        self.custody.record_host_forward();
        let address = self.cpus[index].get_gpr(X86Reg::Rax)?;
        let stack_end = checked_stack_end(self.binding(index).kernel_stack)
            .ok_or_else(|| fail("CPL0 control kernel stack overflow"))?;
        let gpa = checked_private_stack_frame_gpa(stack_end, address, size_of::<NativeFrame>())
            .ok_or_else(|| fail("CPL0 control frame outside its private supervisor stack"))?;
        let ptr = self
            .custody
            .ram()
            .host_ptr(gpa, size_of::<NativeFrame>())
            .ok_or_else(|| fail("CPL0 control frame outside backing"))?
            .cast::<NativeFrame>();
        let frame = unsafe { *ptr };
        unsafe { (*ptr).rax = 0 };
        Ok(frame)
    }

    /// Read a CPU's last seen shootdown generation recorded by its CR3 reload path.
    pub fn fixture_last_seen_generation(&self, index: usize) -> Result<u64, TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        Ok(self
            .binding(index)
            .last_seen_generation
            .load(Ordering::Acquire))
    }

    /// Exact retained generations and acknowledgements for a stopped fixture.
    pub fn fixture_shootdown_state(&self) -> [(u64, u64, [u64; 2]); 2] {
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        core::array::from_fn(|sender| {
            let request = &table.requests[sender];
            (
                request.root.load(Ordering::Acquire),
                request.generation.load(Ordering::Acquire),
                core::array::from_fn(|peer| request.ack[peer].load(Ordering::Acquire)),
            )
        })
    }
    pub fn fixture_shootdown_owner(&self, sender: usize) -> Result<(u64, u64), TrapError> {
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        let request = table
            .requests
            .get(sender)
            .ok_or_else(|| fail("unknown shootdown sender"))?;
        Ok((
            request.mm_key.load(Ordering::Acquire),
            request.owner_generation.load(Ordering::Acquire),
        ))
    }
    pub fn fixture_kick_generation_checks(&self, slot: usize) -> Result<u64, TrapError> {
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        Ok(table
            .kick_checks
            .get(slot)
            .ok_or_else(|| fail("unknown shootdown CPU"))?
            .load(Ordering::Acquire))
    }
    pub fn fixture_shootdown_served(&self, sender: usize, slot: usize) -> Result<u64, TrapError> {
        let table: &ShootdownTable = self.metadata(SHOOTDOWN_OFFSET);
        let request = table
            .requests
            .get(sender)
            .ok_or_else(|| fail("unknown shootdown sender"))?;
        let served = request
            .served
            .get(slot)
            .ok_or_else(|| fail("unknown shootdown CPU"))?;
        Ok(served.load(Ordering::Acquire))
    }
    /// The installed KVM CPUID capability for the stopped fixture vCPU.
    pub fn has_tsc_deadline(&self, index: usize) -> Result<bool, TrapError> {
        let cpu = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        let cpuid = cpu
            .fd()
            .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| fail(format!("KVM_GET_CPUID2: {e}")))?;
        Ok(cpuid
            .as_slice()
            .iter()
            .any(|entry| entry.function == 1 && entry.ecx & (1 << 24) != 0))
    }
    /// Request a stopped fixture's next KVM_RUN to exit immediately. This
    /// exercises the same cancellation result as a cross-thread KVM kick.
    pub fn fixture_cancel_next_run(&mut self, index: usize) -> Result<(), TrapError> {
        let cpu = self
            .cpus
            .get_mut(index)
            .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
        cpu.fd_mut().set_kvm_immediate_exit(1);
        Ok(())
    }
    fn task(&self, index: usize) -> &CurrentTask {
        self.metadata(TASK_OFFSET + index as u64 * STRIDE)
    }
    pub(crate) fn slot(&self, index: usize) -> &ThreadControlSlot {
        self.metadata(CONTROL_OFFSET + index as u64 * STRIDE)
    }
    /// Read the stopped fixture task's Linux robust-list head.
    pub fn robust_list_head(&self, index: usize) -> Result<u64, TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 task"));
        }
        Ok(self.slot(index).robust_list().0)
    }
    /// Qualify separate exact task/MM owners, even with reused visible IDs.
    /// All vCPUs are stopped under this exclusively borrowed fixture carrier.
    pub fn bind_execution(
        &mut self,
        index: usize,
        birth_serial: carrick_sched_core::process::TaskSerial,
        binding: carrick_el1_abi::ExecutionBinding,
        file_table: u64,
    ) -> Result<(), TrapError> {
        self.custody
            .bind_execution(index, birth_serial, binding, file_table)
    }

    pub fn unload_execution(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        self.task(index).clear();
        Ok(())
    }

    pub fn entry_state(&self) -> EntryState {
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        EntryState {
            bindings: core::array::from_fn(|i| {
                let task = self.task(i);
                carrick_core::entry::binding(&task.execution, &task.mm)
            }),
            heads: [self.slot(0).robust_list(), self.slot(1).robust_list()],
            entries: core::array::from_fn(|i| self.binding(i).entries.load(Ordering::Acquire)),
            publications: core::array::from_fn(|i| {
                self.binding(i).publications.load(Ordering::Acquire)
            }),
            completions: core::array::from_fn(|i| {
                self.binding(i).completions.load(Ordering::Acquire)
            }),
            served: counters.served[99].load(Ordering::Acquire),
            host_forwards: self.custody.host_forwards(),
        }
    }

    pub fn inject_boundary_kicks(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        self.binding(index).entry_kick.store(1, Ordering::Release);
        self.binding(index).return_kick.store(1, Ordering::Release);
        Ok(())
    }

    /// Run until a user fixture reports its last result. A finite exit budget
    /// and owned watchdog bound transport loops and an in-guest infinite loop.
    pub fn observe(&mut self, index: usize) -> Result<Observation, TrapError> {
        self.observe_with_forward(index, |frame| {
            Err(fail(format!("unported CPL0 native call {}", frame.rax)))
        })
    }

    /// Run both admitted fixture CPUs at once through their first control
    /// result. This is a bounded live rendezvous witness: neither CPU's KVM_RUN
    /// may be replaced by a host-side completion of its peer's request.
    pub fn fixture_observe_pair(&mut self) -> Result<[u64; 2], TrapError> {
        fn first_result(
            cpu: &mut KvmVcpu,
            ram: &GuestRam,
            stack_end: u64,
            table: &ShootdownTable,
            slot: usize,
            vm: &VmFd,
            execution: &RwLock<()>,
        ) -> Result<u64, TrapError> {
            let watchdog = Watchdog::start();
            for _ in 0..32 {
                let exit =
                    watchdog.during_guest(|| run_member(cpu, table, slot, vm, None, execution))?;
                if watchdog.expired() {
                    return Err(fail("paired fixture guest interval deadline"));
                }
                match exit {
                    VcpuExit::IoOut {
                        port: CONTROL_PORT, ..
                    } => {
                        let address = cpu.get_gpr(X86Reg::Rax)?;
                        let gpa = checked_private_stack_frame_gpa(
                            stack_end,
                            address,
                            size_of::<NativeFrame>(),
                        )
                        .ok_or_else(|| fail("paired control frame outside private stack"))?;
                        let ptr = ram
                            .host_ptr(gpa, size_of::<NativeFrame>())
                            .ok_or_else(|| fail("paired control frame outside backing"))?
                            .cast::<NativeFrame>();
                        // SAFETY: this thread exclusively owns the stopped
                        // vCPU and its retained private kernel stack.
                        return Ok(unsafe { (*ptr).rdi });
                    }
                    VcpuExit::IoOut {
                        port:
                            carrick_x86::cpl0_scheduler::PROGRESS_ENTRY_PORT
                            | carrick_x86::cpl0_scheduler::PROGRESS_RETURN_PORT,
                        ..
                    } => {}
                    VcpuExit::IoOut {
                        port: FATAL_PORT, ..
                    } => {
                        return Err(fail("paired fixture fatal exit"));
                    }
                    VcpuExit::IoOut { port, .. } => {
                        return Err(fail(format!("paired fixture port {port:#x}")));
                    }
                    _ => return Err(fail("paired fixture non-control exit")),
                }
            }
            Err(fail("paired fixture exit budget"))
        }
        let ram = Arc::clone(self.custody.ram());
        let stacks = [
            checked_stack_end(self.binding(0).kernel_stack)
                .ok_or_else(|| fail("first kernel stack overflow"))?,
            checked_stack_end(self.binding(1).kernel_stack)
                .ok_or_else(|| fail("second kernel stack overflow"))?,
        ];
        // SAFETY: the retained table outlives both scoped guest-run threads.
        let table = unsafe { self.custody.metadata::<ShootdownTable>(SHOOTDOWN_OFFSET) };
        let vm = &self.custody.memory().vm().vm;
        let execution = &self.custody.file_execution();
        let [a, b] = &mut self.cpus;
        std::thread::scope(|scope| {
            let left = scope.spawn(|| first_result(a, &ram, stacks[0], table, 0, vm, execution));
            let right = scope.spawn(|| first_result(b, &ram, stacks[1], table, 1, vm, execution));
            let a = left.join().map_err(|_| fail("paired CPU 0 host panic"))??;
            let b = right
                .join()
                .map_err(|_| fail("paired CPU 1 host panic"))??;
            Ok([a, b])
        })
    }

    /// Run both vCPUs concurrently: the editor retires a page while the reader
    /// is actively executing in user mode. Proves that the live cross-CPU shootdown
    /// IPI invalidates the translation and causes the reader's next load to fault.
    pub fn fixture_two_running_cpus_shootdown_fault(
        &mut self,
        editor: usize,
        reader: usize,
        fault_rip: u64,
        fault_va: u64,
    ) -> Result<u64, TrapError> {
        self.fixture_two_running_cpus_shootdown_fault_inner(
            editor,
            reader,
            fault_rip,
            fault_va,
            carrick_x86::cpl0_entry::FIXTURE_HOLD_NONE,
        )
    }

    /// Run both vCPUs concurrently with the shootdown IPI held until the reader
    /// has faulted on the retired leaf. Forces the exact interleaving where the
    /// running peer takes a page fault before the IPI is delivered.
    pub fn fixture_two_running_cpus_shootdown_fault_held_ipi(
        &mut self,
        editor: usize,
        reader: usize,
        fault_rip: u64,
        fault_va: u64,
    ) -> Result<u64, TrapError> {
        self.fixture_two_running_cpus_shootdown_fault_inner(
            editor,
            reader,
            fault_rip,
            fault_va,
            carrick_x86::cpl0_entry::FIXTURE_HOLD_IPI,
        )
    }

    /// Run both vCPUs concurrently with publication held until the reader has
    /// faulted on the gated unmapped address and stopped. Forces the exact interleaving
    /// where the peer stops before the retired generation is published, proving
    /// that it retains its debt and settles on reentry.
    pub fn fixture_two_running_cpus_shootdown_fault_held_publish(
        &mut self,
        editor: usize,
        reader: usize,
        fault_rip: u64,
        fault_va: u64,
    ) -> Result<u64, TrapError> {
        self.fixture_two_running_cpus_shootdown_fault_inner(
            editor,
            reader,
            fault_rip,
            fault_va,
            carrick_x86::cpl0_entry::FIXTURE_HOLD_PUBLISH,
        )
    }

    /// Resume a stopped CPL0 CPU so its KICK handler can settle retained shootdown
    /// debt and reload CR3 before further execution.
    pub fn fixture_resume_stopped_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError> {
        let watchdog = Watchdog::start();
        let exit = watchdog.during_guest(|| self.run_cpu(index))?;
        if watchdog.expired() {
            return Err(fail("stopped CPU reentry exceeded deadline"));
        }
        if !matches!(
            exit,
            VcpuExit::IoOut {
                port: CONTROL_PORT,
                ..
            }
        ) {
            return Err(fail(
                "stopped CPU reentry did not reach completion doorbell",
            ));
        }
        Ok(exit)
    }

    fn fixture_two_running_cpus_shootdown_fault_inner(
        &mut self,
        editor: usize,
        reader: usize,
        fault_rip: u64,
        fault_va: u64,
        hold_mode: u32,
    ) -> Result<u64, TrapError> {
        if editor >= 2 || reader >= 2 || editor == reader {
            return Err(fail("invalid fixture CPU slots"));
        }
        self.fixture_write_backing_byte(0x4_0008, 0)?;
        let ram = Arc::clone(self.custody.ram());
        let stack_end = checked_stack_end(self.binding(editor).kernel_stack)
            .ok_or_else(|| fail("editor kernel stack overflow"))?;
        let table = unsafe { self.custody.metadata::<ShootdownTable>(SHOOTDOWN_OFFSET) };
        let vm = &self.custody.memory().vm().vm;
        let execution = &self.custody.file_execution();
        let [a, b] = &mut self.cpus;
        let (editor_cpu, reader_cpu) = if editor == 0 { (a, b) } else { (b, a) };
        if hold_mode != carrick_x86::cpl0_entry::FIXTURE_HOLD_NONE {
            table.fixture_hold_ipi.store(hold_mode, Ordering::Release);
        }

        let (editor_res, reader_res) = std::thread::scope(|scope| {
            let reader_handle = scope.spawn(|| {
                let watchdog = Watchdog::start();
                let start = std::time::Instant::now();
                let mut words = Vec::with_capacity(carrick_x86::X86_FAULT_RECORD_U32_WORDS);
                while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
                    let exit = watchdog.during_guest(|| {
                        run_member(reader_cpu, table, reader, vm, None, execution)
                    })?;
                    if watchdog.expired() || start.elapsed() > Duration::from_secs(5) {
                        return Err(fail("running reader did not fault before deadline"));
                    }
                    if let VcpuExit::IoOut {
                        port: carrick_x86::FAULT_DOORBELL_PORT,
                        data,
                    } = exit
                    {
                        if hold_mode == carrick_x86::cpl0_entry::FIXTURE_HOLD_IPI {
                            table.fixture_hold_ipi.store(
                                carrick_x86::cpl0_entry::FIXTURE_HOLD_NONE,
                                Ordering::Release,
                            );
                        }
                        words.push(u32::from_le_bytes(
                            data.as_slice()
                                .try_into()
                                .map_err(|_| fail("fixture fault word width"))?,
                        ));
                    }
                }
                let record = carrick_x86::FaultDoorbellRecord::from_u32_words(&words)?;
                if hold_mode == carrick_x86::cpl0_entry::FIXTURE_HOLD_PUBLISH {
                    table.fixture_hold_ipi.store(
                        carrick_x86::cpl0_entry::FIXTURE_HOLD_NONE,
                        Ordering::Release,
                    );
                }
                if record.vector != 14
                    || record.rip != fault_rip
                    || record.cr2 != fault_va
                    || record.cs & 3 != 3
                {
                    return Err(fail(format!("unexpected running user fault: {record:?}")));
                }
                Ok(())
            });

            let editor_handle = scope.spawn(|| {
                let watchdog = Watchdog::start();
                let start = std::time::Instant::now();
                {
                    while ram
                        .host_ptr(0x4_0000, 1)
                        .map(|p| unsafe { (&*p.cast::<AtomicU8>()).load(Ordering::Acquire) })
                        .unwrap_or(0)
                        != 0x11
                    {
                        if start.elapsed() > Duration::from_secs(5) {
                            return Err(fail("running reader never completed loop iteration"));
                        }
                        std::hint::spin_loop();
                    }
                }
                for _ in 0..32 {
                    let exit = watchdog.during_guest(|| {
                        run_member(editor_cpu, table, editor, vm, None, execution)
                    })?;
                    if watchdog.expired() {
                        return Err(fail("running editor deadline"));
                    }
                    match exit {
                        VcpuExit::IoOut {
                            port: CONTROL_PORT, ..
                        } => {
                            let address = editor_cpu.get_gpr(X86Reg::Rax)?;
                            let gpa = checked_private_stack_frame_gpa(
                                stack_end,
                                address,
                                size_of::<NativeFrame>(),
                            )
                            .ok_or_else(|| fail("editor control frame outside private stack"))?;
                            let ptr = ram
                                .host_ptr(gpa, size_of::<NativeFrame>())
                                .ok_or_else(|| fail("editor control frame outside backing"))?
                                .cast::<NativeFrame>();
                            return Ok(unsafe { (*ptr).rdi });
                        }
                        VcpuExit::IoOut {
                            port: FATAL_PORT, ..
                        } => {
                            return Err(fail("editor fixture fatal exit"));
                        }
                        VcpuExit::IoOut {
                            port: ENTRY_KICK_PORT | RETURN_KICK_PORT,
                            ..
                        } => {}
                        _ => return Err(fail("editor fixture non-control exit")),
                    }
                }
                Err(fail("editor fixture exit budget"))
            });

            let editor_res = match editor_handle.join() {
                Ok(res) => res,
                Err(_) => Err(fail("editor thread panic")),
            };
            let reader_res = match reader_handle.join() {
                Ok(res) => res,
                Err(_) => Err(fail("reader thread panic")),
            };
            (editor_res, reader_res)
        });
        let editor_res = editor_res?;
        reader_res?;
        Ok(editor_res)
    }

    /// Resume a stopped native entry after its host service has completed.
    /// The closure receives the exact supervisor frame that rang FORWARD_PORT.
    pub fn observe_with_forward(
        &mut self,
        index: usize,
        mut forward: impl FnMut(&mut NativeFrame) -> Result<(), TrapError>,
    ) -> Result<Observation, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let watchdog = Watchdog::start();
        for _ in 0..32 {
            let exit = watchdog
                .during_guest(|| self.run_cpu(index))
                .map_err(|e| fail(e.to_string()))?;
            if watchdog.expired.load(Ordering::Acquire) {
                let mut detail = "CPL0 fixture deadline".to_owned();
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            let VcpuExit::IoOut { port, .. } = exit else {
                let mut detail = "unexpected CPL0 non-control exit".to_owned();
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            };
            if !matches!(
                port,
                CONTROL_PORT
                    | FORWARD_PORT
                    | ENTRY_KICK_PORT
                    | RETURN_KICK_PORT
                    | WORK_PORT
                    | FATAL_PORT
                    | YIELD_PORT
            ) {
                let mut detail = format!("unexpected CPL0 port {port:#x}");
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            if port == FATAL_PORT {
                if let Some(detail) = carrick_x86_cpl0_host::ring_panic::fatal_port_panic_detail(
                    self.custody.memory(),
                    |reg| self.cpus[index].get_gpr(reg),
                )? {
                    return Err(fail(detail));
                }
                let payload = self.cpus[index].get_gpr(X86Reg::Rax)?;
                let fault = self.user_fault_state(index)?;
                let mut detail = format!("CPL0 fatal exit: payload {payload:#x}, fault {fault:?}");
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            if port == YIELD_PORT {
                self.custody.record_host_yield();
                continue;
            }
            let address = self.cpus[index].get_gpr(X86Reg::Rax)?;
            let stack_end = checked_stack_end(self.binding(index).kernel_stack)
                .ok_or_else(|| fail("CPL0 control kernel stack overflow"))?;
            let gpa = checked_private_stack_frame_gpa(stack_end, address, size_of::<NativeFrame>())
                .ok_or_else(|| fail("CPL0 control frame outside its private supervisor stack"))?;
            let ptr = self
                .custody
                .ram()
                .host_ptr(gpa, size_of::<NativeFrame>())
                .ok_or_else(|| fail("CPL0 control frame outside backing"))?
                .cast::<NativeFrame>();
            // SAFETY: the exclusive stopped vCPU published this supervisor
            // frame; no other CPU uses its private kernel stack.
            let frame = unsafe { &mut *ptr };
            match port {
                CONTROL_PORT => {
                    let counters: &Counters = self.metadata(COUNTERS_OFFSET);
                    return Ok(Observation {
                        result: frame.rdi as i64,
                        heads: [self.slot(0).robust_list(), self.slot(1).robust_list()],
                        served: counters.served[99].load(Ordering::Acquire),
                        forwarded: counters.forwarded[99].load(Ordering::Acquire),
                        semantic_host_exits: self.custody.host_forwards(),
                        entries: core::array::from_fn(|i| {
                            self.binding(i).entries.load(Ordering::Acquire)
                        }),
                        publications: core::array::from_fn(|i| {
                            self.binding(i).publications.load(Ordering::Acquire)
                        }),
                        completions: core::array::from_fn(|i| {
                            self.binding(i).completions.load(Ordering::Acquire)
                        }),
                        kicks: self.custody.kicks(),
                        work_exits: self.custody.work_exits(),
                        captured_stack: self.binding(index).captured_stack.load(Ordering::Acquire),
                        returned_stack: frame.rsp,
                        preserved_rbx: frame.rbx,
                        host_yields: self.custody.host_yields(),
                    });
                }
                FORWARD_PORT => {
                    self.custody.record_host_forward();
                    forward(frame)?;
                }
                ENTRY_KICK_PORT | RETURN_KICK_PORT => {
                    self.task(index).linux.mark_pending_host_work();
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(1);
                    let kicked = self.run_cpu(index);
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(0);
                    if !matches!(kicked, Ok(VcpuExit::Kicked)) {
                        return Err(fail("boundary kick did not interrupt KVM_RUN"));
                    }
                    self.custody.record_kick();
                }
                WORK_PORT => {
                    if self.task(index).linux.take_served_boundary().is_none() {
                        return Err(fail("work exit without completed syscall"));
                    }
                    // This standalone carrier has no zone or host wake
                    // owner: its work exit is the whole settlement.
                    if let Some(doorbell) = self.task(index).linux.take_host_work_doorbell() {
                        doorbell.settled();
                    }
                    self.custody.record_work_exit();
                }
                _ => return Err(fail(format!("unexpected CPL0 doorbell {port:#x}"))),
            }
        }
        Err(fail("CPL0 control exit budget exceeded"))
    }

    pub(crate) fn production_run_context(
        &self,
        slot: usize,
    ) -> Result<ProductionRunContext, TrapError> {
        self.custody.production_run_context(slot)
    }
}

impl carrick_x86_cpl0_host::cpl0_boot::Cpl0BootCarrier for Cpl0Carrier {
    type Memory = KvmVm;
    fn custody(&self) -> &KvmBootstrapCustody {
        &self.custody
    }
    fn custody_mut(&mut self) -> &mut KvmBootstrapCustody {
        &mut self.custody
    }
    fn cpu_count(&self) -> usize {
        self.cpus.len()
    }
    fn cpu_gpr(&self, index: usize, reg: X86Reg) -> Result<u64, TrapError> {
        self.cpus
            .get(index)
            .ok_or_else(|| fail("unknown CPL0 CPU"))?
            .get_gpr(reg)
    }
    fn enter_kernel(&mut self, index: usize, entry: KernelEntry) -> Result<(), TrapError> {
        let cpu = self
            .cpus
            .get_mut(index)
            .ok_or_else(|| fail("unknown CPL0 CPU"))?;
        let mut sregs = cpu
            .fd()
            .get_sregs()
            .map_err(|error| fail(error.to_string()))?;
        sregs.cs = crate::kvm_x86_engine::KvmSegment::from(carrick_x86::SegmentDescriptor::code64(
            carrick_x86::SegmentDpl::Kernel,
        ))
        .0;
        sregs.ss = crate::kvm_x86_engine::KvmSegment::from(
            carrick_x86::SegmentDescriptor::flat_data(carrick_x86::SegmentDpl::Kernel, 0),
        )
        .0;
        sregs.gs.base = entry.gs_base;
        cpu.fd()
            .set_sregs(&sregs)
            .map_err(|error| fail(error.to_string()))?;
        let msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: 0xc000_0102,
            data: 0,
            ..Default::default()
        }])
        .map_err(|error| fail(error.to_string()))?;
        if cpu
            .fd()
            .set_msrs(&msrs)
            .map_err(|error| fail(error.to_string()))?
            != 1
        {
            return Err(fail("production user GS initialization"));
        }
        let mut regs = cpu
            .fd()
            .get_regs()
            .map_err(|error| fail(error.to_string()))?;
        regs.rip = entry.rip;
        regs.rdi = entry.rdi;
        regs.rsp = entry.rsp;
        regs.rflags = 2;
        cpu.fd()
            .set_regs(&regs)
            .map_err(|error| fail(error.to_string()))
    }
    fn run_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError> {
        Cpl0Carrier::run_cpu(self, index)
    }
    fn append_debug_state(&self, index: usize, detail: &mut String) {
        if let Some(cpu) = self.cpus.get(index) {
            cpu.append_debug_state(detail);
        }
    }
}

pub(crate) trait Cpl0HostCustodyKvmExt {
    fn production_run_context(&self, slot: usize) -> Result<ProductionRunContext, TrapError>;
}

impl Cpl0HostCustodyKvmExt for KvmBootstrapCustody {
    fn production_run_context(&self, slot: usize) -> Result<ProductionRunContext, TrapError> {
        if slot >= self.actual_run().len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        Ok(ProductionRunContext {
            ram: Arc::clone(self.ram()),
            vm: Arc::clone(&self.memory().vm().vm),
            actual_run: Arc::clone(self.actual_run()),
            file_execution: Arc::clone(self.file_execution()),
            slot,
            maintenance_root: self.maintenance_root(),
        })
    }
}

impl Cpl0Carrier {
    /// The same KVM carrier, with one fixed native context sidecar per process.
    /// This binds executing shared owners, not the production executor pool.
    pub fn boot_lifecycle(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        image: &Path,
        programs: [&[u8]; 2],
    ) -> Result<Self, TrapError> {
        use carrick_sched_core::{SlotId, ThreadIdentity, ZoneTables};
        use carrick_x86::cpl0_lifecycle::*;
        let mut carrier = Self::boot_inner(frame_inventory, image, programs, true)?;
        // SAFETY: aligned initialized empty retained supervisor backing; all
        // fixture CPUs are stopped throughout native custody publication.
        let zone = unsafe {
            &*carrier
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::PROGRESS_ZONE_GPA,
                    size_of::<ZoneTables>(),
                )
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        for index in 0..2 {
            let birth_serial =
                carrick_sched_core::process::TaskSerial::from_raw_u64(21 + index as u64)
                    .ok_or_else(|| fail("lifecycle birth serial"))?;
            let binding = carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(41 + index as u64),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(11 + index as u64),
                mm: carrick_el1_abi::EntryMmKey::from_raw(11 + index as u64),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(
                    101 + index as u64,
                ),
            };
            carrier.bind_execution(index, birth_serial, binding, 5)?;
            let root = if index == 0 {
                LAYOUT.pml4_base
            } else {
                crate::carrier_interrupts::SECOND_ROOT
            };
            let space = zone
                .spaces
                .publish_closed(binding.mm.raw(), root, 0)
                .ok_or_else(|| fail("lifecycle MM"))?;
            zone.spaces.open(space);
            let slot = SlotId::new(index as u8);
            zone.drive(slot, index as u64 + 1);
            zone.publish_slot_with_affinity(
                slot,
                binding.mm.raw(),
                Some(index as u32),
                carrick_sched_core::AffinitySource::UNBOUND,
            );
            zone.enter_guest(slot);
            zone.install_space(slot, binding.mm.raw())
                .ok_or_else(|| fail("lifecycle installed MM"))?;
            let page_address = METADATA_VA + index as u64 * 0x4000;
            let controls_address = METADATA_VA + 0xb000 + index as u64 * 0x1000;
            // SAFETY: aligned, disjoint, exclusively stopped metadata storage.
            let controls = unsafe {
                carrier
                    .custody
                    .metadata_mut::<[ThreadControlSlot; 9]>(0xb000 + index as u64 * 0x1000)
            };
            for control in controls.iter_mut() {
                *control = ThreadControlSlot::new();
            }
            controls[0].publish_visible_tid(binding.task.raw() as u32);
            let birth = carrick_core::terminal::ThreadBirthIdentity::from_parts(
                binding.task,
                carrick_core_abi::BirthSerial::of_task(birth_serial),
                binding.thread_generation,
            )
            .ok_or_else(|| fail("lifecycle birth identity"))?;
            controls[0].publish_host_birth_identity(birth);
            carrier
                .task(index)
                .publish_lifecycle(page_address, controls_address);
            let lane = LifecycleLane {
                contexts: [const { NativeBirthContext::EMPTY }; 2],
                parent: ThreadIdentity {
                    tid: binding.task.raw(),
                    serial: binding.thread_generation.raw(),
                    mm: binding.mm.raw(),
                    file_table: 5,
                    generation: binding.generation.raw(),
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1 << index,
                    lifecycle_page: page_address,
                    control_slot: controls_address,
                },
                slot,
                maintenance_root: RootGpa::page_aligned(FrameGpa::new(root))
                    .ok_or_else(|| fail("maintenance root"))?,
                data_start: LIFECYCLE_DATA,
                data_end: LIFECYCLE_DATA + 4096,
                wakes: 0,
                births: 0,
                retirements: 0,
            };
            let address = LIFECYCLE_LANE + index as u64 * LIFECYCLE_STRIDE;
            // SAFETY: aligned retained sidecar with no live CPU references yet.
            unsafe {
                carrier
                    .custody
                    .ram()
                    .host_ptr(
                        crate::carrier_interrupts::LIFECYCLE_LANES_GPA.raw()
                            + index as u64 * LIFECYCLE_STRIDE,
                        size_of::<LifecycleLane>(),
                    )
                    .ok_or_else(|| fail("native lifecycle sidecar"))?
                    .cast::<LifecycleLane>()
                    .write(lane);
            }
            carrier
                .binding(index)
                .scheduler_witness
                .store(address, Ordering::Release);
            let cpu = &carrier.cpus[index];
            crate::carrier_interrupts::qualify_xstate(cpu)?;
            let mut system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            system.cr3 = root;
            cpu.fd()
                .set_sregs(&system)
                .map_err(|e| fail(e.to_string()))?;
            // The irqchip starts secondary CPUs awaiting SIPI. This fixture
            // installs both native entry states while stopped, then admits
            // each explicitly instead of relying on firmware AP startup.
            cpu.fd()
                .set_mp_state(kvm_mp_state {
                    mp_state: KVM_MP_STATE_RUNNABLE,
                })
                .map_err(|e| fail(e.to_string()))?;
            carrier
                .custody
                .memory_mut()
                .write(
                    FrameGpa::new(LIFECYCLE_DATA + index as u64 * 4096 + 0x180),
                    &[0x5a + index as u8; 16],
                )
                .map_err(|e| fail(e.to_string()))?;
            carrier
                .custody
                .memory_mut()
                .write(
                    FrameGpa::new(LIFECYCLE_DATA + index as u64 * 4096 + 0x100),
                    &(0xf500u64 + index as u64).to_le_bytes(),
                )
                .map_err(|e| fail(e.to_string()))?;
        }
        Ok(carrier)
    }
    pub fn stock_lifecycle(
        &mut self,
        index: usize,
    ) -> Result<carrick_el1_abi::EntryRef, TrapError> {
        if index >= 2 {
            return Err(fail("unknown lifecycle lane"));
        }
        let page: &ThreadLifecyclePage = self.metadata(index as u64 * 0x4000);
        let entry = page
            .stock(
                0,
                carrick_el1_abi::EntryIdentity {
                    tid: 501 + index as u32,
                    visible_tid: 7,
                    thread_serial: 1001
                        + index as u64
                        + 2 * (page.state(0).map_or(0, |(generation, _)| generation) + 1),
                    birth: carrick_core_abi::entry::BirthSerial::of_task(
                        carrick_sched_core::process::TaskSerial::from_registry_allocation(
                            core::num::NonZeroU64::MIN,
                        ),
                    ),
                    uid_credit: 1,
                },
            )
            .map_err(|e| fail(format!("stock: {e:?}")))?;
        let controls: &[ThreadControlSlot; 9] = self.metadata(0xb000 + index as u64 * 0x1000);
        controls[1]
            .reset_for_host_birth(BlockedMask(0))
            .map_err(|e| fail(format!("reset: {e:?}")))?;
        page.bind_control_address(
            entry,
            METADATA_VA + 0xb000 + index as u64 * 0x1000 + size_of::<ThreadControlSlot>() as u64,
        )
        .map_err(|e| fail(format!("control: {e:?}")))?;
        Ok(entry)
    }
    pub fn reap_lifecycle(
        &mut self,
        index: usize,
        entry: carrick_el1_abi::EntryRef,
    ) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown lifecycle lane"));
        }
        let page: &ThreadLifecyclePage = self.metadata(index as u64 * 0x4000);
        page.reap(entry).map_err(|e| fail(format!("reap: {e:?}")))
    }
    pub fn lifecycle_state(&self, index: usize) -> Result<LifecycleObservation, TrapError> {
        use carrick_x86::cpl0_lifecycle::*;
        if index >= 2 {
            return Err(fail("unknown lifecycle lane"));
        }
        // SAFETY: exclusively stopped CPUs; retained aligned initialized sidecar.
        let lane = unsafe {
            &*self
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::LIFECYCLE_LANES_GPA.raw()
                        + index as u64 * LIFECYCLE_STRIDE,
                    size_of::<LifecycleLane>(),
                )
                .ok_or_else(|| fail("lane observation"))?
                .cast::<LifecycleLane>()
        };
        // SAFETY: boot_lifecycle owns initialized aligned retained zone RAM;
        // CPUs are stopped while the host observes it.
        let zone = unsafe {
            &*self
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::PROGRESS_ZONE_GPA,
                    size_of::<carrick_sched_core::ZoneTables>(),
                )
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<carrick_sched_core::ZoneTables>()
        };
        let page: &ThreadLifecyclePage = self.metadata(index as u64 * 0x4000);
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        let data = self
            .custody
            .ram()
            .host_ptr(LIFECYCLE_DATA + index as u64 * 4096, 64)
            .ok_or_else(|| fail("lifecycle user words"))?;
        let words = core::array::from_fn(|i| {
            // SAFETY: checked retained user storage; CPUs stopped; unaligned
            // scalar reads do not require stronger alignment than its mapping.
            unsafe { core::ptr::read_unaligned(data.add(i * 8).cast::<u64>()) }
        });
        Ok(LifecycleObservation {
            births: lane.births,
            retirements: lane.retirements,
            wakes: lane.wakes,
            live: page.live(),
            state: page.state(0),
            entries: self.binding(index).entries.load(Ordering::Acquire),
            completions: self.binding(index).completions.load(Ordering::Acquire),
            served: [220, 98, 93].map(|nr| counters.served[nr].load(Ordering::Acquire)),
            forwards: self.custody.host_forwards(),
            words,
            parked_parent_result: lane.contexts[0].frame.rax,
            timer_nodes: zone.timer_node_count(),
        })
    }
}

/// The host Exec service (#1093 S4c slice c) on this stopped carrier.
impl Cpl0Carrier {
    /// Stage an exec successor for the claimed row `receipt` on stopped
    /// `cpu`: reserve its fork-stock tables and data frames and import its
    /// rows before the arm. If a holder has the stock, `wake` is enrolled on
    /// its release.
    pub fn stage_exec_successor(
        &mut self,
        cpu: usize,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        request: carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecRequest,
        wake: carrick_hal::fork_stock::StockReleaseWake,
    ) -> Result<carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecStage, TrapError> {
        let cpu = u32::try_from(cpu)
            .ok()
            .filter(|cpu| (*cpu as usize) < self.cpus.len())
            .ok_or_else(|| fail("exec service CPU"))?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| fail(format!("exec random: {error}")))?;
        self.custody.stage_native_exec(
            carrick_guest_arch::CpuId::new(cpu),
            receipt,
            request,
            wake,
            random,
        )
    }

    /// Probe a woken parked exec once against this carrier's fork stock.
    pub fn probe_parked_exec(
        &self,
        parked: carrick_hal::exec_owner::StockParked<
            carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecRequest,
        >,
    ) -> Result<
        carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecRequest,
        carrick_hal::exec_owner::StockParked<
            carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecRequest,
        >,
    > {
        self.custody.probe_parked_exec(parked)
    }

    /// Refuse the unsealed row `receipt` and return its preparation whole.
    pub fn release_exec_successor(
        &mut self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
    ) -> Result<carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecRequest, TrapError> {
        self.custody.release_native_exec(receipt)
    }

    /// The tables and data grants a retained preparation holds.
    pub fn exec_reservation(
        &self,
        successor: ReservationMm,
    ) -> Option<(Vec<RootGpa>, Vec<carrick_core_abi::X86InitialBootGrant>)> {
        self.custody.native_exec_reservation(successor)
    }

    /// Reusable fork-stock table pages.
    pub fn fork_table_stock(&self) -> usize {
        self.custody.fork_table_stock()
    }

    /// Waiters enrolled on the fork stock's release and not yet woken.
    pub fn fork_stock_release_waiters(&self) -> usize {
        self.custody.fork_stock_release_waiters()
    }

    /// Claim an exec for `successor` as the ring's ticket would, reserving
    /// its receipt in the carrier's exec owner.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_claim_exec(
        &mut self,
        successor: ReservationMm,
        root_generation: NonZeroU64,
    ) -> Result<carrick_core_abi::service::ExecAdoptionReceipt, TrapError> {
        self.custody.fixture_claim_exec(successor, root_generation)
    }

    /// Publish the closed successor root the ring publishes before an exec.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_publish_exec_successor(
        &mut self,
        successor: ReservationMm,
    ) -> Result<NonZeroU64, TrapError> {
        self.custody.fixture_publish_exec_successor(successor)
    }

    /// What the Exec service would reserve for `image` on this carrier: its
    /// demand once the service has attached this carrier's vvar and vDSO.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_staged_exec_demand(
        &self,
        image: carrick_x86_cpl0_host::cpl0_boot::exec_service::X86ExecImage,
    ) -> Result<
        carrick_x86_cpl0_host::cpl0_boot::exec_service::ImageFrameDemand,
        carrick_abi::LinuxErrno,
    > {
        self.custody.fixture_staged_exec_demand(image)
    }

    /// Hold all but `left` fork-stock tables, as a live holder would.
    #[cfg(feature = "test-fixtures")]
    pub fn fixture_hold_fork_stock(
        &mut self,
        left: usize,
    ) -> Result<carrick_hal::fork_stock::SuccessorTables, TrapError> {
        self.custody.fixture_hold_fork_stock(left)
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_release_fork_stock(&mut self, held: carrick_hal::fork_stock::SuccessorTables) {
        self.custody.fixture_release_fork_stock(held);
    }
}

impl Cpl0Carrier {
    /// Fill the shared fixture MM census while both CPUs are stopped.
    pub fn exhaust_fork_address_spaces(&mut self) -> Result<(), TrapError> {
        use carrick_sched_core::ZoneTables;
        // SAFETY: boot_lifecycle owns initialized aligned retained zone RAM.
        let zone = unsafe {
            &*self
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::PROGRESS_ZONE_GPA,
                    size_of::<ZoneTables>(),
                )
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        let mut key = 1000;
        while zone.spaces.publish_closed(key, 0x1000, 0).is_some() {
            key += 1;
        }
        Ok(())
    }

    /// Exhaust record or wait-entry capacity in the stopped scheduler fixture.
    pub fn exhaust_lifecycle_capacity(&mut self, entries: bool) -> Result<(), TrapError> {
        use carrick_sched_core::{BoundedSpin, ThreadIdentity, ZoneTables};
        // SAFETY: the fixture owns initialized aligned zone storage; CPUs stopped.
        let zone = unsafe {
            &*self
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::PROGRESS_ZONE_GPA,
                    size_of::<ZoneTables>(),
                )
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        let identity = ThreadIdentity {
            tid: 1000,
            serial: 1,
            mm: 1000,
            file_table: 1,
            generation: 1,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: 0,
            control_slot: 0,
        };
        if entries {
            let record = zone
                .alloc_record(identity)
                .map_err(|_| fail("capacity record"))?;
            let key = 0x70000;
            let guard = zone
                .lock(ZoneTables::bucket_of(identity.mm, key), &BoundedSpin(1024))
                .ok_or_else(|| fail("capacity bucket"))?;
            while zone
                .enqueue(
                    &guard,
                    record,
                    zone.next_seq(record),
                    identity.mm,
                    key,
                    u32::MAX,
                    0,
                )
                .is_ok()
            {}
        } else {
            while zone.alloc_record(identity).is_ok() {}
        }
        Ok(())
    }

    /// Measure remaining record capacity using owned allocations while stopped.
    /// Every temporary record is returned before guest execution resumes.
    pub fn lifecycle_record_capacity(&self) -> Result<usize, TrapError> {
        use carrick_sched_core::{ThreadIdentity, ZoneTables};
        // SAFETY: boot_lifecycle owns initialized aligned retained zone RAM;
        // all guest CPUs are stopped during this diagnostic.
        let zone = unsafe {
            &*self
                .custody
                .ram()
                .host_ptr(
                    crate::carrier_interrupts::PROGRESS_ZONE_GPA,
                    size_of::<ZoneTables>(),
                )
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        let identity = ThreadIdentity {
            tid: 1001,
            serial: 1,
            mm: 1001,
            file_table: 1,
            generation: 1,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: 0,
            control_slot: 0,
        };
        let mut records = Vec::new();
        while let Ok(record) = zone.alloc_record(identity) {
            records.push(record);
        }
        let capacity = records.len();
        for record in records {
            zone.free_record(record);
        }
        Ok(capacity)
    }

    /// Stopped hardware diagnostics, retained independently of the syscall frame.
    pub fn user_fault_state(&self, index: usize) -> Result<(u64, u64, u64, u64, u64), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let binding = self.binding(index);
        let frame = binding.fault_frame.load(Ordering::Acquire);
        let (error, pc) = if frame == 0 {
            (0, 0)
        } else {
            let bytes = self
                .custody
                .memory()
                .read(
                    checked_fault_error_gpa(frame).ok_or_else(|| fail("fault frame overflow"))?,
                    16,
                )
                .map_err(|error| fail(error.to_string()))?;
            (
                u64::from_le_bytes(
                    bytes[..8]
                        .try_into()
                        .map_err(|_| fail("fault error width"))?,
                ),
                u64::from_le_bytes(bytes[8..].try_into().map_err(|_| fail("fault PC width"))?),
            )
        };
        Ok((
            binding.fault_active.load(Ordering::Acquire),
            binding.fault_address.load(Ordering::Acquire),
            error,
            pc,
            binding.fault_reason.load(Ordering::Acquire),
        ))
    }

    /// Poison reserved XSAVE header words while the faulting vCPU is stopped.
    pub fn poison_user_fault_xsave_header(&mut self, index: usize) -> Result<(), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let xsave = (self.binding(index).kernel_stack - 4160) & !63;
        self.custody
            .memory_mut()
            .write(FrameGpa::new(xsave - DIRECT_VA + 520), &[0xa5; 16])
            .map_err(|e| fail(e.to_string()))
    }

    /// Guard the 64 bytes each vCPU's old xsave frame would overwrite below
    /// its 4 KiB #PF entry stack. The vCPU1 guard is below vCPU0's saved
    /// hardware/GPR frame, so both faults may run before inspection.
    pub fn arm_user_fault_stack_canary(&mut self) -> Result<(), TrapError> {
        let first = carrick_x86::fault_stack_base(LAYOUT);
        for address in [first - 64, first + 4096 - 256] {
            self.custody
                .memory_mut()
                .write(FrameGpa::new(address), &[0xa5; 64])
                .map_err(|e| fail(e.to_string()))?;
        }
        Ok(())
    }

    pub fn user_fault_stack_canary_intact(&self) -> Result<bool, TrapError> {
        let first = carrick_x86::fault_stack_base(LAYOUT);
        for address in [first - 64, first + 4096 - 256] {
            let bytes = self
                .custody
                .memory()
                .read(FrameGpa::new(address), 64)
                .map_err(|e| fail(e.to_string()))?;
            if bytes != [0xa5; 64] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod cpl0_layout_tests {
    use super::*;
    use carrick_el1_abi::X86_CPL0_REGION_BASE;
    use std::sync::mpsc;

    #[test]
    fn production_boot_refuses_stale_layout_before_entry() {
        let mut bytes = include_bytes!(concat!(env!("OUT_DIR"), "/carrick-x86-cpl0")).to_vec();
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(&bytes, 62).expect("production ELF");
        let hash_va = IMAGE_VA + X86_INITIAL_BOOT_HEADER_GPA - IMAGE_GPA
            + core::mem::offset_of!(X86InitialBootHeader, layout_hash) as u64;
        let segment = plan
            .segments
            .iter()
            .find(|segment| {
                segment.virtual_address <= hash_va
                    && hash_va + 8 <= segment.virtual_address + segment.file_size
            })
            .expect("embedded boot fingerprint");
        let at = (segment.file_offset + hash_va - segment.virtual_address) as usize;
        let expected = carrick_el1_abi::EL1_ABI_LAYOUT_HASH;
        let found = expected ^ 1;
        bytes[at..at + 8].copy_from_slice(&found.to_le_bytes());
        let inventory = Arc::new(FrameInventoryAuthority::new())
            .physical_projection(Arc::new(ObjectIdRegistry::new()));
        let result = Cpl0Carrier::boot_bytes_inner(
            inventory,
            &bytes,
            [&[], &[]],
            false,
            Some(0x20_000),
            false,
            None,
        );
        assert!(matches!(result, Err(TrapError::ImageAbiMismatch {
            expected: e, found: f,
        }) if e == expected && f == found));
    }

    fn admission_fixture() -> Cpl0Carrier {
        let inventory = Arc::new(FrameInventoryAuthority::new())
            .physical_projection(Arc::new(ObjectIdRegistry::new()));
        let mut program = vec![0x48, 0xb8];
        program.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        Cpl0Carrier::boot(
            inventory,
            Path::new(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")),
            [&program, &program],
        )
        .expect("admission fixture")
    }

    #[test]
    fn file_region_run_refuses_host_access_without_waiting() {
        carrick_test_support::require_kvm!();
        let mut carrier = admission_fixture();
        let context = carrier
            .custody
            .production_run_context(0)
            .expect("run context");
        let stopped = carrier
            .custody
            .file_tables(carrier.file_region_binding())
            .expect("host access");
        let cpu = &mut carrier.cpus[0];
        let outcome = std::thread::scope(|scope| {
            let (send, recv) = mpsc::channel();
            let worker = scope.spawn(move || {
                let watchdog = Watchdog::start();
                send.send(watchdog.during_guest(|| context.run(cpu)))
                    .expect("run result");
            });
            let outcome = recv.recv_timeout(Duration::from_secs(2));
            // Always release custody and join, including the blocking pre-fix path.
            drop(stopped);
            worker.join().expect("join CPU");
            outcome
        });
        assert!(
            matches!(outcome, Ok(Err(TrapError::ExecutionAdmissionBusy))),
            "{:?}",
            outcome.as_ref().map(|result| result.as_ref().err())
        );
        carrier.observe(0).expect("intact admission control");
    }

    #[test]
    fn file_region_poisoned_admission_is_repeated_typed_fatal() {
        carrick_test_support::require_kvm!();
        let mut carrier = admission_fixture();
        let execution = Arc::clone(carrier.custody.file_execution());
        let poison = std::panic::catch_unwind(|| {
            let _writer = execution.write().expect("exclusive admission");
            panic!("injected host custody failure");
        });
        assert!(poison.is_err());
        for _ in 0..2 {
            let error = match carrier.run_cpu(0) {
                Err(error) => error,
                Ok(_) => panic!("poison must never admit CPU"),
            };
            assert!(
                matches!(error, TrapError::ExecutionAdmissionPoisoned),
                "{error}"
            );
            assert_eq!(
                error.to_string(),
                "fatal vCPU execution admission: protection lock poisoned"
            );
            assert_eq!(carrier.custody.actual_run()[0].load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn file_region_published_before_guest_entry() {
        carrick_test_support::require_kvm!();
        let inventory = Arc::new(FrameInventoryAuthority::new())
            .physical_projection(Arc::new(ObjectIdRegistry::new()));
        let carrier =
            Cpl0Carrier::boot_production(inventory, 0x20_000, None).expect("production carrier");
        // Reserved tail of the shared open-table allocation: publication
        // must name this VM, not a process-global host mapping.
        let header_offset = carrick_el1_abi::EL1_FILE_REGION_HEADER_OFFSET;
        let bytes = carrier
            .custody
            .memory()
            .read(FrameGpa::new(KERNEL_REGION_GPA + header_offset), 8)
            .expect("retained supervisor publication");
        assert_eq!(
            u64::from_le_bytes(bytes.try_into().expect("identity word")),
            carrier.custody.memory().identity().nonzero().get(),
            "retained file tables need the exact carrier identity before entry"
        );
    }

    #[test]
    fn file_region_host_refuses_paused_cpl0_descriptor_transaction() {
        carrick_test_support::require_kvm!();
        let inventory = Arc::new(FrameInventoryAuthority::new())
            .physical_projection(Arc::new(ObjectIdRegistry::new()));
        let lock_va = X86_CPL0_REGION_BASE
            + carrick_el1_abi::EL1_FD_MAP_OFFSET
            + carrick_el1_abi::FD_MAP_MUTATION_LOCK_OFFSET as u64;
        let mut program = vec![0x48, 0xbe]; // movabs rsi, shared lock word
        program.extend_from_slice(&lock_va.to_le_bytes());
        program.extend_from_slice(&[0xb9, 1, 0, 0, 0, 0x31, 0xc0, 0xf0, 0x0f, 0xb1, 0x0e]);
        program.extend_from_slice(&[0x66, 0xba]);
        program.extend_from_slice(&YIELD_PORT.to_le_bytes());
        program.extend_from_slice(&[0xee, 0xc7, 0x06, 0, 0, 0, 0, 0xee, 0xf4]);
        let mut carrier = Cpl0Carrier::boot(
            inventory,
            Path::new(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")),
            [&program, &program],
        )
        .expect("CPL0 transaction fixture");
        let binding = carrier.file_region_binding();
        let cpu = &mut carrier.cpus[0];
        let mut sregs = cpu.fd().get_sregs().expect("stopped sregs");
        sregs.cs = crate::kvm_x86_engine::KvmSegment::from(carrick_x86::SegmentDescriptor::code64(
            carrick_x86::SegmentDpl::Kernel,
        ))
        .0;
        sregs.ss = crate::kvm_x86_engine::KvmSegment::from(
            carrick_x86::SegmentDescriptor::flat_data(carrick_x86::SegmentDpl::Kernel, 0),
        )
        .0;
        cpu.fd().set_sregs(&sregs).expect("enter CPL0 fixture");
        let mut regs = cpu.fd().get_regs().expect("stopped regs");
        regs.rip = USER_CODE;
        regs.rflags = 2;
        cpu.fd().set_regs(&regs).expect("CPL0 entry");
        assert!(matches!(
            carrier.run_cpu(0).expect("guest acquired lock"),
            VcpuExit::IoOut {
                port: YIELD_PORT,
                ..
            }
        ));
        assert!(
            carrier
                .custody
                .fixture_file_mutation_active(binding)
                .expect("retained records"),
            "guest owns shared descriptor transaction"
        );
        let refused = matches!(
            carrier.file_tables(binding),
            Err(carrick_el1_abi::FileRegionError::MutationActive)
        );
        // Complete the actual guest unlock before asserting; no held lock leaks.
        assert!(matches!(
            carrier.run_cpu(0).expect("guest unlock control"),
            VcpuExit::IoOut {
                port: YIELD_PORT,
                ..
            }
        ));
        assert!(
            carrier.file_tables(binding).is_ok(),
            "quiescent control admitted"
        );
        assert!(
            refused,
            "physical stop must not grant a paused guest transaction"
        );
    }

    #[test]
    fn file_region_host_mutation_refused_while_cpu_running() {
        carrick_test_support::require_kvm!();
        use carrick_el1_linux::file_table::admit_host_fd;
        use std::os::fd::AsRawFd;
        let inventory = Arc::new(FrameInventoryAuthority::new())
            .physical_projection(Arc::new(ObjectIdRegistry::new()));
        // No host crossing: the CPU loops in real CPL3 until its scoped kick.
        let program = [0xc6, 0x04, 0x25, 0, 0, 4, 0, 0x77, 0xeb, 0xfe];
        let mut carrier = Cpl0Carrier::boot(
            inventory,
            Path::new(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")),
            [&program, &program],
        )
        .expect("running carrier");
        let binding = carrier.file_region_binding();
        let host = std::fs::File::open("/dev/null").expect("real host descriptor");
        let context = carrier
            .custody
            .production_run_context(0)
            .expect("run admission");
        let custody = &carrier.custody;
        let cpu = &mut carrier.cpus[0];
        let refused = std::thread::scope(|scope| {
            let (send, recv) = mpsc::channel();
            let worker = scope.spawn(move || {
                let kick = KvmKickHandle::for_current_thread();
                send.send(kick).expect("publish scoped kick");
                let watchdog = Watchdog::start();
                watchdog.during_guest(|| context.run(cpu))
            });
            let kick = recv
                .recv_timeout(Duration::from_secs(2))
                .expect("worker ready");
            let start = std::time::Instant::now();
            while custody.actual_run()[0].load(Ordering::Acquire) == 0
                || unsafe {
                    (&*custody
                        .ram()
                        .host_ptr(0x4_0000, 1)
                        .expect("live marker")
                        .cast::<AtomicU8>())
                        .load(Ordering::Acquire)
                } != 0x77
            {
                assert!(
                    start.elapsed() < Duration::from_secs(2),
                    "CPU did not enter KVM_RUN"
                );
                std::hint::spin_loop();
            }
            let refused = match custody.file_tables(binding) {
                Err(error) => error == carrick_el1_abi::FileRegionError::Running,
                Ok(tables) => {
                    admit_host_fd(
                        tables.fd_map(),
                        tables.opens(),
                        tables.objects(),
                        5,
                        19,
                        host.as_raw_fd(),
                        carrick_el1_abi::DELEGATED_FLAG_READABLE,
                    );
                    false
                }
            };
            kick.kick();
            let _stopped = worker
                .join()
                .expect("join running CPU")
                .expect("bounded KVM run");
            refused
        });
        assert!(refused, "host mutated file tables while a CPU was running");
        let tables = carrier
            .file_tables(binding)
            .expect("stopped access restored");
        assert!(
            admit_host_fd(
                tables.fd_map(),
                tables.opens(),
                tables.objects(),
                5,
                19,
                host.as_raw_fd(),
                carrick_el1_abi::DELEGATED_FLAG_READABLE
            )
            .is_some()
        );
    }
}

#[cfg(test)]
mod watchdog_tests {
    use super::*;

    #[test]
    fn host_service_time_does_not_consume_the_next_guest_interval() {
        let watchdog = Watchdog::start_with_timeout(Duration::from_millis(100));
        watchdog.during_guest(|| ());
        std::thread::sleep(Duration::from_millis(300));
        assert!(!watchdog.expired());
    }
}

/// A guest exception is an owned process outcome, separate from carrier failure.
#[derive(::core::fmt::Debug)]
pub enum InitialProcessExit {
    OwnedExit {
        status: carrick_personality_linux::lifecycle::LinuxWaitStatus,
        exits: usize,
    },
    RunFailed {
        cause: carrick_core_abi::NativeRunFailureReport,
        exits: usize,
    },
    Exited {
        code: i32,
        exits: usize,
    },
    Fault {
        record: carrick_x86::FaultDoorbellRecord,
        exits: usize,
    },
}

pub fn initial_process_exit(exit: PhysicalProcessExit, exits: usize) -> InitialProcessExit {
    match exit {
        PhysicalProcessExit::Exited(status) => {
            match carrick_personality_linux::lifecycle::LinuxWaitStatus::from_termination_status(
                status,
            ) {
                Ok(status) => InitialProcessExit::OwnedExit { status, exits },
                Err(_) => InitialProcessExit::RunFailed {
                    cause: carrick_core_abi::NativeRunFailureReason::NativeInvalid
                        .at_caller()
                        .report(),
                    exits,
                },
            }
        }
        PhysicalProcessExit::RunFailed(cause) => InitialProcessExit::RunFailed { cause, exits },
    }
}

/// Store the ring realtime word in the carrier zone held by `ram`.
fn publish_zone_realtime_offset(ram: &GuestRam, offset_ns: u64) -> Option<()> {
    let zone = ram.host_ptr(
        META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
        size_of::<X86Cpl0Zone>(),
    )?;
    // SAFETY: `ram` keeps the carrier's metadata window, and the aligned
    // production zone in it, mapped; the published word is a single atomic.
    unsafe { &*zone.cast::<X86Cpl0Zone>() }.publish_realtime_offset(offset_ns);
    Some(())
}

#[cfg(test)]
mod root_exit_validation_tests {
    use super::*;
    #[test]
    fn invalid_signal_root_exits_are_typed_run_failures() {
        for code in [0, 128, 256] {
            for core_dump in [false, true] {
                let outcome = PhysicalProcessExit::Exited(
                    carrick_sched_core::process::TerminationStatus::signaled(code, core_dump),
                );
                let outcome = initial_process_exit(outcome, 1);
                assert!(matches!(
                    outcome,
                    InitialProcessExit::RunFailed {
                        cause: carrick_core_abi::NativeRunFailureReport {
                            reason: carrick_core_abi::NativeRunFailureReason::NativeInvalid,
                            ..
                        },
                        exits: 1
                    }
                ));
            }
        }
    }
}

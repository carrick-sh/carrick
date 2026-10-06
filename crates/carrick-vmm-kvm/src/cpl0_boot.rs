//! Shared CPL0 KVM carrier and its retained guest-MM/metadata backing.
//! Hardware fixtures and the initial production process use the same image;
//! fixture observation ports remain separate from the production transport.
use crate::carrier_memory::{
    BackingExtent, BackingHandle, CarrierMachine, CarrierMemory, InventoryTransaction,
    PreparedBacking,
};
use crate::guest_setup::{GuestRam, WindowKind};
use crate::{KvmKickHandle, KvmVcpu};
use carrick_el1::memory::reservations::{
    LinuxReservationLayout, NoRootWait, X86Cpl0Reservations, X86Cpl0RootReleaseVenue, X86Cpl0Zone,
};
use carrick_el1_abi::GuestMmuPublication;
use carrick_el1_abi::Lifecycle;
use carrick_el1_abi::{
    BlockedMask, Counters, CurrentTask, EL1_BOOTSTRAP_METADATA_SIZE, El1TaskId, ThreadControlSlot,
    ThreadLifecyclePage, X86_CPL0_BOOTSTRAP_METADATA_BASE, X86_CPL0_DYNAMIC_METADATA_BASE,
    X86_CPL0_INITIAL_EXTENT_MAX_SIZE, X86_CPL0_INITIAL_EXTENT_VA, X86_CPL0_REGION_BASE,
};
use carrick_el1_abi::{ReservationMm, ReservationRange};
use carrick_el1_abi::{
    X86_INITIAL_BOOT_HEADER_GPA, X86_INITIAL_BOOT_LOADED, X86_INITIAL_BOOT_MAGIC,
    X86_INITIAL_BOOT_PORT, X86_INITIAL_BOOT_VERSION, X86_INITIAL_MAX_REGIONS,
    X86_INITIAL_MAX_STRINGS, X86InitialBootGrant, X86InitialBootHeader, X86InitialBootRegion,
    X86InitialBootRequest, X86InitialBootString,
};
use carrick_guest_arch::FrameGpa;
use carrick_guest_arch::{AddressContext, ContextGeneration, MmGeneration, RootGpa, UserVa};
use carrick_hal::{
    FrameEventCapacity, FrameInventoryEvent, FrameLength, MappingGeneration, MemPerms,
};
use carrick_hal::{HvVcpu, TrapError, VcpuExit, VcpuKick};
use carrick_kernel::kernel::{FrameInventoryAuthority, MmId, ObjectIdRegistry};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use carrick_mmu_core::x86::descriptor_txn::{
    Access, BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, LeafSize, PageSpan,
    Permissions, translate_leaf,
};
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{SlotId, Waker};
use carrick_x86::cpl0_entry::*;
use carrick_x86::{BringupLayout, X86Reg, X86Vcpu};
use kvm_bindings::{KVM_MP_STATE_RUNNABLE, Msrs, kvm_mp_state, kvm_msr_entry};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const RAM_SIZE: usize = 16 * 1024 * 1024;
const META_GPA: u64 = 0xc0_0000;
const META_LEN: u64 = 0x10_0000;
const PRODUCTION_METADATA_GPA: u64 = META_GPA;
const ALLOCATOR_GPA: u64 = 0x20_00000;
const INITIAL_EXTENT_GPA: u64 = 0x40_00000;
const KERNEL_REGION_GPA: u64 = 0x1_0000_0000;
const INITIAL_MM_KEY: u64 = 301;
static NEXT_EXTENT_ID: AtomicU64 = AtomicU64::new(1);
const INITIAL_STACK_TOP: u64 = 0x7fff_0000;
const INITIAL_STACK_SIZE: u64 = 0x1_0000;
const COUNTERS_OFFSET: u64 = 0x1_0000;
const BINDING_OFFSET: u64 = 0x8000;
const TASK_OFFSET: u64 = 0x9000;
const CONTROL_OFFSET: u64 = 0xa000;
const ROUTES_OFFSET: u64 = 0xd000;
const STRIDE: u64 = 0x100;
const _: () = {
    assert!(size_of::<CpuBinding>() <= STRIDE as usize);
    assert!(ROUTES_OFFSET >= 0xc000 + 9 * size_of::<ThreadControlSlot>() as u64);
    assert!(ROUTES_OFFSET + size_of::<PublishedApicIds>() as u64 <= COUNTERS_OFFSET);
};
const IST_STACK_BASE: u64 = 0xf0_0000;
const IMAGE_VA: u64 = 0xffff_ffff_8000_0000;
const IMAGE_GPA: u64 = 0x10_0000;
const METADATA_VA: u64 = X86_CPL0_DYNAMIC_METADATA_BASE;
pub const USER_CODE: u64 = 0x1_0000;
pub(crate) use carrick_x86::cpl0_entry::DIRECT_VA;
const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x10_0000,
    gdt_base: 0x50_0000,
    pml4_base: 0x60_0000,
};
const _: () = assert!(FIXTURE_PML4_CAPACITY == carrick_x86::X86_PML4_CAPACITY);

fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

fn record_bytes<T: Copy>(record: &T) -> &[u8] {
    // SAFETY: every caller passes a fully initialized fixed-layout ABI
    // record; its storage remains live for the returned borrow.
    unsafe { core::slice::from_raw_parts((record as *const T).cast::<u8>(), size_of::<T>()) }
}

fn append_records<T: Copy>(buffer: &mut Vec<u8>, records: &[T]) -> Result<u64, TrapError> {
    let offset = u64::try_from(buffer.len()).map_err(|_| fail("initial metadata offset"))?;
    for record in records {
        buffer.extend_from_slice(record_bytes(record));
    }
    INITIAL_EXTENT_GPA
        .checked_add(offset)
        .ok_or_else(|| fail("initial metadata address"))
}

struct InitialInventory {
    authority: FrameInventoryAuthority,
    receipt: Option<carrick_hal::FrameInventoryApplyReceipt>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    expected: usize,
    committed: usize,
}
impl InitialInventory {
    fn stage(
        gpas: impl IntoIterator<Item = FrameGpa>,
    ) -> Result<(Self, Vec<X86InitialBootGrant>), TrapError> {
        let gpas: Vec<_> = gpas.into_iter().collect();
        let authority = FrameInventoryAuthority::new();
        let ids = ObjectIdRegistry::new();
        let capacity = FrameEventCapacity::for_event_count(
            gpas.len()
                .checked_mul(2)
                .ok_or_else(|| fail("initial inventory capacity"))?,
        )
        .map_err(|error| fail(format!("initial inventory capacity: {error}")))?;
        let mut reservation = authority
            .reserve(&ids, gpas.len(), gpas.len(), capacity)
            .map_err(|error| fail(format!("initial inventory reserve: {error}")))?;
        let transaction = reservation.transaction();
        let generation = MappingGeneration::from_backend_counter(NonZeroU64::MIN);
        let length = FrameLength::from_mapping_extent(
            NonZeroU64::new(4096).ok_or_else(|| fail("initial frame length"))?,
        );
        let mut rows = Vec::with_capacity(gpas.len());
        for gpa in gpas {
            let frame = reservation
                .claim_frame()
                .map_err(|error| fail(format!("initial frame candidate: {error}")))?;
            let mapping = reservation
                .claim_mapping()
                .map_err(|error| fail(format!("initial mapping candidate: {error}")))?;
            reservation
                .push(FrameInventoryEvent::PrepareMapping {
                    transaction,
                    frame,
                    mapping,
                    generation,
                    gpa: carrick_guest_mem::Gpa(gpa.raw()),
                    length,
                    permissions: MemPerms {
                        read: true,
                        write: true,
                        exec: false,
                    },
                })
                .map_err(|error| fail(format!("initial inventory prepare: {error}")))?;
            reservation
                .push(FrameInventoryEvent::PublishMapping {
                    transaction,
                    mapping,
                    generation,
                })
                .map_err(|error| fail(format!("initial inventory publish: {error}")))?;
            rows.push((gpa, frame, mapping));
        }
        let mm = MmId::from_raw_u64(INITIAL_MM_KEY).ok_or_else(|| fail("initial inventory MM"))?;
        let (_, receipt) = authority
            .apply_with_receipt(mm, reservation.commit(()))
            .map_err(|error| fail(format!("initial inventory apply: {error}")))?;
        let mut frames = Vec::with_capacity(rows.len());
        let mut grants = Vec::with_capacity(rows.len());
        for (gpa, frame, mapping) in rows {
            if !receipt.authorizes(mapping, frame) {
                return Err(fail("initial inventory missing mapping"));
            }
            let identity = BackingIdentity {
                frame_id: NonZeroU64::new(frame.raw())
                    .ok_or_else(|| fail("initial frame identity"))?,
                mapping_id: NonZeroU64::new(mapping.raw())
                    .ok_or_else(|| fail("initial mapping identity"))?,
                owner_generation: NonZeroU64::MIN,
                inventory_revision: NonZeroU64::new(receipt.revision())
                    .ok_or_else(|| fail("initial inventory revision"))?,
            };
            frames.push((gpa, identity));
            grants.push(X86InitialBootGrant {
                gpa: gpa.raw(),
                frame_id: frame.raw(),
                mapping_id: mapping.raw(),
                owner_generation: generation.raw(),
                inventory_revision: receipt.revision(),
            });
        }
        Ok((
            Self {
                authority,
                receipt: Some(receipt),
                frames,
                expected: 0,
                committed: 0,
            },
            grants,
        ))
    }

    fn finish(&mut self) -> Result<(), TrapError> {
        if self.committed != self.expected {
            return Err(fail("initial inventory incomplete"));
        }
        self.receipt = None;
        Ok(())
    }
}
impl InventoryTransaction for InitialInventory {
    fn publish(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        let receipt = self.receipt.as_ref().ok_or_else(|| {
            crate::carrier_memory::MemoryError("initial inventory receipt absent".into())
        })?;
        let snapshot = self.authority.snapshot();
        if snapshot.revision != receipt.revision() || snapshot.mappings.len() != self.frames.len() {
            return Err(crate::carrier_memory::MemoryError(
                "initial inventory publication mismatch".into(),
            ));
        }
        let rows: BTreeMap<_, _> = snapshot
            .mappings
            .iter()
            .map(|row| (row.gpa.0, row))
            .collect();
        for &(gpa, identity) in &self.frames {
            let found = rows.get(&gpa.raw()).is_some_and(|row| {
                row.frame.raw() == identity.frame_id.get()
                    && row.mapping.raw() == identity.mapping_id.get()
                    && row.mm.raw() == INITIAL_MM_KEY
            });
            if !found {
                return Err(crate::carrier_memory::MemoryError(
                    "initial inventory frame missing".into(),
                ));
            }
        }
        Ok(())
    }
    fn commit(
        &mut self,
        publication: &GuestMmuPublication,
    ) -> Result<(), crate::carrier_memory::MemoryError> {
        if publication.outcome != GuestMmuPublication::APPLIED || self.committed >= self.expected {
            return Err(crate::carrier_memory::MemoryError(
                "initial inventory publication".into(),
            ));
        }
        self.committed += 1;
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        if let Some(receipt) = self.receipt.take() {
            self.authority
                .rollback_unpublished_apply(&receipt)
                .map_err(|error| {
                    crate::carrier_memory::MemoryError(format!(
                        "initial inventory rollback: {error}"
                    ))
                })?;
        }
        self.committed = 0;
        Ok(())
    }
}
impl Drop for InitialInventory {
    fn drop(&mut self) {
        if self.receipt.is_some() && self.rollback().is_err() {
            std::process::abort();
        }
    }
}

/// RAII deadline: one bounded blocking wait, one kick on expiry, always joined.
pub(crate) struct Watchdog {
    cancel: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
    pub(crate) expired: Arc<AtomicBool>,
}
impl Watchdog {
    pub(crate) fn start() -> Self {
        let kick = KvmKickHandle::for_current_thread();
        let (cancel, receiver) = mpsc::channel();
        let expired = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&expired);
        let worker = std::thread::spawn(move || {
            if receiver.recv_timeout(Duration::from_secs(5)) == Err(mpsc::RecvTimeoutError::Timeout)
            {
                signal.store(true, Ordering::Release);
                kick.kick();
            }
        });
        Self {
            cancel,
            worker: Some(worker),
            expired,
        }
    }
    pub(crate) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
pub struct Observation {
    pub result: i64,
    pub heads: [(u64, u32); 2],
    pub served: u64,
    pub forwarded: u64,
    pub semantic_host_exits: u64,
    pub entries: [u64; 2],
    pub publications: [u64; 2],
    pub completions: [u64; 2],
    pub kicks: u64,
    pub work_exits: u64,
    pub captured_stack: u64,
    pub returned_stack: u64,
    pub preserved_rbx: u64,
    pub host_yields: u64,
}

/// Stopped-vCPU structural observation, including refusal paths that cannot
/// return through the guest observation syscall. No semantic host service.
#[derive(Debug)]
pub struct EntryState {
    pub bindings: [carrick_el1_abi::ExecutionBinding; 2],
    pub heads: [(u64, u32); 2],
    pub entries: [u64; 2],
    pub publications: [u64; 2],
    pub completions: [u64; 2],
    pub served: u64,
    pub host_forwards: u64,
}

/// The vCPUs drop before the VM, and its registered backing drops last.
/// No run handle or host pointer escapes this fixture owner.
pub struct Cpl0Carrier {
    pub(crate) cpus: [KvmVcpu; 2],
    pub(crate) _vm: CarrierMemory,
    pub(crate) ram: Arc<GuestRam>,
    initial_extent: Option<(BackingHandle, usize)>,
    _kernel_region: Option<BackingHandle>,
    initial_inventory: Option<InitialInventory>,
    metadata_base: NonNull<u8>,
    host_forwards: u64,
    host_yields: u64,
    kicks: u64,
    work_exits: u64,
}

impl Cpl0Carrier {
    /// Size one private retained aperture for the host-staged PT_LOAD bytes,
    /// the boot record, and guest-owned table/data grants. Capacity follows
    /// the submitted image rather than reserving a carrier-wide RAM pool.
    pub fn initial_extent_bytes_for(
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
    ) -> Result<usize, TrapError> {
        const PAGE: usize = 4096;
        const STACK_PAGES: usize = 16;
        const MAX_BYTES: usize = X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize;
        let mut image_pages = 0usize;
        let mut initialized = 0usize;
        for region in &image.regions {
            let pages = usize::try_from((region.end - region.start) / PAGE as u64)
                .map_err(|_| fail("initial image page count"))?;
            image_pages = image_pages
                .checked_add(pages)
                .ok_or_else(|| fail("initial image pages"))?;
            initialized = initialized
                .checked_add(region.file_bytes.len())
                .ok_or_else(|| fail("initial image bytes"))?;
        }
        let strings = argv
            .iter()
            .chain(env)
            .try_fold(0usize, |sum, value| sum.checked_add(value.len()))
            .ok_or_else(|| fail("initial argv/env bytes"))?;
        let user_pages = image_pages
            .checked_add(STACK_PAGES)
            .ok_or_else(|| fail("initial user pages"))?;
        let table_pages = user_pages
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| fail("initial table grant count"))?;
        let grants = table_pages
            .checked_add(user_pages)
            .ok_or_else(|| fail("initial grant count"))?;
        let string_count = argv
            .len()
            .checked_add(env.len())
            .ok_or_else(|| fail("initial string count"))?;
        let region_bytes = image
            .regions
            .len()
            .checked_mul(size_of::<carrick_el1_abi::X86InitialBootRegion>())
            .ok_or_else(|| fail("initial region metadata"))?;
        let string_bytes = string_count
            .checked_mul(size_of::<carrick_el1_abi::X86InitialBootString>())
            .ok_or_else(|| fail("initial string metadata"))?;
        let metadata = size_of::<carrick_el1_abi::X86InitialBootRequest>()
            .checked_add(region_bytes)
            .and_then(|n| n.checked_add(string_bytes))
            .and_then(|n| {
                n.checked_add(
                    grants.checked_mul(size_of::<carrick_el1_abi::X86InitialBootGrant>())?,
                )
            })
            .and_then(|n| {
                n.checked_add(
                    user_pages.checked_mul(size_of::<carrick_el1_abi::GuestMmuPublication>())?,
                )
            })
            .and_then(|n| n.checked_add(initialized))
            .and_then(|n| n.checked_add(strings))
            .and_then(|n| n.checked_add(PAGE * 8)) // bounded alignment and argv terminators
            .ok_or_else(|| fail("initial request capacity"))?;
        let metadata_pages = metadata
            .checked_add(PAGE - 1)
            .ok_or_else(|| fail("initial metadata alignment"))?
            / PAGE;
        let total_pages = metadata_pages
            .checked_add(grants)
            .ok_or_else(|| fail("initial extent pages"))?;
        let bytes = total_pages
            .checked_mul(PAGE)
            .ok_or_else(|| fail("initial extent size"))?;
        if bytes > MAX_BYTES {
            return Err(fail("initial image exceeds carrier memory budget"));
        }
        Ok(bytes)
    }
    pub fn physical_slot_count(&self) -> usize {
        self._vm.slot_count()
    }

    /// Inspect the carrier's one admitted production reservation authority.
    /// The store and zone are two offsets into the same retained metadata
    /// extent; a fixture carrier with no production root returns false.
    pub fn initial_reservation_admitted(&self) -> bool {
        let (Some(table), Some(zone), Some(mm)) = (
            self.ram.host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            ),
            self.ram.host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            ),
            ReservationMm::new(INITIAL_MM_KEY),
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

    /// The initial host-loaded task retains an x86-shaped scheduler record
    /// in the same zone that owns its MM notifications.
    pub fn initial_thread_custody(&self) -> bool {
        let Some(zone) = self.ram.host_ptr(
            META_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
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
        zone.record(record).home() == Some(slot)
            && identity.tid == 41
            && identity.serial == 101
            && identity.mm == INITIAL_MM_KEY
            && identity.lifecycle_page == METADATA_VA
            && identity.control_slot == METADATA_VA + CONTROL_OFFSET
    }

    pub fn retained_bytes(&self) -> usize {
        self._vm.retained_bytes()
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
        if !matches!(va, USER_CODE | 0x3_0000 | 0x3_2000 | 0x3_3000 | 0x3_4000) {
            return Err(fail("fixture leaf outside admitted user page"));
        }
        let mut table = LAYOUT.pml4_base;
        for shift in [39, 30, 21, 12] {
            let address = table + ((va >> shift) & 511) * 8;
            let ptr = self
                .ram
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

    pub fn boot(image: &Path, programs: [&[u8]; 2]) -> Result<Self, TrapError> {
        Self::boot_inner(image, programs, false)
    }

    pub fn boot_with_interrupts(image: &Path, programs: [&[u8]; 2]) -> Result<Self, TrapError> {
        Self::boot_inner(image, programs, true)
    }

    /// Boot the compiled production image in the same retained carrier used
    /// by the hardware fixtures. Guest MM publication follows while stopped.
    pub fn boot_production(initial_extent_bytes: usize) -> Result<Self, TrapError> {
        const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/carrick-x86-cpl0"));
        if initial_extent_bytes == 0
            || initial_extent_bytes > X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize
            || !initial_extent_bytes.is_multiple_of(4096)
        {
            return Err(fail("invalid initial guest MM extent size"));
        }
        Self::boot_bytes_inner(IMAGE, [&[], &[]], false, Some(initial_extent_bytes), false)
    }

    /// The guest MM owner supplies the executable and stack publication here.
    /// This is the sole unbound seam between a stopped production carrier and
    /// EL0 admission; no fixture user page is used as an ELF loader.
    pub fn load_guest_mm(
        &mut self,
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
    ) -> Result<(), TrapError> {
        let (_, extent_len) = self
            .initial_extent
            .ok_or_else(|| fail("initial extent absent"))?;
        if image.regions.is_empty()
            || image.regions.len() > X86_INITIAL_MAX_REGIONS
            || argv.len() + env.len() > X86_INITIAL_MAX_STRINGS
        {
            return Err(fail("initial image request population"));
        }
        let mut staged = vec![0; size_of::<X86InitialBootRequest>()];
        let regions_offset = staged.len();
        staged.resize(
            regions_offset + image.regions.len() * size_of::<X86InitialBootRegion>(),
            0,
        );
        let strings_offset = staged.len();
        staged.resize(
            strings_offset + (argv.len() + env.len()) * size_of::<X86InitialBootString>(),
            0,
        );
        let grants_offset = staged.len();
        let image_pages: usize = image
            .regions
            .iter()
            .map(|r| ((r.end - r.start) / 4096) as usize)
            .sum();
        let data_grants = image_pages
            .checked_add((INITIAL_STACK_SIZE / 4096) as usize)
            .ok_or_else(|| fail("initial data grants"))?;
        let table_grants = data_grants
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| fail("initial table grants"))?;
        let grant_count = table_grants
            .checked_add(data_grants)
            .ok_or_else(|| fail("initial grants"))?;
        staged.resize(
            grants_offset + grant_count * size_of::<X86InitialBootGrant>(),
            0,
        );
        let publications_offset = staged.len();
        staged.resize(
            publications_offset + data_grants * size_of::<carrick_el1_abi::GuestMmuPublication>(),
            0,
        );
        let mut regions = Vec::with_capacity(image.regions.len());
        for region in &image.regions {
            let source_gpa = append_records(&mut staged, region.file_bytes)?;
            regions.push(X86InitialBootRegion {
                start: region.start,
                len: region.end - region.start,
                initialized_offset: region.initialized_offset,
                source_gpa,
                initialized_len: region.file_bytes.len() as u64,
                permissions: u64::from(region.perms.read)
                    | (u64::from(region.perms.write) << 1)
                    | (u64::from(region.perms.execute) << 2),
            });
        }
        let mut strings = Vec::with_capacity(argv.len() + env.len());
        for value in argv.iter().chain(env) {
            if value.as_bytes().contains(&0) {
                return Err(fail("NUL in initial argv/env"));
            }
            let source_gpa = append_records(&mut staged, value.as_bytes())?;
            strings.push(X86InitialBootString {
                source_gpa,
                len: value.len() as u64,
            });
        }
        let frame_offset = staged
            .len()
            .checked_add(4095)
            .ok_or_else(|| fail("initial frame alignment"))?
            & !4095;
        if frame_offset
            .checked_add(grant_count * 4096)
            .is_none_or(|end| end > extent_len)
        {
            return Err(fail("initial extent too small for frame grants"));
        }
        let (mut inventory, grants) = InitialInventory::stage((0..grant_count).map(|index| {
            FrameGpa::new(INITIAL_EXTENT_GPA + (frame_offset + index * 4096) as u64)
        }))?;
        inventory
            .publish()
            .map_err(|error| fail(error.to_string()))?;
        let (handle, _) = self
            .initial_extent
            .ok_or_else(|| fail("initial extent handle"))?;
        self._vm
            .bind_frame_identities(handle, &inventory.frames)
            .map_err(|error| fail(error.to_string()))?;
        // The guest editor's no-op invalidation is valid only while this
        // unpublished root cannot be in any live vCPU TLB. Both vCPUs are
        // stopped here; reject a reused root before the first descriptor edit.
        for cpu in &self.cpus {
            if cpu.get_gpr(X86Reg::Cr3)? == grants[0].gpa {
                return Err(fail("initial root already live in a vCPU"));
            }
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| fail(format!("initial random: {error}")))?;
        let request = X86InitialBootRequest {
            magic: X86_INITIAL_BOOT_MAGIC,
            version: X86_INITIAL_BOOT_VERSION,
            region_count: image.regions.len() as u32,
            entry: image.entry,
            phdr: image.phdr,
            phent: image.phent,
            phnum: image.phnum,
            argc: argv.len() as u16,
            envc: env.len() as u16,
            regions_gpa: INITIAL_EXTENT_GPA + regions_offset as u64,
            strings_gpa: INITIAL_EXTENT_GPA + strings_offset as u64,
            grants_gpa: INITIAL_EXTENT_GPA + grants_offset as u64,
            table_grant_count: table_grants as u32,
            data_grant_count: data_grants as u32,
            publications_gpa: INITIAL_EXTENT_GPA + publications_offset as u64,
            publication_capacity: data_grants as u32,
            publication_count: 0,
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
            random,
            result_root_gpa: 0,
            result_rsp: 0,
            result_status: carrick_el1_abi::X86_INITIAL_BOOT_PENDING,
            extent_pages: (extent_len / 4096) as u32,
            mm_key: INITIAL_MM_KEY,
            generation: 1,
            result_table_used: 0,
            result_data_used: 0,
            result_initial_break: 0,
        };
        staged[..size_of::<X86InitialBootRequest>()].copy_from_slice(record_bytes(&request));
        staged[regions_offset..strings_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                regions.as_ptr().cast::<u8>(),
                regions.len() * size_of::<X86InitialBootRegion>(),
            )
        });
        staged[strings_offset..grants_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                strings.as_ptr().cast::<u8>(),
                strings.len() * size_of::<X86InitialBootString>(),
            )
        });
        staged[grants_offset..publications_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                grants.as_ptr().cast::<u8>(),
                grants.len() * size_of::<X86InitialBootGrant>(),
            )
        });
        self._vm
            .write(FrameGpa::new(INITIAL_EXTENT_GPA), &staged)
            .map_err(|error| fail(error.to_string()))?;
        let header = self
            .ram
            .host_ptr(
                X86_INITIAL_BOOT_HEADER_GPA,
                size_of::<X86InitialBootHeader>(),
            )
            .ok_or_else(|| fail("production image boot header absent"))?;
        // SAFETY: the fixed image header is retained but may not be aligned
        // by the byte-oriented RAM window abstraction.
        let header = unsafe { header.cast::<X86InitialBootHeader>().read_unaligned() };
        if header.magic != X86_INITIAL_BOOT_MAGIC
            || header.version != X86_INITIAL_BOOT_VERSION
            || !(IMAGE_VA..IMAGE_VA + 0x10_0000).contains(&header.entry_va)
        {
            return Err(fail("production image boot header invalid"));
        }
        let kernel_stack = self.binding(0).kernel_stack;
        let cpu = &mut self.cpus[0];
        let mut sregs = cpu
            .fd()
            .get_sregs()
            .map_err(|error| fail(error.to_string()))?;
        sregs.cs.selector = 8;
        sregs.cs.dpl = 0;
        sregs.ss.selector = 0x10;
        sregs.ss.dpl = 0;
        sregs.gs.base = METADATA_VA + BINDING_OFFSET;
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
        regs.rip = header.entry_va;
        regs.rdi = X86_CPL0_INITIAL_EXTENT_VA;
        regs.rsp = kernel_stack;
        regs.rflags = 2;
        cpu.fd()
            .set_regs(&regs)
            .map_err(|error| fail(error.to_string()))?;
        let watchdog = Watchdog::start();
        let exit = HvVcpu::run(&mut self.cpus[0])?;
        if watchdog.expired() {
            return Err(fail("production initial MM deadline"));
        }
        if !matches!(
            exit,
            VcpuExit::IoOut {
                port: X86_INITIAL_BOOT_PORT,
                ..
            }
        ) {
            let mut detail = "unexpected production initial MM exit".to_owned();
            self.cpus[0].append_debug_state(&mut detail);
            return Err(fail(detail));
        }
        if self.cpus[0].get_gpr(X86Reg::Rax)? != X86_CPL0_INITIAL_EXTENT_VA {
            return Err(fail("production initial MM request pointer"));
        }
        let reply = self
            ._vm
            .read(
                FrameGpa::new(INITIAL_EXTENT_GPA),
                size_of::<X86InitialBootRequest>(),
            )
            .map_err(|error| fail(error.to_string()))?;
        // SAFETY: this fixed-size copy is exactly one initialized ABI record.
        let reply = unsafe {
            reply
                .as_ptr()
                .cast::<X86InitialBootRequest>()
                .read_unaligned()
        };
        if reply.result_status != X86_INITIAL_BOOT_LOADED {
            return Err(fail(format!(
                "production initial MM refused: status {}",
                reply.result_status
            )));
        }
        if reply.magic != request.magic
            || reply.version != request.version
            || reply.mm_key != INITIAL_MM_KEY
            || reply.generation != 1
            || reply.result_data_used != reply.publication_count
            || reply.publication_count == 0
            || reply.publication_count > reply.publication_capacity
            || reply.result_root_gpa != grants[0].gpa
            || reply.result_table_used == 0
            || reply.result_table_used > reply.table_grant_count
            || reply.result_initial_break
                != image
                    .regions
                    .iter()
                    .map(|region| region.end)
                    .max()
                    .unwrap_or(0)
            || reply.result_rsp >= reply.stack_top
            || reply.result_rsp < reply.stack_top - reply.stack_size
        {
            return Err(fail("production initial MM reply identity"));
        }
        let mm = NonZeroU64::new(reply.mm_key).ok_or_else(|| fail("initial MM key"))?;
        let generation =
            NonZeroU64::new(reply.generation).ok_or_else(|| fail("initial MM generation"))?;
        let root = RootGpa::page_aligned(FrameGpa::new(reply.result_root_gpa))
            .ok_or_else(|| fail("initial root alignment"))?;
        let context = AddressContext {
            root,
            mm: MmGeneration::new(mm),
            generation: ContextGeneration::new(generation),
        };
        self._vm
            .install_root(mm, context)
            .map_err(|error| fail(error.to_string()))?;
        let publication_bytes = self
            ._vm
            .read(
                FrameGpa::new(reply.publications_gpa),
                reply.publication_count as usize * size_of::<GuestMmuPublication>(),
            )
            .map_err(|error| fail(error.to_string()))?;
        let mut publications = Vec::with_capacity(reply.publication_count as usize);
        for chunk in publication_bytes.chunks_exact(size_of::<GuestMmuPublication>()) {
            // SAFETY: one complete fixed-layout guest ABI publication was
            // copied from retained memory while this vCPU is stopped.
            publications.push(unsafe {
                chunk
                    .as_ptr()
                    .cast::<GuestMmuPublication>()
                    .read_unaligned()
            });
        }
        let tables: Vec<RootGpa> = grants[1..reply.result_table_used as usize]
            .iter()
            .map(|grant| {
                RootGpa::page_aligned(FrameGpa::new(grant.gpa))
                    .ok_or_else(|| fail("initial table grant"))
            })
            .collect::<Result<_, _>>()?;
        inventory.expected = publications.len();
        let mut used_tables = 0usize;
        for (index, publication) in publications.into_iter().enumerate() {
            let perms = if let Some(region) = image.regions.iter().find(|region| {
                region.start <= publication.span_va && publication.span_va < region.end
            }) {
                Permissions {
                    writable: region.perms.write,
                    executable: region.perms.execute,
                    user: true,
                }
            } else if publication.span_va >= reply.stack_top - reply.stack_size
                && publication.span_va < reply.stack_top
            {
                Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                }
            } else {
                return Err(fail("initial publication outside ELF and stack"));
            };
            let output = FrameGpa::new(grants[table_grants + index].gpa);
            let grant = grants[table_grants + index];
            let identity = BackingIdentity {
                frame_id: NonZeroU64::new(grant.frame_id)
                    .ok_or_else(|| fail("initial frame identity"))?,
                mapping_id: NonZeroU64::new(grant.mapping_id)
                    .ok_or_else(|| fail("initial mapping identity"))?,
                owner_generation: NonZeroU64::new(grant.owner_generation)
                    .ok_or_else(|| fail("initial owner generation"))?,
                inventory_revision: NonZeroU64::new(grant.inventory_revision)
                    .ok_or_else(|| fail("initial inventory revision"))?,
            };
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: mm,
                    generation,
                },
                root,
                op: DescriptorOp::Map {
                    span: PageSpan::new(publication.span_va, 4096),
                    output,
                    permissions: perms,
                    size: LeafSize::Page,
                    resident: true,
                    backing: identity,
                },
                tables: tables
                    .get(used_tables..)
                    .ok_or_else(|| fail("initial table receipt count"))?,
            };
            self._vm
                .publish(&txn, publication, &mut inventory)
                .map_err(|error| fail(error.to_string()))?;
            used_tables = used_tables
                .checked_add(publication.tables_linked as usize)
                .ok_or_else(|| fail("initial table receipt overflow"))?;
        }
        self.publish_production_reservations(
            mm,
            root,
            reply.result_initial_break,
            reply.stack_top,
        )?;
        inventory.finish()?;
        self.initial_inventory = Some(inventory);
        Ok(())
    }

    fn publish_production_reservations(
        &mut self,
        mm_key: NonZeroU64,
        root: RootGpa,
        initial_break: u64,
        stack_top: u64,
    ) -> Result<(), TrapError> {
        const ARENA_START: u64 = 0x4000_0000;
        let heap = ReservationRange::new(initial_break, ARENA_START)
            .ok_or_else(|| fail("initial heap layout"))?;
        let arena = ReservationRange::new(ARENA_START, stack_top - INITIAL_STACK_SIZE)
            .ok_or_else(|| fail("initial mmap arena layout"))?;
        let table = self
            .ram
            .host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            )
            .ok_or_else(|| fail("production reservation backing"))?
            .cast::<X86Cpl0Reservations>();
        let zone = self
            .ram
            .host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("production zone backing"))?
            .cast::<X86Cpl0Zone>();
        // SAFETY: both pointers belong to one retained, zeroed and aligned
        // carrier metadata window. The stopped vCPU cannot race publication.
        let (table, zone) = unsafe { (&*table, &*zone) };
        let mm = ReservationMm::new(mm_key.get()).ok_or_else(|| fail("reservation MM key"))?;
        let index = zone
            .spaces
            .publish_closed(mm.raw(), root.address().raw(), 0)
            .ok_or_else(|| fail("production space publication"))?;
        table
            .publish(
                index.index(),
                mm,
                LinuxReservationLayout {
                    heap,
                    arena,
                    brk: initial_break,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .map_err(|error| fail(format!("production reservation publication: {error:?}")))?;
        fn unexpected_boot_wake(
            _: &X86Cpl0Zone,
            _: Waker,
            owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >,
        ) {
            let mut handed = false;
            let (_, effects) = owned.deliver_handbacks(&mut |_| handed = true);
            if handed || effects != carrick_sched_core::WakeEffects::default() {
                std::process::abort();
            }
        }
        let release = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: unexpected_boot_wake,
        };
        X86Cpl0RootReleaseVenue::new(table, release)
            .map_err(|error| fail(format!("production root authority: {error:?}")))?
            .lock(index.index(), mm, &NoRootWait)
            .and_then(|mut model| model.finish_import())
            .map_err(|error| fail(format!("production root admission: {error:?}")))?;
        SpaceAccess::notified(release).open(index);
        let slot = SlotId::new(0);
        zone.drive(slot, 1);
        zone.publish_slot(slot, mm.raw(), Some(0), 0);
        zone.enter_guest(slot);
        zone.install_space(slot, mm.raw())
            .ok_or_else(|| fail("production installed MM"))?;
        self.bind_execution(
            0,
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(41),
                generation: carrick_el1_abi::EntryGeneration::from_raw(11),
                mm: carrick_el1_abi::EntryMmKey::from_raw(mm.raw()),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
            },
        )?;
        zone.current_or_new(
            slot,
            carrick_sched_core::ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: mm.raw(),
                file_table: 5,
                generation: 11,
                affinity: 1,
                lifecycle_page: METADATA_VA,
                control_slot: METADATA_VA + CONTROL_OFFSET,
            },
        )
        .map_err(|_| fail("production scheduler record exhausted"))?;
        Ok(())
    }

    fn read_initial_user(
        &self,
        root: RootGpa,
        start: u64,
        len: usize,
    ) -> Result<Vec<u8>, TrapError> {
        if len > 1024 * 1024 {
            return Err(fail("initial stdout write exceeds bounded transfer"));
        }
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let va = start
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| fail("initial user pointer overflow"))?;
            let leaf = translate_leaf(&self._vm.words(), root, UserVa::new(va), Access::Read, true)
                .map_err(|error| fail(format!("initial user read fault: {error:?}")))?;
            let span = (4096 - (va & 4095)) as usize;
            let count = span.min(len - bytes.len());
            bytes.extend(
                self._vm
                    .read(leaf.output, count)
                    .map_err(|error| fail(error.to_string()))?,
            );
        }
        Ok(bytes)
    }

    /// Resume the published initial MM through the existing shared Linux
    /// personality. Only host-crossing calls leave CPL0 through FORWARD_PORT.
    pub fn run_initial_process(
        &mut self,
        max_exits: usize,
        mut stdio: impl FnMut(i32, &[u8]) -> i64,
    ) -> Result<(i32, usize), TrapError> {
        let mm = NonZeroU64::new(INITIAL_MM_KEY).ok_or_else(|| fail("initial MM key"))?;
        let root = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("initial MM not published"))?
            .root;
        for exits in 1..=max_exits {
            let exit = HvVcpu::run(&mut self.cpus[0])?;
            let VcpuExit::IoOut {
                port: FORWARD_PORT, ..
            } = exit
            else {
                if let VcpuExit::IoOut {
                    port: carrick_x86::FAULT_DOORBELL_PORT,
                    data,
                } = exit
                {
                    let mut words = vec![u32::from_le_bytes(
                        data.as_slice()
                            .try_into()
                            .map_err(|_| fail("initial fault word width"))?,
                    )];
                    while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
                        let VcpuExit::IoOut {
                            port: carrick_x86::FAULT_DOORBELL_PORT,
                            data,
                        } = HvVcpu::run(&mut self.cpus[0])?
                        else {
                            return Err(fail("initial fault record interrupted"));
                        };
                        words.push(u32::from_le_bytes(
                            data.as_slice()
                                .try_into()
                                .map_err(|_| fail("initial fault word width"))?,
                        ));
                    }
                    let record = carrick_x86::FaultDoorbellRecord::from_u32_words(&words)?;
                    return Err(fail(format!("initial process fault: {record:?}")));
                }
                let mut detail = match exit {
                    VcpuExit::IoOut { port, .. } => {
                        format!("unexpected initial process port {port:#x}")
                    }
                    VcpuExit::Halt => "initial process halted".to_owned(),
                    _ => "unexpected initial process exit".to_owned(),
                };
                self.cpus[0].append_debug_state(&mut detail);
                return Err(fail(detail));
            };
            let address = self.cpus[0].get_gpr(X86Reg::Rax)?;
            let stack_end = self.binding(0).kernel_stack + 16;
            if address & 7 != 0
                || address < stack_end - 0x1_0000
                || address
                    .checked_add(size_of::<NativeFrame>() as u64)
                    .is_none_or(|end| end > stack_end)
            {
                return Err(fail("initial syscall frame outside private kernel stack"));
            }
            let ptr = self
                .ram
                .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
                .ok_or_else(|| fail("initial syscall frame backing"))?
                .cast::<NativeFrame>();
            // SAFETY: the stopped CPU published this exact stack-local frame.
            let frame = unsafe { &mut *ptr };
            self.host_forwards += 1;
            match frame.rax {
                1 => {
                    let fd =
                        i32::try_from(frame.rdi).map_err(|_| fail("initial write fd range"))?;
                    let len =
                        usize::try_from(frame.rdx).map_err(|_| fail("initial write size range"))?;
                    let bytes = self.read_initial_user(root, frame.rsi, len)?;
                    frame.rax = stdio(fd, &bytes) as u64;
                }
                60 | 231 => return Ok(((frame.rdi & 255) as i32, exits)),
                call => return Err(fail(format!("unported initial x86 syscall {call}"))),
            }
        }
        Err(fail("initial process exit budget exceeded"))
    }

    /// Counters from the stopped production carrier, including its initial
    /// image entry and each guest-to-host syscall forward.
    pub fn initial_execution_witness(&self) -> (u64, u64) {
        (
            self.binding(0).entries.load(Ordering::Acquire),
            self.host_forwards,
        )
    }

    pub(crate) fn boot_inner(
        image: &Path,
        programs: [&[u8]; 2],
        interrupts: bool,
    ) -> Result<Self, TrapError> {
        let fixture_image = image
            .file_name()
            .is_some_and(|name| name == "carrick-x86-cpl0-fixture");
        let bytes = std::fs::read(image).map_err(|e| fail(format!("CPL0 image: {e}")))?;
        Self::boot_bytes_inner(&bytes, programs, interrupts, None, fixture_image)
    }

    fn boot_bytes_inner(
        bytes: &[u8],
        programs: [&[u8]; 2],
        interrupts: bool,
        initial_extent_bytes: Option<usize>,
        fixture_image: bool,
    ) -> Result<Self, TrapError> {
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(bytes, 62)
            .map_err(|e| fail(format!("CPL0 ELF: {e}")))?;
        if !(IMAGE_VA..IMAGE_VA + 0x10_0000).contains(&plan.entry) {
            return Err(fail("CPL0 entry outside its supervisor image"));
        }
        let mut ram = GuestRam::new();
        if initial_extent_bytes.is_some() {
            let zone_end =
                carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>();
            let region_bytes = (zone_end + 4095) & !4095;
            ram.add_window(0, META_GPA as usize, WindowKind::Private)
                .map_err(|e| fail(e.to_string()))?;
            ram.add_window(PRODUCTION_METADATA_GPA, region_bytes, WindowKind::Private)
                .map_err(|e| fail(e.to_string()))?;
        } else {
            ram.add_window(
                0,
                if interrupts { 2 * RAM_SIZE } else { RAM_SIZE },
                WindowKind::Private,
            )
            .map_err(|e| fail(e.to_string()))?;
        }
        ram.add_window(
            ALLOCATOR_GPA,
            EL1_BOOTSTRAP_METADATA_SIZE as usize,
            WindowKind::Private,
        )
        .map_err(|e| fail(e.to_string()))?;
        let mut maps = Vec::new();
        for segment in &plan.segments {
            let end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or_else(|| fail("CPL0 segment overflow"))?;
            if segment.virtual_address < IMAGE_VA || end > IMAGE_VA + 0x10_0000 {
                return Err(fail("CPL0 segment outside its supervisor image"));
            }
            let start = segment.file_offset as usize;
            let data = bytes
                .get(start..start + segment.file_size as usize)
                .ok_or_else(|| fail("CPL0 segment file bounds"))?;
            let gpa = IMAGE_GPA + segment.virtual_address - IMAGE_VA;
            ram.write_gpa(gpa, data).map_err(|e| fail(e.to_string()))?;
            let va = segment.virtual_address & !0xfff;
            maps.push(Pml4MapSpec {
                va,
                gpa: IMAGE_GPA + va - IMAGE_VA,
                len: ((end + 0xfff) & !0xfff) - va,
                user: false,
                write: segment.perms.write,
                exec: segment.perms.execute,
            });
        }
        // Existing x86 descriptor/TSS/IDT machinery, including private stacks
        // and exception stubs, remains the hardware authority.
        maps.push(Pml4MapSpec {
            va: DIRECT_VA + 0x20_0000,
            gpa: 0x20_0000,
            len: 0xa0_0000,
            user: false,
            write: true,
            exec: true,
        });
        maps.push(Pml4MapSpec {
            va: DIRECT_VA + 0xc0_0000,
            gpa: 0xc0_0000,
            len: if initial_extent_bytes.is_some() {
                ((carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>() + 4095)
                    & !4095) as u64
            } else if interrupts {
                0x140_0000
            } else {
                0x40_0000
            },
            user: false,
            write: true,
            exec: false,
        });
        maps.push(Pml4MapSpec {
            va: METADATA_VA,
            gpa: META_GPA,
            len: META_LEN,
            user: false,
            write: true,
            exec: false,
        });
        if initial_extent_bytes.is_some() {
            maps.push(Pml4MapSpec {
                va: METADATA_VA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
                gpa: PRODUCTION_METADATA_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
                len: (size_of::<X86Cpl0Zone>() as u64 + 4095) & !4095,
                user: false,
                write: true,
                exec: false,
            });
        }
        maps.push(Pml4MapSpec {
            va: X86_CPL0_BOOTSTRAP_METADATA_BASE,
            gpa: ALLOCATOR_GPA,
            len: EL1_BOOTSTRAP_METADATA_SIZE,
            user: false,
            write: true,
            exec: false,
        });
        if let Some(len) = initial_extent_bytes {
            maps.push(Pml4MapSpec {
                va: X86_CPL0_INITIAL_EXTENT_VA,
                gpa: INITIAL_EXTENT_GPA,
                len: len as u64,
                user: false,
                write: true,
                exec: false,
            });
        }
        if initial_extent_bytes.is_some() {
            maps.push(Pml4MapSpec {
                va: X86_CPL0_REGION_BASE,
                gpa: KERNEL_REGION_GPA,
                len: carrick_el1_abi::EL1_REGION_SIZE,
                user: false,
                write: true,
                exec: false,
            });
        }

        for (index, program) in programs.iter().enumerate() {
            if program.is_empty() {
                continue;
            }
            if program.len() > 4096 {
                return Err(fail("CPL0 fixture exceeds one code page"));
            }
            let code = USER_CODE + index as u64 * 4096;
            ram.write_gpa(code, program)
                .map_err(|e| fail(e.to_string()))?;
            maps.push(Pml4MapSpec {
                va: code,
                gpa: code,
                len: 4096,
                user: true,
                write: false,
                exec: true,
            });
            let stack = 0x3_0000 + index as u64 * 0x1_0000;
            maps.push(Pml4MapSpec {
                va: stack,
                gpa: stack,
                len: 8192,
                user: true,
                write: true,
                exec: false,
            });
        }
        if interrupts {
            maps.extend(crate::carrier_interrupts::supervisor_maps());
            maps.push(crate::carrier_interrupts::data_map(0));
        }
        // CPL0 ordinary loads/copies can race a page-table publication after
        // preflight. Keep every bootstrap supervisor leaf outside the user
        // range so a changed lower-half leaf cannot expose kernel backing.
        if maps
            .iter()
            .any(|map| !map.user && map.va < 0x0000_8000_0000_0000)
        {
            return Err(fail("CPL0 supervisor map in user range"));
        }
        let tables = pml4_tables(
            &maps,
            LAYOUT.pml4_base,
            carrick_x86::X86_PML4_CAPACITY as usize,
        )
        .map_err(|e| fail(format!("CPL0 tables: {e:?}")))?;
        ram.write_gpa(LAYOUT.pml4_base, &tables)
            .map_err(|e| fail(e.to_string()))?;
        if interrupts {
            let last = maps.last_mut().ok_or_else(|| fail("progress data map"))?;
            *last = crate::carrier_interrupts::data_map(1);
            let second = pml4_tables(
                &maps,
                crate::carrier_interrupts::SECOND_ROOT,
                carrick_x86::X86_PML4_CAPACITY as usize,
            )
            .map_err(|e| fail(format!("second progress root: {e:?}")))?;
            ram.write_gpa(crate::carrier_interrupts::SECOND_ROOT, &second)
                .map_err(|e| fail(e.to_string()))?;
        }
        let boot = <carrick_hal::x8664_arch::X8664GuestArch as carrick_hal::guest_arch::GuestArch>::bootstrap_sysregs();
        let gdt: Vec<u8> = boot
            .gdt
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        ram.write_gpa(LAYOUT.gdt_base, &gdt)
            .map_err(|e| fail(e.to_string()))?;
        carrick_x86::write_fault_tables_with(LAYOUT, |gpa, bytes| {
            ram.write_gpa(gpa, bytes).map_err(|e| fail(e.to_string()))
        })?;
        // Intel SDM vol. 3: 64-bit TSS IST1 occupies bytes 36..44; the IDT
        // gate's byte 4 selects IST1. Keep double faults off the syscall stack.
        // Reuse the existing descriptors/stubs rather than build another IDT.
        for index in 0..2 {
            let tss = carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index)?;
            let fault_stack =
                carrick_x86::fault_slot_gpa(carrick_x86::fault_stack_base(LAYOUT), index)?;
            ram.write_gpa(tss + 4, &(DIRECT_VA + fault_stack + 4096).to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
            let ist_top = DIRECT_VA + IST_STACK_BASE + (index + 1) * 4096;
            ram.write_gpa(tss + 36, &ist_top.to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
            let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
            ram.write_gpa(idt + 8 * 16 + 4, &[1])
                .map_err(|e| fail(e.to_string()))?;
            for vector in 0..256_u64 {
                let gate_gpa = idt + vector * 16;
                let ptr = ram
                    .host_ptr(gate_gpa, 16)
                    .ok_or_else(|| fail("IDT gate backing"))?;
                // SAFETY: bootstrap owns retained, initialized IDT backing and
                // no vCPU can read it before publication completes.
                let gate = unsafe { core::slice::from_raw_parts(ptr, 16) };
                if gate[5] & 0x80 == 0 {
                    continue;
                }
                let low = u16::from_le_bytes([gate[0], gate[1]]) as u64;
                let mid = u16::from_le_bytes([gate[6], gate[7]]) as u64;
                let high = u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]]) as u64;
                let entry = DIRECT_VA + low + (mid << 16) + (high << 32);
                ram.write_gpa(gate_gpa, &(entry as u16).to_le_bytes())
                    .map_err(|e| fail(e.to_string()))?;
                ram.write_gpa(gate_gpa + 6, &((entry >> 16) as u16).to_le_bytes())
                    .map_err(|e| fail(e.to_string()))?;
                ram.write_gpa(gate_gpa + 8, &((entry >> 32) as u32).to_le_bytes())
                    .map_err(|e| fail(e.to_string()))?;
            }
        }
        // SAFETY: private zeroed backing; typed objects fit and are aligned.
        // They are initialized before registration or any guest execution.
        unsafe {
            let page = ram
                .host_ptr(META_GPA, size_of::<ThreadLifecyclePage>())
                .ok_or_else(|| fail("lifecycle page backing"))?
                .cast::<ThreadLifecyclePage>();
            page.write(ThreadLifecyclePage::new());
            (*page)
                .thread_born()
                .ok_or_else(|| fail("second live task admission"))?;
            let counters = ram
                .host_ptr(META_GPA + COUNTERS_OFFSET, size_of::<Counters>())
                .ok_or_else(|| fail("counter backing"))?
                .cast::<Counters>();
            counters.write(Counters::new());
            let routes = ram
                .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
                .ok_or_else(|| fail("APIC route table backing"))?
                .cast::<PublishedApicIds>();
            routes.write(PublishedApicIds::new());
            for index in 0..2 {
                let offset = index as u64 * STRIDE;
                let slot = ram
                    .host_ptr(
                        META_GPA + CONTROL_OFFSET + offset,
                        size_of::<ThreadControlSlot>(),
                    )
                    .ok_or_else(|| fail("control slot backing"))?
                    .cast::<ThreadControlSlot>();
                slot.write(ThreadControlSlot::new());
                (*slot).reset_for_host_birth(BlockedMask(0));
                if !(*slot).publish_visible_tid(41 + index as u32) {
                    return Err(fail("issued slot identity"));
                }
                let task = ram
                    .host_ptr(META_GPA + TASK_OFFSET + offset, size_of::<CurrentTask>())
                    .ok_or_else(|| fail("current task backing"))?
                    .cast::<CurrentTask>();
                task.write(CurrentTask::new());
                (*task).set(
                    El1TaskId::from_linux_tid(41 + index as i32),
                    11 + index as u64,
                    5,
                );
                (*task)
                    .mm
                    .thread_generation
                    .store(101 + index as u64, Ordering::Release);
                (*task).mm.key.store(201 + index as u64, Ordering::Release);
                (*task).publish_lifecycle(METADATA_VA, METADATA_VA + CONTROL_OFFSET + offset);
                let binding = ram
                    .host_ptr(META_GPA + BINDING_OFFSET + offset, size_of::<CpuBinding>())
                    .ok_or_else(|| fail("CPU binding backing"))?
                    .cast::<CpuBinding>();
                binding.write(CpuBinding {
                    kernel_stack: DIRECT_VA + 0xe1_0000 + index as u64 * 0x1_0000 - 16,
                    user_stack: 0,
                    self_address: METADATA_VA + BINDING_OFFSET + offset,
                    task_address: METADATA_VA + TASK_OFFSET + offset,
                    counters_address: METADATA_VA + COUNTERS_OFFSET,
                    entry_kick: AtomicU32::new(0),
                    return_kick: AtomicU32::new(0),
                    entries: AtomicU64::new(0),
                    publications: AtomicU64::new(0),
                    completions: AtomicU64::new(0),
                    captured_stack: AtomicU64::new(0),
                    scheduler_witness: AtomicU64::new(
                        if fixture_image && interrupts && index == 0 {
                            carrick_x86::cpl0_scheduler::PROGRESS_STATE
                        } else {
                            0
                        },
                    ),
                    cpu_slot: index as u32,
                    tsc_hz: AtomicU64::new(0),
                    wake_routes_address: METADATA_VA + ROUTES_OFFSET,
                    apic_timer_hz: AtomicU64::new(0),
                });
            }
        }
        let ram = Arc::new(ram);
        let mut memory = CarrierMemory::create().map_err(|e| fail(e.to_string()))?;
        if interrupts {
            crate::carrier_interrupts::create_irqchip(memory.vm())?;
        }
        memory
            .install_bootstrap(Arc::clone(&ram))
            .map_err(|e| fail(e.to_string()))?;
        let kernel_region = if initial_extent_bytes.is_some() {
            let identity = NonZeroU64::new(0x101).ok_or_else(|| fail("kernel region identity"))?;
            let extent = BackingExtent::private(
                FrameGpa::new(KERNEL_REGION_GPA),
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .map_err(|e| fail(e.to_string()))?;
            let handles = memory
                .install(&[PreparedBacking {
                    extent: Arc::new(extent),
                    identity: BackingIdentity {
                        frame_id: identity,
                        mapping_id: identity,
                        owner_generation: identity,
                        inventory_revision: identity,
                    },
                }])
                .map_err(|e| fail(e.to_string()))?;
            Some(handles[0])
        } else {
            None
        };
        let initial_extent = if let Some(len) = initial_extent_bytes {
            let identity = NonZeroU64::new(NEXT_EXTENT_ID.fetch_add(1, Ordering::Relaxed))
                .ok_or_else(|| fail("initial backing identity exhausted"))?;
            let extent = BackingExtent::private(FrameGpa::new(INITIAL_EXTENT_GPA), len)
                .map_err(|e| fail(e.to_string()))?;
            let handles = memory
                .install(&[PreparedBacking {
                    extent: Arc::new(extent),
                    identity: BackingIdentity {
                        frame_id: identity,
                        mapping_id: identity,
                        owner_generation: identity,
                        inventory_revision: identity,
                    },
                }])
                .map_err(|e| fail(e.to_string()))?;
            Some((handles[0], len))
        } else {
            None
        };
        let machine = CarrierMachine::from_memory(memory, 2).map_err(|e| fail(e.to_string()))?;
        let (cpus, vm) = machine.into_parts();
        let [mut a, mut b]: [KvmVcpu; 2] =
            cpus.try_into().map_err(|_| fail("carrier vCPU count"))?;
        for (index, cpu) in [&mut a, &mut b].into_iter().enumerate() {
            let mut layout = LAYOUT;
            layout.trampoline_base = plan.entry;
            carrick_x86::program_longmode_entry(
                cpu,
                layout,
                USER_CODE + index as u64 * 4096,
                0x3_1ff0 + index as u64 * 0x1_0000,
            )?;
            carrick_x86::program_fault_segments(cpu, LAYOUT, index as u64)?;
            let mut system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            system.gdt.base = DIRECT_VA + LAYOUT.gdt_base;
            system.idt.base = DIRECT_VA
                + carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index as u64)?;
            system.tr.base = DIRECT_VA
                + carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index as u64)?;
            if interrupts {
                system.apic_base = carrick_x86::interrupts::LAPIC_BASE
                    | 0x800
                    | if index == 0 { 0x100 } else { 0 };
            }
            cpu.fd()
                .set_sregs(&system)
                .map_err(|e| fail(e.to_string()))?;
            cpu.set_syscall_msrs(
                plan.entry,
                boot.star,
                boot.sfmask | (1 << 10) | (1 << 8) | (1 << 18),
            )?;
            let msrs = Msrs::from_entries(&[kvm_msr_entry {
                index: 0xc000_0102,
                data: METADATA_VA + BINDING_OFFSET + index as u64 * STRIDE,
                ..Default::default()
            }])
            .map_err(|e| fail(e.to_string()))?;
            if cpu.fd().set_msrs(&msrs).map_err(|e| fail(e.to_string()))? != 1 {
                return Err(fail("KERNEL_GS_BASE not installed"));
            }
            let system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
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
            if interrupts {
                let lapic = cpu
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
            }
        }
        if interrupts {
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
        let metadata_base = NonNull::new(
            ram.host_ptr(META_GPA, META_LEN as usize)
                .ok_or_else(|| fail("retained metadata backing"))?,
        )
        .ok_or_else(|| fail("null metadata backing"))?;
        Ok(Self {
            cpus: [a, b],
            _vm: vm,
            ram,
            initial_extent,
            _kernel_region: kernel_region,
            initial_inventory: None,
            metadata_base,
            host_forwards: 0,
            host_yields: 0,
            kicks: 0,
            work_exits: 0,
        })
    }

    /// References are private and used only while both vCPUs are stopped.
    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: all callers select initialized, aligned retained records.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }
    pub(crate) fn binding(&self, index: usize) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + index as u64 * STRIDE)
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
        binding: carrick_el1_abi::ExecutionBinding,
    ) -> Result<(), TrapError> {
        if index >= 2
            || !binding.issued()
            || binding.mm.raw() == 0
            || binding.thread_generation.raw() == 0
        {
            return Err(fail("invalid CPL0 fixture execution binding"));
        }
        let tid = i32::try_from(binding.task.raw()).map_err(|_| fail("fixture task range"))?;
        let page_offset = index as u64 * 0x4000;
        let slot_offset = CONTROL_OFFSET + index as u64 * STRIDE;
        // SAFETY: exclusively stopped fixture vCPUs, initialized retained and
        // aligned metadata. Neither page/control reference escapes the owner;
        // each task's fresh page and control slot occupy disjoint metadata.
        unsafe {
            self.metadata_base
                .as_ptr()
                .add(page_offset as usize)
                .cast::<ThreadLifecyclePage>()
                .write(ThreadLifecyclePage::new());
            self.metadata_base
                .as_ptr()
                .add(slot_offset as usize)
                .cast::<ThreadControlSlot>()
                .write(ThreadControlSlot::new());
        }
        if !self.slot(index).publish_visible_tid(tid as u32) {
            return Err(fail("fixture visible task publication"));
        }
        let task = self.task(index);
        task.set(El1TaskId::from_linux_tid(tid), binding.generation.raw(), 5);
        task.mm.key.store(binding.mm.raw(), Ordering::Release);
        task.mm
            .thread_generation
            .store(binding.thread_generation.raw(), Ordering::Release);
        task.publish_lifecycle(METADATA_VA + page_offset, METADATA_VA + slot_offset);
        Ok(())
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
            host_forwards: self.host_forwards,
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
            let exit = HvVcpu::run(&mut self.cpus[index]).map_err(|e| fail(e.to_string()))?;
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
                let payload = self.cpus[index].get_gpr(X86Reg::Rax)?;
                return Err(fail(format!("CPL0 fatal exit: payload {payload:#x}")));
            }
            if port == YIELD_PORT {
                self.host_yields += 1;
                continue;
            }
            let address = self.cpus[index].get_gpr(X86Reg::Rax)?;
            let stack_end = self.binding(index).kernel_stack + 16;
            if address & 7 != 0
                || address < stack_end - 0x1_0000
                || address
                    .checked_add(size_of::<NativeFrame>() as u64)
                    .is_none_or(|end| end > stack_end)
            {
                return Err(fail(
                    "CPL0 control frame outside its private supervisor stack",
                ));
            }
            let ptr = self
                .ram
                .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
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
                        semantic_host_exits: self.host_forwards,
                        entries: core::array::from_fn(|i| {
                            self.binding(i).entries.load(Ordering::Acquire)
                        }),
                        publications: core::array::from_fn(|i| {
                            self.binding(i).publications.load(Ordering::Acquire)
                        }),
                        completions: core::array::from_fn(|i| {
                            self.binding(i).completions.load(Ordering::Acquire)
                        }),
                        kicks: self.kicks,
                        work_exits: self.work_exits,
                        captured_stack: self.binding(index).captured_stack.load(Ordering::Acquire),
                        returned_stack: frame.rsp,
                        preserved_rbx: frame.rbx,
                        host_yields: self.host_yields,
                    });
                }
                FORWARD_PORT => {
                    self.host_forwards += 1;
                    forward(frame)?;
                }
                ENTRY_KICK_PORT | RETURN_KICK_PORT => {
                    self.task(index).linux.mark_pending_host_work();
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(1);
                    let kicked = HvVcpu::run(&mut self.cpus[index]);
                    self.cpus[index].fd_mut().set_kvm_immediate_exit(0);
                    if !matches!(kicked, Ok(VcpuExit::Kicked)) {
                        return Err(fail("boundary kick did not interrupt KVM_RUN"));
                    }
                    self.kicks += 1;
                }
                WORK_PORT => {
                    if self
                        .task(index)
                        .linux
                        .served_with_work
                        .swap(0, Ordering::AcqRel)
                        == 0
                    {
                        return Err(fail("work exit without completed syscall"));
                    }
                    self.task(index)
                        .linux
                        .pending_host_work
                        .store(0, Ordering::Release);
                    self.work_exits += 1;
                }
                _ => return Err(fail(format!("unexpected CPL0 doorbell {port:#x}"))),
            }
        }
        Err(fail("CPL0 control exit budget exceeded"))
    }
}

#[derive(Debug)]
pub struct LifecycleObservation {
    pub births: u64,
    pub retirements: u64,
    pub wakes: u64,
    pub live: u32,
    pub state: Option<(u64, carrick_el1_abi::EntryState)>,
    pub entries: u64,
    pub completions: u64,
    pub served: [u64; 3],
    pub forwards: u64,
    pub words: [u64; 8],
}
impl Cpl0Carrier {
    /// The same KVM carrier, with one fixed native context sidecar per process.
    /// This binds executing shared owners, not the production executor pool.
    pub fn boot_lifecycle(image: &Path, programs: [&[u8]; 2]) -> Result<Self, TrapError> {
        use carrick_sched_core::{SlotId, ThreadIdentity, ZoneTables};
        use carrick_x86::cpl0_lifecycle::*;
        let mut carrier = Self::boot_inner(image, programs, true)?;
        // SAFETY: aligned initialized empty retained supervisor backing; all
        // fixture CPUs are stopped throughout native custody publication.
        let zone = unsafe {
            &*carrier
                .ram
                .host_ptr(0x100_0000, size_of::<ZoneTables>())
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        for index in 0..2 {
            let binding = carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(41 + index as u64),
                generation: carrick_el1_abi::EntryGeneration::from_raw(11 + index as u64),
                mm: carrick_el1_abi::EntryMmKey::from_raw(11 + index as u64),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(
                    101 + index as u64,
                ),
            };
            carrier.bind_execution(index, binding)?;
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
            zone.publish_slot(slot, binding.mm.raw(), Some(index as u32), 0);
            zone.enter_guest(slot);
            zone.install_space(slot, binding.mm.raw())
                .ok_or_else(|| fail("lifecycle installed MM"))?;
            let page_address = METADATA_VA + index as u64 * 0x4000;
            let controls_address = METADATA_VA + 0xb000 + index as u64 * 0x1000;
            // SAFETY: aligned, disjoint, exclusively stopped metadata storage.
            let controls = unsafe {
                &mut *carrier
                    .metadata_base
                    .as_ptr()
                    .add((0xb000 + index * 0x1000) as usize)
                    .cast::<[ThreadControlSlot; 9]>()
            };
            for control in controls.iter_mut() {
                *control = ThreadControlSlot::new();
            }
            controls[0].publish_visible_tid(binding.task.raw() as u32);
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
                    affinity: 1 << index,
                    lifecycle_page: page_address,
                    control_slot: controls_address,
                },
                slot,
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
                    .ram
                    .host_ptr(
                        0x190_0000 + index as u64 * LIFECYCLE_STRIDE,
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
                ._vm
                .write(
                    FrameGpa::new(LIFECYCLE_DATA + index as u64 * 4096 + 0x180),
                    &[0x5a + index as u8; 16],
                )
                .map_err(|e| fail(e.to_string()))?;
            carrier
                ._vm
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
                    uid_credit: 1,
                },
            )
            .map_err(|e| fail(format!("stock: {e:?}")))?;
        let controls: &[ThreadControlSlot; 9] = self.metadata(0xb000 + index as u64 * 0x1000);
        controls[1].reset_for_host_birth(BlockedMask(0));
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
                .ram
                .host_ptr(
                    0x190_0000 + index as u64 * LIFECYCLE_STRIDE,
                    size_of::<LifecycleLane>(),
                )
                .ok_or_else(|| fail("lane observation"))?
                .cast::<LifecycleLane>()
        };
        let page: &ThreadLifecyclePage = self.metadata(index as u64 * 0x4000);
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        let data = self
            .ram
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
            forwards: self.host_forwards,
            words,
        })
    }
}

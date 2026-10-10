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
    X86_CPL0_INITIAL_EXTENT_GPA, X86_CPL0_INITIAL_EXTENT_MAX_SIZE, X86_CPL0_INITIAL_EXTENT_VA,
    X86_CPL0_REGION_BASE,
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
use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
use carrick_hal::{FrameCowAuthority, PhysicalFrameInventory};
use carrick_hal::{
    FrameEventCapacity, FrameId, FrameInventoryEvent, FrameLength, MappingGeneration, MappingId,
    MemPerms,
};
use carrick_hal::{HvVcpu, TrapError, VcpuExit, VcpuKick};
#[cfg(test)]
use carrick_kernel::kernel::{FrameInventoryAuthority, MmId, ObjectIdRegistry};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use carrick_mmu_core::x86::descriptor_txn::{
    Access, BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, Permissions,
    translate_leaf,
};
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{SlotId, Waker};
use carrick_x86::cpl0_entry::*;
use carrick_x86::{BringupLayout, X86Reg, X86Vcpu};
use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_MP_STATE_RUNNABLE, Msrs, kvm_guest_debug,
    kvm_mp_state, kvm_msi, kvm_msr_entry,
};
use kvm_ioctls::VcpuExit as KvmExit;
use kvm_ioctls::VmFd;
use std::collections::VecDeque;
use std::num::NonZeroU64;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const RAM_SIZE: usize = 16 * 1024 * 1024;
const META_GPA: u64 = 0xc0_0000;
const META_LEN: u64 = 0x10_0000;
const PRODUCTION_METADATA_GPA: u64 = META_GPA;
const ALLOCATOR_GPA: u64 = 0x20_00000;
const INITIAL_EXTENT_GPA: u64 = X86_CPL0_INITIAL_EXTENT_GPA;
const KERNEL_REGION_GPA: u64 = 0x1_0000_0000;
const INITIAL_MM_KEY: u64 = 301;
const INITIAL_STACK_TOP: u64 = 0x7fff_0000;
const INITIAL_STACK_SIZE: u64 = 0x1_0000;
const COUNTERS_OFFSET: u64 = 0x1_0000;
const BINDING_OFFSET: u64 = 0x8000;
const TASK_OFFSET: u64 = 0x9000;
const CONTROL_OFFSET: u64 = 0xa000;
const ROUTES_OFFSET: u64 = 0xd000;
const SHOOTDOWN_OFFSET: u64 = 0xe000;
const STRIDE: u64 = 0x100;
const _: () = {
    assert!(size_of::<CpuBinding>() <= STRIDE as usize);
    assert!(ROUTES_OFFSET >= 0xc000 + 9 * size_of::<ThreadControlSlot>() as u64);
    assert!(ROUTES_OFFSET + size_of::<PublishedApicIds>() as u64 <= SHOOTDOWN_OFFSET);
    assert!(SHOOTDOWN_OFFSET + size_of::<ShootdownTable>() as u64 <= COUNTERS_OFFSET);
    assert!(
        carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
            <= META_LEN
    );
};
const IST_STACK_BASE: u64 = 0xf0_0000;
const IMAGE_VA: u64 = 0xffff_ffff_8000_0000;
const IMAGE_GPA: u64 = 0x10_0000;
const METADATA_VA: u64 = X86_CPL0_DYNAMIC_METADATA_BASE;
// Fork lifecycle stock: each 16 KiB slot holds a lifecycle page and, 4 KiB
// above it, the thread control slots. More records than CPUs keep a parent's
// fork from racing a reaped child that has not yet left its slot.
const FORK_LIFECYCLE_OFFSET: u64 = 0x8_8000;
const FORK_LIFECYCLE_STRIDE: u64 = carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE;
const FORK_LIFECYCLE_SLOTS: u64 = 8;
const _: () = {
    assert!(
        carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
            <= FORK_LIFECYCLE_OFFSET
    );
    assert!(FORK_LIFECYCLE_OFFSET.is_multiple_of(0x4000));
    assert!(
        carrick_hal::fork_stock::LIFECYCLE_CONTROLS_OFFSET
            + (carrick_el1_abi::THREAD_POOL_ENTRIES as u64 + 1)
                * size_of::<ThreadControlSlot>() as u64
            <= FORK_LIFECYCLE_STRIDE
    );
    assert!(
        size_of::<ThreadLifecyclePage>() as u64
            <= carrick_hal::fork_stock::LIFECYCLE_CONTROLS_OFFSET
    );
    assert!(FORK_LIFECYCLE_OFFSET + FORK_LIFECYCLE_SLOTS * FORK_LIFECYCLE_STRIDE <= META_LEN);
};
pub const USER_CODE: u64 = 0x1_0000;
pub(crate) use carrick_x86::cpl0_entry::DIRECT_VA;
// Startup stocks one initial MM and its first fork child's private COW branch.
// Later population admission remains bounded by actual available table grants.
const fn initial_copy_branch_table_credits() -> usize {
    2 * carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES
}

const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x10_0000,
    gdt_base: 0x50_0000,
    pml4_base: 0x60_0000,
};
const _: () = assert!(FIXTURE_PML4_CAPACITY == carrick_x86::X86_PML4_CAPACITY);

fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
enum FixtureCpuidError {
    MissingLeafZero,
    FullTable,
}

// The fixture uses CPUID only for the native CPU features admitted at boot,
// APIC topology, XSAVE x87/SSE/AVX, and the optional clock source. KVM hosts
// may return a completely full supported-CPUID table, so carrying unrelated
// cache, trace, and brand leaves into KVM_SET_CPUID2 cannot reserve 0x15.
fn fixture_cpuid_leaf(entry: &kvm_bindings::kvm_cpuid_entry2) -> bool {
    match entry.function {
        0 | 1 | 0x8000_0000 | 0x8000_0001 | 0x8000_0007 | 0x8000_0008 => true,
        0x15 => entry.index == 0,
        7 => entry.index == 0, // SMEP, SMAP and native feature admission.
        0xb | 0x1f => entry.index <= 2, // APIC topology for the two CPUs.
        0xd => entry.index <= 2, // XCR0=x87|SSE|AVX, including XSAVE size.
        _ => false,
    }
}

fn fixture_cpuid_with_tsc_hz(
    entries: &mut Vec<kvm_bindings::kvm_cpuid_entry2>,
    hz: u32,
) -> Result<(), FixtureCpuidError> {
    let mut selected: Vec<_> = entries.iter().copied().filter(fixture_cpuid_leaf).collect();
    let leaf0 = selected
        .iter()
        .position(|entry| entry.function == 0)
        .ok_or(FixtureCpuidError::MissingLeafZero)?;
    let existing = selected.iter().position(|entry| entry.function == 0x15);
    if existing.is_none() && selected.len() >= kvm_bindings::KVM_MAX_CPUID_ENTRIES {
        // This fixture owns its synthetic CPUID model. A retained all-zero
        // duplicate of leaf zero is unused storage, not an architectural
        // feature: carrick-vm returns 64 populated rows and 192 such rows.
        // Reuse only an exact zero duplicate, preserving every real leaf.
        let vacant = selected.iter().enumerate().find_map(|(index, entry)| {
            (index != leaf0
                && entry.function == 0
                && entry.index == 0
                && entry.flags == 0
                && entry.eax == 0
                && entry.ebx == 0
                && entry.ecx == 0
                && entry.edx == 0
                && entry.padding == [0; 3])
                .then_some(index)
        });
        let Some(vacant) = vacant else {
            return Err(FixtureCpuidError::FullTable);
        };
        selected[vacant] = kvm_bindings::kvm_cpuid_entry2 {
            function: 0x15,
            eax: 1,
            ebx: 1,
            ecx: hz,
            ..Default::default()
        };
        selected[leaf0].eax = selected[leaf0].eax.max(0x15);
        *entries = selected;
        return Ok(());
    }
    let clock = kvm_bindings::kvm_cpuid_entry2 {
        function: 0x15,
        eax: 1,
        ebx: 1,
        ecx: hz,
        ..Default::default()
    };
    selected[leaf0].eax = selected[leaf0].eax.max(0x15);
    if let Some(existing) = existing {
        selected[existing] = clock;
    } else {
        selected.push(clock);
    }
    *entries = selected;
    Ok(())
}

/// The host's disposition of one Linux call forwarded by the shared guest.
pub enum InitialSyscallDisposition {
    Return(i64),
    Refused(carrick_abi::LinuxErrno),
    Exit(GuestExitStatus),
}

/// Physical services carry no guest Linux policy or host dispatch authority.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PhysicalCrossingFamily {
    OwnerGrant,
    RootExit,
    ChildRetire,
}
impl PhysicalCrossingFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerGrant => "owner_grant",
            Self::RootExit => "root_exit",
            Self::ChildRetire => "child_retire",
        }
    }
}

#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct InitialReservationLimits {
    pub address: carrick_abi::LinuxRlimit,
    pub data: carrick_abi::LinuxRlimit,
}

impl InitialReservationLimits {
    pub const UNLIMITED: Self = Self {
        address: carrick_abi::LinuxRlimit::new(u64::MAX, u64::MAX),
        data: carrick_abi::LinuxRlimit::new(u64::MAX, u64::MAX),
    };
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct GuestExitStatus(u8);
impl GuestExitStatus {
    pub const fn from_linux_code(code: i32) -> Self {
        Self(code as u8)
    }

    pub const fn code(self) -> i32 {
        self.0 as i32
    }
}

fn backing_identity(ids: &dyn PhysicalFrameInventory) -> Result<BackingIdentity, TrapError> {
    let (frame, mapping) = ids
        .allocate_backing_ids()
        .map_err(|error| fail(error.to_string()))?;
    Ok(BackingIdentity {
        frame_id: NonZeroU64::new(frame.raw())
            .ok_or_else(|| fail("carrier frame identity zero"))?,
        mapping_id: NonZeroU64::new(mapping.raw())
            .ok_or_else(|| fail("carrier mapping identity zero"))?,
        owner_generation: NonZeroU64::MIN,
        inventory_revision: NonZeroU64::MIN,
    })
}

/// Authenticate the guest's mutable completion against the retained host
/// request before any reply field sizes a read, indexes a grant, or subtracts
/// a stack bound. The stopped carrier still owns all unpublished grants on
/// refusal, so dropping its inventory rolls the transaction back.
fn validate_initial_reply(
    request: &X86InitialBootRequest,
    reply: &X86InitialBootRequest,
    grant_count: usize,
    root_gpa: u64,
    initial_break: u64,
) -> Result<(), TrapError> {
    let host_grants = (request.table_grant_count as usize)
        .checked_add(request.data_grant_count as usize)
        .ok_or_else(|| fail("initial MM host grant count overflow"))?;
    let stack_base = request
        .stack_top
        .checked_sub(request.stack_size)
        .ok_or_else(|| fail("initial MM host stack underflow"))?;
    if reply.result_status != X86_INITIAL_BOOT_LOADED
        || reply.magic != request.magic
        || reply.version != request.version
        || reply.region_count != request.region_count
        || reply.entry != request.entry
        || reply.phdr != request.phdr
        || reply.phent != request.phent
        || reply.phnum != request.phnum
        || reply.argc != request.argc
        || reply.envc != request.envc
        || reply.regions_gpa != request.regions_gpa
        || reply.strings_gpa != request.strings_gpa
        || reply.grants_gpa != request.grants_gpa
        || reply.table_grant_count != request.table_grant_count
        || reply.data_grant_count != request.data_grant_count
        || reply.publications_gpa != request.publications_gpa
        || reply.publication_capacity != request.publication_capacity
        || reply.stack_top != request.stack_top
        || reply.stack_size != request.stack_size
        || reply.random != request.random
        || reply.extent_pages != request.extent_pages
        || reply.mm_key != request.mm_key
        || reply.generation != request.generation
        || host_grants != grant_count
        || request.table_grant_count == 0
        || request.data_grant_count == 0
        || reply.publication_count == 0
        || reply.publication_count != request.data_grant_count
        || reply.result_data_used != reply.publication_count
        || reply.result_root_gpa != root_gpa
        || reply.result_table_used == 0
        || reply.result_table_used > request.table_grant_count
        || reply.result_initial_break != initial_break
        || reply.result_rsp < stack_base
        || reply.result_rsp >= request.stack_top
    {
        return Err(fail("production initial MM reply identity"));
    }
    Ok(())
}

fn initial_stack_pages(
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    argv: &[String],
    env: &[String],
) -> Result<usize, TrapError> {
    use carrick_el1::isa::x86_initial_mm::{InitialStackSpec, build_initial_stack};
    let argv_bytes: Vec<&[u8]> = argv.iter().map(|value| value.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|value| value.as_bytes()).collect();
    let stack = build_initial_stack(&InitialStackSpec {
        entry: image.entry,
        phdr: image.phdr,
        phent: image.phent,
        phnum: image.phnum,
        argv: &argv_bytes,
        envp: &env_bytes,
        random: [0; 16],
        stack_top: INITIAL_STACK_TOP,
        stack_size: INITIAL_STACK_SIZE,
    })
    .map_err(|error| fail(format!("initial stack sizing: {error:?}")))?;
    Ok(stack.bytes.len() / 4096)
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
    mm: MmGeneration,
    source: Arc<dyn PhysicalFrameInventory>,
    authority: Arc<dyn FrameCowAuthority>,
    receipt: Option<carrick_hal::UnpublishedFrameInventoryApply<dyn FrameCowAuthority>>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    length: FrameLength,
    expected: usize,
    committed: usize,
    guest_exposed: bool,
    rollback_fault: Arc<AtomicBool>,
}
impl InitialInventory {
    fn stage(
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner_generation: NonZeroU64,
        mm: MmGeneration,
    ) -> Result<(Self, Vec<X86InitialBootGrant>), TrapError> {
        let authority = source.bind(mm);
        let gpas: Vec<_> = gpas.into_iter().collect();
        if table_grants >= gpas.len() {
            return Err(fail("initial inventory grant partition"));
        }
        let capacity = FrameEventCapacity::for_event_count(
            gpas.len()
                .checked_mul(2)
                .ok_or_else(|| fail("initial inventory capacity"))?,
        )
        .map_err(|error| fail(format!("initial inventory capacity: {error}")))?;
        let mut reservation = authority
            .reserve(gpas.len(), gpas.len(), capacity.get())
            .map_err(|error| fail(format!("initial inventory reserve: {error}")))?;
        let transaction = reservation.transaction();
        let generation = MappingGeneration::from_backend_counter(owner_generation);
        let length = FrameLength::from_mapping_extent(
            NonZeroU64::new(frame_len).ok_or_else(|| fail("initial frame length"))?,
        );
        let mut rows = Vec::with_capacity(gpas.len());
        for (index, gpa) in gpas.into_iter().enumerate() {
            let frame = reservation
                .claim_frame()
                .map_err(|error| fail(format!("initial frame candidate: {error}")))?;
            let mapping = reservation
                .claim_mapping()
                .map_err(|error| fail(format!("initial mapping candidate: {error}")))?;
            if index >= table_grants {
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
            }
            rows.push((gpa, frame, mapping, index >= table_grants));
        }
        let receipt = carrick_hal::UnpublishedFrameInventoryApply::apply(
            Arc::clone(&authority),
            reservation.commit(()),
        )
        .map_err(|error| fail(format!("initial inventory apply: {error}")))?;
        let mut frames = Vec::with_capacity(rows.len() - table_grants);
        let mut grants = Vec::with_capacity(rows.len());
        for (gpa, frame, mapping, is_data) in rows {
            if is_data && !receipt.authorizes(mapping, frame) {
                return Err(fail("initial inventory missing mapping"));
            }
            let identity = BackingIdentity {
                frame_id: NonZeroU64::new(frame.raw())
                    .ok_or_else(|| fail("initial frame identity"))?,
                mapping_id: NonZeroU64::new(mapping.raw())
                    .ok_or_else(|| fail("initial mapping identity"))?,
                owner_generation,
                inventory_revision: NonZeroU64::new(receipt.revision())
                    .ok_or_else(|| fail("initial inventory revision"))?,
            };
            if is_data {
                frames.push((gpa, identity));
            }
            grants.push(X86InitialBootGrant {
                gpa: gpa.raw(),
                frame_id: frame.raw(),
                mapping_id: mapping.raw(),
                owner_generation: generation.raw(),
                inventory_revision: receipt.revision(),
            });
        }
        frames.sort_unstable_by_key(|(gpa, _)| gpa.raw());
        Ok((
            Self {
                mm,
                source,
                authority,
                receipt: Some(receipt),
                frames,
                length,
                expected: 0,
                committed: 0,
                guest_exposed: false,
                rollback_fault: Arc::new(AtomicBool::new(false)),
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
        let mm = self.mm;
        if receipt.mm() != mm.raw() {
            return Err(crate::carrier_memory::MemoryError(
                "inventory MM mismatch".into(),
            ));
        }
        for &(gpa, identity) in &self.frames {
            let mapping = MappingId::from_kernel_allocation(identity.mapping_id);
            let frame = FrameId::from_kernel_allocation(identity.frame_id);
            if !receipt.authorizes(mapping, frame)
                || !self
                    .authority
                    .mapping_is_live(
                        mapping,
                        frame,
                        carrick_guest_mem::Gpa(gpa.raw()),
                        self.length,
                    )
                    .map_err(|error| crate::carrier_memory::MemoryError(error.to_string()))?
            {
                return Err(crate::carrier_memory::MemoryError(
                    "inventory frame missing".into(),
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
        self.guest_exposed = true;
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        if self.guest_exposed {
            return Err(crate::carrier_memory::MemoryError(
                "cannot roll back guest-exposed inventory without retirement".into(),
            ));
        }
        if let Some(receipt) = self.receipt.as_mut() {
            receipt.rollback().map_err(|error| {
                crate::carrier_memory::MemoryError(format!("initial inventory rollback: {error}"))
            })?;
        }
        self.receipt = None;
        self.committed = 0;
        Ok(())
    }
}
impl Drop for InitialInventory {
    fn drop(&mut self) {
        if self.receipt.is_some() && !self.guest_exposed && self.rollback().is_err() {
            self.rollback_fault.store(true, Ordering::Release);
        }
    }
}

/// Bound one guest execution interval and pause while the carrier serves an
/// exit. The worker is joined before its owning carrier can be released.
pub(crate) struct Watchdog {
    control: mpsc::Sender<WatchdogControl>,
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

fn physical_interrupt_ready(cpu: &mut KvmVcpu) -> Result<bool, TrapError> {
    let regs = cpu.fd().get_regs().map_err(|e| fail(e.to_string()))?;
    if regs.rflags & (1 << 9) == 0 {
        return Ok(false);
    }
    let events = cpu
        .fd()
        .get_vcpu_events()
        .map_err(|e| fail(e.to_string()))?;
    if events.interrupt.shadow != 0 {
        return Ok(false);
    }
    if events.interrupt.injected != 0 {
        return Ok(true);
    }
    let lapic = cpu.fd().get_lapic().map_err(|e| fail(e.to_string()))?;
    let word =
        |offset: usize| u32::from_le_bytes(std::array::from_fn(|i| lapic.regs[offset + i] as u8));
    let tpr = word(0x80) & 0xff;
    let isr_priority = (0..8)
        .rev()
        .find_map(|i| {
            let bits = word(0x100 + i * 0x10);
            (bits != 0).then(|| (i as u32 * 32 + 31 - bits.leading_zeros()) & 0xf0)
        })
        .unwrap_or(0);
    let priority = (tpr & 0xf0).max(isr_priority);
    Ok((0..8).any(|i| {
        let bits = word(0x200 + i * 0x10);
        (0..32).any(|bit| bits & (1 << bit) != 0 && ((i * 32 + bit) as u32 & 0xf0) > priority)
    }))
}

fn run_member(
    cpu: &mut KvmVcpu,
    table: &ShootdownTable,
    slot: usize,
    vm: &VmFd,
    actual_run: Option<&AtomicU32>,
) -> Result<VcpuExit, TrapError> {
    let member = table
        .members
        .get(slot)
        .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
    struct RunningAdmission<'a>(&'a std::sync::atomic::AtomicU32);
    impl Drop for RunningAdmission<'_> {
        fn drop(&mut self) {
            self.0.store(0, Ordering::Release);
        }
    }
    // A sender that observes this release either targets the live vCPU or
    // races this pre-run scan, which queues its durable MSI before KVM_RUN.
    member.running.store(1, Ordering::Release);
    let running_admission = RunningAdmission(&member.running);
    let sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
    let has_debt = table.requests.iter().any(|request| {
        request.generation.load(Ordering::Acquire) > request.served[slot].load(Ordering::Acquire)
    });
    if has_debt {
        if sregs.cs.dpl == 3 && !stopped_at_interruptible_user(cpu)? {
            return Err(fail("shootdown debt requires interruptible CPL3 reentry"));
        } else if sregs.cs.dpl != 0 && sregs.cs.dpl != 3 {
            return Err(fail("shootdown debt on unsupported CPL reentry"));
        }
        let lapic = cpu.fd().get_lapic().map_err(|e| fail(e.to_string()))?;
        let apic_id = u32::from_le_bytes([
            lapic.regs[0x20] as u8,
            lapic.regs[0x21] as u8,
            lapic.regs[0x22] as u8,
            lapic.regs[0x23] as u8,
        ]) >> 24;
        let delivered = vm
            .signal_msi(kvm_msi {
                address_lo: 0xfee0_0000 | (apic_id << 12),
                data: u32::from(carrick_x86::interrupts::KICK_VECTOR),
                ..Default::default()
            })
            .map_err(|e| fail(format!("KVM_SIGNAL_MSI reentry: {e}")))?;
        if delivered <= 0 {
            return Err(fail("reentry shootdown MSI was blocked"));
        }
    }
    let actual_guard = actual_run.map(|flag| {
        flag.store(1, Ordering::Release);
        RunningAdmission(flag)
    });
    let result = HvVcpu::run(cpu)?;
    drop(actual_guard);
    drop(running_admission);
    if stopped_at_interruptible_user(cpu)? {
        // The host may release a sender after this vCPU has stopped, but
        // leaves `served` behind until native KICK settles debt on reentry.
        for request in &table.requests {
            let generation = request.generation.load(Ordering::Acquire);
            if generation != 0 {
                request.ack[slot].store(generation, Ordering::Release);
            }
        }
    }
    Ok(result)
}
impl Watchdog {
    pub(crate) fn start() -> Self {
        Self::start_with_timeout(Duration::from_secs(5))
    }
    fn start_with_timeout(timeout: Duration) -> Self {
        let kick = KvmKickHandle::for_current_thread();
        let (control, receiver) = mpsc::channel();
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
    /// Apply the safety kick to one guest execution interval. Each guest exit
    /// is progress; host service time does not consume the next interval.
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
impl Drop for Watchdog {
    fn drop(&mut self) {
        let _ = self.control.send(WatchdogControl::Cancel);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod fixture_cpuid_tests {
    use super::*;

    #[test]
    fn full_cpuid_fixture_reuses_only_an_exact_zero_duplicate_of_leaf_zero() {
        let mut entries =
            vec![kvm_bindings::kvm_cpuid_entry2::default(); kvm_bindings::KVM_MAX_CPUID_ENTRIES];
        entries[0].eax = 0x10;
        entries[1].function = 7;
        entries[1].ebx = (1 << 7) | (1 << 20);
        let features = entries[1];
        fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000).expect("vacant duplicate reused");
        assert_eq!(entries.len(), kvm_bindings::KVM_MAX_CPUID_ENTRIES);
        assert_eq!(entries[0].eax, 0x15);
        assert_eq!(entries[1].ebx, features.ebx);
        assert_eq!(entries[2].function, 0x15);
        assert_eq!(entries[2].ecx, 2_000_000_000);
    }

    #[test]
    fn eighty_supported_leaves_leave_room_for_fixture_tsc() {
        let mut entries = vec![kvm_bindings::kvm_cpuid_entry2 {
            function: 0,
            eax: 0x16,
            ..Default::default()
        }];
        entries.extend(
            [1, 7, 0xd, 0x8000_0000, 0x8000_0001, 0x8000_0008].map(|function| {
                kvm_bindings::kvm_cpuid_entry2 {
                    function,
                    ..Default::default()
                }
            }),
        );
        entries.extend(
            (entries.len()..80).map(|index| kvm_bindings::kvm_cpuid_entry2 {
                function: 0x100 + index as u32,
                ..Default::default()
            }),
        );
        assert_eq!(entries.len(), 80);
        fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000).unwrap();
        assert!(entries.len() < 80, "unused host leaves must be removed");
        assert!(
            entries
                .iter()
                .any(|entry| entry.function == 0x15 && entry.ecx == 2_000_000_000)
        );
        assert!(entries.iter().any(|entry| entry.function == 7));
        assert!(entries.iter().any(|entry| entry.function == 0xd));
    }

    #[test]
    fn missing_base_leaf_refuses_without_mutation() {
        let mut entries = (0..kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map(|index| kvm_bindings::kvm_cpuid_entry2 {
                function: 0x100 + index as u32,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let before = entries.clone();
        assert_eq!(
            fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000),
            Err(FixtureCpuidError::MissingLeafZero)
        );
        assert_eq!(entries, before);
    }

    #[test]
    fn full_kvm_cpuid_table_reuses_its_existing_tsc_leaf() {
        let mut entries = vec![kvm_bindings::kvm_cpuid_entry2 {
            function: 0,
            eax: 7,
            ..Default::default()
        }];
        entries.extend((1..kvm_bindings::KVM_MAX_CPUID_ENTRIES).map(|index| {
            kvm_bindings::kvm_cpuid_entry2 {
                function: if index == 17 {
                    0x15
                } else {
                    0x100 + index as u32
                },
                ..Default::default()
            }
        }));
        assert_eq!(
            fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000),
            Ok(())
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.function == 0x15)
                .map(|entry| entry.ecx),
            Some(2_000_000_000)
        );
    }
}

#[derive(::core::fmt::Debug)]
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
#[derive(::core::fmt::Debug)]
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
#[path = "cpl0_anonymous.rs"]
mod anonymous_owner;

#[derive(::core::clone::Clone, ::core::marker::Copy)]
struct ForwardExecution {
    cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    context: AddressContext<RootGpa>,
}

fn admit_forward_execution(
    cpu: carrick_guest_arch::CpuId,
    binding_cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    context: AddressContext<RootGpa>,
    live_root: RootGpa,
    owner_generation: ContextGeneration,
) -> Result<ForwardExecution, TrapError> {
    if cpu != binding_cpu
        || !binding.issued()
        || binding.thread_generation.raw() == 0
        || binding.mm.raw() != context.mm.raw().get()
        || live_root != context.root
        || owner_generation != context.generation
    {
        return Err(fail("stopped forward execution mismatch"));
    }
    Ok(ForwardExecution {
        cpu,
        binding,
        context,
    })
}

#[cfg(test)]
mod forward_execution_tests {
    use super::*;

    fn execution() -> (carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>) {
        (
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(42),
                generation: carrick_el1_abi::EntryGeneration::from_raw(12),
                mm: carrick_el1_abi::EntryMmKey::from_raw(302),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(102),
            },
            AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).expect("aligned root"),
                mm: MmGeneration::new(NonZeroU64::new(302).expect("MM")),
                generation: ContextGeneration::new(NonZeroU64::new(9).expect("incarnation")),
            },
        )
    }

    #[test]
    fn stopped_forward_refuses_wrong_cpu_mm_root_and_incarnation() {
        let (binding, context) = execution();
        let cpu = carrick_guest_arch::CpuId::new(1);
        assert!(
            admit_forward_execution(
                cpu,
                carrick_guest_arch::CpuId::new(0),
                binding,
                context,
                context.root,
                context.generation
            )
            .is_err()
        );
        let wrong_mm = carrick_el1_abi::ExecutionBinding {
            mm: carrick_el1_abi::EntryMmKey::from_raw(301),
            ..binding
        };
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                wrong_mm,
                context,
                context.root,
                context.generation
            )
            .is_err()
        );
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                binding,
                context,
                RootGpa::page_aligned(FrameGpa::new(0x6000)).expect("aligned root"),
                context.generation
            )
            .is_err()
        );
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                binding,
                context,
                context.root,
                ContextGeneration::new(NonZeroU64::new(8).expect("incarnation"))
            )
            .is_err()
        );
        let admitted =
            admit_forward_execution(cpu, cpu, binding, context, context.root, context.generation)
                .expect("exact lane1 owner");
        assert_eq!(admitted.cpu.raw(), 1);
        assert_eq!(admitted.binding, binding);
        assert_eq!(admitted.context, context);
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
enum InitialPeerAdmission {
    Cold,
    Ready,
}

pub struct Cpl0Carrier {
    pub(crate) cpus: [KvmVcpu; 2],
    pub(crate) custody: Cpl0HostCustody,
}

/// One coordinator owns physical backing, grants and retained metadata.
/// CPU execution leases are disjoint from this custody, so stopped host service
/// never borrows the carrier or a simultaneously running peer CPU.
pub(crate) struct Cpl0HostCustody {
    pub(crate) _vm: CarrierMemory,
    pub(crate) ram: Arc<GuestRam>,
    initial_extent: Option<(BackingHandle, usize)>,
    _kernel_region: Option<BackingHandle>,
    frame_inventory: Arc<dyn PhysicalFrameInventory>,
    pub(crate) private_anonymous_witness: crate::cpl0_private_witness::PrivateAnonymousWitness,
    actual_run: Arc<[AtomicU32; 2]>,
    kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
    initial_inventory: Option<InitialInventory>,
    initial_rollback_fault: Option<Arc<AtomicBool>>,
    peer_entry: Option<carrick_guest_arch::KernelVa>,
    peer_admission: InitialPeerAdmission,
    prepare_table_stock: Option<anonymous_owner::PrepareTableStock>,
    /// The ISA-neutral fork stock, loans and child quarantine.
    fork_stock: carrick_hal::fork_stock::ForkStock<carrick_hal::fork_stock::UntaggedRoots>,
    anonymous_next_gpa: FrameGpa,
    anonymous_pending: [Option<anonymous_owner::PendingGrant>; 2],
    owner_grant_crossings: u64,
    root_exit_crossings: u64,
    child_retire_crossings: u64,
    metadata_base: NonNull<u8>,
    host_forwards: u64,
    host_yields: u64,
    kicks: u64,
    work_exits: u64,
}

impl Drop for Cpl0HostCustody {
    fn drop(&mut self) {
        // Unwind the inventory first. Its destructor only records a refused
        // retirement; this carrier observer chooses the existing fail-stop.
        drop(self.initial_inventory.take());
        if self
            .initial_rollback_fault
            .as_ref()
            .is_some_and(|fault| fault.load(Ordering::Acquire))
        {
            carrick_el1::personality::dispatch::invalid_completion(
                carrick_el1::personality::dispatch::NativeInvariant::PhysicalCustody(
                    "unexposed physical inventory rollback failed",
                ),
            );
        }
    }
}

/// Exclusive physical CPU custody while KVM_RUN has returned.
pub(crate) struct StoppedCpuLease<'a> {
    cpu: carrick_guest_arch::CpuId,
    vcpu: &'a mut KvmVcpu,
}

/// Host crossings see only their stopped physical lane and exact MM owner.
/// Process policy and task selection remain in the shared guest owner.
pub struct ForwardVenue<'a> {
    custody: &'a mut Cpl0HostCustody,
    lease: StoppedCpuLease<'a>,
    execution: ForwardExecution,
}

impl Cpl0HostCustody {
    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: the retained owner initialized each aligned record before
        // publication. Callers access atomic metadata or their stopped lane.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }

    fn task(&self, cpu: carrick_guest_arch::CpuId) -> &CurrentTask {
        self.metadata(TASK_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }

    fn binding(&self, cpu: carrick_guest_arch::CpuId) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }
}

impl<'a> ForwardVenue<'a> {
    fn new(
        custody: &'a mut Cpl0HostCustody,
        lease: StoppedCpuLease<'a>,
    ) -> Result<Self, TrapError> {
        let cpu = lease.cpu;
        let task = custody.task(cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("stopped forward MM"))?;
        let context = custody
            ._vm
            .root(mm)
            .ok_or_else(|| fail("stopped forward root"))?;
        let native = custody.binding(cpu);
        let root = RootGpa::page_aligned(FrameGpa::new(lease.vcpu.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("stopped forward CR3 alignment"))?;
        let generation = ContextGeneration::new(
            NonZeroU64::new(native.mm_owner_generation.load(Ordering::Acquire))
                .ok_or_else(|| fail("stopped forward address incarnation"))?,
        );
        let execution = admit_forward_execution(
            cpu,
            carrick_guest_arch::CpuId::new(native.cpu_slot),
            binding,
            context,
            root,
            generation,
        )?;
        Ok(Self {
            custody,
            lease,
            execution,
        })
    }

    pub fn cpu(&self) -> carrick_guest_arch::CpuId {
        self.execution.cpu
    }
}

impl Cpl0Carrier {
    fn run_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError> {
        if index >= self.cpus.len() {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        // SAFETY: `metadata_base` owns this aligned table until every vCPU
        // and scoped guest-run thread has stopped. The table and vCPU fields
        // are disjoint even while this method borrows the vCPU mutably.
        let table = unsafe {
            &*self
                .custody
                .metadata_base
                .as_ptr()
                .add(SHOOTDOWN_OFFSET as usize)
                .cast::<ShootdownTable>()
        };
        run_member(
            &mut self.cpus[index],
            table,
            index,
            &self.custody._vm.vm().vm,
            Some(&self.custody.actual_run[index]),
        )
    }
    /// Size one private retained aperture for the host-staged PT_LOAD bytes,
    /// the boot record, and guest-owned table/data grants. Capacity follows
    /// the submitted image rather than reserving a carrier-wide RAM pool.
    pub fn initial_extent_bytes_for(
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        argv: &[String],
        env: &[String],
    ) -> Result<usize, TrapError> {
        const PAGE: usize = 4096;
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
            .checked_add(initial_stack_pages(image, argv, env)?)
            .ok_or_else(|| fail("initial user pages"))?;
        let table_pages = user_pages
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(initial_copy_branch_table_credits()))
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
            .and_then(|bytes| bytes.checked_add(anonymous_owner::prepare_table_working_bytes()?))
            .ok_or_else(|| fail("initial extent size"))?;
        if bytes > MAX_BYTES {
            return Err(fail("initial image exceeds carrier memory budget"));
        }
        Ok(bytes)
    }
    pub fn physical_slot_count(&self) -> usize {
        self.custody._vm.slot_count()
    }

    /// Inspect the carrier's one admitted production reservation authority.
    /// The store and zone are two offsets into the same retained metadata
    /// extent; a fixture carrier with no production root returns false.
    pub fn initial_reservation_admitted(&self) -> bool {
        let (Some(table), Some(zone), Some(mm)) = (
            self.custody.ram.host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            ),
            self.custody.ram.host_ptr(
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

    /// Observe the stopped boot owner's actual mapping census used by fork.
    pub fn initial_reservation_census(
        &self,
    ) -> Result<Vec<carrick_core::mm::reservation::Mapping>, TrapError> {
        let table = self
            .custody
            .ram
            .host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            )
            .ok_or_else(|| fail("initial census table"))?;
        let zone = self
            .custody
            .ram
            .host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_ZONE_OFFSET,
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
        let mm = ReservationMm::new(INITIAL_MM_KEY).ok_or_else(|| fail("initial census MM"))?;
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
            if let Err(error) = Self::unexpected_boot_wake(zone, waker, owned) {
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

    fn unexpected_boot_wake(
        _: &X86Cpl0Zone,
        _: Waker,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) -> Result<(), TrapError> {
        let mut handed = false;
        let (_, effects) = owned.deliver_handbacks(&mut |_| handed = true);
        if handed || effects != carrick_sched_core::WakeEffects::default() {
            return Err(fail(
                "boot-only publication unexpectedly released a live guest waiter",
            ));
        }
        Ok(())
    }

    /// The initial host-loaded task retains an x86-shaped scheduler record
    /// in the same zone that owns its MM notifications.
    pub fn initial_thread_custody(&self) -> bool {
        let Some(zone) = self.custody.ram.host_ptr(
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

    /// Initial data publications belong to the carrier's one frame inventory,
    /// which remains available to subsequent fault and fork services.
    pub fn initial_inventory_custody(&self) -> bool {
        self.custody
            .initial_inventory
            .as_ref()
            .is_some_and(|initial| {
                Arc::ptr_eq(&self.custody.frame_inventory, &initial.source)
                    && initial.frames.len() == initial.expected
                    && initial.frames.iter().all(|(_, identity)| {
                        initial
                            .authority
                            .live_mapping_row(MappingId::from_kernel_allocation(
                                identity.mapping_id,
                            ))
                            .is_some()
                    })
            })
    }

    pub fn retained_bytes(&self) -> usize {
        self.custody._vm.retained_bytes()
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

    /// Inspect the stopped bootstrap's supervisor direct-window permissions.
    pub fn bootstrap_supervisor_access(&self, gpa: u64, access: Access) -> Result<bool, TrapError> {
        if !(0x20_0000..0xc0_0000).contains(&gpa) {
            return Err(fail("supervisor access outside bootstrap window"));
        }
        let root = RootGpa::page_aligned(FrameGpa::new(LAYOUT.pml4_base))
            .ok_or_else(|| fail("bootstrap root alignment"))?;
        Ok(translate_leaf(
            &self.custody._vm.words(),
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
            &self.custody._vm.words(),
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
    ) -> Result<Self, TrapError> {
        const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/carrick-x86-cpl0"));
        if initial_extent_bytes == 0
            || initial_extent_bytes > X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize
            || !initial_extent_bytes.is_multiple_of(4096)
        {
            return Err(fail("invalid initial guest MM extent size"));
        }
        Self::boot_bytes_inner(
            frame_inventory,
            IMAGE,
            [&[], &[]],
            false,
            Some(initial_extent_bytes),
            false,
        )
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
        let (_, extent_len) = self
            .custody
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
            .checked_add(initial_stack_pages(image, argv, env)?)
            .ok_or_else(|| fail("initial data grants"))?;
        let table_grants = data_grants
            .checked_mul(3)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(initial_copy_branch_table_credits()))
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
        let occupied_end = frame_offset
            .checked_add(grant_count * 4096)
            .ok_or_else(|| fail("initial occupied physical extent"))?;
        let prepare_span = anonymous_owner::prepare_table_suffix(extent_len, occupied_end)
            .ok_or_else(|| fail("initial records/grants overlap Prepare working stock"))?;
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(&self.custody.frame_inventory),
            (0..grant_count).map(|index| {
                FrameGpa::new(INITIAL_EXTENT_GPA + (frame_offset + index * 4096) as u64)
            }),
            table_grants,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(
                NonZeroU64::new(INITIAL_MM_KEY).ok_or_else(|| fail("initial inventory MM"))?,
            ),
        )?;
        self.custody.initial_rollback_fault = Some(Arc::clone(&inventory.rollback_fault));
        let outcome = (|| -> Result<(), TrapError> {
            inventory
                .publish()
                .map_err(|error| fail(error.to_string()))?;
            let (handle, _) = self
                .custody
                .initial_extent
                .ok_or_else(|| fail("initial extent handle"))?;
            self.custody
                ._vm
                .bind_frame_identities(handle, &inventory.frames)
                .map_err(|error| fail(error.to_string()))?;
            // The guest editor's no-op invalidation is valid only while this
            // unpublished root cannot be in any live vCPU TLB. Both vCPUs are
            // stopped here; reject a reused root before the first descriptor edit.
            for cpu in &self.cpus {
                if cpu.get_gpr(X86Reg::Cr3)?
                    == grants
                        .first()
                        .ok_or_else(|| fail("initial root grant absent"))?
                        .gpa
                {
                    return Err(fail("initial root already live in a vCPU"));
                }
            }
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|error| fail(format!("initial random: {error}")))?;
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
            self.custody
                ._vm
                .write(FrameGpa::new(INITIAL_EXTENT_GPA), &staged)
                .map_err(|error| fail(error.to_string()))?;
            let header = self
                .custody
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
                || !(IMAGE_VA..IMAGE_VA + 0x10_0000).contains(&header.peer_entry_va)
            {
                return Err(fail("production image boot header invalid"));
            }
            self.custody.peer_entry = Some(carrick_guest_arch::KernelVa::new(header.peer_entry_va));
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
            let exit = self.run_cpu(0)?;
            if matches!(exit, VcpuExit::Kicked) {
                return Err(fail("production initial MM cancelled"));
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
                .custody
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
            validate_initial_reply(
                &request,
                &reply,
                grants.len(),
                grants
                    .first()
                    .ok_or_else(|| fail("initial root grant absent"))?
                    .gpa,
                image
                    .regions
                    .iter()
                    .map(|region| region.end)
                    .max()
                    .unwrap_or(0),
            )?;
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
            let publication_bytes = self
                .custody
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
            let linked_tables = publications.iter().try_fold(1usize, |count, publication| {
                if publication.revision != GuestMmuPublication::REVISION
                    || publication.outcome != GuestMmuPublication::APPLIED
                    || publication.mm_key != mm.get()
                    || publication.root_gpa != root.address().raw()
                    || publication.generation != generation.get()
                    || publication.span_len != 4096
                {
                    return None;
                }
                count.checked_add(publication.tables_linked as usize)
            });
            let linked_tables =
                linked_tables.ok_or_else(|| fail("initial publication table receipt count"))?;
            let copy_tables = carrick_mmu_core::x86::copy_window::cow_copy_table_frames(
                &self.custody._vm.words(),
                root,
            )
            .map_err(|_| fail("initial private copy branch"))?;
            let total_tables = linked_tables
                .checked_add(copy_tables.len())
                .ok_or_else(|| fail("initial publication table receipt overflow"))?;
            if total_tables != reply.result_table_used as usize {
                return Err(fail("initial publication table receipt count"));
            }
            let copy_grants = grants
                .get(linked_tables..total_tables)
                .ok_or_else(|| fail("initial copy table grant range"))?;
            if !copy_tables
                .iter()
                .zip(copy_grants)
                .all(|(table, grant)| table.address().raw() == grant.gpa)
            {
                return Err(fail("initial copy table grant identity"));
            }
            self.custody
                ._vm
                .install_root(mm, context)
                .map_err(|error| fail(error.to_string()))?;
            // Descriptor transaction identity names only user mapping tables;
            // the separately authenticated private branch is not a user edit.
            let tables: Vec<RootGpa> = grants
                .get(1..linked_tables)
                .ok_or_else(|| fail("initial table grant range"))?
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
                } else if publication.span_va
                    >= reply
                        .stack_top
                        .checked_sub(reply.stack_size)
                        .ok_or_else(|| fail("initial stack bound"))?
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
                let grant_index = table_grants
                    .checked_add(index)
                    .ok_or_else(|| fail("initial data grant index overflow"))?;
                let grant = *grants
                    .get(grant_index)
                    .ok_or_else(|| fail("initial data grant absent"))?;
                let output = FrameGpa::new(grant.gpa);
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
                    // The unpublished builder owns private frames for both
                    // PT_LOAD segments and the initial anonymous stack. Keep
                    // the exact publication operation aligned with that owner.
                    op: DescriptorOp::Prepare {
                        span: PageSpan::new(publication.span_va, 4096),
                        output,
                        permissions: perms,
                        resident: PageSpan::new(publication.span_va, 4096),
                        backing: identity,
                    },
                    tables: tables
                        .get(used_tables..)
                        .ok_or_else(|| fail("initial table receipt count"))?,
                };
                self.custody
                    ._vm
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
                image,
                limits,
            )?;
            inventory.finish()?;
            self.custody.bind_grant_portal()?;
            let unused = grants
                .get(reply.result_table_used as usize..table_grants)
                .ok_or_else(|| fail("initial unused table grants"))?
                .iter()
                .map(|grant| {
                    RootGpa::page_aligned(FrameGpa::new(grant.gpa))
                        .ok_or_else(|| fail("initial unused table alignment"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.custody.install_fork_stock(root, unused)?;
            let stock_bytes = self
                .custody
                ._vm
                .read(prepare_span.start(), prepare_span.len().raw() as usize)
                .map_err(|error| fail(error.to_string()))?;
            self.custody.prepare_table_stock = Some(
                anonymous_owner::PrepareTableStock::seed(prepare_span, &stock_bytes).ok_or_else(
                    || fail("Prepare working table suffix is not exclusive zero storage"),
                )?,
            );
            Ok(())
        })();
        let outcome = match outcome {
            Err(error) if !inventory.guest_exposed => match inventory.rollback() {
                Ok(()) => Err(error),
                Err(rollback) => Err(fail(format!(
                    "initial boot rollback: {rollback}; original: {error}"
                ))),
            },
            result => result,
        };
        // Retain failed physical custody until the carrier retires; rollback
        // refusal never consumes its receipt or publishes a ready guest.
        self.custody.initial_inventory = Some(inventory);
        outcome
    }

    fn publish_production_reservations(
        &mut self,
        mm_key: NonZeroU64,
        root: RootGpa,
        initial_break: u64,
        stack_top: u64,
        image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
        limits: InitialReservationLimits,
    ) -> Result<(), TrapError> {
        const ARENA_START: u64 = 0x4000_0000;
        let heap = ReservationRange::new(initial_break, ARENA_START)
            .ok_or_else(|| fail("initial heap layout"))?;
        let arena = ReservationRange::new(ARENA_START, stack_top - INITIAL_STACK_SIZE)
            .ok_or_else(|| fail("initial mmap arena layout"))?;
        let table = self
            .custody
            .ram
            .host_ptr(
                META_GPA + carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET,
                size_of::<X86Cpl0Reservations>(),
            )
            .ok_or_else(|| fail("production reservation backing"))?
            .cast::<X86Cpl0Reservations>();
        let zone = self
            .custody
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
                    address_limit: limits.address.rlim_cur,
                    data_limit: limits.data.rlim_cur,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .map_err(|error| fail(format!("production reservation publication: {error:?}")))?;
        let wake_error = std::cell::RefCell::new(None);
        let deliver = |zone: &X86Cpl0Zone,
                       waker: Waker,
                       owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {
            if let Err(error) = Self::unexpected_boot_wake(zone, waker, owned) {
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
        X86Cpl0RootReleaseVenue::new(table, release)
            .map_err(|error| fail(format!("production root authority: {error:?}")))?
            .lock(index.index(), mm, &NoRootWait)
            .and_then(|mut model| {
                model.finish_import()?;
                for region in &image.regions {
                    let bits = u64::from(region.perms.read)
                        | (u64::from(region.perms.write) << 1)
                        | (u64::from(region.perms.execute) << 2);
                    model.insert_opaque(
                        ReservationRange::new(region.start, region.end)
                            .ok_or(carrick_el1::memory::reservations::Refusal::Invalid)?,
                        carrick_el1_abi::ReservationProtection::from_bits(bits)
                            .ok_or(carrick_el1::memory::reservations::Refusal::Invalid)?,
                        carrick_el1_abi::ReservationNodeFlags::PRIVATE,
                    )?;
                }
                model.insert_opaque(
                    ReservationRange::new(stack_top - INITIAL_STACK_SIZE, stack_top)
                        .ok_or(carrick_el1::memory::reservations::Refusal::Invalid)?,
                    carrick_el1_abi::ReservationProtection::READ_WRITE,
                    carrick_el1_abi::ReservationNodeFlags::PRIVATE
                        .union(carrick_el1_abi::ReservationNodeFlags::GROWSDOWN),
                )
            })
            .map_err(|error| fail(format!("production root admission: {error:?}")))?;
        SpaceAccess::notified(release).open(index);
        if let Some(error) = wake_error.into_inner() {
            return Err(error);
        }
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
        self.task(0).publish_visible_pid(41);
        zone.current_or_new(
            slot,
            carrick_sched_core::ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: mm.raw(),
                file_table: 5,
                generation: 11,
                affinity: 3,
                lifecycle_page: METADATA_VA,
                control_slot: METADATA_VA + CONTROL_OFFSET,
            },
        )
        .map_err(|_| fail("production scheduler record exhausted"))?;
        Ok(())
    }

    /// Resume the published initial MM through the existing shared Linux
    /// personality. Only host-crossing calls leave CPL0 through FORWARD_PORT.
    fn start_initial_peer(&mut self, max_exits: usize) -> Result<(), TrapError> {
        // READY is a one-way physical boot receipt. Resuming a bounded run
        // preserves CPU1's native context; it must never initialize it twice.
        if self.custody.peer_admission == InitialPeerAdmission::Ready {
            return Ok(());
        }
        let peer = self
            .custody
            .peer_entry
            .ok_or_else(|| fail("initial peer entry absent"))?;
        let stack = self.binding(1).kernel_stack;
        let initial = self
            .custody
            ._vm
            .root(NonZeroU64::new(INITIAL_MM_KEY).ok_or_else(|| fail("initial MM"))?)
            .ok_or_else(|| fail("initial peer root"))?;
        let cpu = &mut self.cpus[1];
        let mut sregs = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
        sregs.cr3 = initial.root.address().raw();
        sregs.cs.selector = 8;
        sregs.cs.dpl = 0;
        sregs.ss.selector = 0x10;
        sregs.ss.dpl = 0;
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
                self.custody.peer_admission = InitialPeerAdmission::Ready;
                Ok(())
            }
            VcpuExit::Kicked => Err(fail("initial peer cancelled")),
            _ => Err(fail("initial peer readiness exit before READY")),
        }
    }

    pub fn run_initial_process(
        &mut self,
        max_exits: usize,
        mut forward: impl FnMut(
            &mut ForwardVenue<'_>,
            &NativeFrame,
        ) -> Result<InitialSyscallDisposition, TrapError>,
    ) -> Result<InitialProcessExit, TrapError> {
        let mm = NonZeroU64::new(INITIAL_MM_KEY).ok_or_else(|| fail("initial MM key"))?;
        if self.custody._vm.root(mm).is_none() {
            return Err(fail("initial MM not published"));
        }
        self.start_initial_peer(max_exits)?;
        let vm = Arc::clone(&self.custody._vm.vm().vm);
        // SAFETY: retained atomic-only shootdown table outlives both scoped actors.
        let table = unsafe {
            &*self
                .custody
                .metadata_base
                .as_ptr()
                .add(SHOOTDOWN_OFFSET as usize)
                .cast::<ShootdownTable>()
        };
        let actual_run = Arc::clone(&self.custody.actual_run);
        let custody = &mut self.custody;
        let mut recent_forwards = VecDeque::with_capacity(8);
        let mut exits = 0usize;
        crate::cpl0_actors::run_two_actors(
            &mut self.cpus,
            |cpu_id, cpu| {
                run_member(
                    cpu,
                    table,
                    cpu_id.raw() as usize,
                    &vm,
                    Some(&actual_run[cpu_id.raw() as usize]),
                )
            },
            |cpu_id, cpu, exit| {
                use crate::cpl0_actors::ActorDecision;
                exits = exits
                    .checked_add(1)
                    .ok_or_else(|| fail("initial process exit counter"))?;
                if exits > max_exits {
                    return Err(fail("initial process exit budget exceeded"));
                }
                let index = cpu_id.raw() as usize;
                if matches!(exit, VcpuExit::Halt) {
                    return Ok(ActorDecision::Park);
                }
                if matches!(exit, VcpuExit::Kicked) {
                    return Err(fail("initial process cancelled"));
                }
                if matches!(
                    exit,
                    VcpuExit::IoOut {
                        port: OWNER_GRANT_PORT,
                        ..
                    }
                ) {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let lease = StoppedCpuLease {
                        cpu: cpu_id,
                        vcpu: cpu,
                    };
                    custody.service_anonymous_grant(&lease)?;
                    return Ok(ActorDecision::Resume);
                }
                if matches!(
                    exit,
                    VcpuExit::IoOut {
                        port: carrick_el1_abi::FORK_STOCK_PORT,
                        ..
                    }
                ) {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let lease = StoppedCpuLease {
                        cpu: cpu_id,
                        vcpu: cpu,
                    };
                    custody.service_fork_stock(&lease)?;
                    return Ok(ActorDecision::Resume);
                }
                if matches!(
                    exit,
                    VcpuExit::IoOut {
                        port: carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT,
                        ..
                    }
                ) {
                    custody.child_retire_crossings = custody
                        .child_retire_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let lease = StoppedCpuLease {
                        cpu: cpu_id,
                        vcpu: cpu,
                    };
                    custody.service_child_retire(&lease)?;
                    return Ok(ActorDecision::Resume);
                }
                if matches!(
                    exit,
                    VcpuExit::IoOut {
                        port: carrick_el1_abi::NATIVE_ROOT_EXIT_PORT,
                        ..
                    }
                ) {
                    custody.root_exit_crossings = custody
                        .root_exit_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let lease = StoppedCpuLease {
                        cpu: cpu_id,
                        vcpu: cpu,
                    };
                    let status = custody.service_root_exit(&lease)?;
                    return Ok(ActorDecision::Finish(InitialProcessExit::Exited {
                        code: status.code(),
                        exits,
                    }));
                }
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
                            } = run_member(cpu, table, index, &vm, Some(&actual_run[index]))?
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
                        let reason = custody.binding(cpu_id).fault_reason.load(Ordering::Acquire);
                        if reason != 6 {
                            return Err(fail(format!(
                                "kernel fault policy refused: reason {reason}, {record:?}"
                            )));
                        }
                        return Ok(ActorDecision::Finish(InitialProcessExit::Fault {
                            record,
                            exits,
                        }));
                    }
                    let mut detail = match exit {
                        VcpuExit::IoOut { port, .. } => {
                            format!("unexpected initial process port {port:#x}")
                        }
                        VcpuExit::Halt => "initial process halted".to_owned(),
                        _ => "unexpected initial process exit".to_owned(),
                    };
                    cpu.append_debug_state(&mut detail);
                    return Err(fail(detail));
                };
                let address = cpu.get_gpr(X86Reg::Rax)?;
                let stack_end = custody.binding(cpu_id).kernel_stack + 16;
                if address & 7 != 0
                    || address < stack_end - 0x1_0000
                    || address
                        .checked_add(size_of::<NativeFrame>() as u64)
                        .is_none_or(|end| end > stack_end)
                {
                    return Err(fail("initial syscall frame outside private kernel stack"));
                }
                let ptr = custody
                    .ram
                    .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
                    .ok_or_else(|| fail("initial syscall frame backing"))?
                    .cast::<NativeFrame>();
                // SAFETY: the stopped CPU published this exact stack-local frame.
                // Copy it before lending the carrier to the host dispatcher, then
                // write only the return register back before resuming the vCPU.
                let mut frame = unsafe { *ptr };
                let native_nr = frame.rax;
                let native_args = [frame.rdi, frame.rsi, frame.rdx];
                custody.host_forwards += 1;
                let decision = {
                    let mut venue = ForwardVenue::new(
                        custody,
                        StoppedCpuLease {
                            cpu: cpu_id,
                            vcpu: cpu,
                        },
                    )?;
                    forward(&mut venue, &frame)?
                };
                match decision {
                    InitialSyscallDisposition::Return(value) => frame.rax = value as u64,
                    InitialSyscallDisposition::Refused(errno) => {
                        frame.rax = errno.guest_retval() as u64;
                    }
                    InitialSyscallDisposition::Exit(code) => {
                        return Ok(ActorDecision::Finish(InitialProcessExit::Exited {
                            code: code.code(),
                            exits,
                        }));
                    }
                }
                if recent_forwards.len() == 8 {
                    recent_forwards.pop_front();
                }
                recent_forwards.push_back((native_nr, native_args, frame.rax as i64));
                // SAFETY: `ptr` names the validated retained supervisor stack and
                // the vCPU is stopped until the next `HvVcpu::run` above.
                unsafe { ptr.write(frame) };
                Ok(ActorDecision::Resume)
            },
            |_cpu_id, cpu| physical_interrupt_ready(cpu),
        )
    }

    /// Counters from the stopped production carrier, including its initial
    /// image entry and each guest-to-host syscall forward.
    pub fn initial_execution_witness(&self) -> (u64, u64) {
        (
            self.binding(0).entries.load(Ordering::Acquire),
            self.custody.host_forwards,
        )
    }

    /// Pages whose PRIVATE native descriptors and physical custody were
    /// checked at the stopped guest's applied owner-grant completion.
    pub fn anonymous_private_pages(&self) -> u64 {
        self.custody.private_anonymous_witness.private_pages()
    }

    /// Shared fork-stock counters: loans, counted capacity refusals (each
    /// lowered to `EAGAIN` by the guest), quarantined and returned children.
    pub fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.custody.fork_stock_counters()
    }

    pub fn physical_crossing_counts(&self) -> [(PhysicalCrossingFamily, u64); 3] {
        [
            (
                PhysicalCrossingFamily::OwnerGrant,
                self.custody.owner_grant_crossings,
            ),
            (
                PhysicalCrossingFamily::RootExit,
                self.custody.root_exit_crossings,
            ),
            (
                PhysicalCrossingFamily::ChildRetire,
                self.custody.child_retire_crossings,
            ),
        ]
    }

    /// Read the per-ordinal CPL0 refusal counter for a native syscall ordinal.
    /// Ordinals >= 512 are read from the overflow bucket.
    pub fn refusal_count(&self, nr: u64) -> u64 {
        let counters: &Counters = self.metadata(COUNTERS_OFFSET);
        if let Ok(index @ 0..=511) = usize::try_from(nr) {
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
        )
    }

    fn boot_bytes_inner(
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        bytes: &[u8],
        programs: [&[u8]; 2],
        interrupts: bool,
        initial_extent_bytes: Option<usize>,
        fixture_image: bool,
    ) -> Result<Self, TrapError> {
        let hardware_interrupts = interrupts || initial_extent_bytes.is_some();
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
        let kernel_pod_storage = anonymous_owner::retained_kernel_pod_storage(&plan.segments);
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
        let stub_start = carrick_x86::fault_stub_base(LAYOUT);
        let stub_end = carrick_x86::fault_tss_base(LAYOUT);
        if !(0x20_0000 < stub_start && stub_start < stub_end && stub_end < 0xc0_0000) {
            return Err(fail("CPL0 stub outside direct window"));
        }
        // Retained exception stubs execute from their supervisor alias. The
        // page tables, private IDTs, TSS, stacks and records need write access
        // but must never be executable in that alias.
        for (start, end, write, exec) in [
            (0x20_0000, stub_start, true, false),
            (stub_start, stub_end, false, true),
            (stub_end, 0xc0_0000, true, false),
        ] {
            maps.push(Pml4MapSpec {
                va: DIRECT_VA + start,
                gpa: start,
                len: end - start,
                user: false,
                write,
                exec,
            });
        }
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
        } else if hardware_interrupts {
            maps.push(crate::carrier_interrupts::lapic_map());
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
        // Fixture bootstrap roots reserve an exclusive zero suffix for the
        // same private copy branch that production initial-MM admission owns.
        // The constructor cannot allocate these pages into any other branch.
        let fixture_copy = fixture_image && initial_extent_bytes.is_none();
        let table_capacity = (carrick_x86::X86_PML4_CAPACITY as usize)
            .checked_sub(if fixture_copy {
                carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES * 4096
            } else {
                0
            })
            .ok_or_else(|| fail("fixture private copy table capacity"))?;
        let tables = pml4_tables(&maps, LAYOUT.pml4_base, table_capacity)
            .map_err(|e| fail(format!("CPL0 tables: {e:?}")))?;
        ram.write_gpa(LAYOUT.pml4_base, &tables)
            .map_err(|e| fail(e.to_string()))?;
        if interrupts {
            let last = maps.last_mut().ok_or_else(|| fail("progress data map"))?;
            *last = crate::carrier_interrupts::data_map(1);
            let second = pml4_tables(
                &maps,
                crate::carrier_interrupts::SECOND_ROOT,
                table_capacity,
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
        if hardware_interrupts {
            use carrick_x86::interrupts::{
                IRQ_HEADER_GPA, IRQ_HEADER_MAGIC, KICK_VECTOR, PAGE_FAULT_VECTOR, RESCHED_VECTOR,
                SHOOTDOWN_VECTOR, TIMER_VECTOR,
            };
            let header = ram
                .read(IRQ_HEADER_GPA, 6 * size_of::<u64>())
                .map_err(|error| fail(format!("native IRQ header: {error}")))?;
            let mut words = [0_u64; 6];
            for (word, bytes) in words.iter_mut().zip(header.chunks_exact(8)) {
                *word = u64::from_le_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| fail("native IRQ header width"))?,
                );
            }
            if words[0] != IRQ_HEADER_MAGIC
                || words[1..]
                    .iter()
                    .any(|pc| !(IMAGE_VA..IMAGE_VA + 0x10_0000).contains(pc))
            {
                return Err(fail("native IRQ header or entry outside image"));
            }
            for index in 0..2 {
                let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
                for (vector, entry) in [
                    TIMER_VECTOR,
                    KICK_VECTOR,
                    RESCHED_VECTOR,
                    SHOOTDOWN_VECTOR,
                    PAGE_FAULT_VECTOR,
                ]
                .into_iter()
                .zip(words[1..].iter().copied())
                {
                    ram.write_gpa(
                        idt + u64::from(vector) * 16,
                        &carrick_x86::interrupts::interrupt_gate(entry),
                    )
                    .map_err(|error| fail(error.to_string()))?;
                }
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
            let shootdown = ram
                .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
                .ok_or_else(|| fail("shootdown table backing"))?
                .cast::<ShootdownTable>();
            shootdown.write(ShootdownTable::new());
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
                (*shootdown).members[index].publish(
                    if interrupts && index == 1 {
                        crate::carrier_interrupts::SECOND_ROOT
                    } else {
                        LAYOUT.pml4_base
                    },
                    201 + index as u64,
                    1,
                );
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
                    pending_irqs: AtomicU32::new(0),
                    shootdown_table_address: METADATA_VA + SHOOTDOWN_OFFSET,
                    fault_active: AtomicU64::new(0),
                    fault_frame: AtomicU64::new(0),
                    fault_address: AtomicU64::new(0),
                    fault_reason: AtomicU64::new(0),
                    mm_owner_generation: AtomicU64::new(1),
                    last_seen_generation: AtomicU64::new(0),
                });
            }
        }
        let ram = Arc::new(ram);
        let mut memory = CarrierMemory::create().map_err(|e| fail(e.to_string()))?;
        if hardware_interrupts {
            crate::carrier_interrupts::create_irqchip(memory.vm())?;
        }
        memory
            .install_bootstrap(Arc::clone(&ram))
            .map_err(|e| fail(e.to_string()))?;
        if fixture_copy {
            let mut roots = vec![LAYOUT.pml4_base];
            if interrupts {
                roots.push(crate::carrier_interrupts::SECOND_ROOT);
            }
            for base in roots {
                let root = RootGpa::page_aligned(FrameGpa::new(base))
                    .ok_or_else(|| fail("fixture copy root alignment"))?;
                let mut grants = [root; carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES];
                for (index, grant) in grants.iter_mut().enumerate() {
                    let pa = base
                        .checked_add(table_capacity as u64)
                        .and_then(|pa| pa.checked_add(index as u64 * 4096))
                        .ok_or_else(|| fail("fixture copy table grant overflow"))?;
                    *grant = RootGpa::page_aligned(FrameGpa::new(pa))
                        .ok_or_else(|| fail("fixture copy table grant alignment"))?;
                }
                carrick_mmu_core::x86::copy_window::provision_cow_copy_window(
                    &memory.words(),
                    root,
                    grants,
                )
                .map_err(|reason| fail(format!("fixture private copy branch: {reason:?}")))?;
            }
        }
        let kernel_region = if initial_extent_bytes.is_some() {
            let identity = backing_identity(&*frame_inventory)?;
            let extent = BackingExtent::private(
                FrameGpa::new(KERNEL_REGION_GPA),
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .map_err(|e| fail(e.to_string()))?;
            let handles = memory
                .install(&[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }])
                .map_err(|e| fail(e.to_string()))?;
            Some(handles[0])
        } else {
            None
        };
        let initial_extent = if let Some(len) = initial_extent_bytes {
            let identity = backing_identity(&*frame_inventory)?;
            let extent = BackingExtent::private(FrameGpa::new(INITIAL_EXTENT_GPA), len)
                .map_err(|e| fail(e.to_string()))?;
            let handles = memory
                .install(&[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }])
                .map_err(|e| fail(e.to_string()))?;
            Some((handles[0], len))
        } else {
            None
        };
        if kernel_region.is_some() {
            memory
                .initialize_fault_records(FrameGpa::new(KERNEL_REGION_GPA))
                .map_err(|error| fail(error.to_string()))?;
        }
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
            if hardware_interrupts && initial_extent_bytes.is_none() {
                // This fixture enters CPL3 directly. Unlike the production
                // initial-MM IRET frame, the generic x86 bootstrap flags
                // still have IF clear for CPL0 bringup. Admit native APIC
                // interrupts before the first fixture user instruction.
                cpu.set_gpr(X86Reg::Rflags, boot.rflags | (1 << 9))?;
            }
            carrick_x86::program_fault_segments(cpu, LAYOUT, index as u64)?;
            let mut system = cpu.fd().get_sregs().map_err(|e| fail(e.to_string()))?;
            if initial_extent_bytes.is_some() {
                const CPUID_SMEP_SMAP: u32 = (1 << 7) | (1 << 20);
                const CR4_SMEP_SMAP: u64 = (1 << 20) | (1 << 21);
                let cpuid = cpu
                    .fd()
                    .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                    .map_err(|error| fail(format!("KVM_GET_CPUID2: {error}")))?;
                let features = cpuid
                    .as_slice()
                    .iter()
                    .find(|entry| entry.function == 7 && entry.index == 0)
                    .map_or(0, |entry| entry.ebx);
                if features & CPUID_SMEP_SMAP != CPUID_SMEP_SMAP {
                    return Err(fail("production CPL0 requires CPUID SMEP and SMAP"));
                }
                system.cr4 |= CR4_SMEP_SMAP;
            }
            system.gdt.base = DIRECT_VA + LAYOUT.gdt_base;
            system.idt.base = DIRECT_VA
                + carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index as u64)?;
            system.tr.base = DIRECT_VA
                + carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index as u64)?;
            if hardware_interrupts {
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
                data: METADATA_VA + BINDING_OFFSET + index as u64 * STRIDE,
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
        let fork_stock = carrick_hal::fork_stock::ForkStock::new(
            vm.identity().nonzero(),
            KERNEL_REGION_GPA,
            carrick_hal::fork_stock::UntaggedRoots,
        );
        let metadata_base = NonNull::new(
            ram.host_ptr(META_GPA, META_LEN as usize)
                .ok_or_else(|| fail("retained metadata backing"))?,
        )
        .ok_or_else(|| fail("null metadata backing"))?;
        Ok(Self {
            cpus: [a, b],
            custody: Cpl0HostCustody {
                _vm: vm,
                ram,
                initial_extent,
                _kernel_region: kernel_region,
                frame_inventory,
                private_anonymous_witness: Default::default(),
                actual_run: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
                kernel_pod_storage,
                initial_inventory: None,
                initial_rollback_fault: None,
                peer_entry: None,
                peer_admission: InitialPeerAdmission::Cold,
                prepare_table_stock: None,
                fork_stock,
                anonymous_next_gpa: FrameGpa::new(0x2_0000_0000),
                anonymous_pending: [None, None],
                owner_grant_crossings: 0,
                root_exit_crossings: 0,
                child_retire_crossings: 0,
                metadata_base,
                host_forwards: 0,
                host_yields: 0,
                kicks: 0,
                work_exits: 0,
            },
        })
    }

    /// References are private and used only while both vCPUs are stopped.
    fn metadata<T>(&self, offset: u64) -> &T {
        self.custody.metadata(offset)
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
        let mut entries = cpuid.as_slice().to_vec();
        fixture_cpuid_with_tsc_hz(&mut entries, hz)
            .map_err(|error| fail(format!("fixture CPUID clock: {error:?}")))?;
        let cpuid = kvm_bindings::CpuId::from_entries(&entries)
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
            ._vm
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

    /// Stage an exact byte in a stopped fixture's retained backing.
    pub fn fixture_write_backing_byte(&mut self, gpa: u64, value: u8) -> Result<(), TrapError> {
        if !matches!(gpa, 0xd1_1000 | 0x4_0000 | 0x4_0008) {
            return Err(fail("fixture byte outside admitted backing"));
        }
        self.custody
            ._vm
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
            ._vm
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
                    .ram
                    .host_ptr(gpa, 1)
                    .ok_or_else(|| fail("fixture user flag outside backing"))?;
                (pointer as usize, false)
            }
            FixtureStopCondition::PendingKick(slot) => {
                let offset = BINDING_OFFSET + slot as u64 * STRIDE;
                let pointer = self
                    .custody
                    .ram
                    .host_ptr(META_GPA + offset, size_of::<CpuBinding>())
                    .ok_or_else(|| fail("fixture IRQ binding outside backing"))?
                    .cast::<CpuBinding>();
                // SAFETY: the retained metadata page contains this initialized
                // per-CPU binding through both the watcher and stopped vCPU.
                let pending = unsafe { &(*pointer).pending_irqs };
                (pending as *const AtomicU32 as usize, true)
            }
        };
        let retained_ram = Arc::clone(&self.custody.ram);
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
        self.custody.host_forwards += 1;
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
            .custody
            .ram
            .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
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
            self.custody
                .metadata_base
                .as_ptr()
                .add(page_offset as usize)
                .cast::<ThreadLifecyclePage>()
                .write(ThreadLifecyclePage::new());
            self.custody
                .metadata_base
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
            host_forwards: self.custody.host_forwards,
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
        ) -> Result<u64, TrapError> {
            let watchdog = Watchdog::start();
            for _ in 0..32 {
                let exit = watchdog.during_guest(|| run_member(cpu, table, slot, vm, None))?;
                if watchdog.expired() {
                    return Err(fail("paired fixture guest interval deadline"));
                }
                match exit {
                    VcpuExit::IoOut {
                        port: CONTROL_PORT, ..
                    } => {
                        let address = cpu.get_gpr(X86Reg::Rax)?;
                        if address & 7 != 0
                            || address < stack_end - 0x1_0000
                            || address
                                .checked_add(size_of::<NativeFrame>() as u64)
                                .is_none_or(|end| end > stack_end)
                        {
                            return Err(fail("paired control frame outside private stack"));
                        }
                        let ptr = ram
                            .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
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
        let ram = Arc::clone(&self.custody.ram);
        let stacks = [
            self.binding(0).kernel_stack + 16,
            self.binding(1).kernel_stack + 16,
        ];
        // SAFETY: the retained table outlives both scoped guest-run threads.
        let table = unsafe {
            &*self
                .custody
                .metadata_base
                .as_ptr()
                .add(SHOOTDOWN_OFFSET as usize)
                .cast::<ShootdownTable>()
        };
        let vm = &self.custody._vm.vm().vm;
        let [a, b] = &mut self.cpus;
        std::thread::scope(|scope| {
            let left = scope.spawn(|| first_result(a, &ram, stacks[0], table, 0, vm));
            let right = scope.spawn(|| first_result(b, &ram, stacks[1], table, 1, vm));
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
        let ram = Arc::clone(&self.custody.ram);
        let stack_end = self.binding(editor).kernel_stack + 16;
        let table = unsafe {
            &*self
                .custody
                .metadata_base
                .as_ptr()
                .add(SHOOTDOWN_OFFSET as usize)
                .cast::<ShootdownTable>()
        };
        let vm = &self.custody._vm.vm().vm;
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
                    let exit = watchdog
                        .during_guest(|| run_member(reader_cpu, table, reader, vm, None))?;
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
                    let exit = watchdog
                        .during_guest(|| run_member(editor_cpu, table, editor, vm, None))?;
                    if watchdog.expired() {
                        return Err(fail("running editor deadline"));
                    }
                    match exit {
                        VcpuExit::IoOut {
                            port: CONTROL_PORT, ..
                        } => {
                            let address = editor_cpu.get_gpr(X86Reg::Rax)?;
                            if address & 7 != 0
                                || address < stack_end - 0x1_0000
                                || address
                                    .checked_add(size_of::<NativeFrame>() as u64)
                                    .is_none_or(|end| end > stack_end)
                            {
                                return Err(fail("editor control frame outside private stack"));
                            }
                            let ptr = ram
                                .host_ptr(address - DIRECT_VA, size_of::<NativeFrame>())
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
                let payload = self.cpus[index].get_gpr(X86Reg::Rax)?;
                let fault = self.user_fault_state(index)?;
                let mut detail = format!("CPL0 fatal exit: payload {payload:#x}, fault {fault:?}");
                self.cpus[index].append_debug_state(&mut detail);
                return Err(fail(detail));
            }
            if port == YIELD_PORT {
                self.custody.host_yields += 1;
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
                .custody
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
                        semantic_host_exits: self.custody.host_forwards,
                        entries: core::array::from_fn(|i| {
                            self.binding(i).entries.load(Ordering::Acquire)
                        }),
                        publications: core::array::from_fn(|i| {
                            self.binding(i).publications.load(Ordering::Acquire)
                        }),
                        completions: core::array::from_fn(|i| {
                            self.binding(i).completions.load(Ordering::Acquire)
                        }),
                        kicks: self.custody.kicks,
                        work_exits: self.custody.work_exits,
                        captured_stack: self.binding(index).captured_stack.load(Ordering::Acquire),
                        returned_stack: frame.rsp,
                        preserved_rbx: frame.rbx,
                        host_yields: self.custody.host_yields,
                    });
                }
                FORWARD_PORT => {
                    self.custody.host_forwards += 1;
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
                    self.custody.kicks += 1;
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
                    self.custody.work_exits += 1;
                }
                _ => return Err(fail(format!("unexpected CPL0 doorbell {port:#x}"))),
            }
        }
        Err(fail("CPL0 control exit budget exceeded"))
    }
}

impl ForwardVenue<'_> {
    fn authenticate_initial_copy_page(
        &self,
        output: FrameGpa,
        address: u64,
    ) -> Result<(), MemoryError> {
        let page = output.raw() & !4095;
        let mm_key = self.execution.binding.mm.raw();
        let mm = carrick_guest_arch::MmGeneration::new(
            NonZeroU64::new(mm_key).ok_or(MemoryError::Unsupported)?,
        );
        let identity = self
            .custody
            ._vm
            .frame_identity(
                NonZeroU64::new(mm_key).ok_or(MemoryError::Unsupported)?,
                FrameGpa::new(page),
            )
            .map_err(|_| MemoryError::OutOfBounds { address, length: 1 })?;
        let row = self
            .custody
            .frame_inventory
            .bind(mm)
            .live_mapping_row(MappingId::from_kernel_allocation(identity.mapping_id))
            .ok_or(MemoryError::OutOfBounds { address, length: 1 })?;
        if row.frame != FrameId::from_kernel_allocation(identity.frame_id)
            || row.generation != MappingGeneration::from_backend_counter(identity.owner_generation)
            || page < row.gpa.0
            || page.checked_add(4096).is_none_or(|end| {
                row.gpa
                    .0
                    .checked_add(row.length.raw())
                    .is_none_or(|limit| end > limit)
            })
        {
            return Err(MemoryError::OutOfBounds { address, length: 1 });
        }
        Ok(())
    }
}

impl GuestMemory for ForwardVenue<'_> {
    fn read_bytes_prefix(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // This bounded crossing copy has one frame of host storage at a time.
        // A later inaccessible page leaves Linux the already readable prefix.
        let limit = length.min(1024 * 1024);
        let mut bytes = Vec::new();
        while bytes.len() < limit {
            let Some(va) = address.checked_add(bytes.len() as u64) else {
                break;
            };
            let count = ((4096 - (va & 4095)) as usize).min(limit - bytes.len());
            match self.read_bytes_raw(va, count) {
                Ok(page) => bytes.extend(page),
                Err(error) if bytes.is_empty() => return Err(error),
                Err(_) => break,
            }
        }
        Ok(bytes)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let ceiling =
            carrick_hal::guest_arch::UserVaCeiling::for_abi(carrick_abi::LinuxGuestAbi::X86_64)
                .exclusive_end();
        if length != 0
            && (address >= ceiling
                || address
                    .checked_add(length as u64)
                    .is_none_or(|end| end > ceiling))
        {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let root = self.execution.context.root;
        let mut bytes = Vec::new();
        while bytes.len() < length {
            let va = address
                .checked_add(bytes.len() as u64)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            let leaf = translate_leaf(
                &self.custody._vm.words(),
                root,
                UserVa::new(va),
                Access::Read,
                true,
            )
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length,
            })?;
            self.authenticate_initial_copy_page(leaf.output, va)?;
            let count = (4096 - (va & 4095)) as usize;
            let count = count.min(length - bytes.len());
            let page = self.custody._vm.read(leaf.output, count).map_err(|_| {
                MemoryError::OutOfBounds {
                    address: va,
                    length,
                }
            })?;
            // A caller can request far more bytes than its live MM maps.
            // Admit storage only as each stage-1 page proves readable.
            bytes
                .try_reserve(page.len())
                .map_err(|_| MemoryError::MetadataAllocation)?;
            bytes.extend(page);
        }
        Ok(bytes)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let ceiling =
            carrick_hal::guest_arch::UserVaCeiling::for_abi(carrick_abi::LinuxGuestAbi::X86_64)
                .exclusive_end();
        if !bytes.is_empty()
            && (address >= ceiling
                || address
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > ceiling))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        let root = self.execution.context.root;
        let mut written = 0;
        while written < bytes.len() {
            let va = address
                .checked_add(written as u64)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })?;
            let leaf = translate_leaf(
                &self.custody._vm.words(),
                root,
                UserVa::new(va),
                Access::Write,
                true,
            )
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: bytes.len(),
            })?;
            self.authenticate_initial_copy_page(leaf.output, va)?;
            let count = ((4096 - (va & 4095)) as usize).min(bytes.len() - written);
            self.custody
                ._vm
                .write(leaf.output, &bytes[written..written + count])
                .map_err(|_| MemoryError::OutOfBounds {
                    address: va,
                    length: bytes.len(),
                })?;
            written += count;
        }
        Ok(())
    }
}

impl CurrentMmMemory for ForwardVenue<'_> {}

impl carrick_hal::x8664_arch::SegmentBaseRegs for ForwardVenue<'_> {
    fn seg_set_fs_base(&mut self, address: u64) -> Result<(), TrapError> {
        let mut sregs = self
            .lease
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|error| fail(format!("KVM_GET_SREGS(fs): {error}")))?;
        sregs.fs.base = address;
        self.lease
            .vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|error| fail(format!("KVM_SET_SREGS(fs): {error}")))
    }

    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.lease
            .vcpu
            .fd()
            .get_sregs()
            .map(|sregs| sregs.fs.base)
            .map_err(|error| fail(format!("KVM_GET_SREGS(fs): {error}")))
    }

    fn seg_set_gs_base(&mut self, address: u64) -> Result<(), TrapError> {
        // FORWARD_PORT stops after SYSCALL's SWAPGS: GS is the kernel CPU
        // binding and KERNEL_GS_BASE holds the user's value until IRET swaps
        // them back. Never replace the live supervisor GS binding here.
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        let msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: KERNEL_GS_BASE,
            data: address,
            ..Default::default()
        }])
        .map_err(|error| fail(format!("KERNEL_GS_BASE entry: {error}")))?;
        let written = self
            .lease
            .vcpu
            .fd()
            .set_msrs(&msrs)
            .map_err(|error| fail(format!("KVM_SET_MSRS(gs): {error}")))?;
        if written != 1 {
            return Err(fail("KVM_SET_MSRS(gs) refused entry"));
        }
        Ok(())
    }

    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        self.lease.vcpu.read_msr(KERNEL_GS_BASE)
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

#[cfg(test)]
mod initial_reply_tests {
    use super::*;

    #[test]
    fn unwind_rollback_refusal_returns_control_to_the_carrier_observer() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (inventory, _) = InitialInventory::stage(
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
        )
        .unwrap();
        authority
            .rollback_unpublished_apply(inventory.receipt.as_ref().unwrap())
            .unwrap();
        let fault = Arc::clone(&inventory.rollback_fault);
        drop(inventory);
        assert!(fault.load(Ordering::Acquire));
        // The carrier observer, rather than this destructor, chooses the
        // existing fail-stop transport after all owned custody is unwound.
    }

    #[test]
    fn refused_initial_rollback_retains_the_exact_physical_receipt() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (mut inventory, _) = InitialInventory::stage(
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
        )
        .unwrap();
        // Another exact retirement makes this rollback refuse; failure must
        // retain the receipt rather than silently consuming physical custody.
        authority
            .rollback_unpublished_apply(inventory.receipt.as_ref().unwrap())
            .unwrap();
        assert!(inventory.rollback().is_err());
        assert!(
            inventory.receipt.is_some(),
            "failed rollback consumed its physical receipt"
        );
        // The fixture itself performed retirement above; no live mapping or
        // unresolved physical custody remains to retry when it leaves scope.
        inventory.receipt = None;
    }

    #[test]
    fn inventory_retains_two_live_owner_selected_mms() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let owners = [INITIAL_MM_KEY, INITIAL_MM_KEY + 1];
        let mut staged = Vec::new();
        for (index, owner) in owners.into_iter().enumerate() {
            let mm = MmId::from_raw_u64(owner).unwrap();
            let (mut inventory, _) = InitialInventory::stage(
                authority.physical_projection(Arc::clone(&ids)),
                [FrameGpa::new(0x2_0000_0000 + index as u64 * 4096)],
                0,
                4096,
                NonZeroU64::MIN,
                MmGeneration::new(NonZeroU64::new(mm.raw()).unwrap()),
            )
            .expect("owner-selected inventory");
            assert_eq!(
                inventory.receipt.as_ref().unwrap().mm().get(),
                mm.raw(),
                "stage-2 inventory must retain the selected MM, not the initial MM"
            );
            inventory.publish().expect("exact MM inventory publication");
            staged.push(inventory);
        }
        assert_ne!(
            staged[0].frames[0].1.mapping_id,
            staged[1].frames[0].1.mapping_id
        );
        assert_ne!(staged[0].frames[0].0, staged[1].frames[0].0);
        for inventory in &mut staged {
            inventory.rollback().unwrap();
        }
    }

    #[test]
    fn initial_inventory_refuses_a_receipt_from_another_mm() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (mut inventory, _) = InitialInventory::stage(
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM")),
        )
        .expect("initial MM inventory");
        inventory.rollback().expect("original custody rollback");
        let mut reservation = authority
            .reserve(&ids, 1, 1, FrameEventCapacity::for_event_count(2).unwrap())
            .expect("foreign MM transaction");
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation = MappingGeneration::from_backend_counter(NonZeroU64::MIN);
        reservation
            .push(FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: carrick_guest_mem::Gpa(0x2_0000_1000),
                length: inventory.length,
                permissions: MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .unwrap();
        let foreign = carrick_hal::UnpublishedFrameInventoryApply::apply(
            authority.physical_projection(Arc::clone(&ids)).bind(
                carrick_guest_arch::MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY + 1).unwrap()),
            ),
            reservation.commit(()),
        )
        .expect("foreign MM receipt");
        // Settle the original unpublished receipt independently, then replace
        // only the receipt. The MM refusal must precede frame authentication.
        inventory.receipt = Some(foreign);
        assert_eq!(inventory.publish().unwrap_err().0, "inventory MM mismatch");
    }

    #[test]
    fn initial_inventory_refuses_a_grant_with_a_different_gpa() {
        let (mut inventory, _) = InitialInventory::stage(
            Arc::new(FrameInventoryAuthority::new())
                .physical_projection(Arc::new(ObjectIdRegistry::new())),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM")),
        )
        .expect("fresh exact inventory grant");
        inventory.frames[0].0 = FrameGpa::new(0x2_0000_1000);
        assert!(
            inventory.publish().is_err(),
            "a mapping/frame pair does not authorize another GPA"
        );
    }

    #[test]
    fn unverified_guest_completion_keeps_inventory_custody_until_vm_teardown() {
        for exposed in [false, true] {
            let authority = Arc::new(FrameInventoryAuthority::new());
            let (mut inventory, _) = InitialInventory::stage(
                authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
                [FrameGpa::new(0x2_0000_0000)],
                0,
                4096,
                NonZeroU64::MIN,
                MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM")),
            )
            .expect("fresh physical grant");
            inventory.guest_exposed = exposed;
            if exposed {
                assert!(
                    inventory.rollback().is_err(),
                    "unverified completion cannot authorize rollback"
                );
            }
            drop(inventory);
            assert_eq!(authority.snapshot().mappings.len(), usize::from(exposed));
        }
    }

    #[test]
    fn initial_inventory_publishes_data_frames_without_table_grants() {
        let base = INITIAL_EXTENT_GPA + 0x20_000;
        let authority = Arc::new(FrameInventoryAuthority::new());
        let (inventory, grants) = InitialInventory::stage(
            authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
            (0..4).map(|index| FrameGpa::new(base + index * 4096)),
            2,
            4096,
            NonZeroU64::MIN,
            MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM")),
        )
        .expect("staged exact grants");
        assert_eq!(grants.len(), 4);
        assert_eq!(inventory.frames.len(), 2);
        let rows = authority.snapshot().mappings;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].gpa.0, grants[2].gpa);
        assert_eq!(rows[1].gpa.0, grants[3].gpa);
    }

    #[test]
    fn corrupted_guest_reply_cannot_change_host_grant_or_stack_geometry() {
        let request = X86InitialBootRequest {
            magic: X86_INITIAL_BOOT_MAGIC,
            version: X86_INITIAL_BOOT_VERSION,
            table_grant_count: 5,
            data_grant_count: 2,
            publication_capacity: 2,
            publications_gpa: INITIAL_EXTENT_GPA + 4096,
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
            mm_key: INITIAL_MM_KEY,
            generation: 1,
            ..Default::default()
        };
        let valid = X86InitialBootRequest {
            result_status: X86_INITIAL_BOOT_LOADED,
            publication_count: 2,
            result_data_used: 2,
            result_table_used: 2,
            result_root_gpa: INITIAL_EXTENT_GPA + 0x2000,
            result_initial_break: 0x401000,
            result_rsp: INITIAL_STACK_TOP - 16,
            ..request
        };
        assert!(
            validate_initial_reply(&request, &valid, 7, valid.result_root_gpa, 0x401000).is_ok()
        );
        for corrupted in [
            X86InitialBootRequest {
                table_grant_count: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publication_capacity: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publications_gpa: u64::MAX,
                ..valid
            },
            X86InitialBootRequest {
                stack_top: 0,
                ..valid
            },
            X86InitialBootRequest {
                stack_size: u64::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publication_count: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                result_table_used: u32::MAX,
                ..valid
            },
        ] {
            assert!(
                validate_initial_reply(&request, &corrupted, 7, valid.result_root_gpa, 0x401000)
                    .is_err(),
                "accepted corrupted guest reply: {corrupted:?}"
            );
        }
    }
}

#[derive(::core::fmt::Debug)]
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
    pub parked_parent_result: u64,
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
                    .custody
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
                .custody
                ._vm
                .write(
                    FrameGpa::new(LIFECYCLE_DATA + index as u64 * 4096 + 0x180),
                    &[0x5a + index as u8; 16],
                )
                .map_err(|e| fail(e.to_string()))?;
            carrier
                .custody
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
                .custody
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
            .custody
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
            forwards: self.custody.host_forwards,
            words,
            parked_parent_result: lane.contexts[0].frame.rax,
        })
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
                .ram
                .host_ptr(0x100_0000, size_of::<ZoneTables>())
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
                .ram
                .host_ptr(0x100_0000, size_of::<ZoneTables>())
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        let identity = ThreadIdentity {
            tid: 1000,
            serial: 1,
            mm: 1000,
            file_table: 1,
            generation: 1,
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
                .ram
                .host_ptr(0x100_0000, size_of::<ZoneTables>())
                .ok_or_else(|| fail("lifecycle zone"))?
                .cast::<ZoneTables>()
        };
        let identity = ThreadIdentity {
            tid: 1001,
            serial: 1,
            mm: 1001,
            file_table: 1,
            generation: 1,
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

    /// Break only the stopped fault-policy counters venue to force a nested
    /// supervisor #PF after the next user fault acquired per-CPU custody.
    pub fn invalidate_user_fault_counters_venue(&mut self) -> Result<(), TrapError> {
        let address =
            META_GPA + BINDING_OFFSET + core::mem::offset_of!(CpuBinding, counters_address) as u64;
        self.custody
            ._vm
            .write(
                FrameGpa::new(address),
                &0xffff_dead_0000_0000_u64.to_le_bytes(),
            )
            .map_err(|error| fail(error.to_string()))
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
                ._vm
                .read(FrameGpa::new(frame - DIRECT_VA + 120), 16)
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
            ._vm
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
                ._vm
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
                ._vm
                .read(FrameGpa::new(address), 64)
                .map_err(|e| fail(e.to_string()))?;
            if bytes != [0xa5; 64] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A guest exception is an owned process outcome, separate from carrier failure.
#[derive(::core::fmt::Debug)]
pub enum InitialProcessExit {
    Exited {
        code: i32,
        exits: usize,
    },
    Fault {
        record: carrick_x86::FaultDoorbellRecord,
        exits: usize,
    },
}

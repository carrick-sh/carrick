//! Shared CPL0 carrier and its retained guest-MM/metadata backing.
//! Hardware fixtures and the initial production process use the same image;
//! fixture observation ports remain separate from the production transport.
use crate::carrier_cpu::FixtureWatchdog;
use crate::carrier_cpu::{CarrierCpu, CarrierCpuDebug, CarrierCpuIo, CarrierRunExit};
use crate::carrier_memory::{
    BackingExtent, BackingHandle, CarrierMemory, CarrierMemoryIo, InventoryTransaction,
    PreparedBacking,
};
use crate::guest_ram::GuestRam;
use carrick_core_abi::X86_CPL0_INITIAL_EXTENT_GPA;
use carrick_core_abi::{X86_INITIAL_BOOT_LOADED, X86InitialBootGrant, X86InitialBootRequest};
use carrick_el1::memory::reservations::{LinuxReservationLayout, X86Cpl0Reservations, X86Cpl0Zone};
use carrick_el1_abi::GuestMmuPublication;
use carrick_el1_abi::{
    Counters, CurrentTask, EL1_BOOTSTRAP_METADATA_SIZE, El1TaskId, ThreadControlSlot,
    ThreadLifecyclePage, X86_CPL0_BOOTSTRAP_METADATA_BASE, X86_CPL0_DYNAMIC_METADATA_BASE,
    X86_CPL0_REGION_BASE,
};
use carrick_el1_abi::{ReservationMm, ReservationRange};
use carrick_guest_arch::FrameGpa;
use carrick_guest_arch::{AddressContext, ContextGeneration, MmGeneration, RootGpa, UserVa};
use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
use carrick_hal::TrapError;
use carrick_hal::{FrameCowAuthority, PhysicalFrameInventory};
#[cfg(test)]
use carrick_hal::{FrameEventCapacity, FrameInventoryEvent, MemPerms};
use carrick_hal::{FrameId, FrameLength, MappingGeneration, MappingId};
#[cfg(test)]
use carrick_kernel::kernel::{FrameInventoryAuthority, MmId, ObjectIdRegistry};
use carrick_mmu_core::x86::descriptor_txn::{
    Access, BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, translate_leaf,
};
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{SlotId, Waker};
use carrick_x86::cpl0_entry::*;
use carrick_x86::{BringupLayout, X86Reg};
use std::num::NonZeroU64;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

pub const RAM_SIZE: usize = 16 * 1024 * 1024;
pub const META_GPA: u64 = 0xc0_0000;
pub const META_LEN: u64 = 0x10_0000;
pub const PRODUCTION_METADATA_GPA: u64 = META_GPA;
pub const ALLOCATOR_GPA: u64 = 0x20_00000;
pub const INITIAL_EXTENT_GPA: u64 = X86_CPL0_INITIAL_EXTENT_GPA;
pub const KERNEL_REGION_GPA: u64 = 0x1_0000_0000;
pub const INITIAL_MM_KEY: u64 = 301;
pub const INITIAL_STACK_TOP: u64 = 0x7fff_0000;
pub const INITIAL_STACK_SIZE: u64 = 0x1_0000;
// Place mmap at the next boundary after the image, preserving low-image space.
pub const INITIAL_ARENA_ALIGNMENT: u64 = 1024 * 1024 * 1024;
pub const COUNTERS_OFFSET: u64 = 0x1_0000;
pub const BINDING_OFFSET: u64 = 0x8000;
pub const TASK_OFFSET: u64 = 0x9000;
pub const CONTROL_OFFSET: u64 = 0xa000;
pub const ROUTES_OFFSET: u64 = 0xd000;
pub const SHOOTDOWN_OFFSET: u64 = 0xe000;
pub const STRIDE: u64 = 0x100;
const _: () = {
    assert!(INITIAL_ARENA_ALIGNMENT.is_power_of_two());
    assert!(INITIAL_ARENA_ALIGNMENT.is_multiple_of(4096));
    assert!(size_of::<CpuBinding>() <= STRIDE as usize);
    assert!(ROUTES_OFFSET >= 0xc000 + 9 * size_of::<ThreadControlSlot>() as u64);
    assert!(ROUTES_OFFSET + size_of::<PublishedApicIds>() as u64 <= SHOOTDOWN_OFFSET);
    assert!(SHOOTDOWN_OFFSET + size_of::<ShootdownTable>() as u64 <= COUNTERS_OFFSET);
    assert!(
        carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
            <= META_LEN
    );
};
pub const IST_STACK_BASE: u64 = 0xf0_0000;
pub const IMAGE_VA: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_BASE;
pub const IMAGE_SIZE: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE;
pub const IMAGE_GPA: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA;
pub const METADATA_VA: u64 = X86_CPL0_DYNAMIC_METADATA_BASE;
// Fork lifecycle stock: each 16 KiB slot holds a lifecycle page and, 4 KiB
// above it, the thread control slots. More records than CPUs keep a parent's
// fork from racing a reaped child that has not yet left its slot.
pub const FORK_LIFECYCLE_OFFSET: u64 = 0x8_8000;
pub const FORK_LIFECYCLE_STRIDE: u64 = carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE;
pub const FORK_LIFECYCLE_SLOTS: u64 = 8;
const _: () = {
    assert!(
        carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
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
pub use carrick_x86::cpl0_entry::DIRECT_VA;
// Startup stocks one initial MM and its first fork child's private COW branch.
// Later population admission remains bounded by actual available table grants.
const fn initial_copy_branch_table_credits() -> usize {
    2 * carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES
}
/// The carrier's maintenance root is one dedicated initial table grant. It
/// is counted on top of the copy-branch credits so taking it never shrinks
/// the fork table stock the first fork was sized against.
pub const MAINTENANCE_ROOT_TABLE_CREDITS: usize = 1;
const fn initial_carrier_table_credits() -> usize {
    initial_copy_branch_table_credits() + MAINTENANCE_ROOT_TABLE_CREDITS
}
/// Initial table grants for `data_pages` user pages: the initial MM's worst
/// case (three tables per page plus its root) and the carrier credits.
pub const fn initial_table_grant_count(data_pages: usize) -> Option<usize> {
    let Some(tables) = data_pages.checked_mul(3) else {
        return None;
    };
    let Some(tables) = tables.checked_add(1) else {
        return None;
    };
    tables.checked_add(initial_carrier_table_credits())
}

/// Fixed physical base of the initial GDT (0x50_0000), immediately following the
/// 1 MiB fixture process lane tables (0x30_0000..0x40_0000) and data (0x40_0000..0x50_0000).
pub const GDT_BASE: u64 = 0x50_0000;
/// Fixed physical base of the shared PML4 page-table pool and initial boot root (0x60_0000).
/// Fixed by contract across the hardware carrier, carrick-x86 bringup, and CPL0 supervisor:
/// - Initial boot CR3 is 0x60_0000.
/// - The pool occupies `carrick_x86::X86_PML4_CAPACITY` bytes (0x1c_0000 bytes, 0x60_0000..0x7c_0000),
///   followed by fault structures (IDT, stubs, TSS, stack, records) spanning 0x7c_0000..0x81_0000.
/// - Compile-time assertion `LAYOUT.gdt_base < LAYOUT.pml4_base` strictly prevents any future
///   image extent expansion from silently overlapping this fixed root pool.
pub const PML4_BASE: u64 = 0x60_0000;

pub const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: IMAGE_GPA,
    gdt_base: GDT_BASE,
    pml4_base: PML4_BASE,
};
const _: () = {
    assert!(IMAGE_GPA.is_multiple_of(4096));
    assert!(IMAGE_SIZE.is_multiple_of(4096));
    assert!(IMAGE_GPA + IMAGE_SIZE <= 0x30_0000);
    assert!(IMAGE_GPA + IMAGE_SIZE <= LAYOUT.gdt_base);
    assert!(LAYOUT.gdt_base.is_multiple_of(4096));
    assert!(LAYOUT.gdt_base < LAYOUT.pml4_base);
    assert!(LAYOUT.pml4_base.is_multiple_of(4096));
    assert!(LAYOUT.pml4_base + carrick_x86::X86_PML4_CAPACITY as u64 <= META_GPA);
};
const _: () = assert!(FIXTURE_PML4_CAPACITY == carrick_x86::X86_PML4_CAPACITY);

/// Guest-physical address of initial frame grant `index`: grants follow
/// the staged boot records, page aligned, inside the initial extent. The
/// first unused table grant becomes the carrier's maintenance root.
pub fn initial_grant_gpa(frame_offset: usize, index: usize) -> FrameGpa {
    FrameGpa::new(INITIAL_EXTENT_GPA + (frame_offset + index * 4096) as u64)
}

pub fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum FixtureCpuidError {
    MissingLeafZero,
    FullTable,
}

pub const MAX_CPUID_ENTRIES: usize = 256;

#[repr(C)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::default::Default,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

// The fixture uses CPUID only for the native CPU features admitted at boot,
// APIC topology, XSAVE x87/SSE/AVX, and the optional clock source.
pub fn fixture_cpuid_leaf(entry: &CpuidEntry) -> bool {
    match entry.function {
        0 | 1 | 0x8000_0000 | 0x8000_0001 | 0x8000_0007 | 0x8000_0008 => true,
        0x15 => entry.index == 0,
        7 => entry.index == 0, // SMEP, SMAP and native feature admission.
        0xb | 0x1f => entry.index <= 2, // APIC topology for the two CPUs.
        0xd => entry.index <= 2, // XCR0=x87|SSE|AVX, including XSAVE size.
        _ => false,
    }
}

pub fn fixture_cpuid_with_tsc_hz(
    entries: &mut Vec<CpuidEntry>,
    hz: u32,
) -> Result<(), FixtureCpuidError> {
    let mut selected: Vec<_> = entries.iter().copied().filter(fixture_cpuid_leaf).collect();
    let leaf0 = selected
        .iter()
        .position(|entry| entry.function == 0)
        .ok_or(FixtureCpuidError::MissingLeafZero)?;
    let existing = selected.iter().position(|entry| entry.function == 0x15);
    if existing.is_none() && selected.len() >= MAX_CPUID_ENTRIES {
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
        selected[vacant] = CpuidEntry {
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
    let clock = CpuidEntry {
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
/// Authenticated terminal outcome from a stopped production CPU.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PhysicalProcessExit {
    Exited(carrick_sched_core::process::TerminationStatus),
    RunFailed(carrick_core_abi::NativeRunFailureReason),
}

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
    RunFailure,
}
impl PhysicalCrossingFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerGrant => "owner_grant",
            Self::RootExit => "root_exit",
            Self::ChildRetire => "child_retire",
            Self::RunFailure => "run_failure",
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

pub fn initial_reservation_layout(
    initial_break: UserVa,
    stack_top: UserVa,
    limits: InitialReservationLimits,
) -> Result<LinuxReservationLayout, TrapError> {
    let stack_base = stack_top
        .raw()
        .checked_sub(INITIAL_STACK_SIZE)
        .filter(|_| stack_top.raw() <= carrick_guest_arch::USER_CEILING)
        .ok_or_else(|| fail("initial stack layout"))?;
    let stack = ReservationRange::new(stack_base, stack_top.raw())
        .ok_or_else(|| fail("initial stack layout"))?;
    // The authenticated break is the highest page-rounded PT_LOAD end. A
    // static PIE can sit above the low initial stack, so neither reservation
    // may depend on a fixed split address or assume the stack is above it.
    let ceiling = if initial_break.raw() <= stack.start() {
        stack.start()
    } else if initial_break.raw() >= stack.end() {
        carrick_guest_arch::USER_CEILING
    } else {
        return Err(fail("initial heap overlaps stack"));
    };
    // Keep at least one page for mmap when the stack/user boundary clips the
    // heap capacity. Neither hidden reservation allocates physical backing.
    let heap_ceiling = ceiling
        .checked_sub(4096)
        .ok_or_else(|| fail("initial heap layout"))?;
    let arena_start = initial_break
        .raw()
        .checked_add(INITIAL_ARENA_ALIGNMENT)
        .map(|end| end & !(INITIAL_ARENA_ALIGNMENT - 1))
        .map(|end| end.min(heap_ceiling))
        .ok_or_else(|| fail("initial heap layout"))?;
    let heap = ReservationRange::new(initial_break.raw(), arena_start)
        .ok_or_else(|| fail("initial heap layout"))?;
    let arena_end = arena_start
        .checked_add(carrick_mem::memory::LINUX_MMAP_SIZE)
        .ok_or_else(|| fail("initial mmap arena overflow"))?
        .min(ceiling);
    let arena = ReservationRange::new(arena_start, arena_end)
        .ok_or_else(|| fail("initial mmap arena layout"))?;
    Ok(LinuxReservationLayout {
        heap,
        arena,
        brk: initial_break.raw(),
        address_limit: limits.address.rlim_cur,
        data_limit: limits.data.rlim_cur,
        external_address_bytes: 0,
        external_data_bytes: 0,
    })
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

pub fn backing_identity(ids: &dyn PhysicalFrameInventory) -> Result<BackingIdentity, TrapError> {
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
pub fn validate_initial_reply(
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
        || reply.executable_entry != request.executable_entry
        || reply.interpreter_base != request.interpreter_base
        || reply.executable_region_count != request.executable_region_count
        || reply.reserved != request.reserved
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

pub fn initial_stack_pages(
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    argv: &[String],
    env: &[String],
) -> Result<usize, TrapError> {
    use carrick_el1::isa::x86_initial_mm::{InitialStackSpec, build_initial_stack};
    let argv_bytes: Vec<&[u8]> = argv.iter().map(|value| value.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|value| value.as_bytes()).collect();
    let _stack = build_initial_stack(&InitialStackSpec {
        entry: image.executable_entry,
        interpreter_base: image.interpreter_base,
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
    // The guest owner backs the configured bootstrap stack, including its
    // zero prefix. Serialization still copies only the initialized tail.
    Ok((INITIAL_STACK_SIZE / 4096) as usize)
}

pub fn record_bytes<T: Copy>(record: &T) -> &[u8] {
    // SAFETY: every caller passes a fully initialized fixed-layout ABI
    // record; its storage remains live for the returned borrow.
    unsafe { core::slice::from_raw_parts((record as *const T).cast::<u8>(), size_of::<T>()) }
}

pub fn append_records<T: Copy>(buffer: &mut Vec<u8>, records: &[T]) -> Result<u64, TrapError> {
    let offset = u64::try_from(buffer.len()).map_err(|_| fail("initial metadata offset"))?;
    for record in records {
        buffer.extend_from_slice(record_bytes(record));
    }
    INITIAL_EXTENT_GPA
        .checked_add(offset)
        .ok_or_else(|| fail("initial metadata address"))
}

pub struct InitialInventory {
    mm: MmGeneration,
    source: Arc<dyn PhysicalFrameInventory>,
    authority: Arc<dyn FrameCowAuthority>,
    receipt: Option<carrick_hal::UnpublishedFrameInventoryApply<dyn FrameCowAuthority>>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    length: FrameLength,
    expected: usize,
    committed: usize,
    guest_exposed: bool,
    rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
}
impl InitialInventory {
    pub fn frames(&self) -> &[(FrameGpa, BackingIdentity)] {
        &self.frames
    }
    pub fn expect_publications(&mut self, count: usize) {
        self.expected = count;
    }
    pub fn guest_exposed(&self) -> bool {
        self.guest_exposed
    }

    pub fn stage(
        rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner_generation: NonZeroU64,
        owner: carrick_hal::GuestFrameOwner,
    ) -> Result<(Self, Vec<X86InitialBootGrant>), TrapError> {
        let mm = owner.native_mm;
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            Arc::clone(&rollback_fault),
            Arc::clone(&source),
            gpas,
            table_grants,
            frame_len,
            owner_generation,
            owner,
        )?
        .handoff()?;
        let grants = staged
            .grants
            .into_iter()
            .map(|grant| X86InitialBootGrant {
                gpa: grant.gpa.raw(),
                frame_id: grant.identity.frame_id.get(),
                mapping_id: grant.identity.mapping_id.get(),
                owner_generation: grant.identity.owner_generation.get(),
                inventory_revision: grant.identity.inventory_revision.get(),
            })
            .collect();
        let authority = staged.authority;
        let receipt = staged.receipt;
        let frames = staged.frames;
        let length = staged.length;
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
                rollback_fault,
            },
            grants,
        ))
    }

    pub fn finish(&mut self) -> Result<(), TrapError> {
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
                        carrick_guest_mem::Gpa::new(gpa.raw()),
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
        if self.receipt.is_some()
            && !self.guest_exposed
            && self.rollback().is_err()
            && let Some(receipt) = self.receipt.take()
        {
            self.rollback_fault.retain(receipt);
        }
    }
}

#[cfg(test)]
mod fixture_cpuid_tests {
    use super::*;

    #[test]
    fn full_cpuid_fixture_reuses_only_an_exact_zero_duplicate_of_leaf_zero() {
        let mut entries = vec![CpuidEntry::default(); MAX_CPUID_ENTRIES];
        entries[0].eax = 0x10;
        entries[1].function = 7;
        entries[1].ebx = (1 << 7) | (1 << 20);
        let features = entries[1];
        fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000).expect("vacant duplicate reused");
        assert_eq!(entries.len(), MAX_CPUID_ENTRIES);
        assert_eq!(entries[0].eax, 0x15);
        assert_eq!(entries[1].ebx, features.ebx);
        assert_eq!(entries[2].function, 0x15);
        assert_eq!(entries[2].ecx, 2_000_000_000);
    }

    #[test]
    fn eighty_supported_leaves_leave_room_for_fixture_tsc() {
        let mut entries = vec![CpuidEntry {
            function: 0,
            eax: 0x16,
            ..Default::default()
        }];
        entries.extend(
            [1, 7, 0xd, 0x8000_0000, 0x8000_0001, 0x8000_0008].map(|function| CpuidEntry {
                function,
                ..Default::default()
            }),
        );
        entries.extend((entries.len()..80).map(|index| CpuidEntry {
            function: 0x100 + index as u32,
            ..Default::default()
        }));
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
        let mut entries = (0..MAX_CPUID_ENTRIES)
            .map(|index| CpuidEntry {
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
    fn full_cpuid_table_reuses_its_existing_tsc_leaf() {
        let mut entries = vec![CpuidEntry {
            function: 0,
            eax: 7,
            ..Default::default()
        }];
        entries.extend((1..MAX_CPUID_ENTRIES).map(|index| CpuidEntry {
            function: if index == 17 {
                0x15
            } else {
                0x100 + index as u32
            },
            ..Default::default()
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
pub mod anonymous_owner;

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ForwardBindingRefusal {
    ContextMismatch,
    GenerationMismatch,
    TaskIdMismatch {
        stopped: carrick_el1_abi::EntryTaskKey,
        expected: carrick_el1_abi::EntryTaskKey,
    },
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
struct ForwardExecution {
    cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    leader_task: carrick_el1_abi::EntryTaskKey,
    context: AddressContext<RootGpa>,
}

impl ForwardExecution {
    /// Authenticate the CR3-registered carrier binding against the execution
    /// the stopped CPU's own lifecycle record names: the address context, the
    /// execution generation, and the process leader task key must match. A
    /// `CLONE_VM` sibling sharing the root's `CR3` and `INITIAL` generation has
    /// a distinct stopped `binding.task` from `leader_task` and is refused.
    fn authenticate_typed(
        &self,
        binding: carrick_hal::guest_arch_binding::GuestArchBinding,
    ) -> Result<(), ForwardBindingRefusal> {
        if binding.context() != self.context {
            return Err(ForwardBindingRefusal::ContextMismatch);
        }
        if binding.task().execution.raw().get() != self.binding.generation.raw() {
            return Err(ForwardBindingRefusal::GenerationMismatch);
        }
        if self.binding.task != self.leader_task {
            return Err(ForwardBindingRefusal::TaskIdMismatch {
                stopped: self.binding.task,
                expected: self.leader_task,
            });
        }
        Ok(())
    }

    fn with_leader_task(mut self, leader_task: carrick_el1_abi::EntryTaskKey) -> Self {
        self.leader_task = leader_task;
        self
    }

    fn authenticate(
        &self,
        binding: carrick_hal::guest_arch_binding::GuestArchBinding,
        refusal: &str,
    ) -> Result<(), TrapError> {
        self.authenticate_typed(binding)
            .map_err(|reason| fail(format!("{refusal}: {reason:?}")))
    }
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
        leader_task: binding.task,
        context,
    })
}

#[cfg(test)]
mod design_doc_tests {
    /// The design doc's x86 live-children limit is this stock's layout.
    #[test]
    fn design_doc_names_the_carrier_lifecycle_record_count_and_offset() {
        let doc = include_str!("../../../docs/design/arm-fork-stock-crossing.md");
        let text = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        let claim = format!(
            "x86 CPL0 has **{} records** at metadata offset `{:#x}`",
            super::FORK_LIFECYCLE_SLOTS,
            super::FORK_LIFECYCLE_OFFSET,
        );
        assert!(text.contains(&claim), "doc must say: {claim}");
    }
}

#[cfg(test)]
mod forward_execution_tests {
    use super::*;

    fn execution() -> (carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>) {
        (
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(42),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(12),
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
        assert_eq!(admitted.leader_task, binding.task);
        assert_eq!(admitted.context, context);
    }

    fn carrier_binding(
        context: AddressContext<RootGpa>,
        execution: u64,
    ) -> carrick_hal::guest_arch_binding::GuestArchBinding {
        carrick_hal::guest_arch_binding::GuestArchBinding::x86(
            carrick_guest_arch::TaskIdentity {
                carrier: carrick_guest_arch::CarrierGeneration::new(
                    NonZeroU64::new(5).expect("carrier"),
                ),
                task: carrick_guest_arch::TaskSerial::new(NonZeroU64::new(77).expect("serial")),
                execution: carrick_guest_arch::ExecutionGeneration::new(
                    NonZeroU64::new(execution).expect("execution"),
                ),
            },
            context,
        )
    }

    /// Every forward phase (idle-peer identity, capture, completion) admits a
    /// CR3-registered binding through this one comparison; a binding whose
    /// address context or execution generation names another issue of the
    /// task, or a `CLONE_VM` sibling sharing the root's CR3 and generation,
    /// must not be served as the stopped execution.
    #[test]
    fn forward_binding_authentication_requires_exact_context_generation_and_task_id() {
        let (binding, context) = execution();
        let cpu = carrick_guest_arch::CpuId::new(1);
        let admitted =
            admit_forward_execution(cpu, cpu, binding, context, context.root, context.generation)
                .expect("exact lane1 owner");
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(context, 12)),
            Ok(())
        );
        admitted
            .authenticate(carrier_binding(context, 12), "exact")
            .expect("exact binding");
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(context, 13)),
            Err(ForwardBindingRefusal::GenerationMismatch)
        );
        assert!(
            admitted
                .authenticate(carrier_binding(context, 13), "stale generation")
                .is_err()
        );
        let other_root = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).expect("aligned root"),
            ..context
        };
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(other_root, 12)),
            Err(ForwardBindingRefusal::ContextMismatch)
        );
        assert!(
            admitted
                .authenticate(carrier_binding(other_root, 12), "other root")
                .is_err()
        );
        let other_incarnation = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(8).expect("incarnation")),
            ..context
        };
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(other_incarnation, 12)),
            Err(ForwardBindingRefusal::ContextMismatch)
        );
        assert!(
            admitted
                .authenticate(carrier_binding(other_incarnation, 12), "other incarnation")
                .is_err()
        );
        // Ruling 4 thread clause: a CLONE_VM sibling sharing root CR3 + INITIAL
        // generation has a distinct stopped task key from the leader's task key.
        let sibling_binding = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(43),
            ..binding
        };
        let sibling_admitted = admit_forward_execution(
            cpu,
            cpu,
            sibling_binding,
            context,
            context.root,
            context.generation,
        )
        .expect("admitted stopped execution")
        .with_leader_task(binding.task);
        assert_eq!(
            sibling_admitted.authenticate_typed(carrier_binding(context, 12)),
            Err(ForwardBindingRefusal::TaskIdMismatch {
                stopped: carrick_el1_abi::EntryTaskKey::from_raw(43),
                expected: carrick_el1_abi::EntryTaskKey::from_raw(42),
            })
        );
        let err = sibling_admitted
            .authenticate(
                carrier_binding(context, 12),
                "idle peer forward binding mismatch",
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("TaskIdMismatch"),
            "unexpected error: {err:?}"
        );
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

/// Stopped production CPUs after the bootstrap I/O receipts are complete.
/// Field order keeps both CPU handles ahead of retained physical backing.
pub struct ProductionWorkerParts<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    cpus: [CarrierCpu<M>; 2],
    custody: Cpl0HostCustody<Mem>,
    root_state: carrick_x86::arch_context::X86ArchContext,
}

/// Physical CPUs are claimed once by executor workers. Shared host custody
/// outlives every claimed CPU and is only entered for stopped host service.
pub struct ProductionCpuFactory<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    cpus: std::sync::Mutex<[Option<CarrierCpu<M>>; 2]>,
    custody: Arc<std::sync::Mutex<Cpl0HostCustody<Mem>>>,
    debug_cpus: [Arc<CarrierCpuDebug>; 2],
}

/// Bounded physical observations owned by the carrier.
pub struct ProductionPhysicalCapture {
    pub zone_census: String,
    pub vcpus: Vec<String>,
    pub unavailable: Vec<String>,
}

pub struct ProductionCpuLease<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    cpu: CarrierCpu<M>,
    _custody: Arc<std::sync::Mutex<Cpl0HostCustody<Mem>>>,
}
/// A forwarded frame copied out of a physical CPU's private CPL0 stack.
/// Another task may reuse that stack while this one waits; the frame is
/// restored only after its exact task and MM binding is loaded again.
pub struct ProductionForwardFrame {
    task: carrick_guest_arch::TaskIdentity,
    slot: carrick_guest_arch::CpuId,
    address: u64,
    execution: ForwardExecution,
    frame: NativeFrame,
}

/// Bytes still reachable from a stopped task's CPL0 RSP. The physical stack
/// may be reused after the task releases its executor; its call chain belongs
/// to the task until it is reloaded on the same physical slot.
pub struct KernelStackSnapshot {
    slot: carrick_guest_arch::CpuId,
    start: u64,
    end: u64,
    bytes: Box<[u8]>,
}

impl KernelStackSnapshot {
    /// # Safety
    /// `source` must point to a stopped, readable mapping of `[base, end)`.
    unsafe fn capture(
        source: *const u8,
        base: u64,
        end: u64,
        rsp: u64,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<Self, TrapError> {
        if rsp < base {
            return Err(fail("CPL0 RSP below private stack"));
        }
        let len = usize::try_from(
            end.checked_sub(rsp)
                .ok_or_else(|| fail("CPL0 RSP beyond stack"))?,
        )
        .map_err(|_| fail("CPL0 stack length overflow"))?;
        if len == 0 || len > 0x1_0000 {
            return Err(fail("CPL0 RSP outside private stack"));
        }
        let offset = usize::try_from(rsp - base).map_err(|_| fail("CPL0 stack offset overflow"))?;
        let mut bytes = vec![0u8; len];
        // SAFETY: caller guarantees stopped guest memory; `bytes` is an owned
        // allocation, never a mutable reference into guest RAM.
        unsafe { std::ptr::copy_nonoverlapping(source.add(offset), bytes.as_mut_ptr(), len) };
        Ok(Self {
            slot,
            start: rsp,
            end,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// # Safety
    /// `destination` must point to the same stopped writable stack mapping.
    unsafe fn restore(
        &self,
        destination: *mut u8,
        base: u64,
        end: u64,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        if self.slot != slot || self.end != end || self.start < base {
            return Err(fail("CPL0 stack restoration binding changed"));
        }
        let offset = usize::try_from(self.start - base)
            .map_err(|_| fail("CPL0 stack restoration offset overflow"))?;
        let extent = usize::try_from(
            end.checked_sub(base)
                .ok_or_else(|| fail("CPL0 stack extent underflow"))?,
        )
        .map_err(|_| fail("CPL0 stack extent overflow"))?;
        if offset.checked_add(self.bytes.len()) != Some(extent) {
            return Err(fail("CPL0 stack restoration extent changed"));
        }
        // SAFETY: caller guarantees stopped guest memory and exact binding.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.bytes.as_ptr(),
                destination.add(offset),
                self.bytes.len(),
            )
        };
        Ok(())
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionCpuLease<M, Mem> {
    pub fn cpu_mut(&mut self) -> &mut CarrierCpu<M> {
        &mut self.cpu
    }

    pub fn physical_slot(&self) -> Option<carrick_guest_arch::CpuId> {
        self.cpu.physical_slot()
    }

    /// Host view of the one ingress reservation while this physical lease
    /// pins its carrier. The queue uses atomic slot publication on both sides.
    pub fn signal_ingress(&self) -> Result<&carrick_el1_abi::SharedSignalIngressQueue, TrapError> {
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("CPL0 signal ingress custody poisoned"))?;
        let queue = custody.metadata::<carrick_el1_abi::SharedSignalIngressQueue>(
            carrick_el1_abi::EL1_SIGNAL_INGRESS_OFFSET,
        ) as *const _;
        drop(custody);
        // SAFETY: this lease retains the carrier custody and its mapped ABI
        // region through the returned borrow; queue access is atomic.
        Ok(unsafe { &*queue })
    }

    pub fn fixture_run_until_native_kick(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<CarrierRunExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.cpu.fixture_run_until_kick(task));
        if watchdog.expired() {
            return Err(fail("native wait fixture guest interval deadline"));
        }
        result
    }

    /// Run a live native fixture.
    pub fn fixture_run_loaded(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<crate::carrier_cpu::StoppedTaskExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.cpu.run_loaded(task));
        if watchdog.expired() {
            return Err(fail("native fixture guest interval deadline"));
        }
        result
    }

    /// Run the real idle peer.
    pub fn fixture_run_idle_peer(&mut self) -> Result<CarrierRunExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.run_idle_peer());
        if watchdog.expired() {
            return Err(fail("native peer fixture guest interval deadline"));
        }
        result
    }

    /// Receive a fixture stdout byte from the real idle peer's stopped frame.
    /// MM and execution identity still come from the authenticated live venue.
    pub fn fixture_idle_peer_write(&mut self, exit: &CarrierRunExit) -> Result<Vec<u8>, TrapError> {
        if *exit != CarrierRunExit::SyscallTrap {
            return Err(fail("idle peer fixture requires write crossing"));
        }
        let task = self.idle_peer_task()?;
        let (bytes, token) = self.capture_forward(task, |venue, frame| {
            if (frame.rax, frame.rdi, frame.rdx) != (1, 1, 1) {
                return Err(fail("peer fixture only receives one stdout byte"));
            }
            venue
                .read_bytes_raw(frame.rsi, 1)
                .map_err(|error| fail(error.to_string()))
        })?;
        self.complete_forward(task, token, 1)?;
        Ok(bytes)
    }

    /// Resolve and authenticate the exact guest task stopped on the idle peer.
    /// The physical peer slot itself is never a task identity.
    pub fn idle_peer_task(&mut self) -> Result<carrick_guest_arch::TaskIdentity, TrapError> {
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let execution = self.cpu.with_idle_peer_io(|io| {
            let slot = carrick_guest_arch::CpuId::new(1);
            Ok(ForwardVenue::new(&mut custody, StoppedCpuLease { cpu: slot, io })?.execution)
        })?;
        drop(custody);
        let binding = self.cpu.registered_task_binding(execution.context.root)?;
        execution.authenticate(binding, "idle peer forward binding mismatch")?;
        Ok(binding.task())
    }

    pub fn save_kernel_stack(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<Option<KernelStackSnapshot>, TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_stopped_io(task, |io| {
            let rsp = io.get_gpr(X86Reg::Rsp)?;
            if rsp < DIRECT_VA {
                return Ok(None);
            }
            let end = custody
                .binding(slot)
                .kernel_stack
                .checked_add(16)
                .ok_or_else(|| fail("CPL0 stack top overflow"))?;
            let base = end
                .checked_sub(0x1_0000)
                .ok_or_else(|| fail("CPL0 stack base underflow"))?;
            let source = custody
                .ram
                .host_ptr(base - DIRECT_VA, 0x1_0000)
                .ok_or_else(|| fail("CPL0 stack backing absent"))?;
            // SAFETY: this exact task and CPU are stopped, and the backing
            // spans the verified private stack.
            unsafe { KernelStackSnapshot::capture(source, base, end, rsp, slot).map(Some) }
        })
    }

    pub fn restore_kernel_stack(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        snapshot: &KernelStackSnapshot,
    ) -> Result<(), TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_stopped_io(task, |_io| {
            let end = custody
                .binding(slot)
                .kernel_stack
                .checked_add(16)
                .ok_or_else(|| fail("CPL0 stack top overflow"))?;
            let base = end
                .checked_sub(0x1_0000)
                .ok_or_else(|| fail("CPL0 stack base underflow"))?;
            let destination = custody
                .ram
                .host_ptr(base - DIRECT_VA, 0x1_0000)
                .ok_or_else(|| fail("CPL0 stack backing absent"))?;
            // SAFETY: the exact task is loaded but stopped, and the snapshot
            // authenticates the physical stack before copying.
            unsafe { snapshot.restore(destination, base, end, slot) }
        })
    }

    pub fn arm_idle_kick(&mut self, kick: &M::KickHandle) -> Result<(), TrapError> {
        self.cpu.arm_idle_kick(kick)
    }
    pub fn arm_loaded_kick(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        kick: &M::KickHandle,
    ) -> Result<(), TrapError> {
        self.cpu.arm_loaded_kick(task, kick)
    }

    pub fn capture_fault_record(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        first: u32,
    ) -> Result<carrick_x86::FaultDoorbellRecord, TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("fault exit has no physical slot"))?;
        let mut words = vec![first];
        while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
            let stopped = self.cpu.run_loaded(task)?;
            let crate::carrier_cpu::CarrierRunExit::FaultDoorbellWord(word) = stopped.exit else {
                return Err(fail("fault record interrupted"));
            };
            words.push(word);
        }
        let record = carrick_x86::FaultDoorbellRecord::from_u32_words(&words)?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let reason = custody.binding(slot).fault_reason.load(Ordering::Acquire);
        if carrick_el1_abi::X86FaultDisposition::from_raw(reason)
            != Some(carrick_el1_abi::X86FaultDisposition::PolicyDeclined)
        {
            return Err(fail(format!(
                "kernel fault policy refused: reason {reason}, {record:?}"
            )));
        }
        Ok(record)
    }

    pub fn run_idle_peer(&mut self) -> Result<CarrierRunExit, TrapError> {
        self.cpu.run_idle_peer()
    }

    pub fn audit_unloaded_peer(&self) -> Result<(), TrapError> {
        self.cpu.audit_unloaded_peer()
    }

    pub fn service_idle_peer_doorbell(
        &mut self,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        let CarrierRunExit::PhysicalDoorbell { port, .. } = exit else {
            return Err(fail("idle peer service requires physical doorbell"));
        };
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let mut work_flags = None;
        let (exit, register_child, unregister_child) = self.cpu.with_idle_peer_io(|io| {
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(1),
                io,
            };
            match *port {
                OWNER_GRANT_PORT => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_anonymous_grant(&lease)?;
                    Ok((None, None, None))
                }
                carrick_el1_abi::FORK_STOCK_PORT => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let child_binding = custody.service_fork_stock(&lease)?;
                    Ok((None, child_binding, None))
                }
                carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT => {
                    custody.child_retire_crossings = custody
                        .child_retire_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let live_root = lease.io.get_gpr(X86Reg::Cr3)? & !0xfff;
                    let root_gpa = RootGpa::page_aligned(FrameGpa::new(live_root))
                        .ok_or_else(|| fail("unaligned child retire CR3"))?;
                    let retire_result = custody.service_child_retire(&lease);
                    Ok((None, None, Some((root_gpa, retire_result))))
                }
                carrick_core_abi::NATIVE_RUN_FAILURE_PORT => {
                    let reason = custody.service_run_failure(&lease)?;
                    custody.run_failure_crossings = custody
                        .run_failure_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    Ok((Some(PhysicalProcessExit::RunFailed(reason)), None, None))
                }
                carrick_core_abi::NATIVE_ROOT_EXIT_PORT => {
                    custody.root_exit_crossings = custody
                        .root_exit_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody
                        .service_root_exit(&lease)
                        .map(|status| (Some(PhysicalProcessExit::Exited(status)), None, None))
                }
                WORK_PORT => {
                    work_flags = Some(take_production_work_boundary(custody.task(lease.cpu))?);
                    Ok((None, None, None))
                }
                _ => Err(fail("unexpected idle peer physical doorbell")),
            }
        })?;
        if let Some(child_binding) = register_child {
            self.cpu.register_child_binding(child_binding)?;
        }
        if let Some((live_root, retire_result)) = unregister_child {
            self.cpu.unregister_child_binding(live_root)?;
            retire_result?;
        }
        if let Some(PhysicalProcessExit::Exited(_) | PhysicalProcessExit::RunFailed(_)) = exit {
            self.cpu.clear_child_bindings()?;
        }
        drop(custody);
        if let Some((served, doorbell)) = work_flags {
            on_work(served, doorbell);
        }
        Ok(exit)
    }

    pub fn is_idle_peer_slot(&self) -> bool {
        self.physical_slot() == Some(carrick_guest_arch::CpuId::new(1))
    }

    pub fn capture_forward<R>(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        forward: impl FnOnce(&mut ForwardVenue<'_, M, Mem>, &NativeFrame) -> Result<R, TrapError>,
    ) -> Result<(R, ProductionForwardFrame), TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_forward_io(task, |io, active_binding| {
            let address = io.get_gpr(X86Reg::Rax)?;
            let stack_end = checked_stack_end(custody.binding(slot).kernel_stack)
                .ok_or_else(|| fail("forward kernel stack overflow"))?;
            let gpa = checked_private_stack_frame_gpa(stack_end, address, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward frame outside private kernel stack"))?;
            let ptr = custody
                .ram
                .host_ptr(gpa, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward frame backing"))?
                .cast::<NativeFrame>();
            // SAFETY: guest execution stopped after the exact frame publication; no
            // guest instruction runs while this copy is made.
            let frame = unsafe { *ptr };
            let mut venue = ForwardVenue::new(&mut custody, StoppedCpuLease { cpu: slot, io })?;
            let execution = venue.execution;
            execution.authenticate(active_binding, "forward capture MM binding mismatch")?;
            let result = forward(&mut venue, &frame)?;
            custody.host_forwards = custody
                .host_forwards
                .checked_add(1)
                .ok_or_else(|| fail("host forward counter exhausted"))?;
            if slot == carrick_guest_arch::CpuId::new(1) {
                custody.idle_peer_forwards = custody
                    .idle_peer_forwards
                    .checked_add(1)
                    .ok_or_else(|| fail("idle peer forward counter exhausted"))?;
            }
            Ok((
                result,
                ProductionForwardFrame {
                    task,
                    slot,
                    address,
                    execution,
                    frame,
                },
            ))
        })
    }

    pub fn complete_forward(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        token: ProductionForwardFrame,
        value: i64,
    ) -> Result<(), TrapError> {
        if token.task != task || self.physical_slot() != Some(token.slot) {
            return Err(fail("forward completion task or physical slot changed"));
        }
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_forward_io(task, |io, active_binding| {
            let lease = StoppedCpuLease {
                cpu: token.slot,
                io,
            };
            let current = ForwardVenue::new(&mut custody, lease)?.execution;
            if current.binding != token.execution.binding
                || current.context != token.execution.context
            {
                return Err(fail("forward completion MM binding changed"));
            }
            current.authenticate(active_binding, "forward completion MM binding changed")?;
            let stack_end = checked_stack_end(custody.binding(token.slot).kernel_stack)
                .ok_or_else(|| fail("forward completion kernel stack overflow"))?;
            let gpa =
                checked_private_stack_frame_gpa(stack_end, token.address, size_of::<NativeFrame>())
                    .ok_or_else(|| fail("forward completion frame outside private kernel stack"))?;
            let ptr = custody
                .ram
                .host_ptr(gpa, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward completion frame backing"))?
                .cast::<NativeFrame>();
            let mut frame = token.frame;
            frame.rax = value as u64;
            // SAFETY: the exact stopped task owns this private kernel stack
            // after reloading its saved CPU image. Restore the whole frame
            // because another task may have used the stack during the wait.
            unsafe { ptr.write(frame) };
            Ok(())
        })
    }

    /// Service a retained forward after the exact task has regained a CPU.
    /// The frame remains owned by the task until `complete_forward` consumes it.
    pub fn with_retained_forward<R>(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        token: &ProductionForwardFrame,
        service: impl FnOnce(&mut ForwardVenue<'_, M, Mem>) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        if token.task != task || self.physical_slot() != Some(token.slot) {
            return Err(fail("retained forward task or physical slot changed"));
        }
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_stopped_io(task, |io| {
            let lease = StoppedCpuLease {
                cpu: token.slot,
                io,
            };
            let mut venue = ForwardVenue::new(&mut custody, lease)?;
            if venue.execution.binding != token.execution.binding
                || venue.execution.context != token.execution.context
            {
                return Err(fail("retained forward MM binding changed"));
            }
            service(&mut venue)
        })
    }

    /// Service one physical doorbell on the stopped worker CPU. Task
    /// identity is supplied by the executor's claimed binding, never by the
    /// doorbell payload or the physical slot.
    pub fn service_physical_doorbell(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        let CarrierRunExit::PhysicalDoorbell { port, .. } = exit else {
            return Err(fail("physical service requires a doorbell exit"));
        };
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let mut work_flags = None;
        let (exit, register_child, unregister_child) = self.cpu.with_stopped_io(task, |io| {
            let lease = StoppedCpuLease { cpu: slot, io };
            match production_port(*port) {
                Some(ProductionPort::OwnerGrant) => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_anonymous_grant(&lease)?;
                    Ok((None, None, None))
                }
                Some(ProductionPort::ForkStock) => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let child_binding = custody.service_fork_stock(&lease)?;
                    Ok((None, child_binding, None))
                }
                Some(ProductionPort::ChildRetire) => {
                    custody.child_retire_crossings = custody
                        .child_retire_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let live_root = lease.io.get_gpr(X86Reg::Cr3)? & !0xfff;
                    let root_gpa = RootGpa::page_aligned(FrameGpa::new(live_root))
                        .ok_or_else(|| fail("unaligned child retire CR3"))?;
                    let retire_result = custody.service_child_retire(&lease);
                    Ok((None, None, Some((root_gpa, retire_result))))
                }
                Some(ProductionPort::RunFailure) => {
                    let reason = custody.service_run_failure(&lease)?;
                    custody.run_failure_crossings = custody.run_failure_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    Ok((Some(PhysicalProcessExit::RunFailed(reason)), None, None))
                }
                Some(ProductionPort::RootExit) => {
                    custody.root_exit_crossings = custody
                        .root_exit_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_root_exit(&lease).map(|status| (Some(PhysicalProcessExit::Exited(status)), None, None))
                }
                Some(ProductionPort::Work) => {
                    work_flags = Some(take_production_work_boundary(custody.task(slot))?);
                    Ok((None, None, None))
                }
                None => {
                    let binding = custody.binding(slot);
                    let rip = lease.io.get_gpr(X86Reg::Rip).unwrap_or(0);
                    let rax = lease.io.get_gpr(X86Reg::Rax).unwrap_or(0);
                    Err(fail(format!(
                        "unexpected physical production port {port:#x} at rip {rip:#x} rax {rax:#x}; outer fault active {}, address {:#x}, reason {}",
                        binding.fault_active.load(Ordering::Acquire),
                        binding.fault_address.load(Ordering::Acquire),
                        binding.fault_reason.load(Ordering::Acquire),
                    )))
                }
            }
        })?;
        if let Some(child_binding) = register_child {
            self.cpu.register_child_binding(child_binding)?;
        }
        if let Some((live_root, retire_result)) = unregister_child {
            self.cpu.unregister_child_binding(live_root)?;
            retire_result?;
        }
        if let Some(PhysicalProcessExit::Exited(_) | PhysicalProcessExit::RunFailed(_)) = exit {
            self.cpu.clear_child_bindings()?;
        }
        drop(custody);
        if let Some((served, doorbell)) = work_flags {
            on_work(served, doorbell);
        }
        Ok(exit)
    }
}

enum ProductionPort {
    OwnerGrant,
    ForkStock,
    ChildRetire,
    RunFailure,
    RootExit,
    Work,
}

fn production_port(port: u16) -> Option<ProductionPort> {
    match port {
        OWNER_GRANT_PORT => Some(ProductionPort::OwnerGrant),
        carrick_el1_abi::FORK_STOCK_PORT => Some(ProductionPort::ForkStock),
        carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT => Some(ProductionPort::ChildRetire),
        carrick_core_abi::NATIVE_RUN_FAILURE_PORT => Some(ProductionPort::RunFailure),
        carrick_core_abi::NATIVE_ROOT_EXIT_PORT => Some(ProductionPort::RootExit),
        WORK_PORT => Some(ProductionPort::Work),
        _ => None,
    }
}

fn take_production_work_boundary(
    task: &CurrentTask,
) -> Result<(bool, Option<carrick_el1_abi::HostWorkDoorbell>), TrapError> {
    let state = &task.linux;
    let boundary = state.take_served_boundary();
    if matches!(
        boundary,
        Some(
            carrick_el1_abi::ServedBoundary::ReplayOriginal { .. }
                | carrick_el1_abi::ServedBoundary::ForwardOriginal { .. }
        )
    ) {
        return Err(fail("x86 work boundary cannot replay a completed syscall"));
    }
    let doorbell = state.take_host_work_doorbell();
    if boundary.is_none() && doorbell.is_none() {
        return Err(fail("x86 work port without owed boundary work"));
    }
    Ok((boundary.is_some(), doorbell))
}

#[cfg(test)]
mod production_work_port_tests {
    use super::{
        CurrentTask, ProductionPort, WORK_PORT, production_port, take_production_work_boundary,
    };

    #[test]
    fn completed_cpl0_work_has_a_production_boundary() {
        assert!(matches!(
            production_port(WORK_PORT),
            Some(ProductionPort::Work)
        ));
    }

    #[test]
    fn work_boundary_consumes_only_the_stopped_tasks_flags_once() {
        let stopped = CurrentTask::new();
        let peer = CurrentTask::new();
        stopped.linux.record_completed_with_work();
        stopped.linux.mark_pending_host_work();
        peer.linux.record_completed_with_work();
        peer.linux.mark_pending_host_work();

        let (served, doorbell) = take_production_work_boundary(&stopped).unwrap();
        assert!(served);
        doorbell.expect("stopped task doorbell").settled();
        assert!(take_production_work_boundary(&stopped).is_err());
        assert!(peer.linux.has_pending_host_work());
        let (served, doorbell) = take_production_work_boundary(&peer).unwrap();
        assert!(served);
        doorbell.expect("peer doorbell").settled();
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionCpuFactory<M, Mem> {
    /// Attach per-exit mirrors only after the run's debug endpoint is live.
    pub fn attach_debug(&self) {
        let mut cpus = self
            .cpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (cpu, debug) in cpus.iter_mut().zip(self.debug_cpus.iter()) {
            if let Some(cpu) = cpu {
                cpu.attach_debug(Arc::clone(debug));
            }
        }
    }

    /// Read the physical zone without taking an execution lease or entering
    /// the guest. A held host custody is reported, never waited on by the debugger.
    pub fn capture_physical_state(&self) -> ProductionPhysicalCapture {
        let mut capture = ProductionPhysicalCapture {
            zone_census: String::new(),
            vcpus: (0..2)
                .map(|index| self.debug_cpus[index].render(index))
                .collect(),
            unavailable: Vec::new(),
        };
        match self.custody.try_lock() {
            Ok(custody) => {
                if let Some(pointer) = custody.ram.host_ptr(
                    META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                    size_of::<X86Cpl0Zone>(),
                ) {
                    // SAFETY: the retained, initialized zone uses atomic
                    // readers for this deliberately non-coherent census.
                    let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
                    if zone.write_census(&mut capture.zone_census).is_err() {
                        capture
                            .unavailable
                            .push("zone census formatting failed".to_owned());
                    }
                } else {
                    capture.unavailable.push("zone backing absent".to_owned());
                }
                for index in 0..2 {
                    let task = custody.task(carrick_guest_arch::CpuId::new(index));
                    capture.vcpus[index as usize].push_str(&format!(
                        " actual_guest_run={} pending_host_work={} served_with_work={}",
                        custody.actual_run[index as usize].load(Ordering::Acquire) != 0,
                        task.linux.has_pending_host_work(),
                        task.linux.served_word(),
                    ));
                }
            }
            Err(_) => capture
                .unavailable
                .push("physical custody busy; pending host work unavailable".to_owned()),
        }
        capture
    }

    /// Place an already runnable fixture task using the real claim/run queues.
    /// Both CPUs must be stopped. Parked waiters are deliberately refused.
    pub fn fixture_place_native_thread(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        self.fixture_place_native_thread_policy(tid, cpu, false)
    }

    /// Bind a queued, unhomed fixture thread to its actor CPU while stopped.
    /// Queue placement alone permits the other CPU to steal the child while
    /// its parent parks. A fixture holding that CPU stopped would then strand
    /// the child there instead of exercising the intended peer exit path.
    pub fn fixture_pin_native_thread(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        self.fixture_place_native_thread_policy(tid, cpu, true)
    }

    fn fixture_place_native_thread_policy(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
        pin_thread: bool,
    ) -> Result<(), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let record = (1..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(carrick_sched_core::RecordId::from_raw)
            .find(|id| {
                zone.record(*id).identity().tid == tid.raw()
                    && matches!(
                        zone.record(*id).claim(),
                        carrick_sched_core::Claim::Queued { .. }
                    )
            })
            .ok_or_else(|| {
                let live: Vec<_> = (1..carrick_sched_core::ZONE_RECORDS as u32)
                    .filter_map(carrick_sched_core::RecordId::from_raw)
                    .filter_map(|id| {
                        let row = zone.record(id);
                        (row.claim() != carrick_sched_core::Claim::Free)
                            .then_some((row.identity(), row.claim()))
                    })
                    .collect();
                fail(format!(
                    "fixture task {} is not queued: {live:?}",
                    tid.raw()
                ))
            })?;
        if zone.record(record).home().is_some() || cpu.raw() >= 2 {
            return Err(fail(
                "fixture placement requires an unhomed task and live CPU",
            ));
        }
        let slot = SlotId::new(cpu.raw() as u8);
        if pin_thread && zone.slot(slot).host_record().is_some() {
            return Err(fail("fixture affinity requires a peer without a host home"));
        }
        if zone.claim_for_host(
            zone.record_ref(record),
            None,
            carrick_sched_core::Handback::Resumed,
            &carrick_sched_core::BoundedSpin(0),
        ) != carrick_sched_core::HostClaim::Claimed
        {
            return Err(fail("fixture queue placement refused"));
        }
        if pin_thread {
            // The host owns this exact unhomed queued thread. The target has
            // no host home, and a Host claim has no live park timer. Use the
            // existing home-release primitive to publish its actor affinity.
            let _ = zone.unhome(slot, record, 1 << cpu.raw());
        }
        if zone.requeue_on(slot, record).is_none() {
            return Err(fail("fixture queue placement refused"));
        }
        Ok(())
    }

    /// Observe an idle actor boundary after its queue guard has been released.
    /// This changes no scheduler claim, receipt readiness or wake generation.
    pub fn fixture_native_cpu_idle(
        &self,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<bool, TrapError> {
        if cpu.raw() >= 2 {
            return Err(fail("unknown native fixture CPU"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let slot = SlotId::new(cpu.raw() as u8);
        let Some(_guard) = zone.slot_lock(slot, &carrick_sched_core::BoundedSpin(0)) else {
            return Ok(false);
        };
        Ok(
            zone.slot(slot).state() == carrick_sched_core::SlotState::IdleWfi
                && zone.slot(slot).current().is_none()
                && zone.slot(slot).queued() == 0,
        )
    }

    /// Atomic fixture census of the actual native wait enrollment.
    /// The fixture retains this task generation; no lifecycle is completed here.
    pub fn fixture_native_wait_state(
        &self,
        tid: El1TaskId,
    ) -> Result<(carrick_sched_core::Claim, u64, u64), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let record = (1..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(carrick_sched_core::RecordId::from_raw)
            .map(|id| zone.record(id))
            .find(|row| {
                row.identity().tid == tid.raw()
                    && (row.claim() != carrick_sched_core::Claim::Free || row.home().is_some())
            })
            .ok_or_else(|| fail("native wait record absent"))?;
        Ok((
            record.claim(),
            zone.counters.el1_parks.load(Ordering::Acquire),
            zone.counters.el1_wakes.load(Ordering::Acquire),
        ))
    }

    pub fn refusal_count(&self, nr: carrick_abi::NativeNr) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let counters: &Counters = custody.metadata(COUNTERS_OFFSET);
        let index = usize::try_from(nr.raw())
            .ok()
            .filter(|index| *index < 512)
            .unwrap_or(512);
        Ok(counters.refused[index].load(Ordering::Acquire))
    }

    pub fn refusal_overflow_count(&self) -> Result<u64, TrapError> {
        self.refusal_count(carrick_abi::NativeNr(512))
    }

    pub fn robust_list_head(&self, index: usize) -> Result<u64, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let slot: &ThreadControlSlot = custody.metadata(CONTROL_OFFSET + index as u64 * STRIDE);
        Ok(slot.robust_list().0)
    }

    pub fn fixture_pending_irqs(&self, index: usize) -> Result<u32, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody
            .binding(carrick_guest_arch::CpuId::new(index as u32))
            .pending_irqs
            .load(Ordering::Acquire))
    }

    /// Publish owed work on the stopped slot's bound task for a live hardware
    /// doorbell witness. The next guest boundary must service this exact bit.
    pub fn fixture_mark_current_host_work(
        &self,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        if slot.raw() >= 2 {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody.task(slot).linux.mark_pending_host_work();
        Ok(())
    }

    pub fn user_fault_state(&self, index: usize) -> Result<(u64, u64, u64, u64, u64), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let binding = custody.binding(carrick_guest_arch::CpuId::new(index as u32));
        let frame = binding.fault_frame.load(Ordering::Acquire);
        let (error, pc) = if frame == 0 {
            (0, 0)
        } else {
            let bytes = custody
                ._vm
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

    /// Lend authenticated file records only while every physical CPU is stopped.
    /// The capability and retained owner remain borrowed for the whole callback.
    pub fn with_stopped_file_tables<R>(
        &self,
        inspect: impl FnOnce(&StoppedFileTables<'_>) -> R,
    ) -> Result<R, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let tables = custody
            .file_tables(custody.files.registration.binding())
            .map_err(|error| fail(format!("stopped file tables: {error:?}")))?;
        Ok(inspect(&tables))
    }

    pub fn initial_execution_witness(&self) -> Result<(u64, u64), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok((
            custody
                .binding(carrick_guest_arch::CpuId::new(0))
                .entries
                .load(Ordering::Acquire),
            custody.host_forwards,
        ))
    }

    /// Host forwards served for a task stopped on the idle peer (CPU 1).
    pub fn idle_peer_forward_witness(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.idle_peer_forwards)
    }

    pub fn anonymous_private_pages(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.private_anonymous_witness.private_pages())
    }

    pub fn anonymous_private_mms(&self) -> Result<Vec<PrivateAnonymousMmEvidence>, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.anonymous_private_mms())
    }

    pub fn cross_mm_private_aliases(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.cross_mm_private_aliases())
    }

    pub fn peer_active_private_grants(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.peer_active_private_grants())
    }

    pub fn physical_crossing_counts(
        &self,
    ) -> Result<[(PhysicalCrossingFamily, u64); 4], TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok([
            (
                PhysicalCrossingFamily::OwnerGrant,
                custody.owner_grant_crossings,
            ),
            (
                PhysicalCrossingFamily::RootExit,
                custody.root_exit_crossings,
            ),
            (
                PhysicalCrossingFamily::ChildRetire,
                custody.child_retire_crossings,
            ),
            (
                PhysicalCrossingFamily::RunFailure,
                custody.run_failure_crossings,
            ),
        ])
    }

    pub fn fork_admission_refusal(
        &self,
    ) -> Result<Option<carrick_hal::fork_stock::ForkAdmissionRefusal>, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock.admission_refusal())
    }

    pub fn fork_stock_counters(
        &self,
    ) -> Result<carrick_hal::fork_stock::ForkStockCounters, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock_counters())
    }

    pub fn claim(&self, slot: usize) -> Result<ProductionCpuLease<M, Mem>, TrapError> {
        let mut cpus = self.cpus.lock().map_err(|_| fail("CPU factory poisoned"))?;
        let cpu = cpus
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or_else(|| fail("physical CPU already claimed or absent"))?;
        if cpu.physical_slot() != Some(carrick_guest_arch::CpuId::new(slot as u32)) {
            return Err(fail("claimed CPU physical identity mismatch"));
        }
        Ok(ProductionCpuLease {
            cpu,
            _custody: Arc::clone(&self.custody),
        })
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionWorkerParts<M, Mem> {
    /// Both CPUs take the root binding from `root_state` itself; callers
    /// cannot supply a second, possibly different, root binding.
    pub fn new(
        mut cpus: [CarrierCpu<M>; 2],
        custody: BootstrapCustody<Mem>,
        root_state: carrick_x86::arch_context::X86ArchContext,
    ) -> Self {
        for cpu in &mut cpus {
            cpu.bind_root(root_state.binding());
        }
        Self {
            cpus,
            custody: custody.0,
            root_state,
        }
    }

    pub fn into_factory(
        self,
    ) -> (
        carrick_x86::arch_context::X86ArchContext,
        ProductionCpuFactory<M, Mem>,
    ) {
        let Self {
            cpus,
            custody,
            root_state,
        } = self;
        let debug_cpus: [Arc<CarrierCpuDebug>; 2] =
            std::array::from_fn(|_| Arc::new(CarrierCpuDebug::default()));
        (
            root_state,
            ProductionCpuFactory {
                cpus: std::sync::Mutex::new(cpus.map(Some)),
                custody: Arc::new(std::sync::Mutex::new(custody)),
                debug_cpus,
            },
        )
    }
    pub fn root_state(&self) -> &carrick_x86::arch_context::X86ArchContext {
        &self.root_state
    }
}
/// The kernel graph's issued root identity for the first production task.
/// Physical CPU slots never manufacture these values.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct InitialTaskBinding {
    pub task: carrick_sched_core::process::TaskKey,
    pub thread: carrick_sched_core::ThreadIdentity,
    pub mm: MmGeneration,
}

/// A single movable view into metadata retained by `Cpl0HostCustody`.
/// Deliberately neither `Clone` nor `Sync`.
struct RetainedMetadataPtr(NonNull<u8>);

impl RetainedMetadataPtr {
    fn as_ptr(&self) -> *mut u8 {
        self.0.as_ptr()
    }
}

// SAFETY: only the enclosing exclusive custody can access this pointer. Its
// GuestRam and registered backing live in that same custody, so moving this
// non-cloneable view to another thread cannot outlive or alias its storage.
unsafe impl Send for RetainedMetadataPtr {}

/// Registration and mapping have one custody. Registration drops first,
/// withdrawing publication while its own backing remains mapped.
struct RetainedFileRegion {
    registration: carrick_el1_abi::FileRegionRegistration,
    execution: Arc<RwLock<()>>,
    _backing: Arc<BackingExtent>,
}

/// Host file references own exclusive execution admission against `run_member`.
/// The single-step fixture bypasses it under exclusive mutable carrier custody;
/// M1 `CarrierMachine::create_stopped` has no F2 admission or file registration.
/// Atomics alone and the host image's descriptor lock are not this proof.
///
/// Limit (F3/F4 constraint): acquisition checks only the fd-map transaction word.
/// A kicked CPU can still hold a `DelegatedFile` inode lock. This proof does not
/// establish inode-lock quiescence for `objects()` / `opens()`; host operations
/// needing those locks can still stall on a paused guest owner.
pub struct StoppedFileTables<'a> {
    tables: carrick_el1_abi::FileTables<'a>,
    _stopped: RwLockWriteGuard<'a, ()>,
}

impl<'a> core::ops::Deref for StoppedFileTables<'a> {
    type Target = carrick_el1_abi::FileTables<'a>;
    fn deref(&self) -> &Self::Target {
        &self.tables
    }
}

// SAFETY: moved only inside exclusive carrier custody. The non-cloning
// registration never escapes its retained backing, and tables use atomics
// and their existing inode/descriptor owners for concurrent guest access.
unsafe impl Send for RetainedFileRegion {}

/// One coordinator owns physical backing, grants and retained metadata.
/// CPU execution leases are disjoint from this custody, so stopped host service
/// never borrows the carrier or a simultaneously running peer CPU.
pub(crate) struct Cpl0HostCustody<M: CarrierMemoryIo> {
    pub(crate) _vm: CarrierMemory<M>,
    pub(crate) ram: Arc<GuestRam>,
    birth_live: BirthSourceRevocation,
    initial_extent: Option<(BackingHandle, usize)>,
    _kernel_region: Option<BackingHandle>,
    files: RetainedFileRegion,
    frame_inventory: Arc<dyn PhysicalFrameInventory>,
    pub(crate) private_anonymous_witness: crate::cpl0_private_witness::PrivateAnonymousWitness,
    actual_run: Arc<[AtomicU32; 2]>,
    kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
    initial_inventory: Option<InitialInventory>,
    initial_rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
    peer_entry: Option<carrick_guest_arch::KernelVa>,
    peer_admission: InitialPeerAdmission,
    initial_task: Option<InitialTaskBinding>,
    prepare_table_stock: Option<anonymous_owner::PrepareTableStock>,
    /// The ISA-neutral fork stock, loans and child quarantine.
    fork_stock: carrick_hal::fork_stock::ForkStock<carrick_hal::fork_stock::UntaggedRoots>,
    maintenance_root: Option<RootGpa>,
    anonymous_next_gpa: FrameGpa,
    anonymous_pending: [Option<anonymous_owner::PendingGrant>; 2],
    owner_grant_crossings: u64,
    root_exit_crossings: u64,
    child_retire_crossings: u64,
    run_failure_crossings: u64,
    metadata_base: RetainedMetadataPtr,
    host_forwards: u64,
    /// Host forwards captured from a task stopped on the idle peer (CPU 1),
    /// so a fixture can prove where EL1 placed the forwarding task.
    idle_peer_forwards: u64,
    host_yields: u64,
    kicks: u64,
    work_exits: u64,
}

impl<M: CarrierMemoryIo> Drop for Cpl0HostCustody<M> {
    fn drop(&mut self) {
        self.birth_live.retire();
        // Unwind the inventory first. Its destructor only records a refused
        // retirement; this carrier observer chooses the existing fail-stop.
        drop(self.initial_inventory.take());
        if self.initial_rollback_fault.failed() {
            carrick_el1_linux::dispatch::invalid_completion(
                carrick_el1_linux::dispatch::NativeInvariant::PhysicalCustody(
                    "unexposed physical inventory rollback failed",
                ),
            );
        }
    }
}

/// Exclusive physical CPU custody while the executor vCPU has returned.
pub(crate) struct StoppedCpuLease<'a, I: CarrierCpuIo> {
    cpu: carrick_guest_arch::CpuId,
    io: &'a mut I,
}

/// Host crossings see only their stopped physical lane and exact MM owner.
/// Process policy and task selection remain in the shared guest owner.
pub struct ForwardVenue<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    custody: &'a mut Cpl0HostCustody<Mem>,
    lease: StoppedCpuLease<'a, M>,
    execution: ForwardExecution,
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    pub fn file_tables(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<StoppedFileTables<'_>, carrick_el1_abi::FileRegionError> {
        let stopped = self
            .files
            .execution
            .try_write()
            .map_err(|_| carrick_el1_abi::FileRegionError::Running)?;
        let tables = self.files.registration.tables(binding)?;
        // A kick may stop CPL0 inside a descriptor transaction. Execution
        // exclusion prevents reentry while its shared lock state is checked.
        if tables.fd_map()[0].mutation_active() {
            return Err(carrick_el1_abi::FileRegionError::MutationActive);
        }
        Ok(StoppedFileTables {
            tables,
            _stopped: stopped,
        })
    }

    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: the retained owner initialized each aligned record before
        // publication. Callers access atomic metadata or their stopped lane.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }

    pub fn task(&self, cpu: carrick_guest_arch::CpuId) -> &CurrentTask {
        self.metadata(TASK_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }

    pub fn binding(&self, cpu: carrick_guest_arch::CpuId) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }
}

impl<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo> ForwardVenue<'a, M, Mem> {
    fn new(
        custody: &'a mut Cpl0HostCustody<Mem>,
        lease: StoppedCpuLease<'a, M>,
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
        let root = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("stopped forward CR3 alignment"))?;
        let generation = ContextGeneration::new(
            NonZeroU64::new(native.mm_owner_generation.load(Ordering::Acquire))
                .ok_or_else(|| fail("stopped forward address incarnation"))?,
        );
        let leader_task = match custody.initial_task {
            Some(initial) if context.mm == initial.mm => {
                carrick_el1_abi::EntryTaskKey::from_raw(initial.thread.tid)
            }
            _ => carrick_el1_abi::EntryTaskKey::from_raw(u64::from(
                task.visible_pid()
                    .ok_or_else(|| fail("stopped forward task has no visible pid"))?,
            )),
        };
        let execution = admit_forward_execution(
            cpu,
            carrick_guest_arch::CpuId::new(native.cpu_slot),
            binding,
            context,
            root,
            generation,
        )?
        .with_leader_task(leader_task);
        Ok(Self {
            custody,
            lease,
            execution,
        })
    }

    pub fn cpu(&self) -> carrick_guest_arch::CpuId {
        self.execution.cpu
    }

    /// Resolve a writable guest descriptor in the stopped task's own CPL0 file
    /// table to its bound [`carrick_el1_abi::HostObjectBinding`].
    pub fn stopped_task_host_object(
        &self,
        guest_fd: i32,
    ) -> Result<Option<carrick_el1_abi::HostObjectBinding>, TrapError> {
        let file_table = self
            .custody
            .task(self.execution.cpu)
            .linux
            .file_table
            .load(Ordering::Acquire)
            .max(1);
        let region = self.custody.binding(self.execution.cpu).file_region;
        let tables = self
            .custody
            .files
            .registration
            .tables(region)
            .map_err(|error| fail(format!("stopped task file tables: {error:?}")))?;
        let _guard = carrick_el1_abi::lock_fd_map(tables.fd_map());
        let Some((handle, _)) =
            carrick_el1_abi::fd_map_lookup(tables.fd_map(), file_table, guest_fd)
        else {
            return Ok(None);
        };
        if handle == 0 {
            return Ok(None);
        }
        Ok(tables
            .opens()
            .get((handle - 1) as usize)
            .filter(|open| {
                open.state.load(Ordering::Acquire) == carrick_el1_abi::DELEGATED_STATE_GUEST
                    && open.flags.load(Ordering::Acquire) & carrick_el1_abi::DELEGATED_FLAG_WRITABLE
                        != 0
            })
            .and_then(carrick_el1_abi::DelegatedOpenFile::host_object))
    }

    /// Authenticate that the stopped task's own CPL0 file table holds a live
    /// writable open description bound to `expected`.
    pub fn stopped_task_has_writable_host_object(
        &self,
        expected: carrick_el1_abi::HostObjectBinding,
    ) -> Result<bool, TrapError> {
        let file_table = self
            .custody
            .task(self.execution.cpu)
            .linux
            .file_table
            .load(Ordering::Acquire)
            .max(1);
        let region = self.custody.binding(self.execution.cpu).file_region;
        let tables = self
            .custody
            .files
            .registration
            .tables(region)
            .map_err(|error| fail(format!("stopped task file tables: {error:?}")))?;
        let _guard = carrick_el1_abi::lock_fd_map(tables.fd_map());
        Ok(tables
            .fd_map()
            .iter()
            .take(carrick_el1_abi::FD_MAP_CAPACITY)
            .any(|slot| {
                let inc = slot.incarnation.load(Ordering::Acquire);
                if inc == 0
                    || inc == carrick_el1_abi::FdMapSlot::CLAIMED
                    || slot.file_table.load(Ordering::Relaxed) != file_table
                {
                    return false;
                }
                let handle = slot.handle.load(Ordering::Relaxed);
                handle
                    .checked_sub(1)
                    .and_then(|idx| tables.opens().get(idx as usize))
                    .is_some_and(|open| {
                        open.state.load(Ordering::Acquire) == carrick_el1_abi::DELEGATED_STATE_GUEST
                            && open.flags.load(Ordering::Acquire)
                                & carrick_el1_abi::DELEGATED_FLAG_WRITABLE
                                != 0
                            && open.host_object() == Some(expected)
                    })
            }))
    }
}

fn checked_readiness_region(base: u64, offset: u64, length: usize, extent: u64) -> Option<u64> {
    let length = u64::try_from(length).ok()?;
    (offset.checked_add(length)? <= extent)
        .then(|| base.checked_add(offset))
        .flatten()
}

pub fn checked_stack_end(kernel_stack: u64) -> Option<u64> {
    kernel_stack.checked_add(16)
}

pub fn checked_private_stack_frame_gpa(stack_end: u64, address: u64, length: usize) -> Option<u64> {
    let stack_start = stack_end.checked_sub(0x1_0000)?;
    let length = u64::try_from(length).ok()?;
    if address & 7 != 0 || address < stack_start || address.checked_add(length)? > stack_end {
        return None;
    }
    let gpa = address.checked_sub(DIRECT_VA)?;
    gpa.checked_add(length)?;
    Some(gpa)
}

pub fn checked_fault_error_gpa(frame: u64) -> Option<FrameGpa> {
    let gpa = frame.checked_sub(DIRECT_VA)?.checked_add(120)?;
    gpa.checked_add(16)?;
    Some(FrameGpa::new(gpa))
}

#[cfg(test)]
mod readiness_span_tests {
    #[test]
    fn supervisor_readiness_span_rejects_host_address_overflow() {
        assert_eq!(
            super::checked_readiness_region(u64::MAX - 8, 16, 16, 64),
            None
        );
        assert_eq!(
            super::checked_readiness_region(0x1000, 16, 16, 32),
            Some(0x1010)
        );
        assert_eq!(super::checked_readiness_region(0x1000, 17, 16, 32), None);
    }

    #[test]
    fn private_stack_and_fault_frame_reject_wrapped_metadata() {
        assert_eq!(super::checked_stack_end(u64::MAX), None);
        assert_eq!(super::checked_private_stack_frame_gpa(8, 0, 16), None);
        assert_eq!(super::checked_fault_error_gpa(0), None);
        assert_eq!(super::checked_fault_error_gpa(super::DIRECT_VA - 1), None);
    }
}

impl<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo> ForwardVenue<'a, M, Mem> {
    /// Inspect a typed readiness batch in the stopped task's supervisor
    /// region. The batch stays on its task-owned kernel stack or heap while
    /// an owned continuation releases the physical CPU.
    pub fn with_host_readiness_entries<R>(
        &mut self,
        address: u64,
        count: usize,
        use_entries: impl FnOnce(&mut [carrick_el1_abi::HostReadinessEntry]) -> R,
    ) -> Result<R, TrapError> {
        if count > 1024 {
            return Err(fail("host readiness batch exceeds poll bound"));
        }
        if count == 0 {
            // Zero-fd poll carries only a deadline. No guest pointer is
            // dereferenced, and an empty Rust slice need not have a guest VA.
            return Ok(use_entries(&mut []));
        }
        let length = count
            .checked_mul(size_of::<carrick_el1_abi::HostReadinessEntry>())
            .ok_or_else(|| fail("host readiness batch length overflow"))?;
        let region = if let Some(offset) = address.checked_sub(X86_CPL0_BOOTSTRAP_METADATA_BASE)
            && offset < EL1_BOOTSTRAP_METADATA_SIZE
        {
            Some((ALLOCATOR_GPA, offset, EL1_BOOTSTRAP_METADATA_SIZE))
        } else if let Some(offset) = address.checked_sub(X86_CPL0_REGION_BASE)
            && offset < carrick_el1_abi::EL1_REGION_SIZE
        {
            Some((KERNEL_REGION_GPA, offset, carrick_el1_abi::EL1_REGION_SIZE))
        } else {
            None
        };
        let (region_gpa, offset, region_len) = region.ok_or_else(|| {
            fail(format!(
                "host readiness batch outside supervisor region: {address:#x}"
            ))
        })?;
        if !address
            .is_multiple_of(core::mem::align_of::<carrick_el1_abi::HostReadinessEntry>() as u64)
        {
            return Err(fail("host readiness batch outside supervisor region"));
        }
        let gpa = checked_readiness_region(region_gpa, offset, length, region_len)
            .ok_or_else(|| fail("host readiness batch outside supervisor region"))?;
        let ptr = self
            .custody
            .ram
            .host_ptr(gpa, length)
            .ok_or_else(|| fail("host readiness batch has no backing"))?
            .cast::<carrick_el1_abi::HostReadinessEntry>();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| fail("host readiness batch allocation failed"))?;
        for index in 0..count {
            // SAFETY: the checked span contains `count` aligned records. The
            // stopped task owns this batch; no Rust reference to guest RAM is
            // created while another vCPU may access the physical backing.
            entries.push(unsafe { core::ptr::read_volatile(ptr.add(index)) });
        }
        let result = use_entries(&mut entries);
        for (index, entry) in entries.into_iter().enumerate() {
            // SAFETY: the same checked span remains live through this stopped
            // carrier service; the write publishes only the staged record.
            unsafe { core::ptr::write_volatile(ptr.add(index), entry) };
        }
        Ok(result)
    }

    fn authenticate_initial_copy_page(
        &self,
        output: FrameGpa,
        address: u64,
    ) -> Result<(), MemoryError> {
        let page = output.raw() & !4095;
        let mm_key = self.execution.binding.mm.raw();
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
            .bind(self.execution.context.into())
            .live_mapping_row(MappingId::from_kernel_allocation(identity.mapping_id))
            .ok_or(MemoryError::OutOfBounds { address, length: 1 })?;
        if row.frame != FrameId::from_kernel_allocation(identity.frame_id)
            || row.generation != MappingGeneration::from_backend_counter(identity.owner_generation)
            || page < row.gpa.raw()
            || page.checked_add(4096).is_none_or(|end| {
                row.gpa
                    .raw()
                    .checked_add(row.length.raw())
                    .is_none_or(|limit| end > limit)
            })
        {
            return Err(MemoryError::OutOfBounds { address, length: 1 });
        }
        Ok(())
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> GuestMemory for ForwardVenue<'_, M, Mem> {
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

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> CurrentMmMemory for ForwardVenue<'_, M, Mem> {}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> carrick_guest_arch::CurrentMmMemory
    for ForwardVenue<'_, M, Mem>
{
    fn write_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_arch::UserMemoryFault> {
        carrick_guest_mem::GuestMemory::write_bytes(self, address, bytes)
            .map_err(|_| carrick_guest_arch::UserMemoryFault)
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> carrick_hal::x8664_arch::SegmentBaseRegs
    for ForwardVenue<'_, M, Mem>
{
    type Error = TrapError;
    fn seg_set_fs_base(&mut self, address: u64) -> Result<(), TrapError> {
        self.lease.io.set_fs_base(address)
    }

    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.lease.io.get_fs_base()
    }

    fn seg_set_gs_base(&mut self, address: u64) -> Result<(), TrapError> {
        // FORWARD_PORT stops after SYSCALL's SWAPGS: GS is the kernel CPU
        // binding and KERNEL_GS_BASE holds the user's value until IRET swaps
        // them back. Never replace the live supervisor GS binding here.
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        self.lease.io.write_msr(KERNEL_GS_BASE, address)
    }

    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        self.lease.io.read_msr(KERNEL_GS_BASE)
    }
}

#[cfg(test)]
mod kernel_stack_tests {
    use super::*;

    #[test]
    fn a_saved_task_restores_its_entire_live_cpl0_call_chain() {
        let mut stack = vec![0u8; 256];
        for (index, byte) in stack.iter_mut().enumerate().skip(128) {
            *byte = index as u8;
        }
        let original = stack.clone();
        let slot = carrick_guest_arch::CpuId::new(0);
        let saved =
            unsafe { KernelStackSnapshot::capture(stack.as_ptr(), 0x1000, 0x1100, 0x1080, slot) }
                .expect("valid CPL0 stack");
        stack.fill(0xa5);
        unsafe { saved.restore(stack.as_mut_ptr(), 0x1000, 0x1100, slot) }
            .expect("same physical stack");
        assert_eq!(&stack[128..], &original[128..]);
        assert!(stack[..128].iter().all(|byte| *byte == 0xa5));
        assert!(
            unsafe {
                saved.restore(
                    stack.as_mut_ptr(),
                    0x1000,
                    0x1100,
                    carrick_guest_arch::CpuId::new(1),
                )
            }
            .is_err()
        );
    }
}

#[cfg(test)]
mod initial_reply_tests {
    use super::*;
    use carrick_core_abi::{X86_INITIAL_BOOT_MAGIC, X86_INITIAL_BOOT_VERSION};

    #[test]
    fn shared_physical_staging_rolls_back_before_exposure() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            Arc::default(),
            authority.physical_projection(ids),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .unwrap();
        let grant = staged.grants()[0];
        let bound = Arc::clone(staged.authority());
        let mapping = MappingId::from_kernel_allocation(grant.identity.mapping_id);
        let frame = FrameId::from_kernel_allocation(grant.identity.frame_id);
        let length = FrameLength::from_mapping_extent(NonZeroU64::new(4096).unwrap());
        let before = bound
            .mapping_is_live(
                mapping,
                frame,
                carrick_guest_mem::Gpa::new(grant.gpa.raw()),
                length,
            )
            .unwrap();
        assert!(before);
        drop(staged);
        let after = bound
            .mapping_is_live(
                mapping,
                frame,
                carrick_guest_mem::Gpa::new(grant.gpa.raw()),
                length,
            )
            .unwrap();
        assert!(!after);
    }

    #[test]
    fn unwind_rollback_refusal_returns_control_to_the_carrier_observer() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (inventory, _) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .unwrap();
        authority
            .rollback_unpublished_apply(inventory.receipt.as_ref().unwrap())
            .unwrap();
        let fault = Arc::clone(&inventory.rollback_fault);
        let retained_authority = Arc::downgrade(&inventory.authority);
        drop(inventory);
        assert!(fault.failed());
        assert!(
            retained_authority.upgrade().is_some(),
            "refused rollback must retain its authority and receipt"
        );
        // The carrier observer, rather than this destructor, chooses the
        // existing fail-stop transport after all owned custody is unwound.
    }

    #[test]
    fn refused_initial_rollback_retains_the_exact_physical_receipt() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (mut inventory, _) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
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
                Arc::default(),
                authority.physical_projection(Arc::clone(&ids)),
                [FrameGpa::new(0x2_0000_0000 + index as u64 * 4096)],
                0,
                4096,
                NonZeroU64::MIN,
                carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(NonZeroU64::new(mm.raw()).unwrap()),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                },
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
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
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
                gpa: carrick_guest_mem::Gpa::new(0x2_0000_1000),
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
            authority
                .physical_projection(Arc::clone(&ids))
                .bind(carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY + 1).unwrap()),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                }),
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
            Arc::default(),
            Arc::new(FrameInventoryAuthority::new())
                .physical_projection(Arc::new(ObjectIdRegistry::new())),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
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
                Arc::default(),
                authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
                [FrameGpa::new(0x2_0000_0000)],
                0,
                4096,
                NonZeroU64::MIN,
                carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(
                        NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                    ),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                },
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
            Arc::default(),
            authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
            (0..4).map(|index| FrameGpa::new(base + index * 4096)),
            2,
            4096,
            NonZeroU64::MIN,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .expect("staged exact grants");
        assert_eq!(grants.len(), 4);
        assert_eq!(inventory.frames.len(), 2);
        let rows = authority.snapshot().mappings;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].gpa.raw(), grants[2].gpa);
        assert_eq!(rows[1].gpa.raw(), grants[3].gpa);
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

#[cfg(test)]
mod cpl0_layout_tests {
    use super::*;
    // x86.mm.initial-image: the static PIE load shape observed in busybox:musl.
    // Only ELF headers are needed to prove reservation placement; no VM or
    // backing proportional to the virtual heap/mmap capacity is allocated.
    fn static_pie_elf() -> Vec<u8> {
        let mut bytes = vec![0; 0x200];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN, no PT_INTERP
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x203e5u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&4u16.to_le_bytes());
        for (index, (address, memory_size, flags)) in [
            (0u64, 0x80f0u64, 4u32),
            (0x9000, 0xee36e, 5),
            (0xf8000, 0x328bc, 4),
            (0x12ba70, 0x50c0, 6),
        ]
        .into_iter()
        .enumerate()
        {
            let header = &mut bytes[64 + index * 56..64 + (index + 1) * 56];
            header[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            header[4..8].copy_from_slice(&flags.to_le_bytes());
            header[16..24].copy_from_slice(&address.to_le_bytes());
            if index == 0 {
                header[32..40].copy_from_slice(&0x200u64.to_le_bytes());
            }
            header[40..48].copy_from_slice(&memory_size.to_le_bytes());
            header[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn static_pie_reservations_follow_image_break_above_old_arena_and_stack() {
        let elf = static_pie_elf();
        let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).unwrap();
        let image = carrick_mem::x86_initial_image::prepare_x86_elf(&program).unwrap();
        let initial_break = image.regions.iter().map(|region| region.end).max().unwrap();
        assert_eq!(initial_break, 0x88_0013_1000);
        assert!(initial_break > 0x4000_0000);
        assert!(initial_break > INITIAL_STACK_TOP);
        let layout = initial_reservation_layout(
            UserVa::new(initial_break),
            UserVa::new(INITIAL_STACK_TOP),
            InitialReservationLimits::UNLIMITED,
        )
        .expect("static PIE heap and mmap reservations must follow its loaded image");
        assert_eq!(layout.brk, initial_break);
        assert_eq!(layout.heap.start(), initial_break);
        assert_eq!(layout.heap.end(), layout.arena.start());
        assert_eq!(layout.heap.end(), 0x88_4000_0000);
        assert_eq!(layout.arena.len(), carrick_mem::memory::LINUX_MMAP_SIZE);
        assert!(layout.arena.end() <= carrick_guest_arch::USER_CEILING);
        assert!(
            image
                .regions
                .iter()
                .all(|region| region.end <= layout.heap.start())
        );
        assert!(INITIAL_STACK_TOP <= layout.heap.start());
    }

    #[test]
    fn low_image_reservations_stop_before_stack_and_retain_launch_limits() {
        let limits = InitialReservationLimits {
            address: carrick_abi::LinuxRlimit::new(0x2000_0000, 0x3000_0000),
            data: carrick_abi::LinuxRlimit::new(0x1000_0000, 0x2000_0000),
        };
        let address_limit = limits.address.rlim_cur;
        let data_limit = limits.data.rlim_cur;
        for initial_break in [
            0x40_1000,
            0x2000_0000,
            0x4000_0000,
            0x4000_1000,
            INITIAL_STACK_TOP - INITIAL_STACK_SIZE - 8192,
        ] {
            let layout = initial_reservation_layout(
                UserVa::new(initial_break),
                UserVa::new(INITIAL_STACK_TOP),
                limits,
            )
            .unwrap();
            assert_eq!(layout.brk, initial_break);
            assert_eq!(layout.heap.start(), initial_break);
            assert!(layout.heap.len() <= INITIAL_ARENA_ALIGNMENT);
            // Preserve both capacities for every formerly admitted low image.
            if initial_break < 0x4000_0000 {
                assert_eq!(layout.heap.len(), 0x4000_0000 - initial_break);
                assert_eq!(
                    layout.arena.len(),
                    INITIAL_STACK_TOP - INITIAL_STACK_SIZE - 0x4000_0000
                );
            }
            assert_eq!(layout.heap.end(), layout.arena.start());
            assert_eq!(layout.arena.end(), INITIAL_STACK_TOP - INITIAL_STACK_SIZE);
            assert_eq!(layout.address_limit, address_limit);
            assert_eq!(layout.data_limit, data_limit);
            assert_eq!(layout.external_address_bytes, 0);
            assert_eq!(layout.external_data_bytes, 0);
        }
    }

    #[test]
    fn initial_reservations_refuse_stack_collision_unaligned_and_exhausted_ranges() {
        let stack_base = INITIAL_STACK_TOP - INITIAL_STACK_SIZE;
        for initial_break in [
            0x40_1001,
            stack_base - 4096,
            stack_base,
            stack_base + 4096,
            carrick_guest_arch::USER_CEILING - 4096,
            carrick_guest_arch::USER_CEILING,
            u64::MAX - 4095,
        ] {
            assert!(
                initial_reservation_layout(
                    UserVa::new(initial_break),
                    UserVa::new(INITIAL_STACK_TOP),
                    InitialReservationLimits::UNLIMITED,
                )
                .is_err(),
                "invalid break {initial_break:#x} must not publish reservations"
            );
        }
        for stack_top in [
            0,
            INITIAL_STACK_SIZE - 4096,
            INITIAL_STACK_TOP + 1,
            u64::MAX,
        ] {
            assert!(
                initial_reservation_layout(
                    UserVa::new(0x40_1000),
                    UserVa::new(stack_top),
                    InitialReservationLimits::UNLIMITED,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn high_image_arena_is_bounded_by_canonical_user_end() {
        for (initial_break, arena_len) in [
            (
                carrick_guest_arch::USER_CEILING - INITIAL_ARENA_ALIGNMENT - 4096,
                INITIAL_ARENA_ALIGNMENT,
            ),
            (carrick_guest_arch::USER_CEILING - 8192, 4096),
        ] {
            let layout = initial_reservation_layout(
                UserVa::new(initial_break),
                UserVa::new(INITIAL_STACK_TOP),
                InitialReservationLimits::UNLIMITED,
            )
            .unwrap();
            assert_eq!(layout.heap.start(), initial_break);
            assert_eq!(layout.heap.end(), layout.arena.start());
            assert_eq!(layout.heap.len(), 4096);
            assert_eq!(layout.arena.len(), arena_len);
            assert_eq!(layout.arena.end(), carrick_guest_arch::USER_CEILING);
        }
    }

    #[test]
    fn cpl0_supervisor_image_extent_ordering_alignment_and_nonoverlap() {
        assert_eq!(IMAGE_GPA, carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA);
        assert_eq!(IMAGE_SIZE, carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE);
        assert_eq!(IMAGE_SIZE, 0x20_0000); // 2 MiB

        // Page alignment for image and layout structures
        assert!(IMAGE_GPA.is_multiple_of(4096));
        assert!(IMAGE_SIZE.is_power_of_two());
        assert!(IMAGE_SIZE.is_multiple_of(4096));
        assert!(LAYOUT.gdt_base.is_multiple_of(4096));
        assert!(LAYOUT.pml4_base.is_multiple_of(4096));

        // Strict non-overlap: image ends at or before fixture process tables (0x30_0000)
        const { assert!(IMAGE_GPA + IMAGE_SIZE <= 0x30_0000) };
        // Image exclusive end <= GDT base
        const { assert!(IMAGE_GPA + IMAGE_SIZE <= LAYOUT.gdt_base) };
        // Ordering: GDT base < PML4 base < fault structures < metadata
        const { assert!(LAYOUT.gdt_base < LAYOUT.pml4_base) };
        assert!(LAYOUT.pml4_base + carrick_x86::X86_PML4_CAPACITY as u64 <= META_GPA);

        let stub_start = carrick_x86::fault_stub_base(LAYOUT);
        let stub_end = carrick_x86::fault_tss_base(LAYOUT);
        let idt_base = carrick_x86::fault_idt_base(LAYOUT);
        assert!(IMAGE_GPA + IMAGE_SIZE <= idt_base);
        assert!(idt_base < stub_start);
        assert!(stub_start < stub_end);
        assert!(stub_end < META_GPA);
    }
}

pub use crate::cpl0_private_witness::PrivateAnonymousMmEvidence;

pub struct BootstrapFileRegion(RetainedFileRegion);
impl BootstrapFileRegion {
    /// # Safety
    /// `backing` must cover the entire writable binding extent and remain
    /// exclusively unpublished during initialization: no other registration,
    /// guest or table reference may access it. Its mapping must remain live
    /// until this registration is dropped.
    pub unsafe fn initialize(
        backing: Arc<BackingExtent>,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<Self, TrapError> {
        let host = backing
            .host_base()
            .map_err(|error| fail(error.to_string()))?;
        let mapped = NonNull::new(host.raw() as *mut u8).ok_or_else(|| fail("null file region"))?;
        // SAFETY: this unpublished extent is exclusively initialized here and
        // retained with its registration in the same non-cloneable owner.
        let registration =
            unsafe { carrick_el1_abi::FileRegionRegistration::initialize(mapped, binding) }
                .map_err(|error| fail(format!("file region publication: {error:?}")))?;
        Ok(Self(RetainedFileRegion {
            registration,
            execution: Arc::new(RwLock::new(())),
            _backing: backing,
        }))
    }
}

/// Linearizes physical teardown against all retained host issuance handles.
struct BirthSourceRevocation(Arc<std::sync::RwLock<bool>>);
impl BirthSourceRevocation {
    fn new() -> Self {
        Self(Arc::new(std::sync::RwLock::new(true)))
    }
    fn retire(&self) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }
}
impl Drop for BirthSourceRevocation {
    fn drop(&mut self) {
        self.retire();
    }
}

#[derive(::core::clone::Clone)]
struct PhysicalBirthSource {
    live: Arc<std::sync::RwLock<bool>>,
    _ram: Arc<GuestRam>,
    zone: NonNull<X86Cpl0Zone>,
    identity: carrick_hal::birth_serial::BirthSourceIdentity,
}
impl core::fmt::Debug for PhysicalBirthSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PhysicalBirthSource")
            .field(&self.identity)
            .finish()
    }
}
impl PhysicalBirthSource {
    fn new(
        ram: Arc<GuestRam>,
        identity: carrick_hal::birth_serial::BirthSourceIdentity,
        live: Arc<std::sync::RwLock<bool>>,
    ) -> Result<Self, carrick_hal::birth_serial::BirthSourceError> {
        use carrick_hal::birth_serial::BirthSourceError;
        let pointer = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or(BirthSourceError::StaleOwner)?;
        if !(pointer as usize).is_multiple_of(core::mem::align_of::<X86Cpl0Zone>()) {
            return Err(BirthSourceError::StaleOwner);
        }
        let zone =
            NonNull::new(pointer.cast::<X86Cpl0Zone>()).ok_or(BirthSourceError::StaleOwner)?;
        Ok(Self {
            _ram: ram,
            zone,
            identity,
            live,
        })
    }
    fn with_zone<T>(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
        op: impl FnOnce(&X86Cpl0Zone) -> T,
    ) -> Result<T, carrick_hal::birth_serial::BirthSourceError> {
        use carrick_hal::birth_serial::BirthSourceError;
        let live = self.live.read().map_err(|_| BirthSourceError::StaleOwner)?;
        if expected != &self.identity || !*live {
            return Err(BirthSourceError::StaleOwner);
        }
        // SAFETY: physical bootstrap initialized this zone in immutable windows;
        // the owning Arc<GuestRam> retains every mapped byte through this borrow.
        Ok(op(unsafe { self.zone.as_ref() }))
    }
}
// SAFETY: zone is derived once from the retained initialized GuestRam. Only
// its atomic issuer is accessed, under the physical-custody revocation guard.
unsafe impl Send for PhysicalBirthSource {}
unsafe impl Sync for PhysicalBirthSource {}
impl carrick_hal::birth_serial::BirthSerialSource for PhysicalBirthSource {
    fn identity(&self) -> &carrick_hal::birth_serial::BirthSourceIdentity {
        &self.identity
    }
    fn allocate_mm(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
    ) -> Result<carrick_guest_arch::MmGeneration, carrick_hal::birth_serial::BirthSourceError> {
        self.with_zone(expected, |zone| zone.mm_issuer().allocate())?
            .ok_or(carrick_hal::birth_serial::BirthSourceError::Exhausted)
    }
    fn adopt_initial_mm(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
        high_water: carrick_guest_arch::MmGeneration,
    ) -> Result<(), carrick_hal::birth_serial::BirthSourceError> {
        if self.with_zone(expected, |zone| zone.mm_issuer().adopt_initial(high_water))? {
            Ok(())
        } else {
            Err(carrick_hal::birth_serial::BirthSourceError::StaleOwner)
        }
    }
    fn allocate(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
    ) -> Result<NonZeroU64, carrick_hal::birth_serial::BirthSourceError> {
        self.with_zone(expected, |zone| zone.serial_issuer().allocate())?
            .ok_or(carrick_hal::birth_serial::BirthSourceError::Exhausted)
    }
    fn adopt_initial(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
        high_water: NonZeroU64,
    ) -> Result<(), carrick_hal::birth_serial::BirthSourceError> {
        if self.with_zone(expected, |zone| {
            zone.serial_issuer().adopt_initial(high_water)
        })? {
            Ok(())
        } else {
            Err(carrick_hal::birth_serial::BirthSourceError::StaleOwner)
        }
    }
    fn advance_past(
        &self,
        expected: &carrick_hal::birth_serial::BirthSourceIdentity,
        issued: NonZeroU64,
    ) -> Result<(), carrick_hal::birth_serial::BirthSourceError> {
        self.with_zone(expected, |zone| zone.serial_issuer().advance_past(issued))
    }
}

pub struct BootstrapCustody<M: CarrierMemoryIo>(Cpl0HostCustody<M>);

impl<M: CarrierMemoryIo> BootstrapCustody<M> {
    pub fn new(
        memory: CarrierMemory<M>,
        ram: Arc<GuestRam>,
        initial_extent: Option<(BackingHandle, usize)>,
        kernel_region: Option<BackingHandle>,
        files: BootstrapFileRegion,
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
    ) -> Result<Self, TrapError> {
        let metadata_base = RetainedMetadataPtr(
            NonNull::new(
                ram.host_ptr(META_GPA, META_LEN as usize)
                    .ok_or_else(|| fail("retained metadata backing"))?,
            )
            .ok_or_else(|| fail("null metadata backing"))?,
        );
        let fork_stock = carrick_hal::fork_stock::ForkStock::new(
            memory.identity().nonzero(),
            carrick_hal::fork_stock::ForkControlCapacity::unused(KERNEL_REGION_GPA),
            carrick_hal::fork_stock::UntaggedRoots,
        );
        Ok(Self(Cpl0HostCustody {
            _vm: memory,
            ram,
            birth_live: BirthSourceRevocation::new(),
            initial_extent,
            _kernel_region: kernel_region,
            files: files.0,
            frame_inventory,
            private_anonymous_witness: Default::default(),
            actual_run: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
            kernel_pod_storage,
            initial_inventory: None,
            initial_rollback_fault: Arc::default(),
            peer_entry: None,
            peer_admission: InitialPeerAdmission::Cold,
            initial_task: None,
            prepare_table_stock: None,
            fork_stock,
            maintenance_root: None,
            anonymous_next_gpa: FrameGpa::new(0x2_0000_0000),
            anonymous_pending: [None, None],
            owner_grant_crossings: 0,
            root_exit_crossings: 0,
            child_retire_crossings: 0,
            run_failure_crossings: 0,
            metadata_base,
            host_forwards: 0,
            idle_peer_forwards: 0,
            host_yields: 0,
            kicks: 0,
            work_exits: 0,
        }))
    }
    pub fn memory(&self) -> &CarrierMemory<M> {
        &self.0._vm
    }
    pub fn memory_mut(&mut self) -> &mut CarrierMemory<M> {
        &mut self.0._vm
    }
    pub fn ram(&self) -> &Arc<GuestRam> {
        &self.0.ram
    }
    pub fn frame_inventory(&self) -> &Arc<dyn PhysicalFrameInventory> {
        &self.0.frame_inventory
    }
    /// Available only while this stopped bootstrap owns the initialized zone.
    pub fn birth_serial_source(
        &self,
    ) -> Result<Arc<dyn carrick_hal::birth_serial::BirthSerialSource>, TrapError> {
        let identity = carrick_hal::birth_serial::BirthSourceIdentity::from_backend_identity(
            self.0._vm.clone_vm(),
            self.0._vm.identity().nonzero(),
            NonZeroU64::MIN,
        );
        let source =
            PhysicalBirthSource::new(self.0.ram.clone(), identity, self.0.birth_live.0.clone())
                .map_err(|error| fail(format!("physical birth source: {error}")))?;
        Ok(Arc::new(source))
    }
    pub fn initial_task(&self) -> Option<InitialTaskBinding> {
        self.0.initial_task
    }
    pub fn set_initial_task(&mut self, task: InitialTaskBinding) {
        self.0.initial_task = Some(task);
    }
    pub fn initial_inventory_custody(&self) -> bool {
        self.0.initial_inventory.as_ref().is_some_and(|initial| {
            Arc::ptr_eq(&self.0.frame_inventory, &initial.source)
                && initial.frames.len() == initial.expected
                && initial.frames.iter().all(|(_, identity)| {
                    initial
                        .authority
                        .live_mapping_row(MappingId::from_kernel_allocation(identity.mapping_id))
                        .is_some()
                })
        })
    }
    pub fn has_initial_inventory(&self) -> bool {
        self.0.initial_inventory.is_some()
    }
    pub fn retain_initial_inventory(&mut self, inventory: InitialInventory) {
        self.0.initial_inventory = Some(inventory);
    }
    pub fn rollback_fault(&self) -> Arc<carrick_hal::physical_grants::PhysicalGrantRollback> {
        Arc::clone(&self.0.initial_rollback_fault)
    }
    pub fn initial_extent(&self) -> Option<(BackingHandle, usize)> {
        self.0.initial_extent
    }
    pub fn peer_entry(&self) -> Option<carrick_guest_arch::KernelVa> {
        self.0.peer_entry
    }
    pub fn set_peer_entry(&mut self, entry: carrick_guest_arch::KernelVa) {
        self.0.peer_entry = Some(entry);
    }
    pub fn peer_ready(&self) -> bool {
        self.0.peer_admission == InitialPeerAdmission::Ready
    }
    pub fn admit_peer(&mut self) {
        self.0.peer_admission = InitialPeerAdmission::Ready;
    }
    pub fn seed_prepare_tables(
        &mut self,
        span: anonymous_owner::PrepareTableSpan,
        bytes: &[u8],
    ) -> Result<(), TrapError> {
        self.0.prepare_table_stock = Some(
            anonymous_owner::PrepareTableStock::seed(span, bytes).ok_or_else(|| {
                fail("Prepare working table suffix is not exclusive zero storage")
            })?,
        );
        Ok(())
    }
    pub fn actual_run(&self) -> &Arc<[AtomicU32; 2]> {
        &self.0.actual_run
    }
    pub fn file_execution(&self) -> &Arc<RwLock<()>> {
        &self.0.files.execution
    }
    pub fn file_region_binding(&self) -> carrick_el1_abi::FileRegionBinding {
        self.0.files.registration.binding()
    }
    pub fn file_tables(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<StoppedFileTables<'_>, carrick_el1_abi::FileRegionError> {
        self.0.file_tables(binding)
    }
    pub fn fixture_file_mutation_active(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<bool, carrick_el1_abi::FileRegionError> {
        Ok(self.0.files.registration.tables(binding)?.fd_map()[0].mutation_active())
    }
    pub fn retire_file_region(&mut self) {
        self.0.files.registration.retire();
    }
    pub fn maintenance_root(&self) -> Option<RootGpa> {
        self.0.maintenance_root
    }
    pub fn bind_grant_portal(&self) -> Result<(), TrapError> {
        self.0.bind_grant_portal()
    }
    pub fn install_fork_stock(
        &mut self,
        root: RootGpa,
        unused: Vec<RootGpa>,
    ) -> Result<(), TrapError> {
        self.0.install_fork_stock(root, unused)
    }
    pub fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.0.fork_stock_counters()
    }
    pub fn anonymous_private_pages(&self) -> u64 {
        self.0.private_anonymous_witness.private_pages()
    }
    pub fn host_forwards(&self) -> u64 {
        self.0.host_forwards
    }
    pub fn host_yields(&self) -> u64 {
        self.0.host_yields
    }
    pub fn kicks(&self) -> u64 {
        self.0.kicks
    }
    pub fn work_exits(&self) -> u64 {
        self.0.work_exits
    }
    pub fn record_host_forward(&mut self) {
        self.0.host_forwards += 1;
    }
    pub fn record_host_yield(&mut self) {
        self.0.host_yields += 1;
    }
    pub fn record_kick(&mut self) {
        self.0.kicks += 1;
    }
    pub fn record_work_exit(&mut self) {
        self.0.work_exits += 1;
    }
    pub fn physical_crossing_counts(&self) -> [(PhysicalCrossingFamily, u64); 4] {
        [
            (
                PhysicalCrossingFamily::OwnerGrant,
                self.0.owner_grant_crossings,
            ),
            (PhysicalCrossingFamily::RootExit, self.0.root_exit_crossings),
            (
                PhysicalCrossingFamily::ChildRetire,
                self.0.child_retire_crossings,
            ),
            (
                PhysicalCrossingFamily::RunFailure,
                self.0.run_failure_crossings,
            ),
        ]
    }
    /// # Safety
    /// The stopped bootstrap owner must select an initialized, aligned record
    /// at `offset`, and retain exclusive access for non-atomic mutations.
    pub unsafe fn metadata<T>(&self, offset: u64) -> &T {
        self.0.metadata(offset)
    }
    /// # Safety
    /// The stopped bootstrap owner must select an initialized, aligned record
    /// at `offset`, and retain exclusive access for the returned borrow.
    pub unsafe fn metadata_mut<T>(&mut self, offset: u64) -> &mut T {
        // SAFETY: the caller upholds the record initialization, alignment, and
        // exclusive-access contract; the borrow cannot outlive this custody.
        unsafe { &mut *self.0.metadata_base.0.as_ptr().add(offset as usize).cast() }
    }
}

#[cfg(test)]
static_assertions::assert_impl_all!(RetainedMetadataPtr: Send);
#[cfg(test)]
static_assertions::assert_not_impl_any!(RetainedMetadataPtr: Clone, Sync);
#[cfg(test)]
static_assertions::assert_impl_all!(Cpl0HostCustody<crate::carrier_memory::test_support::MemoryTestIo>: Send);
#[cfg(test)]
static_assertions::assert_not_impl_any!(Cpl0HostCustody<crate::carrier_memory::test_support::MemoryTestIo>: Clone, Sync);

#[cfg(test)]
mod birth_source_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use carrick_hal::birth_serial::{BirthSerialSource, BirthSourceError, BirthSourceIdentity};
    fn source() -> (BirthSourceRevocation, PhysicalBirthSource) {
        let mut ram = GuestRam::new();
        ram.add_window(
            META_GPA,
            (carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>() + 4095)
                & !4095,
            crate::guest_ram::WindowKind::Shared,
        )
        .unwrap();
        let ram = Arc::new(ram);
        let revocation = BirthSourceRevocation::new();
        let identity = BirthSourceIdentity::from_backend_identity(
            ram.clone(),
            NonZeroU64::MIN,
            NonZeroU64::MIN,
        );
        let source = PhysicalBirthSource::new(ram, identity, revocation.0.clone()).unwrap();
        (revocation, source)
    }
    #[test]
    fn physical_birth_source_retains_bytes_but_refuses_retired_custody() {
        let (custody, source) = source();
        let weak_backing = Arc::downgrade(&source._ram);
        assert_eq!(source.allocate(source.identity()).unwrap().get(), 1);
        assert_eq!(
            source.allocate_mm(source.identity()).unwrap().raw(),
            NonZeroU64::MIN
        );
        let peer = source.clone();
        drop(custody); // Same revocation owner as Cpl0HostCustody::drop.
        assert!(weak_backing.upgrade().is_some());
        assert_eq!(
            source.allocate_mm(source.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.adopt_initial_mm(
                peer.identity(),
                carrick_guest_arch::MmGeneration::new(NonZeroU64::MIN)
            ),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            source.allocate(source.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.advance_past(peer.identity(), NonZeroU64::MAX),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.adopt_initial(peer.identity(), NonZeroU64::MIN),
            Err(BirthSourceError::StaleOwner)
        );
        drop(peer);
        drop(source);
        assert!(weak_backing.upgrade().is_none());
    }
    #[test]
    fn physical_birth_source_rejects_another_generation_one_and_live_handoff() {
        let (_first_custody, first) = source();
        let (_second_custody, second) = source();
        assert_ne!(first.identity(), second.identity());
        assert_eq!(
            first.allocate_mm(second.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            first.allocate_mm(first.identity()).unwrap().raw(),
            core::num::NonZeroU64::MIN
        );
        assert!(
            first
                .adopt_initial_mm(
                    first.identity(),
                    carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::MIN)
                )
                .is_err()
        );
        assert_eq!(
            first.allocate(second.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        first
            .adopt_initial(first.identity(), NonZeroU64::new(103).unwrap())
            .unwrap();
        assert_eq!(first.allocate(first.identity()).unwrap().get(), 104);
        assert_eq!(
            first.adopt_initial(first.identity(), NonZeroU64::new(500).unwrap()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(first.allocate(first.identity()).unwrap().get(), 105);
        assert_eq!(second.allocate(second.identity()).unwrap().get(), 1);
    }
}

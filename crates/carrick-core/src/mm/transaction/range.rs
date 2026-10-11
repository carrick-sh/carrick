//! Shared MM authority for explicit address-space reservation and range commit/decommit primitives.
use super::MmError;
use crate::mm::capacity::{ExtentKind, MetadataAllocatorCore};
use crate::mm::publication::{Alias, AliasGeneration, PublicationBook};
use crate::mm::reservation::{
    NeutralReservationGeometry, NeutralReservationPolicy, ReservationGeometry, ReservationPolicy,
    SharedReservations,
};
use carrick_core_abi::{
    Decision, ExtentAccess, GuestLen, Layout, MmIncarnation, MmIncarnationKey, OwnerGeneration,
    PublicationMm, ReservationBackingReceipt, ReservationCompletion, ReservationMm,
    ReservationPolicyPayload, ReservationProtection, ReservationRange, Stage1Ipa, UserVa,
};
use carrick_guest_arch::{EditLeafSize, EditPermissions, FrameGpa};
use carrick_mmu_core::aarch64::{
    LeafAccess, PageTableManager, UserLeafAccess, terminal_descriptor,
    terminal_descriptor_permits_el0, walk_descriptors,
};
use core::num::NonZeroU64;

const EMPTY_RESOLVER: &[(u64, *const u8); 0] = &[];

const HEAP_RANGE: ReservationRange = unsafe { core::mem::transmute([0x1000u64, 0x100000u64]) };
const ARENA_RANGE: ReservationRange =
    unsafe { core::mem::transmute([0x100000u64, 0xffff_ffff_0000u64]) };
const DEFAULT_MM: ReservationMm = unsafe { core::mem::transmute(1u64) };
const DEFAULT_PUB_MM: PublicationMm = PublicationMm::new(NonZeroU64::MIN);
const DEFAULT_INCARNATION: MmIncarnation = MmIncarnation::new(NonZeroU64::MIN);
const DEFAULT_OWNER_GEN: OwnerGeneration = OwnerGeneration::new(NonZeroU64::MIN);
const DEFAULT_ALIAS_GEN: AliasGeneration = AliasGeneration::new(NonZeroU64::MIN);

/// Shared MM authority exposing explicit address-space reservation,
/// commit, and decommit primitives over `SharedReservations`, `PageTableManager`,
/// `PublicationBook`, and `MetadataAllocatorCore`.
pub struct RangeAuthority<
    Policy: ReservationPolicy = NeutralReservationPolicy,
    Geometry: ReservationGeometry = NeutralReservationGeometry,
> {
    table: alloc::boxed::Box<SharedReservations<Policy, Geometry>>,
    mm: ReservationMm,
    pt_manager: PageTableManager,
    allocator: MetadataAllocatorCore,
    book: PublicationBook,
    total_frames: usize,
    frame_pool_base: FrameGpa,
    allocated_frames: alloc::collections::BTreeMap<u64, (u64, *mut u8)>,
    _backing_storage: alloc::vec::Vec<u8>,
}

unsafe impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Send
    for RangeAuthority<Policy, Geometry>
{
}
unsafe impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> Sync
    for RangeAuthority<Policy, Geometry>
{
}

impl RangeAuthority<NeutralReservationPolicy, NeutralReservationGeometry> {
    /// Create a new shared MM range authority initialized for `total_frames` capacity
    /// at `frame_pool_base`.
    pub fn new(
        pt_manager: PageTableManager,
        frame_pool_base: FrameGpa,
        total_frames: usize,
    ) -> Self {
        let table =
            SharedReservations::<NeutralReservationPolicy, NeutralReservationGeometry>::new();
        let mm = DEFAULT_MM;
        let layout = Layout {
            heap: HEAP_RANGE,
            arena: ARENA_RANGE,
            policy: ReservationPolicyPayload::new([0; 5]),
        };
        let _ = table.publish(0, mm, layout);
        if let Ok(mut model) = table.lock(0, mm) {
            let _ = model.finish_import();
        }

        let mut book = PublicationBook::new();
        let key = MmIncarnationKey {
            mm: DEFAULT_PUB_MM,
            incarnation: DEFAULT_INCARNATION,
        };
        book.register_mm(key);

        let mut allocator = MetadataAllocatorCore::new();
        let backing_size = total_frames
            .checked_mul(4096 + 64)
            .and_then(|v| v.checked_add(1024 * 1024))
            .unwrap_or(32 * 1024 * 1024);
        let mut backing_storage = alloc::vec![0u8; backing_size];
        let base_ptr = backing_storage.as_mut_ptr() as u64;
        let _ = allocator.admit_extent(base_ptr, backing_size, ExtentKind::Bootstrap);

        Self {
            table,
            mm,
            pt_manager,
            allocator,
            book,
            total_frames,
            frame_pool_base,
            allocated_frames: alloc::collections::BTreeMap::new(),
            _backing_storage: backing_storage,
        }
    }
}

impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> RangeAuthority<Policy, Geometry> {
    /// Reserve an address-space range without allocating physical backing frames.
    ///
    /// The virtual address span `[va, va + len)` is marked invalid (PROT_NONE)
    /// in the stage-1 page tables and tracked as metadata-only in the reservation
    /// tree with zero physical frames consumed.
    pub fn reserve_range(&mut self, va: UserVa, len: GuestLen) -> Result<(), MmError> {
        let start = va.raw();
        let end = start.checked_add(len.raw()).ok_or(MmError::Invalid)?;
        let range = ReservationRange::new(start, end).ok_or(MmError::Invalid)?;

        let mut root = self.table.lock(0, self.mm).map_err(MmError::from)?;
        let decision = root.reserve_range(range).map_err(MmError::from)?;
        let Decision::Work(request) = decision else {
            return Err(MmError::Invalid);
        };

        if let Err(e) = self
            .pt_manager
            .set_prot_none(start, len.raw() as usize, None)
        {
            let _ = root.refuse(request);
            return Err(MmError::Table(e));
        }

        let receipt = ReservationBackingReceipt {
            receipt: request.sequence.raw(),
            granted_bytes: 0,
            returned_bytes: 0,
        };
        let completion =
            unsafe { ReservationCompletion::after_descriptor_and_backing_commit(request, receipt) }
                .ok_or(MmError::Invalid)?;

        root.complete(completion).map_err(MmError::from)?;
        Ok(())
    }

    /// Commit a sub-range within an address-space reservation, mapping physical frames
    /// with `access` permissions.
    ///
    /// All operations (stage-1 descriptors, stage-2 publication, and frame inventory)
    /// participate in a single atomic rollback-capable transaction.
    pub fn commit_range(
        &mut self,
        va: UserVa,
        len: GuestLen,
        access: UserLeafAccess,
    ) -> Result<(), MmError> {
        let start = va.raw();
        let end = start.checked_add(len.raw()).ok_or(MmError::Invalid)?;
        let range = ReservationRange::new(start, end).ok_or(MmError::Invalid)?;
        let prot = if access.writable {
            ReservationProtection::READ_WRITE
        } else {
            ReservationProtection::READ
        };

        let mut root = self.table.lock(0, self.mm).map_err(MmError::from)?;
        let decision = root.commit_range(range, prot).map_err(MmError::from)?;
        let Decision::Work(request) = decision else {
            return Err(MmError::Invalid);
        };

        self.pt_manager.begin_undo().map_err(MmError::Table)?;

        let page_count = (len.raw() as usize) / 4096;
        if self.allocated_frames.len() + page_count > self.total_frames {
            let _ = unsafe { self.pt_manager.rollback_undo(EMPTY_RESOLVER, None) };
            let _ = root.refuse(request);
            return Err(MmError::NoMemory);
        }

        let mut staged_frames = alloc::vec::Vec::new();
        let mut alloc_failed = false;
        let mut current_va = start;

        for _ in 0..page_count {
            let (ptr_opt, _) = self.allocator.allocate_with_metrics(4096, 4096);
            let Some(ptr) = ptr_opt else {
                alloc_failed = true;
                break;
            };
            let frame_index = self.allocated_frames.len() + staged_frames.len();
            let frame_ipa = self.frame_pool_base.raw() + (frame_index as u64) * 4096;
            staged_frames.push((current_va, frame_ipa, ptr));

            match self
                .pt_manager
                .map_private_aliased(current_va, frame_ipa, 4096, access, None)
            {
                Ok(_) => {}
                Err(_) => {
                    alloc_failed = true;
                    break;
                }
            }
            current_va += 4096;
        }

        if alloc_failed {
            let _ = unsafe { self.pt_manager.rollback_undo(EMPTY_RESOLVER, None) };
            for (_, _, ptr) in staged_frames {
                self.allocator.deallocate_with_metrics(ptr, 4096);
            }
            let _ = root.refuse(request);
            return Err(MmError::NoMemory);
        }

        self.pt_manager.commit_undo();

        let mm_key = NonZeroU64::new(self.mm.raw())
            .map(PublicationMm::new)
            .ok_or(MmError::Invalid)?;
        let inc_key = NonZeroU64::new(root.incarnation().raw())
            .map(MmIncarnation::new)
            .ok_or(MmError::Invalid)?;
        let key = MmIncarnationKey {
            mm: mm_key,
            incarnation: inc_key,
        };
        for (page_va, frame_ipa, ptr) in staged_frames {
            let permissions = EditPermissions {
                readable: true,
                writable: access.writable,
                executable: access.executable,
                user: true,
            };
            let alias = Alias::new(
                Stage1Ipa::new(frame_ipa),
                GuestLen::new(4096),
                EditLeafSize::Page,
                DEFAULT_OWNER_GEN,
                ExtentAccess::Owner,
                permissions,
                permissions,
                true,
                DEFAULT_ALIAS_GEN,
            );
            self.book.add_alias(key, UserVa::new(page_va), alias);
            self.allocated_frames.insert(page_va, (frame_ipa, ptr));
        }

        let receipt = ReservationBackingReceipt {
            receipt: request.sequence.raw(),
            granted_bytes: len.raw(),
            returned_bytes: 0,
        };
        let completion =
            unsafe { ReservationCompletion::after_descriptor_and_backing_commit(request, receipt) }
                .ok_or(MmError::Invalid)?;

        root.complete(completion).map_err(MmError::from)?;
        Ok(())
    }

    /// Decommit a sub-range within an address-space reservation, revoking access
    /// and returning frame custody to capacity while preserving the reservation bounds.
    pub fn decommit_range(&mut self, va: UserVa, len: GuestLen) -> Result<(), MmError> {
        let start = va.raw();
        let end = start.checked_add(len.raw()).ok_or(MmError::Invalid)?;
        let range = ReservationRange::new(start, end).ok_or(MmError::Invalid)?;

        let mut root = self.table.lock(0, self.mm).map_err(MmError::from)?;
        let decision = root.decommit_range(range).map_err(MmError::from)?;
        let Decision::Work(request) = decision else {
            return Err(MmError::Invalid);
        };

        self.pt_manager
            .set_prot_none(start, len.raw() as usize, None)
            .map_err(MmError::Table)?;

        let mm_key = NonZeroU64::new(self.mm.raw())
            .map(PublicationMm::new)
            .ok_or(MmError::Invalid)?;
        let inc_key = NonZeroU64::new(root.incarnation().raw())
            .map(MmIncarnation::new)
            .ok_or(MmError::Invalid)?;
        let key = MmIncarnationKey {
            mm: mm_key,
            incarnation: inc_key,
        };
        let page_count = (len.raw() as usize) / 4096;
        let mut current_va = start;
        for _ in 0..page_count {
            if let Some((_, ptr)) = self.allocated_frames.remove(&current_va) {
                self.book.drop_alias(key, UserVa::new(current_va));
                self.allocator.deallocate_with_metrics(ptr, 4096);
            }
            current_va += 4096;
        }

        let receipt = ReservationBackingReceipt {
            receipt: request.sequence.raw(),
            granted_bytes: 0,
            returned_bytes: len.raw(),
        };
        let completion =
            unsafe { ReservationCompletion::after_descriptor_and_backing_commit(request, receipt) }
                .ok_or(MmError::Invalid)?;

        root.complete(completion).map_err(MmError::from)?;
        Ok(())
    }

    /// Check whether `[va, va + len)` is fully reserved.
    pub fn is_reserved(&self, va: UserVa, len: GuestLen) -> bool {
        let Some(range) = ReservationRange::new(va.raw(), va.raw() + len.raw()) else {
            return false;
        };
        let Ok(mut root) = self.table.lock(0, self.mm) else {
            return false;
        };
        root.is_reserved(range)
    }

    /// Check whether `[va, va + len)` is fully committed.
    pub fn is_committed(&self, va: UserVa, len: GuestLen) -> bool {
        let Some(range) = ReservationRange::new(va.raw(), va.raw() + len.raw()) else {
            return false;
        };
        let Ok(mut root) = self.table.lock(0, self.mm) else {
            return false;
        };
        root.is_committed(range)
    }

    /// Check whether `va` is readable according to stage-1 descriptors.
    pub fn can_read(&self, va: UserVa) -> bool {
        let walk = walk_descriptors(self.pt_manager.as_bytes(), self.pt_manager.base(), va.raw());
        let desc = terminal_descriptor(walk);
        terminal_descriptor_permits_el0(desc, LeafAccess::Read)
    }

    /// Check whether `va` is writable according to stage-1 descriptors.
    pub fn can_write(&self, va: UserVa) -> bool {
        let walk = walk_descriptors(self.pt_manager.as_bytes(), self.pt_manager.base(), va.raw());
        let desc = terminal_descriptor(walk);
        terminal_descriptor_permits_el0(desc, LeafAccess::Write)
    }

    /// Read bytes through stage-1 page translation.
    pub fn read(&self, va: UserVa, buf: &mut [u8]) -> Result<(), MmError> {
        if !self.can_read(va) {
            return Err(MmError::Fault);
        }
        let page_va = va.raw() & !0xfff;
        let offset = (va.raw() & 0xfff) as usize;
        let Some(&(_, ptr)) = self.allocated_frames.get(&page_va) else {
            return Err(MmError::Fault);
        };
        if offset + buf.len() > 4096 {
            return Err(MmError::Invalid);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    /// Write bytes through stage-1 page translation.
    pub fn write(&mut self, va: UserVa, data: &[u8]) -> Result<(), MmError> {
        if !self.can_write(va) {
            return Err(MmError::Fault);
        }
        let page_va = va.raw() & !0xfff;
        let offset = (va.raw() & 0xfff) as usize;
        let Some(&(_, ptr)) = self.allocated_frames.get(&page_va) else {
            return Err(MmError::Fault);
        };
        if offset + data.len() > 4096 {
            return Err(MmError::Invalid);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(offset), data.len());
        }
        Ok(())
    }

    /// Total capacity in 4 KiB frames.
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Number of frames currently committed.
    pub fn allocated_frames(&self) -> usize {
        self.allocated_frames.len()
    }

    /// Number of frames available for commit.
    pub fn free_frames(&self) -> usize {
        self.total_frames
            .saturating_sub(self.allocated_frames.len())
    }

    /// Snapshot of frame capacity allocator diagnostics.
    pub fn capacity_diagnostics(&self) -> crate::mm::capacity::AllocatorDiagnostics {
        self.allocator.diagnostics()
    }

    /// Reference to the publication book.
    pub fn publication_book(&self) -> &PublicationBook {
        &self.book
    }
}

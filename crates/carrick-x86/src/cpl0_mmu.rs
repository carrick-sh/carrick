//! CPL0 x86 adapter hooks for the shared carrick-core MM owner.
//!
//! Provides direct-mapped descriptor words, owner venue, and grant serving
//! dispatch using the shared `X86Mmu` and `carrick-core::mm::frames::serve_grant`.
#![cfg_attr(not(test), allow(dead_code))]

use carrick_core::mm::frames::serve_grant;
use carrick_core::mm::transaction::MmError;
use carrick_core_abi::FrameGrantResidencyTable;
use carrick_el1_abi::MmPortalSlots;
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOutcome, DescriptorRefusal, LiveDescriptorWords,
};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::mm::LinuxReservationPolicy;
use carrick_sched_core::ZoneTables;
use core::sync::atomic::{AtomicU64, Ordering};

// A larger production grant must also enlarge the allocation-free hardware
// adapter storage; the witness requests this exact core ceiling.
const _: () = assert!(
    carrick_mmu_core::x86::descriptor_txn::PlanEntries::INLINE_CAPACITY
        >= (carrick_core_abi::EL1_FRAME_GRANT_TARGET_SIZE / 4096) as usize + 6
);

pub const PROGRESS_RESERVATIONS: u64 = 0x160_0000;
pub const PROGRESS_RESIDENCY: u64 = 0x170_0000;
pub const PROGRESS_PORTAL: u64 = 0x180_0000;
/// Native context sidecars must never alias the residency authority.
pub const OWNER_CONTEXT_BASE: u64 = 0x1b0_0000;
pub const OWNER_CONTEXT_STRIDE: u64 = 4096;
const _: () = assert!(
    core::mem::size_of::<crate::cpl0_scheduler::ContextBinding>() <= OWNER_CONTEXT_STRIDE as usize
);

pub use carrick_core_abi::GuestMetadataPin;

/// Direct supervisor physical descriptor words. In CPL0, page tables
/// are identity-mapped in the supervisor page table range.
pub struct Cpl0DirectWords {
    start: u64,
    end: u64,
}

impl Cpl0DirectWords {
    /// Construct a descriptor view over an identity-mapped supervisor range.
    ///
    /// # Safety
    ///
    /// Every byte in `start..end` must remain mapped, writable, naturally
    /// aligned table memory for the lifetime of the returned view. No host
    /// caller may construct this from guest physical addresses.
    pub unsafe fn from_identity_mapped_range(start: u64, end: u64) -> Option<Self> {
        (start != 0 && start < end && start.is_multiple_of(4096) && end.is_multiple_of(4096))
            .then_some(Self { start, end })
    }

    fn word(&self, pa: u64) -> Result<*const AtomicU64, DescriptorRefusal> {
        if !pa.is_multiple_of(8)
            || pa < self.start
            || pa.checked_add(8).is_none_or(|end| end > self.end)
        {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        Ok(pa as *const AtomicU64)
    }

    pub fn invalidate_range(&self, va: u64, len: u64) {
        for page in (va..va.saturating_add(len)).step_by(4096) {
            crate::cpl0_scheduler::invalidate_page(page);
        }
    }
}

impl LiveDescriptorWords for Cpl0DirectWords {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        Ok(unsafe { (*ptr).load(Ordering::Acquire) })
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        Ok(unsafe {
            (*ptr)
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        let ptr = self.word(pa)?;
        // SAFETY: construction proves the complete word lies in the retained,
        // identity-mapped table-memory view and `word` proves alignment.
        unsafe { (*ptr).store(value, Ordering::Release) };
        Ok(())
    }

    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        Cpl0DirectWords::invalidate_range(self, va, len);
    }
}

use carrick_personality_linux::mm::MmErrorLinux;

// The unqualified static venue is confined to the unsafe CPL0 entry.
// Host guards can obtain only retained HostOwnerBindings access.
struct X86OwnerVenue;

#[cfg(target_os = "none")]
fn request_owner_boundary(
    zone: &ZoneTables,
    slot: carrick_sched_core::SlotId,
    current: bool,
) -> bool {
    let Some(target) = super::adapter::cpu_binding_address(slot) else {
        return false;
    };
    if zone.slot(slot).sgi_target() != target {
        return false;
    }
    // SAFETY: this guest-only adapter accepts only the carrier's fixed,
    // retained supervisor binding interval, qualified at native owner entry.
    // The published target must match this slot, never an arbitrary address.
    let binding = unsafe { &*(target as *const CpuBinding) };
    if binding.self_address != target || binding.slot != u32::from(slot.raw()) {
        return false;
    }
    publish_owner_boundary(binding, current);
    if current {
        return true;
    }
    // The owned queue publication precedes the native execution-lane wake.
    // Busy ICR is returned to the retained carrier boundary, never polled.
    unsafe { crate::interrupts::hardware::send_wake(crate::interrupts::ApicId(slot.raw())) }.is_ok()
}

#[cfg(not(target_os = "none"))]
fn request_owner_boundary(_: &ZoneTables, _: carrick_sched_core::SlotId, _: bool) -> bool {
    // A guest target grants no host pointer or transport authority. The host
    // reservation entry uses HostOwnerBindings and never reaches this hook.
    false
}

fn publish_owner_boundary(binding: &CpuBinding, current: bool) {
    if current {
        binding.return_kick.store(1, Ordering::Release);
    } else {
        binding.entry_kick.store(1, Ordering::Release);
    }
}

/// Retained carrier transport. Queue placement is already complete; this
/// capability only delivers execution-lane wakes and consumes owned handbacks.
#[cfg(not(target_os = "none"))]
pub trait OwnerExecutionTransport: Sync {
    fn wake(&self, slot: carrick_sched_core::SlotId) -> bool;
    fn handbacks(&self, zone: &ZoneTables);
}

/// Host aliases licensed by the carrier's retained backing, never by casting
/// an integer guest address. This capability cannot outlive the carrier borrow.
#[cfg(not(target_os = "none"))]
pub struct HostOwnerBindings<'a> {
    zone: &'a ZoneTables,
    bindings: [&'a CpuBinding; crate::cpl0_entry::CPU_BINDING_COUNT],
}
#[cfg(not(target_os = "none"))]
impl<'a> HostOwnerBindings<'a> {
    /// # Safety
    /// The carrier must retain these host aliases of its exact published guest
    /// binding pages, and the supplied zone, in the same VM for the borrow.
    pub unsafe fn from_retained_bindings(
        zone: &'a ZoneTables,
        bindings: [&'a CpuBinding; crate::cpl0_entry::CPU_BINDING_COUNT],
    ) -> Option<Self> {
        for (index, binding) in bindings.iter().enumerate() {
            let slot = carrick_sched_core::SlotId::new(index as u8);
            if binding.slot != index as u32
                || Some(binding.self_address) != crate::cpl0_entry::cpu_binding_address(slot)
                || zone.slot(slot).sgi_target() != binding.self_address
            {
                return None;
            }
        }
        Some(Self { zone, bindings })
    }
    pub fn binding(&self, slot: carrick_sched_core::SlotId) -> Option<&CpuBinding> {
        self.bindings
            .get(usize::from(slot.raw()))
            .copied()
            .filter(|binding| {
                self.zone.slot(slot).sgi_target() == binding.self_address
                    && binding.slot == u32::from(slot.raw())
            })
    }
    pub fn with_space_access<R>(
        &self,
        boundary: carrick_sched_core::SlotId,
        transport: &impl OwnerExecutionTransport,
        use_access: impl FnOnce(carrick_sched_core::spaces::notification::SpaceAccess<'_>) -> R,
    ) -> R {
        let deliver =
            |zone: &ZoneTables,
             _: carrick_sched_core::Waker,
             effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
                assert!(core::ptr::eq(zone, self.zone));
                deliver_owner_effects_with(
                    boundary,
                    effects,
                    |slot, current| {
                        let Some(binding) = self.binding(slot) else {
                            return false;
                        };
                        publish_owner_boundary(binding, current);
                        current || transport.wake(slot)
                    },
                    |pending| {
                        if let Some(binding) = self.binding(boundary) {
                            binding
                                .pending_owner_wakes
                                .fetch_or(pending, Ordering::Release);
                        }
                    },
                );
                // Host releases already own a carrier boundary and can deliver
                // the existing completion chain without another guest entry.
                transport.handbacks(zone);
            };
        use_access(
            carrick_sched_core::spaces::notification::SpaceAccess::notified(
                carrick_sched_core::spaces::notification::SpaceReleaseVenue {
                    zone: self.zone,
                    waker: carrick_sched_core::Waker::Host,
                    deliver: &deliver,
                },
            ),
        )
    }
}

fn deliver_owner_effects(
    zone: &ZoneTables,
    venue: carrick_sched_core::SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
) {
    deliver_owner_effects_with(
        venue,
        owned,
        |slot, current| request_owner_boundary(zone, slot, current),
        |pending| {
            #[cfg(target_os = "none")]
            if let Some(target) = super::adapter::cpu_binding_address(venue)
                && zone.slot(venue).sgi_target() == target
            {
                // SAFETY: qualified current lane binding retained by native entry.
                let binding = unsafe { &*(target as *const CpuBinding) };
                binding
                    .pending_owner_wakes
                    .fetch_or(pending, Ordering::Release);
            }
            #[cfg(not(target_os = "none"))]
            let _ = pending;
        },
    );
}

fn deliver_owner_effects_with(
    venue: carrick_sched_core::SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    mut request: impl FnMut(carrick_sched_core::SlotId, bool) -> bool,
    mut retain: impl FnMut(u64),
) {
    let (waker, effects, deferred) = owned.defer_handbacks();
    let own = match waker {
        carrick_sched_core::Waker::El1 { slot } => Some(slot),
        carrick_sched_core::Waker::Host => None,
    };
    let mut undelivered = 0u64;
    for slot in effects
        .sgi_slots()
        .chain(own.filter(|slot| effects.queued_own && *slot != venue))
    {
        if !request(slot, slot == venue) {
            undelivered |= 1u64 << slot.raw();
        }
    }
    if undelivered != 0 {
        retain(undelivered);
    }
    if deferred
        || effects.misplaced
        || (effects.queued_own && own == Some(venue))
        || undelivered != 0
    {
        let _ = request(venue, true);
    }
}

impl carrick_core::mm::transaction::OwnerVenue for X86OwnerVenue {
    fn space_access(
        zone: &ZoneTables,
        slot: carrick_sched_core::SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_> {
        fn deliver(
            zone: &ZoneTables,
            waker: carrick_sched_core::Waker,
            effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
        ) {
            if let carrick_sched_core::Waker::El1 { slot } = waker {
                deliver_owner_effects(zone, slot, effects);
            } else {
                let _ = effects.defer_handbacks();
            }
        }
        carrick_sched_core::spaces::notification::SpaceAccess::notified(
            carrick_sched_core::spaces::notification::SpaceReleaseVenue {
                zone,
                waker: carrick_sched_core::Waker::El1 { slot },
                deliver: &deliver,
            },
        )
    }

    fn deliver_completion(
        zone: &ZoneTables,
        slot: carrick_sched_core::SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        deliver_owner_effects(zone, slot, effects);
    }

    fn encode_error(error: MmError) -> u32 {
        error.errno()
    }

    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NativeReservationGeometry;
impl carrick_core::mm::reservation::ReservationGeometry for NativeReservationGeometry {
    const RESERVATIONS_OFFSET: usize = 0x60_0000;
    const ZONE_OFFSET: usize = 0;
    const REGION_BASE: u64 = 0x100_0000;
    const BOOTSTRAP_BASE: u64 = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE;
    const BOOTSTRAP_SIZE: u64 = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE;
    fn authorizes_internal_read(address: u64, len: u64) -> bool {
        carrick_el1_abi::CarrickInternalReadRange::authorizes(address, len)
    }
}
pub type SharedReservations = carrick_core::mm::reservation::SharedReservations<
    LinuxReservationPolicy,
    NativeReservationGeometry,
>;

#[cfg(target_os = "none")]
use super::adapter::CpuBinding;
#[cfg(not(target_os = "none"))]
use crate::cpl0_entry::CpuBinding;

/// Execute a grant submission in CPL0, calling the shared `serve_grant` owner.
/// Returns 0 on success, or Linux errno (e.g. 22 = EINVAL) on refusal/error.
///
/// # Safety
///
/// The caller must be executing the carrier's CPL0 lane. All nonzero
/// metadata addresses in `binding` must name aligned, initialized records
/// mapped in that execution venue, retained for the entire call and every
/// owner callback. The table-memory interval must be page aligned, writable,
/// identity-mapped supervisor table memory, exclusively edited through the
/// shared exact-MM admission. Published wake targets must retain the issued
/// bindings in the same guest venue. Guest addresses are never host pointers.
///
/// An integer-only binding cannot confer these mapping or lifetime rights:
///
/// ```compile_fail,E0133
/// use carrick_x86::{cpl0_entry::CpuBinding, cpl0_mmu::serve_cpl0_grant};
/// fn unqualified_host_call(binding: &CpuBinding) {
///     serve_cpl0_grant(binding, 0);
/// }
/// ```
pub unsafe fn serve_cpl0_grant(binding: &CpuBinding, slot_index: usize) -> u32 {
    binding.entries.fetch_add(1, Ordering::Relaxed);
    if binding.zone_address == 0
        || binding.reservations_address == 0
        || binding.residency_address == 0
        || binding.portal_address == 0
    {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return 22;
    }

    let zone_ptr = binding.zone_address as *const ZoneTables;
    let reservations_addr = binding.reservations_address;
    let residency_addr = binding.residency_address;
    let portal_addr = binding.portal_address;

    // SAFETY: the carrier retains these published supervisor records for the
    // vCPU lifetime and binds their exact mapped addresses before entry.
    let zone = unsafe { &*zone_ptr };
    // SAFETY: the caller qualifies the mapping and retains the
    // correctly aligned shared reservation record at this address.
    let reservations = unsafe { &*(reservations_addr as *const SharedReservations) };
    // SAFETY: the caller qualifies the mapping and retains the
    // correctly aligned residency record at this address.
    let residency = unsafe { &*(residency_addr as *const FrameGrantResidencyTable) };
    // SAFETY: the caller qualifies the mapping and retains the
    // correctly aligned portal slots at this address.
    let portal_slots = unsafe { &*(portal_addr as *const MmPortalSlots) };

    let Some(grant_slot) = portal_slots.grant(slot_index) else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return 22;
    };

    let Some(carrier) = portal_slots.carrier() else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return MmError::Invalid.errno();
    };

    let portal = carrick_core::mm::transaction::MmPortal::<
        GuestMetadataPin,
        LinuxReservationPolicy,
        NativeReservationGeometry,
        X86OwnerVenue,
    >::for_zone(carrier, reservations, zone)
    .with_mmu(X86Mmu);

    // SAFETY: the CPL0 carrier binds only the retained identity-mapped table
    // arena; host builds never call this entry over guest physical addresses.
    let Some(words) = (unsafe {
        Cpl0DirectWords::from_identity_mapped_range(
            binding.table_memory_start,
            binding.table_memory_end,
        )
    }) else {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        return MmError::Invalid.errno();
    };
    let window_opt = grant_slot.window();
    let result = serve_grant(&portal, grant_slot, &words, residency, binding.slot, || {
        if let Some(w) = window_opt {
            words.invalidate_range(w.range.start(), w.range.len());
        }
    });

    match result {
        Ok(Some(receipt)) => {
            if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) {
                binding.publications.fetch_add(1, Ordering::Relaxed);
                binding.completions.fetch_add(1, Ordering::Relaxed);
                0
            } else {
                binding.completions.fetch_add(1, Ordering::Relaxed);
                22
            }
        }
        Ok(None) => {
            binding.completions.fetch_add(1, Ordering::Relaxed);
            300
        }
        Err(err) => {
            binding.completions.fetch_add(1, Ordering::Relaxed);
            err.errno()
        }
    }
}

/// Native descriptor encoding and retained grant classification for the one
/// shared anonymous transaction. No reservation decisions live in this adapter.
pub struct X86AnonymousEditor<'a, W: LiveDescriptorWords + ?Sized> {
    pub words: &'a W,
    pub residency: &'a FrameGrantResidencyTable,
    pub mm: core::num::NonZeroU64,
}
impl<W: LiveDescriptorWords + ?Sized> X86AnonymousEditor<'_, W> {
    fn execute(
        &self,
        register: u64,
        op: carrick_mmu_core::x86::descriptor_txn::DescriptorOp,
    ) -> Result<(), carrick_core::mm::anonymous::DescriptorEditError> {
        use carrick_core::mm::anonymous::DescriptorEditError;
        use carrick_mmu_core::owner_mmu::OwnerMmu;
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOutcome, DescriptorTxn, DescriptorTxnId, execute_retained_descriptor_txn,
        };
        let root = X86Mmu::root(register).map_err(|_| DescriptorEditError::Refused)?;
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: self.mm,
                generation: core::num::NonZeroU64::MIN,
            },
            root,
            op,
            tables: &[],
        };
        match execute_retained_descriptor_txn(self.words, &txn, root).outcome {
            DescriptorOutcome::Applied { .. } => Ok(()),
            DescriptorOutcome::Refused(_) | DescriptorOutcome::RolledBack(_) => {
                Err(DescriptorEditError::Refused)
            }
            DescriptorOutcome::Indeterminate(_) => Err(DescriptorEditError::RollbackFailed),
        }
    }
}
impl<W: LiveDescriptorWords + ?Sized> carrick_core::mm::anonymous::AnonymousDescriptorEditor
    for X86AnonymousEditor<'_, W>
{
    fn backing(
        &mut self,
        root: u64,
        va: u64,
        len: u64,
    ) -> carrick_core::mm::anonymous::Stage1Backing {
        use carrick_core::mm::anonymous::{ForeignBacking, RangeBacking, Stage1Backing};
        use carrick_mmu_core::x86::descriptor_txn::{ADDRESS, COW, HUGE, PREPARED, PRESENT};
        let malformed = Stage1Backing::foreign(ForeignBacking::Malformed);
        let Some(end) = va.checked_add(len) else {
            return malformed;
        };
        if !va.is_multiple_of(4096) || !len.is_multiple_of(4096) {
            return malformed;
        }
        let mut backing = Stage1Backing::of(RangeBacking::Empty);
        let mut resident = false;
        for page in (va..end).step_by(4096) {
            let mut table = root;
            let mut leaf = None;
            for level in 0..4 {
                let Ok(word) = self
                    .words
                    .load(table + ((page >> (39 - level * 9)) & 511) * 8)
                else {
                    return malformed;
                };
                if level == 3 {
                    leaf = Some(word);
                    break;
                }
                if word == 0 {
                    break;
                }
                if word & PRESENT == 0 || word & HUGE != 0 {
                    return Stage1Backing::foreign(ForeignBacking::Block);
                }
                table = word & ADDRESS;
            }
            let Some(word) = leaf.filter(|word| *word != 0) else {
                continue;
            };
            let Some(grant) = self.residency.lookup(self.mm.get(), page) else {
                return Stage1Backing::foreign(ForeignBacking::HostOwnedLeaf);
            };
            if word & ADDRESS != grant.expected_ipa
                || word & (PRESENT | PREPARED) == 0
                || word & COW != 0
            {
                return malformed;
            }
            backing.push(page, page + 4096);
            if backing.summary == RangeBacking::Foreign {
                return backing;
            }
            resident |= word & PRESENT != 0;
        }
        if !backing.runs().is_empty() {
            backing.summary = if resident {
                RangeBacking::Private
            } else {
                RangeBacking::Prepared
            };
        }
        backing
    }
    fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)> {
        let grant = self.residency.lookup(mm_key, va)?;
        Some((
            grant.identity.semantic_base,
            grant.identity.semantic_base + grant.identity.len,
        ))
    }
    fn protect_and_invalidate(
        &mut self,
        root: u64,
        edit: carrick_core::mm::anonymous::PermissionEdit,
    ) -> Result<(), carrick_core::mm::anonymous::DescriptorEditError> {
        use carrick_mmu_core::x86::descriptor_txn::{DescriptorOp, PageSpan, Permissions};
        self.execute(
            root,
            DescriptorOp::Protect {
                span: PageSpan::new(edit.va, edit.len),
                permissions: Permissions {
                    writable: edit.writable,
                    executable: edit.executable,
                    user: edit.readable || edit.writable || edit.executable,
                },
            },
        )
    }
    fn retire_and_invalidate(
        &mut self,
        root: u64,
        address: u64,
        len: u64,
    ) -> Result<(), carrick_core::mm::anonymous::DescriptorEditError> {
        use carrick_mmu_core::x86::descriptor_txn::{DescriptorOp, PageSpan};
        self.execute(root, DescriptorOp::Unmap(PageSpan::new(address, len)))
    }
    fn supports_move(&self) -> bool {
        true
    }
    fn move_and_invalidate(
        &mut self,
        root: u64,
        _mm_key: u64,
        source: carrick_core_abi::ReservationRange,
        destination: carrick_core_abi::ReservationRange,
    ) -> Result<(), carrick_core::mm::anonymous::DescriptorEditError> {
        use carrick_mmu_core::x86::descriptor_txn::{DescriptorOp, PageSpan};
        self.execute(
            root,
            DescriptorOp::Move {
                span: PageSpan::new(destination.start(), destination.len()),
                source: source.start(),
            },
        )
    }
}

/// Native entry must stop the lane on an indeterminate owner publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousEntryResult {
    Served(i64),
    Indeterminate,
}

/// Decode and serve an anonymous native syscall through the production owner.
/// `None` leaves an unsupported/unadmitted route with the ordinary entry.
///
/// # Safety
/// All `serve_cpl0_grant` execution-venue, mapping, alignment and lifetime
/// requirements apply, including the issued current-task record. `words` must
/// faithfully access that retained table arena and complete the native CPU
/// invalidation in this execution lane; it cannot be an independent root view.
/// The entry must stop, without a user return or physical reuse, if the outcome
/// is `Indeterminate`. The bounded carrier fixture has one executing lane per
/// edited MM; this local no-PCID projection does not supply multi-vCPU shootdown.
pub unsafe fn serve_cpl0_anonymous<W: LiveDescriptorWords + ?Sized>(
    binding: &CpuBinding,
    call: carrick_personality_linux::mm::anonymous::AnonymousCall,
    args: [u64; 6],
    words: &W,
) -> Option<AnonymousEntryResult> {
    use carrick_core::mm::anonymous::{AnonymousRefusal, edit_and_commit};
    use carrick_personality_linux::mm::anonymous::{self, AnonymousDecision};
    if binding.zone_address == 0
        || binding.reservations_address == 0
        || binding.residency_address == 0
        || binding.portal_address == 0
        || binding.context_binding_address == 0
    {
        return None;
    }
    // SAFETY: caller retains and qualifies each issued aligned supervisor record.
    let (zone, table, residency, slots, context) = unsafe {
        (
            &*(binding.zone_address as *const ZoneTables),
            &*(binding.reservations_address as *const SharedReservations),
            &*(binding.residency_address as *const FrameGrantResidencyTable),
            &*(binding.portal_address as *const MmPortalSlots),
            &*(binding.context_binding_address as *const crate::cpl0_scheduler::ContextBinding),
        )
    };
    let carrier = slots.carrier()?;
    let native_mm = crate::cpl0_scheduler::context_mm(
        zone,
        carrick_sched_core::SlotId::from_index(binding.slot as usize)?,
        context,
    )
    .ok()?;
    let mm = carrick_core_abi::ReservationMm::new(native_mm.raw().get())?;
    let index = zone.spaces.find(mm.raw())?;
    if !table.admitted(index.index(), mm) {
        return None;
    }
    let portal = carrick_core::mm::transaction::MmPortal::<
        GuestMetadataPin,
        LinuxReservationPolicy,
        NativeReservationGeometry,
        X86OwnerVenue,
    >::for_zone(carrier, table, zone)
    .with_mmu(X86Mmu);
    let serve = || -> Result<Option<AnonymousEntryResult>, MmError> {
        let mut model = portal.root(mm, binding.slot)?;
        let request = match anonymous::decide(call, args, &mut model) {
            AnonymousDecision::Forward => return Ok(None),
            AnonymousDecision::Unavailable(error) => return Err(MmError::Reservation(error)),
            AnonymousDecision::Return(result) => {
                return Ok(Some(AnonymousEntryResult::Served(result)));
            }
            AnonymousDecision::Work(request) => request,
        };
        let access = portal.space_access(binding.slot)?;
        let Some(_grant) = access.grant(index, mm.raw()) else {
            model.refuse(request)?;
            return Err(MmError::Busy);
        };
        let Some(guard) = access.try_begin_edit(
            index,
            mm.raw(),
            core::num::NonZeroU64::new(u64::from(binding.slot) + 1).ok_or(MmError::Invalid)?,
        ) else {
            model.refuse(request)?;
            return Err(MmError::Busy);
        };
        let mut editor = X86AnonymousEditor {
            words,
            residency,
            mm: core::num::NonZeroU64::new(mm.raw()).ok_or(MmError::Stale)?,
        };
        // SAFETY: the issued table arena and retained grant custody are bound
        // to this exact scheduler editor/root in the CPL0 execution venue.
        let mut authority = unsafe {
            carrick_core::mm::anonymous::AnonymousEditAuthority::from_editor(
                &guard,
                &mut editor,
                Some(residency),
            )
        }
        .ok_or(MmError::Stale)?;
        match edit_and_commit(&mut model, request, &mut authority) {
            Ok(result) => {
                binding.publications.fetch_add(1, Ordering::Relaxed);
                Ok(Some(AnonymousEntryResult::Served(result as i64)))
            }
            Err(AnonymousRefusal::RollbackFailed | AnonymousRefusal::CommitAfterEdit(_)) => {
                Ok(Some(AnonymousEntryResult::Indeterminate))
            }
            Err(_) => Ok(Some(AnonymousEntryResult::Served(-12))),
        }
    };
    let result = match serve() {
        Ok(result) => result,
        Err(error) => Some(AnonymousEntryResult::Served(-i64::from(error.errno()))),
    };
    if result.is_some() {
        binding.entries.fetch_add(1, Ordering::Relaxed);
        if matches!(result, Some(AnonymousEntryResult::Served(_))) {
            binding.completions.fetch_add(1, Ordering::Relaxed);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_words_refuse_every_address_outside_the_qualified_view() {
        // SAFETY: the test never accesses the declared fake range; every
        // attempted word is deliberately outside it and must be refused.
        let words = unsafe { Cpl0DirectWords::from_identity_mapped_range(0x2000, 0x3000) }.unwrap();
        for address in [0, 0x1ff8, 0x3000, 0x4000] {
            assert_eq!(
                words.load(address),
                Err(DescriptorRefusal::TableOutsidePrimary)
            );
        }
    }
}

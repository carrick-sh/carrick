//! Carrier physical custody, independent of N1's MM/reservation/permit policy.
//! Dedicated bounded KVM slots project extents, never one slot per page/MM.
//! This preparation has no public vCPU/run handle. The accepted N1 editor must
//! enclose publication and physical rollback; M5 will bind execution admission.
use crate::guest_setup::{GuestRam, WindowKind};
use crate::{KvmVcpu, KvmVm};
use carrick_el1_abi::GuestMmuPublication;
use carrick_guest_arch::{AddressContext, FrameGpa, RootGpa};
use carrick_hal::HvVm;
use carrick_mmu_core::x86::descriptor_txn::*;
use kvm_bindings::kvm_userspace_memory_region;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(::core::fmt::Debug, ::core::clone::Clone, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct MemoryError(pub String);
impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for MemoryError {}
fn inherited_leaf_names(entry: u64, size: u64, gpa: FrameGpa) -> bool {
    let state = entry & (PRESENT | PREPARED);
    (state == PRESENT || state == PREPARED)
        && entry & RETIRED == 0
        && entry & USER != 0
        && size == PAGE
        && entry & ADDRESS == gpa.raw()
}

fn inventory_page_live(
    authority: &dyn carrick_hal::PhysicalFrameInventory,
    mm: NonZeroU64,
    identity: BackingIdentity,
    gpa: FrameGpa,
) -> bool {
    let bound = authority.bind(carrick_guest_arch::MmGeneration::new(mm));
    let Some(row) = bound.live_mapping_row(carrick_hal::MappingId::from_kernel_allocation(
        identity.mapping_id,
    )) else {
        return false;
    };
    gpa.raw().is_multiple_of(PAGE)
        && row.frame == carrick_hal::FrameId::from_kernel_allocation(identity.frame_id)
        && row.generation
            == carrick_hal::MappingGeneration::from_backend_counter(identity.owner_generation)
        && gpa.raw() >= row.gpa.0
        && gpa.raw().checked_add(PAGE).is_some_and(|end| {
            row.gpa
                .0
                .checked_add(row.length.raw())
                .is_some_and(|limit| end <= limit)
        })
}

fn error(message: impl Into<String>) -> MemoryError {
    MemoryError(message.into())
}

/// An unpublished private extent. It can cover many frames/MM aliases; no
/// carrier-wide shared-zero source exists. Bytes are mutable only before Arc
/// custody or through the exclusively stopped carrier.
pub struct BackingExtent {
    ram: Arc<GuestRam>,
    base: FrameGpa,
    len: usize,
}
impl BackingExtent {
    pub fn private(base: FrameGpa, len: usize) -> Result<Self, MemoryError> {
        if len == 0
            || !(len as u64).is_multiple_of(PAGE)
            || base.raw() & !ADDRESS != 0
            || base
                .raw()
                .checked_add(len as u64)
                .is_none_or(|end| end > 1 << 52)
        {
            return Err(error("invalid carrier extent"));
        }
        let mut ram = GuestRam::new();
        ram.add_window(base.raw(), len, WindowKind::Private)
            .map_err(|e| error(e.to_string()))?;
        Ok(Self {
            ram: Arc::new(ram),
            base,
            len,
        })
    }
    pub fn initialize(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(error("extent initialization bounds"));
        }
        Arc::get_mut(&mut self.ram)
            .ok_or_else(|| error("extent already shared"))?
            .write_gpa(self.base.raw() + offset as u64, bytes)
            .map_err(|e| error(e.to_string()))
    }
    fn retained_window(ram: Arc<GuestRam>, base: u64, len: usize) -> Result<Self, MemoryError> {
        if !ram
            .windows_for_kvm()
            .iter()
            .any(|(gpa, _, size)| *gpa == base && *size == len)
        {
            return Err(error("bootstrap window is not retained"));
        }
        Ok(Self {
            ram,
            base: FrameGpa::new(base),
            len,
        })
    }
    fn ptr(&self, pa: u64, len: usize) -> Option<*mut u8> {
        if pa < self.base.raw()
            || pa.checked_add(len as u64)? > self.base.raw().checked_add(self.len as u64)?
        {
            return None;
        }
        self.ram.host_ptr(pa, len)
    }
}
#[derive(::core::clone::Clone)]
pub struct PreparedBacking {
    pub extent: Arc<BackingExtent>,
    pub identity: BackingIdentity,
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct KvmSlotGeneration(NonZeroU64);
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct BackingHandle {
    vm: CarrierVmId,
    slot: u32,
    generation: KvmSlotGeneration,
}
/// Exact carrier VM incarnation. Local MM, frame and slot numbers may repeat
/// in another VM; exported physical capabilities always retain this domain.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct CarrierVmId(NonZeroU64);
impl CarrierVmId {
    fn allocate() -> Result<Self, MemoryError> {
        static CARRIERS: carrick_sched_core::process::identity_allocator::SerialAllocator =
            carrick_sched_core::process::identity_allocator::SerialAllocator::new();
        CARRIERS
            .allocate()
            .map(Self)
            .ok_or_else(|| error("carrier identity exhausted"))
    }
    pub fn nonzero(self) -> NonZeroU64 {
        self.0
    }
}

impl BackingHandle {
    pub fn vm(self) -> CarrierVmId {
        self.vm
    }

    pub fn slot_index(self) -> u32 {
        self.slot
    }
    pub fn generation(self) -> KvmSlotGeneration {
        self.generation
    }
}
/// Explicit sharing capability for this exact physical registration. Cloning
/// it never creates another slot or gives rights to a reused generation.
pub struct SharedFrameEdge {
    handle: BackingHandle,
    identity: BackingIdentity,
}
/// One selected inherited page in this carrier. The source root, physical
/// registration and original inventory identity remain bound to this edge.
/// Creating it neither allocates physical memory nor authorizes another MM.
pub struct InheritedFrameEdge {
    handle: BackingHandle,
    parent: AddressContext<RootGpa>,
    span: PageSpan,
    gpa: FrameGpa,
    identity: BackingIdentity,
    shared: bool,
    resident: bool,
}
impl InheritedFrameEdge {
    /// The selected source named a guest-committed PRESENT leaf. Prepared
    /// storage is retained by the same edge without claiming first touch.
    pub fn is_resident(&self) -> bool {
        self.resident
    }
    pub fn physical(&self) -> FrameGpa {
        self.gpa
    }
    pub fn span(&self) -> PageSpan {
        self.span
    }
    pub fn identity(&self) -> BackingIdentity {
        self.identity
    }
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
struct Alias {
    slot: u32,
    span: PageSpan,
    inherited: Option<FrameGpa>,
}
struct Slot {
    handle: BackingHandle,
    backing: PreparedBacking,
    frame_identities: BTreeMap<u64, BackingIdentity>,
    inherited_identities: BTreeMap<(NonZeroU64, u64), BackingIdentity>,
    bootstrap: bool,
    alias_count: usize,
    allowed: Vec<NonZeroU64>,
    drains: Vec<AddressContext<RootGpa>>,
}

/// N1 supplies the real frame-inventory transaction. publish authenticates
/// readiness before any present leaf; commit settles exact descriptor receipts.
/// Unmap/COW commit may not retire physical owners: InventoryRetirement does
/// that only after every stale context has drained and the slot is revoked.
/// rollback is required even after a partly failing publish/commit. Failure to
/// restore physical or inventory custody quarantines the carrier.
pub trait InventoryTransaction {
    fn publish(&mut self) -> Result<(), MemoryError>;
    fn commit(&mut self, publication: &GuestMmuPublication) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
/// N1's physical inventory retirement, settled only AFTER exact context drain
/// and memslot deletion. A partly failing retire must be fully reversible.
pub trait InventoryRetirement {
    fn retire(&mut self, identity: BackingIdentity) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum Invalidation {
    Invlpg(PageSpan),
    ReloadCr3,
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct ShootdownPlan {
    pub context: AddressContext<RootGpa>,
    pub invalidation: Invalidation,
}
/// # Safety
/// Completion must execute INVLPG or reload CR3 on EVERY CPU/parked lease that
/// could retain this exact context generation. Entry stays excluded throughout.
/// PCID and global pages are forbidden in this preparation. An ioctl finishing
/// memory-slot deletion is never a stage-1 drain acknowledgement.
pub unsafe trait TranslationDrain {
    fn drain(&mut self, plan: ShootdownPlan) -> Result<(), MemoryError>;
}

/// What `CarrierMemory::retire_child` released.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct RetiredChild {
    pub aliases: usize,
    pub revoked_slots: usize,
}

/// Drain for a retired child's own contexts only.
struct QuarantinedContextDrain {
    context: AddressContext<RootGpa>,
}
// SAFETY: constructed only by `retire_child` from a `SlotAbsence` proof: no
// slot runs this MM, every CPU that ran it reloaded CR3 (maintenance root,
// no PCID/PGE) before publishing absence, and the MM can never be installed
// again. Plans for any other context are refused, never acknowledged.
unsafe impl TranslationDrain for QuarantinedContextDrain {
    fn drain(&mut self, plan: ShootdownPlan) -> Result<(), MemoryError> {
        if plan.context.mm == self.context.mm {
            Ok(())
        } else {
            Err(error("retired child slot names a live context"))
        }
    }
}

/// Inventory side of revoking a retired child's private memslot: its
/// frames were retired with the MM, so this only proves none is still live.
struct AlreadyRetiredInventory {
    authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
}
impl InventoryRetirement for AlreadyRetiredInventory {
    fn retire(&mut self, identity: BackingIdentity) -> Result<(), MemoryError> {
        let mapping = carrick_hal::MappingId::from_kernel_allocation(identity.mapping_id);
        if self.authority.live_mapping_row(mapping).is_some() {
            return Err(error("retired child memslot frame is still mapped"));
        }
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        Ok(())
    }
}

/// Drops VM before all registered backing. It exclusively owns its slot
/// namespace; legacy HvVm::map_memory is never called on this VM.
pub struct CarrierMemory {
    identity: CarrierVmId,
    vm: KvmVm,
    slots: BTreeMap<u32, Slot>,
    by_gpa: BTreeMap<u64, u32>,
    free: BTreeSet<u32>,
    aliases: BTreeMap<NonZeroU64, BTreeMap<u64, Alias>>,
    alias_visits: usize,
    roots: BTreeMap<NonZeroU64, AddressContext<RootGpa>>,
    /// Slots each MM is admitted to (`Slot::allowed`), so retiring an MM
    /// never scans every slot.
    admitted: BTreeMap<NonZeroU64, BTreeSet<u32>>,
    /// Slots whose `drains` name a context of each MM (from unlinked
    /// aliases), so a retired MM's drain debt is dropped without a scan.
    drained_by: BTreeMap<NonZeroU64, BTreeSet<u32>>,
    limit: u32,
    generation: u64,
    quarantined: bool,
    #[cfg(test)]
    fail_install: Option<usize>,
}

/// One KVM VM and its retained physical backing for a bounded set of vCPUs.
/// vCPU handles drop before the memory owner and its VM. All CPUs issued by
/// this owner see the same slot namespace; no standalone CPU can be attached.
pub struct CarrierMachine {
    cpus: Vec<KvmVcpu>,
    memory: CarrierMemory,
}

impl CarrierMachine {
    pub fn create_stopped(vcpu_count: usize) -> Result<Self, MemoryError> {
        Self::from_memory(CarrierMemory::create()?, vcpu_count)
    }

    pub(crate) fn from_memory(
        mut memory: CarrierMemory,
        vcpu_count: usize,
    ) -> Result<Self, MemoryError> {
        if vcpu_count == 0 {
            return Err(error("carrier requires at least one vCPU"));
        }
        let mut cpus = Vec::new();
        for _ in 0..vcpu_count {
            cpus.push(memory.vm.add_vcpu().map_err(|e| error(e.to_string()))?);
        }
        Ok(Self { cpus, memory })
    }

    pub fn vcpu_count(&self) -> usize {
        self.cpus.len()
    }

    pub fn memory_mut(&mut self) -> &mut CarrierMemory {
        &mut self.memory
    }

    pub fn cpu_mut(&mut self, index: usize) -> Option<&mut KvmVcpu> {
        self.cpus.get_mut(index)
    }

    pub(crate) fn into_parts(self) -> (Vec<KvmVcpu>, CarrierMemory) {
        (self.cpus, self.memory)
    }
}

impl CarrierMemory {
    pub(crate) fn vm(&self) -> &KvmVm {
        &self.vm
    }

    /// Bootstrap windows are fixed supervisor and initial-task backing. They
    /// use the same slot allocator as later owner-issued guest MM extents.
    pub(crate) fn install_bootstrap(&mut self, ram: Arc<GuestRam>) -> Result<(), MemoryError> {
        let mut backings = Vec::new();
        for (index, (base, _, len)) in ram.windows_for_kvm().into_iter().enumerate() {
            let serial = NonZeroU64::new(index as u64 + 1)
                .ok_or_else(|| error("bootstrap backing serial exhausted"))?;
            backings.push(PreparedBacking {
                extent: Arc::new(BackingExtent::retained_window(Arc::clone(&ram), base, len)?),
                identity: BackingIdentity {
                    frame_id: serial,
                    mapping_id: serial,
                    owner_generation: serial,
                    inventory_revision: serial,
                },
            });
        }
        let handles = self.install(&backings)?;
        for handle in handles {
            let slot = self
                .slots
                .get_mut(&handle.slot)
                .ok_or_else(|| error("bootstrap slot disappeared"))?;
            slot.bootstrap = true;
        }
        Ok(())
    }

    pub fn create() -> Result<Self, MemoryError> {
        let vm = KvmVm::create_empty().map_err(|e| error(e.to_string()))?;
        let limit = vm.carrier_slot_limit().map_err(|e| error(e.to_string()))?;
        Ok(Self {
            identity: CarrierVmId::allocate()?,
            vm,
            slots: BTreeMap::new(),
            by_gpa: BTreeMap::new(),
            free: (0..limit).collect(),
            aliases: BTreeMap::new(),
            alias_visits: 0,
            roots: BTreeMap::new(),
            admitted: BTreeMap::new(),
            drained_by: BTreeMap::new(),
            limit,
            generation: 0,
            quarantined: false,
            #[cfg(test)]
            fail_install: None,
        })
    }
    pub fn identity(&self) -> CarrierVmId {
        self.identity
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
    pub fn retained_bytes(&self) -> usize {
        self.slots.values().map(|s| s.backing.extent.len).sum()
    }
    fn admit(&self) -> Result<(), MemoryError> {
        if self.quarantined {
            Err(error("carrier memory quarantined"))
        } else {
            Ok(())
        }
    }
    fn record(&self, handle: BackingHandle) -> Result<&Slot, MemoryError> {
        self.slots
            .get(&handle.slot)
            .filter(|s| s.handle == handle)
            .ok_or_else(|| error("stale carrier slot generation"))
    }
    fn set_region(&self, slot: u32, backing: Option<&PreparedBacking>) -> Result<(), MemoryError> {
        let region = if let Some(b) = backing {
            kvm_userspace_memory_region {
                slot,
                flags: 0,
                guest_phys_addr: b.extent.base.raw(),
                memory_size: b.extent.len as u64,
                userspace_addr: b
                    .extent
                    .ptr(b.extent.base.raw(), b.extent.len)
                    .ok_or_else(|| error("extent pointer"))? as u64,
            }
        } else {
            kvm_userspace_memory_region {
                slot,
                ..Default::default()
            }
        };
        // SAFETY: retained complete extent; exclusive dedicated slot namespace.
        // Deletion drops nothing until KVM has confirmed it. A failed deletion
        // retains backing until VM destruction and quarantines all future edits.
        unsafe { self.vm.carrier_set_region(region) }.map_err(|e| error(e.to_string()))
    }
    /// Batch physical publication is rollback-capable. No slot ID is burned by
    /// a failed install. Generations are monotonic and never reused/wrapped.
    pub fn install(
        &mut self,
        backings: &[PreparedBacking],
    ) -> Result<Vec<BackingHandle>, MemoryError> {
        self.admit()?;
        if self.slots.len() + backings.len() > self.limit as usize {
            return Err(error("carrier memslot capacity"));
        }
        for (i, b) in backings.iter().enumerate() {
            let start = b.extent.base.raw();
            let end = start + b.extent.len as u64;
            if self.slots.values().any(|s| {
                start < s.backing.extent.base.raw() + s.backing.extent.len as u64
                    && s.backing.extent.base.raw() < end
            }) || backings[..i].iter().any(|s| {
                start < s.extent.base.raw() + s.extent.len as u64 && s.extent.base.raw() < end
            }) {
                return Err(error("overlapping carrier GPA extent"));
            }
        }
        self.generation
            .checked_add(backings.len() as u64)
            .ok_or_else(|| error("carrier slot generation exhausted"))?;
        let mut installed = Vec::new();
        for b in backings {
            let Some(slot) = self.free.first().copied() else {
                return Err(error("carrier memslot capacity"));
            };
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or_else(|| error("carrier slot generation exhausted"))?;
            let generation =
                NonZeroU64::new(self.generation).ok_or_else(|| error("zero slot generation"))?;
            #[cfg(test)]
            let result = if self.fail_install == Some(installed.len()) {
                Err(error("injected slot publication failure"))
            } else {
                self.set_region(slot, Some(b))
            };
            #[cfg(not(test))]
            let result = self.set_region(slot, Some(b));
            if let Err(reason) = result {
                self.rollback_slots(&installed)?;
                return Err(reason);
            }
            let handle = BackingHandle {
                vm: self.identity,
                slot,
                generation: KvmSlotGeneration(generation),
            };
            self.slots.insert(
                slot,
                Slot {
                    handle,
                    backing: b.clone(),
                    frame_identities: BTreeMap::new(),
                    inherited_identities: BTreeMap::new(),
                    bootstrap: false,
                    alias_count: 0,
                    allowed: Vec::new(),
                    drains: Vec::new(),
                },
            );
            self.by_gpa.insert(b.extent.base.raw(), slot);
            self.free.remove(&slot);
            installed.push(handle);
        }
        Ok(installed)
    }
    fn rollback_slots(&mut self, handles: &[BackingHandle]) -> Result<(), MemoryError> {
        for handle in handles.iter().rev() {
            if let Err(reason) = self.set_region(handle.slot, None) {
                self.quarantined = true;
                return Err(error(format!("slot rollback indeterminate: {reason}")));
            }
            if let Some(slot) = self.slots.remove(&handle.slot) {
                self.by_gpa.remove(&slot.backing.extent.base.raw());
            }
            self.free.insert(handle.slot);
        }
        Ok(())
    }
    pub fn install_root(
        &mut self,
        mm: NonZeroU64,
        context: AddressContext<RootGpa>,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        if self.roots.contains_key(&mm)
            || self.roots.values().any(|c| c.root == context.root)
            || context.root.address().raw() == 0
            || !self.contains(context.root.address(), PAGE)
        {
            return Err(error("unbacked or occupied carrier CR3 root"));
        }
        self.roots.insert(mm, context);
        Ok(())
    }
    /// A retired fork child left quarantine (`absence` proves no slot runs
    /// it, and every CPU that ran it reloaded CR3 since). Drop its CR3
    /// registration and every descriptor alias it held (inherited frame
    /// identities with them), then revoke the memslots that were admitted
    /// only for it. Their frames must already be retired from `inventory`;
    /// the revoke checks that rather than retiring them again. Shared slots
    /// keep no drain entry for the retired context.
    ///
    /// Two phases: every precondition (root, alias slots and counts,
    /// admitted slots, and each private slot's revoke preconditions) is
    /// checked before anything mutates, so a refusal leaves the carrier
    /// exactly as it was and the stock's retry is idempotent. After the
    /// checks only the memslot deletion ioctl can fail; that is a host
    /// fault, never guest-reachable, and it quarantines the carrier as every
    /// other indeterminate memslot change does.
    pub fn retire_child(
        &mut self,
        absence: &carrick_hal::fork_stock::SlotAbsence,
        inventory: &dyn carrick_hal::PhysicalFrameInventory,
    ) -> Result<RetiredChild, MemoryError> {
        self.admit()?;
        let mm = NonZeroU64::new(absence.mm().raw()).ok_or_else(|| error("retired MM key"))?;
        let generation = carrick_guest_arch::MmGeneration::new(mm);
        let authority = inventory.bind(generation);
        let context = *self
            .roots
            .get(&mm)
            .ok_or_else(|| error("retired MM has no carrier CR3 root"))?;
        // Phase 1: validate, mutating nothing.
        let mut held: BTreeMap<u32, usize> = BTreeMap::new();
        for alias in self.aliases.get(&mm).into_iter().flat_map(BTreeMap::values) {
            *held.entry(alias.slot).or_default() += 1;
        }
        for (index, count) in &held {
            let slot = self
                .slots
                .get(index)
                .ok_or_else(|| error("retired MM alias names no carrier slot"))?;
            if slot.alias_count < *count {
                return Err(error("retired MM alias count underflow"));
            }
        }
        let mut private = Vec::new();
        for index in self.admitted.get(&mm).into_iter().flatten() {
            let slot = self
                .slots
                .get(index)
                .ok_or_else(|| error("retired MM admitted to no carrier slot"))?;
            let remaining = slot.alias_count - held.get(index).copied().unwrap_or(0);
            if slot.allowed != [mm] || remaining != 0 || slot.bootstrap {
                continue;
            }
            // `revoke`'s preconditions, checked now so the revoke cannot
            // refuse after the bookkeeping below has run.
            let extent = &slot.backing.extent;
            let start = extent.base.raw();
            let end = start + extent.len as u64;
            if self.roots.iter().any(|(owner, root)| {
                *owner != mm && (start..end).contains(&root.root.address().raw())
            }) {
                return Err(error("retired child slot holds a live CR3/table arena"));
            }
            if slot.drains.iter().any(|drained| drained.mm.raw() != mm) {
                return Err(error("retired child slot owes a live context drain"));
            }
            let mapping =
                carrick_hal::MappingId::from_kernel_allocation(slot.backing.identity.mapping_id);
            if authority.live_mapping_row(mapping).is_some() {
                return Err(error("retired child memslot frame is still mapped"));
            }
            private.push(slot.handle);
        }
        // Phase 2: bookkeeping, infallible after the checks above.
        self.roots.remove(&mm);
        let mut aliases = 0;
        for alias in self.aliases.remove(&mm).unwrap_or_default().into_values() {
            if let Some(slot) = self.slots.get_mut(&alias.slot) {
                slot.alias_count -= 1;
                if let Some(gpa) = alias.inherited {
                    slot.inherited_identities.remove(&(mm, gpa.raw()));
                }
            }
            aliases += 1;
        }
        // The absence proof discharges every pending drain of this MM's
        // contexts, so shared slots do not accumulate retired children.
        for index in self.drained_by.remove(&mm).unwrap_or_default() {
            if let Some(slot) = self.slots.get_mut(&index) {
                slot.drains.retain(|drained| drained.mm.raw() != mm);
            }
        }
        for index in self.admitted.remove(&mm).unwrap_or_default() {
            if let Some(slot) = self.slots.get_mut(&index) {
                slot.allowed.retain(|allowed| *allowed != mm);
            }
        }
        // Phase 3: revoke the private slots (only the ioctl can fail).
        let mut drain = QuarantinedContextDrain { context };
        let mut retired = AlreadyRetiredInventory { authority };
        for handle in &private {
            self.revoke(*handle, &mut drain, &mut retired)?;
        }
        Ok(RetiredChild {
            aliases,
            revoked_slots: private.len(),
        })
    }

    pub fn root(&self, mm: NonZeroU64) -> Option<AddressContext<RootGpa>> {
        self.roots.get(&mm).copied()
    }
    /// Bind independently inventoried physical frames inside one KVM extent.
    /// The memslot remains coarse; descriptor outputs authenticate one page.
    pub fn bind_frame_identities(
        &mut self,
        handle: BackingHandle,
        identities: &[(FrameGpa, BackingIdentity)],
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let slot = self.record(handle)?;
        if slot.bootstrap || slot.alias_count != 0 || !slot.frame_identities.is_empty() {
            return Err(error(
                "frame identities require an unpublished private extent",
            ));
        }
        let base = slot.backing.extent.base.raw();
        let end = base + slot.backing.extent.len as u64;
        let mut map = BTreeMap::new();
        for &(gpa, identity) in identities {
            if !gpa.raw().is_multiple_of(PAGE)
                || gpa.raw() < base
                || gpa.raw().checked_add(PAGE).is_none_or(|last| last > end)
                || map.insert(gpa.raw(), identity).is_some()
            {
                return Err(error("invalid or repeated frame inventory identity"));
            }
        }
        self.slots
            .get_mut(&handle.slot)
            .ok_or_else(|| error("missing frame inventory slot"))?
            .frame_identities = map;
        Ok(())
    }
    pub fn share(&self, handle: BackingHandle) -> Result<SharedFrameEdge, MemoryError> {
        let slot = self.record(handle)?;
        if slot.bootstrap || !slot.frame_identities.is_empty() {
            return Err(error("bootstrap backing cannot be shared as guest data"));
        }
        Ok(SharedFrameEdge {
            handle,
            identity: slot.backing.identity,
        })
    }
    pub fn attach_shared(
        &mut self,
        mm: NonZeroU64,
        edge: &SharedFrameEdge,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        if !self.roots.contains_key(&mm)
            || self.record(edge.handle)?.backing.identity != edge.identity
        {
            return Err(error("stale shared-frame edge"));
        }
        let slot = self
            .slots
            .get_mut(&edge.handle.slot)
            .ok_or_else(|| error("missing shared slot"))?;
        if !slot.allowed.contains(&mm) {
            slot.allowed.push(mm);
            self.admitted
                .entry(mm)
                .or_default()
                .insert(edge.handle.slot);
        }
        Ok(())
    }
    fn locate(&self, pa: FrameGpa, len: usize) -> Option<&Slot> {
        let (_, index) = self.by_gpa.range(..=pa.raw()).next_back()?;
        let slot = self.slots.get(index)?;
        slot.backing.extent.ptr(pa.raw(), len)?;
        Some(slot)
    }
    /// Initialize retained boot records before creating any vCPU.
    pub(crate) fn initialize_fault_records(&mut self, region: FrameGpa) -> Result<(), MemoryError> {
        fn record_ptr<T>(memory: &CarrierMemory, pa: FrameGpa) -> Result<*mut T, MemoryError> {
            let slot = memory
                .locate(pa, size_of::<T>())
                .ok_or_else(|| error("boot record bounds"))?;
            let ptr = slot
                .backing
                .extent
                .ptr(pa.raw(), size_of::<T>())
                .ok_or_else(|| error("boot record backing"))?;
            if !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
                return Err(error("boot record alignment"));
            }
            Ok(ptr.cast::<T>())
        }
        let residency = record_ptr::<carrick_el1_abi::FrameGrantResidencyTable>(
            self,
            FrameGpa::new(region.raw() + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET),
        )?;
        let portal = record_ptr::<carrick_el1_abi::MmPortalSlots>(
            self,
            FrameGpa::new(region.raw() + carrick_el1_abi::EL1_MM_PORTAL_OFFSET),
        )?;
        // SAFETY: exclusive boot memory, before CarrierMachine creates vCPUs;
        // both retained records have checked bounds and alignment.
        unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(residency);
            portal.write(carrick_el1_abi::MmPortalSlots::new());
        }
        Ok(())
    }

    /// Borrow an aligned record from retained stage-2 backing.
    ///
    /// # Safety
    /// The caller must have initialized T before this borrow, and must use
    /// atomic fields (or stopped vCPUs) for every concurrent guest access.
    pub(crate) unsafe fn retained_record<T>(&self, pa: FrameGpa) -> Result<&T, MemoryError> {
        let slot = self
            .locate(pa, size_of::<T>())
            .ok_or_else(|| error("retained record bounds"))?;
        let ptr = slot
            .backing
            .extent
            .ptr(pa.raw(), size_of::<T>())
            .ok_or_else(|| error("retained record backing"))?;
        if !(ptr as usize).is_multiple_of(core::mem::align_of::<T>()) {
            return Err(error("retained record alignment"));
        }
        // SAFETY: the caller owns record initialization and concurrency.
        Ok(unsafe { &*ptr.cast::<T>() })
    }

    /// Recover the exact retained identity at a physical page for this MM.
    pub fn frame_identity(
        &self,
        mm: NonZeroU64,
        gpa: FrameGpa,
    ) -> Result<BackingIdentity, MemoryError> {
        let slot = self
            .locate(gpa, PAGE as usize)
            .ok_or_else(|| error("unbacked inherited page"))?;
        let identity = slot
            .inherited_identities
            .get(&(mm, gpa.raw()))
            .copied()
            .or_else(|| slot.frame_identities.get(&gpa.raw()).copied())
            .or_else(|| {
                slot.frame_identities
                    .is_empty()
                    .then_some(slot.backing.identity)
            })
            .ok_or_else(|| error("missing inherited frame identity"))?;
        let op = DescriptorOp::Map {
            span: PageSpan::new(0, PAGE),
            output: gpa,
            permissions: Permissions {
                writable: false,
                executable: false,
                user: true,
            },
            size: LeafSize::Page,
            resident: true,
            backing: identity,
        };
        self.authenticate(mm, op)?;
        Ok(identity)
    }

    /// Retain only physical pages named by the shared fork owner's selection.
    /// The caller excludes parent editors until these edges are attached.
    pub fn select_inherited_frames(
        &self,
        parent: AddressContext<RootGpa>,
        selection: carrick_el1_abi::PortalForkCustody,
        authority: &dyn carrick_hal::PhysicalFrameInventory,
    ) -> Result<Vec<InheritedFrameEdge>, MemoryError> {
        self.admit()?;
        if self.root(parent.mm.raw()) != Some(parent) {
            return Err(error("stale inherited source root"));
        }
        let carrick_el1_abi::PortalForkCustody::Frame {
            va,
            ipa,
            len,
            shared,
        } = selection
        else {
            return Err(error("inheritance requires selected frame custody"));
        };
        if len == 0
            || !va.is_multiple_of(PAGE)
            || !ipa.is_multiple_of(PAGE)
            || !len.is_multiple_of(PAGE)
            || va.checked_add(len).is_none()
            || ipa.checked_add(len).is_none()
        {
            return Err(error("invalid inherited physical span"));
        }
        let mut edges = Vec::new();
        for offset in (0..len).step_by(PAGE as usize) {
            let gpa = FrameGpa::new(ipa + offset);
            let span = PageSpan::new(va + offset, PAGE);
            let identity = self.frame_identity(parent.mm.raw(), gpa)?;
            let slot = self
                .locate(gpa, PAGE as usize)
                .ok_or_else(|| error("inherited registration absent"))?;
            let resident = self
                .named_leaf_resident(parent, span, gpa)
                .ok_or_else(|| error("selected source does not name retained storage"))?;
            if !inventory_page_live(authority, parent.mm.raw(), identity, gpa) {
                return Err(error("selected source is not a live inventoried page"));
            }
            edges.push(InheritedFrameEdge {
                handle: slot.handle,
                parent,
                span,
                gpa,
                identity,
                shared,
                resident,
            });
        }
        Ok(edges)
    }

    /// Attach a selected page after guest-owned child descriptors and its fresh
    /// mapping row exist. Private inheritance also requires both live leaves
    /// to be read-only; guest-owned COW publication must precede attachment.
    /// This creates no memslot and writes no descriptor.
    pub fn attach_inherited_frame(
        &mut self,
        child: AddressContext<RootGpa>,
        edge: &InheritedFrameEdge,
        identity: BackingIdentity,
        receipt: &carrick_hal::FrameInventoryApplyReceipt,
        authority: &dyn carrick_hal::PhysicalFrameInventory,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        self.record(edge.handle)?;
        let mapping = carrick_hal::MappingId::from_kernel_allocation(identity.mapping_id);
        let frame = carrick_hal::FrameId::from_kernel_allocation(identity.frame_id);
        if child.mm == edge.parent.mm
            || self.root(child.mm.raw()) != Some(child)
            || self.root(edge.parent.mm.raw()) != Some(edge.parent)
            || identity.frame_id != edge.identity.frame_id
            || identity.mapping_id == edge.identity.mapping_id
            || identity.owner_generation != NonZeroU64::MIN
            || receipt.mm() != child.mm.raw()
            || receipt.revision() != identity.inventory_revision.get()
            || !receipt.authorizes(mapping, frame)
            || self.frame_identity(edge.parent.mm.raw(), edge.gpa)? != edge.identity
            || !inventory_page_live(authority, edge.parent.mm.raw(), edge.identity, edge.gpa)
            || !inventory_page_live(authority, child.mm.raw(), identity, edge.gpa)
            || !self.leaf_names(edge.parent, edge.span, edge.gpa)
            || !self.leaf_names(child, edge.span, edge.gpa)
            || (!edge.shared
                && (!self.leaf_read_only(edge.parent, edge.span)
                    || !self.leaf_read_only(child, edge.span)))
        {
            return Err(error("stale or unauthenticated inherited physical edge"));
        }
        let end = edge.span.va + PAGE;
        if self.aliases.get(&child.mm.raw()).is_some_and(|aliases| {
            aliases
                .range(..end)
                .next_back()
                .is_some_and(|(_, alias)| alias.span.va + alias.span.len > edge.span.va)
        }) || self
            .record(edge.handle)?
            .inherited_identities
            .contains_key(&(child.mm.raw(), edge.gpa.raw()))
        {
            return Err(error("inherited child alias already occupied"));
        }
        let count = self
            .record(edge.handle)?
            .alias_count
            .checked_add(1)
            .ok_or_else(|| error("inherited physical alias count exhausted"))?;
        let slot = self
            .slots
            .get_mut(&edge.handle.slot)
            .ok_or_else(|| error("missing inherited registration"))?;
        slot.inherited_identities
            .insert((child.mm.raw(), edge.gpa.raw()), identity);
        slot.alias_count = count;
        self.aliases.entry(child.mm.raw()).or_default().insert(
            edge.span.va,
            Alias {
                slot: edge.handle.slot,
                span: edge.span,
                inherited: Some(edge.gpa),
            },
        );
        Ok(())
    }

    fn leaf_read_only(&self, context: AddressContext<RootGpa>, span: PageSpan) -> bool {
        read_terminal_descriptor(
            &self.words(),
            context.root,
            carrick_guest_arch::UserVa::new(span.va),
        )
        .is_ok_and(|(entry, size)| size == PAGE && entry & WRITE == 0)
    }

    fn named_leaf_resident(
        &self,
        context: AddressContext<RootGpa>,
        span: PageSpan,
        gpa: FrameGpa,
    ) -> Option<bool> {
        let (entry, size) = read_terminal_descriptor(
            &self.words(),
            context.root,
            carrick_guest_arch::UserVa::new(span.va),
        )
        .ok()?;
        inherited_leaf_names(entry, size, gpa).then_some(entry & PRESENT != 0)
    }

    fn leaf_names(&self, context: AddressContext<RootGpa>, span: PageSpan, gpa: FrameGpa) -> bool {
        self.named_leaf_resident(context, span, gpa).is_some()
    }

    fn contains(&self, output: FrameGpa, len: u64) -> bool {
        usize::try_from(len)
            .ok()
            .is_some_and(|len| self.locate(output, len).is_some())
    }
    fn authenticate(&self, mm: NonZeroU64, op: DescriptorOp) -> Result<Option<u32>, MemoryError> {
        let (output, identity) = match op {
            DescriptorOp::Map {
                output, backing, ..
            }
            | DescriptorOp::Prepare {
                output, backing, ..
            } => (output, backing),
            DescriptorOp::CowRepoint { new, backing, .. } => (new, backing),
            _ => return Ok(None),
        };
        let slot = self
            .locate(output, op.span().len as usize)
            .ok_or_else(|| error("unbacked descriptor output"))?;
        let inherited = (op.span().len == PAGE)
            .then(|| slot.inherited_identities.get(&(mm, output.raw())))
            .flatten();
        let expected = if let Some(identity) = inherited {
            *identity
        } else if slot.frame_identities.is_empty() {
            slot.backing.identity
        } else {
            if op.span().len != PAGE {
                return Err(error("frame inventory identity requires one-page output"));
            }
            *slot
                .frame_identities
                .get(&output.raw())
                .ok_or_else(|| error("physical frame lacks an inventory identity"))?
        };
        if slot.bootstrap
            || expected != identity
            || (inherited.is_none() && !slot.allowed.is_empty() && !slot.allowed.contains(&mm))
        {
            return Err(error(
                "unauthenticated backing or missing explicit shared-frame edge",
            ));
        }
        Ok(Some(slot.handle.slot))
    }
    /// Validate the root, table grants and physical output before the guest
    /// may execute an edit. No descriptor or inventory state changes here.
    pub fn admit_guest_edit(&self, txn: &DescriptorTxn<'_>) -> Result<(), MemoryError> {
        self.admit()?;
        let context = self
            .root(txn.id.mm_key)
            .filter(|c| c.root == txn.root)
            .ok_or_else(|| error("stale carrier MM/root"))?;
        let arena = self
            .locate(context.root.address(), PAGE as usize)
            .ok_or_else(|| error("unbacked carrier root arena"))?
            .handle;
        if txn.tables.iter().any(|grant| {
            self.locate(grant.address(), PAGE as usize)
                .is_none_or(|slot| slot.handle != arena)
        }) {
            return Err(error("table grant outside retained root arena"));
        }
        self.authenticate(txn.id.mm_key, txn.op)?;
        Ok(())
    }
    /// Publish physical backing and inventory before the guest can make a
    /// present descriptor. A failed preparation rolls both back without ever
    /// entering the guest editor.
    pub fn prepare<I: InventoryTransaction>(
        &mut self,
        backings: &[PreparedBacking],
        inventory: &mut I,
    ) -> Result<Vec<BackingHandle>, MemoryError> {
        let handles = self.install(backings)?;
        if let Err(reason) = inventory.publish() {
            self.rollback_inventory(inventory)?;
            self.rollback_slots(&handles)?;
            return Err(reason);
        }
        Ok(handles)
    }

    /// Cancel a preparation that never reached a guest edit. Any edit refusal
    /// after stores requires the guest's own rollback receipt or quarantine.
    ///
    /// # Safety
    /// The caller holds exact-MM entry exclusion and proves that no guest
    /// descriptor has named any handle in this preparation.
    pub unsafe fn cancel_prepared<I: InventoryTransaction>(
        &mut self,
        handles: &[BackingHandle],
        inventory: &mut I,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        if handles
            .iter()
            .any(|handle| !self.record(*handle).is_ok_and(|slot| slot.alias_count == 0))
        {
            return Err(error("prepared backing already has guest aliases"));
        }
        self.rollback_inventory(inventory)?;
        self.rollback_slots(handles)
    }

    /// Consume a guest-owned publication after the exact-MM edit and local
    /// drain. The caller keeps the editor and entry exclusion until this
    /// record, N1 inventory and subsequent cross-CPU drain have settled.
    /// This method never plans, applies or undoes a guest descriptor.
    pub fn publish<I: InventoryTransaction>(
        &mut self,
        txn: &DescriptorTxn<'_>,
        publication: GuestMmuPublication,
        inventory: &mut I,
    ) -> Result<GuestMmuPublication, MemoryError> {
        self.admit()?;
        if let Err(reason) = self.admit_guest_edit(txn) {
            self.quarantined = true;
            return Err(reason);
        }
        let context = self
            .root(txn.id.mm_key)
            .filter(|c| c.root == txn.root)
            .ok_or_else(|| error("stale carrier MM/root"))?;
        // The guest may already have made its leaf present. Any mismatch now
        // quarantines the carrier and retains all backing; the host has no
        // authority to author an undo descriptor.
        if !publication.matches_x86_txn(txn) {
            self.quarantined = true;
            return Err(error("guest MMU publication transaction identity mismatch"));
        }
        if !self.guest_postcondition(txn) {
            self.quarantined = true;
            return Err(error("guest MMU publication live descriptor mismatch"));
        }
        let target = match self.authenticate(txn.id.mm_key, txn.op) {
            Ok(index) => index,
            Err(reason) => {
                self.quarantined = true;
                return Err(reason);
            }
        };
        if let Err(reason) = inventory.commit(&publication) {
            self.quarantined = true;
            return Err(error(format!(
                "inventory commit after guest edit: {reason}"
            )));
        }
        // Track physical alias edges, not reservations or Linux VMA policy.
        // An old slot may not be revoked while any descriptor still names it.
        // A retired terminal is inaccessible but still names its predecessor
        // for owner scrub. Keep that physical edge until repoint or unlink.
        if matches!(
            txn.op,
            DescriptorOp::Unmap(_) | DescriptorOp::CowRepoint { .. }
        ) {
            self.remove_aliases(txn.id.mm_key, txn.op.span(), context);
            if self.quarantined {
                return Err(error("guest alias publication became indeterminate"));
            }
        }
        if let Some(index) = target {
            let Some(slot) = self.slots.get_mut(&index) else {
                self.quarantined = true;
                return Err(error("missing authenticated slot after guest edit"));
            };
            if slot.allowed.is_empty() {
                slot.allowed.push(txn.id.mm_key);
                self.admitted
                    .entry(txn.id.mm_key)
                    .or_default()
                    .insert(index);
            }
            slot.alias_count += 1;
            self.aliases.entry(txn.id.mm_key).or_default().insert(
                txn.op.span().va,
                Alias {
                    slot: index,
                    span: txn.op.span(),
                    inherited: None,
                },
            );
        }
        Ok(publication)
    }

    /// Read the terminal graph after the guest edit. Only bounded terminal
    /// leaves in the edited span are visited; unrelated branches cost nothing.
    fn guest_postcondition(&self, txn: &DescriptorTxn<'_>) -> bool {
        let span = txn.op.span();
        let Some(end) = span.end() else {
            return false;
        };
        let words = self.words();
        let mut va = span.va;
        while va < end {
            let terminal =
                read_terminal_descriptor(&words, txn.root, carrick_guest_arch::UserVa::new(va));
            let (entry, size) = match terminal {
                Ok(value) => value,
                Err(DescriptorRefusal::MissingTable)
                    if matches!(txn.op, DescriptorOp::Unmap(_) | DescriptorOp::Retire(_)) =>
                {
                    (0, PAGE)
                }
                Err(_) => return false,
            };
            let physical = entry & ADDRESS;
            let expected_base = match txn.op {
                DescriptorOp::Map { output, .. } | DescriptorOp::Prepare { output, .. } => {
                    Some(output.raw())
                }
                DescriptorOp::Publish { expected, .. } => Some(expected.raw()),
                DescriptorOp::CowRepoint { new, .. } => Some(new.raw()),
                _ => None,
            };
            if let Some(base) = expected_base {
                let Some(expected) = base.checked_add(va - span.va) else {
                    return false;
                };
                if physical != expected {
                    return false;
                }
            }
            let valid = match txn.op {
                DescriptorOp::Map {
                    resident,
                    permissions,
                    ..
                } => {
                    (entry & PRESENT != 0) == resident
                        && (entry & PREPARED != 0) != resident
                        && entry & (PRIVATE | MAY_EXEC) == 0
                        && (entry & MAY_WRITE != 0) == permissions.writable
                        && Self::matches_permissions(entry, permissions)
                }
                DescriptorOp::Prepare {
                    resident,
                    permissions,
                    ..
                } => {
                    let live = resident.contains(va);
                    (entry & PRESENT != 0) == live
                        && (entry & PREPARED != 0) != live
                        && entry & PRIVATE != 0
                        && (entry & MAY_WRITE != 0) == permissions.writable
                        && (entry & MAY_EXEC != 0) == permissions.executable
                        && Self::matches_permissions(entry, permissions)
                }
                DescriptorOp::Publish { .. } => entry & PRESENT != 0 && entry & PREPARED == 0,
                DescriptorOp::Protect { permissions, .. } => {
                    entry & (PRESENT | PREPARED) != 0
                        && entry & PRIVATE != 0
                        && (!permissions.writable || entry & MAY_WRITE != 0)
                        && (!permissions.executable || entry & MAY_EXEC != 0)
                        && Self::matches_permissions(entry, permissions)
                }
                DescriptorOp::ArmCow(_) => {
                    entry & (COW | MAY_WRITE) == (COW | MAY_WRITE) && entry & WRITE == 0
                }
                DescriptorOp::CowRepoint { .. } => {
                    entry & PRESENT != 0 && entry & WRITE != 0 && entry & COW == 0
                        || entry & (PRESENT | PREPARED | RETIRED) == RETIRED && entry & ADDRESS != 0
                }
                DescriptorOp::Unmap(_) => entry & (PRESENT | PREPARED) == 0,
                DescriptorOp::Retire(_) => {
                    entry == 0
                        || entry & (PRESENT | PREPARED | RETIRED) == RETIRED
                            && entry & PRIVATE != 0
                            && entry & ADDRESS != 0
                }
                DescriptorOp::Coalesce { size: expected, .. } => {
                    entry & PRESENT != 0 && size == expected.bytes()
                }
            };
            if !valid {
                return false;
            }
            let Some(next) = va.checked_add(size - (va & (size - 1))) else {
                return false;
            };
            va = next.min(end);
        }
        true
    }

    fn matches_permissions(entry: u64, permissions: Permissions) -> bool {
        (entry & USER != 0) == permissions.user
            && (entry & WRITE != 0) == permissions.writable
            && (entry & NX == 0) == permissions.executable
    }
    fn rollback_inventory<I: InventoryTransaction>(
        &mut self,
        inventory: &mut I,
    ) -> Result<(), MemoryError> {
        if let Err(reason) = inventory.rollback() {
            self.quarantined = true;
            return Err(error(format!("inventory rollback indeterminate: {reason}")));
        }
        Ok(())
    }
    fn remove_aliases(&mut self, mm: NonZeroU64, span: PageSpan, context: AddressContext<RootGpa>) {
        self.alias_visits = 0;
        let Some(aliases) = self.aliases.get_mut(&mm) else {
            return;
        };
        let end = span.va + span.len;
        // One predecessor plus only intersecting physical edges. Unrelated
        // reservations/MMs/512 untouched mappings add no population scan.
        let start = aliases
            .range(..=span.va)
            .next_back()
            .map_or(span.va, |(&va, _)| va);
        let affected: Vec<Alias> = aliases
            .range(start..end)
            .filter_map(|(_, a)| {
                if a.span.va + a.span.len > span.va {
                    Some(*a)
                } else {
                    None
                }
            })
            .collect();
        for alias in affected {
            self.alias_visits += 1;
            aliases.remove(&alias.span.va);
            let Some(slot) = self.slots.get_mut(&alias.slot) else {
                self.quarantined = true;
                return;
            };
            slot.alias_count -= 1;
            if let Some(gpa) = alias.inherited {
                slot.inherited_identities.remove(&(mm, gpa.raw()));
            }
            let alias_end = alias.span.va + alias.span.len;
            for remainder in [
                (alias.span.va, span.va.saturating_sub(alias.span.va)),
                (end, alias_end.saturating_sub(end)),
            ] {
                if remainder.1 != 0 {
                    aliases.insert(
                        remainder.0,
                        Alias {
                            slot: alias.slot,
                            span: PageSpan::new(remainder.0, remainder.1),
                            inherited: alias.inherited,
                        },
                    );
                    slot.alias_count += 1;
                }
            }
            if !slot.drains.contains(&context) {
                slot.drains.push(context);
                self.drained_by.entry(mm).or_default().insert(alias.slot);
            }
        }
    }
    /// Delete physical custody only after descriptor unlink and exact-context
    /// acknowledgements. Failure retains the old registration for a later drain;
    /// a failed deletion quarantines, rather than ignoring ioctl errors.
    pub fn revoke<D: TranslationDrain, I: InventoryRetirement>(
        &mut self,
        handle: BackingHandle,
        drain: &mut D,
        inventory: &mut I,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let slot = self.record(handle)?;
        let extent = &slot.backing.extent;
        if self.roots.values().any(|context| {
            context.root.address().raw() >= extent.base.raw()
                && context.root.address().raw() < extent.base.raw() + extent.len as u64
        }) {
            return Err(error("carrier backing retains a published CR3/table arena"));
        }
        if slot.alias_count != 0 {
            return Err(error("carrier backing still has descriptor aliases"));
        }
        for &context in &slot.drains {
            drain.drain(ShootdownPlan {
                context,
                invalidation: Invalidation::ReloadCr3,
            })?;
        }
        let backing = self.record(handle)?.backing.clone();
        if let Err(reason) = self.set_region(handle.slot, None) {
            self.quarantined = true;
            return Err(reason);
        }
        if let Err(reason) = inventory.retire(backing.identity) {
            // Restore physical custody AND the inventory preimage before the
            // owner can reopen entry. Keep the exact old slot generation.
            let physical = self.set_region(handle.slot, Some(&backing));
            let logical = inventory.rollback();
            if physical.is_err() || logical.is_err() {
                self.quarantined = true;
                return Err(error(
                    "physical retirement rollback indeterminate; backing retained",
                ));
            }
            return Err(reason);
        }
        if let Some(slot) = self.slots.remove(&handle.slot) {
            self.by_gpa.remove(&slot.backing.extent.base.raw());
            for mm in &slot.allowed {
                if let Some(slots) = self.admitted.get_mut(mm) {
                    slots.remove(&handle.slot);
                }
            }
        }
        self.free.insert(handle.slot);
        Ok(())
    }
    pub fn read(&self, pa: FrameGpa, len: usize) -> Result<Vec<u8>, MemoryError> {
        self.admit()?;
        let ptr = self
            .locate(pa, len)
            .and_then(|s| s.backing.extent.ptr(pa.raw(), len))
            .ok_or_else(|| error("carrier read bounds"))?;
        // SAFETY: retained backing, all carrier vCPUs stopped by the caller's
        // exclusive editor; no public run handle escapes this preparation.
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
    }
    pub fn write(&mut self, pa: FrameGpa, bytes: &[u8]) -> Result<(), MemoryError> {
        self.admit()?;
        let ptr = self
            .locate(pa, bytes.len())
            .and_then(|s| s.backing.extent.ptr(pa.raw(), bytes.len()))
            .ok_or_else(|| error("carrier write bounds"))?;
        // SAFETY: exclusive stopped custody, retained bounded backing.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
        Ok(())
    }
    pub fn words(&self) -> DescriptorWords<'_> {
        DescriptorWords { memory: self }
    }
}
/// Borrowed hardware words, reused by either a stopped fixture or the accepted
/// N1 exact-MM editor. Invalidation is an owner obligation: no public run API
/// exists here, and a successful descriptor receipt is NOT a drain receipt.
pub struct DescriptorWords<'a> {
    memory: &'a CarrierMemory,
}
impl DescriptorWords<'_> {
    fn atomic(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        if !pa.is_multiple_of(8) {
            return Err(DescriptorRefusal::BadRange);
        }
        let ptr = self
            .memory
            .locate(FrameGpa::new(pa), 8)
            .and_then(|s| s.backing.extent.ptr(pa, 8))
            .ok_or(DescriptorRefusal::MissingTable)?;
        // SAFETY: page-aligned retained mapping; only the exact-MM writer and
        // hardware A/D writers use these atomic words. N1 excludes those CPUs.
        Ok(unsafe { &*ptr.cast::<AtomicU64>() })
    }
}
impl LiveDescriptorWords for DescriptorWords<'_> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        Ok(self.atomic(pa)?.load(Ordering::Acquire))
    }
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        Ok(self
            .atomic(pa)?
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.atomic(pa)?.store(value, Ordering::Release);
        Ok(())
    }
    fn publish_barrier(&self) {
        std::sync::atomic::fence(Ordering::SeqCst);
    }
    fn invalidate_range(&self, _va: u64, _len: u64) {} // Owner's trailing CPL0 drain before any re-entry.
}

pub mod fixture;
#[cfg(test)]
mod tests;

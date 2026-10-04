//! Carrier physical custody, independent of N1's MM/reservation/permit policy.
//! Dedicated bounded KVM slots project extents, never one slot per page/MM.
//! This preparation has no public vCPU/run handle. The accepted N1 editor must
//! enclose publication and physical rollback; M5 will bind execution admission.
use crate::KvmVm;
use crate::guest_setup::{GuestRam, WindowKind};
use carrick_guest_arch::{AddressContext, FrameGpa, RootGpa};
use carrick_mmu_core::x86::descriptor_txn::*;
use kvm_bindings::kvm_userspace_memory_region;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

mod user_transfer;
pub use user_transfer::RetainedX86Data;
static NEXT_VM_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryError(pub String);
impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for MemoryError {}
fn error(message: impl Into<String>) -> MemoryError {
    MemoryError(message.into())
}

/// An unpublished private extent. It can cover many frames/MM aliases; no
/// carrier-wide shared-zero source exists. Bytes are mutable only before Arc
/// custody or through the exclusively stopped carrier.
pub struct BackingExtent {
    ram: GuestRam,
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
        Ok(Self { ram, base, len })
    }
    pub fn initialize(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(error("extent initialization bounds"));
        }
        self.ram
            .write_gpa(self.base.raw() + offset as u64, bytes)
            .map_err(|e| error(e.to_string()))
    }
    fn ptr(&self, pa: u64, len: usize) -> Option<*mut u8> {
        self.ram.host_ptr(pa, len)
    }
}
#[derive(Clone)]
pub struct PreparedBacking {
    pub extent: Arc<BackingExtent>,
    pub identity: BackingIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvmSlotGeneration(NonZeroU64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackingHandle {
    slot: u32,
    generation: KvmSlotGeneration,
}
impl BackingHandle {
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
#[derive(Clone, Copy)]
struct Alias {
    slot: u32,
    span: PageSpan,
}
struct Slot {
    handle: BackingHandle,
    backing: PreparedBacking,
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
    fn commit(&mut self, receipt: &DescriptorReceipt) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
/// N1's physical inventory retirement, settled only AFTER exact context drain
/// and memslot deletion. A partly failing retire must be fully reversible.
pub trait InventoryRetirement {
    fn retire(&mut self, identity: BackingIdentity) -> Result<(), MemoryError>;
    fn rollback(&mut self) -> Result<(), MemoryError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    Invlpg(PageSpan),
    ReloadCr3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Drops VM before all registered backing. It exclusively owns its slot
/// namespace; legacy HvVm::map_memory is never called on this VM.
pub struct CarrierMemory {
    vm: KvmVm,
    vm_generation: NonZeroU64,
    slots: BTreeMap<u32, Slot>,
    by_gpa: BTreeMap<u64, u32>,
    free: BTreeSet<u32>,
    aliases: BTreeMap<NonZeroU64, BTreeMap<u64, Alias>>,
    alias_visits: usize,
    roots: BTreeMap<NonZeroU64, AddressContext<RootGpa>>,
    limit: u32,
    generation: u64,
    quarantined: bool,
    #[cfg(test)]
    fail_install: Option<usize>,
}
impl CarrierMemory {
    pub fn create() -> Result<Self, MemoryError> {
        let vm = KvmVm::create_empty().map_err(|e| error(e.to_string()))?;
        let limit = vm.carrier_slot_limit().map_err(|e| error(e.to_string()))?;
        let generation = NEXT_VM_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| error("carrier backing generation exhausted"))?;
        let vm_generation =
            NonZeroU64::new(generation).ok_or_else(|| error("zero carrier generation"))?;
        Ok(Self {
            vm,
            vm_generation,
            slots: BTreeMap::new(),
            by_gpa: BTreeMap::new(),
            free: (0..limit).collect(),
            aliases: BTreeMap::new(),
            alias_visits: 0,
            roots: BTreeMap::new(),
            limit,
            generation: 0,
            quarantined: false,
            #[cfg(test)]
            fail_install: None,
        })
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
                slot,
                generation: KvmSlotGeneration(generation),
            };
            self.slots.insert(
                slot,
                Slot {
                    handle,
                    backing: b.clone(),
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
    pub fn root(&self, mm: NonZeroU64) -> Option<AddressContext<RootGpa>> {
        self.roots.get(&mm).copied()
    }
    pub fn share(&self, handle: BackingHandle) -> Result<SharedFrameEdge, MemoryError> {
        let slot = self.record(handle)?;
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
        }
        Ok(())
    }
    fn locate(&self, pa: FrameGpa, len: usize) -> Option<&Slot> {
        let (_, index) = self.by_gpa.range(..=pa.raw()).next_back()?;
        let slot = self.slots.get(index)?;
        slot.backing.extent.ptr(pa.raw(), len)?;
        Some(slot)
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
            } => (output, backing),
            DescriptorOp::CowRepoint { new, backing, .. } => (new, backing),
            _ => return Ok(None),
        };
        let slot = self
            .locate(output, op.span().len as usize)
            .ok_or_else(|| error("unbacked descriptor output"))?;
        if slot.backing.identity != identity
            || (!slot.allowed.is_empty() && !slot.allowed.contains(&mm))
        {
            return Err(error(
                "unauthenticated backing or missing explicit shared-frame edge",
            ));
        }
        Ok(Some(slot.handle.slot))
    }
    /// Descriptors, memslots, and N1's inventory settle together. The caller
    /// holds the accepted exact-MM editor and entry exclusion until this returns
    /// and completes the queued CPL0 drain. COW bytes are copied by N1 before
    /// this hardware repoint, never by a second private COW policy here.
    pub fn publish<I: InventoryTransaction>(
        &mut self,
        txn: &DescriptorTxn<'_>,
        backings: &[PreparedBacking],
        inventory: &mut I,
    ) -> Result<(DescriptorReceipt, Vec<BackingHandle>), MemoryError> {
        self.admit()?;
        let context = self
            .root(txn.id.mm_key)
            .filter(|c| c.root == txn.root)
            .ok_or_else(|| error("stale carrier MM/root"))?;
        // Like the ARM primary-table window, grants share the retained root
        // arena. This keeps stage-1 hierarchy custody tied to a live root and
        // prevents a data-slot revoke from tearing out reachable table pages.
        let arena = self
            .locate(context.root.address(), PAGE as usize)
            .ok_or_else(|| error("unbacked carrier root arena"))?
            .handle;
        if txn.tables.iter().any(|g| {
            self.locate(g.address(), PAGE as usize)
                .is_none_or(|slot| slot.handle != arena)
        }) {
            return Err(error("table grant outside the retained root arena"));
        }
        let plan = plan_descriptor_txn(&self.words(), txn, context.root)
            .map_err(|e| error(format!("descriptor plan: {e:?}")))?;
        let handles = self.install(backings)?;
        let target = match self.authenticate(txn.id.mm_key, txn.op) {
            Ok(index) => index,
            Err(reason) => {
                self.rollback_slots(&handles)?;
                return Err(reason);
            }
        };
        if let Err(reason) = inventory.publish() {
            self.rollback_inventory(inventory)?;
            self.rollback_slots(&handles)?;
            return Err(reason);
        }
        let receipt = apply_descriptor_plan(&self.words(), &plan, &mut InlineJournal::new());
        if !matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) {
            if matches!(receipt.outcome, DescriptorOutcome::Indeterminate(_)) {
                self.quarantined = true;
                return Err(error("indeterminate descriptor rollback; backing retained"));
            }
            self.rollback_inventory(inventory)?;
            self.rollback_slots(&handles)?;
            return Err(error(format!(
                "descriptor publication: {:?}",
                receipt.outcome
            )));
        }
        if let Err(reason) = inventory.commit(&receipt) {
            if !matches!(
                rollback_descriptor_plan(&self.words(), &plan),
                DescriptorOutcome::RolledBack(_)
            ) {
                self.quarantined = true;
                return Err(error("indeterminate descriptor undo; backing retained"));
            }
            self.rollback_inventory(inventory)?;
            self.rollback_slots(&handles)?;
            return Err(reason);
        }
        // Track physical alias edges, not reservations or Linux VMA policy.
        // An old slot may not be revoked while any descriptor still names it.
        if matches!(
            txn.op,
            DescriptorOp::Unmap(_) | DescriptorOp::CowRepoint { .. }
        ) {
            self.remove_aliases(txn.id.mm_key, txn.op.span(), context);
        }
        if let Some(index) = target {
            let slot = self
                .slots
                .get_mut(&index)
                .ok_or_else(|| error("missing authenticated slot"))?;
            if slot.allowed.is_empty() {
                slot.allowed.push(txn.id.mm_key);
            }
            slot.alias_count += 1;
            self.aliases.entry(txn.id.mm_key).or_default().insert(
                txn.op.span().va,
                Alias {
                    slot: index,
                    span: txn.op.span(),
                },
            );
        }
        Ok((receipt, handles))
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
                        },
                    );
                    slot.alias_count += 1;
                }
            }
            if !slot.drains.contains(&context) {
                slot.drains.push(context);
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

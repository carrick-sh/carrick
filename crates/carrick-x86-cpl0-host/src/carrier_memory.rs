//! Carrier physical custody, independent of N1's MM/reservation/permit policy.
//! Dedicated bounded hardware slots project extents, never one slot per page/MM.
//! This preparation has no public vCPU/run handle. The accepted N1 editor must
//! enclose publication and physical rollback; M5 will bind execution admission.
use crate::guest_ram::{GuestRam, WindowKind};
use carrick_core::mm::own::{DrainContext, HoldError, MmKey, SlotHolds};
use carrick_el1_abi::GuestMmuPublication;
use carrick_guest_arch::{AddressContext, FrameGpa, RootGpa};
pub use carrick_mmu_core::x86::descriptor_txn::BackingIdentity;
use carrick_mmu_core::x86::descriptor_txn::*;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct CarrierMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

pub trait CarrierMemoryIo: Send + Sync + 'static {
    fn carrier_slot_limit(&self) -> Result<u32, carrick_hal::OsError>;
    /// Register a user memory region in the carrier.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `region.userspace_addr` points to valid, accessible
    /// host memory of at least `region.memory_size` bytes that remains valid for the
    /// lifetime of the mapping.
    unsafe fn set_user_memory_region(
        &self,
        region: CarrierMemoryRegion,
    ) -> Result<(), carrick_hal::OsError>;
    fn signal_msi(&self, address_lo: u32, data: u32) -> Result<(), carrick_hal::OsError>;

    /// Report a successful host write to retained RAM before the stopped
    /// carrier may reenter. Hardware carriers need no software cache update.
    fn host_wrote_ram(&self, _start: FrameGpa, _len: usize) {}
}

#[derive(::core::fmt::Debug, ::core::clone::Clone, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct MemoryError(pub String);
impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for MemoryError {}

#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub enum InheritedFrameSelectionError {
    MappingGone,
    Invariant(MemoryError),
}

impl From<MemoryError> for InheritedFrameSelectionError {
    fn from(error: MemoryError) -> Self {
        Self::Invariant(error)
    }
}
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
    owner: carrick_hal::GuestFrameOwner,
    identity: BackingIdentity,
    gpa: FrameGpa,
) -> bool {
    let bound = authority.bind(owner);
    let Some(row) = bound.live_mapping_row(carrick_hal::MappingId::from_kernel_allocation(
        identity.mapping_id,
    )) else {
        return false;
    };
    // Physical identity (including physical owner generation) is authenticated
    // against the physical frame authority (CarrierMemory::frame_identity).
    // MappingGeneration tracks virtual mapping mutations/protections in the
    // inventory and must never be conflated with the physical owner generation.
    gpa.raw().is_multiple_of(PAGE)
        && row.frame == carrick_hal::FrameId::from_kernel_allocation(identity.frame_id)
        && gpa.raw() >= row.gpa.raw()
        && gpa.raw().checked_add(PAGE).is_some_and(|end| {
            row.gpa
                .raw()
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
enum ExtentStorage {
    Ram(Arc<GuestRam>),
    Ipc {
        owner: Arc<dyn carrick_el1_abi::IpcWindowBacking>,
        part: IpcWindowPart,
    },
    /// One chunk of a host file's page cache (#1338 shared file window):
    /// guest stores through the slot are the file's bytes, so there is no
    /// copy and nothing to write back.
    HostFile(HostFileMapping),
}

/// A retained host `mmap(MAP_SHARED)` of one file range, unmapped when the
/// extent that owns it drops. The mapping keeps the file's pages alive on
/// its own; the descriptor it was made from may close.
struct HostFileMapping {
    host: core::ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is a plain shared host range with no thread affinity;
// all access goes through the carrier's own custody checks.
unsafe impl Send for HostFileMapping {}
// SAFETY: as above; the carrier never hands out a `&mut` to the bytes.
unsafe impl Sync for HostFileMapping {}

impl Drop for HostFileMapping {
    fn drop(&mut self) {
        // SAFETY: `host`/`len` name exactly the live mapping this value owns,
        // made once by `BackingExtent::host_file_window` and never shared.
        unsafe { libc::munmap(self.host.as_ptr().cast(), self.len) };
    }
}

/// Which allocation of the original IPC authority this extent retains.
#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub enum IpcWindowPart {
    Directory,
    Pool,
}

pub struct BackingExtent {
    storage: ExtentStorage,
    pub base: FrameGpa,
    pub len: usize,
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
            storage: ExtentStorage::Ram(Arc::new(ram)),
            base,
            len,
        })
    }
    /// Retain the original IPC allocation without copying it or assuming
    /// ownership of its deallocator. The authority must retain stable writable
    /// pointers, as required by `IpcWindowBacking`'s carrier mapping contract.
    pub fn ipc_window(
        base: FrameGpa,
        owner: Arc<dyn carrick_el1_abi::IpcWindowBacking>,
        part: IpcWindowPart,
    ) -> Result<Self, MemoryError> {
        let (ptr, len) = match part {
            IpcWindowPart::Directory => (owner.directory_ptr(), owner.directory_len()),
            IpcWindowPart::Pool => (owner.pool_ptr(), owner.pool_len()),
        };
        if ptr.is_null()
            || !(ptr as usize).is_multiple_of(PAGE as usize)
            || len == 0
            || !(len as u64).is_multiple_of(PAGE)
            || base.raw() & !ADDRESS != 0
            || base
                .raw()
                .checked_add(len as u64)
                .is_none_or(|end| end > 1 << 52)
        {
            return Err(error("invalid retained IPC extent"));
        }
        Ok(Self {
            storage: ExtentStorage::Ipc { owner, part },
            base,
            len,
        })
    }

    /// Retain one range of a host file as a live shared extent (#1338): a
    /// host `mmap(MAP_SHARED)` of `len` bytes at `file_offset`, so the slot
    /// projects the file's page cache. Only offsets the window record admits
    /// below the file's size may ever be published from it: a host access
    /// past EOF is a host `SIGBUS`, never a guest one.
    pub fn host_file_window(
        base: FrameGpa,
        file: std::os::fd::BorrowedFd<'_>,
        file_offset: u64,
        len: usize,
    ) -> Result<Self, MemoryError> {
        use std::os::fd::AsRawFd;
        if len == 0
            || !(len as u64).is_multiple_of(PAGE)
            || !file_offset.is_multiple_of(PAGE)
            || base.raw() & !ADDRESS != 0
            || base
                .raw()
                .checked_add(len as u64)
                .is_none_or(|end| end > 1 << 52)
        {
            return Err(error("invalid host-file window extent"));
        }
        let offset = libc::off_t::try_from(file_offset)
            .map_err(|_| error("host-file window offset exceeds off_t"))?;
        // SAFETY: a fresh shared mapping of a caller-borrowed descriptor,
        // checked against MAP_FAILED before it is retained.
        let host = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                offset,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(error(format!(
                "host-file window mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let host = core::ptr::NonNull::new(host.cast::<u8>())
            .ok_or_else(|| error("host-file window mmap returned null"))?;
        Ok(Self {
            storage: ExtentStorage::HostFile(HostFileMapping { host, len }),
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
        let ExtentStorage::Ram(ram) = &mut self.storage else {
            return Err(error(
                "a retained IPC or host-file authority cannot be initialized as private RAM",
            ));
        };
        Arc::get_mut(ram)
            .ok_or_else(|| error("extent already shared"))?
            .write_gpa(self.base.raw() + offset as u64, bytes)
            .map_err(|e| error(e.to_string()))
    }
    fn retained_window(ram: Arc<GuestRam>, base: u64, len: usize) -> Result<Self, MemoryError> {
        if !ram
            .slot_windows()
            .iter()
            .any(|(gpa, _, size)| *gpa == base && *size == len)
        {
            return Err(error("bootstrap window is not retained"));
        }
        Ok(Self {
            storage: ExtentStorage::Ram(ram),
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
        match &self.storage {
            ExtentStorage::Ram(ram) => ram.host_ptr(pa, len),
            ExtentStorage::Ipc { owner, part } => {
                let ptr = match part {
                    IpcWindowPart::Directory => owner.directory_ptr(),
                    IpcWindowPart::Pool => owner.pool_ptr(),
                };
                // SAFETY: the retained authority owns this complete allocation;
                // the extent bounds were checked above.
                Some(unsafe { ptr.add((pa - self.base.raw()) as usize) })
            }
            // SAFETY: the owned mapping covers exactly `self.len` bytes from
            // `self.base`; the extent bounds were checked above.
            ExtentStorage::HostFile(mapping) => {
                Some(unsafe { mapping.host.as_ptr().add((pa - self.base.raw()) as usize) })
            }
        }
    }

    /// A shared file window chunk (#1338): kept for the run, never private.
    pub(crate) fn is_host_file_window(&self) -> bool {
        matches!(self.storage, ExtentStorage::HostFile(_))
    }

    /// Host view of this retained extent; never a guest VA or a GPA.
    pub(crate) fn host_base(&self) -> Result<carrick_guest_mem::HostVa, MemoryError> {
        self.ptr(self.base.raw(), self.len)
            .map(|ptr| carrick_guest_mem::HostVa::new(ptr as usize))
            .ok_or_else(|| error("retained extent host mapping"))
    }

    pub fn read_unpublished(&self, pa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let ptr = self.ptr(pa, len).ok_or_else(|| error("extent range"))?;
        // SAFETY: the retained extent authenticates this complete range; the
        // returned vector does not expose its mutable host address.
        Ok(unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec())
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
pub struct CarrierSlotGeneration(NonZeroU64);
/// The physical backing owner generation in the carrier memory domain.
/// This typed generation represents physical backing ownership and must
/// not be conflated or cross-fed with [`carrick_hal::MappingGeneration`],
/// which tracks virtual mapping protections/mutations.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::core::cmp::PartialOrd,
    ::core::cmp::Ord,
    ::core::hash::Hash,
)]
pub struct PhysicalOwnerGeneration(NonZeroU64);

impl PhysicalOwnerGeneration {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    pub const fn from_counter(counter: NonZeroU64) -> Self {
        Self(counter)
    }

    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}
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
    generation: CarrierSlotGeneration,
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
pub struct CarrierVmId(carrick_core::mm::own::CarrierId);
impl CarrierVmId {
    /// One identity for the VM and its memory-ownership core (#3061).
    fn allocate() -> Result<Self, MemoryError> {
        carrick_core::mm::own::CarrierId::allocate()
            .map(Self)
            .ok_or_else(|| error("carrier identity exhausted"))
    }
    pub fn nonzero(self) -> NonZeroU64 {
        self.0.raw()
    }
    /// The carrier's memory-ownership core identity.
    pub fn carrier(self) -> carrick_core::mm::own::CarrierId {
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
    pub fn generation(self) -> CarrierSlotGeneration {
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

/// One parent shared file window leaf a fork child keeps (#1338). It names
/// the window slot and the parent root it was read from; it owns no frame
/// and carries no inventory identity.
pub struct InheritedWindowEdge {
    handle: BackingHandle,
    parent: AddressContext<RootGpa>,
    span: PageSpan,
    gpa: FrameGpa,
}
impl InheritedWindowEdge {
    pub fn span(&self) -> PageSpan {
        self.span
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
    /// A chunk of one MM's copy-on-write replacement arena (#3099): its
    /// pages authenticate only through `frame_identities`, one grant at a
    /// time, never through the slot's own backing identity.
    arena: bool,
    bootstrap: bool,
}

/// The context a slot's drain debt names (#3127): a slot is held until
/// every context that unlinked an alias into it drains.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
struct SlotDrain(AddressContext<RootGpa>);
impl DrainContext for SlotDrain {
    fn mm(&self) -> MmKey {
        MmKey::new(self.0.mm.raw())
    }
}
fn key(mm: NonZeroU64) -> MmKey {
    MmKey::new(mm)
}
fn hold_error(reason: HoldError) -> MemoryError {
    error(format!("carrier slot holds: {reason:?}"))
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
/// frames were retired with the MM, so this only proves no MM, of any
/// owner, still maps one.
struct AlreadyRetiredInventory<'a> {
    inventory: &'a dyn carrick_hal::PhysicalFrameInventory,
}
impl InventoryRetirement for AlreadyRetiredInventory<'_> {
    fn retire(&mut self, identity: BackingIdentity) -> Result<(), MemoryError> {
        if self
            .inventory
            .frame_is_mapped(carrick_hal::FrameId::from_kernel_allocation(
                identity.frame_id,
            ))
        {
            return Err(error("retired child memslot frame is still mapped"));
        }
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), MemoryError> {
        Ok(())
    }
}

/// Maximum shared host-file window slots per carrier run (`2048 * 2 MiB = 4 GiB`),
/// bounding both KVM memslots and host `mmap` VMA count well below OS limits.
pub const MAX_WINDOW_SLOTS: usize = 2048;
const WINDOW_SLOT_NON_WINDOW_HEADROOM: usize = 512;

/// Typed admission token reserving carrier window slots at `mmap(MAP_SHARED)` time
/// so first touch never discovers memslot exhaustion (#1338, #2975).
#[derive(::core::fmt::Debug)]
#[must_use = "WindowSlotBudget must be consumed by CarrierMemory::install_window_slots"]
pub struct WindowSlotBudget {
    identity: CarrierVmId,
    generation: u64,
    slots: usize,
}

impl WindowSlotBudget {
    pub fn slots(&self) -> usize {
        self.slots
    }
}

/// Drops VM before all registered backing. It exclusively owns its slot
/// namespace; legacy HvVm::map_memory is never called on this VM.
pub struct CarrierMemory<M: CarrierMemoryIo> {
    identity: CarrierVmId,
    vm: Arc<M>,
    slots: BTreeMap<u32, Slot>,
    by_gpa: BTreeMap<u64, u32>,
    free: BTreeSet<u32>,
    window_slots: usize,
    aliases: BTreeMap<NonZeroU64, BTreeMap<u64, Alias>>,
    alias_visits: usize,
    roots: BTreeMap<NonZeroU64, AddressContext<RootGpa>>,
    /// Who holds each slot: admissions, descriptor aliases and drain debts
    /// (#3127). A slot is revoked by the retirement that drops its last
    /// hold, and only then; nothing else decides which slots to revoke.
    holds: SlotHolds<u32, SlotDrain>,
    limit: u32,
    /// The most memslots this carrier held at once (#3099 witness).
    peak_slots: usize,
    generation: u64,
    quarantined: bool,
}

impl<M: CarrierMemoryIo> CarrierMemory<M> {
    pub fn vm(&self) -> &M {
        &self.vm
    }

    pub fn with_unique_vm_mut<R>(&mut self, f: impl FnOnce(&mut M) -> R) -> Option<R> {
        Arc::get_mut(&mut self.vm).map(f)
    }

    pub(crate) fn clone_vm(&self) -> Arc<M> {
        Arc::clone(&self.vm)
    }

    /// Bootstrap windows are fixed supervisor and initial-task backing. They
    /// use the same slot allocator as later owner-issued guest MM extents.
    pub fn install_bootstrap(&mut self, ram: Arc<GuestRam>) -> Result<(), MemoryError> {
        let mut backings = Vec::new();
        for (index, (base, _, len)) in ram.slot_windows().into_iter().enumerate() {
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

    pub fn new(vm: M) -> Result<Self, MemoryError> {
        let limit = vm.carrier_slot_limit().map_err(|e| error(e.to_string()))?;
        Ok(Self {
            identity: CarrierVmId::allocate()?,
            vm: Arc::new(vm),
            slots: BTreeMap::new(),
            by_gpa: BTreeMap::new(),
            free: (0..limit).collect(),
            window_slots: 0,
            aliases: BTreeMap::new(),
            alias_visits: 0,
            roots: BTreeMap::new(),
            holds: SlotHolds::new(),
            limit,
            peak_slots: 0,
            generation: 0,
            quarantined: false,
        })
    }
    pub fn identity(&self) -> CarrierVmId {
        self.identity
    }

    pub fn quarantine(&mut self) {
        self.quarantined = true;
    }

    fn window_headroom(limit: u32) -> usize {
        (limit as usize / 4).clamp(1, WINDOW_SLOT_NON_WINDOW_HEADROOM)
    }

    pub fn window_slots(&self) -> usize {
        self.window_slots
    }

    pub fn available_window_slots(&self) -> usize {
        if self.quarantined {
            return 0;
        }
        let free_cap = self
            .free
            .len()
            .saturating_sub(Self::window_headroom(self.limit));
        let window_cap = MAX_WINDOW_SLOTS.saturating_sub(self.window_slots);
        free_cap.min(window_cap)
    }

    pub fn admit_window_slots(&self, count: usize) -> Option<WindowSlotBudget> {
        if count > self.available_window_slots()
            || self.generation.checked_add(count as u64).is_none()
        {
            return None;
        }
        Some(WindowSlotBudget {
            identity: self.identity,
            generation: self.generation,
            slots: count,
        })
    }

    pub fn install_window_slots(
        &mut self,
        budget: WindowSlotBudget,
        backings: &[PreparedBacking],
    ) -> Result<Vec<BackingHandle>, MemoryError> {
        if budget.identity != self.identity || budget.generation != self.generation {
            return Err(error("stale window slot budget"));
        }
        if backings.len() != budget.slots {
            return Err(error("window slot budget length mismatch"));
        }
        if !backings.iter().all(|b| b.extent.is_host_file_window()) {
            return Err(error("non-window backing in window slot budget"));
        }
        if backings.len() > self.available_window_slots() {
            return Err(error("window slot budget exceeded"));
        }
        self.install_inner(backings)
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
    /// The most memslots this carrier has held at once.
    pub fn peak_slot_count(&self) -> usize {
        self.peak_slots
    }
    /// Borrow the allocation retained by each installed slot, including
    /// bootstrap windows. Callers can clone the Arcs to retain storage
    /// independently of the lifetime of a slot registration.
    pub fn retained_backings(&self) -> impl Iterator<Item = &Arc<BackingExtent>> {
        self.slots.values().map(|slot| &slot.backing.extent)
    }

    pub fn retained_bytes(&self) -> usize {
        self.slots.values().map(|s| s.backing.extent.len).sum()
    }
    /// A broken carrier invariant: quarantine (every later edit fails
    /// closed, so the run ends) and say which.
    fn broken(&mut self, what: &str) -> MemoryError {
        self.quarantined = true;
        error(what)
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

    /// Return the immutable backing named by an authenticated slot handle.
    /// Slot bookkeeping and mutation remain private to this authority.
    pub fn backing(&self, handle: BackingHandle) -> Result<&PreparedBacking, MemoryError> {
        Ok(&self.record(handle)?.backing)
    }

    /// Fail closed when this authority has been quarantined.
    pub fn ensure_available(&self) -> Result<(), MemoryError> {
        self.admit()
    }
    fn set_region(&self, slot: u32, backing: Option<&PreparedBacking>) -> Result<(), MemoryError> {
        let region = if let Some(b) = backing {
            CarrierMemoryRegion {
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
            CarrierMemoryRegion {
                slot,
                ..Default::default()
            }
        };
        // SAFETY: retained complete extent; exclusive dedicated slot namespace.
        // Deletion drops nothing until the backend has confirmed it. A failed deletion
        // retains backing until VM destruction and quarantines all future edits.
        unsafe { self.vm.set_user_memory_region(region) }.map_err(|e| error(e.to_string()))
    }
    /// Batch physical publication is rollback-capable. No slot ID is burned by
    /// a failed install. Generations are monotonic and never reused/wrapped.
    pub fn install(
        &mut self,
        backings: &[PreparedBacking],
    ) -> Result<Vec<BackingHandle>, MemoryError> {
        self.install_inner(backings)
    }

    fn check_no_overlap(&self, backings: &[PreparedBacking]) -> Result<(), MemoryError> {
        let mut batch = Vec::with_capacity(backings.len());
        for b in backings {
            let start = b.extent.base.raw();
            let end = start
                .checked_add(b.extent.len as u64)
                .ok_or_else(|| error("carrier GPA extent overflow"))?;
            if let Some((_, &slot_id)) = self.by_gpa.range(..=start).next_back()
                && let Some(existing) = self.slots.get(&slot_id)
                && existing.backing.extent.base.raw() + existing.backing.extent.len as u64 > start
            {
                return Err(error("overlapping carrier GPA extent"));
            }
            if self.by_gpa.range(start..end).next().is_some() {
                return Err(error("overlapping carrier GPA extent"));
            }
            batch.push((start, end));
        }
        batch.sort_unstable();
        if batch.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(error("overlapping carrier GPA extent"));
        }
        Ok(())
    }

    fn install_inner(
        &mut self,
        backings: &[PreparedBacking],
    ) -> Result<Vec<BackingHandle>, MemoryError> {
        self.admit()?;
        if self.slots.len() + backings.len() > self.limit as usize {
            return Err(error("carrier memslot capacity"));
        }
        self.check_no_overlap(backings)?;
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
            let result = self.set_region(slot, Some(b));
            if let Err(reason) = result {
                self.rollback_slots(&installed)?;
                return Err(reason);
            }
            let handle = BackingHandle {
                vm: self.identity,
                slot,
                generation: CarrierSlotGeneration(generation),
            };
            if b.extent.is_host_file_window() {
                self.window_slots += 1;
            }
            self.slots.insert(
                slot,
                Slot {
                    handle,
                    backing: b.clone(),
                    frame_identities: BTreeMap::new(),
                    inherited_identities: BTreeMap::new(),
                    arena: false,
                    bootstrap: false,
                },
            );
            if let Err(reason) = self.holds.register(slot) {
                self.quarantined = true;
                return Err(hold_error(reason));
            }
            self.by_gpa.insert(b.extent.base.raw(), slot);
            self.free.remove(&slot);
            self.peak_slots = self.peak_slots.max(self.slots.len());
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
                if slot.backing.extent.is_host_file_window() {
                    self.window_slots -= 1;
                }
                if let Err(reason) = self.holds.forget(handle.slot) {
                    self.quarantined = true;
                    return Err(hold_error(reason));
                }
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
    /// Two phases: every precondition (root, alias records per slot, held
    /// slots, and each released slot's revoke preconditions) is checked
    /// before any bookkeeping moves. A released slot has no holder left, so
    /// a failed precondition on it (a live CR3 arena, a frame any MM still
    /// maps, alias records that differ from the ledger) is a broken
    /// invariant: it quarantines the carrier, never a refusal for the
    /// stock to retry, which could only loop. After the checks only the
    /// memslot deletion ioctl can fail; that is a host fault, never
    /// guest-reachable, and it quarantines the carrier as every other
    /// indeterminate memslot change does.
    pub fn retire_child(
        &mut self,
        absence: &carrick_hal::fork_stock::SlotAbsence,
        inventory: &dyn carrick_hal::PhysicalFrameInventory,
    ) -> Result<RetiredChild, MemoryError> {
        self.admit()?;
        let mm = NonZeroU64::new(absence.mm().raw()).ok_or_else(|| error("retired MM key"))?;
        let context = *self
            .roots
            .get(&mm)
            .ok_or_else(|| error("retired MM has no carrier CR3 root"))?;
        // Phase 1: validate, mutating nothing. The ledger names every slot
        // whose last hold this retirement drops, whatever kind it was: the
        // MM's admission, its aliases, or the drain debt of an alias it
        // unlinked (#3127). Those, and only those, are revoked.
        let plan = self.holds.retirement(key(mm));
        let mut private = Vec::new();
        for index in &plan.released {
            let Some(slot) = self.slots.get(index) else {
                return Err(self.broken("retired MM holds a slot the carrier lost"));
            };
            // Bootstrap memory and a shared file window slot (one per file
            // chunk, reused by every later fault, #1338) stay for the run.
            if slot.bootstrap || slot.backing.extent.is_host_file_window() {
                continue;
            }
            // `revoke`'s preconditions, checked now so the revoke cannot
            // refuse after the bookkeeping below has run. Nothing holds the
            // slot any more, so each is a broken invariant: it quarantines
            // the carrier (fatal), never a refusal the stock retries, which
            // could only loop.
            let extent = &slot.backing.extent;
            let start = extent.base.raw();
            let end = start + extent.len as u64;
            if self.roots.iter().any(|(owner, root)| {
                *owner != mm && (start..end).contains(&root.root.address().raw())
            }) {
                return Err(self.broken("retired child slot holds a live CR3/table arena"));
            }
            // Every frame the slot backs (an arena chunk holds one per
            // grant) must be unmapped in every MM, not just the retiring
            // one: a row anywhere means some MM still uses the backing
            // without a hold, and revoking it would pull memory out from
            // under that MM.
            if core::iter::once(&slot.backing.identity)
                .chain(slot.frame_identities.values())
                .any(|identity| {
                    inventory.frame_is_mapped(carrick_hal::FrameId::from_kernel_allocation(
                        identity.frame_id,
                    ))
                })
            {
                return Err(self.broken("retired child memslot frame is still mapped"));
            }
            private.push(slot.handle);
        }
        // The carrier's alias records match the ledger slot by slot, and
        // every slot the MM holds is still installed.
        let mut aliases_by_slot = BTreeMap::<u32, usize>::new();
        for alias in self.aliases.get(&mm).into_iter().flat_map(BTreeMap::values) {
            *aliases_by_slot.entry(alias.slot).or_default() += 1;
        }
        if aliases_by_slot != plan.aliases {
            return Err(self.broken("retired MM alias records differ from its holds"));
        }
        if plan
            .held
            .iter()
            .any(|index| !self.slots.contains_key(index))
        {
            return Err(self.broken("retired MM holds a slot the carrier lost"));
        }
        let aliases = plan.alias_total();
        // Phase 2: bookkeeping, infallible after the checks above. The
        // absence proof discharges every pending drain of this MM's
        // contexts, so shared slots do not accumulate retired children.
        self.roots.remove(&mm);
        for alias in self.aliases.remove(&mm).unwrap_or_default().into_values() {
            if let (Some(slot), Some(gpa)) = (self.slots.get_mut(&alias.slot), alias.inherited) {
                slot.inherited_identities.remove(&(mm, gpa.raw()));
            }
        }
        self.holds.retire(key(mm));
        // Phase 3: revoke the private slots (only the ioctl can fail).
        let mut drain = QuarantinedContextDrain { context };
        let mut retired = AlreadyRetiredInventory { inventory };
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
    pub fn context_by_root(&self, root: RootGpa) -> Option<AddressContext<RootGpa>> {
        self.roots.values().find(|c| c.root == root).copied()
    }
    /// Bind independently inventoried physical frames inside one carrier extent.
    /// The memslot remains coarse; descriptor outputs authenticate one page.
    pub fn bind_frame_identities(
        &mut self,
        handle: BackingHandle,
        identities: &[(FrameGpa, BackingIdentity)],
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let slot = self.record(handle)?;
        if slot.bootstrap
            || slot.arena
            || self.holds.alias_count(handle.slot) != 0
            || !slot.frame_identities.is_empty()
        {
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
    /// Install one chunk of `mm`'s copy-on-write replacement arena (#3099):
    /// one memslot, admitted to `mm` alone, so it retires with `mm`
    /// (`retire_child`) exactly as a per-grant slot did. No page of it
    /// authenticates until [`Self::adopt_frames`] binds a grant's frame.
    /// `backing.identity` is the first grant's, never used to authenticate.
    pub fn install_arena_chunk(
        &mut self,
        mm: NonZeroU64,
        backing: PreparedBacking,
    ) -> Result<BackingHandle, MemoryError> {
        self.admit()?;
        if !self.roots.contains_key(&mm) || backing.extent.is_host_file_window() {
            return Err(error("arena chunk for an unrooted MM or a window"));
        }
        let handle = *self
            .install_inner(core::slice::from_ref(&backing))?
            .first()
            .ok_or_else(|| error("arena chunk install"))?;
        let slot = self
            .slots
            .get_mut(&handle.slot)
            .ok_or_else(|| error("missing arena chunk slot"))?;
        slot.arena = true;
        self.holds.admit(handle.slot, key(mm)).map_err(hold_error)?;
        Ok(handle)
    }

    /// Bind one inventoried grant `[gpa, gpa + len)` inside an arena chunk
    /// of `mm`, then publish its inventory: a supply with no memslot change
    /// and no host mapping call. A failure unbinds it and rolls the
    /// inventory back.
    pub fn adopt_frames<I: InventoryTransaction>(
        &mut self,
        mm: NonZeroU64,
        gpa: FrameGpa,
        len: u64,
        identity: BackingIdentity,
        inventory: &mut I,
    ) -> Result<BackingHandle, MemoryError> {
        self.admit()?;
        let slot = usize::try_from(len)
            .ok()
            .and_then(|len| self.locate(gpa, len))
            .ok_or_else(|| error("grant outside every arena chunk"))?;
        let pages = (0..len / PAGE).map(|page| gpa.raw() + page * PAGE);
        if !slot.arena
            || self.holds.admitted(slot.handle.slot) != [key(mm)]
            || len == 0
            || !gpa.raw().is_multiple_of(PAGE)
            || !len.is_multiple_of(PAGE)
            || pages
                .clone()
                .any(|page| slot.frame_identities.contains_key(&page))
        {
            return Err(error("grant is not a free range of its MM's arena chunk"));
        }
        let index = slot.handle.slot;
        let handle = slot.handle;
        let frames = &mut self
            .slots
            .get_mut(&index)
            .ok_or_else(|| error("missing arena chunk slot"))?
            .frame_identities;
        frames.extend(pages.clone().map(|page| (page, identity)));
        if let Err(reason) = inventory.publish() {
            if let Some(slot) = self.slots.get_mut(&index) {
                for page in pages {
                    slot.frame_identities.remove(&page);
                }
            }
            self.rollback_inventory(inventory)?;
            return Err(reason);
        }
        Ok(handle)
    }

    /// Undo an adoption that never reached a guest edit.
    ///
    /// # Safety
    /// The caller holds exact-MM entry exclusion and proves that no guest
    /// descriptor has named any page of this grant.
    pub unsafe fn cancel_adopted<I: InventoryTransaction>(
        &mut self,
        handle: BackingHandle,
        gpa: FrameGpa,
        len: u64,
        identity: BackingIdentity,
        inventory: &mut I,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let slot = self.record(handle)?;
        let pages = (0..len / PAGE).map(|page| gpa.raw() + page * PAGE);
        if !slot.arena
            || pages
                .clone()
                .any(|page| slot.frame_identities.get(&page) != Some(&identity))
        {
            return Err(error("cancelled grant is not adopted in its chunk"));
        }
        self.rollback_inventory(inventory)?;
        if let Some(slot) = self.slots.get_mut(&handle.slot) {
            for page in pages {
                slot.frame_identities.remove(&page);
            }
        }
        Ok(())
    }

    pub fn share(&self, handle: BackingHandle) -> Result<SharedFrameEdge, MemoryError> {
        let slot = self.record(handle)?;
        if slot.bootstrap || slot.arena || !slot.frame_identities.is_empty() {
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
        self.holds
            .admit(edge.handle.slot, key(mm))
            .map_err(hold_error)
    }
    fn locate(&self, pa: FrameGpa, len: usize) -> Option<&Slot> {
        let (_, index) = self.by_gpa.range(..=pa.raw()).next_back()?;
        let slot = self.slots.get(index)?;
        slot.backing.extent.ptr(pa.raw(), len)?;
        Some(slot)
    }
    /// Initialize retained boot records before creating any vCPU.
    fn record_ptr<T>(&self, pa: FrameGpa) -> Result<*mut T, MemoryError> {
        let slot = self
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

    /// Initialize retained boot records before creating any vCPU.
    pub fn initialize_fault_records(&mut self, region: FrameGpa) -> Result<(), MemoryError> {
        let residency = self.record_ptr::<carrick_el1_abi::FrameGrantResidencyTable>(
            FrameGpa::new(region.raw() + carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_OFFSET),
        )?;
        let ingress = self.record_ptr::<carrick_el1_abi::SharedSignalIngressQueue>(
            FrameGpa::new(region.raw() + carrick_el1_abi::EL1_SIGNAL_INGRESS_OFFSET),
        )?;
        let portal = self.record_ptr::<carrick_el1_abi::MmPortalSlots>(FrameGpa::new(
            region.raw() + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
        ))?;
        // SAFETY: exclusive boot memory, before CarrierMachine creates vCPUs;
        // both retained records have checked bounds and alignment.
        unsafe {
            carrick_el1_abi::FrameGrantResidencyTable::init_in_place(residency);
            carrick_el1_abi::SharedSignalIngressQueue::initialize_at(ingress);
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

    /// Resolve a retained stage-2 byte range to its non-null host alias.
    pub(crate) fn retained_bytes_ptr(
        &self,
        pa: FrameGpa,
        len: usize,
    ) -> Result<core::ptr::NonNull<u8>, MemoryError> {
        let slot = self
            .locate(pa, len)
            .ok_or_else(|| error("retained range bounds"))?;
        let ptr = slot
            .backing
            .extent
            .ptr(pa.raw(), len)
            .ok_or_else(|| error("retained range backing"))?;
        core::ptr::NonNull::new(ptr).ok_or_else(|| error("retained range null pointer"))
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
                (slot.frame_identities.is_empty() && !slot.arena).then_some(slot.backing.identity)
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
    ) -> Result<Vec<InheritedFrameEdge>, InheritedFrameSelectionError> {
        self.admit()?;
        if self.root(parent.mm.raw()) != Some(parent) {
            return Err(error("stale inherited source root").into());
        }
        let carrick_el1_abi::PortalForkCustody::Frame {
            va,
            ipa,
            len,
            shared,
        } = selection
        else {
            return Err(error("inheritance requires selected frame custody").into());
        };
        if len == 0
            || !va.is_multiple_of(PAGE)
            || !ipa.is_multiple_of(PAGE)
            || !len.is_multiple_of(PAGE)
            || va.checked_add(len).is_none()
            || ipa.checked_add(len).is_none()
        {
            return Err(error("invalid inherited physical span").into());
        }
        let mut edges = Vec::new();
        for offset in (0..len).step_by(PAGE as usize) {
            let gpa = FrameGpa::new(ipa + offset);
            let span = PageSpan::new(va + offset, PAGE);
            if self
                .locate(gpa, PAGE as usize)
                .is_some_and(|slot| slot.backing.extent.is_host_file_window())
            {
                // A window page has no frame-inventory row: answering
                // `MappingGone` would rerun the fork forever (#1338).
                return Err(
                    error("a shared file window page is inherited as a window edge").into(),
                );
            }
            let identity = self.frame_identity(parent.mm.raw(), gpa)?;
            let bound = authority.bind(parent.into());
            if bound
                .live_mapping_row(carrick_hal::MappingId::from_kernel_allocation(
                    identity.mapping_id,
                ))
                .is_none()
            {
                return Err(InheritedFrameSelectionError::MappingGone);
            }
            let slot = self
                .locate(gpa, PAGE as usize)
                .ok_or_else(|| error("inherited registration absent"))?;
            let resident = self
                .named_leaf_resident(parent, span, gpa)
                .ok_or_else(|| error("selected source does not name retained storage"))?;
            if !inventory_page_live(authority, parent.into(), identity, gpa) {
                return Err(error("selected source is not a live inventoried page").into());
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
            || PhysicalOwnerGeneration::from_counter(identity.owner_generation)
                != PhysicalOwnerGeneration::INITIAL
            || receipt.mm() != child.mm.raw()
            || receipt.revision() != identity.inventory_revision.get()
            || !receipt.authorizes(mapping, frame)
            || self.frame_identity(edge.parent.mm.raw(), edge.gpa)? != edge.identity
            || !inventory_page_live(authority, edge.parent.into(), edge.identity, edge.gpa)
            || !inventory_page_live(authority, child.into(), identity, edge.gpa)
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
        let slot = self
            .slots
            .get_mut(&edge.handle.slot)
            .ok_or_else(|| error("missing inherited registration"))?;
        self.holds
            .alias(edge.handle.slot, key(child.mm.raw()))
            .map_err(hold_error)?;
        slot.inherited_identities
            .insert((child.mm.raw(), edge.gpa.raw()), identity);
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

    /// Classify one fork custody row against this carrier's shared file
    /// windows (#1338). `None` means the row names no window slot and is
    /// selected by [`Self::select_inherited_frames`]. A window page is the
    /// file's own bytes behind one slot kept for the run, with no frame
    /// inventory: the child keeps the parent's leaf (never a COW) and is
    /// admitted to the slot by [`Self::attach_inherited_window`].
    pub fn select_inherited_window(
        &self,
        parent: AddressContext<RootGpa>,
        selection: carrick_el1_abi::PortalForkCustody,
    ) -> Result<Option<InheritedWindowEdge>, MemoryError> {
        self.admit()?;
        let carrick_el1_abi::PortalForkCustody::Frame {
            va,
            ipa,
            len,
            shared,
        } = selection
        else {
            return Ok(None);
        };
        let gpa = FrameGpa::new(ipa);
        let Some(slot) = self
            .locate(gpa, PAGE as usize)
            .filter(|slot| slot.backing.extent.is_host_file_window())
        else {
            return Ok(None);
        };
        if self.root(parent.mm.raw()) != Some(parent) {
            return Err(error("stale inherited window root"));
        }
        let span = PageSpan::new(va, PAGE);
        // A window leaf is one 4 KiB MapAlias page of a shared mapping.
        if !shared
            || len != PAGE
            || !va.is_multiple_of(PAGE)
            || !ipa.is_multiple_of(PAGE)
            || !self
                .holds
                .admitted(slot.handle.slot)
                .contains(&key(parent.mm.raw()))
            || !self.leaf_names(parent, span, gpa)
        {
            return Err(error("inherited window row names no parent window leaf"));
        }
        Ok(Some(InheritedWindowEdge {
            handle: slot.handle,
            parent,
            span,
            gpa,
        }))
    }

    /// Admit a fork child to the window slot its kept leaf names, and
    /// record that leaf as the child's alias, so retirement and unmap count
    /// it. The guest already copied the leaf; this writes no descriptor.
    pub fn attach_inherited_window(
        &mut self,
        child: AddressContext<RootGpa>,
        edge: &InheritedWindowEdge,
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let slot = self.record(edge.handle)?;
        if child.mm == edge.parent.mm
            || self.root(child.mm.raw()) != Some(child)
            || self.root(edge.parent.mm.raw()) != Some(edge.parent)
            || !slot.backing.extent.is_host_file_window()
            || !self.leaf_names(edge.parent, edge.span, edge.gpa)
            || !self.leaf_names(child, edge.span, edge.gpa)
        {
            return Err(error("stale or unauthenticated inherited window edge"));
        }
        let end = edge.span.va + PAGE;
        if self.aliases.get(&child.mm.raw()).is_some_and(|aliases| {
            aliases
                .range(..end)
                .next_back()
                .is_some_and(|(_, alias)| alias.span.va + alias.span.len > edge.span.va)
        }) {
            return Err(error("inherited child alias already occupied"));
        }
        self.holds
            .alias(edge.handle.slot, key(child.mm.raw()))
            .map_err(hold_error)?;
        self.holds
            .admit(edge.handle.slot, key(child.mm.raw()))
            .map_err(hold_error)?;
        self.aliases.entry(child.mm.raw()).or_default().insert(
            edge.span.va,
            Alias {
                slot: edge.handle.slot,
                span: edge.span,
                inherited: None,
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
        } else if slot.frame_identities.is_empty() && !slot.arena {
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
            || (inherited.is_none() && {
                let allowed = self.holds.admitted(slot.handle.slot);
                !allowed.is_empty() && !allowed.contains(&key(mm))
            })
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
            .any(|handle| self.record(*handle).is_err() || self.holds.alias_count(handle.slot) != 0)
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
            DescriptorOp::Unmap(_) | DescriptorOp::UnmapWindow(_) | DescriptorOp::CowRepoint { .. }
        ) {
            self.remove_aliases(txn.id.mm_key, txn.op.span(), context);
            if self.quarantined {
                return Err(error("guest alias publication became indeterminate"));
            }
        }
        if let Some(index) = target {
            let mm = key(txn.id.mm_key);
            let admitted = if self.holds.admitted(index).is_empty() {
                self.holds.admit(index, mm)
            } else {
                Ok(())
            };
            if let Err(reason) = admitted.and_then(|()| self.holds.alias(index, mm)) {
                self.quarantined = true;
                return Err(hold_error(reason));
            }
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
                    if matches!(
                        txn.op,
                        DescriptorOp::Unmap(_)
                            | DescriptorOp::UnmapWindow(_)
                            | DescriptorOp::Retire(_)
                            | DescriptorOp::ProtectWindow { .. }
                    ) =>
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
                    let present = entry & PRESENT != 0;
                    let prepared = entry & PREPARED != 0;
                    // The resident page is live. Every other page stays
                    // prepared until its first touch, but this settlement
                    // runs without excluding the other CPU: its in-guest
                    // first touch may already have published one (same
                    // output, checked above) and written it.
                    let state = if resident.contains(va) {
                        present && !prepared
                    } else {
                        present != prepared
                    };
                    state
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
                DescriptorOp::Unmap(_) | DescriptorOp::UnmapWindow(_) => {
                    entry & (PRESENT | PREPARED) == 0
                }
                // A window protect skips holes and edits host-mapped leaves.
                DescriptorOp::ProtectWindow { permissions, .. } => {
                    entry == 0
                        || entry & PRESENT != 0
                            && entry & PRIVATE == 0
                            && Self::matches_permissions(entry, permissions)
                }
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
            if self
                .holds
                .unalias(alias.slot, key(mm), SlotDrain(context))
                .is_err()
            {
                self.quarantined = true;
                return;
            }
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
                    if self.holds.alias(alias.slot, key(mm)).is_err() {
                        self.quarantined = true;
                        return;
                    }
                }
            }
        }
    }
    /// Clear the retired terminals of one settled owed return of `mm` and
    /// drop the physical alias edges they kept (#1369 slice 3). `terminals`
    /// came from `carrick_el1::memory::owed_retired_terminals` under the same
    /// editor exclusion.
    /// The backing slots stay registered and admitted for `mm`: their frames
    /// return with the MM's own retirement, as on HVF. A word that changed
    /// under the exclusion quarantines the carrier (a broken invariant).
    pub fn clear_settled_return(
        &mut self,
        mm: NonZeroU64,
        root: RootGpa,
        span: PageSpan,
        terminals: &[carrick_el1::memory::RetiredTerminal],
    ) -> Result<(), MemoryError> {
        self.admit()?;
        let context = self
            .root(mm)
            .filter(|context| context.root == root)
            .ok_or_else(|| error("stale carrier MM/root for an owed return"))?;
        let words = self.words();
        let cleared = carrick_el1::memory::clear_retired_terminals(
            &|pa, current, new| words.compare_exchange(pa, current, new).ok(),
            terminals,
        );
        words.publish_barrier();
        if !cleared {
            self.quarantined = true;
            return Err(error("owed return terminal changed under exclusion"));
        }
        self.remove_aliases(mm, span, context);
        if self.quarantined {
            return Err(error("owed return alias release became indeterminate"));
        }
        Ok(())
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
        if self.holds.alias_count(handle.slot) != 0 {
            return Err(error("carrier backing still has descriptor aliases"));
        }
        for &SlotDrain(context) in self.holds.drains(handle.slot) {
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
            if slot.backing.extent.is_host_file_window() {
                self.window_slots -= 1;
            }
            if let Err(reason) = self.holds.forget(handle.slot) {
                self.quarantined = true;
                return Err(hold_error(reason));
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
        if !bytes.is_empty() {
            self.vm.host_wrote_ram(pa, bytes.len());
        }
        Ok(())
    }
    pub fn words(&self) -> DescriptorWords<'_, M> {
        DescriptorWords { memory: self }
    }
}
/// Borrowed hardware words, reused by either a stopped fixture or the accepted
/// N1 exact-MM editor. Invalidation is an owner obligation: no public run API
/// exists here, and a successful descriptor receipt is NOT a drain receipt.
pub struct DescriptorWords<'a, M: CarrierMemoryIo> {
    memory: &'a CarrierMemory<M>,
}
impl<M: CarrierMemoryIo> DescriptorWords<'_, M> {
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
impl<M: CarrierMemoryIo> LiveDescriptorWords for DescriptorWords<'_, M> {
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

    fn descriptor_diagnostic(
        &self,
        event: carrick_mmu_core::live_descriptor_words::DescriptorDiagnostic,
    ) {
        carrick_hal::diagnostic_capture::trace_descriptor_diagnostic(
            carrick_guest_arch::GuestIsa::X86_64,
            event,
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;

//! Resident private-anonymous memory operations served inside guest EL1.

#[path = "personality/reservations.rs"]
pub mod reservations;

use carrick_el1_abi::{CurrentTask, TrapFrame};
use carrick_mmu_core::aarch64::{
    GuestPermissionEdit, GuestPermissionEditError, GuestRetirementError,
};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

const SYS_BRK: u64 = 214;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const SYS_MPROTECT: u64 = 226;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_GROWSDOWN: u64 = 0x0100;
const MAP_STACK: u64 = 0x20000;
const MAP_HUGETLB: u64 = 0x40000;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const PAGE_SIZE: u64 = 4096;

/// Keep mmap protection outside EL1's vocabulary on the host decode route.
/// The memflagmatrix oracle records ignored bits; mprotect is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MmapProtectionRoute {
    Reservation(carrick_el1_abi::ReservationProtection),
    HostUnrepresentedBits,
}

impl MmapProtectionRoute {
    fn decode(bits: u64) -> Self {
        if let Some(protection) = carrick_el1_abi::ReservationProtection::from_bits(bits) {
            Self::Reservation(protection)
        } else {
            Self::HostUnrepresentedBits
        }
    }
}

/// Decision before T2's descriptor/backing service. `Work` retains the exact
/// originating frame identity; it must survive the host boundary as an owned
/// continuation, never as a request to replay the Linux syscall.
pub enum ReservationDisposition {
    Forward,
    /// Admission/capacity service; never replay on a second VMA authority.
    Unavailable(reservations::Refusal),
    Return(i64),
    Work(PendingReservationSyscall),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReservationOrigin {
    task: carrick_el1_abi::El1TaskId,
    serial: NonZeroU64,
    mm: carrick_el1_abi::ReservationMm,
}
impl ReservationOrigin {
    fn capture(current: &CurrentTask) -> Option<Self> {
        let raw = current.task_id.load(Ordering::Acquire);
        let tid = i32::try_from(raw).ok().filter(|tid| *tid > 0)?;
        Some(Self {
            task: carrick_el1_abi::El1TaskId::from_linux_tid(tid),
            serial: NonZeroU64::new(current.thread_serial.load(Ordering::Acquire))?,
            mm: carrick_el1_abi::ReservationMm::new(current.zone_mm.load(Ordering::Acquire))?,
        })
    }
}

pub struct PendingReservationSyscall {
    request: carrick_el1_abi::ReservationRequest,
    origin: ReservationOrigin,
    elr: u64,
    syscall: u64,
    args: [u64; 6],
}
impl PendingReservationSyscall {
    pub fn request(&self) -> carrick_el1_abi::ReservationRequest {
        self.request
    }
    /// Complete exactly once, on the saved originating frame after T2 completed
    /// descriptors and authenticated backing. Failed authentication keeps the
    /// pending proposal intact so its owner can explicitly refuse/settle it.
    pub fn complete(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
        completion: carrick_el1_abi::ReservationCompletion,
    ) -> Result<(), reservations::Refusal> {
        self.complete_as(frame, current, counters, model, completion, None)
    }
    /// [`Self::complete`] for a retirement whose stage-1 terminals the guest
    /// venue retired: the root commits and journals the range as an owed
    /// return ([`reservations::Reservations::complete_deferring_return`]);
    /// its frames stay unreusable until the host's inventory receipt.
    pub fn complete_deferring_return(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
        completion: carrick_el1_abi::ReservationCompletion,
        slot: reservations::ReturnSlot,
    ) -> Result<(), reservations::Refusal> {
        self.complete_as(frame, current, counters, model, completion, Some(slot))
    }
    fn complete_as(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
        completion: carrick_el1_abi::ReservationCompletion,
        owed_return: Option<reservations::ReturnSlot>,
    ) -> Result<(), reservations::Refusal> {
        if !self.owns_frame(frame, current) || !completion.authenticates(self.request) {
            if let Some(slot) = owed_return {
                model.release_return(slot);
            }
            return Err(reservations::Refusal::Stale);
        }
        let result = match owed_return {
            Some(slot) => model.complete_deferring_return(completion, slot)?,
            None => model.complete(completion)?,
        };
        frame.x[0] = result;
        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn owns_frame(&self, frame: &TrapFrame, current: &CurrentTask) -> bool {
        ReservationOrigin::capture(current) == Some(self.origin)
            && frame.elr == self.elr
            && frame.x[8] == self.syscall
            && frame.x[..6] == self.args
    }
    /// Finish a clean backing/descriptor refusal on the originating thread.
    /// The service must roll back before invoking this method.
    pub fn refuse(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
    ) -> Result<(), reservations::Refusal> {
        if !self.owns_frame(frame, current) {
            return Err(reservations::Refusal::Stale);
        }
        model.refuse(self.request)?;
        frame.x[0] = if self.syscall == SYS_BRK {
            model.brk_current()
        } else {
            (-ENOMEM) as u64
        };
        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    /// Cancel after service rollback when the originating thread is gone.
    /// Cancellation delivers no syscall result and increments no served count.
    pub fn cancel(
        self,
        model: &mut reservations::Reservations<'_>,
    ) -> Result<(), reservations::Refusal> {
        model.refuse(self.request)
    }
}

/// The Linux decoder used by both host and guest adapters. Caller owns the
/// exact-MM reservation guard. No descriptor operation occurs in this layer.
/// T2 integration replaces the existing dispatch fallback with this decision,
/// retaining `Work` until completion instead of forwarding the original SVC.
pub fn decide_anonymous_syscall(
    frame: &TrapFrame,
    current: &CurrentTask,
    model: &mut reservations::Reservations<'_>,
) -> ReservationDisposition {
    use carrick_el1_abi::{ReservationProtection, ReservationRange};
    use reservations::{Decision, Placement, Refusal};
    let Some(origin) = ReservationOrigin::capture(current) else {
        return ReservationDisposition::Unavailable(Refusal::Stale);
    };
    if origin.mm != model.mm() || !model.is_admitted() {
        return ReservationDisposition::Unavailable(Refusal::Stale);
    }
    let nr = frame.x[8];
    let result = match nr {
        SYS_BRK => model.brk(frame.x[0]),
        SYS_MMAP => {
            let flags = frame.x[3];
            let supported = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE;
            if flags & (MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED) != MAP_ANONYMOUS | MAP_PRIVATE
                || flags & (MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB) != 0
                || flags & !supported != 0
            {
                return ReservationDisposition::Forward;
            }
            let prot = match MmapProtectionRoute::decode(frame.x[2]) {
                MmapProtectionRoute::Reservation(protection) => protection,
                MmapProtectionRoute::HostUnrepresentedBits => {
                    return ReservationDisposition::Forward;
                }
            };
            if !frame.x[5].is_multiple_of(PAGE_SIZE) {
                return ReservationDisposition::Return(-EINVAL);
            }
            let placement = if flags & MAP_FIXED_NOREPLACE != 0 {
                Placement::NoReplace(frame.x[0])
            } else if flags & MAP_FIXED != 0 {
                Placement::Fixed(frame.x[0])
            } else if frame.x[0] == 0 {
                Placement::Anywhere
            } else {
                Placement::Hint(frame.x[0])
            };
            model.mmap(placement, frame.x[1], prot)
        }
        SYS_MUNMAP | SYS_MPROTECT => {
            if !frame.x[0].is_multiple_of(PAGE_SIZE) {
                return ReservationDisposition::Return(-EINVAL);
            }
            let prot = if nr == SYS_MPROTECT {
                let Some(prot) = ReservationProtection::from_bits(frame.x[2]) else {
                    return ReservationDisposition::Return(-EINVAL);
                };
                prot
            } else {
                ReservationProtection::NONE
            };
            if frame.x[1] == 0 {
                return ReservationDisposition::Return(if nr == SYS_MUNMAP { -EINVAL } else { 0 });
            }
            let range = frame.x[1]
                .checked_add(PAGE_SIZE - 1)
                .map(|v| v & !(PAGE_SIZE - 1))
                .and_then(|len| frame.x[0].checked_add(len))
                .and_then(|end| ReservationRange::new(frame.x[0], end));
            let Some(range) = range else {
                return ReservationDisposition::Return(-ENOMEM);
            };
            if nr == SYS_MUNMAP {
                model.munmap(range)
            } else {
                model.mprotect(range, prot)
            }
        }
        _ => return ReservationDisposition::Forward,
    };
    match result {
        Ok(Decision::Complete(value)) => ReservationDisposition::Return(value as i64),
        Ok(Decision::Work(request)) => ReservationDisposition::Work(PendingReservationSyscall {
            request,
            origin,
            elr: frame.elr,
            syscall: nr,
            args: [
                frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
            ],
        }),
        Err(Refusal::Collision) => ReservationDisposition::Return(-17),
        Err(Refusal::Invalid) => ReservationDisposition::Return(-EINVAL),
        Err(Refusal::Hole | Refusal::Limit) => ReservationDisposition::Return(-ENOMEM),
        Err(Refusal::ForeignMapping) => ReservationDisposition::Forward,
        Err(error @ (Refusal::Busy | Refusal::Stale | Refusal::MetadataRequired)) => {
            ReservationDisposition::Unavailable(error)
        }
    }
}

/// Result of attempting the bounded EL1 `mprotect` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MprotectDisposition {
    Forward,
    Return(i64),
    /// Served, but the space's VMA journal was full, so the edit is not
    /// recorded: the original syscall must cross once (back-pressure) so the
    /// host commits the metadata after applying the journal. Only this case
    /// costs a host exit; an edit is never dropped.
    ReturnWithWork,
}

/// Result of attempting the bounded EL1 `munmap` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MunmapDisposition {
    Forward,
    Return(i64),
    /// Stage-1 is retired. The original syscall must cross once so the host
    /// can authenticate and return the physical extent and commit VMA metadata.
    Retired,
}

/// Exact-MM live-leaf operation behind the syscall policy.
pub trait AnonymousPermissionEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError>;
}

/// Exact-MM live-terminal retirement behind the syscall policy.
pub trait AnonymousRetirementEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError>;
}

#[cfg(target_os = "none")]
pub struct HardwareAnonymousPermissionEditor;

#[cfg(target_os = "none")]
impl AnonymousPermissionEditor for HardwareAnonymousPermissionEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError> {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let words =
            carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut core::sync::atomic::AtomicU64;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        unsafe {
            carrick_mmu_core::aarch64::protect_existing_el1_private_pages(
                words,
                physical_base,
                byte_len,
                Some(carrick_el1_abi::stage1_table_pool_window()),
                edit,
            )?;
        }
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub struct HardwareAnonymousRetirementEditor;

#[cfg(target_os = "none")]
impl AnonymousRetirementEditor for HardwareAnonymousRetirementEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError> {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let words =
            carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut core::sync::atomic::AtomicU64;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        unsafe {
            carrick_mmu_core::aarch64::retire_existing_el1_private_pages(
                words,
                physical_base,
                byte_len,
                Some(carrick_el1_abi::stage1_table_pool_window()),
                address,
                len,
            )?;
        }
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(())
    }
}

/// What the exact MM's live stage-1 graph holds under one edit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeBacking {
    /// No terminal: nothing was ever backed there (a lazy reservation).
    Empty,
    /// Only EL1-private grants and holes, and some page is resident (its
    /// contents may be anything).
    Private,
    /// Only EL1-private prepared grants EL1 never committed (such as
    /// first-touch stock) and holes.
    Prepared,
    /// Some terminal is a retired lease whose inventory return is owed.
    Retired,
    /// A host-owned terminal, a malformed one, a table outside the primary
    /// arena, or more backed runs than one edit step takes.
    Foreign,
}

/// Backed runs one classification reports; more is [`RangeBacking::Foreign`].
pub const MAX_BACKED_RUNS: usize = 8;

/// One range's classification and its maximal backed runs (`[start, end)`
/// of EL1-private terminals, in address order): the spans an editor step
/// must cover. Pages between runs have no terminal at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage1Backing {
    pub summary: RangeBacking,
    /// Why a `Foreign` summary is foreign (the leave EL1 counts).
    pub foreign: ForeignBacking,
    runs: [(u64, u64); MAX_BACKED_RUNS],
    count: usize,
}

/// Which [`RangeBacking::Foreign`] a range is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignBacking {
    /// A terminal the host owns: a page leaf without EL1 tags.
    HostOwnedLeaf,
    /// An L1/L2 block terminal.
    Block,
    /// More backed runs than one classification reports.
    TooManyRuns,
    /// A malformed terminal, a table outside the primary arena, or a range
    /// that wraps.
    Malformed,
}

impl ForeignBacking {
    pub const fn leave(self) -> carrick_el1_abi::AnonymousLeave {
        match self {
            Self::HostOwnedLeaf => carrick_el1_abi::AnonymousLeave::BackingHostOwnedLeaf,
            Self::Block => carrick_el1_abi::AnonymousLeave::BackingBlock,
            Self::TooManyRuns => carrick_el1_abi::AnonymousLeave::BackingMultiRun,
            Self::Malformed => carrick_el1_abi::AnonymousLeave::BackingMalformed,
        }
    }
}

impl Stage1Backing {
    pub const fn of(summary: RangeBacking) -> Self {
        Self {
            summary,
            foreign: ForeignBacking::Malformed,
            runs: [(0, 0); MAX_BACKED_RUNS],
            count: 0,
        }
    }
    /// A `Foreign` range, for `why`.
    pub const fn foreign(why: ForeignBacking) -> Self {
        let mut backing = Self::of(RangeBacking::Foreign);
        backing.foreign = why;
        backing
    }
    /// `summary` over exactly these backed runs; `Foreign` if too many.
    pub fn with_runs(summary: RangeBacking, runs: &[(u64, u64)]) -> Self {
        let mut backing = Self::of(summary);
        for &(start, end) in runs {
            backing.push(start, end);
        }
        backing
    }
    fn push(&mut self, start: u64, end: u64) {
        if self.count > 0 && self.runs[self.count - 1].1 == start {
            self.runs[self.count - 1].1 = end;
        } else if self.count == MAX_BACKED_RUNS {
            self.summary = RangeBacking::Foreign;
            self.foreign = ForeignBacking::TooManyRuns;
        } else {
            self.runs[self.count] = (start, end);
            self.count += 1;
        }
    }
    pub fn runs(&self) -> &[(u64, u64)] {
        &self.runs[..self.count]
    }
}

/// Classify `[va, va + len)` by walking the live graph rooted at `root`.
/// `read` loads the descriptor word at a table PA, `None` outside the
/// primary arena. Absent tables skip their whole span, so the walk is
/// proportional to the populated terminals, not to `len`.
pub fn classify_stage1_range(
    read: &dyn Fn(u64) -> Option<u64>,
    root: u64,
    va: u64,
    len: u64,
) -> Stage1Backing {
    use carrick_mmu_core::aarch64::{El1PrivateLeafState, el1_private_leaf_state, indices};
    const VALID: u64 = 1;
    const TABLE: u64 = 0b11;
    const TABLE_PA: u64 = 0x0000_FFFF_FFFF_F000;
    const SPANS: [u64; 4] = [1 << 39, 1 << 30, 1 << 21, PAGE_SIZE];
    let malformed = Stage1Backing::foreign(ForeignBacking::Malformed);
    let Some(end) = va.checked_add(len) else {
        return malformed;
    };
    let mut backing = Stage1Backing::of(RangeBacking::Empty);
    let (mut private, mut resident) = (false, false);
    let mut cursor = va;
    while cursor < end {
        let index = indices(cursor);
        let mut table = root;
        let mut level = 0;
        let descriptor = loop {
            let Some(descriptor) = read(table + index[level] as u64 * 8) else {
                return malformed;
            };
            if level < 3 && descriptor & (VALID | TABLE) == VALID | TABLE {
                table = descriptor & TABLE_PA;
                level += 1;
                continue;
            }
            break descriptor;
        };
        let span = SPANS[level];
        let next = (cursor & !(span - 1)).saturating_add(span);
        if descriptor != 0 {
            match el1_private_leaf_state(descriptor) {
                El1PrivateLeafState::Prepared => private = true,
                El1PrivateLeafState::Resident => {
                    private = true;
                    resident = true;
                }
                El1PrivateLeafState::Retired => {
                    return Stage1Backing::of(RangeBacking::Retired);
                }
                El1PrivateLeafState::Unowned if level < 3 => {
                    return Stage1Backing::foreign(ForeignBacking::Block);
                }
                El1PrivateLeafState::Unowned => {
                    return Stage1Backing::foreign(ForeignBacking::HostOwnedLeaf);
                }
                El1PrivateLeafState::Malformed => return malformed,
            }
            backing.push(cursor, next.min(end));
            if backing.summary == RangeBacking::Foreign {
                return Stage1Backing::foreign(ForeignBacking::TooManyRuns);
            }
        }
        if next <= cursor {
            break;
        }
        cursor = next;
    }
    backing.summary = match (private, resident) {
        (true, true) => RangeBacking::Private,
        (true, false) => RangeBacking::Prepared,
        _ => RangeBacking::Empty,
    };
    backing
}

/// Exact-MM read of the live stage-1 graph behind the syscall policy.
pub trait AnonymousBackingProbe {
    fn backing(&mut self, ttbr0: u64, va: u64, len: u64) -> Stage1Backing;
    /// `[start, end)` of the live first-touch grant of exactly `mm_key`
    /// that prepared `va`, if any: stock this MM may hand to a new mapping.
    fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)>;
}

/// Every descriptor step of a delegated anonymous transaction.
pub trait AnonymousDescriptorEditor:
    AnonymousBackingProbe + AnonymousPermissionEditor + AnonymousRetirementEditor
{
}
impl<T> AnonymousDescriptorEditor for T where
    T: AnonymousBackingProbe + AnonymousPermissionEditor + AnonymousRetirementEditor
{
}

/// Hardware descriptor steps for a delegated MM's root transaction.
#[cfg(target_os = "none")]
pub struct HardwareAnonymousEditor;

#[cfg(target_os = "none")]
impl AnonymousBackingProbe for HardwareAnonymousEditor {
    fn backing(&mut self, ttbr0: u64, va: u64, len: u64) -> Stage1Backing {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let root = ttbr0 & TTBR_BADDR_MASK;
        let primary = carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
            words: carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE
                as *mut core::sync::atomic::AtomicU64,
            physical_base: root,
            byte_len: carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
        };
        let pool = carrick_el1_abi::stage1_table_pool_window();
        let read = |pa: u64| {
            [primary, pool].iter().find_map(|window| {
                let offset = pa.checked_sub(window.physical_base)?;
                (offset.is_multiple_of(8) && offset.checked_add(8)? <= window.byte_len as u64).then(
                    || {
                        // SAFETY: the primary alias maps this MM's primary
                        // arena at `root`, and the pool window every arena at
                        // its own address; the caller holds the MM's exact
                        // editor, and the offset was bounds-checked above.
                        unsafe {
                            (*window.words.add((offset / 8) as usize)).load(Ordering::Acquire)
                        }
                    },
                )
            })
        };
        classify_stage1_range(&read, root, va, len)
    }

    fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)> {
        let page = carrick_el1_abi::frame_grant_residency_guest().lookup(mm_key, va)?;
        Some((
            page.identity.semantic_base,
            page.identity.semantic_base + page.identity.len,
        ))
    }
}

#[cfg(target_os = "none")]
impl AnonymousPermissionEditor for HardwareAnonymousEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError> {
        HardwareAnonymousPermissionEditor.protect_and_invalidate(ttbr0, edit)
    }
}

#[cfg(target_os = "none")]
impl AnonymousRetirementEditor for HardwareAnonymousEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError> {
        HardwareAnonymousRetirementEditor.retire_and_invalidate(ttbr0, address, len)
    }
}

/// Where a delegated MM's anonymous syscall went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedAnonymous {
    /// No admitted root owns this MM's anonymous memory: the caller keeps its
    /// pre-delegation path, unchanged.
    NotDelegated,
    /// Served in EL1; the result is in `x0`.
    Served,
    /// The host venue runs the same root for the unchanged syscall. Any
    /// proposal was refused first, so the root is exactly as before.
    Forward,
}

/// brk/mmap/munmap/mprotect for an MM whose shared reservation root is
/// admitted. The root decides; a `Work` proposal completes in EL1 as one
/// transaction under the MM's exact editor: a range with no stage-1 backing
/// completes root-only (zero-backing receipt), a fully EL1-private backed
/// range takes the permission or retirement editor step first, and a
/// retirement's frames are journaled as an owed return for the host's bulk
/// receipt at its next boundary. Everything else refuses the proposal and
/// forwards. Counts served or forwarded exactly once.
pub fn serve_delegated_anonymous<E: AnonymousDescriptorEditor>(
    frame: &mut TrapFrame,
    counters: &carrick_el1_abi::Counters,
    current: &CurrentTask,
    spaces: &AddressSpaces,
    table: &reservations::SharedReservations,
    editor: &mut E,
) -> DelegatedAnonymous {
    let nr = frame.x[8];
    let Some((mm, index)) = delegated_anonymous_root(nr, current, spaces, table) else {
        return DelegatedAnonymous::NotDelegated;
    };
    let mm_key = mm.raw();
    let forward = |why: carrick_el1_abi::AnonymousLeave| {
        counters.forwarded[nr as usize].fetch_add(1, Ordering::Relaxed);
        counters.anonymous_leaves[why as usize].fetch_add(1, Ordering::Relaxed);
        DelegatedAnonymous::Forward
    };
    use carrick_el1_abi::AnonymousLeave as Leave;
    // Busy: the host venue holds the root; it serves the syscall itself.
    let Ok(mut model) = table.lock_el1(index.index(), mm, frame.slot as u32) else {
        return forward(Leave::RootBusy);
    };
    let mut pending = match crate::personality::dispatch::dispatch_anonymous_with_reservations(
        frame, counters, current, &mut model,
    ) {
        crate::personality::dispatch::AnonymousReservationRoute::Action(
            carrick_el1_abi::Action::Served,
        ) => return DelegatedAnonymous::Served,
        // `forwarded[nr]` counted by the route.
        crate::personality::dispatch::AnonymousReservationRoute::Action(_) => {
            counters.anonymous_leaves[Leave::RootDeclined as usize].fetch_add(1, Ordering::Relaxed);
            return DelegatedAnonymous::Forward;
        }
        crate::personality::dispatch::AnonymousReservationRoute::Unavailable(_) => {
            return forward(Leave::RootUnavailable);
        }
        crate::personality::dispatch::AnonymousReservationRoute::Work(pending) => pending,
    };
    let request = pending.request();
    let refuse = |pending: PendingReservationSyscall,
                  model: &mut reservations::Reservations<'_>,
                  why: Leave| {
        // The proposal is this guard's own; refusing it cannot be stale.
        let _ = pending.cancel(model);
        forward(why)
    };
    let (Some(grant), Some(owner)) = (spaces.grant(index, mm_key), NonZeroU64::new(frame.slot + 1))
    else {
        return refuse(pending, &mut model, Leave::NoGrant);
    };
    let Some(_editor_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return refuse(pending, &mut model, Leave::EditorBusy);
    };
    let (va, len) = (request.range.start(), request.range.len());
    if request.operation == carrick_el1_abi::ReservationOperation::Move {
        return refuse(pending, &mut model, Leave::RootDeclined);
    }
    let backing = editor.backing(grant.ttbr0, va, len);
    // One editor call is one all-or-nothing step: a range whose backing is
    // split into several runs by holes goes to the host.
    let run = match backing.runs() {
        [] => None,
        [(start, end)] => Some((*start, *end - *start)),
        _ => return refuse(pending, &mut model, Leave::BackingMultiRun),
    };
    use carrick_el1_abi::ReservationOperation::{Prepare, Protect, Retire};
    // A fresh mapping into a root hole over this MM's first-touch stock
    // adopts it: zero backing EL1 never exposed, re-permissioned for the
    // mapping and committed on first touch; any rest of the range has no
    // terminal and stays lazy. Anything else prepared is a replaced
    // mapping's backing and is retired as an owed return.
    let adopts_stock = request.operation == Prepare
        && backing.summary == RangeBacking::Prepared
        && run.is_some_and(|(start, run_len)| {
            editor
                .stock_span(mm_key, start)
                .is_some_and(|(base, end)| base <= start && start + run_len <= end)
        })
        && {
            let mut nodes = 0usize;
            model
                .observe_range(request.range, &mut |_| nodes += 1)
                .is_ok()
                && nodes == 0
        };
    let owed_return = match (request.operation, backing.summary, run) {
        (_, RangeBacking::Foreign, _) => {
            return refuse(pending, &mut model, backing.foreign.leave());
        }
        // The root refused overlapping proposals while this retirement was
        // owed. Reaching Prepare means the host acknowledged its stage-2 and
        // inventory return. A retained invalid retired terminal exposes no
        // bytes: keep it invalid and publish only the fresh lazy reservation.
        // First touch obtains new zero backing under the new incarnation.
        (Prepare, RangeBacking::Retired, None) => None,
        (_, RangeBacking::Retired, _) => {
            return refuse(pending, &mut model, Leave::BackingRetired);
        }
        (_, RangeBacking::Empty, _) | (_, _, None) => None,
        // The permission editor is the descriptor step of an mprotect and
        // of a stock adoption alike (prepared leaves stay invalid).
        (Protect, RangeBacking::Private | RangeBacking::Prepared, Some((start, run_len)))
        | (Prepare, RangeBacking::Prepared, Some((start, run_len)))
            if request.operation == Protect || adopts_stock =>
        {
            let edit = GuestPermissionEdit {
                va: start,
                len: run_len,
                readable: request.protection.bits() & PROT_READ != 0,
                writable: request.protection.bits() & PROT_WRITE != 0,
                executable: request.protection.bits() & PROT_EXEC != 0,
            };
            match editor.protect_and_invalidate(grant.ttbr0, edit) {
                Ok(()) => None,
                Err(GuestPermissionEditError::RollbackFailed) => {
                    panic!("EL1 anonymous permission rollback failed")
                }
                Err(_) => return refuse(pending, &mut model, Leave::EditRefused),
            }
        }
        (
            Retire | Prepare,
            RangeBacking::Private | RangeBacking::Prepared,
            Some((start, run_len)),
        ) => {
            // The journal slot first: after the descriptor step the commit
            // must not fail for lack of room. The whole range is owed; its
            // pages without a terminal have nothing to return.
            let Ok(slot) = model.reserve_return(request.range) else {
                return refuse(pending, &mut model, Leave::JournalFull);
            };
            match editor.retire_and_invalidate(grant.ttbr0, start, run_len) {
                Ok(()) => {
                    #[cfg(target_os = "none")]
                    carrick_el1_abi::frame_grant_residency_guest()
                        .retire_overlapping(mm_key, va, len);
                    Some(slot)
                }
                Err(GuestRetirementError::RollbackFailed) => {
                    panic!("EL1 anonymous retirement rollback failed")
                }
                Err(_) => {
                    model.release_return(slot);
                    return refuse(pending, &mut model, Leave::EditRefused);
                }
            }
        }
        _ => return refuse(pending, &mut model, Leave::RootDeclined),
    };
    // SAFETY: this guard holds the exact MM's root with `request` pending and
    // its exact descriptor editor. Every descriptor edit and its ASID
    // invalidation completed above; no frame was granted, and none was
    // returned yet: a retirement's frames stay in the inventory as an owed
    // return, journaled in its reserved slot by the commit. The pending sequence names
    // this substrate transaction.
    let completion = unsafe {
        carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            carrick_el1_abi::ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    };
    let retired = owed_return.is_some();
    let completed = match (completion, owed_return) {
        (Some(completion), Some(slot)) => pending
            .complete_deferring_return(frame, current, counters, &mut model, completion, slot),
        (Some(completion), None) => {
            pending.complete(frame, current, counters, &mut model, completion)
        }
        (None, slot) => {
            if let Some(slot) = slot {
                model.release_return(slot);
            }
            Err(reservations::Refusal::Invalid)
        }
    };
    match completed {
        Ok(()) => DelegatedAnonymous::Served,
        // The descriptor edit is live but the root refused to commit it.
        Err(refusal) if retired => {
            panic!("EL1 anonymous retirement commit refused: {refusal:?}")
        }
        Err(_) => refuse(pending, &mut model, Leave::RootUnavailable),
    }
}

/// The admitted root that owns syscall `nr` when it is a delegated MM's
/// anonymous `brk`/`mmap`/`munmap`/`mprotect` (`None`: the MM keeps the
/// paths it had before admission).
pub fn delegated_anonymous_root(
    nr: u64,
    current: &CurrentTask,
    spaces: &AddressSpaces,
    table: &reservations::SharedReservations,
) -> Option<(
    carrick_el1_abi::ReservationMm,
    carrick_sched_core::spaces::SpaceIndex,
)> {
    if !matches!(nr, SYS_BRK | SYS_MUNMAP | SYS_MMAP | SYS_MPROTECT) {
        return None;
    }
    let mm_key = current.zone_mm.load(Ordering::Acquire);
    let mm = carrick_el1_abi::ReservationMm::new(mm_key)?;
    let index = spaces.find(mm_key)?;
    table.admitted(index.index(), mm).then_some((mm, index))
}

/// Try to retire a complete resident private-anonymous `munmap(2)` range in
/// EL1. Policy and backing retirement still cross one host boundary after a
/// successful edit; every mapping shape that is not proven by live tagged
/// terminals stays on the existing host path without mutation.
pub fn try_serve_munmap<E: AnonymousRetirementEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> MunmapDisposition {
    if frame.x[8] != SYS_MUNMAP {
        return MunmapDisposition::Forward;
    }
    let address = frame.x[0];
    let requested_len = frame.x[1];
    if !address.is_multiple_of(PAGE_SIZE) || requested_len == 0 {
        return MunmapDisposition::Return(-EINVAL);
    }
    let Some(len) = requested_len
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return MunmapDisposition::Return(-ENOMEM);
    };
    if address.checked_add(len).is_none() {
        return MunmapDisposition::Return(-ENOMEM);
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return MunmapDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return MunmapDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return MunmapDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return MunmapDisposition::Forward;
    };
    let Some(_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return MunmapDisposition::Forward;
    };
    match editor.retire_and_invalidate(grant.ttbr0, address, len) {
        Ok(()) => {
            #[cfg(target_os = "none")]
            carrick_el1_abi::frame_grant_residency_guest().retire_overlapping(mm_key, address, len);
            MunmapDisposition::Retired
        }
        Err(GuestRetirementError::BadRange) => MunmapDisposition::Return(-EINVAL),
        Err(
            GuestRetirementError::TableOutsidePrimary
            | GuestRetirementError::MissingTable
            | GuestRetirementError::NotPrivateAnonymous,
        ) => MunmapDisposition::Forward,
        Err(GuestRetirementError::RollbackFailed) => {
            panic!("EL1 anonymous retirement rollback failed")
        }
    }
}

/// Try to serve canonical AArch64 `mprotect(2)` for a fully resident
/// private-anonymous range. Every other mapping shape remains on the host path.
pub fn try_serve_mprotect<E: AnonymousPermissionEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> MprotectDisposition {
    if frame.x[8] != SYS_MPROTECT {
        return MprotectDisposition::Forward;
    }
    let address = frame.x[0];
    let requested_len = frame.x[1];
    let prot = frame.x[2];
    if !address.is_multiple_of(PAGE_SIZE) || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return MprotectDisposition::Return(-EINVAL);
    }
    if requested_len == 0 {
        return MprotectDisposition::Forward;
    }
    let Some(len) = requested_len
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return MprotectDisposition::Return(-EINVAL);
    };
    if address.checked_add(len).is_none() {
        return MprotectDisposition::Return(-EINVAL);
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return MprotectDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return MprotectDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return MprotectDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return MprotectDisposition::Forward;
    };
    let Some(guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return MprotectDisposition::Forward;
    };
    // Decided before the tables change: this editor is the only producer, so
    // room now is room when the edit is recorded.
    let journal_room = guard.journal_has_room();
    let edit = GuestPermissionEdit {
        va: address,
        len,
        readable: prot & PROT_READ != 0,
        writable: prot & PROT_WRITE != 0,
        executable: prot & PROT_EXEC != 0,
    };
    match editor.protect_and_invalidate(grant.ttbr0, edit) {
        Ok(()) if journal_room => {
            // The host applies this, in order, before it next reads the
            // MM's VMA rows; no exit now.
            let recorded = guard.journal_protect(address, address + len, (prot & 7) as u8);
            debug_assert!(recorded.is_ok());
            MprotectDisposition::Return(0)
        }
        Ok(()) => MprotectDisposition::ReturnWithWork,
        Err(GuestPermissionEditError::BadRange) => MprotectDisposition::Return(-EINVAL),
        Err(GuestPermissionEditError::PermissionWidening) => MprotectDisposition::Forward,
        Err(
            GuestPermissionEditError::TableOutsidePrimary
            | GuestPermissionEditError::MissingTable
            | GuestPermissionEditError::NotPrivateAnonymous
            | GuestPermissionEditError::Manager(_),
        ) => MprotectDisposition::Forward,
        Err(GuestPermissionEditError::RollbackFailed) => {
            panic!("EL1 anonymous permission rollback failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingEditor {
        calls: Vec<(u64, GuestPermissionEdit)>,
        result: Option<GuestPermissionEditError>,
    }

    impl AnonymousPermissionEditor for RecordingEditor {
        fn protect_and_invalidate(
            &mut self,
            ttbr0: u64,
            edit: GuestPermissionEdit,
        ) -> Result<(), GuestPermissionEditError> {
            self.calls.push((ttbr0, edit));
            self.result.map_or(Ok(()), Err)
        }
    }

    fn fixture(prot: u64) -> (TrapFrame, [CurrentTask; 1], AddressSpaces, u64) {
        let mm = 17;
        let ttbr0 = (9_u64 << 48) | 0x8800_0000_0000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        spaces.open(index);
        let mut frame = TrapFrame::default();
        frame.x[8] = SYS_MPROTECT;
        frame.x[0] = 0x6000_0000;
        frame.x[1] = 0x2001;
        frame.x[2] = prot;
        (frame, [task], spaces, ttbr0)
    }

    #[test]
    fn resident_anonymous_mprotect_rounds_and_edits_under_exact_mm_guard() {
        let (frame, tasks, spaces, ttbr0) = fixture(PROT_READ);
        let mut editor = RecordingEditor::default();
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut editor),
            MprotectDisposition::Return(0)
        );
        assert_eq!(
            editor.calls,
            vec![(
                ttbr0,
                GuestPermissionEdit {
                    va: frame.x[0],
                    len: 0x3000,
                    readable: true,
                    writable: false,
                    executable: false,
                }
            )]
        );
        assert_eq!(spaces.active_editor(spaces.find(17).unwrap()), None);
        // The host learns of the edit from the journal, not from an exit.
        let mut seen = Vec::new();
        assert_eq!(spaces.drain_vma_journal(17, |edit| seen.push(edit)), 1);
        assert_eq!(
            seen,
            vec![carrick_sched_core::VmaEdit {
                start: frame.x[0],
                end: frame.x[0] + 0x3000,
                prot: PROT_READ as u8,
            }]
        );
    }

    #[test]
    fn a_full_journal_leaves_with_work_and_never_loses_an_edit() {
        let (frame, tasks, spaces, _) = fixture(PROT_READ);
        for _ in 0..carrick_sched_core::VMA_JOURNAL_ENTRIES {
            let mut editor = RecordingEditor::default();
            assert_eq!(
                try_serve_mprotect(&frame, &tasks, &spaces, &mut editor),
                MprotectDisposition::Return(0)
            );
        }
        // Full: the hardware edit still happens, but the host must cross.
        let mut editor = RecordingEditor::default();
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut editor),
            MprotectDisposition::ReturnWithWork
        );
        assert_eq!(editor.calls.len(), 1);
        assert_eq!(
            spaces.pending_vma_edits(17),
            carrick_sched_core::VMA_JOURNAL_ENTRIES as u64
        );
        // The host drains, and EL1 journals again.
        assert_eq!(
            spaces.drain_vma_journal(17, |_| {}),
            carrick_sched_core::VMA_JOURNAL_ENTRIES
        );
        let mut editor = RecordingEditor::default();
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut editor),
            MprotectDisposition::Return(0)
        );
    }

    #[test]
    fn a_refused_or_forwarded_mprotect_journals_nothing() {
        let (frame, tasks, spaces, _) = fixture(PROT_READ);
        let mut refused = RecordingEditor {
            result: Some(GuestPermissionEditError::BadRange),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut refused),
            MprotectDisposition::Return(-EINVAL)
        );
        let mut widening = RecordingEditor {
            result: Some(GuestPermissionEditError::PermissionWidening),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut widening),
            MprotectDisposition::Forward
        );
        assert_eq!(spaces.pending_vma_edits(17), 0);
    }

    #[test]
    fn ineligible_mapping_and_permission_widening_forward() {
        let (frame, tasks, spaces, _) = fixture(PROT_READ | PROT_WRITE);
        let mut ineligible = RecordingEditor {
            result: Some(GuestPermissionEditError::NotPrivateAnonymous),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut ineligible),
            MprotectDisposition::Forward
        );

        let mut widening = RecordingEditor {
            result: Some(GuestPermissionEditError::PermissionWidening),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut widening),
            MprotectDisposition::Forward
        );
    }

    #[derive(Default)]
    struct RecordingRetirementEditor {
        calls: Vec<(u64, u64, u64)>,
        result: Option<GuestRetirementError>,
    }

    impl AnonymousRetirementEditor for RecordingRetirementEditor {
        fn retire_and_invalidate(
            &mut self,
            ttbr0: u64,
            address: u64,
            len: u64,
        ) -> Result<(), GuestRetirementError> {
            self.calls.push((ttbr0, address, len));
            self.result.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn resident_anonymous_munmap_retires_under_exact_mm_guard() {
        let (mut frame, tasks, spaces, ttbr0) = fixture(PROT_READ | PROT_WRITE);
        frame.x[8] = SYS_MUNMAP;
        frame.x[1] = 0x2001;
        let mut editor = RecordingRetirementEditor::default();
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Retired
        );
        assert_eq!(editor.calls, vec![(ttbr0, frame.x[0], 0x3000)]);
        assert_eq!(spaces.active_editor(spaces.find(17).unwrap()), None);
    }

    #[test]
    fn malformed_or_ineligible_munmap_preserves_linux_fallback() {
        let (mut frame, tasks, spaces, _) = fixture(PROT_READ | PROT_WRITE);
        frame.x[8] = SYS_MUNMAP;
        frame.x[0] += 1;
        let mut editor = RecordingRetirementEditor::default();
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Return(-EINVAL)
        );
        assert!(editor.calls.is_empty());

        frame.x[0] -= 1;
        editor.result = Some(GuestRetirementError::NotPrivateAnonymous);
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Forward
        );

        frame.x[1] = 0;
        editor.result = None;
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Return(-EINVAL)
        );
    }

    mod delegated {
        use super::super::reservations::{
            DEFERRED_RETURNS, DeferredReturn, Layout, Refusal, SharedReservations,
        };
        use super::super::*;
        use carrick_el1_abi::{
            Counters, ReservationMm, ReservationProtection, ReservationRange, ReservationSequence,
        };
        use std::boxed::Box;

        const ARENA: u64 = 0x100000;

        fn table() -> Box<SharedReservations> {
            // Every atomic and node is zero-valid; root state is MaybeUninit.
            let ptr = unsafe {
                std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>())
            };
            assert!(!ptr.is_null());
            unsafe { Box::from_raw(ptr.cast()) }
        }
        fn layout() -> Layout {
            Layout {
                heap: ReservationRange::new(0x1000, ARENA).unwrap(),
                arena: ReservationRange::new(ARENA, 0x1000000).unwrap(),
                brk: 0x1000,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            }
        }

        /// One MM: its published address space, its root (admitted or
        /// not) in the same slot, and a task running in it.
        struct Mm {
            key: u64,
            ttbr0: u64,
            task: CurrentTask,
        }
        fn mm(spaces: &AddressSpaces, table: &SharedReservations, key: u64, admit: bool) -> Mm {
            let ttbr0 = (key << 48) | 0x8800_0000_0000;
            let index = spaces.publish_closed(key, ttbr0, ttbr0).unwrap();
            spaces.open(index);
            let raw = ReservationMm::new(key).unwrap();
            table.publish(index.index(), raw, layout()).unwrap();
            if admit {
                table
                    .lock(index.index(), raw)
                    .unwrap()
                    .finish_import()
                    .unwrap();
            }
            let task = CurrentTask::new();
            task.task_id.store(key + 100, Ordering::Relaxed);
            task.thread_serial.store(11, Ordering::Relaxed);
            task.zone_mm.store(key, Ordering::Relaxed);
            Mm { key, ttbr0, task }
        }
        fn root<'a>(
            spaces: &AddressSpaces,
            table: &'a SharedReservations,
            mm: &Mm,
        ) -> reservations::Reservations<'a> {
            table
                .lock(
                    spaces.find(mm.key).unwrap().index(),
                    ReservationMm::new(mm.key).unwrap(),
                )
                .unwrap()
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Call {
            Probe(u64, u64, u64),
            Protect(u64, GuestPermissionEdit),
            Retire(u64, u64, u64),
        }
        struct Editor {
            backing: RangeBacking,
            protect: Option<GuestPermissionEditError>,
            /// `(mm, start, end)` of this MM's live first-touch stock.
            stock: Option<(u64, u64, u64)>,
            /// Backed runs to report; `None`: the whole queried range.
            runs: Option<&'static [(u64, u64)]>,
            calls: Vec<Call>,
        }
        impl Editor {
            fn over(backing: RangeBacking) -> Self {
                Self {
                    backing,
                    protect: None,
                    stock: None,
                    runs: None,
                    calls: Vec::new(),
                }
            }
        }
        impl AnonymousBackingProbe for Editor {
            fn backing(&mut self, ttbr0: u64, va: u64, len: u64) -> Stage1Backing {
                self.calls.push(Call::Probe(ttbr0, va, len));
                match self.runs {
                    Some(runs) => Stage1Backing::with_runs(self.backing, runs),
                    None if matches!(
                        self.backing,
                        RangeBacking::Private | RangeBacking::Prepared
                    ) =>
                    {
                        Stage1Backing::with_runs(self.backing, &[(va, va + len)])
                    }
                    None => Stage1Backing::of(self.backing),
                }
            }
            fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)> {
                self.stock
                    .filter(|&(mm, start, end)| mm == mm_key && start <= va && va < end)
                    .map(|(_, start, end)| (start, end))
            }
        }
        impl AnonymousPermissionEditor for Editor {
            fn protect_and_invalidate(
                &mut self,
                ttbr0: u64,
                edit: GuestPermissionEdit,
            ) -> Result<(), GuestPermissionEditError> {
                self.calls.push(Call::Protect(ttbr0, edit));
                self.protect.map_or(Ok(()), Err)
            }
        }
        impl AnonymousRetirementEditor for Editor {
            fn retire_and_invalidate(
                &mut self,
                ttbr0: u64,
                address: u64,
                len: u64,
            ) -> Result<(), GuestRetirementError> {
                self.calls.push(Call::Retire(ttbr0, address, len));
                Ok(())
            }
        }

        fn syscall(
            mm: &Mm,
            spaces: &AddressSpaces,
            table: &SharedReservations,
            counters: &Counters,
            editor: &mut Editor,
            nr: u64,
            args: [u64; 6],
        ) -> (DelegatedAnonymous, i64) {
            let mut frame = TrapFrame {
                elr: 0x40004,
                ..TrapFrame::default()
            };
            frame.x[8] = nr;
            frame.x[..6].copy_from_slice(&args);
            let route =
                serve_delegated_anonymous(&mut frame, counters, &mm.task, spaces, table, editor);
            (route, frame.x[0] as i64)
        }
        const RW: u64 = PROT_READ | PROT_WRITE;
        const ANON: u64 = MAP_PRIVATE | MAP_ANONYMOUS;
        fn mmap_fixed(address: u64, len: u64) -> [u64; 6] {
            [address, len, RW, ANON | MAP_FIXED, u64::MAX, 0]
        }
        fn owed_returns(model: &reservations::Reservations<'_>) -> Vec<DeferredReturn> {
            let mut owed = Vec::new();
            model.observe_deferred_returns(&mut |entry| owed.push(entry));
            owed
        }

        #[test]
        fn mmap_unrepresented_protection_preserves_host_linux_decoder() {
            assert_eq!(
                MmapProtectionRoute::decode(1 << 28),
                MmapProtectionRoute::HostUnrepresentedBits
            );
            assert_eq!(
                MmapProtectionRoute::decode(1 << 27),
                MmapProtectionRoute::HostUnrepresentedBits
            );
            for bits in 0..8 {
                assert!(matches!(
                    MmapProtectionRoute::decode(bits),
                    MmapProtectionRoute::Reservation(_)
                ));
            }
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let delegated = mm(&spaces, &table, 17, true);
            let mut editor = Editor::over(RangeBacking::Empty);
            let (route, _) = syscall(
                &delegated,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MMAP,
                [0, 0x1000, 1 << 28, ANON, u64::MAX, 0],
            );
            assert_eq!(route, DelegatedAnonymous::Forward);
            assert!(editor.calls.is_empty());
        }

        #[test]
        fn delegated_route_serves_admitted_root_and_leaves_unadmitted_mm_unchanged() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let delegated = mm(&spaces, &table, 17, true);
            let host = mm(&spaces, &table, 18, false);
            let mut editor = Editor::over(RangeBacking::Empty);
            for nr in [SYS_BRK, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP] {
                let args = if nr == SYS_MMAP {
                    mmap_fixed(ARENA, 0x2000)
                } else if nr == SYS_BRK {
                    [0x3000, 0, 0, 0, 0, 0]
                } else {
                    [ARENA, 0x2000, PROT_READ, 0, 0, 0]
                };
                assert_eq!(
                    syscall(&host, &spaces, &table, &counters, &mut editor, nr, args).0,
                    DelegatedAnonymous::NotDelegated,
                    "unadmitted MM, syscall {nr}"
                );
                let (route, result) = syscall(
                    &delegated,
                    &spaces,
                    &table,
                    &counters,
                    &mut editor,
                    nr,
                    args,
                );
                assert_eq!(
                    route,
                    DelegatedAnonymous::Served,
                    "admitted MM, syscall {nr}"
                );
                assert!(result >= 0, "syscall {nr}: {result}");
            }
            // Only the admitted MM's exact space was probed, and only its root
            // changed: brk moved, the mapping came and went.
            assert!(
                editor.calls.iter().all(
                    |call| matches!(call, Call::Probe(ttbr0, ..) if *ttbr0 == delegated.ttbr0)
                )
            );
            let mut model = root(&spaces, &table, &delegated);
            assert_eq!(model.brk_current(), 0x3000);
            assert_eq!(model.mapping(ARENA), None);
            let untouched = root(&spaces, &table, &host);
            assert!(!untouched.is_admitted());
            assert_eq!(untouched.brk_current(), 0x1000);
            for nr in [SYS_BRK, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP] {
                assert_eq!(counters.served[nr as usize].load(Ordering::Relaxed), 1);
                assert_eq!(counters.forwarded[nr as usize].load(Ordering::Relaxed), 0);
            }
        }

        #[test]
        fn delegated_lazy_edits_complete_in_guest_with_a_zero_backing_receipt() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let mut editor = Editor::over(RangeBacking::Empty);
            let (route, address) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MMAP,
                [0, 0x3000, RW, ANON, u64::MAX, 0],
            );
            assert_eq!((route, address as u64), (DelegatedAnonymous::Served, ARENA));
            let address = address as u64;
            let (route, result) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MPROTECT,
                [address, 0x1000, PROT_READ, 0, 0, 0],
            );
            assert_eq!((route, result), (DelegatedAnonymous::Served, 0));
            assert_eq!(
                root(&spaces, &table, &task)
                    .mapping(address)
                    .unwrap()
                    .protection,
                ReservationProtection::from_bits(PROT_READ).unwrap()
            );
            let (route, result) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MUNMAP,
                [address, 0x3000, 0, 0, 0, 0],
            );
            assert_eq!((route, result), (DelegatedAnonymous::Served, 0));
            // Nothing was backed: no descriptor step ran and no return is owed.
            assert!(
                editor
                    .calls
                    .iter()
                    .all(|call| matches!(call, Call::Probe(..)))
            );
            let mut model = root(&spaces, &table, &task);
            assert_eq!(model.mapping(address), None);
            assert!(model.pending().is_none());
            assert!(owed_returns(&model).is_empty());
        }

        #[test]
        fn delegated_resident_edits_take_the_editor_step_of_the_root_transaction() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let mut editor = Editor::over(RangeBacking::Empty);
            syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MMAP,
                mmap_fixed(ARENA, 0x4000),
            );
            // The pages were touched since.
            let mut editor = Editor::over(RangeBacking::Private);
            let (route, result) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MPROTECT,
                [ARENA, 0x1001, PROT_READ, 0, 0, 0],
            );
            assert_eq!((route, result), (DelegatedAnonymous::Served, 0));
            let (route, result) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MUNMAP,
                [ARENA + 0x2000, 0x2000, 0, 0, 0, 0],
            );
            assert_eq!((route, result), (DelegatedAnonymous::Served, 0));
            assert_eq!(
                editor.calls,
                vec![
                    Call::Probe(task.ttbr0, ARENA, 0x2000),
                    Call::Protect(
                        task.ttbr0,
                        GuestPermissionEdit {
                            va: ARENA,
                            len: 0x2000,
                            readable: true,
                            writable: false,
                            executable: false,
                        }
                    ),
                    Call::Probe(task.ttbr0, ARENA + 0x2000, 0x2000),
                    Call::Retire(task.ttbr0, ARENA + 0x2000, 0x2000),
                ]
            );
            let mut model = root(&spaces, &table, &task);
            assert_eq!(model.mapping(ARENA + 0x2000), None);
            assert_eq!(
                model.mapping(ARENA).unwrap().protection,
                ReservationProtection::from_bits(PROT_READ).unwrap()
            );
            // The munmap crossed no boundary: its frames are an owed return.
            let owed = owed_returns(&model);
            assert_eq!(owed.len(), 1);
            assert_eq!(
                owed[0].range,
                ReservationRange::new(ARENA + 0x2000, ARENA + 0x4000).unwrap()
            );
            assert_eq!(
                counters.served[SYS_MUNMAP as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(
                counters.forwarded[SYS_MUNMAP as usize].load(Ordering::Relaxed),
                0
            );
        }

        #[test]
        fn delegated_busy_root_or_unservable_step_forwards_with_the_root_unchanged() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let mut editor = Editor::over(RangeBacking::Empty);
            syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut editor,
                SYS_MMAP,
                mmap_fixed(ARENA, 0x2000),
            );
            // The host venue holds the root: forward, the host runs it.
            {
                let _host = root(&spaces, &table, &task);
                let (route, _) = syscall(
                    &task,
                    &spaces,
                    &table,
                    &counters,
                    &mut editor,
                    SYS_MUNMAP,
                    [ARENA, 0x2000, 0, 0, 0, 0],
                );
                assert_eq!(route, DelegatedAnonymous::Forward);
            }
            // A step EL1 cannot take refuses the proposal, then forwards.
            let mut widening = Editor::over(RangeBacking::Private);
            widening.protect = Some(GuestPermissionEditError::PermissionWidening);
            let cases: [(Editor, u64, [u64; 6]); 4] = [
                (
                    widening,
                    SYS_MPROTECT,
                    [ARENA, 0x2000, RW | PROT_EXEC, 0, 0, 0],
                ),
                (
                    Editor::over(RangeBacking::Foreign),
                    SYS_MUNMAP,
                    [ARENA, 0x2000, 0, 0, 0, 0],
                ),
                (
                    Editor::over(RangeBacking::Retired),
                    SYS_MPROTECT,
                    [ARENA, 0x2000, PROT_READ, 0, 0, 0],
                ),
                (
                    Editor::over(RangeBacking::Foreign),
                    SYS_MMAP,
                    mmap_fixed(ARENA, 0x2000),
                ),
            ];
            let generation = root(&spaces, &table, &task).generation();
            for (mut editor, nr, args) in cases {
                let (route, _) = syscall(&task, &spaces, &table, &counters, &mut editor, nr, args);
                assert_eq!(route, DelegatedAnonymous::Forward, "syscall {nr}");
                assert!(
                    !editor
                        .calls
                        .iter()
                        .any(|call| matches!(call, Call::Retire(..)))
                );
                let mut model = root(&spaces, &table, &task);
                assert!(model.pending().is_none());
                assert_eq!(model.generation(), generation);
                assert_eq!(
                    model.mapping(ARENA).unwrap().range,
                    ReservationRange::new(ARENA, ARENA + 0x2000).unwrap()
                );
            }
            assert_eq!(
                counters.forwarded[SYS_MUNMAP as usize].load(Ordering::Relaxed),
                2
            );
            assert_eq!(
                counters.forwarded[SYS_MPROTECT as usize].load(Ordering::Relaxed),
                2
            );
            assert_eq!(
                counters.forwarded[SYS_MMAP as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(
                counters.served[SYS_MUNMAP as usize].load(Ordering::Relaxed),
                0
            );
        }

        #[test]
        fn delegated_retired_frames_stay_unreusable_until_the_inventory_receipt() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let child = mm(&spaces, &table, 19, false);
            let mut lazy = Editor::over(RangeBacking::Empty);
            let mut resident = Editor::over(RangeBacking::Private);
            syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut lazy,
                SYS_MMAP,
                mmap_fixed(ARENA, 0x2000),
            );
            let (route, _) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut resident,
                SYS_MUNMAP,
                [ARENA, 0x2000, 0, 0, 0, 0],
            );
            assert_eq!(route, DelegatedAnonymous::Served);
            // The VA holding the unreconciled frames is not handed out again,
            // not even as fresh lazy memory, by either venue.
            let (route, _) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut lazy,
                SYS_MMAP,
                mmap_fixed(ARENA + 0x1000, 0x1000),
            );
            assert_eq!(route, DelegatedAnonymous::Forward);
            let owed = {
                let mut model = root(&spaces, &table, &task);
                assert_eq!(
                    model.mmap(
                        reservations::Placement::Fixed(ARENA),
                        0x1000,
                        ReservationProtection::READ_WRITE
                    ),
                    Err(Refusal::Busy)
                );
                // Fork and teardown plan from settled memory only.
                let mut child_root = root(&spaces, &table, &child);
                assert_eq!(model.clone_into(&mut child_root), Err(Refusal::Busy));
                let owed = owed_returns(&model);
                assert_eq!(owed.len(), 1);
                assert_eq!(
                    owed[0].range,
                    ReservationRange::new(ARENA, ARENA + 0x2000).unwrap()
                );
                // An older receipt does not release a newer retirement.
                let older = ReservationSequence::new(owed[0].sequence.raw() - 1).unwrap();
                assert_eq!(model.acknowledge_deferred_returns(older), Ok(0));
                owed[0]
            };
            assert_eq!(
                root(&spaces, &table, &task).retire().err(),
                Some(Refusal::Busy)
            );
            // The host reconciled stage-2 and the inventory: its receipt
            // releases the frames and the VA.
            assert_eq!(
                root(&spaces, &table, &task).acknowledge_deferred_returns(owed.sequence),
                Ok(1)
            );
            let mut returned_backing = Editor::over(RangeBacking::Retired);
            let (route, address) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut returned_backing,
                SYS_MMAP,
                mmap_fixed(ARENA + 0x1000, 0x1000),
            );
            assert_eq!(
                (route, address as u64),
                (DelegatedAnonymous::Served, ARENA + 0x1000)
            );
            assert_eq!(
                returned_backing.calls,
                vec![Call::Probe(task.ttbr0, ARENA + 0x1000, 0x1000)]
            );
            assert!(owed_returns(&root(&spaces, &table, &task)).is_empty());
        }

        #[test]
        fn delegated_full_return_journal_forwards_the_next_resident_retirement() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let mut lazy = Editor::over(RangeBacking::Empty);
            let pages = DEFERRED_RETURNS as u64 + 1;
            syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut lazy,
                SYS_MMAP,
                mmap_fixed(ARENA, pages * 0x2000),
            );
            // Disjoint extents: every other page, so none merge.
            let mut resident = Editor::over(RangeBacking::Private);
            for extent in 0..pages {
                let (route, _) = syscall(
                    &task,
                    &spaces,
                    &table,
                    &counters,
                    &mut resident,
                    SYS_MUNMAP,
                    [ARENA + extent * 0x2000, 0x1000, 0, 0, 0, 0],
                );
                let expected = if extent < DEFERRED_RETURNS as u64 {
                    DelegatedAnonymous::Served
                } else {
                    DelegatedAnonymous::Forward
                };
                assert_eq!(route, expected, "extent {extent}");
            }
            let retires = resident
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Retire(..)))
                .count();
            assert_eq!(retires, DEFERRED_RETURNS);
            let mut model = root(&spaces, &table, &task);
            assert_eq!(owed_returns(&model).len(), DEFERRED_RETURNS);
            assert!(model.mapping(ARENA + (pages - 1) * 0x2000).is_some());
        }

        /// Contract `kernel.el1.anonymous-reservations` (first-touch stock):
        /// a fresh mapping into a root hole this MM's stock already backs
        /// adopts it with the permission editor alone: no retirement, no
        /// owed return, no host crossing. A replaced mapping's prepared
        /// backing, or prepared backing that is not this MM's live stock,
        /// is retired as an owed return.
        #[test]
        fn delegated_mmap_into_first_touch_stock_adopts_it() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let window = (ARENA, ARENA + 0x20_0000);
            let mut stock = Editor::over(RangeBacking::Prepared);
            stock.stock = Some((task.key, window.0, window.1));
            let (route, address) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut stock,
                SYS_MMAP,
                [0, 0x2000, PROT_READ, ANON, u64::MAX, 0],
            );
            assert_eq!((route, address as u64), (DelegatedAnonymous::Served, ARENA));
            assert_eq!(
                stock.calls,
                vec![
                    Call::Probe(task.ttbr0, ARENA, 0x2000),
                    Call::Protect(
                        task.ttbr0,
                        GuestPermissionEdit {
                            va: ARENA,
                            len: 0x2000,
                            readable: true,
                            writable: false,
                            executable: false,
                        }
                    ),
                ]
            );
            assert!(owed_returns(&root(&spaces, &table, &task)).is_empty());

            // MAP_FIXED over that mapping: its prepared backing may hold
            // bytes the host wrote; it is retired, never adopted.
            stock.calls.clear();
            let (route, _) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut stock,
                SYS_MMAP,
                mmap_fixed(ARENA, 0x2000),
            );
            assert_eq!(route, DelegatedAnonymous::Served);
            assert!(
                stock
                    .calls
                    .iter()
                    .any(|call| matches!(call, Call::Retire(..)))
            );
            assert_eq!(owed_returns(&root(&spaces, &table, &task)).len(), 1);

            // Prepared leaves that are not this MM's live stock: retired.
            let mut foreign = Editor::over(RangeBacking::Prepared);
            foreign.stock = Some((task.key + 1, window.0, window.1));
            let (route, _) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut foreign,
                SYS_MMAP,
                mmap_fixed(ARENA + 0x10_0000, 0x1000),
            );
            assert_eq!(route, DelegatedAnonymous::Served);
            assert!(
                foreign
                    .calls
                    .iter()
                    .any(|call| matches!(call, Call::Retire(..)))
            );
            assert_eq!(owed_returns(&root(&spaces, &table, &task)).len(), 2);
        }

        /// A fresh mapping that straddles the end of this MM's stock adopts
        /// the stocked part and leaves the rest lazy, still without a host
        /// crossing. Backing split into several runs is one step too many:
        /// the host serves it.
        #[test]
        fn delegated_mmap_straddling_first_touch_stock_adopts_the_stocked_part() {
            let (spaces, table, counters) = (AddressSpaces::new(), table(), Counters::default());
            let task = mm(&spaces, &table, 17, true);
            let mut straddle = Editor::over(RangeBacking::Prepared);
            straddle.stock = Some((task.key, ARENA - 0x1000, ARENA + 0x1000));
            straddle.runs = Some(&[(ARENA, ARENA + 0x1000)]);
            let (route, address) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut straddle,
                SYS_MMAP,
                [0, 0x3000, RW, ANON, u64::MAX, 0],
            );
            assert_eq!((route, address as u64), (DelegatedAnonymous::Served, ARENA));
            assert_eq!(
                straddle.calls[1..],
                [Call::Protect(
                    task.ttbr0,
                    GuestPermissionEdit {
                        va: ARENA,
                        len: 0x1000,
                        readable: true,
                        writable: true,
                        executable: false,
                    }
                )]
            );
            assert!(owed_returns(&root(&spaces, &table, &task)).is_empty());

            let mut split = Editor::over(RangeBacking::Prepared);
            split.stock = Some((task.key, ARENA, ARENA + 0x10_0000));
            split.runs = Some(&[
                (ARENA + 0x8000, ARENA + 0x9000),
                (ARENA + 0xa000, ARENA + 0xb000),
            ]);
            let (route, _) = syscall(
                &task,
                &spaces,
                &table,
                &counters,
                &mut split,
                SYS_MMAP,
                mmap_fixed(ARENA + 0x8000, 0x3000),
            );
            assert_eq!(route, DelegatedAnonymous::Forward);
            assert!(root(&spaces, &table, &task).pending().is_none());
        }

        #[test]
        fn stage1_range_classification_follows_the_live_terminals() {
            const VALID: u64 = 1;
            const TABLE: u64 = 0b11;
            const PRIVATE: u64 = 1 << 56;
            const RETIRED: u64 = 1 << 55;
            let root = 0x8000_0000u64;
            // Four table pages: L0, L1, L2, L3.
            let mut words = vec![0u64; 4 * 512];
            let va = 0x4000_0000u64; // L0[0], L1[1], L2[0]
            words[0] = (root + 0x1000) | VALID | TABLE;
            words[512 + 1] = (root + 0x2000) | VALID | TABLE;
            words[1024] = (root + 0x3000) | VALID | TABLE;
            let leaf = |page: usize| 1536 + page;
            words[leaf(0)] = 0x9000_0000 | PRIVATE | VALID | TABLE; // resident
            words[leaf(1)] = 0x9000_1000 | PRIVATE | 0b10; // prepared (invalid)
            words[leaf(3)] = 0x9000_3000 | VALID | TABLE; // host-owned
            words[leaf(4)] = 0x9000_4000 | PRIVATE | RETIRED | 0b10; // retired (invalid)
            let classify = |words: &Vec<u64>, va: u64, len: u64| {
                let read = |pa: u64| {
                    let offset = pa.checked_sub(root)?;
                    words.get((offset / 8) as usize).copied()
                };
                classify_stage1_range(&read, root, va, len).summary
            };
            let runs = |words: &Vec<u64>, va: u64, len: u64| {
                let read = |pa: u64| {
                    let offset = pa.checked_sub(root)?;
                    words.get((offset / 8) as usize).copied()
                };
                classify_stage1_range(&read, root, va, len).runs().to_vec()
            };
            assert_eq!(classify(&words, va, 0x2000), RangeBacking::Private);
            assert_eq!(
                classify(&words, va + 0x1000, 0x1000),
                RangeBacking::Prepared
            );
            assert_eq!(classify(&words, va + 0x2000, 0x1000), RangeBacking::Empty);
            // A hole beside backed pages: the backed run alone is the step.
            assert_eq!(classify(&words, va, 0x3000), RangeBacking::Private);
            assert_eq!(runs(&words, va, 0x3000), vec![(va, va + 0x2000)]);
            assert_eq!(
                runs(&words, va + 0x1000, 0x2000),
                vec![(va + 0x1000, va + 0x2000)]
            );
            assert_eq!(classify(&words, va + 0x3000, 0x1000), RangeBacking::Foreign);
            assert_eq!(classify(&words, va + 0x4000, 0x1000), RangeBacking::Retired);
            // An absent L2 table is one empty span, whatever its length.
            assert_eq!(
                classify(&words, va + (1 << 21), 1 << 30),
                RangeBacking::Empty
            );
            // A table outside the primary arena is never taken as empty.
            words[1024 + 1] = (root + 0x10_0000) | VALID | TABLE;
            assert_eq!(
                classify(&words, va + (1 << 21), 0x1000),
                RangeBacking::Foreign
            );
            // Each foreign range names its cause (the leave EL1 counts).
            let cause = |words: &Vec<u64>, va: u64, len: u64| {
                let read = |pa: u64| {
                    let offset = pa.checked_sub(root)?;
                    words.get((offset / 8) as usize).copied()
                };
                let backing = classify_stage1_range(&read, root, va, len);
                assert_eq!(backing.summary, RangeBacking::Foreign);
                backing.foreign
            };
            assert_eq!(
                cause(&words, va + 0x3000, 0x1000),
                ForeignBacking::HostOwnedLeaf
            );
            assert_eq!(
                cause(&words, va + (1 << 21), 0x1000),
                ForeignBacking::Malformed
            );
            // An L2 block without EL1 tags.
            words[1024 + 2] = 0x9040_0000 | VALID;
            assert_eq!(cause(&words, va + (2 << 21), 0x1000), ForeignBacking::Block);
            // Nine private runs separated by holes: more than one step takes.
            for page in 0..9 {
                words[leaf(16 + 2 * page)] =
                    (0x9001_0000 + page as u64 * 0x2000) | PRIVATE | VALID | TABLE;
            }
            assert_eq!(
                cause(&words, va + 0x10000, 0x12000),
                ForeignBacking::TooManyRuns
            );
        }
    }
}

//! Preserve the native fork operation and its owner refusal until errno encoding.

use carrick_core::mm::{
    fork::{ForkCensus, ForkError, ForkOwnerRefusal, ForkScratch},
    reservation::Refusal,
    transaction::MmError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkStage {
    ParentLifecycleGate {
        observed: carrick_el1_abi::GateState,
    },
    BirthReservation,
    ParentSpaceEdit,
    ParentForkReady,
    ChildLifecycleClaim,
    ChildControlReset,
    BirthPublication,
    PrepareService,
    ForkFileTable,
    CommitChildService,
    MappingCount,
    SpaceAccess,
    ParentRoot,
    ObserveMappings,
    TransferSequence,
    Census,
    PublishRoot,
    Scratch,
    Prepare,
    Publish,
    Reserve,
    Commit,
    Abort,
    OpenChildSpace,
    StockCrossing,
    /// An untyped answer reached the fork entry from the birth or its MM
    /// service ([`typed_invariant`]).
    Entry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkCause {
    Busy,
    /// A terminal close or host authority (`GateState::Closed`,
    /// `GateState::HostOnly`) shut ring births for this parent. No release
    /// reopens them, so it is no contention: a closing caller retires at its
    /// user return, and a host-only parent keeps today's EAGAIN.
    GateShut,
    Mm(MmError),
    Reservation(Refusal),
    Fork(ForkError),
    StockReservation(carrick_el1_abi::ForkStockRefusal),
    StockCrossing {
        status: u64,
        reply: Option<carrick_el1_abi::ForkStockRefusal>,
    },
    /// A sibling's in-flight birth holds this process's topology
    /// reservation. The refusing section enrolled the process on its
    /// release (`Graph::birth_waiters`) and sampled the process channel's
    /// generation here, under that same guard. Contention, never an errno:
    /// the fork parks on that channel and reruns.
    SiblingBirth {
        observed: carrick_sched_core::process::wait::TaskWakeGeneration,
    },
    /// The kernel heap missed the fork's scratch while metadata grant
    /// `grant` is in flight on the carrier mailbox: capacity is owed, so
    /// this is "not now". Waiting for the grant is a guest wait: the fork
    /// keeps its syscall, parks on the grant request's own queue and reruns
    /// once the carrier answers it (#2441). A miss nothing is owed for is
    /// `Fork(NoMemory)`.
    MetadataOwed {
        grant: carrick_el1_abi::OwedMetadataGrant,
    },
    /// The birth or its MM service answered a bare invariant refusal
    /// instead of a typed cause: the fork's own records, lifecycle page or
    /// loaned stock contradicted themselves ([`typed_invariant`]).
    Untyped(UntypedInvariant),
}

/// A bare native answer that, in a fork, names a broken invariant: the
/// fork walks no guest address, so none of them is a guest error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UntypedInvariant {
    Stale,
    Invalid,
    Quarantined,
}

impl From<MmError> for NativeForkCause {
    fn from(value: MmError) -> Self {
        Self::Mm(value)
    }
}
impl From<Refusal> for NativeForkCause {
    fn from(value: Refusal) -> Self {
        Self::Reservation(value)
    }
}
impl From<ForkError> for NativeForkCause {
    fn from(value: ForkError) -> Self {
        Self::Fork(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeForkRefusal {
    pub stage: NativeForkStage,
    pub cause: NativeForkCause,
}

/// What a native fork refusal means (#2441). Every cause has exactly one
/// class, chosen by an exhaustive match in [`NativeForkRefusal::class`]
/// with no fallback arm, so a new cause cannot silently reach the guest as
/// EFAULT; its author must pick its class.
///
/// No cause is a guest-address fault. The native fork transaction reads and
/// writes only kernel-owned state: the parent's reservations and page
/// tables, the fork scratch, and the carrier's fork stock. The clone's guest
/// pointers (`CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID`, the TLS and stack)
/// are consumed outside it. So EFAULT, which Linux never answers for a plain
/// fork, is not a fork-refusal answer here.
///
/// Per cause:
/// - [`Self::NotNow`]: `Busy`, `SiblingBirth`, `MetadataOwed` (the fork
///   parks on that grant's request queue), `MmError::{Wait, Busy}`,
///   `Refusal::{Busy, PreparedConflict}`, `ForkError::Busy`, and a stock
///   `Inventory` reply. A parent snapshot another live thread of the parent
///   moved between the census and the fork's prepare or publish is
///   `MmError::Busy` at its source: the fork reruns with a fresh snapshot.
/// - [`Self::OutOfMemory`] (ENOMEM): `MmError::{NoMemory, MetadataRequired}`,
///   `PageTableError::{OutOfTables, MetadataAllocation}`,
///   `Refusal::{Limit, MetadataRequired}`,
///   `ForkError::{NoMemory, MetadataRequired, OwnerRefusal(Limit)}`.
/// - [`Self::BirthsExhausted`] (EAGAIN): `GateShut` (no release reopens the
///   parent's births) and a stock `Capacity` reply.
/// - [`Self::Unsupported`] (a counted ENOSYS): `MmError::UnsupportedExecutableCow`.
/// - [`Self::InvariantViolation`] (fatal): the owner refused its own state.
///   `MmError::{Fault, Stale, Invalid, Core}` at every stage, and every
///   other page-table
///   error; `Refusal::{Stale, Invalid, Collision, Hole, ForeignMapping}`;
///   `ForkError::{Invalid, Stale, Core}` and the owner refusals `Invalid`,
///   `Collision`, `Hole` and `ForeignMapping`; a stock `Invalid` or `Stale`
///   reply; a stock crossing that failed without a typed reply; and an
///   untyped `Stale`, `Invalid` or `Quarantined` answer. The
///   live parent's MM cannot be retired or rewritten under its own
///   reserved birth, and the fork walks no guest address, so each of these
///   means the owner contradicted itself, never a guest error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkClass {
    /// Contention or a guest wait: the fork keeps its syscall and reruns.
    /// `Some` names the owner release it enrols on.
    NotNow(Option<carrick_core_abi::PortalOwnerWait>),
    /// Kernel memory or a mapping limit ran out: ENOMEM, as Linux answers
    /// fork and clone.
    OutOfMemory,
    /// The parent admits no more births: EAGAIN.
    BirthsExhausted,
    /// A mapping this kernel cannot fork yet: a counted ENOSYS.
    Unsupported,
    /// A broken kernel invariant: the fork entry ends the run
    /// ([`invariant_violated`]); it never reaches the guest as an errno.
    InvariantViolation,
}

impl NativeForkRefusal {
    /// The one class of this refusal's cause ([`NativeForkClass`]).
    pub fn class(self) -> NativeForkClass {
        use NativeForkClass as Class;
        match self.cause {
            NativeForkCause::Busy
            | NativeForkCause::SiblingBirth { .. }
            | NativeForkCause::MetadataOwed { .. } => Class::NotNow(None),
            NativeForkCause::GateShut => Class::BirthsExhausted,
            NativeForkCause::Mm(error) => mm_class(error),
            NativeForkCause::Reservation(refusal) => reservation_class(refusal),
            NativeForkCause::Fork(error) => fork_class(error),
            NativeForkCause::StockReservation(refusal)
            | NativeForkCause::StockCrossing {
                reply: Some(refusal),
                ..
            } => stock_class(refusal),
            NativeForkCause::StockCrossing { reply: None, .. } => Class::InvariantViolation,
            NativeForkCause::Untyped(
                UntypedInvariant::Stale | UntypedInvariant::Invalid | UntypedInvariant::Quarantined,
            ) => Class::InvariantViolation,
        }
    }

    /// The native answer of this refusal's class. An invariant violation
    /// answers `Quarantined` only off the fork entry, which ends the run
    /// before encoding one.
    pub fn error(self) -> super::native_process_runtime::NativeProcessError {
        use super::native_process_runtime::NativeProcessError as E;
        match self.class() {
            NativeForkClass::NotNow(Some(wait)) => E::OwnerWait(wait),
            NativeForkClass::NotNow(None) => E::Busy,
            NativeForkClass::OutOfMemory => E::NoMemory,
            NativeForkClass::BirthsExhausted => E::Exhausted,
            NativeForkClass::Unsupported => E::Unsupported,
            NativeForkClass::InvariantViolation => E::Quarantined,
        }
    }
}

fn mm_class(error: MmError) -> NativeForkClass {
    use NativeForkClass as Class;
    use carrick_mmu_core::aarch64::PageTableError as Table;
    match error {
        // Owner contention keeps its release to enrol on (#2306).
        MmError::Wait(wait) => Class::NotNow(Some(wait)),
        MmError::Busy => Class::NotNow(None),
        MmError::NoMemory
        | MmError::MetadataRequired
        | MmError::Table(Table::OutOfTables | Table::MetadataAllocation) => Class::OutOfMemory,
        MmError::Reservation(refusal) => reservation_class(refusal),
        MmError::UnsupportedExecutableCow => Class::Unsupported,
        MmError::Fault
        | MmError::Stale
        | MmError::Invalid
        | MmError::Core
        | MmError::Table(
            Table::BadAddress
            | Table::MissingArenaSource
            | Table::ConflictingArenaSource
            | Table::UnresolvedArena(_)
            | Table::GicWindowOutput
            | Table::GuestOwnsLiveDescriptors
            | Table::CarrickOwnedWindow,
        ) => Class::InvariantViolation,
    }
}

fn reservation_class(refusal: Refusal) -> NativeForkClass {
    use NativeForkClass as Class;
    match refusal {
        Refusal::Busy | Refusal::PreparedConflict => Class::NotNow(None),
        Refusal::Limit | Refusal::MetadataRequired => Class::OutOfMemory,
        Refusal::Stale
        | Refusal::Invalid
        | Refusal::Collision
        | Refusal::Hole
        | Refusal::ForeignMapping => Class::InvariantViolation,
    }
}

fn fork_class(error: ForkError) -> NativeForkClass {
    use NativeForkClass as Class;
    match error {
        ForkError::Busy => Class::NotNow(None),
        ForkError::NoMemory
        | ForkError::MetadataRequired
        | ForkError::OwnerRefusal(ForkOwnerRefusal::Limit) => Class::OutOfMemory,
        ForkError::Invalid
        | ForkError::Stale
        | ForkError::Core
        | ForkError::OwnerRefusal(
            ForkOwnerRefusal::Invalid
            | ForkOwnerRefusal::Collision
            | ForkOwnerRefusal::Hole
            | ForkOwnerRefusal::ForeignMapping,
        ) => Class::InvariantViolation,
    }
}

fn stock_class(refusal: carrick_el1_abi::ForkStockRefusal) -> NativeForkClass {
    use carrick_el1_abi::ForkStockRefusal as R;
    match refusal {
        R::Inventory => NativeForkClass::NotNow(None),
        R::Capacity => NativeForkClass::BirthsExhausted,
        R::Invalid | R::Stale => NativeForkClass::InvariantViolation,
    }
}

/// End the run on a fork refusal that broke a kernel invariant
/// ([`NativeForkClass::InvariantViolation`]): never a guest errno. The
/// diagnostic names the refusal's stage and cause; the fatal carries the
/// typed reason `NativeForkInvariant` through the entry-completion sink.
#[track_caller]
pub fn invariant_violated(refusal: NativeForkRefusal) -> ! {
    emit(format_args!("{refusal:?}; class=InvariantViolation"));
    super::dispatch::invalid_completion(super::dispatch::NativeInvariant::NativeService(
        carrick_el1_abi::EntryBindingFatalReason::NativeForkInvariant,
    ))
}

/// Allocate a fork's exact-size scratch, on every ISA's fork venue. The loan
/// was sized from this census, so its one real refusal is a kernel heap
/// miss (#2441). A miss whose metadata grant is in flight is owed capacity:
/// "not now", and the fork reruns. Any other refusal keeps its typed cause,
/// and a heap miss answers ENOMEM. The record names the census and heap.
pub fn fork_scratch(
    request: carrick_el1_abi::PortalForkRequest,
    mapping_count: usize,
    count: &ForkCensus,
) -> Result<ForkScratch, super::native_process_runtime::NativeProcessError> {
    ForkScratch::bounded(
        request,
        mapping_count,
        count.child,
        count.parent,
        count.live,
        count.custody,
    )
    .map_err(|error| {
        let owed = (error == ForkError::NoMemory)
            .then(|| carrick_el1::alloc::GLOBAL_ALLOCATOR.owed_grant())
            .flatten();
        let cause = match owed {
            Some(grant) => NativeForkCause::MetadataOwed { grant },
            None => NativeForkCause::Fork(error),
        };
        let refusal = NativeForkRefusal {
            stage: NativeForkStage::Scratch,
            cause,
        };
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let heap = carrick_el1::alloc::GLOBAL_ALLOCATOR.diagnostics();
            let (child, parent, live, custody) = (count.child, count.parent, count.live, count.custody);
            emit(format_args!(
                "{refusal:?}; census={{child_words: {child}, parent_words: {parent}, live_words: {live}, custody: {custody}, mappings: {mapping_count}}}; heap={heap:?}"
            ));
        }
        super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
    })
}

/// A carrier stock reply that refused the exchange at `stage`, typed by
/// its class on every ISA's fork venue: an `Inventory` reply is not now, a
/// `Capacity` reply exhausts births, a `Stale` or `Invalid` reply, or a
/// completed crossing with no reply (`None`), breaks an invariant.
pub fn stock_refused(
    stage: NativeForkStage,
    reply: Option<carrick_el1_abi::ForkStockRefusal>,
) -> super::native_process_runtime::NativeProcessError {
    refused(
        stage,
        match reply {
            Some(reply) => NativeForkCause::StockReservation(reply),
            None => NativeForkCause::StockCrossing {
                status: 0,
                reply: None,
            },
        },
    )
}

/// Type a fork's bare invariant answer at the fork entry (#2441). Inside a
/// fork, `Stale`, `Invalid` and `Quarantined` name the fork's own records,
/// lifecycle page, loaned stock or settlement contradicting themselves,
/// never a guest error, so they carry [`NativeForkCause::Untyped`] and end
/// the run. Every other answer keeps its own meaning.
pub fn typed_invariant(
    error: super::native_process_runtime::NativeProcessError,
) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    let invariant = match error {
        E::Stale => UntypedInvariant::Stale,
        E::Invalid => UntypedInvariant::Invalid,
        E::Quarantined => UntypedInvariant::Quarantined,
        error => return error,
    };
    refused(NativeForkStage::Entry, NativeForkCause::Untyped(invariant))
}

pub fn refused(
    stage: NativeForkStage,
    cause: impl Into<NativeForkCause>,
) -> super::native_process_runtime::NativeProcessError {
    let refusal = NativeForkRefusal {
        stage,
        cause: cause.into(),
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    emit(format_args!("{refusal:?}"));
    super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
}

/// A sibling's birth holds the reservation; the caller already enrolled on
/// its release and sampled `observed` under the refusing guard. Not a
/// refusal: no diagnostic, and the fork parks instead of failing.
pub fn contended(
    stage: NativeForkStage,
    observed: carrick_sched_core::process::wait::TaskWakeGeneration,
) -> super::native_process_runtime::NativeProcessError {
    super::native_process_runtime::NativeProcessError::ForkRefused(NativeForkRefusal {
        stage,
        cause: NativeForkCause::SiblingBirth { observed },
    })
}

/// The generation a [`contended`] fork enrolled at, if `error` is one.
pub fn sibling_birth(
    error: &Result<u32, super::native_process_runtime::NativeProcessError>,
) -> Option<carrick_sched_core::process::wait::TaskWakeGeneration> {
    match error {
        Err(super::native_process_runtime::NativeProcessError::ForkRefused(
            NativeForkRefusal {
                cause: NativeForkCause::SiblingBirth { observed },
                ..
            },
        )) => Some(*observed),
        _ => None,
    }
}

/// The grant a fork's scratch miss is owed, if `error` is one: the fork
/// waits for that grant, then reruns.
pub fn metadata_owed(
    error: &Result<u32, super::native_process_runtime::NativeProcessError>,
) -> Option<carrick_el1_abi::OwedMetadataGrant> {
    match error {
        Err(super::native_process_runtime::NativeProcessError::ForkRefused(
            NativeForkRefusal {
                cause: NativeForkCause::MetadataOwed { grant },
                ..
            },
        )) => Some(*grant),
        _ => None,
    }
}

/// Contention at an exact refusing site: the caller retains the fork and
/// reruns it, it never reaches the guest as EAGAIN (#2306).
pub fn busy(stage: NativeForkStage) -> super::native_process_runtime::NativeProcessError {
    refused(stage, NativeForkCause::Busy)
}

/// A service may already have emitted a more precise typed refusal.
pub fn at_busy_site(
    stage: NativeForkStage,
    error: super::native_process_runtime::NativeProcessError,
) -> super::native_process_runtime::NativeProcessError {
    if error == super::native_process_runtime::NativeProcessError::Busy {
        busy(stage)
    } else {
        error
    }
}

/// Error-only alias observation alongside the typed Prepare refusal. It never
/// changes the error, grants memory, or runs on a successful preparation.
pub fn refused_prepare(
    error: MmError,
    request: &carrick_el1_abi::PortalForkRequest,
    alias: Option<(
        carrick_guest_arch::UserVa,
        Result<Option<carrick_guest_arch::FrameGpa>, carrick_mmu_core::owner_mmu::OwnerMmuRefusal>,
    )>,
) -> super::native_process_runtime::NativeProcessError {
    let refusal = NativeForkRefusal {
        stage: NativeForkStage::Prepare,
        cause: NativeForkCause::Mm(error),
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    emit(format_args!(
        "{refusal:?}; child=0x{:x}+0x{:x}; alias={alias:?}",
        request.child_tables.base, request.child_tables.len
    ));
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    let _ = (request, alias);
    super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
}

/// Observe the final fork error without changing errno or run-failure policy.
pub fn observe_process_error(
    error: super::native_process_runtime::NativeProcessError,
) -> super::native_process_runtime::NativeProcessError {
    observe_process_error_with(error, emit)
}

fn observe_process_error_with(
    error: super::native_process_runtime::NativeProcessError,
    observe: impl FnOnce(core::fmt::Arguments<'_>),
) -> super::native_process_runtime::NativeProcessError {
    // Typed MM refusals already emitted the more specific owner operation.
    if !matches!(
        error,
        super::native_process_runtime::NativeProcessError::ForkRefused(_)
    ) {
        match error.failure() {
            Ok(failure) => observe(format_args!(
                "ProcessNative::fork error={error:?}; errno={}; run_failure={:?}",
                failure.errno(),
                failure.run_failure_reason()
            )),
            Err(_) => observe(format_args!("ProcessNative::fork error={error:?}; not now")),
        }
    }
    error
}

/// A missing venue retains the lifecycle fallback; it has no final errno yet.
pub fn observe_process_venue<T>(venue: Option<T>) -> Option<T> {
    observe_process_venue_with(venue, emit)
}

fn observe_process_venue_with<T>(
    venue: Option<T>,
    observe: impl FnOnce(core::fmt::Arguments<'_>),
) -> Option<T> {
    if venue.is_none() {
        observe(format_args!(
            "LifecycleNative::process_fork venue=unavailable; outcome=None"
        ));
    }
    venue
}

use super::native_diagnostic::emit;

#[cfg(test)]
mod tests {
    use super::super::native_process_runtime::{NativeContention, NativeProcessError};
    use super::*;

    /// A grant request in flight on a stand-in carrier mailbox.
    fn owed_grant() -> carrick_el1_abi::OwedMetadataGrant {
        let mailbox = carrick_el1_abi::MetadataGrantMailbox::new();
        assert!(
            mailbox.try_publish_request(carrick_el1_abi::MetadataGrantRequest {
                op: carrick_el1_abi::METADATA_GRANT_OP_ALLOC,
                arg1: 512 * 1024,
                arg2: 0,
                arg3: 0,
                cookie: 0,
            })
        );
        mailbox.owed_grant().unwrap()
    }

    /// One of every native fork refusal cause, each nested owner variant
    /// included.
    fn every_cause() -> std::vec::Vec<NativeForkCause> {
        use carrick_el1_abi::ForkStockRefusal as Stock;
        use carrick_mmu_core::aarch64::PageTableError as Table;
        // SAFETY: a synthetic receipt; no owner or queue is entered.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                carrick_core_abi::El1MmHandle::from_admitted_owner(
                    core::num::NonZeroU64::MIN,
                    carrick_el1_abi::ReservationMm::new(7).unwrap(),
                    core::num::NonZeroU64::MIN,
                ),
                carrick_core_abi::PortalWaitCause::Editor,
                1,
            )
        };
        let refusals = [
            Refusal::Busy,
            Refusal::PreparedConflict,
            Refusal::Limit,
            Refusal::MetadataRequired,
            Refusal::Stale,
            Refusal::Invalid,
            Refusal::Collision,
            Refusal::Hole,
            Refusal::ForeignMapping,
        ];
        let owner_refusals = [
            ForkOwnerRefusal::Invalid,
            ForkOwnerRefusal::Collision,
            ForkOwnerRefusal::Hole,
            ForkOwnerRefusal::ForeignMapping,
            ForkOwnerRefusal::Limit,
        ];
        let stock = [
            Stock::Invalid,
            Stock::Stale,
            Stock::Capacity,
            Stock::Inventory,
        ];
        let mut causes = std::vec![
            NativeForkCause::Busy,
            NativeForkCause::GateShut,
            NativeForkCause::SiblingBirth {
                observed: carrick_sched_core::process::wait::TaskWakeGeneration::from_task_counter(
                    1
                ),
            },
            NativeForkCause::MetadataOwed {
                grant: owed_grant()
            },
            NativeForkCause::StockCrossing {
                status: 1,
                reply: None,
            },
        ];
        for error in [
            MmError::Fault,
            MmError::UnsupportedExecutableCow,
            MmError::Stale,
            MmError::Busy,
            MmError::Wait(wait),
            MmError::NoMemory,
            MmError::MetadataRequired,
            MmError::Invalid,
            MmError::Core,
        ]
        .into_iter()
        .chain(
            [
                Table::OutOfTables,
                Table::BadAddress,
                Table::MissingArenaSource,
                Table::ConflictingArenaSource,
                Table::UnresolvedArena(0),
                Table::GicWindowOutput,
                Table::MetadataAllocation,
                Table::GuestOwnsLiveDescriptors,
                Table::CarrickOwnedWindow,
            ]
            .map(MmError::Table),
        )
        .chain(refusals.map(MmError::Reservation))
        {
            causes.push(NativeForkCause::Mm(error));
        }
        causes.extend(refusals.map(NativeForkCause::Reservation));
        for error in [
            ForkError::Invalid,
            ForkError::NoMemory,
            ForkError::Busy,
            ForkError::Stale,
            ForkError::MetadataRequired,
            ForkError::Core,
        ]
        .into_iter()
        .chain(owner_refusals.map(ForkError::OwnerRefusal))
        {
            causes.push(NativeForkCause::Fork(error));
        }
        causes.extend(stock.map(NativeForkCause::StockReservation));
        causes.extend(stock.map(|reply| NativeForkCause::StockCrossing {
            status: 2,
            reply: Some(reply),
        }));
        causes.extend(
            [
                UntypedInvariant::Stale,
                UntypedInvariant::Invalid,
                UntypedInvariant::Quarantined,
            ]
            .map(NativeForkCause::Untyped),
        );
        causes
    }

    /// #2441: no native fork refusal reaches the guest as EFAULT. The fork
    /// transaction walks no guest address, and Linux never answers a plain
    /// fork EFAULT; a refusal is "not now", exhaustion, unsupported, or a
    /// broken invariant that ends the run.
    #[test]
    fn no_fork_refusal_cause_answers_efault() {
        for cause in every_cause() {
            let error = refused(NativeForkStage::Prepare, cause);
            assert_ne!(
                error.failure().map(|failure| failure.errno()),
                Ok(-14),
                "{cause:?} reached the guest as EFAULT"
            );
        }
    }

    /// #2441: each cause has exactly its documented class
    /// ([`NativeForkClass`]); a broken invariant never reaches the guest,
    /// and each other class has its one answer.
    #[test]
    fn every_fork_refusal_cause_has_its_class() {
        use NativeForkClass as Class;
        use carrick_el1_abi::ForkStockRefusal as Stock;
        use carrick_mmu_core::aarch64::PageTableError as Table;
        let expected = |cause: NativeForkCause| match cause {
            NativeForkCause::Busy
            | NativeForkCause::SiblingBirth { .. }
            | NativeForkCause::MetadataOwed { .. }
            | NativeForkCause::Mm(
                MmError::Busy | MmError::Reservation(Refusal::Busy | Refusal::PreparedConflict),
            )
            | NativeForkCause::Reservation(Refusal::Busy | Refusal::PreparedConflict)
            | NativeForkCause::Fork(ForkError::Busy)
            | NativeForkCause::StockReservation(Stock::Inventory)
            | NativeForkCause::StockCrossing {
                reply: Some(Stock::Inventory),
                ..
            } => Class::NotNow(None),
            NativeForkCause::Mm(MmError::Wait(wait)) => Class::NotNow(Some(wait)),
            NativeForkCause::Mm(
                MmError::NoMemory
                | MmError::MetadataRequired
                | MmError::Table(Table::OutOfTables | Table::MetadataAllocation)
                | MmError::Reservation(Refusal::Limit | Refusal::MetadataRequired),
            )
            | NativeForkCause::Reservation(Refusal::Limit | Refusal::MetadataRequired)
            | NativeForkCause::Fork(
                ForkError::NoMemory
                | ForkError::MetadataRequired
                | ForkError::OwnerRefusal(ForkOwnerRefusal::Limit),
            ) => Class::OutOfMemory,
            NativeForkCause::GateShut
            | NativeForkCause::StockReservation(Stock::Capacity)
            | NativeForkCause::StockCrossing {
                reply: Some(Stock::Capacity),
                ..
            } => Class::BirthsExhausted,
            NativeForkCause::Mm(MmError::UnsupportedExecutableCow) => Class::Unsupported,
            _ => Class::InvariantViolation,
        };
        let mut classes = std::collections::BTreeMap::<&str, usize>::new();
        for cause in every_cause() {
            let refusal = NativeForkRefusal {
                stage: NativeForkStage::Prepare,
                cause,
            };
            let class = refusal.class();
            assert_eq!(class, expected(cause), "{cause:?}");
            let answer = refusal.error().failure().map(|failure| failure.errno());
            match class {
                Class::NotNow(_) => assert!(answer.is_err(), "{cause:?}"),
                Class::OutOfMemory => assert_eq!(answer, Ok(-12), "{cause:?}"),
                Class::BirthsExhausted => assert_eq!(answer, Ok(-11), "{cause:?}"),
                Class::Unsupported => assert_eq!(answer, Ok(-38), "{cause:?}"),
                // Off the fork entry only; the entry ends the run first.
                Class::InvariantViolation => assert_eq!(answer, Ok(-5), "{cause:?}"),
            }
            *classes
                .entry(match class {
                    Class::NotNow(_) => "not now",
                    Class::OutOfMemory => "enomem",
                    Class::BirthsExhausted => "eagain",
                    Class::Unsupported => "enosys",
                    Class::InvariantViolation => "invariant",
                })
                .or_default() += 1;
        }
        assert_eq!(
            classes.into_iter().collect::<std::vec::Vec<_>>(),
            [
                ("eagain", 3),
                ("enomem", 11),
                ("enosys", 1),
                ("invariant", 36),
                ("not now", 12),
            ]
        );
    }

    /// #2441, the director's ruling on #2508: a Stale cause is a broken
    /// invariant at every stage, the prepare and publish stages that
    /// re-check the census's parent snapshot included. A snapshot another
    /// live thread of the parent moved is `MmError::Busy` at its source,
    /// never Stale, so no stage reruns a fork on Stale.
    #[test]
    fn every_stale_cause_is_an_invariant_at_every_stage() {
        let observed = carrick_el1_abi::GateState::Open;
        let stages = [
            NativeForkStage::ParentLifecycleGate { observed },
            NativeForkStage::BirthReservation,
            NativeForkStage::ParentSpaceEdit,
            NativeForkStage::ParentForkReady,
            NativeForkStage::ChildLifecycleClaim,
            NativeForkStage::ChildControlReset,
            NativeForkStage::BirthPublication,
            NativeForkStage::PrepareService,
            NativeForkStage::ForkFileTable,
            NativeForkStage::CommitChildService,
            NativeForkStage::MappingCount,
            NativeForkStage::SpaceAccess,
            NativeForkStage::ParentRoot,
            NativeForkStage::ObserveMappings,
            NativeForkStage::TransferSequence,
            NativeForkStage::Census,
            NativeForkStage::PublishRoot,
            NativeForkStage::Scratch,
            NativeForkStage::Prepare,
            NativeForkStage::Publish,
            NativeForkStage::Reserve,
            NativeForkStage::Commit,
            NativeForkStage::Abort,
            NativeForkStage::OpenChildSpace,
            NativeForkStage::StockCrossing,
            NativeForkStage::Entry,
        ];
        for stage in stages {
            let class = |cause| NativeForkRefusal { stage, cause }.class();
            for cause in [
                NativeForkCause::Mm(MmError::Stale),
                NativeForkCause::Mm(MmError::Reservation(Refusal::Stale)),
                NativeForkCause::Reservation(Refusal::Stale),
                NativeForkCause::Fork(ForkError::Stale),
                NativeForkCause::StockReservation(carrick_el1_abi::ForkStockRefusal::Stale),
            ] {
                assert_eq!(
                    class(cause),
                    NativeForkClass::InvariantViolation,
                    "{stage:?} {cause:?}"
                );
            }
            assert_eq!(
                class(NativeForkCause::Mm(MmError::Busy)),
                NativeForkClass::NotNow(None),
                "{stage:?}"
            );
        }
    }

    /// #2441, review P0-2 on #2508: every ISA's fork venue types a carrier
    /// stock reply by its class, and the fork entry types a bare invariant
    /// answer, so no broken invariant reaches the guest as an errno and no
    /// Inventory reply answers EAGAIN.
    #[test]
    fn stock_replies_and_bare_invariants_keep_their_class() {
        use carrick_el1_abi::ForkStockRefusal as Stock;
        let class = |error| match error {
            NativeProcessError::ForkRefused(refusal) => refusal.class(),
            error => panic!("untyped {error:?}"),
        };
        for stage in [NativeForkStage::StockCrossing, NativeForkStage::Reserve] {
            assert_eq!(
                class(stock_refused(stage, Some(Stock::Inventory))),
                NativeForkClass::NotNow(None)
            );
            assert_eq!(
                class(stock_refused(stage, Some(Stock::Capacity))),
                NativeForkClass::BirthsExhausted
            );
            for reply in [Some(Stock::Stale), Some(Stock::Invalid), None] {
                assert_eq!(
                    class(stock_refused(stage, reply)),
                    NativeForkClass::InvariantViolation,
                    "{stage:?} {reply:?}"
                );
            }
        }
        for bare in [
            NativeProcessError::Stale,
            NativeProcessError::Invalid,
            NativeProcessError::Quarantined,
        ] {
            assert_eq!(
                class(typed_invariant(bare)),
                NativeForkClass::InvariantViolation,
                "{bare:?}"
            );
        }
        for kept in [
            NativeProcessError::Busy,
            NativeProcessError::Exhausted,
            NativeProcessError::NoMemory,
            NativeProcessError::Fault,
            NativeProcessError::Unsupported,
        ] {
            assert_eq!(typed_invariant(kept), kept);
        }
    }

    #[test]
    fn boundary_observes_every_untyped_error_without_changing_policy() {
        use NativeProcessError as E;
        use carrick_core_abi::NativeRunFailureReason as R;
        for (error, errno, reason) in [
            (E::Invalid, -22, R::NativeInvalid),
            (E::Stale, -22, R::NativeStale),
            (E::Exhausted, -11, R::NativeExhausted),
            (E::NoMemory, -12, R::NativeNoMemory),
            (E::Fault, -14, R::NativeFault),
            (E::Unsupported, -38, R::NativeUnsupported),
            (E::GroupExitCustody, -38, R::X86GroupExitCustody),
            (E::Quarantined, -5, R::NativeQuarantined),
            (E::NoChild, -10, R::NativeNoChild),
        ] {
            let mut diagnostic = carrick_el1_abi::NativeDiagnostic::new();
            let observed = observe_process_error_with(error, |arguments| {
                core::fmt::write(&mut diagnostic, arguments).unwrap();
            });
            assert_eq!(observed, error);
            let failure = observed.failure().unwrap();
            assert_eq!(failure.errno(), errno);
            assert_eq!(failure.run_failure_reason(), reason);
            assert_eq!(observe_process_error(error), error);
            let expected = std::format!(
                "ProcessNative::fork error={error:?}; errno={errno}; run_failure={reason:?}"
            );
            assert_eq!(diagnostic.message(), Some(expected.as_str()));
        }
        let mut diagnostic = carrick_el1_abi::NativeDiagnostic::new();
        let observed = observe_process_error_with(E::Busy, |arguments| {
            core::fmt::write(&mut diagnostic, arguments).unwrap();
        });
        assert_eq!(observed.failure(), Err(NativeContention::BUSY));
        assert_eq!(
            diagnostic.message(),
            Some("ProcessNative::fork error=Busy; not now")
        );
    }

    #[test]
    fn boundary_does_not_duplicate_typed_refusals() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for cause in [
            NativeForkCause::Fork(ForkError::Core),
            NativeForkCause::StockReservation(R::Invalid),
            NativeForkCause::StockReservation(R::Stale),
            NativeForkCause::StockReservation(R::Capacity),
            NativeForkCause::StockReservation(R::Inventory),
        ] {
            let error = refused(NativeForkStage::Reserve, cause);
            let observed = observe_process_error_with(error, |_| panic!("duplicate refusal"));
            assert_eq!(observed, error);
            assert_eq!(observed.failure(), error.failure());
        }
    }

    #[test]
    fn missing_venue_observation_preserves_fallback_and_success_is_silent() {
        let mut diagnostic = carrick_el1_abi::NativeDiagnostic::new();
        assert_eq!(
            observe_process_venue_with(None::<u32>, |arguments| {
                core::fmt::write(&mut diagnostic, arguments).unwrap();
            }),
            None
        );
        assert_eq!(
            diagnostic.message(),
            Some("LifecycleNative::process_fork venue=unavailable; outcome=None")
        );
        let venue = 42;
        assert_eq!(
            observe_process_venue_with(Some(&venue), |_| panic!("successful venue")),
            Some(&venue)
        );
        assert_eq!(observe_process_venue(None::<u32>), None);
    }

    #[test]
    fn refusal_keeps_stage_and_owner_reason_until_errno_encoding() {
        let error = refused(NativeForkStage::Census, ForkError::Core);
        assert_eq!(
            error,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Census,
                cause: NativeForkCause::Fork(ForkError::Core),
            })
        );
        let NativeProcessError::ForkRefused(refusal) = error else {
            unreachable!()
        };
        assert_eq!(refusal.class(), NativeForkClass::InvariantViolation);
        assert_ne!(error, refused(NativeForkStage::Prepare, ForkError::Core));
        assert_ne!(error, refused(NativeForkStage::Census, ForkError::Stale));
    }

    /// #2441: memory and limit exhaustion at any stage is ENOMEM, as Linux
    /// answers fork and clone, never EFAULT; a heap miss whose metadata grant
    /// is in flight is "not now".
    #[test]
    fn exhausted_fork_is_enomem_and_an_owed_grant_is_contention() {
        use carrick_mmu_core::aarch64::PageTableError;
        for (stage, cause) in [
            (
                NativeForkStage::Scratch,
                NativeForkCause::Fork(ForkError::NoMemory),
            ),
            (
                NativeForkStage::Prepare,
                NativeForkCause::Fork(ForkError::MetadataRequired),
            ),
            (
                NativeForkStage::Publish,
                NativeForkCause::Fork(ForkError::OwnerRefusal(ForkOwnerRefusal::Limit)),
            ),
            (
                NativeForkStage::Prepare,
                NativeForkCause::Mm(MmError::NoMemory),
            ),
            (
                NativeForkStage::Prepare,
                NativeForkCause::Mm(MmError::Table(PageTableError::OutOfTables)),
            ),
            (
                NativeForkStage::Commit,
                NativeForkCause::Mm(MmError::Reservation(Refusal::Limit)),
            ),
            (
                NativeForkStage::Commit,
                NativeForkCause::Reservation(Refusal::Limit),
            ),
            // A fork owner's Limit keeps its type through the MM owner's
            // error (formerly folded into MmError::Fault, so EFAULT).
            (
                NativeForkStage::Publish,
                NativeForkCause::Mm(MmError::from(ForkError::OwnerRefusal(
                    ForkOwnerRefusal::Limit,
                ))),
            ),
        ] {
            let error = refused(stage, cause);
            assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-12));
        }
        assert_eq!(
            refused(
                NativeForkStage::Scratch,
                NativeForkCause::MetadataOwed {
                    grant: owed_grant()
                }
            )
            .failure(),
            Err(NativeContention::BUSY)
        );
        use carrick_el1_abi::ForkStockRefusal as R;
        let error = refused(
            NativeForkStage::StockCrossing,
            NativeForkCause::StockCrossing {
                status: 1,
                reply: Some(R::Capacity),
            },
        );
        assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-11));
        assert_eq!(
            refused(
                NativeForkStage::StockCrossing,
                NativeForkCause::StockCrossing {
                    status: 1,
                    reply: Some(R::Inventory),
                },
            )
            .failure(),
            Err(NativeContention::BUSY)
        );
    }

    /// The census-sized scratch refuses only a heap miss. Without a grant
    /// mailbox (host builds, the x86 CPL0 image) nothing is owed: ENOMEM.
    /// With a grant in flight, the miss is owed that grant.
    #[test]
    fn scratch_heap_miss_is_enomem_unless_a_grant_is_in_flight() {
        let request = carrick_el1_abi::PortalForkRequest {
            operation: carrick_el1_abi::PortalOperation {
                carrier: core::num::NonZeroU64::MIN,
                mm: carrick_el1_abi::ReservationMm::new(1).unwrap(),
                incarnation: core::num::NonZeroU64::MIN,
                sequence: core::num::NonZeroU64::MIN,
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::new(1).unwrap(),
            child_mm: carrick_el1_abi::ReservationMm::new(2).unwrap(),
            child_tables: carrick_el1_abi::PortalForkTableArena::new(0x20000, 0x1000).unwrap(),
            parent_tables: carrick_el1_abi::PortalForkTableArena::new(0x30000, 0x1000).unwrap(),
            kernel_control_ipa: 0x40000,
        };
        let count = ForkCensus {
            child: 512,
            parent: 0,
            live: 512,
            custody: 0,
        };
        assert!(fork_scratch(request, 0, &count).is_ok());
        assert!(carrick_core::mm::fork::inject_scratch_exhausted_once());
        let error = fork_scratch(request, 0, &count).unwrap_err();
        assert_eq!(
            error,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Scratch,
                cause: NativeForkCause::Fork(ForkError::NoMemory),
            })
        );
        assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-12));

        // With a grant request in flight on the carrier mailbox, the same
        // miss is owed that exact grant: the fork waits for it.
        let mailbox: &'static carrick_el1_abi::MetadataGrantMailbox = std::boxed::Box::leak(
            std::boxed::Box::new(carrick_el1_abi::MetadataGrantMailbox::new()),
        );
        assert!(
            mailbox.try_publish_request(carrick_el1_abi::MetadataGrantRequest {
                op: carrick_el1_abi::METADATA_GRANT_OP_ALLOC,
                arg1: 512 * 1024,
                arg2: 0,
                arg3: 0,
                cookie: 0,
            })
        );
        carrick_el1::alloc::install_host_test_grant_mailbox(Some(mailbox));
        assert!(carrick_core::mm::fork::inject_scratch_exhausted_once());
        let owed = fork_scratch(request, 0, &count).unwrap_err();
        carrick_el1::alloc::install_host_test_grant_mailbox(None);
        let grant = mailbox.owed_grant().unwrap();
        assert_eq!(
            owed,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Scratch,
                cause: NativeForkCause::MetadataOwed { grant },
            })
        );
        assert_eq!(super::metadata_owed(&Err(owed)), Some(grant));
    }

    /// A held reservation root at the mapping census or the child commit
    /// is contention on every ISA venue, never the fault answer (#2306).
    #[test]
    fn held_root_at_census_or_commit_is_contention() {
        for stage in [NativeForkStage::MappingCount, NativeForkStage::Commit] {
            for cause in [
                NativeForkCause::Mm(MmError::Busy),
                NativeForkCause::Reservation(Refusal::Busy),
            ] {
                assert_eq!(refused(stage, cause).failure(), Err(NativeContention::BUSY));
            }
            let NativeProcessError::ForkRefused(refusal) = refused(stage, MmError::Fault) else {
                unreachable!()
            };
            assert_eq!(refusal.class(), NativeForkClass::InvariantViolation);
        }
    }

    #[test]
    fn parent_gate_refusal_preserves_observed_state_as_contention() {
        use carrick_el1_abi::GateState;
        for observed in [
            GateState::Open,
            GateState::ForkClosing,
            GateState::Closed,
            GateState::AwaitingExecBinding,
            GateState::HostOnly,
        ] {
            let stage = NativeForkStage::ParentLifecycleGate { observed };
            let error = busy(stage);
            assert_eq!(
                error,
                NativeProcessError::ForkRefused(NativeForkRefusal {
                    stage,
                    cause: NativeForkCause::Busy,
                })
            );
            // A closing or forking gate is "not now", never EAGAIN.
            assert_eq!(error.failure(), Err(NativeContention::BUSY));
            let NativeProcessError::ForkRefused(refusal) = error else {
                unreachable!()
            };
            let mut diagnostic = carrick_el1_abi::NativeDiagnostic::new();
            core::fmt::write(&mut diagnostic, format_args!("{refusal:?}")).unwrap();
            let expected = std::format!(
                "NativeForkRefusal {{ stage: ParentLifecycleGate {{ observed: {observed:?} }}, cause: Busy }}"
            );
            assert_eq!(diagnostic.message(), Some(expected.as_str()));
        }
        // No release reopens a shut gate: a refusal, not contention.
        for observed in [GateState::Closed, GateState::HostOnly] {
            let shut = refused(
                NativeForkStage::ParentLifecycleGate { observed },
                NativeForkCause::GateShut,
            );
            assert_eq!(shut.failure().map(|failure| failure.errno()), Ok(-11));
        }
    }

    /// A stock reply keeps its owner's class at the reservation and at the
    /// crossing: an Invalid or Stale reply means the carrier refused the
    /// parent's own exact request, a broken invariant (#2441).
    #[test]
    fn reserve_diagnostics_preserve_each_stock_refusal_class() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for (reply, class) in [
            (R::Invalid, NativeForkClass::InvariantViolation),
            (R::Stale, NativeForkClass::InvariantViolation),
            (R::Capacity, NativeForkClass::BirthsExhausted),
            (R::Inventory, NativeForkClass::NotNow(None)),
        ] {
            for cause in [
                NativeForkCause::StockReservation(reply),
                NativeForkCause::StockCrossing {
                    status: 2,
                    reply: Some(reply),
                },
            ] {
                let refusal = NativeForkRefusal {
                    stage: NativeForkStage::Reserve,
                    cause,
                };
                assert_eq!(refusal.class(), class, "{cause:?}");
            }
        }
    }
}

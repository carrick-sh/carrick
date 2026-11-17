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
    /// The kernel heap missed the fork's scratch while a metadata grant is
    /// in flight on the carrier mailbox: capacity is owed, so this is "not
    /// now". The fork keeps its syscall and reruns once the carrier serves
    /// the grant (#2441). A miss nothing is owed for is `Fork(NoMemory)`.
    MetadataOwed,
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

impl NativeForkRefusal {
    /// Every cause has exactly one answer, so a new cause cannot reach the
    /// guest as a fallback errno (#2441). Contention is "not now"; memory
    /// and limit exhaustion is ENOMEM, as Linux answers fork and clone.
    pub fn error(self) -> super::native_process_runtime::NativeProcessError {
        use super::native_process_runtime::NativeProcessError as E;
        match self.cause {
            NativeForkCause::Busy
            | NativeForkCause::SiblingBirth { .. }
            | NativeForkCause::MetadataOwed => E::Busy,
            // Today's EAGAIN answer, as a refusal rather than "not now".
            NativeForkCause::GateShut => E::Exhausted,
            NativeForkCause::Mm(error) => mm_error(error),
            NativeForkCause::Reservation(refusal) => reservation_error(refusal),
            NativeForkCause::Fork(error) => fork_error(error),
            NativeForkCause::StockReservation(refusal) => stock_error(refusal),
            // A refused stock reply keeps the owner's answer; a crossing that
            // carried none is the transport's fault answer.
            NativeForkCause::StockCrossing {
                reply: Some(refusal),
                ..
            } => stock_error(refusal),
            NativeForkCause::StockCrossing { reply: None, .. } => E::Fault,
        }
    }
}

fn mm_error(error: MmError) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    match error {
        // Owner contention keeps its release to enrol on (#2306); it is
        // never the fault answer of a refused owner operation.
        MmError::Wait(wait) => E::OwnerWait(wait),
        MmError::Busy => E::Busy,
        MmError::NoMemory
        | MmError::MetadataRequired
        | MmError::Table(carrick_mmu_core::aarch64::PageTableError::OutOfTables) => E::NoMemory,
        MmError::Reservation(refusal) => reservation_error(refusal),
        MmError::Fault
        | MmError::UnsupportedExecutableCow
        | MmError::Stale
        | MmError::Invalid
        | MmError::Core
        | MmError::Table(_) => E::Fault,
    }
}

fn reservation_error(refusal: Refusal) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    match refusal {
        Refusal::Busy | Refusal::PreparedConflict => E::Busy,
        Refusal::Limit | Refusal::MetadataRequired => E::NoMemory,
        Refusal::Stale
        | Refusal::Invalid
        | Refusal::Collision
        | Refusal::Hole
        | Refusal::ForeignMapping => E::Fault,
    }
}

fn fork_error(error: ForkError) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    match error {
        ForkError::Busy => E::Busy,
        ForkError::NoMemory
        | ForkError::MetadataRequired
        | ForkError::OwnerRefusal(ForkOwnerRefusal::Limit) => E::NoMemory,
        ForkError::Invalid
        | ForkError::Stale
        | ForkError::Core
        | ForkError::OwnerRefusal(
            ForkOwnerRefusal::Invalid
            | ForkOwnerRefusal::Collision
            | ForkOwnerRefusal::Hole
            | ForkOwnerRefusal::ForeignMapping,
        ) => E::Fault,
    }
}

fn stock_error(
    refusal: carrick_el1_abi::ForkStockRefusal,
) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    use carrick_el1_abi::ForkStockRefusal as R;
    match refusal {
        R::Invalid => E::Invalid,
        R::Stale => E::Stale,
        R::Capacity => E::Exhausted,
        R::Inventory => E::Busy,
    }
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
        let cause = if error == ForkError::NoMemory
            && carrick_el1::alloc::GLOBAL_ALLOCATOR.capacity_owed()
        {
            NativeForkCause::MetadataOwed
        } else {
            NativeForkCause::Fork(error)
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
        assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-14));
        assert_ne!(error, refused(NativeForkStage::Prepare, ForkError::Core));
        assert_ne!(error, refused(NativeForkStage::Census, ForkError::Stale));
    }

    /// #2441: memory and limit exhaustion at any stage is ENOMEM, as Linux
    /// answers fork and clone, never EFAULT; a heap miss whose metadata grant
    /// is in flight is "not now". Every cause has one exhaustive answer.
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
        ] {
            let error = refused(stage, cause);
            assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-12));
        }
        assert_eq!(
            refused(NativeForkStage::Scratch, NativeForkCause::MetadataOwed).failure(),
            Err(NativeContention::BUSY)
        );
        use carrick_el1_abi::ForkStockRefusal as R;
        for (reply, errno) in [(Some(R::Capacity), Ok(-11)), (None, Ok(-14))] {
            let error = refused(
                NativeForkStage::StockCrossing,
                NativeForkCause::StockCrossing { status: 1, reply },
            );
            assert_eq!(error.failure().map(|failure| failure.errno()), errno);
        }
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
    #[test]
    fn scratch_heap_miss_without_a_grant_mailbox_is_enomem() {
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
            assert_eq!(
                refused(stage, MmError::Fault)
                    .failure()
                    .map(|failure| failure.errno()),
                Ok(-14)
            );
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

    #[test]
    fn reserve_diagnostics_preserve_each_stock_refusal_encoding() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for (reply, error) in [
            (R::Invalid, NativeProcessError::Invalid),
            (R::Stale, NativeProcessError::Stale),
            (R::Capacity, NativeProcessError::Exhausted),
            (R::Inventory, NativeProcessError::Busy),
        ] {
            let diagnostic = refused(
                NativeForkStage::Reserve,
                NativeForkCause::StockReservation(reply),
            );
            assert_eq!(diagnostic.failure(), error.failure());
        }
    }
}

//! Preserve the native fork operation and its owner refusal until errno encoding.

use carrick_core::mm::{fork::ForkError, reservation::Refusal, transaction::MmError};

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
    /// The child's reservation tree needed nodes the shared pool lacked,
    /// and no node bank could be added (#3085): the `BANKS` table is full or
    /// the metadata allocator is out of memory (Linux's ENOMEM for a fork
    /// that cannot allocate its kernel structures), or the allocator's
    /// receipt was broken. A grant in flight or a held bank window is never
    /// stored here: it is "not now" ([`NodeBankDemand::supply`]).
    NodeBank(carrick_core::mm::reservation::NodeBankShortfall),
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
    /// The one encoding of a fork refusal, exhaustive over every cause
    /// (#3085). A cause is contention ("not now": `Busy`, `OwnerWait`), a
    /// Linux `fork(2)` errno (`Exhausted` is EAGAIN: a resource limit;
    /// `NoMemory` is ENOMEM: kernel memory), or a broken invariant (`Stale`,
    /// `Invalid`, `Quarantined`, `Unsupported`). No cause answers EFAULT:
    /// Linux has none for `fork`.
    pub fn error(self) -> super::native_process_runtime::NativeProcessError {
        use super::native_process_runtime::NativeProcessError as E;
        use carrick_core::mm::reservation::{MetadataMiss, NodeBankShortfall as S};
        match self.cause {
            NativeForkCause::Busy | NativeForkCause::SiblingBirth { .. } => E::Busy,
            // Today's EAGAIN answer, as a refusal rather than "not now".
            NativeForkCause::GateShut => E::Exhausted,
            NativeForkCause::NodeBank(S::Full | S::Metadata(MetadataMiss::Exhausted)) => {
                E::NoMemory
            }
            NativeForkCause::NodeBank(S::Metadata(MetadataMiss::GrantPending) | S::Publishing) => {
                E::Busy
            }
            NativeForkCause::NodeBank(S::Invalid) => E::Invalid,
            NativeForkCause::Mm(error) => mm_error(error),
            NativeForkCause::Reservation(refusal) => reservation_error(refusal),
            NativeForkCause::Fork(error) => fork_error(error),
            NativeForkCause::StockReservation(refusal) => stock_error(refusal),
            // A typed reply the crossing carried back is that refusal.
            NativeForkCause::StockCrossing {
                reply: Some(refusal),
                ..
            } => stock_error(refusal),
            // The transport failed before a typed reply: the loan's carrier
            // custody is unconfirmed.
            NativeForkCause::StockCrossing { reply: None, .. } => E::Stale,
        }
    }
}

fn mm_error(error: MmError) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    use carrick_mmu_core::aarch64::PageTableError;
    match error {
        // Owner contention keeps its release to enrol on (#2306); it is
        // never the fault answer of a refused owner operation.
        MmError::Wait(wait) => E::OwnerWait(wait),
        MmError::Busy => E::Busy,
        // The parent changed while its editor was released for the stock
        // crossing (#2890): the fork backs out and reruns from a fresh
        // snapshot, never EFAULT.
        MmError::ParentChanged => E::Busy,
        // The parent's guest COW completions wait for their carrier's
        // settlement. Retained as carrier work, whose acknowledgement
        // settles the requester's MM first (ARM); the x86 venue rings the
        // settlement itself and returns its editor wait instead when it met
        // that editor held (#2947).
        MmError::CowUnsettled => E::Busy,
        // A `MetadataRequired` at Publish is supplied a node bank and
        // reruns ([`NodeBankDemand`]); one that reaches this encoding is
        // kernel memory the fork could not add: ENOMEM, as `fork(2)`.
        MmError::NoMemory | MmError::MetadataRequired => E::NoMemory,
        MmError::Table(PageTableError::OutOfTables) => E::NoMemory,
        MmError::Reservation(refusal) => reservation_error(refusal),
        // A replaced parent (another incarnation) is stale custody.
        MmError::Stale => E::Stale,
        // The owner's own records disagree (a hole or a foreign table in
        // the parent the census accepted): a broken invariant.
        MmError::Invalid | MmError::Fault | MmError::Table(_) => E::Invalid,
        MmError::UnsupportedExecutableCow => E::Unsupported,
        // A rollback that could not restore the parent.
        MmError::Core => E::Quarantined,
    }
}

fn reservation_error(refusal: Refusal) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    match refusal {
        Refusal::Busy | Refusal::PreparedConflict => E::Busy,
        Refusal::Stale => E::Stale,
        Refusal::MetadataRequired => E::NoMemory,
        Refusal::Limit => E::Exhausted,
        Refusal::Invalid | Refusal::Collision | Refusal::Hole | Refusal::ForeignMapping => {
            E::Invalid
        }
    }
}

fn fork_error(error: ForkError) -> super::native_process_runtime::NativeProcessError {
    use super::native_process_runtime::NativeProcessError as E;
    use carrick_core::mm::fork::ForkOwnerRefusal as O;
    match error {
        ForkError::Busy | ForkError::ParentChanged => E::Busy,
        ForkError::NoMemory | ForkError::MetadataRequired => E::NoMemory,
        ForkError::OwnerRefusal(O::Limit) => E::Exhausted,
        ForkError::Stale => E::Stale,
        ForkError::Invalid
        | ForkError::OwnerRefusal(O::Invalid | O::Collision | O::Hole | O::ForeignMapping) => {
            E::Invalid
        }
        ForkError::Core => E::Quarantined,
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
        // An admission limit is EAGAIN; kernel memory the carrier could
        // not allocate is ENOMEM (`fork(2)`).
        R::Capacity(_) => E::Exhausted,
        R::NoMemory => E::NoMemory,
        R::Inventory => E::Busy,
        // The fork owner grows the table and answers `Busy` itself. This
        // cause survives only when that growth was refused for good: the
        // directory is full or the allocator is out of memory.
        R::Residency => E::NoMemory,
    }
}

/// The publish step's refusal, before its loan is returned: either an
/// ordinary refusal, or a demand for one more reservation node bank.
#[must_use = "a node bank demand must be supplied after the fork's loan is returned"]
pub enum PublishRefusal {
    Refused(super::native_process_runtime::NativeProcessError),
    NodeBank(NodeBankDemand),
}

/// The child's reservation tree needed more nodes than the shared pool
/// held at `observed` (#3085). Not an errno: the venue returns its fork
/// loan and releases every MM guard, then [`Self::supply`] adds one bank
/// through the existing bank supply and the fork reruns against it. Each
/// rerun follows either a pool that grew past `observed`, or a wake of the
/// parent space's Metadata cause (a grant served, or another supplier's
/// bank window closed), so reruns are bounded by the `BANKS` table and the
/// grants the carrier gives.
#[must_use = "a node bank demand must be supplied after the fork's loan is returned"]
#[derive(Debug)]
pub struct NodeBankDemand {
    observed: carrick_core::mm::reservation::NodeCapacity,
}

impl NodeBankDemand {
    /// Supply the bank, holding no MM editor, root guard or fork loan.
    /// `metadata` is the parent space's Metadata cause, observed before this
    /// call. The answer is never an errno for contention (#2306):
    /// - the pool grew past `observed` (this call's bank or a peer's):
    ///   `Busy`, and the retained fork reruns at once;
    /// - a metadata grant is in flight for this boundary, or another
    ///   supplier holds the bank window: `OwnerWait` on `metadata`, which
    ///   the grant's publication or that window's close wakes, so the fork
    ///   parks until then, probes once and reruns.
    ///
    /// `waiters` are woken when this call's own window closes. Only memory
    /// no bank can come from answers ENOMEM.
    pub fn supply<
        Policy: carrick_el1_abi::ReservationPolicy,
        Geometry: carrick_el1_abi::ReservationGeometry,
    >(
        self,
        roots: &carrick_core::mm::reservation::SharedReservations<Policy, Geometry>,
        allocator: &impl carrick_core::mm::reservation::ReservationMetadataAllocator,
        metadata: Option<carrick_core_abi::PortalOwnerWait>,
        waiters: &impl carrick_core::mm::reservation::MetadataWaiters,
    ) -> super::native_process_runtime::NativeProcessError {
        use super::native_process_runtime::NativeProcessError as E;
        use carrick_core::mm::reservation::{MetadataMiss, NodeBankShortfall};
        match roots.supply_node_bank(allocator, self.observed, waiters) {
            Ok(()) => E::Busy,
            Err(
                NodeBankShortfall::Metadata(MetadataMiss::GrantPending)
                | NodeBankShortfall::Publishing,
            ) => metadata.map_or(E::Busy, E::OwnerWait),
            Err(shortfall) => refused(
                NativeForkStage::Publish,
                NativeForkCause::NodeBank(shortfall),
            ),
        }
    }
}

/// Classify a refused publish against the node capacity the venue sampled
/// before it ([`carrick_core::mm::reservation::SharedReservations::node_capacity`]).
pub fn refused_publish(
    error: MmError,
    observed: carrick_core::mm::reservation::NodeCapacity,
) -> PublishRefusal {
    match error {
        MmError::MetadataRequired => PublishRefusal::NodeBank(NodeBankDemand { observed }),
        error => PublishRefusal::Refused(refused(NativeForkStage::Publish, error)),
    }
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

    /// #2890: a parent that changed since the fork's snapshot (a sibling's
    /// edit while the editor was released for the stock crossing) is
    /// contention at Prepare and at Publish, on both ISAs, never EFAULT.
    #[test]
    fn a_changed_parent_reruns_the_fork_instead_of_answering_efault() {
        for (stage, cause) in [
            (
                NativeForkStage::Prepare,
                NativeForkCause::Mm(MmError::ParentChanged),
            ),
            (
                NativeForkStage::Publish,
                NativeForkCause::Mm(MmError::ParentChanged),
            ),
            (
                NativeForkStage::Publish,
                NativeForkCause::Fork(ForkError::ParentChanged),
            ),
            // #2947: an unsettled parent COW completion is retained as
            // carrier work, whose answer settles it.
            (
                NativeForkStage::Prepare,
                NativeForkCause::Mm(MmError::CowUnsettled),
            ),
        ] {
            let error = NativeForkRefusal { stage, cause }.error();
            assert_eq!(error, NativeProcessError::Busy, "{stage:?} {cause:?}");
            assert_eq!(error.failure(), Err(NativeContention::BUSY));
        }
        // A replaced parent (another incarnation) is still stale custody.
        assert_eq!(
            NativeForkRefusal {
                stage: NativeForkStage::Prepare,
                cause: NativeForkCause::Mm(MmError::Stale),
            }
            .error(),
            NativeProcessError::Stale
        );
    }

    /// #3085: the encoding is exhaustive and no cause answers EFAULT, which
    /// Linux never returns from `fork`. Capacity is EAGAIN; contention has
    /// no errno; a broken invariant stays a typed native failure.
    #[test]
    fn no_fork_refusal_answers_efault() {
        use carrick_core::mm::fork::ForkOwnerRefusal as O;
        use carrick_core::mm::reservation::{MetadataMiss, NodeBankShortfall as S};
        use carrick_el1_abi::ForkStockRefusal as R;
        use carrick_mmu_core::aarch64::PageTableError;
        let mut causes = std::vec![
            NativeForkCause::Busy,
            NativeForkCause::GateShut,
            NativeForkCause::NodeBank(S::Full),
            NativeForkCause::NodeBank(S::Metadata(MetadataMiss::Exhausted)),
            NativeForkCause::NodeBank(S::Metadata(MetadataMiss::GrantPending)),
            NativeForkCause::NodeBank(S::Invalid),
            NativeForkCause::StockCrossing {
                status: 1,
                reply: None
            },
        ];
        for mm in [
            MmError::Fault,
            MmError::UnsupportedExecutableCow,
            MmError::Stale,
            MmError::Busy,
            MmError::ParentChanged,
            MmError::CowUnsettled,
            MmError::NoMemory,
            MmError::MetadataRequired,
            MmError::Invalid,
            MmError::Core,
            MmError::Table(PageTableError::OutOfTables),
            MmError::Table(PageTableError::BadAddress),
        ] {
            causes.push(NativeForkCause::Mm(mm));
        }
        for refusal in [
            Refusal::Busy,
            Refusal::PreparedConflict,
            Refusal::Stale,
            Refusal::Invalid,
            Refusal::Collision,
            Refusal::Hole,
            Refusal::ForeignMapping,
            Refusal::Limit,
            Refusal::MetadataRequired,
        ] {
            causes.push(NativeForkCause::Reservation(refusal));
            causes.push(NativeForkCause::Mm(MmError::Reservation(refusal)));
        }
        for fork in [
            ForkError::Invalid,
            ForkError::NoMemory,
            ForkError::Busy,
            ForkError::Stale,
            ForkError::ParentChanged,
            ForkError::MetadataRequired,
            ForkError::Core,
            ForkError::OwnerRefusal(O::Invalid),
            ForkError::OwnerRefusal(O::Collision),
            ForkError::OwnerRefusal(O::Hole),
            ForkError::OwnerRefusal(O::ForeignMapping),
            ForkError::OwnerRefusal(O::Limit),
        ] {
            causes.push(NativeForkCause::Fork(fork));
        }
        for reply in [
            R::Invalid,
            R::Stale,
            R::Capacity(carrick_el1_abi::ForkCapacityResource::Tables),
            R::Inventory,
            R::Residency,
        ] {
            causes.push(NativeForkCause::StockReservation(reply));
            causes.push(NativeForkCause::StockCrossing {
                status: 2,
                reply: Some(reply),
            });
            // A crossing's typed reply is that stock refusal.
            assert_eq!(
                NativeForkRefusal {
                    stage: NativeForkStage::StockCrossing,
                    cause: NativeForkCause::StockCrossing {
                        status: 2,
                        reply: Some(reply)
                    },
                }
                .error(),
                NativeForkRefusal {
                    stage: NativeForkStage::Reserve,
                    cause: NativeForkCause::StockReservation(reply),
                }
                .error()
            );
        }
        for cause in causes {
            let error = NativeForkRefusal {
                stage: NativeForkStage::Publish,
                cause,
            }
            .error();
            assert_ne!(error, NativeProcessError::Fault, "{cause:?}");
            if let Ok(failure) = error.failure() {
                assert_ne!(failure.errno(), -14, "{cause:?}");
            }
        }
        // A resource limit is EAGAIN; kernel memory the fork could not
        // allocate is ENOMEM, as `fork(2)` documents.
        for (cause, errno) in [
            (NativeForkCause::GateShut, -11),
            (
                NativeForkCause::Fork(ForkError::OwnerRefusal(O::Limit)),
                -11,
            ),
            (NativeForkCause::NodeBank(S::Full), -12),
            (
                NativeForkCause::NodeBank(S::Metadata(MetadataMiss::Exhausted)),
                -12,
            ),
            (NativeForkCause::Mm(MmError::MetadataRequired), -12),
            (NativeForkCause::Mm(MmError::NoMemory), -12),
            (
                NativeForkCause::Mm(MmError::Table(PageTableError::OutOfTables)),
                -12,
            ),
            (NativeForkCause::Fork(ForkError::NoMemory), -12),
            (NativeForkCause::StockReservation(R::Residency), -12),
        ] {
            assert_eq!(
                refused(NativeForkStage::Publish, cause)
                    .failure()
                    .map(|failure| failure.errno()),
                Ok(errno),
                "{cause:?}"
            );
        }
        // A grant in flight is "not now", never an errno.
        assert_eq!(
            refused(
                NativeForkStage::Publish,
                NativeForkCause::NodeBank(S::Metadata(MetadataMiss::GrantPending))
            )
            .failure(),
            Err(NativeContention::BUSY)
        );
    }

    /// An allocator whose every miss is a grant in flight for this boundary.
    struct GrantInFlight;
    // SAFETY: it never allocates.
    unsafe impl carrick_core::mm::reservation::ReservationMetadataAllocator for GrantInFlight {
        fn allocate_with_extent(
            &self,
            _: core::alloc::Layout,
        ) -> Result<
            (*mut u8, carrick_core_abi::ExtentGrantReceipt),
            carrick_core::mm::reservation::MetadataMiss,
        > {
            Err(carrick_core::mm::reservation::MetadataMiss::GrantPending)
        }
        fn deallocate(&self, _: *mut u8, _: core::alloc::Layout) {
            unreachable!("nothing was allocated")
        }
    }

    /// #3085: a publish refused `MetadataRequired` is a node bank demand,
    /// never an errno; every other publish refusal keeps its stage and cause.
    #[test]
    fn a_publish_short_of_nodes_demands_a_bank() {
        use carrick_core::mm::reservation::{MetadataMiss, NodeBankShortfall};
        use carrick_el1::memory::reservations::SharedReservations;
        // SAFETY: an all-zero table is the empty, unpublished table.
        let table: std::boxed::Box<SharedReservations> = unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>());
            assert!(!ptr.is_null());
            std::boxed::Box::from_raw(ptr.cast())
        };
        let observed = table.node_capacity();
        assert!(matches!(
            refused_publish(MmError::MetadataRequired, observed),
            PublishRefusal::NodeBank(_)
        ));
        let PublishRefusal::Refused(error) = refused_publish(MmError::ParentChanged, observed)
        else {
            panic!("a changed parent is no node demand")
        };
        assert_eq!(
            error,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Publish,
                cause: NativeForkCause::Mm(MmError::ParentChanged),
            })
        );
        let waiters = carrick_core_abi::NO_METADATA_WAITERS;
        // SAFETY: a fixture observation; nothing parks on it here.
        let metadata = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                carrick_core_abi::El1MmHandle::from_admitted_owner(
                    core::num::NonZeroU64::MIN,
                    carrick_el1_abi::ReservationMm::new(7).unwrap(),
                    core::num::NonZeroU64::MIN,
                ),
                carrick_core_abi::PortalWaitCause::Metadata,
                3,
            )
        };
        // A grant in flight for this boundary: "not now", the fork parks on
        // the Metadata cause it observed, which the grant's publication
        // wakes, and reruns.
        let PublishRefusal::NodeBank(demand) = refused_publish(MmError::MetadataRequired, observed)
        else {
            unreachable!()
        };
        let error = demand.supply(&table, &GrantInFlight, Some(metadata), &waiters);
        assert_eq!(error, NativeProcessError::OwnerWait(metadata));
        assert_eq!(table.node_capacity(), observed);
        // Another supplier holds the bank window: the same park, woken by
        // that window's close; this supply allocated nothing.
        let PublishRefusal::NodeBank(demand) = refused_publish(MmError::MetadataRequired, observed)
        else {
            unreachable!()
        };
        let mut peer_backing = std::vec![0u8; 2 * 1024 * 1024];
        let peer = carrick_el1::alloc::MetadataStorage::new();
        peer.admit_bootstrap_region(peer_backing.as_mut_ptr() as u64, peer_backing.len())
            .unwrap();
        // The holder opens the window through the production guard; its
        // drop is that holder's real close.
        let holder = table.open_bank_window_for_test(&waiters).unwrap();
        let error = demand.supply(&table, &peer, Some(metadata), &waiters);
        drop(holder);
        assert_eq!(error, NativeProcessError::OwnerWait(metadata));
        assert_eq!(table.node_capacity(), observed);
        // Memory no grant can add: the demand answers ENOMEM, typed, at
        // Publish.
        let PublishRefusal::NodeBank(demand) = refused_publish(MmError::MetadataRequired, observed)
        else {
            unreachable!()
        };
        let empty = carrick_el1::alloc::MetadataStorage::new();
        let error = demand.supply(&table, &empty, Some(metadata), &waiters);
        assert_eq!(
            error,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Publish,
                cause: NativeForkCause::NodeBank(NodeBankShortfall::Metadata(
                    MetadataMiss::Exhausted
                )),
            })
        );
        assert_eq!(error.failure().map(|failure| failure.errno()), Ok(-12));
        // An allocator with an extent supplies the bank: the fork reruns.
        let mut backing = std::vec![0u8; 2 * 1024 * 1024];
        let allocator = carrick_el1::alloc::MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        let PublishRefusal::NodeBank(demand) = refused_publish(MmError::MetadataRequired, observed)
        else {
            unreachable!()
        };
        assert_eq!(
            demand.supply(&table, &allocator, Some(metadata), &waiters),
            NativeProcessError::Busy
        );
        assert_ne!(table.node_capacity(), observed);
    }

    #[test]
    fn boundary_does_not_duplicate_typed_refusals() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for cause in [
            NativeForkCause::Fork(ForkError::Core),
            NativeForkCause::StockReservation(R::Invalid),
            NativeForkCause::StockReservation(R::Stale),
            NativeForkCause::StockReservation(R::Capacity(
                carrick_el1_abi::ForkCapacityResource::Tables,
            )),
            NativeForkCause::StockReservation(R::Inventory),
            NativeForkCause::StockReservation(R::Residency),
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
        // A census that found the owner's own records broken is quarantine,
        // never EFAULT (#3085).
        assert_eq!(
            error.failure(),
            Ok(super::super::native_process_runtime::NativeFailure::Quarantined)
        );
        assert_ne!(error, refused(NativeForkStage::Prepare, ForkError::Core));
        assert_ne!(error, refused(NativeForkStage::Census, ForkError::Stale));
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
            // A broken owner record is an invariant failure, not EFAULT.
            assert_eq!(
                refused(stage, MmError::Fault).failure(),
                Ok(super::super::native_process_runtime::NativeFailure::Invalid)
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
            (
                R::Capacity(carrick_el1_abi::ForkCapacityResource::Tables),
                NativeProcessError::Exhausted,
            ),
            (R::Inventory, NativeProcessError::Busy),
            (R::Residency, NativeProcessError::NoMemory),
        ] {
            let diagnostic = refused(
                NativeForkStage::Reserve,
                NativeForkCause::StockReservation(reply),
            );
            assert_eq!(diagnostic.failure(), error.failure());
        }
    }
}

//! Exact physical retention records; backend ledgers remain with their host.

/// Carrier-local identity for one installed VM.
///
/// Generations are monotonically allocated by the native VM custody allocator and never
/// reused inside that carrier, so a teardown retry cannot accidentally operate
/// on a successor VM that happens to reuse the same stage-2 coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierVmGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CarrierStage2RecordId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierLogicalOwner {
    pub id: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierStage2RecordSpec {
    pub vm_generation: CarrierVmGeneration,
    pub ipa: u64,
    pub len: usize,
    pub host_addr: usize,
    pub mapped: bool,
    pub backend_map_installed: bool,
    pub release_ipa: bool,
    pub perms: u64,
    pub logical_owner: Option<CarrierLogicalOwner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierStage2RecordIdentity {
    pub record_id: CarrierStage2RecordId,
    pub vm_generation: CarrierVmGeneration,
    pub logical_owner: Option<CarrierLogicalOwner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierStage2BackendError {
    HvReturn(u32),
    ConcurrentRetirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierStage2RetireOutcome {
    RetiredUnmapped,
    DeferredActivePins,
    RetryPending(CarrierStage2BackendError),
    TerminalizedByVmDestroy,
    NotFound,
    OwnerIdentityMismatch,
    OwnerGenerationMismatch,
    VmGenerationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierStage2RecordError {
    InvalidExtent,
    NoLiveVm,
    VmGenerationMismatch,
    RecordIdExhausted,
    RecordNotFound,
    RecordNotTerminal,
    RecordIdentityMismatch,
    ReleaseInFlight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierStage2PinError {
    NotFound,
    VmNotLive,
    OwnerIdentityMismatch,
    OwnerGenerationMismatch,
    VmGenerationMismatch,
    TerminalizedByVmDestroy,
    NotMapped,
    RetirementRequested,
    PinCountExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierStage2RecordSnapshot {
    pub record_id: CarrierStage2RecordId,
    pub vm_generation: CarrierVmGeneration,
    pub ipa: u64,
    pub len: usize,
    pub host_addr: usize,
    pub mapped: bool,
    pub backend_map_installed: bool,
    pub release_ipa: bool,
    pub perms: u64,
    pub logical_owner: Option<CarrierLogicalOwner>,
    pub pin_count: u64,
    pub retirement_requested: bool,
    pub retry_eligible: bool,
    pub retry_pending: Option<CarrierStage2BackendError>,
    pub terminalized_by_vm_destroy: bool,
    pub superseded_by_rebind: bool,
    pub release_in_flight: bool,
    pub release_retry_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierStage2Record {
    pub snapshot: CarrierStage2RecordSnapshot,
    pub unmap_in_flight: bool,
}
/// Software-image disposition after exact physical table-capacity retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableArenaRetirement {
    /// Revoke the stopped MM's image before released backing is accessible.
    Terminal,
    /// Preserve the quiesced image for the existing exec successor handoff.
    ExecHandoff,
}

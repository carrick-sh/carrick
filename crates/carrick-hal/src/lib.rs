//! `carrick-hal` — the carrick Hardware Abstraction Layer.
//!
//! Traits-only leaf crate: zero OS / hypervisor dependencies. Holds the
//! runtime↔engine contract (`SyscallTrap`, `TrapError`),
//! the raw hypervisor traits (`HvVm`/`HvVcpu`/`VcpuExit`), the host-primitive
//! traits (`EventMultiplexer`, `CrossProcessFutex`),
//! errno translation, and shared types (`OsError`, `MemPerms`, `Reg`, `SysReg`).
//! Modules are added by the following tasks.
pub mod container;
pub use container::ContainerId;
pub mod aarch64;
pub use aarch64::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, ExecLevel, aarch64_exception_class,
    is_aarch64_hvc_exception, is_aarch64_hvc_maintenance, is_aarch64_svc_exception,
    is_aarch64_syscall_exception,
};
pub mod error;
pub use error::{MemPerms, OsError, Reg, SysReg};
pub mod foreign_mm;
pub use foreign_mm::{
    ForeignAsid, ForeignAsidGeneration, ForeignCowInvalidationGeneration,
    ForeignCowInvalidationIdentity, ForeignCowKernelProof, ForeignCowReceipt,
    ForeignExecutableRange, ForeignInstructionPublicationPlan, ForeignMmBinding, ForeignMmEndpoint,
    ForeignMmId, ForeignMmInvalidator, ForeignMmInvocation, ForeignMmLeaseEndpoint,
    ForeignMmLiveAuthority, ForeignMmPreparedWrite, ForeignMmReadLease, ForeignMmReadReceipt,
    ForeignMmSnapshot, ForeignMmTransport, ForeignMmTransportError, ForeignMmWriteReceipt,
    ForeignOwnerGeneration, ForeignPtraceTextAuthority, ForeignPtraceTextCowPlan,
    ForeignReadableRange, ForeignStage1Identity,
};
pub mod stage1_exclusive;

pub mod trap;
pub use trap::{
    ExecInventoryCommits, HostAliasBacking, HostAliasOwnedFd, HostAliasSharing, RawSyscall,
    SyscallTrap, TrapError,
};
pub mod vm_backend;
pub use vm_backend::{ForkRamStrategy, GuestVmBackend};
pub mod hypervisor;
pub use hypervisor::{HvVcpu, HvVm, VcpuExit};
pub mod kernel;
pub use kernel::{
    ForeignBackendRevision, ForeignFrameInventoryRevision, ForeignVmaRevision, FrameEventCapacity,
    FrameId, FrameInventoryApplyReceipt, FrameInventoryBatch, FrameInventoryBatchError,
    FrameInventoryCommit, FrameInventoryEvent, FrameInventoryProvenance,
    FrameInventoryReceiptChallenge, FrameInventoryReservation, FrameInventoryReservationError,
    FrameInventoryRetirementReceipt, FrameLength, KernelTransactionId,
    MAX_FRAME_INVENTORY_EVENTS_PER_BATCH, MappingGeneration, MappingId,
};
pub mod event;
pub use event::{EventMultiplexer, Interest, PollEvent, Readiness, TriggerMode, VnodeEvents};
pub mod futex;
pub use futex::{
    SHARED_FUTEX_MAX_SLICE_NS, SharedWaitStep, classify_wait_slice, shared_wait_sliced,
};
pub mod threaded;
pub use threaded::{
    Aarch64CoreRegisters, CowFaultResolution, ExecPredecessorIdentity, ForkLeafDisposition,
    ForkProjectionError, ForkProjectionPlan, ForkProjectionRange, FrameCowAuthority,
    FrameCowIdentity, FrameCowOwnerInventory, FrameCowOwnerLease, FrameCowQuiesce, FutexOutcome,
    GenericVcpuRegistry, GuestEntryRegs, GuestWaitRegisters, HostVa, HvpatchChildKernelToken,
    HvpatchChildTokenIssuer, HvpatchChildTokenVerifier, HvpatchVerifiedChildKernelBinding,
    InGuestFlag, PlatformFutex, ProcessForkRequest, RegAccess, SharedFutexLocation,
    SignalPumpControl, ThreadId, ThreadedEngine, VcpuKick, VcpuKickDyn,
    VcpuLeaseChangeSubscription, VcpuLeaseDrainEnrollment, VcpuLeaseDrainGuard, VcpuLeaseDrainPoll,
    VcpuRegistrationEnrollment, VcpuRegistry, X86SignalXstate, X86XstateCapabilities,
    X86XstateComponent, aarch64_signal_pstate_source, lookup_fork_projection,
    read_aarch64_syscall_frame, validate_fork_projection, validate_total_fork_projection,
};
pub mod sigframe;
pub mod signal_arrival;
pub use signal_arrival::{GenericSignalArrival, SignalArrival};
/// The platform-neutral signal-pump controller, generic over the backend's
/// [`pump_fork_coord::HostSignalPump`] (self-pipe or kqueue).
pub mod pump_fork_coord;
pub use pump_fork_coord::{HostSignalPump, SignalPumpController};
/// The shared signal-pump controller for kick+futex backends (cfg-empty on macOS/HVF).
pub mod fork_coord;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub use fork_coord::GenericSignalPumpControl;
/// The shared async host-signal pump (kick+futex backends; cfg-empty on macOS/HVF).
pub mod signal_pump;
/// The pluggable M:N admission scheduler bounding guest threads onto N vCPU slots.
pub mod vcpu_sched;
pub use vcpu_sched::{SlotId, SlotLease, VcpuScheduler, Yield};
pub mod timer_delivery;
pub use timer_delivery::{PosixTimerSpec, TimerArm, TimerDelivery, TimerSpecNs};
pub mod guest_arch;
pub use guest_arch::{GuestArch, PageTableCodec, PtGranule, SyscallRemap, SyscallTable};
pub mod aarch64_arch;
pub use aarch64_arch::{Aarch64BootSysregs, Aarch64GuestArch, Aarch64Mmu, Aarch64SyscallTable};
pub mod x8664_arch;
pub use x8664_arch::{
    GDT_LEN, SYSCALL_DOORBELL_PORT, X8664BootSysregs, X8664GuestArch, X8664Mmu, X8664SyscallTable,
    entry_trampoline_bytes as x8664_entry_trampoline_bytes,
};
pub mod scheduler;
pub use scheduler::{
    CpuAffinity, CpuLoad, CpuQueueView, GuestCpuId, GuestCpuPolicy, MAX_GUEST_CPUS,
    PreemptOrContinue, SchedulingPolicy, TaskKey, TaskPlacement,
};

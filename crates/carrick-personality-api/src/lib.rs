//! Neutral operating system personality API for Carrick.
//!
//! Re-exports the single path for personality-facing contracts: the [`Personality`]
//! trait, TLS / context pointer register selections, and typed keys an external
//! personality implementation requires.
#![no_std]

// 1. Personality trait, decoding interfaces, and memory copy handles from carrick-core
pub use carrick_core::{
    CallContext, CallOrdinal, Personality, PersonalityAbi, ThreadKey, UserMemory,
};

// 2. Thread pointer register from carrick-guest-arch
pub use carrick_guest_arch::{
    Aarch64ThreadPointerRegister, ThreadPointerRegister, X86ThreadPointerRegister,
};

// 3. Hardware boundary, errors, and typed keys from carrick-guest-arch
pub use carrick_guest_arch::{
    AddressSpaceRegister, Asid, CpuId, EntryArch, EntryDecodeError, EntryEvent, FaultInfo,
    FrameGpa, GuestIsa, KernelVa, NativeAbi, ReturnKind, RootGpa, ServiceError, SlotId,
    ThreadContext, UserReturn, UserVa,
};

// 4. Neutral process lifecycle and scheduling identity from carrick-sched-core
pub use carrick_sched_core::process::{
    ProcessGroupId, SessionId, TaskId, TaskIdentity, TaskKey, TaskLifecycle, TaskRusage,
    TerminationKind, TerminationStatus, WaitChildClass, WaitMode, WaitTarget, Zombie,
};

// 5. Neutral lifecycle authority and entry tokens from carrick-core-abi
pub use carrick_core_abi::{
    EntryRef, EntryState, GateState, NativeRunFailureReason, Served, ThreadLedgerActivity,
};

// 6. Capability-based neutral file service
pub use carrick_core::file;

//! The no_std hardware boundary of Carrick's one in-guest kernel.
//!
//! Kernel-facing traits are sealed on [`Arch`]. ISA crates implement the
//! corresponding backend hooks; they cannot replace the kernel-facing adapter.
//! MM owners, edits, drains and transfers are associated owned capabilities,
//! issued by the real owner, rather than integer IDs minted by this interface.
//! This crate contains no Linux syscall policy, task allocator or memory ledger.
#![no_std]

use core::num::NonZeroU64;

mod sealed {
    pub trait Sealed {}
}

macro_rules! ordinal {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $name(u64);
        impl $name {
            pub const fn new(raw: u64) -> Self { Self(raw) }
            pub const fn raw(self) -> u64 { self.0 }
        }
    )+};
}
ordinal!(
    UserVa,
    FrameGpa,
    GuestLen,
    CounterTick,
    CanonicalOrdinal,
    NativeOrdinal,
    UserFlags,
    FatalCode
);

macro_rules! generation {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $name(NonZeroU64);
        impl $name {
            pub const fn new(raw: NonZeroU64) -> Self { Self(raw) }
            pub const fn raw(self) -> NonZeroU64 { self.0 }
        }
    )+};
}
generation!(
    CarrierGeneration,
    TaskSerial,
    ExecutionGeneration,
    MmGeneration,
    ContextGeneration,
    CpuGeneration,
    BackingGeneration,
    OperationSequence,
    CounterFrequency
);

/// A task serial and execution generation are distinct from Linux/host PIDs.
/// The kernel issues the values; carrying this identity confers no graph rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskIdentity {
    pub carrier: CarrierGeneration,
    pub task: TaskSerial,
    pub execution: ExecutionGeneration,
}

/// A root's physical address, never a user virtual address or PCID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootGpa(FrameGpa);
impl RootGpa {
    pub const fn page_aligned(address: FrameGpa) -> Option<Self> {
        if address.raw() & 0xfff == 0 {
            Some(Self(address))
        } else {
            None
        }
    }
    pub const fn address(self) -> FrameGpa {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressContext<R> {
    pub root: R,
    pub mm: MmGeneration,
    pub generation: ContextGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserRange {
    start: UserVa,
    len: GuestLen,
}
impl UserRange {
    pub const fn checked(start: UserVa, len: GuestLen) -> Option<Self> {
        if start.raw().checked_add(len.raw()).is_some() {
            Some(Self { start, len })
        } else {
            None
        }
    }
    pub const fn start(self) -> UserVa {
        self.start
    }
    pub const fn len(self) -> GuestLen {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        self.len.raw() == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestIsa {
    Aarch64,
    X86_64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalCall {
    pub isa: GuestIsa,
    pub canonical: CanonicalOrdinal,
    pub native: NativeOrdinal,
    /// Register arguments stay raw until the common personality interprets them.
    pub args: [u64; 6],
    pub stack: UserVa,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallResult(i64);
impl SyscallResult {
    pub const fn new(result: i64) -> Self {
        Self(result)
    }
    pub const fn raw(self) -> i64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Write,
    Execute,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultInfo {
    pub address: UserVa,
    pub access: Access,
    pub present: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryEvent {
    Syscall,
    Fault(FaultInfo),
    Interrupt,
    Maintenance,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReturnKind {
    ExceptionReturn,
    FastSyscallReturn,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserReturn {
    pub pc: UserVa,
    pub stack: UserVa,
    pub flags: UserFlags,
    pub kind: ReturnKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyProgress {
    pub completed: GuestLen,
    pub remaining: GuestLen,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline(pub CounterTick);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuId(u32);
impl CpuId {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuTarget {
    pub cpu: CpuId,
    pub generation: CpuGeneration,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakeToken {
    pub task: TaskIdentity,
    pub operation: OperationSequence,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptReason {
    Timer,
    Wake(WakeToken),
    External,
}
/// The acknowledgement is consumed by end_interrupt, never duplicated.
#[derive(Debug)]
pub struct InterruptAck<I> {
    pub reason: InterruptReason,
    pub hardware: I,
}

/// Real crossings only: no generic "dispatch this Linux syscall" request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRequestKind {
    ReadBytes,
    WriteBytes,
    Readiness,
    Clock,
    Terminal,
    Backing,
    Control,
}
#[derive(Debug)]
pub struct OwnedHostRequest<P> {
    pub task: TaskIdentity,
    pub operation: OperationSequence,
    pub kind: HostRequestKind,
    pub payload: P,
}
/// The backend's owned ticket carries completion custody. Copyable identity
/// fields alone cannot manufacture or duplicate a pending completion.
#[derive(Debug)]
pub struct RequestToken<T> {
    task: TaskIdentity,
    operation: OperationSequence,
    ticket: T,
}
impl<T> RequestToken<T> {
    pub const fn new(task: TaskIdentity, operation: OperationSequence, ticket: T) -> Self {
        Self {
            task,
            operation,
            ticket,
        }
    }
    pub const fn task(&self) -> TaskIdentity {
        self.task
    }
    pub const fn operation(&self) -> OperationSequence {
        self.operation
    }
    pub fn into_ticket(self) -> T {
        self.ticket
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatalReport {
    pub task: Option<TaskIdentity>,
    pub detail: FatalCode,
}

/// Native frames and owner capabilities are supplied by the respective owner.
/// No defaults manufacture permissions, completion receipts or saved state.
pub trait ArchTypes {
    type Error;
    type NativeFrame;
    type SavedContext;
    type Root: Copy + Eq;
    type MmOwner;
    type OwnedTranslation;
    type LeafEdit;
    type DrainTicket;
    type DrainReceipt;
    type UserTransfer;
    type PublicationReceipt;
    type HardwareInterrupt;
    type InterruptMask;
    type HostPayload;
    type HostTicket;
    type HostCompletion;
}

/// The only kernel-facing adapter. Backend hooks are the extension point.
///
/// The seal is deliberately private:
/// ```compile_fail
/// use carrick_guest_arch::sealed::Sealed;
/// ```
pub struct Arch<B> {
    backend: B,
}
impl<B> Arch<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }
    pub const fn backend(&self) -> &B {
        &self.backend
    }
    pub fn into_backend(self) -> B {
        self.backend
    }
}
impl<B> sealed::Sealed for Arch<B> {}
impl<B: ArchTypes> ArchTypes for Arch<B> {
    type Error = B::Error;
    type NativeFrame = B::NativeFrame;
    type SavedContext = B::SavedContext;
    type Root = B::Root;
    type MmOwner = B::MmOwner;
    type OwnedTranslation = B::OwnedTranslation;
    type LeafEdit = B::LeafEdit;
    type DrainTicket = B::DrainTicket;
    type DrainReceipt = B::DrainReceipt;
    type UserTransfer = B::UserTransfer;
    type PublicationReceipt = B::PublicationReceipt;
    type HardwareInterrupt = B::HardwareInterrupt;
    type InterruptMask = B::InterruptMask;
    type HostPayload = B::HostPayload;
    type HostTicket = B::HostTicket;
    type HostCompletion = B::HostCompletion;
}

// Generate each sealed projection and its explicit backend extension hook from
// one signature list, so the hardware and kernel sides cannot drift.
macro_rules! arch_trait {
    ($kernel:ident, $backend:ident { $(fn $name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)+ }) => {
        pub trait $kernel: sealed::Sealed + ArchTypes {
            $(fn $name(&mut self, $($arg: $ty),*) -> $out;)+
        }
        pub trait $backend: ArchTypes {
            $(fn $name(&mut self, $($arg: $ty),*) -> $out;)+
        }
        impl<B: $backend> $kernel for Arch<B> {
            $(fn $name(&mut self, $($arg: $ty),*) -> $out { self.backend.$name($($arg),*) })+
        }
    };
}

arch_trait!(EntryArch, EntryBackend {
    fn decode_entry(frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error>;
    fn decode_syscall(frame: &Self::NativeFrame) -> Result<CanonicalCall, Self::Error>;
    fn set_result(frame: &mut Self::NativeFrame, result: SyscallResult) -> Result<(), Self::Error>;
    fn save_context(frame: &Self::NativeFrame) -> Result<Self::SavedContext, Self::Error>;
    fn load_context(frame: &mut Self::NativeFrame, saved: &Self::SavedContext) -> Result<(), Self::Error>;
    fn prepare_user_return(frame: &Self::NativeFrame) -> Result<UserReturn, Self::Error>;
});
arch_trait!(MmuArch, MmuBackend {
    fn install_context(context: AddressContext<Self::Root>) -> Result<(), Self::Error>;
    fn translate_live(owner: &Self::MmOwner, address: UserVa, access: Access) -> Result<Self::OwnedTranslation, Self::Error>;
    fn prepare_leaf_edit(owner: &Self::MmOwner, range: UserRange, translation: Self::OwnedTranslation) -> Result<Self::LeafEdit, Self::Error>;
    fn apply_leaf_edit(edit: &mut Self::LeafEdit) -> Result<(), Self::Error>;
    fn undo_leaf_edit(edit: Self::LeafEdit) -> Result<(), Self::Error>;
    fn request_invalidation(context: AddressContext<Self::Root>, range: UserRange) -> Result<Self::DrainTicket, Self::Error>;
    fn ack_drain(ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error>;
    fn copy_user_chunk(transfer: &mut Self::UserTransfer, limit: GuestLen) -> Result<CopyProgress, Self::Error>;
    fn publish_executable(owner: &Self::MmOwner, range: UserRange) -> Result<Self::PublicationReceipt, Self::Error>;
});
arch_trait!(InterruptArch, InterruptBackend {
    fn counter() -> Result<CounterTick, Self::Error>;
    fn frequency() -> Result<CounterFrequency, Self::Error>;
    fn arm_timer(deadline: Option<Deadline>) -> Result<(), Self::Error>;
    fn send_wake(target: CpuTarget, token: WakeToken) -> Result<(), Self::Error>;
    fn ack_interrupt() -> Result<Option<InterruptAck<Self::HardwareInterrupt>>, Self::Error>;
    fn end_interrupt(ack: InterruptAck<Self::HardwareInterrupt>) -> Result<(), Self::Error>;
    fn mask_interrupts() -> Self::InterruptMask;
    fn restore_interrupts(mask: Self::InterruptMask) -> Result<(), Self::Error>;
    fn park_until_interrupt() -> Result<(), Self::Error>;
    fn current_cpu() -> CpuId;
});
arch_trait!(CrossingArch, CrossingBackend {
    fn submit_host_request(request: OwnedHostRequest<Self::HostPayload>) -> Result<RequestToken<Self::HostTicket>, Self::Error>;
    fn consume_completion(token: RequestToken<Self::HostTicket>) -> Result<Self::HostCompletion, Self::Error>;
    fn leave_idle() -> Result<(), Self::Error>;
    fn report_fatal(report: FatalReport) -> !;
});

pub trait KernelArch: sealed::Sealed + EntryArch + MmuArch + InterruptArch + CrossingArch {}
impl<B: EntryBackend + MmuBackend + InterruptBackend + CrossingBackend> KernelArch for Arch<B> {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_and_range_checks_do_not_mask_or_wrap() {
        assert_eq!(RootGpa::page_aligned(FrameGpa::new(0x1001)), None);
        assert_eq!(
            UserRange::checked(UserVa::new(u64::MAX), GuestLen::new(1)),
            None
        );
        assert!(UserRange::checked(UserVa::new(0x1000), GuestLen::new(0)).is_some());
    }
}

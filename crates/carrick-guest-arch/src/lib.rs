//! The no_std hardware boundary of Carrick's one in-guest kernel.
//!
//! Kernel-facing traits are sealed on [`Arch`]. ISA crates implement the
//! corresponding backend hooks; they cannot replace the kernel-facing adapter.
//! MM owners, edits, drains and transfers are associated owned capabilities,
//! issued by the real owner, rather than integer IDs minted by this interface.
//! This crate contains no Linux syscall policy, task allocator or memory ledger.
#![no_std]

pub use carrick_syscall_abi::CanonicalNr;
use core::num::NonZeroU64;

/// An error indicating that user memory could not be accessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserMemoryFault;

/// Per-backend FS/GS segment-base register access — the ISA-mechanism part of segment base addressing.
pub trait SegmentBaseRegs {
    type Error;
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), Self::Error>;
    fn seg_get_fs_base(&self) -> Result<u64, Self::Error>;
    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), Self::Error>;
    fn seg_get_gs_base(&self) -> Result<u64, Self::Error>;
}

/// User memory access for writing register bases during GET subfunctions or user access.
pub trait CurrentMmMemory {
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), UserMemoryFault>;
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! ordinal {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    KernelVa,
    KernelStackPointer,
    FrameGpa,
    GuestLen,
    CounterTick,
    NativeOrdinal,
    UserFlags,
    FatalCode,
    UserStackOffset,
);

/// Native address-space register bits, including ARM ASID or x86 control
/// bits. This is distinct from a physical root and conveys no MM authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AddressSpaceRegister(u64);
impl AddressSpaceRegister {
    pub const fn from_register(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Nonzero AArch64 stage-1 address-space identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Asid(core::num::NonZeroU16);

impl Asid {
    pub const fn from_registry_allocation(raw: core::num::NonZeroU16) -> Self {
        Self(raw)
    }

    pub const fn first() -> Self {
        Self(core::num::NonZeroU16::MIN)
    }

    pub const fn raw(self) -> u16 {
        self.0.get()
    }

    pub const fn nonzero(self) -> core::num::NonZeroU16 {
        self.0
    }
}

/// A vCPU slot (the syscall-mailbox slot index).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SlotId(u8);
const _: () = assert!(core::mem::size_of::<SlotId>() == 1);

impl SlotId {
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// A slot from a mailbox slot index; `None` beyond 255.
    pub fn from_index(index: usize) -> Option<Self> {
        u8::try_from(index).ok().map(Self)
    }

    pub const fn raw(self) -> u8 {
        self.0
    }

    /// `slot + 1`, the encoding of an optional slot in a record word.
    pub const fn plus_one(self) -> u32 {
        self.0 as u32 + 1
    }

    /// The slot a `slot + 1` word names (0: none).
    pub fn from_plus_one(word: u32) -> Option<Self> {
        word.checked_sub(1)
            .and_then(|index| u8::try_from(index).ok())
            .map(Self)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Registers needed by the shared Linux syscall families. Native frames
/// implement this directly; no ISA-shaped substitute frame is constructed.
pub trait SyscallFrame {
    fn canonical_ordinal(&self) -> CanonicalNr;
    fn argument(&self, index: usize) -> Option<u64>;
    fn result(&self) -> NativeReturnWord;
    fn set_result(&mut self, result: NativeReturnWord);
    fn slot(&self) -> Option<SlotId>;
    /// Index within the supplied task slice. A projected one-task x86 slice
    /// uses index zero while retaining its real CPU slot in `slot()`.
    fn task_index(&self) -> usize {
        self.slot().map_or(usize::MAX, SlotId::index)
    }
    fn user_sp(&self) -> Option<UserVa>;
}

/// Supervisor addresses selected by the image ISA. Offsets within the kernel
/// region retain the shared ABI; a guest cannot use another ISA's base here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelLayout {
    pub region: KernelVa,
    pub zone: KernelVa,
    pub portal: KernelVa,
    pub dynamic_metadata: KernelVa,
}

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

pub const USER_CEILING: u64 = 0x0000_8000_0000_0000;

/// A user operand must be wholly within the canonical lower half. The
/// checked end also excludes wraparound into the supervisor address space.
pub const fn lower_half_range(address: u64, len: u64) -> bool {
    address < USER_CEILING
        && match address.checked_add(len) {
            Some(end) => end <= USER_CEILING,
            None => false,
        }
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
    pub const fn in_lower_half(self) -> bool {
        lower_half_range(self.start.raw(), self.len.raw())
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

/// Exact-MM editor custody for one in-guest descriptor transaction. A root or
/// MM number alone cannot issue this noncopyable capability.
pub struct EditOwner<R> {
    root: R,
    mm_key: NonZeroU64,
    generation: NonZeroU64,
}

/// Retained, writable kernel alias of one page-table arena. The physical
/// root and the virtual access path remain separate address domains.
pub struct TableWindow {
    physical: FrameGpa,
    mapped: KernelVa,
    bytes: GuestLen,
}

impl TableWindow {
    /// # Safety
    /// The caller retains a writable supervisor mapping of every byte in the
    /// physical arena at `mapped` and excludes concurrent table reclamation
    /// for the entire descriptor transaction and receipt settlement.
    pub unsafe fn issue(physical: FrameGpa, mapped: KernelVa, bytes: GuestLen) -> Option<Self> {
        if physical.raw() & 4095 != 0
            || mapped.raw() & 4095 != 0
            || bytes.raw() < 4096
            || bytes.raw() & 4095 != 0
            || physical.raw().checked_add(bytes.raw()).is_none()
            || mapped.raw().checked_add(bytes.raw()).is_none()
        {
            return None;
        }
        Some(Self {
            physical,
            mapped,
            bytes,
        })
    }

    pub const fn physical(&self) -> FrameGpa {
        self.physical
    }
    pub const fn mapped(&self) -> KernelVa {
        self.mapped
    }
    pub const fn bytes(&self) -> GuestLen {
        self.bytes
    }
}

impl<R: Copy> EditOwner<R> {
    /// # Safety
    /// The caller holds the exact-MM editor for `mm_key` through settlement,
    /// has authenticated `root` against the live task, and owns this operation
    /// generation. Neither a stale root nor a borrowed editor may issue it.
    pub unsafe fn issue(root: R, mm_key: NonZeroU64, generation: NonZeroU64) -> Self {
        Self {
            root,
            mm_key,
            generation,
        }
    }

    pub fn root(&self) -> R {
        self.root
    }

    pub fn mm_key(&self) -> NonZeroU64 {
        self.mm_key
    }

    pub fn generation(&self) -> NonZeroU64 {
        self.generation
    }
}

/// Linux user access intent, before ISA descriptor bits are chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
}

/// Host-authenticated output backing, never inferred from a page-table word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditBacking {
    pub frame_id: NonZeroU64,
    pub mapping_id: NonZeroU64,
    pub owner_generation: NonZeroU64,
    pub inventory_revision: NonZeroU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditLeafSize {
    Page,
    Block2M,
    Block1G,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditCowAccess {
    Retired,
    RecordedPrivate,
    User { writable_pages: u8 },
    Kernel,
}

/// A requested descriptor operation. Each variant uses the enclosing intent's
/// exact page-aligned VA range and carries all output and permission data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditOperation {
    Prepare {
        output: FrameGpa,
        permissions: EditPermissions,
        resident: UserRange,
        backing: EditBacking,
    },
    Map {
        output: FrameGpa,
        permissions: EditPermissions,
        size: EditLeafSize,
        resident: bool,
        backing: EditBacking,
    },
    Publish {
        expected: FrameGpa,
        access: Access,
    },
    Protect {
        permissions: EditPermissions,
    },
    ArmCow {
        kernel_only: bool,
        executable: bool,
        adopt_private: bool,
        asid_scoped: bool,
        excluded_ipa: FrameGpa,
        excluded_len: GuestLen,
    },
    CowRepoint {
        old: FrameGpa,
        new: FrameGpa,
        backing: EditBacking,
        access: EditCowAccess,
    },
    Unmap,
    Coalesce {
        size: EditLeafSize,
    },
}

/// ISA-neutral transaction input. The native backend validates unsupported
/// permission combinations and physical-table grants before any live store.
pub struct EditIntent<'a, R> {
    owner: EditOwner<R>,
    range: UserRange,
    operation: EditOperation,
    table_grants: &'a [RootGpa],
}

impl<'a, R: Copy> EditIntent<'a, R> {
    pub fn checked(
        owner: EditOwner<R>,
        range: UserRange,
        operation: EditOperation,
        table_grants: &'a [RootGpa],
    ) -> Option<Self> {
        if range.is_empty() || range.start().raw() & 4095 != 0 || range.len().raw() & 4095 != 0 {
            return None;
        }
        Some(Self {
            owner,
            range,
            operation,
            table_grants,
        })
    }

    pub fn owner(&self) -> &EditOwner<R> {
        &self.owner
    }

    pub fn range(&self) -> UserRange {
        self.range
    }

    pub fn operation(&self) -> EditOperation {
        self.operation
    }

    pub fn table_grants(&self) -> &[RootGpa] {
        self.table_grants
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestIsa {
    Aarch64,
    X86_64,
}
/// Native entry mechanism, without a syscall personality interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAbi {
    Aarch64El0,
    X86_64Syscall,
}

/// An entry frame decode error during personality dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryDecodeError {
    /// A stack or memory argument access faulted on an unmapped or protected address.
    Fault,
    /// An entry frame was invalid for this architecture or profile.
    InvalidFrame,
    /// The ABI or requested convention is unsupported.
    UnsupportedAbi,
    /// Requested argument or operand width is invalid.
    InvalidWidth,
    /// Argument or stack access offset is out of bounds.
    OutOfBounds,
    /// A transient busy state prevents decoding; the carrier resolves this on
    /// re-entry after the busy owner settles (not a caller retry loop).
    Busy,
    /// An architectural register or execution context is unbound on this host or target.
    Unbound,
}

impl core::fmt::Display for EntryDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fault => write!(f, "fault: unmapped or protected address"),
            Self::InvalidFrame => write!(f, "invalid entry frame"),
            Self::UnsupportedAbi => write!(f, "unsupported ABI"),
            Self::InvalidWidth => write!(f, "invalid argument width"),
            Self::OutOfBounds => write!(f, "argument offset out of bounds"),
            Self::Busy => write!(f, "transient busy state; carrier re-enters when settled"),
            Self::Unbound => write!(f, "unbound architectural context"),
        }
    }
}

/// Direction of a user memory transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    FromUser,
    ToUser,
}

/// A service-time error during personality memory operations or call servicing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// A user memory access faulted on an unmapped or invalid address.
    Fault,
    /// A user memory write was refused due to access permission violation (e.g. read-only mapping).
    AccessDenied,
    /// Address arithmetic overflow or address outside the canonical user range.
    RangeOverflow,
    /// Operation was refused (e.g. off-target build or unbound execution state).
    Refused,
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fault => write!(f, "fault: unmapped or invalid user address"),
            Self::AccessDenied => write!(f, "access denied: permission violation"),
            Self::RangeOverflow => write!(f, "range overflow: invalid address or bounds"),
            Self::Refused => write!(f, "service refused: off-target or unbound execution"),
        }
    }
}

impl From<ServiceError> for EntryDecodeError {
    fn from(_err: ServiceError) -> Self {
        EntryDecodeError::Fault
    }
}

impl From<EntryDecodeError> for ServiceError {
    fn from(err: EntryDecodeError) -> Self {
        match err {
            EntryDecodeError::Fault => ServiceError::Fault,
            EntryDecodeError::OutOfBounds => ServiceError::RangeOverflow,
            EntryDecodeError::InvalidFrame => ServiceError::Fault,
            EntryDecodeError::InvalidWidth => ServiceError::Fault,
            EntryDecodeError::UnsupportedAbi => ServiceError::Refused,
            EntryDecodeError::Busy => ServiceError::Refused,
            EntryDecodeError::Unbound => ServiceError::Refused,
        }
    }
}

/// Retains the complete ISA-native frame; six Linux arguments are decoded only
/// after crossing into the Linux personality.
#[derive(Clone, Copy, Debug)]
pub struct NativeEntrySnapshot<'a, F> {
    pub isa: GuestIsa,
    pub abi: NativeAbi,
    pub frame: &'a F,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86Register {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}
pub trait X86Registers {
    fn read(&self, register: X86Register) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Aarch64Register {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    Sp,
    Pc,
    Pstate,
}

pub trait Aarch64Registers {
    fn read(&self, register: Aarch64Register) -> u64;
}

/// Opaque native return-register bits. No errno or Linux result in hardware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct NativeReturnWord(pub u64);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatalReport {
    pub task: Option<TaskIdentity>,
    pub detail: FatalCode,
}

/// ISA-selected scheduler context operations needed by process birth.
/// Implementations preserve native register/TLS/vector state and replace only
/// the child's return value and exact address-space binding. The owner never
/// interprets register words. Storage is the same Context selected by ArchTypes.
pub trait ProcessContext: Copy + Send + Sync + zerocopy::FromZeros {
    fn authenticates(&self, expected: AddressContext<RootGpa>) -> bool;
    fn fork_child(self, address: AddressContext<RootGpa>) -> Self;
    fn set_syscall_return(&mut self, value: u64);
    fn with_syscall_return(mut self, value: u64) -> Self {
        self.set_syscall_return(value);
        self
    }
    fn syscall_return(&self) -> u64;
}

/// Architectural register selection for thread-local storage / thread context on x86_64.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum X86ThreadPointerRegister {
    Fs,
    Gs,
}

/// Architectural register selection for thread-local storage / thread context on AArch64.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Aarch64ThreadPointerRegister {
    TpidrEl0,
    X18,
}

/// Personality-configurable architectural register that serves as the thread context pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ThreadPointerRegister {
    X86(X86ThreadPointerRegister),
    Aarch64(Aarch64ThreadPointerRegister),
}

impl ThreadPointerRegister {
    pub const FS: Self = Self::X86(X86ThreadPointerRegister::Fs);
    pub const GS: Self = Self::X86(X86ThreadPointerRegister::Gs);
    pub const TPIDR_EL0: Self = Self::Aarch64(Aarch64ThreadPointerRegister::TpidrEl0);
    pub const X18: Self = Self::Aarch64(Aarch64ThreadPointerRegister::X18);
}

impl From<X86ThreadPointerRegister> for ThreadPointerRegister {
    fn from(register: X86ThreadPointerRegister) -> Self {
        Self::X86(register)
    }
}

impl From<Aarch64ThreadPointerRegister> for ThreadPointerRegister {
    fn from(register: Aarch64ThreadPointerRegister) -> Self {
        Self::Aarch64(register)
    }
}

/// Hardware-neutral access to the thread pointer / TLS base register in saved thread contexts.
pub trait ThreadContext {
    /// Read the thread pointer value stored for `register`.
    fn thread_pointer(&self, register: ThreadPointerRegister) -> u64;
    /// Write the thread pointer value stored for `register`.
    fn set_thread_pointer(&mut self, register: ThreadPointerRegister, value: u64);

    fn with_thread_pointer(mut self, register: ThreadPointerRegister, value: u64) -> Self
    where
        Self: Sized,
    {
        self.set_thread_pointer(register, value);
        self
    }
}

/// Native frames and owner capabilities are supplied by the respective owner.
/// No defaults manufacture permissions, completion receipts or saved state.
pub trait ArchTypes {
    type Error;
    type NativeFrame;
    type SavedContext;
    /// Zero-valid scheduler record storage for this ISA, distinct from a
    /// live native context that may contain nonzero ownership generations.
    type Context: Copy + Send + Sync + zerocopy::FromZeros;
    type Root: Copy + Eq;
    type MmOwner: 'static;
    type DrainTicket;
    type DrainReceipt;
    type UserTransfer;
    type HardwareInterrupt;
    type InterruptMask;
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
    type Context = B::Context;
    type Root = B::Root;
    type MmOwner = B::MmOwner;
    type DrainTicket = B::DrainTicket;
    type DrainReceipt = B::DrainReceipt;
    type UserTransfer = B::UserTransfer;
    type HardwareInterrupt = B::HardwareInterrupt;
    type InterruptMask = B::InterruptMask;
}

pub trait LayoutBackend {
    const KERNEL_LAYOUT: KernelLayout;
}

pub trait LayoutArch: sealed::Sealed {
    fn kernel_layout(&self) -> KernelLayout;
}

impl<B: LayoutBackend> LayoutArch for Arch<B> {
    fn kernel_layout(&self) -> KernelLayout {
        B::KERNEL_LAYOUT
    }
}

// Generate each sealed projection and its explicit backend extension hook from
// one signature list, so the hardware and kernel sides cannot drift.
macro_rules! arch_trait {
    ($kernel:ident, $backend:ident { $(fn $name:ident $(<$lt:lifetime>)? ($($arg:ident: $ty:ty),*) -> $out:ty;)+ }) => {
        pub trait $kernel: sealed::Sealed + ArchTypes {
            $(fn $name $(<$lt>)? (&mut self, $($arg: $ty),*) -> $out;)+
        }
        pub trait $backend: ArchTypes {
            $(fn $name $(<$lt>)? (&mut self, $($arg: $ty),*) -> $out;)+
        }
        impl<B: $backend> $kernel for Arch<B> {
            $(fn $name $(<$lt>)? (&mut self, $($arg: $ty),*) -> $out { self.backend.$name($($arg),*) })+
        }
    };
}

/// Provider for a default MM owner capability, allowing testing backends or
/// implicit-task backends to supply an MM owner when one is not explicitly passed.
pub trait DefaultMmOwner: ArchTypes
where
    Self::MmOwner: 'static,
{
    fn default_owner() -> Option<&'static Self::MmOwner> {
        None
    }
}

impl<B: DefaultMmOwner> DefaultMmOwner for Arch<B>
where
    Self::MmOwner: 'static,
{
    fn default_owner() -> Option<&'static Self::MmOwner> {
        B::default_owner()
    }
}

arch_trait!(EntryArch, EntryBackend {
    fn current_stack_pointer() -> Result<KernelStackPointer, Self::Error>;
    fn decode_entry(frame: &Self::NativeFrame) -> Result<EntryEvent, Self::Error>;
    fn snapshot<'a>(frame: &'a Self::NativeFrame) -> Result<NativeEntrySnapshot<'a, Self::NativeFrame>, Self::Error>;
    fn set_result(frame: &mut Self::NativeFrame, result: NativeReturnWord) -> Result<(), Self::Error>;
    fn save_context(frame: &Self::NativeFrame) -> Result<Self::SavedContext, Self::Error>;
    fn load_context(frame: &mut Self::NativeFrame, saved: &Self::SavedContext) -> Result<(), Self::Error>;
    fn prepare_user_return(frame: &Self::NativeFrame) -> Result<UserReturn, Self::Error>;
    fn user_stack_pointer(frame: &Self::NativeFrame) -> Result<UserVa, Self::Error>;
});
arch_trait!(MmuArch, MmuBackend {
    fn live_root() -> Result<Self::Root, Self::Error>;
    fn read_user_word(owner: &Self::MmOwner, address: UserVa, width: GuestLen) -> Result<u64, Self::Error>;
    fn validate_user_access(owner: &Self::MmOwner, range: UserRange, access: Access) -> Result<GuestLen, Self::Error>;
    fn install_context(context: AddressContext<Self::Root>) -> Result<(), Self::Error>;
    fn request_invalidation(context: AddressContext<Self::Root>, range: UserRange) -> Result<Self::DrainTicket, Self::Error>;
    fn ack_drain(ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error>;
    fn open_user_transfer(owner: &Self::MmOwner, user: UserVa, kernel: core::ptr::NonNull<u8>, len: GuestLen, direction: TransferDirection) -> Result<Self::UserTransfer, Self::Error>;
    fn copy_user_chunk(transfer: &mut Self::UserTransfer, limit: GuestLen) -> Result<CopyProgress, Self::Error>;
});

/// An exact-MM descriptor edit. The intent retains its noncopyable editor
/// authority through the native transaction and its drain receipt.
pub trait MmuEditArch: sealed::Sealed + ArchTypes {
    type EditReceipt;
    /// # Safety
    /// `tables` is the retained page-table window
    /// of the intent's root, and the caller keeps the exact editor through
    /// receipt settlement. The backend validates the live root before stores.
    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, Self::Root>,
        tables: TableWindow,
    ) -> Result<Self::EditReceipt, Self::Error>;
}

pub trait MmuEditBackend: ArchTypes {
    type EditReceipt;
    /// # Safety
    /// The caller retains the authenticated table window and exact-MM editor
    /// described by `intent` until the returned receipt is settled.
    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, Self::Root>,
        tables: TableWindow,
    ) -> Result<Self::EditReceipt, Self::Error>;
}

impl<B: MmuEditBackend> MmuEditArch for Arch<B> {
    type EditReceipt = B::EditReceipt;

    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, Self::Root>,
        tables: TableWindow,
    ) -> Result<Self::EditReceipt, Self::Error> {
        // SAFETY: this sealed adapter forwards the caller's exact editor and
        // retained table-window obligations unchanged to the native backend.
        unsafe { self.backend.execute_edit(intent, tables) }
    }
}
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
    fn yield_host_effect() -> Result<(), Self::Error>;
    fn report_fatal(report: FatalReport) -> !;
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalFrameParams {
    pub stack: carrick_syscall_abi::LinuxSignalStack,
    pub signal: carrick_signal_core::policy::Signal,
    pub sigcode: i32,
    pub fault_addr: u64,
    pub sp: UserVa,
    pub handler: UserVa,
    pub restorer: Option<UserVa>,
    pub mask: carrick_signal_core::policy::SigBlockMask,
}

arch_trait!(SignalArch, SignalBackend {
    fn setup_signal_frame<'a>(
        frame: &mut Self::NativeFrame,
        params: SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool
    ) -> Result<UserVa, Self::Error>;

    fn restore_signal_frame(
        frame: &mut Self::NativeFrame,
        fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool
    ) -> Result<carrick_signal_core::policy::SigBlockMask, Self::Error>;
});

pub trait KernelArch:
    sealed::Sealed
    + LayoutArch
    + EntryArch
    + MmuArch
    + MmuEditArch
    + InterruptArch
    + CrossingArch
    + SignalArch
{
}
impl<
    B: LayoutBackend
        + EntryBackend
        + MmuBackend
        + MmuEditBackend
        + InterruptBackend
        + CrossingBackend
        + SignalBackend,
> KernelArch for Arch<B>
{
}

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

/// The only EL1-private terminal states encoded by the software bits and
/// descriptor validity. This is the authority gate for prepared backing,
/// retirement, and host-buffer access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum El1PrivateLeafState {
    Unowned,
    Prepared,
    Resident,
    Retired,
    Malformed,
}

/// Architecture decoding for the shared anonymous backing walk.
/// Decoding conveys custody only; it does not authorize descriptor writes.
pub trait AnonymousDescriptorDecode {
    fn indices(va: UserVa) -> [usize; 4];
    fn next_table(descriptor: u64, level: usize) -> Option<FrameGpa>;
    fn private_state(descriptor: u64) -> El1PrivateLeafState;
}

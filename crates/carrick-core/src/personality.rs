//! Neutral operating system personality interface.

use carrick_guest_arch::{
    Access, CopyProgress, DefaultMmOwner, EntryArch, GuestLen, MmuArch, NativeEntrySnapshot,
    NativeReturnWord, ThreadPointerRegister, TransferDirection, UserRange, UserVa,
};
pub use carrick_guest_arch::{EntryDecodeError, ServiceError, UserStackOffset};

pub use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};

/// Typed system call or environment invocation ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct CallOrdinal(u64);

impl CallOrdinal {
    /// Construct a call ordinal from a raw integer.
    pub const fn from_raw(ordinal: u64) -> Self {
        Self(ordinal)
    }

    /// Read the raw integer value of the ordinal.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Neutral thread identity with a generation, preventing ABA / aliasing on recycled IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ThreadKey {
    id: u64,
    generation: u64,
}

impl ThreadKey {
    /// Construct a thread key from an id and generation.
    pub const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }

    /// Read the thread identifier.
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Read the thread generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

impl core::fmt::Display for ThreadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "thread#{}:{}", self.id, self.generation)
    }
}

/// Execution call context provided to [`PersonalityAbi::decode`] to inspect entry frame
/// architectural snapshots and user stack pointers.
pub struct CallContext<'a, A: EntryArch> {
    arch: &'a mut A,
    frame: &'a A::NativeFrame,
}

impl<'a, A: EntryArch> CallContext<'a, A>
where
    EntryDecodeError: From<A::Error>,
{
    /// Create a new call context wrapping the architecture backend and native entry frame.
    pub fn new(arch: &'a mut A, frame: &'a A::NativeFrame) -> Self {
        Self { arch, frame }
    }

    /// Access the native entry frame.
    pub fn frame(&self) -> &A::NativeFrame {
        self.frame
    }

    /// Retrieve the guest user stack pointer for the entry frame.
    pub fn user_stack_pointer(&mut self) -> Result<UserVa, EntryDecodeError> {
        self.arch.user_stack_pointer(self.frame).map_err(Into::into)
    }

    /// Retrieve the architectural register entry snapshot for the entry frame.
    pub fn snapshot(
        &mut self,
    ) -> Result<NativeEntrySnapshot<'a, A::NativeFrame>, EntryDecodeError> {
        self.arch.snapshot(self.frame).map_err(Into::into)
    }
}

impl<'a, A: EntryArch + MmuArch + DefaultMmOwner> CallContext<'a, A>
where
    ServiceError: From<A::Error>,
{
    /// Access user memory for copying data in or out under the architecture's default MM owner.
    pub fn user<'s>(&'s mut self) -> UserMemory<'s, A> {
        UserMemory::new(self.arch)
    }
}

/// Helper trait to convert various range-like or address types into a validated [`UserRange`].
pub trait IntoUserRange {
    /// Convert `self` into a [`UserRange`] given the buffer length in bytes.
    fn into_user_range(self, len: usize) -> Option<UserRange>;
}

impl IntoUserRange for UserRange {
    fn into_user_range(self, len: usize) -> Option<UserRange> {
        if self.len().raw() == len as u64 {
            Some(self)
        } else {
            None
        }
    }
}

impl IntoUserRange for UserVa {
    fn into_user_range(self, len: usize) -> Option<UserRange> {
        UserRange::checked(self, GuestLen::new(len as u64))
    }
}

/// A personality-facing handle for copying data safely and in a bounded manner
/// between host kernel buffers and guest user virtual memory.
pub struct UserMemory<'a, A: MmuArch> {
    arch: &'a mut A,
}

impl<'a, A: MmuArch + DefaultMmOwner> UserMemory<'a, A>
where
    ServiceError: From<A::Error>,
{
    /// Construct a user-memory copy handle using the architecture's default MM owner.
    pub fn new(arch: &'a mut A) -> Self {
        Self { arch }
    }

    fn resolve_owner(&self) -> Result<&'static A::MmOwner, ServiceError> {
        A::default_owner().ok_or(ServiceError::Refused)
    }

    /// Copy bytes from guest user virtual memory into host kernel buffer `dst`.
    ///
    /// `src` can be a [`UserRange`] or [`UserVa`].
    pub fn copy_in(
        &mut self,
        src: impl IntoUserRange,
        dst: &mut [u8],
    ) -> Result<CopyProgress, ServiceError> {
        if dst.is_empty() {
            return Ok(CopyProgress {
                completed: GuestLen::new(0),
                remaining: GuestLen::new(0),
            });
        }
        let range = src
            .into_user_range(dst.len())
            .ok_or(ServiceError::RangeOverflow)?;
        if !range.in_lower_half() {
            return Err(ServiceError::RangeOverflow);
        }
        let owner = self.resolve_owner()?;
        let readable_len = self.arch.validate_user_access(owner, range, Access::Read)?;
        if readable_len.raw() < range.len().raw() {
            return Err(ServiceError::Fault);
        }

        let ptr = core::ptr::NonNull::new(dst.as_mut_ptr()).ok_or(ServiceError::RangeOverflow)?;
        let mut transfer = self.arch.open_user_transfer(
            owner,
            range.start(),
            ptr,
            range.len(),
            TransferDirection::FromUser,
        )?;

        let mut progress = CopyProgress {
            completed: GuestLen::new(0),
            remaining: range.len(),
        };
        while progress.remaining.raw() > 0 {
            let chunk_limit = progress.remaining;
            let step = self.arch.copy_user_chunk(&mut transfer, chunk_limit)?;
            if step.completed.raw() == 0 {
                return Err(ServiceError::Fault);
            }
            progress.completed = GuestLen::new(progress.completed.raw() + step.completed.raw());
            progress.remaining = step.remaining;
        }
        Ok(progress)
    }

    /// Copy bytes from host kernel buffer `src` into guest user virtual memory.
    ///
    /// `dst` can be a [`UserRange`] or [`UserVa`]. Copy-out requires a writable mapping.
    pub fn copy_out(
        &mut self,
        dst: impl IntoUserRange,
        src: &[u8],
    ) -> Result<CopyProgress, ServiceError> {
        if src.is_empty() {
            return Ok(CopyProgress {
                completed: GuestLen::new(0),
                remaining: GuestLen::new(0),
            });
        }
        let range = dst
            .into_user_range(src.len())
            .ok_or(ServiceError::RangeOverflow)?;
        if !range.in_lower_half() {
            return Err(ServiceError::RangeOverflow);
        }
        let owner = self.resolve_owner()?;
        let writable_len = self
            .arch
            .validate_user_access(owner, range, Access::Write)?;
        if writable_len.raw() < range.len().raw() {
            let rem_start = range.start().raw() + writable_len.raw();
            let rem_len = range.len().raw() - writable_len.raw();
            if let Some(rem_range) =
                UserRange::checked(UserVa::new(rem_start), GuestLen::new(rem_len))
            {
                let readable_len = self
                    .arch
                    .validate_user_access(owner, rem_range, Access::Read)
                    .unwrap_or(GuestLen::new(0));
                if readable_len.raw() > 0 {
                    return Err(ServiceError::AccessDenied);
                } else {
                    return Err(ServiceError::Fault);
                }
            } else {
                return Err(ServiceError::RangeOverflow);
            }
        }

        let ptr =
            core::ptr::NonNull::new(src.as_ptr() as *mut u8).ok_or(ServiceError::RangeOverflow)?;
        let mut transfer = self.arch.open_user_transfer(
            owner,
            range.start(),
            ptr,
            range.len(),
            TransferDirection::ToUser,
        )?;

        let mut progress = CopyProgress {
            completed: GuestLen::new(0),
            remaining: range.len(),
        };
        while progress.remaining.raw() > 0 {
            let chunk_limit = progress.remaining;
            let step = self.arch.copy_user_chunk(&mut transfer, chunk_limit)?;
            if step.completed.raw() == 0 {
                return Err(ServiceError::Fault);
            }
            progress.completed = GuestLen::new(progress.completed.raw() + step.completed.raw());
            progress.remaining = step.remaining;
        }
        Ok(progress)
    }

    /// Convenience helper to copy bytes from guest user virtual address `src` into `dst`.
    pub fn copy_in_bytes(
        &mut self,
        src: UserVa,
        dst: &mut [u8],
    ) -> Result<CopyProgress, ServiceError> {
        self.copy_in(src, dst)
    }

    /// Convenience helper to copy bytes from `src` into guest user virtual address `dst`.
    pub fn copy_out_bytes(
        &mut self,
        dst: UserVa,
        src: &[u8],
    ) -> Result<CopyProgress, ServiceError> {
        self.copy_out(dst, src)
    }
}

/// Unified user memory copy trait for personality lifecycle and call servicing.
pub trait UserCopy {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool;
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool;
}

impl<'a, A: MmuArch + DefaultMmOwner> UserCopy for UserMemory<'a, A>
where
    ServiceError: From<A::Error>,
{
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool {
        self.copy_in_bytes(src, dst).is_ok()
    }

    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
        self.copy_out_bytes(dst, src).is_ok()
    }
}

/// Contract for personality-specific entry frame decode and return encoding.
pub trait PersonalityAbi<A: EntryArch>: Send + Sync {
    /// The decoded call representation for this personality.
    type Call;

    /// Decode a system call or environment invocation from the entry frame via `cx`.
    fn decode(&self, cx: &mut CallContext<'_, A>) -> Result<Self::Call, EntryDecodeError>;

    /// Encode an execution result into the native entry frame.
    fn encode_return(
        &self,
        result: NativeReturnWord,
        frame: &mut A::NativeFrame,
    ) -> Result<(), EntryDecodeError>;
}

/// An operating system personality contract for execution context and policy.
pub trait Personality: Send + Sync {
    /// Return the human-readable identifier of this personality.
    fn name(&self) -> &'static str;

    /// The architectural register this personality uses as the thread context / TLS base pointer.
    fn thread_pointer_register(&self) -> ThreadPointerRegister;

    /// The architectural register this personality uses for a specific thread, allowing
    /// personalities to configure thread pointer base registers per task/thread.
    fn thread_pointer_register_for_thread(&self, _thread: ThreadKey) -> ThreadPointerRegister {
        self.thread_pointer_register()
    }

    /// The architectural register this personality uses for a specific task.
    fn thread_pointer_register_for_task(&self, _task: TaskKey) -> ThreadPointerRegister {
        self.thread_pointer_register()
    }
}

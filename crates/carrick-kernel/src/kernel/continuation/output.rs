//! Retained syscall output with exact execution identity and one wait owner.
//! No memory dependency, permit or process-effect custody survives in an
//! operation. Routing consumes the suspension and transfers its dependency.

use super::{CompletionFoldError, GuestOutputRange, owner_wait_cancellation};
use crate::dispatch::{
    CurrentMmMemory, DirectoryReadOutput, DispatchError, DispatchOutcome, FsView,
};
use crate::kernel::objects::{ThreadExecutionLease, ThreadKey};
use crate::kernel::{KernelContext, KernelTaskBinding, MmId};
use carrick_abi::{LINUX_EFAULT, LINUX_EINVAL, LinuxErrno};
use carrick_guest_mem::{GuestVa, MemoryError, MemoryReadWait, OwnedReadContinuation};
use std::collections::VecDeque;
use std::sync::Arc;

/// Exact task incarnation, thread incarnation, MM and independent ASID.
#[derive(Debug)]
pub struct ExactCompletionBinding {
    task: KernelTaskBinding,
    thread: ThreadKey,
    mm: (MmId, u64),
}

impl PartialEq for ExactCompletionBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.task.kernel(), other.task.kernel())
            && self.task.task_key() == other.task.task_key()
            && self.thread == other.thread
            && self.mm == other.mm
    }
}
impl Eq for ExactCompletionBinding {}

impl ExactCompletionBinding {
    pub(crate) fn new(
        context: &KernelContext,
        mm: (MmId, u64),
    ) -> Result<Self, CompletionFoldError> {
        if mm.0 != context.shared().mm().id() {
            return Err(CompletionFoldError::AddressSpace);
        }
        Ok(Self {
            task: context.task_binding(),
            thread: context.thread().key(),
            mm,
        })
    }

    /// Capture before consuming any input, using real execution authority.
    pub(crate) fn capture(
        context: &KernelContext,
        lease: Option<&ThreadExecutionLease>,
    ) -> Result<Self, CompletionFoldError> {
        let lease = lease.ok_or(CompletionFoldError::ExecutionAuthority)?;
        let mm = context
            .thread()
            .authenticate_task_state_authority(lease)
            .map_err(|_| CompletionFoldError::ExecutionAuthority)?;
        Self::new(context, mm)
    }

    pub(crate) fn memory_identity(&self) -> (MmId, u64) {
        self.mm
    }

    fn authenticate(
        &self,
        context: &KernelContext,
        mm: (MmId, u64),
    ) -> Result<(), CompletionFoldError> {
        if self.thread != context.thread().key() {
            return Err(CompletionFoldError::Thread);
        }
        if !Arc::ptr_eq(self.task.kernel(), context.kernel())
            || self.task.task_key() != context.task().key()
        {
            return Err(CompletionFoldError::Task);
        }
        if self.mm != mm || mm.0 != context.shared().mm().id() {
            return Err(CompletionFoldError::AddressSpace);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CompletionOutputSource {
    Zeroes,
    Record(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
struct CompletedWaitOutput {
    result: Result<i64, LinuxErrno>,
    source: CompletionOutputSource,
    writes: std::collections::VecDeque<GuestOutputRange>,
    offset: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum OutputOperation {
    CompletedWait(CompletedWaitOutput),
    FdWait(FdWaitOutput),
    RecvfromAddress(RecvfromAddress),
    DirectoryRead(DirectoryReadOutput),
}

/// Dependency-free, move-only operation. It never owns a permit or editor.
#[derive(Debug, PartialEq, Eq)]
pub struct RetainedOutputCompletion {
    binding: ExactCompletionBinding,
    operation: OutputOperation,
}

/// One dependency paired with the operation that must resume after settlement.
#[derive(Debug, PartialEq, Eq)]
pub struct SuspendedOutputCompletion {
    operation: RetainedOutputCompletion,
    wait: MemoryReadWait,
}

impl SuspendedOutputCompletion {
    pub fn new(operation: RetainedOutputCompletion, wait: MemoryReadWait) -> Self {
        Self { operation, wait }
    }
    pub fn wait(&self) -> &MemoryReadWait {
        &self.wait
    }
    pub fn into_parts(self) -> (RetainedOutputCompletion, MemoryReadWait) {
        (self.operation, self.wait)
    }
    /// Direct settlement for VM-free callers; runtime routing uses into_parts.
    pub fn resume(
        self,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
        mm: (MmId, u64),
        fs: &FsView<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let (operation, wait) = self.into_parts();
        drop(wait);
        operation.resume(context, memory, mm, fs)
    }
}

impl RetainedOutputCompletion {
    pub(super) fn completed_wait(
        result: Result<i64, LinuxErrno>,
        writes: Vec<GuestOutputRange>,
        context: &KernelContext,
        mm: (MmId, u64),
    ) -> Result<Self, CompletionFoldError> {
        if writes
            .iter()
            .any(|range| (range.mm, range.asid_generation) != mm)
        {
            return Err(CompletionFoldError::AddressSpace);
        }
        Ok(Self {
            binding: ExactCompletionBinding::new(context, mm)?,
            operation: OutputOperation::CompletedWait(CompletedWaitOutput {
                result,
                source: CompletionOutputSource::Zeroes,
                writes: writes.into(),
                offset: 0,
            }),
        })
    }
    pub(super) fn set_source(&mut self, source: CompletionOutputSource) {
        let OutputOperation::CompletedWait(output) = &mut self.operation else {
            unreachable!()
        };
        output.source = source;
    }
    pub(super) fn authenticate_identity(
        &self,
        context: &KernelContext,
        mm: (MmId, u64),
    ) -> Result<(), CompletionFoldError> {
        self.binding.authenticate(context, mm)
    }
    pub(crate) fn recvfrom_address(
        binding: ExactCompletionBinding,
        addrlen: crate::dispatch::GuestPtr,
        received: usize,
    ) -> Self {
        Self {
            binding,
            operation: OutputOperation::RecvfromAddress(RecvfromAddress {
                addrlen,
                received,
                phase: AddressPhase::Start,
            }),
        }
    }
    /// Only completed waits carry a previously settled restart disposition.
    pub fn is_completed_wait(&self) -> bool {
        matches!(
            self.operation,
            OutputOperation::CompletedWait(_)
                | OutputOperation::FdWait(FdWaitOutput {
                    retained_wait: Some(_),
                    ..
                })
        )
    }
    pub fn resume(
        self,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
        mm: (MmId, u64),
        fs: &FsView<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.authenticate_identity(context, mm)
            .map_err(DispatchError::CompletionInvariant)?;
        if let Some(cancelled) = owner_wait_cancellation(context) {
            return Ok(DispatchOutcome::OwnerCancelled(cancelled));
        }
        self.publish(context, memory, fs)
    }
    pub(super) fn publish_initial(
        self,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
        mm: (MmId, u64),
    ) -> Result<DispatchOutcome, CompletionFoldError> {
        self.authenticate_identity(context, mm)?;
        // Legacy timeout output folds before fatal signal delivery. Its first
        // publication keeps that ordering; suspended resumes are killable.
        let OutputOperation::CompletedWait(output) = self.operation else {
            unreachable!("only completed waits use initial publication")
        };
        Ok(output.copyout(self.binding, context, memory))
    }
    pub(crate) fn directory_read(
        binding: ExactCompletionBinding,
        output: DirectoryReadOutput,
    ) -> Self {
        Self {
            binding,
            operation: OutputOperation::DirectoryRead(output),
        }
    }
    fn publish(
        self,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
        fs: &FsView<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.operation {
            OutputOperation::DirectoryRead(output) => {
                output.publish(self.binding, context, fs, memory)
            }
            OutputOperation::CompletedWait(output) => {
                Ok(output.copyout(self.binding, context, memory))
            }
            OutputOperation::FdWait(output) => output
                .publish(Some(self.binding), context, memory)
                .map_err(DispatchError::CompletionInvariant),
            OutputOperation::RecvfromAddress(address) => {
                Ok(address.resume(self.binding, context, memory))
            }
        }
    }
    pub(crate) fn suspend(self, wait: MemoryReadWait) -> DispatchOutcome {
        DispatchOutcome::OutputSuspended(Box::new(SuspendedOutputCompletion::new(self, wait)))
    }
}

/// A terminal readiness selection. The original wait remains owned until
/// publication finishes, including its leases, registrations and deadline.
/// None of that state is consulted again during publication.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FdWaitOutput {
    ready: i64,
    writes: FdWaitWrites,
    retained_wait: Option<crate::dispatch::fd_wait::BlockingFdWait>,
}

#[derive(Debug, PartialEq, Eq)]
enum FdWaitWrites {
    Select {
        sets: VecDeque<(GuestVa, Vec<u8>)>,
        offset: usize,
    },
    /// Input record addresses, with only the result field retained for output.
    Poll(VecDeque<(GuestVa, [u8; 2])>),
}

impl FdWaitWrites {
    fn next_unit(&self) -> Result<Option<(GuestVa, &[u8])>, LinuxErrno> {
        use crate::dispatch::copyout::COPYOUT_MAX_BYTES;
        match self {
            Self::Select { sets, offset } => {
                let Some((base, bytes)) = sets.front() else {
                    return Ok(None);
                };
                let address = base.raw().checked_add(*offset as u64).ok_or(LINUX_EFAULT)?;
                let len = (bytes.len() - offset)
                    .min(COPYOUT_MAX_BYTES - address as usize % COPYOUT_MAX_BYTES);
                Ok(Some((
                    GuestVa::new(address),
                    &bytes[*offset..*offset + len],
                )))
            }
            Self::Poll(entries) => {
                let Some((base, bytes)) = entries.front() else {
                    return Ok(None);
                };
                let address = base
                    .raw()
                    .checked_add(core::mem::offset_of!(carrick_abi::LinuxPollFd, revents) as u64)
                    .ok_or(LINUX_EFAULT)?;
                // A field is one complete unit, even when it crosses a page.
                Ok(Some((GuestVa::new(address), bytes)))
            }
        }
    }

    fn advance(&mut self, len: usize) {
        match self {
            Self::Select { sets, offset } => {
                *offset += len;
                if sets
                    .front()
                    .is_some_and(|(_, bytes)| *offset == bytes.len())
                {
                    sets.pop_front();
                    *offset = 0;
                }
            }
            Self::Poll(entries) => {
                entries.pop_front();
            }
        }
    }
}

impl FdWaitOutput {
    pub(crate) fn select(
        ready: i64,
        sets: Vec<(GuestVa, Vec<u8>)>,
        retained_wait: Option<crate::dispatch::fd_wait::BlockingFdWait>,
    ) -> Self {
        Self {
            ready,
            writes: FdWaitWrites::Select {
                sets: sets
                    .into_iter()
                    .filter(|(_, bytes)| !bytes.is_empty())
                    .collect(),
                offset: 0,
            },
            retained_wait,
        }
    }

    pub(crate) fn poll(
        ready: i64,
        entries: Vec<(GuestVa, i16)>,
        retained_wait: crate::dispatch::fd_wait::BlockingFdWait,
    ) -> Self {
        Self {
            ready,
            writes: FdWaitWrites::Poll(
                entries
                    .into_iter()
                    .map(|(address, revents)| (address, revents.to_ne_bytes()))
                    .collect(),
            ),
            retained_wait: Some(retained_wait),
        }
    }

    /// Both memory venues use this publisher. Legacy memory cannot suspend;
    /// owner memory must have exact authority captured before its inputs.
    pub(crate) fn publish(
        mut self,
        binding: Option<ExactCompletionBinding>,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, CompletionFoldError> {
        use crate::dispatch::copyout::{UserSlot, prepare};
        if let Some(binding) = &binding {
            binding.authenticate(context, binding.memory_identity())?;
        } else if memory.user_memory_venue() == carrick_guest_mem::UserMemoryVenue::Owner {
            return Err(CompletionFoldError::ExecutionAuthority);
        }
        loop {
            let (address, bytes) = match self.writes.next_unit() {
                Ok(Some(unit)) => unit,
                Ok(None) => return Ok(DispatchOutcome::Returned { value: self.ready }),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let len = bytes.len();
            let output = match prepare(context, memory, [Some(UserSlot::new(address.raw(), len))]) {
                Ok(output) => output,
                Err(refusal) => {
                    return Ok(refusal.retain(RetainedOutputCompletion {
                        binding: binding.ok_or(CompletionFoldError::ExecutionAuthority)?,
                        operation: OutputOperation::FdWait(self),
                    }));
                }
            };
            if let Err(fault) = output.commit([bytes]) {
                return Ok(fault.outcome());
            }
            self.writes.advance(len);
        }
    }
}

impl CompletedWaitOutput {
    fn copyout(
        mut self,
        binding: ExactCompletionBinding,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        use crate::dispatch::copyout::{COPYOUT_MAX_BYTES, UserSlot, prepare};
        const ZEROES: &[u8; COPYOUT_MAX_BYTES] = &[0; COPYOUT_MAX_BYTES];
        while let Some(range) = self.writes.front().copied() {
            let address = range.start().raw() + self.offset as u64;
            // One portal-sized interval and one permit per bounded effect.
            let len = (range.len() - self.offset)
                .min(COPYOUT_MAX_BYTES - (address as usize % COPYOUT_MAX_BYTES));
            let output = match prepare(context, memory, [Some(UserSlot::new(address, len))]) {
                Ok(output) => output,
                Err(refusal) => {
                    return refusal.retain(RetainedOutputCompletion {
                        binding,
                        operation: OutputOperation::CompletedWait(self),
                    });
                }
            };
            let bytes = match &self.source {
                CompletionOutputSource::Zeroes => &ZEROES[..len],
                CompletionOutputSource::Record(bytes) => &bytes[self.offset..self.offset + len],
            };
            if let Err(fault) = output.commit([bytes]) {
                return fault.outcome();
            }
            self.offset += len;
            if self.offset == range.len() {
                self.writes.pop_front();
                self.offset = 0;
            }
        }
        match self.result {
            Ok(value) => DispatchOutcome::Returned { value },
            Err(errno) => DispatchOutcome::Errno { errno },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AddressPhase {
    Start,
    Read(OwnedReadContinuation),
    Write,
}

/// Payload has already been published; no socket or fd is retained or replayed.
#[derive(Debug, PartialEq, Eq)]
struct RecvfromAddress {
    addrlen: crate::dispatch::GuestPtr,
    received: usize,
    phase: AddressPhase,
}

impl RecvfromAddress {
    fn resume(
        mut self,
        binding: ExactCompletionBinding,
        context: &KernelContext,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        if !matches!(self.phase, AddressPhase::Write) {
            if self.addrlen.0 == 0 {
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
            let result = match self.phase {
                AddressPhase::Read(continuation) => memory.resume_read(continuation),
                AddressPhase::Start => memory.read_bytes(self.addrlen.0, 4),
                AddressPhase::Write => unreachable!(),
            };
            let bytes = match result {
                Ok(bytes) => bytes,
                Err(MemoryError::ReadSuspended(suspension)) => {
                    self.phase = AddressPhase::Read(suspension.continuation);
                    return RetainedOutputCompletion {
                        binding,
                        operation: OutputOperation::RecvfromAddress(self),
                    }
                    .suspend(suspension.wait);
                }
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            };
            let Ok(bytes) = <[u8; 4]>::try_from(bytes.as_slice()) else {
                return DispatchOutcome::errno(LINUX_EFAULT);
            };
            if i32::from_ne_bytes(bytes) < 0 {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            self.phase = AddressPhase::Write;
        }
        use crate::dispatch::copyout::{UserSlot, prepare};
        // This metadata record remains ONE prepared unit, including page crossing.
        let output = match prepare(context, memory, [Some(UserSlot::new(self.addrlen.0, 4))]) {
            Ok(output) => output,
            Err(refusal) => {
                return refusal.retain(RetainedOutputCompletion {
                    binding,
                    operation: OutputOperation::RecvfromAddress(self),
                });
            }
        };
        match output.commit([&0u32.to_ne_bytes()]) {
            Ok(()) => DispatchOutcome::returned_len(self.received)
                .unwrap_or_else(|_| DispatchOutcome::errno(LINUX_EINVAL)),
            Err(fault) => fault.outcome(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use crate::dispatch::copyout::owner_fixture::OwnerRefusingMemory;
    use carrick_guest_mem::GuestVa;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn fd_wait_initial_publication_authenticates_before_preparing() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let other = SyscallDispatcher::new();
        let other = other.capture_one_task_context().unwrap();
        let mm = (context.shared().mm().id(), 41);
        let mut memory = OwnerRefusingMemory::new(0x7000, 8, 0xa5);
        let output = || FdWaitOutput::select(1, vec![(GuestVa::new(0x7000), vec![1; 8])], None);
        assert_eq!(
            output().publish(None, &context, &mut memory),
            Err(CompletionFoldError::ExecutionAuthority)
        );
        assert!(
            output()
                .publish(
                    Some(ExactCompletionBinding::new(&context, mm).unwrap()),
                    &other,
                    &mut memory
                )
                .is_err()
        );
        assert_eq!(memory.prepares, 0);
        assert_eq!(memory.reads.get(), 0);
        assert!(memory.commits.is_empty());
    }

    #[test]
    fn fd_wait_output_retains_original_deadline_and_wait_authority() {
        use crate::dispatch::fd_wait::{BlockingFdWait, BlockingFdWaitKind};
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let deadline = std::time::Instant::now();
        let wait = BlockingFdWait::new(
            BlockingFdWaitKind::Poll {
                entries: Vec::new(),
            },
            Some(deadline),
            crate::dispatch::WaitFds::empty(),
        )
        .unwrap();
        let authority = wait.authority().clone();
        let registrations = wait.registrations().clone();
        let mm = (context.shared().mm().id(), 41);
        let mut memory = OwnerRefusingMemory::new(0x7000, 8, 0xa5);
        memory.refuse_next();
        let outcome = FdWaitOutput::poll(0, vec![(GuestVa::new(0x7000), 0)], wait)
            .publish(
                Some(ExactCompletionBinding::new(&context, mm).unwrap()),
                &context,
                &mut memory,
            )
            .unwrap();
        let DispatchOutcome::OutputSuspended(pending) = outcome else {
            panic!("must suspend")
        };
        let (operation, dependency) = pending.into_parts();
        let OutputOperation::FdWait(output) = &operation.operation else {
            panic!("fd output")
        };
        let wait = output.retained_wait.as_ref().unwrap();
        assert_eq!(wait.caller_deadline(), Some(deadline));
        assert_eq!(wait.authority(), &authority);
        assert!(Arc::ptr_eq(wait.registrations(), &registrations));
        drop(dependency);
        assert_eq!(
            operation
                .resume(&context, &mut memory, mm, &dispatcher.fs_view())
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(memory.prepares, 2);
        assert_eq!(memory.commits, [(0x7006, vec![0; 2])]);
    }

    #[test]
    fn retained_output_authenticates_task_even_when_thread_key_matches() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let other = SyscallDispatcher::new();
        let other = other.capture_one_task_context().unwrap();
        let mm = (context.shared().mm().id(), 41);
        let mut operation = RetainedOutputCompletion::completed_wait(
            Ok(7),
            vec![GuestOutputRange::new(GuestVa::new(0x7000), 4, mm.0, mm.1).unwrap()],
            &context,
            mm,
        )
        .unwrap();
        // Model a colliding thread key across independent kernels. Even a key
        // collision cannot substitute for exact task/kernel authentication.
        operation.binding.thread = other.thread().key();
        let mut memory = OwnerRefusingMemory::new(0x7000, 4, 0xa5);
        assert!(matches!(
            operation.resume(&other, &mut memory, mm, &dispatcher.fs_view()),
            Err(DispatchError::CompletionInvariant(
                CompletionFoldError::Task
            ))
        ));
        assert_eq!(memory.prepares, 0);
        assert_eq!(memory.reads.get(), 0);
        assert!(memory.commits.is_empty());
    }

    #[derive(Debug)]
    struct Dependency(Arc<AtomicBool>);
    impl Drop for Dependency {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    impl carrick_guest_mem::PhysicalMemoryWait for Dependency {
        fn is_ready(&self) -> bool {
            true
        }
        fn enroll(
            &self,
            _: Arc<dyn Fn() + Send + Sync>,
        ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
            (Box::new(()), true)
        }
    }

    #[test]
    fn suspension_split_transfers_the_only_dependency_reference() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let mm = (context.shared().mm().id(), 41);
        let operation = RetainedOutputCompletion::completed_wait(
            Ok(7),
            vec![GuestOutputRange::new(GuestVa::new(0x7000), 4, mm.0, mm.1).unwrap()],
            &context,
            mm,
        )
        .unwrap();
        let released = Arc::new(AtomicBool::new(false));
        let suspension = SuspendedOutputCompletion::new(
            operation,
            MemoryReadWait::Physical(carrick_guest_mem::OwnedMemoryWait(Arc::new(Dependency(
                released.clone(),
            )))),
        );
        let (operation, wait) = suspension.into_parts();
        assert!(!released.load(Ordering::Acquire));
        drop(wait);
        assert!(
            released.load(Ordering::Acquire),
            "operation retained a second dependency"
        );
        let mut memory = OwnerRefusingMemory::new(0x7000, 4, 0xa5);
        assert_eq!(
            operation
                .resume(&context, &mut memory, mm, &dispatcher.fs_view())
                .unwrap(),
            DispatchOutcome::Returned { value: 7 }
        );
        assert_eq!(memory.prepares, 1);
        assert_eq!(memory.commits, [(0x7000, vec![0; 4])]);
    }
}

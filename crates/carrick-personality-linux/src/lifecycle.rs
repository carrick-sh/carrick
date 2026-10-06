//! Linux lifecycle policy over neutral pool transitions and native context hooks.
use crate::abi::entry::SyscallResult;
use crate::abi::thread::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCall {
    Exit,
    SigAltStack,
    SigProcMask,
    SetRobustList,
    GetTid,
    Clone,
    Fork,
    Wait4,
    ExitGroup,
}

/// A primitive returns data, never an entry completion or a final frame write.
pub enum LifecycleOutcome {
    Returned {
        result: SyscallResult,
        work: bool,
    },
    Transferred {
        progress: carrick_core_abi::Served,
        result: SyscallResult,
    },
}

pub fn lifecycle_effect(outcome: &LifecycleOutcome) -> crate::dispatch::FamilyCompletion {
    use crate::dispatch::FamilyCompletion;
    match *outcome {
        LifecycleOutcome::Returned { result, work: true } => {
            FamilyCompletion::CompleteWithWork(result.raw())
        }
        LifecycleOutcome::Returned {
            result,
            work: false,
        } => FamilyCompletion::Complete(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Returned { .. },
            result,
        } => FamilyCompletion::Switched(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Idle,
            ..
        } => FamilyCompletion::Suspended,
    }
}

use crate::thread::*;
use carrick_core::Served;
use carrick_core_abi::EntryMmKey;
use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::UserVa;
use carrick_sched_core::{RecordRef, ThreadIdentity};
use core::sync::atomic::Ordering;

pub trait UserCopy {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool;
    fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool;
}

pub struct ChildContext {
    pub result: SyscallResult,
    pub stack: UserVa,
    pub tls: Option<UserVa>,
    pub visible_tid: u32,
}

pub struct ExitRecord {
    pub reference: RecordRef,
    pub identity: ThreadIdentity,
    pub home: bool,
    pub unadopted: bool,
    pub on_cpu: bool,
    pub needs_host: bool,
    pub cancelled: bool,
    pub object_operation: bool,
}

/// ISA hooks acquire retained metadata and move real native context. They do
/// not route, validate clone flags, lower errno or publish entry completion.
pub trait LifecycleNative<'a>: UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn binding(&self) -> Option<ExecutionBinding>;
    fn task_state(&self) -> Option<&'a crate::abi::entry::LinuxTaskState>;
    fn register_robust_list(&self, head: u64, len: u64) -> Option<SyscallResult> {
        let thread = self.thread()?;
        set_robust_list(
            thread.page,
            RobustListSlot::new(thread.slot, None),
            RobustListHead::new(head),
            RobustListLen::new(len),
        )
        .linux_result()
        .map(SyscallResult::new)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>>;
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: EntryRef,
    ) -> Option<&'a ThreadControlSlot>;
    fn record_decline(&self, reason: LifecycleDecline);
    fn has_scheduler(&self) -> bool;
    fn user_sp(&mut self) -> Option<UserVa>;
    fn affinity(&self) -> Option<u64>;
    fn allocate_record(
        &mut self,
        identity: ThreadIdentity,
    ) -> Result<RecordRef, carrick_sched_core::Exhausted>;
    fn free_record(&mut self, record: RecordRef);
    /// ISA-only context availability, checked before any output or pool claim.
    fn can_prepare_child(&self, _: UserVa, _: Option<UserVa>) -> bool {
        true
    }
    fn prepare_child(&mut self, record: RecordRef, context: ChildContext);
    fn enqueue_born(&mut self, record: RecordRef);
    fn exit_record(&self) -> Option<ExitRecord>;
    fn wake_child_tid(&mut self, mm: EntryMmKey, address: UserVa) -> bool;
    fn release_current(&mut self, record: RecordRef) -> bool;
    fn run_next(&mut self, timeout_result: SyscallResult) -> (Served, SyscallResult);
    fn result(&self) -> SyscallResult;
    fn set_result(&mut self, result: SyscallResult);
    /// Native custody for a process fork. The shared owner selects this only
    /// for an x86 process call with an admitted guest process venue.
    fn process_fork(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    fn process_wait4(
        &mut self,
        _pid: u64,
        _status: UserVa,
        _options: u64,
    ) -> Option<LifecycleOutcome> {
        None
    }
    fn process_exit_group(&mut self, _status: u8) -> Option<LifecycleOutcome> {
        None
    }
}
/// Linux aarch64 syscall numbers served here (`SYS_SET_ROBUST_LIST` is the
/// shared canonical number from [`crate::thread`]).
pub const SYS_EXIT: usize = 93;
pub const SYS_SIGALTSTACK: usize = 132;
pub const SYS_RT_SIGPROCMASK: usize = 135;
pub const SYS_GETTID: usize = 178;
pub const SYS_CLONE: usize = 220;

// clone(2) flags.
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// Ignored by Linux (clone(2): "historical"), so serving it changes nothing;
/// musl's `pthread_create` passes it.
const CLONE_DETACHED: u64 = 0x0040_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// The low byte: the child's exit signal. A thread has none.
const CSIGNAL: u64 = 0xff;

/// Every flag a libc or Go thread creation passes.
const THREAD_CLONE_REQUIRED: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
/// The flags a libc thread creation may add.
const THREAD_CLONE_OPTIONAL: u64 =
    CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED;

// rt_sigprocmask(2).
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;
/// `sizeof(kernel sigset_t)` on arm64.
const RT_SIGSET_SIZE: u64 = 8;
/// SIGKILL (9) and SIGSTOP (19) as mask bits (`signum - 1`): Linux drops
/// them from every mask a thread installs.
const UNBLOCKABLE: u64 = 0x0004_0100;

// sigaltstack(2).
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const MINSIGSTKSZ: u64 = 2048;
/// `sizeof(stack_t)` on arm64: `ss_sp`, `ss_flags` (+4 pad), `ss_size`.
const STACK_T_SIZE: usize = 24;

/// `stack_t` as its three little-endian 64-bit words: `ss_sp`, `ss_flags`
/// in the low half of the second (the pad is zero), `ss_size`.
fn stack_t_words(bytes: &[u8; STACK_T_SIZE]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(chunk);
        *word = u64::from_le_bytes(raw);
    }
    words
}

fn stack_t_bytes(words: [u64; 3]) -> [u8; STACK_T_SIZE] {
    let mut bytes = [0u8; STACK_T_SIZE];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Whether `nr` is a call this module may serve.
pub const fn is_lifecycle_syscall(nr: usize) -> bool {
    matches!(
        nr,
        SYS_EXIT
            | SYS_SET_ROBUST_LIST
            | SYS_SIGALTSTACK
            | SYS_RT_SIGPROCMASK
            | SYS_GETTID
            | SYS_CLONE
    )
}

/// Execute Linux policy, leaving ordinary result installation and completion
/// publication to the authenticated entry owner.
pub fn invoke<'a>(
    call: LifecycleCall,
    native: &mut dyn LifecycleNative<'a>,
) -> Option<LifecycleOutcome> {
    let args = native.arguments();
    let returned = |result, work| LifecycleOutcome::Returned { result, work };
    if call == LifecycleCall::SetRobustList {
        return Some(returned(
            native.register_robust_list(args[0], args[1])?,
            false,
        ));
    }
    match call {
        LifecycleCall::Fork => return native.process_fork(),
        LifecycleCall::Wait4 => {
            return native.process_wait4(args[0], UserVa::new(args[1]), args[2]);
        }
        LifecycleCall::ExitGroup => return native.process_exit_group(args[0] as u8),
        _ => {}
    }
    let thread = native.thread().or_else(|| {
        if call == LifecycleCall::Exit {
            native.record_decline(LifecycleDecline::ExitVenue);
        }
        None
    })?;
    match call {
        LifecycleCall::GetTid => {
            if !thread.page.serves_threads() {
                return None;
            }
            Some(returned(
                SyscallResult::new(i64::from(thread.slot.visible_tid()?)),
                false,
            ))
        }
        LifecycleCall::SigProcMask => {
            let work = serve_sigprocmask(args, thread, native)?;
            Some(returned(SyscallResult::new(0), work))
        }
        LifecycleCall::SigAltStack => {
            let sp = native.user_sp().map(UserVa::raw);
            serve_sigaltstack(args, thread, native, sp)?;
            Some(returned(SyscallResult::new(0), false))
        }
        LifecycleCall::Clone => {
            let visible = serve_clone(args, thread, native)?;
            Some(returned(SyscallResult::new(i64::from(visible)), false))
        }
        LifecycleCall::Exit => {
            if !native.has_scheduler() {
                native.record_decline(LifecycleDecline::ExitScheduler);
                return None;
            }
            let (progress, result) = serve_exit(thread, native)?;
            Some(LifecycleOutcome::Transferred {
                progress,
                result: SyscallResult::new(result),
            })
        }
        _ => None,
    }
}

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)`. `Some(work)`: served
/// (result 0); `work` when a pending signal may now be deliverable to this
/// thread, or must move to a sibling because this thread just blocked it.
pub fn serve_sigprocmask(
    args: [u64; 6],
    thread: LifecycleThread<'_>,
    user: &mut (impl UserCopy + ?Sized),
) -> Option<bool> {
    let [how, set, oldset, size] = [args[0], args[1], args[2], args[3]];
    if !setup_open(thread.page) || size != RT_SIGSET_SIZE {
        return None;
    }
    // Linux reads the new set before it writes the old one; the host lane
    // writes first. An aliased pair would see two answers: the host decides.
    if set != 0 && oldset != 0 && ranges_overlap(set, RT_SIGSET_SIZE, oldset, RT_SIGSET_SIZE) {
        return None;
    }
    // The owning thread is the only writer of its mask.
    let old = thread.slot.blocked();
    let new = if set != 0 {
        let mut bytes = [0u8; 8];
        if !user.copy_in(&mut bytes, UserVa::new(set)) {
            return None;
        }
        let bits = u64::from_le_bytes(bytes);
        let mask = match how {
            SIG_BLOCK => old.0 | bits,
            SIG_UNBLOCK => old.0 & !bits,
            SIG_SETMASK => bits,
            _ => return None,
        };
        Some(BlockedMask(mask & !UNBLOCKABLE))
    } else {
        None
    };
    if oldset != 0 && !user.copy_out(UserVa::new(oldset), &old.0.to_le_bytes()) {
        return None;
    }
    let Some(new) = new else {
        return Some(false);
    };
    let (prev, pending) = thread
        .slot
        .store_blocked_then_read_pending(new, thread.slot.pending());
    let pending = pending.0 | thread.page.pending().load().0;
    let deliverable = pending & !new.0;
    let newly_blocked = pending & new.0 & !prev.0;
    Some(deliverable | newly_blocked != 0)
}

/// `sigaltstack(ss, old_ss)`. `sp` is the caller's stack pointer, when
/// known. Served only when the caller is certainly not running on its
/// alternate stack (the host decides that case: it tracks handler frames).
fn serve_sigaltstack(
    args: [u64; 6],
    thread: LifecycleThread<'_>,
    user: &mut (impl UserCopy + ?Sized),
    sp: Option<u64>,
) -> Option<()> {
    let [ss, old_ss] = [args[0], args[1]];
    if !setup_open(thread.page) {
        return None;
    }
    let size = STACK_T_SIZE as u64;
    if ss != 0 && old_ss != 0 && ranges_overlap(ss, size, old_ss, size) {
        return None;
    }
    let current = thread.slot.read_altstack();
    if !current.is_disabled() {
        let sp = sp?;
        let top = current.sp.checked_add(current.size)?;
        if sp > current.sp && sp <= top {
            return None;
        }
    }
    let replacement = if ss != 0 {
        let mut bytes = [0u8; STACK_T_SIZE];
        if !user.copy_in(&mut bytes, UserVa::new(ss)) {
            return None;
        }
        let [sp, flags, size] = stack_t_words(&bytes);
        let flags = flags as u32;
        if flags & !SS_DISABLE != 0 {
            return None;
        }
        if flags & SS_DISABLE != 0 {
            Some(AltStack::DISABLED)
        } else {
            let stack = AltStack { sp, size, flags };
            if stack.size < MINSIGSTKSZ {
                return None;
            }
            Some(stack)
        }
    } else {
        None
    };
    if old_ss != 0 {
        let (sp, flags, size) = if current.is_disabled() {
            (0, SS_DISABLE, 0)
        } else {
            // Not on the alternate stack (checked above): no SS_ONSTACK.
            (current.sp, current.flags & !SS_ONSTACK, current.size)
        };
        if !user.copy_out(
            UserVa::new(old_ss),
            &stack_t_bytes([sp, u64::from(flags), size]),
        ) {
            return None;
        }
    }
    if let Some(stack) = replacement {
        thread.slot.write_altstack(stack);
    }
    Some(())
}

/// The preimage of one clone tid output (`CloneTidOutputTransaction`): the
/// word the copyout replaces, restored if the clone backs out.
struct TidOutput {
    address: u64,
    preimage: [u8; 4],
}

impl TidOutput {
    fn capture(address: u64, user: &mut (impl UserCopy + ?Sized)) -> Option<Option<Self>> {
        if address == 0 {
            return Some(None);
        }
        let mut preimage = [0u8; 4];
        user.copy_in(&mut preimage, UserVa::new(address))
            .then_some(Some(Self { address, preimage }))
    }
}

/// The parent and child tid outputs of one clone, published and rolled back
/// together, exactly as the host lane does: the parent word first, then the
/// child word; if either copyout fails, every written word gets its preimage
/// back (and the host lane then answers the forwarded clone, EFAULT included).
struct TidOutputs {
    parent: Option<TidOutput>,
    child: Option<TidOutput>,
}

impl TidOutputs {
    fn publish(&self, visible_tid: u32, user: &mut (impl UserCopy + ?Sized)) -> bool {
        let bytes = visible_tid.to_le_bytes();
        let Some(parent) = &self.parent else {
            return self.publish_child(&bytes, user);
        };
        if !user.copy_out(UserVa::new(parent.address), &bytes) {
            return false;
        }
        if self.publish_child(&bytes, user) {
            return true;
        }
        let _ = user.copy_out(UserVa::new(parent.address), &parent.preimage);
        false
    }

    fn publish_child(&self, bytes: &[u8; 4], user: &mut (impl UserCopy + ?Sized)) -> bool {
        self.child
            .as_ref()
            .is_none_or(|child| user.copy_out(UserVa::new(child.address), bytes))
    }

    fn rollback(&self, user: &mut (impl UserCopy + ?Sized)) {
        for output in [&self.parent, &self.child].into_iter().flatten() {
            let _ = user.copy_out(UserVa::new(output.address), &output.preimage);
        }
    }
}

/// `clone(flags, stack, parent_tid, tls, child_tid)` creating a thread.
/// `Some(visible tid)`: the child is born and queued.
fn serve_clone<'a>(
    args: [u64; 6],
    thread: LifecycleThread<'a>,
    native: &mut dyn LifecycleNative<'a>,
) -> Option<u32> {
    if !native.has_scheduler() {
        return None;
    }
    let [flags, stack, parent_tid, tls, child_tid] = [args[0], args[1], args[2], args[3], args[4]];
    let page = thread.page;
    if !page.serves_threads()
        || flags & CSIGNAL != 0
        || flags & THREAD_CLONE_REQUIRED != THREAD_CLONE_REQUIRED
        || flags & !(THREAD_CLONE_REQUIRED | THREAD_CLONE_OPTIONAL) != 0
        || stack == 0
    {
        return None;
    }
    let placement_stack = UserVa::new(stack);
    let placement_tls = (flags & CLONE_SETTLS != 0).then_some(UserVa::new(tls));
    if !native.can_prepare_child(placement_stack, placement_tls) {
        return None;
    }
    let binding = native.binding()?;
    let mm = binding.mm.raw();
    if mm == 0 {
        return None;
    }
    let flag = |bit: u64, address: u64| if flags & bit != 0 { address } else { 0 };
    let clear_child_tid = flag(CLONE_CHILD_CLEARTID, child_tid);
    let outputs = TidOutputs {
        parent: TidOutput::capture(flag(CLONE_PARENT_SETTID, parent_tid), native)?,
        child: TidOutput::capture(flag(CLONE_CHILD_SETTID, child_tid), native)?,
    };

    let state = native.task_state()?;
    let affinity = native.affinity()?;
    let claimed = page
        .claim_any()
        .inspect_err(|error| {
            if *error == TransitionError::PoolEmpty {
                native.record_decline(LifecycleDecline::ClonePoolEmpty);
            }
        })
        .ok()?;
    let entry = claimed.entry();
    // Bound at the clone instant (director ruling 2): the caller's mask and
    // affinity as they are now.
    let blocked = thread.slot.blocked();
    let (Some(identity), Some(child_slot)) = (page.identity(entry), native.born_slot(page, entry))
    else {
        let _ = page.unclaim(claimed);
        return None;
    };
    let Ok(visible) = i32::try_from(identity.visible_tid) else {
        let _ = page.unclaim(claimed);
        return None;
    };
    if !child_slot.publish_visible_tid(identity.visible_tid) {
        let _ = page.unclaim(claimed);
        return None;
    }
    let Ok(record) = native.allocate_record(ThreadIdentity {
        tid: u64::from(identity.tid),
        serial: identity.thread_serial,
        mm,
        file_table: state.file_table.load(Ordering::Acquire),
        // The host binds the child's execution generation at adoption.
        generation: 0,
        affinity,
        lifecycle_page: core::ptr::from_ref(page).addr() as u64,
        control_slot: core::ptr::from_ref(child_slot).addr() as u64,
    }) else {
        // Exhausted: the identity goes back to the pool, the host clones.
        let _ = page.unclaim(claimed);
        return None;
    };
    if !outputs.publish(identity.visible_tid, native) {
        native.free_record(record);
        let _ = page.unclaim(claimed);
        return None;
    }

    if page.thread_born().is_none() {
        outputs.rollback(native);
        native.free_record(record);
        let _ = page.unclaim(claimed);
        return None;
    }

    // Native context installation happens only while the new record is unpublished.
    native.prepare_child(
        record,
        ChildContext {
            result: SyscallResult::new(0),
            stack: placement_stack,
            tls: placement_tls,
            visible_tid: identity.visible_tid,
        },
    );
    child_slot.reset_for_birth(blocked, clear_child_tid, entry);
    let born = BornRecord {
        caller_task: binding.task.raw(),
        caller_serial: binding.thread_generation.raw(),
        clone_flags: flags,
        clear_child_tid,
        blocked,
    };
    if page.record_born(claimed, born).is_err() {
        // Unreachable: only this claimant moves a Claimed entry.
        let _ = page.try_exit();
        outputs.rollback(native);
        native.free_record(record);
        return None;
    }
    native.enqueue_born(record);
    Some(visible as u32)
}

/// `exit(status)` of a non-leader thread that EL1 switched in, when it is
/// not the last thread: `Some` with how the vCPU goes on.
fn serve_exit<'a>(
    thread: LifecycleThread<'a>,
    native: &mut dyn LifecycleNative<'a>,
) -> Option<(Served, i64)> {
    let (page, slot) = (thread.page, thread.slot);
    macro_rules! decline {
        ($reason:expr) => {{
            native.record_decline($reason);
            None
        }};
    }
    if !page.serves_threads() {
        return decline!(LifecycleDecline::ExitDisabled);
    }
    if page.gate() != GateState::Open {
        return decline!(LifecycleDecline::ExitGate);
    }
    // The leader holds no pool entry.
    let entry = slot.entry().or_else(|| {
        native.record_decline(LifecycleDecline::ExitNoEntry);
        None
    })?;
    if !matches!(
        page.state(entry.index()),
        Some((generation, EntryState::Born | EntryState::Published))
            if generation == entry.generation()
    ) {
        return decline!(LifecycleDecline::ExitEntryState);
    }
    // No robust-list walker exists yet (it will live in sched-core, shared
    // with the host lane): a registered list is walked by nobody here.
    if slot.robust_list().0 != 0 {
        return decline!(LifecycleDecline::ExitRobust);
    }
    // A pending signal is delivered (or re-targeted) by the host.
    if page.pending().load().0 != 0 || slot.pending().load().0 != 0 {
        return decline!(LifecycleDecline::ExitPending);
    }
    let binding = native.binding()?;
    let mm = binding.mm.raw();
    let record = native.exit_record().or_else(|| {
        native.record_decline(LifecycleDecline::ExitNoCurrent);
        None
    })?;
    if mm == 0 {
        return decline!(LifecycleDecline::ExitNoMm);
    }
    if record.home {
        return decline!(LifecycleDecline::ExitHome);
    }
    // An adopted job's terminal completion stays with its retained runtime owner.
    if !record.unadopted {
        return decline!(LifecycleDecline::ExitHostAdopted);
    }
    if !record.on_cpu {
        return decline!(LifecycleDecline::ExitClaim);
    }
    if record.needs_host {
        return decline!(LifecycleDecline::ExitHostWork);
    }
    if record.cancelled {
        return decline!(LifecycleDecline::ExitCancelled);
    }
    if record.object_operation {
        return decline!(LifecycleDecline::ExitObjectOperation);
    }
    if record.identity.tid != binding.task.raw() {
        return decline!(LifecycleDecline::ExitIdentity);
    }
    let admission = page
        .begin_exit(entry)
        .inspect_err(|_| {
            native.record_decline(LifecycleDecline::ExitAdmission);
        })
        .ok()?;
    // n > 1 -> n - 1; the last thread exits on the host.
    page.try_exit()
        .inspect_err(|_| {
            native.record_decline(LifecycleDecline::ExitLast);
        })
        .ok()?;
    let clear_child_tid = slot.clear_child_tid();
    if clear_child_tid != 0 {
        let status = native.result();
        let copied = native.copy_out(UserVa::new(clear_child_tid), &CHILD_TID_CLEAR);
        let woken =
            copied && native.wake_child_tid(EntryMmKey::from_raw(mm), UserVa::new(clear_child_tid));
        if !woken {
            // The host exits the thread instead: clearing the word again
            // and waking are idempotent.
            native.set_result(status);
            let _ = page.thread_born();
            return decline!(if copied {
                LifecycleDecline::ExitClearTidWake
            } else {
                LifecycleDecline::ExitClearTidCopyout
            });
        }
    }
    if !native.release_current(record.reference) {
        let _ = page.thread_born();
        return None;
    }
    if admission.commit().is_err() {
        // Unreachable (checked above; only this thread leaves Born or
        // Published that way): the host must look at this process.
        native.task_state()?.mark_pending_host_work();
    }
    Some(native.run_next(SyscallResult::new(crate::sched::ETIMEDOUT_RESULT as i64)))
        .map(|(served, result)| (served, result.raw()))
}

//! Born-in-zone thread lifecycle at EL1 (stage L3 of
//! `docs/superpowers/plans/2026-09-30-el1-thread-lifecycle.md`).
//!
//! EL1 serves, for the running thread of a process whose lifecycle page the
//! host published ([`LifecycleVenue`]):
//!
//! * `clone` with a libc/Go thread flag set: the child takes an identity the
//!   kernel already issued into the page's pool, is born as a zone record
//!   holding the parent's frame, and is queued on this vCPU. The host
//!   publishes the birth at its next settle and adopts the thread at its
//!   first forwarded syscall.
//! * `exit` of a non-leader thread that is not the last one: `CLEARTID` is
//!   cleared and woken, the record freed and the entry marked
//!   `ExitedInZone` for the host to fold.
//! * `rt_sigprocmask`, `sigaltstack`, `set_robust_list` on the thread's
//!   [`ThreadControlSlot`].
//!
//! Every case EL1 cannot answer exactly as the host lane would (an error
//! return, a user copy that faults here, a closed gate, a traced or seccomp
//! process, a full pool) is forwarded with no effect left behind, so the host
//! lane gives the one answer. Nothing here returns an errno.
use super::sched::{ETIMEDOUT_RESULT, Sched, Served, ThreadCpu, UserWord};
use crate::file::UserCopy;
use carrick_el1_abi::{
    Action, AltStack, BlockedMask, BornRecord, Claim, Counters, CurrentTask, El1TaskId, EntryRef,
    EntryState, GateState, LifecycleDecline, ThreadControlSlot, ThreadCtx, ThreadIdentity,
    ThreadLifecyclePage, TransitionError, TrapFrame,
};
use core::sync::atomic::Ordering;

/// Linux aarch64 syscall numbers served here.
pub const SYS_EXIT: usize = 93;
pub const SYS_SET_ROBUST_LIST: usize = 99;
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

/// `sizeof(struct robust_list_head)` on 64-bit Linux.
const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Where EL1 finds the lifecycle state of the thread running on a vCPU. The
/// host (runtime stage L4) publishes it; placement is per process.
pub trait LifecycleVenue {
    /// The lifecycle page of `task`'s process and `task`'s own control
    /// slot, or `None` when EL1 serves no lifecycle call for it.
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>>;
    /// The control slot a thread born into `entry` of `page` will own.
    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot>;
}

/// One running thread's lifecycle state.
#[derive(Clone, Copy)]
pub struct LifecycleThread<'a> {
    pub page: &'a ThreadLifecyclePage,
    pub slot: &'a ThreadControlSlot,
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

/// Serve a lifecycle syscall of the running thread, or `None` to forward it
/// unchanged. `sched` is the vCPU's in-guest scheduler when the process's
/// zone is published (clone and exit need it). Counts what it serves.
pub fn serve<C: ThreadCpu, U: UserWord>(
    frame: &mut TrapFrame,
    counters: &Counters,
    task: &CurrentTask,
    mut sched: Option<Sched<'_, C, U>>,
    venue: &dyn LifecycleVenue,
    user: &mut impl UserCopy,
) -> Option<Action> {
    let nr = frame.x[8] as usize;
    let thread = venue.thread(task).or_else(|| {
        if nr == SYS_EXIT {
            counters.record_lifecycle_decline(LifecycleDecline::ExitVenue);
        }
        None
    })?;
    let orig_x0 = frame.x[0];
    let served = |frame: &mut TrapFrame, result: u64, work: bool| {
        frame.x[0] = result;
        counters.served[nr].fetch_add(1, Ordering::Relaxed);
        task.orig_arg0.store(orig_x0, Ordering::Relaxed);
        if work || task.has_pending_host_work() {
            task.leave_served_with_work()
        } else {
            Action::Served
        }
    };
    match nr {
        SYS_GETTID => {
            if !thread.page.serves_threads() {
                return None;
            }
            Some(served(frame, u64::from(thread.slot.visible_tid()?), false))
        }
        SYS_RT_SIGPROCMASK => {
            let work = serve_sigprocmask(frame, thread, user)?;
            Some(served(frame, 0, work))
        }
        SYS_SIGALTSTACK => {
            let sp = sched.as_mut().map(|sched| user_sp(sched, frame));
            serve_sigaltstack(frame, thread, user, sp)?;
            Some(served(frame, 0, false))
        }
        SYS_SET_ROBUST_LIST => {
            serve_set_robust_list(frame, thread)?;
            Some(served(frame, 0, false))
        }
        SYS_CLONE => {
            let visible = serve_clone(sched.as_mut()?, frame, thread, venue, user, counters)?;
            Some(served(frame, u64::from(visible), false))
        }
        SYS_EXIT => {
            let sched = sched.as_mut().or_else(|| {
                counters.record_lifecycle_decline(LifecycleDecline::ExitScheduler);
                None
            })?;
            let outcome = serve_exit(sched, frame, thread, user, counters)?;
            counters.served[nr].fetch_add(1, Ordering::Relaxed);
            Some(match outcome {
                // The frame is the switched-in thread's, whose own syscall
                // result the switch applied.
                Served::Returned { .. } if task.has_pending_host_work() => {
                    task.leave_served_with_work()
                }
                Served::Returned { .. } => Action::Served,
                Served::Idle => Action::Idle,
            })
        }
        _ => None,
    }
}

/// The running thread's `SP_EL0`.
fn user_sp<C: ThreadCpu, U: UserWord>(sched: &mut Sched<'_, C, U>, frame: &TrapFrame) -> u64 {
    let mut scratch = ThreadCtx::ZERO;
    sched.cpu.save(frame, &mut scratch);
    scratch.sp_el0
}

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}

/// Whether EL1 may serve the per-thread setup calls: the hatch is on and
/// the gate is not terminally closed (a tracer or seccomp must see them).
fn setup_open(page: &ThreadLifecyclePage) -> bool {
    page.serves_sigmask() && page.gate() != GateState::Closed
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)`. `Some(work)`: served
/// (result 0); `work` when a pending signal may now be deliverable to this
/// thread, or must move to a sibling because this thread just blocked it.
fn serve_sigprocmask(
    frame: &TrapFrame,
    thread: LifecycleThread<'_>,
    user: &mut impl UserCopy,
) -> Option<bool> {
    let [how, set, oldset, size] = [frame.x[0], frame.x[1], frame.x[2], frame.x[3]];
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
        if !user.copy_in(&mut bytes, set) {
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
    if oldset != 0 && !user.copy_out(oldset, &old.0.to_le_bytes()) {
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
    frame: &TrapFrame,
    thread: LifecycleThread<'_>,
    user: &mut impl UserCopy,
    sp: Option<u64>,
) -> Option<()> {
    let [ss, old_ss] = [frame.x[0], frame.x[1]];
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
        if !user.copy_in(&mut bytes, ss) {
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
        if !user.copy_out(old_ss, &stack_t_bytes([sp, u64::from(flags), size])) {
            return None;
        }
    }
    if let Some(stack) = replacement {
        thread.slot.write_altstack(stack);
    }
    Some(())
}

/// `set_robust_list(head, len)`: the head goes to the thread's slot, where
/// exit finds it.
fn serve_set_robust_list(frame: &TrapFrame, thread: LifecycleThread<'_>) -> Option<()> {
    let [head, len] = [frame.x[0], frame.x[1]];
    if !setup_open(thread.page) || len != ROBUST_LIST_HEAD_SIZE {
        return None;
    }
    thread
        .slot
        .set_robust_list(head, ROBUST_LIST_HEAD_SIZE as u32);
    Some(())
}

/// The preimage of one clone tid output (`CloneTidOutputTransaction`): the
/// word the copyout replaces, restored if the clone backs out.
struct TidOutput {
    address: u64,
    preimage: [u8; 4],
}

impl TidOutput {
    fn capture(address: u64, user: &mut impl UserCopy) -> Option<Option<Self>> {
        if address == 0 {
            return Some(None);
        }
        let mut preimage = [0u8; 4];
        user.copy_in(&mut preimage, address)
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
    fn publish(&self, visible_tid: u32, user: &mut impl UserCopy) -> bool {
        let bytes = visible_tid.to_le_bytes();
        let Some(parent) = &self.parent else {
            return self.publish_child(&bytes, user);
        };
        if !user.copy_out(parent.address, &bytes) {
            return false;
        }
        if self.publish_child(&bytes, user) {
            return true;
        }
        let _ = user.copy_out(parent.address, &parent.preimage);
        false
    }

    fn publish_child(&self, bytes: &[u8; 4], user: &mut impl UserCopy) -> bool {
        self.child
            .as_ref()
            .is_none_or(|child| user.copy_out(child.address, bytes))
    }

    fn rollback(&self, user: &mut impl UserCopy) {
        for output in [&self.parent, &self.child].into_iter().flatten() {
            let _ = user.copy_out(output.address, &output.preimage);
        }
    }
}

/// `clone(flags, stack, parent_tid, tls, child_tid)` creating a thread.
/// `Some(visible tid)`: the child is born and queued.
fn serve_clone<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &TrapFrame,
    thread: LifecycleThread<'_>,
    venue: &dyn LifecycleVenue,
    user: &mut impl UserCopy,
    counters: &Counters,
) -> Option<u32> {
    let [flags, stack, parent_tid, tls, child_tid] =
        [frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4]];
    let page = thread.page;
    if !page.serves_threads()
        || flags & CSIGNAL != 0
        || flags & THREAD_CLONE_REQUIRED != THREAD_CLONE_REQUIRED
        || flags & !(THREAD_CLONE_REQUIRED | THREAD_CLONE_OPTIONAL) != 0
        || stack == 0
    {
        return None;
    }
    let task = sched.task;
    let mm = task.zone_mm.load(Ordering::Acquire);
    if mm == 0 {
        return None;
    }
    let flag = |bit: u64, address: u64| if flags & bit != 0 { address } else { 0 };
    let clear_child_tid = flag(CLONE_CHILD_CLEARTID, child_tid);
    let outputs = TidOutputs {
        parent: TidOutput::capture(flag(CLONE_PARENT_SETTID, parent_tid), user)?,
        child: TidOutput::capture(flag(CLONE_CHILD_SETTID, child_tid), user)?,
    };

    let claimed = page
        .claim_any()
        .inspect_err(|error| {
            if *error == TransitionError::PoolEmpty {
                counters.record_lifecycle_decline(LifecycleDecline::ClonePoolEmpty);
            }
        })
        .ok()?;
    let entry = claimed.entry();
    // Bound at the clone instant (director ruling 2): the caller's mask and
    // affinity as they are now.
    let blocked = thread.slot.blocked();
    let (zone, slot) = (sched.zone, sched.slot);
    let affinity = match zone.slot(slot).current() {
        Some(record) => zone.record(record).identity().affinity,
        None => zone.slot(slot).affinity(),
    };
    let (Some(identity), Some(child_slot)) = (page.identity(entry), venue.born_slot(page, entry))
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
    let Ok(record) = zone.alloc_record(ThreadIdentity {
        tid: El1TaskId::from_linux_tid(identity.tid as i32).raw(),
        serial: identity.thread_serial,
        mm,
        file_table: task.file_table.load(Ordering::Acquire),
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
    let back_out = |user: &mut _, outputs: Option<&TidOutputs>| {
        if let Some(outputs) = outputs {
            TidOutputs::rollback(outputs, user);
        }
        zone.free_record(record);
    };
    if !outputs.publish(identity.visible_tid, user) {
        back_out(user, None);
        let _ = page.unclaim(claimed);
        return None;
    }

    if page.thread_born().is_none() {
        back_out(user, Some(&outputs));
        let _ = page.unclaim(claimed);
        return None;
    }

    // The child resumes where the parent does, with the parent's registers,
    // clone returning 0, on its own stack and TLS.
    // SAFETY: freshly allocated and unpublished: this vCPU owns it.
    let ctx = unsafe { zone.record(record).ctx_mut() };
    sched.cpu.save(frame, ctx);
    ctx.x[0] = 0;
    ctx.sp_el0 = stack;
    if flags & CLONE_SETTLS != 0 {
        ctx.tpidr_el0 = tls;
    }
    // Preserve the process half of the EL0 vDSO identity and publish the child.
    if ctx.tpidrro_el0 != 0 {
        ctx.tpidrro_el0 = (ctx.tpidrro_el0 & !0xffff_ffff) | u64::from(identity.visible_tid);
    }
    child_slot.reset_for_birth(blocked, clear_child_tid, entry);
    let born = BornRecord {
        caller_task: task.task_id.load(Ordering::Relaxed),
        caller_serial: task.thread_serial.load(Ordering::Relaxed),
        clone_flags: flags,
        clear_child_tid,
        blocked,
    };
    if page.record_born(claimed, born).is_err() {
        // Unreachable: only this claimant moves a Claimed entry.
        let _ = page.try_exit();
        back_out(user, Some(&outputs));
        return None;
    }
    sched.enqueue_born(record);
    Some(visible as u32)
}

/// `exit(status)` of a non-leader thread that EL1 switched in, when it is
/// not the last thread: `Some` with how the vCPU goes on.
fn serve_exit<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    thread: LifecycleThread<'_>,
    user: &mut impl UserCopy,
    counters: &Counters,
) -> Option<Served> {
    let (page, slot) = (thread.page, thread.slot);
    let decline = |reason| {
        counters.record_lifecycle_decline(reason);
        None
    };
    if !page.serves_threads() {
        return decline(LifecycleDecline::ExitDisabled);
    }
    if page.gate() != GateState::Open {
        return decline(LifecycleDecline::ExitGate);
    }
    // The leader holds no pool entry.
    let entry = slot.entry().or_else(|| {
        counters.record_lifecycle_decline(LifecycleDecline::ExitNoEntry);
        None
    })?;
    if !matches!(
        page.state(entry.index()),
        Some((generation, EntryState::Born | EntryState::Published))
            if generation == entry.generation()
    ) {
        return decline(LifecycleDecline::ExitEntryState);
    }
    // No robust-list walker exists yet (it will live in sched-core, shared
    // with the host lane): a registered list is walked by nobody here.
    if slot.robust_list().0 != 0 {
        return decline(LifecycleDecline::ExitRobust);
    }
    // A pending signal is delivered (or re-targeted) by the host.
    if page.pending().load().0 != 0 || slot.pending().load().0 != 0 {
        return decline(LifecycleDecline::ExitPending);
    }
    let task = sched.task;
    let mm = task.zone_mm.load(Ordering::Acquire);
    let (zone, zslot) = (sched.zone, sched.slot);
    // Only a record EL1 switched in: the thread its executor loaded (no
    // record, or the slot's home record) is the executor's to retire.
    let record = zone.slot(zslot).current().or_else(|| {
        counters.record_lifecycle_decline(LifecycleDecline::ExitNoCurrent);
        None
    })?;
    if mm == 0 {
        return decline(LifecycleDecline::ExitNoMm);
    }
    if zone.slot(zslot).host_record() == Some(record) {
        return decline(LifecycleDecline::ExitHome);
    }
    let rec = zone.record(record);
    // Adoption creates a host logical job, even if its zone wait later runs
    // on another slot. ExitedInZone settles the graph and pool custody; it
    // cannot publish that job's terminal completion. Its exit stays with
    // the job owner until that retirement authority can be transferred too.
    if !rec.is_unadopted_birth() {
        return decline(LifecycleDecline::ExitHostAdopted);
    }
    if !matches!(rec.claim(), Claim::OnCpu { slot: owner, .. } if owner == zslot) {
        return decline(LifecycleDecline::ExitClaim);
    }
    if rec.needs_host() {
        return decline(LifecycleDecline::ExitHostWork);
    }
    if rec.is_cancelled() {
        return decline(LifecycleDecline::ExitCancelled);
    }
    if rec.has_object_operation() {
        return decline(LifecycleDecline::ExitObjectOperation);
    }
    if rec.identity().tid != task.task_id.load(Ordering::Relaxed) {
        return decline(LifecycleDecline::ExitIdentity);
    }
    let admission = page
        .begin_exit(entry)
        .inspect_err(|_| {
            counters.record_lifecycle_decline(LifecycleDecline::ExitAdmission);
        })
        .ok()?;
    // n > 1 -> n - 1; the last thread exits on the host.
    page.try_exit()
        .inspect_err(|_| {
            counters.record_lifecycle_decline(LifecycleDecline::ExitLast);
        })
        .ok()?;
    let clear_child_tid = slot.clear_child_tid();
    if clear_child_tid != 0 {
        let status = frame.x[0];
        let copied = user.copy_out(clear_child_tid, &0u32.to_le_bytes());
        let woken = copied
            && sched
                .wake_word(frame, mm, clear_child_tid, u32::MAX, 1)
                .is_some();
        if !woken {
            // The host exits the thread instead: clearing the word again
            // and waking are idempotent.
            frame.x[0] = status;
            let _ = page.thread_born();
            return decline(if copied {
                LifecycleDecline::ExitClearTidWake
            } else {
                LifecycleDecline::ExitClearTidCopyout
            });
        }
    }
    // Checked above: the record holds no object operation (only its own
    // park gives it one), so the release is a plain retirement.
    let _released: carrick_sched_core::CurrentRelease = zone.release_current(
        zslot,
        record,
        &carrick_sched_core::BoundedSpin(carrick_el1_abi::EL1_GUEST_LOCK_SPINS),
    );
    if admission.commit().is_err() {
        // Unreachable (checked above; only this thread leaves Born or
        // Published that way): the host must look at this process.
        task.mark_pending_host_work();
    }
    Some(sched.run_next(frame, ETIMEDOUT_RESULT))
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;

/// Production venue: addresses are EL1-only retained metadata, carried with
/// exact scheduler identity across parks and switches.
pub struct GuestLifecycleVenue;

#[cfg(target_os = "none")]
impl LifecycleVenue for GuestLifecycleVenue {
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
        let (page, slot) = task.lifecycle_refs()?;
        Some(LifecycleThread { page, slot })
    }
    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot> {
        let address = page.control_address(entry)?;
        let end = address.checked_add(core::mem::size_of::<ThreadControlSlot>() as u64)?;
        if address < carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
            || end
                > carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                    + carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE
            || !address.is_multiple_of(core::mem::align_of::<ThreadControlSlot>() as u64)
        {
            return None;
        }
        // SAFETY: the host stocks this address only after reserving executable custody;
        // carrier metadata retains its exact backing across every zone reference.
        Some(unsafe { &*(address as *const ThreadControlSlot) })
    }
}

#[cfg(target_os = "none")]
pub fn guest_venue() -> Option<&'static dyn LifecycleVenue> {
    static VENUE: GuestLifecycleVenue = GuestLifecycleVenue;
    Some(&VENUE)
}
#[cfg(not(target_os = "none"))]
pub fn guest_venue() -> Option<&'static dyn LifecycleVenue> {
    None
}

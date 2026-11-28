//! One idle pass: the order every ISA's idle loop runs (#3061, S2a).
//!
//! An idle CPU repeats [`idle_pass`] until it takes a record or leaves for
//! its host. The order is the lost-wakeup argument, so it lives here once,
//! for ARM's `Sched::idle` and the x86 CPL0 `schedule` alike (#3075 found
//! the x86 copy missing ARM's drain-first and pre-sleep recheck):
//!
//! 1. **Drain** the vectors latched while interrupts were masked. A
//!    reschedule vector carries no state: its sender publishes a condition,
//!    then sends it. Every condition below is read after the drain, so a
//!    condition published after a read still has its vector pending at the
//!    halt, which then returns at once (#3053).
//! 2. **Read** the conditions: the venue's own reasons to leave, expired
//!    timers, the idle scan ([`ZoneTables::take_idle_work`]).
//! 3. **Publish** the slot `IdleWfi` ([`ZoneTables::enter_idle`] with `wfi`
//!    set). From then on a waker that queues here sends a vector.
//! 4. **Recheck** the durable words a wake can leave with no vector that
//!    survives to the halt: pending host work published on a CPU stopped in
//!    a crossing, an owed reschedule ([`ZoneTables::take_resched`]), and the
//!    venue's own owed kicks (an x86 reschedule IPI whose ICR was busy,
//!    #3083). A pass that finds one runs again instead of sleeping.
//! 5. **Halt** (`WFI`, `sti; hlt`), which returns at once on a pending
//!    vector.
//!
//! The ISA mechanics stay in the venue: the drain and halt instructions, the
//! timer, the address-space switch, and everything after a take (the
//! switch-in tail). The venue is a generic parameter, never `dyn`, so each
//! ISA's pass is monomorphised into its own small frame (EL1 and CPL0 stacks
//! are small).

use crate::{OwedPasses, SlotId, SwitchedIn, ZoneTables};

/// A named point in [`idle_pass`] where a test fixture may stop the pass
/// ([`IdleVenue::stop`]). Production venues do nothing there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleStop {
    /// The latched vectors are drained; no condition is read yet.
    AfterDrain,
    /// The timers are expired; the idle scan is next.
    BeforeScan,
    /// The slot is published `IdleWfi`; the final recheck is next.
    IdlePublished,
    /// The final recheck found nothing owed; the halt is next. A wake that
    /// arrives here can only be a vector, never a durable word the recheck
    /// would have read.
    AfterFinalRecheck,
}

/// Why a pass left the idle loop without a record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleLeave {
    /// The venue has its own reason to leave ([`IdleVenue::leaves_for_host`]).
    Venue,
    /// The run queue's head needs this slot's host executor
    /// ([`ZoneTables::head_needs_host`]).
    HeadNeedsHost,
}

/// What one [`idle_pass`] ended with.
#[must_use = "a taken record is this slot's to switch in"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdlePass {
    /// The scan took `SwitchedIn`, and the slot is no longer idle. The venue
    /// switches it in.
    Took(SwitchedIn),
    /// The slot is no longer idle and leaves for its host.
    Leave(IdleLeave),
    /// Nothing to take yet (the venue polled, slept, or the recheck found a
    /// wake owed): run another pass.
    Again,
}

/// The ISA mechanics an idle pass runs on.
pub trait IdleVenue {
    /// Take every vector latched while interrupts were masked, and send any
    /// kick this CPU still owes another (an x86 delivery point, #3083).
    fn drain(&mut self);
    /// Whether this CPU leaves the idle loop for its host now (ARM: host
    /// work is pending, or the slot's affinity excludes this CPU).
    fn leaves_for_host(&mut self) -> bool;
    /// Expire this slot's due timed parks, delivering what they complete.
    fn expire_timers(&mut self);
    /// Send the idle-scan passes a zone operation owes (#3083).
    fn deliver(&mut self, passes: OwedPasses);
    /// Whether a run-queue head that needs the host executor ends the pass
    /// ([`IdleLeave::HeadNeedsHost`]): true where an executor can take it.
    fn leaves_for_executor(&self) -> bool;
    /// Whether this CPU polls once more instead of sleeping (an ARM idle
    /// spin before WFI).
    fn keep_polling(&mut self) -> bool;
    /// Get ready to sleep before the slot is published `IdleWfi`: leave the
    /// installed address space, and arm the timer a sleep needs.
    fn prepare_sleep(&mut self);
    /// The slot is published `IdleWfi` (ARM programs its timer here).
    fn sleep_published(&mut self);
    /// A venue's own reason, read at the final recheck, to run another pass
    /// rather than sleep (ARM: an affinity that excludes this CPU).
    fn recheck_refuses(&mut self) -> bool;
    /// Whether host work is pending on this CPU (the durable word a host
    /// placement on a CPU stopped in a crossing leaves).
    fn host_work_pending(&self) -> bool;
    /// Send the kicks this CPU still owes. False: one is still owed (a busy
    /// ICR), so this CPU must not sleep.
    fn owed_kicks_sent(&mut self) -> bool;
    /// Sleep until a vector, with interrupts masked; it returns at once if
    /// one is pending, and may return early.
    fn halt(&mut self);
    /// The slot was published `IdleWfi` and its sleep, or its refusal, is
    /// over: leave that state (ARM polls again; x86 stops idling).
    fn rejoin(&mut self);
    /// The pass ends with [`IdlePass::Again`] (x86 disarms the timer it
    /// armed in [`Self::prepare_sleep`]).
    fn end_pass(&mut self);
    /// A test fixture's stop at `point`. Production venues do nothing.
    fn stop(&mut self, point: IdleStop) {
        let _ = point;
    }
}

/// Run one idle pass of `slot` on `venue` (see the module docs for the
/// order and why).
pub fn idle_pass<C, V>(zone: &ZoneTables<C>, slot: SlotId, venue: &mut V) -> IdlePass
where
    C: Copy + Send + Sync + zerocopy::FromZeros,
    V: IdleVenue,
{
    venue.drain();
    venue.stop(IdleStop::AfterDrain);
    if venue.leaves_for_host() {
        zone.leave_idle(slot);
        return IdlePass::Leave(IdleLeave::Venue);
    }
    venue.expire_timers();
    venue.stop(IdleStop::BeforeScan);
    let passes = OwedPasses::new();
    let taken = zone.take_idle_work(slot, &passes);
    venue.deliver(passes);
    if let Some(taken) = taken {
        zone.leave_idle(slot);
        return IdlePass::Took(taken);
    }
    if venue.leaves_for_executor() && zone.head_needs_host(slot) {
        zone.leave_idle(slot);
        return IdlePass::Leave(IdleLeave::HeadNeedsHost);
    }
    if venue.keep_polling() {
        return IdlePass::Again;
    }
    venue.prepare_sleep();
    let passes = OwedPasses::new();
    let published = zone.enter_idle(slot, true, &passes);
    venue.deliver(passes);
    if published {
        venue.sleep_published();
        venue.stop(IdleStop::IdlePublished);
        if !(venue.recheck_refuses()
            || venue.host_work_pending()
            || zone.take_resched(slot)
            || !venue.owed_kicks_sent())
        {
            venue.stop(IdleStop::AfterFinalRecheck);
            venue.halt();
        }
        venue.rejoin();
    }
    venue.end_pass();
    IdlePass::Again
}

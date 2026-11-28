#![cfg_attr(target_os = "none", no_std)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
extern crate alloc as rust_alloc;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod anonymous;
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
mod exec_successor;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod linux_personality;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_execution;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod native_host_file;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_process;
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
mod native_stage;

use carrick_el1_abi::Action;

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
mod test_support {
    use core::sync::atomic::Ordering;

    pub const INJECT_ROOT_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe10;
    /// The next owner-selected grant's descriptor executor refuses it before
    /// any store (#2579): for capacity (`TablesExhausted`), for an occupied
    /// leaf (`Occupied`), terminally (`WrongMm`), or for a selection the
    /// root no longer authenticates (`StaleRoot`, #2766).
    pub const INJECT_GRANT_CAPACITY_REFUSAL_ONCE: u64 = 0xffff_ffff_ffff_fe50;
    pub const INJECT_GRANT_OCCUPIED_REFUSAL_ONCE: u64 = 0xffff_ffff_ffff_fe51;
    pub const INJECT_GRANT_TERMINAL_REFUSAL_ONCE: u64 = 0xffff_ffff_ffff_fe52;
    pub const INJECT_GRANT_STALE_REFUSAL_ONCE: u64 = 0xffff_ffff_ffff_fe4c;
    /// Injected grant refusals answered in the high 32 bits; the pages of
    /// the first grant applied after one in the low 32 bits.
    pub const INJECT_GRANT_REFUSAL_CENSUS: u64 = 0xffff_ffff_ffff_fe53;
    /// 1 if the calling member's kernel wait record currently holds an active
    /// `OperationToken`, else 0 (`#2975` r33 P1 #2).
    pub const INJECT_OPERATION_TOKEN_ACTIVE: u64 = 0xffff_ffff_ffff_fe54;
    pub const INJECT_EDITOR_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe11;
    pub const INJECT_PREPARED_CONFLICT_ONCE: u64 = 0xffff_ffff_ffff_fe12;
    pub const INJECT_WAIT_PARK_CENSUS: u64 = 0xffff_ffff_ffff_fe13;
    pub const INJECT_METADATA_REQUIRED_ONCE: u64 = 0xffff_ffff_ffff_fe14;
    pub const INJECT_WAIT_HANDBACK_CENSUS: u64 = 0xffff_ffff_ffff_fe15;
    pub const INJECT_METADATA_ON_REPROBE_ONCE: u64 = 0xffff_ffff_ffff_fe16;
    pub const INJECT_CAUGHT_SIGNAL_ON_PARK: u64 = 0xffff_ffff_ffff_fe17;
    /// As `INJECT_CAUGHT_SIGNAL_ON_PARK`, and the editor is held again once
    /// the parked edit's holder releases: the caught signal's handler-frame
    /// copy finds the editor held while the interrupted edit's operation is
    /// still on the record, as a sibling thread's edit holds it (#3043).
    pub const INJECT_CAUGHT_SIGNAL_ON_PARK_FRAME_HELD: u64 = 0xffff_ffff_ffff_fe55;
    /// The second native signal-clock read from now reports tick 0: a sleep
    /// woken at its deadline first sees the clock before it, and every later
    /// read is real again.
    pub const INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ: u64 = 0xffff_ffff_ffff_fe19;
    /// Once the calling member next parks, publish a caught SIGUSR1 to it
    /// through the production ingress owner.
    pub const INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK: u64 = 0xffff_ffff_ffff_fe1a;
    /// The next exact-MM user write is Busy once, whether it is an owned
    /// (retained-output) copy or a direct signal-output copy.
    pub const INJECT_OWNED_COPY_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe1b;
    /// Read the injected-copy census: refusals in the high 32 bits, owned
    /// copies that completed after an owned refusal in the low 32 bits.
    pub const INJECT_OWNED_COPY_CENSUS: u64 = 0xffff_ffff_ffff_fe1c;
    /// Hold the next owned zero-word copy-out (a clear-tid write) once it has
    /// published to guest memory, until released: the window a descheduled
    /// vCPU opens between a copy's guest-visible publication and the code
    /// after it (#2648).
    pub const INJECT_OWNED_COPY_PUBLISH_GATE: u64 = 0xffff_ffff_ffff_fe2e;
    /// 1 once the armed copy-out is held after its publication, else 0 (and
    /// the peer CPU is kicked so a worker queued behind the poller runs).
    pub const INJECT_OWNED_COPY_PUBLISH_HELD: u64 = 0xffff_ffff_ffff_fe2f;
    /// Release the held copy-out, or disarm a gate that never engaged.
    pub const INJECT_RELEASE_OWNED_COPY_PUBLISH: u64 = 0xffff_ffff_ffff_fe30;
    /// The next anonymous replay settlement reports the ownership refusal
    /// (`Stale`) that `take_object_operation` raises, after the mapping edit
    /// has already committed.
    pub const INJECT_REPLAY_SETTLEMENT_REFUSAL_ONCE: u64 = 0xffff_ffff_ffff_fe1d;
    pub const INJECT_PEER_IDLE_RELEASE_ONCE: u64 = 0xffff_ffff_ffff_fe18;
    /// The calling member blocks SIGUSR1 at the signal checkpoint of its
    /// second syscall return from now (the first is this call's own return).
    /// A `kill` issued right after therefore sees the member eligible when it
    /// enumerates recipients and ineligible by the time it reaches its
    /// checkpoint: the interleaving the guest cannot order deterministically.
    pub const INJECT_BLOCK_SIGUSR1_AT_SECOND_CHECKPOINT: u64 = 0xffff_ffff_ffff_fe1e;
    const SIGUSR1_BIT: u64 = 1 << 9;
    /// Address of the armed member's control slot, or 0.
    static BLOCK_CONTROL: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    static BLOCK_CHECKPOINTS_LEFT: core::sync::atomic::AtomicU8 =
        core::sync::atomic::AtomicU8::new(0);

    /// Run at every syscall-return signal checkpoint, before delivery.
    pub fn block_sigusr1_at_checkpoint(control: &carrick_el1_abi::ThreadControlSlot) {
        let address = control as *const carrick_el1_abi::ThreadControlSlot as usize;
        if BLOCK_CONTROL.load(Ordering::Acquire) != address {
            return;
        }
        if BLOCK_CHECKPOINTS_LEFT.fetch_sub(1, Ordering::AcqRel) == 1 {
            BLOCK_CONTROL.store(0, Ordering::Release);
            let blocked = control.blocked().0 | SIGUSR1_BIT;
            let _ = control.store_blocked_then_read_pending(
                carrick_personality_linux::abi::thread::BlockedMask(blocked),
                control.pending(),
            );
        }
    }

    /// Hold the next native birth inside its topology reservation (#2095),
    /// at its MM preparation, until the waiter below parks or releases it.
    pub const INJECT_HOLD_NEXT_BIRTH: u64 = 0xffff_ffff_ffff_fe1f;
    /// 1 once the armed birth holds its reservation (and the calling member
    /// becomes the waiter whose park releases it), else 0.
    pub const INJECT_BIRTH_HELD: u64 = 0xffff_ffff_ffff_fe20;
    /// Release a held birth from its waiter's own call; 0 also when the
    /// waiter's park already released it.
    pub const INJECT_RELEASE_HELD_BIRTH: u64 = 0xffff_ffff_ffff_fe21;
    const BIRTH_ARMED: u8 = 1;
    const BIRTH_HELD: u8 = 2;
    const BIRTH_RELEASED: u8 = 3;
    /// About seconds of spinning: a waiter that never parks or releases
    /// fails the run instead of hanging it.
    const BIRTH_HOLD_SPINS: u64 = 1 << 32;
    static BIRTH_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

    /// Hold the next completed user-fault COW in the ring, after its guest
    /// copy and repoint completed and before its settlement crossing, so a
    /// sibling can retire the replacement leaf while the completion is
    /// outstanding (#1482 P0-3).
    pub const INJECT_HOLD_NEXT_COW_SETTLE: u64 = 0xffff_ffff_ffff_fe22;
    /// 1 once the armed COW completion is held, else 0.
    pub const INJECT_COW_SETTLE_HELD: u64 = 0xffff_ffff_ffff_fe23;
    /// Release the held COW completion to its settlement crossing, or
    /// disarm a hold that never engaged.
    pub const INJECT_RELEASE_HELD_COW_SETTLE: u64 = 0xffff_ffff_ffff_fe24;
    /// 1 if the hold reached its bound before the sibling released it.
    pub const INJECT_COW_SETTLE_TIMED_OUT: u64 = 0xffff_ffff_ffff_fe25;
    /// As [`INJECT_HOLD_NEXT_COW_SETTLE`], with no spin bound: the hold ends
    /// only on [`INJECT_RELEASE_HELD_COW_SETTLE`], so a fixture's ordering
    /// never depends on vCPU scheduling; the test's own timeout bounds a
    /// hung run (#2947 review).
    pub const INJECT_HOLD_NEXT_COW_SETTLE_UNTIL_RELEASED: u64 = 0xffff_ffff_ffff_fe36;
    /// The calling member's CPU slot, so the fixture can keep the held
    /// member off its poller's CPU.
    pub const INJECT_CURRENT_CPU: u64 = 0xffff_ffff_ffff_fe26;
    /// The next native fork's parent-mapping census finds the parent's
    /// reservation root held by another holder, who releases it when that
    /// acquisition returns (#2306).
    pub const INJECT_FORK_CENSUS_ROOT_HELD_ONCE: u64 = 0xffff_ffff_ffff_fe27;
    /// As above, at the next native fork's child commit.
    pub const INJECT_FORK_COMMIT_ROOT_HELD_ONCE: u64 = 0xffff_ffff_ffff_fe28;
    /// Fork acquisitions refused by an injected root hold.
    pub const INJECT_FORK_ROOT_HOLD_CENSUS: u64 = 0xffff_ffff_ffff_fe29;
    /// Wake the peer CPU and hold its next idle scan, before the scan, for
    /// [`SCAN_HOLD_NS`] (#2306): the window a loaded host opens when the
    /// peer's vCPU thread is descheduled between its wake and its next
    /// sleep. Every migration and rotation this CPU runs meanwhile finds no
    /// idle peer.
    pub const INJECT_HOLD_PEER_SCAN: u64 = 0xffff_ffff_ffff_fe2a;
    /// 1 once the peer's idle scan is held (or released), else 0.
    pub const INJECT_PEER_SCAN_HELD: u64 = 0xffff_ffff_ffff_fe2b;
    const SCAN_ARMED: u8 = 1;
    const SCAN_HELD: u8 = 2;
    const SCAN_RELEASED: u8 = 3;
    /// Ten slices: the poller's slice ends, and its rotation's migration
    /// runs, while the peer is held.
    const SCAN_HOLD_NS: u64 = 20_000_000;
    static SCAN_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// The held slot, plus one (0: none).
    static SCAN_HOLD_SLOT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// Wake the peer CPU and stop its next idle pass right after the pass
    /// has read its conditions (the scan hold above, timers), until this
    /// CPU says it published (#3053). The peer's pass then goes on only
    /// once the reschedule vector of that publication is pending in its
    /// IRR: the publication lands exactly between the pass's read and the
    /// rest of the pass, and its vector is the only wake it has.
    pub const INJECT_ORDER_PEER_AFTER_IDLE_READ: u64 = 0xffff_ffff_ffff_fe5c;
    /// As [`INJECT_ORDER_PEER_AFTER_IDLE_READ`], but this CPU finishes its
    /// arming only once the peer has run an idle pass after the arming
    /// vector was sent and before the arming was complete, as a host that
    /// deschedules this vCPU at the send's exit does (#3136). That pass
    /// consumed the arming vector: it must still stop, never sleep past the
    /// arming with no vector left to wake it.
    pub const INJECT_ORDER_PEER_AFTER_IDLE_READ_LATE_ARM: u64 = 0xffff_ffff_ffff_fe70;
    /// Wake the peer CPU and stop it right after its idle slot is published
    /// IdleWfi, before HLT, until this CPU says it published (#3053). This
    /// CPU then publishes host work on the peer's task with no vector
    /// ([`INJECT_MARK_PEER_HOST_WORK`]): only the durable word announces it.
    pub const INJECT_ORDER_PEER_BEFORE_IDLE_HLT: u64 = 0xffff_ffff_ffff_fe56;
    /// 1 once the armed peer is stopped at its ordering point, else 0.
    pub const INJECT_ORDER_PEER_REACHED: u64 = 0xffff_ffff_ffff_fe57;
    /// This CPU's publication is complete: the stopped peer goes on.
    pub const INJECT_ORDER_PEER_PUBLISHED: u64 = 0xffff_ffff_ffff_fe58;
    /// Ordered peer passes that went on after this CPU's publication (and,
    /// after the idle read, with its reschedule vector pending in the IRR).
    pub const INJECT_ORDER_PEER_CENSUS: u64 = 0xffff_ffff_ffff_fe59;
    /// Publish host work on the stopped peer's task, sending no vector.
    pub const INJECT_MARK_PEER_HOST_WORK: u64 = 0xffff_ffff_ffff_fe5a;
    /// 1 while the stopped peer's task still has host work pending, else 0.
    pub const INJECT_PEER_HOST_WORK_PENDING: u64 = 0xffff_ffff_ffff_fe5b;
    /// The next reschedule IPI this kernel sends finds its ICR busy, once
    /// (#3083): the send is owed by this CPU and resent at its next
    /// delivery point, never fatal.
    pub const INJECT_RESCHED_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe5d;
    /// `sends found busy | owed IPIs resent << 16 | busy-to-idle transitions
    /// an idle-ICR wait saw << 32 | the last resend's UserReturn << 48`.
    pub const INJECT_RESCHED_BUSY_CENSUS: u64 = 0xffff_ffff_ffff_fe5e;
    /// This CPU's ICR is busy until an idle-ICR wait sees it go idle: its
    /// sends (the first and its resend at the return to user, the last
    /// delivery point before a syscall-free user loop) find it busy, its
    /// next poll reads it busy once, the one after idle (#3083).
    pub const INJECT_RESCHED_BUSY_THROUGH_LAST_RETURN: u64 = 0xffff_ffff_ffff_fe5f;
    /// As above for two sends with no busy poll, and the last-chance wait
    /// stalls past its bound once before it polls, as a host descheduling
    /// the vCPU there would (#3083). The ICR has recovered by then.
    pub const INJECT_RESCHED_STALL_AT_LAST_RETURN: u64 = 0xffff_ffff_ffff_fe61;
    /// As [`INJECT_RESCHED_BUSY_THROUGH_LAST_RETURN`], and the last-chance
    /// wait stalls past its bound once right after its poll read the ICR
    /// busy; the ICR recovers meanwhile (#3083).
    pub const INJECT_RESCHED_STALL_AFTER_BUSY_POLL: u64 = 0xffff_ffff_ffff_fe62;
    /// Three sends find the ICR busy (the first, and two resends at the
    /// return to user) with no busy poll, and the CPU stalls past the
    /// last-chance bound once right after the third; the ICR recovers
    /// meanwhile (#3083).
    pub const INJECT_RESCHED_STALL_AFTER_BUSY_SEND: u64 = 0xffff_ffff_ffff_fe63;
    /// Every reschedule IPI send of this CPU finds its ICR busy while every
    /// idle-ICR poll reads it idle: a local APIC that never accepts its
    /// send. The last-chance wait must end fatal, never loop (#3083).
    pub const INJECT_RESCHED_ICR_FLAPPING: u64 = 0xffff_ffff_ffff_fe60;
    /// The next reschedule send finds the ICR busy and also owes this CPU's
    /// own slot, so the next resend pass sends two; that pass's first send
    /// goes out after a stall past the bound and its second finds the ICR
    /// busy, one poll reads busy and the next idle (#3129 P0 1).
    pub const INJECT_RESCHED_TWO_OWED_STALLED: u64 = 0xffff_ffff_ffff_fe64;
    /// Every reschedule send of this CPU finds its ICR busy, and when this
    /// CPU's current task next parks, the scheduler owes the other CPU a
    /// reschedule there, as a waker whose syscall then blocks would: the
    /// next delivery point is the idle pass, never a return to user. The
    /// idle sender must end fatal past the bound, never spin (#3129 P0 2).
    pub const INJECT_RESCHED_OWED_AT_PARK: u64 = 0xffff_ffff_ffff_fe65;
    /// The CPU slot (plus one) whose next park owes the other CPU a
    /// reschedule ([`INJECT_RESCHED_OWED_AT_PARK`]).
    static OWE_AT_PARK_SLOT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    /// Called on each scheduler entry: owe the other CPU a reschedule once
    /// [`INJECT_RESCHED_OWED_AT_PARK`]'s CPU parks its task.
    pub fn owe_peer_resched_at_park(slot: carrick_sched_core::SlotId) {
        if OWE_AT_PARK_SLOT
            .compare_exchange(
                u32::from(slot.raw()) + 1,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let peer = carrick_sched_core::SlotId::new(u8::from(slot.raw() == 0));
        carrick_el1::isa::x86::interrupt::send_resched(peer)
            .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
    }
    const ORDER_AFTER_READ: u8 = 1;
    const ORDER_BEFORE_HLT: u8 = 2;
    /// Armed, with the arming reschedule not yet known sent: a pass that
    /// sees this waits for [`ORDER_ARMED`], never goes on (#3136).
    const ORDER_ARMING: u8 = 1;
    /// Armed, and the arming reschedule was sent: its vector is in the
    /// peer's IRR or already taken, so the peer's pending-vector check sees
    /// it.
    const ORDER_ARMED: u8 = 2;
    const ORDER_REACHED: u8 = 3;
    const ORDER_PUBLISHED: u8 = 4;
    /// Which ordering point is armed ([`ORDER_AFTER_READ`] or
    /// [`ORDER_BEFORE_HLT`]), 0 for none.
    static ORDER_POINT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// The ordered slot, plus one (0: none).
    static ORDER_SLOT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static ORDER_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static ORDER_PASSES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    /// Passes that found the ordering point [`ORDER_ARMING`].
    static ORDER_ARMING_PASSES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    /// The late arming's park of the ordered slot past its final idle
    /// recheck, right before `sti; hlt` (#3136): requested (its wake not
    /// yet known sent), sent, parked, released.
    static LATE_PARK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    const PARK_REQUESTED: u8 = 1;
    const PARK_SENT: u8 = 2;
    const PARK_PARKED: u8 = 3;
    const PARK_RELEASED: u8 = 4;
    /// The stopped peer's current task, published at its ordering point.
    static ORDER_PEER_TASK: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    /// The calling member's next user-memory preparation finds its space
    /// editor held, and the holder releases it before the member enrolls on
    /// the owner wait (#2416): the wait settles before its park.
    pub const INJECT_EDITOR_RELEASED_BEFORE_PARK_ONCE: u64 = 0xffff_ffff_ffff_fe2c;
    /// Owner waits the armed hold refused and released before their park.
    pub const INJECT_EDITOR_RELEASED_BEFORE_PARK_CENSUS: u64 = 0xffff_ffff_ffff_fe2d;
    /// Hold the next native fork after its parent root is published
    /// fork-pending and write-protected, before its commit (#2581), until
    /// the waiter below parks or releases it.
    pub const INJECT_HOLD_NEXT_FORK_COMMIT: u64 = 0xffff_ffff_ffff_fe31;
    /// 1 once the armed fork commit is held (and the calling member becomes
    /// the waiter whose park releases it), else 0.
    pub const INJECT_FORK_COMMIT_HELD: u64 = 0xffff_ffff_ffff_fe32;
    /// Release a held fork commit from its waiter's own call; 0 also when
    /// the waiter's park already released it.
    pub const INJECT_RELEASE_HELD_FORK_COMMIT: u64 = 0xffff_ffff_ffff_fe33;
    static FORK_COMMIT_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// Arm, with [`INJECT_HOLD_NEXT_FORK_COMMIT`], the ordering of #2923: when
    /// the held fork's publication is complete, a sibling held between its
    /// copy-on-write supply ([`INJECT_HOLD_NEXT_COW_SUPPLY`]) is released,
    /// so its resolution with the grant the carrier supplied before the
    /// fork began runs while the fork is pending. The fork hold then ends
    /// on a real event: the sibling parked on the publication's release
    /// (see [`INJECT_REGISTER_FORK_COMMIT_WAITER`]), or the sibling's
    /// copy-on-write completed under the pending fork. The supply hold then
    /// has no spin bound: only the fork's hold releases it.
    pub const INJECT_FORK_COMMIT_RELEASES_SUPPLY: u64 = 0xffff_ffff_ffff_fe48;
    /// The calling member becomes the waiter whose park releases the held
    /// fork commit, before it faults: unlike [`INJECT_FORK_COMMIT_HELD`] it
    /// registers without polling, for a member that will be held in the ring.
    pub const INJECT_REGISTER_FORK_COMMIT_WAITER: u64 = 0xffff_ffff_ffff_fe49;
    /// What ended the held fork commit: 0 not yet, 1 the waiter's park, 2 a
    /// sibling's copy-on-write completing while the fork was pending.
    pub const INJECT_FORK_COMMIT_RELEASE_CAUSE: u64 = 0xffff_ffff_ffff_fe4a;
    const RELEASED_BY_PARK: u8 = 1;
    const RELEASED_BY_PEER_COW: u8 = 2;
    static FORK_COMMIT_RELEASES_SUPPLY: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static FORK_COMMIT_RELEASE_CAUSE: core::sync::atomic::AtomicU8 =
        core::sync::atomic::AtomicU8::new(0);
    /// Address of the armed member's current task, or 0.
    static EARLY_RELEASE_TASK: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static EARLY_RELEASES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    /// As [`INJECT_HOLD_NEXT_COW_SETTLE`], but the hold engages earlier:
    /// after the carrier supplied the faulting member's replacement grant
    /// and before the member resolves its fault with one. The supplied
    /// grant is ready in the MM's pool for the whole hold, so a sibling's
    /// copy-on-write can claim it (#2749). Polled, released and bounded
    /// through the settle hold's calls.
    pub const INJECT_HOLD_NEXT_COW_SUPPLY: u64 = 0xffff_ffff_ffff_fe47;
    /// Switch-ins whose saved context claims its PC is after a `SYSCALL`
    /// while the PC is that `SYSCALL` itself: RIP + 2 is the RCX the
    /// instruction saved (#2900). A rerun rewinds such a context into the
    /// instruction in front of its `SYSCALL`.
    pub const INJECT_MISLABELLED_RESUME_CENSUS: u64 = 0xffff_ffff_ffff_fe4b;
    static MISLABELLED_RESUMES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// Count a switched-in context labelled after its `SYSCALL` whose RIP
    /// is the `SYSCALL` that saved its RCX.
    pub fn observe_resumed_position(words: &carrick_sched_core::ParkedContextWords) {
        use carrick_sched_core::X86ParkedGpr as Gpr;
        if words.saved_syscall_pc() == Some(carrick_sched_core::SavedSyscallPc::AfterSyscall)
            && words
                .user_rip()
                .checked_add(carrick_guest_arch::X86_64_SYSCALL_LEN)
                == Some(words.frame[Gpr::Rcx as usize])
        {
            MISLABELLED_RESUMES.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// The calling member's next owner-selected grant finds its MM editor
    /// held when it serves the window the carrier already prepared and
    /// submitted: the loser of a two-CPU race in one grant window.
    pub const INJECT_SELECTED_SERVE_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe40;
    /// Selected-window serves the armed hold refused.
    pub const INJECT_SELECTED_SERVE_BUSY_CENSUS: u64 = 0xffff_ffff_ffff_fe41;
    /// The next native fork that finds its parent's COW completions
    /// unsettled (#2947) finds the parent's editor held by a real holder
    /// across its settlement crossing, so the carrier settles nothing and
    /// the fork waits for the editor. The holder releases the editor
    /// through its production release once the fork has parked.
    pub const INJECT_HOLD_EDITOR_AT_FORK_COW_SETTLE: u64 = 0xffff_ffff_ffff_fe34;
    /// Bits 32..48: settlement crossings the armed editor hold covered;
    /// 16..32: holds released with their fork parked on the editor;
    /// 0..16: fork settlement crossings that left the parent settled.
    pub const INJECT_FORK_COW_SETTLE_CENSUS: u64 = 0xffff_ffff_ffff_fe35;
    /// The same hold at the next user-write settlement crossing that finds
    /// the caller's MM with COW completions (#3082): a kernel copy into user
    /// memory meets the editor held, settles nothing, and waits for the
    /// editor's release. The fork's census counts it.
    pub const INJECT_HOLD_EDITOR_AT_COPY_COW_SETTLE: u64 = 0xffff_ffff_ffff_fe37;
    /// Settlement crossings of a user write that met the armed copy hold's
    /// editor held. A copy that waits on the editor's release meets it once;
    /// one that reran as bare carrier work meets it again (#3082).
    pub const INJECT_COPY_COW_EDITOR_HELD_CENSUS: u64 = 0xffff_ffff_ffff_fe38;
    static COPY_COW_EDITOR_HELD_CROSSINGS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// A user write's settlement crossing met its MM's editor held: count
    /// it while the copy hold holds the editor.
    pub fn record_copy_cow_editor_held() {
        if FORK_COW_EDITOR
            .lock()
            .as_ref()
            .is_some_and(|held| held.editor_queue.is_some())
        {
            COPY_COW_EDITOR_HELD_CROSSINGS.fetch_add(1, Ordering::AcqRel);
        }
    }
    /// The armed member: the fork whose park releases the held editor.
    static FORK_COW_EDITOR_WAITER: carrick_el1::lock::SpinLock<
        Option<carrick_sched_core::RecordRef>,
    > = carrick_el1::lock::SpinLock::new(None);
    /// The armed member: the copy whose park releases the held editor.
    static COPY_COW_EDITOR_WAITER: carrick_el1::lock::SpinLock<
        Option<carrick_sched_core::RecordRef>,
    > = carrick_el1::lock::SpinLock::new(None);
    static FORK_COW_EDITOR_HOLDS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static FORK_COW_EDITOR_PARKED_RELEASES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static FORK_COW_SETTLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    /// The editor an injected fork hold names: no member of this zone.
    const FORK_COW_EDITOR_HOLDER: core::num::NonZeroU64 = core::num::NonZeroU64::MAX;
    /// The held editor and the fork whose park releases it.
    struct HeldForkEditor {
        editor: carrick_sched_core::spaces::SpaceEditor<
            'static,
            carrick_sched_core::ParkedContextWords,
        >,
        waiter: carrick_sched_core::RecordRef,
        /// The MM's editor queue the waiter must be enrolled on before the
        /// hold releases (the copy hold, #3082): a bare carrier-work rerun
        /// parks nowhere, so the holder keeps the editor and the run hangs.
        editor_queue: Option<u32>,
    }
    // SAFETY: the guard names the one static zone's space entry and its
    // release venue (a plain function delivery); it moves between this
    // image's CPUs only under the lock below.
    unsafe impl Send for HeldForkEditor {}
    static FORK_COW_EDITOR: carrick_el1::lock::SpinLock<Option<HeldForkEditor>> =
        carrick_el1::lock::SpinLock::new(None);

    /// Called by a native fork that refused on its parent's unsettled COW
    /// completions, before it observes the parent's editor and rings the
    /// settlement crossing, on the forking member's CPU: when armed, take
    /// the parent's real editor for the forking record's park to release.
    pub fn hold_editor_for_fork_cow_settle(
        zone: &'static carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>,
        slot: u32,
        mm: u64,
    ) {
        hold_editor_for_armed(&FORK_COW_EDITOR_WAITER, zone, slot, mm, None);
    }

    /// Called by a user-write settlement crossing that found its MM's COW
    /// completions, before it rings the crossing, on the copying member's
    /// CPU: when armed, take the MM's real editor for the copying record's
    /// park to release.
    pub fn hold_editor_for_copy_cow_settle(
        zone: &'static carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>,
        slot: u32,
        handle: carrick_el1_abi::El1MmHandle,
    ) {
        let mm = handle.mm().raw();
        if COPY_COW_EDITOR_WAITER.lock().is_none() {
            return;
        }
        let Some(queue) = core::num::NonZeroU64::new(mm)
            .and_then(|key| zone.space_entry(key))
            .and_then(|entry| entry.notifications(handle.incarnation()).ok())
            .map(|lease| {
                lease
                    .key(carrick_sched_core::spaces::notification::SpaceWaitCause::Editor)
                    .index()
            })
        else {
            carrick_x86_carrier::entry::fatal_boot!();
        };
        hold_editor_for_armed(&COPY_COW_EDITOR_WAITER, zone, slot, mm, Some(queue));
    }

    fn hold_editor_for_armed(
        armed: &carrick_el1::lock::SpinLock<Option<carrick_sched_core::RecordRef>>,
        zone: &'static carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>,
        slot: u32,
        mm: u64,
        editor_queue: Option<u32>,
    ) {
        let Some(waiter) = armed.lock().take() else {
            return;
        };
        let (Some(slot), Some(index)) = (
            carrick_sched_core::SlotId::from_index(slot as usize),
            zone.spaces.find(mm),
        ) else {
            carrick_x86_carrier::entry::fatal_boot!();
        };
        let Some(editor) =
            carrick_core::wait::space_access(zone, slot, crate::native_process::release)
                .try_begin_edit(index, mm, FORK_COW_EDITOR_HOLDER)
        else {
            carrick_x86_carrier::entry::fatal_boot!();
        };
        *FORK_COW_EDITOR.lock() = Some(HeldForkEditor {
            editor,
            waiter,
            editor_queue,
        });
        FORK_COW_EDITOR_HOLDS.fetch_add(1, Ordering::AcqRel);
    }

    /// The fork's settlement crossing returned with its parent settled.
    pub fn record_fork_cow_settled() {
        FORK_COW_SETTLED.fetch_add(1, Ordering::AcqRel);
    }

    /// Called on each scheduler entry: once the fork that met the held
    /// editor has parked, drop the editor, whose release wakes it.
    pub fn release_fork_cow_editor_on_park(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
    ) {
        let mut held = FORK_COW_EDITOR.lock();
        let Some((waiter, editor_queue)) =
            held.as_ref().map(|held| (held.waiter, held.editor_queue))
        else {
            return;
        };
        if !matches!(
            source.zone.record(waiter.id).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ) {
            return;
        }
        if let Some(queue) = editor_queue
            && source
                .zone
                .object_queue_census(queue)
                .is_none_or(|census| census.waiters == 0)
        {
            return;
        }
        let released = held.take();
        drop(held);
        FORK_COW_EDITOR_PARKED_RELEASES.fetch_add(1, Ordering::AcqRel);
        drop(released.map(|held| held.editor));
    }

    /// Address of the armed member's current task, or 0.
    static SELECTED_SERVE_BUSY_TASK: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static SELECTED_SERVE_BUSIES: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// The calling member's next switch-in that holds an adapter operation
    /// (a woken IPC wait) finds its MM's Gate raised, as a host exclusion
    /// raises it (#2660). The gate is lowered through the MM's release venue
    /// once a scheduler pass finds the refused record parked on it, or
    /// requeued instead (the record polled the gate).
    pub const INJECT_GATE_AT_NEXT_OPERATION_SWITCH_IN: u64 = 0xffff_ffff_ffff_fe42;
    /// As above, for the next switch-in carrying a wake result and no
    /// operation (a woken futex wait).
    pub const INJECT_GATE_AT_NEXT_RESULT_SWITCH_IN: u64 = 0xffff_ffff_ffff_fe43;
    /// Injected gate census: parks in bits 0..16, polls in bits 16..32,
    /// raises in bits 32..48.
    pub const INJECT_GATE_CENSUS: u64 = 0xffff_ffff_ffff_fe44;
    /// 1 while the armed member is parked (its peer may now wake it), else
    /// 0 (and the peer CPU is kicked, so a member queued behind the caller
    /// runs).
    pub const INJECT_GATE_TARGET_PARKED: u64 = 0xffff_ffff_ffff_fe45;
    /// For a worker whose bounded wait for the armed member ran out: 128 +
    /// 8 * the member's claim kind (Parked 1, Queued 2, OnCpu 3, other 4)
    /// + the injection state, as its exit code.
    pub const INJECT_GATE_TARGET_STATE: u64 = 0xffff_ffff_ffff_fe46;
    const GATE_OPERATION: u8 = 1;
    const GATE_RESULT: u8 = 2;
    const GATE_RAISED: u8 = 3;
    static GATE_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// The armed member's record, plus one (0: none).
    static GATE_TARGET: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    static GATE_MM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static GATE_PARKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static GATE_POLLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static GATE_RAISES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    fn arm_gate(
        kind: u8,
        binding: &carrick_el1::isa::x86::context::native::CpuBinding,
    ) -> Option<u64> {
        let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
            carrick_guest_arch::CpuId::new(binding.cpu_slot),
        )?;
        let zone = carrick_x86_carrier::native_execution::source(slot).zone;
        let record = zone
            .slot(slot)
            .current()
            .or_else(|| zone.slot(slot).host_record())?;
        GATE_TARGET.store(record.raw() + 1, Ordering::Release);
        GATE_STATE
            .compare_exchange(0, kind, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(0)
    }

    /// Called once `schedule` switched `selected` in, before it installs
    /// the record's MM `mm`: raise that MM's Gate for the armed switch-in.
    pub fn raise_gate_at_switch_in(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
        selected: carrick_sched_core::SwitchedIn,
        mm: u64,
    ) {
        if GATE_TARGET.load(Ordering::Acquire) != selected.record.raw() + 1 {
            return;
        }
        let rec = source.zone.record(selected.record);
        let kind = if rec.has_adapter_operation() {
            GATE_OPERATION
        } else if selected.result.is_some() && !rec.has_object_operation() {
            GATE_RESULT
        } else {
            return;
        };
        if GATE_STATE
            .compare_exchange(kind, GATE_RAISED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Some(index) = source.zone.spaces.find(mm) else {
            carrick_x86_carrier::entry::fatal_boot!();
        };
        GATE_MM.store(mm, Ordering::Release);
        source.zone.spaces.raise(index);
        GATE_RAISES.fetch_add(1, Ordering::AcqRel);
    }

    /// Called at the top of each scheduler pass: once the refused record
    /// has parked on the raised gate, or was requeued instead, lower the
    /// gate through the MM's release venue (which wakes a parked record).
    pub fn lower_injected_gate(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
        slot: carrick_sched_core::SlotId,
    ) {
        if GATE_STATE.load(Ordering::Acquire) != GATE_RAISED {
            return;
        }
        let Some(record) = carrick_sched_core::RecordId::from_raw(
            GATE_TARGET.load(Ordering::Acquire).wrapping_sub(1),
        ) else {
            return;
        };
        let counter = match source.zone.record(record).claim() {
            carrick_sched_core::Claim::Parked { .. } => &GATE_PARKS,
            carrick_sched_core::Claim::Queued { .. } => &GATE_POLLS,
            _ => return,
        };
        if GATE_STATE
            .compare_exchange(GATE_RAISED, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        counter.fetch_add(1, Ordering::AcqRel);
        let mm = GATE_MM.load(Ordering::Acquire);
        let Some(index) = source.zone.spaces.find(mm) else {
            carrick_x86_carrier::entry::fatal_boot!();
        };
        carrick_core::wait::space_access(source.zone, slot, crate::native_process::release)
            .lower(index);
    }

    /// Called after the carrier prepared and submitted `task`'s selected
    /// window, before the guest serves it: hold the editor for exactly the
    /// armed member's serve. The holder releases once the member parks.
    pub fn hold_editor_for_selected_serve(task: &carrick_el1_abi::CurrentTask) {
        let address = task as *const carrick_el1_abi::CurrentTask as u64;
        if SELECTED_SERVE_BUSY_TASK
            .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if !carrick_sched_core::spaces::inject_editor_busy_once() {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            SELECTED_SERVE_BUSIES.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Called before a native member's user-memory access: hold the editor
    /// for exactly the armed member's next acquisition. True when held.
    pub fn hold_editor_for_early_release(task: &carrick_el1_abi::CurrentTask) -> bool {
        let address = task as *const carrick_el1_abi::CurrentTask as u64;
        EARLY_RELEASE_TASK
            .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && (carrick_sched_core::spaces::inject_editor_busy_once()
                || carrick_x86_carrier::entry::fatal_boot!())
    }

    /// The held access returned. If it was refused with an owner wait, the
    /// holder releases now, before the member enrolls; a hold the access
    /// never met fails the run instead of passing vacuously.
    pub fn release_editor_before_park(
        held: bool,
        waited: bool,
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
        task: &'static carrick_el1_abi::CurrentTask,
    ) {
        if !held {
            return;
        }
        if !waited || !crate::anonymous::release_injected_editor_now(source, task) {
            carrick_x86_carrier::entry::fatal_boot!();
        }
        EARLY_RELEASES.fetch_add(1, Ordering::AcqRel);
    }

    /// Called at the top of each pass of the idle scheduler on `slot`,
    /// before it looks for work.
    pub fn hold_idle_scan(slot: carrick_sched_core::SlotId) {
        use carrick_guest_arch::InterruptBackend;
        if SCAN_HOLD_SLOT.load(Ordering::Acquire) != slot.raw() + 1
            || SCAN_HOLD
                .compare_exchange(SCAN_ARMED, SCAN_HELD, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let mut backend = carrick_el1::isa::x86::X86Backend;
        let now = |backend: &mut carrick_el1::isa::x86::X86Backend| {
            backend
                .counter()
                .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!())
                .raw()
        };
        let hz = backend
            .frequency()
            .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!())
            .raw()
            .get();
        let ticks = u128::from(hz) * u128::from(SCAN_HOLD_NS) / 1_000_000_000;
        let until = now(&mut backend).saturating_add(u64::try_from(ticks).unwrap_or(u64::MAX));
        while now(&mut backend) < until {
            core::hint::spin_loop();
        }
        SCAN_HOLD.store(SCAN_RELEASED, Ordering::Release);
    }

    /// Whether this CPU has a timer, kick or reschedule vector pending.
    fn wake_vector_pending() -> bool {
        // SAFETY: CPL0 on this CPU, with its local APIC mapped.
        [
            carrick_el1::isa::x86::interrupts::TIMER_VECTOR,
            carrick_el1::isa::x86::interrupts::KICK_VECTOR,
            carrick_el1::isa::x86::interrupts::RESCHED_VECTOR,
        ]
        .into_iter()
        .any(|vector| unsafe {
            carrick_el1::isa::x86::interrupts::hardware::vector_requested(vector)
        })
    }

    /// Called once the idle scheduler on `slot` is past its final recheck of
    /// its wake words, right before `sti; hlt`: park there for the late
    /// arming, so the next pass begins only after a vector woke this CPU
    /// (#3136).
    pub fn park_after_idle_recheck(slot: carrick_sched_core::SlotId) {
        if ORDER_SLOT.load(Ordering::Acquire) != slot.raw() + 1 {
            return;
        }
        // The request's wake may be in flight, as the arming's is: the
        // same one-word handshake. Wait until it is known sent, then a wake
        // still pending (that one, or any other) would end the HLT by
        // itself: this pass goes on and the next one parks. Parked, the
        // request's wake is normally taken, so the arming's ends the sleep.
        // IRR is not a receipt, though: a posted request still in flight
        // here can end it first (#3180). That only adds a pass, so the
        // witness's verdict is the bound alone, never which pass stopped.
        let mut park = LATE_PARK.load(Ordering::Acquire);
        while park == PARK_REQUESTED {
            core::hint::spin_loop();
            park = LATE_PARK.load(Ordering::Acquire);
        }
        if park != PARK_SENT
            || wake_vector_pending()
            || LATE_PARK
                .compare_exchange(PARK_SENT, PARK_PARKED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        while LATE_PARK.load(Ordering::Acquire) != PARK_RELEASED {
            core::hint::spin_loop();
        }
    }

    /// Resend what this CPU's busy ICR left owed, until nothing is: a wait
    /// with interrupts masked is a delivery point of its own (#3083).
    fn deliver_owed_now() {
        while !carrick_el1::isa::x86::interrupt::deliver_owed_resched(
            carrick_el1::isa::x86::interrupt::DeliveryPoint::KernelInterrupt,
        ) {
            core::hint::spin_loop();
        }
    }

    /// Called on each pass of the idle scheduler on `slot`, right after the
    /// pass has read its conditions (#3053).
    pub fn order_after_idle_read(
        slot: carrick_sched_core::SlotId,
        task: &'static carrick_el1_abi::CurrentTask,
    ) {
        order_peer(slot, task, ORDER_AFTER_READ);
    }

    /// Called once the idle scheduler on `slot` has published it IdleWfi,
    /// right before it may execute HLT (#3053).
    pub fn order_before_idle_hlt(
        slot: carrick_sched_core::SlotId,
        task: &'static carrick_el1_abi::CurrentTask,
    ) {
        order_peer(slot, task, ORDER_BEFORE_HLT);
    }

    /// Stop the armed slot at `point` until the other CPU has published,
    /// once. No spin bound: only the publication ends the stop, and the
    /// test's own bound fails a run that never publishes.
    fn order_peer(
        slot: carrick_sched_core::SlotId,
        task: &'static carrick_el1_abi::CurrentTask,
        point: u8,
    ) {
        if ORDER_POINT.load(Ordering::Acquire) != point
            || ORDER_SLOT.load(Ordering::Acquire) != slot.raw() + 1
        {
            return;
        }
        let mut state = ORDER_STATE.load(Ordering::Acquire);
        if state == ORDER_ARMING {
            // The arming CPU sent a vector this pass may already have
            // drained, and has not yet said so (#3136): a pass that went on
            // here could sleep past the arming with no wake left. Its next
            // store ends the window; then the pending-vector check below
            // tells a taken vector from one still to come.
            ORDER_ARMING_PASSES.fetch_add(1, Ordering::AcqRel);
            while state == ORDER_ARMING {
                core::hint::spin_loop();
                state = ORDER_STATE.load(Ordering::Acquire);
            }
        }
        if state != ORDER_ARMED {
            return;
        }
        // Stop only at a pass that owes no wake already: a vector still
        // pending here (the arming reschedule, a timer) would end the sleep
        // under test by itself. Such a pass goes on; the next one stops.
        if wake_vector_pending() {
            return;
        }
        ORDER_PEER_TASK.store(
            task as *const carrick_el1_abi::CurrentTask as usize,
            Ordering::Release,
        );
        if ORDER_STATE
            .compare_exchange(
                ORDER_ARMED,
                ORDER_REACHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        while ORDER_STATE.load(Ordering::Acquire) != ORDER_PUBLISHED {
            core::hint::spin_loop();
        }
        if point == ORDER_AFTER_READ {
            // The publication's reschedule vector is the wake under test:
            // go on only once it is accepted here and not yet delivered.
            // SAFETY: CPL0 on this CPU, with its local APIC mapped.
            while !unsafe {
                carrick_el1::isa::x86::interrupts::hardware::vector_requested(
                    carrick_el1::isa::x86::interrupts::RESCHED_VECTOR,
                )
            } {
                core::hint::spin_loop();
            }
        }
        ORDER_POINT.store(0, Ordering::Release);
        ORDER_PASSES.fetch_add(1, Ordering::AcqRel);
    }

    fn arm_peer_order(
        binding: &carrick_el1::isa::x86::context::native::CpuBinding,
        point: u8,
        late: bool,
    ) -> Option<u64> {
        let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
        if ORDER_STATE.load(Ordering::Acquire) != 0 {
            return None;
        }
        ORDER_SLOT.store(peer.raw() + 1, Ordering::Release);
        if late {
            // Park the peer past its final recheck first: it comes round to
            // it on this wake and then can only sleep, so its next pass
            // begins after the arming vector below woke it, and that pass's
            // drain has taken it.
            LATE_PARK.store(PARK_REQUESTED, Ordering::Release);
            carrick_el1::isa::x86::interrupt::send_resched(peer)
                .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
            deliver_owed_now();
            LATE_PARK.store(PARK_SENT, Ordering::Release);
            while LATE_PARK.load(Ordering::Acquire) != PARK_PARKED {
                core::hint::spin_loop();
            }
        }
        ORDER_POINT.store(point, Ordering::Release);
        ORDER_STATE.store(ORDER_ARMING, Ordering::Release);
        if late {
            LATE_PARK.store(PARK_RELEASED, Ordering::Release);
        }
        carrick_el1::isa::x86::interrupt::send_resched(peer)
            .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
        if late {
            deliver_owed_now();
            // The pass that vector woke finds the arming incomplete before
            // it completes, as a descheduled arming vCPU allows: the event,
            // never a count of spins.
            while ORDER_ARMING_PASSES.load(Ordering::Acquire) == 0 {
                core::hint::spin_loop();
            }
        }
        ORDER_STATE.store(ORDER_ARMED, Ordering::Release);
        Some(0)
    }

    fn ordered_peer_task() -> Option<&'static carrick_el1_abi::CurrentTask> {
        let address = ORDER_PEER_TASK.load(Ordering::Acquire);
        // SAFETY: the peer published its retained current-task record.
        (address != 0).then(|| unsafe { &*(address as *const carrick_el1_abi::CurrentTask) })
    }

    /// A fork MM acquisition an injected root hold can refuse.
    #[derive(Clone, Copy)]
    pub enum ForkRootSite {
        Census = 1,
        Commit = 2,
    }
    static FORK_ROOT_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static FORK_ROOT_REFUSALS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// The holder an injected fork root hold names: no CPU of this zone.
    const FORK_ROOT_HOLDER: carrick_core::mm::reservation::RootHolder =
        carrick_core::mm::reservation::RootHolder::El1Slot(u32::MAX - 2);

    /// Hold the real reservation root at `index` (`mm`'s) across the next
    /// acquisition at `site` when the fixture armed it. True when held.
    pub fn hold_fork_root(
        site: ForkRootSite,
        roots: &carrick_el1::memory::reservations::X86Cpl0Reservations,
        index: usize,
        mm: carrick_el1_abi::ReservationMm,
    ) -> bool {
        FORK_ROOT_HOLD
            .compare_exchange(site as u8, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && (roots.hold_for_test(index, mm, FORK_ROOT_HOLDER)
                || carrick_x86_carrier::entry::fatal_boot!())
    }

    /// The held acquisition returned: the holder releases the root. A hold
    /// the holder no longer owns fails the run rather than leak.
    pub fn release_fork_root(
        held: bool,
        roots: &carrick_el1::memory::reservations::X86Cpl0Reservations,
        index: usize,
        refused_busy: bool,
    ) {
        if !held {
            return;
        }
        if !roots.release_test_hold(index, FORK_ROOT_HOLDER) {
            carrick_x86_carrier::entry::fatal_boot!();
        }
        if refused_busy {
            FORK_ROOT_REFUSALS.fetch_add(1, Ordering::AcqRel);
        }
    }

    static COW_SETTLE_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static COW_SETTLE_TIMED_OUT: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    /// About seconds of spinning before the hold gives up.
    const COW_SETTLE_HOLD_SPINS: u64 = 1 << 28;

    /// The armed hold engages after the supply crossing, not before the
    /// settlement crossing.
    static COW_HOLD_AT_SUPPLY: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    /// The armed hold has no spin bound.
    static COW_HOLD_UNBOUNDED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    /// Called by the user-fault owner between a COW completion and its
    /// settlement crossing, on the faulting member's CPU. While held it
    /// acknowledges shootdowns, as a member away at its crossing does.
    pub fn hold_armed_cow_settle() {
        // A sibling's copy-on-write completed while a fork is held pending:
        // the contention the fork's publication owes it did not happen.
        if FORK_COMMIT_HOLD
            .compare_exchange(
                BIRTH_HELD,
                BIRTH_RELEASED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            FORK_COMMIT_RELEASE_CAUSE.store(RELEASED_BY_PEER_COW, Ordering::Release);
        }
        hold_armed_cow(false);
    }

    /// Called by the user-fault owner after the carrier supplied its COW
    /// grant and before the member resolves the fault again.
    pub fn hold_armed_cow_supply() {
        hold_armed_cow(true);
    }

    fn hold_armed_cow(at_supply: bool) {
        if COW_HOLD_AT_SUPPLY.load(Ordering::Acquire) != at_supply {
            return;
        }
        if COW_SETTLE_HOLD
            .compare_exchange(BIRTH_ARMED, BIRTH_HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let bounded = !COW_HOLD_UNBOUNDED.swap(false, Ordering::AcqRel);
        let mut spins = 0_u64;
        while COW_SETTLE_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
            spins += 1;
            if bounded && spins > COW_SETTLE_HOLD_SPINS {
                // The sibling never released: let the crossing run and
                // report the hold's bound to the fixture.
                COW_SETTLE_TIMED_OUT.store(true, Ordering::Release);
                break;
            }
            if carrick_el1::isa::x86::interrupt::sync_user_memory_generation().is_err() {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            core::hint::spin_loop();
        }
        if at_supply {
            COW_HOLD_AT_SUPPLY.store(false, Ordering::Release);
        }
        COW_SETTLE_HOLD.store(0, Ordering::Release);
    }

    static BIRTH_WAITER: carrick_el1::lock::SpinLock<Option<carrick_sched_core::RecordRef>> =
        carrick_el1::lock::SpinLock::new(None);

    /// Called by the native birth after `reserve_birth`, before MM
    /// preparation, on the forking member's CPU.
    pub fn hold_armed_birth() {
        if BIRTH_HOLD
            .compare_exchange(BIRTH_ARMED, BIRTH_HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut spins = 0_u64;
        while BIRTH_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
            spins += 1;
            if spins > BIRTH_HOLD_SPINS {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            core::hint::spin_loop();
        }
        BIRTH_HOLD.store(0, Ordering::Release);
    }

    static FORK_COMMIT_WAITER: carrick_el1::lock::SpinLock<Option<carrick_sched_core::RecordRef>> =
        carrick_el1::lock::SpinLock::new(None);

    /// Called by the native fork before its commit, on the forking member's
    /// CPU: the parent root is fork-pending and write-protected.
    pub fn hold_armed_fork_commit() {
        if FORK_COMMIT_HOLD
            .compare_exchange(BIRTH_ARMED, BIRTH_HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if FORK_COMMIT_RELEASES_SUPPLY.swap(false, Ordering::AcqRel) {
            // The sibling's supplied grant has been ready in the pool since
            // before this fork began; its resolution now races the pending
            // fork's custody, and nothing else.
            let _ = COW_SETTLE_HOLD.compare_exchange(
                BIRTH_HELD,
                BIRTH_RELEASED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        let mut spins = 0_u64;
        while FORK_COMMIT_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
            spins += 1;
            if spins > BIRTH_HOLD_SPINS {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            // A real fork preparation returns; the hold must still
            // acknowledge a sibling's TLB shootdown on this running root.
            if carrick_el1::isa::x86::interrupt::service_shootdowns().is_err() {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            core::hint::spin_loop();
        }
        FORK_COMMIT_HOLD.store(0, Ordering::Release);
    }

    /// Called on each scheduler entry: the registered waiter has parked, so
    /// its contended wait is owned by the fork publication's release.
    pub fn release_fork_commit_on_park(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
    ) {
        let waiter = *FORK_COMMIT_WAITER.lock();
        if let Some(record) = waiter
            && matches!(
                source.zone.record(record.id).claim(),
                carrick_sched_core::Claim::Parked { .. }
            )
            && FORK_COMMIT_HOLD
                .compare_exchange(
                    BIRTH_HELD,
                    BIRTH_RELEASED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            FORK_COMMIT_RELEASE_CAUSE.store(RELEASED_BY_PARK, Ordering::Release);
            *FORK_COMMIT_WAITER.lock() = None;
        }
    }

    /// Called on each scheduler entry: the registered waiter has parked, so
    /// its contended wait is owned by the birth's release notification.
    pub fn release_birth_on_park(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
    ) {
        let waiter = *BIRTH_WAITER.lock();
        if let Some(record) = waiter
            && matches!(
                source.zone.record(record.id).claim(),
                carrick_sched_core::Claim::Parked { .. }
            )
            && BIRTH_HOLD
                .compare_exchange(
                    BIRTH_HELD,
                    BIRTH_RELEASED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            *BIRTH_WAITER.lock() = None;
        }
    }
    // Test-only actor ordering: armed by CPU0's fixture syscall; CPU0
    // publishes Parked before requesting CPU1's scheduler to release it.
    // The production object-wait queue and notification choose the wake target.
    const RELEASE_ARMED: u64 = 1;
    const RELEASE_ON_PEER: u64 = 2;
    static PEER_IDLE_RELEASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    pub fn peer_release_pending(slot: carrick_sched_core::SlotId) -> bool {
        slot.raw() == 1 && PEER_IDLE_RELEASE.load(Ordering::Acquire) == RELEASE_ON_PEER
    }

    pub fn defer_release_to_peer(slot: carrick_sched_core::SlotId) -> bool {
        match PEER_IDLE_RELEASE.load(Ordering::Acquire) {
            RELEASE_ARMED if slot.raw() == 0 => {
                PEER_IDLE_RELEASE.store(RELEASE_ON_PEER, Ordering::Release);
                carrick_el1::isa::x86::interrupt::send_resched(carrick_sched_core::SlotId::new(1))
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
                true
            }
            RELEASE_ARMED => true,
            RELEASE_ON_PEER if slot.raw() == 0 => true,
            RELEASE_ON_PEER => {
                PEER_IDLE_RELEASE.store(0, Ordering::Release);
                false
            }
            _ => false,
        }
    }

    static EDIT_PARK_PUBLISHED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    pub fn publish_edit_park() {
        EDIT_PARK_PUBLISHED.store(true, Ordering::Release);
    }

    pub fn take_edit_park() -> bool {
        EDIT_PARK_PUBLISHED.swap(false, Ordering::AcqRel)
    }

    static REPLAY_SETTLEMENT_REFUSAL: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    pub fn take_replay_settlement_refusal() -> bool {
        REPLAY_SETTLEMENT_REFUSAL.swap(false, Ordering::AcqRel)
    }

    static ANONYMOUS_WAIT_HANDBACKS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static METADATA_ON_REPROBE: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static CAUGHT_SIGNAL_ON_PARK: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static FRAME_EDITOR_REHOLD: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static SIGNAL_CLOCK_LAG: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static OWNED_COPY_BUSY: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static OWNED_COPY_REFUSALS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static OWNED_COPY_RETAINED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static OWNED_COPY_RERUNS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    type ArmedSignal = (
        carrick_sched_core::RecordRef,
        carrick_core_abi::ExecutionBinding,
    );
    static SIGNAL_ON_NEXT_PARK: carrick_el1::lock::SpinLock<Option<ArmedSignal>> =
        carrick_el1::lock::SpinLock::new(None);

    pub fn signal_clock_read_lags() -> bool {
        SIGNAL_CLOCK_LAG
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .is_ok_and(|left| left == 1)
    }

    /// Called on each scheduler entry: deliver an armed signal once its member
    /// has parked, from the executor that parked it (whose current task is
    /// still that member's), as `INJECT_CAUGHT_SIGNAL_ON_PARK` does.
    pub fn signal_parked_member(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
        task: &'static carrick_el1_abi::CurrentTask,
    ) {
        let mut slot = SIGNAL_ON_NEXT_PARK.lock();
        let armed = slot.take_if(|(_, binding)| {
            *binding == carrick_el1_linux::common_entry::execution_binding(task)
        });
        drop(slot);
        if let Some((record, binding)) = armed
            && !crate::native_process::inject_caught_signal_once_parked(
                source, task, record, binding,
            )
        {
            *SIGNAL_ON_NEXT_PARK.lock() = Some((record, binding));
        }
    }

    /// Consume the armed Busy for this exact-MM write. `owned` marks a
    /// retained-output copy, whose next completion counts as its rerun.
    pub fn take_owned_copy_busy(owned: bool) -> bool {
        let refused = OWNED_COPY_BUSY.swap(false, Ordering::AcqRel);
        if refused {
            OWNED_COPY_REFUSALS.fetch_add(1, Ordering::AcqRel);
            if owned {
                OWNED_COPY_RETAINED.store(true, Ordering::Release);
            }
        }
        refused
    }

    static OWNED_PUBLISH_GATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    /// About seconds of spinning: a gate nobody releases fails the run
    /// instead of hanging it.
    const OWNED_PUBLISH_GATE_SPINS: u64 = 1 << 32;

    /// Called by an owned copy-out right after its bytes reached guest
    /// memory. An armed gate holds a zero-word copy (a clear-tid write) here.
    pub fn hold_armed_owned_publication(bytes: &[u8]) {
        if bytes != [0_u8; 4] {
            return;
        }
        if OWNED_PUBLISH_GATE
            .compare_exchange(BIRTH_ARMED, BIRTH_HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut spins = 0_u64;
        while OWNED_PUBLISH_GATE.load(Ordering::Acquire) == BIRTH_HELD {
            spins += 1;
            if spins > OWNED_PUBLISH_GATE_SPINS {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            if carrick_el1::isa::x86::interrupt::sync_user_memory_generation().is_err() {
                carrick_x86_carrier::entry::fatal_boot!();
            }
            core::hint::spin_loop();
        }
        OWNED_PUBLISH_GATE.store(0, Ordering::Release);
    }

    /// Count the rerun of a refused owned copy before it publishes: a joiner
    /// that reads the published word in userspace may read the census at
    /// once, so the completion cannot follow the publication (#2648). Returns
    /// whether this copy took the refusal's retained rerun.
    pub fn begin_owned_copy() -> bool {
        let rerun = OWNED_COPY_RETAINED.swap(false, Ordering::AcqRel);
        if rerun {
            OWNED_COPY_RERUNS.fetch_add(1, Ordering::AcqRel);
        }
        rerun
    }

    /// The copy did not publish (it was refused again): its rerun is still
    /// owed, and nothing was visible to a joiner.
    pub fn abort_owned_copy(rerun: bool) {
        if rerun {
            OWNED_COPY_RERUNS.fetch_sub(1, Ordering::AcqRel);
            OWNED_COPY_RETAINED.store(true, Ordering::Release);
        }
    }

    pub fn take_caught_signal_on_park() -> bool {
        CAUGHT_SIGNAL_ON_PARK.swap(false, Ordering::AcqRel)
    }

    /// Whether the caught signal's frame copy must find the editor held again.
    pub fn take_frame_editor_rehold() -> bool {
        FRAME_EDITOR_REHOLD.swap(false, Ordering::AcqRel)
    }

    pub fn record_anonymous_wait_handback() {
        ANONYMOUS_WAIT_HANDBACKS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn arm_metadata_for_reprobe() {
        if METADATA_ON_REPROBE.swap(false, Ordering::AcqRel)
            && !carrick_core::mm::reservation::inject_metadata_required_once()
        {
            carrick_x86_carrier::entry::fatal_boot!();
        }
    }

    pub fn dispatch(
        native: u64,
        binding: &carrick_el1::isa::x86::context::native::CpuBinding,
    ) -> Option<u64> {
        match native {
            INJECT_PEER_IDLE_RELEASE_ONCE => PEER_IDLE_RELEASE
                .compare_exchange(0, RELEASE_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_BLOCK_SIGUSR1_AT_SECOND_CHECKPOINT => {
                // SAFETY: dispatch runs on the CPU that owns this task binding.
                let task =
                    unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
                let (_, control) = task.lifecycle_refs()?;
                BLOCK_CHECKPOINTS_LEFT.store(2, Ordering::Release);
                BLOCK_CONTROL.store(
                    control as *const carrick_el1_abi::ThreadControlSlot as usize,
                    Ordering::Release,
                );
                Some(0)
            }
            INJECT_ROOT_BUSY_ONCE => {
                carrick_core::mm::reservation::inject_root_busy_once().then_some(0)
            }
            INJECT_GRANT_CAPACITY_REFUSAL_ONCE
            | INJECT_GRANT_OCCUPIED_REFUSAL_ONCE
            | INJECT_GRANT_TERMINAL_REFUSAL_ONCE
            | INJECT_GRANT_STALE_REFUSAL_ONCE => {
                use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
                carrick_core::mm::frames::inject_grant_refusal_once(match native {
                    INJECT_GRANT_CAPACITY_REFUSAL_ONCE => DescriptorRefusal::TablesExhausted,
                    INJECT_GRANT_OCCUPIED_REFUSAL_ONCE => DescriptorRefusal::Occupied,
                    INJECT_GRANT_STALE_REFUSAL_ONCE => DescriptorRefusal::StaleRoot,
                    _ => DescriptorRefusal::WrongMm,
                })
                .then_some(0)
            }
            INJECT_GRANT_REFUSAL_CENSUS => {
                let (refusals, pages) = carrick_core::mm::frames::injected_grant_refusal_census();
                Some(refusals << 32 | pages)
            }
            INJECT_EDITOR_BUSY_ONCE => {
                carrick_sched_core::spaces::inject_editor_busy_once().then_some(0)
            }
            INJECT_PREPARED_CONFLICT_ONCE => {
                carrick_core::mm::reservation::inject_prepared_conflict_once().then_some(0)
            }
            INJECT_METADATA_REQUIRED_ONCE => {
                carrick_core::mm::reservation::inject_metadata_required_once().then_some(0)
            }
            INJECT_WAIT_PARK_CENSUS => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                Some(
                    carrick_x86_carrier::native_execution::source(slot)
                        .zone
                        .counters
                        .el1_parks
                        .load(Ordering::Acquire),
                )
            }
            INJECT_OPERATION_TOKEN_ACTIVE => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                let record = zone.record(zone.slot(slot).current()?);
                Some(u64::from(record.has_object_operation()))
            }
            INJECT_WAIT_HANDBACK_CENSUS => Some(ANONYMOUS_WAIT_HANDBACKS.load(Ordering::Acquire)),
            INJECT_METADATA_ON_REPROBE_ONCE => METADATA_ON_REPROBE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ => SIGNAL_CLOCK_LAG
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                let record = zone.record_ref(zone.slot(slot).current()?);
                let execution = carrick_el1_linux::common_entry::execution_binding(
                    carrick_x86_carrier::native_execution::task(),
                );
                let mut armed = SIGNAL_ON_NEXT_PARK.lock();
                armed.is_none().then(|| {
                    *armed = Some((record, execution));
                    0
                })
            }
            INJECT_HOLD_NEXT_BIRTH => BIRTH_HOLD
                .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_BIRTH_HELD => {
                if BIRTH_HOLD.load(Ordering::Acquire) != BIRTH_HELD {
                    return Some(0);
                }
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                *BIRTH_WAITER.lock() = Some(zone.record_ref(zone.slot(slot).current()?));
                Some(1)
            }
            INJECT_RELEASE_HELD_BIRTH => {
                *BIRTH_WAITER.lock() = None;
                let _ = BIRTH_HOLD.compare_exchange(
                    BIRTH_HELD,
                    BIRTH_RELEASED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Some(0)
            }
            INJECT_GATE_AT_NEXT_OPERATION_SWITCH_IN => arm_gate(GATE_OPERATION, binding),
            INJECT_GATE_AT_NEXT_RESULT_SWITCH_IN => arm_gate(GATE_RESULT, binding),
            INJECT_GATE_CENSUS => Some(
                GATE_PARKS.load(Ordering::Acquire)
                    | GATE_POLLS.load(Ordering::Acquire) << 16
                    | GATE_RAISES.load(Ordering::Acquire) << 32,
            ),
            INJECT_GATE_TARGET_STATE => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                let record = carrick_sched_core::RecordId::from_raw(
                    GATE_TARGET.load(Ordering::Acquire).wrapping_sub(1),
                )?;
                let kind: u64 = match zone.record(record).claim() {
                    carrick_sched_core::Claim::Parked { .. } => 1,
                    carrick_sched_core::Claim::Queued { .. } => 2,
                    carrick_sched_core::Claim::OnCpu { .. } => 3,
                    _ => 4,
                };
                Some(128 + 8 * kind + u64::from(GATE_STATE.load(Ordering::Acquire)))
            }
            INJECT_GATE_TARGET_PARKED => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                let record = carrick_sched_core::RecordId::from_raw(
                    GATE_TARGET.load(Ordering::Acquire).wrapping_sub(1),
                )?;
                if matches!(
                    zone.record(record).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                ) {
                    return Some(1);
                }
                let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
                carrick_el1::isa::x86::interrupt::send_resched(peer)
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
                Some(0)
            }
            INJECT_HOLD_NEXT_FORK_COMMIT => FORK_COMMIT_HOLD
                .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_FORK_COMMIT_RELEASES_SUPPLY => {
                // The supply hold ends on the fork's event, never on a
                // spin bound.
                COW_HOLD_UNBOUNDED.store(true, Ordering::Release);
                FORK_COMMIT_RELEASES_SUPPLY.store(true, Ordering::Release);
                Some(0)
            }
            INJECT_REGISTER_FORK_COMMIT_WAITER => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                *FORK_COMMIT_WAITER.lock() = Some(zone.record_ref(zone.slot(slot).current()?));
                Some(0)
            }
            INJECT_FORK_COMMIT_RELEASE_CAUSE => {
                Some(u64::from(FORK_COMMIT_RELEASE_CAUSE.load(Ordering::Acquire)))
            }
            INJECT_FORK_COMMIT_HELD => {
                if FORK_COMMIT_HOLD.load(Ordering::Acquire) != BIRTH_HELD {
                    return Some(0);
                }
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                *FORK_COMMIT_WAITER.lock() = Some(zone.record_ref(zone.slot(slot).current()?));
                Some(1)
            }
            INJECT_RELEASE_HELD_FORK_COMMIT => {
                *FORK_COMMIT_WAITER.lock() = None;
                let _ = FORK_COMMIT_HOLD.compare_exchange(
                    BIRTH_HELD,
                    BIRTH_RELEASED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                Some(0)
            }
            INJECT_HOLD_NEXT_COW_SETTLE => COW_SETTLE_HOLD
                .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_HOLD_NEXT_COW_SETTLE_UNTIL_RELEASED => {
                if COW_SETTLE_HOLD
                    .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return None;
                }
                COW_HOLD_UNBOUNDED.store(true, Ordering::Release);
                Some(0)
            }
            INJECT_HOLD_NEXT_COW_SUPPLY => {
                if COW_SETTLE_HOLD
                    .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return None;
                }
                COW_HOLD_AT_SUPPLY.store(true, Ordering::Release);
                Some(0)
            }
            INJECT_COW_SETTLE_HELD => {
                if COW_SETTLE_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
                    return Some(1);
                }
                // Not held yet: kick the other CPU's scheduler, so a woken
                // sibling queued behind this polling member is taken by the
                // idle CPU instead of waiting for this one to yield.
                let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
                carrick_el1::isa::x86::interrupt::send_resched(peer)
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
                Some(0)
            }
            INJECT_FORK_CENSUS_ROOT_HELD_ONCE | INJECT_FORK_COMMIT_ROOT_HELD_ONCE => {
                let site = if native == INJECT_FORK_CENSUS_ROOT_HELD_ONCE {
                    ForkRootSite::Census
                } else {
                    ForkRootSite::Commit
                };
                FORK_ROOT_HOLD
                    .compare_exchange(0, site as u8, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                    .then_some(0)
            }
            INJECT_FORK_ROOT_HOLD_CENSUS => Some(FORK_ROOT_REFUSALS.load(Ordering::Acquire)),
            INJECT_HOLD_PEER_SCAN => {
                let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
                if SCAN_HOLD
                    .compare_exchange(0, SCAN_ARMED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return None;
                }
                SCAN_HOLD_SLOT.store(peer.raw() + 1, Ordering::Release);
                carrick_el1::isa::x86::interrupt::send_resched(peer)
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
                Some(0)
            }
            INJECT_PEER_SCAN_HELD => {
                Some(u64::from(SCAN_HOLD.load(Ordering::Acquire) >= SCAN_HELD))
            }
            INJECT_ORDER_PEER_AFTER_IDLE_READ => arm_peer_order(binding, ORDER_AFTER_READ, false),
            INJECT_ORDER_PEER_AFTER_IDLE_READ_LATE_ARM => {
                arm_peer_order(binding, ORDER_AFTER_READ, true)
            }
            INJECT_ORDER_PEER_BEFORE_IDLE_HLT => arm_peer_order(binding, ORDER_BEFORE_HLT, false),
            INJECT_ORDER_PEER_REACHED => Some(u64::from(
                ORDER_STATE.load(Ordering::Acquire) >= ORDER_REACHED,
            )),
            INJECT_ORDER_PEER_PUBLISHED => ORDER_STATE
                .compare_exchange(
                    ORDER_REACHED,
                    ORDER_PUBLISHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
                .then_some(0),
            INJECT_ORDER_PEER_CENSUS => Some(ORDER_PASSES.load(Ordering::Acquire)),
            INJECT_MARK_PEER_HOST_WORK => {
                if ORDER_STATE.load(Ordering::Acquire) != ORDER_REACHED {
                    return None;
                }
                ordered_peer_task()?.linux.mark_pending_host_work();
                Some(0)
            }
            INJECT_PEER_HOST_WORK_PENDING => Some(u64::from(
                ordered_peer_task()?.linux.has_pending_host_work(),
            )),
            INJECT_CURRENT_CPU => Some(u64::from(binding.cpu_slot)),
            INJECT_RESCHED_BUSY_ONCE => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(1, 0, None).then_some(0)
            }
            INJECT_RESCHED_BUSY_THROUGH_LAST_RETURN => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(u32::MAX, 1, None)
                    .then_some(0)
            }
            INJECT_RESCHED_STALL_AT_LAST_RETURN => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(
                    2,
                    0,
                    Some(carrick_el1::isa::x86::interrupt::ReschedStall::BeforePoll),
                )
                .then_some(0)
            }
            INJECT_RESCHED_STALL_AFTER_BUSY_POLL => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(
                    u32::MAX,
                    1,
                    Some(carrick_el1::isa::x86::interrupt::ReschedStall::AfterBusyPoll),
                )
                .then_some(0)
            }
            INJECT_RESCHED_STALL_AFTER_BUSY_SEND => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(
                    3,
                    0,
                    Some(carrick_el1::isa::x86::interrupt::ReschedStall::AfterBusySend(3)),
                )
                .then_some(0)
            }
            INJECT_RESCHED_TWO_OWED_STALLED => {
                carrick_el1::isa::x86::interrupt::inject_resched_two_owed_stalled().then_some(0)
            }
            INJECT_RESCHED_OWED_AT_PARK => {
                if !carrick_el1::isa::x86::interrupt::inject_resched_busy(u32::MAX, 0, None) {
                    return None;
                }
                OWE_AT_PARK_SLOT.store(binding.cpu_slot + 1, Ordering::Release);
                Some(0)
            }
            INJECT_RESCHED_ICR_FLAPPING => {
                carrick_el1::isa::x86::interrupt::inject_resched_busy(u32::MAX, 0, None)
                    .then_some(0)
            }
            INJECT_RESCHED_BUSY_CENSUS => {
                let (injected, resent, waits, site, stalls) =
                    carrick_el1::isa::x86::interrupt::resched_busy_census();
                Some(injected | resent << 16 | waits << 32 | u64::from(site) << 48 | stalls << 56)
            }
            INJECT_EDITOR_RELEASED_BEFORE_PARK_ONCE => EARLY_RELEASE_TASK
                .compare_exchange(0, binding.task_address, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_EDITOR_RELEASED_BEFORE_PARK_CENSUS => {
                Some(EARLY_RELEASES.load(Ordering::Acquire))
            }
            INJECT_SELECTED_SERVE_BUSY_ONCE => SELECTED_SERVE_BUSY_TASK
                .compare_exchange(0, binding.task_address, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_SELECTED_SERVE_BUSY_CENSUS => {
                Some(SELECTED_SERVE_BUSIES.load(Ordering::Acquire))
            }
            INJECT_COW_SETTLE_TIMED_OUT => {
                Some(u64::from(COW_SETTLE_TIMED_OUT.load(Ordering::Acquire)))
            }
            INJECT_RELEASE_HELD_COW_SETTLE => {
                // A hold not yet engaged is disarmed: no later COW waits.
                let _ = COW_SETTLE_HOLD
                    .compare_exchange(
                        BIRTH_HELD,
                        BIRTH_RELEASED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .or_else(|_| {
                        COW_HOLD_AT_SUPPLY.store(false, Ordering::Release);
                        COW_HOLD_UNBOUNDED.store(false, Ordering::Release);
                        COW_SETTLE_HOLD.compare_exchange(
                            BIRTH_ARMED,
                            0,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                    });
                Some(0)
            }
            INJECT_OWNED_COPY_BUSY_ONCE => {
                (!OWNED_COPY_BUSY.swap(true, Ordering::AcqRel)).then_some(0)
            }
            INJECT_REPLAY_SETTLEMENT_REFUSAL_ONCE => {
                (!REPLAY_SETTLEMENT_REFUSAL.swap(true, Ordering::AcqRel)).then_some(0)
            }
            INJECT_OWNED_COPY_PUBLISH_GATE => OWNED_PUBLISH_GATE
                .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_OWNED_COPY_PUBLISH_HELD => {
                if OWNED_PUBLISH_GATE.load(Ordering::Acquire) == BIRTH_HELD {
                    return Some(1);
                }
                let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
                carrick_el1::isa::x86::interrupt::send_resched(peer)
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot!());
                Some(0)
            }
            INJECT_RELEASE_OWNED_COPY_PUBLISH => {
                let _ = OWNED_PUBLISH_GATE
                    .compare_exchange(
                        BIRTH_HELD,
                        BIRTH_RELEASED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .or_else(|_| {
                        OWNED_PUBLISH_GATE.compare_exchange(
                            BIRTH_ARMED,
                            0,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                    });
                Some(0)
            }
            INJECT_HOLD_EDITOR_AT_FORK_COW_SETTLE | INJECT_HOLD_EDITOR_AT_COPY_COW_SETTLE => {
                // The caller is the member whose next fork the hold covers.
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                // A CPU's home thread runs as its slot's host record.
                let record = zone
                    .slot(slot)
                    .current()
                    .or_else(|| zone.slot(slot).host_record())?;
                let waiter = zone.record_ref(record);
                let mut armed = if native == INJECT_HOLD_EDITOR_AT_FORK_COW_SETTLE {
                    FORK_COW_EDITOR_WAITER.lock()
                } else {
                    COPY_COW_EDITOR_WAITER.lock()
                };
                if armed.is_some() || FORK_COW_EDITOR.lock().is_some() {
                    return None;
                }
                *armed = Some(waiter);
                Some(0)
            }
            INJECT_FORK_COW_SETTLE_CENSUS => Some(
                ((FORK_COW_EDITOR_HOLDS.load(Ordering::Acquire) & 0xffff) << 32)
                    | ((FORK_COW_EDITOR_PARKED_RELEASES.load(Ordering::Acquire) & 0xffff) << 16)
                    | (FORK_COW_SETTLED.load(Ordering::Acquire) & 0xffff),
            ),
            INJECT_COPY_COW_EDITOR_HELD_CENSUS => {
                Some(COPY_COW_EDITOR_HELD_CROSSINGS.load(Ordering::Acquire))
            }
            INJECT_MISLABELLED_RESUME_CENSUS => Some(MISLABELLED_RESUMES.load(Ordering::Acquire)),
            INJECT_OWNED_COPY_CENSUS => Some(
                (OWNED_COPY_REFUSALS.load(Ordering::Acquire) << 32)
                    | (OWNED_COPY_RERUNS.load(Ordering::Acquire) & u64::from(u32::MAX)),
            ),
            INJECT_CAUGHT_SIGNAL_ON_PARK => {
                if !CAUGHT_SIGNAL_ON_PARK.swap(true, Ordering::AcqRel)
                    && carrick_sched_core::spaces::inject_editor_busy_once()
                {
                    Some(0)
                } else {
                    None
                }
            }
            INJECT_CAUGHT_SIGNAL_ON_PARK_FRAME_HELD => {
                if !CAUGHT_SIGNAL_ON_PARK.swap(true, Ordering::AcqRel)
                    && !FRAME_EDITOR_REHOLD.swap(true, Ordering::AcqRel)
                    && carrick_sched_core::spaces::inject_editor_busy_once()
                {
                    Some(0)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// The production CPL0 transport owed by a completed shared dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionBoundary {
    HostCustody,
    Continue,
    Work,
    Forward,
    Invalid,
}

pub const fn production_boundary(action: Action) -> ProductionBoundary {
    match action {
        Action::Served => ProductionBoundary::Continue,
        Action::ServedWithWork => ProductionBoundary::Work,
        Action::Forward => ProductionBoundary::Forward,
        Action::Idle => ProductionBoundary::Invalid,
        Action::HostCustody => ProductionBoundary::HostCustody,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_work_requires_the_work_exit_before_return() {
        assert_eq!(
            production_boundary(Action::ServedWithWork),
            ProductionBoundary::Work
        );
    }

    #[test]
    fn host_thread_retirement_keeps_distinct_cpl0_transport() {
        assert_eq!(
            production_boundary(Action::HostCustody),
            ProductionBoundary::HostCustody
        );
    }
}

// Non-delegated x86 memory hooks have no host CommitOwed consumer. Refuse
// before acquiring an editor; delegated mappings keep their existing route.
#[unsafe(no_mangle)]
pub static CARRICK_CPL0_ANONYMOUS_HOOK_REFUSALS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[cfg(any(target_os = "none", test))]
pub(crate) fn refuse_anonymous_permission(
    counter: &core::sync::atomic::AtomicU64,
) -> carrick_personality_linux::pending_anonymous::PermissionStep {
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    carrick_personality_linux::pending_anonymous::PermissionStep::Forward
}

#[cfg(any(target_os = "none", test))]
pub(crate) fn refuse_anonymous_retirement(
    counter: &core::sync::atomic::AtomicU64,
) -> carrick_personality_linux::pending_anonymous::RetirementStep {
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    carrick_personality_linux::pending_anonymous::RetirementStep::Forward
}

/// Invalid CPU slots retain the previous forwarding path, never a fatal.
#[cfg(any(target_os = "none", test))]
pub(crate) fn anonymous_call(
    call: carrick_personality_linux::entry::CanonicalCall,
    cpu_slot: u32,
    return_pc: carrick_guest_arch::UserVa,
) -> Option<carrick_el1::memory::AnonymousCall> {
    let slot = usize::try_from(cpu_slot)
        .ok()
        .and_then(carrick_sched_core::SlotId::from_index)?;
    // This venue projects one task, independently of its CPU slot.
    Some(carrick_el1::memory::AnonymousCall::new(
        carrick_core::CallOrdinal::from_raw(call.canonical.raw()),
        call.args,
        0,
        slot,
        return_pc,
    ))
}

#[cfg(test)]
mod anonymous_refusal_tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    #[test]
    fn dead_hooks_count_refusals_without_commit_obligations() {
        let count = AtomicU64::new(0);
        assert!(matches!(
            refuse_anonymous_permission(&count),
            carrick_personality_linux::pending_anonymous::PermissionStep::Forward
        ));
        assert!(matches!(
            refuse_anonymous_retirement(&count),
            carrick_personality_linux::pending_anonymous::RetirementStep::Forward
        ));
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }
    /// Linux decoding stays at the personality edge, before the neutral view.
    #[test]
    fn both_linux_decoders_project_the_same_anonymous_call() {
        use carrick_el1::memory::AnonymousCallView;
        use carrick_personality_linux::entry::{decode_aarch64, decode_x86_64};
        let args = [0x100000, 0x3000, 1, 0, 0, 0];
        for (arm_nr, x86_nr) in [(222, 9), (226, 10), (215, 11)] {
            let arm = decode_aarch64(arm_nr, args, 0x8000);
            let x86 = decode_x86_64(x86_nr, args, 0x8000);
            let pc = carrick_guest_arch::UserVa::new(0x40004);
            let arm = anonymous_call(arm, 7, pc).unwrap();
            let x86 = anonymous_call(x86, 7, pc).unwrap();
            assert_eq!(arm.canonical(), x86.canonical());
            assert_eq!(x86.canonical().raw(), arm_nr);
            assert_eq!(arm.arguments(), args);
            assert_eq!(x86.arguments(), args);
            assert_eq!(arm.return_address(), pc);
            assert_eq!(x86.return_address(), pc);
            assert_eq!(x86.task_index(), 0);
            assert_eq!(x86.slot().index(), 7);
        }
    }
    #[test]
    fn invalid_anonymous_slot_declines_without_fatal() {
        let call = carrick_personality_linux::entry::decode_x86_64(10, [0; 6], 0x8000);
        let pc = carrick_guest_arch::UserVa::new(0x40004);
        assert!(anonymous_call(call, u32::MAX, pc).is_none());
        assert_eq!(anonymous_call(call, 7, pc).unwrap().slot().index(), 7);
    }

    #[test]
    fn syscall_copy_contention_parks_instead_of_becoming_efault() {
        let source = include_str!("linux_personality.rs");
        assert!(
            source.matches("anonymous::park_contended_fault(").count() >= 3,
            "#PF, exec staging, and host-file staging must share the MM-release park"
        );
        assert!(
            !source.contains("Some(stage.refused())\n                            }\n                            UserFaultSupply::Signal"),
            "host-file staging must not classify contention as a refused user copy"
        );
        assert!(
            !source.contains("frame.rax = carrick_syscall_abi::LINUX_EFAULT.guest_retval() as u64;\n                    CompletionRoute::Served\n                }\n                UserFaultSupply::Signal"),
            "exec staging must not classify contention as EFAULT"
        );
    }

    #[test]
    fn selected_owner_waits_park_instead_of_reaching_ud2() {
        let source = include_str!("linux_personality.rs");
        assert!(
            source.contains("UserFaultSupply::TypedRelease(wait)"),
            "the Selected arm must retain the typed owner wait through parking"
        );
        assert!(
            !source.contains(
                "PortalWaitCause::ReservationPool | PortalWaitCause::HostReadiness => None"
            ),
            "reservation-pool and host-readiness receipts name real object queues"
        );
        assert!(
            !source.contains(
                "Err(carrick_core::mm::transaction::MmError::Wait(wait)) => portal_wait_cause(wait)"
            ),
            "a typed owner wait must not collapse to Unresolved(9)"
        );
    }
}

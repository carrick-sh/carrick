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
    pub const INJECT_EDITOR_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe11;
    pub const INJECT_PREPARED_CONFLICT_ONCE: u64 = 0xffff_ffff_ffff_fe12;
    pub const INJECT_WAIT_PARK_CENSUS: u64 = 0xffff_ffff_ffff_fe13;
    pub const INJECT_METADATA_REQUIRED_ONCE: u64 = 0xffff_ffff_ffff_fe14;
    pub const INJECT_WAIT_HANDBACK_CENSUS: u64 = 0xffff_ffff_ffff_fe15;
    pub const INJECT_METADATA_ON_REPROBE_ONCE: u64 = 0xffff_ffff_ffff_fe16;
    pub const INJECT_CAUGHT_SIGNAL_ON_PARK: u64 = 0xffff_ffff_ffff_fe17;
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
    /// The calling member's next owner fault's application step is Busy
    /// once (#2141): after its physical supply crossing returns, before the
    /// guest applies it. Another member's fault never takes it (#2332).
    /// The synthetic editor holder releases once the faulting member parks.
    pub const INJECT_POST_SUPPLY_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe30;
    /// Post-supply Busies injected so far: COW supplies in the high 32 bits,
    /// Prepare supplies in the low 32 bits.
    pub const INJECT_POST_SUPPLY_CENSUS: u64 = 0xffff_ffff_ffff_fe31;
    /// As [`INJECT_POST_SUPPLY_BUSY_ONCE`], but the synthetic holder stays
    /// held after the faulting member parks, until another member's
    /// [`INJECT_RELEASE_POST_SUPPLY_HOLD`].
    pub const INJECT_POST_SUPPLY_BUSY_HELD: u64 = 0xffff_ffff_ffff_fe32;
    /// Release a held post-supply holder from another member: publish the
    /// held MM's Editor release, as a real holder's drop does, whether or
    /// not its waiter has parked yet. 1 if released.
    pub const INJECT_RELEASE_POST_SUPPLY_HOLD: u64 = 0xffff_ffff_ffff_fe33;
    /// 1 once a member parked on an injected contention and no release has
    /// taken that park yet: a fixture orders its release after the park.
    pub const INJECT_POST_SUPPLY_PARKED: u64 = 0xffff_ffff_ffff_fe36;
    /// The next scheduler install of an address space meets its gate raised
    /// once (#2295), between the record's switch-in and the install, as a
    /// host exclusion on another vCPU raises it. The holder lowers it, with
    /// its Gate release, on the refused slot's next scheduler pass.
    pub const INJECT_INSTALL_GATE_ONCE: u64 = 0xffff_ffff_ffff_fe34;
    /// Injected install gates: raised in the high 32 bits, lowered in the
    /// low 32 bits.
    pub const INJECT_INSTALL_GATE_CENSUS: u64 = 0xffff_ffff_ffff_fe35;
    static INSTALL_GATE_ARMED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    /// The raised space's index plus one, or 0.
    static INSTALL_GATE_RAISED: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    static INSTALL_GATE_CENSUS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// Called after a record's switch-in, before its space is installed:
    /// raise that space's gate, if armed.
    pub fn raise_gate_before_install(
        zone: &carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>,
        mm: u64,
    ) {
        if !INSTALL_GATE_ARMED.swap(false, Ordering::AcqRel) {
            return;
        }
        let Some(index) = zone.spaces.find(mm) else {
            carrick_x86_carrier::entry::fatal_boot();
        };
        zone.spaces.raise(index);
        INSTALL_GATE_PASSES.store(2, Ordering::Release);
        INSTALL_GATE_RAISED.store(index.index() + 1, Ordering::Release);
        INSTALL_GATE_CENSUS.fetch_add(1 << 32, Ordering::AcqRel);
    }

    /// Scheduler passes left before the holder lowers an injected gate.
    static INSTALL_GATE_PASSES: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

    /// Called on each scheduler pass: on the second pass after the refusal
    /// (the first sees the refused record queued behind the raised gate),
    /// the holder lowers the injected gate through the production release,
    /// which publishes its Gate release.
    pub fn lower_injected_install_gate(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
    ) {
        if INSTALL_GATE_RAISED.load(Ordering::Acquire) == 0
            || INSTALL_GATE_PASSES
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                    left.checked_sub(1)
                })
                .is_ok_and(|left| left > 1)
        {
            return;
        }
        let raised = INSTALL_GATE_RAISED.swap(0, Ordering::AcqRel);
        let Some(index) = raised
            .checked_sub(1)
            .and_then(carrick_sched_core::spaces::SpaceIndex::from_index)
        else {
            return;
        };
        carrick_core::wait::space_access(source.zone, source.slot, crate::native_process::release)
            .lower(index);
        INSTALL_GATE_CENSUS.fetch_add(1, Ordering::AcqRel);
    }

    /// The member that armed the next post-supply Busy (#2332): only its
    /// own fault takes it. A fork child's first COW fault on the other vCPU
    /// would otherwise take a held Busy no one releases.
    static POST_SUPPLY_BUSY: carrick_el1::lock::SpinLock<Option<carrick_core_abi::ExecutionBinding>> =
        carrick_el1::lock::SpinLock::new(None);

    /// Arm the next post-supply Busy for the member running on `binding`.
    fn arm_post_supply_busy(
        binding: &carrick_el1::isa::x86::context::native::CpuBinding,
    ) -> Option<u64> {
        // SAFETY: dispatch runs on the CPU that owns this task binding.
        let task = unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
        let mut armed = POST_SUPPLY_BUSY.lock();
        if armed.is_some() {
            return None;
        }
        *armed = Some(carrick_el1_linux::common_entry::execution_binding(task));
        Some(0)
    }
    static POST_SUPPLY_HOLD: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    /// Whether a held post-supply holder must outlive its waiter's park.
    pub fn post_supply_held() -> bool {
        POST_SUPPLY_HOLD.load(Ordering::Acquire)
    }
    static POST_SUPPLY_CENSUS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// Called once an owner fault's supply crossing returned: hold this
    /// MM's editor (only this MM's) for the application step that follows,
    /// if armed.
    pub fn hold_editor_after_supply(task: &carrick_el1_abi::CurrentTask, mm: u64, cow: bool) {
        let binding = carrick_el1_linux::common_entry::execution_binding(task);
        if POST_SUPPLY_BUSY
            .lock()
            .take_if(|armed| *armed == binding)
            .is_none()
        {
            return;
        }
        if !carrick_sched_core::spaces::inject_editor_busy_once_for(mm) {
            carrick_x86_carrier::entry::fatal_boot();
        }
        POST_SUPPLY_CENSUS.fetch_add(if cow { 1 << 32 } else { 1 }, Ordering::AcqRel);
    }
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
    /// The calling member's CPU slot, so the fixture can keep the held
    /// member off its poller's CPU.
    pub const INJECT_CURRENT_CPU: u64 = 0xffff_ffff_ffff_fe26;
    static COW_SETTLE_HOLD: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static COW_SETTLE_TIMED_OUT: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    /// About seconds of spinning before the hold gives up.
    const COW_SETTLE_HOLD_SPINS: u64 = 1 << 28;

    /// Called by the user-fault owner between a COW completion and its
    /// settlement crossing, on the faulting member's CPU. While held it
    /// acknowledges shootdowns, as a member away at its crossing does.
    pub fn hold_armed_cow_settle() {
        if COW_SETTLE_HOLD
            .compare_exchange(BIRTH_ARMED, BIRTH_HELD, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let mut spins = 0_u64;
        while COW_SETTLE_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
            spins += 1;
            if spins > COW_SETTLE_HOLD_SPINS {
                // The sibling never released: let the crossing run and
                // report the hold's bound to the fixture.
                COW_SETTLE_TIMED_OUT.store(true, Ordering::Release);
                break;
            }
            if carrick_el1::isa::x86::interrupt::sync_user_memory_generation().is_err() {
                carrick_x86_carrier::entry::fatal_boot();
            }
            core::hint::spin_loop();
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
                carrick_x86_carrier::entry::fatal_boot();
            }
            core::hint::spin_loop();
        }
        BIRTH_HOLD.store(0, Ordering::Release);
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
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot());
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

    fn edit_park_published() -> bool {
        EDIT_PARK_PUBLISHED.load(Ordering::Acquire)
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

    pub fn record_owned_copy_done() {
        if OWNED_COPY_RETAINED.swap(false, Ordering::AcqRel) {
            OWNED_COPY_RERUNS.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn take_caught_signal_on_park() -> bool {
        CAUGHT_SIGNAL_ON_PARK.swap(false, Ordering::AcqRel)
    }

    pub fn record_anonymous_wait_handback() {
        ANONYMOUS_WAIT_HANDBACKS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn arm_metadata_for_reprobe() {
        if METADATA_ON_REPROBE.swap(false, Ordering::AcqRel)
            && !carrick_core::mm::reservation::inject_metadata_required_once()
        {
            carrick_x86_carrier::entry::fatal_boot();
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
            INJECT_HOLD_NEXT_COW_SETTLE => COW_SETTLE_HOLD
                .compare_exchange(0, BIRTH_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_COW_SETTLE_HELD => {
                if COW_SETTLE_HOLD.load(Ordering::Acquire) == BIRTH_HELD {
                    return Some(1);
                }
                // Not held yet: kick the other CPU's scheduler, so a woken
                // sibling queued behind this polling member is taken by the
                // idle CPU instead of waiting for this one to yield.
                let peer = carrick_sched_core::SlotId::new(u8::from(binding.cpu_slot == 0));
                carrick_el1::isa::x86::interrupt::send_resched(peer)
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot());
                Some(0)
            }
            INJECT_CURRENT_CPU => Some(u64::from(binding.cpu_slot)),
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
                        COW_SETTLE_HOLD.compare_exchange(
                            BIRTH_ARMED,
                            0,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                    });
                Some(0)
            }
            INJECT_POST_SUPPLY_BUSY_ONCE => arm_post_supply_busy(binding),
            INJECT_INSTALL_GATE_ONCE => {
                (!INSTALL_GATE_ARMED.swap(true, Ordering::AcqRel)).then_some(0)
            }
            INJECT_INSTALL_GATE_CENSUS => Some(INSTALL_GATE_CENSUS.load(Ordering::Acquire)),
            INJECT_POST_SUPPLY_CENSUS => Some(POST_SUPPLY_CENSUS.load(Ordering::Acquire)),
            INJECT_POST_SUPPLY_PARKED => Some(u64::from(edit_park_published())),
            INJECT_POST_SUPPLY_BUSY_HELD => {
                if POST_SUPPLY_HOLD.swap(true, Ordering::AcqRel) {
                    return None;
                }
                arm_post_supply_busy(binding)
            }
            INJECT_RELEASE_POST_SUPPLY_HOLD => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                if !POST_SUPPLY_HOLD.swap(false, Ordering::AcqRel) {
                    return None;
                }
                Some(u64::from(crate::anonymous::release_held_editor(
                    carrick_x86_carrier::native_execution::source(slot),
                )))
            }
            INJECT_OWNED_COPY_BUSY_ONCE => {
                (!OWNED_COPY_BUSY.swap(true, Ordering::AcqRel)).then_some(0)
            }
            INJECT_REPLAY_SETTLEMENT_REFUSAL_ONCE => {
                (!REPLAY_SETTLEMENT_REFUSAL.swap(true, Ordering::AcqRel)).then_some(0)
            }
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
}

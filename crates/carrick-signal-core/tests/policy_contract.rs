//! VM-free preparation for kernel.el1.signal-delivery-owner (landing C).
//! Authority: signal(7), sigaction(2), sigprocmask(2), sigsuspend(2),
//! setitimer(2), wait(2), clone(2), fork(2), execve(2), https://man7.org/.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_signal_core::SignalSet;
use carrick_signal_core::policy::*;
use carrick_signal_core::timer::*;
use carrick_signal_core::wait::*;
use std::collections::BTreeMap;

fn sig(number: i32) -> Signal {
    Signal::from_number(number).unwrap()
}
fn set(numbers: &[i32]) -> SignalSet {
    numbers
        .iter()
        .fold(SignalSet::default(), |s, &n| s.with(sig(n)))
}
fn mask(numbers: &[i32]) -> SigBlockMask {
    SigBlockMask::blocking_all_of(set(numbers))
}
fn caught(flags: ActionFlags, blocked: &[i32]) -> Action {
    Action {
        disposition: Disposition::Handler(HandlerAddress(0x4000)),
        flags,
        mask: set(blocked),
        restorer: None,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TaskKey {
    id: u32,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ThreadKey {
    task: TaskKey,
    tid: u32,
    generation: u64,
}
fn task(id: u32, generation: u64) -> TaskKey {
    TaskKey { id, generation }
}
fn thread(task: TaskKey, tid: u32) -> ThreadKey {
    ThreadKey {
        task,
        tid,
        generation: 1,
    }
}

#[test]
fn actions_default_ignore_handler_and_uncatchable_signals() {
    let mut actions = ActionTable::default();
    for (number, expected) in [
        (17, Delivery::Ignore),
        (23, Delivery::Ignore),
        (28, Delivery::Ignore),
        (18, Delivery::Continue),
        (19, Delivery::Stop),
        (20, Delivery::Stop),
        (21, Delivery::Stop),
        (22, Delivery::Stop),
        (15, Delivery::Terminate { core_dump: false }),
        (11, Delivery::Terminate { core_dump: true }),
        (32, Delivery::Terminate { core_dump: false }),
    ] {
        assert_eq!(
            actions.prepare_delivery(sig(number), &mut MaskState::default()),
            expected
        );
    }
    let ignored = Action {
        disposition: Disposition::Ignore,
        ..Action::default()
    };
    actions.install(sig(10), ignored).unwrap();
    assert_eq!(
        actions.prepare_delivery(sig(10), &mut MaskState::default()),
        Delivery::Ignore
    );
    for number in [9, 19] {
        assert_eq!(
            actions.install(sig(number), ignored),
            Err(ActionError::Uncatchable)
        );
        assert_eq!(actions.action(sig(number)), Action::default());
    }
    assert_eq!(Signal::from_number(0), None);
    assert_eq!(Signal::from_number(65), None);
    assert!(!sig(31).is_realtime());
    assert!(sig(32).is_realtime());
}

#[test]
fn handler_entry_resets_action_and_composes_mask_without_losing_siginfo() {
    let mut actions = ActionTable::default();
    let action = caught(
        ActionFlags {
            reset_hand: true,
            restart: true,
            siginfo: true,
            ..ActionFlags::default()
        },
        &[12, 9, 19],
    );
    actions.install(sig(10), action).unwrap();
    let mut masks = MaskState::new(mask(&[2]));
    let Delivery::Handler(delivery) = actions.prepare_delivery(sig(10), &mut masks) else {
        unreachable!()
    };
    assert_eq!(delivery.address, HandlerAddress(0x4000));
    assert!(delivery.siginfo);
    assert!(delivery.restart);
    assert_eq!(delivery.restore_mask, mask(&[2]));
    assert_eq!(masks.effective(), mask(&[2, 10, 12]));
    assert_eq!(
        actions.action(sig(10)),
        Action {
            disposition: Disposition::Default,
            ..action
        },
        "one-shot reset preserves flags and mask for action queries"
    );
    masks.restore_after_handler(delivery.restore_mask);
    assert_eq!(masks.effective(), mask(&[2]));
    assert_eq!(
        actions.prepare_delivery(sig(10), &mut masks),
        Delivery::Terminate { core_dump: false }
    );

    // SA_NODEFER removes only the implicit self-block, not an explicit sa_mask.
    for explicit_self in [false, true] {
        let explicit = if explicit_self {
            &[10, 12][..]
        } else {
            &[12][..]
        };
        actions
            .install(
                sig(10),
                caught(
                    ActionFlags {
                        nodefer: true,
                        ..ActionFlags::default()
                    },
                    explicit,
                ),
            )
            .unwrap();
        let mut masks = MaskState::default();
        assert!(matches!(
            actions.prepare_delivery(sig(10), &mut masks),
            Delivery::Handler(_)
        ));
        assert_eq!(masks.effective().contains(sig(10)), explicit_self);
        assert!(masks.effective().contains(sig(12)));
        assert_eq!(
            actions.action(sig(10)).disposition,
            Disposition::Handler(HandlerAddress(0x4000))
        );
    }
}

#[test]
fn masks_and_temporary_masks_replace_restore_and_reject_nested_waits() {
    let mut state = MaskState::new(mask(&[10, 9, 19]));
    assert_eq!(state.effective(), mask(&[10]));
    state.change(MaskChange::Block(set(&[12]))).unwrap();
    state.change(MaskChange::Unblock(set(&[10]))).unwrap();
    assert_eq!(state.effective(), mask(&[12]));
    state.change(MaskChange::Set(set(&[10]))).unwrap();
    // ppoll/pselect/sigsuspend replace the persistent mask; they never union it.
    state.begin_temporary(mask(&[12, 9, 19])).unwrap();
    assert_eq!(state.effective(), mask(&[12]));
    assert_eq!(state.select(set(&[10, 12])), set(&[10]));
    assert_eq!(
        state.begin_temporary(mask(&[])),
        Err(MaskError::TemporaryActive)
    );
    assert_eq!(
        state.change(MaskChange::Set(set(&[]))),
        Err(MaskError::TemporaryActive)
    );
    assert!(state.end_temporary());
    assert!(!state.end_temporary());
    assert_eq!(state.effective(), mask(&[10]));

    state.begin_temporary(mask(&[12])).unwrap();
    let mut actions = ActionTable::default();
    actions
        .install(sig(10), caught(ActionFlags::default(), &[2]))
        .unwrap();
    let Delivery::Handler(delivery) = actions.prepare_delivery(sig(10), &mut state) else {
        unreachable!()
    };
    assert_eq!(state.effective(), mask(&[2, 10, 12]));
    // Handler executes under temporary mask; sigreturn restores pre-wait mask.
    assert_eq!(delivery.restore_mask, mask(&[10]));
    assert!(!state.end_temporary());
    state.restore_after_handler(delivery.restore_mask);
    assert_eq!(state.effective(), mask(&[10]));
}

#[test]
fn pending_keeps_first_standard_and_fifo_realtime_with_number_priority() {
    let mut queue = PendingSignals::default();
    assert_eq!(queue.enqueue(sig(10), Some(1)), EnqueueOutcome::Queued);
    assert_eq!(queue.enqueue(sig(10), Some(2)), EnqueueOutcome::Coalesced);
    queue.enqueue(sig(12), None);
    queue.enqueue(sig(12), Some(3));
    queue.enqueue(sig(35), Some(4));
    queue.enqueue(sig(34), None);
    queue.enqueue(sig(34), Some(5));
    queue.enqueue(sig(64), Some(6));
    assert_eq!(queue.len(), 6);
    for (number, info) in [
        (10, Some(1)),
        (12, None),
        (34, None),
        (34, Some(5)),
        (35, Some(4)),
        (64, Some(6)),
    ] {
        assert_eq!(
            queue.take_in(SignalSet::from_bits(u64::MAX)),
            Some(PendingEntry {
                signal: sig(number),
                info
            })
        );
    }
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.present(), SignalSet::default());
    assert_eq!(queue.take_in(set(&[10])), None);
}

#[test]
fn two_process_pending_owners_do_not_steal_thread_signals_at_1_8_32_targets() {
    for population in [1, 8, 32] {
        let a = task(1, 1);
        let b = task(2, 1);
        let mut process_a = SignalInbox::new(a);
        let mut process_b = SignalInbox::new(b);
        process_a.enqueue_for(a, sig(34), Some(-1)).unwrap();
        process_b.enqueue_for(b, sig(34), Some(-2)).unwrap();
        let mut threads: Vec<_> = (0..population)
            .map(|tid| SignalInbox::new(thread(a, tid)))
            .collect();
        for (i, inbox) in threads.iter_mut().enumerate() {
            // Immediate thread-directed signal after birth, with exact key.
            let key = thread(a, i as u32);
            inbox.enqueue_for(key, sig(34), Some(i as i32)).unwrap();
            let picked =
                take_pending(inbox.pending_mut(), process_a.pending_mut(), set(&[34])).unwrap();
            assert_eq!(picked.owner, PendingOwner::Thread);
            assert_eq!(picked.entry.info, Some(i as i32));
            assert_eq!(process_a.pending().len(), 1);
            assert_eq!(process_b.pending().len(), 1);
        }
        let picked = take_pending(
            threads[0].pending_mut(),
            process_a.pending_mut(),
            set(&[34]),
        )
        .unwrap();
        assert_eq!(picked.owner, PendingOwner::Process);
        assert_eq!(picked.entry.info, Some(-1));
        assert_eq!(process_b.pending().len(), 1);
    }
}

#[test]
fn target_choice_is_exact_live_unblocked_and_linear_at_1_8_32_targets() {
    for population in [1, 8, 32] {
        let a = task(1, 1);
        let b = task(2, 1);
        let targets: Vec<_> = (0..population)
            .map(|tid| DeliveryTarget {
                process: a,
                thread: thread(a, tid),
                live: true,
                blocked: if tid + 1 == population {
                    mask(&[])
                } else {
                    mask(&[10])
                },
            })
            .collect();
        let choice = choose_process_target(a, sig(10), targets.iter().copied());
        assert_eq!(choice.target, Some(thread(a, population - 1)));
        assert_eq!(choice.examined, population as usize);
        let foreign = choose_process_target(b, sig(10), targets.iter().copied());
        assert_eq!(foreign.target, None);
        assert_eq!(foreign.examined, population as usize);
        let dead = targets.iter().copied().map(|mut t| {
            t.live = false;
            t
        });
        assert_eq!(choose_process_target(a, sig(10), dead).target, None);
        assert_eq!(
            choose_process_target(a, sig(9), targets.iter().copied()).examined,
            1
        );
        let blocked = targets.iter().copied().map(|mut t| {
            t.blocked = mask(&[10]);
            t
        });
        assert_eq!(choose_process_target(a, sig(10), blocked).target, None);
    }
}

#[test]
fn reused_task_and_thread_ids_reject_stale_signal_completion() {
    let old = task(7, 1);
    let new = task(7, 2);
    let mut inbox = SignalInbox::<_, i32>::new(new);
    assert_eq!(inbox.enqueue_for(old, sig(10), Some(1)), Err(StaleTarget));
    assert_eq!(inbox.pending().len(), 0);
    let fresh = thread(new, 8);
    let stale = ThreadKey {
        generation: 0,
        ..fresh
    };
    let mut inbox = SignalInbox::<_, i32>::new(fresh);
    assert_eq!(inbox.enqueue_for(stale, sig(10), Some(1)), Err(StaleTarget));
    assert_eq!(
        inbox.enqueue_for(thread(old, 8), sig(10), Some(1)),
        Err(StaleTarget)
    );
    assert_eq!(inbox.pending().len(), 0);
    inbox.enqueue_for(fresh, sig(10), Some(2)).unwrap();
    assert_eq!(
        inbox.pending_mut().take_in(set(&[10])).unwrap().info,
        Some(2)
    );
}

#[test]
fn fork_and_exec_reset_actions_pending_and_masks_in_their_own_domains() {
    let parent = task(1, 1);
    let child = task(2, 1);
    let mut actions = ActionTable::default();
    let handler = caught(
        ActionFlags {
            restart: true,
            ..ActionFlags::default()
        },
        &[2],
    );
    let ignored = Action {
        disposition: Disposition::Ignore,
        mask: set(&[12]),
        ..handler
    };
    actions.install(sig(10), handler).unwrap();
    actions.install(sig(12), ignored).unwrap();
    let mut copied = actions.clone();
    copied.install(sig(10), Action::default()).unwrap();
    assert_eq!(actions.action(sig(10)), handler);
    let exec = actions.for_exec();
    assert_eq!(exec.action(sig(10)), Action::default());
    assert_eq!(exec.action(sig(12)), ignored);
    assert_eq!(actions.action(sig(10)), handler);
    let mut process = SignalInbox::new(parent);
    let mut caller = SignalInbox::new(thread(parent, 1));
    process.enqueue_for(parent, sig(34), Some(1)).unwrap();
    caller
        .enqueue_for(thread(parent, 1), sig(12), Some(2))
        .unwrap();
    assert_eq!(process.for_fork(child).pending().len(), 0);
    assert_eq!(caller.for_fork(thread(child, 2)).pending().len(), 0);
    // Exec does not replace these authorities: both pending sets survive.
    assert_eq!(process.pending().len(), 1);
    assert_eq!(caller.pending().len(), 1);
    let mut masks = MaskState::new(mask(&[10]));
    assert_eq!(masks.for_fork().effective(), mask(&[10]));
    masks.reset_for_exec();
    assert_eq!(masks.effective(), mask(&[10]));
}

#[test]
fn clone_sighand_shares_actions_but_never_masks_or_pending_at_1_8_32_targets() {
    for population in [1, 8, 32] {
        let mut tables = BTreeMap::from([(task(1, 1), ActionTable::default())]);
        let parent_key = task(1, 1);
        let parent = &tables[&parent_key];
        let keys: Vec<_> = (0..population)
            .map(
                |_| match parent.for_clone(parent_key, SighandSharing::Share) {
                    ActionInheritance::Shared(key) => key,
                    ActionInheritance::Copied(_) => unreachable!(),
                },
            )
            .collect();
        let ActionInheritance::Copied(independent) =
            parent.for_clone(parent_key, SighandSharing::Copy)
        else {
            unreachable!()
        };
        let action = caught(ActionFlags::default(), &[]);
        tables
            .get_mut(&parent_key)
            .unwrap()
            .install(sig(10), action)
            .unwrap();
        for key in keys {
            assert_eq!(tables[&key].action(sig(10)), action);
        }
        assert_eq!(independent.action(sig(10)), Action::default());
        let parent_mask = MaskState::new(mask(&[10]));
        let mut child_mask = parent_mask.for_fork();
        child_mask.change(MaskChange::Unblock(set(&[10]))).unwrap();
        assert_eq!(parent_mask.effective(), mask(&[10]));
        assert_eq!(child_mask.effective(), mask(&[]));
    }
}

#[test]
fn masked_sigchld_and_no_child_flags_return_separate_reap_and_notify_decisions() {
    let default = Action::default();
    assert_eq!(
        child_decision(default, ChildEvent::Exited, ChildInterest::default()),
        ChildDecision {
            auto_reap: false,
            notify: false
        }
    );
    for interest in [
        ChildInterest {
            blocked: true,
            synchronous_wait: false,
        },
        ChildInterest {
            blocked: false,
            synchronous_wait: true,
        },
    ] {
        assert_eq!(
            child_decision(default, ChildEvent::Exited, interest),
            ChildDecision {
                auto_reap: false,
                notify: true
            }
        );
    }
    let ignored = Action {
        disposition: Disposition::Ignore,
        ..default
    };
    assert_eq!(
        child_decision(
            ignored,
            ChildEvent::Exited,
            ChildInterest {
                blocked: true,
                synchronous_wait: true
            }
        ),
        ChildDecision {
            auto_reap: true,
            notify: false
        }
    );
    let action = caught(
        ActionFlags {
            no_child_wait: true,
            no_child_stop: true,
            ..ActionFlags::default()
        },
        &[],
    );
    assert_eq!(
        child_decision(action, ChildEvent::Exited, ChildInterest::default()),
        ChildDecision {
            auto_reap: true,
            notify: true
        }
    );
    for event in [ChildEvent::Stopped, ChildEvent::Continued] {
        assert_eq!(
            child_decision(action, event, ChildInterest::default()),
            ChildDecision {
                auto_reap: false,
                notify: false
            }
        );
        assert_eq!(
            child_decision(
                caught(ActionFlags::default(), &[]),
                event,
                ChildInterest::default()
            ),
            ChildDecision {
                auto_reap: false,
                notify: true
            }
        );
    }
    let no_wait_default = Action {
        flags: ActionFlags {
            no_child_wait: true,
            ..ActionFlags::default()
        },
        ..default
    };
    assert!(
        child_decision(
            no_wait_default,
            ChildEvent::Exited,
            ChildInterest::default()
        )
        .auto_reap
    );
}

#[test]
fn restart_class_readiness_and_partial_io_are_distinct_from_signal_delivery() {
    for restart in [false, true] {
        for class in [RestartClass::Never, RestartClass::IfSaRestart] {
            assert_eq!(
                interrupted_wait(class, WaitProgress::Blocked, Some(restart)),
                if restart && class == RestartClass::IfSaRestart {
                    WaitDecision::Restart
                } else {
                    WaitDecision::Eintr
                }
            );
            assert_eq!(
                interrupted_wait(class, WaitProgress::Ready, Some(restart)),
                WaitDecision::CompleteReady
            );
            let bytes = TransferredBytes::new(37).unwrap();
            assert_eq!(
                interrupted_wait(class, WaitProgress::Transferred(bytes), Some(restart)),
                WaitDecision::CompletePartial(bytes)
            );
            assert_eq!(
                interrupted_wait(class, WaitProgress::Blocked, None),
                WaitDecision::Continue
            );
        }
    }
    assert_eq!(TransferredBytes::new(0), None);
    // ppoll/pselect/sigsuspend always use Never, even with SA_RESTART.
    assert_eq!(
        interrupted_wait(RestartClass::Never, WaitProgress::Blocked, Some(true)),
        WaitDecision::Eintr
    );
}

#[test]
fn interval_timer_arm_expire_cancel_and_duplicate_completion_use_injected_time() {
    let owner = task(1, 1);
    let mut timer = IntervalTimer::new(owner);
    let spec = IntervalSpec {
        value: TimerSpan(10),
        interval: TimerSpan(3),
    };
    let update = timer.set(ClockInstant(100), spec).unwrap();
    assert_eq!(update.previous, IntervalSpec::default());
    let ticket = update.ticket.unwrap();
    assert_eq!(ticket.deadline(), ClockInstant(110));
    assert_eq!(
        timer.remaining(ClockInstant(104)),
        IntervalSpec {
            value: TimerSpan(6),
            interval: TimerSpan(3)
        }
    );
    assert_eq!(timer.expire(ticket, ClockInstant(109)).unwrap(), None);
    let expiration = timer.expire(ticket, ClockInstant(110)).unwrap().unwrap();
    assert_eq!(expiration.owner, owner);
    assert_eq!(expiration.next.unwrap().deadline(), ClockInstant(113));
    assert_eq!(timer.expire(ticket, ClockInstant(110)).unwrap(), None);
    // A delayed periodic event advances in constant work, never loops per tick.
    let delayed = timer
        .expire(expiration.next.unwrap(), ClockInstant(1_000_000_000))
        .unwrap()
        .unwrap();
    assert_eq!(
        delayed.next.unwrap().deadline(),
        ClockInstant(1_000_000_001)
    );
    let canceled = timer.cancel().unwrap();
    assert_eq!(
        timer.expire(canceled, ClockInstant(u64::MAX)).unwrap(),
        None
    );
    assert_eq!(timer.remaining(ClockInstant(100)), IntervalSpec::default());
    let one_shot = timer
        .set(
            ClockInstant(0),
            IntervalSpec {
                value: TimerSpan(1),
                interval: TimerSpan(0),
            },
        )
        .unwrap()
        .ticket
        .unwrap();
    assert!(
        timer
            .expire(one_shot, ClockInstant(1))
            .unwrap()
            .unwrap()
            .next
            .is_none()
    );
    assert_eq!(timer.expire(one_shot, ClockInstant(2)).unwrap(), None);
}

#[test]
fn timer_rearm_stale_owner_fork_exec_and_coalescing_at_1_8_32_targets() {
    for population in [1, 8, 32] {
        for id in 0..population {
            let a = task(id, 1);
            let b = task(id + population, 1);
            let mut timer_a = IntervalTimer::new(a);
            let mut timer_b = IntervalTimer::new(b);
            let spec = IntervalSpec {
                value: TimerSpan(4),
                interval: TimerSpan(4),
            };
            let old = timer_a.set(ClockInstant(0), spec).unwrap().ticket.unwrap();
            let new = timer_a.set(ClockInstant(0), spec).unwrap().ticket.unwrap();
            let foreign = timer_b.set(ClockInstant(0), spec).unwrap().ticket.unwrap();
            assert_eq!(timer_a.expire(old, ClockInstant(4)).unwrap(), None);
            assert_eq!(timer_a.expire(foreign, ClockInstant(4)).unwrap(), None);
            let mut reused = IntervalTimer::new(task(id, 2));
            reused.set(ClockInstant(0), spec).unwrap();
            assert_eq!(reused.expire(new, ClockInstant(4)).unwrap(), None);
            assert_eq!(
                timer_a.for_fork(task(id, 3)).remaining(ClockInstant(0)),
                IntervalSpec::default()
            );
            // Exec retains interval timer, unlike POSIX timer_create timers.
            assert_eq!(timer_a.remaining(ClockInstant(0)), spec);
            let mut pending = SignalInbox::new(a);
            let first = timer_a.expire(new, ClockInstant(4)).unwrap().unwrap();
            pending
                .enqueue_for(first.owner, Signal::ALRM, None::<i32>)
                .unwrap();
            let second = timer_a
                .expire(first.next.unwrap(), ClockInstant(8))
                .unwrap()
                .unwrap();
            assert_eq!(
                pending
                    .enqueue_for(second.owner, Signal::ALRM, None)
                    .unwrap(),
                EnqueueOutcome::Coalesced
            );
            assert_eq!(pending.pending().len(), 1);
            assert_eq!(timer_b.remaining(ClockInstant(0)), spec);
        }
    }
}

#[test]
fn timer_zero_value_disarms_and_overflow_does_not_replace_live_state() {
    let mut timer = IntervalTimer::new(task(1, 1));
    let spec = IntervalSpec {
        value: TimerSpan(5),
        interval: TimerSpan(7),
    };
    let ticket = timer.set(ClockInstant(0), spec).unwrap().ticket.unwrap();
    assert_eq!(
        timer.set(ClockInstant(u64::MAX), spec),
        Err(TimerError::ClockOverflow)
    );
    assert_eq!(timer.remaining(ClockInstant(0)), spec);
    let disabled = IntervalSpec {
        value: TimerSpan(0),
        interval: TimerSpan(8),
    };
    let update = timer.set(ClockInstant(1), disabled).unwrap();
    assert_eq!(update.previous.value, TimerSpan(4));
    assert_eq!(update.ticket, None);
    assert_eq!(timer.remaining(ClockInstant(2)), disabled);
    assert_eq!(timer.expire(ticket, ClockInstant(5)).unwrap(), None);
}

#[test]
fn aarch64_and_x86_64_use_one_signal_policy_and_explicit_return_policy() {
    let aarch64 = HandlerReturnPolicy::Aarch64 {
        trampoline: RestorerAddress(0x7000),
    };
    let x86_64 = HandlerReturnPolicy::X86_64;
    let action = caught(ActionFlags::default(), &[]);
    assert_eq!(handler_return(action, aarch64), Ok(RestorerAddress(0x7000)));
    assert_eq!(
        handler_return(action, x86_64),
        Err(HandlerReturnError::MissingRestorer)
    );
    let registered = Action {
        restorer: Some(RestorerAddress(0x8000)),
        ..action
    };
    for architecture in [aarch64, x86_64] {
        assert_eq!(
            handler_return(registered, architecture),
            Ok(RestorerAddress(0x8000))
        );
        let mut table = ActionTable::default();
        table.install(sig(10), registered).unwrap();
        let mut masks = MaskState::default();
        assert!(matches!(
            table.prepare_delivery(sig(10), &mut masks),
            Delivery::Handler(_)
        ));
        assert_eq!(masks.effective(), mask(&[10]));
        assert_eq!(table.action(sig(10)).restorer, registered.restorer);
    }
}

#[test]
fn pending_selection_and_discard_preserve_other_owners_and_counts() {
    let mut thread = PendingSignals::default();
    let mut process = PendingSignals::default();
    thread.enqueue(sig(35), Some(1));
    process.enqueue(sig(34), Some(2));
    process.enqueue(sig(34), Some(3));
    process.enqueue(sig(12), Some(4));
    assert_eq!(
        take_pending(&mut thread, &mut process, set(&[34, 35]))
            .unwrap()
            .owner,
        PendingOwner::Process
    );
    assert_eq!(process.len(), 2);
    assert_eq!(take_pending(&mut thread, &mut process, set(&[10])), None);
    process.discard(set(&[34]));
    assert_eq!(process.len(), 1);
    assert_eq!(process.present(), set(&[12]));
    assert_eq!(thread.len(), 1);
    process.discard(set(&[12, 64]));
    assert!(process.is_empty());
    assert_eq!(thread.take_in(set(&[35])).unwrap().info, Some(1));
}

#[test]
fn ignored_signal_preserves_temporary_wait_and_nested_handlers_restore_masks() {
    let mut table = ActionTable::default();
    let mut masks = MaskState::new(mask(&[12]));
    masks.begin_temporary(mask(&[10])).unwrap();
    assert_eq!(
        table.prepare_delivery(Signal::CHLD, &mut masks),
        Delivery::Ignore
    );
    assert_eq!(masks.effective(), mask(&[10]));
    assert!(masks.end_temporary());
    table
        .install(sig(10), caught(ActionFlags::default(), &[2]))
        .unwrap();
    table
        .install(sig(3), caught(ActionFlags::default(), &[4]))
        .unwrap();
    let Delivery::Handler(outer) = table.prepare_delivery(sig(10), &mut masks) else {
        unreachable!()
    };
    let Delivery::Handler(inner) = table.prepare_delivery(sig(3), &mut masks) else {
        unreachable!()
    };
    assert_eq!(masks.effective(), mask(&[2, 3, 4, 10, 12]));
    masks.restore_after_handler(inner.restore_mask);
    assert_eq!(masks.effective(), mask(&[2, 10, 12]));
    masks.restore_after_handler(outer.restore_mask);
    assert_eq!(masks.effective(), mask(&[12]));
}

#[test]
fn periodic_expiry_overflow_refuses_effect_without_consuming_ticket() {
    let mut timer = IntervalTimer::new(task(1, 1));
    let ticket = timer
        .set(
            ClockInstant(u64::MAX - 2),
            IntervalSpec {
                value: TimerSpan(1),
                interval: TimerSpan(3),
            },
        )
        .unwrap()
        .ticket
        .unwrap();
    assert_eq!(
        timer.expire(ticket, ClockInstant(u64::MAX)),
        Err(TimerError::ClockOverflow)
    );
    assert_eq!(
        timer.remaining(ClockInstant(u64::MAX - 2)).value,
        TimerSpan(1)
    );
    assert_eq!(timer.cancel(), Some(ticket));
}

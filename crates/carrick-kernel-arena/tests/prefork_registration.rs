use std::sync::atomic::Ordering;

use carrick_kernel_arena::arena::KernelArena;
use carrick_kernel_arena::domains::HostPid;
use carrick_kernel_arena::process::FLAG_ALIVE;

#[test]
fn prefork_claim_is_complete_when_child_publishes_pid() {
    let arena = KernelArena::create().expect("create arena");
    let section = &arena.layout().processes;
    let parent_pid = std::process::id();
    let ns_pid = 77;
    let ptrace_stop = 5;

    let record_ref = section
        .claim(None, arena.allocate_generation(), |record| {
            record.parent_host_pid.store(parent_pid, Ordering::Relaxed);
            record.ns_pid.store(ns_pid, Ordering::Relaxed);
            record
                .ptrace_stop_signal
                .store(ptrace_stop, Ordering::Relaxed);
            record.flags.store(FLAG_ALIVE, Ordering::Relaxed);
        })
        .expect("claim unpublished child record");

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        let me = std::process::id();
        section.publish_host_pid(record_ref, HostPid::new(me));
        let found = section.find(HostPid::new(me));
        let ok = found.is_some_and(|found| {
            let record = &section.records[found.index];
            record.parent_host_pid.load(Ordering::Acquire) == parent_pid
                && record.ns_pid.load(Ordering::Acquire) == ns_pid
                && record.ptrace_stop_signal.load(Ordering::Acquire) == ptrace_stop
                && record.flags.load(Ordering::Acquire) & FLAG_ALIVE != 0
        });
        unsafe { libc::_exit(if ok { 0 } else { 70 }) };
    }

    section.publish_host_pid(record_ref, HostPid::new(child as u32));
    let mut status = 0;
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    assert_eq!(waited, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    let found = section
        .find(HostPid::new(child as u32))
        .expect("published child record");
    let record = &section.records[found.index];
    assert_eq!(record.parent_host_pid.load(Ordering::Acquire), parent_pid);
    assert_eq!(record.ns_pid.load(Ordering::Acquire), ns_pid);
    assert_eq!(
        record.ptrace_stop_signal.load(Ordering::Acquire),
        ptrace_stop
    );
}

/// Fork at the existing fill hook, after ancestry but before namespace fill.
/// The shared arena must hide this partially filled record from the child.
#[test]
fn fork_during_fill_keeps_record_unpublished() {
    let arena = KernelArena::create().expect("create arena");
    let section = &arena.layout().processes;
    let pid = HostPid::new(std::process::id());
    let r = section
        .claim(Some(pid), arena.allocate_generation(), |record| {
            record.parent_host_pid.store(pid.raw(), Ordering::Relaxed);
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork failed");
            if child == 0 {
                let hidden = record.state().is_registering() && section.find(pid).is_none();
                unsafe { libc::_exit(if hidden { 0 } else { 70 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            record.ns_pid.store(88, Ordering::Relaxed);
        })
        .expect("claim record");
    assert_eq!(section.find(pid), Some(r));
    assert_eq!(section.records[r.index].ns_pid.load(Ordering::Acquire), 88);
}

// The hook fixes the observation/reap interleaving without wall-clock timing.
#[allow(clippy::expect_used)]
fn observe_parent(
    record: &carrick_kernel_arena::process::ProcessRecord,
    observation: &std::sync::Mutex<()>,
    after_identity: impl FnOnce(),
) -> Option<(u32, u32, u32)> {
    let _observation = observation.lock().expect("observation lock");
    let host = record.state().host_pid()?.raw();
    let ns = record.ns_pid.load(Ordering::Acquire);
    after_identity();
    Some((host, ns, record.parent_host_pid.load(Ordering::Acquire)))
}

#[test]
fn observation_cannot_mix_publication_with_reap() {
    let arena = KernelArena::create().expect("create arena");
    let section = &arena.layout().processes;
    let r = section
        .claim(
            Some(HostPid::new(77)),
            arena.allocate_generation(),
            |record| {
                record.ns_pid.store(88, Ordering::Relaxed);
                record.parent_host_pid.store(99, Ordering::Relaxed);
            },
        )
        .expect("claim record");
    let observation = std::sync::Mutex::new(());
    let observed = observe_parent(&section.records[r.index], &observation, || {
        // Force reap immediately after the observer captured identity. An
        // exact observation owns the guard, so reap cannot clear its body.
        if let Ok(_reap) = observation.try_lock() {
            assert!(section.release(r));
        }
    });
    assert!(
        observed == Some((77, 88, 99)),
        "observation mixed a published identity with a retired body: {observed:?}"
    );
}

/// Plan B6 Step 1's storm variant: 200 real fork children while a sibling
/// scanner thread continuously reads the section. The pre-fork registration
/// invariant is that a record whose host pid is PUBLISHED is already complete
/// (ancestry + ns pid were filled by the parent before `fork(2)`), so the
/// scanner must never observe a published-but-incomplete record and `find`
/// must never surface a REGISTERING sentinel.
#[test]
fn fork_storm_never_exposes_incomplete_records() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    const CHILDREN: u32 = 200;
    const NS_BASE: u32 = 0x5107_0000;

    let arena = Arc::new(KernelArena::create().expect("create arena"));
    let stop = Arc::new(AtomicBool::new(false));
    // Only the test observer and terminal reap share this lock. Registration,
    // fork and child validation retain their original concurrency.
    let observation = Arc::new(std::sync::Mutex::new(()));

    let scanner = {
        let arena = Arc::clone(&arena);
        let stop = Arc::clone(&stop);
        let observation = Arc::clone(&observation);
        std::thread::spawn(move || -> Result<(), String> {
            let section = &arena.layout().processes;
            while !stop.load(Ordering::Acquire) {
                for record in section.records.iter() {
                    let Some((host, ns, parent)) = observe_parent(record, &observation, || {})
                    else {
                        continue; // unpublished: invisible by contract
                    };
                    if !(NS_BASE..NS_BASE + CHILDREN).contains(&ns) {
                        continue; // not one of this test's records
                    }
                    if parent == 0 {
                        return Err(format!(
                            "published record for host pid {host} (ns {ns}) has no parent — \
                             the pre-fork fill was observed incomplete"
                        ));
                    }
                }
                std::thread::yield_now();
            }
            Ok(())
        })
    };

    let section = &arena.layout().processes;
    let parent_pid = std::process::id();
    for i in 0..CHILDREN {
        let record_ref = section
            .claim(None, arena.allocate_generation(), |record| {
                record.parent_host_pid.store(parent_pid, Ordering::Relaxed);
                record.ns_pid.store(NS_BASE + i, Ordering::Relaxed);
                record.flags.store(FLAG_ALIVE, Ordering::Relaxed);
            })
            .expect("claim storm child record");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork {i} failed");
        if child == 0 {
            let me = std::process::id();
            section.publish_host_pid(record_ref, HostPid::new(me));
            let ok = section.find(HostPid::new(me)).is_some_and(|found| {
                let record = &section.records[found.index];
                record.parent_host_pid.load(Ordering::Acquire) == parent_pid
                    && record.ns_pid.load(Ordering::Acquire) == NS_BASE + i
            });
            unsafe { libc::_exit(if ok { 0 } else { 70 }) };
        }
        section.publish_host_pid(record_ref, HostPid::new(child as u32));
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child);
        assert!(libc::WIFEXITED(status), "child {i} did not exit");
        assert_eq!(libc::WEXITSTATUS(status), 0, "child {i} saw a bad record");
        // Terminal reap releases the record; the section must sustain the
        // storm without exhausting (records are REUSED, not leaked).
        let reaped = section
            .find(HostPid::new(child as u32))
            .expect("reaped child record");
        let _observation = observation.lock().expect("reap lock");
        assert!(section.release(reaped));
    }

    stop.store(true, Ordering::Release);
    match scanner.join() {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => panic!("{msg}"),
        Err(_) => panic!("scanner thread panicked"),
    }
}

#[test]
fn typed_record_state_transitions_and_refusals() {
    use carrick_kernel_arena::process::{Busy, RecordState, RecordStateCell};

    let cell = RecordStateCell::new();
    assert_eq!(cell.state(), RecordState::Free);
    assert!(cell.state().is_free());
    assert_eq!(cell.state().host_pid(), None);

    // Refusal: cannot begin_transition on Free
    assert!(cell.begin_transition().is_none());
    // Refusal: cannot publish_deferred on Free
    assert!(!cell.publish_deferred(HostPid::new(100)));

    // Transition: Free -> Registering via claim()
    let token = cell.claim().expect("claim on Free succeeds");
    assert_eq!(cell.state(), RecordState::Registering);
    assert!(cell.state().is_registering());
    assert_eq!(cell.state().host_pid(), None);

    // Refusal: cannot claim while Registering
    assert!(matches!(cell.claim(), Err(Busy)));
    // Refusal: cannot begin_transition while Registering
    assert!(cell.begin_transition().is_none());

    // Drop without publish reverts Registering -> Free
    drop(token);
    assert_eq!(cell.state(), RecordState::Free);

    // Claim again
    let token = cell.claim().expect("claim on Free succeeds again");
    assert_eq!(cell.state(), RecordState::Registering);

    // Transition: Registering -> Live { host_pid } via publish()
    let pid = HostPid::new(1234);
    cell.publish(token, pid);
    assert_eq!(cell.state(), RecordState::Live { host_pid: pid });
    assert!(cell.state().is_live());
    assert_eq!(cell.state().host_pid(), Some(pid));

    // Refusal: cannot claim while Live
    assert!(matches!(cell.claim(), Err(Busy)));
    // Idempotent publication with same pid succeeds
    assert!(cell.publish_deferred(pid));
    // Refusal: publish_deferred with different pid fails
    assert!(!cell.publish_deferred(HostPid::new(9999)));

    // Transition: Live -> Transitioning via begin_transition()
    let guard = cell.begin_transition().expect("begin_transition succeeds");
    assert_eq!(cell.state(), RecordState::Transitioning { host_pid: pid });
    assert!(cell.state().is_transitioning());
    assert_eq!(cell.state().host_pid(), Some(pid));

    // Refusal: cannot claim while Transitioning
    assert!(matches!(cell.claim(), Err(Busy)));
    // Refusal: cannot begin_transition while already Transitioning
    assert!(cell.begin_transition().is_none());
    // Refusal: cannot publish_deferred while Transitioning
    assert!(!cell.publish_deferred(pid));

    // Drop guard reverts Transitioning -> Live
    drop(guard);
    assert_eq!(cell.state(), RecordState::Live { host_pid: pid });

    // Transition to Transitioning again
    let guard = cell.begin_transition().expect("begin_transition succeeds");
    // Transition: Transitioning -> Retiring via guard.retire()
    guard.retire();
    assert_eq!(cell.state(), RecordState::Retiring);
    assert!(cell.state().is_retiring());
    assert_eq!(cell.state().host_pid(), None);

    // Refusal: cannot claim while Retiring
    assert!(matches!(cell.claim(), Err(Busy)));
    // Refusal: cannot begin_transition while Retiring
    assert!(cell.begin_transition().is_none());
    // Refusal: cannot publish_deferred while Retiring
    assert!(!cell.publish_deferred(pid));

    // Transition: Retiring -> Free via finish_retire()
    cell.finish_retire();
    assert_eq!(cell.state(), RecordState::Free);

    // Deferred publication workflow (e.g. pre-fork claim)
    let mut token = cell.claim().expect("claim on Free succeeds");
    token.disarm();
    assert_eq!(cell.state(), RecordState::Registering);
    assert!(cell.publish_deferred(pid));
    assert_eq!(cell.state(), RecordState::Live { host_pid: pid });
}

use std::sync::atomic::Ordering;

use carrick_kernel::arena::KernelArena;
use carrick_kernel::domains::HostPid;
use carrick_kernel::process::FLAG_ALIVE;

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

    use carrick_kernel::process::REGISTERING;

    const CHILDREN: u32 = 200;
    const NS_BASE: u32 = 0x5107_0000;

    let arena = Arc::new(KernelArena::create().expect("create arena"));
    let stop = Arc::new(AtomicBool::new(false));

    let scanner = {
        let arena = Arc::clone(&arena);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || -> Result<(), String> {
            let section = &arena.layout().processes;
            while !stop.load(Ordering::Acquire) {
                for record in section.records.iter() {
                    let host = record.host_pid.load(Ordering::Acquire);
                    if host == 0 || host == REGISTERING {
                        continue; // unpublished: invisible by contract
                    }
                    let ns = record.ns_pid.load(Ordering::Acquire);
                    if !(NS_BASE..NS_BASE + CHILDREN).contains(&ns) {
                        continue; // not one of this test's records
                    }
                    if record.parent_host_pid.load(Ordering::Acquire) == 0 {
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
        section.release(reaped);
    }

    stop.store(true, Ordering::Release);
    match scanner.join() {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => panic!("{msg}"),
        Err(_) => panic!("scanner thread panicked"),
    }
}

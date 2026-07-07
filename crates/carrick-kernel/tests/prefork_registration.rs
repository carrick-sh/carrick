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

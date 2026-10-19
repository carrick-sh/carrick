use carrick_el1_abi::{CurrentTask, El1TaskId};
use carrick_x86_carrier::settle_owed_before_switch;

#[test]
fn suspending_publisher_delivers_host_wake_before_switch() {
    let task = CurrentTask::new();
    task.set(El1TaskId::from_linux_tid(42), 1, 5);
    // A guest pipe publisher leaves a wake in the global host queue and rings
    // this bit before its syscall returns Suspended.
    task.linux.mark_pending_host_work();
    let mut host_wake_delivered = false;
    settle_owed_before_switch(
        &task,
        || task.linux.has_pending_host_work(),
        || {
            host_wake_delivered = task
                .linux
                .take_host_work_doorbell()
                .map(|doorbell| doorbell.settled())
                .is_some();
            task.linux.take_served_boundary();
        },
    );
    task.set(El1TaskId::from_linux_tid(43), 2, 6);
    assert!(
        host_wake_delivered,
        "host must consume the wake before task handoff"
    );
    assert!(!task.linux.has_pending_host_work());
}

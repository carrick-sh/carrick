use carrick_coordinator::{Coordinator, LeaseOwner, ResourceClass};
use tempfile::tempdir;

#[test]
fn crash_recovery_reaps_stale_pid_leases() {
    let dir = tempdir().unwrap();
    let coordinator = Coordinator::new(dir.path().to_path_buf()).unwrap();

    // Use a PID that definitely does not exist on macOS
    let dead_pid: u32 = 4194300; // macOS PID_MAX is 99999

    let stale_owner = LeaseOwner {
        host: "host1".to_string(),
        pid: dead_pid,
        run_id: "conf-dead-c01".to_string(),
        investigation_id: None,
    };

    // Manually inject a stale lease file
    let lease_file = dir.path().join("signed_guest_run.lease.json");
    let lease_json = serde_json::to_string_pretty(&stale_owner).unwrap();
    std::fs::write(&lease_file, lease_json).unwrap();

    // Verify recover_stale_leases identifies dead PID and removes lease file
    let recovered = coordinator
        .recover_stale_leases()
        .expect("recovery should succeed");
    assert_eq!(recovered, 1, "should recover 1 stale lease");
    assert!(!lease_file.exists(), "stale lease file should be removed");

    // Now a live process can acquire the lease
    let live_owner = LeaseOwner {
        host: "host1".to_string(),
        pid: std::process::id(),
        run_id: "conf-live-c01".to_string(),
        investigation_id: None,
    };
    let lease = coordinator
        .try_acquire(ResourceClass::SignedGuestRun, live_owner)
        .expect("acquisition should succeed");
    assert!(lease.is_some());
}

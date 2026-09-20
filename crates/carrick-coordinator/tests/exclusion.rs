use carrick_coordinator::{Coordinator, CoordinatorError, LeaseOwner, ResourceClass};
use tempfile::tempdir;

#[test]
fn carrick_and_docker_phases_are_mutually_exclusive() {
    let dir = tempdir().unwrap();
    let coordinator = Coordinator::new(dir.path().to_path_buf()).unwrap();

    let owner1 = LeaseOwner {
        host: "host1".to_string(),
        pid: std::process::id(),
        run_id: "conf-100-c01".to_string(),
        investigation_id: None,
    };

    let owner2 = LeaseOwner {
        host: "host1".to_string(),
        pid: std::process::id(),
        run_id: "conf-100-d01".to_string(),
        investigation_id: None,
    };

    // Acquire Carrick guest run lease
    let lease1 = coordinator
        .try_acquire(ResourceClass::SignedGuestRun, owner1.clone())
        .expect("should succeed");
    assert!(lease1.is_some(), "lease1 should be acquired");

    // Attempting to acquire Docker lease while Carrick lease is active must fail
    let lease2_result = coordinator.try_acquire(ResourceClass::DockerPhase, owner2.clone());
    assert!(
        matches!(lease2_result, Err(CoordinatorError::Conflict { .. })),
        "expected conflict acquiring DockerPhase while SignedGuestRun is held"
    );

    // Dropping or releasing lease1 frees the resource
    drop(lease1);

    // Now Docker lease can be acquired
    let lease2 = coordinator
        .try_acquire(ResourceClass::DockerPhase, owner2)
        .expect("should succeed after release");
    assert!(lease2.is_some(), "lease2 should be acquired");
}

#[test]
fn timing_window_excludes_all_classes() {
    let dir = tempdir().unwrap();
    let coordinator = Coordinator::new(dir.path().to_path_buf()).unwrap();

    let owner = LeaseOwner {
        host: "host1".to_string(),
        pid: std::process::id(),
        run_id: "conf-timing".to_string(),
        investigation_id: None,
    };

    let timing_lease = coordinator
        .try_acquire(ResourceClass::TimingWindow, owner.clone())
        .unwrap()
        .unwrap();

    for other_class in [
        ResourceClass::Build,
        ResourceClass::SignedGuestRun,
        ResourceClass::DockerPhase,
        ResourceClass::TracingSession,
    ] {
        let res = coordinator.try_acquire(other_class, owner.clone());
        assert!(
            matches!(res, Err(CoordinatorError::Conflict { .. })),
            "timing window must exclude {other_class:?}"
        );
    }

    drop(timing_lease);
}

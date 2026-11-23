#[test]
fn arm_terminal_native_failure_authenticates_once_and_counts_exactly() {
    let binding = crate::ExecutionBinding {
        task: crate::EntryTaskKey::from_raw(41),
        generation: crate::SnapshotGeneration::from_raw(11),
        mm: crate::EntryMmKey::from_raw(301),
        thread_generation: crate::EntryThreadGeneration::from_raw(101),
    };
    let reason = super::NativeRunFailureReason::X86GroupExitCustody.at_caller();
    let record = super::NativeRunFailure::new(binding, reason);
    let mut consumer = super::NativeRunFailureConsumer::default();
    let foreign = crate::ExecutionBinding {
        thread_generation: crate::EntryThreadGeneration::from_raw(102),
        ..binding
    };
    assert_eq!(consumer.consume(&record, foreign), None);
    assert_eq!(consumer.crossings(), 0);
    assert_eq!(consumer.consume(&record, binding), Some((reason, 1)));
    assert_eq!(consumer.consume(&record, binding), None);
    assert_eq!(consumer.crossings(), 1);
    let mut exhausted = super::NativeRunFailureConsumer {
        crossings: u64::MAX,
        consumed: false,
    };
    assert_eq!(exhausted.consume(&record, binding), None);
    assert!(!exhausted.consumed);
}

#[test]
fn native_run_failure_is_bound_to_the_exact_thread_incarnation() {
    let binding = crate::ExecutionBinding {
        task: crate::EntryTaskKey::from_raw(41),
        generation: crate::SnapshotGeneration::from_raw(11),
        mm: crate::EntryMmKey::from_raw(301),
        thread_generation: crate::EntryThreadGeneration::from_raw(101),
    };
    let line = line!() + 1;
    let cause = super::NativeRunFailureReason::X86GroupExitCustody.at_caller();
    let mut record = super::NativeRunFailure::new(binding, cause);
    assert_eq!(record.cause_for(binding), Some(cause));
    // The host names the raising site from the record alone (#2853).
    extern crate std;
    use std::string::ToString;
    let named = record.cause_for(binding).unwrap().to_string();
    assert!(
        named.starts_with("x86 group exit custody at ")
            && named.ends_with(&std::format!("_run_failure_tests.rs:{line}:68")),
        "{named}"
    );
    let foreign = crate::ExecutionBinding {
        thread_generation: crate::EntryThreadGeneration::from_raw(102),
        ..binding
    };
    assert_eq!(record.cause_for(foreign), None);
    record.words[15] = 1;
    assert_eq!(record.cause_for(binding), None);
    record.words[15] = 0;
    record.words[5] = u64::MAX;
    assert_eq!(record.cause_for(binding), None);
}

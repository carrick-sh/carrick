#[test]
fn arm_terminal_native_failure_authenticates_once_and_counts_exactly() {
    let binding = crate::ExecutionBinding {
        task: crate::EntryTaskKey::from_raw(41),
        generation: crate::SnapshotGeneration::from_raw(11),
        mm: crate::EntryMmKey::from_raw(301),
        thread_generation: crate::EntryThreadGeneration::from_raw(101),
    };
    let reason = super::NativeRunFailureReason::X86GroupExitCustody;
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
    let mut record =
        super::NativeRunFailure::new(binding, super::NativeRunFailureReason::X86GroupExitCustody);
    assert_eq!(
        record.reason_for(binding),
        Some(super::NativeRunFailureReason::X86GroupExitCustody)
    );
    let foreign = crate::ExecutionBinding {
        thread_generation: crate::EntryThreadGeneration::from_raw(102),
        ..binding
    };
    assert_eq!(record.reason_for(foreign), None);
    record.words[7] = 1;
    assert_eq!(record.reason_for(binding), None);
    record.words[7] = 0;
    record.words[5] = u64::MAX;
    assert_eq!(record.reason_for(binding), None);
}

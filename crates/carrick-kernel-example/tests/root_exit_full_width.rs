//! Root termination transport must preserve the personality's complete status.
#![allow(clippy::unwrap_used)]

use carrick_core_abi::{
    EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    NativeRootExit,
};
use carrick_sched_core::process::TerminationStatus;

#[test]
fn root_exit_wire_preserves_full_width_termination() {
    let binding = ExecutionBinding {
        task: EntryTaskKey::from_raw(41),
        generation: EntryGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(301),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    let requested = TerminationStatus::exited(0xDEAD_BEEF);
    // This is the production carrier's current publication sequence. Copy
    // the record as the host crossing does, then authenticate its binding.
    let record = NativeRootExit::new(binding, requested).unwrap();
    let host_record = NativeRootExit::from_raw_words(record.raw_words());
    let observed = host_record.status_for(binding).unwrap();
    assert_eq!(observed, requested);
}

#[test]
fn linux_host_adapter_preserves_exit_and_signal_wait_encodings() {
    use carrick_personality_linux::lifecycle::LinuxWaitStatus;
    let binding = ExecutionBinding {
        task: EntryTaskKey::from_raw(41),
        generation: EntryGeneration::from_raw(11),
        mm: EntryMmKey::from_raw(301),
        thread_generation: EntryThreadGeneration::from_raw(101),
    };
    let round_trip = |linux: LinuxWaitStatus| {
        let record = NativeRootExit::new(binding, linux.to_termination_status()).unwrap();
        let host = record.status_for(binding).unwrap();
        assert_eq!(LinuxWaitStatus::from_termination_status(host), linux);
    };
    for code in 0..=u8::MAX {
        round_trip(LinuxWaitStatus::exited(code));
    }
    for signal in 1..=64 {
        for core_dump in [false, true] {
            round_trip(LinuxWaitStatus::signaled(signal, core_dump));
        }
    }
}

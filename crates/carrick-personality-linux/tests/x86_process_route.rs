use carrick_personality_linux::{
    dispatch::{Family, route_aarch64},
    entry::decode_x86_64,
    lifecycle::LifecycleCall,
};

#[test]
fn arm_ppoll_stays_forwarded_until_guest_wait_is_complete() {
    assert_eq!(route_aarch64(73, u64::MAX), Family::Unported);
}
use carrick_syscall_abi::syscall_x86_64::{SyscallRemap, lookup_x86_64};

#[test]
fn x86_process_calls_route_to_neutral_lifecycle_hooks() {
    for (native, expected) in [(61, LifecycleCall::Wait4), (231, LifecycleCall::ExitGroup)] {
        let entry = lookup_x86_64(native).expect("process syscall has a table entry");
        let canonical = match entry.remap {
            SyscallRemap::Direct(canonical) => canonical.raw(),
            SyscallRemap::Private(canonical) => canonical.raw(),
            _ => panic!("process syscall must have a canonical route"),
        };
        let call = decode_x86_64(native, [0; 6], 0x7000);
        assert_eq!(call.canonical.raw(), canonical);
        assert_eq!(
            route_aarch64(call.canonical.raw(), u64::MAX),
            Family::Lifecycle(expected)
        );
    }
    // Native fork has no separate canonical ordinal: its ABI adapter uses
    // the same minimal SIGCHLD clone shape as the shared process owner.
    assert!(lookup_x86_64(57).is_none());
    let fork = decode_x86_64(57, [99; 6], 0x7000);
    assert_eq!(fork.canonical.raw(), 220);
    assert_eq!(fork.args, [17, 0, 0, 0, 0, 0]);
    assert_eq!(fork.native.raw(), 57);
    assert_eq!(
        route_aarch64(fork.canonical.raw(), u64::MAX),
        Family::Lifecycle(LifecycleCall::Clone)
    );
    // ARM's real syscall 220 retains its thread-clone interpretation.
    assert_eq!(
        route_aarch64(220, u64::MAX),
        Family::Lifecycle(LifecycleCall::Clone)
    );
    assert_eq!(
        route_aarch64(260, u64::MAX),
        Family::Lifecycle(LifecycleCall::Wait4)
    );
    assert_eq!(
        route_aarch64(94, u64::MAX),
        Family::Lifecycle(LifecycleCall::ExitGroup)
    );
}

#[test]
fn x86_sched_calls_route_to_neutral_sched_family() {
    for (native, expected) in [
        (
            146,
            carrick_personality_linux::sched::SchedCall::GetPriorityMax,
        ),
        (
            147,
            carrick_personality_linux::sched::SchedCall::GetPriorityMin,
        ),
        (
            148,
            carrick_personality_linux::sched::SchedCall::RrGetInterval,
        ),
    ] {
        let entry = lookup_x86_64(native).expect("sched syscall has a table entry");
        let canonical = match entry.remap {
            SyscallRemap::Direct(canonical) => canonical.raw(),
            SyscallRemap::Private(canonical) => canonical.raw(),
            _ => panic!("sched syscall must have a canonical route"),
        };
        let call = decode_x86_64(native, [0; 6], 0x7000);
        assert_eq!(call.canonical.raw(), canonical);
        assert_eq!(
            route_aarch64(call.canonical.raw(), u64::MAX),
            Family::Sched(expected)
        );
    }
}

#[test]
fn arm_sigreturn_stays_with_host_frame_owner() {
    assert_eq!(route_aarch64(139, u64::MAX), Family::SignalReturn);
    assert_eq!(
        carrick_personality_linux::dispatch::route_x86(139, u64::MAX),
        Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigreturn)
    );
}

#[test]
fn pidfds_remain_unported_until_the_native_owner_exists() {
    assert_eq!(route_aarch64(424, u64::MAX), Family::Unported);
    assert_eq!(
        carrick_personality_linux::dispatch::route_x86(424, u64::MAX),
        Family::Unported
    );
}

#[test]
fn arm_signal_routes_match_preapproved_setup_and_host_return() {
    for ordinal in (129..=139).chain(core::iter::once(240)) {
        let expected = match ordinal {
            132 => Family::Lifecycle(LifecycleCall::SigAltStack),
            // #323 pre-approved ARM rt_sigaction for the native signal owner.
            134 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigaction),
            135 => Family::Lifecycle(LifecycleCall::SigProcMask),
            139 => Family::SignalReturn,
            _ => Family::Unported,
        };
        assert_eq!(
            route_aarch64(ordinal, u64::MAX),
            expected,
            "ARM ordinal {ordinal}"
        );
    }
}

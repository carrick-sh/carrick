use carrick_personality_linux::{
    dispatch::{Family, route_aarch64},
    entry::decode_x86_64,
    lifecycle::LifecycleCall,
};
use carrick_syscall_abi::syscall_x86_64::{SyscallRemap, lookup_x86_64};

#[test]
fn x86_process_calls_route_to_neutral_lifecycle_hooks() {
    for (native, expected) in [
        (57, LifecycleCall::Fork),
        (61, LifecycleCall::Wait4),
        (231, LifecycleCall::ExitGroup),
    ] {
        let entry = lookup_x86_64(native).expect("process syscall has a table entry");
        let canonical = match entry.remap {
            SyscallRemap::Direct(canonical) => canonical,
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

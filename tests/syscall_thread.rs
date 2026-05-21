use carrick::dispatch::DispatchOutcome;

#[test]
fn clone_thread_variant_exists() {
    let o = DispatchOutcome::CloneThread {
        stack: 0x7000,
        tls: 0x9000,
        flags: 0x3d0f00,
        parent_tid_addr: 0,
        child_tid_addr: 0,
    };
    assert!(matches!(o, DispatchOutcome::CloneThread { .. }));
}

#[test]
fn thread_exit_variant_exists() {
    let o = DispatchOutcome::ThreadExit { code: 7 };
    assert!(matches!(o, DispatchOutcome::ThreadExit { .. }));
}

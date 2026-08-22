#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
// This whole target IS test code, but clippy's `allow-expect-in-tests`
// exempts only `#[test]` functions, so a shared fixture helper here is
// linted as production.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use carrick_aarch64::mailbox::{Aarch64SyscallMailbox, MailboxState};
use carrick_vmm_hvf::syscall_mailbox::{HvfSyscallTransport, MailboxBinding, MailboxSlotAllocator};

fn binding() -> (
    MailboxBinding,
    Box<Aarch64SyscallMailbox>,
    Arc<MailboxSlotAllocator>,
) {
    let allocator = Arc::new(MailboxSlotAllocator::new());
    let lease = allocator.allocate().expect("mailbox slot");
    let mut mailbox = Box::new(Aarch64SyscallMailbox {
        magic: 0,
        version: 0,
        size: 0,
        generation: 0,
        sequence: 0,
        state: std::sync::atomic::AtomicU32::new(0),
        trap_kind: 0,
        response_action: 0,
        flags: 0,
        native_nr: 0,
        args: [0; 6],
        x8: 0,
        resume_pc: 0,
        spsr: 0,
        fp: 0,
        lr: 0,
        sp: 0,
        esr: 0,
        return_value: 0,
        resume_x16: 0,
        resume_x17: 0,
        reserved: [0; 72],
    });
    let pointer = NonNull::from(mailbox.as_mut());
    let binding = unsafe { MailboxBinding::new(lease, pointer, HvfSyscallTransport::Mailbox) };
    (binding, mailbox, allocator)
}

#[test]
fn initial_zero_instruction_handoff_releases_only_an_idle_mailbox() {
    let (mut binding, mailbox, allocator) = binding();
    assert_eq!(
        mailbox.state.load(Ordering::Acquire),
        MailboxState::Idle.raw()
    );

    binding
        .release_idle_for_initial_handoff()
        .expect("idle bootstrap mailbox release");

    assert_eq!(
        allocator
            .allocate()
            .expect("released slot is reusable")
            .id()
            .raw(),
        0
    );
}

#[test]
fn initial_handoff_rejects_outstanding_mailbox_without_releasing_authority() {
    for state in [MailboxState::RequestReady, MailboxState::ResponseReady] {
        let (mut binding, mailbox, allocator) = binding();
        mailbox.state.store(state.raw(), Ordering::Release);

        let error = binding
            .release_idle_for_initial_handoff()
            .expect_err("outstanding mailbox must not enter initial handoff");

        assert!(error.to_string().contains("Idle"));
        assert_eq!(
            allocator
                .allocate()
                .expect("original slot must remain owned")
                .id()
                .raw(),
            1
        );
    }
}

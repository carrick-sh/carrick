#![cfg(test)]

use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use applevisor::prelude::*;
use carrick_aarch64::Aarch64Exit;
use carrick_aarch64::mailbox::{
    AARCH64_SYSCALL_MAILBOX_MAGIC, AARCH64_SYSCALL_MAILBOX_SIZE, AARCH64_SYSCALL_MAILBOX_VERSION,
    Aarch64SyscallMailbox, MailboxState, MailboxTrapKind,
};
use carrick_hal::AARCH64_HVC_EXCEPTION_CLASS;

use super::*;
use crate::syscall_mailbox::{HvfSyscallTransport, MailboxBinding, MailboxSlotAllocator};

fn test_binding() -> (MailboxBinding, Box<Aarch64SyscallMailbox>) {
    let allocator = Arc::new(MailboxSlotAllocator::new());
    let lease = allocator.allocate().expect("slot");
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
        portal_quantum_epoch: 0,
        resume_pc: 0,
        spsr: 0,
        fp: 0,
        lr: 0,
        sp: 0,
        esr: 0,
        return_value: 0,
        resume_x16: 0,
        resume_x17: 0,
        clock_x9: 0,
        clock_x10: 0,
        clock_x11: 0,
        clock_x12: 0,
        clock_tmp_x16: 0,
        clock_tmp_x17: 0,
        portal_executor_generation: 0,
        portal_task_serial: 0,
        portal_mm_generation: 0,
    });
    let pointer = NonNull::from(mailbox.as_mut());
    let binding = unsafe { MailboxBinding::new(lease, pointer, HvfSyscallTransport::Mailbox) };
    (binding, mailbox)
}

fn test_publish_valid_request(binding: &MailboxBinding, mailbox: &mut Aarch64SyscallMailbox) {
    mailbox.magic = AARCH64_SYSCALL_MAILBOX_MAGIC;
    mailbox.version = AARCH64_SYSCALL_MAILBOX_VERSION;
    mailbox.size = AARCH64_SYSCALL_MAILBOX_SIZE as u32;
    mailbox.generation = binding.generation();
    mailbox.sequence = 1;
    mailbox.trap_kind = MailboxTrapKind::Syscall.raw();
    mailbox.native_nr = 62; // lseek
    mailbox.args = [9, 0, 0, 0, 0, 0];
    mailbox.resume_pc = 0x1234;
    mailbox.spsr = 0x3c0;
    mailbox.fp = 0x29;
    mailbox.lr = 0x30;
    mailbox.sp = 0x8000;
    mailbox.esr = 0x15 << 26; // SVC
    mailbox
        .state
        .store(MailboxState::RequestReady.raw(), Ordering::Release);
}

#[test]
fn transport_exit_overhead_contract() {
    let (mut binding, mut mailbox) = test_binding();
    test_publish_valid_request(&binding, &mut mailbox);

    struct CountingMockVcpu {
        sysreg_reads: std::sync::atomic::AtomicU32,
        reg_reads: std::sync::atomic::AtomicU32,
    }
    impl VcpuTrapContext for CountingMockVcpu {
        fn get_sys_reg(&self, _reg: SysReg) -> std::result::Result<u64, HypervisorError> {
            self.sysreg_reads.fetch_add(1, Ordering::Relaxed);
            Ok(0x15 << 26) // SVC
        }
        fn get_reg(&self, _reg: Reg) -> std::result::Result<u64, HypervisorError> {
            self.reg_reads.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        }
    }
    let mock = CountingMockVcpu {
        sysreg_reads: std::sync::atomic::AtomicU32::new(0),
        reg_reads: std::sync::atomic::AtomicU32::new(0),
    };

    let mut overhead = SyscallTransportOverhead::default();
    let syndrome = (AARCH64_HVC_EXCEPTION_CLASS << 26) | 2; // HVC #2

    let exit = decode_hvc_syscall_exit(syndrome, &mock, &mut binding, &mut overhead)
        .expect("decode exit successfully")
        .expect("syscall exit");

    assert!(matches!(exit, Aarch64Exit::Syscall { .. }));

    // The contract kernel.transport.exit-overhead imposes an exact budget:
    // 0 host register/sysreg accesses on the forwarded syscall path.
    assert_eq!(
        overhead.total_host_accesses(),
        0,
        "structural budget failed: expected 0 host register accesses, got {} (sysreg reads: {}, reg reads: {})",
        overhead.total_host_accesses(),
        overhead.sysreg_reads,
        overhead.register_reads
    );
}

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

fn test_binding_with_transport(
    transport: HvfSyscallTransport,
) -> (MailboxBinding, Box<Aarch64SyscallMailbox>) {
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
    let binding = unsafe { MailboxBinding::new(lease, pointer, transport) };
    (binding, mailbox)
}

fn test_binding() -> (MailboxBinding, Box<Aarch64SyscallMailbox>) {
    test_binding_with_transport(HvfSyscallTransport::Mailbox)
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

    struct DynamicMockVcpu {
        esr_to_return: std::sync::atomic::AtomicU64,
        sysreg_reads: std::sync::atomic::AtomicU32,
        reg_reads: std::sync::atomic::AtomicU32,
    }
    impl VcpuTrapContext for DynamicMockVcpu {
        fn get_sys_reg(&self, reg: SysReg) -> std::result::Result<u64, HypervisorError> {
            self.sysreg_reads.fetch_add(1, Ordering::Relaxed);
            if reg == SysReg::ESR_EL1 {
                Ok(self.esr_to_return.load(Ordering::Relaxed))
            } else {
                Ok(0)
            }
        }
        fn get_reg(&self, _reg: Reg) -> std::result::Result<u64, HypervisorError> {
            self.reg_reads.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        }
    }
    let mock = DynamicMockVcpu {
        esr_to_return: std::sync::atomic::AtomicU64::new(0x15 << 26),
        sysreg_reads: std::sync::atomic::AtomicU32::new(0),
        reg_reads: std::sync::atomic::AtomicU32::new(0),
    };

    let syndrome = (AARCH64_HVC_EXCEPTION_CLASS << 26) | 2; // HVC #2

    // 1. Published mailbox request path:
    let mut mailbox_overhead = SyscallTransportOverhead::default();
    let outcome = decode_hvc_syscall_exit(syndrome, &mock, &mut binding, &mut mailbox_overhead)
        .expect("decode exit successfully");
    assert!(matches!(
        outcome,
        HvcExitOutcome::Syscall(Aarch64Exit::Syscall { .. })
    ));

    // The contract kernel.transport.exit-overhead imposes an exact budget:
    // 0 host register/sysreg accesses on the forwarded syscall path.
    assert_eq!(
        mailbox_overhead.total_host_accesses(),
        0,
        "structural budget failed: expected 0 host register accesses, got {} (sysreg reads: {}, reg reads: {})",
        mailbox_overhead.total_host_accesses(),
        mailbox_overhead.sysreg_reads,
        mailbox_overhead.register_reads
    );
    assert_eq!(mock.sysreg_reads.load(Ordering::Relaxed), 0);
    assert_eq!(mock.reg_reads.load(Ordering::Relaxed), 0);

    // 2. Idle mailbox / non-SVC path:
    // Transition mailbox to Idle to simulate an exit where the guest did not publish a request.
    mailbox
        .state
        .store(MailboxState::Idle.raw(), Ordering::Release);
    // Set mock ESR_EL1 to a non-SVC exception (e.g. Data Abort: 0x24 << 26).
    // Contract requirement: at most one ESR_EL1 read per exit on every path, exact count 1 for non-SVC.
    mock.esr_to_return.store(0x24 << 26, Ordering::Relaxed);
    mock.sysreg_reads.store(0, Ordering::Relaxed);
    mock.reg_reads.store(0, Ordering::Relaxed);

    let mut idle_non_svc_overhead = SyscallTransportOverhead::default();
    let non_svc_outcome =
        decode_hvc_syscall_exit(syndrome, &mock, &mut binding, &mut idle_non_svc_overhead)
            .expect("decode idle non-svc exit successfully");
    assert!(
        matches!(non_svc_outcome, HvcExitOutcome::NotSvc { esr } if esr == (0x24 << 26)),
        "expected NotSvc with ESR 0x{:x}, got {non_svc_outcome:?}",
        0x24 << 26
    );
    assert_eq!(
        idle_non_svc_overhead.sysreg_reads, 1,
        "structural budget failed: expected exactly 1 sysreg read on idle non-SVC path, got {}",
        idle_non_svc_overhead.sysreg_reads
    );
    assert_eq!(
        idle_non_svc_overhead.register_reads, 0,
        "expected 0 register reads on idle non-SVC path, got {}",
        idle_non_svc_overhead.register_reads
    );
    assert_eq!(
        idle_non_svc_overhead.total_host_accesses(),
        1,
        "expected 1 total host access on idle non-SVC path, got {}",
        idle_non_svc_overhead.total_host_accesses()
    );
    assert_eq!(
        mock.sysreg_reads.load(Ordering::Relaxed),
        1,
        "mock should have seen exactly 1 ESR_EL1 read"
    );
    assert_eq!(
        mock.reg_reads.load(Ordering::Relaxed),
        0,
        "mock should have seen 0 register reads on non-SVC path"
    );

    // 3. Diagnostic Legacy transport path:
    let (mut legacy_binding, mut legacy_mailbox) =
        test_binding_with_transport(HvfSyscallTransport::Legacy);
    test_publish_valid_request(&legacy_binding, &mut legacy_mailbox);
    mock.esr_to_return.store(0x15 << 26, Ordering::Relaxed);
    mock.sysreg_reads.store(0, Ordering::Relaxed);
    mock.reg_reads.store(0, Ordering::Relaxed);

    let mut legacy_overhead = SyscallTransportOverhead::default();
    let legacy_outcome =
        decode_hvc_syscall_exit(syndrome, &mock, &mut legacy_binding, &mut legacy_overhead)
            .expect("decode legacy SVC exit successfully");
    assert!(matches!(
        legacy_outcome,
        HvcExitOutcome::Syscall(Aarch64Exit::Syscall { .. })
    ));
    assert_eq!(
        legacy_overhead.sysreg_reads, 4,
        "legacy fallback path reads ESR_EL1, ELR_EL1, SPSR_EL1, SP_EL0"
    );
    assert_eq!(
        legacy_overhead.register_reads, 9,
        "legacy fallback path reads 9 registers (x0-x5, x8, x29, lr)"
    );
    assert_eq!(mock.sysreg_reads.load(Ordering::Relaxed), 4);
    assert_eq!(mock.reg_reads.load(Ordering::Relaxed), 9);

    // 4. Idle mailbox with SVC ESR fails closed:
    mock.esr_to_return.store(0x15 << 26, Ordering::Relaxed);
    let mut idle_svc_overhead = SyscallTransportOverhead::default();
    let idle_svc_err =
        decode_hvc_syscall_exit(syndrome, &mock, &mut binding, &mut idle_svc_overhead);
    assert!(idle_svc_err.is_err());
}

#[test]
fn transport_published_non_svc_request_fails_closed() {
    let (mut binding, mut mailbox) = test_binding();
    test_publish_valid_request(&binding, &mut mailbox);
    // Overwrite esr with a non-SVC exception (e.g. Data Abort from lower EL: EC=0x24)
    mailbox.esr = 0x24 << 26;

    struct DummyMockVcpu;
    impl VcpuTrapContext for DummyMockVcpu {
        fn get_sys_reg(&self, _reg: SysReg) -> std::result::Result<u64, HypervisorError> {
            Ok(0)
        }
        fn get_reg(&self, _reg: Reg) -> std::result::Result<u64, HypervisorError> {
            Ok(0)
        }
    }
    let mock = DummyMockVcpu;
    let mut overhead = SyscallTransportOverhead::default();
    let syndrome = (AARCH64_HVC_EXCEPTION_CLASS << 26) | 2; // HVC #2

    let result = decode_hvc_syscall_exit(syndrome, &mock, &mut binding, &mut overhead);
    assert!(
        result.is_err(),
        "a request taken from the mailbox with non-SVC ESR must fail with a typed error, not Ok: {result:?}"
    );
}

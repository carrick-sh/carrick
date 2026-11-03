//! ISA register adapters for retained IPC syscall re-entry.

use carrick_core::wait::OperationResumePc;
use carrick_el1_abi::TrapFrame;
use carrick_guest_arch::{NativeOrdinal, UserVa};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use carrick_el1::isa::x86::context::native::NativeFrame;

/// Only syscall inputs and the post-instruction PC. Scheduler context custody
/// still owns TLS, extended registers, the stack and all nonargument GPRs.
/// Keeping this separate prevents an IPC retry from restoring another task's
/// machine context, or treating a completed return value as an input argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcCall<const INSTRUCTION_BYTES: u64> {
    number: NativeOrdinal,
    arguments: [u64; 6],
    return_pc: UserVa,
}

/// Register mechanics for a retained call. A snapshot is captured before any
/// service boundary can overwrite syscall inputs. Restoring it is idempotent:
/// re-entry is calculated from the snapshot, never from the live frame's PC.
/// This owns no descriptor, copy cursor, scheduler ticket or memory authority.
pub trait IpcFrame {
    /// An ISA-specific snapshot cannot be restored into another ISA.
    type SavedCall;
    fn save_ipc_call(&self) -> Self::SavedCall;
    fn restore_ipc_call(&mut self, call: &Self::SavedCall);
    fn ipc_reentry_pc(&self) -> Option<OperationResumePc>;
    /// Restore inputs and select the syscall instruction, without a partial
    /// frame mutation if the snapshot cannot name a valid re-entry address.
    fn restore_ipc_reentry(&mut self, call: &Self::SavedCall) -> bool;
}

impl IpcFrame for TrapFrame {
    type SavedCall = IpcCall<4>;
    fn save_ipc_call(&self) -> Self::SavedCall {
        IpcCall {
            number: NativeOrdinal::new(self.x[8]),
            arguments: [
                self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5],
            ],
            return_pc: UserVa::new(self.elr),
        }
    }
    fn restore_ipc_call(&mut self, call: &Self::SavedCall) {
        self.x[..6].copy_from_slice(&call.arguments);
        self.x[8] = call.number.raw();
        self.elr = call.return_pc.raw();
    }
    fn ipc_reentry_pc(&self) -> Option<OperationResumePc> {
        OperationResumePc::new(self.elr.checked_sub(super::linux::SVC_LEN)?)
    }
    fn restore_ipc_reentry(&mut self, call: &Self::SavedCall) -> bool {
        let Some(pc) = call
            .return_pc
            .raw()
            .checked_sub(super::linux::SVC_LEN)
            .and_then(OperationResumePc::new)
        else {
            return false;
        };
        self.restore_ipc_call(call);
        self.elr = pc.raw();
        true
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
impl IpcFrame for NativeFrame {
    type SavedCall = IpcCall<2>;
    fn save_ipc_call(&self) -> Self::SavedCall {
        IpcCall {
            number: NativeOrdinal::new(self.rax),
            arguments: [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9],
            return_pc: UserVa::new(self.rcx),
        }
    }
    fn restore_ipc_call(&mut self, call: &Self::SavedCall) {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9] = call.arguments;
        self.rax = call.number.raw();
        self.rcx = call.return_pc.raw();
    }
    fn ipc_reentry_pc(&self) -> Option<OperationResumePc> {
        // SYSCALL is two bytes. Unlike SVC, its instruction address need not
        // be aligned. RCX is the hardware return PC; user_rcx is a user GPR.
        OperationResumePc::from_raw(self.rcx.checked_sub(2)?)
    }
    fn restore_ipc_reentry(&mut self, call: &Self::SavedCall) -> bool {
        let Some(pc) = call
            .return_pc
            .raw()
            .checked_sub(2)
            .and_then(OperationResumePc::from_raw)
        else {
            return false;
        };
        self.restore_ipc_call(call);
        self.rcx = pc.raw();
        true
    }
}

#[cfg(test)]
#[path = "../../../carrick-x86/src/cpl0_entry.rs"]
#[allow(dead_code)]
mod x86_native;
#[cfg(test)]
use x86_native::NativeFrame;

#[cfg(test)]
mod tests {
    use super::IpcFrame;
    use super::NativeFrame;
    use carrick_el1_abi::TrapFrame;

    #[test]
    fn arm_reentry_restores_inputs_and_rewinds_svc_once() {
        let mut frame = TrapFrame {
            elr: 0x1004,
            ..TrapFrame::default()
        };
        frame.x[..6].copy_from_slice(&[3, 0x4000, 9, 11, 12, 13]);
        frame.x[8] = 63;
        frame.x[19] = 0x1919;
        assert_eq!(frame.ipc_reentry_pc().map(|pc| pc.raw()), Some(0x1000));
        let saved = frame.save_ipc_call();
        frame.x[..6].fill(0xdead);
        frame.x[8] = 0xbeef;
        frame.elr = 0x2004;
        assert!(frame.restore_ipc_reentry(&saved));
        assert_eq!(frame.x[..6], [3, 0x4000, 9, 11, 12, 13]);
        assert_eq!((frame.x[8], frame.elr, frame.x[19]), (63, 0x1000, 0x1919));
        assert!(frame.restore_ipc_reentry(&saved));
        assert_eq!(
            frame.elr, 0x1000,
            "restoring a saved call must not rewind twice"
        );
    }

    #[test]
    fn x86_reentry_restores_native_read_and_keeps_user_rcx() {
        let mut frame = NativeFrame {
            rax: 0,
            rdi: 3,
            rsi: 0x4000,
            rdx: 9,
            r10: 11,
            r8: 12,
            r9: 13,
            rcx: 0x1002,
            user_rcx: 0xcccc,
            r11: 0x202,
            user_r11: 0xbbbb,
            rbx: 0x7777,
            rsp: 0x8000,
            ..NativeFrame::default()
        };
        assert_eq!(frame.ipc_reentry_pc().map(|pc| pc.raw()), Some(0x1000));
        let saved = frame.save_ipc_call();
        frame.rax = 42;
        frame.rdi = 0xdead;
        frame.r10 = 0xbeef;
        frame.rcx = 0x2002;
        assert!(frame.restore_ipc_reentry(&saved));
        assert_eq!((frame.rax, frame.rcx), (0, 0x1000));
        assert_eq!(
            [
                frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9
            ],
            [3, 0x4000, 9, 11, 12, 13]
        );
        assert_eq!(
            (
                frame.user_rcx,
                frame.user_r11,
                frame.rbx,
                frame.rsp,
                frame.r11
            ),
            (0xcccc, 0xbbbb, 0x7777, 0x8000, 0x202)
        );
        assert!(frame.restore_ipc_reentry(&saved));
        assert_eq!(frame.rcx, 0x1000);
    }

    #[test]
    fn x86_reentry_accepts_unaligned_instruction_addresses() {
        let mut frame = NativeFrame {
            rcx: 0x1003,
            ..NativeFrame::default()
        };
        assert_eq!(frame.ipc_reentry_pc().map(|pc| pc.raw()), Some(0x1001));
        let saved = frame.save_ipc_call();
        assert!(frame.restore_ipc_reentry(&saved));
        assert_eq!(frame.rcx, 0x1001);
    }

    #[test]
    fn invalid_reentry_leaves_the_frame_untouched() {
        for pc in [0, 1, 2, 3, 4, 0x1005] {
            let mut arm = TrapFrame {
                elr: pc,
                ..TrapFrame::default()
            };
            assert!(arm.ipc_reentry_pc().is_none());
            let saved = arm.save_ipc_call();
            let before = arm;
            assert!(!arm.restore_ipc_reentry(&saved));
            assert_eq!(arm, before);
        }
        for pc in [0, 1, 2] {
            let mut x86 = NativeFrame {
                rcx: pc,
                rax: 7,
                ..NativeFrame::default()
            };
            assert!(x86.ipc_reentry_pc().is_none());
            let saved = x86.save_ipc_call();
            assert!(!x86.restore_ipc_reentry(&saved));
            assert_eq!((x86.rcx, x86.rax), (pc, 7));
        }
    }
}

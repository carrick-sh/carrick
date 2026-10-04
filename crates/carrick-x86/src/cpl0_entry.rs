//! Native CPL0 frame and boundary-control transport, shared by the thin image
//! and its KVM bootstrap. No Linux syscall algorithm lives in this adapter.
use carrick_guest_arch::{CanonicalCall, CanonicalOrdinal, GuestIsa, NativeOrdinal, UserVa};
use core::sync::atomic::{AtomicU32, AtomicU64};

pub const FORWARD_PORT: u16 = 0xc5;
pub const CONTROL_PORT: u16 = 0xc8;
pub const ENTRY_KICK_PORT: u16 = 0xc9;
pub const RETURN_KICK_PORT: u16 = 0xca;
pub const WORK_PORT: u16 = 0xcb;
pub const FATAL_PORT: u16 = 0xcc;
/// Fixture observation only, outside Linux semantic serving.
pub const OBSERVE_NATIVE: u64 = u64::MAX;

/// Stack order is enforced by the CPL0 assembly and these compile assertions.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rax: u64,
    pub rcx: u64,
    pub r11: u64,
    pub rsp: u64,
}
const _: () = assert!(core::mem::size_of::<NativeFrame>() == 128);
const _: () = assert!(core::mem::offset_of!(NativeFrame, rax) == 96);

impl NativeFrame {
    pub fn decode(&self) -> CanonicalCall {
        // M2 admits only this canonical route. Unported native ordinals remain
        // distinguishable and cannot alias canonical 99.
        let canonical = if self.rax == 273 { 99 } else { u64::MAX };
        CanonicalCall {
            isa: GuestIsa::X86_64,
            canonical: CanonicalOrdinal::new(canonical),
            native: NativeOrdinal::new(self.rax),
            args: [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9],
            stack: UserVa::new(self.rsp),
        }
    }

    /// IRETQ handles all admitted returns, including TF/RF. Reject privileged
    /// flags and non-user targets before constructing the return frame.
    pub fn valid_user_return(&self) -> bool {
        self.rcx != 0
            && self.rcx < (1 << 47)
            && self.rsp != 0
            && self.rsp < (1 << 47)
            && self.r11 & 2 != 0
            && self.r11 & ((3 << 12) | (1 << 14) | (1 << 17) | (1 << 19) | (1 << 20)) == 0
    }
}

/// Per-vCPU supervisor binding, private to this entry/bootstrap (not a change
/// to the common ABI). SWAPGS accesses only its first three words.
#[repr(C)]
pub struct CpuBinding {
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub self_address: u64,
    pub task_address: u64,
    pub counters_address: u64,
    pub entry_kick: AtomicU32,
    pub return_kick: AtomicU32,
    pub entries: AtomicU64,
    pub publications: AtomicU64,
    pub completions: AtomicU64,
    pub captured_stack: AtomicU64,
    /// Private hardware witness binding; zero in normal M2 entry. This is
    /// retained CPL0 control transport, not common task/scheduler authority.
    pub scheduler_witness: AtomicU64,
}
const _: () = assert!(core::mem::offset_of!(CpuBinding, self_address) == 16);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_entry_keeps_full_width_opaque_head() {
        for head in [0, 0x0000_1234_0000_a000, 0x8000_5678_0000_a000, u64::MAX] {
            let frame = NativeFrame {
                rax: 273,
                rdi: head,
                rsi: 24,
                ..Default::default()
            };
            assert_eq!(frame.decode().args[0], head, "opaque head {head:#018x}");
        }
    }

    #[test]
    fn native_entry_keeps_full_width_robust_list_length() {
        let frame = NativeFrame {
            rax: 273,
            rdi: 0,
            rsi: 0x1_0000_0018,
            ..Default::default()
        };
        assert_eq!(frame.decode().args[1], 0x1_0000_0018);
    }

    #[test]
    fn native_entry_keeps_arguments_number_and_captured_stack() {
        let frame = NativeFrame {
            rax: 273,
            rdi: 1,
            rsi: 24,
            rdx: 3,
            r10: 4,
            r8: 5,
            r9: 6,
            rsp: 0x31fe8,
            ..Default::default()
        };
        let call = frame.decode();
        assert_eq!(call.isa, GuestIsa::X86_64);
        assert_eq!(call.native.raw(), 273);
        assert_eq!(call.canonical.raw(), 99);
        assert_eq!(call.args, [1, 24, 3, 4, 5, 6]);
        assert_eq!(call.stack.raw(), frame.rsp);
        assert_eq!(
            NativeFrame { rax: 99, ..frame }.decode().canonical.raw(),
            u64::MAX
        );
    }
    #[test]
    fn iret_return_rejects_noncanonical_targets_and_privileged_flags() {
        let valid = NativeFrame {
            rcx: 0x10000,
            rsp: 0x31fe8,
            r11: 0x202,
            ..Default::default()
        };
        assert!(valid.valid_user_return());
        for target in [0, 1 << 47, u64::MAX] {
            assert!(
                !NativeFrame {
                    rcx: target,
                    ..valid
                }
                .valid_user_return()
            );
            assert!(
                !NativeFrame {
                    rsp: target,
                    ..valid
                }
                .valid_user_return()
            );
        }
        for mask in [3 << 12, 1 << 14, 1 << 17, 1 << 19, 1 << 20] {
            assert!(
                !NativeFrame {
                    r11: valid.r11 | mask,
                    ..valid
                }
                .valid_user_return()
            );
        }
        assert!(!NativeFrame { r11: 0, ..valid }.valid_user_return());
        // These require IRETQ; there is no unsafe SYSRET alternate path.
        assert!(
            NativeFrame {
                r11: valid.r11 | (1 << 8) | (1 << 16),
                ..valid
            }
            .valid_user_return()
        );
    }
}

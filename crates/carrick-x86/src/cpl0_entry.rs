//! Native CPL0 frame and boundary-control transport, shared by the thin image
//! and its KVM bootstrap. No Linux syscall algorithm lives in this adapter.
use carrick_guest_arch::{GuestIsa, NativeAbi, NativeEntrySnapshot, X86Register, X86Registers};
use core::sync::atomic::{AtomicU32, AtomicU64};

pub const FORWARD_PORT: u16 = 0xc5;
pub const CONTROL_PORT: u16 = 0xc8;
pub const ENTRY_KICK_PORT: u16 = 0xc9;
pub const RETURN_KICK_PORT: u16 = 0xca;
pub const WORK_PORT: u16 = 0xcb;
pub const FATAL_PORT: u16 = 0xcc;
pub const YIELD_PORT: u16 = 0xd0;
/// Fixture observation only, outside Linux semantic serving.
pub const OBSERVE_NATIVE: u64 = u64::MAX;
/// Fixture observation of the shared kernel's active MMU root.
pub const OBSERVE_MMU_ROOT: u64 = u64::MAX - 1;
/// Fixture observation of the shared kernel allocator.
pub const OBSERVE_ALLOCATOR: u64 = u64::MAX - 2;
/// Fixture request for a local MMU drain of the supplied user page.
pub const OBSERVE_MMU_DRAIN: u64 = u64::MAX - 3;
/// Fixture request for a shared-kernel x86 descriptor protection edit.
pub const OBSERVE_DESCRIPTOR_PROTECT: u64 = u64::MAX - 4;
/// Retained KVM fixture page-table window; the root is its first page.
pub const FIXTURE_PML4_CAPACITY: u64 = 448 * 4096;

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
const _: () = {
    assert!(core::mem::offset_of!(NativeFrame, r15) == 0);
    assert!(core::mem::offset_of!(NativeFrame, r14) == 8);
    assert!(core::mem::offset_of!(NativeFrame, r13) == 16);
    assert!(core::mem::offset_of!(NativeFrame, r12) == 24);
    assert!(core::mem::offset_of!(NativeFrame, rbp) == 32);
    assert!(core::mem::offset_of!(NativeFrame, rbx) == 40);
    assert!(core::mem::offset_of!(NativeFrame, r9) == 48);
    assert!(core::mem::offset_of!(NativeFrame, r8) == 56);
    assert!(core::mem::offset_of!(NativeFrame, r10) == 64);
    assert!(core::mem::offset_of!(NativeFrame, rdx) == 72);
    assert!(core::mem::offset_of!(NativeFrame, rsi) == 80);
    assert!(core::mem::offset_of!(NativeFrame, rdi) == 88);
    assert!(core::mem::offset_of!(NativeFrame, rax) == 96);
    assert!(core::mem::offset_of!(NativeFrame, rcx) == 104);
    assert!(core::mem::offset_of!(NativeFrame, r11) == 112);
    assert!(core::mem::offset_of!(NativeFrame, rsp) == 120);
};

impl NativeFrame {
    pub fn snapshot(&self) -> NativeEntrySnapshot<'_, Self> {
        NativeEntrySnapshot {
            isa: GuestIsa::X86_64,
            abi: NativeAbi::X86_64Syscall,
            frame: self,
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

impl X86Registers for NativeFrame {
    fn read(&self, register: X86Register) -> u64 {
        match register {
            X86Register::Rax => self.rax,
            X86Register::Rbx => self.rbx,
            X86Register::Rcx => self.rcx,
            X86Register::Rdx => self.rdx,
            X86Register::Rsi => self.rsi,
            X86Register::Rdi => self.rdi,
            X86Register::Rbp => self.rbp,
            X86Register::Rsp => self.rsp,
            X86Register::R8 => self.r8,
            X86Register::R9 => self.r9,
            X86Register::R10 => self.r10,
            X86Register::R11 => self.r11,
            X86Register::R12 => self.r12,
            X86Register::R13 => self.r13,
            X86Register::R14 => self.r14,
            X86Register::R15 => self.r15,
        }
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
    /// The scheduler slot issued by the stopped-host CPL0 bootstrap.
    pub cpu_slot: u32,
}
const _: () = {
    assert!(core::mem::offset_of!(CpuBinding, kernel_stack) == 0);
    assert!(core::mem::offset_of!(CpuBinding, user_stack) == 8);
    assert!(core::mem::offset_of!(CpuBinding, self_address) == 16);
    assert!(core::mem::offset_of!(CpuBinding, cpu_slot) == 88);
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn decode(frame: &NativeFrame) -> carrick_personality_linux::entry::CanonicalCall {
        carrick_personality_linux::entry::decode_x86_snapshot(frame.snapshot()).unwrap()
    }
    #[test]
    fn native_entry_keeps_full_width_opaque_head() {
        for head in [0, 0x0000_1234_0000_a000, 0x8000_5678_0000_a000, u64::MAX] {
            let frame = NativeFrame {
                rax: 273,
                rdi: head,
                rsi: 24,
                ..Default::default()
            };
            assert_eq!(decode(&frame).args[0], head, "opaque head {head:#018x}");
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
        assert_eq!(decode(&frame).args[1], 0x1_0000_0018);
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
        let call = decode(&frame);
        assert_eq!(call.isa, GuestIsa::X86_64);
        assert_eq!(call.native.raw(), 273);
        assert_eq!(call.canonical.raw(), 99);
        assert_eq!(call.args, [1, 24, 3, 4, 5, 6]);
        assert_eq!(call.stack.raw(), frame.rsp);
        assert_eq!(
            decode(&NativeFrame { rax: 99, ..frame }).canonical.raw(),
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

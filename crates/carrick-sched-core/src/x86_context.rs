//! Shared CPL0 parked-context ABI. Machine conversion belongs to the ISA leaf.

use carrick_guest_arch::{AddressContext, RootGpa};

/// The zero-valid x86 save area in a shared scheduler record.
/// Its frame words are the fifteen PUSH registers followed by IRET's five.
#[repr(C, align(64))]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
    ::zerocopy::FromZeros,
)]
pub struct ParkedContextWords {
    pub frame: [u64; 20],
    root: u64,
    mm: u64,
    generation: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    _xsave_align: [u8; 56],
    pub xsave: [u8; X86_XSAVE_BYTES],
}

pub const X86_XSAVE_BYTES: usize = 832;

/// Supervisor IRET/SYSCALL return target checks shared by native frames and
/// parked scheduler records. Only canonical lower-half user targets qualify.
pub const fn valid_user_return_words(rip: u64, rsp: u64, flags: u64) -> bool {
    rip != 0
        && rip < (1 << 47)
        && rsp != 0
        && rsp < (1 << 47)
        && flags & 2 != 0
        && flags & ((3 << 12) | (1 << 14) | (1 << 17) | (1 << 19) | (1 << 20)) == 0
}

/// sigreturn may update arithmetic/debug flags, never interrupt or privilege state.
pub const fn signal_return_flags(current: u64, requested: u64) -> u64 {
    const USER_MODIFIABLE: u64 = 0x50dd5;
    const PRIVILEGED: u64 = (3 << 12) | (1 << 14) | (1 << 17) | (1 << 19) | (1 << 20);
    ((current & !USER_MODIFIABLE) | (requested & USER_MODIFIABLE) | 0x202) & !PRIVILEGED
}

const _: () = {
    assert!(core::mem::offset_of!(ParkedContextWords, frame) == 0);
    assert!(core::mem::offset_of!(ParkedContextWords, root) == 160);
    assert!(core::mem::offset_of!(ParkedContextWords, mm) == 168);
    assert!(core::mem::offset_of!(ParkedContextWords, generation) == 176);
    assert!(core::mem::offset_of!(ParkedContextWords, fs_base) == 184);
    assert!(core::mem::offset_of!(ParkedContextWords, gs_base) == 192);
    assert!(core::mem::offset_of!(ParkedContextWords, _xsave_align) == 200);
    assert!(core::mem::offset_of!(ParkedContextWords, xsave) == 256);
    assert!(core::mem::size_of::<ParkedContextWords>() == 1088);
    assert!(core::mem::align_of::<ParkedContextWords>() == 64);
};

impl ParkedContextWords {
    pub const ZERO: Self = Self {
        frame: [0; 20],
        root: 0,
        mm: 0,
        generation: 0,
        fs_base: 0,
        gs_base: 0,
        _xsave_align: [0; 56],
        xsave: [0; X86_XSAVE_BYTES],
    };

    /// The caller holds the record's claim while publishing this typed owner.
    pub fn from_parts(
        frame: [u64; 20],
        address: AddressContext<RootGpa>,
        fs_base: u64,
        gs_base: u64,
        xsave: [u8; X86_XSAVE_BYTES],
    ) -> Self {
        Self {
            frame,
            root: address.root.address().raw(),
            mm: address.mm.raw().get(),
            generation: address.generation.raw().get(),
            fs_base,
            gs_base,
            _xsave_align: [0; 56],
            xsave,
        }
    }

    /// A zero, corrupt or recycled save area cannot authenticate a live MM.
    pub fn authenticates(&self, expected: AddressContext<RootGpa>) -> bool {
        self.root != 0
            && self.root == expected.root.address().raw()
            && self.mm == expected.mm.raw().get()
            && self.generation == expected.generation.raw().get()
    }

    pub fn fork_child(self, address: AddressContext<RootGpa>) -> Self {
        let mut frame = self.frame;
        frame[10] = 0; // RAX in the ISA-owned interrupt save order.
        Self::from_parts(frame, address, self.fs_base, self.gs_base, self.xsave)
    }

    pub fn set_syscall_return(&mut self, value: u64) {
        self.frame[10] = value;
    }

    pub fn syscall_return(&self) -> u64 {
        self.frame[10]
    }
}

impl carrick_guest_arch::ProcessContext for ParkedContextWords {
    fn authenticates(&self, expected: AddressContext<RootGpa>) -> bool {
        ParkedContextWords::authenticates(self, expected)
    }
    fn fork_child(self, address: AddressContext<RootGpa>) -> Self {
        ParkedContextWords::fork_child(self, address)
    }
    fn set_syscall_return(&mut self, value: u64) {
        ParkedContextWords::set_syscall_return(self, value);
    }
    fn syscall_return(&self) -> u64 {
        ParkedContextWords::syscall_return(self)
    }
}

#[cfg(test)]
mod signal_return_tests {
    #[test]
    fn flags_preserve_interrupts_and_refuse_privilege() {
        let restored = super::signal_return_flags(0x202, u64::MAX);
        assert_eq!(restored & 0x202, 0x202);
        assert_eq!(restored & ((3 << 12) | (1 << 14)), 0);
        assert!(super::valid_user_return_words(0x400000, 0x700000, restored));
        assert!(!super::valid_user_return_words(1 << 47, 0x700000, restored));
    }
}

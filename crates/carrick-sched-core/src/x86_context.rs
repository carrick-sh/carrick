//! Shared CPL0 parked-context ABI. Machine conversion belongs to the ISA leaf.

use carrick_guest_arch::{AddressContext, RootGpa};

/// The zero-valid x86 save area in a shared scheduler record.
/// Its frame words are the fifteen PUSH registers followed by IRET's five.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, zerocopy::FromZeros)]
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
}

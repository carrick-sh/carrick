//! Shared AArch64 parked-context ABI. Machine conversion belongs to the ISA leaf.

use crate::ThreadCtx;
use carrick_guest_arch::{AddressContext, RootGpa};

/// Mask extracting the physical base address from an ARM TTBR0_EL1 register value
/// (bits [47:12], page-aligned). Upper bits [63:48] store the ASID.
pub const AARCH64_ROOT_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

/// The zero-valid AArch64 save area in a shared scheduler record.
/// Holds the architectural thread context and exact address-space binding.
#[repr(C, align(16))]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
    ::zerocopy::FromZeros,
)]
pub struct Aarch64ParkedContext {
    pub native: ThreadCtx,
    root: u64,
    mm: u64,
    generation: u64,
    _pad: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(Aarch64ParkedContext, native) == 0);
    assert!(core::mem::offset_of!(Aarch64ParkedContext, root) == 832);
    assert!(core::mem::offset_of!(Aarch64ParkedContext, mm) == 840);
    assert!(core::mem::offset_of!(Aarch64ParkedContext, generation) == 848);
    assert!(core::mem::offset_of!(Aarch64ParkedContext, _pad) == 856);
    assert!(core::mem::size_of::<Aarch64ParkedContext>() == 864);
    assert!(core::mem::align_of::<Aarch64ParkedContext>() == 16);
};

impl Aarch64ParkedContext {
    pub const ZERO: Self = Self {
        native: ThreadCtx::ZERO,
        root: 0,
        mm: 0,
        generation: 0,
        _pad: 0,
    };

    pub fn from_parts(native: ThreadCtx, address: AddressContext<RootGpa>) -> Self {
        Self {
            native,
            root: address.root.address().raw(),
            mm: address.mm.raw().get(),
            generation: address.generation.raw().get(),
            _pad: 0,
        }
    }

    pub fn from_register(native: ThreadCtx, register: u64, mm: u64, generation: u64) -> Self {
        Self {
            native,
            root: register,
            mm,
            generation,
            _pad: 0,
        }
    }

    pub fn authenticates(&self, expected: AddressContext<RootGpa>) -> bool {
        let physical_root = self.root & AARCH64_ROOT_ADDRESS_MASK;
        physical_root != 0
            && physical_root == expected.root.address().raw()
            && self.mm == expected.mm.raw().get()
            && self.generation == expected.generation.raw().get()
    }

    pub fn fork_child(mut self, address: AddressContext<RootGpa>) -> Self {
        self.native.x[0] = 0;
        self.root = address.root.address().raw();
        self.mm = address.mm.raw().get();
        self.generation = address.generation.raw().get();
        self
    }

    pub fn set_syscall_return(&mut self, value: u64) {
        self.native.x[0] = value;
    }

    pub fn syscall_return(&self) -> u64 {
        self.native.x[0]
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    pub fn mm(&self) -> u64 {
        self.mm
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl carrick_guest_arch::ProcessContext for Aarch64ParkedContext {
    fn authenticates(&self, expected: AddressContext<RootGpa>) -> bool {
        Aarch64ParkedContext::authenticates(self, expected)
    }
    fn fork_child(self, address: AddressContext<RootGpa>) -> Self {
        Aarch64ParkedContext::fork_child(self, address)
    }
    fn set_syscall_return(&mut self, value: u64) {
        Aarch64ParkedContext::set_syscall_return(self, value);
    }
    fn syscall_return(&self) -> u64 {
        Aarch64ParkedContext::syscall_return(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
    use core::num::NonZeroU64;

    fn test_address(root_addr: u64, mm_val: u64, gen_val: u64) -> AddressContext<RootGpa> {
        AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root_addr)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(mm_val).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(gen_val).unwrap()),
        }
    }

    #[test]
    fn aarch64_context_authenticates_and_refuses_mismatches() {
        let binding = test_address(0x1000, 1, 1);
        let ctx = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, binding);

        // Authenticates against its own binding
        assert!(ctx.authenticates(binding));

        // Refuses differing root
        let diff_root = test_address(0x2000, 1, 1);
        assert!(!ctx.authenticates(diff_root));

        // Refuses differing mm
        let diff_mm = test_address(0x1000, 2, 1);
        assert!(!ctx.authenticates(diff_mm));

        // Refuses differing generation
        let diff_gen = test_address(0x1000, 1, 2);
        assert!(!ctx.authenticates(diff_gen));

        // ASID in upper register bits authenticates against clean page-aligned GPA
        let asid_ctx =
            Aarch64ParkedContext::from_register(ThreadCtx::ZERO, 0xabcd_0000_0000_1000, 1, 1);
        assert!(asid_ctx.authenticates(binding));
        assert!(!asid_ctx.authenticates(diff_root));

        // Zero root does not authenticate
        let zero_ctx = Aarch64ParkedContext::ZERO;
        assert!(!zero_ctx.authenticates(binding));
    }

    #[test]
    fn aarch64_context_fork_child_clears_x0_and_rebinds_address() {
        let parent_binding = test_address(0x1000, 1, 1);
        let mut parent_ctx = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, parent_binding);
        parent_ctx.native.x[0] = 42;
        parent_ctx.native.x[1] = 123;

        let child_binding = test_address(0x2000, 2, 1);
        let child_ctx = parent_ctx.fork_child(child_binding);

        // x0 is cleared to 0 (fork child return value)
        assert_eq!(child_ctx.syscall_return(), 0);
        assert_eq!(child_ctx.native.x[0], 0);
        assert_eq!(child_ctx.native.x[1], 123);

        // Child authenticates against child binding
        assert!(child_ctx.authenticates(child_binding));

        // Child REFUSES parent's binding
        assert!(!child_ctx.authenticates(parent_binding));
    }
}

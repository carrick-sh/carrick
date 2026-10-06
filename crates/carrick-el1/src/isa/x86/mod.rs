//! CPL0 leaves for the existing guest-architecture projections.

use super::ArchError;

pub mod context;
pub mod interrupt;
mod mmu;
pub mod transport;
pub mod user_access;

pub mod interrupts;

/// The CPL0 backend's native leaves. Context and MM owners are bound by
/// later families; their current projections fault before publishing state.
pub struct X86Backend;

pub type Kernel = carrick_guest_arch::Arch<X86Backend>;

/// Construct the sealed kernel-facing adapter for CPL0.
pub const fn kernel_arch() -> Kernel {
    carrick_guest_arch::Arch::new(X86Backend)
}

impl carrick_guest_arch::ArchTypes for X86Backend {
    type Error = ArchError;
    type NativeFrame = context::native::NativeFrame;
    type SavedContext = context::SavedSyscallContext;
    type Context = context::ParkedContextWords;
    type Root = carrick_guest_arch::RootGpa;
    type MmOwner = carrick_el1_abi::CurrentTask;
    type DrainTicket = mmu::DrainTicket;
    type DrainReceipt = mmu::DrainReceipt;
    type UserTransfer = user_access::UserTransfer;
    type HardwareInterrupt = u32;
    type InterruptMask = interrupts::InterruptMask;
}

pub use context::{current_stack_slot, current_thread_cpu};
pub use mmu::ForkDescriptorWords;
pub(crate) use mmu::{NativeDescriptorWords, portal_descriptor_words, portal_invalidate_root};
pub use mmu::{
    execute_native_edit_intent, hardware_live_root, portal_root_is_live, resident_leaf_matches,
    unsupported_arm_descriptor_path,
};
pub use transport::{fatal_entry_binding, yield_host_effect};

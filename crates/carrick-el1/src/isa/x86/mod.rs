//! CPL0 leaves for the existing guest-architecture projections.

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::ArchError;

pub mod context;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod fork_mm;
pub mod live_context;
pub use super::x86_initial_mm as initial_mm;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod interrupt;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(super) mod mmu;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod transport;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod user_access;
pub use super::x86_user_tables as user_tables;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod interrupts;

/// The CPL0 backend's native leaves. Context and MM owners are bound by
/// later families; their current projections fault before publishing state.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub struct X86Backend;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub type Kernel = carrick_guest_arch::Arch<X86Backend>;

/// Construct the sealed kernel-facing adapter for CPL0.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub const fn kernel_arch() -> Kernel {
    carrick_guest_arch::Arch::new(X86Backend)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use context::{current_stack_slot, current_thread_cpu};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use mmu::ForkDescriptorWords;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use mmu::{
    execute_native_edit_intent, hardware_live_root, portal_root_is_live, resident_leaf_matches,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use mmu::{portal_descriptor_words, portal_invalidate_root};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use transport::{complete_native_run_failure, fatal_entry_binding, yield_host_effect};

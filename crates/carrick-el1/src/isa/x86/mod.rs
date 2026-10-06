//! CPL0 leaves for the existing guest-architecture projections.

use super::ArchError;

mod context;
mod interrupt;
mod mmu;
mod transport;
mod user_access;

#[path = "../../../../carrick-x86/src/interrupts.rs"]
pub mod interrupts;

/// The CPL0 backend's native leaves. Context and MM owners are bound by
/// later families; their current projections fault before publishing state.
pub struct X86Backend;

pub type Kernel = carrick_guest_arch::Arch<X86Backend>;

/// Construct the sealed kernel-facing adapter for CPL0.
pub const fn kernel_arch() -> impl carrick_guest_arch::KernelArch {
    carrick_guest_arch::Arch::new(X86Backend)
}

impl carrick_guest_arch::ArchTypes for X86Backend {
    type Error = ArchError;
    type NativeFrame = ();
    type SavedContext = ();
    type Root = carrick_guest_arch::RootGpa;
    type MmOwner = carrick_el1_abi::CurrentTask;
    type OwnedTranslation = ();
    type LeafEdit = ();
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type PublicationReceipt = ();
    type HardwareInterrupt = u32;
    type InterruptMask = interrupts::InterruptMask;
    type HostPayload = ();
    type HostTicket = ();
    type HostCompletion = ();
}

pub use context::{carrick_x86_unbound_stack_slot, carrick_x86_unbound_thread_cpu};
pub use mmu::carrick_x86_unbound_mmu_owner;
pub use transport::{carrick_x86_unbound_entry_fatal, carrick_x86_unbound_host_yield};
pub use user_access::{carrick_x86_unbound_user_access, carrick_x86_unbound_user_word};

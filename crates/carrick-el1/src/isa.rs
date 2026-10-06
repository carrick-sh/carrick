//! Native guest instruction leaves selected by the image architecture.

/// A projection that has not yet acquired the required native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchError {
    Unbound,
    InvalidWidth,
    InvalidFrame,
    InvalidContext,
    Busy,
}

/// ISA-neutral descriptor intents lowered to the existing ARM transaction ABI.
/// This is pure conversion; the AArch64 backend and assembly remain unchanged.
pub mod arm_edit;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub mod aarch64;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86;

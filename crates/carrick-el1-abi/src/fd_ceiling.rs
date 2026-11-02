//! The carrier-wide descriptor ceiling, as every venue that makes a guest
//! descriptor number live must raise it.
//!
//! The ARM EL1 lower-EL synchronous vector answers `close(fd)` and
//! `fstat(fd)` with `-EBADF`, before any EL1 dispatch, for a nonnegative fd
//! strictly above the 32-bit word at [`EL1_FD_CEILING_CONTROL_BASE`] while
//! the carrier gate is enabled (`write_fstat_ceiling_handler` in
//! `carrick-mem`). That answer is only correct if the word is at least every
//! descriptor number any table of the carrier has ever held (#1398).
//!
//! Every venue view of the shared descriptor authority carries a
//! [`DescriptorCeiling`] sink: EL1 raises the word itself
//! ([`GuestCeilingWord`]); a host view raises it through the kernel's
//! authority, which owns the carrier publisher. A view without a sink
//! refuses every install ([`crate::ipc::IpcRegion`]), so no venue can make
//! a number live above the word by omission.

use core::sync::atomic::{AtomicU32, Ordering};

/// Guest VA of the carrier's descriptor-ceiling control page: the page after
/// the carrier maintenance root in the kernel-only block. EL0 cannot reach
/// it; EL1 and the host update its ceiling word only by `fetch_max`.
pub const EL1_FD_CEILING_CONTROL_BASE: u64 =
    crate::EL1_CARRIER_MAINT_ROOT_BASE + crate::EL1_CARRIER_MAINT_ROOT_SIZE;
/// Size of the control page.
pub const EL1_FD_CEILING_CONTROL_SIZE: u64 = 0x4000;
/// Offset of the ceiling word (the highest covered descriptor number).
pub const EL1_FD_CEILING_OFF_CEILING: u64 = 0;
/// Offset of the gate word (uninitialized, enabled or permanently disabled).
pub const EL1_FD_CEILING_OFF_GATE: u64 = 4;

/// A venue's conservative descriptor ceiling.
pub trait DescriptorCeiling: Sync {
    /// Raise the ceiling to at least `fd`, then report whether it now covers
    /// `fd`. `false` refuses the install. Infallible, lock-free or holding
    /// only the ceiling's own short lock; must not reenter a descriptor
    /// table.
    fn cover(&self, fd: u32) -> bool;
}

/// EL1's view: the control-page word at its fixed VA.
pub struct GuestCeilingWord;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl DescriptorCeiling for GuestCeilingWord {
    fn cover(&self, fd: u32) -> bool {
        // SAFETY: the carrier maps this naturally aligned word for the
        // lifetime of every address space (kernel-only, EL1 read/write), and
        // it is accessed only atomically by EL1 and the host.
        let word = unsafe {
            &*((EL1_FD_CEILING_CONTROL_BASE + EL1_FD_CEILING_OFF_CEILING) as *const AtomicU32)
        };
        raise_word(word, fd)
    }
}

/// A carrier whose entry has no ceiling fast reject (x86 CPL0): nothing reads
/// a ceiling, so every number is covered.
pub struct NoCeilingReader;

impl DescriptorCeiling for NoCeilingReader {
    fn cover(&self, _fd: u32) -> bool {
        true
    }
}

/// Monotone raise of one shared word: an acquire load, and `fetch_max` only
/// when the word is below `fd`. Reports the covering read.
pub fn raise_word(word: &AtomicU32, fd: u32) -> bool {
    if word.load(Ordering::Acquire) < fd {
        word.fetch_max(fd, Ordering::AcqRel);
    }
    word.load(Ordering::Acquire) >= fd
}

/// The sink the EL1 kernel's own guest-descriptor projections (the legacy
/// fd_map dup paths) raise. Only the ARM EL1 image has a vector that reads
/// the word; the x86 CPL0 image and host builds of the kernel crate have none.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub static GUEST_DESCRIPTOR_CEILING: GuestCeilingWord = GuestCeilingWord;
/// See the ARM definition: no ceiling reader exists in this build.
#[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
pub static GUEST_DESCRIPTOR_CEILING: NoCeilingReader = NoCeilingReader;

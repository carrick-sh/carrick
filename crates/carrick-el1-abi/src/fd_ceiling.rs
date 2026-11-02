//! The carrier-wide descriptor ceiling, as every venue that makes a guest
//! descriptor number live must raise it.
//!
//! The ARM EL1 lower-EL synchronous vector answers `close(fd)` and
//! `fstat(fd)` with `-EBADF`, before any EL1 dispatch, for a nonnegative fd
//! strictly above the 32-bit word at [`EL1_FD_CEILING_CONTROL_BASE`] while
//! the carrier gate is enabled (`write_fstat_ceiling_handler` in
//! `carrick-mem`). That answer is only correct if the word is at least every
//! descriptor number any table of the carrier has ever held. Host
//! `FileTable` installs raise it through the kernel's `FdCeilingAuthority`;
//! a ring-owned native table changes only in ring, so the ring raises the
//! same word itself, before the new number becomes visible (#1398).

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

#[cfg(not(target_os = "none"))]
static HOST_CEILING_WORD: core::sync::atomic::AtomicPtr<AtomicU32> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Host builds: name the word a VM-free fixture's ring venue raises, standing
/// in for the guest VA the image reads. Production host venues never install
/// into a ring-owned table and leave it unset: their installs are
/// `FileTable` projections the kernel authority has already published.
#[cfg(not(target_os = "none"))]
pub fn record_fd_ceiling_host_word(word: &'static AtomicU32) {
    HOST_CEILING_WORD.store(core::ptr::from_ref(word).cast_mut(), Ordering::Release);
}

fn ceiling_word() -> Option<&'static AtomicU32> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        // SAFETY: the carrier maps this naturally aligned word for the
        // lifetime of every address space (kernel-only, EL1 read/write), and
        // it is accessed only atomically by EL1 and the host.
        Some(unsafe {
            &*((EL1_FD_CEILING_CONTROL_BASE + EL1_FD_CEILING_OFF_CEILING) as *const AtomicU32)
        })
    }
    #[cfg(all(target_os = "none", not(target_arch = "aarch64")))]
    {
        // The x86 CPL0 entry has no ceiling fast return to keep exact.
        None
    }
    #[cfg(not(target_os = "none"))]
    {
        let word = HOST_CEILING_WORD.load(Ordering::Acquire);
        // SAFETY: only `record_fd_ceiling_host_word` stores here, from a
        // `'static` reference.
        (!word.is_null()).then(|| unsafe { &*word })
    }
}

/// Raise the carrier-wide descriptor ceiling to at least `fd` before `fd`
/// becomes visible in a ring-owned table. Monotone, lock-free and O(1);
/// a number already covered costs one acquire load.
pub fn cover_guest_descriptor(fd: usize) {
    let Ok(fd) = u32::try_from(fd) else {
        return;
    };
    let Some(word) = ceiling_word() else {
        return;
    };
    if word.load(Ordering::Acquire) < fd {
        word.fetch_max(fd, Ordering::AcqRel);
    }
}

/// The ceiling the vector would compare against now (host fixtures only).
#[cfg(not(target_os = "none"))]
pub fn fd_ceiling_host_value() -> Option<u32> {
    ceiling_word().map(|word| word.load(Ordering::Acquire))
}

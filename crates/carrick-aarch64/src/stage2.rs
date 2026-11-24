//! The stage-2 backend boundary: the three raw operations a host hypervisor
//! performs on a guest's physical address space.
//!
//! Everything a carrier does to stage-2 (the record table, global-frame
//! owners, lazy replay, COW, sparse materialization) is custody logic built on
//! these three operations. HVF implements them over `hv_vm_map`,
//! `hv_vm_unmap` and `hv_vm_destroy`; the soft CPU will implement them over
//! its mmap windows (#2814). The custody layer above stays one implementation
//! (the staged custody move on #2814, step S0).

use carrick_hal::MemPerms;

pub mod custody;

/// A backend's raw status for one stage-2 operation. Zero is success; any
/// other value is the backend's own refusal code, kept exact so a log or a
/// [`carrick_core_abi::mm::custody::CarrierStage2BackendError`] names what the
/// host said. Callers must treat every nonzero status as failure: a nonzero
/// result is never evidence that a racing mapper already installed the extent.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Status(u32);

impl Stage2Status {
    /// The operation took effect.
    pub const SUCCESS: Self = Self(0);

    /// "Not now": another holder has the backend's stage 2. Nothing changed;
    /// the caller keeps its operation, enrols on the holder's release
    /// ([`Stage2Backend::contention`]), probes once, and reruns it. Never a
    /// refusal and never reported to a guest.
    pub const BUSY: Self = Self(0x4255_5359);

    /// Wrap a backend's raw status word.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The backend's raw status word.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether the operation took effect.
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Whether the backend was busy ([`Stage2Status::BUSY`]).
    pub const fn is_busy(self) -> bool {
        self.0 == Self::BUSY.0
    }
}

/// A status compares equal to its raw word, so `status != 0` reads as the
/// backend's own success test.
impl PartialEq<u32> for Stage2Status {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl core::fmt::LowerHex for Stage2Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&self.0, f)
    }
}

/// Stage-2 permission bits as custody records store them: read `1`, write
/// `2`, execute `4`. [`carrick_core_abi::mm::custody::CarrierStage2RecordSpec`]
/// and the replay keys hold this word.
pub const STAGE2_PERM_READ: u64 = 1;
/// See [`STAGE2_PERM_READ`].
pub const STAGE2_PERM_WRITE: u64 = 2;
/// See [`STAGE2_PERM_READ`].
pub const STAGE2_PERM_EXEC: u64 = 4;

/// Decode a recorded stage-2 permission word. `None` for any bit outside
/// read, write and execute.
pub const fn stage2_perms_from_bits(bits: u64) -> Option<MemPerms> {
    if bits & !(STAGE2_PERM_READ | STAGE2_PERM_WRITE | STAGE2_PERM_EXEC) != 0 {
        return None;
    }
    Some(MemPerms {
        read: bits & STAGE2_PERM_READ != 0,
        write: bits & STAGE2_PERM_WRITE != 0,
        exec: bits & STAGE2_PERM_EXEC != 0,
    })
}

/// Encode permissions as the recorded stage-2 permission word.
pub const fn stage2_perms_bits(perms: MemPerms) -> u64 {
    (if perms.read { STAGE2_PERM_READ } else { 0 })
        | (if perms.write { STAGE2_PERM_WRITE } else { 0 })
        | (if perms.exec { STAGE2_PERM_EXEC } else { 0 })
}

/// The raw stage-2 operations of one host hypervisor.
///
/// Implementations do only the host call and its exact status. Lazy-replay
/// bookkeeping, probes and record custody belong to the caller, so every
/// backend gets the same custody.
pub trait Stage2Backend: Sync {
    /// Install `[host, host + size)` at guest-physical `[ipa, ipa + size)`.
    ///
    /// # Safety
    ///
    /// The host range must stay mapped, and must not be reused for anything
    /// else, until a successful [`Stage2Backend::unmap`] of the same extent or
    /// [`Stage2Backend::destroy`].
    unsafe fn map(
        &self,
        host: *mut core::ffi::c_void,
        ipa: u64,
        size: usize,
        perms: MemPerms,
    ) -> Stage2Status;

    /// Remove the guest-physical extent `[ipa, ipa + size)`.
    ///
    /// # Safety
    ///
    /// No guest CPU may depend on the extent once this returns success, and
    /// the caller owns the extent's custody record.
    unsafe fn unmap(&self, ipa: u64, size: usize) -> Stage2Status;

    /// Destroy the whole guest-physical address space.
    ///
    /// # Safety
    ///
    /// No guest CPU of the VM may still run, and the caller owns the VM's
    /// custody transaction.
    unsafe fn destroy(&self) -> Stage2Status;

    /// The release a caller that saw [`Stage2Status::BUSY`] enrols on. A
    /// backend that is never busy (HVF) has none.
    fn contention(&self) -> Option<&dyn Stage2Contention> {
        None
    }
}

/// The holder's release of a backend that can be busy.
///
/// A contended caller enrols first, then probes once (reruns its
/// operation); only if that probe is busy too does it wait, and the wait
/// ends at the first release after enrolment, so no release is lost.
pub trait Stage2Contention: Sync {
    /// Enrol on the next release. Returns the release epoch the caller saw.
    fn enrol(&self) -> Stage2ReleaseEpoch;

    /// Wait for a release after `epoch`, then leave.
    fn wait_and_leave(&self, epoch: Stage2ReleaseEpoch);

    /// Leave without waiting: the probe after enrolment was not busy.
    fn leave(&self);
}

/// A release count a contended caller enrolled at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2ReleaseEpoch(pub u64);

/// Run `operation` until it is not busy: enrol on the backend's release,
/// probe once, and wait only if that probe is busy too.
pub fn run_past_busy(
    backend: &dyn Stage2Backend,
    mut operation: impl FnMut() -> Stage2Status,
) -> Stage2Status {
    let status = operation();
    if !status.is_busy() {
        return status;
    }
    let Some(contention) = backend.contention() else {
        return status;
    };
    loop {
        let epoch = contention.enrol();
        let status = operation();
        if !status.is_busy() {
            contention.leave();
            return status;
        }
        contention.wait_and_leave(epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permission_word_round_trips() {
        for bits in 0..=7u64 {
            let perms = stage2_perms_from_bits(bits).expect("rwx word");
            assert_eq!(stage2_perms_bits(perms), bits);
        }
        assert_eq!(
            stage2_perms_from_bits(STAGE2_PERM_READ | STAGE2_PERM_WRITE),
            Some(MemPerms {
                read: true,
                write: true,
                exec: false,
            })
        );
    }

    /// The named sets encode as the hypervisor words they replace
    /// (`HV_MEMORY_READ` 1, `HV_MEMORY_WRITE` 2, `HV_MEMORY_EXEC` 4).
    #[test]
    fn every_named_set_encodes_as_its_hypervisor_word() {
        let named = [
            (MemPerms::None, 0),
            (MemPerms::Read, 1),
            (MemPerms::Write, 2),
            (MemPerms::ReadWrite, 3),
            (MemPerms::Exec, 4),
            (MemPerms::ReadExec, 5),
            (MemPerms::WriteExec, 6),
            (MemPerms::ReadWriteExec, 7),
        ];
        for (perms, bits) in named {
            assert_eq!(stage2_perms_bits(perms), bits, "{perms:?}");
            assert_eq!(stage2_perms_from_bits(bits), Some(perms));
        }
    }

    #[test]
    fn a_word_outside_rwx_is_refused() {
        assert_eq!(stage2_perms_from_bits(8), None);
        assert_eq!(stage2_perms_from_bits(STAGE2_PERM_READ | 0x10), None);
    }

    #[test]
    fn only_zero_is_success_and_the_raw_word_is_kept() {
        assert!(Stage2Status::SUCCESS.is_success());
        assert_eq!(Stage2Status::SUCCESS, 0);
        let refused = Stage2Status::from_raw(0xfae9_4003);
        assert!(!refused.is_success());
        assert_ne!(refused, 0);
        assert_eq!(refused.raw(), 0xfae9_4003);
        assert_eq!(format!("0x{refused:x}"), "0xfae94003");
    }
}

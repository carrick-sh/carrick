//! Core capture's guest-memory read policy, shared by every ISA.
//!
//! Core capture pauses the crashing MM for its whole read loop, and that
//! pause raises the MM's published space gate. The gate excludes every new
//! guest editor, including the owner portal's transfer step, so a core read
//! that went through the portal would wait on a gate only capture itself can
//! lower (#1733). Capture therefore reads through the exclusion it already
//! holds, and this module is the only way to do so: [`read_core_bytes`]
//! demands the typed [`ExcludedEditor`] for the exact MM and never calls an
//! owner-routed read on an owner-admitted MM.
//!
//! What is policy and what is mechanics:
//! - Here (ISA-neutral): which MM a proof must name, the page walk, which
//!   pages may be holes (a page with no readable storage reads as its
//!   pristine private file contents or as an untouched zero page, and as
//!   nothing else), and how a refusal is classified. A wait on the gate capture itself raised is a broken
//!   invariant ([`CoreReadError::OwnGate`]); any other holder's dependency
//!   means "not now" ([`CoreReadError::Busy`]): capture keeps the operation,
//!   releases its pause and execution lease, enrols on that wait's existing
//!   release notification, probes once and reruns.
//! - Per ISA ([`CoreMemorySource`]): translating a guest VA through its own
//!   stage-1 format to an output address, copying backing bytes at that
//!   output, and the live-descriptor half of the untouched-zero question.

use std::sync::Arc;

use carrick_el1_abi::{PortalOwnerWait, PortalWaitCause};
use carrick_guest_mem::{
    DeferredAnonymousState, Gpa, GuestMemory, GuestVa, MemoryError, MemoryReadWait, OwnedMemoryWait,
};
use carrick_sched_core::ExcludedEditor;

/// Translation granule of a core read: each fragment translates and copies
/// on its own, so a range spanning shared identity and private overlay pages
/// never assumes one contiguous output.
const CORE_READ_PAGE: u64 = 0x1000;

/// Per-ISA memory mechanics core capture reads through. The defaults are
/// those of an engine whose memory the host owns outright: no guest owner
/// edits its translations, so its ordinary read needs no exclusion.
pub trait CoreMemorySource: GuestMemory {
    /// The exact MM whose live translations capture reads directly, under
    /// its exclusion, page by page; `None` when the engine's memory is
    /// host-owned and its ordinary read already is that direct read.
    fn core_memory_mm(&self) -> Option<u64> {
        None
    }

    /// Host-owned memory read of a range the core VMA snapshot admitted.
    fn read_host_owned_core_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        self.read_bytes(address, length)
    }

    /// ISA mechanics: the output address the live stage-1 translation gives
    /// `va` (an invalidated leaf's retained output included), or `None` when
    /// no output is mapped.
    fn core_stage1_output(&self, _va: GuestVa) -> Result<Option<Gpa>, MemoryError> {
        Err(MemoryError::Unsupported)
    }

    /// VMM mechanics: copy `length` backing bytes of `va` at its translated
    /// `output`. `excluded` is the held proof the backend may read without
    /// re-entering the owner's transfer portal.
    fn read_core_backing(
        &self,
        _excluded: &ExcludedEditor<'_>,
        _va: GuestVa,
        _output: Gpa,
        _length: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::Unsupported)
    }

    /// The exact MM's pristine private-file authority, if it has one.
    fn core_deferred_anonymous(&self) -> Option<Arc<DeferredAnonymousState>> {
        None
    }

    /// Whether `page` reads as fresh zero: its live leaf names no output and
    /// the exact-MM authority answers it is an untouched readable page.
    fn core_untouched_zero(&self, _page: GuestVa) -> bool {
        false
    }
}

/// Another holder's dependency that refused a core read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreReadWait {
    /// An owner wait of the captured MM on a cause other than its gate,
    /// which capture's exclusion does not hold.
    Owner(PortalOwnerWait),
    /// A physical dependency (retained readers of a frame).
    Physical(OwnedMemoryWait),
}

/// Why a core read did not return the range.
#[derive(Debug)]
pub enum CoreReadError {
    /// Not now: another holder must release first. Capture discards its
    /// partial snapshot, releases its pause, enrols on this wait, probes
    /// once and reruns.
    Busy(CoreReadWait),
    /// The read waited on the gate of the very MM whose exclusion capture
    /// holds. Nothing but capture can lower that gate, so waiting would
    /// deadlock; reaching this is a broken invariant, never retried.
    OwnGate(PortalOwnerWait),
    /// The read failed.
    Memory(MemoryError),
}

impl std::fmt::Display for CoreReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy(wait) => write!(formatter, "core read waits on another holder: {wait:?}"),
            Self::OwnGate(wait) => write!(
                formatter,
                "core read waited on the gate of the MM its own capture excludes: {wait:?}"
            ),
            Self::Memory(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CoreReadError {}

/// Read `[address, address + length)` of a range the coherent core VMA
/// snapshot admitted, while `excluded` keeps the MM's guest editor out.
pub fn read_core_bytes<M: CoreMemorySource + ?Sized>(
    memory: &M,
    excluded: &ExcludedEditor<'_>,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, CoreReadError> {
    let Some(mm) = memory.core_memory_mm() else {
        return memory
            .read_host_owned_core_bytes(address, length)
            .map_err(|error| classify(excluded, error).unwrap_or_else(CoreReadError::Memory));
    };
    if excluded.key() != mm {
        return Err(CoreReadError::Memory(MemoryError::HostMap(format!(
            "core read of MM {mm} holds the exclusion of MM {}",
            excluded.key()
        ))));
    }
    let end = address
        .checked_add(length as u64)
        .ok_or(CoreReadError::Memory(MemoryError::OutOfBounds {
            address,
            length,
        }))?;
    let mut out = vec![0; length];
    let mut va = address;
    while va < end {
        let len = (end - va).min(CORE_READ_PAGE - (va % CORE_READ_PAGE));
        let at = (va - address) as usize;
        let dst = &mut out[at..at + len as usize];
        read_core_fragment(memory, excluded, GuestVa::new(va), dst)?;
        va += len;
    }
    Ok(out)
}

fn read_core_fragment<M: CoreMemorySource + ?Sized>(
    memory: &M,
    excluded: &ExcludedEditor<'_>,
    va: GuestVa,
    dst: &mut [u8],
) -> Result<(), CoreReadError> {
    let unbacked = MemoryError::OutOfBounds {
        address: va.raw(),
        length: dst.len(),
    };
    let missing = match memory
        .core_stage1_output(va)
        .map_err(CoreReadError::Memory)?
    {
        Some(output) => match memory.read_core_backing(excluded, va, output, dst.len()) {
            Ok(bytes) if bytes.len() == dst.len() => {
                dst.copy_from_slice(&bytes);
                return Ok(());
            }
            Ok(_) => unbacked,
            // A wait is never a hole: it is ours (a broken invariant) or
            // another holder's (not now).
            Err(error) => match classify(excluded, error) {
                Ok(wait) => return Err(wait),
                Err(error) => error,
            },
        },
        None => unbacked,
    };
    // The page has no readable storage. The admitted VMA then reads as its
    // pristine private file contents or, for an authoritatively untouched
    // page, as fresh zero; anything else fails the capture.
    if let Some(state) = memory.core_deferred_anonymous()
        && state.copy_pristine_file(va, dst).map_err(|error| {
            CoreReadError::Memory(MemoryError::HostMap(format!(
                "read deferred private file backing: {error}"
            )))
        })?
    {
        return Ok(());
    }
    if memory.core_untouched_zero(GuestVa::new(va.raw() & !(CORE_READ_PAGE - 1))) {
        dst.fill(0);
        return Ok(());
    }
    Err(CoreReadError::Memory(missing))
}

/// Classify a wait; any other error comes back unchanged.
fn classify(
    excluded: &ExcludedEditor<'_>,
    error: MemoryError,
) -> Result<CoreReadError, MemoryError> {
    let wait = match error {
        MemoryError::ReadSuspended(suspension) => match suspension.wait {
            MemoryReadWait::Owner(wait) => CoreReadWait::Owner(wait),
            MemoryReadWait::Physical(wait) => CoreReadWait::Physical(wait),
            MemoryReadWait::Supply(request) => {
                return Err(MemoryError::HostMap(format!(
                    "core read asked to supply memory: {request:?}"
                )));
            }
        },
        MemoryError::OwnerWait(wait) => CoreReadWait::Owner(wait),
        MemoryError::Physical(wait) => CoreReadWait::Physical(wait),
        other => return Err(other),
    };
    Ok(match wait {
        // No core read of this MM routes through another MM's owner, and a
        // terminal's retained wait is bound to its own MM: not a wait.
        CoreReadWait::Owner(wait) if wait.handle().mm().raw() != excluded.key() => {
            return Err(MemoryError::HostMap(format!(
                "core read of MM {} waited on MM {}'s owner: {wait:?}",
                excluded.key(),
                wait.handle().mm().raw()
            )));
        }
        CoreReadWait::Owner(wait) if wait.cause() == PortalWaitCause::Gate => {
            CoreReadError::OwnGate(wait)
        }
        wait => CoreReadError::Busy(wait),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{El1MmHandle, ReservationMm};
    use carrick_guest_mem::{
        LegacyProtectionRead, MemoryReadSuspension, OwnedReadContinuation,
        protections::MemoryProtections,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const MM: u64 = 41;
    const OTHER_MM: u64 = 42;

    fn wait(mm: u64, cause: PortalWaitCause) -> PortalOwnerWait {
        // SAFETY: a VM-free policy test; the receipt only names an owner.
        unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(7).unwrap(),
                    ReservationMm::new(mm).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                ),
                cause,
                3,
            )
        }
    }

    fn suspended(wait: PortalOwnerWait) -> MemoryError {
        MemoryError::ReadSuspended(Box::new(MemoryReadSuspension {
            wait: MemoryReadWait::Owner(wait),
            continuation: OwnedReadContinuation::new(()),
        }))
    }

    /// Pages are identity-translated unless listed untranslated; the
    /// ordinary (owner-portal) read always refuses on the MM's own gate.
    #[derive(Default)]
    struct Fake {
        prot: MemoryProtections,
        owner: Option<u64>,
        bytes: BTreeMap<u64, u8>,
        untranslated: Vec<u64>,
        zero: Vec<u64>,
        refuse: BTreeMap<u64, PortalOwnerWait>,
        unbacked: Vec<u64>,
        physical: BTreeMap<u64, OwnedMemoryWait>,
        backing_reads: RefCell<Vec<(u64, usize)>>,
    }

    impl GuestMemory for Fake {
        fn protections(&self) -> Option<LegacyProtectionRead<'_>> {
            Some(LegacyProtectionRead::borrowed(&self.prot))
        }
        fn read_bytes_raw(&self, _address: u64, _length: usize) -> Result<Vec<u8>, MemoryError> {
            Err(suspended(wait(MM, PortalWaitCause::Gate)))
        }
        fn write_bytes_raw(&mut self, _address: u64, _bytes: &[u8]) -> Result<(), MemoryError> {
            Err(MemoryError::Unsupported)
        }
    }

    impl CoreMemorySource for Fake {
        fn core_memory_mm(&self) -> Option<u64> {
            self.owner
        }
        fn core_stage1_output(&self, va: GuestVa) -> Result<Option<Gpa>, MemoryError> {
            let page = va.raw() & !0xfff;
            Ok((!self.untranslated.contains(&page)).then_some(Gpa::new(va.raw())))
        }
        fn read_core_backing(
            &self,
            excluded: &ExcludedEditor<'_>,
            va: GuestVa,
            output: Gpa,
            length: usize,
        ) -> Result<Vec<u8>, MemoryError> {
            assert_eq!(excluded.key(), MM);
            assert_eq!(va.raw(), output.raw());
            self.backing_reads.borrow_mut().push((va.raw(), length));
            let page = va.raw() & !0xfff;
            if let Some(wait) = self.refuse.get(&page) {
                return Err(suspended(*wait));
            }
            if let Some(wait) = self.physical.get(&page) {
                return Err(MemoryError::Physical(wait.clone()));
            }
            if self.unbacked.contains(&page) {
                return Err(MemoryError::HostMap("no current backing".into()));
            }
            Ok(vec![self.bytes.get(&page).copied().unwrap_or(0xee); length])
        }
        fn core_untouched_zero(&self, page: GuestVa) -> bool {
            self.zero.contains(&page.raw())
        }
    }

    fn with_exclusion<R>(mm: u64, run: impl FnOnce(&ExcludedEditor<'_>) -> R) -> R {
        let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
        let index = spaces.publish_closed(mm, 0x1000, 0).unwrap();
        let result = {
            let excluded = spaces.raise_and_wait_for_editor(index, || {});
            run(&excluded)
        };
        spaces.lower(index);
        result
    }

    fn owned() -> Fake {
        Fake {
            owner: Some(MM),
            bytes: [(0x1000, 0x11), (0x2000, 0x22), (0x3000, 0x33)].into(),
            ..Fake::default()
        }
    }

    #[test]
    fn owner_mm_reads_every_page_through_backing_never_the_portal() {
        let fake = owned();
        let bytes = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1ff0, 0x1020).unwrap()
        });
        assert_eq!(bytes.len(), 0x1020);
        assert!(bytes[..0x10].iter().all(|&byte| byte == 0x11));
        assert!(bytes[0x10..0x1010].iter().all(|&byte| byte == 0x22));
        assert!(bytes[0x1010..].iter().all(|&byte| byte == 0x33));
        assert_eq!(
            *fake.backing_reads.borrow(),
            [(0x1ff0, 0x10), (0x2000, 0x1000), (0x3000, 0x10)]
        );
    }

    #[test]
    fn a_wait_on_the_excluded_gate_is_an_invariant_violation() {
        let mut fake = owned();
        fake.refuse.insert(0x2000, wait(MM, PortalWaitCause::Gate));
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap_err()
        });
        assert!(
            matches!(error, CoreReadError::OwnGate(wait) if wait.handle().mm().raw() == MM),
            "{error:?}"
        );
    }

    #[test]
    fn another_holders_dependency_is_busy() {
        let refusal = wait(MM, PortalWaitCause::Reservations);
        let mut fake = owned();
        fake.refuse.insert(0x2000, refusal);
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap_err()
        });
        assert!(
            matches!(&error, CoreReadError::Busy(CoreReadWait::Owner(wait)) if *wait == refusal),
            "{error:?}"
        );
    }

    #[test]
    fn a_retained_physical_reader_is_busy() {
        #[derive(Debug)]
        struct Reader;
        impl carrick_guest_mem::PhysicalMemoryWait for Reader {
            fn is_ready(&self) -> bool {
                false
            }
            fn enroll(
                &self,
                _: Arc<dyn Fn() + Send + Sync>,
            ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
                (Box::new(()), false)
            }
        }
        let reader = OwnedMemoryWait(Arc::new(Reader));
        let mut fake = owned();
        fake.physical.insert(0x2000, reader.clone());
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap_err()
        });
        assert!(
            matches!(&error, CoreReadError::Busy(CoreReadWait::Physical(wait)) if *wait == reader),
            "{error:?}"
        );
    }

    #[test]
    fn a_wait_on_another_mms_owner_is_not_a_wait() {
        let mut fake = owned();
        fake.refuse
            .insert(0x2000, wait(OTHER_MM, PortalWaitCause::Gate));
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap_err()
        });
        assert!(
            matches!(error, CoreReadError::Memory(MemoryError::HostMap(_))),
            "{error:?}"
        );
    }

    #[test]
    fn an_exclusion_of_another_mm_reads_nothing() {
        let fake = owned();
        let error = with_exclusion(OTHER_MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x1000).unwrap_err()
        });
        assert!(matches!(
            error,
            CoreReadError::Memory(MemoryError::HostMap(_))
        ));
        assert!(fake.backing_reads.borrow().is_empty());
    }

    #[test]
    fn an_untranslated_page_is_a_hole_only_when_authoritatively_untouched() {
        let mut fake = owned();
        fake.untranslated.push(0x2000);
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap_err()
        });
        assert!(matches!(
            error,
            CoreReadError::Memory(MemoryError::OutOfBounds {
                address: 0x2000,
                ..
            })
        ));
        fake.zero.push(0x2000);
        let bytes = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap()
        });
        assert!(bytes[0x1000..0x2000].iter().all(|&byte| byte == 0));
        assert!(bytes[0x2000..].iter().all(|&byte| byte == 0x33));
    }

    #[test]
    fn unbacked_storage_is_a_hole_only_when_authoritatively_untouched() {
        let mut fake = owned();
        fake.unbacked.push(0x2000);
        assert!(matches!(
            with_exclusion(MM, |excluded| read_core_bytes(
                &fake, excluded, 0x2000, 0x10
            )),
            Err(CoreReadError::Memory(MemoryError::HostMap(_)))
        ));
        fake.zero.push(0x2000);
        let bytes = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x3000).unwrap()
        });
        assert!(bytes[0x1000..0x2000].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn host_owned_memory_classifies_its_ordinary_read() {
        // A host-owned engine has no owner portal; were its ordinary read
        // ever to wait on the excluded gate, the policy still refuses to
        // treat that as contention.
        let fake = Fake::default();
        let error = with_exclusion(MM, |excluded| {
            read_core_bytes(&fake, excluded, 0x1000, 0x10).unwrap_err()
        });
        assert!(matches!(error, CoreReadError::OwnGate(_)), "{error:?}");
        assert!(fake.backing_reads.borrow().is_empty());
    }
}

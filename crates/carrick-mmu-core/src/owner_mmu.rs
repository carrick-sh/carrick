//! Hardware hooks for the one reservation/transfer owner. A translation is
//! physical evidence only; MmPortal authenticates Linux permission and lifetime.
use crate::aarch64::LeafAccess;
use crate::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerTranslation {
    pub output: FrameGpa,
    pub executable: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerMmuRefusal {
    Protection,
    Unreachable,
    ExecutableCow,
}

/// ISA hooks contain no reservation, permit, frame inventory or fault policy.
/// The caller holds the exact owner editor and supplies its admitted root.
pub trait OwnerMmu {
    fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal>;
    fn translate<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        access: LeafAccess,
        user: bool,
    ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal>;
    fn classify_cow<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        executable_publication: bool,
    ) -> Result<(), OwnerMmuRefusal>;
}

pub struct Aarch64Mmu;
impl OwnerMmu for Aarch64Mmu {
    fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal> {
        RootGpa::page_aligned(FrameGpa::new(register & 0x0000_ffff_ffff_f000))
            .filter(|root| root.address().raw() != 0)
            .ok_or(OwnerMmuRefusal::Unreachable)
    }
    fn translate<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        access: LeafAccess,
        user: bool,
    ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal> {
        use crate::aarch64::terminal_descriptor_permits_el0;
        const PA: u64 = 0x0000_ffff_ffff_f000;
        let mut table = root.address().raw();
        for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
            let descriptor = words
                .load(table + ((va.raw() >> shift) & 511) * 8)
                .map_err(|_| OwnerMmuRefusal::Unreachable)?;
            if descriptor & 1 == 0 {
                return Ok(None);
            }
            if level == 3 || descriptor & 3 == 1 {
                if level == 0 {
                    return Err(OwnerMmuRefusal::Unreachable);
                }
                if user && !terminal_descriptor_permits_el0(descriptor, access) {
                    return Err(OwnerMmuRefusal::Protection);
                }
                let mask = (1u64 << shift) - 1;
                return Ok(Some(OwnerTranslation {
                    output: FrameGpa::new((descriptor & PA & !mask) + (va.raw() & mask)),
                    executable: terminal_descriptor_permits_el0(descriptor, LeafAccess::Execute),
                }));
            }
            table = descriptor & PA;
        }
        Err(OwnerMmuRefusal::Unreachable)
    }
    fn classify_cow<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        executable_publication: bool,
    ) -> Result<(), OwnerMmuRefusal> {
        use crate::aarch64::descriptor_txn::guest_cow::{
            GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
        };
        match classify_guest_cow_write(
            words,
            crate::aarch64::SubstrateGpa(root.address().raw()),
            va.raw(),
            executable_publication,
        ) {
            Ok(_) | Err(GuestCowClass::AlreadyWritable) => Ok(()),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::Executable)) => {
                Err(OwnerMmuRefusal::ExecutableCow)
            }
            Err(GuestCowClass::NotArmed(_)) => Err(OwnerMmuRefusal::Protection),
            Err(GuestCowClass::Unreachable(_)) => Err(OwnerMmuRefusal::Unreachable),
        }
    }
}

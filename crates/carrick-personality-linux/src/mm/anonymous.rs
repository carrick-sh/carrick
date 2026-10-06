//! Linux anonymous syscall interpretation over the existing admitted owner.

use carrick_core::mm::reservation::{ReservationGeometry, ReservationPolicy, Reservations};
use carrick_core_abi::*;
const PAGE_SIZE: u64 = 4096;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;

// Moved with the existing bare-metal Linux decoder: the host ABI crate is
// not in either no_std image's dependency closure.
bitflags::bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct LinuxMmapFlags: u64 {
        const SHARED = 0x01;
        const PRIVATE = 0x02;
        const FIXED = 0x10;
        const ANONYMOUS = 0x20;
        const GROWSDOWN = 0x0100;
        const STACK = 0x20000;
        const HUGETLB = 0x40000;
        const FIXED_NOREPLACE = 0x100000;
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct LinuxMremapFlags: u64 {
        const MAYMOVE = 1;
        const FIXED = 2;
    }
}

/// Keep mmap protection outside EL1's vocabulary on the host decode route.
/// The memflagmatrix oracle records ignored bits; mprotect is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapProtectionRoute {
    Reservation(carrick_core_abi::ReservationProtection),
    HostUnrepresentedBits,
}

impl MmapProtectionRoute {
    pub fn decode(bits: u64) -> Self {
        if let Some(protection) = carrick_core_abi::ReservationProtection::from_bits(bits) {
            Self::Reservation(protection)
        } else {
            Self::HostUnrepresentedBits
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousCall {
    Brk,
    Mmap,
    Unmap,
    Protect,
    Remap,
}
pub enum AnonymousDecision {
    Forward,
    Unavailable(Refusal),
    Return(i64),
    Work(ReservationRequest),
}

pub fn decide<P: ReservationPolicy, G: ReservationGeometry>(
    call: AnonymousCall,
    args: [u64; 6],
    model: &mut Reservations<'_, P, G>,
) -> AnonymousDecision {
    if !model.is_admitted() {
        return AnonymousDecision::Unavailable(Refusal::Stale);
    }
    let result = match call {
        AnonymousCall::Brk => model.brk(args[0]),
        AnonymousCall::Mmap => {
            let flags = LinuxMmapFlags::from_bits_retain(args[3]);
            let required = LinuxMmapFlags::ANONYMOUS | LinuxMmapFlags::PRIVATE;
            let supported = required | LinuxMmapFlags::FIXED | LinuxMmapFlags::FIXED_NOREPLACE;
            if flags & (required | LinuxMmapFlags::SHARED) != required
                || flags.intersects(
                    LinuxMmapFlags::GROWSDOWN | LinuxMmapFlags::STACK | LinuxMmapFlags::HUGETLB,
                )
                || !flags.difference(supported).is_empty()
            {
                return AnonymousDecision::Forward;
            }
            let prot = match MmapProtectionRoute::decode(args[2]) {
                MmapProtectionRoute::Reservation(protection) => protection,
                MmapProtectionRoute::HostUnrepresentedBits => {
                    return AnonymousDecision::Forward;
                }
            };
            if !args[5].is_multiple_of(PAGE_SIZE) {
                return AnonymousDecision::Return(-EINVAL);
            }
            let placement = if flags.contains(LinuxMmapFlags::FIXED_NOREPLACE) {
                Placement::NoReplace(args[0])
            } else if flags.contains(LinuxMmapFlags::FIXED) {
                Placement::Fixed(args[0])
            } else if args[0] == 0 {
                Placement::Anywhere
            } else {
                Placement::Hint(args[0])
            };
            model.mmap(placement, args[1], prot)
        }
        AnonymousCall::Unmap | AnonymousCall::Protect => {
            if !args[0].is_multiple_of(PAGE_SIZE) {
                return AnonymousDecision::Return(-EINVAL);
            }
            let prot = if call == AnonymousCall::Protect {
                let Some(prot) = ReservationProtection::from_bits(args[2]) else {
                    return AnonymousDecision::Return(-EINVAL);
                };
                prot
            } else {
                ReservationProtection::NONE
            };
            if args[1] == 0 {
                return AnonymousDecision::Return(if call == AnonymousCall::Unmap {
                    -EINVAL
                } else {
                    0
                });
            }
            let range = args[1]
                .checked_add(PAGE_SIZE - 1)
                .map(|v| v & !(PAGE_SIZE - 1))
                .and_then(|len| args[0].checked_add(len))
                .and_then(|end| ReservationRange::new(args[0], end));
            let Some(range) = range else {
                return AnonymousDecision::Return(-ENOMEM);
            };
            if call == AnonymousCall::Unmap {
                model.munmap(range)
            } else {
                model.mprotect(range, prot)
            }
        }
        AnonymousCall::Remap => {
            // ARM keeps its existing forwarding route; native clients admit
            // the already-owned reservation remap policy through this call.
            let flags = LinuxMremapFlags::from_bits_retain(args[3]);
            if !args[0].is_multiple_of(PAGE_SIZE)
                || args[1] == 0
                || args[2] == 0
                || !flags
                    .difference(LinuxMremapFlags::MAYMOVE | LinuxMremapFlags::FIXED)
                    .is_empty()
                || flags.contains(LinuxMremapFlags::FIXED)
                    && !flags.contains(LinuxMremapFlags::MAYMOVE)
            {
                return AnonymousDecision::Return(-EINVAL);
            }
            let Some(source) = args[1]
                .checked_add(PAGE_SIZE - 1)
                .map(|len| len & !(PAGE_SIZE - 1))
                .and_then(|len| args[0].checked_add(len))
                .and_then(|end| ReservationRange::new(args[0], end))
            else {
                return AnonymousDecision::Return(-EINVAL);
            };
            if model
                .mapping(args[0])
                .is_some_and(|m| m.flags.contains(ReservationNodeFlags::LOCKED))
            {
                return AnonymousDecision::Forward;
            }
            let target = if flags.contains(LinuxMremapFlags::FIXED) {
                MoveTarget::Fixed(args[4])
            } else if flags.contains(LinuxMremapFlags::MAYMOVE) {
                MoveTarget::MayMove
            } else {
                MoveTarget::InPlace
            };
            model.mremap(source, args[2], target)
        }
    };
    match result {
        Ok(Decision::Complete(value)) => AnonymousDecision::Return(value as i64),
        Ok(Decision::Work(request)) => AnonymousDecision::Work(request),
        Err(Refusal::Collision) => AnonymousDecision::Return(-17),
        Err(Refusal::Invalid) => AnonymousDecision::Return(-EINVAL),
        Err(Refusal::Hole) if call == AnonymousCall::Remap => AnonymousDecision::Return(-14),
        Err(Refusal::Hole | Refusal::Limit) => AnonymousDecision::Return(-ENOMEM),
        Err(Refusal::ForeignMapping) => AnonymousDecision::Forward,
        Err(
            error @ (Refusal::Busy
            | Refusal::PreparedConflict
            | Refusal::Stale
            | Refusal::MetadataRequired),
        ) => AnonymousDecision::Unavailable(error),
    }
}

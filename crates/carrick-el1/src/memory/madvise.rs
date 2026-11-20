//! Apply the shared Linux advice plan to a native reservation root.

use super::ReservationModel;
use carrick_core::mm::reservation::{Refusal, ReservationGeometry};
use carrick_el1_abi::{ReservationNodeFlags as Flags, ReservationRange};
use carrick_guest_arch::{GuestLen, GuestVa};
use carrick_personality_linux::mm::{
    NodeFlagsPolicy,
    madvise::{Advice, Assessment, Class, Range},
};
use carrick_syscall_abi::{LINUX_ENOMEM, LinuxErrno};

pub(super) enum Effect {
    Answer(Result<(), LinuxErrno>),
    Attributes(ReservationRange, Flags, Flags, Result<(), LinuxErrno>),
    Discard(ReservationRange, Result<(), LinuxErrno>),
}

#[inline(never)]
pub(super) fn plan<G: ReservationGeometry, C: Copy + Send + Sync + zerocopy::FromZeros>(
    root: &mut ReservationModel<'_, G, C>,
    address: GuestVa,
    length: GuestLen,
    advice: Advice,
    page_size: GuestLen,
) -> Result<Effect, Refusal> {
    let range = match Range::from_args(address, length, advice, page_size) {
        Err(errno) => return Ok(Effect::Answer(Err(errno))),
        Ok(range) if range.is_empty() => return Ok(Effect::Answer(Ok(()))),
        Ok(range) => range,
    };
    let Some(span) = ReservationRange::new(range.start.raw(), range.end.raw()) else {
        return Ok(Effect::Answer(Err(LINUX_ENOMEM)));
    };
    let mut assessment = Assessment::new(range);
    let mut locked = false;
    let mut foreign = false;
    root.observe_range(span, &mut |mapping| {
        let flags = mapping.flags;
        let class = if flags.root_editable() && mapping.host_backing.is_some() {
            Class::PrivateFile
        } else if flags.root_editable()
            && flags.contains(Flags::ANONYMOUS_PRIVATE)
            // Imported image bytes have no retained file source for re-fault.
            && !(flags.contains(Flags::IMAGE) && advice == Advice::DontNeed)
        {
            Class::PrivateAnonymous
        } else {
            foreign = true;
            Class::Special
        };
        locked |= flags.contains(Flags::LOCKED);
        assessment.observe(
            Range {
                start: GuestVa::new(mapping.range.start().max(span.start())),
                end: GuestVa::new(mapping.range.end().min(span.end())),
            },
            class,
            false,
        );
    })?;
    if foreign {
        return Err(Refusal::ForeignMapping);
    }
    let result = match assessment.verdict(advice, locked) {
        Ok(result) => result,
        Err(errno) => return Ok(Effect::Answer(Err(errno))),
    };
    // All covered mappings are private and owned. Retire their backing in
    // one edit. The planner's hole verdict follows successful effects.
    if advice == Advice::DontNeed {
        Ok(Effect::Discard(span, result))
    } else if let Some((flag, enabled)) = advice.reservation_attribute() {
        let (set, clear) = if enabled {
            (flag, Flags::EMPTY)
        } else {
            (Flags::EMPTY, flag)
        };
        Ok(Effect::Attributes(span, set, clear, result))
    } else {
        Ok(Effect::Answer(result))
    }
}

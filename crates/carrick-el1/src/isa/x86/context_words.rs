//! Zero-valid CPL0 scheduler context storage and authenticated conversion.

use crate::isa::ArchError;
use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
use core::num::NonZeroU64;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::scheduler;
#[cfg(all(test, not(target_os = "none")))]
#[path = "../../../../carrick-x86/src/cpl0_scheduler.rs"]
#[allow(dead_code)] // The host unit test uses only native context records.
mod scheduler;

/// An all-zero valid scheduler record for CPL0. The typed live address
/// context is reconstructed only with the expected owner generation.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, zerocopy::FromZeros)]
pub struct ParkedContextWords {
    pub frame: scheduler::InterruptFrame,
    root: u64,
    mm: u64,
    generation: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    _xsave_align: [u8; 56],
    pub xsave: [u8; scheduler::XSAVE_BYTES],
}

const _: () = {
    assert!(core::mem::offset_of!(ParkedContextWords, frame) == 0);
    assert!(core::mem::offset_of!(ParkedContextWords, root) == 160);
    assert!(core::mem::offset_of!(ParkedContextWords, mm) == 168);
    assert!(core::mem::offset_of!(ParkedContextWords, generation) == 176);
    assert!(core::mem::offset_of!(ParkedContextWords, fs_base) == 184);
    assert!(core::mem::offset_of!(ParkedContextWords, gs_base) == 192);
    assert!(core::mem::offset_of!(ParkedContextWords, _xsave_align) == 200);
    assert!(core::mem::offset_of!(ParkedContextWords, xsave) == 256);
    assert!(core::mem::size_of::<ParkedContextWords>() == 1088);
    assert!(core::mem::align_of::<ParkedContextWords>() == 64);
};

impl ParkedContextWords {
    pub const ZERO: Self = Self {
        frame: scheduler::InterruptFrame {
            gpr: [0; 15],
            rip: 0,
            cs: 0,
            flags: 0,
            rsp: 0,
            ss: 0,
        },
        root: 0,
        mm: 0,
        generation: 0,
        fs_base: 0,
        gs_base: 0,
        _xsave_align: [0; 56],
        xsave: [0; scheduler::XSAVE_BYTES],
    };

    pub fn from_native(context: &scheduler::NativeContext) -> Self {
        let mut xsave = [0; scheduler::XSAVE_BYTES];
        xsave.copy_from_slice(&context.xsave.0);
        Self {
            frame: context.frame,
            root: context.address.root.address().raw(),
            mm: context.address.mm.raw().get(),
            generation: context.address.generation.raw().get(),
            fs_base: context.fs_base,
            gs_base: context.gs_base,
            _xsave_align: [0; 56],
            xsave,
        }
    }

    /// Refuse an empty, corrupt or recycled record before installing CR3 or
    /// restoring user state. The caller supplies its exact live MM authority.
    pub fn into_native(
        self,
        expected: AddressContext<RootGpa>,
    ) -> Result<scheduler::NativeContext, ArchError> {
        let root = RootGpa::page_aligned(FrameGpa::new(self.root))
            .filter(|_| self.root != 0)
            .ok_or(ArchError::InvalidContext)?;
        let mm = NonZeroU64::new(self.mm)
            .map(MmGeneration::new)
            .ok_or(ArchError::InvalidContext)?;
        let generation = NonZeroU64::new(self.generation)
            .map(ContextGeneration::new)
            .ok_or(ArchError::InvalidContext)?;
        let address = AddressContext {
            root,
            mm,
            generation,
        };
        if address != expected {
            return Err(ArchError::InvalidContext);
        }
        Ok(scheduler::NativeContext {
            frame: self.frame,
            address,
            fs_base: self.fs_base,
            gs_base: self.gs_base,
            xsave: scheduler::XsaveArea(self.xsave),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{ContextGeneration, MmGeneration};
    use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
    use carrick_sched_core::spaces::notification::{
        SpaceAccess, SpaceReleaseVenue, SpaceWaitCause,
    };
    use carrick_sched_core::{BoundedSpin, SlotId, ThreadIdentity, Waker, ZoneTables};

    fn deliver_x86_notification(
        _: &ZoneTables<ParkedContextWords>,
        _: Waker,
        effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }

    #[test]
    fn zero_or_recycled_context_cannot_become_live_native_state() {
        let expected = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(7).unwrap()),
        };
        assert!(matches!(
            ParkedContextWords::ZERO.into_native(expected),
            Err(ArchError::InvalidContext)
        ));
        let mut xsave = scheduler::XsaveArea::ZERO;
        xsave.0[816] = 0xa5;
        let native = scheduler::NativeContext {
            frame: scheduler::InterruptFrame {
                gpr: [0x33; 15],
                rip: 0x1000,
                cs: 0x23,
                flags: 0x202,
                rsp: 0x8000,
                ss: 0x1b,
            },
            address: expected,
            fs_base: 0x4000,
            gs_base: 0x5000,
            xsave,
        };
        let words = ParkedContextWords::from_native(&native);
        let restored = words.into_native(expected).unwrap();
        assert_eq!(restored.frame, native.frame);
        assert_eq!(restored.address, native.address);
        assert_eq!((restored.fs_base, restored.gs_base), (0x4000, 0x5000));
        assert_eq!(restored.xsave.0[816], 0xa5);
        let recycled = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(8).unwrap()),
            ..expected
        };
        assert!(matches!(
            words.into_native(recycled),
            Err(ArchError::InvalidContext)
        ));
    }

    #[test]
    fn shared_scheduler_record_carries_x86_context_without_arm_layout() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: every ZoneTables field is zero-valid and the context type
        // implements FromZeros; this allocation owns the full aligned table.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            std::boxed::Box::from_raw(ptr)
        };
        let slot = SlotId::new(0);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 11, Some(0), 0);
        zone.enter_guest(slot);
        let space = zone.spaces.publish_closed(11, 0x6000, 0).unwrap();
        zone.spaces.open(space);
        let record = zone
            .alloc_record(ThreadIdentity {
                mm: 11,
                tid: 41,
                serial: 17,
                generation: 1,
                ..Default::default()
            })
            .unwrap();
        // SAFETY: the newly allocated record is owned by this fixture until
        // requeue; no other actor can read or write its context yet.
        unsafe { *zone.record(record).ctx_mut() = ParkedContextWords::ZERO };
        zone.requeue_preempted(slot, record);
        assert_eq!(zone.switch_in(slot), Some(record));
        // SAFETY: this fixture is the only driver of the on-CPU slot.
        assert!(matches!(
            unsafe { *zone.record(record).ctx_mut() }.into_native(AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
                mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
            }),
            Err(ArchError::InvalidContext)
        ));
    }

    #[test]
    fn x86_zone_owns_exact_space_notification_custody() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: the scheduler table and x86 context words are zero-valid;
        // this allocation owns the full aligned table for the fixture.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            std::boxed::Box::from_raw(ptr)
        };
        let space = zone.spaces.publish_closed(11, 0x6000, 0).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(11).unwrap()).unwrap();
        let incarnation = NonZeroU64::new(1).unwrap();
        entry
            .admit_notifications(incarnation, &BoundedSpin(0), &|effects| {
                let _ = effects.deliver_handbacks(&mut |_| {});
            })
            .unwrap();
        let lease = entry.notifications(incarnation).unwrap();
        assert_eq!(lease.key(SpaceWaitCause::Gate).generation(), 1);
        let venue = SpaceReleaseVenue {
            zone: &zone,
            waker: Waker::Host,
            deliver: deliver_x86_notification,
        };
        let access = SpaceAccess::notified(venue);
        access.open(space);
        let editor = access
            .try_begin_edit(space, 11, NonZeroU64::new(2).unwrap())
            .unwrap();
        editor.set_mmap_next(0x8000);
        assert_eq!(editor.mmap_next(), 0x8000);
        drop(editor);
        zone.spaces.close(space);
        drop(lease);
        entry.close_notifications(incarnation, venue).unwrap();
        entry.retire_entry(venue);
    }
}

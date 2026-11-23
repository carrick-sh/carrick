//! CPL0 conversion through the shared parked-context ABI.

use crate::isa::ArchError;
use carrick_guest_arch::{AddressContext, RootGpa};
pub use carrick_sched_core::ParkedContextWords;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::{native, scheduler};
#[cfg(all(test, not(target_os = "none")))]
use crate::isa::x86::context::native;
#[cfg(all(test, not(target_os = "none")))]
#[path = "../../../../carrick-x86/src/cpl0_scheduler.rs"]
#[allow(dead_code)] // Host unit tests use only native context records.
pub(crate) mod scheduler;

pub fn from_native(
    context: &scheduler::NativeContext,
    position: carrick_sched_core::SavedSyscallPc,
) -> ParkedContextWords {
    scheduler::park_native_context(context, position)
}

pub fn into_native(
    words: ParkedContextWords,
    expected: AddressContext<RootGpa>,
) -> Result<scheduler::NativeContext, ArchError> {
    scheduler::restore_native_context(words, expected).ok_or(ArchError::InvalidContext)
}

/// Convert a syscall return using TLS and XSAVE captured before entering Rust.
/// SYSCALL already clobbered RCX and R11 with the return PC and flags. Keep
/// those values in the GPR slots as well as the IRET tail; every other GPR
/// follows the interrupt entry's push order, not NativeFrame's push order.
pub fn from_syscall(
    frame: &native::NativeFrame,
    address: AddressContext<RootGpa>,
    fs_base: u64,
    user_gs_base: u64,
    xsave: &scheduler::XsaveArea,
) -> Result<scheduler::NativeContext, ArchError> {
    if !frame.valid_user_return() {
        return Err(ArchError::InvalidFrame);
    }
    Ok(scheduler::NativeContext {
        frame: scheduler::InterruptFrame {
            gpr: [
                frame.r15,
                frame.r14,
                frame.r13,
                frame.r12,
                frame.rbp,
                frame.rbx,
                frame.user_r11,
                frame.r10,
                frame.r9,
                frame.r8,
                frame.rax,
                frame.user_rcx,
                frame.rdx,
                frame.rsi,
                frame.rdi,
            ],
            rip: frame.rcx,
            cs: 0x23,
            flags: frame.r11,
            rsp: frame.rsp,
            ss: 0x1b,
        },
        address,
        fs_base,
        gs_base: user_gs_base,
        xsave: xsave.clone(),
    })
}

/// Recover a syscall frame from its exact retained address owner.
/// The independent user GPR slots retain IRQ RCX/R11 even when they differ
/// from the return PC/flags. `position` is where the context's RIP sits:
/// the frame carries it, so a rerun of the frame never re-derives it
/// (#2900).
pub fn syscall_frame_from_native(
    context: &scheduler::NativeContext,
    expected: AddressContext<RootGpa>,
    position: carrick_sched_core::SavedSyscallPc,
) -> Result<native::NativeFrame, ArchError> {
    if context.address != expected || !context.frame.valid_user_return() {
        return Err(ArchError::InvalidContext);
    }
    use carrick_sched_core::X86ParkedGpr as Gpr;
    let gpr = |register: Gpr| context.frame.gpr[register as usize];
    Ok(native::NativeFrame {
        r15: gpr(Gpr::R15),
        r14: gpr(Gpr::R14),
        r13: gpr(Gpr::R13),
        r12: gpr(Gpr::R12),
        rbp: gpr(Gpr::Rbp),
        rbx: gpr(Gpr::Rbx),
        r9: gpr(Gpr::R9),
        r8: gpr(Gpr::R8),
        r10: gpr(Gpr::R10),
        rdx: gpr(Gpr::Rdx),
        rsi: gpr(Gpr::Rsi),
        rdi: gpr(Gpr::Rdi),
        rax: gpr(Gpr::Rax),
        rcx: context.frame.rip,
        r11: context.frame.flags,
        rsp: context.frame.rsp,
        user_rcx: gpr(Gpr::Rcx),
        user_r11: gpr(Gpr::R11),
        syscall_position: carrick_guest_arch::SavedSyscallPcWord::new(position),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
    use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
    use carrick_sched_core::spaces::notification::{
        SpaceAccess, SpaceReleaseVenue, SpaceWaitCause,
    };
    use carrick_sched_core::{BoundedSpin, SlotId, ThreadIdentity, Waker, ZoneTables};
    use core::num::NonZeroU64;

    fn syscall_fixture() -> (
        native::NativeFrame,
        AddressContext<RootGpa>,
        scheduler::XsaveArea,
    ) {
        let frame = native::NativeFrame {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 6,
            rbx: 3,
            r9: 9,
            r8: 8,
            r10: 10,
            rdx: 2,
            rsi: 4,
            rdi: 5,
            rax: 1,
            rcx: 0x1234,
            r11: 0x302,
            rsp: 0x8000,
            user_rcx: 0x1234,
            user_r11: 0x302,
            syscall_position: Default::default(),
        };
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(7).unwrap()),
        };
        let mut xsave = scheduler::XsaveArea::ZERO;
        for (index, byte) in xsave.0.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        (frame, address, xsave)
    }

    #[test]
    fn syscall_conversion_preserves_register_order_tls_and_early_xsave() {
        let (frame, address, xsave) = syscall_fixture();
        let context = from_syscall(&frame, address, 0x4000, 0x5000, &xsave).unwrap();
        let words = from_native(&context, carrick_sched_core::SavedSyscallPc::AfterSyscall);
        assert_eq!(
            words.frame,
            [
                15, 14, 13, 12, 6, 3, 0x302, 10, 9, 8, 1, 0x1234, 2, 4, 5, 0x1234, 0x23, 0x302,
                0x8000, 0x1b,
            ]
        );
        assert_eq!((words.fs_base, words.gs_base), (0x4000, 0x5000));
        assert_eq!(words.xsave, xsave.0);
        let restored = into_native(words, address).unwrap();
        let returned = syscall_frame_from_native(
            &restored,
            address,
            carrick_sched_core::SavedSyscallPc::AtSyscall,
        )
        .unwrap();
        assert_eq!(
            returned.syscall_position.get(),
            Some(carrick_sched_core::SavedSyscallPc::AtSyscall),
            "the frame carries the restored context's position"
        );
        assert_eq!(
            [
                returned.r15,
                returned.r14,
                returned.r13,
                returned.r12,
                returned.rbp,
                returned.rbx,
                returned.r9,
                returned.r8,
                returned.r10,
                returned.rdx,
                returned.rsi,
                returned.rdi,
                returned.rax,
                returned.rcx,
                returned.r11,
                returned.rsp,
            ],
            [
                15, 14, 13, 12, 6, 3, 9, 8, 10, 2, 4, 5, 1, 0x1234, 0x302, 0x8000
            ]
        );
        assert_eq!(restored.xsave.0, xsave.0);
    }

    #[test]
    fn context_conversion_keeps_irq_gprs_and_refuses_invalid_return() {
        let (frame, address, xsave) = syscall_fixture();
        for invalid in [
            native::NativeFrame { rcx: 0, ..frame },
            native::NativeFrame {
                rsp: 1 << 47,
                ..frame
            },
            native::NativeFrame {
                r11: 0x3002,
                ..frame
            },
        ] {
            assert!(matches!(
                from_syscall(&invalid, address, 0, 0, &xsave),
                Err(ArchError::InvalidFrame)
            ));
        }
        let context = from_syscall(&frame, address, 0, 0, &xsave).unwrap();
        for expected in [
            AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).unwrap(),
                ..address
            },
            AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(12).unwrap()),
                ..address
            },
            AddressContext {
                generation: ContextGeneration::new(NonZeroU64::new(8).unwrap()),
                ..address
            },
        ] {
            assert!(matches!(
                syscall_frame_from_native(
                    &context,
                    expected,
                    carrick_sched_core::SavedSyscallPc::AfterSyscall
                ),
                Err(ArchError::InvalidContext)
            ));
        }
        let mut irq = context.clone();
        irq.frame.gpr[6] = 0x56789;
        irq.frame.gpr[11] = 0x12345;
        let returned =
            syscall_frame_from_native(&irq, address, carrick_sched_core::SavedSyscallPc::AtSyscall)
                .unwrap();
        assert_eq!(returned.user_rcx, 0x12345);
        assert_eq!(returned.user_r11, 0x56789);
        assert_eq!(
            from_syscall(&returned, address, irq.fs_base, irq.gs_base, &irq.xsave)
                .unwrap()
                .frame,
            irq.frame
        );
        for (word, value) in [(16, 8), (19, 16)] {
            let mut words = from_native(&context, carrick_sched_core::SavedSyscallPc::AfterSyscall);
            words.frame[word] = value;
            let invalid = scheduler::NativeContext {
                frame: scheduler::InterruptFrame {
                    gpr: words.frame[..15].try_into().unwrap(),
                    rip: words.frame[15],
                    cs: words.frame[16],
                    flags: words.frame[17],
                    rsp: words.frame[18],
                    ss: words.frame[19],
                },
                ..context.clone()
            };
            assert!(matches!(
                syscall_frame_from_native(
                    &invalid,
                    address,
                    carrick_sched_core::SavedSyscallPc::AfterSyscall
                ),
                Err(ArchError::InvalidContext)
            ));
        }
    }

    fn deliver_x86_notification(
        _: &ZoneTables<ParkedContextWords>,
        _: Waker,
        effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }

    /// #2900: the syscall position travels with the frame through every
    /// conversion the return checkpoint and the resume path make, for each
    /// entry kind. A context built from a frame takes the frame's position,
    /// and a frame built from a context takes the context's, so a rerun of
    /// either rewinds only a PC that is after its `SYSCALL`, and only once.
    #[test]
    fn syscall_position_travels_with_the_frame_for_each_entry_kind() {
        use carrick_guest_arch::{ProcessContext, SyscallReturnFrame};
        use carrick_sched_core::SavedSyscallPc::{AfterSyscall, AtSyscall};
        let (trapped, address, xsave) = syscall_fixture();
        let save = |frame: &native::NativeFrame| {
            from_native(
                &from_syscall(frame, address, 0, 0, &xsave).unwrap(),
                frame.syscall_position().unwrap(),
            )
        };
        let restore = |words: ParkedContextWords| {
            syscall_frame_from_native(
                &into_native(words, address).unwrap(),
                address,
                words.saved_syscall_pc().unwrap(),
            )
            .unwrap()
        };
        // A fresh trap: the entry assembly's zero word, after its SYSCALL.
        assert_eq!(trapped.syscall_position(), Some(AfterSyscall));
        let words = save(&trapped);
        assert_eq!(
            (words.user_rip(), words.saved_syscall_pc()),
            (0x1234, Some(AfterSyscall))
        );
        // Parked at the boundary: a frame rewound in place is saved at its
        // SYSCALL, and its resumed frame stays there however often it reruns.
        let mut rewound = trapped;
        assert_eq!(rewound.rewind_to_syscall(), Some(0x1232));
        let mut words = save(&rewound);
        assert_eq!(
            (words.user_rip(), words.saved_syscall_pc()),
            (0x1232, Some(AtSyscall))
        );
        words.restart_syscall();
        let mut resumed = restore(words);
        assert_eq!(
            (resumed.rcx, resumed.syscall_position()),
            (0x1232, Some(AtSyscall))
        );
        assert_eq!(resumed.rewind_to_syscall(), Some(0x1232));
        assert_eq!(
            (resumed.rax, resumed.rdi, resumed.rsi),
            (trapped.rax, trapped.rdi, trapped.rsi)
        );
        // A handler entry and a sigreturn-restored RIP are resume points,
        // which the signal codec writes with their position.
        for pc in [0x5000, 0x1232, 0x1234] {
            let mut entered = trapped;
            entered.replace_return_pc(pc, AtSyscall);
            let mut words = save(&entered);
            assert_eq!(words.saved_syscall_pc(), Some(AtSyscall));
            words.restart_syscall();
            assert_eq!(words.user_rip(), pc, "a resume point is never rewound");
            assert_eq!(restore(words).syscall_pc(), Some(pc));
        }
    }

    #[test]
    fn zero_or_recycled_context_cannot_become_live_native_state() {
        let expected = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(7).unwrap()),
        };
        assert!(matches!(
            into_native(ParkedContextWords::ZERO, expected),
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
        let words = from_native(&native, carrick_sched_core::SavedSyscallPc::AfterSyscall);
        let restored = into_native(words, expected).unwrap();
        assert_eq!(restored.frame, native.frame);
        assert_eq!(restored.address, native.address);
        assert_eq!((restored.fs_base, restored.gs_base), (0x4000, 0x5000));
        assert_eq!(restored.xsave.0[816], 0xa5);
        let recycled = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(8).unwrap()),
            ..expected
        };
        assert!(matches!(
            into_native(words, recycled),
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
        assert!(zone.requeue_preempted(slot, record).is_queued());
        assert_eq!(zone.switch_in(slot), Some(record));
        // SAFETY: this fixture is the only driver of the on-CPU slot.
        assert!(matches!(
            into_native(
                unsafe { *zone.record(record).ctx_mut() },
                AddressContext {
                    root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
                    mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
                    generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
                }
            ),
            Err(ArchError::InvalidContext)
        ));
    }

    #[test]
    fn x86_parked_context_roots_clone_through_shared_fork_owner() {
        use crate::memory::reservations::{
            LinuxReservationLayout, NoRootWait, X86Cpl0Reservations, X86Cpl0RootReleaseVenue,
        };
        use carrick_core::mm::fork::{ForkChildRoot, ForkParentRoot};
        use carrick_el1_abi::{
            PortalForkRequest, PortalForkTableArena, PortalOperation, ReservationMm,
            ReservationProtection, ReservationRange,
        };
        const _: () = {
            assert!(
                core::mem::align_of::<carrick_test_support::TestEl1Region>()
                    >= core::mem::align_of::<X86Cpl0Reservations>()
            );
            assert!(
                core::mem::align_of::<carrick_test_support::TestEl1Region>()
                    >= core::mem::align_of::<ZoneTables<ParkedContextWords>>()
            );
        };
        let region = carrick_test_support::TestEl1Region::zeroed();
        // SAFETY: this aligned region retains both zeroed ABI records at
        // their CPL0 offsets through every root guard and notification lease.
        let (table, zone) = unsafe {
            (
                &*region
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                    .cast::<X86Cpl0Reservations>(),
                &*region
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize)
                    .cast::<ZoneTables<ParkedContextWords>>(),
            )
        };
        let parent_mm = ReservationMm::new(11).unwrap();
        let child_mm = ReservationMm::new(12).unwrap();
        let parent_slot = zone
            .spaces
            .publish_closed(parent_mm.raw(), 0x6000, 0)
            .unwrap();
        let child_slot = zone
            .spaces
            .publish_closed(child_mm.raw(), 0x7000, 0)
            .unwrap();
        let layout = LinuxReservationLayout {
            heap: ReservationRange::new(0x200000, 0x300000).unwrap(),
            arena: ReservationRange::new(0x400000, 0x800000).unwrap(),
            brk: 0x200000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        };
        table
            .publish(parent_slot.index(), parent_mm, layout)
            .unwrap();
        table.publish(child_slot.index(), child_mm, layout).unwrap();
        let venue = X86Cpl0RootReleaseVenue::new(
            table,
            SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
                    deliver_x86_notification,
                ),
            },
        )
        .unwrap();
        let mut parent = venue
            .lock(parent_slot.index(), parent_mm, &NoRootWait)
            .unwrap();
        let range = ReservationRange::new(0x100000, 0x101000).unwrap();
        parent
            .import(range, ReservationProtection::READ_WRITE, true)
            .unwrap();
        parent.finish_import().unwrap();
        let mut child = venue
            .lock(child_slot.index(), child_mm, &NoRootWait)
            .unwrap();
        let request = PortalForkRequest {
            operation: PortalOperation {
                carrier: NonZeroU64::MIN,
                mm: parent_mm,
                incarnation: NonZeroU64::new(parent.incarnation().raw()).unwrap(),
                sequence: parent.next_transfer_sequence().unwrap(),
            },
            parent_generation: parent.generation(),
            child_mm,
            child_tables: PortalForkTableArena::new(0x200000, 4096).unwrap(),
            parent_tables: PortalForkTableArena::new(0x300000, 4096).unwrap(),
            kernel_control_ipa: 0xa00000,
        };
        ForkParentRoot::reserve_fork_certificate(&mut parent, request).unwrap();
        ForkChildRoot::set_fork_origin(&mut child, request).unwrap();
        ForkParentRoot::clone_into(&mut parent, &mut child).unwrap();
        assert!(ForkChildRoot::is_admitted(&child));
        let mut inherited = std::vec::Vec::new();
        child
            .observe_mappings(&mut |mapping| inherited.push(mapping))
            .unwrap();
        assert_eq!(inherited.len(), 1);
        assert_eq!(inherited[0].range, range);
        assert!(inherited[0].anonymous);
        assert_eq!(child.mm(), child_mm);
        assert_eq!(parent.mm(), parent_mm);
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
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(
                deliver_x86_notification,
            ),
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

//! Native context custody for the existing shared scheduler. Queue ordering,
//! claims, preemption and wake ownership remain in `carrick-sched-core`.
//! Included directly by the freestanding image; no host dependencies here.
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::{Claim, RecordRef, SlotId, ZoneTables};

/// PUSH order paired with the interrupt image leaf; IRET's five words follow.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterruptFrame {
    pub gpr: [u64; 15],
    pub rip: u64,
    pub cs: u64,
    pub flags: u64,
    pub rsp: u64,
    pub ss: u64,
}
const _: () = assert!(core::mem::size_of::<InterruptFrame>() == 160);
const _: () = assert!(core::mem::offset_of!(InterruptFrame, rip) == 120);

/// Standard XSAVE with XCR0=x87|SSE|AVX. Bootstrap must qualify CPUID.0D
/// and reject any other enabled component before publishing a task.
pub const XSAVE_BYTES: usize = 832;
pub const XSTATE_MASK: u64 = 7;
#[repr(C, align(64))]
#[derive(Clone)]
pub struct XsaveArea(pub [u8; XSAVE_BYTES]);
impl XsaveArea {
    pub const ZERO: Self = Self([0; XSAVE_BYTES]);
}

#[repr(C)]
#[derive(Clone)]
pub struct NativeContext {
    pub frame: InterruptFrame,
    pub address: AddressContext<RootGpa>,
    pub fs_base: u64,
    pub gs_base: u64,
    pub xsave: XsaveArea,
}

/// An ISA sidecar belongs to one exact shared record incarnation. It stores
/// only machine state, never runnable/blocked state or an alternate queue.
#[repr(C)]
pub struct ContextBinding {
    pub record: RecordRef,
    pub context: NativeContext,
}

/// Bounded hardware witness/control record, outside the common ABI. This is
/// NOT a production task graph or MM owner. The carrier initializes it while
/// stopped and retains it until VM retirement.
pub const PROGRESS_STATE: u64 = 0x170_0000;
pub const PROGRESS_ZONE: u64 = 0x100_0000;
pub const PROGRESS_HEADER: u64 = 0x1f_0000;
pub const PROGRESS_MAGIC: u64 = 0x4d34_4350_4c30_0001;
pub const PROGRESS_DATA: u64 = 0x5_0000;
pub const PROGRESS_ENTRY_PORT: u16 = 0xcd;
pub const PROGRESS_RETURN_PORT: u16 = 0xce;
pub const PROGRESS_DONE_PORT: u16 = 0xcf;
pub const PROGRESS_TURNS: usize = 16;

#[repr(C)]
pub struct ProgressHeader {
    pub magic: u64,
    pub entry: unsafe extern "C" fn() -> !,
    pub timer: unsafe extern "C" fn(),
    pub kick: unsafe extern "C" fn(),
}

#[repr(C)]
pub struct ProgressState {
    pub tasks: [ContextBinding; 2],
    pub maintenance_root: RootGpa,
    pub turns: u64,
    pub order: [u64; PROGRESS_TURNS],
    pub roots: [u64; PROGRESS_TURNS],
    pub iterations: [u64; PROGRESS_TURNS],
    pub wakes: u64,
    pub kick_irqs: u64,
    pub timer_irqs: u64,
    pub failure: u64,
    pub wake_mm: u64,
    pub wake_address: u64,
    pub scratch: XsaveArea,
}

impl ContextBinding {
    pub fn owned_on(&self, zone: &ZoneTables, slot: SlotId) -> bool {
        zone.live(self.record).is_some_and(
            |record| matches!(record.claim(), Claim::OnCpu { slot: owner, .. } if owner == slot),
        )
    }
}

/// Switch admission through the SAME occupancy/gate authority as ARM.
/// The caller first installs its maintenance root; after this grant it must
/// install the exact native root before restoring user state. N1's eventual
/// root receipt validation is deliberately not synthesized here.
pub fn admit_context(zone: &ZoneTables, slot: SlotId, binding: &ContextBinding) -> bool {
    if !binding.owned_on(zone, slot) {
        return false;
    }
    let mm = binding.context.address.mm.raw().get();
    let Some(grant) = zone.install_space(slot, mm) else {
        return false;
    };
    if grant.cow_owed.is_some() || grant.ttbr0 != binding.context.address.root.address().raw() {
        zone.release_space(slot);
        return false;
    }
    true
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
/// Install a qualified no-PCID, non-global root. The bootstrap forbids PGE and
/// PCIDE; MOV CR3 therefore flushes every task translation on this CPU.
/// # Safety
/// The caller holds address-context admission, and both roots retain all
/// executing supervisor code, stack, IDT and context storage.
pub unsafe fn install_root(root: RootGpa) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) root.address().raw(), options(nostack));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
    use carrick_sched_core::ThreadIdentity;
    use std::num::NonZeroU64;

    #[test]
    fn shared_queue_cross_mm_admission_refuses_stale_native_custody() {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        // SAFETY: documented all-zero empty state; uniquely owned box.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let slot = SlotId::new(0);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 11, Some(0), 0);
        zone.enter_guest(slot);
        let mut bindings = Vec::new();
        for mm in [11, 12] {
            let root = RootGpa::page_aligned(FrameGpa::new(mm << 12)).unwrap();
            let index = zone
                .spaces
                .publish_closed(mm, root.address().raw(), 0)
                .unwrap();
            zone.spaces.open(index);
            let record = zone
                .alloc_record(ThreadIdentity {
                    mm,
                    tid: mm,
                    serial: mm,
                    generation: 1,
                    ..Default::default()
                })
                .unwrap();
            zone.requeue_preempted(slot, record);
            bindings.push(ContextBinding {
                record: zone.record_ref(record),
                context: NativeContext {
                    frame: InterruptFrame {
                        gpr: [mm; 15],
                        rip: mm * 100,
                        cs: 0x23,
                        flags: 0x202,
                        rsp: mm * 1000,
                        ss: 0x1b,
                    },
                    address: AddressContext {
                        root,
                        mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
                        generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
                    },
                    fs_base: mm * 16,
                    gs_base: mm * 32,
                    xsave: XsaveArea([mm as u8; XSAVE_BYTES]),
                },
            });
        }
        for turn in 0..8 {
            let id = zone.switch_in(slot).unwrap();
            let binding = &bindings[turn % 2];
            assert_eq!(id, binding.record.id);
            assert!(admit_context(&zone, slot, binding));
            assert_eq!(
                zone.installed_space(slot),
                binding.context.address.mm.raw().get()
            );
            assert!(!admit_context(&zone, slot, &bindings[(turn + 1) % 2]));
            zone.release_space(slot);
            zone.requeue_preempted(slot, id);
        }
        let id = zone.switch_in(slot).unwrap();
        let mut stale = ContextBinding {
            record: bindings[0].record,
            context: bindings[0].context.clone(),
        };
        stale.record.incarnation += 1;
        assert!(!admit_context(&zone, slot, &stale));
        let index = zone.spaces.find(11).unwrap();
        zone.spaces.close(index);
        assert!(!admit_context(&zone, slot, &bindings[0]));
        assert_eq!(id, bindings[0].record.id);
    }
}

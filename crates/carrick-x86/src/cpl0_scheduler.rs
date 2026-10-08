//! Native context custody for the existing shared scheduler. Queue ordering,
//! claims, preemption and wake ownership remain in `carrick-sched-core`.
//! Included directly by the freestanding image; no host dependencies here.
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::{
    Claim, ParkedContextWords, RecordRef, SlotId, X86_XSAVE_BYTES, ZoneTables,
};

/// PUSH order paired with the interrupt image leaf; IRET's five words follow.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, zerocopy::FromZeros)]
pub struct InterruptFrame {
    pub gpr: [u64; 15],
    pub rip: u64,
    pub cs: u64,
    pub flags: u64,
    pub rsp: u64,
    pub ss: u64,
}
impl InterruptFrame {
    pub fn valid_user_return(&self) -> bool {
        self.cs == 0x23
            && self.ss == 0x1b
            && carrick_sched_core::valid_user_return_words(self.rip, self.rsp, self.flags)
    }
}
const _: () = assert!(core::mem::size_of::<InterruptFrame>() == 160);
const _: () = {
    assert!(core::mem::offset_of!(InterruptFrame, gpr) == 0);
    assert!(core::mem::offset_of!(InterruptFrame, rip) == 120);
    assert!(core::mem::offset_of!(InterruptFrame, cs) == 128);
    assert!(core::mem::offset_of!(InterruptFrame, flags) == 136);
    assert!(core::mem::offset_of!(InterruptFrame, rsp) == 144);
    assert!(core::mem::offset_of!(InterruptFrame, ss) == 152);
};

/// Standard XSAVE with XCR0=x87|SSE|AVX. Bootstrap must qualify CPUID.0D
/// and reject any other enabled component before publishing a task.
pub const XSAVE_BYTES: usize = 832;
pub const XSTATE_MASK: u64 = 7;
const _: () = assert!(XSAVE_BYTES == X86_XSAVE_BYTES);
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
const _: () = {
    assert!(core::mem::offset_of!(NativeContext, frame) == 0);
    assert!(core::mem::offset_of!(NativeContext, address) == 160);
    assert!(core::mem::offset_of!(NativeContext, fs_base) == 184);
    assert!(core::mem::offset_of!(NativeContext, gs_base) == 192);
    assert!(core::mem::offset_of!(NativeContext, xsave) == 256);
    assert!(core::mem::size_of::<NativeContext>() == 1088);
    assert!(core::mem::align_of::<NativeContext>() == 64);
};

/// Serialize machine state into the zero-valid shared record. The caller owns
/// that record's claim until it publishes the runnable or parked transition.
pub fn park_native_context(context: &NativeContext) -> ParkedContextWords {
    let mut frame = [0; 20];
    frame[..15].copy_from_slice(&context.frame.gpr);
    frame[15..].copy_from_slice(&[
        context.frame.rip,
        context.frame.cs,
        context.frame.flags,
        context.frame.rsp,
        context.frame.ss,
    ]);
    ParkedContextWords::from_parts(
        frame,
        context.address,
        context.fs_base,
        context.gs_base,
        context.xsave.0,
    )
}

/// Refuse zero, stale or recycled machine state before restoring CR3 or EL0.
pub fn restore_native_context(
    words: ParkedContextWords,
    expected: AddressContext<RootGpa>,
) -> Option<NativeContext> {
    if !words.authenticates(expected) {
        return None;
    }
    let mut gpr = [0; 15];
    gpr.copy_from_slice(&words.frame[..15]);
    let frame = InterruptFrame {
        gpr,
        rip: words.frame[15],
        cs: words.frame[16],
        flags: words.frame[17],
        rsp: words.frame[18],
        ss: words.frame[19],
    };
    if !frame.valid_user_return() {
        return None;
    }
    Some(NativeContext {
        frame,
        address: expected,
        fs_base: words.fs_base,
        gs_base: words.gs_base,
        xsave: XsaveArea(words.xsave),
    })
}

/// Exact shared-record identity and its expected address owner. Machine state
/// lives only in `ZoneRecord<ParkedContextWords>`, never in this witness.
#[repr(C)]
pub struct ContextBinding {
    pub record: RecordRef,
    pub address: AddressContext<RootGpa>,
}

/// Bounded hardware witness/control record, outside the common ABI. This is
/// NOT a production task graph or MM owner. The carrier initializes it while
/// stopped and retains it until VM retirement.
pub const PROGRESS_STATE: u64 = 0xffff_ffff_b070_0000;
pub const PROGRESS_ZONE: u64 = 0xffff_ffff_b000_0000;
pub const PROGRESS_HEADER: u64 = 0x10_2000;
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
    /// One transient native image for the currently executing task only.
    pub active: NativeContext,
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
    pub fn owned_on(&self, zone: &ZoneTables<ParkedContextWords>, slot: SlotId) -> bool {
        zone.live(self.record).is_some_and(|record| {
            record.identity().mm == self.address.mm.raw().get()
                && matches!(record.claim(), Claim::OnCpu { slot: owner, .. } if owner == slot)
        })
    }
}

/// Switch admission through the SAME occupancy/gate authority as ARM.
/// The caller first installs its maintenance root; after this grant it must
/// install the exact native root before restoring user state. N1's eventual
/// root receipt validation is deliberately not synthesized here.
pub fn admit_context(
    zone: &ZoneTables<ParkedContextWords>,
    slot: SlotId,
    binding: &ContextBinding,
) -> bool {
    if !binding.owned_on(zone, slot) {
        return false;
    }
    let mm = binding.address.mm.raw().get();
    let Some(grant) = zone.install_space(slot, mm) else {
        return false;
    };
    if grant.cow_owed.is_some() || grant.ttbr0 != binding.address.root.address().raw() {
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
    fn native_restore_rejects_invalid_iret_user_state() {
        let root = RootGpa::page_aligned(FrameGpa::new(0x60_0000)).unwrap();
        let address = AddressContext {
            root,
            mm: MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let context = NativeContext {
            frame: InterruptFrame {
                rip: 0x40_0000,
                cs: 0x23,
                flags: 0x202,
                rsp: 0x7fff_0000,
                ss: 0x1b,
                ..InterruptFrame::default()
            },
            address,
            fs_base: 0,
            gs_base: 0,
            xsave: XsaveArea::ZERO,
        };
        let words = park_native_context(&context);
        assert!(restore_native_context(words, address).is_some());
        for (index, value) in [
            (15, 1_u64 << 47), // non-user RIP
            (16, 0x1b),        // data selector as CS
            (17, 0x3002),      // privileged IOPL
            (18, 1_u64 << 47), // non-user stack
            (19, 0x23),        // code selector as SS
        ] {
            let mut invalid = words;
            invalid.frame[index] = value;
            assert!(
                restore_native_context(invalid, address).is_none(),
                "word {index}"
            );
        }
    }

    #[test]
    fn shared_queue_cross_mm_admission_refuses_stale_native_custody() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: documented all-zero empty state; uniquely owned box.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
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
            let address = AddressContext {
                root,
                mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
            };
            let native = NativeContext {
                frame: InterruptFrame {
                    gpr: [mm; 15],
                    rip: mm * 100,
                    cs: 0x23,
                    flags: 0x202,
                    rsp: mm * 1000,
                    ss: 0x1b,
                },
                address,
                fs_base: mm * 16,
                gs_base: mm * 32,
                xsave: XsaveArea([mm as u8; XSAVE_BYTES]),
            };
            // SAFETY: this new record remains host-owned until requeue.
            unsafe { *zone.record(record).ctx_mut() = park_native_context(&native) };
            zone.requeue_preempted(slot, record);
            bindings.push(ContextBinding {
                record: zone.record_ref(record),
                address,
            });
        }
        for turn in 0..8 {
            let id = zone.switch_in(slot).unwrap();
            let binding = &bindings[turn % 2];
            assert_eq!(id, binding.record.id);
            assert!(admit_context(&zone, slot, binding));
            assert_eq!(zone.installed_space(slot), binding.address.mm.raw().get());
            assert!(!admit_context(&zone, slot, &bindings[(turn + 1) % 2]));
            zone.release_space(slot);
            zone.requeue_preempted(slot, id);
        }
        let id = zone.switch_in(slot).unwrap();
        let mut stale = ContextBinding {
            record: bindings[0].record,
            address: bindings[0].address,
        };
        stale.record.incarnation += 1;
        assert!(!admit_context(&zone, slot, &stale));
        let mut wrong_mm = ContextBinding {
            record: bindings[0].record,
            address: bindings[1].address,
        };
        assert!(!admit_context(&zone, slot, &wrong_mm));
        wrong_mm.address.mm = bindings[0].address.mm;
        assert!(!admit_context(&zone, slot, &wrong_mm), "root mismatch");
        assert_eq!(zone.installed_space(slot), 0, "refusal vacates occupancy");
        let index = zone.spaces.find(11).unwrap();
        zone.spaces.close(index);
        assert!(!admit_context(&zone, slot, &bindings[0]));
        assert_eq!(id, bindings[0].record.id);
    }
}

// Qualified target_os=none native-context leaves shared by CPL0 bindings.
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
pub enum NativeTlsRegister {
    Fs,
    UserGs,
}
#[cfg(target_os = "none")]
impl NativeTlsRegister {
    const fn msr(self) -> u32 {
        match self {
            Self::Fs => 0xc0000100,
            Self::UserGs => 0xc0000102,
        }
    }
}
#[cfg(target_os = "none")]
pub fn read_tls(register: NativeTlsRegister) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: CPL0; only FS_BASE or the user GS retained after SWAPGS is selected.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") register.msr(), out("eax") low, out("edx") high, options(nostack));
    }
    u64::from(low) | (u64::from(high) << 32)
}
#[cfg(target_os = "none")]
pub fn write_tls(register: NativeTlsRegister, value: u64) {
    // SAFETY: qualified CPL0 context installation; canonical retained user TLS
    // bases only. UserGs selects KERNEL_GS_BASE while SWAPGS retains kernel GS.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") register.msr(), in("eax") value as u32, in("edx") (value>>32) as u32, options(nostack));
    }
}
#[cfg(target_os = "none")]
pub fn save_extended(area: &mut XsaveArea) {
    // SAFETY: stopped-host admission qualified XCR0=7 and the complete 832-byte
    // standard image; XsaveArea has 64-byte alignment and exclusive native custody.
    unsafe {
        core::arch::asm!("xsave64 [{}]", in(reg) area.0.as_mut_ptr(), in("eax") 7u32, in("edx") 0u32, options(nostack));
    }
}
#[cfg(target_os = "none")]
pub fn restore_extended(area: &XsaveArea) {
    // SAFETY: exact retained native context captured by save_extended, with the
    // same qualified XCR0 and aligned complete image, never a foreign incarnation.
    unsafe {
        core::arch::asm!("xrstor64 [{}]", in(reg) area.0.as_ptr(), in("eax") 7u32, in("edx") 0u32, options(nostack));
    }
}

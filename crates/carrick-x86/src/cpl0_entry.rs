//! Native CPL0 frame and boundary-control transport, shared by the thin image
//! and its KVM bootstrap. No Linux syscall algorithm lives in this adapter.
use carrick_guest_arch::{
    CpuId, GuestIsa, NativeAbi, NativeEntrySnapshot, X86Register, X86Registers,
};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64};

/// One xAPIC destination published for an issued scheduler CPU slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedApicId(pub u8);

/// Stopped-host publication shared by every CPU binding in one carrier.
pub struct PublishedApicIds {
    entries: [AtomicU16; carrick_sched_core::ZONE_SLOTS],
}

/// The current KVM carrier admits two native CPUs. Each sender owns one
/// request cell, so mutual invalidations never wait for a global request lock.
pub const CPL0_CPU_COUNT: usize = 2;

pub struct ShootdownRequest {
    pub root: AtomicU64,
    /// Exact MM incarnation that owns `root`; a reused root is a new owner.
    pub mm_key: AtomicU64,
    pub owner_generation: AtomicU64,
    pub generation: AtomicU64,
    pub ack: [AtomicU64; CPL0_CPU_COUNT],
    /// Guest-confirmed drains. Host offline acknowledgement never advances it.
    pub served: [AtomicU64; CPL0_CPU_COUNT],
}

impl ShootdownRequest {
    pub const fn new() -> Self {
        Self {
            root: AtomicU64::new(0),
            mm_key: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            ack: [const { AtomicU64::new(0) }; CPL0_CPU_COUNT],
            served: [const { AtomicU64::new(0) }; CPL0_CPU_COUNT],
        }
    }
}

/// One CPU's live address owner. Odd `revision` means a context switch is in
/// progress; a sender conservatively treats that state as a matching member.
pub struct ShootdownMember {
    pub revision: AtomicU64,
    pub root: AtomicU64,
    pub mm_key: AtomicU64,
    pub owner_generation: AtomicU64,
    /// Published by the host before KVM_RUN, cleared only after a safe CPL3
    /// exit. A stopped member's debt is drained on its next admitted entry.
    pub running: AtomicU32,
}

impl ShootdownMember {
    pub const fn new() -> Self {
        Self {
            revision: AtomicU64::new(0),
            root: AtomicU64::new(0),
            mm_key: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            running: AtomicU32::new(0),
        }
    }

    pub fn publish(&self, root: u64, mm_key: u64, owner_generation: u64) {
        self.revision
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        self.root.store(root, core::sync::atomic::Ordering::Relaxed);
        self.mm_key
            .store(mm_key, core::sync::atomic::Ordering::Relaxed);
        self.owner_generation
            .store(owner_generation, core::sync::atomic::Ordering::Relaxed);
        self.revision
            .fetch_add(1, core::sync::atomic::Ordering::Release);
    }

    pub fn matches_or_changing(&self, root: u64, mm_key: u64, owner_generation: u64) -> bool {
        let first = self.revision.load(core::sync::atomic::Ordering::Acquire);
        if first & 1 != 0 {
            return true;
        }
        let observed = (
            self.root.load(core::sync::atomic::Ordering::Relaxed),
            self.mm_key.load(core::sync::atomic::Ordering::Relaxed),
            self.owner_generation
                .load(core::sync::atomic::Ordering::Relaxed),
        );
        let last = self.revision.load(core::sync::atomic::Ordering::Acquire);
        first != last || observed == (root, mm_key, owner_generation)
    }
}

impl Default for ShootdownRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ShootdownMember {
    fn default() -> Self {
        Self::new()
    }
}

/// Retained publication shared by the exact CPU bindings in one carrier.
pub struct ShootdownTable {
    pub next_generation: AtomicU64,
    /// KICK-entry generation checks; fixture can prove this happened before
    /// the stopped CPU executes its next user instruction.
    pub kick_checks: [AtomicU64; CPL0_CPU_COUNT],
    /// Fixture-only two-live-CPU start barrier; production ignores it.
    pub fixture_arrived: AtomicU32,
    pub requests: [ShootdownRequest; CPL0_CPU_COUNT],
    pub members: [ShootdownMember; CPL0_CPU_COUNT],
}

impl ShootdownTable {
    pub const fn new() -> Self {
        Self {
            next_generation: AtomicU64::new(0),
            kick_checks: [const { AtomicU64::new(0) }; CPL0_CPU_COUNT],
            fixture_arrived: AtomicU32::new(0),
            requests: [const { ShootdownRequest::new() }; CPL0_CPU_COUNT],
            members: [const { ShootdownMember::new() }; CPL0_CPU_COUNT],
        }
    }
}

impl Default for ShootdownTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PublishedApicIds {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishedApicIds {
    pub const fn new() -> Self {
        Self {
            entries: [const { AtomicU16::new(0) }; carrick_sched_core::ZONE_SLOTS],
        }
    }

    pub fn publish(&self, slot: CpuId, apic_id: PublishedApicId) -> bool {
        self.entries.get(slot.raw() as usize).is_some_and(|entry| {
            entry
                .compare_exchange(
                    0,
                    u16::from(apic_id.0) + 1,
                    core::sync::atomic::Ordering::Release,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        })
    }

    pub fn destination(&self, slot: CpuId) -> Option<PublishedApicId> {
        self.entries
            .get(slot.raw() as usize)?
            .load(core::sync::atomic::Ordering::Acquire)
            .checked_sub(1)
            .and_then(|id| u8::try_from(id).ok())
            .map(PublishedApicId)
    }
}

pub const FAULT_DOORBELL_PORT: u16 = 0xc7;
pub const FORWARD_PORT: u16 = 0xc5;
pub const CONTROL_PORT: u16 = 0xc8;
pub const ENTRY_KICK_PORT: u16 = 0xc9;
pub const RETURN_KICK_PORT: u16 = 0xca;
pub const WORK_PORT: u16 = 0xcb;
pub const FATAL_PORT: u16 = 0xcc;
pub const YIELD_PORT: u16 = 0xd0;
/// Physical owner-grant submission/receipt boundary; Linux policy stays in CPL0.
pub const OWNER_GRANT_PORT: u16 = 0xd1;
/// Fixture observation only, outside Linux semantic serving.
pub const OBSERVE_NATIVE: u64 = u64::MAX;
/// Fixture observation of the shared kernel's active MMU root.
pub const OBSERVE_MMU_ROOT: u64 = u64::MAX - 1;
/// Fixture observation of the shared kernel allocator.
pub const OBSERVE_ALLOCATOR: u64 = u64::MAX - 2;
/// Fixture request for a local MMU drain of the supplied user page.
pub const OBSERVE_MMU_DRAIN: u64 = u64::MAX - 3;
/// Fixture request for a shared-kernel x86 descriptor protection edit.
pub const OBSERVE_DESCRIPTOR_PROTECT: u64 = u64::MAX - 4;
pub const OBSERVE_DESCRIPTOR_PREPARE_PUBLISH: u64 = u64::MAX - 5;
pub const OBSERVE_SHARED_PREPARED_FAULT: u64 = u64::MAX - 6;
pub const OBSERVE_SHARED_COW_FAULT: u64 = u64::MAX - 7;
pub const OBSERVE_PORTAL_WINDOW: u64 = u64::MAX - 8;
pub const OBSERVE_FORK_TABLE_WINDOW: u64 = u64::MAX - 9;
pub const OBSERVE_RETIRE_REPOINT: u64 = u64::MAX - 10;
pub const OBSERVE_INITIAL_MM: u64 = u64::MAX - 11;

/// Decode vector 14 only after the hardware frame proves CPL3 origin. A
/// reserved-bit fault cannot be repaired by mapping or COW policy.
pub fn decode_user_page_fault(
    error: u64,
    address: u64,
    cs: u64,
) -> Option<carrick_guest_arch::FaultInfo> {
    use carrick_guest_arch::{Access, FaultInfo, UserVa};
    if cs & 3 != 3
        || error & 4 == 0
        || error & (8 | (1 << 5) | (1 << 15)) != 0
        || address >= (1 << 47)
    {
        return None;
    }
    Some(FaultInfo {
        address: UserVa::new(address),
        access: if error & 16 != 0 {
            Access::Execute
        } else if error & 2 != 0 {
            Access::Write
        } else {
            Access::Read
        },
        present: error & 1 != 0,
    })
}
pub const OBSERVE_CPL0_UACCESS_SHOOTDOWN: u64 = u64::MAX - 12;
/// Supervisor direct-window base mapping low physical RAM into the upper half.
pub const DIRECT_VA: u64 = carrick_el1_abi::X86_CPL0_DIRECT_VA;
/// Retained KVM fixture page-table window; the root is its first page.
pub const FIXTURE_PML4_CAPACITY: u64 = carrick_el1_abi::X86_CPL0_TABLE_ARENA_BYTES;

/// Stack order is enforced by the CPL0 assembly and these compile assertions.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r9: u64,
    pub r8: u64,
    pub r10: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rax: u64,
    pub rcx: u64,
    pub r11: u64,
    pub rsp: u64,
}
const _: () = assert!(core::mem::size_of::<NativeFrame>() == 128);
const _: () = {
    assert!(core::mem::offset_of!(NativeFrame, r15) == 0);
    assert!(core::mem::offset_of!(NativeFrame, r14) == 8);
    assert!(core::mem::offset_of!(NativeFrame, r13) == 16);
    assert!(core::mem::offset_of!(NativeFrame, r12) == 24);
    assert!(core::mem::offset_of!(NativeFrame, rbp) == 32);
    assert!(core::mem::offset_of!(NativeFrame, rbx) == 40);
    assert!(core::mem::offset_of!(NativeFrame, r9) == 48);
    assert!(core::mem::offset_of!(NativeFrame, r8) == 56);
    assert!(core::mem::offset_of!(NativeFrame, r10) == 64);
    assert!(core::mem::offset_of!(NativeFrame, rdx) == 72);
    assert!(core::mem::offset_of!(NativeFrame, rsi) == 80);
    assert!(core::mem::offset_of!(NativeFrame, rdi) == 88);
    assert!(core::mem::offset_of!(NativeFrame, rax) == 96);
    assert!(core::mem::offset_of!(NativeFrame, rcx) == 104);
    assert!(core::mem::offset_of!(NativeFrame, r11) == 112);
    assert!(core::mem::offset_of!(NativeFrame, rsp) == 120);
};

impl NativeFrame {
    pub fn snapshot(&self) -> NativeEntrySnapshot<'_, Self> {
        NativeEntrySnapshot {
            isa: GuestIsa::X86_64,
            abi: NativeAbi::X86_64Syscall,
            frame: self,
        }
    }

    /// IRETQ handles all admitted returns, including TF/RF. Reject privileged
    /// flags and non-user targets before constructing the return frame.
    pub fn valid_user_return(&self) -> bool {
        carrick_sched_core::valid_user_return_words(self.rcx, self.rsp, self.r11)
    }
}

impl X86Registers for NativeFrame {
    fn read(&self, register: X86Register) -> u64 {
        match register {
            X86Register::Rax => self.rax,
            X86Register::Rbx => self.rbx,
            X86Register::Rcx => self.rcx,
            X86Register::Rdx => self.rdx,
            X86Register::Rsi => self.rsi,
            X86Register::Rdi => self.rdi,
            X86Register::Rbp => self.rbp,
            X86Register::Rsp => self.rsp,
            X86Register::R8 => self.r8,
            X86Register::R9 => self.r9,
            X86Register::R10 => self.r10,
            X86Register::R11 => self.r11,
            X86Register::R12 => self.r12,
            X86Register::R13 => self.r13,
            X86Register::R14 => self.r14,
            X86Register::R15 => self.r15,
        }
    }
}

/// Convert the issued CPU domain to the bounded scheduler slot domain.
pub fn checked_scheduler_slot(cpu: CpuId) -> Option<carrick_sched_core::SlotId> {
    Some(carrick_sched_core::SlotId::new(
        u8::try_from(cpu.raw()).ok()?,
    ))
}

/// Per-vCPU supervisor binding, private to this entry/bootstrap (not a change
/// to the common ABI). SWAPGS accesses only its first three words.
#[repr(C)]
pub struct CpuBinding {
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub self_address: u64,
    pub task_address: u64,
    pub counters_address: u64,
    pub entry_kick: AtomicU32,
    pub return_kick: AtomicU32,
    pub entries: AtomicU64,
    pub publications: AtomicU64,
    pub completions: AtomicU64,
    pub captured_stack: AtomicU64,
    /// Private hardware witness binding; zero in normal M2 entry. This is
    /// retained CPL0 control transport, not common task/scheduler authority.
    pub scheduler_witness: AtomicU64,
    /// The scheduler slot issued by the stopped-host CPL0 bootstrap.
    pub cpu_slot: u32,
    /// KVM_GET_TSC_KHZ converted to hertz; zero means no qualified clock.
    pub tsc_hz: AtomicU64,
    /// Shared slot-indexed APIC routing table, retained until all vCPUs stop.
    pub wake_routes_address: u64,
    /// Measured xAPIC timer hertz when TSC-deadline mode is unavailable.
    pub apic_timer_hz: AtomicU64,
    /// Coalesced native interrupt reasons awaiting the shared scheduler.
    /// The IRQ entry publishes here before completing the xAPIC ISR.
    pub pending_irqs: AtomicU32,
    /// Retained per-sender shootdown table, published before any vCPU runs.
    pub shootdown_table_address: u64,
    /// Per-CPU fault custody. The outer frame stays on its TSS entry stack.
    pub fault_active: AtomicU64,
    pub fault_frame: AtomicU64,
    pub fault_address: AtomicU64,
    pub fault_reason: AtomicU64,
    /// Exact MM owner generation of this CPU's active root, published on
    /// every context install. Zero refuses shootdown authentication.
    pub mm_owner_generation: AtomicU64,
    /// Last invalidation generation drained by this CPU for its active root.
    pub last_seen_generation: AtomicU64,
}
const _: () = {
    assert!(core::mem::offset_of!(CpuBinding, kernel_stack) == 0);
    assert!(core::mem::offset_of!(CpuBinding, user_stack) == 8);
    assert!(core::mem::offset_of!(CpuBinding, self_address) == 16);
    assert!(core::mem::offset_of!(CpuBinding, cpu_slot) == 88);
    assert!(core::mem::offset_of!(CpuBinding, fault_active) == 136);
    assert!(core::mem::offset_of!(CpuBinding, fault_frame) == 144);
    assert!(core::mem::offset_of!(CpuBinding, fault_address) == 152);
    assert!(core::mem::offset_of!(CpuBinding, fault_reason) == 160);
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #[test]
    fn scheduler_slot_conversion_rejects_unissued_high_bits() {
        use super::checked_scheduler_slot;
        use carrick_guest_arch::CpuId;
        assert_eq!(
            checked_scheduler_slot(CpuId::new(0)).map(|slot| slot.raw()),
            Some(0)
        );
        assert_eq!(
            checked_scheduler_slot(CpuId::new(255)).map(|slot| slot.raw()),
            Some(255)
        );
        assert!(checked_scheduler_slot(CpuId::new(256)).is_none());
        assert!(checked_scheduler_slot(CpuId::new(u32::MAX)).is_none());
    }
    #[test]
    fn user_page_fault_decodes_only_cpl3_access_with_valid_error_bits() {
        use carrick_guest_arch::{Access, UserVa};
        let write = super::decode_user_page_fault(0b111, 0x7fff_e000, 0x1b).unwrap();
        assert_eq!(write.address, UserVa::new(0x7fff_e000));
        assert_eq!(write.access, Access::Write);
        assert!(write.present);
        let execute = super::decode_user_page_fault(0b10100, 0x400000, 0x1b).unwrap();
        assert_eq!(execute.access, Access::Execute);
        assert!(!execute.present);
        assert!(super::decode_user_page_fault(0b111, 0x7fff_e000, 8).is_none());
        assert!(super::decode_user_page_fault(0b011, 0x7fff_e000, 0x1b).is_none());
        assert!(super::decode_user_page_fault(0b1111, 0x7fff_e000, 0x1b).is_none());
        assert!(super::decode_user_page_fault(7 | (1 << 5), 0x400000, 0x1b).is_none());
        assert!(super::decode_user_page_fault(7 | (1 << 15), 0x400000, 0x1b).is_none());
        assert!(super::decode_user_page_fault(0b111, 1 << 47, 0x1b).is_none());
    }

    use super::*;
    #[test]
    fn apic_routes_cover_every_issued_carrier_slot() {
        let routes = PublishedApicIds::new();
        assert!(routes.publish(CpuId::new(2), PublishedApicId(7)));
        assert_eq!(routes.destination(CpuId::new(2)), Some(PublishedApicId(7)));
        assert!(routes.publish(CpuId::new(255), PublishedApicId(0)));
        assert_eq!(
            routes.destination(CpuId::new(255)),
            Some(PublishedApicId(0))
        );
        assert_eq!(routes.destination(CpuId::new(256)), None);
    }
    fn decode(frame: &NativeFrame) -> carrick_personality_linux::entry::CanonicalCall {
        carrick_personality_linux::entry::decode_x86_snapshot(frame.snapshot()).unwrap()
    }
    #[test]
    fn native_entry_keeps_full_width_opaque_head() {
        for head in [0, 0x0000_1234_0000_a000, 0x8000_5678_0000_a000, u64::MAX] {
            let frame = NativeFrame {
                rax: 273,
                rdi: head,
                rsi: 24,
                ..Default::default()
            };
            assert_eq!(decode(&frame).args[0], head, "opaque head {head:#018x}");
        }
    }

    #[test]
    fn native_entry_keeps_full_width_robust_list_length() {
        let frame = NativeFrame {
            rax: 273,
            rdi: 0,
            rsi: 0x1_0000_0018,
            ..Default::default()
        };
        assert_eq!(decode(&frame).args[1], 0x1_0000_0018);
    }

    #[test]
    fn native_entry_keeps_arguments_number_and_captured_stack() {
        let frame = NativeFrame {
            rax: 273,
            rdi: 1,
            rsi: 24,
            rdx: 3,
            r10: 4,
            r8: 5,
            r9: 6,
            rsp: 0x31fe8,
            ..Default::default()
        };
        let call = decode(&frame);
        assert_eq!(call.isa, GuestIsa::X86_64);
        assert_eq!(call.native.raw(), 273);
        assert_eq!(call.canonical.raw(), 99);
        assert_eq!(call.args, [1, 24, 3, 4, 5, 6]);
        assert_eq!(call.stack.raw(), frame.rsp);
        assert_eq!(
            decode(&NativeFrame { rax: 99, ..frame }).canonical.raw(),
            u64::MAX
        );
    }
    #[test]
    fn iret_return_rejects_noncanonical_targets_and_privileged_flags() {
        let valid = NativeFrame {
            rcx: 0x10000,
            rsp: 0x31fe8,
            r11: 0x202,
            ..Default::default()
        };
        assert!(valid.valid_user_return());
        for target in [0, 1 << 47, u64::MAX] {
            assert!(
                !NativeFrame {
                    rcx: target,
                    ..valid
                }
                .valid_user_return()
            );
            assert!(
                !NativeFrame {
                    rsp: target,
                    ..valid
                }
                .valid_user_return()
            );
        }
        for mask in [3 << 12, 1 << 14, 1 << 17, 1 << 19, 1 << 20] {
            assert!(
                !NativeFrame {
                    r11: valid.r11 | mask,
                    ..valid
                }
                .valid_user_return()
            );
        }
        assert!(!NativeFrame { r11: 0, ..valid }.valid_user_return());
        // These require IRETQ; there is no unsafe SYSRET alternate path.
        assert!(
            NativeFrame {
                r11: valid.r11 | (1 << 8) | (1 << 16),
                ..valid
            }
            .valid_user_return()
        );
    }
}

//! `Aarch64GuestArch` — the aarch64 implementation of the [`GuestArch`] seam.
//!
//! Lives in `carrick-hal` (not `carrick-mem`) because `carrick-hal` already
//! depends on `carrick-mem` + `carrick-guest-mem` + `carrick-abi`, while
//! `carrick-mem` does NOT depend on `carrick-hal` (placing the impl in
//! `carrick-mem` would form a `mem → hal → mem` cycle). See the Phase 1 plan,
//! Task 1 Step 1.
//!
//! Phase 1 is behavior-preserving: every method body calls the existing
//! function verbatim. No routing through the trait happens yet (that starts in
//! later plan tasks).

use crate::guest_arch::{GuestArch, PageTableCodec, PtGranule, SyscallTable};
use carrick_guest_mem::Aarch64SyscallFrame;

/// ELF `e_machine` for AArch64 (`EM_AARCH64`).
const EM_AARCH64: u16 = 183;

/// AArch64 stage-1 walks 4 levels of a 4 KiB-granule long-descriptor table,
/// 9 index bits per level. Mirrors `carrick-mem::page_table`.
const AARCH64_PAGE_SHIFT: u32 = 12;
const AARCH64_PT_LEVELS: u8 = 4;
const AARCH64_PT_INDEX_BITS: u32 = 9;

/// The AArch64 page-table descriptor codec. Phase 1 surface: the granule
/// parameters mirroring `carrick-mem::page_table` (4 KiB granule, 4 levels).
/// The per-descriptor bit helpers are finalized against `page_table.rs` in a
/// later plan task.
#[derive(Clone, Copy, Debug)]
pub struct Aarch64Mmu;

impl PageTableCodec for Aarch64Mmu {
    fn page_shift() -> u32 {
        AARCH64_PAGE_SHIFT
    }

    fn granule() -> PtGranule {
        PtGranule {
            page_shift: AARCH64_PAGE_SHIFT,
            levels: AARCH64_PT_LEVELS,
            index_bits: AARCH64_PT_INDEX_BITS,
        }
    }
}

/// The AArch64 syscall-number metadata table — a thin wrapper over
/// `carrick_abi::syscall::lookup_aarch64` (today's `AARCH64_SYSCALLS`).
#[derive(Clone, Copy, Debug)]
pub struct Aarch64SyscallTable;

impl SyscallTable for Aarch64SyscallTable {
    fn name(number: u64) -> Option<&'static str> {
        carrick_abi::syscall::lookup_aarch64(number).map(|syscall| syscall.name)
    }

    fn is_known(number: u64) -> bool {
        carrick_abi::syscall::lookup_aarch64(number).is_some()
    }
}

/// The aarch64 [`GuestArch`] impl. Unit struct selected as `ThreadedEngine::Arch`
/// on both the HVF and KVM backends; monomorphized, so zero-cost.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64GuestArch;

impl GuestArch for Aarch64GuestArch {
    type Frame = Aarch64SyscallFrame;
    type Mmu = Aarch64Mmu;
    type Table = Aarch64SyscallTable;

    fn decode_syscall(frame: &Self::Frame) -> (u64, [u64; 6]) {
        // Verbatim from `SyscallRequest::from_aarch64_frame`: x8 → number,
        // x0..x5 → the six argument registers.
        (
            frame.x8,
            [frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5],
        )
    }

    fn elf_machine() -> u16 {
        EM_AARCH64
    }

    fn uname_machine() -> &'static str {
        "aarch64"
    }

    fn vdso_bytes() -> Vec<u8> {
        carrick_mem::vdso::vdso_image_bytes()
    }

    fn entry_trampoline_bytes() -> Vec<u8> {
        carrick_mem::memory::el0_trampoline_bytes()
    }

    fn _isa_marker() -> &'static str {
        "aarch64"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_maps_x8_and_x0_through_x5() {
        let frame = Aarch64SyscallFrame {
            x0: 10,
            x1: 11,
            x2: 12,
            x3: 13,
            x4: 14,
            x5: 15,
            x8: 64,
        };
        let (number, args) = Aarch64GuestArch::decode_syscall(&frame);
        assert_eq!(number, 64);
        assert_eq!(args, [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn arch_tags_are_aarch64() {
        assert_eq!(Aarch64GuestArch::elf_machine(), 183);
        assert_eq!(Aarch64GuestArch::uname_machine(), "aarch64");
        assert_eq!(Aarch64GuestArch::_isa_marker(), "aarch64");
    }

    #[test]
    fn vdso_and_trampoline_bytes_are_nonempty() {
        assert!(!Aarch64GuestArch::vdso_bytes().is_empty());
        assert!(!Aarch64GuestArch::entry_trampoline_bytes().is_empty());
    }

    #[test]
    fn syscall_table_knows_a_real_number() {
        // 64 is `write` on aarch64 — present in AARCH64_SYSCALLS.
        assert!(Aarch64SyscallTable::is_known(64));
        assert_eq!(Aarch64SyscallTable::name(64), Some("write"));
        // A wildly-out-of-range number is unknown.
        assert!(!Aarch64SyscallTable::is_known(u64::MAX));
    }

    #[test]
    fn mmu_granule_is_4kib_4_level() {
        assert_eq!(Aarch64Mmu::page_shift(), 12);
        let granule = Aarch64Mmu::granule();
        assert_eq!(granule.page_shift, 12);
        assert_eq!(granule.levels, 4);
        assert_eq!(granule.index_bits, 9);
    }
}

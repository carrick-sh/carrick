//! Host decode of a ring panic at its stopped fatal exit.
//!
//! The ring publishes its `PanicReport` in registers. The host adds what the
//! ring cannot carry there: the return addresses of the panicking CPU's
//! kernel stack, read through the stopped CPU's own page tables. They name
//! the panic's callers; resolve them against the CPL0 image, for example
//! `addr2line -fipCe target/x86_64-unknown-none/release/carrick-x86-cpl0`.

use crate::carrier_memory::{CarrierMemory, CarrierMemoryIo};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
use carrick_mmu_core::x86::descriptor_txn::{Access, translate_leaf};
use carrick_x86::X86Reg;

/// Most return addresses one ring backtrace reports.
pub const RING_BACKTRACE_FRAMES: usize = 48;
/// Largest step between two frame records the walk follows.
const RING_FRAME_STEP_MAX: u64 = 1 << 20;
/// Lowest address of the supervisor half, where every ring frame and return
/// address lives.
const SUPERVISOR_HALF: u64 = 0xffff_8000_0000_0000;

/// Follow a frame-pointer chain from `frame`, reading words with `read`.
///
/// The walk stops at the first record it cannot trust: an unaligned or
/// non-supervisor frame, an unreadable word, a return address outside the
/// supervisor half, or a caller frame that is not strictly above its callee
/// within `RING_FRAME_STEP_MAX` (1 MiB). It therefore ends on any stack, and
/// reports at most [`RING_BACKTRACE_FRAMES`] addresses.
pub fn walk_ring_frames(mut frame: u64, mut read: impl FnMut(u64) -> Option<u64>) -> Vec<u64> {
    let mut returns = Vec::new();
    while returns.len() < RING_BACKTRACE_FRAMES && frame >= SUPERVISOR_HALF && frame & 7 == 0 {
        let Some(return_address) = frame.checked_add(8).and_then(&mut read) else {
            break;
        };
        if return_address < SUPERVISOR_HALF {
            break;
        }
        returns.push(return_address);
        let Some(caller) = read(frame) else {
            break;
        };
        if caller <= frame || caller - frame > RING_FRAME_STEP_MAX {
            break;
        }
        frame = caller;
    }
    returns
}

fn read_supervisor_word<M: CarrierMemoryIo>(
    memory: &CarrierMemory<M>,
    root: RootGpa,
    va: u64,
) -> Option<u64> {
    let leaf = translate_leaf(&memory.words(), root, UserVa::new(va), Access::Read, false).ok()?;
    let within = leaf.size.checked_sub(1)?;
    let gpa = (leaf.output.raw() & !within) | (va & within);
    let bytes = memory.read(FrameGpa::new(gpa), 8).ok()?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// The failure text of a ring panic at a stopped fatal-port exit, or `None`
/// when the exit carries no panic record. The backtrace is best effort: a
/// stack the host cannot read leaves it empty and keeps the record.
pub fn fatal_port_panic_detail<M: CarrierMemoryIo, E>(
    memory: &CarrierMemory<M>,
    mut gpr: impl FnMut(X86Reg) -> Result<u64, E>,
) -> Result<Option<String>, E> {
    let Some(report) = carrick_x86::fatal_port_panic_report(&mut gpr)? else {
        return Ok(None);
    };
    let frame = gpr(X86Reg::Rbp)?;
    let returns = RootGpa::page_aligned(FrameGpa::new(gpr(X86Reg::Cr3)? & !0xfff))
        .map(|root| walk_ring_frames(frame, |va| read_supervisor_word(memory, root, va)))
        .unwrap_or_default();
    let mut detail = format!("CPL0 kernel panic at {report}; ring return addresses:");
    if returns.is_empty() {
        detail.push_str(" unavailable");
    }
    for address in returns {
        detail.push_str(&format!(" {address:#x}"));
    }
    Ok(Some(detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const STACK: u64 = 0xffff_ffff_9000_0000;
    const TEXT: u64 = 0xffff_ffff_8000_1000;

    fn stack(records: &[(u64, u64, u64)]) -> BTreeMap<u64, u64> {
        let mut words = BTreeMap::new();
        for &(frame, caller, return_address) in records {
            words.insert(frame, caller);
            words.insert(frame + 8, return_address);
        }
        words
    }

    #[test]
    fn ring_frame_walk_reports_each_caller_then_stops_at_the_stack_end() {
        let words = stack(&[
            (STACK, STACK + 0x40, TEXT + 1),
            (STACK + 0x40, STACK + 0x100, TEXT + 2),
            (STACK + 0x100, 0, TEXT + 3),
        ]);
        assert_eq!(
            walk_ring_frames(STACK, |va| words.get(&va).copied()),
            [TEXT + 1, TEXT + 2, TEXT + 3]
        );
    }

    #[test]
    fn ring_frame_walk_is_bounded_on_a_cyclic_or_foreign_chain() {
        // A record that names itself as its caller.
        let cyclic = stack(&[(STACK, STACK, TEXT)]);
        assert_eq!(
            walk_ring_frames(STACK, |va| cyclic.get(&va).copied()),
            [TEXT]
        );
        // A chain that descends, one that leaves the supervisor half, an
        // unaligned frame, and an unreadable stack.
        let descending = stack(&[(STACK, STACK - 0x40, TEXT), (STACK - 0x40, STACK, TEXT)]);
        assert_eq!(
            walk_ring_frames(STACK, |va| descending.get(&va).copied()),
            [TEXT]
        );
        let user_return = stack(&[(STACK, STACK + 0x40, 0x40_1000)]);
        assert!(walk_ring_frames(STACK, |va| user_return.get(&va).copied()).is_empty());
        assert!(walk_ring_frames(STACK + 4, |_| Some(TEXT)).is_empty());
        assert!(walk_ring_frames(STACK, |_| None).is_empty());
        assert!(walk_ring_frames(0x7fff_0000, |_| Some(TEXT)).is_empty());
        // An endless ascending chain stops at the frame bound.
        let endless =
            walk_ring_frames(STACK, |va| Some(if va & 8 == 0 { va + 0x10 } else { TEXT }));
        assert_eq!(endless.len(), RING_BACKTRACE_FRAMES);
    }
}

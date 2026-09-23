//! Complete-state differential against the preserved slot emitter. These
//! controls target joins and exact-PC re-entry where x17 changes representation.
use crate::{
    Instruction, Memory, classify, emulate,
    native::{Code, Layout, State},
    tests::elf,
};

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    x: [u64; 31],
    pc: u64,
    sp: u64,
    tls: u64,
    nzcv: u64,
    fpcr: u64,
    fpsr: u64,
    vectors: [u128; 32],
}
impl From<&State> for Snapshot {
    fn from(s: &State) -> Self {
        Self {
            x: s.x,
            pc: s.pc,
            sp: s.sp,
            tls: s.tls,
            nzcv: s.nzcv,
            fpcr: s.fpcr,
            fpsr: s.fpsr,
            vectors: s.vectors,
        }
    }
}
fn trace(words: &[u32], entry: usize, x17: u64, flags: u64, layout: Layout) -> Vec<Snapshot> {
    let (mut memory, image) = Memory::load_elf(&elf(words)).unwrap();
    let code = Code::publish_with_layout(&image, &memory, layout).unwrap();
    let mut state = State::new(image.base() + entry as u64 * 4);
    state.x = std::array::from_fn(|n| 0x1122334400000000 | n as u64);
    state.x[0] = 0;
    state.x[17] = x17;
    state.sp = 0x500800;
    state.tls = 0x77889900;
    state.nzcv = flags;
    state.fpcr = 0x400000; // supported rounding-mode bit
    state.fpsr = 0x08000000; // cumulative saturation
    state.vectors = std::array::from_fn(|n| (n as u128 + 1) * 0x123456789abcdef0123456789);
    let mut records = Vec::new();
    let mut syscalls = 0;
    code.run(&image, &mut memory, &mut state, &mut |s, m| {
        assert!(records.len() < 32, "unbounded checkpoint count");
        records.push(Snapshot::from(&*s));
        let word = image.words()[((s.pc - image.base()) / 4) as usize];
        if classify(word).unwrap() == Instruction::Syscall {
            syscalls += 1;
            if s.pc == image.base() + (words.len() as u64 - 1) * 4 {
                return Ok(false);
            }
            // Returning through a different guest-PC entry must reload the
            // callback's new x17 value, even when the body is an arithmetic join.
            s.x[17] = 0x12340000 + syscalls;
            s.pc += 4;
        } else {
            emulate(word, s, m)?;
        }
        Ok(true)
    })
    .unwrap();
    records
}
fn compare(words: &[u32], entry: usize, x17: u64, flags: u64) -> Vec<Snapshot> {
    let slots = trace(words, entry, x17, flags, Layout::Slots);
    let compact = trace(words, entry, x17, flags, Layout::Compact);
    assert_eq!(
        compact, slots,
        "{words:08x?} entry={entry}, x17={x17}, flags={flags:x}"
    );
    compact
}

#[test]
fn every_guest_pc_entry_restores_x17_and_complete_state() {
    // add x17,#1; add x0,x17,#3; adr x17,.; svc; add x17,#1; svc
    let words = [
        0x91000631, 0x91000e20, 0x10000011, 0xd4000001, 0x91000631, 0xd4000001,
    ];
    for entry in 0..words.len() {
        let records = compare(&words, entry, 0x5678, 0xb0000000);
        assert!(!records.is_empty());
    }
}

#[test]
fn forward_conditionals_preserve_both_join_states() {
    for condition in 0..14 {
        for flags in 0..16 {
            // b.cond skips add x17; target consumes live x17 before SVC.
            let words = [0x54000040 | condition, 0x91000631, 0x91000e20, 0xd4000001];
            compare(&words, 0, 37, flags << 28);
        }
    }
    for wide in [0, 0x80000000] {
        for nonzero in [0, 0x01000000] {
            for x17 in [0, 1, 0x100000000] {
                let words = [
                    0x34000051 | wide | nonzero,
                    0x91000631,
                    0x91000e20,
                    0xd4000001,
                ];
                compare(&words, 0, x17, 0x90000000);
            }
        }
    }
    compare(
        &[0x14000002, 0x91000631, 0x91000e20, 0xd4000001],
        0,
        37,
        0x90000000,
    );
}

#[test]
fn backward_edges_keep_exact_budget_and_live_x17() {
    for count in [1u64, 255, 256, 257, 1024] {
        for wide in [0, 0x80000000] {
            // add x0,#1; sub(s) x17,#1; cbnz/b.ne loop; svc.
            for conditional_flags in [false, true] {
                let sub = 0x51000631 | wide | if conditional_flags { 1 << 29 } else { 0 };
                let back = if conditional_flags {
                    0x54ffffc1
                } else {
                    0x35ffffd1 | wide
                };
                let words = [0x91000400, sub, back, 0xd4000001];
                let records = compare(&words, 0, count, 0xa0000000);
                assert_eq!(records.len() as u64, count / 256 + 1);
                let last = records.last().unwrap();
                assert_eq!(last.x[0], count);
                assert_eq!(last.x[17], 0);
            }
        }
        // Forward exit plus unconditional backward edge also retains the bound.
        let words = [0xb4000091, 0x91000400, 0xd1000631, 0x17fffffd, 0xd4000001];
        let records = compare(&words, 0, count, 0x90000000);
        assert_eq!(records.len() as u64, count / 256 + 1);
        assert_eq!(records.last().unwrap().x[0], count);
    }
}

#[test]
fn adr_adrp_reserved_registers_and_tls_still_checkpoint() {
    for rd in [0u32, 16, 17, 18, 28, 30, 31] {
        for instruction in [0x10000000, 0x90000000, 0xd53bd040] {
            if instruction == 0xd53bd040 && rd == 31 {
                // The existing whitelist rejects the system/XZR encoding.
                assert!(Memory::load_elf(&elf(&[instruction | rd, 0xd4000001])).is_err());
                continue;
            }
            compare(&[instruction | rd, 0xd4000001], 0, 31, 0xc0000000);
        }
    }
    compare(
        &[0xd51bd051, 0xd53bd041, 0xd4000001],
        0,
        0xabcdef,
        0xc0000000,
    );
}

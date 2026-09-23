//! Compact native bodies. x17 remains a live guest register between boundaries.
//! Only host entry veneers, memory scratch use and checkpoints touch its spill.
//! Every guest PC has its own entry veneer, so callback re-entry cannot inherit
//! stale host scratch. Internal branches target bodies and preserve live state.
use super::{
    Image, Instruction, branch, branch_target, classify, emit_memory, load_state, store_state,
};
use anyhow::{Result, ensure};

fn immediate(words: &mut Vec<u32>, register: u32, value: u64) {
    words.push(0xd2800000 | (((value & 65535) as u32) << 5) | register);
    for half in 1..4 {
        words.push(
            0xf2800000 | (half << 21) | ((((value >> (half * 16)) & 65535) as u32) << 5) | register,
        );
    }
}

fn checkpoint(words: &mut Vec<u32>, pc: u64, save_x17: bool) {
    if save_x17 {
        words.push(store_state(17, 136));
    }
    immediate(words, 17, pc);
    words.extend([store_state(17, 248), load_state(17, 832), 0xd61f0220]);
}

fn relocated(word: u32, from: usize, to: usize) -> Result<u32> {
    let delta = to as i64 - from as i64;
    if word & 0x7c000000 == 0x14000000 {
        ensure!(
            (-33554432..33554432).contains(&delta),
            "native branch range"
        );
        Ok((word & 0xfc000000) | ((delta as u32) & 0x3ffffff))
    } else {
        ensure!(
            (-262144..262144).contains(&delta),
            "native conditional range"
        );
        Ok((word & !0xffffe0) | (((delta as u32) & 0x7ffff) << 5))
    }
}

pub(super) fn emit(image: &Image, memory: bool) -> Result<(Vec<u32>, Vec<usize>)> {
    let mut words = Vec::new();
    let mut bodies = Vec::with_capacity(image.words.len() + 1);
    let mut edges = Vec::new();
    let mut cold = Vec::new();
    for (i, &word) in image.words.iter().enumerate() {
        bodies.push(words.len());
        let pc = image.base + i as u64 * 4;
        match classify(word).map_err(anyhow::Error::msg)? {
            Instruction::Integer => words.push(word),
            Instruction::Address if !matches!(word & 31, 18 | 28) => {
                let raw = ((((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3)) << 11;
                let imm = (raw as i32 >> 11) as i64;
                let value = if word >> 31 == 0 {
                    pc.wrapping_add_signed(imm)
                } else {
                    (pc & !4095).wrapping_add_signed(imm << 12)
                };
                immediate(&mut words, word & 31, value);
            }
            Instruction::Branch => {
                let target = branch_target(word, pc);
                ensure!(
                    target >= image.base
                        && target < image.base + image.words.len() as u64 * 4
                        && target.is_multiple_of(4),
                    "branch outside executable authority"
                );
                if target <= pc {
                    // Non-flag-setting decrement; x17 is saved before becoming
                    // scratch, and reloaded before either guest successor.
                    words.extend([
                        store_state(17, 136),
                        load_state(17, 848),
                        0xd1000631,
                        store_state(17, 848),
                    ]);
                    cold.push((words.len(), 0xb4000011, pc, false));
                    words.push(0); // cbz x17, checkpoint at the original branch PC
                    words.push(load_state(17, 136));
                }
                edges.push((words.len(), word, ((target - image.base) / 4) as usize));
                words.push(0);
            }
            Instruction::Memory if memory => {
                words.push(store_state(17, 136));
                let (next, miss) = emit_memory(&mut words, word, 0, 0, true);
                edges.push((next, 0x14000000, i + 1));
                cold.push((miss, 0x14000000, pc, true));
            }
            _ => checkpoint(&mut words, pc, true),
        }
    }
    // Out-of-range fallthrough reports the exact PC through the existing
    // checked callback. It cannot fall into cold stubs or entry veneers.
    bodies.push(words.len());
    checkpoint(&mut words, image.base + image.words.len() as u64 * 4, true);
    for (at, word, target) in edges {
        words[at] = relocated(word, at, bodies[target])?;
    }
    for (at, word, pc, save_x17) in cold {
        words[at] = relocated(word, at, words.len())?;
        checkpoint(&mut words, pc, save_x17);
    }
    let mut entries = Vec::with_capacity(image.words.len());
    for &body in bodies.iter().take(image.words.len()) {
        entries.push(words.len() * 4);
        words.push(load_state(17, 136));
        words.push(branch(words.len(), body));
    }
    Ok((words, entries))
}
